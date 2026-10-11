"""Phase 2 analysis engine: dispatch accepted sources to deterministic analyzers by kind.

Inputs are the in-memory texts captured at intake (already size-bounded, UTF-8 validated and
secret-screened). No file is re-read, no tool or subprocess is invoked, nothing is written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from . import rules_k8s, rules_plan, rules_terraform
from .findings import CoverageNote, FileCoverage, Finding, merge_findings
from .intake import IntakeOutcome
from .secret_screen import SecretHit, screen_text

_ESCAPE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))")


def _unescape(text: str) -> str:
    """Decode \\xNN, \\uNNNN and \\UNNNNNNNN escapes anywhere (HCL and YAML double-quoted escape forms).
    Over-decoding can only add screen hits (fail closed); it never removes text."""
    def repl(m):
        cp = int(next(g for g in m.groups() if g), 16)
        return chr(cp) if cp <= 0x10FFFF and not 0xD800 <= cp <= 0xDFFF else m.group(0)
    return _ESCAPE.sub(repl, text)


def decoded_secret_hits(outcome: IntakeOutcome, max_hits: int = 20) -> List[Tuple[str, SecretHit]]:
    """Second secret screen for `review`: credentials hidden behind escape sequences (line unknown)."""
    hits = []
    # Hardening L2: also files read safely but rejected for a text problem (outcome.screen_only).
    sources = [(rec.path, outcome.contents[rec.path]) for rec in outcome.accepted]
    sources += list(getattr(outcome, "screen_only", {}).items())
    for path, text in sorted(sources):
        decoded = _unescape(text)
        if decoded != text:
            rules = sorted({h.rule_id for h in screen_text(decoded, max_hits)})
            hits.extend((path, SecretHit(rule, None)) for rule in rules)
    return hits

TERRAFORM_KINDS = ("terraform", "terraform-vars")
YAML_KINDS = ("yaml", "kubernetes", "helm-rendered")
PLAN_KINDS = ("terraform-plan",)
NOT_ANALYZED_KINDS = {"json": "Generic JSON has no Phase 2 analyzer (declare kind 'terraform-plan' for plans).",
                      "diff": "Diff/patch files have no Phase 2 analyzer."}

ANALYZERS = (
    (rules_terraform.ANALYZER_ID, rules_terraform.ANALYZER_VERSION, rules_terraform.RULES, TERRAFORM_KINDS),
    (rules_plan.ANALYZER_ID, rules_plan.ANALYZER_VERSION, rules_plan.RULES, PLAN_KINDS),
    (rules_k8s.ANALYZER_ID, rules_k8s.ANALYZER_VERSION, rules_k8s.RULES, YAML_KINDS),
)


@dataclass
class AnalysisOutcome:
    coverage: List[FileCoverage] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return bool(self.coverage) and all(c.status == "analyzed" for c in self.coverage)

    def rule_coverage(self) -> List[dict]:
        evaluated: Dict[str, int] = {}
        for c in self.coverage:
            for rule, n in c.rule_evaluations.items():
                evaluated[rule] = evaluated.get(rule, 0) + n
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
        out = []
        for analyzer_id, _version, rules, _kinds in ANALYZERS:
            for rule in rules:
                out.append({"rule_id": rule, "analyzer": analyzer_id, "evaluations": evaluated.get(rule, 0),
                            "findings": counts.get(rule, 0)})
        return out

    def analyzer_status(self) -> List[dict]:
        out = []
        for analyzer_id, version, _rules, kinds in ANALYZERS:
            files = [c for c in self.coverage if c.analyzer == analyzer_id]
            if not files:
                status = "not_applicable"
            elif all(c.status == "analyzed" for c in files):
                status = "ok"
            elif any(c.status in ("analyzed", "partial") for c in files):
                status = "partial"
            else:
                status = "unavailable"
            out.append({"id": analyzer_id, "version": version, "kind": "deterministic", "status": status,
                        "files": len(files), "input_kinds": list(kinds)})
        return out


def _is_override(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name in ("override.tf", "override.tf.json") or name.endswith(("_override.tf", "_override.tf.json"))


def _terraform_merge_hazards(parsed_tf) -> Dict[str, List[CoverageNote]]:
    """Terraform merges override files into base blocks and treats a module directory as one config.
    P02 analyses files individually, so any merge situation makes coverage partial for that directory."""
    notes: Dict[str, List[CoverageNote]] = {}
    by_dir: Dict[str, List[str]] = {}
    for path in parsed_tf:
        by_dir.setdefault(path.rsplit("/", 1)[0] if "/" in path else "", []).append(path)
    for directory, paths in sorted(by_dir.items()):
        overrides = sorted(p for p in paths if _is_override(p))
        addresses: Dict[str, List[str]] = {}
        for p in paths:
            items, err = parsed_tf[p]
            for b in items or []:
                if getattr(b, "type", None) in ("resource", "data") and len(b.labels) == 2:
                    addresses.setdefault(f"{b.type}.{b.labels[0]}.{b.labels[1]}", []).append(p)
        dup = sorted(a for a, ps in addresses.items() if len(ps) > 1)
        if overrides:
            for p in paths:
                notes.setdefault(p, []).append(CoverageNote(
                    "TF_OVERRIDE_NOT_MERGED", "Directory contains Terraform override file(s); their merge into "
                    "base blocks is not evaluated, so effective values may differ from those analysed."))
        if dup:
            for a in dup:
                for p in sorted(set(addresses[a])):
                    notes.setdefault(p, []).append(CoverageNote(
                        "TF_DUPLICATE_BLOCK_ADDRESS", "A resource/data block address is declared more than once "
                        "in this directory; effective configuration is not evaluated."))
    return notes


def analyze(outcome: IntakeOutcome) -> AnalysisOutcome:
    result = AnalysisOutcome()
    records = sorted(outcome.accepted, key=lambda r: r.path)

    # Terraform: parse every file first so policy-document references can be resolved across files.
    parsed_tf = {}
    for rec in records:
        if rec.kind in TERRAFORM_KINDS:
            parsed_tf[rec.path] = rules_terraform.parse_file(outcome.contents[rec.path])
    policy_docs = set()
    for items, err in parsed_tf.values():
        if items is not None:
            policy_docs |= rules_terraform.declared_policy_documents(items)
    tf_merge_notes = _terraform_merge_hazards(parsed_tf)

    for rec in records:
        text = outcome.contents[rec.path]
        if rec.kind in TERRAFORM_KINDS:
            items, err = parsed_tf[rec.path]
            if err is not None:
                status, note = err
                cov = FileCoverage(rec.path, rec.kind, rules_terraform.ANALYZER_ID,
                                   rules_terraform.ANALYZER_VERSION, status, notes=[note])
                result.coverage.append(cov)
                continue
            cov, found = rules_terraform.analyze_terraform(rec.path, rec.sha256, items, rec.kind, policy_docs)
            for note in tf_merge_notes.get(rec.path, []):
                cov.status = "partial"
                cov.notes.append(note)
        elif rec.kind in PLAN_KINDS:
            cov, found = rules_plan.analyze_plan(rec.path, rec.sha256, text, rec.kind)
        elif rec.kind in YAML_KINDS:
            docs, err = rules_k8s.parse_file(text)
            if err is not None:
                status, note = err
                result.coverage.append(FileCoverage(rec.path, rec.kind, rules_k8s.ANALYZER_ID,
                                                    rules_k8s.ANALYZER_VERSION, status, notes=[note]))
                continue
            cov, found = rules_k8s.analyze_k8s(rec.path, rec.sha256, docs, rec.kind)
            if rec.kind == "helm-rendered":
                cov.notes.append(CoverageNote("HELM_RENDERED_ONLY",
                                              "Rendered output only; Helm was not run and template/values "
                                              "combinations not present here are untested."))
        else:
            cov = FileCoverage(rec.path, rec.kind, None, None, "not_analyzed",
                               notes=[CoverageNote("NO_ANALYZER", NOT_ANALYZED_KINDS.get(
                                   rec.kind, "No Phase 2 analyzer for this kind."))])
            found = []
        result.coverage.append(cov)
        result.findings.extend(found)
    result.findings = merge_findings(result.findings)
    return result
