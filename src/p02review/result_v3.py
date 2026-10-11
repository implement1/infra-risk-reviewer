"""Phase 3A advisory report contract `p02.report.v3` (`p02review explain`).

v3 is derived only from a v2 result that the same code re-derived from the same fixture
(P3-INV-10). It embeds the v2 policy and coverage verbatim (P3-INV-02), contains no source
excerpts (P3-INV-12), and every generated sentence comes from a fixed template with typed slots
and validated citations (P3-INV-15). `validate_result_v3` fails closed on any breach.
"""

from __future__ import annotations

import json
import re
from typing import List, Optional

from . import TOOL_NAME
from . import policy_v2
from .errors import ResultValidationError
from .identity import canonical_json_bytes, sha256_hex
from .result import _external_actions, _walk_strings
from .secret_screen import screen_text

REPORT_SCHEMA_VERSION_V3 = "p02.report.v3"
TOOL_VERSION_V3 = "0.3.0"
PHASE_V3 = "phase-3a-deterministic-reconciliation"
TEMPLATE_CATALOGUE_VERSION = "2"  # v2: corrective pass (C1 questions, C2 link citations)

STATUS_COMPLETED = "completed"
STATUS_REJECTED = "rejected"
STATUS_INTERNAL = "internal_error"
STATUS_MISMATCH = "v2_mismatch"
STATUSES_V3 = (STATUS_COMPLETED, STATUS_REJECTED, STATUS_INTERNAL, STATUS_MISMATCH)

TOP_LEVEL_KEYS_V3 = (
    "schema_version", "tool", "run_id", "status", "v2_reference", "v2_policy", "coverage", "groups", "links",
    "explanation", "verification_questions", "unknowns", "limitations", "model", "errors", "errors_total",
    "errors_truncated", "external_actions", "run_context",
)
SECTION_ORDER = ("decision", "coverage", "findings", "links")
CLAIM_TYPES = ("decision_fact", "coverage_fact", "fact_from_rule", "link_candidate", "unknown",
               "verification_question")
LINK_TYPES = ("unlinked", "candidate_same_type_name")  # "linked" is never emitted (decision N2)

# Phrases that could read as a safety clearance; never allowed in v3-generated text (risk R2).
BANNED_PHRASES = ("safe", "secure", "no risk", "approved", "clean", "passed", "no issues", "nothing to worry",
                  "guarantee", "all clear", "harmless", "verified safe", "can be ignored", "not a concern")
# Substring match, no word boundaries: "safe_bucket" or "XSafe2" must not slip through (verifier D3).
_BANNED_RE = re.compile("|".join(re.escape(p) for p in BANNED_PHRASES), re.IGNORECASE)

# Phase 3A output gate (verifier D1). The shared Phase 1/2 screen anchors tokens with \b, so a credential
# joined to a word character ("sg_<key>", "<key>_x") passes it. v3 additionally refuses any report whose
# content matches these unanchored shapes. Phase 1/2 behaviour is unchanged (pinned; see ADR-0003).
_STRICT_SECRET_RES = (
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),  # fully unanchored; fails closed on any embedded key shape
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
)


def strict_secret_hit(text: str) -> bool:
    return any(r.search(text) for r in _STRICT_SECRET_RES)
_RUN_ID_RE = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")
_TEXT_OK = re.compile(r"\A[\x20-\x7e]*\Z")
MAX_TEXT = 600
MAX_SENTENCES = 2000

LIMITATIONS = (
    "Advisory report derived from the deterministic Phase 2 baseline; it does not change any finding, severity, "
    "coverage status or policy decision.",
    "Parsers cover documented HCL and YAML subsets only; files outside them are reported as coverage gaps.",
    "Variables, modules, override merges and runtime state are not resolved.",
    "Plan-to-configuration relationships are reported only as unlinked or as candidates; module membership is "
    "never verified.",
    "No source excerpts are included.",
    "Phase 2 blind hold-out: 24/25 decisions with frozen labels, 25/25 after three documented label corrections; "
    "small synthetic corpora, not production accuracy.",
    "No language model was used.",
)


def v2_digest(v2: dict) -> str:
    return sha256_hex(canonical_json_bytes({k: v for k, v in v2.items() if k != "run_context"}))


def build_result_v3(*, status: str, v2: Optional[dict], supplied: dict, errors: List[dict], groups: list,
                    links: list, sections: list, questions: list, unknowns: list, elapsed_ms: int) -> dict:
    v2 = v2 or {}
    digest = v2_digest(v2) if v2 else None
    identity = v2.get("input_identity") if isinstance(v2.get("input_identity"), dict) else None
    run_id = "run3-" + sha256_hex(canonical_json_bytes({
        "tool": TOOL_VERSION_V3, "catalogue": TEMPLATE_CATALOGUE_VERSION, "v2": digest, "status": status,
        "supplied": supplied, "errors": [e.get("code") for e in errors]}))[:24]
    coverage = v2.get("coverage") or {}
    error_list = errors[:50]
    result = {
        "schema_version": REPORT_SCHEMA_VERSION_V3,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION_V3, "phase": PHASE_V3,
                 "template_catalogue_version": TEMPLATE_CATALOGUE_VERSION},
        "run_id": run_id,
        "status": status,
        "v2_reference": {
            "schema_version": v2.get("schema_version"),
            "run_id": v2.get("run_id"),
            "status": v2.get("status"),
            "result_sha256": digest,
            "input_identity_sha256": identity["input_identity_sha256"] if identity else None,
            "supplied_result": supplied,
        },
        "v2_policy": v2.get("policy"),
        "coverage": {"state": coverage.get("state"), "analysis_complete": coverage.get("analysis_complete"),
                     "files": coverage.get("files", [])},
        "groups": groups,
        "links": links,
        "explanation": {"template_catalogue_version": TEMPLATE_CATALOGUE_VERSION, "sections": sections},
        "verification_questions": questions,
        "unknowns": unknowns,
        "limitations": list(LIMITATIONS),
        "model": {"backend": "none", "status": "disabled", "ledger_id": None,
                  "note": "No model backend is implemented or authorized in Phase 3A."},
        "errors": error_list,
        "errors_total": len(errors),
        "errors_truncated": len(errors) > len(error_list),
        "external_actions": _external_actions(),
        "run_context": {"elapsed_ms": int(elapsed_ms), "note": "Volatile; excluded from run_id."},
    }
    return result


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ResultValidationError(msg)


def generated_texts(result: dict):
    """Every string produced by Phase 3A templates (v2 material embedded verbatim is excluded)."""
    for section in result["explanation"]["sections"]:
        for s in section["sentences"]:
            yield s["text"]
    for q in result["verification_questions"]:
        yield q["text"]
    for u in result["unknowns"]:
        yield u["text"]
    yield from result["limitations"]


def validate_result_v3(result: dict, v2: Optional[dict] = None) -> None:
    _require(isinstance(result, dict) and tuple(result) == TOP_LEVEL_KEYS_V3, "unexpected top-level keys")
    _require(result["schema_version"] == REPORT_SCHEMA_VERSION_V3, "schema_version")
    _require(bool(_RUN_ID_RE.match(result["run_id"])), "run_id")
    _require(result["status"] in STATUSES_V3, "status")
    model = result["model"]
    _require(model["backend"] == "none" and model["status"] == "disabled" and model["ledger_id"] is None, "model")
    ext = result["external_actions"]
    _require(all(ext[k] == 0 for k in ("network_calls", "model_calls", "subprocess_invocations",
                                       "repository_writes", "cloud_api_calls")), "external actions")
    narrative_empty = (not result["groups"] and not result["links"] and not result["explanation"]["sections"]
                       and not result["verification_questions"] and not result["unknowns"])
    if result["status"] != STATUS_COMPLETED:
        _require(narrative_empty, "no narrative on non-completed runs")
        _require(bool(result["errors"]), "non-completed needs errors")
    else:
        _require(not result["errors"], "completed has no errors")
        _require(result["v2_reference"]["status"] == "completed", "completed needs completed v2")
        _require(result["v2_reference"]["supplied_result"]["matched"] in (True, None), "supplied must match")
        ids = [s["id"] for s in result["explanation"]["sections"]]
        _require(ids == [i for i in SECTION_ORDER if i in ids] and ids[:2] == ["decision", "coverage"],
                 "section order: decision and coverage first")
    if result["v2_policy"] is not None:
        _require(result["v2_policy"].get("decision") in policy_v2.DECISIONS, "v2 decision vocabulary")
    for link in result["links"]:
        _require(link["link_type"] in LINK_TYPES, "link type")
        _require("module-membership-unverified" in link["basis"], "every link basis records unverified membership")
    sentences = [s for sec in result["explanation"]["sections"] for s in sec["sentences"]]
    _require(len(sentences) + len(result["verification_questions"]) <= MAX_SENTENCES, "too many sentences")
    for s in sentences:
        _require(s["claim_type"] in CLAIM_TYPES, "claim type")
        if s["claim_type"] == "fact_from_rule":
            _require(bool(s["evidence_ids"]) and bool(s["finding_ids"]), "rule facts must cite evidence")
        if s["claim_type"] == "coverage_fact":
            _require(bool(s["coverage_refs"]), "coverage facts must cite coverage")
        if s["claim_type"] == "decision_fact":
            _require(bool(s["reason_codes"]), "decision facts must cite reasons")
        if s["claim_type"] == "link_candidate":
            _require(bool(s["finding_ids"]), "link sentences must cite findings")
    for q in result["verification_questions"]:
        _require(q["text"].endswith("?"), "questions end with '?'")
        _require(bool(q["finding_ids"]) or bool(q["coverage_refs"]), "questions must cite what they ask about")
    for text in generated_texts(result):
        _require(isinstance(text, str) and 0 < len(text) <= MAX_TEXT, "text length")
        _require(bool(_TEXT_OK.match(text)), "generated text must be printable ASCII")
        _require(not _BANNED_RE.search(text), "banned phrase in generated text")
    if v2 is not None:
        _cross_check(result, v2)
    serialized = json.dumps(result, sort_keys=True, ensure_ascii=False)
    _require(not screen_text(serialized, 1), "credential-shaped content")
    _require(not strict_secret_hit(serialized), "credential-shaped content")
    for text in _walk_strings(result):
        _require(not screen_text(text, 1), "credential-shaped content")


_QUESTION_REASONS = {"TF-NET-001": ("PUBLIC_ADMIN_INGRESS",),
                     "PLAN-DEL-001": ("DESTRUCTIVE_CHANGE", "CONNECTIVITY_RISK"),
                     "PLAN-REP-001": ("DESTRUCTIVE_CHANGE", "CONNECTIVITY_RISK"),
                     "PLAN-REP-002": ("DESTRUCTIVE_CHANGE", "CONNECTIVITY_RISK")}


def _required_questions_present(result: dict, findings: dict) -> bool:
    """Corrective pass C1: every confirmed public-admin-ingress, delete or destroy-before-create finding, and
    every high-severity replacement, is cited (with all its evidence) by a question of the matching kind."""
    for fid, f in findings.items():
        rule = f["rule_id"]
        if f["state"] != "confirmed_by_rule" or rule not in _QUESTION_REASONS:
            continue
        if rule == "PLAN-REP-002" and f["severity"] != "high":
            continue
        if not any(fid in q["finding_ids"] and set(f["evidence_ids"]) <= set(q["evidence_ids"])
                   and q["reason_code"] in _QUESTION_REASONS[rule] for q in result["verification_questions"]):
            return False
    return True


def _cross_check(result: dict, v2: dict) -> None:
    """Immutability and citation resolution against the re-derived v2 (P3-INV-02, P3-INV-06)."""
    _require(result["v2_policy"] == v2.get("policy"), "v2 policy must be embedded verbatim")
    _require(result["v2_reference"]["result_sha256"] == v2_digest(v2), "v2 digest")
    _require(result["coverage"]["files"] == (v2.get("coverage") or {}).get("files", []), "coverage verbatim")
    findings = {f["id"]: f for f in v2.get("findings", [])}
    evidence = {e["id"] for e in v2.get("evidence", [])}
    grouped = [fid for g in result["groups"] for fid in g["finding_ids"]]
    if result["status"] == STATUS_COMPLETED:
        _require(sorted(grouped) == sorted(findings), "every v2 finding appears in exactly one group")
    for g in result["groups"]:
        members = [findings[fid] for fid in g["finding_ids"] if fid in findings]
        _require(len(members) == len(g["finding_ids"]), "group cites unknown finding")
        _require(g["rule_ids"] == sorted({m["rule_id"] for m in members}), "group rule ids")
        _require(g["states"] == sorted({m["state"] for m in members}), "group states unchanged")
        _require(g["severities"] == sorted({m["severity"] for m in members}), "group severities unchanged")
    coverage_refs = set()
    for f in (v2.get("coverage") or {}).get("files", []):
        coverage_refs.add((f["path"], f["status"]))
        for n in f["notes"]:
            coverage_refs.add((f["path"], n["code"]))
    reasons = set((v2.get("policy") or {}).get("reasons", []))
    items = [s for sec in result["explanation"]["sections"] for s in sec["sentences"]] + result["verification_questions"]
    for s in items:
        _require(set(s["finding_ids"]) <= set(findings), "cites unknown finding")
        _require(set(s["evidence_ids"]) <= evidence, "cites unknown evidence")
        _require(all((r["path"], r["code"]) in coverage_refs for r in s["coverage_refs"]), "cites unknown coverage")
        _require(set(s.get("reason_codes", [])) <= reasons, "cites unknown policy reason")
        for fid in s["finding_ids"]:
            f = findings[fid]
            _require(set(f["evidence_ids"]) & set(s["evidence_ids"]) or not s["evidence_ids"]
                     or s["claim_type"] != "fact_from_rule", "rule facts cite that finding's evidence")
    from . import p3_templates as T  # local import: p3_templates imports this module
    link_sections = [sec for sec in result["explanation"]["sections"] if sec["id"] == "links"]
    link_sentences = link_sections[0]["sentences"] if link_sections else []
    tf_files = [f for f in (v2.get("coverage") or {}).get("files", [])
                if f["kind"] == "terraform" or f["path"].endswith((".tf", ".tf.json"))]
    tf_gaps = [(f["path"], f["status"]) for f in tf_files if f["status"] != "analyzed"]
    if result["status"] == STATUS_COMPLETED:
        _require(len(link_sentences) == len(result["links"]), "one link sentence per link, in order")
        plan_ids = sorted(fid for fid, f in findings.items() if f["rule_id"].startswith("PLAN-"))
        _require(sorted(l["plan_finding_id"] for l in result["links"]) == plan_ids,
                 "exactly one link per plan finding")
        order = [(l["plan_address"] or "", l["link_id"]) for l in result["links"]]
        _require(order == sorted(order), "links in deterministic order")
        _require(_required_questions_present(result, findings), "required verification question missing")
    for link, s in zip(result["links"], link_sentences):
        pf = findings.get(link["plan_finding_id"])
        _require(pf is not None and pf["rule_id"].startswith("PLAN-"), "link must start from a plan finding")
        _require(set(link["static_finding_ids"]) <= set(findings), "link cites unknown static finding")
        # Corrective pass C2: a link sentence cites the plan finding, every static finding and all their evidence.
        ids = [link["plan_finding_id"]] + link["static_finding_ids"]
        _require(s["finding_ids"] == ids, "link sentence cites the plan finding then every static finding")
        _require({e for fid in ids for e in findings[fid]["evidence_ids"]} <= set(s["evidence_ids"]),
                 "link sentence cites the evidence of every linked finding")
        refs = {(r["path"], r["code"]) for r in s["coverage_refs"]}
        if tf_gaps:
            _require(link["link_type"] == "unlinked" and "terraform-coverage-incomplete" in link["basis"],
                     "incomplete Terraform coverage rules out candidates")
            _require(set(tf_gaps) <= refs, "unlinked sentence cites the Terraform coverage gaps")
        if link["link_type"] == "candidate_same_type_name":
            _require(link["basis"] == ["root-address-no-index", "single-static-block", "static-file-analyzed",
                                       "module-membership-unverified"], "candidate basis")
            _require(link["static_resource"] == link["plan_address"], "candidate has the plan entry's TYPE.NAME")
            expected_static = sorted(fid for fid, f in findings.items() if f["resource"] == link["static_resource"]
                                     and f["location"]["path"] == link["static_path"])
            _require(link["static_finding_ids"] == expected_static, "candidate cites every static finding")
            _require(s["template_id"] == T.LINK_CANDIDATE.id and s["text"] == T.LINK_CANDIDATE.render(
                T.display_slots({"plan_address": link["plan_address"], "static_resource": link["static_resource"],
                                 "static_path": link["static_path"],
                                 "span": (link["static_line_start"], link["static_line_start"])})),
                     "candidate sentence is the fixed candidate-only template")
            _require({(f["path"], "analyzed") for f in tf_files} <= refs and all(f["status"] == "analyzed"
                                                                                for f in tf_files),
                     "candidate cites complete Terraform coverage")
            _require((link["static_path"], "analyzed") in refs, "candidate cites its static file coverage")
        else:
            _require(not link["static_finding_ids"] and link["static_path"] is None, "unlinked has no static target")
            _require(s["template_id"] == T.LINK_UNLINKED.id and s["text"] == T.LINK_UNLINKED.render(
                T.display_slots({"plan_address": link["plan_address"], "basis": link["basis"]})),
                     "unlinked sentence is the fixed template")
    for link in result["links"][len(link_sentences):]:
        pf = findings.get(link["plan_finding_id"])
        _require(pf is not None and pf["rule_id"].startswith("PLAN-"), "link must start from a plan finding")
    for u in result["unknowns"]:
        _require((u["path"], u["code"]) in coverage_refs or u["finding_ids"], "unknown must reference v2")
