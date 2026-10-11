"""Run-result contract v2 (``p02review review``) and its deterministic self-validation.

v1 (``p02review ingest``) is untouched in result.py. v2 adds per-file analysis coverage, rule
coverage, analyzer status, located evidence and the Phase 2 policy decision. Every evidence
record is resolved against the source inventory before output; any breach is an internal error.
"""

from __future__ import annotations

import json
import re
from typing import List, Optional

from . import TOOL_NAME
from . import errors as E
from . import policy_v2
from .analysis import ANALYZERS, AnalysisOutcome
from .errors import InputIssue, ResultValidationError, display_path
from .identity import canonical_json_bytes, input_identity, sha256_hex
from .intake import IntakeOutcome
from .limits import Limits
from .result import (STATUS_COMPLETED, STATUS_INTERNAL_ERROR, STATUS_REJECTED, STATUSES, _bounded_errors,
                     _external_actions, _walk_strings)
from .secret_screen import SCREEN_ID, SCREEN_VERSION, screen_text

RESULT_SCHEMA_VERSION_V2 = "p02.run-result.v2"
TOOL_VERSION_V2 = "0.2.0"
PHASE_V2 = "phase-2-deterministic-iac-baseline"

TOP_LEVEL_KEYS_V2 = (
    "schema_version", "tool", "run_id", "status", "input_identity", "source_inventory", "coverage",
    "tool_status", "rule_coverage", "evidence", "findings", "policy", "errors", "errors_total",
    "errors_truncated", "limits", "external_actions", "run_context",
)
_RUN_ID_RE = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")
_FORBIDDEN_WORDS = ("safe", "passed", "pass", "approved", "clean")


def _fixed_tool_status(intake_state: str, screen_state: str) -> list:
    return [
        {"id": "intake-validator", "status": intake_state, "kind": "deterministic"},
        {"id": SCREEN_ID, "version": SCREEN_VERSION, "status": screen_state, "kind": "deterministic",
         "note": "Lightweight pattern screen; not a complete secrets scanner."},
        {"id": "terraform-binary", "status": "not_used", "kind": "deterministic",
         "note": "Terraform is never executed; plans are read only as supplied JSON artifacts."},
        {"id": "helm-binary", "status": "not_used", "kind": "deterministic",
         "note": "Helm is never executed; only submitted rendered YAML is analysed."},
        {"id": "llm-contextual-reviewer", "status": "disabled", "kind": "model",
         "note": "No model is configured or authorized; model calls are zero."},
    ]


def _secret_records(outcome: IntakeOutcome):
    evidence, findings = [], []
    for path, _sha, hit in sorted(outcome.secret_hits, key=lambda t: (t[0], t[2].line or 0, t[2].rule_id)):
        shown = display_path(path)
        key = sha256_hex(canonical_json_bytes(["secret", hit.rule_id, path, hit.line]))
        ev_id, f_id = "E-" + key[:16], "F-" + key[:16]
        evidence.append({"id": ev_id, "kind": "source_lines", "path": shown, "line_start": hit.line,
                         "line_end": hit.line, "plan_address": None, "json_pointer": None, "source_sha256": None,
                         "analyzer": SCREEN_ID, "analyzer_version": SCREEN_VERSION, "rule_id": hit.rule_id,
                         "observation": "Value matched a credential pattern; value and file digest withheld.",
                         "validation_status": "digest_withheld"})
        findings.append({"id": f_id, "rule_id": hit.rule_id, "category": "secrets", "severity": "high",
                         "state": "suspected", "provenance": "deterministic", "analyzer": SCREEN_ID,
                         "resource": shown, "location": {"path": shown, "line_start": hit.line,
                                                         "line_end": hit.line, "plan_address": None},
                         "evidence_ids": [ev_id],
                         "summary": "Possible credential detected; the run was blocked and the value is redacted.",
                         "rationale": "Pattern-based screen; analysis does not run on secret-bearing input.",
                         "recommended_check": "Remove the credential from the fixture and rotate it if it was ever real."})
    return evidence, findings


def build_result_v2(outcome: Optional[IntakeOutcome], analysis: Optional[AnalysisOutcome], *, limits: Limits,
                    elapsed_ms: int, structural_issue: Optional[InputIssue] = None,
                    internal_error: Optional[str] = None, run_id: Optional[str] = None) -> dict:
    issues: List[InputIssue] = []
    if structural_issue is not None:
        issues.append(structural_issue)
    if outcome is not None:
        issues.extend(outcome.issues)
    secret_blocked = bool(outcome and outcome.secret_hits)
    for path, _sha, hit in (outcome.secret_hits if outcome else []):
        issues.append(InputIssue(E.SECRET_SUSPECTED, f"Possible credential (rule {hit.rule_id}); value redacted.",
                                 display_path(path), hit.line))
    inventory = [r.as_dict() for r in sorted(outcome.accepted, key=lambda r: r.path)] if outcome else []

    if internal_error is not None:
        status = STATUS_INTERNAL_ERROR
        issues = [InputIssue(E.INTERNAL_ERROR, f"Unexpected internal failure ({internal_error}); details withheld.")]
        inventory, analysis = [], None
    elif issues:
        status = STATUS_REJECTED
        analysis = None  # never analyse rejected input
    else:
        status = STATUS_COMPLETED

    evidence: list = []
    findings: list = []
    if status == STATUS_REJECTED and outcome is not None:
        evidence, findings = _secret_records(outcome)
    finding_objs = []
    if status == STATUS_COMPLETED and analysis is not None:
        finding_objs = analysis.findings
        seen = set()
        for f in finding_objs:
            for e in f.evidence:
                if e.id not in seen:
                    seen.add(e.id)
                    evidence.append(e.as_dict())
            findings.append(f.as_dict())
        evidence.sort(key=lambda e: (e["path"], e["line_start"] or 0, e["plan_address"] or "", e["id"]))

    identity = None
    if status == STATUS_COMPLETED and outcome is not None and outcome.manifest is not None:
        identity = input_identity(outcome.manifest, outcome.accepted)

    complete = analysis.complete if analysis is not None else False
    policy = policy_v2.decide(finding_objs, complete if status == STATUS_COMPLETED else None,
                              input_rejected=status == STATUS_REJECTED,
                              secret_blocked=secret_blocked and status != STATUS_INTERNAL_ERROR,
                              internal_error=status == STATUS_INTERNAL_ERROR)

    intake_state = {"completed": "ok", "rejected": "rejected"}.get(status, "error")
    screen_state = "not_run" if (status == STATUS_INTERNAL_ERROR or outcome is None) else (
        "hits" if secret_blocked else "no_hits")
    tool_status = _fixed_tool_status(intake_state, screen_state)
    if analysis is not None:
        tool_status[2:2] = analysis.analyzer_status()
    else:
        tool_status[2:2] = [{"id": a, "version": v, "kind": "deterministic", "status": "not_run", "files": 0,
                             "input_kinds": list(k)} for a, v, _r, k in ANALYZERS]

    error_list, error_total, truncated = _bounded_errors(issues, limits)
    if run_id is None:
        basis = {"command": "review", "tool": TOOL_VERSION_V2, "limits": limits.fingerprint(),
                 "analyzers": [[a, v] for a, v, _r, _k in ANALYZERS]}
        if identity is not None:
            basis["input"] = identity["input_identity_sha256"]
        else:
            basis["status"] = status
            basis["manifest_sha256"] = outcome.manifest_sha256 if outcome else None
            basis["errors"] = [[e["code"], e.get("path"), e.get("line")] for e in error_list]
        run_id = "run-" + sha256_hex(canonical_json_bytes(basis))[:24]

    coverage_state = {"completed": "analyzed_complete" if complete else "analyzed_incomplete",
                      "rejected": "input_rejected"}.get(status, "not_assessed_internal_error")
    result = {
        "schema_version": RESULT_SCHEMA_VERSION_V2,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION_V2, "phase": PHASE_V2},
        "run_id": run_id,
        "status": status,
        "input_identity": identity,
        "source_inventory": inventory,
        "coverage": {
            "state": coverage_state,
            "analysis_complete": bool(complete and status == STATUS_COMPLETED),
            "files_declared": outcome.files_declared if outcome else 0,
            "files_accepted": len(inventory),
            "bytes_accepted": sum(r["size_bytes"] for r in inventory),
            "files": [c.as_dict() for c in analysis.coverage] if analysis is not None else [],
            "statement": "Coverage is limited to the Phase 2 baseline rules and the documented HCL/YAML "
                         "subsets; files outside them are reported, never assumed clean.",
        },
        "tool_status": tool_status,
        "rule_coverage": analysis.rule_coverage() if analysis is not None else [],
        "evidence": evidence,
        "findings": findings,
        "policy": policy,
        "errors": error_list,
        "errors_total": error_total,
        "errors_truncated": truncated,
        "limits": {"values": limits.as_dict(), "fingerprint_sha256": limits.fingerprint(),
                   "note": "Provisional defaults; not approved production limits."},
        "external_actions": _external_actions(),
        "run_context": {"elapsed_ms": int(elapsed_ms), "note": "Volatile; excluded from input identity and run_id."},
    }
    validate_result_v2(result)
    return result


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ResultValidationError(msg)


def validate_result_v2(result: dict) -> None:
    _require(tuple(result.keys()) == TOP_LEVEL_KEYS_V2, "unexpected top-level keys")
    _require(result["schema_version"] == RESULT_SCHEMA_VERSION_V2, "schema_version")
    _require(isinstance(result["run_id"], str) and bool(_RUN_ID_RE.match(result["run_id"])), "run_id")
    _require(result["status"] in STATUSES, "status")
    pol = result["policy"]
    _require(pol["decision"] in policy_v2.DECISIONS, "decision")
    _require(pol["human_review_required"] is True, "human review always required")
    _require(all(r in policy_v2.REASONS for r in pol["reasons"]), "reason vocabulary")
    for word in _FORBIDDEN_WORDS:
        _require(result["status"] != word and pol["decision"] != word, "forbidden word")
    findings = result["findings"]
    confirmed_high = any(f["state"] == "confirmed_by_rule" and f["severity"] in ("high", "critical") for f in findings)
    uncertain = any(f["state"] in ("insufficient_evidence", "unsupported") or
                    (f["state"] == "suspected" and f["severity"] in ("high", "critical")) for f in findings)
    # Independent cross-checks of the rubric (fail closed if the gate and the data disagree).
    if result["status"] != STATUS_COMPLETED:
        _require(pol["decision"] == "inconclusive", "non-completed runs are inconclusive")
        _require(result["input_identity"] is None and bool(result["errors"]), "non-completed needs errors")
    else:
        _require(result["input_identity"] is not None and not result["errors"], "completed needs identity")
        if confirmed_high:
            _require(pol["decision"] == "review_required", "confirmed high must require review")
        if pol["decision"] == "no_blocking_findings_detected":
            _require(result["coverage"]["analysis_complete"] is True, "no_blocking needs complete coverage")
            _require(all(f["status"] == "analyzed" for f in result["coverage"]["files"]), "no_blocking file status")
            _require(len(result["coverage"]["files"]) == len(result["source_inventory"]) > 0, "coverage per file")
            _require(not uncertain and not confirmed_high, "no_blocking with uncertain/blocking findings")
        if not result["coverage"]["analysis_complete"]:
            _require(policy_v2.R_COVERAGE in pol["reasons"], "incomplete coverage must be a stated reason")
    # Evidence resolution against the inventory.
    inv = {r["path"]: r for r in result["source_inventory"]}
    ev_ids = set()
    for e in result["evidence"]:
        ev_ids.add(e["id"])
        if result["status"] != STATUS_COMPLETED:
            continue
        rec = inv.get(e["path"])
        _require(rec is not None, "evidence path not in inventory")
        _require(e["source_sha256"] == rec["sha256"], "evidence digest mismatch")
        _require(e["validation_status"] == "resolved_against_inventory", "evidence status")
        if e["kind"] == "source_lines":
            _require(isinstance(e["line_start"], int) and isinstance(e["line_end"], int), "line interval")
            _require(1 <= e["line_start"] <= e["line_end"] <= max(rec["line_count"], 1), "line interval bounds")
        else:
            _require(e["kind"] == "plan_resource" and bool(e["plan_address"]) and bool(e["json_pointer"]),
                     "plan evidence needs address and pointer")
    for f in findings:
        _require(f["provenance"] == "deterministic", "deterministic only")
        _require(bool(f["evidence_ids"]) and set(f["evidence_ids"]) <= ev_ids, "finding without evidence")
    ext = result["external_actions"]
    _require(all(ext[k] == 0 for k in ("network_calls", "model_calls", "subprocess_invocations",
                                       "repository_writes", "cloud_api_calls")), "external actions")
    serialized = json.dumps(result, sort_keys=True, ensure_ascii=False)
    _require(not screen_text(serialized, 1), "result contains credential-shaped content")
    for text in _walk_strings(result):
        _require(not screen_text(text, 1), "result contains credential-shaped content")
