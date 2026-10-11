"""Run-result construction and deterministic self-validation (fail closed on contract breach)."""

from __future__ import annotations

import json
import re
from typing import List, Optional

from . import PHASE, RESULT_SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION
from . import errors as E
from . import policy
from .errors import InputIssue, ResultValidationError, display_path
from .identity import canonical_json_bytes, input_identity, sha256_hex
from .intake import IntakeOutcome
from .limits import Limits
from .secret_screen import SCREEN_ID, SCREEN_VERSION, screen_text

STATUS_COMPLETED = "completed"
STATUS_REJECTED = "rejected"
STATUS_INTERNAL_ERROR = "internal_error"
STATUSES = (STATUS_COMPLETED, STATUS_REJECTED, STATUS_INTERNAL_ERROR)

TOP_LEVEL_KEYS = (
    "schema_version", "tool", "run_id", "status", "input_identity", "source_inventory",
    "coverage", "tool_status", "evidence", "findings", "policy", "errors", "errors_total",
    "errors_truncated", "limits", "external_actions", "run_context",
)
FORBIDDEN_DECISION_WORDS = ("safe", "passed", "pass", "approved", "clean", "no_blocking_findings_detected")
_RUN_ID_RE = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")

_NOT_IMPLEMENTED = [
    ("terraform-static-analyzer", "Planned for Phase 2; not implemented."),
    ("terraform-plan-json-interpreter", "Planned for Phase 2; not implemented."),
    ("kubernetes-manifest-analyzer", "Planned for Phase 2; not implemented."),
    ("helm-rendered-manifest-analyzer", "Planned for Phase 2; not implemented."),
]


def _tool_status(intake_state: str, screen_state: str) -> list:
    entries = [
        {"id": "intake-validator", "status": intake_state, "kind": "deterministic"},
        {"id": SCREEN_ID, "version": SCREEN_VERSION, "status": screen_state, "kind": "deterministic",
         "note": "Lightweight pattern screen; not a complete secrets scanner."},
    ]
    for tool_id, note in _NOT_IMPLEMENTED:
        entries.append({"id": tool_id, "status": "not_implemented", "kind": "deterministic", "note": note})
    entries.append({"id": "llm-contextual-reviewer", "status": "disabled", "kind": "model",
                    "note": "External model calls are not authorized in Phase 1."})
    return entries


def _bounded_errors(issues: List[InputIssue], limits: Limits):
    # Secret issues first so truncation can never hide them; then stable path/code/line order.
    ordered = sorted(issues, key=lambda i: (i.code != E.SECRET_SUSPECTED, i.path or "", i.code, i.line or 0))
    shown = [i.as_dict() for i in ordered[: limits.max_errors_reported]]
    return shown, len(ordered), len(ordered) > limits.max_errors_reported


def derive_run_id(basis: dict) -> str:
    return "run-" + sha256_hex(canonical_json_bytes(basis))[:24]


def _external_actions() -> dict:
    return {
        "network_calls": 0, "model_calls": 0, "subprocess_invocations": 0,
        "repository_writes": 0, "cloud_api_calls": 0,
        "basis": "Phase 1 code contains no network, model, subprocess, repository or cloud call sites.",
    }


def _secret_findings(outcome: IntakeOutcome):
    evidence, findings = [], []
    for path, file_sha, hit in sorted(outcome.secret_hits, key=lambda t: (t[0], t[2].line or 0, t[2].rule_id)):
        shown = display_path(path)
        key = sha256_hex(canonical_json_bytes([hit.rule_id, path, hit.line, file_sha]))
        ev_id, f_id = "E-" + key[:16], "F-" + key[:16]
        evidence.append({
            "id": ev_id, "path": shown, "line_start": hit.line, "line_end": hit.line,
            "source_sha256": None, "analyzer": SCREEN_ID, "rule_id": hit.rule_id,
            "observation": "Value matched a credential pattern; value and file digest withheld.",
            "validation_status": "unverified",
        })
        findings.append({
            "id": f_id, "category": "secrets", "severity": "high", "state": "suspected",
            "provenance": "deterministic", "rule_id": hit.rule_id, "affected": shown,
            "evidence_ids": [ev_id],
            "summary": "Possible credential detected; the run was blocked and the value is redacted.",
            "recommended_check": "Remove the credential from the fixture and rotate it if it was ever real.",
        })
    return evidence, findings


def build_result(outcome: Optional[IntakeOutcome], *, limits: Limits, elapsed_ms: int,
                 structural_issue: Optional[InputIssue] = None, internal_error: Optional[str] = None,
                 run_id: Optional[str] = None) -> dict:
    issues: List[InputIssue] = []
    if structural_issue is not None:
        issues.append(structural_issue)
    if outcome is not None:
        issues.extend(outcome.issues)
    secret_blocked = bool(outcome and outcome.secret_hits)
    for path, _sha, hit in (outcome.secret_hits if outcome else []):
        issues.append(InputIssue(E.SECRET_SUSPECTED,
                                 f"Possible credential (rule {hit.rule_id}); value redacted.",
                                 display_path(path), hit.line))

    evidence, findings = _secret_findings(outcome) if outcome else ([], [])
    inventory = [r.as_dict() for r in sorted(outcome.accepted, key=lambda r: r.path)] if outcome else []

    if internal_error is not None:
        status = STATUS_INTERNAL_ERROR
        issues = [InputIssue(E.INTERNAL_ERROR,
                             f"Unexpected internal failure ({internal_error}); details withheld.")]
        evidence, findings, inventory = [], [], []
    elif issues:
        status = STATUS_REJECTED
    else:
        status = STATUS_COMPLETED

    identity = None
    if status == STATUS_COMPLETED and outcome is not None and outcome.manifest is not None:
        identity = input_identity(outcome.manifest, outcome.accepted)

    if status == STATUS_COMPLETED:
        coverage_state, intake_state = "ingested_not_risk_assessed", "ok"
    elif status == STATUS_REJECTED:
        coverage_state, intake_state = "input_rejected", "rejected"
    else:
        coverage_state, intake_state = "not_assessed_internal_error", "error"

    if status == STATUS_INTERNAL_ERROR:
        screen_state = "not_run"
    elif outcome is None:
        screen_state = "not_run"
    else:
        screen_state = "hits" if secret_blocked else "no_hits"

    error_list, error_total, truncated = _bounded_errors(issues, limits)
    if run_id is None:
        basis = {"tool": TOOL_VERSION, "limits": limits.fingerprint()}
        if identity is not None:
            basis["input"] = identity["input_identity_sha256"]
        else:
            basis["status"] = status
            basis["manifest_sha256"] = outcome.manifest_sha256 if outcome else None
            basis["errors"] = [[e["code"], e.get("path"), e.get("line")] for e in error_list]
        run_id = derive_run_id(basis)

    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "phase": PHASE},
        "run_id": run_id,
        "status": status,
        "input_identity": identity,
        "source_inventory": inventory,
        "coverage": {
            "state": coverage_state,
            "files_declared": outcome.files_declared if outcome else 0,
            "files_accepted": len(inventory),
            "bytes_accepted": sum(r["size_bytes"] for r in inventory),
            "risk_analyzers_implemented": 0,
            "risk_analyzers_run": 0,
            "statement": "Inventory and provenance only; no infrastructure risk coverage exists in Phase 1.",
        },
        "tool_status": _tool_status(intake_state, screen_state),
        "evidence": evidence,
        "findings": findings,
        "policy": policy.decide(input_rejected=status == STATUS_REJECTED,
                                secret_blocked=secret_blocked and status != STATUS_INTERNAL_ERROR,
                                internal_error=status == STATUS_INTERNAL_ERROR),
        "errors": error_list,
        "errors_total": error_total,
        "errors_truncated": truncated,
        "limits": {"values": limits.as_dict(), "fingerprint_sha256": limits.fingerprint(),
                   "note": "Provisional Phase 1 defaults; not approved production limits."},
        "external_actions": _external_actions(),
        "run_context": {"elapsed_ms": int(elapsed_ms),
                        "note": "Volatile; excluded from input identity and run_id."},
    }
    validate_result(result)
    return result


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ResultValidationError(msg)


def validate_result(result: dict) -> None:
    """Deterministic structural check of our own output; any breach is an internal failure."""
    _require(isinstance(result, dict), "result not an object")
    _require(tuple(result.keys()) == TOP_LEVEL_KEYS, "unexpected top-level keys")
    _require(result["schema_version"] == RESULT_SCHEMA_VERSION, "schema_version")
    _require(isinstance(result["run_id"], str) and bool(_RUN_ID_RE.match(result["run_id"])), "run_id")
    _require(result["status"] in STATUSES, "status")
    pol = result["policy"]
    _require(pol["decision"] in policy.PHASE1_DECISIONS, "policy decision must be inconclusive")
    _require(pol["risk_assessment_performed"] is False, "risk_assessment_performed")
    for word in FORBIDDEN_DECISION_WORDS:
        _require(result["status"] != word and pol["decision"] != word, "forbidden status word")
    _require(isinstance(result["source_inventory"], list), "inventory")
    for rec in result["source_inventory"]:
        _require(set(rec) == {"path", "kind", "size_bytes", "sha256", "line_count", "encoding"}, "record keys")
        _require(bool(re.fullmatch(r"[0-9a-f]{64}", rec["sha256"])), "record sha256")
    if result["status"] == STATUS_COMPLETED:
        _require(result["input_identity"] is not None and not result["errors"], "completed needs identity")
    else:
        _require(result["input_identity"] is None and bool(result["errors"]), "non-completed needs errors")
    ev_ids = {e["id"] for e in result["evidence"]}
    for f in result["findings"]:
        _require(f["provenance"] == "deterministic", "Phase 1 findings are deterministic only")
        _require(bool(f["evidence_ids"]) and set(f["evidence_ids"]) <= ev_ids, "finding without evidence")
    _require(isinstance(result["errors_total"], int) and isinstance(result["errors_truncated"], bool), "errors meta")
    ext = result["external_actions"]
    _require(all(ext[k] == 0 for k in ("network_calls", "model_calls", "subprocess_invocations",
                                       "repository_writes", "cloud_api_calls")), "external actions")
    # Output gate: the serialized result itself must not contain anything credential-shaped.
    serialized = json.dumps(result, sort_keys=True, ensure_ascii=False)
    _require(not screen_text(serialized, 1), "result contains credential-shaped content")
    for text in _walk_strings(result):  # decoded strings too, so JSON escaping cannot hide a value
        _require(not screen_text(text, 1), "result contains credential-shaped content")


def _walk_strings(value):
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
