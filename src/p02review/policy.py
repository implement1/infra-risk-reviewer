"""Deterministic Phase 1 policy gate.

No infrastructure risk analyzers exist in Phase 1, so the only decision this gate can
produce is ``inconclusive``. Empty findings are never treated as a safety clearance.
"""

from __future__ import annotations

from typing import List

PHASE1_DECISIONS = ("inconclusive",)
# Defined by the architecture for later phases; deliberately unreachable here.
FUTURE_DECISIONS = ("review_required", "no_blocking_findings_detected")

REASON_NO_ANALYZERS = "NO_RISK_ANALYZERS_IMPLEMENTED"
REASON_INPUT_REJECTED = "INPUT_REJECTED"
REASON_SECRET_BLOCKED = "SUSPECTED_SECRET_BLOCKED"
REASON_INTERNAL_ERROR = "INTERNAL_ERROR"

STATEMENT = ("Phase 1 performs ingestion, provenance and lightweight secret screening only. "
             "No Terraform, Kubernetes, Helm or plan risk analysis was performed. "
             "An empty findings list is not evidence that the change is safe.")


def decide(*, input_rejected: bool, secret_blocked: bool, internal_error: bool = False) -> dict:
    reasons: List[str] = [REASON_NO_ANALYZERS]
    if input_rejected:
        reasons.append(REASON_INPUT_REJECTED)
    if secret_blocked:
        reasons.append(REASON_SECRET_BLOCKED)
    if internal_error:
        reasons.append(REASON_INTERNAL_ERROR)
    decision = {
        "decision": "inconclusive",
        "risk_assessment_performed": False,
        "human_review_required": True,
        "reasons": reasons,
        "statement": STATEMENT,
    }
    if decision["decision"] not in PHASE1_DECISIONS:  # explicit check; not stripped by -O
        raise RuntimeError("Phase 1 policy gate produced a non-inconclusive decision")
    return decision
