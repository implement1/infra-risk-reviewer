"""Phase 2 deterministic policy gate (rubric: docs/adr/ADR-0001 section 5).

Both dimensions stay visible: severe findings are never suppressed by coverage gaps, and
coverage gaps are never hidden by severe findings. ``no_blocking_findings_detected`` means only
that this baseline rule set detected no blocking finding with complete coverage.
"""

from __future__ import annotations

from typing import List, Optional

from .findings import Finding

DECISIONS = ("review_required", "no_blocking_findings_detected", "inconclusive")
BLOCKING_SEVERITIES = ("high", "critical")

R_INPUT_REJECTED = "INPUT_REJECTED"
R_SECRET = "SUSPECTED_SECRET_BLOCKED"
R_INTERNAL = "INTERNAL_ERROR"
R_CONFIRMED_HIGH = "CONFIRMED_HIGH_SEVERITY_FINDING"
R_SUSPECTED_HIGH = "SUSPECTED_HIGH_SEVERITY_FINDING"
R_INSUFFICIENT = "INSUFFICIENT_EVIDENCE_FINDING"
R_COVERAGE = "COVERAGE_INCOMPLETE"
R_NO_BLOCKING = "NO_BLOCKING_FINDING_IN_BASELINE_RULES"
REASONS = (R_INPUT_REJECTED, R_SECRET, R_INTERNAL, R_CONFIRMED_HIGH, R_SUSPECTED_HIGH, R_INSUFFICIENT,
           R_COVERAGE, R_NO_BLOCKING)

STATEMENTS = {
    "review_required": "At least one high-severity finding was confirmed by a deterministic rule. Human review "
                       "is required before merge. Coverage gaps, if any, are listed separately.",
    "no_blocking_findings_detected": "Every declared file was parsed and every applicable Phase 2 rule ran; no "
                                     "blocking finding was detected by this baseline rule set. This is NOT a "
                                     "statement that the change is safe.",
    "inconclusive": "The baseline rules could not establish the required coverage or evidence, so no clean "
                    "disposition is possible. Unknown is not treated as safe.",
}


def decide(findings: List[Finding], coverage_complete: Optional[bool], *, input_rejected: bool = False,
           secret_blocked: bool = False, internal_error: bool = False) -> dict:
    reasons: List[str] = []
    if internal_error or input_rejected:
        if input_rejected:
            reasons.append(R_INPUT_REJECTED)
        if secret_blocked:
            reasons.append(R_SECRET)
        if internal_error:
            reasons.append(R_INTERNAL)
        decision = "inconclusive"
        performed = False
    else:
        performed = True
        confirmed_high = any(f.state == "confirmed_by_rule" and f.severity in BLOCKING_SEVERITIES for f in findings)
        suspected_high = any(f.state == "suspected" and f.severity in BLOCKING_SEVERITIES for f in findings)
        insufficient = any(f.state in ("insufficient_evidence", "unsupported") for f in findings)
        if confirmed_high:
            reasons.append(R_CONFIRMED_HIGH)
        if suspected_high:
            reasons.append(R_SUSPECTED_HIGH)
        if insufficient:
            reasons.append(R_INSUFFICIENT)
        if not coverage_complete:
            reasons.append(R_COVERAGE)
        if confirmed_high:
            decision = "review_required"
        elif coverage_complete and not suspected_high and not insufficient:
            decision = "no_blocking_findings_detected"
            reasons.append(R_NO_BLOCKING)
        else:
            decision = "inconclusive"
    if decision not in DECISIONS:  # explicit, not stripped by -O
        raise RuntimeError("invalid decision")
    return {
        "decision": decision,
        "risk_assessment_performed": performed,
        # Merge/deploy decisions always stay with humans (FR-04); this flag never reads as "skip review".
        "human_review_required": True,
        "blocking_review_required": decision == "review_required",
        "reasons": reasons,
        "statement": STATEMENTS[decision],
        "rubric": "docs/adr/ADR-0001-phase2-parsers-rules-and-policy.md#5-policy-rubric-phase-2-gate",
    }
