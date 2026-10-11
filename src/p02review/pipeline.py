"""Single implementation of the Phase 2 `review` pipeline, shared by `review` and Phase 3A `explain`.

The body is the accepted Phase 2 `cli._review` logic moved here unchanged, so that re-derivation in
Phase 3A can never drift from `review`. Byte-identity is enforced by tests/test_p3_pins.py (golden v2).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from .analysis import AnalysisOutcome, analyze, decoded_secret_hits
from .errors import InputRejected, ResultValidationError
from .intake import IntakeOutcome, run_intake
from .result_v2 import build_result_v2

_FALLBACK_V2 = {"schema_version": "p02.run-result.v2", "status": "internal_error",
                "policy": {"decision": "inconclusive"},
                "errors": [{"code": "INTERNAL_ERROR", "message": "Result construction failed; details withheld."}]}


@dataclass
class PipelineRun:
    result: dict
    outcome: Optional[IntakeOutcome]
    analysis: Optional[AnalysisOutcome]


def _elapsed(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def review_pipeline(fixture_dir: str, limits, run_id: Optional[str], started: float) -> PipelineRun:
    """Phase 2 contract: manifest v1 or v2, deterministic analysis, p02.run-result.v2."""
    outcome = None
    try:
        try:
            outcome = run_intake(fixture_dir, limits, manifest_versions=("1", "2"))
        except InputRejected as exc:
            return PipelineRun(build_result_v2(outcome, None, limits=limits, run_id=run_id,
                                               structural_issue=exc.issue, elapsed_ms=_elapsed(started)),
                               outcome, None)
        # Hardening L2: the decoded-credential screen runs whenever intake read sources safely, even if an
        # unrelated issue was found; a suspected credential takes precedence (exit 4) over other issues (exit 3).
        for path, hit in decoded_secret_hits(outcome):  # escaped credentials block the run (exit 4)
            outcome.secret_hits.append((path, None, hit))
            outcome.accepted = [r for r in outcome.accepted if r.path != path]
        rejected = bool(outcome.issues or outcome.secret_hits)
        analysis = None if rejected else analyze(outcome)
        return PipelineRun(build_result_v2(outcome, analysis, limits=limits, run_id=run_id,
                                           elapsed_ms=_elapsed(started)), outcome, analysis)
    except Exception as exc:  # internal failure: report type only, never the message (may contain data)
        try:
            return PipelineRun(build_result_v2(None, None, limits=limits, run_id=run_id,
                                               internal_error=type(exc).__name__, elapsed_ms=_elapsed(started)),
                               None, None)
        except (ResultValidationError, Exception):
            return PipelineRun(dict(_FALLBACK_V2), None, None)
