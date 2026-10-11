"""Phase 3A `explain` orchestration: re-derive v2, check a supplied result, mirror non-completed
runs, and assemble the advisory v3 report from deterministic components only.

Data flow (no model, no network, no source excerpts):
  fixture -> pipeline.review_pipeline (same code as `review`) -> [compare supplied v2]
          -> p3_group.group -> p3_correlate.correlate -> p3_narrative.build -> result_v3 (validated)
"""

from __future__ import annotations

import json
import time
from typing import Optional

from . import p3_correlate, p3_group, p3_narrative
from .errors import InputRejected, ResultValidationError
from .p3_gateway import NoneBackend
from .p3_input import read_result_file
from .p3_rederive import compare_supplied, rederive
from .result_v3 import (STATUS_COMPLETED, STATUS_INTERNAL, STATUS_MISMATCH, STATUS_REJECTED, build_result_v3,
                        strict_secret_hit, validate_result_v3)

_FALLBACK_V3 = {"schema_version": "p02.report.v3", "status": "internal_error",
                "v2_policy": {"decision": "inconclusive"},
                "errors": [{"code": "INTERNAL_ERROR", "message": "Report construction failed; details withheld."}]}


def _elapsed(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _not_checked() -> dict:
    return {"checked": False, "matched": None, "mismatch_codes": []}


def explain_command(fixture_dir: str, input_result: Optional[str], limits, started: float) -> dict:
    v2 = None
    supplied = _not_checked()
    try:
        supplied_obj = None
        if input_result is not None:
            try:
                supplied_obj = read_result_file(input_result)
            except InputRejected as exc:
                supplied = {"checked": True, "matched": False, "mismatch_codes": []}
                return _finish(STATUS_REJECTED, None, supplied, [exc.issue.as_dict()], started)
        run = rederive(fixture_dir, limits)
        if strict_secret_hit(json.dumps(run.result, ensure_ascii=False)):
            # The shared Phase 1/2 screen let a word-adjacent credential through (verifier D1). Nothing
            # derived from this v2 is emitted, not even paths or the policy; the CLI exits 4.
            err = {"code": "SECRET_SUSPECTED", "message": "Possible credential in content derived from the "
                                                          "fixture; value redacted and no report content emitted."}
            return _finish(STATUS_REJECTED, None, _not_checked(), [err], started)
        v2 = run.result
        if supplied_obj is not None:
            codes = compare_supplied(supplied_obj, v2)
            supplied = {"checked": True, "matched": not codes, "mismatch_codes": codes}
            if codes:
                err = {"code": "V2_MISMATCH",
                       "message": "Supplied result does not equal the result re-derived from the fixture; "
                                  "it is forged, stale, or from different code. Fields: " + ", ".join(codes) + "."}
                return _finish(STATUS_MISMATCH, v2, supplied, [err], started)
        if v2.get("status") != "completed":
            status = STATUS_INTERNAL if v2.get("status") == "internal_error" else STATUS_REJECTED
            return _finish(status, v2, supplied, list(v2.get("errors") or [{"code": "INTERNAL_ERROR",
                                                                            "message": "details withheld"}]),
                           started)
        groups = p3_group.group(v2)
        links = p3_correlate.correlate(run)
        facts_by_id = {f.id: dict(f.facts) for f in (run.analysis.findings if run.analysis else [])}
        sections, questions, unknowns = p3_narrative.build(v2, groups, links, facts_by_id)
        NoneBackend().narrate(None)  # explicit no-op: the only backend that exists in Phase 3A
        return _finish(STATUS_COMPLETED, v2, supplied, [], started, groups, links, sections, questions, unknowns)
    except Exception as exc:  # internal failure: type only, never the message (may contain data)
        err = {"code": "INTERNAL_ERROR", "message": f"Unexpected internal failure ({type(exc).__name__}); "
                                                    "details withheld."}
        # Keep the re-derived v2 decision visible when it exists, so a Phase 3A failure cannot hide a
        # review_required result (verifier O1). Fall back to no v2 content if that report fails validation.
        for keep in ((v2, supplied), (None, _not_checked())):
            try:
                return _finish(STATUS_INTERNAL, keep[0], keep[1], [err], started)
            except Exception:
                continue
        return dict(_FALLBACK_V3)


def _finish(status, v2, supplied, errors, started, groups=(), links=(), sections=(), questions=(), unknowns=()):
    result = build_result_v3(status=status, v2=v2, supplied=supplied, errors=list(errors), groups=list(groups),
                             links=list(links), sections=list(sections), questions=list(questions),
                             unknowns=list(unknowns), elapsed_ms=_elapsed(started))
    validate_result_v3(result, v2 if status == STATUS_COMPLETED else None)
    return result


def summary_v3(result: dict) -> str:
    pol = result.get("v2_policy") or {}
    lines = [f"p02review explain: status={result['status']} v2_decision={pol.get('decision')} run_id={result['run_id']}",
             f"  groups: {len(result['groups'])}; links: {len(result['links'])} "
             f"(candidate {sum(1 for l in result['links'] if l['link_type'] != 'unlinked')}); "
             f"questions: {len(result['verification_questions'])}; unknowns: {len(result['unknowns'])}"]
    for err in result.get("errors", [])[:5]:
        lines.append(f"  - {err['code']} {err.get('message', '')}".rstrip())
    lines.append("  NOTE: advisory, template-only report; the v2 decision, severities and coverage are unchanged.")
    return "\n".join(lines) + "\n"
