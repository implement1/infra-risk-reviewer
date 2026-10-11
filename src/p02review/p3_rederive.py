"""Phase 3A: independent re-derivation of the Phase 2 v2 result (P3-INV-10).

`explain` never trusts a supplied v2 result. It re-runs the accepted Phase 2 pipeline on the fixture
(same code path as `review`, see pipeline.py) and, if a result was supplied, requires exact equality
apart from the volatile `run_context`. Mismatch codes use a fixed vocabulary and never echo content.
"""

from __future__ import annotations

import json
import time
from typing import List

from .identity import canonical_json_bytes, sha256_hex
from .pipeline import PipelineRun, review_pipeline
from .result_v2 import TOP_LEVEL_KEYS_V2

VOLATILE_KEYS = ("run_context",)


def rederive(fixture_dir: str, limits) -> PipelineRun:
    """Re-run Phase 2 `review` in-process with the default run ID (no override is accepted in explain)."""
    return review_pipeline(fixture_dir, limits, None, time.perf_counter())


def stable_view(result: dict) -> dict:
    return {k: v for k, v in result.items() if k not in VOLATILE_KEYS}


def result_digest(result: dict) -> str:
    """SHA-256 of the canonical v2 result without volatile fields."""
    return sha256_hex(canonical_json_bytes(stable_view(result)))


def _exact(value) -> str:
    """Type-exact canonical serialisation. Python's == treats True == 1 and 5 == 5.0 as equal, so equality
    is decided on this text instead (verifier D5). Object key order is not significant in JSON
    (RFC 8259), so nested keys are sorted: a genuine result re-serialised by another tool still matches
    (verifier D4; ADR-0003). Array order is significant; top-level order is checked separately."""
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def compare_supplied(supplied: dict, rederived: dict) -> List[str]:
    """Empty list when the supplied result equals the re-derived one (ignoring run_context): same keys,
    same JSON types and values, same array order; object key order is not compared."""
    a, b = stable_view(supplied), stable_view(rederived)
    if _exact(a) == _exact(b) and list(a) == list(b):
        return []
    codes = []
    known = set(TOP_LEVEL_KEYS_V2)
    if set(a) - known:
        codes.append("UNEXPECTED_FIELDS")
    for key in TOP_LEVEL_KEYS_V2:
        if key in VOLATILE_KEYS:
            continue
        if (key in a) != (key in b) or (key in a and _exact(a[key]) != _exact(b[key])):
            codes.append("FIELD_" + key.upper())
    # Top-level key order is part of the v2 contract (validate_result_v2 enforces it); nested object
    # key order is not (verifier D4, second pass).
    if not codes and list(a) != [k for k in TOP_LEVEL_KEYS_V2 if k in a]:
        codes.append("FIELD_ORDER")
    return codes or ["UNSPECIFIED_DIFFERENCE"]

