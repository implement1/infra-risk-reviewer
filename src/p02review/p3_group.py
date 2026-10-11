"""Phase 3A presentational grouping of v2 findings (P3-05).

Groups findings that share a location key: (path, plan_address) for plan findings and
(path, resource) for source findings. Grouping never drops, merges, re-scores or re-states a
finding: every v2 finding ID appears in exactly one group and keeps its own rule/state/severity.
"""

from __future__ import annotations

from typing import Dict, List

from .identity import canonical_json_bytes, sha256_hex

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def group(v2: dict) -> List[dict]:
    buckets: Dict[tuple, List[dict]] = {}
    for f in v2.get("findings", []):
        loc = f["location"]
        if loc.get("plan_address") is not None:
            key = ("plan", loc["path"], loc["plan_address"])
        else:
            key = ("source", loc["path"], f["resource"])
        buckets.setdefault(key, []).append(f)
    groups = []
    for (kind, path, ident), members in buckets.items():
        confirmed = [m["severity"] for m in members if m["state"] == "confirmed_by_rule" and m["severity"] in SEVERITY_ORDER]
        lines = [m["location"]["line_start"] for m in members if m["location"]["line_start"] is not None]
        groups.append({
            "group_id": "G-" + sha256_hex(canonical_json_bytes([kind, path, ident]))[:16],
            "kind": kind,
            "path": path,
            "resource": ident if kind == "source" else None,
            "plan_address": ident if kind == "plan" else None,
            "line_start": min(lines) if lines else None,
            "finding_ids": [m["id"] for m in members],
            "rule_ids": sorted({m["rule_id"] for m in members}),
            "states": sorted({m["state"] for m in members}),
            "severities": sorted({m["severity"] for m in members}),
            "max_confirmed_severity": max(confirmed, key=SEVERITY_ORDER.index) if confirmed else None,
        })
    groups.sort(key=lambda g: (g["path"], g["line_start"] or 0, g["plan_address"] or "", g["resource"] or "",
                               g["group_id"]))
    return groups
