"""Phase 3A deterministic plan-to-configuration correlation (P3-04; decision N2: no proven links).

For every plan finding, report whether a single static `resource` block in the same fixture has the
same raw TYPE.NAME. Module membership of a .tf file is never known (no root-module declaration), so
the strongest relationship emitted is `candidate_same_type_name`; everything else is `unlinked`.
Raw identifiers are recovered from the in-memory fixture text for comparison only and are never
output; any identifier that `safe_token` would alter is not linkable (P3-INV-14).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from . import rules_terraform
from .findings import safe_token
from .hcl_subset import Block
from .identity import canonical_json_bytes, sha256_hex
from .pipeline import PipelineRun
from .strict_json import StrictJsonError, load_strict

_BARE_ADDRESS = re.compile(r"\A([A-Za-z][A-Za-z0-9_-]*)\.([A-Za-z_][A-Za-z0-9_-]*)\Z")
ALWAYS = "module-membership-unverified"


def _static_blocks(run: PipelineRun) -> List[Tuple[str, str, str, int]]:
    """(raw type, raw name, path, line) for every top-level managed resource block in analysed TF files."""
    blocks = []
    for rec in sorted(run.outcome.accepted, key=lambda r: r.path):
        if rec.kind != "terraform":
            continue
        items, err = rules_terraform.parse_file(run.outcome.contents[rec.path])
        for b in items or []:
            if isinstance(b, Block) and b.type == "resource" and len(b.labels) == 2:
                blocks.append((b.labels[0], b.labels[1], rec.path, b.line_start))
    return blocks


def _raw_plan_address(run: PipelineRun, path: str, pointer: Optional[str]) -> Optional[str]:
    if not pointer or not pointer.startswith("/resource_changes/"):
        return None
    try:
        plan = load_strict(run.outcome.contents[path])
        entry = plan["resource_changes"][int(pointer.rsplit("/", 1)[1])]
    except (StrictJsonError, KeyError, IndexError, ValueError, TypeError):
        return None
    address = entry.get("address") if isinstance(entry, dict) else None
    return address if isinstance(address, str) else None


def correlate(run: PipelineRun) -> List[dict]:
    v2 = run.result
    if v2.get("status") != "completed" or run.outcome is None:
        return []
    statuses: Dict[str, str] = {c["path"]: c["status"] for c in v2["coverage"]["files"]}
    # A candidate claims there is exactly one same-named block. That claim needs every Terraform file to
    # have been analysed: a block may sit in a file that failed to parse or has no analyzer (verifier D6).
    tf_incomplete = any(c["status"] != "analyzed" and (c["kind"] == "terraform" or
                                                        c["path"].endswith((".tf", ".tf.json")))
                        for c in v2["coverage"]["files"])
    blocks = _static_blocks(run)
    evidence = {e["id"]: e for e in v2["evidence"]}
    links = []
    for f in v2["findings"]:
        if not f["rule_id"].startswith("PLAN-"):
            continue
        ev = next((evidence[i] for i in f["evidence_ids"] if i in evidence and evidence[i]["kind"] == "plan_resource"), None)
        raw = _raw_plan_address(run, f["location"]["path"], ev["json_pointer"] if ev else None)
        basis: List[str] = []
        match = None
        if raw is None:
            basis.append("plan-address-unavailable")
        else:
            if safe_token(raw, 200) != raw:
                basis.append("identifier-sanitized")
            if raw.startswith("module."):
                basis.append("module-address")
            elif raw.startswith("data."):
                basis.append("data-source-address")
            elif "[" in raw:
                basis.append("indexed-address")
            m = _BARE_ADDRESS.match(raw)
            if m is None and not basis:
                basis.append("address-unparseable")
            if m is not None:
                same = [b for b in blocks if (b[0], b[1]) == (m.group(1), m.group(2))]
                if not same:
                    basis.append("no-static-block")
                elif len(same) > 1:
                    basis.append("multiple-static-blocks")
                else:
                    match = same[0]
                    if safe_token(f"{match[0]}.{match[1]}", 160) != f"{match[0]}.{match[1]}":
                        basis.append("identifier-sanitized")
                    if statuses.get(match[2]) != "analyzed":
                        basis.append("static-file-not-fully-analyzed")
        if tf_incomplete:
            basis.append("terraform-coverage-incomplete")
        candidate = not basis and match is not None
        static_resource = safe_token(f"{match[0]}.{match[1]}", 160) if match else None
        static_ids = sorted(g["id"] for g in v2["findings"] if match and g["resource"] == static_resource
                            and g["location"]["path"] == match[2]) if candidate else []
        links.append({
            "link_id": "L-" + sha256_hex(canonical_json_bytes([f["id"]]))[:16],
            "plan_finding_id": f["id"],
            "plan_address": f["location"]["plan_address"],
            "static_resource": static_resource if candidate else None,
            "static_path": match[2] if candidate else None,
            "static_line_start": match[3] if candidate else None,
            "static_finding_ids": static_ids,
            "link_type": "candidate_same_type_name" if candidate else "unlinked",
            "basis": (["root-address-no-index", "single-static-block", "static-file-analyzed"] if candidate
                      else sorted(set(basis))) + [ALWAYS],
        })
    links.sort(key=lambda l: (l["plan_address"] or "", l["link_id"]))
    return links
