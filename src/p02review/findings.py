"""Phase 2 finding, evidence and coverage records with stable, reproducible identifiers.

Identifiers are derived only from source identity (path + SHA-256) and normalized
rule/resource/location, never from time or host paths. Text placed in records that derives
from untrusted sources passes through ``safe_token`` (restricted alphabet, bounded length).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")
STATES = ("confirmed_by_rule", "suspected", "insufficient_evidence", "unsupported")
FILE_STATUSES = ("analyzed", "partial", "unsupported", "parse_error", "not_analyzed")

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9_.:/*@+=\[\]\"' ,()<>#{}-]")


def safe_token(value: object, max_len: int = 120) -> str:
    """Bounded, restricted-alphabet rendering of an untrusted identifier for output."""
    if value is None:
        return "<none>"
    text = value if isinstance(value, str) else str(value)
    text = _SAFE_CHARS.sub("?", text)
    if len(text) > max_len:
        text = text[:max_len] + "...[truncated]"
    return text


def _digest(parts: list) -> str:
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class Evidence:
    kind: str                      # "source_lines" | "plan_resource"
    path: str
    source_sha256: str
    analyzer: str
    analyzer_version: str
    rule_id: str
    observation: str               # fixed template text + safe tokens only
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    plan_address: Optional[str] = None
    json_pointer: Optional[str] = None

    @property
    def id(self) -> str:
        return "E-" + _digest([self.analyzer, self.analyzer_version, self.rule_id, self.path,
                               self.source_sha256, self.line_start, self.line_end,
                               self.plan_address, self.json_pointer])[:16]

    def as_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "path": self.path,
            "line_start": self.line_start, "line_end": self.line_end,
            "plan_address": self.plan_address, "json_pointer": self.json_pointer,
            "source_sha256": self.source_sha256, "analyzer": self.analyzer,
            "analyzer_version": self.analyzer_version, "rule_id": self.rule_id,
            "observation": self.observation,
            # result_v2.validate_result_v2 enforces that this claim holds before output.
            "validation_status": "resolved_against_inventory",
        }


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    state: str
    analyzer: str
    resource: str                  # normalized resource identity (safe_token applied)
    path: str
    source_sha256: str
    summary: str
    rationale: str
    recommended_check: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    plan_address: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    locator: str = ""              # sub-object position (e.g. Statement[1], ingress[0], /resource_changes/3)
    # Phase 3A (decision N3): typed, normalized values for templates. Never serialized by as_dict(),
    # never part of `id`, excluded from equality. Schema: p3_facts.SCHEMAS.
    facts: dict = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError("bad severity")
        if self.state not in STATES:
            raise ValueError("bad state")

    @property
    def id(self) -> str:
        # State and severity are part of identity so distinct conclusions about co-located objects
        # can never be merged into (and hidden behind) one another.
        location = self.plan_address if self.plan_address is not None else self.line_start
        return "F-" + _digest([self.rule_id, self.path, self.source_sha256, self.resource, location,
                               self.locator, self.state, self.severity])[:16]

    def as_dict(self) -> dict:
        return {
            "id": self.id, "rule_id": self.rule_id, "category": self.category,
            "severity": self.severity, "state": self.state, "provenance": "deterministic",
            "analyzer": self.analyzer, "resource": self.resource,
            "location": {"path": self.path, "line_start": self.line_start, "line_end": self.line_end,
                         "plan_address": self.plan_address},
            "evidence_ids": sorted({e.id for e in self.evidence}),
            "summary": self.summary, "rationale": self.rationale,
            "recommended_check": self.recommended_check,
        }


@dataclass
class CoverageNote:
    code: str                      # fixed vocabulary, e.g. UNSUPPORTED_CONSTRUCT
    message: str                   # fixed template text + safe tokens only
    line: Optional[int] = None

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "line": self.line}


@dataclass
class FileCoverage:
    path: str
    kind: str
    analyzer: Optional[str]
    analyzer_version: Optional[str]
    status: str
    objects_analyzed: int = 0
    notes: List[CoverageNote] = field(default_factory=list)
    rule_evaluations: Dict[str, int] = field(default_factory=dict)

    def count(self, rule_id: str, n: int = 1) -> None:
        self.rule_evaluations[rule_id] = self.rule_evaluations.get(rule_id, 0) + n

    def as_dict(self) -> dict:
        if self.status not in FILE_STATUSES:
            raise ValueError("bad file status")
        return {"path": self.path, "kind": self.kind, "analyzer": self.analyzer,
                "analyzer_version": self.analyzer_version, "status": self.status,
                "objects_analyzed": self.objects_analyzed,
                "notes": [n.as_dict() for n in self.notes[:50]],
                "notes_truncated": len(self.notes) > 50}


def merge_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate by stable ID, keeping every independently supporting evidence record."""
    merged: Dict[str, Finding] = {}
    for f in findings:
        if f.id in merged:
            existing = merged[f.id]
            known = {e.id for e in existing.evidence}
            existing.evidence.extend(e for e in f.evidence if e.id not in known)
        else:
            merged[f.id] = f
    return sorted(merged.values(), key=lambda f: (f.path, f.line_start or 0, f.plan_address or "", f.rule_id, f.id))
