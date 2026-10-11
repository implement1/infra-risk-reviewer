"""Lightweight credential screening.

THIS IS NOT A COMPLETE SECRETS SCANNER. It recognises a small set of common token shapes
and high-entropy credential assignments so that obvious credentials in a fixture block the
run before any report is produced. Absence of hits does not mean the input is secret-free.

Matched values are never returned: callers receive only a rule identifier and a line number.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import List, Optional

SCREEN_ID = "secret-screen"
SCREEN_VERSION = "2"  # v2 (security maintenance, Option B): token patterns are fully unanchored


@dataclass(frozen=True)
class SecretHit:
    rule_id: str
    line: Optional[int]  # None when the location cannot be mapped to a source line


# Fixed-shape token patterns, each keyed on a distinctive prefix. Version 2 (security maintenance,
# Option B): no word-boundary anchors. In v1, `\b` let a token joined to a word character (e.g. `sg_<key>`,
# `SG<key>`, `x_ghp_...`) pass unmatched. Expected false positives (measured; ADR-0004 section 5): any
# AKIA/ASIA followed by 16 uppercase letters/digits, even mid-word (e.g. `ASIAPACIFICPRIMARYDB01`);
# gh?_/github_pat_ fragments inside snake_case names; `eyJ` mid-word in dotted names; and, rarely, long
# uppercase base32/base36 blobs. A false positive blocks the run (exit 4); it never leaks a value.
# See docs/adr/ADR-0004-credential-screen-v2.md.
_TOKEN_RULES = (
    ("aws-access-key-id", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("github-fine-grained-pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,255}")),
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("slack-token", re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
)

# Generic "credential-like name = long random-looking literal" assignments.
_ASSIGNMENT = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
    r"[\w.-]*\\?[\"']?\s*[:=]\s*\\?[\"']?([^\s\"'`,;\\]{12,})"
)
_REFERENCE_PREFIXES = ("var.", "local.", "data.", "module.", "${", "{{", "$(", "<", "secretkeyref")


def _entropy(value: str) -> float:
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_literal_secret(value: str) -> bool:
    lowered = value.lower()
    if lowered.startswith(_REFERENCE_PREFIXES):
        return False
    has_alpha = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_alpha and has_digit and _entropy(value) >= 3.0


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def screen_text(text: str, max_hits: int = 20) -> List[SecretHit]:
    """Return de-duplicated (rule, line) hits, sorted, at most ``max_hits``. Never values."""
    hits = set()
    for rule_id, pattern in _TOKEN_RULES:
        for m in pattern.finditer(text):
            hits.add(SecretHit(rule_id, _line_of(text, m.start())))
    for m in _ASSIGNMENT.finditer(text):
        if _looks_like_literal_secret(m.group(1)):
            hits.add(SecretHit("credential-assignment", _line_of(text, m.start())))
    ordered = sorted(hits, key=lambda h: (h.line or 0, h.rule_id))
    return ordered[:max_hits]
