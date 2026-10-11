"""Documented input ceilings, enforced in code.

These are provisional Phase 1 defaults chosen for small synthetic fixtures. They are not
approved production limits. Callers may tighten them (never loosen them) via ``tightened``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, fields, replace


@dataclass(frozen=True)
class Limits:
    max_manifest_bytes: int = 64 * 1024          # manifest file size
    max_files: int = 200                         # entries in manifest "files"
    max_file_bytes: int = 256 * 1024             # per accepted source file
    max_total_bytes: int = 2 * 1024 * 1024       # sum of all accepted source files
    max_path_chars: int = 240                    # length of one relative path
    max_path_depth: int = 12                     # path segments
    max_metadata_keys: int = 32
    max_metadata_key_chars: int = 64
    max_metadata_value_chars: int = 512
    max_text_field_chars: int = 2000             # description / provenance strings
    max_errors_reported: int = 50                # bounded error list in the result
    max_secret_hits_per_file: int = 20

    def fingerprint(self) -> str:
        blob = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict:
        return asdict(self)


DEFAULT_LIMITS = Limits()


def tightened(base: Limits = DEFAULT_LIMITS, **overrides: int) -> Limits:
    """Return ``base`` with some ceilings lowered. Raising a ceiling is refused."""
    valid = {f.name for f in fields(Limits)}
    for name, value in overrides.items():
        if name not in valid:
            raise ValueError(f"unknown limit: {name}")
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"limit {name} must be a positive integer")
        if value > getattr(base, name):
            raise ValueError(f"limit {name} may only be lowered (max {getattr(base, name)})")
    return replace(base, **overrides)
