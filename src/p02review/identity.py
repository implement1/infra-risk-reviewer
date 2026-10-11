"""Stable content identity. Depends only on validated content, never on time or host paths."""

from __future__ import annotations

import hashlib
import json
from typing import Iterable

from . import IDENTITY_SCHEME
from .intake import SourceRecord
from .manifest import Manifest


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_identity(records: Iterable[SourceRecord]) -> str:
    """Digest over (path, sha256, size) of every accepted file, sorted by path."""
    items = sorted(({"path": r.path, "sha256": r.sha256, "size_bytes": r.size_bytes} for r in records),
                   key=lambda d: d["path"])
    return sha256_hex(canonical_json_bytes(items))


def manifest_digest(manifest: Manifest) -> str:
    """Digest of the normalized manifest (key order and file order independent)."""
    return sha256_hex(canonical_json_bytes(manifest.normalized()))


def input_identity(manifest: Manifest, records: Iterable[SourceRecord]) -> dict:
    records = list(records)
    c_id = content_identity(records)
    m_id = manifest_digest(manifest)
    combined = sha256_hex(canonical_json_bytes({
        "scheme": IDENTITY_SCHEME,
        "origin": manifest.origin,
        "content_identity": c_id,
        "manifest_digest": m_id,
    }))
    return {
        "scheme": IDENTITY_SCHEME,
        "origin": manifest.origin,
        "fixture_id": manifest.fixture_id,
        "content_identity_sha256": c_id,
        "manifest_digest_sha256": m_id,
        "input_identity_sha256": combined,
        "file_count": len(records),
        "total_bytes": sum(r.size_bytes for r in records),
    }
