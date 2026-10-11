"""Fixture manifest parsing and strict structural validation.

The manifest is untrusted data. Unknown keys, wrong types, duplicate JSON keys, non-finite
numbers and oversized fields are all rejected. Nothing in the manifest can change which
operations the tool performs.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import errors as E
from .errors import InputIssue, InputRejected, display_path
from .limits import Limits

MANIFEST_FILENAME = "p02-manifest.json"
MANIFEST_VERSION = "1"
MANIFEST_V2 = "2"
# Manifest v2 only (Phase 2, additive): a declared kind may refine the extension-derived kind.
KIND_REFINEMENTS = {"yaml": ("kubernetes", "helm-rendered"), "json": ("terraform-plan",)}
SUPPORTED_ORIGINS = ("fixture",)
RESERVED_ORIGINS = ("local_snapshot", "authorized_pr")  # architecture-defined, not enabled

# Extension -> source kind. Matching is case-sensitive; anything else is unsupported.
EXTENSION_KINDS: Tuple[Tuple[str, str], ...] = (
    (".tfvars", "terraform-vars"),
    (".tf", "terraform"),
    (".yaml", "yaml"),
    (".yml", "yaml"),
    (".json", "json"),
    (".diff", "diff"),
    (".patch", "diff"),
)

_TOP_REQUIRED = ("manifest_version", "origin", "fixture_id", "files")
_TOP_ALLOWED = frozenset(_TOP_REQUIRED + ("description", "provenance", "metadata"))
_PROVENANCE_ALLOWED = frozenset(("synthetic", "author", "created", "source", "notes"))
_FILE_ALLOWED = frozenset(("path", "kind"))
_FIXTURE_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
_META_KEY_RE = re.compile(r"\A[A-Za-z0-9_.-]+\Z")
# Conservative Phase 1 path alphabet: rules out homoglyphs, zero-width, C1 and terminal controls.
_PATH_CHARS_RE = re.compile(r"\A[A-Za-z0-9._+@=/-]+\Z")
_BIDI = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


@dataclass(frozen=True)
class FileEntry:
    path: str
    kind: str


@dataclass(frozen=True)
class Manifest:
    manifest_version: str
    origin: str
    fixture_id: str
    description: Optional[str]
    provenance: Dict[str, object]
    metadata: Dict[str, object]
    files: Tuple[FileEntry, ...]

    def normalized(self) -> dict:
        """Canonical dict used for the manifest digest (file order sorted)."""
        return {
            "manifest_version": self.manifest_version,
            "origin": self.origin,
            "fixture_id": self.fixture_id,
            "description": self.description,
            "provenance": dict(sorted(self.provenance.items())),
            "metadata": dict(sorted(self.metadata.items())),
            "files": [{"path": f.path, "kind": f.kind}
                      for f in sorted(self.files, key=lambda f: f.path)],
        }


def kind_for_path(path: str) -> Optional[str]:
    """Kind from the file name's extension. A bare dotfile such as '.tf' has no stem: unsupported."""
    name = path.rsplit("/", 1)[-1]
    for ext, kind in EXTENSION_KINDS:
        if name.endswith(ext) and len(name) > len(ext) and not name.startswith("."):
            return kind
    return None


def _schema(msg: str) -> InputRejected:
    return InputRejected(E.MANIFEST_SCHEMA, msg, path=MANIFEST_FILENAME)


def decode_manifest_bytes(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise InputRejected(E.MANIFEST_ENCODING, "Manifest must be UTF-8 without a byte-order mark.",
                            path=MANIFEST_FILENAME)
    if b"\x00" in raw:
        raise InputRejected(E.MANIFEST_ENCODING, "Manifest contains NUL bytes.", path=MANIFEST_FILENAME)
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:  # message deliberately excludes the offending bytes
        raise InputRejected(E.MANIFEST_ENCODING,
                            f"Manifest is not valid UTF-8 (byte offset {exc.start}).",
                            path=MANIFEST_FILENAME) from None


def _reject_constant(name):
    raise InputRejected(E.MANIFEST_INVALID_JSON, f"Manifest uses non-finite number {name}.",
                        path=MANIFEST_FILENAME)


def parse_manifest_json(text: str) -> Tuple[object, List[str]]:
    """Parse strictly. Duplicate keys are *collected*, not raised, so that the caller can
    secret-screen them before reporting MANIFEST_DUPLICATE_KEY (key text is never echoed)."""
    duplicates: List[str] = []

    def collect_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                duplicates.append(key)
            obj[key] = value
        return obj

    try:
        return json.loads(text, object_pairs_hook=collect_pairs, parse_constant=_reject_constant), duplicates
    except InputRejected:
        raise
    except json.JSONDecodeError as exc:
        raise InputRejected(E.MANIFEST_INVALID_JSON,
                            f"Manifest is not valid JSON (line {exc.lineno}, column {exc.colno}).",
                            path=MANIFEST_FILENAME, line=exc.lineno) from None
    except RecursionError:
        raise InputRejected(E.MANIFEST_INVALID_JSON, "Manifest JSON is nested too deeply.",
                            path=MANIFEST_FILENAME) from None
    except ValueError:  # e.g. integer exceeding the interpreter's digit limit
        raise InputRejected(E.MANIFEST_INVALID_JSON, "Manifest contains an unparseable value.",
                            path=MANIFEST_FILENAME) from None


def iter_strings(value: object):
    """Yield every decoded string in parsed JSON (keys, values, and 'key=value' joins so that a
    credential split between an escaped key and its value is still screened), iteratively."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            for k, v in item.items():
                yield k
                if isinstance(v, (str, int)) and not isinstance(v, bool):
                    yield f"{k}={v}"
                stack.append(v)
        elif isinstance(item, list):
            stack.extend(item)


def has_lone_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in text)


def _check_text(value: object, field: str, limits: Limits) -> str:
    if not isinstance(value, str):
        raise _schema(f"Field '{field}' must be a string.")
    if len(value) > limits.max_text_field_chars:
        raise _schema(f"Field '{field}' exceeds {limits.max_text_field_chars} characters.")
    if any((ord(c) < 0x20 and c not in "\t\n") or ord(c) == 0x7F or c in _BIDI for c in value):
        raise _schema(f"Field '{field}' contains control or bidirectional-override characters.")
    return value


def validate_relative_path(path: object, limits: Limits) -> Optional[InputIssue]:
    """Pure string checks on one manifest path. Returns an issue, or None if acceptable."""
    if not isinstance(path, str) or path == "":
        return InputIssue(E.PATH_INVALID, "File path must be a non-empty string.",
                          display_path(path) if isinstance(path, str) else None)
    shown = display_path(path)
    if len(path) > limits.max_path_chars:
        return InputIssue(E.PATH_INVALID, f"Path exceeds {limits.max_path_chars} characters.", shown)
    if any(ord(c) < 0x20 or ord(c) == 0x7F or c in _BIDI for c in path):
        return InputIssue(E.PATH_INVALID, "Path contains control characters.", shown)
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path) or path.startswith("~"):
        return InputIssue(E.PATH_ABSOLUTE, "Path must be relative to the fixture root.", shown)
    if "\\" in path or ":" in path:
        return InputIssue(E.PATH_INVALID, "Path must use '/' separators and contain no ':' or '\\'.", shown)
    if not _PATH_CHARS_RE.match(path):
        return InputIssue(E.PATH_INVALID, "Path may only contain ASCII letters, digits and . _ - + @ = /.", shown)
    if unicodedata.normalize("NFC", path) != path:
        return InputIssue(E.PATH_INVALID, "Path must be in Unicode NFC form.", shown)
    segments = path.split("/")
    if ".." in segments:
        return InputIssue(E.PATH_TRAVERSAL, "Path contains a '..' segment.", shown)
    if any(s in ("", ".") for s in segments):
        return InputIssue(E.PATH_INVALID, "Path contains empty or '.' segments.", shown)
    if len(segments) > limits.max_path_depth:
        return InputIssue(E.PATH_INVALID, f"Path deeper than {limits.max_path_depth} segments.", shown)
    if path == MANIFEST_FILENAME:
        return InputIssue(E.PATH_INVALID, "The manifest may not list itself.", shown)
    return None


def build_manifest(data: object, limits: Limits,
                   versions: Tuple[str, ...] = (MANIFEST_VERSION,)) -> Tuple[Optional[Manifest], List[InputIssue]]:
    """Validate parsed JSON. Structural errors raise; per-file path errors are collected."""
    if not isinstance(data, dict):
        raise _schema("Manifest top level must be a JSON object.")
    missing = [k for k in _TOP_REQUIRED if k not in data]
    if missing:
        raise _schema(f"Manifest missing required field(s): {', '.join(missing)}.")
    unknown = sorted(set(data) - _TOP_ALLOWED)
    if unknown:
        raise _schema("Manifest has unsupported field(s): "
                      + ", ".join(display_path(k) for k in unknown[:5]) + ".")

    if data["manifest_version"] not in versions:
        expected = " or ".join(f'"{v}"' for v in versions)
        raise _schema(f"Unsupported manifest_version; expected {expected}.")
    version = data["manifest_version"]

    origin = data["origin"]
    if origin not in SUPPORTED_ORIGINS:
        reserved = " (reserved for a later, separately authorized phase)" if origin in RESERVED_ORIGINS else ""
        raise InputRejected(E.ORIGIN_UNSUPPORTED,
                            f"Origin '{display_path(origin)}' is not accepted in Phase 1{reserved}; "
                            "only 'fixture' is supported.", path=MANIFEST_FILENAME)

    fixture_id = data["fixture_id"]
    if not isinstance(fixture_id, str) or not _FIXTURE_ID_RE.match(fixture_id):
        raise _schema("fixture_id must match ^[a-z0-9][a-z0-9._-]{0,63}$.")

    description = None
    if "description" in data and data["description"] is not None:
        description = _check_text(data["description"], "description", limits)

    provenance: Dict[str, object] = {}
    if "provenance" in data:
        prov = data["provenance"]
        if not isinstance(prov, dict):
            raise _schema("provenance must be an object.")
        bad = sorted(set(prov) - _PROVENANCE_ALLOWED)
        if bad:
            raise _schema("provenance has unsupported field(s): "
                          + ", ".join(display_path(k) for k in bad[:5]) + ".")
        for key, value in prov.items():
            if key == "synthetic":
                if not isinstance(value, bool):
                    raise _schema("provenance.synthetic must be a boolean.")
                if value is not True:
                    raise InputRejected(E.PROVENANCE_NOT_SYNTHETIC,
                                        "Fixture origin requires synthetic content; provenance.synthetic is false.",
                                        path=MANIFEST_FILENAME)
            else:
                _check_text(value, f"provenance.{key}", limits)
            provenance[key] = value

    metadata: Dict[str, object] = {}
    if "metadata" in data:
        meta = data["metadata"]
        if not isinstance(meta, dict):
            raise _schema("metadata must be a flat object.")
        if len(meta) > limits.max_metadata_keys:
            raise _schema(f"metadata exceeds {limits.max_metadata_keys} keys.")
        for key, value in meta.items():
            if len(key) > limits.max_metadata_key_chars or not _META_KEY_RE.match(key):
                raise _schema("metadata keys must match ^[A-Za-z0-9_.-]+$ and be bounded in length.")
            if isinstance(value, bool) or value is None:
                pass
            elif isinstance(value, int):
                if abs(value) > 2**53:
                    raise _schema("metadata integers must be within +/-2^53.")
            elif isinstance(value, str):
                if len(value) > limits.max_metadata_value_chars:
                    raise _schema(f"metadata value exceeds {limits.max_metadata_value_chars} characters.")
                _check_text(value, f"metadata.{key}", limits)
            else:
                raise _schema("metadata values must be string, integer, boolean or null.")
            metadata[key] = value

    files_raw = data["files"]
    if not isinstance(files_raw, list) or not files_raw:
        raise _schema("files must be a non-empty array.")
    if len(files_raw) > limits.max_files:
        raise InputRejected(E.FILE_COUNT_EXCEEDED,
                            f"Manifest lists {len(files_raw)} files; ceiling is {limits.max_files}.",
                            path=MANIFEST_FILENAME)

    issues: List[InputIssue] = []
    entries: List[FileEntry] = []
    seen_exact = set()
    seen_folded = set()
    for index, item in enumerate(files_raw):
        if not isinstance(item, dict):
            raise _schema(f"files[{index}] must be an object.")
        extra = sorted(set(item) - _FILE_ALLOWED)
        if extra or "path" not in item:
            raise _schema(f"files[{index}] must contain 'path' and optionally 'kind' only.")
        path = item["path"]
        issue = validate_relative_path(path, limits)
        if issue:
            issues.append(issue)
            continue
        shown = display_path(path)
        folded = path.lower()  # paths are ASCII-only, so lower() is an exact case fold
        if path in seen_exact or folded in seen_folded:
            issues.append(InputIssue(E.PATH_DUPLICATE,
                                     "Path is listed more than once (case-insensitive comparison).", shown))
            continue
        seen_exact.add(path)
        seen_folded.add(folded)
        kind = kind_for_path(path)
        if kind is None:
            issues.append(InputIssue(E.FILE_TYPE_UNSUPPORTED,
                                     "File extension is not in the Phase 1 allowlist.", shown))
            continue
        declared = item.get("kind", kind)
        if version == MANIFEST_V2 and declared in KIND_REFINEMENTS.get(kind, ()):
            kind = declared
        elif "kind" in item and item["kind"] != kind:
            issues.append(InputIssue(E.FILE_KIND_MISMATCH,
                                     f"Declared kind does not match extension-derived kind '{kind}'.", shown))
            continue
        entries.append(FileEntry(path=path, kind=kind))

    manifest = Manifest(
        manifest_version=version,
        origin=origin,
        fixture_id=fixture_id,
        description=description,
        provenance=provenance,
        metadata=metadata,
        files=tuple(entries),
    )
    return manifest, issues
