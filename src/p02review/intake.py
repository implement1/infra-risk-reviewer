"""Filesystem intake: bounded, symlink-refusing reads of manifest-declared files only.

Only paths listed in the manifest are opened. Every path component below the fixture root is
checked with ``lstat`` and files are opened with ``O_NOFOLLOW``; a realpath containment check
is applied as defence in depth. Content is read as bytes, digested, and checked for strict
UTF-8 text. Content is never executed, interpreted as instructions, or echoed in messages.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from . import errors as E
from .errors import InputIssue, InputRejected, display_path
from .limits import Limits
from .manifest import (MANIFEST_FILENAME, Manifest, build_manifest, decode_manifest_bytes, has_lone_surrogate,
                       iter_strings, parse_manifest_json)
from .escape_decode import decoded_values
from .secret_screen import SecretHit, screen_text

# C0 controls except tab/LF/CR, DEL, C1 controls, and bidirectional override/isolate characters.
_LONE_CR = re.compile("\r(?!\n)")  # CR not followed by LF can overwrite text on a terminal
_DISALLOWED_CHARS = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f-\\x9f\\u202a-\\u202e\\u2066-\\u2069]")
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)


@dataclass(frozen=True)
class SourceRecord:
    path: str
    kind: str
    size_bytes: int
    sha256: str
    line_count: int

    def as_dict(self) -> dict:
        return {"path": self.path, "kind": self.kind, "size_bytes": self.size_bytes,
                "sha256": self.sha256, "line_count": self.line_count, "encoding": "utf-8"}


@dataclass
class IntakeOutcome:
    manifest: Optional[Manifest] = None
    manifest_sha256: Optional[str] = None          # digest of raw manifest bytes
    accepted: List[SourceRecord] = field(default_factory=list)
    issues: List[InputIssue] = field(default_factory=list)
    secret_hits: List[Tuple[str, Optional[str], SecretHit]] = field(default_factory=list)  # (path, None, hit)
    files_declared: int = 0
    total_bytes: int = 0
    # In-memory text of accepted files for Phase 2 analysis only; never serialized.
    contents: dict = field(default_factory=dict, repr=False)
    # Hardening L2: text of files that were read safely but rejected for a text problem (control characters,
    # encoding, BOM, NUL). Kept in memory only so credential screening still covers them; never analysed,
    # digested into results, or serialized.
    screen_only: dict = field(default_factory=dict, repr=False)
    # Bytes of text-problem files screened so far; bounded by max_total_bytes (beyond it they are rejected
    # unscreened, i.e. fail-closed with exit 3). Accepted files keep using total_bytes (unchanged contract).
    screened_rejected_bytes: int = 0


def _bounded_read(full_path: str, max_bytes: int, expect: os.stat_result) -> bytes:
    """Open without following symlinks, confirm identity with the earlier lstat, read <= max+1."""
    fd = os.open(full_path, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (expect.st_dev, expect.st_ino):
            raise InputRejected(E.FILE_CHANGED_DURING_READ, "File changed between validation and read.")
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def strip_trailing_separators(path: str) -> str:
    """Lexically normalise an operator-supplied path ('link/', 'link//', 'link/.' -> 'link') so
    that lstat inspects the final component itself instead of following a symlink."""
    return os.path.normpath(path) if path else path


def _check_root(root: str) -> str:
    root = strip_trailing_separators(root)
    try:
        st = os.lstat(root)
    except FileNotFoundError:
        raise InputRejected(E.FIXTURE_ROOT_INVALID, "Fixture directory does not exist.") from None
    except OSError:
        raise InputRejected(E.FIXTURE_ROOT_INVALID, "Fixture directory cannot be inspected.") from None
    if stat.S_ISLNK(st.st_mode):
        raise InputRejected(E.FIXTURE_ROOT_INVALID, "Fixture directory must not be a symbolic link.")
    if not stat.S_ISDIR(st.st_mode):
        raise InputRejected(E.FIXTURE_ROOT_INVALID, "Fixture path is not a directory.")
    return os.path.realpath(root)


def _read_manifest(root: str, limits: Limits) -> bytes:
    path = os.path.join(root, MANIFEST_FILENAME)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise InputRejected(E.MANIFEST_MISSING, f"No {MANIFEST_FILENAME} in the fixture directory.",
                            path=MANIFEST_FILENAME) from None
    if stat.S_ISLNK(st.st_mode):
        raise InputRejected(E.MANIFEST_SYMLINK, "Manifest must not be a symbolic link.", path=MANIFEST_FILENAME)
    if not stat.S_ISREG(st.st_mode):
        raise InputRejected(E.MANIFEST_NOT_REGULAR, "Manifest is not a regular file.", path=MANIFEST_FILENAME)
    if st.st_size > limits.max_manifest_bytes:
        raise InputRejected(E.MANIFEST_TOO_LARGE,
                            f"Manifest exceeds {limits.max_manifest_bytes} bytes.", path=MANIFEST_FILENAME)
    raw = _bounded_read(path, limits.max_manifest_bytes, st)
    if len(raw) > limits.max_manifest_bytes:
        raise InputRejected(E.MANIFEST_TOO_LARGE,
                            f"Manifest exceeds {limits.max_manifest_bytes} bytes.", path=MANIFEST_FILENAME)
    return raw


def _lstat_components(root_real: str, rel: str) -> Tuple[Optional[os.stat_result], Optional[InputIssue]]:
    shown = display_path(rel)
    parts = rel.split("/")
    current = root_real
    st = None
    for i, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return None, InputIssue(E.FILE_MISSING, "Declared file does not exist.", shown)
        except OSError:
            return None, InputIssue(E.FILE_MISSING, "Declared file cannot be inspected.", shown)
        if stat.S_ISLNK(st.st_mode):
            return None, InputIssue(E.PATH_SYMLINK, "Path contains a symbolic link; links are not followed.", shown)
        last = i == len(parts) - 1
        if not last and not stat.S_ISDIR(st.st_mode):
            return None, InputIssue(E.FILE_MISSING, "A parent path component is not a directory.", shown)
    if not stat.S_ISREG(st.st_mode):
        return None, InputIssue(E.FILE_NOT_REGULAR, "Declared path is not a regular file.", shown)
    real = os.path.realpath(current)
    if os.path.commonpath([root_real, real]) != root_real:
        return None, InputIssue(E.PATH_OUTSIDE_ROOT, "Path resolves outside the fixture root.", shown)
    return st, None


def _text_issue(raw: bytes, shown: str) -> Optional[InputIssue]:
    if b"\x00" in raw:
        return InputIssue(E.BINARY_CONTENT, "File contains NUL bytes; binary content is not accepted.", shown)
    if raw.startswith(b"\xef\xbb\xbf"):
        return InputIssue(E.ENCODING_INVALID, "UTF-8 byte-order mark is not accepted.", shown)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        line = raw.count(b"\n", 0, exc.start) + 1
        return InputIssue(E.ENCODING_INVALID, f"File is not valid UTF-8 (byte offset {exc.start}).", shown, line)
    bad = _DISALLOWED_CHARS.search(text) or _LONE_CR.search(text)
    if bad:
        line = text.count("\n", 0, bad.start()) + 1
        return InputIssue(E.CONTROL_CHARACTERS,
                          "File contains control or bidirectional-override characters.", shown, line)
    return None


def _decoded_hits(strings, limits: Limits) -> List[SecretHit]:
    """Screen decoded strings; locations cannot be mapped to source lines, so line is None."""
    rules = set()
    for value in strings:
        for hit in screen_text(value, limits.max_secret_hits_per_file):
            rules.add(hit.rule_id)
    return [SecretHit(rule, None) for rule in sorted(rules)]


def _json_source_hits(text: str, limits: Limits) -> List[SecretHit]:
    """For .json sources, also screen decoded strings (best effort; unparseable JSON is skipped,
    because Phase 1 does not validate source syntax)."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    return _decoded_hits(iter_strings(data), limits)


def _source_hits(kind: str, text: str, limits: Limits) -> Tuple[List[SecretHit], bool]:
    """Credential screen for one source: raw text, then (if no raw hit) the format's decoded values.
    JSON sources: decoded JSON strings (accepted Phase 1 behaviour). HCL/YAML sources: values defined by the
    format's documented escapes (hardening L1; bounded, format-aware, nothing evaluated). The flag is True when
    the hits came only from that HCL/YAML decoding (such files count toward the read budget, see run_intake)."""
    hits = screen_text(text, limits.max_secret_hits_per_file)
    if not hits and kind in ("json", "terraform-plan"):  # any JSON source, incl. v2 refinements
        hits = _json_source_hits(text, limits)
    if not hits:
        _values, decoded = decoded_values(kind, text)
        if decoded.changed:  # screen the whole decoded view, so each value is seen next to its key
            hits = _decoded_hits([decoded.text], limits)
            return hits, bool(hits)
    return hits, False


def run_intake(fixture_root: str, limits: Limits, manifest_versions: Tuple[str, ...] = ("1",)) -> IntakeOutcome:
    """Validate the fixture. Raises InputRejected for structural failures; collects per-file issues."""
    outcome = IntakeOutcome()
    root_real = _check_root(fixture_root)
    raw_manifest = _read_manifest(root_real, limits)
    outcome.manifest_sha256 = hashlib.sha256(raw_manifest).hexdigest()
    text = decode_manifest_bytes(raw_manifest)

    # Screen the raw manifest before any manifest-derived string can reach a message.
    # Digests of secret-bearing content are withheld (None): a hash of a small file could let
    # someone confirm a guessed credential offline.
    for hit in screen_text(text, limits.max_secret_hits_per_file):
        outcome.secret_hits.append((MANIFEST_FILENAME, None, hit))
    if outcome.secret_hits:
        return outcome

    parsed, duplicate_keys = parse_manifest_json(text)
    # Second pass over every *decoded* string (including duplicated keys): JSON escapes (\" or
    # \uXXXX) can hide a credential from the raw-text screen. No manifest-derived text is placed
    # in any message before this pass completes.
    decoded_hits = _decoded_hits(list(iter_strings(parsed)) + duplicate_keys, limits)
    if decoded_hits:
        outcome.secret_hits.extend((MANIFEST_FILENAME, None, hit) for hit in decoded_hits)
        return outcome
    if duplicate_keys:
        raise InputRejected(E.MANIFEST_DUPLICATE_KEY, "Manifest repeats a JSON object key.",
                            path=MANIFEST_FILENAME)
    if any(has_lone_surrogate(s) for s in iter_strings(parsed)):
        raise InputRejected(E.MANIFEST_ENCODING, "Manifest contains an unpaired UTF-16 surrogate escape.",
                            path=MANIFEST_FILENAME)

    manifest, issues = build_manifest(parsed, limits, manifest_versions)
    outcome.manifest = manifest
    outcome.issues.extend(issues)
    outcome.files_declared = len(manifest.files) + len(issues)

    for entry in sorted(manifest.files, key=lambda f: f.path):
        shown = display_path(entry.path)
        st, issue = _lstat_components(root_real, entry.path)
        if issue:
            outcome.issues.append(issue)
            continue
        if st.st_size > limits.max_file_bytes:
            outcome.issues.append(InputIssue(E.FILE_TOO_LARGE,
                                             f"File exceeds per-file ceiling of {limits.max_file_bytes} bytes.", shown))
            continue
        if outcome.total_bytes + st.st_size > limits.max_total_bytes:
            outcome.issues.append(InputIssue(E.TOTAL_SIZE_EXCEEDED,
                                             f"Accepting this file would exceed the total ceiling of "
                                             f"{limits.max_total_bytes} bytes; remaining files not read.", shown))
            break
        try:
            raw = _bounded_read(os.path.join(root_real, entry.path), limits.max_file_bytes, st)
        except InputRejected as exc:
            outcome.issues.append(InputIssue(exc.issue.code, exc.issue.message, shown))
            continue
        except OSError:
            outcome.issues.append(InputIssue(E.FILE_MISSING, "Declared file could not be opened safely.", shown))
            continue
        if len(raw) > limits.max_file_bytes:  # grew after stat
            outcome.issues.append(InputIssue(E.FILE_TOO_LARGE,
                                             f"File exceeds per-file ceiling of {limits.max_file_bytes} bytes.", shown))
            continue
        problem = _text_issue(raw, shown)
        if problem:
            outcome.issues.append(problem)
            # Hardening L2: the bytes were read safely, so screen them before rejecting the file; a credential
            # takes precedence over the text problem (exit 4). Undecodable bytes become U+FFFD, which can only
            # split a token, never create one.
            if outcome.screened_rejected_bytes + len(raw) > limits.max_total_bytes:
                continue  # screening budget spent: stays rejected unscreened (fail-closed, exit 3)
            outcome.screened_rejected_bytes += len(raw)
            text_lossy = raw.decode("utf-8", errors="replace")
            hits, _ = _source_hits(entry.kind, text_lossy, limits)
            if hits:
                outcome.secret_hits.extend((entry.path, None, hit) for hit in hits)
            else:
                outcome.screen_only[entry.path] = text_lossy
            continue
        digest = hashlib.sha256(raw).hexdigest()
        text_content = raw.decode("utf-8")
        hits, via_decoding = _source_hits(entry.kind, text_content, limits)
        if via_decoding:
            # Before hardening such a file was accepted (and counted) by intake; it still counts toward the read
            # budget, so blocked files cannot be used to read and decode beyond max_total_bytes (verifier N3).
            outcome.total_bytes += len(raw)
        if hits:  # not accepted; digest withheld
            outcome.secret_hits.extend((entry.path, None, hit) for hit in hits)
            continue
        lines = raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)
        outcome.accepted.append(SourceRecord(entry.path, entry.kind, len(raw), digest, lines))
        outcome.contents[entry.path] = text_content
        outcome.total_bytes += len(raw)
    return outcome
