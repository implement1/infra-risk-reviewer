"""Error types and safe message helpers.

Error messages never include source file content. Paths taken from the manifest are
untrusted, so they are escaped and truncated before being placed in any message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_MAX_DISPLAY = 120


def display_path(value: object) -> str:
    """Render an untrusted path for messages: printable ASCII only, bounded length."""
    if not isinstance(value, str):
        return f"<non-string:{type(value).__name__}>"
    out = []
    for ch in value:
        code = ord(ch)
        if 0x20 <= code < 0x7F and ch != "\\":
            out.append(ch)
        elif ch == "\\":
            out.append("\\\\")
        else:
            out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
    text = "".join(out)
    if len(text) > _MAX_DISPLAY:
        text = text[:_MAX_DISPLAY] + "...[truncated]"
    return text


@dataclass(frozen=True)
class InputIssue:
    """One reason an input was rejected."""

    code: str
    message: str
    path: Optional[str] = None   # already passed through display_path
    line: Optional[int] = None

    def as_dict(self) -> dict:
        d = {"code": self.code, "message": self.message}
        if self.path is not None:
            d["path"] = self.path
        if self.line is not None:
            d["line"] = self.line
        return d


class InputRejected(Exception):
    """Raised for structural problems that stop intake immediately (fail closed)."""

    def __init__(self, code: str, message: str, *, path: Optional[str] = None,
                 line: Optional[int] = None) -> None:
        super().__init__(code)
        self.issue = InputIssue(code, message, path, line)


class ResultValidationError(Exception):
    """The tool produced a result that violates its own output contract (internal failure)."""


# Error codes (stable identifiers; documented in docs/OPERATIONS.md)
FIXTURE_ROOT_INVALID = "FIXTURE_ROOT_INVALID"
MANIFEST_MISSING = "MANIFEST_MISSING"
MANIFEST_NOT_REGULAR = "MANIFEST_NOT_REGULAR"
MANIFEST_SYMLINK = "MANIFEST_SYMLINK"
MANIFEST_TOO_LARGE = "MANIFEST_TOO_LARGE"
MANIFEST_ENCODING = "MANIFEST_ENCODING"
MANIFEST_INVALID_JSON = "MANIFEST_INVALID_JSON"
MANIFEST_DUPLICATE_KEY = "MANIFEST_DUPLICATE_KEY"
MANIFEST_SCHEMA = "MANIFEST_SCHEMA"
ORIGIN_UNSUPPORTED = "ORIGIN_UNSUPPORTED"
PROVENANCE_NOT_SYNTHETIC = "PROVENANCE_NOT_SYNTHETIC"
FILE_COUNT_EXCEEDED = "FILE_COUNT_EXCEEDED"
PATH_INVALID = "PATH_INVALID"
PATH_ABSOLUTE = "PATH_ABSOLUTE"
PATH_TRAVERSAL = "PATH_TRAVERSAL"
PATH_DUPLICATE = "PATH_DUPLICATE"
PATH_SYMLINK = "PATH_SYMLINK"
PATH_OUTSIDE_ROOT = "PATH_OUTSIDE_ROOT"
FILE_MISSING = "FILE_MISSING"
FILE_NOT_REGULAR = "FILE_NOT_REGULAR"
FILE_TYPE_UNSUPPORTED = "FILE_TYPE_UNSUPPORTED"
FILE_KIND_MISMATCH = "FILE_KIND_MISMATCH"
FILE_TOO_LARGE = "FILE_TOO_LARGE"
TOTAL_SIZE_EXCEEDED = "TOTAL_SIZE_EXCEEDED"
FILE_CHANGED_DURING_READ = "FILE_CHANGED_DURING_READ"
BINARY_CONTENT = "BINARY_CONTENT"
ENCODING_INVALID = "ENCODING_INVALID"
CONTROL_CHARACTERS = "CONTROL_CHARACTERS"
SECRET_SUSPECTED = "SECRET_SUSPECTED"
INTERNAL_ERROR = "INTERNAL_ERROR"
