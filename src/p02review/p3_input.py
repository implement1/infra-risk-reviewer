"""Phase 3A: bounded, symlink-refusing, strict reader for a supplied v2 result file.

The supplied file is untrusted (trust zone 1). It is only ever compared with an independently
re-derived result; it is never used as a source of findings. Errors never echo file content.
Deliberately self-contained so the accepted Phase 1 intake module stays untouched.
"""

from __future__ import annotations

import os
import stat

from .errors import InputRejected
from .strict_json import StrictJsonError, load_strict

DEFAULT_MAX_RESULT_BYTES = 4 * 1024 * 1024

RESULT_FILE_MISSING = "RESULT_FILE_MISSING"
RESULT_FILE_NOT_REGULAR = "RESULT_FILE_NOT_REGULAR"
RESULT_FILE_SYMLINK = "RESULT_FILE_SYMLINK"
RESULT_FILE_TOO_LARGE = "RESULT_FILE_TOO_LARGE"
RESULT_FILE_ENCODING = "RESULT_FILE_ENCODING"
RESULT_FILE_INVALID_JSON = "RESULT_FILE_INVALID_JSON"
RESULT_FILE_NOT_OBJECT = "RESULT_FILE_NOT_OBJECT"

_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
_LABEL = "--input-result"


def _reject(code: str, message: str) -> InputRejected:
    return InputRejected(code, message, path=_LABEL)


def read_result_file(path: str, max_bytes: int = DEFAULT_MAX_RESULT_BYTES) -> dict:
    norm = os.path.normpath(path) if path else path
    # Every existing component is checked so 'link/.' or 'dirlink/file' cannot follow a symlink.
    parts = norm.split(os.sep)
    prefix = os.sep if norm.startswith(os.sep) else ""
    current = prefix
    for i, part in enumerate(p for p in parts if p):
        current = os.path.join(current, part) if current else part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            raise _reject(RESULT_FILE_MISSING, "Supplied result file does not exist.") from None
        except OSError:
            raise _reject(RESULT_FILE_MISSING, "Supplied result file cannot be inspected.") from None
        if stat.S_ISLNK(st.st_mode) and not _is_system_prefix(current):
            raise _reject(RESULT_FILE_SYMLINK, "Supplied result path contains a symbolic link.")
    try:
        st = os.lstat(norm)
    except OSError:
        raise _reject(RESULT_FILE_MISSING, "Supplied result file does not exist.") from None
    if not stat.S_ISREG(st.st_mode):
        raise _reject(RESULT_FILE_NOT_REGULAR, "Supplied result path is not a regular file.")
    if st.st_size > max_bytes:
        raise _reject(RESULT_FILE_TOO_LARGE, f"Supplied result file exceeds {max_bytes} bytes.")
    try:
        fd = os.open(norm, _FLAGS)
    except OSError:
        raise _reject(RESULT_FILE_MISSING, "Supplied result file could not be opened safely.") from None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise _reject(RESULT_FILE_NOT_REGULAR, "Supplied result file changed while being opened.")
        chunks, remaining = [], max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > max_bytes:
        raise _reject(RESULT_FILE_TOO_LARGE, f"Supplied result file exceeds {max_bytes} bytes.")
    if raw.startswith(b"\xef\xbb\xbf") or b"\x00" in raw:
        raise _reject(RESULT_FILE_ENCODING, "Supplied result file must be UTF-8 without BOM or NUL bytes.")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _reject(RESULT_FILE_ENCODING, f"Supplied result file is not valid UTF-8 (byte offset {exc.start}).") from None
    try:
        value = load_strict(text)
    except StrictJsonError as exc:
        raise _reject(RESULT_FILE_INVALID_JSON, f"Supplied result file is not strict JSON ({exc.code}).") from None
    if not isinstance(value, dict):
        raise _reject(RESULT_FILE_NOT_OBJECT, "Supplied result file must contain a JSON object.")
    return value


def _is_system_prefix(path: str) -> bool:
    """Tolerate OS-level symlinked roots such as /tmp -> /private/tmp (macOS) above the user's path."""
    return os.path.dirname(path) == os.sep
