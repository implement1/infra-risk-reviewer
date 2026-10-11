"""Manifest validation with the core's own functions and a bounded staging copy (02 sec. 7.3-7.4; A-6).

* The manifest is read with an O_NOFOLLOW, bounded read of at most max_manifest_bytes + 1 bytes and copied
  byte-for-byte, so P02 reports MANIFEST_TOO_LARGE itself. A symlinked or non-regular manifest is an adapter
  refusal.
* The manifest is judged by the core's public functions (decode_manifest_bytes, parse_manifest_json,
  build_manifest(versions=("1", "2")), which applies validate_relative_path), so the adapter accepts exactly
  what P02 accepts. A manifest the core rejects is still staged alone, and P02 reports its own code.
* A-6: the adapter additionally requires provenance.synthetic to be the JSON value true
  (P02CI_PROVENANCE_NOT_DECLARED). P02 still runs, so a credential is never hidden behind the refusal.
* Every path component is opened relative to its parent directory descriptor with O_NOFOLLOW; nothing outside
  the package directory is opened. Symlinks, non-regular files and hard-linked files are refused, never copied.
  Regular files are copied with a bounded read of at most max_file_bytes + 1 bytes.
"""
import os
import stat
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from p02review.errors import InputRejected
from p02review.limits import DEFAULT_LIMITS, Limits
from p02review.manifest import (MANIFEST_FILENAME, build_manifest, decode_manifest_bytes, parse_manifest_json)

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC

MANIFEST_REFUSALS = ("P02CI_MANIFEST_SYMLINK", "P02CI_MANIFEST_NOT_REGULAR", "P02CI_HARDLINK")


class StageError(Exception):
    """The package directory itself cannot be opened safely (technical failure)."""


@dataclass
class CoreView:
    accepted: bool
    declared: List[str] = field(default_factory=list)
    provenance_declared: bool = False
    fixture_id: Optional[str] = None
    too_large: bool = False


@dataclass
class StageResult:
    refusals: List[Tuple[str, str]]
    view: Optional[CoreView]
    manifest_staged: bool

    @property
    def declared(self) -> List[str]:
        return list(self.view.declared) if self.view and self.view.accepted else []

    @property
    def manifest_refused(self) -> bool:
        return any(code in MANIFEST_REFUSALS and path == MANIFEST_FILENAME for code, path in self.refusals)


def core_view(raw: bytes, limits: Limits = DEFAULT_LIMITS) -> CoreView:
    if len(raw) > limits.max_manifest_bytes:
        return CoreView(accepted=False, too_large=True)
    try:
        text = decode_manifest_bytes(raw)
        data, duplicates = parse_manifest_json(text)
        if duplicates:
            return CoreView(accepted=False)
        manifest, issues = build_manifest(data, limits, versions=("1", "2"))
    except InputRejected:
        return CoreView(accepted=False)
    except Exception:  # anything unexpected: do not guess; P02 judges the manifest itself
        return CoreView(accepted=False)
    if issues or manifest is None:
        return CoreView(accepted=False)
    prov = data.get("provenance") if isinstance(data, dict) else None
    declared_synthetic = isinstance(prov, dict) and prov.get("synthetic") is True
    return CoreView(accepted=True, declared=[f.path for f in manifest.files], provenance_declared=declared_synthetic,
                    fixture_id=manifest.fixture_id)


def _open_dir_chain(root_fd: int, parts: List[str]) -> int:
    fd = os.dup(root_fd)
    try:
        for part in parts:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except OSError:
        os.close(fd)
        raise


def _bounded_read(fd: int, limit: int) -> bytes:
    chunks, total = [], 0
    while total < limit:
        chunk = os.read(fd, min(1 << 16, limit - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _write_new(dest_root: str, rel: str, data: bytes) -> None:
    full = os.path.join(dest_root, *rel.split("/"))
    os.makedirs(os.path.dirname(full), mode=0o700, exist_ok=True)
    fd = os.open(full, _WRITE_FLAGS, 0o600)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
    finally:
        os.close(fd)


def _read_entry(dir_fd: int, name: str, limit: int):
    """Return ("ok", bytes) | ("missing", None) | (refusal_code, None) for one final path component."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return "missing", None
    except OSError:
        return "P02CI_NOT_REGULAR", None
    if stat.S_ISLNK(st.st_mode):
        return "P02CI_PATH_SYMLINK", None
    if not stat.S_ISREG(st.st_mode):
        return "P02CI_NOT_REGULAR", None
    if st.st_nlink > 1:
        return "P02CI_HARDLINK", None
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except OSError:
        return "P02CI_NOT_REGULAR", None
    try:
        fst = os.fstat(fd)
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(fst.st_mode) or fst.st_nlink > 1:
            return "P02CI_NOT_REGULAR", None
        return "ok", _bounded_read(fd, limit)
    finally:
        os.close(fd)


def stage_package(pr_root: str, pkg_rel: str, dest: str, limits: Limits = DEFAULT_LIMITS) -> StageResult:
    """Copy the manifest and the declared, valid files of one package into `dest` (which must not exist)."""
    os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
    os.mkdir(dest, 0o700)
    refusals: List[Tuple[str, str]] = []
    try:
        root_fd = os.open(pr_root, _DIR_FLAGS)
    except OSError:
        raise StageError("pr root") from None
    try:
        try:
            pkg_fd = _open_dir_chain(root_fd, pkg_rel.split("/"))
        except OSError:
            raise StageError("package dir") from None
        try:
            kind, raw = _read_entry(pkg_fd, MANIFEST_FILENAME, limits.max_manifest_bytes + 1)
            if kind != "ok":
                code = {"P02CI_PATH_SYMLINK": "P02CI_MANIFEST_SYMLINK", "P02CI_HARDLINK": "P02CI_HARDLINK",
                        "missing": "P02CI_MANIFEST_NOT_REGULAR"}.get(kind, "P02CI_MANIFEST_NOT_REGULAR")
                refusals.append((code, MANIFEST_FILENAME))
                return StageResult(refusals, None, False)
            _write_new(dest, MANIFEST_FILENAME, raw)
            view = core_view(raw, limits)
            if not view.accepted:
                return StageResult(refusals, view, True)
            if not view.provenance_declared:
                refusals.append(("P02CI_PROVENANCE_NOT_DECLARED", MANIFEST_FILENAME))
            for rel in view.declared:
                parts = rel.split("/")
                code, data = _stage_one(pkg_fd, parts, limits.max_file_bytes + 1)
                if code == "ok":
                    _write_new(dest, rel, data)
                elif code != "missing":
                    refusals.append((code, rel))
            return StageResult(refusals, view, True)
        finally:
            os.close(pkg_fd)
    finally:
        os.close(root_fd)


def _stage_one(pkg_fd: int, parts: List[str], limit: int):
    fd = os.dup(pkg_fd)
    try:
        for comp in parts[:-1]:
            try:
                st = os.stat(comp, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return "missing", None
            except OSError:
                return "P02CI_NOT_REGULAR", None
            if stat.S_ISLNK(st.st_mode):
                return "P02CI_PATH_SYMLINK", None
            if not stat.S_ISDIR(st.st_mode):
                return "missing", None   # a file where a directory is expected: P02 reports FILE_MISSING
            try:
                nfd = os.open(comp, _DIR_FLAGS, dir_fd=fd)
            except OSError:
                return "P02CI_PATH_SYMLINK", None
            os.close(fd)
            fd = nfd
        return _read_entry(fd, parts[-1], limit)
    finally:
        os.close(fd)
