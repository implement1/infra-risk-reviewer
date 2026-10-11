"""A-2: changed-file classification and package discovery (02 sec. 2 as amended).

Every changed path (both the old and the new path of every change; deletions included) falls into exactly one
class, in this precedence:

    protected tooling -> reviewed -> undeclared-in-package -> allow-list -> other

* protected tooling: matches a trusted protected pattern (.github/, ci/, src/, schema/, narrate/, root and
  docs/ CODEOWNERS, inventories). Sets the TRUST DEGRADED notice; never "reviewed".
* reviewed: a declared file (or the accepted manifest) of a package that P02 assessed (rows 4, 5, 7).
* undeclared-in-package: inside a package directory but not declared by any assessed package containing it.
* allow-list: matches a trusted, extension-qualified non-infrastructure pattern.
* other: everything else, including names that are not UTF-8, contain control characters, fail the core path
  validation or are credential-shaped ("unreviewable names": counted, never displayed).

Additionally, every file present at head inside a changed package's own region (excluding nested packages) that
its manifest does not declare is "changed but not reviewed", whether or not the PR touched it (R3 N-03).

A package is a directory strictly under the trusted package root that contains `p02-manifest.json`; the
innermost manifest owns a path, and a file declared by an outer package is judged against the outer list.
"""
import os
import stat
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from p02review.limits import DEFAULT_LIMITS
from p02review.manifest import MANIFEST_FILENAME, validate_relative_path
from p02review.result_v3 import strict_secret_hit
from p02review.secret_screen import screen_text

from p02ci.config import Config, glob_match
from p02ci.model import Unreviewed

PRECEDENCE = ("protected", "reviewed", "undeclared_in_package", "allow_listed", "other")


class TooManyPackages(Exception):
    def __init__(self, protected: bool = False):
        super().__init__("too many packages")
        self.protected = protected


class PackageTooLarge(Exception):
    def __init__(self, protected: bool = False):
        super().__init__("package too large")
        self.protected = protected


@dataclass
class ChangedPath:
    raw: bytes
    status: str
    text: Optional[str]          # strict UTF-8 decoding, or None
    loose: str                   # surrogateescape decoding (matching only, never displayed)
    displayable: bool            # valid, non-credential-shaped name (may be shown through display_path)
    credential_name: bool = False  # the name itself has a credential shape (never shown)
    head_kind: str = "missing"   # regular | symlink | dir | other | missing, at the checked-out commit
    packages: List[str] = field(default_factory=list)   # containing packages, outermost first


@dataclass
class Discovery:
    changes: List[ChangedPath]
    packages: List[str]                          # changed packages (repository-relative dirs)
    protected_changed: bool
    region_files: Dict[str, List[Tuple[bytes, bool]]]   # package -> [(path, is_regular)] in its own region


def _name_ok(text: Optional[str]) -> bool:
    """A name may be displayed (through display_path) only if it is UTF-8, passes the core's own path validation
    and is not credential-shaped. Everything else is an unreviewable name: counted, never shown."""
    if text is None:
        return False
    if validate_relative_path(text, DEFAULT_LIMITS) is not None:
        return False
    if screen_text(text, 1) or strict_secret_hit(text):
        return False
    return True


def _credential_name(text: Optional[str], raw: bytes) -> bool:
    loose = raw.decode("utf-8", "replace") if text is None else text
    return bool(screen_text(loose, 1)) or strict_secret_hit(loose)


def _head_kind(root_b: bytes, raw: bytes) -> str:
    try:
        st = os.lstat(os.path.join(root_b, raw))
    except (OSError, ValueError):
        return "missing"
    if stat.S_ISREG(st.st_mode):
        return "regular"
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    return "other"


def _decode(raw: bytes):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return text, raw.decode("utf-8", "surrogateescape")


def _is_real_dir(pr_root: bytes, rel: str) -> bool:
    cur = pr_root
    for part in rel.split("/"):
        cur = os.path.join(cur, part.encode("utf-8", "surrogateescape"))
        try:
            st = os.lstat(cur)
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode):
            return False
    return True


def _has_manifest(pr_root: bytes, rel: str) -> bool:
    path = os.path.join(pr_root, rel.encode("utf-8", "surrogateescape"), MANIFEST_FILENAME.encode())
    return os.path.lexists(path)


def is_protected(cfg: Config, loose: str) -> bool:
    return any(glob_match(p, loose) for p in cfg.protected)


def discover(pr_root: str, records: List[Tuple[str, bytes]], cfg: Config) -> Discovery:
    root_b = os.fsencode(pr_root)
    prefix = cfg.package_root + "/"
    cache: Dict[str, bool] = {}
    changes: List[ChangedPath] = []
    pkgs: Set[str] = set()
    protected = False
    for status, raw in records:
        text, loose = _decode(raw)
        cp = ChangedPath(raw=raw, status=status, text=text, loose=loose, displayable=_name_ok(text),
                         credential_name=_credential_name(text, raw), head_kind=_head_kind(root_b, raw))
        if is_protected(cfg, loose):
            protected = True
        if text is not None and text.startswith(prefix):
            parts = text.split("/")
            for depth in range(len(cfg.package_root.split("/")) + 1, len(parts)):
                d = "/".join(parts[:depth])
                if d not in cache:
                    cache[d] = (validate_relative_path(d, DEFAULT_LIMITS) is None and _is_real_dir(root_b, d)
                                and _has_manifest(root_b, d))
                if cache[d]:
                    cp.packages.append(d)
        pkgs.update(cp.packages)
        changes.append(cp)
    # R1 V1-01: every package nested under a changed package is assessed too, so a file in a nested package's
    # directory can never leave review just because an outer manifest stopped declaring it.
    region: Dict[str, List[Tuple[bytes, bool]]] = {}
    queue = sorted(pkgs)
    while queue:
        p = queue.pop()
        if p in region:
            continue
        if len(pkgs) > cfg.max_packages:
            raise TooManyPackages(protected)
        try:
            files, nested = _walk_region(root_b, p, cfg.max_walk_entries)
        except PackageTooLarge:
            raise PackageTooLarge(protected) from None
        region[p] = files
        for n in nested:
            if n not in pkgs:
                pkgs.add(n)
                queue.append(n)
    packages = sorted(pkgs, key=lambda p: p.encode("utf-8"))
    if len(packages) > cfg.max_packages:
        raise TooManyPackages(protected)
    return Discovery(changes=changes, packages=packages, protected_changed=protected, region_files=region)


def _walk_region(root_b: bytes, pkg: str, limit: int):
    """Every non-directory entry in the package's own region at head, never following symlinks. A subdirectory
    holding its own manifest is a nested package (returned separately, and assessed as well) only if its path is
    valid; otherwise it is descended into like any other directory, so nothing below it is hidden."""
    out: List[Tuple[bytes, bool]] = []
    nested: List[str] = []
    count = 0
    stack = [pkg.encode("utf-8")]
    while stack:
        rel = stack.pop()
        full = os.path.join(root_b, rel)
        try:
            names = sorted(os.listdir(full))
        except OSError:
            continue
        for name in names:
            count += 1
            if count > limit:
                raise PackageTooLarge()
            crel = rel + b"/" + name
            st = os.lstat(os.path.join(root_b, crel))
            if stat.S_ISDIR(st.st_mode):
                if os.path.lexists(os.path.join(root_b, crel, MANIFEST_FILENAME.encode())):
                    try:
                        text = crel.decode("utf-8")
                    except UnicodeDecodeError:
                        text = None
                    if text is not None and validate_relative_path(text, DEFAULT_LIMITS) is None:
                        nested.append(text)
                        continue  # nested package: its own region, assessed separately
                stack.append(crel)
            else:
                out.append((crel, stat.S_ISREG(st.st_mode)))
    return sorted(out), sorted(nested)


@dataclass
class Classification:
    unreviewed: List[Unreviewed]
    unreviewable_count: int
    classes: Dict[bytes, str]
    credential_name_count: int = 0


def finalize(disc: Discovery, cfg: Config, assessed: Dict[str, List[str]], not_assessed: Set[str]) -> Classification:
    """`assessed`: package -> declared paths, for packages P02 assessed (rows 4/5/7). `not_assessed`: changed
    packages without a trustworthy assessment (rows 1-3; the run is red regardless)."""
    unreviewed: Dict[bytes, Unreviewed] = {}
    unreviewable = 0
    unreviewable_seen = set()
    credential_names = set()
    classes: Dict[bytes, str] = {}
    from p02ci.vocab import CHANGE_WORDS

    def declared_by_assessed(path: str, containing: List[str]) -> bool:
        for p in containing:
            rel = path[len(p) + 1:]
            if p in assessed and (rel in assessed[p] or rel == MANIFEST_FILENAME):
                return True
        return False

    for cp in disc.changes:
        if is_protected(cfg, cp.loose):
            classes[cp.raw] = "protected"
            if cp.credential_name:
                credential_names.add(cp.raw)  # R3 V3-07: the rotation note also covers protected paths
            continue
        change = CHANGE_WORDS.get(cp.status, "modified")
        if not cp.displayable:
            classes[cp.raw] = "other"
            if cp.raw not in unreviewable_seen:
                unreviewable_seen.add(cp.raw)
                unreviewable += 1
            if cp.credential_name:
                credential_names.add(cp.raw)
            continue
        path = cp.text
        if cp.packages and declared_by_assessed(path, cp.packages):
            classes[cp.raw] = "reviewed"
            continue
        if cp.packages:
            classes[cp.raw] = "undeclared_in_package"
            reason = "package_not_assessed" if cp.packages[-1] in not_assessed else "undeclared_in_package"
            unreviewed.setdefault(cp.raw, Unreviewed(path=cp.raw, change=change, reason=reason))
            continue
        # R2 V2-06: an allow-listed name counts only for a regular file (or a deletion); a symlink, gitlink or
        # other entry carrying a documentation name is not reviewed.
        if any(glob_match(p, path) for p in cfg.allow_list) and (cp.status == "D" or cp.head_kind == "regular"):
            classes[cp.raw] = "allow_listed"
            continue
        classes[cp.raw] = "other"
        unreviewed.setdefault(cp.raw, Unreviewed(path=cp.raw, change=change, reason="outside_packages"))

    changed_paths = {cp.raw for cp in disc.changes}
    for pkg, entries in disc.region_files.items():
        if pkg not in assessed:
            continue
        for raw, _regular in entries:
            if raw in changed_paths:
                continue  # already classified above
            text, loose = _decode(raw)
            if is_protected(cfg, loose):
                continue
            containing = [p for p in disc.packages if text is not None and text.startswith(p + "/")]
            if text is not None and declared_by_assessed(text, containing or [pkg]):
                continue
            if not _name_ok(text):
                if raw not in unreviewable_seen:
                    unreviewable_seen.add(raw)
                    unreviewable += 1
                if _credential_name(text, raw):
                    credential_names.add(raw)
                continue
            unreviewed.setdefault(raw, Unreviewed(path=raw, change="unchanged", reason="undeclared_in_package"))
    ordered = [unreviewed[k] for k in sorted(unreviewed)]
    return Classification(unreviewed=ordered, unreviewable_count=unreviewable, classes=classes,
                          credential_name_count=len(credential_names))
