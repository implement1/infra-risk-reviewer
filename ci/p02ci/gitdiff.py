"""A-1 changed-file enumeration (rename detection disabled), united with the effective change of the checked-out
test-merge commit (proposed amendment A-9).

* A-1, exactly as specified: `git -c diff.renames=false diff --no-renames --no-ext-diff --no-textconv
  --name-status -z <base>...<head>` (plus `diff.ignoreSubmodules=none` / `--ignore-submodules=none`, R1 V1-02).
* A-9: the same flags on `<merge^1> <merge>`, the tree change that merging the PR makes relative to the base tip
  GitHub used for refs/pull/N/merge. The checkout must be a two-parent merge whose second parent is the event
  head SHA and whose first parent descends from the event base SHA; anything else is a technical failure.
The union can only add paths. Run as argument lists (no shell) with an isolated git environment; names are
bytes. A rename appears as a deletion plus an addition, so both paths are classified; a deletion is a change.
"""
import os
import re
import shutil
import subprocess
from typing import List, Tuple

_SHA_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SCORE_RE = re.compile(rb"\A[RC][0-9]{1,3}\Z")
MAX_RECORDS = 100000
MAX_OUTPUT = 64 * 1024 * 1024
TIMEOUT = 120


class DiffError(Exception):
    pass


class MergeRefMismatch(DiffError):
    """The checked-out commit is not the expected two-parent test merge of the event SHAs (R4 V4-04)."""


class TooManyChanges(DiffError):
    """More than MAX_RECORDS unique (status, path) records (R3 V3-03)."""


def valid_sha(value) -> bool:
    return isinstance(value, str) and bool(_SHA_RE.match(value))


def git_env(path_value: str) -> dict:
    """No HOME, no system or global config, no prompts, no replace refs, fixed locale."""
    return {"PATH": path_value, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_ATTR_NOSYSTEM": "1", "LC_ALL": "C"}


def diff_command(git: str, pr_dir: str, base: str, head: str) -> List[str]:
    # diff.ignoreSubmodules / --ignore-submodules=none: a `.gitmodules` `ignore = all` must not hide gitlink
    # changes (R1 V1-02).
    return [git, "-C", pr_dir, "-c", "diff.renames=false", "-c", "diff.ignoreSubmodules=none",
            "-c", "core.quotepath=false", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
            "diff", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color", "--no-relative",
            "--ignore-submodules=none", "--name-status", "-z", "--end-of-options", f"{base}...{head}"]


def diff_two_command(git: str, pr_dir: str, old: str, new: str) -> List[str]:
    """Same flags as the A-1 command, but a two-endpoint diff (old tree -> new tree)."""
    cmd = diff_command(git, pr_dir, old, new)
    return cmd[:-1] + [old, new]


def parse_name_status_z(data: bytes) -> List[Tuple[str, bytes]]:
    """Parse `--name-status -z` output into (status, path) pairs. Status is one of A, D, M, T.

    Should a rename or copy record ever appear despite the flags, both paths are kept: a rename source becomes a
    deletion and its destination an addition; a copy source counts as touched (M) and its destination as added.
    Unmerged (U), unknown (X) or broken (B) records, and any malformed record, raise DiffError."""
    if data == b"":
        return []
    if not data.endswith(b"\x00"):
        raise DiffError("unterminated output")
    fields = data[:-1].split(b"\x00")
    out = []
    i = 0
    while i < len(fields):
        st = fields[i]
        if st in (b"A", b"D", b"M", b"T"):
            if i + 1 >= len(fields) or not fields[i + 1]:
                raise DiffError("missing path")
            out.append((st.decode("ascii"), fields[i + 1]))
            i += 2
        elif _SCORE_RE.match(st):
            if i + 2 >= len(fields) or not fields[i + 1] or not fields[i + 2]:
                raise DiffError("missing rename/copy path")
            src, dst = fields[i + 1], fields[i + 2]
            out.append(("D" if st[:1] == b"R" else "M", src))
            out.append(("A", dst))
            i += 3
        else:
            raise DiffError("unknown status")
        if len(out) > 2 * MAX_RECORDS:
            raise TooManyChanges("too many records")
    return out


def _run_git(cmd, path_value, cwd) -> bytes:
    try:
        p = subprocess.run(cmd, env=git_env(path_value), cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise DiffError("git failed") from None
    if p.returncode != 0 or len(p.stdout) > MAX_OUTPUT:
        raise DiffError("git failed")
    return p.stdout


def checkout_commit(git: str, pr_dir: str, path_value: str, cwd: str):
    """(sha, [parents]) of the checked-out PR commit (GitHub's test-merge commit refs/pull/N/merge)."""
    out = _run_git([git, "-C", pr_dir, "rev-list", "--parents", "-n", "1", "HEAD", "--"], path_value, cwd)
    parts = out.decode("ascii", "replace").split()
    if not parts or not all(valid_sha(x) for x in parts):
        raise DiffError("rev-list")
    return parts[0], parts[1:]


def list_changes(pr_dir: str, base: str, head: str, path_value: str, cwd: str) -> List[Tuple[str, bytes]]:
    """A-1 `<base>...<head>` united with `<merge^1> <merge>` (proposed A-9; R2 V2-01/V2-02, R3 V3-01/V3-04).

    The checkout must be GitHub's two-parent test-merge commit: second parent == event head SHA, and the event
    base SHA an ancestor of (or equal to) the first parent. A single-parent or octopus checkout, or a mismatch,
    is a DiffError (technical failure). `diff <base> <merge>` is not used: when the event base lags the merge's
    first parent it would attribute other PRs' base-branch changes to this one (R3 V3-01)."""
    if not (valid_sha(base) and valid_sha(head)):
        raise DiffError("sha")
    git = shutil.which("git", path=path_value)
    if not git or not os.path.isabs(git):
        raise DiffError("git not found")
    records = parse_name_status_z(_run_git(diff_command(git, pr_dir, base, head), path_value, cwd))
    commit, parents = checkout_commit(git, pr_dir, path_value, cwd)
    if len(parents) != 2:
        raise MergeRefMismatch("checkout is not a two-parent test-merge commit")
    if parents[1] != head:
        raise MergeRefMismatch("merge parent is not the event head")
    try:
        p = subprocess.run([git, "-C", pr_dir, "merge-base", "--is-ancestor", "--end-of-options", base, parents[0]],
                           env=git_env(path_value), cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise DiffError("git failed") from None
    if p.returncode == 1:
        raise MergeRefMismatch("event base is not an ancestor of the merge base tip")
    if p.returncode != 0:
        raise DiffError("git failed")
    records += parse_name_status_z(_run_git(diff_two_command(git, pr_dir, parents[0], commit), path_value, cwd))
    seen = set()
    unique = []
    for st, path in records:
        if (st, path) not in seen:
            seen.add((st, path))
            unique.append((st, path))
    if len(unique) > MAX_RECORDS:
        raise TooManyChanges("too many records")
    return unique
