"""Bootstrap: start-up assertions and digest checks before any other adapter or core module is imported.

Planning doc 02 sec. 4 and sec. 7.5; amendment A-8. Only `os` and `sys` are imported at module level. The
trusted search-path roots are inspected before any further standard-library module is imported, because
PYTHONPATH entries precede the standard library on sys.path. The start-up assertions are *detection only*
(A-8): the protection itself comes from `-P -s -B`, the empty working directory and the absolute, trusted-only
PYTHONPATH set by the workflow.
"""
import os
import sys

HEADER = "## P02 Infrastructure Risk Review -- "
TECH_BANNER = "TECHNICAL FAILURE -- no assessment produced"
STANDARD_LINE = "> Deterministic baseline review. Human review is always required. This is not a safety approval."
TRUST_DEGRADED = "TRUST DEGRADED: this PR modifies the P02 workflow or tooling; this result is not authoritative."
FALLBACK = "P02 summary could not be rendered safely; no assessment is shown."

ENV_REQUIRED = ("PATH", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "RUNNER_TEMP", "GITHUB_OUTPUT",
                "GITHUB_STEP_SUMMARY", "P02_BASE_SHA", "P02_HEAD_SHA")
ENV_OPTIONAL = ("LD_LIBRARY_PATH", "LC_CTYPE")
LC_CTYPE_ALLOWED = ("C.UTF-8", "C.utf8")  # set by CPython's own C-locale coercion (PEP 538) under env -i
SRC_TOP_ALLOWED = frozenset(("p02review",))
CI_TOP_ALLOWED = frozenset(("p02ci", "tests", "tools", "deploy", "README.md"))
SUPPORTED_PYTHON = (3, 13)
EXIT_TECHNICAL = 30
CONFIG_NAME = "trusted_config.json"

_HEX = frozenset("0123456789abcdef")


class IntegrityError(Exception):
    """The trusted bundle cannot be hashed safely (symlink, non-regular entry, unreadable file)."""


def trusted_root() -> str:
    """<root>/ci/p02ci/bootstrap.py -> <root> (the base-commit checkout)."""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _under(path: str, root: str) -> bool:
    path = os.path.normpath(path)
    root = os.path.normpath(root)
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _is_digest(v: str) -> bool:
    return isinstance(v, str) and len(v) == 64 and set(v) <= _HEX


# ----------------------------------------------------------------------------- digests (bytes only)
def _sha256_file(path: str) -> str:
    import hashlib
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise IntegrityError("not a regular file")
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


def _digest_lines(lines) -> str:
    import hashlib
    lines = sorted(lines)
    return hashlib.sha256("".join(f"{rel}  {d}\n" for rel, d in lines).encode("ascii")).hexdigest()


def _entries(directory: str):
    import stat
    out = []
    for name in sorted(os.listdir(directory)):
        full = os.path.join(directory, name)
        st = os.lstat(full)
        if stat.S_ISLNK(st.st_mode):
            raise IntegrityError("symlink in trusted bundle")
        out.append((name, full, st))
    return out


def core_digest(root: str) -> str:
    """The documented core build digest (corepin.py algorithm): SHA-256 over sorted "<rel>  <sha256>\\n" lines for
    src/p02review/*.py and schema/*.json. Computed on bytes; the core is not imported. The core package
    directory must hold regular *.py files only: an extension module, a bytecode cache or a sub-package would be
    importable without being covered by the digest."""
    import stat
    lines = []
    pkg = os.path.join(root, "src", "p02review")
    for name, full, st in _entries(pkg):
        if not stat.S_ISREG(st.st_mode) or not name.endswith(".py"):
            raise IntegrityError("unexpected entry in core package")
        lines.append(("src/p02review/" + name, _sha256_file(full)))
    sch = os.path.join(root, "schema")
    for name, full, st in _entries(sch):
        if name.endswith(".json"):
            if not stat.S_ISREG(st.st_mode):
                raise IntegrityError("non-regular schema file")
            lines.append(("schema/" + name, _sha256_file(full)))
    if not lines:
        raise IntegrityError("empty core")
    return _digest_lines(lines)


def adapter_digest(root: str) -> str:
    """SHA-256 over sorted "<rel>  <sha256>\\n" lines for every file in ci/p02ci/, including the trusted
    configuration. Only regular `*.py` files and `trusted_config.json` are allowed there (R1 V1-13): an extension
    module, bytecode cache, `.pth` file or sub-package would be importable or confusing while looking harmless in
    review. Symlinks, directories and other entries are refused."""
    import stat
    lines = []
    base = os.path.join(root, "ci", "p02ci")
    for name, full, st in _entries(base):
        if not stat.S_ISREG(st.st_mode) or not (name.endswith(".py") or name == CONFIG_NAME):
            raise IntegrityError("unexpected entry in adapter")
        lines.append(("ci/p02ci/" + name, _sha256_file(full)))
    if not lines:
        raise IntegrityError("empty adapter")
    return _digest_lines(lines)


# ----------------------------------------------------------------------------- start-up assertions
def _path_list_ok(value, forbidden_roots, allow_missing=False) -> bool:
    if value is None:
        return allow_missing
    parts = value.split(os.pathsep)
    for p in parts:
        if not p or not os.path.isabs(p) or "\n" in p:
            return False
        if any(_under(p, r) for r in forbidden_roots if r):
            return False
    return True


def check_roots(root: str):
    """Top-level entries of the two trusted PYTHONPATH roots must be the expected ones (anything else there
    precedes the standard library on sys.path). Uses only os."""
    problems = []
    try:
        if set(os.listdir(os.path.join(root, "src"))) - SRC_TOP_ALLOWED:
            problems.append("src_root_entries")
        if set(os.listdir(os.path.join(root, "ci"))) - CI_TOP_ALLOWED:
            problems.append("ci_root_entries")
    except OSError:
        problems.append("trusted_roots_unreadable")
    return problems


def startup_problems(root: str, pr_dir, environ, cwd: str):
    """Return a list of fixed problem tokens (empty when the process is set up as the workflow specifies)."""
    problems = []
    if tuple(sys.version_info[:2]) != SUPPORTED_PYTHON:
        problems.append("python_version")
    f = sys.flags
    if not getattr(f, "safe_path", False):
        problems.append("flag_P")
    if not f.no_user_site:
        problems.append("flag_s")
    if not f.dont_write_bytecode:
        problems.append("flag_B")
    if f.inspect or f.interactive or f.ignore_environment or f.no_site:
        problems.append("flags_other")
    keys = set(environ)
    if keys - set(ENV_REQUIRED) - set(ENV_OPTIONAL):
        problems.append("env_unexpected")
    if set(ENV_REQUIRED) - keys:
        problems.append("env_missing")
    if "LC_CTYPE" in environ and environ["LC_CTYPE"] not in LC_CTYPE_ALLOWED:
        problems.append("env_lc_ctype")
    if environ.get("PYTHONDONTWRITEBYTECODE") not in (None, "1"):
        problems.append("env_bytecode")
    expected_pp = os.path.join(root, "src") + os.pathsep + os.path.join(root, "ci")
    if environ.get("PYTHONPATH") != expected_pp:
        problems.append("pythonpath")
    if sys.path[:2] != [os.path.join(root, "src"), os.path.join(root, "ci")]:
        problems.append("sys_path_prefix")
    if any((not p) or (not os.path.isabs(p)) for p in sys.path):
        problems.append("sys_path_relative")
    rt = environ.get("RUNNER_TEMP")
    forbidden = [pr_dir, cwd, rt, root]
    if not _path_list_ok(environ.get("PATH"), forbidden):
        problems.append("path_entries")
    if not _path_list_ok(environ.get("LD_LIBRARY_PATH"), forbidden, allow_missing=True):
        problems.append("ld_library_path")
    if not (os.path.isabs(cwd) and os.path.isdir(cwd)):
        problems.append("cwd")
    else:
        try:
            if os.listdir(cwd):
                problems.append("cwd_not_empty")
        except OSError:
            problems.append("cwd")
        if (pr_dir and _under(cwd, pr_dir)) or _under(cwd, root):
            problems.append("cwd_location")
    if not pr_dir or not os.path.isabs(pr_dir) or os.path.islink(pr_dir) or not os.path.isdir(pr_dir):
        problems.append("pr_dir")
    elif _under(pr_dir, root) or _under(root, pr_dir):
        problems.append("pr_dir_location")
    if not rt or not os.path.isabs(rt) or not os.path.isdir(rt) or (pr_dir and _under(rt, pr_dir)):
        problems.append("runner_temp")
    for k in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
        v = environ.get(k)
        if v is not None and (not os.path.isabs(v) or (pr_dir and _under(v, pr_dir))):
            problems.append("output_paths")
    for name in ("sitecustomize", "usercustomize"):
        mod = sys.modules.get(name)
        mfile = getattr(mod, "__file__", None) if mod is not None else None
        if mod is not None and (not mfile or any(_under(mfile, r) for r in forbidden if r)):
            problems.append("site_hook")
    problems.extend(check_roots(root))
    return problems


# ----------------------------------------------------------------------------- technical-failure output
def technical_summary(codes, trust_degraded=False, footer_digests=None) -> str:
    """Constant layout; only closed-vocabulary codes (P02CI_[A-Z0-9_]+) and hex digests are interpolated."""
    safe = []
    for c in codes:
        if isinstance(c, str) and c.startswith("P02CI_") and len(c) <= 48 and \
                all(ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for ch in c) and c not in safe:
            safe.append(c)
    if not safe:
        safe = ["P02CI_INTERNAL"]
    lines = [HEADER + TECH_BANNER]
    if trust_degraded:
        lines.append("> " + TRUST_DEGRADED)
    lines += [STANDARD_LINE, "",
              "No assessment is shown. Failure codes: " + ", ".join(f"`{c}`" for c in safe) + "."]
    if "P02CI_MERGE_REF_MISMATCH" in safe:
        lines += ["", "The checked-out merge commit does not match the pull request event (the base or head moved, "
                      "or the merge ref is stale). Please re-run the workflow after GitHub updates the merge ref. If "
                      "it persists, check whether the pull request changes .github/ (the workflow)."]
    lines += ["", "**CI conclusion:** the review job fails (technical failure); merging stays blocked by the review "
                  "check."]
    if footer_digests:
        parts = [f"{k} `{v}`" for k, v in footer_digests if _is_digest(v)]
        if parts:
            lines += ["", "---", "Footer: " + "; ".join(parts) + "."]
    return "\n".join(lines) + "\n"


def fallback_summary() -> str:
    return HEADER + TECH_BANNER + "\n" + FALLBACK + "\n"


def _open_append(path):
    if not path or not os.path.isabs(path):
        return None
    try:
        return open(path, "a", encoding="ascii", newline="\n")
    except (OSError, ValueError):
        return None


def write_outputs(environ, summary: str, ack: str) -> bool:
    """Open GITHUB_OUTPUT and GITHUB_STEP_SUMMARY first. If both open, append the summary and then write `ack`
    (forced to `required` if the summary write failed). Otherwise `ack=required` and a technical-failure summary
    (P02CI_OUTPUT_UNWRITABLE) go to whichever is available. Returns False on any failure (the caller then fails
    the job as a technical failure)."""
    if ack not in ("required", "not-required"):
        ack = "required"
    fo = _open_append(environ.get("GITHUB_OUTPUT"))
    fs = _open_append(environ.get("GITHUB_STEP_SUMMARY"))
    ok = fo is not None and fs is not None
    if not ok:
        ack, summary = "required", technical_summary(["P02CI_OUTPUT_UNWRITABLE"])
    try:
        # Summary first (R1 V1-08): `ack=not-required` is written only after the summary was written in full.
        if fs is not None:
            try:
                fs.write(summary)
                fs.flush()
            except (OSError, ValueError):
                ok, ack = False, "required"
        if fo is not None:
            try:
                fo.write(f"ack={ack}\n")
                fo.flush()
            except (OSError, ValueError):
                ok = False
    finally:
        for fh in (fo, fs):
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    ok = False
    return ok


def log(event: str, **fields) -> None:
    """Fixed-format log line: event and key=value pairs from closed vocabularies only."""
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:/-")
    parts = [f"p02ci: {event}"]
    for k, v in fields.items():
        v = str(v)
        if not set(v) <= allowed:
            v = "withheld"
        parts.append(f"{k}={v}")
    sys.stdout.write(" ".join(parts) + "\n")
    sys.stdout.flush()


def fail(environ, codes, check=None, trust_degraded=False, digests=None) -> int:
    log("technical_failure", code=codes[0] if codes else "P02CI_INTERNAL", check=check or "none")
    summary = technical_summary(codes, trust_degraded, digests)
    if not write_outputs(environ, summary, "required"):
        log("output_unwritable")
    return EXIT_TECHNICAL


# ----------------------------------------------------------------------------- arguments
def parse_args(argv):
    """--pr-dir DIR, --expect-core-digest HEX (repeatable), --expect-adapter-digest HEX (repeatable).
    Returns (pr_dir, core_pins, adapter_pins, ok); ok is False for any malformed or missing argument."""
    pr_dir, core_pins, adapter_pins, ok = None, [], [], True
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--pr-dir", "--expect-core-digest", "--expect-adapter-digest") and i + 1 < len(argv):
            v = argv[i + 1]
            if a == "--pr-dir":
                ok = ok and pr_dir is None
                pr_dir = v
            elif a == "--expect-core-digest":
                core_pins.append(v)
            else:
                adapter_pins.append(v)
            i += 2
        else:
            ok = False
            i += 1
    if pr_dir is None or not core_pins or not adapter_pins:
        ok = False
    if not all(_is_digest(p) for p in core_pins + adapter_pins):
        ok = False
    return pr_dir, core_pins, adapter_pins, ok


def main(argv=None) -> int:
    environ = dict(os.environ)
    root = trusted_root()
    pr_dir, core_pins, adapter_pins, args_ok = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = ""
    problems = startup_problems(root, pr_dir, environ, cwd)
    if problems:
        return fail(environ, ["P02CI_STARTUP_UNSAFE"], check=problems[0])
    if not args_ok:
        return fail(environ, ["P02CI_USAGE"], check="arguments")
    # Only now may further standard-library modules be imported (the trusted roots were checked above).
    try:
        cdig = core_digest(root)
    except (OSError, IntegrityError):
        return fail(environ, ["P02CI_CORE_DIGEST_MISMATCH"], check="core_unhashable")
    try:
        adig = adapter_digest(root)
    except (OSError, IntegrityError):
        return fail(environ, ["P02CI_ADAPTER_DIGEST_MISMATCH"], check="adapter_unhashable")
    digests = [("core build digest", cdig), ("adapter digest", adig)]
    if cdig not in core_pins:
        return fail(environ, ["P02CI_CORE_DIGEST_MISMATCH"], check="core_pin", digests=digests)
    if adig not in adapter_pins:
        return fail(environ, ["P02CI_ADAPTER_DIGEST_MISMATCH"], check="adapter_pin", digests=digests)
    log("bundle_verified", core=cdig, adapter=adig)
    from p02ci import config as config_mod
    try:
        cfg = config_mod.load_config(os.path.join(root, "ci", "p02ci", CONFIG_NAME))
    except config_mod.ConfigError:
        return fail(environ, ["P02CI_CONFIG_INVALID"], check="config", digests=digests)
    from p02ci import gitdiff
    if not (gitdiff.valid_sha(environ["P02_BASE_SHA"]) and gitdiff.valid_sha(environ["P02_HEAD_SHA"])):
        return fail(environ, ["P02CI_GIT_FAILED"], check="sha_format", digests=digests)
    from p02ci import app  # lazy: imports the accepted core only after both digests matched
    try:
        return app.run(app.Context(root=root, pr_dir=pr_dir, environ=environ, config=cfg, core_digest=cdig,
                                   adapter_digest=adig))
    except Exception as exc:  # never echo the message (it may contain data); type name only
        log("internal_error", error_type=type(exc).__name__)
        return fail(environ, ["P02CI_INTERNAL"], check="exception", digests=digests)
