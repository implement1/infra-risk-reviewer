"""Shared helpers for the G-CI-2 Mode A adapter tests (L1/L2 and offline E2E equivalents).

Everything here is synthetic. Credential shapes are assembled at runtime from split parts and are never
printed. Git repositories are created in temporary directories with fixed identities and dates.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
CI_DIR = os.path.dirname(HERE)
PROJECT = os.path.dirname(CI_DIR)
SRC = os.path.join(PROJECT, "src")
CORPUS = os.path.join(PROJECT, "examples", "corpus")
WORKFLOW = os.path.join(PROJECT, ".github", "workflows", "p02-review.yml")
for _p in (SRC, CI_DIR, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

MANIFEST = "p02-manifest.json"
ACCEPTED_CORE_DIGEST = "f03b50e89db84f1974f82cabbc6e222d341dae4e206de3a32ceb1f7e20fae518"

# Credential shapes, assembled at runtime (never committed whole, never printed).
AWS_KEY = "AK" + "IA" + "Q" * 4 + "7" * 4 + "Z" * 4 + "3" * 4
GH_TOKEN = "gh" + "p_" + "aB3" * 12
PEM = "-----" + "BEGIN RSA " + "PRIVATE KEY" + "-----"
SECRETS = (AWS_KEY, GH_TOKEN, PEM)

GIT_ENV_BASE = {
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
    "GIT_AUTHOR_NAME": "synthetic", "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
    "GIT_COMMITTER_NAME": "synthetic", "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    "LANG": "C",
}


def manifest(files, fixture_id="pkg", version="2", **extra):
    m = {"manifest_version": version, "origin": "fixture", "fixture_id": fixture_id,
         "provenance": {"synthetic": True}, "files": [f if isinstance(f, dict) else {"path": f} for f in files]}
    m.update(extra)
    return json.dumps(m, indent=1) + "\n"


def corpus_files(case):
    """Return {relpath: bytes} for a corpus fixture directory (including the manifest)."""
    root = os.path.join(CORPUS, case, "fixture")
    out = {}
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            full = os.path.join(dirpath, n)
            with open(full, "rb") as fh:
                out[os.path.relpath(full, root).replace(os.sep, "/")] = fh.read()
    return out


def corpus_cases():
    return sorted(d for d in os.listdir(CORPUS) if os.path.isdir(os.path.join(CORPUS, d, "fixture")))


def package(prefix, files):
    """Prefix every key of {relpath: content} with prefix/."""
    return {f"{prefix}/{k}": v for k, v in files.items()}


# ----------------------------------------------------------------------------- digests (independent copy)
def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def core_digest(root):
    """Independent re-implementation of the documented core build digest (corepin.py algorithm)."""
    lines = []
    pkg = os.path.join(root, "src", "p02review")
    for n in sorted(os.listdir(pkg)):
        if n.endswith(".py"):
            lines.append(("src/p02review/" + n, _sha(os.path.join(pkg, n))))
    sch = os.path.join(root, "schema")
    for n in sorted(os.listdir(sch)):
        if n.endswith(".json"):
            lines.append(("schema/" + n, _sha(os.path.join(sch, n))))
    lines.sort()
    return hashlib.sha256("".join(f"{r}  {d}\n" for r, d in lines).encode("ascii")).hexdigest()


def adapter_digest(root):
    """Independent re-implementation of the adapter digest: every regular file under ci/p02ci/."""
    base = os.path.join(root, "ci", "p02ci")
    lines = []
    for dirpath, dirs, names in os.walk(base):
        dirs.sort()
        for n in names:
            full = os.path.join(dirpath, n)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            lines.append((rel, _sha(full)))
    lines.sort()
    return hashlib.sha256("".join(f"{r}  {d}\n" for r, d in lines).encode("ascii")).hexdigest()


# ----------------------------------------------------------------------------- trusted bundle copies
def make_trusted(dest, config_mutator=None, mutate=None):
    """Copy ci/p02ci, src/p02review and schema/ into dest (a simulated base-commit checkout)."""
    for rel in ("ci/p02ci", "src/p02review", "schema"):
        shutil.copytree(os.path.join(PROJECT, rel), os.path.join(dest, rel),
                        ignore=shutil.ignore_patterns("__pycache__"))
    if config_mutator is not None:
        path = os.path.join(dest, "ci", "p02ci", "trusted_config.json")
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        cfg = config_mutator(cfg) or cfg
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, sort_keys=True)
            fh.write("\n")
    if mutate is not None:
        mutate(dest)
    return dest


# ----------------------------------------------------------------------------- git repositories
def git(repo, *args, check=True, input_bytes=None):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **GIT_ENV_BASE}
    p = subprocess.run(["git", "-C", repo, *args], env=env, capture_output=True, input=input_bytes, check=False)
    if check and p.returncode != 0:
        raise AssertionError("git failed: " + " ".join(args) + "\n" + p.stderr.decode("utf-8", "replace"))
    return p.stdout


def write_tree(repo, files):
    """files: {relpath(str|bytes): content(bytes|str) | None (delete) | ("symlink", target) | ("hardlink", other)}"""
    for rel, content in files.items():
        relb = rel if isinstance(rel, bytes) else rel.encode("utf-8")
        full = os.path.join(os.fsencode(repo), relb)
        if content is None:
            if os.path.lexists(full):
                if os.path.isdir(full) and not os.path.islink(full):
                    shutil.rmtree(full)
                else:
                    os.unlink(full)
            continue
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if os.path.lexists(full):
            os.unlink(full)
        if isinstance(content, tuple) and content[0] == "symlink":
            os.symlink(content[1], full)
        elif isinstance(content, tuple) and content[0] == "hardlink":
            os.link(os.path.join(os.fsencode(repo), content[1].encode()), full)
        else:
            data = content.encode("utf-8") if isinstance(content, str) else content
            with open(full, "wb") as fh:
                fh.write(data)


class Repo:
    """A synthetic PR repository: base commit, then a head commit on a branch, then (by default) a test-merge
    commit with parents (base, head) checked out detached, like GitHub's refs/pull/N/merge, which is what the
    workflow checks out into pr/. `merge_ref=False` leaves the worktree at head (a single-parent checkout, which
    the adapter refuses since R3 V3-04). `gitlinks` maps paths to commit SHAs recorded as gitlinks in head."""

    def __init__(self, root, base_files, head_changes=None, renames=(), merge_ref=True, gitlinks=None):
        self.path = os.path.join(tempfile.mkdtemp(prefix="repo-", dir=root), "pr")
        os.makedirs(self.path)
        git(self.path, "init", "-q", "-b", "main")
        write_tree(self.path, base_files or {"README.md": "synthetic base\n"})
        git(self.path, "add", "-A")
        git(self.path, "commit", "-q", "-m", "base", "--allow-empty")
        self.base = git(self.path, "rev-parse", "HEAD").decode().strip()
        git(self.path, "checkout", "-q", "-b", "pr")
        for old, new in renames:
            os.makedirs(os.path.dirname(os.path.join(self.path, new)) or self.path, exist_ok=True)
            git(self.path, "mv", old, new)
        if head_changes:
            write_tree(self.path, head_changes)
        git(self.path, "add", "-A")
        for gpath, gsha in (gitlinks or {}).items():
            git(self.path, "update-index", "--add", "--cacheinfo", f"160000,{gsha or self.base},{gpath}")
        git(self.path, "commit", "-q", "-m", "head", "--allow-empty")
        self.head = git(self.path, "rev-parse", "HEAD").decode().strip()
        self.merge = None
        if merge_ref:
            # Like GitHub's refs/pull/N/merge: a test-merge commit with parents (base, head), checked out detached.
            git(self.path, "checkout", "-q", "--detach", self.base)
            git(self.path, "merge", "-q", "--no-ff", "-m", "merge ref", self.head)
            self.merge = git(self.path, "rev-parse", "HEAD").decode().strip()


# ----------------------------------------------------------------------------- running the adapter
class AdapterRun:
    def __init__(self, exit_code, summary, outputs_raw, stdout, stderr, runner_temp):
        self.exit = exit_code
        self.summary = summary
        self.outputs_raw = outputs_raw
        self.stdout = stdout
        self.stderr = stderr
        self.runner_temp = runner_temp

    @property
    def ack(self):
        vals = [line[4:] for line in self.outputs_raw.split("\n") if line.startswith("ack=")]
        return vals[-1] if vals else None

    @property
    def red(self):
        return self.exit != 0

    def banner(self):
        first = self.summary.split("\n", 1)[0]
        return first

    def all_text(self):
        return self.summary + self.outputs_raw + self.stdout + self.stderr


def adapter_cmd(pr_dir, core_pins, adapter_pins, python_flags=("-P", "-s", "-B")):
    cmd = [sys.executable, *python_flags, "-m", "p02ci", "--pr-dir", pr_dir]
    for d in core_pins:
        cmd += ["--expect-core-digest", d]
    for d in adapter_pins:
        cmd += ["--expect-adapter-digest", d]
    return cmd


def run_adapter(tmp, repo, trusted=PROJECT, base=None, head=None, env_extra=None, env_drop=(),
                core_pins=None, adapter_pins=None, python_flags=("-P", "-s", "-B"), cwd=None,
                pythonpath=None, summary_path=None, output_path=None, timeout=300):
    """Run the adapter exactly as the workflow does: env -i with the allow-list, -P -s -B, empty cwd."""
    rt = tempfile.mkdtemp(prefix="rt-", dir=tmp)
    work = cwd or tempfile.mkdtemp(prefix="cwd-", dir=tmp)
    summary_path = summary_path or os.path.join(tmp, "step_summary_" + os.path.basename(rt))
    output_path = output_path or os.path.join(tmp, "output_" + os.path.basename(rt))
    for p in (summary_path, output_path):
        if not os.path.exists(p) and os.path.isdir(os.path.dirname(p)):
            open(p, "w").close()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": pythonpath if pythonpath is not None else f"{trusted}/src:{trusted}/ci",
        "PYTHONDONTWRITEBYTECODE": "1",
        "RUNNER_TEMP": rt,
        "GITHUB_OUTPUT": output_path,
        "GITHUB_STEP_SUMMARY": summary_path,
        "P02_BASE_SHA": base if base is not None else repo.base,
        "P02_HEAD_SHA": head if head is not None else repo.head,
    }
    for k in env_drop:
        env.pop(k, None)
    env.update(env_extra or {})
    core_pins = core_pins if core_pins is not None else [core_digest(trusted)]
    adapter_pins = adapter_pins if adapter_pins is not None else [adapter_digest(trusted)]
    p = subprocess.run(adapter_cmd(repo.path, core_pins, adapter_pins, python_flags), env=env, cwd=work,
                       capture_output=True, timeout=timeout)
    summary = ""
    if os.path.isfile(summary_path):
        with open(summary_path, "rb") as fh:
            summary = fh.read().decode("utf-8", "replace")
    outputs = ""
    if os.path.isfile(output_path):
        with open(output_path, "rb") as fh:
            outputs = fh.read().decode("utf-8", "replace")
    return AdapterRun(p.returncode, summary, outputs, p.stdout.decode("utf-8", "replace"),
                      p.stderr.decode("utf-8", "replace"), rt)


# Banner fragments (04 sec. 6, ASCII form; A-8 escaping rule).
BANNER = {
    1: "TECHNICAL FAILURE -- no assessment produced",
    2: "BLOCKED -- suspected credential in submitted files (value not shown). Remove it and rotate the credential.",
    3: "INPUT REJECTED -- no assessment produced",
    4: "BLOCKING REVIEW REQUIRED -- high-severity finding confirmed by a deterministic rule",
    5: "ANALYSIS INCOMPLETE -- P02 could not evaluate everything; this is not a low-risk result",
    6: "FILES CHANGED BUT NOT REVIEWED -- P02 did not analyse these changes",
    7: "NO BLOCKING FINDINGS BY BASELINE RULES -- not a safety approval; normal human review still required.",
    8: "NO INFRASTRUCTURE CHANGES DETECTED",
}
HEADER = "## P02 Infrastructure Risk Review -- "
TRUST_DEGRADED = "TRUST DEGRADED: this PR modifies the P02 workflow or tooling; this result is not authoritative."
FALLBACK = "P02 summary could not be rendered safely; no assessment is shown."


def env_mode_config(cfg, verified_on=None):
    """Mutate a trusted config into a fully attested reviewer-environment gate."""
    import datetime
    day = verified_on if verified_on is not None else datetime.date.today().isoformat()
    cfg["gate"] = {
        "mode": "environment",
        "environment_attestation": {
            "environment": "p02-risk-acknowledgement",
            "required_reviewers": True,
            "prevent_self_review": True,
            "admin_bypass_disabled": True,
            "reviewer_team_excludes_pr_authors": True,
            "no_environment_secrets": True,
            "method": "admin-api-read",
            "verified_by": "repository-admin",
            "verified_on": day,
        },
        "attestation_max_age_days": cfg.get("gate", {}).get("attestation_max_age_days", 90),
    }
    return cfg


class TmpCase(unittest.TestCase):
    """unittest base with a per-test temporary directory (removed afterwards).

    `self.env_trusted` is a trusted-bundle copy whose config carries a complete, current reviewer-environment
    attestation (gate mode 'environment'); the repository's own config uses the fail-on-risk fallback."""

    _env_trusted_dir = None

    @classmethod
    def setUpClass(cls):
        cls._class_tmp = tempfile.mkdtemp(prefix="p02ci-class-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._class_tmp, True)

    @property
    def env_trusted(self):
        cls = type(self)
        if cls._env_trusted_dir is None or not os.path.isdir(cls._env_trusted_dir):
            d = os.path.join(cls._class_tmp, "trusted-env")
            make_trusted(d, config_mutator=env_mode_config)
            cls._env_trusted_dir = d
        return cls._env_trusted_dir

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p02ci-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def repo(self, base_files, head_changes=None, renames=(), merge_ref=True, gitlinks=None):
        return Repo(self.tmp, base_files, head_changes, renames, merge_ref, gitlinks)

    def run_ci(self, repo, **kw):
        return run_adapter(self.tmp, repo, **kw)

    # assertions -----------------------------------------------------------------
    def assertRow(self, run, row):
        self.assertTrue(run.summary.startswith(HEADER + BANNER[row] + "\n"),
                        f"expected banner row {row}; got: {run.summary[:200]!r} exit={run.exit}")

    def assertNoLeak(self, run, *needles):
        text = run.all_text()
        for n in needles or SECRETS:
            self.assertNotIn(n, text)
        for dirpath, _d, names in os.walk(run.runner_temp):
            for name in names:
                pass  # staging copies legitimately hold PR content; they never reach summary/log/output

    def assertGreen(self, run):
        self.assertEqual(run.exit, 0, run.summary[:400] + run.stderr[-400:])

    def assertRed(self, run):
        self.assertNotEqual(run.exit, 0, run.summary[:400])

    def assertAckRequired(self, run):
        self.assertEqual(run.ack, "required")

    def assertSummaryAscii(self, run):
        run.summary.encode("ascii")
