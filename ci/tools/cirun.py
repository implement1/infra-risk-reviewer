"""Run the G-CI-2 adapter test suite and keep a log under evidence/cicd/ (never overwrites an existing log).

Usage: python3 -B ci/tools/cirun.py LOGNAME "note" [unittest args...]
Runs from the project root with PYTHONPATH=<abs>/src:<abs>/ci:<abs>/ci/tests, -B, -W error and
-W error::ResourceWarning. Extra interpreter flags (for example -O) come from CI_PY_FLAGS. Set CI_UNSHARE=1 to
run the suite inside `unshare -n` (no network namespace).
"""
import datetime
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    name, note, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
    logdir = os.path.join(ROOT, "evidence", "cicd")
    os.makedirs(logdir, exist_ok=True)
    path = os.path.join(logdir, name + ".log")
    if os.path.exists(path):
        sys.exit(f"refusing to overwrite {path}")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "PYTHONPATH": os.pathsep.join(os.path.join(ROOT, p) for p in ("src", "ci", os.path.join("ci", "tests"))),
           "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8"}
    extra = os.environ.get("CI_PY_FLAGS", "").split()
    cmd = [sys.executable, "-B", *extra, "-W", "error", "-W", "error::ResourceWarning", "-m", "unittest"]
    cmd += rest if rest else ["discover", "-s", "ci/tests", "-t", "ci/tests", "-p", "test_ci*.py", "-v"]
    if os.environ.get("CI_UNSHARE") == "1":
        cmd = ["unshare", "-n", *cmd]
    started = datetime.datetime.now(datetime.timezone.utc)
    p = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    stamp = started.strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(path, "x", encoding="utf-8") as fh:
        fh.write(f"# {name}\n# {stamp}\n# note: {note}\n# cmd: {' '.join(cmd)} (cwd=project root)\n"
                 f"# python: {sys.version.split()[0]}\n# exit: {p.returncode}\n\n{p.stdout}{p.stderr}")
    tail = (p.stdout + p.stderr).strip().splitlines()[-4:]
    print(f"{name}: exit {p.returncode}")
    print("\n".join(tail))


if __name__ == "__main__":
    main()
