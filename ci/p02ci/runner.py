"""Run the accepted P02 CLI as an isolated subprocess (02 sec. 7.5; A-8).

Argument list, no shell; `python3 -P -s -B -m p02review`; environment exactly PATH, PYTHONPATH=<trusted>/src and
PYTHONDONTWRITEBYTECODE=1 (plus LD_LIBRARY_PATH only when the adapter itself was given one, A-8); working
directory is the adapter's empty directory; stdout and stderr go to files, never to the log; 120 s timeout.
The adapter never passes --run-id (explain's comparison would otherwise fail, 02 sec. 4).
"""
import os
import subprocess
from typing import Dict, List

from p02ci.validate import ProcResult

TIMEOUT = 120
MAX_STDOUT = 32 * 1024 * 1024
MAX_OUT_FILES = 4


def p02_env(adapter_env: Dict[str, str], trusted_root: str) -> Dict[str, str]:
    env = {"PATH": adapter_env["PATH"], "PYTHONPATH": os.path.join(trusted_root, "src"),
           "PYTHONDONTWRITEBYTECODE": "1"}
    if adapter_env.get("LD_LIBRARY_PATH"):
        env["LD_LIBRARY_PATH"] = adapter_env["LD_LIBRARY_PATH"]
    return env


def p02_command(python: str, command: str, fixture: str, extra: List[str]) -> List[str]:
    return [python, "-P", "-s", "-B", "-m", "p02review", command, fixture, *extra]


def _read_bounded(path: str, limit: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(limit + 1)


def run_p02(python: str, command: str, fixture: str, extra: List[str], env: Dict[str, str], cwd: str,
            work: str) -> ProcResult:
    """Run one P02 command. `work` is a fresh directory for stdout/stderr files and the --out-dir."""
    out_dir = os.path.join(work, "out")
    os.mkdir(out_dir, 0o700)
    stdout_path = os.path.join(work, "stdout.json")
    stderr_path = os.path.join(work, "stderr.txt")
    cmd = p02_command(python, command, fixture, ["--out-dir", out_dir, "--quiet", *extra])
    timed_out = False
    code = None
    with open(stdout_path, "xb") as out, open(stderr_path, "xb") as err:
        try:
            p = subprocess.run(cmd, env=env, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                               timeout=TIMEOUT, check=False)
            code = p.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
    stdout = _read_bounded(stdout_path, MAX_STDOUT)
    files = {}
    names = sorted(os.listdir(out_dir))
    for name in names[:MAX_OUT_FILES]:
        full = os.path.join(out_dir, name)
        if os.path.islink(full) or not os.path.isfile(full):
            files[name] = b""
            continue
        files[name] = _read_bounded(full, MAX_STDOUT)
    if len(names) > MAX_OUT_FILES:
        files["__too_many__"] = b""
    return ProcResult(code, stdout, files, timed_out=timed_out)
