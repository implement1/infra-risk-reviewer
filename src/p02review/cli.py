"""Command-line entrypoint: ``python -m p02review ingest FIXTURE_DIR [--out-dir DIR]``.

Exit codes:
  0  completed (ingestion succeeded; policy decision is still ``inconclusive``)
  2  usage error (bad command-line arguments)
  3  input rejected (validation failure)
  4  input rejected because a suspected credential was found
  5  internal failure (details withheld)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .errors import InputRejected, ResultValidationError
from .intake import run_intake, strip_trailing_separators
from .limits import DEFAULT_LIMITS, tightened
from .analysis import analyze, decoded_secret_hits
from .result import STATUS_COMPLETED, STATUS_INTERNAL_ERROR, _RUN_ID_RE, build_result
from .secret_screen import screen_text
from .pipeline import review_pipeline
from .p3_explain import explain_command, summary_v3

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INPUT_REJECTED = 3
EXIT_SECRET_BLOCKED = 4
EXIT_INTERNAL = 5

# Hard-coded last-resort output if even the internal-error result cannot be built.
_FALLBACK = {"schema_version": "p02.run-result.v1", "status": "internal_error",
             "policy": {"decision": "inconclusive"},
             "errors": [{"code": "INTERNAL_ERROR", "message": "Result construction failed; details withheld."}]}


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # keep exit 2 but avoid echoing long untrusted argv fragments
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: invalid arguments\n")
        raise SystemExit(EXIT_USAGE)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog=TOOL_NAME, description="P02 offline fixture ingestion (ingest, Phase 1 contract) and "
                                            "deterministic IaC baseline review (review, Phase 2 contract).")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)
    ing = sub.add_parser("ingest", help="Validate a local synthetic fixture and emit a result JSON.")
    ing.add_argument("fixture_dir", help="Directory containing p02-manifest.json and declared files.")
    ing.add_argument("--out-dir", help="Directory to write <run_id>.json into (must be outside the fixture).")
    ing.add_argument("--run-id", help="Override the deterministic run ID ([A-Za-z0-9._-]{1,64}).")
    ing.add_argument("--max-file-bytes", type=int, help="Lower the per-file ceiling.")
    ing.add_argument("--max-total-bytes", type=int, help="Lower the total-size ceiling.")
    ing.add_argument("--max-files", type=int, help="Lower the file-count ceiling.")
    ing.add_argument("--quiet", action="store_true", help="Do not print the human summary to stderr.")
    rev = sub.add_parser("review", help="Ingest (manifest v1 or v2) and run the Phase 2 deterministic analyzers; "
                                        "emits a p02.run-result.v2 JSON.")
    for action in ing._actions:
        if action.dest != "help":
            rev._add_action(action)
    exp = sub.add_parser("explain", help="Phase 3A: re-derive the v2 result for a fixture and emit an advisory, "
                                         "template-only p02.report.v3 JSON (no model, no source excerpts).")
    exp.add_argument("fixture_dir", help="Directory containing p02-manifest.json and declared files.")
    exp.add_argument("--input-result", help="Optional v2 result to check; it must equal the re-derived result.")
    for action in ing._actions:
        if action.dest in ("out_dir", "max_file_bytes", "max_total_bytes", "max_files", "quiet"):
            exp._add_action(action)
    return p


def _resolve_out_dir(out_dir: str, fixture_dir: str) -> str:
    """Validate only; the directory is created when the result is written."""
    out_dir = strip_trailing_separators(out_dir)
    if os.path.islink(out_dir):
        raise ValueError("--out-dir must not be a symbolic link")
    if os.path.exists(out_dir) and not os.path.isdir(out_dir):
        raise ValueError("--out-dir exists and is not a directory")
    real_out = os.path.realpath(out_dir)
    real_fix = os.path.realpath(strip_trailing_separators(fixture_dir))
    if os.path.commonpath([real_out, real_fix]) == real_fix:
        raise ValueError("--out-dir must be outside the fixture directory")
    return real_out


def _write_atomic(directory: str, name: str, payload: str) -> str:
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".p02-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        final = os.path.join(directory, name)
        os.replace(tmp, final)
        return final
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _summary(result: dict) -> str:
    if result.get("schema_version") == "p02.report.v3":
        return summary_v3(result)
    lines = [
        f"{TOOL_NAME}: status={result['status']} decision={result['policy']['decision']} "
        f"run_id={result['run_id']}",
        f"  files accepted: {result['coverage']['files_accepted']}/{result['coverage']['files_declared']}; "
        f"findings: {len(result['findings'])}; errors: {result['errors_total']}",
    ]
    if result.get("input_identity"):
        lines.append(f"  input identity: {result['input_identity']['input_identity_sha256']}")
    for err in result.get("errors", [])[:10]:
        loc = err.get("path", "")
        if err.get("line"):
            loc += f":{err['line']}"
        lines.append(f"  - {err['code']} {loc} {err['message']}".rstrip())
    if result.get("schema_version") == "p02.run-result.v2":
        cov = result["coverage"]
        lines.append(f"  analysis complete: {cov['analysis_complete']}; reasons: {', '.join(result['policy']['reasons'])}")
        for f in result["findings"][:15]:
            loc = f["location"]
            where = loc["plan_address"] or f"{loc['path']}:{loc['line_start']}-{loc['line_end']}"
            lines.append(f"  * {f['rule_id']} {f['severity']}/{f['state']} {where}")
        for c in cov["files"]:
            if c["status"] != "analyzed":
                codes = ",".join(n["code"] for n in c["notes"][:3])
                lines.append(f"  ~ coverage gap: {c['path']} status={c['status']} {codes}".rstrip())
        lines.append("  NOTE: baseline rules only; no decision here is a statement that the change is safe.")
        return "\n".join(lines) + "\n"
    lines.append("  NOTE: no infrastructure risk analysis is performed in Phase 1; this is not a safety verdict.")
    return "\n".join(lines) + "\n"


def _elapsed(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _ingest(args, limits, started) -> dict:
    """Phase 1 contract (unchanged): manifest v1 only, p02.run-result.v1, always inconclusive."""
    outcome = None
    try:
        try:
            outcome = run_intake(args.fixture_dir, limits)
            return build_result(outcome, limits=limits, run_id=args.run_id, elapsed_ms=_elapsed(started))
        except InputRejected as exc:
            return build_result(outcome, limits=limits, run_id=args.run_id, structural_issue=exc.issue,
                                elapsed_ms=_elapsed(started))
    except Exception as exc:  # internal failure: report type only, never the message (may contain data)
        try:
            return build_result(None, limits=limits, run_id=args.run_id, internal_error=type(exc).__name__,
                                elapsed_ms=_elapsed(started))
        except (ResultValidationError, Exception):
            return dict(_FALLBACK)


def _review(args, limits, started) -> dict:
    """Phase 2 contract: manifest v1 or v2, deterministic analysis, p02.run-result.v2.
    The implementation lives in pipeline.review_pipeline (shared with Phase 3A `explain`)."""
    return review_pipeline(args.fixture_dir, limits, args.run_id, started).result


def run(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    overrides = {k: v for k, v in (("max_file_bytes", args.max_file_bytes),
                                   ("max_total_bytes", args.max_total_bytes),
                                   ("max_files", args.max_files)) if v is not None}
    try:
        limits = tightened(DEFAULT_LIMITS, **overrides)
    except ValueError as exc:
        sys.stderr.write(f"{TOOL_NAME}: error: {exc}\n")
        return EXIT_USAGE
    if getattr(args, "run_id", None) is not None and not _RUN_ID_RE.match(args.run_id):
        sys.stderr.write(f"{TOOL_NAME}: error: --run-id must match [A-Za-z0-9._-]{{1,64}}\n")
        return EXIT_USAGE
    if getattr(args, "run_id", None) is not None and screen_text(args.run_id, 1):
        # Hardening L3: a credential-shaped run ID is invalid CLI input (exit 2), checked before any input is
        # read; the value is never reflected (it would otherwise reach the result, its file name and stdout).
        sys.stderr.write(f"{TOOL_NAME}: error: --run-id must not contain credential-shaped content "
                         f"(value withheld)\n")
        return EXIT_USAGE
    out_dir = None
    if args.out_dir:
        try:
            out_dir = _resolve_out_dir(args.out_dir, args.fixture_dir)
        except (ValueError, OSError) as exc:
            msg = str(exc) if isinstance(exc, ValueError) else "cannot create --out-dir"
            sys.stderr.write(f"{TOOL_NAME}: error: {msg}\n")
            return EXIT_USAGE

    started = time.perf_counter()
    if args.command == "review":
        result = _review(args, limits, started)
    elif args.command == "explain":
        result = explain_command(args.fixture_dir, getattr(args, "input_result", None), limits, started)
    else:
        result = _ingest(args, limits, started)

    payload = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
    if out_dir is not None and result.get("run_id"):
        try:
            _write_atomic(out_dir, f"{result['run_id']}.json", payload)
        except OSError:
            sys.stderr.write(f"{TOOL_NAME}: error: could not write result file\n")
            return EXIT_INTERNAL
    sys.stdout.write(payload)
    if not args.quiet and "coverage" in result:
        sys.stderr.write(_summary(result))

    status = result.get("status")
    if status == STATUS_COMPLETED:
        return EXIT_OK
    if status == STATUS_INTERNAL_ERROR:
        return EXIT_INTERNAL
    # Decide from the policy reasons, which are never truncated (the error list may be).
    policy = result.get("policy") or result.get("v2_policy") or {}  # v3 carries the v2 policy verbatim
    if "SUSPECTED_SECRET_BLOCKED" in policy.get("reasons", []):
        return EXIT_SECRET_BLOCKED
    if result.get("schema_version") == "p02.report.v3" and any(
            e.get("code") == "SECRET_SUSPECTED" for e in result.get("errors", [])):
        return EXIT_SECRET_BLOCKED  # Phase 3A output gate (v3 only; v1/v2 exit logic unchanged)
    return EXIT_INPUT_REJECTED


def main() -> None:
    raise SystemExit(run())
