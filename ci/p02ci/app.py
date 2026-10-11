"""Pipeline: changes -> classification -> staging -> P02 review/explain -> integrity -> summary -> ack.

Imported by the bootstrap only after both bundle digests matched (02 sec. 4). Never executes PR content: the
PR checkout is read as data (git plumbing output and bounded O_NOFOLLOW reads) and is never a working
directory, an import path or an argument to anything but `git -C`.
"""
import datetime
import os
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List

from p02ci import bootstrap, classify, config as config_mod, gitdiff, outcome, render, runner, stage, validate
from p02ci.model import PackageReport, RunReport, order_packages


@dataclass
class Context:
    root: str
    pr_dir: str
    environ: Dict[str, str]
    config: config_mod.Config
    core_digest: str
    adapter_digest: str


def _python_version() -> str:
    return ".".join(str(x) for x in sys.version_info[:3])


def _footer(ctx: Context) -> dict:
    return {"core_digest": ctx.core_digest, "adapter_digest": ctx.adapter_digest, "python": _python_version()}


def _finish(ctx: Context, rep: RunReport) -> int:
    text, row = render.render(rep)
    td = rep.trust_degraded
    ack = outcome.ack_value(row, td)
    code = outcome.exit_code(row, td, rep.gate_mode)
    if not bootstrap.write_outputs(ctx.environ, text, ack):
        bootstrap.log("output_unwritable")
        return outcome.EXIT_TECHNICAL
    bootstrap.log("result", row=row, ack=ack, exit=code, gate_mode=rep.gate_mode)
    return code


def _tech(ctx: Context, codes: List[str], td: bool, mode: str) -> int:
    rep = RunReport(packages=[], unreviewed=[], unreviewable_count=0, trust_degraded=td, gate_mode=mode,
                    gate_note=None, failure_codes=codes, footer=_footer(ctx))
    return _finish(ctx, rep)


def _run_package(ctx: Context, index: int, pkg: str, work_root: str, cwd: str) -> PackageReport:
    base = os.path.join(work_root, str(index))
    os.mkdir(base, 0o700)
    fixture = os.path.join(base, "fixture")
    st = stage.stage_package(ctx.pr_dir, pkg, fixture)
    report = PackageReport(index=index, path=pkg, row=1, status="technical_failure", review_exit=None,
                           explain_exit=None, v2=None, v3=None, error_codes=[], refusals=list(st.refusals),
                           secret_hits=[], failure=None)
    if st.manifest_refused:
        report.row, report.status = 3, "refused"
        bootstrap.log("package", index=index, staged="refused", row=3)
        return report
    env = runner.p02_env(ctx.environ, ctx.root)
    rwork = os.path.join(base, "review")
    os.mkdir(rwork, 0o700)
    review = runner.run_p02(sys.executable, "review", fixture, [], env, cwd, rwork)
    explain = None
    if review.exit_code == 0 and not review.timed_out:
        v2_files = list(review.out_files)
        ework = os.path.join(base, "explain")
        os.mkdir(ework, 0o700)
        if len(v2_files) == 1:
            v2_path = os.path.join(rwork, "out", v2_files[0])
            explain = runner.run_p02(sys.executable, "explain", fixture, ["--input-result", v2_path], env, cwd,
                                     ework)
    declared = st.declared
    fixture_id = st.view.fixture_id if st.view and st.view.accepted else None
    a = validate.assess(review, explain, declared, fixture_id)
    report.review_exit = review.exit_code
    report.explain_exit = explain.exit_code if explain else None
    report.error_codes = a.error_codes
    report.secret_hits = a.secret_hits
    report.status = a.status
    if a.row == 1:
        report.row, report.failure = 1, a.failure
    elif st.refusals and a.row > 3:
        # The adapter refused part of the package: no assessment is shown for it (row 3); a P02 credential
        # result (row 2) still outranks the refusal.
        report.row, report.status = 3, "refused"
    else:
        report.row = a.row
        if a.row in (4, 5, 7):
            report.v2, report.v3 = a.v2, a.v3
    bootstrap.log("package", index=index, review_exit=review.exit_code,
                  explain_exit=(explain.exit_code if explain else "none"), row=report.row,
                  check=(a.check or "none"))
    return report


def run(ctx: Context) -> int:
    cfg = ctx.config
    mode, note = config_mod.effective_gate(cfg, datetime.date.today())
    att = cfg.attestation or {}
    rt = ctx.environ["RUNNER_TEMP"]
    cwd = os.getcwd()
    try:
        records = gitdiff.list_changes(ctx.pr_dir, ctx.environ["P02_BASE_SHA"], ctx.environ["P02_HEAD_SHA"],
                                       ctx.environ["PATH"], cwd)
    except gitdiff.MergeRefMismatch:
        return _tech(ctx, ["P02CI_MERGE_REF_MISMATCH"], False, mode)
    except gitdiff.TooManyChanges:
        return _tech(ctx, ["P02CI_TOO_MANY_CHANGES"], False, mode)
    except gitdiff.DiffError:
        return _tech(ctx, ["P02CI_GIT_FAILED"], False, mode)
    bootstrap.log("changes", count=len(records))
    try:
        disc = classify.discover(ctx.pr_dir, records, cfg)
    except classify.TooManyPackages as exc:
        return _tech(ctx, ["P02CI_TOO_MANY_PACKAGES"], exc.protected, mode)
    except classify.PackageTooLarge as exc:
        return _tech(ctx, ["P02CI_PACKAGE_TOO_LARGE"], exc.protected, mode)
    td = disc.protected_changed
    work_root = tempfile.mkdtemp(prefix="p02-", dir=rt)
    reports = []
    ordered = order_packages([PackageReport(index=0, path=p, row=1, status="technical_failure", review_exit=None,
                                            explain_exit=None, v2=None, v3=None, error_codes=[], refusals=[],
                                            secret_hits=[], failure=None) for p in disc.packages])
    for placeholder in ordered:
        try:
            reports.append(_run_package(ctx, placeholder.index, placeholder.path, work_root, cwd))
        except (stage.StageError, OSError):
            return _tech(ctx, ["P02CI_STAGING_FAILED"], td, mode)
    assessed = {r.path: list(stage_declared(r)) for r in reports if r.row in (4, 5, 7)}
    not_assessed = {r.path for r in reports if r.row not in (4, 5, 7)}
    cls = classify.finalize(disc, cfg, assessed, not_assessed)
    rep = RunReport(packages=reports, unreviewed=cls.unreviewed, unreviewable_count=cls.unreviewable_count,
                    trust_degraded=td, gate_mode=mode, gate_note=note, failure_codes=[], footer=_footer(ctx),
                    attestation_date=att.get("verified_on"), attestation_method=att.get("method"),
                    credential_name_count=cls.credential_name_count)
    return _finish(ctx, rep)


def stage_declared(report: PackageReport):
    """Declared paths of an assessed package, taken from the validated v2 coverage (equal to the manifest's
    declared list, which validate.assess checked)."""
    return [f["path"] for f in report.v2["coverage"]["files"]]
