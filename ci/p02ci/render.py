"""Job-summary renderer (04; A-8): a rendering of the deterministic P02 result, never a judgement of its own.

* Only allowlisted, closed-vocabulary fields are rendered. Identifiers and paths are rendered only through the
  accepted core display functions (display_ident, display_resource, display_path; read-only imports), and are
  additionally withheld if credential-shaped.
* Inside code spans only allow-listed tokens ([A-Za-z0-9_.-]) or display-function output are emitted, verbatim.
  Outside code spans every character of renderer-owned text outside [A-Za-z0-9 .,:;()'/=+-] is emitted as an
  HTML numeric entity (A-8 clarification of 04 sec. 5.3). Output is ASCII only.
* Deterministic ordering; 64 KiB target with the 04 sec. 4 shrink order; 256 KiB hard cap.
* Before the summary is returned, a self-check validates structure, character set, headings, code spans,
  banned wording and re-runs the core credential screens over the whole text. Any failure yields the constant
  fallback summary and a technical failure.
"""
import re
from typing import List, Optional, Tuple

from p02review.p3_templates import IDENT_WITHHELD, PATH_WITHHELD, display_ident, display_path, display_resource
from p02review.result_v3 import BANNED_PHRASES, strict_secret_hit
from p02review.secret_screen import screen_text

from p02ci import bootstrap, outcome, vocab
from p02ci.model import PackageReport, RunReport

TARGET = 64 * 1024
HARD_CAP = 256 * 1024
MAX_PACKAGES = 10
MAX_REFUSAL_ROWS = 20      # R1 V1-03: refusal and credential-hit tables are bounded too; counts stay complete
MAX_SECRET_ROWS = 20

HEADER = bootstrap.HEADER
STANDARD_LINE = bootstrap.STANDARD_LINE
UNTRUSTED_LINE = "> Identifiers below are untrusted data taken from the submitted files."
TRUST_LINE = "> " + bootstrap.TRUST_DEGRADED

BANNERS = {
    1: bootstrap.TECH_BANNER,
    2: "BLOCKED -- suspected credential in submitted files (value not shown). Remove it and rotate the credential.",
    3: "INPUT REJECTED -- no assessment produced",
    4: "BLOCKING REVIEW REQUIRED -- high-severity finding confirmed by a deterministic rule",
    5: "ANALYSIS INCOMPLETE -- P02 could not evaluate everything; this is not a low-risk result",
    6: "FILES CHANGED BUT NOT REVIEWED -- P02 did not analyse these changes",
    7: "NO BLOCKING FINDINGS BY BASELINE RULES -- not a safety approval; normal human review still required.",
    8: "NO INFRASTRUCTURE CHANGES DETECTED",
}
OUTCOME_LABEL = {1: "TECHNICAL FAILURE", 2: "BLOCKED (suspected credential)", 3: "INPUT REJECTED",
                 4: "REVIEW REQUIRED", 5: "ANALYSIS INCOMPLETE", 7: "NO BLOCKING FINDINGS (not a safety approval)"}
PACKAGE_STATUSES = ("completed", "rejected", "internal_error", "refused", "technical_failure")

# Budget steps (04 sec. 4): applied cumulatively until the summary fits the 64 KiB target.
BUDGETS = (
    {"questions": True, "names": 50, "findings": 50, "gaps": 50},
    {"questions": False, "names": 50, "findings": 50, "gaps": 50},
    {"questions": False, "names": 10, "findings": 50, "gaps": 50},
    {"questions": False, "names": 10, "findings": 20, "gaps": 50},
    {"questions": False, "names": 10, "findings": 20, "gaps": 20},
)

_TEXT_OK = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;()'/=+-")
_TOKEN_RE = re.compile(r"\A[A-Za-z0-9_.-]{1,200}\Z")
_SPAN_RE = re.compile(r"`([^`\n]*)`")
_ENTITY_RE = re.compile(r"&#[0-9]{1,3};")
_RESIDUAL_OK = _TEXT_OK | frozenset("|#*>&\n")
_HEADING_RES = (
    re.compile(r"\A## P02 Infrastructure Risk Review -- .+\Z"),
    re.compile(r"\A### Package [0-9]{1,2}\Z"),
    re.compile(r"\A#### (Coverage gaps \(shown first\)|Findings|Questions for the reviewer)\Z"),
    re.compile(r"\A### Changed but not reviewed\Z"),
)
_QUOTE_LINES = frozenset((STANDARD_LINE, UNTRUSTED_LINE, TRUST_LINE))
_SEV_RANK = {s: i for i, s in enumerate(vocab.SEVERITIES)}
_STATE_RANK = {s: i for i, s in enumerate(vocab.STATES)}
_DATE_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_VERSION_RE = re.compile(r"\A[0-9]{1,3}(\.[0-9]{1,3}){1,3}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class RenderError(Exception):
    pass


# ----------------------------------------------------------------------------- primitives
def escape_text(s: str) -> str:
    return "".join(c if c in _TEXT_OK else f"&#{ord(c)};" for c in s)


esc = escape_text


def code(token: str) -> str:
    if not isinstance(token, str) or not _TOKEN_RE.match(token):
        raise RenderError("token")
    return f"`{token}`"


def _display_valid(v: str) -> bool:
    if v in (IDENT_WITHHELD, PATH_WITHHELD):
        return True
    return display_ident(v) == v or display_resource(v) == v or display_path(v) == v


def code_display(v: str) -> str:
    if not isinstance(v, str) or not _display_valid(v) or any(c in v for c in "`|\\\n<>&"):
        raise RenderError("display")
    return f"`{v}`"


def _credential_shaped(v: str) -> bool:
    return bool(screen_text(v, 1)) or strict_secret_hit(v)


def ident_cell(v, k8s: bool = False) -> str:
    d = display_resource(v) if k8s else display_ident(v)
    if d != IDENT_WITHHELD and _credential_shaped(d):
        d = IDENT_WITHHELD
    return code_display(d)


def path_cell(v) -> str:
    d = display_path(v)
    if d != PATH_WITHHELD and _credential_shaped(d):
        d = PATH_WITHHELD
    return code_display(d)


def _ids(ids: List[str], limit: int = 3) -> str:
    shown = [code(i) for i in ids[:limit]]
    extra = len(ids) - limit
    return (", ".join(shown) if shown else "-") + (f" +{extra}" if extra > 0 else "")


def _codes_cell(codes: List[str], limit: int = 5) -> str:
    seen = []
    for c in codes:
        if c not in seen:
            seen.append(c)
    return _ids(seen, limit)


# ----------------------------------------------------------------------------- sections
def _conclusion(row: int, td: bool, mode: str) -> str:
    needs_ack = outcome.ack_value(row, td) == "required"
    if row in (2, 3):
        return "the review job fails; no trustworthy assessment exists for the rejected or blocked input."
    if needs_ack and mode == "environment":
        return ("the gate job waits for a designated reviewer to acknowledge this result in the environment "
                "p02-risk-acknowledgement.")
    if needs_ack:
        return ("human acknowledgement is required, so the review job fails (fail-on-risk fallback). Override only "
                "through the repository's normal bypass procedure.")
    return "no acknowledgement is requested by P02; normal pull request review still applies."


def _gate_line(rep: RunReport) -> str:
    if rep.gate_mode == "environment":
        date = rep.attestation_date if rep.attestation_date and _DATE_RE.match(rep.attestation_date) else None
        method = rep.attestation_method if rep.attestation_method in ("admin-api-read", "canary-pr") else None
        if not date or not method:
            raise RenderError("attestation")
        return esc(f"reviewer environment p02-risk-acknowledgement (protection attested on {date}; method "
                   f"{method}).")
    text = esc("fail-on-risk fallback (D-CI-02(b)): the review job fails whenever human acknowledgement is "
               "required.")
    if rep.gate_note and rep.gate_note != "GATE_FALLBACK_CONFIGURED":
        text += " " + esc("The reviewer-environment attestation is missing, incomplete or expired") + \
            " (" + code(rep.gate_note) + ")."
    return text


def _counts(v2: dict) -> str:
    c = {s: 0 for s in vocab.SEVERITIES}
    for f in v2["findings"]:
        c[f["severity"]] += 1
    return "/".join(str(c[s]) for s in vocab.SEVERITIES)


def _gaps(v2: dict) -> list:
    return [f for f in v2["coverage"]["files"] if f["status"] != "analyzed" or f["notes"]]


def _overview(rep: RunReport) -> List[str]:
    lines = ["| # | Package (untrusted) | Outcome | P02 status | Decision | Findings C/H/U/M/L/I | Coverage |",
             "|---|---|---|---|---|---|---|"]
    for p in rep.packages:
        if p.status not in PACKAGE_STATUSES:
            raise RenderError("status")
        assessed = p.row in (4, 5, 7) and p.v2 is not None
        decision = code(p.v2["policy"]["decision"]) if assessed else "-"
        counts = _counts(p.v2) if assessed else "-"
        if assessed:
            n = len(_gaps(p.v2))
            cov = "complete" if p.v2["coverage"]["analysis_complete"] else f"incomplete ({n} files with gaps)"
        else:
            cov = "-"
        lines.append(f"| {p.index} | {path_cell(p.path)} | {esc(OUTCOME_LABEL[p.row])} | {code(p.status)} | "
                     f"{decision} | {counts} | {esc(cov)} |")
    return lines


def _location(f: dict) -> str:
    loc = f.get("location") or {}
    parts = []
    if loc.get("path") is not None:
        parts.append(path_cell(loc["path"]))
    a, b = loc.get("line_start"), loc.get("line_end")
    if isinstance(a, int) and not isinstance(a, bool):
        if isinstance(b, int) and not isinstance(b, bool) and b != a:
            parts.append(f"lines {a}-{b}")
        else:
            parts.append(f"line {a}")
    if loc.get("plan_address"):
        parts.append(ident_cell(loc["plan_address"]))
    return " ".join(parts) if parts else "-"


def _refusal_table(p: PackageReport) -> List[str]:
    if not p.refusals:
        return []
    lines = ["| Adapter refusal | File (untrusted) |", "|---|---|"]
    for c, path in p.refusals:
        if c not in vocab.ADAPTER_REFUSALS:
            raise RenderError("refusal code")
    for c, path in p.refusals[:MAX_REFUSAL_ROWS]:
        lines.append(f"| {code(c)} | {path_cell(path)} |")
    if len(p.refusals) > MAX_REFUSAL_ROWS:
        lines.append(esc(f"{len(p.refusals) - MAX_REFUSAL_ROWS} further refusals not shown (count is complete); "
                         f"{len(p.refusals)} refusals in total."))
    return lines


def _secret_block(p: PackageReport) -> List[str]:
    lines = ["**Outcome:** " + esc(BANNERS[2])]
    if p.secret_hits:
        lines += ["| Screen rule | File (untrusted) |", "|---|---|"]
        for rule, _path in p.secret_hits:
            if rule not in vocab.SECRET_RULES:
                raise RenderError("secret rule")
        for rule, path in p.secret_hits[:MAX_SECRET_ROWS]:
            lines.append(f"| {code(rule)} | {path_cell(path) if path is not None else '-'} |")
        if len(p.secret_hits) > MAX_SECRET_ROWS:
            lines.append(esc(f"{len(p.secret_hits) - MAX_SECRET_ROWS} further credential hits not shown (count is "
                             f"complete); {len(p.secret_hits)} hits in total."))
    else:
        lines.append(esc("The credential screen blocked the report output; no file is named."))
    return lines


def _package_section(p: PackageReport, budget: dict) -> List[str]:
    lines = ["", f"### Package {p.index}"]
    if p.row == 2:
        lines += _secret_block(p)
        codes = [c for c in p.error_codes] + [c for c, _ in p.refusals]
        if codes:
            lines.append("**Error codes:** " + ", ".join(code(c) for c in dict.fromkeys(codes)))
        return lines + _refusal_table(p)
    if p.row == 3:
        lines.append("**Outcome:** " + esc("INPUT REJECTED -- no assessment produced; no decision or findings are "
                                           "shown."))
        codes = [c for c in p.error_codes] + [c for c, _ in p.refusals]
        lines.append("**Error codes:** " + (", ".join(code(c) for c in dict.fromkeys(codes)) or "-"))
        return lines + _refusal_table(p)
    if p.row not in (4, 5, 7) or p.v2 is None:
        raise RenderError("package row")
    v2, v3 = p.v2, p.v3 or {}
    decision = v2["policy"]["decision"]
    lines.append("**Decision:** " + code(decision) + " -- " + esc(vocab.DECISION_MEANING[decision]))
    lines.append("**Reasons:** " + ", ".join(code(r) for r in v2["policy"]["reasons"]))
    gaps = _gaps(v2)
    if gaps:
        lines += ["#### Coverage gaps (shown first)", "| File (untrusted) | Status | Note codes (deduplicated) |",
                  "|---|---|---|"]
        for g in gaps[:budget["gaps"]]:
            lines.append(f"| {path_cell(g['path'])} | {code(g['status'])} | "
                         f"{_codes_cell([n['code'] for n in g['notes']])} |")
        if len(gaps) > budget["gaps"]:
            lines.append(esc(f"{len(gaps) - budget['gaps']} further coverage gaps not shown; the analysis is "
                             "incomplete."))
    findings = sorted(v2["findings"], key=lambda f: (_SEV_RANK[f["severity"]], _STATE_RANK[f["state"]],
                                                    f["rule_id"], f["id"]))
    lines.append("#### Findings")
    if not findings:
        lines.append(esc("No findings."))
    else:
        lines += ["| # | Severity | State | Rule | Resource (untrusted) | Location (untrusted) | Finding ID | "
                  "Evidence IDs |", "|---|---|---|---|---|---|---|---|"]
        for i, f in enumerate(findings[:budget["findings"]], 1):
            k8s = f["rule_id"].startswith("K8S-")
            lines.append(f"| {i} | {code(f['severity'])} | {code(f['state'])} | {code(f['rule_id'])} | "
                         f"{ident_cell(f['resource'], k8s)} | {_location(f)} | {code(f['id'])} | "
                         f"{_ids(list(f['evidence_ids']))} |")
        if len(findings) > budget["findings"]:
            lines.append(esc(f"{len(findings) - budget['findings']} further findings not shown (counts above are "
                             "complete)."))
    qs = list(v3.get("verification_questions") or [])
    lines.append("#### Questions for the reviewer")
    if not qs:
        lines.append(esc("None."))
    elif not budget["questions"]:
        lines.append(esc(f"{len(qs)} question rows not shown (summary size limit); they are in the P02 report."))
    else:
        lines += ["| Reason code | Question (fixed text) | Cites |", "|---|---|---|"]
        for q in qs[:50]:
            rc = q["reason_code"]
            if q.get("finding_ids"):
                cites = _ids(list(q["finding_ids"]))
            elif q.get("coverage_refs"):
                cites = esc("coverage gap")
            else:
                cites = "-"
            lines.append(f"| {code(rc)} | {esc(vocab.QUESTION_TEXT[rc])} | {cites} |")
        if len(qs) > 50:
            lines.append(esc(f"{len(qs) - 50} further question rows not shown; they are in the P02 report."))
    return lines


def _unreviewed_section(rep: RunReport, budget: dict) -> List[str]:
    total = len(rep.unreviewed) + rep.unreviewable_count
    if not total:
        return []
    lines = ["", "### Changed but not reviewed",
             esc(f"These {total} files were not analysed by P02 and were not screened for credentials. Count: "
                 f"{total} (the count is complete).")]
    if rep.unreviewable_count:
        lines.append(esc(f"{rep.unreviewable_count} of them have names that P02 does not display (unreviewable "
                         "names); they are counted, not listed."))
    if rep.credential_name_count:
        lines.append(esc(f"{rep.credential_name_count} changed file names have a credential shape (not shown). If "
                         "any of them was ever a real credential, remove it and rotate it."))
    if rep.unreviewed:
        lines += ["| File (untrusted) | Change | Reason |", "|---|---|---|"]
        for u in rep.unreviewed[:budget["names"]]:
            try:
                text = u.path.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            change = u.change if u.change in ("added", "modified", "deleted", "type-changed", "unchanged") else None
            if change is None or u.reason not in vocab.REASON_TEXT:
                raise RenderError("unreviewed entry")
            lines.append(f"| {path_cell(text)} | {esc(change)} | {esc(vocab.REASON_TEXT[u.reason])} |")
        if len(rep.unreviewed) > budget["names"]:
            lines.append(esc(f"{len(rep.unreviewed) - budget['names']} further files not shown (count is complete)."))
    return lines


def _footer(rep: RunReport) -> List[str]:
    parts = []
    f = rep.footer or {}
    if _HEX64.match(str(f.get("core_digest", ""))):
        parts.append("core build digest " + code(f["core_digest"]))
    if _HEX64.match(str(f.get("adapter_digest", ""))):
        parts.append("adapter digest " + code(f["adapter_digest"]))
    if _VERSION_RE.match(str(f.get("python", ""))):
        parts.append("Python " + code(f["python"]))
    versions = []
    for p in rep.packages:
        if p.v2 is not None:
            for doc in (p.v2, p.v3 or {}):
                v = str((doc.get("tool") or {}).get("version", ""))
                if _VERSION_RE.match(v) and v not in versions:
                    versions.append(v)
    if versions:
        parts.append("P02 tool versions " + ", ".join(code(v) for v in versions))
    parts.append(esc("action pins: see the workflow file"))
    lines = ["", "---", "**Footer:** " + "; ".join(parts) + "."]
    runs = []
    for p in rep.packages:
        ids = [d.get("run_id") for d in (p.v2 or {}, p.v3 or {}) if d.get("run_id")]
        ids = [i for i in ids if isinstance(i, str) and _TOKEN_RE.match(i)]
        if ids:
            runs.append(esc(f"package {p.index} ") + " / ".join(code(i) for i in ids))
    if runs:
        lines.append("**Run IDs:** " + "; ".join(runs) + ".")
    lines.append(esc("Provenance (synthetic true) is declared by the submitter in each manifest; P02 cannot "
                     "confirm it."))
    lines.append("**Limitations:**")
    lines += ["* " + esc(t) for t in vocab.LIMITATIONS]
    return lines


def _row(rep: RunReport) -> int:
    run_failure = bool(rep.failure_codes) or any(p.row == 1 for p in rep.packages) or len(rep.packages) > MAX_PACKAGES
    return outcome.overall_row([p.row for p in rep.packages], len(rep.unreviewed) + rep.unreviewable_count,
                               run_failure)


def _compose(rep: RunReport, budget: dict) -> Tuple[str, int]:
    row = _row(rep)
    if row == 1:
        codes = list(rep.failure_codes) + [p.failure for p in rep.packages if p.row == 1 and p.failure]
        if len(rep.packages) > MAX_PACKAGES:
            codes.append("P02CI_TOO_MANY_PACKAGES")
        digests = [(k, rep.footer.get(n)) for k, n in (("core build digest", "core_digest"),
                                                         ("adapter digest", "adapter_digest"))
                   if rep.footer and rep.footer.get(n)]
        text = bootstrap.technical_summary(codes, rep.trust_degraded, digests)
        if rep.packages and len(rep.packages) <= MAX_PACKAGES:
            text = _with_package_outcomes(text, rep)
        return text, 1
    lines = [HEADER + BANNERS[row]]
    if rep.trust_degraded:
        lines.append(TRUST_LINE)
    lines += [STANDARD_LINE, UNTRUSTED_LINE, "",
              "**CI conclusion:** " + esc(_conclusion(row, rep.trust_degraded, rep.gate_mode)), "",
              "**Gate mode:** " + _gate_line(rep)]
    if rep.packages:
        lines.append("")
        lines += _overview(rep)
        for p in rep.packages:
            lines += _package_section(p, budget)
    lines += _unreviewed_section(rep, budget)
    if rep.credential_name_count and not (len(rep.unreviewed) + rep.unreviewable_count):
        lines += ["", esc(f"{rep.credential_name_count} changed file names have a credential shape (not shown). If "
                          "any of them was ever a real credential, remove it and rotate it.")]
    lines += _footer(rep)
    return "\n".join(lines) + "\n", row


def _with_package_outcomes(text: str, rep: RunReport) -> str:
    """R1 V1-04: a technical failure in one package must not hide another package's credential notice. Row-1
    summaries list each package's outcome label (no decision, findings or other assessment content) and keep
    every row-2 block (screen rule ID and file through display_path, rotate instruction)."""
    head, sep, foot = text.partition("\n---\n")
    head = head.replace(STANDARD_LINE + "\n", STANDARD_LINE + "\n" + UNTRUSTED_LINE + "\n", 1)
    lines = ["", "| # | Package (untrusted) | Outcome |", "|---|---|---|"]
    for p in rep.packages:
        # R2 V2-04: no assessment outcome is shown in a failed run, only whether one was withheld.
        label = OUTCOME_LABEL[p.row] if p.row in (1, 2, 3) else "assessment withheld (run failed)"
        lines.append(f"| {p.index} | {path_cell(p.path)} | {esc(label)} |")
    total = len(rep.unreviewed) + rep.unreviewable_count
    if total:
        lines += ["", esc(f"{total} changed files were not reviewed (names are not shown in a failed run).")]
    if rep.credential_name_count:
        lines.append(esc(f"{rep.credential_name_count} changed file names have a credential shape (not shown). If "
                         "any of them was ever a real credential, remove it and rotate it."))
    for p in rep.packages:
        if p.row == 2:
            lines += ["", f"### Package {p.index}"] + _secret_block(p)
    body = head.rstrip("\n") + "\n" + "\n".join(lines) + "\n"
    return body + (sep + foot if sep else "")


# ----------------------------------------------------------------------------- self-check
def _strip_spans(line: str) -> Optional[str]:
    """Remove code spans after checking each one; None if a span is not acceptable."""
    for m in _SPAN_RE.finditer(line):
        content = m.group(1)
        if not (_TOKEN_RE.match(content) or _display_valid(content)):
            return None
        if any(c in content for c in "`|\\<>&"):
            return None
    return _SPAN_RE.sub("", line)


def self_check(text: str) -> bool:
    try:
        if not isinstance(text, str) or not text.endswith("\n") or len(text.encode("ascii")) > HARD_CAP:
            return False
    except UnicodeEncodeError:
        return False
    if any(not (0x20 <= ord(c) < 0x7F or c == "\n") for c in text):
        return False
    if screen_text(text, 1) or strict_secret_hit(text):
        return False
    lines = text[:-1].split("\n")
    if not lines[0].startswith(HEADER) or lines[0][len(HEADER):] not in BANNERS.values():
        return False
    table_cells = None
    residual_all = []
    for line in lines:
        residual = _strip_spans(line)
        if residual is None:
            return False
        if residual.count("`"):
            return False
        no_entities = _ENTITY_RE.sub("", residual)
        if "&" in no_entities or not set(no_entities) <= _RESIDUAL_OK:
            return False
        if line.startswith("#") and not any(r.match(line) for r in _HEADING_RES):
            return False
        if line.startswith(">") and line not in _QUOTE_LINES:
            return False
        if ">" in no_entities and not line.startswith(">"):
            return False
        if line.startswith("|"):
            if not line.endswith("|"):
                return False
            cells = no_entities.count("|")
            if table_cells is not None and cells != table_cells:
                return False
            table_cells = cells
        else:
            table_cells = None
            if "|" in no_entities:
                return False
        residual_all.append(no_entities)
    low = "\n".join(residual_all).lower().replace("not a safety approval", "")
    if any(p in low for p in BANNED_PHRASES):
        return False
    return True


def render(rep: RunReport) -> Tuple[str, int]:
    """Return (summary, overall_row). Any failure -> the constant fallback summary and row 1."""
    try:
        text, row = None, None
        for budget in BUDGETS:
            text, row = _compose(rep, budget)
            if row == 1 or len(text.encode("ascii")) <= TARGET:
                break
        if len(text.encode("ascii")) > HARD_CAP:
            return bootstrap.fallback_summary(), 1
        if not self_check(text):
            return bootstrap.fallback_summary(), 1
        return text, row
    except Exception:
        return bootstrap.fallback_summary(), 1
