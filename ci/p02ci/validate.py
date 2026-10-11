"""Result integrity before rendering (02 sec. 4; 04 sec. 7).

Every check below must pass before any part of a package result is rendered; a failure is a row-1 technical
failure and nothing of that package is shown. Checks:
* exit-code mapping (0 / 3 / 4 assessed; 2, 5, timeouts and anything else are technical failures);
* stdout parses as strict JSON (core strict_json), is ASCII, and equals byte-for-byte the single
  `<run_id>.json` file written to --out-dir;
* the core's own contract validators (validate_result_v2, validate_result_v3 with cross-check against v2);
* closed vocabularies (decision, reasons, rule IDs, severities, states, coverage statuses, note codes, error
  codes, question reason codes);
* evidence relationships (IDs well formed and unique; every finding cites existing evidence of the same rule;
  every location and coverage path is a declared file; coverage lists every declared file exactly once);
* an independent recomputation of the ADR-0001 sec. 5 rubric (decision and reasons) from findings and coverage;
* explain: exit 0, `v2_policy` equal to the v2 policy, `v2_reference` naming this v2 run with the supplied result
  checked and matched, no model, questions citing only known findings and declared paths.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from p02review.result_v2 import validate_result_v2
from p02review.result_v3 import validate_result_v3
from p02review.strict_json import load_strict

from p02ci import vocab

_FID = re.compile(r"\AF-[0-9a-f]{16}\Z")
_EID = re.compile(r"\AE-[0-9a-f]{16}\Z")
_RUN_ID = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")
_EXTERNAL = ("network_calls", "model_calls", "subprocess_invocations", "repository_writes", "cloud_api_calls")


@dataclass
class ProcResult:
    exit_code: Optional[int]
    stdout: bytes
    out_files: Dict[str, bytes]
    timed_out: bool = False


@dataclass
class Assessment:
    row: int
    failure: Optional[str] = None
    check: Optional[str] = None
    status: str = "technical_failure"
    v2: Optional[dict] = None
    v3: Optional[dict] = None
    error_codes: List[str] = field(default_factory=list)
    secret_hits: List[Tuple[str, str]] = field(default_factory=list)


class _Fail(Exception):
    def __init__(self, failure, check):
        super().__init__(check)
        self.failure = failure
        self.check = check


def _req(cond, check, failure="P02CI_INTEGRITY"):
    if not cond:
        raise _Fail(failure, check)


def _exit_failure(proc: ProcResult, allowed):
    if proc.timed_out:
        raise _Fail("P02CI_P02_TIMEOUT", "timeout")
    code = proc.exit_code
    if code == 2:
        raise _Fail("P02CI_P02_USAGE", "exit_2")
    if code == 5:
        raise _Fail("P02CI_P02_INTERNAL", "exit_5")
    if code not in allowed:
        raise _Fail("P02CI_P02_UNEXPECTED_EXIT", "exit_other")


def _parse(proc: ProcResult, schema: str) -> dict:
    raw = proc.stdout
    _req(isinstance(raw, bytes) and 0 < len(raw) <= 32 * 1024 * 1024, "stdout_size")
    try:
        text = raw.decode("ascii")
        doc = load_strict(text)
    except Exception:
        raise _Fail("P02CI_INTEGRITY", "json") from None
    _req(isinstance(doc, dict), "json_object")
    _req(doc.get("schema_version") == schema, "schema_version")
    run_id = doc.get("run_id")
    _req(isinstance(run_id, str) and bool(_RUN_ID.match(run_id)), "run_id_format")
    _req(set(proc.out_files) == {f"{run_id}.json"}, "run_id_file")
    _req(proc.out_files[f"{run_id}.json"] == raw, "run_id_file_bytes")
    return doc


def _codes(errs) -> List[str]:
    out = []
    _req(isinstance(errs, list), "errors_list")
    for e in errs:
        _req(isinstance(e, dict) and e.get("code") in vocab.ERROR_CODES, "error_code")
        if e["code"] not in out:
            out.append(e["code"])
    return out


def _rubric(findings, complete):
    confirmed = any(f["state"] == "confirmed_by_rule" and f["severity"] in ("high", "critical") for f in findings)
    suspected = any(f["state"] == "suspected" and f["severity"] in ("high", "critical") for f in findings)
    insufficient = any(f["state"] in ("insufficient_evidence", "unsupported") for f in findings)
    reasons = []
    if confirmed:
        reasons.append("CONFIRMED_HIGH_SEVERITY_FINDING")
    if suspected:
        reasons.append("SUSPECTED_HIGH_SEVERITY_FINDING")
    if insufficient:
        reasons.append("INSUFFICIENT_EVIDENCE_FINDING")
    if not complete:
        reasons.append("COVERAGE_INCOMPLETE")
    if confirmed:
        decision = "review_required"
    elif complete and not suspected and not insufficient:
        decision = "no_blocking_findings_detected"
        reasons.append("NO_BLOCKING_FINDING_IN_BASELINE_RULES")
    else:
        decision = "inconclusive"
    return decision, reasons


def _check_completed_v2(v2: dict, declared: List[str], fixture_id: str) -> None:
    _req(v2.get("status") == "completed", "status_completed")
    pol = v2["policy"]
    _req(pol.get("decision") in vocab.DECISIONS, "decision")
    _req(all(r in vocab.REASONS for r in pol.get("reasons", [])), "reasons")
    _req(pol.get("human_review_required") is True, "human_review")
    _req(pol.get("blocking_review_required") is (pol["decision"] == "review_required"), "blocking_flag")
    ident = v2.get("input_identity") or {}
    _req(ident.get("origin") == "fixture", "origin")
    _req(ident.get("fixture_id") == fixture_id, "fixture_id")
    _req(ident.get("file_count") == len(declared), "file_count")
    _req(all(v2["external_actions"].get(k) == 0 for k in _EXTERNAL), "external_actions")
    declared_set = set(declared)
    cov = v2["coverage"]
    files = cov.get("files")
    _req(isinstance(files, list) and sorted(f.get("path") for f in files) == sorted(declared), "coverage_files")
    _req(len(declared_set) == len(declared), "declared_unique")
    for f in files:
        _req(f.get("status") in vocab.COVERAGE_STATUSES, "coverage_status")
        _req(isinstance(f.get("notes"), list), "notes")
        _req(all(isinstance(n, dict) and n.get("code") in vocab.NOTE_CODES for n in f["notes"]), "note_code")
    complete = all(f["status"] == "analyzed" for f in files)
    _req(cov.get("analysis_complete") is complete, "analysis_complete")
    evidence = v2["evidence"]
    ev_by_id = {}
    for e in evidence:
        _req(isinstance(e.get("id"), str) and bool(_EID.match(e["id"])) and e["id"] not in ev_by_id, "evidence_id")
        ev_by_id[e["id"]] = e
    fids = set()
    for f in v2["findings"]:
        _req(isinstance(f.get("id"), str) and bool(_FID.match(f["id"])) and f["id"] not in fids, "finding_id")
        fids.add(f["id"])
        _req(f.get("rule_id") in vocab.ANALYSIS_RULES, "rule_id")
        _req(f.get("severity") in vocab.SEVERITIES, "severity")
        _req(f.get("state") in vocab.STATES, "state")
        ev = f.get("evidence_ids")
        _req(isinstance(ev, list) and ev and len(set(ev)) == len(ev), "finding_evidence")
        for eid in ev:
            _req(eid in ev_by_id and ev_by_id[eid].get("rule_id") == f["rule_id"], "evidence_relationship")
        loc = f.get("location") or {}
        _req(loc.get("path") is None or loc.get("path") in declared_set, "location_path")
        for k in ("line_start", "line_end"):
            v = loc.get(k)
            _req(v is None or (isinstance(v, int) and not isinstance(v, bool) and v >= 0), "location_lines")
    for e in evidence:
        _req(e.get("path") is None or e.get("path") in declared_set, "evidence_path")
    decision, reasons = _rubric(v2["findings"], complete)
    _req(pol["decision"] == decision, "rubric_decision")
    _req(list(pol["reasons"]) == reasons, "rubric_reasons")


def _check_v3(v3: dict, v2: dict, declared: List[str]) -> None:
    _req(v3.get("status") == "completed", "v3_status")
    try:
        validate_result_v3(v3, v2)
    except Exception:
        raise _Fail("P02CI_INTEGRITY", "v3_contract") from None
    _req(v3.get("v2_policy") == v2.get("policy"), "v2_policy")
    ref = v3.get("v2_reference") or {}
    _req(ref.get("run_id") == v2["run_id"] and ref.get("schema_version") == v2["schema_version"], "v2_reference")
    sup = ref.get("supplied_result") or {}
    _req(sup.get("checked") is True and sup.get("matched") is True and not sup.get("mismatch_codes"), "supplied")
    model = v3.get("model") or {}
    _req(model.get("backend") == "none" and model.get("status") == "disabled", "model")
    _req(all((v3.get("external_actions") or {}).get(k) == 0 for k in _EXTERNAL), "v3_external_actions")
    fids = {f["id"] for f in v2["findings"]}
    declared_set = set(declared)
    for q in v3.get("verification_questions", []):
        _req(q.get("reason_code") in vocab.QUESTION_TEXT, "question_reason")
        ids = q.get("finding_ids")
        _req(isinstance(ids, list) and set(ids) <= fids and len(set(ids)) == len(ids), "question_findings")
        for r in q.get("coverage_refs", []):
            _req(isinstance(r, dict) and r.get("path") in declared_set, "question_coverage")


def assess(review: ProcResult, explain: Optional[ProcResult], declared: List[str], fixture_id: str) -> Assessment:
    try:
        return _assess(review, explain, list(declared), fixture_id)
    except _Fail as f:
        return Assessment(row=1, failure=f.failure, check=f.check)
    except Exception:
        return Assessment(row=1, failure="P02CI_INTEGRITY", check="unexpected")


def _assess(review, explain, declared, fixture_id) -> Assessment:
    _exit_failure(review, (0, 3, 4))
    v2 = _parse(review, "p02.run-result.v2")
    try:
        validate_result_v2(v2)
    except Exception:
        raise _Fail("P02CI_INTEGRITY", "v2_contract") from None
    reasons = v2["policy"].get("reasons", [])
    _req(all(r in vocab.REASONS for r in reasons), "reasons")
    if review.exit_code == 3:
        _req(v2["status"] == "rejected" and "SUSPECTED_SECRET_BLOCKED" not in reasons, "exit3_status")
        codes = _codes(v2["errors"])
        _req(bool(codes), "exit3_codes")
        return Assessment(row=3, status="rejected", error_codes=codes)
    if review.exit_code == 4:
        _req(v2["status"] == "rejected" and "SUSPECTED_SECRET_BLOCKED" in reasons, "exit4_status")
        codes = _codes(v2["errors"])
        hits = []
        for f in v2["findings"]:
            _req(f.get("rule_id") in vocab.SECRET_RULES, "secret_rule")
            hits.append((f["rule_id"], (f.get("location") or {}).get("path")))
        return Assessment(row=2, status="rejected", error_codes=codes, secret_hits=hits)
    _check_completed_v2(v2, declared, fixture_id)
    _req(explain is not None, "explain_missing")
    if explain.timed_out:
        raise _Fail("P02CI_P02_TIMEOUT", "explain_timeout")
    if explain.exit_code == 4:
        v3 = _parse(explain, "p02.report.v3")
        _req(v3.get("status") == "rejected", "explain4_status")
        return Assessment(row=2, status="rejected", error_codes=_codes(v3.get("errors", [])))
    if explain.exit_code == 3:
        try:
            v3 = _parse(explain, "p02.report.v3")
        except _Fail:
            raise _Fail("P02CI_INTEGRITY", "explain3_unparseable") from None
        if v3.get("status") == "v2_mismatch":
            raise _Fail("P02CI_V2_MISMATCH", "v2_mismatch")
        raise _Fail("P02CI_INTEGRITY", "explain_rejected_after_review")
    _exit_failure(explain, (0,))
    v3 = _parse(explain, "p02.report.v3")
    _check_v3(v3, v2, declared)
    row = {"review_required": 4, "inconclusive": 5, "no_blocking_findings_detected": 7}[v2["policy"]["decision"]]
    return Assessment(row=row, status="completed", v2=v2, v3=v3)
