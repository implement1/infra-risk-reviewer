"""Phase 3A deterministic narrative: fixed templates filled only from validated v2 data and typed facts.

Section order is fixed: decision, coverage (every gap is listed before any finding), findings, links.
Each sentence records its template, claim type and citations (finding IDs, evidence IDs, coverage
references, policy reason codes). When a finding's facts are missing or fail their schema, the
honest generic template is used instead of guessing (P3-INV-06, P3-INV-15).
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from . import p3_templates as T
from .identity import canonical_json_bytes, sha256_hex
from .p3_facts import check_facts
from .p3_templates import SlotError

_REASON_ENUM = ("replace_because_tainted", "replace_because_cannot_update", "replace_by_request",
                "replace_by_triggers", "other")
_RBAC002_FIELDS = {("verbs",): "verbs", ("resources",): "resources", ("nonResourceURLs",): "nonResourceURLs",
                   ("nonResourceURLs", "verbs"): "nonResourceURLs and verbs",
                   ("nonResourceURLs", "resources"): "nonResourceURLs and resources"}
_RBAC001_FIELDS = {("resources", "verbs"): "resources and verbs",
                   ("nonResourceURLs", "resources", "verbs"): "nonResourceURLs, resources and verbs"}
_MISSING = {("requests",): "requests", ("limits",): "limits", ("limits", "requests"): "requests or limits"}


def _sentence(tpl, slots, claim_type, finding_ids=(), evidence_ids=(), coverage_refs=(), reason_codes=(), k8s=False):
    return {"template_id": tpl.id, "text": tpl.render(T.display_slots(slots, k8s)), "claim_type": claim_type,
            "finding_ids": list(finding_ids), "evidence_ids": sorted(set(evidence_ids)),
            "coverage_refs": [{"path": p, "code": c} for p, c in coverage_refs],
            "reason_codes": list(reason_codes)}


def _span(f) -> Tuple[int, int]:
    return (f["location"]["line_start"], f["location"]["line_end"])


def _rule_slots(f: dict, facts: dict) -> dict:
    """Slots for the rule-specific template; raises KeyError/SlotError if facts do not fit."""
    rule, loc = f["rule_id"], f["location"]
    if rule.startswith("PLAN-"):
        slots = {"plan_address": loc["plan_address"], "severity": f["severity"],
                 "type_desc": "type recorded in the plan" if facts["plan_type"] else "type not recorded",
                 "stateful_desc": "type is in the stateful list" if facts["stateful"] else
                 "type is not in the stateful list"}
        if rule in ("PLAN-REP-001", "PLAN-REP-002"):
            reason = facts["action_reason"]
            slots["reason_note"] = None if reason is None else (reason if reason in _REASON_ENUM else "other")
        return slots
    slots = {"resource": f["resource"], "path": loc["path"], "span": _span(f), "severity": f["severity"]}
    if rule in ("TF-IAM-001",):
        slots["wildcard_action"] = facts["wildcard_action"]
    elif rule == "TF-IAM-002":
        slots["wildcard_action"] = facts["wildcard_action"]
        slots["resource_scope"] = "all" if facts["resource_all"] else "scoped or partly dynamic"
    elif rule == "TF-NET-001":
        cls = facts["cidr_class"]
        slots.update(cidr_family=_FAMILY[cls.split("_")[0]],
                     cidr_note=("" if "union" not in cls else " (at least one family written as a union of narrower "
                                "ranges)" if cls.startswith("dual") else " (written as a union of narrower ranges)"),
                     ports=facts["ports"], protocol={"all": "any protocol"}.get(facts["protocol"], facts["protocol"]))
    elif rule == "K8S-PRIV-001":
        slots.update(container_list=facts["container_list"], workload_kind=facts["workload_kind"])
    elif rule == "K8S-HOSTNET-001":
        slots["workload_kind"] = facts["workload_kind"]
    elif rule == "K8S-RBAC-001":
        slots.update(role_kind=facts["role_kind"], wildcard_fields=_RBAC001_FIELDS[tuple(facts["wildcard_fields"])])
    elif rule == "K8S-RBAC-002":
        slots.update(role_kind=facts["role_kind"], wildcard_fields=_RBAC002_FIELDS[tuple(facts["wildcard_fields"])])
    elif rule == "K8S-IMG-001":
        slots["tag_desc"] = ("uses the 'latest' tag" if facts["tag_state"] == "latest"
                             else "has no tag or digest (implicitly 'latest')")
    elif rule == "K8S-RES-001":
        slots["missing"] = _MISSING[tuple(facts["missing"])]
    return slots


def _finding_sentence(f: dict, facts: dict) -> dict:
    rule, state, loc = f["rule_id"], f["state"], f["location"]
    claim = "unknown" if state == "insufficient_evidence" else "fact_from_rule"
    tpl = T.RULE_TEMPLATES[(rule, state)]
    try:
        if check_facts(rule, state, facts):
            raise SlotError("facts do not match schema")
        if tpl is T.INSUFFICIENT_PLAN:
            slots = {"plan_address": loc["plan_address"], "rule_id": rule}
        elif tpl is T.INSUFFICIENT_SOURCE:
            slots = {"resource": f["resource"], "path": loc["path"], "span": _span(f), "rule_id": rule,
                     "unresolved": facts["unresolved"]}
        elif tpl in (T.GENERIC_PLAN, T.GENERIC_SOURCE):
            raise SlotError("generic")
        else:
            slots = _rule_slots(f, facts)
        return _sentence(tpl, slots, claim, [f["id"]], f["evidence_ids"], k8s=rule.startswith("K8S-"))
    except (SlotError, KeyError, TypeError):
        if loc.get("plan_address") is not None:
            tpl, slots = T.GENERIC_PLAN, {"plan_address": loc["plan_address"]}
        else:
            tpl, slots = T.GENERIC_SOURCE, {"resource": f["resource"], "path": loc["path"], "span": _span(f)}
        slots.update(rule_id=rule, state=state, severity=f["severity"])
        return _sentence(tpl, slots, claim, [f["id"]], f["evidence_ids"], k8s=rule.startswith("K8S-"))


def _question(tid: str, slots: dict, finding_ids=(), evidence_ids=(), coverage_refs=(), reason_code="", k8s=False):
    tpl = T.QUESTION_TEMPLATES[tid]
    text = tpl.render(T.display_slots(slots, k8s))
    key = sha256_hex(canonical_json_bytes([tid, text]))[:16]
    return {"id": "Q-" + key, "template_id": tid, "text": text, "finding_ids": list(finding_ids),
            "evidence_ids": sorted(set(evidence_ids)), "coverage_refs": [{"path": p, "code": c} for p, c in coverage_refs],
            "reason_code": reason_code}


_FAMILY = {"ipv4": "IPv4", "ipv6": "IPv6", "dual": "IPv4 and IPv6"}
_CHANGE_DESC = {"PLAN-DEL-001": "deleted", "PLAN-REP-001": "destroyed before its replacement exists",
                "PLAN-REP-002": "replaced"}


def _confirmed_question(f: dict, facts: dict, src):
    """Corrective pass C1: one deterministic question per confirmed destructive, connectivity-affecting or
    public-admin-ingress finding. Chosen only from typed facts; returns None when no template applies."""
    rule, ids, ev = f["rule_id"], [f["id"]], f["evidence_ids"]
    if rule == "TF-NET-001" and src:
        if not check_facts(rule, f["state"], facts):
            return _question("Q-net-public-admin", dict(src, ports=facts["ports"],
                                                        cidr_family=_FAMILY[facts["cidr_class"].split("_")[0]]),
                             ids, ev, reason_code="PUBLIC_ADMIN_INGRESS")
        return _question("Q-net-public-admin-generic", src, ids, ev, reason_code="PUBLIC_ADMIN_INGRESS")
    if rule not in _CHANGE_DESC:
        return None
    addr = {"plan_address": f["location"]["plan_address"]}
    valid = not check_facts(rule, f["state"], facts)
    # Without valid facts, statefulness is read from the severity Phase 2 assigned (high only when stateful).
    stateful = facts["stateful"] if valid else f["severity"] == "high"
    connectivity = valid and facts["plan_type"] in T.CONNECTIVITY_TYPES
    if stateful:
        tid = "Q-plan-del-stateful" if rule == "PLAN-DEL-001" else "Q-plan-rep-stateful"
        return _question(tid, addr, ids, ev, reason_code="DESTRUCTIVE_CHANGE")
    if connectivity:
        return _question("Q-plan-connectivity", dict(addr, change_desc=_CHANGE_DESC[rule]), ids, ev,
                         reason_code="CONNECTIVITY_RISK")
    if rule == "PLAN-DEL-001":
        return _question("Q-plan-del", addr, ids, ev, reason_code="DESTRUCTIVE_CHANGE")
    if rule == "PLAN-REP-001":
        return _question("Q-plan-rep-dbc", addr, ids, ev, reason_code="DESTRUCTIVE_CHANGE")
    return None  # PLAN-REP-002 on a non-stateful, non-connectivity type: create-before-destroy, low severity


def _link_coverage_refs(link: dict, files: List[dict]) -> List[Tuple[str, str]]:
    """Coverage the link basis rests on (corrective pass C2): for a candidate, every Terraform file is
    analysed; for terraform-coverage-incomplete, the Terraform files that were not."""
    tf = [c for c in files if c["kind"] == "terraform" or c["path"].endswith((".tf", ".tf.json"))]
    if link["link_type"] == "candidate_same_type_name":
        return [(c["path"], c["status"]) for c in tf]
    if "terraform-coverage-incomplete" in link["basis"]:
        return [(c["path"], c["status"]) for c in tf if c["status"] != "analyzed"]
    return []


def build(v2: dict, groups: List[dict], links: List[dict], facts_by_id: Dict[str, dict] = None):
    facts_by_id = facts_by_id or {}
    findings = {f["id"]: f for f in v2["findings"]}
    policy, files = v2["policy"], v2["coverage"]["files"]
    sections, questions, unknowns = [], [], []

    # 1. decision (verbatim from v2; never recomputed)
    high = [f for f in v2["findings"] if f["state"] == "confirmed_by_rule" and f["severity"] in ("high", "critical")]
    decision = policy["decision"]
    dslots = {"reasons": policy["reasons"]}
    if decision == "review_required":
        dslots["n_high"] = len(high)
    elif decision == "no_blocking_findings_detected":
        dslots["n_files"] = len(files)
    sections.append({"id": "decision", "sentences": [_sentence(
        T.DECISION_TEMPLATES[decision], dslots, "decision_fact", [f["id"] for f in high],
        [e for f in high for e in f["evidence_ids"]], reason_codes=policy["reasons"])]})

    # 2. coverage: summary, then every gap file
    gaps = [c for c in files if c["status"] != "analyzed"]
    cov = [_sentence(T.COVERAGE_SUMMARY, {"n_analyzed": len(files) - len(gaps), "n_files": len(files),
                                          "n_gap": len(gaps)}, "coverage_fact",
                     coverage_refs=[(c["path"], c["status"]) for c in files])]
    for c in gaps:
        codes = sorted({n["code"] for n in c["notes"]})[:12]
        if c["status"] == "partial" and not codes:
            cov.append(_sentence(T.COVERAGE_STATUS_TEMPLATES["partial_no_notes"], {"path": c["path"]}, "coverage_fact",
                                 coverage_refs=[(c["path"], c["status"])]))
        else:
            cov.append(_sentence(T.COVERAGE_STATUS_TEMPLATES[c["status"]], {"path": c["path"], "codes": codes},
                                 "coverage_fact", coverage_refs=[(c["path"], c["status"])] + [(c["path"], x) for x in codes]))
    sections.append({"id": "coverage", "sentences": cov})

    # 3. findings, group by group (every finding exactly once, in group order)
    fs = []
    for g in groups:
        for fid in g["finding_ids"]:
            fs.append(_finding_sentence(findings[fid], facts_by_id.get(fid, {})))
    if not fs:
        fs.append(_sentence(T.FINDINGS_NONE, {}, "coverage_fact", coverage_refs=[(c["path"], c["status"]) for c in files]))
    sections.append({"id": "findings", "sentences": fs})

    # 4. links (candidate or unlinked only)
    if links:
        ls = []
        for link in links:
            pf = findings[link["plan_finding_id"]]
            ids = [pf["id"]] + link["static_finding_ids"]
            evidence = [e for fid in ids for e in findings[fid]["evidence_ids"]]  # plan and static evidence (C2)
            refs = _link_coverage_refs(link, files)
            if link["link_type"] == "candidate_same_type_name":
                ls.append(_sentence(T.LINK_CANDIDATE, {"plan_address": link["plan_address"],
                                                       "static_resource": link["static_resource"],
                                                       "static_path": link["static_path"],
                                                       "span": (link["static_line_start"], link["static_line_start"])},
                                    "link_candidate", ids, evidence, coverage_refs=refs))
            else:
                ls.append(_sentence(T.LINK_UNLINKED, {"plan_address": link["plan_address"], "basis": link["basis"]},
                                    "link_candidate", ids, evidence, coverage_refs=refs))
        sections.append({"id": "links", "sentences": ls})

    # questions: unresolved findings, conditional grants, and coverage gaps
    seen = set()

    def add_q(q):
        if q["id"] not in seen:
            seen.add(q["id"])
            questions.append(q)
            return
        # Same text for another finding (e.g. duplicate plan addresses): keep one question but cite every
        # finding it asks about, so no finding loses its question (corrective pass C1).
        prev = next(x for x in questions if x["id"] == q["id"])
        prev["finding_ids"] += [f for f in q["finding_ids"] if f not in prev["finding_ids"]]
        prev["evidence_ids"] = sorted(set(prev["evidence_ids"]) | set(q["evidence_ids"]))

    for f in v2["findings"]:
        rule, loc, facts = f["rule_id"], f["location"], facts_by_id.get(f["id"], {})
        src = {"resource": f["resource"], "path": loc["path"], "span": _span(f)} if loc.get("line_start") else None
        try:
            if f["state"] == "insufficient_evidence":
                if rule.startswith("PLAN-"):
                    add_q(_question("Q-ins-plan", {"plan_address": loc["plan_address"]}, [f["id"]], f["evidence_ids"],
                                    reason_code="INSUFFICIENT_EVIDENCE"))
                elif rule in ("TF-IAM-001", "TF-IAM-002") and src:
                    add_q(_question("Q-ins-iam", src, [f["id"]], f["evidence_ids"], reason_code="INSUFFICIENT_EVIDENCE"))
                elif rule == "TF-IAM-003" and src:
                    add_q(_question("Q-ins-iam-attach", src, [f["id"]], f["evidence_ids"],
                                    reason_code="INSUFFICIENT_EVIDENCE"))
                elif rule == "TF-NET-001" and src:
                    add_q(_question("Q-ins-net", src, [f["id"]], f["evidence_ids"], reason_code="INSUFFICIENT_EVIDENCE"))
                elif rule.startswith("K8S-") and src and "unresolved" in facts:
                    add_q(_question("Q-ins-k8s", dict(src, unresolved=facts["unresolved"]), [f["id"]], f["evidence_ids"],
                                    reason_code="INSUFFICIENT_EVIDENCE", k8s=True))
            elif f["state"] == "suspected" and rule.startswith("TF-IAM") and src:
                add_q(_question("Q-suspected-iam", src, [f["id"]], f["evidence_ids"], reason_code="SUSPECTED"))
            elif f["state"] == "confirmed_by_rule":
                q = _confirmed_question(f, facts, src)
                if q is not None:
                    add_q(q)
        except SlotError:
            continue
    for c in files:
        for code in sorted({n["code"] for n in c["notes"]}):
            add_q(_question(T.NOTE_QUESTION[code], {"path": c["path"]}, coverage_refs=[(c["path"], code)],
                            reason_code=code))
            tpl = T.UNKNOWN_TEMPLATES[code]
            line = next((n["line"] for n in c["notes"] if n["code"] == code), None)
            unknowns.append({"code": code, "path": c["path"], "line": line, "finding_ids": [],
                             "template_id": tpl.id, "text": tpl.render(T.display_slots({"path": c["path"]}))})
    return sections, questions, unknowns
