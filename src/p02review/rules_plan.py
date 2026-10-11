"""Increment 2.1 - Terraform plan JSON interpreter (supplied artifact only).

Never invokes Terraform and never reads state. A plan describes intended actions at the
time it was generated; P02 does not verify that a plan is current, complete or executable.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from .findings import CoverageNote, Evidence, FileCoverage, Finding, safe_token
from .strict_json import StrictJsonError, load_strict

ANALYZER_ID = "terraform-plan-json-interpreter"
ANALYZER_VERSION = "2"
RULES = ("PLAN-DEL-001", "PLAN-REP-001", "PLAN-REP-002", "PLAN-ACT-UNK")

STATEFUL_TYPES = frozenset((
    "aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance", "aws_dynamodb_table",
    "aws_s3_bucket", "aws_ebs_volume", "aws_efs_file_system", "aws_elasticache_cluster",
    "aws_elasticache_replication_group", "aws_redshift_cluster", "aws_docdb_cluster",
    "aws_neptune_cluster", "aws_opensearch_domain", "aws_elasticsearch_domain", "aws_kms_key",
    "google_sql_database_instance", "google_storage_bucket", "azurerm_storage_account",
    "azurerm_mssql_database", "azurerm_postgresql_flexible_server",
    "kubernetes_persistent_volume", "kubernetes_persistent_volume_claim",
))

NON_DESTRUCTIVE = {("no-op",), ("create",), ("read",), ("update",)}
_FORMAT_RE = re.compile(r"\A1\.[0-9]{1,4}\Z")
_FACT_TYPE = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")
ACTION_REASONS = (  # Terraform action_reason values carried as typed facts (others -> "other")
    "replace_because_tainted", "replace_because_cannot_update", "replace_by_request", "replace_by_triggers",
    "delete_because_no_resource_config", "delete_because_wrong_repetition", "delete_because_count_index",
    "delete_because_each_key", "delete_because_no_module", "delete_because_no_move_target",
)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")


def parse_address(address: str):
    """Parse a resource address: (module.NAME[KEY].)* [data.] TYPE.NAME[KEY].
    Returns (is_data, type) or None if the address does not follow this grammar. Index keys are
    numbers or JSON-style quoted strings (which may contain ']' or '.')."""
    i, n = 0, len(address)

    def ident():
        nonlocal i
        m = _IDENT.match(address, i)
        if not m:
            return None
        i = m.end()
        return m.group(0)

    def index():
        nonlocal i
        if i >= n or address[i] != "[":
            return True
        i += 1
        if i < n and address[i] == '"':
            i += 1
            while i < n and address[i] != '"':
                i += 2 if address[i] == "\\" else 1
            if i >= n:
                return False
            i += 1
        else:
            j = i
            while i < n and address[i].isascii() and address[i].isdigit():
                i += 1
            if i == j:
                return False
        if i >= n or address[i] != "]":
            return False
        i += 1
        return True

    segments = []
    while True:
        name = ident()
        if name is None:
            return None
        segments.append(name)
        if not index():
            return None
        if i == n:
            break
        if address[i] != ".":
            return None
        i += 1
    # Consume module.NAME pairs from the front; "data" is a mode marker only right before TYPE.NAME.
    k = 0
    while len(segments) - k > 2 and segments[k] == "module":
        k += 2
    rest = segments[k:]
    if len(rest) == 3 and rest[0] == "data":
        return True, rest[1]
    if len(rest) == 2:
        return False, rest[0]
    return None


def _destructive(actions: Tuple[str, ...], stateful: bool):
    kind = "stateful (heuristic list)" if stateful else "not in the stateful list"
    if actions == ("delete",):
        return ("PLAN-DEL-001", "high" if stateful else "medium",
                "Plan deletes this resource.",
                f"Action sequence [delete]; resource type is {kind}. Deletion removes the object and "
                "any data it holds; impact depends on state and business context.")
    if actions == ("delete", "create"):
        return ("PLAN-REP-001", "high" if stateful else "medium",
                "Plan replaces this resource, destroying it before creating the replacement.",
                f"Action sequence [delete, create] (destroy-before-create); resource type is {kind}. "
                "The order implies an interval with no instance, and data in the old object is not carried over.")
    if actions == ("create", "delete"):
        return ("PLAN-REP-002", "high" if stateful else "low",
                "Plan replaces this resource, creating the replacement before destroying the original.",
                f"Action sequence [create, delete] (create-before-destroy); resource type is {kind}. "
                "Downtime is typically shorter than destroy-first, but the original object and its data are still removed.")
    return None


def analyze_plan(path: str, sha256: str, text: str, kind: str) -> Tuple[FileCoverage, List[Finding]]:
    cov = FileCoverage(path, kind, ANALYZER_ID, ANALYZER_VERSION, "analyzed")
    findings: List[Finding] = []

    def unknown(pointer: str, address: str, why: str) -> None:
        # "why" is fixed template text plus safe tokens only.
        cov.status = "partial"
        ev = Evidence("plan_resource", path, sha256, ANALYZER_ID, ANALYZER_VERSION, "PLAN-ACT-UNK",
                      f"Resource change could not be interpreted: {why}.",
                      plan_address=address, json_pointer=pointer)
        findings.append(Finding(
            "PLAN-ACT-UNK", "unknown", "unknown", "insufficient_evidence", ANALYZER_ID, address, path, sha256,
            "Plan entry could not be interpreted; its effect is unknown.",
            f"{why}. Unrecognised or malformed entries are never treated as safe.",
            "Inspect this plan entry manually or regenerate the plan with a supported Terraform version.",
            plan_address=address, evidence=[ev], locator=pointer))
        findings[-1].facts.update({"unresolved": "plan entry"})  # Phase 3A typed facts (not serialized)

    try:
        plan = load_strict(text)
    except StrictJsonError as exc:
        cov.status = "parse_error"
        cov.notes.append(CoverageNote(exc.code, exc.message, exc.line))
        return cov, findings

    if not isinstance(plan, dict):
        cov.status = "unsupported"
        cov.notes.append(CoverageNote("PLAN_NOT_OBJECT", "Plan JSON top level is not an object."))
        return cov, findings
    fmt = plan.get("format_version")
    if not isinstance(fmt, str) or not _FORMAT_RE.match(fmt):
        cov.status = "unsupported"
        cov.notes.append(CoverageNote("PLAN_FORMAT_UNSUPPORTED",
                                      "format_version is missing or not a supported 1.x plan format."))
        return cov, findings
    if plan.get("errored") is True:
        cov.status = "partial"
        cov.notes.append(CoverageNote("PLAN_ERRORED", "Plan reports errored=true; it may be incomplete."))
    if plan.get("complete") is False:
        cov.status = "partial"
        cov.notes.append(CoverageNote("PLAN_INCOMPLETE", "Plan reports complete=false (deferred changes)."))
    if "resource_changes" not in plan:
        cov.status = "unsupported"
        cov.notes.append(CoverageNote("PLAN_RESOURCE_CHANGES_MISSING",
                                      "resource_changes is absent; 'no changes' cannot be distinguished from a "
                                      "truncated or unsupported plan, so no plan coverage is claimed."))
        return cov, findings
    changes = plan["resource_changes"]
    if not isinstance(changes, list):
        cov.status = "unsupported"
        cov.notes.append(CoverageNote("PLAN_RESOURCE_CHANGES_MALFORMED", "resource_changes is not an array."))
        return cov, findings

    seen_addresses = {}
    for index, rc in enumerate(changes):
        if isinstance(rc, dict) and isinstance(rc.get("address"), str):
            seen_addresses.setdefault(rc["address"], []).append(index)
    duplicates = {a: idx for a, idx in seen_addresses.items() if len(idx) > 1}
    for address_raw, idx in sorted(duplicates.items()):
        cov.status = "partial"
        cov.notes.append(CoverageNote("PLAN_DUPLICATE_ADDRESS",
                                      f"Address {safe_token(address_raw, 120)} appears {len(idx)} times "
                                      "(entries are reported separately; the plan is malformed or tampered)."))

    for index, rc in enumerate(changes):
        pointer = f"/resource_changes/{index}"
        cov.objects_analyzed += 1
        for rule in RULES:
            cov.count(rule)
        if not isinstance(rc, dict) or not isinstance(rc.get("address"), str) or not rc["address"]:
            unknown(pointer, f"<entry {index}>", "entry has no string address")
            continue
        address = safe_token(rc["address"], 200)
        declared_type = rc.get("type") if isinstance(rc.get("type"), str) else None
        parsed_addr = parse_address(rc["address"])
        addr_is_data, addr_type = parsed_addr if parsed_addr else (None, None)
        mode = rc.get("mode")
        change = rc.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        if not isinstance(actions, list) or not actions or not all(isinstance(a, str) for a in actions):
            unknown(pointer, address, "change.actions is missing or malformed")
            continue
        seq = tuple(actions)
        if seq in NON_DESTRUCTIVE:
            continue
        # The address and the declared type must agree for managed resources; otherwise severity uses
        # the more cautious of the two and the entry is additionally flagged as not interpretable.
        types = {t for t in (declared_type, addr_type) if t}
        stateful = any(t in STATEFUL_TYPES for t in types)
        consistent = (parsed_addr is not None and declared_type is not None and declared_type == addr_type
                      and (mode is None or (mode == "data") == addr_is_data))
        if not consistent:
            unknown(pointer, address, "resource address, type or mode is missing, unparseable or inconsistent")
        verdict = _destructive(seq, stateful)
        if verdict is None:
            unknown(pointer, address, "action sequence " + safe_token("[" + ", ".join(seq) + "]", 80)
                    + " is not recognised")
            continue
        rule_id, severity, summary, rationale = verdict
        reason = rc.get("action_reason")
        reason_txt = f" action_reason={safe_token(reason, 60)}." if isinstance(reason, str) else ""
        ev = Evidence("plan_resource", path, sha256, ANALYZER_ID, ANALYZER_VERSION, rule_id,
                      f"resource_changes entry has change.actions={safe_token(list(seq), 60)}.{reason_txt}",
                      plan_address=address, json_pointer=pointer)
        findings.append(Finding(
            rule_id, "availability", severity, "confirmed_by_rule", ANALYZER_ID, address, path, sha256,
            summary, rationale + " The plan's currency and executability are not verified by P02.",
            "Confirm the deletion/replacement is intended, that backups or migration exist for any data, "
            "and that the plan was generated against current state.",
            plan_address=address, evidence=[ev], locator=pointer))
        findings[-1].facts.update({  # Phase 3A typed facts (not serialized)
            "actions": list(seq), "stateful": stateful,
            "plan_type": declared_type if declared_type and _FACT_TYPE.match(declared_type) else None,
            "action_reason": (reason if reason in ACTION_REASONS else "other") if isinstance(reason, str) else None})
    return cov, findings
