"""Phase 3A: typed schema for the in-memory `facts` that Phase 2 rules attach to findings (decision N3).

Facts are normalized values only (enums, small integers, booleans, allowlisted identifiers); they
are never serialized into v2, never part of finding identity, and never contain raw source text.
`check_facts` returns a list of problems (empty when valid) and is used by tests and templates.
"""

from __future__ import annotations

import re
from typing import Dict, List

PLAN_ACTIONS = ("delete", "create")
ACTION_REASONS = (
    "replace_because_tainted", "replace_because_cannot_update", "replace_by_request", "replace_by_triggers",
    "delete_because_no_resource_config", "delete_because_wrong_repetition", "delete_because_count_index",
    "delete_because_each_key", "delete_because_no_module", "delete_because_no_move_target",
)
WORKLOAD_KINDS = ("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job",
                  "CronJob")
CONTAINER_LISTS = ("containers", "initContainers", "ephemeralContainers")
_TYPE_RE = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")
_SERVICE_WILDCARD = re.compile(r"\A(?:\*|\*:\*|[a-z0-9-]{1,40}:\*)\Z")
_UNRESOLVED_RE = re.compile(r"\A[A-Za-z0-9 ./_()-]{1,80}\Z")


def _is(v, t):
    return isinstance(v, t) and not (t is int and isinstance(v, bool))


SCHEMAS: Dict[str, Dict[str, object]] = {
    "TF-IAM-001": {"wildcard_action": lambda v: isinstance(v, str) and bool(_SERVICE_WILDCARD.match(v)),
                   "resource_all": lambda v: isinstance(v, bool), "condition_present": lambda v: isinstance(v, bool)},
    "TF-IAM-002": {"wildcard_action": lambda v: isinstance(v, str) and bool(_SERVICE_WILDCARD.match(v)),
                   "resource_all": lambda v: isinstance(v, bool), "condition_present": lambda v: isinstance(v, bool)},
    "TF-IAM-003": {"policy_name": lambda v: v == "AdministratorAccess"},
    "TF-NET-001": {"ports": lambda v: v == "all" or (isinstance(v, list) and v and all(p in (22, 3389) for p in v)),
                   "protocol": lambda v: v in ("tcp", "udp", "all"),
                   "cidr_class": lambda v: v in ("ipv4_all", "ipv6_all", "ipv4_union_all", "ipv6_union_all",
                                                 "dual_all", "dual_union_all")},
    "PLAN": {"actions": lambda v: isinstance(v, list) and 1 <= len(v) <= 2 and all(a in PLAN_ACTIONS for a in v),
             "stateful": lambda v: isinstance(v, bool),
             "plan_type": lambda v: v is None or (isinstance(v, str) and bool(_TYPE_RE.match(v))),
             "action_reason": lambda v: v is None or v in ACTION_REASONS + ("other",)},
    "K8S-PRIV-001": {"container_list": lambda v: v in CONTAINER_LISTS, "workload_kind": lambda v: v in WORKLOAD_KINDS},
    "K8S-HOSTNET-001": {"workload_kind": lambda v: v in WORKLOAD_KINDS},
    "K8S-RBAC-001": {"role_kind": lambda v: v in ("Role", "ClusterRole"),
                     "wildcard_fields": lambda v: isinstance(v, list) and v and all(
                         x in ("verbs", "resources", "nonResourceURLs") for x in v) and v == sorted(v)},
    "K8S-RBAC-002": {"role_kind": lambda v: v in ("Role", "ClusterRole"),
                     "wildcard_fields": lambda v: isinstance(v, list) and v and all(
                         x in ("verbs", "resources", "nonResourceURLs") for x in v) and v == sorted(v)},
    "K8S-IMG-001": {"tag_state": lambda v: v in ("latest", "untagged"), "container_list": lambda v: v in CONTAINER_LISTS},
    "K8S-RES-001": {"missing": lambda v: v in (["requests"], ["limits"], ["limits", "requests"]),
                    "container_list": lambda v: v in CONTAINER_LISTS},
}
UNRESOLVED = {"unresolved": lambda v: isinstance(v, str) and bool(_UNRESOLVED_RE.match(v))}


def schema_for(rule_id: str, state: str) -> Dict[str, object]:
    if state == "insufficient_evidence":
        return UNRESOLVED
    if rule_id.startswith("PLAN-") and rule_id != "PLAN-ACT-UNK":
        return SCHEMAS["PLAN"]
    return SCHEMAS.get(rule_id, {})


def check_facts(rule_id: str, state: str, facts: dict) -> List[str]:
    schema = schema_for(rule_id, state)
    problems = []
    if not schema:
        return ["no fact schema for rule/state"] if facts else []
    if set(facts) != set(schema):
        problems.append("fact keys " + ",".join(sorted(facts)) + " != " + ",".join(sorted(schema)))
    for key, ok in schema.items():
        if key in facts and not ok(facts[key]):
            problems.append(f"bad value for {key}")
    return problems
