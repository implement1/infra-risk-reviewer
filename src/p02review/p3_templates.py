"""Phase 3A fixed template catalogue (P3-INV-15). Version: result_v3.TEMPLATE_CATALOGUE_VERSION.

Every sentence in a v3 report is rendered from one of these templates. Template text is fixed,
printable ASCII, and free of banned clearance phrases (checked at definition time). Slots are
typed; `render` rejects any value outside its type, so no free text from any source can enter.
"""

from __future__ import annotations

import re
import string
from typing import Callable, Dict, Tuple

from .findings import SEVERITIES
from .policy_v2 import DECISIONS, REASONS
from .result_v3 import _BANNED_RE


class SlotError(ValueError):
    pass


# Identifier grammar for generated sentences (verifier D2). One or two segments separated by a single
# space (e.g. "Deployment/ns/web containers[app]"); a segment is address characters plus bracketed index
# keys. Spaces, punctuation and prose inside names cannot pass, so free text never enters a sentence.
_KEY = r'(?:[0-9]+|"[A-Za-z0-9_.:/@+=-]{0,64}"|[A-Za-z0-9_.:/@+=-]{1,64})'
_SEG = r"(?:[A-Za-z0-9_.:/@*+=-]|\[" + _KEY + r"\])+"
_IDENT_RE = re.compile(r"\A" + _SEG + r"(?: " + _SEG + r")?\Z")
# Display grammars (corrective pass CV4): Terraform/plan addresses are one segment; only Kubernetes resources
# carry a second, structural segment (containers[..], initContainers[..], ephemeralContainers[..], rules[N]).
_ADDR_DISPLAY_RE = re.compile(r"\A" + _SEG + r"\Z")
_RESOURCE_DISPLAY_RE = re.compile(r"\A" + _SEG + r"(?: (?:(?:containers|initContainers|ephemeralContainers)\["
                                  + _KEY + r"\]|rules\[[0-9]{1,6}\]))?\Z")
_PATH_RE = re.compile(r"\A[A-Za-z0-9._+@=/-]{1,240}\Z")
IDENT_WITHHELD = "[identifier withheld]"
PATH_WITHHELD = "[path withheld]"
MAX_IDENT_DISPLAY = 120
MAX_PATH_DISPLAY = 160
IDENT_SLOTS = ("plan_address", "static_resource")
RESOURCE_SLOTS = ("resource",)
PATH_SLOTS = ("path", "static_path")


def _display(v, grammar):
    if isinstance(v, str) and len(v) <= MAX_IDENT_DISPLAY and grammar.match(v) and not _BANNED_RE.search(v):
        return v
    return IDENT_WITHHELD


def display_ident(v):
    """A Terraform/plan address when it is one segment, fits the grammar and holds no banned word; otherwise a
    fixed marker. The full value remains available in the structured v2/v3 fields that the sentence cites."""
    return _display(v, _ADDR_DISPLAY_RE)


def display_resource(v):
    """A finding resource: one segment, or a Kubernetes object plus one structural second segment."""
    return _display(v, _RESOURCE_DISPLAY_RE)


def display_path(v):
    if (isinstance(v, str) and len(v) <= MAX_PATH_DISPLAY and _PATH_RE.match(v) and ".." not in v.split("/")
            and not _BANNED_RE.search(v)):
        return v
    return PATH_WITHHELD


def display_slots(slots: dict, k8s: bool = False) -> dict:
    """Display values for identifier and path slots. Only Kubernetes findings (k8s=True) may show a structural
    second segment in `resource`; Terraform and plan identifiers must be one segment (corrective pass CV8)."""
    out = dict(slots)
    for k in IDENT_SLOTS:
        if k in out:
            out[k] = display_ident(out[k])
    for k in RESOURCE_SLOTS:
        if k in out:
            out[k] = display_resource(out[k]) if k8s else display_ident(out[k])
    for k in PATH_SLOTS:
        if k in out:
            out[k] = display_path(out[k])
    return out
_CODE_RE = re.compile(r"\A[A-Z][A-Z0-9_]{1,60}\Z")
_UNRESOLVED_RE = re.compile(r"\A[A-Za-z0-9 ./_()-]{1,80}\Z")
_RULE_RE = re.compile(r"\A(?:TF|PLAN|K8S)-[A-Z0-9]+-[A-Z0-9]+\Z")


def _ident(v):
    if v == IDENT_WITHHELD:
        return v
    if not isinstance(v, str) or len(v) > MAX_IDENT_DISPLAY or not _IDENT_RE.match(v):
        raise SlotError("identifier slot")
    return v


def _path(v):
    if v == PATH_WITHHELD:
        return v
    if not isinstance(v, str) or len(v) > MAX_PATH_DISPLAY or not _PATH_RE.match(v) or ".." in v.split("/"):
        raise SlotError("path slot")
    return v


def _span(v):
    if (not isinstance(v, tuple) or len(v) != 2 or not all(isinstance(x, int) and not isinstance(x, bool) for x in v)
            or not 1 <= v[0] <= v[1]):
        raise SlotError("span slot")
    return f"line {v[0]}" if v[0] == v[1] else f"lines {v[0]}-{v[1]}"


def _int(v):
    if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > 1_000_000:
        raise SlotError("int slot")
    return str(v)


def _codes(v):
    if not isinstance(v, (list, tuple)) or len(v) > 12 or not all(isinstance(c, str) and _CODE_RE.match(c) for c in v):
        raise SlotError("codes slot")
    return ", ".join(v) if v else "none recorded"


def _reasons(v):
    if not isinstance(v, (list, tuple)) or not v or not all(r in REASONS for r in v):
        raise SlotError("reasons slot")
    return ", ".join(v)


def _ports(v):
    if v == "all":
        return "all ports"
    if not isinstance(v, list) or not v or not all(p in (22, 3389) for p in v) or v != sorted(set(v)):
        raise SlotError("ports slot")
    return " and ".join({22: "SSH (22)", 3389: "RDP (3389)"}[p] for p in v)


def _unresolved(v):
    if not isinstance(v, str) or not _UNRESOLVED_RE.match(v):
        raise SlotError("unresolved slot")
    return v


def _rule(v):
    if not isinstance(v, str) or not _RULE_RE.match(v):
        raise SlotError("rule slot")
    return v


def _enum(*values):
    def check(v):
        if v not in values:
            raise SlotError("enum slot")
        return v
    return check


SEVERITY = _enum(*SEVERITIES)
DECISION = _enum(*DECISIONS)
STATE = _enum("confirmed_by_rule", "suspected", "insufficient_evidence", "unsupported")


class Template:
    def __init__(self, tid: str, text: str, slots: Dict[str, Callable]):
        names = {f for _, f, _, _ in string.Formatter().parse(text) if f is not None}
        if names != set(slots):
            raise SlotError(f"template {tid}: placeholders {sorted(names)} != slots {sorted(slots)}")
        if not re.fullmatch(r"[\x20-\x7e]+", text) or _BANNED_RE.search(text):
            raise SlotError(f"template {tid}: non-ASCII or banned phrase")
        self.id, self.text, self.slots = tid, text, slots

    def render(self, values: dict) -> str:
        if set(values) != set(self.slots):
            raise SlotError(f"template {self.id}: slot set mismatch")
        rendered = {k: check(values[k]) for k, check in self.slots.items()}
        out = self.text.format(**rendered)
        if _BANNED_RE.search(out) or not re.fullmatch(r"[\x20-\x7e]+", out) or len(out) > 600:
            raise SlotError(f"template {self.id}: rendered text rejected")
        return out


SRC = {"resource": _ident, "path": _path, "span": _span, "severity": SEVERITY}
PLAN = {"plan_address": _ident, "severity": SEVERITY}

# ----------------------------------------------------------------------------- decision
DECISION_TEMPLATES = {
    "review_required": Template(
        "D-review_required",
        "Phase 2 decision (unchanged): review_required. {n_high} high-severity finding(s) were confirmed by "
        "deterministic rules, so human review is required before merge. Policy reasons: {reasons}.",
        {"n_high": _int, "reasons": _reasons}),
    "no_blocking_findings_detected": Template(
        "D-no_blocking_findings_detected",
        "Phase 2 decision (unchanged): no_blocking_findings_detected. All {n_files} declared file(s) were parsed and "
        "every applicable baseline rule ran without a blocking finding. This describes the baseline rules only, not "
        "the change as a whole; human review remains required. Policy reasons: {reasons}.",
        {"n_files": _int, "reasons": _reasons}),
    "inconclusive": Template(
        "D-inconclusive",
        "Phase 2 decision (unchanged): inconclusive. The baseline could not establish the evidence or coverage "
        "needed for a disposition, and unknown is never treated as acceptable. Policy reasons: {reasons}.",
        {"reasons": _reasons}),
}

# ----------------------------------------------------------------------------- coverage
COVERAGE_SUMMARY = Template(
    "C-summary",
    "Coverage: {n_analyzed} of {n_files} declared file(s) were fully analysed; {n_gap} file(s) have coverage gaps "
    "and are listed before any finding.",
    {"n_analyzed": _int, "n_files": _int, "n_gap": _int})
COVERAGE_STATUS_TEMPLATES = {
    "partial": Template("C-partial", "{path} was only partially analysed ({codes}); results for this file may be "
                                     "incomplete.", {"path": _path, "codes": _codes}),
    "partial_no_notes": Template("C-partial_no_notes", "{path} was only partially analysed because at least one value "
                                                       "could not be evaluated; see its insufficient-evidence findings.",
                                 {"path": _path}),
    "unsupported": Template("C-unsupported", "{path} uses constructs outside the supported parser subset ({codes}); no "
                                             "rule results exist for this file.", {"path": _path, "codes": _codes}),
    "parse_error": Template("C-parse_error", "{path} could not be parsed ({codes}); no rule results exist for this "
                                             "file.", {"path": _path, "codes": _codes}),
    "not_analyzed": Template("C-not_analyzed", "{path} has no Phase 2 analyzer ({codes}); its content was not "
                                               "evaluated.", {"path": _path, "codes": _codes}),
}

# ----------------------------------------------------------------------------- findings
_CONF = "confirmed_by_rule"
RULE_TEMPLATES: Dict[Tuple[str, str], Template] = {
    ("TF-IAM-001", _CONF): Template(
        "F-TF-IAM-001-confirmed",
        "{resource} ({path}, {span}): an IAM policy statement allows action '{wildcard_action}' on all resources. "
        "Rule TF-IAM-001, severity {severity}, confirmed by rule.",
        dict(SRC, wildcard_action=_enum("*", "*:*"))),
    ("TF-IAM-001", "suspected"): Template(
        "F-TF-IAM-001-suspected",
        "{resource} ({path}, {span}): an IAM policy statement allows action '{wildcard_action}' on all resources, but "
        "a Condition is present that may narrow it. Rule TF-IAM-001, severity {severity}, suspected.",
        dict(SRC, wildcard_action=_enum("*", "*:*"))),
    ("TF-IAM-002", _CONF): Template(
        "F-TF-IAM-002-confirmed",
        "{resource} ({path}, {span}): an IAM policy statement grants the wildcard action '{wildcard_action}' on "
        "{resource_scope} resources. Rule TF-IAM-002, severity {severity}, confirmed by rule.",
        dict(SRC, wildcard_action=_ident, resource_scope=_enum("all", "scoped or partly dynamic"))),
    ("TF-IAM-002", "suspected"): Template(
        "F-TF-IAM-002-suspected",
        "{resource} ({path}, {span}): an IAM policy statement grants the wildcard action '{wildcard_action}' on "
        "{resource_scope} resources, but a Condition is present that may narrow it. Rule TF-IAM-002, severity "
        "{severity}, suspected.",
        dict(SRC, wildcard_action=_ident, resource_scope=_enum("all", "scoped or partly dynamic"))),
    ("TF-IAM-003", _CONF): Template(
        "F-TF-IAM-003-confirmed",
        "{resource} ({path}, {span}): the AWS-managed AdministratorAccess policy is attached. Rule TF-IAM-003, "
        "severity {severity}, confirmed by rule.", dict(SRC)),
    ("TF-NET-001", _CONF): Template(
        "F-TF-NET-001-confirmed",
        "{resource} ({path}, {span}): ingress from the entire {cidr_family} address space{cidr_note} reaches "
        "{ports} over {protocol}. Rule TF-NET-001, severity {severity}, confirmed by rule. Exposure also depends on "
        "attachment and routing, which were not evaluated.",
        dict(SRC, cidr_family=_enum("IPv4", "IPv6", "IPv4 and IPv6"),
             cidr_note=_enum("", " (written as a union of narrower ranges)",
                            " (at least one family written as a union of narrower ranges)"), ports=_ports,
             protocol=_enum("tcp", "udp", "any protocol"))),
    ("PLAN-DEL-001", _CONF): Template(
        "F-PLAN-DEL-001-confirmed",
        "The supplied plan deletes {plan_address} ({type_desc}; {stateful_desc}). Rule PLAN-DEL-001, severity "
        "{severity}, confirmed by rule. Whether the plan is current was not verified.",
        dict(PLAN, type_desc=_enum("type recorded in the plan", "type not recorded"),
             stateful_desc=_enum("type is in the stateful list", "type is not in the stateful list"))),
    ("PLAN-REP-001", _CONF): Template(
        "F-PLAN-REP-001-confirmed",
        "The supplied plan replaces {plan_address} by destroying it before creating the replacement ({type_desc}; "
        "{stateful_desc}){reason_note}. Rule PLAN-REP-001, severity {severity}, confirmed by rule. Whether the plan is "
        "current was not verified.",
        dict(PLAN, type_desc=_enum("type recorded in the plan", "type not recorded"),
             stateful_desc=_enum("type is in the stateful list", "type is not in the stateful list"),
             reason_note=lambda v: "" if v is None else "; Terraform reason: " + _enum(
                 "replace_because_tainted", "replace_because_cannot_update", "replace_by_request",
                 "replace_by_triggers", "other")(v))),
    ("PLAN-REP-002", _CONF): Template(
        "F-PLAN-REP-002-confirmed",
        "The supplied plan replaces {plan_address} by creating the replacement before destroying the original "
        "({type_desc}; {stateful_desc}){reason_note}. Rule PLAN-REP-002, severity {severity}, confirmed by rule. "
        "Whether the plan is current was not verified.",
        dict(PLAN, type_desc=_enum("type recorded in the plan", "type not recorded"),
             stateful_desc=_enum("type is in the stateful list", "type is not in the stateful list"),
             reason_note=lambda v: "" if v is None else "; Terraform reason: " + _enum(
                 "replace_because_tainted", "replace_because_cannot_update", "replace_by_request",
                 "replace_by_triggers", "other")(v))),
    ("K8S-PRIV-001", _CONF): Template(
        "F-K8S-PRIV-001-confirmed",
        "{resource} ({path}, {span}): a container in {container_list} of a {workload_kind} sets "
        "securityContext.privileged to true. Rule K8S-PRIV-001, severity {severity}, confirmed by rule.",
        dict(SRC, container_list=_enum("containers", "initContainers", "ephemeralContainers"),
             workload_kind=_enum("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
                                 "ReplicationController", "Job", "CronJob"))),
    ("K8S-HOSTNET-001", _CONF): Template(
        "F-K8S-HOSTNET-001-confirmed",
        "{resource} ({path}, {span}): the {workload_kind} pod uses the node network namespace (hostNetwork: true). "
        "Rule K8S-HOSTNET-001, severity {severity} (context-dependent), confirmed by rule.",
        dict(SRC, workload_kind=_enum("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
                                      "ReplicationController", "Job", "CronJob"))),
    ("K8S-RBAC-001", _CONF): Template(
        "F-K8S-RBAC-001-confirmed",
        "{resource} ({path}, {span}): a {role_kind} rule grants every verb on every resource ('*' in "
        "{wildcard_fields}). Rule K8S-RBAC-001, severity {severity}, confirmed by rule.",
        dict(SRC, role_kind=_enum("Role", "ClusterRole"), wildcard_fields=_enum(
            "resources and verbs", "nonResourceURLs, resources and verbs"))),
    ("K8S-RBAC-002", _CONF): Template(
        "F-K8S-RBAC-002-confirmed",
        "{resource} ({path}, {span}): a {role_kind} rule uses '*' in {wildcard_fields}. Rule K8S-RBAC-002, severity "
        "{severity}, confirmed by rule.",
        dict(SRC, role_kind=_enum("Role", "ClusterRole"), wildcard_fields=_enum(
            "verbs", "resources", "nonResourceURLs", "nonResourceURLs and verbs", "nonResourceURLs and resources"))),
    ("K8S-IMG-001", _CONF): Template(
        "F-K8S-IMG-001-confirmed",
        "{resource} ({path}, {span}): the container image {tag_desc}, so the image content can change without a "
        "manifest change. Rule K8S-IMG-001, severity {severity} (context-dependent), confirmed by rule.",
        dict(SRC, tag_desc=_enum("uses the 'latest' tag", "has no tag or digest (implicitly 'latest')"))),
    ("K8S-RES-001", _CONF): Template(
        "F-K8S-RES-001-confirmed",
        "{resource} ({path}, {span}): the container declares no resource {missing}. Rule K8S-RES-001, severity "
        "{severity} (context-dependent), confirmed by rule.",
        dict(SRC, missing=_enum("requests", "limits", "requests or limits"))),
}
INSUFFICIENT_SOURCE = Template(
    "F-insufficient-source",
    "{resource} ({path}, {span}): {rule_id} could not be evaluated because the {unresolved} value is dynamic, "
    "ambiguous or outside the supported subset. Severity is unknown; this is not evidence that the risk is absent.",
    {"resource": _ident, "path": _path, "span": _span, "rule_id": _rule, "unresolved": _unresolved})
INSUFFICIENT_PLAN = Template(
    "F-insufficient-plan",
    "The plan entry {plan_address} could not be interpreted ({rule_id}): the resource address, type, mode or action "
    "sequence is missing, unrecognised or inconsistent. Severity is unknown; this is not evidence that the change has "
    "no effect.",
    {"plan_address": _ident, "rule_id": _rule})
FINDINGS_NONE = Template(
    "F-none",
    "No finding was reported by the Phase 2 baseline rules; this statement covers only the rules and files listed "
    "above, including their coverage gaps.", {})
GENERIC_SOURCE = Template(
    "F-generic-source",
    "{resource} ({path}, {span}): rule {rule_id} reported state {state} with severity {severity}.",
    {"resource": _ident, "path": _path, "span": _span, "rule_id": _rule, "state": STATE, "severity": SEVERITY})
GENERIC_PLAN = Template(
    "F-generic-plan",
    "Plan entry {plan_address}: rule {rule_id} reported state {state} with severity {severity}.",
    {"plan_address": _ident, "rule_id": _rule, "state": STATE, "severity": SEVERITY})

_ALL_RULES = ("TF-IAM-001", "TF-IAM-002", "TF-IAM-003", "TF-NET-001", "PLAN-DEL-001", "PLAN-REP-001",
              "PLAN-REP-002", "PLAN-ACT-UNK", "K8S-PRIV-001", "K8S-HOSTNET-001", "K8S-RBAC-001", "K8S-RBAC-002",
              "K8S-IMG-001", "K8S-RES-001")
for _r in _ALL_RULES:
    _plan = _r.startswith("PLAN-")
    RULE_TEMPLATES.setdefault((_r, "insufficient_evidence"), INSUFFICIENT_PLAN if _plan else INSUFFICIENT_SOURCE)
    for _s in ("confirmed_by_rule", "suspected"):
        RULE_TEMPLATES.setdefault((_r, _s), GENERIC_PLAN if _plan else GENERIC_SOURCE)

# ----------------------------------------------------------------------------- links
_BASIS = _enum("plan-address-unavailable", "identifier-sanitized", "module-address", "data-source-address",
               "indexed-address", "address-unparseable", "no-static-block", "multiple-static-blocks",
               "static-file-not-fully-analyzed", "terraform-coverage-incomplete", "module-membership-unverified")


def _basis(v):
    if not isinstance(v, list) or not v:
        raise SlotError("basis slot")
    return ", ".join(_BASIS(b) for b in v)


LINK_CANDIDATE = Template(
    "L-candidate",
    "Plan entry {plan_address} has the same type and name as {static_resource} in {static_path} ({span}). Module "
    "membership of that file is not verified, so this is a candidate relationship only.",
    {"plan_address": _ident, "static_resource": _ident, "static_path": _path, "span": _span})
LINK_UNLINKED = Template(
    "L-unlinked",
    "Plan entry {plan_address} is not linked to any configuration block ({basis}).",
    {"plan_address": _ident, "basis": lambda v: _basis(v)})

# ----------------------------------------------------------------------------- questions
QUESTION_TEMPLATES = {
    "Q-ins-iam": Template("Q-ins-iam", "What are the resolved effect, actions and resources of the IAM statement for "
                                       "{resource} in {path} at {span}?", {"resource": _ident, "path": _path, "span": _span}),
    "Q-ins-iam-attach": Template("Q-ins-iam-attach", "Which managed policy does {resource} in {path} at {span} attach "
                                                     "once its ARN is resolved?",
                                 {"resource": _ident, "path": _path, "span": _span}),
    "Q-ins-net": Template("Q-ins-net", "What are the resolved source CIDRs, protocol and ports of the ingress rule for "
                                       "{resource} in {path} at {span}?", {"resource": _ident, "path": _path, "span": _span}),
    "Q-ins-k8s": Template("Q-ins-k8s", "What is the intended value of the {unresolved} setting for {resource} in {path} "
                                       "at {span}?", {"unresolved": _unresolved, "resource": _ident, "path": _path,
                                                      "span": _span}),
    "Q-ins-plan": Template("Q-ins-plan", "What change does the plan entry {plan_address} represent, and was the plan "
                                         "produced by a supported Terraform version?", {"plan_address": _ident}),
    "Q-suspected-iam": Template("Q-suspected-iam", "Does the Condition on the IAM statement for {resource} in {path} at "
                                                   "{span} restrict the wildcard grant in every context where it "
                                                   "applies?", {"resource": _ident, "path": _path, "span": _span}),
    "Q-note-module": Template("Q-note-module", "Which resources and permissions are created by the module called from "
                                               "{path}?", {"path": _path}),
    "Q-note-override": Template("Q-note-override", "What is the effective configuration of {path} after Terraform "
                                                   "merges override files and duplicate declarations?", {"path": _path}),
    "Q-note-syntax": Template("Q-note-syntax", "Can {path} be rewritten within the supported subset, or who will review "
                                               "it manually?", {"path": _path}),
    "Q-note-no-analyzer": Template("Q-note-no-analyzer", "Who will review the content of {path}, which no baseline "
                                                         "analyzer covers?", {"path": _path}),
    "Q-note-plan": Template("Q-note-plan", "Can a complete, current plan be supplied in place of {path}?", {"path": _path}),
    "Q-note-k8s": Template("Q-note-k8s", "Which objects in {path} were not recognised, and do any of them configure "
                                         "workloads or permissions?", {"path": _path}),
    "Q-note-rbac-agg": Template("Q-note-rbac-agg", "Which ClusterRoles are aggregated into the role defined in {path}, "
                                                   "and what do they grant?", {"path": _path}),
    "Q-note-helm": Template("Q-note-helm", "Which other values files or template combinations are deployed besides the "
                                           "rendered output in {path}?", {"path": _path}),
    # Catalogue v2 (corrective pass C1): confirmed destructive, connectivity and public-admin-ingress findings.
    "Q-plan-del-stateful": Template(
        "Q-plan-del-stateful", "Before {plan_address} is deleted, is there a recent backup or snapshot that has been "
                               "restored successfully, and is its data migrated or confirmed as no longer needed?",
        {"plan_address": _ident}),
    "Q-plan-del": Template(
        "Q-plan-del", "Is the deletion of {plan_address} intended, and does any other resource, module or external "
                      "system still depend on it?", {"plan_address": _ident}),
    "Q-plan-rep-stateful": Template(
        "Q-plan-rep-stateful", "Replacing {plan_address} recreates it; how will its existing data be preserved or "
                               "migrated, and has a restore from backup been tested?", {"plan_address": _ident}),
    "Q-plan-rep-dbc": Template(
        "Q-plan-rep-dbc", "{plan_address} is destroyed before its replacement is created; what loses service during "
                          "that window, and should create_before_destroy be used?", {"plan_address": _ident}),
    "Q-plan-connectivity": Template(
        "Q-plan-connectivity", "Which instances, load balancers or other dependents rely on {plan_address}, and will "
                               "they lose network connectivity while it is {change_desc}?",
        {"plan_address": _ident, "change_desc": _enum("deleted", "destroyed before its replacement exists",
                                                      "replaced")}),
    "Q-net-public-admin-generic": Template(
        "Q-net-public-admin-generic", "Must the ingress rule for {resource} in {path} at {span} be reachable from "
                                      "the internet, or can its source be limited to a bastion host, VPN or known "
                                      "CIDR range?", {"resource": _ident, "path": _path, "span": _span}),
    "Q-net-public-admin": Template(
        "Q-net-public-admin", "Must {ports} on {resource} in {path} at {span} be reachable from the entire "
                              "{cidr_family} address space, or can the source be limited to a bastion host, VPN or "
                              "known CIDR range, and which instances use this rule?",
        {"ports": _ports, "resource": _ident, "path": _path, "span": _span, "cidr_family": _enum("IPv4", "IPv6", "IPv4 and IPv6")}),
}

# Resource types whose deletion or replacement can interrupt network paths (catalogue v2 heuristic list, used
# only to choose a question; it never changes a finding or severity). Types outside it get the generic questions.
CONNECTIVITY_TYPES = frozenset((
    "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule", "aws_network_acl", "aws_network_acl_rule", "aws_lb", "aws_alb", "aws_elb",
    "aws_lb_listener", "aws_alb_listener", "aws_lb_target_group", "aws_alb_target_group", "aws_route",
    "aws_route_table", "aws_route_table_association", "aws_nat_gateway", "aws_internet_gateway", "aws_eip",
    "aws_subnet", "aws_vpc", "aws_vpc_endpoint", "aws_vpc_peering_connection", "aws_network_interface",
    "aws_ec2_transit_gateway", "aws_ec2_transit_gateway_vpc_attachment", "aws_vpn_gateway", "aws_vpn_connection",
    "aws_route53_record", "aws_route53_zone", "aws_api_gateway_rest_api", "aws_cloudfront_distribution",
    "google_compute_firewall", "google_compute_network", "google_compute_subnetwork", "google_compute_route",
    "google_compute_forwarding_rule", "azurerm_network_security_group", "azurerm_network_security_rule",
    "azurerm_virtual_network", "azurerm_subnet", "azurerm_lb", "azurerm_route_table",
    "kubernetes_service", "kubernetes_ingress", "kubernetes_ingress_v1", "kubernetes_network_policy",
))
NOTE_QUESTION = {
    "MODULE_NOT_ANALYZED": "Q-note-module", "TF_OVERRIDE_NOT_MERGED": "Q-note-override",
    "TF_DUPLICATE_BLOCK_ADDRESS": "Q-note-override", "HCL_SYNTAX_ERROR": "Q-note-syntax",
    "HCL_UNSUPPORTED_CONSTRUCT": "Q-note-syntax", "YAML_SYNTAX_ERROR": "Q-note-syntax",
    "YAML_UNSUPPORTED_CONSTRUCT": "Q-note-syntax", "NO_ANALYZER": "Q-note-no-analyzer",
    "NOT_KUBERNETES": "Q-note-k8s", "UNRECOGNIZED_KIND": "Q-note-k8s", "POD_SPEC_MISSING": "Q-note-k8s",
    "UNKNOWN_TOP_LEVEL_FIELD": "Q-note-k8s", "RBAC_AGGREGATION_NOT_EVALUATED": "Q-note-rbac-agg",
    "HELM_RENDERED_ONLY": "Q-note-helm",
}

# ----------------------------------------------------------------------------- unknowns (one per note code)
_UNKNOWN_TEXT = {
    "HCL_SYNTAX_ERROR": "{path}: the file is not valid HCL within the supported subset, so it was not analysed.",
    "HCL_UNSUPPORTED_CONSTRUCT": "{path}: the file uses HCL outside the supported subset, so it was not analysed.",
    "YAML_SYNTAX_ERROR": "{path}: the file is not valid YAML within the supported subset, so it was not analysed.",
    "YAML_UNSUPPORTED_CONSTRUCT": "{path}: the file uses YAML outside the supported subset, so it was not analysed.",
    "NO_ANALYZER": "{path}: no Phase 2 analyzer exists for this file kind, so its content is unknown to the baseline.",
    "MODULE_NOT_ANALYZED": "{path}: a module call was not analysed because the module source is not part of the "
                           "evidence.",
    "TF_OVERRIDE_NOT_MERGED": "{path}: override files in this directory are not merged, so effective values may differ "
                              "from those analysed.",
    "TF_DUPLICATE_BLOCK_ADDRESS": "{path}: a block address is declared more than once in this directory; the effective "
                                  "configuration was not evaluated.",
    "NOT_KUBERNETES": "{path}: a YAML document has no apiVersion and kind, so it was not analysed as Kubernetes.",
    "UNRECOGNIZED_KIND": "{path}: an object kind is not covered by the Phase 2 rule set.",
    "POD_SPEC_MISSING": "{path}: a workload has no pod specification at the expected path.",
    "UNKNOWN_TOP_LEVEL_FIELD": "{path}: an object has unrecognised top-level fields, so it was not fully understood.",
    "RBAC_AGGREGATION_NOT_EVALUATED": "{path}: an aggregated ClusterRole's effective rules come from other roles and "
                                      "were not evaluated.",
    "HELM_RENDERED_ONLY": "{path}: only this rendered output was analysed; other template and values combinations are "
                          "untested.",
    "PLAN_DUPLICATE_ADDRESS": "{path}: the plan lists the same resource address more than once.",
    "PLAN_ERRORED": "{path}: the plan reports that it errored, so it may be incomplete.",
    "PLAN_INCOMPLETE": "{path}: the plan reports that it is incomplete (deferred changes).",
    "PLAN_FORMAT_UNSUPPORTED": "{path}: the plan format version is missing or unsupported, so it was not analysed.",
    "PLAN_NOT_OBJECT": "{path}: the plan JSON is not an object, so it was not analysed.",
    "PLAN_RESOURCE_CHANGES_MISSING": "{path}: the plan has no resource_changes list, so no plan coverage is claimed.",
    "PLAN_RESOURCE_CHANGES_MALFORMED": "{path}: the plan resource_changes field is malformed, so it was not analysed.",
    "JSON_SYNTAX": "{path}: the plan is not valid JSON, so it was not analysed.",
    "JSON_DUPLICATE_KEY": "{path}: the plan JSON repeats a key, so it was not analysed.",
    "JSON_NON_FINITE": "{path}: the plan JSON contains a non-finite number, so it was not analysed.",
    "JSON_TOO_DEEP": "{path}: the plan JSON is nested too deeply, so it was not analysed.",
    "JSON_TOO_LARGE": "{path}: the plan JSON has too many values, so it was not analysed.",
    "JSON_BAD_STRING": "{path}: the plan JSON contains an invalid string, so it was not analysed.",
}
NOTE_CODES = tuple(sorted(_UNKNOWN_TEXT))
UNKNOWN_TEMPLATES = {code: Template("U-" + code, text, {"path": _path}) for code, text in _UNKNOWN_TEXT.items()}
for _code in NOTE_CODES:
    NOTE_QUESTION.setdefault(_code, "Q-note-plan" if _code.startswith(("PLAN_", "JSON_")) else "Q-note-syntax")


def all_templates():
    seen = {}
    for t in list(DECISION_TEMPLATES.values()) + [COVERAGE_SUMMARY] + list(COVERAGE_STATUS_TEMPLATES.values()) + \
            list(RULE_TEMPLATES.values()) + [FINDINGS_NONE, LINK_CANDIDATE, LINK_UNLINKED] + \
            list(QUESTION_TEMPLATES.values()) + \
            list(UNKNOWN_TEMPLATES.values()):
        seen[t.id] = t
    return [seen[k] for k in sorted(seen)]


_SAMPLES = {
    _ident: "aws_security_group.example", _path: "infra/main.tf", _span: (3, 9), _int: 2, _codes: ["NO_ANALYZER"],
    _reasons: ["COVERAGE_INCOMPLETE"], _ports: [22], _unresolved: "ingress source CIDR/protocol/ports", _rule: "TF-NET-001",
    SEVERITY: "high", DECISION: "inconclusive", STATE: "suspected",
}


def sample_slots(tpl: Template) -> dict:
    """Representative valid slot values for tests (enum slots take their first allowed value)."""
    out = {}
    for name, check in tpl.slots.items():
        if check in _SAMPLES:
            out[name] = _SAMPLES[check]
        elif name == "basis":
            out[name] = ["no-static-block", "module-membership-unverified"]
        elif name == "reason_note":
            out[name] = None
        else:  # enum: discover its first allowed value
            for candidate in ("*", "all", "IPv4", "", "tcp", "type recorded in the plan", "type is in the stateful list",
                              "containers", "Pod", "Role", "resources and verbs", "verbs", "uses the 'latest' tag",
                              "requests", "deleted"):
                try:
                    check(candidate)
                    out[name] = candidate
                    break
                except SlotError:
                    continue
    return out
