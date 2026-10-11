"""Closed vocabularies and renderer-owned fixed text (01 sec. 3 and sec. 8; 04 sec. 2-3).

Anything outside these sets in P02 output is an integrity failure (04 sec. 7). Read-only imports of the
accepted core supply the decision, reason, note-code and error-code sets so that the adapter cannot drift.
"""
from p02review import errors as _errors
from p02review import p3_templates as _T
from p02review import policy_v2 as _policy

DECISIONS = tuple(_policy.DECISIONS)
REASONS = tuple(_policy.REASONS)
ANALYSIS_RULES = ("TF-IAM-001", "TF-IAM-002", "TF-IAM-003", "TF-NET-001", "PLAN-DEL-001", "PLAN-REP-001",
                  "PLAN-REP-002", "PLAN-ACT-UNK", "K8S-PRIV-001", "K8S-HOSTNET-001", "K8S-RBAC-001", "K8S-RBAC-002",
                  "K8S-IMG-001", "K8S-RES-001")
SECRET_RULES = ("aws-access-key-id", "github-token", "github-fine-grained-pat", "private-key-block", "slack-token",
                "jwt", "credential-assignment")
SEVERITIES = ("critical", "high", "unknown", "medium", "low", "info")      # display rank order (04 sec. 3)
STATES = ("confirmed_by_rule", "suspected", "insufficient_evidence", "unsupported")
COVERAGE_STATUSES = ("analyzed", "partial", "unsupported", "parse_error", "not_analyzed")
NOTE_CODES = tuple(_T.NOTE_CODES)
ERROR_CODES = frozenset(v for k, v in vars(_errors).items()
                        if k.isupper() and isinstance(v, str) and v.isupper() and v.replace("_", "").isalpha())
ADAPTER_REFUSALS = ("P02CI_PATH_SYMLINK", "P02CI_NOT_REGULAR", "P02CI_HARDLINK", "P02CI_MANIFEST_SYMLINK",
                    "P02CI_MANIFEST_NOT_REGULAR", "P02CI_PROVENANCE_NOT_DECLARED")

DECISION_MEANING = {
    "review_required": "at least one high-severity finding was confirmed by a deterministic rule; human review is "
                       "required.",
    "inconclusive": "P02 could not evaluate everything; this is not a low-risk result.",
    "no_blocking_findings_detected": "no blocking finding by the baseline rules on complete coverage; this is not "
                                     "a safety approval.",
}

_NOTE_GROUP_TEXT = {
    "Q-note-module": "Identify the resources and permissions created by the module that was not analysed.",
    "Q-note-override": "Establish the effective configuration after override files and duplicate declarations "
                       "are merged.",
    "Q-note-syntax": "Rewrite the file within the supported subset, or name who will review it manually.",
    "Q-note-no-analyzer": "Name who will review this file, which no baseline analyzer covers.",
    "Q-note-plan": "Supply a complete, current plan in place of this file, or review it manually.",
    "Q-note-k8s": "Identify the objects that were not recognised and whether they configure workloads or "
                  "permissions.",
    "Q-note-rbac-agg": "Identify the roles aggregated into this ClusterRole and what they grant.",
    "Q-note-helm": "Identify other values files or template combinations that are deployed.",
}

QUESTION_TEXT = {
    "PUBLIC_ADMIN_INGRESS": "Confirm that SSH or RDP exposure to an entire address family is intended.",
    "DESTRUCTIVE_CHANGE": "Confirm that the deletion or replacement is intended and that data and dependants are "
                          "protected.",
    "CONNECTIVITY_RISK": "Confirm which dependants lose network connectivity while this resource is deleted or "
                         "replaced.",
    "INSUFFICIENT_EVIDENCE": "Supply the resolved values P02 could not evaluate, or review this item manually.",
    "SUSPECTED": "Confirm whether the condition on this statement restricts the wildcard grant everywhere it "
                 "applies.",
}
for _code in NOTE_CODES:
    QUESTION_TEXT[_code] = _NOTE_GROUP_TEXT[_T.NOTE_QUESTION[_code]]

CHANGE_WORDS = {"A": "added", "M": "modified", "D": "deleted", "T": "type-changed"}
REASON_TEXT = {"outside_packages": "outside every package", "undeclared_in_package": "undeclared in package",
               "package_not_assessed": "package not assessed"}

LIMITATIONS = (
    "Advisory rendering of the deterministic P02 baseline; it does not change any finding, severity, coverage "
    "status or decision.",
    "Parsers cover documented HCL and YAML subsets only; files outside them are reported as coverage gaps.",
    "Variables, modules, override merges and runtime state are not resolved.",
    "P02 does not establish that a plan is current, complete or what will be applied.",
    "Only declared files of fixture packages are read; other changed files are listed as not reviewed.",
    "The credential screen is pattern-based and not a complete secrets scanner.",
    "No language model was used.",
)
