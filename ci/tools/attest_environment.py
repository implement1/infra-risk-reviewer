"""A-3 / DEP-3 configuration check: turn a *saved* REST export of the `p02-risk-acknowledgement` environment into
the `gate` block of ci/p02ci/trusted_config.json, or fail.

This tool never contacts GitHub. A repository administrator saves the exports, for example:
    gh api repos/OWNER/REPO/environments/p02-risk-acknowledgement > env.json
    gh api repos/OWNER/REPO/environments/p02-risk-acknowledgement/secrets > secrets.json
and runs:
    python3 -B ci/tools/attest_environment.py env.json --repository OWNER/REPO --secrets-export secrets.json \\
        --admin-bypass-off-confirmed-by NAME --reviewer-team-excludes-pr-authors

Checks (02 sec. 3, DEP-3, A-3): the export is the `p02-risk-acknowledgement` environment of OWNER/REPO (its
`url`); JSON with duplicate keys is refused; it has a `required_reviewers`
protection rule with at least one reviewer and `prevent_self_review: true`; deployment branches are not
restricted (`deployment_branch_policy: null`, because pull_request runs use refs/pull/N/merge); it holds no
secrets; administrator bypass is off. The public REST documentation for environments (checked 2026-10-11) does
not document an administrator-bypass field, so unless the export carries an explicit `can_admins_bypass: false`
the setting must be confirmed by name with --admin-bypass-off-confirmed-by. The reviewer-team composition
(excluding PR authors) cannot be read from the export and must be confirmed explicitly.

Output: JSON for the `gate` key (mode "environment", method "admin-api-read", verified_on today). The adapter
accepts it for at most `attestation_max_age_days` (default 90; A-3 "periodically"). Exit 1 on any failure.
"""
import datetime
import json
import re
import sys

ENV_NAME = "p02-risk-acknowledgement"
_NAME_RE = re.compile(r"\A[A-Za-z0-9 ._@-]{1,64}\Z")


def _no_constant(name):
    raise ValueError(f"non-finite number {name} in export")


def _no_dups(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError("duplicate key in export")
        obj[k] = v
    return obj


def check(env: dict, secrets, bypass_confirmed_by, team_ok, repository=None):
    problems = []
    if not isinstance(env, dict) or env.get("name") != ENV_NAME:
        problems.append("environment name is not p02-risk-acknowledgement")
        return problems
    # R5 V5-03: exact binding to the API URL of OWNER/REPO (owner and repository compared case-insensitively).
    expected = f"https://api.github.com/repos/{repository}/environments/{ENV_NAME}".lower() if repository else None
    if not expected or not isinstance(env.get("url"), str) or env["url"].lower() != expected:
        problems.append("export does not belong to the repository given with --repository OWNER/REPO")
    if "html_url" in env and not (isinstance(env["html_url"], str) and env["html_url"].lower().startswith(
            f"https://github.com/{repository}/".lower())):
        problems.append("export html_url does not belong to the repository")
    if "deployment_branch_policy" not in env:
        problems.append("export lacks deployment_branch_policy (cannot confirm 'No restriction')")
    rules = env.get("protection_rules") or []
    rr = [r for r in rules if isinstance(r, dict) and r.get("type") == "required_reviewers"]
    if not rr:
        problems.append("no required_reviewers protection rule")
    else:
        if not any(r.get("reviewers") for r in rr):
            problems.append("required_reviewers rule has no reviewers")
        if not all(r.get("prevent_self_review") is True for r in rr):
            problems.append("prevent_self_review is not true")
    if env.get("deployment_branch_policy") is not None:
        problems.append("deployment branches are restricted (pull_request merge refs would not match)")
    if "can_admins_bypass" in env:
        if env["can_admins_bypass"] is not False:
            problems.append("administrators can bypass the protection rules")
    elif not bypass_confirmed_by:
        problems.append("administrator bypass not shown in the export; confirm with --admin-bypass-off-confirmed-by")
    if secrets is None:
        problems.append("no environment secrets export supplied (--secrets-export)")
    elif not (isinstance(secrets, dict) and type(secrets.get("total_count")) is int and secrets["total_count"] == 0
              and secrets.get("secrets") == []):
        problems.append("the environment holds secrets (or the secrets export is malformed)")
    if not team_ok:
        problems.append("reviewer team composition not confirmed (--reviewer-team-excludes-pr-authors)")
    return problems


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("--"):
        sys.exit(__doc__)
    env_path = argv.pop(0)
    secrets_path = by = repository = None
    team_ok = False
    while argv:
        a = argv.pop(0)
        if a == "--secrets-export" and argv:
            secrets_path = argv.pop(0)
        elif a == "--admin-bypass-off-confirmed-by" and argv:
            by = argv.pop(0)
            if not _NAME_RE.match(by):
                sys.exit("invalid confirmer name")
        elif a == "--reviewer-team-excludes-pr-authors":
            team_ok = True
        elif a == "--repository" and argv:
            repository = argv.pop(0)
            if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
                sys.exit("invalid --repository (expected OWNER/REPO)")
        else:
            sys.exit(f"unknown argument {a}")
    try:
        with open(env_path, encoding="utf-8") as fh:
            env = json.load(fh, object_pairs_hook=_no_dups, parse_constant=_no_constant)
        secrets = None
        if secrets_path:
            with open(secrets_path, encoding="utf-8") as fh:
                secrets = json.load(fh, object_pairs_hook=_no_dups, parse_constant=_no_constant)
    except ValueError as exc:
        sys.stderr.write(f"attest_environment: {exc}\n")
        return 1
    problems = check(env, secrets, by, team_ok, repository)
    if problems:
        for p in problems:
            sys.stderr.write(f"attest_environment: {p}\n")
        return 1
    gate = {"mode": "environment", "attestation_max_age_days": 90, "environment_attestation": {
        "environment": ENV_NAME, "required_reviewers": True, "prevent_self_review": True,
        "admin_bypass_disabled": True, "reviewer_team_excludes_pr_authors": True, "no_environment_secrets": True,
        "method": "admin-api-read", "verified_by": by or "rest-export",
        "verified_on": datetime.date.today().isoformat()}}
    sys.stdout.write(json.dumps(gate, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
