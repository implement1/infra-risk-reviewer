# Mode A deployment checklist (for the repository administrator; nothing here was configured by G-CI-2)

Each item references the dependency or amendment it satisfies. Live verification of these settings is the L3
scope (separate authorization, D-CI-09).

## Before the first run

1. **Action and runtime pins (DEP-5, L2 invariant 3, D-CI-04).** Replace every `PIN_REQUIRED_*` placeholder in
   `.github/workflows/p02-review.yml` with full 40-character commit SHAs of `actions/checkout` and
   `actions/setup-python`, verified to come from those repositories (not forks), and with the exact Python 3.13
   patch release. Then `python3 -B ci/tests/wflint.py` (strict) must report `problems=0`.
   No SHA was invented in this change. Until pinned, the workflow cannot resolve its actions, so the run fails
   or never reports: the required checks are then red or pending, never green (live behaviour to be confirmed
   in L3).
2. **Accepted suite on the runner image (02 sec. 4).** Run the 288 accepted core tests with the pinned
   interpreter on `ubuntu-24.04` before first use and on every runtime pin change.
3. **LD_LIBRARY_PATH (A-8).** If the pinned interpreter needs it under `env -i`, add
   `LD_LIBRARY_PATH="/opt/hostedtoolcache/Python/3.13.N/x64/lib"` directly after `PYTHONDONTWRITEBYTECODE=1` in
   the `exec env -i` line (the linter accepts only that tool-cache form; the adapter checks it is absolute, has no
   empty segment and is outside pr/, and forwards it to P02). Confirm in L3.
4. **Bootstrap PR (02 sec. 2).** The PR that introduces `ci/` and the workflow has no base-commit bundle; the
   workflow writes a fixed "P02 verdict not available" summary and fails. Code owners review it manually.

## Repository settings (DEP-2)

5. Branch protection or ruleset on the default branch: required status checks **`review`** and **`gate`**
   (bound to this workflow where the plan allows, A-5 / T-CI-17); require pull-request approval; require review
   from Code Owners; install `ci/deploy/CODEOWNERS.proposed` as `CODEOWNERS` with the real team.
6. Where available (GitHub Team / Enterprise Cloud), require this workflow from a protected ref through an
   organisation ruleset (DEP-4); this is the stronger control against workflow rewriting (T-CI-03).
7. Forks: approval required for all external contributors (strictest option). For private or internal
   repositories, "Send write tokens to workflows from pull requests" and "Send secrets to workflows from pull
   requests" must be **off**.
8. Optional hardening: allow only squash or rebase merges into the default branch. This removes the criss-cross
   merge histories behind R2 V2-01 (the adapter already handles them; see ci/README.md, proposed A-9).
9. No repository or organisation secrets are used by this workflow; no cloud trust policy may trust this
   repository's OIDC subjects (DEP-7, infrastructure-owner attestation).

## Gate mode (DEP-3, A-3, D-CI-02)

The committed configuration uses the **fail-on-risk fallback** (D-CI-02(b)): risk, incomplete analysis,
unreviewed changes and TRUST DEGRADED all turn the `review` job red, overridable only through the
repository's normal bypass procedure. Keep it where required reviewers are unavailable (private repositories
outside GitHub Enterprise).

To use the reviewer-environment gate instead:

10. Create environment `p02-risk-acknowledgement`: required reviewers (a team that excludes PR authors where
   possible), **prevent self-review on**, **administrators may not bypass**, no secrets, deployment branches
   "No restriction". Create `p02-no-ack` with no rules and no secrets. (A referenced environment that does
   not exist is auto-created *without* protection rules, so the gate is fail-closed only while
   `p02-risk-acknowledgement` exists with required reviewers.)
11. Save the REST exports and run the configuration check:
    ```
    gh api repos/OWNER/REPO/environments/p02-risk-acknowledgement > env.json
    gh api repos/OWNER/REPO/environments/p02-risk-acknowledgement/secrets > secrets.json
    python3 -B ci/tools/attest_environment.py env.json --repository OWNER/REPO --secrets-export secrets.json \
        --admin-bypass-off-confirmed-by NAME --reviewer-team-excludes-pr-authors
    ```
    The public REST documentation (checked 2026-10-11) does not document an administrator-bypass field in the
    environment response, so the bypass setting must be confirmed by name unless the export shows
    `can_admins_bypass: false`.
12. Put the printed `gate` block into `ci/p02ci/trusted_config.json`, re-pin the adapter digest
    (`python3 -B ci/tools/pin_digests.py --write-workflow`, keeping the old pin alongside until merged) and merge
    through code-owner review. Repeat at least every 90 days (the adapter falls back automatically when the
    attestation expires), and after any environment change. A canary PR expected to show `gate` pending is the
    alternative live check named in A-3.

## L3 scenarios still to run (separate authorization)

E2E-20, E2E-21, E2E-22(b), E2E-26, E2E-31 (conflicts), E2E-32, E2E-35 and the live parts of E2E-01..05, 08,
11, 15..17, 19, 23, 33, 34, 36..39 — see the E2E acceptance matrix.
