# P02 CI adapter — GitHub Actions, Mode A (G-CI-2)

Status: **implemented and verified offline; submitted for G-CI-3 independent acceptance. Not deployed.**
Specification: planning documents 00–07 and the G-CI-1 verification addendum (amendments A-1 to A-8, which
take precedence).

## What it does

```
synthetic PR changes -> changed-file classification -> P02 review -> P02 explain -> integrity checks
  -> sanitized job summary -> `ack` output -> risk-acknowledgement gate
```

* Mode A only: inputs are committed **synthetic** fixture packages under `p02-demo/` (each a directory with a
  `p02-manifest.json`, `origin: "fixture"`, `provenance.synthetic: true`). No Terraform, Helm, cloud command,
  credential, model or PR-provided script is ever executed.
* The accepted core (`src/p02review`) and narrative harness are unchanged and are not copied: the adapter runs
  the core CLI as a subprocess and imports a few public functions read-only (manifest validation, display
  functions, credential screens, contract validators). The narrative harness is not used.

## Layout

| Path | Role |
|---|---|
| `p02ci/bootstrap.py` | start-up assertions (detection only, A-8), digest checks of the core and of the adapter *before* importing either, then lazy import of the pipeline |
| `p02ci/config.py`, `p02ci/trusted_config.json` | trusted configuration (A-4): package root, extension-qualified non-infrastructure allow-list, protected tooling paths, gate mode and reviewer-environment attestation (A-3) |
| `p02ci/gitdiff.py` | A-1 change enumeration (`--no-renames --no-ext-diff --no-textconv --name-status -z`, bytes), united with the effective change of the checked-out test-merge commit (proposed A-9, below) |
| `p02ci/classify.py` | A-2 classification and package discovery, undeclared-in-package detection |
| `p02ci/stage.py` | manifest validation with the core's own functions, A-6 provenance requirement, O_NOFOLLOW bounded staging, adapter refusals |
| `p02ci/runner.py` | isolated `python3 -P -s -B -m p02review` subprocesses |
| `p02ci/validate.py` | result integrity (04 §7): exit mapping, run_id, contract validators, closed vocabularies, evidence relationships, independent rubric recomputation, explain cross-checks |
| `p02ci/render.py`, `p02ci/vocab.py` | job-summary renderer and fixed text (04; A-8 escaping and budgets), self-check, constant fallback |
| `p02ci/outcome.py`, `p02ci/app.py`, `p02ci/model.py` | banner precedence, `ack`, exit codes; pipeline; data model |
| `tests/` | L1 adapter tests, offline E2E equivalents, L2 workflow linter (`wflint.py`) |
| `tools/cirun.py` | test runner that logs to `evidence/cicd/` and never overwrites a log |
| `tools/pin_digests.py` | prints the core and adapter digests; `--write-workflow` updates the workflow pin |
| `tools/attest_environment.py` | A-3 configuration check from a saved REST export (offline) |
| `deploy/` | proposed CODEOWNERS and the repository-settings checklist (nothing is configured by this change) |
| `../.github/workflows/p02-review.yml` | the `review` and `gate` jobs |

The adapter digest covers every file under `ci/p02ci/`, **including `trusted_config.json`**. Any change there
(for example renewing the reviewer-environment attestation) needs a new pin in the workflow; keep the old pin
alongside the new one until the change has merged, because a PR is judged by its base-commit bundle.

## Outcomes

| Row | Banner | `review` job | `ack` |
|---|---|---|---|
| 1 | TECHNICAL FAILURE -- no assessment produced | red (exit 30) | `required` |
| 2 | BLOCKED -- suspected credential ... rotate the credential | red (exit 20) | `required` |
| 3 | INPUT REJECTED -- no assessment produced (incl. `P02CI_*` refusals) | red (exit 20) | `required` |
| 4 | BLOCKING REVIEW REQUIRED | environment mode: green; fallback: red (exit 10) | `required` |
| 5 | ANALYSIS INCOMPLETE | as row 4 | `required` |
| 6 | FILES CHANGED BUT NOT REVIEWED | as row 4 | `required` |
| 7 | NO BLOCKING FINDINGS BY BASELINE RULES -- not a safety approval | green | `not-required` |
| 8 | NO INFRASTRUCTURE CHANGES DETECTED | green | `not-required` |

The TRUST DEGRADED notice (protected tooling changed) never replaces a banner and always forces
`ack=required`. A green result is never a safety approval and never replaces normal PR review.

The adapter writes `ack` as exactly `required` or `not-required` (lower case, one line, written only after the
summary was written in full). GitHub expression comparison is case-insensitive (A-8), so the gate expression
would also select `p02-no-ack` for `NOT-REQUIRED`; the adapter never emits that value, and every other value
(missing, empty, `true`, garbage, padded) selects `p02-risk-acknowledgement` (E2E-36).

**Gate mode.** The repository default is the documented fail-on-risk fallback D-CI-02(b): whenever human
acknowledgement would be required, the `review` job fails. The reviewer-environment gate is used only when the
trusted configuration carries a complete attestation, no older than `attestation_max_age_days` (≤ 180,
default 90), produced from a saved REST export by `tools/attest_environment.py` (A-3). The workflow's
environment expression stays fail-closed in both modes.

## Behaviour worth knowing

* **Change enumeration (proposed amendment A-9).** The A-1 command `git diff ... <base>...<head>` is run exactly
  as specified, and its result is united with `git diff <merge^1> <merge>` (same flags) for the checked-out
  test-merge commit (`refs/pull/N/merge`). The checkout must be a two-parent merge whose second parent equals
  the event head SHA and whose first parent descends from the event base SHA; anything else (single-parent or
  octopus checkout, mismatch) is a technical failure (`P02CI_MERGE_REF_MISMATCH`, with a fixed request to re-run
  once GitHub has updated the merge ref). The union can only add paths. It
  closes R2 V2-01 (criss-cross histories, where the three-dot diff uses one of several merge bases and can omit
  a base-side change that the merge silently reverts) and R2 V2-02 (swapped event SHAs). A diff against the
  event base SHA itself is deliberately not used: it would attribute other PRs' base-branch changes to this
  one when the event base lags the merge (R3 V3-01). More than 100,000 unique changed paths is
  `P02CI_TOO_MANY_CHANGES`. Live GitHub merge-ref parentage is to be confirmed in L3.
  Known fail-closed residual (R4 V4-03): because the A-1 three-dot diff is kept literally, a PR that merged the
  base branch ("update branch") while the event base SHA lags can have base-branch changes attributed to it
  (extra rows, never fewer). Replacing `<base>` with `<merge^1>` in the three-dot diff would remove this; it is
  offered as an option in the G-CI-3 report rather than applied, because A-1 prescribes the form.
* **Nested packages.** Every package nested under a changed package is assessed as well (R1 V1-01). A broken
  nested manifest, or more than 10 packages in total, therefore keeps every PR that touches the outer package
  red (row 3 or row 1) until the base is repaired. This is deliberate (fail closed).
* **Allow-list entries must be regular files.** A symlink, gitlink or other entry with a documentation name is
  "changed but not reviewed" (R2 V2-06).
* **Credential-shaped file names** are never displayed; row 6 then carries a fixed rotation note (R2 V2-08).

## Workflow lint (L2)

`python3 -B ci/tests/wflint.py` lints every file in `.github/workflows/` (strict mode; `--template` accepts the
pending `PIN_REQUIRED_*` pins). `p02-review.yml` must have exactly the specified shape. Every *other* workflow
must be printable ASCII with LF line ends, use no YAML escapes or quoted flow keys, declare explicit read-only
`permissions:` (workflow and job level), reference no `secrets` context or `id-token`, use no
`pull_request_target` / `workflow_run` / `issue_comment` trigger, and define no job ID or name equal to (or
computed into) `review` or `gate`. Linting a PR's own copy is advisory (02 sec. 5): code-owner review of
`.github/` or a required workflow is the control. The D-CI-08 workflow that would run the accepted suites on
pin changes and nightly is **not** included (it is not part of the G-CI-2 scope and running test code from a
PR would execute PR-provided scripts); the linter has no mode for it yet.

## Running the tests

```
python3 -B ci/tools/cirun.py LOGNAME "note"                  # normal
CI_UNSHARE=1 python3 -B ci/tools/cirun.py LOGNAME "note"     # inside unshare -n (no network)
CI_PY_FLAGS=-O python3 -B ci/tools/cirun.py LOGNAME "note"   # optimized
```

All tests are offline and synthetic. Credential shapes are assembled at runtime and never printed.

## Deployment prerequisites (not done here)

See `deploy/REPOSITORY_SETTINGS_CHECKLIST.md`. In short: pin `actions/checkout` and `actions/setup-python` to
verified full commit SHAs and set the exact Python 3.13 patch (replace every `PIN_REQUIRED_*`); run the strict
lint; configure branch protection, CODEOWNERS and (if used) the reviewer environment; run the accepted core
suite on the runner image; and obtain authorization for the L3 sandbox scenarios.
