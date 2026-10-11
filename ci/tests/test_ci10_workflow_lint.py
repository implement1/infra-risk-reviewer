"""L2 workflow static checks (05 sec. 4 invariants 1-11) and workflow-rewriting threats.

Covers E2E-22 (workflow edited to skip P02 / drop environment / widen permissions), E2E-25 (credential access
attempts), E2E-34 incl. the A-5 variant (a PR-added workflow with an always-green `gate` job; duplicate check
names), E2E-26 offline part (no artifact upload) and E2E-20 offline part (no secrets / no write permissions).
Static linting of a PR's copy is advisory (02 sec. 5); these tests prove the linter detects each violation.
"""
import os
import re
import unittest

from cisupport import PROJECT, WORKFLOW, TmpCase


def load_text():
    with open(WORKFLOW, encoding="utf-8") as fh:
        return fh.read()


class RepoWorkflowTests(unittest.TestCase):
    def test_repository_workflow_passes_template_lint(self):
        import wflint
        problems = wflint.lint_text(load_text(), mode="template")
        self.assertEqual(problems, [])

    def test_strict_lint_flags_only_pending_pins(self):
        import wflint
        problems = wflint.lint_text(load_text(), mode="strict")
        self.assertTrue(problems)
        self.assertTrue(all(p.startswith("inv3:") for p in problems), problems)
        self.assertTrue(all("PIN_REQUIRED" in p for p in problems), problems)

    def test_no_fake_sha_pins(self):
        text = load_text()
        self.assertNotRegex(text, r"@[0-9a-f]{40}\b")  # pins are added at deployment, never invented
        self.assertEqual(len(re.findall(r"uses: actions/(checkout|setup-python)@PIN_REQUIRED_", text)), 3)

    def test_workflow_directory_lint_has_no_duplicate_check_names(self):
        import wflint
        self.assertEqual(wflint.lint_directory(os.path.join(PROJECT, ".github", "workflows"), mode="template"), [])

    def test_bootstrap_guard_present(self):
        self.assertIn("trusted/ci/p02ci/__main__.py", load_text())

    def test_workflow_pins_match_independently_computed_digests(self):
        from cisupport import ACCEPTED_CORE_DIGEST, adapter_digest
        text = load_text()
        core = re.findall(r"--expect-core-digest ([0-9a-f]{64})", text)
        adapter = re.findall(r"--expect-adapter-digest ([0-9a-f]{64})", text)
        self.assertEqual(core, [ACCEPTED_CORE_DIGEST])
        self.assertEqual(adapter, [adapter_digest(PROJECT)])

    def test_repository_workflow_runs_offline_through_the_adapter_command(self):
        # The exact `exec env -i ...` line from the workflow, with GitHub variables substituted, runs the adapter.
        import subprocess
        import tempfile
        from cisupport import Repo
        text = load_text()
        line = [l.strip() for l in text.splitlines() if l.strip().startswith("exec env -i ")][0]
        with tempfile.TemporaryDirectory() as tmp:
            ws = os.path.join(tmp, "ws")
            os.makedirs(ws)
            repo = Repo(ws, {"README.md": "r\n"}, {"docs/x.md": "y\n"})
            os.rename(repo.path, os.path.join(ws, "pr"))
            repo.path = os.path.join(ws, "pr")
            from cisupport import make_trusted
            make_trusted(os.path.join(ws, "trusted"))  # stands in for the sparse base-commit checkout
            rt = os.path.join(tmp, "rt")
            os.makedirs(rt)
            cwd = os.path.join(rt, "p02cwd")
            os.makedirs(cwd)
            out, summ = os.path.join(tmp, "out"), os.path.join(tmp, "summ")
            open(out, "w").close()
            open(summ, "w").close()
            env = {"PATH": os.environ["PATH"], "GITHUB_WORKSPACE": ws, "RUNNER_TEMP": rt, "GITHUB_OUTPUT": out,
                   "GITHUB_STEP_SUMMARY": summ, "P02_BASE_SHA": repo.base, "P02_HEAD_SHA": repo.head,
                   "PY": __import__("sys").executable}
            p = subprocess.run(["bash", "-c", "set -eu\n" + line], env=env, cwd=cwd, capture_output=True, text=True)
            with open(out) as fh:
                self.assertEqual(fh.read(), "ack=not-required\n", p.stdout + p.stderr)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


def mutate(text, old, new, count=1):
    assert old in text, old
    return text.replace(old, new, count)


class MutationTests(unittest.TestCase):
    """Each edit an attacker might make in a PR's copy of the workflow is detected (advisory in the PR itself)."""

    def assertFlags(self, text, inv):
        import wflint
        problems = wflint.lint_text(text, mode="template")
        self.assertTrue(any(p.startswith(inv + ":") for p in problems), (inv, problems))

    def test_inv1_triggers(self):
        t = load_text()
        self.assertFlags(mutate(t, "  pull_request:\n", "  pull_request_target:\n"), "inv1")
        self.assertFlags(mutate(t, "on:\n", "on:\n  workflow_run:\n    workflows: [x]\n"), "inv1")
        self.assertFlags(mutate(t, "on:\n", "on:\n  issue_comment:\n"), "inv1")
        self.assertFlags(mutate(t, "    types: [opened, synchronize, reopened, edited]\n",
                                "    types: [opened, synchronize, reopened, edited]\n    paths: ['p02-demo/**']\n"),
                         "inv1")
        self.assertFlags(mutate(t, "    types: [opened, synchronize, reopened, edited]\n",
                                "    types: [opened]\n"), "inv1")

    def test_inv2_permissions(self):
        t = load_text()
        self.assertFlags(mutate(t, "permissions: {}\n", "permissions: write-all\n"), "inv2")
        self.assertFlags(mutate(t, "      contents: read\n", "      contents: read\n      pull-requests: write\n"), "inv2")
        self.assertFlags(mutate(t, "      contents: read\n", "      contents: write\n"), "inv2")
        self.assertFlags(re.sub(r"(\n  gate:\n(?:.*\n)*?    )permissions: \{\}\n", r"\1permissions: {actions: write}\n",
                                t, count=1), "inv2")

    def test_inv3_pins_and_allowlist(self):
        t = load_text()
        self.assertFlags(re.sub(r"actions/checkout@PIN_REQUIRED_\w+", "actions/checkout@v4", t, count=1), "inv3")
        self.assertFlags(mutate(t, "      - id: adapter\n", "      - uses: someone/action@" + "a" * 40 + "\n"
                                                            "      - id: adapter\n"), "inv3")
        self.assertFlags(re.sub(r"actions/checkout@PIN_REQUIRED_\w+", "actions/checkout@" + "A" * 40, t, count=1), "inv3")

    def test_inv4_persist_credentials(self):
        t = load_text()
        self.assertFlags(mutate(t, "persist-credentials: false", "persist-credentials: true"), "inv4")
        self.assertFlags(mutate(t, "          persist-credentials: false\n", ""), "inv4")

    def test_inv5_expressions_in_run(self):
        t = load_text()
        self.assertFlags(mutate(t, "          set -eu\n", "          set -eu\n          echo \"${{ github.event.pull_request.title }}\"\n"),
                         "inv5")
        self.assertFlags(mutate(t, "          set -eu\n", "          set -eu\n          echo ${{ github.head_ref }}\n"),
                         "inv5")

    def test_inv6_secrets_id_token_cache_self_hosted(self):
        t = load_text()
        self.assertFlags(mutate(t, "      contents: read\n", "      contents: read\n      id-token: write\n"), "inv6")
        self.assertFlags(mutate(t, "          set -eu\n", "          set -eu\n          X=\"$TOKEN\"\n", 1).replace(
            "    steps:\n", "    env:\n      TOKEN: ${{ secrets.MY_TOKEN }}\n    steps:\n", 1), "inv6")
        self.assertFlags(mutate(t, "      - id: adapter\n", "      - uses: actions/cache@" + "a" * 40 + "\n"
                                                            "      - id: adapter\n"), "inv6")
        self.assertFlags(mutate(t, "runs-on: ubuntu-24.04", "runs-on: [self-hosted, linux]"), "inv6")
        self.assertFlags(mutate(t, "          set -eu\n",
                                "          set -eu\n          curl -s http://169.254.169.254/latest/meta-data/\n"),
                         "inv6")
        self.assertFlags(mutate(t, "          set -eu\n",
                                "          set -eu\n          echo \"$ACTIONS_ID_TOKEN_REQUEST_URL\"\n"), "inv6")

    def test_inv7_timeouts(self):
        t = load_text()
        self.assertFlags(mutate(t, "    timeout-minutes: 5\n", ""), "inv7")

    def test_inv8_trusted_bundle_from_base(self):
        t = load_text()
        self.assertFlags(mutate(t, "ref: ${{ github.event.pull_request.base.sha }}",
                                "ref: ${{ github.event.pull_request.head.sha }}"), "inv8")
        self.assertFlags(t.replace("$GITHUB_WORKSPACE/trusted/src", "$GITHUB_WORKSPACE/pr/src"), "inv8")

    def test_inv9_required_jobs_unconditional_and_fail_closed_gate(self):
        t = load_text()
        self.assertFlags(mutate(t, "  gate:\n", "  gate:\n    if: ${{ success() }}\n"), "inv9")
        self.assertFlags(mutate(t, "  review:\n", "  review:\n    if: false\n"), "inv9")
        self.assertFlags(mutate(t, "      - id: adapter\n", "      - id: adapter\n        if: false\n"), "inv9")
        self.assertFlags(mutate(t, "      - id: adapter\n", "      - id: adapter\n        continue-on-error: true\n"),
                         "inv9")
        self.assertFlags(re.sub(r"    environment: .*\n", "", t, count=1), "inv9")
        self.assertFlags(re.sub(r"    environment: .*\n",
                                "    environment: ${{ needs.review.outputs.ack == 'required' && "
                                "'p02-risk-acknowledgement' || 'p02-no-ack' }}\n", t, count=1), "inv9")
        self.assertFlags(mutate(t, "  gate:\n", "  gate_renamed:\n"), "inv9")
        self.assertFlags(mutate(t, "  review:\n", "  review:\n    name: something-else\n"), "inv9")

    def test_inv10_python_flags_and_pythonpath(self):
        t = load_text()
        self.assertFlags(mutate(t, "-P -s -B -m p02ci", "-B -m p02ci"), "inv10")
        self.assertFlags(t.replace("PYTHONPATH=\"$GITHUB_WORKSPACE/trusted/src:$GITHUB_WORKSPACE/trusted/ci\"",
                                   "PYTHONPATH=\"$GITHUB_WORKSPACE/trusted/src:$GITHUB_WORKSPACE/trusted/ci:\""),
                         "inv10")
        self.assertFlags(t.replace("PYTHONPATH=\"$GITHUB_WORKSPACE/trusted/src:$GITHUB_WORKSPACE/trusted/ci\"",
                                   "PYTHONPATH=\"src:ci\""), "inv10")
        self.assertFlags(mutate(t, "exec env -i", "exec env"), "inv10")
        self.assertFlags(mutate(t, "          set -eu\n", "          set -eu\n          python3 -c 'print(1)'\n"),
                         "inv10")

    def test_inv11_working_directory(self):
        t = load_text()
        self.assertFlags(mutate(t, "      - id: adapter\n", "      - id: adapter\n        working-directory: pr\n"),
                         "inv11")
        self.assertFlags(mutate(t, "          set -eu\n", "          set -eu\n          cd pr\n"), "inv11")
        self.assertFlags(mutate(t, "permissions: {}\n", "permissions: {}\ndefaults:\n  run:\n    working-directory: pr\n"),
                         "inv11")

    def test_e2e32_concurrency_cancel_in_progress_required(self):
        t = load_text()
        self.assertFlags(mutate(t, "  cancel-in-progress: true\n", "  cancel-in-progress: false\n"), "inv9")
        self.assertFlags(mutate(t, "  group: p02-review-${{ github.event.pull_request.number }}\n",
                                "  group: shared\n"), "inv9")

    def test_e2e22_skip_p02_by_removing_adapter_step(self):
        t = load_text()
        t2 = re.sub(r"      - id: adapter\n(?:        .*\n|\n)*", "      - run: echo ok\n", t, count=1)
        import wflint
        self.assertTrue(wflint.lint_text(t2, mode="template"))

    def test_e2e26_artifact_upload_flagged_in_mode_a(self):
        t = load_text()
        self.assertFlags(mutate(t, "      - id: adapter\n", "      - uses: actions/upload-artifact@" + "a" * 40 + "\n"
                                                            "      - id: adapter\n"), "inv3")

    def test_yaml_features_outside_subset_rejected(self):
        import wflint
        t = load_text()
        for bad in ("x: &a 1\n", "x: *a\n", "x: !!str 1\n", "\tx: 1\n"):
            with self.subTest(bad=bad):
                with self.assertRaises(wflint.WorkflowError):
                    wflint.load_text(t + bad)

    def test_duplicate_keys_rejected(self):
        import wflint
        t = load_text()
        with self.assertRaises(wflint.WorkflowError):
            wflint.load_text(mutate(t, "permissions: {}\n", "permissions: {}\npermissions: write-all\n"))


class DirectoryTests(TmpCase):
    def _dir(self, extra):
        d = os.path.join(self.tmp, "workflows")
        os.makedirs(d)
        with open(os.path.join(d, "p02-review.yml"), "w") as fh:
            fh.write(load_text())
        for name, text in extra.items():
            with open(os.path.join(d, name), "w") as fh:
                fh.write(text)
        return d

    def test_a5_pr_added_workflow_with_always_green_gate_job_is_flagged(self):
        import wflint
        fake = ("name: helper\non:\n  pull_request:\npermissions: {}\njobs:\n  gate:\n    runs-on: ubuntu-24.04\n"
                "    timeout-minutes: 1\n    steps:\n      - run: echo ok\n")
        problems = wflint.lint_directory(self._dir({"helper.yml": fake}), mode="template")
        self.assertTrue(any(p.startswith("dup:") and "gate" in p for p in problems), problems)

    def test_a5_duplicate_by_job_name_field(self):
        import wflint
        fake = ("name: helper\non:\n  pull_request:\npermissions: {}\njobs:\n  other:\n    name: review\n"
                "    runs-on: ubuntu-24.04\n    timeout-minutes: 1\n    steps:\n      - run: echo ok\n")
        problems = wflint.lint_directory(self._dir({"helper.yaml": fake}), mode="template")
        self.assertTrue(any(p.startswith("dup:") and "review" in p for p in problems), problems)

    def test_other_workflow_with_privileged_trigger_flagged(self):
        import wflint
        fake = ("name: x\non:\n  pull_request_target:\npermissions: {}\njobs:\n  x:\n    runs-on: ubuntu-24.04\n"
                "    timeout-minutes: 1\n    steps:\n      - run: echo ok\n")
        problems = wflint.lint_directory(self._dir({"x.yml": fake}), mode="template")
        self.assertTrue(any(p.startswith("inv1:") for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
