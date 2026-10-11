"""Regression tests for blind adversarial verification round R4 (gci2/verifier/R4_REPORT.md), written before the
fixes. V4-01, V4-02 (Low); V4-04, V4-05, V4-06, V4-08 (Info).
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

from cisupport import PROJECT, WORKFLOW, TmpCase, env_mode_config, make_trusted, write_tree
from test_ci12_adversarial_extra import env_export
from test_ci14_verifier_r2 import g
from test_ci15_verifier_r3 import OTHER, _lint_dir

TOOL = os.path.join(PROJECT, "ci", "tools", "attest_environment.py")
PIN_TOOL = os.path.join(PROJECT, "ci", "tools", "pin_digests.py")


class V401FlowKeys(unittest.TestCase):
    def test_v401_quoted_flow_mapping_keys_refused(self):
        for on in ('on: {"pull_request_target": null}\n', "on: {'workflow_run': {workflows: [ci]}}\n",
                   'on: {"issue_c\\x6fmment": null}\n'):
            with self.subTest(on=on):
                text = OTHER.replace("on:\n  pull_request:\n", on)
                self.assertNotEqual(text, OTHER)
                self.assertTrue(_lint_dir({"z.yml": text}))


class V402SecretsContext(unittest.TestCase):
    def test_v402_any_secrets_context_reference_flagged(self):
        for env_line in ("          T: ${{ toJSON(secrets) }}\n", "          T: ${{ secrets['GITHUB_TOKEN'] }}\n"):
            with self.subTest(env_line=env_line.strip()):
                text = OTHER.replace("      - run: echo ok\n", "      - run: echo ok\n        env:\n" + env_line)
                self.assertTrue(_lint_dir({"z.yml": text}))
        text = OTHER.replace("  other:\n", "  other:\n    secrets: inherit\n")
        self.assertTrue(_lint_dir({"z.yml": text}))
        with open(WORKFLOW, encoding="utf-8") as fh:
            t = fh.read()
        for name in ("${{ toJSON(secrets) }}", "${{ secrets['GITHUB_TOKEN'] }}", "${{ github.event.pull_request.title }}"):
            with self.subTest(name=name):
                bad = re.sub(r"(      - id: adapter\n        name: ).*\n", lambda m: m.group(1) + name + "\n", t, count=1)
                self.assertNotEqual(bad, t)
                self.assertTrue(_lint_dir({"p02-review.yml": bad}))


class V404MergeRefMismatchCode(TmpCase):
    def test_v404_mismatch_has_distinct_code_and_rerun_hint(self):
        repo = self.repo({"README.md": "r\n"}, {"docs/x.md": "y\n"})
        run = self.run_ci(repo, head=repo.base)
        self.assertRow(run, 1)
        self.assertIn("P02CI_MERGE_REF_MISMATCH", run.summary)
        self.assertIn("re-run", run.summary)


class V405PinTool(TmpCase):
    def test_v405_write_workflow_keeps_old_adapter_pin(self):
        root = os.path.join(self.tmp, "copy")
        make_trusted(root)
        os.makedirs(os.path.join(root, ".github", "workflows"))
        shutil.copy(WORKFLOW, os.path.join(root, ".github", "workflows", "p02-review.yml"))
        with open(WORKFLOW, encoding="utf-8") as fh:
            old = re.findall(r"--expect-adapter-digest ([0-9a-f]{64})", fh.read())
        with open(os.path.join(root, "ci", "p02ci", "vocab.py"), "a") as fh:
            fh.write("\n")
        env = {"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"}
        p = subprocess.run([sys.executable, "-B", PIN_TOOL, root, "--write-workflow"], capture_output=True, text=True,
                           env=env, cwd=self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(os.path.join(root, ".github", "workflows", "p02-review.yml"), encoding="utf-8") as fh:
            pins = re.findall(r"--expect-adapter-digest ([0-9a-f]{64})", fh.read())
        self.assertEqual(pins[0], old[0])
        self.assertEqual(len(pins), 2)


class V406LintRobustness(unittest.TestCase):
    def test_v406_non_mapping_jobs_reported_not_crashing(self):
        for text in ("name: z\non:\n  pull_request:\npermissions: {}\njobs: [a, b]\n",
                     "name: z\non:\n  pull_request:\npermissions: {}\njobs: x\n",
                     "- a\n- b\n"):
            with self.subTest(text=text[:30]):
                problems = _lint_dir({"z.yml": text})
                self.assertTrue(problems)


class V408Attestation(TmpCase):
    def test_v408_non_calendar_date_forms_fall_back(self):
        from p02ci import config
        with open(os.path.join(PROJECT, "ci", "p02ci", "trusted_config.json"), encoding="utf-8") as fh:
            base = json.load(fh)
        for day in ("2026-W41-1", "20261011  ", "2026-283"):
            with self.subTest(day=day):
                cfg = env_mode_config(json.loads(json.dumps(base)), day)
                try:
                    mode, _ = config.effective_gate(config.parse_config(cfg), datetime.date(2026, 10, 11))
                except config.ConfigError:
                    continue
                self.assertEqual(mode, "fail-on-risk")

    def _tool(self, env_text, *args):
        path = os.path.join(self.tmp, "env.json")
        with open(path, "w") as fh:
            fh.write(env_text)
        spath = os.path.join(self.tmp, "secrets.json")
        with open(spath, "w") as fh:
            json.dump({"total_count": 0, "secrets": []}, fh)
        return subprocess.run([sys.executable, "-B", TOOL, path, "--secrets-export", spath,
                               "--admin-bypass-off-confirmed-by", "repo-admin", "--reviewer-team-excludes-pr-authors",
                               *args], capture_output=True, text=True, cwd=self.tmp,
                              env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"})

    def test_v408_tool_rejects_duplicate_keys_and_binds_to_repository(self):
        doc = env_export(url="https://api.github.com/repos/acme/demo/environments/p02-risk-acknowledgement")
        text = json.dumps(doc)
        self.assertEqual(self._tool(text, "--repository", "acme/demo").returncode, 0)
        self.assertNotEqual(self._tool(text, "--repository", "acme/other").returncode, 0)
        self.assertNotEqual(self._tool(text).returncode, 0)  # repository binding is required
        dup = text.replace('"prevent_self_review": true', '"prevent_self_review": false, "prevent_self_review": true')
        self.assertNotEqual(dup, text)
        self.assertNotEqual(self._tool(dup, "--repository", "acme/demo").returncode, 0)


if __name__ == "__main__":
    unittest.main()
