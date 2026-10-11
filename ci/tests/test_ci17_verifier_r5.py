"""Regression tests for targeted verification round R5 (gci2/verifier/R5_REPORT.md), written before the fixes.
V5-01 (Low); V5-02, V5-03, V5-04 (Info).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

from cisupport import PROJECT, WORKFLOW, TmpCase, make_trusted
from test_ci12_adversarial_extra import env_export
from test_ci15_verifier_r3 import OTHER, _lint_dir

TOOL = os.path.join(PROJECT, "ci", "tools", "attest_environment.py")
PIN_TOOL = os.path.join(PROJECT, "ci", "tools", "pin_digests.py")
ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1"}


class V501SecretsCase(unittest.TestCase):
    def test_v501_case_variants_flagged(self):
        for line in ("          T: ${{ SECRETS.GITHUB_TOKEN }}\n", "          T: ${{ toJSON(Secrets) }}\n",
                     "          T: ${{ github.ID-TOKEN }}\n"):
            with self.subTest(line=line.strip()):
                text = OTHER.replace("      - run: echo ok\n", "      - run: echo ok\n        env:\n" + line)
                self.assertTrue(_lint_dir({"z.yml": text}))
        self.assertTrue(_lint_dir({"z.yml": "run-name: ${{ SECRETS.X }}\n" + OTHER}))


class V502PinTool(TmpCase):
    def _copy(self):
        root = os.path.join(self.tmp, "copy")
        make_trusted(root)
        os.makedirs(os.path.join(root, ".github", "workflows"))
        shutil.copy(WORKFLOW, os.path.join(root, ".github", "workflows", "p02-review.yml"))
        return root, os.path.join(root, ".github", "workflows", "p02-review.yml")

    def _run(self, root):
        return subprocess.run([sys.executable, "-B", PIN_TOOL, root, "--write-workflow"], capture_output=True,
                              text=True, env=ENV, cwd=self.tmp)

    def test_v502_only_the_adapter_command_line_is_rewritten(self):
        root, wf = self._copy()
        with open(wf, encoding="utf-8") as fh:
            text = fh.read()
        text = text.replace("jobs:\n", "# old: --expect-adapter-digest " + "a" * 64 + "\njobs:\n", 1)
        with open(wf, "w", encoding="utf-8") as fh:
            fh.write(text)
        with open(os.path.join(root, "ci", "p02ci", "vocab.py"), "a") as fh:
            fh.write("\n")
        p = self._run(root)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(wf, encoding="utf-8") as fh:
            new = fh.read()
        line = [l for l in new.splitlines() if l.strip().startswith("exec env -i ")][0]
        self.assertEqual(len(re.findall(r"--expect-adapter-digest [0-9a-f]{64}", line)), 2)
        self.assertIn("# old: --expect-adapter-digest " + "a" * 64 + "\n", new)  # comment untouched

    def test_v502_missing_command_line_or_pin_is_an_error(self):
        root, wf = self._copy()
        with open(wf, encoding="utf-8") as fh:
            text = fh.read()
        with open(wf, "w", encoding="utf-8") as fh:
            fh.write(re.sub(r" --expect-adapter-digest [0-9a-f]{64}", "", text))
        self.assertNotEqual(self._run(root).returncode, 0)


class V503AttestationBinding(TmpCase):
    def _tool(self, env_doc, secrets_doc, raw_env=None):
        path = os.path.join(self.tmp, "env.json")
        with open(path, "w") as fh:
            fh.write(raw_env if raw_env is not None else json.dumps(env_doc))
        spath = os.path.join(self.tmp, "secrets.json")
        with open(spath, "w") as fh:
            fh.write(json.dumps(secrets_doc))
        return subprocess.run([sys.executable, "-B", TOOL, path, "--repository", "acme/demo", "--secrets-export",
                               spath, "--admin-bypass-off-confirmed-by", "repo-admin",
                               "--reviewer-team-excludes-pr-authors"], capture_output=True, text=True, cwd=self.tmp,
                              env=ENV)

    def test_v503_crafted_exports_refused(self):
        ok = {"total_count": 0, "secrets": []}
        good = env_export()
        self.assertEqual(self._tool(good, ok).returncode, 0)
        for url in ("https://evil.example/x/repos/acme/demo/environments/p02-risk-acknowledgement",
                    "https://api.github.com/repos/evil/x/repos/acme/demo/environments/p02-risk-acknowledgement"):
            with self.subTest(url=url):
                self.assertNotEqual(self._tool(env_export(url=url), ok).returncode, 0)
        self.assertNotEqual(self._tool(env_export(html_url="https://github.com/evil/x/deployments"), ok).returncode, 0)
        no_policy = env_export()
        del no_policy["deployment_branch_policy"]
        self.assertNotEqual(self._tool(no_policy, ok).returncode, 0)
        for bad in ({"total_count": False, "secrets": []}, {"total_count": 0.0, "secrets": {}}):
            with self.subTest(bad=bad):
                self.assertNotEqual(self._tool(good, bad).returncode, 0)
        raw = json.dumps(good).replace('"id": 1', '"id": NaN')
        self.assertNotEqual(self._tool(None, ok, raw_env=raw).returncode, 0)


class V504MismatchText(TmpCase):
    def test_v504_mismatch_text_points_at_workflow_changes(self):
        repo = self.repo({"README.md": "r\n"}, {"docs/x.md": "y\n"})
        run = self.run_ci(repo, head=repo.base)
        self.assertIn("P02CI_MERGE_REF_MISMATCH", run.summary)
        self.assertIn(".github/", run.summary)


if __name__ == "__main__":
    unittest.main()
