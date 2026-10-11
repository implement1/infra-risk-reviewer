"""Additional focused adversarial cases (written after the first green run; G-CI-2 sec. 7) and the A-3 environment
configuration check tool (offline: it reads a saved REST export, it never calls GitHub).
"""
import json
import os
import subprocess
import sys
import unittest

from cisupport import (BANNER, PROJECT, TmpCase, corpus_files, git, manifest, package)

TOOL = os.path.join(PROJECT, "ci", "tools", "attest_environment.py")
PUBLIC_SSH = ('resource "aws_security_group" "e" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n'
              '    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')


class HostilePackageE2E(TmpCase):
    def test_hostile_package_directory_name_is_not_a_package_and_not_echoed(self):
        files = package("p02-demo/<img src=x>", corpus_files("c01-tf-benign-scoped"))
        repo = self.repo({"README.md": "r\n"}, files)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertNotIn("<img", run.all_text())

    def test_package_path_with_banned_word_is_withheld_in_overview(self):
        repo = self.repo({"README.md": "r\n"}, package("p02-demo/safe-pkg", corpus_files("c03-tf-public-admin-ingress")))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 4)
        self.assertIn("`[path withheld]`", run.summary)
        self.assertNotIn("safe-pkg", run.summary)

    def test_symlinked_package_directory_is_not_followed(self):
        outside = package("elsewhere/pkg", corpus_files("c01-tf-benign-scoped"))
        outside["p02-demo/link"] = ("symlink", "../elsewhere/pkg")
        repo = self.repo({"README.md": "r\n"}, outside)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertNotIn(BANNER[7], run.summary.split("\n", 1)[0])

    def test_gitlink_submodule_added_inside_package_is_unreviewed(self):
        files = package("p02-demo/c01", corpus_files("c01-tf-benign-scoped"))
        repo = self.repo(files, {"p02-demo/c01/main.tf": files["p02-demo/c01/main.tf"] + b"\n"},
                         gitlinks={"p02-demo/c01/vendored": None})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertIn("`p02-demo/c01/vendored`", run.summary)

    def test_many_changed_files_outside_packages_stay_bounded(self):
        head = {f"infra/m{i:04d}.tf": "locals {}\n" for i in range(1500)}
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertIn("Count: 1500", run.summary)
        self.assertLessEqual(len(run.summary.encode()), 64 * 1024)
        self.assertIn("further files not shown (count is complete)", run.summary)

    def test_manifest_cannot_declare_files_outside_its_package(self):
        files = {"p02-demo/pkg/p02-manifest.json": manifest(["../other/x.tf"], "pkg"),
                 "p02-demo/other/x.tf": PUBLIC_SSH}
        repo = self.repo({"README.md": "r\n"}, files)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertIn("PATH_TRAVERSAL", run.summary)

    def test_pr_cannot_grant_itself_environment_mode(self):
        # A PR adding an attestation to its own copy of the trusted config changes nothing: the base copy rules.
        with open(os.path.join(PROJECT, "ci", "p02ci", "trusted_config.json"), encoding="utf-8") as fh:
            cfg = json.load(fh)
        from cisupport import env_mode_config
        env_mode_config(cfg)
        head = package("p02-demo/c03", corpus_files("c03-tf-public-admin-ingress"))
        head["ci/p02ci/trusted_config.json"] = json.dumps(cfg)
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo)  # repository (base) config: fail-on-risk
        self.assertRed(run)
        self.assertIn("fail-on-risk", run.summary)


class ContradictoryOutputTests(unittest.TestCase):
    def test_exit_code_and_status_contradictions_are_technical_failures(self):
        from p02ci import validate
        rejected = {"schema_version": "p02.run-result.v2", "run_id": "run-" + "a" * 24}
        for code, reasons in ((4, ["INPUT_REJECTED"]), (3, ["INPUT_REJECTED", "SUSPECTED_SECRET_BLOCKED"])):
            body = dict(rejected, status="rejected", policy={"decision": "inconclusive", "reasons": reasons})
            raw = json.dumps(body).encode()
            a = validate.assess(validate.ProcResult(code, raw, {f"{body['run_id']}.json": raw}), None, ["a.tf"], "x")
            self.assertEqual(a.row, 1)


def env_export(**over):
    doc = {"id": 1, "name": "p02-risk-acknowledgement", "deployment_branch_policy": None,
           "url": "https://api.github.com/repos/acme/demo/environments/p02-risk-acknowledgement",
           "protection_rules": [{"id": 2, "type": "required_reviewers", "prevent_self_review": True,
                                 "reviewers": [{"type": "Team", "reviewer": {"id": 9, "slug": "p02-reviewers"}}]}]}
    doc.update(over)
    return doc


class AttestationToolTests(TmpCase):
    def _run(self, export, *args, secrets=None):
        path = os.path.join(self.tmp, "env.json")
        with open(path, "w") as fh:
            json.dump(export, fh)
        cmd = [sys.executable, "-B", TOOL, path, "--repository", "acme/demo", *args]
        if secrets is not None:
            spath = os.path.join(self.tmp, "secrets.json")
            with open(spath, "w") as fh:
                json.dump(secrets, fh)
            cmd += ["--secrets-export", spath]
        return subprocess.run(cmd, capture_output=True, text=True, cwd=self.tmp,
                              env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"})

    def test_complete_export_produces_attestation(self):
        p = self._run(env_export(), "--admin-bypass-off-confirmed-by", "repo-admin",
                      "--reviewer-team-excludes-pr-authors", secrets={"total_count": 0, "secrets": []})
        self.assertEqual(p.returncode, 0, p.stderr)
        att = json.loads(p.stdout)["environment_attestation"]
        for k in ("required_reviewers", "prevent_self_review", "admin_bypass_disabled",
                  "reviewer_team_excludes_pr_authors", "no_environment_secrets"):
            self.assertIs(att[k], True)
        self.assertEqual(att["environment"], "p02-risk-acknowledgement")
        self.assertEqual(att["method"], "admin-api-read")

    def test_missing_requirements_fail(self):
        cases = [
            env_export(protection_rules=[]),
            env_export(protection_rules=[{"type": "required_reviewers", "prevent_self_review": False,
                                          "reviewers": [{"type": "User", "reviewer": {"id": 1}}]}]),
            env_export(protection_rules=[{"type": "required_reviewers", "prevent_self_review": True,
                                          "reviewers": []}]),
            env_export(name="p02-no-ack"),
            env_export(deployment_branch_policy={"protected_branches": True, "custom_branch_policies": False}),
            env_export(can_admins_bypass=True),
        ]
        for doc in cases:
            with self.subTest(doc=json.dumps(doc)[:80]):
                p = self._run(doc, "--admin-bypass-off-confirmed-by", "repo-admin",
                              "--reviewer-team-excludes-pr-authors", secrets={"total_count": 0, "secrets": []})
                self.assertNotEqual(p.returncode, 0)

    def test_admin_bypass_and_secrets_need_explicit_evidence(self):
        p = self._run(env_export(), "--reviewer-team-excludes-pr-authors", secrets={"total_count": 0, "secrets": []})
        self.assertNotEqual(p.returncode, 0)  # bypass not in the REST export: needs explicit confirmation
        p = self._run(env_export(), "--admin-bypass-off-confirmed-by", "repo-admin",
                      "--reviewer-team-excludes-pr-authors")
        self.assertNotEqual(p.returncode, 0)  # no secrets export
        p = self._run(env_export(), "--admin-bypass-off-confirmed-by", "repo-admin",
                      "--reviewer-team-excludes-pr-authors", secrets={"total_count": 1, "secrets": [{"name": "X"}]})
        self.assertNotEqual(p.returncode, 0)
        p = self._run(env_export(can_admins_bypass=False), "--reviewer-team-excludes-pr-authors",
                      secrets={"total_count": 0, "secrets": []})
        self.assertEqual(p.returncode, 0, p.stderr)  # an explicit false in the export suffices

    def test_attestation_from_tool_is_accepted_by_adapter_config(self):
        p = self._run(env_export(), "--admin-bypass-off-confirmed-by", "repo-admin",
                      "--reviewer-team-excludes-pr-authors", secrets={"total_count": 0, "secrets": []})
        import datetime
        from p02ci import config
        with open(os.path.join(PROJECT, "ci", "p02ci", "trusted_config.json"), encoding="utf-8") as fh:
            cfg = json.load(fh)
        cfg["gate"] = json.loads(p.stdout)
        mode, note = config.effective_gate(config.parse_config(cfg), datetime.date.today())
        self.assertEqual((mode, note), ("environment", None))


if __name__ == "__main__":
    unittest.main()
