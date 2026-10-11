"""A-2 / A-4: classification precedence, undeclared in-package files, trusted allow-list and package root.

Covers E2E-08 (restated), E2E-19, E2E-37, E2E-38, E2E-31 (offline docs-only part) and A-4.
Precedence: protected tooling -> reviewed -> undeclared-in-package -> allow-list -> other.
"""
import json
import os
import unittest

from cisupport import (BANNER, PROJECT, TRUST_DEGRADED, TmpCase, corpus_files, make_trusted, manifest, package)

PUBLIC_SSH = ('resource "aws_security_group" "evil" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n'
              '    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')


class GlobTests(unittest.TestCase):
    def test_glob_semantics(self):
        from p02ci.config import glob_match
        cases = [
            ("docs/**/*.md", "docs/a.md", True), ("docs/**/*.md", "docs/x/y/a.md", True),
            ("docs/**/*.md", "docs/a.tf", False), ("docs/**/*.md", "docsx/a.md", False),
            ("docs/**/*.md", "x/docs/a.md", False), ("*.md", "README.md", True), ("*.md", "docs/a.md", False),
            (".github/**", ".github/workflows/x.yml", True), (".github/**", ".github", False),
            ("CODEOWNERS", "CODEOWNERS", True), ("CODEOWNERS", "x/CODEOWNERS", False),
            ("FILE_INVENTORY*.sha256", "FILE_INVENTORY_X.sha256", True),
            ("docs/**/*.md", "docs/a.md.tf", False), ("*.md", ".md", False),
        ]
        for pat, path, want in cases:
            with self.subTest(pat=pat, path=path):
                self.assertEqual(glob_match(pat, path), want)


class ConfigTests(TmpCase):
    def _cfg(self):
        with open(os.path.join(PROJECT, "ci", "p02ci", "trusted_config.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_repository_config_loads_and_defaults_to_fail_on_risk(self):
        from p02ci import config
        cfg = config.load_config(os.path.join(PROJECT, "ci", "p02ci", "trusted_config.json"))
        self.assertEqual(cfg.package_root, "p02-demo")
        self.assertEqual(cfg.gate_mode, "fail-on-risk")
        self.assertLessEqual(cfg.max_packages, 10)
        for p in (".github/**", "ci/**", "src/**", "schema/**", "narrate/**", "CODEOWNERS", "docs/CODEOWNERS"):
            self.assertIn(p, cfg.protected)

    def test_a4_allow_list_patterns_must_be_extension_qualified(self):
        from p02ci import config
        for bad in ("docs/**", "*", "**", "docs/*", "**/*", "docs/**/*.*", "docs/**/*.", "*.tf", "*.hcl",
                    "../x.md", "/abs/*.md", "docs//x.md", "docs/**/**/*.md?"):
            with self.subTest(bad=bad):
                cfg = self._cfg()
                cfg["non_infrastructure_allow_list"] = [bad]
                path = os.path.join(self.tmp, "c.json")
                with open(path, "w") as fh:
                    json.dump(cfg, fh)
                with self.assertRaises(config.ConfigError):
                    config.load_config(path)

    def test_mandatory_protected_paths_cannot_be_dropped(self):
        from p02ci import config
        for drop in ("CODEOWNERS", "docs/CODEOWNERS", ".github/**", "ci/**", "src/**", "schema/**", "narrate/**"):
            with self.subTest(drop=drop):
                cfg = self._cfg()
                cfg["protected_tooling"] = [p for p in cfg["protected_tooling"] if p != drop]
                path = os.path.join(self.tmp, "c.json")
                with open(path, "w") as fh:
                    json.dump(cfg, fh)
                with self.assertRaises(config.ConfigError):
                    config.load_config(path)

    def test_unknown_keys_duplicates_and_raised_package_cap_rejected(self):
        from p02ci import config
        path = os.path.join(self.tmp, "c.json")
        for mut in (lambda c: c.update(extra=1), lambda c: c.update(max_packages=11),
                    lambda c: c.update(max_packages=0), lambda c: c.update(package_root="../x"),
                    lambda c: c.update(package_root=""), lambda c: c.update(package_root="ci"),
                    lambda c: c["gate"].update(mode="whatever")):
            cfg = self._cfg()
            mut(cfg)
            with open(path, "w") as fh:
                json.dump(cfg, fh)
            with self.subTest(cfg=sorted(cfg)):
                with self.assertRaises(config.ConfigError):
                    config.load_config(path)
        with open(path, "w") as fh:
            fh.write('{"config_version": "1", "config_version": "1"}')
        with self.assertRaises(config.ConfigError):
            config.load_config(path)

    def test_a4_allow_list_is_read_from_trusted_checkout_not_pr(self):
        # The PR adds its own permissive config and broadens nothing: the trusted copy is the only one read.
        permissive = self._cfg()
        permissive["non_infrastructure_allow_list"] = ["infra/**/*.tf"]
        head = {"ci/p02ci/trusted_config.json": json.dumps(permissive), "infra/x.tf": PUBLIC_SSH}
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertIn(TRUST_DEGRADED, run.summary)
        self.assertEqual(run.ack, "required")

    def test_invalid_trusted_config_is_technical_failure(self):
        trusted = make_trusted(os.path.join(self.tmp, "t"),
                               config_mutator=lambda c: c.update(non_infrastructure_allow_list=["docs/**"]))
        repo = self.repo({"README.md": "r\n"}, {"docs/a.md": "x\n"})
        run = self.run_ci(repo, trusted=trusted)
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_CONFIG_INVALID", run.summary)

    def test_package_root_from_trusted_config(self):
        def mut(c):
            from cisupport import env_mode_config
            env_mode_config(c)
            c["package_root"] = "fixtures"
            return c
        trusted = make_trusted(os.path.join(self.tmp, "t"), config_mutator=mut)
        repo = self.repo({}, package("fixtures/c01", corpus_files("c01-tf-benign-scoped")))
        run = self.run_ci(repo, trusted=trusted)
        self.assertRow(run, 7)
        repo = self.repo({}, package("p02-demo/c01", corpus_files("c01-tf-benign-scoped")))
        run = self.run_ci(repo, trusted=trusted)
        self.assertRow(run, 6)  # p02-demo is not the configured root in this trusted copy


class ClassificationE2E(TmpCase):
    def test_e2e08_restated_benign_package_with_only_declared_files_is_row7_green(self):
        for case in ("c01-tf-benign-scoped", "c06-plan-benign", "c10-k8s-benign"):
            with self.subTest(case=case):
                repo = self.repo({"README.md": "r\n"}, package(f"p02-demo/{case[:3]}", corpus_files(case)))
                run = self.run_ci(repo)  # fallback mode still green for row 7
                self.assertRow(run, 7)
                self.assertGreen(run)
                self.assertEqual(run.ack, "not-required")
                self.assertIn("not a safety approval", run.summary)
                low = run.summary.lower().replace("not a safety approval", "")
                for word in ("safe", "approved", "secure", "all clear", "passed"):
                    self.assertNotIn(word, low)

    def test_e2e08_manifest_only_edit_of_package_with_only_declared_files_is_row7(self):
        files = package("p02-demo/c01", corpus_files("c01-tf-benign-scoped"))
        m = json.loads(files["p02-demo/c01/p02-manifest.json"])
        m["description"] = "edited description"
        repo = self.repo(files, {"p02-demo/c01/p02-manifest.json": json.dumps(m)})
        run = self.run_ci(repo)
        self.assertRow(run, 7)
        self.assertEqual(run.ack, "not-required")

    def test_e2e19_infra_outside_packages_alone(self):
        repo = self.repo({"README.md": "r\n"}, {"infra/main.tf": PUBLIC_SSH})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertGreen(run)
        self.assertEqual(run.ack, "required")
        self.assertIn("not screened for credentials", run.summary)  # A-8

    def test_e2e19_infra_outside_packages_with_benign_package(self):
        head = package("p02-demo/c01", corpus_files("c01-tf-benign-scoped"))
        head["infra/main.tf"] = PUBLIC_SSH
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertEqual(run.ack, "required")
        self.assertIn("no_blocking_findings_detected", run.summary)  # package result still shown

    def test_e2e19_fallback_mode_turns_review_red_with_human_review_required(self):
        repo = self.repo({"README.md": "r\n"}, {"infra/main.tf": PUBLIC_SSH})
        run = self.run_ci(repo)
        self.assertRow(run, 6)
        self.assertRed(run)
        self.assertIn("fail-on-risk", run.summary)

    def test_e2e37_undeclared_added_file_in_package(self):
        head = package("p02-demo/c01", corpus_files("c01-tf-benign-scoped"))
        repo = self.repo(head, {"p02-demo/c01/evil.tf": PUBLIC_SSH})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertIn("`p02-demo/c01/evil.tf`", run.summary)
        self.assertIn("undeclared in package", run.summary)
        self.assertEqual(run.ack, "required")

    def test_e2e37_a2_de_declaration_manifest_only_change_is_row6(self):
        # R3 N-03: remove a risky file from `files` and leave it on disk; only the manifest changes.
        files = package("p02-demo/c01", corpus_files("c01-tf-benign-scoped"))
        files["p02-demo/c01/risky.tf"] = PUBLIC_SSH
        files["p02-demo/c01/p02-manifest.json"] = manifest(["main.tf", "risky.tf"], "c01")
        repo = self.repo(files, {"p02-demo/c01/p02-manifest.json": manifest(["main.tf"], "c01")})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertIn("`p02-demo/c01/risky.tf`", run.summary)
        self.assertEqual(run.ack, "required")
        self.assertNotIn(BANNER[7], run.summary.split("\n", 1)[0])

    def test_e2e37_unchanged_undeclared_file_in_changed_package_is_row6(self):
        files = package("p02-demo/c01", corpus_files("c01-tf-benign-scoped"))
        files["p02-demo/c01/old-undeclared.tf"] = PUBLIC_SSH
        repo = self.repo(files, {"p02-demo/c01/main.tf": files["p02-demo/c01/main.tf"] + b"\n"})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertIn("`p02-demo/c01/old-undeclared.tf`", run.summary)

    def test_e2e37_unknown_types_hcl_tpl_in_package(self):
        head = package("p02-demo/c01", corpus_files("c01-tf-benign-scoped"))
        repo = self.repo(head, {"p02-demo/c01/x.hcl": "a = 1\n", "p02-demo/c01/t.tpl": "x\n",
                                "p02-demo/c01/notes.md": "markdown inside a package\n"})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        for name in ("x.hcl", "t.tpl", "notes.md"):
            self.assertIn(f"`p02-demo/c01/{name}`", run.summary)

    def test_e2e37_nested_packages_innermost_wins(self):
        outer = {"p02-demo/outer/p02-manifest.json": manifest(["main.tf"], "outer"),
                 "p02-demo/outer/main.tf": corpus_files("c01-tf-benign-scoped")["main.tf"]}
        inner = package("p02-demo/outer/inner", corpus_files("c03-tf-public-admin-ingress"))
        base = dict(outer)
        base.update(inner)
        repo = self.repo(base, {"p02-demo/outer/inner/network.tf":
                                corpus_files("c03-tf-public-admin-ingress")["network.tf"] + b"\n"})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 4)  # the inner package was reviewed; its files are not "undeclared" in outer
        self.assertNotIn("undeclared in package", run.summary)

    def test_e2e37_nested_outer_declares_inner_path(self):
        files = {"p02-demo/outer/p02-manifest.json": manifest(["main.tf", "sub/extra.tf"], "outer"),
                 "p02-demo/outer/main.tf": corpus_files("c01-tf-benign-scoped")["main.tf"],
                 "p02-demo/outer/sub/extra.tf": corpus_files("c01-tf-benign-scoped")["main.tf"]}
        repo = self.repo({"README.md": "r\n"}, files)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 7)

    def test_manifest_outside_package_root_is_not_a_package(self):
        repo = self.repo({"README.md": "r\n"}, package("elsewhere/c01", corpus_files("c01-tf-benign-scoped")))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)

    def test_changed_file_directly_under_package_root_not_in_package(self):
        repo = self.repo({"README.md": "r\n"}, {"p02-demo/loose.tf": PUBLIC_SSH})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)

    def test_e2e31_docs_only_is_row8_green(self):
        repo = self.repo({"README.md": "r\n"}, {"docs/guide.md": "x\n", "docs/deep/er/x.md": "y\n",
                                                "README.md": "changed\n"})
        run = self.run_ci(repo)
        self.assertRow(run, 8)
        self.assertGreen(run)
        self.assertEqual(run.ack, "not-required")

    def test_empty_diff_is_row8(self):
        repo = self.repo({"README.md": "r\n"}, {})
        run = self.run_ci(repo)
        self.assertRow(run, 8)
        self.assertGreen(run)

    def test_e2e38_tooling_only_pr_is_trust_degraded_never_plain_green(self):
        for path in ("ci/p02ci/render.py", "src/p02review/cli.py", ".github/workflows/p02-review.yml",
                     "CODEOWNERS", "docs/CODEOWNERS", ".github/CODEOWNERS", "schema/x.json",
                     "narrate/p02narrate/cli.py", "FILE_INVENTORY_PHASE3B1_R1.sha256"):
            with self.subTest(path=path):
                repo = self.repo({"README.md": "r\n"}, {path: "# changed\n"})
                run = self.run_ci(repo, trusted=self.env_trusted)
                self.assertRow(run, 8)
                lines = run.summary.split("\n")
                self.assertIn(TRUST_DEGRADED, lines[1])  # directly under the banner
                self.assertEqual(run.ack, "required")
                self.assertGreen(run)  # environment mode: gate pending

    def test_e2e38_tooling_only_pr_fallback_mode_is_red(self):
        repo = self.repo({"README.md": "r\n"}, {"ci/p02ci/app.py": "# changed\n"})
        run = self.run_ci(repo)
        self.assertRow(run, 8)
        self.assertIn(TRUST_DEGRADED, run.summary)
        self.assertRed(run)

    def test_tooling_deletion_and_rename_degrade_trust(self):
        repo = self.repo({"README.md": "r\n", "CODEOWNERS": "* @o\n"}, renames=[("CODEOWNERS", "docs/owners.md")])
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertIn(TRUST_DEGRADED, run.summary)
        self.assertEqual(run.ack, "required")

    def test_precedence_protected_beats_package_and_allow_list(self):
        from p02ci import classify
        self.assertEqual(classify.PRECEDENCE, ("protected", "reviewed", "undeclared_in_package", "allow_listed",
                                               "other"))

    def test_too_many_packages_is_technical_failure(self):
        head = {}
        for i in range(11):
            head.update(package(f"p02-demo/p{i:02d}", corpus_files("c01-tf-benign-scoped")))
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_TOO_MANY_PACKAGES", run.summary)

    def test_ten_packages_ok(self):
        head = {}
        for i in range(10):
            head.update(package(f"p02-demo/p{i:02d}", corpus_files("c01-tf-benign-scoped")))
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 7)
        self.assertGreen(run)


if __name__ == "__main__":
    unittest.main()
