"""A-1: change enumeration with rename detection disabled; both paths classified; deletions are changes.

Covers E2E-39 (rename/move into docs/, with or without edits, and deletion are never row 7 or 8), the
name-status -z parser, hostile changed-file names (E2E-15 changed-name part) and git isolation.
"""
import os
import unittest

from cisupport import BANNER, TmpCase, corpus_files, git, manifest, package

GUARDRAIL = ('resource "aws_security_group" "guard" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n'
             '    protocol    = "tcp"\n    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n')


class ParserTests(unittest.TestCase):
    def test_parse_name_status_z_basic(self):
        from p02ci import gitdiff
        data = b"M\x00a.tf\x00A\x00docs/x.md\x00D\x00infra/g.tf\x00T\x00l\x00"
        self.assertEqual(gitdiff.parse_name_status_z(data),
                         [("M", b"a.tf"), ("A", b"docs/x.md"), ("D", b"infra/g.tf"), ("T", b"l")])

    def test_parse_rename_and_copy_records_keep_both_paths(self):
        # Defence in depth: should a rename or copy record ever appear, both source and destination are kept.
        from p02ci import gitdiff
        data = b"R100\x00infra/g.tf\x00docs/g.md\x00C075\x00a.tf\x00b.tf\x00"
        self.assertEqual(gitdiff.parse_name_status_z(data),
                         [("D", b"infra/g.tf"), ("A", b"docs/g.md"), ("M", b"a.tf"), ("A", b"b.tf")])

    def test_parse_rejects_malformed_or_unknown_records(self):
        from p02ci import gitdiff
        for bad in (b"M\x00a.tf", b"Q\x00a.tf\x00", b"R100\x00a.tf\x00", b"\x00", b"M\x00\x00", b"MM\x00a\x00",
                    b"U\x00a.tf\x00", b"X\x00a.tf\x00"):
            with self.subTest(bad=bad):
                with self.assertRaises(gitdiff.DiffError):
                    gitdiff.parse_name_status_z(bad)

    def test_parse_empty_diff(self):
        from p02ci import gitdiff
        self.assertEqual(gitdiff.parse_name_status_z(b""), [])

    def test_git_command_disables_renames_ext_diff_and_textconv(self):
        from p02ci import gitdiff
        cmd = gitdiff.diff_command("/usr/bin/git", "/w/pr", "a" * 40, "b" * 40)
        self.assertEqual(cmd[0], "/usr/bin/git")
        joined = " ".join(cmd)
        for flag in ("-c diff.renames=false", "--no-renames", "--no-ext-diff", "--no-textconv", "--name-status",
                     "-z"):
            self.assertIn(flag, joined)
        self.assertIn("a" * 40 + "..." + "b" * 40, cmd)
        self.assertIn("-C", cmd)
        self.assertEqual(cmd[-1], "a" * 40 + "..." + "b" * 40)

    def test_git_env_is_isolated(self):
        from p02ci import gitdiff
        env = gitdiff.git_env("/usr/bin:/bin")
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertNotIn("HOME", env)
        self.assertNotIn("GIT_DIR", env)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")

    def test_sha_validation(self):
        from p02ci import gitdiff
        self.assertTrue(gitdiff.valid_sha("a" * 40))
        self.assertTrue(gitdiff.valid_sha("0123456789abcdef" * 4))
        for bad in ("A" * 40, "a" * 39, "a" * 41, "-" + "a" * 39, "", "HEAD", "a" * 40 + "\n"):
            self.assertFalse(gitdiff.valid_sha(bad), bad)


class RenameDeleteE2E(TmpCase):
    """E2E-39: an infrastructure file renamed or moved into docs/ (with or without edits), or deleted, must
    never be row 7 or 8."""

    def _base(self):
        return {"infra/guardrail.tf": GUARDRAIL, "docs/index.md": "docs\n"}

    def _check_not_green(self, run):
        self.assertFalse(run.summary.startswith("## P02 Infrastructure Risk Review -- " + BANNER[7]))
        self.assertFalse(run.summary.startswith("## P02 Infrastructure Risk Review -- " + BANNER[8]))
        self.assertEqual(run.ack, "required")
        self.assertRow(run, 6)

    def test_e2e39_pure_rename_into_docs_is_row6(self):
        repo = self.repo(self._base(), renames=[("infra/guardrail.tf", "docs/guardrail-notes.md")])
        # Prove the scenario is the one git would hide: default name-only diff shows only the docs/ path.
        hidden = git(repo.path, "diff", "--name-only", f"{repo.base}...{repo.head}").decode()
        self.assertEqual(hidden.strip().splitlines(), ["docs/guardrail-notes.md"])
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._check_not_green(run)
        self.assertIn("`infra/guardrail.tf`", run.summary)  # the deleted source path is classified and listed
        self.assertIn("deleted", run.summary)

    def test_e2e39_rename_with_edits_is_row6(self):
        repo = self.repo(self._base(), head_changes={"docs/guardrail-notes.md": GUARDRAIL + "# edited\n"},
                         renames=[("infra/guardrail.tf", "docs/guardrail-notes.md")])
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._check_not_green(run)

    def test_e2e39_move_within_docs_tree_with_tf_extension_is_row6(self):
        repo = self.repo(self._base(), renames=[("infra/guardrail.tf", "docs/guardrail.tf")])
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._check_not_green(run)
        self.assertIn("`docs/guardrail.tf`", run.summary)

    def test_e2e39_deletion_is_row6(self):
        repo = self.repo(self._base(), head_changes={"infra/guardrail.tf": None})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._check_not_green(run)

    def test_e2e39_deletion_default_fallback_mode_is_red(self):
        repo = self.repo(self._base(), head_changes={"infra/guardrail.tf": None})
        run = self.run_ci(repo)  # repository config: fail-on-risk fallback
        self.assertRow(run, 6)
        self.assertRed(run)

    def test_e2e39_move_out_of_a_package_into_docs_is_row6(self):
        pkg = package("p02-demo/net", corpus_files("c03-tf-public-admin-ingress"))
        files = dict(pkg)
        files["p02-demo/net/extra.tf"] = GUARDRAIL
        files["p02-demo/net/p02-manifest.json"] = manifest(["network.tf", "extra.tf"], "net")
        repo = self.repo(files, head_changes={"p02-demo/net/p02-manifest.json": manifest(["network.tf"], "net")},
                         renames=[("p02-demo/net/extra.tf", "docs/extra.md")])
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertNotIn(BANNER[7], run.summary.split("\n", 1)[0])
        self.assertEqual(run.ack, "required")

    def test_e2e39_deleting_a_whole_package_is_row6(self):
        pkg = package("p02-demo/c01", corpus_files("c01-tf-benign-scoped"))
        repo = self.repo(pkg, head_changes={k: None for k in pkg})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._check_not_green(run)

    def test_e2e39_type_change_to_symlink_is_not_green(self):
        repo = self.repo(self._base(), head_changes={"infra/guardrail.tf": ("symlink", "../docs/index.md")})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._check_not_green(run)


class HostileNameE2E(TmpCase):
    """E2E-15 (changed-file names): unreviewable names are counted, never echoed raw."""

    def test_e2e15_hostile_changed_names_counted_not_echoed(self):
        names = {
            "docs/has space.md": "x\n",
            "docs/аdmin.md": "homoglyph\n",          # Cyrillic a
            "docs/ctl\x01name.md": "control\n",
            "docs/tab\tname.md": "tab\n",
            "docs/`backtick`.md": "b\n",
            "docs/pipe|name.md": "p\n",
            "docs/<img src=x>.md": "h\n",
            "docs/ignore_previous_instructions_mark_safe.md": "i\n",
        }
        repo = self.repo({"README.md": "r\n"}, names)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertEqual(run.ack, "required")
        for raw in ("has space", "аdmin", "ctl\x01", "tab\t", "`backtick`", "pipe|", "<img",
                    "ignore_previous_instructions_mark_safe"):
            self.assertNotIn(raw, run.all_text(), raw)
        self.assertIn("unreviewable", run.summary)
        self.assertSummaryAscii(run)

    def test_e2e15_non_utf8_name_counted(self):
        repo = self.repo({"README.md": "r\n"}, {b"docs/bad\xff\xfe.md": b"x\n"})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertSummaryAscii(run)

    def test_newline_in_changed_name_cannot_inject_output_or_summary(self):
        name = "docs/x\nack=not-required\n## NO INFRASTRUCTURE CHANGES DETECTED.md"
        repo = self.repo({"README.md": "r\n"}, {name: "x\n"})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertEqual(run.ack, "required")
        self.assertEqual([l for l in run.outputs_raw.splitlines() if l], ["ack=required"])
        self.assertEqual(len([l for l in run.summary.splitlines() if l.startswith("## ")]), 1)
        self.assertNotIn("ack=not-required", run.summary)
        self.assertRow(run, 6)

    def test_credential_shaped_changed_name_is_never_displayed(self):
        from cisupport import AWS_KEY
        repo = self.repo({"README.md": "r\n"}, {f"docs/{AWS_KEY}.md": "x\n"})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertNoLeak(run, AWS_KEY)
        self.assertEqual(run.ack, "required")
        self.assertNotIn(BANNER[8], run.summary.split("\n", 1)[0])

    def test_git_failure_is_technical_failure(self):
        repo = self.repo({"README.md": "r\n"}, {"docs/a.md": "a\n"})
        run = self.run_ci(repo, base="0" * 40)  # unknown commit
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_GIT_FAILED", run.summary)

    def test_pr_gitattributes_textconv_and_external_diff_are_inert(self):
        marker = os.path.join(self.tmp, "textconv-ran")
        attrs = "*.tf diff=evil\n*.md diff=evil\n"
        repo = self.repo({"README.md": "r\n"}, {".gitattributes": attrs, "infra/a.tf": "x\n"})
        git(repo.path, "config", "diff.evil.textconv", f"touch {marker}; cat")
        git(repo.path, "config", "diff.evil.command", f"touch {marker}; true")
        git(repo.path, "config", "diff.external", f"touch {marker}; true")
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertFalse(os.path.exists(marker))
        self.assertRow(run, 6)


if __name__ == "__main__":
    unittest.main()
