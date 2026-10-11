"""Regression tests for the blind adversarial verification round R1 (gci2/verifier/R1_REPORT.md), written before
the corresponding fixes. V1-01 (Medium), V1-02..V1-05 (Low), V1-08 and V1-13 (Info), weak-test note.
"""
import json
import os
import re
import unittest

from cisupport import (AWS_KEY, BANNER, HEADER, PROJECT, WORKFLOW, TmpCase, adapter_digest, corpus_files, git,
                       make_trusted, manifest)

C01 = corpus_files("c01-tf-benign-scoped")["main.tf"]
C03 = corpus_files("c03-tf-public-admin-ingress")["network.tf"]


class V101NestedDeDeclaration(TmpCase):
    """A-2: de-declaring a file that lies in a nested package's directory must never give a plain green result."""

    def _base(self, inner_manifest):
        return {"p02-demo/outer/p02-manifest.json": manifest(["main.tf", "inner/evil.tf"], "outer"),
                "p02-demo/outer/main.tf": C01,
                "p02-demo/outer/inner/evil.tf": C03,
                "p02-demo/outer/inner/p02-manifest.json": inner_manifest}

    def test_v101_valid_inner_manifest(self):
        for trusted in (None, "env"):
            with self.subTest(mode=trusted or "fallback"):
                # Exact R1 reproduction: only the outer manifest changes; the inner package is untouched.
                base = self._base(manifest(["other.tf"], "inner"))
                base["p02-demo/outer/inner/other.tf"] = C01
                repo = self.repo(base, {"p02-demo/outer/p02-manifest.json": manifest(["main.tf"], "outer")})
                run = self.run_ci(repo, **({"trusted": self.env_trusted} if trusted else {}))
                self.assertEqual(run.ack, "required")
                self.assertNotIn(BANNER[7], run.summary.split("\n", 1)[0])
                self.assertIn("p02-demo/outer/inner/evil.tf", run.summary)

    def test_v101_garbage_or_empty_inner_manifest(self):
        for content in ("not json", ""):
            with self.subTest(content=content):
                repo = self.repo(self._base(content),
                                 {"p02-demo/outer/p02-manifest.json": manifest(["main.tf"], "outer")})
                run = self.run_ci(repo, trusted=self.env_trusted)
                self.assertEqual(run.ack, "required")
                self.assertNotIn(BANNER[7], run.summary.split("\n", 1)[0])
                self.assertNotIn(BANNER[8], run.summary.split("\n", 1)[0])

    def test_v101_nested_manifest_dir_with_invalid_name_does_not_hide_files(self):
        base = {"p02-demo/outer/p02-manifest.json": manifest(["main.tf"], "outer"),
                "p02-demo/outer/main.tf": C01,
                "p02-demo/outer/in ner/p02-manifest.json": manifest(["evil.tf"], "inner"),
                "p02-demo/outer/in ner/evil.tf": C03}
        repo = self.repo(base, {"p02-demo/outer/main.tf": C01 + b"\n"})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertEqual(run.ack, "required")
        self.assertRow(run, 6)


class V102GitmodulesIgnore(TmpCase):
    def test_v102_gitlink_change_visible_despite_ignore_all(self):
        repo = self.repo({".gitmodules": '[submodule "m"]\n\tpath = p02-demo/pkg/mods\n\turl = ./x\n\tignore = all\n',
                          "p02-demo/pkg/p02-manifest.json": manifest(["main.tf"], "pkg"),
                          "p02-demo/pkg/main.tf": C01}, {}, merge_ref=False)
        git(repo.path, "checkout", "-q", "main")
        git(repo.path, "update-index", "--add", "--cacheinfo", f"160000,{repo.base},p02-demo/pkg/mods")
        git(repo.path, "commit", "-q", "-m", "base gitlink")
        base = git(repo.path, "rev-parse", "HEAD").decode().strip()
        git(repo.path, "checkout", "-q", "-B", "pr2")
        git(repo.path, "update-index", "--cacheinfo", f"160000,{repo.head},p02-demo/pkg/mods")
        git(repo.path, "commit", "-q", "-m", "bump gitlink")
        head = git(repo.path, "rev-parse", "HEAD").decode().strip()
        git(repo.path, "checkout", "-q", "--detach", base)
        git(repo.path, "merge", "-q", "--no-ff", "-m", "merge ref", head)
        os.makedirs(os.path.join(repo.path, "p02-demo", "pkg", "mods"), exist_ok=True)
        run = self.run_ci(repo, base=base, head=head, trusted=self.env_trusted)
        self.assertEqual(run.ack, "required")
        self.assertNotIn(BANNER[8], run.summary.split("\n", 1)[0])

    def test_v102_diff_command_disables_submodule_ignores(self):
        from p02ci import gitdiff
        cmd = " ".join(gitdiff.diff_command("/usr/bin/git", "/w/pr", "a" * 40, "b" * 40))
        self.assertIn("-c diff.ignoreSubmodules=none", cmd)
        self.assertIn("--ignore-submodules=none", cmd)


class V103BoundedTables(unittest.TestCase):
    def test_v103_refusal_and_secret_tables_are_capped_and_counted(self):
        import test_ci08_render as T
        from p02ci import model, render as R
        long = "d/" * 60 + "x.tf"
        pkgs = []
        for i in range(10):
            p = model.PackageReport(index=i + 1, path=f"p02-demo/p{i:02d}", row=3, status="refused", review_exit=3,
                                    explain_exit=None, v2=None, v3=None, error_codes=["FILE_MISSING"],
                                    refusals=[("P02CI_PATH_SYMLINK", f"{long[:-5]}{j:03d}.tf") for j in range(200)],
                                    secret_hits=[], failure=None)
            pkgs.append(p)
        pkgs[0].row, pkgs[0].status = 2, "rejected"
        pkgs[0].secret_hits = [("aws-access-key-id", f"f{j:03d}.tf") for j in range(200)]
        text, row = R.render(T.report(pkgs))
        self.assertEqual(row, 2)
        self.assertIn("rotate the credential", text)
        self.assertLessEqual(len(text.encode()), 64 * 1024)
        self.assertIn("further refusals not shown (count is complete)", text)
        self.assertIn("further credential hits not shown (count is complete)", text)


class V104Row1KeepsCredentialNotice(TmpCase):
    def test_v104_technical_failure_does_not_hide_other_package_credential(self):
        cred = f'resource "aws_s3_bucket" "b" {{\n  tags = {{ k = "{AWS_KEY}" }}\n}}\n'
        hr8 = 'locals {\n  a = "' + '${"' * 1000 + "x" + '"}' * 1000 + '"\n}\n'
        head = {"p02-demo/a-cred/p02-manifest.json": manifest(["main.tf"], "a-cred"), "p02-demo/a-cred/main.tf": cred,
                "p02-demo/b-hr8/p02-manifest.json": manifest(["main.tf"], "b-hr8"), "p02-demo/b-hr8/main.tf": hr8}
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 1)
        self.assertIn("rotate the credential", run.summary)
        self.assertIn("aws-access-key-id", run.summary)
        self.assertNoLeak(run, AWS_KEY)
        self.assertNotIn("#### Findings", run.summary)
        self.assertNotIn("**Decision:**", run.summary)


def load_wf():
    with open(WORKFLOW, encoding="utf-8") as fh:
        return fh.read()


class V105LinterGaps(unittest.TestCase):
    def assertFlagged(self, text):
        import wflint
        self.assertTrue(wflint.lint_text(text, mode="template"), "mutation not detected")

    def _insert(self, step):
        t = load_wf()
        return t.replace("      - id: adapter\n", step + "      - id: adapter\n", 1)

    def test_v105_mutations_detected(self):
        for step in ("      - run: /usr/bin/python3 pr/evil.py\n",
                     "      - run: python3 -P -s -B pr/evil.py\n",
                     "      - run: bash pr/evil.sh\n",
                     "      - shell: python\n        run: print(1)\n",
                     "      - run: cd ./pr && make\n",
                     "      - run: cd -- pr\n",
                     "      - run: echo \"$GITHUB_WORKSPACE/pr/bin\" >> \"$GITHUB_PATH\"\n",
                     "      - run: echo PYTHONPATH=x >> \"$GITHUB_ENV\"\n",
                     "      - run: echo x >> \"$BASH_ENV\"\n",
                     "      - uses: actions/checkout@PIN_REQUIRED_actions_checkout_v4\n        with:\n"
                     "          path: trusted/ci\n          persist-credentials: false\n"):
            with self.subTest(step=step.strip()[:50]):
                self.assertFlagged(self._insert(step))

    def test_v105_adapter_command_line_is_exact(self):
        t = load_wf()
        self.assertFlagged(t.replace(' "$PY" -P -s -B -m p02ci', ' "$PY" -X importtime -P -s -B -m p02ci', 1))
        self.assertFlagged(t.replace(' -m p02ci --pr-dir', ' -m p02ci --extra x --pr-dir', 1))
        self.assertFlagged(t.replace('PYTHONDONTWRITEBYTECODE=1 RUNNER_TEMP', 'PYTHONDONTWRITEBYTECODE=1 FOO=1 RUNNER_TEMP', 1))

    def test_v105_duplicate_names_expression_and_case(self):
        import tempfile
        import wflint
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "p02-review.yml"), "w") as fh:
                fh.write(load_wf())
            for name, body in (("a.yml", "    name: ${{ 'review' }}\n"), ("b.yml", "")):
                job = "Gate" if name == "b.yml" else "other"
                with open(os.path.join(d, name), "w") as fh:
                    fh.write(f"name: x\non:\n  pull_request:\npermissions: {{}}\njobs:\n  {job}:\n{body}"
                             "    runs-on: ubuntu-24.04\n    timeout-minutes: 1\n    steps:\n      - run: echo ok\n")
            problems = wflint.lint_directory(d, mode="template")
        self.assertTrue(any(p.startswith("dup:") and "a.yml" in p for p in problems), problems)
        self.assertTrue(any(p.startswith("dup:") and "b.yml" in p for p in problems), problems)


class V108SummaryBeforeAck(TmpCase):
    def test_v108_ack_not_required_only_after_summary_written(self):
        if not os.path.exists("/dev/full"):
            self.skipTest("/dev/full not available")
        repo = self.repo({"README.md": "r\n"}, {"docs/a.md": "x\n"})
        run = self.run_ci(repo, summary_path="/dev/full")
        self.assertRed(run)
        self.assertEqual(run.ack, "required")


class V113AdapterFileTypes(TmpCase):
    def test_v113_only_py_and_config_in_adapter_dir(self):
        from p02ci import bootstrap
        for name in ("x.so", "y.pyc", "z.pth", "notes.txt"):
            with self.subTest(name=name):
                trusted = make_trusted(os.path.join(self.tmp, "t-" + name))
                with open(os.path.join(trusted, "ci", "p02ci", name), "wb") as fh:
                    fh.write(b"\x00")
                with self.assertRaises(bootstrap.IntegrityError):
                    bootstrap.adapter_digest(trusted)
        trusted = make_trusted(os.path.join(self.tmp, "t-sub"))
        os.makedirs(os.path.join(trusted, "ci", "p02ci", "sub"))
        with self.assertRaises(bootstrap.IntegrityError):
            bootstrap.adapter_digest(trusted)


class WeakTestSymlinkedOutputs(TmpCase):
    def test_outputs_through_symlinks_receive_only_fixed_lines(self):
        real_out = os.path.join(self.tmp, "real_out")
        real_sum = os.path.join(self.tmp, "real_sum")
        open(real_out, "w").close()
        open(real_sum, "w").close()
        lo, ls = os.path.join(self.tmp, "lo"), os.path.join(self.tmp, "ls")
        os.symlink(real_out, lo)
        os.symlink(real_sum, ls)
        repo = self.repo({"README.md": "r\n"}, {"docs/a.md": "x\n"})
        run = self.run_ci(repo, output_path=lo, summary_path=ls)
        with open(real_out) as fh:
            self.assertRegex(fh.read(), r"\Aack=(required|not-required)\n\Z")
        with open(real_sum) as fh:
            self.assertTrue(fh.read().startswith(HEADER))


if __name__ == "__main__":
    unittest.main()
