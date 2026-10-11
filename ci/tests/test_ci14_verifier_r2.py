"""Regression tests for blind adversarial verification round R2 (gci2/verifier/R2_REPORT.md), written before the
fixes. V2-01 (Medium: criss-cross history hides merged changes from the A-1 three-dot enumeration), V2-02, V2-03
(Low), V2-04, V2-05, V2-06, V2-08 (Info).
"""
import os
import subprocess
import unittest

from cisupport import (AWS_KEY, BANNER, GIT_ENV_BASE, HEADER, TRUST_DEGRADED, WORKFLOW, TmpCase, corpus_files,
                       git, manifest, package, write_tree)

C01 = corpus_files("c01-tf-benign-scoped")["main.tf"]
C03 = corpus_files("c03-tf-public-admin-ingress")["network.tf"]
UNTRUSTED = "> Identifiers below are untrusted data taken from the submitted files."


def g(repo, *args, date="2026-01-01T00:00:00Z", check=True):
    env = {"PATH": os.environ["PATH"], **GIT_ENV_BASE, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    p = subprocess.run(["git", "-C", repo, *args], env=env, capture_output=True)
    if check and p.returncode:
        raise AssertionError(p.stderr.decode())
    return p.stdout.decode().strip()


class _R:
    pass


def crisscross(tmp, a1_older=True):
    """Return a repo object whose worktree is GitHub's test-merge commit (base M_A + head M_B) for a PR that
    silently reverts a base-side hardening through a criss-cross history (R2 V2-01 reproduction)."""
    pr = os.path.join(tmp, "cc-" + str(a1_older), "pr")
    os.makedirs(pr)
    da, db = (("2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z") if a1_older
              else ("2026-01-03T00:00:00Z", "2026-01-02T00:00:00Z"))
    g(pr, "init", "-q", "-b", "main")
    write_tree(pr, {"README.md": "r\n", "p02-demo/pkg/p02-manifest.json": manifest(["main.tf"], "pkg"),
                    "p02-demo/pkg/main.tf": C03})
    g(pr, "add", "-A")
    g(pr, "commit", "-q", "-m", "M0")
    m0 = g(pr, "rev-parse", "HEAD")
    g(pr, "checkout", "-q", "-b", "att", m0)
    write_tree(pr, {"docs/a.md": "a\n"})
    g(pr, "add", "-A")
    g(pr, "commit", "-q", "-m", "B1", date=db)
    b1 = g(pr, "rev-parse", "HEAD")
    g(pr, "checkout", "-q", "main")
    write_tree(pr, {"p02-demo/pkg/main.tf": C01})
    g(pr, "add", "-A")
    g(pr, "commit", "-q", "-m", "A1 harden", date=da)
    a1 = g(pr, "rev-parse", "HEAD")
    g(pr, "merge", "-q", "--no-ff", "-m", "M_A", b1, date="2026-01-04T00:00:00Z")
    ma = g(pr, "rev-parse", "HEAD")
    g(pr, "checkout", "-q", "att")
    g(pr, "merge", "-q", "--no-ff", "--no-commit", a1, check=False, date="2026-01-05T00:00:00Z")
    write_tree(pr, {"p02-demo/pkg/main.tf": C03})
    g(pr, "add", "-A")
    g(pr, "commit", "-q", "-m", "M_B", date="2026-01-05T00:00:00Z")
    mb = g(pr, "rev-parse", "HEAD")
    g(pr, "checkout", "-q", "--detach", ma)
    g(pr, "merge", "-q", "--no-ff", "-m", "merge ref", mb, date="2026-01-06T00:00:00Z")
    r = _R()
    r.path, r.base, r.head = pr, ma, mb
    return r


class V201CrissCross(TmpCase):
    def test_v201_reverted_hardening_is_never_green(self):
        for a1_older in (True, False):
            r = crisscross(self.tmp, a1_older)
            with open(os.path.join(r.path, "p02-demo", "pkg", "main.tf"), "rb") as fh:
                self.assertEqual(fh.read(), C03)  # the merge would reintroduce the public SSH ingress
            for trusted in (None, self.env_trusted):
                with self.subTest(a1_older=a1_older, env=bool(trusted)):
                    run = self.run_ci(r, **({"trusted": trusted} if trusted else {}))
                    self.assertEqual(run.ack, "required")
                    first = run.summary.split("\n", 1)[0]
                    self.assertNotIn(BANNER[7], first)
                    self.assertNotIn(BANNER[8], first)
                    self.assertIn("TF-NET-001", run.summary)

    def test_v201_merge_ref_worktree_ordinary_cases(self):
        repo = self.repo({"README.md": "r\n"}, package("p02-demo/c03", corpus_files("c03-tf-public-admin-ingress")),
                         merge_ref=True)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 4)
        repo = self.repo({"README.md": "r\n"}, {"docs/x.md": "y\n"}, merge_ref=True)
        run = self.run_ci(repo)
        self.assertRow(run, 8)
        self.assertEqual(run.ack, "not-required")

    def test_v201_merge_parent_must_match_head_sha(self):
        repo = self.repo({"README.md": "r\n"}, {"docs/x.md": "y\n"}, merge_ref=True)
        run = self.run_ci(repo, head=repo.base)
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_MERGE_REF_MISMATCH", run.summary)  # R4 V4-04 distinct code

    def test_v201_single_parent_checkout_must_equal_head_sha(self):
        repo = self.repo({"README.md": "r\n"}, {"docs/x.md": "y\n"}, merge_ref=False)
        run = self.run_ci(repo, head=repo.base)
        self.assertRed(run)
        self.assertRow(run, 1)


class V202ShaSwap(TmpCase):
    def test_v202_env_sha_swap_cannot_hide_changes(self):
        head = package("p02-demo/c03", corpus_files("c03-tf-public-admin-ingress"))
        head[".github/workflows/p02-review.yml"] = "# edited\n"
        repo = self.repo({"README.md": "r\n"}, head, merge_ref=True)
        run = self.run_ci(repo, trusted=self.env_trusted, base=repo.head)  # base := head
        self.assertEqual(run.ack, "required")
        self.assertNotIn(BANNER[8], run.summary.split("\n", 1)[0])
        run = self.run_ci(repo, trusted=self.env_trusted, head=repo.base)  # head := base
        self.assertEqual(run.ack, "required")
        self.assertRed(run)

    def test_v202_lint_pins_adapter_env_values(self):
        import wflint
        with open(WORKFLOW, encoding="utf-8") as fh:
            t = fh.read()
        bad = t.replace("P02_BASE_SHA: ${{ github.event.pull_request.base.sha }}",
                        "P02_BASE_SHA: ${{ github.event.pull_request.head.sha }}", 1)
        self.assertTrue(wflint.lint_text(bad, mode="template"))


class V203LinterResiduals(unittest.TestCase):
    def _t(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            return fh.read()

    def _insert(self, step, after=False):
        t = self._t()
        if after:
            return t.replace("  gate:\n", step + "  gate:\n", 1)
        return t.replace("      - id: adapter\n", step + "      - id: adapter\n", 1)

    def test_v203_mutations_detected(self):
        import wflint
        steps = [
            "      - run: bash \"$GITHUB_WORKSPACE\"/pr/evil.sh\n",
            "      - run: sh \"${GITHUB_WORKSPACE}\"/pr/evil.sh\n",
            "      - run: cd \"$GITHUB_WORKSPACE\"/pr && make\n",
            "      - run: D=p\"\"r; bash \"$D/evil.sh\"\n",
            "      - run: echo hi\n        env:\n          BASH_ENV: pr/x.sh\n",
            "      - run: echo hi\n        env:\n          PATH: /x/pr/bin\n",
            "      - run: sed -i s/x/y/ trusted/ci/p02ci/outcome.py\n",
            "      - run: cp x trusted/ci/p02ci/app.py\n",
        ]
        for s in steps:
            with self.subTest(step=s.strip()[:50]):
                self.assertTrue(wflint.lint_text(self._insert(s), mode="template"))
        after = "      - run: echo '## fake' >> \"$GITHUB_STEP_SUMMARY\"\n"
        self.assertTrue(wflint.lint_text(self._insert(after, after=True), mode="template"))
        t = self._t()
        for old, new in (("          path: trusted\n", "          path: trusted\n          repository: other/repo\n"),
                         ("          path: pr\n", "          path: pr\n          ref: ${{ github.event.pull_request.base.sha }}\n"),
                         ("    timeout-minutes: 10\n", "    timeout-minutes: 10\n    environment: x\n"),
                         ("PYTHONDONTWRITEBYTECODE=1 RUNNER_TEMP",
                          "PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=\"/home/runner/work/r/r/pr/lib\" RUNNER_TEMP")):
            with self.subTest(old=old.strip()[:30]):
                self.assertIn(old, t)
                self.assertTrue(wflint.lint_text(t.replace(old, new, 1), mode="template"))

    def test_v203_tool_cache_ld_library_path_allowed(self):
        import wflint
        t = self._t().replace("PYTHONDONTWRITEBYTECODE=1 RUNNER_TEMP",
                              "PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=\"/opt/hostedtoolcache/Python/3.13.7/x64/lib\" "
                              "RUNNER_TEMP", 1)
        self.assertEqual(wflint.lint_text(t, mode="template"), [])


class V204V205Row1(TmpCase):
    def test_v204_row1_with_packages_marks_identifiers_untrusted_and_withholds_assessments(self):
        hr8 = 'locals {\n  a = "' + '${"' * 1000 + "x" + '"}' * 1000 + '"\n}\n'
        head = package("p02-demo/a-c03", corpus_files("c03-tf-public-admin-ingress"))
        head.update(package("p02-demo/b-c01", corpus_files("c01-tf-benign-scoped")))
        head.update({"p02-demo/c-hr8/p02-manifest.json": manifest(["main.tf"], "c-hr8"), "p02-demo/c-hr8/main.tf": hr8,
                     "infra/x.tf": C03})
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 1)
        self.assertIn(UNTRUSTED, run.summary)
        for label in ("REVIEW REQUIRED", "NO BLOCKING FINDINGS", "ANALYSIS INCOMPLETE"):
            self.assertNotIn(label, run.summary)
        self.assertIn("not reviewed", run.summary)  # the unreviewed-change count is kept (no names)
        self.assertNotIn("infra/x.tf", run.summary)

    def test_v205_trust_degraded_kept_on_package_cap_failure(self):
        head = {"ci/p02ci/app.py": "# x\n"}
        for i in range(11):
            head.update(package(f"p02-demo/p{i:02d}", corpus_files("c01-tf-benign-scoped")))
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 1)
        self.assertIn(TRUST_DEGRADED, run.summary)


class V206V208Names(TmpCase):
    def test_v206_gitlink_or_symlink_with_allow_listed_name_is_not_green(self):
        repo = self.repo({"README.md": "r\n", "infra/x.tf": C03}, {"docs/link.md": ("symlink", "../infra/x.tf")})
        run = self.run_ci(repo)
        self.assertEqual(run.ack, "required")
        self.assertNotIn(BANNER[8], run.summary.split("\n", 1)[0])
        repo = self.repo({"README.md": "r\n"}, {"docs/a.md": "x\n"}, gitlinks={"docs/runbook.md": None})
        run = self.run_ci(repo)
        self.assertEqual(run.ack, "required")
        self.assertNotIn(BANNER[8], run.summary.split("\n", 1)[0])

    def test_v208_credential_shaped_name_gets_rotation_note_without_the_name(self):
        repo = self.repo({"README.md": "r\n"}, {f"infra/{AWS_KEY}.tf": "x\n"})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertNoLeak(run, AWS_KEY)
        self.assertIn("credential shape", run.summary)
        self.assertIn("rotate", run.summary)


if __name__ == "__main__":
    unittest.main()
