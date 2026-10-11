"""Regression tests for blind adversarial verification round R3 (gci2/verifier/R3_REPORT.md), written before the
fixes. V3-01, V3-02 (Low); V3-03, V3-04, V3-06, V3-07 (Info).
"""
import os
import tempfile
import unittest

from cisupport import (AWS_KEY, BANNER, TRUST_DEGRADED, WORKFLOW, TmpCase, corpus_files, git, manifest)
from test_ci14_verifier_r2 import g
from cisupport import write_tree

C01 = corpus_files("c01-tf-benign-scoped")["main.tf"]
C03 = corpus_files("c03-tf-public-admin-ingress")["network.tf"]


class _R:
    pass


def stale_base_repo(tmp):
    """Event base M0; the base branch moved to M1 (another PR's ci/, infra/ and package changes) before the
    test-merge commit (parents M1, head) was built. This PR itself changes docs/a.md only."""
    pr = os.path.join(tmp, "stale", "pr")
    os.makedirs(pr)
    g(pr, "init", "-q", "-b", "main")
    write_tree(pr, {"README.md": "r\n", "p02-demo/pkg/p02-manifest.json": manifest(["main.tf"], "pkg"),
                    "p02-demo/pkg/main.tf": C01})
    g(pr, "add", "-A")
    g(pr, "commit", "-q", "-m", "M0")
    m0 = g(pr, "rev-parse", "HEAD")
    g(pr, "checkout", "-q", "-b", "feature", m0)
    write_tree(pr, {"docs/a.md": "a\n"})
    g(pr, "add", "-A")
    g(pr, "commit", "-q", "-m", "docs")
    head = g(pr, "rev-parse", "HEAD")
    g(pr, "checkout", "-q", "main")
    write_tree(pr, {"ci/tool.py": "x = 1\n", "infra/other.tf": C03, "p02-demo/pkg/main.tf": C03})
    g(pr, "add", "-A")
    g(pr, "commit", "-q", "-m", "M1 other PR")
    m1 = g(pr, "rev-parse", "HEAD")
    g(pr, "checkout", "-q", "--detach", m1)
    g(pr, "merge", "-q", "--no-ff", "-m", "merge ref", head)
    r = _R()
    r.path, r.base, r.head, r.m1 = pr, m0, head, m1
    return r


class V301StaleBase(TmpCase):
    def test_v301_base_branch_progress_is_not_attributed_to_the_pr(self):
        r = stale_base_repo(self.tmp)
        run = self.run_ci(r)
        self.assertRow(run, 8)
        self.assertEqual(run.ack, "not-required")
        self.assertNotIn(TRUST_DEGRADED, run.summary)
        self.assertGreen(run)

    def test_v301_event_base_must_be_an_ancestor_of_the_merge_first_parent(self):
        r = stale_base_repo(self.tmp)
        g(r.path, "checkout", "-q", "-b", "elsewhere", r.head)
        write_tree(r.path, {"x.md": "x\n"})
        g(r.path, "add", "-A")
        g(r.path, "commit", "-q", "-m", "unrelated")
        unrelated = g(r.path, "rev-parse", "HEAD")
        g(r.path, "checkout", "-q", "--detach", r.m1)
        g(r.path, "merge", "-q", "--no-ff", "-m", "merge ref", r.head)
        run = self.run_ci(r, base=unrelated)
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_MERGE_REF_MISMATCH", run.summary)  # R4 V4-04 distinct code


class V303RecordCap(TmpCase):
    def test_v303_cap_counts_unique_paths_and_has_its_own_code(self):
        from p02ci import gitdiff
        repo = self.repo({"README.md": "r\n"}, {f"docs/f{i:03d}.md": "x\n" for i in range(40)})
        old = gitdiff.MAX_RECORDS
        try:
            gitdiff.MAX_RECORDS = 50
            recs = gitdiff.list_changes(repo.path, repo.base, repo.head, os.environ["PATH"], self.tmp)
            self.assertEqual(len(recs), 40)
            gitdiff.MAX_RECORDS = 30
            with self.assertRaises(gitdiff.TooManyChanges):
                gitdiff.list_changes(repo.path, repo.base, repo.head, os.environ["PATH"], self.tmp)
        finally:
            gitdiff.MAX_RECORDS = old


class V304SingleParent(TmpCase):
    def test_v304_single_parent_checkout_is_refused(self):
        repo = self.repo({"README.md": "r\n"}, {"docs/x.md": "y\n"}, merge_ref=False)
        run = self.run_ci(repo)
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_MERGE_REF_MISMATCH", run.summary)  # R4 V4-04 distinct code


def _lint_dir(files):
    import wflint
    with tempfile.TemporaryDirectory() as d:
        with open(WORKFLOW, encoding="utf-8") as fh:
            main = fh.read()
        with open(os.path.join(d, "p02-review.yml"), "w", encoding="utf-8") as fh:
            fh.write(files.pop("p02-review.yml", main))
        for name, text in files.items():
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        return wflint.lint_directory(d, mode="template")


OTHER = ("name: z\non:\n  pull_request:\npermissions: {}\njobs:\n  other:\n    runs-on: ubuntu-24.04\n"
         "    timeout-minutes: 1\n    steps:\n      - run: echo ok\n")


class V302ParserDifferential(unittest.TestCase):
    def test_v302_escapes_in_other_workflows_are_flagged(self):
        cases = [
            OTHER.replace("  other:\n", "  other:\n    name: \"r\\x65view\"\n"),
            OTHER.replace("  other:\n", "  \"g\\x61te\":\n"),
            OTHER.replace("  pull_request:\n", "  \"pull_request_t\\x61rget\":\n"),
            OTHER.replace("permissions: {}\n", "permissions:\n  \"id-tok\\x65n\": write\n"),
            OTHER.replace("      - run: echo ok\n", "      - run: echo ok\n        env:\n"
                          "          T: \"${{ secr\\x65ts.TOKEN }}\"\n"),
        ]
        for text in cases:
            with self.subTest(text=text[40:110]):
                self.assertTrue(_lint_dir({"z.yml": text}))

    def test_v302_unicode_whitespace_and_line_breaks_rejected(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            t = fh.read()
        expr = "'p02-risk-acknowledgement' }}\n"
        for ch in (" ", "　", " "):
            with self.subTest(ch=hex(ord(ch))):
                self.assertTrue(_lint_dir({"p02-review.yml": t.replace(expr, "'p02-risk-acknowledgement' }}" + ch
                                                                        + "\n", 1)}))
        for ch in (" ", " ", "\u0085"):
            with self.subTest(ch=hex(ord(ch))):
                bad = t.replace("        name: P02 review (adapter;",
                                "        name: P02 review" + ch + "        continue-on-error: true (adapter;", 1)
                self.assertNotEqual(bad, t)
                self.assertTrue(_lint_dir({"p02-review.yml": bad}))
        self.assertTrue(_lint_dir({"p02-review.yml": t.replace("\n", "\r\n")}))


class V306StatusForgery(unittest.TestCase):
    def test_v306_other_workflow_write_permissions_or_default_token_flagged(self):
        self.assertTrue(_lint_dir({"s.yml": OTHER.replace("permissions: {}\n", "permissions:\n  statuses: write\n")}))
        self.assertTrue(_lint_dir({"c.yml": OTHER.replace("permissions: {}\n", "permissions:\n  checks: write\n")}))
        self.assertTrue(_lint_dir({"n.yml": OTHER.replace("permissions: {}\n", "")}))
        self.assertTrue(_lint_dir({"w.yml": OTHER.replace("permissions: {}\n", "permissions: write-all\n")}))
        self.assertEqual(_lint_dir({"ok.yml": OTHER}), [])


class V307ProtectedCredentialName(TmpCase):
    def test_v307_credential_shaped_protected_name_gets_rotation_note(self):
        repo = self.repo({"README.md": "r\n"}, {f".github/{AWS_KEY}.yml": "x: 1\n"})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertIn(TRUST_DEGRADED, run.summary)
        self.assertIn("credential shape", run.summary)
        self.assertNoLeak(run, AWS_KEY)
        self.assertEqual(run.ack, "required")


if __name__ == "__main__":
    unittest.main()
