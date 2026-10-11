"""Result integrity and fault injection: E2E-29 (invalid output), E2E-30 (internal error), 04 sec. 7.

The validator receives real P02 outputs produced on synthetic corpus fixtures, then mutated copies. Every
mutation must be a row-1 technical failure; no partial rendering.
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from cisupport import CORPUS, SRC, TmpCase, manifest

ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}


def run_p02(cmd, fixture, outdir, extra=()):
    os.makedirs(outdir, exist_ok=True)
    p = subprocess.run([sys.executable, "-P", "-s", "-B", "-m", "p02review", cmd, fixture, "--out-dir", outdir,
                        "--quiet", *extra], env=ENV, capture_output=True, cwd=os.path.dirname(outdir))
    files = {}
    for n in os.listdir(outdir):
        with open(os.path.join(outdir, n), "rb") as fh:
            files[n] = fh.read()
    return p.returncode, p.stdout, files


class Real:
    """Real review+explain outputs for one corpus case."""

    def __init__(self, tmp, case):
        fixture = os.path.join(CORPUS, case, "fixture")
        with open(os.path.join(fixture, "p02-manifest.json"), encoding="utf-8") as fh:
            m = json.load(fh)
        self.declared = [f["path"] for f in m["files"]]
        self.fixture_id = m["fixture_id"]
        d = os.path.join(tmp, case)
        self.r_exit, self.r_out, self.r_files = run_p02("review", fixture, os.path.join(d, "r"))
        v2path = os.path.join(d, "r", next(iter(self.r_files)))
        self.e_exit, self.e_out, self.e_files = run_p02("explain", fixture, os.path.join(d, "e"),
                                                        ("--input-result", v2path))


class IntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="p02ci-int-")
        cls.c03 = Real(cls.tmp, "c03-tf-public-admin-ingress")
        cls.c14 = Real(cls.tmp, "c14-mixed-severe-and-broken")
        cls.c01 = Real(cls.tmp, "c01-tf-benign-scoped")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def _assess(self, real, r_exit=None, r_out=None, r_files=None, e_exit=None, e_out=None, e_files=None,
                declared=None, fixture_id=None):
        from p02ci import validate
        review = validate.ProcResult(real.r_exit if r_exit is None else r_exit,
                                     real.r_out if r_out is None else r_out,
                                     real.r_files if r_files is None else r_files)
        explain = validate.ProcResult(real.e_exit if e_exit is None else e_exit,
                                      real.e_out if e_out is None else e_out,
                                      real.e_files if e_files is None else e_files)
        return validate.assess(review, explain, declared if declared is not None else real.declared,
                               fixture_id if fixture_id is not None else real.fixture_id)

    def _mut_v2(self, real, fn, both=True):
        v2 = json.loads(real.r_out)
        fn(v2)
        out = (json.dumps(v2, indent=2, ensure_ascii=True) + "\n").encode()
        files = {f"{v2['run_id']}.json": out} if both else real.r_files
        return out, files

    def _mut_v3(self, real, fn):
        v3 = json.loads(real.e_out)
        fn(v3)
        out = (json.dumps(v3, indent=2, ensure_ascii=True) + "\n").encode()
        return out, {f"{v3['run_id']}.json": out}

    def assertTech(self, a):
        self.assertEqual(a.row, 1, getattr(a, "check", None))
        self.assertIn(a.failure, ("P02CI_INTEGRITY", "P02CI_V2_MISMATCH", "P02CI_P02_USAGE", "P02CI_P02_INTERNAL",
                                  "P02CI_P02_UNEXPECTED_EXIT", "P02CI_P02_TIMEOUT"))

    def test_real_outputs_pass(self):
        self.assertEqual(self._assess(self.c03).row, 4)
        self.assertEqual(self._assess(self.c14).row, 4)
        self.assertEqual(self._assess(self.c01).row, 7)

    def test_e2e29_corrupted_json(self):
        for bad in (b"", b"{", b"not json", self.c03.r_out[:-20], self.c03.r_out + b"{}",
                    self.c03.r_out.replace(b'"status": "completed"', b'"status": "completed", "status": "completed"')):
            with self.subTest(bad=bad[:20]):
                self.assertTech(self._assess(self.c03, r_out=bad, r_files={"x.json": bad}))

    def test_e2e29_unknown_decision_reason_rule_severity_state_status_note(self):
        muts = [
            lambda v: v["policy"].__setitem__("decision", "approved"),
            lambda v: v["policy"]["reasons"].append("LOOKS_FINE"),
            lambda v: v["findings"][0].__setitem__("rule_id", "TF-NEW-999"),
            lambda v: v["findings"][0].__setitem__("severity", "catastrophic"),
            lambda v: v["findings"][0].__setitem__("state", "dismissed"),
            lambda v: v["coverage"]["files"][0].__setitem__("status", "skipped"),
            lambda v: v.__setitem__("schema_version", "p02.run-result.v9"),
            lambda v: v["findings"][0].__setitem__("id", "F-xyz"),
            lambda v: v["findings"][0].__setitem__("evidence_ids", ["E-0000000000000000"]),
            lambda v: v["findings"].append(copy.deepcopy(v["findings"][0])),
            lambda v: v["coverage"]["files"].pop(),
            lambda v: v["input_identity"].__setitem__("fixture_id", "other"),
            lambda v: v["input_identity"].__setitem__("origin", "authorized_pr"),
            lambda v: v["external_actions"].__setitem__("network_calls", 1),
            lambda v: v["policy"].__setitem__("human_review_required", False),
            lambda v: v["findings"][0]["location"].__setitem__("path", "not-declared.tf"),
        ]
        for i, m in enumerate(muts):
            with self.subTest(i=i):
                out, files = self._mut_v2(self.c03, m)
                self.assertTech(self._assess(self.c03, r_out=out, r_files=files))

    def test_e2e29_note_code_outside_closed_set(self):
        def m(v):
            v["coverage"]["files"][1]["notes"][0]["code"] = "NEW_NOTE"
        out, files = self._mut_v2(self.c14, m)
        self.assertTech(self._assess(self.c14, r_out=out, r_files=files))

    def test_e2e29_decision_inconsistent_with_independent_recomputation(self):
        def m(v):
            v["policy"]["decision"] = "inconclusive"
            v["policy"]["blocking_review_required"] = False
        out, files = self._mut_v2(self.c03, m)
        self.assertTech(self._assess(self.c03, r_out=out, r_files=files))

        def m2(v):  # benign result claiming review_required without a confirmed high finding
            v["policy"]["decision"] = "review_required"
        out, files = self._mut_v2(self.c01, m2)
        self.assertTech(self._assess(self.c01, r_out=out, r_files=files))

    def test_e2e29_run_id_mismatch_between_stdout_and_out_dir(self):
        v2 = json.loads(self.c03.r_out)
        files = {"run-000000000000000000000000.json": self.c03.r_out}
        self.assertTech(self._assess(self.c03, r_files=files))
        self.assertTech(self._assess(self.c03, r_files={}))
        self.assertTech(self._assess(self.c03, r_files={f"{v2['run_id']}.json": self.c03.r_out + b" "}))
        self.assertTech(self._assess(self.c03, r_files={f"{v2['run_id']}.json": self.c03.r_out, "extra.json": b"{}"}))

    def test_e2e29_declared_set_mismatch(self):
        self.assertTech(self._assess(self.c03, declared=["network.tf", "other.tf"]))
        self.assertTech(self._assess(self.c03, fixture_id="different"))

    def test_e2e29_explain_v2_mismatch_is_technical_failure(self):
        out, files = self._mut_v3(self.c03, lambda v: v.__setitem__("status", "v2_mismatch"))
        self.assertTech(self._assess(self.c03, e_exit=3, e_out=out, e_files=files))

    def test_e2e29_explain_policy_differs(self):
        def m(v):
            v["v2_policy"]["decision"] = "no_blocking_findings_detected"
        out, files = self._mut_v3(self.c03, m)
        self.assertTech(self._assess(self.c03, e_out=out, e_files=files))

    def test_e2e29_question_cites_unknown_finding(self):
        def m(v):
            v["verification_questions"][0]["finding_ids"] = ["F-0000000000000000"]
        out, files = self._mut_v3(self.c03, m)
        self.assertTech(self._assess(self.c03, e_out=out, e_files=files))

    def test_e2e29_unknown_question_reason_code(self):
        def m(v):
            v["verification_questions"][0]["reason_code"] = "TRUST_ME"
        out, files = self._mut_v3(self.c03, m)
        self.assertTech(self._assess(self.c03, e_out=out, e_files=files))

    def test_e2e29_v3_reference_mismatch_and_model_enabled(self):
        for m in (lambda v: v["v2_reference"].__setitem__("run_id", "run-x"),
                  lambda v: v["v2_reference"]["supplied_result"].__setitem__("matched", False),
                  lambda v: v["model"].__setitem__("status", "enabled"),
                  lambda v: v.__setitem__("schema_version", "p02.report.v4")):
            with self.subTest(m=m):
                out, files = self._mut_v3(self.c03, m)
                self.assertTech(self._assess(self.c03, e_out=out, e_files=files))

    def test_exit_codes_mapping(self):
        self.assertTech(self._assess(self.c03, r_exit=2))
        self.assertTech(self._assess(self.c03, r_exit=5))
        self.assertTech(self._assess(self.c03, r_exit=1))
        self.assertTech(self._assess(self.c03, r_exit=-9))
        self.assertTech(self._assess(self.c03, e_exit=5))
        self.assertTech(self._assess(self.c03, e_exit=2))
        # review completed but explain rejects (not v2_mismatch, not secret): inconsistent -> technical failure
        out, files = self._mut_v3(self.c03, lambda v: v.__setitem__("status", "rejected"))
        self.assertTech(self._assess(self.c03, e_exit=3, e_out=out, e_files=files))

    def test_exit0_with_rejected_status_is_technical_failure(self):
        out, files = self._mut_v2(self.c03, lambda v: v.__setitem__("status", "rejected"))
        self.assertTech(self._assess(self.c03, r_out=out, r_files=files))

    def test_timeout_is_technical_failure(self):
        from p02ci import validate
        a = validate.assess(validate.ProcResult(None, b"", {}, timed_out=True), None, ["x.tf"], "x")
        self.assertEqual(a.row, 1)
        self.assertEqual(a.failure, "P02CI_P02_TIMEOUT")


class InternalErrorE2E(TmpCase):
    def test_e2e30_hr8_deep_nesting_internal_error_is_technical_failure(self):
        tf = 'locals {\n  a = "' + '${"' * 1000 + "x" + '"}' * 1000 + '"\n}\n'
        repo = self.repo({"README.md": "r\n"}, {"p02-demo/hr8/p02-manifest.json": manifest(["main.tf"], "hr8"),
                                                "p02-demo/hr8/main.tf": tf})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_P02_INTERNAL", run.summary)
        self.assertNotIn("#### Findings", run.summary)
        self.assertNotIn("Decision", run.summary)


if __name__ == "__main__":
    unittest.main()
