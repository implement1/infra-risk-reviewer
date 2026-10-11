"""CI gate: ack output, fail-closed expression (E2E-36, A-8), gate modes (A-3, D-CI-02(b)), unwritable outputs,
misleading-green and gate-bypass cases.
"""
import datetime
import itertools
import os
import unittest

from cisupport import (BANNER, PROJECT, WORKFLOW, TmpCase, corpus_files, env_mode_config, make_trusted, package)


class AckDecisionTests(unittest.TestCase):
    def test_ack_not_required_only_for_rows_7_8_without_trust_degraded(self):
        from p02ci import outcome
        for row, td in itertools.product(range(1, 9), (False, True)):
            want = "not-required" if row in (7, 8) and not td else "required"
            self.assertEqual(outcome.ack_value(row, td), want, (row, td))

    def test_ack_rejects_non_int_rows(self):
        from p02ci import outcome
        for row in (None, "7", 7.0, 0, 9, True):
            self.assertEqual(outcome.ack_value(row, False), "required")

    def test_exit_codes_per_row_and_mode(self):
        from p02ci import outcome
        for row in (1, 2, 3):
            for mode in ("environment", "fail-on-risk"):
                self.assertNotEqual(outcome.exit_code(row, False, mode), 0)
        self.assertEqual(outcome.exit_code(1, False, "environment"), outcome.EXIT_TECHNICAL)
        for row in (4, 5, 6):
            self.assertEqual(outcome.exit_code(row, False, "environment"), 0)
            self.assertEqual(outcome.exit_code(row, False, "fail-on-risk"), outcome.EXIT_ACK_REQUIRED)
        for row in (7, 8):
            self.assertEqual(outcome.exit_code(row, False, "fail-on-risk"), 0)
            self.assertEqual(outcome.exit_code(row, True, "fail-on-risk"), outcome.EXIT_ACK_REQUIRED)
            self.assertEqual(outcome.exit_code(row, True, "environment"), 0)
        self.assertNotEqual(outcome.exit_code(4, False, "unknown-mode"), 0)


class GateModeTests(unittest.TestCase):
    def _cfg(self, mut):
        import json
        with open(os.path.join(PROJECT, "ci", "p02ci", "trusted_config.json"), encoding="utf-8") as fh:
            c = json.load(fh)
        mut(c)
        return c

    def test_environment_mode_requires_complete_current_attestation(self):
        from p02ci import config
        today = datetime.date(2026, 10, 11)
        good = self._cfg(lambda c: env_mode_config(c, "2026-10-01"))
        self.assertEqual(config.effective_gate(config.parse_config(good), today)[0], "environment")
        for key in ("required_reviewers", "prevent_self_review", "admin_bypass_disabled",
                    "reviewer_team_excludes_pr_authors", "no_environment_secrets"):
            for val in (False, None, "true", 1):
                with self.subTest(key=key, val=val):
                    c = self._cfg(lambda c: env_mode_config(c, "2026-10-01"))
                    if val is None:
                        del c["gate"]["environment_attestation"][key]
                    else:
                        c["gate"]["environment_attestation"][key] = val
                    try:
                        mode, note = config.effective_gate(config.parse_config(c), today)
                    except config.ConfigError:
                        continue  # a malformed attestation is a config error (technical failure): also safe
                    self.assertEqual(mode, "fail-on-risk")
                    self.assertTrue(note)

    def test_expired_future_or_malformed_attestation_date_falls_back(self):
        from p02ci import config
        today = datetime.date(2026, 10, 11)
        for day in ("2026-07-01", "2026-10-12", "2026-13-01", "yesterday", ""):
            with self.subTest(day=day):
                c = self._cfg(lambda c: env_mode_config(c, day))
                try:
                    mode, note = config.effective_gate(config.parse_config(c), today)
                except config.ConfigError:
                    continue
                self.assertEqual(mode, "fail-on-risk")

    def test_wrong_environment_name_or_method_falls_back(self):
        from p02ci import config
        today = datetime.date(2026, 10, 11)
        for key, val in (("environment", "p02-no-ack"), ("method", "trust-me"), ("verified_by", "")):
            c = self._cfg(lambda c: env_mode_config(c, "2026-10-01"))
            c["gate"]["environment_attestation"][key] = val
            try:
                mode, _ = config.effective_gate(config.parse_config(c), today)
            except config.ConfigError:
                continue
            self.assertEqual(mode, "fail-on-risk")

    def test_attestation_max_age_cannot_exceed_180_days(self):
        from p02ci import config
        c = self._cfg(lambda c: env_mode_config(c, "2026-10-01"))
        c["gate"]["attestation_max_age_days"] = 400
        with self.assertRaises(config.ConfigError):
            config.parse_config(c)


class GateE2E(TmpCase):
    def _risk_repo(self):
        return self.repo({"README.md": "r\n"}, package("p02-demo/c03", corpus_files("c03-tf-public-admin-ingress")))

    def test_fallback_is_the_repository_default_and_states_it(self):
        run = self.run_ci(self._risk_repo())
        self.assertRed(run)
        self.assertEqual(run.ack, "required")
        self.assertIn("fail-on-risk", run.summary)
        self.assertIn("human acknowledgement is required", run.summary)

    def test_environment_mode_review_green_and_ack_required(self):
        run = self.run_ci(self._risk_repo(), trusted=self.env_trusted)
        self.assertGreen(run)
        self.assertEqual(run.ack, "required")
        self.assertIn("p02-risk-acknowledgement", run.summary)

    def test_expired_attestation_in_trusted_config_uses_fallback(self):
        old = (datetime.date.today() - datetime.timedelta(days=200)).isoformat()
        trusted = make_trusted(os.path.join(self.tmp, "t"), config_mutator=lambda c: env_mode_config(c, old))
        run = self.run_ci(self._risk_repo(), trusted=trusted)
        self.assertRed(run)
        self.assertIn("fail-on-risk", run.summary)
        self.assertIn("attestation", run.summary)

    def test_outputs_are_exactly_one_ack_line(self):
        for trusted in (PROJECT, self.env_trusted):
            run = self.run_ci(self._risk_repo(), trusted=trusted)
            self.assertEqual(run.outputs_raw, "ack=required\n")
        repo = self.repo({"README.md": "r\n"}, {"docs/a.md": "x\n"})
        run = self.run_ci(repo)
        self.assertEqual(run.outputs_raw, "ack=not-required\n")

    def test_e2e36_unwritable_github_output_is_red_row1(self):
        for target in (os.path.join(self.tmp, "no", "such", "dir", "out"), self.tmp):
            with self.subTest(target=target):
                run = self.run_ci(self.repo({"README.md": "r\n"}, {"docs/a.md": "x\n"}), output_path=target)
                self.assertRed(run)
                self.assertRow(run, 1)
                self.assertIn("P02CI_OUTPUT_UNWRITABLE", run.summary)

    def test_e2e36_unwritable_step_summary_is_red(self):
        run = self.run_ci(self.repo({"README.md": "r\n"}, {"docs/a.md": "x\n"}),
                          summary_path=os.path.join(self.tmp, "missing-dir", "summary"))
        self.assertRed(run)
        self.assertNotEqual(run.ack, "not-required")

    def test_e2e36_missing_output_env_is_red(self):
        for key in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
            with self.subTest(key=key):
                run = self.run_ci(self.repo({"README.md": "r\n"}, {"docs/a.md": "x\n"}), env_drop=(key,))
                self.assertRed(run)

    def test_symlinked_output_files_are_still_written_only_with_fixed_lines(self):
        # The runner owns these paths; the adapter only ever appends fixed-format lines to them.
        run = self.run_ci(self.repo({"README.md": "r\n"}, {"docs/a.md": "x\n"}))
        self.assertRegex(run.outputs_raw, r"\Aack=(required|not-required)\n\Z")

    def test_misleading_green_never_states_approval_or_pass(self):
        repo = self.repo({"README.md": "r\n"}, package("p02-demo/c01", corpus_files("c01-tf-benign-scoped")))
        run = self.run_ci(repo)
        self.assertRow(run, 7)
        low = run.summary.lower().replace("not a safety approval", "")
        for w in ("approved", "safe", "passed", "green", "secure", "verified"):
            self.assertNotIn(w, low, w)
        self.assertIn("normal human review still required", run.summary)


class ExpressionTests(unittest.TestCase):
    """E2E-36 offline: the workflow's own gate expression evaluated with GitHub expression semantics."""

    def _expr(self):
        import wflint
        wf = wflint.load_workflow(WORKFLOW)
        return wf["jobs"]["gate"]["environment"]

    def test_expression_is_the_fail_closed_form(self):
        import wflint
        self.assertEqual(wflint.normalize_expr(self._expr()), wflint.normalize_expr(wflint.GATE_EXPRESSION))

    def test_e2e36_values(self):
        import wflint
        expr = self._expr()
        cases = {None: "p02-risk-acknowledgement", "": "p02-risk-acknowledgement",
                 "True": "p02-risk-acknowledgement", "true": "p02-risk-acknowledgement",
                 "true\n": "p02-risk-acknowledgement", "garbage": "p02-risk-acknowledgement",
                 "required": "p02-risk-acknowledgement", "not-required ": "p02-risk-acknowledgement",
                 " not-required": "p02-risk-acknowledgement", "not_required": "p02-risk-acknowledgement",
                 "not-required\n": "p02-risk-acknowledgement", "0": "p02-risk-acknowledgement",
                 "not-required": "p02-no-ack",
                 # A-8: GitHub string comparison is case-insensitive. The adapter never emits this value
                 # (test_outputs_are_exactly_one_ack_line); the evaluation is recorded, not relied on.
                 "NOT-REQUIRED": "p02-no-ack", "Not-Required": "p02-no-ack"}
        for val, want in cases.items():
            with self.subTest(val=val):
                ctx = {"needs": {"review": {"outputs": ({} if val is None else {"ack": val})}}}
                self.assertEqual(wflint.evaluate(expr, ctx), want)

    def test_evaluator_semantics(self):
        import wflint
        ev = wflint.evaluate
        self.assertEqual(ev("${{ 'a' == 'A' }}", {}), True)
        self.assertEqual(ev("${{ null == '' }}", {}), True)
        self.assertEqual(ev("${{ '' && 'x' || 'y' }}", {}), "y")
        self.assertEqual(ev("${{ 'x' && '' || 'y' }}", {}), "y")
        self.assertEqual(ev("${{ !('a' != 'a') }}", {}), True)
        # The naive (fail-open) form is what the fail-closed expression replaced:
        naive = "${{ needs.review.outputs.ack == 'required' && 'p02-risk-acknowledgement' || 'p02-no-ack' }}"
        self.assertEqual(ev(naive, {"needs": {"review": {"outputs": {}}}}), "p02-no-ack")


if __name__ == "__main__":
    unittest.main()
