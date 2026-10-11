"""Renderer contract (04): fixed layout, deterministic ordering, escaping, never-render fields, budgets and
truncation (E2E-28), credential re-screen and the self-check / constant fallback (04 sec. 5.5-5.7, A-8).
"""
import re
import unittest

from cisupport import AWS_KEY, BANNER, FALLBACK, HEADER, TRUST_DEGRADED

SEVS = ("critical", "high", "unknown", "medium", "low", "info")
STATES = ("confirmed_by_rule", "suspected", "insufficient_evidence", "unsupported")
RULES = ("TF-IAM-001", "TF-NET-001", "PLAN-DEL-001", "K8S-PRIV-001", "K8S-RBAC-001")
NOTES = ("HCL_SYNTAX_ERROR", "MODULE_NOT_ANALYZED", "NO_ANALYZER", "PLAN_ERRORED", "JSON_SYNTAX",
         "NOT_KUBERNETES", "UNRECOGNIZED_KIND", "HELM_RENDERED_ONLY")


def hexid(prefix, n):
    return f"{prefix}-{n:016x}"


def synth_v2(n_findings=3, n_gaps=1, ident_len=None, path_len=None, notes_per_file=1, ev_per_finding=1,
             decision="review_required", marker=None, resource=None, plan_address=None):
    findings, evidence, files = [], [], []
    for i in range(n_findings):
        ev = [hexid("E", i * 100 + j) for j in range(ev_per_finding)]
        for e in ev:
            evidence.append({"id": e, "observation": marker or "obs", "plan_address": marker or None})
        res = resource if resource is not None else (
            ("aws_security_group." + "r" * (ident_len - 19)) if ident_len else f"aws_security_group.r{i}")
        path = ("d/" * 40 + "x" * (path_len - 83) + ".tf")[:path_len] if path_len else "main.tf"
        rule = RULES[i % len(RULES)]
        findings.append({
            "id": hexid("F", i), "rule_id": rule, "category": "network", "severity": SEVS[i % 6],
            "state": STATES[i % 4], "resource": res,
            "location": {"path": path, "line_start": i + 1, "line_end": i + 2,
                         "plan_address": plan_address if plan_address is not None else (
                             ("aws_db_instance." + "p" * (ident_len - 16)) if ident_len else None)},
            "evidence_ids": ev, "summary": marker or "s", "rationale": marker or "r",
            "recommended_check": marker or "c"})
    for i in range(n_gaps):
        path = ("g/" * 40 + "y" * (path_len - 83) + f"{i:03d}.tf")[-path_len:] if path_len else f"gap{i}.tf"
        files.append({"path": path, "kind": "terraform", "status": "parse_error",
                      "notes": [{"code": NOTES[k % len(NOTES)], "message": marker or "m", "line": 1}
                                for k in range(notes_per_file)], "notes_truncated": False})
    files.append({"path": "main.tf", "kind": "terraform", "status": "analyzed", "notes": [],
                  "notes_truncated": False})
    reasons = {"review_required": ["CONFIRMED_HIGH_SEVERITY_FINDING"], "inconclusive": ["INSUFFICIENT_EVIDENCE_FINDING"],
               "no_blocking_findings_detected": ["NO_BLOCKING_FINDING_IN_BASELINE_RULES"]}[decision]
    if n_gaps:
        reasons = reasons + ["COVERAGE_INCOMPLETE"]
    return {"schema_version": "p02.run-result.v2", "run_id": "run-" + "a" * 24, "status": "completed",
            "tool": {"name": "p02review", "version": "0.2.0"},
            "policy": {"decision": decision, "reasons": reasons, "statement": marker or "st"},
            "findings": findings, "evidence": evidence,
            "coverage": {"analysis_complete": n_gaps == 0, "files": files, "statement": marker or "x"},
            "source_inventory": [{"path": marker or "p"}], "errors": []}


def synth_v3(v2, n_questions=2, marker=None):
    qs = []
    for i in range(n_questions):
        f = v2["findings"][i % max(1, len(v2["findings"]))] if v2["findings"] else None
        qs.append({"id": hexid("Q", i), "text": marker or "q", "reason_code": "PUBLIC_ADMIN_INGRESS",
                   "finding_ids": [f["id"]] if f else [], "evidence_ids": [], "coverage_refs": []})
    return {"schema_version": "p02.report.v3", "run_id": "run3-" + "b" * 24, "status": "completed",
            "v2_policy": v2["policy"], "verification_questions": qs,
            "groups": [{"resource": marker or "g", "plan_address": marker or None}],
            "links": [{"plan_address": marker or "l", "static_resource": marker or "s"}],
            "explanation": {"sections": [{"id": "decision", "sentences": [{"text": marker or "t"}]}]},
            "unknowns": [{"text": marker or "u"}], "limitations": [marker or "lim"],
            "coverage": {"files": [{"notes": [{"message": marker or "m"}]}]}}


def report(packages, unreviewed=(), unreviewable=0, trust_degraded=False, gate_mode="environment"):
    from p02ci import model
    return model.RunReport(packages=list(packages), unreviewed=list(unreviewed), unreviewable_count=unreviewable,
                           trust_degraded=trust_degraded, gate_mode=gate_mode, gate_note=None, failure_codes=[],
                           footer={"core_digest": "f" * 64, "adapter_digest": "a" * 64, "python": "3.13.16",
                                   "tool_versions": "0.2.0/0.3.0"},
                           attestation_date="2026-10-01" if gate_mode == "environment" else None,
                           attestation_method="admin-api-read" if gate_mode == "environment" else None)


def pkg(index, v2, v3=None, path=None, row=None):
    from p02ci import model
    row = row or {"review_required": 4, "inconclusive": 5, "no_blocking_findings_detected": 7}[v2["policy"]["decision"]]
    return model.PackageReport(index=index, path=path or f"p02-demo/p{index:02d}", row=row, status="completed",
                               review_exit=0, explain_exit=0, v2=v2, v3=v3 or synth_v3(v2), error_codes=[],
                               refusals=[], secret_hits=[], failure=None)


def unrev(n, prefix="infra/f"):
    from p02ci import model
    return [model.Unreviewed(path=f"{prefix}{i:05d}.tf".encode(), change="added", reason="outside_packages")
            for i in range(n)]


def render(rep):
    from p02ci import render as R
    return R.render(rep)


class LayoutTests(unittest.TestCase):
    def test_fixed_header_lines(self):
        text, row = render(report([pkg(1, synth_v2())]))
        lines = text.split("\n")
        self.assertEqual(row, 4)
        self.assertEqual(lines[0], HEADER + BANNER[4])
        self.assertIn("Deterministic baseline review. Human review is always required. This is not a safety approval.",
                      text)
        self.assertIn("Identifiers below are untrusted data taken from the submitted files.", text)

    def test_trust_degraded_notice_directly_under_banner_never_replacing_it(self):
        text, row = render(report([pkg(1, synth_v2(decision="no_blocking_findings_detected", n_gaps=0))],
                                  trust_degraded=True))
        lines = text.split("\n")
        self.assertEqual(lines[0], HEADER + BANNER[7])
        self.assertEqual(lines[1], "> " + TRUST_DEGRADED)

    def test_overall_banner_precedence(self):
        p4 = pkg(1, synth_v2())
        p5 = pkg(2, synth_v2(decision="inconclusive"))
        p7 = pkg(3, synth_v2(decision="no_blocking_findings_detected", n_gaps=0))
        self.assertEqual(render(report([p7, p5]))[1], 5)
        self.assertEqual(render(report([p7, p5, p4]))[1], 4)
        self.assertEqual(render(report([p7], unreviewed=unrev(1)))[1], 6)
        self.assertEqual(render(report([p5], unreviewed=unrev(1)))[1], 5)
        self.assertEqual(render(report([p7]))[1], 7)
        self.assertEqual(render(report([]))[1], 8)
        self.assertEqual(render(report([], unreviewable=1))[1], 6)

    def test_finding_order_severity_state_rule_id(self):
        v2 = synth_v2(n_findings=24, n_gaps=0)
        text, _ = render(report([pkg(1, v2)]))
        rows = [l for l in text.splitlines() if re.match(r"^\| \d+ \| `(critical|high|unknown|medium|low|info)`", l)]
        keys = []
        for r in rows:
            cells = [c.strip().strip("`") for c in r.strip("|").split("|")]
            keys.append((SEVS.index(cells[1]), STATES.index(cells[2]), cells[3], cells[6]))
        self.assertEqual(len(keys), 24)
        self.assertEqual(keys, sorted(keys))

    def test_packages_sorted_bytewise_and_numbered(self):
        a = pkg(1, synth_v2(), path="p02-demo/b")
        b = pkg(2, synth_v2(), path="p02-demo/a")
        from p02ci import model
        text, _ = render(report(model.order_packages([a, b])))
        self.assertLess(text.find("`p02-demo/a`"), text.find("`p02-demo/b`"))

    def test_gaps_before_findings_and_questions_after(self):
        text, _ = render(report([pkg(1, synth_v2(n_gaps=2))]))
        self.assertLess(text.find("#### Coverage gaps"), text.find("#### Findings"))
        self.assertLess(text.find("#### Findings"), text.find("#### Questions for the reviewer"))

    def test_counts_complete_in_overview(self):
        v2 = synth_v2(n_findings=300, n_gaps=0)
        text, _ = render(report([pkg(1, v2)]))
        c = sum(1 for f in v2["findings"] if f["severity"] == "critical")
        h = sum(1 for f in v2["findings"] if f["severity"] == "high")
        self.assertIn(f"{c}/{h}/", text)


class SanitizationTests(unittest.TestCase):
    def test_never_render_fields_with_markers(self):
        marker = "MARKERX9"
        v2 = synth_v2(marker=marker)
        text, _ = render(report([pkg(1, v2, synth_v3(v2, marker=marker))]))
        self.assertNotIn(marker, text)

    def test_identifiers_only_through_display_functions_in_code_spans(self):
        for res, shown in (("aws_iam_policy.<img src=x>", "[identifier withheld]"),
                           ("aws_s3_bucket.totally_safe", "[identifier withheld]"),
                           ("a" * 121, "[identifier withheld]"),
                           ("aws_x.ok_name", "aws_x.ok_name"),
                           ("x`y", "[identifier withheld]"), ("x|y", "[identifier withheld]")):
            with self.subTest(res=res[:30]):
                text, _ = render(report([pkg(1, synth_v2(n_findings=1, resource=res))]))
                self.assertIn(f"`{shown}`", text)
                if shown != res:
                    self.assertNotIn(res, text)

    def test_k8s_resource_uses_display_resource(self):
        v2 = synth_v2(n_findings=1, resource="ClusterRole/everything rules[0]")
        v2["findings"][0]["rule_id"] = "K8S-RBAC-001"
        text, _ = render(report([pkg(1, v2)]))
        self.assertIn("`ClusterRole/everything rules[0]`", text)
        v2 = synth_v2(n_findings=1, resource="aws_x.a b")
        text, _ = render(report([pkg(1, v2)]))
        self.assertIn("`[identifier withheld]`", text)  # TF identifiers must be one segment

    def test_credential_shaped_identifier_is_withheld_not_rendered(self):
        v2 = synth_v2(n_findings=1, resource="aws_s3_bucket.b" + AWS_KEY)
        text, row = render(report([pkg(1, v2)]))
        self.assertNotIn(AWS_KEY, text)
        self.assertNotEqual(text, FALLBACK)

    def test_escaping_of_fixed_text_outside_code_spans(self):
        from p02ci import render as R
        self.assertEqual(R.escape_text("a|b`c<d>@e*f_g[h]#!\\"),
                         "a&#124;b&#96;c&#60;d&#62;&#64;e&#42;f&#95;g&#91;h&#93;&#35;&#33;&#92;")
        self.assertEqual(R.escape_text("Plain text, ok: (x) 'y' /z=+-."), "Plain text, ok: (x) 'y' /z=+-.")

    def test_code_span_accepts_only_allowlisted_tokens_or_display_output(self):
        from p02ci import render as R
        self.assertEqual(R.code("TF-NET-001"), "`TF-NET-001`")
        with self.assertRaises(R.RenderError):
            R.code("a b")
        with self.assertRaises(R.RenderError):
            R.code("x`y")
        self.assertEqual(R.code_display(R.display_path("a/b.tf")), "`a/b.tf`")
        with self.assertRaises(R.RenderError):
            R.code_display("raw <x>")

    def test_ascii_only_and_no_html(self):
        v2 = synth_v2(n_findings=5, n_gaps=2)
        text, _ = render(report([pkg(1, v2)], unreviewed=unrev(3)))
        text.encode("ascii")
        self.assertNotRegex(text, r"<[A-Za-z!/]")

    def test_self_check_failure_gives_constant_fallback(self):
        from p02ci import render as R
        for bad in ("café", "x <img>", "line\x00", "## heading" + AWS_KEY, "[a](http://x)"):
            with self.subTest(bad=bad[:12]):
                self.assertFalse(R.self_check(bad + "\n"))
        self.assertTrue(R.self_check(render(report([pkg(1, synth_v2())]))[0]))

    def test_rescreen_hit_on_final_text_yields_fallback(self):
        from p02ci import render as R
        orig = R._compose
        try:
            R._compose = lambda rep, budget: (orig(rep, budget)[0] + "\n" + AWS_KEY + "\n", orig(rep, budget)[1])
            text, row = R.render(report([pkg(1, synth_v2())]))
        finally:
            R._compose = orig
        self.assertEqual(row, 1)
        self.assertIn(FALLBACK, text)
        self.assertNotIn(AWS_KEY, text)

    def test_no_safe_or_approved_wording(self):
        for v2 in (synth_v2(decision="no_blocking_findings_detected", n_gaps=0), synth_v2()):
            text, _ = render(report([pkg(1, v2)]))
            low = text.lower().replace("not a safety approval", "")
            for w in ("safe", "approved", "secure", "clean", "passed", "all clear"):
                self.assertNotIn(w, low)


class BudgetTests(unittest.TestCase):
    def test_e2e28a_large_packages_shrink_in_order_with_complete_counts(self):
        pkgs = [pkg(i + 1, synth_v2(n_findings=300, n_gaps=120, ident_len=120, path_len=160))
                for i in range(10)]
        text, row = render(report(pkgs, unreviewed=unrev(60)))
        size = len(text.encode())
        self.assertLessEqual(size, 256 * 1024)
        self.assertEqual(row, 4)
        self.assertTrue(text.startswith(HEADER + BANNER[4]))
        self.assertIn("further findings not shown (counts above are complete)", text)
        self.assertIn("further coverage gaps not shown; the analysis is incomplete", text)
        self.assertIn("further files not shown (count is complete)", text)
        self.assertNotIn("#### Questions for the reviewer\n|", text)  # step 1: questions dropped
        self.assertIn("question rows not shown", text)
        frows = [l for l in text.splitlines() if re.match(r"^\| \d+ \| `(critical|high|unknown|medium|low|info)`", l)]
        self.assertEqual(len(frows), 10 * 20)

    def test_shrink_steps_apply_only_as_needed(self):
        # Ordinary size: no shrink at all.
        text, _ = render(report([pkg(1, synth_v2(n_findings=40, n_gaps=10))], unreviewed=unrev(30)))
        self.assertLessEqual(len(text.encode()), 64 * 1024)
        self.assertNotIn("not shown", text)

    def test_e2e28b_worst_case_under_hard_cap(self):
        pkgs = [pkg(i + 1, synth_v2(n_findings=300, n_gaps=120, ident_len=120, path_len=160, notes_per_file=50,
                                    ev_per_finding=40))
                for i in range(10)]
        text, row = render(report(pkgs, unreviewed=unrev(5000, prefix="infra/" + "q" * 140 + "/f"),
                                  unreviewable=17, trust_degraded=True))
        size = len(text.encode())
        self.assertLessEqual(size, 256 * 1024, size)
        self.assertGreater(size, 64 * 1024)
        self.assertRegex(text, r"\+\d+")
        self.assertEqual(row, 4)
        # A-8 estimate: about 590 bytes per finding row at most
        frows = [l for l in text.splitlines() if re.match(r"^\| \d+ \| `(critical|high|unknown|medium|low|info)`", l)]
        self.assertLessEqual(max(len(l) for l in frows), 600)

    def test_more_than_hard_cap_is_technical_failure_fallback(self):
        from p02ci import render as R
        old = R.HARD_CAP
        try:
            R.HARD_CAP = 2000
            text, row = R.render(report([pkg(1, synth_v2(n_findings=50, n_gaps=50))]))
        finally:
            R.HARD_CAP = old
        self.assertEqual(row, 1)
        self.assertIn(FALLBACK, text)

    def test_note_codes_deduplicated_max5_plus_n(self):
        text, _ = render(report([pkg(1, synth_v2(n_findings=1, n_gaps=1, notes_per_file=50))]))
        gap = [l for l in text.splitlines() if "gap0.tf" in l][0]
        self.assertEqual(gap.count("`") // 2, 1 + 1 + 5)  # path, status, 5 codes
        self.assertIn("+3", gap)  # 8 distinct codes -> 5 shown + 3

    def test_evidence_ids_max3_plus_n(self):
        text, _ = render(report([pkg(1, synth_v2(n_findings=1, n_gaps=0, ev_per_finding=7))]))
        row = [l for l in text.splitlines() if "`F-0000000000000000`" in l and l.startswith("| 1 |")][0]
        self.assertEqual(len(re.findall(r"`E-[0-9a-f]{16}`", row)), 3)
        self.assertIn("+4", row)


if __name__ == "__main__":
    unittest.main()
