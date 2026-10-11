"""Trusted execution: digests, start-up assertions, import shadowing, environment allow-list.

Covers E2E-23 (PR modifies adapter/core: base bundle runs), E2E-24 (tampered bundle), E2E-33 (import
shadowing, including a control run without -P), 02 sec. 4 and sec. 7.5, A-8 (env -i, detection-only assertion).
"""
import os
import subprocess
import sys
import unittest

from cisupport import (BANNER, HEADER, MANIFEST, PROJECT, TRUST_DEGRADED, TmpCase, adapter_digest, core_digest,
                       corpus_files, make_trusted, manifest, package)

MARKER = "SHADOW_MARKER_" + "7f3a"


def shadow_files(where):
    """PR-supplied modules that would print MARKER if imported."""
    code = f"import sys\nsys.stderr.write('{MARKER}\\n')\nopen('/tmp/{MARKER}_' + __name__, 'w').close()\n"
    return {
        f"{where}p02review/__init__.py": code,
        f"{where}p02review/__main__.py": code,
        f"{where}p02ci/__init__.py": code,
        f"{where}p02ci/__main__.py": code,
        f"{where}sitecustomize.py": code,
        f"{where}usercustomize.py": code,
        f"{where}json.py": code,
        f"{where}hashlib.py": code,
    }


class DigestTests(TmpCase):
    def test_bootstrap_digest_algorithms_match_independent_implementation(self):
        from p02ci import bootstrap
        self.assertEqual(bootstrap.core_digest(PROJECT), core_digest(PROJECT))
        self.assertEqual(core_digest(PROJECT), "f03b50e89db84f1974f82cabbc6e222d341dae4e206de3a32ceb1f7e20fae518")
        self.assertEqual(bootstrap.adapter_digest(PROJECT), adapter_digest(PROJECT))

    def test_bootstrap_imports_only_stdlib(self):
        # The bootstrap must not import the core (02 sec. 4): run it in a fresh interpreter and inspect modules.
        code = ("import sys; import p02ci.bootstrap as b; "
                "bad=[m for m in sys.modules if m.startswith('p02review') or (m.startswith('p02ci') and m not in "
                "('p02ci','p02ci.bootstrap'))]; print(bad)")
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": f"{PROJECT}/src:{PROJECT}/ci", "PYTHONDONTWRITEBYTECODE": "1"}
        p = subprocess.run([sys.executable, "-P", "-s", "-B", "-c", code], env=env, capture_output=True, text=True,
                           cwd=self.tmp)
        self.assertEqual(p.stdout.strip(), "[]", p.stderr)

    def test_e2e24_tampered_core_byte_is_technical_failure(self):
        def tamper(dest):
            path = os.path.join(dest, "src", "p02review", "policy_v2.py")
            with open(path, "ab") as fh:
                fh.write(b"\n# one byte changed\n")
        trusted = make_trusted(os.path.join(self.tmp, "t"), mutate=tamper)
        repo = self.repo({}, package("p02-demo/c03", corpus_files("c03-tf-public-admin-ingress")))
        run = self.run_ci(repo, trusted=trusted, core_pins=[core_digest(PROJECT)],
                          adapter_pins=[adapter_digest(trusted)])
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_CORE_DIGEST_MISMATCH", run.summary)
        self.assertNotIn("TF-NET-001", run.summary)
        self.assertNotIn("Findings", run.summary)
        self.assertEqual(run.ack, "required")

    def test_e2e24_tampered_adapter_is_technical_failure(self):
        def tamper(dest):
            with open(os.path.join(dest, "ci", "p02ci", "render.py"), "ab") as fh:
                fh.write(b"\n")
        trusted = make_trusted(os.path.join(self.tmp, "t"), mutate=tamper)
        repo = self.repo({}, package("p02-demo/c01", corpus_files("c01-tf-benign-scoped")))
        run = self.run_ci(repo, trusted=trusted, core_pins=[core_digest(PROJECT)],
                          adapter_pins=[adapter_digest(PROJECT)])
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_ADAPTER_DIGEST_MISMATCH", run.summary)

    def test_extra_file_in_adapter_dir_changes_digest(self):
        trusted = make_trusted(os.path.join(self.tmp, "t"))
        before = adapter_digest(trusted)
        with open(os.path.join(trusted, "ci", "p02ci", "extra.py"), "w") as fh:
            fh.write("x = 1\n")
        from p02ci import bootstrap
        self.assertNotEqual(bootstrap.adapter_digest(trusted), before)

    def test_symlink_in_adapter_dir_is_refused(self):
        trusted = make_trusted(os.path.join(self.tmp, "t"))
        os.symlink("/etc/hostname", os.path.join(trusted, "ci", "p02ci", "link.py"))
        from p02ci import bootstrap
        with self.assertRaises(bootstrap.IntegrityError):
            bootstrap.adapter_digest(trusted)

    def test_multiple_pins_accept_either_digest(self):
        repo = self.repo({}, {"docs/a.md": "x\n"})
        run = self.run_ci(repo, core_pins=["0" * 64, core_digest(PROJECT)],
                          adapter_pins=[adapter_digest(PROJECT), "1" * 64])
        self.assertGreen(run)
        self.assertRow(run, 8)

    def test_malformed_pin_is_technical_failure(self):
        repo = self.repo({}, {"docs/a.md": "x\n"})
        run = self.run_ci(repo, core_pins=["not-a-digest"])
        self.assertRed(run)
        self.assertRow(run, 1)

    def test_missing_pins_is_technical_failure(self):
        repo = self.repo({}, {"docs/a.md": "x\n"})
        run = self.run_ci(repo, core_pins=[], adapter_pins=[])
        self.assertRed(run)


class BaseBundleTests(TmpCase):
    def test_e2e23_pr_modifying_core_and_adapter_runs_base_bundle_and_degrades_trust(self):
        # The PR's own copies of src/ and ci/ are poisoned; the trusted (base) bundle must be the one that runs.
        poisoned = "raise SystemExit('" + MARKER + "')\n"
        head = {"src/p02review/__init__.py": poisoned, "src/p02review/cli.py": poisoned,
                "ci/p02ci/__init__.py": poisoned, "ci/p02ci/__main__.py": poisoned}
        head.update(package("p02-demo/c03", corpus_files("c03-tf-public-admin-ingress")))
        repo = self.repo({"README.md": "base\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertNotIn(MARKER, run.all_text())
        self.assertRow(run, 4)
        self.assertIn(TRUST_DEGRADED, run.summary)
        self.assertEqual(run.ack, "required")
        self.assertGreen(run)  # environment mode: review green, gate pending


class StartupAssertionTests(TmpCase):
    def _repo(self):
        return self.repo({}, {"docs/a.md": "x\n"})

    def test_without_safe_path_flag_adapter_refuses(self):
        run = self.run_ci(self._repo(), python_flags=("-s", "-B"))
        self.assertRed(run)
        self.assertRow(run, 1)
        self.assertIn("P02CI_STARTUP_UNSAFE", run.summary)

    def test_without_no_user_site_flag_adapter_refuses(self):
        run = self.run_ci(self._repo(), python_flags=("-P", "-B"))
        self.assertRed(run)
        self.assertIn("P02CI_STARTUP_UNSAFE", run.summary)

    def test_without_dont_write_bytecode_adapter_refuses(self):
        # Runs against a throw-away trusted copy: without -B the interpreter writes bytecode while importing the
        # bootstrap (before it can refuse), which would otherwise alter the project's adapter tree.
        trusted = make_trusted(os.path.join(self.tmp, "t"))
        run = self.run_ci(self._repo(), trusted=trusted, python_flags=("-P", "-s"),
                          env_drop=("PYTHONDONTWRITEBYTECODE",),
                          adapter_pins=[adapter_digest(trusted)])
        self.assertRed(run)
        self.assertIn("P02CI_STARTUP_UNSAFE", run.summary)

    def test_empty_pythonpath_segment_refused(self):
        for pp in (f":{PROJECT}/src:{PROJECT}/ci", f"{PROJECT}/src:{PROJECT}/ci:", f"{PROJECT}/src::{PROJECT}/ci"):
            with self.subTest(pp=pp):
                run = self.run_ci(self._repo(), pythonpath=pp)
                self.assertRed(run)
                self.assertIn("P02CI_STARTUP_UNSAFE", run.summary)

    def test_relative_or_foreign_pythonpath_refused(self):
        for pp in (f"src:{PROJECT}/ci", f"{PROJECT}/src:{PROJECT}/ci:/tmp", f"{PROJECT}/ci:{PROJECT}/src"):
            with self.subTest(pp=pp):
                run = self.run_ci(self._repo(), pythonpath=pp)
                self.assertRed(run)
                self.assertIn("P02CI_STARTUP_UNSAFE", run.summary)

    def test_unexpected_environment_variable_refused(self):
        for extra in ({"PYTHONSTARTUP": "/tmp/x.py"}, {"PYTHONHOME": "/usr"}, {"HOME": "/root"},
                      {"GITHUB_TOKEN": "synthetic"}, {"PYTHONINSPECT": "1"}, {"GIT_DIR": "/tmp"}):
            with self.subTest(extra=list(extra)):
                run = self.run_ci(self._repo(), env_extra=extra)
                self.assertRed(run)
                self.assertIn("P02CI_STARTUP_UNSAFE", run.summary)

    def test_ld_library_path_only_if_absolute_without_empty_segments(self):
        run = self.run_ci(self._repo(), env_extra={"LD_LIBRARY_PATH": "/opt/hostedtoolcache/Python/lib"})
        self.assertGreen(run)
        for bad in ("", ":/opt/lib", "lib", "/opt/lib:"):
            with self.subTest(bad=bad):
                run = self.run_ci(self._repo(), env_extra={"LD_LIBRARY_PATH": bad})
                self.assertRed(run)

    def test_cwd_inside_pr_checkout_refused(self):
        repo = self._repo()
        run = self.run_ci(repo, cwd=repo.path)
        self.assertRed(run)
        self.assertIn("P02CI_STARTUP_UNSAFE", run.summary)

    def test_non_empty_cwd_refused(self):
        work = os.path.join(self.tmp, "busy")
        os.makedirs(work)
        open(os.path.join(work, "something"), "w").close()
        run = self.run_ci(self._repo(), cwd=work)
        self.assertRed(run)
        self.assertIn("P02CI_STARTUP_UNSAFE", run.summary)

    def test_missing_runner_temp_or_outputs_is_red(self):
        for key in ("RUNNER_TEMP", "P02_BASE_SHA", "P02_HEAD_SHA"):
            with self.subTest(key=key):
                run = self.run_ci(self._repo(), env_drop=(key,))
                self.assertRed(run)

    def test_bad_sha_values_are_technical_failure(self):
        repo = self._repo()
        for base in ("main", "HEAD~1", "-p", repo.base[:39], repo.base + "0", "--output=/tmp/x"):
            with self.subTest(base=base):
                run = self.run_ci(repo, base=base)
                self.assertRed(run)
                self.assertRow(run, 1)


class ImportShadowingTests(TmpCase):
    """E2E-33: PR-supplied p02review/, p02ci/, sitecustomize.py, stdlib-named modules never execute."""

    def _marker_files(self):
        return [n for n in os.listdir("/tmp") if n.startswith(MARKER)]

    def setUp(self):
        super().setUp()
        for n in self._marker_files():
            os.unlink(os.path.join("/tmp", n))

    def tearDown(self):
        for n in self._marker_files():
            os.unlink(os.path.join("/tmp", n))

    def test_e2e33_shadow_modules_at_root_and_in_package_never_run(self):
        head = {}
        head.update(shadow_files(""))
        head.update(shadow_files("p02-demo/c03/"))
        head.update(package("p02-demo/c03", corpus_files("c03-tf-public-admin-ingress")))
        repo = self.repo({}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertNotIn(MARKER, run.all_text())
        self.assertEqual(self._marker_files(), [])
        self.assertRow(run, 4)  # trusted P02 ran: TF-NET-001 confirmed
        self.assertIn("TF-NET-001", run.summary)
        self.assertIn("### Changed but not reviewed", run.summary)  # the shadow files are reported (row 4 wins)

    def test_e2e33_shadow_modules_in_working_directory_never_run(self):
        work = os.path.join(self.tmp, "hostile-cwd")
        os.makedirs(work)
        # Even if an attacker controlled the cwd contents, -P plus the empty-cwd assertion prevent execution.
        from cisupport import write_tree
        write_tree(work, shadow_files(""))
        repo = self.repo({}, {"docs/a.md": "x\n"})
        run = self.run_ci(repo, cwd=work)
        self.assertNotIn(MARKER, run.all_text())
        self.assertEqual(self._marker_files(), [])
        self.assertRed(run)  # non-empty cwd refused

    def test_e2e33_control_run_without_P_from_pr_directory_shows_attack_is_real(self):
        work = os.path.join(self.tmp, "pr-like")
        os.makedirs(work)
        from cisupport import write_tree
        write_tree(work, shadow_files(""))
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": f"{PROJECT}/src", "PYTHONDONTWRITEBYTECODE": "1"}
        p = subprocess.run([sys.executable, "-B", "-m", "p02review", "--help"], env=env, cwd=work,
                           capture_output=True, text=True)
        self.assertIn(MARKER, p.stderr)  # without -P the cwd copy shadows the trusted analyser
        p = subprocess.run([sys.executable, "-P", "-s", "-B", "-m", "p02review", "--help"], env=env, cwd=work,
                           capture_output=True, text=True)
        self.assertNotIn(MARKER, p.stderr + p.stdout)

    def test_e2e33_control_empty_pythonpath_segment_reenables_sitecustomize(self):
        work = os.path.join(self.tmp, "pr-like")
        os.makedirs(work)
        from cisupport import write_tree
        write_tree(work, {"sitecustomize.py": f"import sys\nsys.stderr.write('{MARKER}\\n')\n"})
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": f"{PROJECT}/src:", "PYTHONDONTWRITEBYTECODE": "1"}
        p = subprocess.run([sys.executable, "-P", "-s", "-B", "-c", "pass"], env=env, cwd=work,
                           capture_output=True, text=True)
        self.assertIn(MARKER, p.stderr)  # why the adapter refuses empty segments

    def test_p02_subprocess_environment_is_exactly_allowlisted(self):
        from p02ci import runner
        env = runner.p02_env({"PATH": "/usr/bin:/bin", "PYTHONPATH": "/t/src:/t/ci", "RUNNER_TEMP": "/rt",
                              "GITHUB_OUTPUT": "/o", "GITHUB_STEP_SUMMARY": "/s", "P02_BASE_SHA": "a" * 40,
                              "P02_HEAD_SHA": "b" * 40, "PYTHONDONTWRITEBYTECODE": "1"}, "/t")
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "PYTHONPATH": "/t/src", "PYTHONDONTWRITEBYTECODE": "1"})
        env = runner.p02_env({"PATH": "/usr/bin", "LD_LIBRARY_PATH": "/opt/py/lib"}, "/t")
        self.assertEqual(env["LD_LIBRARY_PATH"], "/opt/py/lib")
        self.assertEqual(set(env), {"PATH", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "LD_LIBRARY_PATH"})

    def test_p02_command_uses_isolation_flags_and_argument_list(self):
        from p02ci import runner
        cmd = runner.p02_command("/usr/bin/python3", "review", "/rt/p02/1/fixture", ["--out-dir", "/rt/o"])
        self.assertEqual(cmd[:6], ["/usr/bin/python3", "-P", "-s", "-B", "-m", "p02review"])
        self.assertIsInstance(cmd, list)


if __name__ == "__main__":
    unittest.main()
