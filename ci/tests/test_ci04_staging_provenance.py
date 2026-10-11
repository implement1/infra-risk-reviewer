"""Staging, bounded reads, adapter refusals and the Mode A synthetic-only boundary.

Covers E2E-13 (missing / symlink / non-regular / hard link / symlinked manifest / refusal plus credential),
E2E-14 (oversize), E2E-15 (declared unsafe paths, judged by the core), E2E-18 and A-6 (provenance).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from cisupport import (AWS_KEY, BANNER, PROJECT, SRC, TmpCase, corpus_files, corpus_cases, manifest, package,
                       write_tree)

BENIGN = corpus_files("c01-tf-benign-scoped")["main.tf"]


def pkg(files_decl, contents, fixture_id="pkg", **mextra):
    d = {"p02-demo/pkg/p02-manifest.json": manifest(files_decl, fixture_id, **mextra)}
    d.update({f"p02-demo/pkg/{k}": v for k, v in contents.items()})
    return d


class StageUnitTests(TmpCase):
    def _stage(self, files):
        from p02ci import stage
        base = tempfile.mkdtemp(dir=self.tmp)
        root = os.path.join(base, "prtree")
        os.makedirs(root)
        write_tree(root, files)
        dest = os.path.join(base, "stage")
        return stage.stage_package(root, "p02-demo/pkg", dest), dest

    def test_regular_files_copied_byte_identical(self):
        res, dest = self._stage(pkg(["main.tf", "sub/b.tf"], {"main.tf": BENIGN, "sub/b.tf": BENIGN}))
        self.assertEqual(res.refusals, [])
        with open(os.path.join(dest, "main.tf"), "rb") as fh:
            self.assertEqual(fh.read(), BENIGN)
        self.assertTrue(os.path.isfile(os.path.join(dest, "p02-manifest.json")))
        self.assertEqual(sorted(res.declared), ["main.tf", "sub/b.tf"])

    def test_undeclared_files_are_not_staged(self):
        res, dest = self._stage(pkg(["main.tf"], {"main.tf": BENIGN, "other.tf": BENIGN}))
        self.assertFalse(os.path.exists(os.path.join(dest, "other.tf")))

    def test_symlink_file_refused_and_not_followed(self):
        secret_target = os.path.join(self.tmp, "outside.tf")
        with open(secret_target, "w") as fh:
            fh.write("outside\n")
        res, dest = self._stage(pkg(["main.tf", "l.tf"], {"main.tf": BENIGN, "l.tf": ("symlink", secret_target)}))
        self.assertIn(("P02CI_PATH_SYMLINK", "l.tf"), res.refusals)
        self.assertFalse(os.path.lexists(os.path.join(dest, "l.tf")))

    def test_symlinked_directory_component_refused(self):
        outside = os.path.join(self.tmp, "outdir")
        os.makedirs(outside)
        with open(os.path.join(outside, "x.tf"), "wb") as fh:
            fh.write(BENIGN)
        res, dest = self._stage(pkg(["d/x.tf"], {"d": ("symlink", outside)}))
        self.assertIn(("P02CI_PATH_SYMLINK", "d/x.tf"), res.refusals)
        self.assertFalse(os.path.lexists(os.path.join(dest, "d")))

    def test_fifo_refused_as_not_regular(self):
        from p02ci import stage
        root = os.path.join(self.tmp, "prtree")
        write_tree(root, pkg(["main.tf", "f.tf"], {"main.tf": BENIGN}))
        os.mkfifo(os.path.join(root, "p02-demo", "pkg", "f.tf"))
        res = stage.stage_package(root, "p02-demo/pkg", os.path.join(self.tmp, "stage"))
        self.assertIn(("P02CI_NOT_REGULAR", "f.tf"), res.refusals)

    def test_directory_where_file_declared_refused_as_not_regular(self):
        res, _ = self._stage(pkg(["main.tf", "dir.tf"], {"main.tf": BENIGN, "dir.tf/x": "y"}))
        self.assertIn(("P02CI_NOT_REGULAR", "dir.tf"), res.refusals)

    def test_hard_link_refused(self):
        res, _ = self._stage(pkg(["main.tf", "h.tf"], {"main.tf": BENIGN, "h.tf": ("hardlink", "p02-demo/pkg/main.tf")}))
        self.assertIn(("P02CI_HARDLINK", "h.tf"), res.refusals)
        self.assertIn(("P02CI_HARDLINK", "main.tf"), res.refusals)  # both names share the inode

    def test_symlinked_manifest_refused(self):
        root_files = {"p02-demo/real.json": manifest(["main.tf"]), "p02-demo/pkg/main.tf": BENIGN,
                      "p02-demo/pkg/p02-manifest.json": ("symlink", "../real.json")}
        res, dest = self._stage(root_files)
        self.assertIn(("P02CI_MANIFEST_SYMLINK", "p02-manifest.json"), res.refusals)
        self.assertFalse(os.path.exists(os.path.join(dest, "main.tf")))

    def test_non_regular_manifest_refused(self):
        res, _ = self._stage({"p02-demo/pkg/p02-manifest.json/x": "y", "p02-demo/pkg/main.tf": BENIGN})
        self.assertIn(("P02CI_MANIFEST_NOT_REGULAR", "p02-manifest.json"), res.refusals)

    def test_bounded_read_of_oversized_file_and_manifest(self):
        from p02review.limits import DEFAULT_LIMITS
        big = b"#" * (DEFAULT_LIMITS.max_file_bytes + 5000)
        res, dest = self._stage(pkg(["big.tf"], {"big.tf": big}))
        self.assertEqual(os.path.getsize(os.path.join(dest, "big.tf")), DEFAULT_LIMITS.max_file_bytes + 1)
        mbig = manifest(["a.tf"]) + " " * (DEFAULT_LIMITS.max_manifest_bytes + 100)
        res, dest = self._stage({"p02-demo/pkg/p02-manifest.json": mbig, "p02-demo/pkg/a.tf": BENIGN})
        self.assertEqual(os.path.getsize(os.path.join(dest, "p02-manifest.json")),
                         DEFAULT_LIMITS.max_manifest_bytes + 1)
        self.assertFalse(os.path.exists(os.path.join(dest, "a.tf")))

    def test_audit_hook_nothing_outside_package_is_opened(self):
        from p02ci import stage
        root = os.path.join(self.tmp, "prtree")
        outside = os.path.join(self.tmp, "outside.tf")
        with open(outside, "w") as fh:
            fh.write("x\n")
        write_tree(root, pkg(["main.tf", "l.tf", "d/x.tf"], {"main.tf": BENIGN, "l.tf": ("symlink", outside),
                                                             "d": ("symlink", self.tmp)}))
        write_tree(root, {"p02-demo/sibling.tf": BENIGN})
        dest = os.path.join(self.tmp, "stage")
        pkgdir = os.path.realpath(os.path.join(root, "p02-demo", "pkg"))
        opened = []

        def hook(event, args):
            if event == "open" and args and isinstance(args[0], (str, bytes)):
                opened.append(os.fsdecode(args[0]))
        sys.addaudithook(hook)
        recording = []
        opened.clear()
        stage.stage_package(root, "p02-demo/pkg", dest)
        recording.extend(opened)
        opened.clear()
        ancestors = set()
        d = pkgdir
        while d != os.path.dirname(d):
            ancestors.add(d)
            d = os.path.dirname(d)
        for p in recording:
            rp = os.path.realpath(p) if os.path.isabs(p) else p
            # Absolute opens: the package's ancestor directories (directory descriptors for the O_NOFOLLOW
            # component walk), or the staging destination. Relative opens are dir_fd-relative component opens.
            self.assertTrue(rp in ancestors or rp.startswith(os.path.realpath(dest)) or not os.path.isabs(p),
                            f"opened outside package: {p}")
        self.assertFalse(any(os.path.realpath(p) == os.path.realpath(outside) for p in recording if os.path.isabs(p)))

    def test_core_view_accepts_exactly_what_p02_accepts(self):
        """02 sec. 7.3: the adapter's accepted set equals P02's for every corpus manifest and E2E-15 variant."""
        from p02ci import stage
        variants = [corpus_files(c)["p02-manifest.json"] for c in corpus_cases()]
        for bad in ("my file.tf", "../x.tf", "/abs.tf", "C:x.tf", "a\\b.tf", "а.tf", "a\x01.tf", "./a.tf",
                    "a//b.tf", "A.tf\nB.tf", "p02-manifest.json", "x" * 241 + ".tf", "/".join(["d"] * 13) + ".tf"):
            variants.append(manifest([bad]).encode())
        variants.append(manifest(["a.tf", "A.TF"]).encode())
        variants.append(b'{"manifest_version": "2", "manifest_version": "2"}')
        variants.append(manifest(["a.tf"], origin="authorized_pr").encode())
        for raw in variants:
            with self.subTest(raw=raw[:60]):
                view = stage.core_view(raw)
                d = os.path.join(self.tmp, "v")
                os.makedirs(d, exist_ok=True)
                for n in os.listdir(d):
                    os.unlink(os.path.join(d, n))
                with open(os.path.join(d, "p02-manifest.json"), "wb") as fh:
                    fh.write(raw)
                accepted = view.accepted
                if accepted:
                    for rel in view.declared:
                        full = os.path.join(d, rel)
                        os.makedirs(os.path.dirname(full), exist_ok=True)
                        with open(full, "wb") as fh:
                            fh.write(b"locals {}\n" if rel.endswith((".tf", ".tfvars")) else b"{}\n")
                env = {"PATH": os.environ["PATH"], "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}
                p = subprocess.run([sys.executable, "-P", "-s", "-B", "-m", "p02review", "review", d, "--quiet"],
                                   env=env, capture_output=True, cwd=self.tmp)
                result = json.loads(p.stdout)
                p02_manifest_ok = not any(e["code"].startswith(("MANIFEST", "ORIGIN", "PATH", "FILE_COUNT",
                                                                "PROVENANCE"))
                                          for e in result.get("errors", []))
                self.assertEqual(accepted, p02_manifest_ok, [e["code"] for e in result.get("errors", [])])
                import shutil
                shutil.rmtree(d)


class StagingE2E(TmpCase):
    def test_e2e13_missing_declared_file_is_p02_file_missing_row3(self):
        repo = self.repo({"README.md": "r\n"}, pkg(["main.tf", "gone.tf"], {"main.tf": BENIGN}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertRed(run)
        self.assertIn("FILE_MISSING", run.summary)
        self.assertNotIn("TECHNICAL FAILURE", run.summary)

    def test_e2e13_symlink_refusal_is_row3_input_rejected(self):
        repo = self.repo({"README.md": "r\n"}, pkg(["main.tf", "l.tf"], {"main.tf": BENIGN,
                                                                        "l.tf": ("symlink", "main.tf")}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertIn("P02CI_PATH_SYMLINK", run.summary)
        self.assertIn("FILE_MISSING", run.summary)  # P02 still ran on the rest and reported the refused entry
        self.assertNotIn("TECHNICAL FAILURE", run.summary)
        self.assertEqual(run.ack, "required")

    def test_e2e13_symlinked_manifest_is_row3(self):
        files = {"p02-demo/real.json": manifest(["main.tf"]), "p02-demo/pkg/main.tf": BENIGN,
                 "p02-demo/pkg/p02-manifest.json": ("symlink", "../real.json")}
        repo = self.repo({"README.md": "r\n"}, files)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertIn("P02CI_MANIFEST_SYMLINK", run.summary)

    def test_e2e13_symlink_plus_credential_is_row2_not_hidden(self):
        cred = f'resource "aws_s3_bucket" "b" {{\n  bucket = "{AWS_KEY.lower()}x"\n  tags = {{ k = "{AWS_KEY}" }}\n}}\n'
        repo = self.repo({"README.md": "r\n"}, pkg(["main.tf", "l.tf", "c.tf"],
                                                  {"main.tf": BENIGN, "l.tf": ("symlink", "main.tf"), "c.tf": cred}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 2)
        self.assertIn("rotate the credential", run.summary)
        self.assertIn("P02CI_PATH_SYMLINK", run.summary)
        self.assertNoLeak(run, AWS_KEY)

    def test_e2e14_oversized_file_is_p02_file_too_large(self):
        big = b"# filler\n" * 33400  # about 300 KB
        repo = self.repo({"README.md": "r\n"}, pkg(["big.tf"], {"big.tf": big}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertIn("FILE_TOO_LARGE", run.summary)
        self.assertNotIn("#### Findings", run.summary)

    def test_e2e14_total_size_exceeded(self):
        chunk = b"# f\n" * 60000  # 240 KB each, 9 files > 2 MiB
        decl = [f"f{i}.tf" for i in range(9)]
        repo = self.repo({"README.md": "r\n"}, pkg(decl, {n: chunk for n in decl}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertIn("TOTAL_SIZE_EXCEEDED", run.summary)

    def test_e2e14_file_count_exceeded(self):
        decl = [f"f{i}.tf" for i in range(201)]
        repo = self.repo({"README.md": "r\n"}, pkg(decl, {n: "locals {}\n" for n in decl}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertIn("FILE_COUNT_EXCEEDED", run.summary)

    def test_e2e14_manifest_too_large_reported_by_p02(self):
        mbig = manifest(["a.tf"], description="x" * 10) + " " * (64 * 1024 + 10)
        repo = self.repo({"README.md": "r\n"}, {"p02-demo/pkg/p02-manifest.json": mbig, "p02-demo/pkg/a.tf": BENIGN})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertIn("MANIFEST_TOO_LARGE", run.summary)

    def test_e2e15_unsafe_declared_paths_rejected_by_core_and_not_echoed(self):
        for bad, code in (("my file.tf", "PATH_INVALID"), ("../x.tf", "PATH_TRAVERSAL"),
                          ("/etc/passwd.tf", "PATH_ABSOLUTE"), ("аdmin.tf", "PATH_INVALID"),
                          ("a\x07.tf", "PATH_INVALID")):
            with self.subTest(code=code, bad=bad.encode("unicode_escape")):
                repo = self.repo({"README.md": "r\n"}, pkg([bad], {}))
                run = self.run_ci(repo, trusted=self.env_trusted)
                self.assertRow(run, 3)
                self.assertIn(code, run.summary)
                self.assertNotIn(bad, run.all_text())
                self.assertSummaryAscii(run)

    def test_e2e18_authorized_pr_origin_rejected(self):
        repo = self.repo({"README.md": "r\n"}, pkg(["main.tf"], {"main.tf": BENIGN}, origin="authorized_pr"))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertIn("ORIGIN_UNSUPPORTED", run.summary)
        self.assertRed(run)

    def test_e2e18_local_snapshot_and_unknown_origin_rejected(self):
        for origin in ("local_snapshot", "github", "FIXTURE"):
            with self.subTest(origin=origin):
                repo = self.repo({"README.md": "r\n"}, pkg(["main.tf"], {"main.tf": BENIGN}, origin=origin))
                run = self.run_ci(repo, trusted=self.env_trusted)
                self.assertRow(run, 3)
                self.assertIn("ORIGIN_UNSUPPORTED", run.summary)

    def test_e2e18_provenance_synthetic_false_rejected_by_core(self):
        files = pkg(["main.tf"], {"main.tf": BENIGN})
        m = json.loads(files["p02-demo/pkg/p02-manifest.json"])
        m["provenance"]["synthetic"] = False
        files["p02-demo/pkg/p02-manifest.json"] = json.dumps(m)
        repo = self.repo({"README.md": "r\n"}, files)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)
        self.assertIn("PROVENANCE_NOT_SYNTHETIC", run.summary)

    def test_a6_missing_provenance_refused_by_adapter(self):
        for prov in (None, {}, {"author": "someone"}):
            with self.subTest(prov=prov):
                files = pkg(["main.tf"], {"main.tf": BENIGN})
                m = json.loads(files["p02-demo/pkg/p02-manifest.json"])
                if prov is None:
                    del m["provenance"]
                else:
                    m["provenance"] = prov
                files["p02-demo/pkg/p02-manifest.json"] = json.dumps(m)
                repo = self.repo({"README.md": "r\n"}, files)
                run = self.run_ci(repo, trusted=self.env_trusted)
                self.assertRow(run, 3)
                self.assertIn("P02CI_PROVENANCE_NOT_DECLARED", run.summary)
                self.assertRed(run)

    def test_a6_provenance_synthetic_string_true_refused(self):
        files = pkg(["main.tf"], {"main.tf": BENIGN})
        m = json.loads(files["p02-demo/pkg/p02-manifest.json"])
        m["provenance"]["synthetic"] = "true"
        files["p02-demo/pkg/p02-manifest.json"] = json.dumps(m)
        repo = self.repo({"README.md": "r\n"}, files)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 3)

    def test_a6_footer_states_provenance_is_declared_by_submitter(self):
        repo = self.repo({"README.md": "r\n"}, package("p02-demo/c01", corpus_files("c01-tf-benign-scoped")))
        run = self.run_ci(repo)
        self.assertIn("declared by the submitter", run.summary)

    def test_no_terraform_helm_or_shell_executed(self):
        # A package whose files look like scripts; nothing is executed (the adapter only reads bytes).
        marker = os.path.join(self.tmp, "executed")
        script = f"#!/bin/sh\ntouch {marker}\n"
        repo = self.repo({"README.md": "r\n"}, {"p02-demo/pkg/p02-manifest.json": manifest(["main.tf"]),
                                                 "p02-demo/pkg/main.tf": BENIGN, "p02-demo/pkg/run.sh": script,
                                                 "p02-demo/pkg/Makefile": f"all:\n\ttouch {marker}\n",
                                                 "terraform": script, "helm": script, "git": script})
        for name in ("p02-demo/pkg/run.sh", "terraform", "helm", "git"):
            os.chmod(os.path.join(repo.path, name), 0o755)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertFalse(os.path.exists(marker))
        self.assertRow(run, 6)  # run.sh and Makefile are undeclared in the package
        # A PATH that reaches into the PR checkout (or is relative / has empty segments) is refused, so a
        # PR-provided `git` (or any tool) can never substitute for the trusted one.
        for path in (repo.path + ":" + os.environ["PATH"], "bin:" + os.environ["PATH"],
                     ":" + os.environ["PATH"], os.environ["PATH"] + ":"):
            with self.subTest(path=path[:30]):
                run = self.run_ci(repo, trusted=self.env_trusted, env_extra={"PATH": path})
                self.assertFalse(os.path.exists(marker))
                self.assertRed(run)
                self.assertIn("P02CI_STARTUP_UNSAFE", run.summary)


if __name__ == "__main__":
    unittest.main()
