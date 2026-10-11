"""Credential handling: E2E-11, E2E-12 and focused leakage cases (summary, log, outputs).

Credential shapes are assembled at runtime and never printed; assertions only check absence.
"""
import json
import unittest

from cisupport import AWS_KEY, GH_TOKEN, PEM, SECRETS, TmpCase, manifest

BENIGN = 'locals {\n  a = 1\n}\n'


def pkg(name, files_decl, contents, **m):
    d = {f"p02-demo/{name}/p02-manifest.json": manifest(files_decl, name, **m)}
    d.update({f"p02-demo/{name}/{k}": v for k, v in contents.items()})
    return d


class CredentialE2E(TmpCase):
    def _assert_row2(self, run, *needles):
        self.assertRow(run, 2)
        self.assertRed(run)
        self.assertEqual(run.ack, "required")
        self.assertNoLeak(run, *(needles or SECRETS))
        self.assertIn("rotate the credential", run.summary)
        self.assertNotIn("#### Findings", run.summary)

    def test_e2e11_key_shape_in_resource_identifier(self):
        tf = f'resource "aws_s3_bucket" "b_{AWS_KEY}" {{\n  bucket = "x"\n}}\n'
        repo = self.repo({"README.md": "r\n"}, pkg("s11", ["main.tf"], {"main.tf": tf}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._assert_row2(run)
        self.assertIn("aws-access-key-id", run.summary)  # screen rule ID only
        self.assertIn("`main.tf`", run.summary)          # file through display_path

    def test_e2e12_credential_in_plan_value(self):
        plan = {"format_version": "1.2", "resource_changes": [
            {"address": "aws_iam_access_key.k", "type": "aws_iam_access_key", "name": "k", "mode": "managed",
             "change": {"actions": ["create"], "after": {"id": AWS_KEY, "token": GH_TOKEN}}}]}
        repo = self.repo({"README.md": "r\n"}, pkg("s12", [{"path": "plan.json", "kind": "terraform-plan"}],
                                                   {"plan.json": json.dumps(plan)}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._assert_row2(run)

    def test_e2e12_escaped_credential_in_hcl(self):
        escaped = "".join("\\u%04x" % ord(c) for c in AWS_KEY)
        tf = f'locals {{\n  k = "{escaped}"\n}}\n'
        repo = self.repo({"README.md": "r\n"}, pkg("s12b", ["main.tf"], {"main.tf": tf}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._assert_row2(run)

    def test_private_key_block_in_yaml(self):
        y = f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\nstringData:\n  k: \"{PEM}\"\n"
        repo = self.repo({"README.md": "r\n"}, pkg("pem", [{"path": "s.yaml", "kind": "kubernetes"}], {"s.yaml": y}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self._assert_row2(run)

    def test_credential_in_manifest_description(self):
        repo = self.repo({"README.md": "r\n"}, pkg("md", ["main.tf"], {"main.tf": BENIGN},
                                                   description="key " + AWS_KEY))
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRed(run)
        self.assertIn(run.summary.split("\n", 1)[0][len("## P02 Infrastructure Risk Review -- "):][:7],
                      ("BLOCKED", "INPUT R"))
        self.assertNoLeak(run)

    def test_secret_row2_outranks_other_package_review_required(self):
        from cisupport import corpus_files, package
        head = package("p02-demo/c03", corpus_files("c03-tf-public-admin-ingress"))
        head.update(pkg("sec", ["main.tf"], {"main.tf": f'locals {{\n  t = "{GH_TOKEN}"\n}}\n'}))
        repo = self.repo({"README.md": "r\n"}, head)
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 2)
        self.assertNoLeak(run)
        self.assertIn("TF-NET-001", run.summary)  # the trustworthy package is still reported

    def test_credential_in_unreviewed_file_is_not_displayed_and_row6_says_not_screened(self):
        repo = self.repo({"README.md": "r\n"}, {"infra/creds.tf": f'k = "{AWS_KEY}"\n'})
        run = self.run_ci(repo, trusted=self.env_trusted)
        self.assertRow(run, 6)
        self.assertNoLeak(run)
        self.assertIn("not screened for credentials", run.summary)

    def test_logs_contain_only_fixed_format_lines(self):
        tf = f'resource "aws_s3_bucket" "b_{AWS_KEY}" {{\n  bucket = "x"\n}}\n'
        repo = self.repo({"README.md": "r\n"}, pkg("s11", ["main.tf"], {"main.tf": tf}))
        run = self.run_ci(repo, trusted=self.env_trusted)
        for line in (run.stdout + run.stderr).splitlines():
            self.assertRegex(line, r"^p02ci: [a-z_]+( [a-z0-9_]+=[A-Za-z0-9_.:/-]*)*$", line)


if __name__ == "__main__":
    unittest.main()
