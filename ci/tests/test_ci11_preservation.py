"""Accepted-core preservation: the Phase 3B-1 R1 inventory still verifies, no file was added to the frozen
core, schema, narrative harness or accepted tests, and no bytecode cache exists in the project tree.
"""
import hashlib
import os
import unittest

from cisupport import ACCEPTED_CORE_DIGEST, PROJECT, core_digest

FROZEN_DIRS = ("src", "schema", "narrate", "tests", "examples", "tools")


def inventory():
    entries = {}
    with open(os.path.join(PROJECT, "FILE_INVENTORY_PHASE3B1_R1.sha256"), encoding="utf-8") as fh:
        for line in fh:
            digest, rel = line.rstrip("\n").split("  ", 1)
            entries[rel[2:] if rel.startswith("./") else rel] = digest
    return entries


class PreservationTests(unittest.TestCase):
    def test_core_digest_unchanged(self):
        self.assertEqual(core_digest(PROJECT), ACCEPTED_CORE_DIGEST)

    def test_accepted_inventory_verifies(self):
        inv = inventory()
        self.assertGreater(len(inv), 2000)
        bad = []
        for rel, digest in inv.items():
            with open(os.path.join(PROJECT, rel), "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != digest:
                    bad.append(rel)
        self.assertEqual(bad, [])

    def test_no_new_files_in_frozen_trees(self):
        inv = set(inventory())
        extra = []
        for top in FROZEN_DIRS:
            for dirpath, dirs, names in os.walk(os.path.join(PROJECT, top)):
                for n in names:
                    rel = os.path.relpath(os.path.join(dirpath, n), PROJECT).replace(os.sep, "/")
                    if rel not in inv:
                        extra.append(rel)
        self.assertEqual(extra, [])

    def test_no_bytecode_cache_in_project(self):
        found = [d for d, dirs, _ in os.walk(PROJECT) if os.path.basename(d) == "__pycache__"]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
