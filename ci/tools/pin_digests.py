"""Print the core build digest and the adapter digest of a trusted tree (default: this checkout), or update the
`--expect-adapter-digest` pin in .github/workflows/p02-review.yml with --write-workflow.

Usage: python3 -B ci/tools/pin_digests.py [ROOT] [--write-workflow [--replace]]
The workflow pin is the expected value checked by the adapter bootstrap; a pin change is a code-owner-reviewed
change of .github/ (02 sec. 4). Updating the adapter keeps the old pin alongside the new one until the change
has merged (the bootstrap accepts any listed pin).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(os.path.dirname(HERE))
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(PROJECT, "ci"))

from p02ci import bootstrap  # noqa: E402


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = os.path.abspath(args[0]) if args else PROJECT
    core = bootstrap.core_digest(root)
    adapter = bootstrap.adapter_digest(root)
    print(f"core_digest {core}")
    print(f"adapter_digest {adapter}")
    if "--write-workflow" in sys.argv:
        # R4 V4-05: the new adapter pin is *added* after the existing ones (an adapter-update PR is judged by its
        # base bundle, so the old pin must stay until the change has merged; remove it in a follow-up change).
        # --replace drops the old adapter pins (used while developing this change, before any deployment).
        # R5 V5-02: only the single `exec env -i ... -m p02ci` command line is rewritten; it must exist and carry
        # at least one adapter pin. The core pin is never changed by this tool.
        wf = os.path.join(root, ".github", "workflows", "p02-review.yml")
        with open(wf, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        idx = [i for i, line in enumerate(lines) if line.lstrip().startswith("exec env -i ") and " -m p02ci " in line]
        if len(idx) != 1:
            sys.exit("pin_digests: expected exactly one adapter command line in the workflow")
        line = lines[idx[0]]
        pins = re.findall(r" --expect-adapter-digest ([0-9a-f]{64}|ADAPTER_DIGEST_PLACEHOLDER)", line)
        if not pins:
            sys.exit("pin_digests: the adapter command line carries no --expect-adapter-digest pin")
        keep = [] if ("--replace" in sys.argv or pins == ["ADAPTER_DIGEST_PLACEHOLDER"]) else \
            [p for p in pins if p != "ADAPTER_DIGEST_PLACEHOLDER"]
        if adapter not in keep:
            keep.append(adapter)
        new_line = re.sub(r"( --expect-adapter-digest (?:[0-9a-f]{64}|ADAPTER_DIGEST_PLACEHOLDER))+",
                          lambda _m: "".join(f" --expect-adapter-digest {p}" for p in keep), line, count=1)
        if len(keep) > 2:
            print(f"warning: {len(keep)} adapter pins; remove superseded pins once their change has merged")
        if new_line != line:
            lines[idx[0]] = new_line
            with open(wf, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            print("workflow pin updated")

if __name__ == "__main__":
    main()
