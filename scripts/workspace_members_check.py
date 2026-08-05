#!/usr/bin/env python3
"""Every crate in the tree must be a workspace member.

A crate directory that exists but is absent from `[workspace] members` is
still committed, still reviewed, and never built, linted or tested: CI is
green because the workspace does not contain it. That is the same failure
shape as a workflow GitHub accepts and never runs, and this repository has
already been bitten by that class once.

Exit 1 if any `crates/*/Cargo.toml` is missing from the members list.
"""

import re
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    manifest = (root / "Cargo.toml").read_text(encoding="utf-8")
    block = re.search(r"members\s*=\s*\[(.*?)\]", manifest, re.S)
    if not block:
        print("::error::no [workspace] members list found in Cargo.toml")
        return 1
    declared = set(re.findall(r'"([^"]+)"', block.group(1)))

    present = {
        f"crates/{d.name}"
        for d in sorted((root / "crates").iterdir())
        if (d / "Cargo.toml").is_file()
    }

    missing = sorted(present - declared)
    stale = sorted(d for d in declared - present if d.startswith("crates/"))

    if missing:
        print(
            "::error::workspace membership: crate directories exist but are not "
            "workspace members, so nothing builds, lints or tests them."
        )
        for m in missing:
            print(f"  not a member: {m}")
    for s in stale:
        print(f"::error::workspace membership: member has no crate directory: {s}")

    if missing or stale:
        return 1
    print(f"workspace membership gate passed: {len(present)} crates, all members.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
