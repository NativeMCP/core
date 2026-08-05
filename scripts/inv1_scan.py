#!/usr/bin/env python3
"""INV-1 destructive-primitive gate.

GOVERNANCE.md INV-1 forbids destructive filesystem primitives "in any
dependency path reachable from a tool handler." This scanner enforces exactly
that scope: it flags the primitives in production code and ignores
`#[cfg(test)]` modules (compiled out of the release binary, never a tool
handler) and comments (a doc mentioning a primitive is not a call).

This replaces a line-oriented `git grep`, which could neither tell a comment
from a call nor a test from a handler, and therefore flagged legitimate
test-only temp-dir cleanup as an INV-1 violation.

Exit 1 on any violation in production code; 0 otherwise.
"""

import re
import subprocess
import sys

PRIMITIVE = re.compile(
    r"\b(remove_file|remove_dir_all|remove_dir|DeleteFileW?|SHFileOperation)\s*\("
)


def rs_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "*.rs"], capture_output=True, text=True, check=True
    ).stdout
    return [line for line in out.splitlines() if line]


def strip_block_comments(text: str) -> str:
    # Replace block comments with newline-preserving blanks so line numbers hold.
    return re.sub(
        r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S
    )


def production_violations(path: str) -> list[str]:
    text = strip_block_comments(open(path, encoding="utf-8", errors="replace").read())
    lines = text.split("\n")
    hits: list[str] = []
    # Track nesting so a `#[cfg(test)]` module (and everything inside it) is
    # excluded by brace depth, including nested modules and functions.
    depth = 0
    pending_test = False
    test_floor: int | None = None  # depth at which the active cfg(test) block sits
    for lineno, raw in enumerate(lines, 1):
        code = raw.split("//", 1)[0]  # drop line/doc comments
        stripped = raw.strip()
        if test_floor is None and stripped.startswith("#[cfg(test)]"):
            pending_test = True
        opens = code.count("{")
        closes = code.count("}")
        if pending_test and opens > 0:
            test_floor = depth  # the block opens at this depth
            pending_test = False
        in_test = test_floor is not None
        if not in_test and PRIMITIVE.search(code):
            hits.append(f"{path}:{lineno}: {stripped[:100]}")
        depth += opens - closes
        if test_floor is not None and depth <= test_floor:
            test_floor = None
    return hits


def main() -> int:
    violations: list[str] = []
    for path in rs_files():
        violations.extend(production_violations(path))
    if violations:
        print(
            "::error::INV-1 violation: destructive filesystem primitive in "
            "production (non-test) Rust source."
        )
        for v in violations:
            print(v)
        return 1
    print(
        "INV-1 gate passed: no destructive primitive in production code "
        "(cfg(test) modules and comments are out of INV-1 scope)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
