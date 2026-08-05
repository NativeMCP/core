#!/usr/bin/env python3
"""RC-11 / RC-19 vendor-name gate over the kernel crates.

NMCP-SPEC-003 RC-11 requires that the kernel names no vendor, and RC-D9 gives
the reason: a vendor name compiled into `Permission` is the same defect as a
vendor name compiled into the dispatcher, one crate deeper and harder to see.
RC-19 makes it concrete for Microsoft 365, which leaves the kernel entirely and
reaches the server through the gateway as an upstream like any other.

Scope: production Rust in `nmcp-policy`, `nmcp-proto`, `nmcp-router` and
`nmcp-host`. Modelled on `scripts/inv1_scan.py`: `#[cfg(test)]` modules are
excluded by brace depth and comments are stripped, because a test fixture named
after somebody's product is a fixture, and a sentence in a doc comment is not a
coupling. Both are excluded on purpose and that is a deliberate limit of this
gate, not an oversight.

Platform names are NOT vendor names here. `win.api`, `win.api.write` and the
`win_*` tools survive RC-D9 by design: they name a platform capability the
policy enum genuinely gates, and NMCP-SPEC-003 G-3 keeps them while recording
the closed-vocabulary limit they sit inside. This gate would be dishonest if it
pretended otherwise, so `windows` is not on the list below.

One exception, named here rather than left implicit, exactly as RC-11 names
`DELETE_DENIED_NAMES` as its one exception: the `RETIRED_PERMISSIONS` table in
`nmcp-policy`. RC-19 requires that a policy file granting `m365` be refused with
a message naming the replacement, and a refusal cannot name what it refuses
without saying the name. The exception is one named constant in one file, and
the gate fails if it is missing, so it cannot quietly widen into a second home
for the coupling.

Exit 1 on any violation in production code; 0 otherwise.
"""

import re
import subprocess
import sys

# Crates the gate covers. `nmcp-policy` is here because the deepest instance of
# the coupling was there, in the crate that decides authority, rather than in
# the one that dispatches (RC-11).
SCOPED_DIRS = (
    "crates/nmcp-policy/src/",
    "crates/nmcp-proto/src/",
    "crates/nmcp-router/src/",
    "crates/nmcp-host/src/",
)

# Commercial product and service names. Each one, appearing in kernel
# production code, means the kernel learned about a specific vendor at build
# time, which is the property RC-A1 denies. Matched case-insensitively on word
# boundaries so `m365_mail_send`, `M365Config` and "Microsoft 365" all hit while
# `dev_dep_graph` and "a graph property" do not.
VENDOR_NAMES = (
    "m365",
    "microsoft",
    "msgraph",
    "office365",
    "o365",
    "sharepoint",
    "onedrive",
    "outlook",
    "entra",
    "azure",
    "google",
    "gmail",
    "gdrive",
    "github",
    "gitlab",
    "bitbucket",
    "slack",
    "atlassian",
    "jira",
    "confluence",
    "salesforce",
    "dropbox",
    "notion",
    "okta",
)

VENDOR = re.compile(
    r"(?<![0-9A-Za-z_])(" + "|".join(VENDOR_NAMES) + r")(?![0-9A-Za-z])",
    re.IGNORECASE,
)

# The one exception, by name. RC-19's refusal message lives here and nowhere
# else.
EXCEPTION_FILE = "crates/nmcp-policy/src/lib.rs"
EXCEPTION_CONST = "RETIRED_PERMISSIONS"
EXCEPTION_OPEN = re.compile(r"\bconst\s+" + EXCEPTION_CONST + r"\b")


def scoped_rs_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "*.rs"], capture_output=True, text=True, check=True
    ).stdout
    return [
        line
        for line in out.splitlines()
        if line and line.startswith(SCOPED_DIRS)
    ]


def strip_block_comments(text: str) -> str:
    # Replace block comments with newline-preserving blanks so line numbers hold.
    return re.sub(
        r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S
    )


def production_violations(path: str) -> tuple[list[str], bool]:
    """Vendor hits in production code, and whether the named exception was seen."""
    text = strip_block_comments(open(path, encoding="utf-8", errors="replace").read())
    lines = text.split("\n")
    hits: list[str] = []
    saw_exception = False
    # Track nesting so a `#[cfg(test)]` module (and everything inside it) is
    # excluded by brace depth, including nested modules and functions.
    depth = 0
    pending_test = False
    test_floor: int | None = None  # depth at which the active cfg(test) block sits
    # The excepted constant is skipped the same way, by the bracket depth of its
    # own initialiser, so the exception cannot leak past its closing bracket.
    exception_depth: int | None = None
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

        if (
            exception_depth is None
            and path == EXCEPTION_FILE
            and EXCEPTION_OPEN.search(code)
        ):
            saw_exception = True
            exception_depth = 0
        if exception_depth is None and not in_test and VENDOR.search(code):
            hits.append(f"{path}:{lineno}: {stripped[:100]}")

        depth += opens - closes
        if test_floor is not None and depth <= test_floor:
            test_floor = None
        if exception_depth is not None:
            exception_depth += code.count("[") - code.count("]")
            if exception_depth <= 0 and ("]" in code or ";" in code):
                exception_depth = None
    return hits, saw_exception


def main() -> int:
    violations: list[str] = []
    exception_present = False
    files = scoped_rs_files()
    if not files:
        print("::error::vendor-name gate found no files in scope; the paths moved.")
        return 1
    for path in files:
        hits, saw_exception = production_violations(path)
        violations.extend(hits)
        exception_present = exception_present or saw_exception

    if not exception_present:
        print(
            "::error::the RC-19 exception "
            f"({EXCEPTION_CONST} in {EXCEPTION_FILE}) is gone. A retired "
            "permission that no longer refuses by name is a permission a "
            "deployment believes it still has."
        )
        return 1

    if violations:
        print(
            "::error::RC-11/RC-19 violation: a vendor name appears in kernel "
            "production code. The kernel names no vendor: an integration reaches "
            "the server through the gateway as an upstream."
        )
        for v in violations:
            print(v)
        return 1

    print(
        f"vendor-name gate passed: {len(files)} files across "
        f"{len(SCOPED_DIRS)} kernel crates, no vendor name in production code "
        f"(cfg(test) modules and comments are out of scope; {EXCEPTION_CONST} "
        "is the one named exception, RC-19)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
