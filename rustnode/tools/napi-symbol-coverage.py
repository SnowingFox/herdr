#!/usr/bin/env python3
"""Fails when a Node-API entry point the oracle exports is neither exported here nor declared.

The defect this exists for
--------------------------

Node exports 161 `napi_*`/`node_api_*` symbols; a build of this runtime exported 90
and declared 55 more in `shims::DEFERRED`, which left **16 symbols in neither
set**. An addon needing one of them aborts the process at its first call with
`exit 127` and a loader message naming the symbol — which Node also does for a
symbol that genuinely does not exist, so the abort is not itself the defect. The
defect is that the gap was *undeclared* while the crate's stated policy is to
declare every one, so an addon author had no way to learn about them and the
project's own green checks said nothing.

`rn-compat` cannot see this: it reconciles namespace members against
`internalBinding(...)` contracts, and Node-API is the ABI an addon links against,
not a namespace. `tests/symbols.rs` cannot see it either: it compares the binary
against `shims::EXPORTED` in both directions, which is consistent for any
`EXPORTED`/`DEFERRED` split as long as every symbol is covered by one of them —
the very thing that was false.

What it compares
----------------

Three sets:

  oracle     the `napi_*`/`node_api_*` names in the oracle binary's `.dynsym`
  exported   the same names in this build's `.dynsym`
  declared   every name in `shims::DEFERRED`, split on ` / `

The check fails when a name is in `oracle` but in neither `exported` nor
`declared`. It also fails when a name is declared but the oracle does not export
it (a typo or a stale entry) or when a name is both declared and exported (a
deferral that lies about the surface).

Exit codes: 0 pass, 1 the surfaces disagree, 2 the inputs could not be read.
"""

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIMS = os.path.join(ROOT, "crates", "rn-napi", "src", "shims.rs")
DEFAULT_RUSTNODE = os.path.join(ROOT, "target", "release", "rustnode")
DEFAULT_ORACLE = (
    "/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node"
)

# A `DEFERRED` entry is `("member", "reason")`, with ` / ` separating several
# names in one entry. The same pattern `deferred-reach.py` uses, for the same
# reason: rustfmt puts a trailing comma on an entry that spans lines, and a
# pattern without it silently parses zero entries. `re.S` because a reason may
# wrap.
DEFERRED_DECL = re.compile(
    r"pub const DEFERRED:\s*&\[\(&str,\s*&str\)\]\s*=\s*&\[(.*?)\n\];", re.S
)
DEFERRED_ENTRY = re.compile(
    r'\(\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\)', re.S
)


class Unreadable(Exception):
    """An input the check cannot proceed without."""


def symbols(binary):
    """The `napi_*`/`node_api_*` names in `binary`'s defined dynamic symbols.

    `nm -D --defined-only` is the same read `tests/symbols.rs` performs, so the
    gate and the test cannot disagree about what a binary publishes.
    """
    if not os.path.isfile(binary):
        raise Unreadable(f"{binary} does not exist; build it before running this check")
    try:
        output = subprocess.run(
            ["nm", "-D", "--defined-only", binary],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise Unreadable(f"could not run nm: {error}") from error
    if output.returncode != 0:
        raise Unreadable(
            f"nm failed on {binary}: {output.stderr.strip() or output.returncode}"
        )
    names = set()
    for line in output.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[-1]
        if name.startswith("napi_") or name.startswith("node_api_"):
            names.add(name)
    return names


def declared():
    """`{name: reason}` for every name in `shims::DEFERRED`.

    Raises `Unreadable` when the block cannot be found, or when its body has
    content that no entry matches: a regex that quietly matches nothing would
    report a clean bill of health for a file full of declarations, which is the
    failure mode this whole tool guards.

    An empty body is **not** that failure. Every Node-API symbol being exported is
    the goal, and refusing the empty list would make reaching it impossible. So
    the two cases are distinguished by the body: whitespace only means there is
    genuinely nothing deferred, anything else must parse.
    """
    try:
        with open(SHIMS, encoding="utf-8") as handle:
            source = handle.read()
    except OSError as error:
        raise Unreadable(f"could not read {SHIMS}: {error}") from error
    block = DEFERRED_DECL.search(source)
    if block is None:
        raise Unreadable(f"no `pub const DEFERRED` block found in {SHIMS}")
    body = block.group(1)
    entries = DEFERRED_ENTRY.findall(body)
    if not entries and body.strip():
        raise Unreadable(
            f"the DEFERRED block in {SHIMS} has content but no entry matched; the "
            "pattern no longer matches the declaration format"
        )
    names = {}
    for member, reason in entries:
        for name in member.split(" / "):
            names[name.strip()] = reason
    return names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", default=DEFAULT_ORACLE, help="the reference node binary")
    parser.add_argument("--rustnode", default=DEFAULT_RUSTNODE, help="the built rustnode binary")
    parser.add_argument("--verbose", action="store_true")
    arguments = parser.parse_args()

    try:
        oracle = symbols(arguments.oracle)
        exported = symbols(arguments.rustnode)
        deferred = declared()
    except Unreadable as error:
        print(f"napi-symbol-coverage: {error}", file=sys.stderr)
        return 2

    problems = 0

    missing = sorted(oracle - exported)
    undeclared = [name for name in missing if name not in deferred]
    if undeclared:
        problems += 1
        print(
            "these Node-API entry points are exported by the oracle but neither "
            "exported by this build nor declared in shims::DEFERRED:",
            file=sys.stderr,
        )
        for name in undeclared:
            print(f"  {name}", file=sys.stderr)
        print(
            "\nEach one aborts an addon's process at its first call with no "
            "documented reason. Implement it or declare it with a reason that is "
            "true.",
            file=sys.stderr,
        )

    # A declared name the oracle does not export is a typo or a stale entry; either
    # way the declaration is not describing this ABI.
    phantom = sorted(name for name in deferred if name not in oracle)
    if phantom:
        problems += 1
        print(
            "shims::DEFERRED names entry points the oracle does not export:",
            file=sys.stderr,
        )
        for name in phantom:
            print(f"  {name}", file=sys.stderr)

    # A name that is both declared and exported makes the deferral list lie about
    # the surface, which is the other half of "every gap is declared honestly".
    contradictory = sorted(name for name in deferred if name in exported)
    if contradictory:
        problems += 1
        print(
            "shims::DEFERRED declares entry points this build exports:",
            file=sys.stderr,
        )
        for name in contradictory:
            print(f"  {name}", file=sys.stderr)

    if problems:
        return 1

    covered = len(oracle) - len(missing)
    print(
        f"napi-symbol-coverage: {covered} of {len(oracle)} oracle entry points "
        f"exported, {len(missing)} declared deferred, none undeclared"
    )
    if arguments.verbose:
        for name in missing:
            print(f"  deferred: {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
