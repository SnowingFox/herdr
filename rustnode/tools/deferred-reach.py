#!/usr/bin/env python3
"""Finds deferred binding members that `lib/**` needs at load time.

The three-state contract check treats a declared deferral as a pass, which is
correct: declaring an absent member is honest. But it cannot tell you whether
the JavaScript layer tolerates that absence. `zlib` declared `crc32c` deferred
and the contract still reported `zlib 8 recorded 0 missing ok`, while
`lib/zlib.js` destructures `crc32c` at module scope on line 64, so
`require('zlib')` failed outright.

This looks for that class of deferral: a member that appears in a
`const { ... } = internalBinding('ns')` destructuring at module scope, or in a
top-level `binding.member` expression, rather than only inside a function body.

Usage:
    tools/deferred-reach.py
    tools/deferred-reach.py --json

Exit code is 1 when any at-risk deferral is found, so this can gate CI.
"""

import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "vendor", "libnode-js", "lib")

# `crates/<crate>/src/**` declares deferrals as `("member", "reason")` pairs in a
# `DEFERRED` const, which is the convention every binding crate follows.
DEFERRED_DECL = re.compile(
    r'pub const DEFERRED:\s*&\[\(&str,\s*&str\)\]\s*=\s*&\[(.*?)\n\];', re.S
)
DEFERRED_ENTRY = re.compile(r'\(\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)', re.S)
NAMESPACE = re.compile(r'fn namespace\(&self\) -> &\'static str \{\s*"([^"]+)"')
# A destructuring or property read at module scope. Function bodies are indented
# in Node's lib files, so anchoring at column zero is a reliable proxy for
# "runs when the module loads".
TOP_LEVEL_USE = r"(?m)^(?!\s)"


def crate_deferrals():
    """`{namespace: [(member, reason), ...]}` from every binding crate."""
    deferrals = {}
    crates = os.path.join(ROOT, "crates")
    for entry in sorted(os.listdir(crates)):
        source_dir = os.path.join(crates, entry, "src")
        if not os.path.isdir(source_dir):
            continue
        for name in sorted(os.listdir(source_dir)):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(source_dir, name)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            if "DEFERRED" not in text:
                continue
            namespaces = NAMESPACE.findall(text)
            block = DEFERRED_DECL.search(text)
            if not block or not namespaces:
                continue
            members = DEFERRED_ENTRY.findall(block.group(1))
            if members:
                for namespace in namespaces:
                    deferrals.setdefault(namespace, []).extend(members)
    return deferrals


def builtin_sources():
    """Every builtin's source, keyed by id."""
    sources = {}
    for root, _, files in os.walk(LIB):
        for name in files:
            if not name.endswith(".js"):
                continue
            path = os.path.join(root, name)
            relative = os.path.relpath(path, LIB).replace(os.sep, "/")
            identifier = relative[: -len(".js")]
            with open(path, encoding="utf-8", errors="replace") as handle:
                sources[identifier] = handle.read()
    return sources


def eager_uses(source, namespace, member):
    """Where `member` from `namespace` is read at module scope in `source`."""
    hits = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        # A destructuring at module scope: `const { member } = internalBinding(..)`
        # The binding call may be on the same line or the block may start there.
        if re.match(r"\s*(const|let|var)\s*\{", line) and namespace in source:
            block_start = line_number - 1
            block = "\n".join(source.splitlines()[block_start : block_start + 40])
            if f"internalBinding('{namespace}')" in block and re.search(
                rf"\b{re.escape(member)}\b", block
            ):
                hits.append(line_number)

        # A direct top-level read: `binding.member` or `ns.member` outside a
        # function, which the column-zero anchor identifies.
        if line and not line[0].isspace():
            if re.search(rf"\.{re.escape(member)}\b", line):
                hits.append(line_number)
    return sorted(set(hits))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    deferrals = crate_deferrals()
    if not deferrals:
        print("deferred-reach: no declared deferrals found", file=sys.stderr)
        return 0

    sources = builtin_sources()
    findings = []
    for namespace, members in sorted(deferrals.items()):
        for member, reason in members:
            for identifier, source in sources.items():
                # Only files that actually use this namespace can be affected.
                if f"internalBinding('{namespace}')" not in source:
                    continue
                lines = eager_uses(source, namespace, member)
                if lines:
                    findings.append(
                        {
                            "namespace": namespace,
                            "member": member,
                            "reason": reason,
                            "module": identifier,
                            "lines": lines,
                        }
                    )

    if args.json:
        print(json.dumps(findings, indent=2))
        return 1 if findings else 0

    if not findings:
        print(
            f"deferred-reach: {sum(len(m) for m in deferrals.values())} declared "
            f"deferral(s) across {len(deferrals)} namespace(s), none read at load time"
        )
        return 0

    print(
        "deferred-reach: these deferrals break a module at load time, not just "
        "the code path that uses them"
    )
    print("-" * 78)
    for finding in findings:
        locations = ", ".join(str(line) for line in finding["lines"])
        print(
            f"  {finding['namespace']}.{finding['member']}"
            f"  read in {finding['module']}.js:{locations}"
        )
        print(f"    declared reason: {finding['reason']}")
    print()
    print(
        f"{len(findings)} at-risk deferral(s). Either install the member or make "
        "the JavaScript layer's dependency lazy."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
