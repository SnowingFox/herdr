#!/usr/bin/env python3
"""Reports which native namespaces a builtin's transitive dependency closure needs.

The runtime stops at the first missing namespace, so discovering them one error
at a time serialises the work. This walks Node's own `lib/**` instead: for each
builtin, find the `internalBinding('...')` calls and the `require('...')` calls,
follow the requires into other builtins, and print the namespaces that are
reachable from an entry point.

Usage:
    tools/namespace-closure.py path util os
    tools/namespace-closure.py --all

`--all` treats every non-internal builtin as an entry point, which is the full
set of namespaces the stdlib can reach.
"""

import json
import os
import re
import sys
from collections import deque

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "vendor", "libnode-js", "lib")
CONTRACTS = os.path.join(ROOT, "contracts")

# `internalBinding('x')` and `internalBinding("x")`.
BINDING = re.compile(r"internalBinding\(\s*['\"]([^'\"]+)['\"]\s*\)")
# `require('x')`, `require("x")`, and the `node:` prefixed form.
REQUIRE = re.compile(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)")
# `require.resolve('x')` is not a load, so it is excluded before matching.
RESOLVE = re.compile(r"require\.resolve\(\s*['\"][^'\"]+['\"]\s*\)")


def builtin_path(name):
    """The file behind a builtin id, or None when it is not a local builtin."""
    name = name.removeprefix("node:")
    if name.startswith("internal/deps/"):
        candidate = os.path.join(LIB, "internal", "deps", name[len("internal/deps/"):])
    elif name.startswith("internal/") or name.startswith("deps/"):
        candidate = os.path.join(LIB, name)
    else:
        candidate = os.path.join(LIB, name)
    for path in (candidate + ".js", candidate, candidate + "/index.js"):
        if os.path.isfile(path):
            return path
    return None


def scan(path):
    """The namespaces and module ids one file mentions."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        source = RESOLVE.sub("", handle.read())
    return set(BINDING.findall(source)), set(REQUIRE.findall(source))


def closure(entries):
    """Every namespace reachable from `entries`, and where each was first seen."""
    namespaces = {}
    seen = set()
    queue = deque(entries)
    while queue:
        name = queue.popleft()
        if name in seen:
            continue
        seen.add(name)
        path = builtin_path(name)
        if path is None:
            continue
        bindings, requires = scan(path)
        for binding in bindings:
            namespaces.setdefault(binding, name)
        queue.extend(requires)
    return namespaces


def registered():
    """Namespaces this build already installs.

    Read from the contract check's own view rather than by guessing at source
    formatting: `rn-compat` already knows which crates registered and which
    members they install, and it is the thing that must agree with this report.
    """
    import subprocess

    result = subprocess.run(
        ["cargo", "run", "-q", "-p", "rn-compat", "--", "contracts"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    implemented = set()
    for line in (result.stdout + result.stderr).splitlines():
        parts = line.split()
        if len(parts) >= 2 and "ok" in parts:
            implemented.add(parts[0])
    return implemented


def main():
    args = [value for value in sys.argv[1:] if value != "--all"]
    if not args and "--all" not in sys.argv:
        print(__doc__, file=sys.stderr)
        return 2

    if "--all" in sys.argv:
        entries = []
        for entry in sorted(os.listdir(LIB)):
            if not entry.endswith(".js"):
                continue
            name = entry.removesuffix(".js")
            if name in {"_http_agent", "_http_client", "_http_common", "_http_incoming",
                        "_http_outgoing", "_http_server", "_stream_duplex", "_stream_passthrough",
                        "_stream_readable", "_stream_transform", "_stream_wrap", "_stream_writable",
                        "_tls_common", "_tls_wrap"}:
                continue
            entries.append(name)
        entries.extend(["internal/bootstrap/realm", "internal/bootstrap/node"])
    else:
        entries = args

    reachable = closure(entries)
    done = registered()
    contracts = {}
    for name in os.listdir(CONTRACTS):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(CONTRACTS, name), encoding="utf-8") as handle:
            record = json.load(handle)
        contracts[record["namespace"]] = len(record["members"])

    print(f"{'namespace':28} {'members':>8}  status        first needed by")
    print("-" * 90)
    missing = 0
    for namespace in sorted(reachable, key=lambda key: (-contracts.get(key, 0), key)):
        members = contracts.get(namespace)
        members_text = str(members) if members is not None else "-"
        if namespace in done:
            status = "ok"
        elif namespace in contracts:
            status = "MISSING"
            missing += 1
        else:
            status = "not recorded"
        print(f"{namespace:28} {members_text:>8}  {status:12}  {reachable[namespace]}")

    total = sum(1 for namespace in reachable if namespace in contracts)
    print()
    print(f"{len(done & set(reachable))}/{total} recorded namespaces in this closure are implemented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
