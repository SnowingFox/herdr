#!/usr/bin/env python3
"""Reports namespace coverage, grouped by what it unlocks.

`rn-compat contracts` answers "is each namespace correct?" one namespace at a
time. This answers the question that matters for planning: how much of Node's
native surface exists, which namespaces are missing, and which missing ones
still stand between the runtime and a loadable stdlib.

Usage:
    tools/coverage.py
    tools/coverage.py --json
"""

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRACTS = os.path.join(ROOT, "contracts")


def contract_status():
    """Asks rn-compat which namespaces are implemented, rather than guessing."""
    result = subprocess.run(
        ["cargo", "run", "-q", "-p", "rn-compat", "--", "contracts"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "RUSTUP_TOOLCHAIN": os.environ.get("RUSTUP_TOOLCHAIN", "1.96.1")},
    )
    status = {}
    for line in (result.stdout + result.stderr).splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[-1] in {"ok", "unregistered"}:
            status[parts[0]] = {"members": int(parts[1]), "state": parts[-1]}
    return status


def reachable_from_stdlib():
    """The namespaces a non-internal builtin can reach, from the closure tool."""
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "namespace-closure.py"), "--all"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    reachable = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0][0].islower():
            reachable.add(parts[0])
    return reachable


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    status = contract_status()
    if not status:
        print("coverage: rn-compat produced no status; run it directly", file=sys.stderr)
        return 2
    reachable = reachable_from_stdlib()

    total_members = sum(entry["members"] for entry in status.values())
    done = {name: e for name, e in status.items() if e["state"] == "ok"}
    missing = {name: e for name, e in status.items() if e["state"] != "ok"}

    on_path = {name: e for name, e in missing.items() if name in reachable}
    on_path_members = sum(entry["members"] for entry in on_path.values())

    if args.json:
        print(
            json.dumps(
                {
                    "namespaces_total": len(status),
                    "namespaces_implemented": len(done),
                    "members_total": total_members,
                    "members_implemented": sum(e["members"] for e in done.values()),
                    "missing_on_stdlib_path": sorted(
                        on_path, key=lambda name: -on_path[name]["members"]
                    ),
                },
                indent=2,
            )
        )
        return 0

    done_members = sum(e["members"] for e in done.values())
    print(f"{'implemented':<14}{len(done):>3} of {len(status)} namespaces"
          f"    {done_members:>5} of {total_members} members"
          f" ({100 * done_members / total_members:.0f}%)")
    print()

    print("implemented")
    print("-" * 64)
    for name in sorted(done, key=lambda name: -done[name]["members"]):
        print(f"  {name:<28}{done[name]['members']:>5}")

    print()
    print(f"missing, reachable from the stdlib ({len(on_path)} namespaces,"
          f" {on_path_members} members)")
    print("-" * 64)
    for name in sorted(on_path, key=lambda name: -on_path[name]["members"]):
        print(f"  {name:<28}{on_path[name]['members']:>5}")

    off_path = {name: e for name, e in missing.items() if name not in reachable}
    if off_path:
        print()
        print(f"missing, not reachable from any non-internal builtin"
              f" ({len(off_path)} namespaces)")
        print("-" * 64)
        print("  " + " ".join(sorted(off_path)))

    return 0


if __name__ == "__main__":
    sys.exit(main())
