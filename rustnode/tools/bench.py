#!/usr/bin/env python3
"""Compares rustnode against Node on the measurements that can differ.

rustnode reuses V8 and Node's own `lib/**` unchanged, so JavaScript execution
speed is identical by construction. Reporting that as a win would be dishonest.
What can actually differ is everything around the JavaScript: process startup,
how long a builtin takes to become callable, the cost of one native call on a
hot path, and resident memory after a workload.

This measures those four and prints a table. It refuses to report a comparison
it cannot make: with no builtin loader yet, there is nothing to time, and the
script says so rather than printing zeroes.

Usage:
    tools/bench.py                # default: 10 samples per case
    tools/bench.py --samples 50
    tools/bench.py --json         # machine-readable, for a CI baseline
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUSTNODE = os.path.join(ROOT, "target", "release", "rustnode")
RUSTNODE_DEBUG = os.path.join(ROOT, "target", "debug", "rustnode")


def find_node():
    """The Node binary to compare against."""
    for candidate in (os.environ.get("NODE_BIN"), shutil.which("node")):
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def find_rustnode():
    for candidate in (RUSTNODE, RUSTNODE_DEBUG):
        if os.path.isfile(candidate):
            return candidate
    return None


def run_once(binary, args, stdin_text=None):
    """Runs one process and returns (elapsed seconds, exit code, stdout)."""
    start = time.perf_counter()
    result = subprocess.run(
        [binary, *args],
        input=stdin_text,
        capture_output=True,
        text=True,
    )
    elapsed = time.perf_counter() - start
    return elapsed, result.returncode, result.stdout


def measure(binary, args, samples, stdin_text=None):
    """The median wall time of `samples` runs, plus whether all succeeded."""
    times = []
    codes = set()
    for _ in range(samples):
        elapsed, code, _ = run_once(binary, args, stdin_text)
        times.append(elapsed)
        codes.add(code)
    return statistics.median(times), codes == {0}


def peak_rss(binary, args):
    """Peak resident set size in KiB, via `getrusage` on the child.

    A fresh process each time, so this is the runtime's own footprint rather
    than whatever the parent had already faulted in.
    """
    import resource

    pid = os.fork()
    if pid == 0:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            os.execv(binary, [binary, *args])
        finally:
            os._exit(127)
    _, status, usage = os.wait4(pid, 0)
    if status != 0:
        return None
    return usage.ru_maxrss


def startup_cases():
    """Cases every runtime answers without needing a module loader."""
    return [
        ("empty", ["-e", ""]),
        ("arithmetic", ["-e", "1 + 1"]),
        ("print", ["-e", "console.log(1)"]),
    ]


def loader_cases():
    """Cases that need `require`. Skipped when the loader is not there."""
    return [
        ("require('path')", ["-e", "require('path')"]),
        ("require('util')", ["-e", "require('util')"]),
        ("require('fs')", ["-e", "require('fs')"]),
    ]


def loader_works(binary):
    _, code, out = run_once(
        binary, ["-e", "try { require('path'); console.log('ok') } catch (e) { console.log('no') }"]
    )
    return code == 0 and out.strip() == "ok"


def native_call(binary, samples):
    """The cost of one native call on a tight loop.

    `process.cwd()` reaches a Rust binding for `os` work and is the cheapest
    observable native call both runtimes have once the stdlib loads. Without a
    loader there is no such call, so this returns None.
    """
    script = """
      const start = process.hrtime.bigint();
      let total = 0;
      for (let i = 0; i < 200000; i++) total += process.cwd().length ? 1 : 0;
      const end = process.hrtime.bigint();
      console.log(Number(end - start) / 1000000);
    """
    times = []
    for _ in range(samples):
        elapsed, code, out = run_once(binary, ["-e", script])
        if code != 0:
            return None
        try:
            times.append(float(out.strip()))
        except ValueError:
            return None
    return statistics.median(times)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    node = find_node()
    rustnode = find_rustnode()
    if node is None:
        print("bench: no node binary on PATH; set NODE_BIN", file=sys.stderr)
        return 2
    if rustnode is None:
        print(
            "bench: build rustnode first (cargo build --release -p rn-cli)",
            file=sys.stderr,
        )
        return 2

    has_loader = loader_works(rustnode)
    rows = []

    for name, argv in startup_cases():
        node_time, node_ok = measure(node, argv, args.samples)
        rust_time, rust_ok = measure(rustnode, argv, args.samples)
        rows.append(
            {
                "case": name,
                "node_ms": node_time * 1000,
                "rustnode_ms": rust_time * 1000,
                "ratio": node_time / rust_time if rust_time else None,
                "node_ok": node_ok,
                "rustnode_ok": rust_ok,
            }
        )

    if has_loader:
        for name, argv in loader_cases():
            node_time, node_ok = measure(node, argv, args.samples)
            rust_time, rust_ok = measure(rustnode, argv, args.samples)
            rows.append(
                {
                    "case": name,
                    "node_ms": node_time * 1000,
                    "rustnode_ms": rust_time * 1000,
                    "ratio": node_time / rust_time if rust_time else None,
                    "node_ok": node_ok,
                    "rustnode_ok": rust_ok,
                }
            )

    memory = {
        "node_kib": peak_rss(node, ["-e", ""]),
        "rustnode_kib": peak_rss(rustnode, ["-e", ""]),
    }
    calls = {
        "node_ms": native_call(node, args.samples),
        "rustnode_ms": native_call(rustnode, args.samples),
    } if has_loader else None

    if args.json:
        print(
            json.dumps(
                {
                    "loader": has_loader,
                    "cases": rows,
                    "memory": memory,
                    "native_calls": calls,
                },
                indent=2,
            )
        )
        return 0

    print(f"node      {node}")
    print(f"rustnode  {rustnode}")
    print(f"samples   {args.samples} per case (median)")
    print()
    print(f"{'case':22} {'node':>10} {'rustnode':>10} {'node/rust':>10}")
    print("-" * 56)
    for row in rows:
        if not (row["node_ok"] and row["rustnode_ok"]):
            status = " (one runtime failed)"
        else:
            status = ""
        ratio = f"{row['ratio']:.2f}x" if row["ratio"] else "-"
        print(
            f"{row['case']:22} {row['node_ms']:9.2f}ms {row['rustnode_ms']:9.2f}ms {ratio:>10}{status}"
        )

    print()
    node_rss = memory["node_kib"]
    rust_rss = memory["rustnode_kib"]
    if node_rss and rust_rss:
        print(f"peak RSS           node {node_rss / 1024:.1f} MiB   rustnode {rust_rss / 1024:.1f} MiB")
    else:
        print("peak RSS           unavailable (a run failed)")

    if calls:
        if calls["node_ms"] is not None and calls["rustnode_ms"] is not None:
            print(
                f"200k native calls  node {calls['node_ms']:.2f}ms      rustnode {calls['rustnode_ms']:.2f}ms"
            )
        else:
            print("200k native calls  unavailable")

    if not has_loader:
        print()
        print(
            "Builtin loader not available yet, so module loading and native-call cases are skipped."
        )
        print(
            "The startup cases above are still real: they measure the same V8 boot either runtime pays."
        )
        print(
            "Reporting a ratio for anything that has not been implemented would be meaningless."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
