#!/usr/bin/env python3
"""Compares rustnode against Node and Bun on the measurements that can differ.

rustnode reuses V8 and Node's own `lib/**` unchanged, so its JavaScript execution
speed is identical to node's by construction: V8 and the builtin JavaScript are
byte-identical. Reporting that as a win would be dishonest. What can actually
differ is everything around the JavaScript: process startup, how long a builtin
takes to become callable, the cost of one native call on a hot path, and
resident memory after a workload.

    10|This measures those four and prints a table. It refuses to report a comparison
it cannot make: with no builtin loader yet, there is nothing to time, and the
script says so rather than printing zeroes.

Bun is optional. When no Bun binary is found the table is exactly the two-way
table it has always been; when one is found a third column is added. A case a
runtime cannot answer is reported as unavailable and is never timed -- see
`unavailable_reason`.

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

# Where `tools/fetch-bun-oracle.sh` unpacks the pinned Bun. Checked before
# `PATH` for the same reason the Node oracle is: a `bun` on `PATH` is whatever
# the machine happens to have, and a number is only worth recording beside the
# engine that produced it.
BUN_DEFAULT = "/tmp/bun-dl/bun-linux-x64/bun"

# Bun treats `-e ''` as "no script given" and prints its usage banner, so it has
# no empty-script startup row at all and cannot be given an RSS figure from that
# path either (the banner exits before the engine boots: 7.7 MiB median against
# 11.4 MiB for a real no-op). `-e '0'` is the nearest equivalent: a script that
# runs and does nothing. Node and rustnode do not need it -- for them `-e ''` and
# `-e '0'` differ by under 0.1 MiB -- so their RSS stays on the `-e ''` basis it
# always had and only Bun's column is taken this way.
BUN_NOOP_ARGS = ["-e", "0"]


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


def find_bun():
    """The Bun binary to compare against, or None.

    Optional by design: the two-way Node/rustnode table is the comparison this
    tool has always made, and a machine without Bun must still get it unchanged.
    Executability is checked here rather than left to `subprocess`, so a
    `BUN_BIN` that names a non-executable file falls out as "no Bun" instead of
    raising out of the timing loop.
    """
    for candidate in (os.environ.get("BUN_BIN"), BUN_DEFAULT, shutil.which("bun")):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
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
    """Cases every runtime answers without needing a module loader.

    The third element is the stdout the case must produce, or None when the
    case is silent by design. See `unavailable_reason` for why it is checked.
    """
    return [
        ("empty", ["-e", ""], ""),
        ("arithmetic", ["-e", "1 + 1"], ""),
        ("print", ["-e", "console.log(1)"], None),
    ]


def loader_cases():
    """Cases that need `require`. Skipped when the loader is not there."""
    return [
        ("require('path')", ["-e", "require('path')"], ""),
        ("require('util')", ["-e", "require('util')"], ""),
        ("require('fs')", ["-e", "require('fs')"], ""),
    ]


def loader_works(binary):
    _, code, out = run_once(
        binary, ["-e", "try { require('path'); console.log('ok') } catch (e) { console.log('no') }"]
    )
    return code == 0 and out.strip() == "ok"


def unavailable_reason(binary, args, expect_stdout):
    """Why this binary cannot be timed on this case, or None.

    The exit code alone is not enough. Bun exits 0 for `-e ''` and prints its
    usage banner instead of running a script: ~2.3 KB of text in ~1 ms, which as
    an "empty startup" figure measures `--help`, not the engine booting. Timing
    it would put a silent lie in the most-quoted row of the table, so a case
    whose stdout is not the one Node produces is refused instead.

    `expect_stdout` is None for the case whose whole purpose is to write, which
    is the only one that must not be judged this way.
    """
    _, code, out = run_once(binary, args)
    if code != 0:
        return f"exited {code}"
    if expect_stdout is not None and out != expect_stdout:
        return f"wrote {len(out)} bytes to stdout where node writes {len(expect_stdout)}"
    return None


def native_call(binary, samples):
    """The cost of one native call on a tight loop.

    `process.cwd()` reaches a native binding for `os` work and is the cheapest
    observable native call these runtimes have once the stdlib loads. Without a
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
        _, code, out = run_once(binary, ["-e", script])
        if code != 0:
            return None
        try:
            times.append(float(out.strip()))
        except ValueError:
            return None
    return statistics.median(times)


def ratio(numerator_ms, denominator_ms):
    """`numerator / denominator`, or None when either side is unusable."""
    if not numerator_ms or not denominator_ms:
        return None
    return numerator_ms / denominator_ms


def cell(value):
    """A timing cell, or `-` when the runtime has no number."""
    return f"{value:8.2f}ms" if value is not None else "-"


def self_test():
    """Checks the properties that make this tool safe to run anywhere.

    These are the two ways the Bun column could break the tool for someone who
    does not have Bun, or could quietly report a number it did not measure:
    discovery must return None rather than raising, and a case whose stdout is
    not what Node produces must be refused rather than timed. Both are the kind
    of property that stays true until someone refactors `find_bun` to use
    `shutil.which` alone and a `bun` alias on `PATH` starts being timed as if it
    were the engine.
    """
    import tempfile

    failures = []

    def check(name, condition, detail=""):
        if not condition:
            failures.append(f"{name}{': ' + detail if detail else ''}")

    # Discovery never raises and never returns a path it cannot execute.
    saved = os.environ.get("BUN_BIN")
    try:
        os.environ["BUN_BIN"] = "/nonexistent/bun"
        # The default path may or may not exist on this machine; either answer is
        # valid, but it must be a path that exists or None.
        found = find_bun()
        check(
            "find_bun returns None or an existing file",
            found is None or os.path.isfile(found),
            repr(found),
        )

        with tempfile.NamedTemporaryFile("w", suffix="bun", delete=False) as handle:
            handle.write("#!/bin/sh\nexit 0\n")
            not_executable = handle.name
        os.chmod(not_executable, 0o644)
        os.environ["BUN_BIN"] = not_executable
        # A non-executable file must not be returned: subprocess would raise on
        # it from inside the timing loop, which is a crash rather than a skip.
        found = find_bun()
        check(
            "a non-executable BUN_BIN is not discovered",
            found is None or os.access(found, os.X_OK),
            repr(found),
        )
        os.unlink(not_executable)
    finally:
        if saved is None:
            os.environ.pop("BUN_BIN", None)
        else:
            os.environ["BUN_BIN"] = saved

    # A banner-writing binary is refused, and only where stdout is judged.
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write("#!/bin/sh\necho 'usage banner'\nexit 0\n")
        banner = handle.name
    os.chmod(banner, 0o755)
    try:
        check(
            "a silent case with unexpected stdout is refused",
            unavailable_reason(banner, ["-e", ""], "") is not None,
        )
        check(
            "a case that is meant to print is not refused for printing",
            unavailable_reason(banner, ["-e", "console.log(1)"], None) is None,
        )
    finally:
        os.unlink(banner)

    # A failing binary is refused with its exit status.
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write("#!/bin/sh\nexit 7\n")
        failing = handle.name
    os.chmod(failing, 0o755)
    try:
        reason = unavailable_reason(failing, ["-e", ""], "")
        check(
            "a failing binary is refused with its status",
            reason is not None and "7" in reason,
            repr(reason),
        )
    finally:
        os.unlink(failing)

    # The ratio helper must not divide by a missing or zero denominator.
    check("ratio with a missing denominator is None", ratio(10.0, None) is None)
    check("ratio with a zero denominator is None", ratio(10.0, 0.0) is None)
    check("ratio divides left by right", ratio(10.0, 2.0) == 5.0, repr(ratio(10.0, 2.0)))

    for failure in failures:
        print(f"bench self-test: FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("bench self-test: ok")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="check discovery and refusal behaviour without needing any runtime",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    node = find_node()
    rustnode = find_rustnode()
    bun = find_bun()
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
    # A Bun that cannot run the loader cases must not lose the startup cases
    # with them, so its loader support is tracked separately from the table's.
    bun_loader = loader_works(bun) if bun else False
    rows = []

    def add_row(name, argv, expect_stdout):
        node_ms, node_ok = measure(node, argv, args.samples)
        rust_ms, rust_ok = measure(rustnode, argv, args.samples)
        row = {
            "case": name,
            "node_ms": node_ms * 1000,
            "rustnode_ms": rust_ms * 1000,
            "ratio": ratio(node_ms, rust_ms),
            "node_ok": node_ok,
            "rustnode_ok": rust_ok,
            "bun_ms": None,
            "bun_ok": None,
            "bun_unavailable": None,
            "rust_per_bun": None,
        }
        if bun is not None:
            reason = unavailable_reason(bun, argv, expect_stdout)
            if reason:
                row["bun_ok"] = False
                row["bun_unavailable"] = reason
            else:
                bun_ms, bun_ok = measure(bun, argv, args.samples)
                row["bun_ok"] = bun_ok
                if bun_ok:
                    row["bun_ms"] = bun_ms * 1000
                    # rustnode_ms / bun_ms: below 1.00x means rustnode spent
                    # less wall time than Bun. The header names the operands so
                    # the direction of each ratio is not left to the reader.
                    row["rust_per_bun"] = ratio(rust_ms, bun_ms)
        rows.append(row)

    for name, argv, expect_stdout in startup_cases():
        add_row(name, argv, expect_stdout)

    if has_loader:
        for name, argv, expect_stdout in loader_cases():
            add_row(name, argv, expect_stdout)

    memory = {
        "node_kib": peak_rss(node, ["-e", ""]),
        "rustnode_kib": peak_rss(rustnode, ["-e", ""]),
        "bun_kib": None,
    }
    calls = None
    if has_loader:
        calls = {
            "node_ms": native_call(node, args.samples),
            "rustnode_ms": native_call(rustnode, args.samples),
            "bun_ms": None,
        }
        # Bun's two non-timing figures are taken on `-e '0'` rather than on the
        # `-e ''` banner path; see BUN_NOOP_ARGS. The native-call loop is its
        # own script and needs no such substitution, but it still needs a loader.
        if bun is not None and bun_loader:
            memory["bun_kib"] = peak_rss(bun, BUN_NOOP_ARGS)
            calls["bun_ms"] = native_call(bun, args.samples)

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
    print(f"bun       {bun if bun is not None else '(not found; set BUN_BIN or put bun on PATH)'}")
    print(f"samples   {args.samples} per case (median)")
    print()

    if bun is None:
        print(f"{'case':22} {'node':>10} {'rustnode':>10} {'node/rust':>10}")
        print("-" * 56)
        for row in rows:
            status = "" if row["node_ok"] and row["rustnode_ok"] else " (one runtime failed)"
            shown = f"{row['ratio']:.2f}x" if row["ratio"] else "-"
            print(f"{row['case']:22} {row['node_ms']:9.2f}ms {row['rustnode_ms']:9.2f}ms {shown:>10}{status}")
    else:
        # Both ratios divide the left-hand runtime by the right-hand one, and
        # the header names them in that order: "node/rust 2.00x" is "node took
        # twice rustnode's wall time", "rust/bun 0.50x" is "rustnode took half
        # of Bun's". A ratio below 1.00x favours the right-hand runtime.
        print(
            f"{'case':22} {'node':>10} {'rustnode':>10} {'bun':>10} "
            f"{'node/rust':>10} {'rust/bun':>10}"
        )
        print("-" * 78)
        for row in rows:
            notes = []
            if not (row["node_ok"] and row["rustnode_ok"]):
                notes.append("one runtime failed")
            if row["bun_unavailable"]:
                notes.append(f"bun {row['bun_unavailable']}")
            elif row["bun_ok"] is False:
                notes.append("bun failed")
            node_rust = f"{row['ratio']:.2f}x" if row["ratio"] else "-"
            rust_bun = f"{row['rust_per_bun']:.2f}x" if row["rust_per_bun"] else "-"
            bun_text = "n/a" if row["bun_unavailable"] else cell(row["bun_ms"])
            line = (
                f"{row['case']:22} {row['node_ms']:9.2f}ms {row['rustnode_ms']:9.2f}ms "
                f"{bun_text:>10} {node_rust:>10} {rust_bun:>10}"
            )
            if notes:
                line += " (" + "; ".join(notes) + ")"
            print(line)

    print()
    node_rss = memory["node_kib"]
    rust_rss = memory["rustnode_kib"]
    if node_rss and rust_rss:
        line = f"peak RSS           node {node_rss / 1024:.1f} MiB   rustnode {rust_rss / 1024:.1f} MiB"
        if memory["bun_kib"]:
            line += f"   bun {memory['bun_kib'] / 1024:.1f} MiB"
        print(line)
    else:
        print("peak RSS           unavailable (a run failed)")

    if calls:
        if calls["node_ms"] is not None and calls["rustnode_ms"] is not None:
            line = (
                f"200k native calls  node {calls['node_ms']:.2f}ms      "
                f"rustnode {calls['rustnode_ms']:.2f}ms"
            )
            if calls["bun_ms"] is not None:
                line += f"      bun {calls['bun_ms']:.2f}ms"
            print(line)
        else:
            print("200k native calls  unavailable")

    # Only the banner path gets the explanation, and only when it is what
    # actually happened: a Bun that failed every case has its reason printed
    # inline per row, and adding a note about `-e ''` there would explain a
    # behaviour that is not what the reader is looking at.
    empty_row = next((row for row in rows if row["case"] == "empty"), None)
    if empty_row is not None and empty_row["bun_unavailable"] and "stdout" in empty_row["bun_unavailable"]:
        print()
        print("`bun -e ''` prints a usage banner instead of running an empty script, so")
        print("bun has no `empty` row; `arithmetic` is its nearest startup case, and its")
        print("RSS figure is taken on `-e '0'` (a script that runs and does nothing).")

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
