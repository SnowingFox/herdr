#!/usr/bin/env python3
"""Interleaved startup comparison: a baseline binary against a candidate.

    tools/bun-startup-measure.py BASELINE CANDIDATE [--samples 30]

Why interleaved, and why the median
-----------------------------------

Two separate traps, both of which this project has already paid for:

* **A sample-based number lies** when the sampling order correlates with drift.
  Machine load moves over minutes, so measuring all of A and then all of B
  attributes any drift between the two batches to the code. Interleaving runs them
  A B A B ... so a slow patch of wall clock hits both equally, and the medians
  share the same noise distribution.

* **A stale binary is not a control.** This script refuses to run a binary whose
  mtime is older than the source tree it claims to come from. It cannot know
  *which* commit produced it, but it can refuse the obvious case, and the caller
  passes two paths that were just built.

The median rather than the mean: process startup has a fat right tail from page
faults and scheduling, and a mean is dominated by the tail rather than describing
the typical run. 30 samples is the plan's bar.

What is measured
----------------

`-e ''` — start, run the whole bootstrap, exit. That is exactly the path a new
global lengthens, and it is the number the project already tracks against Node.

Each sample subtracts nothing and adds nothing: `perf_counter` around
`subprocess.run`, so process creation is included on purpose. A global installed
during bootstrap cannot be measured without starting a process.

The report also prints the paired difference per sample (baseline minus candidate
for the same index), because the *paired* comparison is the one that is robust to
drift even when the medians happen to land oddly. A negative difference means the
candidate is slower.

Usage:
    tools/bun-startup-measure.py BASE CAND
    tools/bun-startup-measure.py BASE CAND --samples 50 --json

Exit codes:
    0  both binaries ran every sample
    2  a binary is missing, not executable, or older than its tree
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import time

# `-e ''`: the bootstrap end to end and nothing else.
ARGS = ["-e", ""]


def stale(binary):
    """Why `binary` looks older than the tree it should have been built from."""
    if not os.path.isfile(binary):
        return f"{binary} does not exist"
    if not os.access(binary, os.X_OK):
        return f"{binary} is not executable"
    binary_mtime = os.path.getmtime(binary)
    # The binary's own crate source and the workspace root are the two cheapest
    # witnesses that it should have been rebuilt. A source file newer than the
    # binary means a rebuild was skipped.
    tree = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(binary))))
    witnesses = [
        os.path.join(tree, "Cargo.toml"),
        os.path.join(tree, "crates", "rn-cli", "src", "main.rs"),
        os.path.join(tree, "crates", "rn-bun", "src", "lib.rs"),
        os.path.join(tree, "crates", "rn-realm", "src", "lib.rs"),
    ]
    for witness in witnesses:
        if not os.path.exists(witness):
            continue
        if os.path.getmtime(witness) > binary_mtime:
            return (
                f"{binary} is older than {witness}; rebuild before measuring "
                f"(this project has already reported a verdict about a binary four "
                f"merges behind its source)"
            )
    return None


def run_once(binary, extra_environment):
    """One process, wall clock in seconds."""
    environment = dict(os.environ)
    environment.update(extra_environment)
    start = time.perf_counter()
    completed = subprocess.run(
        [binary, *ARGS], capture_output=True, text=True, timeout=120, env=environment
    )
    elapsed = time.perf_counter() - start
    return elapsed, completed.returncode


def measure(baseline, candidate, samples, extra_environment):
    base_times = []
    cand_times = []
    for index in range(samples):
        # Interleaved, and the order alternates per sample so a systematic
        # first-process effect is also shared: A B, then B A, then A B ...
        if index % 2 == 0:
            base_one = run_once(baseline, extra_environment)
            cand_one = run_once(candidate, extra_environment)
        else:
            cand_one = run_once(candidate, extra_environment)
            base_one = run_once(baseline, extra_environment)
        base_elapsed, base_code = base_one
        cand_elapsed, cand_code = cand_one
        if base_code != 0:
            raise SystemExit(f"the baseline exited {base_code} on sample {index}")
        if cand_code != 0:
            raise SystemExit(f"the candidate exited {cand_code} on sample {index}")
        base_times.append(base_elapsed)
        cand_times.append(cand_elapsed)
    return base_times, cand_times


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline")
    parser.add_argument("candidate")
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="environment for both binaries; pass RUSTNODE_BUN_EAGER=0 to measure "
        "the lazy install on the same build",
    )
    args = parser.parse_args()

    extra_environment = {}
    for entry in args.env:
        key, _, value = entry.partition("=")
        extra_environment[key] = value

    for binary in (args.baseline, args.candidate):
        problem = stale(binary)
        if problem:
            print(f"measure: {problem}", file=sys.stderr)
            return 2

    base_times, cand_times = measure(
        args.baseline, args.candidate, args.samples, extra_environment
    )
    paired = [base - cand for base, cand in zip(base_times, cand_times)]

    result = {
        "samples": args.samples,
        "baseline": {
            "path": args.baseline,
            "median_ms": statistics.median(base_times) * 1000.0,
            "mean_ms": statistics.mean(base_times) * 1000.0,
            "min_ms": min(base_times) * 1000.0,
            "max_ms": max(base_times) * 1000.0,
        },
        "candidate": {
            "path": args.candidate,
            "median_ms": statistics.median(cand_times) * 1000.0,
            "mean_ms": statistics.mean(cand_times) * 1000.0,
            "min_ms": min(cand_times) * 1000.0,
            "max_ms": max(cand_times) * 1000.0,
        },
        "median_delta_ms": (statistics.median(cand_times) - statistics.median(base_times))
        * 1000.0,
        "paired_median_delta_ms": statistics.median(paired) * 1000.0,
        # The spread, so "the difference is within noise" can be said with a number
        # rather than asserted. This is the median absolute deviation of the paired
        # differences, which is the scale that matters for a paired comparison.
        "paired_mad_ms": statistics.median([abs(x) for x in paired]) * 1000.0,
    }

    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        print(f"samples: {args.samples}, interleaved, `-e ''`")
        print(
            f"  baseline  {result['baseline']['median_ms']:8.3f} ms median  "
            f"(mean {result['baseline']['mean_ms']:7.3f}, "
            f"range {result['baseline']['min_ms']:.3f}-{result['baseline']['max_ms']:.3f})"
        )
        print(
            f"  candidate {result['candidate']['median_ms']:8.3f} ms median  "
            f"(mean {result['candidate']['mean_ms']:7.3f}, "
            f"range {result['candidate']['min_ms']:.3f}-{result['candidate']['max_ms']:.3f})"
        )
        sign = "+" if result["median_delta_ms"] >= 0 else ""
        print(
            f"  median delta {sign}{result['median_delta_ms']:.3f} ms "
            f"(paired {sign}{result['paired_median_delta_ms']:.3f} ms, "
            f"paired MAD {result['paired_mad_ms']:.3f} ms)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
