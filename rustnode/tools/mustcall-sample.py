#!/usr/bin/env python3
"""Measure how many mustCall files pass with an assertion that never ran.

`common.mustCall` compares its invocation count in a `process.on('exit')`
handler. On a runtime whose `exit` event does not fire on a natural event-loop
exit, that comparison never happens: the file exits 0 whether or not the
wrapped callback ran. A file in that state is *contaminated* -- it passes
without checking what it claims to check -- and this tool measures how often
that is true among files the harness currently records as passing.

    tools/mustcall-sample.py --results tools/harness/results --limit 40
    tools/mustcall-sample.py --results <dir> --limit 40 --seed 7 --json

Sampling rather than a full sweep is deliberate: the parallel suite is 5,167
files and takes hours. The reported rate is therefore a sample estimate and is
labelled as one; the interval is Wilson's, which stays sane at the small counts
a 40-file sample produces.

Two independent answers are produced for each file:

  * `unsatisfied` -- from `tools/mustcall-instrument.js`, which records every
    registration and invocation. This is the direct measurement and needs no
    reference runtime.
  * `node_fails` -- whether the *same file* exits non-zero under a reference
    `node`, when one is available. This can only ever be corroboration: a file
    may fail under node for a reason unrelated to mustCall, so it is reported
    separately rather than folded into the rate.

The file is run in a scratch directory whose `test` entry points at the real
test tree, so a test that resolves `../common` behaves as it does under the
harness and the shared checkout is not written to.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTRUMENT = ROOT / "tools" / "mustcall-instrument.js"


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - spread), min(1.0, centre + spread))


@dataclass
class Outcome:
    file: str
    unsatisfied: int = 0
    satisfied: int = 0
    registrations: int = 0
    runtime_exit: int | None = None
    node_exit: int | None = None
    node_unsatisfied: int | None = None
    error: str | None = None
    samples: list[str] = field(default_factory=list)

    @property
    def contaminated(self) -> bool:
        """Passing here while an assertion it registered never ran.

        The reference runtime, when available, is what makes this a claim
        about *rustnode* rather than about the file: the same instrumented run
        under `node` reports how many assertions that file leaves unsatisfied
        on a runtime with a working exit event. A file that is also
        unsatisfied under `node` (a parent whose child owns the assertions, a
        platform skip) is not evidence about the exit path, so it is excluded
        from the rate and counted separately.
        """
        if self.registrations == 0 or self.unsatisfied == 0:
            return False
        if self.node_unsatisfied is None:
            return True
        return self.unsatisfied > self.node_unsatisfied


def load_passes(results_dir: Path) -> dict[str, bool]:
    """Newest recorded outcome per test file, matching the dashboard's rule."""
    newest: dict[str, tuple[float, bool]] = {}
    for path in sorted(results_dir.glob("run-*.json")):
        mtime = path.stat().st_mtime
        try:
            records = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        for record in records:
            name = record.get("file")
            if not name:
                continue
            if name not in newest or mtime >= newest[name][0]:
                newest[name] = (mtime, bool(record.get("passed")))
    return {name: passed for name, (_, passed) in newest.items()}


def parse_log(path: Path) -> tuple[int, int, int, list[str]]:
    """Returns (registrations, unsatisfied, satisfied, example identifiers)."""
    expected: dict[str, tuple[str, int]] = {}
    hits: dict[str, int] = {}
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = record.get("k")
            if kind == "expect":
                # `expected` is whatever the instrument wrote, which is the count
                # `mustCall`/`mustCallAtLeast` received. It is a number for every
                # call `test/common/index.js` accepts — that function throws on a
                # non-numeric criteria — but the instrument copies the argument
                # verbatim, so a caller reaching it by another route can log an
                # object. Comparing one against a count raised `TypeError:
                # '<' not supported between instances of 'int' and 'dict'` on the
                # `minimum` path, which aborted the whole sample rather than
                # skipping one row. Keep the numeric rows and drop the rest: a
                # row this tool cannot interpret is not evidence either way.
                want = record.get("expected", 1)
                if not isinstance(want, int) or isinstance(want, bool):
                    continue
                expected[record["id"]] = (record.get("kind", ""), want)
            elif kind == "hit":
                hits[record["id"]] = hits.get(record["id"], 0) + 1
    unsatisfied = 0
    satisfied = 0
    examples: list[str] = []
    for ident, (kind, want) in expected.items():
        actual = hits.get(ident, 0)
        short = actual < want if kind == "minimum" else actual != want
        if short:
            unsatisfied += 1
            if len(examples) < 3:
                examples.append(f"{ident}:{kind}={want},actual={actual}")
        else:
            satisfied += 1
    return len(expected), unsatisfied, satisfied, examples


def run_once(
    binary: str,
    relative: str,
    workdir: Path,
    log_path: Path,
    timeout: float,
) -> int | None:
    script = workdir / "test" / relative
    env = dict(os.environ)
    env["INSTR_OUT"] = str(log_path)
    # `NODE_OPTIONS` is not honoured for `--require` by rustnode, so the preload
    # goes on argv and `tools/mustcall-instrument.js` strips itself from
    # `process.execArgv` before the test runs. That is what keeps a forked child
    # from inheriting it: an inherited `--require=<path>` is the form rustnode
    # rejects, which made a forking file exit 9 because of the measurement.
    env.update(
        {
            "TEST_SERIAL_ID": "0",
            "TEST_THREAD_ID": "0",
            "TEST_PARALLEL": "0",
            "NODE_TEST_DIR": str(script.parent.parent),
            "GITHUB_STEP_SUMMARY": "",
        }
    )
    try:
        completed = subprocess.run(
            [binary, "--require", str(INSTRUMENT), str(script)],
            cwd=workdir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        return completed.returncode
    except (subprocess.TimeoutExpired, OSError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="tools/harness/results")
    parser.add_argument(
        "--tests", default=os.environ.get("RUSTNODE_TESTS", "/tmp/node/test")
    )
    parser.add_argument(
        "--node-binary", default=str(ROOT / "target" / "debug" / "rustnode")
    )
    parser.add_argument("--reference", default=None, help="a real node binary")
    parser.add_argument("--suite", default="parallel")
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results_dir = Path(args.results)
    tests_dir = Path(args.tests)
    if not results_dir.is_dir():
        print(f"no results directory at {results_dir}", file=sys.stderr)
        return 2
    if not (tests_dir / "common" / "index.js").exists():
        print(f"no common/index.js under {tests_dir}", file=sys.stderr)
        return 3
    if not Path(args.node_binary).exists():
        print(f"no binary at {args.node_binary}", file=sys.stderr)
        return 3

    passes = load_passes(results_dir)
    candidates = []
    for name, passed in passes.items():
        if not passed or not name.startswith(f"{args.suite}/"):
            continue
        path = tests_dir / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        # A substring test rather than a parse: a file that mentions either
        # name may register an assertion, and including a file that turns out
        # not to is harmless (it records zero registrations) whereas excluding a
        # real one would bias the rate downward.
        if "mustCall" not in text and "mustSucceed" not in text:
            continue
        candidates.append(name)

    candidates.sort()
    rng = random.Random(args.seed)
    sampled = rng.sample(candidates, args.limit) if args.limit < len(candidates) else candidates
    sampled.sort()

    scratch = Path(tempfile.mkdtemp(prefix="mustcall-sample-"))
    workdir = scratch
    try:
        # A symlink rather than a copy: the tree is 103 MB and read-only here,
        # and `--tests`-relative resolution then works as it does under the
        # harness, with `test/` reachable from the scratch directory.
        (workdir / "test").symlink_to(tests_dir)
        outcomes: list[Outcome] = []
        for index, name in enumerate(sampled, 1):
            log_path = scratch / "log.jsonl"
            log_path.unlink(missing_ok=True)
            outcome = Outcome(file=name)
            outcome.runtime_exit = run_once(
                args.node_binary, name, workdir, log_path, args.timeout
            )
            regs, unsat, sat, examples = parse_log(log_path)
            outcome.registrations = regs
            outcome.unsatisfied = unsat
            outcome.satisfied = sat
            outcome.samples = examples
            if regs == 0:
                outcome.error = "no registrations recorded"
            if args.reference:
                node_log = scratch / "node.jsonl"
                node_log.unlink(missing_ok=True)
                outcome.node_exit = run_once(
                    args.reference, name, workdir, node_log, args.timeout
                )
                _, node_unsat, _, _ = parse_log(node_log)
                outcome.node_unsatisfied = node_unsat
            outcomes.append(outcome)
            print(
                f"[{index}/{len(sampled)}] {name}: {regs} registrations, "
                f"{unsat} unsatisfied (node {outcome.node_unsatisfied}), "
                f"exit {outcome.runtime_exit}",
                file=sys.stderr,
            )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    measured = [o for o in outcomes if o.registrations > 0]
    contaminated = [o for o in measured if o.contaminated]
    # Files that report unsatisfied assertions on *both* runtimes are not
    # evidence about the exit path: a parent whose children own the assertions,
    # a platform skip, or a test whose async work never completes registers an
    # expectation that no runtime satisfies. Comparing the two counts is what
    # separates "the exit handler did not run" from "this file always looks
    # like this", and the rate is computed over the former only.
    both_unsatisfied = [
        o for o in measured if o.unsatisfied > 0 and not o.contaminated
    ]
    low, high = wilson(len(contaminated), len(measured))

    summary = {
        "suite": args.suite,
        "seed": args.seed,
        "sampled": len(outcomes),
        "measured": len(measured),
        "skipped_no_registrations": len(outcomes) - len(measured),
        "contaminated": len(contaminated),
        "rate": (len(contaminated) / len(measured)) if measured else 0.0,
        "rate_wilson_95": [low, high],
        "unsatisfied_total": sum(o.unsatisfied for o in contaminated),
        "registrations_total": sum(o.registrations for o in measured),
        "reference": args.reference,
        "reference_failing": sum(1 for o in measured if o.node_exit not in (0, None)),
        "excluded_unsatisfied_on_both": [
            {"file": o.file, "unsatisfied": o.unsatisfied, "node": o.node_unsatisfied}
            for o in both_unsatisfied
        ],
        "outcomes": [o.__dict__ for o in outcomes],
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print()
        print(
            f"sample: {len(measured)} files with a mustCall registration "
            f"({len(outcomes) - len(measured)} skipped: none recorded)"
        )
        print(
            f"contaminated: {len(contaminated)} "
            f"({summary['rate']:.1%}, Wilson 95% {low:.1%}-{high:.1%})"
        )
        print(f"unsatisfied assertions in those files: {summary['unsatisfied_total']}")
        if args.reference:
            print(f"of the same files, failing under node: {summary['reference_failing']}")
            print(
                f"excluded (unsatisfied on both runtimes): {len(both_unsatisfied)}"
            )
        print()
        for o in sorted(measured, key=lambda o: (-o.unsatisfied, o.file)):
            if o.unsatisfied and o.contaminated:
                print(
                    f"  {o.unsatisfied:>3} unsatisfied / {o.registrations:>3} "
                    f"(node {o.node_unsatisfied}) in {o.file}  ({', '.join(o.samples)})"
                )
        for o in both_unsatisfied:
            print(
                f"  excluded: {o.unsatisfied:>3} unsatisfied on rustnode and "
                f"{o.node_unsatisfied} on node in {o.file}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
