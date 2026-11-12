#!/usr/bin/env python3
"""Measure Node's test suite against a rustnode binary, with the skip rule applied.

`rn-harness` records `passed = !timed_out && exit_code == 0`. Node's
`common.skip()` prints a plan line and then exits 0, and a `node:test` file whose
tests all skip exits 0 too, so that rule counts files that never ran a test as
passes. This tool runs the same files the same way and applies the stricter
rule the docs quote:

    a file passes only when it exits 0 AND has none of
      * a cross glyph (`U+2716`) on stdout   (node:test failure marker)
      * `Uncaught` on stdout or stderr       (anywhere in a line)
      * `1..0 # Skipped` at column zero      (common.skip() plan line)
      * `: # SKIP`                           (node:test skip marker)

It also keeps the *whole* stdout and stderr, because both markers can appear
past the 2 KiB/4 KiB heads `rn-harness` retains.

    # every suite, writing raw results
    ./tools/test-tail-map.py run --node target/debug/rustnode \\
        --tests /tmp/node-pin/test --out /tmp/full.json

    # the table, plus named failure families
    ./tools/test-tail-map.py score /tmp/full.json

    # which files a family contains
    ./tools/test-tail-map.py score /tmp/full.json --family fs.cp --list

`run` is deliberately close to `rn-harness` so the two are comparable: same
selection rules, same working directory, same `test/<path>` argument, same
`// Flags:` handling, same 30 s timeout and process-group kill, same `TEST_*`
environment. The one deliberate difference is `TEST_SERIAL_ID`: `rn-harness`
passes `0` to every file, so concurrently running files share one
`test/.tmp.0/` directory and knock each other over with `ENOENT`/`EEXIST`.
Node's own runner gives each file its own id. This tool derives one from the
file path, which is what removes those collisions from the result.
"""

import argparse
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
import zlib
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

SUITES = [
    "parallel",
    "sequential",
    "es-module",
    "internet",
    "pummel",
    "message",
    "known_issues",
    "node-api",
]
# Node splits its suite this way because these tests cannot share a machine.
PARALLEL_SAFE = {"parallel", "es-module", "internet", "message", "node-api"}
# Enough for any real reporter output; a runaway file cannot exhaust memory.
KEEP_BYTES = 512 * 1024

# Ambient variables that change test outcomes and are not part of the runtime
# under test. Removed for both binaries so the comparison is like for like.
SCRUBBED_ENV = ("NODE_DISABLE_COMPILE_CACHE", "NO_COLOR", "FORCE_COLOR")

# `TERM=dumb` makes the REPL report no cursor/colour support, so tests that
# assert on REPL editing behaviour fail for a reason that has nothing to do with
# the runtime. A real CI runner sets a usable TERM; this harness pins one so a
# login shell's `TERM=dumb` cannot masquerade as a runtime defect.
FALLBACK_TERM = "xterm-256color"

SKIP_PLAN = re.compile(r"^1\.\.0 # Skipped", re.M)
SKIP_GLYPH = ": # SKIP"
FAIL_GLYPH = "\u2716"
UNCAUGHT = "Uncaught"


# --------------------------------------------------------------------------
# selection, mirroring tools/harness/src/select.rs
# --------------------------------------------------------------------------


def is_test_file(name):
    return name.startswith("test-") and (name.endswith(".js") or name.endswith(".mjs"))


def collect(root, suites):
    """Every file rn-harness would select, in its order."""
    selected = []
    for suite in SUITES:
        if suites and suite not in suites:
            continue
        suite_dir = os.path.join(root, suite)
        if not os.path.isdir(suite_dir):
            continue
        found = []
        if suite == "node-api":
            # Node's AddonTestConfiguration: one directory down, every .js.
            for sub in sorted(os.listdir(suite_dir)):
                sub_path = os.path.join(suite_dir, sub)
                if not os.path.isdir(sub_path):
                    continue
                for name in sorted(os.listdir(sub_path)):
                    full = os.path.join(sub_path, name)
                    if name.endswith(".js") and os.path.isfile(full):
                        found.append(os.path.relpath(full, root))
        else:
            for dir_path, _dir_names, file_names in os.walk(suite_dir):
                for name in file_names:
                    if is_test_file(name):
                        full = os.path.join(dir_path, name)
                        found.append(os.path.relpath(full, root))
        selected.extend(sorted(found))
    return selected


def read_flags(path):
    """First `// Flags:` line only, exactly as Node's runner reads it."""
    try:
        with open(path, "r", errors="replace") as handle:
            for line in handle:
                stripped = line.lstrip()
                if not stripped.startswith("//"):
                    continue
                rest = stripped[2:].lstrip()
                if rest.startswith("Flags:"):
                    return rest[len("Flags:") :].split()
    except OSError:
        pass
    return []


def serial_id(relative, pinned=None):
    """A stable per-file id, so concurrent files do not share a temp dir.

    `pinned` restores `rn-harness`'s behaviour of giving every file the same
    id, which is what makes its numbers directly comparable to a run recorded
    before this tool existed.
    """
    if pinned is not None:
        return str(pinned)
    return str(zlib.crc32(relative.encode()) % 100000)


# --------------------------------------------------------------------------
# running, mirroring tools/harness/src/runner.rs
# --------------------------------------------------------------------------


def run_one(node, checkout_root, tests_root, relative, timeout, pinned_serial=None):
    argv = [node] + read_flags(os.path.join(tests_root, relative)) + [f"test/{relative}"]
    env = dict(os.environ)
    if env.get("TERM", "dumb") == "dumb":
        env["TERM"] = FALLBACK_TERM
    # These are set by the developer's shell in some agent environments, not by
    # Node, and they change what a test is allowed to observe: a compile-cache
    # test cannot exercise the cache when NODE_DISABLE_COMPILE_CACHE=1, and a
    # colour test cannot see colour when NO_COLOR=1/FORCE_COLOR=0. Leaving them
    # in makes the measurement depend on who ran it.
    for name in SCRUBBED_ENV:
        env.pop(name, None)
    env.update(
        TEST_SERIAL_ID=serial_id(relative, pinned_serial),
        TEST_THREAD_ID="0",
        TEST_PARALLEL="0",
        NODE_TEST_DIR=tests_root,
        GITHUB_STEP_SUMMARY="",
    )
    started = time.monotonic()
    try:
        child = subprocess.Popen(
            argv,
            cwd=checkout_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=env,
        )
    except OSError as error:
        return {
            "file": relative,
            "exit": None,
            "timed_out": False,
            "duration_ms": 0,
            "stdout": "",
            "stderr": f"spawn failed: {error}",
        }

    captured = {1: bytearray(), 2: bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, 1)
    selector.register(child.stderr, selectors.EVENT_READ, 2)
    open_streams = 2
    timed_out = False
    while open_streams and not timed_out:
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            timed_out = True
            break
        for key, _ in selector.select(timeout=min(remaining, 0.05)):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                open_streams -= 1
                continue
            buffer = captured[key.data]
            if len(buffer) < KEEP_BYTES:
                buffer.extend(chunk[: KEEP_BYTES - len(buffer)])
    selector.close()

    if timed_out:
        kill_group(child)
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        kill_group(child)
        child.wait()

    return {
        "file": relative,
        "exit": child.returncode,
        "timed_out": timed_out,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "stdout": captured[1].decode("utf-8", "replace"),
        "stderr": captured[2].decode("utf-8", "replace"),
    }


def kill_group(child):
    """A test that forked keeps the pipes open; signal the whole group."""
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except OSError:
        try:
            child.kill()
        except OSError:
            pass


def command_run(args):
    tests_root = os.path.abspath(args.tests)
    checkout_root = os.path.dirname(tests_root)
    node = os.path.abspath(args.node)
    if not os.path.isfile(node):
        return f"{node} is not a file"

    files = args.only or collect(tests_root, args.suite)
    if args.limit:
        files = files[: args.limit]
    if not files:
        return "no tests selected"

    parallel = [f for f in files if f.split("/")[0] in PARALLEL_SAFE]
    serial = [f for f in files if f.split("/")[0] not in PARALLEL_SAFE]
    print(f"{len(files)} file(s), {args.jobs} job(s), {args.timeout}s timeout", flush=True)

    started = time.monotonic()
    done = 0
    results = []

    def note(relative):
        nonlocal done
        done += 1
        if done % 250 == 0 or done == len(files):
            elapsed = time.monotonic() - started
            print(f"  [{done}/{len(files)}] {elapsed:.0f}s", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for result in pool.map(
            lambda f: run_one(
                node, checkout_root, tests_root, f, args.timeout, args.serial_id
            ),
            parallel,
        ):
            note(result["file"])
            results.append(result)
    for relative in serial:
        result = run_one(node, checkout_root, tests_root, relative, args.timeout, args.serial_id)
        note(relative)
        results.append(result)

    with open(args.out, "w") as handle:
        json.dump(results, handle)
    elapsed = time.monotonic() - started
    print(f"wrote {args.out} in {elapsed:.0f}s")
    return None


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------


def classify(row):
    """(kind, reason) under the four-marker rule."""
    out = row["stdout"]
    err = row["stderr"]
    if row["timed_out"]:
        return "timeout", "timed out"
    if SKIP_PLAN.search(out) or SKIP_GLYPH in out:
        return "skip", first_line(out) or first_line(err)
    if row["exit"] != 0:
        for line in (out + "\n" + err).splitlines():
            if UNCAUGHT in line:
                return "fail", line.strip()
        return "fail", first_line(err) or first_line(out) or f"exit {row['exit']}"
    # Exit 0 is not enough: a node:test reporter prints its own verdict.
    if FAIL_GLYPH in out:
        return "fail", first_line_with(out, FAIL_GLYPH)
    for line in (out + "\n" + err).splitlines():
        if UNCAUGHT in line:
            return "fail", line.strip()
    return "pass", ""


def first_line(text):
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:240]
    return ""


def first_line_with(text, needle):
    for line in text.splitlines():
        if needle in line:
            return line.strip()[:240]
    return ""


NUMBER = re.compile(r"\b\d+\b")


def normalize(reason):
    """Collapse numbers so one family is one row."""
    return NUMBER.sub("<n>", reason.replace("\x1b", "")).strip()


# Failure signatures this document sizes by name. Each is a predicate on a row,
# so a family's size is a count over the same run, not a second measurement.
FAMILIES = {
    "tls_wrap absent": lambda out, err, kind: "internalBinding('tls_wrap')" in err,
    "WorkerImpl": lambda out, err, kind: "WorkerImpl is not a constructor" in err,
    "ReadFileJob/WriteFileJob": lambda out, err, kind: (
        "ReadFileJob is not a constructor" in err or "WriteFileJob is not a constructor" in err
    ),
    "fs.cp bigint stats": lambda out, err, kind: (
        "Method Promise.prototype.then called on incompatible receiver" in err
    ),
    "snapshot-blob": lambda out, err, kind: "unsupported option '--snapshot-blob'" in err,
    "strict equal": lambda out, err, kind: (
        kind == "fail" and "Expected values to be strictly equal" in err
    ),
    "timeout": lambda out, err, kind: kind == "timeout",
    "skipped": lambda out, err, kind: kind == "skip",
}


def command_score(args):
    rows = json.load(open(args.run))
    kinds = Counter()
    families = defaultdict(list)
    reasons = defaultdict(list)
    for row in rows:
        kind, reason = classify(row)
        kinds[kind] += 1
        if kind == "fail":
            reasons[normalize(reason)].append(row["file"])
        for name, predicate in FAMILIES.items():
            if predicate(row["stdout"], row["stderr"], kind):
                families[name].append(row["file"])

    total = len(rows)
    judged = kinds["pass"] + kinds["fail"]
    print(f"files              {total}")
    print(f"passed             {kinds['pass']}")
    print(f"skipped            {kinds['skip']}")
    print(f"failed             {kinds['fail']}")
    print(f"timed out          {kinds['timeout']}")
    if judged:
        print(f"pass/judged        {kinds['pass']}/{judged} = {100.0*kinds['pass']/judged:.1f}%")
    print(f"pass/total         {kinds['pass']}/{total} = {100.0*kinds['pass']/total:.1f}%")

    if args.family:
        wanted = [n for n in FAMILIES if args.family.lower() in n.lower()]
        if not wanted:
            return f"no family matches {args.family!r}; known: {', '.join(FAMILIES)}"
        for name in wanted:
            files = sorted(families[name])
            print(f"\n{name}: {len(files)} file(s)")
            if args.list:
                for file in files:
                    print(f"  {file}")
        return None

    print("\n== named families ==")
    for name in FAMILIES:
        print(f"{len(families[name]):6}  {name}")

    print("\n== exact failure reasons, largest first ==")
    for reason, files in sorted(reasons.items(), key=lambda kv: -len(kv[1]))[: args.top]:
        print(f"{len(files):6}  {reason[:150]}")

    if args.json_out:
        with open(args.json_out, "w") as handle:
            json.dump(
                {
                    "families": {k: sorted(v) for k, v in families.items()},
                    "reasons": {k: sorted(v) for k, v in reasons.items()},
                },
                handle,
                indent=1,
            )
        print(f"\nwrote {args.json_out}")
    return None


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="execute test files and record raw output")
    run.add_argument("--node", required=True)
    run.add_argument("--tests", required=True, help="the checkout's test/ directory")
    run.add_argument("--out", required=True)
    run.add_argument("--suite", action="append", default=[])
    run.add_argument("--only", action="append", default=[])
    run.add_argument("--jobs", type=int, default=8)
    run.add_argument("--timeout", type=int, default=30)
    run.add_argument("--limit", type=int, default=0)
    run.add_argument(
        "--serial-id",
        type=int,
        default=None,
        help="pin TEST_SERIAL_ID for every file, as rn-harness does; "
        "makes a run comparable to results recorded before this tool existed",
    )

    score = sub.add_parser("score", help="apply the pass rule and size the families")
    score.add_argument("run")
    score.add_argument("--family", help="show one family instead of the whole table")
    score.add_argument("--list", action="store_true", help="with --family, list its files")
    score.add_argument("--top", type=int, default=40, help="how many reason rows to print")
    score.add_argument("--json-out")

    args = parser.parse_args()
    error = command_run(args) if args.command == "run" else command_score(args)
    if error:
        print(f"test-tail-map: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
