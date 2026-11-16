#!/usr/bin/env python3
"""Compares `Object.getOwnPropertyNames(process)` between rustnode and the pin.

The "17 missing process members" finding was a hand-counted number, and hand
counts drift: by the time it was worked on, eleven of the seventeen had already
been implemented. This script replaces the count with a measurement, so the
question "is `process` missing a member?" has an answer that does not depend on
anyone re-reading a list.

# What it compares

Three sets, per population:

* **documented** — the `## `process.name`` entries in the pinned
  `doc/api/process.md`, reduced to top-level names. The file is read from the
  pinned source tree `tools/fetch-node-src.sh` maintains, so the reference is the
  revision `tools/node-pin.toml` names and cannot silently become a different
  Node's documentation.
* **oracle** — `Object.getOwnPropertyNames(process)` under the pinned binary.
* **rustnode** — the same under `target/release/rustnode`, or the path passed
  with `--rustnode`.

The verdict is `oracle - rustnode` (a member Node has that this build does not)
and `rustnode - oracle` (a name this build invents). The *documented* set is
reported alongside, because a documented name absent from **both** runtimes is a
property of Node, not a rustnode gap — which is exactly the case for `channel`,
`send`, `connected` and `disconnect` outside a child process.

# Why three populations

`process.channel`, `process.connected`, `process.disconnect` and `process.send`
exist only where there is an IPC channel: a forked child (`NODE_CHANNEL_FD`) or
a worker. `process.permission` exists only under `--permission`. A main-thread-only
comparison therefore reports five legitimate absences as defects, which is what
the original count appears to have done.

    main      a plain `script.js`
    worker    a `worker_threads.Worker`
    forked    `child_process.fork`, which is the population that owns the IPC set

# Exit status

0 when rustnode's own-property set equals the oracle's in every population.
1 when either direction differs, with the names printed.
2 when an input cannot be read (no oracle, no binary, no docs).

A skip is never a pass: a missing oracle is exit 2 rather than "nothing to
compare", which is the failure mode this repository has been bitten by.

    tools/process-member-audit.py              # measure
    tools/process-member-audit.py --self-test  # prove the doc source fails closed
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = ROOT / "tools" / "node-pin.toml"
FETCH_NODE_SRC = ROOT / "tools" / "fetch-node-src.sh"
RUSTNODE = ROOT / "target" / "release" / "rustnode"
# Relative to a Node source tree, in the layout `doc/` keeps upstream.
PROCESS_DOC = Path("doc") / "api" / "process.md"


def rustnode_path() -> Path:
    """The build to measure: `--rustnode <path>`, else the release binary.

    The release default is right for a human or CI run that has one. The gate
    builds only the debug profile, so it passes its own path rather than reading
    an artifact it never produces.
    """
    if "--rustnode" in sys.argv:
        index = sys.argv.index("--rustnode")
        if index + 1 >= len(sys.argv):
            raise SystemExit("--rustnode needs a path")
        return Path(sys.argv[index + 1])
    return RUSTNODE


def pin_value(key: str) -> str:
    """Reads one `[node]`-section value from `tools/node-pin.toml`."""
    section = None
    for line in PIN.read_text().splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.strip("[]")
            continue
        if section == "node" and line.startswith(key):
            _, _, value = line.partition("=")
            return value.strip().strip('"')
    raise SystemExit(f"node-pin.toml has no [node] {key}")


def node_source_candidates() -> tuple[list[Path], list[str]]:
    """Where a pinned Node source tree may be, and what was already ruled out.

    The location is asked of `tools/fetch-node-src.sh --check` rather than
    restated here. That script owns the cache root (`RUSTNODE_NODE_SRC_CACHE`,
    `TMPDIR`, `/tmp`), the pin comparison and the `--dir` override, and a second
    copy of the path arithmetic would be a second thing to keep in step.

    `NODE_SRC` comes first because it is the override `tools/check.sh` and
    `tools/check-options-drift.py` already honour. It is only a candidate: it may
    name a `src`-only checkout, and `/workspace/node`, the maintainer convention,
    has no `doc/`, so a tree that exists but lacks the file is not an answer.
    """
    candidates: list[Path] = []
    looked: list[str] = []
    from_env = os.environ.get("NODE_SRC", "")
    if from_env:
        candidates.append(Path(from_env))

    reported = subprocess.run(
        [str(FETCH_NODE_SRC), "--check"],
        capture_output=True, text=True, check=False,
    )
    if reported.returncode == 0 and reported.stdout.strip():
        candidates.append(Path(reported.stdout.strip().splitlines()[-1]))
    else:
        # The fetcher's own words name the directory it could not use, which is
        # more useful than anything reconstructed from here.
        looked.append(reported.stderr.strip() or "fetch-node-src.sh --check found nothing")
    return candidates, looked


def process_doc(
    candidates: list[Path] | None = None,
    looked: list[str] | None = None,
    open_url=None,
) -> str:
    """The pinned `doc/api/process.md`.

    The local pinned tree comes first: it is what the gate already maintains for
    `tools/gen-options.py`, it needs no network, and reading it cannot fail for a
    reason that has nothing to do with the code. The previous version resolved
    the pin's abbreviated commit through `api.github.com` first, and on a
    rate-limited IP that answers 403, which turned this step red over a
    documentation fetch rather than a `process` defect.

    The network stays as the fallback for a machine with no tree yet, and needs
    no SHA resolution either: `raw.githubusercontent.com` accepts the abbreviated
    commit the pin records, which is the same property `fetch-node-src.sh`'s
    tarball path relies on. So the unauthenticated API call is gone outright.

    `candidates`, `looked` and `open_url` exist for the self-test, which has to
    drive the unmeasurable paths without a pinned tree or a network. Production
    callers pass nothing.
    """
    if candidates is None:
        candidates, looked = node_source_candidates()
    looked = [] if looked is None else looked
    open_url = urllib.request.urlopen if open_url is None else open_url

    for candidate in candidates:
        doc = candidate / PROCESS_DOC
        if doc.is_file():
            return doc.read_text()
        looked.append(f"{candidate} has no {PROCESS_DOC}")

    commit = pin_value("commit")
    url = f"https://raw.githubusercontent.com/nodejs/node/{commit}/doc/api/process.md"
    try:
        with open_url(url, timeout=90) as response:
            return response.read().decode("utf-8")
    except OSError as error:
        # Exit 2 is "could not measure", and reporting a pass would be worse
        # than that: this step's history is checks that reported clean while
        # measuring nothing.
        print(
            "process member audit: cannot read the pinned doc/api/process.md, so "
            "the documented set is unmeasurable.\n"
            "  no pinned Node source tree with that file:",
            file=sys.stderr,
        )
        for note in looked:
            print(f"    {note}", file=sys.stderr)
        print(
            f"  the fallback fetch failed: {url}\n"
            f"    {error}\n"
            "  fix: run ./tools/fetch-node-src.sh to populate the pinned source "
            "tree (it honours RUSTNODE_NODE_SRC_CACHE and TMPDIR), or set NODE_SRC "
            "to a checkout of the pin that includes doc/.",
            file=sys.stderr,
        )
        raise SystemExit(2)


def documented(text: str | None = None, top_level_only: bool = True) -> set[str]:
    """The `process.`-prefixed entries in the pinned `doc/api/process.md`."""
    names = documented_names(process_doc() if text is None else text)
    if not names:
        # An empty set would make `docs - theirs - ours` empty, and every
        # population would then match on a comparison that measured no
        # documentation at all. That is the pass-while-measuring-nothing shape
        # this whole file exists to avoid, so it is "could not measure" (2), not
        # a mismatch and not a pass.
        print(
            "process member audit: the pinned doc/api/process.md yielded no "
            "`## `process.name`` entries; that file is not the documentation this "
            "audit reads, so the documented set is unmeasurable. Run "
            "./tools/fetch-node-src.sh to refresh the pinned source tree.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if top_level_only:
        names = {name for name in names if "." not in name}
    return names


def documented_names(text: str, top_level_only: bool = True) -> set[str]:
    """The documented top-level `process.` names in one `process.md` body.

    Split out so the parser can be exercised against a synthetic file without a
    network or a pinned tree; [documented] is the only caller that also knows how
    to obtain the real one.
    """
    # Level-2 headings are member entries; level 3+ are sub-members or events.
    entries = re.findall(r"^## `process\.([^`]+)`", text, re.M)
    names = {entry.split("(")[0].split("[")[0].strip() for entry in entries}
    if top_level_only:
        names = {name for name in names if "." not in name}
    return names


def run_node(binary: str, runner: str, args: list[str]) -> dict:
    """Runs `runner` under `binary` and parses its one JSON line."""
    completed = subprocess.run(
        [binary, *args, runner],
        capture_output=True, text=True, timeout=120, check=False,
    )
    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise SystemExit(
        f"{binary} produced no JSON from {runner}:\n"
        f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
    )


def probe_source() -> Path:
    """Writes the probe the three populations share."""
    path = Path("/tmp") / "herdr-process-names-probe.cjs"
    path.write_text(
        r"""
// One population per invocation. The worker case re-enters this file, so both
// runtimes are measured by identical code.
const names = () => Object.getOwnPropertyNames(process).sort();
const population = process.env.HERDR_PROBE_POPULATION;
if (population === 'worker-child') {
  process.stdout.write(JSON.stringify({ names: names() }) + '\n');
} else if (population === 'main') {
  process.stdout.write(JSON.stringify({ names: names() }) + '\n');
} else if (population === 'worker') {
  const { Worker } = require('node:worker_threads');
  const worker = new Worker(__filename, { env: { ...process.env,
    HERDR_PROBE_POPULATION: 'worker-child' } });
  let text = '';
  worker.stdout.on('data', (chunk) => { text += chunk; });
  worker.on('exit', () => {
    const parsed = text.trim() ? JSON.parse(text.trim()) : { names: null };
    process.stdout.write(JSON.stringify({ names: parsed.names }) + '\n');
  });
} else if (population === 'forked') {
  // A child only has the IPC set when it was forked, so this population forks
  // itself once with the reporting role.
  const { fork } = require('child_process');
  const child = fork(__filename, {
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    env: { ...process.env, HERDR_PROBE_POPULATION: 'forked-child' },
  });
  child.on('message', (message) => {
    process.stdout.write(JSON.stringify({ names: message.names }) + '\n');
    child.kill();
  });
  child.on('error', (error) => {
    process.stdout.write(JSON.stringify({ names: null, error: String(error) }) + '\n');
  });
} else {
  process.send({ names: names() }, () => process.exit(0));
}
"""
    )
    return path


def measure(binary: str, runner: Path, population: str) -> list[str]:
    env = dict(os.environ)
    env["HERDR_PROBE_POPULATION"] = population
    completed = subprocess.run(
        [binary, str(runner)],
        capture_output=True, text=True, timeout=180, check=False, env=env,
    )
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        parsed = json.loads(line)
        if parsed.get("error"):
            raise SystemExit(f"{binary} ({population}) failed: {parsed['error']}")
        return parsed["names"] or []
    raise SystemExit(
        f"{binary} ({population}) produced no JSON:\n"
        f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
    )


def oracle_path() -> str:
    """The pinned oracle, refusing to fall back to `PATH`.

    A `node` on `PATH` is a different engine with a different `process` surface,
    which is how a wrong-version comparison passed once already. `RN_NODE_ORACLE`
    is honoured because `tools/fetch-node-oracle.sh --dir` sets it.
    """
    from_env = os.environ.get("RN_NODE_ORACLE")
    candidates = [from_env] if from_env else []
    oracle_dir = pin_value("oracle")
    candidates.append(str(Path(oracle_dir) / "bin" / "node"))
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            version = subprocess.run(
                [candidate, "--version"], capture_output=True, text=True, check=False
            ).stdout.strip()
            expected = pin_value("oracle_version")
            if version != expected:
                raise SystemExit(
                    f"{candidate} reports {version}, the pin names {expected}; "
                    "run tools/fetch-node-oracle.sh"
                )
            return candidate
    raise SystemExit(
        "no pinned oracle: run tools/fetch-node-oracle.sh, or set RN_NODE_ORACLE"
    )


def self_test() -> int:
    """Proves the doc source logic still distinguishes the cases it must.

    Both defects this file has had were silent passes, so the shapes worth
    pinning are the ones that used to pass while measuring nothing: an
    unreadable doc, a doc with no member entries, and a parser that quietly
    stops matching. Each is exercised in-process against a synthetic body and a
    patched environment, so the check needs neither a network nor a pinned tree.
    """
    failures = 0

    def expect(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        if ok:
            print(f"ok   self-test: {name}")
            return
        print(f"FAIL self-test: {name}{': ' + detail if detail else ''}", file=sys.stderr)
        failures += 1

    doc = (
        "# Process\n"
        "\n"
        "## `process.abort()`\n"
        "\n"
        "## `process.argv`\n"
        "\n"
        "## `process.send(message[, sendHandle])`\n"
        "\n"
        "### `process.allowedNodeEnvironmentFlags.has(flag)`\n"
        "\n"
        "## `process.report.reportOnFatalError`\n"
    )
    top = documented_names(doc)
    expect(
        "a level-2 entry names a member, calls and brackets stripped",
        {"abort", "argv", "send"} == top,
        f"got {sorted(top)}",
    )
    expect(
        "a level-3 entry is not a member",
        "allowedNodeEnvironmentFlags" not in top,
        f"got {sorted(top)}",
    )
    expect(
        "a dotted level-2 entry is a sub-member, not a top-level name",
        "report" not in top and "report.reportOnFatalError" not in top,
        f"got {sorted(top)}",
    )
    expect(
        "sub-members survive when top-level names are not requested",
        "report.reportOnFatalError" in documented_names(doc, top_level_only=False),
    )

    # The unmeasurable shapes, driven through the injection points rather than by
    # monkeypatching globals: `documented` must not return an empty set, because
    # every population would then match on a comparison over no documentation.
    #
    # Each is expected to fail, so its message is captured rather than printed:
    # a self-test that shouts the failure it is asserting on makes the gate log
    # read like the defect it is proving is handled.

    def exit_code(call) -> tuple[object, str]:
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            try:
                call()
            except SystemExit as exit_signal:
                return exit_signal.code, captured.getvalue()
        return "returned", captured.getvalue()

    code, message = exit_code(lambda: documented(text=""))
    expect(
        "a doc with no member entries is exit 2, not a pass",
        code == 2,
        f"outcome was {code}",
    )
    expect(
        "the empty-parse message says how to obtain the docs",
        "fetch-node-src.sh" in message,
        f"message was {message!r}",
    )

    def unavailable(url, timeout=None):
        raise OSError("Name or service not known")

    code, message = exit_code(
        lambda: process_doc(candidates=[], looked=[], open_url=unavailable)
    )
    expect(
        "no tree and no network is exit 2, not a pass",
        code == 2,
        f"outcome was {code}",
    )
    expect(
        "the unreadable-doc message says how to obtain the tree",
        "fetch-node-src.sh" in message and "NODE_SRC" in message,
        f"message was {message!r}",
    )

    # A doc read from a candidate tree is preferred to the network, which is the
    # whole point of the change: the network opener here fails if it is reached.
    tree = Path(tempfile.mkdtemp())
    try:
        (tree / PROCESS_DOC).parent.mkdir(parents=True)
        (tree / PROCESS_DOC).write_text(doc)
        code, _ = exit_code(lambda: process_doc(candidates=[tree], open_url=unavailable))
        expect(
            "a local pinned tree answers without the network",
            code == "returned",
            f"outcome was {code}",
        )
        names = documented(text=(tree / PROCESS_DOC).read_text())
        expect(
            "the doc read from the tree parses",
            names == {"abort", "argv", "send"},
            f"got {sorted(names)}",
        )
        # A tree that exists but lacks doc/ is not an answer: `/workspace/node` is
        # `src`-only, and accepting it would silently fall back to no docs.
        empty = Path(tempfile.mkdtemp())
        try:
            code, message = exit_code(
                lambda: process_doc(candidates=[empty], open_url=unavailable)
            )
            expect(
                "a tree without doc/api/process.md is not accepted",
                code == 2,
                f"outcome was {code}",
            )
            expect(
                "a rejected tree is named in the message",
                str(empty) in message,
                f"message was {message!r}",
            )
        finally:
            shutil.rmtree(empty, ignore_errors=True)
    finally:
        shutil.rmtree(tree, ignore_errors=True)

    if failures:
        print(f"self-test: {failures} case(s) did not behave as required", file=sys.stderr)
        return 1
    print("self-test: the doc source fails closed on every unmeasurable shape")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    rustnode = rustnode_path()
    if not rustnode.exists():
        raise SystemExit(f"{rustnode} is missing; cargo build --release -p rn-cli")
    oracle = oracle_path()
    docs = documented()
    runner = probe_source()

    failed = False
    for population in ("main", "worker", "forked"):
        theirs = set(measure(oracle, runner, population))
        ours = set(measure(str(rustnode), runner, population))
        missing = sorted(theirs - ours)
        extra = sorted(ours - theirs)
        both_absent = sorted(docs - theirs - ours)

        print(f"--- {population}: oracle {len(theirs)}, rustnode {len(ours)} ---")
        print(f"    documented but absent on BOTH runtimes: {both_absent or 'none'}")
        print(f"    missing on rustnode: {missing or 'none'}")
        print(f"    extra on rustnode  : {extra or 'none'}")
        if missing or extra:
            failed = True
    print()
    print("verdict:", "MISMATCH" if failed else "every population matches")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
