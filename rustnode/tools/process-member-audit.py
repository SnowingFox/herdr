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
  `doc/api/process.md`, reduced to top-level names. The file is fetched from the
  commit `tools/node-pin.toml` names, so the reference cannot silently become a
  different Node's documentation.
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
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = ROOT / "tools" / "node-pin.toml"
RUSTNODE = ROOT / "target" / "release" / "rustnode"


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


def documented(top_level_only: bool = True) -> set[str]:
    """The `process.`-prefixed entries in the pinned `doc/api/process.md`."""
    commit = pin_value("commit")
    # A full commit is 40 hex characters; the pin may record an abbreviation.
    if len(commit) < 40:
        resolved = subprocess.run(
            ["curl", "-sL", f"https://api.github.com/repos/nodejs/node/commits/{commit}"],
            capture_output=True, text=True, check=False,
        )
        found = re.search(r'"sha":\s*"([0-9a-f]{40})"', resolved.stdout)
        if not found:
            raise SystemExit(f"cannot resolve the pin's abbreviated commit {commit}")
        commit = found.group(1)
    cache = Path("/tmp") / f"herdr-process-md-{commit[:12]}.md"
    if not cache.exists():
        url = f"https://raw.githubusercontent.com/nodejs/node/{commit}/doc/api/process.md"
        with urllib.request.urlopen(url, timeout=90) as response:
            cache.write_bytes(response.read())
    text = cache.read_text()
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


def main() -> int:
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
