#!/usr/bin/env python3
"""Differential audit: every JS-visible binding constructor called without `new`.

The question this answers is narrow and mechanical: for each constructor an
`rn-bind-*` crate installs on an `internalBinding()` object, what happens when
JavaScript calls it as a function instead of with `new`, and does rustnode do
the right thing?

Four facts shape the design.

* **The constructor list is derived, never written down.** `rn-compat
  namespaces` reads the same `BindingRegistry` that `internalBinding()` resolves
  through, so a namespace added by a new binding crate joins the audit with no
  edit here. Which members of a namespace are *constructors* is decided by the
  engine: `Reflect.construct` succeeds exactly when a function has
  `[[Construct]]`. Testing for an own `prototype` property instead would be
  wrong in both directions, because rustnode publishes a prototype on every
  binding function while Node's `FunctionTemplate` callbacks have none.

* **One case per process.** Node's construct checks are `CHECK(...)`, which
  aborts rather than throws. In-process, the first such case kills the runner
  and every later case is silently never measured. Each case therefore gets its
  own child, and "the process died" becomes a first-class outcome.

* **The oracle is live, and the rule is not "match Node exactly".** Node aborts
  the process for most of these calls, so copying it literally would mean
  reimplementing a crash. The rule this audit enforces is the one the tree
  already states (`rn-bind-stream-wrap`, `rn-bind-signal-wrap`): never crash,
  and never hand back a value where Node produced none. Concretely, for a
  member that is a constructor in the oracle:

      Node aborts  -> rustnode may throw, or return `undefined`
      Node throws  -> rustnode throws the same error class
      Node returns -> rustnode returns the same type

  Nothing else is allowed. An error *message* is never compared: Node's wording
  is incidental, and freezing it would turn a Node upgrade into a false failure.

* **Gaps are explained, not skipped silently.** A constructor rustnode does not
  install at all is reported as deferred, with the reason the owning crate
  declared in its own `DEFERRED` table -- read from `rn-compat deferred`, not
  from a second list here.

Usage:
    tools/no-new-audit.py                  # rustnode vs the pinned oracle
    tools/no-new-audit.py --json           # machine-readable table
    tools/no-new-audit.py --oracle <bin>   # compare against another Node
    tools/no-new-audit.py --rustnode <bin> # audit another rustnode build

    tools/no-new-audit.py --no-oracle      # rustnode-only safety check

`--no-oracle` needs no Node binary, so it can run in the commit gate. It keeps
the rule that does not depend on a comparison: a constructor called without
`new` must not abort the process and must not return a value. Throwing and
returning `undefined` are both accepted there, because which one is right is
exactly what the oracle decides.

Exit status is 0 when every constructor satisfies the rule, 1 when any does not,
and 2 when the audit itself could not run.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ORACLE = (
    "/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node"
)

# The one member whose correct behavior *is* to end the process. It is the
# binding behind `process.abort()`, so `--no-oracle` must not read its abort as a
# defect; the oracle run agrees, because Node aborts there too.
EXPECTED_ABORTS = ("process_methods", "abort")


def run(command, timeout=120, cwd=None):
    """Runs one child, returning (status, stdout, stderr).

    A negative status means the child died from a signal, which here is
    `SIGABRT` from a failed `CHECK`. That is a real, reportable outcome.
    """
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd or ROOT,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired:
        return "timeout", "", ""
    except FileNotFoundError as error:
        raise SystemExit(f"{command[0]}: {error.strerror}")


def rn_compat(subcommand):
    """Asks `rn-compat` for a registry-derived table, as JSON."""
    environment = dict(os.environ)
    environment.pop("CARGO_TARGET_DIR", None)
    status, out, err = run(
        ["cargo", "run", "-q", "-p", "rn-compat", "--", subcommand], timeout=900
    )
    if status != 0:
        raise SystemExit(
            f"rn-compat {subcommand} failed ({status}): {err.strip()[-800:]}"
        )
    return json.loads(out)


def enumerate_members(runtime, names, workdir):
    """Every function member of every namespace, classified by the engine."""
    listing = os.path.join(workdir, "namespaces.json")
    with open(listing, "w", encoding="utf8") as handle:
        json.dump(names, handle)
    status, out, err = run(
        [runtime, "--no-warnings", "--expose-internals",
         os.path.join(ROOT, "tools", "no-new-enumerate.js"), listing],
        timeout=600,
    )
    if status != 0:
        raise SystemExit(
            f"enumeration failed under {runtime} ({status}): {err.strip()[-800:]}"
        )
    return json.loads(out)


def run_case(runtime, namespace, member):
    """One constructor, one process.

    Each case runs in its own scratch directory because some constructors write
    files when they are called with the wrong arguments: `heap_utils`
    constructors drop a `Heap.<pid>.heapsnapshot` in the working directory, and
    `fs.writeFileUtf8(undefined)` created a file literally named `undefined` in
    the tree root. Both are the callee's business, not the audit's, and running
    in a temporary directory keeps them out of the checkout.
    """
    with tempfile.TemporaryDirectory() as scratch:
        status, out, err = run(
            [runtime, "--no-warnings", "--expose-internals",
             os.path.join(ROOT, "tools", "no-new-case.js"), namespace, member],
            timeout=120,
            cwd=scratch,
        )
    marker = "#CASE#"
    for line in out.splitlines():
        if marker in line:
            return json.loads(line.split(marker, 1)[1])
    # No result line. Three different things can produce that, and they mean very
    # different things:
    #
    #   status >= 0  -- the runtime exited on its own. `errors.triggerUncaughtException`
    #                   and `process_methods.reallyExit` do this: their whole job is
    #                   to end the process, so an exit is the correct outcome.
    #   status == -6 -- SIGABRT, i.e. a failed `CHECK` or a V8 `Fatal error`.
    #                   That is the crash class this audit exists to find.
    #   status == -9 -- SIGKILL. Nothing in the runtime sends this to itself, so it
    #                   is the kernel reclaiming memory on a loaded machine, not a
    #                   property of the constructor. Reported separately so it is
    #                   never counted as a defect.
    if status == -9:
        kind = "killed"
    elif isinstance(status, int) and status < 0:
        kind = "aborted"
    elif status == "timeout":
        kind = "timeout"
    else:
        kind = "exited"
    detail = ""
    for line in err.splitlines():
        if "Assertion failed" in line or "Check failed" in line or "Fatal error" in line:
            detail = line.strip()
            break
    return {"kind": kind, "status": status, "detail": detail}


def describe(outcome):
    """The report's rendering of one outcome."""
    kind = outcome.get("kind")
    if kind == "throw":
        return f"throw:{outcome.get('errorName')}"
    if kind == "return":
        return f"return:{outcome.get('returned')}"
    return kind or "?"


def verdict(oracle, rustnode):
    """The rule, applied to one pair of outcomes.

    Returns None when the pair is acceptable, or a short reason when it is not.
    """
    node_kind = oracle.get("kind")
    # A SIGKILL is the kernel, not the runtime: it can land on either side at
    # random on a loaded machine, and says nothing about the constructor. It is
    # reported as a hole in coverage rather than as agreement or disagreement.
    if rustnode.get("kind") == "killed" or node_kind == "killed":
        return "killed by SIGKILL before it could report (machine under memory pressure)"
    if rustnode.get("kind") == "aborted":
        return "rustnode aborts the process"
    # A runtime whose *contract* is to end the process is expected to end it, on
    # either side. `process.abort()` aborts and `process.reallyExit()` exits; an
    # exit or abort from those is the answer, not a failure to produce one.
    if node_kind in ("aborted", "exited"):
        if rustnode.get("kind") in ("throw", "exited"):
            return None
        if rustnode.get("kind") == "return" and rustnode.get("returned") == "undefined":
            return None
        return f"node {node_kind}, rustnode returned {rustnode.get('returned')}"
    if node_kind == "throw":
        if rustnode.get("kind") != "throw":
            return f"node throws {oracle.get('errorName')}, rustnode {describe(rustnode)}"
        if rustnode.get("errorName") != oracle.get("errorName"):
            return (
                f"error class: node {oracle.get('errorName')}, "
                f"rustnode {rustnode.get('errorName')}"
            )
        return None
    if node_kind == "return":
        if rustnode.get("kind") != "return":
            return f"node returns, rustnode {describe(rustnode)}"
        if rustnode.get("returned") != oracle.get("returned"):
            return (
                f"return type: node {oracle.get('returned')}, "
                f"rustnode {rustnode.get('returned')}"
            )
        return None
    return f"node {describe(oracle)}, rustnode {describe(rustnode)}"


def collect(oracle_binary, rustnode_binary):
    names = rn_compat("namespaces")
    deferred = rn_compat("deferred")
    with tempfile.TemporaryDirectory() as workdir:
        oracle_report = enumerate_members(oracle_binary, names, workdir)
        rustnode_report = enumerate_members(rustnode_binary, names, workdir)

    def constructors(report):
        found = set()
        for namespace, entry in report.items():
            for member, kind in entry.get("members", {}).items():
                if kind == "constructor":
                    found.add((namespace, member))
        return found

    def functions(report):
        found = set()
        for namespace, entry in report.items():
            for member, kind in entry.get("members", {}).items():
                if kind in ("constructor", "function"):
                    found.add((namespace, member))
        return found

    return constructors(oracle_report), functions(rustnode_report), deferred


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", default=DEFAULT_ORACLE)
    parser.add_argument("--rustnode", default=os.path.join(ROOT, "target/debug/rustnode"))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-oracle", action="store_true")
    args = parser.parse_args()

    if args.no_oracle:
        return run_without_oracle(args)

    oracle_constructors, rustnode_installed, deferred = collect(
        args.oracle, args.rustnode
    )

    rows = []
    for namespace, member in sorted(oracle_constructors):
        reason = deferred.get(namespace, {}).get(member)
        if (namespace, member) not in rustnode_installed:
            rows.append({
                "namespace": namespace,
                "member": member,
                "oracle": "constructor",
                "rustnode": "absent",
                "verdict": "deferred" if reason else "missing",
                "reason": reason or "not installed and not declared deferred",
            })
            continue
        oracle = run_case(args.oracle, namespace, member)
        rustnode = run_case(args.rustnode, namespace, member)
        problem = verdict(oracle, rustnode)
        rows.append({
            "namespace": namespace,
            "member": member,
            "oracle": describe(oracle),
            "rustnode": describe(rustnode),
            "verdict": "ok" if problem is None else "bad",
            "reason": problem,
        })

    if args.json:
        json.dump(rows, sys.stdout, indent=2)
        print()
    else:
        print_report(rows)

    return 0 if all(row["verdict"] in ("ok", "deferred") for row in rows) else 1


def run_without_oracle(args):
    """The oracle-free half of the rule, for the commit gate.

    Only crashes are judged here. "Returns a value" is deliberately *not*
    checked: whether returning is wrong depends on whether the member is really a
    class, and rustnode gives every binding function a `prototype`, so nothing on
    this side of the comparison can tell a class from a plain method. Node can,
    through `[[Construct]]`, which is what the oracle run uses.

    A crash, by contrast, is unconditionally wrong: no correct call without `new`
    can kill the process, whatever the member turns out to be. That is the
    property this mode enforces, and the one that was violated before this work.
    """
    names = rn_compat("namespaces")
    with tempfile.TemporaryDirectory() as workdir:
        report = enumerate_members(args.rustnode, names, workdir)

    cases = []
    for namespace, entry in report.items():
        for member, kind in entry.get("members", {}).items():
            if kind == "constructor":
                cases.append((namespace, member))

    rows = []
    for namespace, member in sorted(cases):
        outcome = run_case(args.rustnode, namespace, member)
        problem = None
        kind = outcome.get("kind")
        if kind == "aborted":
            # A deliberate abort is correct for the one member whose contract is
            # to end the process; every other SIGABRT is the V8 `CHECK` this audit
            # is looking for.
            if (namespace, member) != EXPECTED_ABORTS:
                detail = outcome.get("detail") or ""
                problem = "aborts the process" + (f" ({detail})" if detail else "")
        elif kind == "killed":
            problem = "killed by a signal this runtime does not send itself (SIGKILL)"
        elif kind == "timeout":
            problem = "timed out"
        rows.append({
            "namespace": namespace,
            "member": member,
            "rustnode": describe(outcome),
            "verdict": "ok" if problem is None else "bad",
            "reason": problem,
        })

    if args.json:
        json.dump(rows, sys.stdout, indent=2)
        print()
    else:
        width = max((len(f"{row['namespace']}.{row['member']}") for row in rows), default=10)
        print(f"{'constructor':<{width}}  {'rustnode':<20}  verdict")
        print("-" * (width + 32))
        for row in rows:
            name = f"{row['namespace']}.{row['member']}"
            if row["verdict"] == "ok":
                print(f"{name:<{width}}  {row['rustnode']:<20}  ok")
            else:
                print(f"{name:<{width}}  {row['rustnode']:<20}  BAD: {row['reason']}")
        bad = [row for row in rows if row["verdict"] == "bad"]
        print()
        print(f"{len(rows)} constructors found, {len(rows) - len(bad)} survive a plain "
              f"call, {len(bad)} abort the process")

    return 0 if all(row["verdict"] == "ok" for row in rows) else 1


def print_report(rows):
    width = max((len(f"{row['namespace']}.{row['member']}") for row in rows), default=10)
    print(f"{'constructor':<{width}}  {'node':<18}  {'rustnode':<18}  verdict")
    print("-" * (width + 54))
    for row in rows:
        name = f"{row['namespace']}.{row['member']}"
        verdict = row["verdict"]
        if verdict == "ok":
            line = f"{name:<{width}}  {row['oracle']:<18}  {row['rustnode']:<18}  ok"
        elif verdict == "deferred":
            line = f"{name:<{width}}  {'constructor':<18}  {'deferred':<18}  deferred"
        else:
            line = (f"{name:<{width}}  {row['oracle']:<18}  {row['rustnode']:<18}  "
                    f"{verdict.upper()}: {row['reason']}")
        print(line)

    total = len(rows)
    ok = [row for row in rows if row["verdict"] == "ok"]
    deferred_rows = [row for row in rows if row["verdict"] == "deferred"]
    bad = [row for row in rows if row["verdict"] not in ("ok", "deferred")]
    print()
    print(f"{total} constructors found: {len(ok)} agree, "
          f"{len(deferred_rows)} deferred with a declared reason, {len(bad)} wrong")
    if deferred_rows:
        print()
        print("deferred (the owning crate declares the gap and why):")
        for row in deferred_rows:
            print(f"  {row['namespace']}.{row['member']}: {row['reason']}")


if __name__ == "__main__":
    sys.exit(main())
