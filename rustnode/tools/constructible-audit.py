#!/usr/bin/env python3
"""Differential audit: which binding members `new fn()` accepts, against Node.

Node builds almost every binding function through `SetMethod` /
`SetProtoMethod`, which pass `v8::ConstructorBehavior::kThrow`
(`src/util.cc`). A member published that way has no `[[Construct]]`, so
`new process.binding('fs').open()` is a `TypeError`. The members that *are*
constructible are the ones published through `SetConstructorFunction` or
`FunctionTemplate::New`, i.e. the real classes plus a handful of members whose
Node code happens to use a plain `NewFunctionTemplate` (`uv.errname`).

rustnode built nearly everything with `FunctionTemplate::builder(...)`, whose
default is `ConstructorBehavior::Allow`, so it was markedly *more* permissive
than Node: code that wrongly writes `new binding.something()` worked here and
broke on Node. This audit measures that set in both runtimes and diffs it.

The member list is not written down here: `rn-compat namespaces` reads the same
`BindingRegistry` that `internalBinding()` resolves through, and
`tools/no-new-enumerate.js` asks the engine whether each function has
`[[Construct]]`, via `Reflect.construct`. An own `prototype` property would be
the wrong probe in both directions (rustnode gives every binding function a
prototype; Node's template callbacks have none).

Usage:
    tools/constructible-audit.py                      # diff against the oracle
    tools/constructible-audit.py --json               # machine-readable rows
    tools/constructible-audit.py --oracle <bin>
    tools/constructible-audit.py --rustnode <bin>
    tools/constructible-audit.py --record <path>      # write Node's answer as a fixture
    tools/constructible-audit.py --recorded <path>    # diff against that fixture

`--recorded` is the form the commit gate uses: it needs no Node binary, only the
two fixtures `--record` wrote from the pinned oracle, and it judges rustnode's
*shipping* state — the object `internalBinding()` hands out after the vendored
`lib/**` bootstrap has run, which is what `lib/**` and user code actually see.
That distinction matters for six members: the native install leaves
`util.isUint8Array` and friends as a local predicate and a placeholder
`DOMException`, and `pre_execution.js` / `per_context` replace them before any
observation. Judging the native layer alone would report six false failures.

The two fixtures are `<path>` for namespace members and, beside it,
`constructible-prototypes.json` for prototype methods. The second one records
every method with the kind the engine reported, *not* only the constructible
ones: Node builds prototype methods with `SetProtoMethod`, so none of them is
constructible and a constructible-only recording is empty by construction. That
is exactly what it used to be, and it made the prototype half of `--recorded`
compare nothing while reporting a clean result — see
`count_prototype_comparisons` and the zero-comparison guard in `report`.

Exit status is 0 when every member rustnode installs agrees with Node, 1 when
one does not, and 2 when the audit could not run — including when it could not
compare a single prototype method, because "compared nothing" is not a pass.
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


# Namespaces whose classes are not `BaseObject` subclasses and therefore have no
# `prototype` to walk, or whose prototype exposes members through accessors that
# this walk cannot see. `internal_only_v8` is unreachable through
# `internal/test/binding`, so it never appears in the fixture at all.
PROTOTYPE_EXEMPT = frozenset()


# Members Node makes constructible that this build does not install. Each is a
# class whose surface has not landed; `rn-compat deferred` carries the reason the
# owning crate gives. They are listed here explicitly so a *declared* gap is not
# reported as a defect, and so removing one from this list is what proves a class
# shipped. An entry whose member becomes installed fails the audit as stale.
DEFERRED = (
    "crypto.ChaCha20Poly1305CipherJob",
    "crypto.DHBitsJob",
    "crypto.DhKeyPairGenJob",
    "crypto.DsaKeyPairGenJob",
    "crypto.KEMDecapsulateJob",
    "crypto.KEMEncapsulateJob",
    "crypto.KangarooTwelveJob",
    "crypto.KmacJob",
    "crypto.Mac",
    "crypto.TurboShakeJob",
    # (`performance.Histogram` and `performance.SlidingWindowHistogram` were here.
    # Both ship now, so deleting their lines is what proves the class landed rather
    # than merely being declared: an entry that is installed fails this audit as
    # stale. Covered by `crates/rn-bind-performance/tests/differential.rs`.
    # This is the only change this branch makes to this file; everything #135 added
    # — the prototype walk, the fixtures and the non-zero-comparison guard — is
    # master's, untouched.)
    #
    # `fs.CpDirJob` was here for the same reason and left the same way: it ships
    # now, so the line is gone. Covered by
    # `crates/rn-bind-fs/tests/cp_parity.rs`.
    "sqlite.backup",
)


def enumerate_members(runtime, names, workdir):
    """Every own function member of every namespace, classified by the engine."""
    listing = os.path.join(workdir, "namespaces.json")
    with open(listing, "w", encoding="utf8") as handle:
        json.dump(names, handle)
    environment = dict(os.environ)
    environment.pop("CARGO_TARGET_DIR", None)
    try:
        completed = subprocess.run(
            [runtime, "--no-warnings", "--expose-internals",
             os.path.join(ROOT, "tools", "no-new-enumerate.js"), listing],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=ROOT,
            env=environment,
        )
    except FileNotFoundError as error:
        raise SystemExit(f"{runtime}: {error.strerror}")
    if completed.returncode != 0:
        raise SystemExit(
            f"enumeration failed under {runtime} ({completed.returncode}): "
            f"{completed.stderr.strip()[-800:]}"
        )
    return json.loads(completed.stdout)


def enumerate_prototypes(runtime, classes):
    """Every method on each class's prototype, classified by the engine.

    Node installs these with `SetProtoMethod`, which is also
    `ConstructorBehavior::kThrow`, so `new binding.TCP.prototype.connect()` is a
    `TypeError` even though `new binding.TCP()` works. One child process per
    namespace keeps this cheap: the prototype walk allocates nothing and calls
    no method.
    """
    environment = dict(os.environ)
    environment.pop("CARGO_TARGET_DIR", None)
    report = {}
    for namespace, members in sorted(classes.items()):
        if not members:
            continue
        completed = subprocess.run(
            [runtime, "--no-warnings", "--expose-internals",
             os.path.join(ROOT, "tools", "constructible-prototype.js"),
             namespace, *members],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=ROOT,
            env=environment,
        )
        if completed.returncode != 0:
            raise SystemExit(
                f"prototype enumeration failed for {namespace} under {runtime} "
                f"({completed.returncode}): {completed.stderr.strip()[-500:]}"
            )
        for name, entry in json.loads(completed.stdout).items():
            report[(namespace, name)] = entry.get("members", {})
    return report


def namespaces():
    """The namespace list, from the registry that `internalBinding` uses."""
    environment = dict(os.environ)
    environment.pop("CARGO_TARGET_DIR", None)
    completed = subprocess.run(
        ["cargo", "run", "-q", "-p", "rn-compat", "--", "namespaces"],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=ROOT,
        env=environment,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"rn-compat namespaces failed ({completed.returncode}): "
            f"{completed.stderr.strip()[-800:]}"
        )
    return json.loads(completed.stdout)


def prototype_methods(prototypes):
    """`{(namespace, class)}` -> `{method: kind}` for each recorded class.

    The fixture is keyed `"<namespace>.<Class>"` so it is readable and diffable,
    which means every consumer has to split that key back apart. Doing it here
    rather than at each call site is what keeps `--recorded` and the live oracle
    path from drifting into two different readings of one file.
    """
    return {
        tuple(path.split(".", 1)): dict(members)
        for path, members in (prototypes or {}).items()
    }


def count_prototype_comparisons(expected, actual):
    """How many prototype methods the diff can actually judge.

    A method is compared when the oracle's recording names it *and* rustnode's
    prototype exposes it. This is the number the audit is blind without: the
    recorded path used to build its expectation from a fixture that carried only
    constructible methods, of which Node's prototypes have none, so every class
    arrived empty, every loop ran zero times, and the audit printed a clean line
    for a comparison it had never made.
    """
    total = 0
    for key, oracle_methods in expected.items():
        rustnode_methods = actual.get(key, {})
        total += sum(1 for method in oracle_methods if method in rustnode_methods)
    return total


def constructible(report):
    """`{(namespace, member)}` for every function the engine calls a constructor."""
    found = set()
    for namespace, entry in report.items():
        for member, kind in entry.get("members", {}).items():
            if kind == "constructor":
                found.add((namespace, member))
    return found


def installed(report):
    """`{(namespace, member)}` for every function member, constructible or not."""
    found = set()
    for namespace, entry in report.items():
        for member, kind in entry.get("members", {}).items():
            if kind in ("constructor", "function"):
                found.add((namespace, member))
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", default=DEFAULT_ORACLE)
    parser.add_argument("--rustnode", default=os.path.join(ROOT, "target/debug/rustnode"))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--record",
                        help="write Node's constructible members to this path and exit")
    parser.add_argument("--recorded",
                        help="diff against a recorded fixture instead of a live oracle")
    args = parser.parse_args()

    names = namespaces()
    if args.recorded:
        with open(args.recorded, encoding="utf8") as handle:
            fixture = json.load(handle)
        node_constructible = {(namespace, member)
                              for namespace, members in fixture.items()
                              for member in members}
        with tempfile.TemporaryDirectory() as workdir:
            rustnode_report = enumerate_members(args.rustnode, names, workdir)
        classes = {
            namespace: sorted(members)
            for namespace, members in fixture.items()
            if namespace not in PROTOTYPE_EXEMPT
        }
        prototype_path = os.path.join(
            os.path.dirname(os.path.abspath(args.recorded)), "constructible-prototypes.json")
        with open(prototype_path, encoding="utf8") as handle:
            expected_prototypes = prototype_methods(json.load(handle))
        # Every class the member fixture names, not only the ones the prototype
        # fixture happens to hold: a class whose prototype was never recorded has
        # to show up as a missing comparison rather than quietly not existing.
        for namespace, members in fixture.items():
            if namespace in PROTOTYPE_EXEMPT:
                continue
            for member in members:
                expected_prototypes.setdefault((namespace, member), {})
        rustnode_prototypes = enumerate_prototypes(args.rustnode, classes)
        return report(node_constructible, rustnode_report, args.json,
                      expected_prototypes, rustnode_prototypes)

    with tempfile.TemporaryDirectory() as workdir:
        oracle_report = enumerate_members(args.oracle, names, workdir)

    if args.record:
        rows = {
            namespace: sorted(member for member, kind in entry.get("members", {}).items()
                              if kind == "constructor")
            for namespace, entry in oracle_report.items()
            if any(kind == "constructor" for kind in entry.get("members", {}).values())
        }
        with open(args.record, "w", encoding="utf8") as handle:
            json.dump(rows, handle, indent=2, sort_keys=True)
            handle.write("\n")
        prototypes = enumerate_prototypes(args.oracle, rows)
        # Every method with its kind, not only the constructible ones. Node's
        # prototype methods are `SetProtoMethod`, i.e. never constructible, so
        # filtering on `kind == "constructor"` wrote an empty list for every
        # class and made the recorded audit a comparison of nothing.
        prototype_rows = {
            f"{namespace}.{name}": dict(sorted(members.items()))
            for (namespace, name), members in prototypes.items()
        }
        prototype_path = os.path.join(
            os.path.dirname(os.path.abspath(args.record)), "constructible-prototypes.json")
        with open(prototype_path, "w", encoding="utf8") as handle:
            json.dump(prototype_rows, handle, indent=2, sort_keys=True)
            handle.write("\n")
        total = sum(len(members) for members in rows.values())
        prototype_total = sum(len(members) for members in prototype_rows.values())
        prototype_constructible = sum(
            1 for members in prototype_rows.values()
            for kind in members.values() if kind == "constructor")
        print(f"recorded {total} constructible members across {len(rows)} "
              f"namespaces into {args.record}")
        print(f"recorded {prototype_total} prototype method(s) across "
              f"{len(prototype_rows)} class(es) into {prototype_path}, "
              f"{prototype_total - prototype_constructible} of them non-constructible")
        return 0

    with tempfile.TemporaryDirectory() as workdir:
        rustnode_report = enumerate_members(args.rustnode, names, workdir)
        classes = {
            namespace: sorted(member for member, kind in entry.get("members", {}).items()
                              if kind == "constructor" and namespace not in PROTOTYPE_EXEMPT)
            for namespace, entry in oracle_report.items()
        }
        oracle_prototypes = enumerate_prototypes(args.oracle, classes)
        rustnode_prototypes = enumerate_prototypes(args.rustnode, classes)

    node_constructible = constructible(oracle_report)
    return report(node_constructible, rustnode_report, args.json,
                  oracle_prototypes, rustnode_prototypes)


def report(node_constructible, rustnode_report, as_json,
           oracle_prototypes=None, rustnode_prototypes=None):
    """The diff, and the exit status that follows from it."""
    rustnode_constructible = constructible(rustnode_report)
    rustnode_installed = installed(rustnode_report)

    extra = sorted(rustnode_constructible - node_constructible)
    missing = sorted(node_constructible - rustnode_installed)
    # The other direction: a member Node makes constructible and rustnode
    # installs, but does not. Under-permissive is the same divergence as
    # over-permissive — `lib/**` or a user's `new` would fail here and work
    # on Node.
    unbuildable = sorted((node_constructible - rustnode_constructible)
                         & rustnode_installed)
    # A gap that is declared is not a defect, but a declaration that no longer
    # describes a gap is: it lets a shipped class go back to being a method
    # without anything noticing.
    declared = {tuple(name.split(".", 1)) for name in DEFERRED}
    deferred = [pair for pair in missing if pair in declared]
    undeclared = [pair for pair in missing if pair not in declared]
    satisfied = sorted(pair for pair in declared if pair not in missing)

    rows = []
    for namespace, member in extra:
        rows.append({
            "namespace": namespace,
            "member": member,
            "node": "function",
            "rustnode": "constructor",
            "verdict": "bad",
            "reason": "node's member has no [[Construct]], rustnode's does",
        })
    for namespace, member in deferred:
        rows.append({
            "namespace": namespace,
            "member": member,
            "node": "constructor",
            "rustnode": "absent",
            "verdict": "deferred",
            "reason": "not installed; declared in the audit's DEFERRED table",
        })
    for namespace, member in undeclared:
        rows.append({
            "namespace": namespace,
            "member": member,
            "node": "constructor",
            "rustnode": "absent",
            "verdict": "bad",
            "reason": "not installed and not declared deferred",
        })
    for namespace, member in satisfied:
        rows.append({
            "namespace": namespace,
            "member": member,
            "node": "constructor",
            "rustnode": "installed",
            "verdict": "bad",
            "reason": "declared deferred but installed now; delete its DEFERRED line",
        })

    for namespace, member in unbuildable:
        rows.append({
            "namespace": namespace,
            "member": member,
            "node": "constructor",
            "rustnode": "function",
            "verdict": "bad",
            "reason": "node's member has [[Construct]], rustnode's does not",
        })

    # Prototype methods. Node builds these with `SetProtoMethod`, also
    # `kThrow`, so they must not be constructible — even on a class that is.
    prototype_extra = []
    prototype_missing = []
    prototype_comparisons = count_prototype_comparisons(
        oracle_prototypes or {}, rustnode_prototypes or {})
    for (namespace, class_name), oracle_methods in (oracle_prototypes or {}).items():
        rustnode_methods = (rustnode_prototypes or {}).get((namespace, class_name), {})
        for method, node_kind in oracle_methods.items():
            rustnode_kind = rustnode_methods.get(method)
            if rustnode_kind is None:
                continue
            if node_kind != "constructor" and rustnode_kind == "constructor":
                prototype_extra.append(f"{namespace}.{class_name}.prototype.{method}")
            elif node_kind == "constructor" and rustnode_kind != "constructor":
                prototype_missing.append(f"{namespace}.{class_name}.prototype.{method}")
    for path in prototype_extra:
        namespace, class_and_method = path.split(".", 1)
        rows.append({
            "namespace": namespace,
            "member": class_and_method,
            "node": "function",
            "rustnode": "constructor",
            "verdict": "bad",
            "reason": "node's prototype method has no [[Construct]]",
        })
    for path in prototype_missing:
        namespace, class_and_method = path.split(".", 1)
        rows.append({
            "namespace": namespace,
            "member": class_and_method,
            "node": "constructor",
            "rustnode": "function",
            "verdict": "bad",
            "reason": "node's prototype method has [[Construct]]",
        })

    if as_json:
        json.dump({"extra": extra, "missing": missing, "unbuildable": unbuildable,
                   "deferred": deferred, "undeclared": undeclared,
                   "satisfied": satisfied, "prototype_extra": prototype_extra,
                   "prototype_missing": prototype_missing,
                   "prototype_comparisons": prototype_comparisons,
                   "rows": rows}, sys.stdout, indent=2)
        print()
    else:
        width = max((len(f"{row['namespace']}.{row['member']}") for row in rows), default=10)
        print(f"{'member':<{width}}  {'node':<12}  {'rustnode':<12}  verdict")
        print("-" * (width + 44))
        for row in rows:
            name = f"{row['namespace']}.{row['member']}"
            verdict = "DEFERRED" if row["verdict"] == "deferred" else "BAD"
            print(f"{name:<{width}}  {row['node']:<12}  {row['rustnode']:<12}  "
                  f"{verdict}: {row['reason']}")
        print()
        print(f"node: {len(node_constructible)} constructible; "
              f"rustnode: {len(rustnode_constructible)} constructible across "
              f"{len(rustnode_installed)} installed members")
        print(f"{len(extra)} constructible only under rustnode, "
              f"{len(unbuildable)} constructible only under node, "
              f"{len(deferred)} not installed but declared, "
              f"{len(undeclared)} not installed and undeclared, "
              f"{len(satisfied)} declared but no longer a gap")
        print(f"{len(prototype_extra)} prototype method(s) constructible only under "
              f"rustnode, {len(prototype_missing)} constructible only under node, "
              f"across {prototype_comparisons} prototype method(s) compared")

    # A run that compared nothing is the defect this line exists to forbid. The
    # recorded path once built its expectation from a fixture of *constructible*
    # prototype methods, which Node has none of, so every class arrived empty,
    # every loop ran zero times, and the audit printed `0 prototype method(s)
    # constructible only under rustnode` — a clean verdict about no measurement
    # at all. Refusing to answer is the only honest outcome: exit 2 is this
    # script's documented "could not run", which the gate treats as fatal.
    if prototype_comparisons == 0:
        print("the audit compared zero prototype methods, which cannot be a pass: "
              "the prototype fixture or the class list it is diffed against is empty "
              "or unreadable", file=sys.stderr)
        return 2

    return 0 if not (extra or unbuildable or undeclared or satisfied
                     or prototype_extra or prototype_missing) else 1


if __name__ == "__main__":
    sys.exit(main())
