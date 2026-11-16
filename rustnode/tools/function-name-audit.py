#!/usr/bin/env python3
"""Differential audit: what each binding function's `name` is, against Node.

Node publishes almost every binding member through `node::SetMethod` or one of
its siblings in `src/util.cc`, and the last thing `SetMethod` does is
`function->SetName(name_string)` — the function is named after the property it
is published under. V8's `FunctionTemplate::builder` does no such thing, so a
function built there and set on an object reports `f.name === ""`.

That is observable. It reaches stack traces, `util.inspect`, and any `lib/**`
code that names a function by its `.name`; it is also the third time this has
been reported, which is why the fix is a chokepoint (`rn_core::set_method`,
`named_method`, `set_class`) plus this guard rather than 131 hand edits.

# The rule, in both directions

The two runtimes have to agree member for member, so this audit fails on all of:

* **empty where Node names it** — the defect this exists for.
* **named where Node is empty** — the opposite divergence, and not a
  hypothetical: `SetFastMethod`/`SetFastMethodNoSideEffect` are the one
  `SetMethod` variant that omits `SetName`, so Node's `buffer.copy.name`,
  `os.getTotalMem.name`, `types.isDate.name`, `permission.has.name` and
  `zlib.crc32.name` are all `""`. Setting those to their property names would
  trade one wrong answer for another, so a member the oracle leaves unnamed must
  stay unnamed here.
* **a different name than Node's** — `util.getSharedArrayBufferGrowable` is
  `"get growable"` because it republishes V8's own `growable` accessor, and
  `util.isArrayBufferView` is `"isView"`. A helper that blanket-renamed
  everything to its property name would break both.

# Why `--recorded`, and why the fixture is names not predicates

`--recorded` needs no Node binary, so the commit gate can run it. The fixture
carries the oracle's actual `name` for every function — not a boolean "should be
named" — because a boolean cannot express the two exemptions above: it would
have to say "named" for `getSharedArrayBufferGrowable` and be wrong about the
value.

# Why exit 2 on zero comparisons

The audit reads the namespace list from `rn-compat namespaces`, i.e. from the
same registry `internalBinding()` resolves through, and walks the shipping
object after the vendored `lib/**` bootstrap. A run that compared nothing is not
a pass: the guard that this replaces reported a clean result for a measurement it
had not made. Zero compared functions, an unreadable fixture, or a fixture whose
namespaces rustnode no longer registers all exit 2.

Usage:
    tools/function-name-audit.py                     # diff against the live oracle
    tools/function-name-audit.py --json              # machine-readable rows
    tools/function-name-audit.py --oracle <bin>
    tools/function-name-audit.py --rustnode <bin>
    tools/function-name-audit.py --record <path>     # write Node's names as a fixture
    tools/function-name-audit.py --recorded <path>   # diff against that fixture
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
DEFAULT_RUSTNODE = os.path.join(ROOT, "target/debug/rustnode")

# Namespaces `internal/test/binding` refuses under both runtimes. Not an escape
# hatch for a defect: `internalBinding('internal_only_v8')` raises
# `ERR_INVALID_MODULE` on the oracle too, so there is nothing to compare.
UNREACHABLE = frozenset({"internal_only_v8"})


def clean_environment():
    environment = dict(os.environ)
    environment.pop("CARGO_TARGET_DIR", None)
    return environment


def namespaces():
    """The namespace list, from the registry that `internalBinding` uses."""
    completed = subprocess.run(
        ["cargo", "run", "-q", "-p", "rn-compat", "--", "namespaces"],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=ROOT,
        env=clean_environment(),
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"rn-compat namespaces failed ({completed.returncode}): "
            f"{completed.stderr.strip()[-800:]}"
        )
    return json.loads(completed.stdout)


def enumerate_members(runtime, names, workdir):
    """Every own function member of every namespace, with its name."""
    listing = os.path.join(workdir, "namespaces.json")
    with open(listing, "w", encoding="utf8") as handle:
        json.dump(names, handle)
    try:
        completed = subprocess.run(
            [runtime, "--no-warnings", "--expose-internals",
             os.path.join(ROOT, "tools", "function-name-enumerate.js"), listing],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=ROOT,
            env=clean_environment(),
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
    """Every method on each class's prototype, with its name.

    One child process per namespace keeps this cheap: the walk allocates nothing
    and calls no method.
    """
    report = {}
    for namespace, members in sorted(classes.items()):
        if not members:
            continue
        completed = subprocess.run(
            [runtime, "--no-warnings", "--expose-internals",
             os.path.join(ROOT, "tools", "function-name-prototype.js"),
             namespace, *members],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=ROOT,
            env=clean_environment(),
        )
        if completed.returncode != 0:
            raise SystemExit(
                f"prototype enumeration failed for {namespace} under {runtime} "
                f"({completed.returncode}): {completed.stderr.strip()[-500:]}"
            )
        for name, entry in json.loads(completed.stdout).items():
            report[(namespace, name)] = entry.get("members", {})
    return report


def classes_of(report):
    """`{namespace: [ClassName]}` for every member the engine calls a constructor."""
    classes = {}
    for namespace, entry in report.items():
        members = [
            member for member, value in entry.get("members", {}).items()
            if value.get("kind") == "constructor"
        ]
        if members:
            classes[namespace] = sorted(members)
    return classes


def function_members(entry):
    return {
        member: value
        for member, value in entry.get("members", {}).items()
        if value.get("kind") in ("function", "constructor")
    }


def diff(recorded_members, recorded_prototypes, actual_members, actual_prototypes):
    """The rows, and the count of functions the diff actually judged.

    A member is compared when the recording names it *and* rustnode exposes it as
    a function. The count is what stops "compared nothing" from reading as a
    clean result.
    """
    rows = []
    compared = 0

    for namespace, expected in sorted(recorded_members.items()):
        if namespace in UNREACHABLE:
            continue
        actual = function_members(actual_members.get(namespace, {}))
        for member, expected_name in sorted(expected.items()):
            installed = actual.get(member)
            if installed is None:
                # A member the oracle has and rustnode does not is a surface gap,
                # not a naming one; the contract and constructibility audits own
                # it. Naming only judges what both runtimes publish.
                continue
            compared += 1
            actual_name = installed.get("name", "")
            if actual_name == expected_name:
                continue
            if expected_name and not actual_name:
                reason = "node names it, rustnode leaves it empty"
            elif actual_name and not expected_name:
                reason = "node leaves it empty, rustnode names it"
            else:
                reason = "different name from node"
            rows.append({
                "namespace": namespace,
                "member": member,
                "node": expected_name,
                "rustnode": actual_name,
                "verdict": "bad",
                "reason": reason,
            })

    member_compared = compared

    for (namespace, class_name), expected in sorted(recorded_prototypes.items()):
        actual = actual_prototypes.get((namespace, class_name), {})
        for method, expected_name in sorted(expected.items()):
            installed = actual.get(method)
            if installed is None:
                # Accessors and members Node publishes on the instance rather
                # than the prototype land here. They are a prototype-shape
                # question, owned by `constructible-audit.py`.
                continue
            compared += 1
            actual_name = installed.get("name", "")
            if actual_name == expected_name:
                continue
            if expected_name and not actual_name:
                reason = "node names it, rustnode leaves it empty"
            elif actual_name and not expected_name:
                reason = "node leaves it empty, rustnode names it"
            else:
                reason = "different name from node"
            rows.append({
                "namespace": namespace,
                "member": f"{class_name}.prototype.{method}",
                "node": expected_name,
                "rustnode": actual_name,
                "verdict": "bad",
                "reason": reason,
            })

    return rows, member_compared, compared - member_compared


def record(members, prototypes, member_path):
    """Writes the oracle's names as two fixtures beside `member_path`."""
    member_rows = {
        namespace: {
            member: value.get("name", "")
            for member, value in sorted(function_members(entry).items())
        }
        for namespace, entry in sorted(members.items())
        if "error" not in entry and namespace not in UNREACHABLE
    }
    with open(member_path, "w", encoding="utf8") as handle:
        json.dump(member_rows, handle, indent=2, sort_keys=True)
        handle.write("\n")

    prototype_rows = {
        f"{namespace}.{name}": dict(sorted(
            (method, value.get("name", "")) for method, value in members_.items()
        ))
        for (namespace, name), members_ in sorted(prototypes.items())
    }
    prototype_path = os.path.join(
        os.path.dirname(os.path.abspath(member_path)), "function-name-prototypes.json")
    with open(prototype_path, "w", encoding="utf8") as handle:
        json.dump(prototype_rows, handle, indent=2, sort_keys=True)
        handle.write("\n")

    member_total = sum(len(rows) for rows in member_rows.values())
    prototype_total = sum(len(rows) for rows in prototype_rows.values())
    print(f"recorded {member_total} member name(s) across {len(member_rows)} "
          f"namespace(s) into {member_path}")
    print(f"recorded {prototype_total} prototype method name(s) across "
          f"{len(prototype_rows)} class(es) into {prototype_path}")
    return 0


def prototype_methods(fixture):
    """`{(namespace, class)}` -> `{method: name}` from the flat fixture keys."""
    return {
        tuple(path.split(".", 1)): dict(members)
        for path, members in (fixture or {}).items()
    }


def report(rows, member_compared, prototype_compared, as_json):
    if as_json:
        json.dump({"rows": rows, "member_compared": member_compared,
                   "prototype_compared": prototype_compared}, sys.stdout, indent=2)
        print()
    else:
        width = max((len(f"{row['namespace']}.{row['member']}") for row in rows), default=10)
        print(f"{'function':<{width}}  {'node':<24}  {'rustnode':<24}  verdict")
        print("-" * (width + 78))
        for row in rows:
            print(f"{row['namespace']}.{row['member']:<{width}}  "
                  f"{row['node']!r:<24}  {row['rustnode']!r:<24}  "
                  f"BAD: {row['reason']}")
        if rows:
            print()

    # Two independent counts, because the halves can go blind separately. An
    # emptied member fixture still leaves 435 prototype methods to compare, and
    # the first version of this guard reported a clean `0 disagreements` for
    # exactly that input — the same shape of blindness the constructibility
    # fixture had. Refusing to answer is the only honest outcome.
    if member_compared == 0:
        print("the audit compared zero namespace members, which cannot be a pass: "
              "the namespace list, the member fixture, or the binary is empty or "
              "unreadable", file=sys.stderr)
        return 2
    if prototype_compared == 0:
        print("the audit compared zero prototype methods, which cannot be a pass: "
              "the class list or the prototype fixture is empty or unreadable",
              file=sys.stderr)
        return 2
    print(f"{len(rows)} binding function name(s) disagree with node, across "
          f"{member_compared} member(s) and {prototype_compared} prototype "
          f"method(s) compared")
    return 0 if not rows else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", default=DEFAULT_ORACLE)
    parser.add_argument("--rustnode", default=DEFAULT_RUSTNODE)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--record",
                        help="write Node's function names to this path and exit")
    parser.add_argument("--recorded",
                        help="diff against a recorded fixture instead of a live oracle")
    args = parser.parse_args()

    names = namespaces()

    if args.recorded:
        with open(args.recorded, encoding="utf8") as handle:
            recorded_members = json.load(handle)
        prototype_path = os.path.join(
            os.path.dirname(os.path.abspath(args.recorded)),
            "function-name-prototypes.json")
        with open(prototype_path, encoding="utf8") as handle:
            recorded_prototypes = prototype_methods(json.load(handle))
        with tempfile.TemporaryDirectory() as workdir:
            actual_members = enumerate_members(args.rustnode, names, workdir)
        classes = classes_of(actual_members)
        actual_prototypes = enumerate_prototypes(args.rustnode, classes)
        rows, members_compared, prototypes_compared = diff(
            recorded_members, recorded_prototypes, actual_members, actual_prototypes)
        return report(rows, members_compared, prototypes_compared, args.json)

    with tempfile.TemporaryDirectory() as workdir:
        oracle_members = enumerate_members(args.oracle, names, workdir)
    oracle_prototypes = enumerate_prototypes(args.oracle, classes_of(oracle_members))

    if args.record:
        return record(oracle_members, oracle_prototypes, args.record)

    with tempfile.TemporaryDirectory() as workdir:
        actual_members = enumerate_members(args.rustnode, names, workdir)
    actual_prototypes = enumerate_prototypes(args.rustnode, classes_of(actual_members))
    rows, members_compared, prototypes_compared = diff(
        oracle_members, oracle_prototypes, actual_members, actual_prototypes)
    return report(rows, members_compared, prototypes_compared, args.json)


if __name__ == "__main__":
    sys.exit(main())
