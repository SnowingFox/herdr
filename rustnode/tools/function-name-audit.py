#!/usr/bin/env python3
"""Differential audit: what each binding function's `name` and `length` are.

Node publishes almost every binding member through `node::SetMethod` or one of
its siblings in `src/util.cc`. Two facts about the published function come from
that one helper call, and V8's builder reproduces neither on its own:

* **`name`** — the last thing `SetMethod` does is `function->SetName(name_string)`,
  so the function is named after the property it is published under.
  `FunctionTemplate::builder` leaves it `""`.
* **`length`** — every one of those helpers builds its template through
  `NewFunctionTemplate`, which passes an explicit `0` for the length. So a
  member published that way reports `length === 0` on Node, whatever its real
  argument count is. V8's `FunctionTemplate::New` honours whatever length it is
  given, so a binding that passes `length(4)` gets 4 where Node has 0.

Both are observable — they reach stack traces, `util.inspect`, `Function.length`
arithmetic, and any `lib/**` code that inspects a binding — and they are one
measurement apart, which is why this audit judges them in one pass over one
fixture rather than in two scripts that could disagree.

# The rule, in both directions

The two runtimes have to agree member for member, so this audit fails on all of:

* **empty where Node names it** — the naming defect this started as.
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
* **a different length than Node's, in either direction** — over-long (the 14
  members and 97 prototype methods that passed an explicit arity to V8) and
  under-long (`trace_events.trace` is 5 on Node because V8's own
  `SimpleInstallFunction` records it, and `0` here because nothing said
  otherwise).

# Why `--recorded`, and why the fixture is values not predicates

`--recorded` needs no Node binary, so the commit gate can run it. The fixture
carries the oracle's actual `name` and `length` for every function — not a
boolean "should be named" or "should be zero" — because a boolean cannot express
the exemptions above: it would have to say "named" for
`getSharedArrayBufferGrowable` and be wrong about the value, and it could not
express that `serdes.Deserializer` really is 1 while every other constructor
Node installs with `SetConstructorFunction` is 0.

# Why exit 2 on zero comparisons

The audit reads the namespace list from `rn-compat namespaces`, i.e. from the
same registry `internalBinding()` resolves through, and walks the shipping
object after the vendored `lib/**` bootstrap. A run that compared nothing is not
a pass: the guard that this replaces reported a clean result for a measurement
it had not made. Zero compared members, zero compared prototype methods, or zero
compared *lengths* within either half, all exit 2. The last two halves are
separate counters for the reason the naming halves already were: an emptied
length field in the fixture would otherwise leave the name comparison to report
a clean `0 disagreements` about the invariant that had gone blind.

Usage:
    tools/function-name-audit.py                     # diff against the live oracle
    tools/function-name-audit.py --json              # machine-readable rows
    tools/function-name-audit.py --oracle <bin>
    tools/function-name-audit.py --rustnode <bin>
    tools/function-name-audit.py --record <path>     # write Node's answers as a fixture
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


def declared_deferrals():
    """`{"namespace.member"}` for every member a crate declared in `DEFERRED`.

    Read from `rn-compat deferred`, not from the sources: that subcommand prints
    the registry's own view of what each namespace declared it is not
    installing, which is the same data `internalBinding()` resolves through. The
    deferred-reach tool parses the `DEFERRED` consts directly; this is the same
    set through the compiled registry, so a deferral that moved between a const
    and a `deferred()` method cannot look like a silent absence here.

    An unreadable answer is fatal. A silently empty set would turn the
    deferred-skip classification below into "everything skipped is unexplained",
    which is the loud direction, but it would also be wrong about why: 31
    members would be reported as defects when they are declared gaps.
    """
    completed = subprocess.run(
        ["cargo", "run", "-q", "-p", "rn-compat", "--", "deferred"],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=ROOT,
        env=clean_environment(),
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"rn-compat deferred failed ({completed.returncode}): "
            f"{completed.stderr.strip()[-800:]}"
        )
    try:
        by_namespace = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"rn-compat deferred did not print JSON: {error}")
    return {
        f"{namespace}.{member}"
        for namespace, members in by_namespace.items()
        for member in members
    }


def enumerate_members(runtime, names, workdir):
    """Every own function member of every namespace, with name and length."""
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
    """Every method on each class's prototype, with name and length.

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


def recording_of(value):
    """The recorded `{name, length}` pair for one function, from either shape.

    A plain string is the older name-only fixture format. It is still accepted so
    a stale recording cannot silently compare one invariant while looking like a
    full one: its `length` is absent, which the caller reports as a missing
    field rather than as agreement.
    """
    if isinstance(value, str):
        return value, None
    return value.get("name", ""), value.get("length")


def diff_name(expected, actual):
    """The reason a name disagrees, or None. `expected`/`actual` are strings."""
    if actual == expected:
        return None
    if expected and not actual:
        return "node names it, rustnode leaves it empty"
    if actual and not expected:
        return "node leaves it empty, rustnode names it"
    return "different name from node"


def diff_length(expected, actual):
    """The reason a length disagrees, or None."""
    if expected is None or actual is None:
        return None
    if actual == expected:
        return None
    if actual > expected:
        return "rustnode passes an arity node does not"
    return "node records an arity rustnode does not"


def diff(recorded_members, recorded_prototypes, actual_members, actual_prototypes):
    """The rows, the four comparison counts, and an accounting of every skip.

    A function is compared when the recording names it *and* rustnode exposes it
    as a function. The four counters are what stop "compared nothing" from
    reading as a clean result, separately for `name` and for `length`: they are
    different fields of the fixture and can go blind independently.

    # Why the skips are counted and named

    `recorded - compared` is not zero, and leaving it implicit is the defect
    this accounting closes. The member fixture holds 555 rows and the audit
    compares 524: the other 31 are members a crate declared in its `DEFERRED`
    list, so the namespace object never installs them. Skipping those is right.
    Reporting only the 524 makes the number look like the whole fixture, so a
    member that silently fell out of the install path — the one thing this audit
    is best placed to notice — would shrink a count nobody checks.

    So every skipped member is classified:

    * **declared deferral** — `rn-compat deferred` names it. Expected, counted,
      and printed with the same `namespace.member` spelling `deferred-reach.py`
      uses for its findings.
    * **not a declared deferral** — a real gap in the install path. That is
      reported as an error row, not skipped: an installation defect must not be
      able to hide behind the deferred accounting.

    The prototype half has the same arithmetic and is counted the same way. A
    prototype method is skipped when rustnode does not expose it at all; that is
    a *surface* question owned by `constructible-audit.py`, so it is reported as
    an unowned skip here rather than as a naming or arity one, but it is printed
    so the number is visible.
    """
    rows = []
    member_name_compared = 0
    member_length_compared = 0
    prototype_name_compared = 0
    prototype_length_compared = 0
    deferred = declared_deferrals()
    member_recorded = 0
    member_deferred = []
    member_unexplained = []
    prototype_recorded = 0
    prototype_missing = []

    def judge(namespace, member, expected_value, installed, counters):
        expected_name, expected_length = recording_of(expected_value)
        name_reason = diff_name(expected_name, installed.get("name", ""))
        length_reason = diff_length(expected_length, installed.get("length"))
        if expected_value is not None:
            counters[0] += 1
        if expected_length is not None:
            counters[1] += 1
        for field, reason, node_value, rustnode_value in (
            ("name", name_reason, expected_name, installed.get("name", "")),
            ("length", length_reason, expected_length, installed.get("length")),
        ):
            if reason is None:
                continue
            rows.append({
                "namespace": namespace,
                "member": member,
                "field": field,
                "node": node_value,
                "rustnode": rustnode_value,
                "verdict": "bad",
                "reason": reason,
            })

    for namespace, expected in sorted(recorded_members.items()):
        if namespace in UNREACHABLE:
            continue
        actual = function_members(actual_members.get(namespace, {}))
        counters = [0, 0]
        for member, expected_value in sorted(expected.items()):
            member_recorded += 1
            installed = actual.get(member)
            if installed is None:
                # Two very different reasons a recorded member is not installed,
                # and they must not read the same. A declared deferral is a gap
                # the owning crate wrote down; anything else is an installation
                # defect this audit should not swallow.
                path = f"{namespace}.{member}"
                if path in deferred:
                    member_deferred.append(path)
                else:
                    member_unexplained.append(path)
                    rows.append({
                        "namespace": namespace,
                        "member": member,
                        "field": "surface",
                        "node": "installed",
                        "rustnode": "missing",
                        "verdict": "bad",
                        "reason": "node installs it, rustnode does not, and no "
                                  "crate declares it deferred",
                    })
                continue
            judge(namespace, member, expected_value, installed, counters)
        member_name_compared += counters[0]
        member_length_compared += counters[1]

    for (namespace, class_name), expected in sorted(recorded_prototypes.items()):
        actual = actual_prototypes.get((namespace, class_name), {})
        counters = [0, 0]
        for method, expected_value in sorted(expected.items()):
            prototype_recorded += 1
            installed = actual.get(method)
            if installed is None:
                # Accessors and members Node publishes on the instance rather
                # than the prototype land here. They are a prototype-shape
                # question, owned by `constructible-audit.py`; naming and
                # `length` only judge methods both runtimes publish on the
                # prototype.
                prototype_missing.append(
                    f"{namespace}.{class_name}.prototype.{method}")
                continue
            judge(namespace, f"{class_name}.prototype.{method}",
                  expected_value, installed, counters)
        prototype_name_compared += counters[0]
        prototype_length_compared += counters[1]

    accounting = {
        "member_recorded": member_recorded,
        "member_deferred": member_deferred,
        "member_unexplained": member_unexplained,
        "prototype_recorded": prototype_recorded,
        "prototype_missing": prototype_missing,
    }
    return (rows, member_name_compared, member_length_compared,
            prototype_name_compared, prototype_length_compared, accounting)


def record(members, prototypes, member_path):
    """Writes the oracle's names and lengths as two fixtures beside `member_path`."""
    member_rows = {}
    for namespace, entry in sorted(members.items()):
        if "error" in entry or namespace in UNREACHABLE:
            continue
        member_rows[namespace] = {
            member: {"name": value.get("name", ""), "length": value.get("length")}
            for member, value in sorted(function_members(entry).items())
        }
    with open(member_path, "w", encoding="utf8") as handle:
        json.dump(member_rows, handle, indent=2, sort_keys=True)
        handle.write("\n")

    prototype_rows = {
        f"{namespace}.{name}": {
            method: {"name": value.get("name", ""), "length": value.get("length")}
            for method, value in sorted(members_.items())
        }
        for (namespace, name), members_ in sorted(prototypes.items())
    }
    prototype_path = os.path.join(
        os.path.dirname(os.path.abspath(member_path)), "function-name-prototypes.json")
    with open(prototype_path, "w", encoding="utf8") as handle:
        json.dump(prototype_rows, handle, indent=2, sort_keys=True)
        handle.write("\n")

    member_total = sum(len(rows) for rows in member_rows.values())
    prototype_total = sum(len(rows) for rows in prototype_rows.values())
    print(f"recorded {member_total} member name(s) and length(s) across "
          f"{len(member_rows)} namespace(s) into {member_path}")
    print(f"recorded {prototype_total} prototype method name(s) and length(s) "
          f"across {len(prototype_rows)} class(es) into {prototype_path}")
    return 0


def prototype_methods(fixture):
    """`{(namespace, class)}` -> `{method: value}` from the flat fixture keys."""
    return {
        tuple(path.split(".", 1)): dict(members)
        for path, members in (fixture or {}).items()
    }


def report(rows, member_name, member_length, prototype_name, prototype_length,
           accounting, as_json):
    if as_json:
        json.dump({"rows": rows, "member_name_compared": member_name,
                   "member_length_compared": member_length,
                   "prototype_name_compared": prototype_name,
                   "prototype_length_compared": prototype_length,
                   "accounting": accounting},
                  sys.stdout, indent=2)
        print()
    else:
        width = max((len(f"{row['namespace']}.{row['member']}") for row in rows), default=10)
        print(f"{'function':<{width}}  {'field':<6}  {'node':<24}  {'rustnode':<24}  verdict")
        print("-" * (width + 84))
        for row in rows:
            print(f"{row['namespace']}.{row['member']:<{width}}  "
                  f"{row['field']:<6}  "
                  f"{row['node']!r:<24}  {row['rustnode']!r:<24}  "
                  f"BAD: {row['reason']}")
        if rows:
            print()

    # Four independent counts, because the halves can go blind separately. An
    # emptied member fixture still leaves 435 prototype methods to compare, and
    # the first version of this guard reported a clean `0 disagreements` for
    # exactly that input — the same shape of blindness the constructibility
    # fixture had. A fixture that keeps the names but drops the lengths would be
    # the same defect one field over, so `length` is counted on its own.
    for label, count in (
        ("namespace members", member_name),
        ("prototype methods", prototype_name),
        ("member lengths", member_length),
        ("prototype method lengths", prototype_length),
    ):
        if count != 0:
            continue
        print(f"the audit compared zero {label}, which cannot be a pass: the "
              f"namespace list, the fixture, or the binary is empty, unreadable, "
              f"or missing that field", file=sys.stderr)
        return 2

    # Every recorded row ends up in exactly one bucket, and the buckets are
    # printed so the arithmetic is checked rather than assumed. Without this the
    # summary quoted one number for a fixture holding a larger one, and a member
    # that stopped being installed would have shown up only as that number
    # shrinking — a measurement nobody is looking at.
    member_deferred = accounting["member_deferred"]
    member_unexplained = accounting["member_unexplained"]
    prototype_missing = accounting["prototype_missing"]
    member_recorded = accounting["member_recorded"]
    prototype_recorded = accounting["prototype_recorded"]

    if not as_json:
        print(f"members: recorded {member_recorded}, compared {member_name}, "
              f"skipped because deferred {len(member_deferred)}, "
              f"skipped for no declared reason {len(member_unexplained)}")
        print(f"prototype methods: recorded {prototype_recorded}, "
              f"compared {prototype_name}, not published here "
              f"{len(prototype_missing)}")
        for path in member_deferred:
            print(f"  deferred  {path}")
        for path in member_unexplained:
            print(f"  UNEXPLAINED  {path}")
        for path in prototype_missing:
            print(f"  not-published  {path}")
        print()

    # The arithmetic has to close. A row that is neither compared nor classified
    # means the classifier missed a shape, which is the blindness this accounting
    # exists to remove; saying so is better than printing numbers that happen to
    # look plausible.
    if member_name + len(member_deferred) + len(member_unexplained) != member_recorded:
        print(f"the audit accounted for {member_name + len(member_deferred) + len(member_unexplained)} "
              f"member(s) but the fixture records {member_recorded}: a row is neither "
              f"compared nor classified as skipped", file=sys.stderr)
        return 2

    # A member missing from the install path with no deferral behind it is an
    # installation defect. It is already an error row, so the exit status is
    # right through the usual path; this makes the reason explicit rather than
    # letting it read as a naming disagreement.
    if member_unexplained:
        print(f"{len(member_unexplained)} recorded member(s) are not installed and "
              f"no crate declares them deferred: {', '.join(member_unexplained)}",
              file=sys.stderr)

    name_rows = sum(1 for row in rows if row["field"] == "name")
    length_rows = sum(1 for row in rows if row["field"] == "length")
    print(f"{name_rows} binding function name(s) disagree with node, across "
          f"{member_name} member(s) and {prototype_name} prototype method(s) compared")
    print(f"{length_rows} binding function length(s) disagree with node, across "
          f"{member_length} member(s) and {prototype_length} prototype method(s) compared")
    return 0 if not rows else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", default=DEFAULT_ORACLE)
    parser.add_argument("--rustnode", default=DEFAULT_RUSTNODE)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--record",
                        help="write Node's function names and lengths to this path and exit")
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
        return report(*diff(recorded_members, recorded_prototypes,
                            actual_members, actual_prototypes), args.json)

    with tempfile.TemporaryDirectory() as workdir:
        oracle_members = enumerate_members(args.oracle, names, workdir)
    oracle_prototypes = enumerate_prototypes(args.oracle, classes_of(oracle_members))

    if args.record:
        return record(oracle_members, oracle_prototypes, args.record)

    with tempfile.TemporaryDirectory() as workdir:
        actual_members = enumerate_members(args.rustnode, names, workdir)
    actual_prototypes = enumerate_prototypes(args.rustnode, classes_of(actual_members))
    return report(*diff(oracle_members, oracle_prototypes,
                        actual_members, actual_prototypes), args.json)


if __name__ == "__main__":
    sys.exit(main())
