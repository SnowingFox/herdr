#!/usr/bin/env python3
"""Gate step: `gen-options.py --check` with a named, exact, shrinking allowance.

`tools/gen-options.py --check` regenerates `crates/rn-bind-options/src/table.rs`
into memory and compares. On this tree it fails for exactly two entries, and no
gate step ran it, so that drift was invisible: the table could fall arbitrarily
far behind `src/node_options.cc` and every check stayed green. That is CLA-213.

# Why an allowance rather than a regeneration

The two entries that differ are a *decision*, not a bug in the generator:

  `--experimental-ffi`      committed `false`, generator `true`
      `src/node_options.h` defaults the field to `HAVE_FFI`, and a default
      Linux x64 `./configure` enables FFI, so the generator says `true`. This
      build links no libffi, so `true` would advertise a module whose first
      binding call fails. The committed `false` is deliberate.

  `--experimental-sqlite`   committed `true`, generator `false`
      This build compiles the vendored amalgamation, so the field is `true`.
      `gen-options.py`'s `MACROS` still records `HAVE_SQLITE=0`.

Changing either one moves `getCLIOptionsValues` and `process.features`, which is
a separate change with its own verification. Regenerating here would smuggle a
user-visible behaviour change into a gate-hardening commit.

# What makes this allowance safe

It is not "ignore those two options". Each entry names the exact fields that may
differ and the exact committed/generated value of each, so:

  * a *third* entry drifting fails;
  * a listed entry drifting in a *different* field fails;
  * a listed entry drifting to a *different* value fails;
  * an unlisted field, or a missing/extra option, fails.

And it ratchets: when a listed entry stops differing, or leaves the table, this
step fails and says to delete the entry. An allowance that outlives its defect
is how a gate learns to tolerate one.

Usage:
    tools/check-options-drift.py                 # use --node-src, NODE_SRC, /workspace/node, /tmp/node
    tools/check-options-drift.py --node-src DIR
    tools/check-options-drift.py --self-test     # prove the allowance still rejects drift

Exit codes:
  0  the table matches the generator, or differs only in the allowances below
  1  drift the allowance does not name
  2  no Node source tree, so there is nothing to compare against
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLE = os.path.join(ROOT, "crates", "rn-bind-options", "src", "table.rs")
GENERATOR = os.path.join(ROOT, "tools", "gen-options.py")

# The only entries allowed to differ, with the exact difference allowed.
#
# `committed` is what `table.rs` says today; `generated` is what
# `gen-options.py` derives from the pinned `src/node_options.cc` and
# `src/node_options.h`. Both sides are written out so the allowance describes a
# specific gap rather than a permissive shape. Keyed by option name; the value
# maps a field name to the pair of values that may differ.
ALLOWED = {
    "--experimental-ffi": {
        "default_is_true": ("false", "true"),
        "default": ("DefaultValue::Bool(false)", "DefaultValue::Bool(true)"),
    },
    "--experimental-sqlite": {
        "default_is_true": ("true", "false"),
        "default": ("DefaultValue::Bool(true)", "DefaultValue::Bool(false)"),
    },
}

# Why each allowance exists, printed when it is exercised so a reader of the log
# learns the reason instead of finding an unexplained pass.
REASONS = {
    "--experimental-ffi": (
        "committed false because this build links no libffi; the generator derives "
        "HAVE_FFI=1 from a default Linux x64 configure"
    ),
    "--experimental-sqlite": (
        "committed true because this build compiles the vendored amalgamation; "
        "gen-options.py's MACROS still record HAVE_SQLITE=0"
    ),
}


def load_generator():
    spec = importlib.util.spec_from_file_location("gen_options", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    # `gen-options.py` uses `@dataclass`, whose machinery looks the defining
    # module up in `sys.modules`; without this registration the import fails with
    # `'NoneType' object has no attribute '__dict__'`.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def option_records(text: str) -> dict[str, dict[str, str]]:
    """Every `OptionInfo { .. }` in a table, keyed by option name, field by field.

    The table is generated with `#[rustfmt::skip]`, so one field per line and one
    line per field is a property this comparison relies on. If that ever stops
    holding, `name` cannot be found and the option is reported as unparsable
    rather than silently skipped.
    """
    records: dict[str, dict[str, str]] = {}
    for block in re.finditer(r"OptionInfo \{(.*?)\n    \}", text, re.S):
        body = block.group(1)
        fields: dict[str, str] = {}
        for line in body.splitlines():
            match = re.match(r"\s*(\w+):\s*(.*?),?\s*$", line)
            if match:
                fields[match.group(1)] = match.group(2)
        raw_name = fields.pop("name", None)
        if raw_name is None:
            continue
        # The name is a Rust string literal, so the quotes are syntax rather than
        # part of the key: `ALLOWED` names options the way a user types them.
        name = raw_name.strip().strip('"')
        records[name] = fields
    return records


def compare(
    committed_text: str, generated_text: str, allowed_entries: dict | None = None
) -> list[str]:
    """The drift the allowance does not name, as human-readable lines.

    An empty list means "matches, or differs only inside the allowance".
    `allowed_entries` defaults to [`ALLOWED`]; the self-test passes its own so
    each rule can be exercised against fixtures that contain exactly the options
    under test, without weakening the production ratchet.
    """
    allowed_entries = ALLOWED if allowed_entries is None else allowed_entries
    committed = option_records(committed_text)
    generated = option_records(generated_text)
    problems: list[str] = []

    if not committed:
        return ["the committed table parsed to zero options; the parser or the file is broken"]
    if not generated:
        return ["the generated table parsed to zero options; the generator produced nothing"]

    for name in sorted(set(committed) - set(generated)):
        problems.append(f"{name}: present in the committed table, absent from the generator")
    for name in sorted(set(generated) - set(committed)):
        problems.append(f"{name}: the generator emits it, the committed table does not")

    for name in sorted(set(committed) & set(generated)):
        allowed = allowed_entries.get(name, {})
        for field in sorted(set(committed[name]) | set(generated[name])):
            have = committed[name].get(field, "<absent>")
            want = generated[name].get(field, "<absent>")
            if have == want:
                continue
            if field in allowed:
                permitted = allowed[field]
                if (have, want) == permitted:
                    continue
                problems.append(
                    f"{name}.{field}: committed {have}, generated {want}; "
                    f"the allowance names {permitted[0]} -> {permitted[1]}"
                )
                continue
            problems.append(f"{name}.{field}: committed {have}, generated {want}")

    # The ratchet: an allowance whose gap closed is stale and must be deleted,
    # or the next real regression in that field passes inside it.
    for name, allowed in allowed_entries.items():
        if name not in committed and name not in generated:
            problems.append(
                f"{name}: allowed to differ, but the option is gone from both tables; "
                f"remove its entry from ALLOWED"
            )
            continue
        still_differing = any(
            committed.get(name, {}).get(field) != generated.get(name, {}).get(field)
            for field in allowed
        )
        if not still_differing:
            problems.append(
                f"{name}: allowed to differ, but the two tables now agree; "
                f"remove its entry from ALLOWED"
            )

    return problems


def find_node_source(explicit: str | None) -> str | None:
    """The first Node checkout that has the two files the generator reads."""
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("NODE_SRC"):
        candidates.append(os.environ["NODE_SRC"])
    candidates.extend(["/workspace/node", "/tmp/node"])
    for candidate in candidates:
        if candidate and os.path.isfile(os.path.join(candidate, "src", "node_options.cc")):
            return candidate
    return None


def self_test(generator) -> int:
    """Proves the comparison still rejects each drift shape.

    Same reason every other check in this tree has one: a comparison that cannot
    fail is the defect it is supposed to guard. The fixtures are synthetic, and
    each case supplies its own allowance so the rules can be exercised against a
    two-option table without touching the production entry list.

    The production allowance itself is exercised by the real run, which is what
    `tools/check.sh` does; this proves the *mechanism* rejects drift.
    """
    allow = {
        "--flip": {
            "default_is_true": ("false", "true"),
            "default": ("DefaultValue::Bool(false)", "DefaultValue::Bool(true)"),
        }
    }

    def table(second_name: str, flip_true: bool, flip_kind: str = "2", flip_help: str = "flip") -> str:
        return (
            "OPTIONS: &[OptionInfo] = &[\n"
            "    OptionInfo {\n"
            '        name: "--stable",\n'
            '        help_text: "stable",\n'
            "        kind: 2,\n"
            "        env_setting: 0,\n"
            "        default_is_true: false,\n"
            "        namespace: OptionNamespace::None,\n"
            "        default: DefaultValue::Bool(false),\n"
            "    },\n"
            "    OptionInfo {\n"
            f'        name: "{second_name}",\n'
            f'        help_text: "{flip_help}",\n'
            f"        kind: {flip_kind},\n"
            "        env_setting: 0,\n"
            f"        default_is_true: {'true' if flip_true else 'false'},\n"
            "        namespace: OptionNamespace::None,\n"
            f"        default: DefaultValue::Bool({'true' if flip_true else 'false'}),\n"
            "    },\n"
            "]\n"
        )

    committed = table("--flip", False)
    generated = table("--flip", True)

    failures = 0

    def expect(name: str, have: str, want: str, should_fail: bool, needle: str = "", allowance: dict | None = None) -> None:
        nonlocal failures
        problems = compare(have, want, allow if allowance is None else allowance)
        failed = bool(problems)
        if failed != should_fail:
            print(f"FAIL self-test: {name}: problems={problems}", file=sys.stderr)
            failures += 1
            return
        if needle and not any(needle in problem for problem in problems):
            print(f"FAIL self-test: {name}: no problem mentioned {needle!r}: {problems}", file=sys.stderr)
            failures += 1
            return
        print(f"ok   self-test: {name}")

    expect("identical tables pass", committed, committed, False, "", {})
    expect("the named allowance passes", committed, generated, False)
    expect(
        "a third entry drifting fails",
        committed,
        generated.replace('name: "--stable"', 'name: "--renamed"'),
        True,
        "--stable: present in the committed table",
    )
    expect(
        "an allowed entry drifting in another field fails",
        committed,
        table("--flip", True, flip_help="changed"),
        True,
        "--flip.help_text",
    )
    expect(
        "an allowed entry drifting to a different value fails",
        committed,
        table("--flip", True, flip_kind="3"),
        True,
        "--flip.kind",
    )
    expect(
        "the allowed field differing in the wrong direction fails",
        committed,
        table("--flip", False),
        True,
        "remove its entry from ALLOWED",
    )
    expect(
        "an allowance whose gap closed fails",
        committed,
        committed,
        True,
        "remove its entry from ALLOWED",
    )
    expect(
        "an allowance naming an option that left the table fails",
        committed,
        committed,
        True,
        "gone from both tables",
        {"--gone": {"default_is_true": ("false", "true")}},
    )
    expect(
        "an unparsable committed table fails",
        "",
        generated,
        True,
        "zero options",
    )
    expect(
        "an unparsable generated table fails",
        committed,
        "",
        True,
        "zero options",
    )

    if failures:
        print(f"self-test: {failures} case(s) did not behave as required", file=sys.stderr)
        return 1
    print("self-test: the comparison rejects every drift shape it must")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--node-src", default=None)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    generator = load_generator()

    if args.self_test:
        return self_test(generator)

    node_src = find_node_source(args.node_src)
    if node_src is None:
        # A skip here would be the defect this whole file is about: the gate
        # would report green having compared nothing. It is an error instead, and
        # the message says how to satisfy it.
        print(
            "options drift: no Node source tree; pass --node-src, or set NODE_SRC. "
            "Expected src/node_options.cc and src/node_options.h at the pinned "
            "revision f344e7f552e.",
            file=sys.stderr,
        )
        return 2

    generated = generator.generate(node_src)
    try:
        with open(TABLE, encoding="utf-8") as handle:
            committed = handle.read()
    except FileNotFoundError:
        print(f"options drift: {TABLE} is missing", file=sys.stderr)
        return 1

    problems = compare(committed, generated)
    if problems:
        print(
            f"options drift: {TABLE} disagrees with {node_src} in ways the allowance "
            "does not name:",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "regenerate with `python3 tools/gen-options.py --node-src "
            f"{node_src}`, or extend ALLOWED with an exact, reasoned entry.",
            file=sys.stderr,
        )
        return 1

    print(f"options drift: {TABLE} matches {node_src} apart from the recorded allowances")
    for name in sorted(ALLOWED):
        print(f"  allowed: {name}: {REASONS[name]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
