#!/usr/bin/env python3
"""Generates `src/generated.rs` from libuv's own headers.

`internalBinding('uv')` publishes one integer per entry of `UV_ERRNO_MAP`, the
`UV_DIRENT_*` enum, and the human-readable message for every error. None of that
is worth transcribing by hand: the values come from `deps/uv/include/uv.h` and
the platform error header it includes, and the messages come from the same
`UV_ERRNO_MAP` macro Node's `src/uv.cc` iterates.

Regenerate after bumping the Node pin in `tools/node-pin.toml`:

    cd rustnode
    ./crates/rn-bind-uv/tools/generate.py --uv-cc /tmp/node/src/uv.cc

`--uv-cc` is load-bearing, not a convenience. It compiles Node's own
`uv_errors_map` initializer, taken verbatim from that file, and compares the
resulting entry count with the table parsed here. A regex that silently matched
half of `UV_ERRNO_MAP` would therefore fail the run instead of shipping a short
namespace.

The headers under `tools/uv-headers/` are verbatim copies of the ones Node
compiles against, so regenerating needs no Node checkout for the values -- only
`cc`, for the preprocessor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

CRATE = Path(__file__).resolve().parent.parent
HEADERS = CRATE / "tools" / "uv-headers"
CONTRACTS = CRATE.parent.parent / "contracts"
OUTPUT = CRATE / "src" / "generated.rs"

# Floors, not expectations: a parse that silently yields a handful of rows is
# the failure mode this script exists to prevent, so it refuses to write a table
# smaller than a plausible libuv.
MIN_ERRORS = 80
MIN_DIRENT = 8
FUNCTION_MEMBERS = ("errname", "getErrorMap", "getErrorMessage")

MAP_BODY_RE = re.compile(r"^#define\s+UV_ERRNO_MAP\(XX\)(.*?)(?<!\\)\s*$", re.MULTILINE | re.DOTALL)
MAP_LINE_RE = re.compile(
    r'^\s*XX\(\s*([A-Za-z0-9_]+)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)\s*\\?\s*$'
)
DIRENT_RE = re.compile(r"^\s*(UV_DIRENT_[A-Z]+)\s*(?:=\s*-?\d+)?\s*,?\s*$")


def die(message):
    print(f"generate.py: {message}", file=sys.stderr)
    raise SystemExit(1)


def compiler():
    for candidate in ("cc", "gcc", "clang"):
        found = shutil.which(candidate)
        if found:
            return found
    die("no C compiler found; the generator needs `cc` for the preprocessor")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def map_body(header):
    match = MAP_BODY_RE.search(header.read_text())
    if not match:
        die(f"UV_ERRNO_MAP not found in {header}")
    return match.group(1)


def parse_map_text(header):
    """Reads `UV_ERRNO_MAP(XX)` as (name, message) pairs, by plain text parse."""
    entries = []
    for line in map_body(header).splitlines():
        line = line.strip()
        if not line or not line.startswith("XX("):
            continue
        match = MAP_LINE_RE.match(line)
        if not match:
            die(f"cannot parse UV_ERRNO_MAP line: {line!r}")
        entries.append((match.group(1), match.group(2)))
    return entries


def run_cc(source, output=None):
    """Compiles `source` from stdin and runs it, returning its stdout."""
    target = output or (CRATE / "tools" / ".probe.tmp")
    build = subprocess.run(
        [compiler(), "-I", str(HEADERS), "-o", str(target), "-x", "c", "-"],
        input=source,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        die(f"compiling the probe failed:\n{build.stderr}")
    try:
        return subprocess.run([str(target)], capture_output=True, text=True, check=True).stdout
    finally:
        target.unlink(missing_ok=True)


def preprocess(header_dir):
    """Returns every macro visible to a translation unit that includes uv.h.

    Reading values from the preprocessor rather than evaluating the
    `#if defined` chains by hand is what makes `ENOTSUP`/`EOPNOTSUPP` aliases and
    `UV__ERR(x)` indirection resolve exactly as the C compiler resolves them.
    """
    result = subprocess.run(
        [compiler(), "-E", "-dM", "-I", str(header_dir), "-x", "c", "-"],
        input='#include "uv.h"\n',
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        die(f"preprocessing uv.h failed:\n{result.stderr}")

    macros = {}
    for line in result.stdout.splitlines():
        if not line.startswith("#define "):
            continue
        name, _, value = line[len("#define "):].partition(" ")
        macros[name] = value.strip()
    return macros


def probe_map_expansion():
    """Expands `UV_ERRNO_MAP` through `cc`, a second way to read the same list.

    This mirrors what `src/uv.cc` asks the preprocessor for, so a map the regex
    above mis-parses shows up as a disagreement between the two counts.
    """
    source = (
        '#include "uv.h"\n'
        "#include <stdio.h>\n"
        "int main(void) {\n"
        '#define XX(name, message) printf("%s\\t%s\\n", #name, message);\n'
        "  UV_ERRNO_MAP(XX)\n"
        "#undef XX\n"
        "  return 0;\n"
        "}\n"
    )
    return [tuple(line.split("\t", 1)) for line in run_cc(source).splitlines()]


def resolve_macro_int(macros, name, seen=frozenset()):
    """Resolves an object-like macro to an integer, following symbolic aliases."""
    if name in seen:
        die(f"macro {name} resolves in a cycle")
    if name not in macros:
        die(f"macro {name} is not defined for this target")
    value = macros[name]
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        return resolve_macro_int(macros, value, seen | {name})
    die(f"cannot resolve macro {name} = {value!r}")


def resolve_uv_value(macros, name):
    """Resolves `UV_<name>` to an integer.

    `uv/errno.h` defines each entry as either `UV__ERR(SYM)` -- the negated
    platform errno -- or a literal `(-NNNN)` fallback for targets that do not
    define the symbol at all.
    """
    macro = f"UV__{name}"
    if macro not in macros:
        die(f"{macro} is not defined by uv/errno.h")
    value = macros[macro]

    wrapped = re.fullmatch(r"UV__ERR\(([A-Za-z_][A-Za-z0-9_]*)\)", value)
    if wrapped:
        # `UV__ERR(x)` is `(-(x))` when `EDOM > 0`, which holds on every target
        # rustnode builds for; a target where it did not would silently invert
        # every errno-mapped value.
        if macros.get("EDOM", "0").startswith("-"):
            die("this target has EDOM < 0, which flips every UV__ERR value")
        return -resolve_macro_int(macros, wrapped.group(1))

    literal = re.fullmatch(r"\((-?\d+)\)", value)
    if literal:
        return int(literal.group(1))

    die(f"cannot resolve {macro} = {value!r}")


def parse_dirent(header):
    """Reads `uv_dirent_type_t`, whose enumerators are implicit 0..n.

    The search starts from the first `UV_DIRENT_` enumerator and walks outward,
    because `uv_dirent_t` (a typedef of the struct) appears earlier in the header
    and would otherwise anchor the search on the wrong `enum`.
    """
    text = header.read_text()
    first = text.index("UV_DIRENT_")
    body = text[text.rindex("typedef enum {", 0, first):]
    body = body[: body.index("} uv_dirent_type_t;")]
    entries = []
    for line in body.splitlines():
        match = DIRENT_RE.match(line)
        if match:
            entries.append((match.group(1), len(entries)))
    if [value for _, value in entries] != list(range(len(entries))):
        die("uv_dirent_type_t is not a 0..n enum as this generator assumes")
    return entries


def count_uv_cc(uv_cc):
    """Reads what Node's `src/uv.cc` registers, and how many constants it defines.

    The constant count comes from compiling that file's own `uv_errors_map`
    initializer, `V` macro included, so it is the length of the table Node
    actually builds rather than a count of anything parsed here.
    """
    text = uv_cc.read_text()

    fields = re.search(r"struct UVError\s*\{(?P<body>[^}]*)\}\s*;", text)
    if not fields:
        die(f"cannot find `struct UVError` in {uv_cc}")
    names = re.findall(r"^\s*(?:int|const char\*)\s+(\w+)\s*;", fields.group("body"), re.MULTILINE)
    if names != ["value", "name", "message"]:
        die(f"{uv_cc}'s uv_errors_map has unexpected fields: {names}")

    macro = re.search(r"^#define V\(name, message\)\s*(?P<body>.+)$", text, re.MULTILINE)
    if not macro:
        die(f"cannot find the `V` registration macro in {uv_cc}")
    if macro.group("body").strip() != "{UV_##name, #name, message},":
        die(f"{uv_cc}'s V macro changed shape: {macro.group('body').strip()!r}")

    if text.count("UV_ERRNO_MAP(V)") != 1:
        die(f"expected exactly one UV_ERRNO_MAP(V) in {uv_cc}")

    # A second UV_ property defined anywhere in uv.cc would make the namespace
    # larger than the map, and the count would stop describing Node.
    stray = re.findall(r'"(UV_[A-Z0-9_]+)"', text)
    if stray:
        die(f"{uv_cc} names UV_ properties outside the map: {stray}")

    source = (
        '#include "uv.h"\n'
        "#include <stdio.h>\n"
        "struct UVError { int value; const char* name; const char* message; };\n"
        "static const struct UVError uv_errors_map[] = {\n"
        f"{macro.group(0)}\n"
        "UV_ERRNO_MAP(V)\n"
        "#undef V\n"
        "};\n"
        "int main(void) {\n"
        '  printf("%zu\\n", sizeof(uv_errors_map) / sizeof(uv_errors_map[0]));\n'
        "  return 0;\n"
        "}\n"
    )
    table_count = int(run_cc(source, CRATE / "tools" / ".uv-cc-count.tmp").strip())

    functions = re.findall(r'Set(?:Method|ConstructorFunction)\([^;]*?"(\w+)"\s*,', text, re.DOTALL)
    return table_count, functions


def contract_members():
    """Reads the authoritative member list from contracts/uv.json."""
    path = CONTRACTS / "uv.json"
    if not path.is_file():
        die(f"missing {path}; it is the definition of what this namespace must expose")
    return sorted(json.loads(path.read_text())["members"])


def rust_str(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(by_text, values, dirent, uv_cc_count, uv_cc_functions, members):
    lines = []
    add = lines.append
    add("// Generated by crates/rn-bind-uv/tools/generate.py. Do not edit by hand.")
    add("//")
    add("// Values come from libuv's own headers, vendored verbatim from the Node revision")
    add("// pinned in tools/node-pin.toml:")
    for name in ("uv.h", "uv/errno.h"):
        add(f"//   {name}  sha256 {sha256(HEADERS / name)}")
    add("//")
    add("// Cross-checks performed at generation time:")
    add("//   * UV_ERRNO_MAP read by text and by the preprocessor, which must agree")
    add(f"//   * Node's src/uv.cc compiles a {uv_cc_count}-entry `uv_errors_map`, and")
    add("//     UV_CC_REGISTRATIONS below is that number, so a short parse cannot ship")
    add(f"//   * src/uv.cc registers the functions {', '.join(uv_cc_functions)}")
    add(f"//   * the member list below, against contracts/uv.json ({len(members)} members)")
    add("//")
    add("// The numbers are Linux/glibc's: the syscall-mapped entries are `-errno`, so a")
    add("// target with different errno numbering needs a regenerated table. The tests in")
    add("// tests/constants.rs re-derive every value from these same headers and from")
    add("// libc, so a table that is wrong for the host fails instead of reaching JS.")
    add("")
    add("/// One `UV_ERRNO_MAP` entry.")
    add("///")
    add("/// `name` is the spelling `uv_err_name` returns: the map entry without the")
    add("/// `UV_` prefix that the namespace property carries.")
    add("#[derive(Debug, Clone, Copy)]")
    add("pub struct UvError {")
    add("    /// Name without its `UV_` prefix.")
    add("    pub name: &'static str,")
    add("    /// The value `UV_<name>` has; always negative.")
    add("    pub value: i32,")
    add("    /// The text `uv_strerror` returns for this error.")
    add("    pub message: &'static str,")
    add("}")
    add("")
    add("/// Every error libuv declares, in `UV_ERRNO_MAP` order.")
    add("///")
    add("/// The order is observable: `getErrorMap()` inserts in this order, so")
    add("/// JavaScript iterating the map sees the sequence Node produces.")
    add("pub const ERRORS: &[UvError] = &[")
    for name, message in by_text:
        add("    UvError {")
        add(f"        name: {rust_str(name)},")
        add(f"        value: {values[name]},")
        add(f"        message: {rust_str(message)},")
        add("    },")
    add("];")
    add("")
    add("/// How many `UV_*` constants Node's `src/uv.cc` registers.")
    add("///")
    add("/// Its `Initialize()` walks `uv_errors_map` once and defines one property per")
    add("/// entry, so this is both the table's length and the namespace's constant")
    add("/// count. `ERRORS` must have exactly this many entries; a test asserts it.")
    add(f"pub const UV_CC_REGISTRATIONS: usize = {uv_cc_count};")
    add("")
    add("/// `UV_DIRENT_*` from `uv_dirent_type_t`, in enum order.")
    add("///")
    add("/// Node also publishes these from `constants`, but")
    add("/// `lib/internal/vfs/providers/composable.js` destructures all eight out of")
    add("/// this namespace and `contracts/uv.json` records them here, so this crate")
    add("/// owns them.")
    add("pub const DIRENT: &[(&str, i32)] = &[")
    for name, value in dirent:
        add(f"    ({rust_str(name)}, {value}),")
    add("];")
    add("")
    add("/// Every property `internalBinding('uv')` publishes, matching")
    add("/// `contracts/uv.json`.")
    add("pub const MEMBERS: &[&str] = &[")
    for member in members:
        add(f"    {rust_str(member)},")
    add("];")
    add("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--uv-cc",
        type=Path,
        required=True,
        help="Node's src/uv.cc, whose error table is compiled to confirm the count",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail instead of writing when src/generated.rs is stale",
    )
    options = parser.parse_args()

    header = HEADERS / "uv.h"

    by_text = parse_map_text(header)
    if len(by_text) < MIN_ERRORS:
        die(f"parsed only {len(by_text)} UV_ERRNO_MAP entries from {header}")
    by_compiler = probe_map_expansion()
    if by_text != by_compiler:
        die(
            "the text parse and the preprocessor disagree about UV_ERRNO_MAP\n"
            f"  text:          {len(by_text)} entries\n"
            f"  preprocessor:  {len(by_compiler)} entries"
        )

    macros = preprocess(HEADERS)
    values = {}
    owner = {}
    for name, _ in by_text:
        value = resolve_uv_value(macros, name)
        if value in owner:
            die(f"{name} and {owner[value]} both resolve to {value}")
        values[name] = value
        owner[value] = name

    dirent = parse_dirent(header)
    if len(dirent) < MIN_DIRENT:
        die(f"parsed only {len(dirent)} UV_DIRENT_* entries from {header}")

    members = [f"UV_{name}" for name, _ in by_text] + [name for name, _ in dirent]
    members += list(FUNCTION_MEMBERS)
    contract = contract_members()
    if sorted(members) != contract:
        missing = sorted(set(contract) - set(members))
        extra = sorted(set(members) - set(contract))
        die(f"generated members disagree with contracts/uv.json: missing {missing}, extra {extra}")

    if not options.uv_cc.is_file():
        die(f"--uv-cc {options.uv_cc} does not exist")
    uv_cc_count, uv_cc_functions = count_uv_cc(options.uv_cc)
    if uv_cc_count != len(by_text):
        die(
            f"{options.uv_cc} builds a {uv_cc_count}-entry error table but "
            f"uv.h declares {len(by_text)} entries"
        )
    if sorted(uv_cc_functions) != sorted(FUNCTION_MEMBERS):
        die(f"{options.uv_cc} registers {uv_cc_functions}, expected {list(FUNCTION_MEMBERS)}")
    rendered = render(by_text, values, dirent, uv_cc_count, uv_cc_functions, members)

    if options.check:
        current = OUTPUT.read_text() if OUTPUT.exists() else ""
        if current != rendered:
            die(f"{OUTPUT.relative_to(CRATE)} is stale; rerun tools/generate.py")
        print(f"{OUTPUT.relative_to(CRATE)} is up to date ({len(by_text)} errors)")
        return 0

    OUTPUT.write_text(rendered)
    print(
        f"wrote {OUTPUT.relative_to(CRATE)}: {len(by_text)} errors, "
        f"{len(dirent)} dirent types, {len(members)} members, "
        f"{uv_cc_count} uv.cc registrations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
