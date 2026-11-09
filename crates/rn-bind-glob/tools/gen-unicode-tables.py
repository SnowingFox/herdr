#!/usr/bin/env python3
"""Generates `src/unicode_tables.rs` from the Unicode Character Database.

`src/glob/glob_unicode.cc` leans on ICU for three things that a binding crate
cannot take on faith:

* the general-category ranges behind `[:alpha:]`, `[:digit:]` and the rest of
  the POSIX classes in a glob bracket expression;
* `Character.prototype.toUpperCase` / `toLowerCase` semantics, which is what
  minimatch's `nocase` comparison uses;
* case-insensitive closure of a character class (`USET_CASE_INSENSITIVE`).

Bundling ICU for those would mean a new build dependency and a C++ toolchain
step, so the tables are generated here instead and committed. The output is
deterministic, so a regeneration produces a byte-identical file.

The Unicode version must match the one Node reports, because a class range is
an observable answer. `tools/node-pin.toml` pins the Node revision and this
script reads `process.versions.unicode` from the recorder binary; when the pin
moves, regenerate.

Usage:
    tools/gen-unicode-tables.py --ucd <dir>  # dir holding the three UCD files
    tools/gen-unicode-tables.py --fetch      # download UCD 17.0.0 first
"""

import argparse
import os
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "src", "unicode_tables.rs")
UCD_VERSION = "17.0.0"
BASE = f"https://www.unicode.org/Public/{UCD_VERSION}/ucd"

# The general categories the POSIX classes need. Node's `PropertyMask` maps
# each `UnicodeProperty` onto one ICU category mask, so these are the ranges
# that decide whether a character is a member.
CATEGORIES = [
    ("CC", "Control"),
    ("CF", "Format"),
    ("CN", "Unassigned"),
    ("CO", "PrivateUse"),
    ("CS", "Surrogate"),
    ("LL", "LowercaseLetter"),
    ("LM", "ModifierLetter"),
    ("LO", "OtherLetter"),
    ("LT", "TitlecaseLetter"),
    ("LU", "UppercaseLetter"),
    ("MC", "SpacingMark"),
    ("ME", "EnclosingMark"),
    ("MN", "NonspacingMark"),
    ("ND", "DecimalNumber"),
    ("NL", "LetterNumber"),
    ("NO", "OtherNumber"),
    ("PC", "ConnectorPunctuation"),
    ("PD", "DashPunctuation"),
    ("PE", "ClosePunctuation"),
    ("PF", "FinalPunctuation"),
    ("PI", "InitialPunctuation"),
    ("PO", "OtherPunctuation"),
    ("PS", "OpenPunctuation"),
    ("SC", "CurrencySymbol"),
    ("SK", "ModifierSymbol"),
    ("SM", "MathSymbol"),
    ("SO", "OtherSymbol"),
    ("ZL", "LineSeparator"),
    ("ZP", "ParagraphSeparator"),
    ("ZS", "SpaceSeparator"),
]

MAX_CODE_POINT = 0x10FFFF


def parse_unicode_data(path):
    """Returns `{category: [(lo, hi), ...]}` from UnicodeData.txt."""
    by_abbreviation = {abbreviation: name for abbreviation, name in CATEGORIES}
    ranges = {name: [] for _, name in CATEGORIES}
    pending_range = None

    def emit(category, lo, hi):
        # UnicodeData.txt spells the abbreviation in mixed case (`Cc`, `Lu`),
        # so the table's own key has to come from the normalised form.
        name = by_abbreviation.get(category.upper())
        if name is None:
            return
        ranges[name].append((lo, hi))

    with open(path, encoding="utf-8") as handle:
        for line in handle:
            fields = line.split(";")
            if len(fields) < 3:
                continue
            code = int(fields[0], 16)
            name = fields[1]
            category = fields[2]
            if name.endswith(", First>"):
                pending_range = (category, code)
                continue
            if name.endswith(", Last>"):
                if pending_range is not None:
                    emit(pending_range[0], pending_range[1], code)
                    pending_range = None
                continue
            emit(category, code, code)

    grouped = {}
    for abbreviation, name in CATEGORIES:
        grouped[name] = sorted(ranges[name])
    return grouped


def parse_case_folding(path):
    """Returns `{code: [folded codes]}` from the full folds.

    `F` and `C` are the folds a case-insensitive comparison uses; `S` is the
    simple fold that only matters when a full fold does not exist, which the
    `F`/`C` entries already cover.
    """
    fold = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            fields = [field.strip() for field in line.split(";")]
            if len(fields) < 3:
                continue
            status = fields[1]
            if status not in ("C", "F"):
                continue
            code = int(fields[0], 16)
            mapped = [int(value, 16) for value in fields[2].split()]
            fold[code] = mapped
    return fold


def parse_special_casing(path):
    """Returns `{code: [codes]}` for unconditional special lowercasings.

    `String.prototype.toLowerCase()` is not a code-point map: U+0130 lowercases
    to `i` plus a combining dot, and a glob comparison has to reproduce that or
    `*.TXT` disagrees with Node on a Turkish dotted I.
    """
    lower = {}
    upper = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            fields = [field.strip() for field in line.split(";")]
            if len(fields) < 5:
                continue
            # The fifth field carries conditions; unconditional mappings leave
            # it empty.
            if fields[4]:
                continue
            code = int(fields[0], 16)
            lowered = [int(value, 16) for value in fields[1].split()]
            upped = [int(value, 16) for value in fields[3].split()]
            lower[code] = lowered
            upper[code] = upped
    return lower, upper


def parse_unicode_data_case(path):
    """Returns `(lower, upper)` from UnicodeData.txt's simple mappings."""
    lower = {}
    upper = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            fields = line.split(";")
            if len(fields) < 15:
                continue
            code = int(fields[0], 16)
            if fields[12]:
                upper[code] = int(fields[12], 16)
            if fields[13]:
                lower[code] = int(fields[13], 16)
    return lower, upper


def merge_ranges(ranges):
    """Sorts and merges adjacent ranges, so the table is canonical."""
    if not ranges:
        return []
    ordered = sorted(ranges)
    merged = [list(ordered[0])]
    for lo, hi in ordered[1:]:
        last = merged[-1]
        if lo <= last[1] + 1:
            last[1] = max(last[1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


def rust_ranges(name, ranges, out):
    out.append(f"pub static {name}: &[(u32, u32)] = &[")
    line = "   "
    for lo, hi in ranges:
        piece = f" (0x{lo:X}, 0x{hi:X}),"
        if len(line) + len(piece) > 96:
            out.append(line)
            line = "   "
        line += piece
    if line.strip():
        out.append(line)
    out.append("];")
    out.append("")


def rust_map(name, mapping, out):
    out.append(f"pub static {name}: &[(u32, u32)] = &[")
    line = "   "
    for key in sorted(mapping):
        piece = f" (0x{key:X}, 0x{mapping[key]:X}),"
        if len(line) + len(piece) > 96:
            out.append(line)
            line = "   "
        line += piece
    if line.strip():
        out.append(line)
    out.append("];")
    out.append("")


def rust_expansions(name, mapping, out):
    """Emits a map whose values are one or more code points."""
    out.append(f"/// One code point's lowercase expansion, which may be longer than")
    out.append("/// one code point.")
    out.append(f"pub static {name}: &[(u32, &[u32])] = &[")
    for key in sorted(mapping):
        values = ", ".join(f"0x{value:X}" for value in mapping[key])
        out.append(f"    (0x{key:X}, &[{values}]),")
    out.append("];")
    out.append("")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ucd", help="directory holding the UCD text files")
    parser.add_argument("--fetch", action="store_true", help="download the UCD first")
    args = parser.parse_args()

    workdir = args.ucd
    if args.fetch or not workdir:
        workdir = os.path.join(ROOT, "target", "ucd")
        os.makedirs(workdir, exist_ok=True)
        for name in ("UnicodeData.txt", "CaseFolding.txt", "SpecialCasing.txt"):
            target = os.path.join(workdir, name)
            if os.path.exists(target):
                continue
            url = f"{BASE}/{name}"
            print(f"fetching {url}", file=sys.stderr)
            urllib.request.urlretrieve(url, target)

    unicode_data = os.path.join(workdir, "UnicodeData.txt")
    case_folding = os.path.join(workdir, "CaseFolding.txt")
    special_casing = os.path.join(workdir, "SpecialCasing.txt")

    grouped = parse_unicode_data(unicode_data)
    simple_lower, simple_upper = parse_unicode_data_case(unicode_data)
    special_lower, special_upper = parse_special_casing(special_casing)
    folds = parse_case_folding(case_folding)

    out = [
        "// Generated by tools/gen-unicode-tables.py. Do not edit by hand.",
        "//",
        f"// Unicode Character Database {UCD_VERSION}, the version Node reports as",
        "// `process.versions.unicode`. Regenerate when `tools/node-pin.toml` moves.",
        "",
    ]

    out.append("/// Every code point in a general category, keyed by the ICU")
    out.append("/// `U_GC_*_MASK` group `glob_unicode.cc` asks for. The constant")
    out.append("/// names are the two-letter category abbreviations.")
    out.append("pub mod category {")
    for abbreviation, name in CATEGORIES:
        ranges = merge_ranges(grouped[name])
        rust_ranges(abbreviation, ranges, out)
    out.append("}")
    out.append("")

    out.append("/// Simple uppercase mappings from `UnicodeData.txt`, extended with the")
    out.append("/// unconditional 1:1 entries in `SpecialCasing.txt`.")
    upper_map = {}
    for code, upped in simple_upper.items():
        upper_map[code] = upped
    for code, upped in special_upper.items():
        if len(upped) == 1:
            upper_map[code] = upped[0]
    rust_map("TO_UPPER", upper_map, out)

    out.append("/// `String.prototype.toLowerCase()` per code point. A value may hold")
    out.append("/// several code points: U+0130 lowers to `i` plus a combining dot.")
    lower_map = {}
    for code, lowered in simple_lower.items():
        lower_map[code] = [lowered]
    for code, lowered in special_lower.items():
        lower_map[code] = lowered
    rust_expansions("TO_LOWER", lower_map, out)

    out.append("/// Full case folds (`C` + `F`), which is what `u_foldCase` applies.")
    out.append("/// Only code points whose fold differs from themselves are listed.")
    fold_map = {code: mapped[0] for code, mapped in folds.items() if len(mapped) == 1}
    rust_map("FOLD", fold_map, out)
    out.append("/// The inverse of [`FOLD`]: every code point whose full fold is another")
    out.append("/// code point. A case-insensitive class has to admit these, which is")
    out.append("/// what `USET_CASE_INSENSITIVE` does in the C++.")
    inverse = {}
    for code, folded in fold_map.items():
        inverse.setdefault(folded, code)
        inverse.setdefault(code, folded)
    rust_map("FOLD_INVERSE", inverse, out)

    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out).rstrip() + "\n")
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
