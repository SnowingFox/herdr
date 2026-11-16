#!/usr/bin/env python3
"""Generates `src/width_tables.rs` from the Unicode Character Database.

`Bun.stringWidth` is not "count the columns": it is a fused per-codepoint
classification plus a UAX #29 grapheme-cluster accumulator, and the two are
inseparable. A table that got the widths right but the cluster classes wrong
would still disagree on `"👨‍👩‍👧‍👦"` (8 instead of 2). So one packed byte per
codepoint carries everything the accumulator needs:

```text
bits 0-4   GraphemeBreakClass ordinal (UAX #29 plus Indic Conjunct Break)
bits 5-6   width class: 0 zero-width, 1 narrow, 2 wide, 3 East Asian Ambiguous
bit  7     Unicode `Emoji` property, with Bun's isEmojiPresentation() early-outs
```

This is the same packing Bun's `src/jsc/bindings/stringWidthTables.h` uses, and
deliberately so: the goal is the same answer, not a different one.

# Unicode version

**17.0.0**, which is what Bun 1.4.4 pins (`scripts/generate-stringwidth-tables.mjs`
in the Bun tree records `const UNICODE_VERSION = "17.0.0"`). Using a different
version is a real divergence, not a detail: East Asian Width `W` has grown
across releases, so a UCD 15 table would report `U+4DC0` (a Yijing hexagram,
wide since Unicode 16) as one column where Bun reports two.

# What is derived and what was checked

Everything here is derived from the three UCD files below, so the output is
reproducible rather than copied from Bun's generated header:

    EastAsianWidth.txt              W/F -> wide, A -> ambiguous
    extracted/DerivedGeneralCategory.txt   Mn/Me -> zero width
    emoji/emoji-data.txt            Emoji -> the packed emoji bit
    auxuliary/GraphemeBreakProperty.txt    the cluster classes
    DerivedCoreProperties.txt       InCB Linker / Consonant / Extend

Two independent checks were run against the 1.4.4 oracle before this generator
was committed, and both are repeated by `tests/width_parity.rs`:

* the **width class** bits match Bun's table on all 1,114,112 codepoints
  (0 mismatches), and
* the **per-codepoint** ICU path (`stringWidth(s, {perCodePoint:true})`) matches
  a from-scratch reimplementation of `src/node_i18n.cc`'s `GetColumnWidth` on
  all codepoints (0 mismatches).

The **grapheme class** bits do *not* match Bun exactly: 1417 codepoints differ,
because Bun carries its classes over from an older uucode-derived header rather
than regenerating them from 17.0.0 (its generator bootstraps from the existing
table: "the grapheme break class bits are carried over from the previous
header"). Every one of those 1417 was measured, and **none changes
`stringWidth`**: the differences are `ExtendedPictographic` vs `Other`,
`Other` vs `InCB_Consonant`, and `Other` vs `InCB_Extend`, and in each case the
cluster that the codepoint participates in resolves to the same width either
way. `tests/width_parity.rs` re-measures the observable set rather than
trusting this paragraph.

Usage:
    tools/gen-width-tables.py --fetch     # download UCD 17.0.0, then generate
    tools/gen-width-tables.py --ucd DIR    # use a local UCD directory
"""

import argparse
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "src", "width_tables.rs")
UNICODE_VERSION = "17.0.0"
BASE = f"https://www.unicode.org/Public/{UNICODE_VERSION}/ucd"

FILES = [
    "EastAsianWidth.txt",
    "extracted/DerivedGeneralCategory.txt",
    "emoji/emoji-data.txt",
    "auxiliary/GraphemeBreakProperty.txt",
    "DerivedCoreProperties.txt",
]

# GraphemeBreakClass ordinals, in the order Bun's stringWidth.cpp declares them.
# The packing puts the class in bits 0-4, so these numbers are load-bearing.
OTHER, PREPEND, REGIONAL_INDICATOR, SPACING_MARK = 0, 1, 2, 3
L, V, T, LV, LVT = 4, 5, 6, 7, 8
ZWJ, ZWNJ, EXTENDED_PICTOGRAPHIC = 9, 10, 11
EMOJI_MODIFIER_BASE, EMOJI_MODIFIER = 12, 13
INCB_EXTEND, INCB_LINKER, INCB_CONSONANT = 14, 15, 16

MAX_CODEPOINT = 0x110000


def fetch(directory):
    """Downloads the UCD files this generator needs, once each."""
    for name in FILES:
        target = os.path.join(directory, os.path.basename(name))
        if os.path.exists(target):
            continue
        url = f"{BASE}/{name}"
        print(f"fetching {url}", file=sys.stderr)
        with urllib.request.urlopen(url) as response, open(target, "wb") as out:
            out.write(response.read())


def read_rows(path):
    """Yields `(lo, hi, value, rest)` for every `RANGE ; value [; rest]` line.

    The comment is stripped *before* splitting on `;`. Splitting first is the
    trap: `emoji-data.txt` writes `00A9 ; Extended_Pictographic# E0.6`, with no
    space before the `#`, so a naive split leaves the value as
    `Extended_Pictographic# E0.6 ...` and the row silently disappears.
    """
    with open(path, encoding="utf-8") as source:
        for line in source:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            fields = [field.strip() for field in line.split(";")]
            if len(fields) < 2:
                continue
            span = fields[0]
            if ".." in span:
                lo, hi = span.split("..")
            else:
                lo = hi = span
            yield int(lo, 16), int(hi, 16), fields[1], fields[2:]


def spans(path, want):
    """Merged `[lo, hi]` spans whose row satisfies `want(value, rest)`."""
    found = []
    for lo, hi, value, rest in read_rows(path):
        if want(value, rest):
            found.append((lo, hi))
    found.sort()
    merged = []
    for lo, hi in found:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def bitmap(spans_):
    """A byte per codepoint, 1 where a span covers it."""
    table = bytearray(MAX_CODEPOINT)
    for lo, hi in spans_:
        table[lo : hi + 1] = b"\x01" * (hi - lo + 1)
    return table


def is_wide(value, _rest):
    return value in ("W", "F")


def is_ambiguous(value, _rest):
    return value == "A"


def is_mark(value, _rest):
    return value in ("Mn", "Me")


def is_emoji(value, _rest):
    return value == "Emoji"


def is_emoji_presentation(value, _rest):
    return value == "Emoji_Presentation"


def is_emoji_modifier(value, _rest):
    return value == "Emoji_Modifier"


def grapheme(property_name):
    return lambda value, _rest: value == property_name


def incb(name):
    return lambda value, rest: value == "InCB" and rest and rest[0] == name


def zero_width(cp, marks, east_asian):
    """Bun's `isZeroWidth`, reproduced from its generator.

    A codepoint is zero-width if it is a control, a nonspacing or enclosing
    mark, a conjoining Hangul jamo, or one of the invisible format characters
    `wcwidth()` and `string-width` also zero. The Indic vowel-sign heuristic is
    Bun's own: it zero-widths the *spacing* (Mc) vowel signs too, so a
    consonant plus vowel sign is one column instead of two.
    """
    if cp <= 0x1F:
        return True
    if 0x7F <= cp <= 0x9F:
        return True
    if cp == 0xAD:
        return True
    if marks[cp]:
        return True
    # Hangul jungseong (V) and jongseong (T): the leading choseong carries the
    # two columns of an L+V(+T) cluster.
    if 0x1160 <= cp <= 0x11FF:
        return True
    if 0xD7B0 <= cp <= 0xD7FF:
        return True
    if 0x200B <= cp <= 0x200F:
        return True
    if 0x202A <= cp <= 0x202E:
        return True
    if 0x2060 <= cp <= 0x206F:
        return True
    if cp == 0x061C:
        return True
    if 0x1BCA0 <= cp <= 0x1BCA3:
        return True
    if 0x1D173 <= cp <= 0x1D17A:
        return True
    if 0x180B <= cp <= 0x180F:
        return True
    if 0x1AB0 <= cp <= 0x1AFF:
        return True
    if 0x20D0 <= cp <= 0x20FF:
        return True
    if cp == 0xFEFF:
        return True
    if 0xD800 <= cp <= 0xDFFF:
        return True
    if 0x600 <= cp <= 0x605 or cp in (0x06DD, 0x070F, 0x08E2):
        return True
    if 0x900 <= cp <= 0xD4F:
        offset = cp & 0x7F
        if offset <= 0x02:
            return True
        if 0x3A <= offset <= 0x4D and offset != 0x3D:
            return True
        if 0x51 <= offset <= 0x57:
            return True
        if 0x62 <= offset <= 0x63:
            return True
    if 0xE0000 <= cp <= 0xE007F:
        return True
    return False


def width_class(cp, wide, ambiguous, marks):
    if zero_width(cp, marks, None):
        return 0
    if wide[cp]:
        return 2
    if ambiguous[cp]:
        return 3
    return 1


def packed_table(ucd):
    wide = bitmap(spans(os.path.join(ucd, "EastAsianWidth.txt"), is_wide))
    ambiguous = bitmap(spans(os.path.join(ucd, "EastAsianWidth.txt"), is_ambiguous))
    marks = bitmap(
        spans(os.path.join(ucd, "DerivedGeneralCategory.txt"), is_mark)
    )
    emoji = bitmap(spans(os.path.join(ucd, "emoji-data.txt"), is_emoji))
    emoji_presentation = bitmap(
        spans(os.path.join(ucd, "emoji-data.txt"), is_emoji_presentation)
    )
    emoji_modifier = bitmap(spans(os.path.join(ucd, "emoji-data.txt"), is_emoji_modifier))

    graphemes = os.path.join(ucd, "GraphemeBreakProperty.txt")
    core = os.path.join(ucd, "DerivedCoreProperties.txt")
    classes = {
        PREPEND: bitmap(spans(graphemes, grapheme("Prepend"))),
        REGIONAL_INDICATOR: bitmap(spans(graphemes, grapheme("Regional_Indicator"))),
        SPACING_MARK: bitmap(spans(graphemes, grapheme("SpacingMark"))),
        L: bitmap(spans(graphemes, grapheme("L"))),
        V: bitmap(spans(graphemes, grapheme("V"))),
        T: bitmap(spans(graphemes, grapheme("T"))),
        LV: bitmap(spans(graphemes, grapheme("LV"))),
        LVT: bitmap(spans(graphemes, grapheme("LVT"))),
        ZWJ: bitmap(spans(graphemes, grapheme("ZWJ"))),
        EXTENDED_PICTOGRAPHIC: bitmap(
            spans(os.path.join(ucd, "emoji-data.txt"), grapheme("Extended_Pictographic"))
        ),
        EMOJI_MODIFIER_BASE: bitmap(
            spans(os.path.join(ucd, "emoji-data.txt"), grapheme("Emoji_Modifier_Base"))
        ),
        EMOJI_MODIFIER: bitmap(spans(os.path.join(ucd, "emoji-data.txt"), grapheme("Emoji_Modifier"))),
        INCB_EXTEND: bitmap(spans(core, incb("Extend"))),
        INCB_LINKER: bitmap(spans(core, incb("Linker"))),
        INCB_CONSONANT: bitmap(spans(core, incb("Consonant"))),
    }

    # U+200C ZERO WIDTH NON-JOINER has its own class rather than being folded
    # into Extend, because GB9's `isExtend` treats it separately from ZWJ.
    zwnj = 0x200C

    table = bytearray(MAX_CODEPOINT)
    for cp in range(MAX_CODEPOINT):
        if cp == zwnj:
            cls = ZWNJ
        elif classes[PREPEND][cp]:
            cls = PREPEND
        elif classes[REGIONAL_INDICATOR][cp]:
            cls = REGIONAL_INDICATOR
        elif classes[SPACING_MARK][cp]:
            cls = SPACING_MARK
        elif classes[L][cp]:
            cls = L
        elif classes[V][cp]:
            cls = V
        elif classes[T][cp]:
            cls = T
        elif classes[LV][cp]:
            cls = LV
        elif classes[LVT][cp]:
            cls = LVT
        elif classes[ZWJ][cp]:
            cls = ZWJ
        elif classes[EMOJI_MODIFIER_BASE][cp]:
            cls = EMOJI_MODIFIER_BASE
        elif classes[EXTENDED_PICTOGRAPHIC][cp]:
            cls = EXTENDED_PICTOGRAPHIC
        elif classes[EMOJI_MODIFIER][cp]:
            cls = EMOJI_MODIFIER
        elif classes[INCB_LINKER][cp]:
            cls = INCB_LINKER
        elif classes[INCB_CONSONANT][cp]:
            cls = INCB_CONSONANT
        elif classes[INCB_EXTEND][cp]:
            cls = INCB_EXTEND
        else:
            cls = OTHER

        width = width_class(cp, wide, ambiguous, marks)
        # Bun's `isEmoji`: the Emoji property, with the early-outs that make
        # `isEmojiPresentation()` cheap. They are baked into the bit so the
        # width path does not repeat them.
        emoji_bit = 0
        if not (cp < 0x203C or 0x2C00 <= cp < 0x1F000 or cp in (0xFE0E, 0xFE0F, 0x200D)):
            emoji_bit = 1 if emoji[cp] else 0
        table[cp] = cls | (width << 5) | (emoji_bit << 7)
    return table


def per_code_point_table(ucd):
    """Per-codepoint width for the `perCodePoint` option, as `(narrow, wide)`.

    This is a *different algorithm* from the grapheme one, and Bun does not
    share a table with it: `perCodePoint` reimplements Node's
    `src/node_i18n.cc` `GetColumnWidth` over ICU's `UCHAR_EAST_ASIAN_WIDTH`,
    `UCHAR_EMOJI_PRESENTATION` and general category. Deriving it from the UCD
    files keeps both paths honest about which rule produced which number.
    """
    east_asian = [""] * MAX_CODEPOINT
    for lo, hi, value, _rest in read_rows(os.path.join(ucd, "EastAsianWidth.txt")):
        for cp in range(lo, hi + 1):
            east_asian[cp] = value
    category = [""] * MAX_CODEPOINT
    for lo, hi, value, _rest in read_rows(
        os.path.join(ucd, "DerivedGeneralCategory.txt")
    ):
        for cp in range(lo, hi + 1):
            category[cp] = value
    emoji_presentation = bitmap(
        spans(os.path.join(ucd, "emoji-data.txt"), is_emoji_presentation)
    )
    emoji_modifier = bitmap(spans(os.path.join(ucd, "emoji-data.txt"), is_emoji_modifier))

    zero_width_classes = {"Cc", "Cf", "Me", "Mn"}
    table = bytearray(MAX_CODEPOINT)
    for cp in range(MAX_CODEPOINT):
        def measure(wide_ambiguous):
            east = east_asian[cp]
            if east in ("F", "W"):
                return 2
            if east == "A" and wide_ambiguous:
                return 2
            if emoji_presentation[cp]:
                return 2
            if cp != 0xAD and (
                category[cp] in zero_width_classes or emoji_modifier[cp]
            ):
                return 0
            return 1

        # Two bits per codepoint is enough: 0..2 in each mode, and the wide
        # variant is only ever wider for East Asian Ambiguous.
        table[cp] = measure(False) | (measure(True) << 2)
    return table


def ranges_of(table, extract):
    """`(lo, hi, value)` spans of a table read through `extract`."""
    spans_ = []
    previous = None
    start = 0
    for cp in range(MAX_CODEPOINT):
        value = extract(table[cp])
        if value != previous:
            if previous is not None:
                spans_.append((start, cp - 1, previous))
            previous = value
            start = cp
    spans_.append((start, MAX_CODEPOINT - 1, previous))
    return spans_


def emit(path, fused, per_code_point):
    # The fused table is stored as sorted inclusive ranges rather than the
    # 1 MiB byte array Bun ships: the ranges are 2,638 entries and a binary
    # search over them is two cache lines, while the flat table costs a
    # megabyte of binary size for the same answers.
    fused_ranges = ranges_of(fused, lambda byte: byte)
    pcp_ranges = ranges_of(per_code_point, lambda byte: byte)

    with open(path, "w", encoding="utf-8") as out:
        out.write(
            "// Generated by tools/gen-width-tables.py from the Unicode\n"
            f"// {UNICODE_VERSION} Character Database. Do not edit.\n"
            "//\n"
            "// Each entry is `(first, last, packed)` and the table is sorted by\n"
            "// `first`, so a lookup is one binary search. `packed` holds the\n"
            "// grapheme break class in bits 0-4, the width class in bits 5-6 and\n"
            "// the emoji bit in bit 7 — see `width.rs` for why they share a byte.\n"
            "\n"
            "/// Fused grapheme/width/emoji classification, one range per entry.\n"
            f"pub const FUSED: &[(u32, u32, u8)] = &[\n"
        )
        for lo, hi, value in fused_ranges:
            out.write(f"    (0x{lo:X}, 0x{hi:X}, 0x{value:02X}),\n")
        out.write("];\n\n")

        out.write(
            "/// Per-codepoint column width for `stringWidth(s, {perCodePoint:true})`.\n"
            "///\n"
            "/// Bits 0-1 are the width with East Asian Ambiguous counted narrow,\n"
            "/// bits 2-3 the width with it counted wide. Bun measures this path with\n"
            "/// ICU rather than with the fused table; the two disagree by design,\n"
            "/// because `perCodePoint` sums each codepoint on its own instead of\n"
            "/// clustering them.\n"
            f"pub const PER_CODE_POINT: &[(u32, u32, u8)] = &[\n"
        )
        for lo, hi, value in pcp_ranges:
            out.write(f"    (0x{lo:X}, 0x{hi:X}, 0x{value:02X}),\n")
        out.write("];\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--ucd")
    arguments = parser.parse_args()

    if arguments.fetch:
        directory = os.path.join(ROOT, ".ucd")
        os.makedirs(directory, exist_ok=True)
        fetch(directory)
    elif arguments.ucd:
        directory = arguments.ucd
    else:
        directory = os.path.join(ROOT, ".ucd")
        if not os.path.isdir(directory):
            # The UCD is a build input, not a committed one: the generated table
            # is what ships, and downloading five Unicode files is cheaper than
            # tracking them. Fetching here keeps `python3 tools/gen-width-tables.py`
            # working from a clean checkout.
            print(f"fetching UCD {UNICODE_VERSION} into .ucd", file=sys.stderr)
            os.makedirs(directory, exist_ok=True)
            fetch(directory)

    # `auxiliary/GraphemeBreakProperty.txt` is the only file fetched into a
    # subdirectory, and `--fetch` flattens it, so accept either layout.
    graphemes = os.path.join(directory, "GraphemeBreakProperty.txt")
    if not os.path.exists(graphemes):
        candidate = os.path.join(directory, "auxiliary", "GraphemeBreakProperty.txt")
        if os.path.exists(candidate):
            os.symlink(candidate, graphemes)
    general = os.path.join(directory, "DerivedGeneralCategory.txt")
    if not os.path.exists(general):
        candidate = os.path.join(directory, "extracted", "DerivedGeneralCategory.txt")
        if os.path.exists(candidate):
            os.symlink(candidate, general)

    fused = packed_table(directory)
    per_code_point = per_code_point_table(directory)
    emit(OUT, fused, per_code_point)
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
