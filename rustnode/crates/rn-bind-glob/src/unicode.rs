//! Case mapping and character-set arithmetic for glob matching.
//!
//! This is the port of `src/glob/glob_unicode.cc`. The C++ original calls into
//! ICU for case folding and for the Unicode property ranges behind a POSIX
//! class; here the same data is bundled as static tables
//! (`tools/gen-unicode-tables.py` generates them from the UCD), so the crate
//! gains no build dependency and stays deterministic.
//!
//! Two different case operations live here and they are not interchangeable:
//!
//! * [`canonicalize`] is a *comparison* fold. It maps a code point to one
//!   representative so two equivalent characters compare equal. Above ASCII it
//!   uses the simple uppercase mapping, and deliberately refuses a lowercase
//!   character whose uppercase form is ASCII (U+017F's uppercase is `S`, but
//!   `ſ` is not `s` for glob purposes).
//! * [`append_lowered`] is `String.prototype.toLowerCase()`, which produces an
//!   answer rather than a comparison. `*.TXT` matched against `file.txt` folds
//!   the subject with this one.

use crate::unicode_tables::{category, FOLD, FOLD_INVERSE, TO_LOWER, TO_UPPER};

/// The last code point whose case mapping is pure ASCII arithmetic.
pub const MAX_ASCII: u32 = 0x7F;

const MAX_CODE_POINT: u32 = 0x10FFFF;
const MAX_CODE_UNIT: u32 = 0xFFFF;

/// `toLowerCase` for a single code point, ASCII fast path included.
pub fn ascii_lower(c: u32) -> u32 {
    if (b'A' as u32..=b'Z' as u32).contains(&c) {
        c + 32
    } else {
        c
    }
}

/// `toUpperCase` for a single code point, ASCII fast path included.
pub fn ascii_upper(c: u32) -> u32 {
    if (b'a' as u32..=b'z' as u32).contains(&c) {
        c - 32
    } else {
        c
    }
}

/// The Unicode general categories a POSIX class in a bracket expression needs.
///
/// These mirror the ICU `U_GC_*_MASK` groups `glob_unicode.cc` passes to
/// `applyIntPropertyValue`, so `[:alpha:]` covers the same code points Node
/// covers rather than an approximation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicodeProperty {
    /// `\p{L}`
    Letter,
    /// `\p{Nl}`
    LetterNumber,
    /// `\p{Nd}`
    DecimalNumber,
    /// `\p{Zs}`
    SpaceSeparator,
    /// `\p{Cc}`
    Control,
    /// `\p{Z}`
    Separator,
    /// `\p{C}`
    Other,
    /// `\p{Ll}`
    Lowercase,
    /// `\p{Lu}`
    Uppercase,
    /// `\p{P}`
    Punctuation,
    /// `\p{Pc}`
    Connector,
}

impl UnicodeProperty {
    /// The generated tables this property is made of.
    fn parts(self) -> &'static [&'static [(u32, u32)]] {
        // `\p{L}` is the union of five categories, which no single generated
        // table holds, so that one is assembled once.
        static LETTER: std::sync::OnceLock<[&'static [(u32, u32)]; 5]> = std::sync::OnceLock::new();
        static SEPARATOR: [&[(u32, u32)]; 3] = [category::ZS, category::ZL, category::ZP];
        static OTHER: [&[(u32, u32)]; 5] = [
            category::CC,
            category::CF,
            category::CN,
            category::CO,
            category::CS,
        ];
        static PUNCTUATION: [&[(u32, u32)]; 7] = [
            category::PC,
            category::PD,
            category::PE,
            category::PF,
            category::PI,
            category::PO,
            category::PS,
        ];
        static LETTER_NUMBER: [&[(u32, u32)]; 1] = [category::NL];
        static DECIMAL: [&[(u32, u32)]; 1] = [category::ND];
        static SPACE_SEPARATOR: [&[(u32, u32)]; 1] = [category::ZS];
        static CONTROL: [&[(u32, u32)]; 1] = [category::CC];
        static LOWERCASE: [&[(u32, u32)]; 1] = [category::LL];
        static UPPERCASE: [&[(u32, u32)]; 1] = [category::LU];
        static CONNECTOR: [&[(u32, u32)]; 1] = [category::PC];

        match self {
            Self::Letter => LETTER.get_or_init(|| {
                [
                    category::LU,
                    category::LL,
                    category::LT,
                    category::LM,
                    category::LO,
                ]
            }),
            // `\p{Z}` is `Zs`, `Zl` and `Zp`.
            Self::Separator => &SEPARATOR,
            // `\p{C}` is `Cc`, `Cf`, `Cn`, `Co` and `Cs`.
            Self::Other => &OTHER,
            // `\p{P}` is the seven punctuation categories.
            Self::Punctuation => &PUNCTUATION,
            Self::LetterNumber => &LETTER_NUMBER,
            Self::DecimalNumber => &DECIMAL,
            Self::SpaceSeparator => &SPACE_SEPARATOR,
            Self::Control => &CONTROL,
            Self::Lowercase => &LOWERCASE,
            Self::Uppercase => &UPPERCASE,
            Self::Connector => &CONNECTOR,
        }
    }
}

/// An immutable set of code points, stored as sorted, merged ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CharSet {
    ranges: Vec<(u32, u32)>,
    /// Set once the ranges are sorted and merged, so `contains` can binary
    /// search. `seal` clears it when more members are added.
    sealed: bool,
}

impl CharSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_range(&mut self, lo: u32, hi: u32) {
        if lo > hi {
            return;
        }
        self.ranges.push((lo, hi.min(MAX_CODE_POINT)));
        self.sealed = false;
    }

    pub fn add_char(&mut self, c: u32) {
        self.add_range(c, c);
    }

    /// Adds every code point with `property`, the way `AddProperty` does.
    ///
    /// Returns false when the property could not be expanded, which happens on
    /// a Node built without ICU. Every property here is backed by a generated
    /// table, so this is always true, but the signature keeps the caller's
    /// `unsupported_property` handling identical to the original.
    pub fn add_property(&mut self, property: UnicodeProperty) -> bool {
        for part in property.parts() {
            for &(lo, hi) in *part {
                self.add_range(lo, hi);
            }
        }
        true
    }

    /// Sorts and merges the ranges so lookups can binary search.
    pub fn seal(&mut self) {
        if self.ranges.is_empty() {
            self.sealed = true;
            return;
        }
        self.ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.ranges.len());
        merged.push(self.ranges[0]);
        for &(lo, hi) in &self.ranges[1..] {
            let last = merged.last_mut().expect("just pushed");
            // Adjacent ranges merge too, so the result is canonical.
            if lo <= last.1 || lo == last.1.saturating_add(1) {
                last.1 = last.1.max(hi);
            } else {
                merged.push((lo, hi));
            }
        }
        self.ranges = merged;
        self.sealed = true;
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }

    /// Whether `c` is a member.
    ///
    /// The original relies on `seal()` having run; this keeps working on an
    /// unsealed set by falling back to a linear scan, because a missed seal
    /// would otherwise be a silent wrong answer rather than a slow one.
    pub fn contains(&self, c: u32) -> bool {
        if self.sealed {
            let after = self.ranges.partition_point(|&(lo, _)| lo <= c);
            if after == 0 {
                return false;
            }
            return c <= self.ranges[after - 1].1;
        }
        self.ranges.iter().any(|&(lo, hi)| c >= lo && c <= hi)
    }

    /// Adds the case-folded form of every member, for a `u`-flag class.
    ///
    /// This is `UnicodeSet::closeOver(USET_CASE_INSENSITIVE)`: every code point
    /// a member folds to, and every code point that folds to a member, joins the
    /// set. The C++ gets the second direction from ICU; here [`FOLD_INVERSE`]
    /// supplies it.
    pub fn close_over_case_fold(&mut self) {
        self.seal();
        let original = self.ranges.clone();
        self.ranges.clear();
        self.sealed = false;
        for (lo, hi) in original {
            for cp in lo..=hi {
                self.add_char(cp);
                if let Some(folded) = fold_of(cp) {
                    self.add_char(folded);
                }
                if let Some(inverse) = lookup(FOLD_INVERSE, cp) {
                    self.add_char(inverse);
                }
                if cp == MAX_CODE_POINT {
                    break;
                }
            }
        }
        self.seal();
    }

    /// Replaces every member with its case-equivalent representative, for a
    /// non-`u` class.
    pub fn canonicalize_members(&mut self) {
        self.seal();
        let original = self.ranges.clone();
        self.ranges.clear();
        self.sealed = false;
        for (lo, hi) in original {
            if lo > MAX_CODE_UNIT {
                continue;
            }
            let hi = hi.min(MAX_CODE_UNIT);
            for cp in lo..=hi {
                self.add_char(canonicalize(cp, false));
                if cp == MAX_CODE_UNIT {
                    break;
                }
            }
        }
        self.seal();
    }
}

/// The representative a code point compares as.
///
/// `fold` selects full case folding (`u`-flag classes); otherwise the simple
/// uppercase mapping is used and a non-ASCII character whose uppercase form is
/// ASCII is left alone, so `ſ` does not compare equal to `s`.
pub fn canonicalize(cp: u32, fold: bool) -> u32 {
    if cp <= MAX_ASCII {
        return ascii_upper(cp);
    }
    if fold {
        return fold_of(cp).unwrap_or(cp);
    }
    match lookup(TO_UPPER, cp) {
        Some(upper) if upper <= MAX_ASCII => cp,
        Some(upper) => upper,
        None => cp,
    }
}

/// The full case fold of one code point, when it differs from itself.
fn fold_of(cp: u32) -> Option<u32> {
    lookup(FOLD, cp)
}

fn lookup(table: &[(u32, u32)], key: u32) -> Option<u32> {
    table
        .binary_search_by_key(&key, |&(from, _)| from)
        .ok()
        .map(|index| table[index].1)
}

/// Whether `unit` is a line terminator in the JavaScript sense.
///
/// This matters because minimatch's `/,(?!,).*\}/` probe stops at one: `.` does
/// not cross a line terminator, so neither may the scan.
pub fn is_line_terminator(unit: u16) -> bool {
    unit == u16::from(b'\n') || unit == u16::from(b'\r') || unit == 0x2028 || unit == 0x2029
}

/// `String.prototype.toLowerCase()` appended to `out`.
///
/// The output can be longer than the input (U+0130 lowercases to `i` plus a
/// combining dot), which is why this appends to a caller-owned buffer instead
/// of returning a fixed-width mapping.
pub fn append_lowered(text: &str, out: &mut String) {
    for character in text.chars() {
        let code = character as u32;
        match lower_expansion(code) {
            Some(codes) => {
                for mapped in codes {
                    match char::from_u32(*mapped) {
                        Some(character) => out.push(character),
                        None => out.push('\u{FFFD}'),
                    }
                }
            }
            None => out.push(character),
        }
    }
}

/// The code points `code.toLowerCase()` produces, when that is not `code`.
fn lower_expansion(code: u32) -> Option<&'static [u32]> {
    TO_LOWER
        .binary_search_by_key(&code, |&(from, _)| from)
        .ok()
        .map(|index| TO_LOWER[index].1)
}

/// `String.prototype.toLowerCase()` for a whole string.
pub fn lower(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    append_lowered(text, &mut out);
    out
}

/// Whether the two code units are the same under a `nocase` comparison.
///
/// `uflag` selects full folding; without it the comparison is the code-unit
/// one `Canonicalize(c, false)` defines.
pub fn units_equal_folded(a: u32, b: u32, uflag: bool) -> bool {
    if a == b {
        return true;
    }
    canonicalize(a, uflag) == canonicalize(b, uflag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_case_mapping_matches_the_language() {
        assert_eq!(ascii_lower(b'A' as u32), b'a' as u32);
        assert_eq!(ascii_upper(b'z' as u32), b'Z' as u32);
        assert_eq!(ascii_lower(b'0' as u32), b'0' as u32);
    }

    #[test]
    fn canonicalize_prefers_uppercase_above_ascii() {
        // LATIN SMALL LETTER A WITH RING ABOVE folds to its uppercase.
        assert_eq!(canonicalize(0xE5, false), 0xC5);
        // The uppercase and lowercase spellings compare equal.
        assert_eq!(canonicalize(0xE5, false), canonicalize(0xC5, false));
    }

    #[test]
    fn canonicalize_does_not_fold_a_non_ascii_letter_onto_ascii() {
        // LONG S uppercases to 'S', but the original refuses that fold because
        // the uppercase form is ASCII, so `ſ` is not `s` for a plain `nocase`
        // comparison. Node 27 answers false for `matchesGlob('ſ', 's')`.
        assert_eq!(canonicalize(0x17F, false), 0x17F);
        assert_ne!(canonicalize(0x17F, false), canonicalize(b's' as u32, false));
    }

    #[test]
    fn full_folding_still_uppercases_ascii_first() {
        // `Canonicalize` returns `AsciiUpper(cp)` for any ASCII input before it
        // consults the fold table, so with `fold` the long s reaches `s` (0x73)
        // while ASCII `s` reaches `S` (0x53). They are therefore still unequal,
        // which is the original's behaviour rather than an oversight here: the
        // ASCII branch runs first in `Canonicalize`.
        assert_eq!(canonicalize(0x17F, true), b's' as u32);
        assert_eq!(canonicalize(b's' as u32, true), b'S' as u32);
        assert_ne!(canonicalize(0x17F, true), canonicalize(b's' as u32, true));
    }

    #[test]
    fn lowercase_is_string_to_lower_case() {
        assert_eq!(lower("MiXeD.TXT"), "mixed.txt");
        // The Turkish dotted I lowercases to two code points, which is why the
        // buffer is a `String` rather than a code-point mapping.
        assert_eq!(lower("\u{130}"), "i\u{307}");
    }

    #[test]
    fn property_tables_cover_the_expected_characters() {
        let mut decimal = CharSet::new();
        assert!(decimal.add_property(UnicodeProperty::DecimalNumber));
        decimal.seal();
        assert!(decimal.contains(b'7' as u32));
        assert!(!decimal.contains(b'x' as u32));

        let mut letter = CharSet::new();
        assert!(letter.add_property(UnicodeProperty::Letter));
        letter.seal();
        assert!(letter.contains(b'a' as u32));
        assert!(letter.contains('é' as u32));
        assert!(!letter.contains(b'1' as u32));

        let mut space = CharSet::new();
        assert!(space.add_property(UnicodeProperty::SpaceSeparator));
        space.seal();
        assert!(space.contains(b' ' as u32));
        // U+000A is `Cc`, not `Zs`, so `[:space:]` gets it from the class's own
        // extra ranges rather than from this property.
        assert!(!space.contains(b'\n' as u32));
    }

    #[test]
    fn closing_over_a_fold_adds_the_case_variants() {
        let mut set = CharSet::new();
        set.add_char(b'a' as u32);
        set.close_over_case_fold();
        assert!(set.contains(b'A' as u32));
        assert!(set.contains(b'a' as u32));
    }

    #[test]
    fn canonicalizing_members_keeps_only_the_representative() {
        let mut set = CharSet::new();
        set.add_char(b'a' as u32);
        set.add_char(b'A' as u32);
        set.canonicalize_members();
        assert_eq!(set.ranges(), &[(b'A' as u32, b'A' as u32)]);
    }

    #[test]
    fn an_unsealed_set_still_answers_correctly() {
        let mut set = CharSet::new();
        set.add_char(5);
        set.add_char(1);
        assert!(set.contains(5));
        assert!(set.contains(1));
        assert!(!set.contains(3));
    }
}
