//! `GetColumnWidth`: the display width of one code point, from ICU's tables.
//!
//! This is a transcription of `GetColumnWidth` in `src/node_i18n.cc`, and it is
//! a transcription rather than a reimplementation for a measured reason. A
//! table-driven crate can tell you that U+1B44 (BALINESE ADEG ADEG, an `Mc`
//! spacing mark) is a combining character and give it zero columns; Node only
//! zeroes the four categories ICU names explicitly (`Cc`, `Cf`, `Me`, `Mn`) plus
//! emoji modifiers, so Node gives it one. The same distinction decides U+10FFEF
//! and U+3FFEF: unassigned (`Cn`) code points are *not* in Node's zero mask, so
//! they are one column, while a table of "characters known to be printable"
//! reports zero. Both were real failing assertions in
//! `test/parallel/test-icu-stringwidth.js`.
//!
//! Asking ICU the same questions Node asks removes the whole class of
//! disagreement, including for Unicode versions newer than any table copied
//! into this tree.

use crate::ffi;

/// The categories `GetColumnWidth` gives zero columns, as a bit mask over
/// `u_charType`'s values.
///
/// `U_GC_CC_MASK | U_GC_CF_MASK | U_GC_ME_MASK | U_GC_MN_MASK`, computed here
/// from the enum values rather than written as a literal so the mapping stays
/// readable.
fn zero_width_mask() -> u32 {
    (1u32 << ffi::U_CONTROL_CHAR)
        | (1u32 << ffi::U_FORMAT_CHAR)
        | (1u32 << ffi::U_ENCLOSING_MARK)
        | (1u32 << ffi::U_NON_SPACING_MARK)
}

/// The soft hyphen: `Cf`, but the one format character that still occupies a
/// column. Node carves it out by name.
const SOFT_HYPHEN: i32 = 0x00AD;

fn has_binary_property(code_point: i32, property: ffi::UProperty) -> bool {
    // SAFETY: both arguments are plain values; `u_hasBinaryProperty` only reads
    // ICU's immutable property tables.
    unsafe { ffi::u_hasBinaryProperty_78(code_point, property) != 0 }
}

fn east_asian_width(code_point: i32) -> i32 {
    // SAFETY: as above.
    unsafe { ffi::u_getIntPropertyValue_78(code_point, ffi::UCHAR_EAST_ASIAN_WIDTH) }
}

fn general_category(code_point: i32) -> u32 {
    // SAFETY: as above. The return is `int8_t`, widened to the enum's value.
    unsafe { ffi::u_charType_78(code_point) as u32 }
}

/// The columns one code point occupies, exactly as Node computes it.
pub fn column_width(code_point: i32, ambiguous_as_full_width: bool) -> u32 {
    let width = east_asian_width(code_point);

    // `U_EA_FULLWIDTH` and `U_EA_WIDE` are two columns before any other rule is
    // consulted.
    if width == ffi::U_EA_FULLWIDTH || width == ffi::U_EA_WIDE {
        return 2;
    }
    // See http://www.unicode.org/reports/tr11/#Ambiguous: an ambiguous
    // character is one column unless the caller asks for full width.
    if width == ffi::U_EA_AMBIGUOUS && ambiguous_as_full_width {
        return 2;
    }

    // `U_EA_AMBIGUOUS` (when not counted as full width) and `U_EA_NEUTRAL` fall
    // through to here in the C++ switch, so an emoji presentation character is
    // two columns even when Unicode calls it narrow.
    if (width == ffi::U_EA_AMBIGUOUS || width == ffi::U_EA_NEUTRAL)
        && has_binary_property(code_point, ffi::UCHAR_EMOJI_PRESENTATION)
    {
        return 2;
    }

    let in_zero_mask = (zero_width_mask() >> general_category(code_point)) & 1 == 1;
    if code_point != SOFT_HYPHEN
        && (in_zero_mask || has_binary_property(code_point, ffi::UCHAR_EMOJI_MODIFIER))
    {
        return 0;
    }
    1
}

/// Whether `code_point` participates in an emoji sequence for the ZWJ rule.
fn is_emoji_for_sequence(code_point: i32) -> bool {
    has_binary_property(code_point, ffi::UCHAR_EMOJI_PRESENTATION)
        || has_binary_property(code_point, ffi::UCHAR_EMOJI_MODIFIER)
}

const ZWJ: i32 = 0x200D;

/// The display width of a UTF-16 string, as `GetStringWidth` computes it.
///
/// `units` is UTF-16 because that is what Node iterates: a lone surrogate is a
/// single unit and takes one column, and a surrogate pair is one code point.
/// `U16_NEXT`'s rule is inlined below.
pub fn string_width(units: &[u16], ambiguous_as_full_width: bool, expand_emoji: bool) -> u32 {
    let mut width = 0u32;
    let mut previous: i32 = 0;
    let mut index = 0usize;

    while index < units.len() {
        let mut code_point = i32::from(units[index]);
        index += 1;

        if (0xD800..0xDC00).contains(&code_point) && index < units.len() {
            let trail = i32::from(units[index]);
            if (0xDC00..0xE000).contains(&trail) {
                code_point = 0x10000 + ((code_point - 0xD800) << 10) + (trail - 0xDC00);
                index += 1;
            }
        }

        // Inside a ZWJ sequence the individual emoji are not counted: the
        // sequence renders as one glyph. Both the emoji presentation characters
        // and the skin-tone modifiers after a ZWJ drop out. `expand_emoji`
        // skips this and counts every code point, which is what a caller does
        // when its terminal cannot render the joined form.
        if !expand_emoji && index > 0 && previous == ZWJ && is_emoji_for_sequence(code_point) {
            previous = code_point;
            continue;
        }

        width += column_width(code_point, ambiguous_as_full_width);
        previous = code_point;
    }
    width
}

#[cfg(test)]
mod tests {
    use super::*;

    /// UTF-16 units, which is what `GetStringWidth` iterates.
    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn ascii_is_one_column_per_character() {
        assert_eq!(string_width(&units("hello"), false, true), 5);
        assert_eq!(string_width(&[], false, true), 0);
    }

    #[test]
    fn cjk_is_two_columns() {
        assert_eq!(string_width(&units("中"), false, true), 2);
        assert_eq!(string_width(&units("日本"), false, true), 4);
    }

    #[test]
    fn nonspacing_marks_are_zero_and_spacing_marks_are_one() {
        // Mn: COMBINING ACUTE ACCENT.
        assert_eq!(string_width(&units("\u{301}"), false, true), 0);
        // Me: COMBINING ENCLOSING CIRCLE.
        assert_eq!(string_width(&units("\u{20dd}"), false, true), 0);
        // Mc: BALINESE ADEG ADEG. A table-driven implementation calls this
        // combining and reports zero; Node reports one, and this is the
        // assertion that caught it.
        assert_eq!(string_width(&units("\u{1b44}"), false, true), 1);
    }

    #[test]
    fn controls_and_format_characters_are_zero_but_the_soft_hyphen_is_not() {
        assert_eq!(string_width(&units("\u{0}"), false, true), 0);
        assert_eq!(string_width(&units("\u{7f}"), false, true), 0);
        assert_eq!(string_width(&units("\u{200e}"), false, true), 0);
        assert_eq!(string_width(&units("\u{ad}"), false, true), 1);
    }

    #[test]
    fn unassigned_code_points_are_one_column() {
        // Cn, and not in a CJK range. A "known printable" table would report
        // zero here, which is the defect this replaced.
        assert_eq!(string_width(&units("\u{10ffef}"), false, true), 1);
        // Cn inside a CJK range is `Wide`, so ICU — and therefore Node — gives
        // it two columns. `test-icu-stringwidth.js` asserts one for this code
        // point, and that assertion passes because `String.fromCharCode(0x3FFEF)`
        // truncates to U+FFEF, which is one column. Checked against the pinned
        // oracle through `String.fromCodePoint` to keep the two apart.
        assert_eq!(string_width(&units("\u{3ffef}"), false, true), 2);
        assert_eq!(string_width(&units("\u{ffef}"), false, true), 1);
    }

    #[test]
    fn lone_surrogates_are_one_column_each() {
        // `Cs`, reached only from JavaScript: Rust strings cannot hold these, so
        // the units are built by hand.
        assert_eq!(string_width(&[0xd83d], false, true), 1);
        assert_eq!(string_width(&[0xdc78], false, true), 1);
        // A surrogate pair is one code point, two columns.
        assert_eq!(string_width(&[0xd83d, 0xdc78], false, true), 2);
    }

    #[test]
    fn emoji_presentation_overrides_a_narrow_east_asian_width() {
        // U+2764 has East Asian Width Neutral but is an emoji presentation
        // character when followed by its variation selector's zero-width Cf.
        assert_eq!(string_width(&units("\u{2764}"), false, true), 1);
        assert_eq!(string_width(&units("\u{2764}\u{fe0f}"), false, true), 1);
        assert_eq!(string_width(&units("\u{1f435}"), false, true), 2);
    }

    #[test]
    fn a_zwj_sequence_collapses_only_when_the_caller_allows_it() {
        let family = units("\u{1f469}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f467}");
        // Collapsed: the first emoji counts, every component after a ZWJ is
        // skipped, and each ZWJ itself is `Cf` (zero). Measured on the pinned
        // oracle, which reports 2 for the collapsed form and 8 when expanded.
        assert_eq!(string_width(&family, false, false), 2);
        assert_eq!(string_width(&family, false, true), 8);
    }

    #[test]
    fn ambiguous_characters_widen_only_when_asked() {
        assert_eq!(string_width(&units("\u{1d4}"), false, true), 1);
        assert_eq!(string_width(&units("\u{a1}"), false, true), 1);
        assert_eq!(string_width(&units("\u{a1}"), true, true), 2);
    }
}
