//! `internalBinding('icu')` for rustnode.
//!
//! `lib/internal/util/inspect.js` calls `getStringWidth` on every non-ASCII
//! code point it prints, and `lib/buffer.js` calls `transcode` for
//! `Buffer.from(source, from, to)`. Node guards both behind
//! `internalBinding('config').hasIntl`, which is true here because V8 is linked
//! with full ICU (`Intl.Segmenter` exists).
//!
//! # Why `getStringWidth` is the important one
//!
//! `util.inspect` uses it to decide column layout, and `internal/util/inspect`
//! is loaded by `internal/errors`, which is loaded by the realm bootstrap. So a
//! missing `icu` namespace fails `require('events')`, `require('fs')` and
//! `require('util')` — not with an ICU error but with
//! `internalBinding('icu'): the namespace has no Rust implementation yet`
//! thrown from deep inside the inspect code. That is why this namespace matters
//! out of proportion to its six members.
//!
//! The width calculation follows `GetColumnWidth` in `src/node_i18n.cc`:
//! `UCHAR_EAST_ASIAN_WIDTH` decides full width, then emoji presentation
//! overrides to 2, then the control/format/mark categories and emoji modifiers
//! become 0. `unicode-width` supplies the same Unicode tables.
//!
//! # `transcode`
//!
//! The four encodings `lib/buffer.js` transcodes between are utf8, utf16le,
//! latin1 and ascii. All four are implemented here directly, so
//! `Buffer.from(x, 'utf8', 'latin1')` works. What is *not* implemented is the
//! arbitrary-converter surface (`getConverter`, `decode`, `hasConverter`),
//! which needs an ICU converter; those are declared deferred.

use std::cell::RefCell;
use std::collections::BTreeMap;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;
use unicode_width::UnicodeWidthChar;

/// Members exposed on the namespace object, matching `contracts/icu.json`.
pub const MEMBERS: &[&str] = &[
    "decode",
    "getConverter",
    "getStringWidth",
    "hasConverter",
    "icuErrName",
    "transcode",
];

/// Members this build does not install yet.
pub const DEFERRED: &[(&str, &str)] = &[
    (
        "getConverter",
        "needs an ICU converter object; the four encodings buffer.js uses are handled by transcode",
    ),
    (
        "decode",
        "part of the converter surface, same scope as getConverter",
    ),
    (
        "hasConverter",
        "part of the converter surface, same scope as getConverter",
    ),
];

/// The four encodings `lib/buffer.js` transcodes between.
const SUPPORTED: &[&str] = &["utf8", "utf16le", "latin1", "ascii"];

/// ICC error codes, from `icu::UErrorCode`. `transcode` returns one of these
/// when it cannot honour a request.
pub const U_ZERO_ERROR: i32 = 0;
pub const U_INVALID_CHAR_FOUND: i32 = 10;

thread_local! {
    /// Converters created by `getConverter`. The member is deferred, so this is
    /// only ever populated if that changes.
    static CONVERTERS: RefCell<BTreeMap<&'static str, ()>> = const { RefCell::new(BTreeMap::new()) };
}

pub struct Icu;

impl BindingModule for Icu {
    fn namespace(&self) -> &'static str {
        "icu"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 3] = [
            (
                "getStringWidth",
                function(scope, "getStringWidth", get_string_width)?,
            ),
            ("transcode", function(scope, "transcode", transcode)?),
            ("icuErrName", function(scope, "icuErrName", icu_err_name)?),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Icu);
}

fn get_string_width(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(text) = args.get(0).to_string(scope) else {
        rv.set(v8::Integer::new(scope, 0).into());
        return;
    };
    let text = text.to_rust_string_lossy(scope);
    // `getStringWidth(str, ambiguousAsFullWidth, expandEmojiSequence)`.
    let ambiguous_as_full_width = args.get(1).boolean_value(scope);
    let expand_emoji = !args.get(2).is_boolean() || args.get(2).boolean_value(scope);

    let width = string_width(&text, ambiguous_as_full_width, expand_emoji);
    rv.set(v8::Integer::new(scope, width as i32).into());
}

/// The display width of `text` in terminal columns.
///
/// Follows `GetColumnWidth` in `src/node_i18n.cc`, including the two rules that
/// are easy to miss: an emoji presentation character is two columns even when
/// Unicode calls it ambiguous or narrow, and a control, format or mark character
/// is zero columns. U+00AD SOFT HYPHEN is the documented exception, being a
/// format character that still occupies a column.
fn string_width(text: &str, ambiguous_as_full_width: bool, expand_emoji: bool) -> usize {
    let mut width = 0;
    let mut previous = None;
    for character in text.chars() {
        // Inside a ZWJ sequence, the individual emoji are not counted
        // separately: the sequence renders as one glyph. `expand_emoji` skips
        // this check and counts each code point.
        if !expand_emoji && previous == Some('\u{200d}') && is_emoji(character) {
            previous = Some(character);
            continue;
        }
        width += column_width(character, ambiguous_as_full_width);
        previous = Some(character);
    }
    width
}

fn column_width(character: char, ambiguous_as_full_width: bool) -> usize {
    // `UnicodeWidthChar` resolves East-Asian Width, with ambiguous characters
    // counted as one column, which is Node's default.
    let narrow = character.width().unwrap_or(0);
    if narrow == 0 {
        // A zero width from the table means a control, format or combining
        // character. Node still gives the soft hyphen one column.
        return usize::from(character == '\u{00ad}');
    }
    if is_emoji(character) {
        return 2;
    }
    // A wide or fullwidth character is already two columns in the table. An
    // ambiguous one is one column unless the caller asks otherwise.
    if ambiguous_as_full_width && is_ambiguous_width(character) {
        return 2;
    }
    narrow
}

/// Whether `character` renders as an emoji, which Node treats as two columns.
///
/// Node asks ICU for `UCHAR_EMOJI_PRESENTATION`. Without an ICU table this uses
/// the ranges that property covers; the cost of being wrong is a misaligned
/// column in `util.inspect`, not a wrong value from user code.
fn is_emoji(character: char) -> bool {
    matches!(character as u32,
        0x1F300..=0x1F5FF   // Misc Symbols and Pictographs
        | 0x1F600..=0x1F64F // Emoticons
        | 0x1F680..=0x1F6FF // Transport and Map
        | 0x1F700..=0x1F77F
        | 0x1F780..=0x1F7FF
        | 0x1F800..=0x1F8FF
        | 0x1F900..=0x1F9FF // Supplemental Symbols and Pictographs
        | 0x1FA00..=0x1FA6F
        | 0x1FA70..=0x1FAFF
        | 0x2600..=0x27BF   // Misc Symbols and Dingbats
        | 0x1F1E6..=0x1F1FF // Regional indicators
    )
}

/// Whether `character` has East-Asian Width "Ambiguous".
///
/// Node only consults this when `ambiguousAsFullWidth` is set, which
/// `util.inspect` never does, so a conservative approximation is enough: the
/// characters that are ambiguous and commonly appear in box drawing and
/// typographic punctuation.
fn is_ambiguous_width(character: char) -> bool {
    matches!(character as u32,
        0x00A1 | 0x00A4 | 0x00A7 | 0x00A8 | 0x00AA | 0x00AD..=0x00AE
        | 0x00B0..=0x00B4 | 0x00B6..=0x00BA | 0x00BC..=0x00BF
        | 0x2010 | 0x2013..=0x2016 | 0x2018..=0x2019 | 0x201C..=0x201D
        | 0x2020..=0x2022 | 0x2024..=0x2027 | 0x2030 | 0x2032..=0x2033
        | 0x2035 | 0x203B | 0x203E | 0x2074 | 0x207F | 0x2081..=0x2084
        | 0x20AC | 0x2103 | 0x2109 | 0x2113 | 0x2116 | 0x2121..=0x2122
        | 0x2126 | 0x212B | 0x2153..=0x2154 | 0x215B..=0x215E
        | 0x2160..=0x216B | 0x2170..=0x2179 | 0x2189
        | 0x2190..=0x2199 | 0x21B8..=0x21B9 | 0x21D2 | 0x21D4
        | 0x21E7 | 0x2200 | 0x2202..=0x2203 | 0x2207..=0x2208
        | 0x220B | 0x220F | 0x2211 | 0x2215 | 0x221A | 0x221D..=0x2220
        | 0x2223 | 0x2225 | 0x2227..=0x222C | 0x222E | 0x2234..=0x2237
        | 0x223C..=0x223D | 0x2248 | 0x224C | 0x2252 | 0x2260..=0x2261
        | 0x2264..=0x2267 | 0x226A..=0x226B | 0x226E..=0x226F
        | 0x2282..=0x2283 | 0x2286..=0x2287 | 0x2295 | 0x2299 | 0x22A5
        | 0x22BF | 0x2312 | 0x2460..=0x24E9 | 0x24EB..=0x254B
        | 0x2550..=0x2573 | 0x2580..=0x258F | 0x2592..=0x2595
        | 0x25A0..=0x25A1 | 0x25A3..=0x25A9 | 0x25B2..=0x25B3
        | 0x25B6..=0x25B7 | 0x25BC..=0x25BD | 0x25C0..=0x25C1
        | 0x25C6..=0x25C8 | 0x25CB | 0x25CE..=0x25D1 | 0x25E2..=0x25E5
        | 0x25EF | 0x2605..=0x2606 | 0x2609 | 0x260E..=0x260F
        | 0x261C | 0x261E | 0x2640 | 0x2642 | 0x2660..=0x2661
        | 0x2663..=0x2665 | 0x2667..=0x266A | 0x266C..=0x266D | 0x266F
        | 0x269E..=0x269F | 0x26BE..=0x26BF | 0x26C4..=0x26CD
        | 0x26CF..=0x26E1 | 0x26E3 | 0x26E8..=0x26FF | 0x273D
        | 0x2757 | 0x2776..=0x277F | 0x2B55..=0x2B59
        | 0xFFFD
    )
}

fn transcode(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `transcode(source, fromEncoding, toEncoding)` returns either a Buffer or
    // a numeric `UErrorCode`. `lib/buffer.js` checks `typeof result !== 'number'`
    // and builds the error from `icuErrName` when it got one.
    let Ok(source) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(0)) else {
        rv.set(v8::Integer::new(scope, U_INVALID_CHAR_FOUND).into());
        return;
    };
    let from = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope).to_ascii_lowercase())
        .unwrap_or_default();
    let to = args
        .get(2)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope).to_ascii_lowercase())
        .unwrap_or_default();

    if !SUPPORTED.contains(&from.as_str()) || !SUPPORTED.contains(&to.as_str()) {
        rv.set(v8::Integer::new(scope, U_INVALID_CHAR_FOUND).into());
        return;
    }

    let length = source.byte_length();
    let mut input = vec![0u8; length];
    if source.copy_contents(&mut input) != length {
        rv.set(v8::Integer::new(scope, U_INVALID_CHAR_FOUND).into());
        return;
    }

    let decoded = match decode(&input, &from) {
        Some(text) => text,
        None => {
            rv.set(v8::Integer::new(scope, U_INVALID_CHAR_FOUND).into());
            return;
        }
    };
    let output = encode(&decoded, &to);

    // The result is a Buffer, which `lib/buffer.js` receives through
    // `internalBinding('buffer')`'s own constructor. Returning a Uint8Array
    // here is what the JS side accepts, because it only reads `.length` and
    // `.buffer` off the value before wrapping it.
    let Ok(array) = v8::Local::<v8::Uint8Array>::try_from(make_uint8_array(scope, &output)) else {
        rv.set(v8::Integer::new(scope, U_INVALID_CHAR_FOUND).into());
        return;
    };
    rv.set(array.into());
}

fn make_uint8_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> v8::Local<'s, v8::Value> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    match v8::Uint8Array::new(scope, buffer, 0, bytes.len()) {
        Some(array) => array.into(),
        None => v8::undefined(scope).into(),
    }
}

fn decode(bytes: &[u8], encoding: &str) -> Option<String> {
    match encoding {
        "utf8" => String::from_utf8(bytes.to_vec()).ok(),
        "utf16le" => {
            // An odd trailing byte cannot be part of a code unit; ICU reports
            // the error rather than silently dropping it.
            if !bytes.len().is_multiple_of(2) {
                return None;
            }
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16(&units).ok()
        }
        "latin1" => Some(bytes.iter().map(|byte| *byte as char).collect()),
        "ascii" => Some(
            bytes
                .iter()
                .map(|byte| {
                    if *byte < 0x80 {
                        *byte as char
                    } else {
                        '\u{fffd}'
                    }
                })
                .collect(),
        ),
        _ => None,
    }
}

fn encode(text: &str, encoding: &str) -> Vec<u8> {
    match encoding {
        "utf8" => text.as_bytes().to_vec(),
        "utf16le" => text
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect(),
        "latin1" => text
            .chars()
            .map(|character| {
                if (character as u32) <= 0xff {
                    character as u32 as u8
                } else {
                    // Latin-1 cannot represent this; ICU substitutes.
                    0x1a
                }
            })
            .collect(),
        "ascii" => text
            .chars()
            .map(|character| {
                if (character as u32) < 0x80 {
                    character as u32 as u8
                } else {
                    0x1a
                }
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn icu_err_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let code = args.get(0).int32_value(scope).unwrap_or(U_ZERO_ERROR);
    let name = match code {
        U_ZERO_ERROR => "U_ZERO_ERROR",
        U_INVALID_CHAR_FOUND => "U_INVALID_CHAR_FOUND",
        _ => "U_UNKNOWN_ERROR",
    };
    if let Some(text) = v8::String::new(scope, name) {
        rv.set(text.into());
    }
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_text_is_one_column_per_character() {
        assert_eq!(string_width("hello", false, true), 5);
        assert_eq!(string_width("", false, true), 0);
    }

    #[test]
    fn cjk_characters_are_two_columns() {
        // East Asian Wide: the table must say two, not one.
        assert_eq!(string_width("中", false, true), 2);
        assert_eq!(string_width("日本", false, true), 4);
    }

    #[test]
    fn combining_marks_add_no_width() {
        // "e" + COMBINING ACUTE ACCENT renders as one column.
        assert_eq!(string_width("e\u{301}", false, true), 1);
    }

    #[test]
    fn control_characters_are_zero_columns() {
        assert_eq!(string_width("\u{0}", false, true), 0);
        assert_eq!(string_width("\u{7f}", false, true), 0);
    }

    #[test]
    fn the_soft_hyphen_is_the_documented_exception() {
        // It is a format character but still occupies a column.
        assert_eq!(string_width("\u{ad}", false, true), 1);
    }

    #[test]
    fn an_emoji_sequence_counts_as_one_glyph_unless_expanded() {
        // A family emoji joined by ZWJ: collapsed by default, counted per code
        // point when the caller asks for expansion.
        let family = "\u{1F468}\u{200d}\u{1F469}\u{200d}\u{1F467}";
        let collapsed = string_width(family, false, false);
        let expanded = string_width(family, false, true);
        assert!(
            collapsed < expanded,
            "collapsing a ZWJ sequence must count fewer columns: {collapsed} vs {expanded}"
        );
        assert_eq!(expanded, 6, "three emoji, two columns each");
    }

    #[test]
    fn transcoding_round_trips_between_the_supported_encodings() {
        let text = "héllo";
        for encoding in SUPPORTED {
            let bytes = encode(text, encoding);
            let decoded = decode(&bytes, encoding).expect("decodes");
            if *encoding == "ascii" {
                // ASCII cannot carry é; the substitution is documented.
                assert!(decoded.starts_with("h"));
                continue;
            }
            assert_eq!(decoded, text, "round trip through {encoding}");
        }
    }

    #[test]
    fn invalid_utf8_is_an_error_rather_than_a_substitution() {
        // ICU reports U_INVALID_CHAR_FOUND; silently replacing the bytes would
        // hide the caller's bug.
        assert!(decode(&[0xff, 0xfe], "utf8").is_none());
    }

    #[test]
    fn an_odd_length_utf16_input_is_an_error() {
        assert!(decode(&[0x68], "utf16le").is_none());
        assert!(decode(&[0x68, 0x00], "utf16le").is_some());
    }
}
