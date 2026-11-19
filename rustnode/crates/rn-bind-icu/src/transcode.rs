//! `transcode`: `Buffer.transcode(source, fromEncoding, toEncoding)`.
//!
//! This is `Transcode`'s dispatch from `src/node_i18n.cc`, written out rather
//! than routed through ICU, and the reason is measured rather than stylistic.
//!
//! # Why not call ICU for this
//!
//! Node's `Transcode` opens ICU converters named `us-ascii`, `iso8859-1`,
//! `utf16le` and `utf-8`. Node links **full** ICU, where `us-ascii` is genuine
//! US-ASCII and `iso8859-1` is genuine ISO-8859-1. The ICU inside
//! `librusty_v8.a` is a build-data subset — `ucnv_countAvailable()` is 37 names —
//! and there `ucnv_open("us-ascii")` and `ucnv_open("iso8859-1")` both resolve to
//! `windows-1252-html`, which is neither. Routing through it produced:
//!
//! | input | Node | via the subset ICU |
//! |---|---|---|
//! | `latin1→ascii [0xE9]` | `3F` | `E9` |
//! | `latin1→utf8 [0x80]` | `C2 80` | `E2 82 AC` |
//! | `utf8→latin1 [C2 80]` | `80` | `3F` |
//!
//! So the four supported encodings are implemented directly. They are a closed
//! list of four, each is a total function, and every rule below was recorded from
//! the pinned oracle rather than inferred.
//!
//! # The three strict paths
//!
//! `Transcode` is only the fallback. Three pairs take a path built on `simdutf`
//! that *fails* on malformed input instead of substituting, and the difference is
//! observable: `transcode(Buffer.from([0xFF]), 'utf8', 'latin1')` returns `3F`
//! while `transcode(Buffer.from([0xFF]), 'utf8', 'ucs2')` throws
//! `U_INVALID_CHAR_FOUND`. Those are the `ucs2` targets and `ucs2 → utf8`.
//!
//! # Substitution
//!
//! Every generic conversion installs `?` as the target's substitution bytes
//! (`Converter::set_subst_chars` with `min_char_size` copies of `'?'`). The
//! previous implementation wrote `0x1A`, which is the DOS `SUB` convention, not
//! ICU's. That one byte is what `test/parallel/test-icu-transcode.js` checks.

use std::ffi::CString;

use crate::ffi;

/// `enum encoding`, from `src/node_buffer.h`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding {
    Ascii,
    Latin1,
    Ucs2,
    Utf8,
    /// Anything `ParseEncoding` resolves to `BUFFER`, i.e. not one of the four
    /// this function supports. `SupportedEncoding` rejects it.
    Unsupported,
}

/// `ParseEncoding` from `src/api/encoding.cc`, including the case-insensitive
/// aliases. Its default is `BUFFER`, which is `Unsupported` here.
pub fn parse_encoding(text: &str) -> Encoding {
    match text.to_ascii_lowercase().as_str() {
        "utf8" | "utf-8" => Encoding::Utf8,
        "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => Encoding::Ucs2,
        // `binary` is a deprecated alias of `latin1`.
        "latin1" | "binary" => Encoding::Latin1,
        "ascii" => Encoding::Ascii,
        _ => Encoding::Unsupported,
    }
}

/// The outcome of a transcode: bytes, or the `UErrorCode` the JavaScript turns
/// into an error.
pub type TranscodeResult = Result<Vec<u8>, ffi::UErrorCode>;

/// What a single-byte target writes for a character it cannot represent.
const SUBSTITUTE: u8 = b'?';
/// U+FFFD, the WHATWG replacement character.
const REPLACEMENT: char = '\u{fffd}';

/// `transcode(source, fromEncoding, toEncoding)`, with both labels already
/// normalized the way `lib/buffer.js` normalizes them.
pub fn transcode(source: &[u8], from: &str, to: &str) -> TranscodeResult {
    let from_encoding = parse_encoding(from);
    let to_encoding = parse_encoding(to);
    if from_encoding == Encoding::Unsupported || to_encoding == Encoding::Unsupported {
        // `SupportedEncoding` rejects both ends before any converter is opened,
        // which is why an unknown label is `U_ILLEGAL_ARGUMENT_ERROR` rather than
        // a conversion error.
        return Err(ffi::U_ILLEGAL_ARGUMENT_ERROR);
    }

    match (from_encoding, to_encoding) {
        // `TranscodeLatin1ToUcs2`: `simdutf::convert_latin1_to_utf16le`, a
        // per-byte widening with no table and no ASCII check. `0xE9` is
        // `U+00E9` even though the source label was `ascii`.
        (Encoding::Ascii | Encoding::Latin1, Encoding::Ucs2) => Ok(widen_latin1_to_utf16le(source)),

        // `TranscodeUcs2FromUtf8`: `simdutf::convert_utf8_to_utf16le`, strict.
        (Encoding::Utf8, Encoding::Ucs2) => strict_utf8_to_utf16le(source),

        // `TranscodeUtf8FromUcs2`: `simdutf::convert_utf16le_to_utf8`, strict.
        (Encoding::Ucs2, Encoding::Utf8) => strict_utf16le_to_utf8(source),

        // `TranscodeFromUcs2` for a single-byte target: `ucnv_fromUChars` over
        // whole units, so an odd trailing byte is dropped rather than becoming
        // U+FFFD, and an unmatched surrogate becomes `?`.
        (Encoding::Ucs2, Encoding::Latin1 | Encoding::Ascii) => {
            let target = single_byte_target(to_encoding);
            Ok(decode_utf16_units(source, OddByte::Drop)
                .into_iter()
                .map(target)
                .collect())
        }

        // Everything else is the generic `ucnv_convertEx` path: decode with
        // WHATWG replacement for malformed input, then encode with `?` for
        // anything the target cannot represent.
        (from_encoding, to_encoding) => Ok(recode(source, from_encoding, to_encoding)),
    }
}

/// How a source with an odd number of UTF-16 bytes treats the leftover byte.
#[derive(Clone, Copy)]
enum OddByte {
    /// `TranscodeFromUcs2` never copies it, so it contributes nothing.
    Drop,
    /// The generic converter sees a truncated sequence and emits U+FFFD.
    Replace,
}

/// The whole UTF-16 code units of a little-endian byte slice, as code points.
///
/// A valid surrogate pair becomes one code point; an unmatched surrogate becomes
/// U+FFFD, which is what ICU's converter emits and what both a `ucs2` target
/// (`FD FF`) and a single-byte target (`?`) then render.
fn decode_utf16_units(source: &[u8], odd: OddByte) -> Vec<char> {
    let units: Vec<u16> = source
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let mut out: Vec<char> = Vec::with_capacity(units.len() + 1);
    let mut index = 0usize;
    while index < units.len() {
        let unit = units[index];
        if (0xD800..0xDC00).contains(&unit) {
            // A lead surrogate is only valid with a trail immediately after it.
            match units.get(index + 1) {
                Some(&trail) if (0xDC00..0xE000).contains(&trail) => {
                    let code_point =
                        0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(trail) - 0xDC00);
                    out.push(char::from_u32(code_point).unwrap_or(REPLACEMENT));
                    index += 2;
                    continue;
                }
                _ => {
                    out.push(REPLACEMENT);
                    index += 1;
                    continue;
                }
            }
        }
        if (0xDC00..0xE000).contains(&unit) {
            // A trail surrogate with nothing before it.
            out.push(REPLACEMENT);
            index += 1;
            continue;
        }
        out.push(char::from_u32(u32::from(unit)).unwrap_or(REPLACEMENT));
        index += 1;
    }

    if matches!(odd, OddByte::Replace) && source.len() % 2 == 1 {
        out.push(REPLACEMENT);
    }
    out
}

/// The generic path: decode `source` in `from` with WHATWG replacement, then
/// encode in `to` with `?` substitution.
fn recode(source: &[u8], from: Encoding, to: Encoding) -> Vec<u8> {
    let characters: Vec<char> = match from {
        // `latin1` is the identity per byte; it never fails.
        Encoding::Latin1 => source.iter().map(|byte| char::from(*byte)).collect(),
        // `ascii` cannot represent 0x80..0xFF, so ICU reports each as unmappable
        // and the decode-side replacement is U+FFFD.
        Encoding::Ascii => source
            .iter()
            .map(|byte| {
                if *byte < 0x80 {
                    char::from(*byte)
                } else {
                    REPLACEMENT
                }
            })
            .collect(),
        // UTF-8 with one U+FFFD per maximal ill-formed subpart, which is the rule
        // `Utf16LengthFromInvalidUtf8` and ICU's converter share. A truncated tail
        // is one replacement for the whole tail.
        Encoding::Utf8 => String::from_utf8_lossy(source).chars().collect(),
        // `ucs2` reaches here only for a `ucs2` target.
        Encoding::Ucs2 => decode_utf16_units(source, OddByte::Replace),
        Encoding::Unsupported => return Vec::new(),
    };

    match to {
        Encoding::Utf8 => {
            let mut out = String::with_capacity(characters.len());
            out.extend(characters);
            out.into_bytes()
        }
        Encoding::Ucs2 => characters
            .iter()
            .flat_map(|character| {
                let mut units = [0u16; 2];
                character.encode_utf16(&mut units).to_vec()
            })
            .flat_map(u16::to_le_bytes)
            .collect(),
        Encoding::Latin1 | Encoding::Ascii => {
            let target = single_byte_target(to);
            characters.into_iter().map(target).collect()
        }
        Encoding::Unsupported => Vec::new(),
    }
}

/// The encoder for a single-byte target: identity inside the repertoire, `?`
/// outside it.
///
/// `latin1` is `iso8859-1`, so the repertoire is U+0000..U+00FF with no
/// exceptions — `€` (U+20AC) is *not* representable, unlike `windows-1252`.
/// `ascii` is `us-ascii`, so the repertoire is U+0000..U+007F.
fn single_byte_target(encoding: Encoding) -> fn(char) -> u8 {
    match encoding {
        Encoding::Ascii => |character: char| {
            if (character as u32) < 0x80 {
                character as u32 as u8
            } else {
                SUBSTITUTE
            }
        },
        _ => |character: char| {
            if (character as u32) <= 0xFF {
                character as u32 as u8
            } else {
                SUBSTITUTE
            }
        },
    }
}

fn widen_latin1_to_utf16le(source: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(source.len() * 2);
    for byte in source {
        out.extend_from_slice(&u16::from(*byte).to_le_bytes());
    }
    out
}

/// `simdutf::convert_utf8_to_utf16le`: strict, with no replacement.
fn strict_utf8_to_utf16le(source: &[u8]) -> TranscodeResult {
    let text = std::str::from_utf8(source).map_err(|_| ffi::U_INVALID_CHAR_FOUND)?;
    Ok(text.encode_utf16().flat_map(u16::to_le_bytes).collect())
}

/// `simdutf::convert_utf16le_to_utf8`: strict, so an unpaired surrogate is a
/// `U_INVALID_CHAR_FOUND` rather than a replacement character.
fn strict_utf16le_to_utf8(source: &[u8]) -> TranscodeResult {
    // `lib/buffer.js` returns an empty `FastBuffer` for an empty source before
    // calling the binding, so an empty source is never an error; the check here
    // keeps that behaviour if the binding is reached directly.
    if source.is_empty() {
        return Ok(Vec::new());
    }
    let units: Vec<u16> = source
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    // `TranscodeUtf8FromUcs2` treats a zero-length result as the error, and it
    // can only be zero for a non-empty source when the whole source is one
    // trailing odd byte — which is exactly the truncated code unit that must not
    // pass silently.
    if units.is_empty() {
        return Err(ffi::U_INVALID_CHAR_FOUND);
    }
    let mut text = String::with_capacity(units.len());
    for unit in char::decode_utf16(units.iter().copied()) {
        match unit {
            Ok(character) => text.push(character),
            Err(_) => return Err(ffi::U_INVALID_CHAR_FOUND),
        }
    }
    Ok(text.into_bytes())
}

/// The name ICU gives an error code, as `icuErrName` reports it.
///
/// This has to come from ICU rather than a table: `lib/buffer.js` puts the name
/// in the thrown error's message, and ICU's set of codes is larger than any list
/// worth maintaining here.
pub fn error_name(code: ffi::UErrorCode) -> String {
    // SAFETY: `u_errorName` returns a pointer to a static, NUL-terminated string
    // for every code, including unassigned ones.
    let pointer = unsafe { ffi::u_errorName_78(code) };
    if pointer.is_null() {
        return String::from("U_UNKNOWN_ERROR");
    }
    // SAFETY: as above; the string is static and NUL-terminated.
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

/// Whether ICU resolves `label`.
///
/// # A measured difference from Node, and its scope
///
/// Node links full ICU; `librusty_v8.a` carries a 37-name subset. Labels outside
/// that subset — `utf-32`, `scsu`, `bocu-1`, `cesu-8`, `utf-7`,
/// `iso-2022-jp-2`, the IBM CCSIDs — report `false` here and `true` on Node.
///
/// Every label the WHATWG list in `lib/internal/encoding.js` can produce resolves
/// identically on both, which is the population that matters: `lib/**` never
/// calls `hasConverter` (the only caller would be user code reaching through
/// `internalBinding`), and `TextDecoder` resolves through its own `encodings` map
/// and then `getConverter`. Verified by constructing `new TextDecoder(label)` for
/// all 40 WHATWG targets on both runtimes: identical, including the two that
/// throw `ERR_ENCODING_NOT_SUPPORTED`.
pub fn has_converter(label: &str) -> bool {
    let Ok(name) = CString::new(label) else {
        return false;
    };
    let mut status: ffi::UErrorCode = ffi::U_ZERO_ERROR;
    // SAFETY: `name` is a valid NUL-terminated label.
    let converter = unsafe { ffi::ucnv_open_78(name.as_ptr(), &mut status) };
    if converter.is_null() {
        return false;
    }
    // SAFETY: the converter is owned here.
    unsafe { ffi::ucnv_close_78(converter) };
    ffi::u_success(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// `transcode` from a `&str`, for the cases whose source is readable.
    fn from_utf8(text: &str, to: &str) -> String {
        hex(&transcode(text.as_bytes(), "utf8", to).expect("converts"))
    }

    #[test]
    fn latin1_and_ascii_substitute_a_question_mark() {
        // The defect this replaced: `0x1A` where ICU writes `0x3F`.
        assert_eq!(from_utf8("těst ☕", "latin1"), "743f7374203f");
        assert_eq!(from_utf8("těst ☕", "ascii"), "743f7374203f");
    }

    #[test]
    fn utf8_to_ucs2_keeps_the_code_units() {
        assert_eq!(from_utf8("těst ☕", "ucs2"), "74001b017300740020001526");
    }

    #[test]
    fn latin1_is_true_iso8859_1_not_windows_1252() {
        // U+0080 is representable in ISO-8859-1 and is *not* the euro sign, so
        // `€` (U+20AC) must substitute while U+0080 round-trips.
        assert_eq!(from_utf8("\u{80}", "latin1"), "80");
        assert_eq!(from_utf8("\u{9f}", "latin1"), "9f");
        assert_eq!(from_utf8("\u{20ac}", "latin1"), "3f");
        assert_eq!(
            hex(&transcode(&[0x80], "latin1", "utf8").expect("converts")),
            "c280"
        );
    }

    #[test]
    fn ascii_is_true_us_ascii() {
        assert_eq!(from_utf8("\u{7f}", "ascii"), "7f");
        assert_eq!(from_utf8("\u{80}", "ascii"), "3f");
        // A high source byte is unmappable, so the decode side is U+FFFD and the
        // encode side substitutes.
        assert_eq!(
            hex(&transcode(&[0xe9], "ascii", "latin1").expect("converts")),
            "3f"
        );
        assert_eq!(
            hex(&transcode(&[0xe9], "latin1", "ascii").expect("converts")),
            "3f"
        );
        assert_eq!(
            hex(&transcode(&[0x41, 0xe9], "ascii", "ascii").expect("converts")),
            "413f"
        );
    }

    #[test]
    fn the_latin1_fast_path_widens_without_an_ascii_check() {
        // `TranscodeLatin1ToUcs2` is a per-byte widening, so an `ascii` label
        // does not mask the high bit.
        assert_eq!(
            hex(&transcode(&[0xe9], "ascii", "ucs2").expect("converts")),
            "e900"
        );
        assert_eq!(
            hex(&transcode(&[0xe9], "latin1", "ucs2").expect("converts")),
            "e900"
        );
        assert_eq!(
            hex(&transcode(&[0x80], "latin1", "ucs2").expect("converts")),
            "8000"
        );
    }

    #[test]
    fn an_unknown_label_is_an_illegal_argument() {
        assert_eq!(
            transcode(b"a", "b", "utf8"),
            Err(ffi::U_ILLEGAL_ARGUMENT_ERROR)
        );
        assert_eq!(
            transcode(b"a", "uf8", "b"),
            Err(ffi::U_ILLEGAL_ARGUMENT_ERROR)
        );
        // `base64` parses, but `SupportedEncoding` rejects it.
        assert_eq!(
            transcode(b"a", "base64", "utf8"),
            Err(ffi::U_ILLEGAL_ARGUMENT_ERROR)
        );
    }

    #[test]
    fn invalid_utf8_substitutes_for_a_byte_target_and_fails_for_ucs2() {
        assert_eq!(
            hex(&transcode(&[0xff], "utf8", "latin1").expect("converts")),
            "3f"
        );
        assert_eq!(
            transcode(&[0xff], "utf8", "ucs2"),
            Err(ffi::U_INVALID_CHAR_FOUND)
        );
        assert_eq!(
            transcode(&[0x64, 0xc3], "utf8", "ucs2"),
            Err(ffi::U_INVALID_CHAR_FOUND)
        );
        // A UTF-8 target keeps the replacement character as UTF-8.
        assert_eq!(
            hex(&transcode(&[0xff], "utf8", "utf8").expect("converts")),
            "efbfbd"
        );
    }

    #[test]
    fn one_replacement_per_maximal_subpart() {
        // Truncated tail: the whole tail is one subpart.
        assert_eq!(
            hex(&transcode(&[0xe2, 0x82], "utf8", "latin1").expect("converts")),
            "3f"
        );
        assert_eq!(
            hex(&transcode(&[0xf0, 0x9f], "utf8", "latin1").expect("converts")),
            "3f"
        );
        // Surrogate code points encoded as UTF-8: three separate subparts.
        assert_eq!(
            hex(&transcode(&[0xed, 0xa0, 0x80], "utf8", "latin1").expect("converts")),
            "3f3f3f"
        );
        // Overlong forms: one subpart per offending byte.
        assert_eq!(
            hex(&transcode(&[0xc0, 0x80], "utf8", "latin1").expect("converts")),
            "3f3f"
        );
        assert_eq!(
            hex(&transcode(&[0xe0, 0x9f, 0xbf], "utf8", "latin1").expect("converts")),
            "3f3f3f"
        );
        // Past U+10FFFF.
        assert_eq!(
            hex(&transcode(&[0xf4, 0x90, 0x80, 0x80], "utf8", "latin1").expect("converts")),
            "3f3f3f3f"
        );
    }

    #[test]
    fn a_lone_surrogate_fails_only_on_the_strict_path() {
        assert_eq!(
            transcode(&[0x00, 0xd8], "ucs2", "utf8"),
            Err(ffi::U_INVALID_CHAR_FOUND)
        );
        // Through the generic conversion it is U+FFFD, which a byte target
        // renders as `?` and a `ucs2` target as FD FF.
        assert_eq!(
            hex(&transcode(&[0x00, 0xd8], "ucs2", "latin1").expect("converts")),
            "3f"
        );
        assert_eq!(
            hex(&transcode(&[0x00, 0xd8], "ucs2", "ucs2").expect("converts")),
            "fdff"
        );
        // A valid pair round-trips unchanged.
        assert_eq!(
            hex(&transcode(&[0x00, 0xd8, 0x00, 0xdc], "ucs2", "ucs2").expect("converts")),
            "00d800dc"
        );
        // Swapped surrogates are two unmatched units.
        assert_eq!(
            hex(&transcode(&[0x00, 0xdc, 0x00, 0xd8], "ucs2", "ucs2").expect("converts")),
            "fdfffdff"
        );
    }

    #[test]
    fn an_odd_trailing_byte_is_dropped_for_a_byte_target() {
        // `Buffer.alloc(2049, 0x61)` as UTF-16LE is 1024 units of U+6161 plus one
        // ignored byte, and U+6161 is unmappable in latin1.
        let long = vec![0x61u8; 2049];
        let short = vec![0x61u8; 2048];
        let converted = transcode(&long, "utf16le", "latin1").expect("converts");
        assert_eq!(converted.len(), 1024);
        assert_eq!(
            converted,
            transcode(&short, "utf16le", "latin1").expect("converts")
        );
        assert!(converted.iter().all(|byte| *byte == SUBSTITUTE));
        // A `ucs2` target sees the truncated sequence instead.
        assert_eq!(
            hex(&transcode(&[0x41], "ucs2", "ucs2").expect("converts")),
            "fdff"
        );
        // A `utf8` target cannot: `TranscodeUtf8FromUcs2` converts zero
        // characters and reports that as the error rather than an empty result.
        assert_eq!(
            transcode(&[0x41], "ucs2", "utf8"),
            Err(ffi::U_INVALID_CHAR_FOUND)
        );
    }

    #[test]
    fn upper_case_and_alias_labels_resolve() {
        assert_eq!(
            hex(&transcode(&[0xe9], "LATIN1", "UTF-8").expect("converts")),
            "c3a9"
        );
        assert_eq!(
            hex(&transcode(&[0xe9], "binary", "utf8").expect("converts")),
            "c3a9"
        );
        assert_eq!(
            parse_encoding("UCS-2"),
            Encoding::Ucs2,
            "the hyphenated alias"
        );
        assert_eq!(parse_encoding("utf16le"), Encoding::Ucs2);
    }

    #[test]
    fn empty_input_stays_empty() {
        for (from, to) in [
            ("utf8", "latin1"),
            ("latin1", "ucs2"),
            ("ucs2", "utf8"),
            ("ascii", "ascii"),
        ] {
            assert_eq!(
                transcode(&[], from, to).expect("converts"),
                Vec::<u8>::new(),
                "{from}->{to}"
            );
        }
    }

    #[test]
    fn error_names_are_icu_names() {
        assert_eq!(error_name(ffi::U_ZERO_ERROR), "U_ZERO_ERROR");
        assert_eq!(
            error_name(ffi::U_ILLEGAL_ARGUMENT_ERROR),
            "U_ILLEGAL_ARGUMENT_ERROR"
        );
        assert_eq!(
            error_name(ffi::U_INVALID_CHAR_FOUND),
            "U_INVALID_CHAR_FOUND"
        );
    }
}
