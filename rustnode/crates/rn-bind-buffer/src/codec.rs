//! The byte/string conversions behind every `*Slice` and `*Write` member.
//!
//! These are plain Rust functions over `&[u8]` and `&str`, deliberately kept
//! free of V8 types so they can be unit-tested exhaustively against a real
//! `node` binary without spinning an isolate. The binding layer only lifts
//! arguments out of JavaScript and calls into here.
//!
//! # Why not a crate
//!
//! Node's own conversions are a small amount of byte arithmetic plus two tables
//! (`unhex_table`, `unbase64_table`). `base64`, `hex` and UTF-8 handling here
//! are written out instead of pulling in a dependency: the semantics are
//! *not* the textbook ones, and reproducing Node's exact behaviour from a
//! general-purpose crate would mean fighting it in the cases that matter.
//!
//! Three of those cases are worth stating up front, because they look like bugs
//! until you see the C++:
//!
//! * **`ascii` decoding masks every byte with `0x7f`.** `StringBytes::Encode`
//!   calls `nbytes::ForceAscii`, which is `src[i] & 0x7f`. So `0x80` decodes to
//!   `\u{0}`, not `\u{80}`. Encoding the other way is a plain truncation.
//! * **`utf8` decoding of invalid input replaces each *maximal subpart* with one
//!   U+FFFD**, and a four-byte sequence that decodes contributes two UTF-16
//!   units. `Utf16LengthFromInvalidUtf8` in `node_buffer.cc` spells that rule
//!   out; `decode_utf8_lossy_units` below is the same walk.
//! * **`ucs2` is little-endian on every platform.** It is not UTF-16LE "when the
//!   host is little-endian"; `StringBytes` byte-swaps on big-endian hosts so the
//!   bytes in a Buffer always match the documented LE layout.
//!
//! # Validation strategy
//!
//! Where Node calls `simdutf`, this module calls the same functions through the
//! `v8` crate's `simdutf` module, which wraps the copy of simdutf already linked
//! into V8. That keeps `isUtf8` exact (it rejects overlong encodings, surrogate
//! code points and truncated sequences) without a second implementation of the
//! rules drifting from the one Node ships.

/// Which encoding a `*Slice`/`*Write` member speaks.
///
/// The discriminants are Node's `enum encoding` values, because
/// `indexOfString`/`indexOfBuffer` receive that number from JavaScript
/// (`encodingsMap` in `lib/internal/util.js` is built from the
/// `string_decoder` namespace's `encodings` array). Keeping the numbers
/// identical means no translation table can go stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Encoding {
    Ascii = 0,
    Utf8 = 1,
    Base64 = 2,
    Ucs2 = 3,
    /// `binary`, which `ParseEncoding` maps onto `LATIN1`; kept so the numeric
    /// value round-trips even though nothing produces it from `lib/**`.
    Binary = 4,
    Hex = 5,
    Buffer = 6,
    Base64Url = 7,
}

impl Encoding {
    /// The encoding for a Node `enum encoding` number, if it is one.
    pub fn from_i32(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Ascii,
            1 => Self::Utf8,
            2 => Self::Base64,
            3 => Self::Ucs2,
            4 => Self::Binary,
            5 => Self::Hex,
            6 => Self::Buffer,
            7 => Self::Base64Url,
            _ => return None,
        })
    }

    /// Whether this encoding addresses the bytes two at a time.
    pub fn is_wide(self) -> bool {
        self == Self::Ucs2
    }
}

// ---------------------------------------------------------------------------
// ASCII / Latin-1
// ---------------------------------------------------------------------------

/// `nbytes::ForceAscii`: `dst[i] = src[i] & 0x7f`.
///
/// Not `to_ascii_lowercase` and not `char::from(byte)`: Node keeps the low seven
/// bits, which maps `0xff` to `0x7f` and `0x80` to `0x00`.
pub fn force_ascii(src: &[u8]) -> Vec<u8> {
    src.iter().map(|byte| byte & 0x7f).collect()
}

/// Node's `latin1` decode is the identity per byte, which is why
/// `latin1Slice` hands the bytes straight to `new_from_one_byte`; this function
/// exists only for the `decode_latin1` unit test that pins that claim.
#[cfg(test)]
pub fn decode_latin1(src: &[u8]) -> Vec<u16> {
    src.iter().map(|byte| u16::from(*byte)).collect()
}

// ---------------------------------------------------------------------------
// UTF-8
// ---------------------------------------------------------------------------

/// Number of UTF-16 code units a byte slice decodes to, with invalid input
/// replaced one U+FFFD per maximal subpart.
///
/// This is `StringLengthUtf8Impl`: the valid prefix is counted exactly, and the
/// remainder goes through the maximal-subpart walk in
/// [`utf16_units_from_invalid_utf8`].
pub fn utf16_length_from_utf8_lossy(bytes: &[u8]) -> usize {
    let result = v8::simdutf::validate_utf8_with_errors(bytes);
    if result.is_ok() {
        return v8::simdutf::utf16_length_from_utf8(bytes);
    }
    let valid_prefix = result.count;
    let (valid, rest) = bytes.split_at(valid_prefix);
    v8::simdutf::utf16_length_from_utf8(valid) + utf16_units_from_invalid_utf8(rest)
}

/// `Utf16LengthFromInvalidUtf8`, transcribed from `node_buffer.cc`.
///
/// Every maximal subpart of an ill-formed sequence becomes one replacement
/// character; a *well-formed* four-byte sequence becomes two UTF-16 units, which
/// is the branch that makes this more than "count the lead bytes".
pub fn utf16_units_from_invalid_utf8(bytes: &[u8]) -> usize {
    let mut units = 0;
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        if lead < 0x80 {
            index += 1;
            units += 1;
            continue;
        }
        let (length, low, high) = match lead {
            0xC2..=0xDF => (2, 0x80, 0xBF),
            0xE0..=0xEF => {
                let low = if lead == 0xE0 { 0xA0 } else { 0x80 };
                let high = if lead == 0xED { 0x9F } else { 0xBF };
                (3, low, high)
            }
            0xF0..=0xF4 => {
                let low = if lead == 0xF0 { 0x90 } else { 0x80 };
                let high = if lead == 0xF4 { 0x8F } else { 0xBF };
                (4, low, high)
            }
            _ => {
                // Invalid lead byte: one replacement character.
                index += 1;
                units += 1;
                continue;
            }
        };
        let mut seen = 1;
        while seen < length && index + seen < bytes.len() {
            let byte = bytes[index + seen];
            let in_range = if seen == 1 {
                byte >= low && byte <= high
            } else {
                (0x80..=0xBF).contains(&byte)
            };
            if !in_range {
                break;
            }
            seen += 1;
        }
        if seen == length {
            index += length;
            units += if length == 4 { 2 } else { 1 };
        } else {
            // The lead byte plus its valid continuations are one maximal
            // subpart; the byte that failed is decoded again next round.
            index += seen;
            units += 1;
        }
    }
    units
}

/// Decodes UTF-8 into UTF-16 code units, replacing malformed input.
///
/// Valid input goes through simdutf. Invalid input is decoded one maximal
/// subpart at a time so the replacement-character placement matches
/// [`utf16_units_from_invalid_utf8`] exactly; the two must agree or
/// `Buffer#toString` disagrees with `Buffer.byteLength` on the same bytes.
pub fn decode_utf8_lossy(bytes: &[u8]) -> Vec<u16> {
    if bytes.is_empty() {
        return Vec::new();
    }
    if v8::simdutf::validate_utf8(bytes) {
        let mut out = vec![0u16; v8::simdutf::utf16_length_from_utf8(bytes)];
        // SAFETY: `out` holds the exact number of UTF-16 code units simdutf
        // reports for this input, which is what the converter writes.
        let written = unsafe { v8::simdutf::convert_utf8_to_utf16le_with_errors(bytes, &mut out) };
        debug_assert!(written.is_ok(), "validated UTF-8 failed to convert");
        out
    } else {
        decode_utf8_replacing(bytes)
    }
}

/// The invalid-input path of [`decode_utf8_lossy`]: one U+FFFD per maximal
/// subpart, well-formed sequences converted normally.
fn decode_utf8_replacing(bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        if lead < 0x80 {
            out.push(u16::from(lead));
            index += 1;
            continue;
        }
        let (length, low, high) = match lead {
            0xC2..=0xDF => (2, 0x80, 0xBF),
            0xE0..=0xEF => {
                let low = if lead == 0xE0 { 0xA0 } else { 0x80 };
                let high = if lead == 0xED { 0x9F } else { 0xBF };
                (3, low, high)
            }
            0xF0..=0xF4 => {
                let low = if lead == 0xF0 { 0x90 } else { 0x80 };
                let high = if lead == 0xF4 { 0x8F } else { 0xBF };
                (4, low, high)
            }
            _ => {
                out.push(0xFFFD);
                index += 1;
                continue;
            }
        };
        let mut seen = 1;
        while seen < length && index + seen < bytes.len() {
            let byte = bytes[index + seen];
            let in_range = if seen == 1 {
                byte >= low && byte <= high
            } else {
                (0x80..=0xBF).contains(&byte)
            };
            if !in_range {
                break;
            }
            seen += 1;
        }
        if seen < length {
            out.push(0xFFFD);
            index += seen;
            continue;
        }
        let scalar = match length {
            2 => u32::from(lead & 0x1F) << 6 | u32::from(bytes[index + 1] & 0x3F),
            3 => {
                u32::from(lead & 0x0F) << 12
                    | u32::from(bytes[index + 1] & 0x3F) << 6
                    | u32::from(bytes[index + 2] & 0x3F)
            }
            _ => {
                u32::from(lead & 0x07) << 18
                    | u32::from(bytes[index + 1] & 0x3F) << 12
                    | u32::from(bytes[index + 2] & 0x3F) << 6
                    | u32::from(bytes[index + 3] & 0x3F)
            }
        };
        index += length;
        if scalar > 0xFFFF {
            let adjusted = scalar - 0x1_0000;
            out.push(0xD800 + ((adjusted >> 10) as u16));
            out.push(0xDC00 + ((adjusted & 0x3FF) as u16));
        } else {
            // The range checks above exclude surrogates, so this is a BMP
            // scalar and fits one unit.
            out.push(scalar as u16);
        }
    }
    out
}

/// Encodes UTF-16 code units as UTF-8, replacing unpaired surrogates with
/// U+FFFD the way `String::WriteFlags::kReplaceInvalidUtf8` does.
///
/// `max` truncates, and truncation stops at a character boundary: a partial
/// sequence is never emitted, which is what `WriteUtf8V2` guarantees and what
/// `Buffer#write` relies on to report a byte count that is also a valid string
/// length.
///
/// `src` is UTF-16 code units rather than a `&str` because JavaScript strings
/// are WTF-16 and can hold lone surrogates.
pub fn encode_utf8(units: &[u16], max: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(max.min(units.len() * 3));
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        let (scalar, width) = if (0xD800..0xDC00).contains(&unit) {
            match units.get(index + 1) {
                Some(next) if (0xDC00..0xE000).contains(next) => {
                    let combined =
                        0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(*next) - 0xDC00);
                    (combined, 2)
                }
                // Unpaired lead surrogate: one replacement character.
                _ => (0xFFFD, 1),
            }
        } else if (0xDC00..0xE000).contains(&unit) {
            // Unpaired trail surrogate on its own.
            (0xFFFD, 1)
        } else {
            (u32::from(unit), 1)
        };
        let encoded_len = utf8_len(scalar);
        if out.len() + encoded_len > max {
            break;
        }
        push_utf8(scalar, &mut out);
        index += width;
    }
    out
}

/// UTF-8 length of one scalar value.
fn utf8_len(scalar: u32) -> usize {
    match scalar {
        0..=0x7F => 1,
        0x80..=0x7FF => 2,
        0x800..=0xFFFF => 3,
        _ => 4,
    }
}

fn push_utf8(scalar: u32, out: &mut Vec<u8>) {
    match utf8_len(scalar) {
        1 => out.push(scalar as u8),
        2 => {
            out.push(0xC0 | (scalar >> 6) as u8);
            out.push(0x80 | (scalar & 0x3F) as u8);
        }
        3 => {
            out.push(0xE0 | (scalar >> 12) as u8);
            out.push(0x80 | ((scalar >> 6) & 0x3F) as u8);
            out.push(0x80 | (scalar & 0x3F) as u8);
        }
        _ => {
            out.push(0xF0 | (scalar >> 18) as u8);
            out.push(0x80 | ((scalar >> 12) & 0x3F) as u8);
            out.push(0x80 | ((scalar >> 6) & 0x3F) as u8);
            out.push(0x80 | (scalar & 0x3F) as u8);
        }
    }
}

// ---------------------------------------------------------------------------
// UCS-2
// ---------------------------------------------------------------------------

/// Decodes `ucs2` (UTF-16LE) bytes to code units.
///
/// An odd trailing byte is dropped, matching `StringBytes::Encode`'s
/// `str_len = buflen / 2`.
pub fn decode_ucs2(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect()
}

/// Encodes code units as little-endian `ucs2` bytes, truncated to `max`.
pub fn encode_ucs2(units: &[u16], max: usize) -> Vec<u8> {
    let count = (max / 2).min(units.len());
    let mut out = Vec::with_capacity(count * 2);
    for unit in &units[..count] {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

/// `nbytes::unhex_table` as a function: `-1` is "not a hex digit".
fn unhex(byte: u8) -> i8 {
    match byte {
        b'0'..=b'9' => (byte - b'0') as i8,
        b'a'..=b'f' => (byte - b'a' + 10) as i8,
        b'A'..=b'F' => (byte - b'A' + 10) as i8,
        _ => -1,
    }
}

/// `nbytes::HexEncode`: lowercase, two digits per byte.
pub fn encode_hex(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)]);
        out.push(DIGITS[usize::from(byte & 0x0F)]);
    }
    out
}

/// `nbytes::HexDecode`: decode `min(len, src_len / 2)` bytes, stopping at the
/// first non-hex digit.
///
/// An odd trailing digit is left undecoded rather than zero-padded, and the
/// return value is the number of *bytes* written, so `hexWrite("abc")` writes
/// one byte and reports `1`.
pub fn decode_hex(src: &[u8], dst: &mut [u8]) -> usize {
    let mut written = 0;
    while written < dst.len() && written * 2 + 1 < src.len() {
        let high = unhex(src[written * 2]);
        let low = unhex(src[written * 2 + 1]);
        if high < 0 || low < 0 {
            return written;
        }
        dst[written] = ((high as u8) << 4) | low as u8;
        written += 1;
    }
    written
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

const BASE64_STANDARD: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// `simdutf::base64_length_from_binary`: padded length for standard, unpadded
/// for the URL-safe alphabet.
///
/// The asymmetry is Node's: `base64` always emits `=` padding, `base64url`
/// never does. `Buffer#toString('base64url')` returns `"_w"` where `base64`
/// returns `"/w=="`.
pub fn base64_encoded_len(input_len: usize, url: bool) -> usize {
    if url {
        // ceil(len * 4 / 3), computed without floating point.
        (input_len / 3) * 4
            + match input_len % 3 {
                0 => 0,
                1 => 2,
                _ => 3,
            }
    } else {
        input_len.div_ceil(3) * 4
    }
}

/// Encodes with the standard (`+`/`/`, padded) or URL-safe (`-`/`_`, unpadded)
/// alphabet.
pub fn encode_base64(bytes: &[u8], url: bool) -> Vec<u8> {
    let table = if url { BASE64_URL } else { BASE64_STANDARD };
    let mut out = Vec::with_capacity(base64_encoded_len(bytes.len(), url));
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(table[usize::from(b0 >> 2)]);
        out.push(table[usize::from((b0 & 0x03) << 4 | b1 >> 4)]);
        if chunk.len() > 1 {
            out.push(table[usize::from((b1 & 0x0F) << 2 | b2 >> 6)]);
        } else if !url {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(table[usize::from(b2 & 0x3F)]);
        } else if !url {
            out.push(b'=');
        }
    }
    out
}

/// `nbytes::unbase64_table` values: `-2` is whitespace, `-1` is invalid.
///
/// The table accepts *both* alphabets (`+` and `-` both map to 62, `/` and `_`
/// both to 63), which is why `Buffer.from(s, 'base64')` happily decodes
/// base64url input with no option. The whitespace entries are only
/// `\t`, `\n`, `\r` and space; `\f` and `\v` are *invalid*, which is what
/// [`decode_base64_forgiving`] reproduces.
fn unbase64(byte: u8) -> i8 {
    match byte {
        b'A'..=b'Z' => (byte - b'A') as i8,
        b'a'..=b'z' => (byte - b'a' + 26) as i8,
        b'0'..=b'9' => (byte - b'0' + 52) as i8,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        b'\t' | b'\n' | b'\r' | b' ' => -2,
        _ => -1,
    }
}

/// `nbytes::Base64Decode`: Node's forgiving-base64 decoder.
///
/// Whitespace is skipped, `=` ends the input, and both alphabets are accepted.
/// Decoding stops at the first invalid character or when `dst` is full; the
/// return value is the number of bytes written.
///
/// Bytes are emitted as soon as the characters that complete them have been
/// read, not group at a time. That is what `Base64DecodeGroupSlow` does — each
/// of its three `V(...)` steps writes one byte and re-checks the destination —
/// and it is why writing `"aGVsbG8="` into a two-byte buffer yields `6865`
/// rather than nothing.
pub fn decode_base64_forgiving(src: &[u8], dst: &mut [u8]) -> usize {
    let mut written = 0;
    let mut values = [0u8; 4];
    let mut filled = 0usize;

    for byte in src {
        let value = unbase64(*byte);
        if value == -2 {
            continue;
        }
        if value < 0 {
            // `=` and invalid characters both end the input.
            break;
        }
        values[filled] = value as u8;
        filled += 1;
        // One byte completes at every step past the first character: two
        // characters give byte 0, three give byte 1, four give byte 2.
        let completed = match filled {
            2 => 0,
            3 => 1,
            4 => 2,
            _ => continue,
        };
        if written >= dst.len() {
            break;
        }
        dst[written] = match completed {
            0 => (values[0] << 2) | (values[1] >> 4),
            1 => ((values[1] & 0x0F) << 4) | (values[2] >> 2),
            _ => ((values[2] & 0x03) << 6) | values[3],
        };
        written += 1;
        if filled == 4 {
            filled = 0;
        }
    }
    written
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

/// `nbytes::SearchString` over bytes.
///
/// `start` is the index the search begins at in the search direction, and
/// `haystack` is searched up to `search_end` exclusive. Returns `search_end`
/// when there is no match, which every caller compares against.
pub fn search_bytes(
    haystack: &[u8],
    needle: &[u8],
    search_end: usize,
    start: usize,
    forward: bool,
) -> usize {
    let search_end = search_end.min(haystack.len());
    if needle.is_empty() || needle.len() > search_end {
        return search_end;
    }
    let last_start = search_end - needle.len();
    if forward {
        let mut index = start.min(last_start);
        while index <= last_start {
            if haystack[index..index + needle.len()] == *needle {
                return index;
            }
            index += 1;
        }
    } else {
        let mut index = start.min(last_start);
        loop {
            if haystack[index..index + needle.len()] == *needle {
                return index;
            }
            if index == 0 {
                break;
            }
            index -= 1;
        }
    }
    search_end
}

/// The same search over UTF-16 code units, for `ucs2` index lookups.
///
/// Positions are returned in *bytes*, because that is what `Buffer#indexOf`
/// reports; `lib/buffer.js` hands back whatever the binding returns.
pub fn search_ucs2(
    haystack: &[u8],
    needle: &[u16],
    search_end: usize,
    start_units: usize,
    forward: bool,
) -> usize {
    let units = decode_ucs2(&haystack[..search_end.min(haystack.len()) & !1]);
    let found = search_bytes_units(&units, needle, units.len(), start_units, forward);
    found * 2
}

fn search_bytes_units(
    units: &[u16],
    needle: &[u16],
    end: usize,
    start: usize,
    forward: bool,
) -> usize {
    if needle.is_empty() || needle.len() > end {
        return end;
    }
    let last_start = end - needle.len();
    if forward {
        let mut index = start.min(last_start);
        while index <= last_start {
            if units[index..index + needle.len()] == *needle {
                return index;
            }
            index += 1;
        }
    } else {
        let mut index = start.min(last_start);
        loop {
            if units[index..index + needle.len()] == *needle {
                return index;
            }
            if index == 0 {
                break;
            }
            index -= 1;
        }
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_masks_the_high_bit() {
        assert_eq!(
            force_ascii(&[0x00, 0x7F, 0x80, 0xFF]),
            vec![0x00, 0x7F, 0x00, 0x7F]
        );
    }

    #[test]
    fn latin1_is_byte_per_code_point() {
        assert_eq!(
            decode_latin1(&[0x00, 0xE9, 0xFF]),
            vec![0x0000, 0x00E9, 0x00FF]
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_odd_input() {
        assert_eq!(encode_hex(&[0x00, 0x17, 0xF8, 0xFF]), b"0017f8ff".to_vec());
        let mut out = [0u8; 4];
        assert_eq!(decode_hex(b"0017f8ff", &mut out), 4);
        assert_eq!(out, [0x00, 0x17, 0xF8, 0xFF]);
        // Odd length: the trailing digit is not decoded.
        let mut out = [0xCC; 4];
        assert_eq!(decode_hex(b"abc", &mut out), 1);
        assert_eq!(out[0], 0xAB);
        assert_eq!(&out[1..], &[0xCC, 0xCC, 0xCC]);
        // Invalid digit stops the walk without writing.
        let mut out = [0xCC; 4];
        assert_eq!(decode_hex(b"abzz", &mut out), 1);
        assert_eq!(decode_hex(b"zz", &mut out), 0);
    }

    #[test]
    fn base64_url_has_no_padding() {
        for (len, standard, url) in [
            (0usize, "", ""),
            (1, "/w==", "_w"),
            (2, "//8=", "__8"),
            (3, "////", "____"),
            (4, "/////w==", "_____w"),
            (5, "//////8=", "______8"),
        ] {
            let input = vec![0xFFu8; len];
            assert_eq!(
                encode_base64(&input, false),
                standard.as_bytes(),
                "len {len}"
            );
            assert_eq!(encode_base64(&input, true), url.as_bytes(), "len {len}");
            assert_eq!(base64_encoded_len(len, false), standard.len());
            assert_eq!(base64_encoded_len(len, true), url.len());
        }
    }

    #[test]
    fn base64_decoding_is_forgiving() {
        let mut out = [0u8; 8];
        assert_eq!(decode_base64_forgiving(b"aGVsbG8=", &mut out), 5);
        assert_eq!(&out[..5], b"hello");
        // No padding at all.
        assert_eq!(decode_base64_forgiving(b"aGVsbG8", &mut out), 5);
        // Whitespace is skipped; URL-safe characters decode too.
        assert_eq!(decode_base64_forgiving(b"aGVs bG8=", &mut out), 5);
        assert_eq!(decode_base64_forgiving(b"a-_h", &mut out), 3);
        // An invalid character stops decoding; nothing is written for it.
        assert_eq!(decode_base64_forgiving(b"!!!!", &mut out), 0);
        assert_eq!(decode_base64_forgiving(b"aGVs!!!!", &mut out), 3);
        // A single trailing character cannot form a byte.
        assert_eq!(decode_base64_forgiving(b"aGVsbG8=a", &mut out), 5);
        assert_eq!(decode_base64_forgiving(b"Y", &mut out), 0);
        assert_eq!(decode_base64_forgiving(b"YQ", &mut out), 1);
        assert_eq!(out[0], b'a');
    }

    #[test]
    fn base64_decoding_respects_the_destination_length() {
        // node -e 'Buffer.alloc(2,0xcc).write("aGVsbG8=",0,2,"base64")' -> 2, "6865"
        let mut out = [0xCCu8; 2];
        assert_eq!(decode_base64_forgiving(b"aGVsbG8=", &mut out), 2);
        assert_eq!(&out, b"he");
        let mut out = [0xCCu8; 1];
        assert_eq!(decode_base64_forgiving(b"aGVsbG8=", &mut out), 1);
        assert_eq!(&out, b"h");
    }

    #[test]
    fn utf8_length_matches_the_maximal_subpart_rule() {
        // Valid input.
        assert_eq!(utf16_length_from_utf8_lossy(b"hello"), 5);
        assert_eq!(utf16_length_from_utf8_lossy("\u{1F600}".as_bytes()), 2);
        // A lone continuation byte is one replacement character.
        assert_eq!(utf16_length_from_utf8_lossy(&[0x80]), 1);
        // A truncated three-byte sequence is one replacement character.
        assert_eq!(utf16_length_from_utf8_lossy(&[0xE2, 0x82]), 1);
        // An overlong encoding is per-byte replacement: C0 and 80 are each
        // invalid lead/continuation bytes.
        assert_eq!(utf16_length_from_utf8_lossy(&[0xC0, 0x80]), 2);
        // A surrogate half encoded in UTF-8 (ED A0 80): node reports three
        // replacement characters, one per byte, because 0xED followed by A0
        // fails the ED-specific continuation range and each byte then stands
        // alone.
        assert_eq!(utf16_length_from_utf8_lossy(&[0xED, 0xA0, 0x80]), 3);
        // Valid text after invalid bytes still counts.
        assert_eq!(utf16_length_from_utf8_lossy(&[0xFF, 0x41]), 2);
    }

    #[test]
    fn utf8_decoding_agrees_with_the_length() {
        let cases: &[&[u8]] = &[
            b"",
            b"hello",
            &[0x80],
            &[0xE2, 0x82],
            &[0xC0, 0x80],
            &[0xED, 0xA0, 0x80],
            &[0xFF, 0x41],
            &[0xF0, 0x9F, 0x98, 0x80],
            &[0xF0, 0x9F],
        ];
        for case in cases {
            assert_eq!(
                decode_utf8_lossy(case).len(),
                utf16_length_from_utf8_lossy(case),
                "units for {case:?}"
            );
        }
        assert_eq!(
            decode_utf8_lossy(b"hello"),
            vec![0x68, 0x65, 0x6C, 0x6C, 0x6F]
        );
        assert_eq!(decode_utf8_lossy(&[0x80]), vec![0xFFFD]);
        // node -e 'Buffer.from([0xED,0xA0,0x80]).toString()' -> "\uFFFD" * 3
        assert_eq!(
            decode_utf8_lossy(&[0xED, 0xA0, 0x80]),
            vec![0xFFFD, 0xFFFD, 0xFFFD]
        );
        assert_eq!(
            decode_utf8_lossy(&[0xF0, 0x9F, 0x98, 0x80]),
            vec![0xD83D, 0xDE00]
        );
    }

    #[test]
    fn utf8_encoding_replaces_lone_surrogates() {
        assert_eq!(encode_utf8(&[0x41, 0x42], 8), b"AB".to_vec());
        assert_eq!(encode_utf8(&[0xD800], 8), vec![0xEF, 0xBF, 0xBD]);
        assert_eq!(encode_utf8(&[0xDC00], 8), vec![0xEF, 0xBF, 0xBD]);
        assert_eq!(
            encode_utf8(&[0xD83D, 0xDE00], 8),
            vec![0xF0, 0x9F, 0x98, 0x80]
        );
        // Truncation never splits a sequence.
        assert_eq!(encode_utf8(&[0x41, 0xD83D, 0xDE00], 3), b"A".to_vec());
        assert_eq!(encode_utf8(&[0x41, 0xD83D, 0xDE00], 4), b"A".to_vec());
        assert_eq!(encode_utf8(&[0x41, 0xD83D, 0xDE00], 5), {
            let mut expected = b"A".to_vec();
            expected.extend_from_slice(&[0xF0, 0x9F, 0x98, 0x80]);
            expected
        });
    }

    #[test]
    fn ucs2_is_little_endian_and_drops_an_odd_byte() {
        // node -e 'Buffer.from([0x41,0x00,0x42]).toString("ucs2")' -> "A"
        assert_eq!(decode_ucs2(&[0x41, 0x00, 0x42]), vec![0x0041]);
        assert_eq!(
            encode_ucs2(&[0x0041, 0x0042], 4),
            vec![0x41, 0x00, 0x42, 0x00]
        );
        // An odd max truncates to whole units.
        assert_eq!(encode_ucs2(&[0x0041, 0x0042], 3), vec![0x41, 0x00]);
    }

    #[test]
    fn forwards_search_finds_the_first_match() {
        assert_eq!(search_bytes(b"hello world", b"o", 11, 0, true), 4);
        assert_eq!(search_bytes(b"hello world", b"o", 11, 5, true), 7);
        assert_eq!(search_bytes(b"hello world", b"zz", 11, 0, true), 11);
        assert_eq!(search_bytes(b"hello", b"hello", 5, 0, true), 0);
    }

    #[test]
    fn backwards_search_finds_the_last_match() {
        // `start` is the index the backward search begins at, inclusive:
        // node -e 'Buffer.from("hello world").lastIndexOf("o", 10)' -> 7
        assert_eq!(search_bytes(b"hello world", b"o", 11, 10, false), 7);
        // ... and `lastIndexOf("o", 7)` is 7, `lastIndexOf("o", 3)` is -1.
        assert_eq!(search_bytes(b"hello world", b"o", 11, 7, false), 7);
        assert_eq!(search_bytes(b"hello world", b"o", 11, 3, false), 11);
        assert_eq!(search_bytes(b"hello world", b"zz", 11, 10, false), 11);
    }

    #[test]
    fn search_in_utf16_returns_byte_offsets() {
        // "ab" in UCS-2 is 61 00 62 00.
        let haystack = [0x61, 0x00, 0x62, 0x00, 0x61, 0x00];
        assert_eq!(search_ucs2(&haystack, &[0x0062], 6, 0, true), 2);
        assert_eq!(search_ucs2(&haystack, &[0x0061], 6, 1, true), 4);
        assert_eq!(search_ucs2(&haystack, &[0x0061], 6, 2, false), 4);
        assert_eq!(search_ucs2(&haystack, &[0x007A], 6, 0, true), 6);
    }
}
