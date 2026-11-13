//! The byte/string conversions behind `Buffer`, the string decoder, and every
//! `StreamBase` string write.
//!
//! These are plain Rust functions over `&[u8]` and `&str`, deliberately kept
//! free of V8 types so they can be unit-tested exhaustively against a real
//! `node` binary without spinning an isolate. The binding layer only lifts
//! arguments out of JavaScript and calls into here.
//!
//! They live in the kernel crate because more than one binding needs them:
//! `internalBinding('buffer')` and `internalBinding('string_decoder')` decode
//! with them, and `StreamBase::Write*` encodes with them — and `rn-uv` implements
//! `StreamBase` but cannot depend on a binding crate. Keeping one copy is what
//! stops the two sides drifting on the encodings that are not textbook.
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

/// `StringBytes::Size` for `utf8`: the UTF-8 byte length of `units`, counted
/// without producing the bytes.
///
/// This is deliberately not `encode_utf8(units, usize::MAX).len()`. That was
/// the original implementation and it is correct, but it allocates a `u16`
/// copy of the string and then an entire encoded `Vec<u8>` to measure it, so
/// `Buffer.byteLength` cost three passes and two allocations where Node costs
/// one pass and none. `Buffer.byteLength` is called on every buffer-sized
/// string a program writes, so the length is worth its own counter.
///
/// # Semantics
///
/// These are `StringBytes::Size`'s, which calls
/// `simdutf::utf8_length_from_utf16_with_replacement`:
///
/// * every ASCII unit is one byte,
/// * every other BMP scalar is two or three bytes by its value,
/// * a surrogate *pair* is one four-byte scalar,
/// * an unpaired surrogate is one U+FFFD, so **three** bytes.
///
/// That last rule is the one to get right, and it is why the pair must be
/// combined rather than counted unit by unit: `"\uD800"` is 3, but `"\uD83D\uDE00"`
/// is 4 and not 6. Counting each surrogate as three would make the first
/// correct for the wrong reason and the second wrong.
///
/// `write` must agree with this (`Buffer#write` returns the count that
/// `Buffer#byteLength` reports for the same string), which is why both walk
/// the same pair rule. They stay separate functions: `write` emits bytes,
/// truncates at a character boundary, and has to size a buffer, so folding it
/// into a counter would make one depend on the other's `max` handling.
pub fn utf8_length(units: &[u16]) -> usize {
    // The overwhelmingly common case for `Buffer.byteLength` callers. A single
    // wide scan is much cheaper than the per-unit match below, and it answers
    // in units rather than needing to add anything up.
    if units.iter().all(|unit| *unit < 0x80) {
        return units.len();
    }
    // Well-formed UTF-16 cannot contain a surrogate that is not half of a pair,
    // so the pair rule below collapses to "a pair is 4, everything else is its
    // scalar width" and simdutf can count it. This is the same pair of calls
    // `String::Utf8Length` makes. The length is only taken through here once
    // validity is known: `utf8_length_from_utf16le` assumes valid input, while
    // `StringBytes::Size` uses the `_with_replacement` variant, and the two
    // differ on exactly the inputs this branch excludes.
    if units.len() >= UTF16_SIMD_THRESHOLD && v8::simdutf::validate_utf16le(units) {
        return v8::simdutf::utf8_length_from_utf16le(units);
    }
    utf8_length_scalar(units)
}

/// The scalar counter, and the only path for ill-formed UTF-16.
fn utf8_length_scalar(units: &[u16]) -> usize {
    let mut length = 0;
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if (0xD800..0xDC00).contains(&unit) {
            match units.get(index + 1) {
                Some(next) if (0xDC00..0xE000).contains(next) => {
                    length += 4;
                    index += 2;
                }
                // Unpaired lead surrogate: one replacement character.
                _ => {
                    length += 3;
                    index += 1;
                }
            }
            continue;
        }
        if (0xDC00..0xE000).contains(&unit) {
            // Unpaired trail surrogate on its own.
            length += 3;
        } else if unit < 0x80 {
            length += 1;
        } else if unit < 0x800 {
            length += 2;
        } else {
            length += 3;
        }
        index += 1;
    }
    length
}

/// Below this, validating and then counting in SIMD costs more than one scalar
/// pass. The crossover is where simdutf's fixed cost stops dominating, roughly
/// where the `v8` crate puts its own UTF-16 threshold.
const UTF16_SIMD_THRESHOLD: usize = 32;

/// `StringBytes::Size` for a one-byte string: `utf8_length_from_latin1`.
///
/// V8 stores a string that fits in Latin-1 as one byte per character, so the
/// caller has no `u16` units to count and none need to be materialised. Every
/// byte below `0x80` is one UTF-8 byte and every other byte is two, because a
/// Latin-1 code point in `0x80..=0xFF` needs a two-byte sequence.
///
/// `StringBytes::Size` calls `simdutf::utf8_length_from_latin1` here, so the
/// long-input case calls the same function through the copy of simdutf V8
/// already links. That has no validity subtleties — every Latin-1 byte is a
/// valid code point — so unlike the UTF-16 path there is no second
/// implementation to disagree with. Short inputs stay on the scalar sum
/// because the FFI call has a fixed cost that only pays off above a few dozen
/// bytes.
pub fn utf8_length_from_latin1(bytes: &[u8]) -> usize {
    if bytes.is_ascii() {
        return bytes.len();
    }
    if bytes.len() >= LATIN1_SIMD_THRESHOLD {
        return v8::simdutf::utf8_length_from_latin1(bytes);
    }
    // One addition per byte rather than a branch per byte; `(b >> 7)` is the
    // high-bit test without the branch, and the sum vectorises.
    bytes.len()
        + bytes
            .iter()
            .map(|byte| usize::from(byte >> 7))
            .sum::<usize>()
}

/// Below this, the simdutf FFI call costs more than the scalar sum it replaces.
/// The `v8` crate uses the same 128 for its own one-byte length path.
const LATIN1_SIMD_THRESHOLD: usize = 128;

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

/// `StringBytes::StorageSize`: the byte capacity [`write`] may need for `units`.
///
/// Node over-estimates on purpose — "always at least big enough, but may have
/// some extra" — because the exact size costs a second pass over the string and
/// the buffer is allocated once. Only `utf8` can expand past one byte per unit,
/// so only `utf8` gets a three-bytes-per-unit bound.
///
/// The `max` a caller passes to [`write`] is this value. It has to be the same
/// estimate rather than a tighter one: `hex`, `base64` and `base64url` *decode*
/// their input, and `write` sizes its scratch buffer from `max`.
pub fn storage_size(units: &[u16], encoding: Encoding) -> usize {
    match encoding {
        Encoding::Ascii | Encoding::Binary => units.len(),
        // `StringBytes::StorageSize` uses 3 * length for both of these, even
        // though a four-byte scalar needs only two units.
        Encoding::Utf8 | Encoding::Buffer => units.len() * 3,
        Encoding::Ucs2 => units.len() * 2,
        // `simdutf::base64_length_from_binary` on the *input* length, which is
        // an upper bound rather than the decoded size.
        Encoding::Base64 | Encoding::Base64Url => {
            base64_encoded_len(units.len(), encoding == Encoding::Base64Url)
        }
        // Two characters per byte; an odd trailing digit is dropped.
        Encoding::Hex => units.len() / 2,
    }
}

/// `StringBytes::Write`: encode code units as bytes, truncated to `max`.
///
/// This is the one encoder `StreamBase::Write*` uses. It is reachable for every
/// `enum encoding`, because `lib/internal/stream_base_commons.js` converts a
/// chunk with `Buffer.from(data, encoding)` only when the stream has the
/// "decode strings" flag; `net.Socket` does not, so `writeUtf8String` and friends
/// receive the raw string plus the name of the encoding the caller asked for.
///
/// The encodings are *not* uniform, which is the whole reason this is one
/// function instead of a call to `encode_utf8`:
///
/// * `ascii` and `latin1` take the low byte of every code unit. They do **not**
///   mask the high bit on the way in — `StringBytes::Encode` masks on the way
///   *out* — so `'ÿ'` becomes `0xff` here and reads back as `0x7f`.
/// * `utf8` replaces unpaired surrogates with U+FFFD and truncates only at a
///   character boundary.
/// * `ucs2` is little-endian UTF-16, so `"hi"` is four bytes.
/// * `hex`, `base64` and `base64url` *decode* their input rather than encode it.
pub fn write(units: &[u16], encoding: Encoding, max: usize) -> Vec<u8> {
    match encoding {
        Encoding::Utf8 | Encoding::Buffer => encode_utf8(units, max),
        Encoding::Ascii | Encoding::Binary => {
            let count = units.len().min(max);
            units[..count]
                .iter()
                .map(|unit| (*unit & 0xff) as u8)
                .collect()
        }
        Encoding::Ucs2 => encode_ucs2(units, max),
        Encoding::Hex => {
            let text: Vec<u8> = units.iter().map(|unit| (*unit & 0xff) as u8).collect();
            let mut out = vec![0u8; max];
            let written = decode_hex(&text, &mut out);
            out.truncate(written);
            out
        }
        Encoding::Base64 | Encoding::Base64Url => {
            let text: Vec<u8> = units.iter().map(|unit| (*unit & 0xff) as u8).collect();
            let mut out = vec![0u8; max];
            let written = decode_base64_forgiving(&text, &mut out);
            out.truncate(written);
            out
        }
    }
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
///
/// # Why the first byte is found on its own
///
/// A match can only start where `needle[0]` appears, so `memchr` visits the
/// candidate starts rather than every byte of the window. This is what
/// `nbytes::FindFirstCharacter` does, and the difference is not marginal: the
/// straight "compare the whole needle here" loop costs one failed `memcmp` per
/// byte of the window, so an *absent* needle — the worst case for every
/// `Buffer#indexOf` that answers `-1` — ran at roughly one byte per cycle
/// instead of at memory bandwidth. Only the remainder is compared, because
/// `memchr` has already established the first byte.
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
    let first = needle[0];
    let rest = &needle[1..];
    let index = start.min(last_start);
    if forward {
        let mut from = index;
        // `haystack[..=last_start]` is the window of positions a match could
        // start at: past `last_start` the needle no longer fits.
        while from <= last_start {
            let Some(offset) = memchr::memchr(first, &haystack[from..last_start + 1]) else {
                break;
            };
            let at = from + offset;
            if haystack[at + 1..at + needle.len()] == *rest {
                return at;
            }
            from = at + 1;
        }
    } else {
        // The window is `haystack[..=index]`, so `end` stays exclusive.
        let mut end = index + 1;
        while end > 0 {
            let Some(at) = memchr::memrchr(first, &haystack[..end]) else {
                break;
            };
            if haystack[at + 1..at + needle.len()] == *rest {
                return at;
            }
            end = at;
        }
    }
    search_end
}

/// The same search over UTF-16 code units, for `ucs2` index lookups.
///
/// Positions are returned in *bytes*, because that is what `Buffer#indexOf`
/// reports; `lib/buffer.js` hands back whatever the binding returns.
///
/// Units are not decoded into a `Vec<u16>`. `ucs2` is little-endian on every
/// platform, so the haystack's byte pairs already *are* the units, and the
/// candidate skip can run over the bytes directly. Only the higher of the
/// first unit's two bytes is searched for — `nbytes::FindFirstCharacter` does
/// the same, because for ASCII-in-UCS-2 text the other byte is `0x00` and
/// occurs at every unit, which would make the skip useless — and each hit is
/// aligned down to a unit boundary before the whole unit is verified.
pub fn search_ucs2(
    haystack: &[u8],
    needle: &[u16],
    search_end: usize,
    start_units: usize,
    forward: bool,
) -> usize {
    let units_end = search_end.min(haystack.len()) & !1;
    let needle_bytes = needle.len().saturating_mul(2);
    if needle.is_empty() || needle_bytes > units_end {
        // The answer the previous decode-and-scan gave: the whole search
        // window, in bytes, is also its "no match" value.
        return units_end;
    }
    let last_start = units_end - needle_bytes;
    let first = needle[0].to_le_bytes();
    let search_byte = first[0].max(first[1]);
    let index = start_units.saturating_mul(2).min(last_start);
    let found = if forward {
        let mut from = index;
        let mut hit = None;
        while from <= last_start {
            // The window ends one byte past `last_start`, not at it: the
            // matched byte may be the *high* half of the last candidate unit,
            // and dropping it would lose a match that only that byte gates.
            let Some(offset) = memchr::memchr(search_byte, &haystack[from..last_start + 2]) else {
                break;
            };
            // `from` and `last_start` are even, so masking down can only step
            // back into the unit that holds the matched byte.
            let at = from + (offset & !1);
            if haystack_matches_needle_at(haystack, at, needle) {
                hit = Some(at);
                break;
            }
            from = at + 2;
        }
        hit
    } else {
        let mut end = index + 2;
        let mut hit = None;
        while end >= 2 {
            let Some(at) = memchr::memrchr(search_byte, &haystack[..end]) else {
                break;
            };
            let at = at & !1;
            if haystack_matches_needle_at(haystack, at, needle) {
                hit = Some(at);
                break;
            }
            end = at;
        }
        hit
    };
    found.unwrap_or(units_end)
}

/// Whether `needle` occupies the whole units starting at byte offset `at`.
#[inline]
fn haystack_matches_needle_at(haystack: &[u8], at: usize, needle: &[u16]) -> bool {
    needle.iter().enumerate().all(|(index, unit)| {
        let offset = at + index * 2;
        u16::from_le_bytes([haystack[offset], haystack[offset + 1]]) == *unit
    })
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

    /// The units of a JavaScript string, which is what `write` takes.
    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn string_write_uses_the_low_byte_for_ascii_and_latin1() {
        // `node -e "process.stdout.write('\u00e9\u00ffhi','latin1')"` is
        // `e9 ff 68 69`. The high bit is *not* cleared on the way in:
        // `StringBytes::Encode` masks it when reading back.
        assert_eq!(
            write(&units("\u{00e9}\u{00ff}hi"), Encoding::Binary, 8),
            b"\xe9\xffhi"
        );
        // `ascii` narrows the same way; `0xff` stays `0xff` here.
        assert_eq!(
            write(&units("\u{00e9}\u{00ff}hi"), Encoding::Ascii, 8),
            b"\xe9\xffhi"
        );
    }

    #[test]
    fn string_write_encodes_utf8_and_ucs2_differently() {
        assert_eq!(write(&units("hi"), Encoding::Utf8, 8), b"hi");
        // `ucs2` is UTF-16LE, so each unit is two bytes.
        assert_eq!(write(&units("hi"), Encoding::Ucs2, 8), b"h\0i\0");
        // A multi-byte scalar widens in UTF-8 and stays one unit in UCS-2.
        assert_eq!(write(&units("\u{00e9}"), Encoding::Utf8, 8), b"\xc3\xa9");
        assert_eq!(write(&units("\u{00e9}"), Encoding::Ucs2, 8), b"\xe9\0");
    }

    #[test]
    fn string_write_decodes_hex_and_base64_rather_than_encoding_them() {
        // These two *decode* their input, which is what Node's `StringBytes::Write`
        // does for them: `process.stdout.write('6869','hex')` writes `hi`.
        assert_eq!(write(&units("6869"), Encoding::Hex, 8), b"hi");
        assert_eq!(write(&units("aGVsbG8="), Encoding::Base64, 8), b"hello");
        assert_eq!(write(&units("aGVsbG8"), Encoding::Base64Url, 8), b"hello");
    }

    #[test]
    fn string_write_truncates_to_max() {
        // Truncation stops at a character boundary for UTF-8, and a two-byte
        // scalar needs the whole `max` to appear.
        assert_eq!(write(&units("abc"), Encoding::Utf8, 2), b"ab");
        assert_eq!(write(&units("\u{00e9}a"), Encoding::Utf8, 1), b"");
        assert_eq!(write(&units("abc"), Encoding::Binary, 2), b"ab");
        // UCS-2 needs two bytes per unit, so `max` 3 carries one unit.
        assert_eq!(write(&units("abc"), Encoding::Ucs2, 3), b"a\0");
    }

    #[test]
    fn storage_size_is_at_least_the_bytes_write_produces() {
        // The contract `StringBytes::StorageSize` states: always big enough.
        // Every encoding is checked because a too-small estimate would truncate
        // a write silently.
        for encoding in [
            Encoding::Ascii,
            Encoding::Binary,
            Encoding::Utf8,
            Encoding::Buffer,
            Encoding::Ucs2,
            Encoding::Hex,
            Encoding::Base64,
            Encoding::Base64Url,
        ] {
            for text in [
                "",
                "a",
                "hi",
                "héllo",
                "\u{00e9}\u{00ff}",
                "日本語",
                "aGVsbG8=",
            ] {
                let units = units(text);
                let capacity = storage_size(&units, encoding);
                let produced = write(&units, encoding, capacity);
                assert!(
                    produced.len() <= capacity,
                    "{encoding:?} on {text:?}: wrote {} bytes into {capacity}",
                    produced.len()
                );
            }
        }
    }

    #[test]
    fn an_unpaired_surrogate_becomes_one_replacement_character() {
        // `'a\ud800b'` is three code units but four UTF-8 bytes, because the
        // lone surrogate is replaced rather than dropped.
        assert_eq!(
            write(&[0x61, 0xD800, 0x62], Encoding::Utf8, 16),
            "a\u{fffd}b".as_bytes()
        );
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
    fn utf8_length_matches_the_encoder_and_node() {
        // Every expectation here is `Buffer.byteLength` on node 22, which is
        // also `Buffer.from(s).length`. The nine rows are the table that pins
        // the rewrite: the lone-surrogate rows are 3 bytes (one U+FFFD each),
        // and the pair rows prove pairs are combined rather than counted twice.
        let cases: &[(&[u16], usize)] = &[
            (&[], 0),
            (&[0x61], 1),
            (&[0x00E9], 2),
            (&[0x20AC], 3),
            (&[0xD83D, 0xDE00], 4),
            (&[0x61, 0xD83D, 0xDE00, 0x62], 6),
            (&[0xD800], 3),
            (&[0xDC00], 3),
            (&[0x61, 0xD800, 0x62], 5),
            // Adjacent surrogates in the wrong order are two replacements.
            (&[0xDC00, 0xD800], 6),
            (&[0xD800, 0xD800], 6),
            // A trail surrogate after a lead that is not its pair still counts
            // as two replacements, not one four-byte scalar.
            (&[0xD800, 0xD800, 0xDC00], 7),
            // Boundaries of the two- and three-byte ranges.
            (&[0x7F, 0x80, 0x7FF, 0x800, 0xFFFF], 1 + 2 + 2 + 3 + 3),
        ];
        for (units, expected) in cases {
            assert_eq!(utf8_length(units), *expected, "units {units:?}");
            // The counter and the encoder must never disagree: `Buffer#write`
            // reports the number of bytes `Buffer#byteLength` predicts.
            assert_eq!(
                encode_utf8(units, usize::MAX).len(),
                *expected,
                "encoder disagrees on units {units:?}"
            );
        }
    }

    #[test]
    fn utf8_length_from_latin1_is_the_same_row_for_one_byte_strings() {
        // A one-byte V8 string is Latin-1 by definition, so this must agree
        // with `utf8_length` over the same code units.
        let cases: &[(&[u8], usize)] = &[
            (b"", 0),
            (b"a", 1),
            // One byte per character, so this is one code point per element.
            (&[0xE9], 2),
            (&[0xFF], 2),
            (&[0x7F, 0x80], 3),
            (&[0x00], 1),
            (&[0xE9, 0xFF, 0x7F, 0x00], 6),
        ];
        for (bytes, expected) in cases {
            assert_eq!(utf8_length_from_latin1(bytes), *expected, "bytes {bytes:?}");
        }
        // And the general counter must agree when fed the same values as units:
        // a one-byte V8 string is Latin-1 by definition, so `Buffer.byteLength`
        // has to answer the same whether V8 stored the string as one byte or
        // two.
        assert_eq!(
            utf8_length(&[0xE9, 0xFF, 0x7F, 0x00]),
            utf8_length_from_latin1(&[0xE9, 0xFF, 0x7F, 0x00])
        );
    }

    #[test]
    fn utf8_length_handles_long_ill_formed_strings() {
        // The SIMD path in `utf8_length` is gated on `validate_utf16le`, which
        // is what makes it safe: `utf8_length_from_utf16le` assumes well-formed
        // input, and `StringBytes::Size` uses the `_with_replacement` variant
        // precisely because these strings reach it. Every case here is longer
        // than `UTF16_SIMD_THRESHOLD`, so each one exercises the gate rather
        // than the scalar-only short path.
        let mut pairs = Vec::new();
        for _ in 0..200 {
            pairs.extend_from_slice(&[0xD83D, 0xDE00]);
        }
        assert!(pairs.len() > UTF16_SIMD_THRESHOLD);
        assert_eq!(utf8_length(&pairs), 800);
        assert_eq!(encode_utf8(&pairs, usize::MAX).len(), 800);

        // One lone lead surrogate in the middle of an otherwise valid string
        // must still be 3 bytes, and must invalidate the whole string for the
        // SIMD path rather than being silently counted as something else.
        let mut lone_lead = pairs.clone();
        lone_lead.insert(100, 0xD800);
        assert_eq!(utf8_length(&lone_lead), 803);
        assert_eq!(encode_utf8(&lone_lead, usize::MAX).len(), 803);

        // A lone trail surrogate, likewise.
        let mut lone_trail = pairs.clone();
        lone_trail.insert(100, 0xDC00);
        assert_eq!(utf8_length(&lone_trail), 803);
        assert_eq!(encode_utf8(&lone_trail, usize::MAX).len(), 803);

        // A long run of one-byte characters with a single three-byte scalar at
        // the end: the tail must not be lost by a width assumption.
        let mut mostly_ascii = vec![0x61u16; 300];
        mostly_ascii.push(0x20AC);
        assert_eq!(utf8_length(&mostly_ascii), 303);
        assert_eq!(encode_utf8(&mostly_ascii, usize::MAX).len(), 303);
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

    // -- The differential control -------------------------------------------
    //
    // `search_bytes` and `search_ucs2` are public API on a compatibility
    // runtime, and the candidate-skip rewrite is a change of *how* the answer
    // is found, not what it is. The two functions below are the previous
    // implementations, kept verbatim, so "the new one is equivalent" is a
    // result rather than an assertion. They are deliberately the naive shape:
    // any cleverness here would be a second thing to be wrong.

    fn naive_search_bytes(
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

    fn naive_search_ucs2(
        haystack: &[u8],
        needle: &[u16],
        search_end: usize,
        start_units: usize,
        forward: bool,
    ) -> usize {
        let units = decode_ucs2(&haystack[..search_end.min(haystack.len()) & !1]);
        let end = units.len();
        if needle.is_empty() || needle.len() > end {
            return end * 2;
        }
        let last_start = end - needle.len();
        if forward {
            let mut index = start_units.min(last_start);
            while index <= last_start {
                if units[index..index + needle.len()] == *needle {
                    return index * 2;
                }
                index += 1;
            }
        } else {
            let mut index = start_units.min(last_start);
            loop {
                if units[index..index + needle.len()] == *needle {
                    return index * 2;
                }
                if index == 0 {
                    break;
                }
                index -= 1;
            }
        }
        end * 2
    }

    /// SplitMix64. Deterministic and dependency-free, so a failing case
    /// reproduces from the seed alone.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// A value in `0..bound`; `bound == 0` yields 0.
        fn below(&mut self, bound: usize) -> usize {
            if bound == 0 {
                0
            } else {
                (self.next() % bound as u64) as usize
            }
        }
    }

    /// The randomized comparison both directions, over a small alphabet so
    /// that real matches occur often: an implementation with a candidate-skip
    /// bug mostly fails on inputs that *do* match.
    #[test]
    fn search_bytes_agrees_with_the_naive_implementation() {
        let mut rng = Rng(0x5EED_1234_ABCD_0001);
        let mut cases = 0;
        let mut matches = 0;
        for _ in 0..4000 {
            let haystack_len = rng.below(81);
            let haystack: Vec<u8> = (0..haystack_len)
                .map(|_| b'a' + rng.below(3) as u8)
                .collect();
            let needle_len = rng.below(7);
            // The needle is drawn from the same alphabet, and half the time
            // from a slice of the haystack, so both "found" and "absent" are
            // common rather than one dominating by chance.
            let needle: Vec<u8> = if needle_len > 1 && !haystack.is_empty() && rng.below(2) == 0 {
                let at = rng.below(haystack.len());
                haystack[at..(at + needle_len).min(haystack.len())].to_vec()
            } else {
                (0..needle_len).map(|_| b'a' + rng.below(3) as u8).collect()
            };
            // `search_end` runs past the haystack on purpose: the clamp is
            // part of the contract.
            let search_end = rng.below(haystack_len + 5);
            let start = rng.below(haystack_len + 5);
            for forward in [true, false] {
                let expected = naive_search_bytes(&haystack, &needle, search_end, start, forward);
                let actual = search_bytes(&haystack, &needle, search_end, start, forward);
                assert_eq!(
                    actual, expected,
                    "haystack={haystack:?} needle={needle:?} search_end={search_end} \
                     start={start} forward={forward}"
                );
                cases += 1;
                // A match is a position inside the window; every other answer
                // is the window's own end.
                if expected < search_end.min(haystack_len) {
                    matches += 1;
                }
            }
        }
        assert_eq!(cases, 8000);
        // Both branches have to be exercised, or "they agree" only says the
        // no-match path was tested 8000 times.
        assert!(
            (1000..=7000).contains(&matches),
            "the generator produced an unbalanced mix: {matches} matches of {cases}"
        );
    }

    #[test]
    fn search_ucs2_agrees_with_the_naive_implementation() {
        let mut rng = Rng(0x5EED_1234_ABCD_0002);
        let mut cases = 0;
        let mut matches = 0;
        // The alphabet includes units whose *high* byte is the one worth
        // searching for (`0x4101` has its `0x41` in the high half), because
        // that is the case where aligning a hit back down to a unit boundary
        // and not dropping the last candidate's second byte both matter.
        let alphabet: [u16; 5] = [0x0061, 0x0062, 0x0063, 0x4101, 0x0161];
        for _ in 0..4000 {
            let unit_count = rng.below(41);
            let units: Vec<u16> = (0..unit_count)
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect();
            let haystack = encode_ucs2(&units, usize::MAX);
            let needle_len = rng.below(7);
            // Half the needles are a slice of the haystack, so genuine matches
            // are common; the other half are random draws from the alphabet.
            let needle: Vec<u16> = if needle_len > 1 && !units.is_empty() && rng.below(2) == 0 {
                let at = rng.below(units.len());
                units[at..(at + needle_len).min(units.len())].to_vec()
            } else {
                (0..needle_len)
                    .map(|_| alphabet[rng.below(alphabet.len())])
                    .collect()
            };
            let search_end = rng.below(haystack.len() + 5);
            let start_units = rng.below(haystack.len() + 5);
            for forward in [true, false] {
                let expected =
                    naive_search_ucs2(&haystack, &needle, search_end, start_units, forward);
                let actual = search_ucs2(&haystack, &needle, search_end, start_units, forward);
                assert_eq!(
                    actual, expected,
                    "haystack={haystack:?} needle={needle:?} search_end={search_end} \
                     start_units={start_units} forward={forward}"
                );
                cases += 1;
                if expected < search_end.min(haystack.len()) & !1 {
                    matches += 1;
                }
            }
        }
        assert_eq!(cases, 8000);
        assert!(
            (1000..=7000).contains(&matches),
            "the generator produced an unbalanced mix: {matches} matches of {cases}"
        );
    }

    /// One boundary case: `(haystack, needle, search_end, start, forward)`.
    type ByteCase<'a> = (&'a [u8], &'a [u8], usize, usize, bool);

    /// One boundary case: `(haystack, needle, search_end, start_units, forward)`.
    type Ucs2Case<'a> = (&'a [u8], &'a [u16], usize, usize, bool);

    /// The boundaries named one at a time, so a regression says which rule
    /// broke instead of only which random seed found it.
    #[test]
    fn search_boundaries_match_the_naive_implementation() {
        let cases: [ByteCase; 18] = [
            // Empty needle: the window, not a position.
            (b"hello", b"", 5, 0, true),
            (b"hello", b"", 5, 3, true),
            (b"hello", b"", 5, 5, false),
            (b"", b"", 0, 0, true),
            // Needle equal to the haystack, at both ends of the window.
            (b"hello", b"hello", 5, 0, true),
            (b"hello", b"hello", 5, 4, false),
            // Needle longer than the haystack, and longer than the window.
            (b"hello", b"hellos", 5, 0, true),
            (b"hello", b"ell", 3, 0, true),
            // A match at index 0.
            (b"aab", b"aa", 3, 0, true),
            // A match at the last possible start position.
            (b"aab", b"ab", 3, 0, true),
            // No match at all, in both directions.
            (b"aaaa", b"b", 4, 0, true),
            (b"aaaa", b"b", 4, 3, false),
            // A real match beyond `search_end` must not be reported.
            (b"xxneedlexx", b"needle", 6, 0, true),
            (b"xxneedlexx", b"needle", 8, 9, false),
            // `start` past `last_start` clamps to it in both directions.
            (b"abcabc", b"abc", 6, 99, true),
            (b"abcabc", b"abc", 6, 99, false),
            // Backward search from 0 sees only position 0.
            (b"aba", b"a", 3, 0, false),
            (b"aba", b"b", 3, 0, false),
        ];
        for (haystack, needle, search_end, start, forward) in cases {
            assert_eq!(
                search_bytes(haystack, needle, search_end, start, forward),
                naive_search_bytes(haystack, needle, search_end, start, forward),
                "haystack={haystack:?} needle={needle:?} search_end={search_end} \
                 start={start} forward={forward}"
            );
        }
    }

    #[test]
    fn search_ucs2_boundaries_match_the_naive_implementation() {
        // "abab" in UCS-2 is 61 00 62 00 61 00 62 00.
        let haystack = [0x61, 0x00, 0x62, 0x00, 0x61, 0x00, 0x62, 0x00];
        // A unit whose interesting byte is the high half: the candidate scan
        // has to look at both bytes of the first unit, not only the low one.
        let high_byte = encode_ucs2(&[0x4101, 0x4102, 0x4101], usize::MAX);
        let cases: [Ucs2Case; 13] = [
            (&haystack, &[], 8, 0, true),
            (&haystack, &[], 8, 2, false),
            (&haystack, &[0x0061, 0x0062, 0x0061, 0x0062], 8, 0, true),
            (&haystack, &[0x0061, 0x0062, 0x0061, 0x0062], 8, 3, false),
            // Longer than the window, and than the haystack.
            (&haystack, &[0x0061, 0x0062], 3, 0, true),
            (&haystack, &[0x61, 0x62, 0x61, 0x62, 0x61], 8, 0, true),
            // Match at 0, and at the last possible unit.
            (&haystack, &[0x0061], 8, 0, true),
            (&haystack, &[0x0062], 8, 0, true),
            // Absent.
            (&haystack, &[0x007A], 8, 0, true),
            (&haystack, &[0x007A], 8, 3, false),
            (&high_byte, &[0x4102], 6, 0, true),
            (&high_byte, &[0x4102], 6, 2, false),
            (&high_byte, &[0x4101, 0x4102, 0x4101], 6, 0, true),
        ];
        for (haystack, needle, search_end, start_units, forward) in cases {
            assert_eq!(
                search_ucs2(haystack, needle, search_end, start_units, forward),
                naive_search_ucs2(haystack, needle, search_end, start_units, forward),
                "haystack={haystack:?} needle={needle:?} search_end={search_end} \
                 start_units={start_units} forward={forward}"
            );
        }
    }
}
