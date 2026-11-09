//! Byte-to-string conversion for the digest and encoding surfaces.
//!
//! `digest('hex')` and `digest('base64')` are the only encodings a digest ever
//! produces, but `update(data, 'hex')` can decode any encoding Node accepts, and
//! the numeric ids in `encodingsMap` have to be understood as well because
//! `oneShotDigest` passes those instead of a name.
//!
//! Everything here is a pure function over bytes so it can be unit tested
//! without a V8 isolate.

use rn_v8_sys::v8;

/// Encodes `bytes` in `name`, or `None` for an encoding that does not exist.
///
/// The set is Node's `Buffer` encoding set minus the ones that cannot apply to a
/// digest (`utf8` of arbitrary digest bytes is lossy, and Node refuses it for
/// `digest()`; `lib/internal/crypto/hash.js` only ever passes an encoding that
/// `normalizeEncoding` accepted, so anything unrecognised here is a bug).
pub fn encode_bytes(bytes: &[u8], name: &str) -> Option<String> {
    match name {
        "hex" => Some(hex_encode(bytes)),
        "base64" => Some(base64_encode(bytes)),
        "base64url" => Some(base64url_encode(bytes)),
        "latin1" | "binary" => Some(bytes.iter().map(|byte| *byte as char).collect()),
        "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => Some(utf16le_encode(bytes)),
        "utf8" | "utf-8" => String::from_utf8(bytes.to_vec()).ok(),
        _ => None,
    }
}

/// Decodes `text` according to `name`, or `None` if it is not valid in that
/// encoding.
///
/// Used for `hash.update('616263', 'hex')`, which is a common way to feed binary
/// data without building a `Buffer` first.
pub fn decode_string(text: &str, name: &str) -> Option<Vec<u8>> {
    match name {
        "utf8" | "utf-8" => Some(text.as_bytes().to_vec()),
        "hex" => hex_decode(text),
        "base64" => base64_decode(text, false),
        "base64url" => base64_decode(text, true),
        "latin1" | "binary" => Some(text.chars().map(|ch| ch as u32 as u8).collect()),
        "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => Some(utf16le_decode(text)),
        _ => None,
    }
}

/// The normalised encoding name for a numeric `encodingsMap` id.
///
/// `oneShotDigest` receives `encodingsMap[normalized]` rather than the name, so
/// the id has to be translated back. The ids are `lib/internal/util.js`'s and are
/// an internal protocol, like the `kKey*` constants.
pub fn name_from_map_id(id: u32) -> Option<&'static str> {
    match id {
        // `encodingsMap` in `lib/internal/util.js`:
        // ascii: 0, latin1: 1, binary: 1, ucs2: 2, utf16le: 2, utf8: 3,
        // hex: 4, base64: 5, base64url: 6, utf16be: 7.
        1 => Some("latin1"),
        2 => Some("utf16le"),
        3 => Some("utf8"),
        4 => Some("hex"),
        5 => Some("base64"),
        6 => Some("base64url"),
        7 => Some("utf16be"),
        _ => None,
    }
}

/// Lowercase hexadecimal.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // The shifts cannot exceed a nibble, so the index is always in range.
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Parses hexadecimal.
///
/// An odd trailing nibble is **dropped**, not zero-padded: `Buffer.from('abc',
/// 'hex')` is `[0xab]` in Node, verified against a real `node` binary. Zero-padding
/// it to `[0xab, 0xc0]` would silently add a byte, which is the kind of difference
/// that changes a MAC.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if digits.iter().any(|byte| !byte.is_ascii_hexdigit()) {
        return None;
    }
    let pairs = digits.len() / 2;
    let mut out = Vec::with_capacity(pairs);
    for index in 0..pairs {
        let high = hex_value(digits[index * 2])?;
        let low = hex_value(digits[index * 2 + 1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Standard base64 with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    base64_encode_inner(bytes, b"+/", true)
}

/// URL-safe base64 without padding.
pub fn base64url_encode(bytes: &[u8]) -> String {
    base64_encode_inner(bytes, b"-_", false)
}

fn base64_encode_inner(bytes: &[u8], alphabet: &[u8; 2], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let combined = (first << 16) | (second << 8) | third;

        out.push(base64_digit(((combined >> 18) & 0x3f) as u8, alphabet));
        out.push(base64_digit(((combined >> 12) & 0x3f) as u8, alphabet));
        if chunk.len() > 1 {
            out.push(base64_digit(((combined >> 6) & 0x3f) as u8, alphabet));
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(base64_digit((combined & 0x3f) as u8, alphabet));
        } else if pad {
            out.push('=');
        }
    }
    out
}

fn base64_digit(value: u8, alphabet: &[u8; 2]) -> char {
    match value {
        0..=25 => (b'A' + value) as char,
        26..=51 => (b'a' + value - 26) as char,
        52..=61 => (b'0' + value - 52) as char,
        62 => alphabet[0] as char,
        _ => alphabet[1] as char,
    }
}

fn base64_digit_value(byte: u8, url_safe: bool) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' if !url_safe => Some(62),
        b'/' if !url_safe => Some(63),
        b'-' if url_safe => Some(62),
        b'_' if url_safe => Some(63),
        _ => None,
    }
}

/// Decodes base64, tolerating missing padding as Node's `Buffer` does.
pub fn base64_decode(text: &str, url_safe: bool) -> Option<Vec<u8>> {
    let mut digits: Vec<u8> = Vec::with_capacity(text.len());
    for byte in text.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        digits.push(base64_digit_value(byte, url_safe)?);
    }
    if digits.len() % 4 == 1 {
        // One leftover digit cannot represent a byte; Node drops it.
        digits.truncate(digits.len() - 1);
    }
    let mut out = Vec::with_capacity(digits.len() * 3 / 4);
    for chunk in digits.chunks(4) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let fourth = chunk.get(3).copied().unwrap_or(0) as u32;
        let combined = (first << 18) | (second << 12) | (third << 6) | fourth;
        out.push((combined >> 16) as u8);
        if chunk.len() > 2 {
            out.push((combined >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(combined as u8);
        }
    }
    Some(out)
}

/// UTF-16LE bytes, the encoding `digest('utf16le')` produces.
fn utf16le_encode(bytes: &[u8]) -> String {
    // The bytes are interpreted pairwise, with an odd trailing byte becoming a
    // code unit on its own. That is what `buf.toString('utf16le')` does.
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| {
            let low = pair[0] as u16;
            let high = pair.get(1).copied().unwrap_or(0) as u16;
            low | (high << 8)
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// Encodes a Rust string as UTF-16LE bytes.
fn utf16le_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Builds a `Uint8Array` over a fresh backing store holding `bytes`.
///
/// A `Uint8Array` rather than a `Buffer`: at this point in the bootstrap
/// `lib/buffer.js` may not have finished loading, and everything that consumes a
/// digest in `lib/internal/crypto/**` only indexes it or calls `.length`.
pub fn uint8_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Uint8Array>> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    v8::Uint8Array::new(scope, buffer, 0, bytes.len())
}

/// Builds an `ArrayBuffer` holding `bytes`, which is what `crypto.subtle.digest`
/// resolves to.
pub fn array_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::ArrayBuffer>> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    Some(v8::ArrayBuffer::with_backing_store(scope, &store))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x0f, 0x10, 0xff, 0xa5];
        assert_eq!(hex_encode(&bytes), "000f10ffa5");
        assert_eq!(hex_decode("000f10ffa5").expect("decode"), bytes);
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn hex_decode_accepts_uppercase_and_odd_length() {
        assert_eq!(
            hex_decode("DEADBEEF").expect("uppercase"),
            [0xde, 0xad, 0xbe, 0xef]
        );
        // `Buffer.from('abc', 'hex')` is `[0xab]`: the odd nibble is dropped.
        assert_eq!(hex_decode("abc").expect("odd"), [0xab]);
        assert_eq!(hex_decode("").expect("empty"), Vec::<u8>::new());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        assert!(hex_decode("zz").is_none());
        assert!(hex_decode("ab cd ef").is_some(), "whitespace is skipped");
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        // RFC 4648 section 10.
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(
                base64_encode(plain.as_bytes()),
                encoded,
                "encoding {plain:?}"
            );
            assert_eq!(
                base64_decode(encoded, false).expect("decode"),
                plain.as_bytes(),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn base64url_uses_the_url_alphabet_without_padding() {
        // Bytes that produce +, / and = in standard base64.
        let bytes = [0xfb, 0xff, 0xbf];
        assert_eq!(base64_encode(&bytes), "+/+/");
        assert_eq!(base64url_encode(&bytes), "-_-_");
        assert_eq!(base64_decode("-_-_", true).expect("decode"), bytes);
    }

    #[test]
    fn base64_decode_tolerates_missing_padding() {
        assert_eq!(base64_decode("Zm9vYg", false).expect("unpadded"), b"foob");
    }

    #[test]
    fn latin1_round_trips_every_byte() {
        let bytes: Vec<u8> = (0..=255).collect();
        let text: String = bytes.iter().map(|byte| *byte as char).collect();
        assert_eq!(decode_string(&text, "latin1").expect("decode"), bytes);
        assert_eq!(encode_bytes(&bytes, "latin1"), Some(text));
    }

    #[test]
    fn utf16le_round_trips() {
        let bytes = decode_string("hi", "utf16le").expect("decode");
        assert_eq!(bytes, [b'h', 0, b'i', 0]);
        assert_eq!(encode_bytes(&bytes, "utf16le").as_deref(), Some("hi"));
    }

    #[test]
    fn unknown_encoding_is_rejected() {
        assert_eq!(encode_bytes(b"abc", "rot13"), None);
        assert_eq!(decode_string("abc", "rot13"), None);
    }

    #[test]
    fn map_ids_translate_to_names() {
        assert_eq!(name_from_map_id(4), Some("hex"));
        assert_eq!(name_from_map_id(5), Some("base64"));
        assert_eq!(name_from_map_id(6), Some("base64url"));
        assert_eq!(name_from_map_id(1), Some("latin1"));
        assert_eq!(name_from_map_id(999), None);
    }

    #[test]
    fn utf8_output_requires_valid_utf8() {
        assert_eq!(encode_bytes(b"abc", "utf8").as_deref(), Some("abc"));
        // A digest is arbitrary bytes, so invalid UTF-8 must not be silently
        // replaced: Node throws for `digest('utf8')` on such a buffer.
        assert_eq!(encode_bytes(&[0xff, 0xfe], "utf8"), None);
    }
}
