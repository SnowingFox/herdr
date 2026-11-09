//! Turning decoder bytes into a V8 string, matching `StringBytes::Encode`.
//!
//! `src/string_decoder.cc` funnels every result through `MakeString`, which is
//! `StringBytes::Encode` plus one guard for over-long UTF-8. The per-encoding
//! rules are:
//!
//! * `utf8` → `String::NewFromUtf8`, so invalid input becomes U+FFFD exactly as
//!   V8 replaces it. This is why the decoder never calls `from_utf8_lossy` on a
//!   chunk that may end mid-character: that decision belongs in [`crate::state`],
//!   and this module only sees bytes that are already complete.
//! * `utf16le` → 16-bit code units read little-endian, no validation, so a lone
//!   surrogate survives into the JavaScript string. (Node only drops a lone byte
//!   in `flush`, not a lone surrogate.)
//! * `ascii` → one byte per character with the high bit masked off
//!   (`nbytes::ForceAscii`), which turns 0xFF into U+007F rather than U+00FF.
//! * `latin1` → one byte per character, unmasked.
//! * `hex` → two lowercase hex digits per byte.
//! * `base64` → padded standard base64; `base64url` → unpadded URL-safe base64.
//!
//! The pure [`text`] function mirrors this for tests; [`to_v8_string`] is the
//! path the binding uses and defers to V8 for the encodings where V8's own
//! behaviour is the specification.

use rn_v8_sys::v8;

use crate::state::Encoding;

/// Decodes `bytes` to a Rust `String`, standing in for V8.
///
/// This exists so the retention logic in [`crate::state`] can be tested without
/// an isolate. `utf8` and `utf16le` use the lossy standard-library decoders,
/// which agree with V8 on replacement-character placement for invalid input;
/// the isolate tests in `tests/binding.rs` check the real conversion.
#[must_use]
pub fn text(encoding: Encoding, bytes: &[u8]) -> String {
    match encoding {
        Encoding::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        Encoding::Ucs2 => {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        Encoding::Ascii => bytes.iter().map(|byte| char::from(byte & 0x7f)).collect(),
        Encoding::Latin1 => bytes.iter().map(|byte| char::from(*byte)).collect(),
        Encoding::Hex => hex(bytes),
        Encoding::Base64 => base64(bytes, false),
        Encoding::Base64Url => base64(bytes, true),
        // `Buffer` decodes to a copied Buffer, which `StringDecoder` cannot
        // request; `state::State::decode` rejects it before this is reached.
        Encoding::Buffer => String::new(),
    }
}

/// Builds the JavaScript string for `bytes`.
///
/// Returns `Err` with Node's `ERR_STRING_TOO_LONG` code when the input is longer
/// than a V8 string can hold, which is the one case `MakeString` checks before
/// delegating to `StringBytes::Encode`.
pub fn to_v8_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    encoding: Encoding,
    bytes: &[u8],
) -> Result<v8::Local<'s, v8::String>, &'static str> {
    use v8::NewStringType::Normal;

    if bytes.is_empty() {
        // `StringBytes::Encode`: an empty input is the empty string.
        return Ok(v8::String::empty(scope));
    }

    if encoding == Encoding::Buffer {
        return Ok(v8::String::empty(scope));
    }

    let created = match encoding {
        Encoding::Utf8 => {
            if bytes.len() > v8::String::MAX_LENGTH {
                return Err("ERR_STRING_TOO_LONG");
            }
            v8::String::new_from_utf8(scope, bytes, Normal)
        }
        Encoding::Ucs2 => {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            v8::String::new_from_two_byte(scope, &units, Normal)
        }
        Encoding::Ascii => {
            let masked: Vec<u8> = bytes.iter().map(|byte| byte & 0x7f).collect();
            v8::String::new_from_one_byte(scope, &masked, Normal)
        }
        Encoding::Latin1 => v8::String::new_from_one_byte(scope, bytes, Normal),
        // The remaining encodings are ASCII text this side builds itself, so
        // the one-byte constructor is exact and avoids a transcode.
        Encoding::Hex | Encoding::Base64 | Encoding::Base64Url => {
            let encoded = text(encoding, bytes);
            v8::String::new_from_one_byte(scope, encoded.as_bytes(), Normal)
        }
        // Handled above; listed so a new variant cannot silently fall through.
        Encoding::Buffer => Some(v8::String::empty(scope)),
    };

    created.ok_or("ERR_STRING_TOO_LONG")
}

/// `nbytes::HexEncode`: two lowercase digits per byte.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// `simdutf::binary_to_base64`, standard or URL-safe.
///
/// The standard alphabet is padded to a multiple of four characters, which is
/// why a retained base64 group can be emitted unpadded by `decode` and then be
/// padded by `flush`; the URL-safe alphabet is never padded, matching the
/// `base64url` decoder's observed output.
#[must_use]
pub fn base64(bytes: &[u8], url_safe: bool) -> String {
    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let alphabet = if url_safe { URL_SAFE } else { STANDARD };
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for group in bytes.chunks(3) {
        let first = u32::from(group[0]);
        let second = group.get(1).map_or(0, |byte| u32::from(*byte));
        let third = group.get(2).map_or(0, |byte| u32::from(*byte));
        let packed = (first << 16) | (second << 8) | third;

        out.push(char::from(alphabet[((packed >> 18) & 0x3f) as usize]));
        out.push(char::from(alphabet[((packed >> 12) & 0x3f) as usize]));
        if group.len() > 1 {
            out.push(char::from(alphabet[((packed >> 6) & 0x3f) as usize]));
        } else if !url_safe {
            out.push('=');
        }
        if group.len() > 2 {
            out.push(char::from(alphabet[(packed & 0x3f) as usize]));
        } else if !url_safe {
            out.push('=');
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_two_digits_per_byte() {
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(hex(b""), "");
    }

    #[test]
    fn base64_is_padded_and_base64url_is_not() {
        // Observed from `new StringDecoder('base64')` on one, two and three
        // bytes of input.
        assert_eq!(base64(b"A", false), "QQ==");
        assert_eq!(base64(b"AB", false), "QUI=");
        assert_eq!(base64(b"ABC", false), "QUJD");
        assert_eq!(base64(b"ABCD", false), "QUJDRA==");

        assert_eq!(base64(b"A", true), "QQ");
        assert_eq!(base64(b"AB", true), "QUI");
        assert_eq!(base64(b"ABC", true), "QUJD");
    }

    #[test]
    fn base64_url_alphabet_differs_from_standard() {
        // 0xFB 0xFF selects indices 62 and 63.
        assert_eq!(base64(&[0xfb, 0xff, 0xff], false), "+///");
        assert_eq!(base64(&[0xfb, 0xff, 0xff], true), "-___");
    }

    #[test]
    fn ascii_masks_and_latin1_does_not() {
        assert_eq!(text(Encoding::Ascii, &[0x41, 0xff, 0x42]), "A\u{7f}B");
        assert_eq!(text(Encoding::Latin1, &[0x41, 0xff, 0x42]), "A\u{ff}B");
    }

    #[test]
    fn utf16le_reads_little_endian_units() {
        assert_eq!(text(Encoding::Ucs2, &[0x41, 0x00]), "A");
        // U+1F600 as a surrogate pair, little-endian.
        assert_eq!(text(Encoding::Ucs2, &[0x3d, 0xd8, 0x00, 0xde]), "😀");
    }
}
