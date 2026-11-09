//! The `*Slice`, `*Write`, `byteLengthUtf8` and `is*` members.
//!
//! Every function here mirrors one `StringSlice<...>`, `StringWrite<...>`,
//! `SlowWriteString<...>` or validator in `node_buffer.cc`, with the argument
//! list copied from the `lib/internal/buffer.js` call sites:
//!
//! ```text
//! utf8Slice(buffer, start, end)                 -> string
//! utf8Write(buffer, string, offset, length)     -> bytes written
//! utf8WriteStatic(view, string, offset, length) -> bytes written
//! ```
//!
//! `*Write` takes the Buffer as `args[0]` and `*WriteStatic` takes a plain
//! `Uint8Array` the same way; the only difference in Node is that the static
//! form skips the Buffer check and is exposed to the fast-API path. Here both
//! accept any `ArrayBufferView`, which is what "static" means for this binding.

use rn_v8_sys::v8;

use crate::args::{
    self, latin1_string, parse_index, require_string, require_view, string_to_units, utf16_string,
    Index,
};
use crate::codec::{self, Encoding};

/// Runs `*Slice`: decode `[start, end)` of the first argument.
pub(crate) fn slice<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    encoding: Encoding,
) -> Option<v8::Local<'s, v8::String>> {
    let source = args.get(0);
    if !require_view(scope, source) {
        return None;
    }
    let length = args::view_len(source)?;
    if length == 0 {
        return Some(v8::String::empty(scope));
    }
    let start = match parse_index(scope, args.get(1), 0) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };
    let end = match parse_index(scope, args.get(2), length) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };
    if end <= start {
        return Some(v8::String::empty(scope));
    }
    if end > length {
        args::throw_range_error(scope, "Index out of range");
        return None;
    }

    // Copy first: building the result string allocates, which can trigger a GC,
    // and a `&[u8]` into the source's backing store would then be a dangling
    // borrow if the view became unreachable. Node copies for the same reason on
    // the SharedArrayBuffer path; one code path covers both here.
    let bytes = args::copy_view(source)?;
    encode_bytes(scope, &bytes[start..end], encoding)
}

/// Decodes a byte window into a JavaScript string with `encoding`.
fn encode_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
    encoding: Encoding,
) -> Option<v8::Local<'s, v8::String>> {
    match encoding {
        Encoding::Ascii => latin1_string(scope, &codec::force_ascii(bytes)),
        Encoding::Binary => latin1_string(scope, bytes),
        Encoding::Utf8 | Encoding::Buffer => {
            let units = codec::decode_utf8_lossy(bytes);
            utf16_string(scope, &units)
        }
        Encoding::Ucs2 => utf16_string(scope, &codec::decode_ucs2(bytes)),
        Encoding::Hex => latin1_string(scope, &codec::encode_hex(bytes)),
        Encoding::Base64 => latin1_string(scope, &codec::encode_base64(bytes, false)),
        Encoding::Base64Url => latin1_string(scope, &codec::encode_base64(bytes, true)),
    }
}

/// Runs `*Write`/`*WriteStatic`: encode `args[1]` into `args[0]`.
///
/// The three length rules come from `StringWrite`:
///
/// * `offset` past the end of the buffer is `ERR_BUFFER_OUT_OF_BOUNDS`,
/// * `length` defaults to the remaining space and is clamped to it,
/// * a zero-length window writes nothing and reports `0`.
pub(crate) fn write(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    encoding: Encoding,
) -> Option<f64> {
    let target = args.get(0);
    if !require_view(scope, target) {
        return None;
    }
    let string = args.get(1);
    if !require_string(scope, string) {
        return None;
    }
    let total = args::view_len(target)?;
    let offset = match parse_index(scope, args.get(2), 0) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };
    if offset > total {
        args::throw_range_error(scope, "\"offset\" is outside of buffer bounds");
        return None;
    }
    let max_length = match parse_index(scope, args.get(3), total - offset) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };
    let max_length = max_length.min(total - offset);
    if max_length == 0 {
        return Some(0.0);
    }

    let Ok(string) = v8::Local::<v8::String>::try_from(string) else {
        return None;
    };
    let written = write_string_into(scope, target, offset, max_length, &string, encoding);
    Some(written as f64)
}

/// Encodes one string into a window of a buffer view.
fn write_string_into(
    scope: &mut v8::PinScope<'_, '_>,
    target: v8::Local<v8::Value>,
    offset: usize,
    max_length: usize,
    string: &v8::String,
    encoding: Encoding,
) -> usize {
    let units = string_to_units(string, scope);
    let encoded = encode_units(&units, encoding, max_length);
    args::with_view_bytes_mut(target, |bytes| {
        let window = &mut bytes[offset..offset + max_length];
        window[..encoded.len()].copy_from_slice(&encoded);
        encoded.len()
    })
    .unwrap_or(0)
}

/// Encodes UTF-16 code units to bytes, truncated to `max`.
pub(crate) fn encode_units(units: &[u16], encoding: Encoding, max: usize) -> Vec<u8> {
    match encoding {
        Encoding::Utf8 | Encoding::Buffer => codec::encode_utf8(units, max),
        Encoding::Ascii | Encoding::Binary => {
            // `StringBytes::Write` for ASCII and LATIN1 casts each code unit to
            // a byte. `ascii` additionally clears the high bit; on the decode
            // side that is `& 0x7f`, and `StringBytes` does not do it on the way
            // in, so this must not either.
            let bytes: Vec<u8> = units.iter().map(|unit| (*unit & 0xff) as u8).collect();
            bytes[..bytes.len().min(max)].to_vec()
        }
        Encoding::Ucs2 => codec::encode_ucs2(units, max),
        Encoding::Hex => {
            let text: Vec<u8> = units.iter().map(|unit| (*unit & 0xff) as u8).collect();
            let mut out = vec![0u8; max];
            let written = codec::decode_hex(&text, &mut out);
            out.truncate(written);
            out
        }
        Encoding::Base64 | Encoding::Base64Url => {
            let text: Vec<u8> = units.iter().map(|unit| (*unit & 0xff) as u8).collect();
            let mut out = vec![0u8; max];
            let written = codec::decode_base64_forgiving(&text, &mut out);
            out.truncate(written);
            out
        }
    }
}

/// `byteLengthUtf8`: the UTF-8 byte length of a string.
pub(crate) fn byte_length_utf8(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<f64> {
    let value = args.get(0);
    let Ok(string) = v8::Local::<v8::String>::try_from(value) else {
        args::throw_type_error(scope, "argument must be a string");
        return None;
    };
    let units = string_to_units(&string, scope);
    Some(codec::encode_utf8(&units, usize::MAX).len() as f64)
}

/// `byteLengthUtf8Fast`: the same length.
///
/// In Node this is a V8 fast-API callback whose slow fallback returns `-1`
/// unconditionally, so `lib/buffer.js` re-calls `byteLengthUtf8`. That contract
/// is `const length = byteLengthUtf8Fast(string); return length === -1 ?
/// byteLengthUtf8Slow(string) : length;` — so either answer is correct, and
/// returning the real length saves the second call.
pub(crate) fn byte_length_utf8_fast(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<f64> {
    byte_length_utf8(scope, args)
}

/// `stringLengthUtf8`: how many UTF-16 code units a byte slice decodes to.
pub(crate) fn string_length_utf8(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<f64> {
    argument_bytes(scope, args.get(0), |bytes| {
        codec::utf16_length_from_utf8_lossy(bytes)
    })
    .map(|length| length as f64)
}

/// `isUtf8`: exact UTF-8 validation.
///
/// Node calls `simdutf::validate_utf8`, which rejects overlong encodings,
/// surrogate code points and truncated sequences. This calls the same function
/// through the V8 bindings, so the answers cannot drift.
pub(crate) fn is_utf8(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<bool> {
    argument_bytes(scope, args.get(0), |bytes| {
        bytes.is_empty() || v8::simdutf::validate_utf8(bytes)
    })
}

/// `isAscii`: every byte below `0x80`.
pub(crate) fn is_ascii(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<bool> {
    argument_bytes(scope, args.get(0), |bytes| {
        bytes.is_empty() || v8::simdutf::validate_ascii_with_errors(bytes).is_ok()
    })
}

/// `isLatin1`: whether the *string* argument contains only code units `<= 0xFF`.
///
/// This one takes a string, not a view: `lib/buffer.js` validates it with
/// `validateString` first and the C++ does `args[0].As<String>()`.
pub(crate) fn is_latin1(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<bool> {
    let value = args.get(0);
    let Ok(string) = v8::Local::<v8::String>::try_from(value) else {
        args::throw_type_error(scope, "argument must be a string");
        return None;
    };
    Some(string.contains_only_onebyte())
}

/// Reads `value` as bytes whether it is a view or an `ArrayBuffer`.
///
/// `isUtf8`, `isAscii` and `stringLengthUtf8` all accept either; `lib/buffer.js`
/// documents the check as `isTypedArray(input) || isAnyArrayBuffer(input)`.
fn argument_bytes<T>(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
    read: impl FnOnce(&[u8]) -> T,
) -> Option<T> {
    if value.is_array_buffer_view() {
        return args::with_view_bytes(value, read);
    }
    if value.is_array_buffer() || value.is_shared_array_buffer() {
        let buffer = v8::Local::<v8::ArrayBuffer>::try_from(value).ok()?;
        let length = buffer.byte_length();
        let Some(data) = buffer.data() else {
            return Some(read(&[]));
        };
        if length == 0 {
            return Some(read(&[]));
        }
        // SAFETY: an ArrayBuffer's data pointer is valid for its byte length
        // while the buffer is reachable, which it is as an argument. `read`
        // cannot run JavaScript.
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), length) };
        return Some(read(bytes));
    }
    args::throw_type_error(scope, "input must be an ArrayBuffer or an ArrayBufferView");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_write_replaces_lone_surrogates_and_respects_the_limit() {
        assert_eq!(
            encode_units(&[0x41, 0x42], Encoding::Utf8, 8),
            b"AB".to_vec()
        );
        assert_eq!(
            encode_units(&[0xD800], Encoding::Utf8, 8),
            vec![0xEF, 0xBF, 0xBD]
        );
        assert_eq!(encode_units(&[0x00E9], Encoding::Utf8, 8), vec![0xC3, 0xA9]);
        // A two-byte character cannot be split.
        assert_eq!(encode_units(&[0x00E9], Encoding::Utf8, 1), Vec::<u8>::new());
    }

    #[test]
    fn latin1_write_truncates_code_units_to_bytes() {
        assert_eq!(
            encode_units(&[0x00E9, 0x0101], Encoding::Binary, 8),
            vec![0xE9, 0x01]
        );
        // `ascii` does not mask on write; it masks on read.
        assert_eq!(
            encode_units(&[0x00E9, 0x0101], Encoding::Ascii, 8),
            vec![0xE9, 0x01]
        );
    }

    #[test]
    fn ucs2_write_is_little_endian() {
        assert_eq!(
            encode_units(&[0x0041, 0x0042], Encoding::Ucs2, 4),
            vec![0x41, 0x00, 0x42, 0x00]
        );
        assert_eq!(
            encode_units(&[0x0041, 0x0042], Encoding::Ucs2, 3),
            vec![0x41, 0x00]
        );
    }

    /// The code units of an ASCII string, which is what a JS string argument
    /// turns into.
    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn hex_write_stops_at_the_first_bad_digit() {
        assert_eq!(encode_units(&units("abc"), Encoding::Hex, 4), vec![0xAB]);
        assert_eq!(encode_units(&units("abzz"), Encoding::Hex, 4), vec![0xAB]);
        assert_eq!(
            encode_units(&units("zz"), Encoding::Hex, 4),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn base64_write_is_forgiving() {
        let hello: Vec<u16> = "aGVsbG8=".encode_utf16().collect();
        assert_eq!(encode_units(&hello, Encoding::Base64, 8), b"hello".to_vec());
        let no_pad: Vec<u16> = "aGVsbG8".encode_utf16().collect();
        assert_eq!(
            encode_units(&no_pad, Encoding::Base64, 8),
            b"hello".to_vec()
        );
        let url: Vec<u16> = "a-_h".encode_utf16().collect();
        assert_eq!(
            encode_units(&url, Encoding::Base64Url, 8),
            vec![0x6B, 0xEF, 0xE1]
        );
    }
}
