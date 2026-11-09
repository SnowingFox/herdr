//! Lifting JavaScript arguments out of V8, and putting results back.
//!
//! `node_buffer.cc` reads its arguments through V8 accessors that coerce
//! (`IntegerValue`, `Uint32Value`, `ToString`) and through `ArrayBufferView` for
//! every buffer. This module is those accessors with the coercions made
//! explicit, so each binding function reads as the argument list it expects.
//!
//! Two details are load bearing:
//!
//! * A `Buffer` is a `Uint8Array` subclass, so `Local<ArrayBufferView>` is the
//!   only downcast that works for both. `Value::is_uint8_array()` is true for a
//!   plain `Uint8Array` but is not the check Node performs, and it cannot be
//!   turned into a view.
//! * A borrowed view keeps its `&[u8]` inside the closure passed to
//!   [`with_view_bytes`]. Nothing holds a slice into V8's backing store across a
//!   statement that could run JavaScript, because a detached buffer would
//!   invalidate it.

use rn_v8_sys::v8;

use rn_core::codec::Encoding;

/// Turns an argument into a view, if it is one.
pub fn as_view(value: v8::Local<v8::Value>) -> Option<v8::Local<v8::ArrayBufferView>> {
    v8::Local::<v8::ArrayBufferView>::try_from(value).ok()
}

/// Runs `read` over an `ArrayBufferView` argument's bytes without copying.
///
/// Returns `None` when the argument is not an `ArrayBufferView`, which is the
/// one case `node_buffer.cc` rejects with `ERR_INVALID_ARG_TYPE`. The closure
/// gets an empty slice for a zero-length view, whose backing-store pointer V8
/// leaves null.
pub fn with_view_bytes<'s, T>(
    value: v8::Local<'s, v8::Value>,
    read: impl FnOnce(&[u8]) -> T,
) -> Option<T> {
    let view = as_view(value)?;
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() || length == 0 {
        return Some(read(&[]));
    }
    // SAFETY: `data()` is the backing store address plus the view's byte offset,
    // and `byte_length()` bytes are readable from it while the view is
    // reachable. The view is an argument, so it is reachable for this whole
    // call, and `read` cannot run JavaScript.
    let bytes = unsafe { std::slice::from_raw_parts(data, length) };
    Some(read(bytes))
}

/// Copies a view argument's bytes out of V8's heap.
pub fn copy_view(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    with_view_bytes(value, <[u8]>::to_vec)
}

/// The byte length of a view argument.
pub fn view_len(value: v8::Local<v8::Value>) -> Option<usize> {
    as_view(value).map(|view| view.byte_length())
}

/// Writes `write`'s bytes into a view argument's backing store.
///
/// Used by `fill`, `copy`, `swap*` and `mask`, all of which mutate in place. The
/// callback receives an empty slice for a zero-length view and must then do
/// nothing.
pub fn with_view_bytes_mut<T>(
    value: v8::Local<v8::Value>,
    write: impl FnOnce(&mut [u8]) -> T,
) -> Option<T> {
    let view = as_view(value)?;
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() || length == 0 {
        return Some(write(&mut []));
    }
    // SAFETY: `data()` points at `byte_length()` writable bytes owned by the
    // view's backing store, which outlives this call. `write` cannot run
    // JavaScript, and this is the only slice over that range, so there is no
    // aliasing.
    let bytes = unsafe { std::slice::from_raw_parts_mut(data, length) };
    Some(write(bytes))
}

/// The code units of a V8 string, lone surrogates preserved.
///
/// V8 strings are WTF-16, so this must not round-trip through `&str`:
/// `Buffer.from("\uD800", "ucs2")` is `00 d8`, and `utf8` writes replace the
/// lone surrogate with U+FFFD.
pub fn string_to_units(string: &v8::String, scope: &v8::Isolate) -> Vec<u16> {
    let length = string.length();
    if length == 0 {
        return Vec::new();
    }
    let mut units = vec![0u16; length];
    // No flags: raw code units, unvalidated.
    string.write_v2(scope, 0, &mut units, v8::WriteFlags::default());
    units
}

/// A required integer argument, coerced the way `IntegerValue` does.
///
/// `None` means the argument could not be coerced, which V8 signals by leaving a
/// pending exception: the binding then returns without setting a value, exactly
/// like the C++ `if (m.IsNothing()) return;`.
pub fn integer_argument(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<i64> {
    value.integer_value(scope)
}

/// The outcome of `ParseArrayIndex`: a usable index, or "out of range".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Index {
    Value(usize),
    OutOfRange,
}

/// `ParseArrayIndex`: an optional non-negative index with a default.
pub fn parse_index(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
    default: usize,
) -> Index {
    if value.is_undefined() {
        return Index::Value(default);
    }
    let Some(raw) = value.integer_value(scope) else {
        // A pending exception; treat as out of range so the caller still
        // returns and the exception is what the caller observes.
        return Index::OutOfRange;
    };
    if raw < 0 {
        return Index::OutOfRange;
    }
    match usize::try_from(raw) {
        Ok(index) => Index::Value(index),
        Err(_) => Index::OutOfRange,
    }
}

/// The encoding number `indexOfString`/`indexOfBuffer` receive as `args[3]`.
pub fn encoding_argument(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Encoding {
    let raw = value.int32_value(scope).unwrap_or(0);
    Encoding::from_i32(raw).unwrap_or(Encoding::Utf8)
}

/// Parses the `encoding` argument of `fill` the way `ParseEncoding` does.
///
/// `undefined` and unrecognised names both fall back to the default, which is
/// what `ParseEncoding` does. `lib/buffer.js` validates the name before calling
/// the binding, so this only needs the normal spellings and the `binary` alias.
pub fn parse_encoding(
    scope: &mut v8::PinScope<'_, '_>,
    value: Option<v8::Local<v8::Value>>,
    default: Encoding,
) -> Encoding {
    let Some(value) = value else {
        return default;
    };
    let Ok(string) = v8::Local::<v8::String>::try_from(value) else {
        return default;
    };
    let name = string.to_rust_string_lossy(scope);
    match_encoding(&name).unwrap_or(default)
}

/// The `ParseEncoding` name table, lowercased.
fn match_encoding(name: &str) -> Option<Encoding> {
    Some(match name.to_ascii_lowercase().as_str() {
        "utf8" | "utf-8" => Encoding::Utf8,
        "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => Encoding::Ucs2,
        "latin1" | "binary" => Encoding::Binary,
        "base64" => Encoding::Base64,
        "base64url" => Encoding::Base64Url,
        "hex" => Encoding::Hex,
        "ascii" => Encoding::Ascii,
        "buffer" => Encoding::Buffer,
        _ => return None,
    })
}

/// Builds a one-byte JavaScript string from Latin-1 bytes.
pub fn latin1_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::String>> {
    v8::String::new_from_one_byte(scope, bytes, v8::NewStringType::Normal)
}

/// Builds a JavaScript string from UTF-16 code units.
pub fn utf16_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    units: &[u16],
) -> Option<v8::Local<'s, v8::String>> {
    v8::String::new_from_two_byte(scope, units, v8::NewStringType::Normal)
}

/// Builds a JavaScript string from ASCII/UTF-8 bytes that are already known to
/// be ASCII, which is the fast path for `hexSlice` and `asciiSlice`.
pub fn utf8_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::String>> {
    v8::String::new_from_utf8(scope, bytes, v8::NewStringType::Normal)
}

/// Throws a `TypeError` with `message`.
pub fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let text = v8::String::new(scope, message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// Throws a `RangeError` with `message`.
pub fn throw_range_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let text = v8::String::new(scope, message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::range_error(scope, text);
    scope.throw_exception(exception);
}

/// The `argument must be a buffer` check every Buffer binding opens with.
///
/// `THROW_AND_RETURN_UNLESS_BUFFER` is `THROW_AND_RETURN_IF_NOT_BUFFER`, i.e.
/// `IsArrayBufferView`; the message text is V8's `ERR_INVALID_ARG_TYPE` prose
/// for a bare `argument` name, which is what the C++ passes.
pub fn require_view(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> bool {
    if value.is_array_buffer_view() {
        return true;
    }
    throw_type_error(scope, "argument must be a buffer");
    false
}

/// `THROW_AND_RETURN_IF_NOT_STRING`.
pub fn require_string(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> bool {
    if value.is_string() {
        return true;
    }
    throw_type_error(scope, "argument must be a string");
    false
}

/// A `Number` argument as `size_t`, the way `CheckNumberToSize` does it.
///
/// `None` when the value is not a non-negative number below `size_t::MAX`;
/// `CheckNumberToSize` is a `CHECK` in the C++, so reaching it with anything
/// else aborts Node. Rejecting instead keeps a stray call from taking the
/// process down.
pub fn number_to_size(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<usize> {
    let number = value.number_value(scope)?;
    if !number.is_finite() || number < 0.0 {
        return None;
    }
    // The C++ compares against `size_t::MAX` as a double for the same reason:
    // casting an out-of-range double saturates.
    if number >= usize::MAX as f64 {
        return None;
    }
    Some(number as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_names_follow_parse_encoding() {
        assert_eq!(match_encoding("utf8"), Some(Encoding::Utf8));
        assert_eq!(match_encoding("UTF-8"), Some(Encoding::Utf8));
        assert_eq!(match_encoding("utf16le"), Some(Encoding::Ucs2));
        assert_eq!(match_encoding("ucs-2"), Some(Encoding::Ucs2));
        // `binary` is the deprecated alias of `latin1`, and both share a
        // discriminant with `ASCII`'s neighbour rather than being distinct.
        assert_eq!(match_encoding("binary"), Some(Encoding::Binary));
        assert_eq!(match_encoding("latin1"), Some(Encoding::Binary));
        assert_eq!(match_encoding("base64url"), Some(Encoding::Base64Url));
        assert_eq!(match_encoding("nonsense"), None);
    }

    #[test]
    fn encoding_numbers_are_nodes_enum_values() {
        // `encodingsMap` in lib/internal/util.js is built from the
        // `string_decoder` namespace's `encodings` array, in this order.
        assert_eq!(Encoding::from_i32(0), Some(Encoding::Ascii));
        assert_eq!(Encoding::from_i32(1), Some(Encoding::Utf8));
        assert_eq!(Encoding::from_i32(2), Some(Encoding::Base64));
        assert_eq!(Encoding::from_i32(3), Some(Encoding::Ucs2));
        assert_eq!(Encoding::from_i32(5), Some(Encoding::Hex));
        assert_eq!(Encoding::from_i32(7), Some(Encoding::Base64Url));
        assert_eq!(Encoding::from_i32(9), None);
    }
}
