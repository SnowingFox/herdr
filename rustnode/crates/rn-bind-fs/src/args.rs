//! Argument marshalling: turning JavaScript values into Rust operands.
//!
//! Every binding member in `src/node_file.cc` starts by validating its
//! arguments with `BufferValue`, `GetValidatedFd`, `GetOffset` and friends, and
//! the JS layer has already done most user-facing validation. What remains here
//! is the boundary work: paths arrive as `string` or `Buffer`, descriptors as
//! `number`, positions as `number | null`, and stats flags as `boolean`.

use rn_v8_sys::v8;
use rn_v8_sys::v8::Local;

/// Reads a path argument as raw bytes.
///
/// The JS layer passes either a string (already normalised from `URL`) or a
/// `Buffer`. Both become bytes because the kernel does not distinguish, and
/// because a `Buffer` path may legitimately hold non-UTF-8 bytes.
pub fn path_bytes(scope: &mut v8::PinScope<'_, '_>, value: Local<v8::Value>) -> Option<Vec<u8>> {
    if value.is_string() {
        let string: Local<v8::String> = value.try_into().ok()?;
        Some(encode_utf8(scope, string))
    } else if value.is_array_buffer_view() {
        let view: Local<v8::ArrayBufferView> = value.try_into().ok()?;
        let length = view.byte_length();
        if length == 0 {
            return Some(Vec::new());
        }
        let mut out = vec![0u8; length];
        // SAFETY: `view.data()` points at the start of the view's bytes, whose
        // length is exactly `byte_length()`, and `copy_contents` writes at most
        // `out.len()` bytes into `out`.
        let copied = view.copy_contents(&mut out);
        out.truncate(copied);
        Some(out)
    } else {
        None
    }
}

/// Encodes a V8 string to UTF-8 bytes.
pub fn encode_utf8(scope: &mut v8::PinScope<'_, '_>, string: Local<v8::String>) -> Vec<u8> {
    let length = string.utf8_length(scope);
    let mut buffer = vec![0u8; length];
    // `write_utf8_v2` needs a `&mut Isolate`; the scope derefs to one.
    let written = string.write_utf8_v2(scope, &mut buffer, v8::WriteFlags::empty(), None);
    buffer.truncate(written);
    buffer
}

/// Encodes a V8 string using the encoding name the JS layer passed.
///
/// `fs` passes `'utf8'`, `'buffer'`, `'latin1'`, `'ascii'`, `'utf16le'` or
/// `'base64'`-family names depending on the API. Only the encodings the binding
/// actually has to produce for paths, readdir names and link targets are
/// handled here; anything else is reported as unsupported so a caller gets a
/// clear failure instead of silently wrong bytes.
pub fn encode_string_with(
    scope: &mut v8::PinScope<'_, '_>,
    string: Local<v8::String>,
    encoding: Encoding,
) -> Option<Vec<u8>> {
    match encoding {
        Encoding::Utf8 => Some(encode_utf8(scope, string)),
        Encoding::Buffer => Some(encode_utf8(scope, string)),
        Encoding::Latin1 => {
            let length = string.length();
            let mut buffer = vec![0u8; length];
            string.write_one_byte_v2(scope, 0, &mut buffer, v8::WriteFlags::empty());
            Some(buffer)
        }
        Encoding::Ucs2 => {
            // UTF-16 little-endian is what `fs` expects for `'utf16le'`. The
            // string is read as UTF-8 and re-encoded, which is correct for the
            // BMP and matches Node's output for surrogate pairs too because
            // `encode_utf16` produces them.
            let utf8 = encode_utf8(scope, string);
            let text = String::from_utf8(utf8).ok()?;
            let mut out = Vec::with_capacity(text.len() * 2);
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            Some(out)
        }
    }
}

/// Encoding selector mirroring libuv's `enum encoding`, restricted to the
/// values this binding has to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Buffer,
    Latin1,
    Ucs2,
}

impl Encoding {
    /// Maps the string `fs` passes in the encoding slot.
    ///
    /// `undefined` and `null` mean UTF-8, matching `ParseEncoding`'s default.
    pub fn from_value(value: Option<Local<v8::Value>>, scope: &mut v8::PinScope<'_, '_>) -> Self {
        let Some(value) = value else {
            return Self::Utf8;
        };
        if !value.is_string() {
            return Self::Utf8;
        }
        let Ok(string) = Local::<v8::String>::try_from(value) else {
            return Self::Utf8;
        };
        let name = string.to_rust_string_lossy(scope).to_ascii_lowercase();
        match name.as_str() {
            "buffer" => Self::Buffer,
            "latin1" | "binary" | "ascii" => Self::Latin1,
            "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => Self::Ucs2,
            _ => Self::Utf8,
        }
    }
}

/// Reads an integer argument, coercing the way V8's `ToInteger` would.
pub fn int64(scope: &mut v8::PinScope<'_, '_>, value: Local<v8::Value>) -> Option<i64> {
    if value.is_big_int() {
        let big = Local::<v8::BigInt>::try_from(value).ok()?;
        let (raw, lossless) = big.i64_value();
        return if lossless { Some(raw) } else { None };
    }
    value.number_value(scope).map(|raw| raw as i64)
}

/// Reads a 32-bit signed integer argument.
pub fn int32(scope: &mut v8::PinScope<'_, '_>, value: Local<v8::Value>) -> Option<i32> {
    value.int32_value(scope)
}

/// Reads an unsigned 32-bit integer argument.
pub fn uint32(scope: &mut v8::PinScope<'_, '_>, value: Local<v8::Value>) -> Option<u32> {
    value.uint32_value(scope)
}

/// Reads a `boolean`-ish argument the way Node does: anything not `undefined`
/// and not `false` is true for these flags.
pub fn truthy(scope: &mut v8::PinScope<'_, '_>, value: Local<v8::Value>) -> bool {
    value.boolean_value(scope)
}

/// Reads an optional position: `null`/`undefined`/negative means "use the
/// current offset", which libuv encodes as `-1`.
pub fn position(scope: &mut v8::PinScope<'_, '_>, value: Local<v8::Value>) -> i64 {
    if value.is_null_or_undefined() {
        return -1;
    }
    int64(scope, value).unwrap_or(-1)
}
