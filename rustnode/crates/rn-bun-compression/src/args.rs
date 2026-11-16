//! Reading the arguments the eight members take, and building their results.
//!
//! Every fact here is measured against Bun 1.4.4 rather than inferred from its
//! option schema, because the schema and the observable surface disagree in two
//! places that matter:
//!
//! * The schema types the data argument as `string | Buffer`, but a plain
//!   `Uint8Array`, a `DataView` and a `SharedArrayBuffer` are all accepted
//!   (measured), and a `Blob` is not, even though `Bun.hash` takes one.
//! * The schema gives `level` no range, and the range comes from zlib itself:
//!   `{level: 99}` throws `Zlib error: Invalid argument` while
//!   `{level: -1}` is the library default.
//!
//! The string coercion is `Buffer.from(string)`'s, which is UTF-8 with every
//! unpaired surrogate replaced by U+FFFD — the same rule
//! `rn_core::codec::encode_utf8` implements, so `"a\uD800b"` becomes
//! `61 ef bf bd 62` on both runtimes.

use rn_v8_sys::v8;

use crate::error::CompressionError;
use crate::zlib_codec::CompressionParams;

/// The bytes argument `0`, or the rejection every member shares.
///
/// Accepts a `String` (UTF-8 encoded, lone surrogates replaced), an
/// `ArrayBuffer`, a `SharedArrayBuffer`, or any `ArrayBufferView` — for a view,
/// only the view's own window, so `Buffer.from("xxhelloyy").subarray(2, 7)`
/// compresses `hello` and not the whole backing store. A detached buffer reads
/// as empty input, which is what Bun does with one.
pub fn data_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<Vec<u8>, CompressionError> {
    if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
        return Ok(encode_string(scope, text));
    }
    if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        return Ok(copy_backing_store(
            &buffer.get_backing_store(),
            buffer.byte_length(),
        ));
    }
    if let Ok(buffer) = v8::Local::<v8::SharedArrayBuffer>::try_from(value) {
        return Ok(copy_backing_store(
            &buffer.get_backing_store(),
            buffer.byte_length(),
        ));
    }
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        // A detached view reports a zero length and copies nothing, so it reads
        // as empty input rather than as an error.
        let mut bytes = vec![0u8; view.byte_length()];
        let copied = view.copy_contents(&mut bytes);
        bytes.truncate(copied);
        return Ok(bytes);
    }
    Err(CompressionError::invalid_data())
}

/// `Buffer.from(string)`'s bytes: UTF-8, with unpaired surrogates replaced.
fn encode_string(scope: &v8::Isolate, text: v8::Local<v8::String>) -> Vec<u8> {
    // Three bytes per code unit bounds any UTF-8 encoding of `length()` units,
    // and `kReplaceInvalidUtf8` is what turns a lone surrogate into U+FFFD
    // instead of dropping it or writing a replacement scalar by hand.
    let mut out = vec![0u8; text.length() * 3 + 3];
    let written = text.write_utf8_v2(scope, &mut out, v8::WriteFlags::kReplaceInvalidUtf8, None);
    out.truncate(written);
    out
}

fn copy_backing_store(store: &v8::BackingStore, length: usize) -> Vec<u8> {
    match store.get(..length) {
        Some(cells) => cells.iter().map(|cell| cell.get()).collect(),
        None => Vec::new(),
    }
}

/// The `Bun.zstd` level argument.
///
/// Bun reads it with `level as i32`, so a string or a `BigInt` is coerced
/// (`{level: "9"}` and `{level: 9n}` both work) and a symbol is a plain
/// `TypeError` from the coercion itself. `undefined` means "absent", which is
/// Bun's `Option<i32>`; `null` is *not* absent and fails the range check because
/// it coerces to 0.
pub fn zstd_level<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    options: v8::Local<'s, v8::Value>,
) -> Result<i32, Option<CompressionError>> {
    let Some(object) = options_object(scope, options, "ZstdCompressionOptions")? else {
        return Ok(crate::zstd_codec::DEFAULT_LEVEL);
    };
    let Some(raw) = property(scope, object, "level") else {
        return Ok(crate::zstd_codec::DEFAULT_LEVEL);
    };
    if raw.is_undefined() {
        return Ok(crate::zstd_codec::DEFAULT_LEVEL);
    }
    let Some(number) = raw.number_value(scope) else {
        // `Number(Symbol())` throws inside V8 and leaves the exception pending,
        // which Bun surfaces unchanged (`Cannot convert a symbol to a number`).
        return Err(None);
    };
    let level = number as i32;
    if !(crate::zstd_codec::MIN_LEVEL..=crate::zstd_codec::MAX_LEVEL).contains(&level) {
        return Err(Some(crate::zstd_codec::invalid_level()));
    }
    Ok(level)
}

/// Whether argument 1 is an object, for the families that reject a primitive.
///
/// Bun's zlib takes `ZlibCompressionOptions`/`ZlibDecompressionOptions` through a
/// dictionary conversion that accepts an array (`allowArray: true`) and rejects
/// `null`, a number, a boolean or a string with
/// `ZlibCompressionOptions must be an object`. The zstd compression members have
/// the same shape and message with `ZstdCompressionOptions`. The zstd
/// *decompression* members take no options at all, so they never reach here.
pub fn options_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    options: v8::Local<'s, v8::Value>,
    name: &str,
) -> Result<Option<v8::Local<'s, v8::Object>>, Option<CompressionError>> {
    if options.is_undefined() {
        return Ok(None);
    }
    // An array is an object, and Bun's `allowArray` makes it a valid empty
    // options bag, so the only rejection is `null` and the primitives.
    if options.is_object() && !options.is_null() {
        return Ok(Some(v8::Local::<v8::Object>::try_from(options).map_err(
            |_| {
                Some(CompressionError::InvalidArgType(format!(
                    "{name} must be an object"
                )))
            },
        )?));
    }
    let _ = scope;
    Err(Some(CompressionError::InvalidArgType(format!(
        "{name} must be an object"
    ))))
}

/// Reads an own-or-inherited property, treating a failed read as absent.
///
/// A getter that throws leaves the exception pending; the caller's conversion
/// then reports it, which is what Bun's dictionary conversion does.
pub fn property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

/// Parses `ZlibCompressionOptions` in Bun's validation order.
///
/// The order is measured, not guessed, and it is visible: `{level: 99, memLevel:
/// 99}` reports the *memLevel* range error, and `{library: 'nope', memLevel: 99}`
/// reports memLevel too, while `{library: 'nope', level: 99}` reports the
/// library. So the dictionary's validated integers run first, in the order
/// `memLevel` then `strategy`, then `library`, and `level` is never validated at
/// all — an out-of-range level reaches zlib and fails there with
/// `Zlib error: Invalid argument`.
pub fn zlib_compression<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    options: v8::Local<'s, v8::Value>,
) -> Result<CompressionParams, CompressionError> {
    let object = options_object(scope, options, "ZlibCompressionOptions")
        // A pending exception from a throwing getter is not this crate's error;
        // callers see `None` here only for a coercion V8 already reported.
        .map_err(|error| error.unwrap_or_else(CompressionError::invalid_data))?;
    let Some(object) = object else {
        return Ok(CompressionParams::default());
    };

    // The validated integers are read first, in Bun's order (`memLevel` then
    // `strategy`), so a failure names the field Bun's own answer names. `level` is
    // never validated here: an out-of-range level reaches zlib and fails there
    // with `Zlib error: Invalid argument`, which is what Bun reports.
    let mem_level = validated_integer(scope, object, "memLevel", 1, 9)?;
    let strategy = validated_integer(scope, object, "strategy", 0, 4)?;
    check_library(scope, object)?;

    let mut level = CompressionParams::default().level;
    if let Some(value) = property(scope, object, "level") {
        if !value.is_undefined() {
            let Some(number) = value.number_value(scope) else {
                return Err(CompressionError::invalid_data());
            };
            level = number as i32;
        }
    }
    Ok(CompressionParams {
        level,
        mem_level,
        strategy,
    })
}

/// Parses `ZlibDecompressionOptions`.
///
/// Only `windowBits` and `library` are read; `level`, `memLevel` and `strategy`
/// are accepted and ignored — measured: `gunzipSync(gz, {level: 99})` succeeds
/// while `gzipSync("hello", {level: 99})` throws, and `{memLevel: 'x'}` does not
/// even fail the type check on the decompress side.
pub fn zlib_decompression<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    options: v8::Local<'s, v8::Value>,
    default_window_bits: i32,
) -> Result<Decompression, CompressionError> {
    let object = options_object(scope, options, "ZlibDecompressionOptions")
        .map_err(|error| error.unwrap_or_else(CompressionError::invalid_data))?;
    let Some(object) = object else {
        return Ok(Decompression {
            window_bits: default_window_bits,
        });
    };
    // `library` is checked before `windowBits`: measured with
    // `{windowBits: 100, library: 'nope'}`, which reports the library.
    check_library(scope, object)?;
    let mut window_bits = default_window_bits;
    if let Some(bits) = property(scope, object, "windowBits") {
        if !bits.is_undefined() {
            let Some(number) = bits.number_value(scope) else {
                return Err(CompressionError::invalid_data());
            };
            window_bits = number as i32;
        }
    }
    Ok(Decompression { window_bits })
}

/// `ZlibDecompressionOptions` after validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decompression {
    pub window_bits: i32,
}

/// `library`, which must be absent, `null`, `""`, `"zlib"` or `"libdeflate"`.
///
/// `libdeflate` is a real second encoder in Bun and its output differs, but
/// linking it would be a new dependency for a documented alternative rather than
/// for any member's default, so this crate accepts the name and encodes with
/// zlib. That divergence is stated in the report; the *error* for an unknown
/// name is reproduced exactly, because that is what tests assert.
fn check_library<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Result<(), CompressionError> {
    let Some(value) = property(scope, object, "library") else {
        return Ok(());
    };
    if value.is_null() || value.is_undefined() {
        return Ok(());
    }
    let Ok(text) = v8::Local::<v8::String>::try_from(value) else {
        return Err(CompressionError::InvalidArgType(
            "ZlibCompressionOptions.library must be a string".to_string(),
        ));
    };
    let name = text.to_rust_string_lossy(scope);
    if name.is_empty() || name == "zlib" || name == "libdeflate" {
        return Ok(());
    }
    Err(CompressionError::InvalidArgType(
        "Expected library to be one of 'zlib' or 'libdeflate'".to_string(),
    ))
}

/// One of Bun's `validateInteger(min, max)` option fields.
///
/// The messages are Node's `validateInt32` templates verbatim, down to the
/// `Received an instance of Object` spelling for a non-numeric type, because spec
/// 3.4's bar is the message text and not only the error class.
fn validated_integer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    min: i32,
    max: i32,
) -> Result<i32, CompressionError> {
    let Some(value) = property(scope, object, name) else {
        return Ok(default_for(name));
    };
    if value.is_undefined() {
        return Ok(default_for(name));
    }

    let type_name = value.type_of(scope).to_rust_string_lossy(scope);
    if type_name != "number" {
        let received = describe_received(scope, value);
        return Err(CompressionError::InvalidArgType(format!(
            "The \"ZlibCompressionOptions.{name}\" property must be of type number. {received}"
        )));
    }

    let Some(number) = value.number_value(scope) else {
        // A number object whose `valueOf` threw; the exception is already
        // pending and there is no message of ours to add.
        return Err(CompressionError::invalid_data());
    };
    if !number.is_finite() || number.fract() != 0.0 {
        return Err(CompressionError::OutOfRange(format!(
            "The value of \"ZlibCompressionOptions.{name}\" is out of range. It must be an integer. Received {}",
            number_text(number)
        )));
    }
    let integer = number as i64;
    if integer < i64::from(min) || integer > i64::from(max) {
        return Err(CompressionError::OutOfRange(format!(
            "The value of \"ZlibCompressionOptions.{name}\" is out of range. It must be >= {min} && <= {max}. Received {}",
            number_text(number)
        )));
    }
    Ok(integer as i32)
}

fn default_for(name: &str) -> i32 {
    match name {
        "memLevel" => 8,
        // `strategy` defaults to 0, which is also its minimum.
        _ => 0,
    }
}

/// Node's `Received …` tail for a value of the wrong type.
fn describe_received(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<'_, v8::Value>) -> String {
    if value.is_null() {
        return "Received null".to_string();
    }
    let type_name = value.type_of(scope).to_rust_string_lossy(scope);
    match type_name.as_str() {
        "undefined" => "Received undefined".to_string(),
        // Node prints a string's value in quotes and other primitives unquoted:
        // `Received type string ('9')` but `Received type boolean (true)`. Bun
        // inherits the same template, and the difference is one character that a
        // message-text comparison sees.
        "string" => format!(
            "Received type string ('{}')",
            value.to_rust_string_lossy(scope)
        ),
        "boolean" | "symbol" | "bigint" => format!(
            "Received type {type_name} ({})",
            value.to_rust_string_lossy(scope)
        ),
        "function" => {
            // Node prints `Received function <name>`, with the name empty for an
            // anonymous function.
            let name = v8::Local::<v8::Function>::try_from(value)
                .map(|function| function.get_name(scope).to_rust_string_lossy(scope))
                .unwrap_or_default();
            format!("Received function {name}")
        }
        // Objects print their constructor's name rather than `object`.
        _ => match v8::Local::<v8::Object>::try_from(value) {
            Ok(object) => format!(
                "Received an instance of {}",
                object.get_constructor_name().to_rust_string_lossy(scope)
            ),
            Err(_) => "Received an instance of Object".to_string(),
        },
    }
}

/// How Node renders a number in an out-of-range message.
///
/// `Received -0` for negative zero is deliberate: `format!` would print `0`, and
/// the measured message for `{memLevel: -0}` is `Received -0`.
fn number_text(number: f64) -> String {
    if number == 0.0 && number.is_sign_negative() {
        return "-0".to_string();
    }
    if number.is_nan() {
        return "NaN".to_string();
    }
    if number.fract() == 0.0 && number.abs() < 1e21 {
        return format!("{}", number as i64);
    }
    format!("{number}")
}

/// Builds the `Uint8Array` the four zlib members return.
///
/// Bun returns a plain `Uint8Array` here and a `Buffer` from the zstd members —
/// measured through `Object.getPrototypeOf(x).constructor.name`, and observable
/// with `Buffer.isBuffer`. `Uint8Array::new` over an owned backing store gives
/// exactly that, with no prototype surgery.
pub fn uint8_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: Vec<u8>,
) -> Option<v8::Local<'s, v8::Value>> {
    let length = bytes.len();
    let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.into_boxed_slice());
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store.make_shared());
    v8::Uint8Array::new(scope, array_buffer, 0, length).map(v8::Local::into)
}

/// Builds the `Buffer` the four zstd members return.
///
/// Through the global `Buffer`'s `from(arrayBuffer, 0, length)` so the real
/// constructor runs, which is what makes `Buffer.isBuffer` true; the same path
/// `rn-bind-fs` uses for `fs.readdir(dir, 'buffer')`.
pub fn buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: Vec<u8>,
) -> Option<v8::Local<'s, v8::Value>> {
    let length = bytes.len();
    let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.into_boxed_slice());
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store.make_shared());

    let context = scope.get_current_context();
    let global = context.global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let constructor = v8::Local::<v8::Object>::try_from(global.get(scope, key.into())?).ok()?;
    let from_key = v8::String::new(scope, "from")?;
    let from = constructor.get(scope, from_key.into())?;
    let from = v8::Local::<v8::Function>::try_from(from).ok()?;
    let start = v8::Integer::new(scope, 0);
    let count = v8::Integer::new(scope, i32::try_from(length).ok()?);
    let called = from.call(
        scope,
        constructor.into(),
        &[array_buffer.into(), start.into(), count.into()],
    )?;
    called.is_object().then_some(called)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_text_keeps_the_sign_of_negative_zero() {
        // The measured message for `{memLevel: -0}` is `Received -0`; a plain
        // `format!` would say `0` and the test comparing Bun's text would fail.
        assert_eq!(number_text(-0.0), "-0");
        assert_eq!(number_text(0.0), "0");
        assert_eq!(number_text(99.0), "99");
        assert_eq!(number_text(1e9), "1000000000");
        assert_eq!(number_text(f64::NAN), "NaN");
        assert_eq!(number_text(1.5), "1.5");
    }

    #[test]
    fn defaults_are_buns_and_not_zlibs() {
        // Bun's level default is 6, chosen explicitly, and it is not zlib's `-1`.
        assert_eq!(CompressionParams::default().level, 6);
        assert_eq!(CompressionParams::default().mem_level, 8);
        assert_eq!(CompressionParams::default().strategy, 0);
    }
}
