//! Conversion between JavaScript values and SQLite values.
//!
//! This is the part of `node:sqlite` whose behaviour is most visible to a user,
//! and `src/node_sqlite.cc` is unusually specific about it. `BindValue` accepts
//! exactly six kinds and rejects everything else with `ERR_INVALID_ARG_TYPE`;
//! `SQLITE_VALUE_TO_JS` maps the five storage classes back, and a blob comes
//! back as a `Uint8Array` over a fresh `ArrayBuffer` — never a string.
//! `test-sqlite-data-types.js` and `test-sqlite-typed-array-and-data-view.js`
//! assert all of it.
//!
//! # The integer question
//!
//! SQLite has 64-bit integers; JavaScript numbers stop being exact at 2^53. The
//! C++ therefore has two modes: `readBigInts` returns a `BigInt` for every
//! integer, and otherwise a value outside `±(2^53 - 1)` throws
//! `ERR_OUT_OF_RANGE` rather than silently rounding. Both are reproduced here
//! because that rounding is exactly the kind of quiet wrong answer this project
//! exists to avoid.

use rn_v8_sys::v8;

use crate::errors;
use crate::ffi;

/// `kMaxSafeJsInteger` in `src/node_sqlite.cc`: `2^53 - 1`.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// How integers are read back out of SQLite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntMode {
    /// `Number`, throwing for a value a double cannot represent exactly.
    Number,
    /// `BigInt`, exact across the whole `i64` range.
    BigInt,
}

impl IntMode {
    /// `IntegerToValue`: `BigInt` when asked, otherwise a checked `Number`.
    pub fn to_value<'s>(
        self,
        scope: &mut v8::PinScope<'s, '_>,
        value: i64,
    ) -> Option<v8::Local<'s, v8::Value>> {
        match self {
            IntMode::BigInt => Some(v8::BigInt::new_from_i64(scope, value).into()),
            IntMode::Number => {
                if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
                    errors::throw_range(
                        scope,
                        &format!(
                            "Value is too large to be represented as a JavaScript number: {value}"
                        ),
                    );
                    return None;
                }
                Some(v8::Number::new(scope, value as f64).into())
            }
        }
    }
}

/// Why a JavaScript value could not become a SQLite binding.
///
/// `Statement::BindValue` has two distinct failures — `IsBigInt()` with a
/// lossless conversion failing is `ERR_INVALID_ARG_VALUE`, anything else
/// unsupported is `ERR_INVALID_ARG_TYPE` — and the caller has to pick the right
/// one because the message names the parameter. Returning the reason keeps the
/// throw in one place; throwing here as well would leave two exceptions in
/// flight, and the second would overwrite the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindRejection {
    /// A JavaScript type SQLite cannot store.
    WrongType,
    /// A `BigInt` outside the `i64` range.
    BigIntTooLarge,
}

/// One value a statement binds, or one column it reads.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// SQL `NULL`, from `null` or `undefined`.
    Null,
    /// A `Number` binding, which SQLite stores as a float.
    Float(f64),
    /// A `BigInt` binding, which SQLite stores as an integer.
    Integer(i64),
    /// A boolean, which SQLite stores as `1` or `0`.
    Boolean(bool),
    /// Text, as UTF-8 bytes. Held as bytes rather than a `String` because a
    /// JavaScript string can carry a lone surrogate, and `Utf8Value` in the C++
    /// encodes those as replacement characters rather than failing.
    Text(Vec<u8>),
    /// A blob.
    Blob(Vec<u8>),
}

/// Reads a `Value` from a JavaScript argument, or `None` when the kind is
/// rejected.
///
/// The order of the checks is `Statement::BindValue`'s: number, string, null or
/// undefined, buffer-like, boolean, bigint. It matters for a value that is both
/// — a `Number` wrapper object is an object *and* a number, but `IsNumber()` is
/// false for the wrapper and `IsArrayBufferView()` is false too, so it lands in
/// the reject branch exactly as in Node.
pub fn from_js<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<Value, BindRejection> {
    if value.is_number() {
        // `number_value`, not `int32_value`: a double keeps its fraction, and
        // SQLite decides INTEGER versus REAL from the binding call, so `1.5`
        // must go through `sqlite3_bind_double`.
        return match value.number_value(scope) {
            Some(number) => Ok(Value::Float(number)),
            None => Err(BindRejection::WrongType),
        };
    }
    if value.is_string() {
        return match v8::Local::<v8::String>::try_from(value) {
            Ok(text) => Ok(Value::Text(encode_utf8(scope, &text))),
            Err(_) => Err(BindRejection::WrongType),
        };
    }
    if value.is_null() || value.is_undefined() {
        return Ok(Value::Null);
    }
    if let Some(blob) = view_bytes(value) {
        return Ok(Value::Blob(blob));
    }
    if value.is_boolean() {
        return Ok(Value::Boolean(value.boolean_value(scope)));
    }
    if value.is_big_int() {
        let Ok(bigint) = v8::Local::<v8::BigInt>::try_from(value) else {
            return Err(BindRejection::WrongType);
        };
        let (number, lossless) = bigint.i64_value();
        if !lossless {
            // A BigInt that does not fit `i64` is a *value* problem, not a type
            // problem, and `BindValue` reports `ERR_INVALID_ARG_VALUE`. The
            // rejection is returned rather than thrown so the caller throws
            // exactly once, with the message naming this parameter.
            return Err(BindRejection::BigIntTooLarge);
        }
        return Ok(Value::Integer(number));
    }
    Err(BindRejection::WrongType)
}

/// Throws the error a rejected binding produces, choosing the code Node uses.
pub fn reject_binding(scope: &mut v8::PinScope<'_, '_>, index: i32, rejection: BindRejection) {
    match rejection {
        BindRejection::WrongType => errors::throw_type(
            scope,
            &format!("Provided value cannot be bound to SQLite parameter {index}."),
        ),
        BindRejection::BigIntTooLarge => errors::throw_coded(
            scope,
            "ERR_INVALID_ARG_VALUE",
            "BigInt value is too large to bind.",
        ),
    }
}

/// A copy of a buffer-like value's bytes.
///
/// Returns the owned bytes alongside their length. The copy is what makes the
/// result safe to use after a property getter has run: a getter can call
/// `buffer.resize(...)` or `structuredClone(buffer, { transfer })`, which
/// detaches the backing store and leaves any pointer into it dangling.
pub fn view_snapshot<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<(Vec<u8>, usize)> {
    let Some(bytes) = view_bytes(value) else {
        errors::throw_type(
            scope,
            "The \"buffer\" argument must be a Uint8Array or ArrayBuffer.",
        );
        return None;
    };
    let length = bytes.len();
    Some((bytes, length))
}

/// The bytes behind a `Buffer`, typed array, `DataView`, `ArrayBuffer` or
/// `SharedArrayBuffer`, or `None` when the value is none of those.
///
/// `IsArrayBufferView()`, `IsArrayBuffer()` and `IsSharedArrayBuffer()` are
/// three separate checks in the C++ and all three bind a blob, so a bare
/// `ArrayBuffer` and a windowed `DataView` both arrive whole here.
pub fn view_bytes<'s>(value: v8::Local<'s, v8::Value>) -> Option<Vec<u8>> {
    if value.is_array_buffer_view() {
        let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
        let length = view.byte_length();
        if length == 0 {
            return Some(Vec::new());
        }
        let data = view.data() as *const u8;
        if data.is_null() {
            return Some(Vec::new());
        }
        // SAFETY: `data` points at the view's own window into its backing
        // store, and `byte_length` is that window's length.
        Some(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
    } else if value.is_array_buffer() || value.is_shared_array_buffer() {
        let buffer = v8::Local::<v8::ArrayBuffer>::try_from(value).ok()?;
        let length = buffer.byte_length();
        if length == 0 {
            return Some(Vec::new());
        }
        let store = buffer.get_backing_store();
        let data = store.data().map(|pointer| pointer.as_ptr() as *const u8);
        let Some(data) = data else {
            return Some(Vec::new());
        };
        // SAFETY: `store` keeps the allocation alive for the copy, and
        // `byte_length` is its length.
        Some(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
    } else {
        None
    }
}

/// Encodes a V8 string as UTF-8, replacing lone surrogates the way `Utf8Value`
/// does.
pub fn encode_utf8(scope: &mut v8::PinScope<'_, '_>, text: &v8::Local<v8::String>) -> Vec<u8> {
    let length = text.utf8_length(scope);
    let mut buffer = vec![0u8; length];
    let written = text.write_utf8_v2(scope, &mut buffer, v8::WriteFlags::empty(), None);
    buffer.truncate(written);
    buffer
}

/// V8's maximum string length in UTF-16 code units, from
/// `v8::String::kMaxLength`.
///
/// A `TEXT` column can hold more than this — `hex()` doubles its input, so a
/// 128 MiB blob has a 256 MiB text form — and V8 cannot represent it. Node
/// throws `ERR_STRING_TOO_LONG` there, which
/// `pummel/test-sqlite-statement-too-long.js` asserts.
pub const MAX_STRING_LENGTH: usize = 0x1FFF_FFFF;

/// A JavaScript string from UTF-8 bytes.
///
/// SQLite hands back whatever bytes were stored, and a `TEXT` column can hold
/// bytes that are not valid UTF-8 if they were written by another tool. V8's
/// `NewFromUtf8` replaces them rather than failing, which is what Node's
/// `Utf8StringMaybeOneByte` does too, so a lossy conversion is the compatible
/// answer for the encoding.
///
/// The *length* is different: `String::new` returns `None` for a string past
/// `kMaxLength`, and returning `None` from here would make the caller report a
/// missing row instead of the real cause. So this throws the same
/// `ERR_STRING_TOO_LONG` Node does and returns `None`.
pub fn string_from_utf8<'s>(
    scope: &mut v8::PinScope<'s, '_, v8::Context>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::String>> {
    // A UTF-8 buffer's UTF-16 length is at most its byte length, so this is a
    // safe upper bound; a string that clears it may still be too long, which the
    // `String::new` result then reports.
    if bytes.len() > MAX_STRING_LENGTH {
        errors::throw_string_too_long(scope);
        return None;
    }
    let text = String::from_utf8_lossy(bytes);
    match v8::String::new(scope, &text) {
        Some(string) => Some(string),
        None => {
            errors::throw_string_too_long(scope);
            None
        }
    }
}

/// A `Uint8Array` over a fresh `ArrayBuffer` holding `bytes`.
///
/// The copy is deliberate: it is what `SQLITE_VALUE_TO_JS` does, and it means
/// the returned array does not alias SQLite's page cache, which is recycled on
/// the next `sqlite3_step`.
pub fn uint8_array<'s>(
    scope: &mut v8::PinScope<'s, '_, v8::Context>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Uint8Array>> {
    let buffer = v8::ArrayBuffer::new(scope, bytes.len());
    if !bytes.is_empty() {
        let store = buffer.get_backing_store();
        if let Some(data) = store.data() {
            // SAFETY: the backing store is exactly `bytes.len()` bytes, and the
            // destination was freshly allocated so the two cannot overlap.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    data.as_ptr() as *mut u8,
                    bytes.len(),
                );
            }
        }
    }
    v8::Uint8Array::new(scope, buffer, 0, bytes.len())
}

/// Reads column `index` of the row `statement` is positioned on.
///
/// Not `unsafe fn`: the handle is not caller-controlled in a way that could be
/// wrong. Every call site just positioned the statement with `sqlite3_step`, and
/// the index comes from `sqlite3_column_count` on the same statement. Marking it
/// `unsafe` would only push an `unsafe` block onto each of those call sites
/// without adding a check.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the statement handle is live and positioned by every caller"
)]
pub fn column_to_js<'s>(
    scope: &mut v8::PinScope<'s, '_, v8::Context>,
    statement: *mut ffi::sqlite3_stmt,
    index: i32,
    mode: IntMode,
) -> Option<v8::Local<'s, v8::Value>> {
    // SAFETY: `statement` is a live prepared statement positioned on a row, so
    // every accessor below is defined for `0 <= index < column_count`.
    unsafe {
        match ffi::sqlite3_column_type(statement, index) {
            ffi::SQLITE_INTEGER => {
                mode.to_value(scope, ffi::sqlite3_column_int64(statement, index))
            }
            ffi::SQLITE_FLOAT => {
                Some(v8::Number::new(scope, ffi::sqlite3_column_double(statement, index)).into())
            }
            ffi::SQLITE_TEXT => {
                let data = ffi::sqlite3_column_text(statement, index);
                let length = ffi::sqlite3_column_bytes(statement, index).max(0) as usize;
                if data.is_null() {
                    // SQLite returns a null pointer rather than an error, and
                    // the C++ returns Null for it.
                    return Some(v8::null(scope).into());
                }
                let bytes = std::slice::from_raw_parts(data, length);
                Some(string_from_utf8(scope, bytes)?.into())
            }
            ffi::SQLITE_BLOB => {
                let length = ffi::sqlite3_column_bytes(statement, index).max(0) as usize;
                let data = ffi::sqlite3_column_blob(statement, index) as *const u8;
                let bytes = if data.is_null() || length == 0 {
                    &[][..]
                } else {
                    std::slice::from_raw_parts(data, length)
                };
                Some(uint8_array(scope, bytes)?.into())
            }
            ffi::SQLITE_NULL => Some(v8::null(scope).into()),
            // `SQLITE_VALUE_TO_JS` has `UNREACHABLE("Bad SQLite value")` here.
            // Aborting the process over a value SQLite itself produced would be
            // worse than reporting it, so this throws instead.
            _ => {
                errors::throw_sqlite_message(scope, "Bad SQLite value", "Bad SQLite value", 0);
                None
            }
        }
    }
}

/// Reads one argument of a SQL function invocation.
///
/// Not `unsafe fn` for the same reason as [`column_to_js`]: the pointer is the
/// argument SQLite itself passed to the callback that calls this, valid for the
/// duration of that callback.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the value pointer is the one SQLite passed into the running callback"
)]
pub fn argument_to_js<'s>(
    scope: &mut v8::PinScope<'s, '_, v8::Context>,
    value: *mut ffi::sqlite3_value,
    mode: IntMode,
) -> Option<v8::Local<'s, v8::Value>> {
    // SAFETY: `value` is the argument pointer SQLite passed to this invocation
    // and is valid for its duration.
    unsafe {
        match ffi::sqlite3_value_type(value) {
            ffi::SQLITE_INTEGER => mode.to_value(scope, ffi::sqlite3_value_int64(value)),
            ffi::SQLITE_FLOAT => {
                Some(v8::Number::new(scope, ffi::sqlite3_value_double(value)).into())
            }
            ffi::SQLITE_TEXT => {
                let data = ffi::sqlite3_value_text(value);
                let length = ffi::sqlite3_value_bytes(value).max(0) as usize;
                if data.is_null() {
                    return Some(v8::null(scope).into());
                }
                let bytes = std::slice::from_raw_parts(data, length);
                Some(string_from_utf8(scope, bytes)?.into())
            }
            ffi::SQLITE_BLOB => {
                let length = ffi::sqlite3_value_bytes(value).max(0) as usize;
                let data = ffi::sqlite3_value_blob(value) as *const u8;
                let bytes = if data.is_null() || length == 0 {
                    &[][..]
                } else {
                    std::slice::from_raw_parts(data, length)
                };
                Some(uint8_array(scope, bytes)?.into())
            }
            ffi::SQLITE_NULL => Some(v8::null(scope).into()),
            _ => {
                errors::throw_sqlite_message(scope, "Bad SQLite value", "Bad SQLite value", 0);
                None
            }
        }
    }
}

/// `JSValueToSQLiteResult`: the value a SQL function returns.
///
/// The C++ converts `null`/`undefined`, numbers, strings, buffer-likes and
/// `BigInt`, rejects a `Promise` with a specific message, and rejects anything
/// else. A rejection becomes a SQLite error so the statement fails with that
/// text rather than silently returning NULL.
/// Not `unsafe fn`: `context` is the live invocation context SQLite passed to
/// the callback that calls this.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the context pointer is the one SQLite passed into the running callback"
)]
pub fn result_from_js(
    scope: &mut v8::PinScope<'_, '_>,
    context: *mut ffi::sqlite3_context,
    value: v8::Local<'_, v8::Value>,
) {
    if value.is_null_or_undefined() {
        // SAFETY: `context` is the live invocation context SQLite passed in.
        unsafe { ffi::sqlite3_result_null(context) };
    } else if value.is_number() {
        let number = value.number_value(scope).unwrap_or(0.0);
        unsafe { ffi::sqlite3_result_double(context, number) };
    } else if value.is_string() {
        if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
            let bytes = encode_utf8(scope, &text);
            // SAFETY: `SQLITE_TRANSIENT` makes SQLite copy the bytes before the
            // call returns, so `bytes` need not outlive it.
            unsafe {
                ffi::sqlite3_result_text64(
                    context,
                    bytes.as_ptr() as *const std::os::raw::c_char,
                    bytes.len() as u64,
                    ffi::SQLITE_TRANSIENT,
                    ffi::SQLITE_UTF8 as u8,
                )
            };
        }
    } else if let Some(bytes) = view_bytes(value) {
        // SAFETY: as above; `SQLITE_TRANSIENT` copies.
        unsafe {
            ffi::sqlite3_result_blob64(
                context,
                bytes.as_ptr() as *const std::os::raw::c_void,
                bytes.len() as u64,
                ffi::SQLITE_TRANSIENT,
            )
        };
    } else if value.is_big_int() {
        if let Ok(bigint) = v8::Local::<v8::BigInt>::try_from(value) {
            let (number, lossless) = bigint.i64_value();
            if lossless {
                unsafe { ffi::sqlite3_result_int64(context, number) };
            } else {
                result_error(context, "BigInt value is too large for SQLite");
            }
        }
    } else if value.is_promise() {
        result_error(
            context,
            "Asynchronous user-defined functions are not supported",
        );
    } else {
        result_error(
            context,
            "Returned JavaScript value cannot be converted to a SQLite value",
        );
    }
}

/// `sqlite3_result_error` with a message this crate owns.
fn result_error(context: *mut ffi::sqlite3_context, message: &str) {
    // SAFETY: the message outlives the call and SQLite copies `len` bytes of
    // it; `context` is the live invocation context.
    unsafe {
        ffi::sqlite3_result_error(
            context,
            message.as_ptr() as *const std::os::raw::c_char,
            message.len() as i32,
        )
    };
}
