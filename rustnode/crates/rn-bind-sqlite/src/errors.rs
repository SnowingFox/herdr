//! The error objects `node:sqlite` throws.
//!
//! Node builds these with `CreateSQLiteErrorImpl` in `src/node_sqlite.cc`: an
//! `Error` — not a `TypeError` — carrying `code: 'ERR_SQLITE_ERROR'`, plus
//! `errcode` and `errstr` when the message came from SQLite itself. The two
//! extra fields are observable and Node's own tests read them, so they are part
//! of the contract rather than decoration.
//!
//! The other codes here (`ERR_INVALID_STATE`, `ERR_INVALID_ARG_TYPE`,
//! `ERR_OUT_OF_RANGE`, `ERR_ILLEGAL_CONSTRUCTOR`) are the standard Node error
//! codes. They are thrown from Rust because the checks live in the C++ layer
//! Node compiles, and `lib/**` expects the exact `code` string:
//! `assert.throws(..., { code: 'ERR_INVALID_STATE' })` compares it literally.

use std::os::raw::c_char;

use rn_v8_sys::v8;

use crate::ffi;

/// `Environment::err_sqlite_error_string()`.
pub const ERR_SQLITE_ERROR: &str = "ERR_SQLITE_ERROR";

/// Throws `exception` after attaching a `code` property.
///
/// `to_object` rather than `Local::<Object>::try_from`: V8's Rust binding
/// refuses the cast for a `TypeError`, whose constructor is itself an object, so
/// `try_from` answers `Err` and the `code` silently never lands. Every
/// `assert.throws(fn, { code })` in Node's suite would then fail with
/// `code: undefined` and no hint why.
fn throw_with_code<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    exception: v8::Local<'s, v8::Value>,
    code: &str,
) {
    if let Some(object) = exception.to_object(scope) {
        if let (Some(name), Some(value)) =
            (v8::String::new(scope, "code"), v8::String::new(scope, code))
        {
            let _ = object.set(scope, name.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Throws an `Error` with `code`, the shape `THROW_ERR_INVALID_STATE` has.
pub fn throw_coded(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    throw_with_code(scope, exception, code);
}

/// Throws a `TypeError` carrying `code: 'ERR_INVALID_ARG_TYPE'`.
///
/// The `code` is what `assert.throws(fn, { code: 'ERR_INVALID_ARG_TYPE' })`
/// compares, and Node's own `ERR_INVALID_ARG_TYPE` is a `TypeError` with
/// exactly this code.
pub fn throw_type(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    throw_with_code(scope, exception, "ERR_INVALID_ARG_TYPE");
}

/// Throws a `RangeError` carrying `code: 'ERR_OUT_OF_RANGE'`.
pub fn throw_range(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::range_error(scope, text);
    throw_with_code(scope, exception, "ERR_OUT_OF_RANGE");
}

/// Throws `ERR_STRING_TOO_LONG`, the code V8 reports when a value cannot fit a
/// JavaScript string.
///
/// `NullableSQLiteStringToValue` and `SQLITE_VALUE_TO_JS` both raise it rather
/// than truncating, because a truncated result is a wrong answer that looks
/// right.
pub fn throw_string_too_long(scope: &mut v8::PinScope<'_, '_>) {
    throw_coded(
        scope,
        "ERR_STRING_TOO_LONG",
        "Cannot create a string longer than 0x1fffffe8 characters",
    );
}

/// `THROW_AND_RETURN_ON_BAD_STATE` for a *good* condition.
///
/// Node writes `THROW_AND_RETURN_ON_BAD_STATE(env, !db->IsOpen(), "...")`, where
/// the argument is the bad state. Passing the good condition reads better and
/// removes a `!` from every call site. Returns `true` when the caller may
/// continue.
pub fn require(scope: &mut v8::PinScope<'_, '_>, good: bool, message: &str) -> bool {
    if good {
        return true;
    }
    throw_coded(scope, "ERR_INVALID_STATE", message);
    false
}

/// The `Error` a SQLite failure becomes, carrying `errcode` and `errstr`.
///
/// `node_sqlite.cc` builds this from `sqlite3_errmsg` and
/// `sqlite3_extended_errcode`, with `sqlite3_errstr` of the extended code as
/// the generic description.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "every caller holds a live, open connection it just failed on"
)]
pub fn throw_sqlite(scope: &mut v8::PinScope<'_, '_>, db: *mut ffi::sqlite3) {
    if db.is_null() {
        throw_sqlite_message(scope, "unknown error", "unknown error", 0);
        return;
    }
    // SAFETY: `db` is a live connection this binding opened and has not closed;
    // both accessors only read connection state, and `errstr` returns static
    // text for the code.
    unsafe {
        let message = c_string(ffi::sqlite3_errmsg(db));
        let code = ffi::sqlite3_extended_errcode(db);
        let errstr = c_string(ffi::sqlite3_errstr(code));
        throw_sqlite_message(scope, &message, &errstr, code);
    }
}

/// The message-only form: `CreateSQLiteError(isolate, "Failed to ...")`.
pub fn throw_sqlite_message(
    scope: &mut v8::PinScope<'_, '_>,
    message: &str,
    errstr: &str,
    errcode: i32,
) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    if let Some(object) = exception.to_object(scope) {
        if let (Some(key), Some(code)) = (
            v8::String::new(scope, "code"),
            v8::String::new(scope, ERR_SQLITE_ERROR),
        ) {
            let _ = object.set(scope, key.into(), code.into());
        }
        if let Some(key) = v8::String::new(scope, "errcode") {
            let _ = object.set(scope, key.into(), v8::Integer::new(scope, errcode).into());
        }
        if let (Some(key), Some(value)) = (
            v8::String::new(scope, "errstr"),
            v8::String::new(scope, errstr),
        ) {
            let _ = object.set(scope, key.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Reads a NUL-terminated C string, mapping null to the empty string.
///
/// # Safety
///
/// `pointer` must be null or point at a NUL-terminated string that stays alive
/// for the duration of the call.
pub unsafe fn c_string(pointer: *const c_char) -> String {
    if pointer.is_null() {
        return String::new();
    }
    std::ffi::CStr::from_ptr(pointer)
        .to_string_lossy()
        .into_owned()
}
