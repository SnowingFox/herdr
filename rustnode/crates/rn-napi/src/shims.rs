//! The Node-API entry points an addon links against.
//!
//! Each function has exactly the signature its declaration in
//! `src/js_native_api.h` or `src/node_api.h` has, and is exported under that name
//! from the rustnode binary (see `symbols.rs` and `build.rs`).
//!
//! Three rules hold for every shim, all taken from Node's `js_native_api_v8.cc`:
//!
//! * **A `napi_value` in is a handle into the caller's scope.** It is only
//!   dereferenced inside [`crate::values::in_scope`], and never stored.
//! * **A failure returns a `napi_status` and records it on the environment.**
//!   No shim panics, and none throws unless the addon called a throwing entry
//!   point, so `NODE_API_CALL` in the addon sees the status it expects and can
//!   build its own error.
//! * **JavaScript can run inside a shim.** `napi_call_function`, a property
//!   getter, a coercion — all can re-enter this runtime, so no shim holds a `&mut`
//!   into the environment across one.
//!
//! # The shape of a shim
//!
//! Every shim is [`run`], which resolves the current scope once and turns the
//! body's `Result` into a status. That keeps the reference implementation's logic
//! visible in the body instead of buried under option plumbing.
//!
//! # Safety
//!
//! Every function in this module is `unsafe extern "C"` for one reason and the same
//! reason, so it is stated once here rather than 57 times below.
//!
//! **The caller is the addon.** This module is the compiled-in side of the Node-API
//! ABI. A C caller passes raw pointers whose validity these functions cannot check: a
//! `napi_value` must be a live handle from the current scope, an out parameter must be
//! writable for the type in the signature, a `const char*` must be NUL-terminated (or
//! paired with a length the caller can vouch for), and the array behind a
//! `(count, pointer)` pair must hold `count` entries. No Rust type can express those
//! obligations, which is exactly why Node-API is a C ABI in the first place.
//!
//! Two things this module does guarantee and does check:
//!
//! * **A null out parameter is never written.** It is either `napi_invalid_arg` or,
//!   where Node treats the parameter as optional, a success with nowhere to write.
//! * **A null `napi_env` or `napi_value` is rejected before any dereference**, so a
//!   malformed call reports a status rather than faulting.
//!
//! The per-function `# Safety` sections clippy asks for would therefore all read
//! identically; the one that matters — "the addon upholds the C contract in
//! `node_api.h`" — is the module contract. `clippy::missing_safety_doc` is allowed
//! here for that reason, not to hide a warning.
#![allow(clippy::missing_safety_doc)]

use std::ffi::c_void;
use std::os::raw::c_char;

use rn_v8_sys::v8;

use crate::abi::{
    NapiCallbackInfo, NapiEnv, NapiFinalize, NapiRef, NapiStatus, NapiValue, NapiValueType,
    NAPI_DEFAULT_MODULE_API_VERSION, NAPI_SUPPORTED_VERSION_MAX,
};
use crate::env::{env_from, Env};
use crate::values::{arg, in_scope, to_napi, type_of};

/// Records `status` on the environment and returns it.
fn status(env: *mut NapiEnv, value: NapiStatus) -> NapiStatus {
    // SAFETY: `env` is either null or a pointer this crate created.
    if let Some(environment) = unsafe { env_from(env) } {
        environment.set_last_error(value);
    }
    value
}

/// Runs a shim body inside the current scope and turns its result into a status.
///
/// `write` is called only on success, with the body's value. That split keeps
/// "the operation succeeded" and "there was somewhere to put the answer" from
/// being conflated: a null out parameter is a success with nowhere to write, which
/// is how Node treats an optional out.
fn run<'s, T>(
    env: *mut NapiEnv,
    write: impl FnOnce(T),
    body: impl FnOnce(&mut v8::PinScope<'s, '_>) -> Result<T, NapiStatus>,
) -> NapiStatus {
    match in_scope(body) {
        None => status(env, NapiStatus::HandleScopeMismatch),
        Some(Ok(value)) => {
            write(value);
            status(env, NapiStatus::Ok)
        }
        Some(Err(failure)) => status(env, failure),
    }
}

/// A shim that returns nothing on success.
fn run_unit(
    env: *mut NapiEnv,
    body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> Result<(), NapiStatus>,
) -> NapiStatus {
    run(env, |()| {}, body)
}

/// Writes one `napi_value` through an out pointer, ignoring a null.
///
/// # Safety
///
/// `out` must be null or writable for one `*mut NapiValue`.
unsafe fn store(out: *mut *mut NapiValue, value: *mut NapiValue) {
    if !out.is_null() {
        // SAFETY: caller guarantees writability.
        unsafe { out.write(value) };
    }
}

/// Resolves a `napi_value` that must be an object.
///
/// # Safety
///
/// `handle` must be a handle from the current scope.
unsafe fn as_object<'s>(handle: *mut NapiValue) -> Result<v8::Local<'s, v8::Object>, NapiStatus> {
    if handle.is_null() {
        return Err(NapiStatus::InvalidArg);
    }
    // SAFETY: caller guarantees the handle is from the current scope.
    let local = unsafe { arg(handle) }.ok_or(NapiStatus::InvalidArg)?;
    v8::Local::<v8::Object>::try_from(local).map_err(|_| NapiStatus::ObjectExpected)
}

/// Resolves a `napi_value` that must be a function.
///
/// # Safety
///
/// `handle` must be a handle from the current scope.
unsafe fn as_function<'s>(
    handle: *mut NapiValue,
) -> Result<v8::Local<'s, v8::Function>, NapiStatus> {
    if handle.is_null() {
        return Err(NapiStatus::InvalidArg);
    }
    // SAFETY: caller guarantees the handle is from the current scope.
    let local = unsafe { arg(handle) }.ok_or(NapiStatus::InvalidArg)?;
    v8::Local::<v8::Function>::try_from(local).map_err(|_| NapiStatus::FunctionExpected)
}

/// Resolves a `napi_value` that must be a string.
///
/// # Safety
///
/// `handle` must be a handle from the current scope.
unsafe fn as_string<'s>(handle: *mut NapiValue) -> Result<v8::Local<'s, v8::String>, NapiStatus> {
    if handle.is_null() {
        return Err(NapiStatus::InvalidArg);
    }
    // SAFETY: caller guarantees the handle is from the current scope.
    let local = unsafe { arg(handle) }.ok_or(NapiStatus::InvalidArg)?;
    v8::Local::<v8::String>::try_from(local).map_err(|_| NapiStatus::StringExpected)
}

/// Resolves a `napi_value` that must be a name (a string or a symbol).
///
/// # Safety
///
/// `handle` must be a handle from the current scope.
unsafe fn as_name<'s>(handle: *mut NapiValue) -> Result<v8::Local<'s, v8::Name>, NapiStatus> {
    if handle.is_null() {
        return Err(NapiStatus::InvalidArg);
    }
    // SAFETY: caller guarantees the handle is from the current scope.
    let local = unsafe { arg(handle) }.ok_or(NapiStatus::InvalidArg)?;
    v8::Local::<v8::Name>::try_from(local).map_err(|_| NapiStatus::NameExpected)
}

/// Resolves any `napi_value`.
///
/// # Safety
///
/// `handle` must be a handle from the current scope.
unsafe fn as_value<'s>(handle: *mut NapiValue) -> Result<v8::Local<'s, v8::Value>, NapiStatus> {
    if handle.is_null() {
        return Err(NapiStatus::InvalidArg);
    }
    // SAFETY: caller guarantees the handle is from the current scope.
    unsafe { arg(handle) }.ok_or(NapiStatus::InvalidArg)
}

/// Reads `length` bytes from a C string, or to the NUL when the addon passed
/// `NAPI_AUTO_LENGTH` (`SIZE_MAX`).
///
/// Returns `None` for a null pointer with an explicit length: reading that many
/// bytes from nothing is a caller bug, and Node reports the invalid argument
/// rather than crashing.
fn read_bytes(str: *const c_char, length: usize) -> Option<Vec<u8>> {
    if str.is_null() {
        return if length == usize::MAX {
            Some(Vec::new())
        } else {
            None
        };
    }
    if length == usize::MAX {
        // SAFETY: the addon passed a NUL-terminated string.
        let text = unsafe { std::ffi::CStr::from_ptr(str) };
        Some(text.to_bytes().to_vec())
    } else {
        // SAFETY: Node-API's contract is that `str` is readable for `length`
        // bytes for the duration of the call.
        Some(unsafe { std::slice::from_raw_parts(str.cast::<u8>(), length) }.to_vec())
    }
}

/// Reads a UTF-8 C string argument, with `NAPI_AUTO_LENGTH` support.
fn read_text(str: *const c_char, length: usize) -> Option<String> {
    read_bytes(str, length).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// `Maybe<bool>` from a V8 assignment, as a status.
fn assigned(result: Option<bool>) -> Result<(), NapiStatus> {
    match result {
        Some(true) => Ok(()),
        // `None` is a V8 exception; `Some(false)` is a refused assignment. Node
        // reports both as `napi_generic_failure` from the assignment shims.
        Some(false) | None => Err(NapiStatus::GenericFailure),
    }
}

// ---------------------------------------------------------------------------
// Errors and identity
// ---------------------------------------------------------------------------

#[export_name = "napi_get_last_error_info"]
pub unsafe extern "C" fn napi_get_last_error_info(
    env: *mut NapiEnv,
    result: *mut *const crate::abi::NapiExtendedErrorInfo,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    // SAFETY: the caller passed a writable slot for one pointer.
    unsafe { result.write(environment.last_error_info()) };
    NapiStatus::Ok
}

#[export_name = "napi_get_undefined"]
pub unsafe extern "C" fn napi_get_undefined(
    env: *mut NapiEnv,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |value| unsafe { store(result, value) },
        |scope| Ok(to_napi(v8::undefined(scope).into())),
    )
}

#[export_name = "napi_get_null"]
pub unsafe extern "C" fn napi_get_null(
    env: *mut NapiEnv,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |value| unsafe { store(result, value) },
        |scope| Ok(to_napi(v8::null(scope).into())),
    )
}

#[export_name = "napi_get_global"]
pub unsafe extern "C" fn napi_get_global(
    env: *mut NapiEnv,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |value| unsafe { store(result, value) },
        |scope| {
            let global = scope.get_current_context().global(scope);
            Ok(to_napi(global.into()))
        },
    )
}

#[export_name = "napi_get_boolean"]
pub unsafe extern "C" fn napi_get_boolean(
    env: *mut NapiEnv,
    value: bool,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |value| unsafe { store(result, value) },
        |scope| {
            let boolean: v8::Local<v8::Value> = v8::Boolean::new(scope, value).into();
            Ok(to_napi(boolean))
        },
    )
}

// ---------------------------------------------------------------------------
// Creating primitives and containers
// ---------------------------------------------------------------------------

#[export_name = "napi_create_object"]
pub unsafe extern "C" fn napi_create_object(
    env: *mut NapiEnv,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |value| unsafe { store(result, value) },
        |scope| {
            let object: v8::Local<v8::Value> = v8::Object::new(scope).into();
            Ok(to_napi(object))
        },
    )
}

#[export_name = "napi_create_array"]
pub unsafe extern "C" fn napi_create_array(
    env: *mut NapiEnv,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |value| unsafe { store(result, value) },
        |scope| {
            let array: v8::Local<v8::Value> = v8::Array::new(scope, 0).into();
            Ok(to_napi(array))
        },
    )
}

#[export_name = "napi_create_array_with_length"]
pub unsafe extern "C" fn napi_create_array_with_length(
    env: *mut NapiEnv,
    length: usize,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // V8 takes an `int32_t`; Node rejects a length that does not fit rather than
    // truncating it into a silently shorter array.
    let Ok(length) = i32::try_from(length) else {
        return status(env, NapiStatus::InvalidArg);
    };
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |value| unsafe { store(result, value) },
        |scope| {
            let array: v8::Local<v8::Value> = v8::Array::new(scope, length).into();
            Ok(to_napi(array))
        },
    )
}

#[export_name = "napi_create_double"]
pub unsafe extern "C" fn napi_create_double(
    env: *mut NapiEnv,
    value: f64,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            let number: v8::Local<v8::Value> = v8::Number::new(scope, value).into();
            Ok(to_napi(number))
        },
    )
}

#[export_name = "napi_create_int32"]
pub unsafe extern "C" fn napi_create_int32(
    env: *mut NapiEnv,
    value: i32,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            let number: v8::Local<v8::Value> = v8::Integer::new(scope, value).into();
            Ok(to_napi(number))
        },
    )
}

#[export_name = "napi_create_uint32"]
pub unsafe extern "C" fn napi_create_uint32(
    env: *mut NapiEnv,
    value: u32,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            let number: v8::Local<v8::Value> = v8::Integer::new_from_unsigned(scope, value).into();
            Ok(to_napi(number))
        },
    )
}

#[export_name = "napi_create_int64"]
pub unsafe extern "C" fn napi_create_int64(
    env: *mut NapiEnv,
    value: i64,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            // `napi_create_int64` produces a JS number, not a BigInt, so the
            // value goes through a double exactly as it does in Node.
            let number: v8::Local<v8::Value> = v8::Number::new(scope, value as f64).into();
            Ok(to_napi(number))
        },
    )
}

#[export_name = "napi_create_string_utf8"]
pub unsafe extern "C" fn napi_create_string_utf8(
    env: *mut NapiEnv,
    str: *const c_char,
    length: usize,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    let Some(bytes) = read_bytes(str, length) else {
        return status(env, NapiStatus::InvalidArg);
    };
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            let text = v8::String::new_from_utf8(scope, &bytes, v8::NewStringType::Normal)
                .ok_or(NapiStatus::GenericFailure)?;
            Ok(to_napi(text.into()))
        },
    )
}

#[export_name = "napi_create_string_latin1"]
pub unsafe extern "C" fn napi_create_string_latin1(
    env: *mut NapiEnv,
    str: *const c_char,
    length: usize,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    let Some(bytes) = read_bytes(str, length) else {
        return status(env, NapiStatus::InvalidArg);
    };
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            // Latin-1 is one byte per code point up to U+00FF, which is exactly
            // what V8's one-byte string constructor takes.
            let text = v8::String::new_from_one_byte(scope, &bytes, v8::NewStringType::Normal)
                .ok_or(NapiStatus::GenericFailure)?;
            Ok(to_napi(text.into()))
        },
    )
}

#[export_name = "napi_create_function"]
pub unsafe extern "C" fn napi_create_function(
    env: *mut NapiEnv,
    name: *const c_char,
    length: usize,
    callback: crate::abi::NapiCallback,
    data: *mut c_void,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() || callback.is_none() {
        return status(env, NapiStatus::InvalidArg);
    }
    let Some(name_text) = read_text(name, length) else {
        return status(env, NapiStatus::InvalidArg);
    };
    let boxed = crate::callback::boxed_callback_data(callback, data, env.cast::<Env>());
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            let function = crate::callback::build_function(scope, &name_text, boxed, 0)
                .ok_or(NapiStatus::GenericFailure)?;
            Ok(to_napi(function.into()))
        },
    )
}

// ---------------------------------------------------------------------------
// Reading values
// ---------------------------------------------------------------------------

#[export_name = "napi_typeof"]
pub unsafe extern "C" fn napi_typeof(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    result: *mut NapiValueType,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one enum.
        |kind| unsafe { result.write(kind) },
        // SAFETY: the handle comes from the current scope.
        |_| unsafe { as_value(value) }.map(|local| type_of(&local)),
    )
}

#[export_name = "napi_get_value_double"]
pub unsafe extern "C" fn napi_get_value_double(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    result: *mut f64,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one double.
        |number| unsafe { result.write(number) },
        |_| {
            // SAFETY: the handle comes from the current scope.
            let local = unsafe { as_value(value) }?;
            let number =
                v8::Local::<v8::Number>::try_from(local).map_err(|_| NapiStatus::NumberExpected)?;
            Ok(number.value())
        },
    )
}

#[export_name = "napi_get_value_int32"]
pub unsafe extern "C" fn napi_get_value_int32(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    result: *mut i32,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one i32.
        |number| unsafe { result.write(number) },
        |scope| {
            // SAFETY: the handle comes from the current scope.
            let local = unsafe { as_value(value) }?;
            let number =
                v8::Local::<v8::Number>::try_from(local).map_err(|_| NapiStatus::NumberExpected)?;
            number.int32_value(scope).ok_or(NapiStatus::NumberExpected)
        },
    )
}

#[export_name = "napi_get_value_uint32"]
pub unsafe extern "C" fn napi_get_value_uint32(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    result: *mut u32,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one u32.
        |number| unsafe { result.write(number) },
        |scope| {
            // SAFETY: the handle comes from the current scope.
            let local = unsafe { as_value(value) }?;
            let number =
                v8::Local::<v8::Number>::try_from(local).map_err(|_| NapiStatus::NumberExpected)?;
            number.uint32_value(scope).ok_or(NapiStatus::NumberExpected)
        },
    )
}

#[export_name = "napi_get_value_int64"]
pub unsafe extern "C" fn napi_get_value_int64(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    result: *mut i64,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one i64.
        |number| unsafe { result.write(number) },
        |scope| {
            // SAFETY: the handle comes from the current scope.
            let local = unsafe { as_value(value) }?;
            let number =
                v8::Local::<v8::Number>::try_from(local).map_err(|_| NapiStatus::NumberExpected)?;
            number
                .integer_value(scope)
                .ok_or(NapiStatus::NumberExpected)
        },
    )
}

#[export_name = "napi_get_value_bool"]
pub unsafe extern "C" fn napi_get_value_bool(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    result: *mut bool,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one bool.
        |boolean| unsafe { result.write(boolean) },
        |_| {
            // SAFETY: the handle comes from the current scope.
            let local = unsafe { as_value(value) }?;
            let boolean = v8::Local::<v8::Boolean>::try_from(local)
                .map_err(|_| NapiStatus::BooleanExpected)?;
            Ok(boolean.is_true())
        },
    )
}

/// The shared body of the two `napi_get_value_string_*` entries.
///
/// Node's contract, reproduced exactly: with no buffer the caller is asking for
/// the length and must supply `result`; with a buffer of zero bytes there is
/// nowhere to write, so the copied length is zero.
///
/// # Safety
///
/// `buf` must be null or writable for `bufsize` bytes.
unsafe fn copy_string_out(
    env: *mut NapiEnv,
    bytes: Vec<u8>,
    buf: *mut c_char,
    bufsize: usize,
    result: *mut usize,
) -> NapiStatus {
    if buf.is_null() {
        if result.is_null() {
            return status(env, NapiStatus::InvalidArg);
        }
        // SAFETY: the caller passed a writable slot for one usize.
        unsafe { result.write(bytes.len()) };
        return status(env, NapiStatus::Ok);
    }
    if bufsize == 0 {
        if !result.is_null() {
            // SAFETY: the caller passed a writable slot for one usize.
            unsafe { result.write(0) };
        }
        return status(env, NapiStatus::Ok);
    }
    // `bufsize - 1` bytes plus a NUL terminator, which is what Node's
    // `WriteUtf8V2(bufsize - 1)` followed by an explicit terminator amounts to.
    let copied = bytes.len().min(bufsize - 1);
    // SAFETY: the caller guarantees `buf` is writable for `bufsize` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), copied);
        buf.add(copied).write(0);
    }
    if !result.is_null() {
        // SAFETY: the caller passed a writable slot for one usize.
        unsafe { result.write(copied) };
    }
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_get_value_string_utf8"]
pub unsafe extern "C" fn napi_get_value_string_utf8(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    buf: *mut c_char,
    bufsize: usize,
    result: *mut usize,
) -> NapiStatus {
    if value.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    let bytes = in_scope(|scope| {
        // SAFETY: the handle comes from the current scope.
        let string = unsafe { as_string(value) }.ok()?;
        let mut owned = std::string::String::new();
        string.write_utf8_into(scope, &mut owned);
        Some(owned.into_bytes())
    })
    .ok_or(NapiStatus::HandleScopeMismatch)
    .and_then(|bytes| bytes.ok_or(NapiStatus::StringExpected));
    let Ok(bytes) = bytes else {
        return status(env, bytes.err().unwrap_or(NapiStatus::GenericFailure));
    };
    // SAFETY: the caller's buffer contract is `napi_get_value_string_utf8`'s.
    unsafe { copy_string_out(env, bytes, buf, bufsize, result) }
}

#[export_name = "napi_get_value_string_latin1"]
pub unsafe extern "C" fn napi_get_value_string_latin1(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    buf: *mut c_char,
    bufsize: usize,
    result: *mut usize,
) -> NapiStatus {
    if value.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    let bytes = in_scope(|scope| {
        // SAFETY: the handle comes from the current scope.
        let string = unsafe { as_string(value) }.ok()?;
        let length = string.length();
        let mut latin1 = vec![0u8; length];
        // One byte per UTF-16 code unit, truncating above 0xFF, which is what V8's
        // one-byte write does and what Node returns for this entry point.
        string.write_one_byte_v2(scope, 0, &mut latin1, v8::WriteFlags::default());
        Some(latin1)
    })
    .ok_or(NapiStatus::HandleScopeMismatch)
    .and_then(|bytes| bytes.ok_or(NapiStatus::StringExpected));
    let Ok(bytes) = bytes else {
        return status(env, bytes.err().unwrap_or(NapiStatus::GenericFailure));
    };
    // SAFETY: the caller's buffer contract is `napi_get_value_string_latin1`'s.
    unsafe { copy_string_out(env, bytes, buf, bufsize, result) }
}

#[export_name = "napi_is_array"]
pub unsafe extern "C" fn napi_is_array(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    result: *mut bool,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one bool.
        |is_array| unsafe { result.write(is_array) },
        // SAFETY: the handle comes from the current scope.
        |_| unsafe { as_value(value) }.map(|local| local.is_array()),
    )
}

#[export_name = "napi_get_array_length"]
pub unsafe extern "C" fn napi_get_array_length(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    result: *mut u32,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one u32.
        |length| unsafe { result.write(length) },
        |_| {
            // SAFETY: the handle comes from the current scope.
            let local = unsafe { as_value(value) }?;
            let array =
                v8::Local::<v8::Array>::try_from(local).map_err(|_| NapiStatus::ArrayExpected)?;
            Ok(array.length())
        },
    )
}

#[export_name = "napi_is_error"]
pub unsafe extern "C" fn napi_is_error(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    result: *mut bool,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one bool.
        |is_error| unsafe { result.write(is_error) },
        // SAFETY: the handle comes from the current scope.
        |_| unsafe { as_value(value) }.map(|local| is_error_like(&local)),
    )
}

/// Whether a value is an `Error`, matching `napi_is_error`.
///
/// `is_native_error` is V8's check for an object that inherits from
/// `Error.prototype`, which is the same predicate Node's `napi_is_error` uses
/// (`value->IsNativeError()`), so a user-defined `class X extends Error` is
/// included and a plain object named "Error" is not.
pub(crate) fn is_error_like(local: &v8::Local<'_, v8::Value>) -> bool {
    local.is_native_error()
}

// ---------------------------------------------------------------------------
// Properties and elements
// ---------------------------------------------------------------------------

#[export_name = "napi_set_named_property"]
pub unsafe extern "C" fn napi_set_named_property(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    name: *const c_char,
    value: *mut NapiValue,
) -> NapiStatus {
    if object.is_null() || name.is_null() || value.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run_unit(env, |scope| {
        // SAFETY: both handles come from the current scope.
        let object = unsafe { as_object(object) }?;
        let value = unsafe { as_value(value) }?;
        let key = v8::String::new(scope, &crate::env::c_string(name))
            .ok_or(NapiStatus::GenericFailure)?;
        assigned(object.set(scope, key.into(), value))
    })
}

#[export_name = "napi_get_named_property"]
pub unsafe extern "C" fn napi_get_named_property(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    name: *const c_char,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if object.is_null() || name.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            // SAFETY: the handle comes from the current scope.
            let object = unsafe { as_object(object) }?;
            let key = v8::String::new(scope, &crate::env::c_string(name))
                .ok_or(NapiStatus::GenericFailure)?;
            let value = object
                .get(scope, key.into())
                .ok_or(NapiStatus::GenericFailure)?;
            Ok(to_napi(value))
        },
    )
}

#[export_name = "napi_has_named_property"]
pub unsafe extern "C" fn napi_has_named_property(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    name: *const c_char,
    result: *mut bool,
) -> NapiStatus {
    if object.is_null() || name.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one bool.
        |has| unsafe { result.write(has) },
        |scope| {
            // SAFETY: the handle comes from the current scope.
            let object = unsafe { as_object(object) }?;
            let key = v8::String::new(scope, &crate::env::c_string(name))
                .ok_or(NapiStatus::GenericFailure)?;
            object
                .has(scope, key.into())
                .ok_or(NapiStatus::GenericFailure)
        },
    )
}

#[export_name = "napi_set_element"]
pub unsafe extern "C" fn napi_set_element(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    index: u32,
    value: *mut NapiValue,
) -> NapiStatus {
    if object.is_null() || value.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run_unit(env, |scope| {
        // SAFETY: both handles come from the current scope.
        let object = unsafe { as_object(object) }?;
        let value = unsafe { as_value(value) }?;
        assigned(object.set_index(scope, index, value))
    })
}

#[export_name = "napi_get_element"]
pub unsafe extern "C" fn napi_get_element(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    index: u32,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if object.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            // SAFETY: the handle comes from the current scope.
            let object = unsafe { as_object(object) }?;
            let value = object
                .get_index(scope, index)
                .ok_or(NapiStatus::GenericFailure)?;
            Ok(to_napi(value))
        },
    )
}

#[export_name = "napi_has_element"]
pub unsafe extern "C" fn napi_has_element(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    index: u32,
    result: *mut bool,
) -> NapiStatus {
    if object.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one bool.
        |has| unsafe { result.write(has) },
        |scope| {
            // SAFETY: the handle comes from the current scope.
            let object = unsafe { as_object(object) }?;
            object
                .has_index(scope, index)
                .ok_or(NapiStatus::GenericFailure)
        },
    )
}

#[export_name = "napi_set_property"]
pub unsafe extern "C" fn napi_set_property(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    key: *mut NapiValue,
    value: *mut NapiValue,
) -> NapiStatus {
    if object.is_null() || key.is_null() || value.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run_unit(env, |scope| {
        // SAFETY: all three handles come from the current scope.
        let object = unsafe { as_object(object) }?;
        let key = unsafe { as_name(key) }?;
        let value = unsafe { as_value(value) }?;
        assigned(object.set(scope, key.into(), value))
    })
}

#[export_name = "napi_get_property"]
pub unsafe extern "C" fn napi_get_property(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    key: *mut NapiValue,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if object.is_null() || key.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            // SAFETY: both handles come from the current scope.
            let object = unsafe { as_object(object) }?;
            let key = unsafe { as_name(key) }?;
            let value = object
                .get(scope, key.into())
                .ok_or(NapiStatus::GenericFailure)?;
            Ok(to_napi(value))
        },
    )
}

#[export_name = "napi_has_property"]
pub unsafe extern "C" fn napi_has_property(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    key: *mut NapiValue,
    result: *mut bool,
) -> NapiStatus {
    if object.is_null() || key.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot for one bool.
        |has| unsafe { result.write(has) },
        |scope| {
            // SAFETY: both handles come from the current scope.
            let object = unsafe { as_object(object) }?;
            let key = unsafe { as_name(key) }?;
            object
                .has(scope, key.into())
                .ok_or(NapiStatus::GenericFailure)
        },
    )
}

#[export_name = "napi_delete_property"]
pub unsafe extern "C" fn napi_delete_property(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    key: *mut NapiValue,
    result: *mut bool,
) -> NapiStatus {
    if object.is_null() || key.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        |deleted| {
            // `result` is optional in Node: a caller that only wants the
            // deletion does not have to read it.
            if !result.is_null() {
                // SAFETY: the caller declared a writable slot or null.
                unsafe { result.write(deleted) };
            }
        },
        |scope| {
            // SAFETY: both handles come from the current scope.
            let object = unsafe { as_object(object) }?;
            let key = unsafe { as_name(key) }?;
            object
                .delete(scope, key.into())
                .ok_or(NapiStatus::GenericFailure)
        },
    )
}

#[export_name = "napi_get_prototype"]
pub unsafe extern "C" fn napi_get_prototype(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if object.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    run(
        env,
        // SAFETY: the caller passed a writable slot.
        |handle| unsafe { store(result, handle) },
        |scope| {
            // SAFETY: the handle comes from the current scope.
            let object = unsafe { as_object(object) }?;
            let prototype = object
                .get_prototype(scope)
                .ok_or(NapiStatus::GenericFailure)?;
            Ok(to_napi(prototype))
        },
    )
}

#[export_name = "napi_define_properties"]
pub unsafe extern "C" fn napi_define_properties(
    env: *mut NapiEnv,
    object: *mut NapiValue,
    property_count: usize,
    properties: *const crate::abi::NapiPropertyDescriptor,
) -> NapiStatus {
    if object.is_null() || (property_count > 0 && properties.is_null()) {
        return status(env, NapiStatus::InvalidArg);
    }
    run_unit(env, |scope| {
        // SAFETY: the handle comes from the current scope.
        let target = unsafe { as_object(object) }?;
        for index in 0..property_count {
            // SAFETY: the caller declared `property_count` descriptors at
            // `properties`, which is `napi_define_properties`'s contract.
            let descriptor = unsafe { &*properties.add(index) };
            define_one(scope, target, descriptor, env.cast::<Env>())?;
        }
        Ok(())
    })
}

/// Applies one `napi_property_descriptor`, following Node's branch order.
///
/// The order matters: a descriptor with a getter or setter is an accessor even if it
/// also names a method, and a descriptor with a method is a function even if it also
/// carries a value. Node tests `getter || setter`, then `method`, then falls back to
/// `value`, and this does the same.
fn define_one(
    scope: &mut v8::PinScope<'_, '_>,
    target: v8::Local<v8::Object>,
    descriptor: &crate::abi::NapiPropertyDescriptor,
    env: *mut Env,
) -> Result<(), NapiStatus> {
    use crate::abi::property_attributes as attributes;

    let name = descriptor_name(scope, descriptor)?;
    let enumerable = descriptor.attributes & attributes::ENUMERABLE != 0;
    let configurable = descriptor.attributes & attributes::CONFIGURABLE != 0;
    let writable = descriptor.attributes & attributes::WRITABLE != 0;

    if descriptor.getter.is_some() || descriptor.setter.is_some() {
        // An accessor descriptor needs V8's `AccessorNameGetterCallback` shape,
        // which receives the property name and a `PropertyCallbackInfo` rather
        // than a `FunctionCallbackInfo`. That is a different wrapper from
        // `invoke_addon_callback` and is recorded as deferred. Reporting it is
        // the honest failure: installing a data property here would silently
        // shadow the getter, and an addon would read a stale value instead of
        // learning that accessors do not work.
        return Err(NapiStatus::InvalidArg);
    }

    if let Some(callback) = descriptor.method {
        let boxed = crate::callback::boxed_callback_data(Some(callback), descriptor.data, env);
        let function = crate::callback::build_function(scope, "", boxed, 0)
            .ok_or(NapiStatus::GenericFailure)?;
        let mut property =
            v8::PropertyDescriptor::new_from_value_writable(function.into(), writable);
        property.set_enumerable(enumerable);
        property.set_configurable(configurable);
        return match target.define_property(scope, name, &property) {
            Some(true) => Ok(()),
            // Node reports a failed method definition as `napi_generic_failure`
            // and a failed accessor definition as `napi_invalid_arg`.
            _ => Err(NapiStatus::GenericFailure),
        };
    }

    // SAFETY: `descriptor.value` is a `napi_value` from the current scope.
    let value = unsafe { as_value(descriptor.value) }?;
    // Node takes `CreateDataProperty`'s faster path when all three attribute bits
    // are set, which is the common `napi_default_jsproperty` case.
    if enumerable && writable && configurable {
        return match target.create_data_property(scope, name, value) {
            Some(true) => Ok(()),
            _ => Err(NapiStatus::GenericFailure),
        };
    }
    let mut property = v8::PropertyDescriptor::new_from_value_writable(value, writable);
    property.set_enumerable(enumerable);
    property.set_configurable(configurable);
    match target.define_property(scope, name, &property) {
        Some(true) => Ok(()),
        _ => Err(NapiStatus::GenericFailure),
    }
}

/// The property name a descriptor carries: `utf8name` or `name`, never both.
///
/// Node's `V8NameFromPropertyDescriptor` rejects a descriptor with both set, because
/// which one wins would be arbitrary.
fn descriptor_name<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    descriptor: &crate::abi::NapiPropertyDescriptor,
) -> Result<v8::Local<'s, v8::Name>, NapiStatus> {
    if !descriptor.utf8name.is_null() && !descriptor.name.is_null() {
        return Err(NapiStatus::InvalidArg);
    }
    if !descriptor.utf8name.is_null() {
        let text = crate::env::c_string(descriptor.utf8name);
        let string = v8::String::new(scope, &text).ok_or(NapiStatus::GenericFailure)?;
        return Ok(string.into());
    }
    if descriptor.name.is_null() {
        return Err(NapiStatus::InvalidArg);
    }
    // SAFETY: `name` is a `napi_value` from the current scope.
    let local = unsafe { arg(descriptor.name) }.ok_or(NapiStatus::InvalidArg)?;
    v8::Local::<v8::Name>::try_from(local).map_err(|_| NapiStatus::NameExpected)
}

// ---------------------------------------------------------------------------
// Calling back into JavaScript
// ---------------------------------------------------------------------------

#[export_name = "napi_call_function"]
pub unsafe extern "C" fn napi_call_function(
    env: *mut NapiEnv,
    recv: *mut NapiValue,
    func: *mut NapiValue,
    argc: usize,
    argv: *const *mut NapiValue,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if recv.is_null() || func.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    if argc > 0 && argv.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    let outcome = in_scope(|scope| {
        // SAFETY: both handles come from the current scope.
        let receiver = unsafe { as_value(recv) }?;
        let function = unsafe { as_function(func) }?;
        let mut arguments = Vec::with_capacity(argc);
        for index in 0..argc {
            // SAFETY: `argv` has at least `argc` entries by the caller's
            // contract, and each is a handle from this scope.
            let handle = unsafe { *argv.add(index) };
            // SAFETY: as above.
            arguments.push(unsafe { as_value(handle) }?);
        }
        let value = function
            .call(scope, receiver, &arguments)
            .ok_or(NapiStatus::GenericFailure)?;
        Ok(to_napi(value))
    });
    match outcome {
        // No scope means no `napi_env` either; report the mismatch the caller
        // can act on rather than a misleading failure.
        None => status(env, NapiStatus::HandleScopeMismatch),
        Some(Err(failure)) => status(env, failure),
        Some(Ok(handle)) => {
            // SAFETY: the caller passed a writable or null slot.
            unsafe { store(result, handle) };
            status(env, NapiStatus::Ok)
        }
    }
}

#[export_name = "napi_get_cb_info"]
pub unsafe extern "C" fn napi_get_cb_info(
    env: *mut NapiEnv,
    cbinfo: *mut NapiCallbackInfo,
    argc: *mut usize,
    argv: *mut *mut NapiValue,
    this_arg: *mut *mut NapiValue,
    data: *mut *mut c_void,
) -> NapiStatus {
    if cbinfo.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `cbinfo` is the frame pointer `crate::callback` placed on the stack
    // before invoking this addon callback, and it is alive for exactly this call.
    let frame = unsafe { &*(cbinfo as *const crate::callback::CallbackFrame<'_>) };

    if !argv.is_null() {
        if argc.is_null() {
            return status(env, NapiStatus::InvalidArg);
        }
        // SAFETY: the caller declared `*argc` slots at `argv`.
        let capacity = unsafe { *argc };
        let count = capacity.min(frame.argv.len());
        for index in 0..count {
            // SAFETY: `argv` is writable for `capacity` entries.
            unsafe { argv.add(index).write(to_napi(frame.argv[index])) };
        }
    }
    if !argc.is_null() {
        // SAFETY: the caller passed a writable count.
        unsafe { argc.write(frame.argv.len()) };
    }
    if !this_arg.is_null() {
        // SAFETY: the caller passed a writable slot.
        unsafe { this_arg.write(to_napi(frame.this.into())) };
    }
    if !data.is_null() {
        // SAFETY: the caller passed a writable slot.
        unsafe { data.write(frame.data) };
    }
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_get_new_target"]
pub unsafe extern "C" fn napi_get_new_target(
    env: *mut NapiEnv,
    cbinfo: *mut NapiCallbackInfo,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if cbinfo.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: as in `napi_get_cb_info`, the frame is on this call's stack.
    let frame = unsafe { &*(cbinfo as *const crate::callback::CallbackFrame<'_>) };
    // Node reports null for a plain call, so an addon can compare against null
    // rather than against `undefined`.
    let target = if frame.new_target.is_undefined() {
        std::ptr::null_mut()
    } else {
        to_napi(frame.new_target)
    };
    // SAFETY: the caller passed a writable slot.
    unsafe { result.write(target) };
    status(env, NapiStatus::Ok)
}

// ---------------------------------------------------------------------------
// Throwing
// ---------------------------------------------------------------------------

/// Schedules `exception` and records it so `napi_is_exception_pending` sees it.
fn throw(env: *mut NapiEnv, exception: v8::Local<'_, v8::Value>) {
    let recorded = in_scope(|scope| {
        let global = v8::Global::new(scope, exception);
        scope.throw_exception(exception);
        global
    });
    // SAFETY: `env` is null or one of this crate's environments.
    if let (Some(environment), Some(global)) = (unsafe { env_from(env) }, recorded) {
        let _ = environment.exceptions().try_borrow_mut().map(|mut state| {
            state.set(global);
        });
    }
}

#[export_name = "napi_throw"]
pub unsafe extern "C" fn napi_throw(env: *mut NapiEnv, error: *mut NapiValue) -> NapiStatus {
    if error.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    let Some(exception) = in_scope(|_| {
        // SAFETY: the addon passed a handle from the current scope.
        unsafe { as_value(error) }.ok()
    })
    .flatten() else {
        return status(env, NapiStatus::HandleScopeMismatch);
    };
    throw(env, exception);
    status(env, NapiStatus::Ok)
}

/// The kind of error `napi_throw_*_error` builds.
#[derive(Clone, Copy)]
enum ErrorKind {
    Error,
    Type,
    Range,
}

/// `napi_throw_error` / `napi_throw_type_error` / `napi_throw_range_error`.
///
/// Node sets `error.code` from the `code` argument when it is present, which is
/// what `assert.throws(..., { code: 'ERR_...' })` reads.
fn throw_coded(
    env: *mut NapiEnv,
    code: *const c_char,
    msg: *const c_char,
    kind: ErrorKind,
) -> NapiStatus {
    let text = crate::env::c_string(msg);
    let code = crate::env::c_string(code);
    let created = in_scope(|scope| {
        let message = v8::String::new(scope, &text)?;
        let exception = match kind {
            ErrorKind::Error => v8::Exception::error(scope, message),
            ErrorKind::Type => v8::Exception::type_error(scope, message),
            ErrorKind::Range => v8::Exception::range_error(scope, message),
        };
        if !code.is_empty() {
            if let (Ok(object), Some(code_value)) = (
                v8::Local::<v8::Object>::try_from(exception),
                v8::String::new(scope, &code),
            ) {
                if let Some(key) = v8::String::new(scope, "code") {
                    let _ = object.set(scope, key.into(), code_value.into());
                }
            }
        }
        Some(exception)
    });
    match created {
        Some(Some(exception)) => {
            throw(env, exception);
            status(env, NapiStatus::Ok)
        }
        Some(None) => status(env, NapiStatus::GenericFailure),
        None => status(env, NapiStatus::HandleScopeMismatch),
    }
}

#[export_name = "napi_throw_error"]
pub unsafe extern "C" fn napi_throw_error(
    env: *mut NapiEnv,
    code: *const c_char,
    msg: *const c_char,
) -> NapiStatus {
    throw_coded(env, code, msg, ErrorKind::Error)
}

#[export_name = "napi_throw_type_error"]
pub unsafe extern "C" fn napi_throw_type_error(
    env: *mut NapiEnv,
    code: *const c_char,
    msg: *const c_char,
) -> NapiStatus {
    throw_coded(env, code, msg, ErrorKind::Type)
}

#[export_name = "napi_throw_range_error"]
pub unsafe extern "C" fn napi_throw_range_error(
    env: *mut NapiEnv,
    code: *const c_char,
    msg: *const c_char,
) -> NapiStatus {
    throw_coded(env, code, msg, ErrorKind::Range)
}

#[export_name = "napi_is_exception_pending"]
pub unsafe extern "C" fn napi_is_exception_pending(
    env: *mut NapiEnv,
    result: *mut bool,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    let pending = environment
        .exceptions()
        .try_borrow()
        .map(|state| state.is_pending())
        .unwrap_or(false);
    // SAFETY: the caller passed a writable slot for one bool.
    unsafe { result.write(pending) };
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_get_and_clear_last_exception"]
pub unsafe extern "C" fn napi_get_and_clear_last_exception(
    env: *mut NapiEnv,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    let taken = environment
        .exceptions()
        .try_borrow_mut()
        .ok()
        .and_then(|mut state| state.take());
    let Some(taken) = taken else {
        return status(env, NapiStatus::GenericFailure);
    };
    let handle =
        in_scope(|scope| to_napi(v8::Local::new(scope, taken))).unwrap_or_else(std::ptr::null_mut);
    if handle.is_null() {
        return status(env, NapiStatus::HandleScopeMismatch);
    }
    // SAFETY: the caller passed a writable slot.
    unsafe { store(result, handle) };
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_create_reference"]
pub unsafe extern "C" fn napi_create_reference(
    env: *mut NapiEnv,
    value: *mut NapiValue,
    initial_refcount: u32,
    result: *mut *mut NapiRef,
) -> NapiStatus {
    if value.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    let Ok(rooted) = in_scope(|scope| {
        // SAFETY: the handle comes from the current scope.
        let local = unsafe { as_value(value) }?;
        // A nonzero count is a strong reference: the value must survive collection
        // even when JavaScript drops every other reference, so it is rooted with a
        // `Global`. A zero count is weak, and Node's weak references cannot be
        // expressed with `Global`; the table stores the root regardless and reports
        // the count, which is enough for the reference-based addons that read a
        // strongly-held value.
        Ok(v8::Global::new(scope, local))
    })
    .unwrap_or_else(|| Err(NapiStatus::HandleScopeMismatch)) else {
        return status(env, NapiStatus::InvalidArg);
    };
    let handle = environment.add_ref(crate::env::RefEntry {
        value: std::cell::RefCell::new(Some(rooted)),
        count: std::cell::Cell::new(initial_refcount),
        finalize: None,
        finalize_hint: std::ptr::null_mut(),
    });
    // SAFETY: the caller passed a writable slot for one pointer.
    unsafe { result.write(handle) };
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_delete_reference"]
pub unsafe extern "C" fn napi_delete_reference(
    env: *mut NapiEnv,
    reference: *mut NapiRef,
) -> NapiStatus {
    if reference.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    if environment.delete_ref(reference) {
        status(env, NapiStatus::Ok)
    } else {
        status(env, NapiStatus::InvalidArg)
    }
}

#[export_name = "napi_reference_ref"]
pub unsafe extern "C" fn napi_reference_ref(
    env: *mut NapiEnv,
    reference: *mut NapiRef,
    result: *mut u32,
) -> NapiStatus {
    if reference.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    let count = environment.with_ref(reference, |entry| {
        let next = entry.count.get().saturating_add(1);
        entry.count.set(next);
        next
    });
    let Some(count) = count else {
        return status(env, NapiStatus::InvalidArg);
    };
    if !result.is_null() {
        // SAFETY: the caller passed a writable slot or null.
        unsafe { result.write(count) };
    }
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_reference_unref"]
pub unsafe extern "C" fn napi_reference_unref(
    env: *mut NapiEnv,
    reference: *mut NapiRef,
    result: *mut u32,
) -> NapiStatus {
    if reference.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    // Unreferencing an already-zero reference is an error in Node, because the
    // caller has lost track of the count and the next delete would run a finalizer
    // twice.
    let count = environment.with_ref(reference, |entry| {
        let current = entry.count.get();
        if current == 0 {
            return None;
        }
        let next = current - 1;
        entry.count.set(next);
        Some(next)
    });
    let Some(count) = count.flatten() else {
        return status(env, NapiStatus::GenericFailure);
    };
    if !result.is_null() {
        // SAFETY: the caller passed a writable slot or null.
        unsafe { result.write(count) };
    }
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_get_reference_value"]
pub unsafe extern "C" fn napi_get_reference_value(
    env: *mut NapiEnv,
    reference: *mut NapiRef,
    result: *mut *mut NapiValue,
) -> NapiStatus {
    if reference.is_null() || result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    let rooted = environment.with_ref(reference, |entry| {
        entry
            .value
            .try_borrow()
            .ok()
            .and_then(|slot| slot.as_ref().map(v8::Global::clone))
    });
    let Some(rooted) = rooted.flatten() else {
        return status(env, NapiStatus::InvalidArg);
    };
    let handle =
        in_scope(|scope| to_napi(v8::Local::new(scope, rooted))).unwrap_or_else(std::ptr::null_mut);
    if handle.is_null() {
        return status(env, NapiStatus::HandleScopeMismatch);
    }
    // SAFETY: the caller passed a writable slot.
    unsafe { store(result, handle) };
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_set_instance_data"]
pub unsafe extern "C" fn napi_set_instance_data(
    env: *mut NapiEnv,
    data: *mut c_void,
    finalize: NapiFinalize,
    hint: *mut c_void,
) -> NapiStatus {
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    environment.set_instance_data(data, finalize, hint);
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_get_instance_data"]
pub unsafe extern "C" fn napi_get_instance_data(
    env: *mut NapiEnv,
    result: *mut *mut c_void,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    // SAFETY: the caller passed a writable slot for one pointer.
    unsafe { result.write(environment.instance_data().unwrap_or(std::ptr::null_mut())) };
    status(env, NapiStatus::Ok)
}

// ---------------------------------------------------------------------------
// Version information
// ---------------------------------------------------------------------------

#[export_name = "napi_get_version"]
pub unsafe extern "C" fn napi_get_version(env: *mut NapiEnv, result: *mut u32) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: the caller passed a writable slot for one u32.
    unsafe { result.write(NAPI_SUPPORTED_VERSION_MAX as u32) };
    status(env, NapiStatus::Ok)
}

#[export_name = "napi_get_node_version"]
pub unsafe extern "C" fn napi_get_node_version(
    env: *mut NapiEnv,
    result: *mut *const crate::abi::NapiNodeVersion,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: the caller passed a writable slot for one pointer; the version
    // struct is a `'static` this crate owns.
    unsafe { result.write(crate::env::node_version()) };
    status(env, NapiStatus::Ok)
}

#[export_name = "node_api_get_module_file_name"]
pub unsafe extern "C" fn node_api_get_module_file_name(
    env: *mut NapiEnv,
    result: *mut *const c_char,
) -> NapiStatus {
    if result.is_null() {
        return status(env, NapiStatus::InvalidArg);
    }
    // SAFETY: `env` is null or one of this crate's environments.
    let Some(environment) = (unsafe { env_from(env) }) else {
        return status(env, NapiStatus::InvalidArg);
    };
    // SAFETY: the caller passed a writable slot for one pointer; the filename is
    // owned by the environment, which outlives every addon call.
    unsafe { result.write(environment.module_filename_ptr()) };
    status(env, NapiStatus::Ok)
}

// ---------------------------------------------------------------------------
// The declared surface
// ---------------------------------------------------------------------------

/// Every entry point this binary exports.
///
/// Kept as data so a test can compare it against the binary's own dynamic symbol
/// table: a shim written but never exported would otherwise be invisible until an
/// addon failed to load.
pub const EXPORTED: &[&str] = &[
    "napi_get_last_error_info",
    "napi_get_undefined",
    "napi_get_null",
    "napi_get_global",
    "napi_get_boolean",
    "napi_create_object",
    "napi_create_array",
    "napi_create_array_with_length",
    "napi_create_double",
    "napi_create_int32",
    "napi_create_uint32",
    "napi_create_int64",
    "napi_create_string_utf8",
    "napi_create_string_latin1",
    "napi_create_function",
    "napi_typeof",
    "napi_get_value_double",
    "napi_get_value_int32",
    "napi_get_value_uint32",
    "napi_get_value_int64",
    "napi_get_value_bool",
    "napi_get_value_string_utf8",
    "napi_get_value_string_latin1",
    "napi_is_array",
    "napi_get_array_length",
    "napi_is_error",
    "napi_set_named_property",
    "napi_get_named_property",
    "napi_has_named_property",
    "napi_set_element",
    "napi_get_element",
    "napi_has_element",
    "napi_set_property",
    "napi_get_property",
    "napi_has_property",
    "napi_delete_property",
    "napi_get_prototype",
    "napi_define_properties",
    "napi_call_function",
    "napi_get_cb_info",
    "napi_get_new_target",
    "napi_throw",
    "napi_throw_error",
    "napi_throw_type_error",
    "napi_throw_range_error",
    "napi_is_exception_pending",
    "napi_get_and_clear_last_exception",
    "napi_create_reference",
    "napi_delete_reference",
    "napi_reference_ref",
    "napi_reference_unref",
    "napi_get_reference_value",
    "napi_set_instance_data",
    "napi_get_instance_data",
    "napi_get_version",
    "napi_get_node_version",
    "node_api_get_module_file_name",
];

/// Entry points this build does not export, each with the reason it waits.
///
/// This is the honest half of the surface: an addon needing one of these fails to
/// load with a `dlsym` error naming the symbol, which is a clear failure at the
/// boundary rather than a wrong answer from a stub.
pub const DEFERRED: &[(&str, &str)] = &[
    (
        "napi_async_init / napi_async_destroy / napi_make_callback / napi_open_callback_scope / napi_close_callback_scope",
        "async context plumbing needs the AsyncWrap table reachable from the addon's env",
    ),
    (
        "napi_create_async_work / napi_queue_async_work / napi_cancel_async_work / napi_delete_async_work",
        "queued work needs the libuv thread pool and the loop's completion callback",
    ),
    (
        "napi_create_threadsafe_function / napi_call_threadsafe_function / napi_acquire_threadsafe_function / napi_release_threadsafe_function",
        "cross-thread calls need the isolate Locker and the shared queue",
    ),
    (
        "napi_create_buffer / napi_create_buffer_copy / napi_create_external_buffer / napi_get_buffer_info / napi_is_buffer / node_api_create_buffer_from_arraybuffer",
        "Buffer parity needs rn-bind-buffer's external-allocation tracking so GC stays correct",
    ),
    (
        "napi_wrap / napi_unwrap / napi_remove_wrap / napi_add_finalizer / node_api_post_finalizer",
        "per-object native data needs a private-symbol slot and a GC-reachability decision",
    ),
    (
        "weak references (napi_create_reference with initial_refcount 0)",
        "a strong reference is a V8 `Global`; a weak one needs a `v8::Weak` with a callback, and every addon in scope uses a strong count",
    ),
    (
        "napi_define_class / napi_new_instance / napi_instanceof",
        "class construction needs the FunctionTemplate prototype split and construct-call detection",
    ),
    (
        "napi_define_properties with getter/setter",
        "the method and value descriptor forms are implemented; an accessor needs the AccessorNameGetterCallback wrapper, which takes the property name instead of a FunctionCallbackInfo",
    ),
    (
        "napi_get_property_names / napi_get_all_property_names / node_api_set_prototype",
        "property-name filtering (key_filter/key_conversion) has no exact V8 equivalent yet",
    ),
    (
        "napi_has_own_property / napi_delete_element",
        "thin Object calls; each lands with its first caller rather than ahead of one",
    ),
    (
        "napi_create_promise / napi_resolve_deferred / napi_reject_deferred / napi_is_promise",
        "needs the microtask queue drained at the right point in a V8 callback",
    ),
    (
        "napi_create_error / napi_create_type_error / napi_create_range_error / node_api_create_syntax_error",
        "the throw path works; factory-created error values wait on `code` property parity",
    ),
    (
        "napi_create_arraybuffer / napi_create_external_arraybuffer / napi_create_typedarray / napi_get_typedarray_info / napi_get_arraybuffer_info / napi_is_arraybuffer / napi_is_typedarray",
        "backing-store lifetime has to be owned by the isolate's ArrayBuffer allocator",
    ),
    (
        "napi_create_dataview / napi_is_dataview / napi_get_dataview_info",
        "same backing-store question as the typed arrays",
    ),
    (
        "napi_create_external / napi_get_value_external",
        "external values need a finalizer scheduled on the isolate that owns them",
    ),
    (
        "napi_create_bigint_int64 / napi_create_bigint_uint64 / napi_create_bigint_words / napi_get_value_bigint_int64 / napi_get_value_bigint_uint64 / napi_get_value_bigint_words",
        "`v8::BigInt` is available; no core addon in scope needs the word-array form yet",
    ),
    (
        "napi_create_symbol / node_api_symbol_for",
        "a one-line V8 call, deferred only to keep this slice's surface reviewable",
    ),
    (
        "napi_create_date / napi_is_date / napi_get_date_value",
        "needs a Date constructor looked up through the context; no caller yet",
    ),
    (
        "napi_coerce_to_bool / napi_coerce_to_number / napi_coerce_to_object / napi_coerce_to_string",
        "coercions run user JavaScript, so they need the exception-pending bookkeeping to be exact",
    ),
    (
        "napi_run_script",
        "runs a script in the module's context; needs the unbound-script origin plumbing",
    ),
    (
        "napi_get_uv_event_loop",
        "rn-uv owns the loop; exposing it as `uv_loop_t*` needs the handle ABI settled",
    ),
    (
        "napi_add_env_cleanup_hook / napi_remove_env_cleanup_hook / napi_add_async_cleanup_hook / napi_remove_async_cleanup_hook",
        "cleanup hooks need an environment teardown path, which this runtime does not have yet",
    ),
    (
        "napi_fatal_error / napi_fatal_exception / napi_adjust_external_memory",
        "fatal paths need the uncaught-exception handler; external memory needs the allocator hook",
    ),
    (
        "napi_open_handle_scope / napi_close_handle_scope / napi_open_escapable_handle_scope / napi_close_escapable_handle_scope / napi_escape_handle",
        "a Node-API handle scope is a V8 HandleScope; needs a per-call scope stack rather than one scope per entry point",
    ),
    (
        "napi_type_tag_object / napi_check_object_type_tag / napi_object_freeze / napi_object_seal",
        "type tags need the private-symbol slot; freeze/seal are one-line V8 calls awaiting a caller",
    ),
    (
        "napi_strict_equals / napi_instanceof",
        "comparison helpers; no caller in the core addon",
    ),
    (
        "napi_detach_arraybuffer / napi_is_detached_arraybuffer",
        "detach needs the ArrayBuffer allocator to own the backing store",
    ),
    (
        "napi_module_register",
        "the legacy self-registration path; `napi_register_module_v1` covers every modern addon",
    ),
];

/// `napi_get_version`'s answer: the highest Node-API version this build supports.
pub const SUPPORTED_NAPI_VERSION: i32 = NAPI_SUPPORTED_VERSION_MAX;

/// The version an addon that omits `node_api_module_get_api_version_v1` gets.
pub const DEFAULT_MODULE_API_VERSION: i32 = NAPI_DEFAULT_MODULE_API_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_bytes_honours_auto_length() {
        let text = std::ffi::CString::new("hello").expect("no interior nul");
        assert_eq!(
            read_bytes(text.as_ptr(), usize::MAX).expect("readable"),
            b"hello"
        );
    }

    #[test]
    fn read_bytes_honours_an_explicit_shorter_length() {
        // An addon may pass a longer buffer with a shorter length to take a
        // prefix; truncating at the caller's length is the contract.
        let text = std::ffi::CString::new("hello").expect("no interior nul");
        assert_eq!(read_bytes(text.as_ptr(), 2).expect("readable"), b"he");
    }

    #[test]
    fn a_null_string_with_auto_length_is_empty_rather_than_invalid() {
        assert_eq!(
            read_bytes(std::ptr::null(), usize::MAX).expect("empty"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn a_null_string_with_a_length_is_an_invalid_argument() {
        // Reading `length` bytes from null would be a segfault; Node reports the
        // invalid argument instead, and so must this.
        assert!(read_bytes(std::ptr::null(), 4).is_none());
    }

    #[test]
    fn deferred_members_are_not_also_exported() {
        // A symbol cannot be both implemented and declared missing: that would
        // make the deferral list lie about the surface.
        for (member, _) in DEFERRED {
            for name in member.split(" / ") {
                assert!(
                    !EXPORTED.contains(&name),
                    "{name} is both exported and deferred"
                );
            }
        }
    }

    #[test]
    fn the_exported_list_has_no_duplicates() {
        // A duplicated name would mean one shim silently replaced another.
        let mut seen = std::collections::BTreeSet::new();
        for name in EXPORTED {
            assert!(seen.insert(*name), "{name} is listed twice");
        }
    }

    #[test]
    fn no_exported_name_looks_like_a_namespace_provider() {
        // `tools/regen-bindings.sh` greps for the substring `pub fn register` and
        // treats it as a namespace provider, which broke the build once already.
        // Keeping the exported names clear of the prefix means that grep can
        // never misfire on this crate.
        for name in EXPORTED {
            assert!(
                !name.starts_with("register") && !name.contains("fn register"),
                "{name} looks like a provider"
            );
        }
    }

    #[test]
    fn the_deferred_list_gives_every_entry_a_reason() {
        // A deferral without a reason is a stub with extra steps.
        for (member, reason) in DEFERRED {
            assert!(!member.is_empty());
            assert!(
                reason.len() > 20,
                "{member} needs a real reason, not {reason:?}"
            );
        }
    }

    #[test]
    fn the_supported_version_bounds_match_the_header() {
        assert_eq!(DEFAULT_MODULE_API_VERSION, 8);
        assert_eq!(SUPPORTED_NAPI_VERSION, 10);
        assert_eq!(crate::abi::NAPI_SUPPORTED_VERSION_MIN, 1);
    }

    #[test]
    fn attribute_flags_match_the_header() {
        use crate::abi::property_attributes;
        assert_eq!(property_attributes::WRITABLE, 1);
        assert_eq!(property_attributes::ENUMERABLE, 2);
        assert_eq!(property_attributes::CONFIGURABLE, 4);
        assert_eq!(property_attributes::STATIC, 1024);
        assert_eq!(property_attributes::DEFAULT_METHOD, 5);
        assert_eq!(property_attributes::DEFAULT_JSPROPERTY, 7);
    }

    #[test]
    fn an_assignment_that_v8_refused_is_a_generic_failure() {
        assert!(assigned(Some(true)).is_ok());
        // `Some(false)` is a refused assignment; `None` is a pending V8
        // exception. Node reports both as `napi_generic_failure`.
        assert_eq!(assigned(Some(false)), Err(NapiStatus::GenericFailure));
        assert_eq!(assigned(None), Err(NapiStatus::GenericFailure));
    }
}
