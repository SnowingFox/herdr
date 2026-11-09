//! The key-derivation jobs `lib/internal/crypto/**` drives.
//!
//! `pbkdf2`, `scrypt` and `hkdf` do not call a plain native function: each builds
//! a job object, then either
//!
//! * runs it synchronously and destructures `[error, result]` from `run()`, or
//! * sets `job.ondone` and calls `run()`, expecting the callback to be invoked.
//!
//! Both shapes go through the same constructor, selected by the mode argument in
//! position 0 (`kCryptoJobSync` versus `kCryptoJobAsync`). That is Node's
//! `CryptoJob` protocol, and it is why these cannot simply be functions.
//!
//! # Why the async mode completes immediately
//!
//! Node runs these on the libuv threadpool. This landing has no threadpool
//! binding for crypto, and a derivation is a bounded computation, so `run()` in
//! async mode computes the result and then invokes `ondone` before returning.
//! The observable difference from Node is *when* the callback runs — here it is
//! synchronous rather than a later tick — which changes no result and no error.
//! `lib/internal/crypto/pbkdf2.js` only requires that the callback eventually
//! receives `(null, result)` or `(error)`.
//!
//! The derivations themselves are OpenSSL's (`PKCS5_PBKDF2_HMAC`,
//! `EVP_PBE_scrypt`, `EVP_KDF` for HKDF), so the output is identical to Node's.

use rn_v8_sys::v8;

use crate::encoding;
use crate::engine;
use crate::install::{throw_crypto_error, throw_type_error};

/// Internal field index holding the `Box<KdfState>`.
const STATE_FIELD: i32 = 0;

/// `kCryptoJobSync` from `node_crypto.h`.
const K_CRYPTO_JOB_SYNC: i32 = 1;

/// What a derivation job was asked to compute.
enum KdfState {
    Pbkdf2 {
        password: Vec<u8>,
        salt: Vec<u8>,
        iterations: u32,
        keylen: usize,
        digest: String,
    },
    Scrypt {
        password: Vec<u8>,
        salt: Vec<u8>,
        n: u64,
        r: u64,
        p: u64,
        maxmem: u64,
        keylen: usize,
    },
    Hkdf {
        digest: String,
        key: Vec<u8>,
        salt: Option<Vec<u8>>,
        info: Vec<u8>,
        length: usize,
    },
}

impl KdfState {
    /// Runs the derivation.
    fn compute(&self) -> Result<Vec<u8>, engine::CryptoError> {
        match self {
            Self::Pbkdf2 {
                password,
                salt,
                iterations,
                keylen,
                digest,
            } => engine::pbkdf2(digest, password, salt, *iterations, *keylen),
            Self::Scrypt {
                password,
                salt,
                n,
                r,
                p,
                maxmem,
                keylen,
            } => engine::scrypt_with_maxmem(password, salt, *n, *r, *p, *maxmem, *keylen),
            Self::Hkdf {
                digest,
                key,
                salt,
                info,
                length,
            } => engine::hkdf(digest, key, salt.as_deref(), info, *length),
        }
    }
}

fn with_state<R>(object: v8::Local<v8::Object>, body: impl FnOnce(&KdfState) -> R) -> Option<R> {
    // SAFETY: the field only ever holds a pointer from `install_state`, and the
    // finalizer cannot run while `object` is a live local.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *const KdfState;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above; the state is only read through this borrow.
    Some(body(unsafe { &*pointer }))
}

fn install_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    state: KdfState,
) {
    let pointer = Box::into_raw(Box::new(state));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut KdfState;
            // SAFETY: allocated by `install_state`; freed exactly once here.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
}

/// Reads a view or string argument as bytes.
fn bytes_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<Vec<u8>> {
    let value = args.get(index);
    if value.is_string() {
        let text = value.to_string(scope)?;
        return Some(text.to_rust_string_lossy(scope).into_bytes());
    }
    if value.is_null() || value.is_undefined() {
        return Some(Vec::new());
    }
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) else {
        return None;
    };
    let length = view.byte_length();
    let data = view.data().cast::<u8>();
    if data.is_null() {
        return if length == 0 { Some(Vec::new()) } else { None };
    }
    // SAFETY: `data` is the view's backing store and `length` is its byte length,
    // so the range is readable. The bytes are copied before returning to
    // JavaScript.
    Some(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
}

/// `new PBKDF2Job(mode, password, salt, iterations, keylen, digest)`.
pub(crate) fn pbkdf2_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(password) = bytes_argument(scope, &args, 1) else {
        throw_type_error(scope, "The password must be a string or an ArrayBufferView");
        return;
    };
    let Some(salt) = bytes_argument(scope, &args, 2) else {
        throw_type_error(scope, "The salt must be a string or an ArrayBufferView");
        return;
    };
    let iterations = args.get(3).uint32_value(scope).unwrap_or(0);
    let keylen = args.get(4).uint32_value(scope).unwrap_or(0) as usize;
    let digest = args
        .get(5)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();

    let this: v8::Local<v8::Object> = args.this();
    note_mode(scope, this, &args);
    install_state(
        scope,
        this,
        KdfState::Pbkdf2 {
            password,
            salt,
            iterations,
            keylen,
            digest,
        },
    );
    rv.set(this.into());
}

/// `new ScryptJob(mode, password, salt, N, r, p, maxmem, keylen)`.
pub(crate) fn scrypt_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(password) = bytes_argument(scope, &args, 1) else {
        throw_type_error(scope, "The password must be a string or an ArrayBufferView");
        return;
    };
    let Some(salt) = bytes_argument(scope, &args, 2) else {
        throw_type_error(scope, "The salt must be a string or an ArrayBufferView");
        return;
    };
    let number = |index: i32| args.get(index).number_value(scope).unwrap_or(0.0) as u64;
    let n = number(3);
    let r = number(4);
    let p = number(5);
    let maxmem = number(6);
    let keylen = args.get(7).uint32_value(scope).unwrap_or(0) as usize;

    let this: v8::Local<v8::Object> = args.this();
    note_mode(scope, this, &args);
    install_state(
        scope,
        this,
        KdfState::Scrypt {
            password,
            salt,
            n,
            r,
            p,
            maxmem,
            keylen,
        },
    );
    rv.set(this.into());
}

/// `new HKDFJob(mode, digest, key, salt, info, length)`.
pub(crate) fn hkdf_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let digest = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let Some(key) = bytes_argument(scope, &args, 2) else {
        throw_type_error(scope, "The key must be a string or an ArrayBufferView");
        return;
    };
    // An absent salt is meaningful (RFC 5869 substitutes a zero string), so
    // `None` is preserved rather than turned into an empty buffer.
    let salt = if args.get(3).is_undefined() || args.get(3).is_null() {
        None
    } else {
        match bytes_argument(scope, &args, 3) {
            Some(salt) => Some(salt),
            None => {
                throw_type_error(scope, "The salt must be a string or an ArrayBufferView");
                return;
            }
        }
    };
    let Some(info) = bytes_argument(scope, &args, 4) else {
        throw_type_error(scope, "The info must be a string or an ArrayBufferView");
        return;
    };
    let length = args.get(5).uint32_value(scope).unwrap_or(0) as usize;

    let this: v8::Local<v8::Object> = args.this();
    note_mode(scope, this, &args);
    install_state(
        scope,
        this,
        KdfState::Hkdf {
            digest,
            key,
            salt,
            info,
            length,
        },
    );
    rv.set(this.into());
}

/// `job.run()`, shared by all three job classes.
///
/// In sync mode this returns `[undefined, result]` or `[error, undefined]`, which
/// the JavaScript destructures. In async mode it invokes `job.ondone(error,
/// result)` and returns `undefined`.
pub(crate) fn run(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // The mode was consumed by the constructor; the job records whether it was
    // asked to run synchronously by keeping the original first argument.
    let mode = with_state(this, |_| ())
        .map(|()| job_mode(scope, this))
        .unwrap_or(0);
    let computed = with_state(this, KdfState::compute);

    let result = match computed {
        Some(Ok(bytes)) => Ok(bytes),
        Some(Err(error)) => Err(error),
        None => {
            throw(scope, "the job handle is not initialised");
            return;
        }
    };

    if mode == K_CRYPTO_JOB_SYNC {
        rv.set(sync_result(scope, result));
        return;
    }

    // Async: deliver through `ondone`, which is what `pbkdf2`/`scrypt`/`hkdf`
    // install before calling `run()`.
    let Some(key) = v8::String::new(scope, "ondone") else {
        return;
    };
    let Some(callback) = this.get(scope, key.into()) else {
        return;
    };
    let Ok(callback) = v8::Local::<v8::Function>::try_from(callback) else {
        throw_type_error(scope, "job.ondone is not a function");
        return;
    };
    let (first, second): (v8::Local<v8::Value>, v8::Local<v8::Value>) = match result {
        Ok(bytes) => match encoding::uint8_array(scope, &bytes) {
            Some(array) => (v8::undefined(scope).into(), array.into()),
            None => {
                throw(scope, "cannot allocate the derivation result");
                return;
            }
        },
        Err(error) => {
            let Some(text) = v8::String::new(scope, &error.to_string()) else {
                return;
            };
            let exception = v8::Exception::error(scope, text);
            (exception, v8::undefined(scope).into())
        }
    };
    let receiver: v8::Local<v8::Value> = this.into();
    callback.call(scope, receiver, &[first, second]);
}

/// Builds the `[error, result]` array a sync `run()` returns.
fn sync_result<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    result: Result<Vec<u8>, engine::CryptoError>,
) -> v8::Local<'s, v8::Value> {
    let (first, second): (v8::Local<'s, v8::Value>, v8::Local<'s, v8::Value>) = match result {
        Ok(bytes) => match encoding::uint8_array(scope, &bytes) {
            Some(array) => (v8::undefined(scope).into(), array.into()),
            None => {
                throw(scope, "cannot allocate the derivation result");
                return v8::undefined(scope).into();
            }
        },
        Err(error) => {
            let Some(text) = v8::String::new(scope, &error.to_string()) else {
                return v8::undefined(scope).into();
            };
            let exception = v8::Exception::error(scope, text);
            (exception, v8::undefined(scope).into())
        }
    };
    v8::Array::new_with_elements(scope, &[first, second]).into()
}

/// Reads the mode the job was constructed with.
///
/// The constructor does not store it, so it is re-read from a hidden property the
/// constructor writes.
fn job_mode(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) -> i32 {
    let Some(key) = v8::String::new(scope, "__rn_job_mode") else {
        return 0;
    };
    let Some(value) = object.get(scope, key.into()) else {
        return 0;
    };
    value.int32_value(scope).unwrap_or(0)
}

/// Records the job's mode on the instance so `run()` can read it back.
pub(crate) fn note_mode(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    args: &v8::FunctionCallbackArguments<'_>,
) {
    let mode = args.get(0).int32_value(scope).unwrap_or(0);
    let Some(key) = v8::String::new(scope, "__rn_job_mode") else {
        return;
    };
    let value = v8::Integer::new(scope, mode);
    object.set(scope, key.into(), value.into());
}

/// Installs one KDF job class with `run()` on its prototype.
pub(crate) fn install_job_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    constructor: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    let prototype = template.prototype_template(scope);
    let Some(key) = v8::String::new(scope, "run") else {
        return Err(format!("cannot allocate {name}.run"));
    };
    prototype.set(
        key.into(),
        v8::FunctionTemplate::builder(run).build(scope).into(),
    );
    let Some(class_name) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} class name"));
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err(format!("cannot allocate the {name} constructor"));
    };
    let Some(key) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} property name"));
    };
    target.set(scope, key.into(), function.into());
    Ok(())
}

fn throw(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

// `throw_crypto_error` is re-used by the constructors via the `install` module;
// this keeps the import honest without duplicating the mapping.
#[allow(dead_code)]
fn _uses_throw_crypto_error(scope: &mut v8::PinScope<'_, '_>, error: &engine::CryptoError) {
    throw_crypto_error(scope, error);
}
