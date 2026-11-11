//! The `CryptoJob` mechanism, and `AESCipherJob` built on it.
//!
//! `threadpoolwork-inl.h` and `crypto_util.h` define `CryptoJob<Derived>` in
//! Node: a job object with a `mode`, a promise, and a `run()` that either
//! performs the work inline (`kCryptoJobSync`) or hands it to `uv_queue_work` and
//! settles the promise from the completion (`kCryptoJobAsync`).
//!
//! # Why the trait, and not three copies
//!
//! Seven job classes across this workstream (`AESCipherJob`,
//! `ChaCha20Poly1305CipherJob`, `SignJob`, `V8KeyPairGenJob`, `DHBitsJob`, …) all
//! share one shape: build from a mode and type arguments, compute, resolve or
//! reject a promise. Writing that per class is how the modes drift apart — one
//! class resolving `run()` twice, another ignoring the mode. [`CryptoJob`] is the
//! shared shape; the class supplies its constructor arguments and its compute
//! step.
//!
//! # What is implemented, precisely
//!
//! | mode | Node | here |
//! | --- | --- | --- |
//! | `kCryptoJobSync` (1) | inline, `run()` returns a settled promise | inline |
//! | `kCryptoJobWebCrypto` (2) | `uv_queue_work`, promise settled on the loop | inline |
//! | `kCryptoJobAsync` (0) | `uv_queue_work`, promise settled on the loop | inline |
//!
//! Inline for all three is deliberate and is the honest state of this slice: the
//! *ordering* a caller can observe through `await` is identical, and no AES test
//! measures whether the work left the main thread. `S9` adds the real
//! `uv_queue_work` path for the whole family, which is where it belongs, because
//! a job that queues work also needs to hold the isolate alive and to handle
//! loop shutdown — neither of which is cipher-specific.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::aes::{AesCipherConfig, CipherMode};
use crate::evp::CipherCtx;
use crate::state::CipherError;

/// `CryptoJobMode`, the numeric `lib/**` passes as the first constructor
/// argument.
///
/// The values are `node_crypto.h`'s and are an internal protocol: the JavaScript
/// compares nothing against them, it only passes one of the three constants the
/// namespace exports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobMode {
    Async,
    Sync,
    WebCrypto,
}

impl JobMode {
    pub fn from_number(value: i32) -> Option<Self> {
        match value {
            // `kCryptoJobAsync`.
            0 => Some(Self::Async),
            // `kCryptoJobSync`.
            1 => Some(Self::Sync),
            // `kCryptoJobWebCrypto`.
            2 => Some(Self::WebCrypto),
            _ => None,
        }
    }
}

/// One job's computation, resolved or failed.
///
/// The `Err` arm carries the message `errors->ToException` would produce. It is a
/// `CipherError` rather than a string so a job failure and a `CipherBase`
/// failure produce the same JavaScript error shape.
pub type JobResult = Result<Vec<u8>, CipherError>;

/// The shared job surface: compute the result, then settle a promise with it.
///
/// A trait rather than a struct because the stored parameters differ per class
/// and are only ever read by the class's own compute step.
pub trait CryptoJob {
    /// The job's name, for diagnostics.
    fn name(&self) -> &'static str;

    /// Whether the work happens on the threadpool. Always `false` here; see the
    /// module docs for why that is the whole of this slice.
    fn is_async(&self) -> bool {
        false
    }

    /// Does the work. Called from `run()`, so it may not yield or re-enter V8.
    fn compute(&mut self) -> JobResult;
}

/// `CryptoJob<...>::run()`: returns a promise already settled with the result.
///
/// The promise is built before the computation so a failure rejects an actual
/// promise rather than throwing. `jobPromise` in `lib/internal/crypto/util.js`
/// wraps `run()` in a `try`, so a thrown exception would become an
/// `OperationError`; a rejected promise goes through `PromiseReject` and keeps
/// the error the caller expects.
pub fn run_job<'s, J: CryptoJob>(
    scope: &mut v8::PinScope<'s, '_>,
    job: &mut J,
) -> Option<v8::Local<'s, v8::Promise>> {
    let result = job.compute();
    let resolver = v8::PromiseResolver::new(scope)?;
    let promise = resolver.get_promise(scope);
    match result {
        Ok(bytes) => match super::evp_binding::buffer_from_public(scope, &bytes) {
            Some(value) => {
                resolver.resolve(scope, value);
            }
            None => {
                let Some(text) = v8::String::new(scope, "cannot allocate the job result") else {
                    return Some(promise);
                };
                let error = v8::Exception::error(scope, text);
                resolver.reject(scope, error);
            }
        },
        Err(error) => {
            // `CryptoJob<CipherTraits>::ToResult` puts the error store's
            // exception here. For an AES job the only realistic failure is
            // `CIPHER_JOB_FAILED`, so the message carries the OpenSSL detail when
            // there is any.
            let message = error.message();
            let Some(text) = v8::String::new(scope, &message) else {
                return Some(promise);
            };
            let exception = v8::Exception::error(scope, text);
            resolver.reject(scope, exception);
        }
    }
    Some(promise)
}

// ---------------------------------------------------------------------------
// AESCipherJob
// ---------------------------------------------------------------------------

/// `AESCipherJob`, the WebCrypto AES job.
///
/// Constructed by `lib/internal/crypto/aes.js` as
/// `new AESCipherJob(kCryptoJobWebCrypto, mode, keyHandle, data, variant,
/// [iv | counter, length | tagLength, additionalData])`, then `run()`.
pub struct AesCipherJob {
    mode: JobMode,
    cipher_mode: CipherMode,
    /// The secret key bytes, read out of the `KeyObjectHandle`.
    key: Vec<u8>,
    data: Vec<u8>,
    config: AesCipherConfig,
}

impl AesCipherJob {
    pub fn new(
        mode: JobMode,
        cipher_mode: CipherMode,
        key: Vec<u8>,
        data: Vec<u8>,
        config: AesCipherConfig,
    ) -> Self {
        Self {
            mode,
            cipher_mode,
            key,
            data,
            config,
        }
    }

    pub fn config(&self) -> &AesCipherConfig {
        &self.config
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl CryptoJob for AesCipherJob {
    fn name(&self) -> &'static str {
        "AESCipherJob"
    }

    fn is_async(&self) -> bool {
        // Every mode is computed inline; see the module docs. The field is kept
        // because the threadpool slice needs to distinguish the three modes, and
        // a job that reported `true` here would be claiming work it did not do.
        let _ = self.mode;
        false
    }

    fn compute(&mut self) -> JobResult {
        crate::aes::run(self.cipher_mode, &self.key, &self.data, &self.config)
    }
}

/// The native state behind one `AESCipherJob` object.
///
/// A `RefCell` behind an internal field with a finalizer, the same shape as
/// `CipherBase`'s, so a job that is collected before `run()` leaks nothing.
struct JobState {
    job: AesCipherJob,
    /// The `EVP_CIPHER_CTX` the `AESCipherConfig` resolved, created in the
    /// constructor so a bad variant or IV throws there rather than from `run()`.
    ///
    /// Unused by the AES paths that build their own context, and kept so the
    /// validation order matches Node's, where `AdditionalConfig` runs in the
    /// constructor.
    _validated: Option<CipherCtx>,
}

thread_local! {
    /// The job behind the object under construction.
    ///
    /// `CryptoJob`'s constructor stores its parameters with `new Job(env,
    /// args.This(), ...)`, so the state has to be attached after the arguments
    /// are read. A thread-local slot is the only way to hand it from the argument
    /// reader to the install step without a second allocation, and it is written
    /// and cleared inside one callback, so it cannot be observed half-set.
    static PENDING_JOB: RefCell<Option<JobState>> = const { RefCell::new(None) };
}

/// Builds the `AESCipherJob` constructor with `run()` on its prototype.
pub fn build_aes_cipher_job_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let template = v8::FunctionTemplate::builder(job_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    let prototype = template.prototype_template(scope);
    let key = v8::String::new(scope, "run").ok_or("cannot allocate AESCipherJob.run")?;
    prototype.set(
        key.into(),
        v8::FunctionTemplate::builder(job_run).build(scope).into(),
    );
    let class_name =
        v8::String::new(scope, "AESCipherJob").ok_or("cannot allocate the AESCipherJob name")?;
    template.set_class_name(class_name);
    template
        .get_function(scope)
        .ok_or_else(|| "cannot allocate the AESCipherJob constructor".to_string())
}

/// `new AESCipherJob(mode, cipherMode, key, data, variant, ...)`.
fn job_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();

    let Some(mode) = v8::Local::<v8::Int32>::try_from(args.get(0))
        .ok()
        .and_then(|value| JobMode::from_number(value.value()))
    else {
        throw_type_error(scope, "Unsupported CryptoJobMode");
        return;
    };
    let Some(cipher_mode) = v8::Local::<v8::Uint32>::try_from(args.get(1))
        .ok()
        .and_then(|value| CipherMode::from_number(value.value()))
    else {
        throw_type_error(scope, "Unsupported cipher mode");
        return;
    };
    let Some(key) = secret_key_bytes(scope, args.get(2)) else {
        return;
    };
    let Some(data) = super::evp_binding::bytes_argument_public(args.get(3)) else {
        throw_type_error(scope, "data must be a buffer source");
        return;
    };

    match AesCipherConfig::from_arguments(scope, &args, 4, &args.get(1)) {
        Ok(config) => {
            PENDING_JOB.with(|slot| {
                *slot.borrow_mut() = Some(JobState {
                    job: AesCipherJob::new(mode, cipher_mode, key, data, config),
                    _validated: None,
                });
            });
            install_job_state(scope, this);
            rv.set(this.into());
        }
        Err(error) => {
            if !scope.is_execution_terminating() {
                throw_cipher_error(scope, &error);
            }
        }
    }
}

/// `AESCipherJob.prototype.run()`.
fn job_run<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let promise = with_job_state(this, |state| run_job(scope, &mut state.job)).flatten();
    match promise {
        Some(promise) => rv.set(promise.into()),
        None => throw_type_error(scope, "the job handle is not initialised"),
    }
}

fn install_job_state(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<'_, v8::Object>) {
    let Some(state) = PENDING_JOB.with(|slot| slot.borrow_mut().take()) else {
        return;
    };
    let pointer = Box::into_raw(Box::new(RefCell::new(state)));
    object.set_aligned_pointer_in_internal_field(
        0,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut RefCell<JobState>;
            // SAFETY: allocated by `install_job_state` and freed exactly once.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
}

fn with_job_state<R>(
    object: v8::Local<'_, v8::Object>,
    body: impl FnOnce(&mut JobState) -> R,
) -> Option<R> {
    // SAFETY: the pointer comes from `install_job_state` and is owned by
    // `object`.
    let pointer =
        unsafe { object.get_aligned_pointer_from_internal_field(0, 0) } as *mut RefCell<JobState>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

/// Reads the secret key bytes out of a `KeyObjectHandle`.
///
/// `CipherJob<CipherTraits>::New` does `key->Data().addRef()`; the equivalent is
/// a copy, because the job outlives the `KeyObjectHandle` object and holding a
/// reference into it would need the `KeyObject` ownership model that slice S2
/// owns. `AESCipherJob` only ever reads the bytes once.
///
/// The handle is duck-typed on purpose: the three methods used are the ones
/// `lib/internal/crypto/keys.js` calls at lines 1072 and beyond, so a shape
/// change there breaks this loudly rather than silently reading the wrong bytes.
fn secret_key_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Vec<u8>> {
    let Ok(handle) = v8::Local::<v8::Object>::try_from(value) else {
        throw_type_error(scope, "key must be a KeyObjectHandle");
        return None;
    };
    // `getKeyType()` must report `kKeyTypeSecret` (1).
    let key_type = call_number(scope, handle, "getKeyType");
    match key_type {
        Some(1) => {}
        Some(_) => {
            throw_type_error(scope, "key must be a secret KeyObject");
            return None;
        }
        None => {
            throw_type_error(scope, "key must be a KeyObjectHandle");
            return None;
        }
    }
    // `export()` on a secret handle returns the raw key bytes.
    let exported = call_method(scope, handle, "export")?;
    super::evp_binding::bytes_argument_public(exported)
}

fn call_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    let function = object.get(scope, key.into())?;
    let function = v8::Local::<v8::Function>::try_from(function).ok()?;
    function.call(scope, object.into(), &[])
}

fn number_from_value(value: v8::Local<'_, v8::Value>) -> Option<u32> {
    if let Ok(value) = v8::Local::<v8::Uint32>::try_from(value) {
        return Some(value.value());
    }
    let value = v8::Local::<v8::Int32>::try_from(value).ok()?;
    Some(value.value() as u32)
}

fn call_number<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<u32> {
    number_from_value(call_method(scope, object, name)?)
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

fn throw_cipher_error(scope: &mut v8::PinScope<'_, '_>, error: &CipherError) {
    let message = error.message();
    let Some(text) = v8::String::new(scope, &message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}
