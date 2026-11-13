//! The `CryptoJob` machinery: three modes, one trait.
//!
//! `RsaKeyPairGenJob`, `EcKeyPairGenJob`, `NamedKeyPairGenJob` and
//! `SecretKeyGenJob` are all `AsyncWrap` + `ThreadPoolWork` subclasses of Node's
//! `CryptoJob<KeyGenTraits>` template. The JavaScript builds every one of them
//! with the same constructor signature — `mode` in slot 0 followed by the job's
//! own parameters — and then calls `run()`, whose meaning depends on `mode`:
//!
//! | mode | `run()` returns | completion |
//! | --- | --- | --- |
//! | `kCryptoJobSync` (1) | `[err, result]` | immediate, before `run()` returns |
//! | `kCryptoJobAsync` (0) | `undefined` | `job.ondone(err, result)` from the threadpool |
//! | `kCryptoJobWebCrypto` (2) | `[err, result]` | immediate |
//!
//! # Sync must not need the threadpool
//!
//! About 35 of the DH/EC/RSA tests use only the sync form, and a sync job that
//! went through `uv_queue_work` would have to pump the loop to make progress —
//! which it cannot do from inside a V8 callback. So the sync mode computes inline
//! and returns the tuple.
//!
//! # Async really queues
//!
//! `kCryptoJobAsync` puts the work on libuv's threadpool through `uv_queue_work`
//! and delivers the result through `ondone` from the loop. Two consequences drive
//! the design here:
//!
//! * the work runs on a pool thread, so the job must be `Send` and must not touch
//!   V8 while running;
//! * the completion runs inside `uv_run`, which has no V8 scope, so delivering the
//!   result needs [`rn_uv::callback::with_context`] — the same primitive the
//!   socket bindings use.
//!
//! A job that is dropped while queued still completes: `uv_queue_work` holds a
//! `uv_work_t` and the pool calls the after-work callback regardless, which is why
//! the queue slot owns the work and the callback state rather than reading them
//! off the JavaScript object.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;

use rn_v8_sys::v8;

use crate::errors::KeyError;

/// `CryptoJobMode` from `crypto_util.h`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobMode {
    /// `kCryptoJobAsync` (0): queued on the threadpool, completes through
    /// `ondone`.
    Async,
    /// `kCryptoJobSync` (1): computed before `run()` returns.
    Sync,
    /// `kCryptoJobWebCrypto` (2): the WebCrypto form, which also completes
    /// inline but returns `CryptoKey`s rather than `KeyObject`s.
    WebCrypto,
}

impl JobMode {
    /// Reads the mode the JavaScript passed in slot 0.
    pub fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Async,
            1 => Self::Sync,
            2 => Self::WebCrypto,
            _ => return None,
        })
    }

    /// Whether `run()` completes before it returns.
    pub fn is_inline(self) -> bool {
        !matches!(self, Self::Async)
    }
}

/// The work a job performs, and how its result reaches JavaScript.
///
/// The two halves are separate calls because they run on different threads.
/// `run` is `&mut self` and takes no scope: it is called on a pool thread for an
/// async job, where V8 must not be touched. `encode` is called on the main thread
/// with a scope, and it is where a `KeyObject` or a `CryptoKey` is built.
pub trait Runnable: Send + 'static {
    /// The completed result, ready to be turned into a JavaScript value.
    ///
    /// Sending a `KeyData` rather than a `v8::Global` is what keeps this across a
    /// thread boundary; the handle is built on the main thread in `encode`.
    type Output: Send + 'static;

    /// Performs the work.
    fn run(&mut self) -> Result<Self::Output, KeyError>;

    /// Turns a finished output into the JavaScript result.
    ///
    /// Returning `None` after throwing is allowed and propagates the pending
    /// exception, exactly as `ToResult`'s `Nothing<void>` does.
    fn encode<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>>;
}

/// The state an in-flight async job needs, keyed by its `uv_work_t` address.
///
/// Boxed and owned by the request, because the pool calls back with the request
/// and the JavaScript object may be gone by then.
pub struct QueuedJob<J: Runnable> {
    /// The job, taken out by the work callback and put back for `encode`.
    pub job: Mutex<Option<J>>,
    /// The completed output, written by the work callback.
    pub output: Mutex<Option<Result<J::Output, KeyError>>>,
    /// The `ondone` callback, rooted while the job is queued.
    pub ondone: Mutex<Option<v8::Global<v8::Function>>>,
    /// The receiver `ondone` is called on, which is the job object.
    pub receiver: Mutex<Option<v8::Global<v8::Object>>>,
}

thread_local! {
    /// The `uv_work_t` allocations in flight, so a request address can be
    /// recognised as ours.
    ///
    /// A raw-pointer key because that is the identity libuv hands back. Removing
    /// the entry in the after-work callback is what frees it, including when the
    /// loop is shutting down.
    ///
    /// The same addresses are registered with [`rn_uv::threadpool`], which is
    /// what the process exit path cancels: a keygen still queued when
    /// `process.exit()` runs would otherwise keep touching OpenSSL after
    /// `OPENSSL_cleanup` freed it.
    static IN_FLIGHT: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
}

/// Runs a job in the requested mode and returns what `run()` should return.
///
/// `None` means the async path was taken and `run()` must return `undefined`.
pub fn dispatch<'s, J: Runnable + 'static>(
    scope: &mut v8::PinScope<'s, '_>,
    mode: JobMode,
    mut job: J,
    receiver: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Value>> {
    if mode.is_inline() {
        let result = job.run();
        return Some(inline_result(scope, &job, result));
    }
    queue_async(scope, job, receiver);
    None
}

/// Builds the `[error, result]` array a sync `run()` returns.
///
/// The error travels as a *value* in slot 0 rather than as a thrown exception:
/// `generateKeyPairSync`'s `handleError` reads `ret[0]` and throws it itself.
fn inline_result<'s, J: Runnable>(
    scope: &mut v8::PinScope<'s, '_>,
    job: &J,
    result: Result<J::Output, KeyError>,
) -> v8::Local<'s, v8::Value> {
    let undefined = v8::undefined(scope);
    let (error, value): (v8::Local<'s, v8::Value>, v8::Local<'s, v8::Value>) = match result {
        Ok(output) => match job.encode(scope, output) {
            Some(value) => (undefined.into(), value),
            None => (undefined.into(), undefined.into()),
        },
        Err(error) => (error_value(scope, &error), undefined.into()),
    };
    v8::Array::new_with_elements(scope, &[error, value]).into()
}

/// Builds an error object without throwing it, for the `[err, result]` tuple.
pub fn error_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    error: &KeyError,
) -> v8::Local<'s, v8::Value> {
    let message = error.message();
    let Some(text) = v8::String::new(scope, &message) else {
        return v8::undefined(scope).into();
    };
    let exception = if error.is_type_error() {
        v8::Exception::type_error(scope, text)
    } else {
        v8::Exception::error(scope, text)
    };
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let Some(code) = error.code() {
            if let (Some(key), Some(value)) =
                (v8::String::new(scope, "code"), v8::String::new(scope, code))
            {
                object.set(scope, key.into(), value.into());
            }
        }
    }
    exception
}

/// Queues a job on libuv's threadpool.
fn queue_async<'s, J: Runnable + 'static>(
    scope: &mut v8::PinScope<'s, '_>,
    job: J,
    receiver: v8::Local<'s, v8::Object>,
) {
    // The `ondone` callback and the receiver are rooted now: they belong to this
    // job object and must survive the queue even if JavaScript drops its last
    // reference.
    let ondone = match property_function(scope, receiver, "ondone") {
        Some(callback) => v8::Global::new(scope.as_ref(), callback),
        None => {
            // `generateKeyPair` always sets one. Without it there is nowhere to
            // deliver a result, so the work is not queued at all rather than
            // computed and thrown away.
            return;
        }
    };
    let receiver = v8::Global::new(scope.as_ref(), receiver);

    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        // No loop means no threadpool. Delivering the failure through `ondone`
        // keeps the contract, rather than leaving a promise unresolved.
        deliver::<J>(
            scope,
            &ondone,
            &receiver,
            Err(KeyError::OperationFailed("No event loop")),
            None,
        );
        return;
    };

    let state = Box::new(QueuedJob {
        job: Mutex::new(Some(job)),
        output: Mutex::new(None),
        ondone: Mutex::new(Some(ondone)),
        receiver: Mutex::new(Some(receiver)),
    });
    let state = Box::into_raw(state);

    let mut request: Box<libuv_sys2::uv_work_t> = Box::new(unsafe { std::mem::zeroed() });
    request.data = state.cast();
    let request = Box::into_raw(request);
    IN_FLIGHT.with(|slot| {
        slot.borrow_mut().insert(request as usize, request as usize);
    });
    // Also visible to the exit path, which cancels it if `process.exit()` runs
    // while this job is still queued.
    rn_uv::threadpool::register(request);

    // SAFETY: `loop_pointer` is the process loop, which outlives the request;
    // `request` is heap-allocated and stays valid until the after-work callback
    // frees it.
    let queued = unsafe {
        libuv_sys2::uv_queue_work(
            loop_pointer,
            request,
            Some(work_trampoline::<J>),
            Some(after_work_trampoline::<J>),
        )
    };
    if queued != 0 {
        // The loop refused the work and no callback will arrive, so the request
        // and its state are freed here and the failure is reported inline.
        IN_FLIGHT.with(|slot| slot.borrow_mut().remove(&(request as usize)));
        rn_uv::threadpool::unregister(request);
        // SAFETY: both boxes were created just above and no callback owns them.
        let state = unsafe { Box::from_raw(state) };
        unsafe { drop(Box::from_raw(request)) };
        let ondone = state.ondone.lock().ok().and_then(|mut slot| slot.take());
        let receiver = state.receiver.lock().ok().and_then(|mut slot| slot.take());
        if let (Some(ondone), Some(receiver)) = (ondone, receiver) {
            deliver::<J>(
                scope,
                &ondone,
                &receiver,
                Err(KeyError::OperationFailed("Cannot queue the job")),
                None,
            );
        }
    }
}

/// The threadpool half: runs `Runnable::run` off the main thread.
///
/// # Safety
///
/// `request` must be the `uv_work_t` `queue_async` allocated, whose `data` is the
/// `QueuedJob<J>` box for this job.
unsafe extern "C" fn work_trampoline<J: Runnable + 'static>(request: *mut libuv_sys2::uv_work_t) {
    // SAFETY: per the contract above, `data` is the box `queue_async` created.
    let state = unsafe { &*((*request).data as *mut QueuedJob<J>) };
    let result = {
        let mut slot = match state.job.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        match slot.as_mut() {
            Some(job) => job.run(),
            // Taken twice would be a libuv contract violation; there is nothing
            // to run, so the job reports the failure.
            None => Err(KeyError::OperationFailed("Job already ran")),
        }
    };
    let mut output = match state.output.lock() {
        Ok(output) => output,
        Err(poisoned) => poisoned.into_inner(),
    };
    *output = Some(result);
}

/// The loop half: encodes the result and calls `ondone`.
///
/// # Safety
///
/// As [`work_trampoline`].
unsafe extern "C" fn after_work_trampoline<J: Runnable + 'static>(
    request: *mut libuv_sys2::uv_work_t,
    _status: std::ffi::c_int,
) {
    // SAFETY: `state` and `request` were created by `queue_async` and are freed
    // here, exactly once, now that no other callback will use them.
    let state = unsafe { Box::from_raw((*request).data as *mut QueuedJob<J>) };
    IN_FLIGHT.with(|slot| slot.borrow_mut().remove(&(request as usize)));
    rn_uv::threadpool::unregister(request);
    unsafe { drop(Box::from_raw(request)) };

    let output = state
        .output
        .lock()
        .ok()
        .and_then(|mut slot| slot.take())
        .unwrap_or_else(|| Err(KeyError::OperationFailed("Job produced no result")));
    let ondone = state.ondone.lock().ok().and_then(|mut slot| slot.take());
    let receiver = state.receiver.lock().ok().and_then(|mut slot| slot.take());
    let job = state.job.lock().ok().and_then(|mut slot| slot.take());
    let (Some(ondone), Some(receiver), Some(job)) = (ondone, receiver, job) else {
        return;
    };

    // The completion runs inside `uv_run`, which has no V8 scope and no entered
    // context, so the call has to go through the same primitive the socket
    // bindings use.
    rn_uv::callback::with_context(|scope| {
        deliver_from_thread(scope, &job, &ondone, &receiver, output);
    });
}

/// Calls `ondone(error, result)` with an already-computed result.
fn deliver<'s, J: Runnable>(
    scope: &mut v8::PinScope<'s, '_>,
    ondone: &v8::Global<v8::Function>,
    receiver: &v8::Global<v8::Object>,
    error: Result<J::Output, KeyError>,
    job: Option<&J>,
) {
    let callback: v8::Local<v8::Function> = v8::Local::new(scope, ondone);
    let receiver: v8::Local<v8::Object> = v8::Local::new(scope, receiver);
    let undefined = v8::undefined(scope);
    let (first, second): (v8::Local<'s, v8::Value>, v8::Local<'s, v8::Value>) = match error {
        Ok(output) => match job.and_then(|job| job.encode(scope, output)) {
            Some(value) => (undefined.into(), value),
            None => (undefined.into(), undefined.into()),
        },
        Err(error) => (error_value(scope, &error), undefined.into()),
    };
    // `MakeCallback` wraps the delivery in a `TryCatch` and routes a throw
    // through `TriggerUncaughtException`. A keygen completion has no caller left
    // to handle one, so dropping the result would print the error and still exit
    // 0. This covers both the threadpool path and the synchronous one, which
    // share this function.
    let caught = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let inner = &mut try_catch.init();
        let _ = callback.call(inner, receiver.into(), &[first, second]);
        inner
            .exception()
            .map(|exception| v8::Global::new(inner, exception))
    };
    if let Some(caught) = caught {
        let exception = v8::Local::new(scope, &caught);
        rn_errors::report_uncaught_exception(scope, exception);
    }
}

/// [`deliver`] for the loop's own callback, which has an owned job.
fn deliver_from_thread<'s, J: Runnable>(
    scope: &mut v8::PinScope<'s, '_>,
    job: &J,
    ondone: &v8::Global<v8::Function>,
    receiver: &v8::Global<v8::Object>,
    output: Result<J::Output, KeyError>,
) {
    deliver(scope, ondone, receiver, output, Some(job));
}

/// Reads a function-valued property.
fn property_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, name)?;
    let value = object.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mode_values_are_nodes() {
        // These are the `kCryptoJob*` constants `rn-bind-crypto` installs and
        // `keygen.js` passes; a drift here would silently select the wrong path.
        assert_eq!(JobMode::from_raw(0), Some(JobMode::Async));
        assert_eq!(JobMode::from_raw(1), Some(JobMode::Sync));
        assert_eq!(JobMode::from_raw(2), Some(JobMode::WebCrypto));
        assert_eq!(JobMode::from_raw(3), None);
        assert_eq!(JobMode::from_raw(-1), None);
    }

    #[test]
    fn only_async_is_deferred() {
        assert!(!JobMode::Async.is_inline());
        assert!(JobMode::Sync.is_inline());
        assert!(JobMode::WebCrypto.is_inline());
    }
}
