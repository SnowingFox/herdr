//! Node's `CryptoJob` machinery, shared by every `*Job` class the `crypto`
//! namespace installs.
//!
//! `src/crypto/crypto_util.h` defines `CryptoJob<CryptoJobTraits>` and
//! `src/threadpoolwork-inl.h` defines the `ThreadPoolWork` base it rides on.
//! Together they are one protocol with three modes, and every job class in
//! `src/crypto/**` is a `DeriveBitsJob` or a key-generation job over the same
//! skeleton:
//!
//! | mode | `run()` returns | completion |
//! | --- | --- | --- |
//! | `kCryptoJobSync` (1) | `[err, result]` | before `run()` returns |
//! | `kCryptoJobAsync` (0) | `undefined` | `job.ondone(err, result)` from the loop |
//! | `kCryptoJobWebCrypto` (2) | a `Promise` | resolved or rejected from the loop |
//!
//! # Why this is one crate and not four copies
//!
//! `rn-bind-crypto`, `rn-bind-crypto-keys`, `rn-bind-crypto-sign` and
//! `rn-bind-crypto-cipher` each own a slice of the namespace, and each needs the
//! same three-mode dispatch. Four copies is how the modes drift: one crate
//! resolving a promise `run()` returned synchronously, another forgetting that
//! `kCryptoJobWebCrypto` also queues, a third delivering `ondone` with the
//! arguments swapped. [`dispatch`] is that dispatch, written once.
//!
//! # Async really is asynchronous
//!
//! `kCryptoJobAsync` and `kCryptoJobWebCrypto` put their work on libuv's
//! threadpool through `uv_queue_work` and deliver from the completion, never
//! from `run()`. That is not a detail a caller can be expected to overlook:
//! `crypto.randomBytes(n, cb)` promises `cb` runs after the current turn, and a
//! job that called it inline would satisfy every test that only checks the
//! bytes. The ordering is part of the contract, so this module implements it
//! rather than documenting the difference.
//!
//! Two consequences drive the shape below:
//!
//! * the work runs on a pool thread, so it must be `Send` and must not touch
//!   V8 while running — [`Runnable::run`] takes no scope for that reason;
//! * the completion runs inside `uv_run`, which has no V8 scope, so delivering
//!   the result goes through [`rn_uv::callback`] and builds every JavaScript
//!   value on the main thread in [`Runnable::finish`].
//!
//! # The three completion value shapes
//!
//! A trait rather than one hard-coded shape because the jobs genuinely differ:
//!
//! * [`Completion::Callback`] — `ondone(err, value, ...)`; the fs-style jobs and
//!   `randomFill`, which passes the buffer back through a bound closure.
//! * [`Completion::Promise`] — the WebCrypto jobs, whose `run()` returns a
//!   promise settled from the completion.
//! * [`Completion::Tuple`] — the sync form only; `run()` returns `[err, value]`
//!   and there is no completion to deliver.
//!
//! [`Runnable::finish`] returns the JavaScript arguments, so a class supplies
//! its own arity without this module knowing what it is delivering.

use std::sync::Mutex;

use rn_v8_sys::v8;

mod error;
pub mod sync;

pub use error::{CryptoJobError, OpenSslDetail};

/// `CryptoJobMode` from `crypto_util.h`, the value `lib/**` passes in slot 0.
///
/// The numbers are an internal protocol between this crate and the vendored
/// JavaScript: `lib/**` never compares them, it only passes one of the three
/// constants the namespace exports, so a drift would be silent. `rn-bind-crypto`
/// installs the matching `kCryptoJob*` members and its tests pin them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobMode {
    /// `kCryptoJobAsync`: queued, completes through `ondone`.
    Async,
    /// `kCryptoJobSync`: computed before `run()` returns.
    Sync,
    /// `kCryptoJobWebCrypto`: queued, settles the promise `run()` returned.
    WebCrypto,
}

impl JobMode {
    /// Reads the mode from the constructor's first argument.
    ///
    /// `None` for anything that is not one of the three, which is what Node's
    /// `GetCryptoJobMode` turns into a `CHECK`. A job cannot be built with an
    /// unknown mode, so the callers throw rather than defaulting.
    pub fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Async,
            1 => Self::Sync,
            2 => Self::WebCrypto,
            _ => return None,
        })
    }

    /// The `kCryptoJob*` value, for tests and for re-reading a stored mode.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Async => 0,
            Self::Sync => 1,
            Self::WebCrypto => 2,
        }
    }

    /// Whether `run()` completes before it returns.
    ///
    /// Only `Sync` does. `WebCrypto` looks synchronous from JavaScript because
    /// it returns a promise, but the promise is settled from the threadpool, so
    /// it is queued like `Async`.
    pub fn is_inline(self) -> bool {
        matches!(self, Self::Sync)
    }
}

/// The work a job performs, split into the off-thread half and the main-thread
/// half.
///
/// `run` is called on a pool thread for a queued job and must not touch V8
/// (hence no scope argument and the `Send` bound). `finish` is called on the
/// main thread with a scope open and turns the computed value into the
/// JavaScript result; returning `None` after throwing is allowed and leaves the
/// pending exception in place.
pub trait Runnable: Send + 'static {
    /// The computed result, which has to cross a thread boundary.
    type Output: Send + 'static;

    /// Performs the work. No V8 access is possible here.
    fn run(&mut self) -> Result<Self::Output, CryptoJobError>;

    /// Turns a finished result into the JavaScript value `ondone` receives.
    fn finish<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>>;
}

/// How a job's result reaches JavaScript.
///
/// `Callback` and `Promise` are the two queued shapes; `Tuple` is the sync one,
/// and a queued job never uses it.
pub enum Completion {
    /// `job.ondone(...)` on the object the job was constructed on.
    Callback,
    /// Settle the promise `run()` returned.
    Promise,
    /// `run()` returns `[error, value]` directly.
    Tuple,
}

/// What a job's properties are read from, and what `ondone` is called on.
///
/// A `v8::Global` rather than a local because the queued path roots it: the
/// JavaScript object may otherwise be collected between `run()` and the
/// completion, and Node's `CryptoJob` keeps its `AsyncWrap` object alive the
/// same way.
pub struct Handle {
    /// The job object, which is also `ondone`'s receiver.
    pub receiver: v8::Global<v8::Object>,
}

/// The state an in-flight queued job owns.
///
/// Boxed and handed to libuv, because the pool calls back with the request and
/// the JavaScript object may already be unreachable: nothing here may be read
/// off the object during the completion.
struct Queued<J: Runnable> {
    /// The work, taken by the pool thread.
    job: Mutex<Option<J>>,
    /// The result the pool thread wrote.
    output: Mutex<Option<Result<J::Output, CryptoJobError>>>,
    /// `job.ondone`, rooted for the `Callback` shape.
    ondone: Mutex<Option<v8::Global<v8::Function>>>,
    /// The receiver `ondone` is called on, rooted.
    receiver: Mutex<Option<v8::Global<v8::Object>>>,
    /// The promise `run()` returned, rooted for the `Promise` shape.
    ///
    /// Which shape a completion takes is encoded by which of these two is
    /// `Some`, so there is no separate mode field to disagree with them.
    resolver: Mutex<Option<v8::Global<v8::PromiseResolver>>>,
    /// The job's `AsyncWrap` identity, so `ondone` runs inside it.
    ///
    /// `CryptoJob::AfterThreadPoolWork` delivers through `ptr->MakeCallback`,
    /// which pushes the job's own context before calling and emits `after` on
    /// the way out; `None` for a class that never emitted an `init`.
    async_wrap: Option<JobAsyncWrap>,
}

impl<J: Runnable> Queued<J> {
    /// Takes a field out of its `Mutex`, recovering from a poisoned lock.
    ///
    /// A poison means a previous holder panicked. The values already stored are
    /// still owned and still valid, so recovering is better than losing them and
    /// leaving a promise unsettled or `ondone` uncalled.
    fn take<T>(slot: &Mutex<Option<T>>) -> Option<T> {
        match slot.lock() {
            Ok(mut slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        }
    }
}

/// Runs a job in the requested mode.
///
/// Returns what `run()` should return: `None` for the queued modes, which have
/// nothing to return synchronously (`undefined` for `Async`, the promise for
/// `WebCrypto`), and `Some(_)` for `Sync`.
///
/// `completion` is the shape the class wants. `Sync` ignores it and always
/// returns the tuple, because that is the only thing the sync callers
/// destructure — `lib/**` reads `const { 0: err, 1: value } = job.run()`.
/// `CryptoJob`'s `AsyncWrap` identity, as the dispatch needs it.
///
/// `CryptoJob(env, object, type, mode, ...) : AsyncWrap(env, object, type)`
/// (`src/crypto/crypto_util.h:339-345`), so every job class is an async resource
/// whose provider comes from the trait — `RANDOMBYTESREQUEST`,
/// `PBKDF2REQUEST`, `KEYPAIRGENREQUEST` and so on. `AfterThreadPoolWork` then
/// runs `ptr->MakeCallback(ondone, ...)`, which pushes that resource's context
/// and emits `before`/`after` around the delivery.
///
/// The ids are handed to [`dispatch`] rather than read back from the object
/// because the job class's internal field is already the job itself, and because
/// the sync and WebCrypto modes have different completion paths that both need
/// the same pair.
#[derive(Clone, Copy)]
pub struct JobAsyncWrap {
    /// The `init` id the job's constructor emitted.
    pub async_id: f64,
    /// The trigger id that `init` carried.
    pub trigger_async_id: f64,
}

impl JobAsyncWrap {
    /// The `AsyncWrap` context `MakeCallback` pushes.
    pub fn context(self) -> rn_core::callback_scope::AsyncContext {
        rn_core::callback_scope::AsyncContext {
            async_id: self.async_id,
            trigger_async_id: self.trigger_async_id,
        }
    }
}

/// `dispatch` with the job's async identity, so its completion runs in scope.
///
/// The plain [`dispatch`] is for a class that has not emitted an `init`; this is
/// the one every `AsyncWrap`-derived job uses, and it is what makes
/// `crypto.randomBytes(n, cb)` report `RANDOMBYTESREQUEST` activity with a
/// matching `before`/`after`.
pub fn dispatch_with_async_wrap<'s, J: Runnable + 'static>(
    scope: &mut v8::PinScope<'s, '_>,
    mode: JobMode,
    mut job: J,
    receiver: v8::Local<'s, v8::Object>,
    completion: Completion,
    async_wrap: Option<JobAsyncWrap>,
) -> Option<v8::Local<'s, v8::Value>> {
    if mode == JobMode::Sync {
        let result = job.run();
        return Some(sync::tuple(scope, &job, result));
    }

    // `WebCrypto` returns a promise, so one is created here and settled from the
    // completion. Creating it before the work is what makes a rejection an
    // actual rejection rather than a throw out of `run()`: `jobPromise` in
    // `lib/internal/crypto/util.js` wraps `run()` in a `try`, so a throw would
    // become an `OperationError` with the real cause buried in `cause`.
    let resolver = if matches!(completion, Completion::Promise) {
        match v8::PromiseResolver::new(scope) {
            Some(resolver) => Some(resolver),
            None => return None,
        }
    } else {
        None
    };
    let promise = resolver.map(|resolver| resolver.get_promise(scope));

    queue(
        scope,
        job,
        receiver,
        completion,
        resolver.map(|resolver| v8::Global::new(scope.as_ref(), resolver)),
        async_wrap,
    );

    promise.map(v8::Local::into)
}

/// `dispatch` for a job with no async identity to report.
pub fn dispatch<'s, J: Runnable + 'static>(
    scope: &mut v8::PinScope<'s, '_>,
    mode: JobMode,
    job: J,
    receiver: v8::Local<'s, v8::Object>,
    completion: Completion,
) -> Option<v8::Local<'s, v8::Value>> {
    dispatch_with_async_wrap(scope, mode, job, receiver, completion, None)
}

/// Queues `job` on libuv's threadpool.
fn queue<'s, J: Runnable + 'static>(
    scope: &mut v8::PinScope<'s, '_>,
    job: J,
    receiver: v8::Local<'s, v8::Object>,
    completion: Completion,
    resolver: Option<v8::Global<v8::PromiseResolver>>,
    async_wrap: Option<JobAsyncWrap>,
) {
    // `ondone` and the receiver are rooted now: they belong to this job object
    // and must survive the queue even if JavaScript drops its last reference.
    let ondone = match completion {
        // A `Tuple` never reaches here, and a `Promise` has no `ondone`: the
        // promise is the delivery.
        Completion::Callback => match property_function(scope, receiver, "ondone") {
            Some(callback) => Some(v8::Global::new(scope.as_ref(), callback)),
            // Without a callback there is nowhere to deliver a result. Node's
            // `MakeCallback` on an absent `ondone` would throw; not queueing at
            // all leaves the caller with the same silently-missing callback and
            // no way to observe it, so the work is not started.
            None => return,
        },
        Completion::Promise | Completion::Tuple => None,
    };
    let receiver = v8::Global::new(scope.as_ref(), receiver);

    let state = Box::new(Queued {
        job: Mutex::new(Some(job)),
        output: Mutex::new(None),
        ondone: Mutex::new(ondone),
        receiver: Mutex::new(Some(receiver)),
        resolver: Mutex::new(resolver),
        async_wrap,
    });
    let state = Box::into_raw(state);

    let mut request: Box<libuv_sys2::uv_work_t> = Box::new(unsafe { std::mem::zeroed() });
    request.data = state.cast();
    let request = Box::into_raw(request);
    // Visible to the exit path, which cancels it if `process.exit()` runs while
    // the job is still queued.
    rn_uv::threadpool::register(request);

    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        // No loop means no threadpool, so no callback will arrive. The request
        // and its state are freed here and the failure goes through the same
        // delivery a completion would use, so the contract holds either way.
        // SAFETY: both boxes were just created and no callback owns them.
        let state = unsafe { Box::from_raw(state) };
        unsafe { drop(Box::from_raw(request)) };
        rn_uv::threadpool::unregister(request);
        deliver_inline(
            scope,
            &state,
            CryptoJobError::operation_failed("No event loop"),
        );
        return;
    };

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
        // and its state are freed here and the failure is reported through the
        // same delivery path a completion uses.
        rn_uv::threadpool::unregister(request);
        // SAFETY: both boxes were created above and no callback owns them.
        let state = unsafe { Box::from_raw(state) };
        unsafe { drop(Box::from_raw(request)) };
        deliver_inline(
            scope,
            &state,
            CryptoJobError::operation_failed("Cannot queue the job"),
        );
    }
}

/// Delivers a failure that happened before any work was queued.
fn deliver_inline<J: Runnable>(
    scope: &mut v8::PinScope<'_, '_>,
    state: &Queued<J>,
    error: CryptoJobError,
) {
    let ondone = Queued::<J>::take(&state.ondone);
    let receiver = Queued::<J>::take(&state.receiver);
    let resolver = Queued::<J>::take(&state.resolver);
    if let Some(resolver) = resolver {
        reject(scope, &resolver, &error);
        return;
    }
    let (Some(ondone), Some(receiver), Some(job)) =
        (ondone, receiver, Queued::<J>::take(&state.job))
    else {
        return;
    };
    call_ondone(scope, &ondone, &receiver, &job, Err(error));
}

/// The threadpool half: runs `Runnable::run` off the main thread.
///
/// # Safety
///
/// `request` must be the `uv_work_t` [`queue`] allocated, whose `data` is the
/// `Queued<J>` box for this job.
unsafe extern "C" fn work_trampoline<J: Runnable + 'static>(request: *mut libuv_sys2::uv_work_t) {
    // SAFETY: per the contract above, `data` is the box `queue` created, and
    // libuv calls the work callback exactly once per queued request.
    let state = unsafe { &*((*request).data as *mut Queued<J>) };
    let result = {
        let mut slot = match state.job.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        match slot.as_mut() {
            Some(job) => job.run(),
            // Taken twice would be a libuv contract violation; there is nothing
            // to run, so the job reports the failure rather than panicking on a
            // pool thread.
            None => Err(CryptoJobError::operation_failed("Job already ran")),
        }
    };
    let mut output = match state.output.lock() {
        Ok(output) => output,
        Err(poisoned) => poisoned.into_inner(),
    };
    *output = Some(result);
}

/// The loop half: encodes the result and delivers it.
///
/// # Safety
///
/// As [`work_trampoline`].
unsafe extern "C" fn after_work_trampoline<J: Runnable + 'static>(
    request: *mut libuv_sys2::uv_work_t,
    status: std::ffi::c_int,
) {
    // SAFETY: `state` and `request` were created by `queue` and are freed here,
    // exactly once, now that no other callback will use them.
    let state = unsafe { Box::from_raw((*request).data as *mut Queued<J>) };
    rn_uv::threadpool::unregister(request);
    unsafe { drop(Box::from_raw(request)) };

    // A cancelled request (`UV_ECANCELED`) ran no work. Node's async path
    // returns without calling `ondone` in that case, which is what the comment
    // in `CryptoJob::AfterThreadPoolWork` says is a known wart; a promise job
    // rejects instead, so the caller is not left pending forever.
    if status == libuv_sys2::uv_errno_t_UV_ECANCELED {
        let resolver = Queued::<J>::take(&state.resolver);
        if let Some(resolver) = resolver {
            rn_uv::callback::with_context(|scope| {
                reject(scope, &resolver, &CryptoJobError::Canceled);
            });
        }
        return;
    }

    let output = Queued::<J>::take(&state.output)
        .unwrap_or_else(|| Err(CryptoJobError::operation_failed("Job produced no result")));
    let ondone = Queued::<J>::take(&state.ondone);
    let receiver = Queued::<J>::take(&state.receiver);
    let resolver = Queued::<J>::take(&state.resolver);
    let job = Queued::<J>::take(&state.job);
    let Some(job) = job else {
        return;
    };

    // The completion runs inside `uv_run`, which has no V8 scope and no entered
    // context, so the call has to go through the same primitive the socket
    // bindings use.
    let async_wrap = state.async_wrap;
    rn_uv::callback::with_context(|scope| {
        // `CryptoJob::AfterThreadPoolWork` delivers through `ptr->MakeCallback`,
        // so the job's own async context is what executes during `ondone` and
        // its `before`/`after` pair is what a hook observes. `destroy` follows
        // as the job object is released.
        let call = |scoped: &mut v8::PinScope<'_, '_>| {
            if let Some(resolver) = &resolver {
                match output {
                    Ok(output) => resolve(scoped, resolver, &job, output),
                    Err(error) => reject(scoped, resolver, &error),
                }
                return;
            }
            let (Some(ondone), Some(receiver)) = (ondone.as_ref(), receiver.as_ref()) else {
                return;
            };
            call_ondone(scoped, ondone, receiver, &job, output);
        };
        match async_wrap {
            Some(async_wrap) if async_wrap.async_id > 0.0 => {
                let resource = receiver
                    .as_ref()
                    .map(|receiver| v8::Global::new(scope.as_ref(), v8::Local::<v8::Object>::new(scope, receiver)));
                let _ = rn_core::callback_scope::with_scope(
                    scope,
                    rn_core::callback_scope::ScopeArgs {
                        context: async_wrap.context(),
                        resource,
                        frame: None,
                    },
                    call,
                );
                // `CryptoJob` is released by `unique_ptr` in
                // `AfterThreadPoolWork`, which queues the destroy.
                rn_bind_async_wrap::emit_destroy(async_wrap.async_id);
            }
            _ => call(scope),
        }
    });
}

/// Settles a WebCrypto promise with the job's result.
///
/// A `finish` that throws rejects the promise with the thrown value directly
/// rather than wrapping it: the throw already carries the specific reason, and
/// `settleJobPromise` in `lib/internal/crypto/util.js` treats a rejection as the
/// error the caller sees.
fn resolve<J: Runnable>(
    scope: &mut v8::PinScope<'_, '_>,
    resolver: &v8::Global<v8::PromiseResolver>,
    job: &J,
    output: J::Output,
) {
    let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, resolver);
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let inner = &mut try_catch.init();
    let value = job.finish(inner, output);
    let thrown = inner
        .exception()
        .map(|exception| v8::Global::new(inner, exception));
    if let Some(thrown) = thrown {
        let exception: v8::Local<v8::Value> = v8::Local::new(inner, &thrown);
        resolver.reject(inner, exception);
        return;
    }
    match value {
        Some(value) => {
            resolver.resolve(inner, value);
        }
        None => reject_local(
            inner,
            resolver,
            &CryptoJobError::operation_failed("The job result could not be built"),
        ),
    }
}

/// Calls `ondone(error)` or `ondone(undefined, value)`.
///
/// The error travels as an *argument*, not a throw: every async caller in
/// `lib/**` is written as `job.ondone = (error, value) => ...`, and a throw here
/// would surface as an uncaught exception instead of reaching that callback.
fn call_ondone<J: Runnable>(
    scope: &mut v8::PinScope<'_, '_>,
    ondone: &v8::Global<v8::Function>,
    receiver: &v8::Global<v8::Object>,
    job: &J,
    result: Result<J::Output, CryptoJobError>,
) {
    let callback: v8::Local<v8::Function> = v8::Local::new(scope, ondone);
    let receiver: v8::Local<v8::Object> = v8::Local::new(scope, receiver);
    let undefined = v8::undefined(scope);
    let (first, second): (v8::Local<v8::Value>, v8::Local<v8::Value>) = match result {
        Ok(output) => match job.finish(scope, output) {
            Some(value) => (undefined.into(), value),
            None => (undefined.into(), undefined.into()),
        },
        Err(error) => (error.exception(scope), undefined.into()),
    };
    // The call runs inside `uv_run`, where a throw from the callback has no
    // caller left to handle it. Without this a callback that throws would be
    // swallowed: V8 prints the exception but no exit code is set, so the process
    // reports success after a fatal error.
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

/// Rejects a promise with the WebCrypto `OperationError` shape.
///
/// `CryptoJob::RejectWebCrypto` builds a `DOMException` named `OperationError`
/// with the cause attached, rather than rejecting with the raw error, because
/// WebCrypto's contract is a `DOMException` and the `cause` is where the real
/// reason goes. When the per-context `DOMException` is unavailable the error is
/// used directly, which is what Node does too.
fn reject(
    scope: &mut v8::PinScope<'_, '_>,
    resolver: &v8::Global<v8::PromiseResolver>,
    error: &CryptoJobError,
) {
    let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, resolver);
    reject_local(scope, resolver, error);
}

/// [`reject`] for a resolver that is already local on this thread.
fn reject_local(
    scope: &mut v8::PinScope<'_, '_>,
    resolver: v8::Local<v8::PromiseResolver>,
    error: &CryptoJobError,
) {
    let cause = error.exception(scope);
    match operation_error(scope, cause) {
        Some(exception) => {
            resolver.reject(scope, exception);
        }
        None => {
            resolver.reject(scope, cause);
        }
    }
}

/// The `DOMException` named `OperationError` wrapping `cause`.
fn operation_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    cause: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Value>> {
    let exports = rn_core::per_context::per_context_exports(scope)?;
    let key = v8::String::new(scope, "DOMException")?;
    let constructor = exports.get(scope, key.into())?;
    let constructor = v8::Local::<v8::Function>::try_from(constructor).ok()?;

    let options = v8::Object::new(scope);
    let name_key = v8::String::new(scope, "name")?;
    let name = v8::String::new(scope, "OperationError")?;
    options.set(scope, name_key.into(), name.into());
    let cause_key = v8::String::new(scope, "cause")?;
    options.set(scope, cause_key.into(), cause);

    // The message is `CreateWebCryptoJobError`'s, verbatim: WebCrypto tests
    // assert on it and it is not generated from the cause.
    let message = v8::String::new(
        scope,
        "The operation failed for an operation-specific reason",
    )?;
    let instance = constructor.new_instance(scope, &[message.into(), options.into()])?;
    Some(instance.into())
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
        // `lib/**` passes. A drift here would silently select the wrong path,
        // and a sync caller would receive a promise instead of a tuple.
        assert_eq!(JobMode::from_raw(0), Some(JobMode::Async));
        assert_eq!(JobMode::from_raw(1), Some(JobMode::Sync));
        assert_eq!(JobMode::from_raw(2), Some(JobMode::WebCrypto));
        assert_eq!(JobMode::from_raw(3), None);
        assert_eq!(JobMode::from_raw(-1), None);
    }

    #[test]
    fn only_sync_completes_inline() {
        assert!(JobMode::Sync.is_inline());
        assert!(!JobMode::Async.is_inline());
        // `WebCrypto` returns a promise, which reads as synchronous to a caller
        // that only looks at the return value. It is queued like `Async`, and
        // the distinction is exactly what this assertion pins.
        assert!(!JobMode::WebCrypto.is_inline());
    }

    #[test]
    fn the_raw_values_round_trip() {
        for mode in [JobMode::Async, JobMode::Sync, JobMode::WebCrypto] {
            assert_eq!(JobMode::from_raw(mode.as_raw()), Some(mode));
        }
    }
}
