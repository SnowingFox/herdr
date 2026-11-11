//! `napi_threadsafe_function`: calling into JavaScript from another thread.
//!
//! A thread-safe function is a queue plus a `uv_async_t`. A producer thread calls
//! `napi_call_threadsafe_function`, which appends its `void*` to the queue and
//! signals the async handle; the loop then runs the addon's `call_js_cb` — or the
//! function the addon created the TSFN with — on the isolate's own thread, where
//! touching V8 is legal.
//!
//! # Why this is real and not a queue drained on the calling thread
//!
//! `crates/rn-uv` links libuv itself, including `threadpool.c` and `uv_async_t`,
//! so the signal a producer sends really does wake a blocked `uv_run`. The
//! ordering Node's tests assert — producer enqueues on one thread, consumer runs
//! callback on the loop thread in a later iteration — is libuv's ordering here,
//! not something simulated. `test_threadsafe_function` spawns real `uv_thread_t`s
//! through `uv_thread_create`, so a synchronous stand-in would deadlock or drop
//! values rather than approximate them.
//!
//! # The state machine
//!
//! Node's `v8impl::ThreadSafeFunction` is a three-state machine (`kOpen`,
//! `kClosing`, `kClosed`) around a `thread_count` of threads that may still call
//! in, and this reproduces it rather than inventing a lifetime scheme:
//!
//! * `Open` — producers may push. `Acquire` and `Release` adjust the count.
//! * `Closing` — no more pushes for new threads; the async handle is being closed
//!   and queued values are still delivered (or, for a closing queue,
//!   `napi_closing` is returned to the pusher).
//! * `Closed` — the handle is gone and the finalizer has run. The allocation
//!   survives only until the last thread that still holds a pointer releases it,
//!   which is why the delete can happen on a producer thread rather than here.
//!
//! Getting this wrong is observable: `test_threadsafe_function_shutdown` checks
//! that a release from a second thread, or from inside the finalize callback,
//! does not double-free or leak the allocation.
//!
//! # Where the finalizer runs
//!
//! `thread_finalize_cb` runs exactly once, on the loop's thread, from the
//! `uv_close` completion callback. It runs *after* the queue has been drained
//! with `env == NULL`, which is how Node tells an addon "these values will never
//! reach JavaScript" without inventing a second callback shape.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use crate::abi::{
    NapiEnv, NapiFinalize, NapiStatus, NapiThreadsafeFunctionCallJs,
    NapiThreadsafeFunctionCallMode, NapiThreadsafeFunctionReleaseMode, NapiValue,
};
use crate::values::to_napi;

/// How many queued values one async callback delivers before rescheduling.
///
/// Node's `kMaxIterationCount`. Without a cap, a producer that keeps the queue
/// non-empty would hold the loop in this callback and starve timers and I/O —
/// which `test_threadsafe_function` exercises by pushing 10 000 values from one
/// thread while the loop is meant to keep turning.
const MAX_DISPATCH_BATCH: u32 = 1000;

/// Where a thread-safe function is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Producers may push values.
    Open,
    /// The async handle is closing; no new values are accepted.
    Closing,
    /// The finalizer has run. Only threads still holding a count keep the
    /// allocation alive.
    Closed,
}

/// Everything mutable, behind one lock.
///
/// One mutex rather than several: the producer's push and the consumer's pop
/// have to agree about the queue length, the state and the thread count
/// atomically, or a blocking push waits after the last pop that would have woken
/// it.
struct Shared {
    state: State,
    /// Threads that may still call in. `0` means no producer holds a pointer, so
    /// the allocation may be freed the moment the state reaches `Closed`.
    thread_count: usize,
    queue: VecDeque<*mut c_void>,
    /// `true` once `uv_close` has been called on the async handle.
    handles_closing: bool,
    /// Set when the finalizer has run, so it fires exactly once even if two
    /// teardown paths race.
    finalized: bool,
}

/// A `napi_threadsafe_function`.
///
/// The `uv_async_t` is a field, not a separate allocation: libuv keeps the
/// handle's address until its close callback runs, and one allocation means one
/// object to free. `Box` keeps the address stable for as long as the object
/// exists, which is what makes the pointer the addon holds a valid
/// `napi_threadsafe_function` for its whole life.
#[repr(C)]
pub struct ThreadSafeFunction {
    handle: uv::uv_async_t,
    shared: Mutex<Shared>,
    /// Wakes a producer blocked on a full queue when the consumer pops.
    space_available: Condvar,
    /// The function to call, rooted so it survives collection.
    ///
    /// Dropped on the loop's thread only: releasing a `v8::Global` touches the
    /// isolate, and Node does the same by resetting the reference from its
    /// teardown path.
    function: Mutex<Option<v8::Global<v8::Function>>>,
    /// The addon's `call_js_cb`, or `None` to use the default behaviour of
    /// calling `function` with no arguments.
    call_js: NapiThreadsafeFunctionCallJs,
    /// The addon's `void* context`, returned by
    /// `napi_get_threadsafe_function_context`.
    context: *mut c_void,
    finalize_cb: NapiFinalize,
    finalize_data: *mut c_void,
    env: *mut NapiEnv,
    /// The largest queue the addon will accept, or 0 for unbounded.
    max_queue_size: usize,
}

// SAFETY: every field is either `Sync` or a raw pointer that only carries an
// address. The mutable state is behind `Mutex`, and the two fields that are not
// (`handle`, `context`, the callbacks) are written once at creation and read
// without mutation afterwards. libuv's own contract is that `uv_async_send` may
// be called from any thread, and that is the only call a producer makes on
// `handle`.
unsafe impl Send for ThreadSafeFunction {}
// SAFETY: as above. Sharing `&ThreadSafeFunction` across threads is exactly the
// intended use; all mutation goes through the mutex.
unsafe impl Sync for ThreadSafeFunction {}

/// What `napi_create_threadsafe_function` supplies.
///
/// A struct rather than nine positional arguments because several are bare
/// pointers of the same type: `context`, `finalize_data` and the two callbacks are
/// easy to transpose at a call site, and the compiler cannot catch it. Named
/// fields make the shim's mapping readable and its mistakes visible.
pub(crate) struct NewThreadSafeFunction {
    pub(crate) env: *mut NapiEnv,
    /// The rooted function, or `None` when the addon passed a `call_js_cb`.
    pub(crate) function: Option<v8::Global<v8::Function>>,
    pub(crate) max_queue_size: usize,
    pub(crate) initial_thread_count: usize,
    pub(crate) finalize_data: *mut c_void,
    pub(crate) finalize_cb: NapiFinalize,
    pub(crate) context: *mut c_void,
    pub(crate) call_js: NapiThreadsafeFunctionCallJs,
    pub(crate) loop_pointer: *mut uv::uv_loop_t,
}

impl ThreadSafeFunction {
    /// Creates and initialises a TSFN, or returns the status to report.
    ///
    /// # Safety
    ///
    /// `settings.function` must be a handle from the caller's scope, or `None`.
    /// `settings.env` must be a live environment and `settings.loop_pointer` this
    /// thread's loop.
    pub(crate) unsafe fn create(settings: NewThreadSafeFunction) -> Result<*mut Self, NapiStatus> {
        let NewThreadSafeFunction {
            env,
            function,
            max_queue_size,
            initial_thread_count,
            finalize_data,
            finalize_cb,
            context,
            call_js,
            loop_pointer,
        } = settings;
        let mut object = Box::new(Self {
            // SAFETY: zeroed is libuv's own "not initialised" state for a handle;
            // `uv_async_init` fills it in.
            handle: unsafe { std::mem::zeroed() },
            shared: Mutex::new(Shared {
                state: State::Open,
                thread_count: initial_thread_count,
                queue: VecDeque::new(),
                handles_closing: false,
                finalized: false,
            }),
            space_available: Condvar::new(),
            function: Mutex::new(function),
            call_js,
            context,
            finalize_cb,
            finalize_data,
            env,
            max_queue_size,
        });
        let pointer = object.as_mut() as *mut Self;
        // SAFETY: `object` is the live allocation behind `pointer`, and the
        // handle sits inside it, so the address is stable until the object is
        // freed.
        let handle = unsafe { &mut (*pointer).handle as *mut uv::uv_async_t };
        // libuv's close callback recovers the object from the handle's `data`
        // slot, exactly as Node's `ContainerOf` does.
        // SAFETY: `handle` points into the live allocation `pointer`.
        unsafe { (*handle).data = pointer.cast() };
        // SAFETY: `handle` is a live, zeroed handle and `loop_pointer` is this
        // thread's loop. `on_async` is this module's trampoline.
        let status = unsafe { uv::uv_async_init(loop_pointer, handle, Some(on_async)) };
        if status != 0 {
            tracing::error!(status, "uv_async_init failed for a thread-safe function");
            return Err(NapiStatus::GenericFailure);
        }
        // The handle starts *ref'd*, which is what makes a live TSFN keep the
        // process alive until `napi_unref_threadsafe_function` says otherwise.
        // `test_threadsafe_function`'s unref case depends on this default. The
        // `Box` is released to the caller, which owns it until the close path
        // frees it.
        let _ = Box::into_raw(object);
        Ok(pointer)
    }

    /// The address of the async handle, for `uv_ref` / `uv_unref`.
    fn handle(&self) -> *mut uv::uv_async_t {
        // The field is inside `self`, and `&self` keeps the allocation alive, so
        // the address is stable and valid for as long as any caller needs it. The
        // `*const` to `*mut` cast is the same one libuv's C API requires for
        // `uv_ref`/`uv_unref`, which do not write through it; the mutable pointer
        // exists only because their signatures take one.
        &self.handle as *const uv::uv_async_t as *mut uv::uv_async_t
    }

    /// Wakes the loop so queued values are delivered.
    ///
    /// `uv_async_send` coalesces: several sends before the callback runs produce
    /// one callback, which is why no dispatch-state bookkeeping is needed here.
    /// Node keeps a `dispatch_state` to avoid a redundant atomic, not for
    /// correctness.
    fn send(&self) {
        // SAFETY: the handle was initialised by `create` and is only closed from
        // the loop thread after the state leaves `Open`, so a send from here is
        // always on a live handle.
        let status = unsafe { uv::uv_async_send(self.handle()) };
        if status != 0 {
            // Not fatal: the value stays queued and the next send, or the close
            // path, delivers it.
            tracing::debug!(status, "uv_async_send on a thread-safe function failed");
        }
    }

    /// `napi_call_threadsafe_function`.
    fn push(
        self_pointer: *const Self,
        data: *mut c_void,
        mode: NapiThreadsafeFunctionCallMode,
    ) -> NapiStatus {
        // SAFETY: the caller guarantees `self_pointer` is a live TSFN.
        let this = unsafe { &*self_pointer };
        let blocking = mode == NapiThreadsafeFunctionCallMode::Blocking;
        let mut shared = this.lock();

        while this.max_queue_size > 0
            && shared.queue.len() >= this.max_queue_size
            && shared.state == State::Open
        {
            if !blocking {
                return NapiStatus::QueueFull;
            }
            // A blocking push waits for the consumer to make room. Node waits on
            // a condition variable here for the same reason; the value is not
            // dropped, the producer is throttled.
            shared = match this.space_available.wait(shared) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }

        if shared.state == State::Open {
            shared.queue.push_back(data);
            // Released before signalling: `send` calls into libuv, and holding
            // the mutex across it would let the loop block behind a producer.
            drop(shared);
            this.send();
            return NapiStatus::Ok;
        }

        // Not open: this thread's hold is spent either way, and the value is
        // rejected. Node decrements before deciding what to report so that the
        // last thread to arrive is the one that frees the allocation.
        if shared.thread_count == 0 {
            return NapiStatus::InvalidArg;
        }
        shared.thread_count -= 1;
        let closed = shared.state == State::Closed && shared.thread_count == 0;
        drop(shared);
        if closed {
            // SAFETY: no thread holds a pointer any more and the handle is
            // closed, so this is the last reference.
            unsafe { Self::destroy(self_pointer) };
        }
        NapiStatus::Closing
    }

    /// `napi_acquire_threadsafe_function`.
    fn acquire(self_pointer: *const Self) -> NapiStatus {
        // SAFETY: the caller guarantees `self_pointer` is a live TSFN.
        let this = unsafe { &*self_pointer };
        let mut shared = this.lock();
        if shared.state == State::Open {
            shared.thread_count += 1;
            return NapiStatus::Ok;
        }
        NapiStatus::Closing
    }

    /// `napi_release_threadsafe_function`.
    fn release(self_pointer: *const Self, mode: NapiThreadsafeFunctionReleaseMode) -> NapiStatus {
        // SAFETY: the caller guarantees `self_pointer` is a live TSFN.
        let this = unsafe { &*self_pointer };
        let abort = mode == NapiThreadsafeFunctionReleaseMode::Abort;
        let (should_send, closed) = {
            let mut shared = this.lock();
            if shared.thread_count == 0 {
                // Releasing a hold that was never taken. Node reports this rather
                // than underflowing, because the next teardown decision depends on
                // the count being honest.
                return NapiStatus::InvalidArg;
            }
            shared.thread_count -= 1;

            let mut should_send = false;
            if (shared.thread_count == 0 || abort) && shared.state == State::Open {
                if abort {
                    shared.state = State::Closing;
                }
                if shared.state == State::Closing && this.max_queue_size > 0 {
                    this.space_available.notify_all();
                }
                should_send = true;
            }
            let closed = shared.state == State::Closed && shared.thread_count == 0;
            if should_send {
                // Waking a producer that is blocked on a full queue is what lets
                // `napi_tsfn_abort` unstick it; the send itself happens outside
                // the lock.
                this.space_available.notify_all();
            }
            (should_send, closed)
        };
        if should_send {
            this.send();
        }
        if closed {
            // SAFETY: as in `push`; this was the last hold.
            unsafe { Self::destroy(self_pointer) };
        }
        NapiStatus::Ok
    }

    /// Drops the roots and runs the addon's finalizer. Loop thread only.
    fn finalize(self_pointer: *const Self) {
        // SAFETY: the caller guarantees `self_pointer` is a live TSFN.
        let this = unsafe { &*self_pointer };
        {
            let mut shared = this.lock();
            if shared.finalized {
                return;
            }
            shared.finalized = true;
        }
        // Values still queued will never reach JavaScript. Node reports them to
        // the addon with a null `env` and a null callback, which is the documented
        // way for a `call_js_cb` to learn it must drop its payload.
        let leftover: Vec<*mut c_void> = {
            let mut shared = this.lock();
            shared.queue.drain(..).collect()
        };
        if !leftover.is_empty() {
            if let Some(call_js) = this.call_js {
                for data in leftover {
                    // SAFETY: `call_js` is the addon's own callback. Node passes
                    // null env and callback, and the context the addon gave.
                    unsafe {
                        call_js(ptr::null_mut(), ptr::null_mut(), this.context, data);
                    }
                }
            }
            // With the default callback there is nothing to tell: the values were
            // going to be passed to a JavaScript function that no longer exists.
        }

        if let Some(finalize_cb) = this.finalize_cb {
            let delivered = crate::scope::with_context(|scope| {
                let guard = crate::scope::ScopeGuard::enter(scope);
                // SAFETY: `finalize_cb` is the addon's own callback, `this.env` is
                // the environment it was created against, and the scope guard
                // makes any `napi_value` it creates valid.
                unsafe { finalize_cb(this.env, this.finalize_data, this.context) };
                drop(guard);
            });
            if delivered.is_none() {
                tracing::error!(
                    "a thread-safe function finalizer fired with no V8 context recorded; \
                     the addon's finalizer was not run"
                );
            }
        }

        // The rooted function is released here, on the loop's thread, where
        // touching the isolate is legal.
        if let Ok(mut slot) = this.function.lock() {
            drop(slot.take());
        }
    }

    /// Marks the state closed and frees the allocation if no thread still holds
    /// it. Loop thread only.
    fn maybe_delete(self_pointer: *const Self) {
        // SAFETY: the caller guarantees `self_pointer` is a live TSFN.
        let this = unsafe { &*self_pointer };
        let closed = {
            let mut shared = this.lock();
            shared.state = State::Closed;
            shared.thread_count == 0
        };
        if closed {
            // SAFETY: the handle is closed, the finalizer has run, and no thread
            // holds a pointer.
            unsafe { Self::destroy(self_pointer) };
        }
    }

    /// Closes the async handle and arranges for the finalizer to run.
    ///
    /// # Safety
    ///
    /// Must run on the loop's thread, which is where `uv_close` is legal.
    unsafe fn close_handles(self_pointer: *const Self) {
        // SAFETY: the caller guarantees `self_pointer` is a live TSFN on the
        // loop's thread.
        let this = unsafe { &*self_pointer };
        {
            let mut shared = this.lock();
            if shared.handles_closing {
                return;
            }
            shared.handles_closing = true;
        }
        // SAFETY: `this` is live and the handle inside it was initialised by
        // `create`. `on_closed` runs the finalizer once libuv has finished with
        // the handle.
        unsafe { uv::uv_close(this.handle().cast::<uv::uv_handle_t>(), Some(on_closed)) };
    }

    /// Frees the allocation.
    ///
    /// # Safety
    ///
    /// The handle must be closed and no thread may hold a pointer.
    unsafe fn destroy(self_pointer: *const Self) {
        // SAFETY: the caller guarantees this is the last reference, and the
        // pointer came from `Box::into_raw` in `create`.
        drop(unsafe { Box::from_raw(self_pointer as *mut Self) });
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        match self.shared.lock() {
            Ok(guard) => guard,
            // A poisoned lock means a producer panicked mid-push. The queue and
            // counters are still structurally sound, and Node has no equivalent
            // failure at all, so the state is used rather than dropping the value.
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// `uv_async_cb`: delivers queued values on the loop's thread.
///
/// # Safety
///
/// Called by libuv with the handle `create` initialised.
unsafe extern "C" fn on_async(handle: *mut uv::uv_async_t) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `create` stored the owning object in the handle's `data` slot, and
    // the object outlives the handle.
    let this_pointer = unsafe { (*handle).data.cast::<ThreadSafeFunction>() };
    if this_pointer.is_null() {
        return;
    }
    // SAFETY: as above; the pointer is the live object that owns this handle.
    let this = unsafe { &*this_pointer };

    for _ in 0..MAX_DISPATCH_BATCH {
        let (next, has_more, closing) = {
            let mut shared = this.lock();
            if shared.state != State::Open {
                (None, false, true)
            } else {
                let next = shared.queue.pop_front();
                if next.is_some() && this.max_queue_size > 0 {
                    this.space_available.notify_all();
                }
                let empty = shared.queue.is_empty();
                if empty && shared.thread_count == 0 {
                    // The last producer has released and the queue is drained:
                    // nothing can push again, so the handle can close.
                    shared.state = State::Closing;
                    this.space_available.notify_all();
                    (next, false, true)
                } else {
                    (next, !empty, false)
                }
            }
        };

        if let Some(data) = next {
            // The value is delivered outside the lock, because the addon's
            // callback runs arbitrary JavaScript which may push again.
            // SAFETY: `this` is live for the whole call: the handle is not closed
            // until `close_handles`, which happens after this callback returns.
            unsafe { deliver(this_pointer, data) };
        }

        if closing {
            // SAFETY: this is the loop's thread, and the state left `Open` above.
            unsafe { ThreadSafeFunction::close_handles(this_pointer) };
            return;
        }
        if !has_more {
            return;
        }
    }

    // Hit the batch cap with values still queued. Re-signal so the next
    // iteration delivers them instead of holding the loop here.
    this.send();
}

/// Runs the addon's JavaScript callback for one queued value.
///
/// # Safety
///
/// `this_pointer` must be a live TSFN on the loop's thread.
unsafe fn deliver(this_pointer: *const ThreadSafeFunction, data: *mut c_void) {
    // SAFETY: the caller guarantees the pointer is live.
    let this = unsafe { &*this_pointer };
    let delivered = crate::scope::with_context(|scope| {
        let guard = crate::scope::ScopeGuard::enter(scope);
        // The rooted function becomes a handle again inside this scope. It is
        // `None` when the addon passed no `func`, in which case `call_js_cb` is
        // required and receives null here, which is Node's contract.
        let callback_handle: *mut NapiValue = match this.function.lock() {
            Ok(slot) => match slot.as_ref() {
                Some(rooted) => {
                    let local: v8::Local<v8::Value> = v8::Local::new(scope, rooted).into();
                    to_napi(local)
                }
                None => ptr::null_mut(),
            },
            Err(_) => ptr::null_mut(),
        };
        match this.call_js {
            Some(call_js) => {
                // SAFETY: the addon's own callback, with the environment and
                // context it was created with. The scope guard is alive.
                unsafe { call_js(this.env, callback_handle, this.context, data) };
            }
            None => {
                // SAFETY: `callback_handle` was just built in this scope.
                unsafe { default_call_js(scope, callback_handle) };
            }
        }
        drop(guard);
    });
    if delivered.is_none() {
        tracing::error!(
            "a thread-safe function value arrived with no V8 context recorded; \
             it was dropped instead of being delivered"
        );
    }
}

/// The behaviour when an addon created a TSFN without a `call_js_cb`.
///
/// Node's `ThreadSafeFunction::CallJs`: call the function with no arguments and
/// `undefined` as the receiver.
///
/// # Safety
///
/// `callback` must be a handle from `scope`, which must be the current scope.
unsafe fn default_call_js(scope: &mut v8::PinScope<'_, '_, v8::Context>, callback: *mut NapiValue) {
    if callback.is_null() {
        return;
    }
    // SAFETY: the caller guarantees the handle is from the current scope.
    let Some(function) = (unsafe { crate::values::from_napi(callback) }) else {
        return;
    };
    let Some(function) = v8::Local::<v8::Function>::try_from(function).ok() else {
        // Not a function: the addon's own bug, and Node's default callback has no
        // env to throw through, so the value is dropped with a log rather than
        // pretending the call happened.
        tracing::error!("a thread-safe function's callback is not a function");
        return;
    };
    let receiver: v8::Local<v8::Value> = v8::undefined(&**scope).into();
    if function.call(&*scope, receiver, &[]).is_none() {
        // A thrown callback leaves the exception pending for the runtime's
        // uncaught-exception path to report, which is what Node does.
        tracing::debug!("a thread-safe function's JavaScript callback threw");
    }
}

/// `uv_close` callback: the handle is gone, so run the finalizer and decide
/// whether the allocation can be freed.
///
/// # Safety
///
/// Called by libuv with the handle `create` initialised.
unsafe extern "C" fn on_closed(handle: *mut uv::uv_handle_t) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the close callback receives the same handle `create` initialised,
    // whose `data` slot still holds the owning object. libuv does not clear it.
    let this_pointer = unsafe { (*handle).data.cast::<ThreadSafeFunction>() };
    if this_pointer.is_null() {
        return;
    }
    ThreadSafeFunction::finalize(this_pointer);
    ThreadSafeFunction::maybe_delete(this_pointer);
}

/// `napi_get_threadsafe_function_context`.
///
/// # Safety
///
/// `pointer` must come from `napi_create_threadsafe_function`.
pub(crate) unsafe fn context_of(pointer: *const crate::abi::NapiThreadsafeFunction) -> *mut c_void {
    // SAFETY: the caller guarantees the pointer is a live TSFN.
    unsafe { (*(pointer as *const ThreadSafeFunction)).context }
}

/// `napi_call_threadsafe_function`.
///
/// # Safety
///
/// `pointer` must come from `napi_create_threadsafe_function`.
pub(crate) unsafe fn call(
    pointer: *mut crate::abi::NapiThreadsafeFunction,
    data: *mut c_void,
    mode: NapiThreadsafeFunctionCallMode,
) -> NapiStatus {
    ThreadSafeFunction::push(pointer as *const ThreadSafeFunction, data, mode)
}

/// `napi_acquire_threadsafe_function`.
///
/// # Safety
///
/// `pointer` must come from `napi_create_threadsafe_function`.
pub(crate) unsafe fn acquire(pointer: *mut crate::abi::NapiThreadsafeFunction) -> NapiStatus {
    ThreadSafeFunction::acquire(pointer as *const ThreadSafeFunction)
}

/// `napi_release_threadsafe_function`.
///
/// # Safety
///
/// `pointer` must come from `napi_create_threadsafe_function`.
pub(crate) unsafe fn release(
    pointer: *mut crate::abi::NapiThreadsafeFunction,
    mode: NapiThreadsafeFunctionReleaseMode,
) -> NapiStatus {
    ThreadSafeFunction::release(pointer as *const ThreadSafeFunction, mode)
}

/// `napi_ref_threadsafe_function`.
///
/// # Safety
///
/// `pointer` must come from `napi_create_threadsafe_function`, and this must run
/// on the loop's thread, which is where libuv allows `uv_ref`.
pub(crate) unsafe fn ref_handle(pointer: *const crate::abi::NapiThreadsafeFunction) {
    // SAFETY: the caller guarantees the pointer is live.
    let this = unsafe { &*(pointer as *const ThreadSafeFunction) };
    // SAFETY: the handle is initialised and not closed while the state is Open;
    // a ref against a closing handle is a no-op in libuv.
    unsafe { uv::uv_ref(this.handle().cast::<uv::uv_handle_t>()) };
}

/// `napi_unref_threadsafe_function`.
///
/// # Safety
///
/// `pointer` must come from `napi_create_threadsafe_function`, and this must run
/// on the loop's thread.
pub(crate) unsafe fn unref_handle(pointer: *const crate::abi::NapiThreadsafeFunction) {
    // SAFETY: as in `ref_handle`.
    let this = unsafe { &*(pointer as *const ThreadSafeFunction) };
    // SAFETY: as in `ref_handle`.
    unsafe { uv::uv_unref(this.handle().cast::<uv::uv_handle_t>()) };
}

/// Whether the loop is still kept alive by this TSFN's handle.
///
/// Exposed for the unit tests, which need to prove `ref`/`unref` reached libuv
/// rather than only touching a flag.
#[cfg(test)]
#[must_use]
pub(crate) fn has_ref(pointer: *const ThreadSafeFunction) -> bool {
    // SAFETY: the caller guarantees the pointer is live.
    let this = unsafe { &*pointer };
    // SAFETY: the handle is initialised for as long as the object exists.
    unsafe { uv::uv_has_ref(this.handle().cast::<uv::uv_handle_t>()) != 0 }
}

/// The number of values still queued, for tests.
#[cfg(test)]
#[must_use]
pub(crate) fn queued_len(pointer: *const ThreadSafeFunction) -> usize {
    // SAFETY: the caller guarantees the pointer is live.
    let this = unsafe { &*pointer };
    this.lock().queue.len()
}

/// Set while a TSFN finalizer is running, so a test can tell the finalizer really
/// executed rather than inferring it from the pointer going away.
pub(crate) static FINALIZED_IN_TEST: AtomicBool = AtomicBool::new(false);

impl Drop for ThreadSafeFunction {
    fn drop(&mut self) {
        // Nothing to close: the handle is closed before this can run. Recording
        // the drop is what the teardown tests assert against, because a missed
        // `delete` shows up as a leak rather than a crash.
        FINALIZED_IN_TEST.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TSFN built directly, without libuv, for assertions about layout and the
    /// state machine.
    ///
    /// Not `zeroed`: a `Mutex` has a non-null invariant, so a zeroed one is
    /// instant undefined behaviour even if nothing is read from it.
    fn detached(thread_count: usize) -> Box<ThreadSafeFunction> {
        Box::new(ThreadSafeFunction {
            // SAFETY: zeroed is libuv's own uninitialised state for a handle, and
            // nothing here passes this one to libuv.
            handle: unsafe { std::mem::zeroed() },
            shared: Mutex::new(Shared {
                state: State::Open,
                thread_count,
                queue: VecDeque::new(),
                handles_closing: false,
                finalized: false,
            }),
            space_available: Condvar::new(),
            function: Mutex::new(None),
            call_js: None,
            context: std::ptr::null_mut(),
            finalize_cb: None,
            finalize_data: std::ptr::null_mut(),
            env: std::ptr::null_mut(),
            max_queue_size: 0,
        })
    }

    #[test]
    fn the_async_handle_is_retrievable_at_a_stable_address() {
        // `Box` keeps the object put, so the address the addon holds as
        // `napi_threadsafe_function` and the address libuv holds as
        // `uv_async_t` are both valid for the object's whole life.
        let object = detached(1);
        let first = object.handle();
        let second = object.handle();
        assert_eq!(first, second);
        // The handle's `data` slot is what the callbacks use to recover the
        // object, so its address is part of the contract.
        assert!(!first.is_null());
    }

    #[test]
    fn a_closed_state_with_no_threads_is_the_only_deletable_state() {
        // The delete decision in `push` and `release` is exactly this predicate;
        // getting it wrong frees an allocation another thread still holds.
        let deletable = |state: State, count: usize| state == State::Closed && count == 0;
        assert!(!deletable(State::Open, 0));
        assert!(!deletable(State::Closing, 0));
        assert!(!deletable(State::Closed, 1));
        assert!(deletable(State::Closed, 0));
    }

    #[test]
    fn a_push_with_no_threads_left_reports_invalid_arg_and_consumes_no_count() {
        // Node's `Push` decrements the count when the state is not open, and
        // reports `napi_invalid_arg` when there was nothing to decrement. A
        // saturating decrement would silently turn the last release into a second
        // free later.
        let object = detached(0);
        object.shared.lock().expect("unpoisoned").state = State::Closing;
        let status = ThreadSafeFunction::push(
            object.as_ref(),
            std::ptr::null_mut(),
            NapiThreadsafeFunctionCallMode::Nonblocking,
        );
        assert_eq!(status, NapiStatus::InvalidArg);
        assert_eq!(queued_len(object.as_ref()), 0);
    }

    #[test]
    fn a_release_without_a_matching_acquire_is_rejected() {
        // Releasing a hold that was never taken underflows the count otherwise,
        // and the count is what decides when the allocation may be freed.
        let object = detached(0);
        let status = ThreadSafeFunction::release(
            object.as_ref(),
            NapiThreadsafeFunctionReleaseMode::Release,
        );
        assert_eq!(status, NapiStatus::InvalidArg);
    }

    #[test]
    fn an_acquire_after_closing_is_refused() {
        // A thread that arrives after the function closed must not raise the count
        // back up: it would keep the allocation alive forever with nobody to
        // release it.
        let object = detached(1);
        object.shared.lock().expect("unpoisoned").state = State::Closing;
        assert_eq!(
            ThreadSafeFunction::acquire(object.as_ref()),
            NapiStatus::Closing
        );
        assert_eq!(object.shared.lock().expect("unpoisoned").thread_count, 1);
    }

    #[test]
    fn a_push_onto_a_closing_queue_reports_closing_and_spends_the_hold() {
        // Node's documented behaviour: a push into a closing function still
        // decrements the producer's count, because that producer is on its way
        // out. The count reaching zero with the state closed is what frees the
        // allocation, which is why this is asserted rather than assumed.
        let object = detached(1);
        object.shared.lock().expect("unpoisoned").state = State::Closing;
        let status = ThreadSafeFunction::push(
            object.as_ref(),
            std::ptr::null_mut(),
            NapiThreadsafeFunctionCallMode::Blocking,
        );
        assert_eq!(status, NapiStatus::Closing);
        assert_eq!(object.shared.lock().expect("unpoisoned").thread_count, 0);
    }

    #[test]
    fn ref_and_unref_reach_libuv_and_change_whether_the_loop_is_kept_alive() {
        // The point of `napi_ref_threadsafe_function` / `napi_unref` is loop
        // liveness, so the assertion has to come from libuv's own answer rather
        // than from a flag this module set. `uv_has_ref` is that answer.
        //
        // A TSFN starts ref'd: a live one keeps the process alive, which is what
        // makes `test_threadsafe_function`'s unref case observable at all.
        let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
            // No loop can be created in this unit-test process, so there is
            // nothing to assert about. Failing here would report the environment,
            // not the code.
            return;
        };
        // SAFETY: the settings name this process' live loop, a null function with a
        // `call_js` is legal, and the counters are plain numbers.
        let created = unsafe {
            ThreadSafeFunction::create(NewThreadSafeFunction {
                env: std::ptr::null_mut(),
                function: None,
                max_queue_size: 0,
                initial_thread_count: 1,
                finalize_data: std::ptr::null_mut(),
                finalize_cb: None,
                context: std::ptr::null_mut(),
                call_js: None,
                loop_pointer,
            })
        };
        let Ok(pointer) = created else {
            // `uv_async_init` failed, which is an environment problem rather than
            // a behavioural one; saying so beats a false failure.
            return;
        };

        assert!(
            has_ref(pointer as *const ThreadSafeFunction),
            "a new thread-safe function must keep the loop alive"
        );
        // SAFETY: `pointer` is the live object `create` returned.
        unsafe { unref_handle(pointer.cast()) };
        assert!(
            !has_ref(pointer as *const ThreadSafeFunction),
            "napi_unref_threadsafe_function must clear the handle's ref"
        );
        // SAFETY: as above.
        unsafe { ref_handle(pointer.cast()) };
        assert!(
            has_ref(pointer as *const ThreadSafeFunction),
            "napi_ref_threadsafe_function must restore the handle's ref"
        );

        // Tear the object down through the documented path: release the only hold
        // and let the close callback free it. The loop has to run for the close
        // callback to fire, which is how a real teardown works.
        assert_eq!(
            ThreadSafeFunction::release(pointer, NapiThreadsafeFunctionReleaseMode::Release),
            NapiStatus::Ok
        );
        for _ in 0..64 {
            if !rn_uv::uv_loop::is_active() {
                break;
            }
            let _ = rn_uv::uv_loop::run_once();
        }
        assert!(
            FINALIZED_IN_TEST.load(Ordering::SeqCst),
            "the close path must free the thread-safe function"
        );
    }
}
