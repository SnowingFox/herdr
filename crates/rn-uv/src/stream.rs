//! The read, write and shutdown paths shared by `tcp_wrap` and `pipe_wrap`.
//!
//! Both bindings expose the same `StreamBase` methods — `readStart`, `readStop`,
//! `shutdown`, `writeBuffer`, `writev`, `writeUtf8String` and siblings — because
//! `src/stream_base.cc` adds them to the *shared* `LibuvStreamWrap` prototype and
//! `TCP`/`Pipe` inherit it. Implementing them once here keeps the two bindings to
//! the calls that actually differ.
//!
//! # The write protocol
//!
//! `StreamBase::Write` (`src/stream_base.cc`) is the reference. For each write:
//!
//! 1. Sum the buffers into `total_bytes`.
//! 2. Try `uv_try_write` first. If it takes everything, the write completed
//!    *synchronously*: no request object is created and the return value is the
//!    status (`0` on success).
//! 3. Otherwise queue `uv_write` and return the `WriteWrap` object.
//! 4. Either way, publish `bytes`, `async` and `err` into `streamBaseState`,
//!    because `afterWriteDispatched` reads them the moment the call returns.
//!
//! # The synchronous-completion trap
//!
//! A write can finish inside the `handle.writeBuffer(...)` call, *before*
//! JavaScript can attach `req.oncomplete` — it cannot, because `req` is that
//! call's return value. Node records the status on the request object and
//! `afterWriteDispatched` replays it:
//!
//! ```js
//! const status = req.writeStatus;
//! if (status !== null) { req.writeStatus = null; req.oncomplete(status); }
//! ```
//!
//! So [`report_completion`] writes `writeStatus` when `oncomplete` is not yet a
//! function, and never calls a `null` handler. Getting this backwards either
//! drops the completion or fires it twice.

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use crate::callback;
use crate::handle::{
    self, Allocation, StreamState, K_BYTES_WRITTEN, K_LAST_WRITE_ERR, K_LAST_WRITE_WAS_ASYNC,
};

thread_local! {
    /// The shared `streamBaseState` buffer.
    ///
    /// Node allocates this once per `Environment`
    /// (`env->stream_base_state()`) and every stream wrap writes into that one
    /// array: `src/stream_wrap.cc` publishes
    /// `env->stream_base_state().GetJSArray()`, and `StreamBase::SetWriteResult`
    /// writes through the same object. rustnode therefore allocates it here and
    /// nowhere else, so the JavaScript layer and the native write path cannot
    /// end up watching different memory.
    static STATE: RefCell<Option<rn_core::AliasedUint8Array>> = const { RefCell::new(None) };

    /// The read allocation libuv is currently filling.
    ///
    /// `uv_read_start`'s allocator returns a raw buffer and the read callback
    /// gets it back by pointer, so the length has to be remembered between the
    /// two calls to rebuild it as an owned [`Allocation`].
    static PENDING_ALLOCATION: RefCell<Option<(*mut u8, usize)>> = const { RefCell::new(None) };
}

/// The `streamBaseState` typed array, created on first use.
///
/// This is `AliasedInt32Array` in `src/env.h`: five `i32` elements named by
/// [`crate::handle::K_READ_BYTES_OR_ERROR`] and friends. The element width is
/// part of the contract — a `Uint8Array` view of the same bytes would make
/// `streamBaseState[2]` mean something different on each side.
pub fn state_array<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Value>> {
    STATE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(
                rn_core::AliasedUint8Array::new(
                    scope,
                    crate::handle::STREAM_BASE_STATE_FIELDS,
                    rn_core::Element::SignedWord,
                )
                .ok()?,
            );
        }
        slot.as_ref().map(|state| state.array(scope))
    })
}

/// Whether the state buffer has been created yet.
pub fn state_initialised() -> bool {
    STATE.with(|slot| slot.borrow().is_some())
}

/// Runs `body` with the shared state buffer.
pub fn with_state<R>(body: impl FnOnce(&rn_core::AliasedUint8Array) -> R) -> Option<R> {
    STATE.with(|slot| slot.borrow().as_ref().map(body))
}

/// What a write did, in the three values `afterWriteDispatched` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteOutcome {
    /// Bytes the write accounted for.
    pub bytes: usize,
    /// Whether libuv still owes a completion.
    pub asynchronous: bool,
    /// The status: 0 on success, a libuv error otherwise.
    pub error: i32,
}

impl WriteOutcome {
    /// Publishes the outcome into `streamBaseState`.
    ///
    /// `SetWriteResult` writes exactly these three fields, and
    /// `afterWriteDispatched` reads `bytes` and `err` from them before it
    /// decides whether it got a number or a request object.
    pub fn publish(&self, state: &rn_core::AliasedUint8Array) {
        state.set(K_BYTES_WRITTEN, self.bytes as u32);
        state.set(K_LAST_WRITE_WAS_ASYNC, u32::from(self.asynchronous));
        state.set(K_LAST_WRITE_ERR, self.error as u32);
    }
}

/// Publishes a failure into `streamBaseState` for a write that never reached
/// libuv.
pub fn publish_error(error: i32) {
    publish(&WriteOutcome {
        bytes: 0,
        asynchronous: false,
        error,
    });
}

/// Publishes an outcome, doing nothing when `stream_wrap` is not installed yet.
pub fn publish(outcome: &WriteOutcome) {
    with_state(|state| outcome.publish(state));
}

/// Issues `uv_write` and returns libuv's status.
///
/// `owned` keeps any string backing storage alive until the completion fires.
///
/// # Safety
///
/// `stream` must be a live stream; `request` must be the `WriteWrap` object for
/// this write; every entry in `buffers` must point at storage that stays valid
/// until the completion, which `owned` provides for strings and which the caller
/// must provide for buffers (a `FastBuffer`'s backing store is kept alive by
/// `req.buffer` on the JavaScript side, exactly as in Node).
pub unsafe fn queue_write(
    scope: &mut v8::PinScope<'_, '_>,
    stream: *mut uv::uv_stream_t,
    mut buffers: Vec<uv::uv_buf_t>,
    total_bytes: usize,
    request: v8::Local<v8::Object>,
    handle_object: v8::Local<v8::Object>,
    owned: Vec<Box<[u8]>>,
) -> i32 {
    let completion = Box::new(WriteCompletion {
        request: v8::Global::new(scope.as_ref(), request),
        handle: v8::Global::new(scope.as_ref(), handle_object),
        owned,
    });
    let completion = Box::into_raw(completion);

    let storage = Box::into_raw(Box::new(std::mem::MaybeUninit::<uv::uv_write_t>::zeroed()));
    // SAFETY: `storage` is a live, aligned, zeroed `uv_write_t`.
    let request_ref = unsafe { (*storage).as_mut_ptr() };
    // SAFETY: `request_ref` is live and `data` is the slot libuv hands back.
    unsafe {
        (*request_ref).data = completion.cast::<c_void>();
    }

    // SAFETY: the caller guarantees the stream and buffers stay valid.
    let status = unsafe {
        uv::uv_write(
            request_ref,
            stream,
            buffers.as_mut_ptr(),
            buffers.len() as u32,
            Some(after_write),
        )
    };

    if status != 0 {
        // Nothing was queued, so libuv will never call back and both
        // allocations are still ours to release.
        // SAFETY: both pointers came from `Box::into_raw` above and libuv did
        // not take ownership because `uv_write` failed.
        unsafe {
            drop(Box::from_raw(storage));
            drop(Box::from_raw(completion));
        }
        publish_error(status);
    } else {
        publish(&WriteOutcome {
            bytes: total_bytes,
            asynchronous: true,
            error: 0,
        });
    }

    status
}

/// State a queued write carries to its completion.
struct WriteCompletion {
    request: v8::Global<v8::Object>,
    handle: v8::Global<v8::Object>,
    /// String backing storage, freed with this struct.
    #[allow(dead_code)]
    owned: Vec<Box<[u8]>>,
}

/// libuv's write completion.
///
/// # Safety
///
/// Called by libuv with the `uv_write_t` [`queue_write`] allocated.
unsafe extern "C" fn after_write(request: *mut uv::uv_write_t, status: i32) {
    if request.is_null() {
        return;
    }
    // SAFETY: `queue_write` stored this pointer in `data` and libuv hands the
    // same request back exactly once.
    let completion = unsafe { (*request).data.cast::<WriteCompletion>() };
    // SAFETY: the request came from `Box<MaybeUninit<uv_write_t>>` in
    // `queue_write`, and libuv is finished with it.
    drop(unsafe { Box::from_raw(request.cast::<std::mem::MaybeUninit<uv::uv_write_t>>()) });

    let Some(completion) = (unsafe { reclaim(completion) }) else {
        return;
    };

    callback::with_context(|scope| {
        let request: v8::Local<v8::Object> = v8::Local::new(scope, &completion.request);
        let handle: v8::Local<v8::Object> = v8::Local::new(scope, &completion.handle);
        report_completion(scope, request, status, Some(handle), None);
    });
}

/// State a queued shutdown carries to its completion.
struct ShutdownCompletion {
    request: v8::Global<v8::Object>,
    handle: v8::Global<v8::Object>,
}

/// Issues `uv_shutdown`, reporting to `request.oncomplete`.
///
/// # Safety
///
/// `stream` must be a live stream and `request` the `ShutdownWrap` for it.
pub unsafe fn queue_shutdown(
    scope: &mut v8::PinScope<'_, '_>,
    stream: *mut uv::uv_stream_t,
    request: v8::Local<v8::Object>,
    handle_object: v8::Local<v8::Object>,
) -> i32 {
    let completion = Box::new(ShutdownCompletion {
        request: v8::Global::new(scope.as_ref(), request),
        handle: v8::Global::new(scope.as_ref(), handle_object),
    });
    let completion = Box::into_raw(completion);

    let storage = Box::into_raw(Box::new(
        std::mem::MaybeUninit::<uv::uv_shutdown_t>::zeroed(),
    ));
    // SAFETY: `storage` is a live, aligned, zeroed `uv_shutdown_t`.
    let request_ref = unsafe { (*storage).as_mut_ptr() };
    // SAFETY: `request_ref` is live.
    unsafe {
        (*request_ref).data = completion.cast::<c_void>();
    }

    // SAFETY: `stream` is a live stream.
    let status = unsafe { uv::uv_shutdown(request_ref, stream, Some(after_shutdown)) };

    if status != 0 {
        // SAFETY: libuv did not take ownership when `uv_shutdown` failed.
        unsafe {
            drop(Box::from_raw(storage));
            drop(Box::from_raw(completion));
        }
    }
    status
}

/// libuv's shutdown completion.
///
/// # Safety
///
/// Called by libuv with the `uv_shutdown_t` [`queue_shutdown`] allocated.
unsafe extern "C" fn after_shutdown(request: *mut uv::uv_shutdown_t, status: i32) {
    if request.is_null() {
        return;
    }
    // SAFETY: `queue_shutdown` stored this pointer in `data`.
    let completion = unsafe { (*request).data.cast::<ShutdownCompletion>() };
    // SAFETY: the request came from `Box<MaybeUninit<uv_shutdown_t>>`.
    drop(unsafe { Box::from_raw(request.cast::<std::mem::MaybeUninit<uv::uv_shutdown_t>>()) });

    let Some(completion) = (unsafe { reclaim(completion) }) else {
        return;
    };

    callback::with_context(|scope| {
        let request: v8::Local<v8::Object> = v8::Local::new(scope, &completion.request);
        let handle: v8::Local<v8::Object> = v8::Local::new(scope, &completion.handle);
        report_completion(scope, request, status, Some(handle), None);
    });
}

/// Starts reading, wiring libuv's allocator and read callbacks to the state.
///
/// Returns libuv's status. `lib/net.js` sets `handle.reading = true` on the
/// JavaScript side before calling this and checks the result, so a failure has to
/// be a status and not a throw.
///
/// # Safety
///
/// `stream` must be a live stream whose `data` is `state`, and `state` must
/// outlive the read.
pub unsafe fn read_start(stream: *mut uv::uv_stream_t, state: *mut StreamState) -> i32 {
    // SAFETY: the caller guarantees both pointers; `data` is already `state`, so
    // nothing has to be re-stored here.
    unsafe {
        let _ = state;
        uv::uv_read_start(stream, Some(on_alloc), Some(on_read))
    }
}

/// Stops reading. Idempotent, as `uv_read_stop` is.
///
/// # Safety
///
/// `stream` must be a live stream.
pub unsafe fn read_stop(stream: *mut uv::uv_stream_t) -> i32 {
    unsafe { uv::uv_read_stop(stream) }
}

/// libuv's read allocator.
///
/// # Safety
///
/// Called by libuv with a live handle and a writable `uv_buf_t`.
unsafe extern "C" fn on_alloc(
    _handle: *mut uv::uv_handle_t,
    suggested_size: usize,
    buffer: *mut uv::uv_buf_t,
) {
    if buffer.is_null() {
        return;
    }
    let Some(mut allocation) = Allocation::new(suggested_size) else {
        // SAFETY: `buffer` is libuv's out-parameter; a zero length is how it is
        // told the allocation failed.
        unsafe {
            (*buffer).base = ptr::null_mut();
            (*buffer).len = 0;
        }
        return;
    };
    let length = allocation.length();
    let base = allocation.base();
    // SAFETY: `buffer` is libuv's out-parameter, live for this call.
    unsafe {
        (*buffer).base = base.cast();
        (*buffer).len = length;
    }
    std::mem::forget(allocation);
    PENDING_ALLOCATION.with(|slot| {
        *slot.borrow_mut() = Some((base, length));
    });
}

/// Rebuilds the parked read allocation as an owned [`Allocation`].
fn take_allocation() -> Option<Allocation> {
    let (address, length) = PENDING_ALLOCATION.with(|slot| slot.borrow_mut().take())?;
    // SAFETY: `address` and `length` are exactly what `on_alloc` handed libuv,
    // which uses an 8-byte alignment for every read buffer.
    Some(unsafe { Allocation::from_raw(address, length) })
}

/// libuv's read completion.
///
/// # Safety
///
/// Called by libuv with the stream whose `data` is a `*mut StreamState`.
unsafe extern "C" fn on_read(
    stream: *mut uv::uv_stream_t,
    status: isize,
    _buffer: *const uv::uv_buf_t,
) {
    // SAFETY: the binding stored the state pointer in `stream->data`.
    let Some(state) = (unsafe { handle::owner(stream) }) else {
        drop(take_allocation());
        return;
    };
    // SAFETY: `state` is the owner pointer, live while the handle is, and nothing
    // else borrows it during this callback.
    let state = unsafe { &mut *state };

    let allocation = if status > 0 { take_allocation() } else { None };
    if status <= 0 {
        // A failed or empty read still releases the allocator's buffer.
        drop(take_allocation());
    }
    with_state(|stream_base_state| {
        handle::deliver_read(state, stream_base_state, status, allocation);
    });
}

/// Rooted JavaScript values a completion needs, so it can be handed to another
/// thread or held across a native call.
///
/// `lib/internal/stream_base_commons.js`'s `onWriteComplete` reads
/// `this.handle[owner_symbol]`, `this.callback` and `this.error`, so a write
/// completion has to deliver an object with those fields intact. This is that
/// object, rooted.
pub struct CompletionTarget {
    pub request: v8::Global<v8::Object>,
    pub handle: v8::Global<v8::Object>,
}

/// Delivers a completion to `request.oncomplete`, or parks it when JavaScript has
/// not attached one yet.
///
/// This is `ReportWritesToJSStreamListener::OnStreamAfterReqFinished`. If
/// `oncomplete` is a function it is called with `(status, handle, error)`; if it
/// is not, the status goes into `writeStatus` so `afterWriteDispatched` can
/// replay it once it has the request object.
///
/// Returns whether the handler ran.
pub fn report_completion(
    scope: &mut v8::PinScope<'_, '_>,
    request: v8::Local<v8::Object>,
    status: i32,
    handle: Option<v8::Local<v8::Object>>,
    error: Option<&str>,
) -> bool {
    let Some(oncomplete_key) = v8::String::new(scope, "oncomplete") else {
        return false;
    };
    let Some(value) = request.get(scope, oncomplete_key.into()) else {
        return false;
    };

    let Ok(handler) = v8::Local::<v8::Function>::try_from(value) else {
        // Not attached yet: record the status for `afterWriteDispatched`.
        if let Some(write_status_key) = v8::String::new(scope, "writeStatus") {
            request.set(
                scope,
                write_status_key.into(),
                v8::Integer::new(scope, status).into(),
            );
        }
        if let Some(text) = error {
            if let Some(error_key) = v8::String::new(scope, "error") {
                if let Some(message) = v8::String::new(scope, text) {
                    request.set(scope, error_key.into(), message.into());
                }
            }
        }
        return false;
    };

    let status_value: v8::Local<v8::Value> = v8::Integer::new(scope, status).into();
    // `argv[1]` is `stream->GetObject()`, the socket the request belongs to.
    let handle_value: v8::Local<v8::Value> = match handle {
        Some(handle) => handle.into(),
        None => v8::undefined(scope).into(),
    };
    let error_value: v8::Local<v8::Value> = match error {
        Some(text) => match v8::String::new(scope, text) {
            Some(text) => text.into(),
            None => v8::undefined(scope).into(),
        },
        None => v8::undefined(scope).into(),
    };

    let receiver: v8::Local<v8::Value> = request.into();
    let _ = handler.call(scope, receiver, &[status_value, handle_value, error_value]);
    true
}

/// Reads `request.oncomplete` as a function, if JavaScript attached one.
pub fn oncomplete_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    request: v8::Local<v8::Object>,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, "oncomplete")?;
    let value = request.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

/// Reclaims a `Box` handed to a callback, or `None` for a null pointer.
///
/// # Safety
///
/// `pointer` must have come from `Box::into_raw` and not been reclaimed already.
unsafe fn reclaim<T>(pointer: *mut T) -> Option<Box<T>> {
    if pointer.is_null() {
        None
    } else {
        // SAFETY: the caller guarantees the pointer came from `Box::into_raw`.
        Some(unsafe { Box::from_raw(pointer) })
    }
}
