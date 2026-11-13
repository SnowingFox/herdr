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
use crate::listener;

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
    /// gets it back by pointer, so what it was has to be remembered between the
    /// two calls: the address and length of an allocation this crate made, or
    /// the listener's own `uv_buf_t`, which is not ours to free.
    static PENDING_ALLOCATION: RefCell<Option<PendingAllocation>> = const { RefCell::new(None) };
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

/// `LibuvStreamWrap::DoTryWrite`: hand as much as possible to `uv_try_write`.
///
/// This is the first half of `StreamBase::Write`, and skipping it changes
/// observable behaviour rather than just performance. `uv_try_write` completes a
/// write *synchronously* when the descriptor accepts it, which means no
/// `uv_write_t` is ever created — and an outstanding write request is precisely
/// what keeps the event loop alive. Node's stdout pipe takes the whole string on
/// the first call, so `process.stdout.write` alone does not hold the process
/// open; without this, every write left a pending request behind and an unref'd
/// timer had something to keep the loop turning for.
///
/// Returns the number of bytes written, or `0` when nothing was taken. `ENOSYS`
/// and `EAGAIN` are *not* failures: Node treats them as "this stream cannot do
/// that" and falls through to the queued path, so they return `0` too.
///
/// # Safety
///
/// `stream` must be a live stream and every entry in `buffers` must point at
/// storage that stays valid for the call.
pub unsafe fn try_write(stream: *mut uv::uv_stream_t, buffers: &mut [uv::uv_buf_t]) -> usize {
    if buffers.is_empty() {
        return 0;
    }
    // SAFETY: the caller guarantees the stream is live and the buffers are valid
    // for the duration of the call.
    let status = unsafe { uv::uv_try_write(stream, buffers.as_mut_ptr(), buffers.len() as u32) };
    if status == uv::uv_errno_t_UV_ENOSYS || status == uv::uv_errno_t_UV_EAGAIN {
        return 0;
    }
    if status < 0 {
        return 0;
    }
    status as usize
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
        // SAFETY: the caller guarantees `stream` is live, and a live stream's
        // `data` is its `StreamState`.
        state: unsafe { handle::owner(stream) }.unwrap_or(ptr::null_mut()),
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
    /// The stream the write was queued on, so the completion can reach its
    /// listener chain.
    ///
    /// `crypto_tls.cc:784` writes its ciphertext through
    /// `underlying_stream()->Write(...)`, and the completion arrives at the
    /// *underlying* stream — so it has to reach the `TLSWrap` listening to it
    /// rather than JavaScript, or the cleartext write's callback never fires and
    /// `lib/net.js`'s `pending` count never reaches zero.
    state: *mut StreamState,
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
        // SAFETY: the state outlives its handle's completions, and `emit_after_write`
        // holds no reference to it across the listener call.
        unsafe {
            listener::emit_after_write(completion.state, scope, request, Some(handle), status)
        };
    });
}

/// State a queued shutdown carries to its completion.
struct ShutdownCompletion {
    request: v8::Global<v8::Object>,
    handle: v8::Global<v8::Object>,
    /// The stream the shutdown was queued on; see [`WriteCompletion::state`].
    state: *mut StreamState,
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
        // SAFETY: as in `queue_write`.
        state: unsafe { handle::owner(stream) }.unwrap_or(ptr::null_mut()),
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
        // SAFETY: as in `after_write`; `emit_after_shutdown` holds no reference
        // to the state across the listener call.
        unsafe {
            listener::emit_after_shutdown(completion.state, scope, request, Some(handle), status)
        };
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

/// Issues a write with no caller-supplied request object.
///
/// `StreamPipe` is the only caller: it pumps a source stream's reads into a sink
/// with no JavaScript write behind them, so there is no `WriteWrap` to complete.
/// `src/stream_pipe.cc` has the same shape — `sink()->Write(&buffer, 1)` takes a
/// `StreamWriteResult` and its completion is the pipe's own counter, not a
/// callback.
///
/// `owned` keeps the bytes alive until libuv's completion fires.
///
/// Returns libuv's status: `0` when the write was queued, negative otherwise.
///
/// # Safety
///
/// `stream` must be a live stream and every entry in `buffers` must point into
/// `owned`, so the storage outlives the completion.
pub unsafe fn queue_write_unowned(
    stream: *mut uv::uv_stream_t,
    mut buffers: Vec<uv::uv_buf_t>,
    total_bytes: usize,
    owned: Vec<Box<[u8]>>,
) -> i32 {
    if stream.is_null() || buffers.is_empty() {
        return uv::uv_errno_t_UV_EINVAL;
    }
    let completion = Box::new(UnownedWriteCompletion {
        bytes: total_bytes,
        // SAFETY: the caller guarantees `stream` is live, and a live stream's
        // `data` is its `StreamState`.
        state: unsafe { handle::owner(stream) }.unwrap_or(ptr::null_mut()),
        #[allow(dead_code)]
        owned,
    });
    let completion = Box::into_raw(completion);

    let storage = Box::into_raw(Box::new(std::mem::MaybeUninit::<uv::uv_write_t>::zeroed()));
    // SAFETY: `storage` is a live, aligned, zeroed `uv_write_t`.
    let request = unsafe { (*storage).as_mut_ptr() };
    // SAFETY: `request` is live and `data` is the slot libuv hands back.
    unsafe {
        (*request).data = completion.cast::<c_void>();
    }

    // SAFETY: the caller guarantees the stream and buffers stay valid.
    let status = unsafe {
        uv::uv_write(
            request,
            stream,
            buffers.as_mut_ptr(),
            buffers.len() as u32,
            Some(after_unowned_write),
        )
    };

    if status != 0 {
        // SAFETY: libuv took nothing when `uv_write` failed, so both allocations
        // are still ours.
        unsafe {
            drop(Box::from_raw(storage));
            drop(Box::from_raw(completion));
        }
    }
    status
}

/// State an unowned write carries to its completion.
struct UnownedWriteCompletion {
    bytes: usize,
    /// The stream the write was queued on, so the completion reaches its
    /// listener chain rather than JavaScript.
    state: *mut StreamState,
    /// Backing storage, freed with this struct.
    #[allow(dead_code)]
    owned: Vec<Box<[u8]>>,
}

/// libuv completion for [`queue_write_unowned`].
///
/// # Safety
///
/// Called by libuv with the `uv_write_t` `queue_write_unowned` allocated.
unsafe extern "C" fn after_unowned_write(request: *mut uv::uv_write_t, status: i32) {
    if request.is_null() {
        return;
    }
    // SAFETY: `queue_write_unowned` stored this pointer in `data` and libuv hands
    // the same request back exactly once.
    let completion = unsafe { (*request).data.cast::<UnownedWriteCompletion>() };
    // SAFETY: the request came from `Box<MaybeUninit<uv_write_t>>` above and libuv
    // is finished with it.
    drop(unsafe { Box::from_raw(request.cast::<std::mem::MaybeUninit<uv::uv_write_t>>()) });

    let Some(completion) = (unsafe { reclaim_unowned(completion) }) else {
        return;
    };

    callback::with_context(|scope| {
        let request = v8::Object::new(scope);
        let bytes = completion.bytes;
        // `emit_after_write` needs a request to hand the listener, and a pipe has
        // none. The bare object is the same stand-in `StreamWriteResult` implies:
        // the pipe's listener ignores it and only reads `status`.
        let _ = bytes;
        // SAFETY: the state outlives its handle's completions.
        unsafe { listener::emit_after_write(completion.state, scope, request, None, status) };
    });
}

/// Takes an [`UnownedWriteCompletion`] back out of its raw pointer.
///
/// # Safety
///
/// `pointer` must have come from `Box::into_raw` on an `UnownedWriteCompletion`
/// and must not have been reclaimed already.
unsafe fn reclaim_unowned(
    pointer: *mut UnownedWriteCompletion,
) -> Option<Box<UnownedWriteCompletion>> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the pointer came from `Box::into_raw`.
    Some(unsafe { Box::from_raw(pointer) })
}

/// Shuts a stream's writing side down, the way `StreamBase::Shutdown()` does.
///
/// `StreamPipe` calls this when its source ends. Node's version is
/// `ShutdownWrap`-based because a `StreamBase` owns its request; here the sink's
/// write side is ended with `uv_shutdown`, which is what
/// `lib/internal/stream_base_commons.js` ends up issuing for a socket.
///
/// Returns libuv's status, or `UV_ENOTCONN` when the stream is not connected.
///
/// # Safety
///
/// `stream` must be a live stream.
pub unsafe fn end_stream(stream: *mut uv::uv_stream_t) -> i32 {
    if stream.is_null() {
        return uv::uv_errno_t_UV_EINVAL;
    }
    let storage = Box::into_raw(Box::new(
        std::mem::MaybeUninit::<uv::uv_shutdown_t>::zeroed(),
    ));
    // SAFETY: `storage` is a live, aligned, zeroed `uv_shutdown_t`.
    let request = unsafe { (*storage).as_mut_ptr() };
    // SAFETY: `request` is live; `data` stays null, so the completion has nothing
    // to reclaim and only reports through the listener chain.
    unsafe {
        (*request).data = ptr::null_mut();
    }
    // SAFETY: the caller guarantees `stream` is live.
    let status = unsafe { uv::uv_shutdown(request, stream, Some(after_unowned_shutdown)) };
    if status != 0 {
        // SAFETY: libuv took nothing when `uv_shutdown` failed.
        unsafe {
            drop(Box::from_raw(storage));
        }
    }
    status
}

/// libuv completion for [`end_stream`].
///
/// # Safety
///
/// Called by libuv with the `uv_shutdown_t` `end_stream` allocated.
unsafe extern "C" fn after_unowned_shutdown(request: *mut uv::uv_shutdown_t, _status: i32) {
    if request.is_null() {
        return;
    }
    // SAFETY: `end_stream` allocated this and libuv is finished with it.
    drop(unsafe { Box::from_raw(request.cast::<std::mem::MaybeUninit<uv::uv_shutdown_t>>()) });
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
/// This is `LibuvStreamWrap::OnUvAlloc` (`src/stream_wrap.cc:247`), whose whole
/// body is `*buf = EmitAlloc(suggested_size)`. So the buffer does not have to be
/// this crate's: an attached listener — `TLSWrap`'s, which points into its
/// `NodeBIO` — decides where the bytes land.
///
/// # Safety
///
/// Called by libuv with a live handle and a writable `uv_buf_t`.
unsafe extern "C" fn on_alloc(
    handle: *mut uv::uv_handle_t,
    suggested_size: usize,
    buffer: *mut uv::uv_buf_t,
) {
    if buffer.is_null() {
        return;
    }
    let state = unsafe { handle::owner(handle.cast::<uv::uv_stream_t>()) };
    if let Some(state) = state {
        // SAFETY: `state` is the owner pointer the binding stored on the handle,
        // live until the close callback runs, which is after every read.
        if let Some(listener_buffer) = unsafe { listener::emit_alloc(state, suggested_size) } {
            // SAFETY: `buffer` is libuv's out-parameter, live for this call. A
            // listener's buffer is not ours to free, so nothing is parked in
            // `PENDING_ALLOCATION`; the read callback gets it back through the
            // `ReadBuffer::Listener` arm instead.
            unsafe {
                (*buffer).base = listener_buffer.base;
                (*buffer).len = listener_buffer.len;
            }
            PENDING_ALLOCATION.with(|slot| {
                *slot.borrow_mut() = Some(PendingAllocation::Listener(listener_buffer));
            });
            return;
        }
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
        *slot.borrow_mut() = Some(PendingAllocation::Allocated((base, length)));
    });
}

/// The allocation an `alloc_cb` produced, parked until the matching `read_cb`.
///
/// Node parks nothing: `stream_base-inl.h`'s `EmitRead` gets the `uv_buf_t` back
/// from libuv and `EmitToJSStreamListener` releases it through the read slab it
/// owns. rustnode allocates outside the slab, so the two shapes have to be told
/// apart, and the listener's own buffer must never be freed here.
enum PendingAllocation {
    /// This crate allocated it; the reader frees it.
    Allocated((*mut u8, usize)),
    /// A listener returned it; the listener owns it.
    Listener(uv::uv_buf_t),
}

/// Rebuilds the parked read allocation as an owned [`ReadBuffer`].
fn take_allocation() -> Option<listener::ReadBuffer> {
    match PENDING_ALLOCATION.with(|slot| slot.borrow_mut().take())? {
        PendingAllocation::Allocated((address, length)) => {
            // SAFETY: `address` and `length` are exactly what `on_alloc` handed
            // libuv, which uses an 8-byte alignment for every read buffer.
            Some(listener::ReadBuffer::Allocated(unsafe {
                Allocation::from_raw(address, length)
            }))
        }
        PendingAllocation::Listener(buffer) => Some(listener::ReadBuffer::Listener(buffer)),
    }
}

/// libuv's read completion.
///
/// This is `LibuvStreamWrap::OnUvRead` (`src/stream_wrap.cc:289`), whose last
/// act is `EmitRead(nread, *buf)`. Everything the read used to hand straight to
/// `handle.onread` now goes through the listener chain, so a `TLSWrap` between
/// the socket and JavaScript sees the ciphertext first.
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
    let buffer =
        take_allocation().unwrap_or_else(|| listener::ReadBuffer::Listener(empty_buffer()));
    // SAFETY: `state` is the owner pointer, live while the handle is. `emit_read`
    // takes no reference across the listener call, so a listener that closes the
    // socket here cannot alias it.
    unsafe { listener::emit_read(state, status, buffer) };
}

/// A zero-length buffer, for a read that produced no allocation.
fn empty_buffer() -> uv::uv_buf_t {
    uv::uv_buf_t {
        base: ptr::null_mut(),
        len: 0,
    }
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
