//! `TLSWrap` as a `StreamListener`: how the wrapped stream's bytes get here.
//!
//! Node's `TLSWrap` *is* the `StreamListener` that its underlying stream pushes
//! (`stream->PushStreamListener(this)` at `crypto_tls.cc:418`). A `TCP` or `Pipe`
//! hands read data to `TLSWrap::OnStreamRead`, which copies it into `enc_in_` and
//! then runs the SSL state machine.
//!
//! # Why a separate listener object
//!
//! `rn_uv::listener::ListenerRef` takes a `Box<dyn StreamListener>`, and the wrap
//! state has to outlive it — the listener is pushed during `wrap()` and removed
//! during `destroySSL()`, while the state lives until the object is collected. So
//! the listener holds the **state cell address** rather than a borrow, which is
//! also what `rn_uv::listener` requires: no borrow may be held across a listener
//! call, because the callback can re-enter and destroy the socket (R2).
//!
//! # The ordering that keeps the pointer valid
//!
//! The cell pointer is valid exactly while the object's finalizer has not run,
//! and the listener is removed in `destroy()` — which `lib/internal/tls/wrap.js`
//! calls from `close()`, before the last reference to the object is dropped. That
//! is the same ordering Node relies on with `RemoveStreamListener(this)` in
//! `Destroy()`: the listener is taken off the stream before anything can free the
//! thing it points at.
//!
//! A `TLSWrap` that is collected *without* `close()` having run cannot happen
//! through `lib/**`: `TLSSocket`'s `'close'` handler always calls `destroySSL`,
//! and the socket holds the only reference. It can happen through a direct
//! `new tls_wrap.TLSWrap()`, and such an object has no listener at all, so there
//! is nothing to dangle.
//!
//! # What increment 1 does
//!
//! [`WrapListener`] implements `on_stream_alloc` and `on_stream_read` enough to
//! move bytes into `enc_in_` and account for them, and every path that would run
//! the SSL state machine reports "not implemented yet" rather than dropping the
//! data. That is deliberate: silently discarding ciphertext would make the first
//! increment look like a hang once a handshake does start.

use std::cell::RefCell;

use rn_uv::handle::StreamState;
use rn_uv::listener::{ListenerRef, ReadBuffer, StreamListener};
use rn_v8_sys::v8;

use crate::state::{with_state, WrapState};

/// The `StreamListener` a `TLSWrap` pushes onto its underlying stream.
pub struct WrapListener {
    /// The address of the wrap's `RefCell<WrapState>`.
    ///
    /// A raw address rather than a reference because the listener is owned by the
    /// stream and the state by the V8 object, so no borrow of one can be tied to
    /// the lifetime of the other. Every use re-borrows through the `RefCell`,
    /// which is what turns a re-entrant call into a reported failure instead of
    /// aliasing.
    cell: *mut RefCell<WrapState>,
}

// The listener is only ever called from the thread that owns the loop, which is
// the thread that created the wrap. Marking it `Send` would be a lie; not marking
// it is what keeps `rn_uv`'s single-threaded contract checkable.
impl std::fmt::Debug for WrapListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WrapListener")
            .field("cell", &self.cell)
            .finish()
    }
}

impl WrapListener {
    /// A listener for the state at `cell`.
    ///
    /// # Safety
    ///
    /// `cell` must be the address of a `RefCell<WrapState>` that lives until the
    /// listener has been removed from its stream. `wrap()` establishes this by
    /// allocating the state for the object's whole life and removing the listener
    /// in `destroy()`.
    pub unsafe fn new(cell: *mut RefCell<WrapState>) -> Self {
        Self { cell }
    }

    /// Runs `body` with the wrap state, or reports a re-entrant call.
    fn with<R>(&self, body: impl FnOnce(&mut WrapState) -> R) -> Option<R> {
        if self.cell.is_null() {
            return None;
        }
        // SAFETY: the caller of `new` guarantees the cell outlives the listener,
        // and `try_borrow_mut` reports a re-entrant call rather than aliasing.
        let cell = unsafe { &*self.cell };
        let mut state = cell.try_borrow_mut().ok()?;
        Some(body(&mut state))
    }
}

impl StreamListener for WrapListener {
    /// `TLSWrap::OnStreamAlloc`.
    ///
    /// Node returns a slice of `enc_in_`'s writable region so the socket reads
    /// straight into the buffer OpenSSL will decrypt from, avoiding a copy.
    /// rustnode's `NodeBIO` is a `VecDeque`, which cannot hand out a stable write
    /// pointer, so this asks for the default allocation and copies in
    /// `on_stream_read` — one extra memcpy per read, and the only place this
    /// differs from Node's shape.
    fn on_stream_alloc(&mut self, _suggested_size: usize) -> Option<rn_uv::sys::uv_buf_t> {
        None
    }

    /// `TLSWrap::OnStreamRead`.
    ///
    /// Two things happen, in this order:
    ///
    /// 1. the bytes are appended to `enc_in_`, which is where `SSL_read` looks;
    /// 2. the SSL state machine runs ([`crate::wrap`]'s `cycle`), which is what
    ///    turns ciphertext into cleartext and emits it.
    ///
    /// A negative `nread` is an error or EOF; `PassReadErrorToPreviousListener`
    /// is what forwards it to whoever was below this one, so `lib/net.js` sees
    /// the socket's error rather than a stalled TLS stream.
    ///
    /// # R2
    ///
    /// No borrow of the state is held across step 2's JavaScript. The ciphertext
    /// is copied under the borrow, then the borrow ends, then the state machine
    /// runs through [`crate::cycle::run`], which takes its own scoped borrows.
    fn on_stream_read(&mut self, this: &ListenerRef, nread: isize, buffer: ReadBuffer) {
        if nread <= 0 {
            // `UV_EOF` and errors both arrive here. Node forwards them below so
            // the socket's own `'end'`/`'error'` fires; a TLS-level error is
            // reported separately by the state machine once it sees the close.
            this.pass_read_error_to_previous_listener(nread);
            return;
        }
        let Some(bytes) = buffer.bytes(nread) else {
            return;
        };
        if bytes.is_empty() {
            return;
        }
        // The bytes are copied into `enc_in_` while the borrow is held, and the
        // borrow ends before anything else runs.
        let accepted = self
            .with(|state| {
                state
                    .enc_in()
                    .map(|enc_in| enc_in.write(bytes))
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        if accepted < bytes.len() {
            tracing::error!(
                accepted,
                offered = bytes.len(),
                "TLSWrap could only buffer part of a read"
            );
        }
        // The state machine. Increment 1 has no handshake, so this reports the
        // increment that adds it rather than dropping the bytes silently.
        // SAFETY: `cell` is this listener's wrap state, guaranteed live for the
        // listener's whole life by `attach`'s contract.
        unsafe { crate::cycle::run(self.cell) };
    }

    /// `TLSWrap::OnStreamAfterWrite`.
    ///
    /// The write the underlying stream just finished is the **ciphertext** this
    /// wrap queued, not the cleartext the caller is waiting on. Node's override
    /// records the status and lets `EncOut` complete the real `WriteWrap` once the
    /// SSL has produced everything; forwarding it below would complete the
    /// caller's write when only part of its ciphertext had been sent, which is
    /// exactly the `writeQueueSize`/`pending` mismatch that leaves a
    /// `TLSSocket`'s write callback early.
    ///
    /// Increment 1 has no write path, so this records the completion and does not
    /// forward.
    fn on_stream_after_write<'s>(
        &mut self,
        _this: &ListenerRef,
        _scope: &mut v8::PinScope<'s, '_>,
        _request: v8::Local<'s, v8::Object>,
        _handle: Option<v8::Local<'s, v8::Object>>,
        status: i32,
    ) {
        tracing::trace!(status, "TLSWrap ciphertext write completed");
    }

    /// `TLSWrap::OnStreamAfterShutdown`.
    ///
    /// Increment 1 has no shutdown path; the pending shutdown a later increment
    /// holds is completed by `destroy()` with `UV_ECANCELED` (R3), so nothing is
    /// left waiting here.
    fn on_stream_after_shutdown<'s>(
        &mut self,
        _this: &ListenerRef,
        _scope: &mut v8::PinScope<'s, '_>,
        _request: v8::Local<'s, v8::Object>,
        _handle: Option<v8::Local<'s, v8::Object>>,
        _status: i32,
    ) {
    }

    /// `TLSWrap::OnStreamWantsWrite`.
    ///
    /// The underlying socket has room again. Node uses this to resume
    /// `EncOut`; increment 1 has nothing queued, so there is nothing to do — and
    /// doing nothing is correct rather than a stub, because a wrap with an empty
    /// output queue has no work.
    fn on_stream_wants_write(&mut self, _suggested_size: usize) {}

    /// `TLSWrap::OnStreamDestroy`, which must not call into JavaScript.
    ///
    /// This is the stream telling the listener it is going away. Node's
    /// `StreamListener::OnStreamDestroy` is empty for `TLSWrap` — the wrap is
    /// destroyed from its own side — so this clears the back-pointer and leaves
    /// the state alone. Clearing it is what makes a later `destroy()` see that
    /// there is no stream to remove the listener from, which is the
    /// `if (underlying_stream() != nullptr)` guard at `crypto_tls.cc:1496`.
    fn on_stream_destroy(&mut self, _this: &ListenerRef) {
        self.with(|state| {
            state.underlying = None;
            state.listener = None;
        });
    }
}

/// Pushes a listener for `object`'s state onto `stream`.
///
/// Returns the listener id, which `destroy()` needs to remove it.
///
/// `None` when the state cannot be reached or the push is refused (a stream that
/// is already closing), which leaves the wrap in the "attached to nothing" state
/// every method reports rather than crashing.
/// # Safety
///
/// `cell` must be the live state of `object`, and `stream` a live `StreamState`
/// that outlives the listener. `wrap()` is the only caller and satisfies both: it
/// allocated the state for the object's life and resolved the stream from the
/// handle the caller passed.
pub unsafe fn attach(
    object: v8::Local<v8::Object>,
    stream: *mut StreamState,
    cell: *mut RefCell<WrapState>,
) -> Option<rn_uv::listener::ListenerId> {
    if stream.is_null() || cell.is_null() {
        return None;
    }
    let _ = object;
    // SAFETY: `cell` is the live state of `object`, which `wrap` allocated and
    // which outlives the listener because `destroy()` removes it first.
    let listener = ListenerRef::new(Box::new(unsafe { WrapListener::new(cell) }));
    // SAFETY: `stream` is live — `stream_of` returns it from the symbol a stream
    // binding attached, and that binding keeps it valid until its close callback.
    unsafe { rn_uv::listener::push_stream_listener(stream, listener) }
}

/// Removes a listener previously installed by [`attach`].
///
/// Safe to call with an id that is no longer attached, which is the case
/// `on_stream_destroy` creates: the stream's own teardown removed the chain and
/// the wrap's later `destroy()` still has the stale id.
/// # Safety
///
/// `stream` must be live, which the wrap's `destroy()` path guarantees: it runs
/// before the stream's own teardown frees the state.
pub unsafe fn detach(stream: *mut StreamState, id: rn_uv::listener::ListenerId) {
    if stream.is_null() {
        return;
    }
    // SAFETY: `stream` was live when `attach` pushed the listener; the caller is
    // the wrap's `destroy()` path, which runs before the stream is freed.
    unsafe { rn_uv::listener::remove_stream_listener(stream, id) };
}

/// Reads the state behind a listener's cell, for `crate::cycle`.
///
/// Exposed rather than inlined so `cycle` does not have to know where the cell
/// came from, and so the null check lives next to the type that can be null.
///
/// # Safety
///
/// `cell` must be the live state cell of the wrap the caller is acting for, or
/// null.
pub unsafe fn with_cell<R>(
    cell: *mut RefCell<WrapState>,
    body: impl FnOnce(&mut WrapState) -> R,
) -> Option<R> {
    if cell.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the cell is live, per this function's
    // contract; `try_borrow_mut` reports a re-entrant call rather than aliasing.
    let cell = unsafe { &*cell };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

/// The `onread` function a `TLSWrap` object has, for the default listener path.
///
/// `lib/net.js` assigns `handle.onread`; when no listener is on the chain,
/// `rn_uv`'s `deliver_read` calls it. A `TLSWrap` with a listener never reaches
/// that path, but the accessor has to read and write the same slot for the
/// assignment to be observable, which is why this exists.
pub fn onread_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, "onread")?;
    let value = object.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

/// Accounts for bytes the listener accepts, for `bytesRead`.
/// # Safety
///
/// The wrap must still hold a live underlying stream, or none.
pub unsafe fn account_read(object: v8::Local<v8::Object>, count: usize) {
    let _ = with_state(object, |state| {
        // `StreamState` owns the counter; this only exists so a caller that has
        // the object but not the listener can keep it current.
        if let Some(stream) = state.underlying {
            // SAFETY: the underlying stream is live while the wrap holds it, per
            // `attach`'s contract.
            let state = unsafe { &mut *stream };
            state.bytes_read = state.bytes_read.saturating_add(count as u64);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener with a null cell reports nothing rather than crashing, which is
    /// the state a direct `new TLSWrap()` leaves behind.
    #[test]
    fn a_null_cell_is_refused() {
        let listener = WrapListener {
            cell: std::ptr::null_mut(),
        };
        assert!(listener.with(|_| ()).is_none());
        // SAFETY: null is explicitly handled and returns `None`.
        assert!(unsafe { with_cell(std::ptr::null_mut(), |_| ()) }.is_none());
    }

    /// A listener reaches the state it was built for, which is the one thing
    /// every read depends on.
    #[test]
    fn the_listener_reaches_its_state() {
        let cell = Box::into_raw(Box::new(RefCell::new(WrapState::new(
            crate::ssl::Kind::Server,
        ))));
        // SAFETY: `cell` is live and not aliased.
        let listener = unsafe { WrapListener::new(cell) };
        let kind = listener.with(|state| state.kind);
        assert_eq!(kind, Some(crate::ssl::Kind::Server));
        // SAFETY: nothing else holds `cell` after this point.
        let _ = listener;
        // SAFETY: `cell` came from `Box::into_raw` above.
        drop(unsafe { Box::from_raw(cell) });
    }

    /// A re-entrant borrow reports `None` instead of panicking, which is the R2
    /// case: the SSL callback calls JavaScript and `lib/net.js` destroys the
    /// socket from inside it.
    #[test]
    fn a_reentrant_borrow_is_reported() {
        let cell = Box::into_raw(Box::new(RefCell::new(WrapState::new(
            crate::ssl::Kind::Client,
        ))));
        // SAFETY: as above.
        let listener = unsafe { WrapListener::new(cell) };
        let outer = listener.with(|_state| {
            // The inner call stands in for a callback that re-enters while the
            // outer borrow is live.
            listener.with(|_| ()).is_none()
        });
        assert_eq!(outer, Some(true), "the inner borrow must be refused");
        let _ = listener;
        // SAFETY: `cell` came from `Box::into_raw` above.
        drop(unsafe { Box::from_raw(cell) });
    }
}
