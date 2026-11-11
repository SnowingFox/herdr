//! `StreamListener`: how one stream receives the bytes another stream read.
//!
//! Node's `TLSWrap` is `AsyncWrap + StreamBase + StreamListener` and owns no
//! `uv_stream_t` at all. It *wraps* another `StreamBase` — a `TCP` or a `Pipe` —
//! and receives that stream's reads through
//! `StreamListener::OnStreamRead`, decrypts them, and emits the cleartext back
//! out through its **own** `StreamBase`. `src/crypto/crypto_tls.cc` then
//! implements `GetFD`/`ReadStart`/`ReadStop`/`DoWrite`/`DoShutdown` against
//! `underlying_stream()`.
//!
//! This module is that indirection. It is the Rust spelling of
//! `src/stream_base.h:118-182` (`StreamListener`) and `:262-303`
//! (`StreamResource`'s listener half), and the method names are Node's so a
//! worker porting `crypto_tls.cc` can follow the C++ line by line:
//!
//! | Node (`src/stream_base.h`) | here |
//! | --- | --- |
//! | `StreamListener::OnStreamAlloc` :135 | [`StreamListener::on_stream_alloc`] |
//! | `StreamListener::OnStreamRead` :143 | [`StreamListener::on_stream_read`] |
//! | `StreamListener::OnStreamAfterWrite` :150 | [`StreamListener::on_stream_after_write`] |
//! | `StreamListener::OnStreamAfterShutdown` :156 | [`StreamListener::on_stream_after_shutdown`] |
//! | `StreamListener::OnStreamWantsWrite` :163 | [`StreamListener::on_stream_wants_write`] |
//! | `StreamListener::OnStreamDestroy` :166 | [`StreamListener::on_stream_destroy`] |
//! | `StreamListener::stream()` :169 | [`ListenerRef::stream`] |
//! | `StreamListener::PassReadErrorToPreviousListener` :176 | [`ListenerRef::pass_read_error_to_previous_listener`] |
//! | `StreamResource::PushStreamListener` :280 | [`push_stream_listener`] |
//! | `StreamResource::RemoveStreamListener` :283 | [`remove_stream_listener`] |
//! | `StreamResource::EmitAlloc` :287 | [`emit_alloc`] |
//! | `StreamResource::EmitRead` :290 | [`emit_read`] |
//! | `StreamResource::EmitAfterWrite` :294 | [`emit_after_write`] |
//! | `StreamResource::EmitAfterShutdown` :296 | [`emit_after_shutdown`] |
//! | `StreamResource::~StreamResource` (`stream_base.cc:898`) | [`Destroy on drop`](#teardown) |
//!
//! # The chain, and where `default_listener_` went
//!
//! Node's `StreamResource` holds a singly linked list through
//! `listener_`/`previous_listener_`, and `StreamBase`'s constructor pushes a
//! member `EmitToJSStreamListener` as the bottom of every chain. That listener
//! is the one that publishes `streamBaseState` and calls `handle.onread`.
//!
//! Here the same bottom is **absence**: `StreamState::listeners` empty means
//! "deliver to JavaScript", which is exactly what
//! [`crate::handle::deliver_read`] and [`crate::stream::report_completion`]
//! already do. Therefore:
//!
//! * no listener ⇒ the pre-existing code path, byte for byte, with no `Rc`
//!   allocation and no `RefCell` borrow on the hot path;
//! * `previous_listener_ == None` ⇒ the listener is the bottom of the chain and
//!   forwarding reaches JavaScript. That maps 1:1 onto Node, where the bottom
//!   listener's `previous_listener_` *is* `default_listener_`.
//!
//! # Borrow discipline (the rule the TLS work would otherwise break)
//!
//! `lib/net.js` can `destroy()` a socket from inside `onread`, and `TLSWrap`'s
//! listener callbacks run the SSL state machine, which calls back into
//! JavaScript. So **no Rust borrow of `StreamState`, or of any owning wrap's
//! state, may be live across a listener call**. That is why:
//!
//! * every entry point here takes `*mut StreamState`, not `&mut StreamState`.
//!   A raw pointer carries no aliasing claim, so the re-entrant `close()` that
//!   `destroy()` performs can borrow the state again legally;
//! * each function forms its `&mut` in a scope that ends before the call — the
//!   same shape [`crate::handle::deliver_read`] uses for `onread`;
//! * the listener is cloned out of the chain (`Rc`) before the borrow ends, so
//!   removing it mid-delivery cannot free the object under the running call.
//!
//! A `RefCell` *is* borrowed for the duration of a listener call, but it is the
//! listener's own cell — the method receiver, which cannot be expressed any
//! other way in Rust. Nothing else is borrowed while it is: `stream()`,
//! `id()`, `forward_*` and `remove_stream_listener` all touch `Cell`s or the
//! stream's own list. See `tests/listener_delivery.rs`, where a listener removes
//! itself from inside `on_stream_read`.
//!
//! # Teardown
//!
//! `StreamResource::~StreamResource` (`stream_base.cc:898`) walks the chain,
//! calls `OnStreamDestroy` on each listener and removes any that did not remove
//! itself. [`StreamState`]'s `Drop` does the same, and is why a binding that
//! frees a handle with a `TLSWrap` still attached cannot leave the listener
//! pointing at freed memory. `on_stream_destroy` must not call into JavaScript.

use std::cell::{Cell, RefCell};
use std::ptr;
use std::rc::Rc;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use crate::handle::{Allocation, StreamState};

/// The identity of one attached listener, Node's `StreamListener*`.
///
/// Ids are per-thread, monotonically increasing and never reused, so a stale id
/// can only ever fail to match rather than match a new listener.
pub type ListenerId = u64;

thread_local! {
    /// The next id [`ListenerRef::new`] hands out.
    static NEXT_ID: Cell<ListenerId> = const { Cell::new(1) };
}

/// One `StreamListener`, shared between its owner and the stream it is attached
/// to.
///
/// Node has the same two owners: `TLSWrap` owns itself and the underlying
/// stream holds a `StreamListener*` to it. The difference is that Node relies on
/// `Destroy()` calling `RemoveStreamListener` before the wrap dies; here the
/// stream holds an `Rc`, so a listener that outlives its stream keeps working
/// and one that dies early simply stops being reachable.
pub struct ListenerRef {
    inner: Rc<ListenerNode>,
}

/// The shared body of a [`ListenerRef`].
struct ListenerNode {
    id: ListenerId,
    /// The listener itself. Borrowed for exactly one callback.
    listener: RefCell<Box<dyn StreamListener>>,
    /// `StreamListener::stream_` — the resource this listener is attached to,
    /// or null when it is not attached.
    stream: Cell<*mut StreamState>,
    /// `StreamListener::previous_listener_` — the listener this one forwards
    /// to, or `None` for the bottom of the chain (JavaScript).
    ///
    /// Node stores a raw pointer and relies on `RemoveStreamListener` fixing
    /// every link. A strong reference is used here so a listener removed while
    /// a callback below it is still running stays alive until that callback
    /// returns.
    previous: RefCell<Option<ListenerRef>>,
}

impl Clone for ListenerRef {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl std::fmt::Debug for ListenerRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ListenerRef")
            .field("id", &self.id())
            .field("attached", &self.is_attached())
            .finish()
    }
}

impl ListenerRef {
    /// Wraps a listener so it can be pushed onto a stream.
    pub fn new(listener: Box<dyn StreamListener>) -> Self {
        let id = NEXT_ID.with(|next| {
            let id = next.get();
            next.set(id + 1);
            id
        });
        Self {
            inner: Rc::new(ListenerNode {
                id,
                listener: RefCell::new(listener),
                stream: Cell::new(ptr::null_mut()),
                previous: RefCell::new(None),
            }),
        }
    }

    /// This listener's identity, for [`remove_stream_listener`].
    pub fn id(&self) -> ListenerId {
        self.inner.id
    }

    /// `StreamListener::stream()` — the stream this listener is attached to.
    ///
    /// This is `TLSWrap::underlying_stream()`'s starting point: the returned
    /// pointer names the `StreamState` of the socket that is feeding this
    /// listener, and its `stream` field is the `uv_stream_t` to read from, stop
    /// reading, or write to.
    pub fn stream(&self) -> Option<*mut StreamState> {
        let pointer = self.inner.stream.get();
        if pointer.is_null() {
            None
        } else {
            Some(pointer)
        }
    }

    /// Whether this listener is currently on a stream's chain.
    pub fn is_attached(&self) -> bool {
        !self.inner.stream.get().is_null()
    }

    /// Runs `body` with the listener itself.
    ///
    /// The `RefCell` borrow is held for exactly one call into the listener,
    /// which is what makes `&mut`-based state machines such as `TLSWrap`'s
    /// possible without wrapping every field in a cell. Nothing else in this
    /// module borrows a listener across a call, so a listener that re-enters
    /// this module — forwarding, removing itself, or reading its own stream —
    /// cannot collide with it.
    ///
    /// A listener that calls back into *itself* is a structural error and would
    /// panic on the second borrow, exactly as Node's equivalent recursion would
    /// corrupt the SSL state machine. Forwarding goes to `previous`, which is a
    /// different listener.
    pub fn with<R>(&self, body: impl FnOnce(&mut dyn StreamListener) -> R) -> R {
        let mut listener = self.inner.listener.borrow_mut();
        body(&mut **listener)
    }

    /// `StreamListener::PassReadErrorToPreviousListener` (`stream_base.h:176`).
    ///
    /// A protocol listener does not care about read errors — `TLSWrap` forwards
    /// `nread < 0` to whoever was listening below it so the socket can emit the
    /// error. The buffer is `uv_buf_init(nullptr, 0)`, as in `stream_base-inl.h:57`.
    pub fn pass_read_error_to_previous_listener(&self, nread: isize) {
        let previous = self.previous();
        let buffer = ReadBuffer::Listener(uv::uv_buf_t {
            base: ptr::null_mut(),
            len: 0,
        });
        match previous {
            Some(previous) => previous.dispatch_read(nread, buffer),
            // Bottom of the chain: this is Node's `default_listener_`.
            None => match self.stream() {
                Some(state) => deliver_to_js(state, nread, buffer),
                None => drop(buffer),
            },
        }
    }

    /// `StreamListener::OnStreamAfterWrite`'s default body: hand the completion
    /// to the previous listener, or to JavaScript when there is none.
    pub fn forward_after_write<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        request: v8::Local<'s, v8::Object>,
        handle: Option<v8::Local<'s, v8::Object>>,
        status: i32,
    ) {
        match self.previous() {
            Some(previous) => {
                previous.with(|listener| {
                    listener.on_stream_after_write(&previous, scope, request, handle, status)
                });
            }
            None => {
                crate::stream::report_completion(scope, request, status, handle, None);
            }
        }
    }

    /// `StreamListener::OnStreamAfterShutdown`'s default body.
    pub fn forward_after_shutdown<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        request: v8::Local<'s, v8::Object>,
        handle: Option<v8::Local<'s, v8::Object>>,
        status: i32,
    ) {
        match self.previous() {
            Some(previous) => {
                previous.with(|listener| {
                    listener.on_stream_after_shutdown(&previous, scope, request, handle, status)
                });
            }
            None => {
                crate::stream::report_completion(scope, request, status, handle, None);
            }
        }
    }

    /// The listener below this one, if any.
    fn previous(&self) -> Option<ListenerRef> {
        self.inner.previous.borrow().clone()
    }

    /// Clears `StreamListener::stream_` without touching the chain.
    ///
    /// Used by the stream's own teardown, which has already taken the whole
    /// chain apart and only needs the listeners to stop pointing at a state that
    /// is about to be freed.
    pub(crate) fn detach_from_stream(&self) {
        self.inner.stream.set(ptr::null_mut());
    }

    /// Delivers one read to this listener.
    fn dispatch_read(&self, nread: isize, buffer: ReadBuffer) {
        self.with(|listener| listener.on_stream_read(self, nread, buffer));
    }
}

/// The interface `src/stream_base.h:118` describes: an object that controls a
/// stream, instead of a stream that emits to JavaScript.
///
/// `TLSWrap` is the reason this exists — it is an `AsyncWrap + StreamBase +
/// StreamListener` with no libuv handle of its own — but nothing here mentions
/// TLS. `StreamPipe` and `CustomBufferJSListener` are the other two users in
/// Node and both fit this trait.
pub trait StreamListener {
    /// `StreamListener::OnStreamAlloc` (`src/stream_base.h:135`).
    ///
    /// Called before every read, and the buffer returned here is what
    /// `on_stream_read` receives. `TLSWrap` returns a slice of its `NodeBIO`'s
    /// writable region, so the bytes are read straight into the buffer OpenSSL
    /// will decrypt from.
    ///
    /// Returning `None` asks for this crate's default allocation, which is the
    /// equivalent of Node's pure virtual default (Node has no default body to
    /// inherit — every listener provides one). The buffer must not be
    /// zero-length, which `stream_base.h:132` states explicitly.
    ///
    /// A returned buffer belongs to the listener: this crate never frees it.
    fn on_stream_alloc(&mut self, _suggested_size: usize) -> Option<uv::uv_buf_t> {
        None
    }

    /// `StreamListener::OnStreamRead` (`src/stream_base.h:143`).
    ///
    /// `nread` is the byte count, or a negative libuv error code — `UV_EOF` ends
    /// the stream. `this` is the listener as the stream sees it, which is what
    /// `stream()`, `id()` and the `forward_*` helpers act on; Rust methods do
    /// not come with the C++ `this` an equivalent needs.
    ///
    /// The bytes are only valid for the duration of the call.
    fn on_stream_read(&mut self, this: &ListenerRef, nread: isize, buffer: ReadBuffer);

    /// `StreamListener::OnStreamAfterWrite` (`src/stream_base.h:150`).
    ///
    /// The default is Node's: pass the completion to the previous listener.
    /// `TLSWrap` overrides it to complete its own `WriteWrap` instead, because
    /// the write the underlying socket finished is the *ciphertext* it queued,
    /// not the cleartext the caller is waiting on.
    fn on_stream_after_write<'s>(
        &mut self,
        this: &ListenerRef,
        scope: &mut v8::PinScope<'s, '_>,
        request: v8::Local<'s, v8::Object>,
        handle: Option<v8::Local<'s, v8::Object>>,
        status: i32,
    ) {
        this.forward_after_write(scope, request, handle, status);
    }

    /// `StreamListener::OnStreamAfterShutdown` (`src/stream_base.h:156`).
    fn on_stream_after_shutdown<'s>(
        &mut self,
        this: &ListenerRef,
        scope: &mut v8::PinScope<'s, '_>,
        request: v8::Local<'s, v8::Object>,
        handle: Option<v8::Local<'s, v8::Object>>,
        status: i32,
    ) {
        this.forward_after_shutdown(scope, request, handle, status);
    }

    /// `StreamListener::OnStreamWantsWrite` (`src/stream_base.h:163`).
    ///
    /// Node requires `stream->HasWantsWrite()`; no stream in this crate reports
    /// it yet, so the hook exists for parity and is never called.
    fn on_stream_wants_write(&mut self, _suggested_size: usize) {}

    /// `StreamListener::OnStreamDestroy` (`src/stream_base.h:166`).
    ///
    /// Called from the stream's teardown, before the listener is detached. It
    /// must not call into JavaScript: the environment may already be gone.
    fn on_stream_destroy(&mut self, _this: &ListenerRef) {}
}

/// One read's buffer, with the ownership the allocator decided.
///
/// Node hands `OnStreamRead` a bare `uv_buf_t` and relies on the listener that
/// provided it through `OnStreamAlloc` to be the one that releases it. Rust has
/// to say which is which, because the default allocator's buffer is freed by
/// this crate and a listener's buffer must never be.
pub enum ReadBuffer {
    /// Allocated by this crate's default allocator; the reader frees it.
    Allocated(Allocation),
    /// A buffer a listener returned from [`StreamListener::on_stream_alloc`];
    /// the listener owns it.
    Listener(uv::uv_buf_t),
}

impl ReadBuffer {
    /// The bytes for a read of `nread`, or `None` when there are none.
    pub fn bytes(&self, nread: isize) -> Option<&[u8]> {
        if nread <= 0 {
            return None;
        }
        let (base, length) = match self {
            Self::Allocated(allocation) => (allocation.base_const(), allocation.length()),
            Self::Listener(buffer) => (buffer.base.cast::<u8>().cast_const(), buffer.len),
        };
        if base.is_null() || nread as usize > length {
            return None;
        }
        // SAFETY: `base` points at `length` bytes owned by the stream read that
        // produced this buffer, and `nread <= length`.
        Some(unsafe { std::slice::from_raw_parts(base, nread as usize) })
    }

    /// The buffer as Node's `OnStreamRead` receives it.
    pub fn as_uv_buf(&self) -> uv::uv_buf_t {
        match self {
            Self::Allocated(allocation) => uv::uv_buf_t {
                base: allocation.base_const().cast_mut().cast(),
                len: allocation.length(),
            },
            Self::Listener(buffer) => *buffer,
        }
    }
}

/// `StreamResource::PushStreamListener` (`src/stream_base.h:280`).
///
/// Attaches `listener` to `state`, making it the one that sees the stream's
/// reads until something above it is pushed. This is what
/// `crypto_tls.cc:417`'s `stream->PushStreamListener(this)` becomes.
///
/// Returns the listener's id, or `None` when `state` is null or the listener is
/// already attached — Node's `CHECK_NOT_NULL(listener->stream_)`.
///
/// # Safety
///
/// `state` must be a live [`StreamState`] that outlives the attachment. The
/// caller owns it (a binding's per-handle box), which is the same guarantee
/// [`crate::handle::set_owner`] requires.
pub unsafe fn push_stream_listener(
    state: *mut StreamState,
    listener: ListenerRef,
) -> Option<ListenerId> {
    if state.is_null() {
        tracing::error!("PushStreamListener called with no stream");
        return None;
    }
    if listener.is_attached() {
        tracing::error!(
            id = listener.id(),
            "PushStreamListener called for a listener that is already attached"
        );
        return None;
    }
    // SAFETY: the caller guarantees `state` is live. No listener code runs
    // while this borrow is held, so it cannot be re-entered.
    let state = unsafe { &mut *state };
    let previous = state.listeners.last().cloned();
    let id = listener.id();
    listener.inner.previous.replace(previous);
    listener.inner.stream.set(state as *mut StreamState);
    state.listeners.push(listener);
    Some(id)
}

/// `StreamResource::RemoveStreamListener` (`src/stream_base.cc:911`).
///
/// Detaches a listener. Safe to call from inside that listener's own callback:
/// the dispatcher holds an `Rc` to it, so the object survives until the call
/// returns, and the chain it was removed from is not borrowed at the time.
///
/// Returns whether a listener with that id was attached, which is Node's
/// `CHECK_NOT_NULL(current)` on the search loop.
///
/// # Safety
///
/// `state` must be live, or null.
pub unsafe fn remove_stream_listener(state: *mut StreamState, id: ListenerId) -> bool {
    if state.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees `state` is live.
    let state = unsafe { &mut *state };
    let Some(position) = state.listeners.iter().position(|entry| entry.id() == id) else {
        tracing::debug!(
            id,
            "RemoveStreamListener for a listener that is not attached"
        );
        return false;
    };
    let removed = state.listeners.remove(position);
    // Node's unlink repairs the *higher* listener's `previous_listener_` so the
    // chain stays connected across the hole.
    if let Some(above) = state.listeners.get(position) {
        let previous = removed.previous();
        above.inner.previous.replace(previous);
    }
    removed.inner.stream.set(ptr::null_mut());
    removed.inner.previous.replace(None);
    true
}

/// How many listeners are attached, innermost first.
///
/// # Safety
///
/// `state` must be live, or null.
pub unsafe fn listener_count(state: *mut StreamState) -> usize {
    if state.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees `state` is live.
    unsafe { &*state }.listeners.len()
}

/// The listener a read or completion is delivered to, `None` for JavaScript.
fn top_listener(state: *mut StreamState) -> Option<ListenerRef> {
    if state.is_null() {
        return None;
    }
    // SAFETY: every caller of the `emit_*` functions passes a state it owns; the
    // borrow ends with this expression, before any listener runs.
    let state = unsafe { &*state };
    state.listeners.last().cloned()
}

/// `StreamResource::EmitAlloc` (`src/stream_base.h:287`).
///
/// Asks the current listener for the buffer the next read should land in.
/// `None` means "use the default allocation", which is what an empty chain
/// gives.
///
/// # Safety
///
/// `state` must be live, or null.
pub unsafe fn emit_alloc(state: *mut StreamState, suggested_size: usize) -> Option<uv::uv_buf_t> {
    let listener = top_listener(state)?;
    let buffer = listener.with(|inner| inner.on_stream_alloc(suggested_size))?;
    // `src/stream_base.h:132`: "It is not valid to return a zero-length buffer
    // from this method." A listener that does is treated as having no opinion
    // rather than being handed to libuv as a failed allocation.
    if buffer.base.is_null() || buffer.len == 0 {
        tracing::error!(id = listener.id(), "OnStreamAlloc returned an empty buffer");
        return None;
    }
    Some(buffer)
}

/// `StreamResource::EmitRead` (`src/stream_base.h:290`).
///
/// Counts the bytes on `state` — Node increments `bytes_read_` before the
/// listener sees them, so `handle.bytesRead` is already current inside
/// `OnStreamRead` — then delivers to the current listener, or to `handle.onread`
/// when there is none.
///
/// # Safety
///
/// `state` must be live, or null. No reference to it may be held by the caller
/// across this call.
pub unsafe fn emit_read(state: *mut StreamState, nread: isize, buffer: ReadBuffer) {
    if state.is_null() {
        return;
    }
    let listener = {
        // SAFETY: the caller guarantees `state` is live. This borrow ends here.
        let state = unsafe { &mut *state };
        if nread > 0 {
            state.bytes_read += nread as u64;
        }
        state.listeners.last().cloned()
    };
    match listener {
        Some(listener) => listener.dispatch_read(nread, buffer),
        None => deliver_to_js(state, nread, buffer),
    }
}

/// `StreamResource::EmitAfterWrite` (`src/stream_base.h:294`).
///
/// # Safety
///
/// `state` must be live, or null, and must stay live until `status` has been
/// reported. libuv calls a write's completion before the handle's close
/// callback, so a state that is still queuing writes satisfies this.
pub unsafe fn emit_after_write<'s>(
    state: *mut StreamState,
    scope: &mut v8::PinScope<'s, '_>,
    request: v8::Local<'s, v8::Object>,
    handle: Option<v8::Local<'s, v8::Object>>,
    status: i32,
) {
    match top_listener(state) {
        Some(listener) => listener
            .with(|inner| inner.on_stream_after_write(&listener, scope, request, handle, status)),
        None => {
            crate::stream::report_completion(scope, request, status, handle, None);
        }
    }
}

/// `StreamResource::EmitAfterShutdown` (`src/stream_base.h:296`).
///
/// # Safety
///
/// As [`emit_after_write`].
pub unsafe fn emit_after_shutdown<'s>(
    state: *mut StreamState,
    scope: &mut v8::PinScope<'s, '_>,
    request: v8::Local<'s, v8::Object>,
    handle: Option<v8::Local<'s, v8::Object>>,
    status: i32,
) {
    match top_listener(state) {
        Some(listener) => listener.with(|inner| {
            inner.on_stream_after_shutdown(&listener, scope, request, handle, status)
        }),
        None => {
            crate::stream::report_completion(scope, request, status, handle, None);
        }
    }
}

/// `StreamResource::EmitRead`'s tail with no listener: publish and call `onread`.
fn deliver_to_js(state: *mut StreamState, nread: isize, buffer: ReadBuffer) {
    // A buffer that came from a listener is the *listener's* to release, so it
    // is copied rather than adopted. This is the path
    // `stream_base.cc:746` describes: a read allocated by one listener arriving
    // at another whose read was rerouted after that listener was removed.
    let allocation = match buffer {
        ReadBuffer::Allocated(allocation) => Some(allocation),
        ReadBuffer::Listener(buffer) => copy_of(&buffer, nread),
    };
    // SAFETY: `deliver_to_js` runs only when no listener is attached, and it
    // holds no borrow of `state` itself.
    unsafe { crate::handle::deliver_read(state, nread, allocation) };
}

/// Copies `nread` bytes of a listener's buffer into an owned allocation.
fn copy_of(buffer: &uv::uv_buf_t, nread: isize) -> Option<Allocation> {
    if nread <= 0 || buffer.base.is_null() {
        return None;
    }
    let length = nread as usize;
    if length > buffer.len {
        return None;
    }
    let mut allocation = Allocation::new(length)?;
    // SAFETY: `buffer.base` points at `buffer.len` bytes the listener owns, and
    // `length <= buffer.len`. `allocation` is a distinct allocation of `length`.
    unsafe { ptr::copy_nonoverlapping(buffer.base.cast::<u8>(), allocation.base(), length) };
    Some(allocation)
}

impl ListenerRef {
    /// Calls `OnStreamDestroy`, tolerating a listener that is mid-callback.
    ///
    /// `try_borrow_mut` rather than `borrow_mut`: a stream can be dropped while
    /// one of its own listener callbacks is unwinding, in which case the
    /// listener is still borrowed by that frame and the notification would
    /// re-enter itself.
    pub(crate) fn notify_destroyed(&self) {
        match self.inner.listener.try_borrow_mut() {
            Ok(mut listener) => listener.on_stream_destroy(self),
            Err(_) => tracing::debug!(
                id = self.id(),
                "OnStreamDestroy skipped: the listener is mid-callback"
            ),
        }
        self.inner.previous.replace(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a [`Recorder`] saw, so a test can read it back out of the `Rc`.
    #[derive(Default, Clone, Debug, PartialEq, Eq)]
    struct RecorderLog {
        reads: Vec<isize>,
        writes: Vec<i32>,
        destroyed: bool,
        alloc_sizes: Vec<usize>,
    }

    /// A listener that records what it was given and does nothing else.
    #[derive(Default)]
    struct Recorder {
        log: Rc<RefCell<RecorderLog>>,
    }

    impl Recorder {
        fn new() -> (Self, Rc<RefCell<RecorderLog>>) {
            let log = Rc::new(RefCell::new(RecorderLog::default()));
            (
                Self {
                    log: Rc::clone(&log),
                },
                log,
            )
        }
    }

    impl StreamListener for Recorder {
        fn on_stream_alloc(&mut self, suggested_size: usize) -> Option<uv::uv_buf_t> {
            self.log.borrow_mut().alloc_sizes.push(suggested_size);
            None
        }

        fn on_stream_read(&mut self, _this: &ListenerRef, nread: isize, _buffer: ReadBuffer) {
            self.log.borrow_mut().reads.push(nread);
        }

        fn on_stream_after_write<'s>(
            &mut self,
            _this: &ListenerRef,
            _scope: &mut v8::PinScope<'s, '_>,
            _request: v8::Local<'s, v8::Object>,
            _handle: Option<v8::Local<'s, v8::Object>>,
            status: i32,
        ) {
            self.log.borrow_mut().writes.push(status);
        }

        fn on_stream_destroy(&mut self, _this: &ListenerRef) {
            self.log.borrow_mut().destroyed = true;
        }
    }

    /// A `StreamState` with no libuv handle, which is all the chain needs.
    fn state() -> StreamState {
        StreamState::new(ptr::null_mut())
    }

    /// An empty listener buffer, which `bytes()` rejects and `as_uv_buf` keeps.
    fn empty() -> ReadBuffer {
        ReadBuffer::Listener(uv::uv_buf_t {
            base: ptr::null_mut(),
            len: 0,
        })
    }

    #[test]
    fn a_pushed_listener_becomes_the_one_delivered_to() {
        let mut state = state();
        let pointer = &mut state as *mut StreamState;
        let (recorder, log) = Recorder::new();
        let listener = ListenerRef::new(Box::new(recorder));
        // SAFETY: `pointer` names a live state for the whole test.
        let id = unsafe { push_stream_listener(pointer, listener.clone()) };
        assert_eq!(id, Some(listener.id()));
        assert!(listener.is_attached());
        assert_eq!(listener.stream(), Some(pointer));

        // SAFETY: as above.
        unsafe { emit_read(pointer, 7, empty()) };
        assert_eq!(state.bytes_read, 7, "the stream counts before the listener");
        assert_eq!(
            log.borrow().reads,
            vec![7],
            "the push made this listener the destination"
        );
    }

    #[test]
    fn a_removed_listener_is_no_longer_the_destination() {
        let mut state = state();
        let pointer = &mut state as *mut StreamState;
        let (recorder, log) = Recorder::new();
        let listener = ListenerRef::new(Box::new(recorder));
        // SAFETY: `pointer` names a live state for the whole test.
        unsafe {
            push_stream_listener(pointer, listener.clone());
            assert!(remove_stream_listener(pointer, listener.id()));
            assert!(
                !remove_stream_listener(pointer, listener.id()),
                "removing twice reports nothing was there, as Node's search loop does"
            );
            // With no listener attached the read goes to JavaScript, and a state
            // with no owner object simply drops it. The point is that it is not
            // handed to the removed listener.
            emit_read(pointer, 4, empty());
        }
        assert!(!listener.is_attached());
        assert_eq!(listener.stream(), None);
        assert!(log.borrow().reads.is_empty(), "delivery stopped");
        assert_eq!(unsafe { listener_count(pointer) }, 0);
    }

    #[test]
    fn a_listener_cannot_be_pushed_twice() {
        let mut state = state();
        let pointer = &mut state as *mut StreamState;
        let (recorder, _log) = Recorder::new();
        let listener = ListenerRef::new(Box::new(recorder));
        // SAFETY: `pointer` names a live state for the whole test.
        unsafe {
            assert!(push_stream_listener(pointer, listener.clone()).is_some());
            assert_eq!(
                push_stream_listener(pointer, listener.clone()),
                None,
                "Node CHECKs `listener->stream_ == nullptr`"
            );
        }
    }

    #[test]
    fn dropping_the_stream_notifies_and_detaches_its_listeners() {
        let (recorder, log) = Recorder::new();
        let listener = ListenerRef::new(Box::new(recorder));
        {
            let mut state = state();
            let pointer = &mut state as *mut StreamState;
            // SAFETY: `pointer` names a live state inside this block.
            unsafe { push_stream_listener(pointer, listener.clone()) };
            assert!(listener.is_attached());
        }
        assert!(!listener.is_attached(), "teardown detaches");
        assert!(
            log.borrow().destroyed,
            "`OnStreamDestroy` ran, as `StreamResource::~StreamResource` does"
        );
    }

    #[test]
    fn forwarding_reaches_the_listener_below() {
        let mut state = state();
        let pointer = &mut state as *mut StreamState;
        let (below_recorder, below_log) = Recorder::new();
        let below = ListenerRef::new(Box::new(below_recorder));
        let (above_recorder, above_log) = Recorder::new();
        let above = ListenerRef::new(Box::new(above_recorder));
        // SAFETY: `pointer` names a live state for the whole test.
        unsafe {
            push_stream_listener(pointer, below.clone());
            push_stream_listener(pointer, above.clone());
            emit_read(pointer, 3, empty());
        }
        assert!(
            below_log.borrow().reads.is_empty(),
            "only the top listener sees a read"
        );
        assert_eq!(above_log.borrow().reads, vec![3]);

        // `PassReadErrorToPreviousListener` is the forwarding path a protocol
        // listener uses for errors it does not own.
        above.pass_read_error_to_previous_listener(-4095);
        assert_eq!(
            below_log.borrow().reads,
            vec![-4095],
            "the error reached the listener below"
        );
    }

    #[test]
    fn removing_the_middle_listener_keeps_the_chain_connected() {
        let mut state = state();
        let pointer = &mut state as *mut StreamState;
        let (bottom_recorder, bottom_log) = Recorder::new();
        let bottom = ListenerRef::new(Box::new(bottom_recorder));
        let (middle_recorder, middle_log) = Recorder::new();
        let middle = ListenerRef::new(Box::new(middle_recorder));
        let (top_recorder, top_log) = Recorder::new();
        let top = ListenerRef::new(Box::new(top_recorder));
        // SAFETY: `pointer` names a live state for the whole test.
        unsafe {
            push_stream_listener(pointer, bottom.clone());
            push_stream_listener(pointer, middle.clone());
            push_stream_listener(pointer, top.clone());
            assert!(remove_stream_listener(pointer, middle.id()));
            emit_read(pointer, 5, empty());
        }
        // The top still sees the read, and forwarding now skips the hole.
        assert_eq!(top_log.borrow().reads, vec![5]);
        top.pass_read_error_to_previous_listener(-1);
        assert_eq!(
            bottom_log.borrow().reads,
            vec![-1],
            "the removed middle listener is out of the chain"
        );
        assert!(
            middle_log.borrow().reads.is_empty(),
            "the middle listener is detached, not merely skipped"
        );
    }

    #[test]
    fn the_alloc_hook_only_runs_for_the_listener_on_top() {
        let mut state = state();
        let pointer = &mut state as *mut StreamState;
        let (recorder, log) = Recorder::new();
        let listener = ListenerRef::new(Box::new(recorder));
        // SAFETY: `pointer` names a live state for the whole test.
        unsafe {
            assert!(
                emit_alloc(pointer, 4096).is_none(),
                "no listener, no opinion"
            );
            push_stream_listener(pointer, listener);
            assert!(emit_alloc(pointer, 4096).is_none(), "the hook was asked");
        }
        assert_eq!(log.borrow().alloc_sizes, vec![4096]);
    }

    #[test]
    fn a_listener_that_returns_an_empty_buffer_is_ignored() {
        struct Empty;
        impl StreamListener for Empty {
            fn on_stream_alloc(&mut self, _suggested_size: usize) -> Option<uv::uv_buf_t> {
                // `stream_base.h:132` forbids this, so it must not reach libuv.
                Some(uv::uv_buf_t {
                    base: ptr::null_mut(),
                    len: 0,
                })
            }

            fn on_stream_read(&mut self, _this: &ListenerRef, _nread: isize, _buffer: ReadBuffer) {}
        }

        let mut state = state();
        let pointer = &mut state as *mut StreamState;
        // SAFETY: `pointer` names a live state for the whole test.
        unsafe {
            push_stream_listener(pointer, ListenerRef::new(Box::new(Empty)));
            assert!(emit_alloc(pointer, 16).is_none());
        }
    }

    /// Removal from inside the callback is the case `Destroy()` creates: a
    /// `lib/net.js` listener can `destroy()` the socket while `OnStreamRead` is
    /// running, and that runs `RemoveStreamListener(this)` on the listener whose
    /// method is on the stack.
    #[test]
    fn a_listener_can_remove_itself_from_inside_a_read() {
        struct SelfRemover {
            state: *mut StreamState,
            seen: usize,
        }

        impl StreamListener for SelfRemover {
            fn on_stream_read(&mut self, this: &ListenerRef, nread: isize, _buffer: ReadBuffer) {
                if nread > 0 {
                    self.seen += 1;
                    // The same call `TLSWrap::Destroy` makes.
                    // SAFETY: the test keeps `state` live for the whole run.
                    unsafe { remove_stream_listener(self.state, this.id()) };
                }
            }
        }

        let mut state = state();
        let pointer = &mut state as *mut StreamState;
        let listener = ListenerRef::new(Box::new(SelfRemover {
            state: pointer,
            seen: 0,
        }));
        // SAFETY: `pointer` names a live state for the whole test.
        unsafe {
            push_stream_listener(pointer, listener.clone());
            emit_read(pointer, 10, empty());
            assert_eq!(listener_count(pointer), 0, "it removed itself mid-callback");
            assert!(!listener.is_attached());
            // A second read now reaches JavaScript, not the listener.
            emit_read(pointer, 10, empty());
        }
        assert_eq!(
            state.bytes_read, 20,
            "both reads were counted, which `EmitRead` does before delivery"
        );
    }
}
