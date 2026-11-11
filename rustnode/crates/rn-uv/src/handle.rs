//! The shared half of a libuv stream handle.
//!
//! `src/stream_wrap.cc`'s `LibuvStreamWrap` is the base of `TCP` and `Pipe`:
//! both own a `uv_stream_t`, both run the identical read and write paths, and
//! both report completion to JavaScript through `onread`/`oncomplete`.
//!
//! # The read contract
//!
//! `lib/internal/stream_base_commons.js`'s `onStreamRead` does not receive the
//! bytes. It receives an `ArrayBuffer` and reads the count and offset out of the
//! shared `streamBaseState` array first:
//!
//! ```js
//! function onStreamRead(arrayBuffer) {
//!   const nread = streamBaseState[kReadBytesOrError];
//!   const offset = streamBaseState[kArrayBufferOffset];
//!   const buf = new FastBuffer(arrayBuffer, offset, nread);
//! ```
//!
//! So a read publishes `(nread, offset)` *before* calling `onread`, and hands
//! over an `ArrayBuffer` whose backing store holds the bytes. `offset` exists
//! because Node recycles read slabs and a read can start part way into one;
//! rustnode allocates per read and always starts at 0, so the field is written
//! but always zero. It is still written, because a stale non-zero value from an
//! earlier read would silently slice the buffer.

use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use crate::callback;

/// `StreamBaseStateFields::kReadBytesOrError` — index into `streamBaseState`
/// holding the byte count, or the negative error code, of a finished read.
///
/// These five live here rather than in the `stream_wrap` binding because the
/// read and write paths below are what write them, and because they are an ABI
/// fact about `src/stream_base.h` rather than a detail of that namespace. The
/// binding re-exports them, so `internalBinding('stream_wrap')` publishes exactly
/// these numbers.
pub const K_READ_BYTES_OR_ERROR: usize = 0;
/// `StreamBaseStateFields::kArrayBufferOffset` — where in the delivered
/// `ArrayBuffer` a read's bytes start.
pub const K_ARRAY_BUFFER_OFFSET: usize = 1;
/// `StreamBaseStateFields::kBytesWritten` — bytes the last write accounted for.
pub const K_BYTES_WRITTEN: usize = 2;
/// `StreamBaseStateFields::kLastWriteWasAsync` — 1 when the last write queued
/// rather than completing inline.
pub const K_LAST_WRITE_WAS_ASYNC: usize = 3;
/// `StreamBaseStateFields::kLastWriteErr` — the error of the last write, or 0.
pub const K_LAST_WRITE_ERR: usize = 4;
/// `StreamBaseStateFields::kNumStreamBaseStateFields` — the array's length.
///
/// The element type is `Int32Array`: `src/env.h` declares the field as
/// `AliasedInt32Array`. Getting the width wrong is not an error, it silently
/// changes what an index means on one side, which is why the `stream_wrap`
/// tests write from JavaScript and read back from Rust.
pub const STREAM_BASE_STATE_FIELDS: usize = 5;

/// Where the handle is in its lifecycle, mirroring `HandleWrap::State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleState {
    /// `uv_*_init` has run and the handle can be used.
    Initialized,
    /// `uv_close` has been called but its callback has not fired yet.
    Closing,
    /// The close callback fired; the handle must not be touched again.
    Closed,
}

/// The JS function stored on a handle as `onread`, rooted across the native
/// call.
pub type JsCallback = v8::Global<v8::Function>;

/// The state a stream wrap keeps for one libuv handle.
///
/// The `uv_*_t` itself is not here: libuv requires a handle not to move after
/// `uv_*_init`, so a binding allocates it separately and stores a pointer here.
/// That split is what lets the state live in a `Box` (which may move) while the
/// handle stays put.
pub struct StreamState {
    /// The libuv handle, valid until the state is dropped.
    pub stream: *mut uv::uv_stream_t,
    /// Lifecycle, mirroring `HandleWrap::state_`.
    pub state: HandleState,
    /// The JS function stored as `handle.onread`.
    pub on_read: Option<JsCallback>,
    /// Bytes read so far, `StreamResource::bytes_read_`.
    pub bytes_read: u64,
    /// Bytes handed to writes so far, `StreamResource::bytes_written_`.
    pub bytes_written: u64,
    /// `AsyncWrap`'s id, trigger id and provider kind.
    ///
    /// Every wrapped handle in Node is an `AsyncWrap` with an id of its own, and
    /// `lib/net.js` reads it as `this._handle.getAsyncId()` to key the socket's
    /// `async_id_symbol`. `AsyncReset` re-issues the id when a pooled socket is
    /// reused, which is what `lib/internal/http/agent.js::asyncResetHandle` asks
    /// for; keeping the three fields together is what makes that one state
    /// transition rather than three that can disagree.
    ///
    /// The state is plain data because this crate must not depend on a binding;
    /// the `AsyncReset` behaviour that advances it lives in `rn-bind-async-wrap`
    /// and `rn-bind-tcp-wrap` calls it.
    pub async_wrap: rn_core::AsyncWrapState,
    /// The object this state belongs to, rooted.
    ///
    /// Node keeps the reverse mapping (`handle[owner_symbol]`), which works
    /// because the JavaScript object outlives the handle. A native completion
    /// runs with no such mapping available, so the object is rooted here instead
    /// and released when the wrapper is finalised.
    pub owner_object: Option<v8::Global<v8::Object>>,
    /// `AsyncWrap`'s `kAsyncContextFrame`, rooted.
    ///
    /// Node stores the frame in the handle object's internal field
    /// (`kAsyncContextFrame`, `src/async_wrap.h:123`) and `AsyncReset` fills it
    /// from `async_context_frame::current()` (`src/async_wrap.cc:635`). This is
    /// that field, kept beside `owner_object` for the same reason: the callback
    /// that needs it runs from `uv_run`, where only a Rust-side value is
    /// guaranteed reachable.
    ///
    /// It is what makes `AsyncLocalStorage` propagate into a socket callback. A
    /// callback that does not install it runs with whatever frame the last
    /// callback left behind, which outside a `run()` is `undefined`.
    ///
    /// `None` is Node's empty internal field — no frame captured — which reads
    /// as `undefined`, the same value `getStore()` reports outside any `run()`.
    pub context_frame: Option<v8::Global<v8::Value>>,
    /// `StreamResource::listener_`, innermost first.
    ///
    /// Empty means "deliver to JavaScript", which is where Node keeps a
    /// `default_listener_` at the bottom of every chain. See [`crate::listener`]
    /// for the contract and [`crate::listener::push_stream_listener`] for the
    /// only writer.
    ///
    /// A binding may read the length to know whether something is still
    /// listening, but the chain must only be mutated through
    /// `crate::listener`, because that module maintains the
    /// `previous_listener_` links the forwarding paths walk.
    pub listeners: Vec<crate::listener::ListenerRef>,
}

impl StreamState {
    /// A state for a freshly initialised handle.
    pub fn new(stream: *mut uv::uv_stream_t) -> Self {
        Self {
            stream,
            state: HandleState::Initialized,
            on_read: None,
            bytes_read: 0,
            bytes_written: 0,
            async_wrap: rn_core::AsyncWrapState::uninitialised(rn_core::async_wrap::PROVIDER_NONE),
            owner_object: None,
            context_frame: None,
            listeners: Vec::new(),
        }
    }

    /// Whether the handle can still be used, matching `HandleWrap::IsAlive`.
    pub fn is_alive(&self) -> bool {
        self.state == HandleState::Initialized
    }

    /// Whether libuv considers the handle closed or closing.
    pub fn is_closing(&self) -> bool {
        if self.stream.is_null() {
            return true;
        }
        // SAFETY: `stream` is a live libuv handle while this state exists.
        unsafe { uv::uv_is_closing(as_handle(self.stream)) != 0 }
    }

    /// Notifies and detaches every attached listener, innermost last.
    ///
    /// This is the body of `StreamResource::~StreamResource` and is what
    /// `Drop` calls. It is a method rather than a free function so `Drop` can
    /// hand `&mut self` rather than manufacturing a second `&mut` from a raw
    /// pointer to the value being dropped.
    ///
    /// Each listener's `on_stream_destroy` must not call into JavaScript: the
    /// state is being freed, so anything it reaches back into may already be
    /// gone. [`crate::listener`] documents the same constraint on the trait.
    pub fn destroy_listeners(&mut self) {
        let listeners = std::mem::take(&mut self.listeners);
        for listener in &listeners {
            listener.detach_from_stream();
        }
        for listener in &listeners {
            listener.notify_destroyed();
        }
    }
}

/// `StreamResource::~StreamResource` (`src/stream_base.cc:898`).
///
/// A stream's teardown notifies and detaches everything listening to it. Without
/// this, a `TLSWrap` attached to a socket that closed first would keep a
/// dangling `stream_` into freed memory — and its own `Destroy()` would call
/// `RemoveStreamListener` on that memory.
impl Drop for StreamState {
    fn drop(&mut self) {
        if self.listeners.is_empty() {
            return;
        }
        self.destroy_listeners();
    }
}

/// An owned read allocation, from `alloc_cb` to the `ArrayBuffer` JS receives.
pub struct Allocation {
    pointer: *mut u8,
    length: usize,
}

impl Allocation {
    /// Allocates at least `suggested` bytes, or 64 KiB when libuv has no
    /// opinion.
    pub fn new(suggested: usize) -> Option<Self> {
        let length = if suggested == 0 { 64 * 1024 } else { suggested };
        let layout = std::alloc::Layout::from_size_align(length, 8).ok()?;
        // SAFETY: `layout` has a non-zero size, which `alloc` requires.
        let pointer = unsafe { std::alloc::alloc(layout) };
        if pointer.is_null() {
            return None;
        }
        Some(Self { pointer, length })
    }

    /// The address libuv's `uv_buf_t.base` wants.
    pub fn base(&mut self) -> *mut u8 {
        self.pointer
    }

    /// The address without a mutable borrow, for a caller that only reads.
    pub fn base_const(&self) -> *const u8 {
        self.pointer
    }

    /// Rebuilds an [`Allocation`] from the pointer and length an allocator
    /// handed libuv.
    ///
    /// # Safety
    ///
    /// `pointer` must be a live allocation [`Allocation::new`] made with
    /// `length`, and it must not be owned anywhere else.
    pub unsafe fn from_raw(pointer: *mut u8, length: usize) -> Self {
        Self { pointer, length }
    }

    pub fn length(&self) -> usize {
        self.length
    }

    /// Hands the allocation to V8 as the backing store of a new `ArrayBuffer`.
    ///
    /// Consuming `self` is what transfers ownership: from here on V8 frees the
    /// memory with the buffer, and this type must not.
    pub fn into_array_buffer<'s>(
        self,
        scope: &mut v8::PinScope<'s, '_>,
    ) -> v8::Local<'s, v8::ArrayBuffer> {
        let memory = std::mem::ManuallyDrop::new(self);
        // SAFETY: `memory.pointer` came from `std::alloc::alloc` with this exact
        // length and alignment, and `ManuallyDrop` stops this type from freeing
        // it. `Box<[u8]>` is the only way to give
        // `new_backing_store_from_boxed_slice` memory it will not copy.
        let slice = unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                memory.pointer,
                memory.length,
            ))
        };
        let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(slice);
        let store: v8::SharedRef<v8::BackingStore> = store.into();
        v8::ArrayBuffer::with_backing_store(scope, &store)
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        if self.pointer.is_null() || self.length == 0 {
            return;
        }
        // SAFETY: `new` allocated this pointer with the layout below and
        // nothing else frees it (`into_array_buffer` forgets `self`).
        unsafe {
            std::alloc::dealloc(
                self.pointer,
                std::alloc::Layout::from_size_align_unchecked(self.length, 8),
            );
        }
    }
}

/// Delivers one read to `handle.onread` in the shape
/// `internal/stream_base_commons.js` expects.
///
/// This is the bottom of the listener chain: `StreamResource::EmitRead` when no
/// listener is attached, which in Node is `default_listener_`
/// (`EmitToJSStreamListener::OnStreamRead`, `stream_base.cc:731`).
///
/// `status` is libuv's `nread`: positive for bytes, `UV_EOF` at end of stream,
/// any other negative value for an error. The two values JS reads are published
/// to the shared `streamBaseState` first, because `onStreamRead` reads them
/// before it looks at its argument.
///
/// # Why this takes a raw pointer
///
/// `lib/net.js` can `destroy()` the socket from inside `onread`, and that runs
/// `close()` → `StreamState::state = Closing` on the same state. A `&mut` held
/// across the call would make that re-borrow undefined. So the two facts this
/// needs — the byte count and the rooted owner — are taken under a scoped
/// borrow that ends before `callback::with_context`, and the state is not
/// touched again afterwards.
///
/// # Why `onread` is read from the object, not stored on the state
///
/// `Node`'s `StreamResource::EmitRead` does `owner_object()->Get(onread)`, and
/// that matters: `lib/net.js` assigns `handle.onread` after the handle exists
/// (`Socket.prototype._handle.onread = onStreamRead`) and replaces it with
/// `noop` when the socket is paused, so the property is the only authoritative
/// value. A copy taken at construction time would go stale the first time a
/// socket was paused, and a copy taken at `readStart` would miss a later
/// assignment.
///
/// # Safety
///
/// `state` must be live, and the caller must hold no reference to it across this
/// call. The byte count is **not** incremented here: `StreamResource::EmitRead`
/// owns that (`stream_base-inl.h:75`), and [`crate::listener::emit_read`] is the
/// only caller of this function.
pub unsafe fn deliver_read(state: *mut StreamState, status: isize, allocation: Option<Allocation>) {
    if state.is_null() {
        return;
    }
    let Some((owner, context, frame)) = ({
        // SAFETY: the caller guarantees `state` is live. The borrow ends with
        // this block, before anything below can re-enter and mutate the state.
        let state = unsafe { &*state };
        state.owner_object.clone().map(|owner| {
            (
                owner,
                rn_core::callback_scope::AsyncContext {
                    async_id: state.async_wrap.async_id,
                    trigger_async_id: state.async_wrap.trigger_async_id,
                },
                state.context_frame.clone(),
            )
        })
    }) else {
        return;
    };
    let context_args = || rn_core::callback_scope::ScopeArgs {
        context,
        resource: Some(owner.clone()),
        frame: frame.clone(),
    };

    if status > 0 {
        let Some(allocation) = allocation else {
            return;
        };
        publish_read_count(status);
        callback::with_context(|scope| {
            // `CallJSOnreadMethod` ends in `wrap->MakeCallback(onread, ...)`
            // (`src/stream_base.cc:514`), so the callback runs inside an
            // `InternalCallbackScope` for the handle's async wrap. Without this
            // the read callback sees no async context, no frame — which is what
            // `AsyncLocalStorage` reports as `undefined` — and a throw from it
            // reaches nobody.
            let _ = rn_core::callback_scope::with_scope(scope, context_args(), |scope| {
                let object: v8::Local<v8::Object> = v8::Local::new(scope, &owner);
                let Some(handler) = onread_of(scope, object) else {
                    return;
                };
                let buffer = allocation.into_array_buffer(scope);
                let argument: v8::Local<v8::Value> = buffer.into();
                let receiver: v8::Local<v8::Value> = object.into();
                let _ = handler.call(&*scope, receiver, &[argument]);
            });
        });
        return;
    }

    if status == 0 {
        // Nothing happened. `onStreamRead` returns early for a zero count, so
        // calling through would only cost a scope.
        return;
    }

    publish_read_count(status);
    callback::with_context(|scope| {
        // The EOF/error arm of `CallJSOnreadMethod`, same scope as the data arm:
        // `onStreamRead` with no argument is what `lib/net.js` turns into
        // `'end'`/`'error'`, and a throw from an `'end'` handler is just as
        // uncaught as one from `'data'`.
        let _ = rn_core::callback_scope::with_scope(scope, context_args(), |scope| {
            let object: v8::Local<v8::Object> = v8::Local::new(scope, &owner);
            let Some(handler) = onread_of(scope, object) else {
                return;
            };
            let receiver: v8::Local<v8::Value> = object.into();
            let _ = handler.call(&*scope, receiver, &[]);
        });
    });
}

/// Publishes `(nread, offset)` into the shared `streamBaseState`.
///
/// `onStreamRead` reads both before it looks at its argument, so this has to
/// happen before the call and not during it. Doing nothing when `stream_wrap`
/// has not been installed yet is correct: nothing can be reading then.
fn publish_read_count(status: isize) {
    crate::stream::with_state(|state| {
        state.set(K_READ_BYTES_OR_ERROR, status as u32);
        state.set(K_ARRAY_BUFFER_OFFSET, 0);
    });
}

/// Reads the `onread` function off a stream handle object.
///
/// Returns `None` when the property is missing or not callable, which is the
/// state a handle is in before JavaScript attaches its listener.
fn onread_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, "onread")?;
    let value = object.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

/// Casts a typed handle pointer to the `uv_handle_t` libuv's generic calls want.
pub fn as_handle<T>(handle: *mut T) -> *mut uv::uv_handle_t {
    handle.cast()
}

/// Casts a typed handle pointer to the `uv_stream_t` libuv's stream calls want.
pub fn as_stream<T>(handle: *mut T) -> *mut uv::uv_stream_t {
    handle.cast()
}

/// Reads the owner pointer libuv carries for a stream.
///
/// # Safety
///
/// `stream` must be a live stream initialised by this crate.
pub unsafe fn owner(stream: *mut uv::uv_stream_t) -> Option<*mut StreamState> {
    if stream.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `stream` is live, and its `data` field holds
    // the `*mut StreamState` the constructor stored.
    let data = unsafe { (*stream).data };
    if data.is_null() {
        None
    } else {
        Some(data.cast::<StreamState>())
    }
}

/// Stores the owner pointer libuv carries for a stream.
///
/// # Safety
///
/// `stream` must be live and `state` must outlive the handle's close callback.
pub unsafe fn set_owner(stream: *mut uv::uv_stream_t, state: *mut StreamState) {
    if !stream.is_null() {
        // SAFETY: the caller guarantees `stream` is live.
        unsafe { (*stream).data = state.cast::<c_void>() };
    }
}
