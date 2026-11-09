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
    /// The object this state belongs to, rooted.
    ///
    /// Node keeps the reverse mapping (`handle[owner_symbol]`), which works
    /// because the JavaScript object outlives the handle. A native completion
    /// runs with no such mapping available, so the object is rooted here instead
    /// and released when the wrapper is finalised.
    pub owner_object: Option<v8::Global<v8::Object>>,
}

impl StreamState {
    /// A state for a freshly initialised handle.
    pub fn new(stream: *mut uv::uv_stream_t) -> Self {
        Self {
            stream,
            state: HandleState::Initialized,
            on_read: None,
            owner_object: None,
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
/// `status` is libuv's `nread`: positive for bytes, `UV_EOF` at end of stream,
/// any other negative value for an error. The two values JS reads are published
/// to the shared `streamBaseState` first, because `onStreamRead` reads them
/// before it looks at its argument.
pub fn deliver_read(
    state: &StreamState,
    stream_base_state: &rn_core::AliasedUint8Array,
    status: isize,
    allocation: Option<Allocation>,
) {
    let Some(on_read) = state.on_read.clone() else {
        return;
    };

    if status > 0 {
        let Some(allocation) = allocation else {
            return;
        };
        stream_base_state.set(K_READ_BYTES_OR_ERROR, status as u32);
        stream_base_state.set(K_ARRAY_BUFFER_OFFSET, 0);

        callback::with_context(|scope| {
            let buffer = allocation.into_array_buffer(scope);
            let argument: v8::Local<v8::Value> = buffer.into();
            let handler: v8::Local<v8::Function> = v8::Local::new(scope, &on_read);
            let receiver: v8::Local<v8::Value> = v8::undefined(&**scope).into();
            let _ = handler.call(&*scope, receiver, &[argument]);
        });
        return;
    }

    if status == 0 {
        // Nothing happened. `onStreamRead` returns early for a zero count, so
        // calling through would only cost a scope.
        return;
    }

    stream_base_state.set(K_READ_BYTES_OR_ERROR, status as u32);
    stream_base_state.set(K_ARRAY_BUFFER_OFFSET, 0);
    callback::call(&on_read, None, &[]);
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
