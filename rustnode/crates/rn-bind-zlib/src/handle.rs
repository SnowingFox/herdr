//! The V8 objects `lib/zlib.js` constructs and drives.
//!
//! Node's `MakeClass<Stream>` builds one constructor per stream kind, each with
//! the same `init`/`write`/`writeSync`/`params`/`reset`/`close` prototype
//! methods. This module reproduces that shape and keeps the native state behind
//! one internal field.
//!
//! # Handle lifetime
//!
//! `node_zlib.cc` makes the wrapper weak (`MakeWeak()`) and frees its
//! `ZlibContext` in the destructor; `close()` only ends the zlib/Brotli stream.
//! This crate does the same. The state is one heap allocation referenced by an
//! internal field, the JS object owns it, and a guaranteed finalizer releases it.
//! `close()` flips a flag and ends the compressor, so calls on a closed handle
//! behave like Node's no-ops instead of touching freed memory.
//!
//! # Asynchronous writes
//!
//! Node runs `write()` on the libuv threadpool and reports completion from
//! `AfterThreadPoolWork`. There is no threadpool here, so the whole step — the
//! compression *and* the completion — is deferred onto a microtask, which
//! preserves the two properties the native protocol relies on:
//!
//! 1. Between `write()` returning and its completion running, the zlib state
//!    has not advanced. Node's threadpool hop gives it exactly that window, and
//!    `lib/zlib.js` depends on it: `params()` is called through
//!    `paramsAfterFlushCallback` from the flush write's callback, at which point
//!    the stream that was already queued behind that flush (`d.end(...)`, a
//!    second chunk) may have had its own `write()` called but not yet run. If
//!    the step ran inline, `params()` would see a stream that had already
//!    consumed that queued input — `Z_FINISH` in the common case — and
//!    `deflateParams()` would fail with `Z_STREAM_ERROR`.
//! 2. `writeState` holds this step's offsets before `processCallback` runs, and
//!    the callback never runs inside `write()`, so `processCallback`'s "output
//!    buffer full, call `this.write()` again" path re-enters through the
//!    microtask queue instead of growing the native stack.
//!
//! # The oracle is nondeterministic on this exact ordering
//!
//! On the pinned Node 28 oracle the `params()`-inside-a-flush-callback ordering
//! does **not** produce a stable answer, so a single oracle run is not evidence
//! about what rustnode should do. Node reaches the state its own comment at
//! `lib/zlib.js:788-791` calls unsupported ("the call to the native `params()`
//! function should not happen while a write is currently in progress on the
//! threadpool"), and then `deflateParams()` runs on the main thread while a
//! `Z_FINISH` `deflate()` is still executing on a libuv worker thread against
//! the same `z_stream`. Depending on which side wins, the oracle prints `OK`,
//! reports `Z_STREAM_ERROR`, reports `Z_OK`/"buffer error", spins, or
//! **segfaults**. Measured on this nightly, idle, 100 runs: 77 `OK`, 12
//! `Z_STREAM_ERROR`, 6 segfault, 5 `Z_OK`. Loading the machine or shrinking
//! `UV_THREADPOOL_SIZE` moves it a long way — at `UV_THREADPOOL_SIZE=1` it was
//! 53/60 `Z_STREAM_ERROR` — which is the signature of a race and not of a
//! stream-state rule.
//!
//! rustnode takes the majority outcome (the step stays queued, `params()`
//! succeeds, the stream round-trips) **deliberately**. That is not a divergence
//! to fix: reproducing the crash would mean reproducing a data race. If you
//! diff a single oracle run against this crate and see `Z_STREAM_ERROR` or a
//! segfault, that is the oracle, not this code — re-run it, and see
//! `docs/compat-status.md` ("`params()` after a flush is racy on the oracle").

use std::cell::RefCell;
use std::ffi::c_void;

use rn_v8_sys::v8;

use crate::brotli::{BrotliError, BrotliStream};
use crate::constants::*;
use crate::memory::MemoryOwner;
use crate::zlib::{ZlibError, ZlibStream};
use crate::zstd::{ZstdCompressStream, ZstdDecompressStream, ZstdError, CONTENTSIZE_UNKNOWN};
use crate::AfterWrite;
use crate::ZlibMode;

/// Everything a handle can be: one of the zlib modes, Brotli, or zstd.
pub(crate) enum Backend {
    Zlib(Box<ZlibStream>),
    Brotli(Box<BrotliStream>),
    ZstdCompress(Box<ZstdCompressStream>),
    ZstdDecompress(Box<ZstdDecompressStream>),
}

/// A handle's native state, owned by the JS object through an internal field.
pub(crate) struct HandleState {
    backend: Backend,
    /// The wrapper's weak handle, parked here so it lives exactly as long as the
    /// state it finalizes.
    ///
    /// `Weak::drop` cancels the finalizer, so this must not be dropped while the
    /// object is still alive. Keeping it in the state makes the lifetimes
    /// coincide: the finalizer frees the state, which drops this, by which point
    /// the callback has already run and cancelling is a no-op. V8's own
    /// `Context` annex uses the same arrangement.
    weak: Option<v8::Weak<v8::Object>>,
    /// `writeState`: the `Uint32Array(2)` the JS passed to `init`.
    ///
    /// Held as a raw pointer exactly as `node_zlib.cc` holds
    /// `uint32_t* write_result_`. The array is reachable from the engine for the
    /// whole life of the handle.
    write_state: *mut u32,
    /// `writeCallback`, retained across the deferred completion.
    write_cb: Option<v8::Global<v8::Function>>,
    /// The handle object, retained while a completion is outstanding so the
    /// callback can be invoked with it as `this` (Node's `MakeCallback`).
    receiver: Option<v8::Global<v8::Object>>,
    /// The last step's error, reported through `onerror` instead of the write
    /// callback, like `EmitError()`.
    pending_error: Option<StreamError>,
    /// The step a queued async `write()` accepted but has not run yet.
    ///
    /// Node's async `write()` returns having only *scheduled* the compression
    /// on the libuv threadpool; the zlib stream does not move until
    /// `DoThreadPoolWork` runs. Inside that window `lib/zlib.js` calls
    /// `params()` — `paramsAfterFlushCallback` runs while the next write is
    /// already queued — and Node answers it against the stream state *before*
    /// that queued write. Reproducing the window is what makes `deflateParams`
    /// succeed through the async path.
    ///
    /// Node itself does not reliably succeed here, because "inside that
    /// window" is a race it loses on some runs: `params()` on the main thread
    /// can overlap the queued `deflate()` on a pool thread. Its comment at
    /// `lib/zlib.js:788-791` says that must not happen; it happens anyway.
    /// rustnode makes the window deterministic and therefore always takes the
    /// majority outcome. Read the "oracle is nondeterministic" note at the top
    /// of this module before treating one oracle run as the expected answer.
    pending_step: Option<DeferredStep>,
    /// `pending_close_`: a `close()` that arrived while a step was queued.
    ///
    /// Node's `CompressionStream::Close()` records the request and returns;
    /// `AfterThreadPoolWork` performs the close after the step and the write
    /// callback. Ending the zlib stream earlier would leave the queued step
    /// running against a finished stream.
    pending_close: bool,
    write_in_progress: bool,
    closed: bool,
    /// `AsyncWrap`'s id for this handle, `PROVIDER_ZLIB`.
    ///
    /// `CompressionStream(env, wrap) : AsyncWrap(env, wrap, PROVIDER_ZLIB)`
    /// (`src/node_zlib.cc:502-503`), so every zlib handle is an async resource
    /// from construction and its write completion emits `before`/`after` for it.
    /// `None` when `async_wrap` never installed, which is the bootstrap state.
    async_id: Option<f64>,
    /// The trigger id the `init` carried, so the completion pushes the same pair
    /// Node's `AsyncWrap::MakeCallback` would.
    trigger_async_id: Option<f64>,
    /// The compression library's allocations for this handle.
    ///
    /// `CompressionStreamMemoryOwner`'s `zlib_memory_`
    /// (`src/node_zlib.cc:487-488`): `Node / zlib_memory` reports it, and the
    /// node only exists once something has been allocated, which is why
    /// `test/pummel/test-heapdump-zlib.js` can assert its absence on a fresh
    /// stream.
    memory: Box<MemoryOwner>,
    /// This handle's registration in the embedder graph, released with its
    /// state.
    retainer: rn_core::heap_retainers::RetainerId,
    /// The wrapper, weakly.
    ///
    /// The snapshot's `native_to_javascript` edge names the JavaScript object,
    /// and a strong reference would keep it alive so `close()` plus a `GC()`
    /// never reclaimed it. `weak` above is this object's own finalizer handle and
    /// cannot be used for this: it is dropped by the finalizer that frees this
    /// state, so describing a wrapper from it would be describing the object
    /// whose death cancelled it.
    wrapper: v8::Weak<v8::Object>,
}

/// A compression step that `write()` accepted but has not run yet.
struct DeferredStep {
    flush: i32,
    /// A copy of the input bytes: `lib/zlib.js` may reuse or drop its buffer
    /// once `write()` returns, but the deferred step must see the bytes the
    /// call was made with.
    input: Vec<u8>,
    /// `(pointer, length)` into the caller's output `Buffer`, exactly as
    /// `node_zlib.cc` keeps `next_out_` across the threadpool hop.
    output: (*mut u8, usize),
    /// The output view, pinned so V8 cannot collect its backing store while
    /// the step is queued.
    output_keepalive: Option<v8::Global<v8::Value>>,
}

impl HandleState {
    fn new(backend: Backend, wrapper: v8::Weak<v8::Object>) -> Self {
        Self {
            backend,
            weak: None,
            write_state: std::ptr::null_mut(),
            write_cb: None,
            receiver: None,
            pending_error: None,
            pending_step: None,
            pending_close: false,
            write_in_progress: false,
            closed: false,
            async_id: None,
            trigger_async_id: None,
            memory: MemoryOwner::new(),
            retainer: rn_core::heap_retainers::RetainerId::none(),
            wrapper,
        }
    }

    /// Publishes `[availOutAfter, availInAfter]` where `lib/zlib.js` reads them.
    ///
    /// `node_zlib.cc` fills them with
    /// `GetAfterWriteOffsets(&write_result_[1], &write_result_[0])`, and the JS
    /// reads `state[0]` as `availOutAfter` and `state[1]` as `availInAfter`.
    fn store_after_write(&self, after: AfterWrite) {
        if self.write_state.is_null() {
            return;
        }
        // SAFETY: `write_state` came from `Uint32Array::data()` on the live
        // `writeState` array, whose length was checked in `init`. V8 backing
        // stores do not move while their typed array is reachable, and the JS
        // keeps this one in `engine._writeState` until the engine is collected.
        unsafe {
            *self.write_state = after.avail_out;
            *self.write_state.add(1) = after.avail_in;
        }
    }

    /// Records the output buffer a queued async write was given.
    ///
    /// `node_zlib.cc` calls `SetBuffers()` inside `Write()` before the step is
    /// scheduled, so `strm_.next_out`/`avail_out` already point at this write's
    /// buffer while `params()` may still run. Replaying that here keeps
    /// `deflateParams`' block flush writing where Node writes it.
    fn set_pending_output(&mut self, output: (*mut u8, usize)) {
        match &mut self.backend {
            Backend::Zlib(stream) => stream.set_out_cursor(output),
            // Brotli has no `params()` and zstd's is a no-op, so neither reads
            // this cursor.
            Backend::Brotli(_) | Backend::ZstdCompress(_) | Backend::ZstdDecompress(_) => {}
        }
    }

    fn error(&self) -> Option<StreamError> {
        match &self.backend {
            Backend::Zlib(stream) => stream.error_info().map(StreamError::Zlib),
            Backend::Brotli(stream) => stream.error_info().map(StreamError::Brotli),
            Backend::ZstdCompress(stream) => stream.error_info().cloned().map(StreamError::Zstd),
            Backend::ZstdDecompress(stream) => stream.error_info().cloned().map(StreamError::Zstd),
        }
    }

    fn step(&mut self, flush: i32, input: &[u8], output: &mut [u8]) -> AfterWrite {
        match &mut self.backend {
            Backend::Zlib(stream) => stream.write(flush, input, output),
            Backend::Brotli(stream) => stream.write(flush, input, output),
            Backend::ZstdCompress(stream) => stream.write(flush, input, output),
            Backend::ZstdDecompress(stream) => {
                let after = stream.write(flush, input, output);
                // `ZstdDecompressContext::GetErrorInfo` runs after the step and
                // is where a truncated frame turns into `Z_BUF_ERROR`; the
                // compressor has no equivalent check.
                stream.check_truncated(after.avail_in, after.avail_out);
                after
            }
        }
    }

    fn set_params(&mut self, level: i32, strategy: i32) -> Option<StreamError> {
        match &mut self.backend {
            Backend::Zlib(stream) => stream.set_params(level, strategy).map(StreamError::Zlib),
            // `BrotliCompressionStream::Params()` is a documented no-op.
            Backend::Brotli(_) => None,
            // `ZstdStream::Params()` is likewise a documented no-op: zstd
            // parameters are set at init and cannot be changed mid-stream.
            Backend::ZstdCompress(_) | Backend::ZstdDecompress(_) => None,
        }
    }

    fn reset(&mut self) -> Option<StreamError> {
        match &mut self.backend {
            Backend::Zlib(stream) => stream.reset().map(StreamError::Zlib),
            Backend::Brotli(stream) => stream.reset().map(StreamError::Brotli),
            Backend::ZstdCompress(stream) => stream.reset().map(StreamError::Zstd),
            Backend::ZstdDecompress(stream) => stream.reset().map(StreamError::Zstd),
        }
    }

    /// The backend this handle runs, for the heap snapshot's class names.
    pub(crate) fn backend(&self) -> &Backend {
        &self.backend
    }

    /// The compression library's live allocation total.
    ///
    /// zlib and Brotli report through [`MemoryOwner`], whose `zalloc`/`zfree`
    /// they actually call. zstd allocates its workspace from its own C library
    /// with no hook this build installs, so its total comes from the context
    /// itself (`ZSTD_sizeof_CCtx`/`DCtx`), which is the same live allocation
    /// question answered by the library that made it.
    pub(crate) fn memory_bytes(&self) -> usize {
        if let Backend::ZstdCompress(stream) = &self.backend {
            return stream.allocated_bytes();
        }
        if let Backend::ZstdDecompress(stream) = &self.backend {
            return stream.allocated_bytes();
        }
        self.memory.bytes()
    }

    /// `CompressionStream::Close()`: ends the compressor state, leaves the
    /// wrapper alive so a late callback cannot use freed memory.
    ///
    /// A queued step keeps the stream alive: `node_zlib.cc`'s `Close()` records
    /// `pending_close_` and returns while `write_in_progress_` is set, and
    /// `AfterThreadPoolWork` closes once the step and its callback are done.
    /// Closing here instead would leave the queued step compressing into a
    /// finished stream, which is how a flush write followed by `close()` used to
    /// produce a spurious `Z_STREAM_ERROR`.
    fn close(&mut self) {
        if self.write_in_progress {
            self.pending_close = true;
            return;
        }
        self.close_now();
    }

    /// The part of `close()` that actually ends the stream.
    fn close_now(&mut self) {
        self.closed = true;
        self.pending_close = false;
        match &mut self.backend {
            Backend::Zlib(stream) => stream.close(),
            Backend::Brotli(stream) => stream.close(),
            Backend::ZstdCompress(stream) => stream.close(),
            Backend::ZstdDecompress(stream) => stream.close(),
        }
        self.pending_error = None;
        self.pending_step = None;
        // `write_cb` and `receiver` are *not* cleared here. Node's
        // `AfterThreadPoolWork` still calls the write callback after a close, and
        // `processCallback` handles it by checking `self.destroyed`. Clearing them
        // would silently drop that callback; `receiver` additionally keeps this
        // object, and therefore this state, alive until the queued completion has
        // run.
        self.write_in_progress = false;
    }
}

/// Either backend's error, so `onerror(message, errno, code)` has one shape.
pub(crate) enum StreamError {
    Zlib(ZlibError),
    Brotli(BrotliError),
    Zstd(ZstdError),
}

impl StreamError {
    fn parts(&self) -> (&str, i32, &str) {
        match self {
            Self::Zlib(error) => (&error.message, error.err, error.code),
            Self::Brotli(error) => (&error.message, error.err, &error.code),
            Self::Zstd(error) => (&error.message, error.err, &error.code),
        }
    }

    fn closed() -> Self {
        Self::Zlib(ZlibError {
            message: "zlib binding closed".to_string(),
            code: "Z_STREAM_ERROR",
            err: Z_STREAM_ERROR,
        })
    }
}

/// Internal field index holding the `Box<RefCell<HandleState>>`.
const STATE_FIELD: i32 = 0;

/// Borrows the state installed by the constructor.
fn with_state<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut HandleState) -> R,
) -> Option<R> {
    // SAFETY: the field only ever holds a pointer produced by `install_state`.
    // The allocation is released by the object's own finalizer, which cannot run
    // while `object` is a live local.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut RefCell<HandleState>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above. `RefCell` rejects overlapping borrows, and every borrow
    // here is scoped to one callback.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

/// Allocates the state and installs it plus its finalizer.
fn install_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    backend: Backend,
) {
    // The wrapper, weakly: the snapshot's `native_to_javascript` edge names it,
    // and a strong reference would keep the handle alive past `close()`.
    let wrapper = v8::Weak::new(scope, object);
    let mut state = HandleState::new(backend, wrapper);
    // The allocator the compressor will call is this state's counter, so it has
    // to be installed before the first `deflateInit2_` and after the state is in
    // its final location. `MemoryOwner` is a `Box`, so `memory::install` can
    // store a pointer to it that stays valid for the handle's life.
    if let Backend::Zlib(stream) = &mut state.backend {
        crate::memory::install(stream.stream_mut(), &state.memory);
    }
    let pointer = Box::into_raw(Box::new(RefCell::new(state)));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    crate::note_handle_allocated();

    // `AsyncWrap(env, wrap, PROVIDER_ZLIB)`: the handle is an async resource
    // from construction, so `init` fires here and the ids are kept for the
    // `MakeCallback` its write completion performs. Emitting before the ids are
    // stored is deliberate — a hook that inspects the handle must find it
    // installed, which `install_state` has already done.
    let ids = rn_bind_async_wrap::emit_init_for_new_resource(
        scope,
        object,
        rn_core::async_wrap::PROVIDER_ZLIB,
    );
    if let Some((async_id, trigger_async_id)) = ids {
        // SAFETY: `pointer` was just created above and is not otherwise
        // borrowed yet.
        let cell = unsafe { &*pointer };
        if let Ok(mut state) = cell.try_borrow_mut() {
            state.async_id = Some(async_id);
            state.trigger_async_id = Some(trigger_async_id);
        }
    }

    // The heap-snapshot walk reaches this handle through the registration rather
    // than a `BaseObject` tree. It resolves the weak wrapper inside the walk's
    // own scope and reports nothing once the object is gone, so a finalizer that
    // has not run yet cannot make the snapshot claim a dead handle.
    //
    // SAFETY: `pointer` came from `Box::into_raw` just above and is not freed
    // until the finalizer below runs, which cannot happen while the isolate is
    // running this callback.
    let address = pointer as usize;
    let retainer = rn_core::heap_retainers::register(move |graph, scope| {
        // SAFETY: the finalizer clears the registration before it frees the
        // state, so a registration that still exists names a live allocation.
        let cell = unsafe { &*(address as *const RefCell<HandleState>) };
        let Ok(state) = cell.try_borrow() else {
            // A snapshot taken from inside this handle's own callback would find
            // the state borrowed. Reporting nothing is the honest answer.
            return;
        };
        let wrapper = state
            .wrapper
            .to_local(scope)
            .map(v8::Local::<v8::Value>::from);
        if let Some(node) = crate::retainers::describe(&state, wrapper) {
            rn_core::heap_retainers::add_node(graph, &node);
        }
    });
    // SAFETY: `pointer` was just created above and is not otherwise borrowed.
    let cell = unsafe { &*pointer };
    if let Ok(mut state) = cell.try_borrow_mut() {
        state.retainer = retainer;
    }

    // The finalizer owns the allocation from here on, so it is released even if
    // `close()` never runs.
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // The registration outlives the state it describes unless it is
            // dropped first, and a stale one would report freed memory.
            // SAFETY: the finalizer runs exactly once for this allocation.
            let cell = unsafe { &*(address as *const RefCell<HandleState>) };
            if let Ok(state) = cell.try_borrow() {
                rn_core::heap_retainers::unregister(state.retainer);
            }
            let pointer = address as *mut RefCell<HandleState>;
            // SAFETY: `install_state` allocated this Box and nothing else frees
            // it; the finalizer runs exactly once.
            drop(unsafe { Box::from_raw(pointer) });
            crate::note_handle_released();
        }),
    );

    // The `Weak` has to outlive the registration: dropping it would cancel the
    // finalizer. Parking it in the state it finalizes means it lives exactly as
    // long as the object, and dropping it from inside the finalizer is a no-op.
    //
    // SAFETY: `pointer` was just created by `Box::into_raw` above and is not
    // otherwise aliased yet.
    let cell = unsafe { &*pointer };
    if let Ok(mut state) = cell.try_borrow_mut() {
        state.weak = Some(weak);
    }
}

fn throw(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let text = v8::String::new(scope, message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

fn arg_u32(scope: &v8::PinScope<'_, '_>, args: &v8::FunctionCallbackArguments, index: i32) -> u32 {
    args.get(index).uint32_value(scope).unwrap_or(0)
}

fn arg_i32(scope: &v8::PinScope<'_, '_>, args: &v8::FunctionCallbackArguments, index: i32) -> i32 {
    args.get(index).int32_value(scope).unwrap_or(0)
}

/// A `Buffer`/`TypedArray` argument as `(pointer, length)`, with `offset` and
/// `length` checked against the view the way `Buffer::IsWithinBounds` does.
fn view_range(value: v8::Local<v8::Value>, offset: u32, length: u32) -> Option<(*mut u8, usize)> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let total = view.byte_length();
    let offset = offset as usize;
    let length = length as usize;
    if offset.checked_add(length)? > total {
        return None;
    }
    // A zero-length view has a null backing-store pointer; `lib/zlib.js` passes
    // one for the "just a flush" case, and Node's `Buffer::Data` returns null
    // for that as well without it being an error.
    let data = view.data().cast::<u8>();
    if data.is_null() {
        if length == 0 {
            return Some((std::ptr::NonNull::<u8>::dangling().as_ptr(), 0));
        }
        return None;
    }
    // SAFETY: the bounds check proves `offset..offset + length` lies inside the
    // view's live backing store.
    Some((unsafe { data.add(offset) }, length))
}

/// Copies the input side of a `write` call out of JavaScript memory.
fn input_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Result<Vec<u8>, ()> {
    let value = args.get(1);
    if value.is_null() || value.is_undefined() {
        // "just a flush": Node accepts a null input buffer.
        return Ok(Vec::new());
    }
    let offset = arg_u32(scope, args, 2);
    let length = arg_u32(scope, args, 3);
    let Some((pointer, length)) = view_range(value, offset, length) else {
        throw(scope, "input buffer is out of bounds");
        return Err(());
    };
    // SAFETY: `view_range` validated the range against the live backing store.
    // The bytes are copied before any JavaScript can run again.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
}

/// The output side of a `write` call: `(pointer, length)` into the caller's
/// `Buffer`.
///
/// Returned as raw parts rather than a slice because the borrow has to be scoped
/// to the compression step; `run_step` builds the slice and drops it before
/// returning to JavaScript.
fn output_range<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Result<(*mut u8, usize), ()> {
    let offset = arg_u32(scope, args, 5);
    let length = arg_u32(scope, args, 6);
    let Some(range) = view_range(args.get(4), offset, length) else {
        throw(scope, "output buffer is out of bounds");
        return Err(());
    };
    Ok(range)
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

fn zlib_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        throw(scope, "zlib handle constructor requires 'new'");
        return;
    }
    let mode = arg_i32(scope, &args, 0);
    let Some(mode) = ZlibMode::from_i32(mode) else {
        throw(scope, &format!("invalid zlib mode {mode}"));
        return;
    };
    install_state(
        scope,
        args.this(),
        Backend::Zlib(Box::new(ZlibStream::new(mode))),
    );
}

fn brotli_encoder_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        throw(scope, "zlib handle constructor requires 'new'");
        return;
    }
    install_state(
        scope,
        args.this(),
        Backend::Brotli(Box::new(BrotliStream::encoder(&[]))),
    );
}

fn brotli_decoder_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        throw(scope, "zlib handle constructor requires 'new'");
        return;
    }
    install_state(
        scope,
        args.this(),
        Backend::Brotli(Box::new(BrotliStream::decoder(&[]))),
    );
}

/// `new binding.ZstdCompress()`.
///
/// The context is created here rather than in `init` because the handle has to
/// exist before JavaScript can call `init`, and Node's `ZstdStream::New` does
/// the same. `init` installs the parameters and the dictionary, and may replace
/// the context when it starts over.
fn zstd_compress_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        throw(scope, "zlib handle constructor requires 'new'");
        return;
    }
    install_state(
        scope,
        args.this(),
        Backend::ZstdCompress(Box::new(ZstdCompressStream::uninitialized())),
    );
}

/// `new binding.ZstdDecompress()`; see [`zstd_compress_constructor`].
fn zstd_decompress_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        throw(scope, "zlib handle constructor requires 'new'");
        return;
    }
    install_state(
        scope,
        args.this(),
        Backend::ZstdDecompress(Box::new(ZstdDecompressStream::uninitialized())),
    );
}

// ---------------------------------------------------------------------------
// Prototype methods
// ---------------------------------------------------------------------------

/// `init(...)`, whose argument layout depends on the constructor:
///
/// * `Zlib`: `(windowBits, level, memLevel, strategy, writeState, writeCallback,
///   dictionary[, rejectGarbageAfterEnd])`
/// * `Brotli*`: `(params, writeState, writeCallback[, dictionary])`
/// * `Zstd*`: `(params, pledgedSrcSize, writeState, writeCallback[,
///   dictionary[, rejectGarbageAfterEnd]])`
fn init<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();

    let outcome = with_state(object, |state| {
        let callback_index = match &mut state.backend {
            Backend::Zlib(stream) => init_zlib(scope, &args, stream)
                .map(|()| 5)
                .map_err(InitError::Plain),
            Backend::Brotli(stream) => init_brotli(scope, &args, stream)
                .map(|()| 2)
                .map_err(InitError::Plain),
            Backend::ZstdCompress(stream) => init_zstd_compress(scope, &args, stream).map(|()| 3),
            Backend::ZstdDecompress(stream) => {
                init_zstd_decompress(scope, &args, stream).map(|()| 3)
            }
        }?;

        let write_state =
            arg_write_state(scope, &args, callback_index - 1).map_err(InitError::Plain)?;

        let Some(callback) = v8::Local::<v8::Function>::try_from(args.get(callback_index)).ok()
        else {
            return Err(InitError::Plain(
                "init() requires a write callback".to_string(),
            ));
        };

        state.write_state = write_state;
        state.write_cb = Some(v8::Global::new(scope, callback));
        state.pending_error = None;
        state.write_in_progress = false;
        // Re-initializing a closed handle is allowed, as it is in Node, where
        // `init` always runs on a fresh wrapper.
        state.closed = false;
        Ok(())
    });

    match outcome {
        None => throw(scope, "zlib binding closed"),
        Some(Err(InitError::Plain(message))) => throw(scope, &message),
        Some(Err(InitError::InitializationFailed(message))) => throw_with_code(
            scope,
            ErrorKind::Error,
            "ERR_ZLIB_INITIALIZATION_FAILED",
            &message,
        ),
        // The throwing path already replaced `init()`'s own message with the
        // more specific `ERR_INVALID_ARG_TYPE`/`ERR_OUT_OF_RANGE` exception.
        Some(Err(InitError::AlreadyThrown)) => {}
        Some(Ok(())) => {}
    }
}

/// A failed `init()`, in the shapes Node's `Init` implementations produce.
enum InitError {
    /// A plain `Error` with no `code`, which is what the zlib and Brotli paths
    /// have always thrown here.
    Plain(String),
    /// `ERR_ZLIB_INITIALIZATION_FAILED`, which `ZstdStream::Init` throws with
    /// the underlying message once `ZSTD_*_setParameter` or the dictionary load
    /// failed. `test-zlib-zstd.js` matches on this `code` and on the exact
    /// "Setting parameter failed" text.
    InitializationFailed(String),
    /// An exception is already pending on the isolate: the argument validators
    /// throw the specific `ERR_INVALID_ARG_TYPE`/`ERR_OUT_OF_RANGE` themselves
    /// and must not have it replaced by a generic message.
    AlreadyThrown,
}

fn init_zlib<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    stream: &mut ZlibStream,
) -> Result<(), String> {
    let window_bits = arg_u32(scope, args, 0) as i32;
    let level = arg_i32(scope, args, 1);
    let mem_level = arg_u32(scope, args, 2) as i32;
    let strategy = arg_u32(scope, args, 3) as i32;
    let dictionary = dictionary_bytes(args.get(6));
    let reject_garbage_after_end = args.length() >= 8 && args.get(7).is_true();

    stream
        .init(
            level,
            window_bits,
            mem_level,
            strategy,
            &dictionary,
            reject_garbage_after_end,
        )
        .map_err(|error| error.message)
}

/// `init` for `ZstdCompress`, whose layout is
/// `(params, pledgedSrcSize, writeState, writeCallback[, dictionary[,
/// rejectGarbageAfterEnd]])`.
fn init_zstd_compress<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    stream: &mut ZstdCompressStream,
) -> Result<(), InitError> {
    let params = zstd_params(scope, args.get(0))?;
    let pledged = pledged_src_size(scope, args.get(1))?;
    let dictionary = dictionary_bytes(args.get(4));
    // zstd compression accepts the flag for signature parity and ignores it,
    // exactly as `ZstdCompressContext::Init` ignores its third parameter.
    stream
        .init(pledged, &dictionary, &params)
        .map_err(|error| InitError::InitializationFailed(error.message))
}

/// `init` for `ZstdDecompress`, with the same layout as the compressor but a
/// `ZSTD_d_*` parameter namespace.
fn init_zstd_decompress<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    stream: &mut ZstdDecompressStream,
) -> Result<(), InitError> {
    let params = zstd_params(scope, args.get(0))?;
    let pledged = pledged_src_size(scope, args.get(1))?;
    let dictionary = dictionary_bytes(args.get(4));
    let reject_garbage_after_end = args.length() >= 6 && args.get(5).is_true();
    stream
        .init(pledged, &dictionary, &params, reject_garbage_after_end)
        .map_err(|error| InitError::InitializationFailed(error.message))
}

/// The parameter array as `(key, value)` pairs, widened to the `int` zstd takes.
///
/// `lib/zlib.js` sizes the array to the largest `ZSTD_c_`/`ZSTD_d_` constant it
/// knows and prefills it with `-1`, which [`params_array`] already filters, so
/// the keys that reach here are the ones the caller named. Node does not
/// range-check them either: an out-of-band key is rejected by
/// `ZSTD_*_setParameter`, which is what makes `{ [ZSTD_c_strategy]: 130 }`
/// throw "Setting parameter failed" instead of a range error.
fn zstd_params(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Result<Vec<(i32, i32)>, InitError> {
    Ok(params_array(scope, value)
        // `lib/zlib.js` always passes a `Uint32Array`; a caller that reaches
        // the handle directly has no separate error shape here.
        .map_err(InitError::Plain)?
        .into_iter()
        .map(|(key, value)| (key, value as i32))
        .collect())
}

/// `pledgedSrcSize`, which `ZstdStream::Init` accepts only as a safe
/// non-negative integer and otherwise reports as a `TypeError` or `RangeError`.
fn pledged_src_size(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Result<u64, InitError> {
    if value.is_undefined() {
        return Ok(CONTENTSIZE_UNKNOWN);
    }
    if !value.is_number() {
        throw_with_code(
            scope,
            ErrorKind::TypeError,
            "ERR_INVALID_ARG_TYPE",
            "The \"pledgedSrcSize\" argument must be of type number",
        );
        return Err(InitError::AlreadyThrown);
    }
    let number = value.number_value(scope).unwrap_or(f64::NAN);
    if !number.is_finite() || number.trunc() != number || number.abs() > MAX_SAFE_INTEGER {
        throw_with_code(
            scope,
            ErrorKind::RangeError,
            "ERR_OUT_OF_RANGE",
            "The value of \"pledgedSrcSize\" is out of range. It must be a safe integer",
        );
        return Err(InitError::AlreadyThrown);
    }
    if number < 0.0 {
        throw_with_code(
            scope,
            ErrorKind::RangeError,
            "ERR_OUT_OF_RANGE",
            "The value of \"pledgedSrcSize\" is out of range. It must be non-negative",
        );
        return Err(InitError::AlreadyThrown);
    }
    Ok(number as u64)
}

/// `2^53 - 1`, `kMaxSafeJsInteger` in `src/util-inl.h`.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Which JavaScript error constructor `throw_with_code` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    /// `THROW_ERR_*` macros whose entry in `node_errors.h` says `Error`, such as
    /// `ERR_ZLIB_INITIALIZATION_FAILED`.
    Error,
    /// `THROW_ERR_INVALID_ARG_TYPE`.
    TypeError,
    /// `THROW_ERR_OUT_OF_RANGE`.
    RangeError,
}

/// Throws a JavaScript error carrying `code`, which is how Node's
/// `THROW_ERR_*` macros surface in `lib/zlib.js`.
fn throw_with_code(scope: &mut v8::PinScope<'_, '_>, kind: ErrorKind, code: &str, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = match kind {
        ErrorKind::Error => v8::Exception::error(scope, text),
        ErrorKind::TypeError => v8::Exception::type_error(scope, text),
        ErrorKind::RangeError => v8::Exception::range_error(scope, text),
    };
    if let (Ok(object), Some(code)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, code),
    ) {
        if let Some(key) = v8::String::new(scope, "code") {
            let _ = object.set(scope, key.into(), code.into());
        }
    }
    scope.throw_exception(exception);
}

fn init_brotli<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    stream: &mut BrotliStream,
) -> Result<(), String> {
    let params = params_array(scope, args.get(0))?;
    let dictionary = dictionary_bytes(args.get(3));

    if !dictionary.is_empty() {
        match stream {
            BrotliStream::Encode(encoder) => encoder.set_dictionary(&dictionary),
            BrotliStream::Decode(_) => *stream = BrotliStream::decoder(&dictionary),
        }
    }

    if let BrotliStream::Encode(encoder) = stream {
        for (key, value) in params {
            if let Some(error) = encoder.set_params(key, value) {
                return Err(error.code);
            }
        }
    }
    Ok(())
}

/// The `Uint32Array(2)` the handle writes its offsets into.
fn arg_write_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    index: i32,
) -> Result<*mut u32, String> {
    let view = v8::Local::<v8::Uint32Array>::try_from(args.get(index))
        .map_err(|_| "writeState must be a Uint32Array".to_string())?;
    if view.byte_length() < 8 {
        let message = "writeState must hold at least two entries";
        throw(scope, message);
        return Err(message.to_string());
    }
    Ok(view.data().cast::<u32>())
}

/// The `Uint32Array` of parameters `lib/zlib.js` builds, where `-1` means unset.
fn params_array(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Result<Vec<(i32, u32)>, String> {
    let _ = scope;
    let view = v8::Local::<v8::Uint32Array>::try_from(value)
        .map_err(|_| "params must be a Uint32Array".to_string())?;
    let data = view.data().cast::<u32>();
    let length = view.byte_length() / 4;
    if data.is_null() || length == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: `data` covers `length` `u32`s of the live typed array, which the
    // argument keeps reachable for the whole call.
    let entries = unsafe { std::slice::from_raw_parts(data, length) };
    let mut params = Vec::new();
    for (index, value) in entries.iter().enumerate() {
        if *value == u32::MAX {
            continue;
        }
        params.push((index as i32, *value));
    }
    Ok(params)
}

fn dictionary_bytes(value: v8::Local<v8::Value>) -> Vec<u8> {
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) else {
        return Vec::new();
    };
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() || length == 0 {
        return Vec::new();
    }
    // SAFETY: the view's backing store holds `byte_length()` bytes at `data()`.
    unsafe { std::slice::from_raw_parts(data, length) }.to_vec()
}

/// The shared body of `write`/`writeSync`.
///
/// `writeSync` runs the step inline, as `node_zlib.cc`'s `Write<false>` does.
/// `write` only *accepts* the step and queues it: Node schedules it on the libuv
/// threadpool and runs `DoThreadPoolWork` later, and that delay is load-bearing
/// — `lib/zlib.js` calls `params()` from a write callback while the next write
/// is already queued, so the parameter change has to reach a stream the queued
/// step has not touched yet.
fn run_step<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    object: v8::Local<'s, v8::Object>,
    asynchronous: bool,
) {
    let flush = arg_i32(scope, args, 0);
    let Ok(input) = input_bytes(scope, args) else {
        return;
    };
    let output_value = args.get(4);
    let Ok((output_pointer, output_length)) = output_range(scope, args) else {
        return;
    };

    let outcome = if asynchronous {
        with_state(object, |state| {
            if state.closed {
                return Err(StreamError::closed());
            }
            if state.write_in_progress {
                // Node `CHECK`s this rather than reporting it, so a caller that
                // reaches it is already outside the supported protocol. Throw
                // instead of aborting the process.
                return Err(StreamError::Zlib(ZlibError {
                    message: "write in progress".to_string(),
                    code: "Z_STREAM_ERROR",
                    err: Z_STREAM_ERROR,
                }));
            }
            // `node_zlib.cc` calls `SetBuffers()` before scheduling, so the
            // cursor `params()` may use is already the queued write's.
            state.set_pending_output((output_pointer, output_length));
            state.pending_step = Some(DeferredStep {
                flush,
                input,
                output: (output_pointer, output_length),
                output_keepalive: Some(v8::Global::new(scope, output_value)),
            });
            state.write_in_progress = true;
            // The queued completion reaches the state through a raw pointer, so
            // pin the wrapper until that microtask has run. `complete_write`
            // releases it, which is what keeps this from being a cycle.
            state.receiver = Some(v8::Global::new(scope, object));
            Ok(())
        })
    } else {
        // SAFETY: `output_range` validated `output` against the caller's live
        // backing store. The slice is created here and dropped at the end of
        // this function, and `state.step` cannot run JavaScript, so nothing can
        // alias it.
        let output = unsafe { std::slice::from_raw_parts_mut(output_pointer, output_length) };
        with_state(object, |state| {
            if state.closed {
                return Err(StreamError::closed());
            }
            if state.write_in_progress {
                return Err(StreamError::Zlib(ZlibError {
                    message: "write in progress".to_string(),
                    code: "Z_STREAM_ERROR",
                    err: Z_STREAM_ERROR,
                }));
            }
            let after = state.step(flush, &input, output);
            match state.error() {
                // `writeSync` reports failures through `onerror`, which is
                // where `processChunkSync` picks them up; `writeState` stays
                // untouched.
                Some(error) => Err(error),
                None => {
                    state.store_after_write(after);
                    Ok(())
                }
            }
        })
    };

    match outcome {
        None => throw(scope, "zlib binding closed"),
        Some(Err(error)) => emit_error(scope, object, error),
        Some(Ok(())) => {
            if asynchronous && !schedule_completion(scope, object) {
                throw(scope, "cannot schedule zlib write completion");
            }
        }
    }
}

fn write_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();
    run_step(scope, &args, object, false);
}

fn write<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();
    run_step(scope, &args, object, true);
}

/// Queues the `processCallback` equivalent for the write that just ran.
fn schedule_completion<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> bool {
    // SAFETY: as in `with_state`; the pointer stays valid because the state is
    // owned by the object, which `HandleState::receiver` keeps alive until the
    // completion has run.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) };
    if pointer.is_null() {
        return false;
    }
    let external = v8::External::new(scope, pointer.cast_mut());
    let Some(resume) = v8::Function::builder(complete_write)
        .data(external.into())
        .build(scope)
    else {
        return false;
    };
    scope.enqueue_microtask(resume);
    true
}

/// The deferred half of `write()`: `DoThreadPoolWork` plus `AfterThreadPoolWork`
/// and the callback invocation from `processCallback`.
fn complete_write<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let Ok(external) = v8::Local::<v8::External>::try_from(args.data()) else {
        return;
    };
    let pointer = external.value().cast::<RefCell<HandleState>>();
    if pointer.is_null() {
        return;
    }
    // SAFETY: the pointer came from the live handle's internal field, and the
    // `receiver` global held by the state keeps that object alive until this
    // callback has run.
    let cell = unsafe { &*pointer };
    let Ok(mut state) = cell.try_borrow_mut() else {
        return;
    };

    // The step `write()` deferred. `close()` on a queued write leaves the stream
    // open (`pending_close_`), so the state is still usable here; only
    // `close_now` clears `pending_step`, and it cannot run while
    // `write_in_progress` is set.
    if let Some(step) = state.pending_step.take() {
        // SAFETY: `run_step` validated this range against the caller's live
        // backing store and `output_keepalive` kept that view reachable, so the
        // bytes are still the caller's output buffer.
        let output = unsafe { std::slice::from_raw_parts_mut(step.output.0, step.output.1) };
        let after = state.step(step.flush, &step.input, output);
        // The keepalive is dropped here, before any JavaScript runs again.
        drop(step.output_keepalive);
        if let Some(error) = state.error() {
            state.pending_error = Some(error);
        } else {
            state.store_after_write(after);
        }
    }

    state.write_in_progress = false;

    // `CompressionStream::AfterThreadPoolWork` reports the step's error before
    // it finishes a close that arrived while the step was queued.
    if let Some(error) = state.pending_error.take() {
        let receiver = state
            .receiver
            .as_ref()
            .map(|handle| v8::Local::new(scope, handle));
        state.receiver = None;
        drop(state);
        if let Some(object) = receiver {
            emit_error(scope, object, error);
        }
        // `EmitError()` ends with the same `pending_close_` handling as
        // `AfterThreadPoolWork`. `close_now` is idempotent, and in practice the
        // JS `onerror` has already destroyed the engine, which closed the handle
        // through `_destroy`.
        if let Ok(mut state) = cell.try_borrow_mut() {
            if state.pending_close {
                state.close_now();
            }
        }
        return;
    }

    if state.pending_close {
        state.close_now();
    }

    let callback = state
        .write_cb
        .as_ref()
        .map(|handle| v8::Local::new(scope, handle));
    let receiver = state
        .receiver
        .as_ref()
        .map(|handle| v8::Local::new(scope, handle));
    // `CompressionStream::AfterThreadPoolWork` ends with
    // `MakeCallback(writeCallback, 0, nullptr)`, so the handle's own id is the
    // one executing during the callback. Without it the handle's `init` has no
    // `before`, which `test/async-hooks/init-hooks.js` reports.
    let context = state
        .async_id
        .zip(state.trigger_async_id)
        .map(
            |(async_id, trigger_async_id)| rn_core::callback_scope::AsyncContext {
                async_id,
                trigger_async_id,
            },
        );
    // The completion is the last thing that needed the wrapper pinned; release
    // it after taking the locals so this object can be collected next GC.
    state.receiver = None;
    drop(state);

    if let (Some(callback), Some(object)) = (callback, receiver) {
        // A throw here is uncaught: the write completed inside `uv_run`, so
        // nothing above it can handle one. Node's `MakeCallback` catches it and
        // routes it through `TriggerUncaughtException`; ignoring the result
        // leaves V8 to print the error with the process still exiting 0.
        let call = |scoped: &mut v8::PinScope<'_, '_>| {
            let try_catch = std::pin::pin!(v8::TryCatch::new(scoped));
            let inner = &mut try_catch.init();
            let _ = callback.call(inner, object.into(), &[]);
            inner
                .exception()
                .map(|exception| v8::Global::new(inner, exception))
        };
        let caught = match context {
            Some(context) => {
                let resource = v8::Global::new(scope.as_ref(), object);
                // `with_scope` reports a throw itself, so the `TryCatch` above
                // exists only for the unscoped fallback.
                let _ = rn_core::callback_scope::with_scope(
                    scope,
                    rn_core::callback_scope::ScopeArgs {
                        context,
                        resource: Some(&resource),
                        frame: None,
                    },
                    |scoped| {
                        let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scoped));
                        let inner = &mut try_catch.init();
                        let _ = callback.call(inner, object.into(), &[]);
                    },
                );
                None
            }
            None => call(scope),
        };
        if let Some(caught) = caught {
            let exception = v8::Local::new(scope, &caught);
            rn_errors::report_uncaught_exception(scope, exception);
        }
    }
}

fn params<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();
    let level = arg_i32(scope, &args, 0);
    let strategy = arg_i32(scope, &args, 1);

    match with_state(object, |state| state.set_params(level, strategy)) {
        None => throw(scope, "zlib binding closed"),
        Some(Some(error)) => emit_error(scope, object, error),
        Some(None) => {}
    }
}

fn reset<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();
    let outcome = with_state(object, |state| {
        if state.write_in_progress {
            return Some(StreamError::Zlib(ZlibError {
                message: "Cannot reset zlib stream while a write is in progress".to_string(),
                code: "Z_STREAM_ERROR",
                err: Z_STREAM_ERROR,
            }));
        }
        state.reset()
    });
    match outcome {
        None => throw(scope, "zlib binding closed"),
        Some(Some(error)) => emit_error(scope, object, error),
        Some(None) => {}
    }
}

fn close<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();
    let _ = with_state(object, HandleState::close);
}

/// `EmitError()`: call `this.onerror(message, errno, code)`.
fn emit_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    error: StreamError,
) {
    let (message, errno, code) = error.parts();
    let Some(key) = v8::String::new(scope, "onerror") else {
        return;
    };
    let Some(value) = object.get(scope, key.into()) else {
        return;
    };
    let Ok(onerror) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let errno = v8::Integer::new(scope, errno);
    let Some(code) = v8::String::new(scope, code) else {
        return;
    };
    onerror.call(
        scope,
        object.into(),
        &[message.into(), errno.into(), code.into()],
    );
}

// ---------------------------------------------------------------------------
// Class installation
// ---------------------------------------------------------------------------

fn define_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    template: v8::Local<'s, v8::FunctionTemplate>,
) -> Result<(), String> {
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    for (method_name, method) in [
        ("init", rn_core::method(init).build(scope)),
        ("write", rn_core::method(write).build(scope)),
        ("writeSync", rn_core::method(write_sync).build(scope)),
        ("params", rn_core::method(params).build(scope)),
        ("reset", rn_core::method(reset).build(scope)),
        ("close", rn_core::method(close).build(scope)),
    ] {
        let Some(key) = v8::String::new(scope, method_name) else {
            return Err(format!("cannot allocate zlib method name {method_name}"));
        };
        prototype.set(key.into(), method.into());
    }

    let Some(class_name) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate zlib class name {name}"));
    };
    template.set_class_name(class_name);

    let Some(function) = template.get_function(scope) else {
        return Err(format!("cannot allocate zlib constructor {name}"));
    };
    let Some(key) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate zlib constructor name {name}"));
    };
    target.set(scope, key.into(), function.into());
    Ok(())
}

/// Installs `Zlib`, `BrotliEncoder`, `BrotliDecoder`, `ZstdCompress` and
/// `ZstdDecompress`.
pub(crate) fn install_constructors<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    define_class(
        scope,
        target,
        "Zlib",
        rn_core::class(zlib_constructor).build(scope),
    )?;
    define_class(
        scope,
        target,
        "BrotliEncoder",
        rn_core::class(brotli_encoder_constructor).build(scope),
    )?;
    define_class(
        scope,
        target,
        "BrotliDecoder",
        rn_core::class(brotli_decoder_constructor).build(scope),
    )?;
    define_class(
        scope,
        target,
        "ZstdCompress",
        rn_core::class(zstd_compress_constructor).build(scope),
    )?;
    define_class(
        scope,
        target,
        "ZstdDecompress",
        rn_core::class(zstd_decompress_constructor).build(scope),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deflate_state() -> HandleState {
        HandleState::new(Backend::Zlib(Box::new(ZlibStream::new(ZlibMode::Deflate))))
    }

    #[test]
    fn fresh_state_is_open_and_idle() {
        let state = deflate_state();
        assert!(!state.closed);
        assert!(!state.write_in_progress);
        assert!(state.error().is_none());
    }

    #[test]
    fn close_is_idempotent() {
        let mut state = deflate_state();
        state.close();
        assert!(state.closed);
        state.close();
        assert!(state.closed);
    }

    #[test]
    fn store_after_write_uses_the_javascript_field_order() {
        let mut storage = [999u32; 2];
        let mut state = deflate_state();
        state.write_state = storage.as_mut_ptr();
        state.store_after_write(AfterWrite {
            avail_in: 7,
            avail_out: 11,
        });
        // lib/zlib.js reads state[0] as availOutAfter and state[1] as availInAfter.
        assert_eq!(storage, [11, 7]);
    }

    #[test]
    fn a_null_write_state_is_ignored() {
        let state = deflate_state();
        // Must not dereference anything; a handle that never ran `init` has no
        // `writeState`.
        state.store_after_write(AfterWrite {
            avail_in: 1,
            avail_out: 2,
        });
    }
}
