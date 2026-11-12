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
//! `AfterThreadPoolWork`. There is no threadpool here, so the compression step
//! runs inline and only the *completion* is deferred, onto a microtask. That
//! keeps the two properties `processCallback()` relies on:
//!
//! 1. `writeState` holds this step's offsets before the callback runs.
//! 2. The callback never runs inside `write()`, so `processCallback`'s
//!    "output buffer full, call `this.write()` again" path re-enters through the
//!    microtask queue instead of growing the native stack.

use std::cell::RefCell;
use std::ffi::c_void;

use rn_v8_sys::v8;

use crate::brotli::{BrotliError, BrotliStream};
use crate::constants::*;
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
    write_in_progress: bool,
    closed: bool,
}

impl HandleState {
    fn new(backend: Backend) -> Self {
        Self {
            backend,
            weak: None,
            write_state: std::ptr::null_mut(),
            write_cb: None,
            receiver: None,
            pending_error: None,
            write_in_progress: false,
            closed: false,
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

    /// `CompressionStream::Close()`: ends the compressor state, leaves the
    /// wrapper alive so a late callback cannot use freed memory.
    fn close(&mut self) {
        self.closed = true;
        match &mut self.backend {
            Backend::Zlib(stream) => stream.close(),
            Backend::Brotli(stream) => stream.close(),
            Backend::ZstdCompress(stream) => stream.close(),
            Backend::ZstdDecompress(stream) => stream.close(),
        }
        self.pending_error = None;
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
    let pointer = Box::into_raw(Box::new(RefCell::new(HandleState::new(backend))));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    crate::note_handle_allocated();

    // The finalizer owns the allocation from here on, so it is released even if
    // `close()` never runs.
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
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

/// The shared body of `write`/`writeSync`: one compression step, then either
/// the offsets published or `onerror` called.
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
    let Ok((output_pointer, output_length)) = output_range(scope, args) else {
        return;
    };
    // SAFETY: `output_range` validated `output` against the caller's live
    // backing store. The slice is created here and dropped at the end of this
    // function, and `state.step` cannot run JavaScript, so nothing can alias it.
    let output = unsafe { std::slice::from_raw_parts_mut(output_pointer, output_length) };

    let outcome = with_state(object, |state| {
        if state.closed {
            return Err(StreamError::closed());
        }
        if asynchronous && state.write_in_progress {
            return Err(StreamError::Zlib(ZlibError {
                message: "write in progress".to_string(),
                code: "Z_STREAM_ERROR",
                err: Z_STREAM_ERROR,
            }));
        }

        let after = state.step(flush, &input, output);
        match state.error() {
            // `writeSync` reports failures through `onerror`, which is where
            // `processChunkSync` picks them up; `writeState` stays untouched.
            Some(error) => Err(error),
            None => {
                state.store_after_write(after);
                if asynchronous {
                    // The queued completion reaches the state through a raw
                    // pointer, so pin the wrapper until that microtask has run.
                    // `complete_write` releases it, which is what keeps this
                    // from becoming a reference cycle.
                    state.write_in_progress = true;
                    state.receiver = Some(v8::Global::new(scope, object));
                }
                Ok(())
            }
        }
    });

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

/// The deferred half of `write()`: `AfterThreadPoolWork` plus the callback
/// invocation from `processCallback`.
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

    state.write_in_progress = false;

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
        return;
    }

    let callback = state
        .write_cb
        .as_ref()
        .map(|handle| v8::Local::new(scope, handle));
    let receiver = state
        .receiver
        .as_ref()
        .map(|handle| v8::Local::new(scope, handle));
    // The completion is the last thing that needed the wrapper pinned; release
    // it after taking the locals so this object can be collected next GC.
    state.receiver = None;
    drop(state);

    if let (Some(callback), Some(object)) = (callback, receiver) {
        // A throw here is uncaught: the write completed inside `uv_run`, so
        // nothing above it can handle one. Node's `MakeCallback` catches it and
        // routes it through `TriggerUncaughtException`; ignoring the result
        // leaves V8 to print the error with the process still exiting 0.
        let caught = {
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let inner = &mut try_catch.init();
            let _ = callback.call(inner, object.into(), &[]);
            inner
                .exception()
                .map(|exception| v8::Global::new(inner, exception))
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
        ("init", v8::FunctionTemplate::builder(init).build(scope)),
        ("write", v8::FunctionTemplate::builder(write).build(scope)),
        (
            "writeSync",
            v8::FunctionTemplate::builder(write_sync).build(scope),
        ),
        ("params", v8::FunctionTemplate::builder(params).build(scope)),
        ("reset", v8::FunctionTemplate::builder(reset).build(scope)),
        ("close", v8::FunctionTemplate::builder(close).build(scope)),
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
        v8::FunctionTemplate::builder(zlib_constructor).build(scope),
    )?;
    define_class(
        scope,
        target,
        "BrotliEncoder",
        v8::FunctionTemplate::builder(brotli_encoder_constructor).build(scope),
    )?;
    define_class(
        scope,
        target,
        "BrotliDecoder",
        v8::FunctionTemplate::builder(brotli_decoder_constructor).build(scope),
    )?;
    define_class(
        scope,
        target,
        "ZstdCompress",
        v8::FunctionTemplate::builder(zstd_compress_constructor).build(scope),
    )?;
    define_class(
        scope,
        target,
        "ZstdDecompress",
        v8::FunctionTemplate::builder(zstd_decompress_constructor).build(scope),
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
