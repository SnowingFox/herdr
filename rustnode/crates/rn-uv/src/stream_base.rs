//! The `StreamBase` methods, shared by `tcp_wrap` and `pipe_wrap`.
//!
//! `src/stream_base.cc` adds `readStart`, `readStop`, `shutdown`, the four
//! `write*` forms and the counters to the *shared* `LibuvStreamWrap` prototype,
//! and `TCP`/`Pipe` inherit it. rustnode has two separate bindings, so the same
//! methods are installed on two prototypes — but written once here, driven by
//! [`StreamHandle`], so the two cannot drift.
//!
//! Everything here takes `&mut impl StreamHandle`, which is what makes that
//! sharing possible without either binding knowing the other's type.

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use crate::handle::{self, HandleState, StreamState};
use crate::stream;

/// `UV_EBADF`, what `ASSIGN_OR_RETURN_UNWRAP` reports for a bad receiver.
pub const EBADF: i32 = uv::uv_errno_t_UV_EBADF;
/// `UV_EINVAL`, for an argument a `CHECK` would have rejected.
pub const EINVAL: i32 = uv::uv_errno_t_UV_EINVAL;

/// What the shared stream methods need from a socket or pipe handle.
pub trait StreamHandle {
    /// The libuv stream underneath.
    fn stream_state(&mut self) -> &mut StreamState;

    /// Bytes read so far.
    fn bytes_read(&self) -> u64;

    /// Bytes handed to writes so far.
    fn bytes_written(&self) -> u64;
}

/// `StreamBase::ReadStartJS` → `LibuvStreamWrap::ReadStart`.
pub fn read_start(handle: &mut impl StreamHandle) -> i32 {
    let state = handle.stream_state();
    if !state.is_alive() {
        return EINVAL;
    }
    let stream = state.stream;
    // SAFETY: the stream is live and the state lives in the same allocation as
    // the handle, so it outlives every read.
    unsafe { stream::read_start(stream, state as *mut StreamState) }
}

/// `StreamBase::ReadStopJS`.
pub fn read_stop(handle: &mut impl StreamHandle) -> i32 {
    let state = handle.stream_state();
    if !state.is_alive() {
        return EINVAL;
    }
    let stream = state.stream;
    // SAFETY: the stream is live.
    unsafe { stream::read_stop(stream) }
}

/// `StreamBase::Shutdown`.
///
/// Returns `0` when a completion is queued, or a negative error. `uv_shutdown`
/// reports `UV_ENOTCONN` on a stream that is not connected, which
/// `Socket.prototype._final` treats as "nothing to flush".
pub fn shutdown(
    scope: &mut v8::PinScope<'_, '_>,
    handle: &mut impl StreamHandle,
    request: v8::Local<v8::Object>,
    owner: v8::Local<v8::Object>,
) -> i32 {
    let state = handle.stream_state();
    if !state.is_alive() {
        return EINVAL;
    }
    let stream = state.stream;
    // SAFETY: the stream is live and `request` is the caller's `ShutdownWrap`,
    // kept alive by `lib/net.js`.
    unsafe { stream::queue_shutdown(scope, stream, request, owner) }
}

/// `StreamBase::WriteBuffer`: `writeBuffer(req, buffer)`.
///
/// When `req` is null — which `lib/internal/stream_base_commons.js` always does
/// (`handle.writeBuffer(null, data)`) — a `WriteWrap` is created and returned, so
/// `afterWriteDispatched` can attach `oncomplete` and await the completion.
pub fn write_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    handle: &mut impl StreamHandle,
    request: Option<v8::Local<'s, v8::Object>>,
    buffer: v8::Local<v8::Value>,
    owner: v8::Local<'s, v8::Object>,
) -> WriteResult<'s> {
    // SAFETY: `stream_base_commons` keeps the buffer alive on `req.buffer`.
    let Some(buffer) = (unsafe { view_buffer(buffer) }) else {
        return WriteResult::Status(EINVAL);
    };
    dispatch(scope, handle, request, vec![buffer], Vec::new(), owner)
}

/// `StreamBase::Write`: try the write synchronously, then queue what is left.
///
/// This is the order Node uses, and both halves are load-bearing:
///
/// * [`stream::try_write`] first. A pipe that accepts the bytes completes the
///   write without creating a request, and that is what stops a lone
///   `process.stdout.write` from holding the event loop open: an outstanding
///   `uv_write_t` is itself a ref'd handle.
/// * Otherwise `uv_write` the remainder, which reports asynchronously through
///   `request.oncomplete`.
///
/// `owned` is storage the caller flattened for `buffers`; it must survive until
/// the completion, so it is handed to the queued path. When the write completes
/// synchronously it has served its purpose and is dropped here.
fn dispatch<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    handle: &mut impl StreamHandle,
    request: Option<v8::Local<'s, v8::Object>>,
    mut buffers: Vec<uv::uv_buf_t>,
    owned: Vec<Box<[u8]>>,
    owner: v8::Local<'s, v8::Object>,
) -> WriteResult<'s> {
    let total: usize = buffers.iter().map(|buffer| buffer.len).sum();
    let state = handle.stream_state();
    if !state.is_alive() {
        return WriteResult::Status(EINVAL);
    }
    // `StreamBase::Write` counts before it dispatches, so `bytesWritten`
    // includes a write that is still queued.
    state.bytes_written += total as u64;
    let stream = state.stream;

    // SAFETY: the stream is live and `buffers` is valid for the call. If a
    // request is queued below, the storage the buffers point at is kept alive by
    // `owned` (strings) or by `req.buffer` (views).
    let written = unsafe { stream::try_write(stream, &mut buffers) };
    if written >= total {
        // Everything was taken, so no request is created; `afterWriteDispatched`
        // reads the zero as "completed synchronously".
        stream::publish(&stream::WriteOutcome {
            bytes: written,
            asynchronous: false,
            error: 0,
        });
        return WriteResult::Status(0);
    }
    // Slice off what landed, as `DoTryWrite` does: the partially written buffer
    // keeps its tail, and fully written ones are discarded.
    let mut remaining = written;
    let mut start = 0;
    while start < buffers.len() {
        if buffers[start].len > remaining {
            // SAFETY: `remaining` is less than this buffer's length, so the tail
            // stays inside the allocation the caller provided.
            buffers[start] = uv::uv_buf_t {
                base: unsafe { buffers[start].base.add(remaining) },
                len: buffers[start].len - remaining,
            };
            break;
        }
        remaining -= buffers[start].len;
        start += 1;
    }
    buffers.drain(..start);
    let pending: usize = buffers.iter().map(|buffer| buffer.len).sum();

    let Some(request) = request.or_else(|| write_wrap(scope)) else {
        return WriteResult::Status(EINVAL);
    };
    // SAFETY: the stream is live; `owned` keeps any flattened string bytes alive
    // until the completion runs.
    let status =
        unsafe { stream::queue_write(scope, stream, buffers, pending, request, owner, owned) };
    WriteResult::from_status(status, request)
}

/// One encoded chunk of a write, and the storage that keeps it alive.
///
/// `uv_buf_t` is a raw pointer, so whatever it points at has to outlive the
/// libuv completion. A buffer chunk's backing store is held by `req.buffer` in
/// `lib/internal/stream_base_commons.js`; a string chunk has no such owner, so
/// its bytes are flattened here and handed to [`stream::queue_write`] as `owned`
/// storage that the completion drops.
struct Chunk {
    buffer: uv::uv_buf_t,
    storage: Option<Box<[u8]>>,
}

/// Reads a chunk's encoding name out of the `writev` array.
///
/// `writevGeneric` builds the array as `[chunk, encoding, chunk, encoding, ...]`
/// where each encoding is the name the caller passed to `write()`. An absent or
/// unrecognised name is `utf8`, which is what `ParseEncoding`'s fall-through
/// does — `lib/internal/streams/writable.js` has already rejected anything
/// `Buffer.isEncoding` does not know, so this only ever sees real names.
fn chunk_encoding(
    scope: &mut v8::PinScope<'_, '_>,
    chunks: v8::Local<v8::Array>,
    index: u32,
) -> rn_core::Encoding {
    let Some(value) = chunks.get_index(scope, index) else {
        return rn_core::Encoding::Utf8;
    };
    let Ok(name) = v8::Local::<v8::String>::try_from(value) else {
        return rn_core::Encoding::Utf8;
    };
    encoding_from_name(&name.to_rust_string_lossy(scope))
}

/// `ParseEncoding`'s name table.
///
/// `buffer` is not a wire encoding and never reaches here — `writable.js` rejects
/// it for a string chunk — so it falls back to `utf8` with every other unknown
/// name.
fn encoding_from_name(name: &str) -> rn_core::Encoding {
    use rn_core::Encoding;
    match name.to_ascii_lowercase().as_str() {
        "latin1" | "binary" => Encoding::Binary,
        "ascii" => Encoding::Ascii,
        "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => Encoding::Ucs2,
        "hex" => Encoding::Hex,
        "base64" => Encoding::Base64,
        "base64url" => Encoding::Base64Url,
        _ => Encoding::Utf8,
    }
}

/// Copies a JavaScript string out as UTF-16 code units.
///
/// `StringBytes::Write` works from `String::ValueView`, which is the code units
/// themselves; the encodings differ in how they narrow them, and `ucs2` needs the
/// units unmodified, so the conversion cannot happen earlier.
fn string_units(scope: &v8::Isolate, text: &v8::String) -> Vec<u16> {
    let length = text.length();
    if length == 0 {
        return Vec::new();
    }
    let mut units = vec![0u16; length];
    text.write_v2(scope, 0, &mut units, v8::WriteFlags::empty());
    units
}

/// `StreamBase::Writev`: `writev(req, chunks, allBuffers)`.
///
/// With `allBuffers` false the array alternates `[chunk, encoding, ...]`, and
/// each entry may be a `Buffer` or a string with a named encoding. Node does not
/// pre-convert the strings: `StringBytes::Write` runs here, per chunk, because
/// the encoding is per chunk. `net.Socket` never sets the "decode strings" flag,
/// so a plain `process.stdout.write('x')` reaches this function with a *string*
/// in slot 0 and `'utf8'` in slot 1.
pub fn writev<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    handle: &mut impl StreamHandle,
    request: Option<v8::Local<'s, v8::Object>>,
    chunks: v8::Local<v8::Array>,
    all_buffers: bool,
    owner: v8::Local<'s, v8::Object>,
) -> WriteResult<'s> {
    let count = if all_buffers {
        chunks.length() as usize
    } else {
        chunks.length() as usize >> 1
    };
    let stride = if all_buffers { 1 } else { 2 };

    let mut encoded = Vec::with_capacity(count);
    let mut storage_size = 0usize;
    for index in 0..count {
        let Some(value) = chunks.get_index(scope, (index * stride) as u32) else {
            return WriteResult::Status(EINVAL);
        };
        // `Buffer::HasInstance` first, exactly as Node does: a Buffer's bytes are
        // already the wire form and its encoding slot is ignored.
        // SAFETY: `lib/internal/stream_base_commons.js` keeps every chunk alive
        // on `req.buffer`, which outlives the completion.
        if let Some(buffer) = unsafe { view_buffer(value) } {
            encoded.push(Chunk {
                buffer,
                storage: None,
            });
            continue;
        }
        if all_buffers {
            // `Writev` reads `Buffer::Data` unconditionally on this branch, so a
            // non-buffer is a caller error rather than something to coerce.
            return WriteResult::Status(EINVAL);
        }
        let Some(text) = value.to_string(scope) else {
            return WriteResult::Status(EINVAL);
        };
        let encoding = chunk_encoding(scope, chunks, (index * stride + 1) as u32);
        let units = string_units(scope, &text);
        let mut bytes = rn_core::codec::write(
            &units,
            encoding,
            rn_core::codec::storage_size(&units, encoding),
        );
        storage_size += bytes.len();
        encoded.push(Chunk {
            buffer: uv::uv_buf_t {
                base: bytes.as_mut_ptr().cast(),
                len: bytes.len(),
            },
            storage: Some(bytes.into_boxed_slice()),
        });
    }
    if storage_size > i32::MAX as usize {
        // `if (storage_size > INT_MAX) return UV_ENOBUFS;`
        return WriteResult::Status(uv::uv_errno_t_UV_ENOBUFS);
    }
    // `encoded` is fully built, so every `storage` box has its final address and
    // the pointers above stay valid: moving a `Box<[u8]>` moves the box, not the
    // bytes it points at.
    let buffers: Vec<uv::uv_buf_t> = encoded.iter().map(|chunk| chunk.buffer).collect();
    let owned: Vec<Box<[u8]>> = encoded
        .into_iter()
        .filter_map(|chunk| chunk.storage)
        .collect();
    dispatch(scope, handle, request, buffers, owned, owner)
}

/// `StreamBase::WriteString<Encoding>` — `writeUtf8String` and its three
/// siblings.
///
/// The four prototype methods differ *only* in the encoding they name; the body
/// is `WriteString`, which flattens the string with `StringBytes::Write`. So the
/// encoding is a parameter here rather than four copies of this function, and
/// `writeLatin1String` stops emitting UTF-8 by accident.
///
/// The bytes are flattened into storage the write owns, so they stay valid until
/// libuv's completion fires even though the JavaScript string may be collected
/// immediately.
pub fn write_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    handle: &mut impl StreamHandle,
    request: Option<v8::Local<'s, v8::Object>>,
    text: v8::Local<v8::String>,
    encoding: rn_core::Encoding,
    owner: v8::Local<'s, v8::Object>,
) -> WriteResult<'s> {
    let units = string_units(scope.as_ref(), &text);
    let storage = rn_core::codec::write(
        &units,
        encoding,
        rn_core::codec::storage_size(&units, encoding),
    );
    let mut storage = storage.into_boxed_slice();
    let buffer = uv::uv_buf_t {
        base: storage.as_mut_ptr().cast(),
        len: storage.len(),
    };
    dispatch(scope, handle, request, vec![buffer], vec![storage], owner)
}

/// What a write produced, in the shape `FinishWrite` returns it.
pub enum WriteResult<'s> {
    /// The write is queued; JavaScript attaches `oncomplete` to this object.
    Queued(v8::Local<'s, v8::Object>),
    /// A status code, which `afterWriteDispatched` reads as a number.
    Status(i32),
}

impl<'s> WriteResult<'s> {
    /// Maps libuv's status onto the value JavaScript expects.
    ///
    /// `0` means queued, so the request object goes back; anything else is a
    /// status the caller reports through its callback immediately.
    fn from_status(status: i32, request: v8::Local<'s, v8::Object>) -> Self {
        if status == 0 {
            Self::Queued(request)
        } else {
            Self::Status(status)
        }
    }

    /// Writes the result into a V8 return value.
    pub fn apply(self, scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue<'_>) {
        match self {
            Self::Queued(request) => rv.set(request.into()),
            Self::Status(status) => rv.set(v8::Integer::new(scope, status).into()),
        }
    }
}

/// `HandleWrap::Ref`.
pub fn reference(handle: &mut impl StreamHandle) {
    let state = handle.stream_state();
    if state.is_alive() {
        // SAFETY: the stream is live.
        unsafe { uv::uv_ref(handle::as_handle(state.stream)) };
    }
}

/// `HandleWrap::Unref`.
pub fn unreference(handle: &mut impl StreamHandle) {
    let state = handle.stream_state();
    if state.is_alive() {
        // SAFETY: the stream is live.
        unsafe { uv::uv_unref(handle::as_handle(state.stream)) };
    }
}

/// `HandleWrap::HasRef`: `IsAlive(wrap) && uv_has_ref(handle)`.
pub fn has_reference(handle: &mut impl StreamHandle) -> bool {
    let state = handle.stream_state();
    state.is_alive()
        // SAFETY: the stream is live.
        && unsafe { uv::uv_has_ref(handle::as_handle(state.stream)) != 0 }
}

/// `LibuvStreamWrap::GetFD` — the `fd` accessor, `-1` when there is none.
pub fn file_descriptor(handle: &mut impl StreamHandle) -> i32 {
    let state = handle.stream_state();
    let mut descriptor: uv::uv_os_fd_t = -1;
    // SAFETY: the stream is live.
    let status = unsafe { uv::uv_fileno(handle::as_handle(state.stream), &mut descriptor) };
    if status == 0 {
        descriptor
    } else {
        -1
    }
}

/// `LibuvStreamWrap::GetWriteQueueSize` — bytes libuv still has queued.
pub fn write_queue_size(handle: &mut impl StreamHandle) -> u32 {
    let state = handle.stream_state();
    if state.stream.is_null() {
        return 0;
    }
    // SAFETY: the stream is live.
    unsafe { (*state.stream).write_queue_size as u32 }
}

/// `HandleWrap::Close`, shared by both bindings.
///
/// `uv_close` is asynchronous: the callback runs on a later loop turn and is what
/// calls the `close_callback` `lib/net.js` passes so it can emit `'close'`.
pub fn close(
    scope: &mut v8::PinScope<'_, '_>,
    handle: &mut impl StreamHandle,
    owner: v8::Local<v8::Object>,
    callback: v8::Local<v8::Value>,
    on_close: uv::uv_close_cb,
) {
    let state = handle.stream_state();
    // `HandleWrap::Close` returns silently for a handle that is not initialised:
    // closing twice would abort libuv.
    if state.state != HandleState::Initialized {
        return;
    }

    if let Ok(function) = v8::Local::<v8::Function>::try_from(callback) {
        if let Some(key) = v8::String::new(scope, "onclose") {
            owner.set(scope, key.into(), function.into());
        }
    }

    state.state = HandleState::Closing;
    // SAFETY: the stream is live and not already closing.
    unsafe { uv::uv_close(handle::as_handle(state.stream), on_close) };
}

/// Builds a fresh `WriteWrap` for a write whose caller passed no request object.
///
/// This is `StreamBase::Write`'s
/// `env->write_wrap_template()->InstanceTemplate()->NewInstance()` path. The
/// fields are the ones `afterWriteDispatched` reads, so the object shape matches
/// `internalBinding('stream_wrap').WriteWrap`.
fn write_wrap<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    let null = v8::null(scope);
    for name in ["oncomplete", "callback", "handle", "buffer", "writeStatus"] {
        let key = v8::String::new(scope, name)?;
        object.set(scope, key.into(), null.into());
    }
    let async_key = v8::String::new(scope, "async")?;
    object.set(
        scope,
        async_key.into(),
        v8::Boolean::new(scope, false).into(),
    );
    let bytes_key = v8::String::new(scope, "bytes")?;
    object.set(scope, bytes_key.into(), v8::Integer::new(scope, 0).into());
    Some(object)
}

/// Points a `uv_buf_t` at a `Uint8Array`'s bytes.
///
/// # Safety
///
/// The view's backing store must stay alive until libuv is done with the buffer.
/// `lib/internal/stream_base_commons.js` holds `req.buffer` for exactly that
/// reason.
pub unsafe fn view_buffer(value: v8::Local<v8::Value>) -> Option<uv::uv_buf_t> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() {
        if length == 0 {
            return Some(uv::uv_buf_t {
                base: std::ptr::null_mut(),
                len: 0,
            });
        }
        return None;
    }
    Some(uv::uv_buf_t {
        base: data.cast(),
        len: length,
    })
}

/// Calls `handle.onclose()`, the callback `HandleWrap::OnClose` invokes.
///
/// Shared because both bindings' close callbacks need it. `HandleWrap::OnClose`
/// (`src/handle_wrap.cc:155`) ends in `wrap->MakeCallback(onclose, 0, nullptr)`,
/// so this runs inside the handle's `InternalCallbackScope` like a read does:
/// `executionAsyncId()` inside `'close'` is the socket's id, and
/// `AsyncLocalStorage` sees the frame the handle captured.
pub fn call_onclose(
    scope: &mut v8::PinScope<'_, '_>,
    context: rn_core::callback_scope::AsyncContext,
    frame: Option<v8::Global<v8::Value>>,
    object: v8::Local<v8::Object>,
) {
    let Some(key) = v8::String::new(scope, "onclose") else {
        return;
    };
    let Some(value) = object.get(scope, key.into()) else {
        return;
    };
    if let Ok(function) = v8::Local::<v8::Function>::try_from(value) {
        let args = rn_core::callback_scope::ScopeArgs {
            context,
            resource: Some(v8::Global::new(scope.as_ref(), object)),
            frame,
        };
        let _ = rn_core::callback_scope::with_scope(scope, args, |scope| {
            let receiver: v8::Local<v8::Value> = object.into();
            let _ = function.call(&*scope, receiver, &[]);
        });
    }
}

/// Calls `handle.onclose()` for a wrapper that carries no async state.
///
/// `ProcessWrap` is an `AsyncWrap` in Node, but this runtime's process handle
/// has no async id or frame, so there is nothing to push and nothing to install.
/// Calling the callback unscoped is what this did before [`call_onclose`] grew a
/// scope, and it is honest: giving it one would first require giving the handle
/// an async id.
pub fn call_onclose_unscoped(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) {
    let Some(key) = v8::String::new(scope, "onclose") else {
        return;
    };
    let Some(value) = object.get(scope, key.into()) else {
        return;
    };
    if let Ok(function) = v8::Local::<v8::Function>::try_from(value) {
        let receiver: v8::Local<v8::Value> = object.into();
        let _ = function.call(&*scope, receiver, &[]);
    }
}
