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
    let total = buffer.len;
    let state = handle.stream_state();
    if !state.is_alive() {
        return WriteResult::Status(EINVAL);
    }
    let stream = state.stream;

    let Some(request) = request.or_else(|| write_wrap(scope)) else {
        return WriteResult::Status(EINVAL);
    };
    // SAFETY: the buffer points into a view the caller keeps alive.
    let status = unsafe {
        stream::queue_write(
            scope,
            stream,
            vec![buffer],
            total,
            request,
            owner,
            Vec::new(),
        )
    };
    WriteResult::from_status(status, request)
}

/// `StreamBase::Writev`: `writev(req, chunks, allBuffers)`.
pub fn writev<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    handle: &mut impl StreamHandle,
    request: Option<v8::Local<'s, v8::Object>>,
    chunks: v8::Local<v8::Array>,
    all_buffers: bool,
    owner: v8::Local<'s, v8::Object>,
) -> WriteResult<'s> {
    // With `allBuffers` false the array alternates `[chunk, encoding, ...]`, and
    // only the chunk slots hold data: `writevGeneric` has already converted every
    // non-buffer chunk before calling this.
    let stride = if all_buffers { 1 } else { 2 };
    let mut buffers = Vec::new();
    let mut total = 0usize;
    let mut index = 0;
    while index < chunks.length() {
        let Some(value) = chunks.get_index(scope, index) else {
            return WriteResult::Status(EINVAL);
        };
        // SAFETY: the caller keeps every chunk alive on `req.buffer`.
        match unsafe { view_buffer(value) } {
            Some(buffer) => {
                total += buffer.len;
                buffers.push(buffer);
            }
            None => return WriteResult::Status(EINVAL),
        }
        index += stride;
    }

    let state = handle.stream_state();
    if !state.is_alive() {
        return WriteResult::Status(EINVAL);
    }
    let stream = state.stream;

    let Some(request) = request.or_else(|| write_wrap(scope)) else {
        return WriteResult::Status(EINVAL);
    };
    // SAFETY: as in `write_buffer`.
    let status =
        unsafe { stream::queue_write(scope, stream, buffers, total, request, owner, Vec::new()) };
    WriteResult::from_status(status, request)
}

/// `StreamBase::WriteString<UTF8>` and its siblings.
///
/// The string is flattened into a buffer the write owns, so the bytes stay valid
/// until libuv's completion fires even though the JavaScript string may be
/// collected immediately.
pub fn write_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    handle: &mut impl StreamHandle,
    request: Option<v8::Local<'s, v8::Object>>,
    text: v8::Local<v8::String>,
    owner: v8::Local<'s, v8::Object>,
) -> WriteResult<'s> {
    // `StringBytes::StorageSize` for UTF-8 is at most four bytes per code unit;
    // `write_utf8_v2` reports how many it actually used.
    let capacity = text.length().saturating_mul(4) + 4;
    let mut storage = vec![0u8; capacity];
    let written = text.write_utf8_v2(scope.as_ref(), &mut storage, v8::WriteFlags::empty(), None);
    storage.truncate(written);
    let mut storage = storage.into_boxed_slice();
    let base = storage.as_mut_ptr();
    let length = storage.len();

    let state = handle.stream_state();
    if !state.is_alive() {
        return WriteResult::Status(EINVAL);
    }
    let stream = state.stream;

    let Some(request) = request.or_else(|| write_wrap(scope)) else {
        return WriteResult::Status(EINVAL);
    };
    let buffer = uv::uv_buf_t {
        base: base.cast(),
        len: length,
    };
    // SAFETY: `storage` is moved into the write, so its bytes outlive the
    // completion.
    let status = unsafe {
        stream::queue_write(
            scope,
            stream,
            vec![buffer],
            length,
            request,
            owner,
            vec![storage],
        )
    };
    WriteResult::from_status(status, request)
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
/// Shared because both bindings' close callbacks need it.
pub fn call_onclose(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) {
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
