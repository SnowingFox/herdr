//! The methods on the `Pipe` prototype.
//!
//! Everything `StreamBase` provides — reads, writes, shutdown, the counters — is
//! shared with `tcp_wrap` through [`rn_uv::stream_base`]; what is here is only
//! what a pipe does differently. A pipe binds and connects by *path*, not by
//! address and port, and it has `fchmod` where a socket has the socket-option
//! methods.
//!
//! # Paths, not addresses
//!
//! `uv_pipe_bind2`/`uv_pipe_connect2` take a length and a "do not truncate" flag
//! so a path that does not fit the platform's limit is an error rather than a
//! silently shortened socket. `lib/net.js` passes the path straight through and
//! reports whatever error comes back, so both are transcribed with the length
//! `Node` computes: the byte length of the path, with no NUL terminator.

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_core::Encoding;
use rn_uv::handle::{self, HandleState};
use rn_uv::stream_base::{self, StreamHandle, EBADF, EINVAL};

use crate::connect;
use crate::handle::{self as pipe, PipeHandle};

impl StreamHandle for PipeHandle {
    fn stream_state(&mut self) -> &mut rn_uv::handle::StreamState {
        &mut self.state
    }

    fn bytes_read(&self) -> u64 {
        // The counters live on `StreamState` because `rn_uv::stream` is what
        // increments them, matching `StreamResource::bytes_read_`.
        self.state.bytes_read
    }

    fn bytes_written(&self) -> u64 {
        self.state.bytes_written
    }
}

/// `HandleWrap::Close`.
pub fn close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    pipe::with_handle(object, |handle| {
        stream_base::close(scope, handle, object, args.get(0), Some(after_close));
    });
}

/// libuv's close completion for a pipe.
///
/// # Safety
///
/// Called by libuv with a handle this crate initialised.
pub unsafe extern "C" fn after_close(handle_pointer: *mut uv::uv_handle_t) {
    // SAFETY: the handle's `data` is the `StreamState` the constructor stored.
    let Some(state) = (unsafe { handle::owner(handle_pointer.cast::<uv::uv_stream_t>()) }) else {
        return;
    };
    // SAFETY: the owner pointer is live until the wrapper is freed.
    let state = unsafe { &mut *state };
    state.state = HandleState::Closed;

    rn_uv::callback::with_context(|scope| {
        let Some(object) = state
            .owner_object
            .as_ref()
            .map(|object| v8::Local::new(scope, object))
        else {
            return;
        };
        stream_base::call_onclose(scope, object);
    });
}

/// The close completion used when the wrapper died while the pipe was open.
///
/// # Safety
///
/// Called by libuv with a handle whose `data` is the `StreamState` inside a
/// [`PipeHandle`], and only from the finalizer's own `uv_close`.
pub unsafe extern "C" fn finalize_handle(handle_pointer: *mut uv::uv_handle_t) {
    // SAFETY: as in `after_close`.
    let Some(state) = (unsafe { handle::owner(handle_pointer.cast::<uv::uv_stream_t>()) }) else {
        return;
    };
    // SAFETY: the state lives inside a `PipeHandle` box the finalizer kept alive.
    let state = unsafe { &mut *state };
    state.state = HandleState::Closed;
    // SAFETY: `state` is the `state` field of a live `PipeHandle`, so subtracting
    // the field's offset recovers the allocation.
    let owner = unsafe {
        (state as *mut rn_uv::handle::StreamState)
            .cast::<u8>()
            .sub(std::mem::offset_of!(PipeHandle, state))
            .cast::<PipeHandle>()
    };
    // SAFETY: the finalizer handed the box over and nothing else frees it.
    drop(unsafe { Box::from_raw(owner) });
}

/// `HandleWrap::Ref`.
pub fn reference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    pipe::with_handle(args.this(), stream_base::reference);
}

/// `HandleWrap::Unref`.
pub fn unreference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    pipe::with_handle(args.this(), stream_base::unreference);
}

/// `HandleWrap::HasRef`.
pub fn has_reference(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let referenced = pipe::with_handle(args.this(), stream_base::has_reference).unwrap_or(false);
    rv.set(v8::Boolean::new(scope, referenced).into());
}

/// `AsyncWrap::GetAsyncId`; see the `tcp_wrap` copy for why `net` needs it.
pub fn get_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = pipe::with_handle(args.this(), |handle| handle.state.async_id).unwrap_or(0);
    rv.set(v8::Number::new(scope, id as f64).into());
}

/// `StreamBase::ReadStartJS`.
pub fn read_start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = pipe::with_handle(args.this(), stream_base::read_start).unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::ReadStopJS`.
pub fn read_stop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = pipe::with_handle(args.this(), stream_base::read_stop).unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::Shutdown`.
pub fn shutdown(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let status = pipe::with_handle(object, |handle| {
        stream_base::shutdown(scope, handle, request, object)
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::WriteBuffer`.
pub fn write_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    let request = v8::Local::<v8::Object>::try_from(args.get(0)).ok();
    let result = pipe::with_handle(object, |handle| {
        stream_base::write_buffer(scope, handle, request, args.get(1), object)
    });
    match result {
        Some(result) => result.apply(scope, &mut rv),
        None => rv.set(v8::Integer::new(scope, EBADF).into()),
    }
}

/// `StreamBase::Writev`.
pub fn writev<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    let request = v8::Local::<v8::Object>::try_from(args.get(0)).ok();
    let Ok(chunks) = v8::Local::<v8::Array>::try_from(args.get(1)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let all_buffers = args.get(2).is_true();
    let result = pipe::with_handle(object, |handle| {
        stream_base::writev(scope, handle, request, chunks, all_buffers, object)
    });
    match result {
        Some(result) => result.apply(scope, &mut rv),
        None => rv.set(v8::Integer::new(scope, EBADF).into()),
    }
}

/// `writeUtf8String`.
pub fn write_utf8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    write_string(scope, &args, &mut rv, Encoding::Utf8);
}

/// `writeAsciiString`.
pub fn write_ascii<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    write_string(scope, &args, &mut rv, Encoding::Ascii);
}

/// `writeLatin1String`.
pub fn write_latin1<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    write_string(scope, &args, &mut rv, Encoding::Binary);
}

/// `writeUcs2String`.
pub fn write_ucs2<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    write_string(scope, &args, &mut rv, Encoding::Ucs2);
}

fn write_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    rv: &mut v8::ReturnValue<'s>,
    encoding: rn_core::Encoding,
) {
    let object = args.this();
    let request = v8::Local::<v8::Object>::try_from(args.get(0)).ok();
    let Ok(text) = v8::Local::<v8::String>::try_from(args.get(1)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let result = pipe::with_handle(object, |handle| {
        stream_base::write_string(scope, handle, request, text, encoding, object)
    });
    match result {
        Some(result) => result.apply(scope, rv),
        None => rv.set(v8::Integer::new(scope, EBADF).into()),
    }
}

/// `LibuvStreamWrap::GetFD`.
pub fn get_fd(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let fd = pipe::with_handle(args.this(), stream_base::file_descriptor).unwrap_or(-1);
    rv.set(v8::Integer::new(scope, fd).into());
}

/// `StreamBase::GetBytesRead`.
pub fn get_bytes_read(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = pipe::with_handle(args.this(), |handle| handle.bytes_read()).unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `StreamBase::GetBytesWritten`.
pub fn get_bytes_written(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = pipe::with_handle(args.this(), |handle| handle.bytes_written()).unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `LibuvStreamWrap::GetWriteQueueSize`.
pub fn get_write_queue_size(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let size = pipe::with_handle(args.this(), stream_base::write_queue_size).unwrap_or(0);
    rv.set(v8::Integer::new_from_unsigned(scope, size).into());
}

/// `PipeWrap::Bind`: `bind(path)`.
///
/// Uses `uv_pipe_bind2` with `UV_PIPE_NO_TRUNCATE`, as Node does, so a path too
/// long for the platform is an error rather than a silently shortened socket.
pub fn bind(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(path) = arg_string(scope, &args, 0) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    // A path may legitimately start with `\0` (the Linux abstract namespace), so
    // this must not go through `CString`: the length is passed explicitly.
    let bytes = path.as_bytes();

    let status = pipe::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live, `bytes` outlives the call, and the length
        // is exactly its length.
        unsafe {
            uv::uv_pipe_bind2(
                handle.pipe.as_mut(),
                bytes.as_ptr().cast(),
                bytes.len(),
                uv::UV_PIPE_NO_TRUNCATE,
            )
        }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `PipeWrap::Listen`.
pub fn listen(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let backlog = arg_i32(scope, &args, 0);
    let status = pipe::with_handle(object, |handle| {
        if !handle.state.is_alive() {
            return EINVAL;
        }
        handle.state.owner_object = Some(v8::Global::new(scope.as_ref(), object));
        // SAFETY: the stream is live; `on_connection` reads the owner through
        // `data`.
        unsafe { uv::uv_listen(handle.stream(), backlog, Some(on_connection)) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// libuv's connection callback for a listening pipe.
///
/// # Safety
///
/// Called by libuv with the listening stream.
unsafe extern "C" fn on_connection(server: *mut uv::uv_stream_t, status: i32) {
    // SAFETY: the server's `data` is its owner pointer.
    let Some(state) = (unsafe { handle::owner(server) }) else {
        return;
    };
    // SAFETY: the owner pointer is live while the handle is.
    let state = unsafe { &*state };

    if status != 0 {
        rn_uv::callback::with_context(|scope| {
            call_onconnection(scope, state, status, None);
        });
        return;
    }

    let Some(client) = PipeHandle::new(crate::SOCKET) else {
        return;
    };
    let client = Box::into_raw(client);
    // SAFETY: the client's stream is live and its state was installed by
    // `PipeHandle::new`.
    let accepted = unsafe { uv::uv_accept(server, (*client).stream()) };
    if accepted != 0 {
        // SAFETY: libuv never took the handle, so the box is still ours.
        drop(unsafe { Box::from_raw(client) });
        return;
    }
    // SAFETY: the box was just created and libuv is done with it.
    pipe::park_accept(unsafe { Box::from_raw(client) });

    rn_uv::callback::with_context(|scope| {
        let Some(object) = pipe::instantiate(scope) else {
            if let Some(orphan) = pipe::take_pending_accept() {
                // SAFETY: the orphan is a handle nothing adopted.
                unsafe {
                    uv::uv_close(handle::as_handle(orphan.stream()), None);
                    drop(Box::from_raw(Box::into_raw(orphan)));
                }
            }
            return;
        };
        call_onconnection(scope, state, 0, Some(object));
    });
}

/// Calls `server.onconnection(status, handle)`, `this` being the server.
fn call_onconnection(
    scope: &mut v8::PinScope<'_, '_>,
    state: &rn_uv::handle::StreamState,
    status: i32,
    client: Option<v8::Local<v8::Object>>,
) {
    let Some(object) = state
        .owner_object
        .as_ref()
        .map(|object| v8::Local::new(scope, object))
    else {
        return;
    };
    let Some(key) = v8::String::new(scope, "onconnection") else {
        return;
    };
    let Some(value) = object.get(scope, key.into()) else {
        return;
    };
    let Ok(callback) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };
    let status_value: v8::Local<v8::Value> = v8::Integer::new(scope, status).into();
    let handle_value: v8::Local<v8::Value> = match client {
        Some(client) => client.into(),
        None => v8::undefined(scope).into(),
    };
    let receiver: v8::Local<v8::Value> = object.into();
    let _ = callback.call(&*scope, receiver, &[status_value, handle_value]);
}

/// `PipeWrap::Connect`: `connect(req, path)`.
pub fn connect(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let Some(path) = arg_string(scope, &args, 1) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };

    let status = pipe::with_handle(object, |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        connect::dispatch(scope, handle, &request, object, &path)
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `PipeWrap::Open`: adopt an existing descriptor.
pub fn open(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(fd) = args.get(0).integer_value(scope) else {
        return;
    };
    let status = pipe::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and `fd` is the caller's descriptor.
        unsafe { uv::uv_pipe_open(handle.pipe.as_mut(), fd as uv::uv_file) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `PipeWrap::Fchmod`: change the socket file's permissions.
pub fn fchmod(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(mode) = args.get(0).int32_value(scope) else {
        return;
    };
    let status = pipe::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live.
        unsafe { uv::uv_pipe_chmod(handle.pipe.as_mut(), mode) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// Reads argument `index` as an `i32`, falling back to `0`.
fn arg_i32(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> i32 {
    args.get(index).int32_value(scope).unwrap_or(0)
}

/// Reads argument `index` as a Rust string, if it is a string.
fn arg_string(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<String> {
    args.get(index)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
}
