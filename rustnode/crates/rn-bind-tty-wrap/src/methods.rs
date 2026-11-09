//! The methods on the `TTY` prototype.
//!
//! The `StreamBase` half — `readStart`, `readStop`, `shutdown`, the write forms,
//! `close`/`ref`/`unref`/`hasRef` and the counters — is implemented once in
//! [`rn_uv::stream_base`] and driven through [`StreamHandle`], exactly as
//! `tcp_wrap` and `pipe_wrap` do. What is left here is what only a terminal does:
//! the window size, raw mode, and `isTTY`.
//!
//! The return convention is `lib/tty.js`'s: **`0` for success, a negative libuv
//! error for failure**, with `getWindowSize` filling the caller's array on
//! success.

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_core::Encoding;
use rn_uv::handle::{self, HandleState};
use rn_uv::stream_base::{self, StreamHandle, EBADF, EINVAL};

use crate::handle::{self as tty, TtyHandle};

impl StreamHandle for TtyHandle {
    fn stream_state(&mut self) -> &mut rn_uv::handle::StreamState {
        &mut self.state
    }

    fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

/// `TTYWrap::IsTTY` — whether a descriptor is a terminal.
///
/// `lib/tty.js` exposes this as `tty.isatty(fd)`, and `lib/internal/tty.js` uses
/// it for a stdio's colour depth.
pub fn is_tty(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(fd) = args.get(0).int32_value(scope) else {
        return;
    };
    if fd < 0 {
        // `CHECK_GE(fd, 0)`.
        crate::throw_type_error(scope, "isTTY requires a non-negative descriptor");
        return;
    }
    // SAFETY: `uv_guess_handle` only inspects the descriptor.
    let kind = unsafe { uv::uv_guess_handle(fd) };
    rv.set(v8::Boolean::new(scope, kind == uv::uv_handle_type_UV_TTY).into());
}

/// `AsyncWrap::GetAsyncId`; see the `tcp_wrap` copy for why `net` needs it.
pub fn get_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = tty::with_handle(args.this(), |handle| handle.state.async_id).unwrap_or(0);
    rv.set(v8::Number::new(scope, id as f64).into());
}

/// `TTYWrap::GetWindowSize` — `getWindowSize([width, height])`.
pub fn get_window_size(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Ok(out) = v8::Local::<v8::Array>::try_from(args.get(0)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };

    let status = tty::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        let mut width: i32 = 0;
        let mut height: i32 = 0;
        // SAFETY: the handle is live and both out-parameters are live `i32`s.
        let status = unsafe { uv::uv_tty_get_winsize(handle.raw(), &mut width, &mut height) };
        if status == 0 {
            out.set_index(scope, 0, v8::Integer::new(scope, width).into());
            out.set_index(scope, 1, v8::Integer::new(scope, height).into());
        }
        status
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `TTYWrap::SetRawMode` — `setRawMode(mode)`.
pub fn set_raw_mode(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(mode) = args.get(0).int32_value(scope) else {
        return;
    };
    let status = tty::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and `mode` is one of the `UV_TTY_MODE_*`
        // values `lib/tty.js` supplies.
        unsafe { uv::uv_tty_set_mode(handle.raw(), mode as uv::uv_tty_mode_t) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `LibuvStreamWrap::SetBlocking`.
///
/// `lib/net.js` calls it only for a Windows stdio descriptor; reporting success
/// on a platform where libuv has no blocking mode to set is what Node does, since
/// its own implementation is a no-op off Windows.
pub fn set_blocking(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let _ = args.get(0);
    let status = tty::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        #[cfg(windows)]
        {
            // SAFETY: the handle is live.
            unsafe { uv::uv_stream_set_blocking(handle.stream(), i32::from(args.get(0).is_true())) }
        }
        #[cfg(not(windows))]
        {
            0
        }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `HandleWrap::Close`.
pub fn close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    tty::with_handle(object, |handle| {
        stream_base::close(scope, handle, object, args.get(0), Some(after_close));
    });
}

/// libuv's close completion: calls `handle.onclose()` and marks the handle closed.
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
    let owner = state.owner_object.clone();

    rn_uv::callback::with_context(|scope| {
        let Some(object) = owner.as_ref().map(|object| v8::Local::new(scope, object)) else {
            return;
        };
        stream_base::call_onclose(scope, object);
    });

    // `HandleWrap::OnClose` drops the wrap's reference once `onclose` has run, so
    // the wrapper can become garbage and the finalizer can free the box.
    state.owner_object = None;
}

/// The close completion used when the *wrapper* died while the tty was open.
///
/// Nothing is waiting for `onclose`, so this only marks the state closed and frees
/// the allocation. The free has to happen here rather than in the finalizer,
/// because libuv reads `handle->data` up to and including this callback.
///
/// # Safety
///
/// Called by libuv with a handle whose `data` is the `StreamState` inside a
/// [`TtyHandle`], and only from the finalizer's own `uv_close`.
pub unsafe extern "C" fn finalize_handle(handle_pointer: *mut uv::uv_handle_t) {
    // SAFETY: as in `after_close`.
    let Some(state) = (unsafe { handle::owner(handle_pointer.cast::<uv::uv_stream_t>()) }) else {
        return;
    };
    // SAFETY: the state lives inside a `TtyHandle` box the finalizer kept alive so
    // this callback could read it.
    let state = unsafe { &mut *state };
    state.state = HandleState::Closed;
    // SAFETY: `state` is the `state` field of a live `TtyHandle`, so subtracting
    // the field's offset recovers the allocation.
    let owner = unsafe {
        (state as *mut rn_uv::handle::StreamState)
            .cast::<u8>()
            .sub(std::mem::offset_of!(TtyHandle, state))
            .cast::<TtyHandle>()
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
    tty::with_handle(args.this(), stream_base::reference);
}

/// `HandleWrap::Unref`.
pub fn unreference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    tty::with_handle(args.this(), stream_base::unreference);
}

/// `HandleWrap::HasRef`.
pub fn has_reference(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let referenced = tty::with_handle(args.this(), stream_base::has_reference).unwrap_or(false);
    rv.set(v8::Boolean::new(scope, referenced).into());
}

/// `StreamBase::ReadStartJS`.
pub fn read_start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = tty::with_handle(args.this(), stream_base::read_start).unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::ReadStopJS`.
pub fn read_stop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = tty::with_handle(args.this(), stream_base::read_stop).unwrap_or(EBADF);
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
    let status = tty::with_handle(object, |handle| {
        stream_base::shutdown(scope, handle, request, object)
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::WriteBuffer`: `writeBuffer(req, buffer)`.
pub fn write_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    let request = v8::Local::<v8::Object>::try_from(args.get(0)).ok();
    let result = tty::with_handle(object, |handle| {
        stream_base::write_buffer(scope, handle, request, args.get(1), object)
    });
    match result {
        Some(result) => result.apply(scope, &mut rv),
        None => rv.set(v8::Integer::new(scope, EBADF).into()),
    }
}

/// `StreamBase::Writev`: `writev(req, chunks, allBuffers)`.
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
    let result = tty::with_handle(object, |handle| {
        stream_base::writev(scope, handle, request, chunks, all_buffers, object)
    });
    match result {
        Some(result) => result.apply(scope, &mut rv),
        None => rv.set(v8::Integer::new(scope, EBADF).into()),
    }
}

/// `StreamBase::WriteString<UTF8>`: `writeUtf8String(req, string)`.
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

/// The shared body of the four `write*String` methods.
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
    let result = tty::with_handle(object, |handle| {
        stream_base::write_string(scope, handle, request, text, encoding, object)
    });
    match result {
        Some(result) => result.apply(scope, rv),
        None => rv.set(v8::Integer::new(scope, EBADF).into()),
    }
}

/// `LibuvStreamWrap::GetFD` — the `fd` accessor.
pub fn get_fd(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `TTYWrap` records the descriptor it was constructed with, because
    // `uv_fileno` on a tty reports the descriptor libuv wrapped, which is not
    // always the one the caller passed.
    let fd = tty::with_handle(args.this(), |handle| handle.fd).unwrap_or(-1);
    rv.set(v8::Integer::new(scope, fd).into());
}

/// `StreamBase::GetBytesRead`.
pub fn get_bytes_read(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = tty::with_handle(args.this(), |handle| handle.bytes_read).unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `StreamBase::GetBytesWritten`.
pub fn get_bytes_written(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = tty::with_handle(args.this(), |handle| handle.bytes_written).unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `LibuvStreamWrap::GetWriteQueueSize`.
pub fn get_write_queue_size(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let size = tty::with_handle(args.this(), stream_base::write_queue_size).unwrap_or(0);
    rv.set(v8::Integer::new_from_unsigned(scope, size).into());
}
