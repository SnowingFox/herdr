//! `SendWrap` and the send path.
//!
//! `SendWrap` is `AsyncWrap::MakeLazilyInitializedJSTemplate(env)`: a plain
//! constructor with one internal field and no prototype methods. `lib/dgram.js`
//! builds one per `socket.send()`, assigns `list` (which keeps the chunks alive),
//! `address`, `port` and — when the caller passed a callback — `callback` and
//! `oncomplete`, and then passes it to `handle.send(...)`.
//!
//! # The two completion shapes
//!
//! `src/udp_wrap.cc`'s `Send` tries `uv_udp_try_send` first:
//!
//! * If it took the whole message, the send completed *inline* and the native
//!   return is `msg_size + 1`. `lib/dgram.js` checks `err >= 1`, subtracts the
//!   one and calls the callback on `process.nextTick`, so no request object is
//!   ever completed and `oncomplete` must **not** fire.
//! * If it would block (`UV_EAGAIN`) or the platform has no `try_send`
//!   (`UV_ENOSYS`), a `uv_udp_send` is queued and the return is `0`. The
//!   completion then calls `req.oncomplete(status, msg_size)`.
//!
//! The `+ 1` is not cosmetic: a zero-length datagram that went out inline is
//! indistinguishable from a queued one without it, and `lib/dgram.js` would
//! report the wrong send time to its callback.

use std::ffi::c_void;
use std::ptr;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use crate::EBADF;
use crate::EINVAL;

/// `AsyncWrap::MakeLazilyInitializedJSTemplate`'s shape: one internal field, no
/// methods.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(new).length(0).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let Some(name) = v8::String::new(scope, "SendWrap") else {
        return Err("cannot allocate the SendWrap class name".to_string());
    };
    template.set_class_name(name);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate SendWrap")?;
    function.set_name(name);
    Ok(function.into())
}

/// The `SendWrap` constructor callback.
///
/// There is no constructor body beyond `AsyncWrap`'s bookkeeping, and
/// `lib/dgram.js` only ever writes properties onto the result, so there is
/// nothing to do here.
fn new(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    rv.set(object.into());
}

/// `UDPWrap::DoSend`, for IPv4 (`family == 4`) or IPv6.
///
/// The two accepted shapes are
/// `send(req, chunks, count, port, address, hasCallback)` and
/// `send(req, chunks, count, hasCallback)`; `lib/internal/dgram.js` replaces
/// `handle.send` with `handle.send6` for a `udp6` socket, so which one arrives is
/// decided by the family here rather than by argument count alone.
pub fn dispatch(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue<'_>,
    family: u8,
) {
    // `DoSend` checks the scope directly after the unwrap and before any of its
    // `CHECK`s, so a denied send reports the denial rather than a status for a
    // malformed argument list.
    if crate::methods::deny_net(scope, rv, "", true) {
        return;
    }
    let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let Ok(chunks) = v8::Local::<v8::Array>::try_from(args.get(1)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let Some(count) = args.get(2).uint32_value(scope) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };

    let sendto = args.length() == 6;
    let (port, address, has_callback) = if sendto {
        let port = args.get(3).uint32_value(scope).unwrap_or(0) as u16;
        let Some(address) = crate::arg_string(scope, args, 4) else {
            rv.set(v8::Integer::new(scope, EINVAL).into());
            return;
        };
        (port, Some(address), args.get(5).is_true())
    } else {
        (0, None, args.get(3).is_true())
    };

    // Build the `uv_buf_t` array before anything touches libuv, so a malformed
    // chunk is a status rather than a half-issued send.
    let mut buffers = Vec::with_capacity(count as usize);
    let mut message_size = 0usize;
    for index in 0..count {
        let Some(chunk) = chunks.get_index(scope, index) else {
            rv.set(v8::Integer::new(scope, EINVAL).into());
            return;
        };
        // SAFETY: `lib/dgram.js` keeps every chunk alive on `req.list` until the
        // completion fires, which is the same lifetime Node relies on.
        let Some(buffer) = (unsafe { crate::methods::view_buffer(chunk) }) else {
            rv.set(v8::Integer::new(scope, EINVAL).into());
            return;
        };
        message_size += buffer.len;
        buffers.push(buffer);
    }

    // The destination, when this is a `sendto`.
    // SAFETY: `sockaddr_storage` is plain C data, so the all-zero bit pattern is
    // a valid value.
    let mut storage: uv::sockaddr_storage = unsafe { std::mem::zeroed() };
    if let Some(address) = address {
        let status = crate::sockaddr_for_family(family, &address, port, &mut storage);
        if status != 0 {
            rv.set(v8::Integer::new(scope, status).into());
            return;
        }
    }
    let destination: *const uv::sockaddr = if sendto {
        ptr::from_ref(&storage).cast()
    } else {
        ptr::null()
    };

    let outcome = crate::handle::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return Err(EBADF);
        }
        send(
            scope,
            handle,
            &mut buffers,
            message_size,
            destination,
            has_callback,
            &request,
        )
    });

    match outcome {
        Some(Ok(status)) => rv.set(v8::Integer::new(scope, status).into()),
        Some(Err(status)) => rv.set(v8::Integer::new(scope, status).into()),
        None => rv.set(v8::Integer::new(scope, EBADF).into()),
    }
}

/// The tail of `UDPWrap::Send`.
///
/// Returns `msg_size + 1` when libuv took the whole message inline, `0` when a
/// completion is queued, or a negative status when nothing was sent.
fn send(
    scope: &mut v8::PinScope<'_, '_>,
    handle: &mut crate::handle::UdpHandle,
    buffers: &mut [uv::uv_buf_t],
    message_size: usize,
    destination: *const uv::sockaddr,
    have_callback: bool,
    request: &v8::Local<v8::Object>,
) -> Result<i32, i32> {
    // `uv_udp_try_send` takes the buffers by pointer and does not copy them, so
    // the slice has to be the one libuv walks.
    let try_result = {
        // SAFETY: the handle is live, `buffers` holds as many valid descriptors
        // as it says, and `destination` points at a parsed address or is null.
        unsafe {
            uv::uv_udp_try_send(
                handle.raw(),
                buffers.as_mut_ptr(),
                buffers.len() as u32,
                destination,
            )
        }
    };

    if try_result == uv::uv_errno_t_UV_ENOSYS || try_result == uv::uv_errno_t_UV_EAGAIN {
        // Nothing was written: fall through to the queued send.
    } else if try_result >= 0 {
        // Everything (or a prefix) went out inline. A prefix cannot be completed
        // here without another send, and every datagram either fits the socket
        // buffer or reports `UV_EAGAIN`, so the check `src/udp_wrap.cc` makes is
        // that the whole message went out.
        let sent = try_result as usize;
        if sent >= message_size {
            // The `+ 1` tells `lib/dgram.js` this was a synchronous completion.
            return Ok(message_size as i32 + 1);
        }
    } else {
        return Err(try_result);
    }

    let completion = Box::new(SendCompletion {
        request: v8::Global::new(scope.as_ref(), *request),
        handle: handle
            .owner_object
            .as_ref()
            .map(|object| v8::Global::new(scope.as_ref(), v8::Local::new(scope, object))),
        message_size,
        have_callback,
        buffers: buffers.to_vec(),
    });
    let completion = Box::into_raw(completion);

    let storage = Box::into_raw(Box::new(
        std::mem::MaybeUninit::<uv::uv_udp_send_t>::zeroed(),
    ));
    // SAFETY: `storage` is a live, aligned, zeroed `uv_udp_send_t`.
    let request_pointer = unsafe { (*storage).as_mut_ptr() };
    // SAFETY: `request_pointer` is live and `data` is the slot libuv hands back.
    unsafe {
        (*request_pointer).data = completion.cast::<c_void>();
    }

    // SAFETY: the handle is live, the buffers stay valid until the completion
    // because `completion` owns a copy of the descriptors and the caller owns the
    // bytes, and `destination` outlives the call.
    let status = unsafe {
        uv::uv_udp_send(
            request_pointer,
            handle.raw(),
            buffers.as_ptr(),
            buffers.len() as u32,
            destination,
            Some(after_send),
        )
    };

    if status != 0 {
        // Nothing was queued, so libuv will never call back and both allocations
        // are still ours to release.
        // SAFETY: both pointers came from `Box::into_raw` above and libuv did not
        // take ownership because `uv_udp_send` failed.
        unsafe {
            drop(Box::from_raw(storage));
            drop(Box::from_raw(completion));
        }
        return Err(status);
    }

    Ok(0)
}

/// State a queued send carries to its completion.
struct SendCompletion {
    request: v8::Global<v8::Object>,
    handle: Option<v8::Global<v8::Object>>,
    message_size: usize,
    have_callback: bool,
    /// A copy of the descriptors libuv walks, kept so the field they point into
    /// does not go out of scope before a `UV_EAGAIN` retry in libuv itself. The
    /// bytes behind them belong to JavaScript and are held by `req.list`.
    #[allow(dead_code)]
    buffers: Vec<uv::uv_buf_t>,
}

/// libuv's send completion: `req.oncomplete(status, msg_size)`.
///
/// # Safety
///
/// Called by libuv with the `uv_udp_send_t` [`send`] allocated.
unsafe extern "C" fn after_send(request: *mut uv::uv_udp_send_t, status: i32) {
    if request.is_null() {
        return;
    }
    // SAFETY: `send` stored this pointer in `data` and libuv hands the same
    // request back exactly once.
    let completion = unsafe { (*request).data.cast::<SendCompletion>() };
    // SAFETY: the request came from `Box<MaybeUninit<uv_udp_send_t>>` in `send`,
    // and libuv is finished with it.
    drop(unsafe { Box::from_raw(request.cast::<std::mem::MaybeUninit<uv::uv_udp_send_t>>()) });

    if completion.is_null() {
        return;
    }
    // SAFETY: `completion` came from `Box::into_raw` in `send` and is reclaimed
    // exactly here.
    let completion = unsafe { Box::from_raw(completion) };

    // `src/udp_wrap.cc`'s `OnSendDone` only calls back when the request had a
    // callback; a socket whose send was fire-and-forget has nothing to report,
    // and a failed send is surfaced only through the `'error'` event that
    // `lib/dgram.js` raises for a returned status.
    if !completion.have_callback {
        return;
    }

    rn_uv::callback::with_context(|scope| {
        let request: v8::Local<v8::Object> = v8::Local::new(scope, &completion.request);
        let Some(key) = v8::String::new(scope, "oncomplete") else {
            return;
        };
        let Some(value) = request.get(scope, key.into()) else {
            return;
        };
        let Ok(callback) = v8::Local::<v8::Function>::try_from(value) else {
            return;
        };
        let status_value: v8::Local<v8::Value> = v8::Integer::new(scope, status).into();
        let size_value: v8::Local<v8::Value> =
            v8::Integer::new_from_unsigned(scope, completion.message_size as u32).into();
        let receiver: v8::Local<v8::Value> = request.into();
        let _ = callback.call(scope, receiver, &[status_value, size_value]);
        let _ = &completion.handle;
    });
}
