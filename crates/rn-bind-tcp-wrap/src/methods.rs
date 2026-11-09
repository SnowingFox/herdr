//! The methods on the `TCP` prototype.
//!
//! The `StreamBase` half — `readStart`, `readStop`, `shutdown`, the write forms,
//! `close`/`ref`/`unref`/`hasRef` and the counters — is implemented once in
//! [`rn_uv::stream_base`] and driven through [`StreamHandle`], because
//! `src/stream_base.cc` installs it on the prototype `TCP` and `Pipe` both
//! inherit. What is left here is what only a TCP socket does: `bind`, `listen`,
//! `connect`, the socket options, and the address objects.
//!
//! The return convention is the one `lib/net.js` checks: **`0` for success, a
//! negative libuv error for failure**, with `shutdown()` additionally able to
//! report a synchronous completion.

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::addr;
use rn_uv::handle::{self, HandleState};
use rn_uv::stream_base::{self, StreamHandle, EBADF, EINVAL};

use crate::connect;
use crate::handle::{self as tcp, TcpHandle};

impl StreamHandle for TcpHandle {
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
    tcp::with_handle(object, |handle| {
        stream_base::close(scope, handle, object, args.get(0), Some(after_close));
    });
}

/// libuv's close completion: calls `handle.onclose()` and marks the handle closed.
///
/// # Safety
///
/// Called by libuv with a handle this crate initialised.
pub unsafe extern "C" fn after_close(handle_pointer: *mut uv::uv_handle_t) {
    // SAFETY: the handle's `data` is the `*mut StreamState` the constructor
    // stored, still valid because the wrapper outlives the close.
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

/// The close completion used when the *wrapper* died while the socket was open.
///
/// Nothing is waiting for `onclose` — the object it would read from is gone — so
/// this only marks the state closed and frees the allocation. The free has to
/// happen here rather than in the finalizer, because libuv reads `handle->data`
/// up to and including this callback.
///
/// # Safety
///
/// Called by libuv with a handle whose `data` is the `StreamState` inside a
/// [`TcpHandle`], and only from the finalizer's own `uv_close`.
pub unsafe extern "C" fn finalize_handle(handle_pointer: *mut uv::uv_handle_t) {
    // SAFETY: as in `after_close`.
    let Some(state) = (unsafe { handle::owner(handle_pointer.cast::<uv::uv_stream_t>()) }) else {
        return;
    };
    // SAFETY: the state lives inside a `TcpHandle` box the finalizer kept alive
    // so this callback could read it.
    let state = unsafe { &mut *state };
    state.state = HandleState::Closed;
    // SAFETY: `state` is the `state` field of a live `TcpHandle`, so subtracting
    // the field's offset recovers the allocation.
    let owner = unsafe {
        (state as *mut rn_uv::handle::StreamState)
            .cast::<u8>()
            .sub(std::mem::offset_of!(TcpHandle, state))
            .cast::<TcpHandle>()
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
    tcp::with_handle(args.this(), stream_base::reference);
}

/// `HandleWrap::Unref`.
pub fn unreference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    tcp::with_handle(args.this(), stream_base::unreference);
}

/// `HandleWrap::HasRef`.
pub fn has_reference(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let referenced = tcp::with_handle(args.this(), stream_base::has_reference).unwrap_or(false);
    rv.set(v8::Boolean::new(scope, referenced).into());
}

/// `AsyncWrap::GetAsyncId`.
///
/// `lib/net.js` reads this on both the connect path (`Socket.prototype.connect`)
/// and the server path (`listen`), and stores it as the socket's
/// `async_id_symbol`. Node falls back to `newAsyncId()` only in
/// `getNewAsyncId`, which is used when a handle is not wrapped; the direct calls
/// have no fallback, so a handle without this method throws
/// `this._handle.getAsyncId is not a function` from inside `net`.
///
/// The id comes from the state's own allocation, not a fresh value on every
/// call: an async id identifies the *resource*, so two calls must agree.
pub fn get_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = tcp::with_handle(args.this(), |handle| handle.state.async_id).unwrap_or(0);
    rv.set(v8::Number::new(scope, id as f64).into());
}

/// `StreamBase::ReadStartJS`.
pub fn read_start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = tcp::with_handle(args.this(), stream_base::read_start).unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::ReadStopJS`.
pub fn read_stop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = tcp::with_handle(args.this(), stream_base::read_stop).unwrap_or(EBADF);
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
        // `StreamBase::Shutdown` `CHECK(args[0]->IsObject())`.
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let status = tcp::with_handle(object, |handle| {
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
    let result = tcp::with_handle(object, |handle| {
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
    let result = tcp::with_handle(object, |handle| {
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
    write_string(scope, &args, &mut rv);
}

/// `writeAsciiString`.
pub fn write_ascii<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    write_string(scope, &args, &mut rv);
}

/// `writeLatin1String`.
pub fn write_latin1<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    write_string(scope, &args, &mut rv);
}

/// `writeUcs2String`.
pub fn write_ucs2<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    write_string(scope, &args, &mut rv);
}

/// The shared body of the four `write*String` methods.
fn write_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    rv: &mut v8::ReturnValue<'s>,
) {
    let object = args.this();
    let request = v8::Local::<v8::Object>::try_from(args.get(0)).ok();
    let Ok(text) = v8::Local::<v8::String>::try_from(args.get(1)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let result = tcp::with_handle(object, |handle| {
        stream_base::write_string(scope, handle, request, text, object)
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
    let fd = tcp::with_handle(args.this(), stream_base::file_descriptor).unwrap_or(-1);
    rv.set(v8::Integer::new(scope, fd).into());
}

/// `StreamBase::GetBytesRead`.
pub fn get_bytes_read(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = tcp::with_handle(args.this(), |handle| handle.bytes_read()).unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `StreamBase::GetBytesWritten`.
pub fn get_bytes_written(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = tcp::with_handle(args.this(), |handle| handle.bytes_written()).unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `LibuvStreamWrap::GetWriteQueueSize`.
pub fn get_write_queue_size(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let size = tcp::with_handle(args.this(), stream_base::write_queue_size).unwrap_or(0);
    rv.set(v8::Integer::new_from_unsigned(scope, size).into());
}

/// `TCPWrap::Open`: adopt an existing descriptor.
pub fn open(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(fd) = args.get(0).integer_value(scope) else {
        return;
    };
    let status = tcp::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and `fd` is the caller's descriptor.
        unsafe { uv::uv_tcp_open(handle.tcp.as_mut(), fd as uv::uv_os_sock_t) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `TCPWrap::Bind`: `bind(address, port, flags?)`.
pub fn bind(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    bind_family(scope, &args, &mut rv, 4);
}

/// `TCPWrap::Bind6`.
pub fn bind6(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    bind_family(scope, &args, &mut rv, 6);
}

fn bind_family(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue<'_>,
    family: u8,
) {
    let Some(address) = tcp::arg_string(scope, args, 0) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let port = tcp::arg_i32(scope, args, 1) as u16;
    let mut flags = args.get(2).uint32_value(scope).unwrap_or(0);
    if family == 4 {
        // `src/tcp_wrap.cc`: "Can not set IPV6 flags on IPV4 socket".
        flags &= !uv::uv_tcp_flags_UV_TCP_IPV6ONLY;
    }

    let status = if family == 4 {
        addr::ip4(&address, port).map_or_else(
            |status| status,
            |sockaddr| bind_sockaddr(args.this(), std::ptr::from_ref(&sockaddr).cast(), flags),
        )
    } else {
        addr::ip6(&address, port).map_or_else(
            |status| status,
            |sockaddr| bind_sockaddr(args.this(), std::ptr::from_ref(&sockaddr).cast(), flags),
        )
    };
    rv.set(v8::Integer::new(scope, status).into());
}

/// The shared tail of `bind`/`bind6`.
fn bind_sockaddr(object: v8::Local<v8::Object>, sockaddr: *const uv::sockaddr, flags: u32) -> i32 {
    tcp::with_handle(object, |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and `sockaddr` points at a value the caller
        // keeps alive for this call.
        unsafe { uv::uv_tcp_bind(handle.tcp.as_mut(), sockaddr, flags) }
    })
    .unwrap_or(EBADF)
}

/// `TCPWrap::Listen`: `listen(backlog)`.
pub fn listen(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let backlog = tcp::arg_i32(scope, &args, 0);
    let status = tcp::with_handle(object, |handle| {
        if !handle.state.is_alive() {
            return EINVAL;
        }
        // The object is needed twice from native code: `onconnection` for an
        // accepted socket and `onclose` for the close callback.
        handle.state.owner_object = Some(v8::Global::new(scope.as_ref(), object));
        // SAFETY: the stream is live; `on_connection` reads the owner through
        // `data`.
        unsafe { uv::uv_listen(handle.stream(), backlog, Some(on_connection)) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// libuv's connection callback: accepts and calls `server.onconnection`.
///
/// `lib/net.js`'s `onconnection(status, clientHandle)` assigns `onread`,
/// `owner_symbol` and `reading` to the handle it receives and then starts
/// reading, so the object handed over has to be a fully initialised `TCP`.
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
        // A failed accept still reports through `onconnection`, with the status
        // and an `undefined` handle.
        rn_uv::callback::with_context(|scope| {
            call_onconnection(scope, state, status, None);
        });
        return;
    }

    let Some(client) = TcpHandle::new(crate::SOCKET) else {
        return;
    };
    let client = Box::into_raw(client);
    // SAFETY: the client's stream is live and its state was installed by
    // `TcpHandle::new`.
    let accepted = unsafe { uv::uv_accept(server, (*client).stream()) };
    if accepted != 0 {
        // SAFETY: libuv never took the handle, so the box is still ours.
        drop(unsafe { Box::from_raw(client) });
        return;
    }

    // SAFETY: the box was just created above and libuv is done with it; the
    // wrapper construction below adopts it.
    tcp::park_accept(unsafe { Box::from_raw(client) });

    rn_uv::callback::with_context(|scope| {
        let Some(object) = tcp::instantiate(scope) else {
            // The wrapper could not be built, so nothing will adopt the handle.
            // Close it rather than leaking the descriptor.
            if let Some(orphan) = tcp::take_pending_accept() {
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

/// `TCPWrap::Connect`: `connect(req, address, port)`.
pub fn connect(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    connect_family(scope, &args, &mut rv, 4);
}

/// `TCPWrap::Connect6`.
pub fn connect6(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    connect_family(scope, &args, &mut rv, 6);
}

fn connect_family(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue<'_>,
    family: u8,
) {
    let object = args.this();
    let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let Some(address) = tcp::arg_string(scope, args, 1) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let port = tcp::arg_i32(scope, args, 2) as u16;

    let status = tcp::with_handle(object, |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        connect::dispatch(scope, handle, &request, object, &address, port, family)
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `GetSockOrPeerName<TCPWrap, uv_tcp_getsockname>`.
pub fn getsockname(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    sock_or_peer_name(scope, &args, &mut rv, true);
}

/// `GetSockOrPeerName<TCPWrap, uv_tcp_getpeername>`.
pub fn getpeername(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    sock_or_peer_name(scope, &args, &mut rv, false);
}

/// Fills a caller-provided object with `{ address, family, port }`.
///
/// `lib/net.js` passes `this.#address` or `this._sockname` and then reads those
/// three properties, so the object is mutated in place rather than replaced —
/// which is what `AddressToJS` does when handed an existing object.
fn sock_or_peer_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue<'_>,
    local: bool,
) {
    let Ok(target) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };

    let mut storage = std::mem::MaybeUninit::<uv::sockaddr_storage>::zeroed();
    let mut length = std::mem::size_of::<uv::sockaddr_storage>() as i32;

    let status = tcp::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        // SAFETY: `storage` is large enough for any address libuv writes and
        // `length` is its size in bytes.
        unsafe {
            if local {
                uv::uv_tcp_getsockname(
                    handle.tcp.as_mut(),
                    storage.as_mut_ptr().cast(),
                    &mut length,
                )
            } else {
                uv::uv_tcp_getpeername(
                    handle.tcp.as_mut(),
                    storage.as_mut_ptr().cast(),
                    &mut length,
                )
            }
        }
    })
    .unwrap_or(EBADF);

    if status != 0 {
        rv.set(v8::Integer::new(scope, status).into());
        return;
    }

    // SAFETY: libuv filled the storage and returned success.
    let storage = unsafe { storage.assume_init() };
    // SAFETY: `sockaddr_storage` leads with the same family word `sockaddr` reads.
    let parsed =
        unsafe { addr::from_sockaddr(&*std::ptr::from_ref(&storage).cast::<uv::sockaddr>()) };
    let Some(parsed) = parsed else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };

    // `AddressToJS` sets these three, in this order.
    let (Some(address), Some(family)) = (
        v8::String::new(scope, &parsed.address),
        v8::String::new(scope, parsed.family),
    ) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let values: [(&str, v8::Local<v8::Value>); 3] = [
        ("address", address.into()),
        ("family", family.into()),
        (
            "port",
            v8::Number::new(scope, f64::from(parsed.port)).into(),
        ),
    ];
    for (name, value) in values {
        let Some(key) = v8::String::new(scope, name) else {
            rv.set(v8::Integer::new(scope, EINVAL).into());
            return;
        };
        target.set(scope, key.into(), value);
    }

    rv.set(v8::Integer::new(scope, 0).into());
}

/// `TCPWrap::SetNoDelay`.
pub fn set_no_delay(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `int enable = static_cast<int>(args[0]->IsTrue())`.
    let enable = i32::from(args.get(0).is_true());
    let status = tcp::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live.
        unsafe { uv::uv_tcp_nodelay(handle.tcp.as_mut(), enable) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `TCPWrap::SetKeepAlive`.
pub fn set_keep_alive(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(enable) = args.get(0).int32_value(scope) else {
        return;
    };
    let delay = args.get(1).uint32_value(scope).unwrap_or(0);
    let status = tcp::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live.
        unsafe { uv::uv_tcp_keepalive(handle.tcp.as_mut(), enable, delay) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `TCPWrap::SetTypeOfService`.
///
/// `src/tcp_wrap.cc` calls `setsockopt` directly because libuv has no
/// `uv_tcp_set_tos`; this chooses `IP_TOS` for an IPv4 socket and `IPV6_TCLASS`
/// for an IPv6 one, based on the handle's own local address, exactly as Node does.
pub fn set_type_of_service(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(tos) = args.get(0).int32_value(scope) else {
        return;
    };
    let status = tcp::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        let Ok((fd, level, option)) = socket_option_target(handle) else {
            return EINVAL;
        };
        // SAFETY: `fd` is the handle's live descriptor and `tos` is a live `i32`.
        let result = unsafe {
            setsockopt(
                fd,
                level,
                option,
                std::ptr::from_ref(&tos).cast(),
                std::mem::size_of::<i32>() as u32,
            )
        };
        if result == 0 {
            0
        } else {
            EINVAL
        }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `TCPWrap::GetTypeOfService`.
pub fn get_type_of_service(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = tcp::with_handle(args.this(), |handle| {
        if !handle.state.is_alive() {
            return EBADF;
        }
        let Ok((fd, level, option)) = socket_option_target(handle) else {
            return EINVAL;
        };
        let mut tos: i32 = 0;
        let mut length = std::mem::size_of::<i32>() as u32;
        // SAFETY: `fd` is live and `tos`/`length` describe it correctly.
        let result = unsafe {
            getsockopt(
                fd,
                level,
                option,
                std::ptr::from_mut(&mut tos).cast(),
                &mut length,
            )
        };
        if result == 0 {
            tos
        } else {
            EINVAL
        }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, value).into());
}

/// The `(fd, level, option)` a TOS `setsockopt`/`getsockopt` needs.
fn socket_option_target(handle: &mut TcpHandle) -> Result<(i32, i32, i32), i32> {
    let mut descriptor: uv::uv_os_fd_t = -1;
    // SAFETY: the handle is live.
    let status = unsafe { uv::uv_fileno(handle::as_handle(handle.state.stream), &mut descriptor) };
    if status != 0 {
        return Err(status);
    }

    let mut storage = std::mem::MaybeUninit::<uv::sockaddr_storage>::zeroed();
    let mut length = std::mem::size_of::<uv::sockaddr_storage>() as i32;
    // SAFETY: the storage is large enough for any address libuv writes.
    let status = unsafe {
        uv::uv_tcp_getsockname(
            handle.tcp.as_mut(),
            storage.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if status != 0 {
        return Err(status);
    }

    // SAFETY: libuv filled the storage.
    let storage = unsafe { storage.assume_init() };
    match i32::from(storage.ss_family) {
        AF_INET => Ok((descriptor, IPPROTO_IP, IP_TOS)),
        AF_INET6 => Ok((descriptor, IPPROTO_IPV6, IPV6_TCLASS)),
        // `src/tcp_wrap.cc` reports `UV_EINVAL` for an unsupported family.
        _ => Err(EINVAL),
    }
}

/// `AF_INET`, as a `sockaddr`'s `sa_family` reports it.
const AF_INET: i32 = uv::AF_INET as i32;
/// `AF_INET6`, as a `sockaddr`'s `sa_family` reports it.
const AF_INET6: i32 = uv::AF_INET6 as i32;
/// `IPPROTO_IP` from the C headers.
const IPPROTO_IP: i32 = 0;
/// `IP_TOS` from the C headers.
const IP_TOS: i32 = 1;
/// `IPPROTO_IPV6` from the C headers.
const IPPROTO_IPV6: i32 = 41;
/// `IPV6_TCLASS` from the C headers.
const IPV6_TCLASS: i32 = 67;

unsafe extern "C" {
    /// `setsockopt(2)`.
    fn setsockopt(
        socket: i32,
        level: i32,
        name: i32,
        value: *const std::ffi::c_void,
        length: u32,
    ) -> i32;

    /// `getsockopt(2)`.
    fn getsockopt(
        socket: i32,
        level: i32,
        name: i32,
        value: *mut std::ffi::c_void,
        length: *mut u32,
    ) -> i32;
}

/// `TCPWrap::Reset`: abort the connection with a reset rather than a FIN.
pub fn reset(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    if let Ok(function) = v8::Local::<v8::Function>::try_from(args.get(0)) {
        if let Some(key) = v8::String::new(scope, "onclose") {
            object.set(scope, key.into(), function.into());
        }
    }

    let status = tcp::with_handle(object, |handle| {
        if handle.state.state != HandleState::Initialized {
            return 0;
        }
        handle.state.state = HandleState::Closing;
        // SAFETY: the handle is live and not closing.
        unsafe { uv::uv_tcp_close_reset(handle.tcp.as_mut(), Some(after_close)) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}
