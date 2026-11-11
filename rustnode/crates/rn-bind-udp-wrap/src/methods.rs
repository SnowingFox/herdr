//! The methods on the `UDP` prototype.
//!
//! These mirror `src/udp_wrap.cc` one for one. Every method that touches the
//! kernel returns **`0` for success and a negative libuv error for failure**,
//! because that is what `lib/dgram.js` branches on: a non-zero return becomes an
//! `ErrnoException` or a `'error'` event, and `send()` additionally treats a
//! *positive* return as a completed synchronous send (see [`crate::send`]).
//!
//! # Receive
//!
//! `uv_udp_recv_cb` delivers one datagram at a time and has no `StreamBase`
//! behind it: there is no shared slab offset, no `readStart`/`readStop` pair and
//! no `streamBaseState`. The bytes are copied into a fresh `ArrayBuffer` and
//! handed to `handle.onmessage(nread, handle, buffer, address)` — the four
//! arguments `lib/dgram.js`'s `onMessage` reads — or, when the datagram came with
//! an address that will not parse, to `handle.onerror(nread, handle, error)`.

use std::ptr;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::handle::{Allocation, HandleState};

use crate::handle::{self as udp, UdpHandle};
use crate::send;
use crate::{EACCES, EBADF, EINVAL};

/// The `net` permission check a `UDPWrap` entry point makes.
///
/// `src/udp_wrap.cc` has three shapes and they differ in how they report:
///
/// * `DoBind` uses `ERR_ACCESS_DENIED_IF_INSUFFICIENT_PERMISSIONS`, so the error
///   object is the *return value* and `lib/dgram.js` wraps it in an
///   `ExceptionWithHostPort`;
/// * `DoConnect`, `Open` and `DoSend` use `THROW_IF_INSUFFICIENT_PERMISSIONS`
///   with `args.GetReturnValue().Set(UV_EACCES)` as the variadic tail, so the
///   error is thrown and `UV_EACCES` is what a caller that catches it sees
///   returned;
/// * `RecvStart` throws `UV_EACCES` too, but only once per handle, because a
///   socket that was already allowed to bind must not be re-checked on every
///   `recvStart`.
///
/// `resource` is the address for `bind` and empty everywhere else.
pub(crate) fn deny_net(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue<'_>,
    resource: &str,
    throw: bool,
) -> bool {
    match rn_permission::runtime::deny_net(resource) {
        Some(denied) if throw => {
            denied.throw(scope);
            rv.set(v8::Integer::new(scope, EACCES).into());
            true
        }
        Some(denied) => {
            rv.set(denied.to_value(scope));
            true
        }
        None => false,
    }
}

/// `HandleWrap::Close`.
pub fn close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    udp::with_handle(object, |handle| {
        // `HandleWrap::Close` returns silently for a handle that is not
        // initialised: closing twice would abort libuv.
        if handle.state != HandleState::Initialized {
            return;
        }
        if let Ok(function) = v8::Local::<v8::Function>::try_from(args.get(0)) {
            if let Some(key) = v8::String::new(scope, "onclose") {
                object.set(scope, key.into(), function.into());
            }
        }
        handle.state = HandleState::Closing;
        // SAFETY: the handle is live and not already closing.
        unsafe { uv::uv_close(crate::as_handle(handle.raw()), Some(after_close)) };
    });
}

/// libuv's close completion: calls `handle.onclose()` and marks the handle closed.
///
/// # Safety
///
/// Called by libuv with a handle this crate initialised.
pub unsafe extern "C" fn after_close(handle_pointer: *mut uv::uv_handle_t) {
    // SAFETY: the handle's `data` is the `*mut UdpHandle` the constructor stored.
    let Some(pointer) = (unsafe { crate::owner(handle_pointer.cast::<uv::uv_udp_t>()) }) else {
        return;
    };
    // SAFETY: the owner pointer is live until the wrapper is freed, and nothing
    // else frees it while the wrapper is rooted here.
    let handle = unsafe { &mut *pointer };
    handle.state = HandleState::Closed;
    // A receive that was in flight when the close started can leave its
    // allocation parked on the handle; `UdpHandle` owns it, so it is released
    // when the box is.

    rn_uv::callback::with_context(|scope| {
        let Some(object) = handle
            .owner_object
            .as_ref()
            .map(|object| v8::Local::new(scope, object))
        else {
            return;
        };
        // SAFETY: `handle` is the live state of this wrapper.
        rn_uv::stream_base::call_onclose(
            scope,
            rn_core::callback_scope::AsyncContext {
                async_id: handle.async_id,
                trigger_async_id: -1.0,
            },
            None,
            object,
        );
    });

    // `HandleWrap::OnClose` drops the wrap's reference to the object once
    // `onclose` has run, and the object's own collection is what frees the native
    // state. Releasing the root here is what lets that happen: while it is held,
    // the wrapper can never become garbage and the finalizer — the only thing that
    // frees the box — would never run.
    handle.owner_object = None;
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
/// Called by libuv with a handle whose `data` is the `*mut UdpHandle` inside a
/// box the finalizer kept alive, and only from the finalizer's own `uv_close`.
pub unsafe extern "C" fn finalize_handle(handle_pointer: *mut uv::uv_handle_t) {
    // SAFETY: as in `after_close`.
    let Some(pointer) = (unsafe { crate::owner(handle_pointer.cast::<uv::uv_udp_t>()) }) else {
        return;
    };
    // SAFETY: the finalizer handed the box over and nothing else frees it.
    let mut handle = unsafe { Box::from_raw(pointer) };
    handle.state = HandleState::Closed;
    // Dropping `handle` here is what releases the `uv_udp_t` and any parked
    // receive allocation.
    drop(handle);
}

/// `HandleWrap::Ref`.
pub fn reference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    udp::with_handle(args.this(), |handle| {
        if handle.is_alive() {
            // SAFETY: the handle is live.
            unsafe { uv::uv_ref(crate::as_handle(handle.raw())) };
        }
    });
}

/// `HandleWrap::Unref`.
pub fn unreference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    udp::with_handle(args.this(), |handle| {
        if handle.is_alive() {
            // SAFETY: the handle is live.
            unsafe { uv::uv_unref(crate::as_handle(handle.raw())) };
        }
    });
}

/// `HandleWrap::HasRef`: `IsAlive(wrap) && uv_has_ref(handle)`.
pub fn has_reference(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let referenced = udp::with_handle(args.this(), |handle| {
        handle.is_alive()
            // SAFETY: the handle is live.
            && unsafe { uv::uv_has_ref(crate::as_handle(handle.raw())) != 0 }
    })
    .unwrap_or(false);
    rv.set(v8::Boolean::new(scope, referenced).into());
}

/// `AsyncWrap::GetAsyncId`.
///
/// A receiver that is not a `UDP` reports `-1`, which is `kInvalidAsyncId`.
pub fn get_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = udp::with_handle(args.this(), |handle| handle.async_id).unwrap_or(-1.0);
    rv.set(v8::Number::new(scope, id).into());
}

/// `UDPWrap::GetFD` — the `fd` accessor, `-1` when there is none.
///
/// A `uv_udp_t` creates its descriptor lazily, so this reports `-1` until
/// `bind`/`connect`/`open` has run, which is what Node reports too.
pub fn get_fd(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `UDPWrap::GetFD` starts at `UV_EBADF` and keeps that value when
    // `uv_fileno` fails, so a non-`UDP` receiver reports `EBADF`. A `UDP` whose
    // descriptor libuv has not created yet reports `-1`, because `uv_fileno`
    // leaves `descriptor` untouched on failure and it starts there. The two cases
    // are therefore distinguishable by whether the receiver unwrapped at all,
    // which is how Node's `wrap != nullptr` guard behaves.
    let fd = udp::with_handle(args.this(), |handle| {
        let mut descriptor: uv::uv_os_fd_t = -1;
        // SAFETY: the handle is live.
        let _status = unsafe { uv::uv_fileno(crate::as_handle(handle.raw()), &mut descriptor) };
        descriptor
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, fd).into());
}

/// `UDPWrap::Open`: adopt an existing descriptor.
///
/// `UDPWrap::Open` throws and returns `UV_EACCES`, and unlike the stream handles
/// it has no standard-stream or IPC exemption: Node checks it unconditionally,
/// which is why `dgram.createSocket({ fd })` is denied even for fd 0-2 in
/// `test-permission-net-udp-handle.js`.
pub fn open(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(fd) = args.get(0).integer_value(scope) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    if deny_net(scope, &mut rv, "", true) {
        return;
    }
    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and `fd` is the caller's descriptor.
        let status = unsafe { uv::uv_udp_open(handle.raw(), fd as uv::uv_os_sock_t) };
        if status == 0 {
            handle.net_permission_granted = true;
        }
        status
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `UDPWrap::Bind`: `bind(address, port, flags)`.
pub fn bind(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    bind_family(scope, &args, &mut rv, 4);
}

/// `UDPWrap::Bind6`.
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
    let Some(address) = crate::arg_string(scope, args, 0) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    // `DoBind` checks after it has read the address and before it reads the port
    // and flags, and it names the address in the denial.
    if deny_net(scope, rv, &address, false) {
        return;
    }
    let port = args.get(1).uint32_value(scope).unwrap_or(0) as u16;
    let flags = args.get(2).uint32_value(scope).unwrap_or(0);

    // SAFETY: `sockaddr_storage` is plain C data — a family word, a byte array
    // and an aligned integer — so the all-zero bit pattern is a valid value.
    let mut storage: uv::sockaddr_storage = unsafe { std::mem::zeroed() };
    let parsed = crate::sockaddr_for_family(family, &address, port, &mut storage);
    if parsed != 0 {
        rv.set(v8::Integer::new(scope, parsed).into());
        return;
    }

    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and `storage` holds a parsed address that
        // outlives the call.
        let raw = handle.raw();

        let status =
            unsafe { uv::uv_udp_bind(raw, ptr::from_ref(&storage).cast::<uv::sockaddr>(), flags) };
        if status == 0 {
            handle.net_permission_granted = true;
        }
        status
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `UDPWrap::Connect`: `connect(address, port)`.
pub fn connect(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    connect_family(scope, &args, &mut rv, 4);
}

/// `UDPWrap::Connect6`.
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
    // `DoConnect` checks the permission before it reads either argument, because
    // it gates on the socket rather than on a resource.
    if deny_net(scope, rv, "", true) {
        return;
    }
    let Some(address) = crate::arg_string(scope, args, 0) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let port = args.get(1).uint32_value(scope).unwrap_or(0) as u16;

    // SAFETY: `sockaddr_storage` is plain C data, so the all-zero bit pattern is
    // a valid value.
    let mut storage: uv::sockaddr_storage = unsafe { std::mem::zeroed() };
    let parsed = crate::sockaddr_for_family(family, &address, port, &mut storage);
    if parsed != 0 {
        rv.set(v8::Integer::new(scope, parsed).into());
        return;
    }

    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and `storage` holds a parsed address.
        let status = unsafe {
            uv::uv_udp_connect(handle.raw(), ptr::from_ref(&storage).cast::<uv::sockaddr>())
        };
        if status == 0 {
            handle.net_permission_granted = true;
        }
        status
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `UDPWrap::Disconnect`: forget the peer recorded by `connect`.
pub fn disconnect(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live; a null address clears the peer.
        unsafe { uv::uv_udp_connect(handle.raw(), ptr::null()) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `UDPWrap::Send`: `send(req, chunks, count, port, address, hasCallback)`.
pub fn send(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    send::dispatch(scope, &args, &mut rv, 4);
}

/// `UDPWrap::Send6`.
pub fn send6(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    send::dispatch(scope, &args, &mut rv, 6);
}

/// `GetSockOrPeerName<UDPWrap, uv_udp_getsockname>`.
pub fn getsockname(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    sock_or_peer_name(scope, &args, &mut rv, true);
}

/// `GetSockOrPeerName<UDPWrap, uv_udp_getpeername>`.
pub fn getpeername(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    sock_or_peer_name(scope, &args, &mut rv, false);
}

/// Fills a caller-provided object with `{ address, family, port }`.
///
/// `lib/dgram.js`'s `socket.address()` passes a fresh `{}` and reads those three
/// properties, so the object is mutated in place rather than replaced.
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

    // SAFETY: `sockaddr_storage` is plain C data, so the all-zero bit pattern is
    // a valid value and libuv overwrites it.
    let mut storage: uv::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<uv::sockaddr_storage>() as i32;

    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // SAFETY: `storage` is large enough for any address libuv writes and
        // `length` is its size in bytes.
        unsafe {
            if local {
                uv::uv_udp_getsockname(
                    handle.raw(),
                    std::ptr::from_mut(&mut storage).cast(),
                    &mut length,
                )
            } else {
                uv::uv_udp_getpeername(
                    handle.raw(),
                    std::ptr::from_mut(&mut storage).cast(),
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
    let parsed = unsafe { crate::handle::parse_storage(&storage) };
    let Some(parsed) = parsed else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    if !crate::handle::fill_address(scope, target, &parsed) {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    }
    rv.set(v8::Integer::new(scope, 0).into());
}

/// `UDPWrap::AddMembership`: `addMembership(address, iface)`.
pub fn add_membership(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    set_membership(scope, &args, &mut rv, uv::uv_membership_UV_JOIN_GROUP);
}

/// `UDPWrap::DropMembership`.
pub fn drop_membership(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    set_membership(scope, &args, &mut rv, uv::uv_membership_UV_LEAVE_GROUP);
}

fn set_membership(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue<'_>,
    membership: uv::uv_membership,
) {
    let Some(address) = crate::arg_string(scope, args, 0) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    // An absent interface means "the default one", which libuv spells as a null
    // pointer.
    let interface = interface_argument(scope, args, 1);
    let Ok(address) = std::ffi::CString::new(address) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };

    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and both strings outlive the call.
        unsafe {
            uv::uv_udp_set_membership(
                handle.raw(),
                address.as_ptr(),
                interface
                    .as_ref()
                    .map_or(ptr::null(), |interface| interface.as_ptr()),
                membership,
            )
        }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `UDPWrap::AddSourceSpecificMembership`.
pub fn add_source_membership(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    set_source_membership(scope, &args, &mut rv, uv::uv_membership_UV_JOIN_GROUP);
}

/// `UDPWrap::DropSourceSpecificMembership`.
pub fn drop_source_membership(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    set_source_membership(scope, &args, &mut rv, uv::uv_membership_UV_LEAVE_GROUP);
}

fn set_source_membership(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue<'_>,
    membership: uv::uv_membership,
) {
    let Some(source) = crate::arg_string(scope, args, 0) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let Some(group) = crate::arg_string(scope, args, 1) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    // `SetSourceMembership` returns *without doing anything* when the interface
    // argument converts to a null string, before it looks at `IsUndefined()`. So
    // an omitted interface is a no-op here, unlike `setMembership` above, and
    // that asymmetry is upstream behaviour rather than an oversight to fix.
    let Some(interface) = crate::arg_string(scope, args, 2) else {
        return;
    };
    let (Ok(source), Ok(group)) = (
        std::ffi::CString::new(source),
        std::ffi::CString::new(group),
    ) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let interface = if args.get(2).is_undefined() || args.get(2).is_null() {
        None
    } else {
        match std::ffi::CString::new(interface) {
            Ok(interface) => Some(interface),
            Err(_) => {
                rv.set(v8::Integer::new(scope, EINVAL).into());
                return;
            }
        }
    };

    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and every string outlives the call.
        unsafe {
            uv::uv_udp_set_source_membership(
                handle.raw(),
                group.as_ptr(),
                interface
                    .as_ref()
                    .map_or(ptr::null(), |interface| interface.as_ptr()),
                source.as_ptr(),
                membership,
            )
        }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// Reads an optional interface argument as a NUL-terminated string.
fn interface_argument(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<std::ffi::CString> {
    if args.get(index).is_undefined() || args.get(index).is_null() {
        return None;
    }
    let text = crate::arg_string(scope, args, index)?;
    std::ffi::CString::new(text).ok()
}

/// `UDPWrap::SetMulticastInterface`.
pub fn set_multicast_interface(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(interface) = crate::arg_string(scope, &args, 0) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let Ok(interface) = std::ffi::CString::new(interface) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live and the string outlives the call.
        unsafe { uv::uv_udp_set_multicast_interface(handle.raw(), interface.as_ptr()) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// The shared body of the four `SetLibuvInt32` methods.
fn set_libuv_int32(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue<'_>,
    apply: for<'a> fn(&mut UdpHandle, i32) -> i32,
) {
    // `CHECK_EQ(args.Length(), 1)` then `args[0]->Int32Value()`. A value that
    // does not convert leaves the return value untouched, which is what Node's
    // `return` does.
    let Some(flag) = args.get(0).int32_value(scope) else {
        return;
    };
    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        apply(handle, flag)
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `SetLibuvInt32<uv_udp_set_multicast_ttl>`.
pub fn set_multicast_ttl(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    set_libuv_int32(scope, &args, &mut rv, |handle, flag| {
        // SAFETY: the handle is live.
        unsafe { uv::uv_udp_set_multicast_ttl(handle.raw(), flag) }
    });
}

/// `SetLibuvInt32<uv_udp_set_multicast_loop>`.
pub fn set_multicast_loopback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    set_libuv_int32(scope, &args, &mut rv, |handle, flag| {
        // SAFETY: the handle is live.
        unsafe { uv::uv_udp_set_multicast_loop(handle.raw(), flag) }
    });
}

/// `SetLibuvInt32<uv_udp_set_broadcast>`.
pub fn set_broadcast(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    set_libuv_int32(scope, &args, &mut rv, |handle, flag| {
        // SAFETY: the handle is live.
        unsafe { uv::uv_udp_set_broadcast(handle.raw(), flag) }
    });
}

/// `SetLibuvInt32<uv_udp_set_ttl>`.
pub fn set_ttl(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    set_libuv_int32(scope, &args, &mut rv, |handle, flag| {
        // SAFETY: the handle is live.
        unsafe { uv::uv_udp_set_ttl(handle.raw(), flag) }
    });
}

/// `UDPWrap::BufferSize`: `bufferSize(size, isRecv, ctx)`.
///
/// Returns the size the kernel settled on, or `undefined` — with `ctx` filled in
/// — when the call failed. `lib/dgram.js` turns that `undefined` into
/// `ERR_SOCKET_BUFFER_SIZE`, whose message reads `ctx.code`, `ctx.message` and
/// `ctx.syscall`, so all three are what makes the error useful.
pub fn buffer_size(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let is_receive = args.get(1).is_true();
    let syscall = if is_receive {
        "uv_recv_buffer_size"
    } else {
        "uv_send_buffer_size"
    };
    let context = v8::Local::<v8::Object>::try_from(args.get(2)).ok();

    // `CHECK(args[0]->IsUint32())` guards the read; a value outside that range
    // is reported the same way a failed call is, because Node's branch for a
    // non-Int32 collects `UV_EINVAL` into the same context object.
    let size = args.get(0).uint32_value(scope);
    let Some(size) = size else {
        collect_exception_info(scope, context, EINVAL, syscall);
        return;
    };
    let requested = size as i32;

    let outcome = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return (EBADF, requested);
        }
        let mut requested = requested;
        // SAFETY: the handle is live and `requested` is a live `i32` that the
        // call both reads and writes.
        let status = unsafe {
            if is_receive {
                uv::uv_recv_buffer_size(crate::as_handle(handle.raw()), &mut requested)
            } else {
                uv::uv_send_buffer_size(crate::as_handle(handle.raw()), &mut requested)
            }
        };
        (status, requested)
    })
    .unwrap_or((EBADF, requested));

    let (status, actual) = outcome;
    if status != 0 {
        collect_exception_info(scope, context, status, syscall);
        return;
    }
    rv.set(v8::Integer::new(scope, actual).into());
}

/// Fills `{ errno, code, message, syscall }`, which is `CollectUVExceptionInfo`.
fn collect_exception_info(
    scope: &mut v8::PinScope<'_, '_>,
    object: Option<v8::Local<v8::Object>>,
    errno: i32,
    syscall: &str,
) {
    let Some(object) = object else {
        return;
    };
    let Some(code) = v8::String::new(scope, &rn_bind_uv::name(errno)) else {
        return;
    };
    let Some(message) = v8::String::new(scope, &rn_bind_uv::message(errno)) else {
        return;
    };
    let Some(syscall) = v8::String::new(scope, syscall) else {
        return;
    };
    for (name, value) in [
        ("errno", v8::Integer::new(scope, errno).into()),
        ("code", code.into()),
        ("message", message.into()),
        ("syscall", syscall.into()),
    ] {
        if let Some(key) = v8::String::new(scope, name) {
            object.set(scope, key.into(), value);
        }
    }
}

/// `UDPWrap::GetSendQueueSize` — bytes libuv still has queued.
pub fn get_send_queue_size(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let size = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return None;
        }
        // SAFETY: the handle is live.
        Some(unsafe { uv::uv_udp_get_send_queue_size(handle.raw()) })
    })
    .flatten();
    match size {
        Some(size) => rv.set(v8::Number::new(scope, size as f64).into()),
        None => rv.set(v8::Integer::new(scope, EBADF).into()),
    }
}

/// `UDPWrap::GetSendQueueCount` — requests libuv still has queued.
pub fn get_send_queue_count(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let count = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return None;
        }
        // SAFETY: the handle is live.
        Some(unsafe { uv::uv_udp_get_send_queue_count(handle.raw()) })
    })
    .flatten();
    match count {
        Some(count) => rv.set(v8::Number::new(scope, count as f64).into()),
        None => rv.set(v8::Integer::new(scope, EBADF).into()),
    }
}

/// `UDPWrap::RecvStart`.
///
/// `UV_EALREADY` — the socket is already receiving — is reported as success, as
/// `src/udp_wrap.cc` does.
pub fn recv_start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // `UDPWrap::RecvStart` gates the first receive on a handle that was not
        // already let onto the network by a bind/connect/open. It is checked here
        // rather than in the caller so the check sees the handle's own flag, and
        // `net_permission_granted_ = true` afterwards rather than before means a
        // denied start leaves the flag unset.
        if !handle.net_permission_granted {
            if let Some(denied) = rn_permission::runtime::deny_net("") {
                denied.throw(scope);
                return EACCES;
            }
            handle.net_permission_granted = true;
        }
        // SAFETY: the handle is live, and both callbacks read the owner through
        // `data`, which the constructor stored.
        let status = unsafe { uv::uv_udp_recv_start(handle.raw(), Some(on_alloc), Some(on_recv)) };
        if status == uv::uv_errno_t_UV_EALREADY {
            0
        } else {
            status
        }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `UDPWrap::RecvStop`.
pub fn recv_stop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = udp::with_handle(args.this(), |handle| {
        if !handle.is_alive() {
            return EBADF;
        }
        // SAFETY: the handle is live.
        unsafe { uv::uv_udp_recv_stop(handle.raw()) }
    })
    .unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, status).into());
}

/// libuv's receive allocator.
///
/// The allocation is parked on the handle rather than in a thread-local, because
/// a process can have several sockets receiving at once and only the handle ties
/// an allocation to its own datagram.
///
/// # Safety
///
/// Called by libuv with a live handle and a writable `uv_buf_t`.
unsafe extern "C" fn on_alloc(
    handle: *mut uv::uv_handle_t,
    suggested_size: usize,
    buffer: *mut uv::uv_buf_t,
) {
    if buffer.is_null() {
        return;
    }
    // SAFETY: the handle libuv passes is the one this crate initialised.
    let Some(pointer) = (unsafe { crate::owner(handle.cast::<uv::uv_udp_t>()) }) else {
        return;
    };
    // SAFETY: the owner pointer is live for as long as libuv can call back.
    let handle = unsafe { &mut *pointer };

    let Some(mut allocation) = Allocation::new(suggested_size) else {
        // SAFETY: `buffer` is libuv's out-parameter; a zero length is how it is
        // told the allocation failed.
        unsafe {
            (*buffer).base = ptr::null_mut();
            (*buffer).len = 0;
        }
        return;
    };
    let length = allocation.length();
    let base = allocation.base();
    // SAFETY: `buffer` is libuv's out-parameter, live for this call.
    unsafe {
        (*buffer).base = base.cast();
        (*buffer).len = length;
    }
    std::mem::forget(allocation);
    // A second allocator call before the first datagram was read would leak the
    // earlier buffer, so an outstanding allocation is released first. Assigning
    // over it is what drops the old one.
    handle.pending_allocation =
        // SAFETY: `base` and `length` are the allocation `Allocation::new` just
        // made, and `forget` above stopped this scope from owning it.
        Some(unsafe { Allocation::from_raw(base, length) });
}

/// libuv's receive completion.
///
/// # Safety
///
/// Called by libuv with the handle whose `data` is the `*mut UdpHandle`.
unsafe extern "C" fn on_recv(
    raw_handle: *mut uv::uv_udp_t,
    nread: isize,
    _buffer: *const uv::uv_buf_t,
    address: *const uv::sockaddr,
    _flags: u32,
) {
    // SAFETY: the binding stored the owner pointer in `handle->data`.
    let Some(pointer) = (unsafe { crate::owner(raw_handle) }) else {
        return;
    };
    // SAFETY: `pointer` is the owner pointer, live while the handle is.
    let handle = unsafe { &mut *pointer };

    // The allocator's buffer always belongs to this datagram, whether or not it
    // carries bytes, so it is reclaimed before anything else.
    let allocation = handle.pending_allocation.take();

    // `nread == 0 && addr == nullptr` means the read produced nothing at all.
    if nread == 0 && address.is_null() {
        return;
    }

    rn_uv::callback::with_context(|scope| {
        let Some(object) = handle
            .owner_object
            .as_ref()
            .map(|object| v8::Local::new(scope, object))
        else {
            return;
        };
        let nread_value: v8::Local<v8::Value> = v8::Integer::new(scope, nread as i32).into();
        let handle_value: v8::Local<v8::Value> = object.into();

        if nread < 0 {
            // A failed read reports through `onmessage`, and `lib/dgram.js`'s
            // `onMessage` emits the error itself.
            let undefined = v8::undefined(scope).into();
            call_hook(
                scope,
                object,
                "onmessage",
                &[nread_value, handle_value, undefined, undefined],
            );
            return;
        }

        // The address has to parse before the datagram is delivered, because a
        // receiver that cannot name the sender is `onerror`'s business.
        // SAFETY: libuv passed a parsed address for a datagram that arrived.
        let parsed = if address.is_null() {
            None
        } else {
            unsafe { rn_uv::addr::from_sockaddr(&*address) }
        };
        let Some(parsed) = parsed else {
            let message = v8::String::new(scope, "Cannot parse the source address")
                .map(|text| v8::Exception::error(scope, text))
                .unwrap_or_else(|| v8::undefined(scope).into());
            let undefined = v8::undefined(scope).into();
            call_hook(
                scope,
                object,
                "onerror",
                &[nread_value, handle_value, message, undefined],
            );
            return;
        };

        let info = v8::Object::new(scope);
        if !crate::handle::fill_address(scope, info, &parsed) {
            return;
        }

        // `Buffer::New(env, ab, 0, ab->ByteLength())`: a `Buffer` over the bytes
        // libuv just wrote. `lib/dgram.js` hands this to user code, so it has to
        // be a real `Buffer` (`Buffer.isBuffer` true) rather than a `Uint8Array`.
        let length = if nread > 0 { nread as usize } else { 0 };
        let Some(buffer) = buffer_from_allocation(scope, allocation, length) else {
            return;
        };
        call_hook(
            scope,
            object,
            "onmessage",
            &[nread_value, handle_value, buffer.into(), info.into()],
        );
    });
}

/// Builds a `Buffer` over the bytes a receive allocation holds.
///
/// `length` is the datagram's size, which is `<=` the allocation's own length:
/// a zero-length datagram still gets a zero-length backing store, as
/// `ArrayBuffer::NewBackingStore(isolate, 0)` does in `src/udp_wrap.cc`.
fn buffer_from_allocation<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    allocation: Option<Allocation>,
    length: usize,
) -> Option<v8::Local<'s, v8::Uint8Array>> {
    let array_buffer = match allocation {
        Some(allocation) if length > 0 && length <= allocation.length() => {
            allocation.into_array_buffer(scope)
        }
        _ => {
            let store = v8::ArrayBuffer::new_backing_store(scope, 0);
            let store: v8::SharedRef<v8::BackingStore> = store.into();
            v8::ArrayBuffer::with_backing_store(scope, &store)
        }
    };
    let view = v8::Uint8Array::new(scope, array_buffer, 0, length)?;
    // `Buffer` *is* a `Uint8Array` carrying `Buffer.prototype` in both runtimes,
    // so setting the prototype is what makes `Buffer.isBuffer` true. Reading the
    // prototype off the global rather than through `rn-bind-buffer` keeps one
    // binding out of another's state, which is the same choice `http_parser`
    // made for its own buffers.
    if let Some(prototype) = buffer_prototype(scope) {
        view.set_prototype(scope, prototype.into());
    }
    Some(view)
}

/// `Buffer.prototype`, as `lib/buffer.js` installed it on the global.
fn buffer_prototype<'s>(scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let buffer = global.get(scope, key.into())?;
    let object = v8::Local::<v8::Object>::try_from(buffer).ok()?;
    let prototype = v8::String::new(scope, "prototype")?;
    let value = object.get(scope, prototype.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Calls `object[name](arguments…)`, ignoring a missing or non-function hook.
fn call_hook<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    arguments: &[v8::Local<'s, v8::Value>],
) {
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    let Some(value) = object.get(scope, key.into()) else {
        return;
    };
    let Ok(callback) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };
    let receiver: v8::Local<v8::Value> = object.into();
    let _ = callback.call(scope, receiver, arguments);
}

/// A `uv_buf_t` over a typed array's bytes, for the send path.
///
/// # Safety
///
/// The view's backing store must stay alive until libuv is done with the buffer.
/// `lib/dgram.js` keeps the chunks on `req.list` for exactly that reason.
pub unsafe fn view_buffer(value: v8::Local<v8::Value>) -> Option<uv::uv_buf_t> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() {
        if length == 0 {
            return Some(uv::uv_buf_t {
                base: ptr::null_mut(),
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
