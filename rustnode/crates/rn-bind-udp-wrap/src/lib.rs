//! `internalBinding('udp_wrap')` for rustnode.
//!
//! `lib/dgram.js` and `lib/internal/dgram.js` are unchanged Node code, so the
//! contract here is the one `src/udp_wrap.cc` defines. Three members:
//!
//! * `UDP` — the libuv `uv_udp_t` wrapper. Unlike `TCP` there is no socket type
//!   argument: `UDPWrap::SocketType` has a single value and Node's constructor
//!   never reads one.
//! * `SendWrap` — the request object a `send()` reports back to, which
//!   `lib/dgram.js` fills with `list`, `address`, `port` and `oncomplete`.
//! * `constants` — `UV_UDP_IPV6ONLY`, `UV_UDP_REUSEADDR`, `UV_UDP_REUSEPORT`,
//!   the three flags `socket.bind()` passes to `uv_udp_bind`.
//!
//! # The handle surface
//!
//! `lib/dgram.js` calls a mix of three layers, and all three have to be present
//! on the same object:
//!
//! | layer | members |
//! | --- | --- |
//! | `HandleWrap` (`src/handle_wrap.cc`) | `close`, `ref`, `unref`, `hasRef`, `getAsyncId` |
//! | `UDPWrapBase` (`src/udp_wrap.cc`) | `recvStart`, `recvStop` |
//! | `UDPWrap` (`src/udp_wrap.cc`) | `open`, `bind`, `bind6`, `connect`, `connect6`, `send`, `send6`, `disconnect`, `getsockname`, `getpeername`, `addMembership`, `dropMembership`, `addSourceSpecificMembership`, `dropSourceSpecificMembership`, `setMulticastInterface`, `setMulticastTTL`, `setMulticastLoopback`, `setBroadcast`, `setTTL`, `bufferSize`, `getSendQueueSize`, `getSendQueueCount` |
//!
//! plus the `fd` accessor and the `onmessage`/`onerror` properties the receive
//! path calls back through.
//!
//! # Why the receive path is not `StreamBase`
//!
//! A datagram socket has no stream: there is no `readStart`/`readStop`, no
//! `writeBuffer`, and no shared `streamBaseState`. `uv_udp_recv_cb` delivers the
//! sender's address with the bytes, and `lib/dgram.js`'s `onMessage` reads
//! `(nread, handle, buf, rinfo)` — four arguments with a `Buffer` that owns its
//! own bytes rather than an offset into a reused slab. The read path here
//! therefore builds its own `ArrayBuffer` per datagram and hands over a
//! `Buffer`-prototyped view, exactly as `UDPWrap::OnRecv` does.
//!
//! # Sends
//!
//! `src/udp_wrap.cc` tries `uv_udp_try_send` first and reports a *synchronous*
//! completion as `msg_size + 1`, which `lib/dgram.js` checks with `err >= 1` so
//! it can distinguish a zero-length synchronous send from an asynchronous one.
//! Only when that would block does it queue a `uv_udp_send`, and the completion
//! then calls `req.oncomplete(status, msg_size)`. Both paths are implemented
//! here, because a send that always queued would change when `socket.send()`
//! invokes its callback.

use std::ffi::c_void;
use std::ptr;

use libuv_sys2 as uv;
use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub mod handle;
pub mod methods;
pub mod send;

/// Members exposed on the namespace object, matching `contracts/udp_wrap.json`.
pub const MEMBERS: &[&str] = &["SendWrap", "UDP", "constants"];

/// Members this namespace needs but cannot install yet, each with the reason.
///
/// Empty: all three recorded members are installed, along with every handle
/// method `lib/dgram.js` calls.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `UV_UDP_IPV6ONLY` from `uv.h`, applied by `socket.bind({ ipv6Only: true })`.
pub const UV_UDP_IPV6ONLY: i32 = uv::uv_udp_flags_UV_UDP_IPV6ONLY as i32;
/// `UV_UDP_REUSEADDR` from `uv.h`, applied by `socket.bind({ reuseAddr: true })`.
pub const UV_UDP_REUSEADDR: i32 = uv::uv_udp_flags_UV_UDP_REUSEADDR as i32;
/// `UV_UDP_REUSEPORT` from `uv.h`, applied by `socket.bind({ reusePort: true })`.
pub const UV_UDP_REUSEPORT: i32 = uv::uv_udp_flags_UV_UDP_REUSEPORT as i32;

/// `internalBinding('udp_wrap')`.
pub struct UdpWrap;

impl BindingModule for UdpWrap {
    fn namespace(&self) -> &'static str {
        "udp_wrap"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        // `uv_udp_recv_cb` and `uv_udp_send_cb` fire from inside `uv_run`, which
        // is a plain Rust call, so the isolate and context have to be reachable
        // from there. The install callback is the first point where both exist.
        rn_uv::callback::remember_context(scope);

        let object = v8::Object::new(scope);

        // `src/udp_wrap.cc` registers the constructor first and the request
        // second, and `Object.keys()` exposes that order.
        let udp = handle::constructor(scope)?;
        set(scope, object, "UDP", udp)?;

        let send_wrap = send::constructor(scope)?;
        set(scope, object, "SendWrap", send_wrap)?;

        let constants = v8::Object::new(scope);
        for (name, value) in [
            ("UV_UDP_IPV6ONLY", UV_UDP_IPV6ONLY),
            ("UV_UDP_REUSEADDR", UV_UDP_REUSEADDR),
            ("UV_UDP_REUSEPORT", UV_UDP_REUSEPORT),
        ] {
            let value = v8::Integer::new(scope, value);
            define_constant(scope, constants, name, value.into())?;
        }
        set(scope, object, "constants", constants.into())?;

        Ok(object)
    }
}

/// Registers the `udp_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(UdpWrap);
}

fn define_constant(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object
        .define_own_property(
            scope,
            key.into(),
            value,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or_else(|| format!("cannot define constant {name}"))?;
    Ok(())
}

fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))
}

/// Reads argument `index` as an `i32`, falling back to `0`.
pub fn arg_i32(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> i32 {
    args.get(index).int32_value(scope).unwrap_or(0)
}

/// Reads argument `index` as a Rust string, if it is a string.
pub fn arg_string(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<String> {
    args.get(index)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
}

/// Throws a `TypeError`, which is what a failed `CHECK` amounts to here.
pub fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

/// Throws an `Error`.
pub fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::error(scope, text);
        scope.throw_exception(error);
    }
}

/// `sockaddr_for_family` from `src/udp_wrap.cc`.
///
/// Returns libuv's status, and fills `storage` on success. The address literal
/// has to be numeric: `uv_ip4_addr`/`uv_ip6_addr` reject hostnames, and
/// `lib/dgram.js` resolves before it gets here.
pub fn sockaddr_for_family(
    family: u8,
    address: &str,
    port: u16,
    storage: &mut uv::sockaddr_storage,
) -> i32 {
    let parsed = if family == 4 {
        rn_uv::addr::ip4(address, port).map(|address| {
            // SAFETY: `sockaddr_in` is smaller than `sockaddr_storage`, which is
            // defined to hold any address family, and both are plain data.
            unsafe {
                ptr::write(ptr::from_mut(storage).cast::<uv::sockaddr_in>(), address);
            }
        })
    } else {
        rn_uv::addr::ip6(address, port).map(|address| {
            // SAFETY: as above, for `sockaddr_in6`.
            unsafe {
                ptr::write(ptr::from_mut(storage).cast::<uv::sockaddr_in6>(), address);
            }
        })
    };
    match parsed {
        Ok(()) => 0,
        Err(status) => status,
    }
}

/// `uv_errno_t_UV_EBADF`, what `ASSIGN_OR_RETURN_UNWRAP` reports.
pub const EBADF: i32 = uv::uv_errno_t_UV_EBADF;
/// `UV_EINVAL`, for an argument Node's `CHECK` would have rejected.
pub const EINVAL: i32 = uv::uv_errno_t_UV_EINVAL;
/// `UV_EACCES`, the status `udp_wrap`'s permission checks return alongside the
/// error they throw.
pub const EACCES: i32 = uv::uv_errno_t_UV_EACCES;

/// `AsyncWrap::kInvalidAsyncId`.
const INVALID_ASYNC_ID: f64 = -1.0;

thread_local! {
    /// Ids handed out before the `async_wrap` namespace exists.
    ///
    /// Node draws every async id from one counter in `Environment`, which is what
    /// [`rn_bind_async_wrap::next_async_id`] advances. A binding can be installed
    /// and used before that namespace is (`rn-bind-udp-wrap`'s own tests do
    /// exactly that), so the shared sequence is preferred and this is the stand-in
    /// when it is not available yet. Both produce positive, distinct ids, which is
    /// all `async_id_symbol` is used for.
    static FALLBACK_ASYNC_ID: std::cell::Cell<f64> = const { std::cell::Cell::new(1.0) };
}

/// The next async id for a new handle.
pub fn next_async_id() -> f64 {
    let shared = rn_bind_async_wrap::next_async_id();
    if shared != INVALID_ASYNC_ID {
        return shared;
    }
    FALLBACK_ASYNC_ID.with(|counter| {
        let id = counter.get();
        counter.set(id + 1.0);
        id
    })
}

/// The `uv_udp_t` a handle owns, as the generic handle libuv's common calls
/// take.
pub fn as_handle(udp: *mut uv::uv_udp_t) -> *mut uv::uv_handle_t {
    udp.cast()
}

/// Reads a handle's owner pointer out of its `data` field.
///
/// # Safety
///
/// `udp` must be a live handle this crate initialised.
pub unsafe fn owner(udp: *mut uv::uv_udp_t) -> Option<*mut handle::UdpHandle> {
    if udp.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the handle is live, and its `data` field
    // holds the pointer the constructor stored.
    let data = unsafe { (*udp).data };
    if data.is_null() {
        None
    } else {
        Some(data.cast::<handle::UdpHandle>())
    }
}

/// Stores an owner pointer in a handle.
///
/// # Safety
///
/// `udp` must be live and `owner` must outlive the handle's close callback.
pub unsafe fn set_owner(udp: *mut uv::uv_udp_t, owner: *mut handle::UdpHandle) {
    if !udp.is_null() {
        // SAFETY: the caller guarantees the handle is live.
        unsafe { (*udp).data = owner.cast::<c_void>() };
    }
}
