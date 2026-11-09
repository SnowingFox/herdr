//! `internalBinding('tcp_wrap')` for rustnode.
//!
//! `lib/net.js` is unchanged Node code, so this namespace's contract is the one
//! `src/tcp_wrap.cc` defines. Three members:
//!
//! * `TCP` — the libuv `uv_tcp_t` wrapper. Constructed as
//!   `new TCP(constants.SOCKET)` for a client and `new TCP(constants.SERVER)`
//!   for a server; the type only selects which async provider Node would report
//!   and is otherwise not observable here.
//! * `TCPConnectWrap` — the request object a `connect()` reports back to.
//! * `constants` — `SOCKET`, `SERVER`, `UV_TCP_IPV6ONLY`, `UV_TCP_REUSEPORT`.
//!
//! # The handle surface, and where it comes from
//!
//! `lib/net.js` calls a mix of three layers, and all three have to be present on
//! the same object:
//!
//! | layer | methods |
//! | --- | --- |
//! | `HandleWrap` (`src/handle_wrap.cc`) | `close`, `ref`, `unref`, `hasRef` |
//! | `StreamBase` (`src/stream_base.cc`) | `readStart`, `readStop`, `shutdown`, `writeBuffer`, `writev`, `write*String`, `useUserBuffer`, `isStreamBase`, `onread`, `fd`, `external`, `bytesRead`, `bytesWritten` |
//! | `TCPWrap` (`src/tcp_wrap.cc`) | `open`, `bind`, `bind6`, `listen`, `connect`, `connect6`, `getsockname`, `getpeername`, `setNoDelay`, `setKeepAlive`, `setTypeOfService`, `getTypeOfService`, `reset` |
//!
//! `lib/net.js` also reads and writes plain properties on the handle:
//! `reading`, `owner_symbol`, `onconnection`, `onread`. Those live on the
//! instance template as data/accessor properties, exactly as Node creates them.
//!
//! # What this crate defers, and why
//!
//! `lib/net.js` reaches a handful of TCP methods only through feature detection
//! (`if (self._handle.setTypeOfService)`, `if (handle.getsockname)`), so an
//! absent one degrades a single feature rather than breaking `require('net')`.
//! Everything in that set is still implemented, because a missing
//! `setTypeOfService` silently changes what `socket.setTypeOfService()` does.
//! The genuinely absent pieces are declared in [`DEFERRED`].

use libuv_sys2 as uv;
use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub mod connect;
pub mod handle;
pub mod methods;
pub mod wrap;

/// Members exposed on the namespace object, matching `contracts/tcp_wrap.json`.
pub const MEMBERS: &[&str] = &["TCP", "TCPConnectWrap", "constants"];

/// Members this namespace needs but cannot install yet.
///
/// Empty: all three recorded members are installed, and the handle methods
/// `lib/net.js` calls are implemented in [`methods`].
pub const DEFERRED: &[(&str, &str)] = &[];

/// `TCPWrap::SocketType` in `src/tcp_wrap.h`: a client socket.
pub const SOCKET: i32 = 0;
/// `TCPWrap::SocketType` in `src/tcp_wrap.h`: a listening socket.
pub const SERVER: i32 = 1;

/// `UV_TCP_IPV6ONLY` from `uv.h`.
pub const UV_TCP_IPV6ONLY: i32 = uv::uv_tcp_flags_UV_TCP_IPV6ONLY as i32;
/// `UV_TCP_REUSEPORT` from `uv.h`.
pub const UV_TCP_REUSEPORT: i32 = uv::uv_tcp_flags_UV_TCP_REUSEPORT as i32;

/// `internalBinding('tcp_wrap')`.
pub struct TcpWrap;

impl BindingModule for TcpWrap {
    fn namespace(&self) -> &'static str {
        "tcp_wrap"
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
        // The read and write paths need a way back into V8 from libuv, and the
        // install callback is the first point where both the isolate and the
        // context exist.
        rn_uv::callback::remember_context(scope);

        let object = v8::Object::new(scope);

        let tcp = handle::constructor(scope)?;
        set(scope, object, "TCP", tcp)?;

        let connect_wrap = wrap::constructor(scope)?;
        set(scope, object, "TCPConnectWrap", connect_wrap)?;

        let constants = v8::Object::new(scope);
        for (name, value) in [
            ("SOCKET", SOCKET),
            ("SERVER", SERVER),
            ("UV_TCP_IPV6ONLY", UV_TCP_IPV6ONLY),
            ("UV_TCP_REUSEPORT", UV_TCP_REUSEPORT),
        ] {
            let value = v8::Integer::new(scope, value);
            define_constant(scope, constants, name, value.into())?;
        }
        set(scope, object, "constants", constants.into())?;

        Ok(object)
    }
}

/// Registers the `tcp_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(TcpWrap);
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

/// Builds a non-constructible method function, matching `SetProtoMethod`.
pub fn method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    if let Some(text) = v8::String::new(scope, name) {
        function.set_name(text);
    }
    Ok(function.into())
}

/// Builds a constructor function, matching `SetConstructorFunction`.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback)
        .length(0)
        .build(scope);
    let Some(text) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the name of {name}"));
    };
    template.set_class_name(text);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    function.set_name(text);
    Ok(function.into())
}
