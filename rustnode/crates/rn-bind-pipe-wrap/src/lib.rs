//! `internalBinding('pipe_wrap')` for rustnode.
//!
//! `lib/net.js` uses this namespace for two things: unix-domain sockets
//! (`net.createServer().listen('/tmp/sock')`, `net.connect('/tmp/sock')`) and the
//! `fd = -1, addressType = -1` case in `createServerHandle`, where a server is
//! built with no address at all and later adopted through `listen({ fd })`.
//!
//! The contract is `src/pipe_wrap.cc`'s:
//!
//! * `Pipe` — a `uv_pipe_t` wrapper, constructed as
//!   `new Pipe(constants.SOCKET | constants.SERVER | constants.IPC)`.
//! * `PipeConnectWrap` — the request a `connect()` reports back to.
//! * `constants` — `SOCKET`, `SERVER`, `IPC`, `UV_READABLE`, `UV_WRITABLE`.
//!
//! # What is shared with `tcp_wrap`
//!
//! Everything below `LibuvStreamWrap`: `readStart`, `readStop`, `shutdown`, the
//! four `write*` forms, `close`/`ref`/`unref`/`hasRef`, and the `fd`,
//! `bytesRead`, `bytesWritten` and `writeQueueSize` accessors. Those live in
//! [`rn_uv::stream`] and are wired to this binding's handles the same way, so the
//! code below is only what a pipe does differently: `bind` takes a path,
//! `connect` takes a path, and there is `fchmod` and no socket-option machinery.

use libuv_sys2 as uv;
use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub mod connect;
pub mod handle;
pub mod methods;
pub mod wrap;

/// Members exposed on the namespace object, matching `contracts/pipe_wrap.json`.
pub const MEMBERS: &[&str] = &["Pipe", "PipeConnectWrap", "constants"];

/// Members this namespace needs but cannot install yet.
///
/// Empty: all three recorded members are installed.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `PipeWrap::SocketType::SOCKET` — a connected end of a pipe.
pub const SOCKET: i32 = 0;
/// `PipeWrap::SocketType::SERVER` — a listening end.
pub const SERVER: i32 = 1;
/// `PipeWrap::SocketType::IPC` — a pipe that can carry handles.
///
/// `lib/net.js` never constructs one directly; `lib/internal/child_process.js`
/// does, for the channel to a spawned process. The value is published because
/// `constants.IPC` is part of the contract.
pub const IPC: i32 = 2;

/// `UV_READABLE` from `uv.h`, which `uv_pipe_open` takes as a direction flag.
pub const UV_READABLE: i32 = uv::uv_poll_event_UV_READABLE as i32;
/// `UV_WRITABLE` from `uv.h`.
pub const UV_WRITABLE: i32 = uv::uv_poll_event_UV_WRITABLE as i32;

/// `internalBinding('pipe_wrap')`.
pub struct PipeWrap;

impl BindingModule for PipeWrap {
    fn namespace(&self) -> &'static str {
        "pipe_wrap"
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
        // install callback is the first point where the isolate and context both
        // exist.
        rn_uv::callback::remember_context(scope);

        let object = v8::Object::new(scope);

        let pipe = handle::constructor(scope)?;
        set(scope, object, "Pipe", pipe)?;

        let connect_wrap = wrap::constructor(scope)?;
        set(scope, object, "PipeConnectWrap", connect_wrap)?;

        let constants = v8::Object::new(scope);
        for (name, value) in [
            ("SOCKET", SOCKET),
            ("SERVER", SERVER),
            ("IPC", IPC),
            ("UV_READABLE", UV_READABLE),
            ("UV_WRITABLE", UV_WRITABLE),
        ] {
            let value = v8::Integer::new(scope, value);
            define_constant(scope, constants, name, value.into())?;
        }
        set(scope, object, "constants", constants.into())?;

        Ok(object)
    }
}

/// Registers the `pipe_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(PipeWrap);
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
