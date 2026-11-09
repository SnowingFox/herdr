//! `internalBinding('tty_wrap')` for rustnode.
//!
//! This namespace is small but load-bearing twice over:
//!
//! * `lib/internal/child_process.js` destructures `TTY` at module scope, for
//!   `getHandleWrapType`'s `stream instanceof TTY` check. It never constructs
//!   one. So `require('child_process')` — and therefore `require('cluster')`,
//!   and therefore `server.listen()` — fails outright until this namespace
//!   exists.
//! * `lib/tty.js` uses it for real: `new TTY(fd, ctx)` over a terminal, then
//!   `getWindowSize`, `setRawMode` and the stream methods `net.Socket` needs.
//!
//! The contract is `src/tty_wrap.cc`'s, which is five members:
//! `TTY`, `isTTY`, and the three `UV_TTY_MODE_*` constants.
//!
//! # What is shared with `tcp_wrap` and `pipe_wrap`
//!
//! A `TTY` is a `LibuvStreamWrap` like a socket and a pipe, so `readStart`,
//! `readStop`, `shutdown`, the write forms, `close`/`ref`/`unref`/`hasRef` and
//! the `fd`/`bytesRead`/`bytesWritten`/`writeQueueSize` accessors all come from
//! [`rn_uv::stream_base`] and [`rn_uv::stream`]. What is here is only what a
//! terminal adds: construction over a descriptor, the window size and raw mode.

use libuv_sys2 as uv;
use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub mod handle;
pub mod methods;

/// Members exposed on the namespace object, matching `contracts/tty_wrap.json`.
pub const MEMBERS: &[&str] = &[
    "TTY",
    "UV_TTY_MODE_IO",
    "UV_TTY_MODE_NORMAL",
    "UV_TTY_MODE_RAW_VT",
    "isTTY",
];

/// Members this namespace needs but cannot install yet, each with the reason.
///
/// Empty: every recorded member is installed, along with the stream methods a
/// `TTY` inherits.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `UV_TTY_MODE_NORMAL` from `uv.h`: line-buffered, the default for stdio.
pub const UV_TTY_MODE_NORMAL: i32 = uv::uv_tty_mode_t_UV_TTY_MODE_NORMAL as i32;
/// `UV_TTY_MODE_IO` from `uv.h`: non-blocking, used for a readable stdio.
pub const UV_TTY_MODE_IO: i32 = uv::uv_tty_mode_t_UV_TTY_MODE_IO as i32;
/// `UV_TTY_MODE_RAW_VT` from `uv.h`: raw, with control sequences passed through.
pub const UV_TTY_MODE_RAW_VT: i32 = uv::uv_tty_mode_t_UV_TTY_MODE_RAW_VT as i32;

/// `internalBinding('tty_wrap')`.
pub struct TtyWrap;

impl BindingModule for TtyWrap {
    fn namespace(&self) -> &'static str {
        "tty_wrap"
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

        // `src/tty_wrap.cc` registers `isTTY`, then the three constants, then the
        // constructor, and `Object.keys()` exposes that order.
        let is_tty = method(scope, "isTTY", methods::is_tty)?;
        set(scope, object, "isTTY", is_tty)?;

        for (name, value) in [
            ("UV_TTY_MODE_NORMAL", UV_TTY_MODE_NORMAL),
            ("UV_TTY_MODE_IO", UV_TTY_MODE_IO),
            ("UV_TTY_MODE_RAW_VT", UV_TTY_MODE_RAW_VT),
        ] {
            let value = v8::Integer::new(scope, value);
            define_constant(scope, object, name, value.into())?;
        }

        let tty = handle::constructor(scope)?;
        set(scope, object, "TTY", tty)?;

        Ok(object)
    }
}

/// Registers the `tty_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(TtyWrap);
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

/// Allocates a property name.
pub fn key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))
}

/// Builds a non-constructible method function, matching `SetMethodNoSideEffect`.
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

/// `UV_EBADF`, what `ASSIGN_OR_RETURN_UNWRAP` reports for a bad receiver.
pub const EBADF: i32 = uv::uv_errno_t_UV_EBADF;
/// `UV_EINVAL`, for an argument Node's `CHECK` would have rejected.
pub const EINVAL: i32 = uv::uv_errno_t_UV_EINVAL;

/// libuv's error name for `errno`.
///
/// The `uv` namespace owns the full table; a tty only ever reports a handful, and
/// a binding reaching into another binding's crate for three strings would be
/// worse than naming them here. Anything else falls through to the same
/// `Unknown system error <n>` text `uv_err_name` produces.
pub fn error_name(errno: i32) -> String {
    match error_entry(errno) {
        Some((name, _)) => name.to_string(),
        None => format!("Unknown system error {errno}"),
    }
}

/// libuv's message for `errno`.
pub fn error_message(errno: i32) -> String {
    match error_entry(errno) {
        Some((_, message)) => message.to_string(),
        None => format!("Unknown system error {errno}"),
    }
}

/// `(name, message)` for the codes a tty can report.
fn error_entry(errno: i32) -> Option<(&'static str, &'static str)> {
    [
        (
            uv::uv_errno_t_UV_ENOTTY,
            "ENOTTY",
            "inappropriate ioctl for device",
        ),
        (uv::uv_errno_t_UV_EBADF, "EBADF", "bad file descriptor"),
        (uv::uv_errno_t_UV_EINVAL, "EINVAL", "invalid argument"),
    ]
    .into_iter()
    .find(|(value, _, _)| *value == errno)
    .map(|(_, name, message)| (name, message))
}

/// A `uv_tty_t` as the generic handle libuv's common calls take.
pub fn as_handle(tty: *mut uv::uv_tty_t) -> *mut uv::uv_handle_t {
    tty.cast()
}

/// Reads argument `index` as an `i32`, falling back to `0`.
pub fn arg_i32(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> i32 {
    args.get(index).int32_value(scope).unwrap_or(0)
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
