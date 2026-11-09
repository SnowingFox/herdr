//! `internalBinding('process_wrap')` for rustnode.
//!
//! `lib/internal/child_process.js` spawns through this namespace, so the
//! contract is `src/process_wrap.cc`'s. Three members:
//!
//! * `Process` — the `uv_process_t` wrapper. `lib/internal/child_process.js`
//!   constructs one per `ChildProcess`, assigns `onexit` and later reads `pid`.
//! * `constants` — `kProcessFlagDetached`, `kProcessFlagWindowsHide` and
//!   `kProcessFlagWindowsVerbatimArguments`, which `spawn()`'s options turn into
//!   `uv_process_flags`.
//! * `getEnvPairs` — the whole environment as `['KEY=value', …]`.
//!
//! # Why this unblocks `net`
//!
//! `lib/net.js`'s `listenInCluster` requires `cluster` the first time a server
//! listens, `lib/cluster.js` picks `internal/cluster/primary` outside a worker,
//! and `internal/cluster/primary.js` requires `child_process`. So a namespace
//! that only dgram users would ever *call* is still read at module scope by every
//! `server.listen()`.
//!
//! # `getEnvPairs`
//!
//! `lib/child_process.js` calls it once per `spawn()` that inherits the parent's
//! environment, which is the default. Node reaches it through
//! `env->env_vars()->Pairs()`, an interceptor over the real environment block;
//! rustnode has no `process.env` interceptor yet, so this reads the process' own
//! block directly through `environ`. The two agree in the case that matters — a
//! child inherits what the parent started with — and differ only when user code
//! has assigned to `process.env` without passing `options.env`.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub mod constants;
pub mod handle;
pub mod methods;

/// Members exposed on the namespace object, matching `contracts/process_wrap.json`.
pub const MEMBERS: &[&str] = &["Process", "constants", "getEnvPairs"];

/// Members this namespace needs but cannot install yet, each with the reason.
///
/// Empty: all three recorded members are installed.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `internalBinding('process_wrap')`.
pub struct ProcessWrap;

impl BindingModule for ProcessWrap {
    fn namespace(&self) -> &'static str {
        "process_wrap"
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
        // `uv_process_t`'s exit callback fires from inside `uv_run`, so the
        // isolate and context have to be reachable from there.
        rn_uv::callback::remember_context(scope);

        let object = v8::Object::new(scope);

        // `src/process_wrap.cc` registers the constructor, then `getEnvPairs`,
        // then the constants object, and `Object.keys()` exposes that order.
        let process = handle::constructor(scope)?;
        set(scope, object, "Process", process)?;

        let get_env_pairs = method(scope, "getEnvPairs", methods::get_env_pairs)?;
        set(scope, object, "getEnvPairs", get_env_pairs)?;

        let values = v8::Object::new(scope);
        for (name, value) in [
            ("kProcessFlagDetached", constants::PROCESS_FLAG_DETACHED),
            (
                "kProcessFlagWindowsHide",
                constants::PROCESS_FLAG_WINDOWS_HIDE,
            ),
            (
                "kProcessFlagWindowsVerbatimArguments",
                constants::PROCESS_FLAG_WINDOWS_VERBATIM_ARGUMENTS,
            ),
        ] {
            let value = v8::Integer::new(scope, value);
            define_constant(scope, values, name, value.into())?;
        }
        set(scope, object, "constants", values.into())?;

        Ok(object)
    }
}

/// Registers the `process_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(ProcessWrap);
}

/// `uv_errno_t_UV_EINVAL`, for an argument Node's `CHECK` would have rejected.
pub const EINVAL: i32 = libuv_sys2::uv_errno_t_UV_EINVAL;

/// A `uv_process_t` as the generic handle libuv's common calls take.
pub fn as_handle(process: *mut libuv_sys2::uv_process_t) -> *mut libuv_sys2::uv_handle_t {
    process.cast()
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

/// Reads argument `index` as an `i32`, falling back to `0`.
pub fn arg_i32(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> i32 {
    args.get(index).int32_value(scope).unwrap_or(0)
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
