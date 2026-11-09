//! `internalBinding('spawn_sync')` for rustnode.
//!
//! `lib/internal/child_process.js` reads `spawn` from this namespace at module
//! scope, so `require('child_process')` — and therefore `require('cluster')`, and
//! therefore `server.listen()` — fails outright until it exists. That is why a
//! namespace with a single function is on the critical path for `net`.
//!
//! The contract is `src/spawn_sync.cc`'s: one member, `spawn(options)`, returning
//! `{ error?, status, signal, output, pid }`.
//!
//! # Why it blocks, while `spawn` does not
//!
//! `spawnSync` has to return the child's output *by the time it returns*, so it
//! cannot share the process' event loop: a blocking `uv_run` there would run every
//! timer and socket callback the caller had queued. Node therefore creates a
//! private `uv_loop_t`, spawns into it, pumps only that loop, and destroys it —
//! which is what this does too.
//!
//! # Output
//!
//! Each writable stdio is read into a growable list of fixed-size chunks rather
//! than one buffer, because a child that produces more than a few kilobytes would
//! otherwise need repeated reallocation while it runs. Node's
//! `SyncProcessOutputBuffer` is a 64 KiB chunk with a linked successor; this keeps
//! the same shape so `maxBuffer` accounting matches.

use libuv_sys2 as uv;
use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub mod runner;

/// Members exposed on the namespace object, matching `contracts/spawn_sync.json`.
pub const MEMBERS: &[&str] = &["spawn"];

/// Members this namespace needs but cannot install yet, each with the reason.
///
/// Empty: the one recorded member is installed, with every option
/// `lib/child_process.js` supplies.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `internalBinding('spawn_sync')`.
pub struct SpawnSync;

impl BindingModule for SpawnSync {
    fn namespace(&self) -> &'static str {
        "spawn_sync"
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
        // The run happens on its own loop, but its pipe callbacks can still call
        // into V8 (through a `Buffer` allocation), so the context has to be
        // reachable from a plain `uv_run`.
        rn_uv_callback_hook(scope);

        let object = v8::Object::new(scope);
        let spawn = method(scope, "spawn", runner::spawn)?;
        set(scope, object, "spawn", spawn)?;
        Ok(object)
    }
}

/// Registers the `spawn_sync` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(SpawnSync);
}

/// Records the isolate and context a pipe callback will re-enter.
///
/// `rn-uv` owns the re-entry machinery and this namespace does not otherwise use
/// it, but the helper is generic and reusing it keeps one implementation of "how
/// a libuv callback gets back into V8".
fn rn_uv_callback_hook(scope: &mut v8::PinScope<'_, '_>) {
    rn_uv::callback::remember_context(scope);
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

/// `UV_EINVAL`, for options Node's `ParseOptions` rejects.
pub const EINVAL: i32 = uv::uv_errno_t_UV_EINVAL;

/// Throws a `TypeError`, which is what `THROW_ERR_INVALID_ARG_TYPE` amounts to.
pub fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

/// Reads a named property, if it exists.
pub fn property<'s>(
    scope: &v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}
