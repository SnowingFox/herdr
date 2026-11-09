//! `internalBinding('mksnapshot')` for rustnode.
//!
//! This namespace exists so a Node binary can write a startup snapshot of its
//! own bootstrapped state. At runtime it does almost nothing, and that is the
//! point: `internal/v8/startup_snapshot.js` is loaded by `internal/errors` on
//! the ordinary path, reads `isBuildingSnapshotBuffer[0]`, and gets `0`, so
//! every snapshot-only branch is skipped.
//!
//! It is on the critical path anyway. `require('fs')` and `require('util')` both
//! fail with `internalBinding('mksnapshot')` until this namespace exists, which
//! is a lot of consequence for a single zero byte.
//!
//! # What the callbacks are for
//!
//! `setSerializeCallback`, `setDeserializeCallback`,
//! `setDeserializeMainFunction`, `compileSerializeMain` and `runEmbedderPreload`
//! are all reached only from `--build-snapshot` paths. rustnode does not build
//! snapshots yet, so they accept and retain what they are given rather than
//! lying about having used it: a snapshot run would need the rest of that
//! pipeline, which does not exist.

use std::cell::RefCell;

use rn_core::{AliasedUint8Array, BindingModule, Element, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/mksnapshot.json`.
pub const MEMBERS: &[&str] = &[
    "anonymousMainPath",
    "compileSerializeMain",
    "isBuildingSnapshotBuffer",
    "runEmbedderPreload",
    "setDeserializeCallback",
    "setDeserializeMainFunction",
    "setSerializeCallback",
];

/// `kAnonymousMainPath` in `src/node_snapshotable.cc`: the name a snapshotted
/// main script takes, so stack traces read sensibly.
pub const ANONYMOUS_MAIN_PATH: &str = "__node_anonymous_main";

thread_local! {
    /// The snapshot callbacks, retained so a snapshot build could use them.
    static CALLBACKS: RefCell<Option<Callbacks>> = const { RefCell::new(None) };
    /// The one-byte flag buffer `internal/v8/startup_snapshot.js` reads.
    static BUILDING: RefCell<Option<AliasedUint8Array>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct Callbacks {
    serialize: Option<v8::Global<v8::Function>>,
    deserialize: Option<v8::Global<v8::Function>>,
}

pub struct Mksnapshot;

impl BindingModule for Mksnapshot {
    fn namespace(&self) -> &'static str {
        "mksnapshot"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        install_impl(scope)
    }
}

fn install_impl<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Object>, String> {
    // A normal run is not building a snapshot, which is exactly what the JS
    // layer checks to decide whether to skip every snapshot-only branch.
    let building = AliasedUint8Array::new(scope, 1, Element::Byte)?;
    building.set(0, 0);
    let flag_array = building.array(scope);
    BUILDING.with(|slot| *slot.borrow_mut() = Some(building));

    let object = v8::Object::new(scope);
    let values: [(&str, v8::Local<v8::Value>); 7] = [
        ("isBuildingSnapshotBuffer", flag_array),
        (
            "anonymousMainPath",
            v8::String::new(scope, ANONYMOUS_MAIN_PATH)
                .map(|text| text.into())
                .unwrap_or_else(|| v8::undefined(scope).into()),
        ),
        (
            "setSerializeCallback",
            function(scope, "setSerializeCallback", set_serialize_callback)?,
        ),
        (
            "setDeserializeCallback",
            function(scope, "setDeserializeCallback", set_deserialize_callback)?,
        ),
        (
            "setDeserializeMainFunction",
            function(
                scope,
                "setDeserializeMainFunction",
                set_deserialize_main_function,
            )?,
        ),
        (
            "compileSerializeMain",
            function(scope, "compileSerializeMain", compile_serialize_main)?,
        ),
        (
            "runEmbedderPreload",
            function(scope, "runEmbedderPreload", run_embedder_preload)?,
        ),
    ];
    for (name, value) in values {
        set(scope, object, name, value)?;
    }
    Ok(object)
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Mksnapshot);
}

fn set_serialize_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let callback = v8::Local::<v8::Function>::try_from(args.get(0))
        .ok()
        .map(|callback| v8::Global::new(scope, callback));
    CALLBACKS.with(|slot| {
        let mut slot = slot.borrow_mut();
        let callbacks = slot.get_or_insert_with(Callbacks::default);
        callbacks.serialize = callback;
    });
}

fn set_deserialize_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let callback = v8::Local::<v8::Function>::try_from(args.get(0))
        .ok()
        .map(|callback| v8::Global::new(scope, callback));
    CALLBACKS.with(|slot| {
        let mut slot = slot.borrow_mut();
        let callbacks = slot.get_or_insert_with(Callbacks::default);
        callbacks.deserialize = callback;
    });
}

fn set_deserialize_main_function(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // Retained by the same slot as the deserialize callback: both are consumed
    // only when a snapshot is loaded, which rustnode does not do yet.
    set_deserialize_callback(scope, args, _rv);
}

fn compile_serialize_main(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // Only reachable from `--build-snapshot`, which needs the rest of the
    // snapshot pipeline. Failing loudly is better than returning a plausible
    // answer that would produce a broken snapshot.
    throw(
        scope,
        "compileSerializeMain is not implemented: rustnode does not build startup snapshots yet",
    );
}

fn run_embedder_preload(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // There is no embedder preload script: rustnode is a CLI, not an embedder.
    let _ = scope;
}

/// Whether the runtime is building a snapshot. Always false today.
pub fn is_building_snapshot() -> bool {
    BUILDING.with(|slot| {
        slot.borrow()
            .as_ref()
            .and_then(|buffer| buffer.get(0))
            .is_some_and(|value| value != 0)
    })
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}
