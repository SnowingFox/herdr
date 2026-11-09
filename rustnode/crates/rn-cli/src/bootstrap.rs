//! Node's realm bootstrap, driven from Rust.
//!
//! `lib/internal/bootstrap/realm.js` is the file that defines `internalBinding`,
//! `require` and `BuiltinModule` for every builtin that follows. Everything Node
//! does after it depends on it having run.
//!
//! The sequence, which mirrors `Realm::BootstrapRealm()` in `src/node_realm.cc`:
//!
//! 1. create the `primordials` object and run `internal/per_context/primordials`
//!    to fill it, so no builtin ever looks a builtin up through the mutable
//!    global object;
//! 2. create the `process` object;
//! 3. run `internal/bootstrap/realm` with `(process, getLinkedBinding,
//!    getInternalBinding, primordials)`.
//!
//! `getInternalBinding` is the interesting one: it is the only path by which the
//! JavaScript layer reaches a Rust namespace, so it is where the binding registry
//! is consulted.


use rn_core::{BindingModule, InstallCtx};
use rn_js2c::builtin_by_id;
use rn_v8_sys::v8;

/// The result of running the realm bootstrap.
pub struct Bootstrapped {
    /// `internalBinding`, as `realm.js` installed it, for the CLI to call.
    pub internal_binding: Option<v8::Global<v8::Function>>,
    /// `require`, as `realm.js` installed it.
    pub require: Option<v8::Global<v8::Function>>,
}

/// Runs the bootstrap and returns the loaders it created.
pub fn bootstrap_realm(
    scope: &mut v8::PinScope,
    registry: &rn_core::BindingRegistry,
) -> Result<Bootstrapped, String> {
    let global = scope.get_current_context().global(scope);

    let primordials = v8::Object::new(scope);
    run_per_context(scope, primordials)?;

    let process = process_object(scope)?;
    set(scope, global, "process", process.into())?;
    // `realm.js` reads `primordials` as a bare global inside its wrapper, so the
    // object has to be reachable both there and through the parameter below.
    set(scope, global, "primordials", primordials.into())?;

    let get_linked_binding = function_of(scope, "getLinkedBinding", get_linked_binding)?;
    let get_internal_binding = internal_binding_dispatcher(scope, registry)?;

    let realm = builtin_by_id("internal/bootstrap/realm")
        .ok_or("the realm bootstrap is missing from the builtin table")?;
    let function =
        rn_builtins::compile(scope, realm.id(), realm.source(), realm.kind())
            .ok_or("failed to compile internal/bootstrap/realm")?;

    let arguments = [
        process.into(),
        get_linked_binding,
        get_internal_binding,
        primordials.into(),
    ];
    // `realm.js` returns nothing: it hands its loaders to `setInternalLoaders`,
    // which this crate captures. A missing return value is therefore success, not
    // failure, and only a pending exception means the bootstrap did not finish.
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let _ = function.call(scope, global.into(), &arguments);
    if scope.has_caught() {
        let message = scope
            .exception()
            .map(|exception| exception.to_rust_string_lossy(scope))
            .unwrap_or_default();
        return Err(format!("internal/bootstrap/realm threw: {message}"));
    }

    // `require` is what user code and the CLI both need, so it becomes a global
    // the same way Node exposes it to a CommonJS module.
    let require = rn_core::hook_slot::require(scope);
    if let Some(require) = require {
        set(scope, global, "require", require.into())?;
    }

    Ok(Bootstrapped {
        internal_binding: rn_core::hook_slot::internal_binding(scope).map(|function| v8::Global::new(scope, function)),
        require: require.map(|function| v8::Global::new(scope, function)),
    })
}

/// Runs `internal/per_context/primordials` with the parameters its kind declares.
fn run_per_context(scope: &mut v8::PinScope, primordials: v8::Local<v8::Object>) -> Result<(), String> {
    let builtin = builtin_by_id("internal/per_context/primordials")
        .ok_or("primordials is missing from the builtin table")?;
    let function = rn_builtins::compile(scope, builtin.id(), builtin.source(), builtin.kind())
        .ok_or("failed to compile primordials")?;

    let exports = v8::Object::new(scope);
    let private_symbols = v8::Object::new(scope);
    let per_isolate_symbols = v8::Object::new(scope);
    let arguments = [
        exports.into(),
        primordials.into(),
        private_symbols.into(),
        per_isolate_symbols.into(),
    ];
    function
        .call(scope, exports.into(), &arguments)
        .ok_or("primordials threw")?;
    Ok(())
}

/// Builds the `process` object the bootstrap expects.
///
/// Node's `process` is created by `lib/internal/bootstrap/node.js`, which needs
/// far more of the runtime than exists yet. This is the subset `realm.js` itself
/// touches: the load-list array it appends to, and the accessors it defines.
fn process_object<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Object>, String> {
    let process = v8::Object::new(scope);

    let load_list = v8::Array::new(scope, 0);
    set(scope, process, "moduleLoadList", load_list.into())?;

    let versions = v8::Object::new(scope);
    let v8_version = v8::String::new(scope, v8::V8::get_version())
        .ok_or("cannot allocate the V8 version")?;
    set(scope, versions, "v8", v8_version.into())?;
    let node_version = v8::String::new(scope, "28.0.0").ok_or("cannot allocate a version")?;
    set(scope, versions, "node", node_version.into())?;
    set(scope, process, "versions", versions.into())?;

    let version = v8::String::new(scope, "v28.0.0").ok_or("cannot allocate a version")?;
    set(scope, process, "version", version.into())?;
    let platform = v8::String::new(scope, "linux").ok_or("cannot allocate the platform name")?;
    set(scope, process, "platform", platform.into())?;

    let argv = v8::Array::new(scope, 0);
    set(scope, process, "argv", argv.into())?;
    set(scope, process, "execArgv", v8::Array::new(scope, 0).into())?;
    set(scope, process, "env", v8::Object::new(scope).into())?;

    let pid = v8::Integer::new(scope, std::process::id() as i32);
    set(scope, process, "pid", pid.into())?;

    Ok(process)
}

/// Builds `getInternalBinding`, which resolves a namespace out of the registry.
///
/// This is the single path from JavaScript to a Rust binding. An unknown
/// namespace must throw with the name in it, because the alternative is an
/// `undefined` that fails much later and much less clearly.
fn internal_binding_dispatcher<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _registry: &rn_core::BindingRegistry,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(get_internal_binding).build(scope);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate getInternalBinding")?;
    Ok(function.into())
}

/// The `getInternalBinding` implementation.
///
/// A plain function rather than a closure: V8 stores callback data in a
/// statically sized slot, and a capturing closure overruns it.
fn get_internal_binding(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(name) = args.get(0).to_string(scope) else { return };
    let name = name.to_rust_string_lossy(scope);
    match install_namespace(scope, &name) {
        Ok(object) => rv.set(object.into()),
        Err(message) => throw(scope, &message),
    }
}

/// Installs one namespace, caching the result on the global so a second call
/// returns the same object.
fn install_namespace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let global = scope.get_current_context().global(scope);
    let cache_key = format!("__rustnodeBinding_{name}");
    if let Some(key) = v8::String::new(scope, &cache_key) {
        if let Some(existing) = global.get(scope, key.into()) {
            if let Ok(object) = v8::Local::<v8::Object>::try_from(existing) {
                return Ok(object);
            }
        }
    }

    let object = match name {
        "builtins" => install(scope, &rn_builtins::Builtins)?,
        "errors" => install(scope, &rn_errors::Errors)?,
        "module_wrap" => install(scope, &rn_module_wrap::ModuleWrapBinding)?,
        "util" => install(scope, &rn_util::Util)?,
        "types" => install(scope, &rn_util::Types)?,
        other => {
            return Err(format!(
                "internalBinding('{other}') is not available: the namespace has no Rust implementation yet"
            ))
        },
    };

    if let Some(key) = v8::String::new(scope, &cache_key) {
        global.set(scope, key.into(), object.into());
    }
    Ok(object)
}

fn install<'s, M: BindingModule>(
    scope: &mut v8::PinScope<'s, '_>,
    module: &M,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let mut async_ids = rn_core::AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    module.install(scope, &mut ctx)
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

/// Placeholder for a loader entry that is not available yet.
fn get_linked_binding(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    throw(scope, "getLinkedBinding is not implemented yet");
}

fn function_of<'s>(
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

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else { return };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}
