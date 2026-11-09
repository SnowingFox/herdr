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

use rn_js2c::builtin_by_id;
use rn_v8_sys::v8;

/// The result of running the realm bootstrap.
pub struct Bootstrapped {
    /// `internalBinding`, as `realm.js` installed it, for the CLI to call.
    pub internal_binding: Option<v8::Global<v8::Function>>,
    /// `require`, as `realm.js` installed it.
    pub require: Option<v8::Global<v8::Function>>,
}

/// Makes `internal/*` builtins requireable, the way `--expose-internals` does.
///
/// Node calls `BuiltinModule.exposeInternals()` during pre-execution. Without
/// it, `require('internal/test/binding')` throws and Node's own test suite
/// cannot load its helpers, which is why so many tests fail with
/// `Missing internal module`.
pub fn expose_internals(scope: &mut v8::PinScope, loaders: &Bootstrapped) {
    // `require('internal/bootstrap/realm')` returns the bootstrap's own
    // `loaderExports`, which is where `BuiltinModule` lives.
    let Some(require) = loaders.require.as_ref() else {
        return;
    };
    let require = v8::Local::new(scope, require);
    let Some(id) = v8::String::new(scope, "internal/bootstrap/realm") else {
        return;
    };
    let Some(exports) = require.call(scope, v8::undefined(scope).into(), &[id.into()]) else {
        return;
    };
    let Ok(exports) = v8::Local::<v8::Object>::try_from(exports) else {
        return;
    };
    let Some(key) = v8::String::new(scope, "BuiltinModule") else {
        return;
    };
    let Some(value) = exports.get(scope, key.into()) else {
        return;
    };
    let Ok(function) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };
    let Some(key) = v8::String::new(scope, "exposeInternals") else {
        return;
    };
    let Some(value) = function.get(scope, key.into()) else {
        return;
    };
    let Ok(expose) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };
    let _ = expose.call(scope, function.into(), &[]);
}

/// Normalizes the `node:` prefix the way Node's user-land loader does.
///
/// The loader `realm.js` hands out is the *internal* one: it looks ids up in
/// `BuiltinModule.map` verbatim, so `require('node:path')` misses `path` and
/// throws `Missing internal module`. Node's real user-land `require` is the
/// CommonJS loader, which calls `BuiltinModule.normalizeRequirableId` first.
/// That loader needs `contextify` and cannot run yet, so this installs the same
/// normalization over the internal loader. Every specifier that is not a
/// `node:` builtin reaches the internal loader unchanged.
pub fn wrap_require_with_scheme_support(scope: &mut v8::PinScope, loaders: &Bootstrapped) {
    let Some(require) = loaders.require.as_ref() else {
        return;
    };
    let require = v8::Local::new(scope, require);
    let Some(normalize) = normalize_requirable_id(scope, require) else {
        return;
    };

    // The wrapper is written in JavaScript because it has to close over the
    // normalize function and the inner loader. A V8 callback cannot capture
    // values: its data slot is statically sized and a closure does not fit.
    let source = "(function (normalize, inner) {\n\
                  \x20 return function require(id) {\n\
                  \x20   if (typeof id === 'string' && id.startsWith('node:')) {\n\
                  \x20     const normalized = normalize(id);\n\
                  \x20     if (normalized !== undefined) return inner(normalized);\n\
                  \x20   }\n\
                  \x20   return inner(id);\n\
                  \x20 };\n\
                  })";
    let Some(source) = v8::String::new(scope, source) else {
        return;
    };
    let Some(factory) = v8::Script::compile(scope, source, None) else {
        return;
    };
    let Some(factory) = factory.run(scope) else {
        return;
    };
    let Ok(factory) = v8::Local::<v8::Function>::try_from(factory) else {
        return;
    };
    let Some(wrapped) = factory.call(
        scope,
        v8::undefined(scope).into(),
        &[normalize.into(), require.into()],
    ) else {
        return;
    };
    let Ok(wrapped) = v8::Local::<v8::Function>::try_from(wrapped) else {
        return;
    };

    let global = scope.get_current_context().global(scope);
    let _ = set(scope, global, "require", wrapped.into());
    rn_core::hook_slot::replace_require(scope, wrapped);
}

/// Installs the globals that only need bindings which already exist.
///
/// `internal/bootstrap/node.js` is what normally defines `Buffer`,
/// `structuredClone`, `TextEncoder` and the timer functions, and it cannot run
/// until `url`, `contextify`, `v8` and `crypto` land. The modules behind these
/// four do not depend on any of those, so they are installed here to move the
/// global surface forward without waiting: each is the vendored Node
/// implementation, not a reimplementation.
///
/// Anything that needs a missing binding is skipped silently rather than half
/// installed, so a module that starts working later is picked up automatically
/// and one that does not leaves no broken global behind.
pub fn install_early_globals(scope: &mut v8::PinScope, loaders: &Bootstrapped) {
    let Some(require) = loaders.require.as_ref() else {
        return;
    };
    let require = v8::Local::new(scope, require);
    let global = scope.get_current_context().global(scope);

    // `structuredClone` comes straight from the messaging binding, which does a
    // real V8 serializer round trip.
    if let Some(value) = call_require(scope, require, "internal/bootstrap/realm")
        .and_then(|exports| get_property(scope, exports, "internalBinding"))
        .and_then(|binding| call_with_string(scope, binding, "messaging"))
        .and_then(|messaging| get_property(scope, messaging, "structuredClone"))
    {
        let _ = set(scope, global, "structuredClone", value);
    }

    // `TextEncoder` and `TextDecoder` live in `internal/encoding`, which only
    // needs the encoding binding.
    if let Some(encoding) = call_require(scope, require, "internal/encoding") {
        for name in ["TextEncoder", "TextDecoder"] {
            if let Some(value) = get_property(scope, encoding, name) {
                let _ = set(scope, global, name, value);
            }
        }
    }
}

fn call_require<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
    id: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let id = v8::String::new(scope, id)?;
    require.call(scope, v8::undefined(scope).into(), &[id.into()])
}

fn call_with_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    function: v8::Local<'s, v8::Value>,
    argument: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let function = v8::Local::<v8::Function>::try_from(function).ok()?;
    let argument = v8::String::new(scope, argument)?;
    function.call(scope, v8::undefined(scope).into(), &[argument.into()])
}

fn get_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Value>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let object = v8::Local::<v8::Object>::try_from(object).ok()?;
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

/// `BuiltinModule.normalizeRequirableId`, reached through the realm exports.
fn normalize_requirable_id<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
) -> Option<v8::Local<'s, v8::Function>> {
    let id = v8::String::new(scope, "internal/bootstrap/realm")?;
    let exports = require.call(scope, v8::undefined(scope).into(), &[id.into()])?;
    let exports = v8::Local::<v8::Object>::try_from(exports).ok()?;
    let key = v8::String::new(scope, "BuiltinModule")?;
    let builtin_module = exports.get(scope, key.into())?;
    let builtin_module = v8::Local::<v8::Function>::try_from(builtin_module).ok()?;
    let key = v8::String::new(scope, "normalizeRequirableId")?;
    let normalize = builtin_module.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(normalize).ok()
}

/// Runs the bootstrap and returns the loaders it created.
pub fn bootstrap_realm(
    scope: &mut v8::PinScope,
    registry: &'static rn_core::BindingRegistry,
    script_args: &[String],
    exec_argv: &[String],
) -> Result<Bootstrapped, String> {
    let global = scope.get_current_context().global(scope);

    let primordials = v8::Object::new(scope);
    run_per_context(scope, primordials)?;

    let process = process_object(scope, script_args, exec_argv)?;
    set(scope, global, "process", process.into())?;
    // `realm.js` reads `primordials` as a bare global inside its wrapper, so the
    // object has to be reachable both there and through the parameter below.
    set(scope, global, "primordials", primordials.into())?;

    let get_linked_binding = function_of(scope, "getLinkedBinding", get_linked_binding)?;
    let get_internal_binding = internal_binding_dispatcher(scope, registry)?;

    let realm = builtin_by_id("internal/bootstrap/realm")
        .ok_or("the realm bootstrap is missing from the builtin table")?;
    let function = rn_builtins::compile(scope, realm.id(), realm.source(), realm.kind())
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
        internal_binding: rn_core::hook_slot::internal_binding(scope)
            .map(|function| v8::Global::new(scope, function)),
        require: require.map(|function| v8::Global::new(scope, function)),
    })
}

/// Runs `internal/per_context/primordials` with the parameters its kind declares.
fn run_per_context(
    scope: &mut v8::PinScope,
    primordials: v8::Local<v8::Object>,
) -> Result<(), String> {
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
/// Builds the `process` object, including the script arguments as `argv`.
fn process_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    script_args: &[String],
    exec_argv: &[String],
) -> Result<v8::Local<'s, v8::Object>, String> {
    let process = v8::Object::new(scope);

    let load_list = v8::Array::new(scope, 0);
    set(scope, process, "moduleLoadList", load_list.into())?;

    let versions = v8::Object::new(scope);
    let v8_version =
        v8::String::new(scope, v8::V8::get_version()).ok_or("cannot allocate the V8 version")?;
    set(scope, versions, "v8", v8_version.into())?;
    let node_version = v8::String::new(scope, "28.0.0").ok_or("cannot allocate a version")?;
    set(scope, versions, "node", node_version.into())?;
    set(scope, process, "versions", versions.into())?;

    let version = v8::String::new(scope, "v28.0.0").ok_or("cannot allocate a version")?;
    set(scope, process, "version", version.into())?;

    // These are the platform facts `os.arch()`, `os.platform()` and
    // `process.release` read straight back out, so they have to be the real
    // values rather than placeholders. `internal/bootstrap/node.js` normally
    // sets them through `patchProcessObject`; that file cannot run yet, and a
    // hardcoded "linux" would be wrong on macOS and Windows.
    let platform = node_platform();
    let platform = v8::String::new(scope, platform).ok_or("cannot allocate the platform name")?;
    set(scope, process, "platform", platform.into())?;
    let arch =
        v8::String::new(scope, node_arch()).ok_or("cannot allocate the architecture name")?;
    set(scope, process, "arch", arch.into())?;

    let release = v8::Object::new(scope);
    let release_name = v8::String::new(scope, "node").ok_or("cannot allocate the release name")?;
    set(scope, release, "name", release_name.into())?;
    set(scope, process, "release", release.into())?;

    // `process.argv` is `[execPath, ...scriptArgs]`, so the executing script's
    // arguments have to be visible here or `process.argv` lies about what ran.
    // `script_args` already carries the resolved script path in front when one
    // was given, which is where Node puts it too.
    let exec_path = std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| std::env::args().next().unwrap_or_default());
    let mut argv_values = vec![exec_path];
    argv_values.extend(script_args.iter().cloned());
    let argv = v8::Array::new(scope, argv_values.len() as i32);
    for (index, value) in argv_values.iter().enumerate() {
        if let Some(text) = v8::String::new(scope, value) {
            argv.set_index(scope, index as u32, text.into());
        }
    }
    set(scope, process, "argv", argv.into())?;
    // `execArgv` is the runtime flags a child process would inherit, so it keeps
    // `-e`/`-p` and their source but never the executable or the script path.
    let exec_array = v8::Array::new(scope, exec_argv.len() as i32);
    for (index, value) in exec_argv.iter().enumerate() {
        if let Some(text) = v8::String::new(scope, value) {
            exec_array.set_index(scope, index as u32, text.into());
        }
    }
    set(scope, process, "execArgv", exec_array.into())?;
    set(scope, process, "env", v8::Object::new(scope).into())?;

    let pid = v8::Integer::new(scope, std::process::id() as i32);
    set(scope, process, "pid", pid.into())?;

    Ok(process)
}

/// The architecture name Node uses, which is GYP's `target_arch`.
///
/// Rust says `x86_64` where GYP says `x64`, and `lib/**` compares against Node's
/// spelling: `os.arch()` returns it verbatim, and `lib/internal/*` branches on
/// `x64` and `arm64` by name.
fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "x86" => "ia32",
        "aarch64" => "arm64",
        "powerpc64" => "ppc64",
        other => other,
    }
}

/// The platform name Node uses, which is not the Rust target's OS name.
///
/// Node says `win32` and `sunos` where Rust says `windows` and `solaris`, and
/// `lib/**` compares against Node's spelling in dozens of places.
fn node_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "win32",
        "solaris" => "sunos",
        other => other,
    }
}

/// Builds `getInternalBinding`, which resolves a namespace out of the registry.
///
/// This is the single path from JavaScript to a Rust binding. An unknown
/// namespace must throw with the name in it, because the alternative is an
/// `undefined` that fails much later and much less clearly.
fn internal_binding_dispatcher<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    registry: &'static rn_core::BindingRegistry,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let external = v8::External::new(scope, registry as *const _ as *mut std::ffi::c_void);
    let template = v8::FunctionTemplate::builder(get_internal_binding)
        .data(external.into())
        .build(scope);
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
    let Some(name) = args.get(0).to_string(scope) else {
        return;
    };
    let name = name.to_rust_string_lossy(scope);

    let Ok(external) = v8::Local::<v8::External>::try_from(args.data()) else {
        throw(scope, "getInternalBinding was called without a registry");
        return;
    };
    // SAFETY: the pointer comes from a `&'static BindingRegistry` in
    // `internal_binding_dispatcher`, so it outlives every callback that can
    // read it.
    let registry = unsafe { &*(external.value() as *const rn_core::BindingRegistry) };

    match registry.install(scope, &name) {
        Ok(object) => rv.set(object.into()),
        Err(message) => throw(scope, message.as_str()),
    }
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
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}
