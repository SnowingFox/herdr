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

    // `Buffer` is the `buffer` module's own constructor, and the module is
    // requireable, so the global is a reference to the same function a script
    // gets from `require('buffer')`. `btoa` and `atob` come from the same
    // module and are installed alongside it because they share its base64
    // implementation.
    if let Some(buffer) = call_require(scope, require, "buffer") {
        for name in ["Buffer", "btoa", "atob"] {
            if let Some(value) = get_property(scope, buffer, name) {
                let _ = set(scope, global, name, value);
            }
        }
    }

    install_process_methods(scope, require, global);
}

/// Calls `function(argument)` with `undefined` as the receiver.
fn call_with_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    function: v8::Local<'s, v8::Value>,
    argument: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Value>> {
    let function = v8::Local::<v8::Function>::try_from(function).ok()?;
    function.call(scope, v8::undefined(scope).into(), &[argument])
}

/// Installs the `process` methods `internal/process/per_thread.js` wraps.
///
/// `internal/bootstrap/node.js` does this during pre-execution, which cannot run
/// yet. The wrapper is the vendored one rather than a substitute: it owns the
/// `Float64Array`s the native calls fill and turns them into the objects user
/// code sees, so `process.memoryUsage()` reports real numbers exactly as it does
/// in Node.
///
/// Nothing is installed when the module or the binding is missing, so a name
/// that does not work is visibly absent rather than present and wrong.
fn install_process_methods<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
    global: v8::Local<'s, v8::Object>,
) {
    let Some(binding) = call_require(scope, require, "internal/bootstrap/realm")
        .and_then(|exports| get_property(scope, exports, "internalBinding"))
        .and_then(|binding| call_with_string(scope, binding, "process_methods"))
    else {
        return;
    };

    let Some(per_thread) = call_require(scope, require, "internal/process/per_thread") else {
        return;
    };
    let Some(wrap) = get_property(scope, per_thread, "wrapProcessMethods") else {
        return;
    };
    let Some(wrapped) = call_with_value(scope, wrap, binding) else {
        return;
    };
    let Some(process) = get_property(scope, global.into(), "process")
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
    else {
        return;
    };

    for name in [
        "memoryUsage",
        "cpuUsage",
        "threadCpuUsage",
        "resourceUsage",
        "loadEnvFile",
        "_rawDebug",
        "kill",
        "execve",
    ] {
        if let Some(value) = get_property(scope, wrapped, name) {
            let _ = set(scope, process, name, value);
        }
    }

    // `exit` stays the bootstrap's stub: the wrapper's version calls
    // `process.reallyExit`, and replacing the stub would change what `-e` does
    // before the event loop exists.

    // `memoryUsage.rss` is `process_methods.rss`, assigned through the function
    // object rather than returned by the wrapper.
    if let (Some(memory_usage), Some(rss)) = (
        get_property(scope, wrapped, "memoryUsage"),
        get_property(scope, binding, "rss"),
    ) {
        if let Ok(function) = v8::Local::<v8::Function>::try_from(memory_usage) {
            if let Some(key) = v8::String::new(scope, "rss") {
                function.set(scope, key.into(), rss);
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

/// Installs the real CommonJS loader over the builtin-only one.
///
/// `realm.js` hands out a loader that resolves builtin ids and nothing else.
/// `lib/internal/modules/cjs/loader.js` is the loader Node actually uses: it
/// resolves relative and absolute paths, walks `node_modules`, honours
/// `package.json` `exports`, caches by resolved filename, and compiles through
/// `contextify`. Running the vendored file is the whole point of this project,
/// so this wires it up rather than reimplementing any of that.
///
/// `createRequire(filename)` produces a `require` bound to a file, which is
/// what a CommonJS module's own `require` is. For `-e` there is no file, so the
/// working directory stands in and `require('./x')` resolves relative to the
/// process's cwd the way Node's `-e` does.
pub fn install_cjs_loader<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
    script_path: &Option<String>,
) -> Result<(), String> {
    let loader = call_require(scope, require, "internal/modules/cjs/loader")
        .ok_or("internal/modules/cjs/loader did not load")?;
    let loader = v8::Local::<v8::Object>::try_from(loader)
        .map_err(|_| "the commonjs loader is not an object")?;

    // `initializeCJS` freezes the builtin id list and initialises the search
    // paths. It runs after `--expose-internals` so the internal ids are
    // included, which is why Node calls it here and not at load time.
    if let Some(initialize) = get_property(scope, loader.into(), "initializeCJS") {
        if let Ok(initialize) = v8::Local::<v8::Function>::try_from(initialize) {
            initialize
                .call(scope, loader.into(), &[])
                .ok_or("initializeCJS threw")?;
        }
    }
    let module =
        get_property(scope, loader.into(), "Module").ok_or("the commonjs loader has no Module")?;
    let module =
        v8::Local::<v8::Object>::try_from(module).map_err(|_| "Module is not an object")?;
    let create_require =
        get_property(scope, module.into(), "createRequire").ok_or("Module has no createRequire")?;
    let create_require = v8::Local::<v8::Function>::try_from(create_require)
        .map_err(|_| "createRequire is not a function")?;

    // A module's `require` is anchored at its own filename. `-e` has none, so
    // the cwd is used, which is what makes `node -e "require('./x')"` and this
    // agree.
    let anchor = match script_path {
        Some(path) => path.clone(),
        None => {
            let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
            cwd.join("evalmachine.<anonymous>")
                .to_string_lossy()
                .into_owned()
        }
    };
    let Some(anchor) = v8::String::new(scope, &anchor) else {
        return Err("cannot allocate the require anchor".to_string());
    };
    let file_require = create_require
        .call(scope, module.into(), &[anchor.into()])
        .ok_or("createRequire threw")?;
    let file_require = v8::Local::<v8::Function>::try_from(file_require)
        .map_err(|_| "createRequire did not return a function")?;
    let file_require = v8::Global::new(scope, file_require);

    let global = scope.get_current_context().global(scope);
    let file_require = v8::Local::new(scope, file_require);
    // Only the global `require` is replaced. `hook_slot` keeps the realm loader
    // on purpose: every builtin compiled after the realm bootstrap closes over
    // it, and `lib/zlib.js` requires `internal/streams/transform` through that
    // closure. Swapping the slot would send a builtin's own internal requires
    // through the filesystem loader, where `internal/...` is not a path.
    //
    // The global gets a wrapper instead of the raw file loader so a specifier
    // the loader cannot resolve as a path still reaches the realm loader. That
    // is what keeps `--expose-internals` working: `require('internal/util')` is
    // a builtin, not a file, and the CommonJS loader would look for a directory
    // of that name.
    let global_require = wrap_cjs_require_with_builtin_fallback(scope, file_require, require)
        .unwrap_or(file_require);
    set(scope, global, "require", global_require.into())?;

    // `module` and `exports` are globals in a CommonJS module's scope, and a
    // script run from a file expects them the way Node provides them.
    for name in ["module", "exports", "__filename", "__dirname"] {
        if let Some(value) = get_property(scope, module.into(), name) {
            let _ = set(scope, global, name, value);
        }
    }
    Ok(())
}

/// Wraps the CommonJS `require` so a builtin id still resolves.
///
/// The CommonJS loader handles `node:` ids itself through
/// `BuiltinModule.normalizeRequirableId`, but a bare `internal/...` id is only
/// a builtin when `--expose-internals` put it in the user-facing list, and even
/// then the loader resolves it through `BuiltinModule` rather than the
/// filesystem. This tries the file loader first and falls back to the realm
/// loader, which is the loader that knows every builtin id.
fn wrap_cjs_require_with_builtin_fallback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    file_require: v8::Local<'s, v8::Function>,
    realm_require: v8::Local<'s, v8::Function>,
) -> Option<v8::Local<'s, v8::Function>> {
    // A V8 callback cannot capture the two loaders, so the wrapper is built in
    // JavaScript the same way the `node:` wrapper is.
    let source = "(function (fileRequire, realmRequire) {\n\
                  \x20 function isBuiltinId(id) {\n\
                  \x20   return typeof id === 'string' &&\n\
                  \x20     (id.startsWith('internal/') || id.startsWith('node:'));\n\
                  \x20 }\n\
                  \x20 return function require(id) {\n\
                  \x20   if (isBuiltinId(id)) {\n\
                  \x20     try { return realmRequire(id.replace(/^node:/, '')); }\n\
                  \x20     catch (error) {\n\
                  \x20       if (!/Missing internal module/.test(String(error && error.message))) throw error;\n\
                  \x20     }\n\
                  \x20   }\n\
                  \x20   return fileRequire(id);\n\
                  \x20 };\n\
                  })";
    let source = v8::String::new(scope, source)?;
    let factory = v8::Script::compile(scope, source, None)?;
    let factory = factory.run(scope)?;
    let factory = v8::Local::<v8::Function>::try_from(factory).ok()?;
    let wrapped = factory.call(
        scope,
        v8::undefined(scope).into(),
        &[file_require.into(), realm_require.into()],
    )?;
    v8::Local::<v8::Function>::try_from(wrapped).ok()
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
    // `lib/internal/util.js` decides at module scope whether crypto exists by
    // reading `process.versions.openssl`: `const noCrypto =
    // !process.versions.openssl`. Without it, `require('crypto')` throws
    // ERR_NO_CRYPTO even though the binding is installed and working, so this
    // has to be the version the binary actually linked, not a placeholder.
    let openssl_version = v8::String::new(scope, &rn_bind_crypto::engine::openssl_version())
        .ok_or("cannot allocate the OpenSSL version")?;
    set(scope, versions, "openssl", openssl_version.into())?;
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

    // `process.execPath` and `process.env` are not decoration: the CommonJS
    // loader's `Module._initPaths` resolves the global module search path from
    // `path.resolve(process.execPath, '..', '..')`, and `path.resolve` of
    // `undefined` throws inside `Module._initPaths`. `process.env` is read the
    // same way through `safeGetenv('HOME')`.
    let exec_path = std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(value) = v8::String::new(scope, &exec_path) {
        set(scope, process, "execPath", value.into())?;
    }
    let env = v8::Object::new(scope);
    for (key, value) in std::env::vars() {
        if let (Some(key), Some(value)) =
            (v8::String::new(scope, &key), v8::String::new(scope, &value))
        {
            let _ = env.set(scope, key.into(), value.into());
        }
    }
    set(scope, process, "env", env.into())?;

    // `process.features` is read at module scope by `lib/internal/crypto/**`,
    // which destructures `openssl_is_boringssl` immediately. Each flag must
    // report what this binary actually has: a `true` for a subsystem that does
    // not exist turns a clear "missing" into a wrong answer much later.
    let features = v8::Object::new(scope);
    let feature = |scope: &mut v8::PinScope<'_, '_>, name: &str, value: bool| {
        if let Some(key) = v8::String::new(scope, name) {
            let _ = set(scope, features, name, v8::Boolean::new(scope, value).into());
            let _ = key;
        }
    };
    // Real upstream OpenSSL is linked, not BoringSSL.
    feature(scope, "openssl_is_boringssl", false);
    // TLS itself is not implemented yet.
    for name in ["tls", "tls_alpn", "tls_sni", "tls_ocsp"] {
        feature(scope, name, false);
    }
    // The loop is libuv, and IPv6 works through it.
    feature(scope, "uv", true);
    feature(scope, "ipv6", true);
    // Builtins are compiled into the binary by `rn-js2c`.
    feature(scope, "cached_builtins", true);
    // There is no inspector and no debug build.
    feature(scope, "inspector", false);
    feature(scope, "debug", cfg!(debug_assertions));
    // Modules are requireable, and TypeScript stripping is not implemented.
    feature(scope, "require_module", true);
    if let Some(key) = v8::String::new(scope, "typescript") {
        if let Some(value) = v8::String::new(scope, "strip") {
            let _ = features.set(scope, key.into(), value.into());
        }
    }
    set(scope, process, "features", features.into())?;

    let pid = v8::Integer::new(scope, std::process::id() as i32);
    set(scope, process, "pid", pid.into())?;

    // `process.exitCode` is how a test script reports failure, and every one of
    // Node's own tests relies on it: a script that sets it and returns exits
    // with that status. It has to stay an assignment target that the CLI reads
    // on the way out, so it starts at `undefined` — Node's default — and the
    // exit path substitutes 0 for that.
    set(scope, process, "exitCode", v8::undefined(scope).into())?;

    Ok(process)
}

/// Reads `process.exitCode` the way the interpreter would use it.
///
/// Returns `None` when it is unset, which means exit 0. A value that is not a
/// number is Node's `ERR_INVALID_ARG_TYPE`, but this bootstrap has no
/// `internal/errors` to throw it with yet, so an unusable value falls back to
/// the process status rather than silently becoming 0.
pub fn read_exit_code(scope: &mut v8::PinScope) -> Option<i32> {
    let global = scope.get_current_context().global(scope);
    let process = get_property(scope, global.into(), "process")?;
    let code = get_property(scope, process, "exitCode")?;
    if code.is_undefined() || code.is_null() {
        return None;
    }
    code.integer_value(scope).map(|code| code as i32)
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
