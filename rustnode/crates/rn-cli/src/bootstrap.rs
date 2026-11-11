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
    let _ = set_global(scope, global, "require", wrapped.into());
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
        let _ = set_global(scope, global, "structuredClone", value);
    }

    // `TextEncoder` and `TextDecoder` live in `internal/encoding`, which only
    // needs the encoding binding.
    if let Some(encoding) = call_require(scope, require, "internal/encoding") {
        for name in ["TextEncoder", "TextDecoder"] {
            if let Some(value) = get_property(scope, encoding, name) {
                let _ = set_global(scope, global, name, value);
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
                let _ = set_global(scope, global, name, value);
            }
        }
    }

    install_process_methods(scope, require, global);
    install_web_globals(scope);
    install_async_hooks_native_hooks(scope, require);
}

/// Hands `async_wrap` the callbacks `AsyncWrap` calls for its own resources.
///
/// `internal/bootstrap/node.js` does exactly this, immediately after `process`
/// exists and before any user code:
///
/// ```js
/// const { nativeHooks } = require('internal/async_hooks');
/// internalBinding('async_wrap').setupHooks(nativeHooks);
/// ```
///
/// Without it, `async_hook_fields[kInit]` counts the hooks a script enabled but
/// `setupHooks` has no functions to call, so a native `init` or `destroy` —
/// `TCPWrap`'s on construction and on `asyncReset`, and every deferred
/// `emitDestroy` — is emitted into nothing. The JavaScript layer still reports
/// ids, which is why the gap was invisible: `getAsyncId()` answered correctly and
/// only the hooks were missing.
///
/// It runs after `install_early_globals` rather than before because
/// `internal/async_hooks` reads `internalBinding('errors')` at module scope, and
/// that namespace is only reliably installed once the realm bootstrap has
/// finished.
fn install_async_hooks_native_hooks<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
) {
    let Some(internal) = call_require(scope, require, "internal/async_hooks") else {
        return;
    };
    let Some(native_hooks) = get_property(scope, internal, "nativeHooks") else {
        return;
    };
    let Some(binding) = rn_core::hook_slot::internal_binding(scope) else {
        return;
    };
    let Some(name) = v8::String::new(scope, "async_wrap") else {
        return;
    };
    let Some(binding) = binding.call(scope, v8::undefined(scope).into(), &[name.into()]) else {
        return;
    };
    let Ok(binding) = v8::Local::<v8::Object>::try_from(binding) else {
        return;
    };
    let Some(setup) = get_property(scope, binding.into(), "setupHooks") else {
        return;
    };
    let Ok(setup) = v8::Local::<v8::Function>::try_from(setup) else {
        return;
    };
    let _ = setup.call(scope, binding.into(), &[native_hooks]);
}

/// Installs the web globals `test/common/index.js` needs before its first test.
///
/// Node's `pre_execution.js` runs `internal/bootstrap/web/exposed-wildcard`,
/// which installs every `[Exposed=*]` interface. That module cannot run here: it
/// reads `config.hasInspector`, which is `true` because the inspector is built
/// into a real Node, and this build has no `inspector` binding at all, so the
/// console setup throws and the whole module aborts before the globals are
/// installed.
///
/// So the interfaces are installed directly, through the same
/// `exposeLazyInterfaces` helper the module uses. A lazy interface is a getter
/// that loads its module on first access, which is what keeps `require('fs')`
/// from pulling in `abort_controller` at startup.
fn install_web_globals<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let Some(internal_binding) = rn_core::hook_slot::internal_binding(scope) else {
        return;
    };
    let Some(require) = rn_core::hook_slot::require(scope) else {
        return;
    };
    let Some(util) = call_require(scope, require, "internal/util") else {
        return;
    };
    let Some(expose_lazy) = get_property(scope, util, "exposeLazyInterfaces") else {
        return;
    };
    let Ok(expose_lazy) = v8::Local::<v8::Function>::try_from(expose_lazy) else {
        return;
    };

    let global = scope.get_current_context().global(scope);
    // `(target, moduleId, names)`.
    for (module, names) in [
        (
            "internal/abort_controller",
            &["AbortController", "AbortSignal"][..],
        ),
        ("internal/event_target", &["CustomEvent"][..]),
        ("internal/encoding", &["TextEncoder", "TextDecoder"][..]),
        // `util.inspect`'s own test reads `ReadableStream`, and it is an
        // `[Exposed=*]` interface in Node's `exposed-wildcard` bootstrap. The
        // module loads fine here, so this is wiring rather than implementation.
        (
            "internal/webstreams/readablestream",
            &["ReadableStream"][..],
        ),
        (
            "internal/webstreams/writablestream",
            &["WritableStream"][..],
        ),
        (
            "internal/webstreams/transformstream",
            &["TransformStream"][..],
        ),
        (
            "internal/webstreams/queuingstrategies",
            &["ByteLengthQueuingStrategy", "CountQueuingStrategy"][..],
        ),
        // `internal/deps/undici/undici` reads these three at module scope
        // (`webidl.is.Blob = MakeTypeAssertion(Blob)` and neighbours), so a
        // global object whose descriptors get walked — which
        // `test-util-inspect.js` does through `fullObjectGraph(globalThis)` —
        // forces undici to load and fails without them. Node installs them from
        // `internal/bootstrap/web/exposed-window-or-worker.js`, the same module
        // this function mirrors.
        ("internal/worker/io", &["MessageChannel", "MessagePort"][..]),
        ("internal/blob", &["Blob"][..]),
        ("internal/file", &["File"][..]),
    ] {
        let (Some(id), Some(array)) = (v8::String::new(scope, module), names_array(scope, names))
        else {
            continue;
        };
        let _ = expose_lazy.call(scope, util, &[global.into(), id.into(), array.into()]);
    }

    // WebCrypto, from the `exposed-window-or-worker` half of Node's web
    // bootstrap. It is not in `exposed-wildcard`, so the loop above never
    // installs it, and a script run as a file therefore had no `crypto` global
    // at all — `globalThis.crypto.subtle` was `undefined` in 82 files. `-e` mode
    // hid this, because `addBuiltinLibsToObject` installs every builtin as a
    // lazy global and `crypto` then resolves to the `node:crypto` module.
    //
    // The shape is Node's: `crypto` is replaceable so a script may assign it and
    // the three constructors are plain lazy interfaces. Node gates this block on
    // `internalBinding('config').hasOpenSSL`; this build always links OpenSSL —
    // `process.versions.openssl` is read from the linked library above — so the
    // branch is unconditional rather than read from a config field that is a
    // constant here.
    if let Some(define_lazy) = get_property(scope, util, "defineReplaceableLazyAttribute") {
        if let Ok(define_lazy) = v8::Local::<v8::Function>::try_from(define_lazy) {
            if let (Some(id), Some(keys)) = (
                v8::String::new(scope, "internal/crypto/webcrypto"),
                names_array(scope, &["crypto"]),
            ) {
                let _ = define_lazy.call(
                    scope,
                    util,
                    &[
                        global.into(),
                        id.into(),
                        keys.into(),
                        v8::Boolean::new(scope, false).into(),
                    ],
                );
            }
        }
    }
    for name in ["Crypto", "CryptoKey", "SubtleCrypto"] {
        if let (Some(id), Some(array)) = (
            v8::String::new(scope, "internal/crypto/webcrypto"),
            names_array(scope, &[name]),
        ) {
            let _ = expose_lazy.call(scope, util, &[global.into(), id.into(), array.into()]);
        }
    }

    // `DOMException` is an `[Exposed=*]` interface that
    // `internal/bootstrap/web/exposed-wildcard.js` publishes through
    // `internalBinding('messaging').exposeLazyDOMExceptionProperty(globalThis)`.
    // That module cannot run here — it aborts on the missing `inspector`
    // binding — so the same binding call is made directly. `internal/blob.js`
    // and `internal/util.js` construct it, and Node's own
    // `test/parallel/test-util-inspect.js` inspects its prototype.
    if let Some(namespace) = v8::String::new(scope, "messaging") {
        if let Some(messaging) = internal_binding.call(scope, global.into(), &[namespace.into()]) {
            if let Some(expose) = get_property(scope, messaging, "exposeLazyDOMExceptionProperty") {
                if let Ok(expose) = v8::Local::<v8::Function>::try_from(expose) {
                    let _ = expose.call(scope, messaging, &[global.into()]);
                }
            }
        }
    }

    // `URL` and `URLSearchParams` are not lazy in Node: `internal/url` is small
    // and needed by the loader itself.
    if let Some(url) = call_require(scope, require, "internal/url") {
        for name in ["URL", "URLSearchParams"] {
            if let Some(value) = get_property(scope, url, name) {
                let _ = set_global(scope, global, name, value);
            }
        }
    }

    // `Event` and `EventTarget` come from `internal/event_target`, which is the
    // base class `MessagePort` is re-parented onto, so they have to be real
    // rather than a second implementation.
    if let Some(events) = call_require(scope, require, "internal/event_target") {
        for name in ["Event", "EventTarget", "CustomEvent"] {
            if let Some(value) = get_property(scope, events, name) {
                let _ = set_global(scope, global, name, value);
            }
        }
    }

    // `global` is Node's alias for `globalThis`, and `test/common` and many
    // fixtures assign through it.
    let _ = set_global(scope, global, "global", global.into());

    install_process_event_emitter(scope, require, global);

    // The `undici` interfaces are exposed lazily in Node too: `fetch` loads the
    // module on first call and the classes load it on first access, which is what
    // keeps `require('fs')` from pulling in the whole HTTP client.
    for (module, names) in [
        (
            "internal/deps/undici/undici",
            &[
                "FormData",
                "Headers",
                "Request",
                "Response",
                "MessageEvent",
                "CloseEvent",
                "ErrorEvent",
            ][..],
        ),
        ("perf_hooks", &["performance"][..]),
    ] {
        let (Some(id), Some(array)) = (v8::String::new(scope, module), names_array(scope, names))
        else {
            continue;
        };
        let _ = expose_lazy.call(scope, util, &[global.into(), id.into(), array.into()]);
    }

    // `fetch` is a function rather than a lazy interface: Node defines it as an
    // ordinary property whose body loads `undici` on first call, so that even
    // reading `typeof fetch` does not compile the client.
    if let Some(fetch) = lazy_fetch(scope, require) {
        let _ = set_global(scope, global, "fetch", fetch);
    }
    let _ = internal_binding;
}

/// Makes `process` an `EventEmitter`.
///
/// `internal/bootstrap/node.js` does this by
/// `ObjectSetPrototypeOf(process, EventEmitter.prototype)`, and the whole of
/// `test/common` plus most of `lib/**` depends on it: `process.on('exit', ...)`
/// is the first thing many tests do, and `process.emit` is how Node signals
/// `uncaughtException`, `warning` and `worker`.
///
/// It runs here rather than inside `process_object` because the `events` module
/// cannot be required until the realm bootstrap has installed the loaders.
fn install_process_event_emitter<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
    global: v8::Local<'s, v8::Object>,
) {
    let Some(process) = get_property(scope, global.into(), "process")
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
    else {
        return;
    };
    let Some(events) = call_require(scope, require, "events") else {
        return;
    };
    let Some(prototype) = get_property(scope, events, "EventEmitter")
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .and_then(|constructor| get_property(scope, constructor.into(), "prototype"))
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
    else {
        return;
    };
    process.set_prototype(scope, prototype.into());

    // `process.hrtime`, `process.hrtime.bigint`, `process.uptime` and
    // `process.emitWarning` come from the same pre-execution setup. `hrtime` is
    // destructured by `test/common` and most of `lib/**` reads it, and
    // `emitWarning` is how the loader reports a deprecation, so both have to be
    // the vendored implementations rather than stubs.
    install_process_execution_methods(scope, require, process);
}

/// Installs `hrtime`, `uptime` and `emitWarning` on `process`.
///
/// `internal/process/per_thread.js` owns the `hrtime` wrappers and
/// `internal/process/warning.js` owns `emitWarning`; both are run rather than
/// reimplemented so the `Float64Array` handling and the warning queue are Node's.
fn install_process_execution_methods<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
    process: v8::Local<'s, v8::Object>,
) {
    if let Some(per_thread) = call_require(scope, require, "internal/process/per_thread") {
        for name in ["hrtime", "hrtimeBigInt"] {
            if let Some(value) = get_property(scope, per_thread, name) {
                let target = if name == "hrtimeBigInt" {
                    // `process.hrtime.bigint`, not a separate global.
                    let Some(hrtime) = get_property(scope, process.into(), "hrtime")
                        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
                    else {
                        continue;
                    };
                    hrtime
                } else {
                    process
                };
                let key = if name == "hrtimeBigInt" {
                    "bigint"
                } else {
                    "hrtime"
                };
                let _ = set(scope, target, key, value);
            }
        }
    }

    if let Some(warning) = call_require(scope, require, "internal/process/warning") {
        if let Some(value) = get_property(scope, warning, "emitWarning") {
            let _ = set(scope, process, "emitWarning", value);
        }
    }

    // `process.uptime` is a plain binding method.
    if let Some(value) = call_require(scope, require, "internal/bootstrap/realm")
        .and_then(|exports| get_property(scope, exports, "internalBinding"))
        .and_then(|binding_fn| call_with_string(scope, binding_fn, "process_methods"))
        .and_then(|methods| get_property(scope, methods, "uptime"))
    {
        let _ = set(scope, process, "uptime", value);
    }
}

/// Builds Node's lazily-loading `fetch`.
///
/// A V8 callback cannot capture the loader, so the wrapper is written in
/// JavaScript and given `require` as an argument, which is the same technique
/// `wrap_require_with_scheme_support` uses for the same reason.
fn lazy_fetch<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
) -> Option<v8::Local<'s, v8::Value>> {
    let source = "(function (require) {\n\
                  \x20 let impl;\n\
                  \x20 return function fetch(input, init = undefined) {\n\
                  \x20   if (!impl) impl = require('internal/deps/undici/undici').fetch;\n\
                  \x20   return impl(input, init);\n\
                  \x20 };\n\
                  })";
    let source = v8::String::new(scope, source)?;
    let factory = v8::Script::compile(scope, source, None)?.run(scope)?;
    let factory = v8::Local::<v8::Function>::try_from(factory).ok()?;
    factory.call(scope, v8::undefined(scope).into(), &[require.into()])
}

/// Builds a JavaScript string array from `names`.
fn names_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    names: &[&str],
) -> Option<v8::Local<'s, v8::Array>> {
    let array = v8::Array::new(scope, names.len() as i32);
    for (index, name) in names.iter().enumerate() {
        let value = v8::String::new(scope, name)?;
        array.set_index(scope, index as u32, value.into());
    }
    Some(array)
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

    // `internal/bootstrap/node.js` copies the POSIX credential getters onto
    // `process` when the binding reports support:
    //
    // ```js
    // const credentials = internalBinding('credentials');
    // if (credentials.implementsPosixCredentials) {
    //   process.getuid = credentials.getuid;
    //   ...
    // }
    // ```
    //
    // That bootstrap module cannot run here, so the same five assignments are
    // made directly. They are ordinary assignments, not definitions: Node writes
    // them the same way, which is why `process.getuid` is enumerable and
    // replaceable.
    if let Some(credentials) = call_require(scope, require, "internal/bootstrap/realm")
        .and_then(|exports| get_property(scope, exports, "internalBinding"))
        .and_then(|binding| call_with_string(scope, binding, "credentials"))
        .and_then(|credentials| v8::Local::<v8::Object>::try_from(credentials).ok())
    {
        for name in ["getuid", "geteuid", "getgid", "getegid", "getgroups"] {
            if let Some(value) = get_property(scope, credentials.into(), name) {
                let _ = set(scope, process, name, value);
            }
        }
    }

    // The uncaught-exception hooks and `_fatalException`, which
    // `internal/bootstrap/node.js` installs from `internal/process/execution`:
    //
    // ```js
    // process._fatalException = onGlobalUncaughtException;
    // process.setUncaughtExceptionCaptureCallback = setUncaughtExceptionCaptureCallback;
    // process.addUncaughtExceptionCaptureCallback = addUncaughtExceptionCaptureCallback;
    // process.hasUncaughtExceptionCaptureCallback = hasUncaughtExceptionCaptureCallback;
    // ```
    //
    // `lib/domain.js` calls `setUncaughtExceptionCaptureCallback` and
    // `internal/errors.js` names it in a message, so a missing one is a
    // `TypeError` from inside the domain machinery.
    if let Some(execution) = call_require(scope, require, "internal/process/execution") {
        for name in [
            "onGlobalUncaughtException",
            "setUncaughtExceptionCaptureCallback",
            "addUncaughtExceptionCaptureCallback",
            "hasUncaughtExceptionCaptureCallback",
        ] {
            // `_fatalException` is the name `onGlobalUncaughtException` is
            // installed under; the rest keep their own.
            let target = if name == "onGlobalUncaughtException" {
                "_fatalException"
            } else {
                name
            };
            if let Some(value) = get_property(scope, execution, name) {
                let _ = set(scope, process, target, value);
            }
        }
    }

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

    // `process.exit` is `process.reallyExit` behind a check, and the wrapper's
    // version is used here. The comment that used to sit here said `exit` stayed
    // the bootstrap's stub because the wrapper calls `process.reallyExit`, but
    // the stub was `globalThis.__exit`, which nothing ever set, so `process.exit`
    // was a no-op function. `test/common` calls it, and any program that exits
    // early needs it, so the real wrapper is installed and `reallyExit` is
    // supplied from the binding.
    if let Some(value) = get_property(scope, wrapped, "exit") {
        let _ = set(scope, process, "exit", value);
    }
    if let Some(value) = get_property(scope, binding, "reallyExit") {
        let _ = set(scope, process, "reallyExit", value);
    }

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

    // `process.abort`, `umask`, `chdir` and `cwd` come from Node's
    // `does_own_process_state` switch, which also installs the credential
    // setters. Running the vendored module instead of assigning each by hand
    // keeps the argument validation (`parseFileMode`, the cwd cache) exactly as
    // Node has it; `test/common/index.js` calls `process.umask(0o022)` before any
    // test runs, so a missing `umask` aborts the whole suite.
    if let Some(message) = install_process_state_switch(scope) {
        eprintln!("rustnode: process state unavailable: {message}");
    }
}

/// Runs `internal/bootstrap/switches/does_own_process_state`.
///
/// Node picks between this and `does_not_own_process_state` per environment; the
/// main thread owns the process, and `is_main_thread` is the switch that selects
/// this one.
///
/// This module is classified as a *bootstrap script*, not a function builtin: its
/// id starts with `internal/bootstrap/`, so `kind_for` compiles it with
/// `(process, require, internalBinding, primordials)`. It therefore cannot be
/// reached through the ordinary `require`, which would call it as a CommonJS
/// function and leave `internalBinding` undefined. Calling it here is the same
/// thing `BuiltinLoader::CompileAndCall` does for a bootstrap script.
fn install_process_state_switch<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<String> {
    run_bootstrap_script(scope, "internal/bootstrap/switches/does_own_process_state")
}

/// Runs one `internal/bootstrap/**` script with the parameters its kind declares.
///
/// Returns the script's error message when it threw, which is more useful than
/// silence: these scripts install the `process` surface and a half-applied one is
/// worse than a reported gap.
pub fn run_bootstrap_script(scope: &mut v8::PinScope<'_, '_>, id: &str) -> Option<String> {
    let builtin = rn_js2c::builtin_by_id(id)?;
    let function = rn_builtins::compile(scope, builtin.id(), builtin.source(), builtin.kind())?;
    let global = scope.get_current_context().global(scope);
    let process = get_property(scope, global.into(), "process")?;
    let require = rn_core::hook_slot::require(scope)?;
    let internal_binding = rn_core::hook_slot::internal_binding(scope)?;
    let primordials = primordials_from_global(scope)?;
    let arguments = [
        process,
        require.into(),
        internal_binding.into(),
        primordials,
    ];
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let _ = function.call(scope, v8::undefined(scope).into(), &arguments);
    if scope.has_caught() {
        return Some(
            scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(scope))
                .unwrap_or_default(),
        );
    }
    None
}

/// Installs `process.stdout`, `stdin` and `stderr` from Node's own bootstrap.
///
/// Node defines all three as lazy getters in
/// `internal/bootstrap/switches/is_main_thread.js`, which is why every
/// `process.stdout` accessor in `lib/**` assumes a real `tty.WriteStream` or
/// `net.Socket` with `on`/`once`/`removeListener` on it. Without this,
/// `process.stdout` is `undefined`, `patchProcessObject`'s
/// `initializeGlobalConsole(globalConsole)` binds a console to nothing, and the
/// first `console.error` — which is what `process.emitWarning` reaches for —
/// throws `Cannot read properties of undefined (reading 'removeListener')`
/// instead of printing.
///
/// `internal/bootstrap/node.js` runs this during the real bootstrap; the CLI
/// could not earlier because it needs `tty_wrap` and `internal/process/signal`,
/// both of which exist now.
pub fn install_stdio<'s>(scope: &mut v8::PinScope<'s, '_>) {
    if let Some(message) = run_bootstrap_script(scope, "internal/bootstrap/switches/is_main_thread")
    {
        eprintln!("rustnode: stdio unavailable: {message}");
    }
}

/// Replaces the bootstrap's `console` stub with Node's real global console.
///
/// The stub in `bootstrap.js` writes with a synchronous native call straight to
/// descriptor 1. That is *not* what `console.log` does in Node: the real console
/// is a `Console` bound to `process.stdout`/`process.stderr`, so its output goes
/// through the same writable stream, and therefore through the same ordered write
/// queue. The difference is observable the moment those two are mixed:
///
/// ```text
/// process.stdout.write('A'); process.stdout.write('B'); console.log('C');
/// ```
///
/// prints `ABC` in Node and `ACB` with the stub, because the stub bypasses the
/// queue `A` and `B` are still sitting in.
///
/// `internal/console/global` is the module `lib/console.js` re-exports, and its
/// `Console` binds to `process.stdout` lazily on first use — which is why this
/// has to run *after* [`install_stdio`], or the binding captures nothing.
///
/// Nothing is installed when the module is missing, so a broken console stays a
/// missing name instead of a half-built one.
pub fn install_console<'s>(scope: &mut v8::PinScope<'s, '_>, require: v8::Local<'s, v8::Function>) {
    let Some(console) = call_require(scope, require, "internal/console/global") else {
        return;
    };
    let global = scope.get_current_context().global(scope);
    if let Some(key) = v8::String::new(scope, "console") {
        global.set(scope, key.into(), console);
    }
}

/// Reads the `primordials` global the realm bootstrap installs.
fn primordials_from_global<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Value>> {
    let global = scope.get_current_context().global(scope);
    get_property(scope, global.into(), "primordials")
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
    set_global(scope, global, "require", global_require.into())?;

    // `module`, `exports`, `__filename` and `__dirname` are CommonJS wrapper
    // parameters, not globals, so the real values are installed by
    // [`run_main_module`] for the entry file and by the wrapper for every
    // `require()`d module. The loader's `Module` constructor has no static
    // values to mirror here.
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

/// Runs `internal/process/pre_execution` before any user code.
///
/// Node's entry point is not the script: `internal/main/run_main_module`
/// requires `prepareMainThreadExecution()` and only then calls
/// `Module.runMain`. That function is what installs the ESM loader
/// (`initializeESM`), the extension format map, the `process` methods and the
/// `--require` preloads, and it asserts at the end that no user module has run
/// yet — so calling it from user code cannot work. `Module._compile` sets the
/// guard the moment it evaluates a user file, and `initializeModuleLoaders`
/// then throws `ERR_INTERNAL_ASSERTION`.
///
/// That is the whole reason a `.mjs` entry point failed with
/// `ERR_INTERNAL_ASSERTION`: the CLI ran the script through the CommonJS
/// loader, which delegated to the ESM loader, which found its own one-time
/// initialization had never happened and could no longer happen.
///
/// A failure is reported rather than fatal: the steps below it have all worked
/// without pre-execution so far, and a precise message is more useful than
/// refusing to start.
pub fn prepare_execution<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
) {
    let Some(pre_execution) = call_require(scope, require, "internal/process/pre_execution") else {
        eprintln!(
            "rustnode: pre-execution unavailable: internal/process/pre_execution did not load"
        );
        return;
    };
    let Some(prepare) = get_property(scope, pre_execution, "prepareMainThreadExecution") else {
        return;
    };
    let Ok(prepare) = v8::Local::<v8::Function>::try_from(prepare) else {
        return;
    };
    // `expandArgv1` is false: the CLI has already resolved the entry point into
    // `process.argv`, and letting pre-execution re-resolve it would run Node's
    // `Module._findPath` a second time without changing the answer.
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let expand_argv1: v8::Local<v8::Value> = v8::Boolean::new(scope, false).into();
    let _ = prepare.call(scope, pre_execution, &[expand_argv1]);
    if scope.has_caught() {
        let message = scope
            .exception()
            .map(|exception| exception.to_rust_string_lossy(scope))
            .unwrap_or_default();
        eprintln!("rustnode: pre-execution failed: {message}");
    }
}

/// Loads `filename` as the main module, through Node's own entry-point path.
///
/// `internal/modules/run_main` is what decides between the CommonJS loader and
/// the ESM loader, and it is the same function `Module.runMain` exposes, so the
/// decision procedure is Node's rather than a reimplementation here: `.mjs`,
/// `.wasm` and a `.js` inside a `"type": "module"` package go to the ESM loader,
/// everything else to the CommonJS loader.
///
/// It returns a promise when the entry point's graph has a top-level await. The
/// caller has to drain the microtask queue for it, which is why the value is
/// returned instead of dropped.
pub fn run_main<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
    filename: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let run_main = call_require(scope, require, "internal/modules/run_main")?;
    let execute = get_property(scope, run_main, "executeUserEntryPoint")?;
    let execute = v8::Local::<v8::Function>::try_from(execute).ok()?;
    let filename = v8::String::new(scope, filename)?;
    execute.call(scope, v8::undefined(scope).into(), &[filename.into()])
}

/// Runs the realm bootstrap and returns the loaders it created.
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
    set_global(scope, global, "process", process.into())?;
    // `realm.js` reads `primordials` as a bare global inside its wrapper, so the
    // object has to be reachable both there and through the parameter below.
    set_global(scope, global, "primordials", primordials.into())?;

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
        set_global(scope, global, "require", require.into())?;
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
    // The libuv the binary actually links, from `uv_version_string`. Node's test
    // suite branches on this: `test-blocklist.js` expects an overlong zone
    // suffix on a mixed-notation IPv6 address to parse only from libuv 1.53, so
    // a missing value would fail with a `split` of `undefined` rather than a
    // statement about the runtime.
    let uv_version = rn_uv::uv_version_string()
        .and_then(|version| v8::String::new(scope, &version))
        .ok_or("cannot allocate the libuv version")?;
    set(scope, versions, "uv", uv_version.into())?;
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

    // `process.config` is serialized `config.gypi`: `internal/bootstrap/node.js`
    // parses `internalBinding('builtins').config` and freezes the result. The
    // whole of `test/common/index.js` reads `process.config.variables`
    // immediately, so a missing `config` aborts every test in the suite.
    //
    // The object is built here rather than by parsing that JSON again because
    // the `builtins` namespace's `config` string is the same one this
    // reproduces, and doing it natively means it is available before any
    // builtin that might read it.
    let config = v8::Object::new(scope);
    let config_variables = v8::Object::new(scope);
    // The keys `test/common` and `lib/**` actually branch on. A key that is
    // present but wrong is worse than an absent one, so only what this build
    // genuinely has is listed.
    for (name, value) in [
        // ICU data is linked through `rn-bind-icu`.
        ("v8_enable_i18n_support", 1),
        // OpenSSL is linked, and not the BoringSSL fork.
        ("node_use_openssl", 1),
        ("node_shared_openssl", 0),
        ("node_use_bundled_ca", 1),
        ("node_shareable_openssl", 0),
        ("node_target_type", 0),
        // Neither tracing backend is compiled in.
        ("node_use_dtrace", 0),
        ("node_use_etw", 0),
        ("node_use_perfetto", 0),
        ("node_enable_v8_vtune_profiling", 0),
        // V8 builds with the sandbox, matching the linked `v8` crate default.
        ("v8_enable_sandbox", 1),
        // Temporal is not compiled into this V8.
        ("v8_enable_temporal_support", 0),
    ] {
        if let Some(key) = v8::String::new(scope, name) {
            config_variables.set(scope, key.into(), v8::Integer::new(scope, value).into());
        }
    }
    // `node_target_type` is the string `"executable"` in a real gyp file.
    if let Some(key) = v8::String::new(scope, "node_target_type") {
        if let Some(value) = v8::String::new(scope, "executable") {
            config_variables.set(scope, key.into(), value.into());
        }
    }
    set(scope, config, "variables", config_variables.into())?;
    set(scope, process, "config", config.into())?;

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

/// Defines a property on the global object the way Node defines its globals.
///
/// A bare `object.set` creates an enumerable property, and `for (const name in
/// globalThis)` then sees it. That difference is observable and load-bearing:
/// `test/common/index.js` enumerates `globalThis` at exit and fails the test on
/// any name it does not recognise, while Node's own globals are non-enumerable.
/// Installing `Buffer`, `URL` and `primordials` enumerably made 388 files fail
/// with "Unexpected global(s) found".
///
/// The property is written with `set` first, which gives it the writable and
/// configurable flags Node's globals have, and then `Object.defineProperty` is
/// used to clear only `enumerable`. There is no single V8 call in this crate
/// that sets all three flags at once, and doing the second half in JavaScript
/// states the intent in one line instead of juggling three descriptors.
fn set_global(
    scope: &mut v8::PinScope,
    global: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    set(scope, global, name, value)?;
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    let descriptor = v8::Object::new(scope);
    let enumerable = v8::String::new(scope, "enumerable").ok_or("cannot allocate enumerable")?;
    descriptor.set(
        scope,
        enumerable.into(),
        v8::Boolean::new(scope, false).into(),
    );
    let Some(define_property) = object_define_property(scope) else {
        return Err("cannot reach Object.defineProperty".to_string());
    };
    define_property
        .call(
            scope,
            v8::undefined(scope).into(),
            &[global.into(), key.into(), descriptor.into()],
        )
        .ok_or_else(|| format!("cannot redefine the global {name}"))?;
    Ok(())
}

/// `Object.defineProperty`, looked up once per call.
///
/// Reaching it through the intrinsic rather than a captured handle keeps this
/// usable from the bootstrap, which runs before any module could have saved a
/// reference.
fn object_define_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    let global = scope.get_current_context().global(scope);
    let name = v8::String::new(scope, "Object")?;
    let object = global.get(scope, name.into())?;
    let object = v8::Local::<v8::Object>::try_from(object).ok()?;
    let name = v8::String::new(scope, "defineProperty")?;
    let function = object.get(scope, name.into())?;
    v8::Local::<v8::Function>::try_from(function).ok()
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
