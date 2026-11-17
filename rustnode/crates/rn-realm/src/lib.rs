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

pub mod process_env;
pub mod runtime;
pub mod versions;

use rn_js2c::builtin_by_id;
use rn_v8_sys::v8;

pub use runtime::{
    clear_runtime, install_eval_builtins, install_runtime, run_loop, runtime_exit_requested,
    runtime_has_external_work, with_runtime, Runtime,
};

/// The minimal bootstrap that runs before Node's own builtins do.
///
/// It installs `process` and `console` from the `__argv`/`__stdout` hand-off, so
/// [`install_globals`] and the realm bootstrap have something to work with. It
/// is `include_str!`d from `bootstrap.js`, which is the file to read for what it
/// defines.
const BOOTSTRAP: &str = include_str!("bootstrap.js");

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

/// `require(`internal/...`)` from the realm loader.
///
/// `#[allow(dead_code)]` and kept deliberately: this is the one-line form of
/// "reach an internal module through the realm loader", and the option-gated
/// builtin allow-list used it until it was found to duplicate a call Node
/// already makes from `prepareExecution`. A future bootstrap step that needs an
/// internal module before the CJS loader exists will want it again, and
/// re-deriving it from [`call_require`] is how it got an incorrect receiver the
/// first time.
#[allow(dead_code)]
fn require_internal<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
    id: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let id = v8::String::new(scope, id)?;
    require.call(scope, v8::undefined(scope).into(), &[id.into()])
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
    // `Bun` first, and before the `require` early-return below.
    //
    // It is not gated on a loader because assembling it needs no Node builtin:
    // a worker whose `require` failed should still see the global, and a script
    // written for Bun may read `Bun.version` on its first line. It is here rather
    // than in `install_globals` (the `bootstrap.js` hand-off) because that runs
    // before `realm.js` and deletes its `__`-prefixed names on the way out, so a
    // global defined there would have to be redefined afterwards anyway.
    //
    // A failure is reported, not fatal. Every reason it can fail is a build-time
    // mistake in a contribution crate rather than a condition the user caused, and
    // refusing to start would turn one missing member into an unusable runtime;
    // the message names the member and the crate.
    if let Err(message) = rn_bun::install(scope) {
        eprintln!("rustnode: Bun is unavailable: {message}");
    }
    rn_core::profile::mark("install_bun");

    let Some(require) = loaders.require.as_ref() else {
        return;
    };
    let require = v8::Local::new(scope, require);
    let global = scope.get_current_context().global(scope);

    // `internal/bootstrap/node.js` calls `require('internal/worker/js_transferable')
    // .setup()`, and that file cannot run here. Skipping it left the deserializer
    // with no create-object hook: `setDeserializerCreateObjectFunction` was never
    // called, so `JSTransferable::Data::Deserialize` had nothing to invoke and every
    // cloned host object rebuilt as `undefined`. `test-blocklist-clone.js` is the
    // test that fails on this.
    //
    // `setup()` is JavaScript and runs here, before any user script, which is where
    // Node runs it too: the hook has to exist before the first `structuredClone`.
    // It is best-effort like the rest of this function — a failure leaves the hook
    // unset, and the messaging binding reports that by name rather than crashing.
    if let Some(transferable) = call_require(scope, require, "internal/worker/js_transferable") {
        if let Some(setup) = get_property(scope, transferable, "setup") {
            if let Ok(setup) = v8::Local::<v8::Function>::try_from(setup) {
                let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
                let scope = &mut try_catch.init();
                let _ = setup.call(scope, transferable, &[]);
            }
        }
    }

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
        //
        // `BroadcastChannel` is the three-line neighbour of `MessageChannel` and
        // `MessagePort` in that file (line 50, two lines above them), so leaving it
        // out made `globalThis.BroadcastChannel` `undefined` while
        // `require('worker_threads').BroadcastChannel` worked. Node publishes the
        // same class both ways, and both `lib/**` and user code feature-test the
        // global.
        (
            "internal/worker/io",
            &["BroadcastChannel", "MessageChannel", "MessagePort"][..],
        ),
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
    // binding — so the same binding call is made directly, followed by the
    // `exposeLazyInterfaces(globalThis, 'internal/worker/clone_dom_exception', [
    // 'QuotaExceededError'])` the same file performs two lines later.
    // `internal/blob.js` and `internal/util.js` construct `DOMException`, and
    // Node's own `test/parallel/test-util-inspect.js` inspects its prototype.
    //
    // Both are installed as non-enumerable data properties: Node's
    // `exposeLazyInterfaces` passes `enumerable = false`, and
    // `test/common/index.js` fails a test for any *enumerable* global name it
    // does not recognise.
    if let Some(namespace) = v8::String::new(scope, "messaging") {
        if let Some(messaging) = internal_binding.call(scope, global.into(), &[namespace.into()]) {
            if let Some(expose) = get_property(scope, messaging, "exposeLazyDOMExceptionProperty") {
                if let Ok(expose) = v8::Local::<v8::Function>::try_from(expose) {
                    let _ = expose.call(scope, messaging, &[global.into()]);
                }
            }
            if let Some(quota) = get_property(scope, messaging, "QuotaExceededError") {
                let _ = set_global(scope, global, "QuotaExceededError", quota);
            }
        }
    }

    // `URL` and `URLSearchParams` are not lazy in Node: `internal/url` is small
    // and needed by the loader itself.
    //
    // `URLPattern` comes from the same module and is published the same way.
    // Node installs it from `internal/bootstrap/web/exposed-window-or-worker.js`
    // with `exposeInterface(globalThis, 'URLPattern', URLPattern)`, which is a
    // plain non-enumerable data property — `exposeInterface`, not
    // `exposeLazyInterfaces`, because `internal/url` is already loaded by the
    // time that file runs. `internal/url` is the module that destructures
    // `URLPattern` from `internalBinding('url_pattern')`, so it is already
    // resident here for the same reason `URL` is.
    if let Some(url) = call_require(scope, require, "internal/url") {
        for name in ["URL", "URLSearchParams", "URLPattern"] {
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

    // `internal/bootstrap/node.js:157-167` — the members taken straight from
    // `rawMethods`. Each one is assigned onto `process` with no wrapper.
    //
    //   process.dlopen = rawMethods.dlopen;
    //   process.uptime = rawMethods.uptime;
    //   process._getActiveRequests = rawMethods._getActiveRequests;
    //   process._getActiveHandles = rawMethods._getActiveHandles;
    //   process.getActiveResourcesInfo = rawMethods.getActiveResourcesInfo;
    //   process.reallyExit = rawMethods.reallyExit;
    //   process._kill = rawMethods._kill;
    //
    // `_kill` is load-bearing: `internal/process/per_thread.js`'s `kill()` is
    // the whole body of `process.kill()`, and both of its branches call
    // `process._kill(pid, sig)`. It was missing here, so `process.kill()` threw
    // `TypeError: process._kill is not a function` — including for the
    // `process.kill(pid, 0)` liveness probe.
    for name in [
        "dlopen",
        "uptime",
        "_getActiveRequests",
        "_getActiveHandles",
        "getActiveResourcesInfo",
        "reallyExit",
        "_kill",
    ] {
        if let Some(value) = get_property(scope, binding, name) {
            let _ = set(scope, process, name, value);
        }
    }

    // `internal/bootstrap/node.js:170-181` — the members the per-thread wrapper
    // supplies, plus the three `node.js` takes straight from `rawMethods` inside
    // the same block.
    //
    //   process.loadEnvFile = wrapped.loadEnvFile;      ...through...
    //   process.execve = wrapped.execve;
    //   process.constrainedMemory = rawMethods.constrainedMemory;
    //   process.availableMemory = rawMethods.availableMemory;
    //   process.ref = perThreadSetup.ref;
    //   process.unref = perThreadSetup.unref;
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
    for name in ["constrainedMemory", "availableMemory", "reallyExit"] {
        if let Some(value) = get_property(scope, binding, name) {
            let _ = set(scope, process, name, value);
        }
    }
    // `ref` and `unref` come from `per_thread`'s module exports, not from the
    // wrapper, and they act on the process' own handle rather than on a stream.
    for name in ["ref", "unref"] {
        if let Some(value) = get_property(scope, per_thread, name) {
            let _ = set(scope, process, name, value);
        }
    }

    // `internal/bootstrap/node.js:204,207` — `hrtime` is assigned, and
    // `openStdin` is defined on `process` as a function that resumes stdin and
    // returns it.
    //
    //   process.hrtime = perThreadSetup.hrtime;
    //   process.hrtime.bigint = perThreadSetup.hrtimeBigInt;
    //   process.openStdin = function() { process.stdin.resume(); return process.stdin; };
    if let Some(hrtime) = get_property(scope, per_thread, "hrtime") {
        let _ = set(scope, process, "hrtime", hrtime);
        // `hrtime.bigint` is a property *of the function*, not of `process`.
        if let (Some(function), Some(bigint)) = (
            v8::Local::<v8::Function>::try_from(hrtime).ok(),
            get_property(scope, per_thread, "hrtimeBigInt"),
        ) {
            if let Some(key) = v8::String::new(scope, "bigint") {
                function.set(scope, key.into(), bigint);
            }
        }
    }
    install_open_stdin(scope, process);

    // The uncaught-exception hooks and `_fatalException`, which
    // `internal/bootstrap/node.js:325-330` installs from
    // `internal/process/execution`:
    //
    //   process._fatalException = onGlobalUncaughtException;
    //   process.setUncaughtExceptionCaptureCallback = setUncaughtExceptionCaptureCallback;
    //   process.addUncaughtExceptionCaptureCallback = addUncaughtExceptionCaptureCallback;
    //   process.hasUncaughtExceptionCaptureCallback = hasUncaughtExceptionCaptureCallback;
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

    // `internal/bootstrap/node.js:356` — `process.emitWarning`.
    if let Some(warning) = call_require(scope, require, "internal/process/warning") {
        if let Some(value) = get_property(scope, warning, "emitWarning") {
            let _ = set(scope, process, "emitWarning", value);
        }
    }

    // `internal/bootstrap/node.js:419` — `process.getBuiltinModule`, which
    // `lib/internal/modules/helpers.js` is the source of.
    if let Some(helpers) = call_require(scope, require, "internal/modules/helpers") {
        if let Some(value) = get_property(scope, helpers, "getBuiltinModule") {
            let _ = set(scope, process, "getBuiltinModule", value);
        }
    }

    // `internal/bootstrap/node.js:245-263` — `process.allowedNodeEnvironmentFlags`
    // is an accessor whose getter memoises `perThreadSetup.buildAllowedFlags()`.
    // The value is a `Set`, which `--help` and `test/common` both iterate.
    install_allowed_node_environment_flags(scope, process, per_thread);

    // `internal/bootstrap/node.js:185-202` — `process.finalization`, an accessor
    // that lazily requires `internal/process/finalization` and memoises it.
    install_finalization(scope, process, require);

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

/// `process.openStdin`, from `internal/bootstrap/node.js:207`.
///
/// ```js
/// process.openStdin = function() {
///   process.stdin.resume();
///   return process.stdin;
/// };
/// ```
///
/// The function object is built in JavaScript so its `length` and `name` match
/// Node's, and so it refers to `process.stdin` at call time rather than capturing
/// a handle that replacement could leave stale.
fn install_open_stdin<'s>(scope: &mut v8::PinScope<'s, '_>, process: v8::Local<'s, v8::Object>) {
    let Some(function) = run_expression(
        scope,
        "process.openStdin = function openStdin() { \
           process.stdin.resume(); \
           return process.stdin; \
         };",
    ) else {
        return;
    };
    let _ = set(scope, process, "openStdin", function);
}

/// `process.allowedNodeEnvironmentFlags`, from `internal/bootstrap/node.js:245`.
///
/// Node installs an accessor whose getter calls
/// `perThreadSetup.buildAllowedFlags()` on first read and then replaces the
/// accessor with the resulting `Set`, so a program that never touches the
/// property never pays to build it. Node's accessor also has a setter that
/// replaces itself with a plain data property.
///
/// The flags are built here and captured in a real closure, because the getter
/// has to see them after this function returns. `buildAllowedFlags` reads no
/// `this`, so calling it with `undefined` is equivalent to
/// `perThreadSetup.buildAllowedFlags()`.
fn install_allowed_node_environment_flags<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    process: v8::Local<'s, v8::Object>,
    per_thread: v8::Local<'s, v8::Value>,
) {
    let Some(build) = get_property(scope, per_thread, "buildAllowedFlags")
        .and_then(|value| v8::Local::<v8::Function>::try_from(value).ok())
    else {
        return;
    };
    // `buildAllowedFlags` is deliberately **not** called here. It mutates the
    // alias expansion it walks — `per_thread.js:410` splices the self-referencing
    // `--prof-process` expansion in place — so building the set eagerly rewrites
    // the alias map every later reader sees, and `--help` then prints
    // `--prof-process, --` on the option-terminator row. Node builds it on first
    // read for that reason.
    let global = scope.get_current_context().global(scope);
    let Some(slot) = v8::String::new(scope, "__rustnodeAllowedFlagsBuilder") else {
        return;
    };
    let _ = global.set(scope, slot.into(), build.into());
    let getter = run_expression(
        scope,
        "(function (build) {\n\
           let flags;\n\
           return {\n\
             get: function get() {\n\
               flags ??= build();\n\
               Object.defineProperty(process, 'allowedNodeEnvironmentFlags', {\n\
                 __proto__: null, value: flags, configurable: true,\n\
                 enumerable: true, writable: true,\n\
               });\n\
               return flags;\n\
             },\n\
             set: function set(value) {\n\
               Object.defineProperty(process, 'allowedNodeEnvironmentFlags', {\n\
                 __proto__: null, value, configurable: true,\n\
                 enumerable: true, writable: true,\n\
               });\n\
             },\n\
           };\n\
         })(globalThis.__rustnodeAllowedFlagsBuilder)",
    );
    let _ = global.delete(scope, slot.into());
    let Some(pair) = getter.and_then(|value| v8::Local::<v8::Object>::try_from(value).ok()) else {
        return;
    };
    let (Some(get), Some(set)) = (
        get_property(scope, pair.into(), "get"),
        get_property(scope, pair.into(), "set"),
    ) else {
        return;
    };
    let Some(descriptor) = property_descriptor(scope, &[("get", get), ("set", set)], true) else {
        return;
    };
    let Some(key) = v8::String::new(scope, "allowedNodeEnvironmentFlags") else {
        return;
    };
    define_property_on(scope, process, key.into(), descriptor);
}
/// `process.finalization`, from `internal/bootstrap/node.js:185-202`.
///
/// A lazily-required module behind an accessor with both a getter and a setter.
/// Node memoises it in a closure variable, and the setter replaces that variable
/// rather than the property, so a test can stub `process.finalization` before
/// anything reads it and the accessor itself survives.
fn install_finalization<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    process: v8::Local<'s, v8::Object>,
    require: v8::Local<'s, v8::Function>,
) {
    let Some(module) = call_require(scope, require, "internal/process/finalization") else {
        return;
    };
    let Some(create) = get_property(scope, module, "createFinalization")
        .and_then(|value| v8::Local::<v8::Function>::try_from(value).ok())
    else {
        return;
    };
    let Some(value) = create.call(scope, v8::undefined(scope).into(), &[]) else {
        return;
    };

    // The accessor pair is built in JavaScript so the `finalizationMod` local
    // that Node memoises is a real closure variable rather than a global slot.
    let global = scope.get_current_context().global(scope);
    let Some(slot) = v8::String::new(scope, "__rustnodeFinalization") else {
        return;
    };
    let _ = global.set(scope, slot.into(), value);
    let pair = run_expression(
        scope,
        "(function (initial) {\n\
           let finalizationMod = initial;\n\
           return {\n\
             get: function get() { return finalizationMod; },\n\
             set: function set(value) { finalizationMod = value; },\n\
           };\n\
         })(globalThis.__rustnodeFinalization)",
    );
    let _ = global.delete(scope, slot.into());
    let Some(pair) = pair.and_then(|value| v8::Local::<v8::Object>::try_from(value).ok()) else {
        return;
    };
    let (Some(get), Some(set)) = (
        get_property(scope, pair.into(), "get"),
        get_property(scope, pair.into(), "set"),
    ) else {
        return;
    };
    let Some(descriptor) = property_descriptor(scope, &[("get", get), ("set", set)], true) else {
        return;
    };
    let Some(key) = v8::String::new(scope, "finalization") else {
        return;
    };
    define_property_on(scope, process, key.into(), descriptor);
}

/// Evaluates `source` in the current context and returns its completion value.
fn run_expression<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let source = v8::String::new(scope, source)?;
    let script = v8::Script::compile(scope, source, None)?;
    script.run(scope)
}

/// Builds a property descriptor object from `(key, value)` pairs.
fn property_descriptor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[(&str, v8::Local<'s, v8::Value>)],
    enumerable: bool,
) -> Option<v8::Local<'s, v8::Object>> {
    let descriptor = v8::Object::new(scope);
    for (name, value) in entries {
        let key = v8::String::new(scope, name)?;
        descriptor.set(scope, key.into(), *value);
    }
    for (name, flag) in [("enumerable", enumerable), ("configurable", true)] {
        let key = v8::String::new(scope, name)?;
        descriptor.set(scope, key.into(), v8::Boolean::new(scope, flag).into());
    }
    Some(descriptor)
}

/// `Object.defineProperty(target, key, descriptor)` through the real intrinsic.
fn define_property_on<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    key: v8::Local<'s, v8::Value>,
    descriptor: v8::Local<'s, v8::Object>,
) {
    let Some(define) = object_define_property(scope) else {
        return;
    };
    let _ = define.call(
        scope,
        v8::undefined(scope).into(),
        &[target.into(), key, descriptor.into()],
    );
}

/// Runs one `internal/main/**` script with the parameters its kind declares.
///
/// `internal/main/worker_thread.js` is the worker-side entry point. It is a
/// `kMainScript`, so it compiles with `(process, require, internalBinding,
/// primordials)` — the same shape as a bootstrap script, which is why this shares
/// [`run_bootstrap_script`]'s body. It differs in one way that matters: it does
/// *not* return until the realm's loop has stopped, because it installs the
/// `port.on('message')` handler that runs the user script and then starts the
/// port, so the loop is what finishes it.
pub fn run_main_script(scope: &mut v8::PinScope<'_, '_>, id: &str) -> Option<String> {
    run_bootstrap_script(scope, id)
}

/// Runs one `internal/main/**` script from substituted source under its own id.
///
/// The only caller is `--help`: `internal/main/print_help.js` writes its usage
/// header as the literal `'Usage: node [options] ...'`, and the vendored tree
/// must stay byte-identical to Node's (`tools/verify-libjs.sh` pins it). So the
/// program name is substituted in the source at load time rather than by editing
/// the vendored file, and the id — which is also the script's `sourceURL` — stays
/// Node's, so a throw from inside it still names `node:internal/main/print_help`.
pub fn run_main_script_with_source(
    scope: &mut v8::PinScope<'_, '_>,
    id: &str,
    source: &str,
) -> Option<String> {
    run_bootstrap_script_from(scope, id, source)
}

/// Runs one `internal/bootstrap/**` script with the parameters its kind declares.
///
/// Returns the script's error message when it threw, which is more useful than
/// silence: these scripts install the `process` surface and a half-applied one is
/// worse than a reported gap.
pub fn run_bootstrap_script(scope: &mut v8::PinScope<'_, '_>, id: &str) -> Option<String> {
    let builtin = rn_js2c::builtin_by_id(id)?;
    run_bootstrap_script_from(scope, id, builtin.source())
}

/// The body of [`run_bootstrap_script`], over explicit source.
fn run_bootstrap_script_from(
    scope: &mut v8::PinScope<'_, '_>,
    id: &str,
    source: &str,
) -> Option<String> {
    let builtin = rn_js2c::builtin_by_id(id)?;
    let function = rn_builtins::compile(scope, builtin.id(), source, builtin.kind())?;
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
        // The `stack` is included because a Node internal assertion's message
        // names no source line: the stack is the only part that says *where*,
        // and without it a one-line fix becomes a hunt.
        let text = scope.exception().map(|exception| {
            let value: v8::Local<v8::Value> = exception;
            exception_stack(scope, value).unwrap_or_else(|| value.to_rust_string_lossy(scope))
        });
        return Some(text.unwrap_or_default());
    }
    None
}

/// An exception's `stack` when it has one, which is what identifies the site.
fn exception_stack(
    scope: &mut v8::PinScope<'_, '_>,
    exception: v8::Local<'_, v8::Value>,
) -> Option<String> {
    let object = v8::Local::<v8::Object>::try_from(exception).ok()?;
    let key = v8::String::new(scope, "stack")?;
    let stack = object.get(scope, key.into())?;
    if stack.is_undefined() {
        return None;
    }
    stack
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
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

/// The `primordials` object the bootstrap scripts read as a free variable.
///
/// Node passes it as a wrapper parameter; rustnode records it in the hook slot
/// so `globalThis` never carries it. The global is checked only as a fallback for
/// a caller that ran before [`rn_core::hook_slot::set_primordials`], which does
/// not happen in the CLI's ordering but keeps this function total.
fn primordials_from_global<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Value>> {
    if let Some(primordials) = rn_core::hook_slot::primordials(scope) {
        return Some(primordials.into());
    }
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
/// A bare `internal/...` id is only a builtin when `--expose-internals` put it
/// in the user-facing list, and the CommonJS loader resolves it through
/// `BuiltinModule` rather than the filesystem, so the fallback to the realm
/// loader is what keeps `require('internal/bootstrap/realm')` working: that id is
/// deliberately excluded from the id list the loader consults, so only the realm
/// loader — which returns its own `loaderExports` for it — can serve it.
///
/// A `node:` id is *not* routed here. The realm loader is Node's **internal**
/// loader: `requireBuiltin` looks the id up in `BuiltinModule.map`, which holds
/// every vendored builtin, so it has no allow-list and cannot have one — Node's
/// own internals require gated modules at their own scope. Handing a user's
/// `require('node:...')` to it therefore skipped
/// `BuiltinModule.normalizeRequirableId`, the only check on the `node:` branch,
/// and `require('node:quic')` loaded a module `canBeRequiredByUsers` reports
/// false for. The file loader already implements that check
/// (`defaultResolveImplForCJSLoading`: normalize, then
/// `ERR_UNKNOWN_BUILTIN_MODULE`), so the scheme branch is delegated to it
/// exactly like the schemeless branch, and one policy governs both.
fn wrap_cjs_require_with_builtin_fallback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    file_require: v8::Local<'s, v8::Function>,
    realm_require: v8::Local<'s, v8::Function>,
) -> Option<v8::Local<'s, v8::Function>> {
    // A V8 callback cannot capture the two loaders, so the wrapper is built in
    // JavaScript the same way the `node:` wrapper is.
    let source = "(function (fileRequire, realmRequire) {\n\
                  \x20 return function require(id) {\n\
                  \x20   if (typeof id === 'string' && id.startsWith('internal/')) {\n\
                  \x20     try { return realmRequire(id); }\n\
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

/// The `process` state that belongs to the main thread's environment.
///
/// Node decides per thread whether it may mutate process-wide state:
/// `PatchProcessObject` passes `env->owns_process_state() ? ProcessTitleSetter :
/// nullptr`, so a worker's `process.title` reads the main thread's title and is
/// read-only. `debugPort` follows the same shape. Modelling it as one value keeps
/// the two decisions together instead of threading two booleans through every
/// call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessState {
    /// The port `process.debugPort` reports, from `--inspect-port`.
    pub debug_port: u16,
    /// Whether this thread owns process-wide state, i.e. is the main thread.
    ///
    /// A worker passes `false`: its `title` and `debugPort` become getters with
    /// no setter, so a worker cannot rename the process or move the parent's
    /// inspector port.
    pub owns_process_state: bool,
}

impl ProcessState {
    /// The main thread's state, which owns the process and reports `debug_port`.
    pub fn main_thread(debug_port: u16) -> Self {
        Self {
            debug_port,
            owns_process_state: true,
        }
    }

    /// A worker's state: it reads the process's port but may not change it.
    pub fn worker() -> Self {
        Self {
            debug_port: rn_uv::process_title::debug_port(),
            owns_process_state: false,
        }
    }
}

/// Runs the realm bootstrap and returns the loaders it created.
pub fn bootstrap_realm(
    scope: &mut v8::PinScope,
    script_args: &[String],
    exec_argv: &[String],
    state: ProcessState,
) -> Result<Bootstrapped, String> {
    if rn_core::realm::installed().is_none() {
        return Err("no binding registry is installed for this realm".to_string());
    }
    // A realm that is bootstrapping gets a fresh exit state. A worker already
    // has one (its thread was just spawned), but this also covers a thread that
    // bootstraps a second realm, which must not inherit the first one's
    // `_exiting` or `exitCode` — Node constructs a new `Environment` there.
    rn_core::exit_state::reset();
    let global = scope.get_current_context().global(scope);

    let primordials = v8::Object::new(scope);
    run_per_context(scope, primordials)?;
    rn_core::profile::mark("primordials");

    let process = process_object(scope, script_args, exec_argv, state)?;
    set_global(scope, global, "process", process.into())?;
    // `realm.js` destructures `primordials` as a free variable
    // (`/* global ... primordials */`), so it needs the object in scope — but
    // Node's `primordials` is a bootstrap-local, never a `globalThis` property.
    // Recording it in the hook slot lets every bootstrap script reach it without
    // leaving a name on the global object that `test/common/index.js`'s globals
    // audit would reject.
    rn_core::hook_slot::set_primordials(scope, primordials);

    let get_linked_binding = function_of(scope, "getLinkedBinding", get_linked_binding)?;
    let get_internal_binding = internal_binding_dispatcher(scope)?;

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
    rn_core::profile::mark("realm.js executed");

    // `require` is what user code and the CLI both need, so it becomes a global
    // the same way Node exposes it to a CommonJS module.
    let require = rn_core::hook_slot::require(scope);
    if let Some(require) = require {
        set_global(scope, global, "require", require.into())?;
    }

    // `bootstrap/node.js` installs the source-map pair from
    // `internal/source_map/source_map_cache` after `realm.js` has provided
    // `require`, so this is the same point in the ordering. A failure is fatal
    // here rather than swallowed: the getter is what
    // `Error.prepareStackTrace` and the inspector both consult, and a process
    // that reported `sourceMapsEnabled` from a parallel copy of the flag would
    // be worse than one that failed to boot.
    install_process_source_maps(scope)?;
    rn_core::profile::mark("process source maps");

    // `primordials` was a global only long enough for `realm.js` to read it.
    //
    // `lib/internal/bootstrap/realm.js` opens with
    // `/* global process, getLinkedBinding, getInternalBinding, primordials */`,
    // so it resolves `primordials` as a bare global even though the same object
    // is also passed as its fourth argument — that is how Node's own bootstrap
    // wraps the file. Node's `primordials` is a bootstrap-local, never a global,
    // and leaving it visible is observable: `test/common/index.js` enumerates
    // `globalThis` at exit and fails the test for every name it does not
    // recognise, so a leaked `primordials` turns into "Unexpected global(s)
    // found" for any test that loads `common`.
    //
    // Deleting it here rather than before `realm.js` is the ordering that
    // matters: at this point nothing after the bootstrap reads it as a global,
    // and every later consumer receives it as a parameter or a module.
    let primordials_key = v8::String::new(scope, "primordials").ok_or("cannot allocate the key")?;
    let _ = global.delete(scope, primordials_key.into());
    // Debug-only escape hatch for `tools/per-context-audit.js`; see
    // `delete_require_global`'s "audit hook" note. Republished *after* the delete
    // so it is opt-in rather than the leftover the delete was removing.
    if std::env::var_os("RUSTNODE_DEBUG_REALM_PRIMORDIALS").is_some() {
        if let Some(slot) = rn_core::hook_slot::primordials(scope) {
            let _ = set_global(scope, global, "primordials", slot.into());
        }
    }

    Ok(Bootstrapped {
        internal_binding: rn_core::hook_slot::internal_binding(scope)
            .map(|function| v8::Global::new(scope, function)),
        require: require.map(|function| v8::Global::new(scope, function)),
    })
}

/// The `internal/per_context/**` files Node runs, in order.
///
/// `InitializePrimordials` in `src/api/environment.cc` iterates exactly this
/// array. It is a list, not a set: `domexception.js` reads
/// `symbols.messaging_clone_symbol`, and `messageport.js` needs the primordials
/// the first entry built.
const PER_CONTEXT_FILES: &[&str] = &[
    "internal/per_context/primordials",
    "internal/per_context/domexception",
    "internal/per_context/messageport",
];

/// Runs every `internal/per_context/**` script the way `InitializePrimordials` does.
///
/// # What Node passes, and why the arguments are built here
///
/// A `kPerContextScript` compiles with the wrapper parameters
/// `(exports, primordials, privateSymbols, perIsolateSymbols)`. The two symbol
/// objects are not decoration: `domexception.js` destructures
/// `transfer_mode_private_symbol` from the first and
/// `messaging_clone_symbol` / `messaging_deserialize_symbol` from the second, and
/// defines those two as methods on one prototype. With the symbols missing — the
/// previous behaviour, where `run_per_context` handed over empty objects — both
/// methods land on the string key `"undefined"` and the second replaces the
/// first, so `DOMException` still constructed and silently could not clone.
///
/// `perIsolateSymbols` was not even passed to the other two files: only
/// `primordials.js` ran, so `DOMException` came from the hand-built binding in
/// `rn-bind-messaging` instead. That is why it was never an `Error` subclass —
/// the binding built a plain object with data properties, while Node's file
/// creates an `Error` and swaps its prototype.
///
/// # The exports object
///
/// Node keeps one `exports` object for the whole set and stores it on the
/// context under `node:per_context_binding_exports`, which is how
/// `GetPerContextExports` — and therefore `node_messaging.cc`'s
/// `GetDOMException` — finds it again. The same object is stored here, so
/// `internalBinding('messaging')` can return the *identical* constructor the
/// global `DOMException` is, rather than a second class that would fail
/// `instanceof`.
fn run_per_context(
    scope: &mut v8::PinScope,
    primordials: v8::Local<v8::Object>,
) -> Result<(), String> {
    let exports = v8::Object::new(scope);
    let private_symbols = rn_core::private_symbols_object(scope)?;
    let per_isolate_symbols = rn_core::per_isolate_symbols_object(scope)?;

    for id in PER_CONTEXT_FILES {
        let builtin =
            builtin_by_id(id).ok_or_else(|| format!("{id} is missing from the builtin table"))?;
        let function = rn_builtins::compile(scope, builtin.id(), builtin.source(), builtin.kind())
            .ok_or_else(|| format!("failed to compile {id}"))?;

        let arguments = [
            exports.into(),
            primordials.into(),
            private_symbols.into(),
            per_isolate_symbols.into(),
        ];
        // Node calls with the exports object as the receiver, which is what the
        // wrapper's `exports` parameter shadows anyway; matching it keeps a
        // script that reads `this` from behaving differently from Node.
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let _ = function.call(scope, exports.into(), &arguments);
        if scope.has_caught() {
            let message = scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(scope))
                .unwrap_or_default();
            return Err(format!("{id} threw: {message}"));
        }
    }

    rn_core::set_per_context_exports(scope, exports)
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
    state: ProcessState,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let process = v8::Object::new(scope);

    let load_list = v8::Array::new(scope, 0);
    set(scope, process, "moduleLoadList", load_list.into())?;

    let versions = v8::Object::new(scope);
    // Node defines each key with `v8::ReadOnly`, and
    // `test/parallel/test-process-versions.js` asserts exactly that for every
    // key, so the attribute is part of the contract rather than decoration.
    for entry in versions::table() {
        let Some(value) = v8::String::new(scope, &entry.value) else {
            return Err(format!("cannot allocate process.versions.{}", entry.key));
        };
        let Some(key) = v8::String::new(scope, entry.key) else {
            return Err("cannot allocate a version key".to_string());
        };
        if versions
            .define_own_property(
                scope,
                key.into(),
                value.into(),
                v8::PropertyAttribute::READ_ONLY,
            )
            .is_none()
        {
            return Err(format!("cannot define process.versions.{}", entry.key));
        }
    }
    define_read_only(scope, process, "versions", versions.into())?;

    let version = v8::String::new(scope, &versions::process_version_string())
        .ok_or("cannot allocate a version")?;
    define_read_only(scope, process, "version", version.into())?;

    // These are the platform facts `os.arch()`, `os.platform()` and
    // `process.release` read straight back out, so they have to be the real
    // values rather than placeholders. `internal/bootstrap/node.js` normally
    // sets them through `patchProcessObject`; that file cannot run yet, and a
    // hardcoded "linux" would be wrong on macOS and Windows.
    let platform = node_platform();
    let platform = v8::String::new(scope, platform).ok_or("cannot allocate the platform name")?;
    define_read_only(scope, process, "platform", platform.into())?;
    let arch =
        v8::String::new(scope, node_arch()).ok_or("cannot allocate the architecture name")?;
    define_read_only(scope, process, "arch", arch.into())?;

    let release = v8::Object::new(scope);
    let release_name = v8::String::new(scope, "node").ok_or("cannot allocate the release name")?;
    set(scope, release, "name", release_name.into())?;
    define_read_only(scope, process, "release", release.into())?;

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
    // An interceptor over the real environment block, not a snapshot of it.
    // `std::env::vars()` here used to build a plain object, which made
    // `process.env.X = 'y'` invisible to a child process and kept a number
    // assigned to it a number; see `process_env`'s module docs.
    let env = process_env::create(scope)
        .ok_or("cannot allocate the process.env proxy template instance")?;
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
    // The inspector exists: `--inspect` starts a WebSocket endpoint and
    // `internalBinding('inspector')` opens real sessions against V8's inspector, so
    // `process.features.inspector` reporting `false` would be wrong in a way
    // `lib/internal/util/inspector.js` acts on — it skips the console wrapper.
    feature(scope, "inspector", true);
    feature(scope, "debug", cfg!(debug_assertions));
    // Modules are requireable, and TypeScript stripping is not implemented.
    feature(scope, "require_module", true);
    // `dtls` and `quic` are getters in `lib/internal/bootstrap/node.js:290-300`,
    // each a conjunction whose first term is `process.config.variables.node_use_*`.
    // Both are `0` in the pinned build, so both are `false`; this build has no
    // DTLS or QUIC either. Verified against the oracle **with the experimental
    // flags on**, because a value that only happens to be false by default would
    // be wrong the moment a flag flips it:
    //
    //   node --experimental-quic --experimental-dtls \
    //     -e 'console.log(process.features.quic, process.features.dtls)'
    //   false false
    //
    // Omitting them entirely — which is what this used to do — leaves them
    // `undefined`, and `undefined` passes a truthiness check by accident while
    // failing `=== false` and the `in` operator. `test/common/index.js:78` reads
    // `!!process.features.quic`, which is why the 272 QUIC tests still skipped
    // correctly and this was invisible: the bug costs no test files, but the
    // property is still wrong.
    feature(scope, "dtls", false);
    feature(scope, "quic", false);
    if let Some(key) = v8::String::new(scope, "typescript") {
        if let Some(value) = v8::String::new(scope, "strip") {
            let _ = features.set(scope, key.into(), value.into());
        }
    }
    define_read_only_frozen(scope, process, "features", features.into())?;

    let pid = v8::Integer::new(scope, std::process::id() as i32);
    define_read_only(scope, process, "pid", pid.into())?;

    // `process.exitCode` is how a test script reports failure, and every one of
    // Node's own tests relies on it: a script that sets it and returns exits
    // with that status. Node defines it as an *accessor* over a private field
    // (`bootstrap/node.js:107`), with `configurable: false`, so a plain data
    // property reports the right value with the wrong descriptor — visible
    // through `Object.getOwnPropertyDescriptor` and through
    // `delete process.exitCode`, which Node refuses.

    // `process.config` is serialized `config.gypi`: `internal/bootstrap/node.js`
    // parses `internalBinding('builtins').config` and freezes the result. Keep
    // this object sourced from the same string so `process.config` and
    // `internalBinding('builtins').config` cannot drift.
    let config_source = v8::String::new(scope, rn_builtins::build_config_json())
        .ok_or("cannot allocate process.config source")?;
    let config = v8::json::parse(scope, config_source).ok_or("cannot parse process.config JSON")?;
    let config =
        v8::Local::<v8::Object>::try_from(config).map_err(|_| "process.config is not an object")?;
    apply_v8_config_overrides(scope, config)?;
    define_read_only(scope, process, "config", config.into())?;

    install_process_state(scope, process, state)?;

    Ok(process)
}

// The linked v8 crate's build flags are what the corresponding
// `process.config.variables` keys represent.
//
// `v8-152.2.0/build.rs` only flips these with
// `CARGO_FEATURE_V8_ENABLE_SANDBOX` / `CARGO_FEATURE_V8_ENABLE_POINTER_COMPRESSION`.
// This workspace enables `v8/default` + `v8/use_custom_libcxx` only, so both
// features are off (`cargo tree -e features -p rn-cli -i v8`).
const V8_ENABLE_SANDBOX: i32 = 0;
const V8_ENABLE_POINTER_COMPRESSION: i32 = 0;
const V8_ENABLE_EXTERNAL_CODE_SPACE: i32 = if V8_ENABLE_SANDBOX == 1 { 1 } else { 0 };
const V8_ENABLE_POINTER_COMPRESSION_SHARED_CAGE: i32 = 0;

fn apply_v8_config_overrides(
    scope: &mut v8::PinScope<'_, '_>,
    config: v8::Local<'_, v8::Object>,
) -> Result<(), String> {
    let variables_key = v8::String::new(scope, "variables")
        .ok_or("cannot allocate process.config.variables key")?;
    let variables = config
        .get(scope, variables_key.into())
        .ok_or("missing process.config.variables")?;
    let variables = v8::Local::<v8::Object>::try_from(variables)
        .map_err(|_| "process.config.variables is not an object")?;

    for (name, value) in [
        ("v8_enable_sandbox", V8_ENABLE_SANDBOX),
        (
            "v8_enable_pointer_compression",
            V8_ENABLE_POINTER_COMPRESSION,
        ),
        (
            "v8_enable_external_code_space",
            V8_ENABLE_EXTERNAL_CODE_SPACE,
        ),
        (
            "v8_enable_pointer_compression_shared_cage",
            V8_ENABLE_POINTER_COMPRESSION_SHARED_CAGE,
        ),
    ] {
        let key = v8::String::new(scope, name).ok_or("cannot allocate process.config key")?;
        variables.set(scope, key.into(), v8::Integer::new(scope, value).into());
    }

    Ok(())
}

/// The `process` properties `node.cc`'s `PatchProcessObject` and
/// `bootstrap/node.js`'s later blocks install.
///
/// These are the pieces that are not plain data on the object this crate builds:
/// two of them are *native* accessors, one is an ordinary assignment, and the
/// source-map pair comes from `internal/source_map/source_map_cache`. They live
/// together because each has to match Node's descriptor, not just its value, and
/// keeping them in one place makes that visible.
fn install_process_state(
    scope: &mut v8::PinScope<'_, '_>,
    process: v8::Local<v8::Object>,
    state: ProcessState,
) -> Result<(), String> {
    install_title(scope, process, state.owns_process_state)?;
    install_debug_port(scope, process, state)?;
    install_domain(scope, process)?;
    install_max_listeners(scope, process)?;
    install_process_to_string_tag(scope, process)?;
    Ok(())
}

/// `process._exiting` and `process.exitCode`, as accessors over one field set.
///
/// Node backs both with a private-symbol struct (`bootstrap/node.js:92-129`):
/// `_exiting` is a boolean flag and `exitCode` is a tri-state of
/// "absent"/"set to N". They are accessors rather than data properties for a
/// reason that is observable — `exitCode` is `configurable: false`, so an
/// assignment target that could be deleted or redefined would diverge — and the
/// exit path reads them through `Object.getOwnPropertyDescriptor` in the tests
/// below.
///
/// The storage behind the accessors is `rn_core::exit_state`, one set per
/// environment: a worker's `process.exitCode` and `_exiting` are its own, which
/// is what Node's `Environment::exit_code()` gives it. Sharing one value across
/// the process made a worker's exit status the parent's, and tripped the
/// parent's "the exit sequence already ran" guard so its own `exit` handlers
/// were suppressed.
///
/// `exitCode`'s setter follows Node exactly: `null`/`undefined` clear it, a
/// finite number stores it, a non-empty numeric *string* is coerced, and
/// anything else is `ERR_INVALID_ARG_TYPE` from `validateInteger`. The message is
/// built here rather than through `internal/errors` because that module is not
/// reachable from this crate's bootstrap, which is the same constraint the
/// `domain` implementation notes.
fn install_exit_state(
    scope: &mut v8::PinScope<'_, '_>,
    process: v8::Local<v8::Object>,
) -> Result<(), String> {
    // Defined in JavaScript, not through `set_accessor`: a native accessor
    // registered via V8's `SetNativeDataProperty` reports as a `data` descriptor
    // with its current value materialised, while the oracle reports `accessor`
    // for both of these. (`title` and `debugPort` go the other way — Node
    // installs those natively and the oracle reports `data` — which is why the
    // distinction is measured per property rather than assumed.)
    let source = r#"
(function (process, state, ObjectDefineProperty, validateInteger) {
  ObjectDefineProperty(process, '_exiting', {
    __proto__: null,
    get() {
      return state.exiting();
    },
    set(value) {
      state.setExiting(value ? true : false);
    },
    enumerable: true,
    configurable: true,
  });

  ObjectDefineProperty(process, 'exitCode', {
    __proto__: null,
    get() {
      return state.exitCode();
    },
    set(code) {
      if (code !== null && code !== undefined) {
        let value = code;
        // `NumberIsNaN` is a primordial (`internal/per_context/primordials`),
        // not a global, so the check is spelled with `Number.isNaN` here. The
        // observable behaviour is identical: a numeric string is coerced, and a
        // non-numeric one is left as a string for `validateInteger` to reject.
        if (typeof code === 'string' && code !== '' &&
          Number.isNaN((value = Number(code)))) {
          value = code;
        }
        validateInteger(value, 'code');
        state.setExitCode(value);
      } else {
        state.clearExitCode();
      }
    },
    enumerable: true,
    configurable: false,
  });
})"#;
    let state = exit_state_object(scope)?;
    let Some(define) = object_define_property(scope) else {
        return Err("cannot reach Object.defineProperty".to_string());
    };
    let Some(validate) = validate_integer(scope) else {
        // `validateInteger` lives in `internal/validators`; without a loader it
        // is unreachable, so the setter's validation is the one thing this
        // cannot provide. Reporting that as an error is better than installing a
        // setter that accepts nonsense.
        return Err("cannot reach validateInteger for process.exitCode".to_string());
    };
    let code = v8::String::new(scope, source).ok_or("cannot allocate the exit setup script")?;
    let script = v8::Script::compile(scope, code, None).ok_or("cannot compile the exit script")?;
    let factory = script.run(scope).ok_or("the exit script threw")?;
    let factory = v8::Local::<v8::Function>::try_from(factory)
        .map_err(|_| "the exit script is not a function")?;
    factory
        .call(
            scope,
            v8::undefined(scope).into(),
            &[process.into(), state, define.into(), validate],
        )
        .ok_or("the exit script threw while installing")?;
    Ok(())
}

/// `internal/validators`' `validateInteger`, reached through the realm loader.
fn validate_integer<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Value>> {
    let require = rn_core::hook_slot::require(scope)?;
    let id = v8::String::new(scope, "internal/validators")?;
    let exports = require.call(scope, v8::undefined(scope).into(), &[id.into()])?;
    let exports = v8::Local::<v8::Object>::try_from(exports).ok()?;
    let key = v8::String::new(scope, "validateInteger")?;
    exports.get(scope, key.into())
}

/// The Rust-side state the exit accessors read and write.
///
/// An object of closures rather than a raw pointer: V8 callback data is a
/// statically sized slot that a captured closure does not fit in, and the exit
/// path in `runtime.rs` already goes through the same functions.
fn exit_state_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let object = v8::Object::new(scope);
    // Each is added by its own statement rather than through a loop: the
    // callbacks are distinct `fn` items, and collecting them into one array would
    // coerce them to a single function-pointer type, which `MapFnTo` rejects at
    // compile time (each `fn` has its own `UnitValue`).
    let exiting = function_of(scope, "exiting", exit_state_exiting)?;
    set(scope, object, "exiting", exiting)?;
    let set_exiting = function_of(scope, "setExiting", exit_state_set_exiting)?;
    set(scope, object, "setExiting", set_exiting)?;
    let exit_code = function_of(scope, "exitCode", exit_state_exit_code)?;
    set(scope, object, "exitCode", exit_code)?;
    let set_exit_code = function_of(scope, "setExitCode", exit_state_set_exit_code)?;
    set(scope, object, "setExitCode", set_exit_code)?;
    let clear = function_of(scope, "clearExitCode", exit_state_clear_exit_code)?;
    set(scope, object, "clearExitCode", clear)?;
    Ok(object.into())
}

fn exit_state_exiting(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Boolean::new(scope, rn_core::exit_state::exiting()).into());
}

fn exit_state_set_exiting(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let truthy = args.get(0).boolean_value(scope);
    rn_core::exit_state::set_exiting(truthy);
}

fn exit_state_exit_code(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match rn_core::exit_state::exit_code() {
        Some(code) => rv.set(v8::Integer::new(scope, code).into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn exit_state_set_exit_code(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(code) = args.get(0).number_value(scope) else {
        return;
    };
    rn_core::exit_state::set_exit_code(code as i32);
}

fn exit_state_clear_exit_code(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    rn_core::exit_state::clear_exit_code();
}

/// Installs `process.sourceMapsEnabled` and `process.setSourceMapsEnabled`.
///
/// `bootstrap/node.js` reaches `internal/source_map/source_map_cache` through
/// `require`, and rustnode's `require` does not exist until `realm.js` has run —
/// which is after [`process_object`]. Calling this from
/// [`bootstrap_realm`] immediately after the realm bootstrap is the same point in
/// Node's own ordering (`node.js` line 386 comes after `realm.js`).
///
/// A no-op when `require` is absent, so a caller that has no loader yet (a worker
/// before its realm) does not fail; the properties are then simply absent, which
/// the parity test reports rather than hiding.
pub fn install_process_source_maps(scope: &mut v8::PinScope<'_, '_>) -> Result<(), String> {
    let global = scope.get_current_context().global(scope);
    let Some(process) = get_property(scope, global.into(), "process") else {
        return Ok(());
    };
    let Ok(process) = v8::Local::<v8::Object>::try_from(process) else {
        return Ok(());
    };
    install_exit_state(scope, process)?;
    install_source_maps(scope, process)
}

/// The realm's `primordials` object, for the audit to inspect.
///
/// Exposed because the audit has to read the object the realm actually built.
/// It is not on `globalThis` — Node never puts it there — so this is the only
/// route, and it goes through the same slot the bootstrap scripts use.
pub fn primordials<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Value>> {
    rn_core::hook_slot::primordials(scope).map(|primordials| primordials.into())
}

/// Removes the bootstrap's `require` global.
///
/// Node has a global `require` in exactly one place: the `-e`/`-p` evaluation
/// script, where `internal/process/execution.js::evalScript` runs user code with
/// no module wrapper. Everywhere else — a CommonJS file, an ES module — `require`
/// is the module wrapper's parameter, and `globalThis` has no such own property.
///
/// `rn-cli` installs the global because `realm.js` needs to hand its loader to
/// user code before the entry kind is known, and the `-e` path has nothing else
/// to reach it through. This is what a file entry point calls before running, so
/// the surface matches Node for the case where the difference is observable.
///
/// # The audit hook
///
/// `tools/per-context-audit.js` has to inspect the realm's `primordials` object,
/// which Node deliberately keeps off `globalThis`, so there is no supported route
/// from JavaScript. `RUSTNODE_DEBUG_REALM_PRIMORDIALS=1` publishes it as a global
/// for that audit alone, and the audit then asserts the members it destructures —
/// the check that used to read a global that the runtime had leaked by accident.
///
/// This mirrors the existing `RUSTNODE_DEBUG_BINDING` hook in `rn-bind-contextify`:
/// a debug-only variable, off by default, that no normal run sets. It is
/// deliberately *not* a binding member, because a `primordials` own property on
/// `builtins` would itself be a surface Node does not have, and this file is about
/// removing exactly those.
pub fn delete_require_global(scope: &mut v8::PinScope<'_, '_>) {
    let global = scope.get_current_context().global(scope);
    if let Some(key) = v8::String::new(scope, "require") {
        let _ = global.delete(scope, key.into());
    }
}

/// `process.title`, and the two libuv facts behind it.
///
/// `node_process_object.cc:168` installs it with `SetNativeDataProperty` and
/// `ProcessTitleGetter`/`ProcessTitleSetter`. A getter/setter pair defined by
/// hand would report a *data* property through
/// `Object.getOwnPropertyDescriptor`, because V8 materialises a native data
/// property's current value; that is what the oracle reports, and it is why this
/// has to be `set_accessor_with_setter` rather than `define_own_property`.
///
/// The setter really renames the process: `uv_set_process_title`, the same call
/// Node's `ProcessTitleSetter` makes. That only works once `uv_setup_args` has
/// run, which `rn-cli` does at startup; without it libuv answers `UV_ENOBUFS`
/// and the title would be a silent no-op on `ps`.
fn install_title(
    scope: &mut v8::PinScope<'_, '_>,
    process: v8::Local<v8::Object>,
    owns_process_state: bool,
) -> Result<(), String> {
    let key = v8::String::new(scope, "title").ok_or("cannot allocate process.title")?;
    // Node passes `None` for the property attributes, which is `PropertyAttribute::NONE`:
    // enumerable, writable, configurable — the descriptor the oracle reports.
    //
    // The setter is `nullptr` for a thread that does not own process state, which
    // is Node's `env->owns_process_state() ? ProcessTitleSetter : nullptr`. A
    // worker therefore has a getter-only `title`, matching `PatchProcessObject`.
    let configuration = if owns_process_state {
        v8::AccessorConfiguration::new(process_title_getter)
            .setter(process_title_setter)
            .property_attribute(v8::PropertyAttribute::NONE)
    } else {
        v8::AccessorConfiguration::new(process_title_getter)
            .property_attribute(v8::PropertyAttribute::NONE)
    };
    process
        .set_accessor_with_configuration(scope, key.into(), configuration)
        .ok_or("cannot define process.title")?;
    Ok(())
}

fn process_title_getter(
    scope: &mut v8::PinScope<'_, '_>,
    _key: v8::Local<v8::Name>,
    _args: v8::PropertyCallbackArguments<'_>,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let Some(title) = rn_uv::process_title::process_title() else {
        return;
    };
    if let Some(value) = v8::String::new(scope, &title) {
        rv.set(value.into());
    }
}

fn process_title_setter(
    scope: &mut v8::PinScope<'_, '_>,
    _key: v8::Local<v8::Name>,
    value: v8::Local<v8::Value>,
    _args: v8::PropertyCallbackArguments<'_>,
    _rv: v8::ReturnValue<()>,
) {
    // Node's `ProcessTitleSetter` runs `Utf8Value ... ; uv_set_process_title`.
    // It does not validate the argument: a non-string is coerced, and a title
    // longer than the original argv[0] area is truncated by libuv rather than
    // rejected.
    let Some(text) = value.to_string(scope) else {
        return;
    };
    rn_uv::process_title::set_process_title(&text.to_rust_string_lossy(scope));
}

/// `process.debugPort`, a native accessor pair like Node's.
///
/// `DebugPortGetter` reads the environment's inspector host port and
/// `DebugPortSetter` validates `0` or `1024..=65535` before storing it. The
/// stored value is the parsed `--inspect-port`, so `--inspect-port=9339` is what
/// the getter reports, not the `9229` default.
fn install_debug_port(
    scope: &mut v8::PinScope<'_, '_>,
    process: v8::Local<v8::Object>,
    state: ProcessState,
) -> Result<(), String> {
    // Only the owning thread records the port; a worker reads what the main
    // thread stored rather than overwriting it with its own (identical) value.
    if state.owns_process_state {
        rn_uv::process_title::set_debug_port(state.debug_port);
    }
    let key = v8::String::new(scope, "debugPort").ok_or("cannot allocate process.debugPort")?;
    let configuration = if state.owns_process_state {
        v8::AccessorConfiguration::new(process_debug_port_getter)
            .setter(process_debug_port_setter)
            .property_attribute(v8::PropertyAttribute::NONE)
    } else {
        v8::AccessorConfiguration::new(process_debug_port_getter)
            .property_attribute(v8::PropertyAttribute::NONE)
    };
    process
        .set_accessor_with_configuration(scope, key.into(), configuration)
        .ok_or("cannot define process.debugPort")?;
    Ok(())
}

fn process_debug_port_getter(
    scope: &mut v8::PinScope<'_, '_>,
    _key: v8::Local<v8::Name>,
    _args: v8::PropertyCallbackArguments<'_>,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let port = rn_uv::process_title::debug_port();
    rv.set(v8::Integer::new(scope, i32::from(port)).into());
}

fn process_debug_port_setter(
    scope: &mut v8::PinScope<'_, '_>,
    _key: v8::Local<v8::Name>,
    value: v8::Local<v8::Value>,
    _args: v8::PropertyCallbackArguments<'_>,
    _rv: v8::ReturnValue<()>,
) {
    // `DebugPortSetter` takes `Int32Value().FromMaybe(0)`, then refuses anything
    // except 0 and 1024..=65535 with `ERR_OUT_OF_RANGE`. A refused assignment
    // throws from the setter, which V8 reports as a TypeError at the assignment.
    let port = value.int32_value(scope).unwrap_or(0);
    if (port != 0 && port < 1024) || port > 65535 {
        let message = "process.debugPort must be 0 or in range 1024 to 65535";
        if let Some(text) = v8::String::new(scope, message) {
            let exception = v8::Exception::range_error(scope, text);
            if let (Ok(object), Some(code)) = (
                v8::Local::<v8::Object>::try_from(exception),
                v8::String::new(scope, "ERR_OUT_OF_RANGE"),
            ) {
                if let Some(key) = v8::String::new(scope, "code") {
                    let _ = object.set(scope, key.into(), code.into());
                }
            }
            scope.throw_exception(exception);
        }
        return;
    }
    rn_uv::process_title::set_debug_port(port.clamp(0, i32::from(u16::MAX)) as u16);
}

/// `process.domain`, which Node's bootstrap assigns as a plain `null`.
///
/// `lib/internal/bootstrap/node.js:90` is the whole implementation:
/// `process.domain = null`. It is an ordinary enumerable, writable,
/// configurable data property — `lib/domain.js` replaces it when a domain is
/// entered — so `set` reproduces it exactly and no accessor is involved.
fn install_domain(
    scope: &mut v8::PinScope<'_, '_>,
    process: v8::Local<v8::Object>,
) -> Result<(), String> {
    set(scope, process, "domain", v8::null(scope).into())
}

/// `process.sourceMapsEnabled` and `process.setSourceMapsEnabled`, from
/// `internal/source_map/source_map_cache`.
///
/// `bootstrap/node.js:386-416` defines the getter over `getSourceMapsSupport()`
/// and the setter as a call to `setSourceMapsSupport(val, {nodeModules: val,
/// generatedCode: val})`. Both come from the real module here, so the flag is the
/// same state `Error.prepareStackTrace` reads — not a parallel copy that would
/// say `true` while no source map was being consulted.
///
/// `require` is passed in rather than read from the script's scope: the script is
/// compiled as a bare script, so a free `require` would resolve against
/// `globalThis`, and at this point the global `require` is the *wrapper* the CLI
/// installs later, not the loader. Passing the loader the realm just produced
/// makes the dependency explicit.
fn install_source_maps(
    scope: &mut v8::PinScope<'_, '_>,
    process: v8::Local<v8::Object>,
) -> Result<(), String> {
    let Some(require) = rn_core::hook_slot::require(scope) else {
        // Without a loader the block cannot reach its module. The caller decides
        // whether that is fatal; here it means there is nothing to install.
        return Ok(());
    };
    let source = r#"
(function (process, require, ObjectDefineProperty) {
  const {
    getSourceMapsSupport,
    setSourceMapsSupport,
  } = require('internal/source_map/source_map_cache');
  ObjectDefineProperty(process, 'sourceMapsEnabled', {
    __proto__: null,
    enumerable: true,
    configurable: true,
    get() {
      return getSourceMapsSupport().enabled;
    },
  });
  process.setSourceMapsEnabled = function setSourceMapsEnabled(val) {
    setSourceMapsSupport(val, {
      __proto__: null,
      nodeModules: val,
      generatedCode: val,
    });
  };
})"#;
    run_setup_script(scope, source, process, require)
}

/// `process[Symbol.toStringTag]`, from `setupProcessObject`.
///
/// `bootstrap/node.js:428` defines `value: 'process'` with
/// `{enumerable: false, writable: true, configurable: false}`. The
/// non-enumerable bit is what keeps `test/common/index.js`'s globals audit quiet,
/// and `configurable: false` means the tag cannot be swapped later — both are
/// visible through `Object.getOwnPropertyDescriptor` and are what the oracle
/// reports.
fn install_process_to_string_tag(
    scope: &mut v8::PinScope<'_, '_>,
    process: v8::Local<v8::Object>,
) -> Result<(), String> {
    let Some(tag) = v8::String::new(scope, "process") else {
        return Err("cannot allocate the process toStringTag".to_string());
    };
    let symbol = v8::Symbol::get_to_string_tag(scope);
    // `DONT_ENUM` and "configurable: false" are two different flags, and
    // `PropertyAttribute` has no positive `DONT_DELETE`-off spelling: omitting
    // `DONT_DELETE` is what makes a property configurable. Node's descriptor is
    // `enumerable: false, writable: true, configurable: false`, so the delete bit
    // must be *set* here — which is the opposite of the usual reading of the flag
    // and exactly what a value-only probe would miss.
    process
        .define_own_property(
            scope,
            symbol.into(),
            tag.into(),
            v8::PropertyAttribute::DONT_ENUM | v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or_else(|| "cannot define process[Symbol.toStringTag]".to_string())?;
    Ok(())
}

/// `process._maxListeners`, which Node's `EventEmitter` constructor creates.
///
/// `setupProcessObject` calls `FunctionPrototypeCall(EventEmitter, process)`, and
/// `EventEmitter`'s constructor runs `this._maxListeners = defaultMaxListeners` —
/// an *own* data property on `process` whose value is `undefined` for a
/// `defaultMaxListeners` that is not a number. rustnode's `process` inherits
/// `_maxListeners` from a shared prototype instead, which differs in
/// `Object.prototype.hasOwnProperty.call(process, '_maxListeners')` and in
/// `Object.keys(process)`.
///
/// The descriptor is `{enumerable: true, writable: true, configurable: true}`
/// with the value `undefined`, which is what an assignment produces — so this is
/// the same shape as the assignment, written explicitly because the property has
/// to exist even though its value is `undefined`.
fn install_max_listeners(
    scope: &mut v8::PinScope<'_, '_>,
    process: v8::Local<v8::Object>,
) -> Result<(), String> {
    set(scope, process, "_maxListeners", v8::undefined(scope).into())
}

/// Runs one bootstrap-shaped script with `process` in scope.
///
/// The script returns a factory function, which this calls with `process`, the
/// realm's loader, and `Object.defineProperty`. All three are passed as
/// arguments rather than read off `globalThis`: at this point the global
/// `require` is not yet the loader, and resolving the intrinsic through the
/// global would pick up whatever user code had replaced it.
fn run_setup_script(
    scope: &mut v8::PinScope<'_, '_>,
    source: &str,
    process: v8::Local<v8::Object>,
    require: v8::Local<v8::Function>,
) -> Result<(), String> {
    let global = scope.get_current_context().global(scope);
    let Some(object_key) = v8::String::new(scope, "Object") else {
        return Err("cannot allocate the Object key".to_string());
    };
    let Some(object) = global.get(scope, object_key.into()) else {
        return Err("cannot reach Object".to_string());
    };
    let Ok(object) = v8::Local::<v8::Object>::try_from(object) else {
        return Err("Object is not an object".to_string());
    };
    let Some(define_key) = v8::String::new(scope, "defineProperty") else {
        return Err("cannot allocate the defineProperty key".to_string());
    };
    let Some(define) = object.get(scope, define_key.into()) else {
        return Err("cannot reach Object.defineProperty".to_string());
    };
    let Ok(define) = v8::Local::<v8::Function>::try_from(define) else {
        return Err("Object.defineProperty is not a function".to_string());
    };

    let Some(code) = v8::String::new(scope, source) else {
        return Err("cannot allocate the setup script".to_string());
    };
    let Some(script) = v8::Script::compile(scope, code, None) else {
        return Err("cannot compile the setup script".to_string());
    };
    let Some(factory) = script.run(scope) else {
        return Err("the setup script threw".to_string());
    };
    let Ok(factory) = v8::Local::<v8::Function>::try_from(factory) else {
        return Err("the setup script did not produce a function".to_string());
    };
    factory
        .call(
            scope,
            v8::undefined(scope).into(),
            &[process.into(), require.into(), define.into()],
        )
        .ok_or_else(|| "the setup script threw while installing".to_string())?;
    Ok(())
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
///
/// # Why the registry is looked up per call
///
/// It used to be captured as a `&'static` pointer in the callback's data slot,
/// which only worked because the CLI leaked exactly one registry for the
/// process. A worker thread runs its own realm with its own registry, and two
/// isolates must never share one — the objects a registry caches are V8 handles
/// belonging to one isolate. `rn_core::realm` keeps the registry for the thread
/// that is bootstrapping, so the lookup is a thread-local read and the pointer
/// never has to outlive anything.
fn internal_binding_dispatcher<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::class(get_internal_binding).build(scope);
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

    let Some(registry) = rn_core::realm::installed() else {
        throw(scope, "getInternalBinding was called outside a realm");
        return;
    };
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

/// Defines a property Node marks `v8::ReadOnly`.
///
/// `READ_ONLY_PROPERTY` in `src/node_process_object.cc` is
/// `Set(context, key, value, static_cast<PropertyAttribute>(ReadOnly | DontDelete))`
/// only for `pid`; the rest use plain `Set`, which a *frozen* descriptor is not.
/// What the oracle actually reports for `version`, `versions`, `platform`,
/// `arch`, `release` and `config` is `{writable: false, configurable: true,
/// enumerable: true}`, so `READ_ONLY` alone is the flag — adding `DONT_DELETE`
/// would make them non-configurable and diverge in the other direction.
fn define_read_only(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object
        .define_own_property(scope, key.into(), value, v8::PropertyAttribute::READ_ONLY)
        .ok_or_else(|| format!("cannot define {name} as read-only"))?;
    Ok(())
}

/// Defines a property Node marks read-only *and* non-configurable.
///
/// `process.features` is the one member where `bootstrap/node.js:303` passes
/// `writable: false, configurable: false`: its getters are the only way in, and a
/// configurable descriptor would let user code replace the object and defeat
/// them. The oracle reports exactly that pair, so this is the flag set for it.
fn define_read_only_frozen(
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
        .ok_or_else(|| format!("cannot define {name} as read-only and non-configurable"))?;
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

/// `getLinkedBinding`, the loader behind `process._linkedBinding()`.
///
/// `src/node_binding.cc`'s `GetLinkedBinding` checks the `addon` scope against the
/// *module name* before it looks the binding up, so the denial names the binding
/// rather than reporting the missing module. That order is what
/// `test-permission-linked-binding.js` pins: it asks for `'missing'` and expects
/// `ERR_ACCESS_DENIED` with `resource: 'missing'`.
///
/// Only the check is here: rustnode has no linked-binding registry, so a caller
/// that passes the check still gets the `ERR_INVALID_MODULE` a build without that
/// binding gives. `Environment::no_addon_permission_for_linked_bindings` is a
/// worker-only exemption; a worker copies the model onto its own thread, and this
/// thread-local check would then run there too, so the flag is not modelled.
fn get_linked_binding(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Ok(name) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        throw(scope, "The \"module\" argument must be of type string.");
        return;
    };
    let name = name.to_rust_string_lossy(scope);
    if let Some(denied) = rn_permission::runtime::deny_addon(&name) {
        denied.throw(scope);
        return;
    }
    throw_invalid_module(scope, &name);
}

/// Throws the `ERR_INVALID_MODULE` a missing linked binding reports.
fn throw_invalid_module(scope: &mut v8::PinScope<'_, '_>, name: &str) {
    let message = format!("No such binding was linked: {name}");
    let Some(text) = v8::String::new(scope, &message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    if let (Ok(object), Some(code)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, "ERR_INVALID_MODULE"),
    ) {
        if let Some(key) = v8::String::new(scope, "code") {
            let _ = object.set(scope, key.into(), code.into());
        }
    }
    scope.throw_exception(exception);
}

fn function_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::class(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

/// Throws the error `getInternalBinding` reports for a namespace this build
/// does not implement.
///
/// The `code` is `ERR_INVALID_MODULE`, the same one `throw_invalid_module`
/// uses: Node's own `getInternalBinding` reports an unlinked binding through
/// `ERR_INVALID_MODULE`, and a caller that only sees a bare message cannot tell
/// a missing namespace from a typo or a failed load. `node:ffi` is the case that
/// made this visible — the module loaded, warned that it was experimental, and
/// then failed with `code: undefined`, which reads as a bug in the caller.
fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    if let (Ok(object), Some(code)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, "ERR_INVALID_MODULE"),
    ) {
        if let Some(key) = v8::String::new(scope, "code") {
            let _ = object.set(scope, key.into(), code.into());
        }
    }
    scope.throw_exception(exception);
}

/// Installs the hand-off globals and runs the minimal bootstrap script.
///
/// This is the first thing that runs in a fresh isolate: `__argv`, `__stdout`,
/// `__stderr` and `__v8Version` exist only long enough for `bootstrap.js` to
/// copy them onto `process` and `console`, and it deletes them on the way out.
/// Leaving them visible makes `test/common/index.js` fail every test with
/// "Unexpected global(s) found", which is why the script is the one that owns
/// their lifetime.
///
/// # Why a worker calls this too
///
/// A worker isolate starts with nothing — no `process`, no `console`, no way to
/// print the reason it failed. Node's worker bootstrap assumes a realm that
/// already has them, so a worker that skipped this would fail at the first
/// `debuglog()` with a `ReferenceError` that names no cause. The hand-off is
/// per-isolate, so this writes the worker's own `argv` and its own stream
/// objects; `__stdout` and `__stderr` write to the process's real descriptors,
/// which is what Node's `createWorkerStdio` does underneath anyway.
pub fn install_globals(scope: &mut v8::PinScope, args: &[String]) -> Result<(), String> {
    let global = scope.get_current_context().global(scope);

    let argv = v8::Array::new(scope, args.len() as i32);
    for (index, arg) in args.iter().enumerate() {
        let value = v8::String::new(scope, arg).ok_or("cannot allocate argv entry")?;
        argv.set_index(scope, index as u32, value.into());
    }
    set_global(scope, global, "__argv", argv.into())?;

    let stdout = make_stream_object(scope, StdStream::Stdout)?;
    set_global(scope, global, "__stdout", stdout.into())?;

    let stderr = make_stream_object(scope, StdStream::Stderr)?;
    set_global(scope, global, "__stderr", stderr.into())?;

    let version = v8::String::new(scope, v8::V8::get_version()).ok_or("cannot allocate version")?;
    set_global(scope, global, "__v8Version", version.into())?;

    let source = v8::String::new(scope, BOOTSTRAP).ok_or("cannot allocate bootstrap source")?;
    let script = v8::Script::compile(scope, source, None).ok_or("cannot compile bootstrap")?;
    script.run(scope).ok_or("cannot run bootstrap")?;

    Ok(())
}

#[derive(Clone, Copy)]
enum StdStream {
    Stdout,
    Stderr,
}

impl StdStream {
    fn write(self, text: &str) {
        use std::io::Write;
        match self {
            Self::Stdout => {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(text.as_bytes());
                let _ = out.flush();
            }
            Self::Stderr => {
                let mut err = std::io::stderr().lock();
                let _ = err.write_all(text.as_bytes());
                let _ = err.flush();
            }
        }
    }
}

fn stream_write_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let Some(text) = args.get(0).to_string(scope) else {
        return;
    };
    let text = text.to_rust_string_lossy(scope);
    let Some(external) = v8::Local::<v8::External>::try_from(args.data()).ok() else {
        return;
    };
    // SAFETY: the pointer comes from `Box::into_raw` in `make_stream_object` and
    // lives for the whole process, so the read is valid for the callback's life.
    let stream = unsafe { *external.value().cast::<StdStream>() };
    stream.write(&text);
}

fn make_stream_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    stream: StdStream,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let external = v8::External::new(scope, Box::into_raw(Box::new(stream)).cast());
    let template = rn_core::class(stream_write_callback)
        .data(external.into())
        .build(scope);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate stream write function")?;
    let object = v8::Object::new(scope);
    let key = v8::String::new(scope, "write").ok_or("cannot allocate key")?;
    object.set(scope, key.into(), function.into());
    Ok(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_scope<R>(body: impl for<'s> FnOnce(&mut v8::PinScope<'s, '_>) -> R) -> R {
        static V8: std::sync::Once = std::sync::Once::new();
        V8.call_once(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform);
            v8::V8::initialize();
        });

        let mut isolate = v8::Isolate::new(Default::default());
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        body(scope)
    }

    fn object_field<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
        name: &str,
    ) -> v8::Local<'s, v8::Value> {
        let key = v8::String::new(scope, name).expect("field name allocates");
        object
            .get(scope, key.into())
            .unwrap_or_else(|| panic!("object field `{name}` is readable"))
    }

    #[test]
    fn process_config_variables_matches_oracle_snapshot() {
        with_scope(|scope| {
            let process = process_object(scope, &[], &[], ProcessState::main_thread(9229))
                .expect("process object is buildable");
            let config = object_field(scope, process, "config");
            let config =
                v8::Local::<v8::Object>::try_from(config).expect("process.config is an object");
            let variables = object_field(scope, config, "variables");
            let json = v8::json::stringify(scope, variables)
                .expect("config variables stringify")
                .to_rust_string_lossy(scope);

            let actual: serde_json::Value =
                serde_json::from_str(&json).expect("actual variables parse as JSON");
            let expected: serde_json::Value = serde_json::from_str(include_str!(
                "../../rn-builtins/src/build_config_variables.json"
            ))
            .expect("expected fixture parses");

            assert_eq!(actual, expected);
        });
    }
}
