//! `ShadowRealm` support: the embedder hook V8 asks for, and the realm it builds.
//!
//! # What V8 provides and what it wants from the embedder
//!
//! V8 15.x implements `ShadowRealm` itself — the syntax, `evaluate`,
//! `importValue`, the callable and value plumbing across the boundary. What it
//! does *not* have is a global object to put in the new realm, because that
//! belongs to the embedder. `Isolate::SetHostCreateShadowRealmContextCallback`
//! is the seam: V8 calls it once per `new ShadowRealm()` with the context the
//! constructor was invoked from, and the embedder answers with a fresh
//! `v8::Context` that has been bootstrapped to whatever that embedder's notion of
//! a realm is.
//!
//! With no callback installed, V8 throws the bare `Error: Not supported` that
//! rustnode used to print. That message is V8's own, which is the useful clue
//! that nothing about this needed a V8 upgrade: only the hook was missing.
//!
//! # What Node does
//!
//! `shadow_realm::HostCreateShadowRealmContextCallback` in
//! `src/node_shadow_realm.cc` constructs a `ShadowRealm` (a `Realm` subclass),
//! which:
//!
//! 1. copies the initiator realm's *security token* onto the new context, so the
//!    two realms can pass objects and functions across the boundary at all;
//! 2. creates the context through `NewContext`, which runs Node's
//!    `InitializeContext` — `Intl.v8BreakIterator` removal and the
//!    code-generation-from-strings gate that every Node context gets;
//! 3. runs `Realm::RunBootstrapping`, which is `internal/bootstrap/realm`
//!    followed by `ShadowRealm::BootstrapRealm`:
//!    `internal/bootstrap/web/exposed-wildcard` (unless `--no-browser-globals`),
//!    `internal/bootstrap/switches/does_not_own_process_state`, an
//!    `env_proxy_template` instance assigned to `process.env`, and
//!    `internal/bootstrap/shadow_realm`;
//! 4. tracks the realm on the `Environment` so it can be cleaned up and so a heap
//!    snapshot can name it.
//!
//! Point 3's last file is the important one. `internal/bootstrap/shadow_realm`
//! calls `prepareShadowRealmExecution()`, which is deliberately *not*
//! `prepareExecution`: it patches the process object without expanding `argv[1]`,
//! sets up the debug env, then calls
//! `initializeModuleLoaders({ shouldSpawnLoaderHookWorker: false,
//! shouldPreloadModules: false })` — so a ShadowRealm gets its own ESM loader
//! singleton, does not spawn a loader-hook worker, and does not run `--require`
//! preloads. It finishes by putting `vm_dynamic_import_default_internal` on
//! `globalThis[host_defined_option_symbol]`, which is what makes
//! `importValue()` route to `defaultImportModuleDynamically`.
//!
//! Notably it does **not** run `internal/bootstrap/node`. That file installs the
//! node globals (`Buffer`, `process`, `queueMicrotask`, `setTimeout`, ...) and
//! the per-isolate callbacks, none of which a ShadowRealm may see: the whole
//! point of a ShadowRealm is that its global object holds only the intrinsics
//! and the `[Exposed=*]` web interfaces.
//!
//! # What this module does
//!
//! The same sequence, over rustnode's own pieces. [`bootstrap`] is the whole of
//! it and is called from the host callback in [`install_callback`].

use rn_v8_sys::v8;

use crate::{run_bootstrap_script, run_per_context, ProcessState};

/// Creates and bootstraps the context for one `new ShadowRealm()`.
///
/// This is `shadow_realm::HostCreateShadowRealmContextCallback`. The initiator
/// context is the one the constructor ran in, which is also the context
/// `scope.get_current_context()` reports, because V8 wraps the call in a
/// callback scope for it.
///
/// Returning `None` tells V8 the realm could not be created, which it turns into
/// the exception the callback left pending. Node treats a failure here as fatal
/// (`TryCatchScope ... kFatal`); rustnode cannot abort the process from a V8
/// callback without losing the JavaScript stack that says which script asked, so
/// it throws and lets the ordinary uncaught path report it. That is the one
/// deliberate divergence, and it is strictly more informative.
pub fn create_realm<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Context>> {
    let initiator = scope.get_current_context();
    match bootstrap(scope, initiator) {
        Ok(context) => Some(context),
        Err(message) => {
            throw_error(scope, &message);
            None
        }
    }
}

/// The bootstrapping half of [`create_realm`], with the reason on failure.
fn bootstrap<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    initiator: v8::Local<'s, v8::Context>,
) -> Result<v8::Local<'s, v8::Context>, String> {
    // `Realm::New` copies the *initiator's* security token onto the new context.
    // Without it every object crossing the `evaluate` or `importValue` boundary
    // fails V8's access check, which surfaces as an empty object rather than an
    // error — `sr.evaluate('1+2')` would still answer 3 because a number needs no
    // check, but the function `evaluate` returned for a wrapped closure could not
    // be called.
    let security_token = initiator.get_security_token(scope);
    let context = v8::Context::new(scope, Default::default());
    context.set_security_token(security_token);

    // Entering the new context is what makes the rest of this work unchanged:
    // every helper below — `run_per_context`, `run_bootstrap_script`, the
    // `process` builder — reads `scope.get_current_context()`, and Node's
    // bootstrap scripts are the same scripts with the same four wrapper
    // parameters whatever realm runs them.
    let scope = &mut v8::ContextScope::new(scope, context);

    // Claim this context's realm id *before* anything writes a per-realm slot, so
    // `internal/bootstrap/realm`'s `setInternalLoaders` files the loaders under
    // this realm instead of overwriting the principal realm's.
    rn_core::hook_slot::mark_realm(scope);

    // `InitializeContext` for a non-main context: remove `Intl.v8BreakIterator`,
    // which is the one thing `InitializeBaseContextForSnapshot` does, and take
    // the code-generation-from-strings decision through the same
    // allow-then-deny dance so the context's embedder data reports what Node's
    // does.
    initialize_context(scope)?;

    // `Realm::CreateProperties` builds the per-context exports (primordials,
    // `DOMException`, the messaging symbols) and creates the realm's own
    // `process` object. A ShadowRealm gets a fresh one — `process` is per realm in
    // Node, not per environment — but it is never installed on the global.
    let primordials = v8::Object::new(scope);
    run_per_context(scope, primordials)?;
    rn_core::hook_slot::set_primordials(scope, primordials);

    let process = crate::process_object(
        scope,
        &[],
        &rn_core::hook_slot::exec_argv(),
        ProcessState::shadow_realm(),
    )?;

    // `Realm::RunBootstrapping` starts with `internal/bootstrap/realm`, and it
    // runs in *this* realm: it calls `setInternalLoaders`, which `rn-core` now
    // files under this context, so the realm's own `require` and
    // `internalBinding` are the ones its builtins close over.
    run_realm_bootstrap(scope, process, primordials)?;

    // `ShadowRealm::BootstrapRealm`, in Node's order. Each step is guarded by the
    // same condition Node uses.
    //
    // 1. `internal/bootstrap/web/exposed-wildcard`, skipped under
    //    `--no-browser-globals` exactly as `env_->no_browser_globals()` does.
    if browser_globals_enabled() {
        run_bootstrap_step(scope, "internal/bootstrap/web/exposed-wildcard")?;
    }

    // 2. `internal/bootstrap/switches/does_not_own_process_state`. The process
    //    object is not a global here, but builtins loaded in this realm still
    //    call `process.cwd()` — the ESM loader needs it — so the read-only
    //    subset and the `unavailable()` stubs have to be installed on it.
    run_bootstrap_step(
        scope,
        "internal/bootstrap/switches/does_not_own_process_state",
    )?;

    // 3. `process.env`. Node assigns an instance of its `env_proxy_template`,
    //    which is the same interceptor `process.env` is in the principal realm.
    //    `rn-realm`'s `process_env::create` builds exactly that, so this is the
    //    same object shape rather than a plain-object stand-in.
    let env = crate::process_env::create(scope)
        .ok_or("cannot allocate the shadow realm's process.env proxy")?;
    crate::set(scope, process, "env", env.into())?;

    // 4. `internal/bootstrap/shadow_realm`, which runs
    //    `prepareShadowRealmExecution()` and installs the
    //    `host_defined_option_symbol` that makes `importValue` work.
    run_bootstrap_step(scope, "internal/bootstrap/shadow_realm")?;

    // `process` was a global only so `run_bootstrap_script` could hand it to each
    // script's wrapper parameter, which is how Node's `ExecuteBootstrapper` passes
    // `realm->process_object()` too. Node never defines it on a ShadowRealm's
    // global, and neither may this: `typeof process` inside the realm has to be
    // `"undefined"`. Every builtin that needs the object captured it at module
    // scope during its own load, so removing the global does not break them.
    let global = scope.get_current_context().global(scope);
    if let Some(key) = v8::String::new(scope, "process") {
        let _ = global.delete(scope, key.into());
    }

    Ok(context)
}

/// Whether browser globals are enabled, i.e. `--no-browser-globals` was absent.
///
/// `Environment::no_browser_globals()`. It defaults to "browser globals on", so
/// the option's parsed value is only consulted to turn them off.
fn browser_globals_enabled() -> bool {
    !matches!(
        rn_bind_options::parsed::value_of("--no-browser-globals"),
        Some(rn_bind_options::parsed::ParsedValue::Bool(true))
    )
}

/// The parts of Node's `InitializeContext` that apply to a non-main context.
///
/// `InitializeBaseContextForSnapshot` — reached from
/// `InitializeMainContextForSnapshot` — deletes `Intl.v8BreakIterator`, and that
/// is the only part of Node's context initialization observable through
/// JavaScript. `InitializeContextRuntime`'s other work flips
/// code-generation-from-strings off and records the previous answer in embedder
/// data so a later `--disallow-code-generation-from-strings` check reads it; this
/// build does not consult that slot, and the V8 default already allows code
/// generation from strings, so leaving it untouched changes nothing observable.
fn initialize_context(scope: &mut v8::PinScope) -> Result<(), String> {
    let global = scope.get_current_context().global(scope);
    if let Some(intl) = crate::get_property(scope, global.into(), "Intl") {
        if let Ok(intl) = v8::Local::<v8::Object>::try_from(intl) {
            if let Some(key) = v8::String::new(scope, "v8BreakIterator") {
                let _ = intl.delete(scope, key.into());
            }
        }
    }
    Ok(())
}

/// Runs `internal/bootstrap/realm` in the current (new) context.
///
/// This is `Realm::RunBootstrapping`'s first half. It differs from
/// [`crate::bootstrap_realm`] in exactly the ways a second realm should: the
/// per-context files already ran, so `primordials` is passed in rather than
/// rebuilt, and there is no exit-state reset because the environment already has
/// one.
fn run_realm_bootstrap(
    scope: &mut v8::PinScope,
    process: v8::Local<v8::Object>,
    primordials: v8::Local<v8::Object>,
) -> Result<(), String> {
    if rn_core::realm::installed().is_none() {
        return Err("no binding registry is installed for this realm".to_string());
    }
    let global = scope.get_current_context().global(scope);
    crate::set_global(scope, global, "process", process.into())?;

    let get_linked_binding =
        crate::function_of(scope, "getLinkedBinding", crate::get_linked_binding)?;
    let get_internal_binding = crate::internal_binding_dispatcher(scope)?;

    let realm = rn_js2c::builtin_by_id("internal/bootstrap/realm")
        .ok_or("the realm bootstrap is missing from the builtin table")?;
    let function = rn_builtins::compile(scope, realm.id(), realm.source(), realm.kind())
        .ok_or("failed to compile internal/bootstrap/realm for the shadow realm")?;

    let arguments = [
        process.into(),
        get_linked_binding,
        get_internal_binding,
        primordials.into(),
    ];
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let _ = function.call(scope, global.into(), &arguments);
    if scope.has_caught() {
        let message = scope
            .exception()
            .map(|exception| caught_message(scope, exception))
            .unwrap_or_default();
        return Err(format!(
            "internal/bootstrap/realm threw in the shadow realm: {message}"
        ));
    }

    // `bootstrap/node.js` deletes the temporary `primordials` global once
    // `realm.js` has read it; the same reasoning applies here, and more strongly,
    // because this realm's global object is *user visible* through
    // `ShadowRealm#evaluate`. `test-shadow-realm-globals.js` enumerates exactly
    // this object and fails on any name that is not an intrinsic or an
    // `[Exposed=*]` interface.
    //
    // `require` is deliberately not installed on this realm's global at all: every
    // bootstrap script reaches its loader through the wrapper's `require`
    // parameter, which `realm.js` captures in its closure, so nothing below needs
    // a global copy. `process` is installed for the duration of the bootstrap —
    // `run_bootstrap_script` fills the wrapper's `process` parameter from the
    // global — and removed by the caller once the last step has run.
    if let Some(key) = v8::String::new(scope, "primordials") {
        let _ = global.delete(scope, key.into());
    }
    Ok(())
}

/// The message of the exception a `TryCatch` scope has caught.
///
/// The `stack` when the value has one, because that names the *site*: a Node
/// internal assertion's message says what went wrong but not where, and without
/// the stack a failure inside the bootstrap is a one-line message with nothing
/// to follow.
fn caught_message(scope: &mut v8::PinScope<'_, '_>, exception: v8::Local<v8::Value>) -> String {
    crate::exception_stack(scope, exception)
        .unwrap_or_else(|| exception.to_rust_string_lossy(scope))
}

/// Throws an `Error` with `message`.
fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

/// Runs one `internal/bootstrap/**` script, turning a throw into an error string.
fn run_bootstrap_step(scope: &mut v8::PinScope, id: &str) -> Result<(), String> {
    match run_bootstrap_script(scope, id) {
        Some(message) => Err(format!("{id} threw in the shadow realm: {message}")),
        None => Ok(()),
    }
}

/// The callback V8 calls for every `new ShadowRealm()`.
///
/// A bare `fn` because V8 takes a function pointer here with no data slot, which
/// is also why nothing about the creating realm is captured: the initiator comes
/// in as the current context of the callback scope V8 opens.
pub fn host_create_shadow_realm_context<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Context>> {
    create_realm(scope)
}

/// Installs the hook on the isolate.
///
/// The only API that sets it takes `&mut Isolate`, which a binding callback
/// cannot soundly reach, so this is called once from the CLI next to
/// `rn_module_wrap::install_isolate_callbacks` and for the same reason.
pub fn install_callback(isolate: &mut v8::Isolate) {
    isolate.set_host_create_shadow_realm_context_callback(host_create_shadow_realm_context);
}
