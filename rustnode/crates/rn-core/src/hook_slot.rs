//! Per-isolate hooks shared between bindings that cannot see each other.
//!
//! Several namespaces need the same per-isolate facts: the error hooks
//! `errors` stores for later V8 callbacks, the flag `setSourceMapsEnabled`
//! toggles, and the "an exception was reported, exit now" request that the
//! uncaught-exception path raises. They live here rather than in a binding crate
//! so both `errors` and the CLI can read them without one depending on the
//! other's internals.

use std::cell::RefCell;

use rn_v8_sys::v8;

/// Which hook a stored callback belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    /// `setPrepareStackTraceCallback`: V8 calls this to format `error.stack`.
    PrepareStackTrace,
    /// `setSourceMapsEnabled`: whether source maps are consulted.
    SourceMaps,
    /// Set when an uncaught exception was reported and the process must exit.
    ExitRequested,
    /// `setImportModuleDynamicallyCallback`: V8 calls this for `import()`.
    DynamicImport,
    /// `setInitializeImportMetaObjectCallback`: fills in `import.meta`.
    ImportMeta,
    /// `setImportMetaResolveInitializer`: backs `import.meta.resolve`.
    ImportMetaResolve,
}

/// V8 calls this to turn a stack trace into the `error.stack` string.
pub const CALLBACK: Hook = Hook::PrepareStackTrace;
/// Whether source maps are consulted when formatting a stack.
pub const SOURCE_MAPS: Hook = Hook::SourceMaps;
/// Set when an uncaught exception was reported and the process must exit.
pub const EXIT_REQUESTED: Hook = Hook::ExitRequested;
/// Callback V8 invokes for a dynamic `import()`.
pub const DYNAMIC_IMPORT: Hook = Hook::DynamicImport;
/// Callback that populates `import.meta` for a module.
pub const IMPORT_META: Hook = Hook::ImportMeta;
/// Callback behind `import.meta.resolve`.
pub const IMPORT_META_RESOLVE: Hook = Hook::ImportMetaResolve;

/// The loaders `realm.js` installs, once it has.
type Loaders = (
    Option<v8::Global<v8::Function>>,
    Option<v8::Global<v8::Function>>,
);

thread_local! {
    /// The `internalBinding` and `require` functions Node's `realm.js` installs
    /// through `setInternalLoaders`.
    ///
    /// Every builtin compiled after the bootstrap closes over these, and the CLI
    /// needs `require` to run a user script, so they have to outlive the call
    /// that stored them.
    static LOADERS: RefCell<Loaders> = const { RefCell::new((None, None)) };

    /// The `emitWarningSync` function the process bootstrap installed.
    ///
    /// Node keeps this on `Environment` as `process_emit_warning_sync_`, and
    /// `ProcessEmitWarning` is what every native warning goes through. It lives
    /// here rather than only in `rn-bind-process-methods` because a binding crate
    /// that must warn cannot depend on that crate — the messaging namespace's
    /// "posted to itself" case is one — and reaching into another crate's private
    /// thread-local would make that crate's implementation another's contract.
    static WARNING_SINK: RefCell<Option<v8::Global<v8::Function>>> = const { RefCell::new(None) };

    /// The sandbox-to-`v8::Context` lookup `rn-bind-contextify` owns.
    ///
    /// Node's `ContextifyContext::ContextFromContextifiedSandbox`, which any native
    /// code holding a `vm` sandbox can call. A callback here for the same reason as
    /// [`WARNING_SINK`]: `moveMessagePortToContext` needs it, the table it reads
    /// belongs to `rn-bind-contextify`, and depending on that crate from messaging
    /// would invert the registration order rather than express a real dependency.
    static SANDBOX_CONTEXT: RefCell<Option<SandboxContextLookup>> = const { RefCell::new(None) };
}

/// A function that resolves a `vm` sandbox to the realm it contextifies.
///
/// Higher-ranked over the scope's local lifetime alone, like every other callback
/// this crate stores: the `Local<Context>` it returns is owned by the caller's
/// scope, and the table it reads is `rn-bind-contextify`'s thread-local, which is
/// why this is a `fn` pointer rather than a closure over that crate's internals.
pub type SandboxContextLookup = for<'s> fn(
    &mut v8::PinScope<'s, '_>,
    v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Context>>;

/// Records the process's synchronous warning emitter.
///
/// Called by `setEmitWarningSync`, which `lib/internal/bootstrap/node.js` invokes
/// once per realm. One slot per thread, replaced rather than accumulated: a
/// worker's realm installs its own, and a warning must reach the emitter of the
/// thread that produced it.
pub fn set_warning_sink(callback: v8::Global<v8::Function>) {
    WARNING_SINK.with(|slot| *slot.borrow_mut() = Some(callback));
}

/// Records the sandbox-to-context lookup.
///
/// Called once by `rn-bind-contextify`'s `install`, which is the only place that
/// can answer the question.
pub fn set_sandbox_context_lookup(lookup: SandboxContextLookup) {
    SANDBOX_CONTEXT.with(|slot| *slot.borrow_mut() = Some(lookup));
}

/// Resolves a `vm` sandbox to its realm, if contextify has installed the lookup.
///
/// `None` means either that the value is not a contextified sandbox or that no
/// `contextify` namespace has been installed on this thread, which is the same
/// answer `ContextFromContextifiedSandbox` gives for a non-sandbox: the caller
/// reports an invalid context argument.
pub fn sandbox_context<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Context>> {
    let lookup = SANDBOX_CONTEXT.with(|slot| *slot.borrow())?;
    lookup(scope, value)
}

/// Emits a process warning through the installed emitter.
///
/// Node's `ProcessEmitWarning`. It returns `bool` because a Rust caller cannot
/// `CHECK`: before the bootstrap installs the emitter Node aborts, and a warning
/// that could not be delivered is better reported than silently dropped.
///
/// # The `process.emitWarning` fallback
///
/// `setEmitWarningSync` has exactly one caller in `lib/**` — line 357 of
/// `internal/bootstrap/node.js` — and this build does not run that file (it cannot
/// yet; see `rn-realm`'s `install_web_globals`). So the slot is empty on this
/// build, and a binding's warning would vanish. `process.emitWarning` is installed
/// and works, so that is the fallback: the warning is queued on `nextTick` rather
/// than printed synchronously, which is a difference in timing rather than in
/// whether the user sees it.
pub fn emit_warning(scope: &mut v8::PinScope<'_, '_>, message: &str) -> bool {
    let callback = WARNING_SINK.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    });
    let callback = callback.or_else(|| process_emit_warning(scope));
    let Some(callback) = callback else {
        return false;
    };
    let Some(message) = v8::String::new(scope, message) else {
        return false;
    };
    callback
        .call(scope, v8::undefined(scope).into(), &[message.into()])
        .is_some()
}

/// `process.emitWarning`, when the realm has one.
fn process_emit_warning<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    let global = scope.get_current_context().global(scope);
    let process_key = v8::String::new(scope, "process")?;
    let process = global.get(scope, process_key.into())?;
    let process = v8::Local::<v8::Object>::try_from(process).ok()?;
    let method_key = v8::String::new(scope, "emitWarning")?;
    let method = process.get(scope, method_key.into())?;
    v8::Local::<v8::Function>::try_from(method).ok()
}

/// Records the loaders `realm.js` installed.
pub fn set_internal_loaders(
    internal_binding: v8::Global<v8::Function>,
    require: v8::Global<v8::Function>,
) {
    LOADERS.with(|loaders| {
        *loaders.borrow_mut() = (Some(internal_binding), Some(require));
    });
}

/// Returns a local handle to the installed `require`, if the bootstrap ran.
pub fn require<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    LOADERS.with(|loaders| {
        loaders
            .borrow()
            .1
            .as_ref()
            .map(|require| v8::Local::new(scope, require))
    })
}

/// Swaps the installed `require` for a wrapper around it.
///
/// Builtins compiled later close over whatever reference they were given at
/// compile time, so replacing the slot only affects code that reads it from
/// here on. The CLI installs the wrapper before running user code, which is the
/// window that matters: a `node:` specifier is only ever typed by user code.
pub fn replace_require(scope: &mut v8::PinScope, require: v8::Local<v8::Function>) {
    let global = v8::Global::new(scope, require);
    LOADERS.with(|loaders| {
        loaders.borrow_mut().1 = Some(global);
    });
}

/// Returns a local handle to the installed `internalBinding`, if it ran.
pub fn internal_binding<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    LOADERS.with(|loaders| {
        loaders
            .borrow()
            .0
            .as_ref()
            .map(|binding| v8::Local::new(scope, binding))
    })
}

thread_local! {
    /// The `primordials` object, kept out of `globalThis`.
    ///
    /// Node builds `primordials` in `internal/per_context/primordials` and passes
    /// it to every bootstrap script as a parameter; it is never a global. The
    /// bootstrap scripts in `internal/bootstrap/**` still *read* it as a free
    /// variable (`const { ObjectDefineProperty } = primordials;`), which Node
    /// satisfies by compiling them with `primordials` in the wrapper's parameter
    /// list — not by defining a global.
    ///
    /// rustnode cannot use the parameter path for the files it runs through
    /// `run_bootstrap_script`, because the object has to be the same one
    /// `realm.js` built. Holding it here lets that call site hand over the real
    /// object while `globalThis` stays clean, which is what
    /// `test/common/index.js`'s globals audit requires.
    static PRIMORDIALS: RefCell<Option<v8::Global<v8::Object>>> = const { RefCell::new(None) };
}

/// Records the `primordials` object for later bootstrap scripts.
pub fn set_primordials(scope: &mut v8::PinScope, primordials: v8::Local<v8::Object>) {
    let global = v8::Global::new(scope, primordials);
    PRIMORDIALS.with(|slot| *slot.borrow_mut() = Some(global));
}

/// A local handle to the recorded `primordials`, if one was stored.
pub fn primordials<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    PRIMORDIALS.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|primordials| v8::Local::new(scope, primordials))
    })
}

/// Writes text to the process standard error.
type StderrWriter = Box<dyn Fn(&str)>;

thread_local! {
    static STATE: RefCell<HookState> = RefCell::new(HookState::default());
}

struct HookState {
    prepare_stack_trace: Option<v8::Global<v8::Function>>,
    dynamic_import: Option<v8::Global<v8::Function>>,
    import_meta: Option<v8::Global<v8::Function>>,
    import_meta_resolve: Option<v8::Global<v8::Function>>,
    source_maps_enabled: bool,
    exit_requested: bool,
    stderr: Option<StderrWriter>,
    abort_toggle: Option<crate::AliasedUint8Array>,
    abort_on_uncaught_exception: bool,
    trace_exit: bool,
    trace_uncaught: bool,
    stack_trace_limit: i64,
}

/// Node's `PerIsolateOptions::stack_trace_limit` default (`src/node_options.h:359`).
///
/// Spelled here rather than defaulted to `0` because `0` is a *meaningful* value
/// for the option — it prints no frames — so a default of zero would make "the
/// limit was never recorded" and "the limit was set to zero" the same state.
const DEFAULT_STACK_TRACE_LIMIT: i64 = 10;

impl Default for HookState {
    fn default() -> Self {
        Self {
            prepare_stack_trace: None,
            dynamic_import: None,
            import_meta: None,
            import_meta_resolve: None,
            source_maps_enabled: false,
            exit_requested: false,
            stderr: None,
            abort_toggle: None,
            abort_on_uncaught_exception: false,
            trace_exit: false,
            trace_uncaught: false,
            stack_trace_limit: DEFAULT_STACK_TRACE_LIMIT,
        }
    }
}

/// Records the `Uint8Array(1)` `internalBinding('util')` publishes as
/// `shouldAbortOnUncaughtToggle`.
///
/// Node keeps this as an `AliasedUint32Array` on the `Environment`
/// (`env.h:1324`) and initializes it to `1` (`env.cc:1218`), because the
/// JavaScript layer only ever writes `0` or `1` and the native side reads the
/// byte. The binding that owns the array calls this so the fatal-exception path
/// can read the same allocation without depending on `rn-util`.
pub fn set_abort_toggle(toggle: crate::AliasedUint8Array) {
    STATE.with(|state| {
        state.borrow_mut().abort_toggle = Some(toggle);
    });
}

/// Whether `shouldAbortOnUncaughtToggle[0]` is non-zero.
///
/// `true` when no array is installed, matching Node's initialized-to-`1`
/// default: a realm that never installed `util` still aborts when the flag says
/// to. Reading a `None` as "do not abort" would silently disable the flag for
/// any caller that installs the error reporting path before the util namespace.
pub fn abort_toggle_allows_abort() -> bool {
    STATE.with(|state| {
        state
            .borrow()
            .abort_toggle
            .as_ref()
            .is_none_or(|toggle| toggle.flag(0))
    })
}

/// Records whether `--abort-on-uncaught-exception` was on the command line.
///
/// This is `EnvironmentOptions::abort_on_uncaught_exception`, set by
/// `src/node.cc:794` from the V8 argument vector. Node keeps it on the
/// environment rather than reading the option layer at report time, so a later
/// `v8.setFlagsFromString` cannot change it.
pub fn set_abort_on_uncaught_exception(value: bool) {
    STATE.with(|state| {
        state.borrow_mut().abort_on_uncaught_exception = value;
    });
}

/// Whether an uncaught exception must abort the process.
pub fn abort_on_uncaught_exception() -> bool {
    STATE.with(|state| state.borrow().abort_on_uncaught_exception)
}

/// Records whether `--trace-exit` was on the command line.
///
/// This is `EnvironmentOptions::trace_exit`, which `Environment::Exit` reads to
/// print the `WARNING: Exited the environment with code N` line and the stack
/// that led there. It lives here rather than in the CLI for the same reason
/// [`abort_on_uncaught_exception`] does: the exit happens in whichever crate
/// owns the exit path — `process.reallyExit` in `rn-bind-process-methods`, the
/// CLI's own `terminate`, a worker's environment teardown — and every one of
/// them has to see the same value.
///
/// Node reads the option from the environment rather than from the option
/// layer at exit time, so `v8.setFlagsFromString` cannot change it; the same
/// holds here.
pub fn set_trace_exit(value: bool) {
    STATE.with(|state| {
        state.borrow_mut().trace_exit = value;
    });
}

/// Whether `--trace-exit` was given.
#[must_use]
pub fn trace_exit() -> bool {
    STATE.with(|state| state.borrow().trace_exit)
}

/// Records whether `--trace-uncaught` was on the command line.
///
/// `EnvironmentOptions::trace_uncaught`. Two things read it, and they are the
/// two halves of what the flag does: `Environment::InitializeDiagnostics` turns
/// on V8's capture of the stack behind an uncaught exception, and
/// `ReportException` prints the `Thrown at:` block from that capture instead of
/// the `(Use \`node --trace-uncaught ...\`)` hint.
pub fn set_trace_uncaught(value: bool) {
    STATE.with(|state| {
        state.borrow_mut().trace_uncaught = value;
    });
}

/// Whether `--trace-uncaught` was given.
#[must_use]
pub fn trace_uncaught() -> bool {
    STATE.with(|state| state.borrow().trace_uncaught)
}

/// The flags this environment was started with, for `process.execArgv`.
///
/// Node keeps these on `Environment` (`env->exec_argv()`), and they are the
/// *parent's* list in a worker whose `execArgv` was not given:
/// `src/node_worker.cc:664` copies `env->exec_argv()` into the worker's own list
/// when `options.execArgv` is absent. That inheritance is why `--trace-exit` on
/// the parent is visible inside a worker, which is what `test-trace-exit.js`'s
/// two worker cases assert.
///
/// Process-wide rather than a thread-local, because a worker is the reader: its
/// thread starts with empty thread-locals, so a thread-local record of the
/// parent's argv would be invisible exactly where the inheritance has to happen.
/// Node's worker constructor reads the parent `Environment`'s field across the
/// same boundary, from the thread that is still the parent. Writing happens once,
/// from the CLI before any worker exists, so the lock is uncontended in practice.
static EXEC_ARGV_SHARED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Records the flags this environment was started with.
pub fn set_exec_argv(argv: Vec<String>) {
    if let Ok(mut slot) = EXEC_ARGV_SHARED.lock() {
        *slot = argv;
    }
}

/// The flags this environment was started with.
#[must_use]
pub fn exec_argv() -> Vec<String> {
    EXEC_ARGV_SHARED
        .lock()
        .map(|slot| slot.clone())
        .unwrap_or_default()
}

/// Records this environment's `--stack-trace-limit`.
///
/// `PerIsolateOptions::stack_trace_limit`, which `Environment::stack_trace_limit()`
/// reports and both `Environment::Exit`'s trace and `Error.stackTraceLimit`
/// read. It is recorded rather than looked up from the option store because the
/// store is `rn-bind-options`' and this crate is below it; the CLI and the
/// worker bootstrap are the two places that know the parsed value, and both run
/// before any exit can be traced.
pub fn set_stack_trace_limit(value: i64) {
    STATE.with(|state| {
        state.borrow_mut().stack_trace_limit = value;
    });
}

/// This environment's `--stack-trace-limit`, defaulting to Node's `10`.
#[must_use]
pub fn stack_trace_limit() -> i64 {
    STATE.with(|state| state.borrow().stack_trace_limit)
}

/// Installs a closure that writes to the process's standard error.
///
/// The CLI owns the real stream, so it registers the writer here and bindings
/// that must print during a fatal path call [`write_stderr`].
pub fn set_stderr_writer(writer: impl Fn(&str) + 'static) {
    STATE.with(|state| {
        state.borrow_mut().stderr = Some(Box::new(writer));
    });
}

pub fn write_stderr(text: &str) {
    STATE.with(|state| {
        let state = state.borrow();
        match state.stderr.as_ref() {
            Some(writer) => writer(text),
            None => {
                use std::io::Write;
                let mut stderr = std::io::stderr().lock();
                let _ = stderr.write_all(text.as_bytes());
                let _ = stderr.flush();
            }
        }
    });
}

/// Stores the callback for a hook, replacing any previous one.
pub fn store(scope: &mut v8::PinScope, hook: Hook, callback: v8::Global<v8::Function>) {
    let _ = scope;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        match hook {
            Hook::PrepareStackTrace => state.prepare_stack_trace = Some(callback),
            Hook::DynamicImport => state.dynamic_import = Some(callback),
            Hook::ImportMeta => state.import_meta = Some(callback),
            Hook::ImportMetaResolve => state.import_meta_resolve = Some(callback),
            Hook::SourceMaps | Hook::ExitRequested => {}
        }
    });
}

/// Calls the stored `PrepareStackTraceCallback` if there is one.
pub fn prepare_stack_trace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    global: v8::Local<'s, v8::Value>,
    error: v8::Local<'s, v8::Value>,
    trace: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Value>> {
    let callback = STATE.with(|state| {
        state
            .borrow()
            .prepare_stack_trace
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    })?;
    let argv = [global, error, trace];
    callback.call(scope, v8::undefined(scope).into(), &argv)
}

/// Returns a local handle to one stored hook callback.
fn stored<'s>(scope: &mut v8::PinScope<'s, '_>, hook: Hook) -> Option<v8::Local<'s, v8::Function>> {
    STATE.with(|state| {
        let state = state.borrow();
        let callback = match hook {
            Hook::PrepareStackTrace => state.prepare_stack_trace.as_ref(),
            Hook::DynamicImport => state.dynamic_import.as_ref(),
            Hook::ImportMeta => state.import_meta.as_ref(),
            Hook::ImportMetaResolve => state.import_meta_resolve.as_ref(),
            Hook::SourceMaps | Hook::ExitRequested => None,
        }?;
        Some(v8::Local::new(scope, callback))
    })
}

/// The `import()` callback `internal/modules/esm/utils.js` installs.
///
/// V8's dynamically-import handler is a plain `fn` with no data slot, so it
/// reads the real callback from here on every call. That also means the handler
/// sees a later `setImportModuleDynamicallyCallback` immediately, which is what
/// a second realm in the same isolate needs.
pub fn dynamic_import<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    stored(scope, Hook::DynamicImport)
}

// Where `set_dynamic_import_referrer` parks the symbol, so
// `dynamic_import_referrer` can hand it back. Documented on that function.
thread_local! {
    static DYNAMIC_IMPORT_REFERRER: RefCell<Option<v8::Global<v8::Value>>> =
        const { RefCell::new(None) };
}

/// Records the sentinel symbol the dynamic-import callback receives.
pub fn set_dynamic_import_referrer(scope: &mut v8::PinScope, referrer: v8::Local<v8::Value>) {
    let referrer = v8::Global::new(scope, referrer);
    DYNAMIC_IMPORT_REFERRER.with(|slot| {
        *slot.borrow_mut() = Some(referrer);
    });
}

/// The referrer symbol handed to the dynamic-import callback, once one has been
/// recorded.
///
/// `importModuleDynamicallyCallback` in `internal/modules/esm/utils.js` compares
/// this argument by identity against four well-known symbols and throws
/// `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING` when none match, so it has to be the
/// very symbol `internalBinding('symbols')` publishes: a symbol created here
/// would be a different object with the same description and every `import()`
/// would throw. `rn-core` cannot depend on the `symbols` binding crate, so
/// [`set_dynamic_import_referrer`] records the real one and this hands it back.
///
/// rustnode has no per-module host options yet, so the recorded value is the
/// `vm_dynamic_import_default_internal` sentinel, which routes an ordinary
/// `import()` from any context to the default loader.
pub fn dynamic_import_referrer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Value>> {
    DYNAMIC_IMPORT_REFERRER.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|referrer| v8::Local::new(scope, referrer))
    })
}

/// The `vm.SourceTextModule` import.meta callback.
pub fn import_meta<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    stored(scope, Hook::ImportMeta)
}

/// Whether `import.meta.resolve` has an initializer to hang its lazy getter on.
pub fn has_import_meta_resolve() -> bool {
    STATE.with(|state| state.borrow().import_meta_resolve.is_some())
}

/// The `import.meta.resolve` initializer, which closes over the loader.
pub fn import_meta_resolve<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    stored(scope, Hook::ImportMetaResolve)
}

pub fn set_flag(scope: &mut v8::PinScope, hook: Hook, value: bool) {
    let _ = scope;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        match hook {
            Hook::SourceMaps => state.source_maps_enabled = value,
            Hook::ExitRequested => state.exit_requested = value,
            Hook::PrepareStackTrace
            | Hook::DynamicImport
            | Hook::ImportMeta
            | Hook::ImportMetaResolve => {}
        }
    });
}

pub fn flag(hook: Hook) -> bool {
    STATE.with(|state| {
        let state = state.borrow();
        match hook {
            Hook::SourceMaps => state.source_maps_enabled,
            Hook::ExitRequested => state.exit_requested,
            Hook::PrepareStackTrace
            | Hook::DynamicImport
            | Hook::ImportMeta
            | Hook::ImportMetaResolve => false,
        }
    })
}

/// Clears the exit request so a handled exception does not end the process.
pub fn clear_exit_request() {
    STATE.with(|state| state.borrow_mut().exit_requested = false);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_default_to_false_and_round_trip() {
        assert!(!flag(Hook::SourceMaps));
        // The flag setters take a scope only for signature parity with the
        // bindings; the state itself is per-thread.
        STATE.with(|state| state.borrow_mut().source_maps_enabled = true);
        assert!(flag(Hook::SourceMaps));
        STATE.with(|state| state.borrow_mut().source_maps_enabled = false);
    }

    #[test]
    fn stderr_writer_can_be_replaced() {
        set_stderr_writer(|_| {});
        write_stderr("ignored");
        clear_exit_request();
        assert!(!flag(Hook::ExitRequested));
    }

    thread_local! {
        static ORDER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    fn first() {
        ORDER.with(|order| order.borrow_mut().push(1));
    }

    fn second() {
        ORDER.with(|order| order.borrow_mut().push(2));
    }

    #[test]
    fn teardown_hooks_run_newest_first_exactly_once() {
        ORDER.with(|order| order.borrow_mut().clear());
        add_teardown_hook(first);
        // Registering twice must not queue the same function twice: a binding that
        // registers on every call would otherwise grow the list without bound.
        add_teardown_hook(first);
        add_teardown_hook(second);

        run_teardown_hooks();
        assert_eq!(ORDER.with(|order| order.borrow().clone()), vec![2, 1]);

        // The list is cleared, so a second teardown on the same thread is a no-op
        // rather than running a disposed realm's hooks again.
        run_teardown_hooks();
        assert_eq!(ORDER.with(|order| order.borrow().clone()), vec![2, 1]);
        assert!(!has_teardown_hooks());
    }

    #[test]
    fn the_abort_option_defaults_to_off() {
        STATE.with(|state| state.borrow_mut().abort_on_uncaught_exception = false);
        assert!(!abort_on_uncaught_exception());
        set_abort_on_uncaught_exception(true);
        assert!(abort_on_uncaught_exception());
        set_abort_on_uncaught_exception(false);
    }

    #[test]
    fn a_missing_toggle_does_not_suppress_the_abort() {
        // Node initializes `should_abort_on_uncaught_toggle_[0]` to `1`
        // (`src/env.cc:1218`), so "no array installed" has to read as "abort
        // allowed". Reading `None` as `false` would silently disable the flag in
        // any realm that never installed the `util` namespace.
        STATE.with(|state| state.borrow_mut().abort_toggle = None);
        assert!(abort_toggle_allows_abort());
    }
}

thread_local! {
    /// The worker's environment message port, as the object
    /// `internalBinding('worker').getEnvMessagePort()` returns.
    ///
    /// Node keeps this on `Environment` (`env->set_message_port`), which is
    /// per-isolate, and `getEnvMessagePort` reads it back. It is thread-local
    /// here for the same reason: a worker has one and the main thread has none,
    /// and a shared slot would let a worker answer with the main thread's port.
    ///
    /// `None` on the main thread is not a gap — `createWorkerStdio()` in
    /// `lib/internal/worker/io.js` is the only caller and it runs only from the
    /// worker-side bootstrap switch.
    static ENV_MESSAGE_PORT: RefCell<Option<v8::Global<v8::Object>>> = const { RefCell::new(None) };
}

/// Records the port `getEnvMessagePort()` should answer with.
pub fn set_env_message_port(scope: &mut v8::PinScope, port: v8::Local<v8::Object>) {
    let port = v8::Global::new(scope.as_ref(), port);
    ENV_MESSAGE_PORT.with(|slot| *slot.borrow_mut() = Some(port));
}

/// The recorded port, if this thread has one.
pub fn env_message_port<'s>(scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    ENV_MESSAGE_PORT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|port| v8::Local::new(scope, port))
    })
}

/// Clears the recorded port, so a new realm on this thread does not inherit a
/// handle from the isolate that ran before it.
pub fn clear_env_message_port() {
    ENV_MESSAGE_PORT.with(|slot| *slot.borrow_mut() = None);
}

thread_local! {
    /// What a realm teardown must run, in registration order.
    ///
    /// Node has `Environment::AddCleanupHook` for exactly this, and the lock
    /// manager is its main user: `LockManager::OnEnvironmentCleanup` drops the
    /// environment's held locks and pending requests, so a worker that terminates
    /// mid-request cannot leave a resource held by a thread that no longer exists.
    /// rustnode had no equivalent, so a `navigator.locks` request queued by a
    /// worker that was then terminated stayed in the queue forever and every later
    /// request for that name blocked behind it.
    ///
    /// Additive and per thread: a worker registers its own hook, and clearing them
    /// when the realm ends is what stops a reused thread from running a hook that
    /// belongs to an environment that is gone.
    static TEARDOWN_HOOKS: RefCell<Vec<fn()>> = const { RefCell::new(Vec::new()) };
}

/// Registers work that must run when this thread's realm is torn down.
///
/// Idempotent per function pointer, so a binding that registers on every call
/// does not accumulate hooks.
pub fn add_teardown_hook(hook: fn()) {
    TEARDOWN_HOOKS.with(|hooks| {
        let mut hooks = hooks.borrow_mut();
        if !hooks.contains(&hook) {
            hooks.push(hook);
        }
    });
}

/// Runs every teardown hook, newest first, and clears the list.
///
/// Newest first is Node's `RunCleanup` order: a hook registered later may depend
/// on state a hook registered earlier created, so it has to run while that state
/// is still there.
pub fn run_teardown_hooks() {
    let hooks = TEARDOWN_HOOKS.with(|hooks| std::mem::take(&mut *hooks.borrow_mut()));
    for hook in hooks.into_iter().rev() {
        hook();
    }
}

/// Whether any teardown hook is registered. Tests read it.
#[must_use]
pub fn has_teardown_hooks() -> bool {
    TEARDOWN_HOOKS.with(|hooks| !hooks.borrow().is_empty())
}
