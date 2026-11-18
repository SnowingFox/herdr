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
    /// `setEnhanceStackForFatalException`'s first callback.
    EnhanceStackBeforeInspector,
    /// `setEnhanceStackForFatalException`'s second callback: its *return value* is
    /// the text a fatal error prints, `util.inspect`'s rendering of the error.
    EnhanceStackAfterInspector,
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
/// First half of `setEnhanceStackForFatalException`.
pub const ENHANCE_STACK_BEFORE: Hook = Hook::EnhanceStackBeforeInspector;
/// Second half of `setEnhanceStackForFatalException`. Its return value is the
/// text a fatal error prints.
pub const ENHANCE_STACK_AFTER: Hook = Hook::EnhanceStackAfterInspector;

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
    ///
    /// This is the *principal* realm's pair: it is what
    /// [`set_internal_loaders`] writes and what every reader gets unless the
    /// current context has an entry of its own in [`REALM_LOADERS`].
    static LOADERS: RefCell<Loaders> = const { RefCell::new((None, None)) };

    /// Loaders for realms other than the principal one.
    ///
    /// Node keeps `builtin_module_require` and `internal_binding_loader` on the
    /// `Realm`, and `Realm::GetCurrent(context)` picks the one belonging to the
    /// context that is running. One thread can host several realms at once — a
    /// `ShadowRealm` lives inside the same isolate and the same thread as the
    /// realm that created it — so a single slot would let the second realm's
    /// `setInternalLoaders` overwrite the first's, and a builtin compiled in the
    /// principal realm afterwards would close over the shadow realm's loader.
    ///
    /// Keyed by context identity. The lookup walks a short vector because a
    /// process has one principal realm plus however many live `ShadowRealm`s,
    /// which is a handful; a `HashMap` would need `Context` to be `Hash`, and
    /// the crate exposes no identity hash for one.
    static REALM_LOADERS: RefCell<std::collections::BTreeMap<u64, Loaders>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };

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
///
/// Written for whichever realm is current: the first realm to install a pair is
/// the principal realm (its pair lives in [`LOADERS`]), and every later realm —
/// a `ShadowRealm` — gets its own entry in [`REALM_LOADERS`]. `realm.js` calls
/// `setInternalLoaders` once per realm, inside that realm's own context, so the
/// current context is what identifies it.
pub fn set_internal_loaders(
    scope: &mut v8::PinScope,
    internal_binding: v8::Global<v8::Function>,
    require: v8::Global<v8::Function>,
) {
    let loaders = (Some(internal_binding), Some(require));
    if is_principal_realm(scope) {
        LOADERS.with(|slot| *slot.borrow_mut() = loaders);
        return;
    }
    let key = realm_key(scope);
    REALM_LOADERS.with(|slot| {
        slot.borrow_mut().insert(key, loaders);
    });
}

/// The global property a realm's numeric id is stored on.
///
/// Node identifies a running realm by looking up the `Environment` on the context
/// (`Realm::GetCurrent`), which it can do because `AssignToContext` parks a
/// `ContextInfo` in embedder data. rustnode has no `Environment`, so it needs a
/// per-context place to keep a small integer.
///
/// A registered `v8::Symbol` property on the global object, resolved through
/// [`crate::symbol`] so every realm shares one identity. Two other mechanisms
/// were tried and rejected:
///
/// * `Context::set_embedder_data` — the annex it grows does not survive the
///   `ContextScope` the bootstrap enters, and a write there faults the process;
/// * a `v8::Private` property — V8 does not forward private properties through the
///   global *proxy* to the global object, so the read always missed.
///
/// A symbol is equally invisible to `JSON.stringify` and to
/// `for..in`/`Object.keys`, and `rn_core::symbol` already installs every mark of
/// this kind non-enumerably, so `test/common/index.js`'s globals audit stays clean.
const REALM_ID_PROPERTY: &str = "node:rustnode:realm_id";

/// The principal realm's id. Every other realm gets a fresh positive number.
const PRINCIPAL_REALM_ID: f64 = 0.0;

thread_local! {
    /// The next realm id to hand out on this thread.
    static NEXT_REALM_ID: std::cell::Cell<f64> = const { std::cell::Cell::new(1.0) };
}

/// The id stored on the current context's global object, if there is one.
fn read_realm_id(scope: &mut v8::PinScope) -> Option<f64> {
    let symbol = crate::symbol(scope, REALM_ID_PROPERTY);
    let global = scope.get_current_context().global(scope);
    let value = global.get(scope, symbol.into())?;
    if !value.is_number() {
        return None;
    }
    value.number_value(scope)
}

/// Stores `id` on the current context's global object.
///
/// A plain `set` is enough: a symbol key is invisible to `Object.keys`,
/// `for..in`, `JSON.stringify` and `Object.getOwnPropertyNames`, so which
/// attribute it carries cannot reach any audit.
fn write_realm_id(scope: &mut v8::PinScope, id: f64) {
    let symbol = crate::symbol(scope, REALM_ID_PROPERTY);
    let value = v8::Number::new(scope, id);
    let global = scope.get_current_context().global(scope);
    let _ = global.set(scope, symbol.into(), value.into());
}

/// The id of the realm that is running, assigning one if the global has none.
///
/// The first context to ask on a thread is the principal realm: it is the one the
/// CLI bootstraps, and a `ShadowRealm` cannot exist before that has finished
/// because it can only be constructed from user code. [`mark_realm`] lets the
/// shadow-realm bootstrap claim a fresh id for its context first, so the
/// assignment here is the fallback for a `vm` context that never ran `realm.js` —
/// which gets the principal realm's treatment, the way
/// `Realm::GetCurrent`-or-principal does in `module_wrap.cc`.
fn realm_id(scope: &mut v8::PinScope) -> f64 {
    if let Some(id) = read_realm_id(scope) {
        return id;
    }
    write_realm_id(scope, PRINCIPAL_REALM_ID);
    PRINCIPAL_REALM_ID
}

/// Whether the running realm is the principal one.
fn is_principal_realm(scope: &mut v8::PinScope) -> bool {
    realm_id(scope) == PRINCIPAL_REALM_ID
}

/// A hashable key for the running realm, for the per-realm maps.
///
/// `f64` is not `Ord`, and a `BTreeMap` is what these slots use so a lookup does
/// not allocate; the ids are small non-negative integers handed out by
/// [`mark_realm`], so their bit patterns order and hash consistently.
fn realm_key(scope: &mut v8::PinScope) -> u64 {
    realm_id(scope).to_bits()
}

/// Claims a fresh realm id for the current (newly created) context.
///
/// Called by the ShadowRealm bootstrap before it runs `internal/bootstrap/realm`,
/// so every per-realm slot the bootstrap writes lands under this realm rather than
/// the principal one. A no-op for a context that already has an id.
pub fn mark_realm(scope: &mut v8::PinScope) {
    if read_realm_id(scope).is_some() {
        return;
    }
    let id = NEXT_REALM_ID.with(|next| {
        let id = next.get();
        next.set(id + 1.0);
        id
    });
    write_realm_id(scope, id);
}

/// The running realm's id, for diagnostics and tests.
pub fn current_realm_id(scope: &mut v8::PinScope) -> f64 {
    realm_id(scope)
}

/// The loaders belonging to the realm that is running.
///
/// A context with its own entry answers from [`REALM_LOADERS`]; anything else —
/// the principal realm, and a `vm` context that never ran `realm.js` and so falls
/// back the way `Realm::GetCurrent` does — answers from [`LOADERS`].
fn loaders(scope: &mut v8::PinScope) -> Loaders {
    let found = REALM_LOADERS.with(|slot| slot.borrow().get(&realm_key(scope)).cloned());
    found.unwrap_or_else(|| LOADERS.with(|slot| slot.borrow().clone()))
}

/// Returns a local handle to the installed `require`, if this realm has one.
pub fn require<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    loaders(scope)
        .1
        .map(|require| v8::Local::new(scope, require))
}

/// Swaps the installed `require` for a wrapper around it, in the current realm.
///
/// Builtins compiled later close over whatever reference they were given at
/// compile time, so replacing the slot only affects code that reads it from
/// here on. The CLI installs the wrapper before running user code, which is the
/// window that matters: a `node:` specifier is only ever typed by user code.
pub fn replace_require(scope: &mut v8::PinScope, require: v8::Local<v8::Function>) {
    let key = realm_key(scope);
    let require = v8::Global::new(scope, require);
    if is_principal_realm(scope) {
        LOADERS.with(|slot| slot.borrow_mut().1 = Some(require));
        return;
    }
    REALM_LOADERS.with(|slot| {
        slot.borrow_mut().entry(key).or_default().1 = Some(require);
    });
}

/// Returns a local handle to the installed `internalBinding`, if it ran.
pub fn internal_binding<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    loaders(scope)
        .0
        .map(|binding| v8::Local::new(scope, binding))
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
    ///
    /// Per realm, not per thread: Node keeps `primordials` on the `Realm`, so a
    /// `ShadowRealm` gets its own from its own `internal/per_context` run. Sharing
    /// one slot would hand a bootstrap script in the second realm the first
    /// realm's `SafeMap` and `ArrayPrototypeSlice`, which is both the wrong
    /// intrinsics and a cross-realm object leak.
    static PRIMORDIALS: RefCell<Option<v8::Global<v8::Object>>> = const { RefCell::new(None) };

    /// `primordials` for realms other than the principal one.
    static REALM_PRIMORDIALS: RefCell<std::collections::BTreeMap<u64, v8::Global<v8::Object>>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
}

/// Records the `primordials` object for the current realm's later bootstrap
/// scripts.
pub fn set_primordials(scope: &mut v8::PinScope, primordials: v8::Local<v8::Object>) {
    let key = realm_key(scope);
    let primordials_global = v8::Global::new(scope, primordials);
    if is_principal_realm(scope) {
        PRIMORDIALS.with(|slot| *slot.borrow_mut() = Some(primordials_global));
        return;
    }
    REALM_PRIMORDIALS.with(|slot| {
        slot.borrow_mut().insert(key, primordials_global);
    });
}

/// A local handle to the current realm's `primordials`, if one was stored.
pub fn primordials<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let found = REALM_PRIMORDIALS.with(|slot| {
        slot.borrow()
            .get(&realm_key(scope))
            .map(|primordials| v8::Local::new(scope, primordials))
    });
    found.or_else(|| {
        PRIMORDIALS.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|primordials| v8::Local::new(scope, primordials))
        })
    })
}

/// Writes text to the process standard error.
type StderrWriter = Box<dyn Fn(&str)>;

thread_local! {
    static STATE: RefCell<HookState> = RefCell::new(HookState::default());

    /// The principal realm's per-realm callbacks.
    static PRINCIPAL_HOOKS: RefCell<RealmHooks> = RefCell::new(RealmHooks::default());

    /// Per-realm callbacks for every realm other than the principal one.
    static REALM_HOOKS: RefCell<std::collections::BTreeMap<u64, RealmHooks>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
}

struct HookState {
    prepare_stack_trace: Option<v8::Global<v8::Function>>,
    /// `setEnhanceStackForFatalException`'s pair. Separate from
    /// `prepare_stack_trace` because they are a different registration: sharing
    /// one slot meant whichever `set*` ran last won, so `afterInspector` was
    /// discarded at bootstrap and a fatal `ERR_*` printed no `code`.
    enhance_stack_before: Option<v8::Global<v8::Function>>,
    enhance_stack_after: Option<v8::Global<v8::Function>>,
    source_maps_enabled: bool,
    exit_requested: bool,
    stderr: Option<StderrWriter>,
    abort_toggle: Option<crate::AliasedUint8Array>,
    abort_on_uncaught_exception: bool,
    trace_exit: bool,
    trace_uncaught: bool,
    stack_trace_limit: i64,
    zero_fill_buffers: bool,
    extra_info_on_fatal_exception: bool,
    node_version: String,
    force_node_api_uncaught_exceptions_policy: bool,
}

/// The per-realm callbacks Node keeps on `Realm`.
///
/// `initializeESM()` runs once per realm and installs `import()`, `import.meta`
/// and `import.meta.resolve` into `Realm::GetCurrent`. Three of the four hooks
/// are therefore per realm: a `ShadowRealm` runs
/// `internal/bootstrap/shadow_realm`, which calls `prepareShadowRealmExecution`
/// and so `initializeESM` again, in a context whose `internal/modules/esm` copy
/// is its own. Sharing one slot would make the principal realm's `import()`
/// dispatch through the shadow realm's loader singleton — a different
/// `BuiltinModule.map`, so a different `internal/modules/esm/loader` instance —
/// and every module the principal realm imported would be evaluated by the wrong
/// realm's registry.
///
/// `prepare_stack_trace` is deliberately *not* here. rustnode does not install an
/// isolate `PrepareStackTraceCallback` at all, so V8's own per-context
/// `Error.prepareStackTrace` is what formats a stack, and each realm's `Error`
/// constructor therefore already works independently.
#[derive(Clone, Default)]
struct RealmHooks {
    dynamic_import: Option<v8::Global<v8::Function>>,
    import_meta: Option<v8::Global<v8::Function>>,
    import_meta_resolve: Option<v8::Global<v8::Function>>,
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
            enhance_stack_before: None,
            enhance_stack_after: None,
            source_maps_enabled: false,
            exit_requested: false,
            stderr: None,
            abort_toggle: None,
            abort_on_uncaught_exception: false,
            trace_exit: false,
            trace_uncaught: false,
            stack_trace_limit: DEFAULT_STACK_TRACE_LIMIT,
            zero_fill_buffers: false,
            // `extra_info_on_fatal_exception` defaults to *true*
            // (`src/node_options.cc:1419`), unlike every other boolean here.
            extra_info_on_fatal_exception: true,
            node_version: String::new(),
            force_node_api_uncaught_exceptions_policy: false,
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
///
/// # A worker's own list, for its children
///
/// `env->exec_argv()` in Node is a field on the *Environment*, so a worker that
/// creates another worker passes **its own** list, not the process's. The
/// process-wide slot above cannot express that: it holds the CLI's list, and a
/// nested worker reading it would inherit the main thread's flags instead of its
/// parent worker's. [`set_thread_exec_argv`] therefore records the list on the
/// worker's thread, and [`exec_argv`] prefers it. That is what makes
/// `new Worker(..., { execArgv: ['--experimental-web-worker'] })` visible to a
/// `Worker` that the thread in turn constructs —
/// `test-common-wpt-backends.js` builds its web Worker exactly that way, so
/// without this the WPT worker thread had no `Worker` global at all.
static EXEC_ARGV_SHARED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

thread_local! {
    /// This thread's own `env->exec_argv()`, when it is a worker that has one.
    ///
    /// `None` on the main thread and on a worker that never recorded a list, so
    /// [`exec_argv`] falls back to the process-wide slot and the CLI's list keeps
    /// its meaning.
    static EXEC_ARGV_THREAD: std::cell::RefCell<Option<Vec<String>>> =
        const { std::cell::RefCell::new(None) };
}

/// Records the flags this environment was started with.
pub fn set_exec_argv(argv: Vec<String>) {
    if let Ok(mut slot) = EXEC_ARGV_SHARED.lock() {
        *slot = argv;
    }
}

/// Records this worker thread's own flags, for the workers it creates.
///
/// Unlike [`set_exec_argv`] this does not touch the process-wide slot: a worker
/// inheriting its parent's list must not rewrite what the main thread reports as
/// its own.
pub fn set_thread_exec_argv(argv: Vec<String>) {
    EXEC_ARGV_THREAD.with(|slot| *slot.borrow_mut() = Some(argv));
}

/// The flags this environment was started with.
///
/// This thread's own list wins when it has one, which is Node's per-`Environment`
/// answer: a worker passes its `execArgv` to its children, not the process's.
#[must_use]
pub fn exec_argv() -> Vec<String> {
    if let Some(argv) = EXEC_ARGV_THREAD.with(|slot| slot.borrow().clone()) {
        return argv;
    }
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

/// Records whether `--zero-fill-buffers` was on the command line.
///
/// `PerProcessOptions::zero_fill_all_buffers` (`src/node_options.h:430`), which
/// `AllocateUnsafeArrayBuffer` reads (`src/node_buffer.cc:1831`). The allocation
/// itself happens in `rn-bind-buffer`, on whichever thread asks, so the value
/// has to live in the shared slot rather than in the CLI's `Options`.
pub fn set_zero_fill_buffers(value: bool) {
    STATE.with(|state| {
        state.borrow_mut().zero_fill_buffers = value;
    });
}

/// Whether `--zero-fill-buffers` was given.
#[must_use]
pub fn zero_fill_buffers() -> bool {
    STATE.with(|state| state.borrow().zero_fill_buffers)
}

/// Records whether `--no-extra-info-on-fatal-exception` was given.
///
/// `EnvironmentOptions::extra_info_on_fatal_exception`, which `ReportException`
/// reads to decide whether to print the trailing `Node.js <version>` line
/// (`src/node_errors.cc:590`). It is one of the few booleans that defaults to
/// true.
pub fn set_extra_info_on_fatal_exception(value: bool) {
    STATE.with(|state| {
        state.borrow_mut().extra_info_on_fatal_exception = value;
    });
}

/// Whether the fatal-exception trailer should be printed.
#[must_use]
pub fn extra_info_on_fatal_exception() -> bool {
    STATE.with(|state| state.borrow().extra_info_on_fatal_exception)
}

/// Records the version string the fatal-exception trailer quotes.
///
/// `NODE_VERSION` is `rn-realm`'s, and `rn-realm` depends on `rn-errors`, so the
/// text cannot be built where it is printed. The CLI records it once at startup
/// and `rn-errors` reads it from here.
pub fn set_node_version(version: String) {
    STATE.with(|state| {
        state.borrow_mut().node_version = version;
    });
}

/// The version string the fatal-exception trailer quotes.
#[must_use]
pub fn node_version() -> String {
    STATE.with(|state| state.borrow().node_version.clone())
}

/// Records whether `--force-node-api-uncaught-exceptions-policy` was given.
///
/// `EnvironmentOptions::force_node_api_uncaught_exceptions_policy`
/// (`src/node_options.h:251`). `CallbackIntoModule` reads it to decide whether a
/// module-API-version-9-or-older addon's throw becomes a fatal uncaught
/// exception or a DEP0168 deprecation warning (`src/node_api.cc:148`), and
/// `rn-napi` asks the same question here.
pub fn set_force_node_api_uncaught_exceptions_policy(value: bool) {
    STATE.with(|state| {
        state.borrow_mut().force_node_api_uncaught_exceptions_policy = value;
    });
}

/// Whether `--force-node-api-uncaught-exceptions-policy` was given.
#[must_use]
pub fn force_node_api_uncaught_exceptions_policy() -> bool {
    STATE.with(|state| state.borrow().force_node_api_uncaught_exceptions_policy)
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
///
/// `DynamicImport`, `ImportMeta` and `ImportMetaResolve` are per realm, because
/// `initializeESM()` installs them once per realm; see [`RealmHooks`]. The others
/// are per thread, because there is exactly one of each per `Environment`.
pub fn store(scope: &mut v8::PinScope, hook: Hook, callback: v8::Global<v8::Function>) {
    match hook {
        Hook::DynamicImport | Hook::ImportMeta | Hook::ImportMetaResolve => {
            realm_hooks_write(scope, |hooks| match hook {
                Hook::DynamicImport => hooks.dynamic_import = Some(callback),
                Hook::ImportMeta => hooks.import_meta = Some(callback),
                Hook::ImportMetaResolve => hooks.import_meta_resolve = Some(callback),
                Hook::PrepareStackTrace
                | Hook::SourceMaps
                | Hook::ExitRequested
                | Hook::EnhanceStackBeforeInspector
                | Hook::EnhanceStackAfterInspector => {}
            });
        }
        _ => {
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                match hook {
                    Hook::PrepareStackTrace => state.prepare_stack_trace = Some(callback),
                    Hook::EnhanceStackBeforeInspector => {
                        state.enhance_stack_before = Some(callback)
                    }
                    Hook::EnhanceStackAfterInspector => state.enhance_stack_after = Some(callback),
                    Hook::SourceMaps | Hook::ExitRequested => {}
                    Hook::DynamicImport | Hook::ImportMeta | Hook::ImportMetaResolve => {}
                }
            });
        }
    }
}

/// Mutates the current realm's [`RealmHooks`] entry, creating it when absent.
///
/// The principal realm's entry lives in a plain slot; every other realm gets a
/// vector entry keyed by context identity, the same arrangement [`REALM_LOADERS`]
/// uses and for the same reason.
fn realm_hooks_write(scope: &mut v8::PinScope, apply: impl FnOnce(&mut RealmHooks)) {
    if is_principal_realm(scope) {
        PRINCIPAL_HOOKS.with(|hooks| apply(&mut hooks.borrow_mut()));
        return;
    }
    let key = realm_key(scope);
    REALM_HOOKS.with(|slot| {
        apply(slot.borrow_mut().entry(key).or_default());
    });
}

/// A local handle to one per-realm hook callback, from the current realm.
fn realm_hooks_read<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    read: impl Fn(&RealmHooks) -> Option<&v8::Global<v8::Function>>,
) -> Option<v8::Local<'s, v8::Function>> {
    // The principal realm answers from its own slot; an unrecognised context
    // (a `vm` context that never ran `realm.js`) falls through to the same one,
    // which is Node's `Realm::GetCurrent`-or-principal fallback.
    if is_principal_realm(scope) {
        return PRINCIPAL_HOOKS
            .with(|hooks| read(&hooks.borrow()).map(|callback| v8::Local::new(scope, callback)));
    }
    let key = realm_key(scope);
    REALM_HOOKS.with(|slot| {
        slot.borrow()
            .get(&key)
            .and_then(|hooks| read(hooks).map(|callback| v8::Local::new(scope, callback)))
    })
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
    match hook {
        Hook::DynamicImport => realm_hooks_read(scope, |hooks| hooks.dynamic_import.as_ref()),
        Hook::ImportMeta => realm_hooks_read(scope, |hooks| hooks.import_meta.as_ref()),
        Hook::ImportMetaResolve => {
            realm_hooks_read(scope, |hooks| hooks.import_meta_resolve.as_ref())
        }
        Hook::PrepareStackTrace => STATE.with(|state| {
            let state = state.borrow();
            state
                .prepare_stack_trace
                .as_ref()
                .map(|callback| v8::Local::new(scope, callback))
        }),
        Hook::EnhanceStackBeforeInspector => STATE.with(|state| {
            let state = state.borrow();
            state
                .enhance_stack_before
                .as_ref()
                .map(|callback| v8::Local::new(scope, callback))
        }),
        Hook::EnhanceStackAfterInspector => STATE.with(|state| {
            let state = state.borrow();
            state
                .enhance_stack_after
                .as_ref()
                .map(|callback| v8::Local::new(scope, callback))
        }),
        Hook::SourceMaps | Hook::ExitRequested => None,
    }
}

/// `setEnhanceStackForFatalException`'s pair, for the uncaught reporter.
pub fn enhance_stack_pair<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> (
    Option<v8::Local<'s, v8::Function>>,
    Option<v8::Local<'s, v8::Function>>,
) {
    (
        stored(scope, Hook::EnhanceStackBeforeInspector),
        stored(scope, Hook::EnhanceStackAfterInspector),
    )
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
//
// Per realm, like the callback it accompanies: `setDynamicImportCallback` runs
// from `initializeESM` once per realm. The *value* is the same
// `vm_dynamic_import_default_internal` symbol in every realm, but which loader
// consumes it is not, so the slot has to follow the realm rather than the thread.
thread_local! {
    static DYNAMIC_IMPORT_REFERRER: RefCell<Option<v8::Global<v8::Value>>> =
        const { RefCell::new(None) };
    static REALM_DYNAMIC_IMPORT_REFERRER: RefCell<std::collections::BTreeMap<u64, v8::Global<v8::Value>>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
}

/// Records the sentinel symbol the dynamic-import callback receives.
pub fn set_dynamic_import_referrer(scope: &mut v8::PinScope, referrer: v8::Local<v8::Value>) {
    let key = realm_key(scope);
    let referrer = v8::Global::new(scope, referrer);
    if is_principal_realm(scope) {
        DYNAMIC_IMPORT_REFERRER.with(|slot| *slot.borrow_mut() = Some(referrer));
        return;
    }
    REALM_DYNAMIC_IMPORT_REFERRER.with(|slot| {
        slot.borrow_mut().insert(key, referrer);
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
    if is_principal_realm(scope) {
        return DYNAMIC_IMPORT_REFERRER.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|referrer| v8::Local::new(scope, referrer))
        });
    }
    let key = realm_key(scope);
    REALM_DYNAMIC_IMPORT_REFERRER.with(|slot| {
        slot.borrow()
            .get(&key)
            .map(|referrer| v8::Local::new(scope, referrer))
    })
}

/// The `vm.SourceTextModule` import.meta callback.
pub fn import_meta<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    stored(scope, Hook::ImportMeta)
}

/// Whether `import.meta.resolve` has an initializer to hang its lazy getter on.
///
/// Per realm: `initializeESM` installs the initializer once per realm, and a
/// `ShadowRealm`'s `internal/modules/esm/loader` copy is its own, so asking the
/// principal realm's slot from inside a shadow realm would answer for the wrong
/// loader.
pub fn has_import_meta_resolve(scope: &mut v8::PinScope) -> bool {
    realm_hooks_read(scope, |hooks| hooks.import_meta_resolve.as_ref()).is_some()
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
            | Hook::EnhanceStackBeforeInspector
            | Hook::EnhanceStackAfterInspector
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
            | Hook::EnhanceStackBeforeInspector
            | Hook::EnhanceStackAfterInspector
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

    /// Runs `body` with a fresh isolate, context and scope entered.
    ///
    /// Realm identity is per context, so anything that asks which realm is running
    /// needs a real one; there is no way to exercise `mark_realm` or the per-realm
    /// slots without a `v8::Context`.
    fn with_context(body: impl FnOnce(&mut v8::PinScope)) {
        crate::test_support::initialize_v8();
        let mut isolate = v8::Isolate::new(Default::default());
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        body(scope);
    }

    // Realm isolation itself is covered end to end by the CLI's integration tests
    // (a `ShadowRealm` that imports a module must not share the principal realm's
    // loader), because exercising it here needs a second `v8::Context` that the
    // test harness cannot enter the way the bootstrap does. What is unit-testable
    // without that is the id bookkeeping, which is what this covers.
    #[test]
    fn the_principal_realm_is_id_zero_and_stays_there() {
        with_context(|scope| {
            assert_eq!(current_realm_id(scope), PRINCIPAL_REALM_ID);
            // Asking again must not hand out a second id: `realm_id` runs on every
            // `internalBinding` and hook access, and a re-assignment would look
            // like a new realm.
            assert_eq!(current_realm_id(scope), PRINCIPAL_REALM_ID);
            // `mark_realm` is a no-op on a context that already has an id, which
            // is what keeps the bootstrap from renumbering the principal realm if
            // it were ever called from there.
            mark_realm(scope);
            assert_eq!(current_realm_id(scope), PRINCIPAL_REALM_ID);
        });
    }

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
