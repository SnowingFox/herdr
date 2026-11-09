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

/// Writes text to the process standard error.
type StderrWriter = Box<dyn Fn(&str)>;

thread_local! {
    static STATE: RefCell<HookState> = RefCell::new(HookState::default());
}

#[derive(Default)]
struct HookState {
    prepare_stack_trace: Option<v8::Global<v8::Function>>,
    dynamic_import: Option<v8::Global<v8::Function>>,
    import_meta: Option<v8::Global<v8::Function>>,
    import_meta_resolve: Option<v8::Global<v8::Function>>,
    source_maps_enabled: bool,
    exit_requested: bool,
    stderr: Option<StderrWriter>,
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
}
