//! `internalBinding('errors')`.
//!
//! This namespace carries the pieces of Node's uncaught-exception path that
//! cannot live in JavaScript: the V8 message introspection, the
//! `PrepareStackTraceCallback` V8 calls, and the point where control leaves the
//! engine. `lib/internal/errors.js` supplies the formatting around it.
//!
//! Two behaviours here are load-bearing for compatibility and easy to get
//! subtly wrong:
//!
//! * `triggerUncaughtException` must call `process._fatalException` so user code
//!   gets its chance to handle the error, and only print when that returns
//!   false. Printing unconditionally would break every `uncaughtException`
//!   listener.
//! * `getErrorSourcePositions` must expose `startColumn`, not `endColumn`,
//!   because V8's end column is unreliable for multi-byte sources. Node's C++
//!   drops it deliberately and the JavaScript side destructures only what it
//!   gets.

use std::cell::Cell;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/errors.json`.
pub const MEMBERS: &[&str] = &[
    "exitCodes",
    "getErrorSourcePositions",
    "noSideEffectsToString",
    "setEnhanceStackForFatalException",
    "setGetSourceMapErrorSource",
    "setMaybeCacheGeneratedSourceMap",
    "setPrepareStackTraceCallback",
    "setSourceMapsEnabled",
    "triggerUncaughtException",
];

/// `node::ExitCode`, from `src/node_exit_code.h`.
///
/// The values are part of Node's observable contract: a test runner or shell
/// script distinguishes a command-line error from a user error by them.
pub const EXIT_CODES: &[(&str, i32)] = &[
    ("kNoFailure", 0),
    ("kGenericUserError", 1),
    ("kInternalJSParseError", 3),
    ("kInternalJSEvaluationFailure", 4),
    ("kV8FatalError", 5),
    ("kInvalidFatalExceptionMonkeyPatching", 6),
    ("kExceptionInFatalExceptionHandler", 7),
    ("kInvalidCommandLineArgument", 9),
    ("kBootstrapFailure", 10),
    ("kInvalidCommandLineArgument2", 12),
    ("kUnsettledTopLevelAwait", 13),
    ("kStartupSnapshotFailure", 14),
    ("kProcessTimeout", 124),
    ("kAbort", 134),
];

pub struct Errors;

impl BindingModule for Errors {
    fn namespace(&self) -> &'static str {
        "errors"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        let exit_codes = v8::Object::new(scope);
        for (name, code) in EXIT_CODES {
            if let Some(key) = v8::String::new(scope, name) {
                let value = v8::Integer::new(scope, *code);
                exit_codes.set(scope, key.into(), value.into());
            }
        }

        let members: [(&str, v8::Local<v8::Value>); 9] = [
            ("exitCodes", exit_codes.into()),
            (
                "getErrorSourcePositions",
                function(scope, "getErrorSourcePositions", get_error_source_positions)?,
            ),
            (
                "noSideEffectsToString",
                function(scope, "noSideEffectsToString", no_side_effects_to_string)?,
            ),
            (
                "setEnhanceStackForFatalException",
                function(scope, "setEnhanceStackForFatalException", store_callback)?,
            ),
            (
                "setGetSourceMapErrorSource",
                function(scope, "setGetSourceMapErrorSource", store_callback)?,
            ),
            (
                "setMaybeCacheGeneratedSourceMap",
                function(scope, "setMaybeCacheGeneratedSourceMap", store_callback)?,
            ),
            (
                "setPrepareStackTraceCallback",
                function(scope, "setPrepareStackTraceCallback", store_callback)?,
            ),
            (
                "setSourceMapsEnabled",
                function(scope, "setSourceMapsEnabled", set_source_maps_enabled)?,
            ),
            (
                "triggerUncaughtException",
                function(
                    scope,
                    "triggerUncaughtException",
                    trigger_uncaught_exception,
                )?,
            ),
        ];
        for (name, value) in members {
            set(scope, object, name, value)?;
        }

        Ok(object)
    }
}

/// Source position facts for one exception message.
///
/// `startColumn` only: see the module documentation for why `endColumn` is not
/// exposed.
fn get_error_source_positions(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let error = args.get(0);
    if !error.is_object() {
        return;
    }
    let message = v8::Exception::create_message(scope, error);
    let source_line = message.get_source_line(scope);
    let line_number = message.get_line_number(scope);
    let start_column = message.get_start_column();
    let resource_name = message.get_script_resource_name(scope);

    let info = v8::Object::new(scope);
    if let Some(source_line) = source_line {
        if let Some(key) = v8::String::new(scope, "sourceLine") {
            info.set(scope, key.into(), source_line.into());
        }
    }
    if let Some(resource_name) = resource_name {
        if let Some(key) = v8::String::new(scope, "scriptResourceName") {
            info.set(scope, key.into(), resource_name);
        }
    }
    if let (Some(key), Some(line_number)) = (v8::String::new(scope, "lineNumber"), line_number) {
        let value = v8::Integer::new(scope, line_number as i32);
        info.set(scope, key.into(), value.into());
    }
    if let Some(key) = v8::String::new(scope, "startColumn") {
        let value = v8::Integer::new(scope, start_column as i32);
        info.set(scope, key.into(), value.into());
    }
    rv.set(info.into());
}

/// Converts a value to a string without invoking user code.
///
/// This is used while formatting a fatal error, where running a `toString` on a
/// hostile object could throw or re-enter the error handler.
fn no_side_effects_to_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let value = args.get(0);
    if !(value.is_object() || value.is_function()) {
        if let Some(text) = value.to_string(scope) {
            rv.set(text.into());
        }
        return;
    }
    // Only the constructor name is read. Calling any user-defined coercion here
    // could throw while we are already reporting a fatal error.
    let Some(object) = v8::Local::<v8::Object>::try_from(value).ok() else {
        return;
    };
    let name = object.get_constructor_name();
    let mut text = name.to_rust_string_lossy(scope);
    text.push_str(" { ... }");
    if let Some(text) = v8::String::new(scope, &text) {
        rv.set(text.into());
    }
}

/// Stores a JavaScript callback for a later V8 hook to call.
///
/// Node keeps these on the `Environment`. rustnode keeps them on the isolate so
/// the same callback survives across contexts the way Node's does, and so a
/// shadow-realm error is formatted by its own realm's callback.
fn store_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let callback = args.get(0);
    if !callback.is_function() {
        return;
    }
    let Some(callback) = v8::Local::<v8::Function>::try_from(callback).ok() else {
        return;
    };
    let global = v8::Global::new(scope, callback);
    rn_core::hook_slot::store(scope, rn_core::hook_slot::CALLBACK, global);
}

fn set_source_maps_enabled(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let enabled = args.get(0).is_true();
    rn_core::hook_slot::set_flag(scope, rn_core::hook_slot::SOURCE_MAPS, enabled);
}

/// Reports an uncaught exception the way Node does, giving `process` the first
/// chance to handle it.
fn trigger_uncaught_exception(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    // This is `internalBinding('errors').triggerUncaughtException`, which is the
    // function `internal/process/promises.js` and the ESM entry point call with
    // `fromPromise` set. It shares the one implementation with the event loop so
    // the two cannot disagree about the `_fatalException` ordering.
    let error = args.get(0);
    let from_promise = args.get(1).is_true();
    report_uncaught(scope, error, from_promise);
}

/// Reports an uncaught exception the way Node does, giving `process` the first
/// chance to handle it.
///
/// This is `TriggerUncaughtException`'s order: call `process._fatalException`
/// and, when it returns `true`, stop — the handler took responsibility. Only a
/// `false` answer, or no handler at all, reaches the print-and-exit path.
///
/// The event loop calls this rather than [`write_uncaught`] for a callback that
/// threw, because `process.setUncaughtExceptionCaptureCallback` and
/// `process.on('uncaughtException')` both live behind `_fatalException`. The
/// loop's `TryCatch` has already ended by the time it reports, so the exception
/// is passed in as a value rather than taken from the scope.
///
/// Returns `true` when a handler took responsibility ([`report`] does not run,
/// and the caller must let the script continue), `false` when the exception is
/// fatal. The entry point uses that answer to decide between running its
/// remaining work and terminating, which is the same distinction
/// `TriggerUncaughtException` makes by returning early.
pub fn report_uncaught_exception(
    scope: &mut v8::PinScope<'_, '_>,
    error: v8::Local<v8::Value>,
) -> bool {
    report_uncaught(scope, error, false)
}

/// [`report_uncaught_exception`] for a rejection, which Node frames differently.
///
/// `from_promise` is what `internal/process/promises.js` passes to
/// `triggerUncaughtException`, and it changes both the wrapper printed around
/// the stack and the `type` argument `process._fatalException` receives
/// (`'unhandledRejection'` instead of `'uncaughtException'`). A rejection
/// therefore cannot be reported through the plain entry point without lying
/// about which event fired.
pub fn report_uncaught_rejection(
    scope: &mut v8::PinScope<'_, '_>,
    error: v8::Local<v8::Value>,
) -> bool {
    report_uncaught(scope, error, true)
}

thread_local! {
    /// `is_in_uncaught_exception`, from `src/node_errors.cc:198`.
    ///
    /// Set while an uncaught exception is being reported, so a handler that
    /// throws is detected as re-entrant instead of being reported recursively
    /// until the stack runs out. Thread-local because each isolate reports on its
    /// own thread, which is how Node's `thread_local` static works too.
    static REPORTING: Cell<bool> = const { Cell::new(false) };
}

/// Whether an uncaught exception must abort the process instead of being
/// reported through `_fatalException`.
///
/// Two independent facts, exactly as `src/api/environment.cc:65` combines them:
///
/// * the static `--abort-on-uncaught-exception` option, and
/// * `shouldAbortOnUncaughtToggle[0]`, which
///   `process.setUncaughtExceptionCaptureCallback(fn)` clears and
///   `setUncaughtExceptionCaptureCallback(null)` restores
///   (`lib/internal/process/execution.js:121,133`).
///
/// The toggle is the half that makes a capture callback suppress the abort, and
/// it is why this cannot key on the flag alone:
/// `test-process-exception-capture-should-abort-on-uncaught.js` passes the flag
/// and still expects exit 0. A plain `uncaughtException` listener never touches
/// the toggle, so it does not suppress the abort — which is Node's behaviour and
/// is automatic here because that listener is called from inside
/// `_fatalException`, below this check.
fn aborts_on_uncaught() -> bool {
    rn_core::hook_slot::abort_on_uncaught_exception()
        && rn_core::hook_slot::abort_toggle_allows_abort()
}

/// The text Node prints before `ABORT()`.
///
/// V8's own abort path (`Isolate::CreateMessageOrAbort`,
/// `deps/v8/src/execution/isolate.cc:2739`) prints
/// `"%s\n\nFROM\n"` with the localized message followed by
/// `PrintCurrentStackTrace`, which is where the oracle's
/// `Uncaught Error: x` / `FROM` / frame list comes from. The crate exposes no
/// `PrintCurrentStackTrace`, so the frames come from the error's own `stack`,
/// with its header line dropped to avoid printing `Error: x` twice.
fn fatal_exception_text(scope: &mut v8::PinScope, error: v8::Local<v8::Value>) -> String {
    let (name, message) = match v8::Local::<v8::Object>::try_from(error) {
        Ok(object) if error.is_object() => {
            let read = |key: &str| {
                v8::String::new(scope, key)
                    .and_then(|key| object.get(scope, key.into()))
                    .filter(|value| value.is_string())
                    .map(|value| value.to_rust_string_lossy(scope))
            };
            (
                read("name").unwrap_or_else(|| "Error".to_string()),
                read("message").unwrap_or_default(),
            )
        }
        _ => (
            type_name(error).to_string(),
            error.to_rust_string_lossy(scope),
        ),
    };
    let header = if message.is_empty() {
        format!("Uncaught {name}")
    } else {
        format!("Uncaught {name}: {message}")
    };
    // The frames come from `error.stack`, whose first line repeats the header.
    let frames = v8::Local::<v8::Object>::try_from(error)
        .ok()
        .and_then(|object| {
            let key = v8::String::new(scope, "stack")?;
            let stack = object.get(scope, key.into())?;
            stack.is_string().then(|| stack.to_rust_string_lossy(scope))
        })
        .map(|stack| {
            let mut lines = stack.lines();
            lines.next();
            lines.collect::<Vec<_>>().join("\n")
        })
        .unwrap_or_default();
    if frames.is_empty() {
        format!("{header}\n\nFROM\n")
    } else {
        format!("{header}\n\nFROM\n{frames}\n")
    }
}

fn report_uncaught(
    scope: &mut v8::PinScope<'_, '_>,
    error: v8::Local<v8::Value>,
    from_promise: bool,
) -> bool {
    // `is_in_uncaught_exception` (`src/node_errors.cc:1314`): a handler that
    // throws while an uncaught exception is already being reported cannot be
    // reported in turn, because that is the same recursion one level deeper.
    // Node prints a FATAL ERROR line and aborts.
    //
    // This is a guard and not an optimisation. Without it, a
    // `process.on('uncaughtException')` listener that throws — and a domain
    // error handler that throws, which reaches the same place — drives the
    // recursion below until the stack overflows, and a Rust stack overflow is a
    // `SIGSEGV` with `fatal runtime error: stack overflow` on stderr rather than
    // the abort Node produces.
    if REPORTING.with(Cell::get) {
        let text = format!(
            "FATAL ERROR: Re-entrant uncaught exception detected.\n\
             The exception handler threw an error while processing a\n\
             previous uncaught exception, likely due to an inspector\n\
             protocol issue. Aborting to prevent infinite recursion.\n{}",
            fatal_exception_text(scope, error)
        );
        rn_core::hook_slot::write_stderr(&text);
        std::process::abort();
    }
    // `TriggerUncaughtException` checks this *above* the `_fatalException`
    // call (`src/node_errors.cc:1193-1201`) and `ABORT()`s, so on the abort
    // path no JavaScript handler runs at all: no `uncaughtException` listener,
    // no `'exit'` handlers, and `_fatalException` is never reached. Printing
    // first and aborting after is what the ten
    // `test-domain-no-error-handler-abort-on-uncaught-*` files observe, and
    // routing the flag through the handler first would let a listener suppress
    // an abort Node takes.
    //
    // Node gates this on two separate facts and so does this: the static
    // environment option (never re-read, so `v8.setFlagsFromString` cannot
    // change it — that is the V8-level flag's job) and the byte
    // `setUncaughtExceptionCaptureCallback` clears. The capture callback must
    // suppress the abort; a plain `uncaughtException` listener must not, which
    // is automatic here because the listener lives behind `_fatalException`.
    if aborts_on_uncaught() {
        let text = fatal_exception_text(scope, error);
        rn_core::hook_slot::write_stderr(&text);
        std::process::abort();
    }
    // The RAII `UncaughtExceptionGuard` in `src/node_errors.cc:1327`, scoped to
    // everything below: `ABORT()` above never reaches the restore, which is
    // intentional because the process is terminating either way.
    REPORTING.set(true);
    let result = report_uncaught_inner(scope, error, from_promise);
    REPORTING.set(false);
    result
}

/// The part of [`report_uncaught`] that runs with the re-entrancy guard set.
fn report_uncaught_inner(
    scope: &mut v8::PinScope<'_, '_>,
    error: v8::Local<v8::Value>,
    from_promise: bool,
) -> bool {
    if let Some(handler) = process_fatal_exception_handler(scope) {
        let flag = v8::Boolean::new(scope, from_promise);
        let argv = [error, flag.into()];
        // `_fatalException` runs user JavaScript, so it can throw. `!maybe_handled
        // .ToLocal(&handled)` in `src/node_errors.cc:1404` is the case where it
        // does: Node returns and lets that throw propagate as a fresh uncaught
        // exception rather than treating the original one as handled.
        //
        // That is not a corner case — it is how `domain.js` declines an error it
        // has no handler for. It uninstalls its capture callback, which sets
        // `shouldAbortOnUncaughtToggle[0]` back to `1`, and rethrows
        // (`lib/domain.js:195`: "Throw it to let the C++ side handle the exit
        // properly (respects --abort-on-uncaught)"). Re-entering this function
        // with the *rethrown* value is what makes `--abort-on-uncaught-exception`
        // abort there; leaving it to V8's message handler prints
        // `node:domain:NNNN: Uncaught Error: …` to stdout and exits 1 instead.
        // The `-6`/`-7`/`-8` domain files observe exactly that difference.
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let result = handler.call(scope, v8::undefined(scope).into(), &argv);
        if scope.has_caught() && !scope.has_terminated() {
            let rethrown = scope.exception();
            // The throw is consumed here rather than left pending: the value has
            // been reported below, inside this `TryCatch`.
            scope.reset();
            if let Some(rethrown) = rethrown {
                // `_fatalException` threw while an uncaught exception was being
                // reported. Node's `TryCatchScope::CatchMode::kFatal`
                // (`src/node_errors.cc:747`) reports the *new* error and exits
                // `kExceptionInFatalExceptionHandler` (7). Reporting it through
                // this function again would recurse until the stack ran out,
                // which is what the guard at the top turns into an abort.
                //
                // The abort flag still decides the death where it is set: a
                // domain error handler that throws reaches this with the toggle
                // back at `1` (`lib/domain.js:195`), and
                // `test-domain-with-abort-on-uncaught-exception.js` requires a
                // signal death there.
                if aborts_on_uncaught() {
                    let text = fatal_exception_text(scope, rethrown);
                    rn_core::hook_slot::write_stderr(&text);
                    std::process::abort();
                }
                report(scope, rethrown, from_promise);
                return false;
            }
        }
        // `!handled->IsFalse()` in `src/node_errors.cc`: only a literal `false`
        // means "unhandled". A handler that returns `undefined` — every
        // `process.on('uncaughtException')` listener path — has the runtime's
        // own `true` handed back by `_fatalException`, so this only sees a
        // false answer when nothing handled the exception.
        if result.is_some_and(|value| !value.is_false()) {
            return true;
        }
    }
    report(scope, error, from_promise);
    false
}

/// Reads `process._fatalException`, which is monkey-patchable on purpose.
fn process_fatal_exception_handler<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    let global = scope.get_current_context().global(scope);
    let process_key = v8::String::new(scope, "process")?;
    let process = global.get(scope, process_key.into())?;
    if !process.is_object() {
        return None;
    }
    let process = v8::Local::<v8::Object>::try_from(process).ok()?;
    let key = v8::String::new(scope, "_fatalException")?;
    let handler = process.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(handler).ok()
}

/// Prints the exception and sets the process exit code.
fn report(scope: &mut v8::PinScope, error: v8::Local<v8::Value>, from_promise: bool) {
    let text = format_exception(scope, error, from_promise);
    write_uncaught(scope, &text);
}

/// Writes an already-formatted uncaught exception to standard error and asks
/// the process to exit non-zero.
///
/// The event loop calls this when a timer or immediate callback throws: the
/// exception was raised outside any `try` the user wrote, so Node prints it and
/// exits rather than handing it to a caller that no longer exists. It is
/// separate from [`format_exception`] so the loop can format inside its own
/// `TryCatch` scope and write outside it, where V8 handles are no longer valid.
pub fn write_uncaught(scope: &mut v8::PinScope, text: &str) {
    rn_core::hook_slot::write_stderr(text);
    rn_core::hook_slot::set_flag(scope, rn_core::hook_slot::EXIT_REQUESTED, true);
}

/// Produces the text Node prints for an uncaught exception.
///
/// Node wraps an uncaught rejection's message in `UnhandledPromiseRejection`
/// framing; keeping that exact wording matters because tests and log scrapers
/// match on it.
pub fn format_exception(
    scope: &mut v8::PinScope,
    error: v8::Local<v8::Value>,
    from_promise: bool,
) -> String {
    let detail = if error.is_object() {
        let object = v8::Local::<v8::Object>::try_from(error).ok();
        let stack = object
            .and_then(|object| {
                let key = v8::String::new(scope, "stack")?;
                object.get(scope, key.into())
            })
            .filter(|value| value.is_string())
            .map(|value| value.to_rust_string_lossy(scope));
        stack.unwrap_or_else(|| error.to_rust_string_lossy(scope))
    } else {
        let text = error.to_rust_string_lossy(scope);
        let name = type_name(error);
        format!("Uncaught {name}: {text}")
    };

    if from_promise {
        format!("\nnode:internal/process/promises:XXXX\n{detail}\n")
    } else {
        format!("\n{detail}\n")
    }
}

fn type_name(value: v8::Local<v8::Value>) -> &'static str {
    if value.is_number() {
        "number"
    } else if value.is_boolean() {
        "boolean"
    } else if value.is_string() {
        "string"
    } else if value.is_null() {
        "null"
    } else if value.is_undefined() {
        "undefined"
    } else {
        "object"
    }
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a member name")?;
    object.set(scope, key.into(), value);
    Ok(())
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

/// Registers the `errors` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Errors);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_exit_code_from_node_exit_code_h_is_present() {
        let names: Vec<&str> = EXIT_CODES.iter().map(|(name, _)| *name).collect();
        assert_eq!(names.len(), 14);
        assert!(names.contains(&"kGenericUserError"));
        assert!(names.contains(&"kInvalidCommandLineArgument"));
        assert!(names.contains(&"kProcessTimeout"));
    }

    #[test]
    fn exit_code_values_match_node() {
        let value = |name: &str| {
            EXIT_CODES
                .iter()
                .find(|(candidate, _)| *candidate == name)
                .map(|(_, code)| *code)
                .expect(name)
        };
        assert_eq!(value("kNoFailure"), 0);
        assert_eq!(value("kGenericUserError"), 1);
        assert_eq!(value("kInvalidCommandLineArgument"), 9);
        assert_eq!(value("kProcessTimeout"), 124);
        assert_eq!(value("kAbort"), 134);
    }

    #[test]
    fn members_cover_the_recorded_contract() {
        assert_eq!(MEMBERS.len(), 9);
        for member in [
            "triggerUncaughtException",
            "exitCodes",
            "getErrorSourcePositions",
        ] {
            assert!(MEMBERS.contains(&member), "{member} missing");
        }
    }
}
