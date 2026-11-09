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
    let error = args.get(0);
    let from_promise = args.get(1).is_true();

    if let Some(handler) = process_fatal_exception_handler(scope) {
        let from_promise = v8::Boolean::new(scope, from_promise);
        let argv = [error, from_promise.into()];
        let result = handler.call(scope, v8::undefined(scope).into(), &argv);
        if result.is_some_and(|value| value.is_true()) {
            return;
        }
    }

    report(scope, error, from_promise);
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
    rn_core::hook_slot::write_stderr(&text);
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
    registry.register(rn_core::Namespace::from_module(&Errors));
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
