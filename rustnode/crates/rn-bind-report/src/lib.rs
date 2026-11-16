//! `internalBinding('report')` for rustnode.
//!
//! `lib/internal/process/report.js` wraps this into `process.report`. Two
//! distinct things live here:
//!
//! * The **configuration surface** — eighteen getters and setters for the
//!   directory, filename, compact flag, signal and the three "should I report"
//!   predicates.
//! * The **report document** — the diagnostics blob defined by
//!   `src/node_report.cc`. [`document`] reproduces its schema: the same
//!   `reportVersion`, the same eleven sections in the same order, and the same
//!   header fields. A report a consumer cannot parse with the schema its version
//!   claims is worse than no report.
//!
//! # Why the settings are process-wide
//!
//! `per_process::cli_options` holds these in Node, so a report written from a
//! signal handler sees whatever `process.report.directory = …` last set. They
//! live in a `Mutex` here for the same reason: a signal handler reads them.

pub mod document;
pub mod json;
pub mod versions;

use std::cell::RefCell;
use std::sync::{Mutex, OnceLock};

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::document::{ErrorDetails, HeapSpace, HeapStats, ReportInput, ThreadIdentity};

/// Members exposed on the namespace object, matching `contracts/report.json`.
pub const MEMBERS: &[&str] = &[
    "getCompact",
    "getDirectory",
    "getExcludeEnv",
    "getExcludeNetwork",
    "getFilename",
    "getReport",
    "getSignal",
    "setCompact",
    "setDirectory",
    "setExcludeEnv",
    "setExcludeNetwork",
    "setFilename",
    "setReportOnFatalError",
    "setReportOnSignal",
    "setReportOnUncaughtException",
    "setSignal",
    "shouldReportOnFatalError",
    "shouldReportOnSignal",
    "shouldReportOnUncaughtException",
    "writeReport",
];

/// The defaults from `EnvironmentOptions` and `PerProcessOptions` in
/// `src/node_options.h`.
#[derive(Debug, Clone)]
pub struct ReportOptions {
    pub compact: bool,
    pub exclude_env: bool,
    pub exclude_network: bool,
    pub directory: String,
    pub filename: String,
    pub signal: String,
    pub on_fatal_error: bool,
    pub on_signal: bool,
    pub on_uncaught_exception: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            compact: false,
            exclude_env: false,
            exclude_network: false,
            directory: String::new(),
            filename: String::new(),
            // `EnvironmentOptions::report_signal` defaults to SIGUSR2.
            signal: "SIGUSR2".to_string(),
            on_fatal_error: false,
            on_signal: true,
            on_uncaught_exception: true,
        }
    }
}

fn options() -> &'static Mutex<ReportOptions> {
    static OPTIONS: OnceLock<Mutex<ReportOptions>> = OnceLock::new();
    OPTIONS.get_or_init(|| Mutex::new(ReportOptions::default()))
}

thread_local! {
    /// The isolate the report is being built in, recorded at install time.
    ///
    /// `PrintGCStatistics` needs `Isolate::GetHeapStatistics`, and the isolate is
    /// only reachable as a raw pointer because a `v8::Isolate` cannot be rooted.
    /// The pointer is valid while the isolate is alive, and a report is always
    /// built from inside a callback on that isolate's thread.
    static ISOLATE: RefCell<Option<v8::UnsafeRawIsolatePtr>> = const { RefCell::new(None) };

    /// `DiagnosticFilename`'s `seq`, which distinguishes two reports written in
    /// the same second.
    static SEQUENCE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub struct Report;

impl BindingModule for Report {
    fn namespace(&self) -> &'static str {
        "report"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let isolate: &v8::Isolate = scope.as_ref();
        // SAFETY: the isolate outlives every scope taken from it, so keeping a
        // pointer to it is sound for the process' life.
        let pointer = unsafe { isolate.as_raw_isolate_ptr() };
        ISOLATE.with(|slot| *slot.borrow_mut() = Some(pointer));

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 20] = [
            ("getCompact", function(scope, "getCompact", get_compact)?),
            ("setCompact", function(scope, "setCompact", set_compact)?),
            (
                "getDirectory",
                function(scope, "getDirectory", get_directory)?,
            ),
            (
                "setDirectory",
                function(scope, "setDirectory", set_directory)?,
            ),
            ("getFilename", function(scope, "getFilename", get_filename)?),
            ("setFilename", function(scope, "setFilename", set_filename)?),
            ("getSignal", function(scope, "getSignal", get_signal)?),
            ("setSignal", function(scope, "setSignal", set_signal)?),
            (
                "getExcludeEnv",
                function(scope, "getExcludeEnv", get_exclude_env)?,
            ),
            (
                "setExcludeEnv",
                function(scope, "setExcludeEnv", set_exclude_env)?,
            ),
            (
                "getExcludeNetwork",
                function(scope, "getExcludeNetwork", get_exclude_network)?,
            ),
            (
                "setExcludeNetwork",
                function(scope, "setExcludeNetwork", set_exclude_network)?,
            ),
            (
                "shouldReportOnFatalError",
                function(
                    scope,
                    "shouldReportOnFatalError",
                    should_report_on_fatal_error,
                )?,
            ),
            (
                "setReportOnFatalError",
                function(scope, "setReportOnFatalError", set_report_on_fatal_error)?,
            ),
            (
                "shouldReportOnSignal",
                function(scope, "shouldReportOnSignal", should_report_on_signal)?,
            ),
            (
                "setReportOnSignal",
                function(scope, "setReportOnSignal", set_report_on_signal)?,
            ),
            (
                "shouldReportOnUncaughtException",
                function(
                    scope,
                    "shouldReportOnUncaughtException",
                    should_report_on_uncaught_exception,
                )?,
            ),
            (
                "setReportOnUncaughtException",
                function(
                    scope,
                    "setReportOnUncaughtException",
                    set_report_on_uncaught_exception,
                )?,
            ),
            ("getReport", function(scope, "getReport", get_report)?),
            ("writeReport", function(scope, "writeReport", write_report)?),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Report);
}

/// Reads the options, recovering from a poisoned mutex rather than panicking.
///
/// A report can be requested after another thread panicked, and refusing to
/// produce one then is the opposite of useful.
fn with_options<T>(body: impl FnOnce(&mut ReportOptions) -> T) -> T {
    let mut guard = match options().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    body(&mut guard)
}

fn get_compact(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let compact = with_options(|options| options.compact);
    rv.set(v8::Boolean::new(scope, compact).into());
}

fn set_compact(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = args.get(0).boolean_value(scope);
    with_options(|options| options.compact = value);
}

fn get_exclude_env(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_options(|options| options.exclude_env);
    rv.set(v8::Boolean::new(scope, value).into());
}

fn set_exclude_env(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = args.get(0).boolean_value(scope);
    with_options(|options| options.exclude_env = value);
}

fn get_exclude_network(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_options(|options| options.exclude_network);
    rv.set(v8::Boolean::new(scope, value).into());
}

fn set_exclude_network(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = args.get(0).boolean_value(scope);
    with_options(|options| options.exclude_network = value);
}

fn get_directory(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let directory = with_options(|options| options.directory.clone());
    set_string(scope, &mut rv, &directory);
}

fn set_directory(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `process.report.directory = null` clears it, which is how the JS wrapper
    // spells "use the default". Anything else must be a string.
    let value = match v8::Local::<v8::String>::try_from(args.get(0)) {
        Ok(text) => text.to_rust_string_lossy(scope),
        Err(_) => String::new(),
    };
    with_options(|options| options.directory = value);
}

fn get_filename(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let filename = with_options(|options| options.filename.clone());
    set_string(scope, &mut rv, &filename);
}

fn set_filename(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = match v8::Local::<v8::String>::try_from(args.get(0)) {
        Ok(text) => text.to_rust_string_lossy(scope),
        Err(_) => String::new(),
    };
    with_options(|options| options.filename = value);
}

fn get_signal(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let signal = with_options(|options| options.signal.clone());
    set_string(scope, &mut rv, &signal);
}

fn set_signal(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = match v8::Local::<v8::String>::try_from(args.get(0)) {
        Ok(text) => text.to_rust_string_lossy(scope),
        Err(_) => String::new(),
    };
    with_options(|options| options.signal = value);
}

fn should_report_on_fatal_error(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_options(|options| options.on_fatal_error);
    rv.set(v8::Boolean::new(scope, value).into());
}

fn set_report_on_fatal_error(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = args.get(0).boolean_value(scope);
    with_options(|options| options.on_fatal_error = value);
}

fn should_report_on_signal(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_options(|options| options.on_signal);
    rv.set(v8::Boolean::new(scope, value).into());
}

fn set_report_on_signal(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = args.get(0).boolean_value(scope);
    with_options(|options| options.on_signal = value);
}

fn should_report_on_uncaught_exception(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_options(|options| options.on_uncaught_exception);
    rv.set(v8::Boolean::new(scope, value).into());
}

fn set_report_on_uncaught_exception(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = args.get(0).boolean_value(scope);
    with_options(|options| options.on_uncaught_exception = value);
}

/// `getReport(error)`: the document as a string, built but not written.
fn get_report(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `TriggerNodeReport` passes `"JavaScript API"` as the event and
    // `__func__` — which is `GetReport` — as the trigger.
    let document = build(scope, args.get(0), "JavaScript API", "GetReport", None);
    set_string(scope, &mut rv, &document);
}

/// `writeReport(message, trigger, filename, error)`.
fn write_report(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let message = args
        .get(0)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let trigger = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    // `if (info[2]->IsString()) filename = ...`: a missing filename arrives as
    // `undefined` from `lib/internal/process/report.js`, and coercing that would
    // produce the literal name "undefined" and write a file by that name.
    let requested = v8::Local::<v8::String>::try_from(args.get(2))
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();

    // Node's filename precedence, in `TriggerNodeReport`: the caller's name, then
    // the configured one, then a generated diagnostic name. A name of `"stdout"`,
    // `"stderr"` or `"<stdout>"` selects that stream and writes no file.
    let (configured_directory, configured_filename) =
        with_options(|options| (options.directory.clone(), options.filename.clone()));
    let filename = if !requested.is_empty() {
        requested
    } else if !configured_filename.is_empty() {
        configured_filename
    } else {
        diagnostic_filename(0, "report", "json")
    };

    let written = match filename.as_str() {
        "stdout" => {
            let document = build(scope, args.get(3), &message, &trigger, Some("stdout"));
            print!("{document}");
            Some(filename)
        }
        "stderr" => {
            let document = build(scope, args.get(3), &message, &trigger, Some("stderr"));
            eprint!("{document}");
            Some(filename)
        }
        _ => {
            let path = if configured_directory.is_empty() {
                std::path::PathBuf::from(&filename)
            } else {
                std::path::PathBuf::from(&configured_directory).join(&filename)
            };
            let document = build(scope, args.get(3), &message, &trigger, Some(&filename));
            // The banner goes to stderr before the file is opened, which is the
            // order a wrapper that greps for it expects.
            eprintln!("\nWriting Node.js report to file: {filename}");
            match std::fs::write(&path, document.as_bytes()) {
                Ok(()) => {
                    // Node suppresses the completion line only for `stderr`,
                    // where mixing prose into the document would corrupt it.
                    eprintln!("Node.js report completed");
                    Some(filename)
                }
                Err(error) => {
                    eprintln!("Failed to open Node.js report file: {filename} ({error})");
                    None
                }
            }
        }
    };

    match written {
        Some(name) => set_string(scope, &mut rv, &name),
        None => set_string(scope, &mut rv, ""),
    }
}

/// Builds the document for one call.
fn build(
    scope: &mut v8::PinScope<'_, '_>,
    error: v8::Local<v8::Value>,
    event: &str,
    trigger: &str,
    filename: Option<&str>,
) -> String {
    let (compact, exclude_env, exclude_network) = with_options(|options| {
        (
            options.compact,
            options.exclude_env,
            options.exclude_network,
        )
    });
    let mut input = ReportInput::new(event, trigger);
    input.compact = compact;
    input.exclude_env = exclude_env;
    input.exclude_network = exclude_network;
    input.filename = filename;
    input.error = describe_error(scope, error);
    input.component_versions = versions::component_versions();
    input.release = versions::release();
    let heap = heap_stats(scope);
    let thread = ThreadIdentity { thread_id: 0 };
    document::render(&input, heap.as_ref(), &thread)
}

/// `PrintJavaScriptErrorStack`'s inputs, taken from the live error object.
///
/// `ErrorToString` prefers `error.stack` when it is a string, which is what the
/// first line and the remaining lines are split from; the properties are the
/// error's own enumerable keys other than `stack` and `message`, stringified.
fn describe_error(
    scope: &mut v8::PinScope<'_, '_>,
    error: v8::Local<v8::Value>,
) -> Option<ErrorDetails> {
    if error.is_undefined() || error.is_null() {
        return None;
    }
    let object = error.to_object(scope)?;
    let stack_key = v8::String::new(scope, "stack")?;
    let stack = object.get(scope, stack_key.into());
    let rendered = stack
        .and_then(|value| value.to_string(scope))
        .map(|text| text.to_rust_string_lossy(scope))?;

    let mut lines = rendered.split('\n');
    let message = lines.next().unwrap_or_default().to_string();
    let stack_lines: Vec<String> = lines
        .map(|line| line.trim_start().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    let mut properties = Vec::new();
    if let Some(keys) = object.get_own_property_names(scope, Default::default()) {
        for index in 0..keys.length() {
            let Some(key) = keys.get_index(scope, index) else {
                continue;
            };
            let Some(key) = key.to_string(scope) else {
                continue;
            };
            let key = key.to_rust_string_lossy(scope);
            if key == "stack" || key == "message" {
                continue;
            }
            let Some(name) = v8::String::new(scope, &key) else {
                continue;
            };
            let Some(value) = object.get(scope, name.into()) else {
                continue;
            };
            let Some(text) = value.to_string(scope) else {
                continue;
            };
            properties.push((key, text.to_rust_string_lossy(scope)));
        }
    }

    Some(ErrorDetails {
        message,
        stack: stack_lines,
        properties,
    })
}

/// `PrintGCStatistics`'s inputs from the live isolate.
fn heap_stats(scope: &mut v8::PinScope<'_, '_>) -> Option<HeapStats> {
    let pointer = ISOLATE.with(|slot| *slot.borrow())?;
    if pointer.is_null() {
        return None;
    }
    let mut raw = pointer;
    // SAFETY: the pointer was recorded from a live isolate at install time and
    // this callback runs inside that isolate's own scope, so it is still alive
    // and not otherwise borrowed on this thread.
    let isolate = unsafe { v8::Isolate::ref_from_raw_isolate_ptr_mut(&mut raw) };
    let statistics = isolate.get_heap_statistics();
    let spaces = isolate.number_of_heap_spaces();
    let mut heap_spaces = Vec::with_capacity(spaces);
    for index in 0..spaces {
        let Some(space) = isolate.get_heap_space_statistics(index) else {
            continue;
        };
        heap_spaces.push(HeapSpace {
            name: space.space_name().to_string_lossy().into_owned(),
            size: space.space_size(),
            physical_size: space.physical_space_size(),
            used_size: space.space_used_size(),
            available_size: space.space_available_size(),
        });
    }
    let _ = scope;
    Some(HeapStats {
        total_heap_size: statistics.total_heap_size(),
        total_heap_size_executable: statistics.total_heap_size_executable(),
        total_physical_size: statistics.total_physical_size(),
        total_available_size: statistics.total_available_size(),
        total_global_handles_size: statistics.total_global_handles_size(),
        used_global_handles_size: statistics.used_global_handles_size(),
        used_heap_size: statistics.used_heap_size(),
        heap_size_limit: statistics.heap_size_limit(),
        malloced_memory: statistics.malloced_memory(),
        external_memory: statistics.external_memory(),
        peak_malloced_memory: statistics.peak_malloced_memory(),
        number_of_native_contexts: statistics.number_of_native_contexts(),
        number_of_detached_contexts: statistics.number_of_detached_contexts(),
        does_zap_garbage: statistics.does_zap_garbage(),
        spaces: heap_spaces,
    })
}

/// `DiagnosticFilename::MakeFilename`.
///
/// `report.YYYYMMDD.HHMMSS.pid.threadId.NNN.ext`, with `threadId` and `NNN` from
/// the counter Node increments per report.
fn diagnostic_filename(thread_id: u32, prefix: &str, extension: &str) -> String {
    let sequence = SEQUENCE.with(|cell| {
        let next = cell.get() + 1;
        cell.set(next);
        next
    });
    // SAFETY: `time` takes a writable `time_t`.
    let mut now: libc::time_t = 0;
    unsafe { libc::time(&mut now) };
    // SAFETY: `tm` is plain-old-data and `localtime_r` fills it.
    let mut broken: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `broken` is a valid writable `tm`.
    if unsafe { libc::localtime_r(&now, &mut broken) }.is_null() {
        return format!(
            "{prefix}.{}.{thread_id}.{sequence:03}.{extension}",
            std::process::id()
        );
    }
    format!(
        "{prefix}.{:04}{:02}{:02}.{:02}{:02}{:02}.{}.{thread_id}.{sequence:03}.{extension}",
        broken.tm_year + 1900,
        broken.tm_mon + 1,
        broken.tm_mday,
        broken.tm_hour,
        broken.tm_min,
        broken.tm_sec,
        std::process::id()
    )
}

fn set_string(scope: &mut v8::PinScope, rv: &mut v8::ReturnValue, value: &str) {
    if let Some(text) = v8::String::new(scope, value) {
        rv.set(text.into());
    }
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    Ok(rn_core::named_method(scope, name, callback)?.into())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_match_node_options_h() {
        let defaults = ReportOptions::default();
        assert!(!defaults.compact);
        assert!(!defaults.exclude_env);
        assert!(!defaults.exclude_network);
        assert!(!defaults.on_fatal_error);
        // A signal report is on by default; a fatal-error one is not.
        assert_eq!(defaults.signal, "SIGUSR2");
        assert!(defaults.on_signal);
        assert!(defaults.on_uncaught_exception);
    }

    #[test]
    fn a_diagnostic_filename_follows_nodes_shape() {
        // `report.YYYYMMDD.HHMMSS.pid.threadId.NNN.json`, with the sequence
        // counting up so two reports in the same second do not overwrite.
        let first = diagnostic_filename(0, "report", "json");
        let second = diagnostic_filename(0, "report", "json");
        assert!(first.ends_with(".json"));
        assert_ne!(first, second, "the sequence must advance");
        let fields: Vec<&str> = first.split('.').collect();
        assert_eq!(fields.len(), 7, "{first}");
        assert_eq!(fields[0], "report");
        assert_eq!(fields[1].len(), 8, "a YYYYMMDD date");
        assert_eq!(fields[2].len(), 6, "a HHMMSS time");
        assert_eq!(fields[3], std::process::id().to_string());
        assert_eq!(fields[4], "0", "the main thread's id");
        assert_eq!(fields[5].len(), 3, "a zero-padded sequence");
        assert_eq!(fields[6], "json");
    }

    #[test]
    fn a_secret_shaped_name_is_redacted_and_a_plain_one_is_not() {
        assert_eq!(redacted_for_test("MY_API_KEY", "v"), "<redacted>");
        assert_eq!(redacted_for_test("HOME", "/home/u"), "/home/u");
    }

    /// `document::render` redacts through the same predicate; this keeps the
    /// rule visible from the crate's top-level tests.
    fn redacted_for_test(key: &str, value: &str) -> String {
        if document::redacts(key) {
            "<redacted>".to_string()
        } else {
            value.to_string()
        }
    }
}
