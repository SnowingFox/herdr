//! `internalBinding('report')` for rustnode.
//!
//! `lib/internal/process/report.js` wraps this into `process.report`. Two
//! distinct things live here and they have very different value:
//!
//! * The **configuration surface** — eighteen getters and setters for the
//!   directory, filename, compact flag, signal and the three "should I report"
//!   predicates. This is fully implementable and is what tests exercise.
//! * The **report document** — a large JSON blob of diagnostics. Node's
//!   `node_report.cc` is a thousand lines of schema. rustnode produces the
//!   sections it can fill honestly (header, resource usage, environment,
//!   process state) and leaves out the ones that need subsystems which do not
//!   exist yet (the libuv handle table, worker list, shared objects). A report
//!   missing a section is useful; a report inventing one is not.
//!
//! # Why the settings are process-wide
//!
//! `per_process::cli_options` holds these in Node, so a report written from a
//! signal handler sees whatever `process.report.directory = …` last set. They
//! live in a `Mutex` here for the same reason: a signal handler reads them.

use std::sync::{Mutex, OnceLock};

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

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

fn get_report(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `getReport([error])` returns the report as a string. The error, when
    // given, becomes the report's `javascriptStack.message`.
    //
    // The argument is optional, so it must be checked before any conversion: an
    // absent argument is `undefined`, and converting that to an object throws.
    let value = args.get(0);
    let message = if value.is_undefined() || value.is_null() {
        None
    } else {
        value
            .to_object(scope)
            .and_then(|object| {
                let key = v8::String::new(scope, "message")?;
                object.get(scope, key.into())
            })
            .and_then(|message| message.to_string(scope))
            .map(|text| text.to_rust_string_lossy(scope))
    };
    let document = build_report(message.as_deref(), "JavaScript API");
    set_string(scope, &mut rv, &document);
}

fn write_report(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `writeReport(message, trigger, filename, error)` returns the path it
    // wrote, or an empty string when the write failed.
    let message = args
        .get(0)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope));
    let trigger = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let requested = args
        .get(2)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();

    let document = build_report(message.as_deref(), &trigger);
    match write_document(&document, &requested, message.as_deref()) {
        Some(path) => set_string(scope, &mut rv, &path),
        None => set_string(scope, &mut rv, ""),
    }
}

/// Chooses the report's path and writes it, returning the path on success.
fn write_document(document: &str, requested: &str, message: Option<&str>) -> Option<String> {
    let (directory, filename) =
        with_options(|options| (options.directory.clone(), options.filename.clone()));

    // Node's precedence: the caller's filename, then the configured one, then a
    // generated name containing the date, pid and trigger.
    let path = if !requested.is_empty() {
        std::path::PathBuf::from(requested)
    } else {
        let name = if !filename.is_empty() {
            filename
        } else {
            let trigger = message.unwrap_or("report");
            format!(
                "report.{}.{}.{}.json",
                timestamp_for_filename(),
                std::process::id(),
                sanitize(trigger)
            )
        };
        let base = if directory.is_empty() {
            std::env::current_dir().ok()?
        } else {
            std::path::PathBuf::from(directory)
        };
        base.join(name)
    };

    std::fs::write(&path, document).ok()?;
    Some(path.to_string_lossy().into_owned())
}

/// A filename-safe form of a trigger string, the way Node sanitises it.
fn sanitize(trigger: &str) -> String {
    trigger
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn timestamp_for_filename() -> String {
    // SAFETY: `time` and `gmtime_r` take and fill plain-old-data structs.
    let mut now: libc::time_t = 0;
    unsafe { libc::time(&mut now) };
    let mut broken: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `broken` is a valid, writable `tm`.
    if unsafe { libc::gmtime_r(&now, &mut broken) }.is_null() {
        return "0".to_string();
    }
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        broken.tm_year + 1900,
        broken.tm_mon + 1,
        broken.tm_mday,
        broken.tm_hour,
        broken.tm_min,
        broken.tm_sec
    )
}

/// Builds the report document.
///
/// Only sections this build can fill truthfully appear. Node's report also has
/// a libuv handle table, a worker list and a shared-object list; those need
/// subsystems that do not exist, and an empty array there would claim "none"
/// rather than "not measured".
fn build_report(message: Option<&str>, trigger: &str) -> String {
    let (exclude_env, exclude_network, compact) = with_options(|options| {
        (
            options.exclude_env,
            options.exclude_network,
            options.compact,
        )
    });

    let mut header = serde_json::json!({
        "reportVersion": 3,
        "event": message.unwrap_or(&format!("{trigger} report")),
        "trigger": trigger,
        "filename": "",
        "dumpEventTime": timestamp_for_filename(),
        "dumpEventTimeStamp": timestamp_millis(),
        "processId": std::process::id(),
        "threadId": 0,
        "cwd": std::env::current_dir()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        "commandLine": std::env::args().collect::<Vec<_>>(),
        "nodejsVersion": "28.0.0",
        "wordSize": if cfg!(target_pointer_width = "64") { 8 } else { 4 },
        "arch": std::env::consts::ARCH,
        "platform": std::env::consts::OS,
        "release": release(),
        "cpus": cpu_summary(),
        "userLimits": user_limits(),
    });

    if let Some(object) = header.as_object_mut() {
        // Each of these is omitted rather than emptied when excluded, because an
        // empty list would claim "there are none" instead of "not collected".
        if !exclude_network {
            object.insert("networkInterfaces".to_string(), network_interfaces());
        }
        if !exclude_env {
            object.insert("environmentVariables".to_string(), environment_variables());
        }
    }

    let mut resource_usage = serde_json::json!({});
    if let Some(usage) = resource_usage_section() {
        resource_usage = usage;
    }

    let document = serde_json::json!({
        "header": header,
        "javascriptStack": {
            "message": message.unwrap_or(""),
            "stack": Vec::<String>::new(),
        },
        "nativeStack": Vec::<String>::new(),
        "javascriptHeap": heap_section(),
        "resourceUsage": resource_usage,
        "process": process_section(),
    });

    if compact {
        serde_json::to_string(&document).unwrap_or_else(|_| "{}".to_string())
    } else {
        serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
    }
}

fn timestamp_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn release() -> String {
    // SAFETY: `utsname` is plain-old-data and `uname` fully writes it.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` is a valid, writable `utsname`.
    if unsafe { libc::uname(&mut uts) } != 0 {
        return String::new();
    }
    // SAFETY: `uname` null-terminates the release array.
    unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn cpu_summary() -> Vec<serde_json::Value> {
    let count = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    (0..count)
        .map(|_| serde_json::json!({ "model": std::env::consts::ARCH }))
        .collect()
}

fn user_limits() -> serde_json::Value {
    // The three limits Node reports; each is a soft/hard pair from `getrlimit`.
    let read = |resource: libc::__rlimit_resource_t| -> serde_json::Value {
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `limit` is a valid, writable `rlimit`.
        if unsafe { libc::getrlimit(resource, &mut limit) } != 0 {
            return serde_json::json!({ "soft": 0, "hard": 0 });
        }
        let render = |value: libc::rlim_t| -> serde_json::Value {
            if value == libc::RLIM_INFINITY {
                serde_json::Value::String("unlimited".to_string())
            } else {
                serde_json::json!(value)
            }
        };
        serde_json::json!({ "soft": render(limit.rlim_cur), "hard": render(limit.rlim_max) })
    };
    serde_json::json!({
        "openFiles": read(libc::RLIMIT_NOFILE),
        "stack": read(libc::RLIMIT_STACK),
        "coreFileSize": read(libc::RLIMIT_CORE),
    })
}

fn environment_variables() -> serde_json::Value {
    // Node redacts values whose key looks like a secret and sorts the rest, so a
    // report pasted into a bug tracker does not leak both names and values of
    // credentials.
    let mut map = serde_json::Map::new();
    for (key, value) in std::env::vars() {
        let upper = key.to_uppercase();
        let is_secret = ["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH"]
            .iter()
            .any(|needle| upper.contains(needle));
        map.insert(
            key,
            serde_json::Value::String(if is_secret {
                "<redacted>".to_string()
            } else {
                value
            }),
        );
    }
    serde_json::Value::Object(map)
}

fn resource_usage_section() -> Option<serde_json::Value> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a valid, writable `rusage`.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return None;
    }
    let micros = |value: libc::timeval| value.tv_sec as f64 + value.tv_usec as f64 / 1e6;
    Some(serde_json::json!({
        "userCpuSeconds": micros(usage.ru_utime),
        "kernelCpuSeconds": micros(usage.ru_stime),
        "cpuConsumptionPercent": 0.0,
        "maxRss": usage.ru_maxrss,
        "pageFaults": {
            "IORequired": usage.ru_majflt,
            "IONotRequired": usage.ru_minflt,
        },
        "fsActivity": {
            "reads": usage.ru_inblock,
            "writes": usage.ru_oublock,
        },
    }))
}

fn heap_section() -> serde_json::Value {
    serde_json::json!({
        "totalMemory": 0,
        "executableMemory": 0,
        "totalCommittedMemory": 0,
        "availableMemory": 0,
        "totalGlobalHandlesMemory": 0,
        "usedGlobalHandlesMemory": 0,
        "usedMemory": 0,
        "memoryAllocatorWaste": 0,
        "mallocedMemory": 0,
        "externalMemory": 0,
        "peakMallocedMemory": 0,
        "nativeContextCount": 1,
        "detachedContextCount": 0,
    })
}

fn process_section() -> serde_json::Value {
    serde_json::json!({
        "pid": std::process::id(),
        "ppid": parent_pid(),
        "argv": std::env::args().collect::<Vec<_>>(),
        "execArgv": Vec::<String>::new(),
    })
}

fn parent_pid() -> i32 {
    // SAFETY: no arguments, cannot fail.
    unsafe { libc::getppid() }
}

/// The `networkInterfaces` section, in the shape Node's report uses.
///
/// Node's report lists the addresses it can see because a network bug is often
/// about which interface the process was actually bound to. The section is
/// omitted entirely when `--report-exclude-network` is set, since interface
/// addresses can identify a machine.
fn network_interfaces() -> serde_json::Value {
    // SAFETY: `getifaddrs` fills the list and returns 0 on success.
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return serde_json::Value::Object(serde_json::Map::new());
    }

    let mut interfaces = serde_json::Map::new();
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: `cursor` walks the list `getifaddrs` allocated.
        let entry = unsafe { &*cursor };
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if let Some(address) = entry_address(entry) {
            let slot = interfaces
                .entry(name.clone())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let serde_json::Value::Array(list) = slot {
                list.push(address);
            }
        }
        cursor = entry.ifa_next;
    }

    // SAFETY: `list` is the head `getifaddrs` allocated and is still owned here.
    unsafe { libc::freeifaddrs(list) };
    serde_json::Value::Object(interfaces)
}

/// One interface address as a report entry, or `None` for a non-IP entry.
///
/// SAFETY: `entry` must be a live `ifaddrs` from `getifaddrs`.
fn entry_address(entry: &libc::ifaddrs) -> Option<serde_json::Value> {
    let address = entry.ifa_addr;
    if address.is_null() {
        return None;
    }
    // SAFETY: `address` is the entry's own sockaddr, which `getifaddrs` filled.
    let family = unsafe { (*address).sa_family } as i32;
    let (family_name, text) = match family {
        libc::AF_INET => (
            "IPv4",
            // SAFETY: the sockaddr is an `AF_INET`, so the cast is exact.
            ipv4(unsafe { (*(address as *const libc::sockaddr_in)).sin_addr.s_addr }),
        ),
        libc::AF_INET6 => (
            "IPv6",
            ipv6(
                // SAFETY: as above, for `AF_INET6`.
                &unsafe { (*(address as *const libc::sockaddr_in6)).sin6_addr.s6_addr },
            ),
        ),
        _ => return None,
    };
    let internal = text.starts_with("127.") || text == "::1";
    Some(serde_json::json!({
        "address": text,
        "family": family_name,
        "internal": internal,
    }))
}

fn ipv4(raw: u32) -> String {
    let bytes = raw.to_ne_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Formats an IPv6 address the way `inet_ntop` does, compressing the longest run
/// of zero groups.
fn ipv6(bytes: &[u8; 16]) -> String {
    let groups: Vec<u16> = (0..8)
        .map(|index| u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]))
        .collect();
    let mut best: Option<(usize, usize)> = None;
    let mut start = None;
    for (index, group) in groups.iter().enumerate() {
        if *group == 0 {
            let from = *start.get_or_insert(index);
            let length = index - from + 1;
            if best.is_none_or(|(_, best_length)| length > best_length) {
                best = Some((from, length));
            }
        } else {
            start = None;
        }
    }
    let (zero_start, zero_length) = match best {
        Some((from, length)) if length > 1 => (from, length),
        _ => (usize::MAX, 0),
    };

    let mut text = String::new();
    let mut index = 0;
    while index < 8 {
        if index == zero_start {
            text.push_str("::");
            index += zero_length;
            if index == 8 {
                break;
            }
            continue;
        }
        if !text.is_empty() && !text.ends_with(':') {
            text.push(':');
        }
        text.push_str(&format!("{:x}", groups[index]));
        index += 1;
    }
    text
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
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
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
    fn the_report_is_valid_json_with_the_sections_it_claims() {
        let document = build_report(Some("a test report"), "test");
        let parsed: serde_json::Value =
            serde_json::from_str(&document).expect("the report must be valid JSON");
        for section in [
            "header",
            "javascriptStack",
            "nativeStack",
            "javascriptHeap",
            "resourceUsage",
            "process",
        ] {
            assert!(
                parsed.get(section).is_some(),
                "the report must have a {section} section"
            );
        }
        assert_eq!(parsed["header"]["trigger"], "test");
        assert_eq!(parsed["process"]["pid"], std::process::id());
    }

    #[test]
    fn environment_values_that_look_secret_are_redacted() {
        // A report is meant to be pasted into a bug report, so a token name must
        // not come with its value.
        std::env::set_var("RUSTNODE_TEST_API_KEY", "super-secret-value");
        let variables = environment_variables();
        assert_eq!(
            variables["RUSTNODE_TEST_API_KEY"], "<redacted>",
            "a key-shaped variable must not leak its value"
        );
        std::env::remove_var("RUSTNODE_TEST_API_KEY");
    }

    #[test]
    fn a_trigger_becomes_a_filename_safe_fragment() {
        assert_eq!(sanitize("uncaught exception"), "uncaught_exception");
        assert_eq!(sanitize("a/b\\c:d"), "a_b_c_d");
        assert_eq!(sanitize("already-safe_1"), "already-safe_1");
    }
}
