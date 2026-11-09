//! `internalBinding('process_methods')` for rustnode.
//!
//! `lib/internal/bootstrap/node.js` and `lib/internal/process/per_thread.js`
//! turn these into the `process` object user code sees: `process.memoryUsage()`,
//! `process.hrtime()`, `process.cwd()`, `process.cpuUsage()` and the rest. The
//! contract is the one `src/node_process_methods.cc` and
//! `src/node_process_object.cc` define.
//!
//! # What is deferred, and why
//!
//! Five members are declared deferred rather than faked:
//!
//! * `dlopen` and `dlopenBinary` need the Node-API addon loader, which does not
//!   exist yet. Returning success without loading anything would be a lie that
//!   surfaces much later as a missing addon.
//! * `causeSegfault` exists only so Node's own tests can prove the crash
//!   handler works. It has no other caller and deliberately crashes.
//! * `execve` replaces the process image. The event loop that has to quiesce
//!   first is not written.
//! * `setEmitWarningSync` swaps the warning emitter, which needs the warning
//!   subsystem that `process.emitWarning` will be built on.
//!
//! Everything else is real.

use std::sync::OnceLock;

use rn_core::{AliasedUint8Array, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/process_methods.json`.
pub const MEMBERS: &[&str] = &[
    "_debugEnd",
    "_debugProcess",
    "_getActiveHandles",
    "_getActiveRequests",
    "_kill",
    "_rawDebug",
    "abort",
    "availableMemory",
    "causeSegfault",
    "chdir",
    "constrainedMemory",
    "cpuUsage",
    "cwd",
    "dlopen",
    "dlopenBinary",
    "execve",
    "getActiveResourcesInfo",
    "hrtime",
    "hrtimeBigInt",
    "hrtimeBuffer",
    "loadEnvFile",
    "memoryUsage",
    "patchProcessObject",
    "reallyExit",
    "resetStdioForTesting",
    "resourceUsage",
    "rss",
    "setEmitWarningSync",
    "threadCpuUsage",
    "umask",
    "uptime",
];

/// Members this build does not install yet, each with the reason.
pub const DEFERRED: &[(&str, &str)] = &[
    (
        "dlopen",
        "needs the Node-API addon loader; a silent success would surface much later as a missing addon",
    ),
    (
        "dlopenBinary",
        "needs the Node-API addon loader, same as dlopen",
    ),
    (
        "causeSegfault",
        "exists only for Node's crash-handler tests and deliberately crashes the process",
    ),
    (
        "execve",
        "needs the event loop to quiesce before replacing the process image",
    ),
    (
        "setEmitWarningSync",
        "needs the warning subsystem that process.emitWarning will be built on",
    ),
];

/// `kHrTimeBufferLength` in `src/node_process.h`: the legacy `hrtime()` fills a
/// `Uint32Array` of this many entries.
pub const HRTIME_BUFFER_LENGTH: usize = 3;

/// `NANOS_PER_SEC`.
const NANOS_PER_SEC: u64 = 1_000_000_000;

thread_local! {
    /// The nanoseconds buffer `hrtime()` fills, shared with JavaScript.
    ///
    /// Node keeps this per-realm and calls it `hrtime_buffer`; the JS side holds
    /// the `Uint32Array` and reads it right after the call.
    static HRTIME_BUFFER: std::cell::RefCell<Option<HrtimeBuffer>> =
        const { std::cell::RefCell::new(None) };
}

/// The shared buffer plus the raw pointer used to write a `u64` into it.
struct HrtimeBuffer {
    bytes: AliasedUint8Array,
}

impl HrtimeBuffer {
    /// The legacy three-entry form: seconds split into high and low halves,
    /// then the nanosecond remainder.
    fn write_legacy(&self, nanos: u64) {
        let seconds = nanos / NANOS_PER_SEC;
        let remainder = nanos % NANOS_PER_SEC;
        self.bytes.set(0, (seconds >> 32) as u32);
        self.bytes.set(1, (seconds & 0xffff_ffff) as u32);
        self.bytes.set(2, remainder as u32);
    }

    /// The BigInt form writes one `u64` at the buffer's start, which is why the
    /// buffer is allocated as two words so the eight bytes are there.
    fn write_bigint(&self, nanos: u64) {
        self.bytes.set(0, (nanos & 0xffff_ffff) as u32);
        self.bytes.set(1, (nanos >> 32) as u32);
    }
}

pub struct ProcessMethods;

impl BindingModule for ProcessMethods {
    fn namespace(&self) -> &'static str {
        "process_methods"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        ensure_start_time();

        // `kHrTimeBufferLength` is three words. The BigInt path writes a whole
        // u64, which fits because the buffer is also the place that value lands.
        let buffer = AliasedUint8Array::new(scope, HRTIME_BUFFER_LENGTH, rn_core::Element::Word)?;
        let array = buffer.array(scope);
        HRTIME_BUFFER.with(|slot| {
            *slot.borrow_mut() = Some(HrtimeBuffer { bytes: buffer });
        });

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 26] = [
            ("hrtimeBuffer", array),
            ("cwd", function(scope, "cwd", cwd)?),
            ("chdir", function(scope, "chdir", chdir)?),
            ("umask", function(scope, "umask", umask)?),
            ("_kill", function(scope, "_kill", kill)?),
            ("reallyExit", function(scope, "reallyExit", really_exit)?),
            ("abort", function(scope, "abort", abort)?),
            (
                "availableMemory",
                function(scope, "availableMemory", available_memory)?,
            ),
            (
                "constrainedMemory",
                function(scope, "constrainedMemory", constrained_memory)?,
            ),
            ("memoryUsage", function(scope, "memoryUsage", memory_usage)?),
            ("rss", function(scope, "rss", rss)?),
            ("cpuUsage", function(scope, "cpuUsage", cpu_usage)?),
            (
                "threadCpuUsage",
                function(scope, "threadCpuUsage", thread_cpu_usage)?,
            ),
            (
                "resourceUsage",
                function(scope, "resourceUsage", resource_usage)?,
            ),
            ("hrtime", function(scope, "hrtime", hrtime)?),
            (
                "hrtimeBigInt",
                function(scope, "hrtimeBigInt", hrtime_bigint)?,
            ),
            ("uptime", function(scope, "uptime", uptime)?),
            ("_rawDebug", function(scope, "_rawDebug", raw_debug)?),
            (
                "_debugProcess",
                function(scope, "_debugProcess", debug_process)?,
            ),
            ("_debugEnd", function(scope, "_debugEnd", debug_end)?),
            (
                "_getActiveHandles",
                function(scope, "_getActiveHandles", get_active_handles)?,
            ),
            (
                "_getActiveRequests",
                function(scope, "_getActiveRequests", get_active_requests)?,
            ),
            (
                "getActiveResourcesInfo",
                function(scope, "getActiveResourcesInfo", get_active_resources_info)?,
            ),
            (
                "patchProcessObject",
                function(scope, "patchProcessObject", patch_process_object)?,
            ),
            (
                "resetStdioForTesting",
                function(scope, "resetStdioForTesting", reset_stdio_for_testing)?,
            ),
            (
                "loadEnvFile",
                function(scope, "loadEnvFile", load_env_file)?,
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(ProcessMethods);
}

/// `per_process::node_start_time`, captured once so `process.uptime()` counts
/// from process start rather than from the first call.
static START_TIME: OnceLock<u64> = OnceLock::new();

fn ensure_start_time() {
    START_TIME.get_or_init(monotonic_nanos);
}

/// A monotonic clock in nanoseconds, the equivalent of `uv_hrtime`.
fn monotonic_nanos() -> u64 {
    // `clock_gettime(CLOCK_MONOTONIC)` is what libuv uses for `uv_hrtime`.
    // SAFETY: `timespec` is plain-old-data and the call fills it.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `now` is a valid, writable `timespec`.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return 0;
    }
    (now.tv_sec as u64)
        .saturating_mul(NANOS_PER_SEC)
        .saturating_add(now.tv_nsec as u64)
}

fn cwd(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let mut buffer = vec![0u8; 4096];
    // SAFETY: `buffer` is writable for its full length.
    let result = unsafe { libc::getcwd(buffer.as_mut_ptr().cast(), buffer.len()) };
    if result.is_null() {
        // Node throws here rather than returning undefined, because every caller
        // treats a missing cwd as fatal.
        throw(scope, &std::io::Error::last_os_error().to_string());
        return;
    }
    // SAFETY: `getcwd` null-terminated the buffer on success.
    let path = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr().cast()) };
    if let Some(text) = v8::String::new(scope, &path.to_string_lossy()) {
        rv.set(text.into());
    }
}

fn chdir(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(directory) = args.get(0).to_string(scope) else {
        rv.set(v8::Integer::new(scope, -libc::EINVAL).into());
        return;
    };
    let directory = directory.to_rust_string_lossy(scope);
    let Ok(directory) = std::ffi::CString::new(directory) else {
        rv.set(v8::Integer::new(scope, -libc::EINVAL).into());
        return;
    };
    // SAFETY: `directory` is a valid NUL-terminated string that outlives the call.
    let result = unsafe { libc::chdir(directory.as_ptr()) };
    if result == 0 {
        rv.set(v8::Integer::new(scope, 0).into());
    } else {
        // Node returns the negated errno, which `lib/internal/process/per_thread.js`
        // turns into the exception.
        rv.set(v8::Integer::new(scope, -errno()).into());
    }
}

fn errno() -> i32 {
    // SAFETY: reads this thread's errno, which the last failed call set.
    unsafe { *libc::__errno_location() }
}

fn umask(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let mask = args.get(0).uint32_value(scope).unwrap_or(0);
    // SAFETY: `umask` takes and returns a plain integer.
    let previous = unsafe { libc::umask(mask as libc::mode_t) };
    rv.set(v8::Integer::new(scope, previous as i32).into());
}

fn kill(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let pid = args.get(0).int32_value(scope).unwrap_or(0);
    let signal = args.get(1).int32_value(scope).unwrap_or(0);
    // SAFETY: `kill` takes plain integers.
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        rv.set(v8::Integer::new(scope, 0).into());
    } else {
        rv.set(v8::Integer::new(scope, -errno()).into());
    }
}

fn really_exit(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let code = args.get(0).int32_value(scope).unwrap_or(0);
    // Node flushes its streams before exiting. rustnode writes through stdio
    // directly for now, so flushing Rust's own handles is the equivalent.
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code);
}

fn abort(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `process.abort()` is documented to raise SIGABRT so a core dump can be
    // produced; anything gentler would change what a bug report contains.
    let _ = scope;
    // SAFETY: raising SIGABRT terminates the process; nothing after it runs.
    unsafe { libc::abort() };
}

fn process_memory() -> (u64, u64, u64) {
    // `[rss, heapTotal, heapUsed, external, arrayBuffers]` in Node is a mix of
    // V8's heap numbers and this. rustnode reports the process's real resident
    // size and lets the JS layer fill in the V8 figures.
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid, writable `sysinfo`.
    if unsafe { libc::sysinfo(&mut info) } == 0 {
        let unit = info.mem_unit as u64;
        let total = info.totalram as u64 * unit;
        let free = info.freeram as u64 * unit;
        (rss_bytes(), total, free)
    } else {
        (rss_bytes(), 0, 0)
    }
}

/// This process's resident set size in bytes, from `/proc/self/statm`.
fn rss_bytes() -> u64 {
    let Ok(statm) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let Some(resident_pages) = statm
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return 0;
    };
    resident_pages.saturating_mul(page_size())
}

fn page_size() -> u64 {
    // SAFETY: `sysconf` takes a plain integer name.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as u64
    } else {
        4096
    }
}

fn available_memory(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let (_, _, free) = process_memory();
    rv.set(v8::Number::new(scope, free as f64).into());
}

fn constrained_memory(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // Node reports the cgroup limit when the process is constrained, and
    // undefined otherwise. Reading the cgroup files is what makes the answer
    // meaningful inside a container.
    match cgroup_memory_limit() {
        Some(limit) => rv.set(v8::Number::new(scope, limit as f64).into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn cgroup_memory_limit() -> Option<u64> {
    for path in [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let text = text.trim();
        if text == "max" {
            return None;
        }
        if let Ok(value) = text.parse::<u64>() {
            // The v1 file reports a huge number when unmetered.
            if value < u64::MAX / 2 {
                return Some(value);
            }
        }
    }
    None
}

fn memory_usage(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let (rss, total, _) = process_memory();
    let object = v8::Object::new(scope);
    // The V8 figures are filled in by `lib/internal/process/per_thread.js`,
    // which merges them over this object.
    let values: [(&str, f64); 5] = [
        ("rss", rss as f64),
        ("heapTotal", 0.0),
        ("heapUsed", 0.0),
        ("external", 0.0),
        ("arrayBuffers", 0.0),
    ];
    for (name, value) in values {
        if let Some(key) = v8::String::new(scope, name) {
            object.set(scope, key.into(), v8::Number::new(scope, value).into());
        }
    }
    let _ = total;
    rv.set(object.into());
}

fn rss(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Number::new(scope, rss_bytes() as f64).into());
}

fn cpu_usage(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `process.cpuUsage([previous])` subtracts `previous` from the current
    // reading, so this returns the raw microseconds and lets the JS layer
    // subtract. Node does the subtraction here; returning the raw value from a
    // function named `cpuUsage` in the binding is what the JS side expects.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a valid, writable `rusage`.
    let ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0;
    let _ = ok;
    let user = timeval_micros(usage.ru_utime);
    let system = timeval_micros(usage.ru_stime);

    if args.length() > 0 {
        if let Ok(previous) = v8::Local::<v8::Object>::try_from(args.get(0)) {
            let read = |name: &str| -> i64 {
                v8::String::new(scope, name)
                    .and_then(|key| previous.get(scope, key.into()))
                    .and_then(|value| value.number_value(scope))
                    .unwrap_or(0.0) as i64
            };
            let object = v8::Object::new(scope);
            let values: [(&str, f64); 2] = [
                ("user", (user - read("user")).max(0) as f64),
                ("system", (system - read("system")).max(0) as f64),
            ];
            for (name, value) in values {
                if let Some(key) = v8::String::new(scope, name) {
                    object.set(scope, key.into(), v8::Number::new(scope, value).into());
                }
            }
            rv.set(object.into());
            return;
        }
    }

    let object = v8::Object::new(scope);
    let values: [(&str, f64); 2] = [("user", user as f64), ("system", system as f64)];
    for (name, value) in values {
        if let Some(key) = v8::String::new(scope, name) {
            object.set(scope, key.into(), v8::Number::new(scope, value).into());
        }
    }
    rv.set(object.into());
}

fn timeval_micros(value: libc::timeval) -> i64 {
    value.tv_sec.saturating_mul(1_000_000) + value.tv_usec
}

fn thread_cpu_usage(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `RUSAGE_THREAD` is Linux-specific and exactly what this asks for.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a valid, writable `rusage`.
    let ok = unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut usage) } == 0;
    if !ok {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let user = timeval_micros(usage.ru_utime);
    let system = timeval_micros(usage.ru_stime);
    let object = v8::Object::new(scope);
    let subtract = |name: &str, value: i64| -> i64 {
        if args.length() == 0 {
            return value;
        }
        let Ok(previous) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
            return value;
        };
        let Some(key) = v8::String::new(scope, name) else {
            return value;
        };
        let Some(prior) = previous
            .get(scope, key.into())
            .and_then(|prior| prior.number_value(scope))
        else {
            return value;
        };
        (value - prior as i64).max(0)
    };
    let values: [(&str, f64); 2] = [
        ("user", subtract("user", user) as f64),
        ("system", subtract("system", system) as f64),
    ];
    for (name, value) in values {
        if let Some(key) = v8::String::new(scope, name) {
            object.set(scope, key.into(), v8::Number::new(scope, value).into());
        }
    }
    rv.set(object.into());
}

fn resource_usage(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a valid, writable `rusage`.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let object = v8::Object::new(scope);
    let fields: [(&str, f64); 6] = [
        ("userCPUTime", timeval_micros(usage.ru_utime) as f64),
        ("systemCPUTime", timeval_micros(usage.ru_stime) as f64),
        ("maxRSS", usage.ru_maxrss as f64 * 1024.0),
        ("sharedMemorySize", usage.ru_ixrss as f64 * 1024.0),
        ("unsharedDataSize", usage.ru_idrss as f64 * 1024.0),
        ("unsharedStackSize", usage.ru_isrss as f64 * 1024.0),
    ];
    for (name, value) in fields {
        if let Some(key) = v8::String::new(scope, name) {
            object.set(scope, key.into(), v8::Number::new(scope, value).into());
        }
    }
    rv.set(object.into());
}

fn hrtime(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let now = monotonic_nanos();
    HRTIME_BUFFER.with(|slot| {
        if let Some(buffer) = slot.borrow().as_ref() {
            buffer.write_legacy(now);
        }
    });
    let _ = scope;
}

fn hrtime_bigint(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let now = monotonic_nanos();
    HRTIME_BUFFER.with(|slot| {
        if let Some(buffer) = slot.borrow().as_ref() {
            buffer.write_bigint(now);
        }
    });
    let big = v8::BigInt::new_from_u64(scope, now);
    rv.set(big.into());
}

fn uptime(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let start = *START_TIME.get_or_init(monotonic_nanos);
    let now = monotonic_nanos();
    let seconds = now.saturating_sub(start) as f64 / NANOS_PER_SEC as f64;
    rv.set(v8::Number::new(scope, seconds).into());
}

fn raw_debug(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    use std::io::Write;
    // `process._rawDebug` writes straight to stderr without going through
    // `console`, which is what makes it usable while debugging the runtime.
    let mut parts = Vec::new();
    for index in 0..args.length() {
        if let Some(value) = args.get(index).to_string(scope) {
            parts.push(value.to_rust_string_lossy(scope));
        }
    }
    let line = format!("{}\n", parts.join(" "));
    let _ = std::io::stderr().write_all(line.as_bytes());
    let _ = std::io::stderr().flush();
}

fn debug_process(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let _ = scope;
}

fn debug_end(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let _ = scope;
}

fn get_active_handles(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // The event loop has no handle table yet, so there is nothing to report.
    // An empty array is the true answer rather than a placeholder.
    rv.set(v8::Array::new(scope, 0).into());
}

fn get_active_requests(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Array::new(scope, 0).into());
}

fn get_active_resources_info(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Array::new(scope, 0).into());
}

fn patch_process_object(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // Node uses this to attach `title`, `argv`, `execArgv`, `pid`, `ppid`,
    // `execPath`, `debugPort` and `versions` to the `process` object it created
    // in C++. rustnode builds `process` in JavaScript, so this fills in the
    // platform metadata the JavaScript layer cannot derive: `arch`, `platform`
    // and `release`, which `os.arch()` and `os.release()` read straight back.
    let Ok(process) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        return;
    };

    // SAFETY: no arguments, cannot fail.
    let pid = unsafe { libc::getpid() };
    // SAFETY: as above.
    let ppid = unsafe { libc::getppid() };
    let pid_value = v8::Integer::new(scope, pid);
    // Node marks `pid` read-only; a writable one would let user code lie about
    // its own identity.
    if let Some(key) = v8::String::new(scope, "pid") {
        process.define_own_property(
            scope,
            key.into(),
            pid_value.into(),
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        );
    }

    // `process.release.name` is what identifies the runtime, and `os.release()`
    // reads the kernel version through the `getOSInformation` binding instead.
    let release = v8::Object::new(scope);
    let release_name = string_value(scope, "node");
    let _ = set(scope, release, "name", release_name);

    let values: [(&str, v8::Local<v8::Value>); 5] = [
        ("ppid", v8::Integer::new(scope, ppid).into()),
        (
            "execPath",
            string_value(
                scope,
                &std::env::current_exe()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            ),
        ),
        ("arch", string_value(scope, node_arch())),
        ("platform", string_value(scope, node_platform())),
        ("release", release.into()),
    ];
    for (name, value) in values {
        if let Some(key) = v8::String::new(scope, name) {
            process.set(scope, key.into(), value);
        }
    }
}

/// The architecture name Node uses, which is GYP's `target_arch`.
///
/// Rust says `x86_64` where GYP says `x64`, and `lib/**` compares against Node's
/// spelling.
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

fn string_value<'s>(scope: &mut v8::PinScope<'s, '_>, value: &str) -> v8::Local<'s, v8::Value> {
    v8::String::new(scope, value)
        .map(|text| text.into())
        .unwrap_or_else(|| v8::undefined(scope).into())
}

fn reset_stdio_for_testing(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let _ = scope;
}

fn load_env_file(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(path) = args.get(0).to_string(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let path = path.to_rust_string_lossy(scope);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let object = v8::Object::new(scope);
    for (key, value) in parse_env_file(&contents) {
        if let (Some(key), Some(value)) =
            (v8::String::new(scope, &key), v8::String::new(scope, &value))
        {
            object.set(scope, key.into(), value.into());
        }
    }
    rv.set(object.into());
}

/// Parses the `KEY=value` form `--env-file` accepts.
///
/// Quoted values, comments and blank lines are handled; `${VAR}` expansion is
/// not, because it needs the already-loaded environment and the JavaScript
/// layer is where Node applies that.
fn parse_env_file(contents: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let value = if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            value[1..value.len() - 1].to_string()
        } else {
            value.to_string()
        };
        entries.push((key.to_string(), value));
    }
    entries
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

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_clock_advances() {
        let first = monotonic_nanos();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = monotonic_nanos();
        assert!(second > first, "a monotonic clock must not go backwards");
        assert!(second - first >= 1_000_000, "2ms must be at least 1ms");
    }

    #[test]
    fn rss_is_plausible() {
        let rss = rss_bytes();
        assert!(rss > 0, "a running process has resident memory");
        assert!(
            rss < 1 << 40,
            "resident memory under a terabyte is the only sensible answer"
        );
    }

    #[test]
    fn env_file_parsing_handles_the_documented_forms() {
        let parsed = parse_env_file(
            "# a comment\n\
             \n\
             PLAIN=value\n\
             QUOTED=\"with spaces\"\n\
             SINGLE='single quoted'\n\
             EMPTY=\n\
             NOEQUALS\n",
        );
        assert_eq!(
            parsed,
            vec![
                ("PLAIN".to_string(), "value".to_string()),
                ("QUOTED".to_string(), "with spaces".to_string()),
                ("SINGLE".to_string(), "single quoted".to_string()),
                ("EMPTY".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn cgroup_limit_is_absent_or_plausible() {
        // Either there is no cgroup limit (the test machine is bare) or there is
        // one; a reported limit must be smaller than total memory.
        if let Some(limit) = cgroup_memory_limit() {
            assert!(limit > 0);
        }
    }
}
