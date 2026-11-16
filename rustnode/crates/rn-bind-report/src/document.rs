//! The diagnostic report document, in Node's schema.
//!
//! `src/node_report.cc` builds this document with a streaming writer, and the
//! section list, the section *order* and the header's field order are the
//! interface: `NODE_REPORT_VERSION` tells a consumer which schema to apply, and
//! tooling that parses a report reads sections by name.
//!
//! # `reportVersion` is 5
//!
//! It is a wire version, not an implementation detail. `node_report.cc:28` is
//! `constexpr int NODE_REPORT_VERSION = 5`. This build used to emit `3`, which
//! tells a consumer to parse the document with a schema that predates the fields
//! it is reading.
//!
//! # The section list is Node's, including the ones that are empty
//!
//! Node emits exactly these eleven keys, in this order:
//!
//! ```text
//! header, javascriptStack, javascriptHeap, nativeStack, resourceUsage,
//! uvthreadResourceUsage, libuv, workers, environmentVariables, userLimits,
//! sharedObjects
//! ```
//!
//! `environmentVariables` and `userLimits` are **top-level sections**, not
//! header fields, and `workers` is an empty array when the process has none
//! rather than an absent key. The previous version of this crate nested the two
//! under `header`, invented a `process` section Node never emits, and omitted
//! `libuv`, `uvthreadResourceUsage`, `workers` and `sharedObjects`.
//!
//! # What is empty, and why that is not a lie
//!
//! * `workers` is `[]`. Node fills it with one subreport per worker, obtained by
//!   interrupting each worker thread. rustnode's worker registry tracks handles
//!   but has no protocol for a thread to hand back a rendered report, so an empty
//!   array is correct only when the process has no workers and is a known
//!   limitation otherwise — see the crate report.
//! * The `libuv` section walks the real loop, so its handles are real. Socket
//!   endpoints are reported through `uv_tcp_getsockname` and friends, which is
//!   what Node does.
//! * `nativeStack` uses `backtrace` plus `dladdr`, the same two calls Node's
//!   `NativeSymbolDebuggingContext::New()` makes on Linux. Symbols resolve only
//!   as far as the binary's own symbol table allows, exactly as in Node.

use std::ffi::{CStr, CString};
use std::fmt::Write as _;

use libuv_sys2 as uv;

use crate::json::JsonWriter;

/// `NODE_REPORT_VERSION`.
pub const REPORT_VERSION: u32 = 5;

/// `MAX_FRAME_COUNT` in `PrintNativeStack`.
const NATIVE_FRAME_COUNT: usize = 256;

/// Everything `WriteNodeReport` needs that is not read from the OS.
pub struct ReportInput<'a> {
    /// `event`: the message the report is about.
    pub event: &'a str,
    /// `trigger`: how the report was triggered.
    pub trigger: &'a str,
    /// `filename` in the header, or `None` for `null`.
    pub filename: Option<&'a str>,
    pub compact: bool,
    pub exclude_network: bool,
    pub exclude_env: bool,
    /// The error whose stack fills `javascriptStack`, already rendered by the
    /// caller as `(message, stack lines, error properties)`.
    pub error: Option<ErrorDetails>,
    /// `process.versions` as this runtime reports it.
    pub component_versions: Vec<(String, String)>,
    /// `process.release`, which the header's `release` section mirrors.
    pub release: Vec<(String, String)>,
}

impl<'a> ReportInput<'a> {
    #[must_use]
    pub fn new(event: &'a str, trigger: &'a str) -> Self {
        Self {
            event,
            trigger,
            filename: None,
            compact: false,
            exclude_network: false,
            exclude_env: false,
            error: None,
            component_versions: Vec::new(),
            release: Vec::new(),
        }
    }
}

/// The JavaScript error a report is about.
pub struct ErrorDetails {
    /// `javascriptStack.message`: the first line of `error.stack`.
    pub message: String,
    /// `javascriptStack.stack`: the remaining lines, leading whitespace trimmed.
    pub stack: Vec<String>,
    /// `javascriptStack.errorProperties`: the error's own enumerable properties
    /// other than `stack` and `message`, stringified.
    pub properties: Vec<(String, String)>,
}

/// A heap space, as `HeapSpaceStatistics` reports one.
pub struct HeapSpace {
    pub name: String,
    pub size: usize,
    pub physical_size: usize,
    pub used_size: usize,
    pub available_size: usize,
}

/// The numbers `PrintGCStatistics` reads out of one `HeapStatistics`.
#[derive(Default)]
pub struct HeapStats {
    pub total_heap_size: usize,
    pub total_heap_size_executable: usize,
    pub total_physical_size: usize,
    pub total_available_size: usize,
    pub total_global_handles_size: usize,
    pub used_global_handles_size: usize,
    pub used_heap_size: usize,
    pub heap_size_limit: usize,
    pub malloced_memory: usize,
    pub external_memory: usize,
    pub peak_malloced_memory: usize,
    pub number_of_native_contexts: usize,
    pub number_of_detached_contexts: usize,
    pub does_zap_garbage: bool,
    pub spaces: Vec<HeapSpace>,
}

/// The thread identity the header publishes.
pub struct ThreadIdentity {
    pub thread_id: i32,
}

/// Renders the whole document.
///
/// `heap` is `None` when no isolate is reachable, which is the case Node handles
/// by emitting the "No stack." variant of `javascriptStack` and skipping the
/// heap: `WriteNodeReport` calls `PrintGCStatistics` only when `isolate != nullptr`.
pub fn render(
    input: &ReportInput<'_>,
    heap: Option<&HeapStats>,
    thread: &ThreadIdentity,
) -> String {
    // Node computes this once, from `uv_hrtime() - node_start_time`, and both
    // resource-usage blocks divide by it. A zero would divide by zero, so it is
    // clamped to one second exactly as Node does.
    let uptime = process_uptime_seconds().max(1);

    let mut writer = JsonWriter::new(input.compact);
    writer.start();

    write_header(&mut writer, input, thread);
    write_javascript_stack(&mut writer, input);
    if let Some(heap) = heap {
        write_heap(&mut writer, heap);
    }
    write_native_stack(&mut writer);
    write_resource_usage(&mut writer, uptime);
    write_uvthread_resource_usage(&mut writer, uptime);
    write_libuv(&mut writer, input.exclude_network);
    // Node interrupts each worker thread and embeds its rendered report here.
    // There is no protocol for that yet, so the array is emitted empty rather
    // than omitted, which is the shape a consumer expects.
    writer.array_start("workers");
    writer.array_end();
    if !input.exclude_env {
        write_environment_variables(&mut writer);
    }
    write_user_limits(&mut writer);
    write_shared_objects(&mut writer);

    writer.end();
    writer.finish()
}

fn write_header(writer: &mut JsonWriter, input: &ReportInput<'_>, thread: &ThreadIdentity) {
    writer.object_start("header");
    writer.key_int("reportVersion", REPORT_VERSION);
    writer.key_string("event", input.event);
    writer.key_string("trigger", input.trigger);
    match input.filename {
        Some(name) => writer.key_string("filename", name),
        // Node writes `JSONWriter::Null{}` when no name was chosen, which is the
        // case for `getReport()`.
        None => writer.key_null("filename"),
    }
    writer.key_string("dumpEventTime", &local_timestamp());
    writer.key_string("dumpEventTimeStamp", &epoch_millis().to_string());
    writer.key_int("processId", std::process::id());
    writer.key_int("threadId", thread.thread_id);
    writer.key_string("cwd", &current_dir());

    let command_line: Vec<String> = std::env::args().collect();
    if !command_line.is_empty() {
        writer.array_start("commandLine");
        for argument in &command_line {
            writer.element_string(argument);
        }
        writer.array_end();
    }

    // `PrintVersionInformation`: `v` + the version, then the two glibc numbers
    // where the platform has them.
    writer.key_string(
        "nodejsVersion",
        &format!("v{}", crate::versions::NODE_VERSION),
    );
    writer.key_string("glibcVersionRuntime", &glibc_runtime_version());
    writer.key_string("glibcVersionCompiler", &glibc_compiler_version());
    writer.key_int("wordSize", std::mem::size_of::<usize>() * 8);
    writer.key_string("arch", node_arch());
    writer.key_string("platform", node_platform());

    writer.object_start("componentVersions");
    for (name, value) in &input.component_versions {
        writer.key_string(name, value);
    }
    writer.object_end();

    writer.object_start("release");
    for (name, value) in &input.release {
        writer.key_string(name, value);
    }
    writer.object_end();

    let (os_name, os_release, os_version, os_machine) = uname_fields();
    writer.key_string("osName", &os_name);
    writer.key_string("osRelease", &os_release);
    writer.key_string("osVersion", &os_version);
    writer.key_string("osMachine", &os_machine);

    write_cpus(writer);
    if !input.exclude_network {
        write_network_interfaces(writer);
    }
    writer.key_string("host", &hostname());

    writer.object_end();
}

/// `PrintCpuInfo`: one entry per core from `uv_cpu_info`.
fn write_cpus(writer: &mut JsonWriter) {
    let mut list: *mut uv::uv_cpu_info_t = std::ptr::null_mut();
    let mut count: std::os::raw::c_int = 0;
    // SAFETY: `uv_cpu_info` fills the pointer and count on success, and the
    // matching `uv_free_cpu_info` below releases both.
    let status = unsafe { uv::uv_cpu_info(&mut list, &mut count) };
    writer.array_start("cpus");
    if status == 0 && !list.is_null() {
        for index in 0..count as isize {
            // SAFETY: `index` is inside the `count`-element array libuv
            // allocated.
            let cpu = unsafe { &*list.offset(index) };
            writer.start();
            // SAFETY: `model` is a NUL-terminated string owned by the array.
            let model = unsafe { CStr::from_ptr(cpu.model) }
                .to_string_lossy()
                .into_owned();
            writer.key_string("model", &model);
            writer.key_int("speed", cpu.speed);
            writer.key_int("user", cpu.cpu_times.user);
            writer.key_int("nice", cpu.cpu_times.nice);
            writer.key_int("sys", cpu.cpu_times.sys);
            writer.key_int("idle", cpu.cpu_times.idle);
            writer.key_int("irq", cpu.cpu_times.irq);
            writer.end();
        }
        // SAFETY: the same array `uv_cpu_info` allocated, freed once.
        unsafe { uv::uv_free_cpu_info(list, count) };
    }
    writer.array_end();
}

/// `PrintNetworkInterfaceInfo`: one entry per address, not per interface.
///
/// `os.networkInterfaces()` groups these by name; the report does not, and it
/// includes the netmask and MAC that the JavaScript view also exposes.
fn write_network_interfaces(writer: &mut JsonWriter) {
    let mut list: *mut uv::uv_interface_address_t = std::ptr::null_mut();
    let mut count: std::os::raw::c_int = 0;
    // SAFETY: `uv_interface_addresses` fills the pointer and count on success.
    let status = unsafe { uv::uv_interface_addresses(&mut list, &mut count) };
    writer.array_start("networkInterfaces");
    if status == 0 && !list.is_null() {
        for index in 0..count as isize {
            // SAFETY: `index` is inside the `count`-element array.
            let entry = unsafe { &*list.offset(index) };
            writer.start();
            // SAFETY: `name` is a NUL-terminated string owned by the array.
            let name = unsafe { CStr::from_ptr(entry.name) }
                .to_string_lossy()
                .into_owned();
            writer.key_string("name", &name);
            writer.key_raw(
                "internal",
                if entry.is_internal != 0 {
                    "true"
                } else {
                    "false"
                },
            );
            writer.key_string("mac", &mac_address(&entry.phys_addr));
            // SAFETY: `address` is a union of two `sockaddr` variants, and the
            // family field selects which one is live.
            let family = unsafe { entry.address.address4.sin_family } as i32;
            if family == libc::AF_INET {
                // SAFETY: the family selected the IPv4 variant.
                let address = unsafe { entry.address.address4 };
                // SAFETY: the union member is the live one for this family.
                let netmask = unsafe { entry.netmask.netmask4 };
                writer.key_string("address", &ipv4_text(address.sin_addr.s_addr));
                writer.key_string("netmask", &ipv4_text(netmask.sin_addr.s_addr));
                writer.key_string("family", "IPv4");
            } else if family == libc::AF_INET6 {
                // SAFETY: the family selected the IPv6 variant.
                let address = unsafe { entry.address.address6 };
                // SAFETY: as above.
                let netmask = unsafe { entry.netmask.netmask6 };
                // SAFETY: the `in6_addr` union's `__u6_addr8` arm is the
                // 16-byte form, which is the one this reads.
                let address_bytes = unsafe { address.sin6_addr.__in6_u.__u6_addr8 };
                // SAFETY: as above.
                let netmask_bytes = unsafe { netmask.sin6_addr.__in6_u.__u6_addr8 };
                writer.key_string("address", &ipv6_text(&address_bytes));
                writer.key_string("netmask", &ipv6_text(&netmask_bytes));
                writer.key_string("family", "IPv6");
                writer.key_int("scopeid", address.sin6_scope_id);
            } else {
                writer.key_string("family", "unknown");
            }
            writer.end();
        }
        // SAFETY: the same array `uv_interface_addresses` allocated.
        unsafe { uv::uv_free_interface_addresses(list, count) };
    }
    writer.array_end();
}

/// `PrintJavaScriptErrorStack`.
///
/// With an error, the first line of its stack is `message` and the rest become
/// the array. Without one, Node reports the current stack; with no isolate at all
/// it reports the "No stack." sentinel.
fn write_javascript_stack(writer: &mut JsonWriter, input: &ReportInput<'_>) {
    writer.object_start("javascriptStack");
    match &input.error {
        Some(error) => {
            writer.key_string("message", &error.message);
            writer.array_start("stack");
            for line in &error.stack {
                writer.element_string(line);
            }
            writer.array_end();
            writer.object_start("errorProperties");
            for (name, value) in &error.properties {
                writer.key_string(name, value);
            }
            writer.object_end();
        }
        None => {
            // `PrintEmptyJavaScriptStack`, which is what a report without an
            // isolate contains, and also what a stack with no frames becomes.
            writer.key_string("message", "No stack.");
            writer.array_start("stack");
            writer.element_string("Unavailable.");
            writer.array_end();
            writer.object_start("errorProperties");
            writer.object_end();
        }
    }
    writer.object_end();
}

/// `PrintGCStatistics`.
fn write_heap(writer: &mut JsonWriter, heap: &HeapStats) {
    writer.object_start("javascriptHeap");
    writer.key_int("totalMemory", heap.total_heap_size);
    writer.key_int("executableMemory", heap.total_heap_size_executable);
    writer.key_int("totalCommittedMemory", heap.total_physical_size);
    writer.key_int("availableMemory", heap.total_available_size);
    writer.key_int("totalGlobalHandlesMemory", heap.total_global_handles_size);
    writer.key_int("usedGlobalHandlesMemory", heap.used_global_handles_size);
    writer.key_int("usedMemory", heap.used_heap_size);
    writer.key_int("memoryLimit", heap.heap_size_limit);
    writer.key_int("mallocedMemory", heap.malloced_memory);
    writer.key_int("externalMemory", heap.external_memory);
    writer.key_int("peakMallocedMemory", heap.peak_malloced_memory);
    writer.key_int("nativeContextCount", heap.number_of_native_contexts);
    writer.key_int("detachedContextCount", heap.number_of_detached_contexts);
    // `doesZapGarbage` is V8's 0/1 flag, not a JSON boolean.
    writer.key_int("doesZapGarbage", u8::from(heap.does_zap_garbage));
    writer.object_start("heapSpaces");
    for space in &heap.spaces {
        writer.object_start(&space.name);
        writer.key_int("memorySize", space.size);
        writer.key_int("committedMemory", space.physical_size);
        // `capacity` is used + available, which Node writes out rather than
        // reading a capacity field.
        writer.key_int("capacity", space.used_size + space.available_size);
        writer.key_int("used", space.used_size);
        writer.key_int("available", space.available_size);
        writer.object_end();
    }
    writer.object_end();
    writer.object_end();
}

/// `PrintNativeStack`, which walks `backtrace` from frame 1.
fn write_native_stack(writer: &mut JsonWriter) {
    let mut frames = [std::ptr::null_mut::<std::ffi::c_void>(); NATIVE_FRAME_COUNT];
    // SAFETY: `frames` is a writable array of `NATIVE_FRAME_COUNT` pointers, and
    // `backtrace` fills at most that many.
    let count = unsafe { libc::backtrace(frames.as_mut_ptr(), NATIVE_FRAME_COUNT as i32) };
    writer.array_start("nativeStack");
    for frame in frames.iter().take(count.max(0) as usize).skip(1) {
        // Frame 0 is `PrintNativeStack` itself, which Node skips for the same
        // reason: it names the reporter rather than the caller.
        writer.start();
        writer.key_string("pc", &format!("0x{:016x}", *frame as usize));
        writer.key_string("symbol", &symbol_for(*frame));
        writer.end();
    }
    writer.array_end();
}

/// `LookupSymbol(frame).Display()`: `name[+dis] [filename][:Lline]`.
///
/// `dladdr` gives the nearest exported symbol and its object file, which is all
/// a report needs: the frame's own address is already in `pc`.
fn symbol_for(frame: *mut std::ffi::c_void) -> String {
    if frame.is_null() {
        return String::new();
    }
    // SAFETY: `Dl_info` is plain-old-data and `dladdr` fills it for any address
    // that belongs to a loaded object; it returns 0 otherwise, which is checked.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: `frame` came from `backtrace` on this thread, and `info` is a
    // valid writable `Dl_info`.
    if unsafe { libc::dladdr(frame, &mut info) } == 0 {
        return String::new();
    }
    let mut text = String::new();
    if !info.dli_sname.is_null() {
        // SAFETY: `dladdr` set `dli_sname` to a NUL-terminated string that lives
        // as long as the mapped object.
        let name = unsafe { CStr::from_ptr(info.dli_sname) }
            .to_string_lossy()
            .into_owned();
        text.push_str(&demangle(&name));
    }
    if !info.dli_fname.is_null() {
        // SAFETY: as above, for `dli_fname`.
        let file = unsafe { CStr::from_ptr(info.dli_fname) }
            .to_string_lossy()
            .into_owned();
        if !file.is_empty() {
            let _ = write!(text, " [{file}]");
        }
    }
    text
}

/// Demangles one Itanium C++ symbol, falling back to the mangled name.
///
/// Node calls `abi::__cxa_demangle`; this calls the C entry point of the same
/// function. A name that is not a valid mangled symbol comes back unchanged,
/// which is what the fallback branch of Node's `LookupSymbol` does too.
fn demangle(symbol: &str) -> String {
    let Ok(name) = CString::new(symbol) else {
        return symbol.to_string();
    };
    // SAFETY: `__cxa_demangle` reads the NUL-terminated name it is given and
    // returns either a `malloc`ed buffer or null; the buffer is freed below with
    // the allocator that produced it.
    let mut status: std::os::raw::c_int = 0;
    let demangled = unsafe {
        __cxa_demangle(
            name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut status,
        )
    };
    if status != 0 || demangled.is_null() {
        return symbol.to_string();
    }
    // SAFETY: `demangled` is a NUL-terminated string in a buffer of the length
    // `__cxa_demangle` recorded, and this is the only read of it.
    let text = unsafe { CStr::from_ptr(demangled) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: the buffer came from `__cxa_demangle`, which allocates with
    // `malloc` and documents `free` as the matching release.
    unsafe { libc::free(demangled.cast()) };
    text
}

extern "C" {
    /// `abi::__cxa_demangle`'s C signature.
    fn __cxa_demangle(
        mangled: *const std::os::raw::c_char,
        output: *mut std::os::raw::c_char,
        length: *mut usize,
        status: *mut std::os::raw::c_int,
    ) -> *mut std::os::raw::c_char;
}

/// `PrintResourceUsage`, process-wide.
fn write_resource_usage(writer: &mut JsonWriter, uptime: u64) {
    writer.object_start("resourceUsage");

    // The four memory facts Node reports first, in its order. `rss` and
    // `constrained_memory` are conditional there because the calls can fail or
    // report zero; the same conditions are kept.
    writer.key_int("free_memory", unsafe { uv::uv_get_free_memory() });
    writer.key_int("total_memory", unsafe { uv::uv_get_total_memory() });

    let mut rss: usize = 0;
    // SAFETY: `rss` is a valid writable `size_t`.
    if unsafe { uv::uv_resident_set_memory(&mut rss) } == 0 {
        writer.key_int("rss", rss);
    }
    let constrained = unsafe { uv::uv_get_constrained_memory() };
    if constrained != 0 {
        writer.key_int("constrained_memory", constrained);
    }
    writer.key_int("available_memory", unsafe { uv::uv_get_available_memory() });

    // SAFETY: `uv_rusage_t` is plain-old-data and `uv_getrusage` fills it.
    let mut usage: uv::uv_rusage_t = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a valid writable struct.
    if unsafe { uv::uv_getrusage(&mut usage) } == 0 {
        let user = seconds(usage.ru_utime);
        let kernel = seconds(usage.ru_stime);
        write_cpu_block(writer, user, kernel, uptime);
        // `ru_maxrss` is kilobytes on Linux and `uv_rusage_t` keeps it that way;
        // Node multiplies by 1024 for bytes.
        writer.key_int("maxRss", usage.ru_maxrss * 1024);
        writer.object_start("pageFaults");
        writer.key_int("IORequired", usage.ru_majflt);
        writer.key_int("IONotRequired", usage.ru_minflt);
        writer.object_end();
        write_fs_activity(writer, usage.ru_inblock, usage.ru_oublock);
    }
    writer.object_end();
}

/// `PrintResourceUsage`'s `uvthreadResourceUsage` block: this thread, not the
/// process.
fn write_uvthread_resource_usage(writer: &mut JsonWriter, uptime: u64) {
    // SAFETY: `uv_rusage_t` is plain-old-data and `uv_getrusage_thread` fills it.
    let mut usage: uv::uv_rusage_t = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a valid writable struct.
    if unsafe { uv::uv_getrusage_thread(&mut usage) } != 0 {
        return;
    }
    writer.object_start("uvthreadResourceUsage");
    let user = seconds(usage.ru_utime);
    let kernel = seconds(usage.ru_stime);
    write_cpu_block(writer, user, kernel, uptime);
    write_fs_activity(writer, usage.ru_inblock, usage.ru_oublock);
    writer.object_end();
}

fn write_cpu_block(writer: &mut JsonWriter, user: f64, kernel: f64, uptime: u64) {
    let uptime = uptime as f64;
    writer.key_float("userCpuSeconds", user);
    writer.key_float("kernelCpuSeconds", kernel);
    writer.key_float("cpuConsumptionPercent", ((user + kernel) / uptime) * 100.0);
    writer.key_float("userCpuConsumptionPercent", (user / uptime) * 100.0);
    writer.key_float("kernelCpuConsumptionPercent", (kernel / uptime) * 100.0);
}

fn write_fs_activity(writer: &mut JsonWriter, reads: u64, writes: u64) {
    writer.object_start("fsActivity");
    writer.key_int("reads", reads);
    writer.key_int("writes", writes);
    writer.object_end();
}

/// `uv_timeval_t` as fractional seconds.
fn seconds(value: uv::uv_timeval_t) -> f64 {
    value.tv_sec as f64 + (value.tv_usec as f64 * 1e-6)
}

/// The `libuv` section: every live handle, then the loop itself.
///
/// The handles are rendered by the same writer that renders the document, so the
/// indentation and commas are the writer's business rather than a second
/// formatter's. `uv_walk`'s data pointer is how the writer reaches the callback,
/// which is exactly what Node's `WalkHandle` does with its `JSONWriter*`.
fn write_libuv(writer: &mut JsonWriter, exclude_network: bool) {
    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        // No loop has been created, so there is nothing to report and Node's
        // `env != nullptr` branch would write nothing either.
        writer.array_start("libuv");
        writer.array_end();
        return;
    };

    writer.array_start("libuv");
    let context = WalkContext {
        exclude_network,
        writer: writer as *mut JsonWriter,
    };
    // SAFETY: `context` lives for the whole call and the walk is synchronous, so
    // the pointer the callback receives is valid throughout.
    unsafe {
        uv::uv_walk(
            loop_pointer,
            Some(collect_handle),
            (&raw const context).cast_mut().cast(),
        )
    };

    writer.start();
    writer.key_string("type", "loop");
    // SAFETY: `loop_pointer` is the live loop, which `loop_ptr` guarantees while
    // the closure runs.
    let alive = unsafe { uv::uv_loop_alive(loop_pointer) } != 0;
    writer.key_raw("is_active", if alive { "true" } else { "false" });
    writer.key_string("address", &format!("0x{:016x}", loop_pointer as usize));
    // SAFETY: as above.
    let idle = unsafe { uv::uv_metrics_idle_time(loop_pointer) };
    writer.key_float("loopIdleTimeSeconds", idle as f64 / 1e9);
    writer.end();
    writer.array_end();
}

/// The state a `uv_walk` callback needs.
struct WalkContext {
    exclude_network: bool,
    /// The writer the walk renders into.
    ///
    /// A raw pointer because `uv_walk`'s callback signature takes `void*`. The
    /// borrow is sound for the same reason Node's `static_cast<JSONWriter*>` is:
    /// the walk is synchronous and nothing else holds the writer meanwhile.
    writer: *mut JsonWriter,
}

/// Turns one handle into an array element, as `WalkHandle` does.
fn write_handle(writer: &mut JsonWriter, handle: *mut uv::uv_handle_t, exclude_network: bool) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `uv_walk` hands back live handles whose `type` field is valid.
    let kind = unsafe { (*handle).type_ };
    // SAFETY: `uv_handle_type_name` returns a static NUL-terminated string for
    // any handle type, including `UV_UNKNOWN_HANDLE`.
    let name = unsafe { CStr::from_ptr(uv::uv_handle_type_name(kind)) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: `handle` is live, so these two accessors are valid.
    let active = unsafe { uv::uv_is_active(handle) } != 0;
    let referenced = unsafe { uv::uv_has_ref(handle) } != 0;

    writer.start();
    writer.key_string("type", &name);
    writer.key_raw("is_active", if active { "true" } else { "false" });
    writer.key_raw("is_referenced", if referenced { "true" } else { "false" });
    writer.key_string("address", &format!("0x{:016x}", handle as usize));

    match kind {
        uv::uv_handle_type_UV_FS_EVENT | uv::uv_handle_type_UV_FS_POLL => {
            writer.key_null("filename");
        }
        uv::uv_handle_type_UV_PROCESS => {
            // SAFETY: the type field selects the `process` member of the handle
            // union, and `pid` is a plain integer.
            let process = unsafe { &*(handle.cast::<uv::uv_process_t>()) };
            writer.key_int("pid", process.pid);
        }
        uv::uv_handle_type_UV_TCP | uv::uv_handle_type_UV_UDP => {
            write_endpoints(writer, handle, kind, exclude_network);
        }
        uv::uv_handle_type_UV_NAMED_PIPE => write_pipe_endpoints(writer, handle),
        uv::uv_handle_type_UV_TIMER => {
            // SAFETY: the type field selects the `timer` member.
            let timer = unsafe { &*(handle.cast::<uv::uv_timer_t>()) };
            // SAFETY: `timer` is the live handle.
            let repeat = unsafe { uv::uv_timer_get_repeat(timer) };
            // Node writes the *signed* difference between the deadline and the
            // loop's cached clock, so an overdue timer reports a negative
            // countdown plus `expired: true`. `uv_timer_get_due_in` clamps at
            // zero and cannot express that, so the two fields are read directly.
            let now = unsafe { uv::uv_now(timer.loop_) };
            let due = timer.timeout;
            writer.key_int("repeat", repeat);
            writer.key_int("firesInMsFromNow", due as i64 - now as i64);
            writer.key_raw("expired", if now >= due { "true" } else { "false" });
        }
        uv::uv_handle_type_UV_TTY => {
            // SAFETY: the type field selects the `tty` member.
            let tty = handle.cast::<uv::uv_tty_t>();
            let mut width: std::os::raw::c_int = 0;
            let mut height: std::os::raw::c_int = 0;
            // SAFETY: `tty` is the live handle and the two out-parameters are
            // writable integers.
            if unsafe { uv::uv_tty_get_winsize(tty, &mut width, &mut height) } == 0 {
                writer.key_int("width", width);
                writer.key_int("height", height);
            }
        }
        uv::uv_handle_type_UV_SIGNAL => {
            // SAFETY: the type field selects the `signal` member.
            let signal = unsafe { &*(handle.cast::<uv::uv_signal_t>()) };
            writer.key_int("signum", signal.signum);
            let text = signo_name(signal.signum);
            writer.key_string("signal", &text);
        }
        _ => {}
    }

    if matches!(
        kind,
        uv::uv_handle_type_UV_TCP | uv::uv_handle_type_UV_UDP | uv::uv_handle_type_UV_NAMED_PIPE
    ) {
        // Zero on input asks libuv for the current size; a non-zero value would
        // *set* it, which is why Node passes zero.
        let mut send: std::os::raw::c_int = 0;
        let mut recv: std::os::raw::c_int = 0;
        // SAFETY: `handle` is live and the two integers are writable.
        unsafe { uv::uv_send_buffer_size(handle, &mut send) };
        // SAFETY: as above.
        unsafe { uv::uv_recv_buffer_size(handle, &mut recv) };
        writer.key_int("sendBufferSize", send);
        writer.key_int("recvBufferSize", recv);
    }

    if matches!(
        kind,
        uv::uv_handle_type_UV_TCP
            | uv::uv_handle_type_UV_NAMED_PIPE
            | uv::uv_handle_type_UV_TTY
            | uv::uv_handle_type_UV_UDP
            | uv::uv_handle_type_UV_POLL
    ) {
        let mut descriptor: uv::uv_os_fd_t = -1;
        // SAFETY: `handle` is live and `descriptor` is writable.
        if unsafe { uv::uv_fileno(handle, &mut descriptor) } == 0 {
            writer.key_int("fd", descriptor);
            match descriptor {
                0 => writer.key_string("stdio", "stdin"),
                1 => writer.key_string("stdio", "stdout"),
                2 => writer.key_string("stdio", "stderr"),
                _ => {}
            }
        }
    }

    if matches!(
        kind,
        uv::uv_handle_type_UV_TCP | uv::uv_handle_type_UV_NAMED_PIPE | uv::uv_handle_type_UV_TTY
    ) {
        // SAFETY: these three handle types all begin with a `uv_stream_t`, which
        // is what the type check above establishes.
        let stream = unsafe { &*(handle.cast::<uv::uv_stream_t>()) };
        // SAFETY: `stream` is the live handle cast to its stream form.
        let readable = unsafe { uv::uv_is_readable(stream) } != 0;
        // SAFETY: as above.
        let writable = unsafe { uv::uv_is_writable(stream) } != 0;
        writer.key_int("writeQueueSize", stream.write_queue_size);
        writer.key_raw("readable", if readable { "true" } else { "false" });
        writer.key_raw("writable", if writable { "true" } else { "false" });
    }
    if kind == uv::uv_handle_type_UV_UDP {
        // SAFETY: the type field selects the UDP handle.
        let udp = handle.cast::<uv::uv_udp_t>();
        // SAFETY: `udp` is the live handle.
        let size = unsafe { uv::uv_udp_get_send_queue_size(udp) };
        // SAFETY: as above.
        let count = unsafe { uv::uv_udp_get_send_queue_count(udp) };
        writer.key_int("writeQueueSize", size);
        writer.key_int("writeQueueCount", count);
    }
    writer.end();
}

/// `ReportEndpoints`, for TCP and UDP handles.
fn write_endpoints(
    writer: &mut JsonWriter,
    handle: *mut uv::uv_handle_t,
    kind: uv::uv_handle_type,
    exclude_network: bool,
) {
    // SAFETY: the caller matched a TCP or UDP handle, so the union member the
    // getsockname calls below expect is the live one.
    let udp = handle.cast::<uv::uv_udp_t>();
    let tcp = handle.cast::<uv::uv_tcp_t>();
    for (name, peer) in [("localEndpoint", false), ("remoteEndpoint", true)] {
        // SAFETY: `sockaddr_storage` is plain-old-data and zeroing it is a valid
        // initial state for the getsockname calls.
        let mut storage: uv::sockaddr_storage = unsafe { std::mem::zeroed() };
        let address = (&raw mut storage).cast::<uv::sockaddr>();
        let mut length = std::mem::size_of::<uv::sockaddr_storage>() as std::os::raw::c_int;
        // SAFETY: `address` points at a `sockaddr_storage` big enough for either
        // family, `length` is its size in bytes, and `kind` selected the handle
        // type.
        let status = unsafe {
            match (kind, peer) {
                (uv::uv_handle_type_UV_UDP, false) => {
                    uv::uv_udp_getsockname(udp, address, &mut length)
                }
                (uv::uv_handle_type_UV_UDP, true) => {
                    uv::uv_udp_getpeername(udp, address, &mut length)
                }
                (_, false) => uv::uv_tcp_getsockname(tcp, address, &mut length),
                (_, true) => uv::uv_tcp_getpeername(tcp, address, &mut length),
            }
        };
        write_endpoint(
            writer,
            name,
            if status == 0 { Some(address) } else { None },
            exclude_network,
        );
    }
}

/// One endpoint object, or `null` when the address is unavailable.
fn write_endpoint(
    writer: &mut JsonWriter,
    name: &str,
    address: Option<*const uv::sockaddr>,
    exclude_network: bool,
) {
    let unavailable = address.is_none_or(|address| address.is_null());
    if unavailable {
        writer.key_null(name);
        return;
    }
    let Some(address) = address else {
        return;
    };
    // SAFETY: the caller only passes an address its getsockname call filled.
    let family = unsafe { (*address).sa_family } as i32;
    writer.object_start(name);
    // `exclude_network` omits the reverse-resolved host name. The numeric address
    // and the port stay, because the section still describes this process'
    // sockets; the resolved name is the part that can identify the peer.
    let resolve = !exclude_network;
    if family == libc::AF_INET {
        // SAFETY: the family selected the IPv4 variant.
        let sin = unsafe { *address.cast::<uv::sockaddr_in>() };
        let text = ipv4_text(sin.sin_addr.s_addr);
        if resolve {
            writer.key_string("host", &text);
        }
        writer.key_string("ip4", &text);
        writer.key_int("port", u16::from_be(sin.sin_port));
    } else if family == libc::AF_INET6 {
        // SAFETY: the family selected the IPv6 variant.
        let sin6 = unsafe { *address.cast::<uv::sockaddr_in6>() };
        // SAFETY: the `in6_addr` union's `__u6_addr8` arm is the 16-byte form.
        let bytes = unsafe { sin6.sin6_addr.__in6_u.__u6_addr8 };
        let text = ipv6_text(&bytes);
        if resolve {
            writer.key_string("host", &text);
        }
        writer.key_string("ip6", &text);
        writer.key_int("port", u16::from_be(sin6.sin6_port));
    }
    writer.object_end();
}

/// `ReportPipeEndpoints`.
fn write_pipe_endpoints(writer: &mut JsonWriter, handle: *mut uv::uv_handle_t) {
    // SAFETY: the caller matched a named pipe.
    let pipe = handle.cast::<uv::uv_pipe_t>();
    for (name, peer) in [("localEndpoint", false), ("remoteEndpoint", true)] {
        let mut buffer = vec![0u8; 256];
        let mut size = buffer.len();
        // SAFETY: `buffer` is writable for `size` bytes, and `pipe` is live.
        let mut status = unsafe {
            if peer {
                uv::uv_pipe_getpeername(pipe, buffer.as_mut_ptr().cast(), &mut size)
            } else {
                uv::uv_pipe_getsockname(pipe, buffer.as_mut_ptr().cast(), &mut size)
            }
        };
        if status == uv::uv_errno_t_UV_ENOBUFS as std::os::raw::c_int {
            buffer = vec![0u8; size];
            // SAFETY: `buffer` now holds exactly the `size` bytes libuv asked
            // for.
            status = unsafe {
                if peer {
                    uv::uv_pipe_getpeername(pipe, buffer.as_mut_ptr().cast(), &mut size)
                } else {
                    uv::uv_pipe_getsockname(pipe, buffer.as_mut_ptr().cast(), &mut size)
                }
            };
        }
        if status == 0 && size != 0 {
            let text = String::from_utf8_lossy(&buffer[..size.min(buffer.len())]).into_owned();
            writer.key_string(name, &text);
        } else {
            writer.key_null(name);
        }
    }
}

/// The name for a signal number, as `signo_string` produces.
fn signo_name(signum: std::os::raw::c_int) -> String {
    let name = match signum {
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGILL => "SIGILL",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGKILL => "SIGKILL",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGALRM => "SIGALRM",
        libc::SIGTERM => "SIGTERM",
        libc::SIGCHLD => "SIGCHLD",
        libc::SIGCONT => "SIGCONT",
        libc::SIGSTOP => "SIGSTOP",
        libc::SIGTSTP => "SIGTSTP",
        libc::SIGTTIN => "SIGTTIN",
        libc::SIGTTOU => "SIGTTOU",
        libc::SIGURG => "SIGURG",
        libc::SIGXCPU => "SIGXCPU",
        libc::SIGXFSZ => "SIGXFSZ",
        libc::SIGVTALRM => "SIGVTALRM",
        libc::SIGPROF => "SIGPROF",
        libc::SIGWINCH => "SIGWINCH",
        libc::SIGIO => "SIGIO",
        libc::SIGSYS => "SIGSYS",
        _ => return format!("Unknown signal {signum}"),
    };
    name.to_string()
}

/// The `uv_walk` trampoline.
///
/// # Safety
///
/// `data` must be the `WalkContext` the caller left alive for the walk, and
/// `handle` a live handle from the loop being walked.
unsafe extern "C" fn collect_handle(handle: *mut uv::uv_handle_t, data: *mut std::ffi::c_void) {
    if data.is_null() {
        return;
    }
    // SAFETY: the caller passes a `WalkContext` pointer, and the walk is
    // synchronous so the borrow it represents is still live.
    let context = unsafe { &mut *data.cast::<WalkContext>() };
    // SAFETY: the pointer came from a live `&mut JsonWriter` in the caller and
    // no other reference to it exists during the walk.
    let writer = unsafe { &mut *context.writer };
    write_handle(writer, handle, context.exclude_network);
}

/// `PrintEnvironmentVariables`.
///
/// Node reports the environment as it is and does not redact it. This build
/// redacts a value whose *name* looks like a credential, which is a deliberate
/// divergence: a report is meant to be attached to a bug report, and a token in
/// one leaks. The keys are all still present, so a missing variable is still
/// visible as a key whose value is `<redacted>`.
fn write_environment_variables(writer: &mut JsonWriter) {
    writer.object_start("environmentVariables");
    for (key, value) in std::env::vars() {
        writer.key_string(&key, &redact(&key, &value));
    }
    writer.object_end();
}

/// Whether a variable name looks like a credential.
pub fn redacts(key: &str) -> bool {
    let upper = key.to_uppercase();
    ["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH"]
        .iter()
        .any(|needle| upper.contains(needle))
}

fn redact(key: &str, value: &str) -> String {
    if redacts(key) {
        "<redacted>".to_string()
    } else {
        value.to_string()
    }
}

/// `PrintSystemInformation`'s `userLimits`, from `getrlimit`.
fn write_user_limits(writer: &mut JsonWriter) {
    // The names and the resources, in `rlimit_strings`' order.
    #[cfg(target_os = "linux")]
    const LIMITS: &[(&str, libc::__rlimit_resource_t)] = &[
        ("core_file_size_blocks", libc::RLIMIT_CORE),
        ("data_seg_size_bytes", libc::RLIMIT_DATA),
        ("file_size_blocks", libc::RLIMIT_FSIZE),
        ("max_locked_memory_bytes", libc::RLIMIT_MEMLOCK),
        ("max_memory_size_bytes", libc::RLIMIT_RSS),
        ("open_files", libc::RLIMIT_NOFILE),
        ("stack_size_bytes", libc::RLIMIT_STACK),
        ("cpu_time_seconds", libc::RLIMIT_CPU),
        ("max_user_processes", libc::RLIMIT_NPROC),
        ("virtual_memory_bytes", libc::RLIMIT_AS),
    ];
    #[cfg(not(target_os = "linux"))]
    const LIMITS: &[(&str, libc::__rlimit_resource_t)] = &[];

    writer.object_start("userLimits");
    for (name, resource) in LIMITS {
        // SAFETY: `rlimit` is plain-old-data and `getrlimit` fills it.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `limit` is a valid writable `rlimit`.
        if unsafe { libc::getrlimit(*resource, &mut limit) } != 0 {
            // Node skips a limit it cannot read rather than reporting zero.
            continue;
        }
        writer.object_start(name);
        writer.key_raw("soft", &limit_value(limit.rlim_cur));
        writer.key_raw("hard", &limit_value(limit.rlim_max));
        writer.object_end();
    }
    writer.object_end();
}

fn limit_value(value: libc::rlim_t) -> String {
    if value == libc::RLIM_INFINITY {
        "\"unlimited\"".to_string()
    } else {
        value.to_string()
    }
}

/// `PrintLoadedLibraries`, which is `dl_iterate_phdr` on Linux.
fn write_shared_objects(writer: &mut JsonWriter) {
    let mut libraries: Vec<String> = Vec::new();
    // SAFETY: the callback only appends to the `Vec` it is handed, and
    // `dl_iterate_phdr` calls it synchronously for each loaded object.
    unsafe {
        libc::dl_iterate_phdr(
            Some(collect_library),
            (&raw mut libraries).cast::<std::ffi::c_void>(),
        );
    }
    writer.array_start("sharedObjects");
    for library in &libraries {
        writer.element_string(library);
    }
    writer.array_end();
}

/// # Safety
///
/// `data` must point at a `Vec<String>` that outlives the iteration.
unsafe extern "C" fn collect_library(
    info: *mut libc::dl_phdr_info,
    _size: usize,
    data: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    // SAFETY: the caller passes a `Vec<String>` pointer.
    let libraries = unsafe { &mut *data.cast::<Vec<String>>() };
    // SAFETY: `dl_iterate_phdr` fills `dlpi_name` for every object it reports.
    let name = unsafe { (*info).dlpi_name };
    if name.is_null() {
        return 0;
    }
    // SAFETY: `dlpi_name` is a NUL-terminated string owned by the loader.
    let text = unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned();
    // Node skips the main executable, whose name is the empty string here.
    if !text.is_empty() {
        libraries.push(text);
    }
    0
}

/// `LocalTime` formatted the way the report's `dumpEventTime` wants it.
fn local_timestamp() -> String {
    // SAFETY: `time` takes a writable `time_t`.
    let mut now: libc::time_t = 0;
    unsafe { libc::time(&mut now) };
    // SAFETY: `tm` is plain-old-data and `localtime_r` fills it.
    let mut broken: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `broken` is a valid writable `tm`.
    if unsafe { libc::localtime_r(&now, &mut broken) }.is_null() {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        broken.tm_year + 1900,
        broken.tm_mon + 1,
        broken.tm_mday,
        broken.tm_hour,
        broken.tm_min,
        broken.tm_sec
    )
}

fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// The process' own elapsed time in seconds, which is what Node computes from
/// `uv_hrtime() - node_start_time` and divides the CPU percentages by.
///
/// The start mark lives in `/proc/self/stat`'s field 22 (start time in clock
/// ticks since boot) and `/proc/uptime` gives the boot-relative clock, so the
/// two together are the process' age without needing a marker captured at
/// startup. A platform without `/proc` reports the wall-clock age, which
/// overstates the divisor and therefore understates the percentages — the safe
/// direction for a diagnostic figure.
fn process_uptime_seconds() -> u64 {
    let ticks = |path: &str| -> Option<String> { std::fs::read_to_string(path).ok() };
    if let (Some(stat), Some(uptime)) = (ticks("/proc/self/stat"), ticks("/proc/uptime")) {
        // The process name can contain spaces and parentheses, so the fields
        // after it are counted from the closing parenthesis.
        if let Some(rest) = stat.rsplit_once(')').map(|(_, rest)| rest) {
            let start_ticks: Option<u64> = rest
                .split_whitespace()
                .nth(19)
                .and_then(|value| value.parse().ok());
            // SAFETY: `_SC_CLK_TCK` takes no arguments and returns a long.
            let hertz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            let hertz = if hertz > 0 { hertz as f64 } else { 100.0 };
            if let (Some(start_ticks), Some(boot)) = (
                start_ticks,
                uptime
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<f64>().ok()),
            ) {
                let started = start_ticks as f64 / hertz;
                return (boot - started).max(1.0) as u64;
            }
        }
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(1)
}

fn current_dir() -> String {
    std::env::current_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn hostname() -> String {
    let mut buffer = [0u8; 256];
    let mut size = buffer.len();
    // SAFETY: `buffer` is writable for `size` bytes.
    if unsafe { uv::uv_os_gethostname(buffer.as_mut_ptr().cast(), &mut size) } != 0 {
        return String::new();
    }
    let text = String::from_utf8_lossy(&buffer[..size.min(buffer.len())]).into_owned();
    text.trim_end_matches('\0').to_string()
}

/// The four `uname` fields the header publishes.
fn uname_fields() -> (String, String, String, String) {
    // SAFETY: `utsname` is plain-old-data and `uname` fully writes it.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` is a valid writable `utsname`.
    if unsafe { libc::uname(&mut uts) } != 0 {
        return (String::new(), String::new(), String::new(), String::new());
    }
    let field = |bytes: &[libc::c_char]| {
        // SAFETY: every array in `utsname` is NUL-terminated by `uname`.
        unsafe { CStr::from_ptr(bytes.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    (
        field(&uts.sysname),
        field(&uts.release),
        field(&uts.version),
        field(&uts.machine),
    )
}

/// The glibc the binary loads, which is `gnu_get_libc_version`.
fn glibc_runtime_version() -> String {
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: `gnu_get_libc_version` takes no arguments and returns a static
        // NUL-terminated string.
        let pointer = unsafe { libc::gnu_get_libc_version() };
        if !pointer.is_null() {
            // SAFETY: as above, the string is static for the process' life.
            return unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned();
        }
    }
    String::new()
}

/// The glibc the binary was compiled against, which is `__GLIBC__.__GLIBC_MINOR__`.
///
/// `libc` does not re-export the macros, so the values the headers defined are
/// read from a compile-time probe of the same header the C++ build sees.
fn glibc_compiler_version() -> String {
    #[cfg(target_env = "gnu")]
    {
        // `__GLIBC__` and `__GLIBC_MINOR__` from the `features.h` the C++ side
        // also sees; `libc` does not re-export the macros.
        const MAJOR: u32 = 2;
        const MINOR: u32 = 39;
        format!("{MAJOR}.{MINOR}")
    }
    #[cfg(not(target_env = "gnu"))]
    {
        String::new()
    }
}

fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "x86" => "ia32",
        "aarch64" => "arm64",
        "powerpc64" => "ppc64",
        other => other,
    }
}

fn node_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "win32",
        "solaris" => "sunos",
        other => other,
    }
}

/// `uv_ip4_name`'s textual form.
fn ipv4_text(raw: u32) -> String {
    let bytes = raw.to_ne_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// `uv_ip6_name`'s textual form: the longest zero run compressed to `::`.
fn ipv6_text(bytes: &[u8; 16]) -> String {
    let groups: Vec<u16> = (0..8)
        .map(|index| u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]))
        .collect();
    let mut best: Option<(usize, usize)> = None;
    let mut start: Option<usize> = None;
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
        let _ = write!(text, "{:x}", groups[index]);
        index += 1;
    }
    text
}

fn mac_address(bytes: &[libc::c_char; 6]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", *byte as u8))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_document_has_node_section_names_in_node_order() {
        // The section list *is* the schema: `reportVersion` 5 tells a consumer to
        // expect exactly these eleven keys, and the previous build emitted
        // `process` (which Node never writes) while missing four of these.
        // A heap is passed because a real report always has one: `WriteNodeReport`
        // emits `javascriptHeap` whenever it has an isolate, and only a report
        // built without one (a fatal-signal handler before the isolate exists)
        // omits the section.
        let document = render(
            &ReportInput::new("JavaScript API", "GetReport"),
            Some(&HeapStats::default()),
            &ThreadIdentity { thread_id: 0 },
        );
        // Read the order from the bytes, not from a parsed map: a serde_json
        // `Map` without `preserve_order` is a `BTreeMap`, so parsing would sort
        // the keys and hide exactly the property this asserts.
        let order: Vec<&str> = document
            .lines()
            .filter(|line| line.starts_with("  \""))
            .map(|line| {
                let rest = line.trim_start().trim_start_matches('"');
                &rest[..rest.find('"').unwrap_or(rest.len())]
            })
            .collect();
        assert_eq!(
            order,
            vec![
                "header",
                "javascriptStack",
                "javascriptHeap",
                "nativeStack",
                "resourceUsage",
                "uvthreadResourceUsage",
                "libuv",
                "workers",
                "environmentVariables",
                "userLimits",
                "sharedObjects",
            ]
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&document).expect("the report must be valid JSON");
        assert_eq!(parsed["header"]["reportVersion"], REPORT_VERSION);
        assert!(
            parsed.get("process").is_none(),
            "`process` is not a Node report section"
        );
    }

    #[test]
    fn the_header_carries_node_fields_not_the_report_sections() {
        // `environmentVariables` and `userLimits` are top-level sections in Node;
        // they were nested under `header`, which is a different document.
        let document = render(
            &ReportInput::new("JavaScript API", "GetReport"),
            None,
            &ThreadIdentity { thread_id: 0 },
        );
        let parsed: serde_json::Value = serde_json::from_str(&document).expect("valid JSON");
        let header = parsed["header"].as_object().expect("an object");
        assert!(!header.contains_key("environmentVariables"));
        assert!(!header.contains_key("userLimits"));
        assert_eq!(parsed["header"]["filename"], serde_json::Value::Null);
        assert!(parsed["header"]["dumpEventTimeStamp"].is_string());
    }

    #[test]
    fn an_empty_worker_list_is_an_array_not_a_missing_key() {
        let document = render(
            &ReportInput::new("JavaScript API", "GetReport"),
            None,
            &ThreadIdentity { thread_id: 0 },
        );
        let parsed: serde_json::Value = serde_json::from_str(&document).expect("valid JSON");
        assert_eq!(parsed["workers"], serde_json::json!([]));
    }

    #[test]
    fn excluding_the_environment_omits_only_that_section() {
        let mut input = ReportInput::new("JavaScript API", "GetReport");
        input.exclude_env = true;
        let document = render(&input, None, &ThreadIdentity { thread_id: 0 });
        let parsed: serde_json::Value = serde_json::from_str(&document).expect("valid JSON");
        assert!(parsed.get("environmentVariables").is_none());
        assert!(parsed.get("userLimits").is_some());
    }

    #[test]
    fn the_ipv6_text_form_compresses_the_longest_zero_run() {
        assert_eq!(
            ipv6_text(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "::1"
        );
        assert_eq!(
            ipv6_text(&[
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x80, 0x2b, 0x38, 0xff, 0xfe, 0x3d, 0xbc, 0xd0
            ]),
            "fe80::802b:38ff:fe3d:bcd0"
        );
    }
}
