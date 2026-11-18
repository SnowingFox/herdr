//! Which builtins get a code cache.
//!
//! This is the set an *empty* script compiles, plus the set the first
//! `process.stdout` read compiles. The first group was taken from a real startup
//! rather than from a reading of `lib/**`. The second is not optional startup
//! work in the same sense, but it is *unavoidable* startup work for any script
//! that prints, which is nearly every real script and every benchmark case:
//! `process.stdout` is a lazy getter whose first read builds a `net.Socket`, and
//! `net.js` plus the `stream` stack it pulls in is about 4 ms of parse with no
//! cache at all. Leaving them out made `console.log(1)` cost more in the user
//! script phase than any bootstrap phase, so they belong here.
//!
//! Nothing here is a correctness boundary. A builtin missing from this list is
//! compiled from source, exactly as it was before the cache existed.
//!
//! # Keeping this honest
//!
//! `crates/rn-cli/tests/stdio_cache_plan.rs` runs the real binary and fails when
//! a builtin either script compiles is absent from this list, so the second
//! group cannot fall behind `lib/**` silently. Adding to this list costs build
//! time and embedded size only; it never changes what a script observes.

/// Builtins compiled by an empty run, or by the first stdio stream.
pub const CACHED_BUILTINS: &[&str] = &[
    "async_hooks",
    "buffer",
    "diagnostics_channel",
    "events",
    "fs",
    "internal/assert",
    "internal/async_context_frame",
    "internal/async_hooks",
    "internal/bootstrap/realm",
    "internal/bootstrap/switches/does_own_process_state",
    "internal/bootstrap/switches/is_main_thread",
    "internal/buffer",
    "internal/console/constructor",
    "internal/console/global",
    "internal/constants",
    "internal/encoding",
    "internal/encoding/single-byte",
    "internal/encoding/util",
    "internal/errors",
    "internal/event_target",
    "internal/events/abort_listener",
    "internal/fixed_queue",
    "internal/fs/utils",
    "internal/inspector_async_hook",
    "internal/linkedlist",
    "internal/modules/cjs/loader",
    "internal/modules/customization_hooks",
    "internal/modules/esm/get_format",
    "internal/modules/esm/utils",
    "internal/modules/helpers",
    "internal/modules/package_json_reader",
    "internal/modules/package_map",
    "internal/modules/run_main",
    "internal/options",
    "internal/per_context/messageport",
    "internal/per_context/primordials",
    "internal/perf/utils",
    "internal/priority_queue",
    "internal/process/execution",
    "internal/process/finalization",
    "internal/process/per_thread",
    "internal/process/permission",
    "internal/process/pre_execution",
    "internal/process/promises",
    "internal/process/signal",
    "internal/process/task_queues",
    "internal/process/warning",
    "internal/querystring",
    "internal/source_map/source_map_cache",
    "internal/streams/utils",
    "internal/timers",
    "internal/trace_events",
    "internal/url",
    "internal/util",
    "internal/util/debuglog",
    "internal/util/inspect",
    "internal/util/inspector",
    "internal/util/types",
    "internal/v8/startup_snapshot",
    "internal/validators",
    "internal/vm",
    "internal/webidl",
    "internal/worker/js_transferable",
    "path",
    "querystring",
    "timers",
    "util",
    "util/types",
    // The stdio stream. `process.stdout` and `process.stderr` are lazy getters
    // that build a `net.Socket` on first read, so this set is what any script
    // that writes pays before its first byte. `internal/tty` and
    // `internal/util/colors` are here because a pty and a `console.log` are the
    // other two ways the same read happens; `internal/fs/sync_write_stream` is
    // the FILE case. Order follows the load order `net` produces.
    "stream",
    "internal/streams/state",
    "internal/streams/destroy",
    "internal/streams/end-of-stream",
    "internal/streams/legacy",
    "internal/streams/add-abort-signal",
    "internal/streams/readable",
    "string_decoder",
    "internal/streams/from",
    "internal/streams/writable",
    "internal/streams/duplex",
    "internal/net",
    "internal/stream_base_commons",
    "internal/perf/observe",
    "internal/perf/performance_entry",
    "net",
    "internal/tty",
    "internal/fs/sync_write_stream",
    "internal/util/colors",
    // The ES module graph, reached because `-e`, stdin, `--check` and
    // `--input-type` all run through Node's own `internal/main/**` scripts and
    // `prepareMainThreadExecution` initialises the module loaders. It is the
    // same load order the loader itself produces.
    "module",
    "internal/modules/esm/assert",
    "internal/modules/esm/load",
    "internal/modules/esm/loader",
    "internal/modules/esm/module_job",
    "internal/modules/esm/module_map",
    "internal/modules/esm/resolve",
    "internal/modules/esm/translators",
    "internal/modules/typescript",
    "internal/source_map/source_map",
    "internal/vm/module",
];
