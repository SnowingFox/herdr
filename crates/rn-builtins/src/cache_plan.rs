//! Which builtins get a code cache.
//!
//! This is the set an *empty* script compiles, nothing more. It was taken from a
//! real startup rather than from a reading of `lib/**`, and `rn-builtins`' tests
//! assert it still matches what the bootstrap loads: a builtin that joins the
//! startup path without joining this list fails that test, so the plan cannot
//! quietly fall behind and silently lose its cache.
//!
//! `require('fs')` and the other module cases compile a handful more than an
//! empty run does. Those are left out deliberately: they are not startup cost,
//! and keeping the plan to what an empty run needs is what holds the embedded
//! table to roughly half a mebibyte.
//!
//! Nothing here is a correctness boundary. A builtin missing from this list is
//! compiled from source, exactly as it was before the cache existed.

/// Builtins compiled by an empty run, and therefore worth caching.
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
];
