//! `internalBinding('heap_utils')` for rustnode.
//!
//! `lib/v8.js` loads this namespace at module scope, so `require('v8')` — and
//! therefore a large part of the test suite — fails outright without it. Three
//! members exist on the namespace, and all three are implemented here.
//!
//! This crate also registers `internalBinding('internal_only_v8')`, the one-member
//! namespace `v8.queryObjects()` is built on. Both live here because
//! `lib/internal/heap_utils.js` is the single module that destructures members of
//! either, so a caller loading one loads the other.
//!
//! # `triggerHeapSnapshot(filename, options)` — implemented
//!
//! `src/heap_utils.cc`'s `TriggerHeapSnapshot` takes a V8 heap snapshot and
//! writes it to `filename`, returning the path. `WriteSnapshot` opens the file
//! with `O_WRONLY | O_CREAT | O_TRUNC` and `0600`, streams V8's JSON
//! serialization into it, and closes. V8's `Isolate::take_heap_snapshot` is the
//! same streaming API, so this reproduces the behaviour rather than approximating
//! it: the bytes written are V8's own JSON, and a `.heapsnapshot` file from here
//! loads in DevTools.
//!
//! `options` is the `Uint8Array([+exposeInternals, +exposeNumericValues])`
//! `internal/heap_utils.js`'s `getHeapSnapshotOptions` builds. It is passed
//! through to V8's `TakeHeapSnapshot(options)` rather than dropped, which the
//! `v8` crate's own binding cannot do; see `rn_v8_sys::take_heap_snapshot`.
//!
//! On this V8 the two flags change nothing, and that is measured rather than
//! assumed: the pinned build's `HeapProfiler::TakeSnapshot` forwards only
//! `control`, `context_name_resolver` and `stack_state` into the generator, and
//! `grep -rn 'snapshot_mode\|numerics_mode' src/` over its tree finds no read of
//! either field outside the assignments that set them. So a regular snapshot
//! already contains the `exposeInternals` node and already labels numeric values
//! with `numeric` edges, which is why both option cases of
//! `test/common/heap.js`'s `getHeapSnapshotOptionTests` pass here with or
//! without the flags. The plumbing is what makes that a property of the options
//! rather than an accident of the crate's binding, and it is what will start
//! mattering if V8 begins honouring the fields.
//!
//! # `createHeapSnapshotStream(options)` — implemented
//!
//! Returns the readable handle `lib/v8.js`'s `getHeapSnapshot()` wraps in
//! `internal/heap_utils.js`'s `HeapSnapshotStream`, a `Readable`. The handle is
//! the `AsyncWrap` + `StreamBase` surface `onStreamRead` drives: `readStart`
//! pushes the snapshot through `onread` in 64 KiB chunks and then reports
//! `UV_EOF`. See [`stream`] for what is reproduced and what is deliberately not.
//!
//! # `buildEmbedderGraph(...values)` — implemented
//!
//! `src/heap_utils.cc:BuildEmbedderGraph` walks Node's `BaseObject` tree into a
//! `JSGraph` and then, for each argument, asks the graph for that value's node.
//! rustnode has no `BaseObject` tree to walk and no `Environment`, so what is
//! reproduced is the part the binding's own comment calls its reason for
//! existing: "include supplied values so tests can verify that JSGraph returns
//! one graph node for each distinct V8 value". Each distinct argument gets one
//! node carrying `value`, and repeat arguments collapse onto the first — the
//! same `SameValue` deduplication `JSGraphJSNode::IsSame` performs.
//!
//! The nodes carry `name`, `isRoot`, `size` and an empty `edges` array like
//! Node's, and no `wraps` edge, because a value that is its own wrapper has
//! nothing to point at. See [`build_embedder_graph`].

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub mod stream;

/// Members exposed on the namespace object, matching
/// `contracts/heap_utils.json`.
pub const MEMBERS: &[&str] = &[
    "buildEmbedderGraph",
    "createHeapSnapshotStream",
    "triggerHeapSnapshot",
];

/// Members this build does not implement, each with the reason.
///
/// `rn-compat` reports a declared deferral as a pass and an undeclared gap as a
/// failure, so these are visible rather than silent. Empty: all three contract
/// members are installed.
pub const DEFERRED: &[(&str, &str)] = &[];

pub struct HeapUtils;

impl BindingModule for HeapUtils {
    fn namespace(&self) -> &'static str {
        "heap_utils"
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
        let object = v8::Object::new(scope);
        // `lib/internal/stream_base_commons.js` reads this shared array, so a
        // snapshot stream has to have created it before `onStreamRead` runs.
        // `stream_wrap` normally creates it on install; doing it here as well
        // keeps `heap_utils` usable on its own.
        rn_uv::stream::state_array(scope);

        let constructor = stream::constructor(scope)?;
        let function = v8::Local::<v8::Function>::try_from(constructor)
            .map_err(|_| "the HeapSnapshotStream constructor is not a function".to_string())?;
        stream::remember_constructor(scope, function);

        install_function(scope, object, "buildEmbedderGraph", build_embedder_graph)?;
        install_function(
            scope,
            object,
            "createHeapSnapshotStream",
            create_heap_snapshot_stream,
        )?;
        install_function(scope, object, "triggerHeapSnapshot", trigger_heap_snapshot)?;
        Ok(object)
    }
}

/// Installs one native member on the namespace object.
fn install_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    rn_core::set_method(scope, object, name, callback)?;
    Ok(())
}

/// `buildEmbedderGraph(...values)`: one graph node per distinct argument.
///
/// `src/heap_utils.cc:211` is the shape this follows, minus the `BaseObject`
/// walk. It builds a `JSGraph`, hands it to
/// `Environment::BuildEmbedderGraph` — which tracks the `Environment` and every
/// retainer reachable from it — and then calls `graph.V8Node(args[i])` once per
/// argument. `JSGraph::CreateObject` turns the result into an `Array` of plain
/// objects with `name`, `isRoot`, `size`, `edges`, and, for a node that is not
/// an embedder node, `value`.
///
/// The walk is what rustnode cannot do: `Environment` and the `BaseObject`
/// hierarchy it owns do not exist here, and the graph V8 offers has no embedder
/// nodes because rustnode registers no build callback. The arguments, though,
/// are ordinary V8 values, and that is the whole of what the binding's own
/// comment says it adds them for. So this returns exactly the nodes
/// `graph.V8Node` would have produced for them: one per distinct value, each
/// with `value` set and `isRoot` false.
///
/// A repeated argument collapses onto the first occurrence because
/// `JSGraphJSNode::IsSame` compares with `Value::SameValue`, which is what
/// `Object.is` means: `NaN` matches itself, `0` and `-0` do not, and a BigInt
/// matches only the same BigInt value. `Value::same_value` is that exact call,
/// so `sameBigint` above collapses onto `bigint` while two distinct `{}` stay
/// apart.
///
/// # Why `edges` is always empty and `wraps` never appears
///
/// `CreateObject` sets `wraps` only for a node whose `WrapperNode()` is not
/// null, and `AddEdge` is only called by the `MemoryTracker` walk this does not
/// run. A value that is its own wrapper — every argument here, since none of
/// them is an embedder node with a JS wrapper — has nothing else to point at.
///
/// # Why `name` is `"<JS Node>"`
///
/// `JSGraphJSNode::Name()` returns that literal for every value node, and it is
/// what `CreateObject` writes into `name` when `NamePrefix()` is null. It is not
/// the value's class name: `node.name` is a snapshot-node name, and a heap
/// snapshot's own JS object nodes get their name from the map instead.
fn build_embedder_graph(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    /// `JSGraphJSNode::Name()`, the literal `CreateObject` copies into `name`.
    const NODE_NAME: &str = "<JS Node>";

    let Some(name) = v8::String::new(scope, NODE_NAME) else {
        throw_error(scope, "buildEmbedderGraph: cannot allocate the node name");
        return;
    };
    let Some(edges_key) = v8::String::new(scope, "edges") else {
        throw_error(scope, "buildEmbedderGraph: cannot allocate a property key");
        return;
    };
    let Some(name_key) = v8::String::new(scope, "name") else {
        throw_error(scope, "buildEmbedderGraph: cannot allocate a property key");
        return;
    };
    let Some(value_key) = v8::String::new(scope, "value") else {
        throw_error(scope, "buildEmbedderGraph: cannot allocate a property key");
        return;
    };
    let Some(root_key) = v8::String::new(scope, "isRoot") else {
        throw_error(scope, "buildEmbedderGraph: cannot allocate a property key");
        return;
    };
    let Some(size_key) = v8::String::new(scope, "size") else {
        throw_error(scope, "buildEmbedderGraph: cannot allocate a property key");
        return;
    };

    let array = v8::Array::new(scope, 0);
    // The values already emitted, in argument order. Linear for the same reason
    // `JSGraph` is: the list is the arguments of one call, and the test that
    // exercises it passes five.
    let mut emitted: Vec<v8::Local<'_, v8::Value>> = Vec::new();
    // `CreateObject`'s `size_t i`, which is separate from the argument index: a
    // duplicate argument produces no node, so indexing the array by argument
    // would leave a hole.
    let mut next_slot: u32 = 0;

    for index in 0..args.length() {
        let value = args.get(index);
        if emitted.iter().any(|seen| seen.same_value(value)) {
            continue;
        }

        let node = v8::Object::new(scope);
        // `CreateObject`: name, isRoot, size, edges, then value for a non-embedder
        // node. `size` is `SizeInBytes()`, which `JSGraphJSNode` reports as 0.
        let written = node.set(scope, name_key.into(), name.into()).is_some()
            && node
                .set(scope, root_key.into(), v8::Boolean::new(scope, false).into())
                .is_some()
            // `Number::New(isolate, 0)`: a plain `0`, not `-0` or a NaN box.
            && node
                .set(scope, size_key.into(), v8::Number::new(scope, 0.0).into())
                .is_some()
            && node
                .set(scope, edges_key.into(), v8::Array::new(scope, 0).into())
                .is_some()
            && node.set(scope, value_key.into(), value).is_some();
        if !written {
            throw_error(scope, "buildEmbedderGraph: cannot build a graph node");
            return;
        }
        // `nodes->Set(context, i++, obj)`; it appends past the initial length,
        // which `Array::new(scope, 0)` leaves empty.
        if array.set_index(scope, next_slot, node.into()).is_none() {
            throw_error(scope, "buildEmbedderGraph: cannot append a graph node");
            return;
        }
        next_slot += 1;
        emitted.push(value);
    }

    rv.set(array.into())
}

/// `createHeapSnapshotStream(options)`.
///
/// `options` is `getHeapSnapshotOptions`' `Uint8Array([exposeInternals,
/// exposeNumericValues])`, forwarded to V8 through
/// [`rn_v8_sys::take_heap_snapshot`] rather than V8's no-argument default.
///
/// A failure to allocate the stream throws instead of returning `undefined`:
/// `lib/v8.js`'s `getHeapSnapshot` asserts the handle is truthy, and an
/// assertion failure there would name the wrong problem.
fn create_heap_snapshot_stream(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let options = snapshot_options(scope, args.get(0));

    // One buffer, appended in order. The snapshot is serialized in consecutive
    // chunks of a single JSON document, and `try_reserve` keeps a huge snapshot
    // from aborting the process on allocation failure: aborting the snapshot
    // (`false`) is the contract's own way to stop, and the empty result is
    // reported as the failure it is.
    let mut bytes: Vec<u8> = Vec::new();
    let snapshot = with_snapshot_isolate(|isolate| {
        // SAFETY: see `with_snapshot_isolate`: the handle is this thread's live
        // isolate and the callback is synchronous.
        unsafe {
            rn_v8_sys::take_heap_snapshot(isolate, options, |chunk| {
                match bytes.try_reserve(chunk.len()) {
                    Ok(()) => {
                        bytes.extend_from_slice(chunk);
                        true
                    }
                    Err(_) => false,
                }
            })
        }
    });
    match snapshot {
        None => {
            throw_error(
                scope,
                "createHeapSnapshotStream ran before the isolate was recorded",
            );
            return;
        }
        Some(Err(reason)) => {
            throw_error(scope, &format!("createHeapSnapshotStream: {reason}"));
            return;
        }
        Some(Ok(())) => {}
    }

    let Some(constructor) = stream::constructor_for(scope) else {
        throw_error(
            scope,
            "createHeapSnapshotStream: the constructor is not installed",
        );
        return;
    };
    // A snapshot that produced no bytes is a failure, not an empty stream: V8
    // returns early on an allocation failure, and `lib/v8.js` would otherwise
    // hand back a `Readable` that ends immediately and parses as nothing.
    if bytes.is_empty() {
        throw_error(scope, "createHeapSnapshotStream: V8 produced no snapshot");
        return;
    }
    match stream::create(scope, constructor, bytes) {
        Some(object) => rv.set(object.into()),
        None => throw_error(
            scope,
            "createHeapSnapshotStream: cannot allocate the stream",
        ),
    }
}

/// `triggerHeapSnapshot(filename, options)`.
///
/// With `filename` undefined Node generates one from the date and the thread id
/// and returns it; with a filename it writes there and returns that same value.
/// Both paths are reproduced, because `v8.writeHeapSnapshot()` with no argument
/// is the documented call and the returned name is how a caller finds the file.
fn trigger_heap_snapshot(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let options = snapshot_options(scope, args.get(1));
    let filename = match args.get(0) {
        value if value.is_undefined() => diagnostic_filename("Heap", "heapsnapshot"),
        value => match value.to_string(scope) {
            Some(text) => text.to_rust_string_lossy(scope),
            None => {
                throw_type_error(scope, "heap snapshot filename must be a string");
                return;
            }
        },
    };

    // `O_WRONLY | O_CREAT | O_TRUNC` at `0600`, exactly as `WriteSnapshot` does.
    let mut options_file = std::fs::OpenOptions::new();
    options_file.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options_file.mode(0o600);
    }
    let mut file = match options_file.open(&filename) {
        Ok(file) => file,
        Err(error) => {
            throw_io_error(scope, &error, &filename);
            return;
        }
    };

    let mut write_error = None;
    // The snapshot is serialized in consecutive chunks of one JSON document, so
    // they are written in order. Returning `false` aborts the snapshot; there is
    // nothing useful to gain from a partial one, so a write failure is recorded
    // and the rest is dropped.
    let snapshot = with_snapshot_isolate(|isolate| {
        // SAFETY: see `with_snapshot_isolate`: the handle is this thread's live
        // isolate and the callback is synchronous.
        unsafe {
            rn_v8_sys::take_heap_snapshot(isolate, options, |chunk| {
                use std::io::Write;
                if write_error.is_some() {
                    return false;
                }
                match file.write_all(chunk) {
                    Ok(()) => true,
                    Err(error) => {
                        write_error = Some(error);
                        false
                    }
                }
            })
        }
    });
    match snapshot {
        None => {
            throw_error(
                scope,
                "triggerHeapSnapshot ran before the isolate was recorded",
            );
            return;
        }
        Some(Err(reason)) => {
            throw_error(scope, &format!("triggerHeapSnapshot: {reason}"));
            return;
        }
        Some(Ok(())) => {}
    }

    if let Some(error) = write_error {
        throw_io_error(scope, &error, &filename);
        return;
    }
    drop(file);

    match v8::String::new(scope, &filename) {
        Some(value) => rv.set(value.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// Reads `getHeapSnapshotOptions`' `Uint8Array([exposeInternals, numerics])`.
///
/// Node's `src/heap_utils.cc:GetHeapSnapshotOptions` `CHECK`s that the argument
/// is a `Uint8Array` and reads two bytes out of it; a non-array never reaches
/// there, because `lib/internal/heap_utils.js`'s `getHeapSnapshotOptions` always
/// builds one. So a malformed argument is treated as V8's default here rather
/// than thrown: this is the position of Node's `CHECK` (a crash guard), not an
/// input-validation point.
///
/// Public because `Worker.prototype.getHeapSnapshot(options)` takes the same
/// array: `lib/internal/worker.js:544` calls `getHeapSnapshotOptions` and passes
/// the result to `takeHeapSnapshot`, so both bindings have to read it the same
/// way.
#[must_use]
pub fn snapshot_options(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> rn_v8_sys::HeapSnapshotOptions {
    let Ok(array) = v8::Local::<v8::Array>::try_from(value) else {
        return rn_v8_sys::HeapSnapshotOptions::new();
    };
    let flag = |index: u32| -> bool {
        array
            .get_index(scope, index)
            .and_then(|item| item.uint32_value(scope))
            .is_some_and(|value| value != 0)
    };
    rn_v8_sys::HeapSnapshotOptions {
        expose_internals: flag(0),
        expose_numeric_values: flag(1),
    }
}

/// `DiagnosticFilename::MakeFilename`: `Heap.<yyyymmdd>.<hhmmss>.<pid>.<tid>.<seq>.<ext>`.
///
/// `MakeFilename` in `src/util.cc:247` writes the prefix, the local date, the
/// local time, the process id, the thread id, a zero-padded three-digit sequence
/// and the extension, dot-separated.
///
/// The thread id and the sequence are what keep two snapshots apart. A name of
/// `<date>.<time>.<pid>` collides whenever two snapshots are taken in the same
/// second, and the second silently overwrites the first — which is exactly what
/// `test/sequential/test-heapdump-flag.js` catches, because it raises SIGUSR2
/// twice in a row and expects two files. The sequence is process-wide rather
/// than per-thread, so two threads snapshotting in the same second also differ.
fn diagnostic_filename(prefix: &str, extension: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// `MakeFilename`'s `static unsigned int seq`, which starts at zero and is
    /// pre-incremented, so the first name ends in `001`.
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    // `LocalTime` in Node; UTC here because converting needs a timezone
    // database, and the name only has to be unique and sortable.
    let (year, month, day, hour, minute, second) = civil_from_unix(now);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
    format!(
        "{prefix}.{year:04}{month:02}{day:02}.{hour:02}{minute:02}{second:02}.{}.{}.{sequence:03}.{extension}",
        std::process::id(),
        thread_identifier(),
    )
}

/// The `thread_id` `MakeFilename` takes: a stable, numeric, per-thread value.
///
/// Node passes `env->thread_id()`, an `Environment`-level counter that is 0 for
/// the main thread. rustnode has no environment-level counter to read here, and
/// a `std::thread::ThreadId` cannot be turned into a number, so the value is
/// derived from the thread's name when the caller set one and otherwise from a
/// per-thread counter assigned on first use. The only requirement the filename
/// has is that two threads do not agree, which either source satisfies.
fn thread_identifier() -> u64 {
    use std::cell::Cell;

    thread_local! {
        static THIS_THREAD: Cell<u64> = const { Cell::new(0) };
    }
    static NEXT_THREAD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    THIS_THREAD.with(|slot| {
        let assigned = slot.get();
        if assigned != 0 {
            return assigned;
        }
        let value = NEXT_THREAD.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        slot.set(value);
        value
    })
}

/// Converts a Unix timestamp to a proleptic Gregorian date and time of day.
///
/// Howard Hinnant's `civil_from_days`, which is the standard branch-free
/// conversion: it is here rather than a `chrono` dependency because a filename
/// should not pull in a date library.
fn civil_from_unix(seconds: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let hour = (remainder / 3_600) as u32;
    let minute = ((remainder % 3_600) / 60) as u32;
    let second = (remainder % 60) as u32;

    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day, hour, minute, second)
}

// The isolate a heap snapshot is taken from, recorded by
// `set_snapshot_isolate` and read by `with_snapshot_isolate`, which documents
// why it has to be recorded rather than obtained from the callback.
thread_local! {
    static SNAPSHOT_ISOLATE: std::cell::Cell<Option<v8::UnsafeRawIsolatePtr>> =
        const { std::cell::Cell::new(None) };
}

/// Records the isolate heap snapshots are taken from.
pub fn set_snapshot_isolate(isolate: &mut v8::Isolate) {
    // SAFETY: producing the handle is safe; only re-entering it requires the
    // guarantee documented on `snapshot_isolate`.
    let pointer = unsafe { isolate.as_raw_isolate_ptr() };
    SNAPSHOT_ISOLATE.with(|slot| slot.set(Some(pointer)));
}

/// Runs `body` against the recorded isolate.
///
/// `Isolate` is a `NonNull<RealIsolate>` newtype with no `Drop` impl, so the
/// value built here borrows the isolate rather than owning it: dropping it is a
/// no-op, and it never outlives the call that produced it.
///
/// `take_heap_snapshot` needs `&mut Isolate`, which a function callback cannot
/// obtain soundly — the `v8` crate documents
/// `FunctionCallbackArguments::get_isolate` as unsound inside a callback scope,
/// and calling it segfaults. So the CLI records the isolate at startup through
/// [`set_snapshot_isolate`] and this re-enters it for one snapshot.
///
/// SAFETY: the handle was recorded from a live isolate on this thread, which
/// outlives every callback.
fn with_snapshot_isolate<R>(body: impl FnOnce(&mut v8::Isolate) -> R) -> Option<R> {
    let pointer = SNAPSHOT_ISOLATE.with(|slot| slot.get())?;
    let mut isolate = unsafe { v8::Isolate::from_raw_isolate_ptr(pointer) };
    Some(body(&mut isolate))
}

fn throw_io_error(scope: &mut v8::PinScope<'_, '_>, error: &std::io::Error, path: &str) {
    throw_error(scope, &format!("{path}: {error}"));
}

fn throw_error(scope: &mut v8::PinScope, message: &str) {
    if let Some(message) = v8::String::new(scope, message) {
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
    }
}

fn throw_type_error(scope: &mut v8::PinScope, message: &str) {
    if let Some(message) = v8::String::new(scope, message) {
        let exception = v8::Exception::type_error(scope, message);
        scope.throw_exception(exception);
    }
}

/// Registers the `heap_utils` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(HeapUtils);
    registry.register_module(InternalOnlyV8);
}

/// `internalBinding('internal_only_v8')`.
///
/// One contract member, `queryObjects`, which `lib/internal/heap_utils.js`
/// destructures at module scope — and `lib/v8.js` requires that file — so the
/// namespace has to exist before `require('v8')` can load at all. The name is
/// absent from the object because it is deferred; see
/// [`INTERNAL_ONLY_V8_DEFERRED`].
///
/// The implementation is a genuine deferral rather than an oversight: Node's
/// `QueryObjects` walks the heap through
/// `HeapProfiler::QueryObjects(context, predicate, out)` with a C++
/// `QueryObjectPredicate` that checks the creation context and the prototype
/// chain. The `v8` crate this build links binds only
/// `HeapProfiler::TakeHeapSnapshot`, so there is no call to make, and returning
/// an empty array would claim every object had been collected.
pub struct InternalOnlyV8;

/// Members `contracts/internal_only_v8.json` records.
pub const INTERNAL_ONLY_V8_MEMBERS: &[&str] = &["queryObjects"];

/// Why `queryObjects` is not implemented.
///
/// Empty: `queryObjects` is implemented, through the `HeapProfiler::QueryObjects`
/// shim in `rn-v8-sys`. This constant stays because the registry subtracts it from
/// the contract, and the gate reports a name that is neither installed nor
/// deferred — which is exactly the shape a future gap here should take.
pub const INTERNAL_ONLY_V8_DEFERRED: &[(&str, &str)] = &[];

impl BindingModule for InternalOnlyV8 {
    fn namespace(&self) -> &'static str {
        "internal_only_v8"
    }

    fn members(&self) -> &'static [&'static str] {
        INTERNAL_ONLY_V8_MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        INTERNAL_ONLY_V8_DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        // `lib/internal/heap_utils.js` destructures `_queryObjects` at module
        // scope, so the member has to exist before `lib/v8.js` can load.
        install_function(scope, object, "queryObjects", query_objects)?;
        Ok(object)
    }
}

/// `queryObjects(prototype)`.
///
/// `lib/internal/heap_utils.js`'s `queryObjects(ctor, options)` does the argument
/// validation — `ctor` must be a function, `options.format` one of `count` or
/// `summary` — and calls `_queryObjects(ctor.prototype)`. So this receives one
/// argument, a prototype object, and returns the matching objects as an `Array`.
///
/// Node's `QueryObjects` answers a non-object argument with an empty `Array`
/// (`src/internal_only_v8.cc`: `if (!args[0]->IsObject())`). That branch is
/// reachable here only through a direct `internalBinding` call, because the JS
/// wrapper has already rejected a non-function constructor, but it is reproduced
/// because it is the C's behaviour rather than an accident of the wrapper.
fn query_objects<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let prototype = args.get(0);
    if !prototype.is_object() {
        rv.set(v8::Array::new(scope, 0).into());
        return;
    }
    let Ok(search) = v8::Local::<v8::Object>::try_from(prototype) else {
        rv.set(v8::Array::new(scope, 0).into());
        return;
    };
    // SAFETY: `scope` is the entered scope the walk runs in, and `search` is an
    // object handle from that same scope, so both outlive the call.
    let found = unsafe { rn_v8_sys::query_objects(scope, search) };
    match found {
        Some(array) => rv.set(array.into()),
        // The shim only refuses a null argument, so reaching here means V8
        // produced a null handle; an empty array is Node's answer for "nothing
        // matched" and is the only honest report available.
        None => rv.set(v8::Array::new(scope, 0).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_cover_the_recorded_contract_without_the_deferral() {
        assert_eq!(
            MEMBERS,
            [
                "buildEmbedderGraph",
                "createHeapSnapshotStream",
                "triggerHeapSnapshot"
            ]
        );
        assert!(
            DEFERRED.is_empty(),
            "{DEFERRED:?} is deferred but every contract member is installed"
        );
        for (name, reason) in DEFERRED {
            // `MEMBERS` means "install() sets this". A deferred name in both lists
            // cancels itself out of the contract subtraction, which is the shape
            // `sqlite.backup` shipped; the gate reports the pair as a
            // contradiction now.
            assert!(
                !MEMBERS.contains(name),
                "{name} is deferred, so it must not also be claimed installed"
            );
            assert!(!reason.is_empty(), "{name} has no reason");
        }
    }

    /// `internal_only_v8` claims its one contract member and defers nothing.
    ///
    /// This is the assertion that would have caught the deferral outliving the
    /// fix: while `queryObjects` was unimplemented it was absent from `MEMBERS`
    /// and present in `DEFERRED`, and now the reverse has to hold.
    #[test]
    fn the_internal_only_v8_namespace_claims_query_objects() {
        assert_eq!(INTERNAL_ONLY_V8_MEMBERS, ["queryObjects"]);
        assert!(
            INTERNAL_ONLY_V8_DEFERRED.is_empty(),
            "{:?} is still deferred",
            INTERNAL_ONLY_V8_DEFERRED
        );
        assert!(!INTERNAL_ONLY_V8_MEMBERS.contains(&"getHeapProfiler"));
    }

    #[test]
    fn the_date_conversion_is_the_gregorian_calendar() {
        // 2000-01-01T00:00:00Z, the epoch's first leap-year boundary.
        assert_eq!(civil_from_unix(946_684_800), (2000, 1, 1, 0, 0, 0));
        // 2024-02-29T12:34:56Z, to exercise a leap day.
        assert_eq!(civil_from_unix(1_709_210_096), (2024, 2, 29, 12, 34, 56));
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn a_generated_filename_carries_the_prefix_pid_and_extension() {
        let name = diagnostic_filename("Heap", "heapsnapshot");
        assert!(name.starts_with("Heap."), "{name}");
        assert!(name.ends_with(".heapsnapshot"), "{name}");
        assert!(
            name.contains(&format!(".{}.", std::process::id())),
            "{name} has no pid"
        );
    }
}
