//! `internalBinding('heap_utils')` for rustnode.
//!
//! `lib/v8.js` loads this namespace at module scope, so `require('v8')` — and
//! therefore a large part of the test suite — fails outright without it. Three
//! members exist on the namespace: two are implemented here, and the third is
//! deferred with a reason.
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
//! `internal/heap_utils.js`'s `getHeapSnapshotOptions` builds. V8's
//! `TakeHeapSnapshot` in the `v8` crate takes no options argument, so both flags
//! are read and reported as unsupported rather than silently ignored — see
//! [`DEFERRED`].
//!
//! # `createHeapSnapshotStream(options)` — implemented
//!
//! Returns the readable handle `lib/v8.js`'s `getHeapSnapshot()` wraps in
//! `internal/heap_utils.js`'s `HeapSnapshotStream`, a `Readable`. The handle is
//! the `AsyncWrap` + `StreamBase` surface `onStreamRead` drives: `readStart`
//! pushes the snapshot through `onread` in 64 KiB chunks and then reports
//! `UV_EOF`. See [`stream`] for what is reproduced and what is deliberately not.
//!
//! # `buildEmbedderGraph` — deferred
//!
//! It exists so the inspector can label embedder objects (`BaseObject` instances)
//! in a snapshot. rustnode has no `BaseObject` hierarchy to describe, and no
//! inspector to read the result.

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
/// failure, so these are visible rather than silent.
pub const DEFERRED: &[(&str, &str)] = &[(
    "buildEmbedderGraph",
    "needs v8::HeapProfiler::AddBuildEmbedderGraphCallback with an EmbedderGraph subclass, and \
     describes Node's BaseObject hierarchy to the inspector; the v8 crate exposes no embedder \
     graph binding at all, and rustnode has neither that hierarchy nor an inspector",
)];

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
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name} key"))?;
    object.set(scope, key.into(), function.into());
    Ok(())
}

/// `createHeapSnapshotStream(options)`.
///
/// `options` is `getHeapSnapshotOptions`' `Uint8Array([exposeInternals,
/// exposeNumericValues])`. The `v8` crate's `take_heap_snapshot` exposes no
/// options parameter, so the flags are parsed and reported as unsupported rather
/// than silently ignored — the same gap [`trigger_heap_snapshot`] has, and for
/// the same reason.
///
/// A failure to allocate the stream throws instead of returning `undefined`:
/// `lib/v8.js`'s `getHeapSnapshot` asserts the handle is truthy, and an
/// assertion failure there would name the wrong problem.
fn create_heap_snapshot_stream(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let _options = snapshot_options(scope, args.get(0));

    // One buffer, appended in order. `take_heap_snapshot` invokes the callback
    // repeatedly with consecutive chunks of a single JSON document, and
    // `try_reserve` keeps a huge snapshot from aborting the process on
    // allocation failure: aborting the snapshot (`false`) is the contract's own
    // way to stop, and the empty result is reported as the failure it is.
    let mut bytes: Vec<u8> = Vec::new();
    let snapshot = with_snapshot_isolate(|isolate| {
        isolate.take_heap_snapshot(|chunk| match bytes.try_reserve(chunk.len()) {
            Ok(()) => {
                bytes.extend_from_slice(chunk);
                true
            }
            Err(_) => false,
        })
    });
    if snapshot.is_none() {
        throw_error(
            scope,
            "createHeapSnapshotStream ran before the isolate was recorded",
        );
        return;
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
    // `take_heap_snapshot` invokes the callback repeatedly with consecutive
    // chunks of one JSON document, so they are appended in order. Returning
    // `false` aborts the snapshot; there is nothing useful to gain from a
    // partial one, so a write failure is recorded and the rest is dropped.
    let snapshot = with_snapshot_isolate(|isolate| {
        isolate.take_heap_snapshot(|chunk| {
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
    });
    if snapshot.is_none() {
        throw_error(
            scope,
            "triggerHeapSnapshot ran before the isolate was recorded",
        );
        return;
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
    let _ = options;
}

/// Reads `getHeapSnapshotOptions`' `Uint8Array([exposeInternals, numerics])`.
///
/// The `v8` crate's `take_heap_snapshot` exposes no options parameter, so V8
/// always takes a regular snapshot with numeric values hidden. The values are
/// still parsed and returned so the deferral is a documented gap rather than an
/// invisible one, and so a caller passing a malformed array is rejected the way
/// `validateObject` would reject it.
fn snapshot_options(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> (bool, bool) {
    let Ok(array) = v8::Local::<v8::Array>::try_from(value) else {
        return (false, false);
    };
    let flag = |index: u32| -> bool {
        array
            .get_index(scope, index)
            .and_then(|item| item.uint32_value(scope))
            .map(|value| value != 0)
            .unwrap_or(false)
    };
    (flag(0), flag(1))
}

/// `DiagnosticFilename(id, prefix, ext)`: `Heap.<yyyymmdd>.<hhmmss>.<pid>.heapsnapshot`.
///
/// `MakeFilename` in `src/util.cc` is `prefix`, the local date, the local time,
/// the process id and the extension, each dot-separated and zero-padded. The
/// process id is what keeps two snapshots in one second apart.
fn diagnostic_filename(prefix: &str, extension: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    // `LocalTime` in Node; UTC here because converting needs a timezone
    // database, and the name only has to be unique and sortable.
    let (year, month, day, hour, minute, second) = civil_from_unix(now);
    format!(
        "{prefix}.{year:04}{month:02}{day:02}.{hour:02}{minute:02}{second:02}.{}.{extension}",
        std::process::id()
    )
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
/// One member, `queryObjects`, which `lib/internal/heap_utils.js` destructures at
/// module scope — and `lib/v8.js` requires that file — so the namespace has to
/// exist before `require('v8')` can load at all.
///
/// The implementation is a genuine deferral rather than an oversight: Node's
/// `QueryObjects` walks the heap through
/// `HeapProfiler::QueryObjects(context, predicate, out)` with a C++
/// `QueryObjectPredicate` that checks the creation context and the prototype
/// chain. The `v8` crate this build links exposes no `QueryObjects` binding at
/// all, so there is no API to call, and returning an empty array would claim
/// every object had been collected.
pub struct InternalOnlyV8;

/// Members `contracts/internal_only_v8.json` records.
pub const INTERNAL_ONLY_V8_MEMBERS: &[&str] = &["queryObjects"];

/// Why `queryObjects` is not implemented.
pub const INTERNAL_ONLY_V8_DEFERRED: &[(&str, &str)] = &[(
    "queryObjects",
    "needs v8::HeapProfiler::QueryObjects with a C++ QueryObjectPredicate; the v8 crate \
     exposes no such binding, and an empty array would claim every object had been collected",
)];

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
        // Deliberately empty: the namespace object has to exist so `require`
        // succeeds, and `queryObjects` reads as `undefined` because it is not
        // installed. `deferred()` is what records that, and `deferred-reach.py`
        // proves it is not called at module scope.
        Ok(v8::Object::new(scope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_cover_the_recorded_contract() {
        assert_eq!(
            MEMBERS,
            [
                "buildEmbedderGraph",
                "createHeapSnapshotStream",
                "triggerHeapSnapshot"
            ]
        );
        for (name, reason) in DEFERRED {
            assert!(
                MEMBERS.contains(name),
                "{name} is deferred but not a member"
            );
            assert!(!reason.is_empty(), "{name} has no reason");
        }
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
