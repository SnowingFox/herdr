//! `internalBinding('performance')` for rustnode.
//!
//! `lib/internal/process/pre_execution.js` calls `markBootstrapComplete()` on
//! every start, and `lib/internal/perf/*` builds the `perf_hooks` API on the
//! rest, so this sits on the bootstrap path.
//!
//! # The milestone scale
//!
//! `milestones` is a `Float64Array(8)` of **nanosecond** timestamps from the
//! monotonic clock, one per `NODE_PERFORMANCE_MILESTONES` entry, and `-1` marks
//! one that has not been reached yet. That sentinel matters: `performance.measure()`
//! checks for it, so a zero-initialised array would report every milestone as
//! having happened at time origin.
//!
//! The two origin entries are the exception and do not follow the milestone rule.
//! `PerformanceState::Initialize` stores them directly rather than through
//! `Mark()`, with their own units, and `lib/internal/perf/utils.js` divides them
//! back out:
//!
//! * `TIME_ORIGIN` holds **nanoseconds** from the monotonic clock, and
//!   `getTimeOrigin()` divides by `1e6` to get the milliseconds `now()` is
//!   measured in;
//! * `TIME_ORIGIN_TIMESTAMP` holds **microseconds** since the Unix epoch, and
//!   `getTimeOriginTimestamp()` divides by `1e3` for `performance.timeOrigin` in
//!   milliseconds.
//!
//! So `performance.timeOrigin + performance.now()` reconstructs `Date.now()`,
//! which is the invariant callers build a wall-clock conversion on.
//!
//! # What needs the event loop
//!
//! `loopIdleTime`, `uvMetricsInfo` and `updateGarbageCollectionTracking` report
//! loop and collector statistics.

mod cbor;
mod eld;
mod hdr;
mod histogram_binding;

use std::cell::RefCell;
use std::sync::OnceLock;

use rn_core::{AliasedUint8Array, BindingModule, Element, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/performance.json`.
pub const MEMBERS: &[&str] = &[
    "Histogram",
    "SlidingWindowHistogram",
    "constants",
    "createELDHistogram",
    "loopIdleTime",
    "markBootstrapComplete",
    "milestones",
    "notify",
    "now",
    "observerCounts",
    "setupObservers",
    "updateGarbageCollectionTracking",
    "uvMetricsBigIntBuffer",
    "uvMetricsBuffer",
    "uvMetricsInfo",
];

/// The members this namespace declares it does not install yet, with the reason.
///
/// Empty: every member in [`MEMBERS`] is installed. The two histogram
/// constructors used to be listed here because the subsystem they need did not
/// exist, which made `perf_hooks.createHistogram()` throw `_Histogram is not a
/// constructor`. They are installed now, so there is nothing left to declare.
///
pub const DEFERRED: &[(&str, &str)] = &[
    // `performance.Histogram` and `performance.SlidingWindowHistogram` used to be
    // declared here with a reason saying the histogram subsystem did not exist.
    // It exists now, so they are installed rather than deferred.
    //
    // This block keeps its comment because `tools/deferred-reach.py` matches
    // `&\[(.*?)\n\];` and rustfmt folds an empty `&[\n]` back to `&[]`, which the
    // pattern does not accept. The comment is what keeps the two-line form
    // stable, and the tool then reads this file's entries instead of reporting
    // that it could not parse them.
];

/// `NODE_PERFORMANCE_MILESTONES` in `src/node_perf_common.h`, in enum order.
pub const MILESTONES: &[(&str, usize)] = &[
    ("TIME_ORIGIN_TIMESTAMP", 0),
    ("TIME_ORIGIN", 1),
    ("ENVIRONMENT", 2),
    ("NODE_START", 3),
    ("V8_START", 4),
    ("LOOP_START", 5),
    ("LOOP_EXIT", 6),
    ("BOOTSTRAP_COMPLETE", 7),
];

/// `NODE_PERFORMANCE_MILESTONE_INVALID`: one past the last real milestone.
pub const MILESTONE_INVALID: usize = 8;

/// `NODE_PERFORMANCE_ENTRY_TYPES` in `src/node_perf_common.h`, in enum order.
pub const ENTRY_TYPES: &[(&str, usize)] = &[
    ("GC", 0),
    ("HTTP", 1),
    ("HTTP2", 2),
    ("NET", 3),
    ("DNS", 4),
    ("QUIC", 5),
];

/// `NODE_PERFORMANCE_ENTRY_TYPE_INVALID`.
pub const ENTRY_TYPE_INVALID: usize = 6;

/// `NODE_PERFORMANCE_ENTRY_TYPE_GC`, the only entry type this crate publishes.
pub const ENTRY_TYPE_GC: usize = 0;

/// `PerformanceState`'s `uv_metrics` is three entries.
pub const UV_METRICS_LENGTH: usize = 3;

/// The GC types, bound to `v8::GCType` exactly as `node_perf.h` binds them.
///
/// `PerformanceGCKind` is not a private numbering: each name *is* the matching
/// `v8::GCType` enumerator, because the value arrives from V8 and has to be
/// reported without a translation table. `v8::GCType` here is
/// `Scavenge=1, MinorMarkSweep=2, MarkSweepCompact=4, IncrementalMarking=8,
/// ProcessWeakCallbacks=16`, so `MAJOR` is 4 and `MINOR_MARK_SWEEP` is 2 —
/// reading them as a sorted enum would swap those two and make a consumer that
/// filters on `MAJOR` see every scavenge instead.
pub const GC_TYPES: &[(&str, u32)] = &[
    (
        "NODE_PERFORMANCE_GC_MAJOR",
        v8::GCType::kGCTypeMarkSweepCompact.0,
    ),
    ("NODE_PERFORMANCE_GC_MINOR", v8::GCType::kGCTypeScavenge.0),
    (
        "NODE_PERFORMANCE_GC_MINOR_MARK_SWEEP",
        v8::GCType::kGCTypeMinorMarkSweep.0,
    ),
    (
        "NODE_PERFORMANCE_GC_INCREMENTAL",
        v8::GCType::kGCTypeIncrementalMarking.0,
    ),
    (
        "NODE_PERFORMANCE_GC_WEAKCB",
        v8::GCType::kGCTypeProcessWeakCallbacks.0,
    ),
];

/// The GC types Node publishes as *enumerable* constants.
///
/// `NODE_DEFINE_CONSTANT` for the five kinds and the seven flags, but
/// `NODE_DEFINE_HIDDEN_CONSTANT` for the entry types and the milestones: those
/// are installed read-only and non-enumerable, so `Object.keys(constants)`
/// lists twelve names in Node and a table that published all twenty-six would
/// be observable through `perf_hooks.constants`.
pub const ENUMERATED_GC_TYPES: usize = 5;

/// The GC flags, from `v8::GCFlag`'s Node-facing names.
pub const GC_FLAGS: &[(&str, u32)] = &[
    ("NODE_PERFORMANCE_GC_FLAGS_NO", 0),
    ("NODE_PERFORMANCE_GC_FLAGS_CONSTRUCT_RETAINED", 1),
    ("NODE_PERFORMANCE_GC_FLAGS_FORCED", 2),
    (
        "NODE_PERFORMANCE_GC_FLAGS_SYNCHRONOUS_PHANTOM_PROCESSING",
        4,
    ),
    ("NODE_PERFORMANCE_GC_FLAGS_ALL_AVAILABLE_GARBAGE", 8),
    ("NODE_PERFORMANCE_GC_FLAGS_ALL_EXTERNAL_MEMORY", 16),
    ("NODE_PERFORMANCE_GC_FLAGS_SCHEDULE_IDLE", 32),
];

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    /// The callback `notify` publishes entries to, installed by
    /// `lib/internal/perf/observe.js`.
    static OBSERVER_CALLBACK: RefCell<Option<v8::Global<v8::Function>>> =
        const { RefCell::new(None) };
    /// The collection in progress between the V8 prologue and epilogue.
    ///
    /// Node keeps this on `PerformanceState` because the pair of callbacks is
    /// one pair per environment. It lives here for the same reason, and it is
    /// what makes a nested collection's prologue ignorable rather than a
    /// mispaired start time.
    static GC_IN_PROGRESS: RefCell<Option<GcInProgress>> = const { RefCell::new(None) };
    /// Whether the prologue and epilogue callbacks are registered with V8.
    ///
    /// `ReconcileGarbageCollectionTracking` in Node: adding a callback twice is
    /// not an error in V8 but it does mean two entries per collection, and
    /// removing a callback that was never added aborts the process.
    static GC_TRACKING_INSTALLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A GC entry that has been recorded and is waiting for the check phase.
    static GC_PENDING: RefCell<Option<GcEntry>> = const { RefCell::new(None) };
}

struct State {
    milestones: AliasedUint8Array,
    observers: AliasedUint8Array,
    uv_metrics: AliasedUint8Array,
    uv_metrics_bigint: AliasedUint8Array,
}

/// One collection, from the prologue's start mark to the epilogue's duration.
struct GcInProgress {
    kind: u32,
    start_nanos: u64,
}

/// A completed collection, delivered on the next check phase.
///
/// Node defers the delivery through `env->SetImmediate` so the entry's
/// `startTime`/`duration` are measured against the same time origin the
/// JavaScript layer uses, and so a GC during a callback does not re-enter
/// JavaScript in the middle of it. A whole struct fits in the native-immediate
/// queue only if the queue can hold data, so this is drained by one fixed
/// callback that takes whatever is pending.
struct GcEntry {
    start_time: f64,
    duration: f64,
    kind: u32,
    flags: u32,
}

/// The time origin, captured once so every measurement shares one zero point.
///
/// `(monotonic nanoseconds at origin, unix microseconds at origin)`.
static TIME_ORIGIN: OnceLock<(u64, f64)> = OnceLock::new();

/// Process start, as `performance_process_start` holds it in Node.
fn time_origin() -> (u64, f64) {
    *TIME_ORIGIN.get_or_init(|| (monotonic_nanos(), unix_micros()))
}

/// Milliseconds since the time origin, the unit `performance.now()` uses.
fn performance_now() -> f64 {
    let (origin_nanos, _) = time_origin();
    let now = monotonic_nanos();
    now.saturating_sub(origin_nanos) as f64 / 1_000_000.0
}

/// A monotonic clock in nanoseconds, which is what `uv_hrtime()` reads.
///
/// `clock_gettime(CLOCK_MONOTONIC)` is the same clock libuv uses for
/// `uv_hrtime`, so a delta computed here is in the unit `recordDelta` records
/// and in the unit `Histogram::RecordDelta` compares against.
pub(crate) fn monotonic_nanos() -> u64 {
    // SAFETY: `timespec` is plain-old-data and `clock_gettime` fills it.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `now` is a valid, writable `timespec`.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return 0;
    }
    (now.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(now.tv_nsec as u64)
}

/// Microseconds since the Unix epoch.
///
/// `GetCurrentTimeInMicroseconds()` is what Node stores in
/// `TIME_ORIGIN_TIMESTAMP`; `lib/internal/perf/utils.js` divides it by `1e3`
/// to publish `performance.timeOrigin` in milliseconds.
fn unix_micros() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64() * 1_000_000.0)
        .unwrap_or(0.0)
}

pub struct Performance;

impl BindingModule for Performance {
    fn namespace(&self) -> &'static str {
        "performance"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        // Installing these as `undefined` is not the same as not installing
        // them: `members()` claimed the names, so `rn-compat` counted them as
        // covered and the without-`new` audit saw an absent constructor with no
        // declared reason. `perf_hooks` reads both as classes, so a namespace
        // that publishes `undefined` under those names fails at the first
        // `new Histogram()` with a message about `undefined` not being a
        // constructor. Declaring the gap is what keeps that visible.
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let milestones = AliasedUint8Array::new(scope, MILESTONE_INVALID, Element::Double)?;
        let observers = AliasedUint8Array::new(scope, ENTRY_TYPE_INVALID, Element::Word)?;
        let uv_metrics = AliasedUint8Array::new(scope, UV_METRICS_LENGTH, Element::Double)?;
        let uv_metrics_bigint = AliasedUint8Array::new(scope, UV_METRICS_LENGTH, Element::Double)?;

        // Every milestone starts unreached. Zero would claim all of them
        // happened at time origin, which `perf_hooks` checks against.
        for index in 0..MILESTONE_INVALID {
            milestones.set_float(index, -1.0);
        }
        // The first two are known as soon as the origin exists, and they are the
        // two that do not use the nanosecond milestone scale: see the module
        // documentation for the units `lib/internal/perf/utils.js` expects.
        let (origin_nanos, origin_unix) = time_origin();
        milestones.set_float(MILESTONES[0].1, origin_unix);
        milestones.set_float(MILESTONES[1].1, origin_nanos as f64);

        let milestone_array = milestones.array(scope);
        let observer_array = observers.array(scope);
        let uv_array = uv_metrics.array(scope);
        let uv_bigint_array = uv_metrics_bigint.array(scope);

        STATE.with(|state| {
            *state.borrow_mut() = Some(State {
                milestones,
                observers,
                uv_metrics,
                uv_metrics_bigint,
            })
        });

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 15] = [
            ("milestones", milestone_array),
            ("observerCounts", observer_array),
            ("uvMetricsBuffer", uv_array),
            ("uvMetricsBigIntBuffer", uv_bigint_array),
            ("constants", constants_object(scope)),
            ("now", function(scope, "now", now)?),
            (
                "markBootstrapComplete",
                function(scope, "markBootstrapComplete", mark_bootstrap_complete)?,
            ),
            ("notify", function(scope, "notify", notify)?),
            (
                "setupObservers",
                function(scope, "setupObservers", setup_observers)?,
            ),
            (
                "updateGarbageCollectionTracking",
                function(
                    scope,
                    "updateGarbageCollectionTracking",
                    update_garbage_collection_tracking,
                )?,
            ),
            (
                "loopIdleTime",
                function(scope, "loopIdleTime", loop_idle_time)?,
            ),
            (
                "uvMetricsInfo",
                function(scope, "uvMetricsInfo", uv_metrics_info)?,
            ),
            // `lib/internal/perf/event_loop_delay.js` calls this and wraps the
            // result in `ELDHistogram`, so the object it returns has to carry the
            // whole handle interface plus `start`/`stop`.
            ("createELDHistogram", eld::create_function(scope)?),
            // The two histogram classes `lib/internal/histogram.js` destructures
            // and `perf_hooks.createHistogram()` builds on. Their methods are the
            // handle interface that module calls by name.
            (
                "Histogram",
                histogram_binding::histogram_constructor(scope)?,
            ),
            (
                "SlidingWindowHistogram",
                histogram_binding::sliding_constructor(scope)?,
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        // The ELD handle's template is built up front so the first
        // `monitorEventLoopDelay()` does not pay for a `FunctionTemplate` inside a
        // call that may already be timing the loop.
        eld::register_template(scope)?;
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Performance);
}

/// Builds the `constants` object with Node's two attribute classes.
///
/// `src/node_perf.cc` defines the GC kinds and flags with `NODE_DEFINE_CONSTANT`
/// (read-only, enumerable) and the entry types and milestones with
/// `NODE_DEFINE_HIDDEN_CONSTANT` (read-only, non-enumerable). Both are
/// non-configurable, so the object is not frozen but no key can be removed.
fn constants_object<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let object = v8::Object::new(scope);
    let visible: Vec<(String, u32)> = GC_TYPES
        .iter()
        .chain(GC_FLAGS.iter())
        .map(|(name, value)| ((*name).to_string(), *value))
        .collect();
    let hidden: Vec<(String, u32)> = ENTRY_TYPES
        .iter()
        .map(|(name, value)| (format!("NODE_PERFORMANCE_ENTRY_TYPE_{name}"), *value as u32))
        .chain(
            MILESTONES
                .iter()
                .map(|(name, value)| (format!("NODE_PERFORMANCE_MILESTONE_{name}"), *value as u32)),
        )
        .collect();

    for (name, value) in visible {
        // `NODE_DEFINE_CONSTANT` is `v8::ReadOnly | v8::DontDelete`, which is
        // `writable:false, enumerable:true, configurable:false`.
        let attributes = v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE;
        define_constant(scope, object, &name, value, attributes);
    }
    for (name, value) in hidden {
        // `NODE_DEFINE_HIDDEN_CONSTANT` adds `v8::DontEnum`, which is what keeps
        // `Object.keys(constants)` at Node's twelve names.
        let attributes = v8::PropertyAttribute::READ_ONLY
            | v8::PropertyAttribute::DONT_DELETE
            | v8::PropertyAttribute::DONT_ENUM;
        define_constant(scope, object, &name, value, attributes);
    }
    object.into()
}

fn define_constant(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: u32,
    attributes: v8::PropertyAttribute,
) {
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    let value = v8::Integer::new_from_unsigned(scope, value);
    // `define_own_property` rather than `set`: `set` creates a writable,
    // configurable, enumerable data property and ignores the attributes Node
    // publishes these with.
    object.define_own_property(scope, key.into(), value.into(), attributes);
}

fn now(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Number::new(scope, performance_now()).into());
}

fn mark_bootstrap_complete(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let _ = scope;
    let value = performance_now();
    STATE.with(|state| {
        if let Some(state) = state.borrow().as_ref() {
            state.milestones.set_float(MILESTONES[7].1, value);
        }
    });
}

fn notify(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `notify(type, entry)` publishes a performance entry, which is a different
    // thing from a milestone: `lib/internal/perf/observe.js` installs the
    // callback and filters by entry type. Nothing is published when no one is
    // observing that type, which is the whole point of `observerCounts`.
    let Some(kind) = args.get(0).to_string(scope) else {
        return;
    };
    let kind = kind.to_rust_string_lossy(scope);
    let Some(entry_type) = ENTRY_TYPES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(&kind))
        .map(|(_, index)| *index)
    else {
        return;
    };

    let observing = STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.observers.get(entry_type))
            .is_some_and(|count| count > 0)
    });
    if !observing {
        return;
    }

    let callback = OBSERVER_CALLBACK.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    });
    if let Some(callback) = callback {
        let entry = args.get(1);
        let _ = callback.call(scope, v8::undefined(scope).into(), &[entry]);
    }
}

fn setup_observers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `setupObservers(callback)` installs the single callback every entry is
    // published through. `lib/internal/perf/observe.js` owns the filtering by
    // type; the native side only needs `observerCounts` to skip work nobody
    // asked for.
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw(scope, "setupObservers expects a function");
        return;
    };
    let callback = v8::Global::new(scope, callback);
    OBSERVER_CALLBACK.with(|slot| *slot.borrow_mut() = Some(callback));
}

/// `updateGarbageCollectionTracking()`: reconcile the V8 callbacks.
///
/// `internal/perf/observe.js` calls this whenever the `'gc'` observer count
/// changes, and Node's `ReconcileGarbageCollectionTracking` registers the
/// prologue/epilogue pair exactly when the count is above zero. The count lives
/// in the shared `observerCounts` array, so this reads the same byte the
/// JavaScript layer just incremented.
fn update_garbage_collection_tracking(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let wanted = STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.observers.get(ENTRY_TYPE_GC))
            .is_some_and(|count| count > 0)
    });
    let installed = GC_TRACKING_INSTALLED.with(std::cell::Cell::get);
    if wanted == installed {
        return;
    }
    if wanted {
        // A stale start mark from a collection that was interrupted before its
        // epilogue would otherwise be paired with the next epilogue's duration.
        GC_IN_PROGRESS.with(|in_progress| *in_progress.borrow_mut() = None);
        scope.add_gc_prologue_callback(gc_prologue, std::ptr::null_mut(), v8::GCType::kGCTypeAll);
        scope.add_gc_epilogue_callback(gc_epilogue, std::ptr::null_mut(), v8::GCType::kGCTypeAll);
        GC_TRACKING_INSTALLED.with(|installed| installed.set(true));
    } else {
        GC_IN_PROGRESS.with(|in_progress| *in_progress.borrow_mut() = None);
        scope.remove_gc_prologue_callback(gc_prologue, std::ptr::null_mut());
        scope.remove_gc_epilogue_callback(gc_epilogue, std::ptr::null_mut());
        GC_TRACKING_INSTALLED.with(|installed| installed.set(false));
    }
}

/// `MarkGarbageCollectionStart`: remember when the collection began.
///
/// # Safety
///
/// V8 calls this with the isolate whose callback it is, which the `v8` crate
/// hands over as an opaque pointer this callback deliberately does not touch.
unsafe extern "C" fn gc_prologue(
    _isolate: v8::UnsafeRawIsolatePtr,
    gc_type: v8::GCType,
    _flags: v8::GCCallbackFlags,
    _data: *mut std::ffi::c_void,
) {
    // Node ignores a prologue that arrives while one is already pending, because
    // V8 can report the outer and inner collection of a nested pair in either
    // order relative to each other; see nodejs/node#44046.
    GC_IN_PROGRESS.with(|in_progress| {
        let mut in_progress = in_progress.borrow_mut();
        if in_progress.is_some() {
            return;
        }
        *in_progress = Some(GcInProgress {
            kind: gc_type.0,
            start_nanos: monotonic_nanos(),
        });
    });
}

/// `MarkGarbageCollectionEnd`: publish the entry on the next check phase.
///
/// # Safety
///
/// As in [`gc_prologue`].
unsafe extern "C" fn gc_epilogue(
    _isolate: v8::UnsafeRawIsolatePtr,
    gc_type: v8::GCType,
    flags: v8::GCCallbackFlags,
    _data: *mut std::ffi::c_void,
) {
    let Some(start) = GC_IN_PROGRESS.with(|in_progress| {
        let mut in_progress = in_progress.borrow_mut();
        let start = in_progress.take()?;
        // An epilogue whose type does not match the pending prologue belongs to
        // a collection that was not the one being measured, so pairing them
        // would report one collection's start against another's duration.
        (start.kind == gc_type.0).then_some(start)
    }) else {
        return;
    };

    // If no one is listening to GC entries, do not create them. The observer
    // count is the authority, not the callback's presence: the callback is only
    // registered while an observer wants it, but `disconnect()` can decrement
    // the count from JavaScript between the prologue and the epilogue.
    let observing = STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.observers.get(ENTRY_TYPE_GC))
            .is_some_and(|count| count > 0)
    });
    if !observing {
        return;
    }

    let (origin_nanos, _) = time_origin();
    let start_time = start.start_nanos.saturating_sub(origin_nanos) as f64 / 1_000_000.0;
    let duration = monotonic_nanos().saturating_sub(start.start_nanos) as f64 / 1_000_000.0;
    GC_PENDING.with(|pending| {
        *pending.borrow_mut() = Some(GcEntry {
            start_time,
            duration,
            kind: start.kind,
            flags: flags.0,
        });
    });
    // Node runs `entry->Notify(env)` from `env->SetImmediate`, which both defers
    // the JavaScript call out of the collection and gives every entry the same
    // ordering guarantee. The native queue is the same seam here.
    rn_core::native_immediates::set_immediate(deliver_gc_entry);
}

/// Delivers the pending GC entry to the JavaScript observer callback.
///
/// `lib/internal/perf/observe.js`'s `observerCallback(name, type, startTime,
/// duration, details)` builds the `PerformanceEntry`; `detail.kind` and
/// `detail.flags` are the two numbers the constants exist for.
fn deliver_gc_entry(scope: &mut v8::PinScope<'_, '_>) {
    let Some(entry) = GC_PENDING.with(|pending| pending.borrow_mut().take()) else {
        return;
    };
    let callback = OBSERVER_CALLBACK.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    });
    let Some(callback) = callback else {
        return;
    };
    let (Some(name), Some(entry_type)) =
        (v8::String::new(scope, "gc"), v8::String::new(scope, "gc"))
    else {
        return;
    };
    let detail = v8::Object::new(scope);
    let kind = v8::Integer::new_from_unsigned(scope, entry.kind);
    let flags = v8::Integer::new_from_unsigned(scope, entry.flags);
    for (key, value) in [("kind", kind), ("flags", flags)] {
        if let Some(key) = v8::String::new(scope, key) {
            detail.set(scope, key.into(), value.into());
        }
    }
    let arguments = [
        name.into(),
        entry_type.into(),
        v8::Number::new(scope, entry.start_time).into(),
        v8::Number::new(scope, entry.duration).into(),
        detail.into(),
    ];
    let _ = callback.call(scope, v8::undefined(scope).into(), &arguments);
}

fn loop_idle_time(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `perf_hooks.eventLoopUtilization()` expects nanoseconds and zero means
    // the loop has not idle time recorded. The loop does not exist yet, so zero
    // is the honest answer rather than a fabricated figure.
    rv.set(v8::Number::new(scope, 0.0).into());
}

fn uv_metrics_info(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // Node's `uvMetricsInfo()` fills the two shared buffers and returns a
    // BigInt mask saying which of the three counters are valid. The loop does
    // not exist yet, so the counters are zero and the mask says so: a `0` mask
    // means "none of these were measured", which is different from reporting a
    // measured zero.
    STATE.with(|state| {
        if let Some(state) = state.borrow().as_ref() {
            for index in 0..UV_METRICS_LENGTH {
                state.uv_metrics.set_float(index, 0.0);
                state.uv_metrics_bigint.set_float(index, 0.0);
            }
        }
    });
    rv.set(v8::BigInt::new_from_u64(scope, 0).into());
}

/// The milestone value at `index`, or `None` when out of range or unset.
pub fn milestone(index: usize) -> Option<f64> {
    STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.milestones.get_float(index))
    })
}

/// The observer count for an entry type.
pub fn observer_count(entry_type: usize) -> Option<u32> {
    STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.observers.get(entry_type))
    })
}

/// Whether the bootstrap-complete milestone has been recorded.
pub fn bootstrap_complete() -> bool {
    milestone(MILESTONES[7].1).is_some_and(|value| value >= 0.0)
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::method(callback).build(scope);
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
    fn the_milestone_indices_follow_the_enum() {
        for (index, (name, value)) in MILESTONES.iter().enumerate() {
            assert_eq!(*value, index, "{name} must be at {index}");
        }
        assert_eq!(MILESTONE_INVALID, MILESTONES.len());
        assert_eq!(ENTRY_TYPE_INVALID, ENTRY_TYPES.len());
    }

    #[test]
    fn the_time_origin_is_stable() {
        let (first_nanos, first_unix) = time_origin();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let (second_nanos, second_unix) = time_origin();
        // The origin is a fixed point, not the current time.
        assert_eq!(first_nanos, second_nanos);
        assert_eq!(first_unix, second_unix);
        assert!(first_unix > 0.0);
    }

    #[test]
    fn the_time_origin_timestamp_is_microseconds() {
        // `getTimeOriginTimestamp()` divides this by 1e3, so a value in
        // milliseconds would publish `timeOrigin` a thousand times too small and
        // `timeOrigin + now()` would stop reconstructing `Date.now()`.
        let (_, origin_micros) = time_origin();
        let origin_millis = origin_micros / 1e3;
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs_f64() * 1_000.0)
            .unwrap_or(0.0);
        assert!(origin_millis > 1.6e12, "a Unix timestamp in milliseconds");
        assert!(
            (origin_millis - now_millis).abs() < 60_000.0,
            "the origin is this process' start, not the epoch"
        );
    }

    #[test]
    fn now_advances_and_starts_near_zero() {
        let first = performance_now();
        std::thread::sleep(std::time::Duration::from_millis(3));
        let second = performance_now();
        assert!(second > first, "the clock must advance");
        assert!(
            second - first >= 1.0,
            "the unit is milliseconds, so 3ms of sleep must show"
        );
    }

    #[test]
    fn the_gc_kinds_are_the_v8_enumerators_node_reports() {
        // These are wire values a consumer compares against `detail.kind`, and
        // `MAJOR`/`MINOR_MARK_SWEEP` are adjacent numbers in the enum but not
        // adjacent here.
        let kinds: std::collections::HashMap<_, _> = GC_TYPES.iter().copied().collect();
        assert_eq!(kinds["NODE_PERFORMANCE_GC_MAJOR"], 4);
        assert_eq!(kinds["NODE_PERFORMANCE_GC_MINOR"], 1);
        assert_eq!(kinds["NODE_PERFORMANCE_GC_MINOR_MARK_SWEEP"], 2);
        assert_eq!(kinds["NODE_PERFORMANCE_GC_INCREMENTAL"], 8);
        assert_eq!(kinds["NODE_PERFORMANCE_GC_WEAKCB"], 16);
        // The table is bound to `v8::GCType` rather than to literals, so this is
        // the property that keeps it from drifting from the linked V8.
        assert_eq!(
            kinds["NODE_PERFORMANCE_GC_MAJOR"],
            v8::GCType::kGCTypeMarkSweepCompact.0
        );
        assert_eq!(
            kinds["NODE_PERFORMANCE_GC_MINOR_MARK_SWEEP"],
            v8::GCType::kGCTypeMinorMarkSweep.0
        );
    }

    #[test]
    fn only_the_gc_kinds_and_flags_are_enumerated() {
        // `Object.keys(perf_hooks.constants)` is twelve names in Node: five GC
        // kinds and seven flags. The entry types and milestones exist but are
        // non-enumerable.
        assert_eq!(ENUMERATED_GC_TYPES, GC_TYPES.len());
        assert_eq!(GC_TYPES.len() + GC_FLAGS.len(), 12);
        assert_eq!(
            GC_TYPES.len() + GC_FLAGS.len() + ENTRY_TYPES.len() + MILESTONES.len(),
            26
        );
    }
}
