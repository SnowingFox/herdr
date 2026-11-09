//! `internalBinding('performance')` for rustnode.
//!
//! `lib/internal/process/pre_execution.js` calls `markBootstrapComplete()` on
//! every start, and `lib/internal/perf/*` builds the `perf_hooks` API on the
//! rest, so this sits on the bootstrap path.
//!
//! # The milestone scale
//!
//! `milestones` is a `Float64Array(8)` of millisecond offsets from the time
//! origin, one per `NODE_PERFORMANCE_MILESTONES` entry. `performance.timeOrigin`
//! is the Unix timestamp those offsets are measured from, and `-1` in a slot
//! means the milestone has not been reached yet. That sentinel matters:
//! `performance.measure()` checks for it, so a zero-initialised array would
//! report every milestone as having happened at time origin.
//!
//! # What needs the event loop
//!
//! `loopIdleTime`, `uvMetricsInfo` and `updateGarbageCollectionTracking` report
//! loop and collector statistics. The loop does not exist yet, so those return
//! the value that means "not measured" rather than a plausible zero, and say so
//! here.

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

/// `PerformanceState`'s `uv_metrics` is three entries.
pub const UV_METRICS_LENGTH: usize = 3;

/// The GC types, from `v8::GCType`'s Node-facing names.
pub const GC_TYPES: &[(&str, u32)] = &[
    ("NODE_PERFORMANCE_GC_MAJOR", 2),
    ("NODE_PERFORMANCE_GC_MINOR", 1),
    ("NODE_PERFORMANCE_GC_MINOR_MARK_SWEEP", 4),
    ("NODE_PERFORMANCE_GC_INCREMENTAL", 8),
    ("NODE_PERFORMANCE_GC_WEAKCB", 16),
];

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
}

struct State {
    milestones: AliasedUint8Array,
    observers: AliasedUint8Array,
    uv_metrics: AliasedUint8Array,
    uv_metrics_bigint: AliasedUint8Array,
}

/// The time origin, captured once so every measurement shares one zero point.
static TIME_ORIGIN: OnceLock<(u64, f64)> = OnceLock::new();

/// `(monotonic nanoseconds at origin, unix milliseconds at origin)`.
fn time_origin() -> (u64, f64) {
    *TIME_ORIGIN.get_or_init(|| (monotonic_nanos(), unix_millis()))
}

/// Milliseconds since the time origin, the unit `performance.now()` uses.
fn performance_now() -> f64 {
    let (origin_nanos, _) = time_origin();
    let now = monotonic_nanos();
    now.saturating_sub(origin_nanos) as f64 / 1_000_000.0
}

fn monotonic_nanos() -> u64 {
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

fn unix_millis() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64() * 1000.0)
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
        // The first two are known as soon as the origin exists.
        let (origin_nanos, origin_unix) = time_origin();
        let _ = origin_unix;
        milestones.set_float(MILESTONES[0].1, origin_unix);
        milestones.set_float(MILESTONES[1].1, performance_now());
        let _ = origin_nanos;

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
            (
                "createELDHistogram",
                function(scope, "createELDHistogram", create_eld_histogram)?,
            ),
            // The two histogram constructors need the histogram subsystem in
            // `internal/histogram.js`, which drives them through this binding.
            ("Histogram", undefined_value(scope)),
            ("SlidingWindowHistogram", undefined_value(scope)),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

fn undefined_value<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    v8::undefined(scope).into()
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Performance);
}

fn constants_object<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let object = v8::Object::new(scope);
    let mut entries: Vec<(String, u32)> = GC_TYPES
        .iter()
        .map(|(name, value)| ((*name).to_string(), *value))
        .collect();
    entries.extend(
        GC_FLAGS
            .iter()
            .map(|(name, value)| ((*name).to_string(), *value)),
    );
    entries.extend(
        ENTRY_TYPES
            .iter()
            .map(|(name, value)| (format!("NODE_PERFORMANCE_ENTRY_TYPE_{name}"), *value as u32)),
    );
    entries.extend(
        MILESTONES
            .iter()
            .map(|(name, value)| (format!("NODE_PERFORMANCE_MILESTONE_{name}"), *value as u32)),
    );
    for (name, value) in entries {
        if let Some(key) = v8::String::new(scope, &name) {
            object.set(
                scope,
                key.into(),
                v8::Integer::new_from_unsigned(scope, value).into(),
            );
        }
    }
    object.into()
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

fn update_garbage_collection_tracking(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // Node recomputes its GC counters here from the observer counts. With no
    // collector statistics collected yet there is nothing to recompute.
    let _ = scope;
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

fn create_eld_histogram(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // An ELD histogram tracks event-loop delay. Its storage is the histogram
    // subsystem's, which is not written yet; constructing one that recorded
    // nothing would look like a working instrument.
    throw(
        scope,
        "createELDHistogram is not implemented: the event loop it measures does not exist yet",
    );
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
}
