//! The native `Histogram` and `SlidingWindowHistogram` behind `perf_hooks`.
//!
//! `lib/internal/histogram.js` destructures both from
//! `internalBinding('performance')` and builds `perf_hooks.createHistogram()` on
//! top. The JavaScript classes there are the public surface — validation,
//! `RecordableHistogram`, `ClonedHistogram`, the transfer mode — and every one of
//! their accessors forwards to a method on the object this module installs. So
//! the contract here is the *handle* interface, not `perf_hooks`'s: `count()`,
//! `min()`, `percentile(p)`, `percentiles(map)` and the rest are methods the JS
//! layer calls by name, and a missing one turns into
//! `TypeError: this[kHandle].percentiles is not a function`.
//!
//! # Why the numbers come from [`crate::hdr`]
//!
//! Node's `HistogramBase` holds an `hdr_histogram*` from the bundled
//! `deps/histogram`, so `min`/`max`/`percentile` are bucket arithmetic over that
//! library's layout rather than statistics over the recorded samples. A histogram
//! that stored the samples and computed a real minimum would report a different
//! `max` than Node for the same input, because Node reports the *upper edge of the
//! bucket the maximum landed in*. [`crate::hdr`] reproduces that arithmetic; this
//! module is the object plumbing around it.
//!
//! # Counters that live outside the histogram
//!
//! `exceeds_`, `prev_` and `reset_count_` are fields of Node's `Histogram` class
//! rather than of `hdr_histogram`, and each has a behaviour that follows from
//! that: `add` sums `exceeds_` across both, `subtract` decrements it and bumps
//! `reset_count_`, and `recordDelta` keeps `prev_` so the first call records
//! nothing. They are [`HistogramState`] fields here for the same reason.
//!
//! `meanBigInt` and `stddevBigInt` are deliberately absent, because they are
//! absent in Node too: the native `HistogramImpl` has no such method and
//! `lib/internal/histogram.js` defines no such accessor, so both read `undefined`
//! on a real histogram. Installing them would be a divergence, not an improvement.
//!
//! # Why the state is reached through a tag rather than a scope
//!
//! Every method receives `this` as an arbitrary object. The authoritative answer to
//! "is this one of mine" has to be available without a `v8::PinScope`, because the
//! accessor bodies need the scope themselves to allocate their return value, and
//! holding a borrow of it while validating `this` makes every one of them a double
//! borrow. So the internal field holds a pointer to a [`HistogramCell`] whose first
//! word is a tag only this module writes: a foreign object either has no internal
//! field or holds something whose first word is not a tag, and both are rejected
//! without touching the scope.

use std::cell::RefCell;
use std::ffi::c_void;

use rn_v8_sys::v8;

use crate::hdr::{HdrHistogram, Layout};

/// The internal field holding the state cell.
pub(crate) const STATE_FIELD: i32 = 0;

/// The word that marks an allocation as one of this module's histogram cells.
///
/// Written when the cell is boxed and cleared when the finalizer frees it, so a
/// stale pointer reads a zero tag rather than a freed cell's contents.
const CELL_TAG: u64 = 0x5045_5246_4849_5354; // "PERFHIST"

/// The same, for a sliding-window cell.
const SLIDING_TAG: u64 = 0x5045_5246_534C_4944; // "PERFSLID"

/// The boxed histogram state behind one JavaScript handle.
pub(crate) struct HistogramCell {
    tag: u64,
    state: RefCell<HistogramState>,
}

/// The boxed sliding-window state behind one JavaScript handle.
struct SlidingCell {
    tag: u64,
    state: RefCell<SlidingState>,
}

/// Everything Node keeps beside the `hdr_histogram`.
pub struct HistogramState {
    /// The recorded data.
    pub histogram: HdrHistogram,
    /// `prev_`: the `uv_hrtime()` of the previous `recordDelta`.
    pub prev: u64,
    /// `reset_count_`: bumped by `reset()` and `subtract()`.
    pub reset_count: u64,
    /// `exceeds_`: how many values were rejected as out of range.
    pub exceeds: u64,
    /// EWMA smoothing factor, `1 - 2^(-1/halfLife)`; `0` disables the EWMA.
    pub ewma_alpha: f64,
    /// EWMA mean, meaningful only when `ewma_initialized`.
    pub ewma_mean: f64,
    /// EWMA variance, from which `ewmaStddev` is derived.
    pub ewma_variance: f64,
    /// Whether at least one value has been fed to the EWMA.
    pub ewma_initialized: bool,
    /// `threshold_`: the SLO boundary the binary EWMA tracks.
    pub threshold: i64,
    /// EWMA of "this sample exceeded `threshold`".
    pub ewma_error_rate: f64,
}

impl HistogramState {
    /// `Histogram::Histogram`: derive the EWMA factor from the half life.
    ///
    /// `alpha = 1 - exp(-ln(2) / halfLife)`, the half-life decay Node uses; a half
    /// life of `0` leaves `alpha` at `0`, which disables the EWMA rather than
    /// dividing by zero.
    pub fn new(histogram: HdrHistogram, half_life: f64, threshold: i64) -> Self {
        let ewma_alpha = if half_life > 0.0 {
            1.0 - (-std::f64::consts::LN_2 / half_life).exp()
        } else {
            0.0
        };
        Self {
            histogram,
            prev: 0,
            reset_count: 0,
            exceeds: 0,
            ewma_alpha,
            ewma_mean: 0.0,
            ewma_variance: 0.0,
            ewma_initialized: false,
            threshold,
            ewma_error_rate: 0.0,
        }
    }

    /// `Histogram::UpdateEwma`, called after a successful record.
    fn update_ewma(&mut self, value: f64) {
        if self.ewma_alpha <= 0.0 {
            return;
        }
        if !self.ewma_initialized {
            self.ewma_mean = value;
            self.ewma_variance = 0.0;
            self.ewma_initialized = true;
            if self.threshold > 0 {
                self.ewma_error_rate = if value > self.threshold as f64 {
                    1.0
                } else {
                    0.0
                };
            }
            return;
        }
        let diff = value - self.ewma_mean;
        self.ewma_mean += self.ewma_alpha * diff;
        self.ewma_variance =
            (1.0 - self.ewma_alpha) * (self.ewma_variance + self.ewma_alpha * diff * diff);

        if self.threshold > 0 {
            let exceeded = if value > self.threshold as f64 {
                1.0
            } else {
                0.0
            };
            self.ewma_error_rate += self.ewma_alpha * (exceeded - self.ewma_error_rate);
        }
    }

    /// `Histogram::Record`: record, or count the value as exceeding.
    pub fn record(&mut self, value: i64) {
        if self.histogram.record(value) {
            self.update_ewma(value as f64);
        } else {
            self.exceeds += 1;
        }
    }

    /// `Histogram::RecordCorrected`.
    pub fn record_corrected(&mut self, value: i64, expected_interval: i64) {
        if self.histogram.record_corrected(value, expected_interval) {
            self.update_ewma(value as f64);
        } else {
            self.exceeds += 1;
        }
    }

    /// `Histogram::RecordDelta`: record the time since the previous call.
    ///
    /// Returns the delta in nanoseconds. The first call only establishes the
    /// reference point, so it records nothing and returns `0` — which is what makes
    /// an event-loop-delay histogram's first interval silent.
    pub fn record_delta(&mut self) -> u64 {
        let time = crate::monotonic_nanos();
        let mut delta = 0_i64;
        if self.prev > 0 {
            // `CHECK_GE(time, prev_)`: a clock that went backwards would make the
            // delta negative and the record would be silently rejected.
            delta = time.saturating_sub(self.prev) as i64;
            if self.histogram.record(delta) {
                self.update_ewma(delta as f64);
            } else {
                self.exceeds += 1;
            }
        }
        self.prev = time;
        delta as u64
    }

    /// `Histogram::Reset`.
    pub fn reset(&mut self) {
        self.histogram.reset();
        self.reset_count += 1;
        self.exceeds = 0;
        self.prev = 0;
        self.ewma_mean = 0.0;
        self.ewma_variance = 0.0;
        self.ewma_error_rate = 0.0;
        self.ewma_initialized = false;
    }

    /// `Histogram::Subtract`: remove `other`'s counts and report what was dropped.
    pub fn subtract(&mut self, other: &HistogramState) -> i64 {
        let dropped = self.histogram.subtract(&other.histogram);
        self.reset_count += 1;
        self.exceeds = self.exceeds.saturating_sub(other.exceeds);
        dropped
    }

    /// `Histogram::Skewness`: third standardised moment over median equivalent
    /// values, `0` below three samples or with no spread.
    pub fn skewness(&self) -> f64 {
        let total = self.histogram.count();
        if total < 3 {
            return 0.0;
        }
        let mean = self.histogram.mean();
        let mut m2 = 0.0_f64;
        let mut m3 = 0.0_f64;
        for bucket in self.histogram.iter_recorded() {
            let dev = bucket.median as f64 - mean;
            let d2 = dev * dev;
            m2 += bucket.count as f64 * d2;
            m3 += bucket.count as f64 * d2 * dev;
        }
        let n = total as f64;
        let variance = m2 / n;
        if variance == 0.0 {
            return 0.0;
        }
        let s3 = variance * variance.sqrt();
        (m3 / n) / s3
    }

    /// `Histogram::Kurtosis`: excess kurtosis, `0` below four samples.
    pub fn kurtosis(&self) -> f64 {
        let total = self.histogram.count();
        if total < 4 {
            return 0.0;
        }
        let mean = self.histogram.mean();
        let mut m2 = 0.0_f64;
        let mut m4 = 0.0_f64;
        for bucket in self.histogram.iter_recorded() {
            let dev = bucket.median as f64 - mean;
            let d2 = dev * dev;
            m2 += bucket.count as f64 * d2;
            m4 += bucket.count as f64 * d2 * d2;
        }
        let n = total as f64;
        let variance = m2 / n;
        if variance == 0.0 {
            return 0.0;
        }
        let s4 = variance * variance;
        (m4 / n) / s4 - 3.0
    }

    /// An independent copy, as `Histogram::Clone` builds for `snapshot()`.
    ///
    /// The recorded data and every counter that survives a copy travel; the
    /// recorded-snapshot cache does not, because it is derived state.
    pub fn snapshot(&self) -> HistogramState {
        HistogramState {
            histogram: self.histogram.clone_recorded(),
            prev: self.prev,
            reset_count: self.reset_count,
            exceeds: self.exceeds,
            ewma_alpha: self.ewma_alpha,
            ewma_mean: self.ewma_mean,
            ewma_variance: self.ewma_variance,
            ewma_initialized: self.ewma_initialized,
            threshold: self.threshold,
            ewma_error_rate: self.ewma_error_rate,
        }
    }
}

/// `Histogram::Cdf`: the share of samples at or below `value`.
///
/// Walks every bucket including empty ones, because the comparison is against the
/// bucket's *highest* equivalent value: a `value` inside a bucket's range has to
/// find that bucket even when it holds nothing, and the loop's second exit covers
/// the case where every sample is below `value`.
pub fn cdf(histogram: &HdrHistogram, value: i64) -> f64 {
    let total = histogram.count();
    if total == 0 {
        return 0.0;
    }
    for bucket in histogram.iter_all() {
        if bucket.highest >= value {
            return bucket.cumulative_count as f64 / total as f64;
        }
        if bucket.cumulative_count >= total {
            break;
        }
    }
    1.0
}

// ---------------------------------------------------------------------------
// Cell plumbing.
// ---------------------------------------------------------------------------

/// Boxes `state` onto `object` and registers the finalizer that frees it.
pub(crate) fn install_state(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    state: HistogramState,
) {
    let pointer = Box::into_raw(Box::new(HistogramCell {
        tag: CELL_TAG,
        state: RefCell::new(state),
    }));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: the pointer came from `Box::into_raw` in this function and no
            // other owner exists; the finalizer runs exactly once. Clearing the tag
            // first makes a stale pointer read as "not a cell".
            let pointer = address as *mut HistogramCell;
            unsafe {
                (*pointer).tag = 0;
                drop(Box::from_raw(pointer));
            }
        }),
    );
    std::mem::forget(weak);
}

/// The live histogram cell behind `object`, or `None` when it is not one of ours.
pub(crate) fn cell_of(object: v8::Local<'_, v8::Object>) -> Option<&'static HistogramCell> {
    // SAFETY: the field is only ever written by `install_state`, which stores a
    // `Box<HistogramCell>`. Only the leading tag word is read through a foreign
    // pointer, which is what makes a foreign object's field harmless.
    let cell = unsafe { tagged_cell::<HistogramCell>(object, CELL_TAG) }?;
    Some(cell)
}

/// Reads `object`'s state field as a `T` whose first word must equal `tag`.
///
/// `T` is one of this module's two cell types, both of which begin with their tag.
/// The field is written by `install_state`/`install_sliding_state` only.
///
/// # Safety
///
/// `T` must be a cell type whose first field is a `u64` tag written by this
/// module. A pointer into any other allocation would be read as one, so this is
/// only sound because nothing else ever writes internal field `STATE_FIELD` of an
/// object built from these templates.
unsafe fn tagged_cell<T>(object: v8::Local<'_, v8::Object>, tag: u64) -> Option<&'static T>
where
    T: CellTag,
{
    if object.internal_field_count() <= STATE_FIELD as usize {
        return None;
    }
    // SAFETY: see the function documentation.
    let pointer =
        unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) } as *const T;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the pointer is either a live cell of ours or an unreadable address;
    // this deliberately only dereferences the tag before deciding. V8 keeps the
    // allocation alive for as long as the object exists, and the caller holds a
    // live handle.
    let cell = unsafe { &*pointer };
    if cell.tag() != tag {
        return None;
    }
    Some(cell)
}

/// The leading tag word of one of this module's cells.
trait CellTag {
    fn tag(&self) -> u64;
}

impl CellTag for HistogramCell {
    fn tag(&self) -> u64 {
        self.tag
    }
}

impl CellTag for SlidingCell {
    fn tag(&self) -> u64 {
        self.tag
    }
}

/// The state pointer for a cell, as `eld`'s sampling callbacks need it.
pub(crate) fn state_pointer(object: v8::Local<'_, v8::Object>) -> *mut RefCell<HistogramState> {
    match cell_of(object) {
        Some(cell) => &cell.state as *const RefCell<HistogramState> as *mut RefCell<HistogramState>,
        None => std::ptr::null_mut(),
    }
}

/// Runs `body` with the state of `args.this()`, which must be a histogram.
///
/// Takes no scope: the accessor bodies need `&mut PinScope` to allocate their
/// return values, and holding a borrow of the scope here would make every one of
/// them a double borrow. The cell tag is the authority instead.
pub(crate) fn with_this<R>(
    args: &v8::FunctionCallbackArguments<'_>,
    body: impl FnOnce(&mut HistogramState) -> R,
) -> Option<R> {
    with_object(args.this(), body)
}

/// Runs `body` with the state of `object`.
pub(crate) fn with_object<R>(
    object: v8::Local<'_, v8::Object>,
    body: impl FnOnce(&mut HistogramState) -> R,
) -> Option<R> {
    let cell = cell_of(object)?;
    let mut state = cell.state.borrow_mut();
    Some(body(&mut state))
}

pub(crate) fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

/// Throws the `ERR_OUT_OF_RANGE` a native range check produces.
pub(crate) fn throw_out_of_range(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        for (key, value) in [("code", "ERR_OUT_OF_RANGE"), ("name", "RangeError")] {
            let (Some(key), Some(value)) =
                (v8::String::new(scope, key), v8::String::new(scope, value))
            else {
                continue;
            };
            object.set(scope, key.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// The `Illegal invocation` a method throws when `this` is not a histogram.
pub(crate) fn throw_illegal_invocation(scope: &mut v8::PinScope<'_, '_>) {
    throw_type_error(scope, "Illegal invocation");
}

/// Reads an argument that may be a Number or a BigInt as an `i64`.
///
/// Returns `Err(())` when the value cannot be represented, which the caller turns
/// into `ERR_OUT_OF_RANGE` — the shape `Int64Value(&lossless)` has in
/// `HistogramBase::New`.
pub(crate) fn int64_from_value(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Result<i64, ()> {
    if value.is_big_int() {
        let Ok(big) = v8::Local::<v8::BigInt>::try_from(value) else {
            return Err(());
        };
        let (converted, lossless) = big.i64_value();
        if lossless {
            Ok(converted)
        } else {
            Err(())
        }
    } else {
        value
            .number_value(scope)
            .map(|number| number as i64)
            .ok_or(())
    }
}

pub(crate) fn method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::Local<'s, v8::FunctionTemplate> {
    // `rn_core::method` is the chokepoint for "Node publishes this through
    // `SetMethod`, so it is not constructible". It sets
    // `ConstructorBehavior::Throw`, which is what this helper spelled out before
    // the chokepoint existed; going through it keeps the audit in
    // `tools/constructible-audit.py` able to see this crate.
    rn_core::method(callback).length(length).build(scope)
}

/// Installs the handle methods every histogram-shaped object offers.
///
/// `lib/internal/histogram.js` calls these by name on the value it got from
/// `new _Histogram(...)`, and `lib/internal/perf/event_loop_delay.js` calls the
/// same set on the object `createELDHistogram` returned. Sharing the table is what
/// makes the ELD handle a drop-in for the plain one; Node gets the same property by
/// having both native classes derive from `HistogramImpl`.
pub(crate) fn add_histogram_methods<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    template: v8::Local<'s, v8::FunctionTemplate>,
) -> Result<(), String> {
    let prototype = template.prototype_template(scope);
    let methods: [(&str, v8::Local<'s, v8::FunctionTemplate>); 34] = [
        ("count", method(scope, 0, histogram_count)),
        ("countBigInt", method(scope, 0, histogram_count_bigint)),
        ("min", method(scope, 0, histogram_min)),
        ("minBigInt", method(scope, 0, histogram_min_bigint)),
        ("max", method(scope, 0, histogram_max)),
        ("maxBigInt", method(scope, 0, histogram_max_bigint)),
        ("mean", method(scope, 0, histogram_mean)),
        ("stddev", method(scope, 0, histogram_stddev)),
        ("exceeds", method(scope, 0, histogram_exceeds)),
        ("exceedsBigInt", method(scope, 0, histogram_exceeds_bigint)),
        ("percentile", method(scope, 1, histogram_percentile)),
        (
            "percentileBigInt",
            method(scope, 1, histogram_percentile_bigint),
        ),
        ("percentiles", method(scope, 1, histogram_percentiles)),
        (
            "percentilesBigInt",
            method(scope, 1, histogram_percentiles_bigint),
        ),
        ("percentilesAt", method(scope, 2, histogram_percentiles_at)),
        ("countAt", method(scope, 1, histogram_count_at)),
        ("cdf", method(scope, 1, histogram_cdf)),
        ("linearBuckets", method(scope, 2, histogram_linear_buckets)),
        ("logBuckets", method(scope, 3, histogram_log_buckets)),
        ("skewness", method(scope, 0, histogram_skewness)),
        ("kurtosis", method(scope, 0, histogram_kurtosis)),
        ("ewmaMean", method(scope, 0, histogram_ewma_mean)),
        ("ewmaStddev", method(scope, 0, histogram_ewma_stddev)),
        ("ewmaErrorRate", method(scope, 0, histogram_ewma_error_rate)),
        ("record", method(scope, 1, histogram_record)),
        ("recordDelta", method(scope, 0, histogram_record_delta)),
        (
            "recordCorrected",
            method(scope, 2, histogram_record_corrected),
        ),
        ("add", method(scope, 1, histogram_add)),
        ("subtract", method(scope, 1, histogram_subtract)),
        ("reset", method(scope, 0, histogram_reset)),
        ("resetCount", method(scope, 0, histogram_reset_count)),
        ("snapshot", method(scope, 0, histogram_snapshot)),
        ("diff", method(scope, 1, histogram_diff)),
        ("export", method(scope, 0, histogram_export)),
    ];
    for (name, function) in methods {
        let key = v8::String::new(scope, name).ok_or("cannot allocate a method name")?;
        prototype.set(key.into(), function.into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The handle methods.
// ---------------------------------------------------------------------------

/// A `number` accessor over the handle state.
macro_rules! number_accessor {
    ($name:ident, $scope:ident, $args:ident, $rv:ident, $body:expr) => {
        fn $name(
            $scope: &mut v8::PinScope<'_, '_>,
            $args: v8::FunctionCallbackArguments<'_>,
            mut $rv: v8::ReturnValue<'_>,
        ) {
            let Some(value) = with_this(&$args, $body) else {
                throw_illegal_invocation($scope);
                return;
            };
            let value: f64 = value;
            $rv.set(v8::Number::new($scope, value).into());
        }
    };
}

/// The same, for an accessor whose value is a `BigInt`.
macro_rules! bigint_accessor {
    ($name:ident, $scope:ident, $args:ident, $rv:ident, $body:expr) => {
        fn $name(
            $scope: &mut v8::PinScope<'_, '_>,
            $args: v8::FunctionCallbackArguments<'_>,
            mut $rv: v8::ReturnValue<'_>,
        ) {
            let Some(value) = with_this(&$args, $body) else {
                throw_illegal_invocation($scope);
                return;
            };
            let value: i64 = value;
            $rv.set(v8::BigInt::new_from_i64($scope, value).into());
        }
    };
}

number_accessor!(
    histogram_count,
    scope,
    args,
    rv,
    |state| state.histogram.count() as f64
);
bigint_accessor!(histogram_count_bigint, scope, args, rv, |state| state
    .histogram
    .count());
number_accessor!(
    histogram_min,
    scope,
    args,
    rv,
    |state| state.histogram.min() as f64
);
bigint_accessor!(histogram_min_bigint, scope, args, rv, |state| state
    .histogram
    .min());
number_accessor!(
    histogram_max,
    scope,
    args,
    rv,
    |state| state.histogram.max() as f64
);
bigint_accessor!(histogram_max_bigint, scope, args, rv, |state| state
    .histogram
    .max());
number_accessor!(histogram_mean, scope, args, rv, |state| state
    .histogram
    .mean());
number_accessor!(histogram_stddev, scope, args, rv, |state| state
    .histogram
    .stddev());
number_accessor!(histogram_exceeds, scope, args, rv, |state| state.exceeds
    as f64);
number_accessor!(
    histogram_reset_count,
    scope,
    args,
    rv,
    |state| state.reset_count as f64
);
number_accessor!(histogram_skewness, scope, args, rv, |state| state
    .skewness());
number_accessor!(histogram_kurtosis, scope, args, rv, |state| state
    .kurtosis());
number_accessor!(histogram_ewma_mean, scope, args, rv, |state| {
    if state.ewma_initialized {
        state.ewma_mean
    } else {
        0.0
    }
});
number_accessor!(histogram_ewma_stddev, scope, args, rv, |state| {
    if state.ewma_initialized {
        state.ewma_variance.sqrt()
    } else {
        0.0
    }
});
number_accessor!(histogram_ewma_error_rate, scope, args, rv, |state| {
    if state.ewma_initialized {
        state.ewma_error_rate
    } else {
        0.0
    }
});

// `exceedsBigInt` is `BigInt::New(isolate, exceeds_)`, which is signed.
bigint_accessor!(
    histogram_exceeds_bigint,
    scope,
    args,
    rv,
    |state| state.exceeds as i64
);

fn histogram_percentile(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(percentile) = args.get(0).number_value(scope) else {
        throw_type_error(scope, "percentile must be a number");
        return;
    };
    // `CHECK_GT(percentile, 0)` / `CHECK_LE(percentile, 100)`: the JS layer has
    // already rejected anything outside the range, so reaching here with a bad
    // value means the caller bypassed it.
    if !(percentile > 0.0 && percentile <= 100.0) {
        throw_out_of_range(scope, "percentile must be > 0 && <= 100");
        return;
    }
    let Some(value) = with_this(&args, |state| {
        state.histogram.value_at_percentile(percentile)
    }) else {
        throw_illegal_invocation(scope);
        return;
    };
    rv.set(v8::Number::new(scope, value as f64).into());
}

fn histogram_percentile_bigint(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(percentile) = args.get(0).number_value(scope) else {
        throw_type_error(scope, "percentile must be a number");
        return;
    };
    if !(percentile > 0.0 && percentile <= 100.0) {
        throw_out_of_range(scope, "percentile must be > 0 && <= 100");
        return;
    }
    let Some(value) = with_this(&args, |state| {
        state.histogram.value_at_percentile(percentile)
    }) else {
        throw_illegal_invocation(scope);
        return;
    };
    rv.set(v8::BigInt::new_from_i64(scope, value).into());
}

fn histogram_percentiles(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(map) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "percentiles expects a Map");
        return;
    };
    let Some(entries) = with_this(&args, |state| state.histogram.percentiles()) else {
        throw_illegal_invocation(scope);
        return;
    };
    fill_map(scope, map, &entries, false);
}

fn histogram_percentiles_bigint(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(map) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "percentilesBigInt expects a Map");
        return;
    };
    let Some(entries) = with_this(&args, |state| state.histogram.percentiles()) else {
        throw_illegal_invocation(scope);
        return;
    };
    fill_map(scope, map, &entries, true);
}

fn histogram_percentiles_at(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(map) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "percentilesAt expects a Map");
        return;
    };
    let Ok(input) = v8::Local::<v8::Float64Array>::try_from(args.get(1)) else {
        throw_type_error(scope, "percentilesAt expects a Float64Array");
        return;
    };
    let length = input.length();
    let mut percentiles = Vec::with_capacity(length);
    for index in 0..length {
        let Some(value) = input.get_index(scope, index as u32) else {
            return;
        };
        percentiles.push(value.number_value(scope).unwrap_or(0.0));
    }
    let Some(values) = with_this(&args, |state| {
        state.histogram.values_at_percentiles(&percentiles)
    }) else {
        throw_illegal_invocation(scope);
        return;
    };
    let entries: Vec<(f64, i64)> = percentiles.iter().copied().zip(values).collect();
    fill_map(scope, map, &entries, false);
}

fn histogram_count_at(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(value) = args.get(0).number_value(scope) else {
        throw_type_error(scope, "countAt expects a number");
        return;
    };
    let Some(count) = with_this(&args, |state| state.histogram.count_at_value(value as i64)) else {
        throw_illegal_invocation(scope);
        return;
    };
    rv.set(v8::Number::new(scope, count as f64).into());
}

fn histogram_cdf(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(value) = args.get(0).number_value(scope) else {
        throw_type_error(scope, "cdf expects a number");
        return;
    };
    let Some(result) = with_this(&args, |state| cdf(&state.histogram, value as i64)) else {
        throw_illegal_invocation(scope);
        return;
    };
    rv.set(v8::Number::new(scope, result).into());
}

fn histogram_linear_buckets(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(step_size) = args.get(0).number_value(scope) else {
        throw_type_error(scope, "linearBuckets expects a step size");
        return;
    };
    let Ok(map) = v8::Local::<v8::Object>::try_from(args.get(1)) else {
        throw_type_error(scope, "linearBuckets expects a Map");
        return;
    };
    let Some(entries) = with_this(&args, |state| {
        state
            .histogram
            .linear_buckets(step_size as i64)
            .into_iter()
            .map(|(value, count)| (value as f64, count))
            .collect::<Vec<(f64, i64)>>()
    }) else {
        throw_illegal_invocation(scope);
        return;
    };
    fill_map(scope, map, &entries, false);
}

fn histogram_log_buckets(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(first_bucket) = args.get(0).number_value(scope) else {
        throw_type_error(scope, "logBuckets expects a first bucket");
        return;
    };
    let Some(log_base) = args.get(1).number_value(scope) else {
        throw_type_error(scope, "logBuckets expects a base");
        return;
    };
    let Ok(map) = v8::Local::<v8::Object>::try_from(args.get(2)) else {
        throw_type_error(scope, "logBuckets expects a Map");
        return;
    };
    let Some(entries) = with_this(&args, |state| {
        state
            .histogram
            .log_buckets(first_bucket as i64, log_base)
            .into_iter()
            .map(|(value, count)| (value as f64, count))
            .collect::<Vec<(f64, i64)>>()
    }) else {
        throw_illegal_invocation(scope);
        return;
    };
    fill_map(scope, map, &entries, false);
}

fn histogram_record(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let value = match int64_from_value(scope, args.get(0)) {
        Ok(value) => value,
        Err(()) => {
            throw_out_of_range(scope, "value is out of range");
            return;
        }
    };
    if value < 0 {
        throw_out_of_range(scope, "value is out of range");
        return;
    }
    if with_this(&args, |state| state.record(value)).is_none() {
        throw_illegal_invocation(scope);
    }
}

fn histogram_record_delta(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if with_this(&args, |state| state.record_delta()).is_none() {
        throw_illegal_invocation(scope);
    }
}

fn histogram_record_corrected(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let value = match int64_from_value(scope, args.get(0)) {
        Ok(value) => value,
        Err(()) => {
            throw_out_of_range(scope, "value is out of range");
            return;
        }
    };
    if value < 0 {
        throw_out_of_range(scope, "value is out of range");
        return;
    }
    let expected_interval = match int64_from_value(scope, args.get(1)) {
        Ok(value) => value,
        Err(()) => {
            throw_out_of_range(scope, "expected_interval is out of range");
            return;
        }
    };
    if expected_interval < 1 {
        throw_out_of_range(scope, "expected_interval is out of range");
        return;
    }
    if with_this(&args, |state| {
        state.record_corrected(value, expected_interval)
    })
    .is_none()
    {
        throw_illegal_invocation(scope);
    }
}

/// Throws the error `DoDiff` reports for the reason the two histograms differ.
///
/// The order matters: `kIncompatible` is decided by the layout, then `kReset` by
/// the reset counters, then `kNotEarlier` by the counts. Node checks them in that
/// order too, so a layout mismatch reads as `ERR_INVALID_ARG_VALUE` even when the
/// counts would also have failed.
fn throw_coded_diff_error(
    scope: &mut v8::PinScope<'_, '_>,
    this: &HistogramState,
    other: &HistogramState,
) {
    let compatible = {
        let a = this.histogram.layout_counts_len();
        let b = other.histogram.layout_counts_len();
        a == b && this.histogram.same_layout(&other.histogram)
    };
    let (code, message) = if !compatible {
        (
            "ERR_INVALID_ARG_VALUE",
            "other must have the same configuration as the histogram",
        )
    } else if this.reset_count != other.reset_count {
        (
            "ERR_INVALID_STATE",
            "Values were removed from the histogram after other was taken",
        )
    } else {
        (
            "ERR_INVALID_ARG_VALUE",
            "other contains values that are not in the histogram",
        )
    };
    throw_coded(scope, code, message, code == "ERR_INVALID_STATE");
}

/// Throws an `Error` (or `TypeError`) carrying `code`.
fn throw_coded(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str, plain_error: bool) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = if plain_error {
        // `ERR_INVALID_STATE` is a plain `Error` with a `code`, not a `TypeError`.
        v8::Exception::error(scope, text)
    } else {
        v8::Exception::type_error(scope, text)
    };
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let Some(key) = v8::String::new(scope, "code") {
            if let Some(value) = v8::String::new(scope, code) {
                object.set(scope, key.into(), value.into());
            }
        }
    }
    scope.throw_exception(exception);
}

fn histogram_reset(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if with_this(&args, |state| state.reset()).is_none() {
        throw_illegal_invocation(scope);
    }
}

/// `add(other)`: merge `other`'s samples into this histogram.
///
/// `h.add(h)` is legal and Node gives it a single write lock. A `RefCell` cannot
/// borrow the same cell twice, so the self case copies `other` first. That is the
/// only difference from Node's path and it produces the same counts, because
/// `hdr_add` reads `other` without mutating it.
fn histogram_add(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(other_object) = v8::Local::<v8::Object>::try_from(args.get(0)).ok() else {
        throw_type_error(scope, "add expects a Histogram");
        return;
    };
    let (Some(this_cell), Some(other_cell)) = (cell_of(args.this()), cell_of(other_object)) else {
        throw_illegal_invocation(scope);
        return;
    };
    let dropped = if std::ptr::eq(this_cell, other_cell) {
        let copy = other_cell.state.borrow().snapshot();
        let mut this = this_cell.state.borrow_mut();
        this.exceeds += copy.exceeds;
        this.histogram.add(&copy.histogram)
    } else {
        let other = other_cell.state.borrow();
        let mut this = this_cell.state.borrow_mut();
        this.exceeds += other.exceeds;
        if other.prev > this.prev {
            this.prev = other.prev;
        }
        this.histogram.add(&other.histogram)
    };
    rv.set(v8::Number::new(scope, dropped as f64).into());
}

/// `subtract(other)`: remove `other`'s counts from this histogram.
fn histogram_subtract(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(other_object) = v8::Local::<v8::Object>::try_from(args.get(0)).ok() else {
        throw_type_error(scope, "subtract expects a Histogram");
        return;
    };
    let (Some(this_cell), Some(other_cell)) = (cell_of(args.this()), cell_of(other_object)) else {
        throw_illegal_invocation(scope);
        return;
    };
    let dropped = if std::ptr::eq(this_cell, other_cell) {
        let copy = other_cell.state.borrow().snapshot();
        let mut this = this_cell.state.borrow_mut();
        this.subtract(&copy)
    } else {
        let other = other_cell.state.borrow();
        let mut this = this_cell.state.borrow_mut();
        this.subtract(&other)
    };
    rv.set(v8::Number::new(scope, dropped as f64).into());
}

/// `export()`: the CBOR payload `importHistogram` reads.
fn histogram_export(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(bytes) = with_this(&args, |state| {
        crate::cbor::export(
            &state.histogram,
            crate::cbor::EwmaExport {
                alpha: state.ewma_alpha,
                mean: state.ewma_mean,
                variance: state.ewma_variance,
                error_rate: state.ewma_error_rate,
                threshold: state.threshold,
            },
        )
    }) else {
        throw_illegal_invocation(scope);
        return;
    };
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let Some(array) = v8::Uint8Array::new(scope, buffer, 0, buffer.byte_length()) else {
        return;
    };
    rv.set(array.into());
}

/// `importHistogram(data)`: rebuild a handle from an `export()` payload.
fn histogram_import(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Ok(view) = v8::Local::<v8::Uint8Array>::try_from(args.get(0)) else {
        throw_type_error(scope, "importHistogram expects a Uint8Array");
        return;
    };
    let mut bytes = vec![0_u8; view.byte_length()];
    let copied = view.copy_contents(&mut bytes);
    bytes.truncate(copied);
    let Some(imported) = crate::cbor::import(&bytes) else {
        // `ERR_INVALID_ARG_VALUE`, matching `DoImport`'s rejection for a payload
        // `Histogram::Import` refuses.
        throw_coded(
            scope,
            "ERR_INVALID_ARG_VALUE",
            "Invalid histogram export data",
            false,
        );
        return;
    };
    let mut state = HistogramState::new(
        imported.histogram,
        // `Import` recomputes the half life from `alpha` so a later record
        // continues the same smoothing; a payload without an EWMA leaves it off.
        if imported.ewma.alpha > 0.0 && imported.ewma.alpha < 1.0 {
            -1.0 / (1.0 - imported.ewma.alpha).log2()
        } else {
            0.0
        },
        imported.ewma.threshold,
    );
    if imported.ewma.alpha > 0.0 {
        state.ewma_mean = imported.ewma.mean;
        state.ewma_variance = imported.ewma.variance;
        state.ewma_error_rate = imported.ewma.error_rate;
        state.ewma_initialized = true;
    }
    if let Some(object) = new_histogram_object(scope, state) {
        rv.set(object.into());
    }
}

/// `Histogram.import(data)`, the static entry `importHistogram` calls.
fn histogram_import_static(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    rv: v8::ReturnValue<'_>,
) {
    histogram_import(scope, args, rv);
}

/// `snapshot()`: a new handle holding a copy of this one's data.
fn histogram_snapshot(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(snapshot) = with_this(&args, |state| state.snapshot()) else {
        throw_illegal_invocation(scope);
        return;
    };
    if let Some(object) = new_histogram_object(scope, snapshot) {
        rv.set(object.into());
    }
}

/// `diff(other)`: a new handle holding the samples recorded since `other`.
fn histogram_diff(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let (Some(this_cell), Some(other_cell)) = (
        cell_of(args.this()),
        v8::Local::<v8::Object>::try_from(args.get(0))
            .ok()
            .and_then(cell_of),
    ) else {
        throw_illegal_invocation(scope);
        return;
    };
    if std::ptr::eq(this_cell, other_cell) {
        throw_type_error(scope, "the histograms are not comparable");
        return;
    }
    let difference = {
        let other = other_cell.state.borrow();
        let this = this_cell.state.borrow();
        this.histogram
            .diff(&other.histogram, this.reset_count, other.reset_count)
            .map(|histogram| {
                let mut state = HistogramState::new(histogram, 0.0, 0);
                // `Histogram::Diff` carries only the difference in `exceeds_`; the
                // reset counter and the EWMA cannot be subtracted and stay at their
                // initial values in Node too.
                state.exceeds = this.exceeds.saturating_sub(other.exceeds);
                state
            })
    };
    let Some(difference) = difference else {
        // `DoDiff` distinguishes three failures, and a caller branches on the
        // code, so collapsing them into one `TypeError` would be a real
        // regression rather than a cosmetic one.
        throw_coded_diff_error(scope, &this_cell.state.borrow(), &other_cell.state.borrow());
        return;
    };
    if let Some(object) = new_histogram_object(scope, difference) {
        rv.set(object.into());
    }
}

// ---------------------------------------------------------------------------
// Templates.
// ---------------------------------------------------------------------------

thread_local! {
    /// The `Histogram` instance template, so `snapshot()` and `diff()` can build a
    /// second handle of the same shape without a second `FunctionTemplate`.
    static HISTOGRAM_TEMPLATE: RefCell<Option<v8::Global<v8::FunctionTemplate>>> =
        const { RefCell::new(None) };
    static SLIDING_TEMPLATE: RefCell<Option<v8::Global<v8::FunctionTemplate>>> =
        const { RefCell::new(None) };
}

/// Builds a new handle object of the `Histogram` template holding `state`.
///
/// `HistogramBase::Create` in Node: `snapshot()` and `diff()` return one of these,
/// which the JS layer then wraps in `ClonedHistogram`.
fn new_histogram_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: HistogramState,
) -> Option<v8::Local<'s, v8::Object>> {
    let template = HISTOGRAM_TEMPLATE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|template| v8::Local::new(scope, template))
    })?;
    let instance = template.instance_template(scope);
    let object = instance.new_instance(scope)?;
    install_state(scope, object, state);
    Some(object)
}

/// `new Histogram(lowest, highest, figures, halfLife, threshold)`.
///
/// The `Histogram` name is Node's internal one: `perf_hooks` wraps it in
/// `RecordableHistogram`, and the JS class never lets a caller construct this
/// directly (`Histogram`'s JS constructor throws `ERR_ILLEGAL_CONSTRUCTOR`).
fn histogram_new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(scope, "Histogram cannot be invoked without 'new'");
        return;
    }
    let lowest = match int64_from_value(scope, args.get(0)) {
        Ok(value) => value,
        Err(()) => {
            throw_out_of_range(scope, "options.lowest is out of range");
            return;
        }
    };
    let highest = match int64_from_value(scope, args.get(1)) {
        Ok(value) => value,
        Err(()) => {
            throw_out_of_range(scope, "options.highest is out of range");
            return;
        }
    };
    let Some(figures) = args.get(2).uint32_value(scope) else {
        throw_type_error(scope, "figures must be an unsigned integer");
        return;
    };
    let half_life = args.get(3).number_value(scope).unwrap_or(0.0);
    let threshold = args
        .get(4)
        .number_value(scope)
        .map(|value| value as i64)
        .unwrap_or(0);

    let Ok(layout) = Layout::new(lowest, highest, figures as i32) else {
        throw_out_of_range(scope, "Invalid histogram options");
        return;
    };
    let object = args.this();
    install_state(
        scope,
        object,
        HistogramState::new(HdrHistogram::new(layout), half_life, threshold),
    );
    rv.set(object.into());
}

/// Builds the `Histogram` constructor.
///
/// `rn_core::class` rather than `rn_core::method`: `lib/internal/histogram.js`
/// writes `new _Histogram(...)`, so this member must accept `new`. Its *prototype*
/// methods go through [`method`], which is the distinction Node's
/// `SetConstructorFunction` + `SetProtoMethod` pair draws.
pub fn histogram_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::class(histogram_new).length(5).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    // Node names this class `Histogram` even though `perf_hooks` shows
    // `RecordableHistogram`: `inspect()` of the raw handle prints this name.
    if let Some(name) = v8::String::new(scope, "Histogram") {
        template.set_class_name(name);
    }
    add_histogram_methods(scope, template)?;

    // `Histogram.import(data)`: `HistogramBase::Initialize` installs this on the
    // *constructor* with `SetMethodNoSideEffect`, and `importHistogram` in
    // `lib/internal/histogram.js` is `_Histogram.import(data)`.
    let import_key = v8::String::new(scope, "import").ok_or("cannot allocate `import`")?;
    template.set(
        import_key.into(),
        method(scope, 1, histogram_import_static).into(),
    );

    HISTOGRAM_TEMPLATE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, template)));
    let function = template
        .get_function(scope)
        .ok_or_else(|| "cannot allocate the Histogram constructor".to_string())?;
    Ok(function.into())
}

// ---------------------------------------------------------------------------
// The sliding window.
// ---------------------------------------------------------------------------

/// The ring of chunks a `SlidingWindowHistogram` keeps.
///
/// The layout is Node's `SlidingWindowHistogram`: `chunks` holds a histogram per
/// slot, `generations` records which generation each slot holds, and
/// [`NO_GENERATION`] marks an empty slot. A slot is reused for a new generation by
/// resetting the histogram already there, which is what keeps the ring's
/// allocation bounded.
pub struct SlidingState {
    layout: Layout,
    chunks: Vec<Option<HdrHistogram>>,
    generations: Vec<u64>,
    /// The histogram moved into the first slot that needs one.
    spare: Option<HdrHistogram>,
    time_based: bool,
    rotate_at: u64,
    /// `uv_hrtime()` at construction, the origin for time-based generations.
    origin: u64,
    current_generation: u64,
    records_in_current_chunk: u64,
    has_count_records: bool,
}

/// `kNoGeneration`: an empty slot.
pub const NO_GENERATION: u64 = u64::MAX;

impl SlidingState {
    fn new(layout: Layout, chunk_count: usize, time_based: bool, rotate_at: u64) -> Self {
        Self {
            layout,
            chunks: (0..chunk_count).map(|_| None).collect(),
            generations: vec![NO_GENERATION; chunk_count],
            spare: Some(HdrHistogram::new(layout)),
            time_based,
            rotate_at,
            origin: crate::monotonic_nanos(),
            current_generation: 0,
            records_in_current_chunk: 0,
            has_count_records: false,
        }
    }

    /// `CurrentTimeGeneration`.
    fn current_time_generation(&self) -> u64 {
        crate::monotonic_nanos().saturating_sub(self.origin) / self.rotate_at
    }

    /// `GetChunk`: the histogram for `generation`, reset or allocated as needed.
    ///
    /// Takes the slot out and puts it back rather than returning a borrow of the
    /// `Vec`. That is what lets the `else` branch allocate without holding a
    /// second mutable borrow of `self`, and it is why this cannot fail: every arm
    /// either found a histogram or installed one.
    fn chunk_for(&mut self, generation: u64) -> Option<&mut HdrHistogram> {
        let index = (generation % self.chunks.len() as u64) as usize;
        if self.generations[index] != generation {
            let mut chunk = match self.chunks[index].take() {
                Some(chunk) => chunk,
                None => match self.spare.take() {
                    Some(spare) => spare,
                    None => HdrHistogram::new(self.layout),
                },
            };
            // A reused slot holds the previous generation's samples, so it has to
            // be cleared; a freshly allocated one is already empty.
            chunk.reset();
            self.chunks[index] = Some(chunk);
            self.generations[index] = generation;
        }
        self.chunks[index].as_mut()
    }

    /// `RecordValue`. Returns `false` when no chunk could be produced.
    fn record(&mut self, value: i64) -> bool {
        let generation = if self.time_based {
            self.current_time_generation()
        } else if self.records_in_current_chunk == self.rotate_at {
            self.current_generation + 1
        } else {
            self.current_generation
        };
        let Some(chunk) = self.chunk_for(generation) else {
            return false;
        };
        chunk.record(value);
        if !self.time_based {
            if generation != self.current_generation {
                self.current_generation = generation;
                self.records_in_current_chunk = 0;
            }
            self.records_in_current_chunk += 1;
            self.has_count_records = true;
        }
        true
    }

    /// `CreateSnapshot`: merge the chunks still inside the window.
    fn snapshot(&self) -> HdrHistogram {
        let mut snapshot = HdrHistogram::new(self.layout);
        let current_generation = if self.time_based {
            self.current_time_generation()
        } else {
            if !self.has_count_records {
                return snapshot;
            }
            self.current_generation
        };
        let chunk_count = self.chunks.len() as u64;
        for (index, chunk) in self.chunks.iter().enumerate() {
            let generation = self.generations[index];
            if generation == NO_GENERATION
                || generation > current_generation
                || current_generation - generation >= chunk_count
            {
                continue;
            }
            if let Some(chunk) = chunk {
                snapshot.add(chunk);
            }
        }
        snapshot
    }

    /// `ResetWindow`.
    fn reset(&mut self) {
        for generation in self.generations.iter_mut() {
            *generation = NO_GENERATION;
        }
        self.origin = crate::monotonic_nanos();
        self.current_generation = 0;
        self.records_in_current_chunk = 0;
        self.has_count_records = false;
    }
}

fn install_sliding_state(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    state: SlidingState,
) {
    let pointer = Box::into_raw(Box::new(SlidingCell {
        tag: SLIDING_TAG,
        state: RefCell::new(state),
    }));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: as in `install_state`.
            let pointer = address as *mut SlidingCell;
            unsafe {
                (*pointer).tag = 0;
                drop(Box::from_raw(pointer));
            }
        }),
    );
    std::mem::forget(weak);
}

fn sliding_cell_of(object: v8::Local<'_, v8::Object>) -> Option<&'static SlidingCell> {
    // SAFETY: as in `cell_of`.
    unsafe { tagged_cell::<SlidingCell>(object, SLIDING_TAG) }
}

fn with_sliding<R>(
    args: &v8::FunctionCallbackArguments<'_>,
    body: impl FnOnce(&mut SlidingState) -> R,
) -> Option<R> {
    let cell = sliding_cell_of(args.this())?;
    let mut state = cell.state.borrow_mut();
    Some(body(&mut state))
}

fn sliding_record(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let value = match int64_from_value(scope, args.get(0)) {
        Ok(value) => value,
        Err(()) => {
            throw_out_of_range(scope, "value is out of range");
            return;
        }
    };
    if value < 0 {
        throw_out_of_range(scope, "value is out of range");
        return;
    }
    match with_sliding(&args, |state| state.record(value)) {
        Some(true) => {}
        Some(false) => throw_out_of_range(scope, "memory allocation failed"),
        None => throw_illegal_invocation(scope),
    }
}

fn sliding_snapshot(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(snapshot) = with_sliding(&args, |state| HistogramState::new(state.snapshot(), 0.0, 0))
    else {
        throw_illegal_invocation(scope);
        return;
    };
    if let Some(object) = new_histogram_object(scope, snapshot) {
        rv.set(object.into());
    }
}

fn sliding_reset(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if with_sliding(&args, |state| state.reset()).is_none() {
        throw_illegal_invocation(scope);
    }
}

/// `new SlidingWindowHistogram(lowest, highest, figures, chunks, timeBased, rotateAt)`.
fn sliding_new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(
            scope,
            "SlidingWindowHistogram cannot be invoked without 'new'",
        );
        return;
    }
    let lowest = match int64_from_value(scope, args.get(0)) {
        Ok(value) => value,
        Err(()) => {
            throw_out_of_range(scope, "options.lowest is out of range");
            return;
        }
    };
    let highest = match int64_from_value(scope, args.get(1)) {
        Ok(value) => value,
        Err(()) => {
            throw_out_of_range(scope, "options.highest is out of range");
            return;
        }
    };
    let Some(figures) = args.get(2).uint32_value(scope) else {
        throw_type_error(scope, "figures must be an unsigned integer");
        return;
    };
    let Some(chunk_count) = args.get(3).uint32_value(scope) else {
        throw_type_error(scope, "chunks must be an unsigned integer");
        return;
    };
    if chunk_count == 0 {
        throw_out_of_range(scope, "options.chunks is out of range");
        return;
    }
    let time_based = args.get(4).boolean_value(scope);
    let rotate_at = match v8::Local::<v8::BigInt>::try_from(args.get(5)) {
        Ok(big) => {
            let (converted, lossless) = big.u64_value();
            if lossless {
                converted
            } else {
                throw_out_of_range(scope, "rotation interval is out of range");
                return;
            }
        }
        Err(_) => match args.get(5).number_value(scope) {
            Some(value) if value > 0.0 => value as u64,
            _ => {
                throw_out_of_range(scope, "rotation interval is out of range");
                return;
            }
        },
    };
    if rotate_at == 0 {
        throw_out_of_range(scope, "rotation interval is out of range");
        return;
    }

    let Ok(layout) = Layout::new(lowest, highest, figures as i32) else {
        throw_out_of_range(scope, "Invalid histogram options");
        return;
    };
    let object = args.this();
    install_sliding_state(
        scope,
        object,
        SlidingState::new(layout, chunk_count as usize, time_based, rotate_at),
    );
    rv.set(object.into());
}

/// Builds the `SlidingWindowHistogram` constructor.
///
/// A class for the same reason as [`histogram_constructor`]:
/// `createSlidingWindowHistogram` does `new _SlidingWindowHistogram(...)`.
pub fn sliding_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::class(sliding_new).length(6).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    if let Some(name) = v8::String::new(scope, "SlidingWindowHistogram") {
        template.set_class_name(name);
    }

    let prototype = template.prototype_template(scope);
    let methods: [(&str, v8::Local<'s, v8::FunctionTemplate>); 3] = [
        ("record", method(scope, 1, sliding_record)),
        ("snapshot", method(scope, 0, sliding_snapshot)),
        ("reset", method(scope, 0, sliding_reset)),
    ];
    for (name, function) in methods {
        let key = v8::String::new(scope, name).ok_or("cannot allocate a method name")?;
        prototype.set(key.into(), function.into());
    }

    SLIDING_TEMPLATE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, template)));
    let function = template
        .get_function(scope)
        .ok_or_else(|| "cannot allocate the SlidingWindowHistogram constructor".to_string())?;
    Ok(function.into())
}

// ---------------------------------------------------------------------------
// Map filling.
// ---------------------------------------------------------------------------

/// Inserts `entries` into `map` through `Map.prototype.set`.
///
/// `Object::set` would stringify a numeric key, so `map.get(50)` would miss the
/// `"50"` property `percentiles` had written. The builtin is looked up per call
/// rather than cached: `lib/**` captures its own primordials, and this has to use
/// the one the caller's `Map` was built from.
fn fill_map(
    scope: &mut v8::PinScope<'_, '_>,
    map: v8::Local<'_, v8::Object>,
    entries: &[(f64, i64)],
    bigint: bool,
) {
    let Some(set) = map_set_function(scope) else {
        return;
    };
    for (key, value) in entries {
        let key: v8::Local<v8::Value> = v8::Number::new(scope, *key).into();
        let value: v8::Local<v8::Value> = if bigint {
            v8::BigInt::new_from_i64(scope, *value).into()
        } else {
            v8::Number::new(scope, *value as f64).into()
        };
        let _ = set.call(scope, map.into(), &[key, value]);
    }
}

fn map_set_function<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let map_name = v8::String::new(scope, "Map")?;
    let constructor = global.get(scope, map_name.into())?;
    let constructor = v8::Local::<v8::Object>::try_from(constructor).ok()?;
    let prototype_key = v8::String::new(scope, "prototype")?;
    let prototype = constructor.get(scope, prototype_key.into())?;
    let prototype = v8::Local::<v8::Object>::try_from(prototype).ok()?;
    let set_key = v8::String::new(scope, "set")?;
    let set = prototype.get(scope, set_key.into())?;
    v8::Local::<v8::Function>::try_from(set).ok()
}

// ---------------------------------------------------------------------------
// The ELD half installs its sampling state in field 1 through this.
// ---------------------------------------------------------------------------

/// Boxes an ELD sampling state into field 1 of `object`.
pub(crate) fn install_eld_state(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    state: crate::eld::EldState,
) {
    let pointer = Box::into_raw(Box::new(RefCell::new(state)));
    object.set_aligned_pointer_in_internal_field(1, pointer.cast::<c_void>().cast_const(), 0);
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: as in `install_state`. The sampling state releases its libuv
            // handles before the allocation goes.
            crate::eld::release_handles(address as *mut RefCell<crate::eld::EldState>);
            drop(unsafe { Box::from_raw(address as *mut RefCell<crate::eld::EldState>) });
        }),
    );
    std::mem::forget(weak);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EWMA factor is the half-life decay Node derives, and a zero half life
    /// disables it rather than producing a division by zero.
    #[test]
    fn the_ewma_factor_follows_the_half_life() {
        let layout = Layout::new(1, 1000, 3).expect("valid");
        let disabled = HistogramState::new(HdrHistogram::new(layout), 0.0, 0);
        assert_eq!(disabled.ewma_alpha, 0.0);

        let half_life = HistogramState::new(HdrHistogram::new(layout), 1.0, 0);
        // alpha = 1 - 2^(-1/1) = 0.5
        assert!((half_life.ewma_alpha - 0.5).abs() < 1e-12);
    }

    /// `cdf` reports `0` for an empty histogram and `1` above every sample.
    #[test]
    fn the_cdf_covers_the_recorded_range() {
        let layout = Layout::new(1, 1000, 2).expect("valid");
        let mut histogram = HdrHistogram::new(layout);
        assert_eq!(cdf(&histogram, 10), 0.0);
        for value in [10, 20, 30, 40] {
            histogram.record(value);
        }
        // The oracle reports 0 at 9, 0.25 at 10 and 0.75 at 30: each sample is
        // its own bucket at this layout, so the cdf steps by one quarter.
        assert_eq!(cdf(&histogram, 9), 0.0);
        assert!((cdf(&histogram, 10) - 0.25).abs() < 1e-12);
        assert!((cdf(&histogram, 30) - 0.75).abs() < 1e-12);
        assert!((cdf(&histogram, 41) - 1.0).abs() < 1e-12);
    }

    /// The sliding window keeps only the generations inside its ring, so a snapshot
    /// after more rotations than chunks holds the newest ones.
    #[test]
    fn the_sliding_window_forgets_generations_outside_the_ring() {
        let layout = Layout::new(1, 1000, 2).expect("valid");
        // Two records per chunk and two chunks hold four records exactly, so all
        // four survive; the fifth is where a chunk is reused. The oracle reports
        // count 4 for this input and count 6 after twenty records with three
        // chunks, which is the same rule.
        let mut state = SlidingState::new(layout, 2, false, 2);
        for value in [10, 20, 30, 40] {
            state.record(value);
        }
        assert_eq!(state.snapshot().count(), 4);
        state.record(50);
        let snapshot = state.snapshot();
        assert_eq!(snapshot.count(), 3);
        assert_eq!(snapshot.min(), 30);
    }
}
