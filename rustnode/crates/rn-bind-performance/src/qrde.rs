//! `qrde`: quantile-respectful density estimation by Harrell-Davis quantiles.
//!
//! Port of `CalculateQrde` and the helpers above it in `src/histogram.cc`. The
//! shape of the computation is not a textbook QRDE:
//!
//! * The quantile at probability `p` is the integral of the inverse CDF under a
//!   `Beta(a, b)` weight with `a = (n+1)p` and `b = (n+1)(1-p)`. Node evaluates
//!   that integral bucket by bucket over the *recorded* buckets, using the
//!   regularized incomplete beta function for the rank mass and its front term
//!   for the within-bucket first moment. Reproducing the numbers means
//!   reproducing that sum, not just the beta parameters: the two agree only in
//!   the limit.
//! * The first and last quantiles are the first bucket's lower endpoint and the
//!   last bucket's upper endpoint rather than integrals, so the outer bins are
//!   pinned to the data's range.
//! * Monotonicity is repaired after the fact: a quantile below its predecessor is
//!   raised to it and counted in `corrections`.
//!
//! # Dequantization
//!
//! A bucket holding more than one sample stands for a range of values, and the
//! three modes decide whether that range is spread out:
//!
//! * `none` puts every sample at the bucket's median equivalent value;
//! * `hdr` spreads only where the bucket is wider than one unit
//!   (`resolution > 1`), which is where HDR quantization actually loses detail;
//! * `all` spreads every bucket with more than one sample, including the
//!   single-unit ones.
//!
//! # Why the work runs on the threadpool
//!
//! Node's `GetQrde` returns a promise and runs `CalculateQrde` on a
//! `ThreadPoolWork`, so a thousand-bin request over a million samples does not
//! block the event loop. The `qrde` tests depend on that directly: one records
//! into the histogram *after* scheduling and asserts the result describes the
//! earlier state, and the worker test exits while a job is in flight. Taking the
//! snapshot before returning is what makes the first correct; the second only
//! needs the job to be cancellable, which `rn_uv::threadpool` provides.

use std::sync::{Arc, Mutex, MutexGuard};

use rn_v8_sys::v8;

use crate::beta::{
    beta_parameters, clamp, reflect_beta_parameters, regularized_incomplete_beta_with_front,
    BetaParameters,
};
use crate::hdr::{HdrHistogram, RecordedBucket};

/// `QrdeDequantization`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dequantization {
    None,
    Hdr,
    All,
}

impl Dequantization {
    /// The mode from the integer `lib/internal/histogram.js` passes, or `None`
    /// when it is outside the enum. Node `CHECK`s the bound, so an out-of-range
    /// value is a caller bug rather than something to guess at.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Hdr),
            2 => Some(Self::All),
            _ => None,
        }
    }

    /// `QrdeDequantizationName`, the string the result object carries back.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Hdr => "hdr",
            Self::All => "all",
        }
    }
}

/// `Histogram::RecordedSnapshot`: the buckets `qrde` integrates over, plus the
/// total they add up to.
///
/// Shared rather than cloned because the cached-snapshot path hands the same
/// allocation to later calls, exactly as `CacheRecordedSnapshot` stores a
/// `shared_ptr`.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub buckets: Vec<RecordedBucket>,
    pub total_count: i64,
}

impl Snapshot {
    /// `Histogram::BuildRecordedSnapshot`.
    pub fn build(histogram: &HdrHistogram) -> Self {
        let total_count = histogram.count();
        if total_count == 0 {
            return Self::default();
        }
        Self {
            buckets: histogram.recorded_buckets(),
            total_count,
        }
    }
}

/// The quantiles and densities `CalculateQrde` produces.
#[derive(Debug, Default)]
pub struct QrdeResult {
    pub quantiles: Vec<f64>,
    pub densities: Vec<f64>,
    pub corrections: usize,
}

/// `QrdeShouldDequantize`.
fn should_dequantize(bucket: &RecordedBucket, dequantization: Dequantization) -> bool {
    bucket.count > 1
        && (dequantization == Dequantization::All
            || (dequantization == Dequantization::Hdr && bucket.resolution > 1.0))
}

/// `QrdeBucketRange`: the span a dequantized bucket covers.
///
/// The first and last buckets only extend inward, so the reported range never
/// leaves the data: the lower endpoint of the whole estimate is the first
/// bucket's own value, not half a bucket below it.
fn bucket_range(snapshot: &Snapshot, index: usize, dequantization: Dequantization) -> (f64, f64) {
    let bucket = &snapshot.buckets[index];
    if !should_dequantize(bucket, dequantization) {
        return (bucket.value, bucket.value);
    }

    let half_resolution = bucket.resolution / 2.0;
    if snapshot.buckets.len() == 1 {
        return (
            bucket.value - half_resolution,
            bucket.value + half_resolution,
        );
    }
    if index == 0 {
        return (bucket.value, bucket.value + half_resolution);
    }
    if index + 1 == snapshot.buckets.len() {
        return (bucket.value - half_resolution, bucket.value);
    }
    (
        bucket.value - half_resolution,
        bucket.value + half_resolution,
    )
}

/// `0x1p-80`, the tail mass below which `QrdeExactSupport` stops integrating.
///
/// Collapsing both tails changes a quantile by at most `2^-79` times the histogram
/// range, which is less than `2^-16` over the int64 value domain.
const TAIL_MASS: f64 = f64::from_bits(0x3F0_0000_0000_0000);

/// `QrdeExactSupport`: shrink the integrated range to the buckets that carry
/// mass above [`TAIL_MASS`] in both tails.
///
/// Returns `None` where Node leaves the full range in place — when a CDF comes
/// back non-finite or the searches do not bracket a range. The full range is the
/// right answer there rather than an error.
fn exact_support(
    snapshot: &Snapshot,
    params: &BetaParameters,
    reflected: &BetaParameters,
    count: f64,
) -> Option<(usize, usize)> {
    let len = snapshot.buckets.len();
    let mut lo = 0;
    let mut hi = len;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let rank = snapshot.buckets[mid].cumulative_count as f64 / count;
        let cdf = regularized_incomplete_beta_with_front(params, rank, false).0;
        if !cdf.is_finite() {
            return None;
        }
        if cdf < TAIL_MASS {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == len {
        return None;
    }
    let first = lo;

    lo = first;
    hi = len;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let remaining_rank =
            (snapshot.total_count - snapshot.buckets[mid].cumulative_count) as f64 / count;
        let survival = regularized_incomplete_beta_with_front(reflected, remaining_rank, false).0;
        if !survival.is_finite() {
            return None;
        }
        if survival > TAIL_MASS {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == len || lo < first {
        return None;
    }
    Some((first, lo + 1))
}

/// `QrdeQuantile`: the Harrell-Davis quantile at probability `p`.
fn quantile(snapshot: &Snapshot, p: f64, dequantization: Dequantization) -> f64 {
    let count = snapshot.total_count as f64;
    let a = (count + 1.0) * p;
    let b = (count + 1.0) * (1.0 - p);
    let mass_params = beta_parameters(a, b, true);
    let reflected_params = reflect_beta_parameters(&mass_params);

    let mut begin_index = 0usize;
    let mut end_index = snapshot.buckets.len();
    if mass_params.uses_asymptotic_cdf() {
        // Outside this interval the normal-tail mass is below 2e-33.
        const SUPPORT_DEVIATIONS: f64 = 12.0;
        let lower_rank =
            (mass_params.mean() - SUPPORT_DEVIATIONS * mass_params.standard_deviation()).max(0.0);
        let upper_rank =
            (mass_params.mean() + SUPPORT_DEVIATIONS * mass_params.standard_deviation()).min(1.0);
        let first = snapshot
            .buckets
            .partition_point(|bucket| (bucket.cumulative_count as f64) < lower_rank * count);
        begin_index = first;
        let last = first
            + snapshot.buckets[first..]
                .partition_point(|bucket| (bucket.cumulative_count as f64) < upper_rank * count);
        if last != snapshot.buckets.len() {
            end_index = last + 1;
        }
    } else if snapshot.buckets.len() >= 512 {
        if let Some((first, end)) = exact_support(snapshot, &mass_params, &reflected_params, count)
        {
            begin_index = first;
            end_index = end;
        }
    }

    let dequantize = dequantization != Dequantization::None;
    let first_range = bucket_range(snapshot, 0, dequantization);
    let last_range = bucket_range(snapshot, snapshot.buckets.len() - 1, dequantization);
    let lower_endpoint = first_range.0;
    let upper_endpoint = last_range.1;

    let mut previous_cdf = 0.0_f64;
    let mut previous_survival = 0.0_f64;
    let mut previous_front = 0.0_f64;
    let mut previous_count = if begin_index == 0 {
        0
    } else {
        snapshot.buckets[begin_index - 1].cumulative_count
    };
    if previous_count != 0 {
        let previous_rank = previous_count as f64 / count;
        let (cdf, front) =
            regularized_incomplete_beta_with_front(&mass_params, previous_rank, dequantize);
        if !cdf.is_finite() || (dequantize && !front.is_finite()) {
            begin_index = 0;
            end_index = snapshot.buckets.len();
            previous_count = 0;
            previous_cdf = 0.0;
            previous_front = 0.0;
        } else {
            previous_cdf = clamp(cdf, 0.0, 1.0);
            previous_front = front;
        }
    }

    let mut value = lower_endpoint * previous_cdf;
    let mut using_survival = false;

    for i in begin_index..end_index {
        let bucket = &snapshot.buckets[i];
        let u0 = previous_count as f64 / count;
        let u1 = bucket.cumulative_count as f64 / count;
        let front;
        let mass;
        // Above the symmetry point the reflected CDF is used so small upper-tail
        // interval weights are not lost to a subtraction from one.
        if u1 <= mass_params.symmetry_point() {
            let (cdf, front_value) =
                regularized_incomplete_beta_with_front(&mass_params, u1, dequantize);
            front = front_value;
            let cdf = clamp(cdf, previous_cdf, 1.0);
            mass = cdf - previous_cdf;
            previous_cdf = cdf;
        } else {
            let remaining_rank = (snapshot.total_count - bucket.cumulative_count) as f64 / count;
            let (mut survival, front_value) = regularized_incomplete_beta_with_front(
                &reflected_params,
                remaining_rank,
                dequantize,
            );
            front = front_value;
            if using_survival {
                survival = clamp(survival, 0.0, previous_survival);
                mass = previous_survival - survival;
            } else {
                survival = clamp(survival, 0.0, 1.0 - previous_cdf);
                mass = 1.0 - previous_cdf - survival;
                using_survival = true;
            }
            previous_survival = survival;
        }

        if !should_dequantize(bucket, dequantization) {
            value += bucket.value * mass;
        } else {
            // `I_x(a + 1, b) = I_x(a, b) - front / a`, so the first moment within
            // this rank interval does not need a second beta CDF.
            let sum = a + b;
            let rank_width = bucket.count as f64 / count;
            let local_moment = clamp(
                (a / sum - u0) * mass - (front - previous_front) / sum,
                0.0,
                rank_width * mass,
            );
            let (lower, upper) = bucket_range(snapshot, i, dequantization);
            value += lower * mass + (upper - lower) * local_moment / rank_width;
        }

        previous_front = front;
        previous_count = bucket.cumulative_count;
    }

    let remaining_mass = if using_survival {
        previous_survival
    } else {
        1.0 - previous_cdf
    };
    value += upper_endpoint * clamp(remaining_mass, 0.0, 1.0);
    value
}

/// `CalculateQrde`.
pub fn calculate(
    snapshot: &Snapshot,
    probabilities: &[f64],
    dequantization: Dequantization,
) -> QrdeResult {
    let mut result = QrdeResult::default();
    if snapshot.buckets.is_empty() {
        return result;
    }

    result.quantiles.resize(probabilities.len(), 0.0);
    result.densities.resize(probabilities.len() - 1, 0.0);

    let first_range = bucket_range(snapshot, 0, dequantization);
    let last_range = bucket_range(snapshot, snapshot.buckets.len() - 1, dequantization);
    let lowest = first_range.0;
    let highest = last_range.1;
    result.quantiles[0] = lowest;
    result.quantiles[probabilities.len() - 1] = highest;

    for i in 1..probabilities.len() - 1 {
        let mut value = quantile(snapshot, probabilities[i], dequantization);
        value = clamp(value, lowest, highest);
        if value < result.quantiles[i - 1] {
            value = result.quantiles[i - 1];
            result.corrections += 1;
        }
        result.quantiles[i] = value;
    }

    for i in 0..result.densities.len() {
        let width = result.quantiles[i + 1] - result.quantiles[i];
        let probability_mass = probabilities[i + 1] - probabilities[i];
        result.densities[i] = if width == 0.0 {
            f64::INFINITY
        } else {
            probability_mass / width
        };
    }

    result
}

/// One queued `qrde` request: what to integrate, and what the result reports.
pub struct Work {
    snapshot: Arc<Snapshot>,
    probabilities: Arc<Vec<f64>>,
    dequantization: Dequantization,
}

impl Work {
    pub fn new(
        snapshot: Arc<Snapshot>,
        probabilities: Vec<f64>,
        dequantization: Dequantization,
    ) -> Self {
        Self {
            snapshot,
            probabilities: Arc::new(probabilities),
            dequantization,
        }
    }

    /// Runs the estimate and hands back everything the completion reports.
    fn run(&self) -> (Arc<Snapshot>, Arc<Vec<f64>>, QrdeResult) {
        let result = calculate(&self.snapshot, &self.probabilities, self.dequantization);
        (
            Arc::clone(&self.snapshot),
            Arc::clone(&self.probabilities),
            result,
        )
    }
}

/// The state an in-flight request owns.
///
/// Every field is a `Mutex` because the work callback runs on a pool thread and
/// the completion runs on the loop's thread: the snapshot crosses one way, the
/// result the other, and the V8 handles are only ever touched on the loop.
struct Queued {
    /// Taken by the work callback, put back afterwards so the completion can
    /// still report the probability boundaries the result describes.
    work: Mutex<Option<Work>>,
    snapshot: Mutex<Option<Arc<Snapshot>>>,
    result: Mutex<Option<QrdeResult>>,
    probabilities: Mutex<Option<Arc<Vec<f64>>>>,
    /// The histogram whose cache should be filled, when the caller asked for one.
    /// Rooted so the state cell behind it cannot be freed while the job is in
    /// flight — Node keeps the same object alive through a `shared_ptr`.
    cache_target: Mutex<Option<v8::Global<v8::Object>>>,
    cache_generation: u64,
    /// The mode the result reports. Mirrored out of the work item because the
    /// completion runs after the work has been consumed on the pool thread.
    mode: Mutex<Dequantization>,
    resolver: Mutex<Option<v8::Global<v8::PromiseResolver>>>,
}

impl Queued {
    /// Takes a field out of its `Mutex`, recovering from a poisoned lock.
    ///
    /// A poison means a previous holder panicked. The values already stored are
    /// still owned and still valid, so recovering is better than losing them and
    /// leaving a promise unsettled forever.
    fn take<T>(slot: &Mutex<Option<T>>) -> Option<T> {
        lock(slot).take()
    }
}

fn lock<T>(slot: &Mutex<T>) -> MutexGuard<'_, T> {
    match slot.lock() {
        Ok(slot) => slot,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Creates the promise and queues `work` on the threadpool.
///
/// Returns the promise, or `None` when V8 refused a resolver, which leaves an
/// exception pending.
pub fn schedule<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    work: Work,
    cache: Option<(v8::Global<v8::Object>, u64)>,
) -> Option<v8::Local<'s, v8::Value>> {
    let resolver = v8::PromiseResolver::new(scope)?;
    let promise = resolver.get_promise(scope);

    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        // No loop means no threadpool and no completion to settle the promise
        // with, so the failure is delivered now rather than leaving it pending
        // forever.
        if let Some(message) = v8::String::new(scope, "No event loop is available") {
            let exception = v8::Exception::error(scope, message);
            resolver.reject(scope, exception);
        }
        return Some(promise.into());
    };

    let cache_generation = cache.as_ref().map_or(0, |(_, generation)| *generation);
    let mode = work.dequantization;
    let state = Box::into_raw(Box::new(Queued {
        work: Mutex::new(Some(work)),
        snapshot: Mutex::new(None),
        result: Mutex::new(None),
        probabilities: Mutex::new(None),
        cache_target: Mutex::new(cache.map(|(target, _)| target)),
        cache_generation,
        mode: Mutex::new(mode),
        resolver: Mutex::new(Some(v8::Global::new(scope.as_ref(), resolver))),
    }));

    let mut request: Box<libuv_sys2::uv_work_t> = Box::new(unsafe { std::mem::zeroed() });
    request.data = state.cast();
    let request = Box::into_raw(request);
    rn_uv::threadpool::register(request);

    // SAFETY: `loop_pointer` is the process loop, which outlives the request;
    // `request` is heap-allocated and stays valid until the after-work callback
    // frees it.
    let queued = unsafe {
        libuv_sys2::uv_queue_work(
            loop_pointer,
            request,
            Some(work_trampoline),
            Some(after_work_trampoline),
        )
    };
    if queued != 0 {
        // The loop refused the work, so no callback will arrive. Both boxes are
        // freed here and the promise is rejected inline, which keeps the contract
        // either way: the caller always gets a settled promise.
        rn_uv::threadpool::unregister(request);
        // SAFETY: neither box was handed on; libuv took no ownership on failure.
        let state = unsafe { Box::from_raw(state) };
        unsafe { drop(Box::from_raw(request)) };
        if let Some(resolver) = Queued::take(&state.resolver) {
            let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, &resolver);
            if let Some(message) = v8::String::new(scope, "cannot queue the QRDE job") {
                let exception = v8::Exception::error(scope, message);
                resolver.reject(scope, exception);
            }
        }
    }

    Some(promise.into())
}

/// The threadpool half: integrates the snapshot off the main thread.
///
/// # Safety
///
/// `request` must be the `uv_work_t` [`schedule`] allocated, whose `data` is the
/// `Queued` box for this job.
unsafe extern "C" fn work_trampoline(request: *mut libuv_sys2::uv_work_t) {
    // SAFETY: per the contract above, `data` is the box `schedule` created, and
    // libuv calls the work callback exactly once per queued request.
    let state = unsafe { &*((*request).data as *mut Queued) };
    let Some(work) = Queued::take(&state.work) else {
        return;
    };
    let (snapshot, probabilities, result) = work.run();
    *lock(&state.snapshot) = Some(snapshot);
    *lock(&state.probabilities) = Some(probabilities);
    *lock(&state.result) = Some(result);
}

/// The loop half: turns the result into a settled promise.
///
/// # Safety
///
/// As [`work_trampoline`].
unsafe extern "C" fn after_work_trampoline(
    request: *mut libuv_sys2::uv_work_t,
    status: std::ffi::c_int,
) {
    // SAFETY: `state` and `request` were created by `schedule` and are freed
    // here, exactly once, now that no other callback will use them.
    let state = unsafe { Box::from_raw((*request).data as *mut Queued) };
    rn_uv::threadpool::unregister(request);
    unsafe { drop(Box::from_raw(request)) };

    let Some(resolver) = Queued::take(&state.resolver) else {
        return;
    };
    let cache_target = Queued::take(&state.cache_target);

    // A cancelled request (`UV_ECANCELED`) ran no work. `process.exit()` is the
    // only route to that and the process is going away, but rejecting is still
    // cheaper than reasoning about a promise nobody can observe — and Node
    // rejects it with the same message.
    if status == libuv_sys2::uv_errno_t_UV_ECANCELED {
        rn_uv::callback::with_context(|scope| {
            let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, &resolver);
            if let Some(message) = v8::String::new(scope, "QRDE job was canceled") {
                let exception = v8::Exception::error(scope, message);
                resolver.reject(scope, exception);
            }
        });
        return;
    }

    let snapshot = Queued::take(&state.snapshot);
    let result = Queued::take(&state.result);
    let probabilities = Queued::take(&state.probabilities);

    rn_uv::callback::with_context(|scope| {
        let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, &resolver);
        let (Some(snapshot), Some(result), Some(probabilities)) = (snapshot, result, probabilities)
        else {
            if let Some(message) = v8::String::new(scope, "the QRDE job produced no result") {
                let exception = v8::Exception::error(scope, message);
                resolver.reject(scope, exception);
            }
            return;
        };

        if let Some(target) = cache_target {
            let object: v8::Local<v8::Object> = v8::Local::new(scope, &target);
            crate::histogram_binding::cache_recorded_snapshot(
                object,
                state.cache_generation,
                &snapshot,
            );
        }

        match result_object(
            scope,
            &snapshot,
            &result,
            &probabilities,
            *lock(&state.mode),
        ) {
            Some(value) => {
                resolver.resolve(scope, value);
            }
            None => {
                if let Some(message) = v8::String::new(scope, "the QRDE result could not be built")
                {
                    let exception = v8::Exception::error(scope, message);
                    resolver.reject(scope, exception);
                }
            }
        }
    });
}

/// Builds the result object `GetQrde`'s `AfterThreadPoolWork` resolves with.
///
/// The prototype is `null` and the field order is the one `names[]` lists in the
/// C: `assert.strictEqual(Object.getPrototypeOf(result), null)` is in the test,
/// and the order is observable through `Object.keys`.
fn result_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    snapshot: &Snapshot,
    result: &QrdeResult,
    probabilities: &[f64],
    dequantization: Dequantization,
) -> Option<v8::Local<'s, v8::Value>> {
    let probabilities = float64_array(scope, probabilities)?;
    let quantiles = float64_array(scope, &result.quantiles)?;
    let densities = float64_array(scope, &result.densities)?;
    // `BigInt::New(isolate, snapshot_->total_count)` is signed.
    let count = v8::BigInt::new_from_i64(scope, snapshot.total_count);
    let bucket_count = v8::Number::new(scope, snapshot.buckets.len() as f64);
    let corrections = v8::Number::new(scope, result.corrections as f64);
    let mode = v8::String::new(scope, dequantization.name())?;

    let names: [v8::Local<v8::Name>; 7] = [
        v8::String::new(scope, "probabilities")?.into(),
        v8::String::new(scope, "quantiles")?.into(),
        v8::String::new(scope, "densities")?.into(),
        v8::String::new(scope, "count")?.into(),
        v8::String::new(scope, "bucketCount")?.into(),
        v8::String::new(scope, "corrections")?.into(),
        v8::String::new(scope, "dequantize")?.into(),
    ];
    let values: [v8::Local<v8::Value>; 7] = [
        probabilities.into(),
        quantiles.into(),
        densities.into(),
        count.into(),
        bucket_count.into(),
        corrections.into(),
        mode.into(),
    ];
    let object =
        v8::Object::with_prototype_and_properties(scope, v8::null(scope).into(), &names, &values);
    Some(object.into())
}

/// `ToFloat64Array`: a fresh `Float64Array` over a copy of `values`.
fn float64_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    values: &[f64],
) -> Option<v8::Local<'s, v8::Float64Array>> {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for value in values {
        bytes.extend_from_slice(&value.to_ne_bytes());
    }
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    v8::Float64Array::new(scope, buffer, 0, values.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hdr::Layout;

    fn snapshot_of(values: &[i64], figures: i32) -> Snapshot {
        let layout = Layout::new(1, i64::MAX, figures).expect("valid layout");
        let mut histogram = HdrHistogram::new(layout);
        for value in values {
            histogram.record(*value);
        }
        Snapshot::build(&histogram)
    }

    fn probabilities(bins: usize) -> Vec<f64> {
        (0..=bins).map(|i| i as f64 / bins as f64).collect()
    }

    /// An empty histogram produces no quantiles at all, which is what the JS
    /// layer turns into two empty `Float64Array`s.
    #[test]
    fn an_empty_snapshot_yields_no_quantiles() {
        let snapshot = snapshot_of(&[], 3);
        let result = calculate(&snapshot, &probabilities(10), Dequantization::Hdr);
        assert!(result.quantiles.is_empty());
        assert!(result.densities.is_empty());
        assert_eq!(result.corrections, 0);
    }

    /// With every sample on one value and `none`, the estimate collapses to a
    /// point mass: every quantile is that value and every density is infinite.
    #[test]
    fn a_point_mass_collapses_and_has_infinite_density() {
        let snapshot = snapshot_of(&[100; 100], 3);
        let result = calculate(&snapshot, &probabilities(10), Dequantization::None);
        assert_eq!(result.quantiles.len(), 11);
        for value in &result.quantiles {
            assert!((value - 100.0).abs() < 1e-12, "{value}");
        }
        for density in &result.densities {
            assert!(density.is_infinite(), "{density}");
        }
    }

    /// `all` dequantizes the point mass across the bucket's half-width on either
    /// side, which is what makes its density finite where `none`'s is infinite.
    ///
    /// The test asserts the shape rather than the exact numbers: `100` sits in a
    /// one-unit bucket at this layout, so the span is `[99.5, 100.5]` and the
    /// quantiles step linearly across it.
    #[test]
    fn dequantizing_a_point_mass_spreads_it_over_the_bucket() {
        let snapshot = snapshot_of(&[100; 100], 3);
        assert_eq!(snapshot.buckets.len(), 1);
        assert_eq!(snapshot.buckets[0].resolution, 1.0);
        let result = calculate(&snapshot, &probabilities(10), Dequantization::All);
        assert!((result.quantiles[0] - 99.5).abs() < 1e-12);
        assert!((result.quantiles[10] - 100.5).abs() < 1e-12);
        for step in 1..10 {
            let expected = 99.5 + step as f64 / 10.0;
            assert!(
                (result.quantiles[step] - expected).abs() < 1e-12,
                "step {step}: {} vs {expected}",
                result.quantiles[step]
            );
        }
        for density in &result.densities {
            assert!((density - 1.0).abs() < 1e-12, "{density}");
        }
    }

    /// The quantiles are non-decreasing whatever the input, and every crossing the
    /// repair had to make is counted.
    #[test]
    fn the_quantiles_are_monotone_and_corrections_are_counted() {
        let snapshot = snapshot_of(&[3, 4, 7, 11, 11, 20, 41, 90, 91, 92], 3);
        let result = calculate(&snapshot, &probabilities(100), Dequantization::Hdr);
        for pair in result.quantiles.windows(2) {
            assert!(pair[0] <= pair[1], "{} > {}", pair[0], pair[1]);
        }
        // The densities follow from the quantiles, so a mass that adds up to one
        // interval is what proves the same pairing was used.
        for (index, density) in result.densities.iter().enumerate() {
            let width = result.quantiles[index + 1] - result.quantiles[index];
            assert!((density * width - 0.01).abs() < 1e-9, "{index}: {density}");
        }
    }

    /// The `hdr` and `none` modes agree where no bucket holds more than one
    /// sample, because there is nothing to dequantize.
    #[test]
    fn hdr_and_none_agree_when_every_bucket_is_unique() {
        let values: Vec<i64> = (1..=200).collect();
        let snapshot = snapshot_of(&values, 3);
        assert!(snapshot.buckets.iter().all(|bucket| bucket.count == 1));
        let none = calculate(&snapshot, &probabilities(20), Dequantization::None);
        for mode in [Dequantization::Hdr, Dequantization::All] {
            let other = calculate(&snapshot, &probabilities(20), mode);
            for (a, b) in none.quantiles.iter().zip(other.quantiles.iter()) {
                // A single-sample bucket is never dequantized, so only the
                // endpoints can differ — and they do not, because `bucket_range`
                // returns the value for a non-dequantized bucket.
                assert!((a - b).abs() < 1e-9, "{a} vs {b}");
            }
        }
    }

    /// A bucket wider than one unit is dequantized under `hdr` but a single-unit
    /// bucket is not, which is the whole difference between the two modes.
    #[test]
    fn the_hdr_mode_only_spreads_buckets_wider_than_one_unit() {
        let narrow = RecordedBucket {
            value: 100.0,
            resolution: 1.0,
            count: 5,
            cumulative_count: 5,
        };
        let wide = RecordedBucket {
            value: 100.0,
            resolution: 16.0,
            count: 5,
            cumulative_count: 5,
        };
        assert!(!should_dequantize(&narrow, Dequantization::Hdr));
        assert!(should_dequantize(&wide, Dequantization::Hdr));
        assert!(should_dequantize(&narrow, Dequantization::All));
        assert!(!should_dequantize(&narrow, Dequantization::None));
    }
}
