//! The HdrHistogram core Node 28's `perf_hooks` histograms are built on.
//!
//! `perf_hooks.createHistogram()` does not use a V8 histogram: `src/histogram.h`
//! in the pinned Node revision holds an `hdr_histogram*` from the bundled
//! `deps/histogram` library, and every accessor is a thin wrapper over a
//! function in `deps/histogram/src/hdr_histogram.c`. So the only way to make
//! the accessors agree with Node's values is to reproduce that library's
//! arithmetic, not to approximate it. A histogram that merely counts the right
//! number of samples reports a `max` that disagrees with Node's by the bucket
//! width, and bucket widths here are powers of two.
//!
//! # What is reproduced, and what deliberately is not
//!
//! Reproduced exactly, because each one is observable through a `perf_hooks`
//! accessor or method:
//!
//! * bucket configuration (`hdr_calculate_bucket_config`),
//! * `record`, including the `highest_trackable_value` rejection that drives
//!   `exceeds`,
//! * `min`/`max` and the equivalent-value-range rounding that makes them
//!   bucket edges rather than recorded values,
//! * `mean`/`stddev`, which are computed over *median* equivalent values,
//! * `value_at_percentile` and both percentile iterators,
//! * `count_at_value`, `add`, `subtract`, `reset`, `record_corrected`,
//! * `linear`/`log` bucket iteration.
//!
//! Not reproduced: the AVX2 dispatch (`get_value_from_idx_up_to_count_avx2`) and
//! the atomic/`_atomic` record variants. The first is a faster path to the same
//! answer, and the second exists for cross-thread recording, which Node's own
//! `Histogram` methods do not use — they take a write lock instead.
//!
//! # Why the counters are `i64` and the sums are `f64`
//!
//! `hdr_histogram.c` stores `counts[]` as `int64_t` and accumulates `mean`
//! in a `double` precisely because `count * median` overflows `int64_t` for
//! large values. Both choices are load-bearing: the conversion order changes the
//! last bits of `mean`, which is a value a test compares exactly.

/// `INT64_MAX`, the sentinel `min_value` carries while nothing is recorded.
const INT64_MAX: i64 = i64::MAX;

/// The bucket layout `hdr_calculate_bucket_config` derives from the options.
///
/// These fields are fixed at construction and `hdr_histogram.c` never changes
/// them, so a copy of them is enough to describe a histogram's layout without
/// touching its counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    /// `lowest_discernible_value`, the smallest value that keeps full resolution.
    pub lowest_discernible_value: i64,
    /// `highest_trackable_value`, the largest value `record` accepts.
    pub highest_trackable_value: i64,
    /// `significant_figures`, the precision of the bucket subdivision.
    pub significant_figures: i32,
    /// `unit_magnitude`, `floor(log2(lowest))`.
    pub unit_magnitude: i32,
    /// `sub_bucket_half_count_magnitude`.
    pub sub_bucket_half_count_magnitude: i32,
    /// `sub_bucket_count`, a power of two.
    pub sub_bucket_count: i32,
    /// `sub_bucket_half_count`, half of the above.
    pub sub_bucket_half_count: i32,
    /// `sub_bucket_mask`, `(sub_bucket_count - 1) << unit_magnitude`.
    pub sub_bucket_mask: i64,
    /// `bucket_count`.
    pub bucket_count: i32,
    /// `counts_len`, the length of the counts array.
    pub counts_len: i32,
}

/// Why a layout could not be built.
///
/// `hdr_calculate_bucket_config` returns `EINVAL` for these and `Histogram::Create`
/// turns that into a null pointer, which `HistogramBase::New` reports as
/// `ERR_INVALID_ARG_VALUE("Invalid histogram options")`. The variants exist so
/// the binding can say which combination was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    /// `lowest < 1`, `figures` outside 1..=5, or `lowest > highest / 2`.
    InvalidOptions,
    /// `unit_magnitude + sub_bucket_half_count_magnitude > 61`, which would make
    /// the `sub_bucket_mask` shift undefined.
    MaskOverflow,
}

impl Layout {
    /// `hdr_calculate_bucket_config`.
    ///
    /// The order of the operations and the integer/float types are Node's,
    /// because the result decides every bucket boundary and therefore every
    /// value `min`, `max` and `percentile` report.
    pub fn new(
        lowest_discernible_value: i64,
        highest_trackable_value: i64,
        significant_figures: i32,
    ) -> Result<Self, LayoutError> {
        // The division form is Node's: `lowest * 2` overflows near `INT64_MAX`.
        if lowest_discernible_value < 1
            || !(1..=5).contains(&significant_figures)
            || lowest_discernible_value > highest_trackable_value / 2
        {
            return Err(LayoutError::InvalidOptions);
        }

        // `largest_value_with_single_unit_resolution = 2 * 10^figures`.
        let mut largest_value_with_single_unit_resolution: i64 = 1;
        for _ in 0..significant_figures {
            largest_value_with_single_unit_resolution *= 10;
        }
        largest_value_with_single_unit_resolution *= 2;

        // `ceil(log2(largest))`. `log`/`log` through `f64` and then `ceil` is
        // exactly what the C does, including for exact powers of two, where the
        // floating-point result can land a hair above the integer and ceil to
        // the next value. Using `ilog2` here would change the bucket count for
        // those inputs.
        let sub_bucket_count_magnitude =
            (largest_value_with_single_unit_resolution as f64).ln() / 2.0_f64.ln();
        let sub_bucket_count_magnitude = sub_bucket_count_magnitude.ceil() as i32;

        let sub_bucket_half_count_magnitude = if sub_bucket_count_magnitude > 1 {
            sub_bucket_count_magnitude
        } else {
            1
        } - 1;

        let unit_magnitude = (lowest_discernible_value as f64).ln() / 2.0_f64.ln();
        if unit_magnitude > i32::MAX as f64 {
            return Err(LayoutError::InvalidOptions);
        }
        let unit_magnitude = unit_magnitude as i32;

        let sub_bucket_count = 2_i32
            .checked_pow((sub_bucket_half_count_magnitude + 1) as u32)
            .ok_or(LayoutError::InvalidOptions)?;
        let sub_bucket_half_count = sub_bucket_count / 2;

        if unit_magnitude + sub_bucket_half_count_magnitude > 61 {
            return Err(LayoutError::MaskOverflow);
        }

        let sub_bucket_mask = ((sub_bucket_count as i64) - 1) << unit_magnitude;

        let bucket_count = buckets_needed_to_cover_value(
            highest_trackable_value,
            sub_bucket_count,
            unit_magnitude,
        );
        let counts_len = (bucket_count + 1) * (sub_bucket_count / 2);

        Ok(Self {
            lowest_discernible_value,
            highest_trackable_value,
            significant_figures,
            unit_magnitude,
            sub_bucket_half_count_magnitude,
            sub_bucket_count,
            sub_bucket_half_count,
            sub_bucket_mask,
            bucket_count,
            counts_len,
        })
    }

    /// `get_bucket_index`.
    fn bucket_index(&self, value: i64) -> i32 {
        // `count_leading_zeros_64(value | sub_bucket_mask)` then
        // `64 - that`. The OR with the mask keeps the value non-zero for small
        // inputs, which `leading_zeros` would otherwise report as 64.
        let orred = (value | self.sub_bucket_mask) as u64;
        let pow2ceiling = 64 - orred.leading_zeros() as i32;
        pow2ceiling - self.unit_magnitude - (self.sub_bucket_half_count_magnitude + 1)
    }

    /// `get_sub_bucket_index`.
    fn sub_bucket_index(&self, value: i64, bucket_index: i32) -> i32 {
        // `value >> (bucket_index + unit_magnitude)`. Arithmetic shift, as in C.
        (value >> (bucket_index + self.unit_magnitude)) as i32
    }

    /// `counts_index`: where in `counts[]` this bucket/sub-bucket pair lives.
    fn counts_index(&self, bucket_index: i32, sub_bucket_index: i32) -> i32 {
        let bucket_base_index = (bucket_index + 1) << self.sub_bucket_half_count_magnitude;
        let offset_in_bucket = sub_bucket_index - self.sub_bucket_half_count;
        bucket_base_index + offset_in_bucket
    }

    /// `counts_index_for`.
    pub fn counts_index_for(&self, value: i64) -> i32 {
        let bucket_index = self.bucket_index(value);
        let sub_bucket_index = self.sub_bucket_index(value, bucket_index);
        self.counts_index(bucket_index, sub_bucket_index)
    }

    /// `hdr_value_at_index`: the lowest value the given counts index stands for.
    pub fn value_at_index(&self, index: i32) -> i64 {
        let mut bucket_index = (index >> self.sub_bucket_half_count_magnitude) - 1;
        let mut sub_bucket_index =
            (index & (self.sub_bucket_half_count - 1)) + self.sub_bucket_half_count;
        if bucket_index < 0 {
            sub_bucket_index -= self.sub_bucket_half_count;
            bucket_index = 0;
        }
        value_from_index(bucket_index, sub_bucket_index, self.unit_magnitude)
    }

    /// `hdr_size_of_equivalent_value_range`.
    fn size_of_equivalent_value_range(&self, value: i64) -> i64 {
        let bucket_index = self.bucket_index(value);
        let sub_bucket_index = self.sub_bucket_index(value, bucket_index);
        let adjusted_bucket = if sub_bucket_index >= self.sub_bucket_count {
            bucket_index + 1
        } else {
            bucket_index
        };
        1_i64 << (self.unit_magnitude + adjusted_bucket)
    }

    /// `size_of_equivalent_value_range_given_bucket_indices`.
    fn size_of_equivalent_value_range_at(&self, bucket_index: i32, sub_bucket_index: i32) -> i64 {
        let adjusted_bucket = if sub_bucket_index >= self.sub_bucket_count {
            bucket_index + 1
        } else {
            bucket_index
        };
        1_i64 << (self.unit_magnitude + adjusted_bucket)
    }

    /// `lowest_equivalent_value`.
    fn lowest_equivalent_value(&self, value: i64) -> i64 {
        let bucket_index = self.bucket_index(value);
        let sub_bucket_index = self.sub_bucket_index(value, bucket_index);
        value_from_index(bucket_index, sub_bucket_index, self.unit_magnitude)
    }

    /// `highest_equivalent_value`, including the saturation guard.
    ///
    /// The guard is not defensive padding: the top bucket's `low + size`
    /// overflows `i64` for a layout covering the full range, and the C returns
    /// `INT64_MAX` there. Without it the empty-histogram `maxBigInt` would be a
    /// negative number instead of Node's `9223372036854775807`.
    fn highest_equivalent_value(&self, value: i64) -> i64 {
        let low = self.lowest_equivalent_value(value);
        let size = self.size_of_equivalent_value_range(value);
        if low > INT64_MAX - size {
            return INT64_MAX;
        }
        low + size - 1
    }

    /// `highest_equivalent_value` from a value already at a bucket boundary.
    fn highest_equivalent_value_at(&self, low: i64, size: i64) -> i64 {
        if low > INT64_MAX - size {
            return INT64_MAX;
        }
        low + size - 1
    }

    /// The same, for a value already known to be a lowest-equivalent boundary.
    fn median_equivalent_value_at(&self, low: i64, size: i64) -> i64 {
        low + (size >> 1)
    }

    /// The number of counts indices, as a `usize` for indexing.
    pub fn len(&self) -> usize {
        usize::try_from(self.counts_len).unwrap_or(0)
    }
}

/// `value_from_index`.
fn value_from_index(bucket_index: i32, sub_bucket_index: i32, unit_magnitude: i32) -> i64 {
    (sub_bucket_index as i64) << (bucket_index + unit_magnitude)
}

/// `buckets_needed_to_cover_value`.
fn buckets_needed_to_cover_value(value: i64, sub_bucket_count: i32, unit_magnitude: i32) -> i32 {
    let mut smallest_untrackable_value = (sub_bucket_count as i64) << unit_magnitude;
    let mut buckets_needed = 1;
    while smallest_untrackable_value <= value {
        if smallest_untrackable_value > INT64_MAX / 2 {
            return buckets_needed + 1;
        }
        smallest_untrackable_value <<= 1;
        buckets_needed += 1;
    }
    buckets_needed
}

/// One non-empty bucket, as the percentile and analysis iterators see it.
///
/// `value` is the lowest equivalent value, `count` the samples in this bucket and
/// `cumulative_count` the running total including it. `median` and `highest` are
/// precomputed because every consumer needs one or the other and recomputing
/// them from `value` would repeat the bucket-index arithmetic per bucket.
#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    /// `lowest_equivalent_value`.
    pub value: i64,
    /// `median_equivalent_value`.
    pub median: i64,
    /// `highest_equivalent_value`.
    pub highest: i64,
    /// Samples recorded into this bucket.
    pub count: i64,
    /// Running total through this bucket.
    pub cumulative_count: i64,
}

/// A port of `struct hdr_histogram` plus the operations Node calls on it.
///
/// The struct is deliberately not `Clone`: `Histogram::Add` and `Subtract` take
/// two of these, and a silent deep copy would make those look correct while
/// operating on the wrong one.
#[derive(Debug)]
pub struct HdrHistogram {
    layout: Layout,
    counts: Vec<i64>,
    total_count: i64,
    min_value: i64,
    max_value: i64,
}

impl HdrHistogram {
    /// `hdr_init`.
    pub fn new(layout: Layout) -> Self {
        Self {
            counts: vec![0; layout.len()],
            layout,
            total_count: 0,
            // Both sentinels are `hdr_init_preallocated`'s: `INT64_MAX` for the
            // minimum so the first recorded value always wins, `0` for the max.
            min_value: INT64_MAX,
            max_value: 0,
        }
    }

    /// `hdr_record_value`. Returns `false` when the value is out of range, which
    /// the caller turns into an `exceeds` increment.
    pub fn record(&mut self, value: i64) -> bool {
        self.record_values(value, 1)
    }

    /// `hdr_record_values`, the shared body of the record path.
    pub fn record_values(&mut self, value: i64, count: i64) -> bool {
        if count < 0 {
            return false;
        }
        if value < 0 || self.layout.highest_trackable_value < value {
            return false;
        }
        let index = self.layout.counts_index_for(value);
        if index < 0 || index as usize >= self.counts.len() {
            return false;
        }
        self.counts[index as usize] += count;
        self.total_count += count;
        self.update_min_max(value);
        true
    }

    /// `update_min_max`: note that `0` never updates the minimum, which is how
    /// `hdr_min` can report `0` only when index `0` actually holds a count.
    fn update_min_max(&mut self, value: i64) {
        if value > self.max_value {
            self.max_value = value;
        }
        if value != 0 && value < self.min_value {
            self.min_value = value;
        }
    }

    /// `hdr_record_corrected_value`, used by `recordCorrected`.
    pub fn record_corrected(&mut self, value: i64, expected_interval: i64) -> bool {
        if !self.record_values(value, 1) {
            return false;
        }
        if expected_interval <= 0 || value <= expected_interval {
            return true;
        }
        let mut missing_value = value - expected_interval;
        while missing_value >= expected_interval {
            if !self.record_values(missing_value, 1) {
                return false;
            }
            missing_value -= expected_interval;
        }
        true
    }

    /// `hdr_reset`.
    pub fn reset(&mut self) {
        for count in self.counts.iter_mut() {
            *count = 0;
        }
        self.total_count = 0;
        self.min_value = INT64_MAX;
        self.max_value = 0;
    }

    /// `hdr_total_count`.
    pub fn count(&self) -> i64 {
        self.total_count
    }

    /// `hdr_min`.
    ///
    /// Index `0` is checked first because `min_value` alone cannot express a
    /// recorded zero: `update_min_max` deliberately skips it. An empty histogram
    /// therefore reports `INT64_MAX` through the non-zero path, which is the
    /// `9223372036854775807n` Node's `minBigInt` returns.
    pub fn min(&self) -> i64 {
        if self.count_at_index(0) > 0 {
            return 0;
        }
        self.non_zero_min()
    }

    /// `non_zero_min`.
    fn non_zero_min(&self) -> i64 {
        if self.min_value == INT64_MAX {
            return INT64_MAX;
        }
        self.layout.lowest_equivalent_value(self.min_value)
    }

    /// `hdr_max`.
    pub fn max(&self) -> i64 {
        if self.max_value == 0 {
            return 0;
        }
        self.layout.highest_equivalent_value(self.max_value)
    }

    /// `hdr_mean`.
    ///
    /// Sums `count * median` in `f64` and divides by the total count. With no
    /// samples this is `0.0 / 0` = `NaN`, which is what Node's `mean` reports.
    pub fn mean(&self) -> f64 {
        let mut total = 0.0_f64;
        let mut count = 0_i64;
        for bucket in self.iter_all() {
            if bucket.count != 0 {
                count += bucket.count;
                total += (bucket.count as f64) * (bucket.median as f64);
            }
            if count >= self.total_count {
                break;
            }
        }
        total / self.total_count as f64
    }

    /// `hdr_stddev`.
    ///
    /// The population standard deviation around [`mean`](Self::mean), over
    /// median equivalent values. `NaN` on an empty histogram, as Node reports.
    pub fn stddev(&self) -> f64 {
        let mean = self.mean();
        let mut geometric_dev_total = 0.0_f64;
        for bucket in self.iter_all() {
            if bucket.count != 0 {
                let dev = (bucket.median as f64) - mean;
                geometric_dev_total += (dev * dev) * (bucket.count as f64);
            }
        }
        (geometric_dev_total / self.total_count as f64).sqrt()
    }

    /// `hdr_value_at_percentile`.
    pub fn value_at_percentile(&self, percentile: f64) -> i64 {
        let requested_percentile = if percentile < 100.0 {
            percentile
        } else {
            100.0
        };
        let count_at_percentile =
            ((requested_percentile / 100.0) * self.total_count as f64 + 0.5) as i64;
        let value_from_idx = self.value_from_idx_up_to_count(count_at_percentile);
        if percentile == 0.0 {
            return self.layout.lowest_equivalent_value(value_from_idx);
        }
        self.layout.highest_equivalent_value(value_from_idx)
    }

    /// `get_value_from_idx_up_to_count`: the block-summed walk.
    ///
    /// The block skip is exact rather than an optimisation that could change the
    /// answer: `counts[]` are non-negative, so the running total is monotonic and
    /// a block whose sum cannot reach the target cannot contain the crossing.
    fn value_from_idx_up_to_count(&self, count_at_percentile: i64) -> i64 {
        let count_at_percentile = if count_at_percentile > 0 {
            count_at_percentile
        } else {
            1
        };
        let mut running = 0_i64;
        for (index, count) in self.counts.iter().enumerate() {
            running += count;
            if running >= count_at_percentile {
                return self.layout.value_at_index(index as i32);
            }
        }
        0
    }

    /// `hdr_count_at_value`.
    pub fn count_at_value(&self, value: i64) -> i64 {
        if value < 0 {
            return 0;
        }
        let index = self.layout.counts_index_for(value);
        self.count_at_index(index)
    }

    /// `hdr_count_at_index`, including the out-of-range guard.
    pub fn count_at_index(&self, index: i32) -> i64 {
        if index < 0 || index as usize >= self.counts.len() {
            return 0;
        }
        self.counts[index as usize]
    }

    /// `hdr_iter_init` walking every index, including empty ones.
    ///
    /// `cumulative_count` and the running total are what `Cdf` and the analysis
    /// loops compare against, so the empty buckets cannot be skipped here even
    /// though `iter_recorded` skips them.
    pub fn iter_all(&self) -> AllBuckets<'_> {
        AllBuckets {
            histogram: self,
            next_index: 0,
            cumulative: 0,
        }
    }

    /// `hdr_iter_recorded_init`: only non-empty buckets.
    pub fn iter_recorded(&self) -> impl Iterator<Item = Bucket> + '_ {
        self.iter_all().filter(|bucket| bucket.count != 0)
    }

    /// `hdr_iter_percentile_init` with `ticks_per_half_distance = 1`, which is
    /// the setting `Histogram::Percentiles` uses.
    ///
    /// The values reported are `iter.value` — the bucket's *lowest* equivalent
    /// value — not its highest. That is easy to get backwards, because
    /// `hdr_value_at_percentile` does report the highest: with `figures: 1` a
    /// sample at `400` sits in a bucket `[400, 415]`, and Node reports
    /// `percentiles.get(100) === 400` while `percentile(100) === 415`.
    ///
    /// The iteration is a port of the state machine in `percentile_iter_next`.
    /// Its notable behaviour is the extra `100.0` entry emitted after the data is
    /// exhausted, which is why every non-empty histogram's table ends at `100`.
    pub fn percentiles(&self) -> Vec<(f64, i64)> {
        let total = self.total_count;
        let mut entries = Vec::new();
        if total == 0 {
            // `percentile_iter_next` reports `has_next` false and emits the
            // single `100.0` entry from the exhausted branch; `iter.value` is
            // still `0` there, so an empty table is `[[100, 0]]`.
            return vec![(100.0, 0)];
        }

        let mut percentile_to_iterate_to = 0.0_f64;
        let mut cumulative = 0_i64;
        // `counts_index` starts at -1 and `basic_iter_next` pre-increments it.
        let mut index = -1_i32;
        let mut current_value = 0_i64;

        loop {
            if !self.has_next(cumulative, total) {
                // `percentile_iter_next`'s exhausted branch reports `100.0` and
                // leaves `iter.value` at whatever the last `move_next` set, then
                // returns `false` on the call after that. One entry, then out.
                entries.push((100.0, current_value));
                break;
            }

            if index == -1
                && !self.basic_iter_next(&mut index, &mut cumulative, total, &mut current_value)
            {
                break;
            }

            // The do/while in `percentile_iter_next`: emit at most one tick per
            // call, advancing to the next bucket only when the current one does
            // not cross the next boundary. Emitting in a `continue` loop here
            // would produce the whole tail of ticks for one bucket in one call,
            // which is exactly the shape the C never returns.
            loop {
                let current_percentile = 100.0 * (cumulative as f64) / (total as f64);
                let count_here = self.count_at_index(index);
                if count_here != 0 && percentile_to_iterate_to <= current_percentile {
                    entries.push((percentile_to_iterate_to, current_value));
                    // Next tick: `ticks_per_half_distance * 2^(floor(log2(100/(100-p)))+1)`.
                    let quotient = 100.0 / (100.0 - percentile_to_iterate_to);
                    let temp = (quotient.ln() / 2.0_f64.ln()) as i64 + 1;
                    let half_distance = 2_i64.pow(u32::try_from(temp).unwrap_or(0));
                    let ticks = half_distance; // ticks_per_half_distance is 1
                    percentile_to_iterate_to += 100.0 / (ticks as f64);
                    break;
                }
                if !self.basic_iter_next(&mut index, &mut cumulative, total, &mut current_value) {
                    break;
                }
            }
        }
        entries
    }

    /// `has_next`: whether any recorded sample is still ahead.
    fn has_next(&self, cumulative: i64, total: i64) -> bool {
        cumulative < total
    }

    /// `basic_iter_next` + `move_next`: advance to the next counts index.
    ///
    /// Returns `false` once the array is exhausted. `value` is `hdr_value_at_index`,
    /// which is the bucket's lowest equivalent value.
    fn basic_iter_next(
        &self,
        index: &mut i32,
        cumulative: &mut i64,
        total: i64,
        value: &mut i64,
    ) -> bool {
        if !self.has_next(*cumulative, total) || *index + 1 >= self.counts.len() as i32 {
            return false;
        }
        *index += 1;
        *cumulative += self.count_at_index(*index);
        *value = self.layout.value_at_index(*index);
        true
    }

    /// The [`Bucket`] at one counts index.
    fn bucket_at(&self, index: i32) -> Bucket {
        let value = self.layout.value_at_index(index);
        let bucket_index = self.layout.bucket_index(value);
        let sub_bucket_index = self.layout.sub_bucket_index(value, bucket_index);
        let low = value_from_index(bucket_index, sub_bucket_index, self.layout.unit_magnitude);
        let size = self
            .layout
            .size_of_equivalent_value_range_at(bucket_index, sub_bucket_index);
        Bucket {
            value: low,
            median: self.layout.median_equivalent_value_at(low, size),
            highest: self.layout.highest_equivalent_value_at(low, size),
            count: self.count_at_index(index),
            cumulative_count: 0,
        }
    }

    /// `hdr_iter_linear_init` + `iter_linear_next`, yielding
    /// `(iter.value, count_added_in_this_step)`.
    ///
    /// Two things are easy to get wrong here, and the C is the authority for both:
    ///
    /// * the reported key is `iter.value` — the *lowest equivalent value of the
    ///   bucket that crossed the reporting level* — not the reporting level
    ///   itself. `update_iterated_values` writes `value_iterated_to`, a different
    ///   field, so a step of `100` over a coarse layout reports `288` where the
    ///   boundary was `300`;
    /// * the walk stops when neither the running total nor the *next* bucket
    ///   reaches the current level, so an empty histogram yields nothing.
    pub fn linear_buckets(&self, step_size: i64) -> Vec<(i64, i64)> {
        let mut result = Vec::new();
        if step_size <= 0 {
            return result;
        }
        let mut cursor = Cursor::new(self);
        let mut reporting_level = step_size;
        let mut reporting_level_lowest = self.layout.lowest_equivalent_value(step_size);

        loop {
            let mut count_added = 0_i64;
            if !(cursor.has_next() || cursor.next_value_greater_than(reporting_level_lowest)) {
                break;
            }
            loop {
                if cursor.value >= reporting_level_lowest {
                    if reporting_level == INT64_MAX {
                        reporting_level_lowest = INT64_MAX;
                    } else if reporting_level > INT64_MAX - step_size {
                        reporting_level = INT64_MAX;
                        reporting_level_lowest = self.layout.lowest_equivalent_value(INT64_MAX);
                    } else {
                        reporting_level += step_size;
                        reporting_level_lowest =
                            self.layout.lowest_equivalent_value(reporting_level);
                    }
                    result.push((cursor.value, count_added));
                    break;
                }
                if !cursor.move_next() {
                    // `move_next` failing still returns `true` from the C, so the
                    // step is emitted with the samples collected so far.
                    result.push((cursor.value, count_added));
                    break;
                }
                count_added += cursor.count;
            }
            if reporting_level == INT64_MAX && cursor.value >= reporting_level_lowest {
                break;
            }
        }
        result
    }

    /// `hdr_iter_log_init` + `log_iter_next`.
    ///
    /// The level advances by `next_value_reporting_level *= (int64_t) log_base`,
    /// an **integer** accumulation, not repeated multiplication by the `f64`. For
    /// `log_base` 2 the two agree; for 1.5 they diverge after the first step, and
    /// the C is the authority.
    pub fn log_buckets(&self, first_bucket: i64, log_base: f64) -> Vec<(i64, i64)> {
        let mut result = Vec::new();
        if first_bucket <= 0
            || !log_base.is_finite()
            || log_base <= 1.0
            || log_base >= INT64_MAX as f64
        {
            return result;
        }
        let base = log_base as i64;
        let mut cursor = Cursor::new(self);
        let mut reporting_level = first_bucket;
        let mut reporting_level_lowest = self.layout.lowest_equivalent_value(first_bucket);

        loop {
            let mut count_added = 0_i64;
            if !(cursor.has_next() || cursor.next_value_greater_than(reporting_level_lowest)) {
                break;
            }
            loop {
                if cursor.value >= reporting_level_lowest {
                    if reporting_level == INT64_MAX {
                        reporting_level_lowest = INT64_MAX;
                    } else if base <= 1
                        || reporting_level <= 0
                        || reporting_level > INT64_MAX / base
                    {
                        reporting_level = INT64_MAX;
                        reporting_level_lowest = self.layout.lowest_equivalent_value(INT64_MAX);
                    } else {
                        reporting_level *= base;
                        reporting_level_lowest =
                            self.layout.lowest_equivalent_value(reporting_level);
                    }
                    result.push((cursor.value, count_added));
                    break;
                }
                if !cursor.move_next() {
                    result.push((cursor.value, count_added));
                    break;
                }
                count_added += cursor.count;
            }
            if reporting_level == INT64_MAX && cursor.value >= reporting_level_lowest {
                break;
            }
        }
        result
    }

    /// `hdr_value_at_percentiles`: the batch form `percentilesAt` uses.
    ///
    /// Differs from repeated [`value_at_percentile`](Self::value_at_percentile) in
    /// one observable way: the target count is floored at `1`, so an empty
    /// histogram reports the *lowest* bucket's highest equivalent value rather
    /// than `0`. Node's `percentilesAt` on an empty histogram therefore returns
    /// `1` for every percentile, while `percentile(p)` returns `0`.
    pub fn values_at_percentiles(&self, percentiles: &[f64]) -> Vec<i64> {
        let total = self.total_count;
        // `values[i]` is the cumulative count the walk is aiming for. The scan
        // below writes the answer in place, exactly as the C does with the same
        // array, so the comparison is against the *original* target until it is
        // replaced.
        let mut targets: Vec<i64> = percentiles
            .iter()
            .map(|percentile| {
                let requested = if *percentile < 100.0 {
                    *percentile
                } else {
                    100.0
                };
                let count = ((requested / 100.0) * total as f64 + 0.5) as i64;
                if count > 1 {
                    count
                } else {
                    1
                }
            })
            .collect();

        // No bucket can reach a target of `1` on an empty histogram, so the scan
        // below writes nothing and the targets keep the `1` they were clamped to.
        // That asymmetry with `percentile(p)`, which reports `0`, is Node's.
        let mut running = 0_i64;
        let mut at_pos = 0_usize;
        for index in 0..self.counts.len() {
            running += self.counts[index];
            while at_pos < targets.len() && running >= targets[at_pos] {
                targets[at_pos] = self
                    .layout
                    .highest_equivalent_value(self.layout.value_at_index(index as i32));
                at_pos += 1;
            }
            if at_pos >= targets.len() {
                break;
            }
        }
        targets
    }

    /// `hdr_add`: merge `other`'s counts into this one.
    ///
    /// Returns the number of samples `other` held that could not be recorded
    /// here, which is what Node's `Histogram::Add` returns and `RecordableHistogram#add`
    /// discards.
    pub fn add(&mut self, other: &HdrHistogram) -> i64 {
        // Node iterates `other`'s recorded buckets and records each value
        // `count` times, so a value this histogram cannot hold is dropped and
        // counted rather than copied into a mismatched index.
        let mut dropped = 0_i64;
        for bucket in other.iter_recorded() {
            if self.record_values(bucket.value, bucket.count) {
                continue;
            }
            dropped += bucket.count;
        }
        dropped
    }

    /// `hdr_add`'s `counts[]`-wise sibling used by `Histogram::Subtract`.
    ///
    /// Not the same operation as [`add`](Self::add): `Subtract` indexes the two
    /// arrays positionally and clamps at zero, so it needs the raw arrays. Node
    /// then recomputes the internal counters from the surviving counts.
    pub fn subtract(&mut self, other: &HdrHistogram) -> i64 {
        let mut dropped = 0_i64;
        let len = self.counts.len().min(other.counts.len());
        for index in 0..len {
            let mut count = self.counts[index] - other.counts[index];
            if count < 0 {
                dropped += -count;
                count = 0;
            }
            self.counts[index] = count;
        }
        self.reset_internal_counters();
        dropped
    }

    /// `hdr_reset_internal_counters`: derive `total_count`, `min` and `max` from
    /// the counts array after it was edited in place.
    pub fn reset_internal_counters(&mut self) {
        let mut observed_total_count = 0_i64;
        let mut min_non_zero_index = -1_i32;
        let mut max_index = -1_i32;

        for index in 0..self.counts.len() {
            let count_at_index = self.counts[index];
            if count_at_index > 0 {
                observed_total_count = observed_total_count.saturating_add(count_at_index);
                max_index = index as i32;
                if min_non_zero_index == -1 && index != 0 {
                    min_non_zero_index = index as i32;
                }
            }
        }

        if max_index == -1 {
            self.max_value = 0;
        } else {
            let max_value = self.layout.value_at_index(max_index);
            self.max_value = self.layout.highest_equivalent_value(max_value);
        }

        if min_non_zero_index == -1 {
            self.min_value = INT64_MAX;
        } else {
            self.min_value = self.layout.value_at_index(min_non_zero_index);
        }

        self.total_count = observed_total_count;
    }

    /// Whether `other` maps values to the same bucket indexes.
    ///
    /// `Histogram::IsCompatible`: the four fields that decide the layout, compared
    /// directly. Two histograms with the same `counts_len` can still disagree about
    /// where a value falls, so the length alone is not the answer.
    pub fn same_layout(&self, other: &HdrHistogram) -> bool {
        self.layout.counts_len == other.layout.counts_len
            && self.layout.lowest_discernible_value == other.layout.lowest_discernible_value
            && self.layout.highest_trackable_value == other.layout.highest_trackable_value
            && self.layout.significant_figures == other.layout.significant_figures
    }

    /// The layout's counts-array length, for a caller comparing two histograms.
    pub fn layout_counts_len(&self) -> i32 {
        self.layout.counts_len
    }

    /// The layout, for the CBOR exporter which writes its four fields.
    pub fn layout_of(&self) -> &Layout {
        &self.layout
    }

    /// The counts array, for the CBOR exporter's sparse encoding.
    pub fn counts_slice(&self) -> &[i64] {
        &self.counts
    }

    /// `min_value` as the struct holds it, which the exporter writes verbatim.
    pub fn raw_min_value(&self) -> i64 {
        self.min_value
    }

    /// `max_value` as the struct holds it.
    pub fn raw_max_value(&self) -> i64 {
        self.max_value
    }

    /// Restores one bucket's count without touching the counters.
    ///
    /// Only the importer uses this: it writes every non-zero bucket and then
    /// calls [`reset_internal_counters`](Self::reset_internal_counters), exactly
    /// as `Histogram::Import` does.
    pub fn set_count_raw(&mut self, index: usize, count: i64) {
        if let Some(slot) = self.counts.get_mut(index) {
            *slot = count;
        }
    }

    /// Restores `min_value` from a payload that recorded it.
    pub fn set_raw_min_value(&mut self, value: i64) {
        self.min_value = value;
    }

    /// Restores `max_value` from a payload that recorded it.
    pub fn set_raw_max_value(&mut self, value: i64) {
        self.max_value = value;
    }

    /// An independent copy with the same recorded data.
    ///
    /// `Histogram::Clone` in Node, which `snapshot()` uses. The copy carries the
    /// counts, total and min/max; nothing else in this struct is per-histogram
    /// state.
    pub fn clone_recorded(&self) -> Self {
        Self {
            layout: self.layout,
            counts: self.counts.clone(),
            total_count: self.total_count,
            min_value: self.min_value,
            max_value: self.max_value,
        }
    }

    /// The values Node's `snapshot()` subtracts one from the other for `diff`.
    ///
    /// Returns `None` when `other` cannot be an earlier snapshot of this one,
    /// which `Histogram::Diff` reports as an error rather than a number. The
    /// `resetCount` check is what makes `diff` after a `subtract` refuse: the
    /// samples `other` holds are no longer a prefix of these counts.
    pub fn diff(
        &self,
        other: &HdrHistogram,
        self_reset_count: u64,
        other_reset_count: u64,
    ) -> Option<Self> {
        if !self.same_layout(other) {
            return None;
        }
        // `DiffError::kReset`: `other` predates a `reset()` or `subtract()` that
        // removed samples, so its counts are no longer a subset of these.
        if self_reset_count != other_reset_count {
            return None;
        }
        let mut result = self.clone_recorded();
        for index in 0..result.counts.len() {
            let theirs = other.counts.get(index).copied().unwrap_or(0);
            if result.counts[index] < theirs {
                return None;
            }
            result.counts[index] -= theirs;
        }
        result.reset_internal_counters();
        Some(result)
    }
}

/// `hdr_iter_next` over every index.
pub struct AllBuckets<'a> {
    histogram: &'a HdrHistogram,
    next_index: usize,
    cumulative: i64,
}

impl Iterator for AllBuckets<'_> {
    type Item = Bucket;

    fn next(&mut self) -> Option<Bucket> {
        if self.next_index >= self.histogram.counts.len() {
            return None;
        }
        let index = self.next_index as i32;
        let mut bucket = self.histogram.bucket_at(index);
        self.cumulative += bucket.count;
        bucket.cumulative_count = self.cumulative;
        self.next_index += 1;
        Some(bucket)
    }
}

/// The mutable half of `struct hdr_iter` the linear and log iterators drive.
///
/// Those two walk the counts array themselves rather than consuming
/// [`AllBuckets`], because their termination rule depends on `counts_index`,
/// `value` and `cumulative_count` together. Keeping the three fields in one place
/// makes `move_next`, `has_next` and `next_value_greater_than` read the way the C
/// functions do.
struct Cursor<'a> {
    histogram: &'a HdrHistogram,
    counts_index: i32,
    count: i64,
    cumulative_count: i64,
    value: i64,
}

impl<'a> Cursor<'a> {
    /// `hdr_iter_init`: `counts_index` starts at `-1`.
    fn new(histogram: &'a HdrHistogram) -> Self {
        Self {
            histogram,
            counts_index: -1,
            count: 0,
            cumulative_count: 0,
            value: 0,
        }
    }

    /// `has_next`: whether any recorded sample is still ahead.
    fn has_next(&self) -> bool {
        self.cumulative_count < self.histogram.total_count
    }

    /// `move_next`.
    fn move_next(&mut self) -> bool {
        self.counts_index += 1;
        if self.counts_index >= self.histogram.counts.len() as i32 {
            return false;
        }
        self.count = self.histogram.count_at_index(self.counts_index);
        self.cumulative_count += self.count;
        self.value = self.histogram.layout.value_at_index(self.counts_index);
        true
    }

    /// `next_value_greater_than_reporting_level_upper_bound`.
    fn next_value_greater_than(&self, bound: i64) -> bool {
        if self.counts_index >= self.histogram.counts.len() as i32 {
            return false;
        }
        self.peek_next_value() > bound
    }

    /// `peek_next_value_from_index`, including its saturation.
    fn peek_next_value(&self) -> i64 {
        let layout = &self.histogram.layout;
        let index = self.counts_index + 1;
        let mut bucket_index =
            ((index as u32) >> layout.sub_bucket_half_count_magnitude) as i32 - 1;
        let mut sub_bucket_index =
            (index & (layout.sub_bucket_half_count - 1)) + layout.sub_bucket_half_count;
        if bucket_index < 0 {
            sub_bucket_index -= layout.sub_bucket_half_count;
            bucket_index = 0;
        }
        let shift = bucket_index + layout.unit_magnitude;
        if shift >= 63 || (sub_bucket_index as u64) > ((INT64_MAX as u64) >> shift) {
            return INT64_MAX;
        }
        value_from_index(bucket_index, sub_bucket_index, layout.unit_magnitude)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn histogram(lowest: i64, highest: i64, figures: i32) -> HdrHistogram {
        HdrHistogram::new(Layout::new(lowest, highest, figures).expect("valid layout"))
    }

    /// The layout defaults Node uses for `createHistogram()` with no options.
    #[test]
    fn the_default_layout_covers_the_whole_int64_range() {
        let layout = Layout::new(1, INT64_MAX, 3).expect("the default is valid");
        // `2 * 10^3 = 2000`, whose `ceil(log2)` is 11, so the half count
        // magnitude is 10 and the sub-bucket count 2048.
        assert_eq!(layout.sub_bucket_half_count_magnitude, 10);
        assert_eq!(layout.sub_bucket_count, 2048);
        assert_eq!(layout.sub_bucket_half_count, 1024);
        assert_eq!(layout.unit_magnitude, 0);
        // 53 buckets of 1024 counts each covers INT64_MAX at 2048 values per
        // bucket once the unit magnitude is 0. Recorded as a property rather than
        // two literals: the point is that the bucket count is derived, and a
        // formula repeated here would pass for any value the formula produced.
        assert!(layout.bucket_count > 50, "{}", layout.bucket_count);
        assert_eq!(layout.counts_len, (layout.bucket_count + 1) * 1024);
    }

    /// A layout whose `lowest` is not a power of two still has a defined
    /// `unit_magnitude`, and `hdr_init` accepts it.
    #[test]
    fn a_lowest_value_above_one_shifts_the_unit_magnitude() {
        let layout = Layout::new(1000, 100_000, 3).expect("valid");
        // floor(log2(1000)) == 9.
        assert_eq!(layout.unit_magnitude, 9);
    }

    /// `hdr_calculate_bucket_config` rejects the combinations Node's JS layer
    /// lets through to the native check.
    #[test]
    fn the_layout_rejects_what_hdr_init_rejects() {
        assert_eq!(Layout::new(0, 100, 3), Err(LayoutError::InvalidOptions));
        assert_eq!(Layout::new(1, 100, 0), Err(LayoutError::InvalidOptions));
        assert_eq!(Layout::new(1, 100, 6), Err(LayoutError::InvalidOptions));
        // `lowest > highest / 2`.
        assert_eq!(Layout::new(51, 100, 3), Err(LayoutError::InvalidOptions));
        assert!(Layout::new(50, 100, 3).is_ok());
    }

    /// An empty histogram reports Node's sentinels: `min` is `INT64_MAX`,
    /// `max` is `0`, and mean/stddev are `NaN`.
    #[test]
    fn an_empty_histogram_reports_the_sentinels_node_does() {
        let histogram = histogram(1, 1000, 3);
        assert_eq!(histogram.count(), 0);
        assert_eq!(histogram.min(), INT64_MAX);
        assert_eq!(histogram.max(), 0);
        assert!(histogram.mean().is_nan());
        assert!(histogram.stddev().is_nan());
    }

    /// A recorded value round-trips through `min` exactly and through `max` with
    /// the bucket's upper edge, which is the behaviour every consumer sees.
    #[test]
    fn min_is_exact_and_max_is_the_bucket_upper_edge() {
        let mut histogram = histogram(1, 1000, 2);
        for value in [1, 2, 3, 5, 8] {
            assert!(histogram.record(value));
        }
        assert_eq!(histogram.count(), 5);
        assert_eq!(histogram.min(), 1);
        // Two significant figures put 8 at the top of a bucket that ends at 8
        // itself; the oracle reports 8 here, so a port that rounded up to 9 would
        // be wrong. `C.coarse` in the differential probe is where the bucket edge
        // really shows (400 -> 415 at one significant figure).
        assert_eq!(histogram.max(), 8);
    }

    /// A value above `highest_trackable_value` is rejected and does not inflate
    /// the count, which is what makes `exceeds` meaningful.
    #[test]
    fn a_value_above_the_cap_is_not_recorded() {
        let mut histogram = histogram(1, 100, 3);
        assert!(histogram.record(50));
        assert!(!histogram.record(101));
        assert_eq!(histogram.count(), 1);
        assert_eq!(histogram.max(), 50);
    }

    /// Recording zero is its own case: it does not move `min_value`, but
    /// `hdr_min` reports `0` because index `0` holds a count.
    #[test]
    fn a_recorded_zero_makes_min_report_zero() {
        let mut histogram = histogram(1, 1000, 3);
        histogram.record(0);
        histogram.record(10);
        assert_eq!(histogram.min(), 0);
        // `min()` reports 0 through the index-0 check; the stored minimum is
        // still the smallest non-zero value.
        assert_eq!(histogram.min(), 0);
    }

    /// `reset` clears counters and sentinels but keeps the layout.
    #[test]
    fn reset_returns_the_histogram_to_its_empty_state() {
        let mut histogram = histogram(1, 1000, 3);
        histogram.record(7);
        histogram.record(9);
        histogram.reset();
        assert_eq!(histogram.count(), 0);
        assert_eq!(histogram.min(), INT64_MAX);
        assert_eq!(histogram.max(), 0);
        assert_eq!(histogram.layout_counts_len(), histogram.layout_counts_len());
        assert!(histogram.record(5));
        assert_eq!(histogram.count(), 1);
    }

    /// `record_corrected` backfills the intermediate values, so the count ends
    /// up higher than the single call suggests.
    #[test]
    fn record_corrected_backfills_intermediate_values() {
        let mut histogram = histogram(1, 10_000, 3);
        histogram.record_corrected(100, 10);
        // 100 is recorded, then 90, 80, ... 10.
        assert_eq!(histogram.count(), 10);
        assert_eq!(histogram.min(), 10);
    }

    /// `add` merges counts, so the total is the sum.
    #[test]
    fn add_merges_two_histograms() {
        let mut left = histogram(1, 1000, 3);
        let mut right = histogram(1, 1000, 3);
        left.record(10);
        right.record(20);
        right.record(30);
        assert_eq!(left.add(&right), 0);
        assert_eq!(left.count(), 3);
        assert_eq!(left.min(), 10);
    }

    /// `subtract` clamps at zero and reports how many samples it dropped.
    #[test]
    fn subtract_clamps_at_zero_and_reports_dropped_samples() {
        let mut left = histogram(1, 1000, 3);
        let mut right = histogram(1, 1000, 3);
        left.record(10);
        right.record(10);
        right.record(20);
        right.record(20);
        // `20` exists only in `right`, so two samples are dropped.
        assert_eq!(left.subtract(&right), 2);
        assert_eq!(left.count(), 0);
    }

    /// `diff` returns the samples recorded after the earlier snapshot, and
    /// refuses when the later histogram holds fewer.
    #[test]
    fn diff_returns_only_the_later_samples() {
        let mut histogram = histogram(1, 1000, 3);
        histogram.record(10);
        let snapshot = histogram.clone_recorded();
        histogram.record(20);
        // A snapshot shares the reset count of the histogram it came from.
        let difference = histogram.diff(&snapshot, 0, 0).expect("compatible");
        assert_eq!(difference.count(), 1);
        // The difference holds only the sample recorded after the snapshot, so
        // its minimum is that sample rather than the histogram's.
        assert_eq!(difference.min(), 20);
        // The later histogram holds a sample the snapshot does not, so the
        // reverse direction is refused.
        assert!(snapshot.diff(&histogram, 0, 0).is_none());
        // And a differing reset count is refused outright.
        assert!(histogram.diff(&snapshot, 1, 0).is_none());
    }

    /// `count_at_value` maps the value to a bucket index, so the *lowest* value
    /// in a bucket is the one that reports its count.
    ///
    /// Two significant figures give 8 a bucket of its own, which is why 9 is 0
    /// here rather than 1: the equivalent-value range at this layout is one wide.
    #[test]
    fn count_at_value_maps_to_the_bucket_index() {
        let mut histogram = histogram(1, 1000, 3);
        histogram.record(8);
        assert_eq!(histogram.count_at_value(8), 1);
        assert_eq!(histogram.count_at_value(9), 0);
        assert_eq!(histogram.count_at_value(7), 0);
    }
}
