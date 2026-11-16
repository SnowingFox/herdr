//! `Histogram#export()` and `perf_hooks.importHistogram()`, on Node's wire format.
//!
//! The format is the one `Histogram::Export` and `Histogram::Import` in
//! `src/histogram.cc` define: a CBOR map with a fixed key set, whose only
//! interesting member is the sparse, delta-encoded counts array. Reproducing it
//! byte for byte matters in one direction — an exported histogram is meant to
//! outlive the process that wrote it, so a peer reads it with Node's decoder —
//! which is why the encoder's key order, integer widths and the `float64` choice
//! for `conversion_ratio` all follow the C rather than being "obviously right".
//!
//! The decoder is deliberately as strict as Node's: duplicate keys, an
//! out-of-range bucket index, a `counts_len` that disagrees with the options, and
//! a `total_count` that disagrees with the counts are all rejections rather than
//! repairs. Those checks are load-bearing — `Import` is fed arbitrary bytes, and
//! a relaxed decoder is how a crafted buffer becomes an out-of-bounds write in
//! the counts array.

use crate::hdr::{HdrHistogram, Layout};

/// The format version this encoder writes (`kExportVersion`).
const EXPORT_VERSION: u64 = 2;
/// The version that rejects unknown keys (`kStrictExportVersion`).
const STRICT_EXPORT_VERSION: u64 = 1;

const KEY_VERSION: u64 = 0;
const KEY_LOWEST: u64 = 1;
const KEY_HIGHEST: u64 = 2;
const KEY_FIGURES: u64 = 3;
const KEY_TOTAL_COUNT: u64 = 4;
const KEY_MIN: u64 = 5;
const KEY_MAX: u64 = 6;
const KEY_NORM_OFFSET: u64 = 7;
const KEY_CONV_RATIO: u64 = 8;
const KEY_COUNTS_LEN: u64 = 9;
const KEY_COUNTS: u64 = 10;
const KEY_EWMA: u64 = 11;

const EWMA_ALPHA: u64 = 0;
const EWMA_MEAN: u64 = 1;
const EWMA_VARIANCE: u64 = 2;
const EWMA_ERROR_RATE: u64 = 3;
const EWMA_THRESHOLD: u64 = 4;

/// CBOR major types, as the upper three bits of the initial byte.
const CBOR_UINT: u8 = 0 << 5;
const CBOR_ARRAY: u8 = 4 << 5;
const CBOR_MAP: u8 = 5 << 5;
/// Major 7 with additional information 27: an IEEE 754 double.
const CBOR_FLOAT64: u8 = 0xfb;

/// The EWMA state an export may carry.
///
/// Present only when the histogram was built with a `halfLife`, which is what
/// arms the EWMA in the first place.
#[derive(Clone, Copy, Debug, Default)]
pub struct EwmaExport {
    pub alpha: f64,
    pub mean: f64,
    pub variance: f64,
    pub error_rate: f64,
    pub threshold: i64,
}

impl EwmaExport {
    /// Whether this state should be written at all.
    fn is_present(self) -> bool {
        self.alpha > 0.0
    }
}

/// `CborWriteUint`: the shortest of the five integer encodings for `value`.
fn write_uint(out: &mut Vec<u8>, major: u8, value: u64) {
    if value <= 23 {
        out.push(major | value as u8);
    } else if value <= 0xff {
        out.push(major | 24);
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(major | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xffff_ffff {
        out.push(major | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// `CborWriteFloat64`: always the 9-byte form, never a shorter one.
///
/// The shorter float16/float32 forms are valid CBOR and would decode the same,
/// but `CborWriteFloat64` only ever emits `0xfb`, and an export that used a
/// narrower encoding would not be byte-identical to Node's.
fn write_float64(out: &mut Vec<u8>, value: f64) {
    out.push(CBOR_FLOAT64);
    out.extend_from_slice(&value.to_bits().to_be_bytes());
}

/// `Histogram::Export`.
///
/// Returns the bytes `histogram.export()` hands to JavaScript.
pub fn export(histogram: &HdrHistogram, ewma: EwmaExport) -> Vec<u8> {
    let layout = histogram.layout_of();
    let counts = histogram.counts_slice();
    let non_zero = counts.iter().filter(|count| **count != 0).count();

    let map_size = if ewma.is_present() { 12 } else { 11 };
    let mut out = Vec::with_capacity(64 + non_zero * 10);
    write_uint(&mut out, CBOR_MAP, map_size);

    for (key, value) in [
        (KEY_VERSION, EXPORT_VERSION),
        (KEY_LOWEST, layout.lowest_discernible_value as u64),
        (KEY_HIGHEST, layout.highest_trackable_value as u64),
        (KEY_FIGURES, layout.significant_figures as u64),
        (KEY_TOTAL_COUNT, histogram.count() as u64),
        (KEY_MIN, histogram.raw_min_value() as u64),
        (KEY_MAX, histogram.raw_max_value() as u64),
        // `normalizing_index_offset` is always zero in this implementation: the
        // only thing that sets it is the decoder, and nothing rotates a histogram
        // here. Written anyway so the map has Node's shape.
        (KEY_NORM_OFFSET, 0),
    ] {
        write_uint(&mut out, CBOR_UINT, key);
        write_uint(&mut out, CBOR_UINT, value);
    }

    // `conversion_ratio` follows `normalizing_index_offset` and precedes
    // `counts_len`, and it is the one field written as a float even though its
    // value is always 1.0. Both are load-bearing: the map's byte layout is what a
    // peer's decoder walks in order.
    write_uint(&mut out, CBOR_UINT, KEY_CONV_RATIO);
    write_float64(&mut out, 1.0);

    write_uint(&mut out, CBOR_UINT, KEY_COUNTS_LEN);
    write_uint(&mut out, CBOR_UINT, layout.counts_len as u64);

    // The sparse counts: an array of `[delta, count, ...]` pairs where the first
    // delta is the absolute index and each later one is a step from the previous.
    write_uint(&mut out, CBOR_UINT, KEY_COUNTS);
    write_uint(&mut out, CBOR_ARRAY, (non_zero * 2) as u64);
    let mut previous = 0_i32;
    for (index, count) in counts.iter().enumerate() {
        if *count == 0 {
            continue;
        }
        let index = index as i32;
        write_uint(&mut out, CBOR_UINT, (index - previous) as u64);
        write_uint(&mut out, CBOR_UINT, *count as u64);
        previous = index;
    }

    if ewma.is_present() {
        write_uint(&mut out, CBOR_UINT, KEY_EWMA);
        write_uint(&mut out, CBOR_MAP, 5);
        for (key, value) in [
            (EWMA_ALPHA, ewma.alpha),
            (EWMA_MEAN, ewma.mean),
            (EWMA_VARIANCE, ewma.variance),
            (EWMA_ERROR_RATE, ewma.error_rate),
        ] {
            write_uint(&mut out, CBOR_UINT, key);
            write_float64(&mut out, value);
        }
        write_uint(&mut out, CBOR_UINT, EWMA_THRESHOLD);
        write_uint(&mut out, CBOR_UINT, ewma.threshold as u64);
    }

    out
}

/// A cursor over the CBOR a decode is reading.
struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// `CborReadUint`: the argument of the item at the cursor, whatever its
    /// major type. The caller checks the major type separately.
    fn read_argument_bits(&mut self) -> Option<u64> {
        let byte = *self.data.get(self.position)?;
        self.position += 1;
        let info = byte & 0x1f;
        let read = |reader: &mut Self, count: usize| -> Option<u64> {
            if reader.remaining() < count {
                return None;
            }
            let mut value = 0_u64;
            for _ in 0..count {
                value = (value << 8) | reader.data[reader.position] as u64;
                reader.position += 1;
            }
            Some(value)
        };
        match info {
            0..=23 => Some(info as u64),
            24 => read(self, 1),
            25 => read(self, 2),
            26 => read(self, 4),
            27 => read(self, 8),
            // 28..=31 are reserved or indefinite-length, neither supported.
            _ => None,
        }
    }

    /// `CborReadArgument`: the same, rejected unless the major type matches.
    fn read_argument(&mut self, major: u8) -> Option<u64> {
        let byte = *self.data.get(self.position)?;
        if byte & 0xe0 != major {
            return None;
        }
        self.read_argument_bits()
    }

    /// `CborReadInt64`: a non-negative integer that fits in an `i64`.
    fn read_int64(&mut self) -> Option<i64> {
        let value = self.read_argument(CBOR_UINT)?;
        i64::try_from(value).ok()
    }

    /// `CborReadInt32`.
    fn read_int32(&mut self) -> Option<i32> {
        let value = self.read_argument(CBOR_UINT)?;
        i32::try_from(value).ok()
    }

    /// `CborReadFloat64` + `CborReadNumber`: a uint or a `float64`.
    ///
    /// A `float32` or `float16` is rejected, matching the C, which only accepts
    /// `0xfb` or an unsigned integer.
    fn read_number(&mut self) -> Option<f64> {
        if *self.data.get(self.position)? == CBOR_FLOAT64 {
            self.position += 1;
            if self.remaining() < 8 {
                return None;
            }
            let mut bits = 0_u64;
            for _ in 0..8 {
                bits = (bits << 8) | self.data[self.position] as u64;
                self.position += 1;
            }
            return Some(f64::from_bits(bits));
        }
        let value = self.read_argument(CBOR_UINT)?;
        Some(value as f64)
    }

    /// `CborSkipItem`: step over one well-formed item, including nested items.
    fn skip_item(&mut self, depth: usize) -> Option<()> {
        if depth > 16 {
            return None;
        }
        let byte = *self.data.get(self.position)?;
        let major = byte >> 5;
        let argument = self.read_argument_bits()?;
        match major {
            // Unsigned integers and byte/text strings have no children.
            0 => Some(()),
            1 => Some(()),
            2 | 3 => {
                let length = usize::try_from(argument).ok()?;
                if self.remaining() < length {
                    return None;
                }
                self.position += length;
                Some(())
            }
            4 => {
                for _ in 0..argument {
                    self.skip_item(depth + 1)?;
                }
                Some(())
            }
            5 => {
                for _ in 0..argument {
                    self.skip_item(depth + 1)?;
                    self.skip_item(depth + 1)?;
                }
                Some(())
            }
            // Major 7 is a simple value or a float whose argument is inline.
            7 => Some(()),
            _ => None,
        }
    }
}

/// What a successful [`import`] produced.
pub struct Imported {
    pub histogram: HdrHistogram,
    /// The EWMA state the payload carried, if any.
    pub ewma: EwmaExport,
}

/// `Histogram::Import`. Returns `None` for anything Node rejects.
///
/// The rejections are the point: this is fed arbitrary bytes from a peer, and
/// every one of the bounds checks below prevents an out-of-bounds write into the
/// counts array.
pub fn import(data: &[u8]) -> Option<Imported> {
    let mut reader = Reader::new(data);
    let map_size = reader.read_argument(CBOR_MAP)?;

    let mut lowest: i64 = 1;
    let mut highest: i64 = i64::MAX;
    let mut figures: i32 = 3;
    let mut total_count: i64 = 0;
    let mut min_value: i64 = i64::MAX;
    let mut max_value: i64 = 0;
    let mut norm_offset: i32 = 0;
    let mut conv_ratio: f64 = 1.0;
    let mut counts_len: i32 = 0;
    let mut version: u64 = STRICT_EXPORT_VERSION;
    let mut seen_keys: u64 = 0;
    let mut seen_ewma_keys: u64 = 0;
    let mut has_unknown_keys = false;
    let mut sparse_counts: Vec<(i32, i64)> = Vec::new();
    let mut ewma = EwmaExport::default();

    let mark_seen = |seen: &mut u64, key: u64| -> bool {
        let bit = 1_u64 << key;
        if *seen & bit != 0 {
            return false;
        }
        *seen |= bit;
        true
    };

    for _ in 0..map_size {
        let key = reader.read_argument(CBOR_UINT)?;
        if key > KEY_EWMA {
            reader.skip_item(0)?;
            has_unknown_keys = true;
            continue;
        }
        if !mark_seen(&mut seen_keys, key) {
            return None;
        }
        match key {
            KEY_VERSION => {
                version = reader.read_argument(CBOR_UINT)?;
                if !(STRICT_EXPORT_VERSION..=EXPORT_VERSION).contains(&version) {
                    return None;
                }
            }
            KEY_LOWEST => lowest = reader.read_int64()?,
            KEY_HIGHEST => highest = reader.read_int64()?,
            KEY_FIGURES => figures = reader.read_int32()?,
            KEY_TOTAL_COUNT => total_count = reader.read_int64()?,
            KEY_MIN => min_value = reader.read_int64()?,
            KEY_MAX => max_value = reader.read_int64()?,
            KEY_NORM_OFFSET => norm_offset = reader.read_int32()?,
            KEY_CONV_RATIO => conv_ratio = reader.read_number()?,
            KEY_COUNTS_LEN => counts_len = reader.read_int32()?,
            KEY_COUNTS => {
                let array_len = reader.read_argument(CBOR_ARRAY)?;
                if array_len % 2 != 0 {
                    return None;
                }
                // Each element needs at least one byte, so an array length larger
                // than the remaining buffer is a lie. Without this, a crafted
                // `array_len` of `2^60` would allocate before the loop noticed.
                if array_len > reader.remaining() as u64 {
                    return None;
                }
                sparse_counts.reserve((array_len / 2) as usize);
                let mut accumulated: i64 = 0;
                for step in 0..array_len / 2 {
                    let delta = reader.read_int32()?;
                    let count = reader.read_int64()?;
                    // Indices are strictly increasing, so only the first delta —
                    // the absolute index of the first non-empty bucket — may be 0.
                    if step > 0 && delta == 0 {
                        return None;
                    }
                    accumulated += delta as i64;
                    if accumulated > i32::MAX as i64 {
                        return None;
                    }
                    sparse_counts.push((accumulated as i32, count));
                }
            }
            KEY_EWMA => {
                let sub_size = reader.read_argument(CBOR_MAP)?;
                for _ in 0..sub_size {
                    let sub_key = reader.read_argument(CBOR_UINT)?;
                    if sub_key > EWMA_THRESHOLD {
                        reader.skip_item(0)?;
                        has_unknown_keys = true;
                        continue;
                    }
                    if !mark_seen(&mut seen_ewma_keys, sub_key) {
                        return None;
                    }
                    match sub_key {
                        EWMA_ALPHA => ewma.alpha = reader.read_number()?,
                        EWMA_MEAN => ewma.mean = reader.read_number()?,
                        EWMA_VARIANCE => ewma.variance = reader.read_number()?,
                        EWMA_ERROR_RATE => ewma.error_rate = reader.read_number()?,
                        EWMA_THRESHOLD => ewma.threshold = reader.read_int64()?,
                        _ => return None,
                    }
                }
            }
            _ => return None,
        }
    }

    // Version 1 data keeps its original semantics: unknown keys are rejected.
    if version == STRICT_EXPORT_VERSION && has_unknown_keys {
        return None;
    }

    let layout = Layout::new(lowest, highest, figures).ok()?;
    if layout.counts_len != counts_len {
        return None;
    }
    // The normalization offset must index into the counts array, or a later
    // `record` would write out of bounds through `counts_inc_normalised`.
    if norm_offset < 0 || norm_offset >= counts_len {
        return None;
    }

    let mut histogram = HdrHistogram::new(layout);
    let mut observed_total: i64 = 0;
    for (index, count) in &sparse_counts {
        if *index < 0 || *index >= counts_len {
            return None;
        }
        observed_total = observed_total.checked_add(*count)?;
        histogram.set_count_raw(*index as usize, *count);
    }
    let _ = conv_ratio;

    // Derive the total, min and max from the counts, then overwrite min and max
    // with the recorded values when the payload carried them.
    histogram.reset_internal_counters();
    if seen_keys & (1 << KEY_TOTAL_COUNT) != 0 && total_count != histogram.count() {
        return None;
    }
    if seen_keys & (1 << KEY_MIN) != 0 {
        histogram.set_raw_min_value(min_value);
    }
    if seen_keys & (1 << KEY_MAX) != 0 {
        histogram.set_raw_max_value(max_value);
    }

    // A half life is what arms the EWMA, and Node recomputes it from `alpha` so
    // that a later record continues the same smoothing.
    let threshold = ewma.threshold;
    let ewma = if ewma.alpha > 0.0 {
        EwmaExport { threshold, ..ewma }
    } else {
        EwmaExport::default()
    };

    Some(Imported { histogram, ewma })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn histogram() -> HdrHistogram {
        let layout = Layout::new(1, 1000, 3).expect("valid");
        let mut histogram = HdrHistogram::new(layout);
        for value in [10, 20, 30] {
            histogram.record(value);
        }
        histogram
    }

    /// A round trip preserves every recorded value and the derived statistics.
    #[test]
    fn a_round_trip_preserves_the_recorded_data() {
        let original = histogram();
        let bytes = export(&original, EwmaExport::default());
        let imported = import(&bytes).expect("its own export must import");
        assert_eq!(imported.histogram.count(), original.count());
        assert_eq!(imported.histogram.min(), original.min());
        assert_eq!(imported.histogram.max(), original.max());
        assert_eq!(imported.histogram.mean(), original.mean());
        assert_eq!(imported.histogram.stddev(), original.stddev());
        assert_eq!(
            imported.histogram.value_at_percentile(50.0),
            original.value_at_percentile(50.0)
        );
    }

    /// The encoder's header is a CBOR map of the size Node writes, so a peer's
    /// decoder sees the shape it expects.
    #[test]
    fn the_export_begins_with_an_eleven_entry_map() {
        let bytes = export(&histogram(), EwmaExport::default());
        // Major 5 (map) with 11 entries: `0xa0 | 11`.
        assert_eq!(bytes[0], CBOR_MAP | 11);
    }

    /// An EWMA makes the map one entry larger, which is the only structural
    /// difference between the two shapes.
    #[test]
    fn an_ewma_export_carries_one_more_map_entry() {
        let bytes = export(
            &histogram(),
            EwmaExport {
                alpha: 0.5,
                mean: 1.0,
                variance: 2.0,
                error_rate: 0.25,
                threshold: 7,
            },
        );
        assert_eq!(bytes[0], CBOR_MAP | 12);
        let imported = import(&bytes).expect("an EWMA export must import");
        assert_eq!(imported.ewma.alpha, 0.5);
        assert_eq!(imported.ewma.threshold, 7);
    }

    /// Truncated input is rejected rather than panicking.
    #[test]
    fn truncated_input_is_rejected() {
        let bytes = export(&histogram(), EwmaExport::default());
        for length in 0..bytes.len() {
            assert!(
                import(&bytes[..length]).is_none(),
                "a {length}-byte prefix must not import"
            );
        }
    }

    /// A bucket index past the counts array is rejected, which is the bounds
    /// check that stops a crafted payload writing out of bounds.
    #[test]
    fn an_out_of_range_bucket_index_is_rejected() {
        let mut bytes = export(&histogram(), EwmaExport::default());
        // The payload's counts are recorded at bucket indexes well inside the
        // array; rewriting the `counts_len` field to disagree is the simplest way
        // to build a payload the importer must refuse.
        let layout = Layout::new(1, 1000, 3).expect("valid");
        let mut wrong = Vec::new();
        write_uint(&mut wrong, CBOR_MAP, 11);
        for (key, value) in [
            (KEY_VERSION, EXPORT_VERSION),
            (KEY_LOWEST, 1),
            (KEY_HIGHEST, 1000),
            (KEY_FIGURES, 3),
            (KEY_COUNTS_LEN, layout.counts_len as u64 + 1),
        ] {
            write_uint(&mut wrong, CBOR_UINT, key);
            write_uint(&mut wrong, CBOR_UINT, value);
        }
        assert!(import(&wrong).is_none());
        // And the real one still imports, so the rejection above is about the
        // mismatched length rather than about a short map.
        bytes.truncate(bytes.len());
        assert!(import(&bytes).is_some());
    }
}
