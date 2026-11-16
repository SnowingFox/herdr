//! The monotonic clock `Bun`'s time members measure from.
//!
//! `Bun.nanoseconds()` is not `Date.now()` in nanoseconds and not
//! `performance.now()` either: it reports nanoseconds since the process started,
//! which is `1_004_000_000`-ish after a one-second `await Bun.sleep(1000)` on Bun
//! 1.4.4. The origin is therefore recorded once, at bootstrap, and every read is
//! `now - origin`.
//!
//! # Why this lives here and not in a contribution crate
//!
//! Three separate Tier-1 groups need it — `nanoseconds` and both sleeps in
//! text/misc, and anything that times a file operation in files — so a copy per
//! crate is a copy that can disagree about the origin. One origin per process is
//! the property `Bun` itself has: two members of the same global cannot disagree
//! about when the process started.
//!
//! The origin is a `OnceLock` rather than a value passed through every call
//! because the members that read it are V8 callbacks, whose data slot is a
//! statically sized `Value` and cannot carry a captured `Instant`.
//!
//! `pub` rather than `pub(crate)`, with [`record_process_start`] and
//! [`nanoseconds_since_start`], because [`crate::BunRegistry`] is not the only
//! thing a contribution crate reaches for and a private clock would be
//! reimplemented in the first crate that needs it.

use std::sync::OnceLock;
use std::time::Instant;

static ORIGIN: OnceLock<Instant> = OnceLock::new();

/// Records the process start origin, once.
///
/// Called by `rn-bun`'s `install` before any member is built, and idempotent: a
/// second call leaves the first origin in place, because a worker isolate
/// re-running the bootstrap must not reset a clock the main thread already read.
pub fn record_process_start() {
    let _ = ORIGIN.set(Instant::now());
}

/// Nanoseconds since the recorded origin.
///
/// If no origin was recorded this records one and returns 0, which keeps the
/// function total for a binding crate called from a test that never ran the
/// install step. Returning an error instead would make every such test fail for a
/// reason unrelated to what it measures.
pub fn nanoseconds_since_start() -> u64 {
    let origin = *ORIGIN.get_or_init(Instant::now);
    // `as_nanos` is a `u128`; the value is a duration since process start, which
    // cannot reach 584 years, so the cast is not a wrap in practice. Saturating
    // keeps the binding honest rather than silently truncating in the case that
    // cannot happen.
    u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Milliseconds as a float, for members that report fractional time.
pub fn milliseconds_since_start() -> f64 {
    nanoseconds_since_start() as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_origin_is_recorded_once_and_time_moves_forward() {
        // Another test in this process may already have recorded the origin; the
        // assertion that matters is that it does not move, not that this test was
        // first.
        record_process_start();
        let first = nanoseconds_since_start();
        let after_record = nanoseconds_since_start();
        assert!(
            after_record >= first,
            "a second record_process_start reset the origin: {first} then {after_record}"
        );

        std::thread::sleep(std::time::Duration::from_millis(5));
        let later = nanoseconds_since_start();
        assert!(
            later > after_record,
            "the clock did not advance: {after_record} then {later}"
        );
        assert!(
            later - after_record >= 4_000_000,
            "5 ms of sleep reported as {} ns, so this is not a nanosecond clock",
            later - after_record
        );
    }

    #[test]
    fn the_millisecond_view_agrees_with_the_nanosecond_one() {
        let nanos = nanoseconds_since_start();
        let millis = milliseconds_since_start();
        let difference = (millis * 1_000_000.0 - nanos as f64).abs();
        assert!(
            difference < 2_000_000.0,
            "the two views disagree by {difference} ns, so one of them is not \
             reading the same clock"
        );
    }
}
