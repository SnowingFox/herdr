//! `Bun.nanoseconds`, `Bun.sleep`, `Bun.sleepSync` and `Bun.shrink`.
//!
//! `nanoseconds()` returns the monotonic clock in nanoseconds as a **`number`**,
//! not a BigInt. Its absolute value means nothing across processes, so only its
//! type, safe-integer property and monotonicity are testable.
//!
//! `sleep` and `sleepSync` disagree on almost everything, and each disagreement
//! was measured:
//!
//! ```text
//! sleep(number | Date)   resolves after the delay; NaN and a negative resolve at once
//! sleep(string | bigint | null | {})   TypeError, NO code
//!                                       "sleep expects a number (milliseconds)"
//!
//! sleepSync(number)      blocks; NaN blocks for 0, and 1.5 blocks for 1
//! sleepSync(Date | null | string)      TypeError ERR_INVALID_ARG_TYPE
//!                                       "milliseconds must be a number"
//! sleepSync(-5)                        TypeError ERR_INVALID_ARG_TYPE
//!                                       "argument to sleepSync must not be negative, got -5"
//! ```
//!
//! The one thing they agree on is that a `Date` is an accepted input shape and
//! that `NaN` is not an error — Bun's own code treats `NaN` as `0`, so it is
//! "0 with no diagnostic", not "invalid".

/// What a `sleep` argument turned into.
pub enum SleepDelay {
    /// Wait this many milliseconds, then resolve.
    Milliseconds(f64),
    /// The argument is not an acceptable shape; the message carries no `code`.
    Invalid,
    /// `sleepSync`-only: the argument is acceptable but out of range, and the
    /// message names the value.
    Negative(i64),
}

/// Reads `sleep`'s argument as a delay.
///
/// `Some(number)` is the numeric form; `Some(date_epoch_millis)` is the `Date`
/// form, which delays until that instant and therefore resolves immediately when
/// it is in the past.
pub fn validate_sleep(number: Option<f64>, date_epoch_millis: Option<f64>) -> SleepDelay {
    if let Some(milliseconds) = number {
        if milliseconds.is_nan() {
            // Bun's `NaN` handling is its `NaN`-to-zero conversion, not an
            // error: `Bun.sleep(NaN)` resolves in about a millisecond.
            return SleepDelay::Milliseconds(0.0);
        }
        return SleepDelay::Milliseconds(milliseconds.max(0.0));
    }
    if let Some(epoch) = date_epoch_millis {
        if epoch.is_nan() {
            return SleepDelay::Milliseconds(0.0);
        }
        let now = crate::uuid::unix_millis() as f64;
        return SleepDelay::Milliseconds((epoch - now).max(0.0));
    }
    SleepDelay::Invalid
}

/// Reads `sleepSync`'s argument as whole milliseconds.
///
/// `NaN` is accepted and treated as zero; a negative value is rejected by name
/// and value; anything that is not a number at all is rejected with Node's
/// `ERR_INVALID_ARG_TYPE`.
pub fn validate_sleep_sync(number: Option<f64>) -> Result<u64, SleepSyncError> {
    let Some(milliseconds) = number else {
        return Err(SleepSyncError::NotANumber);
    };
    if milliseconds.is_nan() {
        return Ok(0);
    }
    if milliseconds < 0.0 {
        return Err(SleepSyncError::Negative(milliseconds));
    }
    Ok(milliseconds as u64)
}

/// The two `sleepSync` failures, each with its own message.
pub enum SleepSyncError {
    NotANumber,
    Negative(f64),
}

impl SleepSyncError {
    /// The message Bun throws, which carries `ERR_INVALID_ARG_TYPE` in both
    /// cases.
    pub fn message(&self) -> String {
        match self {
            Self::NotANumber => "milliseconds must be a number".to_string(),
            Self::Negative(value) => format!(
                "argument to sleepSync must not be negative, got {}",
                format_number(*value)
            ),
        }
    }
}

/// `String(number)` for the values these messages reach: `-5`, not `-5.0`.
fn format_number(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e21 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

/// The monotonic clock in nanoseconds, which is `uv_hrtime()`'s clock.
pub fn monotonic_nanos() -> u64 {
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

/// Blocks the current thread.
pub fn sleep_sync(milliseconds: u64) {
    if milliseconds > 0 {
        std::thread::sleep(std::time::Duration::from_millis(milliseconds));
    }
}
