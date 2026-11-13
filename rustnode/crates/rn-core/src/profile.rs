//! Opt-in startup phase timing.
//!
//! `docs/startup.md`'s breakdown came from timers that lived in the CLI under
//! `RN_PROFILE_PHASES`. They were lost when `rn-cli` was refactored into
//! `rn-realm`, which left startup cost with no instrument at all: a regression
//! could be attributed to a commit by bisecting medians, but not to a *phase*,
//! and the two candidate mechanisms that were checked by hand both turned out
//! to be wrong.
//!
//! This is that instrument, rebuilt where both the CLI and the realm bootstrap
//! can reach it.
//!
//! # It is off unless asked for
//!
//! Reading the variable costs one `std::env::var` at first use, which is cached
//! in a `OnceLock`. When it is unset, [`mark`] is a load of a bool and a
//! return: no clock read, no allocation, nothing to show up in a profile of the
//! thing being profiled. That matters because the whole point is measuring
//! startup, and an instrument that perturbs its own subject is worse than none.
//!
//! # Why the output is on stderr and not `tracing`
//!
//! The report has to survive a process that exits through `std::process::exit`
//! on a user error, which skips tracing's shutdown, and it must not interleave
//! with a `console.log` the user asked for on stdout. One `write_all` to
//! stderr at the end is the smallest thing that satisfies both.
//!
//! # Reading the report
//!
//! Each line is `name  cumulative  delta`, in milliseconds, where cumulative is
//! measured from process entry and delta is the gap since the previous mark.
//! Cumulative is the column to read for "how much of startup is this"; delta is
//! the column to read for "what did this phase cost". A phase that is itself
//! the last mark in a nested sequence shows a delta of 0 and only its
//! cumulative is meaningful — the marks are a linear sequence, not a tree.

use std::sync::OnceLock;
use std::time::Instant;

/// Process entry, so every cumulative figure is measured from the same origin.
///
/// `std::time::Instant` is monotonic, and a `LazyLock` would delay the origin to
/// the first `mark`, which would make `entry` report 0 by construction and hide
/// the cost before it.
static ORIGIN: OnceLock<Instant> = OnceLock::new();

/// Whether `RN_PROFILE_PHASES` was set when the process started.
///
/// Cached: `std::env::var` takes a lock and allocates, and a per-phase read
/// would put that cost inside the phases being measured.
static ENABLED: OnceLock<bool> = OnceLock::new();

/// The marks recorded so far, in order.
static MARKS: OnceLock<std::sync::Mutex<Vec<(&'static str, f64)>>> = OnceLock::new();

/// Whether phase timing is on.
#[must_use]
pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var_os("RN_PROFILE_PHASES").is_some())
}

/// Records the moment the process started.
///
/// Call this as early as `main` can, so `entry` in the report is the cost of
/// getting to `main` rather than a constant zero. A second call is ignored.
pub fn start() {
    if !enabled() {
        return;
    }
    let _ = ORIGIN.set(Instant::now());
}

/// Records a phase boundary called `name`.
///
/// Does nothing when [`enabled`] is false, which is the default.
pub fn mark(name: &'static str) {
    if !enabled() {
        return;
    }
    let origin = *ORIGIN.get_or_init(Instant::now);
    let elapsed = origin.elapsed().as_secs_f64() * 1000.0;
    MARKS
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((name, elapsed));
}

/// Writes the report to stderr.
///
/// Idempotent, and safe to call from an exit path: it takes nothing but the
/// recorded numbers, so a partially initialised runtime still reports what it
/// reached. Does nothing when [`enabled`] is false.
pub fn report() {
    if !enabled() {
        return;
    }
    let Some(marks) = MARKS.get() else {
        return;
    };
    let Ok(marks) = marks.lock() else {
        return;
    };
    if marks.is_empty() {
        return;
    }
    use std::io::Write;
    let mut text = String::from("\nstartup phases (RN_PROFILE_PHASES)\n");
    text.push_str("  phase                                    cumulative     delta\n");
    let mut previous = 0.0_f64;
    for (name, cumulative) in marks.iter() {
        text.push_str(&format!(
            "  {name:<40} {cumulative:>10.2} ms {:>8.2} ms\n",
            cumulative - previous
        ));
        previous = *cumulative;
    }
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(text.as_bytes());
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marking_is_a_no_op_when_the_variable_is_unset() {
        // The suite does not set `RN_PROFILE_PHASES`, so this is the default path
        // every real run takes. The guard is skipped rather than asserted when it
        // *is* set: a developer running with it on must not see a false failure.
        if enabled() {
            return;
        }
        start();
        mark("ignored");
        assert!(
            MARKS
                .get()
                .is_none_or(|marks| marks.lock().map(|marks| marks.is_empty()).unwrap_or(true)),
            "a disabled mark must record nothing"
        );
        report();
    }
}
