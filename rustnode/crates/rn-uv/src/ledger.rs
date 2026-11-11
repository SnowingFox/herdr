//! Counting libuv handles so a teardown can be *proved*, not assumed.
//!
//! A worker thread creates its own loop and its own handles, and a handle that
//! outlives the loop it belongs to is the failure this project has already paid
//! for twice: a failed `uv_spawn` left a handle open, `uv_loop_close` returned
//! `UV_EBUSY`, the loop was freed anyway, and libuv's process-global signal tree
//! kept a dangling watcher that segfaulted roughly one run in three.
//!
//! So every long-lived handle this runtime creates is counted where it is created
//! and counted again when its close callback runs. A teardown then has two
//! assertions available to it, and both are cheap:
//!
//! * `outstanding() == 0` — nothing was left open, which is what makes
//!   `uv_loop_close` succeed instead of reporting `UV_EBUSY`;
//! * `closed() == created()` — every close callback ran exactly once, so no
//!   handle was closed twice (the `!uv__is_closing(handle)` abort) and none was
//!   silently skipped.
//!
//! # Why per thread *and* process-wide
//!
//! A worker's teardown has to answer "did **this** worker leak", and a
//! process-wide counter cannot: the main thread's loop and its keepalive are
//! created once and legitimately outlive every worker, so a global difference
//! would show five outstanding handles after a perfectly clean worker exit. The
//! per-thread counters answer the question the teardown is actually asking; the
//! process-wide totals are what a create/terminate loop reads to see a *trend*
//! across many threads.
//!
//! # What this does not do
//!
//! It does not intercept libuv. A handle is counted because the code that
//! initialises it calls [`record_created`] and the callback it registers for
//! `uv_close` calls [`record_closed`]. That is a deliberate limitation: the only
//! alternative is wrapping every `uv_close` call site, a much larger change for
//! the same evidence. The consequence is that a handle created by code that does
//! not call [`record_created`] is invisible here — so the rule for new handles is
//! that creating one means counting it.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

/// Handles created, across every thread in the process.
static CREATED: AtomicU64 = AtomicU64::new(0);
/// Handles whose close callback has run, across every thread.
static CLOSED: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Handles created on this thread.
    static LOCAL_CREATED: Cell<u64> = const { Cell::new(0) };
    /// Handles closed on this thread.
    static LOCAL_CLOSED: Cell<u64> = const { Cell::new(0) };
}

/// Records that a long-lived handle was initialised successfully.
///
/// Call this immediately after `uv_*_init` returns `0`, never before: a failed
/// initialisation leaves nothing to close, and counting it would make the ledger
/// report a leak that cannot exist.
pub fn record_created() {
    CREATED.fetch_add(1, Ordering::SeqCst);
    LOCAL_CREATED.with(|count| count.set(count.get().saturating_add(1)));
}

/// Records that a handle's close callback ran.
///
/// This is the first statement of the `uv_close` callback. It must be called from
/// the callback and nowhere else: recording it when `uv_close` is merely
/// *requested* would hide exactly the bug this ledger exists to catch, because
/// libuv runs the callback later and a loop freed in between is what dangles.
pub fn record_closed() {
    CLOSED.fetch_add(1, Ordering::SeqCst);
    LOCAL_CLOSED.with(|count| count.set(count.get().saturating_add(1)));
}

/// A point-in-time view of the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Handles created so far.
    pub created: u64,
    /// Handles whose close callback has run so far.
    pub closed: u64,
}

impl Snapshot {
    /// Handles created but not yet closed.
    #[must_use]
    pub fn outstanding(self) -> u64 {
        self.created.saturating_sub(self.closed)
    }

    /// Whether every handle created has had its close callback run.
    #[must_use]
    pub fn is_clean(self) -> bool {
        self.outstanding() == 0
    }
}

impl std::fmt::Display for Snapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "created={} closed={} outstanding={}",
            self.created,
            self.closed,
            self.outstanding()
        )
    }
}

/// Reads the process-wide totals.
#[must_use]
pub fn snapshot() -> Snapshot {
    Snapshot {
        created: CREATED.load(Ordering::SeqCst),
        closed: CLOSED.load(Ordering::SeqCst),
    }
}

/// Reads this thread's totals.
///
/// This is the view a teardown must use, because the main thread's handles are
/// expected to outlive it.
#[must_use]
pub fn thread_snapshot() -> Snapshot {
    Snapshot {
        created: LOCAL_CREATED.with(Cell::get),
        closed: LOCAL_CLOSED.with(Cell::get),
    }
}

/// Resets the process-wide totals, for a test that wants to count one scenario.
///
/// The per-thread counters are left alone: they belong to the thread that created
/// the handles, and clearing them from another thread would make a teardown
/// report a leak it did not have.
pub fn reset() {
    CREATED.store(0, Ordering::SeqCst);
    CLOSED.store(0, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both cases below call `reset()` and then assert absolute counts on
    /// process-wide atomics, so they cannot run concurrently with each other or
    /// with `threadpool`'s registry tests. See [`crate::GLOBAL_STATE`].
    #[test]
    fn the_ledger_counts_creation_and_close_separately() {
        let _serialised = crate::global_state_guard();
        reset();
        assert!(snapshot().is_clean(), "an empty ledger is clean");
        let starting = thread_snapshot();

        record_created();
        record_created();
        let after = thread_snapshot();
        assert_eq!(after.created, starting.created + 2);
        assert_eq!(after.closed, starting.closed);
        assert!(!after.is_clean(), "two open handles are not clean");

        record_closed();
        assert_eq!(
            thread_snapshot().outstanding(),
            after.outstanding() - 1,
            "one is still open"
        );

        record_closed();
        let finished = thread_snapshot();
        assert_eq!(
            finished.created, after.created,
            "closing does not change how many were created"
        );
        assert_eq!(
            finished.closed,
            after.closed + 2,
            "both closes were counted"
        );
        assert_eq!(finished.outstanding(), 0, "nothing is left open");
        assert!(finished.is_clean());
    }

    #[test]
    fn the_process_totals_move_with_the_thread_totals() {
        let _serialised = crate::global_state_guard();
        reset();
        record_created();
        let process = snapshot();
        assert_eq!(process.created, 1);
        assert_eq!(process.closed, 0);
        record_closed();
        assert!(snapshot().is_clean());
        assert_eq!(snapshot().created, snapshot().closed);
    }
}
