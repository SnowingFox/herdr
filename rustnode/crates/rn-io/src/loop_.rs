//! The event loop: phases, the poller under them, and when the loop stops.
//!
//! Node's order is libuv's `uv_run` order, with a microtask drain after each
//! phase because V8's microtask queue is drained by the embedder:
//!
//! 1. **timers** — every timer whose deadline has passed.
//! 2. **pending callbacks** — deferred I/O callbacks from the previous turn.
//! 3. **poll** — wait for readiness, up to the next timer deadline.
//! 4. **check** — `setImmediate` callbacks.
//! 5. **close callbacks** — handles being torn down.
//!
//! `lib/internal/process/task_queues.js` documents the drain points: ticks and
//! microtasks run between every pair of those, which is why `setTimeout(f, 0)`
//! reports after a `queueMicrotask()` scheduled in the script body and before
//! the process exits.
//!
//! # When the loop stops
//!
//! libuv's rule is `uv__loop_alive()`: a turn runs while a *ref'd* handle is
//! active, and only ref'd work lets the poll phase block. An `unref()`'d handle
//! is therefore work the loop will run if it is already due, but never work it
//! waits for. Measured against a real `node`, `setTimeout(f, 1).unref()` on its
//! own exits in 0.1ms without calling `f`.
//!
//! The one allowance is a final turn for a deadline that has already passed by
//! the end of a turn: libuv runs due timers before deciding the loop is dead, so
//! an unref'd timer that became due during a turn kept alive by something else
//! still fires.
//!
//! # Why this is not libuv FFI
//!
//! `Backend::Libuv` names the ordering contract, not a link against libuv. Two
//! facts decided it:
//!
//! * The workspace links no C library: `rn-bind-uv` reproduces libuv's error
//!   strings from a table for the same reason, and libuv would have to be built
//!   and shipped per platform alongside the binary.
//! * The phases are not libuv's hard part. What Node's tests assert is that a
//!   timer due at 41 ms runs after one due at 40 ms, that an immediate runs
//!   before a timer created in the same turn, and that `unref()` decides exit.
//!   Those are the ordering rules below, and they are testable without a
//!   syscall.
//!
//! The poller under them is `poll(2)`, the same readiness primitive `epoll`
//! wraps for the handle counts a single-threaded runtime has, reached through
//! `libc` so no new dependency appears. `Backend::IoUring` stays unimplemented
//! and [`Loop::new`] rejects it instead of pretending.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use crate::backend::{Backend, LoopHandle, WakeupState};
use crate::poll::Poller;

/// One of the loop's phases, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Timers,
    Pending,
    Poll,
    Check,
    Close,
}

impl Phase {
    /// The phases in the order one loop turn runs them.
    pub const ORDER: [Phase; 5] = [
        Phase::Timers,
        Phase::Pending,
        Phase::Poll,
        Phase::Check,
        Phase::Close,
    ];
}

/// What the loop needs from the runtime it is driving.
///
/// The loop knows nothing about V8 or timers; it asks these questions and runs
/// them. That keeps the ordering testable without an isolate, which is what lets
/// a unit test pin the phase order while the behaviour those phases exist for is
/// checked against a real `node` binary by the CLI's integration tests.
pub trait Scheduler {
    /// Runs every timer whose deadline has passed at `now_ms`, and records what
    /// is pending for [`next_deadline`](Self::next_deadline).
    fn run_timers(&mut self, now_ms: f64);

    /// Runs the deferred I/O callbacks queued for the previous turn.
    fn run_pending(&mut self);

    /// Waits for readiness on `poller`, at most `timeout`.
    ///
    /// `Some(Duration::ZERO)` means "check and return", which the loop asks for
    /// whenever a callback is already runnable or nothing is ref'd: blocking
    /// there would delay work that does not depend on I/O, or wait for a timer
    /// the process is not being kept alive for.
    fn poll(&mut self, poller: &mut Poller, timeout: Option<Duration>);

    /// Runs every queued `setImmediate` callback.
    fn run_immediates(&mut self);

    /// Runs close callbacks, the last JavaScript in a turn.
    fn run_close(&mut self);

    /// Drains ticks and V8 microtasks.
    ///
    /// Called between phases, never inside one, matching
    /// `lib/internal/process/task_queues.js`'s `runNextTicks()`.
    fn drain(&mut self);

    /// The next timer deadline, as the last timer phase reported it.
    fn next_deadline(&self) -> Option<f64>;

    /// Whether a ref'd timer, ref'd immediate or pending tick is outstanding.
    ///
    /// This decides whether the loop runs another turn: only ref'd work keeps
    /// the process alive.
    fn has_refed_work(&self) -> bool;

    /// Whether a callback is queued for the check phase.
    ///
    /// The poll phase must not block while one is: the check phase runs the
    /// moment poll returns, and the immediate is already runnable.
    fn has_pending_immediates(&self) -> bool;

    /// Whether a timer deadline that keeps the process alive is armed.
    ///
    /// Distinct from [`has_refed_work`](Self::has_refed_work) because a ref'd
    /// immediate keeps the loop turning but must not make poll wait: an
    /// `unref()`'d timer next to a ref'd `setImmediate` exits without firing in
    /// Node, so a pending immediate must not lend its ref to the deadline.
    fn has_refed_deadline(&self) -> bool;

    /// Whether the process has asked to exit, e.g. an uncaught exception or
    /// `process.exit()`.
    fn exit_requested(&self) -> bool;

    /// The loop's monotonic millisecond clock.
    fn now_ms(&self) -> f64;
}

/// A loop over a [`Scheduler`].
#[derive(Debug)]
pub struct Loop {
    backend: Backend,
    handle: LoopHandle,
    poller: Poller,
}

impl Loop {
    /// Builds a loop for `backend`, or explains why that backend cannot run.
    pub fn new(backend: Backend) -> Result<Self, String> {
        match backend {
            Backend::Libuv => {}
            Backend::IoUring => {
                return Err(
                    "the io_uring backend is not implemented; use the default libuv ordering"
                        .to_string(),
                )
            }
        }
        let poller = Poller::new()?;
        let wakeups = Rc::new(RefCell::new(WakeupState::default()));
        let handle = LoopHandle::new(backend, wakeups);
        Ok(Self {
            backend,
            handle,
            poller,
        })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// A handle other code can use to arm this loop.
    pub fn handle(&self) -> LoopHandle {
        self.handle.clone()
    }

    /// Runs one turn of the loop.
    ///
    /// Returns whether another turn is warranted. `false` means nothing is left
    /// to run, so the caller may exit.
    pub fn tick<S: Scheduler>(&mut self, scheduler: &mut S) -> bool {
        for phase in Phase::ORDER {
            if scheduler.exit_requested() {
                return false;
            }
            match phase {
                Phase::Timers => {
                    let now = scheduler.now_ms();
                    // Drop the arm this turn is about to honour before running
                    // timers, so the deadline the phase reports is the only one
                    // left and a superseded arm cannot resurface.
                    let _ = self.handle.clear_due(now);
                    scheduler.run_timers(now);
                    // The timer phase is the only thing that knows what to wait
                    // for, so the deadline is re-armed from what it reported
                    // rather than from whatever was armed before it ran.
                    match scheduler.next_deadline() {
                        Some(at) => self.handle.wake_at(at),
                        None => self.handle.cancel_wakeup(),
                    }
                }
                Phase::Pending => scheduler.run_pending(),
                Phase::Poll => {
                    let timeout = self.poll_timeout(scheduler);
                    scheduler.poll(&mut self.poller, timeout);
                }
                Phase::Check => scheduler.run_immediates(),
                Phase::Close => scheduler.run_close(),
            }
            scheduler.drain();
        }

        if scheduler.exit_requested() {
            return false;
        }
        if scheduler.has_refed_work() {
            return true;
        }
        // Nothing ref'd is left, but a deadline that has already arrived gets a
        // final turn: `setTimeout(f, 4).unref()` next to a `setImmediate(g)`
        // fires `f` in Node, because the deadline passed while `g` kept the loop
        // turning, and libuv runs due timers before deciding the loop is dead.
        // A deadline still in the future gets nothing, which is what makes the
        // same test with a 5ms timer print only `g`.
        scheduler
            .next_deadline()
            .is_some_and(|deadline| deadline <= scheduler.now_ms())
    }

    /// Runs turns until nothing is left, up to `turn_limit`.
    ///
    /// The limit guards against a scheduler that never settles. The runtime
    /// passes [`u32::MAX`] because a real program is allowed to run forever;
    /// tests use a small number so a bug fails instead of hanging.
    pub fn run<S: Scheduler>(&mut self, scheduler: &mut S, turn_limit: u32) -> StopReason {
        // libuv checks `uv__loop_alive()` before the first iteration and does
        // not run a turn at all when nothing is ref'd. That first check is
        // load-bearing: without it the loop would run one turn for an
        // `unref()`'d timer, and a turn is long enough for a 1ms deadline to
        // arrive, so the timer would fire when Node never calls it.
        if scheduler.exit_requested() {
            return StopReason::ExitRequested;
        }
        if !scheduler.has_refed_work() {
            return StopReason::Idle;
        }
        for _ in 0..turn_limit {
            if !self.tick(scheduler) {
                return if scheduler.exit_requested() {
                    StopReason::ExitRequested
                } else {
                    StopReason::Idle
                };
            }
        }
        StopReason::TurnLimit
    }

    /// How long the poll phase may block.
    fn poll_timeout<S: Scheduler>(&self, scheduler: &S) -> Option<Duration> {
        // Nothing to wait for when a callback is already runnable. The check
        // phase runs straight after poll, so blocking here would delay an
        // immediate that does not depend on I/O at all.
        if scheduler.has_pending_immediates() {
            return Some(Duration::ZERO);
        }
        // `None` is "wait until a descriptor is ready". With no deadline armed
        // and no descriptor registered, that wait could only end at process
        // death, so every path that cannot name a duration returns zero.
        if !scheduler.has_refed_deadline() {
            return Some(Duration::ZERO);
        }
        let Some(deadline) = scheduler.next_deadline() else {
            return Some(Duration::ZERO);
        };
        let delay = (deadline - scheduler.now_ms()).max(0.0);
        // libuv rounds the timeout up so a 1ms timer cannot return early and
        // then have to spin for the fractional remainder.
        Some(Duration::from_millis(delay.ceil() as u64))
    }
}

/// Why [`Loop::run`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Nothing is left to run: the process may exit.
    Idle,
    /// The scheduler asked to exit, e.g. an uncaught exception.
    ExitRequested,
    /// The turn limit was reached before the loop settled.
    TurnLimit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A scheduler that records the order its phases ran in.
    #[derive(Default)]
    struct Recorder {
        log: Vec<&'static str>,
        /// What each `run_timers` call reports as the next deadline.
        deadlines: VecDeque<Option<f64>>,
        next: Option<f64>,
        now: f64,
        refed: bool,
        immediates: bool,
        exit: bool,
    }

    impl Scheduler for Recorder {
        fn run_timers(&mut self, _now_ms: f64) {
            self.log.push("timers");
            self.next = self.deadlines.pop_front().flatten();
        }
        fn run_pending(&mut self) {
            self.log.push("pending");
        }
        fn poll(&mut self, _poller: &mut Poller, timeout: Option<Duration>) {
            self.log.push("poll");
            let _ = timeout;
        }
        fn run_immediates(&mut self) {
            self.log.push("check");
        }
        fn run_close(&mut self) {
            self.log.push("close");
        }
        fn drain(&mut self) {
            self.log.push("drain");
        }
        fn next_deadline(&self) -> Option<f64> {
            self.next
        }
        fn has_refed_work(&self) -> bool {
            self.refed
        }
        fn has_pending_immediates(&self) -> bool {
            self.immediates
        }
        fn has_refed_deadline(&self) -> bool {
            self.refed
        }
        fn exit_requested(&self) -> bool {
            self.exit
        }
        fn now_ms(&self) -> f64 {
            self.now
        }
    }

    #[test]
    fn one_turn_runs_the_phases_in_node_order_with_a_drain_between_each() {
        let mut scheduler = Recorder::default();
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        let _ = event_loop.tick(&mut scheduler);
        assert_eq!(
            scheduler.log,
            [
                "timers", "drain", "pending", "drain", "poll", "drain", "check", "drain", "close",
                "drain"
            ]
        );
    }

    #[test]
    fn the_io_uring_backend_is_rejected_rather_than_silently_emulated() {
        let Err(error) = Loop::new(Backend::IoUring) else {
            panic!("io_uring must be rejected");
        };
        assert!(error.contains("io_uring"));
    }

    #[test]
    fn a_turn_with_nothing_refed_stops_the_loop() {
        let mut scheduler = Recorder::default();
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(
            event_loop.run(&mut scheduler, 10),
            StopReason::Idle,
            "a scheduler with nothing outstanding must not spin"
        );
        assert!(
            scheduler.log.is_empty(),
            "libuv runs no turn at all when nothing is ref'd"
        );
    }

    #[test]
    fn refed_work_keeps_the_loop_running_until_it_is_gone() {
        let mut scheduler = Recorder {
            refed: true,
            ..Recorder::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert!(event_loop.tick(&mut scheduler));
        scheduler.refed = false;
        assert_eq!(event_loop.run(&mut scheduler, 10), StopReason::Idle);
    }

    #[test]
    fn an_exit_request_stops_before_the_next_phase() {
        let mut scheduler = Recorder {
            exit: true,
            ..Recorder::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert!(!event_loop.tick(&mut scheduler));
        assert_eq!(
            event_loop.run(&mut scheduler, 10),
            StopReason::ExitRequested,
            "`run` reports the exit request even when it stops before a turn"
        );
        assert!(
            scheduler.log.is_empty(),
            "no phase runs after an exit request"
        );
    }

    #[test]
    fn the_turn_limit_bounds_a_scheduler_that_never_settles() {
        let mut scheduler = Recorder {
            refed: true,
            ..Recorder::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(event_loop.run(&mut scheduler, 3), StopReason::TurnLimit);
    }

    #[test]
    fn a_timer_deadline_becomes_the_poll_timeout() {
        let mut scheduler = Recorder {
            now: 1000.0,
            refed: true,
            ..Recorder::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        scheduler.deadlines.push_back(Some(1042.0));
        let _ = event_loop.tick(&mut scheduler);
        assert_eq!(
            event_loop.poll_timeout(&scheduler),
            Some(Duration::from_millis(42)),
            "the poll must wait until the next deadline, not longer"
        );
    }

    #[test]
    fn a_fractional_deadline_rounds_up_so_polling_cannot_spin() {
        let mut scheduler = Recorder {
            now: 10.25,
            refed: true,
            ..Recorder::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        scheduler.deadlines.push_back(Some(10.5));
        let _ = event_loop.tick(&mut scheduler);
        assert_eq!(
            event_loop.poll_timeout(&scheduler),
            Some(Duration::from_millis(1))
        );
    }

    #[test]
    fn a_turn_without_a_deadline_does_not_block() {
        let scheduler = Recorder {
            now: 5.0,
            refed: true,
            ..Recorder::default()
        };
        let event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(event_loop.poll_timeout(&scheduler), Some(Duration::ZERO));
    }

    #[test]
    fn an_unrefed_timer_never_lets_the_poll_block() {
        // `setTimeout(f, 1).unref()` makes the loop run one more turn but must
        // not make it sit waiting for the deadline.
        let mut scheduler = Recorder {
            refed: false,
            ..Recorder::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        scheduler.deadlines.push_back(Some(5.0));
        let _ = event_loop.tick(&mut scheduler);
        assert_eq!(event_loop.poll_timeout(&scheduler), Some(Duration::ZERO));
    }

    #[test]
    fn an_unrefed_timer_that_is_not_due_stops_the_loop() {
        // Measured from `node`: `setTimeout(f, 1).unref()` on its own exits in
        // 0.1ms without calling `f`, so a deadline in the future is not work.
        let mut scheduler = Recorder {
            now: 0.0,
            ..Recorder::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        scheduler.deadlines.push_back(Some(50.0));
        assert!(!event_loop.tick(&mut scheduler));
        assert_eq!(
            scheduler
                .log
                .iter()
                .filter(|line| **line == "timers")
                .count(),
            1,
            "the turn ran, and then the loop stopped rather than waiting"
        );
    }

    #[test]
    fn an_unrefed_timer_never_starts_a_run_even_when_it_is_due() {
        // Measured from `node`: `setTimeout(f, 1).unref()` on its own exits in
        // 0.1ms without calling `f`, even though a millisecond may already have
        // passed by the time the loop starts. The entry check is what guarantees
        // that, because a turn is long enough for a short deadline to arrive.
        let mut scheduler = Recorder {
            now: 10.0,
            ..Recorder::default()
        };
        scheduler.deadlines.push_back(Some(10.0));
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(event_loop.run(&mut scheduler, 10), StopReason::Idle);
        assert!(scheduler.log.is_empty(), "no turn ran for unref'd work");
    }

    #[test]
    fn a_deadline_that_arrived_during_a_live_turn_gets_a_final_one() {
        // Measured from `node`: `setTimeout(f, 4).unref()` next to a
        // `setImmediate(g)` fires `f`, because the deadline passed while `g`
        // kept the loop turning. The reverse — a 5ms deadline — does not fire,
        // and that is the `is_some_and` comparison below.
        let mut scheduler = Recorder {
            now: 10.0,
            ..Recorder::default()
        };
        scheduler.deadlines.push_back(Some(10.0));
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert!(event_loop.tick(&mut scheduler), "a due deadline runs again");
        scheduler.deadlines.push_back(None);
        assert!(!event_loop.tick(&mut scheduler), "and then the loop stops");
    }

    #[test]
    fn a_deadline_still_in_the_future_gets_no_final_turn() {
        // The 5ms case: an active deadline that is not due and not ref'd is
        // where the loop stops, which is what keeps an `unref()`'d interval from
        // pinning the process.
        let mut scheduler = Recorder {
            now: 0.0,
            refed: true,
            ..Recorder::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        scheduler.deadlines.push_back(Some(50.0));
        assert!(event_loop.tick(&mut scheduler), "refed work keeps turning");
        // The work went away and left only a deadline half a turn in the future.
        scheduler.refed = false;
        assert!(!event_loop.tick(&mut scheduler));
    }

    #[test]
    fn a_pending_tick_keeps_the_loop_alive_without_a_timer() {
        // `process.nextTick` on its own is ref'd work: Node runs the tick and
        // then exits, and the loop must not stop before the tick runs.
        let mut scheduler = Recorder {
            refed: true,
            ..Recorder::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert!(event_loop.tick(&mut scheduler));
        scheduler.refed = false;
        assert_eq!(event_loop.run(&mut scheduler, 10), StopReason::Idle);
    }
}
