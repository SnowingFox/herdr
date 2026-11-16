//! The tick and microtask checkpoint Node runs after every callback.
//!
//! `src/api/callback.cc`'s `InternalCallbackScope::Close` runs at the end of
//! every native-to-JavaScript callback, and it is where Node keeps the guarantee
//! that `process.nextTick` and promise callbacks run before the loop advances a
//! phase:
//!
//! ```text
//! if (!tick_info->has_tick_scheduled()) PerformCheckpoint(isolate);
//! if (!has_tick_scheduled && !has_rejection_to_warn) return;
//! tick_callback->Call(...);
//! ```
//!
//! rustnode used to run that checkpoint only between whole loop iterations
//! (`rn_io::Loop::tick`), which is one iteration too late. A callback that
//! queued a tick had it run after the check phase, so a `setImmediate` beat a
//! `.then`, and a socket's `'close'` ran before the `process.nextTick` its own
//! `'connect'` handler had queued. Neither is a hang or a lost callback — both
//! queues do drain — so a program takes a different branch instead of failing.
//!
//! # Where the checkpoint is driven from
//!
//! From [`enter_callback`] / [`leave_callback`], which
//! `rn_uv::callback::with_context` brackets every callback with. That funnel is
//! the only place that re-enters V8 from libuv, so it is the same boundary
//! Node's `MakeCallback` is.
//!
//! # Why the seam exists
//!
//! The funnel cannot reach either fact the checkpoint needs: whether a tick is
//! queued lives in the shared `tickInfo` buffer the `task_queue` namespace owns,
//! and running the tick callback needs the runtime's `runNextTicks`. So this
//! module holds the interface and the two owners register their half, the same
//! way [`crate::callback_scope`] and [`crate::native_immediates`] are arranged.
//! Before either registration the checkpoint does nothing, which is the honest
//! state during bootstrap: there is no tick queue to drain yet.
//!
//! # Two rules that are not obvious
//!
//! * **Only the outermost callback drains.** `InternalCallbackScope::Close`
//!   returns early at `async_callback_scope_depth() > 1`, because the outer
//!   scope is about to drain anyway. Without the same rule a JavaScript call
//!   that re-entered a completion (a SQLite function, an inspector dispatch)
//!   would run the tick queue in the middle of a JavaScript stack, which is
//!   exactly what an explicit microtask policy exists to prevent.
//! * **A callback that threw does not drain.** `InternalMakeCallback` calls
//!   `MarkAsFailed()`, and `Close` then returns at `if (failed_) return;`, so an
//!   uncaught exception runs before any microtask the throwing callback queued.
//!   The failure is recorded by [`note_callback_failed`], which
//!   `rn_errors::report_uncaught_exception` calls — the single function every
//!   completion path's catch block already goes through. `RunTimers` is the one
//!   scope that is not an `InternalMakeCallback`, and it clears the flag again
//!   with [`forget_callback_failure`] because Node's timer handle does drain
//!   after a handled throw.

use std::cell::Cell;

use rn_v8_sys::v8;

/// How the checkpoint asks "is a tick or a rejection waiting?".
///
/// This is `TickInfo::has_tick_scheduled() || has_rejection_to_warn()` in
/// `src/api/callback.cc`, and it is a predicate rather than a value because the
/// answer is a byte in a shared buffer the JavaScript side writes.
pub type PendingCheck = fn() -> bool;

/// How the checkpoint runs `processTicksAndRejections`.
pub type TickDrain = fn(&mut v8::PinScope<'_, '_>);

/// The two registered halves of the checkpoint.
///
/// One slot rather than two so the hot path takes a single borrow: this runs on
/// every I/O completion in the process.
#[derive(Clone, Copy)]
struct Checkpoint {
    pending: PendingCheck,
    drain: TickDrain,
}

thread_local! {
    /// How many callback scopes are open on this thread.
    ///
    /// `Environment::async_callback_scope_depth()`. Only the transition from one
    /// to zero is a checkpoint.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    /// Whether the callback being run threw.
    ///
    /// `InternalCallbackScope::failed_`. Reset when the outermost scope opens,
    /// because the flag belongs to one callback and not to the thread.
    static FAILED: Cell<bool> = const { Cell::new(false) };
    /// Whether a checkpoint is already running on this thread.
    ///
    /// The drain calls JavaScript, and that JavaScript can complete a binding
    /// call that ends another callback scope. Re-entering the tick loop from
    /// inside itself would run `processTicksAndRejections` while it is on the
    /// stack.
    static IN_CHECKPOINT: Cell<bool> = const { Cell::new(false) };
    /// The registered halves of the checkpoint, once both have installed.
    static CHECKPOINT: Cell<Option<Checkpoint>> = const { Cell::new(None) };
    /// The predicate alone, for the half-installed window.
    static PENDING: Cell<Option<PendingCheck>> = const { Cell::new(None) };
    /// The drain alone, for the half-installed window.
    static DRAIN: Cell<Option<TickDrain>> = const { Cell::new(None) };
}

/// Runs the checkpoint regardless of the callback depth.
///
/// The depth test in [`leave_callback`] protects a JavaScript call that re-entered
/// a completion, but it also swallows a completion *nested in another native
/// callback*: a `TLSWrap` runs its whole state machine inside one scope, so an
/// HTTP/2 session that consumes a TLS socket receives and finishes while that
/// outer scope is still open, and nothing drains when the inner scope closes.
///
/// A caller that has to observe the queue draining — delivering a staged body
/// only after the tick `core.js` queued for `'response'`, for instance — therefore
/// asks for it explicitly instead of relying on a scope closing above it.
///
/// The failure and re-entrancy guards inside [`checkpoint`] still apply, so this
/// cannot nest a checkpoint inside itself.
pub fn checkpoint_now(scope: &mut v8::PinScope<'_, '_>, inside_loop: bool) {
    if inside_loop {
        checkpoint(scope);
    }
}

/// Publishes [`CHECKPOINT`] once both halves have registered.
fn publish() {
    let (Some(pending), Some(drain)) = (
        PENDING.with(|slot| slot.get()),
        DRAIN.with(|slot| slot.get()),
    ) else {
        return;
    };
    CHECKPOINT.with(|slot| slot.set(Some(Checkpoint { pending, drain })));
}

/// Withdraws [`CHECKPOINT`] when either half goes away.
fn withdraw() {
    if PENDING.with(|slot| slot.get()).is_none() || DRAIN.with(|slot| slot.get()).is_none() {
        CHECKPOINT.with(|slot| slot.set(None));
    }
}

/// Clears [`IN_CHECKPOINT`] when the checkpoint it guards ends, however it ends.
struct CheckpointGuard;

impl Drop for CheckpointGuard {
    fn drop(&mut self) {
        IN_CHECKPOINT.with(|flag| flag.set(false));
    }
}

/// Registers the predicate that says whether a checkpoint has work.
///
/// Called by the `task_queue` namespace at install, because the flags it reads
/// are that namespace's shared buffer.
pub fn set_pending_check(pending: PendingCheck) {
    PENDING.with(|slot| slot.set(Some(pending)));
    publish();
}

/// Registers the function that runs the tick callback.
///
/// Called by the realm runtime, which is the only crate that holds
/// `runNextTicks`: `internal/process/task_queues.js` creates it and Node's
/// `setTickCallback` gives `processTicksAndRejections` to the native side.
pub fn set_tick_drain(drain: TickDrain) {
    DRAIN.with(|slot| slot.set(Some(drain)));
    publish();
}

/// Removes both halves, so a new realm on this thread cannot inherit the
/// previous one's.
pub fn clear() {
    PENDING.with(|slot| slot.set(None));
    DRAIN.with(|slot| slot.set(None));
    CHECKPOINT.with(|slot| slot.set(None));
    withdraw();
}

/// Records that the callback now running threw.
///
/// Only the outermost call matters: `Close` reads one flag for the callback that
/// is unwinding, and a nested scope's failure is the outer one's failure too.
pub fn note_callback_failed() {
    FAILED.with(|flag| flag.set(true));
}

/// Clears the failure recorded for the callback now running.
///
/// `RunTimers` opens a plain `InternalCallbackScope`, not an
/// `InternalMakeCallback`, and `Close` on such a scope performs the checkpoint
/// whether or not `processTimers` threw — the throw was already handed to
/// `_fatalException` by the handle's own `TryCatchScope`. Clearing the flag is
/// how the timer path keeps that difference; see
/// `rn_bind_timers::run_timer_callback`.
pub fn forget_callback_failure() {
    FAILED.with(|flag| flag.set(false));
}

/// Marks the start of one native-to-JavaScript callback.
pub fn enter_callback() {
    let depth = DEPTH.with(|depth| {
        let next = depth.get().saturating_add(1);
        depth.set(next);
        next
    });
    if depth == 1 {
        // A fresh outermost scope: the previous callback's verdict does not
        // apply to this one.
        FAILED.with(|flag| flag.set(false));
    }
}

/// Marks the end of one native-to-JavaScript callback.
///
/// `inside_loop` is `true` only while libuv's `uv_run` is on the stack. A
/// callback scope opened outside it — a binding function that JavaScript called,
/// which then completes something synchronously — must not drain: there is a
/// JavaScript frame above it, and the checkpoint only belongs at the boundary
/// where control returns to the loop.
///
/// The depth is decremented *after* the checkpoint, not before, so a callback
/// that re-enters another completion while the drain runs still sees a depth
/// above zero and leaves the draining to this scope.
pub fn leave_callback(scope: &mut v8::PinScope<'_, '_>, inside_loop: bool) {
    let depth = DEPTH.with(|depth| depth.get());
    if depth <= 1 && inside_loop {
        checkpoint(scope);
    }
    DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
}

/// Whether a checkpoint is running on this thread.
#[must_use]
pub fn in_checkpoint() -> bool {
    IN_CHECKPOINT.with(|flag| flag.get())
}

/// How many callback scopes are open. Exposed so a test can pin the boundary.
#[must_use]
pub fn callback_depth() -> u32 {
    DEPTH.with(|depth| depth.get())
}

/// Runs Node's checkpoint once, if there is anything to run.
///
/// The order is `InternalCallbackScope::Close`'s: microtasks first when no tick
/// is queued, then the tick callback if a microtask — or the callback itself —
/// queued one.
fn checkpoint(scope: &mut v8::PinScope<'_, '_>) {
    // One borrow for both halves: this runs on every I/O completion.
    let Some(Checkpoint { pending, drain }) = CHECKPOINT.with(|slot| slot.get()) else {
        // The runtime or the task queue has not installed yet, so there is no
        // tick queue to drain.
        return;
    };
    // `InternalCallbackScope::Close`'s first test, and the one a throwing
    // callback hits.
    if FAILED.with(|flag| flag.get()) {
        // `Close` returns at `if (failed_) return;` before it reaches the
        // checkpoint. The catch block has already reported the throw through
        // `process._fatalException`.
        return;
    }
    // `if (!env_->can_call_into_js()) return;`, checked before anything runs.
    // A `process.exit()` or a fatal exception has stopped the environment.
    if rn_core_exit_requested() {
        return;
    }
    if IN_CHECKPOINT.with(|flag| flag.replace(true)) {
        return;
    }
    let _guard = CheckpointGuard;

    if !pending() {
        // Nothing is queued in `tickInfo`, which is the common case for a
        // completion that only resumes a state machine. The microtask queue is
        // still taken: a `.then` the callback queued is invisible to `pending()`.
        scope.perform_microtask_checkpoint();
    }
    // The checkpoint above can queue a tick of its own — a `.then` that calls
    // `process.nextTick` is the ordinary case — which is why this is re-read
    // rather than tested once.
    if pending() {
        drain(scope);
    }
}

/// Whether the environment has been asked to stop.
///
/// This is `Environment::can_call_into_js()` read the way this runtime exposes
/// it: `process.reallyExit` and the fatal-exception path both raise the shared
/// flag from the callback that asked for them.
fn rn_core_exit_requested() -> bool {
    crate::hook_slot::flag(crate::hook_slot::EXIT_REQUESTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The depth, the failure flag and the re-entrancy flag are all per
    /// callback, so a test has to reset them before it can trust a reading.
    fn reset() {
        DEPTH.with(|depth| depth.set(0));
        FAILED.with(|flag| flag.set(false));
        IN_CHECKPOINT.with(|flag| flag.set(false));
    }

    #[test]
    fn the_failure_flag_belongs_to_the_outermost_callback() {
        reset();
        enter_callback();
        note_callback_failed();
        assert!(FAILED.with(|flag| flag.get()));
        // A nested scope opening must not clear the verdict of the callback it
        // is nested in.
        enter_callback();
        assert!(FAILED.with(|flag| flag.get()));
        DEPTH.with(|depth| depth.set(0));
        // The next outermost callback starts clean.
        enter_callback();
        assert!(!FAILED.with(|flag| flag.get()));
        reset();
    }

    #[test]
    fn a_depth_that_was_never_opened_does_not_underflow() {
        // `leave_callback` runs once per `with_context`, and a caller that
        // returned before entering is the reason this saturates rather than
        // wrapping to `u32::MAX` — which would look like a deep nesting and
        // silently disable every later checkpoint.
        reset();
        let depth = DEPTH.with(|depth| depth.get());
        assert_eq!(depth, 0);
        // No scope is open, so this must leave it at zero.
        DEPTH.with(|d| d.set(depth.saturating_sub(1)));
        assert_eq!(callback_depth(), 0);
        reset();
    }

    #[test]
    fn the_checkpoint_is_withdrawn_until_both_halves_register() {
        // `rn-uv` installs before `realm.js` runs, so there is a window where the
        // drain exists and the predicate does not. Publishing early would make
        // the checkpoint call a missing half on every completion.
        reset();
        clear();
        assert!(CHECKPOINT.with(|slot| slot.get()).is_none());

        let pending: PendingCheck = || false;
        set_pending_check(pending);
        assert!(
            CHECKPOINT.with(|slot| slot.get()).is_none(),
            "one half is not a checkpoint"
        );

        let drain: TickDrain = |_| {};
        set_tick_drain(drain);
        let published = CHECKPOINT
            .with(|slot| slot.get())
            .expect("both halves publish");
        assert!(!(published.pending)(), "the registered predicate is used");

        clear();
        assert!(
            CHECKPOINT.with(|slot| slot.get()).is_none(),
            "a new realm must not inherit the previous one's checkpoint"
        );
        reset();
    }
}
