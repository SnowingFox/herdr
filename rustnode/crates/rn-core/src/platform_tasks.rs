//! Draining the tasks V8 posts to its platform, not to JavaScript.
//!
//! V8's embedder API posts work to the foreground task runner of the platform
//! rather than to a JavaScript queue. `MemoryMeasurement::ScheduleGCTask` is the
//! one that made this necessary: `v8::Isolate::MeasureMemory` resolves its promise
//! from a task posted there, so `vm.measureMemory()` is unobservable until that
//! queue is flushed. GC work driven by `--max-old-space-size` uses the same
//! runner, which is why the flush belongs in the loop rather than next to
//! `measureMemory`.
//!
//! rustnode ran no such flush, and the symptom was a promise that never settled:
//! `vm.measureMemory({ execution: 'eager' })` posted its GC task, the loop found
//! no libuv handle to wait on, and the process exited with the promise still
//! pending. Node flushes the same runner from the check phase of every iteration
//! (`PerIsolatePlatformData::FlushForegroundTasksInternal`), and
//! [`pump_foreground_tasks`] is that flush.
//!
//! # Why the flag exists
//!
//! A task sitting in that queue owns no libuv handle, so libuv's liveness answer
//! does not see it. [`note_possible_pending`] marks the iterations where a flush
//! might find something, and [`maybe_pending`] keeps the loop alive for them.
//!
//! The flag is not a gate on the flush, deliberately: V8 posts to this queue on
//! its own as well (GC finalizers under heap pressure), and skipping the flush
//! when nothing had been recorded from here made `test-vm-contextified-script-leak`
//! and `test-vm-synthetic-module-leak` fail where the unconditional flush passes.
//!
//! It is bounded rather than sticky for the opposite reason. `measureMemory()`
//! with the default execution is answered with a *delayed* task, and a process
//! with nothing else pending exits before that task is due. Node does the same —
//! `node -e 'require("vm").measureMemory()'` prints no result and exits — so the
//! flag must not hold the loop open waiting for it.

use std::cell::Cell;

use rn_v8_sys::v8;

thread_local! {
    /// Whether a producer has handed V8 work that completes on the platform.
    static MAYBE_PENDING: Cell<bool> = const { Cell::new(false) };
}

/// Records that V8 now has platform work which will complete this isolate.
///
/// Called by whatever posts such work. It is a hint, not a count: a flush that
/// runs a task clears it.
pub fn note_possible_pending() {
    MAYBE_PENDING.with(|slot| slot.set(true));
}

/// Whether the loop should run one more iteration in case a platform task is
/// waiting.
pub fn maybe_pending() -> bool {
    MAYBE_PENDING.with(|slot| slot.get())
}

/// Runs the tasks the platform has queued for this isolate.
///
/// Returns whether any task ran. The flush itself is unconditional — see the
/// module docs for the two leak tests that catch a gated version — so this is
/// called from every iteration's checkpoint, where it returns immediately when
/// the queue is empty.
pub fn pump_foreground_tasks(scope: &v8::PinScope<'_, '_>) -> bool {
    let ran_any = rn_v8_sys::pump_platform_tasks(scope);
    if !ran_any {
        // Nothing was waiting. Clearing here is what bounds the optimism to one
        // extra iteration: a delayed task (a default-execution
        // `measureMemory()`) must be abandoned, not awaited, exactly as Node
        // abandons it. A producer that posts again sets the flag again.
        MAYBE_PENDING.with(|slot| slot.set(false));
    }
    ran_any
}
