//! Keeping the parent's loop and the JS layer in step with its workers.
//!
//! `lib/internal/worker.js` is written against a native handle that reports two
//! things: whether it keeps the loop alive, and when the thread has stopped. Node
//! gets both from libuv — the handle is ref'd through `env->add_refs(1)` and the
//! exit arrives through `SetImmediateThreadsafe`. rustnode has neither, so this
//! module supplies the same two answers from a registry the parent thread owns.
//!
//! # Why a registry and not a libuv handle
//!
//! The worker's thread has its own libuv loop, and no handle on it can be waited
//! on by the parent's `uv_run`. The one genuine cross-loop primitive is the
//! `uv_async_t` in `rn_uv::wake`, and that is for *waking*, not for tracking
//! liveness. So liveness is a plain list the parent scans, which is what libuv
//! would do internally anyway.
//!
//! # Why the exit is polled in the check phase
//!
//! Node's `onexit` fires from an immediate. The check phase is where immediates
//! run, so polling there gives the same ordering against timers, port deliveries
//! and `setImmediate`, and it cannot fire in the middle of an unrelated callback.
//! That is also why the parent never blocks in `join` while the thread is still
//! running: a blocking join would stall the loop that has to deliver the
//! worker's last messages first.

use std::cell::RefCell;
use std::rc::Rc;

use rn_v8_sys::v8;

use crate::handle::WorkerHandle;

thread_local! {
    /// Every worker object created on this thread that has not been disposed.
    ///
    /// `Rc` because a `WorkerHandle` holds a `v8::Global` (the parent port) and
    /// is not `Send`; it must only ever be touched by the thread that created it.
    static WORKERS: RefCell<Vec<Rc<RefCell<WorkerHandle>>>> = const { RefCell::new(Vec::new()) };
}

/// Registers a worker so the loop can see it and report its exit.
pub fn register(handle: Rc<RefCell<WorkerHandle>>) {
    WORKERS.with(|workers| workers.borrow_mut().push(handle));
    // The check handle must be armed *now*, not when the thread finishes: a
    // worker that exits quickly would signal a loop libuv had already let return
    // from poll, and the exit would only be noticed at whatever timer happened to
    // be next. Arming here means one iteration is scheduled the moment a worker
    // exists, which is also what makes the loop's liveness answer meaningful.
    rn_bind_timers::arm_check_phase();
    // The loop must now stay alive for this worker's exit, and that means the
    // wake handle has to be ref'd: without it libuv calls the loop dead and the
    // callback that reports the exit never runs.
    rn_uv::wake::acquire();
}

/// Removes a worker that has been disposed, Node's `kDispose`.
///
/// Without this the registry would keep every `Worker` object alive for the life
/// of the process, and a `create`/`terminate` loop would leak one port per
/// iteration.
pub fn unregister(handle: &Rc<RefCell<WorkerHandle>>) {
    let removed = WORKERS.with(|workers| {
        let mut workers = workers.borrow_mut();
        let before = workers.len();
        workers.retain(|existing| !Rc::ptr_eq(existing, handle));
        before != workers.len()
    });
    if removed {
        rn_uv::wake::release();
    }
}

/// Whether any worker on this thread still pins the parent's loop.
///
/// This is the `has_external_work` half: a `Worker` object is a ref'd handle in
/// Node until `unref()` or until its thread exits, and without this the parent's
/// loop returns idle the instant the script ends, before the worker has printed
/// anything.
#[must_use]
pub fn any_keeps_loop_alive() -> bool {
    WORKERS.with(|workers| {
        let workers = workers.borrow();
        workers
            .iter()
            .any(|worker| worker.borrow().keeps_loop_alive())
    })
}

/// How many worker objects this thread still tracks.
///
/// Exposed for tests: a create/terminate loop that leaves this climbing has
/// leaked an object per worker.
#[must_use]
pub fn tracked_count() -> usize {
    WORKERS.with(|workers| workers.borrow().len())
}

/// Whether a worker's exit is waiting to be reported.
///
/// The check phase is armed from this, so a worker that finishes while the loop
/// is blocked in poll still wakes it: the thread's last act before setting
/// `finished` is to signal the parent's `uv_async_t`, and this predicate is what
/// makes the resulting iteration do the report.
#[must_use]
pub fn has_finished() -> bool {
    WORKERS.with(|workers| {
        let workers = workers.borrow();
        workers.iter().any(|worker| {
            let handle = worker.borrow();
            handle.exited() && !handle.reported()
        })
    })
}

/// Reports the exit of every worker whose thread has stopped.
///
/// Returns whether any `onexit` callback ran, which the loop uses to decide
/// whether it did work this turn.
///
/// The handle is joined here — after the thread has already set its finished
/// flag, so the join returns at once — because this is the point where the
/// parent is between two JavaScript callbacks and can afford it. Joining is what
/// releases the thread's stack and its `JoinHandle`; leaving it to `Drop` would
/// detach instead.
pub fn report_finished(scope: &mut v8::PinScope<'_, '_>) -> bool {
    // Snapshot first: a `onexit` callback may create or dispose another worker,
    // and mutating the registry while iterating it would be a panic rather than
    // a bug report.
    let workers: Vec<Rc<RefCell<WorkerHandle>>> = WORKERS.with(|workers| workers.borrow().clone());

    let mut reported = false;
    for worker in workers {
        let (callback, code) = {
            let handle = worker.borrow();
            if !handle.exited() || handle.reported() {
                continue;
            }
            (handle.onexit(scope), handle.exit_code())
        };
        {
            // `claim_report` is what makes this happen exactly once, even though
            // the predicate above may be true for several turns while
            // `onexit`'s own work keeps the loop running.
            let handle = worker.borrow();
            if !handle.claim_report() {
                continue;
            }
        }
        // `onexit` is `Worker.prototype[kOnExit]`, which drains the ports, emits
        // `exit` and clears the handle. `lib/internal/worker.js` assigns it
        // between `new WorkerImpl` and `startThread`, so it exists by the time a
        // thread can finish.
        if let Some(callback) = callback {
            let code = v8::Integer::new(scope, code);
            let null = v8::null(scope);
            let arguments = [code.into(), null.into(), null.into()];
            // A throw inside a worker's `'exit'` listener is uncaught: the event
            // is reported from the check phase, where nothing above it can handle
            // one. `onexit` runs through `MakeCallback` in Node, so a throw goes
            // to `TriggerUncaughtException` and sets a non-zero exit code.
            let caught = {
                let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
                let inner = &mut try_catch.init();
                let _ = callback.call(inner, v8::undefined(inner).into(), &arguments);
                inner
                    .exception()
                    .map(|exception| v8::Global::new(inner, exception))
            };
            if let Some(caught) = caught {
                let exception = v8::Local::new(&*scope, &caught);
                rn_errors::report_uncaught_exception(scope, exception);
            }
        }
        // The thread is finished, so its `JoinHandle` returns immediately. It is
        // joined rather than detached so the thread does not outlive its stack.
        let joined = worker.borrow().join();
        if !joined {
            tracing::error!("a worker thread could not be joined after it finished");
        }
        // The report is the last thing this worker needs from the parent's loop,
        // so its ref on the wake handle goes now. This is what lets the process
        // exit once the script has nothing else outstanding, and it is why the
        // ref is taken in `register` rather than in the `Worker` constructor:
        // the two have to be balanced across exactly this pair.
        unregister(&worker);
        reported = true;
    }
    reported
}
