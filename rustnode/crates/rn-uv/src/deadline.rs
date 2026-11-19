//! Waking libuv at a V8 delayed task's deadline.
//!
//! # The deadline libuv cannot see
//!
//! `Atomics.waitAsync` with a timeout does not use a libuv timer. V8 arms it as a
//! *delayed platform task* whose expiry is resolved by a foreground task on the
//! waiting isolate's queue. libuv knows nothing about that deadline, so it sizes
//! its poll from its own timer heap alone and sleeps past it: a 300ms
//! `Atomics.waitAsync` next to a 1000ms interval settled at 905ms, on the
//! interval's wake-up rather than its own.
//!
//! `rn_v8_sys::platform::remaining_until_isolate_millis` answers how long until
//! that deadline. The obvious use — return it from the loop as a poll timeout —
//! would be a second authority deciding how long to sleep, which is exactly what
//! `rn-io`'s `Scheduler` refuses to become: it would have to reproduce
//! `uv__backend_timeout`'s rules (a runnable callback, an idle handle, a closing
//! handle and a child process all force zero) and would disagree with libuv
//! about the answer eventually.
//!
//! # What this does instead
//!
//! One `uv_timer_t`, armed at the V8 deadline and started with a callback that
//! does nothing. libuv's own `uv__next_timeout` then takes it into account when
//! it decides how long to poll, so the loop wakes at the right moment and its
//! checkpoint runs the task that was waiting. libuv remains the only authority on
//! *when the loop sleeps*; this only gives it one more deadline to consider, the
//! same way any other handle would.
//!
//! The handle is **unref'd**, so it never keeps the process alive. That is
//! Node's behaviour and not an incidental detail: a pending `Atomics.waitAsync`
//! timeout does not hold a process open either, so a program with nothing else
//! pending exits before its deadline and the promise never settles. A ref'd
//! handle here would turn every such program into one that waits out its longest
//! `waitAsync` timeout.
//!
//! # Per iteration
//!
//! [`sync`] runs at the start of each iteration. The query behind it takes the
//! queue lock and scans the table, which is too much to pay once per iteration of
//! every program, so the last decision is remembered against a revision that the
//! platform bumps whenever the delayed set changes: an unchanged revision means
//! the previous decision still stands and nothing is touched.
//!
//! That cache is what makes this free in the steady state, and it has one hazard
//! the timer callback owns — see [`on_deadline`] for the case where the handle
//! fires a fraction of a millisecond before the task is due.

use std::pin::Pin;

use libuv_sys2 as uv;

thread_local! {
    /// The deadline handle, as an address, or 0 before it is created.
    ///
    /// An address rather than the `Pin<Box<_>>` because the box is deliberately
    /// leaked: libuv keeps the handle pointer until its close callback runs, and
    /// that callback is the loop's sweep in `uv_loop::close_loop`, not this
    /// module. Holding the box here would make the free depend on thread-local
    /// destruction order relative to the loop's.
    static HANDLE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// The [`Decision`] this thread last acted on.
    ///
    /// [`sync`] runs before every iteration, so anything it does is paid once per
    /// iteration by every program — including the ones that never call
    /// `Atomics.waitAsync`. Remembering the decision against the revision it was
    /// made from turns the steady state into two inline loads and a compare.
    static LAST: std::cell::Cell<Option<Decision>> = const { std::cell::Cell::new(None) };
}

/// What the deadline handle should be doing, and the revision it was decided at.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Decision {
    revision: u64,
    /// The delay armed, or `None` when the handle should be stopped.
    arm: Option<u64>,
}

/// Arms the handle at the isolate's next V8 delayed deadline, or stops it.
///
/// Called once per loop iteration, before `uv_run`, so the deadline libuv is
/// about to poll against is the current one. The last decision is remembered
/// against the revision it was made from, so an iteration where nothing about the
/// delayed set changed costs two inline loads and a compare — which is what keeps
/// this free for the programs that never call `Atomics.waitAsync` at all.
pub fn sync() {
    let revision = rn_v8_sys::platform::delayed_revision();
    if LAST
        .with(std::cell::Cell::get)
        .is_some_and(|last| last.revision == revision)
    {
        return;
    }
    let decision = Decision {
        revision,
        arm: decide(),
    };
    LAST.with(|slot| slot.set(Some(decision)));
    match decision.arm {
        Some(millis) => arm(millis),
        None => stop(),
    }
}

/// What the handle should be doing right now.
fn decide() -> Option<u64> {
    let isolate = crate::callback::remembered_isolate_key()?;
    let millis = rn_v8_sys::platform::remaining_until_isolate_millis(isolate)?;
    // The cached loop clock is only refreshed at phase boundaries, and the delay
    // is added to it by `uv_timer_start`. Without this the timer is armed from the
    // previous iteration's time and can therefore fire a few milliseconds early —
    // the task is then not due yet, and the loop needs an extra iteration.
    crate::uv_loop::update_time();
    Some(millis)
}

/// Starts the handle for `millis` from now, creating it on first use.
fn arm(millis: u64) {
    let Some(handle) = handle() else {
        return;
    };
    // SAFETY: `handle` is the live handle this module created.
    let status = unsafe { uv::uv_timer_start(handle, Some(on_deadline), millis, 0) };
    if status != 0 {
        tracing::error!(status, millis, "uv_timer_start failed for the V8 deadline");
    }
}

/// Stops the handle if it is running.
fn stop() {
    let address = HANDLE.with(std::cell::Cell::get);
    if address == 0 {
        return;
    }
    // SAFETY: a non-zero address is the live handle this module created.
    unsafe {
        let handle = address as *mut uv::uv_timer_t;
        // `uv_timer_stop` on an inactive handle still walks its queue node, and
        // this runs once per iteration whenever *any* isolate has a delayed task,
        // so an idle handle takes the cheap path out.
        if uv::uv_is_active(handle.cast()) != 0 {
            uv::uv_timer_stop(handle);
        }
    }
}

/// The handle, created and unref'd on first use.
fn handle() -> Option<*mut uv::uv_timer_t> {
    let existing = HANDLE.with(std::cell::Cell::get);
    if existing != 0 {
        return Some(existing as *mut uv::uv_timer_t);
    }
    let loop_pointer = crate::uv_loop::loop_ptr()?;
    let mut storage = Box::pin(std::mem::MaybeUninit::<uv::uv_timer_t>::zeroed());
    // SAFETY: `storage` is a live, aligned, zeroed slot and `loop_pointer` is this
    // thread's live loop.
    let status = unsafe { uv::uv_timer_init(loop_pointer, storage.as_mut_ptr()) };
    if status != 0 {
        tracing::error!(status, "uv_timer_init failed for the V8 deadline");
        return None;
    }
    // SAFETY: `uv_timer_init` succeeded, so the slot is initialised. `Pin<Box<_>>`
    // keeps it where libuv was given it; only the box is forgotten, never the
    // value.
    let timer: Pin<Box<uv::uv_timer_t>> =
        unsafe { std::mem::transmute::<_, Pin<Box<uv::uv_timer_t>>>(storage) };
    let handle = std::ptr::from_ref(&*timer).cast_mut();
    // `uv_timer_init` leaves the handle ref'd, so this is the call that makes the
    // deadline inert for liveness. See the module docs for why it must be.
    // SAFETY: `handle` is the live handle just initialised.
    unsafe { uv::uv_unref(handle.cast()) };
    crate::ledger::record_created();
    std::mem::forget(timer);
    HANDLE.with(|slot| slot.set(handle as usize));
    Some(handle)
}

/// The deadline handle's callback, which has nothing to do.
///
/// Being due is the whole job: libuv's poll returned, the loop advances through
/// its check phase, and `rn-io`'s checkpoint drains the delayed task that the
/// deadline belonged to.
///
/// It still has to invalidate the cached decision, though. `uv_timer_start` arms
/// from libuv's *cached* clock, which can be a fraction of a millisecond behind
/// the one the deadline was computed from, so the callback can run while the task
/// is still a hair short of due. The task then stays queued and the delayed set is
/// unchanged — so without this bump the next [`sync`] would decide nothing had
/// moved, leave the now-inactive handle stopped, and the task would wait for an
/// unrelated wake-up. That is the exact bug this module exists to fix, so it must
/// not be reachable from the fix's own edge case.
///
/// # Safety
///
/// Called by libuv with the live handle this module initialised.
unsafe extern "C" fn on_deadline(_handle: *mut uv::uv_timer_t) {
    LAST.with(|slot| slot.set(None));
}

/// The handle's address, or null before it is created.
///
/// Exposed for tests: the pair "started but unref'd" is what makes this fix work,
/// and a regression in either half shows up as a process that will not exit or as
/// a promise that still waits for an unrelated wake-up.
pub fn handle_for_test() -> *mut uv::uv_timer_t {
    HANDLE.with(std::cell::Cell::get) as *mut uv::uv_timer_t
}

/// Whether the handle exists and is running.
pub fn is_armed() -> bool {
    let address = HANDLE.with(std::cell::Cell::get);
    if address == 0 {
        return false;
    }
    // SAFETY: a non-zero address is the live handle this module created.
    unsafe { uv::uv_is_active((address as *mut uv::uv_timer_t).cast()) != 0 }
}

/// Closes the handle and waits for libuv to finish with it.
///
/// The loop's own sweep in `uv_loop::close_loop` closes it too, so this is only
/// for a caller that closes the loop some other way. Idempotent: after the first
/// call the handle is forgotten, so the sweep cannot close it twice.
pub fn shutdown() {
    let address = HANDLE.with(|slot| slot.replace(0));
    if address == 0 {
        return;
    }
    let handle = address as *mut uv::uv_timer_t;
    // SAFETY: `address` came from `handle`, which was removed from the
    // thread-local above so nothing can start it again.
    unsafe {
        uv::uv_timer_stop(handle);
        uv::uv_close(handle.cast(), Some(on_closed));
    }
}

/// Records and frees a closed deadline handle.
///
/// # Safety
///
/// Called by libuv as the `uv_close` callback for the handle [`handle`] leaked.
unsafe extern "C" fn on_closed(handle: *mut uv::uv_handle_t) {
    crate::ledger::record_closed();
    // SAFETY: `handle` was leaked by `handle` and libuv is done with it now, so
    // this is the one deallocation.
    drop(unsafe { Box::from_raw(handle as *mut uv::uv_timer_t) });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handle is created only when it is needed, and is unref'd.
    ///
    /// Both halves matter: a handle created on every loop start would be work for
    /// every program, and a ref'd one would make a pending `Atomics.waitAsync`
    /// timeout keep the process alive, which Node does not do.
    #[test]
    fn the_deadline_handle_is_unrefed_and_not_created_by_sync() {
        let _serialised = crate::global_state_guard();
        assert!(
            handle_for_test().is_null(),
            "nothing has needed the handle yet"
        );
        sync();
        assert!(
            handle_for_test().is_null(),
            "a loop with no V8 deadline must not create it"
        );

        let handle = handle().expect("the loop is creatable");
        assert!(!handle.is_null());
        // SAFETY: `handle` is the live handle just created.
        unsafe {
            assert_eq!(uv::uv_is_active(handle.cast()), 0, "not started by init");
            assert_eq!(uv::uv_has_ref(handle.cast()), 0, "and never keeps it alive");
        }
        shutdown();
        let _ = crate::uv_loop::run_once();
    }

    /// Arming then stopping leaves nothing running, so an iteration with no
    /// deadline does not sleep against a stale one.
    #[test]
    fn arming_and_stopping_follow_the_deadline() {
        let _serialised = crate::global_state_guard();
        arm(50);
        assert!(is_armed(), "a deadline arms the handle");
        stop();
        assert!(!is_armed(), "no deadline stops it again");
        shutdown();
        let _ = crate::uv_loop::run_once();
    }

    /// A due handle drops the cached decision, so the next `sync` re-reads it.
    ///
    /// The case this defends is the timer firing a fraction of a millisecond
    /// before the task is due: the delayed set is unchanged, so a cache that
    /// survived the callback would leave the handle stopped and the task waiting
    /// for an unrelated wake-up — the very bug this module fixes.
    #[test]
    fn a_fired_deadline_does_not_trust_the_previous_decision() {
        let _serialised = crate::global_state_guard();
        LAST.with(|slot| {
            slot.set(Some(Decision {
                revision: 7,
                arm: Some(5),
            }))
        });
        // SAFETY: the callback ignores its handle argument, which is why a null
        // is safe to pass here and every real handle is too.
        unsafe { on_deadline(std::ptr::null_mut()) };
        assert!(
            LAST.with(std::cell::Cell::get).is_none(),
            "the decision must be dropped so the next sync recomputes it"
        );
    }
}
