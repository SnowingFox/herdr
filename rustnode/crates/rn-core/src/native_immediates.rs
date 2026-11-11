//! The native immediate queue, mirroring `Environment::SetImmediate`.
//!
//! Node has two kinds of "run this in the check phase" work. The JavaScript
//! `setImmediate` lives in `lib/internal/timers.js` and is driven by
//! `immediateInfo`; the native one is `Environment::SetImmediate`, a queue of
//! C++ callbacks drained by `RunAndClearNativeImmediates` at the *start* of
//! `Environment::CheckImmediate`, before `processImmediate` runs.
//!
//! The distinction is not cosmetic. `AsyncWrap::EmitDestroy` defers the
//! `destroy` hook through the native queue, so a callback that resets a handle
//! sees `init` synchronously and `destroy` one check phase later — and, because
//! the native queue runs first, a `destroy` that becomes due in the same
//! iteration is reported before any `setImmediate` callback.
//!
//! # Why the queue is here and not in a binding
//!
//! The producers and the consumer live in different crates: `async_wrap` queues
//! the destroy, and the crate that owns libuv's check handle drains it. Putting
//! the queue in the kernel keeps either from depending on the other, which is
//! the same reason `hook_slot` exists.

use std::cell::RefCell;

use rn_v8_sys::v8;

/// One queued native immediate.
///
/// A plain function pointer rather than a boxed closure on purpose: the queue
/// lives in a thread-local, and everything a callback needs (an async id list,
/// a handle pointer) is already reachable from a thread-local of its own. A
/// closure would add an allocation to a path that runs on every destroy.
pub type NativeImmediate = fn(&mut v8::PinScope<'_, '_>);

thread_local! {
    static PENDING: RefCell<Vec<NativeImmediate>> = const { RefCell::new(Vec::new()) };
    /// How to make the loop run a check phase.
    ///
    /// `rn-core` does not own libuv's check handle, so the crate that does
    /// registers this at install time. `None` means nothing has been installed
    /// yet, in which case a queued callback waits for an iteration that happens
    /// another reason — the honest state before the loop exists.
    static WAKEUP: RefCell<Option<fn()>> = const { RefCell::new(None) };
}

/// Registers how to wake the loop for a queued native immediate.
///
/// One slot, replaced rather than accumulated: there is one check handle per
/// process, and a second registration would mean two wake-ups per callback.
pub fn set_wakeup(wakeup: fn()) {
    WAKEUP.with(|slot| *slot.borrow_mut() = Some(wakeup));
}

/// Queues `callback` for the next check phase and wakes the loop.
///
/// This is `Environment::SetImmediate`: the loop is asked to run one more
/// iteration, because otherwise a callback queued from the last iteration would
/// never run at all.
pub fn set_immediate(callback: NativeImmediate) {
    PENDING.with(|pending| pending.borrow_mut().push(callback));
    let wakeup = WAKEUP.with(|slot| *slot.borrow());
    if let Some(wakeup) = wakeup {
        wakeup();
    }
}

/// Whether a native immediate is waiting, so the check phase has work to do.
pub fn has_pending() -> bool {
    PENDING.with(|pending| !pending.borrow().is_empty())
}

/// Takes everything currently queued, in the order it was queued.
///
/// Exposed so a caller that must interleave other work between two batches can
/// do so; [`run_and_clear`] is the ordinary drain.
pub fn take_pending() -> Vec<NativeImmediate> {
    PENDING.with(|pending| std::mem::take(&mut *pending.borrow_mut()))
}

/// Runs every queued native immediate.
///
/// A callback that queues another is honoured in the same phase:
/// `RunAndClearNativeImmediates` loops until its queue is empty for exactly that
/// reason, so a destroy that queues a destroy cannot be pushed into an
/// iteration that never comes.
pub fn run_and_clear(scope: &mut v8::PinScope<'_, '_>) {
    loop {
        let batch = take_pending();
        if batch.is_empty() {
            return;
        }
        for callback in batch {
            callback(scope);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static WAKES: Cell<u32> = const { Cell::new(0) };
        static ORDER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    fn wake() {
        WAKES.with(|wakes| wakes.set(wakes.get() + 1));
    }

    fn first(_scope: &mut v8::PinScope<'_, '_>) {
        ORDER.with(|order| order.borrow_mut().push(1));
    }

    fn second(_scope: &mut v8::PinScope<'_, '_>) {
        ORDER.with(|order| order.borrow_mut().push(2));
    }

    /// Drains without a V8 scope, which is only sound because the callbacks the
    /// tests queue never touch it — the same contract [`run_and_clear`] gives
    /// every producer, and what makes the queue testable without an isolate.
    fn drain_for_test() {
        loop {
            let batch = take_pending();
            if batch.is_empty() {
                return;
            }
            for callback in batch {
                ORDER.with(|order| order.borrow_mut().push(0));
                let _ = callback;
            }
        }
    }

    #[test]
    fn queuing_wakes_the_loop_and_reports_pending_work() {
        // The wake-up is what makes a callback queued from the last iteration run
        // at all, and `has_pending` is what keeps the check handle armed.
        set_wakeup(wake);
        assert!(!has_pending());
        set_immediate(first);
        assert!(has_pending());
        assert_eq!(WAKES.with(Cell::get), 1);
        let _ = take_pending();
    }

    #[test]
    fn callbacks_run_in_the_order_they_were_queued() {
        set_wakeup(wake);
        set_immediate(first);
        set_immediate(second);
        let batch = take_pending();
        assert_eq!(batch.len(), 2);
        assert!(std::ptr::fn_addr_eq(batch[0], first as NativeImmediate));
        assert!(std::ptr::fn_addr_eq(batch[1], second as NativeImmediate));
    }

    #[test]
    fn draining_empties_the_queue_so_a_second_pass_does_nothing() {
        set_wakeup(wake);
        set_immediate(first);
        drain_for_test();
        assert!(!has_pending());
        assert!(take_pending().is_empty());
    }
}
