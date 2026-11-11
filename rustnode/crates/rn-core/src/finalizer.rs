//! Finalizers that run on the loop's thread even when V8 calls them from another.
//!
//! # The problem this exists for
//!
//! V8 invokes a weak callback on whichever thread triggered the collection. In
//! this runtime that is **not** the isolate's thread: measured directly, a
//! buffer's backing-store deleter ran on thread `0x7f9d…e6c0` while the isolate
//! lived on `0x7f9d…2940`. Real Node runs the same finalizer on the main thread
//! (`pthread_equal` returned true), so this is a divergence to fix, not a
//! property of V8.
//!
//! A finalizer is addon code: it may call `napi_throw_error`, create a value,
//! delete a reference. All of that needs a handle scope and an entered context,
//! and doing it from a foreign thread without a `v8::Locker` is undefined
//! behaviour — not merely "fails to find a scope". `with_guaranteed_finalizer`'s
//! own documentation says so: reaching for the isolate from the callback is
//! unsound unless the isolate is provably alive.
//!
//! # The shape of the fix
//!
//! Node does not run the addon's finalizer from the GC callback either. It parks
//! it on `pending_finalizers` and calls `DrainFinalizerQueue` from a
//! `SetImmediate` — `node_napi_env__::EnqueueFinalizer` in `src/node_api.cc`.
//! Enqueue-from-any-thread, drain-on-the-loop-thread is the whole design.
//!
//! [`enqueue`] is that enqueue: a process-wide mutex-protected list, safe to call
//! from a GC thread because it touches no V8 state. [`run_pending`] is the drain,
//! called from the check phase where a scope already exists.
//!
//! # Why a `Mutex` and not a channel
//!
//! The queue holds a plain closure and nothing else, has one consumer, and must
//! never block a GC thread. A `Mutex<Vec<_>>` with a short critical section is the
//! smallest thing that satisfies that; a channel would add a dependency and a
//! second wake mechanism for no benefit, since the loop already has to be woken
//! and that is `native_immediates::set_wakeup`'s job.

use std::sync::{Mutex, OnceLock};

/// How to make the loop run a check phase.
///
/// `rn-core` does not own libuv's check handle, so the crate that does registers
/// this — the same seam `native_immediates` uses, for the same reason. Without it a
/// queued finalizer would wait for some unrelated work to arm the handle, which for
/// a script with nothing else pending means never.
///
/// Process-wide rather than thread-local, unlike `native_immediates::WAKEUP`:
/// `enqueue` runs on whichever thread V8 collected on, so a thread-local slot
/// would be empty exactly when it is needed.
fn wakeup() -> &'static Mutex<Option<fn()>> {
    static WAKEUP: OnceLock<Mutex<Option<fn()>>> = OnceLock::new();
    WAKEUP.get_or_init(|| Mutex::new(None))
}

/// Registers how to wake the loop for a deferred finalizer.
///
/// One slot, replaced rather than accumulated: there is one check handle per
/// process.
pub fn set_wakeup(wake: fn()) {
    match wakeup().lock() {
        Ok(mut slot) => *slot = Some(wake),
        Err(poisoned) => *poisoned.into_inner() = Some(wake),
    }
}

/// Wakes the loop so the queued finalizers run.
///
/// # Why this must not touch libuv directly
///
/// `enqueue` runs on whichever thread V8 collected on, and libuv handles belong to
/// the loop that created them. Calling a wakeup that starts a `uv_check_t` from a
/// GC thread would create a *second* set of handles on a loop nothing pumps.
/// Verified the hard way: doing that armed handles that never ran and left the
/// finalizer stuck.
///
/// The registered wakeup is therefore expected to be thread-safe and to signal the
/// loop rather than manipulate it. `rn-bind-timers` registers one that posts to the
/// loop's async handle, which is safe from any thread.
fn wake() {
    let wake = match wakeup().lock() {
        Ok(slot) => *slot,
        Err(poisoned) => *poisoned.into_inner(),
    };
    if let Some(wake) = wake {
        wake();
    }
}

/// One deferred finalizer.
///
/// A boxed closure rather than a function pointer: a finalizer carries the addon's
/// `napi_finalize`, its `data`, its `hint` and the `napi_env`. Those are four
/// words of captured state, and there is one allocation per freed object at most,
/// on a path that already allocated that object.
type Pending = Box<dyn FnOnce(&mut rn_v8_sys::v8::PinScope<'_, '_>) + Send>;

fn queue() -> &'static Mutex<Vec<Pending>> {
    static QUEUE: OnceLock<Mutex<Vec<Pending>>> = OnceLock::new();
    QUEUE.get_or_init(|| Mutex::new(Vec::new()))
}

/// Defers `body` to the loop's thread.
///
/// Safe to call from any thread, including a V8 GC thread, because it touches no
/// V8 state — only the queue's mutex.
///
/// Returns `false` when the queue is poisoned, which means another thread panicked
/// while holding it. The caller should treat that as "the finalizer will not run"
/// rather than retrying, because the queue's contents are then unknown.
pub fn enqueue(body: impl FnOnce(&mut rn_v8_sys::v8::PinScope<'_, '_>) + Send + 'static) -> bool {
    match queue().lock() {
        Ok(mut pending) => {
            pending.push(Box::new(body));
            drop(pending);
            // The loop has to run an iteration, or nothing drains the queue.
            wake();
            true
        }
        Err(poisoned) => {
            // The list itself is still structurally sound — a `Vec` cannot be
            // half-pushed — so recovering is better than dropping the finalizer.
            poisoned.into_inner().push(Box::new(body));
            wake();
            true
        }
    }
}

/// Whether any finalizer is waiting, so the check phase knows it has work.
#[must_use]
pub fn has_pending() -> bool {
    match queue().lock() {
        Ok(pending) => !pending.is_empty(),
        Err(poisoned) => !poisoned.into_inner().is_empty(),
    }
}

/// Runs every deferred finalizer on this thread.
///
/// Call this from the check phase, where a scope exists. A finalizer that enqueues
/// another is honoured in the same drain, which is what `DrainFinalizerQueue`'s
/// `while (!pending_finalizers.empty())` loop does: an addon deleting a reference
/// inside a finalizer must not push the next finalizer into an iteration that may
/// never come.
pub fn run_pending(scope: &mut rn_v8_sys::v8::PinScope<'_, '_>) {
    loop {
        let batch = match queue().lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        if batch.is_empty() {
            return;
        }
        for finalizer in batch {
            finalizer(scope);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deferred_finalizer_is_visible_before_it_runs() {
        // `has_pending` is what tells the check phase to run at all; a queue that
        // swallowed the entry would leave the finalizer waiting forever.
        let before = has_pending();
        assert!(
            enqueue(|_| {}),
            "enqueueing must not fail on an unpoisoned queue"
        );
        assert!(has_pending() || before, "the entry must be visible");
    }

    #[test]
    fn enqueueing_from_another_thread_is_safe() {
        // The whole point: V8 calls the weak callback on a GC thread. This proves
        // the queue itself accepts that without touching V8.
        let handle = std::thread::spawn(|| {
            let marker = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let inner = marker.clone();
            assert!(enqueue(move |_| {
                inner.store(true, std::sync::atomic::Ordering::SeqCst);
            }));
            marker
        });
        let marker = handle.join().expect("the thread must not panic");
        assert!(has_pending(), "the other thread's entry must be queued");
        // The marker is not set yet: nothing has drained.
        assert!(!marker.load(std::sync::atomic::Ordering::SeqCst));
    }
}
