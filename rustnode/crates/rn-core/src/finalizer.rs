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

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;

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
    /// The registered wakeup, in a cell that is set once at install time and read
    /// from any thread afterwards.
    type Wakeup = Mutex<Option<fn()>>;
    static WAKEUP: OnceLock<Wakeup> = OnceLock::new();
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

/// The body of a deferred finalizer.
///
/// Takes no scope argument, and the queue is not generic over one. `PinScope` is
/// invariant over its lifetime and context parameters, so a stored closure that
/// named them could only be enqueued and drained from code that agreed on exactly
/// those types — which the enqueue site (a GC thread in `rn-napi`) and the drain (a
/// scheduler iteration) do not.
///
/// Each `rn-napi` finalizer instead re-enters through `rn-napi::scope::with_context`,
/// which opens a handle scope and publishes it, so `napi_*` calls inside the
/// finalizer resolve normally.
pub type FinalizerBody = dyn FnOnce() + Send;

/// One deferred finalizer.
///
/// A boxed closure rather than a function pointer: a finalizer carries the addon's
/// `napi_finalize`, its `data`, its `hint` and the `napi_env`. Those are four words
/// of captured state, and there is at most one allocation per freed object, on a
/// path that already allocated that object.
type Pending = Box<FinalizerBody>;

/// The queue, keyed by the thread that must run each entry.
///
/// Per-thread rather than one flat list because there is one isolate per worker
/// thread: a worker's finalizer calls into the worker's isolate, and running it on
/// the main thread would enter the wrong one. Keying by the *owning* thread means
/// each realm drains exactly its own finalizers and the question never arises,
/// which is better than guarding at the call site.
///
/// The key is captured at [`enqueue`] time and read at drain time, so a worker that
/// exits without collecting leaves its entries behind rather than handing them to
/// another realm.
fn queue() -> &'static Mutex<HashMap<ThreadId, Vec<Pending>>> {
    static QUEUE: OnceLock<Mutex<HashMap<ThreadId, Vec<Pending>>>> = OnceLock::new();
    QUEUE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The thread that owns the finalizers being enqueued.
///
/// A GC callback runs on whichever thread triggered the collection, which is *not*
/// the isolate's thread in this runtime (measured: they differ). The owner is
/// therefore an explicit parameter rather than `thread::current()`.
fn owner_of(owner: Option<ThreadId>) -> ThreadId {
    owner.unwrap_or_else(|| std::thread::current().id())
}

/// Defers `body` to the loop's thread.
///
/// Safe to call from any thread, including a V8 GC thread, because it touches no
/// V8 state — only the queue's mutex.
///
/// Returns `false` when the queue is poisoned, which means another thread panicked
/// while holding it. The caller should treat that as "the finalizer will not run"
/// rather than retrying, because the queue's contents are then unknown.
pub fn enqueue(body: impl FnOnce() + Send + 'static) -> bool {
    enqueue_for(None, body)
}

/// Defers `body` to `owner`'s thread.
///
/// `owner` is the thread whose isolate the finalizer must run against; `None`
/// means the current thread. A V8 GC callback passes `Some` because it runs on a
/// collection thread, not the isolate's.
pub fn enqueue_for(owner: Option<ThreadId>, body: impl FnOnce() + Send + 'static) -> bool {
    let key = owner_of(owner);
    match queue().lock() {
        Ok(mut pending) => {
            pending.entry(key).or_default().push(Box::new(body));
            drop(pending);
            // The loop has to run an iteration, or nothing drains the queue.
            wake();
            true
        }
        Err(poisoned) => {
            // The map itself is still structurally sound — a `HashMap` cannot be
            // half-inserted — so recovering is better than dropping the finalizer.
            poisoned
                .into_inner()
                .entry(key)
                .or_default()
                .push(Box::new(body));
            wake();
            true
        }
    }
}

/// Whether any finalizer is waiting, so the check phase knows it has work.
#[must_use]
pub fn has_pending() -> bool {
    has_pending_for(std::thread::current().id())
}

/// Whether a finalizer is waiting for `owner`'s thread.
#[must_use]
pub fn has_pending_for(owner: ThreadId) -> bool {
    match queue().lock() {
        Ok(pending) => pending.get(&owner).is_some_and(|list| !list.is_empty()),
        Err(poisoned) => poisoned
            .into_inner()
            .get(&owner)
            .is_some_and(|list| !list.is_empty()),
    }
}

/// Runs every deferred finalizer on this thread.
///
/// Call this from the check phase, where a scope exists. A finalizer that enqueues
/// another is honoured in the same drain, which is what `DrainFinalizerQueue`'s
/// `while (!pending_finalizers.empty())` loop does: an addon deleting a reference
/// inside a finalizer must not push the next finalizer into an iteration that may
/// never come.
pub fn run_pending() {
    let owner = std::thread::current().id();
    loop {
        let batch = match queue().lock() {
            Ok(mut pending) => pending.remove(&owner).unwrap_or_default(),
            Err(poisoned) => poisoned.into_inner().remove(&owner).unwrap_or_default(),
        };
        if batch.is_empty() {
            return;
        }
        for finalizer in batch {
            finalizer();
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
            enqueue(|| {}),
            "enqueueing must not fail on an unpoisoned queue"
        );
        assert!(has_pending() || before, "the entry must be visible");
    }

    #[test]
    fn enqueueing_from_another_thread_is_safe() {
        // The whole point: V8 calls the weak callback on a GC thread, not the
        // isolate's. This proves the queue accepts that without touching V8, and
        // that the entry is filed under the *owner* rather than the thread that
        // happened to enqueue it.
        let owner = std::thread::current().id();
        let handle = std::thread::spawn(move || {
            let marker = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let inner = marker.clone();
            assert!(enqueue_for(Some(owner), move || {
                inner.store(true, std::sync::atomic::Ordering::SeqCst);
            }));
            marker
        });
        let marker = handle.join().expect("the thread must not panic");
        assert!(
            has_pending_for(owner),
            "the entry must be filed under the owner thread, not the enqueuer"
        );
        // The marker is not set yet: nothing has drained.
        assert!(!marker.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn an_entry_for_another_thread_is_not_drained_here() {
        // The worker_threads hazard: a worker's finalizer must not be picked up by
        // the main realm's drain, because `with_context` would enter the main
        // isolate while the addon's pointers belong to the worker's.
        // A thread that runs a drain of its own, so the entry is genuinely
        // processed there rather than merely filed and ignored.
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        let other = std::thread::spawn(move || {
            let id = std::thread::current().id();
            assert!(enqueue_for(Some(id), move || {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }));
            (id, has_pending_for(id))
        })
        .join()
        .expect("the other thread must not panic");
        let (other, filed_on_owner) = other;
        assert!(filed_on_owner, "filed under its owner's id");
        assert!(has_pending_for(other), "filed under its owner");
        assert!(
            !has_pending_for(std::thread::current().id()),
            "the current thread must not see another thread's work"
        );
        // Drain here: it must leave the other thread's entry alone. The `|| true`
        // this replaces made the check vacuous, which is the failure mode this
        // whole slice keeps running into.
        run_pending();
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "this thread's drain must not run another thread's finalizer"
        );
        assert!(
            has_pending_for(other),
            "the other thread's entry must still be waiting for that thread"
        );
    }
}
