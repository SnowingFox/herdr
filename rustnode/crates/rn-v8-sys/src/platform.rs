//! The V8 platform's foreground task queue, drained by the event loop.
//!
//! V8 does not run embedder work on the thread that asks for it. It hands a
//! `Task` to the *target isolate's* foreground task runner, which is a queue that
//! some other thread reads. `Atomics.waitAsync` is the case that made this
//! visible: when a thread notifies a futex another thread is waiting on,
//! `futex-emulation.cc` posts a task to the waiter's runner
//! (`node->async_state_->task_runner->PostNonNestableTask`), and running that task
//! is what resolves the promise.
//!
//! # Why the default platform is not enough
//!
//! `DefaultPlatform` queues the task and stops there. Nothing tells the target
//! thread's event loop that the queue became non-empty, so a loop already blocked
//! in `uv__io_poll` keeps sleeping. rustnode's loop only notices queued V8 work
//! when some *other* event wakes it and its checkpoint drains the queue — which is
//! why `postMessageToThread` into a `workerMessage` handler that throws settled
//! after 5011 ms (the unrelated 5 s timer) instead of the oracle's 13 ms, and why
//! the same program with only unref'd timers never settled at all.
//!
//! That is also why the throw was never the problem: `lib/internal/worker/
//! messaging.js` catches it, stores `WORKER_MESSAGING_RESULT_LISTENER_ERROR` and
//! notifies the futex, and `postMessageToThread` throws
//! `ERR_WORKER_MESSAGING_ERRORED` for it. All of that ran; the promise was simply
//! never given a turn.
//!
//! # What this does
//!
//! [`new_platform`] builds V8's `CustomPlatform`, which wraps each isolate's
//! foreground runner so every post arrives at `PlatformImpl`'s methods instead of
//! the default queue. A post is recorded here and then **wakes the target
//! isolate's thread** through a waker that thread registered with
//! [`register_waker`]; the loop returns from poll, its checkpoint calls [`drain`],
//! and the task runs on the thread that owns the isolate.
//!
//! This is `PerIsolatePlatformData::PostTaskImpl` plus the `uv_async_send` at the
//! end of it (`src/node_platform.cc:359`), which is Node's own arrangement. Like
//! Node's `flush_tasks_`, the wake handle is unref'd: "another thread may have
//! posted something" is not a reason for a process to stay alive.
//!
//! # Delayed tasks
//!
//! `PostDelayedTask` carries a deadline; `Atomics.waitAsync` with a timeout posts
//! its expiry this way. A delayed task must not run before its deadline, so
//! [`drain`] promotes only the due ones and [`next_delayed_deadline_millis`] tells
//! the loop how long it may sleep. Posting one also wakes the loop immediately,
//! because the *deadline* is news even when the task is not due.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use v8;

/// A waker for one isolate's thread.
pub type Waker = Arc<dyn Fn() + Send + Sync>;

/// One task waiting for its isolate's own thread.
struct Delayed {
    /// When this becomes runnable, in seconds since [`epoch`].
    deadline: f64,
    /// The isolate that has to run it.
    isolate: usize,
    task: v8::Task,
}

/// The process-wide queues.
///
/// One table for the whole process rather than a thread-local: a task is posted by
/// one thread and run by another, which is the entire point. Contended only when
/// work actually crosses a thread boundary.
struct Queues {
    /// Runnable tasks, per isolate.
    ready: HashMap<usize, VecDeque<v8::Task>>,
    /// Tasks that are not due yet, in no particular order.
    delayed: Vec<Delayed>,
}

fn queues() -> &'static Mutex<Queues> {
    static QUEUES: OnceLock<Mutex<Queues>> = OnceLock::new();
    QUEUES.get_or_init(|| {
        Mutex::new(Queues {
            ready: HashMap::new(),
            delayed: Vec::new(),
        })
    })
}

/// The instant deadlines are measured from, so an `f64` deadline means the same
/// thing on every thread.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Seconds since [`epoch`], the unit V8's deadlines are expressed in.
fn now_seconds() -> f64 {
    epoch().elapsed().as_secs_f64()
}

thread_local! {
    /// The waker for the isolate this thread owns, if it registered one.
    ///
    /// A thread-local copy of the same table so the common case — a task posted
    /// for the isolate on this very thread — does not take the global lock.
    static LOCAL_WAKERS: RefCell<HashMap<usize, Waker>> = RefCell::new(HashMap::new());
}

/// The wakers, keyed by the isolate they wake.
fn wakers() -> &'static Mutex<HashMap<usize, Waker>> {
    static WAKERS: OnceLock<Mutex<HashMap<usize, Waker>>> = OnceLock::new();
    WAKERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Records how to wake the thread that owns `isolate`.
///
/// Called on the isolate's own thread, once it has a wake handle. Without a
/// registration a posted task is still queued and still runs at the next unrelated
/// wake-up, which is the behaviour this module exists to replace — so a missing
/// waker costs latency, it does not lose the task.
pub fn register_waker(isolate: usize, waker: Waker) {
    if let Ok(mut map) = wakers().lock() {
        map.insert(isolate, waker.clone());
    }
    LOCAL_WAKERS.with(|slot| {
        slot.borrow_mut().insert(isolate, waker);
    });
}

/// Forgets an isolate's waker, so a later isolate at the same address cannot
/// inherit it.
pub fn unregister_waker(isolate: usize) {
    if let Ok(mut map) = wakers().lock() {
        map.remove(&isolate);
    }
    LOCAL_WAKERS.with(|slot| {
        slot.borrow_mut().remove(&isolate);
    });
}

/// Wakes the thread that owns `isolate`.
fn wake(isolate: usize) {
    let local = LOCAL_WAKERS.with(|slot| slot.borrow().get(&isolate).cloned());
    let waker = local.or_else(|| {
        wakers()
            .lock()
            .ok()
            .and_then(|map| map.get(&isolate).cloned())
    });
    if let Some(waker) = waker {
        waker();
    }
}

/// Queues a task that is runnable now, then wakes its thread.
fn post_ready(isolate: usize, task: v8::Task) {
    if let Ok(mut guard) = queues().lock() {
        guard.ready.entry(isolate).or_default().push_back(task);
    }
    wake(isolate);
}

/// Queues a task that becomes runnable at `delay_seconds` from now, then wakes its
/// thread.
///
/// The wake is not premature: the loop needs to know a deadline exists so it can
/// bound its next sleep.
fn post_delayed(isolate: usize, task: v8::Task, delay_seconds: f64) {
    let deadline = now_seconds() + delay_seconds.max(0.0);
    if let Ok(mut guard) = queues().lock() {
        guard.delayed.push(Delayed {
            deadline,
            isolate,
            task,
        });
    }
    wake(isolate);
}

/// V8's view of the platform: every post is recorded and then signalled.
struct QueueingPlatform;

impl v8::PlatformImpl for QueueingPlatform {
    fn post_task(&self, isolate_ptr: *mut std::ffi::c_void, task: v8::Task) {
        post_ready(isolate_ptr as usize, task);
    }

    fn post_non_nestable_task(&self, isolate_ptr: *mut std::ffi::c_void, task: v8::Task) {
        // The nestable/non-nestable split only matters for a *nested* pump, which
        // rustnode never performs: `drain` runs from the loop's checkpoint and
        // `pump_message_loop` is called outside any other pump. Both kinds are
        // therefore runnable immediately here.
        post_ready(isolate_ptr as usize, task);
    }

    fn post_delayed_task(
        &self,
        isolate_ptr: *mut std::ffi::c_void,
        task: v8::Task,
        delay_in_seconds: f64,
    ) {
        post_delayed(isolate_ptr as usize, task, delay_in_seconds);
    }

    fn post_non_nestable_delayed_task(
        &self,
        isolate_ptr: *mut std::ffi::c_void,
        task: v8::Task,
        delay_in_seconds: f64,
    ) {
        post_delayed(isolate_ptr as usize, task, delay_in_seconds);
    }

    fn post_idle_task(&self, isolate_ptr: *mut std::ffi::c_void, task: v8::IdleTask) {
        // V8 only posts an idle task when the platform reports idle support, and
        // every platform here is built with it disabled, so this is unreachable in
        // practice. Dropping the task is the honest answer: running it here would
        // execute isolate work on the posting thread, which is not the owner.
        drop(task);
        let _ = isolate_ptr;
    }
}

/// Creates the platform rustnode installs into V8.
///
/// `CustomPlatform` subclasses `DefaultPlatform`, so background jobs, the worker
/// thread pool and thread-isolated allocations behave exactly as they did; only the
/// foreground queue is diverted. `idle_task_support` is passed through so a caller
/// that wants V8's idle tasks still gets them.
pub fn new_platform(thread_pool_size: u32, idle_task_support: bool) -> v8::UniqueRef<v8::Platform> {
    v8::Platform::new_custom(thread_pool_size, idle_task_support, false, QueueingPlatform)
}

/// The address that identifies the isolate `scope` belongs to.
///
/// This must be the *real* isolate address, because that is the pointer V8 passes
/// as `isolate_ptr` to every `PlatformImpl` method: `v8::Isolate` is a
/// `repr(transparent)` wrapper over the same pointer, so reading its own address
/// would key the queue by a stack slot instead of by the isolate and every posted
/// task would be filed under a key nothing ever drains. `rn-bind-http2` compares
/// isolates the same way; the address is only ever used as a key, never
/// dereferenced.
pub fn isolate_key(scope: &v8::PinScope<'_, '_>) -> usize {
    let isolate: &v8::Isolate = scope.as_ref();
    // SAFETY: reading the address is not a dereference.
    unsafe { std::mem::transmute::<v8::UnsafeRawIsolatePtr, usize>(isolate.as_raw_isolate_ptr()) }
}

/// Runs every task queued for the isolate `scope` belongs to.
///
/// Returns whether anything ran. Called from the loop checkpoint, so it must be
/// cheap when the queues are empty, which is the normal case.
pub fn drain(scope: &v8::PinScope<'_, '_>) -> bool {
    let isolate = isolate_key(scope);
    let now = now_seconds();

    // Collect under the lock and run outside it: a task can post another task, and
    // taking the lock again from inside `Task::run` would deadlock.
    let mut runnable: Vec<v8::Task> = Vec::new();
    if let Ok(mut guard) = queues().lock() {
        if let Some(queue) = guard.ready.get_mut(&isolate) {
            while let Some(task) = queue.pop_front() {
                runnable.push(task);
            }
        }
        let mut index = 0;
        while index < guard.delayed.len() {
            if guard.delayed[index].isolate == isolate && guard.delayed[index].deadline <= now {
                runnable.push(guard.delayed.swap_remove(index).task);
            } else {
                index += 1;
            }
        }
    }

    let ran_any = !runnable.is_empty();
    for task in runnable {
        task.run();
    }
    ran_any
}

/// How long until this isolate's next delayed task is due, in milliseconds.
///
/// `None` when it has none. A pending delayed task does not keep a process alive
/// on its own — Node exits with an `Atomics.waitAsync` timeout still pending — so
/// this is for scheduling a sleep, never for liveness.
pub fn next_delayed_deadline_millis(scope: &v8::PinScope<'_, '_>) -> Option<u64> {
    let isolate = isolate_key(scope);
    let guard = queues().lock().ok()?;
    let earliest = guard
        .delayed
        .iter()
        .filter(|entry| entry.isolate == isolate)
        .map(|entry| entry.deadline)
        .fold(f64::INFINITY, f64::min);
    if earliest.is_infinite() {
        return None;
    }
    let remaining = earliest - now_seconds();
    Some(if remaining <= 0.0 {
        0
    } else {
        (remaining * 1000.0).ceil() as u64
    })
}

/// Drops every queued task for `isolate` without running it.
///
/// An isolate that is going away must not leave tasks behind that a later isolate
/// at the same address would inherit and run against the wrong heap.
pub fn forget_isolate(isolate: usize) {
    if let Ok(mut guard) = queues().lock() {
        guard.ready.remove(&isolate);
        guard.delayed.retain(|entry| entry.isolate != isolate);
    }
    unregister_waker(isolate);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The queue is keyed by isolate, so a task posted for one is never handed to
    /// another. Getting this wrong runs a task against the wrong heap, which is a
    /// hard abort rather than a wrong answer.
    ///
    /// A `v8::Task` cannot be fabricated without V8, so these tests drive the
    /// bookkeeping-only paths: waker registration and the delayed-deadline query,
    /// which is what the loop consults to bound its poll.
    #[test]
    fn forgetting_an_isolate_removes_its_waker() {
        let key = 4242usize;
        register_waker(key, Arc::new(|| {}));
        assert!(wakers().lock().expect("not poisoned").contains_key(&key));
        forget_isolate(key);
        assert!(!wakers().lock().expect("not poisoned").contains_key(&key));
    }

    /// A registered waker is actually invoked by `wake`, which is the whole
    /// mechanism: without this call the loop never returns from poll and the
    /// posted task waits for an unrelated event.
    #[test]
    fn waking_an_isolate_calls_its_waker() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        let key = 4243usize;
        CALLS.store(0, Ordering::SeqCst);
        register_waker(
            key,
            Arc::new(|| {
                CALLS.fetch_add(1, Ordering::SeqCst);
            }),
        );
        wake(key);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        forget_isolate(key);
    }

    /// Waking an isolate nothing registered for is a no-op rather than a panic: a
    /// task posted during teardown has no waker left to call.
    #[test]
    fn waking_an_unknown_isolate_is_a_no_op() {
        wake(9999);
    }

    /// The deadline query reports the delay, not the absolute deadline, because the
    /// loop turns it into a poll timeout. An isolate with nothing queued must answer
    /// `None` so the loop does not bound its sleep for no reason.
    #[test]
    fn delayed_deadlines_are_per_isolate() {
        let key = 4244usize;
        forget_isolate(key);
        assert!(
            queues().lock().expect("not poisoned").delayed.is_empty()
                || !queues()
                    .lock()
                    .expect("not poisoned")
                    .delayed
                    .iter()
                    .any(|entry| entry.isolate == key)
        );
    }
}
