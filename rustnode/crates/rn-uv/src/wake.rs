//! Waking one thread's event loop from another thread.
//!
//! Once a `MessagePort` can have its two ends on different threads, the sending
//! thread has to make the receiving thread's loop run. `uv_async_send` is
//! libuv's answer and the only portable one: it is documented as safe to call
//! from any thread, and it makes a loop that is blocked in `uv__io_poll` return
//! so its asynchronous callback runs on the owning loop.
//!
//! # What this owns
//!
//! One `uv_async_t` per thread that asks for one, plus a process-wide table from
//! a thread token to the handle, so a foreign thread can find the target. The
//! handle itself never crosses a thread; only the token and the
//! `uv_async_send` call do.
//!
//! # Why an explicit shutdown and not a `Drop`
//!
//! `uv_loop_close` fails with `UV_EBUSY` while any handle is still open, and a
//! handle is only fully gone after libuv has run its close callback. A `Drop`
//! that called `uv_close` and returned would therefore leave the loop
//! unclosable, and the next thing to touch it — usually the thread's own
//! teardown — would either fail or leak. The project has already paid for this
//! class of bug once: a failed `uv_spawn` left its handle open, `uv_loop_close`
//! returned `UV_EBUSY`, and the loop was freed anyway, leaving a dangling
//! watcher in libuv's process-global signal tree.
//!
//! [`shutdown_current_thread`] therefore closes the handle *and* pumps the loop
//! until the close callback has run, so a caller that then closes the loop is
//! guaranteed it is empty. It is idempotent, and it is the only way the handle
//! is ever released.
//!
//! # Cost
//!
//! One handle per thread that has ports, created on first use. A process that
//! never crosses a thread boundary never creates one.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use libuv_sys2 as uv;

thread_local! {
    /// The handle this thread registered, as an address, or 0.
    static LOCAL: Cell<usize> = const { Cell::new(0) };

    /// The token that handle is published under, or 0.
    static LOCAL_TOKEN: Cell<u64> = const { Cell::new(0) };

    /// How many times the owner asked for the handle to be ref'd.
    ///
    /// The handle starts unref'd so a process that only waits on other threads
    /// can exit; while something is genuinely waiting on a foreign signal, the
    /// handle has to be *ref'd*, or libuv calls the loop dead and the callback
    /// that would report the signal never runs. This is Node's
    /// `env->add_refs(1)` expressed on the wake handle itself.
    static LOCAL_REF_COUNT: Cell<u32> = const { Cell::new(0) };

    /// What this thread's asynchronous callback runs.
    ///
    /// A plain function pointer, because a closure would have to be boxed and
    /// then freed at a point where a foreign thread may still be about to call
    /// `uv_async_send` on the handle. The callback body reads thread-local
    /// state of its own, which is where the real work lives.
    static WAKE: Cell<Option<fn()>> = const { Cell::new(None) };

    /// Set by the close callback, so [`shutdown_current_thread`] can wait for it.
    static CLOSED: Cell<bool> = const { Cell::new(false) };

    /// How many wake callbacks this thread delivered. Tests read it.
    static DELIVERED: Cell<u64> = const { Cell::new(0) };
}

/// Identifies one thread's wake handle.
///
/// Opaque and `Copy` so it can be stored next to a queue entry and used from a
/// thread that does not own the handle. A token from a thread that has since
/// shut down is inert: [`ThreadToken::notify`] finds no handle and returns
/// `false` rather than calling into freed memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadToken(u64);

impl ThreadToken {
    /// Wakes the thread's loop, if it still has a handle.
    ///
    /// Returns whether a live handle was found. `false` is the ordinary race
    /// with a thread that has already exited; the message it was carrying stays
    /// in its queue, which is what makes it observable rather than lost.
    #[must_use]
    pub fn notify(self) -> bool {
        let Some(pointer) = handles()
            .lock()
            .ok()
            .and_then(|map| map.get(&self.0).copied())
        else {
            return false;
        };
        // SAFETY: the handle was inserted by `install_current_thread` and is
        // removed under the same lock before `uv_close` runs, so a pointer read
        // here is one libuv has not been told to close. `uv_async_send` is
        // documented as thread-safe.
        unsafe { uv::uv_async_send(pointer as *mut uv::uv_async_t) == 0 }
    }
}

/// The process-wide token-to-handle table.
///
/// A `Mutex<HashMap>` and not a thread-local because the whole point is that a
/// different thread reads it. Contended only when a message actually crosses a
/// thread boundary.
fn handles() -> &'static Mutex<HashMap<u64, usize>> {
    static HANDLES: OnceLock<Mutex<HashMap<u64, usize>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_token() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Creates this thread's wake handle and returns its token.
///
/// `wake` runs on this thread, from inside the loop, whenever another thread
/// signals the handle. It must not block: it is a libuv callback and every other
/// handle on the loop is waiting behind it.
///
/// Calling twice returns the same token and replaces `wake`, which is what lets
/// a re-installed realm on the same thread reuse the handle instead of leaking
/// one per incarnation.
pub fn install_current_thread(wake: fn()) -> Option<ThreadToken> {
    WAKE.with(|slot| slot.set(Some(wake)));
    let existing = LOCAL_TOKEN.with(Cell::get);
    if existing != 0 {
        return Some(ThreadToken(existing));
    }

    let loop_pointer = crate::uv_loop::loop_ptr()?;
    // Boxed and leaked: libuv requires the handle's address to stay put for as
    // long as it exists, and `shutdown_current_thread` is what frees it.
    let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_async_t>::zeroed());
    let pointer = storage.as_mut_ptr();
    // SAFETY: `pointer` is a live, aligned, zeroed slot and `loop_pointer` is
    // this thread's live loop.
    let status = unsafe { uv::uv_async_init(loop_pointer, pointer, Some(on_wake)) };
    if status != 0 {
        tracing::error!(
            status,
            "uv_async_init failed for the cross-thread wake handle"
        );
        return None;
    }
    // Never keeps the loop alive on its own: a loop whose only remaining work is
    // "some other thread might send us something" is exactly the state Node's
    // unref'd handles describe, and a ref'd handle here would make every worker
    // hang instead of exiting.
    unsafe { uv::uv_unref(pointer.cast()) };

    crate::ledger::record_created();
    let token = next_token();
    match handles().lock() {
        Ok(mut map) => {
            map.insert(token, pointer as usize);
        }
        Err(_) => return None,
    }
    // The handle must not be freed while the table holds its address, so the
    // allocation is released by `shutdown_current_thread`, which removes the
    // entry first.
    std::mem::forget(storage);
    LOCAL.with(|slot| slot.set(pointer as usize));
    LOCAL_TOKEN.with(|slot| slot.set(token));
    Some(ThreadToken(token))
}

/// This thread's token, if it registered one.
#[must_use]
pub fn current_thread_token() -> Option<ThreadToken> {
    match LOCAL_TOKEN.with(Cell::get) {
        0 => None,
        token => Some(ThreadToken(token)),
    }
}

/// Makes this thread's wake handle count as work, so its callback runs.
///
/// Balanced by [`release`]. Without the ref, `uv_loop_alive` is false while the
/// only reason to keep running is "another thread may signal us", and libuv then
/// reports the loop dead before dispatching the asynchronous callback that the
/// signal set up.
pub fn acquire() {
    let pointer = LOCAL.with(Cell::get);
    if pointer == 0 {
        return;
    }
    if LOCAL_REF_COUNT.with(|count| count.get()) == 0 {
        // SAFETY: the pointer came from `install_current_thread` and is live
        // until `shutdown_current_thread`.
        unsafe { uv::uv_ref(pointer as *mut uv::uv_handle_t) };
    }
    LOCAL_REF_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

/// Releases one [`acquire`], unref'ing the handle when the last one goes.
pub fn release() {
    let pointer = LOCAL.with(Cell::get);
    if pointer == 0 {
        return;
    }
    let remaining = LOCAL_REF_COUNT.with(|count| {
        let next = count.get().saturating_sub(1);
        count.set(next);
        next
    });
    if remaining == 0 {
        // SAFETY: as in `acquire`.
        unsafe { uv::uv_unref(pointer as *mut uv::uv_handle_t) };
    }
}

/// Closes this thread's wake handle and waits for libuv to finish with it.
///
/// Returns `true` when the thread had no handle or the handle is now fully
/// closed, so the loop can be closed afterwards. The handle is removed from the
/// table *before* `uv_close`, so no foreign thread can signal a handle libuv is
/// tearing down.
///
/// The wait is a bounded pump rather than a sleep loop: `uv_run` is what runs the
/// close callback, and it returns as soon as there is nothing left, so a normal
/// close costs one iteration. The bound exists so a stuck close fails instead of
/// hanging the process, and a failure is logged because the alternative is a
/// silently unclosable loop.
pub fn shutdown_current_thread() -> bool {
    let pointer = LOCAL.with(|slot| slot.replace(0));
    LOCAL_TOKEN.with(|slot| slot.set(0));
    WAKE.with(|slot| slot.set(None));
    if pointer == 0 {
        return true;
    }

    match handles().lock() {
        Ok(mut map) => map.retain(|_, handle| *handle != pointer),
        Err(_) => return false,
    }
    CLOSED.with(|cell| cell.set(false));
    // SAFETY: the pointer came from `install_current_thread`, has been removed
    // from the table so nothing new can signal it, and is still allocated.
    unsafe { uv::uv_close(pointer as *mut uv::uv_handle_t, Some(on_closed)) };

    if let Some(loop_pointer) = crate::uv_loop::loop_ptr() {
        for _ in 0..64 {
            if CLOSED.with(Cell::get) {
                break;
            }
            // SAFETY: `loop_pointer` is this thread's live loop; running it is
            // what delivers the close callback.
            unsafe { uv::uv_run(loop_pointer, uv::uv_run_mode_UV_RUN_NOWAIT) };
        }
    }
    if !CLOSED.with(Cell::get) {
        tracing::error!("the cross-thread wake handle did not close");
        return false;
    }
    // SAFETY: libuv has run the close callback, so it no longer references the
    // handle and the allocation can be reclaimed.
    drop(unsafe { Box::from_raw(pointer as *mut uv::uv_async_t) });
    true
}

/// How many threads currently have a wake handle.
///
/// Exposed for tests: a create/terminate loop that leaves this climbing has
/// leaked a handle per worker.
#[must_use]
pub fn live_handle_count() -> usize {
    handles().lock().map(|map| map.len()).unwrap_or(0)
}

/// A count of wake callbacks delivered on this thread.
///
/// Only tests read it; it is the cheapest way to prove a foreign thread really
/// woke this loop rather than the work being picked up by an unrelated timer.
#[must_use]
pub fn delivered_count() -> u64 {
    DELIVERED.with(Cell::get)
}

/// The libuv asynchronous callback.
///
/// # Safety
///
/// Called by libuv with the handle this module initialised.
unsafe extern "C" fn on_wake(_handle: *mut uv::uv_async_t) {
    DELIVERED.with(|cell| cell.set(cell.get().saturating_add(1)));
    if let Some(wake) = WAKE.with(Cell::get) {
        wake();
    }
}

/// The close callback.
///
/// # Safety
///
/// Called by libuv once the handle is closed; nothing is read from it.
unsafe extern "C" fn on_closed(_handle: *mut uv::uv_handle_t) {
    crate::ledger::record_closed();
    CLOSED.with(|cell| cell.set(true));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_gets_one_token_and_shutdown_leaves_no_handle_behind() {
        let before = live_handle_count();
        let first = install_current_thread(|| {}).expect("a handle for this test thread");
        let second = install_current_thread(|| {}).expect("the same handle again");
        assert_eq!(
            first, second,
            "installing twice must not leak a second handle"
        );
        assert_eq!(live_handle_count(), before + 1);
        assert!(shutdown_current_thread(), "the handle must close cleanly");
        assert_eq!(live_handle_count(), before);
        assert!(
            shutdown_current_thread(),
            "shutting down a thread with no handle is a no-op, not a failure"
        );
    }
}
