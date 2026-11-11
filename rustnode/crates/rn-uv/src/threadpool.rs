//! Cancelling and draining libuv's threadpool before the process image unloads.
//!
//! # The crash this exists for
//!
//! `process.exit()` terminates by running the C runtime's exit sequence:
//! `atexit` handlers first, then the `.fini_array` destructors. OpenSSL
//! registers `OPENSSL_cleanup` with `atexit`, and that handler frees process-wide
//! state — `err_string_lock` among it (`crypto/err/err.c::err_cleanup`). libuv
//! registers `uv_library_shutdown` as a *destructor*, which runs *after* a
//! `atexit` handler registered earlier, so its worker-join happens too late.
//!
//! A pool thread still inside `EVP_PKEY_keygen` therefore touches OpenSSL after
//! `OPENSSL_cleanup` has freed it. Two outcomes were measured, and the second is
//! what makes this bug deceptive:
//!
//! * it dies on a `CRYPTO_THREAD_unlock` of a lock that is no longer there —
//!   the `libuv-worker` SIGSEGV `test-crypto-keygen-bit-length.js` reports;
//! * or the keygen's next OpenSSL call fails against the same freed state, so the
//!   job *returns an error in a few milliseconds* instead of running to
//!   completion. That is why `process.exit()` used to look prompt while an RSA
//!   16384 keygen (25–68 s of real work) was in flight: the work was not finishing
//!   quickly, it was being cut short by the corrupted state.
//!
//! Moving the join earlier makes the in-flight job finish **normally**, so the
//! exit now waits for one real job where it used to wait for a failing one. That
//! is also what Node does: `Environment::ExitEnv` stops the threadpool the same
//! way, and a `node` process on the same script waits the whole keygen.
//!
//! # Why this is a drain and not a wait
//!
//! Node's `Environment::ExitEnv` (`src/api/environment.cc`) calls
//! `uv_library_shutdown()` before `DisposePlatform()` and before `exit()`.
//! `uv_library_shutdown` posts the pool's exit message, so each worker finishes
//! **the one item it is holding** and then leaves. Requests still sitting in the
//! queue are dropped rather than run, which is why [`drain`] calls `uv_cancel`
//! first: libuv's exit message is posted at the tail, so a deep queue would
//! otherwise be executed in full.
//!
//! So the cost of exiting is one in-flight item, not the whole backlog: 256
//! queued RSA-4096 keygens, 25 s of work if run, exit in ~0.6 s. A pending
//! `setTimeout` or an unfinished socket write is not threadpool work and is
//! unaffected: it is discarded, exactly as `uv_library_shutdown` discards a
//! queued request.
//!
//! # Why the work is registered here
//!
//! `uv_cancel` needs the request address, and the crates that queue work own
//! theirs (`rn-bind-crypto-keys` allocates a `uv_work_t` per job, `rn-napi` one
//! per `napi_async_work`, `rn-bind-fs` one per file job). This module is the
//! shared set of live request addresses so the exit path can reach all of them
//! without the bindings depending on each other. Registration is a plain address,
//! because that is the identity libuv hands back in the callbacks.
//!
//! Only `uv_queue_work` requests are tracked. libuv's other threadpool entry
//! points — `uv_fs_*`, `uv_getaddrinfo`, `uv_random` — are not used directly by
//! this workspace: file work is queued through `uv_queue_work` in `rn-bind-fs`,
//! so it is covered here too, and a future direct call would need its own
//! registration rather than being silently missed.

use std::sync::Mutex;
use std::sync::OnceLock;

use libuv_sys2 as uv;

/// The `uv_work_t` addresses currently owned by libuv.
///
/// A `Mutex` rather than a thread-local: [`drain`] runs on the exiting thread
/// while a worker may be finishing, and the after-work callback that unregisters
/// an entry runs from `uv_run` on the loop's thread. Neither is the other.
static IN_FLIGHT: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

/// Whether [`drain`] has already run.
///
/// `uv_library_shutdown` is idempotent itself, but cancelling a request twice
/// would be a second `uv_cancel` on memory the first one released, so the whole
/// sequence is once-only.
static DRAINED: OnceLock<()> = OnceLock::new();

fn in_flight() -> &'static Mutex<Vec<usize>> {
    IN_FLIGHT.get_or_init(|| Mutex::new(Vec::new()))
}

/// Records a request that libuv now owns.
///
/// The caller must call [`unregister`] from the after-work callback, which is the
/// point libuv has finished with the request.
pub fn register(request: *mut uv::uv_work_t) {
    if request.is_null() {
        return;
    }
    let mut list = match in_flight().lock() {
        Ok(list) => list,
        // A poisoned lock means a registration panicked while holding it. The
        // addresses already recorded are still valid, so recovering is better
        // than losing them and crashing at exit.
        Err(poisoned) => poisoned.into_inner(),
    };
    list.push(request as usize);
}

/// Forgets a request the after-work callback has released.
pub fn unregister(request: *mut uv::uv_work_t) {
    if request.is_null() {
        return;
    }
    let address = request as usize;
    let mut list = match in_flight().lock() {
        Ok(list) => list,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(index) = list.iter().position(|entry| *entry == address) {
        list.swap_remove(index);
    }
}

/// Cancels queued work, joins the pool's threads, and lets libuv be unloaded.
///
/// Safe to call more than once and safe when the pool was never started: both
/// `uv_cancel` (no registered request) and `uv_library_shutdown` (a pool it never
/// created) are no-ops in that case. After this returns, no libuv worker thread
/// is running, so the `atexit` handlers and destructors that follow cannot race
/// one.
///
/// # What this blocks on, and what it does not
///
/// The wait is bounded by the requests that are *already executing*, because
/// `uv_cancel` cannot interrupt those and `uv_library_shutdown` posts its exit
/// message after them. Queued requests are cancelled and never run, so a backlog
/// adds nothing. Anything that is not threadpool work — a pending timer, a socket
/// write, an unref'd handle — is not waited for at all.
///
/// The remaining cost is real and worth stating: a threadpool job that never
/// returns (a read of a FIFO nobody writes, say) will keep exit waiting, because
/// the worker cannot be interrupted. Node has exactly the same behaviour for the
/// same reason; the alternative is unloading code a worker is still executing.
pub fn drain() {
    if DRAINED.set(()).is_err() {
        return;
    }

    // Copied out and dropped before cancelling: `uv_cancel` takes libuv's own
    // pool mutex, and holding this one across it would invert the lock order
    // against a worker finishing at the same time.
    let requests: Vec<usize> = {
        let mut list = match in_flight().lock() {
            Ok(list) => list,
            Err(poisoned) => poisoned.into_inner(),
        };
        std::mem::take(&mut *list)
    };

    for address in requests {
        // SAFETY: the address was registered by a caller that owned a live
        // `uv_work_t`, and libuv keeps a request valid until its after-work
        // callback runs. `uv_cancel` only reads the request header, and returns
        // `UV_EBUSY` for work already executing, which is the case that cannot
        // be interrupted.
        unsafe { uv::uv_cancel(address as *mut uv::uv_req_t) };
    }

    // SAFETY: calls libuv's own process-wide teardown. It is a destructor in
    // libuv, so the runtime would call it later anyway; doing it here is what
    // puts the join before OpenSSL's `atexit` cleanup instead of after it. The
    // internal `was_shutdown` latch makes the later destructor call a no-op.
    unsafe { uv::uv_library_shutdown() };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request is remembered until its completion, so the exit path can reach
    /// it, and forgotten afterwards so a recycled address is not cancelled.
    #[test]
    fn a_registered_request_is_tracked_until_unregistered() {
        let mut request: uv::uv_work_t = unsafe { std::mem::zeroed() };
        let pointer = &mut request as *mut uv::uv_work_t;

        let before = list_snapshot();
        register(pointer);
        assert_eq!(
            list_snapshot().len(),
            before.len() + 1,
            "registering must add the address the exit path will cancel"
        );
        assert!(list_snapshot().contains(&(pointer as usize)));

        unregister(pointer);
        assert_eq!(
            list_snapshot().len(),
            before.len(),
            "the completion must release the entry"
        );
        assert!(!list_snapshot().contains(&(pointer as usize)));
    }

    /// Unregistering something that is not there is not an error: the completion
    /// for a request cancelled at exit never runs, and a second delivery would be
    /// libuv's bug rather than a reason to panic in a callback.
    #[test]
    fn unregistering_an_unknown_address_is_a_no_op() {
        let mut request: uv::uv_work_t = unsafe { std::mem::zeroed() };
        let pointer = &mut request as *mut uv::uv_work_t;
        let before = list_snapshot();
        unregister(pointer);
        assert_eq!(list_snapshot().len(), before.len());
    }

    fn list_snapshot() -> Vec<usize> {
        match in_flight().lock() {
            Ok(list) => list.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}
