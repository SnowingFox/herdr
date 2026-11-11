//! `napi_async_work`: work that runs on libuv's thread pool.
//!
//! `napi_create_async_work` takes two C callbacks. `execute` runs on a pool
//! thread and must not touch JavaScript; `complete` runs back on the loop's
//! thread with a `napi_status` saying how the work ended. Node builds this out of
//! `node::ThreadPoolWork`, which is a thin wrapper over `uv_queue_work`, so the
//! ordering Node's tests observe — execute on some thread, complete on the loop,
//! `napi_cancelled` when the request never ran — is libuv's ordering.
//!
//! # Why there is a real thread pool
//!
//! `crates/rn-uv` links `libuv-sys2`, which compiles libuv's own `threadpool.c`,
//! so `uv_queue_work`, `uv_cancel` and the `wq_async` completion handle all
//! exist in this runtime. Nothing here emulates them: `execute` really does run
//! on a pool thread, and `complete` really is delivered from a later loop
//! iteration. `test_uv_threadpool_size` depends on the pool being finite and
//! shared, so a synchronous stand-in would fail it rather than approximate it.
//!
//! # Who owns the allocation
//!
//! One [`AsyncWork`] per `napi_async_work`, owned by the addon between
//! `napi_create_async_work` and `napi_delete_async_work`, exactly as Node's
//! `new uvimpl::Work` / `delete` pair. The `uv_work_t` lives *inside* that
//! allocation, so a queued request's address is stable for as long as libuv may
//! touch it.
//!
//! The completion callback runs while the request is still on the loop, and the
//! addon's `complete` is allowed to call `napi_delete_async_work` — Node's own
//! `test_async` does exactly that — so the completion path never reads the
//! allocation after invoking the addon. It copies what it needs first.

use std::ffi::c_void;

use libuv_sys2 as uv;

use crate::abi::{
    NapiAsyncCompleteCallback, NapiAsyncExecuteCallback, NapiAsyncWork, NapiEnv, NapiStatus,
};

/// One queued or completed `napi_async_work`.
///
/// The `uv_work_t` is the first field so a `*mut uv_work_t` handed to libuv and
/// the `*mut AsyncWork` the addon holds are the same address. That is what
/// `libuv`'s `data` field is not used for: `uv_work_t::data` carries the
/// allocation too, because the alternative — trusting that the addon's
/// `napi_async_work` is still valid inside the pool callback — is the same
/// address computed twice, and reading it once from libuv's own field keeps the
/// two in step even if the addon ever passes a `napi_async_work` it did not
/// create (which Node would crash on, and so does this).
#[repr(C)]
pub struct AsyncWork {
    request: uv::uv_work_t,
    /// The environment the addon created this work against.
    ///
    /// `Env` is leaked by `load`, so a pointer to it stays valid for the life of
    /// the process. The pool thread only carries it; nothing dereferences it off
    /// the loop's thread.
    env: *mut NapiEnv,
    execute: NapiAsyncExecuteCallback,
    complete: NapiAsyncCompleteCallback,
    /// The addon's own `void* data`, handed to both callbacks unchanged.
    data: *mut c_void,
    /// Whether `napi_queue_async_work` has been called and no completion has run.
    ///
    /// Only the loop's thread mutates it, so a plain `bool` behind the loop's
    /// single-threaded access is enough. It is what makes `napi_queue_async_work`
    /// on an already-queued work an error instead of a second `uv_queue_work` on
    /// a request libuv is still using.
    queued: bool,
}

// SAFETY: the allocation is created and destroyed on the loop's thread, and the
// only pointer that crosses a thread boundary is the `uv_work_t` address, which
// libuv hands to its own pool. The callbacks carry `env`, `execute`, `complete`
// and `data` unchanged and are invoked by libuv on the thread it chooses, which
// is the contract Node-API states for them.
unsafe impl Send for AsyncWork {}
// SAFETY: as above; the type is shared with libuv, not between JavaScript calls.
unsafe impl Sync for AsyncWork {}

impl AsyncWork {
    /// Allocates a work item. The caller owns the returned pointer until
    /// [`delete`].
    pub(crate) fn new(
        env: *mut NapiEnv,
        execute: NapiAsyncExecuteCallback,
        complete: NapiAsyncCompleteCallback,
        data: *mut c_void,
    ) -> *mut Self {
        let mut work = Box::new(Self {
            // SAFETY: `uv_work_t` is a plain-old-data struct of pointers and
            // integers, for which an all-zero value is libuv's own "not
            // initialised yet" state; `uv_queue_work` fills it in.
            request: unsafe { std::mem::zeroed() },
            env,
            execute,
            complete,
            data,
            queued: false,
        });
        let pointer = work.as_mut() as *mut Self;
        // libuv's completion path reads `data` to find the allocation; storing it
        // here rather than recomputing the address in the callback keeps the two
        // in step if the layout ever changes.
        work.request.data = pointer.cast();
        Box::into_raw(work)
    }

    /// Queues the work on the loop's thread pool.
    ///
    /// Returns `Err` with the libuv error code on failure, which the shim turns
    /// into a `napi_status`.
    pub(crate) fn queue(&mut self, loop_pointer: *mut uv::uv_loop_t) -> Result<(), i32> {
        if self.queued {
            // libuv would overwrite the request's queue node while a pool thread
            // is using it. Node does not guard this, but Node also never reaches
            // it: `napi_queue_async_work` on queued work is a caller bug either
            // way, and reporting it beats corrupting the pool's queue.
            return Err(uv::uv_errno_t_UV_EINVAL);
        }
        self.queued = true;
        let request = &mut self.request as *mut uv::uv_work_t;
        // SAFETY: `request` is the live, zeroed struct inside this allocation and
        // `loop_pointer` is the process' loop. The callbacks are this module's
        // own trampolines, and libuv copies both out of the request before it
        // returns.
        let status = unsafe {
            uv::uv_queue_work(loop_pointer, request, Some(on_execute), Some(on_complete))
        };
        if status != 0 {
            self.queued = false;
            return Err(status);
        }
        Ok(())
    }

    /// Cancels a queued request if the pool has not started it.
    ///
    /// Returns libuv's error code: `UV_EBUSY` when the work is already running,
    /// `UV_EINVAL` when it is not queued at all. A successful cancel still
    /// delivers `complete` — with `napi_cancelled` — from the loop, which is what
    /// `test_async`'s `TestCancel` waits for.
    pub(crate) fn cancel(&mut self) -> i32 {
        if !self.queued {
            return uv::uv_errno_t_UV_EINVAL;
        }
        let request = &mut self.request as *mut uv::uv_work_t;
        // SAFETY: `request` is live and `uv_cancel` reads only its `type` and
        // `loop` fields, which `uv_queue_work` filled in.
        unsafe { uv::uv_cancel(request.cast::<uv::uv_req_t>()) }
    }

    /// Frees an allocation the addon no longer needs.
    ///
    /// # Safety
    ///
    /// `pointer` must come from [`AsyncWork::new`] and must not still be queued:
    /// libuv owns the request until the completion callback has run.
    pub(crate) unsafe fn delete(pointer: *mut Self) {
        if pointer.is_null() {
            return;
        }
        // SAFETY: the caller guarantees the pointer came from `new` and is not
        // queued, so no pool thread and no loop callback still references it.
        drop(unsafe { Box::from_raw(pointer) });
    }
}

/// `uv_work_cb`: runs on a thread-pool thread.
///
/// # Safety
///
/// Called by libuv with the `uv_work_t` embedded in a live [`AsyncWork`].
unsafe extern "C" fn on_execute(request: *mut uv::uv_work_t) {
    if request.is_null() {
        return;
    }
    // SAFETY: the request is the first field of an `AsyncWork` this module
    // allocated, and the allocation lives until the addon deletes it after the
    // completion callback has run.
    let work = unsafe { &*request.cast::<AsyncWork>() };
    let Some(execute) = work.execute else {
        return;
    };
    // SAFETY: `execute` is the addon's own callback, and Node-API defines it as
    // receiving the `napi_env` and `void* data` it was created with. It must not
    // touch JavaScript; that is the addon's contract, not something this side can
    // enforce.
    unsafe { execute(work.env, work.data) };
}

/// `uv_after_work_cb`: runs back on the loop's thread.
///
/// # Safety
///
/// Called by libuv with the `uv_work_t` embedded in a live [`AsyncWork`].
unsafe extern "C" fn on_complete(request: *mut uv::uv_work_t, status: i32) {
    if request.is_null() {
        return;
    }
    // SAFETY: as in `on_execute`; the request is still embedded in the live
    // allocation.
    let work = unsafe { &mut *request.cast::<AsyncWork>() };
    // Cleared before the addon runs: Node's completion callbacks routinely call
    // `napi_delete_async_work` from inside `complete`, and `test_async` does.
    // Nothing below may touch `work` after the addon has been called.
    work.queued = false;
    let Some(complete) = work.complete else {
        return;
    };
    let env = work.env;
    let data = work.data;
    let work_status = convert_uv_status(status);

    // JavaScript runs inside `complete`, so it needs the isolate and a context,
    // which a libuv callback does not have. `with_context` is the same re-entry
    // every other binding uses for a completion.
    let delivered = crate::scope::with_context(|scope| {
        let guard = crate::scope::ScopeGuard::enter(scope);
        // SAFETY: `complete` is the addon's own callback and `env` is the
        // environment it was created against, which `load` leaks so it outlives
        // every callback. The scope guard is alive for the whole call, so any
        // `napi_value`s the addon creates there are valid.
        unsafe { complete(env, work_status, data) };
        drop(guard);
    });
    if delivered.is_none() {
        // No recorded context means no addon has been installed into an isolate
        // yet, which cannot happen for work an addon created. Reporting it is
        // better than dropping the completion silently.
        tracing::error!(
            "an async work completion fired with no V8 context recorded; \
             the addon's complete callback was not run"
        );
    }
}

/// libuv's completion code as the `napi_status` an addon's `complete` expects.
///
/// `uv__work_done` reports `UV_ECANCELED` for a request `uv_cancel` removed
/// before a pool thread started it, and 0 for one that ran. Node's
/// `ConvertUVErrorCode` maps exactly those two, plus `EINVAL`, and everything
/// else to `napi_generic_failure`.
fn convert_uv_status(status: i32) -> NapiStatus {
    match status {
        0 => NapiStatus::Ok,
        uv::uv_errno_t_UV_EINVAL => NapiStatus::InvalidArg,
        uv::uv_errno_t_UV_ECANCELED => NapiStatus::Cancelled,
        _ => NapiStatus::GenericFailure,
    }
}

/// The `napi_async_work` an addon holds, as the `uv_work_t` it points at.
///
/// # Safety
///
/// `work` must be a pointer this module returned from [`AsyncWork::new`].
pub(crate) unsafe fn delete_work(work: *mut NapiAsyncWork) {
    // SAFETY: the caller guarantees the pointer came from `napi_create_async_work`,
    // which allocates an `AsyncWork`.
    unsafe { AsyncWork::delete(work.cast::<AsyncWork>()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libuv_completion_codes_map_to_the_statuses_an_addon_compares() {
        // `test_async`'s `CancelComplete` only calls back when status is exactly
        // `napi_cancelled`, so this mapping is the difference between that test
        // passing and it hanging.
        assert_eq!(convert_uv_status(0), NapiStatus::Ok);
        assert_eq!(
            convert_uv_status(uv::uv_errno_t_UV_EINVAL),
            NapiStatus::InvalidArg
        );
        assert_eq!(
            convert_uv_status(uv::uv_errno_t_UV_ECANCELED),
            NapiStatus::Cancelled
        );
        assert_eq!(convert_uv_status(-1), NapiStatus::GenericFailure);
    }

    #[test]
    fn the_uv_request_is_the_first_field_so_one_address_serves_both() {
        // libuv only ever sees the `uv_work_t`, and the callbacks recover the
        // allocation by casting that address back. If the field moved, every
        // callback would read the wrong memory.
        assert_eq!(std::mem::offset_of!(AsyncWork, request), 0);
    }

    #[test]
    fn an_unset_request_reports_einval_rather_than_queueing() {
        // `uv_cancel` on a request that was never queued is `UV_EINVAL` in libuv.
        // Reaching `uv_work_work`'s queue for a request no pool thread owns would
        // be the same answer through a longer path.
        let mut work = Box::new(AsyncWork {
            // SAFETY: zeroed is libuv's own uninitialised state for this struct.
            request: unsafe { std::mem::zeroed() },
            env: std::ptr::null_mut(),
            execute: None,
            complete: None,
            data: std::ptr::null_mut(),
            queued: false,
        });
        assert_eq!(work.cancel(), uv::uv_errno_t_UV_EINVAL);
    }
}
