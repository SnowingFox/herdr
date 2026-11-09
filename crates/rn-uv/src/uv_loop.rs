//! The libuv event loop a rustnode process runs on.
//!
//! `lib/net.js` and `lib/internal/stream_base_commons.js` are unchanged Node
//! code, and they expect a real libuv loop underneath: a write queues behind
//! earlier writes on the same handle, a read delivers `UV_EOF` rather than a
//! zero length, and `ref()`/`unref()` decide whether the process is still alive.
//! Reimplementing that on top of blocking syscalls would reproduce the
//! signatures and none of the ordering, so this crate links libuv itself
//! (`libuv-sys2`, which compiles the library from the source it vendors) and
//! owns the one loop the process has.
//!
//! # Two owners of one loop
//!
//! The loop here is created on first use by whichever binding needs it, and is
//! run by the CLI at the end of a script. The event-loop workstream owns
//! scheduling decisions (timers, `process.nextTick`, when to block versus spin),
//! so this crate deliberately keeps only what a *handle* needs:
//!
//! * a place to register a JS callback and get it called back on the loop
//!   thread,
//! * [`run`] / [`run_once`] so the owner can drive the loop, and
//! * [`loop_ptr`] for code that needs to hand libuv a loop.
//!
//! Nothing here decides *when* to call [`run`]; that is the integration point
//! documented on [`run`].
//!
//! # Why callbacks go through a `Global`
//!
//! A libuv completion fires from inside `uv_run`, which is a plain Rust call,
//! not inside a V8 callback scope. The isolate is not re-entrant from there
//! without telling V8 first. Every callback this crate registers therefore runs
//! inside [`crate::CallbackScope`], which enters the isolate, opens a handle
//! scope and a context scope, and only then touches JavaScript.

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr;

use libuv_sys2 as uv;

/// Size of the buffer libuv is told to fill for a read, when it does not have a
/// better idea.
///
/// Node's `Environment::stream_read_slab()` grows on demand and recycles slabs
/// between reads. rustnode allocates per read (`uv::uv_read_start`'s `alloc_cb`
/// contract requires it), and this is the size handed to libuv when its own
/// suggestion is unusable.
pub const READ_SLAB_SIZE: usize = 64 * 1024;

thread_local! {
    /// The process' loop, created on first use.
    ///
    /// A `Box` keeps the address stable for the life of the process, which
    /// matters because libuv stores pointers into the loop and handles store a
    /// pointer back to it.
    static LOOP: RefCell<Option<LoopHandle>> = const { RefCell::new(None) };

    /// Whether [`with_loop`] is currently inside its closure.
    ///
    /// `uv_run` can call back into JavaScript, and that JavaScript can call
    /// back into a binding that wants the loop, so the loop cannot be borrowed
    /// mutably across a run. This guard is what lets the reentrant path get at
    /// the pointer without a second `RefCell` borrow.
    static IN_LOOP: RefCell<bool> = const { RefCell::new(false) };
}

/// The loop pointer plus everything that has to be dropped with it.
struct LoopHandle {
    pointer: *mut uv::uv_loop_t,
}

// SAFETY: the loop is only ever touched from the thread that created it, which
// is the isolate's thread; `LOOP` is thread-local for that reason, and the
// raw pointer never crosses a thread boundary.
impl LoopHandle {
    fn create() -> Option<Self> {
        // The loop lives in a `Box` for the whole process, so a `MaybeUninit`
        // plus `Box` gives a stable, aligned address without a second
        // allocation after init.
        let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_loop_t>::zeroed());
        // SAFETY: `storage` is a live, aligned, zeroed `uv_loop_t`; `uv_loop_init`
        // initialises it in place and returns a libuv error code on failure.
        let status = unsafe { uv::uv_loop_init(storage.as_mut_ptr()) };
        if status != 0 {
            tracing::error!(status, "uv_loop_init failed");
            return None;
        }
        // SAFETY: `uv_loop_init` succeeded, so the value is initialised.
        let mut boxed = unsafe { Box::from_raw(Box::into_raw(storage).cast::<uv::uv_loop_t>()) };
        let pointer = boxed.as_mut() as *mut uv::uv_loop_t;
        std::mem::forget(boxed);
        Some(Self { pointer })
    }
}

/// Runs `body` with the process' loop, creating it on first use.
///
/// Returns `None` when the loop could not be created, which is the only
/// failure mode: `uv_loop_init` failing means the process cannot do I/O at all.
pub fn with_loop<R>(body: impl FnOnce(*mut uv::uv_loop_t) -> R) -> Option<R> {
    LOOP.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = LoopHandle::create();
        }
        let handle = slot.as_ref()?;
        Some(body(handle.pointer))
    })
}

/// The process' loop pointer, creating the loop if it does not exist.
///
/// This is the entry point for code that needs to hand a loop to libuv, for
/// example a `uv_*_init` call. Prefer [`with_loop`] when the pointer is only
/// needed for the duration of a call: this does not keep the loop alive.
pub fn loop_ptr() -> Option<*mut uv::uv_loop_t> {
    with_loop(|pointer| pointer)
}

/// Whether the loop has been created yet.
pub fn is_initialised() -> bool {
    LOOP.with(|cell| cell.borrow().is_some())
}

/// One step of the loop, without blocking.
///
/// Returns `true` when the loop still has referenced work pending. This is the
/// blocking-free variant an embedding runtime uses between tasks; [`run`] is the
/// one that blocks.
pub fn run_once() -> bool {
    run_inner(uv::uv_run_mode_UV_RUN_NOWAIT)
}

/// Runs the loop until it has no referenced handles or requests left.
///
/// # Integration point
///
/// This function *is* the interface the event-loop workstream needs: it drives
/// libuv to completion and returns `true` if the loop still had work (which
/// only happens when every remaining handle is unreferenced, matching
/// `uv_run`'s own return value). A CLI that grows a real scheduler should call
/// [`run_once`] from its own tick loop rather than [`run`], because `run` blocks
/// until the process has nothing to do — which is right for "run the script to
/// completion" and wrong once timers and `process.nextTick` share the turn.
///
/// Timers are the one thing this crate does not own. `uv_run` handles them, but
/// nothing here arms them: `setTimeout` needs `rn-bind-timers` and the
/// `process.nextTick` queue to be connected to this loop, which is the loop
/// workstream's job.
pub fn run() -> bool {
    run_inner(uv::uv_run_mode_UV_RUN_DEFAULT)
}

fn run_inner(mode: uv::uv_run_mode) -> bool {
    let entered = IN_LOOP.with(|flag| {
        let mut flag = flag.borrow_mut();
        if *flag {
            false
        } else {
            *flag = true;
            true
        }
    });
    // A nested `uv_run` would re-enter libuv on a loop that is already running,
    // which libuv does not support. The outer run will pick up whatever work
    // the nested caller queued, so returning "still busy" is correct.
    if !entered {
        return true;
    }

    let Some(pointer) = loop_ptr() else {
        IN_LOOP.with(|flag| *flag.borrow_mut() = false);
        return false;
    };
    // SAFETY: the pointer came from `loop_ptr`, which owns the loop for the
    // process, and `IN_LOOP` guarantees no other `uv_run` is active.
    let remaining = unsafe { uv::uv_run(pointer, mode) };
    IN_LOOP.with(|flag| *flag.borrow_mut() = false);
    remaining != 0
}

/// Whether libuv considers the loop to have referenced work.
pub fn is_active() -> bool {
    let Some(pointer) = loop_ptr() else {
        return false;
    };
    // SAFETY: `pointer` is the process' live loop.
    unsafe { uv::uv_loop_alive(pointer) != 0 }
}

/// Whether the loop has no referenced work left.
///
/// Exposed for tests that need a bounded pump rather than a blocking run, so a
/// callback that never completes fails an assertion instead of hanging the suite.
pub fn is_idle_for_test() -> bool {
    !is_active()
}

/// Asks a running loop to return from `uv_run` as soon as it can.
pub fn stop() {
    let Some(pointer) = loop_ptr() else {
        return;
    };
    // SAFETY: `pointer` is the process' live loop.
    unsafe { uv::uv_stop(pointer) };
}

/// Closes every handle on the loop and releases it.
///
/// Called when a process is shutting down deliberately. Any handle still open
/// is closed first, because `uv_loop_close` refuses to release a loop that
/// still owns handles.
pub fn shutdown() -> bool {
    let Some(pointer) = loop_ptr() else {
        return true;
    };

    // Walking `closing_handles` directly would race with libuv's own state; the
    // documented way to drain is to let libuv run until nothing is left, then
    // close. Handles that are still open keep the loop alive, so stop them via
    // `uv_walk` and close each one.
    // SAFETY: `pointer` is the process' live loop, and `close_walked_handle`
    // only calls `uv_close` on handles libuv handed to it.
    unsafe {
        uv::uv_walk(pointer, Some(close_walked_handle), ptr::null_mut());
        uv::uv_run(pointer, uv::uv_run_mode_UV_RUN_DEFAULT);
        let status = uv::uv_loop_close(pointer);
        status == 0
    }
}

/// `uv_walk` callback used by [`shutdown`].
unsafe extern "C" fn close_walked_handle(handle: *mut uv::uv_handle_t, _arg: *mut c_void) {
    if handle.is_null() {
        return;
    }
    // SAFETY: libuv passes a live handle. A handle that is already closing must
    // not be closed twice, which is what `uv_is_closing` checks.
    if unsafe { uv::uv_is_closing(handle) } == 0 {
        // SAFETY: as above; a null `close_cb` asks libuv to just release it.
        unsafe { uv::uv_close(handle, None) };
    }
}

/// Reads `handle->data`, the pointer libuv carries back to its owner.
///
/// # Safety
///
/// `handle` must be a live libuv handle that this crate initialised, so that
/// `data` holds the pointer its owner stored there.
pub unsafe fn handle_data<T>(handle: *mut uv::uv_handle_t) -> Option<*mut T> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `handle` is live.
    let data = unsafe { (*handle).data };
    if data.is_null() {
        None
    } else {
        Some(data.cast::<T>())
    }
}

/// Stores an owner pointer in a handle so libuv callbacks can find it.
///
/// # Safety
///
/// `handle` must be a live libuv handle and `data` must stay valid (and be a
/// `Box`'s allocation, or otherwise outlive the close callback) for as long as
/// libuv may call back on it.
pub unsafe fn set_handle_data<T>(handle: *mut uv::uv_handle_t, data: *mut T) {
    if !handle.is_null() {
        // SAFETY: the caller guarantees `handle` is live.
        unsafe { (*handle).data = data.cast::<c_void>() };
    }
}

/// An owned libuv buffer allocation handed to JS as an `ArrayBuffer`.
///
/// libuv's `alloc_cb` must produce storage that stays valid until the matching
/// `read_cb`, and Node then hands that same memory to JavaScript without
/// copying. This wraps the allocation so the `read_cb` side can build an
/// `ArrayBuffer` over it and let V8 own the free.
pub struct ReadBuffer {
    pointer: *mut u8,
    length: usize,
}

impl ReadBuffer {
    /// Allocates at least `suggested` bytes.
    ///
    /// Returns `None` only when the allocation failed, which libuv reports by
    /// receiving a zero-length buffer.
    pub fn new(suggested: usize) -> Option<Self> {
        let length = if suggested == 0 {
            READ_SLAB_SIZE
        } else {
            suggested
        };
        // SAFETY: `alloc` with a non-zero size and byte alignment is always a
        // valid call; the result is checked for null.
        let pointer =
            unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align(length, 8).ok()?) };
        if pointer.is_null() {
            return None;
        }
        Some(Self { pointer, length })
    }

    /// The allocation's address, as libuv's `uv_buf_t.base` wants it.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.pointer
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl Drop for ReadBuffer {
    fn drop(&mut self) {
        if self.pointer.is_null() {
            return;
        }
        // SAFETY: `new` allocated this pointer with the layout below and
        // nothing else frees it.
        unsafe {
            std::alloc::dealloc(
                self.pointer,
                std::alloc::Layout::from_size_align_unchecked(self.length, 8),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loop exists on demand and survives repeated lookups with the same
    /// address, which is what makes `handle->loop` pointers stay valid.
    #[test]
    fn the_loop_is_created_once_and_keeps_its_address() {
        let first = loop_ptr().expect("the loop must be creatable");
        let second = loop_ptr().expect("the loop must still be creatable");
        assert_eq!(first, second);
        assert!(is_initialised());
    }

    /// An idle loop has nothing to do, so a non-blocking run reports no work
    /// and returns immediately.
    #[test]
    fn an_idle_loop_has_no_work() {
        assert!(!run_once());
        assert!(!is_active());
    }
}
