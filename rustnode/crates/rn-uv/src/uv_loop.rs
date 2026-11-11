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
//! # One loop, one owner
//!
//! Every asynchronous handle in rustnode — `tcp_wrap`, `udp_wrap`, `pipe_wrap`,
//! `process_wrap`, `tty_wrap`, and the scheduler's own timer, check and idle
//! handles — hangs off this loop. [`run_once`] advances it by the amount libuv
//! itself decides, which is the only way the phases a JavaScript timer sees are
//! the phases Node's timer sees.
//!
//! A second, `poll(2)`-based loop in `rn-io` used to sit beside this one and was
//! the only loop anything pumped. That is gone: `rn-io` now drives *this* loop,
//! and it does not own a readiness primitive of its own.
//!
//! # Why a keep-alive descriptor exists
//!
//! `uv__io_poll` returns immediately when the loop watches no file descriptor
//! (`loop->nfds == 0`), so a loop with only a timer armed would spin at 100% CPU
//! instead of sleeping until the deadline. Node avoids that by keeping an
//! unreferenced `uv_async_t` for child-process notifications: the async
//! watcher's descriptor gives the backend something to wait on, while the
//! handle's `unref` keeps it from counting as work. [`LoopHandle::create`]
//! creates the same handle for the same reason. Without it `setTimeout(f, 2000)`
//! would burn two seconds of CPU rather than sleep for two seconds.
//!
//! # Why callbacks go through a `Global`
//!
//! A libuv completion fires from inside `uv_run`, which is a plain Rust call,
//! not inside a V8 callback scope. The isolate is not re-entrant from there
//! without telling V8 first. Every callback this crate registers therefore runs
//! inside [`with_context`], which enters the isolate, opens a handle scope and a
//! context scope, and only then touches JavaScript.

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

thread_local! {
    /// Whether [`shutdown`] is running on this thread.
    ///
    /// Guards against the re-entrancy described there: close callbacks run
    /// JavaScript, and that JavaScript can ask for the same teardown.
    static SHUTTING_DOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Clears [`SHUTTING_DOWN`] when the shutdown it guards ends, however it ends.
struct ShutdownGuard;

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        SHUTTING_DOWN.with(|flag| flag.set(false));
    }
}

/// The loop pointer plus everything that has to be dropped with it.
struct LoopHandle {
    pointer: *mut uv::uv_loop_t,
    /// The unreferenced async handle that gives the backend a descriptor.
    ///
    /// Never signalled: it exists so `uv__io_poll` can sleep instead of
    /// returning at once on a loop with no watchers. See the module docs.
    keepalive: *mut uv::uv_async_t,
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
        let keepalive = create_keepalive(pointer)?;
        crate::ledger::record_created();
        Some(Self { pointer, keepalive })
    }
}

/// Releases the loop and its storage.
///
/// The struct is only ever stored in the thread-local `LOOP`, so this runs when
/// that thread is torn down — which for a worker is one per `new Worker()`. Before
/// this existed every worker leaked its whole `uv_loop_t` plus the keepalive
/// handle, which is a leak a create/terminate loop shows as steadily growing RSS.
///
/// The handles themselves are closed by [`close_loop`] before this runs; a handle
/// still open here means `close_loop` reported failure, and the loop is dropped
/// anyway because the thread is ending. That case is logged rather than hidden.
impl Drop for LoopHandle {
    fn drop(&mut self) {
        // SAFETY: `pointer` came from the `Box` `create` leaked, and nothing else
        // owns it. The keepalive handle was allocated the same way.
        unsafe {
            if !self.keepalive.is_null() {
                drop(Box::from_raw(self.keepalive));
            }
            drop(Box::from_raw(self.pointer));
        }
    }
}

/// Creates the unreferenced async handle that lets the backend sleep.
///
/// `uv_async_init` also registers the async watcher's descriptor, which is the
/// only thing that stops `uv__io_poll` from returning immediately. The handle is
/// started by `uv_async_init` and unref'd here, so it never keeps the loop
/// alive: it contributes a descriptor, not work.
fn create_keepalive(pointer: *mut uv::uv_loop_t) -> Option<*mut uv::uv_async_t> {
    let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_async_t>::zeroed());
    // SAFETY: `storage` is a live, aligned, zeroed `uv_async_t` and `pointer` is
    // the loop `uv_loop_init` just initialised. The callback is never reached
    // because nothing ever signals this handle, but libuv requires a non-null
    // one.
    let status = unsafe { uv::uv_async_init(pointer, storage.as_mut_ptr(), Some(keepalive_cb)) };
    if status != 0 {
        tracing::error!(status, "uv_async_init failed");
        return None;
    }
    // SAFETY: `uv_async_init` succeeded, so the handle is initialised.
    let boxed = unsafe { Box::from_raw(Box::into_raw(storage).cast::<uv::uv_async_t>()) };
    let handle = Box::into_raw(boxed);
    // SAFETY: `handle` is the live handle just initialised.
    unsafe { uv::uv_unref(handle.cast()) };
    Some(handle)
}

/// The keep-alive handle's callback. Nothing signals it, so it never runs.
///
/// # Safety
///
/// Called by libuv with a live handle if something ever signals it.
unsafe extern "C" fn keepalive_cb(_handle: *mut uv::uv_async_t) {}

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

/// The address of the loop's keep-alive handle, or null before it exists.
///
/// Exposed so a test can assert the handle is started but unref'd: that pair is
/// what gives the backend a descriptor to wait on without counting as work, and
/// a regression in either half shows up as a spin or as a process that will not
/// exit.
pub fn keepalive_handle() -> *mut uv::uv_async_t {
    LOOP.with(|cell| {
        cell.borrow()
            .as_ref()
            .map_or(ptr::null_mut(), |handle| handle.keepalive)
    })
}

/// The loop's cached clock, in milliseconds.
///
/// This is `uv_now`: the value libuv refreshed at the start of the current
/// iteration. Within one JavaScript callback it does not advance, which is
/// exactly what libuv gives Node's `processTimers(now)`.
pub fn now_ms() -> f64 {
    with_loop(|pointer| {
        // SAFETY: `pointer` is the process' live loop.
        unsafe { uv::uv_now(pointer) as f64 }
    })
    .unwrap_or(0.0)
}

/// Refreshes the loop's cached clock, as `uv_update_time` does.
///
/// Callers that compute a delay from an absolute deadline need this first, or
/// the delay is measured from the previous iteration's time.
pub fn update_time() {
    if let Some(pointer) = loop_ptr() {
        // SAFETY: `pointer` is the process' live loop.
        unsafe { uv::uv_update_time(pointer) };
    }
}

/// One step of the loop, blocking in poll as libuv sees fit.
///
/// This is `uv_run(UV_RUN_ONCE)`: the iteration runs pending, idle, prepare,
/// poll, check, close and timers, and poll waits until a descriptor is ready or
/// the earliest ref'd libuv timer is due. `uv__backend_timeout` is what decides
/// that duration for us — zero when a callback is already runnable, the next
/// timer deadline otherwise, and "ignore the timer" when every timer is unref'd.
///
/// Returns `true` when the loop still has referenced work pending.
pub fn run_once_blocking() -> bool {
    run_inner(uv::uv_run_mode_UV_RUN_ONCE)
}

/// One step of the loop, without blocking.
///
/// This is `uv_run(UV_RUN_NOWAIT)`: poll returns immediately. It exists for
/// tests and for callers that already know something is runnable; a loop driven
/// entirely by it would spin, because libuv never gets to decide on a timeout.
pub fn run_once() -> bool {
    run_inner(uv::uv_run_mode_UV_RUN_NOWAIT)
}

/// Runs the loop until it has no referenced handles or requests left.
///
/// Unlike [`run_once`], this does not return between iterations, so nothing in
/// Rust can drain a microtask queue between two phases. `rn-io` therefore drives
/// the loop one [`run_once`] at a time and leaves `run` for callers that only
/// need the blocking behaviour. Both are the same loop; the difference is who
/// regains control, not what runs.
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

/// Closes every handle on the loop, drains, and releases the loop.
///
/// This is the teardown a *realm* performs, and the order matters in a way that
/// has already cost this project twice:
///
/// 1. every handle is closed with `uv_close`, which only *requests* the close —
///    libuv frees it when it runs the callback, from inside `uv_run`;
/// 2. `uv_run` is driven until it returns "not alive", which is the point where
///    every close callback has fired and nothing is left to schedule;
/// 3. `uv_loop_close` is called and its result is returned, because a non-zero
///    result means a handle is *still* open — and freeing the loop anyway is
///    what leaves a dangling watcher in libuv's process-global signal tree.
///
/// `uv_stop` is deliberately not used. It makes the current `uv_run` return
/// early without closing anything, so the next `uv_run` resumes the same handles:
/// a terminate that used it would appear to work once and then hang on the second
/// cycle, which is exactly what a create/terminate loop exercises.
///
/// Returns `true` when the loop closed cleanly. `false` means something is still
/// open and the caller must not treat the loop as released.
pub fn close_loop() -> bool {
    let Some(pointer) = loop_ptr() else {
        return true;
    };

    // `uv_run` below executes close callbacks, and a close callback can run
    // JavaScript that ends up here again. A nested sweep would call `uv_close`
    // on handles libuv has already been told to close, which aborts inside libuv
    // rather than returning an error. The outer run drains everything, so the
    // inner call reports what it can know.
    if SHUTTING_DOWN.with(|flag| flag.replace(true)) {
        return false;
    }
    let _guard = ShutdownGuard;

    // SAFETY: `pointer` is this thread's live loop; `close_walked_handle` only
    // calls `uv_close` on handles libuv handed to it, and skips ones already
    // closing.
    unsafe {
        uv::uv_walk(pointer, Some(close_walked_handle), ptr::null_mut());
        // `UV_RUN_DEFAULT` blocks until there is no referenced work. Close
        // callbacks are what make the remaining handles disappear, and the
        // keepalive handle is unref'd, so this returns once they have all run.
        uv::uv_run(pointer, uv::uv_run_mode_UV_RUN_DEFAULT);
        if uv::uv_loop_close(pointer) == 0 {
            return true;
        }
    }

    // Still open. One more sweep catches a handle a close callback created or a
    // binding armed from its own teardown; the second `uv_loop_close` is the
    // honest answer either way.
    // SAFETY: as above.
    unsafe {
        uv::uv_walk(pointer, Some(close_walked_handle), ptr::null_mut());
        uv::uv_run(pointer, uv::uv_run_mode_UV_RUN_DEFAULT);
        uv::uv_loop_close(pointer) == 0
    }
}

/// `uv_walk` callback used by [`close_loop`].
///
/// # Safety
///
/// Called by libuv for each live handle on the loop.
unsafe extern "C" fn close_walked_handle(handle: *mut uv::uv_handle_t, _arg: *mut c_void) {
    if handle.is_null() {
        return;
    }
    // SAFETY: libuv passes a live handle. A handle that is already closing must
    // not be closed twice, which is what `uv_is_closing` checks.
    if unsafe { uv::uv_is_closing(handle) } == 0 {
        // SAFETY: as above. The callback is the ledger's close hook rather than
        // `None`, because a handle that libuv releases without a callback would
        // never be counted, and the whole point of the ledger is that
        // `closed == created` is checkable.
        unsafe { uv::uv_close(handle, Some(walked_handle_closed)) };
    }
}

/// The close callback [`close_loop`] gives every handle it sweeps.
///
/// # Safety
///
/// Called by libuv once a swept handle is closed. It touches no handle state, so
/// it is valid for every handle type.
unsafe extern "C" fn walked_handle_closed(_handle: *mut uv::uv_handle_t) {
    crate::ledger::record_closed();
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

    /// The keep-alive descriptor gives the backend something to wait on, and is
    /// unreferenced so it never keeps the loop alive on its own.
    ///
    /// The descriptor count is the point: with `nfds == 0` libuv returns from
    /// `uv__io_poll` without waiting, so a pending timer would spin.
    #[test]
    fn the_keepalive_handle_supplies_a_descriptor_without_counting_as_work() {
        let pointer = loop_ptr().expect("the loop must be creatable");
        let keepalive = keepalive_handle();
        assert!(!keepalive.is_null());
        // SAFETY: both pointers name the process' live loop and handle.
        unsafe {
            assert_eq!(uv::uv_is_active(keepalive.cast()), 1, "started by init");
            assert_eq!(uv::uv_has_ref(keepalive.cast()), 0, "but never ref'd");
            assert!(
                (*pointer).nfds >= 1,
                "the backend has a descriptor to wait on"
            );
        }
        assert!(!is_active(), "an unref'd handle is not work");
    }

    #[test]
    fn the_loop_clock_is_monotonic_milliseconds() {
        update_time();
        let first = now_ms();
        std::thread::sleep(std::time::Duration::from_millis(2));
        update_time();
        let second = now_ms();
        assert!(second >= first);
        assert!(second - first >= 1.0, "the unit must be milliseconds");
    }
}
