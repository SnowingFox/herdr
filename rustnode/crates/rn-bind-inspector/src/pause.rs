//! The paused state: what `run_message_loop_on_pause` blocks on, and who wakes it.
//!
//! This is `inspector_agent.cc`'s `runMessageLoop()` (`:797`) and
//! `MainThreadInterface::WaitForFrontendEvent()` (`main_thread_interface.cc:221`),
//! which together are what make a breakpoint actually stop JavaScript.
//!
//! # What Node does, and what this does instead
//!
//! Node's loop is:
//!
//! ```text
//! while (shouldRunMessageLoop()) {
//!   if (interface_) interface_->WaitForFrontendEvent();
//!   env_->RunAndClearInterrupts();
//! }
//! ```
//!
//! `WaitForFrontendEvent` blocks on a **condition variable** until the IO thread
//! posts a request. It does *not* run `uv_run`; Node's inspector IO lives on its own
//! thread (`uv_thread_create` in `inspector_io.cc:270`), so the paused thread has
//! nothing to poll and simply sleeps. That distinction matters here: nesting `uv_run`
//! inside a V8 callback would re-enter the loop from a callback that the loop itself
//! is running, and rustnode's `Loop::run` owns a `&mut` to the scheduler that a
//! nested call cannot borrow. A condvar is both what Node does and the only shape
//! that fits this architecture.
//!
//! # Why the wait is bounded
//!
//! `wait_timeout` rather than `wait`: a `Debugger.pause` whose client disappears must
//! not hang the process forever, and `--inspect-brk` with no client is the same case.
//! Node handles it with a disconnect notification; here the timeout is 30 s, which is
//! long enough that no real debugger session sees it and short enough that a test
//! cannot hang the run.
//!
//! # Who wakes it
//!
//! Three things:
//!
//! * A frontend message arrives — `deliver` in `session.rs`, and the socket server's
//!   `drain` — because the paused thread is the only one allowed to dispatch it.
//! * `Debugger.resume` / `Debugger.disable` arrives, which clears `resumed`.
//! * The frontend disconnects, which clears `attached` so the loop stops waiting for
//!   a client that is gone.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long a pause waits before giving up on the frontend.
///
/// Long enough that a human debugging a program never sees it; short enough that a
/// test with a vanished client finishes. Node has no timeout — it relies on the
/// frontend disconnecting — but Node also blocks the whole process, so a wedged
/// debugger there is a wedged process.
pub const PAUSE_TIMEOUT: Duration = Duration::from_secs(30);

/// The shared paused state.
///
/// Deliberately not a thread-local: the socket reader threads and the writer thread
/// both need to signal it, and `V8InspectorSession` may only be touched on the
/// isolate's thread. Everything here is plain `std` synchronisation with no V8
/// handle in it, so a foreign thread may hold it.
struct Paused {
    /// Set while the isolate is suspended in `run_message_loop_on_pause`.
    waiting: bool,
    /// Set while a pause is wanted — cleared by `Debugger.resume`.
    ///
    /// Named from the loop's point of view: `resumed == true` means "stop waiting".
    resumed: bool,
    /// A frontend is attached, so waiting is worth doing at all.
    attached: bool,
    /// Incremented by anything that wants the paused loop to look again.
    generation: u32,
}

static PAUSED: Mutex<Paused> = Mutex::new(Paused {
    waiting: false,
    resumed: false,
    attached: false,
    generation: 0,
});
static WAKEUP: Condvar = Condvar::new();

/// Counts nested pauses, so only the outermost one drives the loop.
static PAUSE_DEPTH: AtomicU32 = AtomicU32::new(0);

/// Whether the isolate is currently suspended in the pause loop.
pub fn is_paused() -> bool {
    PAUSED
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .waiting
}

/// Marks a frontend as attached or gone.
///
/// A disconnect while paused is what lets the loop stop: `should_run` requires an
/// attached frontend, so losing the last one exits the pause rather than sitting out
/// the whole timeout.
pub fn set_attached(attached: bool) {
    let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
    paused.attached = attached;
    if !attached {
        paused.resumed = false;
        paused.generation = paused.generation.wrapping_add(1);
    }
    drop(paused);
    WAKEUP.notify_all();
}

/// Whether a frontend is attached.
pub fn is_attached() -> bool {
    PAUSED
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .attached
}

/// Asks the paused loop to look at its exit condition again.
///
/// Called after a frontend message has been queued, because the paused thread is the
/// one that has to dispatch it and it is asleep in `wait`.
pub fn wake() {
    let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
    paused.generation = paused.generation.wrapping_add(1);
    drop(paused);
    WAKEUP.notify_all();
}

/// Ends a pause, as `Debugger.resume` does.
///
/// `quitMessageLoopOnPause` in `inspector_agent.cc:590` is exactly
/// `waiting_for_resume_ = false`, and this is its counterpart.
///
/// Only takes effect while a pause is actually in progress. A `resume` that arrived
/// after the last pause ended — the frontend answering late, or a test whose threads
/// race — must not be credited to the next pause, or that pause returns instantly and
/// looks like the no-op this slice exists to remove.
pub fn resume() {
    let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
    if !paused.waiting {
        return;
    }
    paused.resumed = true;
    paused.generation = paused.generation.wrapping_add(1);
    drop(paused);
    WAKEUP.notify_all();
}

/// Sets whether a pause should keep waiting.
pub fn set_resumed(resumed: bool) {
    let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
    // The field is named from the loop's point of view: `resumed == true` means "stop
    // waiting". Inverting here keeps the call sites reading naturally while the wait
    // condition stays `!resumed`.
    paused.resumed = resumed;
    paused.generation = paused.generation.wrapping_add(1);
    drop(paused);
    WAKEUP.notify_all();
}

/// Arms a pause, clearing any resume left over from an earlier one.
///
/// Called before the wait begins, which is what makes the resume consumed by exactly
/// one pause. V8 calls `runMessageLoopOnPause` after it has suspended, so arming there
/// is correct; a test that drives the loop directly calls this first.
pub fn arm() {
    let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
    paused.resumed = false;
    paused.generation = paused.generation.wrapping_add(1);
}

/// Whether a pause should keep running its wait loop.
///
/// The three clauses are Node's `shouldRunMessageLoop` (`inspector_agent.cc:788`)
/// translated: keep waiting while a frontend is attached and nobody asked to resume,
/// and stop the moment either stops being true.
fn should_run(paused: &Paused) -> bool {
    paused.attached && !paused.resumed
}

/// Blocks the isolate's thread until the pause is over.
///
/// Returns whether it waited at all. A call with no frontend attached is a no-op
/// rather than a 30-second stall: `--inspect-brk` with nobody listening must not hang,
/// and Node's `shouldRunMessageLoop` returns false in the same situation.
pub fn run_pause_loop() -> bool {
    // A nested pause — a `Debugger.pause` delivered while already paused, or a
    // breakpoint hit inside an `Runtime.evaluate` — must not start a second loop.
    // `runMessageLoop` guards this with `running_nested_loop_` (`:798`), and without
    // the guard the inner call would consume the `Debugger.resume` the outer one is
    // waiting for.
    let depth = PAUSE_DEPTH.fetch_add(1, Ordering::SeqCst);
    if depth > 0 {
        PAUSE_DEPTH.fetch_sub(1, Ordering::SeqCst);
        return false;
    }

    let waited = {
        let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
        // A pause starts un-resumed regardless of what the previous one left behind.
        paused.resumed = false;
        if !should_run(&paused) {
            PAUSE_DEPTH.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        paused.waiting = true;
        let deadline = Instant::now() + PAUSE_TIMEOUT;
        while should_run(&paused) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                tracing::warn!(
                    "the inspector was paused for {PAUSE_TIMEOUT:?} with no resume; continuing"
                );
                break;
            }
            let (next, _timeout) = WAKEUP
                .wait_timeout(paused, remaining)
                .unwrap_or_else(|poison| poison.into_inner());
            paused = next;
        }
        paused.waiting = false;
        true
    };

    PAUSE_DEPTH.fetch_sub(1, Ordering::SeqCst);
    if waited {
        // The frontend that saw the pause has had its `Debugger.paused`; anything it
        // queued during the wait is dispatched by the caller's drain.
        crate::drain_pending();
    }
    waited
}

/// Requests a pause before the next statement.
///
/// V8 asks the client to pause through `schedule_pause_on_next_statement`, which needs
/// a session; this is the agent-side record that a pause is wanted, used by
/// `callAndPauseOnStart` and `--inspect-brk` before any session exists.
static PAUSE_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Records that the next statement should stop.
pub fn request_pause() {
    PAUSE_REQUESTED.store(true, Ordering::SeqCst);
}

/// Takes the pending pause request, if there is one.
pub fn take_pause_request() -> bool {
    PAUSE_REQUESTED.swap(false, Ordering::SeqCst)
}

/// Whether a pause has been requested and not yet taken.
pub fn pause_requested() -> bool {
    PAUSE_REQUESTED.load(Ordering::SeqCst)
}
