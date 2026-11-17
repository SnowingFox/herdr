//! The paused state: what `run_message_loop_on_pause` blocks on, and who wakes it.
//!
//! This is `inspector_agent.cc`'s `runMessageLoop()` (`:797`) and
//! `MainThreadInterface::WaitForFrontendEvent()` (`main_thread_interface.cc:221`),
//! which together are what make a breakpoint actually stop JavaScript.
//!
//! # What Node does
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
//! posts a request, and `RunAndClearInterrupts` then dispatches it. The two halves
//! matter equally: the wait is what stops JavaScript, and the dispatch is what lets
//! `Debugger.resume` arrive at all. A loop with only the first half never returns,
//! because the message that would end it is still sitting in the queue.
//!
//! Node's IO thread is separate from the isolate (`uv_thread_create` in
//! `inspector_io.cc:270`), so the paused thread never runs `uv_run` while waiting.
//! rustnode's socket reader threads are separate for the same reason, so this needs
//! no nested loop either: the wait is a condvar, and the dispatch is
//! [`crate::drain_pending_messages`] with the V8 scope the pause callback was handed.
//!
//! Nesting `uv_run` here would be wrong regardless: rustnode's `Loop::run` owns a
//! `&mut` to the scheduler, and a nested call cannot borrow it.
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
//! * The socket reader, after queueing a message, so the paused thread looks at the
//!   queue. It is the only thread allowed to dispatch, because a
//!   `V8InspectorSession` may not be touched off the isolate's thread.
//! * `Debugger.resume`, which the dispatch above reaches V8, which calls
//!   `quitMessageLoopOnPause`.
//! * The frontend disconnecting, which clears `attached` so the loop stops waiting
//!   for a client that is gone.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use rn_v8_sys::v8;

/// How long a pause waits before giving up on the frontend.
///
/// Long enough that a human debugging a program never sees it; short enough that a
/// test with a vanished client finishes. Node has no timeout — it relies on the
/// frontend disconnecting — but Node also blocks the whole process, so a wedged
/// debugger there is a wedged process.
pub const PAUSE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long `--inspect-brk` waits for the first client to connect.
///
/// Separate from [`PAUSE_TIMEOUT`] because it bounds a different event: this one
/// waits for a socket to be accepted, which a client either does quickly or not at
/// all. `test/debugger` spawns the child and connects immediately, so this is never
/// reached there; the value is what keeps `rustnode --inspect-brk app.js` from
/// waiting forever in a terminal with no debugger.
pub const ATTACH_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Set while `--inspect-brk` is holding the process before user code.
    ///
    /// Node's `waitForFrontend()` (`inspector_agent.cc:551`) sets
    /// `waiting_for_frontend_` and enters the same `runMessageLoop()`, and
    /// `runIfWaitingForDebugger` clears it. The distinction from `waiting` is what
    /// ends the loop: a pause ends on `Debugger.resume`, and this ends on the
    /// client saying "run", which is a different command and a different event.
    waiting_for_frontend: bool,
    /// Incremented by anything that wants the paused loop to look again.
    generation: u32,
}

static PAUSED: Mutex<Paused> = Mutex::new(Paused {
    waiting: false,
    resumed: false,
    attached: false,
    waiting_for_frontend: false,
    generation: 0,
});
static WAKEUP: Condvar = Condvar::new();

/// Counts nested pauses, so only the outermost one drives the loop.
static PAUSE_DEPTH: AtomicU32 = AtomicU32::new(0);

/// Whether `--inspect-brk` is holding the process before user code.
///
/// The `NodeRuntime.enable` handler asks this so it can answer with
/// `NodeRuntime.waitingForDebugger` — Node's agent emits that event from the V8
/// channel that was marked waiting, and a client enables the domain during
/// `--inspect-brk`'s wait rather than during a pause.
#[must_use]
pub fn waiting_for_frontend() -> bool {
    PAUSED
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .waiting_for_frontend
}

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
/// This is Node's `shouldRunMessageLoop` (`inspector_agent.cc:788`) translated:
///
/// ```text
/// if (waiting_for_frontend_) return true;
/// if (waiting_for_sessions_disconnect_ || waiting_for_resume_) return hasConnectedSessions();
/// return false;
/// ```
///
/// The first clause is `--inspect-brk`'s pre-execution wait, which ends on
/// `Runtime.runIfWaitingForDebugger` rather than on `Debugger.resume`. The second is
/// an ordinary pause, which ends on resume. Both require a connected frontend, or a
/// client that disappeared would leave the process waiting for nobody.
fn should_run(paused: &Paused) -> bool {
    if paused.waiting_for_frontend {
        return paused.attached;
    }
    paused.attached && !paused.resumed
}

/// Ends the `--inspect-brk` wait, as `Runtime.runIfWaitingForDebugger` does.
///
/// Node: `runIfWaitingForDebugger` sets `waiting_for_frontend_ = false` and
/// unsets the waiting flag on every channel (`inspector_agent.cc:588`). The
/// observable a client relies on is that user code starts, which is why this wakes
/// the loop rather than only clearing a flag.
pub fn run_if_waiting_for_debugger() {
    let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
    if !paused.waiting_for_frontend {
        return;
    }
    paused.waiting_for_frontend = false;
    paused.generation = paused.generation.wrapping_add(1);
    drop(paused);
    WAKEUP.notify_all();
}

/// Blocks until `Runtime.runIfWaitingForDebugger`, dispatching frontend messages.
///
/// This is `waitForFrontend()` (`inspector_agent.cc:551`) and it is what
/// `--inspect-brk` promises: the process does not run a line of user code until a
/// client says so. It uses the same loop as an ordinary pause because Node does —
/// `runMessageLoop()` consults `shouldRunMessageLoop`, which answers `true` for
/// either reason — and because the client's first commands (`Debugger.enable`,
/// `Debugger.setBreakpointByUrl`, `Runtime.runIfWaitingForDebugger`) all arrive while
/// it is blocked.
///
/// Returns whether it waited. A run with no frontend attached returns at once, which
/// is Node's `WaitForConnectByOptions` behaviour when nothing is listening.
pub fn wait_for_frontend_loop(
    scope: &mut v8::PinScope<'_, '_>,
    dispatch: impl Fn(&mut v8::PinScope<'_, '_>) -> usize,
    attach_timeout: Duration,
) -> bool {
    // The listener accepts on its own thread and the client connects a moment after
    // `Debugger listening on` is printed, so waiting for the first attachment is
    // part of this. Node's `WaitForConnectByOptions` blocks on a semaphore the io
    // thread signals when a socket is accepted, which is the same ordering.
    {
        let deadline = Instant::now() + attach_timeout;
        loop {
            let paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
            if paused.attached {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            // The condvar is notified by `set_attached(true)`, so this is a wait for
            // exactly the event, not a poll.
            let (next, _timeout) = WAKEUP
                .wait_timeout(paused, remaining)
                .unwrap_or_else(|poison| poison.into_inner());
            drop(next);
        }
    }

    {
        let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
        paused.waiting_for_frontend = true;
        paused.resumed = false;
        paused.waiting = true;
    }

    // The connection may have been accepted a moment before the client sends
    // anything, so this loop both waits for `runIfWaitingForDebugger` and
    // dispatches the commands that precede it. A client that never sends it is
    // bounded by `PAUSE_TIMEOUT`, the same bound an unresumed pause has.
    let deadline = Instant::now() + PAUSE_TIMEOUT;
    loop {
        let dispatched = dispatch(scope);
        let paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
        if !should_run(&paused) {
            break;
        }
        if dispatched > 0 {
            drop(paused);
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            tracing::warn!(
                "--inspect-brk waited {PAUSE_TIMEOUT:?} for a client to run; continuing"
            );
            break;
        }
        let (next, _timeout) = WAKEUP
            .wait_timeout(paused, remaining)
            .unwrap_or_else(|poison| poison.into_inner());
        drop(next);
    }

    let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
    paused.waiting = false;
    paused.waiting_for_frontend = false;
    drop(paused);
    true
}

/// Blocks the isolate's thread until the pause is over, dispatching frontend
/// messages while it waits.
///
/// Returns whether it waited at all. A call with no frontend attached is a no-op
/// rather than a 30-second stall: `--inspect-brk` with nobody listening must not hang,
/// and Node's `shouldRunMessageLoop` returns false in the same situation.
///
/// `scope` is the V8 scope the caller entered around `run_message_loop_on_pause`;
/// dispatching a protocol message needs one, and there is nowhere else to get it.
/// That is the second half of Node's loop — `env_->RunAndClearInterrupts()` — and
/// leaving it out is what makes a pause un-resumable: the `Debugger.resume` sits in
/// the queue while the paused thread waits for it.
///
/// `dispatch` is that second half, passed in rather than reached through
/// [`crate::drain_pending_messages`] so a test can hand the loop its own server. In
/// production it is always `drain_pending_messages`, which uses the server the CLI
/// installed.
pub fn run_pause_loop(
    scope: &mut v8::PinScope<'_, '_>,
    dispatch: impl Fn(&mut v8::PinScope<'_, '_>) -> usize,
) -> bool {
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
        {
            let mut paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
            // A pause starts un-resumed regardless of what the previous one left behind.
            paused.resumed = false;
            if !should_run(&paused) {
                PAUSE_DEPTH.fetch_sub(1, Ordering::SeqCst);
                return false;
            }
            // `waiting` stays set for the whole loop, including while a message is
            // being dispatched: `resume` only takes effect while it is, and the
            // resume arrives *during* a dispatch.
            paused.waiting = true;
        }

        let deadline = Instant::now() + PAUSE_TIMEOUT;
        loop {
            // Dispatch whatever the frontend queued *before* waiting again. This is
            // `env_->RunAndClearInterrupts()`, the half of Node's loop that makes
            // `Debugger.resume` reachable at all.
            //
            // No lock is held across it: the dispatch can call
            // `quit_message_loop_on_pause`, which takes the same lock to clear
            // `resumed`, and holding it here would deadlock the pause against
            // itself.
            let dispatched = dispatch(scope);

            let paused = PAUSED.lock().unwrap_or_else(|poison| poison.into_inner());
            if !should_run(&paused) {
                break;
            }
            if dispatched > 0 {
                // Anything the dispatch queued in turn — a nested `Runtime.evaluate`
                // on the paused frame, or the immediate the reader asked for — is
                // picked up on the next turn rather than by a sleep.
                drop(paused);
                continue;
            }
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
            drop(next);
        }
        PAUSED
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .waiting = false;
        true
    };

    PAUSE_DEPTH.fetch_sub(1, Ordering::SeqCst);
    if waited {
        // A message that arrived just before the resume — the client's next
        // command, or the immediate the reader queued — is dispatched here rather
        // than being held until the loop's next check phase, because the caller is
        // about to hand control back to V8 and there may be no next turn.
        dispatch(scope);
    }
    waited
}

/// Whether a pause loop is currently on the stack of any thread.
///
/// This is `running_nested_loop_`'s observable. A caller that is about to pause
/// consults it to decide whether it is re-entering — a `Debugger.pause` delivered
/// during a pause, or a breakpoint hit inside a `Runtime.evaluate` on the paused
/// frame — and the loop sets it for the whole wait so that decision is answerable
/// from anywhere.
#[must_use]
pub fn pause_on_stack() -> bool {
    PAUSE_DEPTH.load(Ordering::SeqCst) > 0
}

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
