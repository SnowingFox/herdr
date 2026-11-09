//! Event loop. The first backend keeps libuv semantics so Node's timer and
//! handle ordering tests pass; io_uring replaces the poller later without
//! changing this interface.
//!
//! The loop is deliberately split in two:
//!
//! * [`Loop`] owns the phase order and the poller. It is pure bookkeeping and
//!   testable without a JavaScript engine.
//! * [`Scheduler`] is what the loop asks to run each phase. `rn-cli` implements
//!   it over V8 and the `timers` binding.
//!
//! That split is what lets a unit test pin "timers, pending, poll, check, close,
//! with a drain between each" while the behaviour those phases exist for is
//! checked against a real `node` binary by the CLI's integration tests.

pub mod backend;
pub mod loop_;
pub mod poll;
pub mod timer;

pub use backend::{Backend, LoopHandle, Wakeup};
pub use loop_::{Loop, Phase, Scheduler, StopReason};
pub use poll::{Descriptor, Poller, Ready};
pub use timer::TimerHeap;

use std::cell::RefCell;

thread_local! {
    /// The loop this thread's isolate runs on.
    ///
    /// Bindings that must re-arm the loop (`scheduleTimer` in the `timers`
    /// namespace, and every asynchronous I/O binding that follows it) run inside
    /// a V8 callback, which receives no context and cannot be handed a
    /// `LoopHandle`. Node solves this by reaching the loop through the
    /// `Environment` its callbacks capture; rustnode has no per-isolate object
    /// yet, so the loop installs itself here and a binding asks for it.
    ///
    /// `None` before the CLI builds a loop, which is the whole bootstrap window.
    /// A binding that finds nothing reports honestly instead of pretending it
    /// armed a loop that does not exist.
    static CURRENT: RefCell<Option<LoopHandle>> = const { RefCell::new(None) };
}

/// Records `handle` as the loop on this thread.
pub fn install_loop(handle: LoopHandle) {
    CURRENT.with(|current| *current.borrow_mut() = Some(handle));
}

/// The loop installed on this thread, if the runtime has created one.
pub fn current_loop() -> Option<LoopHandle> {
    CURRENT.with(|current| current.borrow().clone())
}

/// Forgets the installed loop.
///
/// The CLI calls this when its isolate is done so a later isolate on the same
/// thread cannot arm a loop that no longer runs.
pub fn uninstall_loop() {
    CURRENT.with(|current| *current.borrow_mut() = None);
}
