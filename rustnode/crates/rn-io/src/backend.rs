//! Which poller a loop runs on, and the handle other threads of control use to
//! arm it.
//!
//! `LoopHandle` is the equivalent of libuv's `uv_timer_t` for a loop that has
//! exactly one of them: Node's `Environment` owns a single timer handle, and
//! both `scheduleTimer()` and the return value of `processTimers()` re-arm that
//! one handle. Arming from anywhere that can see the handle is what keeps the
//! deadline in one place instead of in every caller's own variable.

use std::cell::RefCell;
use std::rc::Rc;

use crate::timer::TimerHeap;

/// Which poller a loop is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// Node's phase order: timers, pending callbacks, poll, check, close, with
    /// a microtask drain between each.
    ///
    /// The name records the ordering contract, which is libuv's. The poller
    /// underneath is `poll(2)` driven by `libc` rather than FFI into libuv: the
    /// workspace links no C library beyond the one `libc` already wraps, and
    /// `rn-bind-uv` documents the same decision for libuv's error strings. A
    /// libuv that had to be built and shipped per platform would buy nothing
    /// here, because what Node's tests assert is the order the phases run in,
    /// not which system call waited.
    #[default]
    Libuv,
    /// Native Linux io_uring poller.
    ///
    /// Not implemented. `Loop::new` rejects it rather than quietly running the
    /// portable loop under a name that claims otherwise.
    IoUring,
}

/// One pending wakeup: when the loop must wake, and which arming asked for it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Wakeup {
    /// Absolute deadline on the loop's monotonic millisecond clock.
    pub at_ms: f64,
    /// The arm generation that produced this deadline.
    pub generation: u64,
}

impl Wakeup {
    /// Milliseconds from `now_ms` until this deadline, never negative.
    pub fn delay_ms(&self, now_ms: f64) -> f64 {
        (self.at_ms - now_ms).max(0.0)
    }
}

/// The arming state a [`LoopHandle`] shares with its loop.
///
/// libuv's `uv_timer_t` holds one deadline, and Node's `Environment` owns
/// exactly one of them: `scheduleTimer()` starts it and the value
/// `processTimers()` returns restarts it. Rustnode keeps the same single
/// deadline, and the [`TimerHeap`] here is what makes "which of two pending
/// arms is real" answerable rather than implied. Without it a superseded arm
/// would look identical to the live one, which is the bug the old
/// `pop_due`-returns-a-sequence-number version could not even express.
#[derive(Debug, Default)]
pub(crate) struct WakeupState {
    pending: TimerHeap,
    generation: u64,
    /// The arm generation that is still in force.
    current: Option<u64>,
    /// The deadline of the arm generation still in force.
    current_at: Option<f64>,
}

impl WakeupState {
    /// Arms the loop at `at_ms`, replacing any earlier deadline.
    ///
    /// A handle has one deadline, like libuv's single timer per environment:
    /// arming again supersedes rather than accumulates, so a timer created
    /// before an earlier one is inserted does not leave a stale deadline
    /// behind that would wake the loop early for nothing.
    pub(crate) fn wake_at(&mut self, at_ms: f64) {
        self.generation += 1;
        let generation = self.generation;
        let _ = self.pending.insert(at_ms as u64, generation);
        self.current = Some(generation);
        self.current_at = Some(at_ms);
    }

    /// Cancels the pending deadline, the way `uv_timer_stop` does.
    pub(crate) fn cancel(&mut self) {
        self.generation += 1;
        self.current = None;
        self.current_at = None;
        self.pending.clear();
    }

    /// The deadline currently in force, if any.
    pub(crate) fn next(&self) -> Option<Wakeup> {
        Some(Wakeup {
            at_ms: self.current_at?,
            generation: self.current?,
        })
    }

    /// Drops every arming that has come due at or before `now_ms`.
    ///
    /// Returns whether the deadline that came due was still the one in force. A
    /// `false` means a newer arming replaced it, which is the case the discarded
    /// id made invisible: the old code popped a sequence number and could not
    /// tell a superseded deadline from a live one.
    pub fn take_due(&mut self, now_ms: f64) -> bool {
        let mut live = false;
        while let Some(generation) = self.pending.pop_due(now_ms as u64) {
            if self.current == Some(generation) {
                self.current = None;
                self.current_at = None;
                live = true;
            }
        }
        live
    }
}

/// A loop's arming state, shared with whoever schedules work on it.
///
/// Cloning is cheap and every clone arms the same loop, which is what the
/// bindings need: `scheduleTimer` runs inside V8 and has no other route back to
/// the loop it is scheduling on.
#[derive(Debug, Clone)]
pub struct LoopHandle {
    backend: Backend,
    wakeups: Rc<RefCell<WakeupState>>,
}

impl LoopHandle {
    pub(crate) fn new(backend: Backend, wakeups: Rc<RefCell<WakeupState>>) -> Self {
        Self { backend, wakeups }
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Asks the loop to wake at `at_ms` on its monotonic clock.
    pub fn wake_at(&self, at_ms: f64) {
        self.wakeups.borrow_mut().wake_at(at_ms);
    }

    /// Asks the loop to wake `delay_ms` from now.
    pub fn wake_in(&self, now_ms: f64, delay_ms: f64) {
        self.wake_at(now_ms + delay_ms.max(0.0));
    }

    /// Cancels the pending deadline.
    pub fn cancel_wakeup(&self) {
        self.wakeups.borrow_mut().cancel();
    }

    /// The deadline currently in force, if any.
    pub fn next_wakeup(&self) -> Option<Wakeup> {
        self.wakeups.borrow().next()
    }

    /// Clears every arming that has come due at or before `now_ms`.
    ///
    /// Returns whether the deadline that came due was still in force. The loop
    /// calls this before a turn's timer phase so a deadline that was superseded
    /// between arming and firing cannot be mistaken for the live one.
    pub fn clear_due(&self, now_ms: f64) -> bool {
        self.wakeups.borrow_mut().take_due(now_ms)
    }

    /// Whether any arm is recorded, live or superseded.
    ///
    /// Exposed for tests: it is the only way to see that a superseded arm was
    /// cleared rather than left to fire.
    pub fn pending_arms(&self) -> usize {
        self.wakeups.borrow().pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> Rc<RefCell<WakeupState>> {
        Rc::new(RefCell::new(WakeupState::default()))
    }

    #[test]
    fn a_handle_arms_the_loop_it_came_from() {
        let wakeups = state();
        let handle = LoopHandle::new(Backend::Libuv, Rc::clone(&wakeups));
        handle.wake_in(100.0, 25.0);
        assert_eq!(wakeups.borrow().next().map(|w| w.at_ms), Some(125.0));
    }

    #[test]
    fn arming_again_replaces_the_earlier_deadline() {
        // One deadline per loop, like libuv's single timer handle: a second arm
        // must not leave the first one to fire early.
        let wakeups = state();
        let handle = LoopHandle::new(Backend::Libuv, Rc::clone(&wakeups));
        handle.wake_at(50.0);
        let first = handle.next_wakeup().map(|w| w.generation);
        handle.wake_at(10.0);
        let second = handle.next_wakeup().map(|w| w.generation);
        assert_ne!(first, second);
        assert_eq!(handle.next_wakeup().map(|w| w.at_ms), Some(10.0));
    }

    #[test]
    fn a_superseded_deadline_is_not_reported_live() {
        let wakeups = state();
        let handle = LoopHandle::new(Backend::Libuv, Rc::clone(&wakeups));
        handle.wake_at(5.0);
        handle.wake_at(100.0);
        // Both arms are still on the heap, but only the newer one is live.
        assert_eq!(handle.pending_arms(), 2);
        assert!(!handle.clear_due(5.0), "the 5ms arm was superseded");
        assert_eq!(handle.next_wakeup().map(|w| w.at_ms), Some(100.0));
        assert!(handle.clear_due(100.0), "the 100ms arm is the live one");
        assert!(handle.next_wakeup().is_none());
    }

    #[test]
    fn cancelling_clears_the_deadline() {
        let wakeups = state();
        let handle = LoopHandle::new(Backend::Libuv, Rc::clone(&wakeups));
        handle.wake_at(5.0);
        handle.cancel_wakeup();
        assert!(handle.next_wakeup().is_none());
        assert!(!wakeups.borrow_mut().take_due(5.0));
    }

    #[test]
    fn the_default_backend_is_the_node_ordered_one() {
        assert_eq!(Backend::default(), Backend::Libuv);
    }
}
