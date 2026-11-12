//! Coalescing event queue between native threads and the JS event loop.
//!
//! Native threads push events and only request a JS wake-up when none is already pending; JS then
//! drains the whole batch in one call. This keeps FFI crossings proportional to JS turns rather
//! than to PTY reads.

use std::collections::VecDeque;
use std::sync::Mutex;

pub trait Coalesce {
    /// Whether `self` (the newest event) supersedes `previous` when they are adjacent.
    fn supersedes(&self, previous: &Self) -> bool;
}

struct State<T> {
    items: VecDeque<T>,
    wake_pending: bool,
}

pub struct EventQueue<T> {
    state: Mutex<State<T>>,
}

impl<T: Coalesce> Default for EventQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Coalesce> EventQueue<T> {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                items: VecDeque::new(),
                wake_pending: false,
            }),
        }
    }

    /// Push an event. Returns true when the caller must wake the JS side.
    pub fn push(&self, item: T) -> bool {
        let mut state = self.lock();
        if let Some(last) = state.items.back_mut() {
            if item.supersedes(last) {
                *last = item;
                return Self::request_wake(&mut state);
            }
        }
        state.items.push_back(item);
        Self::request_wake(&mut state)
    }

    /// Drain all pending events and clear the wake flag.
    pub fn take(&self) -> Vec<T> {
        let mut state = self.lock();
        state.wake_pending = false;
        state.items.drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.lock().items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn request_wake(state: &mut State<T>) -> bool {
        if state.wake_pending {
            false
        } else {
            state.wake_pending = true;
            true
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State<T>> {
        // A poisoned queue only means another thread panicked mid-push; the data is still valid.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    enum Ev {
        Output(u32),
        Exit,
    }

    impl Coalesce for Ev {
        fn supersedes(&self, previous: &Self) -> bool {
            matches!((self, previous), (Ev::Output(_), Ev::Output(_)))
        }
    }

    #[test]
    fn first_push_requests_wake_and_later_pushes_do_not() {
        let queue = EventQueue::new();
        assert!(queue.push(Ev::Output(1)));
        assert!(!queue.push(Ev::Exit));
    }

    #[test]
    fn adjacent_outputs_coalesce_to_latest() {
        let queue = EventQueue::new();
        queue.push(Ev::Output(1));
        queue.push(Ev::Output(2));
        queue.push(Ev::Exit);
        queue.push(Ev::Output(3));
        assert_eq!(queue.take(), vec![Ev::Output(2), Ev::Exit, Ev::Output(3)]);
    }

    #[test]
    fn take_rearms_the_wake_flag() {
        let queue = EventQueue::new();
        assert!(queue.push(Ev::Output(1)));
        assert_eq!(queue.take(), vec![Ev::Output(1)]);
        assert!(queue.is_empty());
        assert!(queue.push(Ev::Output(2)));
    }
}
