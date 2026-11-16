//! Which poller a loop runs on, and the handle other code uses to identify it.
//!
//! There is one loop in rustnode and it is libuv's. This enum names the backend
//! that loop was asked for, and the *readiness backend* inside it is chosen
//! separately by `HERDR_URING` — see [`crate::loop_::Loop::poller`].

/// Which poller a loop is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// libuv's loop, which is the loop Node itself runs.
    ///
    /// The phase order — timers, pending, idle, prepare, poll, check, close —
    /// and the decision of how long to wait are libuv's, not rustnode's. Node's
    /// ordering guarantees are statements about `uv_run`, so the only way to
    /// reproduce them without re-deriving the rules is to run the same loop.
    /// `crates/rn-uv` owns the `uv_loop_t` and every handle on it.
    #[default]
    Libuv,
    /// The same loop, with its readiness wait served by io_uring.
    ///
    /// This is not a second loop: the phases, the deadlines and the callbacks
    /// are libuv's, and only the `epoll_pwait` inside `uv__io_poll` is replaced.
    /// It is selected at runtime by `HERDR_URING=1` and falls back to epoll when
    /// the kernel cannot provide a ring, so a program can request it without
    /// being able to fail because of it.
    IoUring,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_backend_is_the_node_ordered_one() {
        assert_eq!(Backend::default(), Backend::Libuv);
    }
}
