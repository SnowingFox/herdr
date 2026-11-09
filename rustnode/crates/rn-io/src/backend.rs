//! Which poller a loop runs on, and the handle other code uses to identify it.
//!
//! There is one loop in rustnode and it is libuv's. This enum names the backend
//! that loop is built on so a future native poller can be selected without
//! changing any caller, and so an unavailable backend is rejected rather than
//! silently emulated.

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
    /// Native Linux io_uring poller.
    ///
    /// Not implemented. `Loop::new` rejects it rather than quietly running the
    /// libuv loop under a name that claims otherwise.
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
