//! Event loop. The first backend keeps libuv semantics so Node's timer and
//! handle ordering tests pass; io_uring replaces the poller later without
//! changing this interface.

pub mod backend;
pub mod timer;

pub use backend::{Backend, LoopHandle};
pub use timer::TimerHeap;
