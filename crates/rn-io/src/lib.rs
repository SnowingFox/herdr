//! The event loop rustnode runs on, and when to run it.
//!
//! There is one loop in this runtime and it is libuv's, owned by `crates/rn-uv`.
//! This crate is the part that decides when it runs: one `uv_run(UV_RUN_ONCE)`
//! iteration at a time, with a `process.nextTick` and microtask drain between
//! iterations.
//!
//! # Why this is not a second loop
//!
//! An earlier version of this crate owned a `poll(2)` poller, its own timer heap,
//! and a phase order that reproduced libuv's in Rust. It was the loop the CLI
//! drove, and the real libuv loop that every I/O handle lives on was never
//! pumped, so `net`, `dgram` and `child_process` scheduled work that no one ran.
//! Two loops cannot both be the loop: whichever one a handle is registered on is
//! the only one that can report it, and the timer deadlines in one are invisible
//! to the other.
//!
//! What is left here is the seam that has to exist: [`Scheduler`], which lets the
//! runtime drain JavaScript queues at the one point libuv cannot know about.
//!
//! # Ordering
//!
//! Node's guarantees — `process.nextTick` before a microtask, a 0ms timer after
//! both, `setImmediate` in the check phase that follows poll, `unref()` deciding
//! whether the process waits — are statements about `uv_run` plus a checkpoint
//! after every JavaScript callback. Running the same loop is what makes them
//! true; see `crates/rn-uv/src/uv_loop.rs`.

pub mod backend;
pub mod loop_;

pub use backend::Backend;
pub use loop_::{Loop, Scheduler, StopReason};
