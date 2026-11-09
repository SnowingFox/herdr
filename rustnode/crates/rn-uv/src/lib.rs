//! libuv plumbing shared by rustnode's socket namespaces.
//!
//! `internalBinding('stream_wrap')`, `internalBinding('tcp_wrap')` and
//! `internalBinding('pipe_wrap')` all speak the same underlying protocol: a
//! libuv handle with a JavaScript object attached, a read that delivers its
//! bytes as an `ArrayBuffer`, and a write that queues behind earlier writes.
//! That shared half lives here so the three bindings describe only their own
//! differences.
//!
//! # What this crate owns
//!
//! * [`uv_loop`] — the process' one `uv_loop_t`, created on first use, plus
//!   [`uv_loop::run`] and [`uv_loop::run_once`]. Every asynchronous handle in
//!   rustnode lives on this loop, including the timer, check and idle handles the
//!   `timers` namespace arms.
//! * [`callback`] — re-entering V8 from a libuv completion, which is not legal
//!   without a handle scope and an entered context.
//! * [`addr`] — the `sockaddr` conversions and the `{ address, family, port }`
//!   shape `lib/net.js` reads out of `getsockname()`.
//! * [`handle`] — the per-handle state every stream wrap keeps.
//! * [`stream`] — the read, write and shutdown paths `TCP` and `Pipe` share.
//! * [`stream_base`] — the `StreamBase` methods both socket bindings install.
//!
//! # What this crate does not own
//!
//! `process.nextTick`, V8's microtask queue, and the decision of when the loop
//! runs at all. Those belong to `crates/rn-io`, which drives this loop one
//! iteration at a time, and `crates/rn-cli`, which implements the drain between
//! iterations. The timers themselves are libuv handles, but they live in
//! `crates/rn-bind-timers` because their callbacks need a V8 scope.
pub mod addr;
pub mod callback;
pub mod handle;
pub mod stream;
pub mod stream_base;
pub mod streams;
pub mod uv_loop;

pub use libuv_sys2 as sys;
