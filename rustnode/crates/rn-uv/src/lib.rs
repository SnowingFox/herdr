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
//! * [`uv_loop`] — the process' `uv_loop_t`, created on first use, plus [`uv_loop::run`]
//!   and [`uv_loop::run_once`], which are the event-loop workstream's integration
//!   point.
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
//! Timers, `process.nextTick`, and the decision of when the loop runs at all.
//! Those belong to `crates/rn-io` and `crates/rn-cli`; see [`uv_loop::run`] for the
//! exact interface between the two.

pub mod addr;
pub mod callback;
pub mod handle;
pub mod stream;
pub mod stream_base;
pub mod uv_loop;

pub use libuv_sys2 as sys;
