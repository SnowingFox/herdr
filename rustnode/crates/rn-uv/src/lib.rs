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
//! * [`listener`] — `StreamListener`: how one stream receives the reads another
//!   stream performed, which is what a `TLSWrap` with no libuv handle of its own
//!   is built on.
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
pub mod listener;
pub mod stream;
pub mod stream_base;
pub mod streams;
pub mod uv_loop;

pub use libuv_sys2 as sys;

/// The libuv version the binary linked, as `uv_version_string` reports it.
///
/// `process.versions.uv` is the JavaScript view of this, and Node's test suite
/// branches on it: `test-blocklist.js` expects an overlong zone suffix on a
/// mixed-notation IPv6 address to parse only from libuv 1.53, so the value has
/// to come from the library actually linked rather than from a manifest.
pub fn uv_version_string() -> Option<String> {
    // SAFETY: libuv returns a pointer to a static, NUL-terminated string that
    // lives for the process, and it is never null.
    let pointer = unsafe { libuv_sys2::uv_version_string() };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the pointer is static and NUL-terminated, as stated above.
    Some(
        unsafe { std::ffi::CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned(),
    )
}
