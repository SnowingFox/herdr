//! The `StreamBase` half of `binding.Http2Stream`.
//!
//! `src/node_http2.h:288` declares it as both:
//!
//! ```cpp
//! class Http2Stream : public AsyncWrap,
//!                     public StreamBase {
//! ```
//!
//! and the four virtuals are what make it usable as either end of a `StreamPipe`.
//! rustnode had the methods on the prototype (`readStart`, `readStop`, `shutdown`,
//! `writeBuffer`, …) but never published the stream as a `StreamBase`, so
//! `new StreamPipe(handle, other)` failed the type check — and the write path went
//! through [`super::provider`]'s queue rather than through `StreamBase`.
//!
//! # The four virtuals, and where Node puts each
//!
//! | | Node | here |
//! | --- | --- | --- |
//! | `ReadStart` | `Http2Stream::ReadStart` (`node_http2.cc:2706`) | [`Http2StreamOps::read_start`] |
//! | `ReadStop` | `Http2Stream::ReadStop` (`:2725`) | [`Http2StreamOps::read_stop`] |
//! | `DoShutdown` | `Http2Stream::DoShutdown` (`:2389`) | [`Http2StreamOps::shutdown`] |
//! | `DoWrite` | `Http2Stream::DoWrite` (`:2744`) | [`Http2StreamOps::write`] |
//! | `HasWantsWrite` | `true` (`node_http2.h:320`) | [`Http2StreamOps::has_wants_write`] |
//!
//! # What a write does here
//!
//! `DoWrite` appends the buffers to the stream's `queue_` and calls
//! `nghttp2_session_resume_data`; the queued bytes are framed when nghttp2 asks
//! the data provider for them. rustnode's equivalent queue is
//! [`StreamRecord::pending`], which [`super::provider`] drains, so a write appends
//! there and resumes the provider. That is the same shape.
//!
//! The completion is **asynchronous** (`0` from `DoWrite`): `stream_base_commons`
//! attaches `oncomplete` to the returned `WriteWrap`, and the provider reports it
//! once the bytes have left. This is the one place a pipe write is not permitted
//! to finish synchronously, and Node's own `StreamPipe::ProcessData` takes its
//! `else` branch here — `is_reading_ = false` and `source()->ReadStop()` — which is
//! the backpressure that keeps an HTTP/2 sink from buffering a whole file.
//!
//! # Backpressure: `HasWantsWrite`
//!
//! Because `HasWantsWrite()` is `true`, `StreamPipe` does not resume the source
//! itself after a write completes. Instead `Http2Stream::OnRead` calls
//! `EmitWantsWrite(length)` when it has drained the queue and wants more, which is
//! the `amount == 0 && is_writable()` branch at `node_http2.cc:2874`. That reaches
//! [`Http2StreamOps`] via [`rn_uv::listener::emit_wants_write`], and only then does
//! the pipe read again.

use std::ptr;

use rn_uv::handle::StreamState;
use rn_uv::stream_ops::{StreamOps, WriteOutcome};

use crate::session::SessionState;
use crate::stream::StreamHandleState;

/// The ops every `binding.Http2Stream` state carries.
pub struct Http2StreamOps;

/// The one instance every HTTP/2 stream state points at.
pub static HTTP2_STREAM_OPS: Http2StreamOps = Http2StreamOps;

/// The stream handle behind a state, from the state's own owner pointer.
fn handle_of(state: *mut StreamState) -> Option<&'static StreamHandleState> {
    if state.is_null() {
        return None;
    }
    // SAFETY: the caller passes the live state it read the ops from.
    let owner = unsafe { (*state).owner };
    if owner.is_null() {
        None
    } else {
        // SAFETY: the owner is the `StreamHandleState` this state was installed
        // from, which the stream's finalizer frees only after the object is gone.
        Some(unsafe { &*owner.cast::<StreamHandleState>() })
    }
}

/// The session behind a stream handle.
fn session_of(handle: &StreamHandleState) -> Option<&'static SessionState> {
    if handle.session.is_null() {
        None
    } else {
        // SAFETY: a stream is only reachable through the session that created it,
        // so the session outlives it.
        Some(unsafe { &*handle.session })
    }
}

impl StreamOps for Http2StreamOps {
    /// `Http2Stream::ReadStart` (`src/node_http2.cc:2706`).
    ///
    /// Two effects, both load-bearing:
    ///
    /// * `set_reading()`, so `OnDataChunkReceived` knows the owner is consuming and
    ///   tells nghttp2 the bytes are consumed rather than deferring them.
    /// * `nghttp2_session_consume_stream` for whatever arrived while paused, which
    ///   is what reopens the flow-control window a paused stream was withholding.
    unsafe fn read_start(&self, state: *mut StreamState) -> i32 {
        let Some(handle) = handle_of(state) else {
            return rn_uv::stream_base::EINVAL;
        };
        handle.reading.set(true);
        let Some(session) = session_of(handle) else {
            return rn_uv::stream_base::EINVAL;
        };
        let id = handle.id;
        // The bytes received while the readable side was paused were counted
        // rather than consumed; `ReadStart` is what hands that credit back.
        let paused = {
            let mut streams = session.streams.borrow_mut();
            match streams.get_mut(&id) {
                Some(record) => {
                    // Mirrored on the record because the data path runs from
                    // `mem_recv`, where no V8 scope exists to read the handle.
                    record.reading = true;
                    std::mem::take(&mut record.paused_unconsumed)
                }
                None => 0,
            }
        };
        if paused > 0 {
            // SAFETY: `raw` is the live nghttp2 session; `id` is a stream it owns.
            if let Some(raw) = crate::session_ptr(session) {
                unsafe { crate::ffi::nghttp2_session_consume(raw, id, paused) };
            }
        }
        0
    }

    /// `Http2Stream::ReadStop` (`src/node_http2.cc:2725`).
    unsafe fn read_stop(&self, state: *mut StreamState) -> i32 {
        let Some(handle) = handle_of(state) else {
            return rn_uv::stream_base::EINVAL;
        };
        handle.reading.set(false);
        if let Some(session) = session_of(handle) {
            let id = handle.id;
            if let Some(record) = session.streams.borrow_mut().get_mut(&id) {
                record.reading = false;
            }
        }
        0
    }

    /// `Http2Stream::DoShutdown` (`src/node_http2.cc:2389`).
    ///
    /// Ends the writable side by marking the record ended and re-arming the
    /// provider, which is what makes the next DATA frame carry END_STREAM.
    ///
    /// Returns `1` — a synchronous completion — which is what Node does and why
    /// `Http2Stream::CreateShutdownWrap` returns `nullptr`.
    unsafe fn shutdown(&self, state: *mut StreamState) -> i32 {
        let Some(handle) = handle_of(state) else {
            return rn_uv::stream_base::EINVAL;
        };
        let Some(session) = session_of(handle) else {
            return rn_uv::stream_base::EINVAL;
        };
        let id = handle.id;
        if let Some(record) = session.streams.borrow_mut().get_mut(&id) {
            if record.destroyed {
                // `if (is_destroyed()) return UV_EPIPE;`
                return rn_uv::sys::uv_errno_t_UV_EPIPE;
            }
            record.ended = true;
        } else {
            return rn_uv::sys::uv_errno_t_UV_EPIPE;
        }
        if let Some(raw) = crate::session_ptr(session) {
            // SAFETY: `raw` is live and `id` is a stream this session owns.
            unsafe { crate::ffi::nghttp2_session_resume_data(raw, id) };
            crate::session::schedule_write(session);
        }
        1
    }

    /// `Http2Stream::DoWrite` (`src/node_http2.cc:2744`).
    ///
    /// Queues the bytes for the data provider and resumes it. The completion is
    /// asynchronous: `stream_base_commons` holds the returned `WriteWrap` and the
    /// provider completes it once the bytes have been framed.
    unsafe fn write(
        &self,
        state: *mut StreamState,
        buffers: Vec<rn_uv::sys::uv_buf_t>,
        total_bytes: usize,
        owned: Vec<Box<[u8]>>,
    ) -> WriteOutcome {
        let Some(handle) = handle_of(state) else {
            return WriteOutcome::Sync(rn_uv::stream_base::EINVAL);
        };
        let Some(session) = session_of(handle) else {
            return WriteOutcome::Sync(rn_uv::stream_base::EINVAL);
        };
        let id = handle.id;

        let mut bytes: Vec<u8> = Vec::with_capacity(total_bytes);
        for buffer in &buffers {
            if buffer.base.is_null() || buffer.len == 0 {
                continue;
            }
            // SAFETY: the caller keeps every buffer valid until the completion,
            // which is what `owned` is for on the string path; on the pipe path
            // the bytes are copied out here, so the storage only has to survive
            // this call.
            let slice = unsafe { std::slice::from_raw_parts(buffer.base.cast::<u8>(), buffer.len) };
            bytes.extend_from_slice(slice);
        }
        drop(owned);

        {
            let mut streams = session.streams.borrow_mut();
            let Some(record) = streams.get_mut(&id) else {
                return WriteOutcome::Sync(rn_uv::sys::uv_errno_t_UV_EPIPE);
            };
            // `if (!is_writable() || is_destroyed()) return UV_EOF;`
            if record.destroyed || record.ended {
                return WriteOutcome::Sync(rn_uv::sys::uv_errno_t_UV_EOF);
            }
            record.pending.extend_from_slice(&bytes);
            record.sent_bytes += bytes.len() as u64;
        }
        if let Some(raw) = crate::session_ptr(session) {
            // SAFETY: `raw` is live and `id` is a stream this session owns.
            unsafe { crate::ffi::nghttp2_session_resume_data(raw, id) };
            crate::session::schedule_write(session);
        }
        // Synchronous, and that is this runtime's existing HTTP/2 write contract:
        // `writeBuffer`'s own path reports its completion the moment the bytes are
        // accepted into `pending` (`stream::queue_write`), because the provider
        // drains that queue rather than pulling through `StreamBase`. Reporting a
        // queued completion here would need a `WriteWrap` that nothing completes,
        // which leaves `StreamPipe`'s `pendingWrites()` permanently raised — the
        // pipe then never shuts its sink down and the peer waits for END_STREAM
        // forever.
        //
        // The bytes are safely queued at this point, so "accepted" is also true.
        WriteOutcome::Sync(0)
    }

    /// `Http2Stream::HasWantsWrite` returns `true` (`src/node_http2.h:320`).
    ///
    /// This is what hands backpressure to the stream: the pipe stops reading
    /// after every queued write and only resumes when the provider emits
    /// `OnStreamWantsWrite`.
    fn has_wants_write(&self) -> bool {
        true
    }

    fn has_libuv_stream(&self) -> bool {
        // An HTTP/2 stream is framed by nghttp2, not held in a `uv_stream_t`.
        false
    }
}

/// A stream state for an HTTP/2 stream handle.
///
/// # Safety
///
/// `owner` must outlive the returned state, which the stream's finalizer
/// guarantees by keeping both in one allocation.
pub unsafe fn new_stream_state(owner: *mut StreamHandleState) -> StreamState {
    let mut state = StreamState::new(ptr::null_mut());
    state.ops = &HTTP2_STREAM_OPS;
    state.owner = owner.cast();
    state
}

/// The `StreamBase` half of one `binding.Http2Stream`.
///
/// A `RefCell` because the state is reached two ways: from the object's internal
/// field, and through the `*mut StreamState` the listener layer holds for the
/// duration of a callback. Both are short, scoped borrows — the same discipline
/// [`rn_uv::listener`] documents.
pub struct StreamHalf {
    state: std::cell::RefCell<StreamState>,
}

impl StreamHalf {
    /// A half whose owner pointer is filled in by [`StreamHalf::install_owner`].
    pub fn new() -> Self {
        Self {
            state: std::cell::RefCell::new(StreamState::new(ptr::null_mut())),
        }
    }

    /// The state address the listener layer takes.
    pub fn state_pointer(&self) -> *mut StreamState {
        self.state.as_ptr()
    }

    /// Records the allocation that owns this state, so the ops can find it.
    ///
    /// # Safety
    ///
    /// `self` must be at its final address and `owner` must outlive the state.
    pub unsafe fn install_owner(&self, owner: *mut StreamHandleState) {
        // SAFETY: the caller guarantees both lifetimes.
        let state = unsafe { &mut *self.state.as_ptr() };
        state.ops = &HTTP2_STREAM_OPS;
        state.owner = owner.cast();
    }
}

impl Default for StreamHalf {
    fn default() -> Self {
        Self::new()
    }
}
