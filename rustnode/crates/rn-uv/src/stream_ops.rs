//! What a `StreamPipe` needs from a stream, independent of libuv.
//!
//! `src/stream_pipe.cc` drives a `StreamBase*`, not a `uv_stream_t*`. That
//! distinction is load-bearing: Node accepts a `FileHandle` (`AsyncWrap +
//! StreamBase`) and a `binding.Http2Stream` (`AsyncWrap + StreamBase`) as either
//! end of a pipe, and neither owns a libuv stream. `StreamPipe::New` only checks
//! that both arguments are objects and that `StreamBase::FromObject` finds a
//! `StreamBase`; what happens next is four virtual calls —
//! `ReadStart`/`ReadStop`, `Write`, `Shutdown` and `HasWantsWrite`.
//!
//! rustnode had no such indirection: [`crate::stream`] calls libuv directly and
//! `rn-bind-stream-pipe` reached for the `uv_stream_t` behind each handle. So a
//! pipe over two non-socket streams could not exist, and the type check was the
//! only thing standing between a caller and a null pointer.
//!
//! This module is that indirection. [`StreamState`] carries a [`StreamOps`], and
//! the bindings that already own a `uv_stream_t` keep the default
//! [`LibuvStreamOps`] — so a socket behaves exactly as before — while a
//! `FileHandle` or an `Http2Stream` installs its own.
//!
//! # Why a `&'static` vtable rather than a trait object per stream
//!
//! The implementation for a given stream kind is a zero-sized type chosen once
//! when the handle is created, so a `&'static dyn StreamOps` costs one pointer and
//! no allocation. It also keeps [`StreamState`] `Send`-agnostic and free of
//! lifetime parameters, which every existing constructor call site depends on.
//!
//! # The write contract
//!
//! [`StreamOps::write`] reports whether a completion is still owed. Node's
//! `StreamBase::Write` returns `StreamWriteResult{async, err, wrap, ...}`, and
//! `StreamPipe::ProcessData` branches on it:
//!
//! ```cpp
//! StreamWriteResult res = sink()->Write(&buffer, 1);
//! pending_writes_++;
//! if (!res.async) {
//!   writable_listener_.OnStreamAfterWrite(nullptr, res.err);
//! } else {
//!   is_reading_ = false;
//!   ...
//! }
//! ```
//!
//! A synchronous completion therefore has to be reported to the pipe *inline*,
//! including a failing one. Returning only a status, as the pre-existing
//! `queue_write_unowned` call did, loses the difference between "finished" and
//! "queued" and makes the write counter drift.

use libuv_sys2 as uv;

use crate::handle::StreamState;

/// What a write did, in the shape `StreamPipe::ProcessData` branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The write finished inside the call. No completion will arrive, so the
    /// caller must run its completion path itself.
    Sync(i32),
    /// The write was accepted and its completion will be delivered through the
    /// stream's listener chain via [`crate::listener::emit_after_write`].
    Queued,
}

/// The four virtual methods `StreamBase` gives a `StreamPipe`.
///
/// Every method takes the `*mut StreamState` rather than `&mut StreamState`
/// because the listener layer's borrow rule applies here too: a write completion
/// can run JavaScript, which can close or destroy the very stream being written
/// to.
pub trait StreamOps: Send + Sync {
    /// `StreamBase::ReadStart`.
    ///
    /// # Safety
    ///
    /// `state` must be the live state this ops value was read from.
    unsafe fn read_start(&self, state: *mut StreamState) -> i32;

    /// `StreamBase::ReadStop`.
    ///
    /// # Safety
    ///
    /// `state` must be the live state this ops value was read from.
    unsafe fn read_stop(&self, state: *mut StreamState) -> i32;

    /// `StreamBase::Shutdown` — end this stream's writable side.
    ///
    /// Returns `1` when it finished synchronously (Node's
    /// `StreamBase::Shutdown` "1 in case of a synchronous completion"), `0` when a
    /// completion is owed, or a negative libuv error.
    ///
    /// # Safety
    ///
    /// `state` must be the live state this ops value was read from.
    unsafe fn shutdown(&self, state: *mut StreamState) -> i32;

    /// `StreamBase::Write` for the one-buffer case a pipe uses.
    ///
    /// `owned` keeps the bytes alive until the completion fires and is dropped
    /// when the write finishes synchronously.
    ///
    /// # Safety
    ///
    /// `state` must be the live state this ops value was read from, and every
    /// buffer must point into `owned` or at storage the caller keeps alive until
    /// the completion.
    unsafe fn write(
        &self,
        state: *mut StreamState,
        buffers: Vec<uv::uv_buf_t>,
        total_bytes: usize,
        owned: Vec<Box<[u8]>>,
    ) -> WriteOutcome;

    /// `StreamBase::HasWantsWrite`.
    ///
    /// A stream that reports it receives `OnStreamWantsWrite` instead of the pipe
    /// resuming the source itself, which is what lets an `Http2Stream` apply its
    /// own backpressure.
    fn has_wants_write(&self) -> bool {
        false
    }

    /// Whether a `uv_stream_t` is behind this state, for the paths that genuinely
    /// need one (`uv_fileno`, `uv_is_closing`, `uv_ref`).
    fn has_libuv_stream(&self) -> bool {
        true
    }
}

/// The default: a stream backed by a libuv handle, which is every socket.
pub struct LibuvStreamOps;

/// The one [`LibuvStreamOps`] instance every socket state points at.
pub static LIBUV_STREAM_OPS: LibuvStreamOps = LibuvStreamOps;

impl StreamOps for LibuvStreamOps {
    unsafe fn read_start(&self, state: *mut StreamState) -> i32 {
        if state.is_null() {
            return crate::stream_base::EINVAL;
        }
        // SAFETY: the caller passes the live state it read the ops from.
        let state_ref = unsafe { &*state };
        let stream = state_ref.stream;
        if stream.is_null() {
            return crate::stream_base::EINVAL;
        }
        // SAFETY: the state owns a live stream for as long as it exists.
        unsafe { crate::stream::read_start(stream, state) }
    }

    unsafe fn read_stop(&self, state: *mut StreamState) -> i32 {
        if state.is_null() {
            return crate::stream_base::EINVAL;
        }
        // SAFETY: as above.
        let stream = unsafe { (*state).stream };
        if stream.is_null() {
            return crate::stream_base::EINVAL;
        }
        // SAFETY: a live stream, per the state's contract.
        unsafe { crate::stream::read_stop(stream) }
    }

    unsafe fn shutdown(&self, state: *mut StreamState) -> i32 {
        if state.is_null() {
            return crate::stream_base::EINVAL;
        }
        // SAFETY: as above.
        let stream = unsafe { (*state).stream };
        if stream.is_null() {
            return crate::stream_base::EINVAL;
        }
        // `uv_shutdown` reports UV_ENOTCONN on a stream that never connected,
        // which a socket treats as "nothing to flush" — the same value
        // `StreamBase::Shutdown` passes back.
        let status = unsafe { crate::stream::end_stream(stream) };
        // `uv_shutdown` always queues its completion, so this is never the
        // synchronous form; a non-zero status means it never queued at all.
        if status == 0 {
            0
        } else {
            status
        }
    }

    unsafe fn write(
        &self,
        state: *mut StreamState,
        mut buffers: Vec<uv::uv_buf_t>,
        total_bytes: usize,
        owned: Vec<Box<[u8]>>,
    ) -> WriteOutcome {
        if state.is_null() || buffers.is_empty() {
            return WriteOutcome::Sync(crate::stream_base::EINVAL);
        }
        // SAFETY: as above; the state is live for the call.
        let stream = unsafe { (*state).stream };
        if stream.is_null() {
            return WriteOutcome::Sync(crate::stream_base::EINVAL);
        }

        // `StreamBase::Write` tries `DoTryWrite` first, and a stream that accepts
        // everything completes without ever creating a request. A pipe depends on
        // this: an outstanding `uv_write_t` holds the loop open.
        // SAFETY: the stream is live and every buffer points into `owned` or into
        // storage the caller keeps alive for the call.
        let written = unsafe { crate::stream::try_write(stream, &mut buffers) };
        if written >= total_bytes {
            // Synchronous success. `owned` served its purpose.
            drop(owned);
            return WriteOutcome::Sync(0);
        }

        // Slice off what landed, exactly as `DoTryWrite`'s caller does.
        let remaining = after_partial_write(buffers, written);
        let pending: usize = remaining.iter().map(|buffer| buffer.len).sum();
        // SAFETY: `stream` is live; `owned` keeps the bytes valid until the
        // completion, which frees it.
        let status =
            unsafe { crate::stream::queue_write_unowned(stream, remaining, pending, owned) };
        if status == 0 {
            WriteOutcome::Queued
        } else {
            WriteOutcome::Sync(status)
        }
    }
}

/// Drops the buffers `uv_try_write` fully consumed and trims a partial one.
///
/// This is the same walk [`crate::stream_base`]'s private `after_partial_write`
/// performs; it lives here as well because the ops path must produce the tail
/// *before* handing the list to `uv_write`, and that helper is written against the
/// binding-facing `WriteBuffers` enum.
fn after_partial_write(buffers: Vec<uv::uv_buf_t>, written: usize) -> Vec<uv::uv_buf_t> {
    let mut buffers = buffers;
    let mut remaining = written;
    let mut start = 0;
    while start < buffers.len() {
        if buffers[start].len > remaining {
            // SAFETY: `remaining` is less than this buffer's length, so the tail
            // stays inside the allocation the caller provided.
            buffers[start] = uv::uv_buf_t {
                base: unsafe { buffers[start].base.add(remaining) },
                len: buffers[start].len - remaining,
            };
            break;
        }
        remaining -= buffers[start].len;
        start += 1;
    }
    buffers.drain(..start);
    buffers
}

/// The ops for a state whose stream is a specific implementation.
///
/// Returns the default for a state that predates this module or was built by a
/// binding with no opinion, which keeps every existing socket on the libuv path.
///
/// # Safety
///
/// `state` must be live, or null.
pub unsafe fn ops_of(state: *mut StreamState) -> &'static dyn StreamOps {
    if state.is_null() {
        return &LIBUV_STREAM_OPS;
    }
    // SAFETY: the caller guarantees the state is live.
    unsafe { (*state).ops }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn a_fresh_state_reports_the_libuv_ops() {
        // Every socket constructor goes through `StreamState::new`, so this is
        // what keeps `tcp_wrap` and `pipe_wrap` on the path they already had.
        let state = StreamState::new(ptr::null_mut());
        assert!(state.ops.has_libuv_stream());
        assert!(!state.ops.has_wants_write());
    }

    #[test]
    fn a_null_stream_reports_einval_rather_than_crashing() {
        // A `JSStream` or a consumed `TLSWrap` has a state with no libuv handle.
        // Before the ops indirection existed these were unrepresentable; the
        // guard is what a caller that reaches them anyway gets.
        let mut state = StreamState::new(ptr::null_mut());
        let pointer = &mut state as *mut StreamState;
        // SAFETY: `pointer` names a live state for the whole test.
        let ops = unsafe { ops_of(pointer) };
        // SAFETY: as above; every call passes the same live state.
        unsafe {
            assert_eq!(ops.read_start(pointer), crate::stream_base::EINVAL);
            assert_eq!(ops.read_stop(pointer), crate::stream_base::EINVAL);
            assert_eq!(ops.shutdown(pointer), crate::stream_base::EINVAL);
            assert_eq!(
                ops.write(pointer, Vec::new(), 0, Vec::new()),
                WriteOutcome::Sync(crate::stream_base::EINVAL)
            );
        }
    }

    #[test]
    fn a_partial_write_keeps_only_the_tail() {
        // `DoTryWrite`'s caller contract: fully written buffers are discarded and
        // the partly written one keeps its remainder.
        let mut first = vec![1u8, 2, 3, 4];
        let mut second = vec![5u8, 6, 7];
        let buffers = vec![
            uv::uv_buf_t {
                base: first.as_mut_ptr().cast(),
                len: first.len(),
            },
            uv::uv_buf_t {
                base: second.as_mut_ptr().cast(),
                len: second.len(),
            },
        ];
        // 6 bytes landed: the first buffer is gone and two bytes of the second.
        let remaining = after_partial_write(buffers, 6);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].len, 1);
        assert_eq!(
            remaining[0].base,
            // SAFETY: the tail is inside `second`'s allocation.
            unsafe { second.as_mut_ptr().add(2) }.cast()
        );
    }

    #[test]
    fn a_complete_write_leaves_nothing() {
        let mut buffer = vec![0u8; 4];
        let buffers = vec![uv::uv_buf_t {
            base: buffer.as_mut_ptr().cast(),
            len: buffer.len(),
        }];
        assert!(after_partial_write(buffers, 4).is_empty());
    }
}
