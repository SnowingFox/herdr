//! The nghttp2 data provider: how a stream's body bytes reach a DATA frame.
//!
//! `Http2Stream::Provider::Stream` in `src/node_http2.cc` is a
//! `nghttp2_data_provider` whose read callback nghttp2 calls when it wants body
//! bytes for a stream. The callback receives a buffer to fill and reports how many
//! bytes it wrote, plus `NGHTTP2_DATA_FLAG_EOF` when there are no more.
//!
//! # Where the bytes come from
//!
//! Node's provider reads from the `Http2Stream`'s `StreamBase` — the writable
//! `Duplex` `core.js` built around the stream — through `ReadStart` and its own
//! pause/resume machinery, so a slow producer is backpressured by nghttp2 rather
//! than buffered here.
//!
//! rustnode's `Duplex` is JavaScript, and `writeBuffer` already copied the bytes
//! into the stream's pending queue by the time nghttp2 asks. So the provider drains
//! that queue. The observable difference is one buffer of memory per stream rather
//! than a pull through `StreamBase`; the wire behaviour is the same, because nghttp2
//! still decides how many bytes go into each frame.
//!
//! # Why an empty queue is not EOF
//!
//! Reporting `EOF` the moment the queue empties would end the stream on the first
//! frame, before `core.js` had a chance to write a second chunk — which is exactly
//! what a chunked response does. An empty queue therefore reports
//! `NGHTTP2_ERR_DEFERRED`, asking nghttp2 to come back, and
//! [`crate::session::schedule_write`] is what makes it come back when more arrives.
//! `EOF` is reported only for a stream whose `ended` flag is set, which `shutdown()`
//! and `end()` set.

use std::ptr;

use crate::ffi;
use crate::session::SessionState;

/// `NGHTTP2_DATA_FLAG_EOF`.
pub const DATA_FLAG_EOF: u32 = 0x01;
/// `NGHTTP2_ERR_DEFERRED`, which asks nghttp2 to retry later.
pub const ERR_DEFERRED: isize = -508;

/// A provider, owned for the duration of one `nghttp2_submit_*` call.
pub struct Provider {
    raw: ffi::nghttp2_data_provider2,
}

impl Provider {
    /// A provider that drains the stream's `pending` queue.
    pub fn new(session: &SessionState, _stream_id: i32, _options: i32) -> Self {
        // `nghttp2_data_source.ptr` is how a read callback finds its own session.
        // Node stores the `Http2Stream*`; here it is the session, because the
        // stream id arrives as a callback argument and the queue lives on the
        // stream handle the session holds.
        let source = ffi::nghttp2_data_source {
            ptr: (session as *const SessionState).cast_mut().cast(),
        };
        Self {
            raw: ffi::nghttp2_data_provider2 {
                source,
                read_callback: Some(read_callback),
            },
        }
    }

    /// The zero-length form `shutdown()` submits.
    ///
    /// A provider whose read callback reports EOF immediately with no bytes is how
    /// an empty DATA frame carrying END_STREAM is produced.
    pub fn end_stream() -> Self {
        Self {
            raw: ffi::nghttp2_data_provider2 {
                source: ffi::nghttp2_data_source {
                    ptr: ptr::null_mut(),
                },
                read_callback: Some(empty_read_callback),
            },
        }
    }

    /// The provider, for `nghttp2_submit_response2` / `nghttp2_submit_data2`.
    pub fn as_ptr(&self) -> *const ffi::nghttp2_data_provider2 {
        &self.raw
    }
}

/// The read callback: fill `buf` from the stream's pending bytes.
///
/// # Safety
///
/// Called by nghttp2 with `buf` writable for `length` bytes and `data_flags` for one
/// `u32`.
unsafe extern "C" fn read_callback(
    _session: *mut ffi::nghttp2_session,
    stream_id: i32,
    buf: *mut u8,
    length: usize,
    data_flags: *mut u32,
    source: *mut ffi::nghttp2_data_source,
    _user_data: *mut std::ffi::c_void,
) -> isize {
    if source.is_null() || buf.is_null() || data_flags.is_null() {
        return ERR_DEFERRED;
    }
    // SAFETY: `Provider::new` stored the `SessionState` pointer in `source.ptr`,
    // and the state outlives the nghttp2 session that is asking.
    let state = unsafe { (*source).ptr };
    if state.is_null() {
        return ERR_DEFERRED;
    }
    // SAFETY: as above; this is the state the provider was built from.
    let state = unsafe { &*state.cast::<SessionState>() };

    let Some((bytes, ended)) = crate::stream::take_pending(state, stream_id, length) else {
        // No handle for this stream means it closed under us. EOF lets nghttp2
        // finish the frame and close the stream rather than retry forever.
        // SAFETY: `data_flags` is writable per this callback's contract.
        unsafe { *data_flags |= DATA_FLAG_EOF };
        return 0;
    };
    if bytes.is_empty() {
        if ended {
            // SAFETY: `data_flags` is writable per this callback's contract.
            unsafe { *data_flags |= DATA_FLAG_EOF };
            return 0;
        }
        return ERR_DEFERRED;
    }
    let count = bytes.len().min(length);
    // SAFETY: `buf` is writable for `length` bytes and `count <= length`.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, count);
    }
    if ended && count == bytes.len() {
        // SAFETY: `data_flags` is writable per this callback's contract.
        unsafe { *data_flags |= DATA_FLAG_EOF };
    }
    count as isize
}

/// The zero-length read callback: always EOF, never any bytes.
///
/// # Safety
///
/// As [`read_callback`].
unsafe extern "C" fn empty_read_callback(
    _session: *mut ffi::nghttp2_session,
    _stream_id: i32,
    _buf: *mut u8,
    _length: usize,
    data_flags: *mut u32,
    _source: *mut ffi::nghttp2_data_source,
    _user_data: *mut std::ffi::c_void,
) -> isize {
    if !data_flags.is_null() {
        // SAFETY: `data_flags` is writable per this callback's contract.
        unsafe { *data_flags |= DATA_FLAG_EOF };
    }
    0
}
