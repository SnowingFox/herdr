//! The nghttp2 callback table, and the C-ABI trampolines that reach JavaScript.
//!
//! `Http2Session::Callbacks` in `src/node_http2.cc` is one `nghttp2_session_callbacks`
//! with eleven setters. Each trampoline receives a `user_data` pointer — the
//! `Http2Session*` in Node, the [`crate::session::SessionState`] here — and calls
//! one of the eleven functions `lib/internal/http2/core.js` installed through
//! `setCallbackFunctions`.
//!
//! # Why `user_data` and not a Rust closure
//!
//! nghttp2 is C and has no closure. Node uses `static_cast<Http2Session*>(user_data)`
//! for the same reason. The pointer is the address of the `SessionState` box, which
//! is stable for the session's life.
//!
//! # Re-entering V8
//!
//! A trampoline runs on the isolate's thread, inside `nghttp2_session_mem_recv`
//! or `mem_send`, which itself runs inside a libuv read or write completion. That
//! means a scope and an entered context are needed, exactly as
//! [`rn_uv::callback::with_context`] provides. It is not optional: calling into V8
//! without one crashes.
//!
//! # Errors
//!
//! Every callback returns an `nghttp2` status. `0` means "continue". A callback
//! that cannot reach JavaScript returns `NGHTTP2_ERR_CALLBACK_FAILURE`, which makes
//! nghttp2 abort the operation — that is what Node does when a `MakeCallback`
//! returns empty.

use std::ffi::c_void;
use std::ptr;

use rn_v8_sys::v8;

use crate::ffi;
use crate::session::SessionState;

/// `NGHTTP2_ERR_CALLBACK_FAILURE`, which aborts the current nghttp2 operation.
const CALLBACK_FAILURE: std::os::raw::c_int = -902;
/// `NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`, which resets the stream.
const TEMPORAL_CALLBACK_FAILURE: std::os::raw::c_int = -521;

/// The callback table plus the eleven setters `Http2Session::Callbacks` performs.
pub struct Callbacks {
    table: *mut ffi::nghttp2_session_callbacks,
}

// SAFETY: the table is only ever used from the isolate's thread, and nghttp2 does
// not move or free it while a session holds it.
unsafe impl Send for Callbacks {}

impl Callbacks {
    /// Builds a fully populated callback table.
    pub fn new() -> Result<Self, String> {
        let mut table: *mut ffi::nghttp2_session_callbacks = ptr::null_mut();
        // SAFETY: `table` is an out-parameter and the call only writes to it.
        let status = unsafe { ffi::nghttp2_session_callbacks_new(&mut table) };
        if status != 0 || table.is_null() {
            return Err(format!(
                "nghttp2_session_callbacks_new failed with {status}"
            ));
        }
        // SAFETY: `table` is live and every setter below only stores into it.
        unsafe {
            ffi::nghttp2_session_callbacks_set_on_begin_headers_callback(
                table,
                Some(on_begin_headers),
            );
            ffi::nghttp2_session_callbacks_set_on_header_callback2(table, Some(on_header));
            ffi::nghttp2_session_callbacks_set_on_frame_recv_callback(table, Some(on_frame_recv));
            ffi::nghttp2_session_callbacks_set_on_stream_close_callback(
                table,
                Some(on_stream_close),
            );
            ffi::nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
                table,
                Some(on_data_chunk),
            );
            ffi::nghttp2_session_callbacks_set_on_frame_not_send_callback(
                table,
                Some(on_frame_not_sent),
            );
            ffi::nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
                table,
                Some(on_invalid_frame),
            );
            ffi::nghttp2_session_callbacks_set_error_callback2(table, Some(on_nghttp_error));
            ffi::nghttp2_session_callbacks_set_on_frame_send_callback(table, Some(on_frame_sent));
        }
        Ok(Self { table })
    }

    /// The table, for `nghttp2_session_*_new2`.
    pub fn as_ptr(&self) -> *const ffi::nghttp2_session_callbacks {
        self.table
    }
}

impl Drop for Callbacks {
    fn drop(&mut self) {
        if !self.table.is_null() {
            // SAFETY: `table` came from `nghttp2_session_callbacks_new` and is
            // freed exactly once, after every session that referenced it is gone.
            unsafe { ffi::nghttp2_session_callbacks_del(self.table) };
        }
    }
}

/// `static_cast<Http2Session*>(user_data)`, as the state behind the session.
///
/// # Safety
///
/// `user_data` must be the pointer `SessionState::attach` stored in the nghttp2
/// session, so it is a live `SessionState`.
unsafe fn session_of(user_data: *mut c_void) -> Option<&'static SessionState> {
    if user_data.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `user_data` is the state behind the session
    // whose callback this is, and that state lives until the session is freed.
    Some(unsafe { &*user_data.cast::<SessionState>() })
}

/// Calls one of `core.js`'s session callbacks with `args`.
///
/// The receiver is the session's JS object, which is what `this[kOwner]` reads in
/// `core.js`. A missing callback or a missing object is not an error: it is the
/// state before `core.js` finished loading, and Node's per-callback guards do the
/// same thing.
///
/// Returns whether the call happened.
fn call_callback(
    scope: &mut v8::PinScope<'_, '_>,
    state: &SessionState,
    pick: impl FnOnce(&crate::SessionCallbacks) -> Option<v8::Global<v8::Function>>,
    args: &[v8::Local<'_, v8::Value>],
) -> bool {
    let Some(object) = crate::session_object(scope, state) else {
        return false;
    };
    let Some(callback) = pick_global(pick) else {
        return false;
    };
    let callback = v8::Local::new(scope, callback);
    callback.call(scope, object.into(), args).is_some()
}

/// Reads one callback out of the process-wide table.
///
/// Named with the `_global` suffix so it cannot be confused with the `pick`
/// parameter of [`call_callback`], which is a chooser rather than the lookup.
pub(crate) fn pick_global(
    chooser: impl FnOnce(&crate::SessionCallbacks) -> Option<v8::Global<v8::Function>>,
) -> Option<v8::Global<v8::Function>> {
    crate::with_callbacks(chooser)
}

/// `OnBeginHeadersCallback`: a HEADERS block started for `frame`'s stream.
///
/// Creates the stream record if this is a new stream, so the header callback that
/// follows has somewhere to put its pairs. Trailers reuse the existing record,
/// which is what `StartHeaders` does.
unsafe extern "C" fn on_begin_headers(
    _session: *mut ffi::nghttp2_session,
    frame: *const ffi::nghttp2_frame,
    user_data: *mut c_void,
) -> std::os::raw::c_int {
    // SAFETY: nghttp2 passes back the `user_data` the session was created with,
    // and the frame pointer is valid for the duration of the callback.
    let Some(state) = (unsafe { session_of(user_data) }) else {
        return CALLBACK_FAILURE;
    };
    if frame.is_null() {
        return CALLBACK_FAILURE;
    }
    // SAFETY: `frame` is a live frame of type HEADERS for this callback.
    let hd = unsafe { (*frame).hd };
    let category = unsafe { (*frame).headers.cat };

    if state.closing.get() {
        // Node refuses a new stream while closing, because the JS wrapper would
        // never get an `onread` and the DATA frames that follow would arrive with
        // nowhere to go.
        if let Some(raw) = crate::session_ptr(state) {
            // SAFETY: `raw` is a live nghttp2 session.
            unsafe {
                ffi::nghttp2_submit_rst_stream(
                    raw,
                    ffi::NGHTTP2_FLAG_NONE,
                    hd.stream_id,
                    ffi::NGHTTP2_REFUSED_STREAM_CODE,
                );
            }
        }
        return TEMPORAL_CALLBACK_FAILURE;
    }

    let mut streams = state.streams.borrow_mut();
    match streams.get_mut(&hd.stream_id) {
        Some(record) => {
            // Trailers: reuse the record, as `StartHeaders` does.
            record.category = category;
            record.headers.clear();
        }
        None => {
            streams.insert(
                hd.stream_id,
                crate::session::StreamRecord {
                    id: hd.stream_id,
                    category,
                    ..Default::default()
                },
            );
        }
    }
    0
}

/// `OnHeaderCallback`: one header pair. Appends to the stream's pending block.
unsafe extern "C" fn on_header(
    _session: *mut ffi::nghttp2_session,
    frame: *const ffi::nghttp2_frame,
    name: *mut ffi::nghttp2_rcbuf,
    value: *mut ffi::nghttp2_rcbuf,
    flags: u8,
    user_data: *mut c_void,
) -> std::os::raw::c_int {
    // SAFETY: as `on_begin_headers`.
    let Some(state) = (unsafe { session_of(user_data) }) else {
        return CALLBACK_FAILURE;
    };
    if frame.is_null() {
        return CALLBACK_FAILURE;
    }
    // SAFETY: `frame` is live and `name`/`value` are rcbufs nghttp2 owns for the
    // duration of this callback.
    let stream_id = unsafe { (*frame).hd.stream_id };
    // SAFETY: `nghttp2_rcbuf_get_buf` only reads the rcbuf it is given.
    let name_bytes = unsafe { ffi::nghttp2_rcbuf_get_buf(name) };
    // SAFETY: as above.
    let value_bytes = unsafe { ffi::nghttp2_rcbuf_get_buf(value) };
    // SAFETY: both bases point at `len` bytes owned by the rcbufs, live for this
    // call, so the copies below stay inside them.
    let (name_copy, value_copy) = unsafe {
        (
            slice_of(name_bytes).to_vec(),
            slice_of(value_bytes).to_vec(),
        )
    };

    let mut streams = state.streams.borrow_mut();
    let max = state.max_header_pairs.get() as usize;
    let Some(record) = streams.get_mut(&stream_id) else {
        // The stream was closed while its headers were arriving, which
        // `on_header` reports as a temporal failure so nghttp2 resets it.
        return TEMPORAL_CALLBACK_FAILURE;
    };
    if record.destroyed || record.headers.len() >= max {
        return TEMPORAL_CALLBACK_FAILURE;
    }
    record.headers.push((name_copy, value_copy, flags));
    0
}

/// Copies an `nghttp2_vec` into a slice, treating a null base as empty.
///
/// # Safety
///
/// `vector.base` must point at `vector.len` readable bytes, or be null.
unsafe fn slice_of(vector: ffi::nghttp2_vec) -> &'static [u8] {
    if vector.base.is_null() || vector.len == 0 {
        return &[];
    }
    // SAFETY: the caller guarantees the range is readable, and nghttp2's rcbufs
    // outlive the callback that reads them.
    unsafe { std::slice::from_raw_parts(vector.base, vector.len) }
}

/// `OnFrameReceive`: dispatch a complete frame to `core.js`.
unsafe extern "C" fn on_frame_recv(
    _session: *mut ffi::nghttp2_session,
    frame: *const ffi::nghttp2_frame,
    user_data: *mut c_void,
) -> std::os::raw::c_int {
    // SAFETY: as `on_begin_headers`.
    let Some(state) = (unsafe { session_of(user_data) }) else {
        return CALLBACK_FAILURE;
    };
    if frame.is_null() {
        return CALLBACK_FAILURE;
    }
    // SAFETY: `frame` is live for this callback.
    let hd = unsafe { (*frame).hd };
    match hd.type_ {
        ffi::NGHTTP2_HEADERS => handle_headers_frame(state, frame),
        ffi::NGHTTP2_DATA => handle_data_frame(state, frame),
        ffi::NGHTTP2_SETTINGS => {
            // Only a non-ACK SETTINGS frame reports new remote settings; an ACK is
            // the peer confirming ours, which is not a change.
            if hd.flags & ffi::NGHTTP2_FLAG_ACK == 0 {
                let _ = rn_uv::callback::with_context(|scope| {
                    call_callback(scope, state, |callbacks| callbacks.settings.clone(), &[]);
                });
            }
            0
        }
        ffi::NGHTTP2_PING => {
            // `frame->ping.opaque_data` is the eight-byte ping payload.
            // SAFETY: a PING frame's `ping` member is the live variant.
            let payload = unsafe { (*frame).ping.opaque_data };
            let _ = rn_uv::callback::with_context(|scope| {
                let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(
                    payload.to_vec().into_boxed_slice(),
                );
                let store: v8::SharedRef<v8::BackingStore> = store.into();
                let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
                let value: v8::Local<v8::Value> = buffer.into();
                call_callback(scope, state, |callbacks| callbacks.ping.clone(), &[value]);
            });
            0
        }
        ffi::NGHTTP2_GOAWAY => {
            // SAFETY: a GOAWAY frame's `goaway` member is the live variant.
            let goaway = unsafe { (*frame).goaway };
            let _ = rn_uv::callback::with_context(|scope| {
                let args = [
                    v8::Integer::new(scope, goaway.error_code as i32).into(),
                    v8::Integer::new(scope, goaway.last_stream_id).into(),
                ];
                call_callback(
                    scope,
                    state,
                    |callbacks| callbacks.goaway_data.clone(),
                    &args,
                );
            });
            0
        }
        ffi::NGHTTP2_RST_STREAM if hd.stream_id > 0 => {
            // Stamp the stream so `onStreamClose` can tell a peer reset apart from
            // a natural close: both surface through `on_stream_close`.
            if let Some(record) = state.streams.borrow_mut().get_mut(&hd.stream_id) {
                record.peer_reset = true;
            }
            0
        }
        _ => 0,
    }
}

/// `HandleHeadersFrame`: hand the collected header block to `onSessionHeaders`.
fn handle_headers_frame(
    state: &SessionState,
    frame: *const ffi::nghttp2_frame,
) -> std::os::raw::c_int {
    // SAFETY: `frame` is a HEADERS frame for this callback.
    let (hd, category) = unsafe { ((*frame).hd, (*frame).headers.cat) };
    let (headers, options) = {
        let streams = state.streams.borrow();
        match streams.get(&hd.stream_id) {
            Some(record) => (record.headers.clone(), record.options),
            None => return 0,
        }
    };

    // `handle` in `core.js` is a *stream* handle, and the JS side builds the
    // `ServerHttp2Stream`/`ClientHttp2Stream` around it. The handle is created
    // lazily by `crate::stream::handle_for`, which needs the session object.
    let outcome = rn_uv::callback::with_context(|scope| {
        let Some(handle) = crate::stream::handle_for(scope, state, hd.stream_id, category, options)
        else {
            return false;
        };
        let Some(headers_array) = headers_to_array(scope, &headers) else {
            return false;
        };
        let sensitive = v8::Array::new(scope, 0);
        let args = [
            handle.into(),
            v8::Integer::new(scope, hd.stream_id).into(),
            v8::Integer::new(scope, category).into(),
            v8::Integer::new(scope, i32::from(hd.flags)).into(),
            headers_array.into(),
            sensitive.into(),
        ];
        call_callback(scope, state, |callbacks| callbacks.headers.clone(), &args)
    })
    .unwrap_or(false);

    if outcome {
        // The block has been delivered; a trailer block starts empty.
        if let Some(record) = state.streams.borrow_mut().get_mut(&hd.stream_id) {
            record.headers.clear();
        }
        0
    } else {
        // `core.js` was not reachable. Destroying the stream is what Node's
        // empty `MakeCallback` result amounts to.
        TEMPORAL_CALLBACK_FAILURE
    }
}

/// `HandleDataFrame`: forward a DATA frame's bytes to the stream's readable side.
fn handle_data_frame(
    state: &SessionState,
    frame: *const ffi::nghttp2_frame,
) -> std::os::raw::c_int {
    // SAFETY: `frame` is a DATA frame for this callback.
    let hd = unsafe { (*frame).hd };
    let end_stream = hd.flags & ffi::NGHTTP2_FLAG_END_STREAM != 0;
    if end_stream {
        // `EmitRead` with EOF on the stream's own `StreamBase`, which is what ends
        // the readable side. Chunks arrived through `on_data_chunk`.
        crate::stream::emit_eof(state, hd.stream_id);
    }
    0
}

/// `OnDataChunkReceived`: the bytes of a DATA frame.
unsafe extern "C" fn on_data_chunk(
    _session: *mut ffi::nghttp2_session,
    _flags: u8,
    stream_id: i32,
    data: *const u8,
    len: usize,
    user_data: *mut c_void,
) -> std::os::raw::c_int {
    // SAFETY: as `on_begin_headers`.
    let Some(state) = (unsafe { session_of(user_data) }) else {
        return CALLBACK_FAILURE;
    };
    if data.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: nghttp2 guarantees `data` points at `len` readable bytes for the
    // duration of this callback.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    crate::stream::deliver_data(state, stream_id, bytes);
    0
}

/// `OnStreamClose`: nghttp2 finished with a stream.
unsafe extern "C" fn on_stream_close(
    _session: *mut ffi::nghttp2_session,
    stream_id: i32,
    error_code: u32,
    user_data: *mut c_void,
) -> std::os::raw::c_int {
    // SAFETY: as `on_begin_headers`.
    let Some(state) = (unsafe { session_of(user_data) }) else {
        return CALLBACK_FAILURE;
    };
    let peer_reset = {
        let mut streams = state.streams.borrow_mut();
        match streams.remove(&stream_id) {
            Some(record) => record.peer_reset,
            None => false,
        }
    };
    let _ = rn_uv::callback::with_context(|scope| {
        let args = [
            v8::Integer::new(scope, error_code as i32).into(),
            v8::Boolean::new(scope, peer_reset).into(),
        ];
        crate::stream::call_stream_callback(
            scope,
            state,
            stream_id,
            |callbacks| callbacks.stream_close.clone(),
            &args,
        );
    });
    0
}

/// `OnInvalidFrame`: nghttp2 rejected a frame.
unsafe extern "C" fn on_invalid_frame(
    _session: *mut ffi::nghttp2_session,
    frame: *const ffi::nghttp2_frame,
    lib_error_code: std::os::raw::c_int,
    user_data: *mut c_void,
) -> std::os::raw::c_int {
    // SAFETY: as `on_begin_headers`.
    let Some(state) = (unsafe { session_of(user_data) }) else {
        return CALLBACK_FAILURE;
    };
    if frame.is_null() {
        return CALLBACK_FAILURE;
    }
    // SAFETY: `frame` is live for this callback.
    let hd = unsafe { (*frame).hd };
    let exceeded = state.invalid_frames.get() + 1 > crate::MAX_INVALID_FRAMES;
    state.invalid_frames.set(state.invalid_frames.get() + 1);
    if exceeded {
        return CALLBACK_FAILURE;
    }
    let _ = rn_uv::callback::with_context(|scope| {
        let args = [
            v8::Integer::new(scope, hd.stream_id).into(),
            v8::Integer::new(scope, i32::from(hd.type_)).into(),
            v8::Integer::new(scope, lib_error_code).into(),
        ];
        call_callback(
            scope,
            state,
            |callbacks| callbacks.frame_error.clone(),
            &args,
        );
    });
    0
}

/// `OnFrameNotSent`.
unsafe extern "C" fn on_frame_not_sent(
    _session: *mut ffi::nghttp2_session,
    _frame: *const ffi::nghttp2_frame,
    _lib_error_code: std::os::raw::c_int,
    _user_data: *mut c_void,
) -> std::os::raw::c_int {
    // Node logs this and continues; nothing in `lib/**` observes it.
    0
}

/// `OnFrameSent`: counts a completed frame.
unsafe extern "C" fn on_frame_sent(
    _session: *mut ffi::nghttp2_session,
    _frame: *const ffi::nghttp2_frame,
    user_data: *mut c_void,
) -> std::os::raw::c_int {
    // SAFETY: as `on_begin_headers`.
    let Some(state) = (unsafe { session_of(user_data) }) else {
        return CALLBACK_FAILURE;
    };
    state.chunks_sent.set(state.chunks_sent.get() + 1);
    0
}

/// `OnNghttpError`: nghttp2 reported an error string.
unsafe extern "C" fn on_nghttp_error(
    _session: *mut ffi::nghttp2_session,
    _lib_error_code: std::os::raw::c_int,
    msg: *const std::os::raw::c_char,
    len: usize,
    user_data: *mut c_void,
) -> std::os::raw::c_int {
    // SAFETY: as `on_begin_headers`.
    let Some(state) = (unsafe { session_of(user_data) }) else {
        return CALLBACK_FAILURE;
    };
    if msg.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: nghttp2 passes `len` readable bytes at `msg`.
    let bytes = unsafe { std::slice::from_raw_parts(msg.cast::<u8>(), len) };
    // The buffer is not NUL-terminated on this path, which is why the length is
    // used rather than `CStr`.
    if let Ok(text) = std::str::from_utf8(bytes) {
        *state.recv_error_code.borrow_mut() = Some(text.to_string());
    }
    0
}

/// Converts header pairs into the flat `[name, value, name, value, ...]` array
/// `toHeaderObject` reads.
///
/// `core.js`'s `toHeaderObject` walks the array in pairs, so the shape is two
/// entries per header with no interleaved flags. Node's `headers_v` is built the
/// same way; the `flags` byte travels separately through `sensitiveHeaders`, which
/// this runtime never marks.
fn headers_to_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    headers: &[(Vec<u8>, Vec<u8>, u8)],
) -> Option<v8::Local<'s, v8::Array>> {
    let mut flat: Vec<v8::Local<'s, v8::Value>> = Vec::with_capacity(headers.len() * 2);
    for (name, value, _flags) in headers {
        flat.push(string_from_bytes(scope, name)?.into());
        flat.push(string_from_bytes(scope, value)?.into());
    }
    Some(v8::Array::new_with_elements(scope, &flat))
}

/// A JavaScript string from wire bytes.
///
/// Header names and values on the wire are not guaranteed to be UTF-8 — HTTP/2
/// carries them as opaque octets — so an invalid sequence is decoded lossily
/// rather than rejected. Node constructs the string with `OneByteString`, which is
/// Latin-1 for bytes above 0x7f; a lossy UTF-8 decode is observably different only
/// for headers that are not valid UTF-8, and those cannot be sent as JavaScript
/// strings in the first place.
fn string_from_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::String>> {
    match std::str::from_utf8(bytes) {
        Ok(text) => v8::String::new(scope, text),
        Err(_) => v8::String::new(scope, &String::from_utf8_lossy(bytes)),
    }
}
