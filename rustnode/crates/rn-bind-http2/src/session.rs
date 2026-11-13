//! The native state behind one `binding.Http2Session`.
//!
//! `Http2Session` in `src/node_http2.cc` is an `AsyncWrap`, a `StreamListener`
//! and a memory manager at once. This is the Rust spelling of its data: the
//! nghttp2 session, the option object it was built with, the socket it consumed,
//! and the JS callbacks `lib/internal/http2/core.js` installed through
//! `setCallbackFunctions`.
//!
//! # Why the callbacks are read per call and not cached here
//!
//! `setCallbackFunctions` runs at module scope, before any session exists, and
//! stores the eleven functions in one process-wide table
//! ([`crate::SessionCallbacks`]). A session reads them at the moment it needs to
//! call one, which is what makes a session constructed before `core.js` finished
//! loading behave like Node's: the function is simply not there yet, and the
//! per-callback guard in the C++ (`if (!(bitfield & ...)) return`) has the same
//! effect.
//!
//! # Lifecycle
//!
//! The nghttp2 session is created in [`SessionState::new`] and freed on `close`
//! or in the destructor. It must be freed exactly once, and nothing may call into
//! it after that, so the pointer is `None`d before `nghttp2_session_del` runs.
//! `Drop` frees it if `close` did not, which is the case when V8 collects a
//! session that JavaScript never destroyed.
//!
//! # Threading
//!
//! Everything here is `!Send` and only ever touched from the isolate's thread.
//! nghttp2 itself is not thread-safe per session, and Node makes the same
//! assumption.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ptr;

use rn_v8_sys::v8;

use crate::callbacks::Callbacks;
use crate::ffi;
use crate::state;

/// `SessionType` from `node_http2.h`: `NGHTTP2_SESSION_SERVER`.
pub const SESSION_SERVER: i32 = 0;
/// `SessionType`: `NGHTTP2_SESSION_CLIENT`.
pub const SESSION_CLIENT: i32 = 1;

/// One stream's nghttp2-side bookkeeping, as `Http2Stream` keeps it.
///
/// Node's `Http2Stream` is an `AsyncWrap + StreamBase` with a real JS object per
/// stream. The JS object is created by `core.js` in `onSessionHeaders`, which
/// passes back a fresh `binding.Http2Stream` handle; this record is what that
/// handle points at.
#[derive(Debug, Default)]
pub struct StreamRecord {
    /// `nghttp2_stream`'s id.
    pub id: i32,
    /// `headers_category()`: `NGHTTP2_HCAT_*`.
    pub category: i32,
    /// The header pairs seen so far for the current HEADERS block, as
    /// `(name, value, flags)`.
    pub headers: Vec<(Vec<u8>, Vec<u8>, u8)>,
    /// `is_destroyed()`.
    pub destroyed: bool,
    /// `peer_reset()`: a RST_STREAM arrived, which `onStreamClose` needs to tell a
    /// peer reset apart from a natural close.
    pub peer_reset: bool,
    /// The `streamOptions` the stream was created with.
    pub options: i32,
    /// Whether the JS side asked for trailers, from `STREAM_OPTION_GET_TRAILERS`.
    pub want_trailers: bool,
    /// `stats_`'s `received_bytes`, for `stream.stats` if it is ever asked for.
    pub received_bytes: u64,
    /// `stats_`'s `sent_bytes`.
    pub sent_bytes: u64,
    /// Body bytes `writeBuffer` has accepted but nghttp2 has not framed yet.
    ///
    /// On the record rather than the handle because the provider's read callback
    /// runs inside `nghttp2_session_mem_send`, where a V8 scope would be a
    /// liability: draining a `Vec<u8>` needs none, and reaching into the handle
    /// object would.
    pub pending: Vec<u8>,
    /// Set by `shutdown()`/`end()`: the provider may report EOF.
    pub ended: bool,
}

/// One `nghttp2_submit_*` call that had to wait for `mem_recv` to return.
///
/// Every variant carries what the submit needs and owns its buffers, so replaying
/// it later cannot reference storage that a JavaScript frame has since dropped.
#[derive(Debug)]
pub enum DeferredSubmit {
    /// `nghttp2_submit_goaway`.
    Goaway {
        code: u32,
        last_stream_id: i32,
        data: Vec<u8>,
    },
    /// `nghttp2_submit_rst_stream`.
    RstStream { stream_id: i32, code: u32 },
    /// `nghttp2_submit_response2`, with the header block already flattened.
    Response {
        stream_id: i32,
        /// `(name, value, flags)` triples, which is what `nghttp2_nv` needs.
        headers: Vec<(Vec<u8>, Vec<u8>, u8)>,
        empty_payload: bool,
    },
    /// `nghttp2_submit_headers` (`info`, and the trailer-less `respond`).
    Headers {
        stream_id: i32,
        headers: Vec<(Vec<u8>, Vec<u8>, u8)>,
        flags: u8,
    },
    /// `nghttp2_submit_trailer`.
    Trailer {
        stream_id: i32,
        headers: Vec<(Vec<u8>, Vec<u8>, u8)>,
    },
    /// `nghttp2_submit_data2`.
    Data { stream_id: i32, flags: u8 },
    /// `nghttp2_submit_push_promise`.
    PushPromise {
        stream_id: i32,
        headers: Vec<(Vec<u8>, Vec<u8>, u8)>,
    },
    /// `nghttp2_submit_ping`.
    Ping { payload: [u8; 8] },
    /// `nghttp2_submit_settings`.
    Settings {
        entries: Vec<ffi::nghttp2_settings_entry>,
    },
    /// `nghttp2_submit_altsvc`.
    AltSvc {
        stream_id: i32,
        origin: Vec<u8>,
        value: Vec<u8>,
    },
    /// `nghttp2_submit_origin`.
    Origin { origins: Vec<Vec<u8>> },
    /// `nghttp2_submit_request2`.
    Request {
        stream_id_hint: i32,
        headers: Vec<(Vec<u8>, Vec<u8>, u8)>,
        empty_payload: bool,
        parent: i32,
        weight: i32,
        exclusive: bool,
    },
}

/// Everything a `binding.Http2Session` owns.
pub struct SessionState {
    /// The nghttp2 session, or `None` once it has been freed.
    pub session: Cell<*mut ffi::nghttp2_session>,
    /// `NGHTTP2_SESSION_SERVER` or `NGHTTP2_SESSION_CLIENT`.
    pub session_type: i32,
    /// `StreamBase*` of the socket this session consumed, or null.
    ///
    /// Node keeps a `StreamBase*`; here it is the `rn_uv` `StreamState` the socket
    /// binding attached, which is the same fact.
    pub stream: Cell<*mut rn_uv::handle::StreamState>,
    /// The `StreamPipe`-style listener id on that stream, so `close` can detach.
    pub listener: Cell<Option<rn_uv::listener::ListenerId>>,
    /// True between `consume` and `close`, and what makes a second `consume` a
    /// no-op instead of a double push.
    pub consumed: Cell<bool>,
    /// `flags_`'s `is_destroyed()`: `close` or a fatal error ran.
    pub destroyed: Cell<bool>,
    /// `is_closing()`: a GOAWAY was submitted, so new streams are refused.
    pub closing: Cell<bool>,
    /// Submits recorded while `mem_recv` was on the stack, in submission order.
    ///
    /// `nghttp2_submit_*` must not touch the outbound queue while nghttp2 is
    /// walking it, and a stream callback runs *inside* `mem_recv`. Replaying here
    /// preserves the exact call order, which is load-bearing: a `RST_STREAM`
    /// submitted after a `DATA` must still be applied after it, or the reset
    /// overtakes the body and the peer sees a reset stream instead of a response —
    /// the same defect increment 6 fixed at the RST site, one layer down. A
    /// `Vec` is therefore correct and a set or a per-kind slot is not.
    pub deferred_submits: RefCell<Vec<DeferredSubmit>>,
    /// A dispose that was requested while `mem_recv` was on the stack.
    ///
    /// `nghttp2_session_del` must not run until nghttp2 has returned from the
    /// receive it is in the middle of, so the free is recorded here and performed
    /// immediately afterwards.
    pub pending_dispose: Cell<bool>,
    /// A destroy that was deferred out of a receive, with the socket flag it
    /// arrived with.
    ///
    /// The whole teardown waits, not just the free: `ondone` runs JavaScript that
    /// ends the socket, and ending it re-enters nghttp2. Recording both here is what
    /// keeps the teardown from being dropped — skipping it turned every crash into a
    /// hang in an earlier cut.
    pub pending_destroy: Cell<Option<bool>>,
    /// `setGracefulCloseInitiated()`: `setGracefulClose` ran, so the
    /// `ongracefulclosecomplete` notification is armed.
    pub graceful_close: Cell<bool>,
    /// Whether that notification has fired, so it fires once.
    pub graceful_close_notified: Cell<bool>,
    /// `is_receiving()`: inside `nghttp2_session_mem_recv`.
    ///
    /// `SendPendingData` must not run while this is set, because sending can close
    /// a stream and free nghttp2 state the receive path is walking.
    pub receiving: Cell<bool>,
    /// `is_sending()`: inside `SendPendingData`, to stop recursion.
    pub sending: Cell<bool>,
    /// `is_write_scheduled()`: nghttp2 may have bytes waiting to be flushed.
    pub write_scheduled: Cell<bool>,
    /// Whether a flush callback is already queued for the check phase.
    ///
    /// Separate from [`write_scheduled`](Self::write_scheduled) because they answer
    /// different questions: the first is "is there anything to send", the second is
    /// "will something send it". Collapsing them dropped the initial SETTINGS
    /// frame.
    pub write_queued: Cell<bool>,
    /// Whether reading is stopped (`MaybeStopReading`).
    pub reading_stopped: Cell<bool>,
    /// `rejected_stream_count_`.
    pub rejected_streams: Cell<u32>,
    /// `invalid_frame_count_`.
    pub invalid_frames: Cell<u32>,
    /// The local window size the session was configured with.
    pub connection_window_size: Cell<i32>,
    /// `max_session_memory_`, in bytes.
    pub max_session_memory: Cell<u64>,
    /// `max_header_pairs_`.
    pub max_header_pairs: Cell<u32>,
    /// `max_outstanding_pings_`.
    pub max_outstanding_pings: Cell<usize>,
    /// `max_outstanding_settings_`.
    pub max_outstanding_settings: Cell<usize>,
    /// The streams by id, as `FindStream` reads them.
    pub streams: RefCell<BTreeMap<i32, StreamRecord>>,
    /// The JS handle object per stream id, rooted.
    ///
    /// `core.js` wraps this object in a `Duplex` and passes it back to native code
    /// on every subsequent call for the stream, so it has to be reachable by id —
    /// there is no local handle in a libuv callback. Node gets the same thing from
    /// `nghttp2_session_set_stream_user_data`, which stores the pointer in
    /// nghttp2's own stream object; a map is the Rust spelling because the pointer
    /// would be a `v8::Global` this crate already owns.
    pub handles: RefCell<BTreeMap<i32, v8::Global<v8::Object>>>,
    /// The `Http2Session` JS object, rooted.
    ///
    /// `MakeCallback`'s receiver is `this` in `src/node_http2.cc`, and every
    /// callback in `core.js` starts with `this[kOwner]`. The callbacks run from
    /// libuv completions where no local handle is in scope, so the object is
    /// rooted here — the same job `AsyncWrap::object()` does.
    pub object: RefCell<Option<v8::Global<v8::Object>>>,
    /// The socket's JS object, rooted, so the pair stays alive together.
    pub stream_object: RefCell<Option<v8::Global<v8::Object>>>,
    /// `js_fields_`: the `Uint8Array(12)` `core.js` reads as `kNativeFields`.
    pub fields: RefCell<Option<v8::Global<v8::ArrayBuffer>>>,
    /// `outgoing_storage_`: nghttp2's bytes waiting to be written, gathered here
    /// until the write completes.
    ///
    /// `SendPendingData` copies out of nghttp2's buffers because
    /// `nghttp2_session_mem_send` invalidates them on the next call, and a queued
    /// `uv_write` needs them to outlive this call.
    pub outgoing: RefCell<Vec<u8>>,
    /// `has_pending_data_`.
    pub has_pending_data: Cell<bool>,
    /// `custom_recv_error_code_`: the error string nghttp2 reported, if any.
    pub recv_error_code: RefCell<Option<String>>,
    /// `chunks_sent_since_last_write_`.
    pub chunks_sent: Cell<u64>,
    /// `chunks_sent_since_last_write_at_`.
    pub chunks_sent_at: Cell<u64>,
    /// `current_session_memory_`.
    pub session_memory: Cell<u64>,
    /// The callback table, owned by this session until `dispose`.
    ///
    /// A raw pointer because the `nghttp2_session` holds it for its whole life and
    /// nghttp2 does not copy it; keeping it in a `Box` the state owns is what makes
    /// the two lifetimes coincide.
    callbacks: Cell<*mut Callbacks>,
}

impl SessionState {
    /// Builds a session of `session_type` with `option`.
    ///
    /// Mirrors `Http2Session`'s constructor: the nghttp2 session is created
    /// against `callbacks`, and the two `server_new2`/`client_new2` forms are used
    /// so the option object applies.
    pub fn new(session_type: i32) -> Result<Box<Self>, String> {
        let callbacks = Callbacks::new()?;
        let option = crate::options::Options::from_buffer(session_type)?;

        // The state is boxed *before* the nghttp2 session exists so that its
        // address is stable and can be handed over as `user_data` at creation.
        // Taking the address of a box and then passing it to `*_new2` is the only
        // ordering that avoids a window in which a callback could fire with a null
        // or stale `user_data` — which is what happened when the session was made
        // first and `set_user_data` called afterwards: the very first
        // `nghttp2_submit_settings` produced a frame whose `on_frame_sent` read a
        // pointer that was no longer the state.
        let mut state = Box::new(Self {
            session: Cell::new(ptr::null_mut()),
            session_type,
            stream: Cell::new(ptr::null_mut()),
            listener: Cell::new(None),
            consumed: Cell::new(false),
            destroyed: Cell::new(false),
            closing: Cell::new(false),
            pending_dispose: Cell::new(false),
            pending_destroy: Cell::new(None),
            deferred_submits: RefCell::new(Vec::new()),
            graceful_close: Cell::new(false),
            graceful_close_notified: Cell::new(false),
            receiving: Cell::new(false),
            sending: Cell::new(false),
            write_scheduled: Cell::new(false),
            write_queued: Cell::new(false),
            reading_stopped: Cell::new(false),
            rejected_streams: Cell::new(0),
            invalid_frames: Cell::new(0),
            connection_window_size: Cell::new(crate::options::DEFAULT_CONNECTION_WINDOW_SIZE),
            max_session_memory: Cell::new(crate::options::DEFAULT_MAX_SESSION_MEMORY),
            max_header_pairs: Cell::new(128),
            max_outstanding_pings: Cell::new(10),
            max_outstanding_settings: Cell::new(10),
            streams: RefCell::new(BTreeMap::new()),
            handles: RefCell::new(BTreeMap::new()),
            object: RefCell::new(None),
            stream_object: RefCell::new(None),
            fields: RefCell::new(None),
            outgoing: RefCell::new(Vec::new()),
            has_pending_data: Cell::new(false),
            recv_error_code: RefCell::new(None),
            chunks_sent: Cell::new(0),
            chunks_sent_at: Cell::new(0),
            session_memory: Cell::new(0),
            callbacks: Cell::new(Box::into_raw(Box::new(callbacks))),
        });

        let user_data = (&mut *state as *mut Self).cast::<std::ffi::c_void>();
        let mut raw: *mut ffi::nghttp2_session = ptr::null_mut();
        // SAFETY: `state.callbacks` holds a live callback table for the duration of
        // the call, `option` is live, and `user_data` is the address of the box
        // this function returns, so it outlives the session.
        let status = unsafe {
            if session_type == SESSION_SERVER {
                ffi::nghttp2_session_server_new2(
                    &mut raw,
                    (*state.callbacks.get()).as_ptr(),
                    user_data,
                    option.as_ptr(),
                )
            } else {
                ffi::nghttp2_session_client_new2(
                    &mut raw,
                    (*state.callbacks.get()).as_ptr(),
                    user_data,
                    option.as_ptr(),
                )
            }
        };
        if status != 0 {
            return Err(format!(
                "nghttp2_session_new failed with {status}: {}",
                // SAFETY: `nghttp2_strerror` returns static text for any code.
                unsafe {
                    std::ffi::CStr::from_ptr(ffi::nghttp2_strerror(status)).to_string_lossy()
                }
            ));
        }
        state.session.set(raw);
        Ok(state)
    }

    /// Frees the nghttp2 session exactly once.
    ///
    /// Idempotent because `close` and `Drop` both call it and either may run
    /// first: a JS `destroy()` that runs before GC leaves `Drop` nothing to do.
    pub fn dispose(&self) {
        let raw = self.session.replace(ptr::null_mut());
        if raw.is_null() {
            return;
        }
        // SAFETY: `raw` came from `nghttp2_session_*_new2` and is freed exactly
        // once, because `replace` already cleared the slot.
        unsafe { ffi::nghttp2_session_del(raw) };
        let callbacks = self.callbacks.replace(ptr::null_mut());
        if !callbacks.is_null() {
            // SAFETY: `callbacks` came from `Box::into_raw` in `new` and holds a
            // `Callbacks` no one else refers to any more.
            drop(unsafe { Box::from_raw(callbacks) });
        }
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.dispose();
    }
}

/// Writes one `sessionState` value from a getter, ignoring a freed session.
pub fn refresh_state(state: &SessionState) {
    let raw = state.session.get();
    if raw.is_null() {
        return;
    }
    let _ = crate::state::Http2State::with(|shared| {
        // SAFETY: `raw` is a live nghttp2 session; every getter below only reads.
        unsafe {
            shared.set_session_state(
                state::IDX_SESSION_STATE_EFFECTIVE_LOCAL_WINDOW_SIZE,
                f64::from(ffi::nghttp2_session_get_effective_local_window_size(raw)),
            );
            shared.set_session_state(
                state::IDX_SESSION_STATE_EFFECTIVE_RECV_DATA_LENGTH,
                f64::from(ffi::nghttp2_session_get_effective_recv_data_length(raw)),
            );
            shared.set_session_state(
                state::IDX_SESSION_STATE_NEXT_STREAM_ID,
                f64::from(ffi::nghttp2_session_get_next_stream_id(raw)),
            );
            shared.set_session_state(
                state::IDX_SESSION_STATE_LOCAL_WINDOW_SIZE,
                f64::from(ffi::nghttp2_session_get_local_window_size(raw)),
            );
            shared.set_session_state(
                state::IDX_SESSION_STATE_LAST_PROC_STREAM_ID,
                f64::from(ffi::nghttp2_session_get_last_proc_stream_id(raw)),
            );
            shared.set_session_state(
                state::IDX_SESSION_STATE_REMOTE_WINDOW_SIZE,
                f64::from(ffi::nghttp2_session_get_remote_window_size(raw)),
            );
            shared.set_session_state(
                state::IDX_SESSION_STATE_OUTBOUND_QUEUE_SIZE,
                ffi::nghttp2_session_get_outbound_queue_size(raw) as f64,
            );
            shared.set_session_state(
                state::IDX_SESSION_STATE_HD_DEFLATE_DYNAMIC_TABLE_SIZE,
                ffi::nghttp2_session_get_hd_deflate_dynamic_table_size(raw) as f64,
            );
            shared.set_session_state(
                state::IDX_SESSION_STATE_HD_INFLATE_DYNAMIC_TABLE_SIZE,
                ffi::nghttp2_session_get_hd_inflate_dynamic_table_size(raw) as f64,
            );
        }
    });
}

/// The live nghttp2 session pointer, or `None` once it has been freed.
pub fn raw(state: &SessionState) -> Option<*mut ffi::nghttp2_session> {
    let pointer = state.session.get();
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Queues a check-phase write, coalescing repeat calls.
///
/// `Http2Scope`'s `MaybeScheduleWrite`: any call into nghttp2 that can enqueue a
/// frame ends with this, so the bytes leave on one pass rather than one write per
/// frame. It is also what makes a provider's `NGHTTP2_ERR_DEFERRED` recoverable —
/// when more bytes arrive, this schedules the retry.
pub fn schedule_write(state: &SessionState) {
    // Mark that a flush is needed and queue the callback iff one is not already
    // queued. The distinction matters: the *callback* must not be queued twice,
    // but the *flush* must re-run for a submit that happened after the previous
    // pass drained. Coalescing on one flag for both jobs is what made the initial
    // SETTINGS frame vanish — `core.js` submits it right after `consume`, whose
    // own flush had already passed, and the submit then found the flag set and
    // queued nothing.
    state.write_scheduled.set(true);
    if state.destroyed.get() {
        return;
    }
    if state.write_queued.replace(true) {
        return;
    }
    // The session is reachable from the queued callback only through a
    // thread-local list, because the native immediate queue takes plain function
    // pointers.
    PENDING_WRITES.with(|pending| {
        pending
            .borrow_mut()
            .push((state as *const SessionState) as usize)
    });
    rn_core::native_immediates::set_immediate(flush_writes);
}

thread_local! {
    /// Sessions with a write due on the next check phase, as raw addresses.
    static PENDING_WRITES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Flushes every scheduled session write.
fn flush_writes(scope: &mut v8::PinScope<'_, '_>) {
    let sessions: Vec<usize> =
        PENDING_WRITES.with(|pending| std::mem::take(&mut *pending.borrow_mut()));
    for address in sessions {
        if address == 0 {
            continue;
        }
        // SAFETY: the address came from `schedule_write`, which is only called for
        // a live session, and `detach` removes it from this queue before the state
        // is freed. That removal is what makes this dereference sound: without it,
        // a session torn down between the queue and the check phase left a dangling
        // address here, and the flush below read the freed state — the segfault
        // this increment fixed (`session.goaway()` twice in a row on the server
        // closes the session before the deferred write runs).
        let state = unsafe { &*(address as *const SessionState) };
        if state.destroyed.get() {
            // Belt and braces: a destroyed session has already been detached, so
            // touching it here would be the same use-after-free.
            continue;
        }
        // Clear the queued flag *before* flushing: a submit made during the flush
        // (nghttp2 can queue an ACK while sending) has to be able to queue another
        // pass rather than being swallowed.
        state.write_queued.set(false);
        send_pending_data(scope, state);
    }
}

/// `SendPendingData`: drain nghttp2's outbound queue onto the socket.
///
/// The three guards are `SendPendingData`'s own: not while destroying, not
/// recursively, and not while inside `mem_recv` — sending can close a stream and
/// free nghttp2 state the receive path is still walking.
pub fn send_pending_data(scope: &mut v8::PinScope<'_, '_>, state: &SessionState) {
    if !state.write_scheduled.get() {
        return;
    }
    if state.destroyed.get() || state.sending.get() || state.receiving.get() {
        return;
    }
    let Some(raw) = raw(state) else {
        return;
    };
    let stream_state = state.stream.get();
    if stream_state.is_null() {
        // No stream yet. Leave `write_scheduled` set so `consume` picks it up.
        return;
    }
    state.write_scheduled.set(false);
    // SAFETY: `stream_state` is live while the socket object is.
    let stream = unsafe { (*stream_state).stream };
    if stream.is_null() {
        return;
    }
    state.sending.set(true);

    let mut gathered: Vec<u8> = Vec::new();
    loop {
        let mut chunk: *const u8 = ptr::null();
        // SAFETY: `raw` is live and `mem_send` returns a pointer valid until the
        // next call, which is why the bytes are copied immediately.
        let length = unsafe { ffi::nghttp2_session_mem_send(raw, &mut chunk) };
        if length <= 0 {
            break;
        }
        if chunk.is_null() {
            break;
        }
        // SAFETY: `mem_send` returned `length` readable bytes at `chunk`.
        gathered.extend_from_slice(unsafe { std::slice::from_raw_parts(chunk, length as usize) });
    }
    state.sending.set(false);

    if gathered.is_empty() {
        state.has_pending_data.set(false);
        return;
    }
    *state.outgoing.borrow_mut() = gathered;
    state.has_pending_data.set(true);

    let bytes = std::mem::take(&mut *state.outgoing.borrow_mut());
    let length = bytes.len();
    let buffer = rn_uv::sys::uv_buf_t {
        base: bytes.as_ptr() as *mut std::os::raw::c_char,
        len: length,
    };
    // SAFETY: `stream` is the socket this session consumed and is live until the
    // session closes; `bytes` is moved into `owned` so the buffer outlives the
    // completion.
    let status = unsafe {
        rn_uv::stream::queue_write_unowned(
            stream,
            vec![buffer],
            length,
            vec![bytes.into_boxed_slice()],
        )
    };
    // nghttp2 reports more to send whenever it queued a frame behind the one just
    // handed over — an ACK it generated while reading, or a SETTINGS submitted
    // after the gather above. Re-arming here is what keeps the connection moving;
    // without it the peer waits for a frame nobody will send, which is exactly the
    // stall this loop was fixed for.
    if status == 0 {
        // SAFETY: `raw` is live.
        if unsafe { ffi::nghttp2_session_want_write(raw) } != 0 {
            schedule_write(state);
        }
    }
    state.has_pending_data.set(status == 0);
    maybe_notify_graceful_close(state);
    let _ = scope;
}

/// `Consume`: take over a socket's reads and writes.
///
/// The socket binding attached its `StreamState` under a symbol, so this finds the
/// same state `StreamBase::FromObject` would unwrap, then pushes a listener so
/// accepted bytes reach nghttp2 instead of JavaScript.
pub fn consume(
    scope: &mut v8::PinScope<'_, '_>,
    state: &SessionState,
    stream_object: v8::Local<'_, v8::Object>,
) -> Result<(), String> {
    if state.consumed.replace(true) {
        return Ok(());
    }
    // SAFETY: `stream_object` is a live local, so any state a binding attached to
    // it outlives this call. `state_of` reads the state symbol first and falls
    // back to the stream symbol, so a `JSStream` (which has no libuv handle) is
    // accepted alongside a `TCP` or `Pipe`.
    let stream_state = unsafe { rn_uv::streams::state_of(scope, stream_object) };
    let Some(stream_state) = stream_state else {
        return Err("Http2Session.consume requires a stream handle".to_string());
    };
    state.stream.set(stream_state);
    *state.stream_object.borrow_mut() = Some(v8::Global::new(scope.as_ref(), stream_object));

    let listener = rn_uv::listener::ListenerRef::new(Box::new(SessionListener {
        state: (state as *const SessionState).cast_mut(),
    }));
    // SAFETY: `stream_state` is live and outlives the attachment, which the socket
    // binding's own state guarantees.
    if let Some(id) = unsafe { rn_uv::listener::push_stream_listener(stream_state, listener) } {
        state.listener.set(Some(id));
    }
    // The SETTINGS frame `core.js` submitted from the constructor was queued
    // before this stream existed, so it is still pending. Scheduling here is what
    // flushes it now that there is somewhere to write.
    schedule_write(state);
    Ok(())
}

/// The listener a session pushes onto the socket it consumed.
struct SessionListener {
    state: *mut SessionState,
}

impl rn_uv::listener::StreamListener for SessionListener {
    /// `Http2Session::OnStreamRead`: hand the bytes to nghttp2.
    fn on_stream_read(
        &mut self,
        this: &rn_uv::listener::ListenerRef,
        nread: isize,
        buffer: rn_uv::listener::ReadBuffer,
    ) {
        if self.state.is_null() {
            return;
        }
        // SAFETY: the session owns this listener and outlives the attachment.
        let state = unsafe { &*self.state };
        if nread <= 0 {
            // EOF or an error: `PassReadErrorToPreviousListener` is what lets
            // `lib/net.js` see the socket close. A zero-length read is not
            // forwarded, exactly as `OnStreamRead` does.
            if nread < 0 {
                this.pass_read_error_to_previous_listener(nread);
            }
            return;
        }
        let Some(bytes) = buffer.bytes(nread) else {
            return;
        };
        let bytes = bytes.to_vec();
        let _ = rn_uv::callback::with_context(|scope| receive_scope(scope, state, &bytes));
    }
}

/// Records `submit` if nghttp2 is mid-receive, and runs it now otherwise.
///
/// This is the single gate every `nghttp2_submit_*` call goes through. The rule it
/// enforces is the one increment 9 established by experiment: nghttp2 must not have
/// its outbound queue mutated while `nghttp2_session_mem_recv` is walking it, which
/// is exactly where a stream callback runs. Violating it produced a null read
/// inside `session_pack_extension` and a deterministic SIGSEGV.
///
/// Deliberately a gate on `receiving` and not on "am I in a callback": the only
/// window that is unsound is `mem_recv`. One submit is documented as legal from a
/// *different* callback — `nghttp2_submit_trailer` from the data read callback —
/// and that callback runs from `mem_send`, where `receiving` is already false, so it
/// is not deferred. Deferring it "for symmetry" would change when trailers reach
/// the wire for no reason.
///
/// Returns whether the submit ran immediately.
pub fn defer_or<R>(
    state: &SessionState,
    submit: DeferredSubmit,
    immediate: impl FnOnce() -> R,
) -> bool {
    if state.receiving.get() {
        state.deferred_submits.borrow_mut().push(submit);
        false
    } else {
        let _ = immediate();
        true
    }
}

/// Replays everything recorded during a receive, in submission order.
///
/// Runs after `receiving` is cleared and before the flush that follows, so the
/// replayed frames go out in the same pass as the ones the receive itself produced.
/// Order is the reason the queue is a `Vec`: a RST_STREAM submitted after a DATA
/// must be applied after it, or it overtakes the body.
fn replay_deferred(state: &SessionState) {
    let queued = std::mem::take(&mut *state.deferred_submits.borrow_mut());
    for submit in queued {
        apply_deferred(state, submit);
    }
}

/// Hands one recorded submit to nghttp2. `receiving` is false by the time this runs.
fn apply_deferred(state: &SessionState, submit: DeferredSubmit) {
    let Some(raw) = raw(state) else {
        return;
    };
    // SAFETY: every call below only queues a frame, and none of them runs while
    // `mem_recv` is on the stack — `replay_deferred` is called from
    // `receive_scope` after the receive returns.
    unsafe {
        match submit {
            DeferredSubmit::Goaway {
                code,
                last_stream_id,
                data,
            } => {
                let last = if last_stream_id == 0 {
                    -1
                } else {
                    last_stream_id
                };
                ffi::nghttp2_submit_goaway(
                    raw,
                    ffi::NGHTTP2_FLAG_NONE,
                    last,
                    code,
                    data.as_ptr(),
                    data.len(),
                );
            }
            DeferredSubmit::RstStream { stream_id, code } => {
                ffi::nghttp2_submit_rst_stream(raw, ffi::NGHTTP2_FLAG_NONE, stream_id, code);
            }
            DeferredSubmit::Response {
                stream_id,
                headers,
                empty_payload,
            } => {
                let block = crate::headers::block_from_pairs(&headers);
                ffi::nghttp2_submit_response2(
                    raw,
                    stream_id,
                    block.as_ptr(),
                    block.len(),
                    if empty_payload {
                        std::ptr::null()
                    } else {
                        let provider = crate::stream::provider::Provider::new(state, stream_id, 0);
                        provider.as_ptr()
                    },
                );
            }
            DeferredSubmit::Headers {
                stream_id,
                headers,
                flags,
            } => {
                let block = crate::headers::block_from_pairs(&headers);
                ffi::nghttp2_submit_headers(
                    raw,
                    flags,
                    stream_id,
                    std::ptr::null(),
                    block.as_ptr(),
                    block.len(),
                    std::ptr::null_mut(),
                );
            }
            DeferredSubmit::Trailer { stream_id, headers } => {
                let block = crate::headers::block_from_pairs(&headers);
                ffi::nghttp2_submit_trailer(raw, stream_id, block.as_ptr(), block.len());
            }
            DeferredSubmit::Data { stream_id, flags } => {
                let provider = crate::stream::provider::Provider::new(state, stream_id, 0);
                ffi::nghttp2_submit_data2(raw, flags, stream_id, provider.as_ptr());
            }
            DeferredSubmit::PushPromise { stream_id, headers } => {
                let block = crate::headers::block_from_pairs(&headers);
                ffi::nghttp2_submit_push_promise(
                    raw,
                    ffi::NGHTTP2_FLAG_NONE,
                    stream_id,
                    block.as_ptr(),
                    block.len(),
                    std::ptr::null_mut(),
                );
            }
            DeferredSubmit::Ping { payload } => {
                ffi::nghttp2_submit_ping(raw, ffi::NGHTTP2_FLAG_NONE, payload.as_ptr());
            }
            DeferredSubmit::Settings { entries } => {
                ffi::nghttp2_submit_settings(
                    raw,
                    ffi::NGHTTP2_FLAG_NONE,
                    entries.as_ptr(),
                    entries.len(),
                );
            }
            DeferredSubmit::AltSvc {
                stream_id,
                origin,
                value,
            } => {
                ffi::nghttp2_submit_altsvc(
                    raw,
                    ffi::NGHTTP2_FLAG_NONE,
                    stream_id,
                    origin.as_ptr(),
                    origin.len(),
                    value.as_ptr(),
                    value.len(),
                );
            }
            DeferredSubmit::Origin { origins } => {
                let entries: Vec<ffi::Nghttp2OriginEntry> = origins
                    .iter()
                    .map(|origin| ffi::Nghttp2OriginEntry {
                        origin: origin.as_ptr().cast_mut(),
                        origin_len: origin.len(),
                    })
                    .collect();
                ffi::nghttp2_submit_origin(
                    raw,
                    ffi::NGHTTP2_FLAG_NONE,
                    entries.as_ptr(),
                    entries.len(),
                );
            }
            DeferredSubmit::Request {
                stream_id_hint,
                headers,
                empty_payload,
                parent,
                weight,
                exclusive,
            } => {
                let block = crate::headers::block_from_pairs(&headers);
                let mut pri_spec = ffi::nghttp2_priority_spec {
                    stream_id: parent,
                    weight,
                    exclusive: i32::from(exclusive),
                };
                let pri = if parent > 0 {
                    &mut pri_spec as *mut _
                } else {
                    std::ptr::null_mut()
                };
                ffi::nghttp2_submit_request2(
                    raw,
                    pri,
                    block.as_ptr(),
                    block.len(),
                    // A deferred request cannot hand its provider back to the caller,
                    // so the empty form is used; `core.js` only defers `request` from
                    // a session callback, which happens on the server.
                    if empty_payload || stream_id_hint <= 0 {
                        std::ptr::null()
                    } else {
                        let provider =
                            crate::stream::provider::Provider::new(state, stream_id_hint, 0);
                        provider.as_ptr()
                    },
                    std::ptr::null_mut(),
                );
            }
        }
    }
}

/// Sends whatever nghttp2 has queued, if it is legal to send right now.
///
/// This is `SendPendingData` without the "is a flush scheduled" gate, because the
/// caller has a frame of its own to queue afterwards and needs the earlier ones on
/// the wire first. It refuses while `receiving` (nghttp2 is walking its own receive
/// buffer) and while a send is already in progress, which are the two conditions
/// `SendPendingData` itself refuses on.
pub fn flush_pending(state: &SessionState) {
    if state.receiving.get() || state.sending.get() || state.destroyed.get() {
        return;
    }
    let Some(raw) = raw(state) else {
        return;
    };
    let stream_state = state.stream.get();
    if stream_state.is_null() {
        return;
    }
    // Nothing queued means nothing to do, and calling `mem_send` for no reason
    // would clear a schedule the check phase is relying on.
    // SAFETY: `raw` is live and `want_write` only reads.
    if unsafe { ffi::nghttp2_session_want_write(raw) } == 0 {
        return;
    }
    // Mark the deferred flush as already handled, then run one.
    state.write_scheduled.set(true);
    send_pending_data_ungated(state);
}

/// The body of [`send_pending_data`] without the "is a flush scheduled" check.
fn send_pending_data_ungated(state: &SessionState) {
    let _ = rn_uv::callback::with_context(|scope| send_pending_data(scope, state));
}

/// `ConsumeHTTP2Data`: feed `bytes` to nghttp2 and send what it queued.
pub fn receive(session: &SessionState, bytes: &[u8], scope: &mut v8::PinScope<'_, '_>) {
    receive_scope(scope, session, bytes);
}

/// The body of `ConsumeHTTP2Data`.
fn receive_scope(scope: &mut v8::PinScope<'_, '_>, state: &SessionState, bytes: &[u8]) {
    let Some(raw) = raw(state) else {
        return;
    };
    state.recv_error_code.borrow_mut().take();
    state.receiving.set(true);
    // SAFETY: `raw` is live and `bytes` is readable for its length.
    let consumed = unsafe { ffi::nghttp2_session_mem_recv(raw, bytes.as_ptr(), bytes.len()) };
    state.receiving.set(false);
    state
        .session_memory
        .set(state.session_memory.get() + bytes.len() as u64);

    // Everything submitted from inside the receive is replayed here: `receiving`
    // is already false, so nghttp2 is no longer walking its own outbound queue.
    // This happens *before* the flush below so a replayed frame leaves in the same
    // pass rather than waiting for the next check phase.
    if state.pending_dispose.replace(false) {
        // The session was destroyed from inside this receive. The teardown that
        // `Http2Session::Destroy` performs is replayed here, in its original order,
        // now that `mem_recv` has returned: free the nghttp2 session, then let
        // `core.js` finish closing the socket, then detach. Skipping it entirely
        // turned every one of these crashes into a 124, because nothing ended the
        // socket and the loop never drained.
        state.dispose();
        let socket_destroyed = state.pending_destroy.replace(None).unwrap_or(false);
        let _ = socket_destroyed;
        let object = state
            .object
            .borrow()
            .as_ref()
            .map(|object| v8::Global::new(scope.as_ref(), object));
        if let Some(object) = object {
            let object = v8::Local::new(scope, object);
            // `finishSessionClose` — the same callback `destroy` would have called.
            if let Some(key) = v8::String::new(scope, "ondone") {
                if let Some(value) = object.get(scope, key.into()) {
                    if let Ok(handler) = v8::Local::<v8::Function>::try_from(value) {
                        let _ = handler.call(scope, object.into(), &[]);
                    }
                }
            }
        }
        return;
    }
    if !state.destroyed.get() {
        replay_deferred(state);
    }
    // One flush for both the frames this receive produced and the replayed ones.
    // `replay_deferred` deliberately does not schedule anything of its own: two
    // schedules would mean two flushes and a double send.
    if consumed >= 0 && !state.destroyed.get() {
        schedule_write(state);
    }
    if consumed >= 0 {
        maybe_notify_graceful_close(state);
    }
    if consumed < 0 {
        let code = consumed as i32;
        let custom = state.recv_error_code.borrow().clone();
        let _ = rn_uv::callback::with_context(|scope| {
            let args = [
                v8::Integer::new(scope, code).into(),
                match custom
                    .as_deref()
                    .and_then(|text| v8::String::new(scope, text))
                {
                    Some(text) => text.into(),
                    None => v8::null(scope).into(),
                },
            ];
            let Some(object) = crate::session_object(scope, state) else {
                return;
            };
            let Some(callback) = crate::callbacks::pick_global(|callbacks| callbacks.error.clone())
            else {
                return;
            };
            let callback = v8::Local::new(scope, callback);
            let _ = callback.call(scope, object.into(), &args);
        });
    }
    let _ = scope;
}

/// The option object's connection window, applied after the session exists.
pub fn apply_connection_window(session: &SessionState) {
    let Some(raw) = raw(session) else {
        return;
    };
    let window = crate::options::Options::connection_window_size();
    session.connection_window_size.set(window);
    // SAFETY: `raw` is live and stream id 0 is the connection itself.
    unsafe {
        ffi::nghttp2_session_set_local_window_size(raw, ffi::NGHTTP2_FLAG_NONE, 0, window);
    }
}

/// Submits the session-level SETTINGS frame the constructor asks for.
///
/// `core.js` calls `session.settings(settings)` from the `Http2Session`
/// constructor, so this runs before any stream exists.
pub fn submit_settings(session: &SessionState) -> i32 {
    let Some(raw) = raw(session) else {
        return -901;
    };
    let entries = crate::state::Http2State::with(crate::settings::entries).unwrap_or_default();
    // SAFETY: `raw` is live and `entries` is a live slice.
    let status = unsafe {
        ffi::nghttp2_submit_settings(raw, ffi::NGHTTP2_FLAG_NONE, entries.as_ptr(), entries.len())
    };
    schedule_write(session);
    status
}

/// `Http2Session::Close`: submit GOAWAY, then free the nghttp2 session.
///
/// Order matters. `nghttp2_submit_goaway` only queues the frame, so the write has
/// to happen before the session is freed or the peer never learns why the
/// connection ended. `destroyed` is set first so nothing schedules more work.
pub fn close(scope: &mut v8::PinScope<'_, '_>, session: &SessionState, code: u32) {
    if session.destroyed.replace(true) {
        return;
    }
    if let Some(raw) = raw(session) {
        // Submitting here is unsafe when nghttp2 is mid-receive — that is the
        // segfault this increment exists to fix — and draining is equally unsafe,
        // because `mem_send` would walk the queue `mem_recv` is building.
        //
        // Both are skipped in that window. The cost is that a session destroyed
        // from inside a receive callback does not get its GOAWAY onto the wire; the
        // peer sees the socket close instead. That is the correct trade: the frame
        // is advisory, a corrupted nghttp2 queue is fatal, and `destroyed` already
        // tells every other path to stop.
        if session.receiving.get() {
            // `nghttp2_session_del` here would free the session nghttp2 is still
            // walking — a use-after-free, and the real cause of the
            // `session_pack_extension` null read. Nothing is submitted and nothing
            // is freed during the receive; the free happens in `dispose_deferred`
            // once `mem_recv` has returned.
            session.pending_dispose.set(true);
            return;
        }
        // SAFETY: `raw` is live and `mem_recv` is not on the stack.
        unsafe {
            ffi::nghttp2_submit_goaway(raw, ffi::NGHTTP2_FLAG_NONE, 0, code, ptr::null(), 0);
        }
        // The GOAWAY frame is drained here rather than through `schedule_write`,
        // because `send_pending_data` refuses to run on a destroyed session and
        // this is the last chance to put bytes on the wire.
        if !session.sending.get() && !session.receiving.get() {
            let mut gathered: Vec<u8> = Vec::new();
            loop {
                let mut chunk: *const u8 = ptr::null();
                // SAFETY: `raw` is live and the returned pointer is copied
                // immediately.
                let length = unsafe { ffi::nghttp2_session_mem_send(raw, &mut chunk) };
                if length <= 0 || chunk.is_null() {
                    break;
                }
                // SAFETY: `mem_send` returned `length` readable bytes.
                gathered.extend_from_slice(unsafe {
                    std::slice::from_raw_parts(chunk, length as usize)
                });
            }
            if !gathered.is_empty() {
                let stream_state = session.stream.get();
                // SAFETY: `stream_state` is live while the socket object is.
                let stream = unsafe {
                    if stream_state.is_null() {
                        ptr::null_mut()
                    } else {
                        (*stream_state).stream
                    }
                };
                if !stream.is_null() {
                    let count = gathered.len();
                    let buffer = rn_uv::sys::uv_buf_t {
                        base: gathered.as_ptr() as *mut std::os::raw::c_char,
                        len: count,
                    };
                    // SAFETY: `stream` is live until its own close callback, and
                    // `gathered` is moved into `owned`.
                    unsafe {
                        let _ = rn_uv::stream::queue_write_unowned(
                            stream,
                            vec![buffer],
                            count,
                            vec![gathered.into_boxed_slice()],
                        );
                    }
                }
            }
        }
    }
    let _ = scope;
}

/// Detaches the listener and frees the nghttp2 session.
///
/// `socket_destroyed` is the second argument `Http2Session::Destroy` receives: when
/// `core.js` already destroyed the socket there is nothing left to read and no
/// reason to stop the read, but when it has not been destroyed the read has to be
/// stopped so libuv releases the handle and the loop can drain.
pub fn detach(session: &SessionState, socket_destroyed: bool) {
    // Drop any deferred flush that still names this session *before* the state is
    // freed below. `flush_writes` dereferences every queued address, so an entry
    // left behind is a use-after-free waiting for the next check phase.
    let address = (session as *const SessionState) as usize;
    PENDING_WRITES.with(|pending| {
        pending.borrow_mut().retain(|queued| *queued != address);
    });
    session.write_queued.set(false);
    session.write_scheduled.set(false);
    let stream = session.stream.replace(ptr::null_mut());
    let listener = session.listener.take();
    if !stream.is_null() {
        // SAFETY: `stream` is the state the socket binding owns and it is live
        // while the socket object is.
        unsafe {
            if let Some(id) = listener {
                rn_uv::listener::remove_stream_listener(stream, id);
            }
            // Stopping the read is what releases the libuv handle, and it is
            // outside the `listener` branch on purpose: a session that consumed a
            // socket but never got a listener id still started a read, and leaving
            // it running keeps the socket ref'd so `uv_run` never drains. That is a
            // hang rather than an error, which is much worse to diagnose.
            if !socket_destroyed {
                let raw = (*stream).stream;
                if !raw.is_null() {
                    rn_uv::stream::read_stop(raw);
                }
            }
        }
    }
    session.consumed.set(false);
    session.dispose();
}

/// `MaybeNotifyGracefulCloseComplete`: tell `core.js` the connection is drained.
///
/// `http2session.setGracefulClose()` sets a flag, and `core.js` installs
/// `handle.ongracefulclosecomplete = this[kMaybeDestroy]` before calling it. Once
/// nghttp2 neither wants to read nor write, that callback is what destroys the
/// session — so a graceful `session.close()` completes only if this runs. Without
/// it `close()` sends its GOAWAY and then waits forever: the exact timeout the
/// measurement is full of.
///
/// Called after every write flush and after every receive, which is where Node
/// calls it (`MaybeNotifyGracefulCloseComplete` at the end of `SendPendingData`
/// and of the receive path).
pub fn maybe_notify_graceful_close(state: &SessionState) {
    if !state.graceful_close.get() {
        return;
    }
    let Some(raw) = raw(state) else {
        return;
    };
    // SAFETY: `raw` is live and both getters only read.
    let (want_write, want_read) = unsafe {
        (
            ffi::nghttp2_session_want_write(raw),
            ffi::nghttp2_session_want_read(raw),
        )
    };
    if want_write != 0 || want_read != 0 {
        return;
    }
    // The callback runs at most once: a second notification would destroy an
    // already-destroyed session.
    if state.graceful_close_notified.replace(true) {
        return;
    }
    let _ = rn_uv::callback::with_context(|scope| {
        let Some(object) = crate::session_object(scope, state) else {
            return;
        };
        let Some(key) = v8::String::new(scope, "ongracefulclosecomplete") else {
            return;
        };
        let Some(value) = object.get(scope, key.into()) else {
            return;
        };
        let Ok(handler) = v8::Local::<v8::Function>::try_from(value) else {
            return;
        };
        let _ = handler.call(scope, object.into(), &[]);
    });
}

/// A GOAWAY with `code`, which is `Http2Session::Goaway`.
pub fn goaway(session: &SessionState, code: u32, last_stream_id: i32, data: &[u8]) {
    if raw(session).is_none() {
        return;
    }
    // `nghttp2_submit_*` must not run while `nghttp2_session_mem_recv` is walking
    // the outbound queue. `core.js` calls this from a stream callback, which is
    // *inside* `mem_recv`, so submitting here corrupts nghttp2's frame queue and
    // the next `mem_send` reads a null field inside `session_pack_extension` — the
    // segfault that `session.goaway()` on a live stream reproduced every time.
    //
    // `closing` is set either way: it drives stream refusal, which must take effect
    // from the moment JavaScript asked, not from the moment nghttp2 heard.
    session.closing.set(true);
    let submit = DeferredSubmit::Goaway {
        code,
        last_stream_id,
        data: data.to_vec(),
    };
    defer_or(session, submit, || {
        submit_goaway_now(session, code, last_stream_id, data)
    });
}

/// Hands a GOAWAY to nghttp2, which must not be inside `mem_recv`.
fn submit_goaway_now(session: &SessionState, code: u32, last_stream_id: i32, data: &[u8]) {
    let Some(raw) = raw(session) else {
        return;
    };
    // `core.js` passes 0 to mean "the last one nghttp2 processed"; nghttp2 reads a
    // negative value that way, so it is translated here.
    let last = if last_stream_id == 0 {
        -1
    } else {
        last_stream_id
    };
    // SAFETY: `raw` is live, this is never called from inside `mem_recv`, and
    // `data` is readable for its length.
    unsafe {
        ffi::nghttp2_submit_goaway(
            raw,
            ffi::NGHTTP2_FLAG_NONE,
            last,
            code,
            data.as_ptr(),
            data.len(),
        );
    }
    schedule_write(session);
}

/// A PING with `payload`, which is `Http2Session::Ping`.
pub fn ping(session: &SessionState, payload: &[u8; 8]) -> i32 {
    let Some(raw) = raw(session) else {
        return -901;
    };
    // SAFETY: `raw` is live and `payload` is exactly the eight bytes nghttp2
    // reads.
    let status = unsafe { ffi::nghttp2_submit_ping(raw, ffi::NGHTTP2_FLAG_NONE, payload.as_ptr()) };
    schedule_write(session);
    status
}
