//! `binding.Http2Stream`: one stream's handle and its prototype methods.
//!
//! `lib/internal/http2/core.js` never constructs this. It receives one as the
//! `handle` argument of `onSessionHeaders` and wraps it:
//!
//! ```js
//! stream = new ServerHttp2Stream(session, handle, id, {}, obj);
//! ```
//!
//! so the handle has to exist before that callback fires. [`handle_for`] creates it
//! from the callbacks module, and the session keeps it rooted per id so a later
//! `on_data_chunk` or `on_stream_close` can reach it — there is no local handle in a
//! libuv callback. Node gets the same reachability from
//! `nghttp2_session_set_stream_user_data`, which stores a pointer in nghttp2's own
//! stream object; a map of `v8::Global`s is the Rust spelling.
//!
//! # Scope of this increment
//!
//! The constructor, the id, the state refresh and the four `StreamBase` counters are
//! installed. The frame-submitting methods (`respond`, `info`, `trailers`,
//! `pushPromise`) submit real nghttp2 frames. The write path copies into a pending
//! queue that [`provider`] drains, rather than reading back through a `StreamBase`,
//! because the writable side in `core.js` is a JavaScript `Duplex`.
//!
//! `sendFile`'s descriptor path is absent: it needs `fs`'s `FileHandle`, which is
//! deferred in `rn-bind-fs`, and nothing else in `lib/**` reaches for it.

pub mod provider;

use std::cell::{Cell, RefCell};
use std::ptr;

use rn_v8_sys::v8;

use crate::ffi;
use crate::session::SessionState;

/// The internal field holding the `*mut StreamHandleState`.
const STREAM_FIELD: i32 = 0;

/// The native half of a `binding.Http2Stream`.
///
/// The authoritative stream record lives in [`SessionState::streams`] keyed by id,
/// because nghttp2 owns the protocol state and the record is only what the
/// callbacks need to see. This struct carries what each prototype method needs
/// without a second map lookup.
pub struct StreamHandleState {
    /// The session this stream belongs to.
    pub session: *mut SessionState,
    /// `nghttp2_stream`'s id.
    pub id: i32,
    /// `headers_category()`.
    pub category: i32,
    /// `streamOptions` the stream was created with.
    pub options: i32,
    /// The JS object, rooted.
    pub object: RefCell<Option<v8::Global<v8::Object>>>,
    /// Whether the readable side has been started.
    pub reading: Cell<bool>,
}

/// Builds the `Http2Stream` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name = v8::String::new(scope, "Http2Stream")
        .ok_or("cannot allocate the Http2Stream class name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(STREAM_FIELD as usize + 1);

    let prototype = template.prototype_template(scope);
    macro_rules! install {
        ($($name:literal => $method:expr),* $(,)?) => {
            $(
                let method_template = v8::FunctionTemplate::builder($method)
                    .length(0)
                    .constructor_behavior(v8::ConstructorBehavior::Throw)
                    .build(scope);
                let key = v8::String::new(scope, $name)
                    .ok_or_else(|| format!("cannot allocate Http2Stream.{}", $name))?;
                prototype.set(key.into(), method_template.into());
            )*
        };
    }
    install! {
        "id" => get_id,
        "destroy" => destroy,
        "rstStream" => rst_stream,
        "respond" => respond,
        "info" => info,
        "trailers" => trailers,
        "pushPromise" => push_promise,
        "priority" => priority,
        "disableAutoTrailers" => disable_auto_trailers,
        "refreshState" => refresh_state,
        "readStart" => read_start,
        "readStop" => read_stop,
        "shutdown" => shutdown,
        "writeBuffer" => write_buffer,
        "writev" => writev,
        "writeAsciiString" => write_ascii,
        "writeUtf8String" => write_utf8,
        "writeUcs2String" => write_ucs2,
        "writeLatin1String" => write_latin1,
        "useUserBuffer" => use_user_buffer,
        "bytesRead" => get_bytes_read,
        "bytesWritten" => get_bytes_written,
        "getAsyncId" => get_async_id,
    }

    template
        .get_function(scope)
        .map(Into::into)
        .ok_or_else(|| "cannot allocate the Http2Stream constructor".to_string())
}

/// `new binding.Http2Stream()`.
///
/// Node's template has **no** `New` callback — `Initialize` builds it with
/// `FunctionTemplate::New(isolate)` and a class name — so constructing one from
/// JavaScript yields an empty object carrying the prototype and an internal field.
/// [crate::stream::handle_for] is what fills that field in when *this* crate makes
/// the stream, which is the only path any caller takes; a bare construction has no
/// state and every method on it reports the "no state" case rather than crashing.
fn new(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
}

/// The state behind a stream handle object.
fn with_state<R>(
    object: v8::Local<'_, v8::Object>,
    body: impl FnOnce(&StreamHandleState) -> R,
) -> Option<R> {
    if object.internal_field_count() <= STREAM_FIELD as usize {
        return None;
    }
    // SAFETY: the field only ever holds a pointer installed by `handle_for`, and
    // the object is a live local so its finalizer has not run.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STREAM_FIELD, 0) }
        as *mut StreamHandleState;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above; the borrow is scoped to one callback.
    Some(body(unsafe { &*pointer }))
}

/// The session behind a stream handle.
fn session_of(object: v8::Local<'_, v8::Object>) -> Option<&'static SessionState> {
    let pointer = with_state(object, |state| state.session)?;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: a stream is only reachable through the session that created it, so
    // the session outlives it.
    Some(unsafe { &*pointer })
}

/// Creates the JS handle for `stream_id`, reusing the one the session holds.
pub fn handle_for<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    session: &SessionState,
    stream_id: i32,
    category: i32,
    options: i32,
) -> Option<v8::Local<'s, v8::Object>> {
    if let Some(existing) = session.handles.borrow().get(&stream_id) {
        return Some(v8::Local::new(scope, existing));
    }
    let function = v8::Local::<v8::Function>::try_from(constructor(scope).ok()?).ok()?;
    let object = function.new_instance(scope, &[])?;

    let state = Box::into_raw(Box::new(StreamHandleState {
        session: (session as *const SessionState).cast_mut(),
        id: stream_id,
        category,
        options,
        object: RefCell::new(Some(v8::Global::new(scope.as_ref(), object))),
        reading: Cell::new(false),
    }));
    object.set_aligned_pointer_in_internal_field(STREAM_FIELD, state.cast::<std::ffi::c_void>(), 0);

    let address = state as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this finalizer
            // runs exactly once.
            drop(unsafe { Box::from_raw(address as *mut StreamHandleState) });
        }),
    );
    // The weak handle must outlive the object it finalizes.
    std::mem::forget(weak);

    session
        .handles
        .borrow_mut()
        .insert(stream_id, v8::Global::new(scope.as_ref(), object));
    Some(object)
}

/// The JS handle for `stream_id`, if one exists.
pub fn object_for<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    session: &SessionState,
    stream_id: i32,
) -> Option<v8::Local<'s, v8::Object>> {
    session
        .handles
        .borrow()
        .get(&stream_id)
        .map(|handle| v8::Local::new(scope, handle))
}

/// Delivers `bytes` to `stream_id`'s readable side through its `onread`.
///
/// `stream_base_commons.js`'s `onStreamRead` does not take the byte count as an
/// argument: it reads it from `streamBaseState[kReadBytesOrError]` and builds a
/// `FastBuffer` over the `ArrayBuffer` it is given at
/// `streamBaseState[kArrayBufferOffset]`. So the count is published first, then
/// `onread` is called with the buffer — which is exactly what
/// `CallJSOnreadMethod` does.
///
/// The `onread` a stream handle carries is assigned by `core.js` in `kInit`
/// (`handle.onread = onStreamRead`), so the property lookup is the same one
/// `lib/net.js` relies on.
pub fn deliver_data(session: &SessionState, stream_id: i32, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    {
        let mut streams = session.streams.borrow_mut();
        let Some(record) = streams.get_mut(&stream_id) else {
            return;
        };
        record.received_bytes += bytes.len() as u64;
    }
    let payload = bytes.to_vec();
    let _ = rn_uv::callback::with_context(|scope| {
        let Some(object) = object_for(scope, session, stream_id) else {
            return;
        };
        // `streamBaseState[kReadBytesOrError] = nread`, without which `onStreamRead`
        // sees a stale count and pushes the wrong slice.
        rn_uv::stream::with_state(|state| {
            state.set(rn_uv::handle::K_READ_BYTES_OR_ERROR, payload.len() as u32)
        });
        let handler = onread_of(scope, object);
        let Some(handler) = handler else {
            return;
        };
        let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(payload.into_boxed_slice());
        let store: v8::SharedRef<v8::BackingStore> = store.into();
        let buffer: v8::Local<v8::Value> =
            v8::ArrayBuffer::with_backing_store(scope, &store).into();
        let _ = handler.call(scope, object.into(), &[buffer]);
    });
}

/// Reports end-of-stream on `stream_id`'s readable side.
///
/// A non-positive count is how `onStreamRead` learns the stream ended:
/// `lib/net.js` turns `UV_EOF` into `'end'` and any other negative into
/// `'error'`.
pub fn emit_eof(session: &SessionState, stream_id: i32) {
    let _ = rn_uv::callback::with_context(|scope| {
        let Some(object) = object_for(scope, session, stream_id) else {
            return;
        };
        rn_uv::stream::with_state(|state| {
            state.set(rn_uv::handle::K_READ_BYTES_OR_ERROR, EOF as u32)
        });
        let Some(handler) = onread_of(scope, object) else {
            return;
        };
        // No buffer argument, as `CallJSOnreadMethod` does for an error.
        let _ = handler.call(scope, object.into(), &[]);
    });
}

/// `UV_EOF`.
const EOF: i32 = -4095;

/// The `onread` a stream handle carries, if `core.js` assigned one.
fn onread_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, "onread")?;
    let value = object.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

/// Takes up to `limit` bytes from a stream's pending queue.
///
/// Returns `(bytes, ended)`, or `None` when the stream has no record. `ended` says
/// whether the stream is finished, which is what lets the provider report
/// `NGHTTP2_DATA_FLAG_EOF` rather than asking to be called again.
///
/// Scope-free on purpose: the provider's read callback runs inside
/// `nghttp2_session_mem_send`, and taking a `Vec<u8>` needs no V8 at all.
pub fn take_pending(
    session: &SessionState,
    stream_id: i32,
    limit: usize,
) -> Option<(Vec<u8>, bool)> {
    let mut streams = session.streams.borrow_mut();
    let record = streams.get_mut(&stream_id)?;
    let take = record.pending.len().min(limit);
    let bytes = record.pending.drain(..take).collect::<Vec<u8>>();
    record.sent_bytes += take as u64;
    Some((bytes, record.ended && record.pending.is_empty()))
}

/// Calls a per-stream callback with the stream handle as the receiver.
///
/// Used by `on_stream_close` and the trailer path, where `core.js`'s callback reads
/// `this[kOwner]` to find the `Http2Stream` it belongs to.
pub fn call_stream_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    session: &SessionState,
    stream_id: i32,
    pick: impl FnOnce(&crate::SessionCallbacks) -> Option<v8::Global<v8::Function>>,
    args: &[v8::Local<'s, v8::Value>],
) {
    let Some(object) = object_for(scope, session, stream_id) else {
        return;
    };
    let Some(callback) = crate::callbacks::pick_global(pick) else {
        return;
    };
    let callback = v8::Local::new(scope, callback);
    let _ = callback.call(scope, object.into(), args);
}

/// `Http2Stream::GetID`.
fn get_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = with_state(args.this(), |state| state.id).unwrap_or(-1);
    rv.set(v8::Integer::new(scope, id).into());
}

/// `Http2Stream::Destroy`.
fn destroy(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if let (Some(state), Some(id)) = (
        session_of(args.this()),
        with_state(args.this(), |handle| handle.id),
    ) {
        if let Some(record) = state.streams.borrow_mut().get_mut(&id) {
            record.destroyed = true;
        }
        submit_rst(state, id, ffi::NGHTTP2_CANCEL_CODE);
    }
}

/// `Http2Stream::RstStream`.
fn rst_stream(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let code = args.get(0).uint32_value(scope).unwrap_or(0);
    if let (Some(state), Some(id)) = (
        session_of(args.this()),
        with_state(args.this(), |handle| handle.id),
    ) {
        submit_rst(state, id, code);
    }
}

/// Submits an RST_STREAM and schedules the write that carries it.
fn submit_rst(state: &SessionState, stream_id: i32, code: u32) {
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    // SAFETY: `raw` is a live nghttp2 session.
    unsafe {
        ffi::nghttp2_submit_rst_stream(raw, ffi::NGHTTP2_FLAG_NONE, stream_id, code);
    }
    crate::session::schedule_write(state);
}

/// `Http2Stream::Priority`: advisory only, and nghttp2 deprecated RFC 7540
/// priorities, which is why `test-http2-priority-event.js` notes they are gone.
fn priority(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
}

/// `Http2Stream::DisableAutoTrailers`.
fn disable_auto_trailers(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if let (Some(state), Some(id)) = (
        session_of(args.this()),
        with_state(args.this(), |handle| handle.id),
    ) {
        if let Some(record) = state.streams.borrow_mut().get_mut(&id) {
            record.want_trailers = true;
        }
    }
}

/// Submits a header block for `id` with `flags`, returning nghttp2's status.
fn submit_headers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    flags: u8,
) -> Option<i32> {
    let state = session_of(args.this())?;
    let id = with_state(args.this(), |handle| handle.id)?;
    let raw = crate::session_ptr(state)?;
    let headers = crate::headers::nv_from_array(scope, args.get(0))?;
    // SAFETY: `raw` is live and `headers` owns its storage for the call; nghttp2
    // copies the pairs it is given.
    let status = unsafe {
        ffi::nghttp2_submit_headers(
            raw,
            flags,
            id,
            ptr::null(),
            headers.as_ptr(),
            headers.len(),
            ptr::null_mut(),
        )
    };
    crate::session::schedule_write(state);
    Some(status)
}

/// `Http2Stream::Info`: non-final HEADERS, no END_STREAM.
fn info(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    match submit_headers(scope, args, ffi::NGHTTP2_FLAG_NONE) {
        Some(status) => rv.set(v8::Integer::new(scope, status).into()),
        None => rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_INVALID_ARGUMENT).into()),
    }
}

/// `Http2Stream::Trailers`.
fn trailers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    let Some(headers) = crate::headers::nv_from_array(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_INVALID_ARGUMENT).into());
        return;
    };
    // SAFETY: `raw` is live and `headers` owns its storage for the call.
    let status = unsafe { ffi::nghttp2_submit_trailer(raw, id, headers.as_ptr(), headers.len()) };
    crate::session::schedule_write(state);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `Http2Stream::PushPromise`.
fn push_promise(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    if state.session_type != crate::session::SESSION_SERVER {
        rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_PROTO).into());
        return;
    }
    let Some(headers) = crate::headers::nv_from_array(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_INVALID_ARGUMENT).into());
        return;
    };
    // SAFETY: `raw` is live and `headers` owns its storage for the call.
    let promised = unsafe {
        ffi::nghttp2_submit_push_promise(
            raw,
            ffi::NGHTTP2_FLAG_NONE,
            id,
            headers.as_ptr(),
            headers.len(),
            ptr::null_mut(),
        )
    };
    if promised > 0 {
        state.streams.borrow_mut().insert(
            promised,
            crate::session::StreamRecord {
                id: promised,
                category: ffi::NGHTTP2_HCAT_PUSH_RESPONSE,
                ..Default::default()
            },
        );
    }
    crate::session::schedule_write(state);
    rv.set(v8::Integer::new(scope, promised).into());
}

/// `Http2Stream::Respond`: the final response HEADERS, with a body provider.
fn respond(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    let Some(headers) = crate::headers::nv_from_array(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_INVALID_ARGUMENT).into());
        return;
    };
    let options = args.get(1).uint32_value(scope).unwrap_or(0) as i32;
    let empty_payload = options & crate::STREAM_OPTION_EMPTY_PAYLOAD != 0;
    let provider = provider::Provider::new(state, id, options);
    // `nghttp2_submit_response2` half-closes the outbound stream, which is why
    // `core.js` uses it only for the final response and `info` for anything else.
    // SAFETY: `raw` is live, `headers` owns its storage for the call, and
    // `provider` outlives it.
    let status = unsafe {
        ffi::nghttp2_submit_response2(
            raw,
            id,
            headers.as_ptr(),
            headers.len(),
            if empty_payload {
                ptr::null()
            } else {
                provider.as_ptr()
            },
        )
    };
    if status != 0 {
        rv.set(v8::Integer::new(scope, status).into());
        return;
    }
    crate::session::schedule_write(state);
    rv.set(v8::Integer::new(scope, id).into());
}

/// `Http2Stream::RefreshState`: publish this stream's window and close flags.
fn refresh_state(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    // SAFETY: `raw` is live and every getter below only reads.
    let (window, local_close, remote_close) = unsafe {
        (
            ffi::nghttp2_session_get_stream_local_window_size(raw, id),
            ffi::nghttp2_session_get_stream_local_close(raw, id),
            ffi::nghttp2_session_get_stream_remote_close(raw, id),
        )
    };
    let _ = crate::state::Http2State::with(|shared| {
        shared.set_stream_state(
            crate::state::IDX_STREAM_STATE_LOCAL_WINDOW_SIZE,
            f64::from(window),
        );
        shared.set_stream_state(
            crate::state::IDX_STREAM_STATE_LOCAL_CLOSE,
            f64::from(local_close),
        );
        shared.set_stream_state(
            crate::state::IDX_STREAM_STATE_REMOTE_CLOSE,
            f64::from(remote_close),
        );
    });
}

/// `StreamBase::ReadStart`.
fn read_start(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    with_state(args.this(), |state| state.reading.set(true));
}

/// `StreamBase::ReadStop`.
fn read_stop(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    with_state(args.this(), |state| state.reading.set(false));
}

/// `StreamBase::Shutdown`: end this stream's writable side.
fn shutdown(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    if let Some(record) = state.streams.borrow_mut().get_mut(&id) {
        record.ended = true;
    }
    let provider = provider::Provider::end_stream();
    // SAFETY: `raw` is live and the provider outlives the call.
    let status = unsafe {
        ffi::nghttp2_submit_data2(raw, ffi::NGHTTP2_FLAG_END_STREAM, id, provider.as_ptr())
    };
    crate::session::schedule_write(state);
    if let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) {
        rn_bind_stream_wrap::wrap::report_completion(scope, request, status, None, None);
    }
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::Writev`, which `stream_base_commons.js` reaches when the chunk
/// is a buffer list.
fn writev(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let mut bytes = Vec::new();
    if let Ok(array) = v8::Local::<v8::Array>::try_from(args.get(1)) {
        // `allBuffers` is the third argument; `core.js` passes `true` from
        // `writeGeneric`, so every entry is a buffer and the array is flat.
        let all_buffers = args.get(2).boolean_value(scope);
        let stride = if all_buffers { 1 } else { 2 };
        let count = (array.length() as usize) / stride;
        for index in 0..count {
            let Some(value) = array.get_index(scope, (index * stride) as u32) else {
                continue;
            };
            // SAFETY: `stream_base_commons` keeps every view alive on `req.chunks`.
            if let Some(buffer) = unsafe { rn_uv::stream_base::view_buffer(value) } {
                // SAFETY: the view is live for this call.
                let slice =
                    unsafe { std::slice::from_raw_parts(buffer.base.cast::<u8>(), buffer.len) };
                bytes.extend_from_slice(slice);
            }
        }
    }
    queue_write(scope, args.this(), id, bytes, args.get(0), &mut rv);
}

/// The four `write*String` forms, which differ only in encoding.
///
/// `writeGeneric` in `lib/internal/stream_base_commons.js` reaches these for a
/// string chunk, and which one it picks depends on the encoding the caller asked
/// for — so all four have to exist or a plain `stream.end('text')` fails with
/// "is not a function".
fn write_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    encoding: rn_core::Encoding,
    rv: &mut v8::ReturnValue<'_>,
) {
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Ok(text) = v8::Local::<v8::String>::try_from(args.get(1)) else {
        let _ = scope;
        return;
    };
    let length = text.length();
    let mut units = vec![0u16; length];
    text.write_v2(scope, 0, &mut units, v8::WriteFlags::empty());
    let bytes = rn_core::codec::write(
        &units,
        encoding,
        rn_core::codec::storage_size(&units, encoding),
    );
    queue_write(scope, args.this(), id, bytes, args.get(0), rv);
}

/// `writeAsciiString`.
fn write_ascii(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_string(scope, args, rn_core::Encoding::Ascii, &mut rv);
}

/// `writeUtf8String`.
fn write_utf8(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_string(scope, args, rn_core::Encoding::Utf8, &mut rv);
}

/// `writeUcs2String`.
fn write_ucs2(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_string(scope, args, rn_core::Encoding::Ucs2, &mut rv);
}

/// `writeLatin1String`.
fn write_latin1(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_string(scope, args, rn_core::Encoding::Binary, &mut rv);
}

/// `StreamBase::WriteBuffer`.
fn write_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    // SAFETY: `stream_base_commons` keeps the view alive on `req.buffer`.
    let Some(buffer) = (unsafe { rn_uv::stream_base::view_buffer(args.get(1)) }) else {
        rv.set(v8::Integer::new(scope, -22).into());
        return;
    };
    // SAFETY: the view is live for the call; the bytes are copied below.
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.base.cast::<u8>(), buffer.len) }.to_vec();
    queue_write(scope, args.this(), id, bytes, args.get(0), &mut rv);
}

/// Submits `bytes` as a DATA frame on `id`.
fn queue_write(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    id: i32,
    bytes: Vec<u8>,
    request: v8::Local<'_, v8::Value>,
    rv: &mut v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(object) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    if let Some(record) = state.streams.borrow_mut().get_mut(&id) {
        record.pending.extend_from_slice(&bytes);
    }
    let provider = provider::Provider::new(state, id, 0);
    // SAFETY: `raw` is live and the provider outlives the call.
    let status =
        unsafe { ffi::nghttp2_submit_data2(raw, ffi::NGHTTP2_FLAG_NONE, id, provider.as_ptr()) };
    crate::session::schedule_write(state);
    if let Ok(request) = v8::Local::<v8::Object>::try_from(request) {
        rn_bind_stream_wrap::wrap::report_completion(scope, request, status, None, None);
    }
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::UseUserBuffer`, which an HTTP/2 stream does not support.
fn use_user_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    /// `UV_ENOTSUP`.
    const ENOTSUP: i32 = -4028;
    rv.set(v8::Integer::new(scope, ENOTSUP).into());
}

/// `StreamBase::bytesRead`.
fn get_bytes_read(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = session_of(args.this())
        .and_then(|session| {
            with_state(args.this(), |handle| handle.id).and_then(|id| {
                session
                    .streams
                    .borrow()
                    .get(&id)
                    .map(|record| record.received_bytes)
            })
        })
        .unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `StreamBase::bytesWritten`.
fn get_bytes_written(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = session_of(args.this())
        .and_then(|session| {
            with_state(args.this(), |handle| handle.id).and_then(|id| {
                session
                    .streams
                    .borrow()
                    .get(&id)
                    .map(|record| record.sent_bytes)
            })
        })
        .unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `AsyncWrap::getAsyncId`.
///
/// A stream has no `AsyncWrap` of its own here, so there is no id to report.
/// `core.js` only stores the value on `async_id_symbol` for context propagation,
/// which is a separate slice; `-1` is the sentinel Node uses for "no id".
fn get_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set(v8::Number::new(scope, -1.0).into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_data_flag_bits_are_nghttp2s() {
        // The provider sets these on `*data_flags`; a wrong bit would either end a
        // stream early or never end it.
        assert_eq!(provider::DATA_FLAG_EOF, 0x01);
        assert_eq!(provider::ERR_DEFERRED, -508);
    }

    #[test]
    fn the_stream_field_count_leaves_room_for_the_state_pointer() {
        // `with_state` refuses an object whose field count is not larger than the
        // index, which is how a bare `{}` passed as a stream handle is rejected
        // rather than read as a null state.
        assert_eq!(STREAM_FIELD, 0);
    }
}
