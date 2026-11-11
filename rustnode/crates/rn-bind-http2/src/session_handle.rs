//! The `Http2Session` constructor, its prototype and its field object.
//!
//! `Initialize` in `src/node_http2.cc` builds this template with seventeen
//! `SetProtoMethod` calls, `AsyncWrap`'s template as its parent, and an internal
//! field count. This module reproduces that surface; the bodies live in
//! [`crate::session`] and [`crate::stream`] where they belong.
//!
//! # `fields`
//!
//! `Http2Session`'s constructor does `this[kNativeFields] = handle.fields`, and
//! `core.js` then reads `handle.fields.buffer` to write `maxSessionInvalidFrames`
//! and `maxSessionRejectedStreams` into it with a `Uint32Array` view. So `fields`
//! must be a `Uint8Array(12)` over a real `ArrayBuffer`, and the same buffer has to
//! be readable from here when a callback needs one of those numbers.
//!
//! # Why the object is created here and not by `core.js`
//!
//! `new binding.Http2Session(type)` is the only constructor `core.js` calls, and it
//! takes one argument. Everything else about the session — its socket, its
//! settings, its callbacks — arrives through method calls afterwards, which is why
//! the lifecycle methods all tolerate being called in any order.

use std::ffi::c_void;

use rn_v8_sys::v8;

use crate::session::{SessionState, SESSION_CLIENT, SESSION_SERVER};

/// The internal field holding the `*mut SessionState`.
const SESSION_FIELD: i32 = 0;

/// Builds the `Http2Session` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name = v8::String::new(scope, "Http2Session")
        .ok_or("cannot allocate the Http2Session class name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(SESSION_FIELD as usize + 1);

    let prototype = template.prototype_template(scope);
    macro_rules! install {
        ($($method_name:literal => $method:expr),* $(,)?) => {
            $(
                let method_template = v8::FunctionTemplate::builder($method)
                    .length(0)
                    .constructor_behavior(v8::ConstructorBehavior::Throw)
                    .build(scope);
                let key = v8::String::new(scope, $method_name)
                    .ok_or_else(|| format!("cannot allocate Http2Session.{}", $method_name))?;
                prototype.set(key.into(), method_template.into());
            )*
        };
    }
    // `Initialize`'s seventeen `SetProtoMethod` calls, in its order.
    install! {
        "origin" => origin,
        "altsvc" => altsvc,
        "ping" => ping,
        "consume" => consume,
        "receive" => receive,
        "destroy" => destroy,
        "goaway" => goaway,
        "hasPendingData" => has_pending_data,
        "settings" => settings,
        "request" => request,
        "setNextStreamID" => set_next_stream_id,
        "setLocalWindowSize" => set_local_window_size,
        "updateChunksSent" => update_chunks_sent,
        "refreshState" => refresh_state,
        "localSettings" => local_settings,
        "remoteSettings" => remote_settings,
        "setGracefulClose" => set_graceful_close,
    }

    template
        .get_function(scope)
        .map(Into::into)
        .ok_or_else(|| "cannot allocate the Http2Session constructor".to_string())
}

/// The state behind a session handle object.
pub fn with_state<R>(
    object: v8::Local<'_, v8::Object>,
    body: impl FnOnce(&SessionState) -> R,
) -> Option<R> {
    if object.internal_field_count() <= SESSION_FIELD as usize {
        return None;
    }
    // SAFETY: the field only ever holds a pointer installed by `new`, and the
    // object is a live local so its finalizer has not run.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(SESSION_FIELD, 0) }
        as *mut SessionState;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above; the borrow is scoped to one callback.
    Some(body(unsafe { &*pointer }))
}

/// `new binding.Http2Session(type)`.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        crate::throw_type_error(scope, "Http2Session cannot be invoked without 'new'");
        return;
    }
    let session_type = args.get(0).int32_value(scope).unwrap_or(SESSION_SERVER);
    if session_type != SESSION_SERVER && session_type != SESSION_CLIENT {
        crate::throw_type_error(scope, "Http2Session requires a valid session type");
        return;
    }
    let state = match SessionState::new(session_type) {
        Ok(state) => state,
        Err(reason) => {
            crate::throw_type_error(scope, &format!("Http2Session: {reason}"));
            return;
        }
    };
    let pointer = Box::into_raw(state);
    let object = args.this();
    object.set_aligned_pointer_in_internal_field(SESSION_FIELD, pointer.cast::<c_void>(), 0);

    // SAFETY: `pointer` came from `Box::into_raw` above and nothing else holds it.
    let state = unsafe { &*pointer };
    *state.object.borrow_mut() = Some(v8::Global::new(scope.as_ref(), object));

    // `fields`: a `Uint8Array(kSessionUint8FieldCount)` over a real `ArrayBuffer`,
    // so `core.js` can make a `Uint32Array` view at `kSessionMaxInvalidFrames`.
    let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(
        vec![0u8; crate::K_SESSION_UINT8_FIELD_COUNT as usize].into_boxed_slice(),
    );
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    *state.fields.borrow_mut() = Some(v8::Global::new(scope.as_ref(), buffer));
    let fields = v8::Uint8Array::new(
        scope,
        buffer,
        0,
        crate::K_SESSION_UINT8_FIELD_COUNT as usize,
    );
    let Some(fields) = fields else {
        crate::throw_type_error(scope, "cannot allocate the Http2Session fields array");
        return;
    };
    if let Some(key) = v8::String::new(scope, "fields") {
        object.set(scope, key.into(), fields.into());
    }

    // The two defaults `SessionJSFields` starts with, written through the typed
    // array so the bytes are at the offsets `core.js`'s `Uint32Array` view reads.
    write_field_u32(
        fields,
        crate::K_SESSION_MAX_INVALID_FRAMES as usize,
        crate::MAX_INVALID_FRAMES,
    );
    write_field_u32(
        fields,
        crate::K_SESSION_MAX_REJECTED_STREAMS as usize,
        crate::MAX_REJECTED_STREAMS,
    );

    // The connection-level window, which nghttp2 has no option setter for.
    crate::session::apply_connection_window(state);

    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this finalizer
            // runs exactly once.
            drop(unsafe { Box::from_raw(address as *mut SessionState) });
        }),
    );
    // The weak handle must outlive the object it finalizes.
    std::mem::forget(weak);

    rv.set(object.into());
}

/// Writes a `u32` into a `Uint8Array` at `offset`, in the array's endianness.
///
/// The bytes are written one at a time through the typed array rather than through
/// a raw backing-store pointer: the array is what `core.js` holds, so writing
/// through it cannot address a store the engine has since replaced.
fn write_field_u32(fields: v8::Local<'_, v8::Uint8Array>, offset: usize, value: u32) {
    // SAFETY: the engine keeps a `Uint8Array`'s backing store at a stable address
    // while the array is reachable, which it is — `fields` is a live local.
    unsafe {
        let data = fields.data().cast::<u8>();
        if data.is_null() {
            return;
        }
        let bytes = value.to_ne_bytes();
        for (index, byte) in bytes.iter().enumerate() {
            *data.add(offset + index) = *byte;
        }
    }
}

/// Calls `this.ondone()` when `core.js` installed one.
///
/// A throw from it is reported as an uncaught exception, which is what Node does
/// for a callback invoked through `MakeCallback`.
fn call_ondone(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<'_, v8::Object>) {
    let Some(key) = v8::String::new(scope, "ondone") else {
        return;
    };
    let Some(value) = object.get(scope, key.into()) else {
        return;
    };
    let Ok(handler) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };
    let _ = handler.call(scope, object.into(), &[]);
}

/// `Http2Session::Consume`: `handle.consume(socket._handle)`.
fn consume(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(stream_object) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        crate::throw_type_error(scope, "Http2Session.consume requires a stream handle");
        return;
    };
    let outcome = match with_state(args.this(), |state| state as *const SessionState) {
        // SAFETY: `state` came from the live object behind `args.this()`.
        Some(state) => crate::session::consume(scope, unsafe { &*state }, stream_object),
        None => Err("Http2Session.consume on a dead session".to_string()),
    };
    if let Err(reason) = outcome {
        crate::throw_type_error(scope, &reason);
    }
}

/// `Http2Session::Receive`: feed bytes to nghttp2 directly.
fn receive(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(0)) else {
        return;
    };
    let length = view.byte_length();
    let mut bytes = vec![0u8; length];
    view.copy_contents(&mut bytes);
    if let Some(state) = with_state(args.this(), |state| state as *const SessionState) {
        // SAFETY: `state` came from the live object behind `args.this()`.
        let state = unsafe { &*state };
        crate::session::receive(state, &bytes, scope);
    }
}

/// `Http2Session::Destroy`: close and free the nghttp2 session.
fn destroy(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let code = args
        .get(0)
        .uint32_value(scope)
        .unwrap_or(crate::ffi::NGHTTP2_CANCEL_CODE);
    let object = args.this();
    let socket_destroyed = args.get(1).boolean_value(scope);
    // The order here is the whole fix. `core.js` sets `handle.ondone` right before
    // calling this, and `finishSessionClose` is what ends the socket — so it runs
    // *first*, while the session can still write its GOAWAY and while the socket
    // object is intact. Disposing before it left `finishSessionClose` with a dead
    // handle and an unended socket: the loop never drained and every file that
    // reached this path timed out.
    if let Some(state) = with_state(object, |state| state as *const SessionState) {
        // SAFETY: as `receive`.
        let state = unsafe { &*state };
        crate::session::close(scope, state, code);
    }
    call_ondone(scope, object);
    if let Some(state) = with_state(object, |state| state as *const SessionState) {
        // SAFETY: as `receive`.
        let state = unsafe { &*state };
        crate::session::detach(state, socket_destroyed);
    }
}

/// `Http2Session::Goaway`.
fn goaway(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let code = args.get(0).uint32_value(scope).unwrap_or(0);
    let last_stream_id = args.get(1).int32_value(scope).unwrap_or(0);
    let mut data = Vec::new();
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(2)) {
        let length = view.byte_length();
        data.resize(length, 0);
        view.copy_contents(&mut data);
    }
    if let Some(state) = with_state(args.this(), |state| state as *const SessionState) {
        // SAFETY: as `receive`.
        let state = unsafe { &*state };
        crate::session::goaway(state, code, last_stream_id, &data);
    }
}

/// `Http2Session::Ping`.
fn ping(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let mut payload = [0u8; 8];
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(0)) {
        let mut bytes = vec![0u8; view.byte_length()];
        view.copy_contents(&mut bytes);
        let count = bytes.len().min(8);
        payload[..count].copy_from_slice(&bytes[..count]);
    }
    if let Some(state) = with_state(args.this(), |state| state as *const SessionState) {
        // SAFETY: as `receive`.
        let state = unsafe { &*state };
        let status = crate::session::ping(state, &payload);
        rv.set(v8::Integer::new(scope, status).into());
    }
}

/// `Http2Session::Settings`: submit a SETTINGS frame.
fn settings(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if let Some(state) = with_state(args.this(), |state| state as *const SessionState) {
        // SAFETY: as `receive`.
        let state = unsafe { &*state };
        let status = crate::session::submit_settings(state);
        rv.set(v8::Boolean::new(scope, status == 0).into());
    }
}

/// `Http2Session::Request`: open a client stream.
fn request(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = with_state(args.this(), |state| state as *const SessionState) else {
        return;
    };
    // SAFETY: as `receive`.
    let state = unsafe { &*state };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    let Some(headers) = crate::headers::nv_from_array(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, crate::ffi::NGHTTP2_ERR_INVALID_ARGUMENT).into());
        return;
    };
    let options = args.get(1).uint32_value(scope).unwrap_or(0) as i32;
    let parent = args.get(2).int32_value(scope).unwrap_or(0);
    let weight = args.get(3).int32_value(scope).unwrap_or(16);
    let exclusive = args.get(4).boolean_value(scope);

    let mut pri_spec = crate::ffi::nghttp2_priority_spec {
        stream_id: parent,
        weight,
        exclusive: i32::from(exclusive),
    };
    let pri = if parent > 0 {
        &mut pri_spec as *mut _
    } else {
        std::ptr::null_mut()
    };
    let empty_payload = options & crate::STREAM_OPTION_EMPTY_PAYLOAD != 0;
    let provider = crate::stream::provider::Provider::new(state, 0, options);

    // SAFETY: `raw` is live, `headers` owns its storage for the call, and `pri` is
    // either null or points at a live spec.
    let stream_id = unsafe {
        crate::ffi::nghttp2_submit_request2(
            raw,
            pri,
            headers.as_ptr(),
            headers.len(),
            if empty_payload {
                std::ptr::null()
            } else {
                provider.as_ptr()
            },
            std::ptr::null_mut(),
        )
    };
    if stream_id <= 0 {
        // `Request` returns the negative code so `core.js` can turn it into
        // `ERR_HTTP2_OUT_OF_STREAMS` or `ERR_HTTP2_STREAM_SELF_DEPENDENCY`.
        rv.set(v8::Integer::new(scope, stream_id).into());
        return;
    }
    state.streams.borrow_mut().insert(
        stream_id,
        crate::session::StreamRecord {
            id: stream_id,
            category: crate::ffi::NGHTTP2_HCAT_REQUEST,
            options,
            ..Default::default()
        },
    );
    // On success `Request` returns the *handle object*, not the id: `core.js`
    // immediately calls `ret.id()` and `this[kInit](ret.id(), ret)`, so a number
    // here would be read as an error code and the stream would be cancelled.
    let Some(handle) = crate::stream::handle_for(
        scope,
        state,
        stream_id,
        crate::ffi::NGHTTP2_HCAT_REQUEST,
        options,
    ) else {
        rv.set(v8::Integer::new(scope, stream_id).into());
        return;
    };
    crate::session::schedule_write(state);
    rv.set(handle.into());
}

/// `Http2Session::SetNextStreamID`.
fn set_next_stream_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = args.get(0).int32_value(scope).unwrap_or(0);
    let Some(state) = with_state(args.this(), |state| state as *const SessionState) else {
        return;
    };
    // SAFETY: as `receive`.
    let state = unsafe { &*state };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    // SAFETY: `raw` is live.
    let status = unsafe { crate::ffi::nghttp2_session_set_next_stream_id(raw, id) };
    rv.set(v8::Boolean::new(scope, status >= 0).into());
}

/// `Http2Session::SetLocalWindowSize`.
fn set_local_window_size(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let window = args.get(0).int32_value(scope).unwrap_or(0);
    let Some(state) = with_state(args.this(), |state| state as *const SessionState) else {
        return;
    };
    // SAFETY: as `receive`.
    let state = unsafe { &*state };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    // SAFETY: `raw` is live and stream 0 is the connection.
    let status = unsafe {
        crate::ffi::nghttp2_session_set_local_window_size(
            raw,
            crate::ffi::NGHTTP2_FLAG_NONE,
            0,
            window,
        )
    };
    rv.set(v8::Integer::new(scope, status).into());
}

/// `Http2Session::UpdateChunksSent`.
fn update_chunks_sent(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if let Some(state) = with_state(args.this(), |state| state as *const SessionState) {
        // SAFETY: as `receive`.
        let state = unsafe { &*state };
        state.chunks_sent.set(0);
    }
}

/// `Http2Session::HasPendingData`.
fn has_pending_data(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let pending = with_state(args.this(), |state| state.has_pending_data.get()).unwrap_or(false);
    rv.set(v8::Boolean::new(scope, pending).into());
}

/// `Http2Session::RefreshState`.
fn refresh_state(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if let Some(state) = with_state(args.this(), |state| state as *const SessionState) {
        // SAFETY: as `receive`.
        let state = unsafe { &*state };
        crate::session::refresh_state(state);
    }
}

/// `Http2Session::RefreshSettings<get_local_settings, true>`.
fn local_settings(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    refresh_settings(args.this(), true);
}

/// `Http2Session::RefreshSettings<get_remote_settings, false>`.
fn remote_settings(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    refresh_settings(args.this(), false);
}

/// `Http2Settings::Update`: write the seven settings into the shared buffer.
fn refresh_settings(object: v8::Local<'_, v8::Object>, local: bool) {
    let Some(state) = with_state(object, |state| state as *const SessionState) else {
        return;
    };
    // SAFETY: `state` came from the live object behind `object`.
    let state = unsafe { &*state };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    let values: [(usize, i32); 7] = [
        (
            crate::state::IDX_SETTINGS_HEADER_TABLE_SIZE,
            crate::ffi::NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
        ),
        (
            crate::state::IDX_SETTINGS_ENABLE_PUSH,
            crate::ffi::NGHTTP2_SETTINGS_ENABLE_PUSH,
        ),
        (
            crate::state::IDX_SETTINGS_MAX_CONCURRENT_STREAMS,
            crate::ffi::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
        ),
        (
            crate::state::IDX_SETTINGS_INITIAL_WINDOW_SIZE,
            crate::ffi::NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
        ),
        (
            crate::state::IDX_SETTINGS_MAX_FRAME_SIZE,
            crate::ffi::NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
        ),
        (
            crate::state::IDX_SETTINGS_MAX_HEADER_LIST_SIZE,
            crate::ffi::NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
        ),
        (
            crate::state::IDX_SETTINGS_ENABLE_CONNECT_PROTOCOL,
            crate::ffi::NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
        ),
    ];
    let _ = crate::state::Http2State::with(|shared| {
        for (index, id) in values {
            // SAFETY: `raw` is live and the getters only read.
            let value = unsafe {
                if local {
                    crate::ffi::nghttp2_session_get_local_settings(raw, id)
                } else {
                    crate::ffi::nghttp2_session_get_remote_settings(raw, id)
                }
            };
            shared.set_setting(index, value);
        }
        // The flag bitset names which settings are present, and
        // `getSettings` in `util.js` reports a settings object by reading them
        // unconditionally — it does not consult the flags — so setting every bit
        // is what makes `session.localSettings()` return all seven.
        shared.set_setting(crate::state::IDX_SETTINGS_COUNT, 0x7f);
        shared.set_setting(crate::state::IDX_SETTINGS_COUNT + 1, 0);
    });
}

/// `Http2Session::Origin`: an ORIGIN frame.
fn origin(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(state) = with_state(args.this(), |state| state as *const SessionState) else {
        return;
    };
    // SAFETY: as `receive`.
    let state = unsafe { &*state };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    let mut entries: Vec<crate::ffi::Nghttp2OriginEntry> = Vec::new();
    let mut storage: Vec<Vec<u8>> = Vec::new();
    for index in 0..args.length() {
        let Some(text) = args.get(index).to_string(scope) else {
            continue;
        };
        let mut buffer = vec![0u8; text.length() * 3 + 3];
        let written = text.write_utf8_v2(scope, &mut buffer, v8::WriteFlags::empty(), None);
        buffer.truncate(written);
        storage.push(buffer);
    }
    for bytes in &storage {
        entries.push(crate::ffi::Nghttp2OriginEntry {
            origin: bytes.as_ptr().cast_mut(),
            origin_len: bytes.len(),
        });
    }
    // SAFETY: `raw` is live and both slices own their storage for the call.
    unsafe {
        crate::ffi::nghttp2_submit_origin(
            raw,
            crate::ffi::NGHTTP2_FLAG_NONE,
            entries.as_ptr(),
            entries.len(),
        );
    }
    crate::session::schedule_write(state);
}

/// `Http2Session::AltSvc`: an ALTSVC frame.
fn altsvc(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(state) = with_state(args.this(), |state| state as *const SessionState) else {
        return;
    };
    // SAFETY: as `receive`.
    let state = unsafe { &*state };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    let stream_id = args.get(0).int32_value(scope).unwrap_or(0);
    let text = |value: v8::Local<'_, v8::Value>| -> Option<Vec<u8>> {
        let text = value.to_string(scope)?;
        let mut buffer = vec![0u8; text.length() * 3 + 3];
        let written = text.write_utf8_v2(scope, &mut buffer, v8::WriteFlags::empty(), None);
        buffer.truncate(written);
        Some(buffer)
    };
    let Some(origin) = text(args.get(1)) else {
        return;
    };
    let Some(value) = text(args.get(2)) else {
        return;
    };
    // SAFETY: `raw` is live and both buffers are readable for their lengths.
    unsafe {
        crate::ffi::nghttp2_submit_altsvc(
            raw,
            crate::ffi::NGHTTP2_FLAG_NONE,
            stream_id,
            origin.as_ptr(),
            origin.len(),
            value.as_ptr(),
            value.len(),
        );
    }
    crate::session::schedule_write(state);
}

/// `Http2Session::setGracefulClose`.
fn set_graceful_close(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if let Some(state) = with_state(args.this(), |state| state as *const SessionState) {
        // SAFETY: as `receive`.
        let state = unsafe { &*state };
        state.closing.set(true);
        // `setGracefulCloseInitiated(true)`, then check immediately. The order in
        // `core.js` is `this.goaway()` *then* `handle.setGracefulClose()`, so by
        // the time this runs the GOAWAY has already been flushed and nothing else
        // will call back in — waiting for a later flush means waiting forever,
        // which is the `close()` timeout.
        state.graceful_close.set(true);
        crate::session::maybe_notify_graceful_close(state);
    }
}
