//! The `JSStream` prototype methods.
//!
//! Two directions, and keeping them apart is what makes this module readable:
//!
//! * **Native → JavaScript.** `readStart`, `readStop`, `shutdown` and the write
//!   forms call `this.onreadstart()`, `this.onreadstop()`, `this.onshutdown(req)`
//!   and `this.onwrite(req, bufs)`. Each returns a libuv-style status that the
//!   caller passes straight back to `lib/net.js`.
//! * **JavaScript → native.** `readBuffer(chunk)` hands bytes to the reading
//!   side, `emitEOF()` reports end of stream, and `finishWrite`/`finishShutdown`
//!   complete a request the JavaScript side has finished with.
//!
//! # The write protocol, and why the request may be the return value
//!
//! `StreamBase::Write` creates a `WriteWrap` when the caller did not supply one,
//! and `FinishWrite` returns that object so `lib/internal/stream_base_commons.js`
//! can attach `req.oncomplete` afterwards:
//!
//! ```js
//! const req = handle.writeBuffer(null, chunk);
//! if (typeof req === 'object') req.oncomplete = afterWriteDispatched;
//! else if (req !== 0) return afterWriteDispatched.call(this, { error: req });
//! ```
//!
//! So a write that never queued has to report a *number*, and one that did has to
//! report the request object. [`write_result`] is that decision in one place.
//!
//! # `streamBaseState`
//!
//! `onStreamRead` in `lib/internal/stream_base_commons.js` does not take the byte
//! count as an argument; it reads it out of the shared `streamBaseState` array,
//! which `stream_wrap` publishes. `readBuffer` therefore has to write the count
//! and the offset into that same array before calling `onread`, exactly as
//! `CallJSOnreadMethod` does. Sharing the array rather than keeping a second one
//! is the point of it being aliased.

use rn_v8_sys::v8;

use crate::handle::{self, with_slot, StreamSlot};

/// `UV_EPROTO`, what `src/js_stream.cc` returns when a hook could not be called.
const EPROTO: i32 = 71;
/// `UV_EINVAL`, `StreamBase::JSMethod`'s answer for a dead handle.
const EINVAL: i32 = 22;
/// `UV_EOF` from `uv.h`.
const EOF: i32 = -4095;

/// Calls `object[name]()` and returns its `i32` result.
///
/// `src/js_stream.cc` treats a missing hook, a throw and a non-integer result the
/// same way: `UV_EPROTO`. That is deliberate — `lib/internal/js_stream_socket.js`
/// assigns every hook in its constructor, so a missing one means the object is not
/// a `JSStreamSocket`, and reporting a protocol error beats silently succeeding.
pub(crate) fn call_int_hook<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    arguments: &[v8::Local<'s, v8::Value>],
) -> i32 {
    let Some(function) = hook(scope, object, name) else {
        return EPROTO;
    };
    let receiver: v8::Local<'_, v8::Value> = object.into();
    match function.call(scope, receiver, arguments) {
        Some(value) => value.int32_value(scope).unwrap_or(EPROTO),
        None => EPROTO,
    }
}

/// Reads `object[name]` as a function.
pub(crate) fn hook<'s>(
    scope: &v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, name)?;
    let value = object.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

/// Wraps `bytes` in a `Buffer`, which is what `DoWrite` hands to `onwrite`.
pub(crate) fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let view = v8::Uint8Array::new(scope, array_buffer, 0, bytes.len())?;
    if let Some(prototype) = buffer_prototype(scope) {
        view.set_prototype(scope, prototype.into());
    }
    Some(view.into())
}

/// `Buffer.prototype`, as `lib/buffer.js` installed it on the global.
pub(crate) fn buffer_prototype<'s>(
    scope: &v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let buffer = global.get(scope, key.into())?;
    let object = v8::Local::<v8::Object>::try_from(buffer).ok()?;
    let prototype_key = v8::String::new(scope, "prototype")?;
    let value = object.get(scope, prototype_key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Copies a `uv_buf_t`'s bytes into a fresh `Buffer`.
///
/// `src/js_stream.cc` does `Buffer::Copy(env, bufs[i].base, bufs[i].len)` for
/// exactly this reason: the caller may reuse its backing store as soon as the
/// write returns, so the bytes `onwrite` sees have to be its own.
pub(crate) fn copy_view<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Value>> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let length = view.byte_length();
    let base = view.data().cast::<u8>();
    if length == 0 {
        return buffer_from(scope, &[]);
    }
    if base.is_null() {
        return None;
    }
    // SAFETY: `base` points at `length` bytes of the caller's view, which is
    // alive for this call; the copy happens before it can be collected.
    let bytes = unsafe { std::slice::from_raw_parts(base, length) };
    buffer_from(scope, bytes)
}

/// Publishes a write outcome into `streamBaseState` and shapes the return value.
///
/// `StreamBase::SetWriteResult` writes the three fields, then `FinishWrite`
/// chooses between the request object and the status. `lazy` is `true` when the
/// caller passed no request, which is the case that can return the object.
pub(crate) fn publish_write(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue<'_>,
    bytes: usize,
    asynchronous: bool,
    status: i32,
    request: Option<v8::Local<'_, v8::Object>>,
    lazy: bool,
) {
    // The array is created by `stream_wrap`'s install; touching it here first
    // makes this crate independent of which namespace loaded earlier.
    let _ = rn_uv::stream::state_array(scope);
    rn_uv::stream::publish(&rn_uv::stream::WriteOutcome {
        bytes,
        asynchronous,
        error: status,
    });
    match request {
        Some(request) if lazy && status == 0 => rv.set(request.into()),
        _ => rv.set(v8::Integer::new(scope, status).into()),
    }
}

/// Builds the request object a write or shutdown needs when the caller supplied
/// none, matching `env->write_wrap_template()->InstanceTemplate()->NewInstance()`.
pub(crate) fn new_request<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    fields: &[&str],
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    let null = v8::null(scope);
    for name in fields {
        let key = v8::String::new(scope, name)?;
        object.set(scope, key.into(), null.into());
    }
    Some(object)
}

/// `StreamBase::ReadStartJS` → `JSStream::ReadStart`.
pub(crate) fn read_start<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let status = with_slot(object, |slot| {
        // A second `readStart` is harmless in Node — `net.Socket` guards it — but
        // recording the transition keeps `readStop` idempotent too.
        slot.reading.set(true);
        call_int_hook(scope, object, "onreadstart", &[])
    })
    .unwrap_or(EINVAL);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::ReadStopJS` → `JSStream::ReadStop`.
pub(crate) fn read_stop<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let status = with_slot(object, |slot| {
        slot.reading.set(false);
        call_int_hook(scope, object, "onreadstop", &[])
    })
    .unwrap_or(EINVAL);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::Shutdown` → `JSStream::DoShutdown`.
///
/// `lib/internal/js_stream_socket.js`'s `doShutdown` ends the wrapped stream and
/// calls back with `handle.finishShutdown(req, 0)`, so the status returned here
/// is only "did the call happen".
pub(crate) fn shutdown<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let given = v8::Local::<v8::Object>::try_from(args.get(0)).ok();
    let lazy = given.is_none();
    let Some(request) = given.or_else(|| new_request(scope, &["oncomplete", "callback", "handle"]))
    else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let argument: v8::Local<'_, v8::Value> = request.into();
    let status = with_slot(object, |_| {
        call_int_hook(scope, object, "onshutdown", &[argument])
    })
    .unwrap_or(EINVAL);
    if status == 0 && lazy {
        rv.set(request.into());
    } else {
        rv.set(v8::Integer::new(scope, status).into());
    }
}

/// `StreamBase::WriteBuffer` → `JSStream::DoWrite`.
pub(crate) fn write_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let chunk = args.get(1);
    let Some(argument) = copy_view(scope, chunk) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let length = v8::Local::<v8::ArrayBufferView>::try_from(chunk)
        .map(|view| view.byte_length())
        .unwrap_or(0);
    do_write(scope, &args, &mut rv, length, vec![argument]);
}

/// `StreamBase::Writev` → `JSStream::DoWrite` with one chunk per buffer.
pub(crate) fn writev<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Ok(chunks) = v8::Local::<v8::Array>::try_from(args.get(1)) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    // With `allBuffers` false the array alternates `[chunk, encoding, …]`, and
    // only the chunk slots hold data; `writevGeneric` has already converted every
    // non-buffer chunk before calling this, exactly as on a socket.
    let stride = if args.get(2).is_true() { 1 } else { 2 };
    let mut copies = Vec::new();
    let mut total = 0usize;
    let mut index = 0;
    while index < chunks.length() {
        let Some(value) = chunks.get_index(scope, index) else {
            rv.set(v8::Integer::new(scope, EINVAL).into());
            return;
        };
        let Some(copy) = copy_view(scope, value) else {
            rv.set(v8::Integer::new(scope, EINVAL).into());
            return;
        };
        if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
            total += view.byte_length();
        }
        copies.push(copy);
        index += stride;
    }
    do_write(scope, &args, &mut rv, total, copies);
}

/// `JSStream::DoWrite`: copy the buffers and call `onwrite(req, bufs)`.
pub(crate) fn do_write<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    rv: &mut v8::ReturnValue<'s>,
    total: usize,
    copies: Vec<v8::Local<'s, v8::Value>>,
) {
    let object = args.this();
    let given = v8::Local::<v8::Object>::try_from(args.get(0)).ok();
    let lazy = given.is_none();
    let Some(request) = given.or_else(|| {
        new_request(
            scope,
            &["oncomplete", "callback", "handle", "buffer", "writeStatus"],
        )
    }) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };

    // `bytes_written_ += total_bytes` happens in `StreamBase::Write` before
    // `DoWrite`, so `handle.bytesWritten` is already up to date inside
    // `onwrite`.
    with_slot(object, |slot| {
        slot.bytes_written
            .set(slot.bytes_written.get() + total as u64);
    });

    let buffers = v8::Array::new_with_elements(scope, &copies);
    let request_value: v8::Local<'_, v8::Value> = request.into();
    let buffers_value: v8::Local<'_, v8::Value> = buffers.into();
    let status = with_slot(object, |_| {
        call_int_hook(scope, object, "onwrite", &[request_value, buffers_value])
    })
    .unwrap_or(EINVAL);

    // `async = err == 0`: anything else means nothing was queued, so the request
    // is handed back to nobody and the status is what the caller reads.
    let queued = status == 0;
    publish_write(scope, rv, total, queued, status, Some(request), lazy);
}

/// `writeUtf8String`, `writeAsciiString`, `writeLatin1String`, `writeUcs2String`.
///
/// Node flattens the string with `StringBytes::Write` for the named encoding and
/// then writes the bytes. `StreamBase`'s `write*` family is reached from
/// `lib/internal/stream_base_commons.js` only when the chunk is a string and the
/// handle has no `writeBuffer`, which never happens for a `JSStreamSocket` — but
/// the methods exist on the prototype and have to behave.
macro_rules! write_string {
    ($name:ident) => {
        pub(crate) fn $name<'s>(
            scope: &mut v8::PinScope<'s, '_>,
            args: v8::FunctionCallbackArguments<'s>,
            mut rv: v8::ReturnValue<'s>,
        ) {
            let text = args.get(1);
            let Some(text) = text.to_string(scope) else {
                rv.set(v8::Integer::new(scope, EINVAL).into());
                return;
            };
            let mut storage = Vec::with_capacity(text.length().saturating_mul(4) + 4);
            storage.resize(text.length().saturating_mul(4) + 4, 0);
            let written =
                text.write_utf8_v2(scope.as_ref(), &mut storage, v8::WriteFlags::empty(), None);
            storage.truncate(written);
            let Some(argument) = buffer_from(scope, &storage) else {
                rv.set(v8::Integer::new(scope, EINVAL).into());
                return;
            };
            do_write(scope, &args, &mut rv, written, vec![argument]);
        }
    };
}

write_string!(write_utf8);
write_string!(write_ascii);
write_string!(write_latin1);
write_string!(write_ucs2);

/// `StreamBase::UseUserBuffer`.
///
/// `StreamBase::AddMethods` installs it on every stream; `src/js_stream.cc`
/// inherits the default, which installs a `CustomBufferJSListener`. Nothing in
/// `lib/internal/js_stream_socket.js` calls it — a `JSStreamSocket` reads through
/// `readBuffer` — so reporting success without adopting the buffer is the honest
/// answer, and the alternative (a stub that claimed to adopt it) would break
/// `readBuffer` instead.
pub(crate) fn use_user_buffer(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set(v8::Integer::new(_scope, 0).into());
}

/// `JSStream::ReadBuffer`: hand `chunk` to `onread`.
///
/// `EmitAlloc`/`EmitRead` in Node loop over the chunk so a listener that accepts
/// less than offered is respected. `EmitToJSStreamListener` always offers the
/// whole slab, so the loop collapses into one delivery here; splitting would only
/// change how many `data` events one `readBuffer` produced.
pub(crate) fn read_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'_>,
) {
    let chunk = args.get(0);
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(chunk) else {
        return;
    };
    let length = view.byte_length();
    if length == 0 {
        return;
    }
    let base = view.data().cast::<u8>();
    if base.is_null() {
        return;
    }
    let object = args.this();

    // `EmitRead` counts the bytes before the listener sees them.
    with_slot(object, |slot| {
        slot.bytes_read.set(slot.bytes_read.get() + length as u64);
    });

    // `CallJSOnreadMethod` publishes the count and offset first, because
    // `onStreamRead` reads them before it looks at its argument.
    let _ = rn_uv::stream::state_array(scope);
    rn_uv::stream::with_state(|state| {
        state.set(rn_uv::handle::K_READ_BYTES_OR_ERROR, length as u32);
        state.set(rn_uv::handle::K_ARRAY_BUFFER_OFFSET, 0);
    });

    // The bytes are copied into a fresh backing store: the caller owns `chunk`
    // and may reuse it, and `onread` keeps the `ArrayBuffer` it is given.
    // SAFETY: `base` points at `length` bytes of the caller's live view.
    let bytes = unsafe { std::slice::from_raw_parts(base, length) };
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);

    if let Some(onread) = onread_of(scope, object) {
        let argument: v8::Local<'_, v8::Value> = array_buffer.into();
        let receiver: v8::Local<'_, v8::Value> = object.into();
        let _ = onread.call(scope, receiver, &[argument]);
    }
}

/// `JSStream::EmitEOF`: `EmitRead(UV_EOF)`, which calls `onread` with no argument.
pub(crate) fn emit_eof<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let _ = rn_uv::stream::state_array(scope);
    rn_uv::stream::with_state(|state| {
        state.set(rn_uv::handle::K_READ_BYTES_OR_ERROR, EOF as u32);
        state.set(rn_uv::handle::K_ARRAY_BUFFER_OFFSET, 0);
    });
    if let Some(onread) = onread_of(scope, object) {
        let receiver: v8::Local<'_, v8::Value> = object.into();
        let _ = onread.call(scope, receiver, &[]);
    }
}

/// Reads the `onread` function off a `JSStream` object.
pub(crate) fn onread_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, "onread")?;
    let value = object.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

/// The `onread` accessor's getter.
pub(crate) fn get_onread(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let value = with_slot(object, |slot| {
        slot.onread
            .borrow()
            .as_ref()
            .map(|onread| v8::Local::new(scope, onread))
    })
    .flatten();
    match value {
        Some(value) => rv.set(value.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// The `onread` accessor's setter, mirroring `BaseObject::InternalFieldSet` with
/// its `&Value::IsFunction` check: a non-function leaves the field alone.
pub(crate) fn set_onread(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(function) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        return;
    };
    let object = args.this();
    with_slot(object, |slot| {
        *slot.onread.borrow_mut() = Some(v8::Global::new(scope.as_ref(), function));
    });
}

/// `StreamBase::GetFD`: `JSStream` inherits the default, which is `-1`.
pub(crate) fn get_fd(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set(v8::Integer::new(_scope, -1).into());
}

/// `StreamBase::GetExternal`: the `External` that makes `util.inspect` say
/// `[External: …]`.
///
/// `StreamBase::AddMethods` installs it on every stream; the `JSStream` test in
/// `test/parallel/test-util-inspect.js` asserts exactly that rendering, so the
/// pointer has to be non-null and distinct per object. The slot's address is
/// both.
pub(crate) fn get_external(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let address = with_slot(object, |slot| slot as *const StreamSlot as usize);
    if let Some(address) = address {
        let external = v8::External::new(scope, address as *mut std::ffi::c_void);
        rv.set(external.into());
    }
}

/// `StreamBase::GetBytesRead`.
pub(crate) fn get_bytes_read(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = with_slot(args.this(), |slot| slot.bytes_read.get()).unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `StreamBase::GetBytesWritten`.
pub(crate) fn get_bytes_written(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = with_slot(args.this(), |slot| slot.bytes_written.get()).unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `JSStream::Finish<WriteWrap>`: `w->Done(status)`.
///
/// `Done` is `stream()->EmitAfterWrite(this, status)`, and the listener is
/// `ReportWritesToJSStreamListener`, which calls `req.oncomplete(status)` — or
/// records `writeStatus` when the callback is not attached yet.
pub(crate) fn finish_write<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    finish(scope, &args, "finishWrite");
}

/// `JSStream::Finish<ShutdownWrap>`: the same completion for a shutdown.
pub(crate) fn finish_shutdown<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    finish(scope, &args, "finishShutdown");
}

/// Delivers a request's completion, in the shape `report_completion` expects.
pub(crate) fn finish<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    name: &str,
) {
    let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        handle::throw_type_error(scope, &format!("{name} requires a request object"));
        return;
    };
    let Some(status) = args.get(1).int32_value(scope) else {
        handle::throw_type_error(scope, &format!("{name} requires an integer status"));
        return;
    };
    // `w->Done(status)` runs the listener, which reads `oncomplete` off the
    // request. `report_completion` parks the status in `writeStatus` when the
    // callback is not there yet, which is what `afterWriteDispatched` replays.
    let handle_object = request_handle(scope, request);
    rn_uv::stream::report_completion(scope, request, status, handle_object, None);
}

/// Reads `request.handle`, the stream object a completion reports.
pub(crate) fn request_handle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    request: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Object>> {
    let key = v8::String::new(scope, "handle")?;
    let value = request.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}
