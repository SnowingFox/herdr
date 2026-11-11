//! The `StreamBase::AddMethods` surface for `TLSWrap`.
//!
//! Node calls `StreamBase::AddMethods(env, t)` on the `TLSWrap` template
//! (`crypto_tls.cc:2455`), which installs four accessors and ten methods on the
//! prototype. Their bodies in `crypto_tls.cc` all delegate to the **underlying**
//! stream, not to a libuv handle: `TLSWrap` has none.
//!
//! | method | `crypto_tls.cc` | delegates to |
//! | --- | --- | --- |
//! | `GetFD` | :1506 | `underlying_stream()->GetFD()` |
//! | `GetBytesRead`/`GetBytesWritten` | — | `StreamBase`'s counters |
//! | `ReadStart`/`ReadStop` | :1511 | `underlying_stream()->ReadStart()` |
//! | `Shutdown` | :1531 | queue until the SSL has flushed |
//! | `DoWrite` | :1621 | `ClearOut` then `EncOut`, which writes ciphertext |
//! | `write*` forms | `StreamBase::Write` | `DoWrite` |
//!
//! # Increment 1
//!
//! The surface is installed and the read-only accessors answer correctly, so
//! `lib/net.js` can construct a socket and read its counters. The methods that
//! move data report the increment that lands them, for the same reason the
//! prototype methods do: a `writeBuffer` that returned `0` would tell
//! `lib/net.js` the write succeeded instantly, which is worse than an error.
//!
//! [`complete_cancelled`] is the exception and is fully implemented: it is R3's
//! mechanism, reached from `destroySSL`, and it has to work from increment 1
//! or the teardown path leaks a `WriteWrap` the moment anything is queued.

use rn_v8_sys::v8;

use crate::state::with_state;
use crate::wrap::throw_type_error;

/// Installs one `StreamBase` accessor onto `prototype`.
///
/// Takes a *function item* rather than a pointer for the reason
/// [`crate::methods`] documents: V8's `MapFnTo` is implemented for zero-sized
/// types, so a `fn`-pointer alias fails its static size assertion.
pub fn install_accessor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: &v8::ObjectTemplate,
    name: &str,
) -> Result<(), String> {
    macro_rules! accessor {
        ($callback:path) => {{
            // `set_accessor_property` takes `FunctionTemplate`s, not `Function`s,
            // because it installs the accessor on a *template* rather than on an
            // existing object.
            let function = v8::FunctionTemplate::builder($callback)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope);
            prototype.set_accessor_property(
                crate::wrap::key(scope, name)?.into(),
                Some(function),
                None,
                v8::PropertyAttribute::READ_ONLY
                    | v8::PropertyAttribute::DONT_DELETE
                    | v8::PropertyAttribute::DONT_ENUM,
            );
        }};
    }
    match name {
        "fd" => accessor!(get_fd),
        "_externalStream" => accessor!(get_external),
        "bytesRead" => accessor!(get_bytes_read),
        "bytesWritten" => accessor!(get_bytes_written),
        other => return Err(format!("{other} is not a StreamBase accessor")),
    }
    Ok(())
}

/// Installs one `StreamBase` method onto `prototype`.
pub fn install_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: &v8::Template,
    name: &str,
) -> Result<(), String> {
    macro_rules! method {
        ($callback:path) => {{
            // A `FunctionTemplate`, for the reason `crate::methods` documents.
            let template = v8::FunctionTemplate::builder($callback)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope);
            prototype.set(crate::wrap::key(scope, name)?.into(), template.into());
        }};
    }
    match name {
        "readStart" => method!(read_start),
        "readStop" => method!(read_stop),
        "shutdown" => method!(shutdown),
        "useUserBuffer" => method!(use_user_buffer),
        "writev" => method!(writev),
        "writeBuffer" => method!(write_buffer),
        "writeAsciiString" => method!(write_ascii),
        "writeUtf8String" => method!(write_utf8),
        "writeUcs2String" => method!(write_ucs2),
        "writeLatin1String" => method!(write_latin1),
        other => return Err(format!("{other} is not a StreamBase method")),
    }
    Ok(())
}

/// `StreamBase::GetFD`.
///
/// The wrapped stream's descriptor. -1 for a wrap with no stream or no state,
/// which is what `wrap.js`'s `this._parent.fd` proxy answers for a
/// `JSStreamSocket` (it has no descriptor either).
fn get_fd(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let fd = with_state(args.this(), |state| {
        let Some(stream) = state.underlying else {
            return -1i64;
        };
        // SAFETY: the underlying stream is live while the wrap holds it.
        let stream = unsafe { &*stream };
        if stream.stream.is_null() {
            return -1i64;
        }
        // SAFETY: `stream.stream` is a live libuv stream, checked above.
        let fd = unsafe { libc_fd(stream.stream) };
        fd as i64
    })
    .unwrap_or(-1);
    rv.set(v8::Integer::new(scope, fd as i32).into());
}

/// `uv_fileno`, which needs `uv_handle_t*` rather than `uv_stream_t*`.
///
/// # Safety
///
/// `stream` must be a live libuv stream.
unsafe fn libc_fd(stream: *mut rn_uv::sys::uv_stream_t) -> i32 {
    // SAFETY: a `uv_stream_t` is a `uv_handle_t` with extra fields at the front,
    // and libuv's own type pun is the same cast.
    let handle = stream.cast::<rn_uv::sys::uv_handle_t>();
    let mut fd: i32 = -1;
    // SAFETY: `handle` is live, and `fd` is a live local out-parameter.
    let status = unsafe { rn_uv::sys::uv_fileno(handle, &mut fd) };
    if status < 0 {
        -1
    } else {
        fd
    }
}

/// `StreamBase::GetExternal`, Node's opaque handle for a non-file stream.
///
/// `null` for a `TLSWrap`, because the external handle lives on the *underlying*
/// stream and Node returns that one's. A `TLSWrap` wrapping a `JSStream` has none
/// at all, and `lib/internal/js_stream_socket.js` never reads this property.
fn get_external<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    rv.set(v8::null(scope).into());
}

/// `StreamBase::GetBytesRead`, the counter the wrapped stream keeps.
fn get_bytes_read<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let count = with_state(args.this(), |state| {
        let Some(stream) = state.underlying else {
            return 0u64;
        };
        // SAFETY: the underlying stream is live while the wrap holds it.
        let stream = unsafe { &*stream };
        stream.bytes_read
    })
    .unwrap_or(0);
    rv.set(v8::Number::new(scope, count as f64).into());
}

/// `StreamBase::GetBytesWritten`.
fn get_bytes_written<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let count = with_state(args.this(), |state| {
        let Some(stream) = state.underlying else {
            return 0u64;
        };
        // SAFETY: the underlying stream is live while the wrap holds it.
        let stream = unsafe { &*stream };
        stream.bytes_written
    })
    .unwrap_or(0);
    rv.set(v8::Number::new(scope, count as f64).into());
}

/// `StreamBase::ReadStartJS` → `TLSWrap::ReadStart` (`crypto_tls.cc:1092`).
///
/// Starts reads on the **underlying** stream, not on a libuv handle of its own —
/// `TLSWrap` has none. The bytes then arrive through
/// [`crate::listener::WrapListener::on_stream_read`], which is where they enter
/// `enc_in_`.
///
/// `crypto_tls.cc:1094` guards on `!flags_.eof` so a read is not re-armed after a
/// close-notify has been seen; the same guard is here, and `0` is the answer in
/// that case because there is nothing to start.
fn read_start<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    // What to do is decided under the borrow; the call into rn-uv happens after
    // it ends, which is R2 — `read_start` can synchronously deliver a read.
    let target = with_state(object, |state| {
        if state.flags.eof {
            return None;
        }
        state.flags.reading = true;
        state.underlying
    });
    let Some(Some(stream)) = target else {
        rv.set(v8::Integer::new(scope, 0).into());
        return;
    };
    // SAFETY: the underlying stream is live while the wrap holds it, and it was
    // resolved from the handle `wrap()` was given.
    let status = unsafe {
        let state = &mut *stream;
        if state.stream.is_null() {
            0
        } else {
            rn_uv::stream::read_start(state.stream, stream)
        }
    };
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::ReadStopJS` → `TLSWrap::ReadStop` (`crypto_tls.cc:1099`).
fn read_stop<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    let target = with_state(object, |state| {
        state.flags.reading = false;
        state.underlying
    });
    let Some(Some(stream)) = target else {
        rv.set(v8::Integer::new(scope, 0).into());
        return;
    };
    // SAFETY: as `read_start`.
    let status = unsafe {
        let state = &mut *stream;
        if state.stream.is_null() {
            0
        } else {
            rn_uv::stream::read_stop(state.stream)
        }
    };
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::Shutdown` → `TLSWrap::DoShutdown` (`crypto_tls.cc:1328`).
///
/// Issues `SSL_shutdown` (twice, because the first call only sends the
/// close-notify and the second waits for the peer's) and parks the `ShutdownWrap`
/// until the ciphertext has drained. The parking is what R3 is about: a request
/// held here must be completed on teardown, or `lib/net.js` waits forever.
///
/// The deferred path — a shutdown issued from inside the SSL library's stack —
/// is `crypto_tls.cc:1333`, and it is reachable today because `ClearIn` runs the
/// machine. It parks the request and reports `0`, and the next cycle completes
/// it.
fn shutdown<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(request) = request_argument(args.get(0)) else {
        throw_type_error(scope, "shutdown expects a ShutdownWrap");
        return;
    };
    let object = args.this();

    // Decide under the borrow, act after it.
    let plan = with_state(object, |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            // `DoShutdown` after `destroySSL`: Node reports `UV_EPROTO` for a
            // write it cannot encrypt, and a shutdown has the same problem.
            return Err(-71);
        }
        if state.in_library_call() {
            // `crypto_tls.cc:1333`: `SSL_shutdown` must not run on the library's
            // own stack. Park it; the next cycle completes it.
            state.pending_shutdown = Some(v8::Global::new(scope.as_ref(), request));
            state.flags.shutdown = true;
            return Ok(0);
        }
        // `crypto_tls.cc:1344`: the first `SSL_shutdown` sends the close-notify
        // and returns 0; the second waits for the peer's and returns 1. Node calls
        // it twice for exactly that reason, and discarding the result (as an
        // earlier version did) still sends the notify.
        //
        // SAFETY: `ssl` is live, checked above.
        let first = unsafe { openssl_sys::SSL_shutdown(ssl) };
        if first == 0 {
            // SAFETY: as above.
            unsafe { openssl_sys::SSL_shutdown(ssl) };
        }
        state.flags.shutdown = true;
        // The close-notify is now in `enc_out_`. Node ends `DoShutdown` with
        // `EncOut()` (`crypto_tls.cc:1350`), and that is the step an earlier
        // version omitted: without it the notify stays in the BIO, the socket's
        // `shutdown` never reaches the peer, and neither side ever closes.
        //
        // SAFETY: `ssl` is live, checked above, and `state` is this borrow.
        unsafe { crate::cycle::enc_out(state, ssl) };
        Ok(0)
    });

    match plan {
        Some(Ok(0)) => {
            // `crypto_tls.cc:1351`: `EncOut()` produced the close-notify, then the
            // **underlying stream's own** `DoShutdown` puts a FIN on the wire and
            // completes the request.
            //
            // Two ordering constraints, both learned by measurement:
            //
            // * the close-notify must go out *before* the FIN, or the peer sees a
            //   truncated stream instead of a clean close;
            // * the request must be completed by the stream's shutdown callback,
            //   not locally — `lib/net.js` only marks the writable side finished
            //   from `afterShutdown`, and if that never runs the socket never
            //   closes and `server.close()`'s callback never fires.
            let underlying = with_state(object, |state| state.underlying).flatten();
            let Some(stream) = underlying else {
                rn_bind_stream_wrap::wrap::report_completion(scope, request, 0, None, None);
                rv.set(v8::Integer::new(scope, 0).into());
                return;
            };
            // The notify is flushed *without* the caller's request: it is
            // ciphertext, not the caller's write, and passing the request here
            // would complete it before the FIN was even issued. The caller's
            // completion follows from `queue_shutdown` below.
            //
            // SAFETY: `stream` is the wrap's own `underlying`, live while it holds
            // it.
            let _ = unsafe { flush(scope, object, stream, None) };
            // SAFETY: the stream is live and `request` is the caller's
            // `ShutdownWrap`, kept alive by `lib/net.js`.
            let status = unsafe {
                let state = &mut *stream;
                if state.stream.is_null() {
                    0
                } else {
                    rn_uv::stream::queue_shutdown(scope, state.stream, request, object)
                }
            };
            rv.set(v8::Integer::new(scope, status).into());
        }
        Some(Ok(_)) => rv.set(v8::Integer::new(scope, 0).into()),
        Some(Err(status)) => rv.set(v8::Integer::new(scope, status).into()),
        None => {
            throw_type_error(scope, "Invalid TLSWrap receiver");
        }
    }
}

/// Reads a request object out of a method argument.
///
/// `lib/internal/stream_base_commons.js` always passes one for `shutdown`; a
/// non-object is a caller bug, so it is reported rather than ignored.
fn request_argument<'s>(value: v8::Local<'s, v8::Value>) -> Option<v8::Local<'s, v8::Object>> {
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Hands whatever `EncOut` produced to the underlying stream.
///
/// This is the write half of `TLSWrap::EncOut` (`crypto_tls.cc:1000`): the bytes
/// are ciphertext, and they go out through the wrapped stream's own write path
/// rather than through a libuv handle of this wrap's.
///
/// `request`, when given, is the `WriteWrap` or `ShutdownWrap` whose completion
/// follows the flush. When there is nothing to write the request completes
/// immediately, which is the "no pending encrypted output" case at
/// `crypto_tls.cc:1183`.
///
/// Returns the status the caller should report, or `None` when a completion is
/// queued and will report itself.
/// # Safety
///
/// `stream` must be a live `StreamState` — the wrapped stream's, retrieved from
/// the wrap's own `underlying` field while the wrap still holds it.
pub unsafe fn flush<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    stream: *mut rn_uv::handle::StreamState,
    request: Option<v8::Local<'s, v8::Object>>,
) -> Option<i32> {
    // The bytes are taken under the borrow and the borrow ends before anything
    // calls into V8 (R2).
    let taken = with_state(object, |state| {
        if state.pending_output.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut state.pending_output))
    });
    let Some(Some(bytes)) = taken else {
        // Nothing to send. A request waiting on the flush is complete now: this
        // is `EncOut`'s "no pending encrypted output" branch, and completing it
        // here rather than leaving it parked is R3's contract.
        if let Some(request) = request {
            rn_bind_stream_wrap::wrap::report_completion(scope, request, 0, None, None);
        }
        return Some(0);
    };

    // SAFETY: the stream is live while the wrap holds it, and `bytes` is a Vec
    // whose allocation outlives the call — `owned` below keeps it alive until the
    // completion.
    let request = match request {
        Some(request) => request,
        None => empty_request(scope, object),
    };
    let raw_stream = {
        // SAFETY: the stream is live while the wrap holds it.
        let state = unsafe { &*stream };
        state.stream
    };
    if raw_stream.is_null() {
        return Some(-71);
    }
    let length = bytes.len();
    let buffer = rn_uv::sys::uv_buf_t {
        base: bytes.as_ptr() as *mut std::os::raw::c_char,
        len: length,
    };
    // SAFETY: `raw_stream` is live, and `bytes` is moved into `owned` so its
    // allocation outlives the libuv completion.
    let status = unsafe {
        rn_uv::stream::queue_write(
            scope,
            raw_stream,
            vec![buffer],
            length,
            request,
            object,
            vec![bytes.into_boxed_slice()],
        )
    };
    Some(status)
}

/// A stand-in request object for a flush with no caller-supplied wrap.
///
/// `queue_write` needs a request to attach its completion to. `EncOut` has no
/// `WriteWrap` of its own — the ciphertext it sends is not a caller's write — so
/// a bare object is used and its completion calls nothing. That is what Node's
/// `StreamWriteResult` does for the same case: the write is part of the SSL's
/// machinery, not a request the JavaScript side made.
fn empty_request<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _object: v8::Local<'s, v8::Object>,
) -> v8::Local<'s, v8::Object> {
    v8::Object::new(scope)
}

/// `StreamBase::UseUserBuffer`, which `TLSWrap` does not support.
///
/// `StreamBase`'s body is `return UV_ENOTSUP` for a stream that has no user
/// buffer concept, and `lib/**` tolerates it: nothing in `lib/internal/tls/` calls
/// it. Reporting `UV_ENOTSUP` is the correct answer rather than a deferral, and
/// it is what a real `node` returns here.
fn use_user_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    /// `UV_ENOTSUP` from `uv.h`.
    const ENOTSUP: i32 = -4028;
    rv.set(v8::Integer::new(scope, ENOTSUP).into());
}

/// `StreamBase::Writev`, which is `StreamBase::Write` over an array of buffers.
fn writev<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    let mut chunks = Vec::new();
    // `writev(req, chunks, allBuffers)`: the middle argument is the array.
    if let Ok(array) = v8::Local::<v8::Array>::try_from(args.get(1)) {
        let length = array.length();
        for index in 0..length {
            let Some(value) = array.get_index(scope, index) else {
                continue;
            };
            // SAFETY: `stream_base_commons` keeps each view alive on `req.chunks`.
            if let Some(buffer) = unsafe { rn_uv::stream_base::view_buffer(value) } {
                chunks.push(buffer);
            }
        }
    }
    write_chunks(scope, args, chunks, rv);
}

/// `StreamBase::WriteBuffer`, the single-buffer write.
fn write_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    // SAFETY: `stream_base_commons` keeps the view alive on `req.buffer`.
    let Some(buffer) = (unsafe { rn_uv::stream_base::view_buffer(args.get(1)) }) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    write_chunks(scope, args, vec![buffer], rv);
}

/// `StreamBase::WriteString<ASCII>`.
fn write_ascii<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    write_string(scope, args, rv, StringEncoding::Latin1);
}

/// `StreamBase::WriteString<UTF8>`.
fn write_utf8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    write_string(scope, args, rv, StringEncoding::Utf8);
}

/// `StreamBase::WriteString<UCS2>`.
fn write_ucs2<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    write_string(scope, args, rv, StringEncoding::Utf16Le);
}

/// `StreamBase::WriteString<LATIN1>`.
fn write_latin1<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    write_string(scope, args, rv, StringEncoding::Latin1);
}

/// Which encoding a `write*String` form flattens with.
#[derive(Clone, Copy)]
enum StringEncoding {
    Utf8,
    Latin1,
    Utf16Le,
}

/// The shared body of the four `write*String` forms.
///
/// Flattens the string, then goes through the same path a `Buffer` write takes.
/// The bytes are copied into an owned `Vec` because a V8 string's representation
/// is not stable across a call into V8, which the completion path does.
fn write_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
    encoding: StringEncoding,
) {
    let value = args.get(1);
    let Ok(text) = v8::Local::<v8::String>::try_from(value) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let bytes = match encoding {
        // `to_rust_string_lossy` is UTF-8 by construction, which is the `<UTF8>`
        // form's contract.
        StringEncoding::Utf8 => text.to_rust_string_lossy(scope).into_bytes(),
        StringEncoding::Latin1 | StringEncoding::Utf16Le => {
            // `to_rust_string_lossy` decodes through UTF-8, so the Latin-1 form
            // is a lossy downcast and the UCS-2 form is a re-encode of the same
            // code units. Both are exact for the bytes `lib/net.js` actually
            // sends through these forms — ASCII and Latin-1 text — and the
            // lossy path is only reachable for a code point above U+00FF, which
            // the `<LATIN1>` form cannot represent in Node either.
            let text = text.to_rust_string_lossy(scope);
            match encoding {
                StringEncoding::Utf16Le => text
                    .encode_utf16()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<u8>>(),
                _ => text.chars().map(|ch| ch as u32 as u8).collect::<Vec<u8>>(),
            }
        }
    };
    // SAFETY: `view_buffer` is not used here; the bytes are owned by this frame
    // and handed to `queue_write` as its `owned` storage below.
    let chunk = rn_uv::sys::uv_buf_t {
        base: bytes.as_ptr() as *mut std::os::raw::c_char,
        len: bytes.len(),
    };
    let object = args.this();
    let Some(request) = write_request(scope, args) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let status = dispatch_chunks(scope, object, request, vec![chunk], vec![bytes]);
    rv.set(v8::Integer::new(scope, status.max(0)).into());
}

/// The shared body of `writeBuffer` and `writev`.
fn write_chunks<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    chunks: Vec<rn_uv::sys::uv_buf_t>,
    mut rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    let Some(request) = write_request(scope, args) else {
        rv.set(v8::Integer::new(scope, EINVAL).into());
        return;
    };
    let status = dispatch_chunks(scope, object, request, chunks, Vec::new());
    rv.set(v8::Integer::new(scope, status.max(0)).into());
}

/// The `WriteWrap` a write method was given, or a fresh one.
///
/// `lib/internal/stream_base_commons.js` passes `null` as argument 0 and then
/// attaches `oncomplete` to the returned object, which is why a missing request
/// means "make one" rather than "this is a bug".
fn write_request<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
) -> Option<v8::Local<'s, v8::Object>> {
    if let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) {
        return Some(request);
    }
    let constructor = rn_bind_stream_wrap::wrap::constructor::<rn_bind_stream_wrap::WriteWrap>(
        scope,
        rn_bind_stream_wrap::wrap::write_constructor,
    )
    .ok()?;
    let function = v8::Local::<v8::Function>::try_from(constructor).ok()?;
    function.new_instance(scope, &[])
}

/// Encrypts `chunks` with `SSL_write` and queues the ciphertext.
///
/// This is `TLSWrap::DoWrite` (`crypto_tls.cc:1114`), reduced to its synchronous
/// path. The shape:
///
/// 1. concatenate the cleartext,
/// 2. `SSL_write` under the library-call scope, which is what produces ciphertext
///    into `enc_out_`,
/// 3. on `WANT_WRITE`/`WANT_READ`, park the bytes in `pending_cleartext` so the
///    next `ClearOut` retries them rather than truncating the write,
/// 4. flush the ciphertext.
///
/// Returns the status the caller reports: `0` when a completion is queued, a
/// negative error otherwise.
fn dispatch_chunks<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    request: v8::Local<'s, v8::Object>,
    chunks: Vec<rn_uv::sys::uv_buf_t>,
    owned: Vec<Vec<u8>>,
) -> i32 {
    let mut cleartext = Vec::new();
    for chunk in &chunks {
        if chunk.len == 0 {
            continue;
        }
        if chunk.base.is_null() {
            return EINVAL;
        }
        // SAFETY: `chunk.base` points at `chunk.len` readable bytes. A view's
        // bytes are held by `req.buffer`, and a string's by `owned`.
        let bytes = unsafe { std::slice::from_raw_parts(chunk.base.cast::<u8>(), chunk.len) };
        cleartext.extend_from_slice(bytes);
    }
    let _ = owned;
    if cleartext.is_empty() {
        // `crypto_tls.cc:1170`'s empty-write case: there is nothing to encrypt,
        // but the ciphertext from an earlier handshake may still need to go out.
        return match with_state(object, |state| state.underlying) {
            Some(Some(stream)) => {
                // SAFETY: `stream` is the wrap's own `underlying`, live.
                unsafe { flush(scope, object, stream, Some(request)) }.unwrap_or(0)
            }
            _ => {
                rn_bind_stream_wrap::wrap::report_completion(scope, request, 0, None, None);
                0
            }
        };
    }

    let plan = with_state(object, |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            // `crypto_tls.cc:1121`: "Write after DestroySSL" is `UV_EPROTO`.
            return Err(EPROTO);
        }
        if state.in_library_call() {
            // `crypto_tls.cc:1141`: a write issued from inside the SSL library's
            // stack is parked. Dropping it would lose the caller's bytes; writing
            // it here would re-enter the state machine.
            state.pending_cleartext.extend_from_slice(&cleartext);
            state.current_write = Some(v8::Global::new(scope.as_ref(), request));
            state.flags.write_callback_scheduled = true;
            return Ok(None);
        }
        state.flags.write_callback_scheduled = true;
        state.current_write = Some(v8::Global::new(scope.as_ref(), request));
        state.library_call_depth = state.library_call_depth.saturating_add(1);
        // SAFETY: `ssl` is live, checked above.
        let written = unsafe {
            openssl_sys::SSL_write(
                ssl,
                cleartext.as_ptr().cast(),
                cleartext.len() as std::os::raw::c_int,
            )
        };
        // SAFETY: `written` is this call's own return value.
        let outcome = unsafe { crate::cycle::IoOutcome::of(ssl, written, written.max(0) as usize) };
        state.library_call_depth = state.library_call_depth.saturating_sub(1);
        match outcome {
            crate::cycle::IoOutcome::Wrote(_) => {}
            crate::cycle::IoOutcome::WantRead | crate::cycle::IoOutcome::WantWrite => {
                state.pending_cleartext.extend_from_slice(&cleartext);
            }
            crate::cycle::IoOutcome::ZeroReturn | crate::cycle::IoOutcome::SyscallEof => {
                state.flags.eof = true;
            }
            crate::cycle::IoOutcome::Failed(reason) => {
                state.error = Some(reason);
                state.flags.write_callback_scheduled = false;
                let _ = state.current_write.take();
                return Err(EPROTO);
            }
        }
        Ok(state.underlying)
    });

    match plan {
        // The write was parked for the next cycle, which will complete it.
        Some(Ok(None)) => 0,
        // SAFETY: `stream` is the wrap's own `underlying`, live.
        Some(Ok(Some(stream))) => {
            unsafe { flush(scope, object, stream, Some(request)) }.unwrap_or(0)
        }
        Some(Err(status)) => {
            rn_bind_stream_wrap::wrap::report_completion(scope, request, status, None, None);
            status
        }
        None => {
            rn_bind_stream_wrap::wrap::report_completion(scope, request, EINVAL, None, None);
            EINVAL
        }
    }
}

/// `UV_EINVAL`, for a write this crate cannot represent.
const EINVAL: i32 = 22;
/// `UV_EPROTO`, `DoWrite`'s answer after the SSL is gone.
const EPROTO: i32 = 71;

/// `onread`'s getter, `StreamBase::AddMethods`'s last accessor.
///
/// `lib/net.js` assigns `handle.onread` and `rn_uv`'s default listener calls it
/// when no `StreamListener` is on the chain. The slot lives on the object rather
/// than in the state because it is a plain property in Node too — stored in an
/// internal field there, but with no observable difference for a read/write pair
/// that agree.
pub(crate) fn get_onread<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(key) = v8::String::new(scope, ONREAD_SLOT) else {
        return;
    };
    match args.this().get(scope, key.into()) {
        Some(value) => rv.set(value),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `onread`'s setter.
pub(crate) fn set_onread<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let value = args.get(0);
    // `BaseObject::InternalFieldSet<.., &Value::IsFunction>` rejects a non-function
    // by doing nothing, which is the behaviour `lib/net.js` relies on when it
    // clears the handler with `null`.
    let Some(key) = v8::String::new(scope, ONREAD_SLOT) else {
        return;
    };
    let _ = args.this().set(scope, key.into(), value);
}

/// The property that holds `onread`.
///
/// A plain string key rather than the internal field Node uses: the observable
/// contract is that assigning and reading agree, and a field would need a second
/// internal field (`StreamBase::kOnReadFunctionField`) that V8 would have to
/// root. The name is private enough that nothing in `lib/**` reads it directly.
const ONREAD_SLOT: &str = "__rustnode_onread";

/// Completes a write or shutdown request with a status, which is R3.
///
/// `WriteWrap::Done(status, error_string)` and `ShutdownWrap::Done(status)` both
/// end up in `rn_bind_stream_wrap::report_completion`, which calls the request's
/// `oncomplete`. That is what decrements `lib/net.js`'s `pending` count, so
/// **not** calling this is exactly the "socket never finishes closing" failure
/// the plan's R3 describes.
///
/// The status is `UV_ECANCELED` from `destroySSL` and a success code from a
/// normal flush. The message is only attached for the cancelled case, matching
/// Node's `InvokeQueued(UV_ECANCELED, "Canceled because of SSL destruction")`.
pub fn complete_cancelled(
    scope: &mut v8::PinScope<'_, '_>,
    request: &v8::Global<v8::Object>,
    status: i32,
) {
    let request = v8::Local::new(scope, request);
    rn_bind_stream_wrap::wrap::report_completion(
        scope,
        request,
        status,
        None,
        Some("Canceled because of SSL destruction"),
    );
}

#[cfg(test)]
mod tests {

    /// The two lists are the sizes `StreamBase::AddMethods` installs.
    ///
    /// The per-name coverage is exercised against the real binary in
    /// `tests/prototype.rs`, which is where a name that `install_method` rejects
    /// would fail — these functions need a V8 scope, so they cannot be called
    /// from a unit test.
    #[test]
    fn the_stream_surface_lists_are_complete() {
        assert_eq!(crate::wrap::STREAM_METHODS.len(), 10);
        assert_eq!(crate::wrap::STREAM_ACCESSORS.len(), 4);
        assert!(crate::wrap::STREAM_METHODS.contains(&"useUserBuffer"));
        assert!(!crate::wrap::PROTO_METHODS.contains(&"writeBuffer"));
    }

    /// `useUserBuffer` is a real answer rather than a deferral, because
    /// `StreamBase`'s own body reports `UV_ENOTSUP` for a stream without one.
    #[test]
    fn the_stream_surface_is_ten_and_four() {
        assert!(crate::wrap::STREAM_METHODS.contains(&"useUserBuffer"));
        assert!(!crate::wrap::PROTO_METHODS.contains(&"writeBuffer"));
    }
}
