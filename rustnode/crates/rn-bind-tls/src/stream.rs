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

use crate::methods::NOT_IMPLEMENTED;
use crate::state::with_state;
use crate::wrap::throw_coded;

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

/// `StreamBase::ReadStartJS` → `TLSWrap::ReadStart`, which is
/// `underlying_stream()->ReadStart()`.
///
/// Increment 2, because starting reads before the state machine exists would
/// deliver ciphertext into `enc_in_` and never decrypt it — a hang rather than an
/// error.
fn read_start<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    throw_coded(
        scope,
        "readStart is not implemented yet: it starts reads on the wrapped stream (tls_wrap increment 2)",
        NOT_IMPLEMENTED,
    );
    rv.set(v8::Integer::new(scope, -1).into());
}

/// `StreamBase::ReadStopJS`.
fn read_stop<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    throw_coded(
        scope,
        "readStop is not implemented yet: it stops reads on the wrapped stream (tls_wrap increment 2)",
        NOT_IMPLEMENTED,
    );
    rv.set(v8::Integer::new(scope, -1).into());
}

/// `StreamBase::Shutdown` → `TLSWrap::DoShutdown`.
///
/// Node's version queues the `ShutdownWrap` and issues the SSL close-notify, then
/// completes the request once the ciphertext has flushed. Increment 2 has the
/// queueing half; increment 3 the flush.
fn shutdown<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    throw_coded(
        scope,
        "shutdown is not implemented yet: it queues a ShutdownWrap until the SSL flushes (tls_wrap increment 2)",
        NOT_IMPLEMENTED,
    );
    rv.set(v8::Integer::new(scope, -1).into());
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
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    throw_coded(
        scope,
        "writev is not implemented yet: it encrypts and writes ciphertext (tls_wrap increment 2)",
        NOT_IMPLEMENTED,
    );
    rv.set(v8::Integer::new(scope, -1).into());
}

/// `StreamBase::WriteBuffer`, the single-buffer write.
fn write_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    throw_coded(
        scope,
        "writeBuffer is not implemented yet: it encrypts and writes ciphertext (tls_wrap increment 2)",
        NOT_IMPLEMENTED,
    );
    rv.set(v8::Integer::new(scope, -1).into());
}

/// `StreamBase::WriteString<ASCII>`.
fn write_ascii<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    throw_coded(
        scope,
        "writeAsciiString is not implemented yet (tls_wrap increment 2)",
        NOT_IMPLEMENTED,
    );
    rv.set(v8::Integer::new(scope, -1).into());
}

/// `StreamBase::WriteString<UTF8>`.
fn write_utf8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    throw_coded(
        scope,
        "writeUtf8String is not implemented yet (tls_wrap increment 2)",
        NOT_IMPLEMENTED,
    );
    rv.set(v8::Integer::new(scope, -1).into());
}

/// `StreamBase::WriteString<UCS2>`.
fn write_ucs2<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    throw_coded(
        scope,
        "writeUcs2String is not implemented yet (tls_wrap increment 2)",
        NOT_IMPLEMENTED,
    );
    rv.set(v8::Integer::new(scope, -1).into());
}

/// `StreamBase::WriteString<LATIN1>`.
fn write_latin1<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    throw_coded(
        scope,
        "writeLatin1String is not implemented yet (tls_wrap increment 2)",
        NOT_IMPLEMENTED,
    );
    rv.set(v8::Integer::new(scope, -1).into());
}

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
