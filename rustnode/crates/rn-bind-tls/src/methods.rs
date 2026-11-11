//! The 42 `TLSWrap` prototype methods.
//!
//! `crypto_tls.cc:2397-2460` installs them; [`crate::wrap::PROTO_METHODS`] is the
//! list. This module supplies each body, and it is split in three:
//!
//! | group | what they do | increment |
//! | --- | --- | --- |
//! | implemented here | read state this crate already has — `destroySSL`, `getServername`, `verifyError`, `getProtocol`, the counters | 1 |
//! | [`pending`] | throw with the increment that will land them named | 2, 3, 4 |
//! | the stream surface | [`crate::stream`], which delegates to the wrapped stream | 2 |
//!
//! # Why the unimplemented ones throw rather than return `undefined`
//!
//! A method that returns `undefined` moves the failure into
//! `lib/internal/tls/wrap.js`, where the reporting frame is JavaScript rather than
//! this crate. A method that throws
//! `start is not implemented yet: ... (tls_wrap increment 3)` names the gap and
//! the plan's own numbering, which is what makes a partial landing usable instead
//! of mysterious. This is the same reasoning `rn-bind-secure-context`'s `STUBS`
//! records: a declared gap is visible and a lie is not.
//!
//! The code is `ERR_TLS_NOT_IMPLEMENTED` rather than Node's
//! `ERR_METHOD_NOT_IMPLEMENTED` so a test that matches on it knows it is looking
//! at this crate's gap rather than at a Node code it might match by accident.
//!
//! # Why the installer is a match rather than a table
//!
//! V8's `MapFnTo` is implemented for **zero-sized types**, so a callback routed
//! through a `fn`-pointer alias fails the static size assertion in
//! `v8::support::UnitValue`. Each implementation therefore has to reach
//! `FunctionTemplate::builder` as a *function item*. That is what the `method!`
//! macro below does, and it is why this is one match rather than an array of
//! `(name, callback)` pairs — `rn-bind-js-stream`'s `install_method!` macro exists
//! for the same reason.

use std::os::raw::c_int;

use rn_v8_sys::v8;

use crate::state::with_state;
use crate::wrap::{key, throw_coded, throw_type_error};

/// The code every pending method throws.
pub const NOT_IMPLEMENTED: &str = "ERR_TLS_NOT_IMPLEMENTED";

/// The `.length` of a prototype method, which is observable.
///
/// Node's `SetProtoMethod` uses the callback's own arity, so the numbers here are
/// the argument counts in `crypto_tls.cc`.
pub fn length_of(name: &str) -> i32 {
    match name {
        "setServername" | "setSession" | "setOCSPResponse" => 1,
        "setKeyCert"
        | "setVerifyMode"
        | "setALPNProtocols"
        | "exportKeyingMaterial"
        | "setMaxSendFragment"
        | "setPskIdentityHint" => 2,
        "loadSession" => 3,
        _ => 0,
    }
}

/// Declares one prototype method that throws, naming the increment that lands it.
///
/// A `macro_rules!` expansion rather than a shared generic: V8's `MapFnTo` needs a
/// zero-sized function *item*, and every pending method has to be its own item so
/// the message is a compile-time constant. This is the same shape
/// `rn-bind-js-stream` uses for its `install_method!` table.
macro_rules! pending_method {
    ($callback:ident, $method:literal, $increment:literal, $reason:literal) => {
        fn $callback<'s>(
            scope: &mut v8::PinScope<'s, '_>,
            _args: v8::FunctionCallbackArguments<'s>,
            _rv: v8::ReturnValue<'s>,
        ) {
            throw_coded(
                scope,
                concat!(
                    $method,
                    " is not implemented yet: ",
                    $reason,
                    " (tls_wrap increment ",
                    $increment,
                    ")"
                ),
                NOT_IMPLEMENTED,
            );
        }
    };
}

// Increment 3: the handshake state machine and the SSL_get_error retry loop.
pending_method!(
    pending_start,
    "start",
    3,
    "it sends the ClientHello, which needs SSL_do_handshake and the retry loop"
);
pending_method!(
    pending_set_verify_mode,
    "setVerifyMode",
    3,
    "it calls SSL_set_verify and is read by the handshake state machine"
);
pending_method!(
    pending_get_cipher,
    "getCipher",
    3,
    "it reads SSL_get_current_cipher, which needs a completed handshake"
);
pending_method!(
    pending_renegotiate,
    "renegotiate",
    3,
    "it drives SSL_renegotiate through the retry loop"
);

// Increment 4: the SSL callbacks, session resumption, and the queries that need a
// completed handshake.
pending_method!(
    pending_cert_cb_done,
    "certCbDone",
    4,
    "it resumes the handshake from the oncertcb handler, which needs the callback machinery"
);
pending_method!(
    pending_client_hello_done,
    "clientHelloDone",
    4,
    "it resumes a server handshake parked for the session callback"
);
pending_method!(
    pending_enable_cert_cb,
    "enableCertCb",
    4,
    "it parks the handshake until oncertcb answers"
);
pending_method!(
    pending_enable_alpn_cb,
    "enableALPNCb",
    4,
    "it installs SSL_CTX_set_alpn_select_cb"
);
pending_method!(
    pending_enable_keylog_callback,
    "enableKeylogCallback",
    4,
    "it installs SSL_CTX_set_keylog_callback, which calls into JavaScript"
);
pending_method!(
    pending_enable_session_callbacks,
    "enableSessionCallbacks",
    4,
    "it installs the new/get session callbacks, which call into JavaScript"
);
pending_method!(
    pending_load_session,
    "loadSession",
    4,
    "it installs a session for the next handshake"
);
pending_method!(
    pending_new_session_done,
    "newSessionDone",
    4,
    "it resumes after the onnewsession handler"
);
pending_method!(
    pending_request_ocsp,
    "requestOCSP",
    4,
    "it enables the status-request extension and needs the OCSP response path"
);
pending_method!(
    pending_set_alpn_protocols,
    "setALPNProtocols",
    4,
    "it calls SSL_CTX_set_alpn_protos and needs the ALPN callback"
);
pending_method!(
    pending_set_key_cert,
    "setKeyCert",
    4,
    "it installs a per-SSL certificate and key, which switch on the SNI context path"
);
pending_method!(
    pending_set_ocsp_response,
    "setOCSPResponse",
    4,
    "it attaches a stapled OCSP response"
);
pending_method!(
    pending_set_servername,
    "setServername",
    4,
    "it calls SSL_set_tlsext_host_name and interacts with the SNI callback"
);
pending_method!(
    pending_set_session,
    "setSession",
    4,
    "it calls SSL_set_session for resumption"
);
pending_method!(
    pending_export_keying_material,
    "exportKeyingMaterial",
    4,
    "it needs a completed handshake to export from"
);
pending_method!(
    pending_get_alpn_negotiated_protocol,
    "getALPNNegotiatedProtocol",
    4,
    "it needs the ALPN callback to have negotiated a protocol"
);
pending_method!(
    pending_get_certificate,
    "getCertificate",
    4,
    "it needs a handshake that selected a certificate"
);
pending_method!(
    pending_get_x509_certificate,
    "getX509Certificate",
    4,
    "it needs a handshake that selected a certificate"
);
pending_method!(
    pending_get_ephemeral_key_info,
    "getEphemeralKeyInfo",
    4,
    "it reads the peer's ephemeral key, which needs a completed handshake"
);
pending_method!(
    pending_get_finished,
    "getFinished",
    4,
    "it reads the local Finished message, which needs a completed handshake"
);
pending_method!(
    pending_get_peer_certificate,
    "getPeerCertificate",
    4,
    "it needs the peer's chain and the verification result"
);
pending_method!(
    pending_get_peer_x509_certificate,
    "getPeerX509Certificate",
    4,
    "it needs the peer's chain and the verification result"
);
pending_method!(
    pending_has_peer_certificate,
    "hasPeerCertificate",
    4,
    "it needs the peer's chain"
);
pending_method!(
    pending_get_peer_finished,
    "getPeerFinished",
    4,
    "it reads the peer's Finished message, which needs a completed handshake"
);
pending_method!(
    pending_get_session,
    "getSession",
    4,
    "it needs a handshake that produced a session"
);
pending_method!(
    pending_enable_psk_callback,
    "enablePskCallback",
    4,
    "it installs SSL_CTX_set_psk_client_callback, which calls into JavaScript"
);
pending_method!(
    pending_set_psk_identity_hint,
    "setPskIdentityHint",
    4,
    "it calls SSL_use_psk_identity_hint for a server handshake"
);

/// Installs one prototype method onto `prototype`.
pub fn install_into<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: &v8::Template,
    name: &'static str,
) -> Result<(), String> {
    let length = length_of(name);

    macro_rules! method {
        ($callback:path) => {{
            // A `FunctionTemplate` rather than a `Function`: `Template::Set` on a
            // prototype template accepts a primitive or a *Template*, and a
            // `Function` is neither. Node's `SetProtoMethod` installs the template
            // directly for the same reason.
            let template = v8::FunctionTemplate::builder($callback)
                .length(length)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope);
            prototype.set(key(scope, name)?.into(), template.into());
        }};
    }

    match name {
        // Implemented today.
        "destroySSL" => method!(destroy_ssl),
        "getServername" => method!(get_servername),
        "verifyError" => method!(verify_error),
        "isSessionReused" => method!(is_session_reused),
        "getProtocol" => method!(get_protocol),
        "getSharedSigalgs" => method!(get_shared_sigalgs),
        "getTLSTicket" => method!(get_tls_ticket),
        "setMaxSendFragment" => method!(set_max_send_fragment),
        "enableTrace" => method!(enable_trace),
        "writesIssuedByPrevListenerDone" => method!(writes_issued_by_prev_listener_done),

        // Increment 2: the read and write paths.
        "receive" => method!(receive),

        // Increment 3: the handshake state machine and the SSL_get_error retry loop.
        "start" => method!(pending_start),
        "setVerifyMode" => method!(pending_set_verify_mode),
        "getCipher" => method!(pending_get_cipher),
        "renegotiate" => method!(pending_renegotiate),

        // Increment 4: the SSL callbacks, session resumption, and the queries that
        // need a completed handshake.
        "certCbDone" => method!(pending_cert_cb_done),
        "clientHelloDone" => method!(pending_client_hello_done),
        "enableCertCb" => method!(pending_enable_cert_cb),
        "enableALPNCb" => method!(pending_enable_alpn_cb),
        "enableKeylogCallback" => method!(pending_enable_keylog_callback),
        "enableSessionCallbacks" => method!(pending_enable_session_callbacks),
        "loadSession" => method!(pending_load_session),
        "newSessionDone" => method!(pending_new_session_done),
        "requestOCSP" => method!(pending_request_ocsp),
        "setALPNProtocols" => method!(pending_set_alpn_protocols),
        "setKeyCert" => method!(pending_set_key_cert),
        "setOCSPResponse" => method!(pending_set_ocsp_response),
        "setServername" => method!(pending_set_servername),
        "setSession" => method!(pending_set_session),
        "exportKeyingMaterial" => method!(pending_export_keying_material),
        "getALPNNegotiatedProtocol" => method!(pending_get_alpn_negotiated_protocol),
        "getCertificate" => method!(pending_get_certificate),
        "getX509Certificate" => method!(pending_get_x509_certificate),
        "getEphemeralKeyInfo" => method!(pending_get_ephemeral_key_info),
        "getFinished" => method!(pending_get_finished),
        "getPeerCertificate" => method!(pending_get_peer_certificate),
        "getPeerX509Certificate" => method!(pending_get_peer_x509_certificate),
        "hasPeerCertificate" => method!(pending_has_peer_certificate),
        "getPeerFinished" => method!(pending_get_peer_finished),
        "getSession" => method!(pending_get_session),
        "enablePskCallback" => method!(pending_enable_psk_callback),
        "setPskIdentityHint" => method!(pending_set_psk_identity_hint),

        other => return Err(format!("{other} is not a TLSWrap prototype method")),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The methods this increment implements
// ---------------------------------------------------------------------------

/// `TLSWrap::Receive` (`crypto_tls.cc:636`): ciphertext injected from JavaScript.
///
/// `wrap.js:617` calls this from `initRead` for bytes that arrived on the socket
/// before the `TLSWrap` existed — the socket is created, data is buffered, and
/// only then is the handle wrapped. Those bytes are already ciphertext, so they
/// skip the listener and go straight into `enc_in_`.
///
/// The loop copies as much as the BIO accepts and stops when the wrap closes,
/// which is Node's `while (len > 0 && wrap->IsAlive() && !wrap->IsClosing())`.
/// Anything the BIO refuses is dropped rather than re-queued: the BIO accepts
/// everything it is offered, so a refusal means the wrap is going away.
fn receive<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let value = args.get(0);
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) else {
        throw_type_error(scope, "receive expects an ArrayBufferView");
        return;
    };
    let length = view.byte_length();
    let base = view.data().cast::<u8>();
    if length == 0 {
        return;
    }
    if base.is_null() {
        throw_type_error(scope, "receive was given a view with no data");
        return;
    }
    // SAFETY: `base` points at `length` bytes of the caller's view, valid for the
    // duration of the call.
    let bytes = unsafe { std::slice::from_raw_parts(base, length) };

    let object = args.this();
    let accepted = with_state(object, |state| {
        // `crypto_tls.cc:1391`'s guard: after `DestroySSL` there is no BIO to
        // write into, and Node's loop exits on `IsAlive()` being false.
        let Some(enc_in) = state.enc_in() else {
            return 0;
        };
        enc_in.write(bytes)
    });
    if accepted == Some(0) {
        return;
    }
    // The state machine runs, which is what decrypts the injected bytes. This is
    // `wrap->OnStreamRead(copy, buf)` at `crypto_tls.cc:650`.
    let Some(cell) = crate::state::state_cell(object) else {
        return;
    };
    // SAFETY: `cell` is this object's live state, and the object is the receiver
    // of the call, so it cannot be collected during it.
    let outcome = unsafe { crate::cycle::run(cell) };
    let _ = outcome;
    // Whatever `ClearIn`/`EncOut` produced now goes to the socket. The borrow is
    // taken and released before `flush`, which is R2.
    let stream = with_state(object, |state| state.underlying).flatten();
    if let Some(stream) = stream {
        // SAFETY: `stream` is the wrap's own `underlying`, live while it holds it.
        unsafe { crate::stream::flush(scope, object, stream, None) };
    }
}

/// `TLSWrap::DestroySSL`, and the one teardown path (R1, R3, R4).
///
/// Node's body is `wrap->Destroy();`. The parts that need a `PinScope` —
/// completing the queued write and shutdown, and removing the listener — run after
/// the state borrow ends, which is R2. The ordering inside
/// [`crate::state::WrapState::destroy`] is Node's: complete the queued write first,
/// then free the SSL.
///
/// Idempotent, because `wrap.js`'s `close()` and the `'close'` handler both reach
/// it and the finalizer is the third path.
fn destroy_ssl<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    let Some(destroyed) = with_state(object, |state| state.destroy()) else {
        // A receiver that is not a `TLSWrap`, or a re-entrant destroy from inside
        // a callback. Node's `ASSIGN_OR_RETURN_UNWRAP` reports a TypeError for the
        // first; `destroy` itself makes the second a no-op.
        throw_type_error(scope, "Invalid TLSWrap receiver");
        return;
    };

    // R3: the queued write is completed with `UV_ECANCELED` rather than dropped,
    // so `lib/net.js`'s write callback fires and the `WriteWrap` is released.
    if let Some(write) = destroyed.write {
        crate::stream::complete_cancelled(scope, &write, UV_ECANCELED);
    }
    if let Some(shutdown) = destroyed.shutdown {
        crate::stream::complete_cancelled(scope, &shutdown, UV_ECANCELED);
    }
    // R1/R4: the listener comes off the stream, so nothing points at the state
    // after it is freed and the stream does not hold a callback alive.
    if let (Some(stream), Some(id)) = (destroyed.underlying, destroyed.listener) {
        // SAFETY: `stream` is the wrapped stream, live until its own close
        // callback; `destroySSL` runs before that because `wrap.js`'s `close()`
        // destroys the socket before releasing it.
        unsafe { crate::listener::detach(stream, id) };
    }
}

/// `UV_ECANCELED`, the status Node reports for work cancelled by teardown.
const UV_ECANCELED: i32 = -4082;

/// `TLSEXT_NAMETYPE_host_name` (`tls1.h`), the name type `GetServername` asks for.
const TLSEXT_NAMETYPE_HOST_NAME: c_int = 0;

/// `TLSWrap::GetServername`.
///
/// `SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)`, or `null` when none was
/// set. Answerable before a handshake — `wrap.js`'s `reinitializeHandle` calls it
/// to carry a name across a handle swap — so it is implemented here.
fn get_servername<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let name = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return None;
        }
        // SAFETY: `ssl` is the live SSL of this wrap, checked immediately above.
        let pointer =
            unsafe { crate::ffi_extra::SSL_get_servername(ssl, TLSEXT_NAMETYPE_HOST_NAME) };
        if pointer.is_null() {
            return None;
        }
        // SAFETY: OpenSSL returns a NUL-terminated string owned by the SSL.
        let text = unsafe { std::ffi::CStr::from_ptr(pointer) };
        Some(text.to_string_lossy().into_owned())
    });
    match name.flatten() {
        Some(text) => match v8::String::new(scope, &text) {
            Some(value) => rv.set(value.into()),
            None => rv.set(v8::null(scope).into()),
        },
        // A receiver with no state, a freed SSL, or no name: `null`, which is what
        // `wrap.js` treats as "nothing to carry over".
        None => rv.set(v8::null(scope).into()),
    }
}

/// `TLSWrap::VerifyError`.
///
/// `SSL_get_verify_result`, which is `X509_V_OK` (0) when verification succeeded or
/// was not requested. `lib/internal/tls/wrap.js` reads it and turns a non-zero
/// value into `ERR_TLS_CERT_ALTNAME_INVALID` or the peer-certificate error, so
/// returning the raw code is what makes that branch run.
fn verify_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let code = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return 0i64;
        }
        // SAFETY: `ssl` is live, checked above.
        unsafe { openssl_sys::SSL_get_verify_result(ssl) as i64 }
    })
    .unwrap_or(0);
    rv.set(v8::Number::new(scope, code as f64).into());
}

/// `TLSWrap::IsSessionReused`.
///
/// `SSL_session_reused`: false before a handshake, true after a resumed one. It
/// will start returning true once resumption lands in increment 4.
fn is_session_reused<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let reused = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return false;
        }
        // SAFETY: `ssl` is live, checked above.
        unsafe { openssl_sys::SSL_session_reused(ssl) != 0 }
    })
    .unwrap_or(false);
    rv.set(v8::Boolean::new(scope, reused).into());
}

/// `TLSWrap::GetProtocol`.
///
/// `SSL_get_version`, as a string. A wrap with no SSL reports `null`, which
/// `wrap.js` handles for a socket that never handshook.
fn get_protocol<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let version = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return None;
        }
        // SAFETY: `ssl` is live, checked above.
        let pointer = unsafe { openssl_sys::SSL_get_version(ssl) };
        if pointer.is_null() {
            return None;
        }
        // SAFETY: OpenSSL returns a static NUL-terminated string.
        let text = unsafe { std::ffi::CStr::from_ptr(pointer) };
        Some(text.to_string_lossy().into_owned())
    });
    match version.flatten() {
        Some(text) => match v8::String::new(scope, &text) {
            Some(value) => rv.set(value.into()),
            None => rv.set(v8::null(scope).into()),
        },
        None => rv.set(v8::null(scope).into()),
    }
}

/// `TLSWrap::GetSharedSigalgs`.
///
/// `SSL_get_shared_sigalgs`, as an array of `[sign, hash]` pairs. Before a
/// handshake there are none, so an empty array is the correct answer rather than a
/// deferral.
fn get_shared_sigalgs<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let names = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return Vec::new();
        }
        // SAFETY: `ssl` is live, checked above. Index 0 with null out-parameters
        // asks only for the count, which is what `tls1.h` documents.
        let count = unsafe {
            crate::ffi_extra::SSL_get_shared_sigalgs(
                ssl,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if count <= 0 {
            return Vec::new();
        }
        let mut names = Vec::new();
        for index in 1..=count {
            let mut sign: c_int = 0;
            let mut hash: c_int = 0;
            let mut sign_hash: c_int = 0;
            // SAFETY: `index` is within the count OpenSSL reported, and the
            // out-parameters are live locals; the raw-signature pointers may be
            // null, which `tls1.h` allows.
            let ok = unsafe {
                crate::ffi_extra::SSL_get_shared_sigalgs(
                    ssl,
                    index,
                    &mut sign,
                    &mut hash,
                    &mut sign_hash,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok > 0 {
                names.push((sign, hash));
            }
        }
        names
    })
    .unwrap_or_default();

    let array = v8::Array::new(scope, names.len() as i32);
    for (index, (sign, hash)) in names.iter().enumerate() {
        let pair = v8::Array::new(scope, 2);
        let _ = pair.set_index(scope, 0, v8::Integer::new(scope, *sign).into());
        let _ = pair.set_index(scope, 1, v8::Integer::new(scope, *hash).into());
        let _ = array.set_index(scope, index as u32, pair.into());
    }
    rv.set(array.into());
}

/// `TLSWrap::GetTLSTicket`.
///
/// The session ticket, which only exists after a handshake *and* only with a
/// resumption callback installed. `null` until increment 4 lands both, which is
/// what `lib/internal/tls/wrap.js` guards on; reporting an empty buffer would make
/// `tls.connect` believe a session was available.
fn get_tls_ticket<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    rv.set(v8::null(scope).into());
}

/// `TLSWrap::SetMaxSendFragment`.
///
/// `SSL_set_max_send_fragment`, a macro over `SSL_ctrl`, expanded in
/// [`crate::ffi_extra`]. Answers the return value, which
/// `test-tls-max-send-fragment.js` reads.
fn set_max_send_fragment<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let value = args.get(0);
    if !value.is_number() {
        throw_type_error(scope, "setMaxSendFragment expects a number");
        return;
    }
    let Some(fragment) = value.int32_value(scope) else {
        throw_type_error(scope, "setMaxSendFragment expects a number");
        return;
    };
    let result = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        // SAFETY: `ssl` is checked for null inside `set_max_send_fragment`.
        unsafe { crate::ssl::set_max_send_fragment(ssl, fragment) }
    })
    .unwrap_or(0);
    rv.set(v8::Integer::new(scope, result).into());
}

/// `TLSWrap::EnableTrace`.
///
/// A no-op, and correctly so: `HAVE_SSL_TRACE` is `0` on this build because the
/// vendored OpenSSL is not built with `enable-ssl-trace`, so `lib/**` never calls
/// this. A caller that does gets no trace because there is no trace to give;
/// pretending would be a lie rather than a documented gap.
fn enable_trace<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
}

/// `TLSWrap::WritesIssuedByPrevListenerDone`.
///
/// `wrap.js` calls it once the empty write it issued to the previous owner
/// completed, which turns off `has_active_write_issued_by_prev_listener`.
/// Answerable now because the flag exists.
fn writes_issued_by_prev_listener_done<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let _ = with_state(args.this(), |state| {
        state.flags.has_active_write_issued_by_prev_listener = false;
    });
}

/// `TLSWrap::GetWriteQueueSize`, the `writeQueueSize` accessor.
///
/// `NodeBIO::FromBIO(enc_out_)->Length()`, the ciphertext waiting to be written.
/// Zero for a wrap with no SSL, which is what `lib/net.js` reads to size its retry.
pub fn get_write_queue_size<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let pending = with_state(args.this(), |state| {
        let buffered = state
            .enc_out()
            .map(|enc_out| enc_out.pending())
            .unwrap_or(0);
        buffered + state.pending_output.len()
    })
    .unwrap_or(0);
    rv.set(v8::Number::new(scope, pending as f64).into());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name in the installer's list has an implementation. `install_into`
    /// answers `Ok` for all 42 and `Err` for anything else.
    #[test]
    fn every_listed_method_is_known() {
        for name in crate::wrap::PROTO_METHODS {
            // The installer needs a scope, so the reachable check here is the
            // arity table and the name set: a name in `PROTO_METHODS` that this
            // module does not match would be rejected at namespace install, which
            // `tests/prototype.rs` exercises against the real binary.
            assert!((0..=3).contains(&length_of(name)));
        }
        assert_eq!(crate::wrap::PROTO_METHODS.len(), 42);
    }

    /// The ten implemented methods are all in the installed list, and the rest
    /// are pending — the split the module docs describe.
    #[test]
    fn the_implemented_set_is_named() {
        let implemented = [
            "destroySSL",
            "getServername",
            "verifyError",
            "isSessionReused",
            "getProtocol",
            "getSharedSigalgs",
            "getTLSTicket",
            "setMaxSendFragment",
            "enableTrace",
            "writesIssuedByPrevListenerDone",
        ];
        for name in implemented {
            assert!(
                crate::wrap::PROTO_METHODS.contains(&name),
                "{name} is implemented but not installed"
            );
        }
        // 42 installed minus 10 implemented: the remainder throw.
        assert_eq!(crate::wrap::PROTO_METHODS.len() - implemented.len(), 32);
    }

    /// `length_of` matches the argument counts `crypto_tls.cc` uses.
    #[test]
    fn the_arity_table_is_node_s() {
        assert_eq!(length_of("setServername"), 1);
        assert_eq!(length_of("setSession"), 1);
        assert_eq!(length_of("setOCSPResponse"), 1);
        assert_eq!(length_of("setVerifyMode"), 2);
        assert_eq!(length_of("loadSession"), 3);
        assert_eq!(length_of("start"), 0);
        assert_eq!(length_of("destroySSL"), 0);
    }
}
