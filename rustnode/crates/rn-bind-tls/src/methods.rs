//! The 42 `TLSWrap` prototype methods, plus the `AsyncWrap` surface they inherit.
//!
//! `crypto_tls.cc:2397-2460` installs them; [`crate::wrap::PROTO_METHODS`] is the
//! list. This module supplies each body, and it is split in four:
//!
//! | group | what they do | increment |
//! | --- | --- | --- |
//! | implemented here | read state this crate already has — `destroySSL`, `getServername`, `verifyError`, `getProtocol`, the counters | 1 |
//! | the stream surface | [`crate::stream`], which delegates to the wrapped stream | 2 |
//! | the handshake | `start`, `setVerifyMode`, `getCipher`, the `SSL_get_error` loop | 3 |
//! | sessions and ALPN | `enableSessionCallbacks`, `loadSession`, `setSession`, `newSessionDone`, `setALPNProtocols`, `enableALPNCb`, `enableKeylogCallback` | 4 |
//! | the `pending_method!` bodies | throw with the increment that will land them named | 3, 4 |
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
//! # Why increment 4 covers seven methods and not the whole list
//!
//! The seven are the ones a real connection reaches: `https.Agent` attaches a
//! `'session'` listener to every socket it opens, `http2.connect` sets
//! `ALPNProtocols`, and a resumption round trip needs `loadSession`/`setSession`
//! with `newSessionDone` to unpark the server's ticket. What remains is listed in
//! the `pending_method!` table with a reason each: mostly OCSP, PSK and
//! SNI-certificate switching, which no ordinary HTTPS or HTTP/2 connection
//! reaches.
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
use crate::wrap::{key, throw_coded, throw_error, throw_type_error};

/// The code every pending method throws.
pub const NOT_IMPLEMENTED: &str = "ERR_TLS_NOT_IMPLEMENTED";

/// The `.length` of a prototype method, always 0.
///
/// `SetProtoMethod` builds its template through `NewFunctionTemplate`, which
/// passes an explicit `0` for the length (`src/util.cc`, and `crypto_tls.cc`
/// calls `SetProtoMethod` for every one of these). V8 honours whatever length it
/// is handed, so passing the callback's real arity — 1 for `setServername`, 3
/// for `loadSession` — reported a function Node does not have. The
/// argument-count knowledge is still in the table below as documentation of the
/// callback's shape, but it no longer reaches the published function.
pub fn length_of(_name: &str) -> i32 {
    0
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

pending_method!(
    pending_renegotiate,
    "renegotiate",
    3,
    "it drives SSL_renegotiate through the retry loop"
);

// Increment 4 landed the session and ALPN surface a real connection reaches:
// `enableSessionCallbacks`, `enableALPNCb`, `enableKeylogCallback`,
// `loadSession`, `setSession`, `newSessionDone`, `setALPNProtocols`. What is
// still deferred is listed below with the connection shape that would need it, so
// the remaining gaps are visible rather than implied.
//
// | method | why it is still deferred |
// | --- | --- |
// | `certCbDone`, `enableCertCb` | OCSP and SNI certificate switching for a server: `SSL_set_cert_cb` parks the handshake until JavaScript answers. An ordinary TLS server and every client path never enters it. |
// | `clientHelloDone` | Resumes a server handshake parked by the *early ClientHello* callback, which only a `'resumeSession'` server listener reaches. Client-side resumption uses `setSession`, which is implemented. |
// | `requestOCSP`, `setOCSPResponse` | The stapled-OCSP pair. `requestOCSP` needs `SSL_set_tlsext_status_type` plus the response callback; `setOCSPResponse` needs a peer response to attach. Neither is on by default. |
// | `setKeyCert` | Per-`SSL` certificate for an SNI-selected context. A server's certificate comes from its `SecureContext`, so only `setSecureContext`-per-session server code needs this. |
// | `exportKeyingMaterial`, `getFinished`, `getPeerFinished` | Channel-binding and Finished-message queries: `tlsSocket.exportKeyingMaterial()` and the `test-tls-*` files that read them. Nothing in `https`, `http2` or `fetch` calls them. |
// | `enablePskCallback`, `setPskIdentityHint` | Pre-shared keys, an alternative to certificates. `tls.connect({ pskCallback })` is the only caller, and no mainstream client uses it. |
// | `getX509Certificate` | The `X509Certificate` object for the *local* certificate. `getCertificate` (legacy shape) is implemented; this is the newer class-returning form. |
// | `renegotiate` | TLS 1.2 renegotiation. TLS 1.3 has no renegotiation and this build's clients negotiate 1.3; `tlsSocket.renegotiate()` is the only caller. |
pending_method!(
    pending_cert_cb_done,
    "certCbDone",
    4,
    "it resumes the handshake from the oncertcb handler, which needs the OCSP and SNI certificate-switch path"
);
pending_method!(
    pending_client_hello_done,
    "clientHelloDone",
    4,
    "it resumes a server handshake parked by the early ClientHello callback, which only a 'resumeSession' server listener reaches"
);
pending_method!(
    pending_enable_cert_cb,
    "enableCertCb",
    4,
    "it parks the handshake until oncertcb answers, which is the OCSP and SNI certificate-switch path"
);
pending_method!(
    pending_request_ocsp,
    "requestOCSP",
    4,
    "it enables the status-request extension and needs the OCSP response path"
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
    pending_export_keying_material,
    "exportKeyingMaterial",
    4,
    "it needs a completed handshake to export from"
);
pending_method!(
    pending_get_finished,
    "getFinished",
    4,
    "it reads the local Finished message, which needs a completed handshake"
);
pending_method!(
    pending_get_peer_finished,
    "getPeerFinished",
    4,
    "it reads the peer's Finished message, which needs a completed handshake"
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
pending_method!(
    pending_get_x509_certificate,
    "getX509Certificate",
    4,
    "it needs a handshake that selected a certificate"
);

/// Installs one prototype method onto `prototype`.
pub fn install_into<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: &v8::Template,
    name: &'static str,
) -> Result<(), String> {
    macro_rules! method {
        ($callback:path) => {{
            // A `FunctionTemplate` rather than a `Function`: `Template::Set` on a
            // prototype template accepts a primitive or a *Template*, and a
            // `Function` is neither. Node's `SetProtoMethod` installs the template
            // directly for the same reason, and reports the length 0 that
            // `rn_core::method` carries.
            let template = rn_core::method($callback).build(scope);
            prototype.set(key(scope, name)?.into(), template.into());
        }};
    }

    match name {
        // Implemented today.
        "destroySSL" => method!(destroy_ssl),
        "getServername" => method!(get_servername),
        "verifyError" => method!(crate::peer_cert::verify_error),
        "isSessionReused" => method!(is_session_reused),
        "getProtocol" => method!(get_protocol),
        "getSharedSigalgs" => method!(crate::peer_cert::get_shared_sigalgs),
        "getTLSTicket" => method!(crate::peer_cert::get_tls_ticket),
        "setMaxSendFragment" => method!(set_max_send_fragment),
        "enableTrace" => method!(enable_trace),
        "writesIssuedByPrevListenerDone" => method!(writes_issued_by_prev_listener_done),

        // Increment 2: the read and write paths.
        "receive" => method!(receive),

        // Increment 3: the handshake state machine and the SSL_get_error retry loop.
        "start" => method!(start),
        "setVerifyMode" => method!(set_verify_mode),
        "getCipher" => method!(get_cipher),
        "renegotiate" => method!(pending_renegotiate),

        // Increment 4: the SSL callbacks, session resumption, and the queries that
        // need a completed handshake.
        "certCbDone" => method!(pending_cert_cb_done),
        "clientHelloDone" => method!(pending_client_hello_done),
        "enableCertCb" => method!(pending_enable_cert_cb),
        "enableALPNCb" => method!(enable_alpn_cb),
        "enableKeylogCallback" => method!(enable_keylog_callback),
        "enableSessionCallbacks" => method!(enable_session_callbacks),
        "loadSession" => method!(load_session),
        "newSessionDone" => method!(new_session_done),
        "requestOCSP" => method!(pending_request_ocsp),
        "setALPNProtocols" => method!(set_alpn_protocols),
        "setKeyCert" => method!(pending_set_key_cert),
        "setOCSPResponse" => method!(pending_set_ocsp_response),
        "setServername" => method!(set_servername),
        "setSession" => method!(set_session),
        "exportKeyingMaterial" => method!(pending_export_keying_material),
        "getALPNNegotiatedProtocol" => method!(get_alpn_negotiated_protocol),
        "getCertificate" => method!(crate::peer_cert::get_certificate),
        "getX509Certificate" => method!(pending_get_x509_certificate),
        "getEphemeralKeyInfo" => method!(get_ephemeral_key_info),
        "getFinished" => method!(pending_get_finished),
        "getPeerCertificate" => method!(crate::peer_cert::get_peer_certificate),
        "getPeerX509Certificate" => method!(crate::peer_cert::get_peer_x509_certificate),
        "hasPeerCertificate" => method!(crate::peer_cert::has_peer_certificate_method),
        "getPeerFinished" => method!(pending_get_peer_finished),
        "getSession" => method!(get_session),
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

/// `TLSWrap::GetSession` (`crypto_tls.cc:1977`): the current session as DER.
///
/// `SSL_get_session` then `i2d_SSL_SESSION` into a `Buffer`. An absent session is
/// `undefined`, not an empty buffer — the binding simply does not set a return
/// value, which JavaScript reads as `undefined`.
///
/// This is on the **server's accept path**, not an optional query:
/// `lib/internal/tls/wrap.js`'s new-session handling reads it while a connection
/// is being established, and a throw there aborts `'connection'` before
/// `'secureConnection'` — which is why a server never accepted at all while this
/// was a stub.
fn get_session<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let der = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return None;
        }
        // SAFETY: `ssl` is live, checked above. The session is owned by the SSL.
        let session = unsafe { openssl_sys::SSL_get_session(ssl) };
        if session.is_null() {
            return None;
        }
        // SAFETY: `session` is live for the SSL's lifetime; a null output pointer
        // asks only for the encoded length.
        let length = unsafe { openssl_sys::i2d_SSL_SESSION(session, std::ptr::null_mut()) };
        if length <= 0 {
            return None;
        }
        let mut bytes = vec![0u8; length as usize];
        let mut cursor = bytes.as_mut_ptr();
        // SAFETY: `bytes` has exactly `length` bytes, and `i2d_SSL_SESSION`
        // advances `cursor` past what it wrote without overrunning the buffer it
        // was given room for.
        let written = unsafe { openssl_sys::i2d_SSL_SESSION(session, &mut cursor) };
        if written <= 0 {
            return None;
        }
        bytes.truncate(written as usize);
        Some(bytes)
    });

    let Some(Some(bytes)) = der else {
        // No session, or none that can be encoded: the binding leaves the return
        // value unset, which is `undefined`.
        rv.set(v8::undefined(scope).into());
        return;
    };
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let Some(view) = v8::Uint8Array::new(scope, array_buffer, 0, array_buffer.byte_length()) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    if let Some(prototype) = buffer_prototype(scope) {
        view.set_prototype(scope, prototype.into());
    }
    rv.set(view.into());
}

/// `Buffer.prototype` from the global, so a buffer this crate builds is a real
/// `Buffer` rather than a bare `Uint8Array`.
fn buffer_prototype<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let buffer_key = v8::String::new(scope, "Buffer")?;
    let buffer = global.get(scope, buffer_key.into())?;
    let buffer = v8::Local::<v8::Object>::try_from(buffer).ok()?;
    let prototype_key = v8::String::new(scope, "prototype")?;
    let value = buffer.get(scope, prototype_key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// `TLSWrap::GetCipher` (`crypto_tls.cc:2060`), via `GetCipherInfo`.
///
/// `{name, standardName, version}`, from `SSL_get_current_cipher` — `crypto_common.cc:183`.
/// `undefined` when no cipher is current (before the handshake), which is what
/// `GetCipherInfo`'s `return MaybeLocal<Object>()` becomes.
///
/// This is read by `tlsSocket.getCipher()`, which `test-tls-*` calls on every
/// established socket, and by `lib/internal/tls/wrap.js` when it builds the
/// `'session'` object — so it is on the client's completion path, not an optional
/// query.
fn get_cipher<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let info = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return None;
        }
        // SAFETY: `ssl` is live, checked above. The cipher is owned by the SSL.
        let cipher = unsafe { openssl_sys::SSL_get_current_cipher(ssl) };
        if cipher.is_null() {
            return None;
        }
        // All three names come from `SSL_CIPHER_*` accessors over the same
        // struct; each is a static string owned by OpenSSL.
        // SAFETY: `cipher` is live for the SSL's lifetime.
        let name = unsafe { openssl_sys::SSL_CIPHER_get_name(cipher) };
        // `SSL_CIPHER_standard_name` is OpenSSL's IANA spelling; `openssl-sys`
        // does not declare it, so the standard name falls back to the OpenSSL
        // name, which is what it is for every TLS 1.3 suite anyway.
        // SAFETY: as above.
        let version = unsafe { openssl_sys::SSL_CIPHER_get_version(cipher) };
        let read = |pointer: *const std::os::raw::c_char| -> Option<String> {
            if pointer.is_null() {
                return None;
            }
            // SAFETY: OpenSSL returns NUL-terminated static strings for both.
            Some(
                unsafe { std::ffi::CStr::from_ptr(pointer) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        Some((read(name), read(version)))
    });

    let Some(Some((name, version))) = info else {
        // `GetCipherInfo` returns an empty `MaybeLocal<Object>`, which the
        // binding turns into `undefined`.
        rv.set(v8::undefined(scope).into());
        return;
    };
    let object = v8::Object::new(scope);
    let standard = name.clone();
    for (field, value) in [
        ("name", name),
        ("standardName", standard),
        ("version", version),
    ] {
        let Some(text) = value.and_then(|text| v8::String::new(scope, &text)) else {
            continue;
        };
        if let Ok(field_key) = key(scope, field) {
            let _ = object.set(scope, field_key.into(), text.into());
        }
    }
    rv.set(object.into());
}

/// `TLSWrap::GetEphemeralKeyInfo` (`crypto_tls.cc:2264`).
///
/// `null` for a server, which is Node's first branch: a server has no ephemeral
/// key of the *peer* to report. For a client it reads `SSL_get_peer_tmp_key`,
/// which the handshake must have completed to have.
///
/// Both halves are needed before a client handshake can finish:
/// `lib/internal/tls/wrap.js`'s `_finishInit` path reaches this through
/// `getEphemeralKeyInfo` when building the `'session'` object, so a throw here
/// stops `secureConnect` after the handshake has already succeeded.
///
/// The peer key's type is reported by name (`'ECDH'`/`'DH'`) plus its curve or
/// bit size, which is what `tls.TLSSocket.getEphemeralKeyInfo` documents. OpenSSL
/// exposes the parameters through `EVP_PKEY_get_base_id` and, for an EC key,
/// `EVP_PKEY_get_group_name` in 3.x.
fn get_ephemeral_key_info<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let is_server =
        with_state(args.this(), |state| state.kind == crate::ssl::Kind::Server).unwrap_or(false);
    if is_server {
        // `crypto_tls.cc:2272`.
        rv.set(v8::null(scope).into());
        return;
    }
    let info = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return None;
        }
        // SAFETY: `ssl` is live, checked above, and `key` is a live local
        // out-parameter. The key is owned by the SSL.
        let mut key: *mut openssl_sys::EVP_PKEY = std::ptr::null_mut();
        let ok = unsafe { openssl_sys::SSL_get_peer_tmp_key(ssl, &mut key) };
        if ok == 0 || key.is_null() {
            return None;
        }
        // `crypto_common.cc:223` branches on the key's algorithm, and the `type`
        // it reports is a *family* name rather than the OpenSSL id: `'DH'` for
        // Diffie-Hellman, `'ECDH'` for every elliptic-curve agreement including
        // X25519 and X448, with the curve in `name`.
        // SAFETY: `key` is live.
        let base_id = unsafe { openssl_sys::EVP_PKEY_id(key) };
        // SAFETY: `key` is live.
        let size = unsafe { openssl_sys::EVP_PKEY_bits(key) };
        match base_id {
            openssl_sys::EVP_PKEY_DH => Some((DH_TYPE, None::<String>, size)),
            openssl_sys::EVP_PKEY_X25519 => Some((ECDH_TYPE, Some("X25519".to_string()), size)),
            openssl_sys::EVP_PKEY_X448 => Some((ECDH_TYPE, Some("X448".to_string()), size)),
            openssl_sys::EVP_PKEY_EC => {
                // `ncrypto::Ec::GetCurveId` then `OBJ_nid2sn`, which is the short
                // name (`'prime256v1'`, `'secp384r1'`). The provider parameter
                // `OSSL_PKEY_PARAM_GROUP_NAME` holds the same string on 3.x.
                let mut buffer = [0 as std::os::raw::c_char; 128];
                let mut out_len: usize = 0;
                // SAFETY: `key` is live, `buffer` has 128 bytes, and `out_len`
                // is a live local.
                let read = unsafe {
                    openssl_sys::EVP_PKEY_get_utf8_string_param(
                        key,
                        OSSL_PKEY_PARAM_GROUP_NAME.as_ptr().cast(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        &mut out_len,
                    )
                };
                if read != 1 || out_len == 0 {
                    return None;
                }
                // SAFETY: OpenSSL wrote `out_len` bytes into `buffer`.
                let bytes =
                    unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), out_len) };
                Some((
                    ECDH_TYPE,
                    Some(String::from_utf8_lossy(bytes).into_owned()),
                    size,
                ))
            }
            _ => None,
        }
    });

    // `crypto_common.cc:249`: `GetEphemeralKey` **always returns an object** —
    // `{}` when nothing was found, never `null`. Returning `null` breaks
    // `lib/internal/tls/wrap.js`, which reads `.type` off the result, and a real
    // TLS 1.3 connection genuinely returns `{}` because the peer's key is not
    // exposed as a temporary key under 1.3.
    let Some(Some((name, curve, size))) = info else {
        rv.set(v8::Object::new(scope).into());
        return;
    };
    let object = v8::Object::new(scope);
    if let Ok(type_key) = key(scope, "type") {
        if let Some(type_value) = v8::String::new(scope, name) {
            let _ = object.set(scope, type_key.into(), type_value.into());
        }
    }
    if let Ok(name_key) = key(scope, "name") {
        // `crypto_common.cc:218`: `name` is `undefined` for a DH key, because
        // there is no curve to report.
        let value: v8::Local<v8::Value> = match curve.as_deref() {
            Some(text) => match v8::String::new(scope, text) {
                Some(text) => text.into(),
                None => v8::undefined(scope).into(),
            },
            None => v8::undefined(scope).into(),
        };
        let _ = object.set(scope, name_key.into(), value);
    }
    if let Ok(size_key) = key(scope, "size") {
        let _ = object.set(scope, size_key.into(), v8::Integer::new(scope, size).into());
    }
    rv.set(object.into());
}

/// `crypto_common.cc:226`'s `env->dh_string()`.
const DH_TYPE: &str = "DH";
/// `crypto_common.cc:240`'s `env->ecdh_string()`.
const ECDH_TYPE: &str = "ECDH";

/// `OSSL_PKEY_PARAM_GROUP_NAME` from `core_names.h`, NUL-terminated.
///
/// `openssl-sys` does not export the provider parameter names, and the string is
/// part of OpenSSL's public parameter interface rather than an internal.
const OSSL_PKEY_PARAM_GROUP_NAME: &[u8] = b"group\0";

/// `TLSWrap::GetALPNNegotiatedProto`.
///
/// `SSL_get0_alpn_selected`, returning `false` when none was negotiated — Node
/// returns `false` rather than `null` here, and `wrap.js:1208` assigns it
/// straight to `this.alpnProtocol`, so the distinction is observable.
///
/// This is on the **critical path of every client handshake**, not an optional
/// query: `TLSSocket.prototype._finishInit` reads it before it emits `'secure'`,
/// so a throw here means `secureConnect` never fires even though the handshake
/// completed. It is the reason a completed handshake looked like a hang.
fn get_alpn_negotiated_protocol<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let protocol = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return None;
        }
        let mut data: *const u8 = std::ptr::null();
        let mut length: std::os::raw::c_uint = 0;
        // SAFETY: `ssl` is live, and both out-parameters are live locals.
        unsafe {
            openssl_sys::SSL_get0_alpn_selected(ssl, &mut data, &mut length);
        }
        if data.is_null() || length == 0 {
            return None;
        }
        // SAFETY: OpenSSL points at `length` bytes owned by the SSL.
        let bytes = unsafe { std::slice::from_raw_parts(data, length as usize) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    });
    match protocol.flatten() {
        Some(text) => match v8::String::new(scope, &text) {
            Some(value) => rv.set(value.into()),
            None => rv.set(v8::Boolean::new(scope, false).into()),
        },
        // Node's `GetALPNNegotiatedProto` sets `false`, not `null`.
        None => rv.set(v8::Boolean::new(scope, false).into()),
    }
}

/// `TLSWrap::SetServername` (`crypto_tls.cc:1539`): the SNI host name.
///
/// `SSL_set_tlsext_host_name`, which is `SSL_ctrl(SSL_CTRL_SET_TLSEXT_HOSTNAME)`.
///
/// This is **not** optional on the client path: `lib/internal/tls/wrap.js:1072`
/// calls it from `_init` whenever `connectOptions.servername` is set, and
/// `tls.connect` derives that from `host`. While this was a stub, `tls.connect({
/// host })` threw inside `_init` and left the socket half-built, so the process
/// never exited — the same symptom as the teardown bugs, from a completely
/// different cause.
///
/// The three `CHECK`s are `TypeError`s here: a server wrap, a started wrap, or a
/// destroyed one is a caller bug rather than a user error, and a real `node` would
/// abort on each.
fn set_servername<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let value = args.get(0);
    let Ok(text) = v8::Local::<v8::String>::try_from(value) else {
        throw_type_error(scope, "setServername expects a string");
        return;
    };
    let name = text.to_rust_string_lossy(scope);
    // A NUL inside the name would truncate the C string OpenSSL receives, so it is
    // rejected rather than silently cut.
    if name.as_bytes().contains(&0) {
        throw_type_error(scope, "setServername must not contain a NUL byte");
        return;
    }
    let ready = with_state(args.this(), |state| {
        if state.kind != crate::ssl::Kind::Client {
            return Err("setServername is client-only");
        }
        if state.flags.started {
            return Err("setServername must be called before start()");
        }
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return Err("setServername after destroySSL");
        }
        let Ok(c_string) = std::ffi::CString::new(name.clone()) else {
            return Err("setServername must not contain a NUL byte");
        };
        // SAFETY: `ssl` is live, checked above, and `c_string` outlives the call.
        // OpenSSL copies the name into the SSL's extension state.
        //
        // `openssl_sys::SSL_set_tlsext_host_name` is the crate's expansion of the
        // same `SSL_ctrl` the macro uses, so there is no second copy here.
        unsafe {
            openssl_sys::SSL_set_tlsext_host_name(
                ssl,
                c_string.as_ptr() as *mut std::os::raw::c_char,
            );
        }
        Ok(())
    });
    match ready {
        Some(Ok(())) => {}
        Some(Err(message)) => throw_type_error(scope, message),
        None => throw_type_error(scope, "Invalid TLSWrap receiver"),
    }
}

/// `TLSWrap::SetVerifyMode` (`crypto_tls.cc:1381`).
///
/// `lib/internal/tls/wrap.js:967` calls this from `_init` whenever a cert is
/// requested or the peer is to be rejected, which is *most* sockets — so it is
/// the first method a `new tls.TLSSocket()` reaches, and the one this crate used
/// to throw from.
///
/// The mode is asymmetric in Node and the asymmetry matters:
///
/// * a **server** asks for a peer certificate via `SSL_VERIFY_PEER`, and adds
///   `FAIL_IF_NO_PEER_CERT` only when it must reject. Without the request flag
///   there is nothing to reject, so the mode is `VERIFY_NONE`;
/// * a **client** always uses `VERIFY_NONE` and checks the certificate *after*
///   the handshake, because a handshake-time failure for an expired certificate
///   would report `ERR_SSL_*` instead of the `ERR_TLS_CERT_*` code
///   `lib/_tls_wrap.js` produces.
///
/// The verify callback is Node's `VerifyCallback`, which always returns 1. That
/// is what makes the mode meaningful without aborting the handshake: OpenSSL
/// still runs verification and records the result on `SSL_get_verify_result`,
/// but a failure does not terminate the connection, so `rejectUnauthorized`
/// stays a JavaScript decision and `verifyError()` reports the reason. Without
/// it, a server with `requestCert: true, rejectUnauthorized: false` sent `SSL
/// alert 48` (`unknown_ca`) and never accepted the connection — defect 2.
fn set_verify_mode<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    if args.length() < 2 {
        throw_type_error(
            scope,
            "setVerifyMode expects (requestCert, rejectUnauthorized)",
        );
        return;
    }
    let request_cert = args.get(0);
    let reject_unauthorized = args.get(1);
    if !(request_cert.is_true() || request_cert.is_false())
        || !(reject_unauthorized.is_true() || reject_unauthorized.is_false())
    {
        throw_type_error(scope, "setVerifyMode expects booleans");
        return;
    }
    let request = request_cert.is_true();
    let reject = reject_unauthorized.is_true();

    let mode = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return None;
        }
        let mode = if state.kind == crate::ssl::Kind::Server {
            if !request {
                openssl_sys::SSL_VERIFY_NONE
            } else {
                let mut mode = openssl_sys::SSL_VERIFY_PEER;
                if reject {
                    mode |= openssl_sys::SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
                }
                mode
            }
        } else {
            // `crypto_tls.cc:1403`: a client checks after the handshake.
            openssl_sys::SSL_VERIFY_NONE
        };
        state.verify_mode = mode;
        // SAFETY: `ssl` is live, checked above.
        unsafe { openssl_sys::SSL_set_verify(ssl, mode, Some(crate::peer_cert::always_continue)) };
        Some(mode)
    });
    if matches!(mode, Some(None)) {
        throw_type_error(scope, "setVerifyMode on a destroyed TLSWrap");
    }
}

/// `TLSWrap::Start` (`crypto_tls.cc:654`): send the ClientHello.
///
/// Node's body is three lines and a comment that reads oddly until the state
/// machine is in view:
///
/// ```c
/// wrap->ClearOut();   // SSL_read, which triggers the handshake
/// wrap->EncOut();     // hand the ClientHello to the socket
/// ```
///
/// `ClearOut` is the `SSL_read` phase, and `SSL_read` on a client that has not
/// handshaked *starts* the handshake and produces the ClientHello into
/// `enc_out_`. There is no `SSL_do_handshake` call here because reading does the
/// same thing through the same state machine; the explicit `SSL_do_handshake`
/// driver is what `OnStreamRead` uses on a later flight, and both go through
/// [`crate::cycle::run`] so there is one place the phases are ordered.
///
/// The `CHECK(!flags_.started)` and `CHECK(wrap->is_client())` are a `TypeError`
/// here: calling `start()` twice, or on a server, is a caller bug that a real
/// `node` would abort on.
fn start<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    let ready = with_state(object, |state| {
        if state.flags.started {
            return Err("start() was already called");
        }
        if state.kind != crate::ssl::Kind::Client {
            return Err("start() is client-only");
        }
        if state.ssl.is_none() {
            return Err("start() after destroySSL");
        }
        state.flags.started = true;
        Ok(())
    });
    match ready {
        Some(Ok(())) => {}
        Some(Err(message)) => {
            throw_type_error(scope, message);
            return;
        }
        None => {
            throw_type_error(scope, "Invalid TLSWrap receiver");
            return;
        }
    }

    let Some(cell) = crate::state::state_cell(object) else {
        return;
    };
    // SAFETY: `cell` is this object's live state and the object is the receiver,
    // so it cannot be collected during the call.
    unsafe { crate::cycle::run(cell) };

    // The ClientHello is now in `enc_out_` (or `pending_output`); hand it to the
    // socket. `crypto_tls.cc:660`'s `EncOut()`.
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

/// `TLSWrap::SetMaxSendFragment`.
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

/// `TLSWrap::IsSessionReused`.
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

// ---------------------------------------------------------------------------
// Increment 4: session callbacks, resumption, and ALPN
// ---------------------------------------------------------------------------

/// `TLSWrap::EnableSessionCallbacks` (`crypto_tls.cc:1413`).
///
/// Three lines in Node: `CHECK_NOT_NULL(ssl_)` and `enable_session_callbacks()`.
/// The new/get-session callbacks themselves are installed on the `SSL_CTX` when
/// the wrap is built ([`crate::callback::install`]), exactly as
/// `TLSWrap::TLSWrap` does it; this method is the *per-wrap* switch that decides
/// whether they act, which is `has_session_callbacks()` in
/// `NewSessionCallback`.
///
/// This is the method `https.Agent` reaches without meaning to: it attaches a
/// `'session'` listener to every socket it creates (`lib/https.js:456`) to fill
/// its session cache, and `wrap.js:940`'s `newListener` hook turns that into this
/// call. Until it existed, **every** HTTPS request threw here.
fn enable_session_callbacks<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let result = with_state(args.this(), |state| {
        if state.ssl.is_none() {
            return Err("enableSessionCallbacks after destroySSL");
        }
        state.flags.session_callbacks = true;
        if let Some(handles) = state.callback.as_ref() {
            handles.session_callbacks.set(true);
        }
        Ok(())
    });
    match result {
        Some(Ok(())) => {}
        Some(Err(message)) => throw_coded(scope, message, "ERR_TLS_INVALID_STATE"),
        None => throw_type_error(scope, "Invalid TLSWrap receiver"),
    }
}

/// `TLSWrap::EnableALPNCb` (`crypto_tls.cc:1513`).
///
/// Sets `flags_.alpn_callback_enabled` and installs `SelectALPNCallback` on the
/// context. The flag is what makes the callback route the offered list to
/// JavaScript instead of matching against `alpn_protos_`; installing the callback
/// without it would leave `ALPNCallback` never firing.
fn enable_alpn_cb<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let result = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return Err("enableALPNCb after destroySSL");
        }
        state.flags.alpn_callback_enabled = true;
        if let Some(handles) = state.callback.as_ref() {
            handles.alpn_callback_enabled.set(true);
        }
        // SAFETY: `ssl` is live, checked above.
        let ctx = unsafe { crate::ffi_extra::SSL_get_SSL_CTX(ssl) };
        if ctx.is_null() {
            return Err("the SSL has no SSL_CTX");
        }
        // SAFETY: `ctx` is live for the SSL's lifetime, and the callback is a
        // plain `extern "C"` function with no captured state — every wrap's
        // selection reads its own state through the SSL's app-data.
        unsafe { install_alpn_select(ctx) };
        Ok(())
    });
    match result {
        Some(Ok(())) => {}
        Some(Err(message)) => throw_coded(scope, message, "ERR_TLS_INVALID_STATE"),
        None => throw_type_error(scope, "Invalid TLSWrap receiver"),
    }
}

/// `SSL_CTX_set_alpn_select_cb(ctx, SelectALPNCallback, nullptr)`.
///
/// The context is shared by every `SSL` built from one `SecureContext`, so this
/// runs once per wrap and is idempotent: installing the same function twice is
/// what Node's `EnableALPNCb` and `SetALPNProtocols` both do.
///
/// # Safety
///
/// `ctx` must be a live `SSL_CTX`.
unsafe fn install_alpn_select(ctx: *mut openssl_sys::SSL_CTX) {
    // SAFETY: delegated to the caller's guarantee. The callback and the (ignored)
    // argument pointer are `'static` and null, so neither can dangle.
    unsafe {
        openssl_sys::SSL_CTX_set_alpn_select_cb__fixed_rust(
            ctx,
            Some(crate::callback::select_alpn),
            std::ptr::null_mut(),
        );
    }
}

/// `TLSWrap::EnableKeylogCallback` (`crypto_tls.cc:1419`).
///
/// `sc_->SetKeylogCallback(KeylogCallback)`, which is
/// `SSL_CTX_set_keylog_callback`. `wrap.js` calls it from `newListener` when a
/// `'keylog'` listener is attached, so a socket with one threw here before this
/// increment.
fn enable_keylog_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let result = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return Err("enableKeylogCallback after destroySSL");
        }
        // SAFETY: `ssl` is live, checked above.
        let ctx = unsafe { crate::ffi_extra::SSL_get_SSL_CTX(ssl) };
        if ctx.is_null() {
            return Err("the SSL has no SSL_CTX");
        }
        // SAFETY: `ctx` is live for the SSL's lifetime and the callback reads
        // only what OpenSSL passes it plus the wrap's own app-data.
        unsafe { openssl_sys::SSL_CTX_set_keylog_callback(ctx, Some(crate::callback::keylog)) };
        Ok(())
    });
    match result {
        Some(Ok(())) => {}
        Some(Err(message)) => throw_coded(scope, message, "ERR_TLS_INVALID_STATE"),
        None => throw_type_error(scope, "Invalid TLSWrap receiver"),
    }
}

/// `TLSWrap::LoadSession` (`crypto_tls.cc:2068`): store a session for *this*
/// handshake.
///
/// The server side's resumption path: `wrap.js`'s `loadSession(hello)` emits
/// `'resumeSession'`, and the application's handler calls this with the DER it
/// kept, then `clientHelloDone()` to resume the parked handshake. It is also the
/// client's manual path via `tls.TLSSocket#setSession`.
///
/// Node tolerates an argument that does not decode — it stores whatever
/// `d2i_SSL_SESSION` produced, including null — so a malformed buffer here clears
/// the slot rather than throwing. The handshake then proceeds unresumed, which is
/// visible as `session.reused === false` rather than as a connection failure.
fn load_session<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(der) = bytes_argument(scope, args.get(0), "loadSession") else {
        return;
    };
    let result = with_state(args.this(), |state| {
        if state.ssl.is_none() {
            return Err("loadSession after destroySSL");
        }
        state.session.store(crate::ssl::Session::from_der(&der));
        Ok(())
    });
    match result {
        Some(Ok(())) => {}
        Some(Err(message)) => throw_coded(scope, message, "ERR_TLS_INVALID_STATE"),
        None => throw_type_error(scope, "Invalid TLSWrap receiver"),
    }
}

/// `TLSWrap::SetSession` (`crypto_tls.cc:2003`): `SSL_set_session`.
///
/// The client's resumption path, reached from `wrap.js`'s `this._handle.setSession`
/// when `tls.connect({ session })` is given one — which is how an
/// `https.Agent`-cached session is replayed. The decoded session is freed after
/// the call because `SSL_set_session` takes its own reference: Node's
/// `SSLSessionPointer` destructor does exactly the same at the end of the
/// statement.
fn set_session<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(der) = bytes_argument(scope, args.get(0), "setSession") else {
        return;
    };
    // Node's `GetTLSSession` returns null for bytes it cannot decode and then
    // returns silently (`// TODO(tniessen): figure out error handling`).
    let Some(session) = crate::ssl::Session::from_der(&der) else {
        return;
    };
    let result = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return Err("setSession after destroySSL");
        }
        // SAFETY: `ssl` is live, checked above, and `session` outlives the call.
        // `SSL_set_session` takes its own reference on success, so the `Session`
        // that owns this pointer frees only the reference created by
        // `d2i_SSL_SESSION` below.
        let ok = unsafe { openssl_sys::SSL_set_session(ssl, session.as_ptr()) == 1 };
        if ok {
            Ok(())
        } else {
            Err("SSL_set_session error")
        }
    });
    match result {
        Some(Ok(())) => {}
        Some(Err(message)) => throw_error(scope, message),
        None => throw_type_error(scope, "Invalid TLSWrap receiver"),
    }
}

/// `TLSWrap::NewSessionDone` (`crypto_tls.cc:2237`).
///
/// Clears `flags_.awaiting_new_session` and runs `NewSessionDoneCb`, which is one
/// `Cycle()`. The flag matters: `EncOut` refuses to write while it is set, so a
/// server cannot send the ticket before the application has decided whether to
/// store the session. Clearing it without cycling would leave the parked output
/// in `enc_out_` until the next unrelated event.
fn new_session_done<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    let Some(cell) = crate::state::state_cell(object) else {
        throw_type_error(scope, "Invalid TLSWrap receiver");
        return;
    };
    // The flag is cleared through the callback slot, not through the state: this
    // method is reached from inside `SSL_do_handshake`, where `cycle` holds the
    // state's borrow — see `callback::clear_awaiting_new_session`.
    crate::callback::clear_awaiting_new_session(cell);
    // `with_state` is attempted afterwards and deliberately ignored when it
    // fails: the state half of the flag is only readable outside a library call,
    // and `enc_out` already prefers the slot's value.
    let _ = with_state(object, |state| {
        state.flags.awaiting_new_session = false;
    });
    // SAFETY: `cell` is this object's live state and the object is the receiver,
    // so it cannot be collected during the call.
    unsafe { crate::cycle::run(cell) };
    // The parked ciphertext — the server's ticket, usually — is now in
    // `pending_output` and has to reach the socket.
    let stream = with_state(object, |state| state.underlying).flatten();
    if let Some(stream) = stream {
        // SAFETY: `stream` is the wrap's own `underlying`, live while it holds it.
        unsafe { crate::stream::flush(scope, object, stream, None) };
    }
}

/// `TLSWrap::SetALPNProtocols` (`crypto_tls.cc:1819`): the ALPN list.
///
/// Two branches, and which one runs is the whole negotiation:
///
/// * **client** — `SSL_set_alpn_protos`, which makes OpenSSL send the list in its
///   ClientHello and pick whatever the server answers. A return of anything but 0
///   is a `CHECK_EQ` failure in Node; here it is a `TypeError`, because the only
///   way to reach it is a list OpenSSL considers malformed.
/// * **server** — keep the list in `alpn_protos_` and install
///   `SelectALPNCallback`, which matches it against each ClientHello.
///
/// This is what `http2.connect('https://…')` reaches first:
/// `lib/internal/http2/core.js` sets `ALPNProtocols: ['h2']`, so before this
/// increment a secure HTTP/2 session threw before it was even constructed.
fn set_alpn_protocols<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(protos) = bytes_argument(scope, args.get(0), "setALPNProtocols") else {
        return;
    };
    let result = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return Err("setALPNProtocols after destroySSL".to_string());
        }
        if state.kind == crate::ssl::Kind::Client {
            // SAFETY: `ssl` is live, checked above, and `protos` outlives the
            // call; OpenSSL copies the list into the SSL.
            let status = unsafe {
                openssl_sys::SSL_set_alpn_protos(
                    ssl,
                    protos.as_ptr(),
                    protos.len() as std::os::raw::c_uint,
                )
            };
            if status != 0 {
                return Err(format!(
                    "SSL_set_alpn_protos failed with {status}: the list is empty or malformed"
                ));
            }
            return Ok(());
        }
        state.alpn_protos = protos;
        if let Some(handles) = state.callback.as_ref() {
            // The callback reads the list from the slot rather than the state,
            // because it runs on OpenSSL's stack where `cycle` holds the borrow.
            *handles.alpn_protos.borrow_mut() = state.alpn_protos.clone();
        }
        // SAFETY: `ssl` is live, checked above.
        let ctx = unsafe { crate::ffi_extra::SSL_get_SSL_CTX(ssl) };
        if ctx.is_null() {
            return Err("the SSL has no SSL_CTX".to_string());
        }
        // SAFETY: `ctx` is live for the SSL's lifetime.
        unsafe { install_alpn_select(ctx) };
        Ok(())
    });
    match result {
        Some(Ok(())) => {}
        Some(Err(message)) => throw_type_error(scope, &message),
        None => throw_type_error(scope, "Invalid TLSWrap receiver"),
    }
}

/// The bytes of an `ArrayBufferView` argument, or a `TypeError`.
///
/// Node's bindings `CHECK` the view type; a coercion would turn a caller's bug
/// into a plausible-looking zero-length list, which `AGENTS.md` names as the
/// reason bindings here are type-strict.
fn bytes_argument<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
    method: &str,
) -> Option<Vec<u8>> {
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) else {
        throw_type_error(scope, &format!("{method} expects a Buffer"));
        return None;
    };
    let length = view.byte_length();
    if length == 0 {
        return Some(Vec::new());
    }
    let base = view.data().cast::<u8>();
    if base.is_null() {
        throw_type_error(scope, &format!("{method} was given a view with no data"));
        return None;
    }
    // SAFETY: `base` points at `length` bytes of the caller's view, valid for the
    // duration of the call, and the copy does not outlive it.
    Some(unsafe { std::slice::from_raw_parts(base, length) }.to_vec())
}

// ---------------------------------------------------------------------------
// The AsyncWrap surface (increment 4, defect 5)
// ---------------------------------------------------------------------------

/// Installs one `AsyncWrap` method onto `prototype`.
///
/// Separate from [`install_into`] because the names are not in
/// [`crate::wrap::PROTO_METHODS`]: they come from `AsyncWrap`'s template, which
/// `TLSWrap` inherits rather than lists.
pub fn install_async_wrap_into<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: &v8::Template,
    name: &'static str,
) -> Result<(), String> {
    // `async_wrap.cc` installs these with `SetProtoMethod`, so all three report
    // `length` 0 even though `asyncReset` takes an argument.
    macro_rules! method {
        ($callback:path) => {{
            let template = rn_core::method($callback).build(scope);
            prototype.set(key(scope, name)?.into(), template.into());
        }};
    }
    match name {
        "getAsyncId" => method!(get_async_id),
        "asyncReset" => method!(async_reset),
        "getProviderType" => method!(get_provider_type),
        other => return Err(format!("{other} is not an AsyncWrap method")),
    }
    Ok(())
}

/// `AsyncWrap::GetAsyncId`.
///
/// The id comes from the wrap's own state, not a fresh value per call: an async
/// id identifies the *resource*, so two calls must agree and `asyncReset` is the
/// only thing that changes it. `kInvalidAsyncId` for a receiver that is not a
/// wrap, which is Node's `Set(kInvalidAsyncId)` before `UNWRAP`.
fn get_async_id<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let id = with_state(args.this(), |state| state.async_wrap.async_id())
        .unwrap_or(rn_bind_async_wrap::INVALID_ASYNC_ID);
    rv.set(v8::Number::new(scope, id).into());
}

/// `AsyncWrap::GetProviderType`.
///
/// `PROVIDER_TLSWRAP` (68) for a real wrap. `lib/internal/http/agent.js` reads
/// this to build the `ReusedHandle` it resets a pooled socket with, so the
/// `init` hook that follows names the resource with the kind it already was.
fn get_provider_type<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let provider = with_state(args.this(), |state| state.async_wrap.provider())
        .unwrap_or(rn_core::async_wrap::PROVIDER_NONE);
    rv.set(v8::Integer::new_from_unsigned(scope, provider).into());
}

/// `AsyncWrap::AsyncReset`.
///
/// Assigns a new async id and runs the `destroy`/`init` pair that goes with the
/// change. A `TLSWrap` is built inside `wrap()`, which resets it once; a socket
/// pulled back out of an `http.Agent` keep-alive pool is reset per request,
/// which is what makes a reused TLS connection a new async resource.
fn async_reset<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    // `CHECK(args[0]->IsObject())`. A non-object is a caller bug that a real
    // `node` aborts on; throwing keeps the process alive without hiding it.
    let Ok(resource) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "asyncReset requires a resource object");
        return;
    };
    // `args[1]->IsNumber() ? args[1].As<Number>()->Value() : kInvalidAsyncId`.
    let execution_async_id = if args.get(1).is_number() {
        args.get(1).number_value(scope)
    } else {
        None
    };
    let object = args.this();
    let _ = with_state(object, |state| {
        rn_bind_async_wrap::async_reset(
            scope,
            &mut state.async_wrap,
            resource,
            object,
            execution_async_id,
        );
        state.context_frame = rn_bind_async_wrap::current_context_frame(scope);
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
            // name set: a name in `PROTO_METHODS` that this module does not
            // match would be rejected at namespace install, which
            // `tests/prototype.rs` exercises against the real binary.
            assert_eq!(length_of(name), 0, "{name}");
        }
        assert_eq!(crate::wrap::PROTO_METHODS.len(), 42);
    }

    /// The implemented methods are all in the installed list, and the remainder
    /// throw — the split the module docs describe.
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
            // Increment 2 and 3.
            "receive",
            "start",
            "setVerifyMode",
            "getCipher",
            "setServername",
            "getALPNNegotiatedProtocol",
            "getEphemeralKeyInfo",
            "getSession",
            // Increment 4.
            "enableSessionCallbacks",
            "enableALPNCb",
            "enableKeylogCallback",
            "loadSession",
            "setSession",
            "newSessionDone",
            "setALPNProtocols",
        ];
        for name in implemented {
            assert!(
                crate::wrap::PROTO_METHODS.contains(&name),
                "{name} is implemented but not installed"
            );
        }
        // The rest still throw, and each names its increment. The count is pinned
        // so a method that quietly becomes implemented — or stops being — shows up
        // here rather than only in a live smoke test.
        assert_eq!(crate::wrap::PROTO_METHODS.len() - implemented.len(), 17);
    }

    /// The deferrals a real HTTPS or HTTP/2 connection does not reach, so the
    /// remaining gaps are visible with their reasons.
    ///
    /// Keeping this as data is the point: `pending` entries throw a message that
    /// names the increment, and a test that listed them nowhere would let one
    /// silently drift into "implemented" or vanish from the prototype.
    #[test]
    fn the_deferred_set_is_the_ocsp_psk_and_sni_surface() {
        let deferred = [
            "certCbDone",
            "clientHelloDone",
            "enableCertCb",
            "enablePskCallback",
            "exportKeyingMaterial",
            "getFinished",
            "getPeerFinished",
            "getX509Certificate",
            "renegotiate",
            "requestOCSP",
            "setKeyCert",
            "setOCSPResponse",
            "setPskIdentityHint",
        ];
        for name in deferred {
            assert!(
                crate::wrap::PROTO_METHODS.contains(&name),
                "{name} is deferred but not installed"
            );
        }
        assert_eq!(deferred.len(), 13);
    }

    /// Every prototype method reports `length` 0, whatever its arity.
    ///
    /// `SetProtoMethod` builds through `NewFunctionTemplate`, so Node reports 0
    /// for all of them. Asserting it by name pins the rule rather than leaving a
    /// table that looks like it should have per-name values.
    #[test]
    fn the_arity_table_is_node_s() {
        for name in crate::wrap::PROTO_METHODS {
            assert_eq!(length_of(name), 0, "{name}");
        }
        assert_eq!(length_of("setServername"), 0);
        assert_eq!(length_of("loadSession"), 0);
        assert_eq!(length_of("start"), 0);
    }
}
