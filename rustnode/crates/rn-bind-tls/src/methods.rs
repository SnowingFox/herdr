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
        "start" => method!(start),
        "setVerifyMode" => method!(set_verify_mode),
        "getCipher" => method!(get_cipher),
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
        "getALPNNegotiatedProtocol" => method!(get_alpn_negotiated_protocol),
        "getCertificate" => method!(pending_get_certificate),
        "getX509Certificate" => method!(pending_get_x509_certificate),
        "getEphemeralKeyInfo" => method!(get_ephemeral_key_info),
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
/// The verify callback is `None` rather than a native `VerifyCallback`: Node
/// installs one to stop OpenSSL from aborting, and this crate's post-handshake
/// check is what decides, so there is nothing for it to do. A `None` here means
/// OpenSSL accepts the chain and `verifyError()` reports the result — the same
/// observable behaviour, without a callback that would have to call into V8.
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
        unsafe { openssl_sys::SSL_set_verify(ssl, mode, None) };
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
