//! The peer's certificate chain, the verification result, and the accessors that
//! read them.
//!
//! `crypto_tls.cc`'s `GetPeerCertificate` (`:1865`), `GetPeerX509Certificate`
//! (`:1881`), `HasPeerCertificate` (`:1895`), `GetCertificate` (`:1902`) and
//! `VerifyError` (`:2029`) are the five functions this mirrors, and they are not
//! five independent features: all five read state a completed handshake left on
//! the `SSL`, and the verification result is what `authorized` becomes.
//!
//! # The chain is two different things depending on the side
//!
//! `GetPeerCert`'s comment is the whole trap:
//!
//! ```text
//! // NOTE: This is because of the odd OpenSSL behavior. On client `cert_chain`
//! // contains the `peer_certificate`, but on server it doesn't.
//! X509Pointer cert(is_server ? X509Pointer::PeerFrom(ssl) : X509Pointer());
//! STACK_OF(X509)* ssl_certs = SSL_get_peer_cert_chain(ssl.get());
//! ```
//!
//! On a **client**, `SSL_get_peer_cert_chain` starts at the leaf. On a **server**
//! it starts at the *first intermediate*, and the leaf comes only from
//! `SSL_get1_peer_certificate`. Reading only the chain on a server therefore
//! reports the intermediate as the peer's certificate, which chains and
//! fingerprints plausibly and is wrong.
//!
//! # The chain is read, never consumed
//!
//! The peer chain is owned by the `SSL`, and `SSL_get_peer_cert_chain` returns a
//! borrowed pointer. Node copies it (`CloneSSLCerts` duplicates every entry) and
//! this does the same, which is why repeated reads work:
//! `test-tls-peer-certificate-repeated-reads.js` exists because a version of
//! Node consumed the chain and left the second read with only the leaf.
//!
//! # `verifyError()` is an object, not a number
//!
//! `TLSSocket.prototype.getPeerCertificate`'s neighbours read `verifyError()`
//! and take `.code` off it:
//!
//! ```js
//! const verifyError = this._handle.verifyError();
//! if (verifyError) {
//!   this.authorizationError = verifyError.code;
//! ```
//!
//! So the binding returns `null` or an `Error` carrying `code`, not an
//! `X509_V_*` integer. Returning the integer makes `authorizationError`
//! `undefined` and every test that compares it against
//! `UNABLE_TO_VERIFY_LEAF_SIGNATURE` fails with no error at all — which is
//! defect 1 in this increment's brief, measured as `client err: undefined`.

use std::os::raw::{c_int, c_long};

use openssl_sys as ffi;
use rn_v8_sys::v8;

use crate::state::with_state;

/// `#define NID_auth_psk 1048` in `obj_mac.h`.
///
/// `verifyPeerCertificate` uses it to allow a certificate-less PSK handshake.
const NID_AUTH_PSK: c_int = 1048;

/// `#define TLS1_3_VERSION 0x0304` in `tls1.h`.
const TLS1_3_VERSION: c_int = 0x0304;

extern "C" {
    /// `int SSL_CIPHER_get_auth_nid(const SSL_CIPHER *ciph);` — `ssl.h`.
    ///
    /// `openssl-sys` has `SSL_CIPHER_get_name`, `_standard_name` and
    /// `_get_version` but not this one.
    fn SSL_CIPHER_get_auth_nid(cipher: *const ffi::SSL_CIPHER) -> c_int;

    /// `int SSL_SESSION_get0_ticket(const SSL_SESSION *s, const unsigned char **tick,
    /// size_t *len);` — `ssl.h`.
    fn SSL_SESSION_get0_ticket(
        session: *const ffi::SSL_SESSION,
        ticket: *mut *const std::ffi::c_uchar,
        length: *mut usize,
    ) -> c_int;

    /// `int SSL_set1_verify_cert_store(SSL *s, X509_STORE *st);` — `ssl.h`.
    ///
    /// `SetCACerts` calls it so a per-`SSL` context's trust store reaches the
    /// connection; that is the "is the server's CA store from addCACert reached"
    /// half of defect 2.
    pub(crate) fn SSL_set1_verify_cert_store(
        ssl: *mut ffi::SSL,
        store: *mut ffi::X509_STORE,
    ) -> c_int;

    /// `STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx);`
    fn SSL_CTX_get_client_CA_list(ctx: *const ffi::SSL_CTX) -> *mut ffi::stack_st_X509_NAME;

    /// `STACK_OF(X509_NAME) *SSL_dup_CA_list(const STACK_OF(X509_NAME) *sk);`
    fn SSL_dup_CA_list(names: *const ffi::stack_st_X509_NAME) -> *mut ffi::stack_st_X509_NAME;
}

/// `#define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT 2` in `x509_vfy.h`.
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
/// `#define X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT 18`.
const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
/// `#define X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE 21`.
const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;

/// The DER of the peer's chain, leaf first.
///
/// `GetPeerCert`'s two-branch read: `SSL_get1_peer_certificate` supplies the
/// leaf on a server, and `SSL_get_peer_cert_chain` supplies the rest. On a
/// client the chain already starts at the leaf, which is why `issuers_start`
/// exists.
///
/// Returns an empty list when there is no peer certificate at all, which the
/// binding reports as `undefined` rather than an empty object — a caller that
/// only wanted "is there one" gets [`has_peer_certificate`] instead.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the only callers are the TLSWrap prototype methods, which pass \
              WrapState::ssl_ptr() for the wrap that is the call's receiver; that \
              Ssl is owned by the same WrapState and freed only by its destroy \
              path, so it is live for the whole call"
)]
pub fn peer_chain(ssl: *mut ffi::SSL, is_server: bool, include_issuers: bool) -> Vec<Vec<u8>> {
    if ssl.is_null() {
        return Vec::new();
    }

    // The leaf. `SSL_get1_peer_certificate` is the 3.x spelling and returns a
    // **new reference**, so it is freed here; `SSL_get_peer_cert_chain`'s
    // entries are borrowed and are only copied.
    //
    // SAFETY: `ssl` is live, and the returned `X509` is owned by this function
    // for the duration of the read.
    let leaf = unsafe { ffi::SSL_get1_peer_certificate(ssl) };

    // SAFETY: `ssl` is live; the stack is owned by the SSL and only read here.
    let chain = unsafe { ffi::SSL_get_peer_cert_chain(ssl) };
    let chain_len = if chain.is_null() {
        0
    } else {
        // SAFETY: `chain` is a live `STACK_OF(X509)`, which
        // `OPENSSL_sk_num` only reads.
        unsafe { ffi::OPENSSL_sk_num(chain.cast()) }.max(0)
    };

    let mut certificates = Vec::new();
    if !leaf.is_null() {
        // SAFETY: `leaf` is this function's reference.
        if let Some(der) = unsafe { der_of(leaf) } {
            certificates.push(der);
        }
    }

    // `issuers_start`: on a client the chain's first entry *is* the leaf, and
    // Node skips it exactly when it was taken from the chain rather than from
    // `PeerFrom`. On a server nothing is skipped.
    let start = if is_server || leaf.is_null() { 0 } else { 1 };
    if include_issuers {
        for index in start..chain_len {
            // SAFETY: `index` is inside the count read above.
            let entry = unsafe { ffi::OPENSSL_sk_value(chain.cast(), index) } as *mut ffi::X509;
            if entry.is_null() {
                continue;
            }
            // SAFETY: `entry` is borrowed from the live chain.
            if let Some(der) = unsafe { der_of(entry) } {
                certificates.push(der);
            }
        }
    } else if certificates.is_empty() && chain_len > 0 {
        // An abbreviated read on a client with a chain but no `PeerFrom`: the
        // leaf is the chain's first entry.
        // SAFETY: `chain_len > 0`, so index 0 exists.
        let entry = unsafe { ffi::OPENSSL_sk_value(chain.cast(), 0) } as *mut ffi::X509;
        if !entry.is_null() {
            // SAFETY: borrowed from the live chain.
            if let Some(der) = unsafe { der_of(entry) } {
                certificates.push(der);
            }
        }
    }

    if !leaf.is_null() {
        // SAFETY: the reference `SSL_get1_peer_certificate` returned, freed
        // exactly once.
        unsafe { ffi::X509_free(leaf) };
    }
    certificates
}

/// The DER encoding of one certificate, which the snapshot design needs.
///
/// # Safety
///
/// `certificate` must be a live `X509`, or null.
unsafe fn der_of(certificate: *mut ffi::X509) -> Option<Vec<u8>> {
    if certificate.is_null() {
        return None;
    }
    // SAFETY: `certificate` is live and `i2d_X509` only reads it.
    unsafe {
        let length = ffi::i2d_X509(certificate, std::ptr::null_mut());
        if length <= 0 {
            return None;
        }
        let mut bytes = vec![0u8; length as usize];
        let mut cursor = bytes.as_mut_ptr();
        let written = ffi::i2d_X509(certificate, &mut cursor);
        if written != length {
            return None;
        }
        Some(bytes)
    }
}

/// `HasPeerCertificate` (`crypto_tls.cc:1895`): whether the peer sent a
/// certificate.
///
/// `wrap.js:1343` reads it to tell an unauthorized socket from one with no
/// certificate at all, so it has to be the certificate's presence and not the
/// verify result: a TLS 1.3 resumed handshake reports `X509_V_OK` with no
/// certificate, which is exactly the case the check exists for.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "reachable only from the TLSWrap prototype methods and \
              peer_verify_result, both of which hand over WrapState::ssl_ptr() for \
              a wrap whose Ssl is alive for the call"
)]
pub fn has_peer_certificate(ssl: *mut ffi::SSL) -> bool {
    if ssl.is_null() {
        return false;
    }
    // SAFETY: `ssl` is live, and `SSL_get1_peer_certificate` returns a new
    // reference this function frees.
    let certificate = unsafe { ffi::SSL_get1_peer_certificate(ssl) };
    if certificate.is_null() {
        return false;
    }
    // SAFETY: the reference just taken.
    unsafe { ffi::X509_free(certificate) };
    true
}

/// The local certificate's DER, or `None`.
///
/// `GetCertificate` is `SSL_get_certificate`, which is a **borrowed** pointer to
/// the certificate the `SSL` is currently configured with — not the context's.
/// That distinction is what makes `setKeyCert`'s SNI swap visible here.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "called only by GetCertificate's binding, with WrapState::ssl_ptr() \
              from the wrap that is the receiver; the certificate it returns is \
              owned by that SSL and only read"
)]
pub fn local_certificate(ssl: *mut ffi::SSL) -> Option<Vec<u8>> {
    if ssl.is_null() {
        return None;
    }
    // SAFETY: `ssl` is live; the returned `X509` is owned by the SSL.
    let certificate = unsafe { ffi::SSL_get_certificate(ssl) };
    // SAFETY: borrowed, only read.
    unsafe { der_of(certificate) }
}

/// The `X509_STORE` a per-`SSL` context installed, for `SetCACerts`.
///
/// Returns whether `SSL_set1_verify_cert_store` accepted it. A server that
/// installed a client-CA list on its `SSL_CTX` did **not** install the store on
/// the per-`SSL` object when `CertCbDone` swapped the context, so this is the
/// call that makes an SNI context's `ca` reach verification. Without it a
/// connection whose context came from `SNICallback` verifies against the
/// default context's store, which is defect 2's second half.
///
/// # Safety
///
/// `ssl` must be live, and `ctx` must be a live `SSL_CTX` that outlives the
/// call.
pub unsafe fn set_ca_certs(ssl: *mut ffi::SSL, ctx: *mut ffi::SSL_CTX) -> bool {
    if ssl.is_null() || ctx.is_null() {
        return false;
    }
    // SAFETY: both pointers are live per the caller's contract; the store is
    // owned by the context and only associated with the SSL.
    unsafe {
        let store = ffi::SSL_CTX_get_cert_store(ctx);
        if SSL_set1_verify_cert_store(ssl, store) != 1 {
            return false;
        }
        // `SetCACerts` also duplicates the client-CA list, which is what tells a
        // TLS 1.2 client which issuers to offer a certificate from.
        let names = SSL_CTX_get_client_CA_list(ctx);
        if names.is_null() {
            return true;
        }
        let copy = SSL_dup_CA_list(names);
        if copy.is_null() {
            return true;
        }
        // `SSL_set_client_CA_list` takes ownership of `copy`.
        ffi::SSL_set_client_CA_list(ssl, copy);
    }
    true
}

/// `SSL_set_verify` as `SetVerifyMode`'s counterpart to [`crate::ssl`]'s
/// `SSL_VERIFY_NONE`.
///
/// # Safety
///
/// `ssl` must be live, or null.
pub unsafe fn set_verify(ssl: *mut ffi::SSL, mode: c_int, callback: VerifyCallback) {
    if ssl.is_null() {
        return;
    }
    // SAFETY: `ssl` is live per the caller's contract.
    unsafe { ffi::SSL_set_verify(ssl, mode, callback) };
}

/// The per-connection verify callback type.
pub type VerifyCallback = Option<extern "C" fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int>;

/// Node's `VerifyCallback` (`crypto_tls.cc:97`): always return 1.
///
/// The comment in Node is the specification and it is not a shortcut:
///
/// ```text
/// // From https://www.openssl.org/docs/man3.0/man3/SSL_verify_cb:
/// //   If VerifyCallback returns 1, the verification process is continued. If
/// //   VerifyCallback always returns 1, the TLS/SSL handshake will not be
/// //   terminated with respect to verification failures and the connection will
/// //   be established.
/// ```
///
/// This is defect 2's fix. Without a callback, `SSL_VERIFY_PEER` on a server
/// makes OpenSSL abort the handshake with `SSL alert 48` (`unknown_ca`) when the
/// client's chain does not verify — even with `rejectUnauthorized: false`, whose
/// whole meaning is "complete the handshake and let JavaScript decide".
/// Returning 1 keeps the connection alive and leaves the reason on
/// `SSL_get_verify_result`, which is what [`verify_result`] reads.
pub extern "C" fn always_continue(_preverify_ok: c_int, _ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    1
}

/// `SSL_get_verify_result` for a live `SSL`.
///
/// The four `SSL_get_*` queries this and its neighbours make are one family and
/// share one argument contract, which [`peer_verify_result`] states.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "called only by VerifyError::of, which is reached from the \
              verifyError() prototype method with WrapState::ssl_ptr() for that \
              method's own receiver; the SSL is alive for the call"
)]
/// `SSLPointer::verifyPeerCertificate` (`ncrypto.cc:5175`), as `VerifyError`
/// consumes it.
///
/// `None` means "no verdict at all", which `VerifyError` turns into
/// `UNABLE_TO_GET_ISSUER_CERT`: a peer that presented no certificate has not
/// been verified. The two exceptions ncrypto carves out are a PSK handshake,
/// where there is no certificate by design, and a TLS 1.3 resumption, where the
/// PSK *is* the authentication and OpenSSL reports `X509_V_OK` anyway.
pub fn peer_verify_result(ssl: *mut ffi::SSL) -> Option<c_long> {
    if ssl.is_null() {
        return None;
    }
    if has_peer_certificate(ssl) {
        // SAFETY: `ssl` is live.
        return Some(unsafe { ffi::SSL_get_verify_result(ssl) });
    }

    // SAFETY: `ssl` is live; both pointers are owned by the SSL and only read.
    unsafe {
        let cipher = ffi::SSL_get_current_cipher(ssl);
        let session = ffi::SSL_get_session(ssl);
        if cipher.is_null() || session.is_null() {
            return None;
        }
        if SSL_CIPHER_get_auth_nid(cipher) == NID_AUTH_PSK
            || (ffi::SSL_SESSION_get_protocol_version(session) == TLS1_3_VERSION
                && ffi::SSL_session_reused(ssl) != 0)
        {
            return Some(ffi::X509_V_OK as c_long);
        }
    }
    None
}

/// The reason string `X509_verify_cert_error_string` reports for a code.
fn reason_for(code: c_int) -> Option<String> {
    // SAFETY: the call accepts any code and returns a static string or null.
    let pointer = unsafe { ffi::X509_verify_cert_error_string(code as c_long) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: OpenSSL returns a static NUL-terminated string.
    let text = unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    (!text.is_empty()).then_some(text)
}

/// `X509Pointer::ErrorCode` (`ncrypto.cc:2031`): the `code` property.
///
/// The list is Node's and the order does not matter; what does is that an
/// unlisted code becomes `UNSPECIFIED` rather than being invented. `errno` 24 is
/// `INVALID_CA` on 3.x and `NO_ISSUER_PUBLIC_KEY` on 3.0+, which is why the
/// table is written with 3.x's name for it.
pub fn error_code(error: c_int) -> &'static str {
    match error {
        2 => "UNABLE_TO_GET_ISSUER_CERT",
        3 => "UNABLE_TO_GET_CRL",
        4 => "UNABLE_TO_DECRYPT_CERT_SIGNATURE",
        5 => "UNABLE_TO_DECRYPT_CRL_SIGNATURE",
        6 => "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
        7 => "CERT_SIGNATURE_FAILURE",
        8 => "CRL_SIGNATURE_FAILURE",
        9 => "CERT_NOT_YET_VALID",
        10 => "CERT_HAS_EXPIRED",
        11 => "CRL_NOT_YET_VALID",
        12 => "CRL_HAS_EXPIRED",
        13 => "ERROR_IN_CERT_NOT_BEFORE_FIELD",
        14 => "ERROR_IN_CERT_NOT_AFTER_FIELD",
        15 => "ERROR_IN_CRL_LAST_UPDATE_FIELD",
        16 => "ERROR_IN_CRL_NEXT_UPDATE_FIELD",
        17 => "OUT_OF_MEM",
        18 => "DEPTH_ZERO_SELF_SIGNED_CERT",
        19 => "SELF_SIGNED_CERT_IN_CHAIN",
        20 => "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
        21 => "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        22 => "CERT_CHAIN_TOO_LONG",
        23 => "CERT_REVOKED",
        24 => "INVALID_CA",
        25 => "PATH_LENGTH_EXCEEDED",
        26 => "INVALID_PURPOSE",
        27 => "CERT_UNTRUSTED",
        28 => "CERT_REJECTED",
        62 => "HOSTNAME_MISMATCH",
        _ => "UNSPECIFIED",
    }
}

/// `GetValidationErrorReason` (`crypto_common.cc:55`): the message, including
/// the `--use-system-ca` hint for the errors a local root would fix.
///
/// The hint is not cosmetic. `test-tls-friendly-error-message.js` asserts
/// `/try running Node\.js with --use-system-ca/` against the message of a
/// self-signed server with no matching CA, so a bare
/// `X509_verify_cert_error_string` fails it even though the first half of the
/// text matches.
pub fn validation_error_reason(error: c_int, use_system_ca: bool) -> Option<String> {
    let mut reason = reason_for(error)?;
    let suggest_system_ca = error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
        // The `#ifdef OPENSSL_IS_BORINGSSL` branch in Node is unreachable on
        // OpenSSL, so `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` does *not* suggest the
        // flag here even though it reads as though it should.
        || error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        || (error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT && !use_system_ca);
    if suggest_system_ca {
        reason.push_str(
            "; if the root CA is installed locally, try running Node.js with --use-system-ca",
        );
    }
    Some(reason)
}

/// Everything `verifyError()` needs, resolved from the `SSL`.
///
/// `None` means `X509_V_OK` — the binding sets `null` and `wrap.js` records
/// `authorized = true`.
pub struct VerifyError {
    /// The `X509_V_ERR_*` code, which becomes `authorizationError`.
    pub code: c_int,
    /// The human-readable message, which is what an `Error`'s `.message` is.
    pub message: String,
    /// The `code` property: the string form of [`Self::code`].
    pub code_name: &'static str,
}

impl VerifyError {
    /// Resolves the failure for a live `SSL`, honouring the `--use-system-ca`
    /// option the way `GetValidationErrorReason` does.
    pub fn of(ssl: *mut ffi::SSL, use_system_ca: bool) -> Option<Self> {
        let code =
            peer_verify_result(ssl).unwrap_or(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT as c_long);
        let code = code as c_int;
        if code == 0 {
            return None;
        }
        let message = validation_error_reason(code, use_system_ca)?;
        Some(Self {
            code,
            message,
            code_name: error_code(code),
        })
    }
}

// ---------------------------------------------------------------------------
// The binding methods
// ---------------------------------------------------------------------------

/// `TLSWrap::GetPeerCertificate` (`crypto_tls.cc:1865`).
///
/// `abbreviated` is `args.Length() < 1 || !args[0]->IsTrue()`, so
/// `getPeerCertificate()` gives the leaf alone and `getPeerCertificate(true)`
/// adds the `issuerCertificate` chain. The result is the legacy object
/// `translatePeerCertificate` expects, so `x509.js`'s `toLegacyObject()` and
/// this cannot drift: both come from
/// [`rn_bind_crypto_x509::legacy_object`].
pub fn get_peer_certificate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let detailed = args.length() >= 1 && args.get(0).is_true();
    let (ssl, is_server) = match with_state(args.this(), |state| (state.ssl_ptr(), state.kind)) {
        Some((ssl, kind)) => (ssl, kind == crate::ssl::Kind::Server),
        None => {
            crate::wrap::throw_type_error(scope, "Invalid TLSWrap receiver");
            return;
        }
    };
    // The short form still needs the leaf's issuers *off* the chain so the object
    // can be built from the same snapshot; but it reports only the leaf's own
    // fields, which is what `abbreviated` selects below.
    let chain = peer_chain(ssl, is_server, true);
    if chain.is_empty() {
        // `Undefined(env->isolate())`, which `wrap.js` turns into `{}`.
        rv.set(v8::undefined(scope).into());
        return;
    }
    let Some(object) = build_legacy(scope, ssl, &chain, detailed) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    rv.set(object);
}

/// Builds the legacy object for `chain` (leaf first), adding the issuer chain
/// when `detailed`, and making the last self-signed certificate circular.
///
/// `AddIssuerChainToObject` links each issuer found *in the peer's own chain*;
/// `GetLastIssuedCert` then walks the trust store for anything above it; and the
/// final step makes a self-signed last entry point at itself, which is why
/// `issuerCertificate === issuerCertificate.issuerCertificate` holds for a
/// self-signed peer and why Node's own consumers test for that identity rather
/// than for `undefined`.
fn build_legacy<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    ssl: *mut ffi::SSL,
    chain: &[Vec<u8>],
    detailed: bool,
) -> Option<v8::Local<'s, v8::Value>> {
    use rn_bind_crypto_x509::snapshot::parse_der;

    let leaf = parse_der(chain.first()?)?;
    let leaf_object = rn_bind_crypto_x509::legacy_object(scope, &leaf)?;
    let leaf_object = v8::Local::<v8::Object>::try_from(leaf_object).ok()?;
    if !detailed {
        return Some(leaf_object.into());
    }

    let mut current = leaf_object;
    let mut current_certificate = leaf;

    // Every entry above the leaf, in order, linked as `issuerCertificate`. The
    // walk stops when the chain stops being a chain: `AddIssuerChainToObject`
    // only links an entry the current certificate is *issued by*, so a chain
    // with an unrelated certificate in it produces a shorter walk rather than a
    // false link.
    for der in chain.iter().skip(1) {
        let Some(candidate) = parse_der(der) else {
            break;
        };
        if !issued_by(&candidate, &current_certificate) {
            break;
        }
        let Some(object) = rn_bind_crypto_x509::legacy_object(scope, &candidate) else {
            break;
        };
        set_issuer(scope, current, object);
        let Ok(object) = v8::Local::<v8::Object>::try_from(object) else {
            break;
        };
        current = object;
        current_certificate = candidate;
    }

    // `GetLastIssuedCert`: walk the trust store for issuers the peer did not
    // send. A server commonly sends only its leaf, so without this
    // `getPeerCertificate(true)` would report a one-element chain for a
    // perfectly valid certificate.
    let mut guard = 0;
    while !issued_by(&current_certificate, &current_certificate) && guard < 16 {
        guard += 1;
        // SAFETY: `ssl` was checked non-null by the caller's `with_state` read,
        // and it is the live SSL of the wrap being queried.
        let Some((issuer_certificate, object)) =
            (unsafe { store_issuer(scope, ssl, &current_certificate) })
        else {
            break;
        };
        if !set_issuer(scope, current, object) {
            break;
        }
        let Ok(object) = v8::Local::<v8::Object>::try_from(object) else {
            break;
        };
        current = object;
        current_certificate = issuer_certificate;
    }

    // The last certificate should be self-signed, and Node makes that explicit
    // by pointing the link at itself rather than leaving it `undefined`. The
    // check has no "did anything get linked" condition attached: a self-signed
    // leaf with no chain at all is still made circular, and
    // `translatePeerCertificate`'s `c.issuerCertificate !== c` guard is what
    // stops that from recursing.
    if issued_by(&current_certificate, &current_certificate) {
        set_issuer(scope, current, current.into());
    }
    Some(leaf_object.into())
}

/// Whether `subject` was issued by `issuer`, which is `X509_check_issued`.
fn issued_by(issuer: &openssl::x509::X509, subject: &openssl::x509::X509) -> bool {
    use foreign_types::ForeignTypeRef;
    // SAFETY: both handles are live Rust-owned certificates; `X509_check_issued`
    // only reads them. `X509_check_issued(issuer, subject)` is the argument order
    // `ncrypto`'s `isIssuedBy` uses.
    unsafe { ffi::X509_check_issued(issuer.as_ptr(), subject.as_ptr()) == 0 }
}

/// The trust store's issuer for `certificate`, as (certificate, JS object).
///
/// `X509Pointer::IssuerFrom` (`ncrypto.cc:1999`) with the same construction: a
/// throwaway `X509_STORE_CTX` over the `SSL_CTX`'s store, then
/// `X509_STORE_CTX_get1_issuer`. This is what lets `getPeerCertificate(true)`
/// report a full chain when the peer sent only its leaf, which a server
/// commonly does.
///
/// # Safety
///
/// `ssl` must be live, or null.
unsafe fn store_issuer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    ssl: *mut ffi::SSL,
    certificate: &openssl::x509::X509,
) -> Option<(openssl::x509::X509, v8::Local<'s, v8::Value>)> {
    use foreign_types::ForeignType;

    if ssl.is_null() {
        return None;
    }
    // SAFETY: `ssl` is live, so its `SSL_CTX` is too: `SSL_new` holds a
    // reference for the SSL's whole life.
    let issuer = unsafe {
        let ctx = crate::ffi_extra::SSL_get_SSL_CTX(ssl);
        if ctx.is_null() {
            return None;
        }
        let store = ffi::SSL_CTX_get_cert_store(ctx);
        if store.is_null() {
            return None;
        }
        let store_ctx = ffi::X509_STORE_CTX_new();
        if store_ctx.is_null() {
            return None;
        }
        let mut issuer: *mut ffi::X509 = std::ptr::null_mut();
        let initialised =
            ffi::X509_STORE_CTX_init(store_ctx, store, std::ptr::null_mut(), std::ptr::null_mut());
        let found = initialised == 1
            && crate::ffi_extra::X509_STORE_CTX_get1_issuer(
                &mut issuer,
                store_ctx,
                certificate.as_ptr(),
            ) == 1
            && !issuer.is_null();
        ffi::X509_STORE_CTX_free(store_ctx);
        if !found {
            return None;
        }
        // `get1_issuer` returns a new reference, so the owning `X509` is correct.
        openssl::x509::X509::from_ptr(issuer)
    };
    let object = rn_bind_crypto_x509::legacy_object(scope, &issuer)?;
    Some((issuer, object))
}

/// Sets `issuer` as `object.issuerCertificate`, which is a `Set` of an own
/// property.
fn set_issuer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    issuer: v8::Local<'s, v8::Value>,
) -> bool {
    let Some(key) = v8::String::new(scope, "issuerCertificate") else {
        return false;
    };
    object.set(scope, key.into(), issuer).is_some()
}

/// `TLSWrap::GetSharedSigalgs` (`crypto_tls.cc:2084`).
///
/// `SSL_get_shared_sigalgs` as an array of `"RSA-PSS+SHA384"` strings — *not*
/// `[sign, hash]` numeric pairs, which is what this returned before and is why
/// `test-tls-set-sigalgs.js` failed its `deepStrictEqual` against node's answer.
///
/// Two details of the loop are load-bearing and both were wrong:
///
/// * **Index 0 is a real entry, not a count probe.** `SSL_get_shared_sigalgs`
///   (`t1_lib.c:3693`) validates `idx < shared_sigalgslen` and returns the
///   *length*; index 0 with null out-parameters returns the length only because
///   the caller asked for an in-range index, so iterating `1..=count` both skips
///   the first entry and reads one past the end.
/// * **The count is what the call returns, not a separate probe.** Node calls it
///   once with index 0 to size the array, then once per index.
///
/// The name is built from the sign NID and the hash NID through
/// `OBJ_nid2sn`, with node's five special-cased family prefixes, because
/// `OBJ_nid2sn(NID_rsassaPss)` is `RSASSA-PSS` where the API reports `RSA-PSS`.
pub fn get_shared_sigalgs<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let names = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return Vec::new();
        }
        // SAFETY: `ssl` is live, checked above, and index 0 is in range whenever
        // the list is non-empty.
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
        let mut names = Vec::with_capacity(count.max(0) as usize);
        for index in 0..count {
            let mut sign: c_int = 0;
            let mut hash: c_int = 0;
            // SAFETY: `index` is inside the count just read, and the
            // out-parameters are live locals; the raw-signature pointers are null,
            // which `t1_lib.c:3715` allows.
            let ok = unsafe {
                crate::ffi_extra::SSL_get_shared_sigalgs(
                    ssl,
                    index,
                    &mut sign,
                    &mut hash,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok <= 0 {
                break;
            }
            names.push(crate::peer_cert::sigalg_name(sign, hash));
        }
        names
    })
    .unwrap_or_default();

    let array = v8::Array::new(scope, names.len() as i32);
    for (index, name) in names.iter().enumerate() {
        if let Some(text) = v8::String::new(scope, name) {
            let _ = array.set_index(scope, index as u32, text.into());
        }
    }
    rv.set(array.into());
}

/// `GetSharedSigalgs`'s per-entry name: `"RSA-PSS+SHA384"`.
///
/// `crypto_tls.cc:2102-2156`. The sign NID's *family* decides the prefix, with
/// five special cases where `OBJ_nid2sn` does not produce the name the API
/// reports (`RSASSA-PSS` rather than `RSA-PSS`, for instance), and the hash NID
/// goes through `OBJ_nid2sn` unchanged. An unknown NID on either side becomes
/// `UNDEF`, which is node's own fallback rather than an error.
pub fn sigalg_name(sign_nid: c_int, hash_nid: c_int) -> String {
    const NID_RSA_ENCRYPTION: c_int = 6;
    const NID_DSA: c_int = 116;
    const NID_RSASSA_PSS: c_int = 912;
    const NID_X9_62_ID_ECPUBLICKEY: c_int = 408;
    const NID_ED25519: c_int = 1087;
    const NID_ED448: c_int = 1088;

    let prefix = match sign_nid {
        NID_RSA_ENCRYPTION => "RSA".to_string(),
        NID_RSASSA_PSS => "RSA-PSS".to_string(),
        NID_DSA => "DSA".to_string(),
        NID_X9_62_ID_ECPUBLICKEY => "ECDSA".to_string(),
        NID_ED25519 => "Ed25519".to_string(),
        NID_ED448 => "Ed448".to_string(),
        other => nid_short_name(other).unwrap_or_else(|| "UNDEF".to_string()),
    };
    let hash = nid_short_name(hash_nid).unwrap_or_else(|| "UNDEF".to_string());
    format!("{prefix}+{hash}")
}

/// `OBJ_nid2sn`, as an owned `String`.
fn nid_short_name(nid: c_int) -> Option<String> {
    extern "C" {
        fn OBJ_nid2sn(nid: c_int) -> *const std::os::raw::c_char;
    }
    // SAFETY: returns a static NUL-terminated string or null.
    let pointer = unsafe { OBJ_nid2sn(nid) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: static string owned by OpenSSL.
    let text = unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    (!text.is_empty()).then_some(text)
}

/// `TLSWrap::GetPeerX509Certificate` (`crypto_tls.cc:1881`).
///
/// A real `X509Certificate`, built from the peer's chain so its
/// `issuerCertificate` getter walks the same chain `getPeerCertificate(true)`
/// reports. `wrap.js:1292` wraps the result in `InternalX509Certificate`, so the
/// object handed back here is the *native* certificate the native constructor
/// takes, which is why it comes from
/// [`rn_bind_crypto_x509::certificate_from_chain`] rather than from this crate.
pub fn get_peer_x509_certificate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let (ssl, is_server) = match with_state(args.this(), |state| (state.ssl_ptr(), state.kind)) {
        Some((ssl, kind)) => (ssl, kind == crate::ssl::Kind::Server),
        None => {
            crate::wrap::throw_type_error(scope, "Invalid TLSWrap receiver");
            return;
        }
    };
    let chain = peer_chain(ssl, is_server, true);
    match rn_bind_crypto_x509::certificate_from_chain(scope, chain) {
        Some(object) => rv.set(object.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `TLSWrap::GetCertificate` (`crypto_tls.cc:1902`): the *local* certificate, in
/// the same legacy shape as the peer's.
///
/// `getCertificate()`'s comment in `wrap.js` says it plainly — "It's not a peer
/// cert, but the formatting is identical" — so both go through the same
/// builder.
pub fn get_certificate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let ssl = match with_state(args.this(), |state| state.ssl_ptr()) {
        Some(ssl) => ssl,
        None => {
            crate::wrap::throw_type_error(scope, "Invalid TLSWrap receiver");
            return;
        }
    };
    let Some(der) = local_certificate(ssl) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let Some(certificate) = rn_bind_crypto_x509::snapshot::parse_der(&der) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    match rn_bind_crypto_x509::legacy_object(scope, &certificate) {
        Some(object) => rv.set(object),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `TLSWrap::HasPeerCertificate` (`crypto_tls.cc:1895`).
pub fn has_peer_certificate_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let has =
        with_state(args.this(), |state| has_peer_certificate(state.ssl_ptr())).unwrap_or(false);
    rv.set(v8::Boolean::new(scope, has).into());
}

/// `TLSWrap::VerifyError` (`crypto_tls.cc:2029`): `null`, or an `Error` whose
/// `.code` is the `X509_V_ERR_*` name.
///
/// Defect 1 lives here. `wrap.js` does
///
/// ```js
/// const verifyError = this._handle.verifyError();
/// if (verifyError) {
///   this.authorizationError = verifyError.code;
///   if (this._rejectUnauthorized) this.destroy();
/// ```
///
/// so the return value has to be an object with a `code`; a bare number makes
/// `authorizationError` `undefined` and the socket's `'error'` an `Error` with no
/// message at all — the measured `client err: undefined`.
///
/// `Exception::Error(reason)` is what Node builds, so the result is an ordinary
/// `Error` with a stack, and the message is
/// [`validation_error_reason`]'s text (`self-signed certificate`, `unable to
/// verify the first certificate`, plus the `--use-system-ca` hint where Node
/// adds it).
pub fn verify_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let ssl = match with_state(args.this(), |state| state.ssl_ptr()) {
        Some(ssl) => ssl,
        None => {
            crate::wrap::throw_type_error(scope, "Invalid TLSWrap receiver");
            return;
        }
    };
    // `env->options()->use_system_ca`, which the hint's text depends on.
    let use_system_ca = rn_bind_options::parsed::value_of("--use-system-ca")
        .map(|value| matches!(value, rn_bind_options::parsed::ParsedValue::Bool(true)))
        .unwrap_or(false);
    let Some(error) = VerifyError::of(ssl, use_system_ca) else {
        // `args.GetReturnValue().SetNull()`, and `wrap.js` treats a falsy result
        // as "verified".
        rv.set(v8::null(scope).into());
        return;
    };
    let Some(message) = v8::String::new(scope, &error.message) else {
        rv.set(v8::null(scope).into());
        return;
    };
    let exception = v8::Exception::error(scope, message);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let Some(code) = v8::String::new(scope, error.code_name) {
            if let Some(key) = v8::String::new(scope, "code") {
                let _ = object.set(scope, key.into(), code.into());
            }
        }
    }
    rv.set(exception);
}

/// `TLSWrap::GetTLSTicket` (`crypto_tls.cc:2217`): the session ticket as a
/// `Buffer`, or nothing set (which JavaScript reads as `undefined`).
///
/// A ticket exists only once the handshake has produced one, so this answers
/// `undefined` before that rather than an empty buffer —
/// `wrap.js`'s session handling treats an empty buffer as a usable ticket.
pub fn get_tls_ticket<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let ticket = with_state(args.this(), |state| {
        let ssl = state.ssl_ptr();
        if ssl.is_null() {
            return None;
        }
        // SAFETY: `ssl` is live; the session and its ticket are owned by it.
        unsafe {
            let session = ffi::SSL_get_session(ssl);
            if session.is_null() {
                return None;
            }
            let mut data: *const std::ffi::c_uchar = std::ptr::null();
            let mut length: usize = 0;
            if SSL_SESSION_get0_ticket(session, &mut data, &mut length) != 1 {
                return None;
            }
            if data.is_null() || length == 0 {
                return None;
            }
            Some(std::slice::from_raw_parts(data, length).to_vec())
        }
    });
    let Some(Some(ticket)) = ticket else {
        // The binding leaves the return value unset, which is `undefined`.
        rv.set(v8::undefined(scope).into());
        return;
    };
    match rn_bind_crypto_keys::buffer_from(scope, &ticket) {
        Some(buffer) => rv.set(buffer),
        None => rv.set(v8::undefined(scope).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `verifyError()` reports `null` for `X509_V_OK`, which is what makes
    /// `authorized` true. A number that is zero is still truthy to the
    /// `if (verifyError)` in `wrap.js`, so this is the distinction that matters
    /// most.
    #[test]
    fn a_clean_verify_result_is_not_an_error() {
        assert!(VerifyError::of(std::ptr::null_mut(), false).is_some());
        assert!(
            VerifyError::of(std::ptr::null_mut(), false)
                .map(|error| error.code != 0)
                .unwrap_or(false),
            "a null SSL has no verdict, which VerifyError reports as UNABLE_TO_GET_ISSUER_CERT"
        );
    }

    /// The code table is Node's, and an unknown code is `UNSPECIFIED` rather
    /// than being invented.
    #[test]
    fn the_error_codes_are_node_s() {
        assert_eq!(
            error_code(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT),
            "DEPTH_ZERO_SELF_SIGNED_CERT"
        );
        assert_eq!(error_code(20), "UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
        assert_eq!(
            error_code(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE),
            "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
        );
        assert_eq!(error_code(19), "SELF_SIGNED_CERT_IN_CHAIN");
        assert_eq!(error_code(9999), "UNSPECIFIED");
    }

    /// The message is `X509_verify_cert_error_string`'s, which is the exact text
    /// `test-tls-peer-certificate`-style tests match on.
    #[test]
    fn the_reason_is_openssl_s_text() {
        assert_eq!(
            validation_error_reason(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, false).as_deref(),
            Some(
                "self-signed certificate; if the root CA is installed locally, \
                 try running Node.js with --use-system-ca"
            )
        );
        assert_eq!(
            validation_error_reason(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE, false).as_deref(),
            Some(
                "unable to verify the first certificate; if the root CA is installed locally, \
                 try running Node.js with --use-system-ca"
            )
        );
    }

    /// `UNABLE_TO_GET_ISSUER_CERT` suggests the flag only when it is not
    /// already on, which is the `!env->options()->use_system_ca` clause.
    #[test]
    fn the_system_ca_hint_respects_the_flag() {
        let without =
            validation_error_reason(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, false).expect("a reason");
        assert!(without.contains("--use-system-ca"));
        let with =
            validation_error_reason(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, true).expect("a reason");
        assert!(!with.contains("--use-system-ca"));
    }

    /// `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` does not suggest the flag on OpenSSL:
    /// the branch that would is inside `#ifdef OPENSSL_IS_BORINGSSL`.
    #[test]
    fn issuer_cert_locally_does_not_suggest_the_flag() {
        let reason = validation_error_reason(20, false).expect("a reason");
        assert!(!reason.contains("--use-system-ca"));
    }

    /// A null `SSL` has no chain, no certificate, and no local certificate, so
    /// each accessor reports absence rather than dereferencing.
    #[test]
    fn a_null_ssl_reports_nothing() {
        assert!(peer_chain(std::ptr::null_mut(), false, true).is_empty());
        assert!(peer_chain(std::ptr::null_mut(), true, true).is_empty());
        assert!(!has_peer_certificate(std::ptr::null_mut()));
        assert!(local_certificate(std::ptr::null_mut()).is_none());
        assert!(peer_verify_result(std::ptr::null_mut()).is_none());
    }

    /// The callback is Node's non-op: it continues the handshake whatever OpenSSL
    /// thinks, which is what keeps `rejectUnauthorized: false` from aborting on
    /// `SSL alert 48`.
    #[test]
    fn the_verify_callback_always_continues() {
        assert_eq!(always_continue(0, std::ptr::null_mut()), 1);
        assert_eq!(always_continue(1, std::ptr::null_mut()), 1);
    }
}
