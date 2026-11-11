//! `SecureContext` for `internalBinding('crypto')`.
//!
//! `src/crypto/crypto_context.cc` is the translation unit this mirrors. The
//! class lands on the **`crypto`** namespace rather than forming one of its own,
//! because `src/node_crypto.cc` aggregates a dozen `Initialize` calls onto one
//! `target` and `SecureContext` is one of them. This crate therefore exports
//! [`install_classes`] and `rn-bind-crypto` calls it, exactly as the DH, cipher
//! and keys slices do.
//!
//! # What the JavaScript does with this class
//!
//! `lib/internal/tls/common.js:88` builds it, then `configSecureContext` in
//! `lib/internal/tls/secure-context.js` configures it:
//!
//! ```text
//! this.context = new NativeSecureContext();
//! this.context.init(secureProtocol, minV, maxV);
//! if (secureOptions) this.context.setOptions(secureOptions);
//! ```
//!
//! Then `configSecureContext(c.context, options)` calls up to 19 methods, and
//! `lib/internal/tls/wrap.js:832` brand-checks the result with
//! `instanceof NativeSecureContext` before handing it to `tls_wrap.wrap`.
//!
//! # Scope of this landing
//!
//! This is the **shell** — the milestone the plan defines for slice S4. It makes
//! the class exist, constructible, and `instanceof`-checkable, implements the
//! `SSL_CTX` surface for real, and makes every unimplemented method **throw**
//! rather than silently succeed. A stub that returns `undefined` moves the
//! failure into `TLSWrap`, where it is much harder to attribute; a stub that
//! throws names itself.
//!
//! [`stubs`] is the list of what throws and why. The short version: the
//! certificate-compression path, the PKCS#12 loader, the ticket-key HMAC
//! callback, and the bundled/extra root store are not implemented. Everything in
//! `configSecureContext`'s default path — ciphers, protocols, CA certs, cert,
//! key, CRL, session settings, ticket keys, ECDH curve and DH parameters — is
//! real OpenSSL work against a real `SSL_CTX`.
//!
//! # State ownership
//!
//! The `Context` lives in a heap allocation behind an internal field, freed by a
//! `Weak::with_guaranteed_finalizer`, the same shape the DH and keys crates use.
//! V8's garbage collector is the only thing that decides when a context dies, so
//! a finalizer is the only correct place to release the `SSL_CTX`.
//!
//! The entry point is deliberately not named `register*`: `tools/regen-bindings.sh`
//! treats a `register` declaration as a namespace provider, and this crate does
//! not provide a namespace.

use std::cell::RefCell;

use rn_v8_sys::v8;

pub mod context;
pub mod ffi_extra;

#[cfg(test)]
mod tests;

pub use context::{Context, ContextError};

/// The internal field holding the `*mut RefCell<Context>`.
const CONTEXT_STATE_FIELD: i32 = 0;

/// `SecureContext::kInternalFieldCount` is 1 in Node: the `BaseObject` pointer.
const INTERNAL_FIELD_COUNT: usize = 1;

/// Installs `SecureContext` onto `target`, which is the `crypto` namespace.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let class = build_class(scope)?;
    set_property(scope, target, "SecureContext", class)
}

/// The members this crate installs, for the parent crate's `MEMBERS` list.
pub const MEMBERS: &[&str] = &["SecureContext"];

/// The prototype methods this landing installs but does **not** implement, each
/// with the reason and the exception it throws.
///
/// This is the honest counterpart to a `DEFERRED` list: the methods exist (so
/// `configSecureContext`'s calls resolve and a `typeof` check passes) but calling
/// one throws `ERR_CRYPTO_UNSUPPORTED_OPERATION` instead of pretending to work.
/// Anything not named here, and not in [`NAMESPACE_STUBS`], is real OpenSSL work
/// against a real `SSL_CTX`.
///
/// The distinction between this list and [`NAMESPACE_STUBS`] matters and cost a
/// test failure to get right: `SecureContext::Initialize` in `crypto_context.cc`
/// installs six **namespace** members (`getBundledRootCertificates`,
/// `getSystemCACertificates`, `getExtraCACertificates`, `resetRootCertStore`,
/// `getUserRootCertificates`, `startLoadingCertificatesOffThread`) beside the
/// constructor, and it is only `GetConstructorTemplate` that installs prototype
/// methods. A namespace member listed here would be a method that does not exist,
/// which is exactly what the first version of this got wrong.
pub const STUBS: &[(&str, &str)] = &[
    (
        "setCertificateCompression",
        "RFC 8879 certificate compression needs SSL_CTX_set1_cert_comp_preference \
         plus the pre-compressed-cert cache that SNI context switching replays. \
         Node gates it on NODE_OPENSSL_HAS_CERT_COMP; it is not wired here.",
    ),
    (
        "loadPKCS12",
        "The .pfx/.p12 path needs PKCS12_parse plus the cert/key/CA installation \
         sequence. The keys slice owns the PKCS#12 parser, so this lands with it.",
    ),
    (
        "enableTicketKeyCallback",
        "The ticket-key callback hands OpenSSL's HMAC/AES state to a JavaScript \
         function, which needs the re-entrancy guard from the tls_wrap slice. \
         Without it a callback here would re-enter SSL_do_handshake.",
    ),
];

/// The `crypto` namespace members `crypto_context.cc` installs that this landing
/// does **not** install at all.
///
/// These are not stubs on the class: they are separate functions on the
/// `internalBinding('crypto')` object, and they are the root-certificate-store
/// surface. They are listed rather than installed because installing a throwing
/// one would make `lib/tls.js` fail at module scope — it destructures
/// `getCertificateCompressionAlgorithms` there — while a missing member only
/// fails a caller that asks for it. `rn-bind-crypto`'s `DEFERRED` list already
/// names most of them; the coordinator's `install.rs` edit is where they stay
/// declared rather than here.
pub const NAMESPACE_STUBS: &[(&str, &str)] = &[
    (
        "getBundledRootCertificates",
        "Needs the bundled root blob, which is not in this tree; only the system \
         store is loaded by addRootCerts.",
    ),
    (
        "getSystemCACertificates",
        "Same root-store surface as getBundledRootCertificates.",
    ),
    (
        "getExtraCACertificates",
        "Same root-store surface as getBundledRootCertificates.",
    ),
    (
        "resetRootCertStore",
        "Same root-store surface as getBundledRootCertificates.",
    ),
    (
        "getUserRootCertificates",
        "Same root-store surface as getBundledRootCertificates.",
    ),
    (
        "startLoadingCertificatesOffThread",
        "Needs a threadpool and the bundled root blob; the keys/x509 slices own \
         the asynchronous certificate loading.",
    ),
];

// ---------------------------------------------------------------------------
// The constructor and its methods
// ---------------------------------------------------------------------------

/// `new SecureContext()`.
///
/// Node's `New` does nothing but allocate the `BaseObject`; every field starts
/// empty and `init` fills them in. The context is created here so the internal
/// field is valid immediately, which makes `getTicketKeys()` before `init` report
/// `NotInitialised` from the state rather than reading a null pointer.
fn constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this = args.this();
    let pointer = Box::into_raw(Box::new(RefCell::new(Context::default())));
    this.set_aligned_pointer_in_internal_field(
        CONTEXT_STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        this,
        Box::new(move || {
            let pointer = address as *mut RefCell<Context>;
            // SAFETY: allocated by `constructor` for this object alone, and this
            // finalizer is the only thing that frees it. `Context::drop` releases
            // the `SSL_CTX` if `close()` did not.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    rv.set(this.into());
}

/// Runs `body` with the object's `Context`, or reports a bad receiver.
///
/// A receiver that is not a `SecureContext` gets the error Node's
/// `ASSIGN_OR_RETURN_UNWRAP` produces, rather than a panic. A re-entrant borrow
/// cannot happen because nothing in this crate calls back into V8 while holding
/// it.
///
/// # Why the internal-field count is checked
///
/// `get_aligned_pointer_from_internal_field` reads raw storage at a fixed offset
/// into the object's embedder fields. Called on an object that has *no* internal
/// fields it does not return null — it reads whatever bytes are at that offset,
/// which for a prototype object happened to be a misaligned address and aborted
/// the process:
///
/// ```text
/// misaligned pointer dereference: address must be a multiple of 0x8 but is 0x1a6ad3219149
/// ```
///
/// That is reached by reading `SecureContext.prototype._external`, which a real
/// `node` answers with a `TypeError` from the accessor's `Signature` guard. The
/// count check is this crate's equivalent guard, and it is load-bearing: without
/// it a legal JavaScript expression crashes the process instead of throwing.
fn with_state<R>(this: v8::Local<v8::Object>, body: impl FnOnce(&mut Context) -> R) -> Option<R> {
    // The prototype, and anything else not created by `constructor`, has no
    // embedder fields, so field 0 is not a pointer and must not be read.
    if this.internal_field_count() < INTERNAL_FIELD_COUNT {
        return None;
    }
    // SAFETY: the object has at least one internal field, and the only writer of
    // field 0 is `constructor`, which stores a `*mut RefCell<Context>` there.
    // Nothing but the object's finalizer clears or replaces it.
    let pointer = unsafe { this.get_aligned_pointer_from_internal_field(CONTEXT_STATE_FIELD, 0) }
        as *mut RefCell<Context>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above, and the finalizer runs only once the object is
    // unreachable, which cannot happen while `this` is a live local.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

/// `init(secureProtocol, minV, maxV)`.
///
/// `secureProtocol` is `undefined` or a string; the versions are int32. Node
/// `CHECK`s the types, so a wrong one is a `TypeError` here too rather than a
/// silent coercion (`AGENTS.md`: a binding that coerces hides the caller's bug).
fn init(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let protocol = args.get(0);
    let secure_protocol = if protocol.is_undefined() || protocol.is_null() {
        None
    } else if let Some(text) = string_of(scope, protocol) {
        Some(text)
    } else {
        throw_type_error(scope, "secureProtocol must be a string");
        return;
    };

    let Some(min_version) = int32_of(args.get(1)) else {
        throw_type_error(scope, "minVersion must be an int32");
        return;
    };
    let Some(max_version) = int32_of(args.get(2)) else {
        throw_type_error(scope, "maxVersion must be an int32");
        return;
    };

    let result = with_state(args.this(), |context| {
        context.init(secure_protocol.as_deref(), min_version, max_version)
    });
    match result {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// Installs one method that takes no arguments and returns nothing.
macro_rules! void_method {
    ($name:ident, $body:expr) => {
        fn $name(
            scope: &mut v8::PinScope<'_, '_>,
            args: v8::FunctionCallbackArguments<'_>,
            _rv: v8::ReturnValue,
        ) {
            let body: fn(&mut Context) -> Result<(), ContextError> = $body;
            match with_state(args.this(), body) {
                Some(Ok(())) => {}
                Some(Err(error)) => throw_context_error(scope, &error),
                None => throw_type_error(scope, "Invalid SecureContext receiver"),
            }
        }
    };
}

void_method!(add_root_certs, |context: &mut Context| context
    .add_root_certs());
void_method!(set_allow_partial_trust_chain, |context: &mut Context| {
    context.set_allow_partial_trust_chain()
});

/// `setCiphers(list)`.
fn set_ciphers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(list) = required_string(scope, args.get(0), "ciphers") else {
        return;
    };
    match with_state(args.this(), |context| context.set_ciphers(&list)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setCipherSuites(list)`.
fn set_cipher_suites(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(list) = required_string(scope, args.get(0), "cipherSuites") else {
        return;
    };
    match with_state(args.this(), |context| context.set_cipher_suites(&list)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setSigalgs(list)`.
fn set_sigalgs(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(list) = required_string(scope, args.get(0), "sigalgs") else {
        return;
    };
    match with_state(args.this(), |context| context.set_sigalgs(&list)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setECDHCurve(curve)`.
fn set_ecdh_curve(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(curve) = required_string(scope, args.get(0), "ecdhCurve") else {
        return;
    };
    match with_state(args.this(), |context| context.set_ecdh_curve(&curve)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setDHParam(dhparam)`.
///
/// The JavaScript passes `true` for `"auto"` and a string/Buffer for explicit
/// PEM, which is what `crypto_context.cc:2080` branches on. The return value is
/// the `SecurityWarning` string for sub-2048-bit parameters, which
/// `configSecureContext` feeds to `process.emitWarning`.
fn set_dh_param(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = args.get(0);
    let result = if value.is_true() {
        with_state(args.this(), |context| context.set_dh_param_auto())
    } else if let Some(pem) = bytes_of(value) {
        with_state(args.this(), |context| context.set_dh_param_pem(&pem))
    } else {
        throw_type_error(scope, "dhparam must be true, a string or a buffer");
        return;
    };

    match result {
        Some(Ok(warning)) => {
            if let Some(warning) = warning {
                if let Some(text) = v8::String::new(scope, &warning) {
                    rv.set(text.into());
                }
            }
        }
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setMinProto(version)`.
fn set_min_proto(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(version) = version_of(scope, args.get(0)) else {
        return;
    };
    match with_state(args.this(), |context| context.set_min_proto(version)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setMaxProto(version)`.
fn set_max_proto(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(version) = version_of(scope, args.get(0)) else {
        return;
    };
    match with_state(args.this(), |context| context.set_max_proto(version)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `getMinProto()`.
fn get_min_proto(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match with_state(args.this(), |context| context.min_proto()) {
        Some(Ok(version)) => rv.set(v8::Integer::new(scope, version).into()),
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `getMaxProto()`.
fn get_max_proto(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match with_state(args.this(), |context| context.max_proto()) {
        Some(Ok(version)) => rv.set(v8::Integer::new(scope, version).into()),
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setOptions(options)`.
fn set_options(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = args.get(0);
    let Ok(number) = v8::Local::<v8::Number>::try_from(value) else {
        throw_type_error(scope, "options must be a number");
        return;
    };
    let options = number.value() as i64;
    match with_state(args.this(), |context| context.set_options(options)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setSessionIdContext(value)`.
fn set_session_id_context(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(value) = required_string(scope, args.get(0), "sessionIdContext") else {
        return;
    };
    match with_state(args.this(), |context| {
        context.set_session_id_context(&value)
    }) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setSessionTimeout(seconds)`.
fn set_session_timeout(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(seconds) = int32_of(args.get(0)) else {
        throw_type_error(scope, "sessionTimeout must be an int32");
        return;
    };
    match with_state(args.this(), |context| context.set_session_timeout(seconds)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setCert(cert)`.
fn set_cert(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(pem) = byte_source(scope, args.get(0), "cert") else {
        return;
    };
    match with_state(args.this(), |context| context.set_cert(&pem)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setKey(key[, passphrase])`.
fn set_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(pem) = byte_source(scope, args.get(0), "key") else {
        return;
    };
    let passphrase_value = args.get(1);
    let passphrase = if passphrase_value.is_undefined() || passphrase_value.is_null() {
        None
    } else if let Some(text) = string_of(scope, passphrase_value) {
        Some(text)
    } else {
        throw_type_error(scope, "passphrase must be a string");
        return;
    };
    match with_state(args.this(), |context| {
        context.set_key(&pem, passphrase.as_deref())
    }) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `addCACert(cert)`.
fn add_ca_cert(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(pem) = byte_source(scope, args.get(0), "ca") else {
        return;
    };
    match with_state(args.this(), |context| context.add_ca_cert(&pem)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `addCRL(crl)`.
fn add_crl(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(pem) = byte_source(scope, args.get(0), "crl") else {
        return;
    };
    match with_state(args.this(), |context| context.add_crl(&pem)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `getTicketKeys()` returns a 48-byte `Buffer`.
fn get_ticket_keys(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let result = with_state(args.this(), |context| {
        context.ticket_keys().map(|keys| keys.to_vec())
    });
    match result {
        Some(Ok(bytes)) => match buffer_from(scope, &bytes) {
            Ok(buffer) => rv.set(buffer),
            Err(error) => throw(scope, error),
        },
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `setTicketKeys(keys)`.
fn set_ticket_keys(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(bytes) = bytes_of(args.get(0)) else {
        throw_type_error(scope, "ticketKeys must be a Buffer");
        return;
    };
    let Ok(keys) = <[u8; 48]>::try_from(bytes.as_slice()) else {
        throw_coded(
            scope,
            &format!(
                "The argument 'ticketKeys' must be exactly 48 bytes. Received {}",
                bytes.len()
            ),
            "ERR_INVALID_ARG_VALUE",
        );
        return;
    };
    match with_state(args.this(), |context| context.set_ticket_keys(&keys)) {
        Some(Ok(())) => rv.set(v8::Boolean::new(scope, true).into()),
        Some(Err(error)) => throw_context_error(scope, &error),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `getCertificate()` returns the leaf certificate as DER, or `null`.
fn get_certificate(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match with_state(args.this(), |context| context.certificate_der()) {
        Some(Some(der)) => match buffer_from(scope, &der) {
            Ok(buffer) => rv.set(buffer),
            Err(error) => throw(scope, error),
        },
        Some(None) => rv.set(v8::null(scope).into()),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `getIssuer()` returns the issuer certificate as DER, or `null`.
fn get_issuer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match with_state(args.this(), |context| context.issuer_der()) {
        Some(Some(der)) => match buffer_from(scope, &der) {
            Ok(buffer) => rv.set(buffer),
            Err(error) => throw(scope, error),
        },
        Some(None) => rv.set(v8::null(scope).into()),
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// `close()` releases the `SSL_CTX`. Idempotent.
fn close(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // A bad receiver is not an error here: `close()` is called from a
    // `once('close')` handler in `wrap.js` where throwing would turn a teardown
    // into a second failure.
    let _ = with_state(args.this(), |context| context.close());
}

/// `_external` reads the `SSL_CTX` address.
///
/// Node returns a `v8::External` wrapping the raw pointer, and a real `node`
/// makes that observable: the value is an object whose `constructor` is
/// `undefined` and which cannot be converted to a primitive. Returning the
/// address as a `BigInt` would be a different type with different observable
/// behaviour, so it returns a real `External` here. Nothing in `lib/**` reads it;
/// `tls_wrap` gets the context through the internal field, not through this
/// property, so its only job is to be the same shape Node's is.
fn external(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match with_state(args.this(), |context| context.external_pointer()) {
        Some(address) => {
            // `External::new` takes a `*mut c_void`; `0` for a closed context is
            // a null `External`, which is what an `SSL_CTX` that has been freed
            // has become. It is not dereferenced here or anywhere in this crate.
            let value = v8::External::new(scope, address as *mut std::os::raw::c_void);
            rv.set(value.into());
        }
        None => throw_type_error(scope, "Invalid SecureContext receiver"),
    }
}

/// One method that is deliberately not implemented: it throws.
///
/// See [`stubs`] for why each one is missing. The exception carries
/// `ERR_CRYPTO_UNSUPPORTED_OPERATION`, the code Node itself uses for a feature
/// the linked OpenSSL build does not provide, so a caller that checks for it
/// takes the same path it would on a build without the feature.
macro_rules! stub_method {
    ($name:ident, $method:literal, $reason:literal) => {
        fn $name(
            scope: &mut v8::PinScope<'_, '_>,
            _args: v8::FunctionCallbackArguments<'_>,
            _rv: v8::ReturnValue,
        ) {
            throw_coded(
                scope,
                concat!($method, " is not implemented in this build: ", $reason),
                "ERR_CRYPTO_UNSUPPORTED_OPERATION",
            );
        }
    };
}

stub_method!(
    set_certificate_compression,
    "setCertificateCompression",
    "certificate compression is not wired to the OpenSSL bindings here."
);
stub_method!(
    load_pkcs12,
    "loadPKCS12",
    "the PKCS#12 loader lands with the keys slice."
);
stub_method!(
    enable_ticket_key_callback,
    "enableTicketKeyCallback",
    "the ticket-key callback needs the tls_wrap re-entrancy guard."
);

// ---------------------------------------------------------------------------
// Class construction
// ---------------------------------------------------------------------------

/// Builds the `SecureContext` constructor and its prototype.
///
/// The method set is Node's exactly: `Crypto_context.cc:1312-1343` installs 27
/// prototype methods and the `_external` accessor, and every one of them is here.
/// A method Node has that this omitted would make `configSecureContext` throw
/// `TypeError: context.<name> is not a function`, which is a different failure
/// from a stub's explicit error and harder to attribute.
fn build_class<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELD_COUNT);
    let prototype = template.prototype_template(scope);

    macro_rules! install_methods {
        ($($name:literal => $callback:path),* $(,)?) => {
            $(
                {
                    let method = v8::FunctionTemplate::builder($callback).build(scope);
                    let Some(key) = v8::String::new(scope, $name) else {
                        return Err(format!("cannot allocate the {} property name", $name));
                    };
                    prototype.set(key.into(), method.into());
                }
            )*
        };
    }

    install_methods!(
        "init" => init,
        "setKey" => set_key,
        "setCert" => set_cert,
        "addCACert" => add_ca_cert,
        "setAllowPartialTrustChain" => set_allow_partial_trust_chain,
        "addCRL" => add_crl,
        "addRootCerts" => add_root_certs,
        "setCipherSuites" => set_cipher_suites,
        "setCiphers" => set_ciphers,
        "setSigalgs" => set_sigalgs,
        "setECDHCurve" => set_ecdh_curve,
        "setDHParam" => set_dh_param,
        "setMaxProto" => set_max_proto,
        "setMinProto" => set_min_proto,
        "getMaxProto" => get_max_proto,
        "getMinProto" => get_min_proto,
        "setOptions" => set_options,
        "setSessionIdContext" => set_session_id_context,
        "setSessionTimeout" => set_session_timeout,
        "setCertificateCompression" => set_certificate_compression,
        "close" => close,
        "loadPKCS12" => load_pkcs12,
        "setTicketKeys" => set_ticket_keys,
        "enableTicketKeyCallback" => enable_ticket_key_callback,
        "getTicketKeys" => get_ticket_keys,
        "getCertificate" => get_certificate,
        "getIssuer" => get_issuer,
    );

    // The `_external` accessor. Node installs it with `SetAccessorProperty`, so
    // reading `ctx._external` runs the getter; a real `node` reports an object
    // whose `constructor` is undefined, which is what `External` gives. It is
    // installed as a *getter*, not as a prototype method, because
    // `typeof prototype._external` must be `undefined` — the property lives on
    // the prototype as an accessor, not as a function value.
    {
        let getter = v8::FunctionTemplate::builder(external).build(scope);
        let Some(key) = v8::String::new(scope, "_external") else {
            return Err("cannot allocate the _external property name".to_string());
        };
        // `DONT_DELETE` without `READ_ONLY`: Node's descriptor is
        // `{ get, enumerable: true, configurable: false }`, which is
        // `DONT_DELETE` alone. A real `node` reports exactly that, verified with
        // `Object.getOwnPropertyDescriptor` on a live context.
        prototype.set_accessor_property(
            key.into(),
            Some(getter),
            None,
            v8::PropertyAttribute::DONT_DELETE,
        );
    }

    // The class name has to be set *before* `get_function`, because V8 refuses
    // `SetClassName` on a template that has already been instantiated. The first
    // version of this set the constants through `get_function` in a loop and
    // then named the class, which aborted the process with
    // `FunctionTemplate already instantiated`.
    let Some(class_name) = v8::String::new(scope, "SecureContext") else {
        return Err("cannot allocate the SecureContext class name".to_string());
    };
    template.set_class_name(class_name);

    let Some(function) = template.get_function(scope) else {
        return Err("cannot allocate the SecureContext constructor".to_string());
    };
    let Some(function_name) = v8::String::new(scope, "SecureContext") else {
        return Err("cannot allocate the SecureContext function name".to_string());
    };
    function.set_name(function_name);

    // The five ticket-key index constants. `lib/**` does not read them, but they
    // are part of the class Node installs and a test can observe them.
    for (name, value) in [
        ("kTicketKeyReturnIndex", 0i32),
        ("kTicketKeyHMACIndex", 1),
        ("kTicketKeyAESIndex", 2),
        ("kTicketKeyNameIndex", 3),
        ("kTicketKeyIVIndex", 4),
    ] {
        let Some(key) = v8::String::new(scope, name) else {
            return Err(format!("cannot allocate the {name} property name"));
        };
        function.set(scope, key.into(), v8::Integer::new(scope, value).into());
    }

    Ok(function.into())
}

// ---------------------------------------------------------------------------
// Argument marshalling
// ---------------------------------------------------------------------------

/// Reads a JavaScript string, or throws a `TypeError` naming the argument.
fn required_string(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
    name: &str,
) -> Option<String> {
    match string_of(scope, value) {
        Some(text) => Some(text),
        None => {
            throw_type_error(scope, &format!("{name} must be a string"));
            None
        }
    }
}

/// Reads a version argument. Node `CHECK`s `IsInt32`.
fn version_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<i32> {
    let version = int32_of(value);
    if version.is_none() {
        throw_type_error(scope, "version must be an int32");
    }
    version
}

/// Reads a PEM argument, which the JavaScript passes as a string or a view.
fn byte_source(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
    name: &str,
) -> Option<Vec<u8>> {
    if let Some(text) = string_of(scope, value) {
        return Some(text.into_bytes());
    }
    if let Some(bytes) = bytes_of(value) {
        return Some(bytes);
    }
    throw_type_error(
        scope,
        &format!("{name} must be a string, Buffer, TypedArray or DataView"),
    );
    None
}

/// Copies the bytes behind a `Buffer`, typed array, `DataView` or `ArrayBuffer`.
fn bytes_of(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let length = view.byte_length();
        let mut bytes = vec![0u8; length];
        let copied = view.copy_contents(&mut bytes);
        bytes.truncate(copied);
        return Some(bytes);
    }
    let buffer = v8::Local::<v8::ArrayBuffer>::try_from(value).ok()?;
    let store = buffer.get_backing_store();
    let length = buffer.byte_length();
    let mut bytes = vec![0u8; length];
    if length > 0 {
        // `data()` on a non-shared backing store is contiguous; the length came
        // from the buffer itself, so the copy cannot overrun.
        let data = store.data()?;
        // SAFETY: `data` points at `length` bytes owned by `store`, which is
        // alive for this call.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), length);
        }
    }
    Some(bytes)
}

/// Reads a JavaScript string as UTF-8, or `None` for a non-string.
fn string_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<String> {
    let text = v8::Local::<v8::String>::try_from(value).ok()?;
    Some(text.to_rust_string_lossy(scope))
}

/// Reads an int32, or `None` for anything else.
///
/// `v8::Value::to_int32` would coerce, which `CHECK(args[0]->IsInt32())` does
/// not; the try_from is the difference.
fn int32_of(value: v8::Local<v8::Value>) -> Option<i32> {
    v8::Local::<v8::Int32>::try_from(value)
        .ok()
        .map(|value| value.value())
}

/// Emits bytes as a `Buffer`, which is what `getTicketKeys` and the cert
/// accessors return.
fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Result<v8::Local<'s, v8::Value>, &'static str> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice())
            .make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let buffer = buffer_constructor(scope).ok_or("global Buffer is not a function")?;
    let from_key = v8::String::new(scope, "from").ok_or("cannot allocate 'from'")?;
    let from = buffer
        .get(scope, from_key.into())
        .ok_or("Buffer.from lookup failed")?;
    let from =
        v8::Local::<v8::Function>::try_from(from).map_err(|_| "Buffer.from is not a function")?;
    let start = v8::Integer::new(scope, 0);
    let length = v8::Integer::new(scope, bytes.len() as i32);
    let receiver = buffer.into();
    let called = from
        .call(
            scope,
            receiver,
            &[array_buffer.into(), start.into(), length.into()],
        )
        .ok_or("Buffer.from threw")?;
    if !called.is_object() {
        return Err("Buffer.from returned a non-object");
    }
    Ok(called)
}

/// The global `Buffer` object.
///
/// Returned as an `Object` rather than a `Function`: the real `Buffer` is
/// callable, but nothing here calls it, and requiring callability would reject a
/// usable shape.
fn buffer_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let value = global.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Sets a property on an object, returning a `String` error on failure.
fn set_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    object.set(scope, key.into(), value);
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Turns a [`ContextError`] into the closest Node exception.
fn throw_context_error(scope: &mut v8::PinScope<'_, '_>, error: &ContextError) {
    match error {
        ContextError::InvalidProtocolMethod(message) => {
            throw_coded(scope, message, "ERR_TLS_INVALID_PROTOCOL_METHOD")
        }
        ContextError::InvalidProtocolVersion(version) => throw_coded(
            scope,
            &error.to_string(),
            if *version == 0 {
                "ERR_TLS_INVALID_PROTOCOL_VERSION"
            } else {
                "ERR_CRYPTO_OPERATION_FAILED"
            },
        ),
        ContextError::Ciphers(_)
        | ContextError::EcdhCurve(_)
        | ContextError::Sigalgs(_)
        | ContextError::SessionIdContext(_)
        | ContextError::Install(_) => {
            throw_coded(scope, &error.to_string(), "ERR_CRYPTO_OPERATION_FAILED")
        }
        ContextError::Pem(_) => {
            throw_coded(scope, &error.to_string(), "ERR_CRYPTO_OPERATION_FAILED")
        }
        ContextError::DhParamTooSmall => {
            throw_coded(scope, &error.to_string(), "ERR_INVALID_ARG_VALUE")
        }
        ContextError::NotInitialised => {
            throw_coded(scope, &error.to_string(), "ERR_CRYPTO_INVALID_STATE")
        }
    }
}

/// Throws an `Error` carrying a `.code`, which is the shape Node's tests read.
fn throw_coded(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(code_key) = v8::String::new(scope, "code") {
        if let Some(code_value) = v8::String::new(scope, code) {
            object.set(scope, code_key.into(), code_value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Throws a plain `TypeError`, which is what a bad argument type is in Node.
fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// Throws a plain `Error`.
fn throw(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}
