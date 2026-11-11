//! `X509Certificate`: the native half of `lib/internal/crypto/x509.js`.
//!
//! One internal field holds a [`CertificateState`]. The state is the immutable
//! DER snapshot plus this certificate's index in it, so every accessor reparses
//! a live `X509` and nothing holds a pointer into another isolate's heap.
//!
//! # The brand, and why `HasInstance` is not the brand
//!
//! `x509.js` installs `isX509Certificate` as a `SafeWeakMap`/private-field test
//! and then falls back to the native `isX509Certificate(value)`, which is
//! [`super::install`]'s `HasInstance`. `test-crypto-x509-brand-check.js` replaces
//! `X509Certificate[Symbol.hasInstance]` with `() => true` and asserts the
//! *native* answer for a `Buffer` is still `false`. `FunctionTemplate::has_instance`
//! is unaffected by the JavaScript `Symbol.hasInstance`, which is exactly why the
//! native test and the JavaScript test both exist.
//!
//! # Why the issuer is a `Global<Object>`
//!
//! `getIssuerCert()` returns a certificate object, and `x509.js` wraps it in
//! `new InternalX509Certificate(cert)`, whose constructor calls back into this
//! one. Node hands over `issuer_cert_->object()`, the *same* base object. Holding
//! a `Global<Object>` here reproduces that: the returned object is the one this
//! state built, so `instanceof` holds and its state cache is shared.
//!
//! # `ERR_INVALID_THIS`
//!
//! Every method starts with [`state_of`]. `x509.js` calls methods through
//! `FunctionPrototypeCall(nativeX, this, …)` on objects that may be anything —
//! `{}`, a `Buffer`, a spoofed prototype — and the expected error is
//! `ERR_INVALID_THIS` with `TypeError`, which
//! `test-crypto-x509-brand-check.js` asserts for all 28 methods and 19 getters.
//! Returning `undefined` instead would be a silent wrong answer.

use std::cell::RefCell;

use openssl::x509::X509;
use rn_v8_sys::v8;

use crate::blocklist::{self, SpkiCheck};
use crate::names::{self, AltNameOption};
use crate::snapshot::{Snapshot, parse_pem_or_der};

/// The internal field holding the `*mut RefCell<CertificateState>`.
const STATE_FIELD: i32 = 0;

/// A marker field, so reading a never-written pointer is impossible.
///
/// V8 does not guarantee internal fields start zeroed; the `KeyObject` work found
/// that reading an uninitialised aligned-pointer field aborts the process. The
/// marker is a plain `Value` slot, well defined to read as `undefined` before
/// anything writes it.
const PRESENT_FIELD: i32 = 1;

/// The fields the instance template reserves.
pub(crate) const INTERNAL_FIELD_COUNT: usize = PRESENT_FIELD as usize + 1;

/// What one `X509Certificate` object holds.
pub(crate) struct CertificateState {
    /// The chain, leaf first, shared with every other object over it.
    snapshot: Snapshot,
    /// Which member of the snapshot *this* object is.
    index: usize,
    /// The issuer's JavaScript object, when the chain had one.
    ///
    /// `x509.js` reads this through `getIssuerCert()` and caches it itself, so
    /// this is the native parent link rather than a second cache.
    issuer: Option<v8::Global<v8::Object>>,
}

impl CertificateState {
    /// The live certificate, reparsed from the snapshot.
    fn certificate(&self) -> Option<X509> {
        self.snapshot.parse(self.index)
    }

    /// The exact DER bytes of this certificate.
    fn der(&self) -> Option<&[u8]> {
        self.snapshot.der_at(self.index)
    }
}

/// Runs `body` with the state an object holds, or `None` when it holds none.
///
/// # Safety contract
///
/// The pointer is read only when [`PRESENT_FIELD`] says [`set_state`] wrote it,
/// so a receiver that is not one of these objects — including a plain object with
/// no internal fields — cannot make this read uninitialised memory.
fn with_state<R>(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&CertificateState) -> R,
) -> Option<R> {
    let pointer = state_pointer(scope, object)?;
    // SAFETY: the marker proves `set_state` allocated this box for this object,
    // and only its finaliser frees it.
    let cell = unsafe { &*pointer };
    let state = cell.try_borrow().ok()?;
    Some(body(&state))
}

fn state_pointer(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
) -> Option<*mut RefCell<CertificateState>> {
    if object.internal_field_count() <= PRESENT_FIELD as usize {
        return None;
    }
    let marker = object.get_internal_field(scope, PRESENT_FIELD as usize)?;
    let marker = v8::Local::<v8::Value>::try_from(marker).ok()?;
    if !marker.boolean_value(scope) {
        return None;
    }
    // SAFETY: the marker says `set_state` wrote the pointer for this object.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut RefCell<CertificateState>;
    (!pointer.is_null()).then_some(pointer)
}

/// Stores `state` on `object` and installs its finaliser.
pub(crate) fn set_state(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    state: CertificateState,
) {
    let pointer = Box::into_raw(Box::new(RefCell::new(state)));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<std::ffi::c_void>().cast_const(),
        0,
    );
    // The marker goes in after the pointer, so a reader that sees it always sees
    // a pointer that was written.
    let marker = v8::Boolean::new(scope, true);
    object.set_internal_field(PRESENT_FIELD as usize, marker.into());
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut RefCell<CertificateState>;
            // SAFETY: allocated just above for this object alone; this finaliser
            // is the only thing that frees it.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
}

/// Whether `value` carries this crate's native certificate state.
///
/// This is `X509Certificate::HasInstance`, and it tests native state rather than
/// the prototype chain — which is what makes it immune to the replaced
/// `Symbol.hasInstance` the brand-check test installs.
pub(crate) fn is_native_certificate(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> bool {
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return false;
    };
    with_state(scope, object, |_| ()).is_some()
}

/// Creates a certificate object with `state`, which is `X509Certificate::New`.
///
/// `constructor` is the native `FunctionTemplate`, so the new object has the
/// right prototype and internal fields without running JavaScript.
pub(crate) fn new_instance<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    constructor: v8::Local<'s, v8::Function>,
    state: CertificateState,
) -> Option<v8::Local<'s, v8::Object>> {
    // `new_instance` on the function would run the constructor callback, which
    // expects to be a `new X509Certificate(buffer)` call. The template's instance
    // template creates a bare object with the fields instead.
    let object = constructor
        .get("prototype")
        .and_then(|prototype| v8::Local::<v8::Object>::try_from(prototype).ok())?;
    let _ = object;
    None
}

/// Builds a certificate object with `state` using the template's instance
/// template, which is what `new X509Certificate(buffer)` produces.
pub(crate) fn instance_from_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    template: v8::Local<'s, v8::FunctionTemplate>,
    state: CertificateState,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = template.instance_template(scope).new_instance(scope)?;
    set_state(scope, object, state);
    Some(object)
}

/// Emits the `this`-receiver error `ASSIGN_OR_RETURN_UNWRAP` produces.
pub(crate) fn throw_invalid_this(scope: &mut v8::PinScope<'_, '_>) {
    let Some(text) = v8::String::new(scope, "Value of \"this\" must be of type X509Certificate")
    else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(code) = v8::String::new(scope, "code") {
        if let Some(value) = v8::String::new(scope, "ERR_INVALID_THIS") {
            object.set(scope, code.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Emits `ERR_CRYPTO_OPERATION_FAILED` with `message`.
fn throw_operation_failed(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(code) = v8::String::new(scope, "code") {
        if let Some(value) = v8::String::new(scope, "ERR_CRYPTO_OPERATION_FAILED") {
            object.set(scope, code.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Emits an OpenSSL-shaped `ThrowCryptoError`.
fn throw_crypto_error(scope: &mut v8::PinScope<'_, '_>, packed: u64) {
    if let Some(detail) = rn_crypto_openssl::openssl_error_for(packed) {
        let Some(text) = v8::String::new(scope, &detail.message) else {
            return;
        };
        let exception = v8::Exception::error(scope, text);
        let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
            scope.throw_exception(exception);
            return;
        };
        for (name, value) in [
            ("code", detail.code()),
            ("library", format!("{} routines", detail.library)),
            ("reason", detail.reason.clone()),
        ] {
            let (Some(key), Some(text)) = (v8::String::new(scope, name), v8::String::new(scope, &value))
            else {
                continue;
            };
            object.set(scope, key.into(), text.into());
        }
        scope.throw_exception(exception);
        return;
    }
    throw_operation_failed(scope, "Failed to parse X.509 certificate");
}

/// Emits a string, or `undefined` for `None`, which is the `Set` convention in
/// `crypto_x509.cc`: an absent value is left unset and JavaScript reads it as
/// `undefined` rather than as `null`.
fn set_optional_string(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue,
    value: Option<String>,
) {
    if let Some(value) = value {
        if let Some(text) = v8::String::new(scope, &value) {
            rv.set(text.into());
        }
    }
}

/// Emits bytes as a real `Buffer`.
fn set_buffer(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, bytes: &[u8]) {
    match rn_bind_crypto_keys::buffer_from(scope, bytes) {
        Some(value) => rv.set(value),
        None => throw_operation_failed(scope, "cannot allocate the result buffer"),
    }
}

/// `new X509Certificate(buffer)` — `X509Certificate::NewFromHandle`.
///
/// Two call shapes: one `ArrayBufferView` (parse it), or an existing
/// `X509Certificate` (share its snapshot and issuer). Anything else is
/// `ERR_INVALID_ARG_TYPE`, which `x509.js` normally catches first but the native
/// side checks too.
pub(crate) fn constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();

    if args.length() == 1 {
        if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(0)) {
            let bytes = view_bytes(&view);
            let Some(parsed) = parse_pem_or_der(&bytes) else {
                throw_crypto_error(scope, last_error());
                return;
            };
            let Some(snapshot) = Snapshot::from_der(vec![match parsed.to_der() {
                Ok(der) => der,
                Err(_) => {
                    throw_crypto_error(scope, last_error());
                    return;
                }
            }]) else {
                throw_operation_failed(scope, "Failed to snapshot X.509 certificate");
                return;
            };
            set_state(
                scope,
                this,
                CertificateState {
                    snapshot,
                    index: 0,
                    issuer: None,
                },
            );
            rv.set(this.into());
            return;
        }

        // `new X509Certificate(other)`: the handle copy. The snapshot is shared,
        // so this is a pointer bump plus the issuer link.
        if let Ok(source) = v8::Local::<v8::Object>::try_from(args.get(0)) {
            if let Some(copied) = with_state(scope, source, |state| {
                (
                    state.snapshot.clone(),
                    state.index,
                    state.issuer.as_ref().map(|global| v8::Local::new(scope, global)),
                )
            }) {
                let (snapshot, index, issuer) = copied;
                set_state(
                    scope,
                    this,
                    CertificateState {
                        snapshot,
                        index,
                        issuer,
                    },
                );
                rv.set(this.into());
                return;
            }
        }
    }

    let Some(text) = v8::String::new(
        scope,
        "value must be an X509CertificateHandle or BufferSource",
    ) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(code) = v8::String::new(scope, "code") {
        if let Some(value) = v8::String::new(scope, "ERR_INVALID_ARG_TYPE") {
            object.set(scope, code.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Copies an `ArrayBufferView`'s bytes.
fn view_bytes(view: &v8::Local<v8::ArrayBufferView>) -> Vec<u8> {
    let length = view.byte_length();
    let mut bytes = vec![0u8; length];
    let copied = view.copy_contents(&mut bytes);
    bytes.truncate(copied);
    bytes
}

/// The packed OpenSSL error currently on the queue, or 0.
fn last_error() -> u64 {
    // SAFETY: the error queue is thread-local, and this only reads and clears
    // its head entry.
    unsafe { openssl_sys::ERR_get_error() }
}

/// Builds every prototype method. One macro over `fn` items because
/// `FunctionTemplate::builder` needs the item type, not a `fn` pointer.
macro_rules! install_methods {
    ($scope:ident, $prototype:ident, $($name:literal => $callback:path),* $(,)?) => {
        $(
            {
                let template = v8::FunctionTemplate::builder($callback).build($scope);
                let Some(key) = v8::String::new($scope, $name) else {
                    return Err(format!("cannot allocate the {} property name", $name));
                };
                $prototype.set(key.into(), template.into());
            }
        )*
    };
}

pub(crate) use install_methods;

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

/// Runs `body` on the receiver's live certificate, or throws `ERR_INVALID_THIS`.
fn with_certificate<R>(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    body: impl FnOnce(&X509) -> R,
) -> Option<R> {
    let parsed = with_state(scope, this, |state| state.certificate());
    let Some(parsed) = parsed else {
        throw_invalid_this(scope);
        return None;
    };
    match parsed {
        Some(certificate) => Some(body(&certificate)),
        None => {
            // The state is present but the bytes no longer parse. That cannot
            // happen with a snapshot built by this crate, and a thrown error is
            // honest about it rather than reporting a plausible value.
            throw_operation_failed(scope, "Failed to parse X.509 certificate snapshot");
            None
        }
    }
}

/// `subject` / `issuer`.
fn name_property(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    subject: bool,
) {
    let printed = with_certificate(scope, this, |certificate| names::print_name(certificate, subject));
    if let Some(printed) = printed {
        set_optional_string(scope, rv, printed);
    }
}

/// `X509Certificate::Subject`.
pub(crate) fn subject(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    name_property(scope, args.this(), &mut rv, true);
}

/// `X509Certificate::Issuer`.
pub(crate) fn issuer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    name_property(scope, args.this(), &mut rv, false);
}

/// `X509Certificate::SubjectAltName`.
///
/// Three-way outcome in `GetSubjectAltNameString`: no extension at all is
/// `undefined`; a *present but malformed* extension throws for direct
/// inspection, while the legacy TLS object gets the `"DNS:"` sentinel so
/// hostname verification cannot fall back to the common name. This is the
/// `kThrow` mode.
pub(crate) fn subject_alt_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let outcome = with_certificate(scope, args.this(), |certificate| {
        crate::certificate_alt_names::subject_alt_name(certificate)
    });
    match outcome {
        Some(AltNames::Absent) => rv.set_undefined(),
        Some(AltNames::Text(text)) => set_optional_string(scope, rv, Some(text)),
        Some(AltNames::Malformed) => {
            throw_operation_failed(scope, "Failed to format subject alternative name")
        }
        None => {}
    }
}

/// The three `GetSubjectAltNameString` outcomes.
pub(crate) enum AltNames {
    /// No SAN extension.
    Absent,
    /// The formatted list.
    Text(String),
    /// The extension is present and could not be formatted.
    Malformed,
}

/// `X509Certificate::InfoAccess`.
pub(crate) fn info_access(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let text = with_certificate(scope, args.this(), |certificate| {
        crate::certificate_alt_names::info_access(certificate)
    });
    if let Some(text) = text {
        set_optional_string(scope, rv, text);
    }
}

/// `X509Certificate::ValidFrom` / `ValidTo`.
fn validity(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    from: bool,
) {
    let printed = with_certificate(scope, this, |certificate| {
        crate::certificate_dates::print_time(certificate, from)
    });
    if let Some(printed) = printed {
        set_optional_string(scope, rv, printed);
    }
}

/// `X509Certificate::ValidFrom`.
pub(crate) fn valid_from(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    validity(scope, args.this(), &mut rv, true);
}

/// `X509Certificate::ValidTo`.
pub(crate) fn valid_to(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    validity(scope, args.this(), &mut rv, false);
}

/// `X509Certificate::ValidFromDate` / `ValidToDate`.
fn validity_date(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    from: bool,
) {
    let millis = with_certificate(scope, this, |certificate| {
        crate::certificate_dates::seconds(certificate, from)
    });
    let Some(millis) = millis else {
        return;
    };
    // An unparseable time is `NaN`, which is `Date` with an invalid value, not
    // an omitted property: `Date::New(context, NaN)` is what Node builds.
    let millis = millis.map_or(f64::NAN, |seconds| seconds as f64 * 1000.0);
    // SAFETY: `Date::new` only allocates; it cannot fail in a way that needs
    // handling here.
    let date = v8::Date::new(scope, millis);
    rv.set(date.into());
}

/// `X509Certificate::ValidFromDate`.
pub(crate) fn valid_from_date(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    validity_date(scope, args.this(), &mut rv, true);
}

/// `X509Certificate::ValidToDate`.
pub(crate) fn valid_to_date(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    validity_date(scope, args.this(), &mut rv, false);
}

/// `X509Certificate::SignatureAlgorithm`.
pub(crate) fn signature_algorithm(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let text = with_certificate(scope, args.this(), crate::certificate_der::signature_algorithm);
    if let Some(text) = text {
        set_optional_string(scope, rv, text);
    }
}

/// `X509Certificate::SignatureAlgorithmOID`.
pub(crate) fn signature_algorithm_oid(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let text = with_certificate(scope, args.this(), crate::certificate_der::signature_algorithm_oid);
    if let Some(text) = text {
        set_optional_string(scope, rv, text);
    }
}

/// `X509Certificate::SerialNumber`.
pub(crate) fn serial_number(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let text = with_certificate(scope, args.this(), crate::certificate_der::serial_number);
    if let Some(text) = text {
        set_optional_string(scope, rv, text);
    }
}

/// `fingerprint`, `fingerprint256`, `fingerprint512`.
fn fingerprint(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    digest: openssl::hash::MessageDigest,
) {
    let text = with_certificate(scope, this, |certificate| {
        crate::certificate_der::fingerprint(certificate, digest)
    });
    if let Some(text) = text {
        set_optional_string(scope, rv, text);
    }
}

/// `X509Certificate::Fingerprint<Digest::SHA1>`.
pub(crate) fn fingerprint_sha1(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    fingerprint(scope, args.this(), &mut rv, openssl::hash::MessageDigest::sha1());
}

/// `X509Certificate::Fingerprint<Digest::SHA256>`.
pub(crate) fn fingerprint_sha256(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    fingerprint(scope, args.this(), &mut rv, openssl::hash::MessageDigest::sha256());
}

/// `X509Certificate::Fingerprint<Digest::SHA512>`.
pub(crate) fn fingerprint_sha512(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    fingerprint(scope, args.this(), &mut rv, openssl::hash::MessageDigest::sha512());
}

/// `X509Certificate::KeyUsage`.
///
/// An array of dotted OIDs from the extended-key-usage extension, or
/// `undefined` when the extension is absent. `enumUsages` returns `false` for an
/// absent extension, and the binding leaves the property unset.
pub(crate) fn key_usage(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let usages = with_certificate(scope, args.this(), crate::certificate_der::key_usage);
    let Some(usages) = usages else {
        return;
    };
    let Some(usages) = usages else {
        rv.set_undefined();
        return;
    };
    let values: Vec<v8::Local<v8::Value>> = usages
        .iter()
        .filter_map(|usage| v8::String::new(scope, usage).map(Into::into))
        .collect();
    rv.set(v8::Array::new_with_elements(scope, &values).into());
}

/// `X509Certificate::Pem`.
pub(crate) fn pem(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let text = with_certificate(scope, args.this(), |certificate| {
        certificate.to_pem().ok().and_then(|bytes| {
            // PEM writing ignores the requested line ending on input; the bytes
            // are ASCII because PEM is base64.
            String::from_utf8(bytes).ok()
        })
    });
    if let Some(text) = text {
        set_optional_string(scope, rv, text);
    }
}

/// `X509Certificate::Der`.
pub(crate) fn der(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let bytes = with_state(scope, args.this(), |state| state.der().map(<[u8]>::to_vec));
    let Some(bytes) = bytes else {
        throw_invalid_this(scope);
        return;
    };
    match bytes {
        Some(bytes) => set_buffer(scope, &mut rv, &bytes),
        None => throw_operation_failed(scope, "Failed to encode the certificate"),
    }
}

/// `X509Certificate::Version`.
pub(crate) fn version(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let number = with_certificate(scope, args.this(), crate::certificate_der::version);
    if let Some(Some(number)) = number {
        rv.set(v8::Integer::new(scope, number).into());
    }
}

/// `X509Certificate::SubjectName` / `IssuerName`.
fn structured_name(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    subject: bool,
) {
    let value = with_certificate(scope, this, |certificate| {
        crate::certificate_extra::structured_name(certificate, subject)
    });
    match value {
        Some(Some(value)) => rv.set(value),
        Some(None) => rv.set_undefined(),
        None => {}
    }
}

/// `X509Certificate::SubjectName`.
pub(crate) fn subject_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    structured_name(scope, args.this(), &mut rv, true);
}

/// `X509Certificate::IssuerName`.
pub(crate) fn issuer_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    structured_name(scope, args.this(), &mut rv, false);
}

/// `X509Certificate::Extensions`.
pub(crate) fn extensions(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_certificate(scope, args.this(), crate::certificate_extra::extensions);
    match value {
        Some(Some(value)) => rv.set(value),
        Some(None) => rv.set_undefined(),
        None => {}
    }
}

/// `X509Certificate::Tbs`: the exact `TBSCertificate` bytes.
///
/// Read from the **snapshot DER**, not from a re-encoded live certificate: the
/// signature covers the bytes as received, and a re-encode can normalise them.
pub(crate) fn tbs(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let bytes = with_state(scope, args.this(), |state| {
        state.der().and_then(crate::certificate_der::exact_tbs)
    });
    let Some(bytes) = bytes else {
        throw_invalid_this(scope);
        return;
    };
    if let Some(bytes) = bytes {
        set_buffer(scope, &mut rv, &bytes);
    }
}

/// `X509Certificate::Signature`.
pub(crate) fn signature(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_certificate(scope, args.this(), crate::certificate_extra::signature);
    match value {
        Some(Some(value)) => rv.set(value),
        Some(None) => rv.set_undefined(),
        None => {}
    }
}

/// `X509Certificate::PublicKey`.
///
/// Returns a `KeyObjectHandle` over the certificate's public key, which
/// `x509.js` wraps in `new PublicKeyObject(handle)`. The handle class belongs to
/// `rn-bind-crypto-keys`, so it is created through that crate rather than
/// rebuilt here.
pub(crate) fn public_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let key = with_certificate(scope, args.this(), |certificate| {
        certificate.public_key().ok()
    });
    let Some(key) = key else {
        return;
    };
    let Some(key) = key else {
        throw_crypto_error(scope, last_error());
        return;
    };
    let Some(pkey) = rn_crypto_openssl::PKey::from_public(key) else {
        throw_operation_failed(scope, "Failed to read the certificate public key");
        return;
    };
    let Some(handle) =
        rn_bind_crypto_keys::create_public_handle(scope, pkey)
    else {
        throw_operation_failed(scope, "cannot create the KeyObjectHandle");
        return;
    };
    rv.set(handle.into());
}

/// `X509Certificate::CheckCA`.
pub(crate) fn check_ca(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let ca = with_certificate(scope, args.this(), crate::certificate_extra::is_ca);
    if let Some(ca) = ca {
        rv.set(v8::Boolean::new(scope, ca).into());
    }
}

/// The three `X509View::CheckMatch` outcomes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckMatch {
    Match,
    NoMatch,
    InvalidName,
}

/// `checkHost`, `checkEmail` and `checkIP`, which share one shape.
///
/// `MATCH` returns the matched name (or the input) as a string, `NO_MATCH`
/// leaves the property unset so JavaScript reads `undefined`, and
/// `INVALID_NAME` throws `ERR_INVALID_ARG_VALUE("Invalid name")`.
fn check_subject(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    subject: SubjectCheck,
) {
    let Some(name) = string_argument(scope, &args, 0) else {
        // `CheckX509Subject` has `CHECK(args[0]->IsString())`; JavaScript
        // validates first, so reaching here is a programming error.
        throw_type_error(scope, "The name argument must be a string");
        return;
    };
    let flags = args.get(1).uint32_value(scope).unwrap_or(0) as std::ffi::c_uint;
    let outcome = with_certificate(scope, args.this(), |certificate| match subject {
        SubjectCheck::Host => crate::certificate_extra::check_host(certificate, &name, flags),
        SubjectCheck::Email => crate::certificate_extra::check_email(certificate, &name, flags),
        SubjectCheck::Ip => crate::certificate_extra::check_ip(certificate, &name, flags),
    });
    match outcome {
        Some(Some((CheckMatch::Match, matched))) => {
            // `CheckHost` replaces the return value with the *matched* name when
            // OpenSSL reported one, which is how a wildcard reports which name
            // it matched.
            let returned = matched.unwrap_or(name);
            if let Some(text) = v8::String::new(scope, &returned) {
                rv.set(text.into());
            }
        }
        Some(Some((CheckMatch::NoMatch, _))) => rv.set_undefined(),
        Some(Some((CheckMatch::InvalidName, _))) => throw_invalid_arg_value(scope, "Invalid name"),
        Some(None) => throw_operation_failed(scope, "X.509 check failed"),
        None => {}
    }
}

/// Which check [`check_subject`] runs.
#[derive(Clone, Copy)]
pub(crate) enum SubjectCheck {
    Host,
    Email,
    Ip,
}

/// `X509Certificate::CheckHost`.
pub(crate) fn check_host(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_subject(scope, args, &mut rv, SubjectCheck::Host);
}

/// `X509Certificate::CheckEmail`.
pub(crate) fn check_email(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_subject(scope, args, &mut rv, SubjectCheck::Email);
}

/// `X509Certificate::CheckIP`.
pub(crate) fn check_ip(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_subject(scope, args, &mut rv, SubjectCheck::Ip);
}

/// `X509Certificate::CheckIssued`.
pub(crate) fn check_issued(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let other = args.get(0);
    let Ok(other) = v8::Local::<v8::Object>::try_from(other) else {
        throw_type_error(scope, "The issuer argument must be an X509Certificate");
        return;
    };
    let issuer = with_state(scope, other, |state| state.certificate());
    let Some(issuer) = issuer else {
        throw_type_error(scope, "The issuer argument must be an X509Certificate");
        return;
    };
    let Some(issuer) = issuer else {
        throw_operation_failed(scope, "Failed to parse X.509 certificate snapshot");
        return;
    };
    let issued = with_certificate(scope, args.this(), |certificate| {
        certificate.issued(&issuer) == openssl::x509::X509VerifyResult::OK
    });
    if let Some(issued) = issued {
        rv.set(v8::Boolean::new(scope, issued).into());
    }
}

/// `X509Certificate::CheckPrivateKey` and `verify`, which both take a key handle.
fn check_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    private: bool,
) {
    let Ok(handle) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "The key argument must be a KeyObjectHandle");
        return;
    };
    let Some(key) = rn_bind_crypto_keys::key_of_handle(scope, handle) else {
        throw_type_error(scope, "The key argument must be a KeyObjectHandle");
        return;
    };
    let Some(key) = key.asymmetric_key().cloned() else {
        throw_operation_failed(scope, "The key argument must be an asymmetric key");
        return;
    };
    let outcome = with_certificate(scope, args.this(), |certificate| {
        crate::certificate_extra::check_key(certificate, &key, private)
    });
    if let Some(outcome) = outcome {
        rv.set(v8::Boolean::new(scope, outcome).into());
    }
}

/// `X509Certificate::CheckPrivateKey`.
pub(crate) fn check_private_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_key(scope, args, &mut rv, true);
}

/// `X509Certificate::CheckPublicKey`, installed as `verify`.
pub(crate) fn verify(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_key(scope, args, &mut rv, false);
}

/// `X509Certificate::GetIssuerCert`.
pub(crate) fn get_issuer_cert(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let issuer = with_state(scope, args.this(), |state| {
        state.issuer.as_ref().map(|global| v8::Local::new(scope, global))
    });
    match issuer {
        Some(Some(issuer)) => rv.set(issuer.into()),
        Some(None) => rv.set_undefined(),
        None => throw_invalid_this(scope),
    }
}

/// `X509Certificate::ToLegacy`.
pub(crate) fn to_legacy(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_certificate(scope, args.this(), crate::certificate_extra::to_legacy);
    match value {
        Some(Some(value)) => rv.set(value),
        Some(None) => rv.set_undefined(),
        None => {}
    }
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn string_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<String> {
    let Ok(text) = v8::Local::<v8::String>::try_from(args.get(index)) else {
        return None;
    };
    Some(text.to_rust_string_lossy(scope))
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

fn throw_invalid_arg_value(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(code) = v8::String::new(scope, "code") {
        if let Some(value) = v8::String::new(scope, "ERR_INVALID_ARG_VALUE") {
            object.set(scope, code.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// The SPKI check, re-exported so the verify-callback path and the class share it.
pub(crate) fn spki_blocks(certificate: &X509) -> SpkiCheck {
    blocklist::check_spki(Some(certificate))
}
