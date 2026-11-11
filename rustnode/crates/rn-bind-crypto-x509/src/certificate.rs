//! `X509Certificate`: the native half of `lib/internal/crypto/x509.js`.
//!
//! One internal field holds a [`CertificateState`]: the immutable DER snapshot
//! plus this certificate's index in it. Every accessor reparses a live `X509`, so
//! nothing holds a pointer into another isolate's heap and the object stays
//! shareable.
//!
//! # The brand, and why `Symbol.hasInstance` is not it
//!
//! `x509.js` installs `isX509Certificate` as a private-field test and falls back
//! to the native `isX509Certificate(value)`, which is this crate's
//! [`is_native_certificate`]. `test-crypto-x509-brand-check.js` replaces
//! `X509Certificate[Symbol.hasInstance]` with `() => true` and asserts the *native*
//! answer for a `Buffer` is still `false`. Testing native state is what makes that
//! hold: a replaced `Symbol.hasInstance` does not affect it, and neither does
//! `Object.setPrototypeOf`.
//!
//! # `ERR_INVALID_THIS`
//!
//! Every method starts by reading the receiver's state. `x509.js` calls methods
//! through `FunctionPrototypeCall(nativeX, this, …)` on objects that may be
//! anything — `{}`, a `Buffer`, a spoofed prototype — and the expected error is a
//! `TypeError` with `code: 'ERR_INVALID_THIS'`.
//! `test-crypto-x509-brand-check.js` asserts exactly that for all 19 getters and
//! 9 methods. Returning `undefined` instead would be a silent wrong answer.

use std::cell::RefCell;

use openssl::x509::X509;
use rn_v8_sys::v8;

use crate::alt_names::{self, SubjectAltName};
use crate::dates;
use crate::der_accessors;
use crate::extras;
use crate::legacy;
use crate::names;
use crate::snapshot::{parse_pem_or_der, Snapshot};

/// The internal field holding the `*mut RefCell<CertificateState>`.
const STATE_FIELD: i32 = 0;

/// A marker field, so reading a never-written pointer is impossible.
///
/// V8 does not guarantee internal fields start zeroed, and reading an
/// uninitialised aligned-pointer field aborts the process — the `KeyObject` work
/// found that. The marker is a plain `Value` slot, well defined to read as
/// `undefined` before anything writes it.
const PRESENT_FIELD: i32 = 1;

/// The fields the instance template reserves.
pub(crate) const INTERNAL_FIELD_COUNT: usize = PRESENT_FIELD as usize + 1;

/// What one `X509Certificate` object holds.
pub(crate) struct CertificateState {
    /// The chain, leaf first, shared with every object over it.
    pub(crate) snapshot: Snapshot,
    /// Which member of the snapshot *this* object is.
    pub(crate) index: usize,
    /// The issuer's JavaScript object, when the chain had one.
    pub(crate) issuer: Option<v8::Global<v8::Object>>,
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
pub(crate) fn with_state<R>(
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
    // The clone/transfer machinery finds a handle through this private mark, the
    // way `BaseObject`'s wrapper private does. Without it `structuredClone` and a
    // worker `postMessage` produce a plain `Object`, which looks like success and
    // silently loses the certificate.
    rn_core::host_object::mark(scope, object, CERTIFICATE_KIND);
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

/// Replaces the issuer link on an existing certificate's state.
pub(crate) fn set_issuer(object: v8::Local<v8::Object>, issuer: v8::Global<v8::Object>) {
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut RefCell<CertificateState>;
    if pointer.is_null() {
        return;
    }
    // SAFETY: the pointer was installed by `set_state` for this object and its
    // finaliser has not run, because `object` is a live local. A re-entrant borrow
    // cannot happen: nothing in this crate calls V8 while holding the state.
    let cell = unsafe { &*pointer };
    if let Ok(mut state) = cell.try_borrow_mut() {
        state.issuer = Some(issuer);
    }
}

/// Whether `value` carries this crate's native certificate state.
pub(crate) fn is_native_certificate(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> bool {
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return false;
    };
    with_state(scope, object, |_| ()).is_some()
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

pub(crate) fn throw_operation_failed(scope: &mut v8::PinScope<'_, '_>, message: &str) {
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

pub(crate) fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

pub(crate) fn throw_invalid_arg_value(scope: &mut v8::PinScope<'_, '_>, message: &str) {
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

/// Emits an `Error` with `code` set, which is the shape Node's tests read.
pub(crate) fn throw_coded(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(key) = v8::String::new(scope, "code") {
        if let Some(value) = v8::String::new(scope, code) {
            object.set(scope, key.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Runs `body` on the receiver's live certificate, or throws `ERR_INVALID_THIS`.
fn with_certificate<R>(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    body: impl FnOnce(&X509) -> R,
) -> Option<R> {
    let parsed = with_state(scope, this, CertificateState::certificate);
    let Some(parsed) = parsed else {
        throw_invalid_this(scope);
        return None;
    };
    match parsed {
        Some(certificate) => Some(body(&certificate)),
        None => {
            // The state is present but the bytes no longer parse. That cannot
            // happen for a snapshot this crate built, and a thrown error is
            // honest about it rather than reporting a plausible value.
            throw_operation_failed(scope, "Failed to parse X.509 certificate snapshot");
            None
        }
    }
}

/// Installs a prototype method from an `fn` item.
///
/// A macro rather than a table of `fn` pointers: `FunctionTemplate::builder` needs
/// the item type, because V8's trampoline is generic over a zero-sized unit type.
macro_rules! install_methods {
    ($scope:ident, $prototype:ident, $($name:literal => $callback:path),* $(,)?) => {
        $(
            {
                let template = v8::FunctionTemplate::builder($callback).build($scope);
                let key = v8::String::new($scope, $name)?;
                $prototype.set(key.into(), template.into());
            }
        )*
    };
}

pub(crate) use install_methods;

fn set_optional(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, value: Option<String>) {
    // An absent value leaves the return value unset, which JavaScript reads as
    // `undefined`; that is `Set`'s convention throughout `crypto_x509.cc`.
    if let Some(value) = value {
        if let Some(text) = v8::String::new(scope, &value) {
            rv.set(text.into());
        }
    }
}

fn set_buffer(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, bytes: &[u8]) {
    match rn_bind_crypto_keys::buffer_from(scope, bytes) {
        Some(value) => rv.set(value),
        None => throw_operation_failed(scope, "cannot allocate the result buffer"),
    }
}

// ---------------------------------------------------------------------------
// The constructor
// ---------------------------------------------------------------------------

/// `new X509Certificate(buffer)` — `X509Certificate::NewFromHandle`.
///
/// Two shapes: one `ArrayBufferView` (parse it) or an existing certificate (share
/// its snapshot and issuer). `x509.js` has already turned a string into a `Buffer`
/// and rejected everything else, but the native side checks too, because a direct
/// `Reflect.construct` bypasses that.
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
                throw_crypto_error(scope, "Failed to parse X.509 certificate");
                return;
            };
            let Some(der) = parsed.to_der().ok() else {
                throw_crypto_error(scope, "Failed to parse X.509 certificate");
                return;
            };
            let Some(snapshot) = Snapshot::from_der(vec![der]) else {
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

        if let Ok(source) = v8::Local::<v8::Object>::try_from(args.get(0)) {
            // The `Global` is cloned inside the borrow and materialised after it,
            // because `v8::Local::new` needs `scope` mutably.
            let copied = with_state(scope, source, |state| {
                (state.snapshot.clone(), state.index, state.issuer.clone())
            });
            let copied = copied;
            if let Some((snapshot, index, issuer)) = copied {
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

    throw_coded(
        scope,
        "value must be an X509CertificateHandle or BufferSource",
        "ERR_INVALID_ARG_TYPE",
    );
}

fn view_bytes(view: &v8::Local<v8::ArrayBufferView>) -> Vec<u8> {
    let length = view.byte_length();
    let mut bytes = vec![0u8; length];
    let copied = view.copy_contents(&mut bytes);
    bytes.truncate(copied);
    bytes
}

/// `ThrowCryptoError` over the pending OpenSSL error, or `fallback` when empty.
pub(crate) fn throw_crypto_error(scope: &mut v8::PinScope<'_, '_>, fallback: &str) {
    // SAFETY: reads and clears the thread-local error queue head.
    let packed = unsafe { openssl_sys::ERR_get_error() } as u64;
    let Some(detail) = (packed != 0)
        .then(|| rn_crypto_openssl::openssl_error_for(packed))
        .flatten()
    else {
        throw_operation_failed(scope, fallback);
        return;
    };
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
        let (Some(key), Some(text)) =
            (v8::String::new(scope, name), v8::String::new(scope, &value))
        else {
            continue;
        };
        object.set(scope, key.into(), text.into());
    }
    scope.throw_exception(exception);
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

fn name_property(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    subject: bool,
) {
    let printed = with_certificate(scope, this, |certificate| {
        names::print_name(certificate, subject)
    });
    if let Some(printed) = printed {
        set_optional(scope, rv, printed);
    }
}

pub(crate) fn subject(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    name_property(scope, args.this(), &mut rv, true);
}

pub(crate) fn issuer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    name_property(scope, args.this(), &mut rv, false);
}

/// `subjectAltName`, in its `kThrow` mode.
///
/// A **present but malformed** SAN throws
/// `ERR_CRYPTO_OPERATION_FAILED("Failed to format subject alternative name")`
/// rather than returning `undefined`, because `undefined` would make a
/// certificate with an unparseable SAN indistinguishable from one with no SAN at
/// all. The legacy object uses the `"DNS:"` sentinel instead; see
/// [`crate::legacy`].
pub(crate) fn subject_alt_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let outcome = with_certificate(scope, args.this(), alt_names::subject_alt_name);
    match outcome {
        Some(SubjectAltName::Absent) => rv.set_undefined(),
        Some(SubjectAltName::Text(text)) => set_optional(scope, &mut rv, Some(text)),
        Some(SubjectAltName::Malformed) => {
            throw_operation_failed(scope, "Failed to format subject alternative name")
        }
        None => {}
    }
}

pub(crate) fn info_access(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let text = with_certificate(scope, args.this(), alt_names::info_access);
    if let Some(text) = text {
        set_optional(scope, &mut rv, text);
    }
}

fn validity(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    from: bool,
) {
    let printed = with_certificate(scope, this, |certificate| {
        dates::print_time(certificate, from)
    });
    if let Some(printed) = printed {
        set_optional(scope, rv, printed);
    }
}

pub(crate) fn valid_from(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    validity(scope, args.this(), &mut rv, true);
}

pub(crate) fn valid_to(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    validity(scope, args.this(), &mut rv, false);
}

fn validity_date(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    from: bool,
) {
    let millis = with_certificate(scope, this, |certificate| dates::seconds(certificate, from));
    let Some(millis) = millis else {
        return;
    };
    // An unparseable time is `NaN`, which is an invalid `Date` rather than an
    // absent property: `Date::New(context, NaN)` is what Node builds.
    let millis = millis.map_or(f64::NAN, |seconds| seconds as f64 * 1000.0);
    match v8::Date::new(scope, millis) {
        Some(date) => rv.set(date.into()),
        None => throw_operation_failed(scope, "cannot allocate the validity date"),
    }
}

pub(crate) fn valid_from_date(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    validity_date(scope, args.this(), &mut rv, true);
}

pub(crate) fn valid_to_date(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    validity_date(scope, args.this(), &mut rv, false);
}

pub(crate) fn signature_algorithm(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_certificate(scope, args.this(), der_accessors::signature_algorithm);
    if let Some(value) = value {
        set_optional(scope, &mut rv, value);
    }
}

pub(crate) fn signature_algorithm_oid(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_certificate(scope, args.this(), der_accessors::signature_algorithm_oid);
    if let Some(value) = value {
        set_optional(scope, &mut rv, value);
    }
}

pub(crate) fn serial_number(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = with_certificate(scope, args.this(), der_accessors::serial_number);
    if let Some(value) = value {
        set_optional(scope, &mut rv, value);
    }
}

fn fingerprint(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    digest: openssl::hash::MessageDigest,
) {
    let value = with_certificate(scope, this, |certificate| {
        der_accessors::fingerprint(certificate, digest)
    });
    if let Some(value) = value {
        set_optional(scope, rv, value);
    }
}

pub(crate) fn fingerprint_sha1(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    fingerprint(
        scope,
        args.this(),
        &mut rv,
        openssl::hash::MessageDigest::sha1(),
    );
}

pub(crate) fn fingerprint_sha256(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    fingerprint(
        scope,
        args.this(),
        &mut rv,
        openssl::hash::MessageDigest::sha256(),
    );
}

pub(crate) fn fingerprint_sha512(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    fingerprint(
        scope,
        args.this(),
        &mut rv,
        openssl::hash::MessageDigest::sha512(),
    );
}

pub(crate) fn key_usage(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let usages = with_certificate(scope, args.this(), der_accessors::key_usage);
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

pub(crate) fn pem(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let text = with_certificate(scope, args.this(), |certificate| {
        certificate
            .to_pem()
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    });
    if let Some(text) = text {
        set_optional(scope, &mut rv, text);
    }
}

/// `raw`: this certificate's exact DER bytes, from the snapshot.
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

pub(crate) fn version(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let number = with_certificate(scope, args.this(), der_accessors::version);
    if let Some(Some(number)) = number {
        rv.set(v8::Integer::new(scope, number).into());
    }
}

fn structured_name(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
    subject: bool,
) {
    // The certificate is parsed first and the V8 builder runs afterwards: passing
    // `scope` into the closure would hold the state borrow across an allocation.
    let certificate = with_state(scope, this, CertificateState::certificate);
    let value = match certificate {
        Some(Some(certificate)) => Some(extras::structured_name(scope, &certificate, subject)),
        Some(None) => {
            throw_operation_failed(scope, "Failed to parse X.509 certificate snapshot");
            None
        }
        None => {
            throw_invalid_this(scope);
            None
        }
    };
    match value {
        Some(Some(value)) => rv.set(value),
        Some(None) => rv.set_undefined(),
        None => {}
    }
}

pub(crate) fn subject_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    structured_name(scope, args.this(), &mut rv, true);
}

pub(crate) fn issuer_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    structured_name(scope, args.this(), &mut rv, false);
}

pub(crate) fn extensions(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let certificate = with_state(scope, args.this(), CertificateState::certificate);
    let value = match certificate {
        Some(Some(certificate)) => Some(extras::extensions(scope, &certificate)),
        Some(None) => {
            throw_operation_failed(scope, "Failed to parse X.509 certificate snapshot");
            None
        }
        None => {
            throw_invalid_this(scope);
            None
        }
    };
    match value {
        Some(Some(value)) => rv.set(value),
        Some(None) => rv.set_undefined(),
        None => {}
    }
}

/// `tbs`: the exact `TBSCertificate` bytes, read from the snapshot DER.
pub(crate) fn tbs(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let bytes = with_state(scope, args.this(), |state| {
        state.der().and_then(der_accessors::exact_tbs)
    });
    let Some(bytes) = bytes else {
        throw_invalid_this(scope);
        return;
    };
    match bytes {
        Some(bytes) => set_buffer(scope, &mut rv, &bytes),
        None => throw_operation_failed(scope, "Failed to read the TBSCertificate"),
    }
}

pub(crate) fn signature(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let certificate = with_state(scope, args.this(), CertificateState::certificate);
    let value = match certificate {
        Some(Some(certificate)) => Some(extras::signature(scope, &certificate)),
        Some(None) => {
            throw_operation_failed(scope, "Failed to parse X.509 certificate snapshot");
            None
        }
        None => {
            throw_invalid_this(scope);
            None
        }
    };
    match value {
        Some(Some(value)) => rv.set(value),
        Some(None) => rv.set_undefined(),
        None => {}
    }
}

/// `publicKey`: a `KeyObjectHandle` over the certificate's public key.
///
/// `x509.js` wraps the handle in `new PublicKeyObject(...)`, so the handle must be
/// `rn-bind-crypto-keys`'s class or `instanceof` fails inside `keys.js`.
pub(crate) fn public_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let certificate = with_state(scope, args.this(), CertificateState::certificate);
    let handle = match certificate {
        Some(Some(certificate)) => {
            let key = extras::owned_public_key(&certificate).and_then(|key| {
                // SAFETY: `owned_public_key` returned one reference this call owns.
                unsafe { extras::pkey_from_raw(key) }
            });
            key.and_then(|key| {
                let key = rn_crypto_openssl::PKey::from_public(key)?;
                rn_bind_crypto_keys::create_public_handle(scope, key)
            })
        }
        Some(None) => {
            throw_operation_failed(scope, "Failed to parse X.509 certificate snapshot");
            None
        }
        None => {
            throw_invalid_this(scope);
            None
        }
    };
    match handle {
        Some(handle) => rv.set(handle.into()),
        None => throw_crypto_error(scope, "Failed to read the certificate public key"),
    }
}

/// `checkCA`.
pub(crate) fn check_ca(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let ca = with_certificate(scope, args.this(), extras::is_ca);
    if let Some(ca) = ca {
        rv.set(v8::Boolean::new(scope, ca).into());
    }
}

/// `checkHost`, `checkEmail` and `checkIP`, which share one shape.
fn check_subject(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    which: SubjectCheck,
) {
    let Some(name) = string_argument(scope, &args, 0) else {
        // `CheckX509Subject` has `CHECK(args[0]->IsString())`; `x509.js` validates
        // first, so this is a programming error rather than a user error.
        throw_type_error(scope, "The name argument must be a string");
        return;
    };
    let flags = args.get(1).uint32_value(scope).unwrap_or(0);
    let outcome = with_certificate(scope, args.this(), |certificate| match which {
        SubjectCheck::Host => extras::check_host(certificate, &name, flags),
        SubjectCheck::Email => (extras::check_email(certificate, &name, flags), None),
        SubjectCheck::Ip => (extras::check_ip(certificate, &name, flags), None),
    });
    match outcome {
        Some((CheckMatch::Match, matched)) => {
            // A host check replaces the result with the *matched* name when
            // OpenSSL reports one, which is how a wildcard certificate reports
            // which name it matched.
            let returned = matched.unwrap_or(name);
            if let Some(text) = v8::String::new(scope, &returned) {
                rv.set(text.into());
            }
        }
        Some((CheckMatch::NoMatch, _)) => rv.set_undefined(),
        Some((CheckMatch::InvalidName, _)) => throw_invalid_arg_value(scope, "Invalid name"),
        Some((CheckMatch::Failed, _)) => throw_operation_failed(scope, "X.509 check failed"),
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

/// The four `X509View::CheckMatch` outcomes.
///
/// `Failed` is separate from `NoMatch` on purpose: a certificate OpenSSL could not
/// check is not a certificate whose name did not match, and conflating the two
/// would turn an internal error into `undefined`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CheckMatch {
    Match,
    NoMatch,
    InvalidName,
    Failed,
}

impl CheckMatch {
    /// Maps the raw `X509_check_*` return.
    ///
    /// `0` is no match, `1` a match, `-2` an invalid name, anything else a
    /// failure. Shared so the three checks cannot disagree about `-2`.
    pub(crate) fn from_raw(value: std::ffi::c_int) -> Self {
        match value {
            0 => Self::NoMatch,
            1 => Self::Match,
            -2 => Self::InvalidName,
            _ => Self::Failed,
        }
    }
}

pub(crate) fn check_host(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_subject(scope, args, &mut rv, SubjectCheck::Host);
}

pub(crate) fn check_email(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_subject(scope, args, &mut rv, SubjectCheck::Email);
}

pub(crate) fn check_ip(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_subject(scope, args, &mut rv, SubjectCheck::Ip);
}

pub(crate) fn check_issued(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(other) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "The issuer argument must be an X509Certificate");
        return;
    };
    let issuer = with_state(scope, other, CertificateState::certificate);
    let Some(issuer) = issuer else {
        throw_type_error(scope, "The issuer argument must be an X509Certificate");
        return;
    };
    let Some(issuer) = issuer else {
        throw_operation_failed(scope, "Failed to parse X.509 certificate snapshot");
        return;
    };
    let issued = with_certificate(scope, args.this(), |certificate| {
        extras::is_issued_by(certificate, &issuer)
    });
    if let Some(issued) = issued {
        rv.set(v8::Boolean::new(scope, issued).into());
    }
}

/// `checkPrivateKey` and `verify`, which both take a `KeyObjectHandle`.
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
    let key = rn_bind_crypto_keys::key_of_handle(scope, handle);
    let Some(key) = key else {
        throw_type_error(scope, "The key argument must be a KeyObjectHandle");
        return;
    };
    let Some(key) = key.asymmetric_key().cloned() else {
        throw_operation_failed(scope, "The key argument must be an asymmetric key");
        return;
    };
    let outcome = with_certificate(scope, args.this(), |certificate| {
        if private {
            extras::check_private_key(certificate, key.openssl_ref())
        } else {
            extras::check_public_key(certificate, key.openssl_ref())
        }
    });
    if let Some(outcome) = outcome {
        rv.set(v8::Boolean::new(scope, outcome).into());
    }
}

/// `checkPrivateKey`: whether `key` is this certificate's private key.
///
/// This is `X509_check_private_key`, a public-half comparison, not a signature
/// operation, so it does not overlap `rn-crypto-openssl::sign`.
pub(crate) fn check_private_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_key(scope, args, &mut rv, true);
}

/// `verify`: whether the certificate's signature validates under `key`.
///
/// The verification is OpenSSL's `X509_verify`, which is the same
/// `EVP_DigestVerify` machinery `rn-crypto-openssl::sign` wraps for
/// `crypto.verify`. Reimplementing the TBS-and-digest assembly here would be the
/// second signature path that must not exist, so this calls the library operation
/// rather than reassembling one.
pub(crate) fn verify(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    check_key(scope, args, &mut rv, false);
}

pub(crate) fn get_issuer_cert(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let issuer = with_state(scope, args.this(), |state| state.issuer.clone());
    match issuer {
        Some(Some(issuer)) => {
            let issuer = v8::Local::new(scope, &issuer);
            rv.set(issuer.into());
        }
        Some(None) => rv.set_undefined(),
        None => throw_invalid_this(scope),
    }
}

pub(crate) fn to_legacy(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let certificate = with_state(scope, args.this(), CertificateState::certificate);
    let value = match certificate {
        Some(Some(certificate)) => Some(legacy::to_legacy(scope, &certificate)),
        Some(None) => {
            throw_operation_failed(scope, "Failed to parse X.509 certificate snapshot");
            None
        }
        None => {
            throw_invalid_this(scope);
            None
        }
    };
    match value {
        Some(Some(value)) => rv.set(value),
        Some(None) => rv.set_undefined(),
        None => {}
    }
}

/// The `host_object` kind a certificate handle is marked with.
pub(crate) const CERTIFICATE_KIND: &str = "X509Certificate";

/// Registers the certificate as a cloneable native handle.
///
/// Called from [`crate::install_classes`], which runs while the binding registry is
/// built and so before the first clone can reach the table.
pub(crate) fn register_clone_kind() {
    rn_core::host_object::register_kind(CERTIFICATE_KIND, clone_for_messaging);
}

/// `X509Certificate::CloneForMessaging`, which copies the snapshot reference.
///
/// Node's `X509CertificateTransferData` holds the `shared_ptr<const
/// X509CertificateSnapshot>` and the index; this holds the equivalent, which is a
/// cheap clone of the shared DER list.
fn clone_for_messaging<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<std::sync::Arc<dyn rn_core::host_object::TransferData>> {
    let payload = with_state(scope, object, |state| (state.snapshot.clone(), state.index))?;
    Some(std::sync::Arc::new(CertificateClone {
        snapshot: payload.0,
        index: payload.1,
    }))
}

/// The receiving half of a certificate clone.
struct CertificateClone {
    snapshot: Snapshot,
    index: usize,
}

impl rn_core::host_object::TransferData for CertificateClone {
    fn rebuild<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
        // `Deserialize` rebuilds through `X509Certificate::New(env, snapshot_,
        // snapshot_index_)` and then wraps the result in the JavaScript class with
        // `new InternalX509Certificate(handle)`, so the clone is a real
        // `X509Certificate` and its getters work. `new_certificate` is that same
        // path: it rebuilds the issuer chain and constructs the JavaScript subclass.
        crate::install::rebuild_from_snapshot(scope, self.snapshot.clone(), self.index)
    }
}

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
