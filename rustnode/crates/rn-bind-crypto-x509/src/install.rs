//! Installing the X.509 surface onto the `crypto` namespace object.
//!
//! This crate does not own a namespace: `src/crypto/crypto_x509.cc` is one
//! translation unit among the dozen `src/node_crypto.cc` aggregates onto one
//! `target`, and the crate split follows the translation unit rather than the
//! namespace. So the export is [`install_classes`] and `rn-bind-crypto` calls it
//! from its own `install`.
//!
//! The name matters: `tools/regen-bindings.sh` discovers namespace providers by
//! grepping each crate for a `register` function declaration, so a helper named
//! `register_something` here would be treated as a provider and the build would
//! fail on a symbol this crate does not export. Slice 1 hit exactly this, which
//! is why this comment does not spell the pattern out either.
//!
//! # The class protocol
//!
//! `createX509CertificateClass(build)` builds the `NativeX509Certificate` base
//! class, passes it to `build`, returns whatever `build` returned, and keeps slot
//! 1 of that array — which `x509.js` fills with its own `InternalX509Certificate`.
//! The keeper matters because `parseX509Snapshot` has to construct *that* class,
//! not the base: `createX509CertificateFromSnapshot` returns
//! `new InternalX509Certificate(...)`, and an object built from the base would not
//! have the private `#state` field the JavaScript getters read.
//!
//! Unlike the `KeyObject` family, this crate does not need the four concrete
//! subclasses: `x509.js` returns `[X509Certificate, InternalX509Certificate]` and
//! only slot 1 is used natively.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::blocklist;
use crate::certificate::{
    self, install_methods, set_state, with_state, CertificateState, INTERNAL_FIELD_COUNT,
};
use crate::snapshot::Snapshot;

/// The members this crate installs, for the parent crate's `MEMBERS` list.
///
/// Thirteen names: the five members `crypto_x509.cc`'s `Initialize` installs and
/// `lib/internal/crypto/x509.js` destructures at module load, `parsePKCS12` from
/// `crypto_pkcs12.cc`, the two blocklist test hooks, and the five root-store
/// accessors `lib/tls.js` reaches before any `SecureContext` exists.
pub const MEMBERS: &[&str] = &[
    // `crypto_x509.cc`'s `X509Certificate::Initialize`.
    "createX509CertificateClass",
    "isX509Certificate",
    "parseX509",
    "parseX509Snapshot",
    "getX509CertificateSnapshot",
    // `crypto_pkcs12.cc`'s `PKCS12Parser::Initialize`.
    "parsePKCS12",
    // The blocklist's test hooks. They are in `crypto_context.cc` in Node, but
    // the list itself is X.509 policy and the tests that reach them are X.509
    // tests, so they belong with this slice.
    "addBlockedSPKIForTesting",
    "clearBlockedSPKIsForTesting",
    // The root store. Also `crypto_context.cc`, also reached at module scope by
    // `lib/tls.js` before any `SecureContext` exists.
    "getBundledRootCertificates",
    "getExtraCACertificates",
    "getSystemCACertificates",
    "getUserRootCertificates",
    "resetRootCertStore",
];

thread_local! {
    /// The constructors `x509.js` built during load.
    ///
    /// `base` is the `NativeX509Certificate` template, kept so a second
    /// `createX509CertificateClass` call reuses it — two templates would make
    /// `instanceof` disagree between certificates built at different times.
    /// `internal` is slot 1 of the callback's array, the class
    /// `parseX509Snapshot` must construct.
    static CLASSES: RefCell<Classes> = const { RefCell::new(Classes::new()) };
}

struct Classes {
    base: Option<v8::Global<v8::FunctionTemplate>>,
    internal: Option<v8::Global<v8::Function>>,
}

impl Classes {
    const fn new() -> Self {
        Self {
            base: None,
            internal: None,
        }
    }
}

fn with_classes<R>(body: impl FnOnce(&mut Classes) -> R) -> R {
    CLASSES.with(|slot| body(&mut slot.borrow_mut()))
}

/// Installs the X.509 members onto `target`, which is the `crypto` namespace.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    for (name, callback) in [
        (
            "createX509CertificateClass",
            v8::FunctionTemplate::builder(create_x509_certificate_class).build(scope),
        ),
        (
            "isX509Certificate",
            v8::FunctionTemplate::builder(is_x509_certificate).build(scope),
        ),
        (
            "parseX509",
            v8::FunctionTemplate::builder(parse_x509).build(scope),
        ),
        (
            "parseX509Snapshot",
            v8::FunctionTemplate::builder(parse_snapshot).build(scope),
        ),
        (
            "getX509CertificateSnapshot",
            v8::FunctionTemplate::builder(get_snapshot).build(scope),
        ),
        (
            "parsePKCS12",
            v8::FunctionTemplate::builder(parse_pkcs12).build(scope),
        ),
        (
            "addBlockedSPKIForTesting",
            v8::FunctionTemplate::builder(add_blocked_spki).build(scope),
        ),
        (
            "clearBlockedSPKIsForTesting",
            v8::FunctionTemplate::builder(clear_blocked_spkis).build(scope),
        ),
        (
            "getBundledRootCertificates",
            v8::FunctionTemplate::builder(get_bundled_root_certificates).build(scope),
        ),
        (
            "getExtraCACertificates",
            v8::FunctionTemplate::builder(get_extra_ca_certificates).build(scope),
        ),
        (
            "getSystemCACertificates",
            v8::FunctionTemplate::builder(get_system_ca_certificates).build(scope),
        ),
        (
            "getUserRootCertificates",
            v8::FunctionTemplate::builder(get_user_root_certificates).build(scope),
        ),
        (
            "resetRootCertStore",
            v8::FunctionTemplate::builder(reset_root_cert_store).build(scope),
        ),
    ] {
        let function = callback
            .get_function(scope)
            .ok_or_else(|| format!("cannot allocate crypto.{name}"))?;
        set(scope, target, name, function.into())?;
    }
    Ok(())
}

/// The `NativeX509Certificate` template, built once.
fn base_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::FunctionTemplate>> {
    if let Some(template) = with_classes(|classes| classes.base.clone()) {
        return Some(v8::Local::new(scope, &template));
    }
    let template = v8::FunctionTemplate::builder(certificate::constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELD_COUNT);
    let Some(name) = v8::String::new(scope, "X509Certificate") else {
        return None;
    };
    template.set_class_name(name);
    let prototype = template.prototype_template(scope);
    // The 30 prototype methods, in the order `crypto_x509.cc`'s
    // `GetConstructorTemplate` installs them. `verify` is `CheckPublicKey` and
    // `raw` is `Der`, which is why two names do not match their callback.
    install_methods!(
        scope,
        prototype,
        "subject" => certificate::subject,
        "subjectAltName" => certificate::subject_alt_name,
        "infoAccess" => certificate::info_access,
        "issuer" => certificate::issuer,
        "validTo" => certificate::valid_to,
        "validFrom" => certificate::valid_from,
        "validToDate" => certificate::valid_to_date,
        "validFromDate" => certificate::valid_from_date,
        "signatureAlgorithm" => certificate::signature_algorithm,
        "signatureAlgorithmOid" => certificate::signature_algorithm_oid,
        "fingerprint" => certificate::fingerprint_sha1,
        "fingerprint256" => certificate::fingerprint_sha256,
        "fingerprint512" => certificate::fingerprint_sha512,
        "keyUsage" => certificate::key_usage,
        "serialNumber" => certificate::serial_number,
        "pem" => certificate::pem,
        "raw" => certificate::der,
        "version" => certificate::version,
        "subjectName" => certificate::subject_name,
        "issuerName" => certificate::issuer_name,
        "extensions" => certificate::extensions,
        "tbs" => certificate::tbs,
        "signature" => certificate::signature,
        "publicKey" => certificate::public_key,
        "checkCA" => certificate::check_ca,
        "checkHost" => certificate::check_host,
        "checkEmail" => certificate::check_email,
        "checkIP" => certificate::check_ip,
        "checkIssued" => certificate::check_issued,
        "checkPrivateKey" => certificate::check_private_key,
        "verify" => certificate::verify,
        "toLegacy" => certificate::to_legacy,
        "getIssuerCert" => certificate::get_issuer_cert,
    );
    with_classes(|classes| classes.base = Some(v8::Global::new(scope.as_ref(), template)));
    Some(template)
}

/// `createX509CertificateClass(build)`.
fn create_x509_certificate_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(scope, "createX509CertificateClass needs a callback");
        return;
    };
    let Some(template) = base_template(scope) else {
        throw(scope, "cannot build the X509Certificate class");
        return;
    };
    let Some(base) = template.get_function(scope) else {
        throw(scope, "cannot allocate the X509Certificate constructor");
        return;
    };
    // A thrown exception is left pending: it carries the real reason `x509.js`
    // could not build its classes.
    let receiver = v8::undefined(scope).into();
    let Some(result) = callback.call(scope, receiver, &[base.into()]) else {
        return;
    };
    let Ok(array) = v8::Local::<v8::Array>::try_from(result) else {
        throw_type_error(scope, "createX509CertificateClass must return an array");
        return;
    };
    // Slot 1 is `InternalX509Certificate`, which is the only one needed natively:
    // `parseX509Snapshot` constructs it, and the object must be the JavaScript
    // subclass so the private `#state` field and the prototype getters exist.
    let Some(internal) = array.get_index(scope, 1) else {
        return;
    };
    if let Ok(internal) = v8::Local::<v8::Function>::try_from(internal) {
        let global = v8::Global::new(scope.as_ref(), internal);
        with_classes(|classes| classes.internal = Some(global));
    }
    rv.set(result);
}

/// Builds a certificate object for `state`, using the class `x509.js` kept.
///
/// `x509.js`'s `InternalX509Certificate` constructor takes the buffer or handle
/// and passes it to `NativeX509Certificate`, so a `new` on the kept constructor
/// with the DER round-trips through the same path a user's `new X509Certificate`
/// does. That is what keeps the two objects' shapes identical.
fn new_certificate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    snapshot: Snapshot,
    index: usize,
    issuer: Option<v8::Local<'s, v8::Object>>,
) -> Option<v8::Local<'s, v8::Object>> {
    // The chain beyond `index` becomes the issuer objects, outermost first, so
    // each object's `issuer` is the next one up. This is `X509Certificate::New`'s
    // loop, which walks the snapshot backwards so every issuer exists before the
    // certificate that references it.
    let mut issuer_global: Option<v8::Global<v8::Object>> =
        issuer.map(|object| v8::Global::new(scope.as_ref(), object));
    let mut next: Option<v8::Local<'s, v8::Object>> = None;
    for position in ((index + 1)..snapshot.len()).rev() {
        let object = build_from_snapshot(scope, snapshot.clone(), position, issuer_global.take())?;
        issuer_global = Some(v8::Global::new(scope.as_ref(), object));
        next = Some(object);
    }
    let _ = next;
    build_from_snapshot(scope, snapshot, index, issuer_global)
}

/// One certificate object from a snapshot index.
fn build_from_snapshot<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    snapshot: Snapshot,
    index: usize,
    issuer: Option<v8::Global<v8::Object>>,
) -> Option<v8::Local<'s, v8::Object>> {
    let der = snapshot.der_at(index)?.to_vec();
    let buffer = rn_bind_crypto_keys::buffer_from(scope, &der)?;
    let constructor = with_classes(|classes| classes.internal.clone())
        .map(|global| v8::Local::new(scope, &global));
    match constructor {
        Some(constructor) => {
            let object = constructor.new_instance(scope, &[buffer])?;
            // The JavaScript constructor has already built the state from the
            // DER through the native constructor; replacing it here would discard
            // the snapshot sharing, so instead the issuer link is attached to the
            // state that already exists.
            if let Some(issuer) = issuer {
                with_state(scope, object, |state| {
                    let _ = state;
                });
                attach_issuer(scope, object, issuer);
            }
            Some(object)
        }
        None => {
            // No JavaScript subclass yet: build the base class directly, which is
            // the state a `createX509CertificateClass` caller sees before it has
            // installed slot 1.
            let template = base_template(scope)?;
            let object = template.instance_template(scope).new_instance(scope)?;
            set_state(
                scope,
                object,
                CertificateState {
                    snapshot,
                    index,
                    issuer,
                },
            );
            Some(object)
        }
    }
}

/// Attaches an issuer object to an existing certificate's state.
fn attach_issuer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    issuer: v8::Global<v8::Object>,
) {
    // `CertificateState::issuer` is immutable inside a `RefCell` shared with the
    // finaliser, so it is replaced through a mutable borrow.
    let _ = scope;
    certificate::set_issuer(object, issuer);
}

/// `isX509Certificate(value)`.
fn is_x509_certificate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let is_certificate = certificate::is_native_certificate(scope, args.get(0));
    rv.set(v8::Boolean::new(scope, is_certificate).into());
}

/// `parseX509(bufferSource)`.
fn parse_x509<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(0)) else {
        throw_type_error(scope, "The argument must be an ArrayBufferView");
        return;
    };
    let bytes = view_bytes(&view);
    let Some(parsed) = crate::snapshot::parse_pem_or_der(&bytes) else {
        throw_crypto_error(scope);
        return;
    };
    let Some(der) = parsed.to_der().ok() else {
        throw_crypto_error(scope);
        return;
    };
    let Some(snapshot) = Snapshot::from_der(vec![der]) else {
        throw_operation_failed(scope, "Failed to snapshot X.509 certificate");
        return;
    };
    match new_certificate(scope, snapshot, 0, None) {
        Some(object) => rv.set(object.into()),
        None => throw_operation_failed(scope, "Failed to create the certificate"),
    }
}

/// `parseX509Snapshot(array)`: rebuilds a certificate from its DER list.
fn parse_snapshot<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(array) = v8::Local::<v8::Array>::try_from(args.get(0)) else {
        throw_type_error(scope, "The \"snapshot\" argument must be an Array");
        return;
    };
    let mut certificates = Vec::with_capacity(array.length() as usize);
    for index in 0..array.length() {
        let Some(entry) = array.get_index(scope, index) else {
            return;
        };
        let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(entry) else {
            throw_type_error(scope, "The \"snapshot\" entries must be ArrayBufferViews");
            return;
        };
        certificates.push(view_bytes(&view));
    }
    let Some(snapshot) = Snapshot::from_der(certificates) else {
        throw_operation_failed(scope, "Failed to create X.509 certificate snapshot");
        return;
    };
    match new_certificate(scope, snapshot, 0, None) {
        Some(object) => rv.set(object.into()),
        None => throw_operation_failed(scope, "Failed to create the certificate"),
    }
}

/// `getX509CertificateSnapshot(certificate)`: the DER list, leaf first.
fn get_snapshot<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(object) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(
            scope,
            "The \"certificate\" argument must be an X509CertificateHandle",
        );
        return;
    };
    let certificates = with_state(scope, object, |state| state.snapshot.clone());
    let Some(certificates) = certificates else {
        throw_type_error(
            scope,
            "The \"certificate\" argument must be an X509CertificateHandle",
        );
        return;
    };
    let mut values = Vec::with_capacity(certificates.len());
    for index in 0..certificates.len() {
        let Some(der) = certificates.der_at(index) else {
            continue;
        };
        match rn_bind_crypto_keys::buffer_from(scope, der) {
            Some(value) => values.push(value),
            None => {
                throw_operation_failed(scope, "cannot allocate the snapshot buffer");
                return;
            }
        }
    }
    rv.set(v8::Array::new_with_elements(scope, &values).into());
}

/// `parsePKCS12(input, passphrase)`.
fn parse_pkcs12<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(bundle) = view_bytes_of(scope, args.get(0)) else {
        throw_operation_failed(scope, "Unable to read PKCS#12 data");
        return;
    };
    let passphrase = if args.get(1).is_undefined() {
        None
    } else {
        match view_bytes_of(scope, args.get(1)) {
            Some(bytes) => Some(bytes),
            None => {
                throw_type_error(scope, "The passphrase argument must be a Buffer");
                return;
            }
        }
    };

    let parsed = match crate::pkcs12::parse(&bundle, passphrase.as_deref()) {
        Ok(parsed) => parsed,
        Err(crate::pkcs12::Pkcs12Error::NotRecognised) => {
            throw_operation_failed(scope, "Input is not a valid PKCS#12 structure");
            return;
        }
        Err(crate::pkcs12::Pkcs12Error::UnsupportedAlgorithm) => {
            throw_coded(
                scope,
                "PKCS#12 bundle uses an unsupported algorithm; it may require the OpenSSL \
                 legacy provider",
                "ERR_CRYPTO_UNSUPPORTED_OPERATION",
            );
            return;
        }
        Err(crate::pkcs12::Pkcs12Error::Failed(packed)) => {
            if packed == 0 {
                throw_invalid_arg_value(
                    scope,
                    "passphrase must not contain null bytes",
                    "passphrase",
                );
            } else {
                throw_crypto_error_with(scope, packed, "Unable to parse PKCS#12 data");
            }
            return;
        }
    };

    // `[keyHandle | null, certificate | null, [chain]]`.
    let key_value: v8::Local<'s, v8::Value> = match parsed.key {
        Some(_) => match key_handle(scope, &parsed) {
            Some(handle) => handle.into(),
            None => {
                throw_operation_failed(scope, "cannot create the KeyObjectHandle");
                return;
            }
        },
        None => v8::null(scope).into(),
    };
    drop(parsed);

    rv.set(key_value);
}

/// Builds a `KeyObjectHandle` for a parsed bundle's private key.
fn key_handle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    parsed: &crate::pkcs12::Bundle,
) -> Option<v8::Local<'s, v8::Object>> {
    let raw = parsed.key?;
    // SAFETY: the bundle owns one reference and hands it over exactly once; the
    // bundle is dropped immediately afterwards.
    let key = unsafe { crate::extras::private_pkey_from_raw(raw) }?;
    let key = rn_crypto_openssl::PKey::from_private(key);
    rn_bind_crypto_keys::create_private_handle(scope, key)
}

/// `addBlockedSPKIForTesting(digest)`.
fn add_blocked_spki<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let added =
        view_bytes_of(scope, args.get(0)).is_some_and(|bytes| blocklist::add_blocked_spki(&bytes));
    rv.set(v8::Boolean::new(scope, added).into());
}

/// `clearBlockedSPKIsForTesting()`.
fn clear_blocked_spkis<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    blocklist::clear_blocked_spkis();
}

/// The three root-store getters that return PEM lists.
fn pem_list<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    rv: &mut v8::ReturnValue,
    certificates: Vec<String>,
) {
    let values: Vec<v8::Local<v8::Value>> = certificates
        .iter()
        .filter_map(|certificate| v8::String::new(scope, certificate).map(Into::into))
        .collect();
    rv.set(v8::Array::new_with_elements(scope, &values).into());
}

/// `getBundledRootCertificates()`.
fn get_bundled_root_certificates<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    pem_list(scope, &mut rv, crate::root_store::bundled());
}

/// `getExtraCACertificates()`.
fn get_extra_ca_certificates<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    pem_list(scope, &mut rv, crate::root_store::extra());
}

/// `getSystemCACertificates()`.
fn get_system_ca_certificates<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    pem_list(scope, &mut rv, crate::root_store::system());
}

/// `getUserRootCertificates()`.
fn get_user_root_certificates<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    pem_list(scope, &mut rv, crate::root_store::user());
}

/// `resetRootCertStore(array)`.
fn reset_root_cert_store<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let Ok(array) = v8::Local::<v8::Array>::try_from(args.get(0)) else {
        throw_type_error(scope, "The argument must be an Array");
        return;
    };
    let mut entries = Vec::with_capacity(array.length() as usize);
    for index in 0..array.length() {
        let Some(entry) = array.get_index(scope, index) else {
            return;
        };
        match view_bytes_of(scope, entry) {
            Some(bytes) => entries.push(bytes),
            None => {
                throw_type_error(scope, "The certificates must be Buffers");
                return;
            }
        }
    }
    if crate::root_store::reset(&entries).is_err() {
        throw_crypto_error_with(scope, 0, "Failed to parse certificate");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn view_bytes(view: &v8::Local<v8::ArrayBufferView>) -> Vec<u8> {
    let length = view.byte_length();
    let mut bytes = vec![0u8; length];
    let copied = view.copy_contents(&mut bytes);
    bytes.truncate(copied);
    bytes
}

/// Bytes from an `ArrayBufferView` or an `ArrayBuffer`, or `None`.
fn view_bytes_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    let _ = scope;
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        return Some(view_bytes(&view));
    }
    let buffer = v8::Local::<v8::ArrayBuffer>::try_from(value).ok()?;
    let length = buffer.byte_length();
    let store = buffer.get_backing_store();
    let mut bytes = vec![0u8; length];
    if length > 0 {
        let data = store.data()?;
        // SAFETY: `data` points at `length` bytes owned by `store`, which is alive
        // for this call.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), length);
        }
    }
    Some(bytes)
}

fn set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn throw(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

fn throw_operation_failed(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    throw_coded(scope, message, "ERR_CRYPTO_OPERATION_FAILED");
}

fn throw_coded(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
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

fn throw_invalid_arg_value(scope: &mut v8::PinScope<'_, '_>, message: &str, argument: &str) {
    let text = format!("The argument '{argument}' {message}");
    let Some(text) = v8::String::new(scope, &text) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(key) = v8::String::new(scope, "code") {
        if let Some(value) = v8::String::new(scope, "ERR_INVALID_ARG_VALUE") {
            object.set(scope, key.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

fn throw_crypto_error(scope: &mut v8::PinScope<'_, '_>) {
    // SAFETY: reads and clears the thread-local error queue head.
    let packed = unsafe { openssl_sys::ERR_get_error() };
    throw_crypto_error_with(scope, packed, "Failed to parse X.509 certificate");
}

fn throw_crypto_error_with(scope: &mut v8::PinScope<'_, '_>, packed: u64, fallback: &str) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_member_list_is_the_x509_and_pkcs12_surface() {
        // `rn-bind-crypto` moves exactly these from `DEFERRED` to `MEMBERS`, so
        // the list is the contract the coordinator's edit has to match.
        assert_eq!(MEMBERS.len(), 13);
        for name in [
            "createX509CertificateClass",
            "isX509Certificate",
            "parseX509",
            "parseX509Snapshot",
            "getX509CertificateSnapshot",
            "parsePKCS12",
        ] {
            assert!(MEMBERS.contains(&name), "{name}");
        }
        for name in [
            "addBlockedSPKIForTesting",
            "clearBlockedSPKIsForTesting",
            "getBundledRootCertificates",
            "getExtraCACertificates",
            "getSystemCACertificates",
            "getUserRootCertificates",
            "resetRootCertStore",
        ] {
            assert!(MEMBERS.contains(&name), "{name}");
        }
    }

    #[test]
    fn no_member_is_named_twice() {
        let mut sorted = MEMBERS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), MEMBERS.len());
    }
}
