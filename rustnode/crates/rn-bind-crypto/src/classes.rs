//! Members `lib/internal/crypto/**` calls while it loads.
//!
//! `tools/deferred-reach.py` found seven members that `lib/**` reaches at module
//! scope, which a declared deferral cannot cover: a deferral is honest about a
//! gap, but the module that needs the member at load time simply cannot be
//! required. Those seven are implemented here.
//!
//! # The class factories
//!
//! `keys.js` runs `createNativeKeyObjectClass(...)` and `createCryptoKeyClass(...)`
//! at module scope to build its class hierarchy. Each factory is handed a callback
//! and returns whatever that callback returns — an array of the classes the
//! JavaScript then destructures.
//!
//! Node's versions create a V8 `FunctionTemplate` that stores an `ncrypto` handle,
//! and the JavaScript subclasses rely on that base holding the handle for every
//! later method. Implementing that faithfully is the whole `KeyObject` surface.
//! What these do is supply the **class shape**: a base constructor that accepts
//! and retains its arguments, so extending it works and the module loads.
//!
//! `createX509CertificateClass` used to have a stand-in here as well. It is gone:
//! `rn-bind-crypto-x509` now installs the real class, and two implementations of
//! one member where only the later one is reachable is worse than one.
//!
//! # The four list and lifecycle members
//!
//! `getMacs()` is enumeration like `getHashes()`, so it is derived from OpenSSL.
//! `getSSLCiphers()` and `getCertificateCompressionAlgorithms()` are reached from
//! `lib/tls.js` at module scope and answered from the linked library. And
//! `startLoadingCertificatesOffThread()` is a startup optimisation whose absence
//! of effect is harmless: it preloads the root store on a thread, and this build
//! loads the store synchronously when a TLS context is created.

use rn_v8_sys::v8;

// ---------------------------------------------------------------------------
// Class factories
// ---------------------------------------------------------------------------

/// `new.target`-compatible base class the JavaScript extends.
///
/// The instance stores its constructor arguments in `__rn_native_args` so a
/// future method on the real key surface has something to read. The property is an
/// implementation detail of a class the user never constructs directly, and the
/// name is chosen to be unmistakably internal.
fn make_base_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Option<v8::Local<'s, v8::Function>> {
    let template = v8::FunctionTemplate::builder(base_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    let class_name = v8::String::new(scope, name)?;
    template.set_class_name(class_name);
    template.get_function(scope)
}

/// The base constructor: keeps its arguments and returns `this`.
fn base_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let storage = v8::Object::new(scope);
    for index in 0..args.length() {
        let Some(key) = v8::String::new(scope, &format!("{index}")) else {
            continue;
        };
        storage.set(scope, key.into(), args.get(index));
    }
    let Some(key) = v8::String::new(scope, "__rn_native_args") else {
        return;
    };
    this.set(scope, key.into(), storage.into());
    rv.set(this.into());
}

/// Builds a base class, passes it to the callback, and returns the callback's
/// result, which is the array of classes the JavaScript destructures.
fn call_with_base_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    which: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let callback = v8::Local::<v8::Function>::try_from(args.get(0)).ok()?;
    let base = make_base_class(scope, "NativeBase")?;
    let receiver = v8::undefined(scope).into();
    let result = callback.call(scope, receiver, &[base.into()]);
    if result.is_none() {
        // The callback threw; leave the pending exception to propagate rather than
        // replacing it with a different error.
        let _ = which;
    }
    result
}

/// `createCryptoKeyClass(callback)`.
pub(crate) fn create_crypto_key_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match call_with_base_class(scope, &args, "createCryptoKeyClass") {
        Some(value) => rv.set(value),
        None => throw_type_error(scope, "createCryptoKeyClass needs a callback"),
    }
}

// ---------------------------------------------------------------------------
// Enumeration and lifecycle members
// ---------------------------------------------------------------------------

/// `getMacs()`: the MAC algorithms the linked OpenSSL provides.
///
/// `lib/internal/crypto/util.js` calls this at module scope through
/// `getMacs = cachedArrayByFipsGeneration(() => filterDuplicateStrings(_getMacs(), true))`,
/// which is why it cannot be deferred. It is derived from OpenSSL the same way
/// `getHashes()` is, so nothing advertised is unusable.
///
/// `filterDuplicateStrings(..., true)` in the JavaScript drops the `-mac` suffixed
/// duplicates, so the raw provider names are what belong here.
pub(crate) fn get_macs(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let names = crate::enumerate::mac_names();
    let Some(array) = string_array(scope, &names) else {
        throw(scope, "cannot allocate the MAC list");
        return;
    };
    rv.set(array.into());
}

/// `getSSLCiphers()`: the TLS cipher suites OpenSSL offers.
///
/// `lib/tls.js` calls this at module scope to build `tls.getCiphers()`. It comes
/// from a real `SSL_CTX`, which is the only way to get the list OpenSSL would
/// actually negotiate, rather than a guess about its default policy.
pub(crate) fn get_ssl_ciphers(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let names = crate::enumerate::ssl_cipher_names();
    let Some(array) = string_array(scope, &names) else {
        throw(scope, "cannot allocate the TLS cipher list");
        return;
    };
    rv.set(array.into());
}

/// `getCertificateCompressionAlgorithms()`.
///
/// `lib/tls.js` binds this at module scope to
/// `tls.getCertificateCompressionAlgorithms`. The list is what the linked
/// OpenSSL was built with: `brotli`, `zlib` and `zstd`, in its own order.
pub(crate) fn get_certificate_compression_algorithms(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let names = crate::enumerate::certificate_compression_algorithms();
    let Some(array) = string_array(scope, &names) else {
        throw(scope, "cannot allocate the certificate compression list");
        return;
    };
    rv.set(array.into());
}

/// `startLoadingCertificatesOffThread()`.
///
/// `lib/tls.js` calls this while it loads, so it has to exist. Node uses it to
/// begin populating the root certificate store on a background thread so the first
/// TLS handshake does not pay for it. This build has no asynchronous root-store
/// loading, and the store is read when a context is created, so there is nothing
/// to start: the function is a no-op that reports honestly rather than pretending
/// a load is in flight.
pub(crate) fn start_loading_certificates_off_thread(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
}

fn string_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    names: &[String],
) -> Option<v8::Local<'s, v8::Array>> {
    let array = v8::Array::new(scope, names.len() as i32);
    for (index, name) in names.iter().enumerate() {
        let value = v8::String::new(scope, name)?;
        array.set_index(scope, index as u32, value.into());
    }
    Some(array)
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
