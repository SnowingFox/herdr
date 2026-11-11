//! The `KeyObject` family for `internalBinding('crypto')`.
//!
//! `src/crypto/crypto_keys.cc`, `crypto_keygen.cc` and `crypto_spkac.cc` are the
//! translation units this mirrors. The first is 2,230 lines and is where nearly
//! every asymmetric operation starts: `createSecretKey`, `createPublicKey`,
//! `createPrivateKey`, `KeyObject.export()`, and the handle the WebCrypto layer
//! wraps a key in.
//!
//! # What this crate installs
//!
//! | member | what it is |
//! | --- | --- |
//! | `KeyObjectHandle` | the native handle class |
//! | `createNativeKeyObjectClass` | builds the `KeyObject` base class |
//! | `getKeyObjectSlots` | `[type, handle]` in one call |
//! | `isKeyObject` | the brand check behind `util.types.isKeyObject` |
//! | `SecretKeyGenJob` | `crypto.generateKeySync` |
//! | `RsaKeyPairGenJob`, `EcKeyPairGenJob`, `NamedKeyPairGenJob` | `crypto.generateKeyPair*` |
//!
//! The first four are the class protocol and cannot be split: `keys.js` calls
//! `createNativeKeyObjectClass` at module scope, so the namespace does not load
//! without it.
//!
//! # Why it is a separate crate
//!
//! `internalBinding('crypto')` is one namespace object assembled from a dozen
//! translation units, because that is what `src/node_crypto.cc` does: it calls
//! `Initialize` on each class and they all land on one `target`. The crate split
//! follows the *translation unit*, not the namespace, so this crate exports
//! [`install_classes`] and `rn-bind-crypto` calls it once. That keeps the
//! namespace's `MEMBERS`/`DEFERRED` partition owned by one file.
//!
//! The export is deliberately not named `register*`: `tools/regen-bindings.sh`
//! discovers namespace providers by grepping each crate for a `register`
//! function declaration, and a helper matching that substring is treated as a
//! provider — which then fails the `rn-bindings` build on a missing symbol.
//!
//! # State ownership
//!
//! A key lives in a `RefCell<KeyData>` behind an internal field, freed by a
//! `Weak::with_guaranteed_finalizer`. V8's GC is the only thing that decides when
//! a key dies, so a finalizer is the only correct place to release it.
//! `KeyData` is itself reference counted, which is what makes a public view of a
//! private key — `createPublicKey(privateKey)` — free rather than a copy.

mod args;
mod errors;
mod gen;
mod handle;
mod install;
mod jobs;
mod state;
mod templates;

pub use handle::read_key_from_js;
pub use install::{buffer_from, install_classes, MEMBERS};
pub use state::{KeyData, KeyType};

/// Builds a `KeyObjectHandle` over a public key, for crates that hand one back.
///
/// `X509Certificate#publicKey()` and `parsePKCS12` both return a handle, and both
/// are outside this crate. Exposing the constructor is deliberate: the alternative
/// is either a second `KeyObjectHandle` implementation or for X.509 to reach into
/// this crate's internals, and a duplicate handle class would break
/// `instanceof KeyObjectHandle` — which `keys.js` checks.
pub fn create_public_handle<'s>(
    scope: &mut rn_v8_sys::v8::PinScope<'s, '_>,
    key: rn_crypto_openssl::PKey,
) -> Option<rn_v8_sys::v8::Local<'s, rn_v8_sys::v8::Object>> {
    let data = KeyData::asymmetric(KeyType::Public, key)?;
    install::create_handle(scope, data)
}

/// Builds a `KeyObjectHandle` over a private key, for `parsePKCS12`.
///
/// The same reasoning as [`create_public_handle`]: the handle class must be this
/// crate's, because `keys.js` checks `handle instanceof KeyObjectHandle`.
pub fn create_private_handle<'s>(
    scope: &mut rn_v8_sys::v8::PinScope<'s, '_>,
    key: rn_crypto_openssl::PKey,
) -> Option<rn_v8_sys::v8::Local<'s, rn_v8_sys::v8::Object>> {
    let data = KeyData::asymmetric(KeyType::Private, key)?;
    install::create_handle(scope, data)
}

/// Reads the `KeyData` a `KeyObjectHandle` holds.
///
/// `X509Certificate#checkPrivateKey()` and `#verify()` take a handle from
/// `x509.js`, which obtained it with `getKeyObjectHandle(key)`. This is the one
/// supported way to read it without exposing the handle's internal fields.
pub fn key_of_handle(
    scope: &mut rn_v8_sys::v8::PinScope<'_, '_>,
    handle: rn_v8_sys::v8::Local<rn_v8_sys::v8::Object>,
) -> Option<KeyData> {
    templates::with_key_data(scope, handle, KeyData::clone)
}

/// The `kKeyType*`, `kCryptoJob*` and curve-encoding values this crate reads.
///
/// Duplicated from `rn-bind-crypto`'s constant table rather than imported,
/// because the dependency runs the other way: that crate installs the namespace
/// object and this one fills part of it. The values are an internal protocol
/// between `keys.js` and the binding, so a drift would be a silent arg-shift bug;
/// `rn-bind-crypto`'s tests pin the numbers and this crate's `args` tests pin its
/// reading of them.
pub mod constants {
    /// `kKeyTypeSecret`.
    pub const K_KEY_TYPE_SECRET: i32 = 1;
    /// `kKeyTypePublic`.
    pub const K_KEY_TYPE_PUBLIC: i32 = 2;
    /// `kKeyTypePrivate`.
    pub const K_KEY_TYPE_PRIVATE: i32 = 3;

    /// `kCryptoJobAsync`.
    pub const K_CRYPTO_JOB_ASYNC: i32 = 0;
    /// `kCryptoJobSync`.
    pub const K_CRYPTO_JOB_SYNC: i32 = 1;
    /// `kCryptoJobWebCrypto`.
    pub const K_CRYPTO_JOB_WEB_CRYPTO: i32 = 2;

    /// `kKeyVariantRSA_SSA_PKCS1_v1_5`.
    pub const K_KEY_VARIANT_RSA_SSA_PKCS1_V1_5: i32 = 0;
    /// `kKeyVariantRSA_PSS`.
    pub const K_KEY_VARIANT_RSA_PSS: i32 = 1;
    /// `kKeyVariantRSA_OAEP`.
    pub const K_KEY_VARIANT_RSA_OAEP: i32 = 2;

    /// `OPENSSL_EC_NAMED_CURVE`.
    pub const OPENSSL_EC_NAMED_CURVE: i32 = 1;
    /// `OPENSSL_EC_EXPLICIT_CURVE`.
    pub const OPENSSL_EC_EXPLICIT_CURVE: i32 = 0;
}
