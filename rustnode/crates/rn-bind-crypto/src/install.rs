//! Building the `internalBinding('crypto')` object.
//!
//! The JavaScript in `vendor/libnode-js/lib/crypto.js` and
//! `lib/internal/crypto/**` is unchanged Node code. It owns every option check,
//! error message and stream decision; this crate is only the native handle it
//! drives. The shapes below come from those call sites, which are the authority
//! this has to match:
//!
//! * `new _Hash(algorithm, xofLen, algorithmId, cache[, functionName,
//!   customization])` for `crypto.createHash`, then `update(data, encoding)`
//!   returning truthy and `digest(encoding)` returning the result.
//! * `new _Hmac()` then `init(algorithm, key)`, then the same `update`/`digest`.
//! * `randomFillSyncImpl(buffer, offset, size)` filling in place, and
//!   `secureBuffer(size)` for the random-UUID batch buffers.
//! * `getHashes()`, `getCiphers()`, `getCurves()` returning arrays derived from
//!   the linked OpenSSL.
//! * `timingSafeEqual(a, b)` throwing on a length mismatch.
//!
//! # Why the constants are here and not computed
//!
//! The `kKeyFormat*`, `kKeyType*` and `kCryptoJob*` numbers are an internal
//! protocol between this crate and `lib/internal/crypto/**`: they appear only as
//! arguments back into the binding, never on a public API. Their values are
//! Node's, copied from `node_crypto.h`, because the JavaScript layer compares
//! them against what it passed rather than against anything this crate reports.
//!
//! # Encoding of `digest()` and `update()`
//!
//! `digest('hex')` has to return a hex string and `digest()` a `Buffer`.
//! `lib/internal/crypto/hash.js` passes the *normalised* encoding name and also
//! passes `encodingsMap[normalized]`, an internal numeric encoding id. Both paths
//! are supported: the string is what the public API sends, and the numeric id is
//! what `oneShotDigest` sends.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::encoding;
use crate::engine::{self, CryptoError, Digest, Hmac};

/// Members exposed on the namespace object, matching `contracts/crypto.json`.
///
/// The list is the subset this landing implements. `contracts/crypto.json`
/// records 144 members; the rest are named in [`DEFERRED`] with a reason, so the
/// gap is declared rather than hidden.
pub const MEMBERS: &[&str] = &[
    // Hashing. `HashJob`/`oneShotDigest` are the one-shot and WebCrypto paths;
    // `KangarooTwelveJob` and `TurboShakeJob` are separate XOF algorithms that
    // are not wired up and are declared deferred.
    "Hash",
    "HashJob",
    "Hmac",
    "HmacJob",
    "oneShotDigest",
    // Key-derivation jobs. `crypto.pbkdf2`/`scrypt`/`hkdf` build one and call
    // `run()`, in both the sync and async forms.
    "PBKDF2Job",
    "ScryptJob",
    "HKDFJob",
    // Diffie-Hellman. Installed by `rn-bind-crypto-dh`, which owns
    // `src/crypto/crypto_dh.cc`; the classes are on this object because that is
    // the namespace Node aggregates them onto.
    "DiffieHellman",
    "DiffieHellmanGroup",
    // The cipher surface. Installed by `rn-bind-crypto-cipher`, which owns
    // `src/crypto/crypto_cipher.cc` and `crypto_aes.cc`. `getCipherInfo` is in
    // that translation unit too, not in the enumeration module, so it comes with
    // them rather than with `getCiphers`.
    "CipherBase",
    "AESCipherJob",
    "getCipherInfo",
    // The `KeyObject` family. Installed by `rn-bind-crypto-keys`, which owns
    // `src/crypto/crypto_keys.cc`. `KeyObjectHandle` is the handle class and
    // `isKeyObject`/`getKeyObjectSlots` are the two queries over it;
    // `createNativeKeyObjectClass` is already listed above because `lib/tls.js`
    // reaches it at module scope, and the crate now supplies its real body rather
    // than the base-class stand-in that used to live here.
    "KeyObjectHandle",
    "getKeyObjectSlots",
    "isKeyObject",
    // The key-generation jobs. `SecretKeyGenJob` and the three key-pair jobs the
    // traditional API uses are here; `DsaKeyPairGenJob` and `DhKeyPairGenJob`
    // stay deferred with their own slices.
    "SecretKeyGenJob",
    "RsaKeyPairGenJob",
    "EcKeyPairGenJob",
    "NamedKeyPairGenJob",
    // The signature surface, installed by `rn-bind-crypto-sign` from
    // `src/crypto/crypto_sig.cc` and `crypto_rsa.cc`. `Sign`/`Verify` are the
    // streaming classes `lib/internal/crypto/sig.js` drives; `SignJob` is the
    // one-shot `crypto.sign`/`crypto.verify` form and `RSACipherJob` the RSA
    // encrypt/decrypt job `rsa.js` builds for RSA-OAEP.
    "Sign",
    "Verify",
    "SignJob",
    "RSACipherJob",
    // The `RSAKeyVariant` values `keygen.js` puts in `RsaKeyPairGenJob`'s second
    // slot. Without them the argument is `undefined`, the variant defaults to
    // PKCS#1, and every `rsa-pss` generation silently produces a plain RSA key.
    "kKeyVariantRSA_SSA_PKCS1_v1_5",
    "kKeyVariantRSA_PSS",
    "kKeyVariantRSA_OAEP",
    // Random.
    "randomFillSync",
    "secureBuffer",
    "secureHeapUsed",
    // Enumeration, all derived from the linked OpenSSL.
    "getCiphers",
    "getCurves",
    "getHashes",
    "getCachedAliases",
    "getMacs",
    // Reached at module scope by `lib/tls.js` and `lib/internal/crypto/util.js`,
    // so they are load-bearing for `require('crypto')` rather than optional.
    "getSSLCiphers",
    "getCertificateCompressionAlgorithms",
    "startLoadingCertificatesOffThread",
    "createNativeKeyObjectClass",
    "createCryptoKeyClass",
    // The X.509 surface, installed by `rn-bind-crypto-x509`, which owns
    // `src/crypto/crypto_x509.cc` and `crypto_pkcs12.cc`. `x509.js` runs
    // `createX509CertificateClass` at module scope and destructures the rest, so
    // these are load-bearing for `require('crypto')`.
    "createX509CertificateClass",
    "isX509Certificate",
    "parseX509",
    "parseX509Snapshot",
    "getX509CertificateSnapshot",
    "parsePKCS12",
    // The SPKI blocklist's test hooks and the root-store accessors. They live in
    // `crypto_context.cc` rather than `crypto_x509.cc`, but the list is X.509
    // policy and `lib/tls.js` reads the root store before any `SecureContext`
    // exists, so they land with this slice.
    "addBlockedSPKIForTesting",
    "clearBlockedSPKIsForTesting",
    "getBundledRootCertificates",
    "getExtraCACertificates",
    "getSystemCACertificates",
    "getUserRootCertificates",
    "resetRootCertStore",
    // Comparison and feature queries.
    "timingSafeEqual",
    "getFipsCrypto",
    "getFipsCryptoGeneration",
    "getOpenSSLSecLevelCrypto",
    // Constants the JavaScript layer passes straight back in.
    "kCryptoJobAsync",
    "kCryptoJobSync",
    "kCryptoJobWebCrypto",
    "kKeyEncodingPKCS1",
    "kKeyEncodingPKCS8",
    "kKeyEncodingSEC1",
    "kKeyEncodingSPKI",
    "kKeyFormatDER",
    "kKeyFormatJWK",
    "kKeyFormatPEM",
    "kKeyFormatRawPrivate",
    "kKeyFormatRawPublic",
    "kKeyFormatRawSeed",
    "kKeyFormatStore",
    "kKeyTypePrivate",
    "kKeyTypePublic",
    "kKeyTypeSecret",
    "kSigEncDER",
    "kSigEncP1363",
    "kSignJobModeSign",
    "kSignJobModeVerify",
    "kWebCryptoCipherDecrypt",
    "kWebCryptoCipherEncrypt",
    "kWebCryptoKeyFormatJWK",
    "kWebCryptoKeyFormatPKCS8",
    "kWebCryptoKeyFormatRaw",
    "kWebCryptoKeyFormatSPKI",
    "RSA_PKCS1_PSS_PADDING",
    "OPENSSL_EC_EXPLICIT_CURVE",
    "OPENSSL_EC_NAMED_CURVE",
    // Hostname-verification flags. `lib/internal/crypto/x509.js` builds its
    // option table from these, so they have to be numbers even though the X.509
    // classes themselves are deferred. Values are `openssl/x509v3.h`'s.
    "X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT",
    "X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS",
    "X509_CHECK_FLAG_NEVER_CHECK_SUBJECT",
    "X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS",
    "X509_CHECK_FLAG_NO_WILDCARDS",
    "X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS",
];

/// Members `contracts/crypto.json` records that this crate does not install yet.
///
/// Each entry is a real gap with the reason it is a gap, not a placeholder. The
/// two groups are the ones that need machinery this landing does not have:
/// asymmetric keys and everything built on them (the `KeyObject` family, X.509,
/// the `*Job` classes that run on the threadpool) and the AEAD/streaming cipher
/// handles that need an async completion path.
///
/// `lib/crypto.js` reads most of these at module scope through a destructuring,
/// which binds `undefined` harmlessly, so the namespace loads and the hashing,
/// HMAC, random and enumeration surface works. A member that is *called* while a
/// module loads is a different matter; `tools/deferred-reach.py` checks exactly
/// that and is part of the gate.
pub const DEFERRED: &[(&str, &str)] = &[
    (
        "Argon2Job",
        "Argon2 needs OpenSSL's Argon2 provider, which `openssl-src` does not build; \
         `crypto.argon2` must report ERR_CRYPTO_ARGON2_NOT_SUPPORTED, as Node does when the \
         provider is absent.",
    ),
    (
        "ChaCha20Poly1305CipherJob",
        "WebCrypto ChaCha20-Poly1305 is a threadpool job, deferred with the WebCrypto surface.",
    ),
    (
        "CheckPrimeJob",
        "Prime checking is a threadpool job built on BN primitives; the sync half is deferred \
         with the rest of the key surface.",
    ),
    (
        "DHBitsJob",
        "The async `crypto.diffieHellman()` form is a CryptoJob; the sync `run()` path \
         and the shared `CryptoJob` machinery land with the rest of the job family.",
    ),
    (
        "DhKeyPairGenJob",
        "Key generation and DH share the asymmetric key surface, deferred with KeyObject.",
    ),
    (
        "DsaKeyPairGenJob",
        "Key generation is part of the asymmetric key surface, deferred with KeyObject.",
    ),
    (
        "ECDH",
        "ECDH is part of the asymmetric key surface, deferred with KeyObject.",
    ),
    (
        "ECDHConvertKey",
        "ECDH key conversion needs the EC key surface, deferred with KeyObject.",
    ),
    (
        "KEMDecapsulateJob",
        "ML-KEM decapsulation needs the KeyObject surface and OpenSSL's KEM provider.",
    ),
    (
        "KEMEncapsulateJob",
        "ML-KEM encapsulation needs the KeyObject surface and OpenSSL's KEM provider.",
    ),
    (
        "KangarooTwelveJob",
        "KT128/KT256 are not in the OpenSSL build `openssl-src` produces.",
    ),
    (
        "KmacJob",
        "KMAC needs the KeyObject surface for its key and is not in this OpenSSL build.",
    ),
    ("Mac", "createMac needs the KeyObject surface for its key."),
    (
        "RandomBytesJob",
        "The async `randomBytes` path needs the event loop; `randomBytes` works because \
         `lib/internal/crypto/random.js` implements it over the sync fill.",
    ),
    (
        "RandomPrimeJob",
        "Prime generation is part of the key surface, deferred with KeyObject.",
    ),
    (
        "SecureContext",
        "A TLS secure context needs the tls binding; this crate does not own it.",
    ),
    (
        "TurboShakeJob",
        "TurboSHAKE is not in the OpenSSL build `openssl-src` produces.",
    ),
    (
        "certExportChallenge",
        "SPKAC challenge extraction needs the certificate surface, which is deferred with X.509.",
    ),
    (
        "certExportPublicKey",
        "SPKAC public-key extraction needs the certificate surface, deferred with X.509.",
    ),
    (
        "certVerifySpkac",
        "SPKAC verification needs the certificate surface, deferred with X.509.",
    ),
    (
        "getCachedMacAliases",
        "`getMacs()` needs the MAC surface; the hash alias cache is installed.",
    ),
    (
        "getCryptoKeySlots",
        "Exposes WebCrypto key slots, deferred with CryptoKey.",
    ),
    (
        "isCryptoKey",
        "The CryptoKey type test needs the WebCrypto CryptoKey class, which is deferred.",
    ),
    (
        "isKeyAlgorithmAvailable",
        "Asks whether a named key algorithm is usable; deferred with the key surface.",
    ),
    (
        "kKEMDecapsulate",
        "ML-KEM decapsulation mode flag; the KEM jobs it selects are deferred.",
    ),
    (
        "kKEMEncapsulate",
        "ML-KEM encapsulation mode flag; the KEM jobs it selects are deferred.",
    ),
    (
        "kKeyVariantAES_CBC_128",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_CBC_192",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_CBC_256",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_CTR_128",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_CTR_192",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_CTR_256",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_GCM_128",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_GCM_192",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_GCM_256",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_KW_128",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_KW_192",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_KW_256",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_OCB_128",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_OCB_192",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kKeyVariantAES_OCB_256",
        "WebCrypto AES key variants, deferred with the WebCrypto surface.",
    ),
    (
        "kTypeArgon2d",
        "Argon2 is not built into the OpenSSL this crate links.",
    ),
    (
        "kTypeArgon2i",
        "Argon2 is not built into the OpenSSL this crate links.",
    ),
    (
        "kTypeArgon2id",
        "Argon2 is not built into the OpenSSL this crate links.",
    ),
    (
        "privateDecrypt",
        "RSA decryption needs the KeyObject surface.",
    ),
    (
        "privateEncrypt",
        "RSA encryption needs the KeyObject surface.",
    ),
    (
        "publicDecrypt",
        "RSA decryption needs the KeyObject surface.",
    ),
    (
        "publicEncrypt",
        "RSA encryption needs the KeyObject surface.",
    ),
    (
        "setFipsCrypto",
        "FIPS mode needs a validated provider; `getFipsCrypto` reports false truthfully and \
         turning it on cannot succeed.",
    ),
    (
        "setupFipsIndicatorChannel",
        "FIPS indicator events, deferred with setFipsCrypto.",
    ),
    (
        "testFipsCrypto",
        "FIPS indicator testing, deferred with FIPS.",
    ),
];

/// The numeric constants `lib/internal/crypto/**` passes back into the binding.
///
/// Values are `node_crypto.h`'s. They are an internal protocol only: nothing
/// outside this crate and that JavaScript ever sees them.
mod constants {
    /// `kCryptoJobAsync`.
    pub const K_CRYPTO_JOB_ASYNC: i32 = 0;
    /// `kCryptoJobSync`.
    pub const K_CRYPTO_JOB_SYNC: i32 = 1;
    /// `kCryptoJobWebCrypto`.
    pub const K_CRYPTO_JOB_WEB_CRYPTO: i32 = 2;

    /// `kKeyEncodingPKCS1`.
    pub const K_KEY_ENCODING_PKCS1: i32 = 1;
    /// `kKeyEncodingPKCS8`.
    pub const K_KEY_ENCODING_PKCS8: i32 = 2;
    /// `kKeyEncodingSEC1`.
    pub const K_KEY_ENCODING_SEC1: i32 = 3;
    /// `kKeyEncodingSPKI`.
    pub const K_KEY_ENCODING_SPKI: i32 = 4;

    /// `kKeyFormatDER`.
    pub const K_KEY_FORMAT_DER: i32 = 1;
    /// `kKeyFormatPEM`.
    pub const K_KEY_FORMAT_PEM: i32 = 2;
    /// `kKeyFormatJWK`.
    pub const K_KEY_FORMAT_JWK: i32 = 3;
    /// `kKeyFormatRawPublic`.
    pub const K_KEY_FORMAT_RAW_PUBLIC: i32 = 4;
    /// `kKeyFormatRawPrivate`.
    pub const K_KEY_FORMAT_RAW_PRIVATE: i32 = 5;
    /// `kKeyFormatRawSeed`.
    pub const K_KEY_FORMAT_RAW_SEED: i32 = 6;
    /// `kKeyFormatStore`.
    pub const K_KEY_FORMAT_STORE: i32 = 7;

    /// `kKeyTypeSecret`.
    pub const K_KEY_TYPE_SECRET: i32 = 1;
    /// `kKeyTypePublic`.
    pub const K_KEY_TYPE_PUBLIC: i32 = 2;
    /// `kKeyTypePrivate`.
    pub const K_KEY_TYPE_PRIVATE: i32 = 3;

    /// `kSigEncDER`.
    pub const K_SIG_ENC_DER: i32 = 1;
    /// `kSigEncP1363`.
    pub const K_SIG_ENC_P1363: i32 = 2;

    /// `kSignJobModeSign`.
    /// `RSAKeyVariant` from `crypto_rsa.h`, which `keygen.js` passes as the
    /// second argument of `RsaKeyPairGenJob`.
    pub const K_KEY_VARIANT_RSA_SSA_PKCS1_V1_5: i32 = 0;
    /// `kKeyVariantRSA_PSS`.
    pub const K_KEY_VARIANT_RSA_PSS: i32 = 1;
    /// `kKeyVariantRSA_OAEP`.
    pub const K_KEY_VARIANT_RSA_OAEP: i32 = 2;

    /// `kSignJobModeSign`.
    pub const K_SIGN_JOB_MODE_SIGN: i32 = 1;
    /// `kSignJobModeVerify`.
    pub const K_SIGN_JOB_MODE_VERIFY: i32 = 2;

    /// `kWebCryptoCipherEncrypt`.
    pub const K_WEBCRYPTO_CIPHER_ENCRYPT: i32 = 1;
    /// `kWebCryptoCipherDecrypt`.
    pub const K_WEBCRYPTO_CIPHER_DECRYPT: i32 = 2;

    /// `kWebCryptoKeyFormatRaw`.
    pub const K_WEBCRYPTO_KEY_FORMAT_RAW: i32 = 1;
    /// `kWebCryptoKeyFormatPKCS8`.
    pub const K_WEBCRYPTO_KEY_FORMAT_PKCS8: i32 = 2;
    /// `kWebCryptoKeyFormatSPKI`.
    pub const K_WEBCRYPTO_KEY_FORMAT_SPKI: i32 = 3;
    /// `kWebCryptoKeyFormatJWK`.
    pub const K_WEBCRYPTO_KEY_FORMAT_JWK: i32 = 4;

    /// `RSA_PKCS1_PSS_PADDING`, from OpenSSL's `rsa.h`.
    pub const RSA_PKCS1_PSS_PADDING: i32 = 6;
    /// `OPENSSL_EC_NAMED_CURVE`.
    pub const OPENSSL_EC_NAMED_CURVE: i32 = 1;
    /// `OPENSSL_EC_EXPLICIT_CURVE`.
    pub const OPENSSL_EC_EXPLICIT_CURVE: i32 = 0;

    /// `X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT`.
    pub const X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT: i32 = 0x1;
    /// `X509_CHECK_FLAG_NO_WILDCARDS`.
    pub const X509_CHECK_FLAG_NO_WILDCARDS: i32 = 0x2;
    /// `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`.
    pub const X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS: i32 = 0x4;
    /// `X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS`.
    pub const X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS: i32 = 0x8;
    /// `X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS`.
    pub const X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS: i32 = 0x10;
    /// `X509_CHECK_FLAG_NEVER_CHECK_SUBJECT`.
    pub const X509_CHECK_FLAG_NEVER_CHECK_SUBJECT: i32 = 0x20;
}

/// Internal field index holding the `Box<HashState>`.
const HASH_STATE_FIELD: i32 = 0;
/// Internal field index holding the `Box<HmacState>`.
const HMAC_STATE_FIELD: i32 = 0;

/// `internalBinding('crypto')`.
pub struct Crypto;

impl BindingModule for Crypto {
    fn namespace(&self) -> &'static str {
        "crypto"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        // Functions.
        for (name, callback) in [
            (
                "randomFillSync",
                v8::FunctionTemplate::builder(random_fill_sync)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "secureBuffer",
                v8::FunctionTemplate::builder(secure_buffer)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getHashes",
                v8::FunctionTemplate::builder(get_hashes)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getCiphers",
                v8::FunctionTemplate::builder(get_ciphers)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getCurves",
                v8::FunctionTemplate::builder(get_curves)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getCachedAliases",
                v8::FunctionTemplate::builder(get_cached_aliases)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getMacs",
                v8::FunctionTemplate::builder(crate::classes::get_macs)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getSSLCiphers",
                v8::FunctionTemplate::builder(crate::classes::get_ssl_ciphers)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getCertificateCompressionAlgorithms",
                v8::FunctionTemplate::builder(
                    crate::classes::get_certificate_compression_algorithms,
                )
                .build(scope)
                .get_function(scope),
            ),
            (
                "startLoadingCertificatesOffThread",
                v8::FunctionTemplate::builder(
                    crate::classes::start_loading_certificates_off_thread,
                )
                .build(scope)
                .get_function(scope),
            ),
            // `createNativeKeyObjectClass` is not here: `rn-bind-crypto-keys`
            // installs the real one, and installing a base-class stand-in first
            // would leave two implementations of the same member where only the
            // later one is reachable.
            (
                "createCryptoKeyClass",
                v8::FunctionTemplate::builder(crate::classes::create_crypto_key_class)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "timingSafeEqual",
                v8::FunctionTemplate::builder(timing_safe_equal)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "secureHeapUsed",
                v8::FunctionTemplate::builder(secure_heap_used)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getFipsCrypto",
                v8::FunctionTemplate::builder(get_fips_crypto)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getFipsCryptoGeneration",
                v8::FunctionTemplate::builder(get_fips_crypto_generation)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "getOpenSSLSecLevelCrypto",
                v8::FunctionTemplate::builder(get_openssl_sec_level)
                    .build(scope)
                    .get_function(scope),
            ),
            (
                "oneShotDigest",
                v8::FunctionTemplate::builder(one_shot_digest)
                    .build(scope)
                    .get_function(scope),
            ),
        ] {
            let Some(function) = callback else {
                return Err(format!("cannot allocate crypto.{name}"));
            };
            set(scope, object, name, function.into())?;
        }

        // The `Hash` and `Hmac` handle classes.
        install_hash_class(scope, object)?;
        install_hmac_class(scope, object)?;
        // The Diffie-Hellman classes. They live in `rn-bind-crypto-dh` because
        // `src/crypto/crypto_dh.cc` is a separate translation unit in Node, but
        // they are members of *this* namespace object, which is how
        // `src/node_crypto.cc` aggregates them too.
        rn_bind_crypto_dh::install_classes(scope, object)?;
        rn_bind_crypto_cipher::install_classes(scope, object)?;
        // The `KeyObject` family. Same reasoning one translation unit over: it
        // also lands on this object, because `src/node_crypto.cc` aggregates a
        // dozen `Initialize` calls onto one `target`. This replaces the base-class
        // stand-in that used to be installed above, so the `crate::classes`
        // binding for `createNativeKeyObjectClass` must not be installed as well.
        rn_bind_crypto_keys::install_classes(scope, object)?;
        // `Sign`/`Verify` and the two signature jobs. Same one-translation-unit
        // split: `src/crypto/crypto_sig.cc` and `crypto_rsa.cc` install onto this
        // object because `src/node_crypto.cc` aggregates their `Initialize` calls
        // onto one `target`. This also defines `RSA_PKCS1_PSS_PADDING`, so the
        // constant block below must not define it again.
        rn_bind_crypto_sign::install_classes(scope, object)?;
        // `X509Certificate` and the X.509 helpers. `src/crypto/crypto_x509.cc`
        // and `crypto_pkcs12.cc` are separate translation units that
        // `src/node_crypto.cc` aggregates onto this one `target`. This replaces
        // the base-class stand-in `crate::classes::create_x509_certificate_class`
        // installed above, so that binding must not run as well.
        rn_bind_crypto_x509::install_classes(scope, object)?;
        // The job handles, whose instances expose `run()`.
        install_job_class(scope, object, "HashJob", hash_job)?;
        install_job_class(scope, object, "HmacJob", hmac_job)?;
        crate::kdf::install_job_class(scope, object, "PBKDF2Job", crate::kdf::pbkdf2_constructor)?;
        crate::kdf::install_job_class(scope, object, "ScryptJob", crate::kdf::scrypt_constructor)?;
        crate::kdf::install_job_class(scope, object, "HKDFJob", crate::kdf::hkdf_constructor)?;

        // Numeric constants.
        for (name, value) in [
            ("kCryptoJobAsync", constants::K_CRYPTO_JOB_ASYNC),
            ("kCryptoJobSync", constants::K_CRYPTO_JOB_SYNC),
            ("kCryptoJobWebCrypto", constants::K_CRYPTO_JOB_WEB_CRYPTO),
            ("kKeyEncodingPKCS1", constants::K_KEY_ENCODING_PKCS1),
            ("kKeyEncodingPKCS8", constants::K_KEY_ENCODING_PKCS8),
            ("kKeyEncodingSEC1", constants::K_KEY_ENCODING_SEC1),
            ("kKeyEncodingSPKI", constants::K_KEY_ENCODING_SPKI),
            ("kKeyFormatDER", constants::K_KEY_FORMAT_DER),
            ("kKeyFormatPEM", constants::K_KEY_FORMAT_PEM),
            ("kKeyFormatJWK", constants::K_KEY_FORMAT_JWK),
            ("kKeyFormatRawPublic", constants::K_KEY_FORMAT_RAW_PUBLIC),
            ("kKeyFormatRawPrivate", constants::K_KEY_FORMAT_RAW_PRIVATE),
            ("kKeyFormatRawSeed", constants::K_KEY_FORMAT_RAW_SEED),
            ("kKeyFormatStore", constants::K_KEY_FORMAT_STORE),
            ("kKeyTypeSecret", constants::K_KEY_TYPE_SECRET),
            ("kKeyTypePublic", constants::K_KEY_TYPE_PUBLIC),
            ("kKeyTypePrivate", constants::K_KEY_TYPE_PRIVATE),
            ("kSigEncDER", constants::K_SIG_ENC_DER),
            ("kSigEncP1363", constants::K_SIG_ENC_P1363),
            ("kSignJobModeSign", constants::K_SIGN_JOB_MODE_SIGN),
            ("kSignJobModeVerify", constants::K_SIGN_JOB_MODE_VERIFY),
            (
                "kWebCryptoCipherEncrypt",
                constants::K_WEBCRYPTO_CIPHER_ENCRYPT,
            ),
            (
                "kWebCryptoCipherDecrypt",
                constants::K_WEBCRYPTO_CIPHER_DECRYPT,
            ),
            (
                "kWebCryptoKeyFormatRaw",
                constants::K_WEBCRYPTO_KEY_FORMAT_RAW,
            ),
            (
                "kWebCryptoKeyFormatPKCS8",
                constants::K_WEBCRYPTO_KEY_FORMAT_PKCS8,
            ),
            (
                "kWebCryptoKeyFormatSPKI",
                constants::K_WEBCRYPTO_KEY_FORMAT_SPKI,
            ),
            (
                "kWebCryptoKeyFormatJWK",
                constants::K_WEBCRYPTO_KEY_FORMAT_JWK,
            ),
            (
                "kKeyVariantRSA_SSA_PKCS1_v1_5",
                constants::K_KEY_VARIANT_RSA_SSA_PKCS1_V1_5,
            ),
            ("kKeyVariantRSA_PSS", constants::K_KEY_VARIANT_RSA_PSS),
            ("kKeyVariantRSA_OAEP", constants::K_KEY_VARIANT_RSA_OAEP),
            ("RSA_PKCS1_PSS_PADDING", constants::RSA_PKCS1_PSS_PADDING),
            ("OPENSSL_EC_NAMED_CURVE", constants::OPENSSL_EC_NAMED_CURVE),
            (
                "OPENSSL_EC_EXPLICIT_CURVE",
                constants::OPENSSL_EC_EXPLICIT_CURVE,
            ),
            (
                "X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT",
                constants::X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT,
            ),
            (
                "X509_CHECK_FLAG_NO_WILDCARDS",
                constants::X509_CHECK_FLAG_NO_WILDCARDS,
            ),
            (
                "X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS",
                constants::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
            ),
            (
                "X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS",
                constants::X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS,
            ),
            (
                "X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS",
                constants::X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS,
            ),
            (
                "X509_CHECK_FLAG_NEVER_CHECK_SUBJECT",
                constants::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
            ),
        ] {
            let value = v8::Integer::new(scope, value);
            set(scope, object, name, value.into())?;
        }

        Ok(object)
    }
}

/// Registers the `crypto` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Crypto);
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/// The native state behind a `Hash` handle.
struct HashState {
    /// `Some` until `digest()` runs. `lib/internal/crypto/hash.js` rejects a
    /// second `digest()` itself, but the binding has to hold the same invariant
    /// or a direct call would resurrect a finalised context.
    digest: Option<Digest>,
    /// Kept so `copy()` can rebuild from the algorithm name; `Digest` owns a
    /// hasher that cannot be cloned through the safe API.
    algorithm: String,
    /// `xofLen` from `new Hash(name, xofLen, id, cache)`, used by the XOF modes
    /// that are not wired up. Retained so `copy()` preserves it.
    xof_len: Option<u32>,
}

/// Reads the state pointer installed by a constructor.
///
/// Returns `None` for an object that was not built by this constructor, which is
/// reachable from JavaScript by `Hash.prototype.update.call({})`.
fn with_hash_state<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut HashState) -> R,
) -> Option<R> {
    // SAFETY: the field only ever holds a pointer produced by
    // `install_hash_state`, and the finalizer that frees it cannot run while
    // `object` is a live local.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HASH_STATE_FIELD, 0) }
        as *mut std::cell::RefCell<HashState>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above. `RefCell` rejects a reentrant borrow, and every borrow
    // here is scoped to one callback.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

/// Allocates the state and installs it with a finalizer.
fn install_hash_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    state: HashState,
) {
    let pointer = Box::into_raw(Box::new(std::cell::RefCell::new(state)));
    object.set_aligned_pointer_in_internal_field(
        HASH_STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut std::cell::RefCell<HashState>;
            // SAFETY: `install_hash_state` allocated this Box and nothing else
            // frees it; the finalizer runs exactly once.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
}

/// `new Hash(algorithm, xofLen, algorithmId, cache[, functionName,
/// customization])`.
///
/// `algorithm` may be another `Hash` handle, which is `Hash.prototype.copy`.
fn hash_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();

    let first = args.get(0);
    // `algorithm instanceof _Hash` is the copy path: `Hash.prototype.copy` passes
    // the existing handle so the algorithm and options carry over.
    if let Ok(source) = v8::Local::<v8::Object>::try_from(first) {
        // A copy continues from the same state: `Hash.prototype.copy` exists so a
        // caller can branch a digest mid-stream, and rebuilding from the algorithm
        // name would silently restart from empty.
        if let Some(copied) =
            with_hash_state(source, |state| state.digest.as_ref().map(Digest::try_clone))
        {
            match copied {
                Some(Ok(digest)) => {
                    let (algorithm, xof_len) =
                        with_hash_state(source, |state| (state.algorithm.clone(), state.xof_len))
                            .unwrap_or_default();
                    install_hash_state(
                        scope,
                        this,
                        HashState {
                            digest: Some(digest),
                            algorithm,
                            xof_len,
                        },
                    );
                    rv.set(this.into());
                }
                Some(Err(error)) => throw_crypto_error(scope, &error),
                None => throw(scope, "Cannot copy a finalised hash"),
            }
            return;
        }
    }

    let Some(algorithm) = string_argument(scope, &args, 0) else {
        throw(scope, "The algorithm argument must be a string");
        return;
    };
    // `xofLen` is `undefined` unless the caller asked for a specific output
    // length, which only the extendable-output digests use.
    let xof_len = args.get(1).uint32_value(scope);

    // `outputLength` only means anything for the extendable-output digests; for a
    // fixed-length algorithm it is ignored, which is what Node does.
    match Digest::new_with_output_length(&algorithm, xof_len) {
        Ok(digest) => {
            install_hash_state(
                scope,
                this,
                HashState {
                    digest: Some(digest),
                    algorithm,
                    xof_len,
                },
            );
            rv.set(this.into());
        }
        Err(error) => throw_crypto_error(scope, &error),
    }
}

/// `Hash.prototype.update(data, encoding)`.
///
/// Returns `true` on success. The JavaScript layer treats a falsy return as
/// `ERR_CRYPTO_HASH_UPDATE_FAILED`, so a failure here has to throw rather than
/// return false: Node's `Hash::Update` throws for an invalid state and returns
/// `false` only for a failed `EVP_DigestUpdate`, and reporting the throw as a
/// throw keeps the two distinct.
fn hash_update(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(bytes) = data_argument(scope, &args, 0, 1) else {
        return;
    };

    let updated = with_hash_state(this, |state| match state.digest.as_mut() {
        Some(digest) => digest.update(&bytes).is_ok(),
        None => false,
    });
    match updated {
        Some(true) => rv.set(v8::Boolean::new(scope, true).into()),
        Some(false) => {
            // Either the hash was already finalised or OpenSSL refused the
            // update. Node distinguishes these; `lib/internal/crypto/hash.js`
            // checks `kFinalized` before calling, so reaching here means the
            // OpenSSL update failed.
            throw(scope, "Digest update failed");
        }
        None => throw(scope, "Hash state is not available"),
    }
}

/// `Hash.prototype.digest(encoding)`.
///
/// `encoding` is either a normalised name (`"hex"`, `"base64"`, `"latin1"`, ...)
/// or `undefined`, which means a `Buffer`. Node's `Hash::Digest` returns a
/// `Buffer` for an absent encoding.
fn hash_digest(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let selected = digest_encoding(scope, &args, 0);

    // `Some(Err(..))` is a finalising failure; `None` means there was no digest
    // to finalise, which is a different error.
    // Outer `Option`: whether the object carries state at all. Inner: whether a
    // digest was still unfinalised.
    let finished = with_hash_state(this, |state| state.digest.take().map(Digest::finish)).flatten();
    match finished {
        Some(Ok(bytes)) => emit_digest(scope, &mut rv, &bytes, selected.as_deref()),
        Some(Err(error)) => throw_crypto_error(scope, &error),
        None => throw(scope, "Digest already called"),
    }
}

/// Installs `Hash` as a constructor with `update` and `digest` on its prototype.
fn install_hash_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(hash_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    // A prototype template only accepts a `Template` here, not a built
    // `Function`; handing it a Function aborts V8 with "Invalid value, must be a
    // primitive or a Template".
    let prototype = template.prototype_template(scope);
    for (name, callback) in [
        ("update", v8::FunctionTemplate::builder(hash_update)),
        ("digest", v8::FunctionTemplate::builder(hash_digest)),
    ] {
        let Some(key) = v8::String::new(scope, name) else {
            return Err(format!("cannot allocate the Hash method name {name}"));
        };
        prototype.set(key.into(), callback.build(scope).into());
    }
    let Some(class_name) = v8::String::new(scope, "Hash") else {
        return Err("cannot allocate the Hash class name".to_string());
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err("cannot allocate the Hash constructor".to_string());
    };
    let Some(key) = v8::String::new(scope, "Hash") else {
        return Err("cannot allocate the Hash property name".to_string());
    };
    target.set(scope, key.into(), function.into());
    Ok(())
}

// ---------------------------------------------------------------------------
// Hmac
// ---------------------------------------------------------------------------

/// The native state behind an `Hmac` handle.
struct HmacState {
    hmac: Option<Hmac>,
    /// The algorithm and key, kept so the handle could be re-initialised.
    algorithm: Option<String>,
    key: Vec<u8>,
}

fn with_hmac_state<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut HmacState) -> R,
) -> Option<R> {
    // SAFETY: as `with_hash_state`; the pointer comes from `install_hmac_state`
    // and nothing else frees it while `object` is live.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HMAC_STATE_FIELD, 0) }
        as *mut std::cell::RefCell<HmacState>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

fn install_hmac_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    state: HmacState,
) {
    let pointer = Box::into_raw(Box::new(std::cell::RefCell::new(state)));
    object.set_aligned_pointer_in_internal_field(
        HMAC_STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut std::cell::RefCell<HmacState>;
            // SAFETY: allocated by `install_hmac_state`, freed exactly once by
            // this finalizer.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
}

/// `new Hmac()` — the JavaScript layer calls `init` straight afterwards.
fn hmac_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    install_hmac_state(
        scope,
        this,
        HmacState {
            hmac: None,
            algorithm: None,
            key: Vec::new(),
        },
    );
    rv.set(this.into());
}

/// `Hmac.prototype.init(algorithm, key)`.
fn hmac_init(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(algorithm) = string_argument(scope, &args, 0) else {
        throw(scope, "The algorithm argument must be a string");
        return;
    };
    let Some(key) = data_argument(scope, &args, 1, 2) else {
        return;
    };

    match Hmac::new(&algorithm, &key) {
        Ok(hmac) => {
            with_hmac_state(this, |state| {
                state.hmac = Some(hmac);
                state.algorithm = Some(algorithm);
                state.key = key;
            });
        }
        Err(error) => throw_crypto_error(scope, &error),
    }
}

/// `Hmac.prototype.update(data, encoding)`, shared with `Hash` by the JavaScript
/// layer (`Hmac.prototype.update = Hash.prototype.update`), so this is the same
/// implementation for a different state type.
fn hmac_update(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(bytes) = data_argument(scope, &args, 0, 1) else {
        return;
    };
    let updated = with_hmac_state(this, |state| match state.hmac.as_mut() {
        Some(hmac) => hmac.update(&bytes).is_ok(),
        None => false,
    });
    match updated {
        Some(true) => rv.set(v8::Boolean::new(scope, true).into()),
        Some(false) => throw(scope, "Hmac update failed"),
        None => throw(scope, "Hmac state is not available"),
    }
}

/// `Hmac.prototype.digest(encoding)`.
fn hmac_digest(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let selected = digest_encoding(scope, &args, 0);

    let finished = with_hmac_state(this, |state| state.hmac.as_mut().map(Hmac::finish)).flatten();
    match finished {
        Some(Ok(bytes)) => emit_digest(scope, &mut rv, &bytes, selected.as_deref()),
        Some(Err(error)) => throw_crypto_error(scope, &error),
        None => throw(scope, "Hmac is not initialised"),
    }
}

fn install_hmac_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(hmac_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    // As in `install_hash_class`: a prototype template needs a `Template`.
    let prototype = template.prototype_template(scope);
    for (name, callback) in [
        ("init", v8::FunctionTemplate::builder(hmac_init)),
        ("update", v8::FunctionTemplate::builder(hmac_update)),
        ("digest", v8::FunctionTemplate::builder(hmac_digest)),
    ] {
        let Some(key) = v8::String::new(scope, name) else {
            return Err(format!("cannot allocate the Hmac method name {name}"));
        };
        prototype.set(key.into(), callback.build(scope).into());
    }
    let Some(class_name) = v8::String::new(scope, "Hmac") else {
        return Err("cannot allocate the Hmac class name".to_string());
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err("cannot allocate the Hmac constructor".to_string());
    };
    let Some(key) = v8::String::new(scope, "Hmac") else {
        return Err("cannot allocate the Hmac property name".to_string());
    };
    target.set(scope, key.into(), function.into());
    Ok(())
}

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------

/// `randomFillSync(buffer, offset, size)`.
///
/// Fills in place and returns the buffer. `lib/internal/crypto/random.js` has
/// already validated the offset and size against the view, so a bad range here
/// is a programming error rather than a user error; it throws anyway instead of
/// writing out of bounds.
fn random_fill_sync(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let target = args.get(0);
    let offset = args.get(1).uint32_value(scope).unwrap_or(0) as usize;
    let size = args.get(2).uint32_value(scope).unwrap_or(0) as usize;

    let Some(mut range) = view_bytes_mut(target, offset, size) else {
        throw(scope, "The buffer is out of bounds");
        return;
    };
    // SAFETY: `view_bytes_mut` validated `offset..offset + size` against the
    // live backing store and holds the only mutable borrow of it.
    match engine::random_fill(unsafe { range.as_mut_slice() }) {
        Ok(()) => rv.set(target),
        Err(error) => throw_crypto_error(scope, &error),
    }
}

/// `secureBuffer(size)`: a zeroed buffer allocated from the secure heap.
///
/// Node allocates this from `OPENSSL_secure_malloc` so the UUID seed cannot be
/// swapped to disk, and returns `undefined` when that fails. A plain zeroed
/// `ArrayBuffer` is returned here, because `openssl-src` builds without the
/// secure heap in this configuration. The observable difference is that the
/// memory is not mlocked; the bytes and the length are the same, and
/// `lib/internal/crypto/random.js` only uses it as scratch space for UUIDs.
fn secure_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let size = args.get(0).uint32_value(scope).unwrap_or(0) as usize;
    match encoding::uint8_array(scope, &vec![0u8; size]) {
        Some(array) => rv.set(array.into()),
        None => throw(scope, "cannot allocate the secure buffer"),
    }
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// `getHashes()`.
fn get_hashes(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let names = engine::hash_algorithms();
    match string_array(scope, &names) {
        Some(array) => rv.set(array.into()),
        None => throw(scope, "cannot allocate the digest list"),
    }
}

/// `getCiphers()`.
fn get_ciphers(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let names = engine::cipher_algorithms();
    match string_array(scope, &names) {
        Some(array) => rv.set(array.into()),
        None => throw(scope, "cannot allocate the cipher list"),
    }
}

/// `getCurves()`.
fn get_curves(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let names = engine::curve_names();
    match string_array(scope, &names) {
        Some(array) => rv.set(array.into()),
        None => throw(scope, "cannot allocate the curve list"),
    }
}

/// `getCachedAliases()`: the alias-to-id table `getHashCache()` builds.
///
/// `lib/internal/crypto/util.js` calls this to build `getHashCache()`, a plain
/// object mapping a name to an id it later passes back as `algorithmId`. Nothing
/// in this crate uses the id — `Digest::new` resolves the name itself — so the
/// mapping is by index over the enumeration, which is stable for the life of the
/// process and unique per name, and that is the only property the JavaScript
/// layer depends on.
fn get_cached_aliases(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let names = engine::hash_algorithms();
    let object = v8::Object::new(scope);
    for (index, name) in names.iter().enumerate() {
        let Some(key) = v8::String::new(scope, name) else {
            throw(scope, "cannot allocate a digest alias");
            return;
        };
        // `getCachedHashId` returns `-1` for a miss, so ids start at 0.
        let value = v8::Integer::new_from_unsigned(scope, index as u32);
        object.set(scope, key.into(), value.into());
    }
    rv.set(object.into());
}

// ---------------------------------------------------------------------------
// Comparison and feature queries
// ---------------------------------------------------------------------------

/// `timingSafeEqual(a, b)`.
///
/// `lib/crypto.js` calls this directly, and `lib/internal/crypto/kem_hybrids.js`
/// uses it to compare key material. A length mismatch throws
/// `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH`, which the JavaScript layer maps from
/// the message.
fn timing_safe_equal(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let left = args.get(0);
    let right = args.get(1);
    let Some(left_bytes) = view_bytes(left, 0, view_length(left)) else {
        throw_type_error(
            scope,
            "The first argument must be an ArrayBuffer or TypedArray",
        );
        return;
    };
    let Some(right_bytes) = view_bytes(right, 0, view_length(right)) else {
        throw_type_error(
            scope,
            "The second argument must be an ArrayBuffer or TypedArray",
        );
        return;
    };
    match engine::timing_safe_equal(left_bytes, right_bytes) {
        Ok(equal) => rv.set(v8::Boolean::new(scope, equal).into()),
        Err(CryptoError::InvalidArgument(message)) => throw(scope, &message),
        Err(error) => throw_crypto_error(scope, &error),
    }
}

/// `getFipsCrypto()`.
///
/// Always false: `openssl-src` builds without the FIPS provider, and reporting
/// true would make `lib/internal/crypto/util.js` behave as if a validated module
/// were in use.
fn get_fips_crypto(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Boolean::new(scope, engine::FIPS_ENABLED).into());
}

/// `getFipsCryptoGeneration()`: the counter `getHashCache()` watches.
///
/// The cache is invalidated when this changes, and FIPS mode cannot change in
/// this build, so it is a constant. It is still a function returning a number
/// because the JavaScript reads it that way.
fn get_fips_crypto_generation(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Integer::new(scope, 0).into());
}

/// `secureHeapUsed()`: bytes used from OpenSSL's secure heap, or `undefined`.
///
/// `lib/internal/crypto/util.js` turns `undefined` into
/// `{ total: 0, used: 0, utilization: 0, min: 0 }`, which is exactly right for a
/// build with no secure heap configured (`--secure-heap` is not passed, and
/// `openssl-src` is built without one), so `undefined` is the honest answer rather
/// than a fabricated zero.
fn secure_heap_used(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set_undefined();
}

/// `getOpenSSLSecLevelCrypto()`.
///
/// OpenSSL's default security level is 1 at the library level; `openssl-src`
/// does not raise it.
fn get_openssl_sec_level(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Integer::new(scope, 1).into());
}

// ---------------------------------------------------------------------------
// One-shot digest and the job shims
// ---------------------------------------------------------------------------

/// `oneShotDigest(algorithm, algorithmId, cache, input, encoding,
/// encodingId[, outputLength, functionName, customization])`.
///
/// `crypto.hash()` uses this. The `algorithmId` in position 1 is the id from
/// `getCachedHashId`, which is only meaningful to the C++ fast path; the name in
/// position 0 is authoritative here.
///
/// `input` may be a string, in which case the encoding is the *input* encoding
/// and `lib/internal/crypto/hash.js` has already validated it. `encoding` in
/// position 4 is the output encoding.
fn one_shot_digest(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(algorithm) = string_argument(scope, &args, 0) else {
        throw(scope, "The algorithm argument must be a string");
        return;
    };
    // Position 1 is the numeric algorithm id, position 2 the alias cache; both
    // are for the C++ fast path and are unused here.
    let input = args.get(3);
    let Some(input_bytes) = string_or_view_bytes(scope, input) else {
        throw_type_error(scope, "The input must be a string or an ArrayBufferView");
        return;
    };
    let output_encoding = digest_encoding(scope, &args, 4);

    match engine::digest_once(&algorithm, &input_bytes) {
        Ok(bytes) => emit_digest(scope, &mut rv, &bytes, output_encoding.as_deref()),
        Err(error) => throw_crypto_error(scope, &error),
    }
}

/// `HashJob` for `crypto.subtle.digest`.
///
/// `lib/internal/crypto/hash.js` builds this as
/// `jobPromise(() => new HashJob(mode, algorithm, data))`, and `jobPromise` calls
/// `.run()` on the result. So this installs a *constructor* whose instances carry
/// the request and expose `run()`, rather than a plain function.
///
/// `run()` returns a promise resolved before it returns. The digest itself is
/// synchronous, so the only observable contract — a promise settling to an
/// `ArrayBuffer` — is satisfied, and it needs no event loop.
fn hash_job<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // `mode` in position 0 selects sync/async/WebCrypto and only affects
    // scheduling, which is already immediate.
    let Some(algorithm) = string_argument(scope, &args, 1) else {
        throw(scope, "The algorithm argument must be a string");
        return;
    };
    let data = args.get(2);
    let Some(data_bytes) = string_or_view_bytes(scope, data) else {
        throw_type_error(scope, "The data must be a string or an ArrayBufferView");
        return;
    };
    let output_length = args.get(3).uint32_value(scope);

    install_job_state(
        scope,
        this,
        JobState::Digest {
            algorithm,
            data: data_bytes,
            output_length,
        },
    );
    rv.set(this.into());
}

/// `HmacJob` for the WebCrypto HMAC path.
///
/// Same shape as [`hash_job`]; `lib/internal/crypto/mac.js` builds it as
/// `new HmacJob(mode, algorithm, key, data)`.
fn hmac_job<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(algorithm) = string_argument(scope, &args, 1) else {
        throw(scope, "The algorithm argument must be a string");
        return;
    };
    let key = args.get(2);
    let data = args.get(3);
    let Some(key_bytes) = string_or_view_bytes(scope, key) else {
        throw_type_error(scope, "The key must be a string or an ArrayBufferView");
        return;
    };
    let Some(data_bytes) = string_or_view_bytes(scope, data) else {
        throw_type_error(scope, "The data must be a string or an ArrayBufferView");
        return;
    };
    install_job_state(
        scope,
        this,
        JobState::Hmac {
            algorithm,
            key: key_bytes,
            data: data_bytes,
        },
    );
    rv.set(this.into());
}

/// The work a job handle will run.
enum JobState {
    Digest {
        algorithm: String,
        data: Vec<u8>,
        output_length: Option<u32>,
    },
    Hmac {
        algorithm: String,
        key: Vec<u8>,
        data: Vec<u8>,
    },
}

/// Internal field index holding the `Box<JobState>`.
const JOB_STATE_FIELD: i32 = 0;

fn with_job_state<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&JobState) -> R,
) -> Option<R> {
    // SAFETY: the field only ever holds a pointer from `install_job_state`, and
    // the finalizer cannot run while `object` is a live local.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(JOB_STATE_FIELD, 0) }
        as *const JobState;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above; the state is only read through this borrow.
    Some(body(unsafe { &*pointer }))
}

fn install_job_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    state: JobState,
) {
    let pointer = Box::into_raw(Box::new(state));
    object.set_aligned_pointer_in_internal_field(
        JOB_STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *const JobState;
            // SAFETY: allocated by `install_job_state`; freed exactly once here.
            drop(unsafe { Box::from_raw(pointer as *mut JobState) });
        }),
    );
}

/// `HashJob.prototype.run()` / `HmacJob.prototype.run()`.
///
/// Returns a promise, resolved or rejected before this function returns.
fn job_run(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let computed = with_job_state(this, |state| match state {
        JobState::Digest {
            algorithm,
            data,
            output_length,
        } => match output_length {
            Some(length) => {
                Digest::new_with_output_length(algorithm, Some(*length)).and_then(|mut digest| {
                    digest.update(data)?;
                    digest.finish()
                })
            }
            None => engine::digest_once(algorithm, data),
        },
        JobState::Hmac {
            algorithm,
            key,
            data,
        } => engine::hmac_once(algorithm, key, data),
    });

    let Some(computed) = computed else {
        throw(scope, "the job handle is not initialised");
        return;
    };
    let promise = match computed {
        Ok(bytes) => match encoding::array_buffer(scope, &bytes) {
            Some(buffer) => resolve_promise(scope, buffer.into()),
            None => {
                throw(scope, "cannot allocate the job result");
                return;
            }
        },
        Err(error) => {
            let Some(text) = v8::String::new(scope, &error.to_string()) else {
                return;
            };
            let exception = v8::Exception::error(scope, text);
            reject_promise(scope, exception)
        }
    };
    if let Some(promise) = promise {
        rv.set(promise.into());
    }
}

/// Installs a job constructor with `run()` on its prototype.
fn install_job_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    constructor: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    let prototype = template.prototype_template(scope);
    let Some(key) = v8::String::new(scope, "run") else {
        return Err(format!("cannot allocate {name}.run"));
    };
    prototype.set(
        key.into(),
        v8::FunctionTemplate::builder(job_run).build(scope).into(),
    );
    let Some(class_name) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} class name"));
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err(format!("cannot allocate the {name} constructor"));
    };
    let Some(key) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} property name"));
    };
    target.set(scope, key.into(), function.into());
    Ok(())
}

/// Builds an already-resolved promise.
fn resolve_promise<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Promise>> {
    let resolver = v8::PromiseResolver::new(scope)?;
    resolver.resolve(scope, value);
    Some(resolver.get_promise(scope))
}

/// Builds an already-rejected promise.
fn reject_promise<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    error: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Promise>> {
    let resolver = v8::PromiseResolver::new(scope)?;
    resolver.reject(scope, error);
    Some(resolver.get_promise(scope))
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

/// Reads argument `index` as a Rust string.
fn string_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<String> {
    let value = args.get(index);
    if value.is_undefined() || value.is_null() {
        return None;
    }
    let text = value.to_string(scope)?;
    Some(text.to_rust_string_lossy(scope))
}

/// Reads the bytes of a `Buffer`/`TypedArray`/`ArrayBuffer` argument.
///
/// A string is decoded according to the encoding argument at `encoding_index`,
/// mirroring `ParseEncoding` in `node_crypto.cc`: `update('abc', 'hex')` means
/// the string is hex, not that the digest output is hex.
fn data_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
    encoding_index: i32,
) -> Option<Vec<u8>> {
    let value = args.get(index);
    if value.is_string() {
        let text = value.to_string(scope)?;
        let text = text.to_rust_string_lossy(scope);
        let encoding = string_argument(scope, args, encoding_index);
        return match encoding.as_deref() {
            None | Some("utf8") | Some("utf-8") => Some(text.into_bytes()),
            Some(name) => encoding::decode_string(&text, name),
        };
    }
    let length = view_length(value);
    view_bytes(value, 0, length).map(<[u8]>::to_vec)
}

/// Reads a `string` or view as bytes, for the one-shot paths where no separate
/// input encoding exists.
fn string_or_view_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<Vec<u8>> {
    if value.is_string() {
        let text = value.to_string(scope)?;
        return Some(text.to_rust_string_lossy(scope).into_bytes());
    }
    let length = view_length(value);
    view_bytes(value, 0, length).map(<[u8]>::to_vec)
}

/// The byte length of a view or `ArrayBuffer`, or 0 for anything else.
fn view_length(value: v8::Local<v8::Value>) -> usize {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        return view.byte_length();
    }
    if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        return buffer.byte_length();
    }
    0
}

/// Borrows `offset..offset + length` from a view or `ArrayBuffer`.
///
/// Returns `None` when the range falls outside the backing store, rather than
/// reading past it.
fn view_bytes(value: v8::Local<v8::Value>, offset: usize, length: usize) -> Option<&'static [u8]> {
    let (pointer, total) = view_pointer(value)?;
    let end = offset.checked_add(length)?;
    if end > total {
        return None;
    }
    if pointer.is_null() {
        return if length == 0 { Some(&[]) } else { None };
    }
    // SAFETY: the bounds check proves `offset..offset + length` lies inside a
    // live backing store. The returned slice is tied to that store by the
    // caller's V8 scope; the `'static` lifetime is narrowed immediately by the
    // callers, which copy out of it before returning to JavaScript.
    Some(unsafe { std::slice::from_raw_parts(pointer.add(offset), length) })
}

/// A mutable slice over a range of a view.
fn view_bytes_mut(value: v8::Local<v8::Value>, offset: usize, length: usize) -> Option<ViewRange> {
    let (pointer, total) = view_pointer(value)?;
    let end = offset.checked_add(length)?;
    if end > total {
        return None;
    }
    if pointer.is_null() {
        return if length == 0 {
            Some(ViewRange(std::ptr::NonNull::<u8>::dangling().as_ptr(), 0))
        } else {
            None
        };
    }
    // SAFETY: the bounds check above proves the range is inside the live backing
    // store, and the caller holds the only borrow while filling it.
    Some(ViewRange(unsafe { pointer.add(offset) }, length))
}

/// A writable range inside a JavaScript backing store.
struct ViewRange(*mut u8, usize);

impl ViewRange {
    /// The range as a mutable slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure no other reference to the same bytes exists for the
    /// duration of the borrow, which `view_bytes_mut` guarantees by construction
    /// within one callback.
    unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the pointer and length were validated against the backing store
        // in `view_bytes_mut`.
        unsafe { std::slice::from_raw_parts_mut(self.0, self.1) }
    }
}

/// The data pointer and byte length of a view or `ArrayBuffer`.
fn view_pointer(value: v8::Local<v8::Value>) -> Option<(*mut u8, usize)> {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        return Some((view.data().cast::<u8>(), view.byte_length()));
    }
    if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        let length = buffer.byte_length();
        return match buffer.data() {
            Some(data) => Some((data.as_ptr().cast::<u8>(), length)),
            None => Some((std::ptr::null_mut(), 0)),
        };
    }
    None
}

/// The output encoding for `digest(encoding)`.
///
/// `None` means "return a `Buffer`". `lib/internal/crypto/hash.js` has already
/// normalised and validated most names, but `oneShotDigest` passes the numeric
/// id from `encodingsMap` in position 5, so a number selects the same encoding.
fn digest_encoding(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<String> {
    let value = args.get(index);
    if value.is_undefined() || value.is_null() {
        return None;
    }
    if value.is_number() {
        // `encodingsMap` ids, from `lib/internal/util.js`.
        let id = value.uint32_value(scope)?;
        return encoding::name_from_map_id(id).map(str::to_string);
    }
    let text = value.to_string(scope)?;
    let text = text.to_rust_string_lossy(scope);
    if text.is_empty() || text.eq_ignore_ascii_case("buffer") {
        return None;
    }
    Some(text)
}

/// Sets the return value to a digest in the requested encoding.
fn emit_digest(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue,
    bytes: &[u8],
    encoding_name: Option<&str>,
) {
    match encoding_name {
        None => match encoding::uint8_array(scope, bytes) {
            Some(array) => rv.set(array.into()),
            None => throw(scope, "cannot allocate the digest result"),
        },
        Some(name) => match encoding::encode_bytes(bytes, name) {
            Some(text) => match v8::String::new(scope, &text) {
                Some(value) => rv.set(value.into()),
                None => throw(scope, "cannot allocate the digest string"),
            },
            None => throw_type_error(scope, &format!("Unknown encoding: {name}")),
        },
    }
}

/// Builds a JavaScript array of strings.
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

pub(crate) fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// Throws the JavaScript error a [`CryptoError`] corresponds to.
///
/// The messages are the ones `lib/internal/errors.js` turns into
/// `ERR_CRYPTO_INVALID_DIGEST`, so the code a caller sees is Node's.
pub(crate) fn throw_crypto_error(scope: &mut v8::PinScope<'_, '_>, error: &CryptoError) {
    match error {
        CryptoError::UnknownAlgorithm(name) => {
            throw(scope, &format!("Digest method not supported: {name}"));
        }
        other => throw(scope, &other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_name_is_crypto() {
        assert_eq!(Crypto.namespace(), "crypto");
    }

    #[test]
    fn installed_and_deferred_partition_the_contract() {
        // Every member is either installed or declared deferred, never both and
        // never neither, or `rn-compat` reports a real mismatch.
        let mut installed: std::collections::BTreeSet<&str> = MEMBERS.iter().copied().collect();
        assert_eq!(installed.len(), MEMBERS.len(), "duplicate member name");

        let deferred: std::collections::BTreeSet<&str> =
            DEFERRED.iter().map(|(member, _)| *member).collect();
        assert_eq!(deferred.len(), DEFERRED.len(), "duplicate deferral");

        for member in &deferred {
            assert!(
                !installed.contains(member),
                "{member} is both installed and deferred"
            );
        }
        installed.extend(deferred.iter().copied());

        // The contract records 144 members; together the two lists must cover
        // exactly that set. The integration test in `tests/binding.rs` checks the
        // names against the contract file itself; this pins the total.
        assert_eq!(installed.len(), 144, "expected 144 members in total");

        // Every deferral has a written reason that is more than a placeholder.
        for (member, reason) in DEFERRED {
            assert!(
                reason.len() > 20,
                "{member} has no real reason for being deferred"
            );
        }
    }

    #[test]
    fn the_signature_surface_is_installed_and_not_deferred() {
        // Slice S7 added exactly these four, from `crypto_sig.cc` and
        // `crypto_rsa.cc`. A member present in both lists, or in neither, makes
        // `rn-compat` report a mismatch that reads as an unrelated contract
        // failure — so the four are named here rather than left to the totals.
        for member in ["Sign", "Verify", "SignJob", "RSACipherJob"] {
            assert!(
                MEMBERS.contains(&member),
                "{member} must be installed by rn-bind-crypto-sign"
            );
            assert!(
                !DEFERRED.iter().any(|(name, _)| *name == member),
                "{member} is both installed and deferred"
            );
        }
    }

    #[test]
    fn every_installed_member_is_named() {
        for member in MEMBERS {
            assert!(!member.is_empty());
        }
    }

    #[test]
    fn matches_the_recorded_contract() {
        // The contract file is the authority. This runs in the crate's own test
        // so a member renamed on one side and not the other fails here first.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/crypto.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            // A checkout without contracts is bring-up state; the gate's
            // `rn-compat` run is what enforces it there.
            return;
        };
        let contract: serde_json::Value = serde_json::from_str(&raw).expect("contract json");
        let recorded: std::collections::BTreeSet<String> = contract["members"]
            .as_object()
            .expect("members object")
            .keys()
            .cloned()
            .collect();

        let mut covered: std::collections::BTreeSet<String> =
            MEMBERS.iter().map(|member| (*member).to_string()).collect();
        covered.extend(DEFERRED.iter().map(|(member, _)| (*member).to_string()));

        let missing: Vec<&String> = recorded.difference(&covered).collect();
        let extra: Vec<&String> = covered.difference(&recorded).collect();
        assert!(
            missing.is_empty(),
            "contract members not covered: {missing:?}"
        );
        assert!(extra.is_empty(), "members not in the contract: {extra:?}");
    }
}
