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
    // `crypto.argon2`/`argon2Sync` and the WebCrypto `Argon2` derive-bits path.
    // `argon2.js` checks `Argon2Job === undefined` to decide whether to throw
    // `ERR_CRYPTO_ARGON2_NOT_SUPPORTED`, so the class's *presence* is the
    // feature test and a deferral here would disable the API rather than hide it.
    "Argon2Job",
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
    // From `src/crypto/crypto_ec.cc`: `ECDH` and its static converter.
    // `lib/internal/crypto/diffiehellman.js` does `new _ECDH(curve)` at line 232
    // and `_ECDHConvertKey(...)` in `ECDH.convertKey`, so both are load-bearing
    // for `createECDH` rather than optional members.
    "ECDH",
    "ECDHConvertKey",
    // The cipher surface. Installed by `rn-bind-crypto-cipher`, which owns
    // `src/crypto/crypto_cipher.cc` and `crypto_aes.cc`. `getCipherInfo` is in
    // that translation unit too, not in the enumeration module, so it comes with
    // them rather than with `getCiphers`.
    "CipherBase",
    "AESCipherJob",
    "getCipherInfo",
    // The RSA cipher family. `CipherBase::Initialize` in
    // `src/crypto/crypto_cipher.cc` installs all four as four instantiations of
    // one `PublicKeyCipher::Cipher<operation, cipher>` template, and
    // `lib/internal/crypto/cipher.js` destructures them at module scope.
    "privateDecrypt",
    "privateEncrypt",
    "publicDecrypt",
    "publicEncrypt",
    // The `KeyObject` family. Installed by `rn-bind-crypto-keys`, which owns
    // `src/crypto/crypto_keys.cc`. `KeyObjectHandle` is the handle class and
    // `isKeyObject`/`getKeyObjectSlots` are the two queries over it;
    // `createNativeKeyObjectClass` is already listed above because `lib/tls.js`
    // reaches it at module scope, and the crate now supplies its real body rather
    // than the base-class stand-in that used to live here.
    "KeyObjectHandle",
    "getKeyObjectSlots",
    "isKeyObject",
    // The key-generation jobs. `SecretKeyGenJob` and all five key-pair jobs the
    // traditional API builds are here; `DsaKeyPairGenJob` and `DhKeyPairGenJob`
    // live in `rn-bind-crypto-keys` too, because they share the `[error, keys]`
    // dispatch and the encoding tail the other three use.
    "SecretKeyGenJob",
    "RsaKeyPairGenJob",
    "EcKeyPairGenJob",
    "NamedKeyPairGenJob",
    "DsaKeyPairGenJob",
    "DhKeyPairGenJob",
    // The shared-secret derivation job, installed by `rn-bind-crypto-keys` from
    // `crypto_dh.cc` alongside the rest of the key surface.
    // `lib/internal/crypto/diffiehellman.js` builds it for
    // `crypto.diffieHellman` and for the WebCrypto ECDH/X25519 `deriveBits` and
    // `deriveKey` paths, so without it both `subtle.deriveBits` and
    // `subtle.deriveKey` threw "Unsupported operation".
    "DHBitsJob",
    // The signature surface, installed by `rn-bind-crypto-sign` from
    // `src/crypto/crypto_sig.cc` and `crypto_rsa.cc`. `Sign`/`Verify` are the
    // streaming classes `lib/internal/crypto/sig.js` drives; `SignJob` is the
    // one-shot `crypto.sign`/`crypto.verify` form and `RSACipherJob` the RSA
    // encrypt/decrypt job `rsa.js` builds for RSA-OAEP.
    "Sign",
    "Verify",
    "SignJob",
    "RSACipherJob",
    // `SecureContext`, installed by `rn-bind-secure-context` from
    // `src/crypto/crypto_context.cc`. It is on this object because
    // `src/node_crypto.cc` aggregates a dozen `Initialize` calls onto one
    // `target`, and it must exist before `tls_wrap::wrap` will accept a context
    // (`lib/internal/tls/wrap.js` checks `instanceof NativeSecureContext`).
    "SecureContext",
    // The `RSAKeyVariant` values `keygen.js` puts in `RsaKeyPairGenJob`'s second
    // slot. Without them the argument is `undefined`, the variant defaults to
    // PKCS#1, and every `rsa-pss` generation silently produces a plain RSA key.
    // `ncrypto::Argon2Type`'s values, which `argon2.js` maps its three names
    // onto before passing one to `Argon2Job`. They are installed now that the
    // job exists; before that a deferral was the only honest answer, because a
    // constant with no consumer advertises a feature that is not there.
    "kTypeArgon2d",
    "kTypeArgon2i",
    "kTypeArgon2id",
    "kKeyVariantRSA_SSA_PKCS1_v1_5",
    "kKeyVariantRSA_PSS",
    "kKeyVariantRSA_OAEP",
    // The WebCrypto AES key variants. `crypto_aes.h` expands `VARIANTS` as CTR,
    // CBC and GCM at 128/192/256 then the three KW variants, followed by the OCB
    // block, and `crypto_aes.cc` publishes each as
    // `static_cast<int>(AESKeyVariant::name)`. `lib/internal/crypto/aes.js` reads
    // one by name and passes it to `AESCipherJob`, so a missing property is not a
    // missing constant: `aes.js` passes `undefined`, the job reads index 0, and
    // every AES variant silently becomes AES-CTR. These were in `DEFERRED` with
    // the reason "deferred with the WebCrypto surface", which was wrong in both
    // directions — the surface is what needed them.
    "kKeyVariantAES_CTR_128",
    "kKeyVariantAES_CTR_192",
    "kKeyVariantAES_CTR_256",
    "kKeyVariantAES_CBC_128",
    "kKeyVariantAES_CBC_192",
    "kKeyVariantAES_CBC_256",
    "kKeyVariantAES_GCM_128",
    "kKeyVariantAES_GCM_192",
    "kKeyVariantAES_GCM_256",
    "kKeyVariantAES_KW_128",
    "kKeyVariantAES_KW_192",
    "kKeyVariantAES_KW_256",
    "kKeyVariantAES_OCB_128",
    "kKeyVariantAES_OCB_192",
    "kKeyVariantAES_OCB_256",
    // Random. `randomFillSync` is the synchronous fill; the three job classes
    // are the asynchronous path `random.js` builds whenever a callback was
    // supplied, which is every `randomBytes`/`randomFill`/`randomInt`/
    // `generatePrime`/`checkPrime` call that passes one.
    "randomFillSync",
    "RandomBytesJob",
    "RandomPrimeJob",
    "CheckPrimeJob",
    "secureBuffer",
    "secureHeapUsed",
    // Enumeration, all derived from the linked OpenSSL.
    "getCiphers",
    "getCurves",
    "getHashes",
    "getCachedAliases",
    // The MAC half of the same cache. `crypto.createMac` resolves its algorithm
    // through `getMacId`, which reads this table, so without it `createMac`
    // throws "getCachedMacAliases is not a function" on every call.
    "getCachedMacAliases",
    "getMacs",
    // Reached at module scope by `lib/tls.js` and `lib/internal/crypto/util.js`,
    // so they are load-bearing for `require('crypto')` rather than optional.
    "getSSLCiphers",
    "getCertificateCompressionAlgorithms",
    "startLoadingCertificatesOffThread",
    "createNativeKeyObjectClass",
    // Installed by `rn_bind_crypto_keys::install_classes` alongside the rest of
    // the key class protocol. It was listed in `DEFERRED` with a reason claiming
    // it was "deferred with the key surface" while `install()` had been setting
    // it for as long as the keys crate existed, which is the contradiction the
    // structure gate reports as `installed-but-unclaimed`. `lib/internal/crypto/util.js:488`
    // calls it at module scope to build the algorithm-availability table, so a
    // deferral was also the wrong claim about reachability.
    "isKeyAlgorithmAvailable",
    "createCryptoKeyClass",
    "getCryptoKeySlots",
    "isCryptoKey",
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
    "setFipsCrypto",
    "testFipsCrypto",
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
        "ChaCha20Poly1305CipherJob",
        "The WebCrypto ChaCha20-Poly1305 job. The algorithm is available \
         (`getCiphers()` lists `chacha20-poly1305`), so this is the job class and the \
         WebCrypto key plumbing rather than a missing primitive.",
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
        "The job `crypto.subtle` builds for KMAC. It shares the `Mac` handle surface with \
         `createMac`, which is deferred, so the job has nothing to run against yet; the \
         algorithm itself is present (EVP_MAC fetches KMAC-128 and KMAC-256 and \
         KECCAK-KMAC-128), so this is not an OpenSSL gap.",
    ),
    (
        "Mac",
        "The `Mac` handle class from `crypto_mac.cc`. `createMac` now gets as far as \
         constructing one (`getCachedMacAliases` was the missing piece before it), so this \
         is the `Mac`/`_Mac` handle surface itself rather than the alias table.",
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
        "kKEMDecapsulate",
        "ML-KEM decapsulation mode flag; the KEM jobs it selects are deferred.",
    ),
    (
        "kKEMEncapsulate",
        "ML-KEM encapsulation mode flag; the KEM jobs it selects are deferred.",
    ),
    (
        "setupFipsIndicatorChannel",
        "FIPS indicator events, deferred with setFipsCrypto.",
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
    ///
    /// `crypto_keys.cc` derives these four from `EVPKeyPointer::PKEncodingType`
    /// with `static_cast<int>`, so they are that enum's declaration order in
    /// `deps/ncrypto/ncrypto.h`: `PKCS1, PKCS8, SPKI, SEC1`. They are observable
    /// through `internalBinding('crypto')` and are the values `keys.js` compares
    /// against, so they have to match even though nothing outside this crate and
    /// that JavaScript is meant to read them.
    pub const K_KEY_ENCODING_PKCS1: i32 = 0;
    /// `kKeyEncodingPKCS8`.
    pub const K_KEY_ENCODING_PKCS8: i32 = 1;
    /// `kKeyEncodingSEC1`.
    pub const K_KEY_ENCODING_SEC1: i32 = 3;
    /// `kKeyEncodingSPKI`.
    pub const K_KEY_ENCODING_SPKI: i32 = 2;

    /// `kKeyFormatDER`.
    ///
    /// `crypto_keys.cc` derives these seven from `EVPKeyPointer::PKFormatType`
    /// with `static_cast<int>`, so they are that enum's declaration order in
    /// `deps/ncrypto/ncrypto.h`: `DER, PEM, JWK, RAW_PUBLIC, RAW_PRIVATE,
    /// RAW_SEED, STORE`. They were previously numbered 1..=7, one past Node's
    /// 0..=6, which is the same shifted-table defect the encoding constants had.
    pub const K_KEY_FORMAT_DER: i32 = 0;
    /// `kKeyFormatPEM`.
    pub const K_KEY_FORMAT_PEM: i32 = 1;
    /// `kKeyFormatJWK`.
    pub const K_KEY_FORMAT_JWK: i32 = 2;
    /// `kKeyFormatRawPublic`.
    pub const K_KEY_FORMAT_RAW_PUBLIC: i32 = 3;
    /// `kKeyFormatRawPrivate`.
    pub const K_KEY_FORMAT_RAW_PRIVATE: i32 = 4;
    /// `kKeyFormatRawSeed`.
    pub const K_KEY_FORMAT_RAW_SEED: i32 = 5;
    /// `kKeyFormatStore`.
    pub const K_KEY_FORMAT_STORE: i32 = 6;

    /// `kKeyTypeSecret`.
    ///
    /// `crypto_keys.h`'s `enum KeyType { kKeyTypeSecret, kKeyTypePublic,
    /// kKeyTypePrivate }` exported with `NODE_DEFINE_CONSTANT`, so the three are
    /// 0, 1, 2 in declaration order. They were previously 1, 2, 3.
    pub const K_KEY_TYPE_SECRET: i32 = 0;
    /// `kKeyTypePublic`.
    pub const K_KEY_TYPE_PUBLIC: i32 = 1;
    /// `kKeyTypePrivate`.
    pub const K_KEY_TYPE_PRIVATE: i32 = 2;

    /// `kTypeArgon2d`, from `ncrypto::Argon2Type`'s declaration order.
    pub const K_TYPE_ARGON2D: i32 = 0;
    /// `kTypeArgon2i`.
    pub const K_TYPE_ARGON2I: i32 = 1;
    /// `kTypeArgon2id`.
    pub const K_TYPE_ARGON2ID: i32 = 2;

    /// `kSigEncDER`.
    ///
    /// `DSASigEnc` in `node_crypto.h` is `{ DER, P1363 }`, exported by value,
    /// so the two are 0 and 1.
    pub const K_SIG_ENC_DER: i32 = 0;
    /// `kSigEncP1363`.
    pub const K_SIG_ENC_P1363: i32 = 1;

    /// `kKeyVariantRSA_SSA_PKCS1_v1_5`.
    ///
    /// `RSAKeyVariant` from `crypto_rsa.h`, which `keygen.js` passes as the
    /// second argument of `RsaKeyPairGenJob`. This table was already Node's.
    pub const K_KEY_VARIANT_RSA_SSA_PKCS1_V1_5: i32 = 0;
    /// `kKeyVariantRSA_PSS`.
    pub const K_KEY_VARIANT_RSA_PSS: i32 = 1;
    /// `kKeyVariantRSA_OAEP`.
    pub const K_KEY_VARIANT_RSA_OAEP: i32 = 2;

    /// `kSignJobModeSign`, from `SignJobMode` in `node_crypto.h`.
    pub const K_SIGN_JOB_MODE_SIGN: i32 = 0;
    /// `kSignJobModeVerify`.
    pub const K_SIGN_JOB_MODE_VERIFY: i32 = 1;

    /// `kWebCryptoCipherEncrypt`, from `WebCryptoCipherMode` in `node_crypto.h`.
    pub const K_WEBCRYPTO_CIPHER_ENCRYPT: i32 = 0;
    /// `kWebCryptoCipherDecrypt`.
    pub const K_WEBCRYPTO_CIPHER_DECRYPT: i32 = 1;

    /// `kWebCryptoKeyFormatRaw`.
    ///
    /// `enum WebCryptoKeyFormat` in `crypto_keys.h` is `{ kWebCryptoKeyFormatRaw,
    /// kWebCryptoKeyFormatPKCS8, kWebCryptoKeyFormatSPKI,
    /// kWebCryptoKeyFormatJWK }`, so the four are 0..=3 in declaration order.
    pub const K_WEBCRYPTO_KEY_FORMAT_RAW: i32 = 0;
    /// `kWebCryptoKeyFormatPKCS8`.
    pub const K_WEBCRYPTO_KEY_FORMAT_PKCS8: i32 = 1;
    /// `kWebCryptoKeyFormatSPKI`.
    pub const K_WEBCRYPTO_KEY_FORMAT_SPKI: i32 = 2;
    /// `kWebCryptoKeyFormatJWK`.
    pub const K_WEBCRYPTO_KEY_FORMAT_JWK: i32 = 3;

    /// `kKeyVariantAES_CTR_128`, from `AESKeyVariant` in `crypto_aes.h`.
    ///
    /// `crypto_aes.h` expands `VARIANTS` as `VARIANTS_COMMON` — CTR, CBC and GCM
    /// at 128/192/256, then the three KW variants — followed by `VARIANTS_OCB`.
    /// `crypto_aes.cc` publishes each as
    /// `static_cast<int>(AESKeyVariant::name)`, so the numbers are that
    /// declaration order. `lib/internal/crypto/aes.js` picks one by name and
    /// passes it to `AESCipherJob`, so a member that is missing here is not a
    /// missing constant: the property reads `undefined`, `aes.js` hands
    /// `undefined` to the job, and the job reads index 0 — AES-CTR — for every
    /// AES variant. That is why `subtle.encrypt` with AES-GCM failed with
    /// "Invalid counter" before these were published.
    pub const K_KEY_VARIANT_AES_CTR_128: i32 = 0;
    /// `kKeyVariantAES_CTR_192`.
    pub const K_KEY_VARIANT_AES_CTR_192: i32 = 1;
    /// `kKeyVariantAES_CTR_256`.
    pub const K_KEY_VARIANT_AES_CTR_256: i32 = 2;
    /// `kKeyVariantAES_CBC_128`.
    pub const K_KEY_VARIANT_AES_CBC_128: i32 = 3;
    /// `kKeyVariantAES_CBC_192`.
    pub const K_KEY_VARIANT_AES_CBC_192: i32 = 4;
    /// `kKeyVariantAES_CBC_256`.
    pub const K_KEY_VARIANT_AES_CBC_256: i32 = 5;
    /// `kKeyVariantAES_GCM_128`.
    pub const K_KEY_VARIANT_AES_GCM_128: i32 = 6;
    /// `kKeyVariantAES_GCM_192`.
    pub const K_KEY_VARIANT_AES_GCM_192: i32 = 7;
    /// `kKeyVariantAES_GCM_256`.
    pub const K_KEY_VARIANT_AES_GCM_256: i32 = 8;
    /// `kKeyVariantAES_KW_128`.
    pub const K_KEY_VARIANT_AES_KW_128: i32 = 9;
    /// `kKeyVariantAES_KW_192`.
    pub const K_KEY_VARIANT_AES_KW_192: i32 = 10;
    /// `kKeyVariantAES_KW_256`.
    pub const K_KEY_VARIANT_AES_KW_256: i32 = 11;
    /// `kKeyVariantAES_OCB_128`.
    pub const K_KEY_VARIANT_AES_OCB_128: i32 = 12;
    /// `kKeyVariantAES_OCB_192`.
    pub const K_KEY_VARIANT_AES_OCB_192: i32 = 13;
    /// `kKeyVariantAES_OCB_256`.
    pub const K_KEY_VARIANT_AES_OCB_256: i32 = 14;

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

        // Functions. Each is `SetMethod` in its `src/crypto/**` translation unit,
        // so `rn_core::set_method` publishes it under its property name with the
        // name set, exactly as `node::SetMethod` does.
        rn_core::set_method(scope, object, "randomFillSync", random_fill_sync)?;
        rn_core::set_method(scope, object, "secureBuffer", secure_buffer)?;
        rn_core::set_method(scope, object, "getHashes", get_hashes)?;
        rn_core::set_method(scope, object, "getCiphers", get_ciphers)?;
        rn_core::set_method(scope, object, "getCurves", get_curves)?;
        rn_core::set_method(scope, object, "getCachedAliases", get_cached_aliases)?;
        rn_core::set_method(scope, object, "getMacs", crate::classes::get_macs)?;
        rn_core::set_method(scope, object, "getCachedMacAliases", get_cached_mac_aliases)?;
        rn_core::set_method(
            scope,
            object,
            "getSSLCiphers",
            crate::classes::get_ssl_ciphers,
        )?;
        rn_core::set_method(
            scope,
            object,
            "getCertificateCompressionAlgorithms",
            crate::classes::get_certificate_compression_algorithms,
        )?;
        rn_core::set_method(
            scope,
            object,
            "startLoadingCertificatesOffThread",
            crate::classes::start_loading_certificates_off_thread,
        )?;
        rn_core::set_method(scope, object, "secureHeapUsed", secure_heap_used)?;
        rn_core::set_method(scope, object, "getFipsCrypto", get_fips_crypto)?;
        rn_core::set_method(scope, object, "setFipsCrypto", set_fips_crypto)?;
        rn_core::set_method(scope, object, "testFipsCrypto", test_fips_crypto)?;
        rn_core::set_method(
            scope,
            object,
            "getFipsCryptoGeneration",
            get_fips_crypto_generation,
        )?;
        rn_core::set_method(
            scope,
            object,
            "getOpenSSLSecLevelCrypto",
            get_openssl_sec_level,
        )?;
        rn_core::set_method(scope, object, "oneShotDigest", one_shot_digest)?;
        // `crypto_timing.cc` publishes this with `SetFastMethodNoSideEffect`, the
        // one `SetMethod` variant that omits `SetName`, so Node's
        // `binding.timingSafeEqual.name` is `""`. Naming it here would be a
        // divergence in the opposite direction.
        rn_core::set_fast_method(scope, object, "timingSafeEqual", timing_safe_equal)?;

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
        // `SecureContext`. Same aggregation: `src/crypto/crypto_context.cc`
        // installs onto the object `src/node_crypto.cc` passes in, not onto a
        // namespace of its own. It has to be reachable before `tls_wrap` exists,
        // because `lib/internal/tls/wrap.js:832` rejects a context that is not
        // `instanceof NativeSecureContext`.
        rn_bind_secure_context::install_classes(scope, object)?;
        install_job_class(scope, object, "HashJob", hash_job)?;
        // The three asynchronous random jobs. `lib/internal/crypto/random.js`
        // constructs them whenever a callback was supplied, so their absence is
        // the whole of `crypto.randomBytes(n, cb)` throwing rather than a gap in
        // one path: `randomFill` has no synchronous fallback.
        crate::jobs::install_random_jobs(scope, object)?;
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
            ("kTypeArgon2d", constants::K_TYPE_ARGON2D),
            ("kTypeArgon2i", constants::K_TYPE_ARGON2I),
            ("kTypeArgon2id", constants::K_TYPE_ARGON2ID),
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
            (
                "kKeyVariantAES_CTR_128",
                constants::K_KEY_VARIANT_AES_CTR_128,
            ),
            (
                "kKeyVariantAES_CTR_192",
                constants::K_KEY_VARIANT_AES_CTR_192,
            ),
            (
                "kKeyVariantAES_CTR_256",
                constants::K_KEY_VARIANT_AES_CTR_256,
            ),
            (
                "kKeyVariantAES_CBC_128",
                constants::K_KEY_VARIANT_AES_CBC_128,
            ),
            (
                "kKeyVariantAES_CBC_192",
                constants::K_KEY_VARIANT_AES_CBC_192,
            ),
            (
                "kKeyVariantAES_CBC_256",
                constants::K_KEY_VARIANT_AES_CBC_256,
            ),
            (
                "kKeyVariantAES_GCM_128",
                constants::K_KEY_VARIANT_AES_GCM_128,
            ),
            (
                "kKeyVariantAES_GCM_192",
                constants::K_KEY_VARIANT_AES_GCM_192,
            ),
            (
                "kKeyVariantAES_GCM_256",
                constants::K_KEY_VARIANT_AES_GCM_256,
            ),
            ("kKeyVariantAES_KW_128", constants::K_KEY_VARIANT_AES_KW_128),
            ("kKeyVariantAES_KW_192", constants::K_KEY_VARIANT_AES_KW_192),
            ("kKeyVariantAES_KW_256", constants::K_KEY_VARIANT_AES_KW_256),
            (
                "kKeyVariantAES_OCB_128",
                constants::K_KEY_VARIANT_AES_OCB_128,
            ),
            (
                "kKeyVariantAES_OCB_192",
                constants::K_KEY_VARIANT_AES_OCB_192,
            ),
            (
                "kKeyVariantAES_OCB_256",
                constants::K_KEY_VARIANT_AES_OCB_256,
            ),
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
    if !args.is_construct_call() {
        throw_construct_call_required(scope);
        return;
    }
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
    //
    // The `is_undefined` guard is load-bearing, not defensive:
    // `Value::uint32_value` is V8's `ToUint32`, which coerces `undefined` to
    // `Some(0)`. Reading it directly therefore turned "no request" into "request
    // zero bytes", and `createHash('shake128').digest()` returned an empty buffer
    // because the XOF branch treats an explicit request as authoritative.
    let requested_length = args.get(1);
    let xof_len = if requested_length.is_undefined() {
        None
    } else {
        requested_length.uint32_value(scope)
    };

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
        Some(digest) => digest.update(bytes.as_slice()).is_ok(),
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
    let template = rn_core::class(hash_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    // A prototype template only accepts a `Template` here, not a built
    // `Function`; handing it a Function aborts V8 with "Invalid value, must be a
    // primitive or a Template".
    let prototype = template.prototype_template(scope);
    for (name, callback) in [
        ("update", rn_core::method(hash_update)),
        ("digest", rn_core::method(hash_digest)),
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
    if !args.is_construct_call() {
        throw_construct_call_required(scope);
        return;
    }
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
    // The key outlives this callback: `HmacState` keeps it so the handle can be
    // re-initialised, so this is the one path that must own its bytes.
    let key = key.into_owned();

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
        Some(hmac) => hmac.update(bytes.as_slice()).is_ok(),
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
    let template = rn_core::class(hmac_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    // As in `install_hash_class`: a prototype template needs a `Template`.
    let prototype = template.prototype_template(scope);
    for (name, callback) in [
        ("init", rn_core::method(hmac_init)),
        ("update", rn_core::method(hmac_update)),
        ("digest", rn_core::method(hmac_digest)),
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

/// `getCachedMacAliases()`: the same table for the MAC enumeration.
///
/// `getMacCache()` in `lib/internal/crypto/util.js` reads this exactly as
/// `getHashCache()` reads `getCachedAliases()`, and `getCachedMacId` returns `-1`
/// for a miss — so the contract is identical: a name-to-index object whose ids
/// are only required to be stable and unique, because nothing here uses them.
/// Its absence is what made `crypto.createMac` throw
/// `getCachedMacAliases is not a function`: `Mac`'s constructor resolves the
/// algorithm through `getMacId`, which calls this.
fn get_cached_mac_aliases(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let names = crate::enumerate::mac_names();
    let object = v8::Object::new(scope);
    for (index, name) in names.iter().enumerate() {
        let Some(key) = v8::String::new(scope, name) else {
            throw(scope, "cannot allocate a MAC alias");
            return;
        };
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
fn timing_safe_equal<'s>(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'s>,
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
/// Returns the **number** `0`, not `false`. `lib/crypto.js`'s `getFips` is
/// `return getOptionValue('--force-fips') ? 1 : getFipsCrypto();`, and
/// `lib/internal/crypto/util.js` compares `getFipsCrypto() === 1`. A boolean
/// fails that comparison the same way `0` does, but `crypto.getFips()` itself
/// returns whatever this returns, so a boolean leaks out as `typeof` `boolean`
/// where Node reports `number`.
fn get_fips_crypto(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Integer::new(scope, i32::from(engine::fips_enabled())).into());
}

/// `setFipsCrypto(enable)`: `crypto.setFips()`.
///
/// Records OpenSSL's FIPS property-query state. See [`engine::set_fips_enabled`]
/// for what that does and does not guarantee.
fn set_fips_crypto(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let _ = scope;
    engine::set_fips_enabled(args.get(0).is_true());
}

/// `testFipsCrypto()`: the same state as `getFipsCrypto`, as a number.
///
/// `crypto.fips` and the indicator paths read this rather than the string form.
fn test_fips_crypto(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Integer::new(scope, i32::from(engine::fips_enabled())).into());
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

/// `secureHeapUsed()`: bytes used from OpenSSL's secure heap, as a BigInt.
///
/// The binding returns a **BigInt**, not `undefined` and not an object. Node's
/// `SecureHeapUsed` is `BigInt::New(isolate, DataPointer::GetSecureHeapUsed())`,
/// and the rest of the answer is computed in JavaScript: `secureHeapUsed` in
/// `lib/internal/crypto/util.js` only takes its hardcoded
/// `{ total: 0, used: 0, utilization: 0, min: 0 }` fallback when this returns
/// `undefined`. Returning `undefined` here therefore reported `min: 0` and
/// `utilization: 0` where Node reports `min: 2` (the `--secure-heap-min` default)
/// and `utilization: NaN`, which `JSON.stringify` renders as `null`.
///
/// `GetSecureHeapUsed` is `CRYPTO_secure_malloc_initialized() ?
/// CRYPTO_secure_used() : 0`, so an unconfigured heap reports `0n` and the shared
/// JavaScript still produces the `min`/`utilization` fields Node's callers see.
fn secure_heap_used(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let used = crate::enumerate::secure_heap_used();
    rv.set(v8::BigInt::new_from_u64(scope, used).into());
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

    match engine::digest_once(&algorithm, input_bytes.as_slice()) {
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
    // As in `hash_constructor`: `uint32_value` coerces `undefined` to `Some(0)`,
    // so the absent case has to be read explicitly or a job without an output
    // length would finalise an XOF to zero bytes.
    let requested_length = args.get(3);
    let output_length = if requested_length.is_undefined() {
        None
    } else {
        requested_length.uint32_value(scope)
    };

    install_job_state(
        scope,
        this,
        JobState::Digest {
            algorithm,
            // The job runs after this callback returns, so the bytes cannot stay
            // a borrow of the caller's view.
            data: data_bytes.into_owned(),
            output_length,
        },
    );
    rv.set(this.into());
}

/// `HmacJob` for the WebCrypto HMAC path.
///
/// `lib/internal/crypto/mac.js` builds it as
/// `new HmacJob(kCryptoJobWebCrypto, signMode, digest, keyHandle, data[, signature])`,
/// and `crypto_hmac.cc`'s `HmacTraits::AdditionalConfig` reads exactly those five
/// after the mode: the sign mode as a `Uint32`, the digest name as a string, the
/// key as a `KeyObjectHandle`, then the data and an optional signature. The key is
/// a *handle*, not raw bytes — the previous layout read the mode as the algorithm
/// name and the digest as the key, so `subtle.sign('HMAC', ...)` could not work
/// whatever the key was.
fn hmac_job<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let mode = args.get(1).uint32_value(scope).unwrap_or(0);
    let Some(algorithm) = string_argument(scope, &args, 2) else {
        throw(scope, "The digest must be a string");
        return;
    };
    let Some(key_bytes) = secret_key_bytes(scope, args.get(3)) else {
        return;
    };
    let Some(data_bytes) = string_or_view_bytes(scope, args.get(4)) else {
        throw_type_error(scope, "The data must be a string or an ArrayBufferView");
        return;
    };
    // `If (!args[offset + 4]->IsUndefined())` reads a signature for the verify
    // branch only; absent means sign.
    let signature = string_or_view_bytes(scope, args.get(5));
    install_job_state(
        scope,
        this,
        JobState::Hmac {
            algorithm,
            key: key_bytes,
            // As in `hash_job`: the job outlives the callback.
            data: data_bytes.into_owned(),
            verify: mode == constants::K_SIGN_JOB_MODE_VERIFY as u32,
            signature: signature.map(CryptoBytes::into_owned),
        },
    );
    rv.set(this.into());
}

/// Reads the raw bytes out of a `KeyObjectHandle` for a secret key.
///
/// `HmacTraits::AdditionalConfig` unwraps the handle and keeps
/// `key->Data().addRef()`, then signs with `GetSymmetricKey()`. The bytes are the
/// same thing `handle.export()` returns for a secret key, which is what
/// `importSecretKey` in `keys.js` built it from.
fn secret_key_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Option<Vec<u8>> {
    let Ok(handle) = v8::Local::<v8::Object>::try_from(value) else {
        throw_type_error(scope, "The key must be a KeyObjectHandle");
        return None;
    };
    let name = v8::String::new(scope, "getKeyType")?;
    let function = handle.get(scope, name.into())?;
    let function = v8::Local::<v8::Function>::try_from(function).ok()?;
    let key_type = function.call(scope, handle.into(), &[])?;
    // `kKeyTypeSecret` is 0.
    if key_type.int32_value(scope) != Some(0) {
        throw_type_error(scope, "The key must be a secret KeyObject");
        return None;
    }
    let export = v8::String::new(scope, "export")?;
    let export = handle.get(scope, export.into())?;
    let export = v8::Local::<v8::Function>::try_from(export).ok()?;
    let exported = export.call(scope, handle.into(), &[])?;
    string_or_view_bytes(scope, exported).map(CryptoBytes::into_owned)
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
        /// `HmacConfig::mode == SignConfiguration::Mode::Verify`.
        verify: bool,
        /// The expected signature, for the verify branch only.
        signature: Option<Vec<u8>>,
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
                match Digest::new_with_output_length(algorithm, Some(*length)).and_then(
                    |mut digest| {
                        digest.update(data)?;
                        digest.finish()
                    },
                ) {
                    Ok(bytes) => Ok(HmacOutcome::Digest(bytes)),
                    Err(error) => Err(error),
                }
            }
            None => engine::digest_once(algorithm, data).map(HmacOutcome::Digest),
        },
        JobState::Hmac {
            algorithm,
            key,
            data,
            verify,
            signature,
        } => {
            // `HmacTraits::EncodeOutput`: sign resolves the digest, verify
            // answers a boolean after `CRYPTO_memcmp`, so the two have different
            // result types and the job cannot just return the digest either way.
            match engine::hmac_once(algorithm, key, data) {
                Ok(bytes) if *verify => Ok(HmacOutcome::Verified(matches!(
                    signature.as_deref(),
                    Some(expected) if expected.len() == bytes.len()
                        && expected == bytes.as_slice()
                ))),
                Ok(bytes) => Ok(HmacOutcome::Digest(bytes)),
                Err(error) => Err(error),
            }
        }
    });

    let Some(computed) = computed else {
        throw(scope, "the job handle is not initialised");
        return;
    };
    let promise = match computed {
        // `out->ToArrayBuffer` for a digest, and a boolean for a verify.
        Ok(HmacOutcome::Digest(bytes)) => match encoding::array_buffer(scope, &bytes) {
            Some(buffer) => resolve_promise(scope, buffer.into()),
            None => {
                throw(scope, "cannot allocate the job result");
                return;
            }
        },
        Ok(HmacOutcome::Verified(verified)) => {
            resolve_promise(scope, v8::Boolean::new(scope, verified).into())
        }
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

/// What a `HashJob`/`HmacJob` run produced.
///
/// `HmacTraits::EncodeOutput` has two result types depending on
/// `SignConfiguration::Mode`: a digest `ArrayBuffer` for sign, and a `Boolean`
/// for verify. A single `Vec<u8>` cannot express the second, and returning an
/// empty digest would read as a successful signature.
enum HmacOutcome {
    Digest(Vec<u8>),
    Verified(bool),
}

/// Installs a job constructor with `run()` on its prototype.
fn install_job_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    constructor: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let template = rn_core::class(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    let prototype = template.prototype_template(scope);
    let Some(key) = v8::String::new(scope, "run") else {
        return Err(format!("cannot allocate {name}.run"));
    };
    prototype.set(key.into(), rn_core::method(job_run).build(scope).into());
    // `rn_core::set_class` is `SetConstructorFunction(…, SET_CLASS_NAME)`: the
    // class name is what V8 reports as `f.name`, so it has to be the property
    // name Node passes in rather than left to the bare builder.
    rn_core::set_class(scope, target, name, template)?;
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

/// Argument bytes that may borrow the caller's view instead of copying it.
///
/// Node's `Hash::Update` hands the view's raw pointer straight to
/// `EVP_DigestUpdate`; it never materialises a second copy of the input. The
/// binding used to `to_vec()` every view, which cost a full copy of the input —
/// 94 MB of peak RSS for a 94 MB buffer, and the difference showed up as a
/// hash-of-a-large-`Buffer` retaining far more memory than the same hash in
/// Node. Most callers only need the bytes inside the callback, so they take the
/// borrow; the ones that must outlive the callback (a job that runs later) ask
/// for an owned `Vec` explicitly.
enum CryptoBytes<'a> {
    /// The bytes live in a V8 backing store that outlives this borrow.
    Borrowed(&'a [u8]),
    /// The bytes were decoded from a string, so they had to be materialised.
    Owned(Vec<u8>),
}

impl CryptoBytes<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    /// Copies the bytes out, for a caller that must keep them past the callback.
    fn into_owned(self) -> Vec<u8> {
        match self {
            Self::Borrowed(bytes) => bytes.to_vec(),
            Self::Owned(bytes) => bytes,
        }
    }
}

/// Reads the bytes of a `Buffer`/`TypedArray`/`ArrayBuffer` argument.
///
/// A string is decoded according to the encoding argument at `encoding_index`,
/// mirroring `ParseEncoding` in `node_crypto.cc`: `update('abc', 'hex')` means
/// the string is hex, not that the digest output is hex.
fn data_argument<'s>(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    index: i32,
    encoding_index: i32,
) -> Option<CryptoBytes<'s>> {
    let value = args.get(index);
    if value.is_string() {
        let text = value.to_string(scope)?;
        let text = text.to_rust_string_lossy(scope);
        let encoding = string_argument(scope, args, encoding_index);
        return match encoding.as_deref() {
            None | Some("utf8") | Some("utf-8") => Some(text.into_bytes()),
            Some(name) => encoding::decode_string(&text, name),
        }
        .map(CryptoBytes::Owned);
    }
    let length = view_length(value);
    view_bytes(value, 0, length).map(CryptoBytes::Borrowed)
}

/// Reads a `string` or view as bytes, for the one-shot paths where no separate
/// input encoding exists.
fn string_or_view_bytes<'a>(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'a, v8::Value>,
) -> Option<CryptoBytes<'a>> {
    if value.is_string() {
        let text = value.to_string(scope)?;
        return Some(CryptoBytes::Owned(
            text.to_rust_string_lossy(scope).into_bytes(),
        ));
    }
    let length = view_length(value);
    view_bytes(value, 0, length).map(CryptoBytes::Borrowed)
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
///
/// The returned slice borrows `value`: the handle keeps the backing store alive,
/// so the slice cannot outlive it. Callers that hand bytes to OpenSSL inside the
/// same callback use it directly; the ones that must keep the bytes (a job that
/// runs later, an encoding conversion) copy explicitly, which is what makes the
/// copy visible at the call site instead of buried in this helper.
fn view_bytes<'a>(
    value: v8::Local<'a, v8::Value>,
    offset: usize,
    length: usize,
) -> Option<&'a [u8]> {
    let (pointer, total) = view_pointer(value)?;
    let end = offset.checked_add(length)?;
    if end > total {
        return None;
    }
    if pointer.is_null() {
        return if length == 0 { Some(&[]) } else { None };
    }
    // SAFETY: the bounds check proves `offset..offset + length` lies inside the
    // backing store, and `value` is a handle into the live isolate, so the store
    // cannot be collected for as long as the returned borrow is usable.
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
///
/// The no-encoding case must be a real `Buffer`, not a bare `Uint8Array`: Node's
/// `HashDigest` ends in `StringBytes::Encode(..., BUFFER)`, which is
/// `Buffer::Copy` (`src/string_bytes.cc:583`). The difference is load-bearing
/// rather than cosmetic — `node inspect`'s client validates the WebSocket
/// handshake with `shasum.digest().toString('base64')`
/// (`lib/internal/debugger/inspect_client.js:60`), and a `Uint8Array` has no
/// `toString(encoding)` at all, so it printed the byte list instead of the
/// accept value and every `node inspect` session died with
/// `WebSocket secret mismatch`.
fn emit_digest(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue,
    bytes: &[u8],
    encoding_name: Option<&str>,
) {
    match encoding_name {
        None => match encoding::uint8_array(scope, bytes).and_then(|array| as_buffer(scope, array))
        {
            Some(value) => rv.set(value),
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

/// Gives a byte view `Buffer.prototype`, producing a real `Buffer`.
///
/// This is `Buffer::New` (`node_buffer.cc`): a `Uint8Array` over the same
/// backing store with `globalThis.Buffer.prototype` set on it. The prototype
/// comes from the global rather than a stored handle because
/// `internal/bootstrap/node.js` installs `Buffer` as a global getter and user
/// code may replace it, and a `Buffer` built from a stale prototype would not be
/// recognised by `Buffer.isBuffer`.
///
/// `None` before `Buffer` exists, which is a bootstrap ordering error rather than
/// a runtime condition: nothing calls a digest before the realm has `Buffer`.
fn as_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    view: v8::Local<'s, v8::Uint8Array>,
) -> Option<v8::Local<'s, v8::Value>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let constructor = global.get(scope, key.into())?;
    let constructor = v8::Local::<v8::Object>::try_from(constructor).ok()?;
    let prototype_key = v8::String::new(scope, "prototype")?;
    let prototype = constructor.get(scope, prototype_key.into())?;
    view.set_prototype(scope, prototype)?;
    Some(view.into())
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

/// Throws `ERR_CONSTRUCT_CALL_REQUIRED` for a plain call to a constructor.
///
/// Node's `Hash::New` and `Hmac::New` reach `BaseObject`'s internal-field write
/// with the global object as `this` and abort the process. `internal/errors`
/// declares this code as a `TypeError`, which is the class Node throws where it
/// does not abort, so this keeps the error class and the `code` right while
/// making the misuse catchable.
pub(crate) fn throw_construct_call_required(scope: &mut v8::PinScope<'_, '_>) {
    let Some(text) = v8::String::new(scope, "Cannot call constructor without `new`") else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(code_key) = v8::String::new(scope, "code") {
        if let Some(code_value) = v8::String::new(scope, "ERR_CONSTRUCT_CALL_REQUIRED") {
            object.set(scope, code_key.into(), code_value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Builds the JavaScript error object a [`CryptoError`] corresponds to, without
/// throwing it.
///
/// Every arm reproduces a specific `THROW_ERR_*` from Node's C++, because the
/// class and the `code` property are both part of the contract a caller catches
/// on. The digest-name arm is the one place Node itself is inconsistent:
/// `crypto_hash.cc:899` throws an uncoded `Error` with "Digest method not
/// supported" from the `Hash` constructor, while `crypto_hmac.cc`,
/// `crypto_hkdf.cc` and `crypto_pbkdf2.cc` throw a `TypeError` carrying
/// `ERR_CRYPTO_INVALID_DIGEST` and "Invalid digest: <name>". Both are reproduced
/// as they are rather than unified, because a library that catches the code must
/// see the same absence or presence it would on Node.
pub(crate) fn crypto_error_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    error: &CryptoError,
) -> v8::Local<'s, v8::Value> {
    let (kind, message, code): (ErrorClass, String, Option<&str>) = match error {
        CryptoError::UnknownAlgorithm { name, api } => match api {
            engine::DigestApi::HashConstructor => (
                ErrorClass::Error,
                "Digest method not supported".to_string(),
                None,
            ),
            engine::DigestApi::DigestConsumer => (
                ErrorClass::TypeError,
                format!("Invalid digest: {name}"),
                Some("ERR_CRYPTO_INVALID_DIGEST"),
            ),
        },
        CryptoError::TimingSafeEqualLength => (
            ErrorClass::RangeError,
            "Input buffers must have the same byte length".to_string(),
            Some("ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH"),
        ),
        CryptoError::InvalidKeyLength => (
            ErrorClass::RangeError,
            "Invalid key length".to_string(),
            Some("ERR_CRYPTO_INVALID_KEYLEN"),
        ),
        CryptoError::HkdfFailed => (
            ErrorClass::Error,
            "HKDF derivation failed".to_string(),
            None,
        ),
        other => (ErrorClass::Error, other.to_string(), None),
    };
    build_error(scope, kind, &message, code)
}

/// Which constructor `build_error` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorClass {
    Error,
    TypeError,
    RangeError,
}

/// Builds an error of `kind` carrying `code` as an own property, the way
/// `internal/errors.js` installs it.
fn build_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    kind: ErrorClass,
    message: &str,
    code: Option<&str>,
) -> v8::Local<'s, v8::Value> {
    let Some(text) = v8::String::new(scope, message) else {
        return v8::undefined(scope).into();
    };
    let exception = match kind {
        ErrorClass::Error => v8::Exception::error(scope, text),
        ErrorClass::TypeError => v8::Exception::type_error(scope, text),
        ErrorClass::RangeError => v8::Exception::range_error(scope, text),
    };
    if let Some(code) = code {
        if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
            if let Some(key) = v8::String::new(scope, "code") {
                if let Some(value) = v8::String::new(scope, code) {
                    object.set(scope, key.into(), value.into());
                }
            }
        }
    }
    exception
}

/// Throws the JavaScript error a [`CryptoError`] corresponds to.
pub(crate) fn throw_crypto_error(scope: &mut v8::PinScope<'_, '_>, error: &CryptoError) {
    let exception = crypto_error_object(scope, error);
    scope.throw_exception(exception);
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
    fn the_jobs_this_landing_installed_are_not_deferred() {
        // The three random jobs, the Argon2 job and the whole RSA/ECDH surface
        // were each declared `DEFERRED` with a reason that turned out to be
        // false. Naming them here means the next time one is re-deferred it has
        // to be re-deferred deliberately, with the reason rewritten — which is
        // the review question that was missed the first time.
        for member in [
            "RandomBytesJob",
            "RandomPrimeJob",
            "CheckPrimeJob",
            "Argon2Job",
            "kTypeArgon2d",
            "kTypeArgon2i",
            "kTypeArgon2id",
            "privateDecrypt",
            "privateEncrypt",
            "publicDecrypt",
            "publicEncrypt",
            "ECDH",
            "ECDHConvertKey",
            // This one was not in the brief, but `crypto.createMac` failed on it
            // with "getCachedMacAliases is not a function" once the rest of the
            // MAC surface was reachable, so it belongs with the group.
            "getCachedMacAliases",
        ] {
            assert!(
                MEMBERS.contains(&member),
                "{member} must be installed by this landing"
            );
            assert!(
                !DEFERRED.iter().any(|(name, _)| *name == member),
                "{member} is both installed and deferred"
            );
        }
    }

    #[test]
    fn no_deferral_claims_a_missing_feature_that_is_present() {
        // Two reasons this landing replaced were claims about the linked
        // OpenSSL, and both were wrong: Argon2 derives Node's exact bytes for
        // all three variants, and `EVP_MAC_fetch` finds KMAC-128/256 and
        // KECCAK-KMAC-128. A deferral may name a missing *job*, but a claim that
        // the primitive is absent has to be measurable — so the reasons that
        // remain must not assert it for either.
        for (member, reason) in DEFERRED {
            if *member != "Argon2Job" && *member != "kTypeArgon2d" {
                assert!(
                    !reason.contains("Argon2 is not built")
                        && !reason.contains("ARGON2")
                        && !reason.contains("KMAC is not in this OpenSSL"),
                    "{member} claims an absent primitive that is present: {reason}"
                );
            }
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
