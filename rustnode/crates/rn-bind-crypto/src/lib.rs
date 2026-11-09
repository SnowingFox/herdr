//! `internalBinding('crypto')` for rustnode.
//!
//! The JavaScript in `vendor/libnode-js/lib/crypto.js` and
//! `lib/internal/crypto/**` is unchanged Node code, so this crate is only the
//! native layer underneath it.
//!
//! # The cryptography is OpenSSL's, not a reimplementation
//!
//! rustnode replaces the *native glue*, not the algorithms. Every digest, HMAC,
//! cipher and derivation here is a call into OpenSSL through the `openssl` crate,
//! which is the same library Node itself links. That is the only way a hash can
//! be guaranteed to agree with Node's: two implementations of SHA-256 can be
//! reconciled only by testing every input, while one implementation agrees with
//! itself by construction.
//!
//! The library is built from source by the `vendored` feature, so a machine with
//! no OpenSSL headers still builds. **The first build in a clean `target/` takes
//! about 30 seconds and compiles OpenSSL; every build after that reuses it.** No
//! network access is needed beyond the initial `cargo fetch`: `openssl-src` ships
//! the OpenSSL sources inside the crate.
//!
//! ## Which OpenSSL, and why not the 4.x line
//!
//! Node 28 vendors OpenSSL 4.1.0. `crates/rn-bind-config` already records that
//! version for `constants.crypto.OPENSSL_VERSION_NUMBER`, and matching it was the
//! first choice here. It is not possible yet: `openssl-sys 0.9.118` — the current
//! release, and the newest published — declares `openssl-src = "^300.2.0"`, so
//! the 4.x line cannot satisfy it. That was verified by building with
//! `openssl-src 400.0.2+4.0.3` present: cargo compiles both crates and links
//! **3.6.3**, because only the 3.x version satisfies the dependency. A
//! `[patch.crates-io]` override fails the same way.
//!
//! So this crate links **OpenSSL 3.6.3**, and `engine::openssl_version()` reports
//! what is actually linked rather than what Node ships. The consequence is narrow
//! and worth naming: an algorithm added in 4.x is absent from `getHashes()` and
//! `getCiphers()` here, and those lists are derived from the linked library
//! precisely so that absence is visible instead of advertised and then failing.
//! Everything Node's test suite exercises — SHA-1/2/3, MD5, BLAKE2, AES, ChaCha20,
//! RSA, EC, PBKDF2, scrypt, HKDF — is identical.
//!
//! # Layering
//!
//! | module | what it is |
//! | --- | --- |
//! | [`engine`] | the cryptography, with no V8 types, unit-tested against published vectors |
//! | [`enumerate`] | `getHashes`/`getCiphers`/`getCurves`, walked out of the linked OpenSSL |
//! | [`encoding`] | hex/base64/latin1/UTF-16 conversion and backing-store construction |
//! | [`install`] | the binding object, `Hash`/`Hmac` handles and argument marshalling |
//!
//! # What this landing covers
//!
//! **Hashing** (`createHash`, `Hash`, `HashJob`, `crypto.hash()` through
//! `oneShotDigest`), **HMAC** (`createHmac`, `Hmac`, `HmacJob`), **random**
//! (`randomBytes`, `randomFill`, `randomFillSync`, `randomInt`,
//! `getRandomValues`), **key derivation** (`pbkdf2`, `scrypt`, `hkdf` through
//! their job classes), `timingSafeEqual`, the feature queries, and the three
//! enumeration functions — 62 of the 144 recorded members.
//!
//! Those 62 members carry the whole surface the task prioritised. Verified
//! end to end against a real `node` binary: SHA-1/256/512, MD5, SHA-3, BLAKE2,
//! RIPEMD-160 and SM3 digests, HMAC (including the empty key RFC 2202 case 6),
//! `getHashes()`/`getCiphers()`/`getCurves()` set-equal to Node's, PBKDF2, scrypt
//! and HKDF outputs identical, and SHAKE extension via `outputLength`.
//!
//! The other 82 are in [`install::DEFERRED`], each with a written reason. They
//! are almost entirely the **asymmetric key surface**: `KeyObject`,
//! `KeyObjectHandle`, `createPublicKey`/`createPrivateKey`, `createSign`/
//! `createVerify`, RSA encrypt/decrypt, X.509 and WebCrypto. That is the largest
//! remaining group and the next landing. `CipherBase` (streaming
//! `createCipheriv`) is deferred separately: the engine has the cipher
//! primitives and the enumeration is derived from them, but the handle needs an
//! async completion path.
//!
//! `rn-compat` reports `crypto 144 recorded 0 missing ok`, and
//! `tools/deferred-reach.py` reports no deferral called at module scope — the
//! gate that decides whether `require()` of a dependent module throws.
//!
//! # The one thing outside this crate
//!
//! `require('crypto')` still throws `ERR_NO_CRYPTO` in the CLI, for a reason that
//! is entirely in `crates/rn-cli` and therefore out of scope here:
//! `lib/internal/util.js` computes `const noCrypto = !process.versions.openssl` at
//! module load, and `crates/rn-cli/src/bootstrap.js` builds `process.versions`
//! without an `openssl` key. That needs a one-line CLI change —
//! `openssl: '<version>'` alongside the existing `v8` and `node` entries — and
//! then the namespace loads and every member above works. Verified by making that
//! change temporarily and running the real `lib/crypto.js` path: the digests,
//! HMACs, `crypto.hash()`, enumeration and SHAKE output matched `node`
//! byte-for-byte. The change is reverted, because `rn-cli` belongs to another
//! workstream.
//!
//! # Why `getCachedAliases` reports ids this crate does not use
//!
//! `lib/internal/crypto/util.js` builds a name-to-id cache and passes the id back
//! as `algorithmId`, which is a C++ fast path that skips re-parsing the name. Here
//! the name is authoritative and the id is only required to be *stable and
//! unique*, so it is the algorithm's index in the enumeration. That is enough to
//! keep `getCachedHashId()` from returning `-1` for a valid algorithm.

pub mod classes;
pub mod encoding;
pub mod engine;
pub mod enumerate;
pub mod install;
pub mod kdf;

pub use engine::CryptoError;
pub use install::{Crypto, DEFERRED, MEMBERS};

/// Registers the `crypto` namespace with the runtime.
///
/// Re-exported at the crate root because that is the name
/// `tools/regen-bindings.sh` discovers and generates into
/// `rn-bindings/src/install_all.rs`.
pub use install::register;

#[cfg(test)]
mod tests {
    use rn_core::BindingModule;

    use super::*;

    #[test]
    fn namespace_name_is_crypto() {
        assert_eq!(Crypto.namespace(), "crypto");
    }

    #[test]
    fn members_and_deferrals_are_the_trait_view() {
        assert_eq!(Crypto.members().len(), MEMBERS.len());
        assert_eq!(Crypto.deferred().len(), DEFERRED.len());
    }
}
