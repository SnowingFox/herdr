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
//! `[patch.crates-io]` override fails the same way: cargo warns that the patch
//! "was not used in the crate graph" and keeps the 3.6.3 entry.
//!
//! So this crate links **OpenSSL 3.6.3**, and `engine::openssl_version()` reports
//! what is actually linked rather than what Node ships.
//!
//! ### The six `getHashes()` names this version cannot supply: cSHAKE
//!
//! `getHashes()` matches Node **element for element** except for six cSHAKE
//! names: `cshake128`, `cshake256`, `cshake-128`, `cshake-256`,
//! `cshake-keccak-128` and `cshake-keccak-256`. This is not an enumeration gap
//! and not a provider that needs loading; it is an absence from the OpenSSL
//! source this build compiles:
//!
//! * **3.6.3 has no cSHAKE anywhere.** `grep -ri cshake` over the vendored
//!   3.6.3 tree returns nothing, `providers/implementations/digests/` has no
//!   `cshake_prov.c`, and the built `libcrypto.a` exports zero symbols matching
//!   `cshake`. No spelling, case, or `EVP_MD_fetch` property query can reach a
//!   digest that was never compiled.
//! * **The legacy provider is not the answer.** cSHAKE is registered by
//!   `providers/defltprov.c` — the *default* provider — in the 4.x line, not by
//!   `legacyprov.c`. `openssl-src` already builds with its `legacy` feature on
//!   (that is `openssl-sys`'s own default), so loading legacy would add MD2/MD4/
//!   RC4 and still not cSHAKE. Confirmed in the 4.0.3 tree
//!   (`defltprov.c:123-133`) and against a real 4.0.3 build, where
//!   `EVP_MD_fetch("cshake-128")` returns `CSHAKE-128` with no provider
//!   property query at all.
//! * **cSHAKE arrived in OpenSSL 4.x.** It is present in every `openssl-src`
//!   4.0.x release (`400.0.0+4.0.1`, `400.0.1+4.0.2`, `400.0.2+4.0.3`), and
//!   absent from every 3.x one. It is a new algorithm family, not a build flag.
//!
//! **Measured, not assumed.** Building this workspace against OpenSSL 4.0.3
//! (via a local `openssl-sys` fork whose `openssl-src` requirement was widened
//! from `^300.2.0` to `<500`) makes `getHashes()` **exactly equal** to the
//! oracle — 87 names, element for element, including all six cSHAKE spellings —
//! and `getMacs()` exactly equal at 11. The 230 crypto unit tests pass on that
//! build. So the cSHAKE gap closes the moment the 4.x line is reachable, and it
//! is reachable only through a dependency change outside this crate.
//!
//! What a future fix needs, stated exactly so it can be checked rather than
//! re-derived:
//!
//! 1. `openssl-sys` (or a maintained fork of it) to accept `openssl-src >=4`,
//!    then `openssl-src = "400.x"` in place of `300.6.1`; **or**
//!    `openssl-src 3.7`/`3.8` to backport cSHAKE (not true of any release as of
//!    3.6.3 — the newest 3.x).
//! 2. No change in this crate. `enumerate.rs` already walks
//!    `EVP_MD_do_all_provided` and `EVP_MD_names_do_all`, which is where the
//!    six names come from; it reports them the moment the library has them.
//!
//! Until then the absence is visible by design: the lists are derived from the
//! linked library, so nothing is advertised that cannot then be used.
//!
//! ### Camellia is a build flag, and is now enabled
//!
//! The 27 `camellia*` cipher names were absent for a different reason: this was
//! `openssl-src`'s default, not an OpenSSL 3.6.3 limitation. `openssl-src` passes
//! `no-camellia` to `Configure` unless its own `camellia` feature is on, which
//! drops `crypto/camellia/` from the build and leaves no `Camellia_*` symbol in
//! `libcrypto.a`. `Cargo.toml` now names `openssl-src` with `features =
//! ["camellia"]` as a build-dependency; because `openssl-sys` already depends on
//! the same crate, cargo unifies the two and enables the feature on the single
//! OpenSSL build. See that file for the cost (build time only) and
//! `enumerate.rs` for why nothing else changed.
//!
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
//! `getRandomValues` with their asynchronous `RandomBytesJob`, `RandomPrimeJob`
//! and `CheckPrimeJob`), **key derivation** (`pbkdf2`, `scrypt`, `hkdf`,
//! `argon2` through their job classes), `timingSafeEqual`, the feature queries,
//! and the three enumeration functions.
//!
//! Those 62 members carry the whole surface the task prioritised. Verified
//! end to end against a real `node` binary: SHA-1/256/512, MD5, SHA-3, BLAKE2,
//! RIPEMD-160 and SM3 digests, HMAC (including the empty key RFC 2202 case 6),
//! `getHashes()`/`getCiphers()`/`getCurves()` set-equal to Node's, PBKDF2, scrypt
//! and HKDF outputs identical, and SHAKE extension via `outputLength`.
//!
//! # The asynchronous job classes
//!
//! Every `*Job` class `lib/**` constructs is a `CryptoJob<traits>`: a mode in
//! slot 0, a `run()` whose meaning depends on that mode, and a completion that
//! is a tuple (`Sync`), an `ondone` call (`Async`) or a promise (`WebCrypto`).
//! That machinery is `rn-crypto-job`, shared with `rn-bind-crypto-cipher`,
//! `rn-bind-crypto-sign` and `rn-bind-crypto-keys`, because four copies is how
//! the modes drift.
//!
//! The random jobs live in [`random_jobs`] and are installed by [`jobs`]. Their
//! absence was not a missing optimisation: `randomFill` at
//! `lib/internal/crypto/random.js:229` constructs a `RandomBytesJob`
//! unconditionally whenever a callback was supplied, so every asynchronous
//! `randomBytes`, `randomFill`, `randomInt`, `generatePrime` and `checkPrime`
//! threw `TypeError: RandomBytesJob is not a constructor` while the synchronous
//! halves worked.
//!
//! `Argon2Job` is in [`argon2_job`]. It was previously deferred on the claim
//! that `openssl-src` does not build OpenSSL's Argon2 provider; it does, and
//! `openssl::kdf::argon2*` reproduces Node's bytes for all three variants.
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

pub mod argon2_job;
pub mod classes;
pub mod encoding;
pub mod engine;
pub mod enumerate;
pub mod install;
pub mod job_async;
pub mod jobs;
pub mod kdf;
pub mod random_jobs;

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
