//! Bun's hashing group for `rustnode`.
//!
//! `Bun` is one flat property space that several workers fill in parallel, so
//! this crate is a **contribution**: it implements [`rn_bun_api::BunModule`] for
//! [`Hashing`], declares its member names, and installs them into the staging
//! object the registry hands it. It never creates `Bun`, never edits `rn-bun`,
//! `rn-bun-members` or any shared list, and never installs on `globalThis`.
//!
//! # Members
//!
//! | member | what it is |
//! | --- | --- |
//! | `Bun.SHA1` … `Bun.SHA512_256`, `Bun.MD4`, `Bun.MD5` | one class per fixed-width digest |
//! | `Bun.sha` | `SHA-512/256` as a bare one-shot function |
//! | `Bun.hash` | wyhash final-4, plus twelve named variants as own properties |
//! | `Bun.CryptoHasher` | the generic class: 19 algorithms, optional HMAC key |
//!
//! # Why the digests are OpenSSL's
//!
//! Every fixed-width digest, `Bun.sha`, and every `CryptoHasher` algorithm, is
//! `EVP_DigestUpdate`/`EVP_DigestFinal_ex` over the OpenSSL that
//! `rn-bind-crypto` already links. A RustCrypto reimplementation would turn each
//! algorithm into its own compatibility surface; running the same code Bun and
//! Node run means a digest can only disagree through a bug in the glue here.
//!
//! # MD4 and the legacy provider
//!
//! `Bun.MD4` works, and Bun's source says why: it is BoringSSL, which still ships
//! MD4, not OpenSSL 3 with its default-only provider list. This build of OpenSSL
//! has the *code* for MD4 (`ossl_legacy_provider_init` is linked into
//! `libcrypto.a`, because the vendored build is configured without `no-legacy`)
//! but the default context refuses to load it, which is why
//! `crypto.createHash('md4')` fails here exactly as it fails on real Node.
//!
//! So `Bun.MD4` — and `HMAC-MD4` — are served through a **separate, non-default
//! `OSSL_LIB_CTX`** that loads the built-in `default` and `legacy` providers. That
//! context is created on first use and reused; the process-wide default context is
//! never touched, so Node's `crypto` surface keeps reporting exactly what it did
//! before. `digest.rs`'s `md4_is_reachable_and_the_default_context_still_is_not`
//! is the control: it fails if MD4 becomes fetchable from the default context,
//! which is the silent widening this crate must not cause.
//!
//! # `Bun.hash` is not "a fast hash"
//!
//! It is wyhash **final-4**, and [`wyhash::hash`] is a transcription of Bun's
//! `src/wyhash/lib.rs` rather than an equivalent function. The distinction is
//! invisible in benchmarks and fatal in practice: a user's cache keys or dedup
//! checks are values this function produced. It matches Bun's output exactly on
//! 516 recorded vectors covering every input length from 0 to 250, both seed
//! widths, and inputs up to 100 000 bytes — see `tests/wyhash.rs` and
//! `tests/fixtures/wyhash-vectors.txt`.

pub mod digest;
pub mod hashes;
pub mod install;
pub mod wyhash;

use rn_bun_api::BunModule;
use rn_v8_sys::v8;

/// Every member this crate installs on `Bun`.
///
/// `install` sets exactly these and nothing else. The registry compares this list
/// against the staging object in both directions, so a name added here without an
/// install, or installed without being declared, fails the build rather than
/// reaching a caller as `undefined`.
pub const MEMBERS: &[&str] = &[
    "hash",
    "CryptoHasher",
    "sha",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA512_256",
    "MD4",
    "MD5",
];

/// The hashing group's contribution to `Bun`.
pub struct Hashing;

impl BunModule for Hashing {
    fn contributor(&self) -> &'static str {
        "rn-bun-hash"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    /// Nothing in this group is deferred. Every member above is implemented and
    /// tested against values recorded from Bun 1.4.4, including `Bun.hash`, whose
    /// wyhash final-4 output matches exactly.
    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        target: v8::Local<'s, v8::Object>,
    ) -> Result<(), String> {
        install::install(scope, target)
    }
}

/// Registers this crate with the `Bun` registry.
///
/// `tools/regen-bun-contributions.sh` finds this declaration on disk and rewrites
/// the generated aggregator in `rn-bun-members`, which is why adding this crate
/// needed no edit to `rn-bun`.
pub fn register(registry: &mut rn_bun_api::BunRegistry) -> Result<(), String> {
    registry.register_module(Hashing)
}

/// The 19 algorithm names `Bun.CryptoHasher.algorithms` reports, in Bun's order.
///
/// The list is not derivable from anything: it is neither every digest OpenSSL can
/// fetch nor every digest Node exposes. `sha512-256` is hyphenated here while
/// `SHA512_256` (underscored) is the class name, so case-folding one into the other
/// is wrong in both directions.
pub const CRYPTO_HASHER_ALGORITHMS: &[&str] = &[
    "blake2b256",
    "blake2b512",
    "blake2s256",
    "md4",
    "md5",
    "ripemd160",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512-224",
    "sha512-256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "shake128",
    "shake256",
];
