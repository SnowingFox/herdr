//! The key algorithms `ncrypto::KeyAlgorithm` names, and what each supports.
//!
//! Node resolves a key algorithm by *name*, case-insensitively, out of a fixed
//! table, and then asks it questions: is it RSA, is it available in this
//! OpenSSL, does it support a raw public key, what is its seed size. The
//! JavaScript layer depends on those answers rather than on the algorithm's
//! OpenSSL id, because "the name `crypto.generateKeyPairSync` accepts" and "the
//! `EVP_PKEY` type an imported key reports" are different questions.
//!
//! # Why the table is explicit
//!
//! `EVP_PKEY_get0_type_name` is a provider query that returns the provider's own
//! spelling, and two `EVP_PKEY` types can share one name (`SM2` is an EC key).
//! Node therefore carries a table and matches on `EVP_PKEY_is_a`, in a fixed
//! order, so an imported SM2 key reports `SM2` and not `EC`. The order below is
//! Node's `kKeyAlgorithms` order and is load-bearing for exactly that reason.
//!
//! # Availability is asked, not declared
//!
//! `is_available` builds an `EVP_PKEY_CTX` by name from the linked library, which
//! is exactly what Node's `isAvailable()` does. The answer is a fact about the
//! OpenSSL this binary links, not something this table can assert: the vendored
//! 3.6.3 build *does* provide ML-DSA, ML-KEM and SLH-DSA, so those report
//! available here even though an OpenSSL built without them would not. That is
//! the behaviour Node has too, and it is why `crypto.generateKeyPairSync`'s
//! argument check asks rather than testing a list.

use openssl::pkey::Id;

extern "C" {
    /// The provider's primary name for a key type.
    ///
    /// `openssl-sys 0.9.118` does not export this one, and the table walk below
    /// cannot replace it: `SM2` keys *are* EC keys, so `EVP_PKEY_is_a("EC")`
    /// answers yes for them and the walk would report `EC` for an SM2 key. Node
    /// asks the provider first for exactly this reason, and the answer it gives
    /// is the difference between `asymmetricKeyType === 'sm2'` and `'ec'`.
    fn EVP_PKEY_get0_type_name(pkey: *const openssl_sys::EVP_PKEY) -> *const std::ffi::c_char;
}
/// The family an algorithm belongs to, which decides the raw-key and one-shot
/// behaviour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Family {
    Other,
    EdDsa,
    Xdh,
    MlDsa,
    MlKem,
    SlhDsa,
}

/// One entry of Node's key-algorithm table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyAlgorithm {
    /// The canonical name, as `KeyAlgorithm::name()` returns it.
    name: &'static str,
    /// The lowercase spelling `crypto.generateKeyPairSync` accepts as its
    /// `type`, which is `None` for algorithms Node does not expose that way.
    key_type_name: Option<&'static str>,
    family: Family,
}

impl KeyAlgorithm {
    const fn new(name: &'static str, key_type_name: Option<&'static str>, family: Family) -> Self {
        Self {
            name,
            key_type_name,
            family,
        }
    }

    /// The canonical spelling, e.g. `"RSA-PSS"`.
    pub fn name(self) -> &'static str {
        self.name
    }

    /// The `crypto.generateKeyPairSync` type name, or `None` when Node does not
    /// accept this algorithm there. `SM2` is the only such entry.
    pub fn key_type_name(self) -> Option<&'static str> {
        self.key_type_name
    }

    /// `KeyAlgorithm::isRsa()`: the two RSA variants, which share the
    /// `asymmetricKeyDetails` shape.
    pub fn is_rsa(self) -> bool {
        self.name == RSA.name || self.name == RSA_PSS.name
    }

    /// Whether the linked OpenSSL has a key manager for this algorithm.
    ///
    /// This is `EVP_PKEY_CTX_new_from_name`, which is exactly what Node's
    /// `isAvailable()` calls. A name that resolves here can be generated; one
    /// that does not is absent from this OpenSSL build rather than broken.
    pub fn is_available(self) -> bool {
        // `EVP_PKEY_CTX_new_from_name` with a null library context and property
        // query is the default-provider lookup Node performs. `openssl-sys`
        // models it, and the context is freed immediately: only its existence
        // matters.
        let Ok(c_name) = std::ffi::CString::new(self.name) else {
            return false;
        };
        // SAFETY: `c_name` is a valid NUL-terminated string for the call, and
        // the returned context (if any) is owned by this function and freed
        // exactly once below.
        unsafe {
            let context = openssl_sys::EVP_PKEY_CTX_new_from_name(
                std::ptr::null_mut(),
                c_name.as_ptr(),
                std::ptr::null(),
            );
            if context.is_null() {
                // The failed lookup leaves an error on the queue; clearing it
                // keeps a successful `is_available` from poisoning a later
                // `ThrowCryptoError` with a stale "unsupported algorithm".
                openssl_sys::ERR_clear_error();
                return false;
            }
            openssl_sys::EVP_PKEY_CTX_free(context);
            true
        }
    }

    /// Post-quantum families, which are `AKP` in JWK and use `alg` rather than
    /// `crv`.
    pub fn is_pqc(self) -> bool {
        matches!(self.family, Family::MlDsa | Family::MlKem | Family::SlhDsa)
    }

    /// EdDSA and XDH: the algorithms with an RFC 8037 raw public key.
    pub fn is_okp(self) -> bool {
        matches!(self.family, Family::EdDsa | Family::Xdh)
    }

    /// `KeyAlgorithm::isOneShot`: the algorithms a *streaming* signature handle
    /// cannot drive.
    ///
    /// EdDSA and the post-quantum signature families sign a whole message rather
    /// than a digest, so `crypto.createSign`/`createVerify` reject them with
    /// `ERR_CRYPTO_UNSUPPORTED_OPERATION`. `crypto.sign`/`crypto.verify` (the
    /// one-shot job) still work, because they pass the message through.
    pub fn is_one_shot(self) -> bool {
        // Named individually rather than by family: `Family::EdDsa` also holds
        // X25519 and X448, which are key-agreement algorithms with no signature
        // operation at all, and rejecting them here would change the error a
        // `createSign` on a key-agreement key reports.
        matches!(self.name, "Ed25519" | "Ed448")
            // The post-quantum signature families are named per parameter set
            // (`ML-DSA-44`, `SLH-DSA-SHA2-128f`), so a prefix is the only stable
            // match. ML-KEM is excluded: it is key encapsulation, not a signature.
            || self.name.starts_with("ML-DSA-")
            || self.name.starts_with("SLH-DSA-")
    }

    /// Whether a raw public key can be imported or exported.
    pub fn supports_raw_public(self) -> bool {
        self.is_okp() || self.is_pqc()
    }

    /// Whether a raw private key can be imported or exported. SLH-DSA has a raw
    /// public key but no raw private one; ML-DSA and ML-KEM expose a *seed*
    /// instead, which is a separate format.
    pub fn supports_raw_private(self) -> bool {
        self.is_okp() || self.family == Family::SlhDsa
    }

    /// The seed length in bytes, or 0 when the algorithm has no seed format.
    pub fn seed_size(self) -> usize {
        match self.family {
            Family::MlDsa => 32,
            Family::MlKem => 64,
            _ => 0,
        }
    }

    /// The `openssl` crate's `Id` for this algorithm, where one exists.
    ///
    /// `Id` is the numeric type OpenSSL's legacy API uses. Provider-only
    /// algorithms (the post-quantum families) have no `Id`, so `None` is
    /// returned and callers that need a type must use the name.
    pub fn id(self) -> Option<Id> {
        if self == RSA {
            Some(Id::RSA)
        } else if self == RSA_PSS {
            Some(Id::RSA_PSS)
        } else if self == DSA {
            Some(Id::DSA)
        } else if self == DH {
            Some(Id::DH)
        } else if self == EC {
            Some(Id::EC)
        } else if self == ED25519 {
            Some(Id::ED25519)
        } else if self == ED448 {
            Some(Id::ED448)
        } else if self == X25519 {
            Some(Id::X25519)
        } else if self == X448 {
            Some(Id::X448)
        } else {
            None
        }
    }

    /// Looks an algorithm up by name, case-insensitively.
    ///
    /// This is `KeyAlgorithm::FromName`. It matches the *canonical* spellings
    /// only: `"rsa"` finds `RSA`, but `"rsa-pss"` finds `RSA-PSS` and nothing
    /// else, because the table is the authority on what exists.
    pub fn from_name(name: &str) -> Option<Self> {
        TABLE
            .iter()
            .copied()
            .find(|algorithm| algorithm.name.eq_ignore_ascii_case(name))
    }

    /// Resolves the algorithm behind a parsed `EVP_PKEY`.
    ///
    /// Node first asks the provider for the type name and, when that does not
    /// match a table entry, walks the table with `EVP_PKEY_is_a` in order. The
    /// second step is what makes an SM2 key report `SM2` rather than `EC`.
    pub fn of(pkey: &openssl::pkey::PKeyRef<impl openssl::pkey::HasPublic>) -> Option<Self> {
        use foreign_types::ForeignTypeRef;

        // SAFETY: `as_ptr` is the key's own `EVP_PKEY *`, which stays alive for
        // the duration of the borrow, and every call below only reads from it.
        let raw = pkey.as_ptr();
        let type_name = unsafe { EVP_PKEY_get0_type_name(raw) };
        if !type_name.is_null() {
            // SAFETY: a provider's type name is a static NUL-terminated string.
            let name = unsafe { std::ffi::CStr::from_ptr(type_name) };
            if let Ok(name) = name.to_str() {
                if let Some(algorithm) = Self::from_name(name) {
                    return Some(algorithm);
                }
            }
        }
        TABLE.iter().copied().find(|algorithm| {
            let Ok(c_name) = std::ffi::CString::new(algorithm.name) else {
                return false;
            };
            // SAFETY: `raw` is a live key and `c_name` is NUL-terminated.
            unsafe { openssl_sys::EVP_PKEY_is_a(raw, c_name.as_ptr()) == 1 }
        })
    }
}

/// The name a `KeyAlgorithm` reports, which is also its table index.
pub type KeyAlgorithmName = &'static str;

pub const RSA: KeyAlgorithm = KeyAlgorithm::new("RSA", Some("rsa"), Family::Other);
pub const RSA_PSS: KeyAlgorithm = KeyAlgorithm::new("RSA-PSS", Some("rsa-pss"), Family::Other);
pub const DSA: KeyAlgorithm = KeyAlgorithm::new("DSA", Some("dsa"), Family::Other);
pub const DH: KeyAlgorithm = KeyAlgorithm::new("DH", Some("dh"), Family::Other);
pub const EC: KeyAlgorithm = KeyAlgorithm::new("EC", Some("ec"), Family::Other);
pub const ED25519: KeyAlgorithm = KeyAlgorithm::new("Ed25519", Some("ed25519"), Family::EdDsa);
pub const ED448: KeyAlgorithm = KeyAlgorithm::new("Ed448", Some("ed448"), Family::EdDsa);
pub const X25519: KeyAlgorithm = KeyAlgorithm::new("X25519", Some("x25519"), Family::Xdh);
pub const X448: KeyAlgorithm = KeyAlgorithm::new("X448", Some("x448"), Family::Xdh);
/// SM2 is an EC key with no `crypto.generateKeyPairSync` type of its own, which
/// is why it carries no key type name.
pub const SM2: KeyAlgorithm = KeyAlgorithm::new("SM2", None, Family::Other);
pub const ML_DSA_44: KeyAlgorithm =
    KeyAlgorithm::new("ML-DSA-44", Some("ml-dsa-44"), Family::MlDsa);
pub const ML_DSA_65: KeyAlgorithm =
    KeyAlgorithm::new("ML-DSA-65", Some("ml-dsa-65"), Family::MlDsa);
pub const ML_DSA_87: KeyAlgorithm =
    KeyAlgorithm::new("ML-DSA-87", Some("ml-dsa-87"), Family::MlDsa);
pub const ML_KEM_512: KeyAlgorithm =
    KeyAlgorithm::new("ML-KEM-512", Some("ml-kem-512"), Family::MlKem);
pub const ML_KEM_768: KeyAlgorithm =
    KeyAlgorithm::new("ML-KEM-768", Some("ml-kem-768"), Family::MlKem);
pub const ML_KEM_1024: KeyAlgorithm =
    KeyAlgorithm::new("ML-KEM-1024", Some("ml-kem-1024"), Family::MlKem);
pub const SLH_DSA_SHA2_128F: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHA2-128f",
    Some("slh-dsa-sha2-128f"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHA2_128S: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHA2-128s",
    Some("slh-dsa-sha2-128s"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHA2_192F: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHA2-192f",
    Some("slh-dsa-sha2-192f"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHA2_192S: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHA2-192s",
    Some("slh-dsa-sha2-192s"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHA2_256F: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHA2-256f",
    Some("slh-dsa-sha2-256f"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHA2_256S: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHA2-256s",
    Some("slh-dsa-sha2-256s"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHAKE_128F: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHAKE-128f",
    Some("slh-dsa-shake-128f"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHAKE_128S: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHAKE-128s",
    Some("slh-dsa-shake-128s"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHAKE_192F: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHAKE-192f",
    Some("slh-dsa-shake-192f"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHAKE_192S: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHAKE-192s",
    Some("slh-dsa-shake-192s"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHAKE_256F: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHAKE-256f",
    Some("slh-dsa-shake-256f"),
    Family::SlhDsa,
);
pub const SLH_DSA_SHAKE_256S: KeyAlgorithm = KeyAlgorithm::new(
    "SLH-DSA-SHAKE-256s",
    Some("slh-dsa-shake-256s"),
    Family::SlhDsa,
);

/// Node's `kKeyAlgorithms`, in its order.
///
/// The order matters: `of()` walks it with `EVP_PKEY_is_a`, so `EC` must not
/// precede `SM2` or an SM2 key would report `EC`.
pub const TABLE: &[KeyAlgorithm] = &[
    RSA,
    RSA_PSS,
    DSA,
    DH,
    EC,
    ED25519,
    ED448,
    X25519,
    X448,
    SM2,
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_128S,
    SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_192S,
    SLH_DSA_SHA2_256F,
    SLH_DSA_SHA2_256S,
    SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S,
    SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_256F,
    SLH_DSA_SHAKE_256S,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_resolves_case_insensitively() {
        for algorithm in TABLE {
            assert_eq!(
                KeyAlgorithm::from_name(algorithm.name()),
                Some(*algorithm),
                "{}",
                algorithm.name()
            );
            assert_eq!(
                KeyAlgorithm::from_name(&algorithm.name().to_ascii_lowercase()),
                Some(*algorithm),
                "{}",
                algorithm.name()
            );
        }
    }

    #[test]
    fn unknown_names_do_not_resolve() {
        assert_eq!(KeyAlgorithm::from_name("not-a-key"), None);
        assert_eq!(KeyAlgorithm::from_name(""), None);
    }

    /// The key type name is the canonical name lowercased, except for SM2 which
    /// has none.
    #[test]
    fn key_type_names_are_lowercase_names() {
        for algorithm in TABLE {
            match algorithm.key_type_name() {
                Some(spelling) => assert_eq!(
                    spelling,
                    algorithm.name().to_ascii_lowercase(),
                    "{}",
                    algorithm.name()
                ),
                None => assert_eq!(algorithm.name(), "SM2"),
            }
        }
    }

    #[test]
    fn sm2_is_the_only_algorithm_without_a_key_type() {
        let without: Vec<&str> = TABLE
            .iter()
            .filter(|algorithm| algorithm.key_type_name().is_none())
            .map(|algorithm| algorithm.name())
            .collect();
        assert_eq!(without, vec!["SM2"]);
    }

    #[test]
    fn rsa_and_rsa_pss_are_the_rsa_family() {
        assert!(RSA.is_rsa());
        assert!(RSA_PSS.is_rsa());
        for algorithm in TABLE.iter().filter(|a| !a.is_rsa()) {
            assert!(!algorithm.is_rsa(), "{}", algorithm.name());
        }
    }

    #[test]
    fn okp_and_pqc_support_the_raw_formats() {
        // EdDSA and XDH have an RFC 8037 raw public key; SLH-DSA has both a raw
        // public and a raw private key; ML-DSA/ML-KEM expose a *seed* instead of
        // a raw private key.
        assert!(ED25519.supports_raw_public() && ED25519.supports_raw_private());
        assert!(X448.supports_raw_public() && X448.supports_raw_private());
        assert!(SLH_DSA_SHA2_128F.supports_raw_public());
        assert!(SLH_DSA_SHA2_128F.supports_raw_private());
        assert!(ML_DSA_44.supports_raw_public());
        assert!(!ML_DSA_44.supports_raw_private());
        assert!(ML_KEM_768.supports_raw_public());
        assert!(!ML_KEM_768.supports_raw_private());
        // RSA and EC do not: their raw form is EC-point specific, which the
        // binding handles separately.
        assert!(!RSA.supports_raw_public());
        assert!(!EC.supports_raw_public());
    }

    #[test]
    fn only_mldsa_and_mlkem_have_a_seed() {
        assert_eq!(ML_DSA_44.seed_size(), 32);
        assert_eq!(ML_KEM_768.seed_size(), 64);
        assert_eq!(SLH_DSA_SHA2_128F.seed_size(), 0);
        assert_eq!(ED25519.seed_size(), 0);
    }

    /// Availability is a fact about the linked OpenSSL, so what is asserted here
    /// is the two directions rather than a hard-coded list: the classic
    /// algorithms must be present, and `is_available` must agree with an
    /// independent `EVP_PKEY_CTX` probe for every entry. That keeps the test
    /// honest on a build with or without the post-quantum providers.
    #[test]
    fn availability_agrees_with_a_direct_probe() {
        for algorithm in [RSA, RSA_PSS, DSA, DH, EC, ED25519, ED448, X25519, X448] {
            assert!(
                algorithm.is_available(),
                "{} should be available in this build",
                algorithm.name()
            );
        }
        // The vendored OpenSSL 3.6.3 does ship the post-quantum key types, so
        // this checks agreement rather than assuming either answer. A build
        // without them would flip both sides together.
        for algorithm in TABLE {
            assert_eq!(
                algorithm.is_available(),
                probe_availability(algorithm.name()),
                "{} disagrees with EVP_PKEY_CTX_new_from_name",
                algorithm.name()
            );
        }
    }

    /// An independent `EVP_PKEY_CTX_new_from_name` probe, deliberately not
    /// sharing code with `is_available`.
    fn probe_availability(name: &str) -> bool {
        let Ok(c_name) = std::ffi::CString::new(name) else {
            return false;
        };
        // SAFETY: `c_name` is NUL-terminated for the call and any context is
        // freed exactly once below.
        unsafe {
            let context = openssl_sys::EVP_PKEY_CTX_new_from_name(
                std::ptr::null_mut(),
                c_name.as_ptr(),
                std::ptr::null(),
            );
            openssl_sys::ERR_clear_error();
            if context.is_null() {
                return false;
            }
            openssl_sys::EVP_PKEY_CTX_free(context);
            true
        }
    }

    #[test]
    fn ids_are_present_exactly_for_the_named_algorithms() {
        for algorithm in [RSA, RSA_PSS, DSA, DH, EC, ED25519, ED448, X25519, X448] {
            assert!(algorithm.id().is_some(), "{}", algorithm.name());
        }
        assert_eq!(SM2.id(), None);
        assert_eq!(ML_DSA_44.id(), None);
    }
}
