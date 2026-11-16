//! The encoding enums JavaScript passes into the key binding.
//!
//! `lib/internal/crypto/keys.js` sends `kKeyFormat*` and `kKeyEncoding*` as
//! plain integers out of the `crypto` namespace, and the binding turns them back
//! into these types. They are an internal protocol between the two halves of the
//! same feature — never a public API — so the discriminants are Node's and are
//! pinned by `rn-bind-crypto`'s constant table rather than derived here.
//!
//! The values are duplicated in `rn-bind-crypto`'s `constants` module because
//! that crate owns the namespace object. This crate deliberately does not depend
//! on it: the dependency runs the other way, and a cycle would be the only
//! alternative.

/// `ncrypto::EVPKeyPointer::PKFormatType`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyFormat {
    /// `kKeyFormatDER` (0).
    Der,
    /// `kKeyFormatPEM` (1).
    Pem,
    /// `kKeyFormatJWK` (2).
    Jwk,
    /// `kKeyFormatRawPublic` (3).
    RawPublic,
    /// `kKeyFormatRawPrivate` (4).
    RawPrivate,
    /// `kKeyFormatRawSeed` (5).
    RawSeed,
    /// `kKeyFormatStore` (6), an OpenSSL STORE loader descriptor.
    Store,
}

impl KeyFormat {
    /// The `kKeyFormat*` value, or `None` for a number Node never sends.
    pub fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Der,
            1 => Self::Pem,
            2 => Self::Jwk,
            3 => Self::RawPublic,
            4 => Self::RawPrivate,
            5 => Self::RawSeed,
            6 => Self::Store,
            _ => return None,
        })
    }

    /// Whether this format carries a raw key, which changes what slot the
    /// encoding *type* means: for raw formats the second argument is an EC point
    /// conversion form or null, not a `kKeyEncoding*`.
    pub fn is_raw(self) -> bool {
        matches!(self, Self::RawPublic | Self::RawPrivate | Self::RawSeed)
    }

    /// The `kKeyFormat*` value, for tests that pin the wire numbers.
    ///
    /// These are `PKFormatType`'s declaration order — `DER, PEM, JWK,
    /// RAW_PUBLIC, RAW_PRIVATE, RAW_SEED, STORE` — which is 0..=6, the same
    /// numbering `crypto_keys.cc` exports with `static_cast<int>`.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Der => 0,
            Self::Pem => 1,
            Self::Jwk => 2,
            Self::RawPublic => 3,
            Self::RawPrivate => 4,
            Self::RawSeed => 5,
            Self::Store => 6,
        }
    }
}

/// `ncrypto::EVPKeyPointer::PKEncodingType`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyEncoding {
    /// RSAPublicKey / RSAPrivateKey according to PKCS#1.
    Pkcs1,
    /// PrivateKeyInfo or EncryptedPrivateKeyInfo according to PKCS#8.
    Pkcs8,
    /// SubjectPublicKeyInfo according to X.509.
    Spki,
    /// ECPrivateKey according to SEC1.
    Sec1,
}

impl KeyEncoding {
    /// The `kKeyEncoding*` value, or `None` for a number Node never sends.
    ///
    /// The numbers are the *declaration order* of `PKEncodingType` in
    /// `deps/ncrypto/ncrypto.h` — `PKCS1, PKCS8, SPKI, SEC1` — not a private
    /// numbering of this crate's own. `crypto_keys.cc` exports them with
    /// `static_cast<int>` of that enum, so the four numbers are observable
    /// through `internalBinding('crypto')` and are what `lib/internal/crypto/
    /// keys.js` compares against. A shifted table stays self-consistent, which
    /// is exactly how one survived: every round trip inside this runtime still
    /// worked while `sec1` silently produced PKCS#8.
    pub fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Pkcs1,
            1 => Self::Pkcs8,
            2 => Self::Spki,
            3 => Self::Sec1,
            _ => return None,
        })
    }

    /// The `kKeyEncoding*` value, for tests that pin the wire numbers.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Pkcs1 => 0,
            Self::Pkcs8 => 1,
            Self::Spki => 2,
            Self::Sec1 => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_encoding_numbers_are_nodes() {
        // `crypto_keys.cc` derives these from `PKEncodingType`'s declaration
        // order, and `node --expose-internals` reports exactly 0 1 2 3.
        assert_eq!(KeyEncoding::Pkcs1.as_raw(), 0);
        assert_eq!(KeyEncoding::Pkcs8.as_raw(), 1);
        assert_eq!(KeyEncoding::Spki.as_raw(), 2);
        assert_eq!(KeyEncoding::Sec1.as_raw(), 3);

        assert_eq!(KeyEncoding::from_raw(0), Some(KeyEncoding::Pkcs1));
        assert_eq!(KeyEncoding::from_raw(1), Some(KeyEncoding::Pkcs8));
        assert_eq!(KeyEncoding::from_raw(2), Some(KeyEncoding::Spki));
        assert_eq!(KeyEncoding::from_raw(3), Some(KeyEncoding::Sec1));
        // The numbering is dense with no gap at either end, so the first value
        // Node never sends is the one past SEC1.
        assert_eq!(KeyEncoding::from_raw(4), None);
        assert_eq!(KeyEncoding::from_raw(-1), None);
    }

    #[test]
    fn the_format_numbers_are_not_the_encoding_numbers() {
        // Both are small integers passed in adjacent argument slots. Sharing a
        // table between them is the easiest way to reintroduce a shift, so the
        // two are pinned separately.
        //
        // `crypto_keys.cc` derives these from `PKFormatType`'s declaration
        // order, and `node --expose-internals` reports exactly 0 1 2 3 4 5 6.
        // They were numbered 1..=7 here until this was pinned: self-consistent,
        // and therefore invisible to every round trip inside this runtime.
        assert_eq!(KeyFormat::Der.as_raw(), 0);
        assert_eq!(KeyFormat::Pem.as_raw(), 1);
        assert_eq!(KeyFormat::Jwk.as_raw(), 2);
        assert_eq!(KeyFormat::RawPublic.as_raw(), 3);
        assert_eq!(KeyFormat::RawPrivate.as_raw(), 4);
        assert_eq!(KeyFormat::RawSeed.as_raw(), 5);
        assert_eq!(KeyFormat::Store.as_raw(), 6);

        assert_eq!(KeyFormat::from_raw(0), Some(KeyFormat::Der));
        assert_eq!(KeyFormat::from_raw(1), Some(KeyFormat::Pem));
        assert_eq!(KeyFormat::from_raw(2), Some(KeyFormat::Jwk));
        assert_eq!(KeyFormat::from_raw(3), Some(KeyFormat::RawPublic));
        assert_eq!(KeyFormat::from_raw(4), Some(KeyFormat::RawPrivate));
        assert_eq!(KeyFormat::from_raw(5), Some(KeyFormat::RawSeed));
        assert_eq!(KeyFormat::from_raw(6), Some(KeyFormat::Store));
        // The numbering is dense with no gap at either end, so the first value
        // Node never sends is the one past STORE.
        assert_eq!(KeyFormat::from_raw(7), None);
        assert_eq!(KeyFormat::from_raw(-1), None);
    }
}

/// How a private key is written out.
#[derive(Clone, Debug, Default)]
pub struct PrivateKeyEncoding {
    pub format: Option<KeyFormat>,
    pub encoding: Option<KeyEncoding>,
    /// The cipher's OpenSSL name, e.g. `"aes-256-cbc"`. Only PEM/DER accept one.
    pub cipher: Option<String>,
    /// The passphrase, used only when `cipher` is set.
    pub passphrase: Option<Vec<u8>>,
    /// When set, `export()` returns a `KeyObjectHandle` instead of bytes. That is
    /// the `generateKeyPairSync` default, where no encoding was requested.
    pub output_key_object: bool,
    /// The EC point conversion form, meaningful only for the raw formats.
    pub ec_point_form: i32,
}

/// How a public key is written out.
#[derive(Clone, Debug, Default)]
pub struct PublicKeyEncoding {
    pub format: Option<KeyFormat>,
    pub encoding: Option<KeyEncoding>,
    /// See [`PrivateKeyEncoding::output_key_object`].
    pub output_key_object: bool,
    /// See [`PrivateKeyEncoding::ec_point_form`].
    pub ec_point_form: i32,
}
