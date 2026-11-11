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
    /// `kKeyFormatDER` (1).
    Der,
    /// `kKeyFormatPEM` (2).
    Pem,
    /// `kKeyFormatJWK` (3).
    Jwk,
    /// `kKeyFormatRawPublic` (4).
    RawPublic,
    /// `kKeyFormatRawPrivate` (5).
    RawPrivate,
    /// `kKeyFormatRawSeed` (6).
    RawSeed,
    /// `kKeyFormatStore` (7), an OpenSSL STORE loader descriptor.
    Store,
}

impl KeyFormat {
    /// The `kKeyFormat*` value, or `None` for a number Node never sends.
    pub fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            1 => Self::Der,
            2 => Self::Pem,
            3 => Self::Jwk,
            4 => Self::RawPublic,
            5 => Self::RawPrivate,
            6 => Self::RawSeed,
            7 => Self::Store,
            _ => return None,
        })
    }

    /// Whether this format carries a raw key, which changes what slot the
    /// encoding *type* means: for raw formats the second argument is an EC point
    /// conversion form or null, not a `kKeyEncoding*`.
    pub fn is_raw(self) -> bool {
        matches!(self, Self::RawPublic | Self::RawPrivate | Self::RawSeed)
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
    pub fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            1 => Self::Pkcs1,
            2 => Self::Pkcs8,
            3 => Self::Spki,
            4 => Self::Sec1,
            _ => return None,
        })
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
