//! The `KeyObject` data every handle shares.
//!
//! Node's `KeyObjectData` is one value with two shapes: a symmetric key (a byte
//! string) or an asymmetric key (an `EVP_PKEY` plus the key type it reports as).
//! It is `shared_ptr`-backed, so a `KeyObject` and every `KeyObjectHandle`
//! derived from it refer to one key, and a worker-thread clone shares it too.
//!
//! # Why the key type is part of the value
//!
//! `addRefWithType` is how `createPublicKey(privateKey)` returns a *public*
//! `KeyObject` over the *same* `EVP_PKEY`: the reported type is a property of the
//! view, not of the key. That is why `KeyType` sits beside the key here rather
//! than inside it, and why [`KeyData::as_type`] is a clone rather than a strip.

use std::sync::Arc;

use rn_crypto_openssl::PKey;

/// `KeyType` from `crypto_keys.h`: the three values `kKeyType*` name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyType {
    Secret,
    Public,
    Private,
}

impl KeyType {
    /// The `kKeyType*` value, which is what the binding reports to JavaScript and
    /// what `keys.js` compares against.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Secret => 1,
            Self::Public => 2,
            Self::Private => 3,
        }
    }

    /// Reads a `kKeyType*` value.
    pub fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            1 => Self::Secret,
            2 => Self::Public,
            3 => Self::Private,
            _ => return None,
        })
    }

    /// The `type` string the JavaScript `KeyObject` getter reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// The key material, shared between every handle over it.
#[derive(Clone)]
enum Material {
    Secret(Arc<Vec<u8>>),
    Asymmetric(Arc<PKey>),
}

/// A key and the type it is presented as.
///
/// Cheap to clone; the underlying bytes or `EVP_PKEY` are reference counted.
#[derive(Clone)]
pub struct KeyData {
    key_type: KeyType,
    material: Material,
}

impl std::fmt::Debug for KeyData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyData")
            .field("key_type", &self.key_type)
            .finish_non_exhaustive()
    }
}

impl KeyData {
    /// A symmetric key, which is always `Secret`.
    pub fn secret(bytes: Vec<u8>) -> Self {
        Self {
            key_type: KeyType::Secret,
            material: Material::Secret(Arc::new(bytes)),
        }
    }

    /// An asymmetric key presented as `key_type`.
    ///
    /// The `PKey` is already shared by value, so wrapping it in an `Arc` here is
    /// what makes `addRefWithType` — the public view — free.
    pub fn asymmetric(key_type: KeyType, key: PKey) -> Option<Self> {
        if key_type == KeyType::Secret {
            // A secret key has no `EVP_PKEY`; accepting this would create a
            // `KeyData` whose `symmetric_key()` panics.
            return None;
        }
        Some(Self {
            key_type,
            material: Material::Asymmetric(Arc::new(key)),
        })
    }

    /// The reported key type.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// The same key presented as another type, which is `addRefWithType`.
    ///
    /// This is how `createPublicKey(privateKey)` works: the `EVP_PKEY` is shared,
    /// and only the reported type changes. It is deliberately infallible —
    /// Node's `addRefWithType` has no failure path.
    pub fn as_type(&self, key_type: KeyType) -> Self {
        Self {
            key_type,
            material: self.material.clone(),
        }
    }

    /// The symmetric bytes, or `None` for an asymmetric key.
    pub fn symmetric_key(&self) -> Option<&[u8]> {
        match &self.material {
            Material::Secret(bytes) => Some(bytes),
            Material::Asymmetric(_) => None,
        }
    }

    /// The symmetric key length in bytes.
    pub fn symmetric_key_size(&self) -> usize {
        self.symmetric_key().map_or(0, <[u8]>::len)
    }

    /// The asymmetric key, or `None` for a secret key.
    pub fn asymmetric_key(&self) -> Option<&PKey> {
        match &self.material {
            Material::Asymmetric(key) => Some(key),
            Material::Secret(_) => None,
        }
    }

    /// Whether this holds a key at all. `KeyObjectData` has a null state that
    /// represents "parse failed", and the binding checks it before use.
    pub fn is_valid(&self) -> bool {
        match &self.material {
            Material::Secret(bytes) => !bytes.is_empty(),
            Material::Asymmetric(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_key_reports_its_bytes_and_length() {
        let data = KeyData::secret(vec![1, 2, 3, 4]);
        assert_eq!(data.key_type(), KeyType::Secret);
        assert_eq!(data.symmetric_key(), Some(&[1u8, 2, 3, 4][..]));
        assert_eq!(data.symmetric_key_size(), 4);
        assert!(data.asymmetric_key().is_none());
        assert!(data.is_valid());
    }

    #[test]
    fn an_empty_secret_key_is_not_valid() {
        // `KeyObjectData::operator bool` is false for a failed parse, and an
        // empty secret cannot be a real key — `createSecretKey(Buffer.alloc(0))`
        // is allowed by Node but the handle is still constructible, so what this
        // pins is that the null state is distinguishable.
        assert!(!KeyData::secret(Vec::new()).is_valid());
    }

    #[test]
    fn a_public_view_shares_the_key() {
        let key =
            PKey::from_private(openssl::pkey::PKey::ec_gen("prime256v1").expect("P-256 generates"));
        let private = KeyData::asymmetric(KeyType::Private, key.clone()).expect("a private key");
        let public = private.as_type(KeyType::Public);
        assert_eq!(public.key_type(), KeyType::Public);
        // Same key material, different reported type — that is `addRefWithType`.
        assert_eq!(
            public
                .asymmetric_key()
                .expect("still a key")
                .eq(private.asymmetric_key().expect("a key")),
            rn_crypto_openssl::EqualResult::Equal
        );
    }

    #[test]
    fn a_secret_key_cannot_be_presented_as_asymmetric() {
        assert!(KeyData::asymmetric(
            KeyType::Secret,
            PKey::from_private(openssl::pkey::PKey::ec_gen("prime256v1").expect("generates")),
        )
        .is_none());
    }

    #[test]
    fn the_type_values_match_node() {
        // These are the `kKeyType*` constants `rn-bind-crypto` installs, and the
        // JavaScript compares against them; a drift here would make every key
        // report the wrong type without failing anywhere else.
        assert_eq!(KeyType::Secret.as_raw(), 1);
        assert_eq!(KeyType::Public.as_raw(), 2);
        assert_eq!(KeyType::Private.as_raw(), 3);
        for value in 1..=3 {
            assert_eq!(KeyType::from_raw(value).map(KeyType::as_raw), Some(value));
        }
        assert_eq!(KeyType::from_raw(0), None);
        assert_eq!(KeyType::Secret.as_str(), "secret");
        assert_eq!(KeyType::Public.as_str(), "public");
        assert_eq!(KeyType::Private.as_str(), "private");
    }
}
