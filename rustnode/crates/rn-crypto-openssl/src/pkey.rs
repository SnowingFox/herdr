//! The owned `EVP_PKEY` every key object holds.
//!
//! Node's `ncrypto::EVPKeyPointer` is a `unique_ptr`-alike with three jobs: own
//! the key, answer what kind of key it is, and write it back out in the encoding
//! the caller asked for. This is the same type in Rust, on top of
//! `openssl::pkey::PKey` for the ownership and the safe accessors, reaching into
//! `openssl-sys` only where the safe crate has no equivalent.
//!
//! # Why the key is shared rather than cloned
//!
//! `KeyObjectData` in Node is `shared_ptr`-backed so a `KeyObject` and every
//! `KeyObjectHandle` derived from it — and every worker-thread clone — refer to
//! one `EVP_PKEY`. Duplicating the key on every access would be
//! indistinguishable in behaviour but would change `equals()`: `EVP_PKEY_eq` is
//! a value comparison, so it would still answer correctly, but a key that is
//! large (an 8192-bit RSA key is 4 KiB of BIGNUMs) would be copied on every
//! `getKeyObjectHandle`. `Arc` is the equivalent here.

use std::sync::Arc;

use openssl::bn::BigNumRef;
use openssl::pkey::{PKey as OpenSslPKey, Private, Public};
use openssl::rsa::Padding;

use crate::algorithm::{KeyAlgorithm, EC};
use crate::encode::{KeyEncoding, KeyFormat, PrivateKeyEncoding, PublicKeyEncoding};
use crate::error::{failure, ParseFailure, ParseResult};

/// The EC point conversion form, from `internalBinding('constants').crypto`.
///
/// The numbers are OpenSSL's `point_conversion_form_t`, and the JavaScript
/// passes them straight through from the `constants` namespace.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EcPointForm {
    Compressed,
    Uncompressed,
    Hybrid,
}

impl EcPointForm {
    pub fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            2 => Self::Compressed,
            4 => Self::Uncompressed,
            6 => Self::Hybrid,
            _ => return None,
        })
    }

    /// The `point_conversion_form_t` value.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Compressed => 2,
            Self::Uncompressed => 4,
            Self::Hybrid => 6,
        }
    }

    /// The `openssl` crate's equivalent, for `EcPointRef::to_bytes`.
    pub fn as_openssl(self) -> openssl::ec::PointConversionForm {
        match self {
            Self::Compressed => openssl::ec::PointConversionForm::COMPRESSED,
            Self::Uncompressed => openssl::ec::PointConversionForm::UNCOMPRESSED,
            Self::Hybrid => openssl::ec::PointConversionForm::HYBRID,
        }
    }
}

/// An owned, shareable `EVP_PKEY`.
///
/// Cheap to clone (one `Arc` bump) and `Send + Sync`, because `OpenSslPKey` is:
/// the underlying `EVP_PKEY` is reference-counted by OpenSSL and is immutable
/// once parsed, which is what lets `KeyObjectData` be shared with a worker.
#[derive(Clone)]
pub struct PKey {
    inner: Arc<OpenSslPKey<Private>>,
    /// The reported algorithm. Kept alongside the key because resolving it walks
    /// a 28-entry table with `EVP_PKEY_is_a` per entry, and every
    /// `asymmetricKeyType` read would pay for it again otherwise.
    algorithm: Option<KeyAlgorithm>,
}

impl std::fmt::Debug for PKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PKey")
            .field("algorithm", &self.algorithm.map(KeyAlgorithm::name))
            .field("bits", &self.bits())
            .finish()
    }
}

impl PKey {
    /// Wraps a public `EVP_PKEY`. Nothing in the key path produces one — every
    /// import goes through the private-key parser, which also accepts public
    /// keys — but the type is needed where `openssl` hands back `PKey<Public>`.
    pub fn from_public(key: OpenSslPKey<Public>) -> Option<Self> {
        // Adopt a second reference to the same `EVP_PKEY` rather than round-
        // tripping through DER: `PKey<Private>` and `PKey<Public>` are the same
        // C pointer with a different type parameter, and `EVP_PKEY_up_ref` is how
        // the `openssl` crate itself converts between them. A DER round-trip
        // would also work but would re-encode and re-parse a key that is already
        // in hand.
        use foreign_types::ForeignType;
        // `PKey<Private>` and `PKey<Public>` are the same C pointer with a
        // different type parameter, so `from_ptr` only re-labels the ownership
        // type — but it adopts a reference, and `up_ref` is what supplies one.
        // Without it both wrappers would free the same `EVP_PKEY`.
        // SAFETY: `key.as_ptr()` is a live `EVP_PKEY *` owned by `key`.
        unsafe {
            openssl_sys::EVP_PKEY_up_ref(key.as_ptr());
            let promoted = OpenSslPKey::from_ptr(key.as_ptr());
            Some(Self::from_private(promoted))
        }
    }

    /// Wraps a private `EVP_PKEY`, resolving its algorithm once.
    pub fn from_private(key: OpenSslPKey<Private>) -> Self {
        let algorithm = KeyAlgorithm::of(&key);
        Self {
            inner: Arc::new(key),
            algorithm,
        }
    }

    /// The `openssl` wrapper, for the operations this type does not model.
    ///
    /// Named `openssl_ref` rather than `as_ref` because `as_ref` would be
    /// confusable with `std::convert::AsRef::as_ref`, which this type does not
    /// implement and should not appear to.
    pub fn openssl_ref(&self) -> &openssl::pkey::PKeyRef<Private> {
        &self.inner
    }

    /// Whether the key holds private material.
    ///
    /// `openssl::pkey::PKey` is generic over `Private`/`Public`, but a
    /// `PKey<Private>` can still be a public-only key: that is how the
    /// private-key parser reports a public key it read successfully. Ask OpenSSL
    /// rather than trusting the type parameter, because `createPrivateKey` on a
    /// public key must fail and `createPublicKey` on one must not.
    ///
    /// The question is asked in two forms because OpenSSL's provider parameters
    /// name the private component differently per family: an EC/RSA/DSA/DH key
    /// reports it as `d`, while an OKP key has no `d` at all and only answers
    /// through the raw-private accessor. `priv` is checked too because OpenSSL 3
    /// names the EC private parameter `priv` in some key types.
    pub fn has_private(&self) -> bool {
        let mut length = 0usize;
        // SAFETY: `raw()` is this key's live `EVP_PKEY *`; a null output buffer
        // asks only for the length, so nothing is written.
        let raw = unsafe {
            openssl_sys::EVP_PKEY_get_raw_private_key(self.raw(), std::ptr::null_mut(), &mut length)
        };
        if raw == 1 {
            return true;
        }
        // SAFETY: thread-local error queue only; the failed probe above left an
        // entry that must not outlive this function.
        unsafe { openssl_sys::ERR_clear_error() };
        [c"d", c"priv"].iter().any(|name| {
            let Some(value) = self.bn_param(name) else {
                return false;
            };
            value.num_bits() > 0
        })
    }

    /// The raw `EVP_PKEY *`.
    pub fn raw(&self) -> *mut openssl_sys::EVP_PKEY {
        use foreign_types::ForeignTypeRef;
        self.inner.as_ptr()
    }

    /// The reported algorithm, or `None` for a key type this table does not
    /// name.
    pub fn algorithm(&self) -> Option<KeyAlgorithm> {
        self.algorithm
    }

    /// `asymmetricKeyType`: the lowercase key type name, or `None` when the
    /// algorithm has none (SM2) or is unknown.
    pub fn key_type_name(&self) -> Option<&'static str> {
        self.algorithm.and_then(KeyAlgorithm::key_type_name)
    }

    /// The key's strength in bits: the modulus length for RSA, the field size
    /// for EC, the public-key width for the rest.
    pub fn bits(&self) -> u32 {
        self.inner.bits()
    }

    /// Whether this key is of the given algorithm.
    pub fn is_a(&self, algorithm: KeyAlgorithm) -> bool {
        self.algorithm == Some(algorithm)
    }

    /// Whether two keys hold the same key material.
    ///
    /// `EVP_PKEY_eq` answers -2 when the two keys are of different types, which
    /// Node reports as `ERR_CRYPTO_UNSUPPORTED_OPERATION` rather than `false`;
    /// the caller decides, so the three-way answer is returned.
    pub fn eq(&self, other: &Self) -> EqualResult {
        // SAFETY: both pointers are live `EVP_PKEY *` for the duration of the
        // call, and `EVP_PKEY_eq` only reads them.
        match unsafe { openssl_sys::EVP_PKEY_eq(self.raw(), other.raw()) } {
            1 => EqualResult::Equal,
            0 => EqualResult::Unequal,
            _ => EqualResult::Incomparable,
        }
    }

    /// Whether an EC key's parameters and public point are internally
    /// consistent, which is `KeyObjectHandle::CheckEcKeyData`.
    ///
    /// A non-EC key answers `false` rather than failing: the caller
    /// (`keys.js`'s `asymmetricKeyDetails` path) only asks for an EC key, and
    /// Node's `DCHECK(key.isA(KeyAlgorithm::EC))` would abort on anything else.
    pub fn ec_check(&self) -> bool {
        let Ok(ec) = self.inner.ec_key() else {
            return false;
        };
        ec.check_key().is_ok()
    }

    /// `EVP_PKEY_CTX` for this key with key generation initialised, which the
    /// keygen jobs use.
    pub fn new_ctx(&self) -> Option<openssl::pkey_ctx::PkeyCtx<Private>> {
        openssl::pkey_ctx::PkeyCtx::new(self.openssl_ref()).ok()
    }

    /// Encodes this key with a public-key encoding.
    ///
    /// Returns `Ok(None)` when the configuration asks for a `KeyObjectHandle`
    /// instead of bytes, which the caller satisfies by handing the key back.
    /// That is not an error, it is the `generateKeyPairSync` default.
    pub fn write_public(&self, config: &PublicKeyEncoding) -> ParseResult<Option<EncodedKey>> {
        if config.output_key_object {
            return Ok(None);
        }
        let format = config.format.unwrap_or(KeyFormat::Pem);
        if format == KeyFormat::Jwk {
            // JWK is assembled from the key's components by the binding crate,
            // which is where the JSON shape belongs. Reaching here means the
            // caller asked this layer for something it does not do.
            return Ok(None);
        }
        if format == KeyFormat::RawPublic {
            return Ok(None);
        }
        let bytes = match (format, config.encoding) {
            // A PEM *type* is meaningful: `type: 'pkcs1'` writes
            // `BEGIN RSA PUBLIC KEY`, and returning SPKI for it is a silent
            // format change that `test-crypto-keygen-sync.js` catches with a
            // regex on the header.
            (KeyFormat::Pem, Some(KeyEncoding::Pkcs1)) => {
                if !self.is_a(crate::algorithm::RSA) {
                    return Err(failure(true));
                }
                let rsa = self.inner.rsa().map_err(|_| failure(false))?;
                rsa.public_key_to_pem_pkcs1()
            }
            (KeyFormat::Pem, _) => self.inner.public_key_to_pem(),
            (KeyFormat::Der, Some(KeyEncoding::Pkcs1)) => {
                // PKCS#1 is RSA-only. For another type OpenSSL's `i2d_PUBKEY`
                // would silently produce SPKI, so the rejection is explicit.
                if !self.is_a(crate::algorithm::RSA) {
                    return Err(failure(true));
                }
                let rsa = self.inner.rsa().map_err(|_| failure(false))?;
                rsa.public_key_to_der_pkcs1()
            }
            (KeyFormat::Der, _) => self.inner.public_key_to_der(),
            _ => return Err(failure(true)),
        };
        match bytes {
            Ok(bytes) => Ok(Some(EncodedKey::new(format, bytes))),
            Err(_) => Err(failure(false)),
        }
    }

    /// Encodes this key with a private-key encoding.
    pub fn write_private(&self, config: &PrivateKeyEncoding) -> ParseResult<Option<EncodedKey>> {
        if config.output_key_object {
            return Ok(None);
        }
        let format = config.format.unwrap_or(KeyFormat::Pem);
        if matches!(
            format,
            KeyFormat::Jwk | KeyFormat::RawPrivate | KeyFormat::RawSeed | KeyFormat::Store
        ) {
            return Ok(None);
        }
        let cipher = match &config.cipher {
            Some(name) => {
                // The cipher applies only to PEM and DER, and
                // `GetPrivateKeyEncodingFromJs` has already rejected the other
                // formats.
                let Some(nid) = nid_of_cipher(name) else {
                    return Err(failure(true));
                };
                let Some(cipher) = openssl::symm::Cipher::from_nid(nid) else {
                    return Err(failure(true));
                };
                Some(cipher)
            }
            None => None,
        };
        let passphrase = config.passphrase.as_deref().unwrap_or(&[]);

        let bytes = match (format, config.encoding) {
            (KeyFormat::Pem, Some(KeyEncoding::Pkcs1)) => {
                if !self.is_a(crate::algorithm::RSA) {
                    return Err(failure(true));
                }
                let rsa = self.inner.rsa().map_err(|_| failure(false))?;
                match cipher {
                    Some(cipher) => rsa.private_key_to_pem_passphrase(cipher, passphrase),
                    None => rsa.private_key_to_pem(),
                }
            }
            (KeyFormat::Pem, Some(KeyEncoding::Sec1)) => {
                if !self.is_a(EC) {
                    return Err(failure(true));
                }
                let ec = self.inner.ec_key().map_err(|_| failure(false))?;
                match cipher {
                    Some(cipher) => ec.private_key_to_pem_passphrase(cipher, passphrase),
                    None => ec.private_key_to_pem(),
                }
            }
            (KeyFormat::Pem, _) => match cipher {
                Some(cipher) => self
                    .inner
                    .private_key_to_pem_pkcs8_passphrase(cipher, passphrase),
                None => self.inner.private_key_to_pem_pkcs8(),
            },
            (KeyFormat::Der, Some(KeyEncoding::Pkcs1)) => {
                if !self.is_a(crate::algorithm::RSA) {
                    return Err(failure(true));
                }
                let rsa = self.inner.rsa().map_err(|_| failure(false))?;
                // DER PKCS#1 does not permit encryption; OpenSSL's
                // `i2d_RSAPrivateKey_bio` has no cipher argument at all, and
                // Node's `GetPrivateKeyEncodingFromJs` rejects the pair before
                // reaching here.
                rsa.private_key_to_der()
            }
            (KeyFormat::Der, Some(KeyEncoding::Sec1)) => {
                if !self.is_a(EC) {
                    return Err(failure(true));
                }
                let ec = self.inner.ec_key().map_err(|_| failure(false))?;
                ec.private_key_to_der()
            }
            (KeyFormat::Der, _) => match cipher {
                Some(cipher) => self
                    .inner
                    .private_key_to_pkcs8_passphrase(cipher, passphrase),
                None => self.inner.private_key_to_pkcs8(),
            },
            _ => return Err(failure(true)),
        };
        match bytes {
            Ok(bytes) => Ok(Some(EncodedKey::new(format, bytes))),
            Err(_) => Err(failure(false)),
        }
    }

    /// The raw public key bytes, for the OKP and post-quantum formats.
    pub fn raw_public_key(&self) -> Option<Vec<u8>> {
        self.inner.raw_public_key().ok()
    }

    /// The raw private key bytes, for the OKP formats.
    pub fn raw_private_key(&self) -> Option<Vec<u8>> {
        self.inner.raw_private_key().ok()
    }

    /// The seed bytes, for ML-DSA and ML-KEM.
    ///
    /// The seed is 32 bytes for ML-DSA and 64 for ML-KEM, and asking for it on a
    /// key that was imported from an expanded form fails — that is
    /// `RawExportError::MISSING_SEED` in Node, which reports "key does not have
    /// an available seed".
    pub fn raw_seed(&self) -> Option<Vec<u8>> {
        let size = self.algorithm?.seed_size();
        if size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size];
        self.inner.seed_into(&mut buffer).ok()?;
        Some(buffer)
    }

    /// Exports the EC public key in a point conversion form.
    ///
    /// `i2d_PUBKEY` would emit SPKI; the raw form is the point alone, which is
    /// what `options.format === 'raw-public'` with an EC key asks for.
    pub fn ec_public_point(&self, form: EcPointForm) -> Option<Vec<u8>> {
        let ec = self.inner.ec_key().ok()?;
        let group = ec.group();
        let point = ec.public_key();
        let mut context = openssl::bn::BigNumContext::new().ok()?;
        point.to_bytes(group, form.as_openssl(), &mut context).ok()
    }

    /// Exports the EC private scalar.
    pub fn ec_private_scalar(&self) -> Option<Vec<u8>> {
        let ec = self.inner.ec_key().ok()?;
        let width = ec.group().order_bits().div_ceil(8) as i32;
        ec.private_key().to_vec_padded(width).ok()
    }

    /// Exports the EC private key as SEC1 PKCS#8.
    pub fn ec_private_pkcs8(&self) -> Option<Vec<u8>> {
        self.inner.private_key_to_pkcs8().ok()
    }

    /// `keyDetail()` for an RSA key: modulus length and public exponent, plus
    /// the PSS parameters for an `RSA-PSS` key that carried them.
    pub fn rsa_detail(&self) -> Option<RsaDetail> {
        let rsa = self.inner.rsa().ok()?;
        let modulus_length = rsa.n().num_bits() as u32;
        let public_exponent = rsa.e().to_vec();
        let pss = if self.is_a(crate::algorithm::RSA_PSS) {
            self.rsa_pss_params()
        } else {
            None
        };
        Some(RsaDetail {
            modulus_length,
            public_exponent,
            pss,
        })
    }
    /// The RSASSA-PSS parameters an `RSA-PSS` key was created with.
    ///
    /// An *absent* parameters sequence means the key is unrestricted and Node adds
    /// nothing; an *empty* sequence restricts the key to the defaults (SHA-1,
    /// MGF1-SHA-1, salt length 20) and Node adds all three. Node tells the two
    /// apart by asking for `saltlen`, which reads only when the sequence is
    /// present — so `None` here means "unrestricted", not "read failed".
    ///
    /// The parameter names are OpenSSL's `OSSL_PKEY_PARAM_RSA_PSS_SALTLEN`
    /// (`"saltlen"`), `OSSL_PKEY_PARAM_RSA_DIGEST` (`"digest"`) and
    /// `OSSL_PKEY_PARAM_RSA_MGF1_DIGEST` (`"mgf1-digest"`). Guessing at
    /// `"pss.digest-algorithm"` returns nothing even on a restricted key, which
    /// makes every `rsa-pss` key look unrestricted.
    fn rsa_pss_params(&self) -> Option<RsaPssParams> {
        // SAFETY: `raw()` is the live key; the string parameters are copied into
        // the buffers below and the queue is cleared so a deliberate miss does not
        // surface later.
        unsafe {
            let salt_length = int_param(self.raw(), c"saltlen")?;
            // A restricted key reports the salt length it will use. The two
            // negative spellings mean "follow the digest", which is a *restricted*
            // key too — `RSA_PSS_SALTLEN_DIGEST` (-1) and `_AUTO` (-2) — so the
            // resolved digest size is reported instead of the sentinel, which is
            // what `asymmetricKeyDetails.saltLength` is documented to be.
            let salt_length = if salt_length < 0 {
                digest_size(salt_length, &self.raw_digest_name())?
            } else {
                salt_length
            };
            // The provider may omit default SHA-1 parameters, so a missing digest
            // means SHA-1 rather than a malformed key.
            let digest = self
                .raw_digest_name()
                .map(|name| pss_digest_long_name(&name))
                .unwrap_or_else(|| "sha1".to_string());
            let mgf1_digest = utf8_param(self.raw(), c"mgf1-digest")
                .map(|name| pss_digest_long_name(&name))
                .unwrap_or_else(|| digest.clone());
            Some(RsaPssParams {
                digest,
                mgf1_digest: Some(mgf1_digest),
                salt_length,
            })
        }
    }

    /// The provider's own spelling of the key's digest, e.g. `"SHA2-256"`.
    ///
    /// # Safety-free by construction
    ///
    /// Reads only; the queue is cleared on a miss so a key without a digest does
    /// not leave an entry for the next caller.
    pub fn raw_digest_name(&self) -> Option<String> {
        // SAFETY: `raw()` is the live key; the parameter is copied into the
        // buffer below.
        unsafe { utf8_param(self.raw(), c"digest") }
    }

    /// The modulus length and divisor length of a DSA key.
    pub fn dsa_detail(&self) -> Option<DsaDetail> {
        let dsa = self.inner.dsa().ok()?;
        Some(DsaDetail {
            modulus_length: dsa.p().num_bits() as usize,
            divisor_length: dsa.q().num_bits() as usize,
        })
    }

    /// The named curve of an EC key, in Node's short form (`"prime256v1"`).
    pub fn ec_curve_name(&self) -> Option<String> {
        let ec = self.inner.ec_key().ok()?;
        let nid = ec.group().curve_name()?;
        Some(nid.short_name().ok()?.to_string())
    }

    /// Sets the RSA padding on an operation context, used by the sign and
    /// cipher crates.
    pub fn set_rsa_padding(
        context: &mut openssl::pkey_ctx::PkeyCtx<Private>,
        padding: Padding,
    ) -> bool {
        context.set_rsa_padding(padding).is_ok()
    }

    /// `EVP_PKEY_bits` for a borrowed BIGNUM, exposed so the detail paths do not
    /// each need a raw call.
    pub fn bignum_bits(value: &BigNumRef) -> u32 {
        value.num_bits() as u32
    }

    /// Reads a BIGNUM parameter off the key by name.
    ///
    /// `openssl` exposes the classic per-type accessors (`rsa().n()`) but not the
    /// generic provider query, and the DH and sign crates need `p`, `q` and `g`
    /// without knowing which family the key is. The returned `BigNum` owns its
    /// reference, so nothing borrows from the key.
    pub fn bn_param(&self, name: &std::ffi::CStr) -> Option<openssl::bn::BigNum> {
        let mut pointer: *mut openssl_sys::BIGNUM = std::ptr::null_mut();
        // SAFETY: `raw()` is the live key and `name` is NUL-terminated; a success
        // hands back a new `BIGNUM` reference, adopted below.
        let ok =
            unsafe { openssl_sys::EVP_PKEY_get_bn_param(self.raw(), name.as_ptr(), &mut pointer) };
        if ok != 1 || pointer.is_null() {
            // SAFETY: thread-local error queue only.
            unsafe { openssl_sys::ERR_clear_error() };
            return None;
        }
        // SAFETY: `pointer` is a new reference from `EVP_PKEY_get_bn_param`, and
        // `BigNum::from_ptr` adopts exactly one.
        use foreign_types::ForeignType;
        Some(unsafe { openssl::bn::BigNum::from_ptr(pointer) })
    }

    /// Converts this key to a public-only view, for `createPublicKey` from a
    /// private key.
    ///
    /// Node's `addRefWithType(kKeyTypePublic)` keeps the *same* `EVP_PKEY` and
    /// only changes the reported type, so this returns a clone of the shared key
    /// rather than stripping the private half. That matters: a
    /// `createPublicKey(privateKey)` result must still export the public half in
    /// every format, and exporting a public-only view as SPKI works either way.
    pub fn to_public_view(&self) -> Self {
        self.clone()
    }
}

/// The three-way answer `EVP_PKEY_eq` gives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EqualResult {
    Equal,
    Unequal,
    /// The keys are of different types. Node maps this to
    /// `ERR_CRYPTO_UNSUPPORTED_OPERATION`, not to `false`.
    Incomparable,
}

/// An encoded key and the format it was encoded in.
///
/// Which format it was matters: PEM becomes a `String` and DER a `Buffer` at the
/// JavaScript boundary, so the format has to travel with the bytes.
#[derive(Clone, Debug)]
pub struct EncodedKey {
    pub format: KeyFormat,
    pub bytes: Vec<u8>,
}

impl EncodedKey {
    pub fn new(format: KeyFormat, bytes: Vec<u8>) -> Self {
        Self { format, bytes }
    }

    /// Whether this encoding should reach JavaScript as a string.
    pub fn is_text(&self) -> bool {
        self.format == KeyFormat::Pem
    }
}

/// The salt length a negative sentinel stands for.
///
/// `RSA_PSS_SALTLEN_DIGEST` (-1) and `_AUTO` (-2) both mean "as long as the
/// digest", and the reported value is that digest's size. `None` when the digest
/// cannot be resolved, which means the parameters are malformed.
fn digest_size(sentinel: i32, digest: &Option<String>) -> Option<i32> {
    if sentinel != -1 && sentinel != -2 {
        return None;
    }
    let name = digest.as_deref()?;
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: NUL-terminated name, read-only lookups.
    unsafe {
        let md = openssl_sys::EVP_get_digestbyname(c_name.as_ptr());
        if md.is_null() {
            openssl_sys::ERR_clear_error();
            return None;
        }
        let size = openssl_sys::EVP_MD_get_size(md);
        (size > 0).then_some(size)
    }
}

/// `asymmetricKeyDetails` for an RSA key.
#[derive(Clone, Debug)]
pub struct RsaDetail {
    pub modulus_length: u32,
    /// The public exponent as a big-endian byte string, which is what Node puts
    /// in an `ArrayBuffer` for `publicExponent`.
    pub public_exponent: Vec<u8>,
    /// Present only for a restricted `RSA-PSS` key.
    pub pss: Option<RsaPssParams>,
}

/// The RSASSA-PSS parameters an `RSA-PSS` key was restricted with.
#[derive(Clone, Debug)]
pub struct RsaPssParams {
    /// The digest name, e.g. `"sha256"`.
    pub digest: String,
    /// The MGF1 digest, absent when the MGF is not MGF1.
    pub mgf1_digest: Option<String>,
    /// The salt length; -1 means "the digest length", which is OpenSSL's
    /// `RSA_PSS_SALTLEN_DIGEST`.
    pub salt_length: i32,
}

/// `RsaPssDigestLongName`: the long name for a digest the provider reported.
///
/// The provider answers with its own spelling — `"SHA2-256"` — and
/// `asymmetricKeyDetails.hashAlgorithm` has to be the `OBJ_nid2ln` long name,
/// `"sha256"`. Resolving through the name → NID → long-name chain is what makes
/// the two agree; lowercasing the provider's string leaves `"sha2-256"`, which no
/// Node test accepts.
fn pss_digest_long_name(name: &str) -> String {
    let Ok(c_name) = std::ffi::CString::new(name) else {
        return name.to_ascii_lowercase();
    };
    // SAFETY: `c_name` is NUL-terminated and valid for the call; both lookups
    // only read it and return static data.
    unsafe {
        let digest = openssl_sys::EVP_get_digestbyname(c_name.as_ptr());
        if digest.is_null() {
            openssl_sys::ERR_clear_error();
            return name.to_ascii_lowercase();
        }
        let nid = openssl_sys::EVP_MD_get_type(digest);
        if nid == openssl_sys::NID_undef {
            return name.to_ascii_lowercase();
        }
        let long = openssl_sys::OBJ_nid2ln(nid);
        if long.is_null() {
            return name.to_ascii_lowercase();
        }
        std::ffi::CStr::from_ptr(long)
            .to_string_lossy()
            .into_owned()
    }
}

/// `asymmetricKeyDetails` for a DSA key.
#[derive(Clone, Debug)]
pub struct DsaDetail {
    pub modulus_length: usize,
    pub divisor_length: usize,
}

/// Reads an OpenSSL `utf8_string` parameter off a key.
///
/// # Safety
///
/// `pkey` must be a live `EVP_PKEY *`. The returned string is owned by the
/// caller; nothing borrows from OpenSSL after the call.
unsafe fn utf8_param(pkey: *const openssl_sys::EVP_PKEY, name: &std::ffi::CStr) -> Option<String> {
    let mut buffer = [0i8; 128];
    let mut length = 0usize;
    let ok = openssl_sys::EVP_PKEY_get_utf8_string_param(
        pkey,
        name.as_ptr(),
        buffer.as_mut_ptr(),
        buffer.len(),
        &mut length,
    );
    if ok != 1 {
        openssl_sys::ERR_clear_error();
        return None;
    }
    let bytes: Vec<u8> = buffer[..length.min(buffer.len())]
        .iter()
        .map(|value| *value as u8)
        .collect();
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Reads an `int` parameter off a key.
///
/// # Safety
///
/// `pkey` must be a live `EVP_PKEY *`.
unsafe fn int_param(pkey: *const openssl_sys::EVP_PKEY, name: &std::ffi::CStr) -> Option<i32> {
    let mut value = 0i32;
    let ok = openssl_sys::EVP_PKEY_get_int_param(pkey, name.as_ptr(), &mut value);
    if ok != 1 {
        openssl_sys::ERR_clear_error();
        return None;
    }
    Some(value)
}

/// Resolves a cipher name to its NID, which is how `openssl::symm::Cipher` is
/// looked up.
///
/// `OBJ_txt2nid` is not in `openssl-sys`; `EVP_get_cipherbyname` is, and it
/// resolves exactly the names `crypto.createCipheriv` accepts — including the
/// aliases `OBJ_txt2nid` would miss, because it goes through the same lookup
/// OpenSSL's own cipher-name parsing uses.
fn nid_of_cipher(name: &str) -> Option<openssl::nid::Nid> {
    let Ok(c_name) = std::ffi::CString::new(name) else {
        return None;
    };
    // SAFETY: `c_name` is NUL-terminated and valid for the call; the lookup only
    // reads it and returns a static `EVP_CIPHER *`.
    let cipher = unsafe { openssl_sys::EVP_get_cipherbyname(c_name.as_ptr()) };
    if cipher.is_null() {
        // SAFETY: thread-local error queue only.
        unsafe { openssl_sys::ERR_clear_error() };
        return None;
    }
    // SAFETY: `cipher` is a live static descriptor from the table above.
    let nid = unsafe { openssl_sys::EVP_CIPHER_get_nid(cipher) };
    if nid == openssl_sys::NID_undef {
        return None;
    }
    Some(openssl::nid::Nid::from_raw(nid))
}

/// A `ParseResult` shorthand for the "wrong key type" rejection.
pub fn wrong_key_type() -> ParseFailure {
    failure(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed RSA key, so the tests do not pay for generation.
    const RSA_PEM: &str = include_str!("../tests/data/rsa-2048.pem");

    fn rsa() -> PKey {
        let key =
            OpenSslPKey::private_key_from_pem(RSA_PEM.as_bytes()).expect("the fixture parses");
        PKey::from_private(key)
    }

    #[test]
    fn algorithm_resolution_names_the_key_type() {
        let key = rsa();
        assert_eq!(key.algorithm(), Some(crate::algorithm::RSA));
        assert_eq!(key.key_type_name(), Some("rsa"));
        assert_eq!(key.bits(), 2048);
        assert!(key.has_private());
    }

    #[test]
    fn public_encoding_round_trips() {
        let key = rsa();
        let pem = key
            .write_public(&PublicKeyEncoding::default())
            .expect("encoding succeeds")
            .expect("a PEM encoding");
        assert!(pem.is_text());
        assert!(pem.bytes.starts_with(b"-----BEGIN PUBLIC KEY-----"));

        let der = key
            .write_public(&PublicKeyEncoding {
                format: Some(KeyFormat::Der),
                ..Default::default()
            })
            .expect("encoding succeeds")
            .expect("a DER encoding");
        assert!(!der.is_text());

        let pkcs1 = key
            .write_public(&PublicKeyEncoding {
                format: Some(KeyFormat::Der),
                encoding: Some(KeyEncoding::Pkcs1),
                ..Default::default()
            })
            .expect("PKCS#1 is allowed for RSA")
            .expect("a DER encoding");
        // `RSAPublicKey ::= SEQUENCE` is a plain SEQUENCE; SPKI wraps it in an
        // AlgorithmIdentifier, so the two differ in both length and content.
        assert_ne!(pkcs1.bytes, der.bytes);
    }

    #[test]
    fn pkcs1_is_rejected_for_a_non_rsa_key() {
        let key = OpenSslPKey::ec_gen("prime256v1").expect("P-256 generates");
        let key = PKey::from_private(key);
        let outcome = key.write_public(&PublicKeyEncoding {
            format: Some(KeyFormat::Der),
            encoding: Some(KeyEncoding::Pkcs1),
            ..Default::default()
        });
        assert!(outcome.is_err(), "PKCS#1 is RSA-only");
    }

    #[test]
    fn output_key_object_means_no_bytes() {
        let key = rsa();
        let outcome = key
            .write_public(&PublicKeyEncoding {
                output_key_object: true,
                ..Default::default()
            })
            .expect("not an error");
        assert!(outcome.is_none());
    }

    #[test]
    fn private_encoding_round_trips_and_encrypts() {
        let key = rsa();
        let pem = key
            .write_private(&PrivateKeyEncoding::default())
            .expect("encoding succeeds")
            .expect("a PEM encoding");
        assert!(pem.bytes.starts_with(b"-----BEGIN PRIVATE KEY-----"));

        let encrypted = key
            .write_private(&PrivateKeyEncoding {
                cipher: Some("aes-256-cbc".to_string()),
                passphrase: Some(b"secret".to_vec()),
                ..Default::default()
            })
            .expect("encryption succeeds")
            .expect("an encrypted PEM encoding");
        assert!(encrypted
            .bytes
            .starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    }

    #[test]
    fn ec_detail_and_raw_exports_agree() {
        let key = OpenSslPKey::ec_gen("prime256v1").expect("P-256 generates");
        let key = PKey::from_private(key);
        assert_eq!(key.ec_curve_name().as_deref(), Some("prime256v1"));
        assert!(key.has_private());

        let compressed = key
            .ec_public_point(EcPointForm::Compressed)
            .expect("the point exports");
        let uncompressed = key
            .ec_public_point(EcPointForm::Uncompressed)
            .expect("the point exports");
        // Compressed is 33 bytes (a 32-byte X coordinate plus the 0x02/0x03
        // parity prefix); uncompressed is 65 (plus the 0x04 prefix).
        assert_eq!(compressed.len(), 33);
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(compressed[0] & 0xfe, 0x02);
        assert_eq!(uncompressed[0], 0x04);

        let scalar = key.ec_private_scalar().expect("the private scalar exports");
        assert_eq!(scalar.len(), 32);
    }

    #[test]
    fn rsa_detail_reports_modulus_and_exponent() {
        let key = rsa();
        let detail = key.rsa_detail().expect("an RSA key has a detail");
        assert_eq!(detail.modulus_length, 2048);
        // The fixture was generated with 65537 as the exponent.
        assert_eq!(detail.public_exponent, vec![0x01, 0x00, 0x01]);
        assert!(
            detail.pss.is_none(),
            "a plain RSA key has no PSS parameters"
        );
    }

    #[test]
    fn equality_is_three_way() {
        let key = rsa();
        assert_eq!(key.eq(&key.clone()), EqualResult::Equal);

        let other = OpenSslPKey::ec_gen("prime256v1").expect("P-256 generates");
        assert_eq!(
            key.eq(&PKey::from_private(other)),
            EqualResult::Incomparable,
            "different key types are not merely unequal"
        );
    }

    #[test]
    fn a_public_key_is_not_a_private_key() {
        let key = rsa();
        let pem = key
            .write_public(&PublicKeyEncoding::default())
            .expect("encoding succeeds")
            .expect("a PEM encoding");
        let public = OpenSslPKey::public_key_from_pem(&pem.bytes).expect("the public half parses");
        let public = PKey::from_public(public).expect("converts");
        assert!(
            !public.has_private(),
            "a public key has no private material"
        );
        assert_eq!(public.bits(), 2048);
    }
}
