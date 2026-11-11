//! Raw key import, for the OKP, EC-point and post-quantum formats.
//!
//! `crypto.createSecretKey` is not this; these are the `raw-public`,
//! `raw-private` and `raw-seed` formats, which `keys.js` passes as
//! `kKeyFormatRaw*` with the algorithm name in a separate slot. Three things can
//! go wrong and each has its own error, which is why this is a separate module
//! from the PEM/DER parser:
//!
//! * the algorithm name is not a key type Node accepts → `ERR_INVALID_ARG_VALUE`
//!   "Invalid asymmetricKeyType: <name>";
//! * the algorithm exists but the format is not one it supports — raw-public on
//!   RSA — → `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS`;
//! * the algorithm and format agree and the bytes are wrong → `ERR_INVALID_ARG_VALUE`
//!   "Invalid key data".
//!
//! The EC path is structurally different: an EC raw key is an encoded *point*
//! (public) or a scalar (private), so it goes through `EC_KEY` rather than
//! `EVP_PKEY_new_raw_*`.

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::PKey as OpenSslPKey;

use crate::algorithm::{KeyAlgorithm, EC};
use crate::encode::KeyFormat;
use crate::error::{clear_error, failure, ParseResult};
use crate::pkey::PKey;

/// Why a raw import failed, in the shapes the binding reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyFormatError {
    /// No table entry for the algorithm name the caller passed.
    UnknownAlgorithm,
    /// The algorithm exists but does not support this raw format.
    UnsupportedFormat,
    /// The algorithm's provider is not in this OpenSSL build.
    UnavailableAlgorithm,
    /// The name resolved to an EC key but the named curve did not.
    UnknownCurve,
    /// The bytes are not a valid key of this form.
    InvalidData,
}

/// Imports a raw public key: `EVP_PKEY_new_raw_public_key_ex`, or an EC point.
pub fn import_raw_public_key(
    algorithm: KeyAlgorithm,
    bytes: &[u8],
    named_curve: Option<&str>,
) -> Result<PKey, KeyFormatError> {
    if algorithm == EC {
        return import_ec_point(bytes, named_curve);
    }
    if !algorithm.supports_raw_public() {
        return Err(KeyFormatError::UnsupportedFormat);
    }
    new_raw(algorithm, bytes, RawKind::Public)
}

/// Imports a raw private key: `EVP_PKEY_new_raw_private_key_ex`, or an EC
/// scalar.
pub fn import_raw_private_key(
    algorithm: KeyAlgorithm,
    bytes: &[u8],
    named_curve: Option<&str>,
) -> Result<PKey, KeyFormatError> {
    if algorithm == EC {
        return import_ec_scalar(bytes, named_curve);
    }
    if !algorithm.supports_raw_private() {
        return Err(KeyFormatError::UnsupportedFormat);
    }
    new_raw(algorithm, bytes, RawKind::Private)
}

/// Imports a seed: the `raw-seed` format ML-DSA and ML-KEM use.
pub fn import_raw_seed(algorithm: KeyAlgorithm, bytes: &[u8]) -> Result<PKey, KeyFormatError> {
    if algorithm.seed_size() == 0 {
        return Err(KeyFormatError::UnsupportedFormat);
    }
    if bytes.len() != algorithm.seed_size() {
        return Err(KeyFormatError::InvalidData);
    }
    new_raw(algorithm, bytes, RawKind::Private)
}

/// Dispatches a raw import by its `kKeyFormat*` value.
pub fn import_raw(
    format: KeyFormat,
    algorithm: KeyAlgorithm,
    bytes: &[u8],
    named_curve: Option<&str>,
) -> Result<PKey, KeyFormatError> {
    match format {
        KeyFormat::RawPublic => import_raw_public_key(algorithm, bytes, named_curve),
        KeyFormat::RawPrivate => import_raw_private_key(algorithm, bytes, named_curve),
        KeyFormat::RawSeed => import_raw_seed(algorithm, bytes),
        _ => Err(KeyFormatError::UnsupportedFormat),
    }
}

#[derive(Clone, Copy)]
enum RawKind {
    Public,
    Private,
}

/// Builds an `EVP_PKEY` from raw bytes through the provider's `_ex` constructor.
fn new_raw(algorithm: KeyAlgorithm, bytes: &[u8], kind: RawKind) -> Result<PKey, KeyFormatError> {
    let Ok(name) = std::ffi::CString::new(algorithm.name()) else {
        return Err(KeyFormatError::InvalidData);
    };
    // SAFETY: `name` is NUL-terminated and valid for the call; `bytes` is a live
    // slice whose length is passed with it. The returned key is owned by this
    // function and either adopted below or freed on the error path.
    let key = unsafe {
        match kind {
            RawKind::Public => openssl_sys::EVP_PKEY_new_raw_public_key_ex(
                std::ptr::null_mut(),
                name.as_ptr(),
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len(),
            ),
            RawKind::Private => openssl_sys::EVP_PKEY_new_raw_private_key_ex(
                std::ptr::null_mut(),
                name.as_ptr(),
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len(),
            ),
        }
    };
    if key.is_null() {
        clear_error();
        return Err(KeyFormatError::InvalidData);
    }
    // SAFETY: the pointer came from the `_ex` constructor, which returns one new
    // reference owned by the caller, and `from_ptr` adopts exactly that one.
    use foreign_types::ForeignType;
    let key = unsafe { OpenSslPKey::from_ptr(key) };
    Ok(PKey::from_private(key))
}

/// Builds an EC key from an encoded point, which is the `raw-public` form.
fn import_ec_point(bytes: &[u8], named_curve: Option<&str>) -> Result<PKey, KeyFormatError> {
    let group = ec_group(named_curve)?;
    let mut context = BigNumContext::new().map_err(|_| KeyFormatError::InvalidData)?;
    // The conversion form is not passed: OpenSSL reads it from the first byte of
    // the buffer (0x02/0x03 compressed, 0x04 uncompressed, 0x06/0x07 hybrid),
    // which is exactly the distinction `options.type` produced on the way in.
    let point = EcPoint::from_bytes(&group, bytes, &mut context)
        .map_err(|_| KeyFormatError::InvalidData)?;
    let key = EcKey::from_public_key(&group, &point).map_err(|_| KeyFormatError::InvalidData)?;
    let pkey = OpenSslPKey::from_ec_key(key).map_err(|_| KeyFormatError::InvalidData)?;
    Ok(PKey::from_public(pkey).ok_or(KeyFormatError::InvalidData)?)
}

/// Builds an EC key from a private scalar, which is the `raw-private` form.
///
/// Node requires the scalar to be exactly the group's order width, so a 31-byte
/// P-256 scalar is rejected rather than left-padded: the fixed width is what
/// makes the raw format round-trip.
fn import_ec_scalar(bytes: &[u8], named_curve: Option<&str>) -> Result<PKey, KeyFormatError> {
    let group = ec_group(named_curve)?;
    let order = group.order_bits().div_ceil(8) as usize;
    if bytes.len() != order {
        return Err(KeyFormatError::InvalidData);
    }
    let scalar = BigNum::from_slice(bytes).map_err(|_| KeyFormatError::InvalidData)?;
    let mut context = BigNumContext::new().map_err(|_| KeyFormatError::InvalidData)?;
    let mut point = EcPoint::new(&group).map_err(|_| KeyFormatError::InvalidData)?;
    // The public half has to be derived from the scalar, because the raw format
    // carries no point. `mul_generator2` takes `&self` and an explicit context;
    // the deprecated `mul_generator` mutates a context internally.
    point
        .mul_generator2(&group, &scalar, &mut context)
        .map_err(|_| KeyFormatError::InvalidData)?;
    let key = EcKey::from_private_components(&group, &scalar, &point)
        .map_err(|_| KeyFormatError::InvalidData)?;
    let pkey = OpenSslPKey::from_ec_key(key).map_err(|_| KeyFormatError::InvalidData)?;
    Ok(PKey::from_private(pkey))
}

/// Resolves the named curve.
///
/// `None` means "the algorithm is EC and no curve was given", which Node's
/// `DCHECK_IMPLIES(algorithm == &KeyAlgorithm::EC, args[offset + 4]->IsString())`
/// says cannot happen; it is an `UnknownCurve` here rather than a panic.
fn ec_group(named_curve: Option<&str>) -> Result<EcGroup, KeyFormatError> {
    let Some(name) = named_curve else {
        return Err(KeyFormatError::UnknownCurve);
    };
    // `OBJ_txt2nid` is not in `openssl-sys`, and the two names it would accept
    // for a curve are the short name (`prime256v1`) and the long one
    // (`secp256r1`). `OBJ_sn2nid` covers the first, `OBJ_ln2nid` the second, so
    // both are tried rather than only the spelling `crypto.getCurves()` lists.
    let nid = resolve_curve_nid(name);
    let nid = match nid {
        Some(nid) if nid != Nid::UNDEF => nid,
        _ => return Err(KeyFormatError::UnknownCurve),
    };
    EcGroup::from_curve_name(nid).map_err(|_| KeyFormatError::UnknownCurve)
}

/// Resolves a curve name through OpenSSL's short and long name tables.
fn resolve_curve_nid(name: &str) -> Option<Nid> {
    let Ok(c_name) = std::ffi::CString::new(name) else {
        return None;
    };
    extern "C" {
        /// Not exported by `openssl-sys`, which has only the short-name lookup.
        fn OBJ_ln2nid(name: *const std::ffi::c_char) -> std::ffi::c_int;
    }
    // SAFETY: `c_name` is NUL-terminated and valid for both calls, which only
    // read it.
    let nid = unsafe {
        let short = openssl_sys::OBJ_sn2nid(c_name.as_ptr());
        if short != openssl_sys::NID_undef {
            short
        } else {
            OBJ_ln2nid(c_name.as_ptr())
        }
    };
    if nid == openssl_sys::NID_undef {
        // SAFETY: thread-local error queue only.
        unsafe { openssl_sys::ERR_clear_error() };
        return None;
    }
    Some(Nid::from_raw(nid))
}

/// Maps a `KeyFormatError` onto the `ParseFailure` the binding reports, so the
/// raw path and the PEM/DER path share one error channel.
///
/// Only `InvalidData` is a parse failure with OpenSSL detail. The rest are
/// argument errors the binding throws by name, and reporting a stale queue entry
/// there would give the error a `code` from an unrelated operation.
pub fn as_parse_failure(error: KeyFormatError) -> ParseResult<PKey> {
    match error {
        KeyFormatError::InvalidData => Err(failure(false)),
        KeyFormatError::UnknownAlgorithm
        | KeyFormatError::UnsupportedFormat
        | KeyFormatError::UnavailableAlgorithm
        | KeyFormatError::UnknownCurve => {
            clear_error();
            Err(failure(true))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{ED25519, RSA, X25519};

    #[test]
    fn an_ed25519_raw_key_pair_round_trips() {
        let generated = OpenSslPKey::generate_ed25519().expect("Ed25519 generates");
        let private = generated.raw_private_key().expect("a raw private key");
        let public = generated.raw_public_key().expect("a raw public key");

        let imported = import_raw_private_key(ED25519, &private, None).expect("imports");
        assert_eq!(imported.key_type_name(), Some("ed25519"));
        assert!(imported.has_private());

        let imported_public = import_raw_public_key(ED25519, &public, None).expect("imports");
        assert_eq!(imported_public.key_type_name(), Some("ed25519"));
        assert!(!imported_public.has_private());
    }

    #[test]
    fn an_x25519_raw_key_imports() {
        let generated = OpenSslPKey::generate_x25519().expect("X25519 generates");
        let private = generated.raw_private_key().expect("a raw private key");
        let imported = import_raw_private_key(X25519, &private, None).expect("imports");
        assert_eq!(imported.key_type_name(), Some("x25519"));
    }

    #[test]
    fn a_rsa_raw_key_is_an_unsupported_format() {
        // Raw formats are the OKP and post-quantum families; RSA's raw form does
        // not exist, and this is `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS`.
        let outcome = import_raw_public_key(RSA, &[0u8; 32], None);
        assert_eq!(outcome.err(), Some(KeyFormatError::UnsupportedFormat));
    }

    #[test]
    fn a_wrong_length_raw_key_is_invalid_data() {
        let outcome = import_raw_private_key(ED25519, &[0u8; 7], None);
        assert_eq!(outcome.err(), Some(KeyFormatError::InvalidData));
    }

    #[test]
    fn ec_points_and_scalars_round_trip() {
        let generated = OpenSslPKey::ec_gen("prime256v1").expect("P-256 generates");
        let key = PKey::from_private(generated);
        let uncompressed = key
            .ec_public_point(crate::pkey::EcPointForm::Uncompressed)
            .expect("exports");
        let compressed = key
            .ec_public_point(crate::pkey::EcPointForm::Compressed)
            .expect("exports");
        let scalar = key.ec_private_scalar().expect("exports");

        let from_uncompressed =
            import_raw_public_key(EC, &uncompressed, Some("prime256v1")).expect("imports");
        assert_eq!(from_uncompressed.key_type_name(), Some("ec"));

        // A compressed point is a different encoding of the same key, so the
        // imported key must equal the uncompressed one.
        let from_compressed =
            import_raw_public_key(EC, &compressed, Some("prime256v1")).expect("imports");
        assert_eq!(
            from_uncompressed.eq(&from_compressed),
            crate::pkey::EqualResult::Equal
        );

        let from_scalar = import_raw_private_key(EC, &scalar, Some("prime256v1")).expect("imports");
        assert!(from_scalar.has_private());
        let derived = from_scalar
            .ec_public_point(crate::pkey::EcPointForm::Uncompressed)
            .expect("exports");
        assert_eq!(
            import_raw_public_key(EC, &derived, Some("prime256v1"))
                .expect("imports")
                .eq(&from_uncompressed),
            crate::pkey::EqualResult::Equal
        );
    }

    #[test]
    fn a_short_ec_scalar_is_rejected_not_padded() {
        // The fixed width is what makes the format round-trip; padding a 31-byte
        // scalar would silently change its value.
        let outcome = import_raw_private_key(EC, &[0u8; 31], Some("prime256v1"));
        assert_eq!(outcome.err(), Some(KeyFormatError::InvalidData));
    }

    #[test]
    fn an_unknown_curve_is_reported_as_such() {
        let outcome = import_raw_public_key(EC, &[4u8; 65], Some("not-a-curve"));
        assert_eq!(outcome.err(), Some(KeyFormatError::UnknownCurve));
    }

    #[test]
    fn a_missing_curve_is_an_unknown_curve() {
        let outcome = import_raw_public_key(EC, &[4u8; 65], None);
        assert_eq!(outcome.err(), Some(KeyFormatError::UnknownCurve));
    }

    #[test]
    fn a_seed_import_requires_the_algorithm_seed_size() {
        // ML-DSA is not in OpenSSL 3.6, so the seed import cannot succeed here;
        // what is checkable without a provider is the length rule.
        let outcome = import_raw_seed(crate::algorithm::ML_DSA_44, &[0u8; 31]);
        assert_eq!(outcome.err(), Some(KeyFormatError::InvalidData));
        // Ed25519 has no seed format at all.
        let outcome = import_raw_seed(ED25519, &[0u8; 32]);
        assert_eq!(outcome.err(), Some(KeyFormatError::UnsupportedFormat));
    }
}
