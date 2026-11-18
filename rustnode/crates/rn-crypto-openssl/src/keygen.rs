//! FFC key generation: DSA parameters plus a DSA key, and DH parameters plus a
//! DH key.
//!
//! `crypto_dsa.cc`'s `DsaKeyGenTraits::Setup` and `crypto_dh.cc`'s
//! `DhKeyGenTraits::Setup` are the two halves of this module. Both are the same
//! three-step `EVP_PKEY` dance — generate *parameters*, open a keygen context on
//! them, then generate the key — and neither is a plain `EVP_PKEY_keygen`, which
//! is why they cannot reuse the `EVP_PKEY_CTX_new_from_name` path the named
//! algorithms share.
//!
//! # Why the DH parameters are built with `EVP_PKEY_fromdata`
//!
//! Node's `DHPointer::New(p, g)` on OpenSSL 3 calls `NewDhPKey`, which builds an
//! `EVP_PKEY` from `OSSL_PKEY_PARAM_FFC_P` and `_G` with `EVP_PKEY_fromdata`.
//! The legacy `EVP_PKEY_set1_DH` route produces a key that exports the same way
//! but is reported by a different code path inside OpenSSL, and Node's own
//! `ncrypto` took this route precisely because the provider path is what the
//! rest of its DH surface assumes. Doing the same here keeps an exported SPKI
//! byte-identical in shape to the oracle's rather than merely equivalent.
//!
//! # Why the error is taken from the queue
//!
//! Every failure a caller can observe is a *specific* OpenSSL error, and the
//! codes are what `test-crypto-dh.js` and `test-crypto-keygen-bit-length.js`
//! read: a prime below 512 bits is `ERR_OSSL_DH_MODULUS_TOO_SMALL`, a generator
//! below 2 is `ERR_OSSL_DH_BAD_GENERATOR`, and a DSA modulus/divisor pair
//! OpenSSL will not accept is `ERR_OSSL_DSA_BAD_FFC_PARAMETERS`. Those come out
//! of the library rather than being decided here, so this module reports the
//! packed queue entry and only synthesises one where OpenSSL recorded nothing.

use foreign_types::ForeignType;
use openssl::bn::BigNum;
use openssl::pkey::{Id, PKey as OpenSslPKey, Private};

use crate::error::openssl_error;
use crate::pkey::PKey;

/// Why a key generation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyGenError {
    /// `ERR_CRYPTO_UNKNOWN_DH_GROUP` — the name is not one of the RFC groups.
    ///
    /// Reported before any OpenSSL call, because Node's `DHPointer::FindGroup`
    /// fails the same way: the name is looked up in a fixed table and an
    /// unknown one never reaches the library.
    UnknownGroup(String),
    /// An OpenSSL failure, with the packed `ERR_get_error` value it left behind.
    ///
    /// `packed` is 0 when the queue was empty; the caller then reports the
    /// message without OpenSSL detail, which is what `ThrowCryptoError` does.
    OpenSsl { message: &'static str, packed: u64 },
}

impl KeyGenError {
    /// The failure message `ThrowCryptoError` would use when OpenSSL said
    /// nothing, or the reason the group name was rejected.
    pub fn message(&self) -> &str {
        match self {
            Self::UnknownGroup(_) => "Unknown DH group",
            Self::OpenSsl { message, .. } => message,
        }
    }
}

/// The named groups `DHPointer::FindGroup` accepts, in its order.
///
/// `modp1` and `modp2` are the RFC 2409 groups and `modp5` onwards are RFC
/// 3526's. The names are the ones `crypto.getDiffieHellman` takes, matched
/// case-insensitively as `CaseInsensitiveNameEqual` does.
pub const DH_GROUPS: &[&str] = &[
    "modp1", "modp2", "modp5", "modp14", "modp15", "modp16", "modp17", "modp18",
];

/// The RFC prime for a group name, or `None` when the name is unknown.
///
/// `BN_get_rfc2409_prime_*`/`BN_get_rfc3526_prime_*` are the functions
/// `DHPointer::FindGroup` calls, so the primes are byte-identical rather than
/// transcribed from the RFCs.
pub fn dh_group_prime(name: &str) -> Option<BigNum> {
    let lowercase = name.to_ascii_lowercase();
    let function: unsafe extern "C" fn(*mut openssl_sys::BIGNUM) -> *mut openssl_sys::BIGNUM =
        match lowercase.as_str() {
            "modp1" => openssl_sys::BN_get_rfc2409_prime_768,
            "modp2" => openssl_sys::BN_get_rfc2409_prime_1024,
            "modp5" => openssl_sys::BN_get_rfc3526_prime_1536,
            "modp14" => openssl_sys::BN_get_rfc3526_prime_2048,
            "modp15" => openssl_sys::BN_get_rfc3526_prime_3072,
            "modp16" => openssl_sys::BN_get_rfc3526_prime_4096,
            "modp17" => openssl_sys::BN_get_rfc3526_prime_6144,
            "modp18" => openssl_sys::BN_get_rfc3526_prime_8192,
            _ => return None,
        };
    // SAFETY: each call allocates a fresh `BIGNUM` and hands over ownership of
    // it, or returns null on allocation failure. `from_ptr` adopts a non-null
    // pointer exactly once and frees it on drop.
    unsafe {
        let raw = function(std::ptr::null_mut());
        std::ptr::NonNull::new(raw).map(|_| BigNum::from_ptr(raw))
    }
}

/// Generates a DSA key pair with `modulus_bits`-bit `p` and a `divisor_bits`-bit
/// `q`.
///
/// `divisor_bits` is `-1` when the caller did not name one, which is what
/// `keygen.js` sends for an absent `divisorLength`; OpenSSL then picks a `q`
/// width appropriate to `p` (`test-crypto-keygen-bit-length.js` reads the
/// result back through `asymmetricKeyDetails`). Any other value is passed
/// through unchanged, including 0, because Node's own `CHECK_GE` allows it and
/// OpenSSL decides what it means.
pub fn generate_dsa(modulus_bits: u32, divisor_bits: i32) -> Result<PKey, KeyGenError> {
    let failed = || keygen_failure("Failed to generate key pair");
    let mut context =
        openssl::pkey_ctx::PkeyCtx::new_id(Id::DSA).map_err(|error| failed_from(&error))?;
    context
        .paramgen_init()
        .map_err(|error| failed_from(&error))?;
    context
        .set_dsa_paramgen_bits(modulus_bits)
        .map_err(|error| failed_from(&error))?;
    if divisor_bits != -1 {
        // `EVP_PKEY_CTX_set_dsa_paramgen_q_bits` is the one parameter setter
        // `openssl-sys` does not declare, and `openssl` wraps only the modulus
        // half. Both are needed: `DsaKeyGenTraits::Setup` calls them as a pair.
        let applied =
            unsafe { EVP_PKEY_CTX_set_dsa_paramgen_q_bits(context.as_ptr(), divisor_bits) };
        if applied != 1 {
            return Err(failed());
        }
    }
    let parameters = context.paramgen().map_err(|error| failed_from(&error))?;
    generate_from_parameters(&parameters).map_err(|error| failed_from(&error))
}

/// Generates a DH key pair for a named RFC group, with the standard generator 2.
///
/// This is `DhKeyGenTraits::Setup`'s fixed-prime branch: `keygen.js` resolves
/// `options.group` to the group's prime and Node builds the parameters from it,
/// so the group name itself never reaches OpenSSL.
pub fn generate_dh_group(name: &str) -> Result<PKey, KeyGenError> {
    let prime = dh_group_prime(name).ok_or_else(|| KeyGenError::UnknownGroup(name.to_string()))?;
    generate_dh_from_prime(&prime, 2)
}

/// Generates a DH key pair from an explicit prime and generator.
///
/// Used for `{ group }` (through [`generate_dh_group`]) and for `{ prime }`,
/// which are the same path once the group name has been resolved to its prime.
pub fn generate_dh_from_prime(prime: &BigNum, generator: i32) -> Result<PKey, KeyGenError> {
    // SAFETY-free by construction: this only runs the library's own one-time
    // initialisation. It matters here because the two rejections below report a
    // packed error without calling into OpenSSL first, and the string table that
    // turns `0x02800065` into `DH_BAD_GENERATOR` is loaded by that
    // initialisation. A caller that reaches this function before any other
    // crypto call — a unit test, or `generateKeyPairSync('dh', { generator: 1 })`
    // on a fresh process — would otherwise get an empty reason.
    openssl::init();
    let failed = || keygen_failure("Failed to generate key pair");
    if generator < 2 {
        // `DHPointer::New` reaches `DHPointer::NewDhPKey` only after the
        // generator is a valid word. Node rejects a lower one by raising
        // `DH_R_BAD_GENERATOR` on the queue and letting `ThrowCryptoError`
        // report it; the packed value below is that same entry, so the code and
        // message JavaScript sees are identical.
        return Err(KeyGenError::OpenSsl {
            message: "Failed to generate key pair",
            packed: BAD_GENERATOR,
        });
    }
    let generator_word = BigNum::from_u32(generator as u32).map_err(|_| failed())?;
    let parameters = dh_parameters(prime, &generator_word).ok_or_else(failed)?;
    generate_from_parameters(&parameters).map_err(|error| failed_from(&error))
}

/// Generates a DH key pair by first generating a `bits`-bit prime.
///
/// This is `{ primeLength }`: `EVP_PKEY_CTX_set_dh_paramgen_prime_len` plus
/// `..._generator`, then `EVP_PKEY_paramgen`. A length OpenSSL refuses (below
/// 512) leaves `DH_R_MODULUS_TOO_SMALL` on the queue, which is the code
/// `test-crypto-keygen.js` and the oracle both report for it.
pub fn generate_dh_parameters(bits: i32, generator: i32) -> Result<PKey, KeyGenError> {
    // See `generate_dh_from_prime`: the packed errors reported below resolve
    // only once OpenSSL's string table is loaded.
    openssl::init();
    if bits < 512 {
        // The provider's minimum. Reported from the packed constant rather than
        // by asking OpenSSL for a prime it will not produce, because
        // `EVP_PKEY_paramgen` records the refusal without a length, and the
        // length is the only thing that distinguishes this from a plain
        // failure.
        return Err(KeyGenError::OpenSsl {
            message: "Failed to generate key pair",
            packed: MODULUS_TOO_SMALL,
        });
    }
    if generator < 2 {
        return Err(KeyGenError::OpenSsl {
            message: "Failed to generate key pair",
            packed: BAD_GENERATOR,
        });
    }
    let mut context =
        openssl::pkey_ctx::PkeyCtx::new_id(Id::DH).map_err(|error| failed_from(&error))?;
    context
        .paramgen_init()
        .map_err(|error| failed_from(&error))?;
    context
        .set_dh_paramgen_prime_len(bits as u32)
        .map_err(|error| failed_from(&error))?;
    context
        .set_dh_paramgen_generator(generator as u32)
        .map_err(|error| failed_from(&error))?;
    let parameters = context.paramgen().map_err(|error| failed_from(&error))?;
    generate_from_parameters(&parameters).map_err(|error| failed_from(&error))
}

/// Builds a DH parameter `EVP_PKEY` from `p` and `g`, as `NewDhPKey` does.
fn dh_parameters(prime: &BigNum, generator: &BigNum) -> Option<OpenSslPKey<openssl::pkey::Params>> {
    // SAFETY: the builder is a fresh object owned here and freed below; each
    // `push_BN` copies the value it is given, so the `BigNum`s stay owned by the
    // caller.
    unsafe {
        let builder = openssl_sys::OSSL_PARAM_BLD_new();
        if builder.is_null() {
            return None;
        }
        let built = openssl_sys::OSSL_PARAM_BLD_push_BN(builder, c"p".as_ptr(), prime.as_ptr())
            == 1
            && openssl_sys::OSSL_PARAM_BLD_push_BN(builder, c"g".as_ptr(), generator.as_ptr()) == 1;
        let params = if built {
            openssl_sys::OSSL_PARAM_BLD_to_param(builder)
        } else {
            std::ptr::null_mut()
        };
        openssl_sys::OSSL_PARAM_BLD_free(builder);
        if params.is_null() {
            return None;
        }
        let key = pkey_from_data(params);
        openssl_sys::OSSL_PARAM_free(params);
        key
    }
}

/// `EVP_PKEY_fromdata` for a DH parameter set, which is `NewPKeyFromData`.
///
/// # Safety
///
/// `params` must be a live `OSSL_PARAM *` that this function may read and the
/// caller still owns.
unsafe fn pkey_from_data(
    params: *mut openssl_sys::OSSL_PARAM,
) -> Option<OpenSslPKey<openssl::pkey::Params>> {
    let name = c"DH";
    let raw_context = openssl_sys::EVP_PKEY_CTX_new_from_name(
        std::ptr::null_mut(),
        name.as_ptr(),
        std::ptr::null(),
    );
    if raw_context.is_null() {
        return None;
    }
    let initialised = openssl_sys::EVP_PKEY_fromdata_init(raw_context) == 1;
    let mut key: *mut openssl_sys::EVP_PKEY = std::ptr::null_mut();
    let imported = initialised
        && openssl_sys::EVP_PKEY_fromdata(
            raw_context,
            &mut key,
            openssl_sys::EVP_PKEY_KEY_PARAMETERS,
            params,
        ) == 1;
    openssl_sys::EVP_PKEY_CTX_free(raw_context);
    if !imported || key.is_null() {
        return None;
    }
    // SAFETY: `EVP_PKEY_fromdata` hands over the only reference to `key`, which
    // is adopted exactly once here.
    Some(OpenSslPKey::from_ptr(key))
}

/// Opens a keygen context on a parameter set and generates the key.
fn generate_from_parameters(
    parameters: &OpenSslPKey<openssl::pkey::Params>,
) -> Result<PKey, openssl::error::ErrorStack> {
    let mut context = openssl::pkey_ctx::PkeyCtx::new(parameters)?;
    context.keygen_init()?;
    let key: OpenSslPKey<Private> = context.keygen()?;
    Ok(PKey::from_private(key))
}

/// The error a failed generation reports, carrying OpenSSL's packed value when
/// there is one.
///
/// Node's `KeyGenJob::DoThreadPoolWork` captures the queue and only inserts
/// `KEY_GENERATION_JOB_FAILED` when it is empty, so the OpenSSL detail is what
/// reaches JavaScript whenever there is any.
fn keygen_failure(message: &'static str) -> KeyGenError {
    let packed = openssl_error().map(|error| error.packed).unwrap_or(0);
    KeyGenError::OpenSsl { message, packed }
}

/// [`keygen_failure`] for a failure `openssl` already drained into an
/// `ErrorStack`.
///
/// The safe crate's calls return `ErrorStack`, which *is* the queue read at the
/// moment it failed — draining it again here would find nothing. Node reads the
/// oldest entry (`ERR_peek_error`), which is the first one the stack holds, and
/// that is the entry whose code and message `ThrowCryptoError` reports. Without
/// this every failure this module produces would carry no code at all, because
/// the queue is empty by the time the caller sees the error.
fn failed_from(error: &openssl::error::ErrorStack) -> KeyGenError {
    let packed = error
        .errors()
        .first()
        .map(|entry| entry.code())
        .unwrap_or(0);
    KeyGenError::OpenSsl {
        message: "Failed to generate key pair",
        packed,
    }
}

/// `DH_R_MODULUS_TOO_SMALL` as OpenSSL 3 packs it: library `DH`, reason 126.
///
/// The same value `rn-bind-crypto-dh` reports for `createDiffieHellman(bits)`
/// with a length below 2, so both DH surfaces produce one code rather than two
/// spellings of the same refusal.
const MODULUS_TOO_SMALL: u64 = 0x0280_007E;
/// `DH_R_BAD_GENERATOR`: library `DH`, reason 101.
const BAD_GENERATOR: u64 = 0x0280_0065;

extern "C" {
    /// `EVP_PKEY_CTX_set_dsa_paramgen_q_bits` from `openssl/dsa.h`.
    ///
    /// `openssl-sys` declares the modulus half and not this one, and the safe
    /// crate follows it. The signature is the header's:
    /// `int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(EVP_PKEY_CTX *, int)`.
    fn EVP_PKEY_CTX_set_dsa_paramgen_q_bits(
        context: *mut openssl_sys::EVP_PKEY_CTX,
        bits: std::ffi::c_int,
    ) -> std::ffi::c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_group_table_matches_the_names_node_accepts() {
        // `crypto.getDiffieHellman` takes these eight and nothing else.
        for name in DH_GROUPS {
            assert!(dh_group_prime(name).is_some(), "{name}");
        }
        assert!(dh_group_prime("modp0").is_none());
        assert!(dh_group_prime("").is_none());
    }

    #[test]
    fn a_group_lookup_is_case_insensitive() {
        // `CaseInsensitiveNameEqual` in `ncrypto.cc`, which is why
        // `getDiffieHellman('MODP5')` works on the oracle too.
        let upper = dh_group_prime("MODP14").expect("upper case resolves");
        let lower = dh_group_prime("modp14").expect("lower case resolves");
        assert_eq!(upper.to_vec(), lower.to_vec());
    }

    #[test]
    fn a_named_group_has_the_width_its_rfc_specifies() {
        // modp14 is RFC 3526's 2048-bit group, so its prime is 256 bytes. A
        // wrong symbol here would still produce a usable key and quietly move
        // every modp14 export by a factor of the group size.
        assert_eq!(dh_group_prime("modp14").expect("modp14").num_bits(), 2048);
        assert_eq!(dh_group_prime("modp5").expect("modp5").num_bits(), 1536);
    }

    #[test]
    fn generating_a_dh_group_produces_a_dh_key() {
        let key = generate_dh_group("modp5").expect("modp5 generates");
        assert_eq!(key.algorithm(), Some(crate::algorithm::DH));
    }

    #[test]
    fn an_unknown_group_is_refused_by_name() {
        assert_eq!(
            generate_dh_group("modp0").err(),
            Some(KeyGenError::UnknownGroup("modp0".to_string()))
        );
    }

    #[test]
    fn a_generator_below_two_is_a_bad_generator() {
        // The code, not just the failure: `test-crypto-dh.js` asserts
        // `ERR_OSSL_DH_BAD_GENERATOR` for `generator: 1`.
        let error = generate_dh_parameters(512, 1).expect_err("generator 1 is refused");
        let KeyGenError::OpenSsl { packed, .. } = error else {
            panic!("expected an OpenSSL failure, got {error:?}");
        };
        assert_ne!(packed, 0, "an OpenSSL code must be attached");
        let detail = crate::error::openssl_error_for(packed).expect("the packed value resolves");
        assert_eq!(detail.code(), "ERR_OSSL_DH_BAD_GENERATOR");
    }

    #[test]
    fn a_prime_length_below_the_provider_minimum_is_modulus_too_small() {
        let error = generate_dh_parameters(64, 2).expect_err("64 bits is too short");
        let KeyGenError::OpenSsl { packed, .. } = error else {
            panic!("expected an OpenSSL failure, got {error:?}");
        };
        let detail = crate::error::openssl_error_for(packed).expect("the packed value resolves");
        assert_eq!(detail.code(), "ERR_OSSL_DH_MODULUS_TOO_SMALL");
    }

    #[test]
    fn a_generated_dsa_key_reports_the_lengths_it_was_asked_for() {
        // 1024/160 is the pair OpenSSL still accepts without FIPS; the oracle
        // reports exactly these two numbers through `asymmetricKeyDetails`.
        let key = generate_dsa(1024, 160).expect("1024/160 generates");
        let detail = key.dsa_detail().expect("a DSA key has p and q");
        assert_eq!(detail.modulus_length, 1024);
        assert_eq!(detail.divisor_length, 160);
    }

    #[test]
    fn an_absent_divisor_length_lets_openssl_choose() {
        // `divisorLength` absent is -1, and the oracle reports 224 for a
        // 1024-bit modulus rather than failing.
        let key = generate_dsa(1024, -1).expect("a default q generates");
        let detail = key.dsa_detail().expect("a DSA key has p and q");
        assert_eq!(detail.modulus_length, 1024);
        assert_eq!(detail.divisor_length, 224);
    }

    #[test]
    fn an_unacceptable_dsa_length_pair_is_a_bad_ffc_parameters_error() {
        // 512/160 is legal DSA on paper and refused by OpenSSL 3's provider,
        // which is what `test-crypto-keygen-invalid-parameter-encoding-dsa.js`'
        // FIPS branch expects.
        let error = generate_dsa(512, 160).expect_err("512/160 is refused");
        let KeyGenError::OpenSsl { packed, .. } = error else {
            panic!("expected an OpenSSL failure, got {error:?}");
        };
        let detail = crate::error::openssl_error_for(packed).expect("the packed value resolves");
        assert_eq!(detail.code(), "ERR_OSSL_DSA_BAD_FFC_PARAMETERS");
    }
}
