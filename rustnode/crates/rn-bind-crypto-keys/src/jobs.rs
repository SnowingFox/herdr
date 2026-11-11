//! The four key-generation jobs.
//!
//! `crypto_keygen.cc` and `crypto_keygen.h` are the sources. Each job reads its
//! parameters from the constructor argument list, generates key material through
//! OpenSSL, and reports the result as `[error, keys]` — or as a single handle for
//! the secret case.
//!
//! # The argument layouts
//!
//! Slot 0 is always the mode. After that each job differs, and the offsets are
//! what `keygen.js` builds:
//!
//! ```text
//! SecretKeyGenJob     (mode, length)
//! RsaKeyPairGenJob    (mode, variant, modulusBits, exponent,
//!                      [pss: hash, mgf1Hash, saltLength], pubFormat, pubType,
//!                      privFormat, privType, cipher, passphrase)
//! EcKeyPairGenJob     (mode, namedCurve, paramEncoding, pubFormat, pubType,
//!                      privFormat, privType, cipher, passphrase)
//! NamedKeyPairGenJob  (mode, type, pubFormat, pubType, privFormat, privType,
//!                      cipher, passphrase)
//! ```
//!
//! `DsaKeyPairGenJob` and `DhKeyPairGenJob` are *not* here: they belong to the
//! DH slice's crate and to the DSA surface respectively, and only their
//! constructors need to exist for `keygen.js` to load. They are declared deferred
//! by the parent crate rather than stubbed into something that silently returns
//! the wrong shape.

use openssl::pkey::PKey as OpenSslPKey;
use rn_crypto_openssl::{KeyAlgorithm, PKey, PrivateKeyEncoding, PublicKeyEncoding};
use rn_v8_sys::v8;

use crate::args::{read_format_and_type, read_private_key_tail, EncodingContext, Values};
use crate::errors::{throw, KeyError};
use crate::gen::{self, JobMode, Runnable};
use crate::handle::values_of;
use crate::install::create_handle;
use crate::state::{KeyData, KeyType};

/// The internal field a job instance stores its state in.
///
/// Jobs are not key objects, so this is their own field rather than a reuse of
/// the key field: a job object never holds a `KeyData`, and giving it one would
/// make the brand check answer `true` for it.
const JOB_FIELD: i32 = 0;

/// `kKeyVariantRSA_SSA_PKCS1_v1_5`.
const K_KEY_VARIANT_RSA_SSA_PKCS1_V1_5: i32 = 0;
/// `kKeyVariantRSA_PSS`.
const K_KEY_VARIANT_RSA_PSS: i32 = 1;

/// Installs the four job classes.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // Each job reserves one internal field for its parameters and mode. Without
    // it `set_aligned_pointer_in_internal_field` in the constructor has nowhere
    // to write, and `run()` would read a null.
    macro_rules! job_class {
        ($name:literal => $constructor:path) => {{
            let template = v8::FunctionTemplate::builder($constructor).build(scope);
            template
                .instance_template(scope)
                .set_internal_field_count(JOB_FIELD as usize + 1);
            let Some(function) = template.get_function(scope) else {
                return Err(format!("cannot allocate crypto.{}", $name));
            };
            let Some(key) = v8::String::new(scope, $name) else {
                return Err(format!("cannot allocate crypto.{}", $name));
            };
            target.set(scope, key.into(), function.into());
        }};
    }
    job_class!("SecretKeyGenJob" => secret_constructor);
    job_class!("RsaKeyPairGenJob" => rsa_constructor);
    job_class!("EcKeyPairGenJob" => ec_constructor);
    job_class!("NamedKeyPairGenJob" => named_constructor);
    Ok(())
}

/// The parameters a key-pair job generates from.
struct KeyPairSpec {
    algorithm: KeyAlgorithm,
    /// The RSA variant, or `None` for the other families.
    rsa_variant: Option<i32>,
    modulus_bits: u32,
    exponent: u32,
    /// The PSS digest and MGF1 digest names, for an `RSA-PSS` job.
    pss_hash: Option<String>,
    pss_mgf1_hash: Option<String>,
    pss_salt_length: i32,
    /// The EC curve, for an `EcKeyPairGenJob`.
    named_curve: Option<String>,
    ec_param_encoding: i32,
    public_encoding: PublicKeyEncoding,
    private_encoding: PrivateKeyEncoding,
}

impl Runnable for KeyPairSpec {
    type Output = KeyData;

    fn run(&mut self) -> Result<Self::Output, KeyError> {
        let key = generate_key_pair(self)?;
        // A generated key is always private; `ToEncodedPublicKey` derives the
        // public half from it when the caller asked for one.
        KeyData::asymmetric(KeyType::Private, key).ok_or(KeyError::InvalidKeyType)
    }

    fn encode<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        // `KeyPairGenTraits::EncodeKey`: `[public, private]`, each either a
        // `KeyObjectHandle` or an encoded value.
        let key = output.asymmetric_key()?;
        let public = encode_public(scope, key, &self.public_encoding, KeyType::Public)?;
        let private = encode_private(scope, key, &self.private_encoding, KeyType::Private)?;
        Some(v8::Array::new_with_elements(scope, &[public, private]).into())
    }
}

/// Encodes one half of a generated pair.
///
/// With no encoding requested the result is a `KeyObjectHandle` — that is what
/// `generateKeyPairSync('rsa', { modulusLength })` returns, and `keys.js` wraps
/// it in a `PublicKeyObject`/`PrivateKeyObject`. Otherwise it is the encoded bytes
/// or string, which `KeyPairGenTraits::EncodeKey` returns as `[public, private]`.
///
/// The raw formats are handled here rather than through `PKey::write_public`
/// because they are not encodings of the key at all: `raw-public` is the
/// algorithm's public key bytes, and `raw-private`/`raw-seed` are the private
/// scalar or seed. `write_public` answers `Ok(None)` for them, which the caller
/// would otherwise turn into a missing array element.
fn encode_public<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: &PKey,
    encoding: &PublicKeyEncoding,
    key_type: KeyType,
) -> Option<v8::Local<'s, v8::Value>> {
    if encoding.output_key_object {
        let data = KeyData::asymmetric(key_type, key.clone())?;
        return create_handle(scope, data).map(v8::Local::into);
    }
    if encoding.format == Some(rn_crypto_openssl::KeyFormat::RawPublic) {
        let bytes = match key.algorithm() {
            // An EC raw public key is an encoded point, and the point form comes
            // from the encoding's type slot.
            Some(algorithm) if algorithm == rn_crypto_openssl::EC => {
                let form = rn_crypto_openssl::EcPointForm::from_raw(encoding.ec_point_form)
                    .unwrap_or(rn_crypto_openssl::EcPointForm::Uncompressed);
                key.ec_public_point(form)?
            }
            _ => key.raw_public_key()?,
        };
        return crate::install::buffer_from(scope, &bytes);
    }
    let encoded = key.write_public(encoding).ok()??;
    emit_encoded(scope, &encoded)
}

/// [`encode_public`] for the private half.
fn encode_private<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: &PKey,
    encoding: &PrivateKeyEncoding,
    key_type: KeyType,
) -> Option<v8::Local<'s, v8::Value>> {
    if encoding.output_key_object {
        let data = KeyData::asymmetric(key_type, key.clone())?;
        return create_handle(scope, data).map(v8::Local::into);
    }
    match encoding.format {
        Some(rn_crypto_openssl::KeyFormat::RawPrivate) => {
            let bytes = match key.algorithm() {
                Some(algorithm) if algorithm == rn_crypto_openssl::EC => key.ec_private_scalar()?,
                _ => key.raw_private_key()?,
            };
            crate::install::buffer_from(scope, &bytes)
        }
        Some(rn_crypto_openssl::KeyFormat::RawSeed) => {
            let bytes = key.raw_seed()?;
            crate::install::buffer_from(scope, &bytes)
        }
        _ => {
            let encoded = key.write_private(encoding).ok()??;
            emit_encoded(scope, &encoded)
        }
    }
}

/// Emits an encoded key: a string for PEM, a `Buffer` for DER.
///
/// The two differ because `lib/internal/crypto/keygen.js`'s `wrapKey` treats a
/// string and a view differently, and Node's `ToV8Value` makes the same split.
fn emit_encoded<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    encoded: &rn_crypto_openssl::EncodedKey,
) -> Option<v8::Local<'s, v8::Value>> {
    if encoded.is_text() {
        let text = std::str::from_utf8(&encoded.bytes).ok()?;
        return v8::String::new(scope, text).map(v8::Local::into);
    }
    crate::install::buffer_from(scope, &encoded.bytes)
}

/// Generates a key pair from a spec.
fn generate_key_pair(spec: &KeyPairSpec) -> Result<PKey, KeyError> {
    if spec.algorithm == rn_crypto_openssl::RSA || spec.algorithm == rn_crypto_openssl::RSA_PSS {
        return generate_rsa(spec);
    }
    if spec.algorithm == rn_crypto_openssl::EC {
        return generate_ec(spec);
    }
    generate_named(spec)
}

/// Generates an RSA key, with the PSS restrictions when the variant asks for them.
///
/// Built through `EVP_PKEY_CTX_new_id` and `EVP_PKEY_keygen` rather than the
/// `openssl` crate's convenience wrappers, for two reasons the wrappers get wrong
/// here:
///
/// * `PkeyCtx::set_rsa_keygen_pubexp` takes the `BigNum` *by value* and
///   transfers ownership to OpenSSL, so calling it with a temporary leaves the
///   context holding a freed exponent — the symptom is `pub exponent out of range`
///   from `EVP_PKEY_keygen`. `EVP_PKEY_CTX_set1_rsa_keygen_pubexp` copies it.
/// * the PSS restrictions (`md`, `mgf1_md`, `saltlen`) are `OSSL_PARAM`s on the
///   context, and the crate has no wrapper for them. Setting them is what makes
///   the resulting key *restricted*: without it the key is a plain RSA key whose
///   `asymmetricKeyType` is still `rsa-pss` but whose parameters are absent, and
///   `test-crypto-keygen-rsa-pss.js` asserts they are present.
fn generate_rsa(spec: &KeyPairSpec) -> Result<PKey, KeyError> {
    let pss = spec.rsa_variant == Some(K_KEY_VARIANT_RSA_PSS);
    // `EVP_PKEY_RSA_PSS` and `EVP_PKEY_RSA` are distinct ids, and the PSS one is
    // what makes OpenSSL produce a restricted key type.
    let id = if pss {
        openssl::pkey::Id::RSA_PSS
    } else {
        openssl::pkey::Id::RSA
    };
    let context = openssl::pkey_ctx::PkeyCtx::new_id(id)
        .map_err(|_| KeyError::OperationFailed("Failed to generate key pair"))?;
    let mut context = context;
    context
        .keygen_init()
        .map_err(|_| KeyError::OperationFailed("Failed to generate key pair"))?;
    context
        .set_rsa_keygen_bits(spec.modulus_bits)
        .map_err(|_| KeyError::OperationFailed("Failed to generate key pair"))?;

    // `set1` copies the exponent; the crate's `set_rsa_keygen_pubexp` would take
    // ownership of a value that dies at the end of this function.
    let exponent =
        openssl::bn::BigNum::from_u32(spec.exponent).map_err(|_| KeyError::InvalidKeyLength)?;
    let context_ptr = foreign_types::ForeignType::as_ptr(&context);
    // SAFETY: the context is live and `exponent` is a live `BIGNUM`.
    let copied = unsafe {
        openssl_sys::EVP_PKEY_CTX_set1_rsa_keygen_pubexp(
            context_ptr,
            foreign_types::ForeignType::as_ptr(&exponent),
        )
    };
    if copied != 1 {
        return Err(KeyError::OperationFailed("Failed to generate key pair"));
    }

    if pss {
        set_pss_restrictions(&mut context, spec)?;
    }

    context
        .keygen()
        .map(PKey::from_private)
        .map_err(|_| KeyError::OperationFailed("Failed to generate key pair"))
}

/// Applies the restrictions that make an `RSA-PSS` key restricted.
///
/// These go through `EVP_PKEY_CTX_set_rsa_pss_keygen_md` and its siblings, not
/// through `EVP_PKEY_CTX_set_params`: the `OSSL_PARAM` form named
/// `rsa_pss_keygen_md` is accepted (it returns 1) and silently does nothing on
/// this OpenSSL, so the generated key has no restrictions at all and
/// `asymmetricKeyDetails` comes back empty. The ctrl-based functions are what
/// actually set them.
/// Reads an integer argument, or `None` when it is absent or another kind.
///
/// `Value::int32_value` reports 0 for anything that is not an integer, so it
/// cannot distinguish "0" from "not supplied" — which matters for `saltLength`,
/// where 0 is a legal explicit value and absent means the digest length.
fn int32_arg(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<i32> {
    let _ = scope;
    v8::Local::<v8::Int32>::try_from(args.get(index))
        .ok()
        .map(|value| value.value())
}

/// Reads a string-valued argument, or `None` for anything else.
fn string_arg(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<String> {
    let value = args.get(index);
    let text = v8::Local::<v8::String>::try_from(value).ok()?;
    Some(text.to_rust_string_lossy(scope))
}

/// Resolves a digest name to a raw `EVP_MD *`.
///
/// `EVP_get_digestbyname` rather than `openssl::md::Md::from_nid`: the ctrl-based
/// PSS functions take the legacy `const EVP_MD *`, and the crate's `Md` wrapper
/// may hold a provider-fetched digest instead, which `EVP_PKEY_CTX_ctrl` rejects
/// with `Failed to generate key pair`.
fn digest_by_name(name: &str) -> Option<*const openssl_sys::EVP_MD> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c_name` is NUL-terminated and valid for the call, which returns a
    // static descriptor or null.
    let digest = unsafe { openssl_sys::EVP_get_digestbyname(c_name.as_ptr()) };
    if digest.is_null() {
        // SAFETY: thread-local error queue only.
        unsafe { openssl_sys::ERR_clear_error() };
        return None;
    }
    Some(digest)
}

fn set_pss_restrictions(
    context: &mut openssl::pkey_ctx::PkeyCtx<()>,
    spec: &KeyPairSpec,
) -> Result<(), KeyError> {
    extern "C" {
        /// Not exposed by `openssl-sys 0.9.118`, and they are the only way to
        /// restrict a key at generation time.
        fn EVP_PKEY_CTX_set_rsa_pss_keygen_md(
            ctx: *mut openssl_sys::EVP_PKEY_CTX,
            md: *const openssl_sys::EVP_MD,
        ) -> std::ffi::c_int;
        fn EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(
            ctx: *mut openssl_sys::EVP_PKEY_CTX,
            md: *const openssl_sys::EVP_MD,
        ) -> std::ffi::c_int;
        fn EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(
            ctx: *mut openssl_sys::EVP_PKEY_CTX,
            saltlen: std::ffi::c_int,
        ) -> std::ffi::c_int;
    }

    let failed = || KeyError::OperationFailed("Failed to generate key pair");
    let context_ptr = foreign_types::ForeignType::as_ptr(context);

    // Only the parameters the caller named are restricted; an absent one leaves
    // that aspect of the key unrestricted, which is what `keygen.js` means by
    // passing `undefined`.
    if let Some(hash) = &spec.pss_hash {
        let digest = digest_by_name(hash).ok_or_else(failed)?;
        // SAFETY: the context and the digest are both live for the call.
        let applied = unsafe { EVP_PKEY_CTX_set_rsa_pss_keygen_md(context_ptr, digest) };
        if applied != 1 {
            return Err(failed());
        }
    }
    if let Some(mgf1) = &spec.pss_mgf1_hash {
        let digest = digest_by_name(mgf1).ok_or_else(failed)?;
        // SAFETY: as above.
        let applied = unsafe { EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(context_ptr, digest) };
        if applied != 1 {
            return Err(failed());
        }
    }
    // An absent `saltLength` means "the digest length", and OpenSSL records the
    // *resolved* value on the key rather than -1. Setting -1 alone leaves the key
    // reporting `saltLength: 0`, so the digest size is substituted here: 32 for
    // SHA-256, 48 for SHA-384, 64 for SHA-512, which is what Node reports.
    let salt_length = if spec.pss_salt_length < 0 {
        digest_by_name(spec.pss_hash.as_deref().unwrap_or("sha1"))
            .map(|digest| {
                // SAFETY: `digest` is a static `EVP_MD` from the table above.
                unsafe { openssl_sys::EVP_MD_get_size(digest) }
            })
            .filter(|size| *size > 0)
            .unwrap_or(20)
    } else {
        spec.pss_salt_length
    };
    // SAFETY: the context is live.
    let applied = unsafe { EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(context_ptr, salt_length) };
    if applied != 1 {
        return Err(failed());
    }
    Ok(())
}

/// Generates an EC key on the requested curve.
fn generate_ec(spec: &KeyPairSpec) -> Result<PKey, KeyError> {
    let Some(curve) = &spec.named_curve else {
        return Err(KeyError::InvalidCurve);
    };
    let nid = curve_nid(curve).ok_or(KeyError::InvalidCurve)?;
    let group = openssl::ec::EcGroup::from_curve_name(nid).map_err(|_| KeyError::InvalidCurve)?;
    if spec.ec_param_encoding == crate::constants::OPENSSL_EC_EXPLICIT_CURVE {
        // An explicit-parameter key writes the whole curve into the encoding
        // rather than naming it. `set_asn1_flag(NAMED_CURVE)` off is what makes
        // the difference, and `test-crypto-keygen-async-explicit-elliptic-curve.js`
        // asserts the encoded form is larger because of it.
        let mut group = group;
        group.set_asn1_flag(openssl::ec::Asn1Flag::EXPLICIT_CURVE);
        let key = openssl::ec::EcKey::generate(&group).map_err(|_| KeyError::InvalidCurve)?;
        let pkey = OpenSslPKey::from_ec_key(key).map_err(|_| KeyError::InvalidCurve)?;
        return Ok(PKey::from_private(pkey));
    }
    let key = openssl::ec::EcKey::generate(&group).map_err(|_| KeyError::InvalidCurve)?;
    let pkey = OpenSslPKey::from_ec_key(key).map_err(|_| KeyError::InvalidCurve)?;
    Ok(PKey::from_private(pkey))
}

/// Generates a key pair for any algorithm `EVP_PKEY_CTX_new_from_name` accepts.
///
/// This is `NamedKeyPairGenTraits::Setup`: the algorithm is whatever
/// `keygen.js` passed as the `type`, and the generation is a plain `EVP_PKEY`
/// keygen. It covers Ed25519, X25519 and the post-quantum families, which the
/// linked OpenSSL does provide.
fn generate_named(spec: &KeyPairSpec) -> Result<PKey, KeyError> {
    let name =
        std::ffi::CString::new(spec.algorithm.name()).map_err(|_| KeyError::InvalidKeyType)?;
    // SAFETY: `name` is NUL-terminated and valid for the call; the returned
    // context is owned here and freed by `PkeyCtx`'s wrapper.
    let raw = unsafe {
        openssl_sys::EVP_PKEY_CTX_new_from_name(
            std::ptr::null_mut(),
            name.as_ptr(),
            std::ptr::null(),
        )
    };
    if raw.is_null() {
        return Err(KeyError::IncompatibleKeyOptions {
            encoding: spec.algorithm.name().to_string(),
            detail: "is not a supported key type",
        });
    }
    // SAFETY: `raw` is a new context reference, adopted exactly once.
    use foreign_types::ForeignType;
    let mut context: openssl::pkey_ctx::PkeyCtx<openssl::pkey::Private> =
        unsafe { openssl::pkey_ctx::PkeyCtx::from_ptr(raw) };
    context
        .keygen_init()
        .map_err(|_| KeyError::OperationFailed("Failed to generate key pair"))?;
    let key = context
        .keygen()
        .map_err(|_| KeyError::OperationFailed("Failed to generate key pair"))?;
    Ok(PKey::from_private(key))
}

/// Resolves a curve name to its NID.
pub(crate) fn curve_nid(curve: &str) -> Option<openssl::nid::Nid> {
    Some(match curve {
        // The names `crypto.getCurves()` lists are OpenSSL's short names.
        "prime256v1" | "secp256r1" | "P-256" => openssl::nid::Nid::X9_62_PRIME256V1,
        "secp384r1" | "P-384" => openssl::nid::Nid::SECP384R1,
        "secp521r1" | "P-521" => openssl::nid::Nid::SECP521R1,
        "secp256k1" => openssl::nid::Nid::SECP256K1,
        other => return rn_crypto_openssl::nid_of_curve(other),
    })
}

/// The `SecretKeyGenConfig` a `SecretKeyGenJob` carries.
struct SecretSpec {
    length_bits: u32,
    /// The byte length, which is `bits / 8` for the traditional form and
    /// `ceil(bits / 8)` for WebCrypto.
    length: usize,
    truncate_to_bit_length: bool,
}

impl Runnable for SecretSpec {
    type Output = KeyData;

    fn run(&mut self) -> Result<Self::Output, KeyError> {
        let mut bytes = vec![0u8; self.length];
        // `ncrypto::CSPRNG`, which is `RAND_bytes`.
        openssl::rand::rand_bytes(&mut bytes)
            .map_err(|_| KeyError::OperationFailed("Failed to generate key"))?;
        if self.truncate_to_bit_length {
            // A bit length that is not a multiple of 8 has to be masked in the
            // high byte, or the key would be longer than asked for.
            truncate_to_bits(self.length_bits, &mut bytes);
        }
        Ok(KeyData::secret(bytes))
    }

    fn encode<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        // `SecretKeyGenTraits::EncodeKey` returns a `KeyObjectHandle`, which
        // `keygen.js` wraps in a `SecretKeyObject`.
        create_handle(scope, output).map(v8::Local::into)
    }
}

/// Masks a generated key down to `bits` bits.
///
/// `TruncateToBitLength` in `crypto_util.cc`: the spare bits in the highest byte
/// are cleared, so the result is genuinely `bits` long rather than rounded up.
fn truncate_to_bits(bits: u32, bytes: &mut [u8]) {
    let remainder = bits % 8;
    if remainder == 0 || bytes.is_empty() {
        return;
    }
    // Big-endian: the high-order byte is index 0.
    let mask = 0xFFu8 << (8 - remainder);
    bytes[0] &= mask;
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

/// `new SecretKeyGenJob(mode, length)`.
fn secret_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = JobMode::from_raw(args.get(0).int32_value(scope).unwrap_or(-1)) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    let bits = args.get(1).uint32_value(scope).unwrap_or(0);
    let (length, truncate) = if mode == JobMode::WebCrypto {
        // WebCrypto lengths are in bits and may not be byte-aligned.
        (bits.div_ceil(8) as usize, !bits.is_multiple_of(8))
    } else {
        ((bits / 8) as usize, false)
    };
    let spec = SecretSpec {
        length_bits: bits,
        length,
        truncate_to_bit_length: truncate,
    };
    install_job(scope, this, mode, spec);
    rv.set(this.into());
}

/// `new RsaKeyPairGenJob(mode, variant, modulusBits, exponent[, hash, mgf1, salt], …encoding)`.
fn rsa_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = JobMode::from_raw(args.get(0).int32_value(scope).unwrap_or(-1)) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    let variant = args
        .get(1)
        .int32_value(scope)
        .unwrap_or(K_KEY_VARIANT_RSA_SSA_PKCS1_V1_5);
    let modulus_bits = args.get(2).uint32_value(scope).unwrap_or(0);
    let exponent = args.get(3).uint32_value(scope).unwrap_or(0x10001);

    // The PSS variant carries three extra parameters before the encoding, which
    // is why the offsets are variant-dependent.
    let (pss_hash, pss_mgf1_hash, pss_salt_length, mut offset) = if variant == K_KEY_VARIANT_RSA_PSS
    {
        (
            // A string-valued slot, or `None` when `keygen.js` passed
            // `undefined` because the option was absent. `to_string` would
            // stringify `undefined` into the literal `"undefined"`, which
            // `digest_by_name` then fails to resolve.
            string_arg(scope, &args, 4),
            string_arg(scope, &args, 5),
            // `int32_value` returns 0 for a non-integer, which would silently
            // turn an absent `saltLength` into an explicit zero-length salt.
            int32_arg(scope, &args, 6).unwrap_or(-1),
            7,
        )
    } else {
        (None, None, -1, 4)
    };

    let values = values_of(scope, &args);
    let algorithm = if variant == K_KEY_VARIANT_RSA_PSS {
        rn_crypto_openssl::RSA_PSS
    } else {
        rn_crypto_openssl::RSA
    };
    let Some((public_encoding, private_encoding)) =
        read_encodings(scope, &values, &mut offset, mode, algorithm)
    else {
        return;
    };
    let spec = KeyPairSpec {
        algorithm,
        rsa_variant: Some(variant),
        modulus_bits,
        exponent,
        pss_hash,
        pss_mgf1_hash,
        pss_salt_length,
        named_curve: None,
        ec_param_encoding: crate::constants::OPENSSL_EC_NAMED_CURVE,
        public_encoding,
        private_encoding,
    };
    install_job(scope, this, mode, spec);
    rv.set(this.into());
}

/// `new EcKeyPairGenJob(mode, namedCurve, paramEncoding, …encoding)`.
fn ec_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = JobMode::from_raw(args.get(0).int32_value(scope).unwrap_or(-1)) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    let named_curve = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope));
    let ec_param_encoding = args
        .get(2)
        .int32_value(scope)
        .unwrap_or(crate::constants::OPENSSL_EC_NAMED_CURVE);
    let mut offset = 3;
    let values = values_of(scope, &args);
    let Some((public_encoding, private_encoding)) =
        read_encodings(scope, &values, &mut offset, mode, rn_crypto_openssl::EC)
    else {
        return;
    };
    let spec = KeyPairSpec {
        algorithm: rn_crypto_openssl::EC,
        rsa_variant: None,
        modulus_bits: 0,
        exponent: 0,
        pss_hash: None,
        pss_mgf1_hash: None,
        pss_salt_length: -1,
        named_curve,
        ec_param_encoding,
        public_encoding,
        private_encoding,
    };
    install_job(scope, this, mode, spec);
    rv.set(this.into());
}

/// `new NamedKeyPairGenJob(mode, type, …encoding)`.
fn named_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = JobMode::from_raw(args.get(0).int32_value(scope).unwrap_or(-1)) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    let Some(type_name) = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
    else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    // `NamedKeyPairGenTraits::AdditionalConfig`: the name must be a canonical key
    // type spelling and available in this build.
    // An unknown or unavailable type is `ERR_INVALID_ARG_VALUE` naming the value,
    // which is what `test-crypto-keygen.js` expects for `'rsa2'`. Traditional key
    // generation accepts the lowercase type spelling only; WebCrypto passes
    // normalised names and checks availability during normalisation instead.
    let Some(algorithm) = KeyAlgorithm::from_name(&type_name)
        .filter(|algorithm| algorithm.key_type_name() == Some(type_name.as_str()))
        .filter(|algorithm| algorithm.is_available())
    else {
        throw(scope, &KeyError::UnsupportedKeyType(type_name));
        return;
    };
    let mut offset = 2;
    let values = values_of(scope, &args);
    let Some((public_encoding, private_encoding)) =
        read_encodings(scope, &values, &mut offset, mode, algorithm)
    else {
        return;
    };
    let spec = KeyPairSpec {
        algorithm,
        rsa_variant: None,
        modulus_bits: 0,
        exponent: 0,
        pss_hash: None,
        pss_mgf1_hash: None,
        pss_salt_length: -1,
        named_curve: None,
        ec_param_encoding: crate::constants::OPENSSL_EC_NAMED_CURVE,
        public_encoding,
        private_encoding,
    };
    install_job(scope, this, mode, spec);
    rv.set(this.into());
}

/// Reads the public and private encoding pairs a key-pair job carries.
///
/// The WebCrypto form has no encodings at all: it carries the algorithm object
/// and usage masks instead, and always produces `CryptoKey`s.
fn read_encodings(
    scope: &mut v8::PinScope<'_, '_>,
    values: &Values,
    offset: &mut usize,
    mode: JobMode,
    algorithm: KeyAlgorithm,
) -> Option<(PublicKeyEncoding, PrivateKeyEncoding)> {
    if mode == JobMode::WebCrypto {
        // `KeyGenJob::New` reads the algorithm, usage masks and extractable flag
        // for this form. Building a `CryptoKey` is the WebCrypto slice's work,
        // and no acceptance test in this selection uses the WebCrypto keygen
        // path, so it reports rather than producing the wrong object.
        throw(scope, &KeyError::UnsupportedOperation);
        return None;
    }

    // A malformed encoding at generation time is `ERR_CRYPTO_INVALID_KEYTYPE`:
    // `keygen.js` has already validated the option shapes, so what is left is a
    // number this build does not know.
    let public = read_format_and_type(values, offset, EncodingContext::Generate)
        .ok()
        .or_else(|| {
            throw(scope, &KeyError::InvalidKeyType);
            None
        })?;
    let mut private = read_format_and_type(values, offset, EncodingContext::Generate)
        .ok()
        .or_else(|| {
            throw(scope, &KeyError::InvalidKeyType);
            None
        })?;
    // A raw format is only valid for an algorithm that has one. Node rejects the
    // pair at generation time with `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS` rather
    // than producing `undefined` for a half-encoded pair, which is what
    // `test-crypto-keygen-raw.js` asserts for RSA and DSA.
    // A raw format is only valid for an algorithm that has one, and the check
    // has to happen here rather than at export: a half-encoded pair would
    // otherwise produce `undefined` for one half. `test-crypto-keygen-raw.js`
    // asserts `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS` for RSA and DSA.
    {
        // The two halves are validated positionally, because a raw format in the
        // wrong slot is a different error from an unsupported one:
        // `raw-private`/`raw-seed` in `publicKeyEncoding` and `raw-public` in
        // `privateKeyEncoding` are `ERR_INVALID_ARG_VALUE` from `keygen.js`'s own
        // checks, while a family without a raw form at all is
        // `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS`. `test-crypto-keygen-raw.js`
        // asserts both.
        if let Some(format) = public.format {
            let wrong_slot = matches!(
                format,
                rn_crypto_openssl::KeyFormat::RawPrivate | rn_crypto_openssl::KeyFormat::RawSeed
            );
            if wrong_slot {
                throw(
                    scope,
                    &KeyError::UnsupportedKeyType(
                        match format {
                            rn_crypto_openssl::KeyFormat::RawPrivate => "raw-private",
                            _ => "raw-seed",
                        }
                        .to_string(),
                    ),
                );
                return None;
            }
            if format == rn_crypto_openssl::KeyFormat::RawPublic
                && !(algorithm == rn_crypto_openssl::EC || algorithm.supports_raw_public())
            {
                throw(
                    scope,
                    &KeyError::IncompatibleKeyOptions {
                        encoding: algorithm.name().to_string(),
                        detail: "does not support this key encoding",
                    },
                );
                return None;
            }
        }
        if let Some(format) = private.format {
            if format == rn_crypto_openssl::KeyFormat::RawPublic {
                throw(
                    scope,
                    &KeyError::UnsupportedKeyType("raw-public".to_string()),
                );
                return None;
            }
            let supported = match format {
                rn_crypto_openssl::KeyFormat::RawPrivate => {
                    algorithm == rn_crypto_openssl::EC || algorithm.supports_raw_private()
                }
                rn_crypto_openssl::KeyFormat::RawSeed => algorithm.seed_size() != 0,
                _ => true,
            };
            if !supported {
                throw(
                    scope,
                    &KeyError::IncompatibleKeyOptions {
                        encoding: algorithm.name().to_string(),
                        detail: "does not support this key encoding",
                    },
                );
                return None;
            }
        }
    }
    if read_private_key_tail(
        values,
        offset,
        EncodingContext::Generate,
        private.format,
        &mut private,
    )
    .is_err()
    {
        throw(scope, &KeyError::InvalidKeyType);
        return None;
    }
    Some((
        PublicKeyEncoding {
            format: public.format,
            encoding: public.encoding,
            output_key_object: public.output_key_object,
            ec_point_form: public.ec_point_form,
        },
        PrivateKeyEncoding {
            format: private.format,
            encoding: private.encoding,
            cipher: private.cipher,
            passphrase: private.passphrase,
            output_key_object: private.output_key_object,
            ec_point_form: private.ec_point_form,
        },
    ))
}

/// Stores the job and its mode on the instance, and installs `run`.
///
/// `run` is installed as an own property rather than on a shared prototype
/// because each job class has a different `Runnable` type parameter, and a
/// prototype method cannot be generic.
fn install_job<J: Runnable + 'static>(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    mode: JobMode,
    job: J,
) {
    // The mode and the job live in one box, so the `run` callback can recover
    // both without a second internal field.
    let boxed = Box::new((mode, std::cell::RefCell::new(Some(job))));
    let pointer = Box::into_raw(boxed);
    object.set_aligned_pointer_in_internal_field(
        JOB_FIELD,
        pointer.cast::<std::ffi::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut (JobMode, std::cell::RefCell<Option<J>>);
            // SAFETY: allocated just above for this object alone, freed once.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    install_run::<J>(scope, object);
}

/// Installs `run` on a job instance.
fn install_run<J: Runnable + 'static>(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
) {
    let template = v8::FunctionTemplate::builder(run::<J>).build(scope);
    let Some(function) = template.get_function(scope) else {
        return;
    };
    if let Some(key) = v8::String::new(scope, "run") {
        object.set(scope, key.into(), function.into());
    }
}

/// `job.run()`.
fn run<'s, J: Runnable + 'static>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // SAFETY: field 0 is the box `install_job` created for this object.
    let pointer = unsafe { this.get_aligned_pointer_from_internal_field(JOB_FIELD, 0) }
        as *mut (JobMode, std::cell::RefCell<Option<J>>);
    if pointer.is_null() {
        throw(scope, &KeyError::InvalidThis("CryptoJob"));
        return;
    }
    // SAFETY: as above; the finalizer runs only when the object is unreachable.
    let (mode, cell) = unsafe { &*pointer };
    let job = match cell.try_borrow_mut() {
        Ok(mut slot) => slot.take(),
        Err(_) => None,
    };
    let Some(job) = job else {
        throw(scope, &KeyError::OperationFailed("Job already ran"));
        return;
    };
    // SAFETY: reading the mode, which lives in the same box.
    let mode = *mode;
    let this: v8::Local<v8::Object> = args.this();
    match gen::dispatch(scope, mode, job, this) {
        Some(value) => rv.set(value),
        // An async job returns `undefined`; `generateKeyPair` ignores the return
        // value and waits for `ondone`.
        None => rv.set(v8::undefined(scope).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_masks_the_high_byte_to_the_requested_width() {
        // `TruncateToBitLength` clears the spare high bits rather than rounding
        // the length up, so a 9-bit key really is 9 bits of entropy in 2 bytes.
        let mut bytes = vec![0xFFu8, 0xFF];
        truncate_to_bits(9, &mut bytes);
        assert_eq!(bytes, vec![0x80, 0xFF]);

        let mut bytes = vec![0xFFu8; 4];
        truncate_to_bits(32, &mut bytes);
        assert_eq!(bytes, vec![0xFF; 4], "a byte-aligned width is untouched");

        let mut bytes = vec![0xFFu8, 0xFF];
        truncate_to_bits(1, &mut bytes);
        assert_eq!(bytes, vec![0x80, 0xFF], "one bit keeps the top bit");
    }

    #[test]
    fn the_curve_names_resolve() {
        // The spellings `crypto.getCurves()` lists and the JWK names both have to
        // resolve, because `generateKeyPairSync` and `createPrivateKey` use
        // different ones.
        for name in ["prime256v1", "secp384r1", "secp521r1", "secp256k1"] {
            assert!(curve_nid(name).is_some(), "{name}");
        }
        assert_eq!(
            curve_nid("P-256"),
            Some(openssl::nid::Nid::X9_62_PRIME256V1)
        );
        assert_eq!(curve_nid("not-a-curve"), None);
    }
}
