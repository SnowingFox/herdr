//! The six key-generation jobs.
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
//! DsaKeyPairGenJob    (mode, modulusBits, divisorBits, pubFormat, pubType,
//!                      privFormat, privType, cipher, passphrase)
//! DhKeyPairGenJob     (mode, group) | (mode, primeOrPrimeLength, generator),
//!                      then the same encoding tail
//! ```
//!
//! The DH job is the only one whose parameter count varies: `keygen.js` sends a
//! single group-name string when `options.group` was given, and a prime (or a
//! prime length) plus a generator otherwise. `DhKeyGenTraits::AdditionalConfig`
//! in `crypto_dh.cc` decides which by testing `args[offset]->IsString()`, and
//! that test is the only thing that distinguishes the two layouts.

use openssl::pkey::PKey as OpenSslPKey;
use rn_crypto_job::{dispatch, Completion, CryptoJobError, JobMode, Runnable};
use rn_crypto_openssl::{KeyAlgorithm, KeyFormat, PKey, PrivateKeyEncoding, PublicKeyEncoding};
use rn_v8_sys::v8;

use crate::args::{read_format_and_type, read_private_key_tail, EncodingContext, Values};
use crate::errors::{throw, KeyError};
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

/// Installs the six job classes.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // Each job reserves one internal field for its parameters and mode. Without
    // it `set_aligned_pointer_in_internal_field` in the constructor has nowhere
    // to write, and `run()` would read a null.
    macro_rules! job_class {
        ($name:literal => $constructor:path) => {{
            let template = rn_core::class($constructor).build(scope);
            template
                .instance_template(scope)
                .set_internal_field_count(JOB_FIELD as usize + 1);
            // `SetConstructorFunction(…, SET_CLASS_NAME)` in `crypto_keys.cc`, so
            // the class name is the property name and `f.name` reports it.
            rn_core::set_class(scope, target, $name, template)?;
        }};
    }
    job_class!("SecretKeyGenJob" => secret_constructor);
    job_class!("RsaKeyPairGenJob" => rsa_constructor);
    job_class!("EcKeyPairGenJob" => ec_constructor);
    job_class!("NamedKeyPairGenJob" => named_constructor);
    job_class!("DsaKeyPairGenJob" => dsa_constructor);
    job_class!("DhKeyPairGenJob" => dh_constructor);
    Ok(())
}

/// Rejects a call that did not use `new`.
///
/// Node's job constructors are entered through `NewFunctionTemplate` with
/// `ConstructorBehavior::kAllow`, and every one of them reaches a
/// `set_aligned_pointer_in_internal_field` on `args.This()`. Called as a plain
/// function, `This()` is the global object, that write is out of bounds, and V8
/// aborts the process. Node does abort here too, so this is not a divergence in
/// the strict sense; it is a divergence from what a caller can survive, and the
/// tree's policy (see `rn-bind-stream-wrap`) is that a misuse is a catchable
/// `TypeError` rather than a crash. Returning `undefined` instead would be
/// worse than throwing: the caller would get a value where Node gave it a dead
/// process, and `new Job()` would still work.
pub(crate) fn require_new(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
) -> bool {
    if args.is_construct_call() {
        return true;
    }
    throw(scope, &KeyError::ConstructCallRequired);
    false
}

/// The DH parameters a `DhKeyPairGenJob` generates from.
///
/// `DhKeyPairParams` is a `std::variant<BignumPointer, int>`, and which arm it
/// holds decides which OpenSSL call generates the parameters: a fixed prime is
/// imported with `EVP_PKEY_fromdata`, while a bit length is generated with
/// `EVP_PKEY_CTX_set_dh_paramgen_prime_len`. `keygen.js` sends the fixed prime
/// for both `{ group }` and `{ prime }`, because it resolves the group name to
/// its RFC prime before calling the constructor — so the group arm only exists
/// here to keep the two spellings distinct in the error a bad name produces.
enum DhSource {
    /// `{ group: name }`, resolved through `dh_group_prime`.
    Group(String),
    /// `{ prime: <bytes> }`.
    Prime(Vec<u8>),
    /// `{ primeLength: bits }`.
    Length(i32),
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
    /// The `q` width for a `DsaKeyPairGenJob`, or `None` for every other family.
    /// `-1` means keygen.js did not name one.
    dsa_divisor_bits: Option<i32>,
    /// The DH parameter source, or `None` for every other family.
    dh: Option<(DhSource, i32)>,
    public_encoding: PublicKeyEncoding,
    private_encoding: PrivateKeyEncoding,
    /// How the result is presented, which is what the mode decides.
    output: KeyGenOutput,
}

/// What a key-generation job produces.
///
/// `kCryptoJobWebCrypto` is not "the sync mode with a different wrapper": Node
/// reads four extra constructor arguments (the algorithm dictionary, the two
/// usage masks and the extractable flag), skips the encoded-key tail entirely,
/// queues the work like `kCryptoJobAsync`, and settles a promise with a
/// `CryptoKey` — or, for a pair, an ordinary object with `publicKey` and
/// `privateKey`. Treating it as a third inline tuple mode is what made
/// `subtle.generateKey` return `[null, KeyObjectHandle]`.
enum KeyGenOutput {
    /// `[encodedPublic, encodedPrivate]`, or `[KeyObjectHandle, KeyObjectHandle]`
    /// when no encoding was requested. This is the traditional pair form.
    EncodedPair,
    /// A single `KeyObjectHandle` over generated secret bytes.
    SecretHandle,
    /// A `CryptoKey`, built through `keys.js`'s `InternalCryptoKey`.
    CryptoKey {
        algorithm: v8::Global<v8::Value>,
        usages_mask: u32,
        extractable: bool,
    },
    /// A `{publicKey, privateKey}` pair of `CryptoKey`s.
    CryptoKeyPair {
        algorithm: v8::Global<v8::Value>,
        public_usages_mask: u32,
        private_usages_mask: u32,
        extractable: bool,
    },
}

impl Runnable for KeyPairSpec {
    type Output = KeyData;

    fn run(&mut self) -> Result<Self::Output, CryptoJobError> {
        let key = generate_key_pair(self).map_err(|error| crate::errors::job_error(&error))?;
        // A generated key is always private; Node's `KeyPairGenTraits::DoKeyGen`
        // stores exactly that (`CreateAsymmetric(kKeyTypePrivate, ...)`), and
        // `EncodeWebCryptoKey` calls `addRefWithType(kKeyTypePublic)` on it for
        // the public half.
        KeyData::asymmetric(KeyType::Private, key)
            .ok_or_else(|| crate::errors::job_error(&KeyError::InvalidKeyType))
    }

    fn finish<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        let key = output.asymmetric_key()?;
        match &self.output {
            // `KeyPairGenTraits::EncodeKey`: `[public, private]`, each either a
            // `KeyObjectHandle` or an encoded value.
            KeyGenOutput::EncodedPair => {
                let public = encode_public(scope, key, &self.public_encoding, KeyType::Public)?;
                let private = encode_private(scope, key, &self.private_encoding, KeyType::Private)?;
                Some(v8::Array::new_with_elements(scope, &[public, private]).into())
            }
            // `KeyGenJob::EncodeWebCryptoKey` for `kWebCryptoKeyPair`: two
            // `CryptoKey`s in a plain object with own `publicKey` /
            // `privateKey` data properties, both taken through
            // `addRefWithType`. The public half is always extractable and the
            // private half takes the caller's flag.
            KeyGenOutput::CryptoKeyPair {
                algorithm,
                public_usages_mask,
                private_usages_mask,
                extractable,
            } => {
                let algorithm = v8::Local::new(scope, algorithm);
                let public = crypto_key(
                    scope,
                    key,
                    KeyType::Public,
                    algorithm,
                    *public_usages_mask,
                    true,
                )?;
                let private = crypto_key(
                    scope,
                    key,
                    KeyType::Private,
                    algorithm,
                    *private_usages_mask,
                    *extractable,
                )?;
                let object = v8::Object::new(scope);
                for (name, value) in [("publicKey", public), ("privateKey", private)] {
                    let field = v8::String::new(scope, name)?;
                    object.set(scope, field.into(), value)?;
                }
                Some(object.into())
            }
            // A single key has no pair to encode; the caller is a secret-key job.
            KeyGenOutput::SecretHandle | KeyGenOutput::CryptoKey { .. } => None,
        }
    }
}

/// Builds one `CryptoKey` over `key` presented as `key_type`.
///
/// `NativeCryptoKey::Create` is a handle plus `keys.js`'s `InternalCryptoKey`,
/// so this wraps the key in a fresh `KeyObjectHandle` first — the handle owns the
/// `EVP_PKEY` and the `CryptoKey` reads key material back through it, which is
/// why nothing is copied onto the key object itself.
fn crypto_key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: &PKey,
    key_type: KeyType,
    algorithm: v8::Local<'s, v8::Value>,
    usages_mask: u32,
    extractable: bool,
) -> Option<v8::Local<'s, v8::Value>> {
    let data = KeyData::asymmetric(key_type, key.clone())?;
    let handle = create_handle(scope, data)?;
    crate::cryptokey::create_crypto_key(
        scope,
        handle,
        algorithm,
        usages_mask,
        extractable,
        None,
        None,
    )
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
/// The JWK form of one half of a generated pair.
///
/// `KeyPairGenTraits::EncodeKey` calls `ToEncodedPublicKey`, whose JWK arm is
/// `ExportJWKInner`; the fields come from the same place `KeyObject.export({
/// format: 'jwk' })` gets them. A key type JWK cannot represent (DSA, DH) is
/// `ERR_CRYPTO_JWK_UNSUPPORTED_KEY_TYPE`, thrown rather than dropped: `finish`
/// runs under a `TryCatch`, so a throw becomes the `[error, undefined]` the
/// caller's `handleError` reads. Returning `None` instead left both slots
/// undefined and surfaced as "Cannot destructure property '0' of 'keys'".
fn encode_jwk<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: &PKey,
    key_type: KeyType,
) -> Option<v8::Local<'s, v8::Value>> {
    let Some(data) = KeyData::asymmetric(key_type, key.clone()) else {
        throw(scope, &KeyError::InvalidKeyType);
        return None;
    };
    let fields = match crate::handle::export_jwk_fields(&data, false) {
        Ok(fields) => fields,
        Err(error) => {
            throw(scope, &error);
            return None;
        }
    };
    let object = v8::Object::new(scope);
    for (name, value) in fields {
        let field = v8::String::new(scope, name)?;
        let value = v8::String::new(scope, &value)?;
        object.set(scope, field.into(), value.into())?;
    }
    Some(object.into())
}

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
    if encoding.format == Some(KeyFormat::Jwk) {
        return encode_jwk(scope, key, key_type);
    }
    // Same reasoning as `encode_private`: the write's failure is what JavaScript
    // has to see, and `ok()??` discarded it.
    match key.write_public(encoding) {
        Ok(Some(encoded)) => emit_encoded(scope, &encoded),
        Ok(None) => {
            throw(
                scope,
                &KeyError::IncompatibleKeyOptions {
                    encoding: "raw".to_string(),
                    detail: "must be exported with the raw exporter",
                },
            );
            None
        }
        Err(failure) => {
            crate::handle::report_parse_failure(scope, &failure, "Failed to encode public key");
            None
        }
    }
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
        Some(KeyFormat::Jwk) => encode_jwk(scope, key, key_type),
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
            // A `write_private` failure is `ThrowCryptoError` with the packed
            // value it recorded — for an unknown cipher that is
            // `ERR_CRYPTO_UNKNOWN_CIPHER`, and for a rejected format/type pair
            // `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS`. `ok()??` used to drop both,
            // which turned every one of those into "keys is undefined" at the
            // caller. `finish` runs under a `TryCatch`, so throwing here is how
            // the failure reaches `handleError`.
            match key.write_private(encoding) {
                Ok(Some(encoded)) => emit_encoded(scope, &encoded),
                Ok(None) => {
                    throw(
                        scope,
                        &KeyError::IncompatibleKeyOptions {
                            encoding: "raw".to_string(),
                            detail: "must be exported with the raw exporter",
                        },
                    );
                    None
                }
                Err(failure) => {
                    crate::handle::report_parse_failure(
                        scope,
                        &failure,
                        "Failed to encode private key",
                    );
                    None
                }
            }
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
    if spec.algorithm == rn_crypto_openssl::DSA {
        return generate_dsa(spec);
    }
    if spec.algorithm == rn_crypto_openssl::DH {
        return generate_dh(spec);
    }
    generate_named(spec)
}

/// Generates a DSA key pair, which is `DsaKeyGenTraits::Setup`.
fn generate_dsa(spec: &KeyPairSpec) -> Result<PKey, KeyError> {
    let divisor_bits = spec.dsa_divisor_bits.unwrap_or(-1);
    rn_crypto_openssl::generate_dsa(spec.modulus_bits, divisor_bits)
        .map_err(|error| keygen_error(&error))
}

/// Generates a DH key pair, which is `DhKeyGenTraits::Setup`.
fn generate_dh(spec: &KeyPairSpec) -> Result<PKey, KeyError> {
    let failed = || KeyError::OperationFailed("Failed to generate key pair");
    let Some((source, generator)) = &spec.dh else {
        return Err(KeyError::InvalidKeyType);
    };
    let generated = match source {
        DhSource::Group(name) => rn_crypto_openssl::generate_dh_group(name),
        DhSource::Prime(bytes) => {
            let prime = openssl::bn::BigNum::from_slice(bytes).map_err(|_| failed())?;
            rn_crypto_openssl::generate_dh_from_prime(&prime, *generator)
        }
        DhSource::Length(bits) => rn_crypto_openssl::generate_dh_parameters(*bits, *generator),
    };
    generated.map_err(|error| keygen_error(&error))
}

/// Maps a generation failure onto the error the job reports.
///
/// The two shapes are real and tested differently: an unknown group is
/// `ERR_CRYPTO_UNKNOWN_DH_GROUP`, and everything else is `ThrowCryptoError` with
/// the packed OpenSSL value, which is what gives
/// `test-crypto-dh.js`/`test-crypto-keygen.js` a `code` to read.
fn keygen_error(error: &rn_crypto_openssl::KeyGenError) -> KeyError {
    match error {
        rn_crypto_openssl::KeyGenError::UnknownGroup(_) => {
            KeyError::UnknownDhGroup(error.message().to_string())
        }
        rn_crypto_openssl::KeyGenError::OpenSsl { message, packed } => KeyError::OpenSsl {
            message,
            packed: *packed,
        },
    }
}

/// The error a failed key generation reports, carrying OpenSSL's packed value
/// when there is one.
///
/// `KeyGenJob::DoThreadPoolWork` captures the queue and only inserts
/// `KEY_GENERATION_JOB_FAILED` when it is empty, so the OpenSSL detail is what
/// reaches JavaScript whenever there is any.
fn keygen_failure(message: &'static str) -> KeyError {
    let packed = rn_crypto_openssl::openssl_error()
        .map(|error| error.packed)
        .unwrap_or(0);
    KeyError::OpenSsl { message, packed }
}

/// [`keygen_failure`] for a failure `openssl` already drained into an
/// `ErrorStack`.
///
/// The safe crate's calls return `ErrorStack`, which *is* the queue read at the
/// moment it failed — draining it again finds nothing. `CryptoErrorStore::Capture`
/// reports the oldest entry, which is the first one the stack holds.
fn failed_from(error: &openssl::error::ErrorStack) -> KeyError {
    let packed = error
        .errors()
        .first()
        .map(|entry| entry.code())
        .unwrap_or(0);
    KeyError::OpenSsl {
        message: "Failed to generate key pair",
        packed,
    }
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
    // Every failure below comes from OpenSSL and carries its packed entry, which
    // is what gives `publicExponent: 1` the `ERR_OSSL_RSA_PUB_EXPONENT_OUT_OF_RANGE`
    // code `test-crypto-keygen.js` matches on `/exponent/` in the message.
    // Reporting a bare `ERR_CRYPTO_OPERATION_FAILED` lost both.
    let failed = || keygen_failure("Failed to generate key pair");
    let context = openssl::pkey_ctx::PkeyCtx::new_id(id).map_err(|error| failed_from(&error))?;
    let mut context = context;
    context.keygen_init().map_err(|error| failed_from(&error))?;
    context
        .set_rsa_keygen_bits(spec.modulus_bits)
        .map_err(|error| failed_from(&error))?;

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
        return Err(failed());
    }

    if pss {
        set_pss_restrictions(&mut context, spec)?;
    }

    context
        .keygen()
        .map(PKey::from_private)
        .map_err(|error| failed_from(&error))
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
    // Same reasoning as `generate_rsa`: the failure is OpenSSL's, and its packed
    // entry is the `code` the caller reads.
    context.keygen_init().map_err(|error| failed_from(&error))?;
    let key = context.keygen().map_err(|error| failed_from(&error))?;
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
    output: KeyGenOutput,
}

impl Runnable for SecretSpec {
    type Output = KeyData;

    fn run(&mut self) -> Result<Self::Output, CryptoJobError> {
        let mut bytes = vec![0u8; self.length];
        // `ncrypto::CSPRNG`, which is `RAND_bytes`.
        openssl::rand::rand_bytes(&mut bytes).map_err(|_| {
            crate::errors::job_error(&KeyError::OperationFailed("Failed to generate key"))
        })?;
        if self.truncate_to_bit_length {
            // A bit length that is not a multiple of 8 has to be masked in the
            // high byte, or the key would be longer than asked for.
            truncate_to_bits(self.length_bits, &mut bytes);
        }
        Ok(KeyData::secret(bytes))
    }

    fn finish<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        match &self.output {
            // `SecretKeyGenTraits::EncodeKey` returns a `KeyObjectHandle`, which
            // `keygen.js` wraps in a `SecretKeyObject`.
            KeyGenOutput::SecretHandle | KeyGenOutput::EncodedPair => {
                create_handle(scope, output).map(v8::Local::into)
            }
            // `KeyGenJob::EncodeWebCryptoKey`'s non-pair branch: the same
            // `KeyObjectData::CreateSecret`, but wrapped through
            // `NativeCryptoKey::Create` so the caller receives a `CryptoKey`.
            KeyGenOutput::CryptoKey {
                algorithm,
                usages_mask,
                extractable,
            } => {
                let handle = create_handle(scope, output)?;
                crate::cryptokey::create_crypto_key(
                    scope,
                    handle,
                    v8::Local::new(scope, algorithm),
                    *usages_mask,
                    *extractable,
                    None,
                    None,
                )
            }
            KeyGenOutput::CryptoKeyPair { .. } => None,
        }
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
    if !require_new(scope, &args) {
        return;
    }
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
    // `KeyGenJob::New`'s non-pair WebCrypto branch reads three more slots:
    // `CHECK(args[offset]->IsObject())`, `CHECK(args[offset + 1]->IsUint32())`
    // and `CHECK(args[offset + 2]->IsBoolean())`, i.e. the algorithm dictionary,
    // the usages mask and `extractable`.
    let output = match read_webcrypto_key_config(scope, &args, 2, mode, false) {
        Ok(Some(config)) => config,
        Ok(None) => KeyGenOutput::SecretHandle,
        Err(()) => return,
    };
    let spec = SecretSpec {
        length_bits: bits,
        length,
        truncate_to_bit_length: truncate,
        output,
    };
    install_job(scope, this, mode, spec);
    rv.set(this.into());
}

/// Reads the WebCrypto tail `KeyGenJob::New` expects after the algorithm's own
/// parameters.
///
/// The pair form is `{algorithm, publicUsages, privateUsages, extractable}` and
/// the secret form is `{algorithm, usages, extractable}`; the caller says which
/// by `pair`. Returns `Ok(None)` when the job is not in WebCrypto mode, which is
/// the traditional path where the same slots are encodings instead.
fn read_webcrypto_key_config(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    offset: usize,
    mode: JobMode,
    pair: bool,
) -> Result<Option<KeyGenOutput>, ()> {
    if mode != JobMode::WebCrypto {
        return Ok(None);
    }
    let offset = offset as i32;
    let algorithm = args.get(offset);
    let Ok(algorithm) = v8::Local::<v8::Object>::try_from(algorithm) else {
        throw(scope, &KeyError::InvalidKeyType);
        return Err(());
    };
    let first = args.get(offset + 1).uint32_value(scope).unwrap_or(0);
    let second = args.get(offset + 2);
    if pair {
        let private = second.uint32_value(scope).unwrap_or(0);
        let extractable = args.get(offset + 3).is_true();
        Ok(Some(KeyGenOutput::CryptoKeyPair {
            algorithm: v8::Global::new(scope.as_ref(), v8::Local::<v8::Value>::from(algorithm)),
            public_usages_mask: first,
            private_usages_mask: private,
            extractable,
        }))
    } else {
        let extractable = second.is_true();
        Ok(Some(KeyGenOutput::CryptoKey {
            algorithm: v8::Global::new(scope.as_ref(), v8::Local::<v8::Value>::from(algorithm)),
            usages_mask: first,
            extractable,
        }))
    }
}

/// `new RsaKeyPairGenJob(mode, variant, modulusBits, exponent[, hash, mgf1, salt], …encoding)`.
fn rsa_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    if !require_new(scope, &args) {
        return;
    }
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
        // A string-valued slot, or `None` when `keygen.js` passed `undefined`
        // because the option was absent. `to_string` would stringify `undefined`
        // into the literal `"undefined"`, which `digest_by_name` then fails to
        // resolve.
        let hash = string_arg(scope, &args, 4);
        let mgf1 = string_arg(scope, &args, 5);
        // `RsaKeyGenTraits::AdditionalConfig` resolves both names here, at
        // construction time, and reports `ERR_CRYPTO_INVALID_DIGEST` — a
        // `TypeError` whose message names the offending digest. The generation
        // path would otherwise fail on the background thread with a generic
        // `ERR_CRYPTO_OPERATION_FAILED`, which is what `test-crypto-keygen.js`
        // catches on both the `hashAlgorithm` and `mgf1HashAlgorithm` cases.
        for (name, label) in [(&hash, "Invalid digest"), (&mgf1, "Invalid MGF1 digest")] {
            let Some(name) = name else { continue };
            if digest_by_name(name).is_none() {
                throw(
                    scope,
                    &KeyError::InvalidDigest {
                        message: format!("{label}: {name}"),
                    },
                );
                return;
            }
        }
        (
            hash,
            mgf1,
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
    // The WebCrypto form stops after the variant's own parameters: no encoding
    // pair is read, and the next four slots are the algorithm dictionary, the two
    // usage masks and `extractable` (`KeyGenJob::New`'s `kWebCryptoKeyPair`
    // branch).
    let output = match read_webcrypto_key_config(scope, &args, offset, mode, true) {
        Ok(Some(config)) => config,
        Ok(None) => KeyGenOutput::EncodedPair,
        Err(()) => return,
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
        dsa_divisor_bits: None,
        dh: None,
        public_encoding,
        private_encoding,
        output,
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
    if !require_new(scope, &args) {
        return;
    }
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = JobMode::from_raw(args.get(0).int32_value(scope).unwrap_or(-1)) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    let named_curve = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope));
    // `args[*offset + 1]->IsNullOrUndefined()` means "named curve"; only an
    // explicit integer selects a form, because `int32_value` coerces `undefined`
    // to `Some(0)` and 0 is `OPENSSL_EC_EXPLICIT_CURVE`. Reading it blindly
    // turned every WebCrypto EC key — which passes `undefined` here — into an
    // explicit-parameter key, whose PKCS#8 export is 381 bytes where the oracle's
    // is 138.
    let param_encoding_value = args.get(2);
    let ec_param_encoding = if param_encoding_value.is_null_or_undefined() {
        crate::constants::OPENSSL_EC_NAMED_CURVE
    } else {
        param_encoding_value
            .int32_value(scope)
            .unwrap_or(crate::constants::OPENSSL_EC_NAMED_CURVE)
    };
    let mut offset = 3;
    let values = values_of(scope, &args);
    // `new EcKeyPairGenJob(kCryptoJobWebCrypto, namedCurve, undefined,
    // {name, namedCurve}, publicUsages, privateUsages, extractable)`: the
    // algorithm dictionary sits where the public encoding's format goes.
    let output = match read_webcrypto_key_config(scope, &args, offset, mode, true) {
        Ok(Some(config)) => config,
        Ok(None) => KeyGenOutput::EncodedPair,
        Err(()) => return,
    };
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
        dsa_divisor_bits: None,
        dh: None,
        public_encoding,
        private_encoding,
        output,
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
    if !require_new(scope, &args) {
        return;
    }
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
    // `NamedKeyPairGenTraits::AdditionalConfig`:
    //
    //     if (algorithm == nullptr || (!algorithm->isOkp() && !algorithm->isPqc()) ||
    //         (mode != kCryptoJobWebCrypto &&
    //          (std::string_view(*name, name.length()) != algorithm->keyTypeName() ||
    //           !algorithm->isAvailable()))) { THROW_ERR_INVALID_ARG_VALUE(...) }
    //
    // So this class names only Okp/Pqc algorithms, and the strict spelling and
    // availability checks apply to the traditional path alone. WebCrypto passes
    // normalised names (`'Ed25519'`, `'ML-DSA-44'`) that are neither the lowercase
    // `asymmetricKeyType` spelling nor case-insensitively equal to it, so applying
    // the traditional filter made every `subtle.generateKey('Ed25519', ...)` throw
    // `ERR_INVALID_ARG_VALUE` naming an algorithm the caller had just been given.
    let algorithm = KeyAlgorithm::from_name(&type_name)
        .filter(|algorithm| algorithm.is_okp() || algorithm.is_pqc());
    let algorithm = algorithm.filter(|algorithm| {
        mode == JobMode::WebCrypto
            || (algorithm.key_type_name() == Some(type_name.as_str()) && algorithm.is_available())
    });
    let Some(algorithm) = algorithm else {
        throw(scope, &KeyError::UnsupportedKeyType(type_name));
        return;
    };
    let mut offset = 2;
    let values = values_of(scope, &args);
    let output = match read_webcrypto_key_config(scope, &args, offset, mode, true) {
        Ok(Some(config)) => config,
        Ok(None) => KeyGenOutput::EncodedPair,
        Err(()) => return,
    };
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
        dsa_divisor_bits: None,
        dh: None,
        public_encoding,
        private_encoding,
        output,
    };
    install_job(scope, this, mode, spec);
    rv.set(this.into());
}

/// `new DsaKeyPairGenJob(mode, modulusBits, divisorBits, …encoding)`.
///
/// `DsaKeyGenTraits::AdditionalConfig` reads two `CHECK`ed arguments and leaves
/// `offset` at 3, so the encoding tail is the same one every other job reads —
/// but there is no WebCrypto branch, because `keygen.js` never builds a DSA job
/// for `subtle`. Node would abort on a `kCryptoJobWebCrypto` DSA job rather than
/// generate anything, so this rejects the mode instead of guessing at an
/// argument layout that `lib/**` does not produce.
fn dsa_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    if !require_new(scope, &args) {
        return;
    }
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = JobMode::from_raw(args.get(0).int32_value(scope).unwrap_or(-1)) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    if mode == JobMode::WebCrypto {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    }
    let modulus_bits = args.get(1).uint32_value(scope).unwrap_or(0);
    // `int32_value` reports 0 for anything that is not an integer, which would
    // turn an absent `divisorLength` into an explicit zero-bit `q`; `keygen.js`
    // sends -1 for the absent case, so the distinction is preserved here.
    let divisor_bits = int32_arg(scope, &args, 2).unwrap_or(-1);
    let mut offset = 3;
    let values = values_of(scope, &args);
    let Some((public_encoding, private_encoding)) =
        read_encodings(scope, &values, &mut offset, mode, rn_crypto_openssl::DSA)
    else {
        return;
    };
    let spec = KeyPairSpec {
        algorithm: rn_crypto_openssl::DSA,
        rsa_variant: None,
        modulus_bits,
        exponent: 0,
        pss_hash: None,
        pss_mgf1_hash: None,
        pss_salt_length: -1,
        named_curve: None,
        ec_param_encoding: crate::constants::OPENSSL_EC_NAMED_CURVE,
        dsa_divisor_bits: Some(divisor_bits),
        dh: None,
        public_encoding,
        private_encoding,
        output: KeyGenOutput::EncodedPair,
    };
    install_job(scope, this, mode, spec);
    rv.set(this.into());
}

/// `new DhKeyPairGenJob(mode, group, …encoding)` or
/// `new DhKeyPairGenJob(mode, primeOrPrimeLength, generator, …encoding)`.
///
/// The two layouts are told apart exactly as `DhKeyGenTraits::AdditionalConfig`
/// does it, by testing whether slot 1 is a string. A string is a group name and
/// the tail starts at 2; anything else is a prime (bytes) or a prime length
/// (int32) with the generator in slot 2, and the tail starts at 3.
fn dh_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    if !require_new(scope, &args) {
        return;
    }
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = JobMode::from_raw(args.get(0).int32_value(scope).unwrap_or(-1)) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    if mode == JobMode::WebCrypto {
        // `keygen.js` has no WebCrypto DH branch: `subtle.generateKey` for DH is
        // not part of WebCrypto, so Node reaches the same `CHECK` failure this
        // rejects as an error rather than as an abort.
        throw(scope, &KeyError::InvalidKeyType);
        return;
    }
    let first = args.get(1);
    let (source, generator, mut offset) = if let Ok(text) = v8::Local::<v8::String>::try_from(first)
    {
        // `{ group }`. `keygen.js` forbids a generator beside a group, so the
        // standard generator 2 is not a default here: it is the only legal
        // value, and `DhKeyGenTraits::Setup` supplies it the same way.
        let name = text.to_rust_string_lossy(scope);
        if rn_crypto_openssl::dh_group_prime(&name).is_none() {
            throw(scope, &KeyError::UnknownDhGroup(name));
            return;
        }
        (DhSource::Group(name), 2, 2)
    } else if let Some(bytes) = crate::handle::bytes_of(first) {
        // `{ prime }`. `keygen.js` has already validated that it is a buffer and
        // rejected a `primeLength` beside it.
        let generator = int32_arg(scope, &args, 2).unwrap_or(2);
        (DhSource::Prime(bytes), generator, 3)
    } else {
        // `{ primeLength }`, which `keygen.js` validates as an int32 because
        // that is the only remaining member of the union.
        let bits = int32_arg(scope, &args, 1).unwrap_or(0);
        let generator = int32_arg(scope, &args, 2).unwrap_or(2);
        (DhSource::Length(bits), generator, 3)
    };
    let values = values_of(scope, &args);
    let Some((public_encoding, private_encoding)) =
        read_encodings(scope, &values, &mut offset, mode, rn_crypto_openssl::DH)
    else {
        return;
    };
    let spec = KeyPairSpec {
        algorithm: rn_crypto_openssl::DH,
        rsa_variant: None,
        modulus_bits: 0,
        exponent: 0,
        pss_hash: None,
        pss_mgf1_hash: None,
        pss_salt_length: -1,
        named_curve: None,
        ec_param_encoding: crate::constants::OPENSSL_EC_NAMED_CURVE,
        dsa_divisor_bits: None,
        dh: Some((source, generator)),
        public_encoding,
        private_encoding,
        output: KeyGenOutput::EncodedPair,
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
        // `KeyPairGenTraits::AdditionalConfig` returns early for this mode:
        // "if (mode == kCryptoJobWebCrypto) return v8::JustVoid();" — no
        // public/private encoding pair is read at all, because the job always
        // produces `CryptoKey`s. The three constructors read the algorithm
        // dictionary, the two usage masks and the extractable flag themselves,
        // through `read_webcrypto_key_config`.
        return Some((PublicKeyEncoding::default(), PrivateKeyEncoding::default()));
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
                    // `THROW_ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS(env)` with no
                    // arguments, i.e. the template's own text, which never names
                    // the algorithm. `test-crypto-keygen-raw.js` compares only
                    // the code, but the message is what a caller reads and the
                    // oracle's is this one.
                    &KeyError::IncompatibleKeyOptions {
                        encoding: String::new(),
                        detail: "is incompatible with the key type",
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
                    // `THROW_ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS(env)` with no
                    // arguments, i.e. the template's own text, which never names
                    // the algorithm. `test-crypto-keygen-raw.js` compares only
                    // the code, but the message is what a caller reads and the
                    // oracle's is this one.
                    &KeyError::IncompatibleKeyOptions {
                        encoding: String::new(),
                        detail: "is incompatible with the key type",
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
    let template = rn_core::class(run::<J>).build(scope);
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
    // `Completion::Promise` for the WebCrypto mode: `CryptoJob::Run` creates a
    // `Promise::Resolver`, returns its promise and queues the work, so
    // `jobPromise` in `lib/internal/crypto/util.js` receives a promise to await
    // rather than a `[err, value]` tuple. The other two modes keep their own
    // shapes — `Callback` for `kCryptoJobAsync` (the `generateKeyPair`
    // callback form) and the tuple for `kCryptoJobSync`.
    let completion = match mode {
        JobMode::WebCrypto => Completion::Promise,
        JobMode::Async | JobMode::Sync => Completion::Callback,
    };
    match dispatch(scope, mode, job, this, completion) {
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

    #[test]
    fn generated_ec_keys_export_jwk_fields_for_both_halves() {
        let key = openssl::pkey::PKey::ec_gen("prime256v1").expect("P-256 generates");
        let key = PKey::from_private(key);

        let public = KeyData::asymmetric(KeyType::Public, key.clone()).expect("public key data");
        let public = crate::handle::export_jwk_fields(&public, false).expect("public JWK fields");
        assert!(
            public
                .iter()
                .any(|(name, value)| *name == "kty" && value == "EC"),
            "public JWK must carry kty=EC"
        );
        assert!(
            public.iter().all(|(name, _)| *name != "d"),
            "public JWK must not include the private scalar"
        );

        let private = KeyData::asymmetric(KeyType::Private, key).expect("private key data");
        let private =
            crate::handle::export_jwk_fields(&private, false).expect("private JWK fields");
        assert!(
            private.iter().any(|(name, _)| *name == "d"),
            "private JWK must include the private scalar"
        );
    }

    #[test]
    fn a_dsa_spec_generates_a_key_with_the_requested_lengths() {
        // `DsaKeyGenTraits::AdditionalConfig` reads the two lengths and nothing
        // else, so a spec carrying them is the whole job. 1024/160 is the pair
        // OpenSSL accepts without the FIPS restriction.
        let spec = dsa_spec(1024, 160);
        let key = generate_key_pair(&spec).expect("1024/160 generates");
        let detail = key.dsa_detail().expect("a DSA key has p and q");
        assert_eq!(detail.modulus_length, 1024);
        assert_eq!(detail.divisor_length, 160);
    }

    #[test]
    fn an_absent_dsa_divisor_length_is_passed_through_as_absences() {
        // `keygen.js` sends -1 for an absent `divisorLength`, and passing 0
        // instead is a different request: OpenSSL would be asked for a zero-bit
        // `q`. The oracle reports 224 for a 1024-bit modulus, so this pins the
        // pass-through rather than the number.
        let spec = dsa_spec(1024, -1);
        let key = generate_key_pair(&spec).expect("a default q generates");
        let detail = key.dsa_detail().expect("a DSA key has p and q");
        assert_eq!(detail.modulus_length, 1024);
        assert_eq!(detail.divisor_length, 224);
    }

    #[test]
    fn a_dsa_failure_reports_the_openssl_code_rather_than_a_generic_one() {
        // 512/160 is refused by the provider, and the test that covers it reads
        // `ERR_OSSL_DSA_BAD_FFC_PARAMETERS`. A generic
        // `ERR_CRYPTO_OPERATION_FAILED` here would make that assertion fail on
        // the code even though the generation failed as it should.
        let error = generate_key_pair(&dsa_spec(512, 160)).expect_err("512/160 is refused");
        assert_eq!(
            error.code(),
            None,
            "the code is derived from the packed value"
        );
        let KeyError::OpenSsl { packed, .. } = error else {
            panic!("expected an OpenSSL failure");
        };
        let detail = rn_crypto_openssl::openssl_error_for(packed).expect("resolves");
        assert_eq!(detail.code(), "ERR_OSSL_DSA_BAD_FFC_PARAMETERS");
    }

    #[test]
    fn a_dh_group_spec_generates_a_key_over_that_group() {
        for (group, bits) in [("modp5", 1536), ("modp14", 2048)] {
            let spec = dh_group_spec(group);
            let key = generate_key_pair(&spec).expect("the group generates");
            assert_eq!(key.bits(), bits, "{group} has {bits}-bit p");
        }
    }

    #[test]
    fn an_unknown_dh_group_is_the_dedicated_error() {
        // `DhKeyGenTraits::AdditionalConfig` throws this before generating
        // anything, and `test-crypto-keygen.js` asserts both the code and the
        // exact message.
        let error = generate_key_pair(&dh_group_spec("modp0")).expect_err("modp0 is not a group");
        assert_eq!(error.code(), Some("ERR_CRYPTO_UNKNOWN_DH_GROUP"));
        assert_eq!(error.message(), "Unknown DH group");
    }

    #[test]
    fn a_dh_prime_length_spec_generates_a_prime_of_that_width() {
        // 512 is the smallest the provider accepts, and the smallest the suite
        // asks for; a larger one costs seconds per call.
        let spec = dh_spec(DhSource::Length(512), 2);
        let key = generate_key_pair(&spec).expect("512-bit parameters generate");
        assert_eq!(key.bits(), 512);
    }

    #[test]
    fn a_dh_prime_length_below_the_provider_minimum_reports_modulus_too_small() {
        let error = generate_key_pair(&dh_spec(DhSource::Length(64), 2)).expect_err("64 is short");
        let KeyError::OpenSsl { packed, .. } = error else {
            panic!("expected an OpenSSL failure");
        };
        let detail = rn_crypto_openssl::openssl_error_for(packed).expect("resolves");
        assert_eq!(detail.code(), "ERR_OSSL_DH_MODULUS_TOO_SMALL");
    }

    #[test]
    fn a_dh_generator_below_two_reports_bad_generator() {
        let error = generate_key_pair(&dh_spec(DhSource::Length(512), 1)).expect_err("gen 1");
        let KeyError::OpenSsl { packed, .. } = error else {
            panic!("expected an OpenSSL failure");
        };
        let detail = rn_crypto_openssl::openssl_error_for(packed).expect("resolves");
        assert_eq!(detail.code(), "ERR_OSSL_DH_BAD_GENERATOR");
    }

    #[test]
    fn an_explicit_dh_prime_behaves_like_the_group_it_came_from() {
        // `generateKeyPairSync('dh', { prime: group.getPrime() })` is the same
        // key as `{ group }` once the name is resolved, which is what
        // `test-crypto-dh-stateless.js` compares the two exports through.
        let prime = rn_crypto_openssl::dh_group_prime("modp5").expect("modp5");
        let spec = dh_spec(DhSource::Prime(prime.to_vec()), 2);
        let key = generate_key_pair(&spec).expect("an explicit prime generates");
        assert_eq!(key.bits(), 1536);
    }

    /// A `KeyPairSpec` carrying only what a DSA job reads.
    fn dsa_spec(modulus_bits: u32, divisor_bits: i32) -> KeyPairSpec {
        KeyPairSpec {
            algorithm: rn_crypto_openssl::DSA,
            rsa_variant: None,
            modulus_bits,
            exponent: 0,
            pss_hash: None,
            pss_mgf1_hash: None,
            pss_salt_length: -1,
            named_curve: None,
            ec_param_encoding: crate::constants::OPENSSL_EC_NAMED_CURVE,
            dsa_divisor_bits: Some(divisor_bits),
            dh: None,
            public_encoding: PublicKeyEncoding::default(),
            private_encoding: PrivateKeyEncoding::default(),
            output: KeyGenOutput::EncodedPair,
        }
    }

    /// A `KeyPairSpec` carrying a named-group DH request.
    fn dh_group_spec(group: &str) -> KeyPairSpec {
        dh_spec(DhSource::Group(group.to_string()), 2)
    }

    /// A `KeyPairSpec` carrying only what a DH job reads.
    fn dh_spec(source: DhSource, generator: i32) -> KeyPairSpec {
        KeyPairSpec {
            algorithm: rn_crypto_openssl::DH,
            rsa_variant: None,
            modulus_bits: 0,
            exponent: 0,
            pss_hash: None,
            pss_mgf1_hash: None,
            pss_salt_length: -1,
            named_curve: None,
            ec_param_encoding: crate::constants::OPENSSL_EC_NAMED_CURVE,
            dsa_divisor_bits: None,
            dh: Some((source, generator)),
            public_encoding: PublicKeyEncoding::default(),
            private_encoding: PrivateKeyEncoding::default(),
            output: KeyGenOutput::EncodedPair,
        }
    }
}
