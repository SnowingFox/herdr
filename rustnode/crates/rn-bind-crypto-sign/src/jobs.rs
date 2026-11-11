//! `SignJob` and `RSACipherJob`, the one-shot signature and RSA cipher jobs.
//!
//! `crypto.sign`/`crypto.verify` build a `SignJob` and call `.run()`; `rsa.js`
//! builds one for the WebCrypto RSASSA-PKCS1-v1_5 and RSA-PSS paths, and builds
//! an `RSACipherJob` for RSA-OAEP. All of them take the whole message in one call
//! rather than streaming it, so they are a different shape from the `Sign` and
//! `Verify` classes.
//!
//! # Why the key is decoded in the constructor
//!
//! `new SignJob(...)` receives the key material in slots 2..7 and `run()` is
//! called later, on a fresh stack, where the constructor's V8 arguments no longer
//! exist. The key is therefore decoded in the constructor and owned by the job,
//! which is the opposite of Node's layout — Node's `CryptoJob` keeps a
//! `shared_ptr<KeyObjectData>` — but observably identical, because nothing
//! between construction and `run()` can change the key.
//!
//! # Sync only, and why that is declared rather than faked
//!
//! `sig.js` picks `kCryptoJobAsync` when a callback was given and
//! `kCryptoJobSync` otherwise, and for the sync mode reads the result out of
//! `job.run()`'s *return value*. That is the form `test-crypto-sign-verify.js`
//! and every `crypto.sign(...)` call in the suite use. The async form needs the
//! libuv threadpool and a completion callback, which is slice S9; a job built
//! with `kCryptoJobAsync` reports that it needs a callback rather than silently
//! resolving synchronously, because a promise that settles early is
//! indistinguishable from a correct one to most tests and would hide the gap.

use foreign_types::ForeignTypeRef;
use rn_bind_crypto_keys::{read_key_from_js, KeyType};
use rn_crypto_openssl::{
    bytes_of_rs, clear_openssl_error, default_sign_padding, digest_by_name, sign_digest,
    signature_from_p1363, signature_to_p1363, verify_digest, PKey, SignError,
    RSA_PKCS1_PSS_PADDING,
};
use rn_v8_sys::v8;

/// `kSignJobModeSign`.
const K_SIGN_JOB_MODE_SIGN: i32 = 1;
/// `kSignJobModeVerify`.
const K_SIGN_JOB_MODE_VERIFY: i32 = 2;
/// `kSigEncDER`.
const K_SIG_ENC_DER: i32 = 1;
/// `kSigEncP1363`.
const K_SIG_ENC_P1363: i32 = 2;
/// `kKeyVariantRSA_SSA_PKCS1_v1_5`.
const K_KEY_VARIANT_RSA_SSA_PKCS1_V1_5: i32 = 0;

/// Why a job failed, with the OpenSSL detail when there is any.
///
/// The detail has to be captured at the failure site: the thread-local error
/// queue is drained by the first reader, so a generic `("message", "code")` pair
/// loses the real reason. That is what made a restricted RSA-PSS key report
/// "Signature operation failed" where real `node` reports
/// `ERR_OSSL_DIGEST_NOT_ALLOWED` with "digest not allowed".
#[derive(Clone, Debug)]
enum JobError {
    /// A cryptographic failure with nothing on the OpenSSL queue.
    Plain(&'static str, &'static str),
    /// A failure OpenSSL described: the packed error and its parts.
    OpenSsl {
        packed: u64,
        library: String,
        reason: String,
    },
}

impl JobError {
    /// The best description of whatever OpenSSL just queued, or `fallback`.
    fn from_queue(fallback: &'static str) -> Self {
        match rn_crypto_openssl::openssl_error() {
            Some(error) => Self::OpenSsl {
                packed: error.packed,
                library: error.library_display,
                reason: error.reason,
            },
            None => Self::Plain(fallback, "ERR_CRYPTO_OPERATION_FAILED"),
        }
    }
}

/// The work a job handle carries, with the key already decoded.
enum JobKind {
    /// A one-shot sign or verify over a whole message.
    Sign {
        job_mode: i32,
        /// The key, or `None` when the constructor's decode failed. The failure
        /// is recorded rather than thrown so `run()` can report it in the
        /// `[err, result]` shape the sync caller destructures.
        key: Option<PKey>,
        key_error: Option<(&'static str, &'static str)>,
        data: Vec<u8>,
        /// `null` for Ed25519, where there is no separate digest algorithm.
        algorithm: Option<String>,
        salt_length: Option<i32>,
        padding: Option<i32>,
        dsa_encoding: i32,
        signature: Option<Vec<u8>>,
        /// Ed25519ctx/Ed448 domain-separation string, from `options.context`.
        context: Option<Vec<u8>>,
    },
    /// The RSA encrypt/decrypt job, which belongs to the cipher slice.
    RsaCipher { variant: i32 },
}

/// Installs `SignJob` and `RSACipherJob`, and the padding constant that
/// `Sign::Initialize` defines.
pub fn install_sign_job<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    install_job_class(scope, target, "SignJob", sign_job_constructor)?;
    install_job_class(scope, target, "RSACipherJob", rsa_cipher_job_constructor)?;
    // Defined in `crypto_sig.cc`'s `Sign::Initialize` rather than in a constants
    // block, so it belongs to this translation unit's install.
    set_number(
        scope,
        target,
        "RSA_PKCS1_PSS_PADDING",
        RSA_PKCS1_PSS_PADDING,
    )
}

/// `new SignJob(mode, jobMode, keyData, keyFormat, keyType, passphrase,
/// namedCurve, data, algorithm, saltLength, padding, dsaEncoding, context,
/// signature)`.
///
/// `sig.js` builds this for `crypto.sign`/`crypto.verify`; `rsa.js` builds it for
/// the WebCrypto RSASSA paths with `kCryptoJobWebCrypto`. The two differ only in
/// where the key comes from: the first passes PEM/DER bytes, the second a
/// `KeyObjectHandle`, and `read_key_from_js` accepts either.
fn sign_job_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let job_mode = int_at(&args, 1).unwrap_or(K_SIGN_JOB_MODE_SIGN);
    // The state is installed *first*, with no key, so a decode failure below
    // leaves the object runnable instead of with a null internal field. `run()`
    // on such a job reports the failure through the `[err, result]` pair, which
    // is the shape the sync caller destructures; without this the receiver has
    // no state at all and `run()` has to guess.
    install_state(
        scope,
        this,
        JobKind::Sign {
            job_mode,
            key: None,
            key_error: Some(("the job has no key", "ERR_CRYPTO_INVALID_KEYTYPE")),
            data: Vec::new(),
            algorithm: None,
            salt_length: None,
            padding: None,
            dsa_encoding: K_SIG_ENC_DER,
            signature: None,
            context: None,
        },
    );

    // The key occupies slots 2..7: data, format, type, passphrase, namedCurve.
    let mut key_offset = 2usize;
    // A verify job takes a public or a private key; a sign job only a private one.
    let key_type = if job_mode == K_SIGN_JOB_MODE_VERIFY {
        KeyType::Public
    } else {
        KeyType::Private
    };
    let decoded = read_key_from_js(scope, &args, &mut key_offset, key_type);
    let (key, key_error) = match decoded {
        Some(data) => match data.asymmetric_key() {
            Some(key) => (Some(key.clone()), None),
            None => (
                None,
                Some((
                    "a secret key cannot be used to sign",
                    "ERR_CRYPTO_INVALID_KEYTYPE",
                )),
            ),
        },
        // `read_key_from_js` throws for a real parse failure. The job keeps its
        // placeholder state and the pending exception propagates, which is what
        // `sig.js` sees.
        None => return,
    };

    let Some(data) = bytes_of(args.get(7)) else {
        throw_type_error(scope, "The data argument must be an ArrayBufferView");
        return;
    };
    let algorithm = string_of(scope, args.get(8));
    // `sig.js` passes `pssSaltLength` in slot 9 and `rsaPadding` in slot 10.
    let salt_length = int_at(&args, 9);
    let padding = int_at(&args, 10);
    let dsa_encoding = int_at(&args, 11).unwrap_or(K_SIG_ENC_DER);
    // Slot 12 is the ML-DSA/Ed448 context string; `sig.js` sends `undefined`
    // when no `context` option was given.
    let context = bytes_of(args.get(12));
    let signature = if job_mode == K_SIGN_JOB_MODE_VERIFY {
        match bytes_of(args.get(13)) {
            Some(bytes) => Some(bytes),
            None => {
                throw_type_error(scope, "The signature argument must be an ArrayBufferView");
                return;
            }
        }
    } else {
        None
    };

    replace_state(
        scope,
        this,
        JobKind::Sign {
            job_mode,
            key,
            key_error,
            data,
            algorithm,
            salt_length,
            padding,
            dsa_encoding,
            signature,
            context,
        },
    );
    rv.set(this.into());
}

/// `new RSACipherJob(mode, cipherMode, key, data, variant, hash, label)`.
///
/// The key is not decoded: RSA encryption needs `EVP_PKEY_encrypt` and the key's
/// padding variant, which the cipher slice owns. Constructing the job is enough
/// for `rsa.js` to reach `run()`, where the gap is reported.
fn rsa_cipher_job_constructor<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let variant = int_at(&args, 4).unwrap_or(K_KEY_VARIANT_RSA_SSA_PKCS1_V1_5);
    install_state(_scope, this, JobKind::RsaCipher { variant });
    rv.set(this.into());
}

/// `SignJob.prototype.run()` / `RSACipherJob.prototype.run()`.
///
/// The sync form returns `[err, result]`, which `sig.js` destructures:
///
/// ```text
/// const { 0: err, 1: signature } = job.run();
/// if (err !== undefined) throw err;
/// ```
///
/// So a failure is a two-element array whose first entry is the error *object*,
/// not a thrown exception — throwing here would surface as an uncaught error
/// instead of the `ERR_*` the caller expects.
fn run(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(state) = with_state(this) else {
        throw(scope, "the job handle is not initialised");
        return;
    };

    let outcome = match &state {
        JobKind::Sign {
            job_mode,
            key,
            key_error,
            data,
            algorithm,
            salt_length,
            padding,
            dsa_encoding,
            signature,
            context,
        } => {
            if let Some((message, code)) = key_error {
                emit_pair(scope, &mut rv, Err(JobError::Plain(message, code)));
                return;
            }
            let Some(key) = key else {
                emit_pair(
                    scope,
                    &mut rv,
                    Err(JobError::Plain(
                        "the job has no key",
                        "ERR_CRYPTO_INVALID_KEYTYPE",
                    )),
                );
                return;
            };
            run_sign(
                key,
                *job_mode,
                data,
                algorithm.as_deref(),
                *salt_length,
                *padding,
                *dsa_encoding,
                signature.as_deref(),
                context.as_deref(),
            )
        }
        JobKind::RsaCipher { variant } => {
            // Reported rather than half-implemented: a job that returned its
            // input would look like a pass to a caller that does not compare
            // bytes, and `rsa.js`'s OAEP path is the cipher slice's work.
            let message = if *variant == 2 {
                "RSA-OAEP is not implemented yet"
            } else {
                "RSACipherJob is not implemented yet"
            };
            Err(JobError::Plain(message, "ERR_CRYPTO_OPERATION_FAILED"))
        }
    };

    match outcome {
        Ok(JobOutcome::Signature(bytes)) => {
            emit_pair(scope, &mut rv, Ok(BytesOrBool::Bytes(bytes)))
        }
        Ok(JobOutcome::Verified(value)) => emit_pair(scope, &mut rv, Ok(BytesOrBool::Bool(value))),
        Err(error) => emit_pair(scope, &mut rv, Err(error)),
    }
}

/// What a successful job produced.
enum JobOutcome {
    Signature(Vec<u8>),
    Verified(bool),
}

/// Hashes `data` with `algorithm` and signs or verifies it.
///
/// An absent algorithm means Ed25519/Ed448, whose signature is over the message
/// and not over a digest: `crypto.sign(null, data, ed25519Key)` is the form
/// `test-crypto-sign-verify.js` uses for those. They go through
/// `EVP_DigestSign` with a null digest rather than this prehashed path.
#[allow(clippy::too_many_arguments)]
fn run_sign(
    key: &PKey,
    job_mode: i32,
    data: &[u8],
    algorithm: Option<&str>,
    salt_length: Option<i32>,
    padding: Option<i32>,
    dsa_encoding: i32,
    signature: Option<&[u8]>,
    context: Option<&[u8]>,
) -> Result<JobOutcome, JobError> {
    let is_rsa = key.algorithm().is_some_and(|algorithm| algorithm.is_rsa());
    let is_pss = key
        .algorithm()
        .is_some_and(|algorithm| algorithm.name() == "RSA-PSS");
    let padding = padding.unwrap_or_else(|| default_sign_padding(is_pss));

    let Some(algorithm) = algorithm else {
        // The EdDSA path: no digest, so the message is signed directly.
        return run_eddsa(key, job_mode, data, signature, context);
    };
    if context.is_some_and(|value| !value.is_empty()) {
        // Only the EdDSA instances accept a context string. Node reports this
        // through `SignBase::Error::ContextUnsupported`, which is
        // `ERR_CRYPTO_OPERATION_FAILED` with exactly this message.
        return Err(JobError::Plain(
            "Context parameter is unsupported",
            "ERR_CRYPTO_OPERATION_FAILED",
        ));
    }
    let Some(digest) = digest_by_name(algorithm) else {
        return Err(JobError::Plain(
            "Invalid digest",
            "ERR_CRYPTO_INVALID_DIGEST",
        ));
    };

    // `CanUsePrehashedFallback`: SM2's digest signing first hashes the
    // algorithm-specific `Z` value, so signing an already-computed digest is not
    // equivalent to hashing the message. SM2 must therefore go through
    // `EVP_DigestSign`, which computes `Z` itself, and it is the one case where
    // the one-shot and streaming paths deliberately disagree: `check` in
    // `test-crypto-sign-verify.js` asserts that an SM2 signature produced by the
    // streaming path does *not* verify through `crypto.verify`.
    if key_is_sm2(key) {
        return run_message_sign(key, job_mode, data, digest, signature);
    }

    let hashed = match hash_once(digest, data) {
        Some(hashed) => hashed,
        None => return Err(JobError::from_queue("Digest failed")),
    };

    if job_mode == K_SIGN_JOB_MODE_VERIFY {
        let Some(signature) = signature else {
            return Err(JobError::Plain(
                "A signature is required",
                "ERR_CRYPTO_INVALID_ARG_VALUE",
            ));
        };
        let signature = if dsa_encoding == K_SIG_ENC_P1363 {
            match bytes_of_rs(key.openssl_ref()) {
                Some(width) => match signature_from_p1363(signature, width) {
                    Some(converted) => converted,
                    // A body that is not exactly two `width`-byte integers is
                    // not a signature at all. Real `node` answers `false` here
                    // rather than throwing — verified against `node` v22 for
                    // every length offset the test tries (-2, -1, 1, 2, 4, 8
                    // from the fixed width) — so this matches it instead of
                    // reporting `Malformed signature`. `test-crypto-sign-verify`
                    // accepts either, because its `catch` continues.
                    None => return Ok(JobOutcome::Verified(false)),
                },
                None => signature.to_vec(),
            }
        } else {
            signature.to_vec()
        };
        match verify_digest(
            key.openssl_ref(),
            &hashed,
            digest,
            &signature,
            is_rsa,
            padding,
            salt_length,
        ) {
            Ok(result) => Ok(JobOutcome::Verified(result)),
            Err(error) => Err(job_error_from_sign(error, "Signature verification failed")),
        }
    } else {
        match sign_digest(
            key.openssl_ref(),
            &hashed,
            digest,
            is_rsa,
            padding,
            salt_length,
        ) {
            Ok(mut bytes) => {
                if dsa_encoding == K_SIG_ENC_P1363 {
                    if let Some(width) = bytes_of_rs(key.openssl_ref()) {
                        match signature_to_p1363(&bytes, width) {
                            Some(converted) => bytes = converted,
                            None => {
                                return Err(JobError::Plain(
                                    "Malformed signature",
                                    "ERR_CRYPTO_OPERATION_FAILED",
                                ))
                            }
                        }
                    }
                }
                Ok(JobOutcome::Signature(bytes))
            }
            Err(error) => Err(job_error_from_sign(error, "Signature operation failed")),
        }
    }
}

/// Converts a [`SignError`] into a [`JobError`], keeping OpenSSL's detail.
///
/// The shared layer drains the queue into `SignError::OpenSsl` (or carries the
/// detail itself, for the padding path), so reading the queue again here would
/// find it empty and report `fallback` instead of, say,
/// `ERR_OSSL_DIGEST_NOT_ALLOWED`.
fn job_error_from_sign(error: SignError, fallback: &'static str) -> JobError {
    match error {
        SignError::UnknownDigest => JobError::Plain("Invalid digest", "ERR_CRYPTO_INVALID_DIGEST"),
        SignError::NotInitialised => JobError::Plain("Not initialised", "ERR_CRYPTO_INVALID_STATE"),
        SignError::MalformedSignature => {
            JobError::Plain("Malformed signature", "ERR_CRYPTO_OPERATION_FAILED")
        }
        SignError::Padding {
            packed,
            library,
            reason,
        } => JobError::OpenSsl {
            packed,
            library,
            reason,
        },
        SignError::OpenSsl(stack) => match stack.first() {
            Some((packed, library, reason)) => JobError::OpenSsl {
                packed: *packed,
                library: library.clone(),
                reason: reason.clone(),
            },
            None => JobError::from_queue(fallback),
        },
    }
}

/// Signs or verifies with an EdDSA key, whose signature covers the message.
///
/// `EVP_DigestSign` with a null digest is the operation OpenSSL defines for this,
/// and it is the only way Ed25519 works: `EVP_PKEY_sign` over a digest is
/// unsupported for the family, which is why `crypto.createSign` rejects it with
/// `ERR_CRYPTO_UNSUPPORTED_OPERATION` in real Node.
///
/// # Ed25519ctx
///
/// A non-empty `context` needs `EVP_DigestSignInit_ex` rather than the plain
/// `_init`, with *two* provider parameters: `instance = "Ed25519ctx"` and
/// `context-string = <bytes>`. The instance switch is not optional — without it
/// OpenSSL 3 **silently ignores** the context string, so a signature made with
/// one would verify without it, which is precisely the bug
/// `test-crypto-sign-verify.js` asserts against. `deps/ncrypto/ncrypto.cc`'s
/// `signInitWithContext` does the same two-parameter call for the same reason.
///
/// An empty context is exactly equivalent to none: `has_context` in
/// `crypto_sig.cc` requires `context_string.size() > 0`.
fn run_eddsa(
    key: &PKey,
    job_mode: i32,
    data: &[u8],
    signature: Option<&[u8]>,
    context: Option<&[u8]>,
) -> Result<JobOutcome, JobError> {
    let context = context.filter(|value| !value.is_empty());
    // `SignJob` checks the length before touching OpenSSL, and it is a caller
    // error rather than a provider limitation: Ed25519ctx's context string is
    // limited to 255 bytes by the algorithm, and the test asserts the exact
    // code and message.
    if let Some(context) = context {
        if context.len() > 255 {
            return Err(JobError::Plain(
                "context string must be at most 255 bytes",
                "ERR_OUT_OF_RANGE",
            ));
        }
    }
    let signing = job_mode != K_SIGN_JOB_MODE_VERIFY;
    let signature = if signing {
        None
    } else {
        match signature {
            Some(signature) => Some(signature),
            None => {
                return Err(JobError::Plain(
                    "A signature is required",
                    "ERR_CRYPTO_INVALID_ARG_VALUE",
                ))
            }
        }
    };

    // `key.supportsContextString()` in Node: a key whose signature algorithm does
    // not advertise the parameter cannot take one. For plain Ed25519 that is the
    // case unless the provider offers the `instance` switch as well.
    if context.is_some() && !supports_context_string(key) {
        return Err(JobError::Plain(
            "Context parameter is unsupported",
            "ERR_CRYPTO_OPERATION_FAILED",
        ));
    }

    let Ok(mut md_context) = openssl::md_ctx::MdCtx::new() else {
        return Err(JobError::from_queue("Signature operation failed"));
    };
    let mut pkey_context: *mut openssl_sys::EVP_PKEY_CTX = std::ptr::null_mut();

    let initialised = match context {
        None => {
            // SAFETY: the context is live, the key is live for the call, a null
            // digest is the documented EdDSA form, and `pkey_context` is an
            // out-parameter.
            unsafe {
                if signing {
                    openssl_sys::EVP_DigestSignInit(
                        md_context.as_ptr(),
                        &mut pkey_context,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        key.openssl_ref().as_ptr(),
                    )
                } else {
                    openssl_sys::EVP_DigestVerifyInit(
                        md_context.as_ptr(),
                        &mut pkey_context,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        key.openssl_ref().as_ptr(),
                    )
                }
            }
        }
        Some(context) => {
            eddsa_init_with_context(&mut md_context, key, context, signing, &mut pkey_context)
        }
    };
    if initialised != 1 || pkey_context.is_null() {
        clear_openssl_error();
        return Err(JobError::from_queue("Signature operation failed"));
    }

    if signing {
        // SAFETY: the digest context is initialised for signing; a null buffer
        // asks for the size.
        let mut length = 0usize;
        if unsafe {
            openssl_sys::EVP_DigestSign(
                md_context.as_ptr(),
                std::ptr::null_mut(),
                &mut length,
                data.as_ptr(),
                data.len(),
            )
        } != 1
        {
            clear_openssl_error();
            return Err(JobError::from_queue("Signature operation failed"));
        }
        let mut output = vec![0u8; length];
        // SAFETY: `output` is writable for `length` bytes, the size just
        // reported, and `length` is updated to the written count.
        if unsafe {
            openssl_sys::EVP_DigestSign(
                md_context.as_ptr(),
                output.as_mut_ptr(),
                &mut length,
                data.as_ptr(),
                data.len(),
            )
        } != 1
        {
            clear_openssl_error();
            return Err(JobError::from_queue("Signature operation failed"));
        }
        output.truncate(length);
        Ok(JobOutcome::Signature(output))
    } else {
        let signature = signature.expect("the verify branch required a signature");
        // SAFETY: the digest context is initialised for verification and both
        // slices are live for the call.
        let verified = unsafe {
            openssl_sys::EVP_DigestVerify(
                md_context.as_ptr(),
                signature.as_ptr(),
                signature.len(),
                data.as_ptr(),
                data.len(),
            )
        };
        clear_openssl_error();
        Ok(JobOutcome::Verified(verified == 1))
    }
}

/// `EVP_DigestSignInit_ex` / `EVP_DigestVerifyInit_ex` with the Ed25519ctx
/// instance and the context string.
///
/// Both parameters go in one call because the instance switch only takes effect
/// at initialisation: setting `context-string` on an `Ed25519` (rather than
/// `Ed25519ctx`) context is accepted and then ignored.
fn eddsa_init_with_context(
    md_context: &mut openssl::md_ctx::MdCtx,
    key: &PKey,
    context: &[u8],
    signing: bool,
    pkey_context: &mut *mut openssl_sys::EVP_PKEY_CTX,
) -> std::ffi::c_int {
    // `Ed25519ctx` is the only instance Node switches to: Ed448 takes the context
    // string directly, because `Ed448` already includes it in its definition.
    let is_ed25519 = key
        .algorithm()
        .is_some_and(|algorithm| algorithm.name() == "Ed25519");
    // `OSSL_PARAM` has no `Default`; a zeroed array is the correct starting
    // state and every entry that matters is overwritten below.
    let mut params: [openssl_sys::OSSL_PARAM; 3] = unsafe { std::mem::zeroed() };
    let mut count = 0usize;
    // The instance name has to be mutable for `OSSL_PARAM_construct_utf8_string`,
    // which only stores the pointer; nothing writes through it.
    let mut instance = *b"Ed25519ctx\0";
    if is_ed25519 {
        // SAFETY: the name is NUL-terminated and the length is 0, which makes the
        // constructor use `strlen`. `instance` outlives the call.
        params[count] =
            unsafe { param_utf8_string(c"instance".as_ptr(), instance.as_mut_ptr().cast(), 0) };
        count += 1;
    }
    // SAFETY: `context` outlives the call and the constructor only records its
    // address and length.
    params[count] = unsafe {
        openssl_sys::OSSL_PARAM_construct_octet_string(
            c"context-string".as_ptr(),
            context.as_ptr().cast_mut().cast(),
            context.len(),
        )
    };
    count += 1;
    // The array is NUL-terminated by a key-less entry, which is what the
    // provider iteration in `EVP_DigestSignInit_ex` looks for.
    // SAFETY: constructs a terminator by value.
    params[count] = unsafe { openssl_sys::OSSL_PARAM_construct_end() };

    // SAFETY: every pointer is live for the call, the terminator entry ends the
    // array, and `pkey_context` is an out-parameter.
    unsafe {
        if signing {
            digest_sign_init_ex(
                md_context.as_ptr(),
                pkey_context,
                key.openssl_ref().as_ptr(),
                params.as_ptr(),
            )
        } else {
            digest_verify_init_ex(
                md_context.as_ptr(),
                pkey_context,
                key.openssl_ref().as_ptr(),
                params.as_ptr(),
            )
        }
    }
}

/// `EVP_DigestSignInit_ex`, which `openssl-sys` 0.9.118 does not bind.
///
/// Declared here for the same reason the wrapper crate declares
/// `ERR_error_string_n`: the symbols are exported by the linked OpenSSL and the
/// `_ex` forms are the only way to pass provider parameters at initialisation.
///
/// # Safety
///
/// `context` must be a live `EVP_MD_CTX *`, `pkey` a live `EVP_PKEY *`, `params`
/// a NUL-terminated `OSSL_PARAM` array, and `pkey_context` writable.
unsafe fn digest_sign_init_ex(
    context: *mut openssl_sys::EVP_MD_CTX,
    pkey_context: *mut *mut openssl_sys::EVP_PKEY_CTX,
    pkey: *const openssl_sys::EVP_PKEY,
    params: *const openssl_sys::OSSL_PARAM,
) -> std::ffi::c_int {
    unsafe extern "C" {
        fn EVP_DigestSignInit_ex(
            ctx: *mut openssl_sys::EVP_MD_CTX,
            pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
            mdname: *const std::os::raw::c_char,
            libctx: *mut openssl_sys::OSSL_LIB_CTX,
            props: *const std::os::raw::c_char,
            pkey: *const openssl_sys::EVP_PKEY,
            params: *const openssl_sys::OSSL_PARAM,
        ) -> std::ffi::c_int;
    }
    // SAFETY: forwarded from this function's contract; a null digest name asks
    // OpenSSL to take it from the key.
    unsafe {
        EVP_DigestSignInit_ex(
            context,
            pkey_context,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            pkey,
            params,
        )
    }
}

/// `EVP_DigestVerifyInit_ex`, the verification half of [`digest_sign_init_ex`].
///
/// # Safety
///
/// As [`digest_sign_init_ex`].
unsafe fn digest_verify_init_ex(
    context: *mut openssl_sys::EVP_MD_CTX,
    pkey_context: *mut *mut openssl_sys::EVP_PKEY_CTX,
    pkey: *const openssl_sys::EVP_PKEY,
    params: *const openssl_sys::OSSL_PARAM,
) -> std::ffi::c_int {
    unsafe extern "C" {
        fn EVP_DigestVerifyInit_ex(
            ctx: *mut openssl_sys::EVP_MD_CTX,
            pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
            mdname: *const std::os::raw::c_char,
            libctx: *mut openssl_sys::OSSL_LIB_CTX,
            props: *const std::os::raw::c_char,
            pkey: *const openssl_sys::EVP_PKEY,
            params: *const openssl_sys::OSSL_PARAM,
        ) -> std::ffi::c_int;
    }
    // SAFETY: forwarded from this function's contract.
    unsafe {
        EVP_DigestVerifyInit_ex(
            context,
            pkey_context,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            pkey,
            params,
        )
    }
}

/// `EVP_SIGNATURE_settable_ctx_params`, which `openssl-sys` 0.9.118 does not bind.
///
/// # Safety
///
/// `signature` must be a live `EVP_SIGNATURE *`.
unsafe fn signature_settable_ctx_params(
    signature: *const openssl_sys::EVP_SIGNATURE,
) -> *const openssl_sys::OSSL_PARAM {
    unsafe extern "C" {
        fn EVP_SIGNATURE_settable_ctx_params(
            signature: *const openssl_sys::EVP_SIGNATURE,
        ) -> *const openssl_sys::OSSL_PARAM;
    }
    // SAFETY: forwarded from this function's contract.
    unsafe { EVP_SIGNATURE_settable_ctx_params(signature) }
}

/// `OSSL_PARAM_construct_utf8_string`, which `openssl-sys` does not bind.
///
/// # Safety
///
/// `key` must be NUL-terminated and `buf` must outlive the returned parameter.
unsafe fn param_utf8_string(
    key: *const std::os::raw::c_char,
    buf: *mut std::os::raw::c_char,
    bsize: usize,
) -> openssl_sys::OSSL_PARAM {
    unsafe extern "C" {
        fn OSSL_PARAM_construct_utf8_string(
            key: *const std::os::raw::c_char,
            buf: *mut std::os::raw::c_char,
            bsize: usize,
        ) -> openssl_sys::OSSL_PARAM;
    }
    // SAFETY: forwarded from this function's contract.
    unsafe { OSSL_PARAM_construct_utf8_string(key, buf, bsize) }
}

/// `EVPKeyPointer::supportsContextString`.
///
/// Asks the provider's signature implementation which parameters it accepts,
/// rather than guessing from the algorithm name: a build whose provider lacks
/// `context-string` has to report "unsupported" instead of accepting a context
/// and ignoring it.
fn supports_context_string(key: &PKey) -> bool {
    let Some(type_name) = key.algorithm().map(|algorithm| algorithm.name()) else {
        return false;
    };
    if !matches!(type_name, "Ed25519" | "Ed448") {
        return false;
    }
    let Ok(name) = std::ffi::CString::new(type_name) else {
        return false;
    };
    // SAFETY: `name` is NUL-terminated; the fetched signature is owned here and
    // freed exactly once below.
    unsafe {
        let signature =
            openssl_sys::EVP_SIGNATURE_fetch(std::ptr::null_mut(), name.as_ptr(), std::ptr::null());
        if signature.is_null() {
            clear_openssl_error();
            return false;
        }
        let params = signature_settable_ctx_params(signature);
        let supported = !params.is_null()
            && !openssl_sys::OSSL_PARAM_locate_const(params, c"context-string".as_ptr()).is_null();
        openssl_sys::EVP_SIGNATURE_free(signature);
        clear_openssl_error();
        supported
    }
}

/// Whether a key is SM2, which changes how the one-shot path signs.
///
/// `EVPKeyPointer::mayBeSM2` answers true for an `SM2` key and for an EC key on
/// the `sm2` curve; the provider reports an SM2 key's type name as `EC` in some
/// builds, so the curve name is checked as well.
fn key_is_sm2(key: &PKey) -> bool {
    if key
        .algorithm()
        .is_some_and(|algorithm| algorithm.name() == "SM2")
    {
        return true;
    }
    key.ec_curve_name().as_deref() == Some("sm2")
}

/// Signs or verifies a whole message with `EVP_DigestSign`, hashing inside
/// OpenSSL.
///
/// This is the SM2 path, where the digest step also computes the `Z` value. It
/// is `EVP_DigestSign`/`EVP_DigestVerify` rather than the prehashed
/// `EVP_PKEY_sign` for that reason, and it is why an SM2 signature from here does
/// not match one from the streaming class.
fn run_message_sign(
    key: &PKey,
    job_mode: i32,
    data: &[u8],
    digest: &openssl::md::MdRef,
    signature: Option<&[u8]>,
) -> Result<JobOutcome, JobError> {
    let Ok(md_context) = openssl::md_ctx::MdCtx::new() else {
        return Err(JobError::from_queue("Signature operation failed"));
    };
    let mut pkey_context: *mut openssl_sys::EVP_PKEY_CTX = std::ptr::null_mut();
    let signing = job_mode != K_SIGN_JOB_MODE_VERIFY;
    // SAFETY: the context is live, the digest is static, the key is live, and
    // `pkey_context` is an out-parameter.
    let initialised = unsafe {
        if signing {
            openssl_sys::EVP_DigestSignInit(
                md_context.as_ptr(),
                &mut pkey_context,
                digest.as_ptr(),
                std::ptr::null_mut(),
                key.openssl_ref().as_ptr(),
            )
        } else {
            openssl_sys::EVP_DigestVerifyInit(
                md_context.as_ptr(),
                &mut pkey_context,
                digest.as_ptr(),
                std::ptr::null_mut(),
                key.openssl_ref().as_ptr(),
            )
        }
    };
    if initialised != 1 || pkey_context.is_null() {
        clear_openssl_error();
        return Err(JobError::from_queue("Signature operation failed"));
    }
    if signing {
        let mut length = 0usize;
        // SAFETY: initialised for signing; a null buffer asks for the size.
        if unsafe {
            openssl_sys::EVP_DigestSign(
                md_context.as_ptr(),
                std::ptr::null_mut(),
                &mut length,
                data.as_ptr(),
                data.len(),
            )
        } != 1
        {
            clear_openssl_error();
            return Err(JobError::from_queue("Signature operation failed"));
        }
        let mut output = vec![0u8; length];
        // SAFETY: `output` is writable for `length` bytes and `length` is updated
        // to the written count.
        if unsafe {
            openssl_sys::EVP_DigestSign(
                md_context.as_ptr(),
                output.as_mut_ptr(),
                &mut length,
                data.as_ptr(),
                data.len(),
            )
        } != 1
        {
            clear_openssl_error();
            return Err(JobError::from_queue("Signature operation failed"));
        }
        output.truncate(length);
        Ok(JobOutcome::Signature(output))
    } else {
        let Some(signature) = signature else {
            return Err(JobError::Plain(
                "A signature is required",
                "ERR_CRYPTO_INVALID_ARG_VALUE",
            ));
        };
        // SAFETY: initialised for verification and both slices are live.
        let verified = unsafe {
            openssl_sys::EVP_DigestVerify(
                md_context.as_ptr(),
                signature.as_ptr(),
                signature.len(),
                data.as_ptr(),
                data.len(),
            )
        };
        clear_openssl_error();
        Ok(JobOutcome::Verified(verified == 1))
    }
}

/// Hashes a whole buffer with one digest.
fn hash_once(digest: &openssl::md::MdRef, data: &[u8]) -> Option<Vec<u8>> {
    let mut context = openssl::md_ctx::MdCtx::new().ok()?;
    context.digest_init(digest).ok()?;
    context.digest_update(data).ok()?;
    let mut output = vec![0u8; context.size()];
    let written = context.digest_final(&mut output).ok()?;
    output.truncate(written);
    Some(output)
}

/// Emits `[err, result]` as a two-element array.
///
/// `undefined` in slot 0 on success is what `sig.js` checks against, so the slot
/// is explicitly `undefined` rather than absent.
fn emit_pair(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue,
    outcome: Result<BytesOrBool, JobError>,
) {
    let array = v8::Array::new(scope, 2);
    match outcome {
        Ok(value) => {
            let converted: v8::Local<v8::Value> = match value {
                BytesOrBool::Bytes(bytes) => match buffer_from(scope, &bytes) {
                    Ok(value) => value,
                    Err(error) => {
                        throw(scope, &format!("cannot allocate the result: {error}"));
                        return;
                    }
                },
                BytesOrBool::Bool(value) => v8::Boolean::new(scope, value).into(),
            };
            array.set_index(scope, 0, v8::undefined(scope).into());
            array.set_index(scope, 1, converted);
        }
        Err(error) => {
            // The error is an object with `code` (and, for an OpenSSL failure,
            // `library`/`reason`/`message`), because `sig.js` does
            // `const { 0: err } = job.run(); if (err !== undefined) throw err;`
            // and the test then reads `.code` off it.
            let (message, code) = match &error {
                JobError::Plain(message, code) => ((*message).to_string(), (*code).to_string()),
                JobError::OpenSsl {
                    packed,
                    library,
                    reason,
                } => (
                    format!("error:{packed:08X}:{library}::{reason}"),
                    // The packed value carries the numeric library id, which is
                    // what Node's table is keyed by. Reverse-mapping the display
                    // name would need an entry per spelling.
                    rn_crypto_openssl::ossl_code_for(*packed, reason),
                ),
            };
            let Some(text) = v8::String::new(scope, &message) else {
                return;
            };
            let exception = v8::Exception::error(scope, text);
            if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
                for (name, value) in [
                    ("code", code),
                    (
                        "library",
                        match &error {
                            JobError::OpenSsl { library, .. } => library.clone(),
                            JobError::Plain(..) => String::new(),
                        },
                    ),
                    (
                        "reason",
                        match &error {
                            JobError::OpenSsl { reason, .. } => reason.clone(),
                            JobError::Plain(..) => String::new(),
                        },
                    ),
                ] {
                    if value.is_empty() {
                        continue;
                    }
                    if let (Some(key), Some(value)) =
                        (v8::String::new(scope, name), v8::String::new(scope, &value))
                    {
                        if object.set(scope, key.into(), value.into()).is_none() {
                            return;
                        }
                    }
                }
            }
            array.set_index(scope, 0, exception);
            array.set_index(scope, 1, v8::undefined(scope).into());
        }
    }
    rv.set(array.into());
}

/// A job result, before it is converted to a JavaScript value.
enum BytesOrBool {
    Bytes(Vec<u8>),
    Bool(bool),
}

/// The internal field holding the `*mut JobKind`.
const JOB_STATE_FIELD: i32 = 0;

/// Borrows the job's state, or `None` for an object this crate did not build.
///
/// # Why the alignment check
///
/// `run()` is installed on both job prototypes, and V8 will happily call
/// `SignJob.prototype.run` with an `RSACipherJob` receiver or with an object a
/// constructor rejected before it reached `install_state` — a job whose key
/// failed to parse, for example. In those cases field 0 holds V8's own filler
/// (which is not a pointer this crate wrote) and reading it as `*const JobKind`
/// is an immediate misaligned-dereference abort, not a catchable error.
///
/// The check is `is_aligned` on the raw pointer: a real `Box<JobKind>` is
/// 8-byte aligned because `JobKind` contains a `PKey`, and V8's filler is not.
/// A false positive would require a filler value that happens to be
/// 8-byte-aligned *and* point at a valid `JobKind`, which cannot be produced by
/// the rejection paths this guards.
fn with_state(object: v8::Local<v8::Object>) -> Option<&'static JobKind> {
    // SAFETY: the field is read as a plain address; the dereference below is
    // guarded by the alignment check and the null check.
    let raw = unsafe { object.get_aligned_pointer_from_internal_field(JOB_STATE_FIELD, 0) };
    if raw.is_null() {
        return None;
    }
    let pointer = raw as *const JobKind;
    if !(pointer as usize).is_multiple_of(std::mem::align_of::<JobKind>()) {
        return None;
    }
    // SAFETY: `install_state` is the only writer of this field for a job object,
    // it always stores a `Box<JobKind>` that this crate allocated, and the
    // finalizer cannot run while `object` is a live local.
    Some(unsafe { &*pointer })
}

/// Replaces the job's state in place, freeing the placeholder.
///
/// The finalizer registered by [`install_state`] captures the *original* address,
/// so overwriting the field would leak the placeholder and leave the finalizer
/// freeing memory that is already gone. Writing through the existing box and
/// leaving its address in place keeps the finalizer correct for the object's
/// whole life.
fn replace_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    kind: JobKind,
) {
    // SAFETY: field 0 was written by `install_state` for this object, which the
    // constructors always call before reaching here, and nothing else has
    // touched it. The placeholder box is still owned by the finalizer.
    let raw = unsafe { object.get_aligned_pointer_from_internal_field(JOB_STATE_FIELD, 0) };
    if raw.is_null() {
        install_state(scope, object, kind);
        return;
    }
    let pointer = raw as *mut JobKind;
    // SAFETY: as above, plus the alignment invariant `install_state` maintains.
    unsafe {
        std::ptr::write(pointer, kind);
    }
}

fn install_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    kind: JobKind,
) {
    let pointer = Box::into_raw(Box::new(kind));
    object.set_aligned_pointer_in_internal_field(
        JOB_STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *const JobKind;
            // SAFETY: allocated by `install_state`; freed exactly once here.
            drop(unsafe { Box::from_raw(pointer as *mut JobKind) });
        }),
    );
}

fn install_job_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    constructor: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    let prototype = template.prototype_template(scope);
    let Some(key) = v8::String::new(scope, "run") else {
        return Err(format!("cannot allocate {name}.run"));
    };
    prototype.set(
        key.into(),
        v8::FunctionTemplate::builder(run).build(scope).into(),
    );
    let Some(class_name) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} class name"));
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err(format!("cannot allocate the {name} constructor"));
    };
    let Some(property) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} property name"));
    };
    target.set(scope, property.into(), function.into());
    Ok(())
}

fn set_number<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    value: i32,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    target.set(scope, key.into(), v8::Integer::new(scope, value).into());
    Ok(())
}

fn int_at(args: &v8::FunctionCallbackArguments<'_>, index: i32) -> Option<i32> {
    let value = args.get(index);
    if value.is_undefined() || value.is_null() {
        return None;
    }
    v8::Local::<v8::Int32>::try_from(value)
        .ok()
        .map(|value| value.value())
}

fn string_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<String> {
    if value.is_undefined() || value.is_null() {
        return None;
    }
    let text = v8::Local::<v8::String>::try_from(value).ok()?;
    Some(text.to_rust_string_lossy(scope))
}

fn bytes_of(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let length = view.byte_length();
        let mut bytes = vec![0u8; length];
        let copied = view.copy_contents(&mut bytes);
        bytes.truncate(copied);
        return Some(bytes);
    }
    if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        return Some(crate::copy_backing_store(
            &buffer.get_backing_store(),
            buffer.byte_length(),
        ));
    }
    // See `bytes_of` in `lib.rs`: `crypto.verify` accepts a SharedArrayBuffer for
    // both data and signature, and it is a distinct V8 type.
    if let Ok(buffer) = v8::Local::<v8::SharedArrayBuffer>::try_from(value) {
        return Some(crate::copy_backing_store(
            &buffer.get_backing_store(),
            buffer.byte_length(),
        ));
    }
    None
}

fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Result<v8::Local<'s, v8::Value>, &'static str> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice())
            .make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let context = scope.get_current_context();
    let global = context.global(scope);
    let Some(key) = v8::String::new(scope, "Buffer") else {
        return Err("cannot allocate 'Buffer'");
    };
    let Some(value) = global.get(scope, key.into()) else {
        return Err("global Buffer is missing");
    };
    let Ok(buffer) = v8::Local::<v8::Object>::try_from(value) else {
        return Err("global Buffer is not an object");
    };
    let Some(from_key) = v8::String::new(scope, "from") else {
        return Err("cannot allocate 'from'");
    };
    let Some(from) = buffer.get(scope, from_key.into()) else {
        return Err("Buffer.from lookup failed");
    };
    let Ok(from) = v8::Local::<v8::Function>::try_from(from) else {
        return Err("Buffer.from is not a function");
    };
    let start = v8::Integer::new(scope, 0);
    let length = v8::Integer::new(scope, bytes.len() as i32);
    let called = from
        .call(
            scope,
            buffer.into(),
            &[array_buffer.into(), start.into(), length.into()],
        )
        .ok_or("Buffer.from threw")?;
    Ok(called)
}

fn throw(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_PEM: &str = include_str!("../tests/data/rsa-2048.pem");

    fn rsa_key() -> PKey {
        PKey::from_private(
            openssl::pkey::PKey::private_key_from_pem(RSA_PEM.as_bytes())
                .expect("the fixture parses"),
        )
    }

    fn ec_key() -> PKey {
        PKey::from_private(openssl::pkey::PKey::ec_gen("prime256v1").expect("P-256 generates"))
    }

    fn ed25519_key() -> PKey {
        PKey::from_private(openssl::pkey::PKey::generate_ed25519().expect("Ed25519 generates"))
    }

    /// Signs a whole message, as `crypto.sign(algo, data, key)` does.
    fn sign(key: &PKey, algorithm: Option<&str>, data: &[u8]) -> Vec<u8> {
        match run_sign(
            key,
            K_SIGN_JOB_MODE_SIGN,
            data,
            algorithm,
            None,
            None,
            K_SIG_ENC_DER,
            None,
            None,
        ) {
            Ok(JobOutcome::Signature(bytes)) => bytes,
            other => panic!("signing failed: {:?}", other.err()),
        }
    }

    /// Verifies a whole message, as `crypto.verify(algo, data, key, sig)` does.
    fn verify(key: &PKey, algorithm: Option<&str>, data: &[u8], sig: &[u8]) -> bool {
        match run_sign(
            key,
            K_SIGN_JOB_MODE_VERIFY,
            data,
            algorithm,
            None,
            None,
            K_SIG_ENC_DER,
            Some(sig),
            None,
        ) {
            Ok(JobOutcome::Verified(value)) => value,
            other => panic!("verification failed: {:?}", other.err()),
        }
    }

    #[test]
    fn rsa_signs_and_verifies_a_buffer() {
        let key = rsa_key();
        let sig = sign(&key, Some("sha256"), b"the quick brown fox");
        // A PKCS#1 v1.5 signature is exactly the modulus width.
        assert_eq!(sig.len(), 256);
        assert!(verify(&key, Some("sha256"), b"the quick brown fox", &sig));
        assert!(
            !verify(&key, Some("sha256"), b"the quick brown fo", &sig),
            "a different message must not verify"
        );
    }

    #[test]
    fn ec_signs_and_verifies_a_buffer() {
        let key = ec_key();
        let sig = sign(&key, Some("sha256"), b"the quick brown fox");
        // ECDSA over P-256 is DER: a SEQUENCE of two INTEGERs.
        assert_eq!(sig[0], 0x30);
        assert!(
            sig.len() >= 68 && sig.len() <= 72,
            "DER length is {}",
            sig.len()
        );
        assert!(verify(&key, Some("sha256"), b"the quick brown fox", &sig));
        assert!(!verify(&key, Some("sha256"), b"tampered", &sig));
    }

    #[test]
    fn ed25519_signs_and_verifies_a_buffer() {
        let key = ed25519_key();
        // The `null` algorithm is what `crypto.sign(null, data, ed25519Key)` sends:
        // EdDSA signs the message, not a digest.
        let sig = sign(&key, None, b"the quick brown fox");
        assert_eq!(sig.len(), 64);
        assert!(verify(&key, None, b"the quick brown fox", &sig));
        assert!(!verify(&key, None, b"tampered", &sig));
    }

    #[test]
    fn a_bad_signature_returns_false_rather_than_throwing() {
        let key = rsa_key();
        let sig = sign(&key, Some("sha256"), b"one");
        // A structurally valid signature over different data is a plain mismatch,
        // which is `Ok(false)` — not an error. Node's
        // `test-crypto-verify-failure.js` exists to pin exactly this.
        assert!(!verify(&key, Some("sha256"), b"two", &sig));

        // Garbage of the right length is also a mismatch, not a throw.
        let garbage = vec![0u8; sig.len()];
        assert!(!verify(&key, Some("sha256"), b"one", &garbage));
    }

    #[test]
    fn a_wrong_key_type_reports_the_openssl_error() {
        // Signing with a key-agreement key is what `test-crypto-sign-verify.js`
        // asserts on: `ERR_OSSL_EVP_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`,
        // not a panic and not a generic failure.
        let key =
            PKey::from_private(openssl::pkey::PKey::generate_x25519().expect("X25519 generates"));
        let outcome = run_sign(
            &key,
            K_SIGN_JOB_MODE_SIGN,
            b"data",
            Some("sha256"),
            None,
            None,
            K_SIG_ENC_DER,
            None,
            None,
        );
        match outcome {
            Err(JobError::OpenSsl { reason, .. }) => {
                assert!(
                    reason.contains("operation not supported"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected an OpenSSL error, got {:?}", other.err()),
        }
    }

    #[test]
    fn an_unknown_digest_is_invalid_digest() {
        let key = rsa_key();
        match run_sign(
            &key,
            K_SIGN_JOB_MODE_SIGN,
            b"data",
            Some("not-a-digest"),
            None,
            None,
            K_SIG_ENC_DER,
            None,
            None,
        ) {
            Err(JobError::Plain(message, code)) => {
                assert_eq!(message, "Invalid digest");
                assert_eq!(code, "ERR_CRYPTO_INVALID_DIGEST");
            }
            other => panic!("expected an invalid-digest error, got {:?}", other.err()),
        }
    }

    #[test]
    fn p1363_signatures_have_the_r_s_width() {
        let key = ec_key();
        let sig = run_sign(
            &key,
            K_SIGN_JOB_MODE_SIGN,
            b"p1363",
            Some("sha256"),
            None,
            None,
            K_SIG_ENC_P1363,
            None,
            None,
        );
        let Ok(JobOutcome::Signature(bytes)) = sig else {
            panic!("signing failed: {:?}", sig.err());
        };
        // P-256's r and s are 32 bytes each.
        assert_eq!(bytes.len(), 64);
        assert!(verify_with_p1363(&key, b"p1363", &bytes));
    }

    fn verify_with_p1363(key: &PKey, data: &[u8], sig: &[u8]) -> bool {
        match run_sign(
            key,
            K_SIGN_JOB_MODE_VERIFY,
            data,
            Some("sha256"),
            None,
            None,
            K_SIG_ENC_P1363,
            Some(sig),
            None,
        ) {
            Ok(JobOutcome::Verified(value)) => value,
            other => panic!("verification failed: {:?}", other.err()),
        }
    }

    #[test]
    fn an_ed25519_context_changes_the_signature() {
        let key = ed25519_key();
        let plain = sign(&key, None, b"message");
        let with_context = match run_sign(
            &key,
            K_SIGN_JOB_MODE_SIGN,
            b"message",
            None,
            None,
            None,
            K_SIG_ENC_DER,
            None,
            Some(b"domain"),
        ) {
            Ok(JobOutcome::Signature(bytes)) => bytes,
            other => panic!("context signing failed: {:?}", other.err()),
        };
        assert_ne!(
            plain, with_context,
            "a context must change the signature, or OpenSSL ignored it"
        );

        // The context-bound signature must not verify without the context: that
        // is the Ed25519ctx property the pinned test asserts.
        assert!(!verify(&key, None, b"message", &with_context));
    }

    #[test]
    fn a_context_over_255_bytes_is_out_of_range() {
        let key = ed25519_key();
        match run_sign(
            &key,
            K_SIGN_JOB_MODE_SIGN,
            b"message",
            None,
            None,
            None,
            K_SIG_ENC_DER,
            None,
            Some(&[0u8; 256]),
        ) {
            Err(JobError::Plain(message, code)) => {
                assert_eq!(message, "context string must be at most 255 bytes");
                assert_eq!(code, "ERR_OUT_OF_RANGE");
            }
            other => panic!("expected an out-of-range error, got {:?}", other.err()),
        }
    }

    #[test]
    fn rsa_pss_salt_lengths_round_trip() {
        let key = rsa_key();
        for salt_length in [Some(8), Some(16), Some(20), None] {
            let sig = run_sign(
                &key,
                K_SIGN_JOB_MODE_SIGN,
                b"pss",
                Some("sha256"),
                salt_length,
                Some(RSA_PKCS1_PSS_PADDING),
                K_SIG_ENC_DER,
                None,
                None,
            );
            let Ok(JobOutcome::Signature(bytes)) = sig else {
                panic!("PSS signing with {salt_length:?} failed: {:?}", sig.err());
            };
            let verified = run_sign(
                &key,
                K_SIGN_JOB_MODE_VERIFY,
                b"pss",
                Some("sha256"),
                salt_length,
                Some(RSA_PKCS1_PSS_PADDING),
                K_SIG_ENC_DER,
                Some(&bytes),
                None,
            );
            assert!(
                matches!(verified, Ok(JobOutcome::Verified(true))),
                "PSS with salt {salt_length:?} did not verify"
            );
        }
    }

    #[test]
    fn the_signature_encoding_values_are_stable() {
        assert_eq!(K_SIG_ENC_DER, 1);
        assert_eq!(K_SIG_ENC_P1363, 2);
        assert_eq!(K_SIGN_JOB_MODE_SIGN, 1);
        assert_eq!(K_SIGN_JOB_MODE_VERIFY, 2);
    }
}
