//! The signing and verification operations `crypto_sig.cc` and `crypto_rsa.cc`
//! build on.
//!
//! Node's `crypto_sig.cc` is a thin layer over three ncrypto primitives:
//! `EVPMDCtxPointer` (the streaming digest), `EVPKeyCtxPointer::initForSign` /
//! `initForVerify` plus `signInto` / `verify`, and `EVPKeyCtxPointer::
//! setRsaPadding` for the RSA padding and PSS salt length. This module is that
//! middle layer, so `rn-bind-crypto-sign` only has to marshal arguments and map
//! results, and the `cipher` crate can reuse `apply_rsa_options` unchanged.
//!
//! # Why the RSA padding is conditional
//!
//! `ApplyRSAOptions` in Node asks `pkey.isRsaVariant()` before touching the
//! padding, because `EVP_PKEY_CTX_set_rsa_padding` fails on a key that is not
//! RSA. Passing a padding to an EC key is not an error there, and neither is it
//! here: the call is skipped, so EC and Ed25519 signing use the same code path
//! as RSA with the option simply not applied.

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::md_ctx::MdCtx;
use openssl::pkey::{HasPublic, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::Padding;
use openssl_sys as ffi;

/// `RSA_PKCS1_PSS_PADDING`, from `openssl/rsa.h`.
pub const RSA_PKCS1_PSS_PADDING: i32 = 6;
/// `RSA_PKCS1_PADDING`.
pub const RSA_PKCS1_PADDING: i32 = 1;

/// The remaining `RSA_*_PADDING` values, kept in one table because they are an
/// internal protocol between `lib/internal/crypto/**` and this layer: the
/// JavaScript passes the number through from `constants.crypto`, so a drift here
/// would silently change the padding rather than fail.
pub const PADDINGS: &[(&str, i32)] = &[
    ("RSA_PKCS1_PADDING", RSA_PKCS1_PADDING),
    ("RSA_NO_PADDING", 3),
    ("RSA_PKCS1_OAEP_PADDING", 4),
    ("RSA_X931_PADDING", 5),
    ("RSA_PKCS1_PSS_PADDING", RSA_PKCS1_PSS_PADDING),
];

/// The padding a key signs with when the caller did not name one, which is
/// `EVPKeyPointer::getDefaultSignPadding`.
///
/// An `RSA-PSS` key defaults to PSS and every other key to PKCS#1 v1.5. That is
/// what makes `createSign('sha256').sign(pssKey)` produce a PSS signature
/// without the caller asking for one.
pub fn default_sign_padding(is_rsa_pss: bool) -> i32 {
    if is_rsa_pss {
        RSA_PKCS1_PSS_PADDING
    } else {
        RSA_PKCS1_PADDING
    }
}

/// `EVPKeyCtxPointer::setRsaPadding`: the padding and, for PSS, the salt length.
///
/// `EVP_PKEY_CTX_set_rsa_pss_saltlen` only applies to a PSS-padded context;
/// OpenSSL rejects it otherwise, which is why Node guards it with a
/// `padding == RSA_PKCS1_PSS_PADDING` check rather than setting it always. A
/// `None` salt length leaves OpenSSL's default (-2, "auto") in place.
///
/// # Why this reports a [`PaddingFailure`] instead of a bool
///
/// `openssl`'s `set_rsa_padding` returns the OpenSSL error as an `ErrorStack`,
/// which *drains* the thread-local queue. A caller that then reads the queue to
/// build the `ERR_OSSL_*` shape — which is exactly what `crypto_sig.cc` does —
/// finds it empty and reports a generic "EVP_SignFinal failed" instead of the
/// real `illegal or unsupported padding mode`. The captured stack is carried out
/// so the caller can report the true error rather than a substitute.
pub fn set_rsa_padding<C: HasPublic>(
    context: &mut PkeyCtx<C>,
    padding: i32,
    salt_length: Option<i32>,
) -> Result<(), PaddingFailure> {
    // `Padding::from_raw` accepts PSS even though there is no named constant for
    // the signature padding in older bindings.
    if let Err(stack) = context.set_rsa_padding(Padding::from_raw(padding)) {
        return Err(PaddingFailure::from_stack(&stack));
    }
    if padding == RSA_PKCS1_PSS_PADDING {
        if let Some(salt_length) = salt_length {
            // `EVP_PKEY_CTX_set_rsa_pss_saltlen` has no safe wrapper. A failure
            // here is a salt length that cannot fit the key, which Node reports
            // as a signing failure.
            // SAFETY: `context` is a live `EVP_PKEY_CTX *` owned by the caller.
            let ok =
                unsafe { ffi::EVP_PKEY_CTX_set_rsa_pss_saltlen(context.as_ptr(), salt_length) };
            if ok != 1 {
                // This call is raw, so the queue was not drained and the caller
                // reads it normally.
                return Err(PaddingFailure::Queued);
            }
        }
    }
    Ok(())
}

/// Why setting the RSA padding failed.
///
/// `Queued` means the error is still on the OpenSSL queue and the caller reads it
/// there; `Captured` means the safe wrapper already drained the queue, so the
/// detail has to travel with the failure.
pub enum PaddingFailure {
    Queued,
    Captured {
        packed: u64,
        library: String,
        reason: String,
    },
}

impl PaddingFailure {
    fn from_stack(stack: &openssl::error::ErrorStack) -> Self {
        // The first entry is the innermost cause, which is the one Node reports
        // as the `code`/`library`/`reason` triple.
        let Some(error) = stack.errors().first() else {
            return Self::Queued;
        };
        Self::Captured {
            packed: error.code(),
            library: error.library().unwrap_or_default().to_string(),
            reason: error.reason().unwrap_or_default().to_string(),
        }
    }
}

/// `ApplyRSAOptions`: the padding for RSA keys, nothing for every other family.
///
/// `is_rsa` gates the call because `EVP_PKEY_CTX_set_rsa_padding` fails with
/// `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` on a non-RSA context. Node
/// treats that as "not applicable" rather than an error, and so does this.
pub fn apply_rsa_options<C: HasPublic>(
    context: &mut PkeyCtx<C>,
    is_rsa: bool,
    padding: i32,
    salt_length: Option<i32>,
) -> Result<(), PaddingFailure> {
    if !is_rsa {
        return Ok(());
    }
    set_rsa_padding(context, padding, salt_length)
}

/// How an operation over a signature context failed.
///
/// Node's `SignBase::Error` has more variants, but the "OpenSSL refused" ones all
/// report the queued error when there is one and a fixed message otherwise, and
/// that fixed message is the caller's to choose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The digest name does not resolve: `ERR_CRYPTO_INVALID_DIGEST`.
    UnknownDigest,
    /// A method was called before `init`, or after the context was consumed:
    /// `ERR_CRYPTO_INVALID_STATE` with the message "Not initialised".
    NotInitialised,
    /// OpenSSL refused the operation. The vector is the `ERR_*` stack as
    /// `(packed code, library, reason)` triples; empty means nothing was queued
    /// and the caller uses its own fixed message.
    OpenSsl(Vec<(u64, String, String)>),
    /// A signature could not be converted between DER and `ieee-p1363`:
    /// `ERR_CRYPTO_OPERATION_FAILED` with "Malformed signature".
    MalformedSignature,
    /// Setting the RSA padding failed and the safe wrapper had already drained
    /// the OpenSSL queue, so the detail travels here instead.
    Padding {
        packed: u64,
        library: String,
        reason: String,
    },
}

impl SignError {
    /// Wraps an `ErrorStack` the `openssl` crate drained into a `SignError`.
    ///
    /// The first entry is the innermost cause and is the one Node reports as the
    /// `code`/`library`/`reason` triple.
    pub fn from_stack(stack: &openssl::error::ErrorStack) -> Self {
        let entries: Vec<(u64, String, String)> = stack
            .errors()
            .iter()
            .map(|error| {
                (
                    error.code(),
                    // The *display* name, because that is what the `library`
                    // property carries. The numeric id travels in `code()`'s high
                    // bits, so the `ERR_OSSL_*` code needs no reverse mapping.
                    error.library().unwrap_or_default().to_string(),
                    error.reason().unwrap_or_default().to_string(),
                )
            })
            .collect();
        Self::OpenSsl(entries)
    }

    /// The error a failed `apply_rsa_options` produces.
    fn from_padding(failure: PaddingFailure) -> Self {
        match failure {
            // The raw salt-length call left its error queued, so reading the
            // queue is still the right way to describe it.
            PaddingFailure::Queued => Self::OpenSsl(openssl_stack()),
            PaddingFailure::Captured {
                packed,
                library,
                reason,
            } => Self::Padding {
                packed,
                library,
                reason,
            },
        }
    }
}

/// The streaming digest a `Sign` or `Verify` handle accumulates into.
///
/// Node models the three states with a nullable `mdctx_` and returns
/// `NotInitialised` whenever it is null. The same three states are an enum here,
/// so the `sign`/`verify` call can consume the context and a second call is
/// rejected rather than reusing a finalised digest.
///
/// The digest algorithm is carried beside the context rather than read back from
/// it: `EVP_DigestFinal_ex` leaves the `EVP_MD_CTX` without a readable digest on
/// this OpenSSL, and `setSignatureMd` needs the algorithm *after* the digest has
/// been finalised. Reading it back there yields a null `EVP_MD *`, which fails
/// the sign with an empty error queue — a failure with no diagnostic at all.
pub enum SignContext {
    /// After `init`: accumulating input, not yet finalised.
    Streaming {
        context: MdCtx,
        digest: &'static openssl::md::MdRef,
    },
    /// Before `init`, or after `sign`/`verify` consumed it.
    Consumed,
}

impl SignContext {
    /// `SignBase::Init`: creates the digest context for a named digest.
    pub fn init(name: &str) -> Result<Self, SignError> {
        let Some(digest) = digest_by_name(name) else {
            return Err(SignError::UnknownDigest);
        };
        let Ok(mut context) = MdCtx::new() else {
            return Err(SignError::OpenSsl(openssl_stack()));
        };
        if context.digest_init(digest).is_err() {
            return Err(SignError::OpenSsl(openssl_stack()));
        }
        Ok(Self::Streaming { context, digest })
    }

    /// Whether `init` has run and nothing has finalised it yet.
    pub fn is_streaming(&self) -> bool {
        matches!(self, Self::Streaming { .. })
    }

    /// `SignBase::Update`.
    ///
    /// Returns `NotInitialised` for a consumed context, which is the state Node
    /// reports when `update` follows `sign`: `sig.js` does not guard that call,
    /// so a plain `sign.update()` after `sign()` has to produce an error rather
    /// than silently succeeding.
    pub fn update(&mut self, data: &[u8]) -> Result<(), SignError> {
        match self {
            Self::Streaming { context, .. } => {
                if context.digest_update(data).is_err() {
                    return Err(SignError::OpenSsl(openssl_stack()));
                }
                Ok(())
            }
            Self::Consumed => Err(SignError::NotInitialised),
        }
    }
}

/// Resolves a digest name.
///
/// Two lookups, because they cover different spellings: `Md::from_nid` on
/// `OBJ_txt2nid` resolves every name OpenSSL knows, including `"RSA-SHA256"`,
/// while `Md::fetch` covers a provider-supplied digest that has no NID. Both are
/// case-insensitive at the OpenSSL level; the `openssl` crate's wrappers are not,
/// so the name is lowercased first.
pub fn digest_by_name(name: &str) -> Option<&'static openssl::md::MdRef> {
    let lower = name.to_ascii_lowercase();
    let c_name = std::ffi::CString::new(lower.as_str()).ok()?;
    // SAFETY: `c_name` is NUL-terminated and valid for the call, and the returned
    // descriptor is a static owned by OpenSSL.
    let raw = unsafe { ffi::EVP_get_digestbyname(c_name.as_ptr()) };
    if raw.is_null() {
        clear_openssl_error();
        return None;
    }
    // SAFETY: `EVP_get_digestbyname` returns a static `EVP_MD *` that lives for
    // the process, which is exactly the lifetime `MdRef::from_ptr` requires.
    Some(unsafe { openssl::md::MdRef::from_ptr(raw as *mut _) })
}

/// `Node_SignFinal`: finalises the accumulated digest and signs it with `key`.
///
/// Returns the signature bytes. For ECDSA and DSA those are DER at this point;
/// the `ieee-p1363` conversion is the caller's job because it needs the
/// signature-encoding argument.
///
/// # Why the digest is finalised first
///
/// Node's `Node_SignFinal` runs `mdctx.digestFinal()` and then signs the raw
/// digest with `EVP_PKEY_sign`, having recorded the digest algorithm on the key
/// context through `setSignatureMd`. That ordering is not an optimisation: the
/// digest algorithm has to be named on the *signing* context for an RSA PKCS#1
/// signature to carry its DigestInfo wrapper and for PSS to know its salt size,
/// and OpenSSL rejects `EVP_PKEY_CTX_set_signature_md` once a key context has
/// already completed an operation. Hashing first and signing the digest is
/// therefore the only order that works, and `test-crypto-sign-verify.js`
/// verifies the result against a signature produced by real `node`.
///
/// The output buffer is sized from `EVP_PKEY_size` and truncated to the written
/// length, which is what Node does: an RSA signature is exactly the key size,
/// while an ECDSA one is shorter than that worst case.
pub fn sign_final(
    context: SignContext,
    key: &openssl::pkey::PKeyRef<Private>,
    is_rsa: bool,
    padding: i32,
    salt_length: Option<i32>,
) -> Result<Vec<u8>, SignError> {
    let SignContext::Streaming {
        mut context,
        digest: md,
    } = context
    else {
        return Err(SignError::NotInitialised);
    };
    let digest = finalise_digest(&mut context)?;
    sign_digest(key, &digest, md, is_rsa, padding, salt_length)
}

/// Signs an already-computed digest, which is the second half of
/// [`sign_final`].
///
/// Split out so the one-shot `SignJob` path, which hashes a whole buffer and then
/// signs it, shares the exact same signing code rather than a near-copy.
pub fn sign_digest(
    key: &openssl::pkey::PKeyRef<Private>,
    digest: &[u8],
    md: &openssl::md::MdRef,
    is_rsa: bool,
    padding: i32,
    salt_length: Option<i32>,
) -> Result<Vec<u8>, SignError> {
    let mut pkey_context = match PkeyCtx::new(key) {
        Ok(context) => context,
        Err(stack) => return Err(SignError::from_stack(&stack)),
    };
    if let Err(stack) = pkey_context.sign_init() {
        return Err(SignError::from_stack(&stack));
    }
    if let Err(failure) = apply_rsa_options(&mut pkey_context, is_rsa, padding, salt_length) {
        return Err(SignError::from_padding(failure));
    }
    if !set_signature_md(&mut pkey_context, md) {
        return Err(SignError::OpenSsl(openssl_stack()));
    }
    let mut output = vec![0u8; key.size()];
    // `PkeyCtx::sign` returns the OpenSSL error as an `ErrorStack`, which drains
    // the thread-local queue. Re-reading the queue on failure therefore finds
    // nothing and reports a generic signing failure, where the real reason —
    // `RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY`, a restricted PSS key's
    // `digest not allowed` — is in the stack that was returned. It is captured
    // here so the caller can report the true error.
    let written = match pkey_context.sign(digest, Some(&mut output)) {
        Ok(written) => written,
        Err(stack) => return Err(SignError::from_stack(&stack)),
    };
    output.truncate(written);
    Ok(output)
}

/// `Verify::VerifyFinal`: finalises the accumulated digest and checks `signature`.
///
/// A signature that does not match is `Ok(false)`, not an error: Node assigns
/// `pkctx.verify`'s result and only an initialisation failure is an error. That
/// distinction is what `test-crypto-verify-failure.js` exists to pin.
pub fn verify_final(
    context: SignContext,
    key: &openssl::pkey::PKeyRef<impl HasPublic>,
    signature: &[u8],
    is_rsa: bool,
    padding: i32,
    salt_length: Option<i32>,
) -> Result<bool, SignError> {
    let SignContext::Streaming {
        mut context,
        digest: md,
    } = context
    else {
        return Err(SignError::NotInitialised);
    };
    let digest = finalise_digest(&mut context)?;
    verify_digest(key, &digest, md, signature, is_rsa, padding, salt_length)
}

/// Verifies a signature over an already-computed digest.
///
/// Returns `Ok(false)` for a plain mismatch. A mismatch makes OpenSSL queue an
/// error, which is cleared here: leaving it would make the *next* operation
/// report a spurious OpenSSL failure, and `crypto_sig.cc` wraps its verify calls
/// in `ClearErrorOnReturn` for the same reason.
pub fn verify_digest(
    key: &openssl::pkey::PKeyRef<impl HasPublic>,
    digest: &[u8],
    md: &openssl::md::MdRef,
    signature: &[u8],
    is_rsa: bool,
    padding: i32,
    salt_length: Option<i32>,
) -> Result<bool, SignError> {
    let mut pkey_context = match PkeyCtx::new(key) {
        Ok(context) => context,
        Err(stack) => return Err(SignError::from_stack(&stack)),
    };
    if let Err(stack) = pkey_context.verify_init() {
        return Err(SignError::from_stack(&stack));
    }
    if let Err(failure) = apply_rsa_options(&mut pkey_context, is_rsa, padding, salt_length) {
        return Err(SignError::from_padding(failure));
    }
    if !set_signature_md(&mut pkey_context, md) {
        return Err(SignError::OpenSsl(openssl_stack()));
    }
    // `PkeyCtx::verify` is `verify(data, signature)` — data first, unlike the raw
    // `EVP_PKEY_verify(ctx, sig, siglen, data, datalen)`. Passing the digest as
    // the signature makes OpenSSL report "wrong signature length".
    let verified = pkey_context.verify(digest, signature).unwrap_or(false);
    clear_openssl_error();
    Ok(verified)
}

/// `mdctx.digestFinal(mdctx.getExpectedSize())`.
fn finalise_digest(context: &mut MdCtx) -> Result<Vec<u8>, SignError> {
    let size = context.size();
    let mut digest = vec![0u8; size];
    let written = context
        .digest_final(&mut digest)
        .map_err(|_| SignError::OpenSsl(openssl_stack()))?;
    digest.truncate(written);
    Ok(digest)
}

/// `pkctx.setSignatureMd(mdctx)`: records the digest algorithm on the key context.
///
/// `EVP_PKEY_CTX_set_signature_md` has no safe wrapper. It ties the signature to
/// the digest that produced the input: without it an RSA PKCS#1 signature omits
/// the DigestInfo wrapper and verifies against nothing, and a PSS signature has
/// no salt size.
fn set_signature_md<C: HasPublic>(context: &mut PkeyCtx<C>, digest: &openssl::md::MdRef) -> bool {
    // SAFETY: both pointers are live and owned by the caller for the duration of
    // the call; `EVP_PKEY_CTX_set_signature_md` only reads the digest.
    unsafe { ffi::EVP_PKEY_CTX_set_signature_md(context.as_ptr(), digest.as_ptr()) == 1 }
}

/// The bytes of each of `r` and `s` in a DSA-family signature, which is
/// `EVPKeyPointer::getBytesOfRS`.
///
/// `None` for a key whose signature is not DSA-shaped — RSA and EdDSA — which is
/// the `kNoDsaSignature` case Node short-circuits on before any conversion.
///
/// # Why DSA reads `q` and not the group
///
/// The two families size `r`/`s` differently: an ECDSA signature's integers are
/// bounded by the curve's *order*, while a DSA signature's are bounded by `q`,
/// the subgroup prime. Reading the group order for a DSA key gives the size of
/// `p` — 1024 bits for `dsa_private_1025.pem`, so 128 bytes instead of 20 — and
/// `crypto.sign(..., {dsaEncoding: 'ieee-p1363'})` then emits a signature twice
/// the documented length. `test-crypto-sign-verify.js` asserts the exact length,
/// which is how this surfaced.
pub fn bytes_of_rs(key: &openssl::pkey::PKeyRef<impl HasPublic>) -> Option<usize> {
    if let Ok(ec) = key.ec_key() {
        let order_bits = ec.group().order_bits();
        return Some(order_bits.div_ceil(8) as usize);
    }
    // `EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_FFC_Q)` is the `q` of a DSA
    // key; the classic `dsa().q()` accessor covers the same key through the
    // deprecated-but-present DSA type.
    let dsa = key.dsa().ok()?;
    Some((dsa.q().num_bits() as usize).div_ceil(8))
}

/// `ncrypto::extractP1363`: DER-encoded `(r, s)` to fixed-width `r || s`.
///
/// `None` when the input is not a well-formed ECDSA signature or an integer does
/// not fit `width`, which the caller reports as a malformed signature.
pub fn signature_to_p1363(signature: &[u8], width: usize) -> Option<Vec<u8>> {
    use openssl::ecdsa::EcdsaSig;
    let parsed = EcdsaSig::from_der(signature).ok()?;
    let r = parsed.r().to_vec_padded(width as i32).ok()?;
    let s = parsed.s().to_vec_padded(width as i32).ok()?;
    let mut output = vec![0u8; width * 2];
    output[..width].copy_from_slice(&r);
    output[width..].copy_from_slice(&s);
    Some(output)
}

/// `ConvertSignatureToDER`: fixed-width `r || s` back to a DER signature.
///
/// `None` when the input is not exactly two `width`-byte integers, which is what
/// Node rejects before attempting the ASN.1 encode.
pub fn signature_from_p1363(signature: &[u8], width: usize) -> Option<Vec<u8>> {
    use openssl::bn::BigNum;
    use openssl::ecdsa::EcdsaSig;
    if signature.len() != width * 2 {
        return None;
    }
    let r = BigNum::from_slice(&signature[..width]).ok()?;
    let s = BigNum::from_slice(&signature[width..]).ok()?;
    EcdsaSig::from_private_components(r, s).ok()?.to_der().ok()
}

/// The `ERR_*` stack as `(packed code, library, reason)` triples.
pub fn openssl_stack() -> Vec<(u64, String, String)> {
    let mut entries = Vec::new();
    loop {
        // SAFETY: `ERR_get_error` pops from the thread-local queue and returns 0
        // when it is empty, which terminates the loop.
        let code = unsafe { ffi::ERR_get_error() };
        if code == 0 {
            break;
        }
        entries.push(decode_error(code));
    }
    entries
}

/// Empties the thread-local error queue.
pub fn clear_openssl_error() {
    // SAFETY: thread-local queue only.
    unsafe { ffi::ERR_clear_error() };
}

/// Decodes one packed `ERR_*` value into its display parts.
///
/// The library and reason come from `ERR_lib_error_string` /
/// `ERR_reason_error_string` rather than by splitting the formatted message: the
/// formatted text is `error:<code>:<library> routines::<reason>`, and the
/// library there is a *display name* (`rsa`) whose upper-cased form is what
/// `ERR_OSSL_RSA_...` needs, while the reason needs its spaces replaced.
fn decode_error(code: u64) -> (u64, String, String) {
    // SAFETY: both lookups read a static table the process owns and return a
    // pointer into it that outlives every caller.
    let (library, reason) = unsafe {
        (
            error_string(ffi::ERR_lib_error_string(code)),
            error_string(ffi::ERR_reason_error_string(code)),
        )
    };
    (code, library, reason)
}

/// Reads a `*const c_char` from the error table, or an empty string.
fn error_string(pointer: *const std::os::raw::c_char) -> String {
    if pointer.is_null() {
        return String::new();
    }
    // SAFETY: the error-table strings are static and NUL-terminated for the life
    // of the process.
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

/// Converts an RSA padding value to the `openssl` enum.
pub fn padding_from_raw(value: i32) -> Padding {
    Padding::from_raw(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::PKey as OpenSslPKey;

    const RSA_PEM: &str = include_str!("../tests/data/rsa-2048.pem");

    fn rsa_key() -> OpenSslPKey<Private> {
        OpenSslPKey::private_key_from_pem(RSA_PEM.as_bytes()).expect("the fixture parses")
    }

    fn sign_with(key: &OpenSslPKey<Private>, is_rsa: bool, data: &[u8]) -> Vec<u8> {
        let mut context = SignContext::init("sha256").expect("sha256 resolves");
        context.update(data).expect("the update succeeds");
        sign_final(context, key, is_rsa, RSA_PKCS1_PADDING, None).expect("signing succeeds")
    }

    fn verify_with(key: &OpenSslPKey<Private>, is_rsa: bool, data: &[u8], sig: &[u8]) -> bool {
        let mut context = SignContext::init("sha256").expect("sha256 resolves");
        context.update(data).expect("the update succeeds");
        verify_final(context, key, sig, is_rsa, RSA_PKCS1_PADDING, None).expect("verify runs")
    }

    #[test]
    fn rsa_sign_and_verify_round_trip() {
        let key = rsa_key();
        let sig = sign_with(&key, true, b"hello world");
        // An RSA-2048 signature is exactly the modulus width.
        assert_eq!(sig.len(), 256);
        assert!(verify_with(&key, true, b"hello world", &sig));
        assert!(!verify_with(&key, true, b"hello worlds", &sig));
    }

    #[test]
    fn ec_sign_and_verify_round_trip() {
        let key = OpenSslPKey::ec_gen("prime256v1").expect("P-256 generates");
        let sig = sign_with(&key, false, b"hello world");
        assert!(!sig.is_empty());
        // ECDSA signatures are DER: a SEQUENCE of two INTEGERs.
        assert_eq!(sig[0], 0x30);
        assert!(verify_with(&key, false, b"hello world", &sig));
        assert!(!verify_with(&key, false, b"tampered", &sig));
    }

    #[test]
    fn ed25519_sign_and_verify_round_trip() {
        let key = OpenSslPKey::generate_ed25519().expect("Ed25519 generates");
        // Ed25519 is a one-shot algorithm: `EVP_DigestSign` with a digest is not
        // supported, so this uses the raw signer rather than the digest path.
        use openssl::sign::{Signer, Verifier};
        let mut signer = Signer::new_without_digest(&key).expect("a signer");
        let sig = signer.sign_oneshot_to_vec(b"hello world").expect("signs");
        assert_eq!(sig.len(), 64);
        let mut verifier = Verifier::new_without_digest(&key).expect("a verifier");
        assert!(verifier
            .verify_oneshot(&sig, b"hello world")
            .expect("verify runs"));
        let mut tampered = Verifier::new_without_digest(&key).expect("a verifier");
        assert!(!tampered
            .verify_oneshot(&sig, b"tampered")
            .expect("verify runs"));
    }

    #[test]
    fn a_pss_signature_uses_the_salt_length() {
        let key = rsa_key();
        let mut context = SignContext::init("sha256").expect("sha256 resolves");
        context.update(b"pss").expect("update");
        let sig = sign_final(
            context,
            &key,
            true,
            RSA_PKCS1_PSS_PADDING,
            // -1 is RSA_PSS_SALTLEN_DIGEST.
            Some(-1),
        )
        .expect("PSS signs");
        assert_eq!(sig.len(), 256);

        let mut verify = SignContext::init("sha256").expect("resolves");
        verify.update(b"pss").expect("update");
        assert!(
            verify_final(verify, &key, &sig, true, RSA_PKCS1_PSS_PADDING, Some(-1))
                .expect("PSS verifies")
        );
    }

    #[test]
    fn a_consumed_context_reports_not_initialised() {
        let mut context = SignContext::init("sha256").expect("resolves");
        context.update(b"data").expect("update");
        let key = rsa_key();
        let _ = sign_final(context, &key, true, RSA_PKCS1_PADDING, None).expect("signs");
        // The state is consumed by `sign_final`, so a second update cannot work.
        let mut fresh = SignContext::init("sha256").expect("resolves");
        fresh.update(b"data").expect("update");
        let _ = sign_final(fresh, &key, true, RSA_PKCS1_PADDING, None).expect("signs");
        assert!(matches!(
            SignContext::Consumed.update(b"x"),
            Err(SignError::NotInitialised)
        ));
    }

    #[test]
    fn an_unknown_digest_is_rejected() {
        assert!(matches!(
            SignContext::init("not-a-real-digest"),
            Err(SignError::UnknownDigest)
        ));
    }

    #[test]
    fn digest_lookup_is_case_insensitive() {
        for name in ["sha256", "SHA256", "Sha256"] {
            assert!(digest_by_name(name).is_some(), "{name} resolves");
        }
        assert!(digest_by_name("nope-nope").is_none());
    }

    #[test]
    fn the_default_padding_follows_the_key_variant() {
        assert_eq!(default_sign_padding(false), RSA_PKCS1_PADDING);
        assert_eq!(default_sign_padding(true), RSA_PKCS1_PSS_PADDING);
    }

    #[test]
    fn p1363_conversion_round_trips_for_ec() {
        let key = OpenSslPKey::ec_gen("prime256v1").expect("P-256 generates");
        let sig = sign_with(&key, false, b"p1363");
        let width = bytes_of_rs(&key).expect("P-256 has a known r/s width");
        assert_eq!(width, 32);
        let p1363 = signature_to_p1363(&sig, width).expect("converts");
        assert_eq!(p1363.len(), 64);
        let back = signature_from_p1363(&p1363, width).expect("converts back");
        assert!(verify_with(&key, false, b"p1363", &back));
    }

    #[test]
    fn p1363_rejects_the_wrong_width() {
        let key = OpenSslPKey::ec_gen("prime256v1").expect("P-256 generates");
        let width = bytes_of_rs(&key).expect("a width");
        assert!(signature_from_p1363(&[0u8; 63], width).is_none());
    }

    #[test]
    fn rsa_and_ed25519_have_no_dsa_signature_width() {
        assert!(bytes_of_rs(&rsa_key()).is_none());
        let ed = OpenSslPKey::generate_ed25519().expect("generates");
        assert!(bytes_of_rs(&ed).is_none());
    }

    #[test]
    fn the_padding_values_match_openssl() {
        // These are the numbers `lib/internal/crypto/sig.js` forwards from
        // `constants.crypto`; a drift changes the padding silently.
        for (name, value) in PADDINGS {
            assert!(*value > 0, "{name} has a positive value");
        }
        assert_eq!(RSA_PKCS1_PADDING, 1);
        assert_eq!(RSA_PKCS1_PSS_PADDING, 6);
    }
}
