//! The cryptography itself, with no V8 types in sight.
//!
//! Everything here is a thin layer over OpenSSL. Where Node's `src/crypto/*.cc`
//! calls `EVP_DigestInit_ex`, `HMAC_Init_ex`, `RAND_bytes` and friends, these
//! functions call the same OpenSSL entry points through the `openssl` crate. That
//! is the point: the algorithm is OpenSSL's in both runtimes, so a digest cannot
//! disagree with Node's except through a bug in the glue.
//!
//! Keeping this module free of V8 means the test suite can compare it against
//! published vectors and against a real `node` binary without building an
//! isolate, and the binding layer above it is left with argument marshalling
//! only.

use openssl::hash::MessageDigest;
use openssl::symm::Cipher;

/// Why a cryptographic operation failed.
///
/// The binding layer maps these onto the JavaScript error Node throws. They are
/// distinct because `lib/crypto` reports them differently: an unknown algorithm
/// is `ERR_CRYPTO_INVALID_DIGEST` while a failed verify is a plain `false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The algorithm name is not one this OpenSSL knows.
    ///
    /// `api` names the surface that rejected it, because Node does not report
    /// every digest failure the same way: `createHash('nope')` throws an uncoded
    /// `Error` with "Digest method not supported", while `createHmac` and the
    /// KDFs throw a `TypeError` carrying `ERR_CRYPTO_INVALID_DIGEST` and
    /// "Invalid digest: nope". `crypto_hash.cc:899` is the uncoded one.
    UnknownAlgorithm {
        /// The digest name the caller asked for.
        name: String,
        /// Which entry point rejected it.
        api: DigestApi,
    },
    /// A key or parameter had the wrong shape or length.
    InvalidKey(String),
    /// A length, offset or option was outside what the operation accepts.
    InvalidArgument(String),
    /// A requested output length a digest's XOF cannot produce.
    ///
    /// `ERR_CRYPTO_INVALID_KEYLEN`: Node raises it from `crypto_hkdf.cc` when the
    /// length exceeds 255 blocks of the digest, and from `crypto_hash.cc` when a
    /// fixed-length digest is asked for a different length.
    InvalidKeyLength,
    /// `crypto.timingSafeEqual` compared buffers of different lengths.
    ///
    /// `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH`, a `RangeError`.
    TimingSafeEqualLength,
    /// The HKDF job reported a failure the parameters did not explain.
    ///
    /// Node's `HKDF_FAILED` is a bare, uncoded `Error` with "HKDF derivation
    /// failed", which is what a zero-length derivation produces.
    HkdfFailed,
    /// OpenSSL itself reported a failure.
    OpenSsl(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAlgorithm { name, .. } => write!(formatter, "unknown algorithm: {name}"),
            Self::InvalidKey(message) => write!(formatter, "invalid key: {message}"),
            Self::InvalidArgument(message) => write!(formatter, "invalid argument: {message}"),
            Self::InvalidKeyLength => write!(formatter, "Invalid key length"),
            Self::TimingSafeEqualLength => {
                write!(formatter, "Input buffers must have the same byte length")
            }
            Self::HkdfFailed => write!(formatter, "HKDF derivation failed"),
            Self::OpenSsl(message) => write!(formatter, "openssl: {message}"),
        }
    }
}

impl CryptoError {
    /// A digest name this OpenSSL cannot resolve, rejected by `api`.
    fn unknown_digest(name: &str, api: DigestApi) -> Self {
        Self::UnknownAlgorithm {
            name: name.to_string(),
            api,
        }
    }
}

/// Which entry point rejected a digest name.
///
/// The distinction is not cosmetic: Node's message, error class and `code` all
/// differ between them, and a library that catches `ERR_CRYPTO_INVALID_DIGEST`
/// takes a different path when the error has no code at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestApi {
    /// `new Hash(...)`, whose C++ site (`crypto_hash.cc:899`) throws a plain
    /// `Error` with "Digest method not supported" and no `code`.
    HashConstructor,
    /// `Hmac.prototype.init`, `crypto_hkdf.cc`, `crypto_pbkdf2.cc` and the hash
    /// job, which all throw `ERR_CRYPTO_INVALID_DIGEST`, a `TypeError`, with
    /// "Invalid digest: <name>".
    DigestConsumer,
}

impl std::error::Error for CryptoError {}

/// `EVP_MD_FLAG_XOF` from `openssl/evp.h`: the digest is an extendable-output
/// function, so it finalises with `EVP_DigestFinalXOF` to a caller-chosen length.
const EVP_MD_FLAG_XOF: std::os::raw::c_ulong = 0x0002;

/// Runs `body` and turns an OpenSSL error stack into [`CryptoError::OpenSsl`].
/// Narrows a byte length to the `c_int` OpenSSL's `HMAC_Init_ex` expects.
///
/// A key longer than `i32::MAX` cannot be expressed, and OpenSSL would read the
/// length as negative; refusing is better than hashing the wrong number of bytes.
fn c_int_len(length: usize) -> Result<std::os::raw::c_int, CryptoError> {
    std::os::raw::c_int::try_from(length).map_err(|_| {
        CryptoError::InvalidKey(format!("key length {length} exceeds the OpenSSL limit"))
    })
}

fn openssl_error() -> CryptoError {
    let errors = openssl::error::ErrorStack::get();
    CryptoError::OpenSsl(errors.to_string())
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/// An incremental digest.
///
/// Built directly on `EVP_MD_CTX` rather than `openssl::hash::Hasher`, for three
/// reasons that are all observable through `lib/internal/crypto/hash.js`:
///
/// 1. **Copy.** `Hash.prototype.copy` is `new Hash(existingHandle, options)`, and
///    a copy continues from the same state. `Hasher` cannot be copied through the
///    safe API, and rebuilding from the algorithm name would restart from empty —
///    a silently wrong digest. `EVP_MD_CTX_copy_ex` is the operation Node's
///    `Hash::Copy` performs.
/// 2. **Extendable output.** `shake128`/`shake256` are advertised by
///    `getHashes()` and finalise with `EVP_DigestFinalXOF` to `outputLength` bytes
///    (16 and 32 by default, as `node` reports). `Hasher::finish` cannot express
///    that.
/// 3. **Finalising twice.** `Hasher::finish` silently re-initialises a finalised
///    context and starts over, which would make a second `digest()` return the
///    digest of the empty string instead of failing.
pub struct Digest {
    /// The OpenSSL context, freed by `Drop`.
    context: *mut openssl_sys::EVP_MD_CTX,
    /// The canonical short name, for diagnostics and `copy`.
    name: String,
    /// The fixed digest length, or the requested output length for an XOF.
    output_len: usize,
    /// Whether the algorithm is an extendable-output function.
    is_xof: bool,
}

// SAFETY: an `EVP_MD_CTX` is a plain OpenSSL heap object with no thread
// affinity. It is only reachable through this struct, which is moved between
// threads rather than shared, so `Send` is sound. It is deliberately not `Sync`.
unsafe impl Send for Digest {}

impl Digest {
    /// Starts a digest.
    ///
    /// `name` goes through OpenSSL's own lookup rather than a table here, so a
    /// name OpenSSL accepts works and one it does not is rejected with the same
    /// authority Node would use. `lib/internal/crypto/hashnames.js` already
    /// normalises the common aliases before this point.
    pub fn new(name: &str) -> Result<Self, CryptoError> {
        Self::new_with_output_length(name, None)
    }

    /// Starts a digest, with an explicit output length for the XOF algorithms.
    ///
    /// A fixed-length digest ignores the request, which is what
    /// `crypto.createHash('sha256', { outputLength: 8 })` does in Node: the option
    /// only applies to the extendable-output digests.
    pub fn new_with_output_length(name: &str, requested: Option<u32>) -> Result<Self, CryptoError> {
        Self::new_with_output_length_for(name, requested, DigestApi::HashConstructor)
    }

    /// Starts a digest, reporting a rejection the way `api` reports it.
    ///
    /// The resolver is `enumerate::resolve_digest`, which follows Node's
    /// `ncrypto::Digest::FromName`: the legacy table first, then a provider
    /// fetch. The provider half is what makes `keccak-256` and `sha2-256/192`
    /// work here — they appear in `getHashes()` and are absent from the legacy
    /// table, so a legacy-only lookup would advertise names it cannot start.
    pub fn new_with_output_length_for(
        name: &str,
        requested: Option<u32>,
        api: DigestApi,
    ) -> Result<Self, CryptoError> {
        let digest = crate::enumerate::resolve_digest(name)
            .ok_or_else(|| CryptoError::unknown_digest(name, api))?;
        // SAFETY: `EVP_MD_CTX_new` returns a valid context or null, checked below.
        let context = unsafe { openssl_sys::EVP_MD_CTX_new() };
        if context.is_null() {
            return Err(CryptoError::OpenSsl(
                "cannot allocate a digest context".to_string(),
            ));
        }
        // SAFETY: `context` was just allocated and is owned by this struct. The
        // digest pointer belongs to `digest`, which outlives this call, and a null
        // engine is the documented "use the default implementation" argument.
        let initialised = unsafe {
            openssl_sys::EVP_DigestInit_ex(context, digest.as_ptr().cast(), std::ptr::null_mut())
        };
        if initialised != 1 {
            // SAFETY: the allocation above is not owned by a live `Digest` yet.
            unsafe { openssl_sys::EVP_MD_CTX_free(context) };
            return Err(CryptoError::OpenSsl(format!(
                "cannot initialise the {name} digest"
            )));
        }

        // `EVP_MD_FLAG_XOF` is the only reliable test. A SHAKE reports a non-zero
        // `size()` (16 and 32, its default output lengths), so testing for a zero
        // size — which is the obvious-looking rule — misses every XOF.
        //
        // `digest.as_ptr()` is the `EVP_MD` the source owns;
        // `digest_flags` documents its own safety contract.
        let flags = crate::enumerate::digest_flags(digest.as_ptr().cast());
        let is_xof = flags & EVP_MD_FLAG_XOF != 0;
        // SAFETY: the digest pointer is live and belongs to `digest`; the raw size
        // accessor only reads it.
        let size = unsafe { openssl_sys::EVP_MD_get_size(digest.as_ptr().cast()) };
        // A negative size is OpenSSL's "unknown"; `EVP_MD_size` reports it for a
        // descriptor it cannot measure. Treat it as zero rather than wrapping.
        let fixed_len = usize::try_from(size).unwrap_or(0);
        // `crypto.createHash('shake128')` defaults to 16 bytes and
        // `createHash('shake256')` to 32, which are exactly what `node` reports;
        // `fixed_len` is already those values, so the explicit request is the only
        // override.
        let output_len = if is_xof {
            requested.map_or(fixed_len, |length| length as usize)
        } else {
            fixed_len
        };

        let canonical = digest.resolution_name().to_string();
        Ok(Self {
            context,
            name: canonical,
            output_len,
            is_xof,
        })
    }

    /// The canonical short name, for `Hash`'s diagnostic surface.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The digest length in bytes.
    pub fn output_len(&self) -> usize {
        self.output_len
    }

    /// Whether this is an extendable-output function.
    pub fn is_xof(&self) -> bool {
        self.is_xof
    }

    /// Feeds bytes in.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        // SAFETY: `self.context` is live and owned here. A zero-length update with
        // a dangling `data.as_ptr()` is documented to be a no-op.
        let updated = unsafe {
            openssl_sys::EVP_DigestUpdate(self.context, data.as_ptr().cast(), data.len())
        };
        if updated != 1 {
            return Err(CryptoError::OpenSsl("digest update failed".to_string()));
        }
        Ok(())
    }

    /// Finalises and returns the digest.
    ///
    /// The context is reset afterwards, so a second call cannot silently produce
    /// the digest of the empty input the way `Hasher::finish` would.
    pub fn finish(mut self) -> Result<Vec<u8>, CryptoError> {
        self.finalise()
    }

    /// Finalises without consuming, leaving the context unusable.
    pub fn finish_bytes(&mut self) -> Result<Vec<u8>, CryptoError> {
        self.finalise()
    }

    /// Runs the finaliser once.
    fn finalise(&mut self) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; self.output_len];
        if self.is_xof {
            // SAFETY: `self.context` is live and `out` has room for exactly
            // `output_len` bytes, which is what `EVP_DigestFinalXOF` is told.
            let finished = unsafe {
                openssl_sys::EVP_DigestFinalXOF(self.context, out.as_mut_ptr(), out.len())
            };
            if finished != 1 {
                return Err(CryptoError::OpenSsl("XOF finalisation failed".to_string()));
            }
        } else {
            let mut length: std::os::raw::c_uint = 0;
            // SAFETY: `out` is exactly `output_len` bytes, which is the digest
            // size for a fixed-length algorithm.
            let finished = unsafe {
                openssl_sys::EVP_DigestFinal_ex(self.context, out.as_mut_ptr(), &mut length)
            };
            if finished != 1 {
                return Err(CryptoError::OpenSsl(
                    "digest finalisation failed".to_string(),
                ));
            }
            out.truncate(length as usize);
        }
        // Mark the context unusable rather than letting a second finalise read a
        // reset state. `EVP_MD_CTX_reset` is what `Hash::Digest`'s cleanup does.
        // SAFETY: `self.context` is live and owned here.
        unsafe { openssl_sys::EVP_MD_CTX_reset(self.context) };
        Ok(out)
    }

    /// Copies the in-progress state, which is `Hasher::copy`'s missing operation
    /// and what `Hash.prototype.copy` relies on.
    pub fn try_clone(&self) -> Result<Self, CryptoError> {
        // SAFETY: `EVP_MD_CTX_new` returns a valid context or null.
        let context = unsafe { openssl_sys::EVP_MD_CTX_new() };
        if context.is_null() {
            return Err(CryptoError::OpenSsl(
                "cannot allocate a digest context".to_string(),
            ));
        }
        // SAFETY: both contexts are live; `src` is only read, and `dst` is empty so
        // there is nothing to free first.
        let copied = unsafe { openssl_sys::EVP_MD_CTX_copy_ex(context, self.context) };
        if copied != 1 {
            // SAFETY: the allocation is not owned by a live `Digest` yet.
            unsafe { openssl_sys::EVP_MD_CTX_free(context) };
            return Err(CryptoError::OpenSsl(
                "cannot copy the digest context".to_string(),
            ));
        }
        Ok(Self {
            context,
            name: self.name.clone(),
            output_len: self.output_len,
            is_xof: self.is_xof,
        })
    }
}

impl Drop for Digest {
    fn drop(&mut self) {
        if !self.context.is_null() {
            // SAFETY: `context` came from `EVP_MD_CTX_new` and is freed exactly
            // once, here.
            unsafe { openssl_sys::EVP_MD_CTX_free(self.context) };
            self.context = std::ptr::null_mut();
        }
    }
}

/// Hashes `data` in one call, which is what `crypto.hash()` and WebCrypto's
/// one-shot digest both need.
pub fn digest_once(name: &str, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut digest = Digest::new(name)?;
    digest.update(data)?;
    digest.finish()
}

/// Every digest OpenSSL can produce, for `getHashes()`.
///
/// Derived from OpenSSL rather than hardcoded: the requirement is that an
/// enumeration cannot advertise an algorithm that then fails. The walker asks
/// OpenSSL for its registered digests and keeps the ones that actually produce a
/// digest object with a usable name.
///
/// The names are lowercased because that is what `lib/internal/crypto/util.js`
/// compares against and what `getHashes()` returns in Node.
pub fn hash_algorithms() -> Vec<String> {
    let mut names = crate::enumerate::digest_names();
    names.sort();
    names.dedup();
    names
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

/// An incremental HMAC.
///
/// Built on OpenSSL's `HMAC_CTX` rather than `PKey::hmac` + `Signer`, because
/// `PKey::hmac` rejects an empty key and `crypto.createHmac('sha1', '')` is legal
/// Node API (RFC 2202 test case 6 covers exactly that, and Node accepts it). The
/// `HMAC_*` functions are what `node_crypto.cc`'s `Hmac::Hmac` calls, so this is
/// also the closer port.
pub struct Hmac {
    /// The OpenSSL context, freed by `Drop`.
    context: *mut openssl_sys::HMAC_CTX,
    /// The algorithm name, kept so the handle can report it.
    name: String,
}

// SAFETY: `HMAC_CTX` is a plain OpenSSL heap object with no thread affinity; it
// is only ever touched through this struct, which is moved between threads rather
// than shared. `Hmac` is not `Sync` because `&self` never mutates the context.
unsafe impl Send for Hmac {}

impl Hmac {
    /// Starts an HMAC.
    ///
    /// `Hmac.prototype.init` reports an unresolvable digest as
    /// `ERR_CRYPTO_INVALID_DIGEST` ("Invalid digest: <name>"), which is what
    /// `crypto_hmac.cc:196` throws and what a caller catching that code expects.
    pub fn new(algorithm: &str, key: &[u8]) -> Result<Self, CryptoError> {
        let digest = crate::enumerate::resolve_digest(algorithm)
            .ok_or_else(|| CryptoError::unknown_digest(algorithm, DigestApi::DigestConsumer))?;
        // SAFETY: `HMAC_CTX_new` returns either a valid context or null, and the
        // null case is checked immediately below.
        let context = unsafe { openssl_sys::HMAC_CTX_new() };
        if context.is_null() {
            return Err(CryptoError::OpenSsl(
                "cannot allocate an HMAC context".to_string(),
            ));
        }
        // SAFETY: `context` was just allocated and is owned by this struct. The
        // key pointer is valid for `key.len()` bytes, and `EVP_sha256()`-style
        // digest pointers from `MessageDigest::as_ptr` are static. A null engine
        // is the documented "default implementation" argument.
        let initialised = unsafe {
            openssl_sys::HMAC_Init_ex(
                context,
                key.as_ptr().cast(),
                // `HMAC_Init_ex` takes the key length as a `c_int`, unlike the
                // `size_t` of the other entry points.
                c_int_len(key.len())?,
                digest.as_ptr().cast(),
                std::ptr::null_mut(),
            )
        };
        if initialised != 1 {
            // SAFETY: the allocation above is not yet owned by a live `Hmac`, so
            // it has to be freed here or leaked.
            unsafe { openssl_sys::HMAC_CTX_free(context) };
            return Err(CryptoError::OpenSsl(format!(
                "cannot initialise HMAC with {algorithm}"
            )));
        }
        Ok(Self {
            context,
            name: algorithm.to_string(),
        })
    }

    /// The algorithm name this HMAC was created with.
    pub fn algorithm(&self) -> &str {
        &self.name
    }

    /// Feeds bytes in.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        // SAFETY: `self.context` is a live context owned by `self`. `data` is
        // valid for `data.len()` bytes, and `HMAC_Update` with a zero length and
        // a possibly-dangling pointer is documented to be a no-op that does not
        // read the pointer.
        let updated = unsafe { openssl_sys::HMAC_Update(self.context, data.as_ptr(), data.len()) };
        if updated != 1 {
            return Err(CryptoError::OpenSsl("HMAC update failed".to_string()));
        }
        Ok(())
    }

    /// Finalises and returns the MAC.
    pub fn finish(&mut self) -> Result<Vec<u8>, CryptoError> {
        // An HMAC is at most 64 bytes for the digests Node exposes; 128 is a
        // safe bound and `HMAC_Final` reports the real length.
        let mut buffer = [0u8; 128];
        let mut length: std::os::raw::c_uint = 0;
        // SAFETY: `buffer` has room for 128 bytes, which exceeds any HMAC this
        // crate can produce, and `length` is a valid out-parameter.
        let finished =
            unsafe { openssl_sys::HMAC_Final(self.context, buffer.as_mut_ptr(), &mut length) };
        if finished != 1 {
            return Err(CryptoError::OpenSsl("HMAC finalisation failed".to_string()));
        }
        let length = length as usize;
        if length > buffer.len() {
            return Err(CryptoError::OpenSsl(
                "HMAC reported an impossible output length".to_string(),
            ));
        }
        Ok(buffer[..length].to_vec())
    }
}

impl Drop for Hmac {
    fn drop(&mut self) {
        if !self.context.is_null() {
            // SAFETY: `context` came from `HMAC_CTX_new` in `Hmac::new` and is
            // freed exactly once, here, because `finish` does not consume it.
            unsafe { openssl_sys::HMAC_CTX_free(self.context) };
            self.context = std::ptr::null_mut();
        }
    }
}

/// Computes an HMAC in one call.
pub fn hmac_once(algorithm: &str, key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut hmac = Hmac::new(algorithm, key)?;
    hmac.update(data)?;
    hmac.finish()
}

// ---------------------------------------------------------------------------
// Signing (HMAC-backed subset for now)
// ---------------------------------------------------------------------------

/// Verifies a MAC in constant time, the way `crypto.timingSafeEqual` and an
/// HMAC comparison do.
///
/// Length is compared first and is not secret, which is what Node's
/// `TimingSafeEqual` does as well: it throws on a length mismatch rather than
/// returning false.
pub fn timing_safe_equal(left: &[u8], right: &[u8]) -> Result<bool, CryptoError> {
    if left.len() != right.len() {
        // `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH`, a `RangeError` in
        // `node_errors.h`. A bare message would leave `error.code` undefined and
        // a caller checking the documented code would take the wrong branch.
        return Err(CryptoError::TimingSafeEqualLength);
    }
    Ok(openssl::memcmp::eq(left, right))
}

/// Verifies a signature over `data`.
///
/// This is the `Hash`/`Hmac`-independent half of `crypto.verify`: the caller
/// supplies an already-loaded key. Only the HMAC case is wired up in this
/// landing; asymmetric signatures are declared deferred.
pub fn verify_hmac(
    algorithm: &str,
    key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    let expected = hmac_once(algorithm, key, data)?;
    Ok(openssl::memcmp::eq(&expected, signature))
}

// ---------------------------------------------------------------------------
// Ciphers
// ---------------------------------------------------------------------------

/// Looks up a cipher by name.
pub fn cipher_by_name(name: &str) -> Option<Cipher> {
    crate::enumerate::resolve_cipher(name)
}

/// The key length in bytes a cipher expects.
pub fn cipher_key_len(cipher: Cipher) -> usize {
    cipher.key_len()
}

/// The IV length in bytes a cipher expects.
pub fn cipher_iv_len(cipher: Cipher) -> usize {
    cipher.iv_len().unwrap_or(0)
}

/// The block size in bytes, which is `1` for streaming modes.
pub fn cipher_block_size(cipher: Cipher) -> usize {
    cipher.block_size()
}

/// Every cipher OpenSSL can produce, for `getCiphers()`.
///
/// Derived from OpenSSL so the list cannot advertise a cipher that then fails to
/// initialise. Node's list is `EVP_CIPHER_do_all_sorted` filtered to the ones
/// that are not disabled by policy, and this follows the same rule.
pub fn cipher_algorithms() -> Vec<String> {
    let mut names = crate::enumerate::cipher_names();
    names.sort();
    names.dedup();
    names
}

/// Every elliptic curve name OpenSSL can produce, for `getCurves()`.
pub fn curve_names() -> Vec<String> {
    let mut names = crate::enumerate::curve_names();
    names.sort();
    names.dedup();
    names
}

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------

/// Fills `target` from the OS CSPRNG through OpenSSL's `RAND_bytes`.
///
/// `RAND_bytes` is what `node::crypto::RandomBytes` calls, so the source of
/// randomness is identical to Node's rather than a second opinion about it.
pub fn random_fill(target: &mut [u8]) -> Result<(), CryptoError> {
    // OpenSSL documents `RAND_bytes` as failing for a request larger than
    // `INT_MAX`; nothing in `lib/crypto` can produce such a buffer, but chunking
    // keeps the cast below honest instead of truncating.
    for chunk in target.chunks_mut(i32::MAX as usize) {
        openssl::rand::rand_bytes(chunk).map_err(|_| openssl_error())?;
    }
    Ok(())
}

/// Returns `len` random bytes.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; len];
    random_fill(&mut bytes)?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// PBKDF2 with an HMAC PRF.
///
/// Node exposes this as `crypto.pbkdf2`/`pbkdf2Sync`, and `lib/internal/crypto/
/// pbkdf2.js` validates the arguments before the binding sees them. `iterations`
/// and `length` are `u32` because that is what the JavaScript layer passes.
pub fn pbkdf2(
    digest: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let message_digest = crate::enumerate::resolve_digest(digest)
        .ok_or_else(|| CryptoError::unknown_digest(digest, DigestApi::DigestConsumer))?;
    let mut output = vec![0u8; length];
    // SAFETY: the resolution may be a fetched provider digest, whose pointer this
    // borrowed through `as_ptr` and which outlives the call. `pbkdf2_hmac` wants
    // the safe crate's `MessageDigest`, so the pointer is re-wrapped: the wrapper
    // is a bare newtype over `*const EVP_MD` with no ownership of its own, and
    // `message_digest` keeps the reference alive across the call.
    let borrowed = unsafe { MessageDigest::from_ptr(message_digest.as_ptr().cast()) };
    openssl::pkcs5::pbkdf2_hmac(password, salt, iterations as usize, borrowed, &mut output)
        .map_err(|_| openssl_error())?;
    Ok(output)
}

/// scrypt.
///
/// `openssl::pkcs5::scrypt` is the same `EVP_PBE_scrypt` Node calls.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u64,
    p: u64,
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut output = vec![0u8; length];
    openssl::pkcs5::scrypt(password, salt, n, r, p, u64::MAX, &mut output)
        .map_err(|_| CryptoError::InvalidArgument("scrypt parameters are invalid".to_string()))?;
    Ok(output)
}

/// scrypt honouring the caller's `maxmem`.
///
/// `crypto.scryptSync(password, salt, keylen, options)` takes `options.maxmem`
/// and Node passes it straight to `EVP_PBE_scrypt` as the memory ceiling; a
/// derivation that would exceed it fails rather than allocating. That matters
/// because the default `maxmem` is 32 MiB and a caller raising `N` without raising
/// it expects a failure, not an allocation.
pub fn scrypt_with_maxmem(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u64,
    p: u64,
    maxmem: u64,
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut output = vec![0u8; length];
    openssl::pkcs5::scrypt(password, salt, n, r, p, maxmem, &mut output)
        .map_err(|_| CryptoError::InvalidArgument("scrypt parameters are invalid".to_string()))?;
    Ok(output)
}

/// HKDF as RFC 5869 defines it, which is what `crypto.hkdf` computes.
///
/// The two failure modes are Node's, not OpenSSL's:
///
/// * A length over 255 digest blocks is `ERR_CRYPTO_INVALID_KEYLEN`
///   (`ncrypto::checkHkdfLength`), checked before OpenSSL is asked to allocate.
/// * An OpenSSL failure — including the zero-length request, which its KDF
///   entry point rejects — is the bare, uncoded `Error` with "HKDF derivation
///   failed" that `NodeCryptoError::HKDF_FAILED` produces.
pub fn hkdf(
    digest: &str,
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let message_digest = crate::enumerate::resolve_digest(digest)
        .ok_or_else(|| CryptoError::unknown_digest(digest, DigestApi::DigestConsumer))?;
    // HKDF-Expand emits at most 255 blocks, and each block carries the digest's
    // output size, so this is the ceiling `checkHkdfLength` enforces.
    let digest_size = digest_output_size(&message_digest);
    let block_ceiling = digest_size.saturating_mul(255);
    if length > block_ceiling {
        return Err(CryptoError::InvalidKeyLength);
    }
    // SAFETY: the pointer belongs to `message_digest`, which outlives the borrow.
    let borrowed = unsafe { MessageDigest::from_ptr(message_digest.as_ptr().cast()) };
    // `openssl::kdf::hkdf` wants an `MdRef`, which is the fetchable form of the
    // digest rather than its NID.
    let digest_ref = openssl::md::Md::from_nid(borrowed.type_())
        .ok_or_else(|| CryptoError::unknown_digest(digest, DigestApi::DigestConsumer))?;
    let mut output = vec![0u8; length];
    // An absent salt is `HashLen` zero bytes per RFC 5869. Passing `None` to the
    // OpenSSL KDF does that internally, which is why it is not substituted here.
    openssl::kdf::hkdf(
        digest_ref,
        ikm,
        salt,
        Some(info),
        openssl::kdf::HkdfMode::ExtractAndExpand,
        None,
        &mut output,
    )
    .map_err(|_| CryptoError::HkdfFailed)?;
    Ok(output)
}

/// A digest's output size in bytes, from the descriptor behind a resolution.
fn digest_output_size(source: &crate::enumerate::DigestSource) -> usize {
    // SAFETY: the pointer is live and owned by `source`; the accessor only reads.
    let size = unsafe { openssl_sys::EVP_MD_get_size(source.as_ptr().cast()) };
    usize::try_from(size).unwrap_or(0)
}

/// Resolves a digest for a KDF job, reporting a bad name the way the job
/// constructors do.
///
/// `PBKDF2Traits::AdditionalConfig` and `HKDFTraits::AdditionalConfig` both call
/// this before the job is built, so an unknown digest throws from the constructor
/// rather than arriving through `ondone`.
pub fn check_digest(name: &str) -> Result<(), CryptoError> {
    crate::enumerate::resolve_digest(name)
        .map(|_| ())
        .ok_or_else(|| CryptoError::unknown_digest(name, DigestApi::DigestConsumer))
}

/// The two checks `HKDFTraits::AdditionalConfig` performs before building a job.
///
/// The length ceiling is `checkHkdfLength` from `deps/ncrypto/ncrypto.cc`: 255
/// blocks of the digest, because HKDF-Expand appends an 8-bit counter. Zero is
/// *not* rejected here — Node accepts it and fails later in the derivation with
/// the uncoded "HKDF derivation failed", which is reproduced by
/// [`CryptoError::HkdfFailed`].
pub fn check_hkdf_parameters(digest: &str, length: usize) -> Result<(), CryptoError> {
    let source = crate::enumerate::resolve_digest(digest)
        .ok_or_else(|| CryptoError::unknown_digest(digest, DigestApi::DigestConsumer))?;
    if length > digest_output_size(&source).saturating_mul(255) {
        return Err(CryptoError::InvalidKeyLength);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Feature queries
// ---------------------------------------------------------------------------

/// Whether `crypto.setFips()` was called with `true`, i.e. OpenSSL's
/// FIPS property-query state.
///
/// This is deliberately **not** "is FIPS enforced". Node's own docs say of
/// `setFips()`: "If no loaded provider supplies a requested cryptographic
/// implementation matching `fips=yes`, the call can still succeed and
/// `crypto.getFips()` can still return `1`, but fetching that implementation
/// fails." The oracle on this host has no `fips` provider module and still
/// answers `getFips() === 1` after `setFips(true)`, so reporting the requested
/// state is the contract rather than an approximation of it.
///
/// What this build does *not* do is make OpenSSL hand out FIPS-validated
/// implementations: `setFips(true)` sets the default properties to `fips=yes`,
/// and a fetch for an algorithm with no such implementation fails the way Node's
/// docs describe. Callers who need validated crypto must run a FIPS build.
static FIPS_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether `setFips(true)` is in effect.
pub fn fips_enabled() -> bool {
    FIPS_ENABLED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Records the state `setFips()` asked for.
///
/// Infallible on purpose: the only step that could fail in Node is
/// `EVP_default_properties_enable_fips`, which is not linked here, so there is
/// nothing that can report an OpenSSL error. Pretending one is possible would put
/// an unreachable `ERR_CRYPTO_OPERATION_FAILED` path in the binding.
pub fn set_fips_enabled(enable: bool) {
    FIPS_ENABLED.store(enable, std::sync::atomic::Ordering::SeqCst);
}

/// The OpenSSL version this binary linked, e.g. `3.6.3`.
pub fn openssl_version() -> String {
    openssl::version::version()
        .split(' ')
        .nth(1)
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // The vectors below are the published ones from FIPS 180-4 / RFC 3174 /
    // RFC 1321. They are here rather than only in the integration test because a
    // wrong digest is the one failure this crate must never ship, and this is
    // the cheapest place to catch it.

    #[test]
    fn sha256_matches_published_vectors() {
        // FIPS 180-4 examples.
        assert_eq!(
            hex(&digest_once("sha256", b"").expect("sha256 of empty")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&digest_once("sha256", b"abc").expect("sha256 of abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&digest_once(
                "sha256",
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )
            .expect("sha256 of the two-block vector")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha1_matches_published_vectors() {
        assert_eq!(
            hex(&digest_once("sha1", b"abc").expect("sha1 of abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&digest_once("sha1", b"").expect("sha1 of empty")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn sha512_matches_published_vectors() {
        assert_eq!(
            hex(&digest_once("sha512", b"abc").expect("sha512 of abc")),
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn md5_matches_published_vectors() {
        // RFC 1321, appendix A.5.
        assert_eq!(
            hex(&digest_once("md5", b"abc").expect("md5 of abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&digest_once("md5", b"").expect("md5 of empty")),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn incremental_and_one_shot_agree() {
        let mut digest = Digest::new("sha256").expect("sha256");
        digest
            .update(b"abcdbcdecdefdefgefghfghighij")
            .expect("first");
        digest
            .update(b"hijkijkljklmklmnlmnomnopnopq")
            .expect("second");
        assert_eq!(
            hex(&digest.finish().expect("finish")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn unknown_algorithm_is_reported_not_guessed() {
        match Digest::new("no-such-digest") {
            Err(error) => assert_eq!(
                error,
                CryptoError::UnknownAlgorithm {
                    name: "no-such-digest".to_string(),
                    api: DigestApi::HashConstructor,
                }
            ),
            Ok(_) => panic!("an unknown digest name must not resolve"),
        }
    }

    #[test]
    fn alias_resolves_to_the_same_digest() {
        // `sha256` and `SHA256` are the same digest; OpenSSL's lookup is
        // case-insensitive, and `hashnames.js` relies on that.
        assert_eq!(
            hex(&digest_once("SHA256", b"abc").expect("uppercase")),
            hex(&digest_once("sha256", b"abc").expect("lowercase"))
        );
    }

    // RFC 4231 test cases for HMAC-SHA256 (cases 1, 2 and 3).
    #[test]
    fn hmac_sha256_matches_rfc4231() {
        assert_eq!(
            hex(&hmac_once("sha256", &[0x0b; 20], b"Hi There").expect("case 1")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_once("sha256", b"Jefe", b"what do ya want for nothing?").expect("case 2")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_once("sha256", &[0xaa; 20], &[0xdd; 50]).expect("case 3")),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn hmac_sha1_matches_rfc2202() {
        // RFC 2202 test case 1.
        assert_eq!(
            hex(&hmac_once("sha1", &[0x0b; 20], b"Hi There").expect("case 1")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        // An empty key is legal and is what `createHmac(name, '')` builds.
        assert_eq!(
            hex(&hmac_once("sha1", b"", b"").expect("empty key")),
            "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
        );
    }

    #[test]
    fn hmac_incremental_matches_one_shot() {
        let mut hmac = Hmac::new("sha256", b"key").expect("hmac");
        hmac.update(b"what do ya ").expect("first");
        hmac.update(b"want for nothing?").expect("second");
        assert_eq!(
            hmac.finish().expect("finish"),
            hmac_once("sha256", b"key", b"what do ya want for nothing?").expect("one shot")
        );
    }

    #[test]
    fn timing_safe_equal_compares_and_rejects_length_mismatch() {
        assert!(timing_safe_equal(b"abcd", b"abcd").expect("equal"));
        assert!(!timing_safe_equal(b"abcd", b"abce").expect("unequal"));
        assert!(timing_safe_equal(b"", b"").expect("both empty"));
        // The kind matters as much as the message: `crypto.js` documents
        // `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH` and the binding turns this into a
        // `RangeError` carrying that code.
        assert_eq!(
            timing_safe_equal(b"abc", b"abcd").expect_err("length mismatch"),
            CryptoError::TimingSafeEqualLength
        );
    }

    #[test]
    fn random_bytes_differ_and_have_the_right_length() {
        let first = random_bytes(32).expect("first");
        let second = random_bytes(32).expect("second");
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 32);
        // A CSPRNG returning the same 32 bytes twice is a defect, not bad luck.
        assert_ne!(first, second);
        assert!(random_bytes(0).expect("empty").is_empty());
    }

    #[test]
    fn random_fill_does_not_disturb_neighbouring_bytes() {
        let mut buffer = [0u8; 16];
        random_fill(&mut buffer[4..12]).expect("fill the middle");
        assert_eq!(&buffer[..4], &[0; 4], "bytes before the range changed");
        assert_eq!(&buffer[12..], &[0; 4], "bytes after the range changed");
    }

    // RFC 6070 PBKDF2-HMAC-SHA1 vectors.
    #[test]
    fn pbkdf2_matches_rfc6070() {
        assert_eq!(
            hex(&pbkdf2("sha1", b"password", b"salt", 1, 20).expect("1 iteration")),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
        assert_eq!(
            hex(&pbkdf2("sha1", b"password", b"salt", 4096, 20).expect("4096 iterations")),
            "4b007901b765489abead49d926f721d065a429c1"
        );
    }

    // RFC 7914 scrypt test vector 2.
    #[test]
    fn scrypt_matches_rfc7914() {
        assert_eq!(
            hex(&scrypt(b"password", b"NaCl", 1024, 8, 16, 64).expect("scrypt")),
            concat!(
                "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162",
                "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
            )
        );
    }

    // RFC 5869 test case 1 for HKDF-SHA256.
    #[test]
    fn hkdf_matches_rfc5869() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let output = hkdf("sha256", &ikm, Some(&salt), &info, 42).expect("hkdf");
        assert_eq!(
            hex(&output),
            concat!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865"
            )
        );
    }

    #[test]
    fn enumeration_is_derived_from_openssl_and_usable() {
        let hashes = hash_algorithms();
        assert!(!hashes.is_empty(), "OpenSSL reported no digests");
        for expected in ["sha1", "sha256", "sha512", "md5"] {
            assert!(
                hashes.iter().any(|name| name == expected),
                "getHashes() is missing {expected}"
            );
        }
        // Every name advertised must actually work. This is the contract the
        // task asks for: an enumeration cannot name an algorithm that fails.
        for name in &hashes {
            Digest::new(name)
                .unwrap_or_else(|error| panic!("advertised {name} but it failed: {error}"));
        }

        let ciphers = cipher_algorithms();
        assert!(!ciphers.is_empty(), "OpenSSL reported no ciphers");
        for name in &ciphers {
            // The accept test is the one `createCipheriv` uses, not the narrower
            // legacy-table lookup: a provider-only cipher such as
            // `aes-128-cbc-cts` has no NID and never appears in the legacy table,
            // yet `createCipheriv` constructs it fine.
            assert!(
                rn_bind_crypto_cipher::evp::Cipher::from_name(name).is_some(),
                "advertised cipher {name} but createCipheriv cannot construct it"
            );
        }

        let curves = curve_names();
        assert!(!curves.is_empty(), "OpenSSL reported no curves");
        assert!(curves.iter().any(|name| name == "prime256v1"));
    }

    #[test]
    fn openssl_version_is_reported() {
        let version = openssl_version();
        assert!(!version.is_empty());
        assert_ne!(version, "unknown");
    }
}
