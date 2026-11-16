//! The OpenSSL digest layer: one algorithm resolver, one incremental hasher, no
//! V8 types.
//!
//! Everything `Bun.SHA1` … `Bun.MD5` and `Bun.CryptoHasher` compute runs through
//! [`Digest`] here. Keeping it free of V8 means the digests can be unit-tested
//! against vectors without building an isolate, and the binding layer above is
//! left with argument marshalling only.
//!
//! # Why a private library context
//!
//! `Bun.MD4` works, and `crypto.createHash('md4')` does not — on Node it is
//! `ERR_OSSL_EVP_UNSUPPORTED`, and in this build it fails the same way because
//! the vendored OpenSSL enables only the `default` provider. Bun has MD4 because
//! it uses BoringSSL, which never had a provider split.
//!
//! The vendored OpenSSL does contain the legacy provider's code:
//! `ossl_legacy_provider_init` is a linked symbol, because `openssl-src` is
//! configured without `no-legacy`. Loading it in the process's *default* library
//! context would make `crypto.createHash('md4')` start working, quietly widening
//! Node's surface — a change this crate has no business making. So MD4 is served
//! from a separate `OSSL_LIB_CTX` that loads `default` and `legacy` and is
//! reused for the life of the process. The default context is untouched.
//!
//! # `blake2b256` is not a fetchable algorithm
//!
//! `CryptoHasher.algorithms` lists `blake2b256`, and OpenSSL has no such digest
//! name: BLAKE2b is parameterised by output length and the `default` provider
//! registers only `BLAKE2B-512`. Bun gets a 256-bit variant because BoringSSL
//! exposes one. Here it is `BLAKE2B-512` with the provider's `size` context
//! parameter set to 32 *before the first update*, which is the documented way to
//! request a shorter BLAKE2b and produces the same digest as
//! `hashlib.blake2b(digest_size=32)`. Setting it at finalise time is too late:
//! BLAKE2 absorbs the output length into its first block.

use std::ffi::{c_char, c_int, c_uint, c_void, CString};
use std::sync::Mutex;

/// The size OpenSSL's `EVP_MAX_MD_SIZE` reports, and the largest digest any
/// algorithm here produces.
pub const MAX_DIGEST_LEN: usize = 64;

/// Mirror of `OSSL_PARAM`, which `openssl-sys` declares but does not construct.
///
/// `OSSL_PARAM_construct_uint` is the only constructor reached for, and it
/// fills this layout; the mirror exists so the array it writes into can live on
/// the stack in Rust.
#[repr(C)]
#[derive(Clone, Copy)]
struct OsslParam {
    key: *const c_char,
    data_type: u32,
    data: *mut c_void,
    data_size: usize,
    return_size: usize,
}

type CoreHandle = c_void;

extern "C" {
    /// The legacy provider's entry point, linked into the vendored `libcrypto`.
    fn ossl_legacy_provider_init(
        handle: *const CoreHandle,
        params: *const OsslParam,
        out: *mut *const OsslParam,
        provider_context: *mut *mut c_void,
    ) -> c_int;
    fn OSSL_PROVIDER_add_builtin(
        context: *mut openssl_sys::OSSL_LIB_CTX,
        name: *const c_char,
        init: Option<
            unsafe extern "C" fn(
                *const CoreHandle,
                *const OsslParam,
                *mut *const OsslParam,
                *mut *mut c_void,
            ) -> c_int,
        >,
    ) -> c_int;
    fn EVP_DigestInit_ex2(
        context: *mut openssl_sys::EVP_MD_CTX,
        digest: *const openssl_sys::EVP_MD,
        params: *const OsslParam,
    ) -> c_int;
    fn OSSL_PARAM_construct_uint(key: *const c_char, value: *mut c_uint) -> OsslParam;
    fn OSSL_PARAM_construct_end() -> OsslParam;
    fn EVP_DigestFinalXOF(context: *mut openssl_sys::EVP_MD_CTX, out: *mut u8, len: usize)
        -> c_int;
    fn EVP_MD_get_flags(digest: *const openssl_sys::EVP_MD) -> std::os::raw::c_ulong;
}

/// `EVP_MD_FLAG_XOF` from `openssl/evp.h`.
const EVP_MD_FLAG_XOF: std::os::raw::c_ulong = 0x0002;

/// `OSSL_PARAM_UTF8_STRING` from `openssl/core.h`: the type of a string-valued
/// context parameter such as HMAC's `digest`.
const OSSL_PARAM_UTF8_STRING: u32 = 4;

/// Why a digest operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// The algorithm name is not one `Bun.CryptoHasher.algorithms` lists.
    ///
    /// This is a whitelist and not an OpenSSL lookup on purpose: Bun rejects
    /// names OpenSSL would happily fetch (`sha2-256`, `sha256WithRSAEncryption`),
    /// and accepting them would make the class more permissive than the thing it
    /// is compatible with.
    UnknownAlgorithm(String),
    /// OpenSSL rejected an operation on an algorithm it did resolve.
    OpenSsl(String),
    /// The context could not be set up, which is a build problem rather than a
    /// caller error.
    Unavailable(String),
}

impl std::fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAlgorithm(name) => write!(formatter, "Unsupported algorithm {name}"),
            Self::OpenSsl(message) => write!(formatter, "openssl: {message}"),
            Self::Unavailable(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for DigestError {}

/// How an algorithm is reached, which decides the digest length and the
/// finaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A normal fixed-length digest.
    Fixed,
    /// An extendable-output function: finalise with `EVP_DigestFinalXOF`.
    Xof,
    /// BLAKE2b with a non-default output length, set as a context parameter.
    Blake2bSized(u32),
}

/// One entry of `Bun.CryptoHasher.algorithms`, with what this build needs to
/// reproduce it.
#[derive(Debug, Clone, Copy)]
pub struct Algorithm {
    /// The name `CryptoHasher.algorithms` reports and `.algorithm` returns.
    pub name: &'static str,
    /// The name to fetch from OpenSSL, when it differs from `name`.
    pub fetch: &'static str,
    /// The digest length in bytes.
    pub length: usize,
    /// How to initialise and finalise it.
    pub kind: Kind,
}

const fn fixed(name: &'static str, length: usize) -> Algorithm {
    Algorithm {
        name,
        fetch: name,
        length,
        kind: Kind::Fixed,
    }
}

/// The 19 algorithms, in `CryptoHasher.algorithms` order.
pub const ALGORITHMS: &[Algorithm] = &[
    Algorithm {
        name: "blake2b256",
        fetch: "BLAKE2B-512",
        length: 32,
        kind: Kind::Blake2bSized(32),
    },
    fixed("blake2b512", 64),
    fixed("blake2s256", 32),
    fixed("md4", 16),
    fixed("md5", 16),
    fixed("ripemd160", 20),
    fixed("sha1", 20),
    fixed("sha224", 28),
    fixed("sha256", 32),
    fixed("sha384", 48),
    fixed("sha512", 64),
    fixed("sha512-224", 28),
    fixed("sha512-256", 32),
    fixed("sha3-224", 28),
    fixed("sha3-256", 32),
    fixed("sha3-384", 48),
    fixed("sha3-512", 64),
    Algorithm {
        name: "shake128",
        fetch: "shake128",
        length: 16,
        kind: Kind::Xof,
    },
    Algorithm {
        name: "shake256",
        fetch: "shake256",
        length: 32,
        kind: Kind::Xof,
    },
];

/// The alias table, exactly as `crypto_hasher`'s `ALGORITHM_MAP` has it.
///
/// Lookup is ASCII-case-insensitive against these keys, so `SHA-256` and
/// `sha256` both land on `sha256`. What is *not* here matters as much: `sha_256`,
/// `sha2-256`, `md-5`, `blake2b-512` and `ripemd-160` are all rejected, and
/// `sha512_256` (the class spelling) is rejected in favour of `sha512-256`.
pub const ALIASES: &[(&str, &str)] = &[
    ("md4", "md4"),
    ("md5", "md5"),
    ("sha1", "sha1"),
    ("sha-1", "sha1"),
    ("sha128", "sha1"),
    ("sha224", "sha224"),
    ("sha256", "sha256"),
    ("sha384", "sha384"),
    ("sha512", "sha512"),
    ("rmd160", "ripemd160"),
    ("sha-224", "sha224"),
    ("sha-256", "sha256"),
    ("sha-384", "sha384"),
    ("sha-512", "sha512"),
    ("sha3-224", "sha3-224"),
    ("sha3-256", "sha3-256"),
    ("sha3-384", "sha3-384"),
    ("sha3-512", "sha3-512"),
    ("shake128", "shake128"),
    ("shake256", "shake256"),
    ("shake-128", "shake128"),
    ("shake-256", "shake256"),
    ("ripemd160", "ripemd160"),
    ("blake2b256", "blake2b256"),
    ("blake2b512", "blake2b512"),
    ("blake2s256", "blake2s256"),
    ("sha-512224", "sha512-224"),
    ("sha512-224", "sha512-224"),
    ("sha-512256", "sha512-256"),
    ("sha512-256", "sha512-256"),
    ("sha-512/224", "sha512-224"),
    ("sha-512_224", "sha512-224"),
    ("sha-512/256", "sha512-256"),
    ("sha-512_256", "sha512-256"),
];

/// Resolves a JS algorithm name to its canonical [`Algorithm`].
pub fn resolve(name: &str) -> Option<&'static Algorithm> {
    let canonical = ALIASES
        .iter()
        .find(|(alias, _)| alias.eq_ignore_ascii_case(name))
        .map(|(_, canonical)| *canonical)?;
    ALGORITHMS
        .iter()
        .find(|algorithm| algorithm.name == canonical)
}

/// The private library context, created on first use.
///
/// `Mutex<Option<...>>` rather than `OnceLock` because the pointers it holds are
/// not `Send` and the context must be freed at process exit, which a `OnceLock`
/// cannot do. The mutex is taken once per digest construction, which is
/// negligible next to `EVP_DigestInit_ex2`.
static CONTEXT: Mutex<Option<Context>> = Mutex::new(None);

struct Context {
    library: *mut openssl_sys::OSSL_LIB_CTX,
    default_provider: *mut openssl_sys::OSSL_PROVIDER,
    legacy_provider: *mut openssl_sys::OSSL_PROVIDER,
}

// SAFETY: an `OSSL_LIB_CTX` and its providers are plain OpenSSL heap objects
// with no thread affinity. Access is serialised by the `Mutex` that holds them,
// and a digest only holds the raw context pointer, not the mutex, while it
// runs — the context outlives every digest because it is never freed.
unsafe impl Send for Context {}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: each pointer came from the matching `new`/`load` call and is
        // released exactly once, here. Order matters: providers before the
        // context that owns them.
        unsafe {
            openssl_sys::OSSL_PROVIDER_unload(self.default_provider);
            openssl_sys::OSSL_PROVIDER_unload(self.legacy_provider);
            openssl_sys::OSSL_LIB_CTX_free(self.library);
        }
    }
}

/// Creates the private context if it does not exist yet.
fn context() -> Result<std::sync::MutexGuard<'static, Option<Context>>, DigestError> {
    let mut slot = CONTEXT
        .lock()
        .map_err(|_| DigestError::Unavailable("the digest context lock is poisoned".into()))?;
    if slot.is_some() {
        return Ok(slot);
    }
    // SAFETY: `OSSL_LIB_CTX_new` returns a fresh context or null, checked below.
    unsafe {
        let library = openssl_sys::OSSL_LIB_CTX_new();
        if library.is_null() {
            return Err(DigestError::Unavailable(
                "cannot allocate an OpenSSL library context".into(),
            ));
        }
        let legacy_name = CString::new("legacy").expect("no interior NUL");
        // Registering the linked-in legacy implementation under the name
        // `legacy` is what makes `OSSL_PROVIDER_load` find it. Without this the
        // load fails: the vendored build has no separate `legacy.so` to open.
        if OSSL_PROVIDER_add_builtin(
            library,
            legacy_name.as_ptr(),
            Some(ossl_legacy_provider_init),
        ) != 1
        {
            openssl_sys::OSSL_LIB_CTX_free(library);
            return Err(DigestError::Unavailable(
                "cannot register the built-in legacy provider".into(),
            ));
        }
        let default_name = CString::new("default").expect("no interior NUL");
        let default_provider = openssl_sys::OSSL_PROVIDER_load(library, default_name.as_ptr());
        let legacy_provider = openssl_sys::OSSL_PROVIDER_load(library, legacy_name.as_ptr());
        if default_provider.is_null() || legacy_provider.is_null() {
            let error = openssl::error::ErrorStack::get().to_string();
            if !default_provider.is_null() {
                openssl_sys::OSSL_PROVIDER_unload(default_provider);
            }
            if !legacy_provider.is_null() {
                openssl_sys::OSSL_PROVIDER_unload(legacy_provider);
            }
            openssl_sys::OSSL_LIB_CTX_free(library);
            return Err(DigestError::Unavailable(format!(
                "cannot load the default and legacy providers: {error}"
            )));
        }
        *slot = Some(Context {
            library,
            default_provider,
            legacy_provider,
        });
    }
    Ok(slot)
}

/// An incremental digest over one OpenSSL `EVP_MD_CTX`.
///
/// Built on the raw context rather than `openssl::hash::Hasher` because
/// [`copy`](Self::copy) is part of the surface (`CryptoHasher.prototype.copy`)
/// and the safe wrapper exposes no way to duplicate an in-progress context.
/// `EVP_MD_CTX_copy_ex` is the operation; rebuilding from the algorithm name
/// would restart from empty and produce a silently wrong digest.
pub struct Digest {
    context: *mut openssl_sys::EVP_MD_CTX,
    digest: *const openssl_sys::EVP_MD,
    algorithm: &'static Algorithm,
    /// The `size` value for a BLAKE2b request, kept so [`copy`](Self::copy) can
    /// reapply it. Zero for every other algorithm.
    blake2b_size: c_uint,
}

// SAFETY: as `Context`: an `EVP_MD_CTX` has no thread affinity and moves with
// the struct rather than being shared.
unsafe impl Send for Digest {}

impl Digest {
    /// Starts a digest for `algorithm`.
    pub fn new(algorithm: &'static Algorithm) -> Result<Self, DigestError> {
        // The guard is released before the digest is returned: the context it
        // protects is only read here, to fetch the `EVP_MD`, and the digest then
        // owns a reference-counted `EVP_MD` of its own.
        let guard = context()?;
        let Some(state) = guard.as_ref() else {
            return Err(DigestError::Unavailable(
                "the digest context is not initialised".into(),
            ));
        };

        let fetch_name = CString::new(algorithm.fetch).expect("algorithm names have no NUL");
        // SAFETY: the library context is live (the whole process), the name is a
        // valid C string, and a null property query selects no property filter.
        let digest = unsafe {
            openssl_sys::EVP_MD_fetch(state.library, fetch_name.as_ptr(), std::ptr::null())
        };
        if digest.is_null() {
            let error = openssl::error::ErrorStack::get().to_string();
            return Err(DigestError::Unavailable(format!(
                "the {} digest is not available: {error}",
                algorithm.name
            )));
        }
        // SAFETY: `digest` is live and owned by this struct from here on.
        let is_xof = unsafe { EVP_MD_get_flags(digest) } & EVP_MD_FLAG_XOF != 0;
        if is_xof != (algorithm.kind == Kind::Xof) {
            // A provider that changed its mind about an algorithm's shape would
            // otherwise produce a wrong-length digest through the other
            // finaliser. Refuse rather than guess.
            // SAFETY: `digest` came from `EVP_MD_fetch` and nothing else owns it.
            unsafe { openssl_sys::EVP_MD_free(digest as *mut _) };
            return Err(DigestError::Unavailable(format!(
                "the {} digest has an unexpected shape",
                algorithm.name
            )));
        }

        let mut this = Self {
            // Placeholder, replaced below; `set_up` allocates the real one.
            context: std::ptr::null_mut(),
            digest,
            algorithm,
            blake2b_size: 0,
        };
        if let Err(error) = this.set_up() {
            this.release_digest();
            return Err(error);
        }
        this.clear_openssl_errors();
        Ok(this)
    }

    /// Initialises `context` for this algorithm.
    ///
    /// The `OSSL_PARAM` key and value are locals here so the pointers inside the
    /// parameter array stay valid for the duration of the OpenSSL call. Keeping
    /// them in `self` would store pointers into a struct that is about to move,
    /// which is a use-after-move that only shows up as a wrong digest.
    ///
    /// # Safety
    ///
    /// `context` must be a live `EVP_MD_CTX` and `self.digest` a live `EVP_MD`.
    unsafe fn initialise(&self, context: *mut openssl_sys::EVP_MD_CTX) -> c_int {
        if self.blake2b_size == 0 {
            return EVP_DigestInit_ex2(context, self.digest, std::ptr::null());
        }
        // BLAKE2b is parameterised by output length, so a 32-byte request is
        // `BLAKE2B-512` with `size` = 32 applied *before the first update*: the
        // length is absorbed into BLAKE2b's initial block, so setting it at
        // finalise time would produce the 512-bit digest truncated, which is a
        // different value.
        let key = CString::new("size").expect("no interior NUL");
        let mut value = self.blake2b_size;
        let mut params = [
            OSSL_PARAM_construct_uint(key.as_ptr(), &mut value),
            OSSL_PARAM_construct_end(),
        ];
        EVP_DigestInit_ex2(context, self.digest, params.as_mut_ptr())
    }

    /// Allocates a fresh context and applies the algorithm's parameters.
    fn set_up(&mut self) -> Result<(), DigestError> {
        self.blake2b_size = match self.algorithm.kind {
            Kind::Blake2bSized(size) => size,
            _ => 0,
        };

        // SAFETY: `EVP_MD_CTX_new` returns a valid context or null, checked here.
        let context = unsafe { openssl_sys::EVP_MD_CTX_new() };
        if context.is_null() {
            return Err(DigestError::Unavailable(
                "cannot allocate a digest context".into(),
            ));
        }
        self.context = context;

        // SAFETY: the context was just allocated and is owned here; `self` is
        // initialised enough for `initialise`, which only reads `digest` and
        // `blake2b_size`.
        let initialised = unsafe { self.initialise(context) };
        if initialised != 1 {
            let error = openssl::error::ErrorStack::get().to_string();
            // SAFETY: `self.context` is live and owned here; dropping it is the
            // only release path.
            unsafe {
                openssl_sys::EVP_MD_CTX_free(self.context);
            }
            self.context = std::ptr::null_mut();
            return Err(DigestError::OpenSsl(format!(
                "cannot initialise the {} digest: {error}",
                self.algorithm.name
            )));
        }
        Ok(())
    }

    /// The name `CryptoHasher.prototype.algorithm` reports.
    pub fn name(&self) -> &'static str {
        self.algorithm.name
    }

    /// The digest length in bytes.
    pub fn length(&self) -> usize {
        self.algorithm.length
    }

    /// Feeds bytes in.
    pub fn update(&mut self, data: &[u8]) -> Result<(), DigestError> {
        // SAFETY: the context is live; a zero-length update with a dangling
        // `data.as_ptr()` is documented to be a no-op.
        let updated = unsafe {
            openssl_sys::EVP_DigestUpdate(self.context, data.as_ptr().cast(), data.len())
        };
        if updated != 1 {
            let error = openssl::error::ErrorStack::get().to_string();
            return Err(DigestError::OpenSsl(format!(
                "digest update failed: {error}"
            )));
        }
        Ok(())
    }

    /// Finalises into `out`, which must be exactly [`length`](Self::length)
    /// bytes, and resets the context so a later [`update`](Self::update) starts
    /// from empty rather than from a finalised state.
    pub fn finish_into(&mut self, out: &mut [u8]) -> Result<(), DigestError> {
        debug_assert_eq!(out.len(), self.algorithm.length);
        let finished = match self.algorithm.kind {
            Kind::Xof => {
                // SAFETY: `out` is exactly `length` bytes, which is what the XOF
                // finaliser is told to produce.
                unsafe { EVP_DigestFinalXOF(self.context, out.as_mut_ptr(), out.len()) }
            }
            Kind::Blake2bSized(_) => {
                let mut written: c_uint = 0;
                // `EVP_DigestFinal_ex` writes the full 64 bytes of BLAKE2b-512;
                // `out` is 32, so a scratch buffer is needed and then truncated.
                let mut scratch = [0u8; MAX_DIGEST_LEN];
                // SAFETY: `scratch` is `MAX_DIGEST_LEN` bytes, the maximum any
                // algorithm here produces.
                let result = unsafe {
                    openssl_sys::EVP_DigestFinal_ex(
                        self.context,
                        scratch.as_mut_ptr(),
                        &mut written,
                    )
                };
                if result == 1 {
                    let written = written as usize;
                    if written < out.len() {
                        return Err(DigestError::OpenSsl(format!(
                            "the BLAKE2b digest produced {written} bytes, expected {}",
                            out.len()
                        )));
                    }
                    out.copy_from_slice(&scratch[..out.len()]);
                }
                result
            }
            Kind::Fixed => {
                let mut written: c_uint = 0;
                // SAFETY: `out` is exactly the digest length, which is what the
                // finaliser writes for a fixed-length algorithm.
                let result = unsafe {
                    openssl_sys::EVP_DigestFinal_ex(self.context, out.as_mut_ptr(), &mut written)
                };
                if result == 1 && written as usize != out.len() {
                    return Err(DigestError::OpenSsl(format!(
                        "the {} digest produced {written} bytes, expected {}",
                        self.algorithm.name,
                        out.len()
                    )));
                }
                result
            }
        };
        if finished != 1 {
            let error = openssl::error::ErrorStack::get().to_string();
            return Err(DigestError::OpenSsl(format!(
                "digest finalisation failed: {error}"
            )));
        }
        // Put the context back to its initial state. Bun's `CryptoHasher` lets a
        // second `digest()` restart from empty; the per-algorithm classes refuse
        // it in the binding layer, but the restart has to happen here so a
        // `digest()` after a *failed* attempt behaves the same.
        self.restart();
        Ok(())
    }

    /// Finalises into a fresh `Vec`, for the one-shot paths.
    pub fn finish(&mut self) -> Result<Vec<u8>, DigestError> {
        let mut out = vec![0u8; self.algorithm.length];
        self.finish_into(&mut out)?;
        Ok(out)
    }

    /// Resets the context to its initial state.
    fn restart(&mut self) {
        // SAFETY: the context is live and `EVP_DigestInit_ex2` re-initialises it
        // in place, which is what makes a second digest start from empty.
        unsafe { self.initialise(self.context) };
        self.clear_openssl_errors();
    }

    /// Duplicates the in-progress state, which is `CryptoHasher.prototype.copy`.
    pub fn copy(&self) -> Result<Self, DigestError> {
        let mut this = Self {
            context: std::ptr::null_mut(),
            digest: self.digest,
            algorithm: self.algorithm,
            blake2b_size: self.blake2b_size,
        };
        // SAFETY: `EVP_MD_CTX_new` returns a valid context or null.
        let context = unsafe { openssl_sys::EVP_MD_CTX_new() };
        if context.is_null() {
            return Err(DigestError::Unavailable(
                "cannot allocate a digest context".into(),
            ));
        }
        // SAFETY: the destination is empty so there is nothing to free first,
        // and the source is live and only read.
        let copied = unsafe { openssl_sys::EVP_MD_CTX_copy_ex(context, self.context) };
        if copied != 1 {
            // SAFETY: the allocation is not owned by a live `Digest` yet.
            unsafe { openssl_sys::EVP_MD_CTX_free(context) };
            return Err(DigestError::OpenSsl(
                "cannot copy the digest context".into(),
            ));
        }
        // `copy` takes a reference on the `EVP_MD` it inherits, since both
        // structs will free theirs.
        this.context = context;
        this.retain_digest();
        Ok(this)
    }

    /// Takes a reference on the shared `EVP_MD`.
    fn retain_digest(&mut self) {
        let name = CString::new(self.algorithm.fetch).expect("algorithm names have no NUL");
        let Ok(guard) = context() else { return };
        let Some(state) = guard.as_ref() else { return };
        // SAFETY: fetching the same name again returns the same provider-owned
        // descriptor with another reference, which `Drop` releases.
        let fetched =
            unsafe { openssl_sys::EVP_MD_fetch(state.library, name.as_ptr(), std::ptr::null()) };
        if !fetched.is_null() {
            self.digest = fetched;
        }
    }

    /// Releases `self.digest` without touching the context.
    fn release_digest(&mut self) {
        if !self.digest.is_null() {
            // SAFETY: every `EVP_MD` stored here came from `EVP_MD_fetch` and is
            // released exactly once, here or in `Drop`.
            unsafe { openssl_sys::EVP_MD_free(self.digest as *mut _) };
            self.digest = std::ptr::null();
        }
    }

    fn clear_openssl_errors(&self) {
        while openssl::error::Error::get().is_some() {}
    }
}

impl Drop for Digest {
    fn drop(&mut self) {
        if !self.context.is_null() {
            // SAFETY: `context` came from `EVP_MD_CTX_new` and is freed once.
            unsafe { openssl_sys::EVP_MD_CTX_free(self.context) };
            self.context = std::ptr::null_mut();
        }
        self.release_digest();
    }
}

/// One-shot digest of `data` under `name`.
pub fn digest_once(name: &str, data: &[u8]) -> Option<Result<Vec<u8>, DigestError>> {
    let algorithm = resolve(name)?;
    Some(Digest::new(algorithm).and_then(|mut digest| {
        digest.update(data)?;
        digest.finish()
    }))
}

/// One-shot HMAC of `data` under `name` with `key`.
pub fn hmac_once(name: &str, key: &[u8], data: &[u8]) -> Option<Result<Vec<u8>, DigestError>> {
    let algorithm = resolve(name)?;
    Some(hmac(algorithm, key, data))
}

/// HMAC over `algorithm`, used by `CryptoHasher` when a key is supplied.
///
/// Run through `EVP_MAC` against the *private* library context, not
/// `openssl::sign::Signer`. `Signer` resolves its digest from the process default
/// context, which refuses MD4 — so HMAC-MD4 worked for plain digests but failed
/// with `inner_evp_generic_fetch:unsupported (MD4)`. That was a real divergence
/// found by the HMAC fixture, and it is why this does not reuse the safe wrapper.
fn hmac(algorithm: &'static Algorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>, DigestError> {
    // Measured against Bun 1.4.4: exactly three names refuse an HMAC, and the
    // rest — including MD4 and BLAKE2b — accept one. The message is Bun's.
    if algorithm.kind == Kind::Xof || algorithm.name == "blake2s256" {
        return Err(DigestError::Unavailable(
            "HMAC is not supported for this algorithm yet".into(),
        ));
    }

    // `blake2b256` cannot go through OpenSSL's HMAC. That construction drives
    // BLAKE2B-512 and truncates, which is a *different MAC* from the one Bun
    // produces: HMAC-BLAKE2b-256 of `abc` under `key` is `e0bbaaa9…`, while the
    // truncating form is `05cc4815…`. HMAC is a generic construction over any
    // hash, so it is built here directly from the digest that already has the
    // right output length.
    if matches!(algorithm.kind, Kind::Blake2bSized(_)) {
        return hmac_over_digest(algorithm, key, data);
    }

    let guard = context()?;
    let Some(state) = guard.as_ref() else {
        return Err(DigestError::Unavailable(
            "the digest context is not initialised".into(),
        ));
    };

    let mac_name = CString::new("HMAC").expect("no interior NUL");
    // SAFETY: the library context is live for the process and the name is a
    // valid C string; a null property query applies no filter.
    let mac =
        unsafe { openssl_sys::EVP_MAC_fetch(state.library, mac_name.as_ptr(), std::ptr::null()) };
    if mac.is_null() {
        let error = openssl::error::ErrorStack::get().to_string();
        return Err(DigestError::Unavailable(format!(
            "cannot fetch the HMAC implementation: {error}"
        )));
    }
    // SAFETY: `mac` is a live `EVP_MAC` owned here.
    let context = unsafe { openssl_sys::EVP_MAC_CTX_new(mac) };
    if context.is_null() {
        // SAFETY: `mac` came from `EVP_MAC_fetch`.
        unsafe { openssl_sys::EVP_MAC_free(mac) };
        return Err(DigestError::Unavailable(
            "cannot allocate the HMAC context".into(),
        ));
    }

    // The digest is chosen with the `digest` context parameter. `blake2b256` is
    // `BLAKE2B-512` with `size` = 32, for the same reason as the plain digest:
    // BLAKE2b absorbs its output length into the first block.
    let digest_key = CString::new("digest").expect("no interior NUL");
    let digest_name = CString::new(algorithm.fetch).expect("algorithm names have no NUL");
    // No `size` parameter here, deliberately. For a plain BLAKE2b digest the
    // output length is absorbed into the first block, which is how `blake2b256`
    // becomes BLAKE2b-32. HMAC is not that construction: OpenSSL's HMAC drives
    // BLAKE2B-512 and truncates, which is a different MAC from the one Bun
    // produces (measured: HMAC-BLAKE2b-256 of `abc` under `key` is
    // `e0bbaaa9…`, while the truncating form is `05cc4815…`). `blake2b256` is
    // deferred for the HMAC path below rather than answered with the wrong MAC.
    // SAFETY: the pointers below are valid C strings and the array is terminated.
    let params: Vec<OsslParam> = vec![
        OsslParam {
            key: digest_key.as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: digest_name.as_ptr().cast_mut().cast::<c_void>(),
            data_size: digest_name.as_bytes().len(),
            return_size: 0,
        },
        unsafe { OSSL_PARAM_construct_end() },
    ];

    // SAFETY: `context` is live, the key pointer is valid for `key.len()`, and
    // `params` is a terminated array whose backing strings outlive this call.
    let initialised = unsafe {
        openssl_sys::EVP_MAC_init(context, key.as_ptr(), key.len(), params.as_ptr().cast())
    };
    let result = if initialised != 1 {
        Err(DigestError::OpenSsl(format!(
            "cannot initialise HMAC-{}: {}",
            algorithm.name,
            openssl::error::ErrorStack::get()
        )))
    } else {
        // SAFETY: as above; `data` is valid for its own length.
        let updated = unsafe { openssl_sys::EVP_MAC_update(context, data.as_ptr(), data.len()) };
        if updated != 1 {
            Err(DigestError::OpenSsl(format!(
                "HMAC-{} update failed: {}",
                algorithm.name,
                openssl::error::ErrorStack::get()
            )))
        } else {
            // BLAKE2b's MAC reports the full 64 bytes whatever the `size`
            // parameter said, so the scratch buffer is `MAX_DIGEST_LEN` and the
            // result is truncated to the algorithm's own length afterwards. A
            // buffer sized to `algorithm.length` fails with "buffer too small".
            let mut scratch = [0u8; MAX_DIGEST_LEN];
            let mut written: usize = 0;
            // SAFETY: `scratch` is the largest digest this crate produces.
            let finished = unsafe {
                openssl_sys::EVP_MAC_final(
                    context,
                    scratch.as_mut_ptr(),
                    &mut written,
                    scratch.len(),
                )
            };
            if finished != 1 {
                Err(DigestError::OpenSsl(format!(
                    "HMAC-{} finalisation failed: {}",
                    algorithm.name,
                    openssl::error::ErrorStack::get()
                )))
            } else if written < algorithm.length {
                Err(DigestError::OpenSsl(format!(
                    "HMAC-{} produced {written} bytes, expected {}",
                    algorithm.name, algorithm.length
                )))
            } else {
                Ok(scratch[..algorithm.length].to_vec())
            }
        }
    };

    // SAFETY: both were allocated above and nothing else owns them.
    unsafe {
        openssl_sys::EVP_MAC_CTX_free(context);
        openssl_sys::EVP_MAC_free(mac);
    }
    result
}

/// HMAC built directly from [`Digest`], for an algorithm OpenSSL's HMAC cannot
/// express at the right output length.
///
/// RFC 2104: `H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m))`, with the key padded or hashed
/// to the digest's block size. Only `blake2b256` reaches here today, and it is
/// general rather than special-cased so a future sized digest gets the same
/// treatment instead of a second copy of this arithmetic.
fn hmac_over_digest(
    algorithm: &'static Algorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, DigestError> {
    // BLAKE2b's block size is 128 bytes. Read from OpenSSL rather than assumed, so
    // a future sized algorithm cannot silently get the wrong pad length.
    let block_size = block_size_of(algorithm)?;

    let mut block = vec![0u8; block_size];
    if key.len() > block_size {
        let mut digest = Digest::new(algorithm)?;
        digest.update(key)?;
        let hashed = digest.finish()?;
        block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Digest::new(algorithm)?;
    inner.update(&block.iter().map(|byte| byte ^ 0x36).collect::<Vec<_>>())?;
    inner.update(data)?;
    let inner_digest = inner.finish()?;

    let mut outer = Digest::new(algorithm)?;
    outer.update(&block.iter().map(|byte| byte ^ 0x5c).collect::<Vec<_>>())?;
    outer.update(&inner_digest)?;
    outer.finish()
}

/// The block size OpenSSL reports for `algorithm`.
fn block_size_of(algorithm: &'static Algorithm) -> Result<usize, DigestError> {
    let guard = context()?;
    let Some(state) = guard.as_ref() else {
        return Err(DigestError::Unavailable(
            "the digest context is not initialised".into(),
        ));
    };
    let name = CString::new(algorithm.fetch).expect("algorithm names have no NUL");
    // SAFETY: the library context is live for the process and the name is a valid
    // C string.
    let digest =
        unsafe { openssl_sys::EVP_MD_fetch(state.library, name.as_ptr(), std::ptr::null()) };
    if digest.is_null() {
        return Err(DigestError::Unavailable(format!(
            "the {} digest is not available",
            algorithm.name
        )));
    }
    // SAFETY: `digest` is live and only read here.
    let block = unsafe { openssl_sys::EVP_MD_get_block_size(digest) };
    // SAFETY: `digest` came from `EVP_MD_fetch` and nothing else owns it.
    unsafe { openssl_sys::EVP_MD_free(digest as *mut _) };
    usize::try_from(block).map_err(|_| {
        DigestError::Unavailable(format!(
            "the {} digest reports a block size of {block}",
            algorithm.name
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every advertised algorithm matches a value the oracle printed.
    ///
    /// The vectors live in `tests/fixtures/digest-vectors.txt` because they are
    /// recorded output, not expectations someone typed: one transcription slip
    /// in a 96-character hex string is invisible in review and fatal to a test.
    #[test]
    fn every_advertised_algorithm_matches_its_published_vector() {
        let fixture = include_str!("../tests/fixtures/digest-vectors.txt");
        let mut section = "";
        let mut compared = 0usize;
        for line in fixture.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                section = line;
                continue;
            }
            if section != "[crypto_hasher]" {
                continue;
            }
            let Some((key, value)) = line.split_once(" = ") else {
                continue;
            };
            let Some((name, field)) = key.split_once('.') else {
                continue;
            };
            if field == "byteLength" {
                let advertised =
                    resolve(name).unwrap_or_else(|| panic!("{name} is not advertised"));
                assert_eq!(advertised.length.to_string(), value, "{name}.byteLength");
                continue;
            }
            let input: &[u8] = match field {
                "empty" => b"",
                "abc" => b"abc",
                "multi" => MULTI_PATTERN.as_slice(),
                "large" => LARGE_PATTERN.as_slice(),
                other => panic!("unknown input {other}"),
            };
            let bytes = digest_once(name, input)
                .unwrap_or_else(|| panic!("{name} is not advertised"))
                .unwrap_or_else(|error| panic!("{name} failed: {error}"));
            let actual: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(&actual, value.trim_matches('"'), "{name} of {field}");
            compared += 1;
        }
        assert_eq!(compared, ALGORITHMS.len() * 4, "fixture shape changed");
    }

    /// Byte `i` is `(i*37 + 11) & 0xff`, which is the pattern the fixture was
    /// recorded with. Defined once so the two cannot drift.
    static MULTI_PATTERN: [u8; 200] = pattern::<200>();
    static LARGE_PATTERN: [u8; 100000] = pattern::<100000>();

    const fn pattern<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        let mut i = 0;
        while i < N {
            bytes[i] = ((i * 37 + 11) & 0xff) as u8;
            i += 1;
        }
        bytes
    }

    #[test]
    fn md4_is_reachable_and_the_default_context_still_is_not() {
        // The compatibility requirement: Bun.MD4 works here …
        let md4 = digest_once("md4", b"abc")
            .expect("md4 is advertised")
            .expect("md4 works");
        assert_eq!(md4, hex("a448017aaf21d8525fc10ae87aa6729d"));

        // … and it works *only* through the private context. Asking the process
        // default for MD4 must still fail, because that is what keeps
        // `crypto.createHash('md4')` behaving as it did before this crate
        // existed. If this assertion ever flips, this crate has widened Node's
        // surface.
        let name = CString::new("MD4").expect("no NUL");
        // SAFETY: a null library context is the process default; the name is a
        // valid C string.
        let fetched = unsafe {
            openssl_sys::EVP_MD_fetch(std::ptr::null_mut(), name.as_ptr(), std::ptr::null())
        };
        assert!(
            fetched.is_null(),
            "MD4 became fetchable from the default context, which widens Node's crypto surface"
        );
    }

    #[test]
    fn blake2b256_is_blake2b32_not_a_truncation() {
        // BLAKE2b-256 is a *different* digest from the first 32 bytes of
        // BLAKE2b-512, so a truncating implementation would pass a length check
        // and be wrong.
        let short = digest_once("blake2b256", b"abc")
            .expect("advertised")
            .expect("works");
        let long = digest_once("blake2b512", b"abc")
            .expect("advertised")
            .expect("works");
        assert_eq!(short.len(), 32);
        assert_ne!(short, long[..32], "blake2b256 must not be a truncation");
    }

    #[test]
    fn chunked_updates_equal_one_update() {
        let data: Vec<u8> = (0..1000).map(|i| (i * 7 + 3) as u8).collect();
        for algorithm in ALGORITHMS {
            let mut one = Digest::new(algorithm).expect("constructs");
            one.update(&data).expect("update");
            let expected = one.finish().expect("finish");

            let mut chunked = Digest::new(algorithm).expect("constructs");
            for chunk in data.chunks(37) {
                chunked.update(chunk).expect("update");
            }
            assert_eq!(
                chunked.finish().expect("finish"),
                expected,
                "{} across chunk boundaries",
                algorithm.name
            );
        }
    }

    #[test]
    fn copy_forks_the_state() {
        let algorithm = resolve("sha256").expect("sha256 is advertised");
        let mut original = Digest::new(algorithm).expect("constructs");
        original.update(b"ab").expect("update");
        let mut forked = original.copy().expect("copy");
        forked.update(b"c").expect("update");
        original.update(b"c").expect("update");
        assert_eq!(
            forked.finish().expect("finish"),
            original.finish().expect("finish"),
            "a copy must continue from the same state"
        );
    }

    #[test]
    fn digest_restarts_after_finalising() {
        // `CryptoHasher` allows a second `digest()`, which reports the digest of
        // whatever was fed since the first one.
        let algorithm = resolve("sha256").expect("sha256 is advertised");
        let mut digest = Digest::new(algorithm).expect("constructs");
        digest.update(b"abc").expect("update");
        let first = digest.finish().expect("finish");
        let second = digest.finish().expect("second finish");
        assert_eq!(
            first,
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            second,
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            "a second digest must hash the empty input, not repeat the first"
        );
    }

    #[test]
    fn aliases_resolve_and_non_aliases_do_not() {
        for (alias, canonical) in [
            ("SHA256", "sha256"),
            ("SHA-256", "sha256"),
            ("SHA-1", "sha1"),
            ("sha128", "sha1"),
            ("SHA-512/256", "sha512-256"),
            ("md5", "md5"),
            ("MD5", "md5"),
            ("BLAKE2B512", "blake2b512"),
            ("shake-128", "shake128"),
        ] {
            assert_eq!(resolve(alias).map(|a| a.name), Some(canonical), "{alias}");
        }
        for name in [
            "sha_256",
            "sha2-256",
            "sha512_256",
            "md-5",
            "ripemd-160",
            "blake2b-512",
            "sha512/256",
            "bogus",
            "",
        ] {
            assert!(resolve(name).is_none(), "{name} must not resolve");
        }
    }

    #[test]
    fn hmac_matches_node() {
        // `node -e 'crypto.createHmac("sha256","key").update("abc").digest("hex")'`
        let digest = hmac_once("sha256", b"key", b"abc")
            .expect("advertised")
            .expect("works");
        assert_eq!(
            digest,
            hex("9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab")
        );
    }

    #[test]
    fn hmac_rejects_the_extendable_output_functions() {
        for name in ["shake128", "shake256"] {
            let error = hmac_once(name, b"key", b"abc")
                .expect("advertised")
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "HMAC is not supported for this algorithm yet"
            );
        }
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect()
    }
}
