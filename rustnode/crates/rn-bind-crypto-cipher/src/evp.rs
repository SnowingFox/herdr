//! The `EVP_CIPHER_CTX` state machine, with no V8 types in sight.
//!
//! Everything here is a direct translation of `CipherBase`'s behaviour in
//! `src/crypto/crypto_cipher.cc` and of the `ncrypto::CipherCtxPointer` calls it
//! makes. Keeping it free of V8 means the cipher semantics are unit-testable
//! against published vectors and against a real `node` binary without building
//! an isolate, which is how the parity table in the crate's tests is produced.
//!
//! # The four modes that are not "update until you are done"
//!
//! Most ciphers are a streaming loop: `update` in, `final` out. Four families
//! are not, and Node models them with `has_one_shot_update_` rather than a
//! separate class:
//!
//! | family | rule |
//! | --- | --- |
//! | CCM decrypt | the tag is verified during `update`, so `final` only reports it |
//! | SIV / GCM-SIV | the whole message is authenticated at once; one `update` only |
//! | CTS | the length decides the last two blocks, so `update` must see them all |
//! | XTS | the data unit is the whole message; a partial unit is an error |
//! | wrap | AES-KW is a single operation over a whole block multiple |
//!
//! Getting this wrong is not subtle for XTS and CTS: `test-crypto-cipheriv-xts`
//! asserts that a 15-byte `update` fails, that the failure leaves the handle in a
//! state where a *second* 15-byte update also fails, and that the correct
//! one-shot update afterwards still succeeds. So a failed one-shot update must
//! not consume the one-shot slot.

use std::ffi::c_int;
use std::os::raw::c_ulong;

use openssl_sys as ffi;

use crate::CipherError;

/// The three OpenSSL entry points `openssl-sys` 0.9.118 does not declare.
///
/// Declared here rather than reached through a different API because each is the
/// only way to do what `CipherBase` does, and all three take a fixed, simple
/// signature that cannot drift:
///
/// * `EVP_CIPHER_CTX_settable_params` — the descriptor table that decides
///   whether `ctsMode`/`xtsStandard` is even accepted. Setting a parameter a
///   cipher does not advertise must fail *before* the call, which is what makes
///   `ERR_CRYPTO_UNSUPPORTED_OPERATION` on plain CBC deterministic.
/// * `EVP_CIPHER_CTX_set_params` — applies them.
/// * `EVP_CIPHER_get0_name` — the provider name, used to re-resolve a legacy
///   table entry into a provider cipher.
///
/// `rn-bind-crypto`'s `enumerate.rs` declares the walkers it needs the same way
/// and for the same reason, so this follows that precedent rather than adding a
/// `bindgen` step for three functions.
mod sys {
    use std::ffi::c_int;

    use openssl_sys::{EVP_CIPHER, EVP_CIPHER_CTX, OSSL_PARAM};

    unsafe extern "C" {
        /// The parameters a cipher context can accept, or null.
        pub fn EVP_CIPHER_CTX_settable_params(ctx: *mut EVP_CIPHER_CTX) -> *const OSSL_PARAM;

        /// Applies a terminated `OSSL_PARAM` array to a context.
        pub fn EVP_CIPHER_CTX_set_params(
            ctx: *mut EVP_CIPHER_CTX,
            params: *const OSSL_PARAM,
        ) -> c_int;

        /// The cipher's canonical provider name.
        pub fn EVP_CIPHER_get0_name(cipher: *mut EVP_CIPHER) -> *const std::ffi::c_char;
    }
}

// ---------------------------------------------------------------------------
// Cipher classification
// ---------------------------------------------------------------------------

/// Mode bits of `EVP_CIPH_MODE`, from `openssl/evp.h`.
const EVP_CIPH_MODE: c_ulong = 0x000F_0007;
const EVP_CIPH_STREAM_CIPHER: c_ulong = 0x0;
const EVP_CIPH_CBC_MODE: c_ulong = 0x2;
const EVP_CIPH_CFB_MODE: c_ulong = 0x3;
const EVP_CIPH_CTR_MODE: c_ulong = 0x5;
const EVP_CIPH_GCM_MODE: c_ulong = 0x6;
const EVP_CIPH_CCM_MODE: c_ulong = 0x7;
const EVP_CIPH_XTS_MODE: c_ulong = 0x10001;
const EVP_CIPH_WRAP_MODE: c_ulong = 0x10002;
const EVP_CIPH_OCB_MODE: c_ulong = 0x10003;
const EVP_CIPH_SIV_MODE: c_ulong = 0x10004;
const EVP_CIPH_GCM_SIV_MODE: c_ulong = 0x10005;

/// `EVP_CIPH_FLAG_CTS`, the flag `ncrypto::Cipher::isCtsMode` tests.
const EVP_CIPH_FLAG_CTS: c_ulong = 0x4000;

/// `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW`: without it `EVP_CipherInit_ex` refuses a
/// wrap cipher outright.
const EVP_CIPHER_CTX_FLAG_WRAP_ALLOW: c_int = 0x1;

/// `EVP_CTRL_AEAD_SET_IVLEN`, `_SET_TAG` and `_GET_TAG`.
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;

/// `NID_chacha20_poly1305`, for the one stream cipher that authenticates.
const NID_CHACHA20_POLY1305: c_int = 1018;

/// `EVP_GCM_TLS_TAG_LEN`: the default tag length for GCM, SIV and ChaCha20.
const DEFAULT_AEAD_TAG_LENGTH: u32 = 16;

/// The longest tag `setAuthTag` will accept, `EVP_MAX_AEAD_TAG_LENGTH`.
pub const MAX_AUTH_TAG_LENGTH: usize = 16;

// ---------------------------------------------------------------------------
// Cipher handle
// ---------------------------------------------------------------------------

/// One resolvable `EVP_CIPHER` and the facts the binding reads off it.
///
/// Node's `ncrypto::Cipher` is the same idea: a `const EVP_CIPHER*` plus the mode
/// predicates, so the rest of the code asks "is this GCM" instead of comparing
/// numbers.
///
/// The pointer is shared behind an `Arc` rather than copied, because a fetched
/// cipher is reference-counted by OpenSSL and `EVP_CIPHER_free` must run exactly
/// once per fetch. `openssl-sys` does not declare `EVP_CIPHER_up_ref`, so a
/// derived `Clone` that copied the pointer would free it twice; sharing the owner
/// is the correct alternative and costs one atomic increment on a handle that is
/// created once per cipher stream.
#[derive(Clone)]
pub struct Cipher {
    inner: std::sync::Arc<CipherInner>,
}

struct CipherInner {
    pointer: *const ffi::EVP_CIPHER,
    /// Whether the pointer came from `EVP_CIPHER_fetch` and must be freed.
    ///
    /// `EVP_get_cipherbyname` returns a pointer into a static table; fetching
    /// returns a reference-counted object. Freeing the wrong one is a crash, so
    /// the provenance is part of the handle rather than assumed.
    fetched: bool,
}

// SAFETY: an `EVP_CIPHER` is immutable after creation and OpenSSL's provider
// ciphers are safe to reference from any thread. This handle only ever reads it.
unsafe impl Send for CipherInner {}
// SAFETY: as above. The handle has no interior mutability.
unsafe impl Sync for CipherInner {}

impl Drop for CipherInner {
    fn drop(&mut self) {
        if self.fetched && !self.pointer.is_null() {
            // SAFETY: `pointer` came from `EVP_CIPHER_fetch`, which returns a
            // reference the caller owns, and the `Arc` guarantees this is the
            // last owner.
            unsafe { ffi::EVP_CIPHER_free(self.pointer.cast_mut()) };
        }
    }
}

impl Cipher {
    /// Resolves a cipher name the way `createCipheriv` has to.
    ///
    /// Two lookups, in the order `ncrypto::Cipher::FromName` uses them. The
    /// legacy table comes first because it is where OpenSSL's aliases live
    /// (`aes128-wrap` resolves there and not through a provider fetch), and a
    /// provider fetch second because algorithms that only exist in a provider —
    /// `aes-128-cbc-cts` on this OpenSSL — are absent from the legacy table
    /// entirely.
    ///
    /// The legacy pointer is converted to a fetched one on purpose. A legacy
    /// `EVP_CIPHER` has `origin == EVP_ORIG_METH`, and OpenSSL 3's
    /// `evp_cipher_init_internal` routes that into a `legacy` branch which fails
    /// for XTS with `EVP_R_NO_OPERATION_SET`. Fetching it instead gives the
    /// provider implementation of the same algorithm, which is the one Node
    /// drives.
    pub fn from_name(name: &str) -> Option<Self> {
        let text = std::ffi::CString::new(name).ok()?;
        clear_errors();
        // SAFETY: `text` is a valid NUL-terminated string and the lookup only
        // reads it.
        let legacy = unsafe { ffi::EVP_get_cipherbyname(text.as_ptr()) };
        if !legacy.is_null() {
            // SAFETY: `legacy` is a non-null `EVP_CIPHER` from OpenSSL's table.
            let canonical = unsafe { sys::EVP_CIPHER_get0_name(legacy.cast_mut()) };
            if !canonical.is_null() {
                // SAFETY: `canonical` is a NUL-terminated string owned by the
                // cipher, live for as long as the table entry is.
                if let Some(resolved) = Self::fetch(unsafe { std::ffi::CStr::from_ptr(canonical) })
                {
                    return Some(resolved);
                }
            }
        }
        Self::fetch(&text)
    }

    /// Resolves a cipher by NID, which is the `getCipherInfo(number)` path.
    pub fn from_nid(nid: c_int) -> Option<Self> {
        clear_errors();
        // SAFETY: `OBJ_nid2sn` only reads the integer.
        let short = unsafe { ffi::OBJ_nid2sn(nid) };
        if short.is_null() {
            return None;
        }
        // SAFETY: a non-null short name is a static NUL-terminated string.
        Self::from_name(&unsafe { std::ffi::CStr::from_ptr(short) }.to_string_lossy())
    }

    fn fetch(name: &std::ffi::CStr) -> Option<Self> {
        // SAFETY: the name is a valid C string and a null property query means
        // "the default properties", which is what Node uses.
        let pointer =
            unsafe { ffi::EVP_CIPHER_fetch(std::ptr::null_mut(), name.as_ptr(), std::ptr::null()) };
        if pointer.is_null() {
            return None;
        }
        Some(Self {
            inner: std::sync::Arc::new(CipherInner {
                pointer,
                fetched: true,
            }),
        })
    }

    fn mode(&self) -> c_ulong {
        if self.inner.pointer.is_null() {
            return 0;
        }
        // SAFETY: the pointer is a live `EVP_CIPHER`.
        unsafe { ffi::EVP_CIPHER_get_flags(self.inner.pointer) & EVP_CIPH_MODE }
    }

    fn flags(&self) -> c_ulong {
        if self.inner.pointer.is_null() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { ffi::EVP_CIPHER_get_flags(self.inner.pointer) }
    }

    /// The cipher's fixed IV length, or 0 when it takes no IV.
    pub fn iv_length(&self) -> usize {
        if self.inner.pointer.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let length = unsafe { ffi::EVP_CIPHER_get_iv_length(self.inner.pointer) };
        usize::try_from(length).unwrap_or(0)
    }

    /// The cipher's default key length.
    pub fn key_length(&self) -> usize {
        if self.inner.pointer.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let length = unsafe { ffi::EVP_CIPHER_get_key_length(self.inner.pointer) };
        usize::try_from(length).unwrap_or(0)
    }

    /// The cipher's block size. Stream ciphers report 1.
    pub fn block_size(&self) -> usize {
        if self.inner.pointer.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let size = unsafe { ffi::EVP_CIPHER_get_block_size(self.inner.pointer) };
        usize::try_from(size).unwrap_or(1).max(1)
    }

    /// The NID, or 0 for a cipher with no object identifier.
    pub fn nid(&self) -> c_int {
        if self.inner.pointer.is_null() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { ffi::EVP_CIPHER_get_nid(self.inner.pointer) }
    }

    /// `ncrypto::Cipher::getName`, which prefers the short NID name.
    pub fn name(&self) -> String {
        let nid = self.nid();
        if nid != 0 {
            // SAFETY: only reads the integer.
            let short = unsafe { ffi::OBJ_nid2sn(nid) };
            if !short.is_null() {
                // SAFETY: a static NUL-terminated string.
                return unsafe { std::ffi::CStr::from_ptr(short) }
                    .to_string_lossy()
                    .into_owned();
            }
        }
        if self.inner.pointer.is_null() {
            return String::new();
        }
        // SAFETY: a live cipher's provider name is a static string.
        let canonical = unsafe { sys::EVP_CIPHER_get0_name(self.inner.pointer.cast_mut()) };
        if canonical.is_null() {
            return String::new();
        }
        // SAFETY: as above.
        unsafe { std::ffi::CStr::from_ptr(canonical) }
            .to_string_lossy()
            .into_owned()
    }

    /// The lowercase mode label `getCipherInfo` reports.
    pub fn mode_label(&self) -> &'static str {
        match self.mode() {
            EVP_CIPH_CCM_MODE => "ccm",
            EVP_CIPH_CFB_MODE => "cfb",
            EVP_CIPH_CBC_MODE => "cbc",
            EVP_CIPH_CTR_MODE => "ctr",
            EVP_CIPH_GCM_MODE => "gcm",
            EVP_CIPH_OCB_MODE => "ocb",
            EVP_CIPH_SIV_MODE => "siv",
            EVP_CIPH_GCM_SIV_MODE => "gcm-siv",
            EVP_CIPH_WRAP_MODE => "wrap",
            EVP_CIPH_XTS_MODE => "xts",
            EVP_CIPH_STREAM_CIPHER => "stream",
            // `EVP_CIPH_ECB_MODE` and `EVP_CIPH_OFB_MODE` are the two the
            // reference switch lists that are not named constants above because
            // nothing else here needs them.
            0x1 => "ecb",
            0x4 => "ofb",
            _ => "{unknown}",
        }
    }

    pub fn is_gcm(&self) -> bool {
        self.mode() == EVP_CIPH_GCM_MODE
    }

    pub fn is_ccm(&self) -> bool {
        self.mode() == EVP_CIPH_CCM_MODE
    }

    pub fn is_ocb(&self) -> bool {
        self.mode() == EVP_CIPH_OCB_MODE
    }

    pub fn is_ctr(&self) -> bool {
        self.mode() == EVP_CIPH_CTR_MODE
    }

    pub fn is_xts(&self) -> bool {
        self.mode() == EVP_CIPH_XTS_MODE
    }

    pub fn is_wrap(&self) -> bool {
        self.mode() == EVP_CIPH_WRAP_MODE
    }

    pub fn is_siv(&self) -> bool {
        self.mode() == EVP_CIPH_SIV_MODE
    }

    pub fn is_gcm_siv(&self) -> bool {
        self.mode() == EVP_CIPH_GCM_SIV_MODE
    }

    /// `ncrypto::Cipher::isCtsMode`, which reads a flag rather than a mode.
    pub fn is_cts(&self) -> bool {
        self.flags() & EVP_CIPH_FLAG_CTS != 0
    }

    /// `ncrypto::Cipher::isChaCha20Poly1305`.
    pub fn is_chacha20_poly1305(&self) -> bool {
        self.nid() == NID_CHACHA20_POLY1305
    }

    pub fn is_stream(&self) -> bool {
        self.mode() == EVP_CIPH_STREAM_CIPHER
    }

    /// The AEAD modes `CipherBase` treats specially.
    ///
    /// This is `ncrypto::Cipher::isSupportedAuthenticatedMode`, which is a mode
    /// test plus the ChaCha20-Poly1305 special case: it is a stream cipher by
    /// mode and authenticates anyway.
    pub fn is_authenticated(&self) -> bool {
        match self.mode() {
            EVP_CIPH_CCM_MODE
            | EVP_CIPH_GCM_MODE
            | EVP_CIPH_OCB_MODE
            | EVP_CIPH_SIV_MODE
            | EVP_CIPH_GCM_SIV_MODE => true,
            EVP_CIPH_STREAM_CIPHER => self.is_chacha20_poly1305(),
            _ => false,
        }
    }

    /// Whether a single `update` carries the whole message.
    ///
    /// `CipherBase::Update` computes this as
    /// `is_ccm_decipher || is_siv || is_cts || is_xts || is_wrap`; the CCM half
    /// depends on the direction, so the caller passes it in.
    pub fn is_one_shot(&self, decrypting_ccm: bool) -> bool {
        decrypting_ccm
            || self.is_siv()
            || self.is_gcm_siv()
            || self.is_cts()
            || self.is_xts()
            || self.is_wrap()
    }

    /// `Cipher::IsValidGCMTagLength`, from NIST SP 800-38D page 9.
    pub fn is_valid_gcm_tag_length(length: u32) -> bool {
        length == 4 || length == 8 || (12..=16).contains(&length)
    }
}

/// Empties the OpenSSL error queue.
///
/// A failed lookup pushes an error even when the caller intends to fall through
/// to another lookup, and a stale entry would be reported by the *next*
/// operation's error message.
pub fn clear_errors() {
    // SAFETY: `ERR_clear_error` takes no arguments and only touches the
    // thread-local queue.
    unsafe { ffi::ERR_clear_error() };
}

/// The packed OpenSSL errors currently on the queue, oldest first.
///
/// `ThrowCryptoError` reports the *first* error it captures as the message
/// prefix, so the order matters.
pub fn take_errors() -> Vec<u64> {
    let mut errors = Vec::new();
    loop {
        // SAFETY: pops one entry from the thread-local queue.
        let code = unsafe { ffi::ERR_get_error() };
        if code == 0 {
            return errors;
        }
        errors.push(code);
    }
}

// ---------------------------------------------------------------------------
// The context
// ---------------------------------------------------------------------------

/// An `EVP_CIPHER_CTX` plus the bookkeeping `CipherBase` keeps beside it.
///
/// The context is created once in [`CipherCtx::new`] and freed exactly once in
/// `Drop`; `final` resets it to represent "this handle is finished", which is
/// what makes a second `final()` throw `ERR_CRYPTO_INVALID_STATE` instead of
/// computing the final block of an empty message.
pub struct CipherCtx {
    pointer: *mut ffi::EVP_CIPHER_CTX,
    /// The resolved cipher, kept for the mode predicates `update` needs.
    cipher: Cipher,
    /// The algorithm name the caller passed, verbatim.
    ///
    /// Kept because every message `CipherBase` builds from the cipher name uses
    /// *this* string, not OpenSSL's canonical one: `createCipheriv('aes-256-ccm',
    /// ...)` must report `authTagLength required for aes-256-ccm` while
    /// `createCipheriv('id-aes256-CCM', ...)` reports `... for id-aes256-CCM`.
    /// Both resolve to the same `EVP_CIPHER`, so the canonical name cannot
    /// distinguish them and a test comparing the message catches the difference.
    requested_name: String,
    /// Whether this handle encrypts. `CipherBase`'s `kind_`.
    encrypting: bool,
    /// `auth_tag_state_`.
    auth_tag_state: AuthTagState,
    /// `auth_tag_len_`: the tag length fixed at construction, or `None`.
    auth_tag_len: Option<u32>,
    /// The tag `final()` computed, for a later `getAuthTag()`.
    auth_tag: Option<Vec<u8>>,
    /// `pending_auth_failed_`: CCM and SIV report authentication failure from
    /// `final` even though `update` saw it.
    pending_auth_failed: bool,
    /// `has_one_shot_update_`: whether the one `update` a one-shot cipher allows
    /// has been spent.
    has_one_shot_update: bool,
    /// `siv_aad_components_`, which SIV caps at 126.
    siv_aad_components: u32,
    /// `max_message_size_`, the CCM length limit.
    max_message_size: i32,
    /// Whether the handle is finished. `ctx_ == nullptr` in the reference.
    finished: bool,
}

/// `CipherBase::AuthTagState`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthTagState {
    Unknown,
    SetByUser,
    Computed,
}

/// `CipherBase::UpdateResult`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpdateResult {
    Success,
    MessageSize,
    ErrorState,
}

/// `CipherBase::kMaxSivAADComponents`.
const MAX_SIV_AAD_COMPONENTS: u32 = 126;

/// The arguments `CipherCtx::new` needs, bundled.
///
/// Eight positional arguments with three booleans-and-Options was the shape that
/// produced a silent swap of `cts_mode` and `xts_standard` in review, and clippy
/// flags it for the same reason. Named fields make a swap a compile error.
pub struct Init<'a> {
    /// The resolved cipher.
    pub cipher: Cipher,
    /// The algorithm name the caller passed, kept for error messages.
    pub requested_name: &'a str,
    /// Whether this handle encrypts.
    pub encrypting: bool,
    /// The secret key.
    pub key: &'a [u8],
    /// The IV, or empty for a cipher that takes none.
    pub iv: &'a [u8],
    /// `authTagLength` as the JavaScript passed it, or `None` for `-1`.
    pub auth_tag_len: Option<u32>,
    /// `options.ctsMode`, already validated by the JavaScript.
    pub cts_mode: Option<&'a str>,
    /// `options.xtsStandard`, already validated by the JavaScript.
    pub xts_standard: Option<&'a str>,
}

// SAFETY: an `EVP_CIPHER_CTX` is a plain OpenSSL heap object with no thread
// affinity; it is not shared between threads, only moved.
unsafe impl Send for CipherCtx {}

impl Drop for CipherCtx {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: allocated by `EVP_CIPHER_CTX_new` and freed exactly once.
            unsafe { ffi::EVP_CIPHER_CTX_free(self.pointer) };
            self.pointer = std::ptr::null_mut();
        }
    }
}

impl CipherCtx {
    /// `CipherBase::CommonInit`.
    ///
    /// The two-stage `EVP_CipherInit_ex` is not redundant: the first call only
    /// selects the cipher, which is the point at which IV length, tag length,
    /// CTS mode, XTS standard and key length can be set; the second supplies key
    /// and IV and actually prepares the context. Reversing them makes every one
    /// of those settings fail with "operation not supported".
    pub fn new(params: Init<'_>) -> Result<Self, CipherError> {
        let Init {
            cipher,
            requested_name,
            encrypting,
            key,
            iv,
            auth_tag_len,
            cts_mode,
            xts_standard,
        } = params;
        clear_errors();
        // SAFETY: allocates a fresh context.
        let pointer = unsafe { ffi::EVP_CIPHER_CTX_new() };
        if pointer.is_null() {
            return Err(CipherError::OperationFailed(
                "Failed to allocate cipher context".to_string(),
            ));
        }
        let mut ctx = Self {
            pointer,
            cipher: cipher.clone(),
            requested_name: requested_name.to_string(),
            encrypting,
            auth_tag_state: AuthTagState::Unknown,
            auth_tag_len: None,
            auth_tag: None,
            pending_auth_failed: false,
            has_one_shot_update: false,
            siv_aad_components: 0,
            max_message_size: i32::MAX,
            finished: false,
        };

        if cipher.is_wrap() {
            // SAFETY: the flag is read by the next `EVP_CipherInit_ex` and the
            // context is live.
            unsafe { ffi::EVP_CIPHER_CTX_set_flags(ctx.pointer, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW) };
        }

        let encrypt = i32::from(encrypting);
        // SAFETY: selects the cipher; null key and IV mean "not yet".
        let selected = unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.pointer,
                cipher.inner.pointer,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                encrypt,
            )
        };
        if selected != 1 {
            return Err(ctx.init_failure("Failed to initialize cipher"));
        }

        if let Some(mode) = cts_mode {
            if !ctx.set_string_param("cts_mode", mode) {
                return Err(CipherError::UnsupportedModeOption {
                    cipher: ctx.requested_name.clone(),
                    option: "ctsMode",
                });
            }
        }
        if let Some(standard) = xts_standard {
            // `OSSL_CIPHER_PARAM_XTS_STANDARD` is not a public macro in 3.0; the
            // parameter name is used directly so a provider that advertises it
            // is found either way, which is what `ncrypto` does too.
            if !ctx.set_string_param("xts_standard", standard) {
                return Err(CipherError::UnsupportedModeOption {
                    cipher: ctx.requested_name.clone(),
                    option: "xtsStandard",
                });
            }
        }

        if cipher.is_authenticated() && !ctx.init_authenticated(iv.len(), auth_tag_len)? {
            return Err(CipherError::InvalidAuthTag(
                "authentication tag initialization failed".to_string(),
            ));
        }

        // SAFETY: sets the key length on the selected cipher; the context is
        // live and the cipher requires it.
        let keylen = unsafe { ffi::EVP_CIPHER_CTX_set_key_length(ctx.pointer, key.len() as c_int) };
        if keylen != 1 {
            return Err(CipherError::InvalidKeyLength);
        }

        let key_pointer = if key.is_empty() {
            std::ptr::null()
        } else {
            key.as_ptr()
        };
        let iv_pointer = if iv.is_empty() {
            std::ptr::null()
        } else {
            iv.as_ptr()
        };
        // SAFETY: the cipher is already selected; key and IV are slices that
        // outlive the call.
        let initialised = unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.pointer,
                std::ptr::null(),
                std::ptr::null_mut(),
                key_pointer,
                iv_pointer,
                encrypt,
            )
        };
        if initialised != 1 {
            return Err(ctx.init_failure("Failed to initialize cipher"));
        }
        Ok(ctx)
    }

    /// A context that has only selected a cipher: no key, no IV.
    ///
    /// This is `CipherCtxPointer::New()` followed by `ctx.init(cipher, true)`,
    /// which is what `GetCipherInfo` uses to test a requested key or IV length
    /// without a key. `new` cannot stand in for it, because `new` also applies
    /// the AEAD setup that a length check must not require.
    pub fn bare(cipher: Cipher) -> Option<Self> {
        clear_errors();
        // SAFETY: allocates a fresh context.
        let pointer = unsafe { ffi::EVP_CIPHER_CTX_new() };
        if pointer.is_null() {
            return None;
        }
        let ctx = Self {
            pointer,
            cipher: cipher.clone(),
            requested_name: cipher.name(),
            encrypting: true,
            auth_tag_state: AuthTagState::Unknown,
            auth_tag_len: None,
            auth_tag: None,
            pending_auth_failed: false,
            has_one_shot_update: false,
            siv_aad_components: 0,
            max_message_size: i32::MAX,
            finished: false,
        };
        if cipher.is_wrap() {
            // SAFETY: read by the next `EVP_CipherInit_ex`.
            unsafe { ffi::EVP_CIPHER_CTX_set_flags(ctx.pointer, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW) };
        }
        // SAFETY: selects the cipher with a null key and IV, which is the
        // documented way to configure the context without them.
        let selected = unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.pointer,
                cipher.inner.pointer,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            )
        };
        if selected != 1 {
            return None;
        }
        Some(ctx)
    }

    /// `CipherBase::InitAuthenticated`.
    ///
    /// Returns `Ok(false)` for "the tag length was rejected", which the caller
    /// turns into the specific error; `Err` carries a complete error already.
    fn init_authenticated(
        &mut self,
        iv_len: usize,
        auth_tag_len: Option<u32>,
    ) -> Result<bool, CipherError> {
        let is_siv = self.cipher.is_siv() || self.cipher.is_gcm_siv();

        if !is_siv && !self.set_iv_length(iv_len) {
            return Err(CipherError::InvalidIv);
        }

        if self.cipher.is_ccm() {
            // The message length is bounded by the IV: 2^(8*(15-iv_len)) - 1,
            // capped at INT_MAX. `test-crypto-cipheriv-decipheriv` and the CCM
            // tests both depend on the exact bound.
            if !(7..=13).contains(&iv_len) {
                return Err(CipherError::InvalidIv);
            }
            self.max_message_size = match iv_len {
                12 => 16_777_215,
                13 => 65_535,
                _ => i32::MAX,
            };
        }

        let length = match auth_tag_len {
            None => {
                // GCM, SIV and ChaCha20-Poly1305 default to a 16-byte tag; CCM
                // and OCB require the caller to say so.
                if self.cipher.is_gcm() || is_siv || self.cipher.is_chacha20_poly1305() {
                    DEFAULT_AEAD_TAG_LENGTH
                } else {
                    return Err(CipherError::InvalidAuthTag(format!(
                        "authTagLength required for {}",
                        self.requested_name
                    )));
                }
            }
            Some(length) => {
                let invalid = if is_siv {
                    length != DEFAULT_AEAD_TAG_LENGTH
                } else if self.cipher.is_gcm() {
                    !Cipher::is_valid_gcm_tag_length(length)
                } else {
                    !self.set_aead_tag_length(length as usize)
                };
                if invalid {
                    return Err(CipherError::InvalidAuthTag(format!(
                        "Invalid authentication tag length: {length}"
                    )));
                }
                length
            }
        };

        self.auth_tag_len = Some(length);
        Ok(true)
    }

    /// `CipherCtxPointer::setCtsMode` / `setXtsStandard`.
    ///
    /// Both are `OSSL_PARAM` string parameters, and both must be *locally*
    /// settable: a cipher that does not declare the parameter fails here, which
    /// is exactly the `ERR_CRYPTO_UNSUPPORTED_OPERATION` the tests assert for
    /// `ctsMode` on plain CBC.
    fn set_string_param(&mut self, key: &str, value: &str) -> bool {
        let Ok(key) = std::ffi::CString::new(key) else {
            return false;
        };
        let Ok(value) = std::ffi::CString::new(value) else {
            return false;
        };
        // SAFETY: `EVP_CIPHER_CTX_settable_params` returns a provider-owned
        // descriptor table, read-only here.
        let settable = unsafe { sys::EVP_CIPHER_CTX_settable_params(self.pointer) };
        if settable.is_null() {
            return false;
        }
        // SAFETY: `settable` is a NUL-terminated-terminated descriptor array and
        // `key` is a valid C string.
        let descriptor = unsafe { ffi::OSSL_PARAM_locate_const(settable, key.as_ptr()) };
        if descriptor.is_null() {
            return false;
        }
        // SAFETY: `descriptor` is a live `OSSL_PARAM`.
        let data_type = unsafe { (*descriptor).data_type };
        // `OSSL_PARAM_UTF8_STRING` is 4.
        if data_type != 4 {
            return false;
        }
        // The parameter is built by hand rather than with
        // `OSSL_PARAM_construct_utf8_string`, which `openssl-sys` declares but
        // whose returned value is a by-value struct: constructing it here keeps
        // the two ends' `OSSL_PARAM` layouts explicit and avoids a second
        // definition of the same struct in this crate.
        let parameter = ffi::OSSL_PARAM {
            key: key.as_ptr(),
            data_type,
            data: value.as_ptr().cast_mut().cast(),
            data_size: 0,
            return_size: 0,
        };
        let mut list = [parameter, end_parameter()];
        // SAFETY: `list` is a terminated descriptor array of the right layout
        // and the context is live.
        let applied = unsafe { sys::EVP_CIPHER_CTX_set_params(self.pointer, list.as_mut_ptr()) };
        applied == 1
    }

    fn set_iv_length(&mut self, length: usize) -> bool {
        // SAFETY: a control call on a live context.
        let applied = unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                self.pointer,
                EVP_CTRL_AEAD_SET_IVLEN,
                length as c_int,
                std::ptr::null_mut(),
            )
        };
        applied == 1
    }

    /// `EVP_CTRL_AEAD_SET_TAG` with a null pointer, which only records the
    /// length. Public because the WebCrypto OCB path sets it after construction.
    pub fn set_aead_tag_length_public(&mut self, length: usize) -> bool {
        self.set_aead_tag_length(length)
    }

    /// `EVP_CIPHER_CTX_set_key_length`, for `getCipherInfo`'s feasibility check.
    pub fn set_key_length(&mut self, length: usize) -> bool {
        if self.pointer.is_null() {
            return false;
        }
        // SAFETY: a control call on a live context.
        unsafe { ffi::EVP_CIPHER_CTX_set_key_length(self.pointer, length as c_int) == 1 }
    }

    /// `EVP_CTRL_AEAD_SET_IVLEN`, for `getCipherInfo`'s OCB check.
    pub fn set_iv_length_public(&mut self, length: usize) -> bool {
        self.set_iv_length(length)
    }

    /// `EVP_CTRL_AEAD_SET_TAG` with a null pointer, which only records the
    /// length.
    fn set_aead_tag_length(&mut self, length: usize) -> bool {
        // SAFETY: a control call on a live context.
        let applied = unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                self.pointer,
                EVP_CTRL_AEAD_SET_TAG,
                length as c_int,
                std::ptr::null_mut(),
            )
        };
        applied == 1
    }

    /// `EVP_CTRL_AEAD_SET_TAG` with the tag itself.
    pub fn set_aead_tag(&mut self, tag: &mut [u8]) -> bool {
        // SAFETY: a control call on a live context; OpenSSL copies the tag.
        let applied = unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                self.pointer,
                EVP_CTRL_AEAD_SET_TAG,
                tag.len() as c_int,
                tag.as_mut_ptr().cast(),
            )
        };
        applied == 1
    }

    /// `EVP_CTRL_AEAD_GET_TAG`, after `final` on an encrypting AEAD context.
    fn get_aead_tag(&mut self, length: usize) -> Option<Vec<u8>> {
        let mut tag = vec![0u8; length];
        // SAFETY: a control call on a live context, writing at most `length`
        // bytes into a buffer of exactly that size.
        let applied = unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                self.pointer,
                EVP_CTRL_AEAD_GET_TAG,
                length as c_int,
                tag.as_mut_ptr().cast(),
            )
        };
        (applied == 1).then_some(tag)
    }

    /// Turns a failed OpenSSL call into the error `ThrowCryptoError` reports.
    ///
    /// `ThrowCryptoError` uses `ERR_error_string_n` on the first captured error
    /// as the message, so the message has to carry the packed code. The shape is
    /// `error:<code>:<library> routines::<reason>`, and the tests match on the
    /// `code`/`library`/`reason` properties rather than the text.
    fn init_failure(&self, fallback: &str) -> CipherError {
        let errors = take_errors();
        match errors.first() {
            Some(code) => CipherError::OpenSsl(*code),
            None => CipherError::OperationFailed(fallback.to_string()),
        }
    }

    /// Whether the context is still usable. `CipherBase::ctx_ != nullptr`.
    pub fn is_live(&self) -> bool {
        !self.finished && !self.pointer.is_null()
    }

    pub fn cipher(&self) -> Cipher {
        self.cipher.clone()
    }

    pub fn is_encrypting(&self) -> bool {
        self.encrypting
    }

    pub fn auth_tag_state(&self) -> AuthTagState {
        self.auth_tag_state
    }

    /// The tag computed by `final`, or `None` before it or when not encrypting.
    pub fn auth_tag(&self) -> Option<&[u8]> {
        self.auth_tag.as_deref()
    }

    /// `CipherBase::Update`.
    ///
    /// Returns `(bytes, one_shot_spent)` semantics through `self`, because the
    /// one-shot bookkeeping is part of the state the next call has to see.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, CipherError> {
        if !self.is_live() {
            return Err(CipherError::UpdateFailed);
        }
        if data.len() > i32::MAX as usize {
            return Err(CipherError::OutOfRange("data is too long".to_string()));
        }

        let is_ccm = self.cipher.is_ccm();
        let is_ccm_decipher = !self.encrypting && is_ccm;

        if is_ccm && !self.check_ccm_message_length(data.len())? {
            return Err(CipherError::InvalidMessageLength);
        }

        let is_siv = self.cipher.is_siv() || self.cipher.is_gcm_siv();
        let is_one_shot = self.cipher.is_one_shot(is_ccm_decipher);
        if is_one_shot && self.has_one_shot_update {
            return Err(CipherError::UpdateFailed);
        }

        let block_size = self.cipher.block_size();
        if data.len().saturating_add(block_size) > i32::MAX as usize {
            return Err(CipherError::UpdateFailed);
        }

        clear_errors();
        // `data.len() + block_size` is the `EVP_CipherUpdate` contract for every
        // mode except wrap, whose pre-call below reports the real size.
        let mut output_size = data.len() + block_size;
        let mut out_len: c_int = 0;

        // Wrap mode has to be told the input length before it can produce
        // output: a null output buffer with `finalize` false validates the length
        // and stores the exact output size. That size is *larger* than
        // `input + one block` for DES3 wrap — it adds two 8-byte blocks — so the
        // answer has to size the buffer. Treating the call as a pure validation
        // step truncates the result to 144 bytes where Node returns 152.
        if self.encrypting && self.cipher.is_wrap() && !data.is_empty() {
            let mut length = c_int::try_from(output_size).unwrap_or(c_int::MAX);
            // SAFETY: a null output asks OpenSSL to only size the output; no
            // bytes are written.
            let checked = unsafe {
                ffi::EVP_CipherUpdate(
                    self.pointer,
                    std::ptr::null_mut(),
                    &mut length,
                    data.as_ptr(),
                    data.len() as c_int,
                )
            };
            if checked != 1 {
                // The queued error is deliberately dropped: `CipherBase::Update`
                // opens its own `MarkPopErrorOnReturn` around the operation, so
                // the error stack is empty by the time `ThrowCryptoError` reads
                // it and the fixed message is what a caller sees.
                clear_errors();
                return Err(CipherError::UpdateFailed);
            }
            let reported = usize::try_from(length).unwrap_or(0);
            if reported > output_size {
                output_size = reported;
            }
            out_len = 0;
        }

        let mut out = vec![0u8; output_size];

        // SAFETY: the output buffer is `data.len() + block_size`, which is the
        // `EVP_CipherUpdate` contract, and both pointers are valid for the
        // stated lengths.
        let updated = unsafe {
            ffi::EVP_CipherUpdate(
                self.pointer,
                out.as_mut_ptr(),
                &mut out_len,
                data.as_ptr(),
                data.len() as c_int,
            )
        };

        if is_ccm_decipher
            || is_siv
            || ((self.cipher.is_cts() || self.cipher.is_xts() || self.cipher.is_wrap())
                && updated == 1)
        {
            self.has_one_shot_update = true;
        }

        // AES-SIV reports a bad tag from `update` while CCM reports it from
        // `update` but the AEAD contract says `final` is where it surfaces.
        let pending_auth_failed = updated != 1 && !self.encrypting && (is_ccm || is_siv);

        let produced = if pending_auth_failed {
            0
        } else {
            usize::try_from(out_len).unwrap_or(0)
        };
        out.truncate(produced.min(out.len()));

        if pending_auth_failed {
            self.pending_auth_failed = true;
            return Ok(out);
        }
        if updated != 1 {
            // As above: Node's inner mark pops the OpenSSL error, so this is a
            // plain `Error` with the fixed text and no `code`. The context stays
            // usable, which `test-crypto-cipheriv-xts` requires: a failed
            // 15-byte update must be followed by a successful one-shot update.
            clear_errors();
            return Err(CipherError::UpdateFailed);
        }
        Ok(out)
    }

    fn check_ccm_message_length(&mut self, length: usize) -> Result<bool, CipherError> {
        let length = i32::try_from(length).unwrap_or(i32::MAX);
        if length > self.max_message_size {
            return Err(CipherError::InvalidMessageLength);
        }
        Ok(true)
    }

    /// `CipherBase::Final`.
    pub fn finalize(&mut self) -> Result<Vec<u8>, CipherError> {
        if !self.is_live() {
            return Err(CipherError::InvalidState);
        }
        let is_one_shot = self.cipher.is_siv()
            || self.cipher.is_gcm_siv()
            || self.cipher.is_cts()
            || self.cipher.is_xts()
            || self.cipher.is_wrap();
        if is_one_shot && !self.has_one_shot_update {
            self.finished = true;
            return Err(CipherError::FinalFailed("Unsupported state".to_string()));
        }

        let block_size = self.cipher.block_size();
        let is_ccm_decipher = !self.encrypting && self.cipher.is_ccm();

        // In CCM the tag is checked during `update`; `EVP_CipherFinal` must not
        // be called because it fails unconditionally.
        let mut queued_error = None;
        let (ok, out) = if is_ccm_decipher {
            let ok = self.auth_tag_state == AuthTagState::SetByUser
                && self.has_one_shot_update
                && !self.pending_auth_failed;
            (ok, Vec::new())
        } else {
            clear_errors();
            let mut out = vec![0u8; block_size];
            let mut out_len: c_int = 0;
            // SAFETY: the output buffer is one block, which is
            // `EVP_CipherFinal`'s contract, and the context is live.
            let finalised =
                unsafe { ffi::EVP_CipherFinal(self.pointer, out.as_mut_ptr(), &mut out_len) };
            // `CipherBase::Final` leaves the errors on the stack and
            // `ThrowCryptoError` prefers one of them, which is why a CBC decipher
            // reports `ERR_OSSL_BAD_DECRYPT` while a GCM tag mismatch — which
            // queues nothing — reports the fixed message instead.
            let queued = take_errors();
            queued_error = queued.first().copied();
            let produced = usize::try_from(out_len).unwrap_or(0).min(block_size);
            out.truncate(produced);
            let mut ok = finalised == 1;

            if ok && self.encrypting && self.cipher.is_authenticated() {
                if let Some(length) = self.auth_tag_len {
                    match self.get_aead_tag(length as usize) {
                        Some(tag) => {
                            self.auth_tag = Some(tag);
                            self.auth_tag_state = AuthTagState::Computed;
                        }
                        None => {
                            // A CCM context that never saw an `update` has not been
                            // told the message length, so `EVP_CTRL_AEAD_GET_TAG`
                            // fails with `PROV_R_TAG_NOT_SET`. The reference lets
                            // this become the thrown error, and
                            // `test-crypto-authenticated` asserts exactly that
                            // code, so the queued error is captured here rather
                            // than discarded for the fixed message.
                            if let Some(packed) = take_errors().first().copied() {
                                queued_error = Some(packed);
                            }
                            ok = false;
                        }
                    }
                }
            }
            (ok, out)
        };

        self.finished = true;
        if ok {
            return Ok(out);
        }
        match queued_error {
            Some(packed) => Err(CipherError::OpenSsl(packed)),
            None => Err(CipherError::AuthenticationFailed),
        }
    }

    /// `CipherBase::SetAutoPadding`.
    pub fn set_auto_padding(&mut self, padding: bool) -> bool {
        if !self.is_live() {
            return false;
        }
        // SAFETY: a control call on a live context.
        let applied = unsafe { ffi::EVP_CIPHER_CTX_set_padding(self.pointer, i32::from(padding)) };
        applied == 1
    }

    /// `CipherBase::SetAuthTag`.
    pub fn set_auth_tag(&mut self, tag: &mut [u8]) -> Result<bool, CipherError> {
        if !self.is_live()
            || !self.cipher.is_authenticated()
            || self.encrypting
            || self.auth_tag_state != AuthTagState::Unknown
        {
            return Ok(false);
        }
        if (self.cipher.is_siv() || self.cipher.is_gcm_siv()) && self.has_one_shot_update {
            return Ok(false);
        }
        if tag.len() > i32::MAX as usize {
            return Err(CipherError::OutOfRange("buffer is too big".to_string()));
        }
        // The expected length is fixed at construction — that is the DEP0182
        // requirement — so a mismatch is an error rather than a resize.
        let Some(expected) = self.auth_tag_len else {
            return Err(CipherError::InvalidAuthTag(
                "the authentication tag length was not set".to_string(),
            ));
        };
        if expected as usize != tag.len() {
            return Err(CipherError::InvalidAuthTag(format!(
                "Invalid authentication tag length: {}",
                tag.len()
            )));
        }
        if tag.len() > MAX_AUTH_TAG_LENGTH {
            return Err(CipherError::InvalidAuthTag(format!(
                "Invalid authentication tag length: {}",
                tag.len()
            )));
        }
        if !self.set_aead_tag(tag) {
            return Ok(false);
        }
        self.auth_tag_state = AuthTagState::SetByUser;
        Ok(true)
    }

    /// `CipherBase::SetAAD`.
    pub fn set_aad(&mut self, data: &[u8], plaintext_len: i32) -> Result<bool, CipherError> {
        if !self.is_live() || !self.cipher.is_authenticated() {
            return Ok(false);
        }
        let is_siv = self.cipher.is_siv();
        if (is_siv || self.cipher.is_gcm_siv()) && self.has_one_shot_update {
            return Ok(false);
        }
        if is_siv && self.siv_aad_components >= MAX_SIV_AAD_COMPONENTS {
            return Ok(false);
        }

        clear_errors();
        let mut out_len: c_int = 0;

        if self.cipher.is_ccm() {
            if plaintext_len < 0 {
                return Err(CipherError::MissingArgument(
                    "options.plaintextLength required for CCM mode with AAD".to_string(),
                ));
            }
            if !self.check_ccm_message_length(plaintext_len as usize)? {
                return Ok(false);
            }
            // Tell OpenSSL the plaintext length before any AAD. A null data
            // pointer with a non-zero length is how CCM receives it.
            let mut length = out_len;
            // SAFETY: a null input with a length is the documented way to
            // declare the CCM plaintext length; no bytes are read or written.
            let declared = unsafe {
                ffi::EVP_CipherUpdate(
                    self.pointer,
                    std::ptr::null_mut(),
                    &mut length,
                    std::ptr::null(),
                    plaintext_len,
                )
            };
            if declared != 1 {
                return Ok(false);
            }
        }

        // SAFETY: a null output with a real input is the AAD path; OpenSSL reads
        // `data.len()` bytes and writes nothing.
        let applied = unsafe {
            ffi::EVP_CipherUpdate(
                self.pointer,
                std::ptr::null_mut(),
                &mut out_len,
                data.as_ptr(),
                data.len() as c_int,
            )
        };
        if applied == 1 && is_siv {
            self.siv_aad_components += 1;
        }
        Ok(applied == 1)
    }
}

/// `OSSL_PARAM_construct_end`: an all-zero terminator.
fn end_parameter() -> ffi::OSSL_PARAM {
    ffi::OSSL_PARAM {
        key: std::ptr::null(),
        data_type: 0,
        data: std::ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }
}

/// `EVP_CIPHER_CTX_block_size` for a live context.
pub fn context_block_size(ctx: &CipherCtx) -> usize {
    if ctx.pointer.is_null() {
        return 1;
    }
    // SAFETY: the context is live.
    let size = unsafe { ffi::EVP_CIPHER_CTX_block_size(ctx.pointer) };
    usize::try_from(size).unwrap_or(1).max(1)
}

/// Builds the `error:<code>:<library> routines::<reason>` text and the
/// `ERR_OSSL_*` code Node attaches to a crypto failure.
///
/// This is `node::crypto::error::Decorate` in `crypto_util.cc`, and the exact
/// shape is asserted by Node's own tests, so it is reproduced rather than
/// approximated:
///
/// ```text
/// message  error:1C80006B:Provider routines::wrong final block length
/// code     ERR_OSSL_WRONG_FINAL_BLOCK_LENGTH
/// library  Provider routines
/// reason   wrong final block length
/// ```
///
/// Three details are easy to get wrong and each produces a plausible string no
/// test accepts:
///
/// 1. **The code prefix comes from the library *number*, not its name.** `ERR_LIB_PROV`
///    is 57 and the mapping is `PROV -> "PROV_"`, so the prefix would be
///    `ERR_OSSL_PROV_` — except the reason map below only names the libraries
///    Node has a macro for, and `PROV` is not one of them, so the prefix is the
///    bare `ERR_OSSL_`. That is why `ERR_OSSL_WRONG_FINAL_BLOCK_LENGTH` has no
///    library segment at all.
/// 2. **`ERR_LIB_SSL` uses no prefix**, giving `ERR_SSL_...` rather than
///    `ERR_OSSL_SSL_...`.
/// 3. **The reason is upper-cased with spaces to underscores**, and it is the
///    *reason* string, not the packed code.
///
/// `ERR_lib_error_string` and `ERR_reason_error_string` come from `openssl-sys`;
/// the library number is recovered from the packed code with `ERR_GET_LIB`'s
/// shift and mask, which are stable in OpenSSL 3.
pub fn describe_error(packed: u64) -> ErrorDescription {
    let packed = packed as std::os::raw::c_ulong;
    // SAFETY: both accessors only read the packed code.
    let (library, reason) = unsafe {
        (
            ffi::ERR_lib_error_string(packed),
            ffi::ERR_reason_error_string(packed),
        )
    };
    let library_name = if library.is_null() {
        String::new()
    } else {
        // SAFETY: a static NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(library) }
            .to_string_lossy()
            .into_owned()
    };
    let reason_name = if reason.is_null() {
        String::new()
    } else {
        // SAFETY: a static NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(reason) }
            .to_string_lossy()
            .into_owned()
    };

    // `ERR_error_string_n`'s format is `error:<code>:<library>:<function>:<reason>`,
    // and `ERR_lib_error_string` already returns the display name *including* the
    // word "routines" (`"Provider routines"`, `"Diffie-Hellman routines"`). The
    // function field is empty for provider errors, so the doubled colon in
    // `error:1C80006B:Provider routines::wrong final block length` is correct and
    // not a formatting bug — it is the empty `<function>` slot.
    let message = format!("error:{packed:08X}:{library_name}::{reason_name}");

    // `ERR_GET_LIB`: the library number is bits 23..30 of the packed code.
    let lib = ((packed >> 23) & 0xFF) as c_int;
    let prefix = if lib == ERR_LIB_SSL { "" } else { "OSSL_" };
    let library_segment = library_macro_name(lib);
    let reason_segment: String = reason_name
        .chars()
        .map(|c| {
            if c == ' ' {
                '_'
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect();
    let code = format!("ERR_{prefix}{library_segment}{reason_segment}");
    ErrorDescription {
        code,
        message,
        library: library_name,
        reason: reason_name,
    }
}

/// The four observable pieces of a decorated crypto error.
///
/// One struct rather than a tuple because `ThrowCryptoError` writes four
/// properties and a positional return would make a swap of `library` and
/// `reason` compile.
pub struct ErrorDescription {
    /// The `code` property, `ERR_OSSL_*`.
    pub code: String,
    /// The `message`, `error:<code>:<library>::<reason>`.
    pub message: String,
    /// The `library` property, e.g. `Provider routines`.
    pub library: String,
    /// The `reason` property, e.g. `wrong final block length`.
    pub reason: String,
}

/// `ERR_LIB_SSL`, whose errors are reported as `ERR_SSL_*` rather than
/// `ERR_OSSL_SSL_*`.
const ERR_LIB_SSL: c_int = 20;

/// The libraries `Decorate`'s `OSSL_ERROR_CODES_MAP` names, as `<NAME>_`.
///
/// A library absent from this map contributes no segment: `ERR_LIB_PROV` is 57
/// and is *not* in Node's map, which is why a provider error's code is
/// `ERR_OSSL_WRONG_FINAL_BLOCK_LENGTH` and not `ERR_OSSL_PROV_...`. Values are
/// from `openssl/err.h`.
fn library_macro_name(lib: c_int) -> &'static str {
    match lib {
        2 => "SYS_",
        3 => "BN_",
        4 => "RSA_",
        5 => "DH_",
        6 => "EVP_",
        7 => "BUF_",
        8 => "OBJ_",
        9 => "PEM_",
        10 => "DSA_",
        11 => "X509_",
        13 => "ASN1_",
        14 => "CONF_",
        15 => "CRYPTO_",
        16 => "EC_",
        20 => "SSL_",
        32 => "BIO_",
        33 => "PKCS7_",
        34 => "X509V3_",
        35 => "PKCS12_",
        36 => "RAND_",
        37 => "DSO_",
        38 => "ENGINE_",
        39 => "OCSP_",
        40 => "UI_",
        41 => "COMP_",
        42 => "ECDSA_",
        43 => "ECDH_",
        44 => "OSSL_STORE_",
        45 => "FIPS_",
        46 => "CMS_",
        47 => "TS_",
        48 => "HMAC_",
        50 => "CT_",
        51 => "ASYNC_",
        52 => "KDF_",
        53 => "SM2_",
        128 => "USER_",
        _ => "",
    }
}
