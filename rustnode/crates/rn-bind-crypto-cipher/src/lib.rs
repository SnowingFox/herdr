//! `CipherBase` and `AESCipherJob` for `internalBinding('crypto')`.
//!
//! `src/crypto/crypto_cipher.cc` is the binding this mirrors, with
//! `crypto_aes.cc` and `crypto_chacha20_poly1305.cc` as the two WebCrypto job
//! traits that sit beside it. All three land on the `crypto` object that
//! `rn-bind-crypto` already builds rather than forming a namespace of their own,
//! which is why the entry point is [`install_classes`] and not a
//! `BindingModule`.
//!
//! # What the JavaScript does with these
//!
//! `lib/internal/crypto/cipher.js` builds `Cipheriv`/`Decipheriv` over
//! `LazyTransform`, and the only native object involved is one `CipherBase`
//! handle per stream:
//!
//! | JavaScript | native |
//! | --- | --- |
//! | `new CipherBase(isEncrypt, cipher, key, iv, authTagLength[, ctsMode, xtsStandard])` | the constructor |
//! | `update(data, inputEncoding)` | [`evp_binding`]'s `update` |
//! | `final()` | `final` |
//! | `setAutoPadding(bool)` | `EVP_CIPHER_CTX_set_padding` |
//! | `getAuthTag()` | `EVP_CTRL_AEAD_GET_TAG`, after `final()` |
//! | `setAuthTag(tag)` | `EVP_CTRL_AEAD_SET_TAG`, before the ciphertext |
//! | `setAAD(aad, plaintextLength)` | `EVP_CipherUpdate` with a null output |
//!
//! # Why this is not a wrapper around `openssl::symm`
//!
//! `openssl::symm::Crypter` exists and would cover plain CBC/CTR/GCM. It cannot
//! cover the rest of what this handle must do, and every gap is observable:
//!
//! * **Wrap mode** needs `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW` set *before* the cipher
//!   is selected, and `Crypter::new` never sets it.
//! * **Per-cipher AEAD tag length** is three `EVP_CIPHER_CTX_ctrl` calls the safe
//!   wrapper does not expose for a `Crypter`.
//! * **CTS and XTS mode options** are `OSSL_PARAM` string parameters applied
//!   between the two `EVP_CipherInit_ex` calls.
//! * **A finalising call that reports failure.** `test-crypto-cipheriv-cbc-cts`
//!   asserts that `final()` on a decipher with the wrong tag throws, which is
//!   `EVP_CipherFinal` returning 0 rather than a Rust error.
//!
//! So the context is driven through `openssl-sys`, the same way `engine.rs`
//! drives `EVP_MD_CTX` in `rn-bind-crypto`. `openssl-sys` is the one already in
//! the graph, and no second OpenSSL is linked.
//!
//! # `CryptoJob` modes
//!
//! `AESCipherJob` is a `CryptoJob<AESCipherTraits>` in Node with three modes
//! (`kCryptoJobAsync`, `kCryptoJobSync`, `kCryptoJobWebCrypto`), and `run()`
//! returns a promise in all three. This crate resolves it **inline for every
//! mode**, which is what sync mode does:
//!
//! * `crypto.subtle`'s AES jobs use `kCryptoJobWebCrypto`, and `jobPromise` in
//!   `lib/internal/crypto/util.js` only wraps `run()`'s return in a promise. A
//!   promise resolved before `run()` returns is indistinguishable to `await`.
//! * `kCryptoJobAsync` would need `uv_queue_work` plus a completion that settles
//!   the promise from the loop. That is the shared `CryptoJob` machinery (slice
//!   S9), not cipher-specific, and a private threadpool path here would be the
//!   second inconsistent job implementation the plan warns against.
//!
//! What is therefore *not* implemented is doing the work off the main thread.
//! No AES test observes that; the observable behaviour, which the WebCrypto
//! tests do check, is identical.
//!
//! # OpenSSL version
//!
//! This crate calls the same 3.6.3 build `rn-bind-crypto` links; `openssl-sys`
//! appears once in the dependency graph and `openssl-src` is built once. Two
//! algorithms the pinned Node's OpenSSL 4.1 has and 3.6 does not —
//! `sm4-xts` — are simply absent from `getCiphers()`, and the tests that need them
//! `common.printSkipMessage` on exactly that fact.

use rn_v8_sys::v8;

pub mod aes;
pub mod evp;
pub mod evp_binding;
pub mod info;
pub mod job;
pub mod state;

pub use state::{CipherError, CipherState, ErrorKind, Kind};

/// The members this crate installs, for the parent crate's `MEMBERS` list.
///
/// `getCiphers` and `getSSLCiphers` are **not** here: `rn-bind-crypto` already
/// installs both from its own enumeration module, and re-registering them would
/// replace a working function with a second copy.
/// `getCipherInfo` is listed because `src/crypto/crypto_cipher.cc` owns it, but
/// `rn-bind-crypto` already declares it deferred in its own `DEFERRED` list. The
/// coordinator's `install.rs` edit moves that one entry; this crate only supplies
/// the function, so the name is here for that edit to reference.
pub const MEMBERS: &[&str] = &["CipherBase", "AESCipherJob", "getCipherInfo"];

/// Installs `CipherBase` and `AESCipherJob` onto `target`, the `crypto`
/// namespace object.
///
/// Called from `rn-bind-crypto`'s `install`, exactly as
/// `rn_bind_crypto_dh::install_classes` is.
///
/// # Why this is not named `register`
///
/// `tools/regen-bindings.sh` discovers a namespace-providing crate by grepping
/// its sources for the literal text of a public `register` function, so a crate
/// that exports one is put in the generated `install_all` list and the build then
/// fails on the symbol. Slice 1 hit precisely that with a helper whose name began
/// with `register`, and this comment must not repeat the trigger string either —
/// the grep does not distinguish a doc comment from code. `install_classes` is the
/// name that sidesteps it, matching `rn-bind-crypto-dh`.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let cipher = evp_binding::build_cipher_base_class(scope)?;
    set(scope, target, "CipherBase", cipher.into())?;
    let job = job::build_aes_cipher_job_class(scope)?;
    set(scope, target, "AESCipherJob", job.into())?;
    let info = v8::FunctionTemplate::builder(info::get_cipher_info)
        .build(scope)
        .get_function(scope)
        .ok_or("cannot allocate crypto.getCipherInfo")?;
    set(scope, target, "getCipherInfo", info.into())?;
    Ok(())
}

/// Sets a property on the namespace object.
fn set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    object.set(scope, key.into(), value);
    Ok(())
}
