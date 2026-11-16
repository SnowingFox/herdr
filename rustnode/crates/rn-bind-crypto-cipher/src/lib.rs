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
pub mod public_key;
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
/// The four RSA cipher members are here too: `CipherBase::Initialize` installs
/// them in `src/crypto/crypto_cipher.cc`, immediately after `CipherBase` itself,
/// because they are one translation unit's `PublicKeyCipher` template. They came
/// off `rn-bind-crypto`'s deferred list for the same reason `getCipherInfo` did.
pub const MEMBERS: &[&str] = &[
    "CipherBase",
    "AESCipherJob",
    "getCipherInfo",
    "publicEncrypt",
    "privateDecrypt",
    "privateEncrypt",
    "publicDecrypt",
];

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
    let info = rn_core::method(info::get_cipher_info)
        .build(scope)
        .get_function(scope)
        .ok_or("cannot allocate crypto.getCipherInfo")?;
    set(scope, target, "getCipherInfo", info.into())?;
    // The four `PublicKeyCipher::Cipher<operation, cipher>` instantiations.
    // `lib/internal/crypto/cipher.js` destructures all four at module scope, so
    // an absent one binds `undefined` and throws `method is not a function` on
    // the first call rather than at load.
    for (name, operation) in [
        ("publicEncrypt", public_key::Cipher::Encrypt),
        ("privateDecrypt", public_key::Cipher::Decrypt),
        ("privateEncrypt", public_key::Cipher::Sign),
        ("publicDecrypt", public_key::Cipher::Recover),
    ] {
        // `rn_core::method`, not a bare builder: these four are Node's
        // `SetMethod`, which passes `ConstructorBehavior::kThrow`, so
        // `new binding.crypto.publicEncrypt(...)` is a `TypeError` on Node.
        // A bare `FunctionTemplate::builder` defaults to `Allow`, which made
        // every one of them constructible here and not there.
        let function = match operation {
            public_key::Cipher::Encrypt => rn_core::method(public_encrypt).build(scope),
            public_key::Cipher::Decrypt => rn_core::method(private_decrypt).build(scope),
            public_key::Cipher::Sign => rn_core::method(private_encrypt).build(scope),
            public_key::Cipher::Recover => rn_core::method(public_decrypt).build(scope),
        }
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate crypto.{name}"))?;
        set(scope, target, name, function.into())?;
    }
    Ok(())
}

/// One function per member, because `FunctionTemplate::builder` needs the item
/// type: V8's trampoline is generic over a zero-sized unit type and a `fn`
/// pointer is not zero-sized, so a single function taking the operation as an
/// argument cannot be installed four times.
fn public_encrypt<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    run_public_key(scope, &args, &mut rv, public_key::Cipher::Encrypt);
}

fn private_decrypt<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    run_public_key(scope, &args, &mut rv, public_key::Cipher::Decrypt);
}

fn private_encrypt<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    run_public_key(scope, &args, &mut rv, public_key::Cipher::Sign);
}

fn public_decrypt<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    run_public_key(scope, &args, &mut rv, public_key::Cipher::Recover);
}

/// Runs one operation and reports its outcome as Node does.
fn run_public_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    cipher: public_key::Cipher,
) {
    match public_key::run(scope, args, cipher) {
        Ok(bytes) => match public_key::emit(scope, &bytes) {
            Some(buffer) => rv.set(buffer),
            None => throw_message(scope, "Could not allocate the result buffer"),
        },
        Err(public_key::CryptoFailure::Thrown) => {
            // The key decoder threw; its exception is the one the caller must
            // see, so nothing is replaced here.
        }
        Err(public_key::CryptoFailure::InvalidArgument(message)) => {
            throw_coded(scope, &message, "ERR_INVALID_ARG_VALUE");
        }
        Err(public_key::CryptoFailure::InvalidDigest) => {
            throw_coded(scope, "Invalid digest used", "ERR_OSSL_EVP_INVALID_DIGEST");
        }
        Err(public_key::CryptoFailure::Message(message)) => throw_message(scope, &message),
        Err(public_key::CryptoFailure::OpenSsl(packed)) => {
            // `ThrowCryptoError`: the message is `ERR_error_string_n`'s output
            // rather than a caller-supplied one.
            throw_openssl(scope, packed);
        }
    }
}

/// Throws `ThrowCryptoError`'s shape for a packed OpenSSL value.
///
/// The value was captured at the failure site because `openssl`'s helpers drain
/// the queue into an `ErrorStack`: reading `ERR_peek_error` here would see
/// nothing and every failure would report `ERR_CRYPTO_OPERATION_FAILED`. When
/// there is no value at all — an operation that failed without a reason — Node's
/// fallback is exactly that code, so the two paths agree.
fn throw_openssl(scope: &mut v8::PinScope<'_, '_>, packed: u64) {
    let Some(detail) = rn_crypto_openssl::openssl_error_for(packed) else {
        throw_coded(scope, "Unspecified error", "ERR_CRYPTO_OPERATION_FAILED");
        return;
    };
    let message = detail.message.clone();
    let Some(text) = v8::String::new(scope, &message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    for (name, value) in [
        ("code", detail.code()),
        ("library", detail.library_display.clone()),
        ("reason", detail.reason.clone()),
    ] {
        if let (Some(key), Some(value)) =
            (v8::String::new(scope, name), v8::String::new(scope, &value))
        {
            object.set(scope, key.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Throws an `Error` carrying a `.code`.
fn throw_coded(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = if code == "ERR_INVALID_ARG_VALUE" {
        v8::Exception::type_error(scope, text)
    } else {
        v8::Exception::error(scope, text)
    };
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let (Some(key), Some(value)) =
            (v8::String::new(scope, "code"), v8::String::new(scope, code))
        {
            object.set(scope, key.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Throws a plain `Error`.
fn throw_message(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
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
