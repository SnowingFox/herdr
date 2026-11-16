//! `publicEncrypt`, `privateDecrypt`, `privateEncrypt` and `publicDecrypt`.
//!
//! `src/crypto/crypto_cipher.cc` installs these four in `CipherBase::Initialize`
//! as four instantiations of one template — `PublicKeyCipher::Cipher<operation,
//! cipher>` — so they are one implementation here as well:
//!
//! | member | key type | `EVP_PKEY_*` |
//! | --- | --- | --- |
//! | `publicEncrypt` | public | `encrypt` |
//! | `privateDecrypt` | private | `decrypt` |
//! | `privateEncrypt` | private | `sign` |
//! | `publicDecrypt` | public | `verify_recover` |
//!
//! The two pairs are mirror images: `publicEncrypt`/`privateDecrypt` is ordinary
//! public-key encryption with the public operation first, and
//! `privateEncrypt`/`publicDecrypt` is the signature-shaped "encrypt with the
//! private key so anyone can recover it" operation. They share every argument
//! and both paddings, which is why one function covers all four.
//!
//! # Why the members were missing rather than broken
//!
//! `lib/internal/crypto/cipher.js` destructures all four from the binding at
//! module scope:
//!
//! ```text
//! const {
//!   CipherBase,
//!   privateDecrypt: _privateDecrypt,
//!   ...
//! } = internalBinding('crypto');
//! ```
//!
//! A destructuring of an absent member binds `undefined`, which is why
//! `require('crypto')` loaded and only the first `publicEncrypt(...)` call threw
//! `TypeError: method is not a function` — the deferral was invisible until the
//! call. `rsaFunctionFor` then applies the default padding per member.
//!
//! # The argument layout is the key decode's, not this module's
//!
//! `PublicKeyCipher::Cipher` calls `KeyObjectData::GetPublicOrPrivateKeyFromJs`
//! and then reads from wherever that left the offset. The key occupies five
//! slots (data, format, type, passphrase, namedCurve), so the buffer is at
//! `offset`, the padding at `offset + 1`, `oaepHash` at `offset + 2`, `oaepLabel`
//! at `offset + 3` and `mgf1Hash` at `offset + 4`. Reading them at fixed indices
//! would break the moment the key format changes how many slots it consumed,
//! which is exactly why the offset is threaded rather than guessed.

use foreign_types::ForeignType;
use rn_bind_crypto_keys::{read_key_from_js, KeyType};
use rn_v8_sys::v8;

use crate::evp_binding::buffer_from_public;

/// Which key the operation needs.
///
/// This is `PublicKeyCipher::kPublic`/`kPrivate` and it decides two things: the
/// key type `GetPublicOrPrivateKeyFromJs` is asked for, and whether
/// `RSA_PKCS1_PADDING` needs implicit rejection (a private decrypt only).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Operation {
    Public,
    Private,
}

/// The four `EVP_PKEY_*` operations, named after the member that exposes them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cipher {
    /// `publicEncrypt`: `EVP_PKEY_encrypt`.
    Encrypt,
    /// `privateDecrypt`: `EVP_PKEY_decrypt`.
    Decrypt,
    /// `privateEncrypt`: `EVP_PKEY_sign` over the padded block.
    Sign,
    /// `publicDecrypt`: `EVP_PKEY_verify_recover`.
    Recover,
}

impl Cipher {
    /// The member name, for error messages and the install table.
    pub fn member(self) -> &'static str {
        match self {
            Self::Encrypt => "publicEncrypt",
            Self::Decrypt => "privateDecrypt",
            Self::Sign => "privateEncrypt",
            Self::Recover => "publicDecrypt",
        }
    }

    /// Which key this operation reads, which is `kPublic`/`kPrivate` in Node.
    ///
    /// `encrypt` and `recover` are public operations and the other two private.
    /// Node passes it as the `template` parameter rather than deriving it, and
    /// the two agree, so deriving it here keeps them from disagreeing.
    pub fn operation(self) -> Operation {
        match self {
            Self::Encrypt | Self::Recover => Operation::Public,
            Self::Decrypt | Self::Sign => Operation::Private,
        }
    }
}

/// `RSA_PKCS1_PADDING` from OpenSSL's `rsa.h`.
const RSA_PKCS1_PADDING: i32 = 1;

/// `EVP_PKEY_CTX_ctrl_str`, which the safe `openssl` crate does not wrap.
///
/// Only one control is used through it — `rsa_pkcs1_implicit_rejection` — and it
/// has no `EVP_PKEY_CTX_set_*` sibling, so the string form is the only way to
/// reach it. Declared here rather than reached for at the call site so the FFI
/// signature is in one place.
mod ffi {
    extern "C" {
        /// Sets a control by name. Returns `1` when the control was accepted, a
        /// negative value when the key type does not support it.
        pub fn EVP_PKEY_CTX_ctrl_str(
            context: *mut openssl_sys::EVP_PKEY_CTX,
            name: *const std::os::raw::c_char,
            value: *const std::os::raw::c_char,
        ) -> std::os::raw::c_int;
    }
}

/// Runs one of the four operations and returns the bytes.
///
/// The error is the message only; the caller throws it and the packed OpenSSL
/// value is picked up from the queue by `throw_crypto_error`, which is what
/// `ThrowCryptoError` does on the thread that failed.
pub fn run(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    cipher: Cipher,
) -> Result<Vec<u8>, CryptoFailure> {
    // The key occupies five slots and the reader advances the offset past them,
    // so everything after this is relative to where the key ended.
    let mut offset = 0usize;
    let Some(data) = read_key_from_js(scope, args, &mut offset, KeyType::Public) else {
        // `read_key_from_js` threw, so the pending exception is the result.
        return Err(CryptoFailure::Thrown);
    };
    let Some(key) = data.asymmetric_key() else {
        return Err(CryptoFailure::Message("Invalid key type".to_string()));
    };

    let Some(buffer) = view_bytes(args.get(offset as i32)) else {
        return Err(CryptoFailure::Message(
            "The buffer argument must be an ArrayBuffer or a typed array".to_string(),
        ));
    };
    // `args[offset + 1]->Uint32Value`: `undefined` becomes 0, which is not a
    // valid padding and is rejected by OpenSSL rather than being defaulted —
    // `cipher.js` always passes an explicit one from `key.padding`.
    let padding = args.get(offset as i32 + 1).uint32_value(scope).unwrap_or(0) as i32;

    // `oaepHash` and `mgf1Hash` are strings when present. An absent one leaves
    // the context's default (SHA-1 for OAEP, the OAEP digest for MGF1), which is
    // what Node relies on.
    let oaep_hash = string_of(scope, args.get(offset as i32 + 2));
    let oaep_label = if args.get(offset as i32 + 3).is_undefined() {
        None
    } else {
        match view_bytes(args.get(offset as i32 + 3)) {
            Some(label) => Some(label),
            None => {
                return Err(CryptoFailure::Message(
                    "The oaepLabel argument must be an ArrayBuffer or a typed array".to_string(),
                ))
            }
        }
    };
    let mgf1_hash = string_of(scope, args.get(offset as i32 + 4));

    operate(
        key,
        cipher,
        padding,
        oaep_hash.as_deref(),
        oaep_label.as_deref(),
        mgf1_hash.as_deref(),
        &buffer,
    )
}

/// The core operation, with no V8 types: what `ncrypto::CipherImpl` does.
///
/// Separate from [`run`] so the OpenSSL sequence is readable and so the same
/// code serves `RSACipherJob`, which carries its arguments rather than reading
/// them.
pub fn operate(
    key: &rn_crypto_openssl::PKey,
    cipher: Cipher,
    padding: i32,
    oaep_hash: Option<&str>,
    oaep_label: Option<&[u8]>,
    mgf1_hash: Option<&str>,
    input: &[u8],
) -> Result<Vec<u8>, CryptoFailure> {
    // `pkey.newCtx()`: a context over the key, with no engine.
    let mut context = key
        .new_ctx()
        .ok_or_else(|| CryptoFailure::Message("Failed to create a key context".to_string()))?;

    // `EVP_PKEY_*_init`, one per operation. Doing this before the padding is
    // load-bearing: `EVP_PKEY_CTX_set_rsa_padding` fails with
    // `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` on a fresh context, so a
    // context that has not been initialised cannot be configured.
    let initialised = match cipher {
        Cipher::Encrypt => context.encrypt_init(),
        Cipher::Decrypt => context.decrypt_init(),
        Cipher::Sign => context.sign_init(),
        Cipher::Recover => context.verify_recover_init(),
    };
    initialised.map_err(|stack| CryptoFailure::OpenSsl(packed_of(&stack)))?;

    // A private decrypt with PKCS#1 v1.5 padding needs implicit rejection
    // turned on, which is what makes a corrupted ciphertext produce a stable
    // pseudo-random plaintext instead of `ERR_OSSL_RSA_PKCS_DECODING_ERROR`.
    //
    // This is Node's behaviour and it is observable: decrypting a tampered
    // `publicEncrypt` result returns bytes rather than throwing, and
    // `test-crypto-rsa-oaep.js` and the PKCS#1 tests in `test/parallel` both rely
    // on it. OpenSSL 3.2 added the control and enables it by default, so the call
    // is normally a no-op confirmation; when the control is unsupported the
    // operation is refused, which is what `setRsaImplicitRejection` returning
    // false means in Node.
    if cipher == Cipher::Decrypt
        && cipher.operation() == Operation::Private
        && padding == RSA_PKCS1_PADDING
        && !set_implicit_rejection(&context)
    {
        return Err(CryptoFailure::InvalidArgument(
            "RSA_PKCS1_PADDING is no longer supported for private decryption".to_string(),
        ));
    }

    // `setRsaPadding` always runs, even when the value is the default, because
    // the caller's value is what decides between PKCS#1, OAEP and X9.31.
    context
        .set_rsa_padding(padding_from_raw(padding))
        .map_err(|stack| CryptoFailure::OpenSsl(packed_of(&stack)))?;

    if let Some(name) = oaep_hash {
        let digest = rn_crypto_openssl::digest_by_name(name).ok_or(CryptoFailure::InvalidDigest)?;
        context
            .set_rsa_oaep_md(digest)
            .map_err(|stack| CryptoFailure::OpenSsl(packed_of(&stack)))?;
    }
    if let Some(name) = mgf1_hash {
        let digest = rn_crypto_openssl::digest_by_name(name).ok_or(CryptoFailure::InvalidDigest)?;
        context
            .set_rsa_mgf1_md(digest)
            .map_err(|stack| CryptoFailure::OpenSsl(packed_of(&stack)))?;
    }
    // An empty label is not the same as no label: `set0_rsa_oaep_label` with a
    // zero-length allocation changes the OAEP parameters, and Node only calls it
    // when the buffer is non-empty (`params.label.len != 0`).
    if let Some(label) = oaep_label {
        if !label.is_empty() {
            context
                .set_rsa_oaep_label(label)
                .map_err(|stack| CryptoFailure::OpenSsl(packed_of(&stack)))?;
        }
    }

    // Two passes: the first asks for the output length, the second writes it.
    // `EVP_PKEY_encrypt`/`decrypt`/`sign`/`verify_recover` all follow that
    // contract, and `CipherImpl` does exactly this.
    let length = match cipher {
        Cipher::Encrypt => context.encrypt(input, None),
        Cipher::Decrypt => context.decrypt(input, None),
        Cipher::Sign => context.sign(input, None),
        Cipher::Recover => context.verify_recover(input, None),
    }
    .map_err(|stack| CryptoFailure::OpenSsl(packed_of(&stack)))?;

    let mut output = vec![0u8; length];
    let written = match cipher {
        Cipher::Encrypt => context.encrypt(input, Some(&mut output)),
        Cipher::Decrypt => context.decrypt(input, Some(&mut output)),
        Cipher::Sign => context.sign(input, Some(&mut output)),
        Cipher::Recover => context.verify_recover(input, Some(&mut output)),
    }
    .map_err(|stack| CryptoFailure::OpenSsl(packed_of(&stack)))?;
    output.truncate(written);
    Ok(output)
}

/// The packed `ERR_get_error` value from a drained error stack.
///
/// The first entry is the root cause, which is the one `ThrowCryptoError`
/// reports; `openssl`'s `Error::code` keeps the packed value verbatim. A stack
/// with no entries is 0, which the caller reports as
/// `ERR_CRYPTO_OPERATION_FAILED` — the same fallback Node uses.
fn packed_of(stack: &openssl::error::ErrorStack) -> u64 {
    stack.errors().first().map_or(0, |error| error.code())
}

/// Turns on `rsa_pkcs1_implicit_rejection` for a decrypt context.
///
/// Node's `setRsaImplicitRejection` calls
/// `EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pkcs1_implicit_rejection", "1")` and treats
/// a non-positive result as "unsupported". A negative return is
/// `EVP_PKEY_CTX_ctrl_str`'s `-2` for "this control is not supported by this key
/// type", which a non-RSA key produces.
fn set_implicit_rejection(context: &openssl::pkey_ctx::PkeyCtx<openssl::pkey::Private>) -> bool {
    // Both strings are `'static` and NUL-terminated, so they outlive the call.
    const NAME: &[u8] = b"rsa_pkcs1_implicit_rejection\0";
    const VALUE: &[u8] = b"1\0";
    // SAFETY: the context is live for the duration of the call, and both
    // arguments are NUL-terminated byte strings with static lifetime.
    unsafe {
        ffi::EVP_PKEY_CTX_ctrl_str(
            context.as_ptr(),
            NAME.as_ptr().cast(),
            VALUE.as_ptr().cast(),
        ) > 0
    }
}

/// Maps the caller's numeric padding onto the `openssl` crate's type.
///
/// `Padding::from_raw` is a newtype over the same `c_int` OpenSSL uses, so the
/// value is passed through untouched. That matters: the numbers come from
/// `binding.constants.crypto` in `lib/internal/crypto/util.js` and are OpenSSL's
/// own (`RSA_PKCS1_PADDING` 1, `RSA_PKCS1_OAEP_PADDING` 4,
/// `RSA_NO_PADDING` 3, ...). Translating through a fixed table would silently
/// map an unknown value onto a real padding; passing it through lets OpenSSL
/// reject it with the reason it actually has.
fn padding_from_raw(value: i32) -> openssl::rsa::Padding {
    openssl::rsa::Padding::from_raw(value)
}

/// Why one of the four operations failed.
///
/// Split because the JavaScript shapes differ: an OpenSSL failure becomes
/// `ThrowCryptoError` (code, library, reason from the queue), an invalid
/// argument is a coded `NodeError`, and `Thrown` means a JavaScript exception is
/// already pending and must be left alone.
pub enum CryptoFailure {
    /// An OpenSSL failure, carrying the packed value from the drained queue.
    ///
    /// The `openssl` crate moves the queue into the returned `ErrorStack`, so by
    /// the time the caller has the failure, `ERR_peek_error` sees nothing. The
    /// packed value is therefore captured here, at the failure site, and the
    /// caller builds `ThrowCryptoError` from it — with a later read from the
    /// queue the code and reason would be missing and every failure would come
    /// out as `ERR_CRYPTO_OPERATION_FAILED`.
    OpenSsl(u64),
    /// `ERR_INVALID_ARG_VALUE` with the caller's message.
    InvalidArgument(String),
    /// `ERR_OSSL_EVP_INVALID_DIGEST`.
    InvalidDigest,
    /// A message with no code, thrown as a plain `Error`.
    Message(String),
    /// `read_key_from_js` threw; the pending exception is the result.
    Thrown,
}

/// Reads a string argument, or `None` when it is absent.
fn string_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<'_, v8::Value>) -> Option<String> {
    if value.is_undefined() || value.is_null() {
        return None;
    }
    let text = v8::Local::<v8::String>::try_from(value).ok()?;
    Some(text.to_rust_string_lossy(scope))
}

/// Copies the bytes behind a buffer source.
fn view_bytes(value: v8::Local<'_, v8::Value>) -> Option<Vec<u8>> {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let length = view.byte_length();
        let mut bytes = vec![0u8; length];
        let copied = view.copy_contents(&mut bytes);
        bytes.truncate(copied);
        return Some(bytes);
    }
    let buffer = v8::Local::<v8::ArrayBuffer>::try_from(value).ok()?;
    let store = buffer.get_backing_store();
    let length = buffer.byte_length();
    let mut bytes = vec![0u8; length];
    if length > 0 {
        let data = store.data()?;
        // SAFETY: `data` points at `length` bytes owned by `store`, which is
        // alive for this call, and the copy completes before returning.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), length);
        }
    }
    Some(bytes)
}

/// Emits the result as a `Buffer`, which is what every caller expects.
pub fn emit<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    buffer_from_public(scope, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_members_are_the_four_cipher_js_destructures() {
        // `lib/internal/crypto/cipher.js` reads these four names at module
        // scope. A rename here binds `undefined` there, which loads cleanly and
        // fails on the first call with `method is not a function`.
        assert_eq!(Cipher::Encrypt.member(), "publicEncrypt");
        assert_eq!(Cipher::Decrypt.member(), "privateDecrypt");
        assert_eq!(Cipher::Sign.member(), "privateEncrypt");
        assert_eq!(Cipher::Recover.member(), "publicDecrypt");
    }

    #[test]
    fn the_operations_pair_the_way_node_pairs_them() {
        // `PublicKeyCipher::Cipher<kPublic, encrypt>` and
        // `<kPrivate, decrypt>` are the encrypt/decrypt pair;
        // `<kPrivate, sign>` and `<kPublic, recover>` are the other direction.
        // Swapping either would make `privateDecrypt` take a public key, which
        // OpenSSL rejects with an unhelpful message.
        assert_eq!(Cipher::Encrypt.operation(), Operation::Public);
        assert_eq!(Cipher::Decrypt.operation(), Operation::Private);
        assert_eq!(Cipher::Sign.operation(), Operation::Private);
        assert_eq!(Cipher::Recover.operation(), Operation::Public);
    }

    #[test]
    fn the_padding_values_are_openssls() {
        // These are `rsa.h`'s and `cipher.js` passes them back verbatim after
        // reading them from `binding.constants.crypto`. The value goes straight
        // through rather than being mapped, so an unknown one reaches OpenSSL and
        // fails there with the real reason instead of becoming a valid padding.
        assert_eq!(RSA_PKCS1_PADDING, 1);
        for raw in [1, 3, 4, 5, 6, 99] {
            assert_eq!(padding_from_raw(raw).as_raw(), raw);
        }
    }
}
