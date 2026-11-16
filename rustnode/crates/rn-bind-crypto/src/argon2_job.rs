//! `Argon2Job`: `crypto.argon2`, `crypto.argon2Sync` and the WebCrypto
//! `Argon2` derive-bits path.
//!
//! `src/crypto/crypto_argon2.cc` is the source. It is compiled only when
//! `OPENSSL_WITH_ARGON2` is set, and when it is not the JavaScript sees
//! `Argon2Job === undefined` and `argon2()` throws
//! `ERR_CRYPTO_ARGON2_NOT_SUPPORTED`. That conditional exists because OpenSSL
//! gained Argon2 in 3.2, and whether a build has it is a configure option.
//!
//! # Why the deferral for this job was wrong
//!
//! It said "OpenSSL's Argon2 provider, which `openssl-src` does not build". The
//! provider is built: `openssl-src` compiles `providers/implementations/kdfs/
//! argon2.c` into `libdefault.a` (the `$ARGON2_GOAL` in that directory's
//! `build.info`), and `openssl::kdf::argon2id` links and produces Node's exact
//! bytes for all three variants. The reason was a guess about the dependency
//! rather than a measurement of it, which is exactly what a deferral must not be.
//!
//! # The argument layout
//!
//! ```text
//! new Argon2Job(mode, pass, salt, lanes, keylen, memcost, iter, secret, ad, type)
//! ```
//!
//! `pass` is a buffer for the traditional API and a `KeyObjectHandle` for the
//! WebCrypto one, which is why the first slot is checked for both. `type` is a
//! `kTypeArgon2*` value that `argon2.js` reads off the namespace.

use rn_crypto_job::{CryptoJobError, JobMode, Runnable};
use rn_v8_sys::v8;

use crate::encoding;

/// `ncrypto::Argon2Type`: `ARGON2D`, `ARGON2I`, `ARGON2ID`.
///
/// The numbers are the order of that enum in `ncrypto.h`, and `argon2.js`
/// passes one of the `kTypeArgon2*` members the namespace exports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Argon2Type {
    D,
    I,
    Id,
}

impl Argon2Type {
    /// Reads a `kTypeArgon2*` value.
    pub fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::D,
            1 => Self::I,
            2 => Self::Id,
            _ => return None,
        })
    }

    /// The name `argon2.js` validates against, for error messages.
    pub fn name(self) -> &'static str {
        match self {
            Self::D => "argon2d",
            Self::I => "argon2i",
            Self::Id => "argon2id",
        }
    }
}

/// One Argon2 derivation's parameters.
pub struct Argon2Job {
    pass: Vec<u8>,
    salt: Vec<u8>,
    lanes: u32,
    keylen: u32,
    memcost: u32,
    iter: u32,
    secret: Option<Vec<u8>>,
    ad: Option<Vec<u8>>,
    kind: Argon2Type,
}

impl Argon2Job {
    /// Reads the ten constructor arguments.
    ///
    /// `pass` may be a `KeyObjectHandle`, which is what the WebCrypto path
    /// passes; the symmetric bytes are read out of it by its `export` method,
    /// exactly as `AESCipherJob` does. Node's `AdditionalConfig` only checks
    /// `KeyObjectHandle::HasInstance(args[offset])` and otherwise treats the
    /// value as a buffer, so both shapes are accepted here.
    pub fn from_arguments<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        args: &v8::FunctionCallbackArguments<'s>,
        mode: JobMode,
    ) -> Option<Self> {
        let _ = mode;
        let Some(pass) = secret_or_bytes(scope, args.get(1)) else {
            crate::install::throw_type_error(
                scope,
                "The pass argument must be an ArrayBufferView or a KeyObjectHandle",
            );
            return None;
        };
        let Some(Some(salt)) = optional_bytes(scope, args.get(2)) else {
            crate::install::throw_type_error(scope, "The salt argument must be an ArrayBufferView");
            return None;
        };
        let lanes = args.get(3).uint32_value(scope).unwrap_or(0);
        let keylen = args.get(4).uint32_value(scope).unwrap_or(0);
        let memcost = args.get(5).uint32_value(scope).unwrap_or(0);
        let iter = args.get(6).uint32_value(scope).unwrap_or(0);
        // `secret` and `ad` are absent in the traditional API (an empty buffer
        // arrives instead) and present only in the WebCrypto form.
        let Some(secret) = optional_bytes(scope, args.get(7)) else {
            crate::install::throw_type_error(
                scope,
                "The secret argument must be an ArrayBufferView",
            );
            return None;
        };
        let Some(ad) = optional_bytes(scope, args.get(8)) else {
            crate::install::throw_type_error(
                scope,
                "The associatedData argument must be an ArrayBufferView",
            );
            return None;
        };
        let Some(kind) = Argon2Type::from_raw(args.get(9).int32_value(scope).unwrap_or(-1)) else {
            crate::install::throw_type_error(scope, "Unsupported Argon2 type");
            return None;
        };
        Some(Self {
            pass,
            salt,
            lanes,
            keylen,
            memcost,
            iter,
            // An empty `secret`/`ad` means "not supplied": Node only sets the
            // parameter when `len != 0`, and an explicit empty parameter is not
            // the same as an absent one to the provider.
            secret: secret.filter(|bytes| !bytes.is_empty()),
            ad: ad.filter(|bytes| !bytes.is_empty()),
            kind,
        })
    }
}

impl Runnable for Argon2Job {
    type Output = Vec<u8>;

    fn run(&mut self) -> Result<Self::Output, CryptoJobError> {
        // `DeriveBits` returns an empty buffer for a zero-length tag without
        // touching OpenSSL, "useless, yes, but allowed via the API".
        if self.keylen == 0 {
            return Ok(Vec::new());
        }
        let mut output = vec![0u8; self.keylen as usize];
        let result = match self.kind {
            Argon2Type::D => openssl::kdf::argon2d(
                None,
                &self.pass,
                &self.salt,
                self.ad.as_deref(),
                self.secret.as_deref(),
                self.iter,
                self.lanes,
                self.memcost,
                &mut output,
            ),
            Argon2Type::I => openssl::kdf::argon2i(
                None,
                &self.pass,
                &self.salt,
                self.ad.as_deref(),
                self.secret.as_deref(),
                self.iter,
                self.lanes,
                self.memcost,
                &mut output,
            ),
            Argon2Type::Id => openssl::kdf::argon2id(
                None,
                &self.pass,
                &self.salt,
                self.ad.as_deref(),
                self.secret.as_deref(),
                self.iter,
                self.lanes,
                self.memcost,
                &mut output,
            ),
        };
        result.map_err(|stack| {
            crate::random_jobs::stack_error_named(&stack, "Failed to derive key")
        })?;
        Ok(output)
    }

    fn finish<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        // `Argon2Traits::EncodeOutput` is `out->ToArrayBuffer(env)`, so the
        // result is an `ArrayBuffer` and `argon2.js` wraps it in a `Buffer`.
        encoding::array_buffer(scope, &output).map(v8::Local::into)
    }
}

/// Reads a `KeyObjectHandle`'s symmetric bytes, or a buffer source.
fn secret_or_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Vec<u8>> {
    if let Some(bytes) = buffer_bytes(value) {
        return Some(bytes);
    }
    // The WebCrypto form passes the handle. `export()` on a secret handle returns
    // the raw key bytes; the shape check is duck-typed for the reason
    // `AESCipherJob` records, so a handle whose methods change fails loudly.
    let handle = v8::Local::<v8::Object>::try_from(value).ok()?;
    let exported = call_method(scope, handle, "export")?;
    buffer_bytes(exported)
}

/// Calls a zero-argument method on `object`.
fn call_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    let function = object.get(scope, key.into())?;
    let function = v8::Local::<v8::Function>::try_from(function).ok()?;
    function.call(scope, object.into(), &[])
}

/// Reads an optional buffer argument.
///
/// `Some(None)` for `undefined`/`null`, which is how the WebCrypto form passes
/// "no secret". `None` for a value that is present but not a buffer, which the
/// caller reports.
fn optional_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Option<Vec<u8>>> {
    let _ = scope;
    if value.is_undefined() || value.is_null() {
        return Some(None);
    }
    buffer_bytes(value).map(Some)
}

/// Copies the bytes behind a buffer source.
fn buffer_bytes(value: v8::Local<'_, v8::Value>) -> Option<Vec<u8>> {
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
        // SAFETY: `data` points at `length` bytes owned by `store`, alive here.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), length);
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_types_are_ncryptos_enum_order() {
        // `enum class Argon2Type { ARGON2D, ARGON2I, ARGON2ID }` in
        // `ncrypto.h`. `argon2.js` maps its string names onto these through
        // `kTypeArgon2*`, so a swap would silently derive with the wrong variant
        // — and the two non-id variants are not interchangeable.
        assert_eq!(Argon2Type::from_raw(0), Some(Argon2Type::D));
        assert_eq!(Argon2Type::from_raw(1), Some(Argon2Type::I));
        assert_eq!(Argon2Type::from_raw(2), Some(Argon2Type::Id));
        assert_eq!(Argon2Type::from_raw(3), None);
    }

    #[test]
    fn the_three_variants_produce_nodes_bytes() {
        // The expected values are what real `node` produces for these
        // parameters (`argon2Sync` for each of the three names), which is the
        // only way to know the parameter plumbing is right: the provider will
        // happily derive *something* for a wrong `lanes`/`memcost`/`iter`
        // assignment.
        let cases = [
            (
                "ebb fe7d9 520f cb0c 2f28 ab7b 7b0e 1aee 3b52 1c5e 8c31 be07 6727 3a98 8adc 04e5",
                Argon2Type::D,
            ),
            (
                "89d 62790 b796 494d 9064 c467 7b49 4f5b da1d cfc2 4078 9482 ce47 10dc 047c 3103",
                Argon2Type::I,
            ),
            (
                "f1f6c2617b3cc4ae1447b6f87cd371ea3e824d2df86bf300c587a30ee8326360",
                Argon2Type::Id,
            ),
        ];
        for (expected, kind) in cases {
            let expected: String = expected.chars().filter(|c| *c != ' ').collect();
            let mut job = Argon2Job {
                pass: b"password".to_vec(),
                salt: vec![1u8; 16],
                lanes: 1,
                keylen: 32,
                memcost: 64,
                iter: 2,
                secret: None,
                ad: None,
                kind,
            };
            let output = job.run().expect("derive");
            let hex: String = output.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, expected, "{}", kind.name());
        }
    }

    #[test]
    fn a_zero_length_tag_is_an_empty_result() {
        // `DeriveBits` short-circuits before OpenSSL for `keylen == 0`, so this
        // must not reach the provider — a zero-length output is rejected there.
        let mut job = Argon2Job {
            pass: b"password".to_vec(),
            salt: vec![1u8; 16],
            lanes: 1,
            keylen: 0,
            memcost: 64,
            iter: 2,
            secret: None,
            ad: None,
            kind: Argon2Type::Id,
        };
        assert_eq!(job.run(), Ok(Vec::new()));
    }
}
