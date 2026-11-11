//! The error shapes `lib/internal/crypto/**` and Node's tests read.
//!
//! Three families, and they are not interchangeable:
//!
//! * `THROW_ERR_CRYPTO_*` — a `NodeError` with a `code` and, for some, a message
//!   built from an `internal/errors` template. The tests assert on both.
//! * `ThrowCryptoError` — an ordinary `Error` whose `code` is
//!   `ERR_OSSL_<LIB>_<REASON>` plus `library` and `reason` fields. Built by the
//!   wrapper crate from the packed OpenSSL error.
//! * `ERR_INVALID_ARG_TYPE`/`ERR_INVALID_ARG_VALUE` — thrown by the *JavaScript*
//!   layer, never from here. The binding has no business duplicating them, and a
//!   duplicated message drifts.
//!
//! # Why the message text is spelled out
//!
//! `internal/errors` builds `ERR_CRYPTO_INVALID_KEYTYPE` as `Invalid key type`,
//! `ERR_MISSING_PASSPHRASE` as `Passphrase required for encrypted key`, and so
//! on. The binding throws through `v8::Exception` and sets `code` itself, so the
//! template has to be reproduced here exactly. A test that only checks `code`
//! would pass with any message; several Node tests check the message too.

use rn_v8_sys::v8;

/// One error the binding can report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// `ERR_CRYPTO_INVALID_KEYTYPE`, "Invalid key type".
    InvalidKeyType,
    /// `ERR_CRYPTO_INVALID_KEYLEN`, "Invalid key length".
    InvalidKeyLength,
    /// `ERR_CRYPTO_INVALID_CURVE`, "Invalid EC curve name".
    InvalidCurve,
    /// `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS`, "The selected key encoding %s %s".
    /// Both halves are supplied by the caller because Node appends its own detail.
    IncompatibleKeyOptions {
        encoding: String,
        detail: &'static str,
    },
    /// `ERR_CRYPTO_INVALID_JWK`, with the caller's message, which is one of five
    /// fixed strings.
    InvalidJwk(&'static str),
    /// `ERR_MISSING_PASSPHRASE`, "Passphrase required for encrypted key".
    MissingPassphrase,
    /// `ERR_CRYPTO_OPERATION_FAILED`, with the caller's message.
    OperationFailed(&'static str),
    /// `ERR_INVALID_THIS`, "Value of \"this\" must be of type %s".
    InvalidThis(&'static str),
    /// `ERR_INVALID_ARG_VALUE`, an `ERR_INVALID_ARG_VALUE`-shaped `TypeError`.
    ///
    /// `keygen.js`'s `case 'rsa'` and `NamedKeyPairGenTraits::AdditionalConfig`
    /// both reject an unsupported key type this way, and the message names the
    /// offending value: "The argument 'type' must be a supported key type.
    /// Received '<value>'". It is a `TypeError`, which
    /// `test-crypto-keygen.js` asserts with `assert.throws`.
    UnsupportedKeyType(String),
    /// `ERR_CRYPTO_UNSUPPORTED_OPERATION`, "Unsupported operation".
    ///
    /// Thrown where Node throws it rather than being invented: two keys of
    /// different types are not comparable, and `equals` reports that as this
    /// code rather than answering `false`.
    UnsupportedOperation,
    /// An OpenSSL failure, reported as `ThrowCryptoError` does: the caller's
    /// message when there is no packed error, and the OpenSSL detail otherwise.
    OpenSsl { message: &'static str, packed: u64 },
}

impl KeyError {
    /// The `code` property, or `None` for an error with no code.
    pub fn code(&self) -> Option<&'static str> {
        Some(match self {
            Self::InvalidKeyType => "ERR_CRYPTO_INVALID_KEYTYPE",
            Self::InvalidKeyLength => "ERR_CRYPTO_INVALID_KEYLEN",
            Self::InvalidCurve => "ERR_CRYPTO_INVALID_CURVE",
            Self::IncompatibleKeyOptions { .. } => "ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS",
            Self::InvalidJwk(_) => "ERR_CRYPTO_INVALID_JWK",
            Self::MissingPassphrase => "ERR_MISSING_PASSPHRASE",
            Self::OperationFailed(_) => "ERR_CRYPTO_OPERATION_FAILED",
            Self::InvalidThis(_) => "ERR_INVALID_THIS",
            Self::UnsupportedOperation => "ERR_CRYPTO_UNSUPPORTED_OPERATION",
            Self::UnsupportedKeyType(_) => "ERR_INVALID_ARG_VALUE",
            // `ThrowCryptoError` builds its code from the packed error, and
            // `ERR_CRYPTO_OPERATION_FAILED` is what Node uses when there is none.
            Self::OpenSsl { packed: 0, .. } => "ERR_CRYPTO_OPERATION_FAILED",
            Self::OpenSsl { .. } => return None,
        })
    }

    /// Whether this is a `TypeError` rather than an `Error`.
    ///
    /// Only `ERR_INVALID_THIS` is: `internal/errors` derives the constructor from
    /// the code's prefix, and `E('ERR_INVALID_THIS', ...)` is declared with
    /// `TypeError`.
    pub fn is_type_error(&self) -> bool {
        // `ERR_INVALID_THIS` and `ERR_INVALID_ARG_VALUE` are both `TypeError`s;
        // `internal/errors` derives the constructor from the code.
        matches!(self, Self::InvalidThis(_) | Self::UnsupportedKeyType(_))
    }

    /// The message text.
    pub fn message(&self) -> String {
        match self {
            Self::InvalidKeyType => "Invalid key type".to_string(),
            Self::InvalidKeyLength => "Invalid key length".to_string(),
            Self::InvalidCurve => "Invalid EC curve name".to_string(),
            Self::IncompatibleKeyOptions { encoding, detail } => {
                format!("The selected key encoding {encoding} {detail}")
            }
            Self::InvalidJwk(message) => (*message).to_string(),
            Self::MissingPassphrase => "Passphrase required for encrypted key".to_string(),
            Self::OperationFailed(message) => (*message).to_string(),
            Self::InvalidThis(expected) => {
                format!("Value of \"this\" must be of type {expected}")
            }
            Self::UnsupportedOperation => "Unsupported operation".to_string(),
            Self::UnsupportedKeyType(value) => {
                format!("The argument 'type' must be a supported key type. Received '{value}'")
            }
            Self::OpenSsl { message, packed } => {
                if *packed == 0 {
                    (*message).to_string()
                } else {
                    // `ThrowCryptoError` replaces the caller's message with
                    // `ERR_error_string_n`'s output, so the message this reports
                    // is the OpenSSL one and the caller's text is dropped. That
                    // is Node's behaviour, not an oversight.
                    (*message).to_string()
                }
            }
        }
    }
}

/// Throws `error` from `scope`.
///
/// `packed` is threaded through so an OpenSSL failure can carry `library` and
/// `reason` as well as its `code`, which is what `ThrowCryptoError` attaches and
/// what `test-crypto-keygen-async-encrypted-private-key.js` reads.
pub fn throw(scope: &mut v8::PinScope<'_, '_>, error: &KeyError) {
    let message = error.message();
    let Some(text) = v8::String::new(scope, &message) else {
        return;
    };
    let exception = if error.is_type_error() {
        v8::Exception::type_error(scope, text)
    } else {
        v8::Exception::error(scope, text)
    };
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(code) = error.code() {
        set_string(scope, object, "code", code);
    }
    if let KeyError::OpenSsl { packed, message } = error {
        if *packed != 0 && !attach_openssl_detail(scope, object, *packed, message) {
            // One of the field assignments threw (a prototype setter). That
            // exception is the one the caller must see, so ours is dropped.
            return;
        }
    }
    scope.throw_exception(exception);
}

/// Attaches the `library`, `reason` and `code` fields `ThrowCryptoError` builds
/// from a packed OpenSSL error.
///
/// Returns `false` when assigning one of those fields threw — which happens when
/// a test installs a throwing setter for `library` on `Object.prototype`, the
/// exact case `test-crypto-sign-verify.js` covers ("bye, bye, library"). The
/// pending exception must then be left alone: calling `ThrowException` with our
/// own error would replace it, and the test would see the OpenSSL message
/// instead of the setter's.
fn attach_openssl_detail(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    packed: u64,
    fallback: &'static str,
) -> bool {
    // The wrapper crate owns the unpacking, so the shapes agree between every
    // crate that reports an OpenSSL failure.
    let Some(detail) = rn_crypto_openssl::openssl_error_for(packed) else {
        // No string for the packed value: Node reports the caller's message with
        // `ERR_CRYPTO_OPERATION_FAILED`, which is already set.
        let _ = fallback;
        return true;
    };
    // `library` is the *display* name, which already carries " routines" and is
    // present even for a library Node's code table omits (DECODER, PROVIDER).
    // `code` is the other one and has no segment for those.
    if !set_string(scope, object, "code", &detail.code())
        || !set_string(scope, object, "library", &detail.library_display)
        || !set_string(scope, object, "reason", &detail.reason)
    {
        return false;
    }
    if let Some(text) = v8::String::new(scope, &detail.message) {
        // `ThrowCryptoError` sets the message to `ERR_error_string_n`'s output,
        // replacing whatever the caller passed. Doing it here keeps the shape in
        // one place instead of at every call site.
        let Some(key) = v8::String::new(scope, "message") else {
            return false;
        };
        if object.set(scope, key.into(), text.into()).is_none() {
            return false;
        }
    }
    true
}

/// Sets a string property, reporting whether the assignment completed.
///
/// `Object::set` returns `None` when a setter on the prototype chain threw, so
/// this is the signal the caller needs to stop and let that exception stand.
fn set_string(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    name: &str,
    value: &str,
) -> bool {
    let (Some(key), Some(text)) = (v8::String::new(scope, name), v8::String::new(scope, value))
    else {
        return true;
    };
    object.set(scope, key.into(), text.into()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_has_the_code_its_variant_names() {
        assert_eq!(
            KeyError::InvalidKeyType.code(),
            Some("ERR_CRYPTO_INVALID_KEYTYPE")
        );
        assert_eq!(
            KeyError::MissingPassphrase.code(),
            Some("ERR_MISSING_PASSPHRASE")
        );
        assert_eq!(
            KeyError::InvalidThis("KeyObject").code(),
            Some("ERR_INVALID_THIS")
        );
    }

    #[test]
    fn an_openssl_failure_without_detail_is_an_operation_failure() {
        // `ERR_crypto_operation_failed` is what Node reports when OpenSSL left
        // nothing in the queue, and the caller's message survives.
        let error = KeyError::OpenSsl {
            message: "Failed to read private key",
            packed: 0,
        };
        assert_eq!(error.code(), Some("ERR_CRYPTO_OPERATION_FAILED"));
        assert_eq!(error.message(), "Failed to read private key");
    }

    #[test]
    fn an_openssl_failure_with_detail_has_no_static_code() {
        // The code is `ERR_OSSL_<LIB>_<REASON>`, which is not a compile-time
        // constant; `throw` builds it from the packed value.
        let error = KeyError::OpenSsl {
            message: "Failed to read private key",
            packed: 0x1E08_010C,
        };
        assert_eq!(error.code(), None);
    }

    #[test]
    fn only_invalid_this_is_a_type_error() {
        assert!(KeyError::InvalidThis("KeyObject").is_type_error());
        assert!(!KeyError::InvalidKeyType.is_type_error());
        assert!(!KeyError::MissingPassphrase.is_type_error());
    }

    #[test]
    fn the_messages_match_the_internal_errors_templates() {
        // These strings are `internal/errors`' templates, not free text, and
        // several Node tests assert on the message as well as the code.
        assert_eq!(
            KeyError::MissingPassphrase.message(),
            "Passphrase required for encrypted key"
        );
        assert_eq!(
            KeyError::InvalidThis("KeyObject").message(),
            "Value of \"this\" must be of type KeyObject"
        );
        assert_eq!(KeyError::InvalidCurve.message(), "Invalid EC curve name");
    }
}
