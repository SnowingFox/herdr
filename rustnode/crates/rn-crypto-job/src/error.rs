//! The error a job reports, and the three JavaScript shapes it has to take.
//!
//! A job failure reaches JavaScript in one of three forms depending on the mode,
//! and they are not interchangeable:
//!
//! * `Sync` — an *error value* in slot 0 of the returned tuple. `lib/**` reads
//!   `const { 0: err, 1: value } = job.run(); if (err !== undefined) throw err`,
//!   so throwing here would surface as an uncaught exception from the wrong
//!   place.
//! * `Async` — the first argument of `ondone`, same reasoning.
//! * `WebCrypto` — a rejected promise, wrapped in a `DOMException` named
//!   `OperationError` with the real error as `cause`.
//!
//! So a job error is a value, not a thrown exception, until something decides it
//! is the caller's problem. [`CryptoJobError::exception`] builds that value.

use rn_v8_sys::v8;

/// The OpenSSL detail `ThrowCryptoError` attaches.
///
/// Kept as data rather than read from the error queue at delivery time: the
/// queue is thread-local, the failure happens on a pool thread and the
/// JavaScript object is built on the main thread, so the queue there would be
/// empty or hold an unrelated entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSslDetail {
    /// The packed `ERR_get_error` value, e.g. `0x0200006E`.
    pub packed: u64,
    /// The `code` property, e.g. `ERR_OSSL_RSA_DATA_TOO_LARGE_FOR_KEY_SIZE`.
    pub code: String,
    /// The `library` property, e.g. `rsa routines`.
    pub library: String,
    /// The `reason` property, e.g. `data too large for key size`.
    pub reason: String,
    /// The `message` property, which is `ERR_error_string_n`'s output.
    pub message: String,
}

/// One failure a job can report.
///
/// The variants exist because the *JavaScript shape* differs, not because the
/// messages do: a `NodeError` carries a `code`, an OpenSSL failure carries
/// `library`/`reason` instead and derives its code from the packed value, and a
/// cancelled job is neither.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoJobError {
    /// `THROW_ERR_CRYPTO_*`: a code, a message and nothing else.
    ///
    /// The message is spelled out at the call site rather than derived from the
    /// code, because `internal/errors`' templates are not all "the code's name
    /// with underscores": `ERR_CRYPTO_OPERATION_FAILED` is "Unspecified error"
    /// in some paths and the caller's own text in others.
    Node {
        code: &'static str,
        message: String,
        /// Whether the code's template is declared with `TypeError`.
        type_error: bool,
    },
    /// `ERR_INVALID_ARG_VALUE`-shaped: a `RangeError` with a message.
    ///
    /// `ERR_OUT_OF_RANGE` is declared as a `RangeError` in `internal/errors`,
    /// and `assert.throws(..., RangeError)` is what several tests check, so the
    /// constructor has to be right as well as the code.
    OutOfRange { message: String },
    /// `ThrowCryptoError`: an `Error` whose fields come from OpenSSL.
    OpenSsl(OpenSslDetail),
    /// The work was cancelled before it ran, which only a shutdown can cause.
    Canceled,
}

impl CryptoJobError {
    /// `ERR_CRYPTO_OPERATION_FAILED` with the caller's message.
    pub fn operation_failed(message: &str) -> Self {
        Self::Node {
            code: "ERR_CRYPTO_OPERATION_FAILED",
            message: message.to_string(),
            type_error: false,
        }
    }

    /// `ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE`, whose template is
    /// `Invalid key object type %s, expected %s.`
    ///
    /// A `TypeError` in `internal/errors`, and a test asserts that too.
    pub fn invalid_key_object_type(actual: &str, expected: &str) -> Self {
        Self::Node {
            code: "ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE",
            message: format!("Invalid key object type {actual}, expected {expected}."),
            type_error: true,
        }
    }

    /// The `code` property, or `None` when OpenSSL supplies it or there is none.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Node { code, .. } => Some(code),
            Self::OutOfRange { .. } => Some("ERR_OUT_OF_RANGE"),
            Self::OpenSsl(detail) => Some(&detail.code),
            Self::Canceled => None,
        }
    }

    /// The message text.
    pub fn message(&self) -> String {
        match self {
            Self::Node { message, .. } => message.clone(),
            Self::OutOfRange { message } => message.clone(),
            Self::OpenSsl(detail) => detail.message.clone(),
            Self::Canceled => "The operation was canceled".to_string(),
        }
    }

    /// Builds the error as a JavaScript value without throwing it.
    ///
    /// This is the `[err, value]` and `ondone(err, ...)` form. It is a value on
    /// purpose: every caller in `lib/**` inspects the error rather than catching
    /// it, and an exception here would escape from inside a libuv completion
    /// where nothing can handle it.
    pub fn exception<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
        let message = self.message();
        let Some(text) = v8::String::new(scope, &message) else {
            return v8::undefined(scope).into();
        };
        let exception = match self {
            Self::Node {
                type_error: true, ..
            } => v8::Exception::type_error(scope, text),
            Self::OutOfRange { .. } => v8::Exception::range_error(scope, text),
            _ => v8::Exception::error(scope, text),
        };
        let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
            return exception;
        };
        if let Some(code) = self.code() {
            if let (Some(key), Some(value)) =
                (v8::String::new(scope, "code"), v8::String::new(scope, code))
            {
                object.set(scope, key.into(), value.into());
            }
        }
        // `ThrowCryptoError` attaches `library` and `reason` as well, and
        // `test-crypto-dh-errors.js` and the RSA tests read them.
        if let Self::OpenSsl(detail) = self {
            for (name, value) in [
                ("library", detail.library.as_str()),
                ("reason", detail.reason.as_str()),
            ] {
                if let (Some(key), Some(text)) =
                    (v8::String::new(scope, name), v8::String::new(scope, value))
                {
                    object.set(scope, key.into(), text.into());
                }
            }
        }
        exception
    }
}

impl std::fmt::Display for CryptoJobError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_codes_are_the_ones_internal_errors_declares() {
        assert_eq!(
            CryptoJobError::operation_failed("x").code(),
            Some("ERR_CRYPTO_OPERATION_FAILED")
        );
        assert_eq!(
            CryptoJobError::invalid_key_object_type("public", "private").code(),
            Some("ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE")
        );
        assert_eq!(
            CryptoJobError::OutOfRange {
                message: "invalid options.add".to_string()
            }
            .code(),
            Some("ERR_OUT_OF_RANGE")
        );
    }

    #[test]
    fn the_key_object_type_message_matches_the_template() {
        // `E('ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE', 'Invalid key object type %s,
        // expected %s.', TypeError)` — the trailing full stop is part of the
        // template and Node's tests compare the whole sentence.
        assert_eq!(
            CryptoJobError::invalid_key_object_type("public", "private").message(),
            "Invalid key object type public, expected private."
        );
    }

    #[test]
    fn an_openssl_failure_reports_its_derived_code() {
        let error = CryptoJobError::OpenSsl(OpenSslDetail {
            packed: 0x0200_006E,
            code: "ERR_OSSL_RSA_DATA_TOO_LARGE_FOR_KEY_SIZE".to_string(),
            library: "rsa routines".to_string(),
            reason: "data too large for key size".to_string(),
            message: "error:0200006E:rsa routines::data too large for key size".to_string(),
        });
        assert_eq!(
            error.code(),
            Some("ERR_OSSL_RSA_DATA_TOO_LARGE_FOR_KEY_SIZE")
        );
        // The message is `ERR_error_string_n`'s output, which replaces whatever
        // the caller passed — that is what `ThrowCryptoError` does.
        assert_eq!(
            error.message(),
            "error:0200006E:rsa routines::data too large for key size"
        );
    }
}
