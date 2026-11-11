//! The cipher's error type and the state `CipherBase` keeps.
//!
//! The variants exist because Node reports these differently: an unknown cipher
//! is `ERR_CRYPTO_UNKNOWN_CIPHER`, a bad key length is `ERR_CRYPTO_INVALID_KEYLEN`
//! (a `RangeError`), an IV problem is `ERR_CRYPTO_INVALID_IV` (a `TypeError`), and
//! an OpenSSL failure carries the packed code in its message and its `code`
//! property. Collapsing them into one variant would produce errors whose `name`
//! and `code` the tests read and would not match.

/// `CipherBase`'s kind, which decides several behaviours in `final`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Cipher,
    Decipher,
}

impl Kind {
    pub fn is_encrypting(self) -> bool {
        self == Self::Cipher
    }
}

/// Why a cipher operation failed, already resolved to the shape Node throws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// `ERR_CRYPTO_UNKNOWN_CIPHER`: the name does not resolve.
    UnknownCipher,
    /// `ERR_CRYPTO_INVALID_KEYLEN`: `EVP_CIPHER_CTX_set_key_length` refused it.
    InvalidKeyLength,
    /// `ERR_CRYPTO_INVALID_IV`: missing, wrong length, or a mode that forbids it.
    InvalidIv,
    /// `ERR_CRYPTO_INVALID_AUTH_TAG`.
    InvalidAuthTag(String),
    /// `ERR_CRYPTO_INVALID_COUNTER`, for a WebCrypto CTR counter outside the
    /// accepted length.
    InvalidCounter,
    /// `ERR_CRYPTO_INVALID_TAG_LENGTH`, for a WebCrypto tag length in bits.
    InvalidTagLength,
    /// `ERR_CRYPTO_INVALID_MESSAGELEN`, a `RangeError`.
    InvalidMessageLength,
    /// `ERR_CRYPTO_UNSUPPORTED_OPERATION`, for `ctsMode`/`xtsStandard` on a
    /// cipher that does not implement them.
    UnsupportedModeOption {
        cipher: String,
        option: &'static str,
    },
    /// `ERR_CRYPTO_INVALID_STATE`, which is what `final()` on an already
    /// finalised handle throws. Its message is `ERR_CRYPTO_INVALID_STATE`'s own
    /// text, `Invalid state`, and it carries the code.
    InvalidState,
    /// `final()` failing to complete: the XTS "final without update" case, a
    /// wrap-mode length failure, and an AEAD that could not authenticate.
    ///
    /// A plain `Error` with the given text and **no** `code`: `CipherBase::Final`
    /// builds it through `ThrowCryptoError` with a fixed default message, and
    /// when OpenSSL queued nothing — which is precisely the authentication-failure
    /// case — the default text is what remains.
    FinalFailed(String),
    /// The `update` failure text, a plain `Error` with **no** `code`.
    ///
    /// This is not `ERR_CRYPTO_INVALID_STATE` even though the two strings look
    /// adjacent: `CipherBase::Update` throws
    /// `ThrowCryptoError(env, err, "Trying to add data in unsupported state")`,
    /// and because its own `MarkPopErrorOnReturn` has already emptied the error
    /// stack, the result is a bare `Error` with that message and no `code`.
    /// `test-crypto-cipheriv-xts` and `-cbc-cts` match the message and would
    /// still pass with a code attached, but a test that asserted `e.code ===
    /// undefined` would not, so the shape is the reference's.
    UpdateFailed,
    /// A `final()` that failed authentication or could not complete. Node throws
    /// "Unsupported state or unable to authenticate data" for an AEAD and
    /// "Unsupported state" otherwise, with the OpenSSL error attached when there
    /// is one.
    AuthenticationFailed,
    /// `ERR_OUT_OF_RANGE`.
    OutOfRange(String),
    /// `ERR_MISSING_ARGS`, for CCM AAD without `plaintextLength`.
    MissingArgument(String),
    /// `ERR_CRYPTO_OPERATION_FAILED` with a fixed message.
    OperationFailed(String),
    /// A packed OpenSSL error from a failed call, reported as
    /// `error:<code>:...` with `code`/`library`/`reason`.
    OpenSsl(u64),
}

impl CipherError {
    /// The `code` property Node attaches, or `None` for a plain `Error`.
    ///
    /// A plain `Error` with a message and no code is what the `Unsupported
    /// state` family is: `ThrowCryptoError` only decorates when OpenSSL produced
    /// an error, and these paths are taken precisely when it did not.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::UnknownCipher => Some("ERR_CRYPTO_UNKNOWN_CIPHER"),
            Self::InvalidKeyLength => Some("ERR_CRYPTO_INVALID_KEYLEN"),
            Self::InvalidIv => Some("ERR_CRYPTO_INVALID_IV"),
            Self::InvalidAuthTag(_) => Some("ERR_CRYPTO_INVALID_AUTH_TAG"),
            Self::InvalidCounter => Some("ERR_CRYPTO_INVALID_COUNTER"),
            Self::InvalidTagLength => Some("ERR_CRYPTO_INVALID_TAG_LENGTH"),
            Self::InvalidMessageLength => Some("ERR_CRYPTO_INVALID_MESSAGELEN"),
            Self::UnsupportedModeOption { .. } => Some("ERR_CRYPTO_UNSUPPORTED_OPERATION"),
            Self::InvalidState => Some("ERR_CRYPTO_INVALID_STATE"),
            Self::FinalFailed(_) | Self::UpdateFailed => None,
            Self::OutOfRange(_) => Some("ERR_OUT_OF_RANGE"),
            Self::MissingArgument(_) => Some("ERR_MISSING_ARGS"),
            Self::OperationFailed(_) => Some("ERR_CRYPTO_OPERATION_FAILED"),
            Self::AuthenticationFailed | Self::OpenSsl(_) => None,
        }
    }

    /// The message.
    ///
    /// `InvalidState` is the one variant whose text is only sometimes formatted
    /// through `ERR_CRYPTO_INVALID_STATE`'s `%s`: `CipherBase::Update` throws
    /// `ThrowCryptoError(env, err, "Trying to add data in unsupported state")`,
    /// which is a bare `Error` with that text, while `final` throws either
    /// `ThrowCryptoError(env, err, "Unsupported state")` or the AEAD-specific
    /// "Unsupported state or unable to authenticate data". So the text is
    /// carried, not derived.
    pub fn message(&self) -> String {
        match self {
            Self::UnknownCipher => "Unknown cipher".to_string(),
            Self::InvalidKeyLength => "Invalid key length".to_string(),
            Self::InvalidIv => "Invalid initialization vector".to_string(),
            Self::InvalidAuthTag(detail) => detail.clone(),
            Self::InvalidCounter => "Invalid counter".to_string(),
            Self::InvalidTagLength => "Invalid taglength".to_string(),
            Self::InvalidMessageLength => "Invalid message length".to_string(),
            Self::UnsupportedModeOption { cipher, option } => {
                format!("{cipher} does not support the {option} option")
            }
            Self::InvalidState => "Invalid state".to_string(),
            Self::FinalFailed(text) => text.clone(),
            Self::UpdateFailed => "Trying to add data in unsupported state".to_string(),
            Self::AuthenticationFailed => {
                "Unsupported state or unable to authenticate data".to_string()
            }
            Self::OutOfRange(text) => text.clone(),
            Self::MissingArgument(text) => text.clone(),
            Self::OperationFailed(text) => text.clone(),
            Self::OpenSsl(packed) => crate::evp::describe_error(*packed).message,
        }
    }

    /// The `name` of the JavaScript error object.
    pub fn error_kind(&self) -> ErrorKind {
        match self {
            // `ERR_CRYPTO_INVALID_AUTH_TAG`, `_IV`, `_COUNTER`, `_DIGEST` and
            // `_MAC` are `TypeError`s in `node_errors.h`.
            Self::InvalidIv | Self::InvalidAuthTag(_) | Self::InvalidCounter => {
                ErrorKind::TypeError
            }
            // `ERR_CRYPTO_INVALID_KEYLEN`, `_MESSAGELEN` and `_TAG_LENGTH` are
            // `RangeError`s.
            Self::InvalidKeyLength
            | Self::InvalidTagLength
            | Self::InvalidMessageLength
            | Self::OutOfRange(_) => ErrorKind::RangeError,
            _ => ErrorKind::Error,
        }
    }

    /// The `library` and `reason` properties, for an OpenSSL error only.
    pub fn decorate(&self) -> Option<(String, String)> {
        match self {
            Self::OpenSsl(packed) => {
                let parts = crate::evp::describe_error(*packed);
                if parts.library.is_empty() && parts.reason.is_empty() {
                    None
                } else {
                    Some((parts.library, parts.reason))
                }
            }
            _ => None,
        }
    }
}

/// Which JavaScript constructor to build the thrown error with.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Error,
    TypeError,
    RangeError,
}

/// The cipher handle's whole state.
///
/// Node splits this between `CipherBase`'s fields and the `EVP_CIPHER_CTX`; they
/// are one struct here because nothing outside this crate can observe the
/// difference, and separating them would let the two disagree.
pub struct CipherState {
    pub kind: Kind,
    pub context: crate::evp::CipherCtx,
}

impl CipherState {
    pub fn new(kind: Kind, context: crate::evp::CipherCtx) -> Self {
        Self { kind, context }
    }

    pub fn is_encrypting(&self) -> bool {
        self.kind.is_encrypting()
    }
}
