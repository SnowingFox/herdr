//! The two error families the compression members throw, with Bun's shapes.
//!
//! Spec 3.4 measured three families and they are not interchangeable:
//!
//! | family | constructor | `code` | message |
//! | --- | --- | --- | --- |
//! | zlib decode | `Error` | **none** | zlib's own text, or `Zlib returned an error` |
//! | zstd decode | `Error` | `ERR_ZSTD` | `Decompression failed: {reason}` |
//! | argument type | `TypeError` | `ERR_INVALID_ARG_TYPE` | `data must be a string, …` |
//! | option range | `RangeError` | `ERR_OUT_OF_RANGE` | `The value of "…" is out of range. …` |
//!
//! The zlib family having no `code` is the one that catches Node-shaped code:
//! Node's `zlib` throws errors carrying `errno`/`code`/`Z_DATA_ERROR`, and Bun
//! throws a bare `Error`, so `err.code === 'Z_DATA_ERROR'` is false here.

use rn_v8_sys::v8;

/// A failure one of the eight members reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionError {
    /// A plain `Error` with no `code`: the zlib family.
    ///
    /// The message is already the exact text Bun throws, because the three
    /// zlib-level outcomes (`incorrect header check`, `invalid block type`,
    /// `Zlib returned an error`) come from different places and collapsing them
    /// into one enum variant would lose the distinction the tests assert.
    Zlib(String),
    /// `ERR_ZSTD` on an `Error`. `reason` is the `Bun.zstd` error enumerator
    /// name, so the message is `Decompression failed: {reason}` when it came from
    /// a decode and the reason alone when it came from a compress.
    Zstd { reason: String, decompress: bool },
    /// `ERR_INVALID_ARG_TYPE` on a `TypeError`, thrown for input data and for
    /// option values of the wrong type.
    InvalidArgType(String),
    /// `ERR_OUT_OF_RANGE` on a `RangeError`, thrown by the integer validators
    /// `memLevel` and `strategy`.
    OutOfRange(String),
}

impl CompressionError {
    /// The `data must be …` rejection every member shares, verbatim.
    ///
    /// Note that it names only `string`, `ArrayBuffer` and `ArrayBufferView`,
    /// and deliberately **not** `Blob`, unlike the hash family — that omission is
    /// recorded in spec 3.4 and is what a `Bun.hash`-shaped argument check would
    /// get wrong.
    pub fn invalid_data() -> Self {
        Self::InvalidArgType("data must be a string, ArrayBuffer or ArrayBufferView".to_string())
    }

    /// The message text, which is the part every test compares.
    pub fn message(&self) -> String {
        match self {
            CompressionError::Zlib(message) => message.clone(),
            CompressionError::Zstd { reason, decompress } => {
                if *decompress {
                    format!("Decompression failed: {reason}")
                } else {
                    reason.clone()
                }
            }
            CompressionError::InvalidArgType(message) | CompressionError::OutOfRange(message) => {
                message.clone()
            }
        }
    }

    /// The `code`, when this family carries one.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            CompressionError::Zlib(_) => None,
            CompressionError::Zstd { .. } => Some("ERR_ZSTD"),
            CompressionError::InvalidArgType(_) => Some("ERR_INVALID_ARG_TYPE"),
            CompressionError::OutOfRange(_) => Some("ERR_OUT_OF_RANGE"),
        }
    }

    /// Builds the JavaScript error value, with `code` attached when the family
    /// has one.
    ///
    /// Not thrown: callers either throw it (sync members) or reject with it (the
    /// promise members), and only the caller knows which.
    pub fn exception<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
        let Some(text) = v8::String::new(scope, &self.message()) else {
            return v8::undefined(scope).into();
        };
        let exception = match self {
            CompressionError::InvalidArgType(_) => v8::Exception::type_error(scope, text),
            CompressionError::OutOfRange(_) => v8::Exception::range_error(scope, text),
            CompressionError::Zlib(_) | CompressionError::Zstd { .. } => {
                v8::Exception::error(scope, text)
            }
        };
        if let (Some(code), Ok(object)) =
            (self.code(), v8::Local::<v8::Object>::try_from(exception))
        {
            if let (Some(key), Some(value)) =
                (v8::String::new(scope, "code"), v8::String::new(scope, code))
            {
                let _ = object.set(scope, key.into(), value.into());
            }
        }
        exception
    }

    /// Throws this error and returns `None`, for the `Result`-returning members.
    pub fn throw<'s>(self, scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Value>> {
        let exception = self.exception(scope);
        scope.throw_exception(exception);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_zlib_family_has_no_code() {
        // The single most important property of this family: Node's `zlib`
        // attaches `Z_DATA_ERROR`, and Bun does not.
        assert_eq!(
            CompressionError::Zlib("incorrect header check".into()).code(),
            None
        );
        assert_eq!(
            CompressionError::invalid_data().code(),
            Some("ERR_INVALID_ARG_TYPE")
        );
    }

    #[test]
    fn a_zstd_decode_failure_is_prefixed_and_a_compress_failure_is_not() {
        let decode = CompressionError::Zstd {
            reason: "InvalidZstdData".into(),
            decompress: true,
        };
        assert_eq!(decode.message(), "Decompression failed: InvalidZstdData");
        assert_eq!(decode.code(), Some("ERR_ZSTD"));
        let compress = CompressionError::Zstd {
            reason: "Destination buffer is too small".into(),
            decompress: false,
        };
        assert_eq!(compress.message(), "Destination buffer is too small");
    }

    #[test]
    fn the_input_message_names_three_shapes_and_not_blob() {
        let message = CompressionError::invalid_data().message();
        assert_eq!(
            message,
            "data must be a string, ArrayBuffer or ArrayBufferView"
        );
        assert!(!message.contains("Blob"));
    }
}
