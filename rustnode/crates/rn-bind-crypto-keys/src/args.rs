//! Reading the encoding arguments `lib/internal/crypto/keys.js` sends.
//!
//! Every `KeyObjectHandle` entry point is a positional argument list with a
//! `kKeyFormat*` in one slot and a `kKeyEncoding*` or a point-conversion form in
//! the next. The layout differs per context — an *input* call has no cipher
//! slot, an *export* call does, a *generate* call may omit the encoding
//! entirely — and the offsets are what `crypto_keys.cc` walks with its
//! `unsigned int* offset` parameter.
//!
//! This module is that walk, in one place. It returns the offsets it consumed so
//! the caller can assert it reached the end of the argument list, which is Node's
//! `CHECK_EQ(offset, args.Length())`: a mismatch means the JavaScript and the
//! binding disagree about the shape, and silently accepting a short list would
//! make the next argument read the wrong slot.

use rn_crypto_openssl::{KeyEncoding, KeyFormat};

/// Which call is decoding, which decides whether a slot exists.
///
/// `crypto_keys.h`'s `KeyEncodingContext`. The distinction is real: `Input` has no
/// cipher slot because an imported key's cipher comes from its own PEM header,
/// while `Export` has one because the caller chooses it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EncodingContext {
    /// `createPrivateKey`/`createPublicKey`: no cipher or passphrase slot after
    /// the type.
    Input,
    /// `KeyObject.export()`: cipher and passphrase follow the type.
    Export,
    /// `generateKeyPairSync`: the encoding may be absent entirely.
    Generate,
}

/// What a caller read from the argument list.
#[derive(Clone, Debug, Default)]
pub struct ReadEncoding {
    pub format: Option<KeyFormat>,
    pub encoding: Option<KeyEncoding>,
    /// The cipher's name, when the context has a cipher slot and one is present.
    pub cipher: Option<String>,
    /// The passphrase bytes, when the context has a passphrase slot.
    pub passphrase: Option<Vec<u8>>,
    /// The EC point conversion form, which for a raw format occupies the type
    /// slot instead of a `kKeyEncoding*`.
    pub ec_point_form: i32,
    /// No encoding was requested, so the caller wants a `KeyObjectHandle`.
    pub output_key_object: bool,
}

/// Something the argument list could not be read as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EncodingError {
    /// A `kKeyFormat*` value this build does not know.
    UnknownFormat,
    /// A `kKeyEncoding*` value this build does not know.
    UnknownEncoding,
    /// A format/type pair that cannot appear in this context — a JWK generate
    /// request, or an unnamed type on an export.
    Unsupported,
}

/// Reads the format and type slots at `offset`.
///
/// Mirrors `GetKeyFormatAndTypeFromJs`. The `undefined` case is only legal for
/// `Generate`, where `generateKeyPairSync` without a `publicKeyEncoding` asks for
/// key objects rather than bytes — that is what `output_key_object` records, and
/// it is why both slots have to be `undefined` together.
pub fn read_format_and_type(
    values: &Values,
    offset: &mut usize,
    context: EncodingContext,
) -> Result<ReadEncoding, EncodingError> {
    let mut read = ReadEncoding::default();
    let format_value = values.at(*offset);
    if format_value.is_undefined() {
        if context != EncodingContext::Generate || !values.at(*offset + 1).is_undefined() {
            // Node's `CHECK_EQ(context, kKeyContextGenerate)` /
            // `CHECK(args[offset + 1]->IsUndefined())`. A half-specified encoding
            // is a caller bug, so it is rejected rather than guessed at.
            return Err(EncodingError::Unsupported);
        }
        read.output_key_object = true;
        *offset += 2;
        return Ok(read);
    }

    let Some(format_value) = format_value.int32() else {
        return Err(EncodingError::Unsupported);
    };
    let Some(format) = KeyFormat::from_raw(format_value) else {
        return Err(EncodingError::UnknownFormat);
    };
    read.format = Some(format);

    let type_value = values.at(*offset + 1);
    if format.is_raw() {
        // Raw formats use the type slot for the key type name or a point
        // conversion form.
        //
        // The two halves are not symmetric, which is easy to miss:
        // `raw-public`/`raw-private` on an *export* carry a
        // `point_conversion_form_t` integer, but on *import* `keys.js` sends
        // `asymmetricKeyType`, a string like `"ed25519"`, because the raw bytes
        // alone do not say which curve or family they belong to. Rejecting the
        // string makes `crypto.sign(null, data, {key, format: 'raw-private',
        // asymmetricKeyType: 'ed25519'})` fail with a message about encodings,
        // which names nothing that is actually wrong.
        if let Some(form) = type_value.int32() {
            read.ec_point_form = form;
        } else if type_value.string().is_none() && !type_value.is_null_or_undefined() {
            return Err(EncodingError::Unsupported);
        }
    } else if let Some(value) = type_value.int32() {
        let Some(encoding) = KeyEncoding::from_raw(value) else {
            return Err(EncodingError::UnknownEncoding);
        };
        read.encoding = Some(encoding);
    } else {
        // A null type is legal in exactly two places: a PEM input, where the
        // header says what the encoding is, and a JWK generate request, which
        // has no encoding type at all. Everywhere else the caller must name one.
        let allowed = (context == EncodingContext::Input && format == KeyFormat::Pem)
            || (context == EncodingContext::Generate && format == KeyFormat::Jwk);
        if !allowed || !type_value.is_null_or_undefined() {
            return Err(EncodingError::Unsupported);
        }
        read.encoding = Some(KeyEncoding::Pkcs1);
    }

    *offset += 2;
    Ok(read)
}

/// Reads the cipher and passphrase slots a private-key encoding may carry.
///
/// Mirrors the tail of `GetPrivateKeyEncodingFromJs`. Raw formats have no
/// encryption: they still consume the slots, but both must be null, because a
/// raw key written with a cipher would silently ignore it otherwise.
pub fn read_private_key_tail(
    values: &Values,
    offset: &mut usize,
    context: EncodingContext,
    format: Option<KeyFormat>,
    read: &mut ReadEncoding,
) -> Result<(), EncodingError> {
    if read.output_key_object {
        // The generate case with no encoding: Node consumes one slot and the
        // caller has no cipher to give.
        if context != EncodingContext::Input {
            *offset += 1;
        }
        return Ok(());
    }

    let raw = format.is_some_and(KeyFormat::is_raw);
    if raw || format == Some(KeyFormat::RawSeed) {
        if context != EncodingContext::Input {
            if !values.at(*offset).is_null_or_undefined() {
                return Err(EncodingError::Unsupported);
            }
            *offset += 1;
        }
        if !values.at(*offset).is_null_or_undefined() {
            return Err(EncodingError::Unsupported);
        }
        *offset += 1;
        return Ok(());
    }

    let mut needs_passphrase = false;
    if context != EncodingContext::Input {
        // An export names the cipher it wants. An import does not: whether the
        // key is encrypted is a fact about the key, and the cipher is in its own
        // PEM header. So this slot exists only on the export path, and the
        // passphrase then sits *after* it.
        let cipher = values.at(*offset);
        if let Some(name) = cipher.string() {
            // `ncrypto::Cipher::FromNameForKeyEncoding`: a name that does not
            // resolve is `ERR_CRYPTO_UNKNOWN_CIPHER`, which the caller reports.
            read.cipher = Some(name);
            needs_passphrase = true;
        } else if !cipher.is_null_or_undefined() {
            return Err(EncodingError::Unsupported);
        }
        *offset += 1;
    }

    let passphrase = values.at(*offset);
    if let Some(bytes) = passphrase.bytes() {
        if context != EncodingContext::Input && read.cipher.is_none() {
            // A passphrase with no cipher has nothing to encrypt with. Node's
            // `CHECK_IMPLIES(context != kKeyContextInput, config.cipher)`.
            return Err(EncodingError::Unsupported);
        }
        read.passphrase = Some(bytes);
    } else if !passphrase.is_null_or_undefined() || needs_passphrase {
        // `CHECK(args[offset]->IsNullOrUndefined() && !needs_passphrase)`.
        return Err(EncodingError::Unsupported);
    }

    *offset += 1;
    Ok(())
}

/// A decoded argument list, so the readers above can be tested without V8.
///
/// The binding fills this from `FunctionCallbackArguments`; the tests fill it
/// directly. Keeping the walk independent of V8 is what makes the offset
/// arithmetic testable, and the offsets are where the bugs are.
#[derive(Clone, Debug, Default)]
pub struct Values {
    values: Vec<Value>,
}

/// One argument's kind and payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Value {
    /// An absent argument, and also a slot past the end of the list.
    #[default]
    Undefined,
    Null,
    Int32(i32),
    String(String),
    Bytes(Vec<u8>),
    /// A JavaScript object, carrying its position in the argument list.
    ///
    /// The index rather than the handle, so this module stays V8-free: a JWK and
    /// an OpenSSL STORE descriptor are both objects, and the caller reads the
    /// properties off the argument at `index`.
    Object(usize),
    /// Something the walk does not expect in a positional slot.
    Other,
}

impl Values {
    pub fn new(values: Vec<Value>) -> Self {
        Self { values }
    }

    fn at(&self, index: usize) -> &Value {
        self.values.get(index).unwrap_or(&Value::Undefined)
    }

    /// The argument at `index`, for a caller that needs more than the kind.
    pub fn get(&self, index: usize) -> &Value {
        self.at(index)
    }

    /// The argument at `index`, or `None` past the end.
    ///
    /// Distinct from [`Values::get`], which reads past the end as `undefined`
    /// because that is what `args[i]` does. Code that wants "present and of this
    /// kind" uses this one.
    pub fn opt(&self, index: usize) -> Option<&Value> {
        self.values.get(index)
    }
}

impl Value {
    /// Whether this is `undefined`, which an absent argument also reads as.
    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    /// Whether this entry is a JavaScript object, i.e. a JWK or STORE
    /// descriptor.
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    /// Whether this is `null` or `undefined`.
    pub fn is_null_or_undefined(&self) -> bool {
        matches!(self, Self::Null | Self::Undefined)
    }

    /// The value as an `i32`, or `None` for any other kind.
    pub fn int32(&self) -> Option<i32> {
        match self {
            Self::Int32(value) => Some(*value),
            _ => None,
        }
    }

    /// The value as a string, or `None` for any other kind.
    pub fn string(&self) -> Option<String> {
        match self {
            Self::String(text) => Some(text.clone()),
            _ => None,
        }
    }

    /// The value as bytes, or `None` for any other kind.
    pub fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pem_input_reads_format_and_a_null_type() {
        let values = Values::new(vec![Value::Int32(2), Value::Null]);
        let mut offset = 0;
        let read = read_format_and_type(&values, &mut offset, EncodingContext::Input)
            .expect("a PEM input is legal");
        assert_eq!(read.format, Some(KeyFormat::Pem));
        assert_eq!(read.encoding, Some(KeyEncoding::Pkcs1));
        assert!(!read.output_key_object);
        assert_eq!(offset, 2);
    }

    #[test]
    fn a_der_export_reads_its_type() {
        let values = Values::new(vec![Value::Int32(1), Value::Int32(3)]);
        let mut offset = 0;
        let read = read_format_and_type(&values, &mut offset, EncodingContext::Export)
            .expect("DER with SPKI is legal");
        assert_eq!(read.format, Some(KeyFormat::Der));
        assert_eq!(read.encoding, Some(KeyEncoding::Spki));
        assert_eq!(offset, 2);
    }

    #[test]
    fn a_generate_with_no_encoding_asks_for_a_key_object() {
        // `generateKeyPairSync('rsa', { modulusLength })` passes undefined for
        // both slots, which is how it gets `KeyObject`s back instead of bytes.
        let values = Values::new(vec![Value::Undefined, Value::Undefined]);
        let mut offset = 0;
        let read = read_format_and_type(&values, &mut offset, EncodingContext::Generate)
            .expect("an omitted encoding is legal when generating");
        assert!(read.output_key_object);
        assert_eq!(read.format, None);
        assert_eq!(offset, 2);
    }

    #[test]
    fn an_omitted_encoding_is_only_legal_when_generating() {
        let values = Values::new(vec![Value::Undefined, Value::Undefined]);
        let mut offset = 0;
        assert_eq!(
            read_format_and_type(&values, &mut offset, EncodingContext::Export).err(),
            Some(EncodingError::Unsupported)
        );
        let mut offset = 0;
        assert_eq!(
            read_format_and_type(&values, &mut offset, EncodingContext::Input).err(),
            Some(EncodingError::Unsupported)
        );
    }

    #[test]
    fn a_half_specified_encoding_is_rejected() {
        // Format present, type `undefined`: Node's two CHECKs both fail.
        let values = Values::new(vec![Value::Int32(2), Value::Undefined]);
        let mut offset = 0;
        assert_eq!(
            read_format_and_type(&values, &mut offset, EncodingContext::Generate).err(),
            Some(EncodingError::Unsupported)
        );
    }

    #[test]
    fn an_unknown_format_or_type_is_named_as_such() {
        let values = Values::new(vec![Value::Int32(99), Value::Null]);
        let mut offset = 0;
        assert_eq!(
            read_format_and_type(&values, &mut offset, EncodingContext::Input).err(),
            Some(EncodingError::UnknownFormat)
        );
        let values = Values::new(vec![Value::Int32(1), Value::Int32(99)]);
        let mut offset = 0;
        assert_eq!(
            read_format_and_type(&values, &mut offset, EncodingContext::Export).err(),
            Some(EncodingError::UnknownEncoding)
        );
    }

    #[test]
    fn an_export_without_a_type_is_rejected() {
        // A DER export must name SPKI, PKCS#8, PKCS#1 or SEC1; there is nothing
        // to infer it from.
        let values = Values::new(vec![Value::Int32(1), Value::Null]);
        let mut offset = 0;
        assert_eq!(
            read_format_and_type(&values, &mut offset, EncodingContext::Export).err(),
            Some(EncodingError::Unsupported)
        );
    }

    #[test]
    fn a_raw_format_reads_the_point_form_from_the_type_slot() {
        let values = Values::new(vec![Value::Int32(4), Value::Int32(2)]);
        let mut offset = 0;
        let read = read_format_and_type(&values, &mut offset, EncodingContext::Export)
            .expect("a raw public export is legal");
        assert_eq!(read.format, Some(KeyFormat::RawPublic));
        assert_eq!(read.encoding, None);
        assert_eq!(read.ec_point_form, 2, "compressed");
    }

    #[test]
    fn a_raw_format_accepts_a_null_point_form() {
        let values = Values::new(vec![Value::Int32(5), Value::Null]);
        let mut offset = 0;
        let read = read_format_and_type(&values, &mut offset, EncodingContext::Export)
            .expect("raw-private has no point form");
        assert_eq!(read.format, Some(KeyFormat::RawPrivate));
        assert_eq!(read.ec_point_form, 0);
    }

    #[test]
    fn an_export_reads_its_cipher_and_passphrase() {
        let values = Values::new(vec![
            Value::Int32(2),
            Value::Int32(2),
            Value::String("aes-256-cbc".to_string()),
            Value::Bytes(b"secret".to_vec()),
        ]);
        let mut offset = 0;
        let mut read = read_format_and_type(&values, &mut offset, EncodingContext::Export)
            .expect("PEM PKCS#8");
        read_private_key_tail(
            &values,
            &mut offset,
            EncodingContext::Export,
            read.format,
            &mut read,
        )
        .expect("a cipher and passphrase are legal here");
        assert_eq!(read.cipher.as_deref(), Some("aes-256-cbc"));
        assert_eq!(read.passphrase.as_deref(), Some(&b"secret"[..]));
        assert_eq!(offset, 4, "the whole list was consumed");
    }

    #[test]
    fn an_input_has_no_cipher_slot() {
        // `createPrivateKey` builds `handle.init(kKeyTypePrivate, data,
        // format, type, passphrase, namedCurve)` — there is no cipher slot at
        // all, because whether the key is encrypted is a fact in its own PEM
        // header rather than something the caller chooses.
        let values = Values::new(vec![
            Value::Int32(2),
            Value::Null,
            Value::Bytes(b"secret".to_vec()),
        ]);
        let mut offset = 0;
        let mut read =
            read_format_and_type(&values, &mut offset, EncodingContext::Input).expect("PEM");
        read_private_key_tail(
            &values,
            &mut offset,
            EncodingContext::Input,
            read.format,
            &mut read,
        )
        .expect("the input tail is one slot shorter");
        assert!(read.cipher.is_none());
        assert_eq!(read.passphrase.as_deref(), Some(&b"secret"[..]));
        assert_eq!(offset, 3, "the input path consumed one fewer slot");
    }

    #[test]
    fn a_passphrase_without_a_cipher_is_rejected_on_export() {
        let values = Values::new(vec![
            Value::Int32(2),
            Value::Int32(2),
            Value::Null,
            Value::Bytes(b"secret".to_vec()),
        ]);
        let mut offset = 0;
        let mut read = read_format_and_type(&values, &mut offset, EncodingContext::Export)
            .expect("PEM PKCS#8");
        assert_eq!(
            read_private_key_tail(
                &values,
                &mut offset,
                EncodingContext::Export,
                read.format,
                &mut read,
            )
            .err(),
            Some(EncodingError::Unsupported),
            "nothing to encrypt with"
        );
    }

    #[test]
    fn a_cipher_without_a_passphrase_is_rejected() {
        let values = Values::new(vec![
            Value::Int32(2),
            Value::Int32(2),
            Value::String("aes-128-cbc".to_string()),
            Value::Null,
        ]);
        let mut offset = 0;
        let mut read = read_format_and_type(&values, &mut offset, EncodingContext::Export)
            .expect("PEM PKCS#8");
        assert_eq!(
            read_private_key_tail(
                &values,
                &mut offset,
                EncodingContext::Export,
                read.format,
                &mut read,
            )
            .err(),
            Some(EncodingError::Unsupported)
        );
    }

    #[test]
    fn a_raw_format_rejects_a_cipher() {
        let values = Values::new(vec![
            Value::Int32(5),
            Value::Null,
            Value::String("aes-128-cbc".to_string()),
            Value::Null,
        ]);
        let mut offset = 0;
        let mut read = read_format_and_type(&values, &mut offset, EncodingContext::Export)
            .expect("raw-private");
        assert_eq!(
            read_private_key_tail(
                &values,
                &mut offset,
                EncodingContext::Export,
                read.format,
                &mut read,
            )
            .err(),
            Some(EncodingError::Unsupported),
            "a raw key has no encryption form"
        );
    }

    #[test]
    fn the_generate_tail_consumes_one_slot_when_no_encoding_was_given() {
        let values = Values::new(vec![Value::Undefined, Value::Undefined, Value::Null]);
        let mut offset = 0;
        let mut read = read_format_and_type(&values, &mut offset, EncodingContext::Generate)
            .expect("no encoding");
        read_private_key_tail(
            &values,
            &mut offset,
            EncodingContext::Generate,
            read.format,
            &mut read,
        )
        .expect("legal");
        assert_eq!(offset, 3);
    }

    #[test]
    fn a_slot_past_the_end_reads_as_undefined() {
        // Node's `args[i]` is `undefined` past the end, and the walk relies on
        // that: a short list has to fail the same CHECK a wrong one does, not
        // index out of bounds.
        let values = Values::new(vec![Value::Int32(2)]);
        let mut offset = 0;
        let read = read_format_and_type(&values, &mut offset, EncodingContext::Input)
            .expect("a null type past the end is undefined");
        assert_eq!(read.encoding, Some(KeyEncoding::Pkcs1));
    }
}
