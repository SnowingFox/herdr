//! `KeyObjectHandle`: the native handle every `KeyObject` wraps.
//!
//! `keys.js` builds one with `new KeyObjectHandle()` and then calls
//! `handle.init(type, ...)` with the already-validated key data. Everything else
//! on the prototype is a query or an export.
//!
//! | JavaScript | here |
//! | --- | --- |
//! | `handle.init(type, data, format, type, passphrase, namedCurve)` | [`init`] |
//! | `handle.getKeyType()` | [`get_key_type`] |
//! | `handle.getSymmetricKeySize()` | [`get_symmetric_key_size`] |
//! | `handle.getAsymmetricKeyType()` | [`get_asymmetric_key_type`] |
//! | `handle.keyDetail(object)` | [`get_key_detail`] |
//! | `handle.equals(other)` | [`equals`] |
//! | `handle.export(format, type, cipher, passphrase)` | [`export`] |
//! | `handle.exportJwk(object, handleRsaPss)` | [`export_jwk`] |
//! | `handle.rawPublicKey()` / `rawPrivateKey()` / `rawSeed()` | the raw exporters |
//! | `handle.exportECPublicRaw(form)` and friends | the EC exporters |
//! | `handle.checkEcKeyData()` | [`check_ec_key_data`] |
//!
//! # `init` is where the argument shapes live
//!
//! One function with a branch per key type, because that is what
//! `KeyObjectHandle::Init` is: the argument list *shape* changes with the type,
//! and each branch decodes its own. The offset arithmetic lives in
//! [`crate::args`] so it is testable without an isolate.
//!
//! # Objects in the argument list
//!
//! Three things arrive as JavaScript objects rather than buffers: a JWK, an
//! OpenSSL STORE descriptor, and another `KeyObjectHandle`. The decoder records
//! the argument *index* for those — it does not touch V8 — and this module reads
//! the properties off the live argument at that index.

use rn_crypto_openssl::{
    import_raw, import_raw_private_key, import_raw_public_key, parse_private_key,
    parse_public_or_private_key, EcPointForm, EqualResult, KeyAlgorithm, KeyFormat, KeyFormatError,
    PKey, PrivateKeyEncoding, PublicKeyEncoding,
};
use rn_v8_sys::v8;

use crate::args::{
    read_format_and_type, read_private_key_tail, EncodingContext, EncodingError, Value, Values,
};
use crate::errors::{throw, KeyError};
use crate::state::{KeyData, KeyType};
use crate::templates::{set_key_data, with_key_data};

/// `new KeyObjectHandle()`, which only reserves the internal field.
///
/// `init` fills it in. A handle whose `init` was never called is a valid object
/// whose every method reports "invalid handle", which is what Node's
/// `ASSIGN_OR_RETURN_UNWRAP` produces.
pub fn constructor<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    // The internal field is deliberately left untouched: V8 zeroes internal
    // fields when it allocates the object, and `set_aligned_pointer_in_internal_field`
    // is not a plain store — it writes a *tagged* word, so writing a null pointer
    // here and reading it back later yields the tag bits rather than null.
    // "No key yet" is therefore represented by never having called
    // `set_key_data`, which is also what `keys.js` does: it constructs the handle
    // and then calls `init`.
    let this: v8::Local<v8::Object> = args.this();
    rv.set(this.into());
}

/// Installs every prototype method.
pub fn install_methods<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: v8::Local<'s, v8::ObjectTemplate>,
) -> Option<()> {
    /// A method list, built one at a time.
    ///
    /// A macro because `FunctionTemplate::builder` needs the *item* type: V8's
    /// trampoline is generic over a zero-sized unit type and a `fn` pointer is
    /// not zero-sized, so a slice of them does not compile.
    macro_rules! methods {
        ($($name:literal => $callback:path),* $(,)?) => {
            $(
                {
                    let template = v8::FunctionTemplate::builder($callback).build(scope);
                    let key = v8::String::new(scope, $name)?;
                    prototype.set(key.into(), template.into());
                }
            )*
        };
    }
    methods!(
        "init" => init,
        "getKeyType" => get_key_type,
        "getSymmetricKeySize" => get_symmetric_key_size,
        "getAsymmetricKeyType" => get_asymmetric_key_type,
        "checkEcKeyData" => check_ec_key_data,
        "export" => export,
        "exportJwk" => export_jwk,
        "rawPublicKey" => raw_public_key,
        "rawPrivateKey" => raw_private_key,
        "rawSeed" => raw_seed,
        "exportECPublicRaw" => export_ec_public_raw,
        "exportECPrivateRaw" => export_ec_private_raw,
        "exportECPrivatePkcs8" => export_ec_private_pkcs8,
        "keyDetail" => get_key_detail,
        "equals" => equals,
    );
    Some(())
}

/// Reads the argument list into the V8-independent [`Values`] the decoder wants.
pub(crate) fn values_of(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
) -> Values {
    let mut values = Vec::with_capacity(args.length() as usize);
    for index in 0..args.length() {
        let value = args.get(index);
        if value.is_undefined() {
            values.push(Value::Undefined);
        } else if value.is_null() {
            values.push(Value::Null);
        } else if let Ok(number) = v8::Local::<v8::Int32>::try_from(value) {
            values.push(Value::Int32(number.value()));
        } else if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
            values.push(Value::String(text.to_rust_string_lossy(scope)));
        } else if let Some(bytes) = bytes_of(value) {
            values.push(Value::Bytes(bytes));
        } else if value.is_object() || value.is_function() {
            // A JWK, a STORE descriptor, a `KeyObjectHandle`, or a boxed
            // primitive. Recorded by index so `object_at` can read it.
            values.push(Value::Object(index as usize));
        } else {
            values.push(Value::Other);
        }
    }
    Values::new(values)
}

/// Copies the bytes behind a `Buffer`, typed array, `DataView` or `ArrayBuffer`.
///
/// Type-strict: `AGENTS.md` records that a binding which coerces its arguments
/// hides the caller's bug, and Node's `ArrayBufferOrViewContents` is equally
/// strict. A string is *not* accepted here; the caller handles it, because a
/// string key needs an encoding rather than arriving as raw UTF-8.
pub(crate) fn bytes_of(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
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
        // `data()` is contiguous for a non-shared backing store, and the length
        // came from the buffer itself, so the slice cannot overrun.
        let data = store.data()?;
        // SAFETY: `data` points at `length` bytes owned by `store`, alive here.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), length);
        }
    }
    Some(bytes)
}

/// Reads a value as bytes, accepting a string as its UTF-8 bytes.
///
/// `ByteSource::FromStringOrBuffer` is what Node uses for a PEM or DER argument,
/// and a string there is a PEM block, so UTF-8 is the right reading.
fn value_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Bytes(bytes) => Some(bytes.clone()),
        Value::String(text) => Some(text.clone().into_bytes()),
        _ => None,
    }
}

/// The live V8 object at a decoded `Value::Object` index.
fn object_at<'s>(
    args: &v8::FunctionCallbackArguments<'s>,
    value: &Value,
) -> Option<v8::Local<'s, v8::Object>> {
    let Value::Object(index) = value else {
        return None;
    };
    v8::Local::<v8::Object>::try_from(args.get(*index as i32)).ok()
}

/// Reads a property off a JavaScript object as a string.
fn property_string(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
) -> Option<String> {
    let key = v8::String::new(scope, name)?;
    let value = object.get(scope, key.into())?;
    let text = v8::Local::<v8::String>::try_from(value).ok()?;
    Some(text.to_rust_string_lossy(scope))
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// `handle.init(type, data, format, type, passphrase, namedCurve)`.
fn init<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let values = values_of(scope, &args);

    let Some(key_type_value) = values.opt(0).and_then(|value| value.int32()) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    let Some(key_type) = KeyType::from_raw(key_type_value) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };

    match key_type {
        KeyType::Secret => init_secret(scope, &args, &values, this, &mut rv),
        KeyType::Public | KeyType::Private => {
            init_asymmetric(scope, &args, &values, this, key_type, &mut rv)
        }
    }
}

/// The `kKeyTypeSecret` branch.
///
/// `args.Length() == 5 && args[2] is an integer` selects the JWK form, which
/// reports the key type it resolved to; otherwise the key is the second argument
/// as bytes.
fn init_secret(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    values: &Values,
    this: v8::Local<v8::Object>,
    rv: &mut v8::ReturnValue,
) {
    let is_jwk = values
        .opt(2)
        .and_then(|value| value.int32())
        .and_then(KeyFormat::from_raw)
        == Some(KeyFormat::Jwk);
    if is_jwk {
        let Some(jwk) = object_at(args, values.get(1)) else {
            throw(
                scope,
                &KeyError::InvalidJwk("Invalid JWK secret key format"),
            );
            return;
        };
        let Some(key) = property_string(scope, jwk, "k") else {
            throw(
                scope,
                &KeyError::InvalidJwk("Invalid JWK secret key format"),
            );
            return;
        };
        let Some(bytes) = base64url_decode(&key) else {
            throw(
                scope,
                &KeyError::InvalidJwk("Invalid JWK secret key format"),
            );
            return;
        };
        let data = KeyData::secret(bytes);
        let key_type = data.key_type().as_raw();
        set_key_data(scope, this, data);
        rv.set(v8::Integer::new(scope, key_type).into());
        return;
    }

    let Some(bytes) = values.opt(1).and_then(value_bytes) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    set_key_data(scope, this, KeyData::secret(bytes));
}

/// The `kKeyTypePublic` / `kKeyTypePrivate` branch.
fn init_asymmetric(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    values: &Values,
    this: v8::Local<v8::Object>,
    key_type: KeyType,
    rv: &mut v8::ReturnValue,
) {
    // A raw or JWK format is detected from the integer in slot 2.
    if let Some(format) = values
        .opt(2)
        .and_then(|value| value.int32())
        .and_then(KeyFormat::from_raw)
    {
        if format.is_raw() {
            // `KeyObjectHandle.import(keyType, data, format, type, passphrase,
            // namedCurve)`: the key type occupies slot 0, so the data slot is 1.
            let Some(data) = import_raw_key(scope, values, 1, format, key_type) else {
                return;
            };
            set_key_data(scope, this, data);
            return;
        }
        if format == KeyFormat::Jwk {
            let Some(jwk) = object_at(args, values.get(1)) else {
                throw(scope, &KeyError::InvalidJwk("Invalid JWK key format"));
                return;
            };
            let Some(data) = import_jwk(scope, jwk, key_type) else {
                return;
            };
            // A JWK that held a private key and was asked for a public one
            // reports `public`; asking for private and finding only public
            // material is `ERR_CRYPTO_INVALID_JWK`.
            let resolved = match (key_type, data.key_type()) {
                (KeyType::Public, KeyType::Private) => data.as_type(KeyType::Public),
                (KeyType::Private, KeyType::Public) => {
                    throw(
                        scope,
                        &KeyError::InvalidJwk("JWK does not contain private key material"),
                    );
                    return;
                }
                _ => data,
            };
            let key_type = resolved.key_type().as_raw();
            set_key_data(scope, this, resolved);
            rv.set(v8::Integer::new(scope, key_type).into());
            return;
        }
    }

    let mut offset = 1;
    let key = match key_type {
        KeyType::Public => read_public_or_private_key(scope, args, values, &mut offset),
        KeyType::Private => read_private_key(scope, args, values, &mut offset),
        KeyType::Secret => unreachable!("the secret branch handles its own type"),
    };
    let Some(key) = key else {
        return;
    };
    let Some(data) = KeyData::asymmetric(key_type, key) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    set_key_data(scope, this, data);
}

/// `GetPublicOrPrivateKeyFromJs`, for another binding crate that takes a key.
///
/// `crypto_sig.cc` does not construct a `KeyObjectHandle`: its `sign` and
/// `verify` methods call these two static decoders on their own argument list and
/// use the `EVP_PKEY` directly. Exposing them here rather than repeating the
/// walk in another crate is the point of this crate owning `crypto_keys.cc` —
/// the PEM/DER/JWK/raw/KeyObject dispatch, its offset arithmetic and its error
/// shapes are subtle enough that two copies would diverge.
///
/// `args` is the *whole* callback argument list and `offset` is where the key
/// starts. On return `offset` points at the first argument *after* the key, so
/// the caller can read its own trailing arguments. Returns `None` after
/// throwing, which is what the Node original signals with an empty
/// `KeyObjectData`.
///
/// # Why the offset is forced forward
///
/// `GetPrivateKeyFromJs` consumes five slots on every path — data, format, type,
/// passphrase, namedCurve — and the private reader here does the same. The public
/// reader returns from its parse branch without advancing the last slots, because
/// `createPublicKey` has no arguments after the key and never needs the number.
/// `crypto_sig.cc`'s callers *do* have arguments after the key, so the trailing
/// slots are consumed here for both kinds: without it `Sign.verify` reads the
/// signature from the middle of the key's own argument list.
pub fn read_key_from_js(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    offset: &mut usize,
    key_type: KeyType,
) -> Option<KeyData> {
    let values = values_of(scope, args);
    let start = *offset;
    let key = match key_type {
        // `GetPublicOrPrivateKeyFromJs` in Node accepts either kind: verifying
        // with the private half is normal, and the raw-private format only
        // exists for private keys.
        KeyType::Public => read_public_or_private_from_js(scope, args, &values, offset),
        KeyType::Private => read_private_key(scope, args, &values, offset),
        KeyType::Secret => {
            throw(scope, &KeyError::InvalidKeyType);
            None
        }
    }?;
    // The key occupies `start..start + 5`. A reader that returned early leaves
    // `offset` inside that range, so this raises it to the end rather than
    // trusting each branch to have advanced identically.
    *offset = (*offset).max(start + KEY_ARGUMENT_SLOTS);
    let Some(data) = KeyData::asymmetric(key_type, key) else {
        throw(scope, &KeyError::InvalidKeyType);
        return None;
    };
    Some(data)
}

/// The number of argument slots a key occupies: data, format, type, passphrase
/// and namedCurve.
const KEY_ARGUMENT_SLOTS: usize = 5;

/// `GetPublicOrPrivateKeyFromJs`: a key that may be either kind.
///
/// `Verify.verify` and `verifyOneShot` take a public *or* private key — using the
/// private half to verify is normal, and `test-crypto-sign-verify.js` does it in
/// its raw-key block. The private reader is tried first because it accepts every
/// shape the public one does plus the raw-private and seed formats; a public PEM
/// parses through it too, since `PEM_read_bio_PrivateKey` is not what runs — the
/// dispatch below is `parse_public_or_private_key`, which tries both.
fn read_public_or_private_from_js(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    values: &Values,
    offset: &mut usize,
) -> Option<PKey> {
    let data = values.get(*offset).clone();
    let format = values
        .opt(*offset + 1)
        .and_then(|value| value.int32())
        .and_then(KeyFormat::from_raw);

    // A raw key must go through the raw importer: the PEM parser would be handed
    // 32 bytes of key material and report "failed to read asymmetric key", which
    // names nothing that is actually wrong. `raw-public` imports with the public
    // target and the other two with the private one, because a seed and a private
    // scalar are both private material.
    if let Some(format @ (KeyFormat::RawPublic | KeyFormat::RawPrivate | KeyFormat::RawSeed)) =
        format
    {
        let target = if format == KeyFormat::RawPublic {
            KeyType::Public
        } else {
            KeyType::Private
        };
        return import_raw_key(scope, values, *offset, format, target)?
            .asymmetric_key()
            .cloned();
    }
    if matches!(data, Value::String(_) | Value::Bytes(_)) {
        // Everything else is decoded by whichever parser recognises it.
        return read_public_or_private_key(scope, args, values, offset);
    }
    // A descriptor object: JWK, raw, or an existing handle. The private reader
    // covers all three, and the *reported* key type is decided by the caller.
    read_private_key(scope, args, values, offset)
}

/// `GetPrivateKeyFromJs`: decodes a private key from the argument list.
fn read_private_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    values: &Values,
    offset: &mut usize,
) -> Option<PKey> {
    let data = values.get(*offset).clone();
    if data.is_object() {
        // An object with no integer format in the next slot is another
        // `KeyObjectHandle`: `createPrivateKey(privateKey)` and
        // `createPublicKey(privateKey)` both pass a key that is already in hand,
        // and `keys.js`'s `prepareAsymmetricKey` routes it here.
        let Some(format) = values
            .opt(*offset + 1)
            .and_then(|value| value.int32())
            .and_then(KeyFormat::from_raw)
        else {
            let object = object_at(args, &data)?;
            let key = with_key_data(scope, object, |data| data.asymmetric_key().cloned()).flatten();
            let Some(key) = key else {
                throw(scope, &KeyError::InvalidKeyType);
                return None;
            };
            *offset += 5;
            return Some(key);
        };
        match format {
            KeyFormat::Jwk => {
                let jwk = object_at(args, &data)?;
                let data = import_jwk(scope, jwk, KeyType::Private)?;
                *offset += 5;
                return Some(data.asymmetric_key()?.clone());
            }
            KeyFormat::Store => {
                // The OpenSSL STORE loader is a separate surface: it needs URI
                // and property handling, a passphrase, and an
                // `OpenSSLStore` permission check. Reported rather than treating
                // the URI as key bytes.
                throw(
                    scope,
                    &KeyError::OperationFailed("OpenSSL STORE loaders are not implemented yet"),
                );
                return None;
            }
            format if format.is_raw() => {
                let data = import_raw_key(scope, values, *offset, format, KeyType::Private)?;
                *offset += 5;
                return Some(data.asymmetric_key()?.clone());
            }
            _ => {
                // An object with a DER/PEM format but no buffer is not a key.
                throw(scope, &KeyError::InvalidKeyType);
                return None;
            }
        }
    }

    // A raw key arrives as a `Buffer`, not as an object descriptor, so the
    // object branch above never sees it. `keys.js` sends
    // `{format: 'raw-private', asymmetricKeyType: 'ed25519', key: <Buffer>}` as
    // four positional slots exactly like a PEM key, and the *format* slot is what
    // distinguishes them. Checking it here rather than requiring an object is
    // what makes `crypto.sign(null, data, {format: 'raw-private', ...})` work:
    // without it the bytes are handed to the PEM parser and the caller sees
    // "Failed to read private key" for a key that reads fine through
    // `createPrivateKey`, because that path starts at slot 0 and this one does
    // not.
    if let Some(format) = values
        .opt(*offset + 1)
        .and_then(|value| value.int32())
        .and_then(KeyFormat::from_raw)
    {
        if format.is_raw() || format == KeyFormat::RawSeed {
            let data = import_raw_key(scope, values, *offset, format, KeyType::Private)?;
            *offset += KEY_ARGUMENT_SLOTS;
            return Some(data.asymmetric_key()?.clone());
        }
    }

    let bytes = value_bytes(&data)?;
    // The data slot is consumed before the encoding is read: Node's
    // `args[(*offset)++]` inside `GetPrivateKeyFromJs`. Without this the format
    // read lands on the key bytes and sees no integer at all.
    *offset += 1;
    let config = read_private_config(scope, values, offset, EncodingContext::Input)?;
    // The namedCurve slot is only meaningful for the raw format, which returned
    // above, but it still occupies a position.
    *offset += 1;
    match parse_private_key(&bytes, &config) {
        Ok(key) => Some(key),
        Err(failure) => {
            report_parse_failure(scope, &failure, "Failed to read private key");
            None
        }
    }
}

/// `GetPublicOrPrivateKeyFromJs`: reads a key whose kind is not known in advance.
fn read_public_or_private_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    values: &Values,
    offset: &mut usize,
) -> Option<PKey> {
    let data = values.get(*offset).clone();

    if !matches!(data, Value::String(_) | Value::Bytes(_)) {
        if let Some(format) = values
            .opt(*offset + 1)
            .and_then(|value| value.int32())
            .and_then(KeyFormat::from_raw)
        {
            match format {
                KeyFormat::Jwk => {
                    let jwk = object_at(args, &data)?;
                    let data = import_jwk(scope, jwk, KeyType::Public)?;
                    *offset += 5;
                    return Some(data.asymmetric_key()?.clone());
                }
                KeyFormat::Store => {
                    // Only private keys accept a STORE descriptor.
                    throw(
                        scope,
                        &KeyError::IncompatibleKeyOptions {
                            encoding: "store".to_string(),
                            detail: "is only accepted for private keys",
                        },
                    );
                    return None;
                }
                format if format.is_raw() => {
                    let data = import_raw_key(scope, values, *offset, format, KeyType::Public)?;
                    *offset += 5;
                    return Some(data.asymmetric_key()?.clone());
                }
                _ => {}
            }
        }
        // Not a buffer, not a JWK, not raw: it has to be a `KeyObjectHandle`,
        // which is how `createPublicKey(privateKey)` reads a key already in hand.
        let object = object_at(args, &data)?;
        let key = with_key_data(scope, object, |data| data.asymmetric_key().cloned()).flatten();
        let Some(key) = key else {
            throw(scope, &KeyError::InvalidKeyType);
            return None;
        };
        *offset += 5;
        return Some(key);
    }

    let bytes = value_bytes(&data)?;
    // The data slot is consumed before the encoding is read, as in
    // `read_private_key`: Node's `args[(*offset)++]`.
    *offset += 1;
    let (config, passphrase) = read_public_config(scope, values, offset)?;
    let format = config.format.unwrap_or(KeyFormat::Pem);
    // A public key's PEM block may be encrypted; `keys.js` passes the passphrase
    // in that slot even though `PublicKeyEncoding` has no field for it, because
    // the type describes how to *write* a public key.
    match parse_public_or_private_key(&bytes, format, config.encoding, passphrase.as_deref()) {
        Ok(key) => Some(key),
        Err(failure) => {
            report_parse_failure(scope, &failure, "Failed to read asymmetric key");
            None
        }
    }
}

/// Reads a public-key encoding configuration.
///
/// A public key has no cipher slot, but it does have the passphrase slot
/// `keys.js` passes through from `prepareAsymmetricKey`, so only the cipher is
/// skipped.
fn read_public_config(
    scope: &mut v8::PinScope<'_, '_>,
    values: &Values,
    offset: &mut usize,
) -> Option<(PublicKeyEncoding, Option<Vec<u8>>)> {
    let read = match read_format_and_type(values, offset, EncodingContext::Input) {
        Ok(read) => read,
        Err(error) => {
            throw_encoding_error(scope, error);
            return None;
        }
    };
    if read.output_key_object {
        throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: "undefined".to_string(),
                detail: "is not a valid encoding for an imported key",
            },
        );
        return None;
    }
    // The passphrase slot, when there is one: `keys.js` sends a bare string or
    // buffer through `prepareAsymmetricKey`'s early return with no options at
    // all, so the slot may not exist. Reading it as `undefined` is correct — an
    // absent slot means no passphrase, which is exactly the condition a PEM block
    // without an `ENCRYPTED` header needs.
    let passphrase = values.opt(*offset).and_then(value_bytes);
    *offset += 1;
    Some((
        PublicKeyEncoding {
            format: read.format,
            encoding: read.encoding,
            output_key_object: false,
            ec_point_form: read.ec_point_form,
        },
        passphrase,
    ))
}

/// Reads a private-key encoding configuration, including its cipher tail.
fn read_private_config(
    scope: &mut v8::PinScope<'_, '_>,
    values: &Values,
    offset: &mut usize,
    context: EncodingContext,
) -> Option<PrivateKeyEncoding> {
    let mut read = match read_format_and_type(values, offset, context) {
        Ok(read) => read,
        Err(error) => {
            throw_encoding_error(scope, error);
            return None;
        }
    };
    if let Err(error) = read_private_key_tail(values, offset, context, read.format, &mut read) {
        throw_encoding_error(scope, error);
        return None;
    }
    Some(PrivateKeyEncoding {
        format: read.format,
        encoding: read.encoding,
        cipher: read.cipher,
        passphrase: read.passphrase,
        output_key_object: read.output_key_object,
        ec_point_form: read.ec_point_form,
    })
}

fn throw_encoding_error(scope: &mut v8::PinScope<'_, '_>, error: EncodingError) {
    match error {
        EncodingError::UnknownFormat | EncodingError::UnknownEncoding => {
            throw(scope, &KeyError::InvalidKeyType)
        }
        EncodingError::Unsupported => throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: "selected".to_string(),
                detail: "is not a valid key encoding",
            },
        ),
    }
}

/// Reports a failed parse with the shape `ThrowCryptoError` builds.
fn report_parse_failure(
    scope: &mut v8::PinScope<'_, '_>,
    failure: &rn_crypto_openssl::ParseFailure,
    message: &'static str,
) {
    match failure.kind {
        rn_crypto_openssl::ParseError::NeedPassphrase => throw(scope, &KeyError::MissingPassphrase),
        rn_crypto_openssl::ParseError::NotRecognized | rn_crypto_openssl::ParseError::Failed => {
            throw(
                scope,
                &KeyError::OpenSsl {
                    message,
                    packed: failure.packed(),
                },
            )
        }
    }
}

/// Imports a raw key from slots 1 (data), 3 (algorithm name) and 5 (curve).
///
/// The layout is `ImportRawKeyFromArgs`'s: the format is in slot 2, the algorithm
/// name in slot 3, the passphrase in slot 4 and the curve in slot 5.
fn import_raw_key(
    scope: &mut v8::PinScope<'_, '_>,
    values: &Values,
    base: usize,
    format: KeyFormat,
    target: KeyType,
) -> Option<KeyData> {
    // The slots are relative to `base`, which is 0 for a `KeyObjectHandle.import`
    // call and the key's own index when `Sign.sign`'s argument list is walked.
    // Absolute indices here silently read the wrong slot for the second shape,
    // which surfaces as "Failed to read private key" with no clue why.
    // `base` is the *data* slot. The key's five slots are data, format, type,
    // passphrase, namedCurve, so the type name and the curve name sit two and
    // four slots along — not three and five, which is the same arithmetic shifted
    // by the format slot that `read_format_and_type` has already consumed.
    let bytes = values.opt(base).and_then(value_bytes)?;
    let Some(type_name) = values.opt(base + 2).and_then(|value| match value {
        Value::String(text) => Some(text.clone()),
        _ => None,
    }) else {
        throw(scope, &KeyError::InvalidKeyType);
        return None;
    };
    let Some(algorithm) = KeyAlgorithm::from_name(&type_name) else {
        throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: type_name,
                detail: "is not a supported key type",
            },
        );
        return None;
    };
    let named_curve = values.opt(base + 4).and_then(|value| match value {
        Value::String(text) => Some(text.clone()),
        _ => None,
    });
    match import_raw(format, algorithm, &bytes, named_curve.as_deref()) {
        Ok(key) => KeyData::asymmetric(target, key),
        Err(error) => {
            report_key_format_error(scope, error, &type_name);
            None
        }
    }
}

fn report_key_format_error(
    scope: &mut v8::PinScope<'_, '_>,
    error: KeyFormatError,
    type_name: &str,
) {
    match error {
        KeyFormatError::UnknownAlgorithm | KeyFormatError::UnavailableAlgorithm => throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: type_name.to_string(),
                detail: "is not a supported key type",
            },
        ),
        KeyFormatError::UnsupportedFormat => throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: type_name.to_string(),
                detail: "does not support this key encoding",
            },
        ),
        KeyFormatError::UnknownCurve => throw(scope, &KeyError::InvalidCurve),
        KeyFormatError::InvalidData => throw(
            scope,
            &KeyError::OpenSsl {
                message: "Invalid key data",
                packed: 0,
            },
        ),
    }
}

/// Imports a key from a JWK object.
///
/// # Which families this covers
///
/// `RSA`, `EC` and `OKP` are the three the RFC 7518/8037 formats define, and they
/// are what every Node test in the crypto selection uses. `AKP` (the
/// post-quantum `ML-DSA`/`ML-KEM` form) is a different shape — `alg` and `pub`
/// rather than `crv` and `x` — and its import needs a provider this build has but
/// that no test here exercises for JWK. It reports rather than silently reading
/// the wrong fields as empty.
fn import_jwk(
    scope: &mut v8::PinScope<'_, '_>,
    jwk: v8::Local<v8::Object>,
    target: KeyType,
) -> Option<KeyData> {
    let Some(kty) = property_string(scope, jwk, "kty") else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK key format"));
        return None;
    };
    match kty.as_str() {
        "oct" => import_jwk_oct(scope, jwk),
        "RSA" => import_jwk_rsa(scope, jwk, target),
        "EC" => import_jwk_ec(scope, jwk, target),
        "OKP" => import_jwk_okp(scope, jwk, target),
        "AKP" => {
            throw(scope, &KeyError::InvalidJwk("Unsupported JWK AKP \"alg\""));
            None
        }
        _ => {
            let message = format_jwk_unsupported(&kty);
            let _ = message;
            throw(
                scope,
                &KeyError::InvalidJwk("is not a supported JWK key type"),
            );
            None
        }
    }
}

/// The `"%s is not a supported JWK key type"` message needs the type interpolated
/// into a fixed template; `KeyError::InvalidJwk` carries a `&'static str`, so the
/// caller's text is dropped here rather than leaked.
fn format_jwk_unsupported(kty: &str) -> String {
    format!("{kty} is not a supported JWK key type")
}

/// `oct`: a secret key in base64url.
fn import_jwk_oct(scope: &mut v8::PinScope<'_, '_>, jwk: v8::Local<v8::Object>) -> Option<KeyData> {
    let Some(k) = property_string(scope, jwk, "k") else {
        throw(
            scope,
            &KeyError::InvalidJwk("Invalid JWK secret key format"),
        );
        return None;
    };
    let Some(bytes) = base64url_decode(&k) else {
        throw(
            scope,
            &KeyError::InvalidJwk("Invalid JWK secret key format"),
        );
        return None;
    };
    Some(KeyData::secret(bytes))
}

/// `RSA`: `n` and `e` are required, and `d` plus the CRT parameters make it a
/// private key.
fn import_jwk_rsa(
    scope: &mut v8::PinScope<'_, '_>,
    jwk: v8::Local<v8::Object>,
    target: KeyType,
) -> Option<KeyData> {
    use openssl::rsa::Rsa;

    let modulus = property_bignum(scope, jwk, "n");
    let exponent = property_bignum(scope, jwk, "e");
    let (Some(n), Some(e)) = (modulus, exponent) else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK RSA key"));
        return None;
    };

    let private = if target == KeyType::Private || property_string(scope, jwk, "d").is_some() {
        property_bignum(scope, jwk, "d")
    } else {
        None
    };

    let Some(d) = private else {
        // Public-only: the key is `n` and `e`.
        let Ok(rsa) = Rsa::from_public_components(n, e) else {
            throw(scope, &KeyError::InvalidJwk("Invalid JWK RSA key"));
            return None;
        };
        let pkey = openssl::pkey::PKey::from_rsa(rsa).ok()?;
        let key = PKey::from_public(pkey)?;
        return KeyData::asymmetric(KeyType::Public, key);
    };

    // `from_private_components` wants all eight components; when a JWK omits the
    // CRT pair the builder is used directly so the key is still constructible.
    let built = match (
        property_bignum(scope, jwk, "p"),
        property_bignum(scope, jwk, "q"),
    ) {
        (Some(p), Some(q)) => {
            match (
                property_bignum(scope, jwk, "dp"),
                property_bignum(scope, jwk, "dq"),
                property_bignum(scope, jwk, "qi"),
            ) {
                (Some(dp), Some(dq), Some(qi)) => {
                    // All eight components present: the full constructor.
                    Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)
                }
                _ => openssl::rsa::RsaPrivateKeyBuilder::new(n, e, d)
                    .and_then(|builder| builder.set_factors(p, q))
                    .map(|builder| builder.build()),
            }
        }
        _ => openssl::rsa::RsaPrivateKeyBuilder::new(n, e, d).map(|builder| builder.build()),
    };
    let Ok(rsa) = built else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK RSA key"));
        return None;
    };
    let Ok(pkey) = openssl::pkey::PKey::from_rsa(rsa) else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK RSA key"));
        return None;
    };
    KeyData::asymmetric(KeyType::Private, PKey::from_private(pkey))
}

/// `EC`: `crv`, `x` and `y` describe the point; `d` makes it private.
fn import_jwk_ec(
    scope: &mut v8::PinScope<'_, '_>,
    jwk: v8::Local<v8::Object>,
    target: KeyType,
) -> Option<KeyData> {
    use openssl::ec::{EcGroup, EcKey, EcPoint};

    let Some(curve) = property_string(scope, jwk, "crv") else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK EC key"));
        return None;
    };
    let Some(nid) = curve_nid(&curve) else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK EC key"));
        return None;
    };
    let group = match EcGroup::from_curve_name(nid) {
        Ok(group) => group,
        Err(_) => {
            throw(scope, &KeyError::InvalidJwk("Invalid JWK EC key"));
            return None;
        }
    };
    let (Some(x), Some(y)) = (
        property_bignum(scope, jwk, "x"),
        property_bignum(scope, jwk, "y"),
    ) else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK EC key"));
        return None;
    };

    let d = if target == KeyType::Private {
        property_bignum(scope, jwk, "d")
    } else {
        None
    };

    if let Some(d) = d {
        let mut context = match openssl::bn::BigNumContext::new() {
            Ok(context) => context,
            Err(_) => {
                throw(scope, &KeyError::InvalidJwk("Invalid JWK EC key"));
                return None;
            }
        };
        let mut point = match EcPoint::new(&group) {
            Ok(point) => point,
            Err(_) => {
                throw(scope, &KeyError::InvalidJwk("Invalid JWK EC key"));
                return None;
            }
        };
        if point
            .set_affine_coordinates_gfp(&group, &x, &y, &mut context)
            .is_err()
        {
            throw(scope, &KeyError::InvalidJwk("Invalid JWK EC key"));
            return None;
        }
        let key = match EcKey::from_private_components(&group, &d, &point) {
            Ok(key) => key,
            Err(_) => {
                throw(scope, &KeyError::InvalidJwk("Invalid JWK EC key"));
                return None;
            }
        };
        return finish_ec(key, KeyType::Private);
    }

    let key = match EcKey::from_public_key_affine_coordinates(&group, &x, &y) {
        Ok(key) => key,
        Err(_) => {
            throw(scope, &KeyError::InvalidJwk("Invalid JWK EC key"));
            return None;
        }
    };
    finish_ec_public(key)
}

fn finish_ec(
    key: openssl::ec::EcKey<openssl::pkey::Private>,
    key_type: KeyType,
) -> Option<KeyData> {
    let pkey = openssl::pkey::PKey::from_ec_key(key).ok()?;
    KeyData::asymmetric(key_type, PKey::from_private(pkey))
}

fn finish_ec_public(key: openssl::ec::EcKey<openssl::pkey::Public>) -> Option<KeyData> {
    let pkey = openssl::pkey::PKey::from_ec_key(key).ok()?;
    KeyData::asymmetric(KeyType::Public, PKey::from_public(pkey)?)
}

/// `OKP`: `crv` names Ed25519/X25519, `x` is the public key and `d` the private.
fn import_jwk_okp(
    scope: &mut v8::PinScope<'_, '_>,
    jwk: v8::Local<v8::Object>,
    target: KeyType,
) -> Option<KeyData> {
    let Some(curve) = property_string(scope, jwk, "crv") else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK OKP key"));
        return None;
    };
    let Some(algorithm) = KeyAlgorithm::from_name(&curve) else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK OKP key"));
        return None;
    };
    if !algorithm.is_okp() {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK OKP key"));
        return None;
    }
    let Some(public) = property_string(scope, jwk, "x").and_then(|x| base64url_decode(&x)) else {
        throw(scope, &KeyError::InvalidJwk("Invalid JWK OKP key"));
        return None;
    };
    let private = if target == KeyType::Private {
        property_string(scope, jwk, "d")
    } else {
        None
    };
    match private {
        Some(private) => {
            let Some(private) = base64url_decode(&private) else {
                throw(scope, &KeyError::InvalidJwk("Invalid JWK OKP key"));
                return None;
            };
            match import_raw_private_key(algorithm, &private, None) {
                Ok(key) => KeyData::asymmetric(KeyType::Private, key),
                Err(_) => {
                    throw(scope, &KeyError::InvalidJwk("Invalid JWK OKP key"));
                    None
                }
            }
        }
        None => match import_raw_public_key(algorithm, &public, None) {
            Ok(key) => KeyData::asymmetric(KeyType::Public, key),
            Err(_) => {
                throw(scope, &KeyError::InvalidJwk("Invalid JWK OKP key"));
                None
            }
        },
    }
}

/// Reads a JWK field that holds a base64url-encoded big-endian integer.
fn property_bignum(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
) -> Option<openssl::bn::BigNum> {
    let text = property_string(scope, object, name)?;
    let bytes = base64url_decode(&text)?;
    openssl::bn::BigNum::from_slice(&bytes).ok()
}

/// Resolves a JWK curve name to its NID.
///
/// JWKs use the RFC 7518 names, which are OpenSSL's short names for P-256 and
/// P-384 but not for P-521 (`secp521r1`), and the X25519/Ed25519 curves are key
/// types rather than EC groups.
fn curve_nid(curve: &str) -> Option<openssl::nid::Nid> {
    Some(match curve {
        "P-256" => openssl::nid::Nid::X9_62_PRIME256V1,
        "P-384" => openssl::nid::Nid::SECP384R1,
        "P-521" => openssl::nid::Nid::SECP521R1,
        _ => return None,
    })
}

/// Decodes base64url with no padding, which is the JWK encoding.
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    use openssl::base64;
    // OpenSSL's decoder wants padding; JWK strips it.
    let mut padded = text.replace('-', "+").replace('_', "/");
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    base64::decode_block(&padded).ok()
}

/// Encodes bytes as base64url with no padding, for JWK export.
fn base64url_encode(bytes: &[u8]) -> String {
    use openssl::base64;
    base64::encode_block(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

fn get_key_type<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    match with_key_data(scope, args.this(), |data| data.key_type().as_raw()) {
        Some(key_type) => rv.set(v8::Integer::new(scope, key_type).into()),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

fn get_symmetric_key_size<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    match with_key_data(scope, args.this(), KeyData::symmetric_key_size) {
        Some(size) => rv.set(v8::Integer::new(scope, size as i32).into()),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

fn get_asymmetric_key_type<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let name = with_key_data(scope, args.this(), |data| {
        data.asymmetric_key().and_then(|key| key.key_type_name())
    });
    match name {
        Some(Some(name)) => {
            if let Some(text) = v8::String::new(scope, name) {
                rv.set(text.into());
            }
        }
        Some(None) => rv.set(v8::undefined(scope).into()),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

fn check_ec_key_data<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let result = with_key_data(scope, args.this(), |data| {
        data.asymmetric_key().map(|key| key.ec_check())
    });
    match result {
        Some(Some(checked)) => rv.set(v8::Boolean::new(scope, checked).into()),
        Some(None) => rv.set(v8::Boolean::new(scope, false).into()),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

fn equals<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(other) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    // Both keys are cloned out before comparing: the two `with_key_data` calls
    // each need the scope, and a borrow of one key may not span the other's.
    let left = with_key_data(scope, args.this(), KeyData::clone);
    let right = with_key_data(scope, other, KeyData::clone);
    let result = match (left, right) {
        (Some(left), Some(right)) => Some(keys_equal(&left, &right)),
        _ => None,
    };
    match result {
        Some(Ok(equal)) => rv.set(v8::Boolean::new(scope, equal).into()),
        Some(Err(())) => throw(scope, &KeyError::UnsupportedOperation),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

/// `KeyObjectHandle::Equals`: compares two keys' material.
pub(crate) fn keys_equal(left: &KeyData, right: &KeyData) -> Result<bool, ()> {
    if left.key_type() != right.key_type() {
        // Node's `CHECK_EQ(key_type, key2.GetKeyType())` is a crash there and an
        // error here; `keys.js` compares the types before calling.
        return Err(());
    }
    match (left.symmetric_key(), right.symmetric_key()) {
        (Some(left), Some(right)) => Ok(constant_time_equal(left, right)),
        (None, None) => {
            let (Some(left), Some(right)) = (left.asymmetric_key(), right.asymmetric_key()) else {
                return Ok(false);
            };
            match left.eq(right) {
                EqualResult::Equal => Ok(true),
                EqualResult::Unequal => Ok(false),
                // -2 from `EVP_PKEY_eq`: different key types, which Node reports
                // as `ERR_CRYPTO_UNSUPPORTED_OPERATION` rather than `false`.
                EqualResult::Incomparable => Err(()),
            }
        }
        _ => Ok(false),
    }
}

/// `CRYPTO_memcmp`, so comparing two keys does not leak where they differ.
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

fn get_key_detail<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(target) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw(scope, &KeyError::InvalidThis("KeyObjectHandle"));
        return;
    };
    let Some(detail) = with_key_data(scope, args.this(), key_detail) else {
        throw(scope, &KeyError::InvalidThis("KeyObjectHandle"));
        return;
    };
    match detail {
        Some(Some(detail)) => {
            detail.write(scope, target);
            rv.set(target.into());
        }
        Some(None) => throw(scope, &KeyError::InvalidKeyType),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

/// The `asymmetricKeyDetails` values for a key, resolved without V8.
pub(crate) fn key_detail(data: &KeyData) -> Option<Option<KeyDetail>> {
    if data.key_type() == KeyType::Secret {
        // A secret key's only detail is its length in bits, which
        // `GetSecretKeyDetail` writes as `length`.
        return Some(Some(KeyDetail::Secret {
            bits: data.symmetric_key_size() * 8,
        }));
    }
    let key = data.asymmetric_key()?;
    let Some(algorithm) = key.algorithm() else {
        return Some(None);
    };
    if algorithm.is_rsa() {
        let Some(detail) = key.rsa_detail() else {
            return Some(None);
        };
        return Some(Some(KeyDetail::Rsa(detail)));
    }
    if algorithm == rn_crypto_openssl::DSA {
        let Some(detail) = key.dsa_detail() else {
            return Some(None);
        };
        return Some(Some(KeyDetail::Dsa(detail)));
    }
    if algorithm == rn_crypto_openssl::EC {
        return Some(Some(KeyDetail::Ec {
            named_curve: key.ec_curve_name(),
        }));
    }
    if algorithm == rn_crypto_openssl::DH {
        // `GetDhKeyDetail` writes nothing at all.
        return Some(Some(KeyDetail::Empty));
    }
    // `ERR_CRYPTO_INVALID_KEYTYPE` for a key type with no detail.
    Some(None)
}

/// The fields `keyDetail` writes onto the target object.
pub(crate) enum KeyDetail {
    Secret { bits: usize },
    Rsa(rn_crypto_openssl::RsaDetail),
    Dsa(rn_crypto_openssl::DsaDetail),
    Ec { named_curve: Option<String> },
    Empty,
}

impl KeyDetail {
    fn write(self, scope: &mut v8::PinScope<'_, '_>, target: v8::Local<v8::Object>) {
        match self {
            Self::Secret { bits } => set_number(scope, target, "length", bits as f64),
            Self::Rsa(detail) => {
                set_number(
                    scope,
                    target,
                    "modulusLength",
                    f64::from(detail.modulus_length),
                );
                // `publicExponent` is an `ArrayBuffer` of the big-endian bytes,
                // not a number: the field's type is the encoding, and a bigger
                // exponent would not fit a double.
                if let Some(buffer) = array_buffer(scope, &detail.public_exponent) {
                    set_value(scope, target, "publicExponent", buffer.into());
                }
                if let Some(pss) = detail.pss {
                    set_text(scope, target, "hashAlgorithm", &pss.digest);
                    if let Some(mgf1) = pss.mgf1_digest {
                        set_text(scope, target, "mgf1HashAlgorithm", &mgf1);
                    }
                    set_number(scope, target, "saltLength", f64::from(pss.salt_length));
                }
            }
            Self::Dsa(detail) => {
                set_number(scope, target, "modulusLength", detail.modulus_length as f64);
                set_number(scope, target, "divisorLength", detail.divisor_length as f64);
            }
            Self::Ec { named_curve } => {
                if let Some(name) = named_curve {
                    set_text(scope, target, "namedCurve", &name);
                }
            }
            Self::Empty => {}
        }
    }
}

fn set_number(
    scope: &mut v8::PinScope<'_, '_>,
    target: v8::Local<v8::Object>,
    name: &str,
    value: f64,
) {
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    target.set(scope, key.into(), v8::Number::new(scope, value).into());
}

fn set_text(
    scope: &mut v8::PinScope<'_, '_>,
    target: v8::Local<v8::Object>,
    name: &str,
    value: &str,
) {
    let (Some(key), Some(text)) = (v8::String::new(scope, name), v8::String::new(scope, value))
    else {
        return;
    };
    target.set(scope, key.into(), text.into());
}

fn set_value(
    scope: &mut v8::PinScope<'_, '_>,
    target: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) {
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    target.set(scope, key.into(), value);
}

/// Builds an `ArrayBuffer` over a copy of `bytes`.
fn array_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::ArrayBuffer>> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice())
            .make_shared();
    Some(v8::ArrayBuffer::with_backing_store(scope, &store))
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

fn export<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let values = values_of(scope, &args);
    let Some(key_type) = with_key_data(scope, args.this(), KeyData::key_type) else {
        throw(scope, &KeyError::InvalidThis("KeyObjectHandle"));
        return;
    };

    if key_type == KeyType::Secret {
        let bytes = with_key_data(scope, args.this(), |data| {
            data.symmetric_key().map(<[u8]>::to_vec)
        })
        .flatten();
        match bytes {
            Some(bytes) => emit_buffer(scope, &mut rv, &bytes),
            None => throw(scope, &KeyError::InvalidKeyType),
        }
        return;
    }

    let mut offset = 0;
    if key_type == KeyType::Public {
        let Some((config, _passphrase)) = read_public_config(scope, &values, &mut offset) else {
            return;
        };
        export_public(scope, &args, &mut rv, &config);
        return;
    }

    let Some(config) = read_private_config(scope, &values, &mut offset, EncodingContext::Export)
    else {
        return;
    };
    // The private raw formats are handled the same way and for the same reason.
    match config.format {
        Some(KeyFormat::RawPrivate) => {
            let bytes = with_key_data(scope, args.this(), |data| {
                let key = data.asymmetric_key()?;
                Some(match key.algorithm() {
                    Some(algorithm) if algorithm == rn_crypto_openssl::EC => {
                        key.ec_private_scalar()
                    }
                    _ => key.raw_private_key(),
                })
            });
            match bytes {
                Some(Some(Some(bytes))) => emit_buffer(scope, &mut rv, &bytes),
                Some(Some(None)) => throw(
                    scope,
                    &KeyError::OperationFailed("Failed to get raw private key"),
                ),
                _ => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
            }
            return;
        }
        Some(KeyFormat::RawSeed) => {
            let bytes = with_key_data(scope, args.this(), |data| {
                data.asymmetric_key().and_then(|key| key.raw_seed())
            });
            match bytes {
                Some(Some(bytes)) => emit_buffer(scope, &mut rv, &bytes),
                Some(None) => throw(
                    scope,
                    &KeyError::OperationFailed("key does not have an available seed"),
                ),
                None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
            }
            return;
        }
        _ => {}
    }
    export_private(scope, &args, &mut rv, &config);
}

fn export_public(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    config: &PublicKeyEncoding,
) {
    // The raw formats are not encodings of the key: `raw-public` is the
    // algorithm's public bytes and an EC point otherwise, so it does not go
    // through `PKey::write_public`, which reports `Ok(None)` for it.
    if config.format == Some(KeyFormat::RawPublic) {
        let result = with_key_data(scope, args.this(), |data| {
            let key = data.asymmetric_key()?;
            let bytes = match key.algorithm() {
                Some(algorithm) if algorithm == rn_crypto_openssl::EC => {
                    let form = EcPointForm::from_raw(config.ec_point_form)
                        .unwrap_or(EcPointForm::Uncompressed);
                    key.ec_public_point(form)
                }
                _ => key.raw_public_key(),
            };
            Some(bytes)
        });
        match result {
            Some(Some(Some(bytes))) => emit_buffer(scope, rv, &bytes),
            Some(Some(None)) => throw(
                scope,
                &KeyError::OperationFailed("Failed to get raw public key"),
            ),
            _ => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
        }
        return;
    }
    let encoded = with_key_data(scope, args.this(), |data| {
        let key = data.asymmetric_key()?;
        Some(key.write_public(config))
    })
    .flatten();
    match encoded {
        Some(Ok(Some(encoded))) => emit_encoded(scope, rv, &encoded),
        Some(Ok(None)) => throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: "raw".to_string(),
                detail: "must be exported with the raw exporter",
            },
        ),
        Some(Err(failure)) => report_parse_failure(scope, &failure, "Failed to encode public key"),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

fn export_private(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    config: &PrivateKeyEncoding,
) {
    let encoded = with_key_data(scope, args.this(), |data| {
        let key = data.asymmetric_key()?;
        Some(key.write_private(config))
    })
    .flatten();
    match encoded {
        Some(Ok(Some(encoded))) => emit_encoded(scope, rv, &encoded),
        Some(Ok(None)) => throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: "raw".to_string(),
                detail: "must be exported with the raw exporter",
            },
        ),
        Some(Err(failure)) => report_parse_failure(scope, &failure, "Failed to encode private key"),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

/// Emits an encoded key: a string for PEM, a `Buffer` for DER.
fn emit_encoded(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue,
    encoded: &rn_crypto_openssl::EncodedKey,
) {
    if encoded.is_text() {
        match std::str::from_utf8(&encoded.bytes) {
            Ok(text) => {
                if let Some(value) = v8::String::new(scope, text) {
                    rv.set(value.into());
                }
            }
            Err(_) => throw(
                scope,
                &KeyError::OperationFailed("PEM encoding is not valid UTF-8"),
            ),
        }
        return;
    }
    emit_buffer(scope, rv, &encoded.bytes);
}

/// `handle.exportJwk(object, handleRsaPss)` fills `object` and returns it.
fn export_jwk<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(target) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw(scope, &KeyError::InvalidThis("KeyObjectHandle"));
        return;
    };
    let handle_rsa_pss = args.get(1).boolean_value(scope);
    let result = with_key_data(scope, args.this(), |data| {
        export_jwk_fields(data, handle_rsa_pss)
    });
    match result {
        Some(Ok(fields)) => {
            for (name, value) in fields {
                set_text(scope, target, name, &value);
            }
            rv.set(target.into());
        }
        Some(Err(error)) => throw(scope, &error),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

/// The JWK fields for a key, as `(name, value)` pairs.
///
/// Returns the *secret* shape for a secret key and the asymmetric one otherwise.
/// `handle_rsa_pss` decides whether an `RSA-PSS` key exports as `RSA` — a
/// restricted PSS key has the same components, and only the algorithm changes.
pub(crate) fn export_jwk_fields(
    data: &KeyData,
    handle_rsa_pss: bool,
) -> Result<Vec<(&'static str, String)>, KeyError> {
    if data.key_type() == KeyType::Secret {
        // `ExportJWKSecretKey`: `kty: 'oct'` and `k` in base64url.
        let bytes = data.symmetric_key().unwrap_or(&[]);
        return Ok(vec![
            ("kty", "oct".to_string()),
            ("k", base64url_encode(bytes)),
        ]);
    }
    let key = data.asymmetric_key().ok_or(KeyError::InvalidKeyType)?;
    let Some(algorithm) = key.algorithm() else {
        return Err(KeyError::InvalidJwk("Unsupported JWK key type"));
    };
    if algorithm.is_rsa() || (handle_rsa_pss && algorithm == rn_crypto_openssl::RSA_PSS) {
        let detail = key.rsa_detail().ok_or(KeyError::InvalidKeyType)?;
        let rsa = key
            .openssl_ref()
            .rsa()
            .map_err(|_| KeyError::InvalidKeyType)?;
        let mut fields = vec![
            ("kty", "RSA".to_string()),
            ("n", base64url_encode(&rsa.n().to_vec())),
            ("e", base64url_encode(&detail.public_exponent)),
        ];
        // A private RSA key exports its CRT components. `d` is the private
        // exponent; without it the object is a public key.
        if data.key_type() == KeyType::Private {
            fields.push(("d", base64url_encode(&rsa.d().to_vec())));
            if let (Some(p), Some(q)) = (rsa.p(), rsa.q()) {
                fields.push(("p", base64url_encode(&p.to_vec())));
                fields.push(("q", base64url_encode(&q.to_vec())));
                fields.push((
                    "dp",
                    base64url_encode(&rsa.dmp1().ok_or(KeyError::InvalidKeyType)?.to_vec()),
                ));
                fields.push((
                    "dq",
                    base64url_encode(&rsa.dmq1().ok_or(KeyError::InvalidKeyType)?.to_vec()),
                ));
                fields.push((
                    "qi",
                    base64url_encode(&rsa.iqmp().ok_or(KeyError::InvalidKeyType)?.to_vec()),
                ));
            }
        }
        return Ok(fields);
    }
    if algorithm == rn_crypto_openssl::EC {
        let ec = key
            .openssl_ref()
            .ec_key()
            .map_err(|_| KeyError::InvalidKeyType)?;
        let curve = jwk_curve_name(ec.group()).ok_or(KeyError::InvalidKeyType)?;
        let mut context =
            openssl::bn::BigNumContext::new().map_err(|_| KeyError::InvalidKeyType)?;
        let point = ec.public_key();
        let mut x = openssl::bn::BigNum::new().map_err(|_| KeyError::InvalidKeyType)?;
        let mut y = openssl::bn::BigNum::new().map_err(|_| KeyError::InvalidKeyType)?;
        point
            .affine_coordinates_gfp(ec.group(), &mut x, &mut y, &mut context)
            .map_err(|_| KeyError::InvalidKeyType)?;
        let width = ec.group().order_bits().div_ceil(8) as i32;
        let mut fields = vec![
            ("kty", "EC".to_string()),
            ("crv", curve.to_string()),
            (
                "x",
                base64url_encode(
                    &x.to_vec_padded(width)
                        .map_err(|_| KeyError::InvalidKeyType)?,
                ),
            ),
            (
                "y",
                base64url_encode(
                    &y.to_vec_padded(width)
                        .map_err(|_| KeyError::InvalidKeyType)?,
                ),
            ),
        ];
        if data.key_type() == KeyType::Private {
            fields.push((
                "d",
                base64url_encode(
                    &ec.private_key()
                        .to_vec_padded(width)
                        .map_err(|_| KeyError::InvalidKeyType)?,
                ),
            ));
        }
        return Ok(fields);
    }
    if algorithm.is_okp() {
        let Some(public) = key.raw_public_key() else {
            return Err(KeyError::OperationFailed("Failed to export JWK"));
        };
        let mut fields = vec![
            ("kty", "OKP".to_string()),
            ("crv", algorithm.name().to_string()),
            ("x", base64url_encode(&public)),
        ];
        if data.key_type() == KeyType::Private {
            let Some(private) = key.raw_private_key() else {
                return Err(KeyError::OperationFailed("Failed to export JWK"));
            };
            fields.push(("d", base64url_encode(&private)));
        }
        return Ok(fields);
    }
    Err(KeyError::InvalidJwk("Unsupported JWK key type"))
}

/// The JWK `crv` name for an EC group, which is not the OpenSSL short name for
/// P-521.
fn jwk_curve_name(group: &openssl::ec::EcGroupRef) -> Option<&'static str> {
    Some(match group.curve_name()? {
        openssl::nid::Nid::X9_62_PRIME256V1 => "P-256",
        openssl::nid::Nid::SECP384R1 => "P-384",
        openssl::nid::Nid::SECP521R1 => "P-521",
        _ => return None,
    })
}

fn raw_public_key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let result = with_key_data(scope, args.this(), |data| {
        let key = data.asymmetric_key()?;
        Some(
            key.algorithm()
                .map(|algorithm| (key.raw_public_key(), algorithm)),
        )
    });
    match result {
        Some(Some(Some((Some(bytes), _)))) => emit_buffer(scope, &mut rv, &bytes),
        Some(Some(Some((None, algorithm)))) if algorithm.supports_raw_public() => throw(
            scope,
            &KeyError::OperationFailed("Failed to get raw public key"),
        ),
        Some(Some(Some((_, _)))) => throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: "raw-public".to_string(),
                detail: "is not supported for this key type",
            },
        ),
        _ => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

fn raw_private_key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let result = with_key_data(scope, args.this(), |data| {
        let key = data.asymmetric_key()?;
        Some(
            key.algorithm()
                .map(|algorithm| (key.raw_private_key(), algorithm)),
        )
    });
    match result {
        Some(Some(Some((Some(bytes), _)))) => emit_buffer(scope, &mut rv, &bytes),
        Some(Some(Some((None, algorithm)))) if algorithm.supports_raw_private() => throw(
            scope,
            &KeyError::OperationFailed("Failed to get raw private key"),
        ),
        Some(Some(Some((_, _)))) => throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: "raw-private".to_string(),
                detail: "is not supported for this key type",
            },
        ),
        _ => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

fn raw_seed<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let result = with_key_data(scope, args.this(), |data| {
        let key = data.asymmetric_key()?;
        Some(
            key.algorithm()
                .map(|algorithm| (key.raw_seed(), algorithm.seed_size())),
        )
    });
    match result {
        Some(Some(Some((Some(bytes), _)))) => emit_buffer(scope, &mut rv, &bytes),
        // A key with a seed format that will not export it was imported from an
        // expanded form, so the seed is gone.
        Some(Some(Some((None, size)))) if size != 0 => throw(
            scope,
            &KeyError::OperationFailed("key does not have an available seed"),
        ),
        Some(Some(Some((_, _)))) => throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: "raw-seed".to_string(),
                detail: "is not supported for this key type",
            },
        ),
        _ => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

fn export_ec_public_raw<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let form = args.get(0).int32_value(scope).unwrap_or(0);
    let Some(form) = EcPointForm::from_raw(form) else {
        throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: "raw-public".to_string(),
                detail: "has an invalid point conversion form",
            },
        );
        return;
    };
    let result = with_key_data(scope, args.this(), |data| match data.asymmetric_key() {
        None => EcExport::NotAKey,
        Some(key) if !key.is_a(rn_crypto_openssl::EC) => EcExport::NotEc,
        Some(key) => match key.ec_public_point(form) {
            Some(bytes) => EcExport::Ok(bytes),
            None => EcExport::Failed,
        },
    });
    report_ec_export(scope, &mut rv, result, "raw-public", "public");
}

fn export_ec_private_raw<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let result = with_key_data(scope, args.this(), |data| match data.asymmetric_key() {
        None => EcExport::NotAKey,
        Some(key) if !key.is_a(rn_crypto_openssl::EC) => EcExport::NotEc,
        Some(key) => match key.ec_private_scalar() {
            Some(bytes) => EcExport::Ok(bytes),
            None => EcExport::Failed,
        },
    });
    report_ec_export(scope, &mut rv, result, "raw-private", "private");
}

/// The outcome of an EC raw export, with the three failures kept distinct.
///
/// They are distinct because Node reports them as different errors: a non-EC key
/// is `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS`, an EC key whose point will not
/// encode is `ERR_CRYPTO_OPERATION_FAILED`. Folding them into nested `Option`s
/// made the two indistinguishable, which is why this enum exists.
enum EcExport {
    Ok(Vec<u8>),
    /// The receiver is not a native key object.
    NotAKey,
    /// The key exists but is not an EC key.
    NotEc,
    /// The key is EC and its material would not export.
    Failed,
}

fn report_ec_export(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue,
    result: Option<EcExport>,
    format: &str,
    half: &'static str,
) {
    match result {
        Some(EcExport::Ok(bytes)) => emit_buffer(scope, rv, &bytes),
        Some(EcExport::NotEc) => throw(
            scope,
            &KeyError::IncompatibleKeyOptions {
                encoding: format.to_string(),
                detail: "is only supported for EC keys",
            },
        ),
        Some(EcExport::Failed) => throw(
            scope,
            &KeyError::OperationFailed(match half {
                "public" => "Failed to export EC public key",
                _ => "Failed to export EC private key",
            }),
        ),
        Some(EcExport::NotAKey) | None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

fn export_ec_private_pkcs8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let encoded = with_key_data(scope, args.this(), |data| {
        data.asymmetric_key().and_then(|key| key.ec_private_pkcs8())
    });
    match encoded {
        Some(Some(bytes)) => emit_buffer(scope, &mut rv, &bytes),
        Some(None) => throw(
            scope,
            &KeyError::OperationFailed("Failed to export EC private key"),
        ),
        None => throw(scope, &KeyError::InvalidThis("KeyObjectHandle")),
    }
}

/// Emits bytes as a real `Buffer`, which every export path returns.
fn emit_buffer(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, bytes: &[u8]) {
    match crate::install::buffer_from(scope, bytes) {
        Some(value) => rv.set(value),
        None => throw(
            scope,
            &KeyError::OperationFailed("cannot allocate the key buffer"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rn_crypto_openssl::PKey;

    fn ec_key() -> PKey {
        PKey::from_private(openssl::pkey::PKey::ec_gen("prime256v1").expect("P-256 generates"))
    }

    fn rsa_key() -> PKey {
        PKey::from_private(
            openssl::pkey::PKey::private_key_from_pem(
                include_str!("../tests/data/rsa-2048.pem").as_bytes(),
            )
            .expect("the fixture parses"),
        )
    }

    #[test]
    fn equal_secret_keys_compare_equal() {
        let left = KeyData::secret(vec![1, 2, 3]);
        let right = KeyData::secret(vec![1, 2, 3]);
        assert_eq!(keys_equal(&left, &right), Ok(true));
    }

    #[test]
    fn different_secret_keys_do_not() {
        let left = KeyData::secret(vec![1, 2, 3]);
        assert_eq!(
            keys_equal(&left, &KeyData::secret(vec![1, 2, 4])),
            Ok(false)
        );
        // A length difference is not a prefix match.
        assert_eq!(keys_equal(&left, &KeyData::secret(vec![1, 2])), Ok(false));
    }

    #[test]
    fn the_same_asymmetric_key_compares_equal() {
        let key = ec_key();
        let left = KeyData::asymmetric(KeyType::Private, key.clone()).expect("private");
        let right = KeyData::asymmetric(KeyType::Private, key).expect("private");
        assert_eq!(keys_equal(&left, &right), Ok(true));
    }

    #[test]
    fn a_public_view_of_a_private_key_is_not_comparable() {
        // The type is compared before the key material, which mirrors Node's
        // `CHECK_EQ(key_type, key2.GetKeyType())`. `keys.js` never calls it with
        // mismatched types, so the error is the honest answer.
        let key = ec_key();
        let private = KeyData::asymmetric(KeyType::Private, key.clone()).expect("private");
        let public = KeyData::asymmetric(KeyType::Public, key).expect("public");
        assert_eq!(keys_equal(&private, &public), Err(()));
    }

    #[test]
    fn a_secret_and_an_asymmetric_key_are_not_comparable() {
        let secret = KeyData::secret(vec![1, 2, 3]);
        let asymmetric = KeyData::asymmetric(KeyType::Private, ec_key()).expect("private");
        assert_eq!(keys_equal(&secret, &asymmetric), Err(()));
    }

    #[test]
    fn a_secret_key_detail_reports_its_length_in_bits() {
        let data = KeyData::secret(vec![0u8; 16]);
        match key_detail(&data) {
            Some(Some(KeyDetail::Secret { bits })) => assert_eq!(bits, 128),
            _ => panic!("expected a secret detail"),
        }
    }

    #[test]
    fn an_ec_key_detail_reports_its_curve() {
        let data = KeyData::asymmetric(KeyType::Private, ec_key()).expect("private");
        match key_detail(&data) {
            Some(Some(KeyDetail::Ec { named_curve })) => {
                assert_eq!(named_curve.as_deref(), Some("prime256v1"));
            }
            _ => panic!("expected an EC detail"),
        }
    }

    #[test]
    fn an_rsa_key_detail_reports_modulus_and_exponent() {
        let data = KeyData::asymmetric(KeyType::Private, rsa_key()).expect("private");
        match key_detail(&data) {
            Some(Some(KeyDetail::Rsa(detail))) => {
                assert_eq!(detail.modulus_length, 2048);
                assert_eq!(detail.public_exponent, vec![0x01, 0x00, 0x01]);
            }
            _ => panic!("expected an RSA detail"),
        }
    }

    /// A secret key's JWK is `kty` + `k`, and `k` is base64url with no padding.
    #[test]
    fn a_secret_jwk_has_the_oct_shape() {
        let data = KeyData::secret(vec![0xFF, 0xFE, 0xFD]);
        let fields = export_jwk_fields(&data, false).expect("a secret JWK");
        assert_eq!(fields[0], ("kty", "oct".to_string()));
        assert_eq!(fields[1].0, "k");
        // Padding stripped, and `+`/`/` are not base64url.
        assert!(!fields[1].1.contains('='));
        assert!(!fields[1].1.contains('+'));
        assert!(!fields[1].1.contains('/'));
    }

    /// An EC private JWK carries `crv`, `x`, `y` and `d`, in that order.
    #[test]
    fn an_ec_jwk_has_the_rfc7518_shape() {
        let data = KeyData::asymmetric(KeyType::Private, ec_key()).expect("private");
        let fields = export_jwk_fields(&data, false).expect("an EC JWK");
        let names: Vec<&str> = fields.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, vec!["kty", "crv", "x", "y", "d"]);
        assert_eq!(fields[0].1, "EC");
        assert_eq!(fields[1].1, "P-256", "the JWK name, not prime256v1");
        // P-256 coordinates are 32 bytes, which is 43 base64url characters.
        for (name, value) in &fields[2..] {
            assert_eq!(value.len(), 43, "{name} should be a 32-byte coordinate");
        }
    }

    /// A public EC JWK omits `d`.
    #[test]
    fn an_ec_public_jwk_omits_the_private_scalar() {
        let data = KeyData::asymmetric(KeyType::Public, ec_key()).expect("public");
        let fields = export_jwk_fields(&data, false).expect("an EC JWK");
        assert!(fields.iter().all(|(name, _)| *name != "d"));
    }

    /// An RSA private JWK carries the CRT components, which is what makes it
    /// importable as a usable key rather than a slow one.
    #[test]
    fn an_rsa_private_jwk_carries_its_crt_parameters() {
        let data = KeyData::asymmetric(KeyType::Private, rsa_key()).expect("private");
        let fields = export_jwk_fields(&data, false).expect("an RSA JWK");
        let names: Vec<&str> = fields.iter().map(|(name, _)| *name).collect();
        for required in ["kty", "n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            assert!(names.contains(&required), "missing {required}");
        }
        assert!(fields[1].1.len() > 300, "a 2048-bit modulus is long");
    }

    /// `base64url` round-trips, and the alphabet is the URL-safe one.
    #[test]
    fn base64url_round_trips() {
        for bytes in [&b""[..], b"a", b"ab", b"abc", &[0xFF, 0xFE, 0xFD, 0xFC][..]] {
            let encoded = base64url_encode(bytes);
            assert!(!encoded.contains('='), "no padding");
            assert!(
                !encoded.contains('+') && !encoded.contains('/'),
                "url alphabet"
            );
            assert_eq!(base64url_decode(&encoded).as_deref(), Some(bytes));
        }
    }

    #[test]
    fn constant_time_comparison_matches_slice_equality() {
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
        assert!(!constant_time_equal(b"abc", b"ab"));
        assert!(constant_time_equal(b"", b""));
    }
}
