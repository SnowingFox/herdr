//! `Sign` and `Verify` for `internalBinding('crypto')`.
//!
//! `src/crypto/crypto_sig.cc` and `src/crypto/crypto_rsa.cc` are the translation
//! units this mirrors. The four members it installs on the `crypto` namespace
//! object are `Sign`, `Verify`, `SignJob` and `RSACipherJob`; the padding and
//! digest helpers those expose (`RSA_PKCS1_PSS_PADDING`, the `kSigEnc*` values,
//! the default padding for a key variant) live here too, because they are what
//! `lib/internal/crypto/sig.js` passes straight back in.
//!
//! # What the JavaScript does with these
//!
//! `lib/internal/crypto/sig.js` builds a `Writable`-derived `Sign` whose only job
//! is validation and encoding. Every operation is `this[kHandle].<method>(...)`:
//!
//! | JavaScript | native |
//! | --- | --- |
//! | `new _Sign()` | `Sign` constructor |
//! | `init(algorithm)` | `SignInit` |
//! | `update(data, encoding)` | `SignUpdate` |
//! | `sign(key, format, type, passphrase, namedCurve, padding, saltLength, dsaEncoding)` | `SignFinal` |
//! | `new _Verify()` / `init` / `update` | the same three, on `Verify` |
//! | `verify(key, format, type, passphrase, namedCurve, signature, padding, saltLength, dsaEncoding)` | `VerifyFinal` |
//!
//! `SignJob` is the one-shot form (`crypto.sign`/`crypto.verify`), which takes
//! the key and the whole message in one call and returns `[err, result]` from
//! `run()`.
//!
//! # Why the key is decoded here rather than being a `KeyObjectHandle`
//!
//! Node's `Sign::SignFinal` calls `KeyObjectData::GetPrivateKeyFromJs` on its own
//! argument list. That decoder handles PEM, DER, JWK, the raw formats and an
//! already-constructed `KeyObjectHandle`, and it lives in `crypto_keys.cc` — so
//! it is `rn-bind-crypto-keys`'s, not a second copy here. This crate calls it and
//! gets back an owned `EVP_PKEY`.
//!
//! # State ownership
//!
//! The digest context lives in a heap allocation behind an internal field, freed
//! by a `Weak::with_guaranteed_finalizer`, exactly as the `Hash`, `Hmac` and
//! `DiffieHellman` handles do. V8's GC is the only thing that decides when a
//! handle dies, so a finalizer is the only correct place to release it.
//!
//! # The `kSignJobMode*` values
//!
//! `sig.js` passes `kSignJobModeSign`/`kSignJobModeVerify` as the second argument
//! of `SignJob`, and `rsa.js` passes them to the same class for WebCrypto. They
//! are installed from `rn-bind-crypto`'s constant table, which owns every
//! `kCryptoJob*`/`kSignJob*` number on the namespace.

use std::cell::RefCell;

use rn_crypto_openssl::{
    default_sign_padding, sign_final, signature_from_p1363, signature_to_p1363, verify_final,
    SignContext, SignError,
};
use rn_v8_sys::v8;

pub mod jobs;

pub use jobs::install_sign_job;

/// The members this crate installs, for the parent crate's `MEMBERS` list.
///
/// `Sign` and `Verify` are the two classes; `SignJob` is the one-shot job and
/// `RSACipherJob` the RSA encrypt/decrypt job from `crypto_rsa.cc`, which shares
/// this translation unit's padding handling.
pub const MEMBERS: &[&str] = &["Sign", "Verify", "SignJob", "RSACipherJob"];

/// The internal field holding the `*mut RefCell<SignContext>`.
const SIGN_STATE_FIELD: i32 = 0;
/// Both classes are `BaseObject`s in Node, so one field is all they need.
const INTERNAL_FIELD_COUNT: usize = 1;

/// Installs `Sign`, `Verify` and the two jobs onto `target`, the crypto namespace.
///
/// Called from `rn-bind-crypto`'s `install`, so this crate never builds a
/// namespace object of its own — the same reason `rn-bind-crypto-dh` exports
/// `install_classes` rather than a `BindingModule`.
///
/// Deliberately not named `register*`: `tools/regen-bindings.sh` treats a crate
/// with a `register` function as a namespace provider and then fails the
/// `rn-bindings` build on a symbol this crate does not export.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    install_sign_class(scope, target)?;
    install_verify_class(scope, target)?;
    install_sign_job(scope, target)?;
    Ok(())
}

/// The digest context behind a handle.
///
/// `SignContext` already models "not initialised" and "consumed", so the wrapper
/// only has to make the borrow re-entrancy-safe: a `RefCell` here matches the
/// `Hash`/`Hmac`/`Dh` handles, and nothing in this crate calls back into V8 while
/// the borrow is held.
struct SignState(SignContext);

impl SignState {
    fn new() -> Self {
        Self(SignContext::Consumed)
    }
}

/// `new Sign()` / `new Verify()`.
///
/// Node's `Sign::New` allocates a `Sign` whose `mdctx_` is null until `init`
/// runs, and `sig.js` calls `init` on the next line. The state is therefore
/// constructed in the consumed state rather than initialising a digest that the
/// caller may never use.
fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let pointer = Box::into_raw(Box::new(RefCell::new(SignState::new())));
    this.set_aligned_pointer_in_internal_field(
        SIGN_STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        this,
        Box::new(move || {
            let pointer = address as *mut RefCell<SignState>;
            // SAFETY: `constructor` allocated this Box for this object alone and
            // this finalizer is the only thing that frees it.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    rv.set(this.into());
}

/// Runs `body` with the handle's state, or reports a receiver that is not one.
///
/// A receiver that is not a `Sign` gets the error `ASSIGN_OR_RETURN_UNWRAP`
/// produces in Node rather than a panic: `Sign.prototype.sign.call({})` is
/// reachable from JavaScript.
fn with_state<R>(this: v8::Local<v8::Object>, body: impl FnOnce(&mut SignState) -> R) -> Option<R> {
    // SAFETY: the pointer was written by `constructor` into this object's field 0
    // and only its finalizer clears it, which cannot run while `this` is a live
    // local.
    let pointer = unsafe { this.get_aligned_pointer_from_internal_field(SIGN_STATE_FIELD, 0) }
        as *mut RefCell<SignState>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above. `try_borrow_mut` rather than `borrow_mut` so a re-entrant
    // call reports an error instead of aborting.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

/// `Sign.prototype.init(algorithm)` / `Verify.prototype.init(algorithm)`.
fn init(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(algorithm) = string_of(scope, args.get(0)) else {
        throw_type_error(scope, "The algorithm argument must be a string");
        return;
    };
    match SignContext::init(&algorithm) {
        Ok(context) => {
            if with_state(args.this(), |state| state.0 = context).is_none() {
                throw(scope, "Invalid Sign receiver");
            }
        }
        Err(error) => throw_sign_error(scope, &error, "Init"),
    }
}

/// `Sign.prototype.update(data, encoding)`.
///
/// `sig.js` has already validated the argument type and encoding, so a bad value
/// here is a direct call rather than the public API.
fn update(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(data) = data_argument(scope, &args, 0, 1) else {
        throw_type_error(
            scope,
            "The data argument must be a string, Buffer, TypedArray or DataView",
        );
        return;
    };
    let result = with_state(args.this(), |state| state.0.update(&data));
    match result {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_sign_error(scope, &error, "Update"),
        None => throw(scope, "Invalid Sign receiver"),
    }
}

/// `Sign.prototype.sign(key, format, type, passphrase, namedCurve, padding,
/// saltLength, dsaEncoding)`.
fn sign(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let mut offset = 0usize;
    let Some(key) = rn_bind_crypto_keys::read_key_from_js(
        scope,
        &args,
        &mut offset,
        rn_bind_crypto_keys::KeyType::Private,
    ) else {
        // `read_key_from_js` has already thrown the parse error.
        return;
    };
    let Some(asymmetric) = key.asymmetric_key().cloned() else {
        throw(scope, "a secret key cannot be used to sign");
        return;
    };
    let Some(options) = padding_options(scope, &args, offset, &asymmetric) else {
        return;
    };
    let Some(encoding) = signature_encoding(scope, &args, offset + 2) else {
        return;
    };

    // The signature context is moved out of the handle, which is what makes a
    // second `sign()` report "Not initialised" — the same transition Node's
    // `std::move(mdctx_)` makes.
    let state = with_state(args.this(), |state| {
        std::mem::replace(&mut state.0, SignContext::Consumed)
    });
    let Some(context) = state else {
        throw(scope, "Invalid Sign receiver");
        return;
    };
    if !context.is_streaming() {
        throw_sign_error(scope, &SignError::NotInitialised, "Sign");
        return;
    }
    let is_rsa = asymmetric
        .algorithm()
        .is_some_and(|algorithm| algorithm.is_rsa());
    // `Sign::SignFinal` rejects a one-shot algorithm before signing anything:
    // Ed25519 and the post-quantum signatures sign a whole message, which a
    // streaming handle cannot supply. `crypto.sign` (the job) is the supported
    // route for them, and real `node` reports exactly this code.
    if asymmetric
        .algorithm()
        .is_some_and(|algorithm| algorithm.is_one_shot())
    {
        throw_coded(
            scope,
            "Unsupported crypto operation",
            "ERR_CRYPTO_UNSUPPORTED_OPERATION",
        );
        return;
    }
    match sign_final(
        context,
        asymmetric.openssl_ref(),
        is_rsa,
        options.padding,
        options.salt_length,
    ) {
        Ok(mut signature) => {
            if encoding == SIGNATURE_ENCODING_P1363 {
                // `ConvertSignatureToP1363` is applied only when the key is
                // DSA-shaped; for RSA the signature is already final.
                let Some(width) = rn_crypto_openssl::bytes_of_rs(asymmetric.openssl_ref()) else {
                    emit_bytes(scope, &mut rv, &signature);
                    return;
                };
                let Some(converted) = signature_to_p1363(&signature, width) else {
                    throw_sign_error(scope, &SignError::MalformedSignature, "Sign");
                    return;
                };
                signature = converted;
            }
            emit_bytes(scope, &mut rv, &signature);
        }
        Err(error) => throw_sign_error(scope, &error, "Sign"),
    }
}

/// `Verify.prototype.verify(key, format, type, passphrase, namedCurve, signature,
/// padding, saltLength, dsaEncoding)`.
fn verify(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let mut offset = 0usize;
    let Some(key) = rn_bind_crypto_keys::read_key_from_js(
        scope,
        &args,
        &mut offset,
        rn_bind_crypto_keys::KeyType::Public,
    ) else {
        return;
    };
    let Some(asymmetric) = key.asymmetric_key().cloned() else {
        throw(scope, "a secret key cannot be used to verify");
        return;
    };
    let Some(signature) = bytes_of(args.get(offset as i32)) else {
        throw_type_error(
            scope,
            "The signature argument must be a Buffer, TypedArray or DataView",
        );
        return;
    };
    let Some(options) = padding_options(scope, &args, offset + 1, &asymmetric) else {
        return;
    };
    let Some(encoding) = signature_encoding(scope, &args, offset + 3) else {
        return;
    };

    let state = with_state(args.this(), |state| {
        std::mem::replace(&mut state.0, SignContext::Consumed)
    });
    let Some(context) = state else {
        throw(scope, "Invalid Verify receiver");
        return;
    };
    if !context.is_streaming() {
        throw_sign_error(scope, &SignError::NotInitialised, "Verify");
        return;
    }
    let is_rsa = asymmetric
        .algorithm()
        .is_some_and(|algorithm| algorithm.is_rsa());
    // Same gate as `sign`: `Verify::VerifyFinal` refuses a one-shot algorithm
    // before verifying, so `createVerify` on an Ed25519 key is unsupported rather
    // than silently wrong.
    if asymmetric
        .algorithm()
        .is_some_and(|algorithm| algorithm.is_one_shot())
    {
        throw_coded(
            scope,
            "Unsupported crypto operation",
            "ERR_CRYPTO_UNSUPPORTED_OPERATION",
        );
        return;
    }

    // `DSASigEnc::P1363` means the caller supplied `r || s`, which OpenSSL cannot
    // verify directly, so it is re-encoded as DER first. A signature that is not
    // exactly two `width`-byte integers is malformed, which Node reports as an
    // operation failure rather than returning false.
    let signature = if encoding == SIGNATURE_ENCODING_P1363 {
        match rn_crypto_openssl::bytes_of_rs(asymmetric.openssl_ref()) {
            Some(width) => match signature_from_p1363(&signature, width) {
                Some(converted) => converted,
                None => {
                    throw_sign_error(scope, &SignError::MalformedSignature, "Verify");
                    return;
                }
            },
            // A non-DSA key ignores the encoding argument, which is what
            // `UseP1363Encoding` does in Node.
            None => signature,
        }
    } else {
        signature
    };

    match verify_final(
        context,
        asymmetric.openssl_ref(),
        &signature,
        is_rsa,
        options.padding,
        options.salt_length,
    ) {
        Ok(result) => rv.set(v8::Boolean::new(scope, result).into()),
        Err(error) => throw_sign_error(scope, &error, "Verify"),
    }
}

/// The padding and PSS salt length for a key, from the two trailing slots.
struct PaddingOptions {
    padding: i32,
    salt_length: Option<i32>,
}

/// Reads `padding` and `saltLength`, defaulting the padding by key variant.
///
/// `GetPaddingFromJS` falls back to `key.getDefaultSignPadding()` when the
/// argument is `undefined`, which is how an `RSA-PSS` key signs with PSS without
/// the caller passing `padding`. `GetSaltLenFromJS` leaves it `None`, which makes
/// OpenSSL use its own default — -2, "as long as the digest allows" — which is
/// what `sig.js` passes for a PSS pad when `saltLength` is absent.
fn padding_options(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: usize,
    key: &rn_crypto_openssl::PKey,
) -> Option<PaddingOptions> {
    let padding = match int32_at(scope, args, index) {
        Some(value) => value,
        None if is_undefined(args, index) => {
            let is_pss = key
                .algorithm()
                .is_some_and(|algorithm| algorithm.name() == "RSA-PSS");
            default_sign_padding(is_pss)
        }
        None => {
            throw_type_error(scope, "The padding argument must be an int32");
            return None;
        }
    };
    let salt_length = if is_undefined(args, index + 1) {
        None
    } else {
        match int32_at(scope, args, index + 1) {
            Some(value) => Some(value),
            None => {
                throw_type_error(scope, "The saltLength argument must be an int32");
                return None;
            }
        }
    };
    Some(PaddingOptions {
        padding,
        salt_length,
    })
}

/// `kSigEncDER` / `kSigEncP1363`, which `sig.js` passes as `dsaEncoding`.
const SIGNATURE_ENCODING_DER: i32 = 1;
/// `kSigEncP1363`.
const SIGNATURE_ENCODING_P1363: i32 = 2;

/// Reads the `dsaEncoding` slot, rejecting a value outside `DSASigEnc`.
///
/// Node's `GetDSASigEncFromJS` reports `ERR_OUT_OF_RANGE` with "invalid signature
/// encoding" for anything outside the enum, and `CheckThrow` is never reached
/// because the check happens before the key touches OpenSSL.
fn signature_encoding(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: usize,
) -> Option<i32> {
    let value = int32_at(scope, args, index).unwrap_or(SIGNATURE_ENCODING_DER);
    if value != SIGNATURE_ENCODING_DER && value != SIGNATURE_ENCODING_P1363 {
        throw_coded(scope, "invalid signature encoding", "ERR_OUT_OF_RANGE");
        return None;
    }
    Some(value)
}

/// Reads an int32 argument, or `None` when it is not one.
fn int32_at(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: usize,
) -> Option<i32> {
    let value = args.get(index as i32);
    if value.is_undefined() || value.is_null() {
        return None;
    }
    v8::Local::<v8::Int32>::try_from(value)
        .ok()
        .map(|value| value.value())
        .or_else(|| value.number_value(scope).map(|value| value as i32))
}

/// Whether an argument is absent.
fn is_undefined(args: &v8::FunctionCallbackArguments<'_>, index: usize) -> bool {
    let value = args.get(index as i32);
    value.is_undefined() || value.is_null()
}

/// Installs `Sign` with `init`, `update` and `sign`.
fn install_sign_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let Some(function) = build_class(scope, "Sign", "sign", sign)? else {
        return Err("cannot allocate the Sign constructor".to_string());
    };
    set(scope, target, "Sign", function)
}

/// Installs `Verify` with `init`, `update` and `verify`.
fn install_verify_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let Some(function) = build_class(scope, "Verify", "verify", verify)? else {
        return Err("cannot allocate the Verify constructor".to_string());
    };
    set(scope, target, "Verify", function)
}

/// Builds a `Sign`-shaped class whose final method is `final_name`.
///
/// `Sign` and `Verify` differ only in that method's name and the direction it
/// runs in, so they are the same builder with a different argument. Keeping them
/// separate matters observably: `test-crypto-sign-verify.js` asserts that
/// `Verify.prototype.sign` is `undefined`, so the prototypes cannot be shared.
fn build_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    final_name: &str,
    final_callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<Option<v8::Local<'s, v8::Value>>, String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELD_COUNT);
    let prototype = template.prototype_template(scope);
    for (method, callback) in [
        ("init", v8::FunctionTemplate::builder(init).build(scope)),
        ("update", v8::FunctionTemplate::builder(update).build(scope)),
    ] {
        let Some(key) = v8::String::new(scope, method) else {
            return Err(format!("cannot allocate the {name}.{method} name"));
        };
        prototype.set(key.into(), callback.into());
    }
    let Some(key) = v8::String::new(scope, final_name) else {
        return Err(format!("cannot allocate the {name}.{final_name} name"));
    };
    prototype.set(
        key.into(),
        v8::FunctionTemplate::builder(final_callback)
            .build(scope)
            .into(),
    );

    let Some(class_name) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} class name"));
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err(format!("cannot allocate the {name} constructor"));
    };
    Ok(Some(function.into()))
}

// ---------------------------------------------------------------------------
// Argument marshalling
// ---------------------------------------------------------------------------

/// Reads a JavaScript string as UTF-8, or `None` for a non-string.
fn string_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<String> {
    let text = v8::Local::<v8::String>::try_from(value).ok()?;
    Some(text.to_rust_string_lossy(scope))
}

/// Reads `data` as bytes, decoding a string according to the encoding argument.
///
/// This mirrors `Decode<Sign>` in `crypto_sig.cc`: a string is hex/base64/... as
/// the encoding slot says, and a view is its bytes. `update` is the only method
/// that takes a string here.
fn data_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
    encoding_index: i32,
) -> Option<Vec<u8>> {
    let value = args.get(index);
    if let Some(text) = string_of(scope, value) {
        let encoding = string_of(scope, args.get(encoding_index));
        return Some(decode_text(&text, encoding.as_deref()));
    }
    bytes_of(value)
}

/// Decodes a string in an encoding `sig.js` has already validated.
fn decode_text(text: &str, encoding: Option<&str>) -> Vec<u8> {
    let Some(encoding) = encoding else {
        return text.as_bytes().to_vec();
    };
    match encoding {
        "utf8" | "utf-8" => text.as_bytes().to_vec(),
        "latin1" | "binary" => text
            .chars()
            .map(|character| character as u32 as u8)
            .collect(),
        "base64" | "base64url" => decode_base64(text),
        "hex" => decode_hex(text),
        "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => text
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect(),
        // `sig.js` validates before calling, so an unknown name here is a direct
        // call and treating it as UTF-8 is the least surprising answer.
        _ => text.as_bytes().to_vec(),
    }
}

/// Decodes hex, ignoring a trailing partial byte the way `Buffer.from(_, 'hex')`
/// does.
fn decode_hex(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index + 1 < bytes.len() {
        let Some(high) = (bytes[index] as char).to_digit(16) else {
            break;
        };
        let Some(low) = (bytes[index + 1] as char).to_digit(16) else {
            break;
        };
        output.push(((high << 4) | low) as u8);
        index += 2;
    }
    output
}

/// Decodes base64, stopping at the first invalid character.
fn decode_base64(text: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(text.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for character in text.bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => break,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    output
}

/// Copies the bytes behind a `Buffer`, typed array, `DataView` or `ArrayBuffer`.
fn bytes_of(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let length = view.byte_length();
        let mut bytes = vec![0u8; length];
        let copied = view.copy_contents(&mut bytes);
        bytes.truncate(copied);
        return Some(bytes);
    }
    if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        return Some(copy_backing_store(
            &buffer.get_backing_store(),
            buffer.byte_length(),
        ));
    }
    // A `SharedArrayBuffer` is a distinct V8 type with its own backing store, and
    // `crypto.verify` accepts one for both the data and the signature
    // (`test-crypto-sign-verify.js` asserts it). Treating it as a plain object
    // rejects a perfectly valid input.
    if let Ok(buffer) = v8::Local::<v8::SharedArrayBuffer>::try_from(value) {
        return Some(copy_backing_store(
            &buffer.get_backing_store(),
            buffer.byte_length(),
        ));
    }
    None
}

/// Emits bytes as a `Buffer`, which is what `sig.js` calls `.toString()` on.
fn emit_bytes(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, bytes: &[u8]) {
    match buffer_from(scope, bytes) {
        Ok(value) => rv.set(value),
        Err(reason) => throw(scope, &format!("cannot allocate the signature: {reason}")),
    }
}

/// `Buffer.from(arrayBuffer, 0, length)` over a fresh backing store.
///
/// The global `Buffer` is looked up on every call rather than cached: a
/// `v8::Global` would pin the constructor for the isolate's lifetime and outlive
/// a context teardown.
fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Result<v8::Local<'s, v8::Value>, &'static str> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice())
            .make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let context = scope.get_current_context();
    let global = context.global(scope);
    let Some(key) = v8::String::new(scope, "Buffer") else {
        return Err("cannot allocate 'Buffer'");
    };
    let Some(value) = global.get(scope, key.into()) else {
        return Err("global Buffer is missing");
    };
    let Ok(buffer) = v8::Local::<v8::Object>::try_from(value) else {
        return Err("global Buffer is not an object");
    };
    let Some(from_key) = v8::String::new(scope, "from") else {
        return Err("cannot allocate 'from'");
    };
    let Some(from) = buffer.get(scope, from_key.into()) else {
        return Err("Buffer.from lookup failed");
    };
    let Ok(from) = v8::Local::<v8::Function>::try_from(from) else {
        return Err("Buffer.from is not a function");
    };
    let start = v8::Integer::new(scope, 0);
    let length = v8::Integer::new(scope, bytes.len() as i32);
    let called = from
        .call(
            scope,
            buffer.into(),
            &[array_buffer.into(), start.into(), length.into()],
        )
        .ok_or("Buffer.from threw")?;
    if !called.is_object() {
        return Err("Buffer.from returned a non-object");
    }
    Ok(called)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Throws the JavaScript error a [`SignError`] corresponds to.
///
/// The shapes are `CheckThrow`'s. The three that matter to the tests are
/// `ERR_CRYPTO_INVALID_DIGEST` (an unknown algorithm), `ERR_CRYPTO_INVALID_STATE`
/// with "Not initialised" (a method called out of order) and
/// `ERR_CRYPTO_OPERATION_FAILED` with a message (a signing failure with nothing
/// on the OpenSSL queue).
fn throw_sign_error(scope: &mut v8::PinScope<'_, '_>, error: &SignError, operation: &str) {
    match error {
        SignError::UnknownDigest => {
            throw_coded(scope, "Invalid digest", "ERR_CRYPTO_INVALID_DIGEST")
        }
        SignError::NotInitialised => {
            throw_coded(scope, "Not initialised", "ERR_CRYPTO_INVALID_STATE")
        }
        SignError::MalformedSignature => {
            throw_coded(scope, "Malformed signature", "ERR_CRYPTO_OPERATION_FAILED")
        }
        // The safe wrapper drained the OpenSSL queue while reporting the
        // padding failure, so the detail arrives with the error rather than on
        // the queue. Without this the caller would see a generic signing failure
        // where real `node` reports "illegal or unsupported padding mode".
        SignError::Padding {
            packed,
            library,
            reason,
        } => throw_openssl(scope, *packed, library, reason),
        SignError::OpenSsl(stack) => {
            if let Some((code, library, reason)) = stack.first() {
                throw_openssl(scope, *code, library, reason);
            } else {
                // No queued error. Node falls back to a fixed message per
                // operation, which is what makes `sign()` on a public key report
                // "PEM_read_bio_PrivateKey failed" rather than an empty error.
                let message = match operation {
                    "Update" => "EVP_SignUpdate failed",
                    "Verify" => "EVP_PKEY_verify failed",
                    _ => "EVP_SignFinal failed",
                };
                throw_coded(scope, message, "ERR_CRYPTO_OPERATION_FAILED");
            }
        }
    }
}

/// Throws an `Error` carrying a `.code`, which is the shape Node's tests read.
fn throw_coded(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(code_key) = v8::String::new(scope, "code") {
        if let Some(code_value) = v8::String::new(scope, code) {
            object.set(scope, code_key.into(), code_value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Throws the OpenSSL-shaped error `ThrowCryptoError` builds.
///
/// The shape is `code`/`library`/`reason`/`message`. The `code` derivation is
/// `rn-crypto-openssl`'s, not this crate's: it needs Node's numeric library table
/// (`PROVIDER` is absent from it, so a provider error's code carries no library
/// segment), and duplicating that here would drift.
///
/// `library` is the display form `ERR_lib_error_string` returns — "Provider
/// routines", "rsa routines" — and the message uses it verbatim.
fn throw_openssl(scope: &mut v8::PinScope<'_, '_>, packed: u64, library: &str, reason: &str) {
    let message = format!("error:{packed:08X}:{library}::{reason}");
    let Some(text) = v8::String::new(scope, &message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    let code = rn_crypto_openssl::ossl_code_for(packed, reason);
    for (name, value) in [
        ("code", code),
        ("library", library.to_string()),
        ("reason", reason.to_string()),
    ] {
        let (Some(key), Some(text)) =
            (v8::String::new(scope, name), v8::String::new(scope, &value))
        else {
            continue;
        };
        if object.set(scope, key.into(), text.into()).is_none() {
            // A setter on the prototype chain threw — a test can install one for
            // `library`. That exception is the one the caller must see, so this
            // returns without replacing it.
            return;
        }
    }
    scope.throw_exception(exception);
}

fn throw(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

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

/// Copies `length` bytes out of a backing store.
///
/// Shared between the `ArrayBuffer` and `SharedArrayBuffer` paths, which have
/// identical layouts but distinct V8 types.
pub(crate) fn copy_backing_store(
    store: &v8::SharedRef<v8::BackingStore>,
    length: usize,
) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    if length == 0 {
        return bytes;
    }
    let Some(data) = store.data() else {
        return bytes;
    };
    // SAFETY: `data` points at `length` bytes owned by `store`, which the caller
    // holds for the duration of the copy.
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), length);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_installed_members_are_the_translation_units_contract() {
        assert_eq!(MEMBERS, &["Sign", "Verify", "SignJob", "RSACipherJob"]);
    }

    #[test]
    fn hex_decoding_matches_buffer_from() {
        assert_eq!(decode_hex("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode_hex("DEADBEEF"), vec![0xde, 0xad, 0xbe, 0xef]);
        // A trailing half-byte is dropped, as `Buffer.from(s, 'hex')` does.
        assert_eq!(decode_hex("deadbee"), vec![0xde, 0xad, 0xbe]);
        assert_eq!(decode_hex(""), Vec::<u8>::new());
    }

    #[test]
    fn base64_decoding_matches_buffer_from() {
        assert_eq!(decode_base64("aGVsbG8="), b"hello".to_vec());
        assert_eq!(decode_base64("aGVsbG8h"), b"hello!".to_vec());
        // The URL-safe alphabet decodes through the same table.
        assert_eq!(decode_base64("-_8="), vec![0xfb, 0xff]);
    }

    #[test]
    fn utf8_and_latin1_differ_as_they_should() {
        // "é" is two bytes in UTF-8 and one in latin1: the encoding argument is
        // what decides, and getting it wrong silently changes the signed bytes.
        assert_eq!(decode_text("é", Some("utf8")), vec![0xc3, 0xa9]);
        assert_eq!(decode_text("é", Some("latin1")), vec![0xe9]);
    }

    #[test]
    fn no_encoding_means_utf8() {
        assert_eq!(decode_text("abc", None), b"abc".to_vec());
        assert_eq!(decode_text("abc", Some("utf-8")), b"abc".to_vec());
    }

    #[test]
    fn the_signature_encoding_values_match_the_binding_constants() {
        // `kSigEncDER`/`kSigEncP1363` are installed by `rn-bind-crypto`; a drift
        // would make `dsaEncoding: 'ieee-p1363'` silently request DER.
        assert_eq!(SIGNATURE_ENCODING_DER, 1);
        assert_eq!(SIGNATURE_ENCODING_P1363, 2);
    }
}
