//! The `CipherBase` V8 class: constructor, methods, and argument marshalling.
//!
//! `src/crypto/crypto_cipher.cc`'s `CipherBase::Initialize` is the spec, and the
//! method set is exactly what it installs:
//!
//! | prototype method | `CipherBase::` |
//! | --- | --- |
//! | `update(data, inputEncoding)` | `Update` |
//! | `final()` | `Final` |
//! | `setAutoPadding(bool)` | `SetAutoPadding` |
//! | `getAuthTag()` | `GetAuthTag` |
//! | `setAuthTag(tag)` | `SetAuthTag` |
//! | `setAAD(aad, plaintextLength)` | `SetAAD` |
//!
//! There is deliberately **no** `initiv` method, which is a real difference from
//! the pinned source: `lib/internal/crypto/cipher.js` at `f344e7f552e` calls
//! `new CipherBase(isEncrypt, cipher, credential, iv, authTagLength)` and does all
//! the initialisation in the constructor. An `initiv` would be dead code that a
//! future reader might trust.
//!
//! # State ownership
//!
//! The state lives in a heap allocation behind an internal field with a
//! guaranteed finalizer, exactly as `rn-bind-crypto-dh` and `rn-bind-crypto` do
//! for their handles. A `CipherBase` that is garbage collected without `final()`
//! still has a live `EVP_CIPHER_CTX`, and the finalizer is the only place that
//! can free it.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::evp::{Cipher, CipherCtx};
use crate::state::{CipherError, CipherState, ErrorKind, Kind};

/// The internal field holding the `*mut RefCell<CipherState>`.
const STATE_FIELD: i32 = 0;

/// `CipherBase::kInternalFieldCount` is 1 in Node and the single field is the
/// `BaseObject` pointer, so one is the right count here too.
const INTERNAL_FIELD_COUNT: usize = 1;

/// `CipherBase::kNoAuthTagLength`, which the JavaScript sends as `-1`.
const NO_AUTH_TAG_LENGTH: i32 = -1;

/// Builds the `CipherBase` constructor with its prototype methods.
pub fn build_cipher_base_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELD_COUNT);

    let prototype = template.prototype_template(scope);
    for (name, callback) in [
        ("update", v8::FunctionTemplate::builder(update)),
        ("final", v8::FunctionTemplate::builder(finalize)),
        (
            "setAutoPadding",
            v8::FunctionTemplate::builder(set_auto_padding),
        ),
        ("getAuthTag", v8::FunctionTemplate::builder(get_auth_tag)),
        ("setAuthTag", v8::FunctionTemplate::builder(set_auth_tag)),
        ("setAAD", v8::FunctionTemplate::builder(set_aad)),
    ] {
        let key = v8::String::new(scope, name)
            .ok_or_else(|| format!("cannot allocate the CipherBase method {name}"))?;
        prototype.set(key.into(), callback.build(scope).into());
    }

    let class_name =
        v8::String::new(scope, "CipherBase").ok_or("cannot allocate the CipherBase name")?;
    template.set_class_name(class_name);
    template
        .get_function(scope)
        .ok_or_else(|| "cannot allocate the CipherBase constructor".to_string())
}

/// `new CipherBase(isEncrypt, cipher, key, iv, authTagLength[, ctsMode, xtsStandard])`.
///
/// Every argument is type-checked rather than coerced. A binding that coerces
/// hides the caller's bug: `lib/internal/crypto/cipher.js` passes exactly these
/// seven, and a wrong shape means the JavaScript is not what this was written
/// against.
fn constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();

    // `args[0]->IsTrue()`: anything that is not `true` is a decipher.
    let kind = if args.get(0).is_true() {
        Kind::Cipher
    } else {
        Kind::Decipher
    };

    let Some(cipher_name) = string_argument(scope, args.get(1)) else {
        throw(
            scope,
            "The cipher argument must be a string",
            ErrorKind::TypeError,
        );
        return;
    };
    let Some(key) = bytes_argument(args.get(2)) else {
        throw(
            scope,
            "The key argument must be a Buffer, TypedArray or ArrayBuffer",
            ErrorKind::TypeError,
        );
        return;
    };
    // `args[3]` is `null` for a cipher with no IV, which is legal; an absent
    // argument is not, because the JavaScript always passes one.
    let iv = if args.get(3).is_null() {
        Vec::new()
    } else {
        match bytes_argument(args.get(3)) {
            Some(iv) => iv,
            None => {
                throw(
                    scope,
                    "The iv argument must be a Buffer, TypedArray, ArrayBuffer or null",
                    ErrorKind::TypeError,
                );
                return;
            }
        }
    };

    // `args[4]` is `authTagLength` as a uint32, or `-1` for "not specified".
    let auth_tag_length = if let Ok(value) = v8::Local::<v8::Uint32>::try_from(args.get(4)) {
        Some(value.value())
    } else if let Ok(value) = v8::Local::<v8::Int32>::try_from(args.get(4)) {
        if value.value() == NO_AUTH_TAG_LENGTH {
            None
        } else {
            throw(
                scope,
                "authTagLength must be a non-negative integer or -1",
                ErrorKind::TypeError,
            );
            return;
        }
    } else {
        throw(
            scope,
            "authTagLength must be a non-negative integer or -1",
            ErrorKind::TypeError,
        );
        return;
    };

    let cts_mode = optional_string(scope, args.get(5));
    let xts_standard = optional_string(scope, args.get(6));

    // `CipherBase::InitIv`. The `cipher.isChaCha20Poly1305()` and SIV checks are
    // here rather than in `CipherCtx::new` because they are about the *argument*
    // rather than about the context.
    let Some(cipher) = Cipher::from_name(&cipher_name) else {
        throw_cipher_error(scope, &CipherError::UnknownCipher);
        return;
    };

    let expected_iv = cipher.iv_length();
    let has_iv = !iv.is_empty();

    if !has_iv && expected_iv != 0 {
        // `createCipheriv('aes-128-cbc', key, null)` and
        // `createCipheriv('aes-128-ecb', key, Buffer.alloc(0))`: the second is
        // legal because ECB's expected IV length is 0.
        throw_cipher_error(scope, &CipherError::InvalidIv);
        return;
    }
    if !cipher.is_authenticated() && has_iv && iv.len() != expected_iv {
        // Every non-AEAD cipher requires exactly its IV length. The loop in
        // `test-crypto-cipheriv-decipheriv` tries all 256 lengths against CBC and
        // ECB, so this is load-bearing.
        throw_cipher_error(scope, &CipherError::InvalidIv);
        return;
    }
    if cipher.is_chacha20_poly1305() && iv.len() > 12 {
        // OpenSSL does not reject this itself under some conditions; the
        // security advisory the reference cites is why the check exists.
        throw_cipher_error(scope, &CipherError::InvalidIv);
        return;
    }
    if cipher.is_siv() && has_iv {
        throw_cipher_error(scope, &CipherError::InvalidIv);
        return;
    }
    if cipher.is_gcm_siv() && (!has_iv || iv.len() != expected_iv) {
        throw_cipher_error(scope, &CipherError::InvalidIv);
        return;
    }

    match CipherCtx::new(crate::evp::Init {
        cipher,
        requested_name: &cipher_name,
        encrypting: kind.is_encrypting(),
        key: &key,
        iv: &iv,
        auth_tag_len: auth_tag_length,
        cts_mode: cts_mode.as_deref(),
        xts_standard: xts_standard.as_deref(),
    }) {
        Ok(context) => install(scope, this, CipherState::new(kind, context)),
        Err(error) => throw_cipher_error(scope, &error),
    }
    rv.set(this.into());
}

/// `CipherBase.prototype.update(data, inputEncoding)`.
fn update(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // `Decode<CipherBase>`: a string is decoded with the encoding in argument 1,
    // and anything else is read as a view. `LazyTransform` always passes a
    // Buffer, so the string path only matters for a direct handle call.
    let Some(data) = data_argument(scope, &args, 0, 1) else {
        return;
    };

    let updated = with_state(this, |state| state.context.update(&data));
    match updated {
        Some(Ok(bytes)) => emit_bytes(scope, &mut rv, &bytes),
        Some(Err(error)) => throw_cipher_error(scope, &error),
        None => throw(scope, "Cipher handle is not initialised", ErrorKind::Error),
    }
}

/// `CipherBase.prototype.final()`.
fn finalize(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // `Final` checks the live context first and throws `ERR_CRYPTO_INVALID_STATE`
    // with no message, which is what a second `final()` produces.
    let live = with_state(this, |state| state.context.is_live());
    match live {
        Some(true) => {}
        Some(false) => {
            throw_cipher_error(scope, &CipherError::InvalidState);
            return;
        }
        None => {
            throw(scope, "Cipher handle is not initialised", ErrorKind::Error);
            return;
        }
    }

    // Whether this is an AEAD has to be read *before* finalising, because
    // `final` releases the context. `ThrowCryptoError`'s default message differs
    // between an AEAD and a plain cipher.
    let authenticated = with_state(this, |state| state.context.cipher().is_authenticated());
    // The default message `CipherBase::Final` passes to `ThrowCryptoError`. It is
    // used only when OpenSSL queued nothing, which is the tag-mismatch case.
    let default_message = if authenticated == Some(true) {
        "Unsupported state or unable to authenticate data"
    } else {
        "Unsupported state"
    }
    .to_string();
    let result = with_state(this, |state| state.context.finalize());

    match result {
        Some(Ok(bytes)) => emit_bytes(scope, &mut rv, &bytes),
        Some(Err(error)) => {
            // `ThrowCryptoError` prefers an OpenSSL error when one is queued and
            // falls back to the default message otherwise. In the reference that
            // default is chosen from `is_auth_mode`, so it is computed here too.
            if let CipherError::OpenSsl(packed) = error {
                throw_decorated(scope, &default_message, packed);
                return;
            }
            let message = match (&error, authenticated) {
                (CipherError::AuthenticationFailed, Some(true)) => {
                    "Unsupported state or unable to authenticate data".to_string()
                }
                (CipherError::AuthenticationFailed, _) => "Unsupported state".to_string(),
                (other, _) => other.message(),
            };
            throw_bare(scope, &message);
        }
        None => throw(scope, "Cipher handle is not initialised", ErrorKind::Error),
    }
}

/// `CipherBase.prototype.setAutoPadding(autoPadding)`.
fn set_auto_padding(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // `args.Length() < 1 || args[0]->IsTrue()`: an omitted argument means `true`.
    let padding = args.length() < 1 || args.get(0).is_true();
    let applied = with_state(this, |state| state.context.set_auto_padding(padding));
    match applied {
        Some(applied) => rv.set(v8::Boolean::new(scope, applied).into()),
        None => rv.set(v8::Boolean::new(scope, false).into()),
    }
}

/// `CipherBase.prototype.getAuthTag()`.
fn get_auth_tag(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // Only callable after `final()` and only when encrypting; otherwise the
    // return value stays `undefined`, which `cipher.js` turns into
    // `ERR_CRYPTO_INVALID_STATE('getAuthTag')`.
    let tag = with_state(this, |state| {
        let context = &state.context;
        if context.is_live()
            || !context.is_encrypting()
            || context.auth_tag_state() != crate::evp::AuthTagState::Computed
        {
            return None;
        }
        context.auth_tag().map(<[u8]>::to_vec)
    })
    .flatten();
    if let Some(tag) = tag {
        emit_bytes(scope, &mut rv, &tag);
    }
}

/// `CipherBase.prototype.setAuthTag(tag, encoding)`.
fn set_auth_tag(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(mut tag) = data_argument(scope, &args, 0, 1) else {
        return;
    };
    let applied = with_state(this, |state| state.context.set_auth_tag(&mut tag));
    match applied {
        Some(Ok(applied)) => rv.set(v8::Boolean::new(scope, applied).into()),
        Some(Err(error)) => throw_cipher_error(scope, &error),
        None => rv.set(v8::Boolean::new(scope, false).into()),
    }
}

/// `CipherBase.prototype.setAAD(aad, plaintextLength)`.
fn set_aad(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some(data) = bytes_argument(args.get(0)) else {
        throw(
            scope,
            "The aadbuf argument must be a Buffer, TypedArray or ArrayBuffer",
            ErrorKind::TypeError,
        );
        return;
    };
    // `CHECK(args[1]->IsInt32())`: `cipher.js` passes `getUIntOption(options,
    // 'plaintextLength')`, which is `-1` when absent.
    let plaintext_length = match v8::Local::<v8::Int32>::try_from(args.get(1)) {
        Ok(value) => value.value(),
        Err(_) => {
            throw(
                scope,
                "plaintextLength must be an integer",
                ErrorKind::TypeError,
            );
            return;
        }
    };
    let applied = with_state(this, |state| state.context.set_aad(&data, plaintext_length));
    match applied {
        Some(Ok(applied)) => rv.set(v8::Boolean::new(scope, applied).into()),
        Some(Err(error)) => throw_cipher_error(scope, &error),
        None => rv.set(v8::Boolean::new(scope, false).into()),
    }
}

// ---------------------------------------------------------------------------
// State plumbing
// ---------------------------------------------------------------------------

/// Allocates the state, stores it in the internal field, and installs a
/// finalizer that frees it.
fn install(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    state: CipherState,
) {
    let pointer = Box::into_raw(Box::new(RefCell::new(state)));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut RefCell<CipherState>;
            // SAFETY: allocated by `install` and freed exactly once, here.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
}

/// Runs `body` with the handle's state, or `None` when there is none.
///
/// `try_borrow_mut` rather than `borrow_mut`: a re-entrant call from inside
/// `update` would otherwise abort the process, and returning `None` produces the
/// "not initialised" error instead.
fn with_state<R>(
    object: v8::Local<'_, v8::Object>,
    body: impl FnOnce(&mut CipherState) -> R,
) -> Option<R> {
    // SAFETY: the pointer comes from `install` and nothing else frees it while
    // `object` is live.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut RefCell<CipherState>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above; the allocation is live and owned by `object`.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

/// Reads a string argument, or `None` for anything else.
fn string_argument(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Option<String> {
    let text = v8::Local::<v8::String>::try_from(value).ok()?;
    Some(text.to_rust_string_lossy(scope))
}

/// Reads a string argument that may be `undefined` or `null`.
fn optional_string(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Option<String> {
    if value.is_undefined() || value.is_null() {
        return None;
    }
    string_argument(scope, value)
}

/// The bytes of a `Buffer`/`TypedArray`/`ArrayBuffer`, copied out.
///
/// A copy rather than a borrow because `EVP_CipherUpdate` is called while the
/// state is borrowed, and holding a slice into a V8 backing store across that
/// would let a GC-triggered callback observe a dangling borrow.
pub fn bytes_argument_public(value: v8::Local<'_, v8::Value>) -> Option<Vec<u8>> {
    bytes_argument(value)
}

/// The shared implementation behind [`bytes_argument_public`].
fn bytes_argument(value: v8::Local<'_, v8::Value>) -> Option<Vec<u8>> {
    let (pointer, length) = view_pointer(value)?;
    if length == 0 {
        return Some(Vec::new());
    }
    if pointer.is_null() {
        return None;
    }
    // SAFETY: `view_pointer` proved `0..length` lies inside a live backing store
    // and the copy completes before this function returns to JavaScript.
    Some(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
}

/// `Decode<CipherBase>`: a string is decoded with `encoding`, anything else is
/// read as bytes.
fn data_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
    encoding_index: i32,
) -> Option<Vec<u8>> {
    let value = args.get(index);
    if value.is_string() {
        let text = v8::Local::<v8::String>::try_from(value).ok()?;
        let text = text.to_rust_string_lossy(scope);
        let encoding = string_argument(scope, args.get(encoding_index));
        return Some(match encoding.as_deref() {
            None | Some("utf8") | Some("utf-8") | Some("buffer") => text.into_bytes(),
            Some(name) => match decode_string(&text, name) {
                Some(bytes) => bytes,
                None => {
                    throw(
                        scope,
                        &format!("Unknown encoding: {name}"),
                        ErrorKind::TypeError,
                    );
                    return None;
                }
            },
        });
    }
    let bytes = bytes_argument(value);
    if bytes.is_none() {
        // `cipher.js` validates the type before reaching here, so this only
        // fires for a direct handle call.
        throw(
            scope,
            "The data argument must be a string, Buffer, TypedArray or DataView",
            ErrorKind::TypeError,
        );
    }
    bytes
}

/// Decodes a JavaScript string in one of Node's `Buffer` encodings.
///
/// `ParseEncoding` in `node_crypto.cc` accepts the whole set `Buffer` does and
/// defaults to `UTF8` when the encoding argument is missing.
/// `update(plain, "ascii")` is what `test-crypto-padding` calls, so the set has
/// to be complete rather than convenient.
///
/// # Why this is not `rn-bind-crypto::encoding::decode_string`
///
/// That function exists and is public, and this is a second implementation of
/// the same table, which is normally the thing to avoid. It cannot be shared:
/// `rn-bind-crypto` depends on this crate for [`install_classes`], so a
/// dependency back is a cargo cycle. Moving the table into `rn-core` would fix
/// it properly and is the right change when a third caller appears; until then a
/// local copy with a test pinning every name is cheaper than a workspace-wide
/// move, and the test is what keeps the two from drifting silently.
///
/// [`install_classes`]: crate::install_classes
fn decode_string(text: &str, encoding: &str) -> Option<Vec<u8>> {
    match encoding {
        "utf8" | "utf-8" => Some(text.as_bytes().to_vec()),
        "hex" => decode_hex(text),
        "base64" => decode_base64(text),
        "base64url" => decode_base64url(text),
        // `ascii` and `latin1` are the same write: the low byte of each UTF-16
        // code unit, which is what `StringBytes::Write` does for both.
        "latin1" | "binary" | "ascii" => Some(text.chars().map(|c| c as u32 as u8).collect()),
        "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => {
            let units: Vec<u16> = text.encode_utf16().collect();
            let mut out = Vec::with_capacity(units.len() * 2);
            for unit in units {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            Some(out)
        }
        _ => None,
    }
}

/// `Buffer.from(text, 'hex')`: an odd number of digits truncates, as Node does.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let high = (pair[0] as char).to_digit(16)?;
        // An odd trailing nibble is dropped rather than zero-padded, matching
        // `hex_decode` in `rn-bind-crypto`.
        let Some(low) = pair.get(1) else {
            break;
        };
        let low = (*low as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

/// `Buffer.from(text, 'base64')`.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    decode_base64_alphabet(text, b'+', b'/')
}

/// `Buffer.from(text, 'base64url')`: the URL-safe alphabet.
fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    decode_base64_alphabet(text, b'-', b'_')
}

fn decode_base64_alphabet(text: &str, plus: u8, slash: u8) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            _ if byte == plus => 62,
            _ if byte == slash => 63,
            // Padding ends the data; whitespace is skipped. Anything else is not
            // base64, and Node ignores invalid characters too, which is why this
            // returns `None` only for a caller that passed a bad encoding name.
            b'=' => break,
            _ if byte.is_ascii_whitespace() => continue,
            _ => continue,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Some(out)
}

/// The data pointer and byte length of a view or `ArrayBuffer`.
fn view_pointer(value: v8::Local<'_, v8::Value>) -> Option<(*const u8, usize)> {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        return Some((view.data().cast::<u8>().cast_const(), view.byte_length()));
    }
    if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        let length = buffer.byte_length();
        return match buffer.data() {
            Some(data) => Some((data.as_ptr().cast::<u8>().cast_const(), length)),
            None if length == 0 => Some((std::ptr::null(), 0)),
            None => None,
        };
    }
    None
}

// ---------------------------------------------------------------------------
// Output and errors
// ---------------------------------------------------------------------------

/// Emits bytes as a `Buffer`.
///
/// A real `Buffer`, not a `Uint8Array`: `test-crypto-cipheriv-decipheriv` passes
/// `cipher.update(...)` straight to `Buffer.concat` and
/// `test-crypto-aes-wrap` deep-compares against a `Buffer`, and both would fail
/// on the constructor name.
fn emit_bytes(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, bytes: &[u8]) {
    match buffer_from(scope, bytes) {
        Ok(value) => rv.set(value),
        Err(reason) => throw(
            scope,
            &format!("cannot allocate the cipher result: {reason}"),
            ErrorKind::Error,
        ),
    }
}

/// `Buffer.from(arrayBuffer, 0, length)`, for the job's result.
pub fn buffer_from_public<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    buffer_from(scope, bytes).ok()
}

/// `Buffer.from(arrayBuffer, 0, length)` over a fresh backing store.
///
/// `Buffer.from` rather than `new Buffer(...)`: the latter is deprecated and the
/// warning is visible to every test that captures stderr.
fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Result<v8::Local<'s, v8::Value>, &'static str> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice())
            .make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let global = scope.get_current_context().global(scope);
    let buffer_key = v8::String::new(scope, "Buffer").ok_or("cannot allocate 'Buffer'")?;
    let buffer = global
        .get(scope, buffer_key.into())
        .ok_or("global Buffer lookup failed")?;
    let buffer =
        v8::Local::<v8::Object>::try_from(buffer).map_err(|_| "global Buffer is not an object")?;
    let from_key = v8::String::new(scope, "from").ok_or("cannot allocate 'from'")?;
    let from = buffer
        .get(scope, from_key.into())
        .ok_or("Buffer.from lookup failed")?;
    let from =
        v8::Local::<v8::Function>::try_from(from).map_err(|_| "Buffer.from is not a function")?;
    let start = v8::Integer::new(scope, 0);
    let length = v8::Integer::new(scope, bytes.len() as i32);
    let receiver = buffer.into();
    let called = from
        .call(
            scope,
            receiver,
            &[array_buffer.into(), start.into(), length.into()],
        )
        .ok_or("Buffer.from threw")?;
    if !called.is_object() {
        return Err("Buffer.from returned a non-object");
    }
    Ok(called)
}

/// Throws the JavaScript error a [`CipherError`] corresponds to.
fn throw_cipher_error(scope: &mut v8::PinScope<'_, '_>, error: &CipherError) {
    let message = error.message();
    let Some(text) = v8::String::new(scope, &message) else {
        return;
    };
    let exception = match error.error_kind() {
        ErrorKind::Error => v8::Exception::error(scope, text),
        ErrorKind::TypeError => v8::Exception::type_error(scope, text),
        ErrorKind::RangeError => v8::Exception::range_error(scope, text),
    };
    if let (Some(code), Ok(object)) = (error.code(), v8::Local::<v8::Object>::try_from(exception)) {
        set_string_property(scope, object, "code", code);
        if let Some((library, reason)) = error.decorate() {
            set_string_property(scope, object, "library", &library);
            set_string_property(scope, object, "reason", &reason);
        }
    }
    scope.throw_exception(exception);
}

/// Throws a plain `Error` with no `code`, which is what `ThrowCryptoError`
/// produces when no OpenSSL error was queued.
fn throw_bare(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

/// Throws an `Error` carrying `code`, `library` and `reason` from a packed
/// OpenSSL error.
///
/// This is `ThrowCryptoError` with a captured error: the message is the
/// `error:<code>:...` text when OpenSSL produced one, and the fixed default
/// otherwise. `CipherBase::Final` uses it so a CBC decipher reports
/// `ERR_OSSL_BAD_DECRYPT` while a GCM tag mismatch — which queues nothing —
/// keeps the fixed message.
fn throw_decorated(scope: &mut v8::PinScope<'_, '_>, fallback: &str, packed: u64) {
    let described = crate::evp::describe_error(packed);
    let text = if described.message.is_empty() {
        fallback.to_string()
    } else {
        described.message.clone()
    };
    let Some(text) = v8::String::new(scope, &text) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        set_string_property(scope, object, "code", &described.code);
        for (name, value) in [
            ("library", described.library.as_str()),
            ("reason", described.reason.as_str()),
        ] {
            if !value.is_empty() {
                set_string_property(scope, object, name, value);
            }
        }
    }
    scope.throw_exception(exception);
}

fn throw(scope: &mut v8::PinScope<'_, '_>, message: &str, kind: ErrorKind) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = match kind {
        ErrorKind::Error => v8::Exception::error(scope, text),
        ErrorKind::TypeError => v8::Exception::type_error(scope, text),
        ErrorKind::RangeError => v8::Exception::range_error(scope, text),
    };
    scope.throw_exception(exception);
}

fn set_string_property(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    name: &str,
    value: &str,
) {
    let (Some(key), Some(text)) = (v8::String::new(scope, name), v8::String::new(scope, value))
    else {
        return;
    };
    object.set(scope, key.into(), text.into());
}
