//! Argument marshalling and the twelve installed members.
//!
//! [`install`] is this crate's only entry point: the foundation crate `rn-bun`
//! creates the `Bun` object and calls each group's `install` with it as `target`.
//! Nothing here creates `Bun`, and nothing here touches `rn-realm`.
//!
//! # The shape of each class
//!
//! All eight per-algorithm classes share one template shape, built once per
//! isolate and then given a class name and its own callbacks:
//!
//! ```text
//! ctor length=0, name="<CLASS>"
//! proto:   byteLength=getter(len 0) | digest=fn(len 0) | update=fn(len 1) | constructor
//! statics: byteLength=getter(len 0) | hash=fn(len 2)
//! ```
//!
//! Two traps, both measured:
//!
//! * `byteLength` is a **getter**. `Bun.SHA256.byteLength()` throws, and calling
//!   one class's getter on another class's instance throws a message naming the
//!   *installed* class — so the eight accessors genuinely differ.
//! * `update` has `length` **1** even though it accepts a second encoding
//!   argument that is then ignored.
//!
//! # Instances carry no own properties
//!
//! `Object.getOwnPropertyNames(new Bun.SHA256())` is `[]` on Bun, so state cannot
//! live in a named or ordinary symbol property. It lives behind an internal
//! field, which V8 keeps out of `getOwnPropertyNames`, `getOwnPropertySymbols`,
//! `JSON.stringify` and `for…in` all at once.

use rn_v8_sys::v8;

use crate::digest::{self, Digest, DigestError};
use crate::{hashes, wyhash, CRYPTO_HASHER_ALGORITHMS};

/// The one internal field on every hasher instance, holding a
/// `*mut std::cell::RefCell<State>`.
const STATE_FIELD: i32 = 0;

/// What a hasher instance keeps.
///
/// `CryptoHasher` can be an HMAC, whose data has to be buffered because OpenSSL's
/// `Signer` is not copyable the way `EVP_MD_CTX` is, so there are two shapes
/// rather than one.
enum State {
    /// A plain digest: the per-class hashers and an unkeyed `CryptoHasher`.
    Plain { digest: Digest, digested: bool },
    /// A keyed `CryptoHasher`. `data` accumulates the updates so `copy()` and a
    /// second `digest()` can rebuild the MAC.
    Keyed {
        algorithm: &'static digest::Algorithm,
        key: Vec<u8>,
        data: Vec<u8>,
        digested: bool,
    },
}

/// One of the eight fixed-width classes.
struct ClassSpec {
    /// The JS class name, e.g. `SHA512_256`.
    name: &'static str,
    /// The `CryptoHasher` algorithm it wraps, e.g. `sha512-256`.
    algorithm: &'static str,
}

const CLASSES: &[ClassSpec] = &[
    ClassSpec {
        name: "SHA1",
        algorithm: "sha1",
    },
    ClassSpec {
        name: "SHA224",
        algorithm: "sha224",
    },
    ClassSpec {
        name: "SHA256",
        algorithm: "sha256",
    },
    ClassSpec {
        name: "SHA384",
        algorithm: "sha384",
    },
    ClassSpec {
        name: "SHA512",
        algorithm: "sha512",
    },
    ClassSpec {
        name: "SHA512_256",
        algorithm: "sha512-256",
    },
    ClassSpec {
        name: "MD4",
        algorithm: "md4",
    },
    ClassSpec {
        name: "MD5",
        algorithm: "md5",
    },
];

/// The index into [`CLASSES`] carried in a callback's data slot.
///
/// A `FunctionTemplate` callback is a bare `fn` pointer, so "which class am I"
/// has to travel in the data slot. `CLASSES` is `'static`, so the index is all
/// that is needed and nothing is leaked.
fn class_of(args: &v8::FunctionCallbackArguments<'_>) -> &'static ClassSpec {
    let index = v8::Local::<v8::Integer>::try_from(args.data())
        .map(|value| value.value())
        .unwrap_or(-1);
    CLASSES
        .get(usize::try_from(index).unwrap_or(usize::MAX))
        .expect("every per-class callback is installed with its class index")
}

/// Installs the hashing group onto `target`.
///
/// `target` is the registry's per-module staging object, not the global. This sets
/// exactly [`crate::MEMBERS`] and nothing else; the registry compares the staging
/// object's own keys against that declaration in both directions after this
/// returns.
pub fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    install_hash(scope, target)?;
    install_sha(scope, target)?;
    install_crypto_hasher(scope, target)?;
    for (index, spec) in CLASSES.iter().enumerate() {
        let class = build_class(scope, index, spec)?;
        set_member(scope, target, spec.name, class.into())?;
    }
    Ok(())
}

/// `Bun.sha`, which is SHA-512/256 as a bare one-shot.
///
/// A separate function object from `Bun.SHA512_256.hash` — measured:
/// `Bun.sha === Bun.SHA512_256.hash` is `false` — with `length` **1**, not 2, and
/// no `new` (`new Bun.sha()` is "function is not a constructor"). It takes the same
/// output argument as the static form, so `Bun.sha("abc", "buffer")` is a `Buffer`
/// and `Bun.sha("abc")` is a plain `Uint8Array`.
fn install_sha<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let function = rn_core::named_method_with_length(scope, "sha", 1, sha_callback)?;
    set_member(scope, target, "sha", function.into())
}

fn sha_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(input) = bytes_of(scope, args.get(0)) else {
        throw_invalid_input(scope);
        return;
    };
    let Some(output) = output_of(scope, args.get(1)) else {
        return;
    };
    let Some(algorithm) = digest::resolve("sha512-256") else {
        throw_error_coded(
            scope,
            "ERR_CRYPTO_OPERATION_FAILED",
            "sha512-256 is missing from the algorithm table",
        );
        return;
    };
    let bytes = match Digest::new(algorithm).and_then(|mut digest| {
        digest.update(&input)?;
        digest.finish()
    }) {
        Ok(bytes) => bytes,
        Err(error) => {
            throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance);
            return;
        }
    };
    // A `Uint8Array` when no encoding is given, like the per-class family and
    // unlike `CryptoHasher`.
    if let Some(value) = emit(scope, output, &bytes, false) {
        rv.set(value);
    }
}

/// Defines `name` on `target` with Bun's attribute set: writable, enumerable,
/// non-configurable.
fn set_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    target
        .define_own_property(scope, key.into(), value, v8::PropertyAttribute::DONT_DELETE)
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn throw_type_coded(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    attach_code(scope, exception, code);
    scope.throw_exception(exception);
}

fn throw_error_coded(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    attach_code(scope, exception, code);
    scope.throw_exception(exception);
}

fn attach_code(scope: &mut v8::PinScope<'_, '_>, exception: v8::Local<'_, v8::Value>, code: &str) {
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        return;
    };
    let Some(key) = v8::String::new(scope, "code") else {
        return;
    };
    let Some(value) = v8::String::new(scope, code) else {
        return;
    };
    object.set(scope, key.into(), value.into());
}

/// `ERR_INVALID_ARG_TYPE` with the message every digest entry point shares.
fn throw_invalid_input(scope: &mut v8::PinScope<'_, '_>) {
    throw_type_coded(
        scope,
        "ERR_INVALID_ARG_TYPE",
        "input must be a string, ArrayBuffer, ArrayBufferView or Blob",
    );
}

/// The `Bun.hash` variant, whose wording differs: `data must be …`.
fn throw_invalid_data(scope: &mut v8::PinScope<'_, '_>) {
    throw_type_coded(
        scope,
        "ERR_INVALID_ARG_TYPE",
        "data must be a string, ArrayBuffer, ArrayBufferView or Blob",
    );
}

fn throw_already_digested(scope: &mut v8::PinScope<'_, '_>, class: &str, action: &str) {
    throw_error_coded(
        scope,
        "ERR_INVALID_STATE",
        &format!("{class} hasher already digested, create a new instance to {action}"),
    );
}

/// `ERR_INVALID_THIS`, with the suffix shaped from what the receiver actually is.
///
/// An object names its constructor (`an instance of Array`), a primitive reports
/// its type and value (`type string ('x')`). Both shapes are measured, and a
/// test that only checked `code` would miss the difference.
fn throw_invalid_this(
    scope: &mut v8::PinScope<'_, '_>,
    class: &str,
    this: v8::Local<'_, v8::Value>,
) {
    let received = describe_receiver(scope, this);
    throw_type_coded(
        scope,
        "ERR_INVALID_THIS",
        &format!("Expected this to be instanceof {class}, but received {received}"),
    );
}

fn describe_receiver(scope: &mut v8::PinScope<'_, '_>, this: v8::Local<'_, v8::Value>) -> String {
    if this.is_null() {
        return "null".into();
    }
    if this.is_undefined() {
        return "undefined".into();
    }
    if this.is_object() {
        let name = v8::Local::<v8::Object>::try_from(this)
            .ok()
            .and_then(|object| constructor_name(scope, object));
        return match name {
            Some(name) => format!("an instance of {name}"),
            None => "an instance of Object".into(),
        };
    }
    let kind = if this.is_number() {
        "number"
    } else if this.is_string() {
        "string"
    } else if this.is_boolean() {
        "boolean"
    } else if this.is_big_int() {
        "bigint"
    } else if this.is_symbol() {
        "symbol"
    } else {
        "value"
    };
    let text = this
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope));
    match text {
        Some(text) if kind == "string" => format!("type string ('{text}')"),
        Some(text) => format!("type {kind} ({text})"),
        None => format!("type {kind}"),
    }
}

fn constructor_name(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> Option<String> {
    let constructor_key = v8::String::new(scope, "constructor")?;
    let constructor = object.get(scope, constructor_key.into())?;
    let constructor = v8::Local::<v8::Object>::try_from(constructor).ok()?;
    let name_key = v8::String::new(scope, "name")?;
    let name = constructor.get(scope, name_key.into())?;
    Some(name.to_rust_string_lossy(scope))
}

/// Which spelling of the unknown-algorithm message to use.
///
/// Bun really does differ: the instance form is `Unsupported algorithm bogus`,
/// the static form is `Unsupported algorithm "bogus"` with quotes. A test that
/// shares one expectation between them fails on one of the two.
#[derive(Clone, Copy)]
enum UnknownAlgorithmStyle {
    Instance,
    Static,
}

fn throw_digest_error(
    scope: &mut v8::PinScope<'_, '_>,
    error: &DigestError,
    style: UnknownAlgorithmStyle,
) {
    match error {
        DigestError::UnknownAlgorithm(name) => {
            let message = match style {
                UnknownAlgorithmStyle::Instance => format!("Unsupported algorithm {name}"),
                UnknownAlgorithmStyle::Static => format!("Unsupported algorithm \"{name}\""),
            };
            throw_type_coded(scope, "ERR_INVALID_ARG_TYPE", &message);
        }
        DigestError::OpenSsl(message) | DigestError::Unavailable(message) => {
            throw_error_coded(scope, "ERR_CRYPTO_OPERATION_FAILED", message);
        }
    }
}

// ---------------------------------------------------------------------------
// Byte inputs and outputs
// ---------------------------------------------------------------------------

/// The bytes of a `string`, `ArrayBuffer`, `ArrayBufferView` or `Blob`.
///
/// The accepted set, the order it is tried in, and the rejection are measured.
/// This is **not** a `ToString` coercion: a plain object, a number, `true`,
/// `null` and an omitted argument are all `ERR_INVALID_ARG_TYPE`, while a
/// `String` *object* is accepted. A `SharedArrayBuffer` arrives here as an
/// `ArrayBuffer` because V8 types it as one, and a view is hashed from its own
/// `byteOffset`/`byteLength` rather than from its whole backing buffer.
fn bytes_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<'_, v8::Value>) -> Option<Vec<u8>> {
    if value.is_string() || value.is_string_object() {
        return Some(
            value
                .to_string(scope)?
                .to_rust_string_lossy(scope)
                .into_bytes(),
        );
    }
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let mut out = vec![0u8; view.byte_length()];
        let copied = view.copy_contents(&mut out);
        out.truncate(copied);
        return Some(out);
    }
    if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        let length = buffer.byte_length();
        let mut out = vec![0u8; length];
        if let Some(data) = buffer.data() {
            // SAFETY: `data` points at `byte_length` initialised bytes for as long
            // as `buffer` is alive, which it is here.
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), out.as_mut_ptr(), length);
            }
        }
        return Some(out);
    }
    if is_blob(scope, value) {
        return blob_bytes(scope, value);
    }
    None
}

/// Whether `value` is a `Blob`, decided by its `Symbol.toStringTag`.
///
/// A plain object can lie about that tag, but the lie costs it an error from the
/// byte read below rather than a hash of attacker-chosen bytes.
fn is_blob(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<'_, v8::Value>) -> bool {
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return false;
    };
    let Some(key) = v8::String::new(scope, "constructor") else {
        return false;
    };
    let Some(constructor) = object.get(scope, key.into()) else {
        return false;
    };
    let Ok(constructor) = v8::Local::<v8::Object>::try_from(constructor) else {
        return false;
    };
    let Some(name_key) = v8::String::new(scope, "name") else {
        return false;
    };
    let Some(name) = constructor.get(scope, name_key.into()) else {
        return false;
    };
    name.to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope) == "Blob")
        .unwrap_or(false)
}

/// Reads a `Blob`'s bytes synchronously.
///
/// `Blob#arrayBuffer()` is a promise and none of Bun's hashing entry points are
/// async, so this walks the blob binding's reader — the `getReader().pull(...)`
/// pair `internal/blob.js` itself uses — and drains it in a loop. Every part is
/// memory-resident, so `pull` invokes its callback synchronously and the loop
/// terminates without touching the event loop.
///
/// The handle lives behind a private symbol (`Symbol(kHandle)`), which is
/// reachable from `Object.getOwnPropertySymbols` even though its value is not
/// public API. If that symbol or the reader is missing — a host that installed
/// `Blob` without the blob binding — this answers `None`, and the caller reports
/// the input as invalid rather than hashing nothing.
fn blob_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Option<Vec<u8>> {
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;

    let symbols = object.get_own_property_names(scope, v8::GetPropertyNamesArgs::default())?;
    let mut handle_key = None;
    for index in 0..symbols.length() {
        let Some(key) = symbols.get_index(scope, index) else {
            continue;
        };
        let Ok(symbol) = v8::Local::<v8::Symbol>::try_from(key) else {
            continue;
        };
        let description = symbol.description(scope);
        if description.to_rust_string_lossy(scope) == "kHandle" {
            handle_key = Some(key);
            break;
        }
    }
    let handle_key = handle_key?;
    let handle = object.get(scope, handle_key)?;
    let handle = v8::Local::<v8::Object>::try_from(handle).ok()?;

    let get_reader_key = v8::String::new(scope, "getReader")?;
    let get_reader = handle.get(scope, get_reader_key.into())?;
    let get_reader = v8::Local::<v8::Function>::try_from(get_reader).ok()?;
    let reader = get_reader.call(scope, handle.into(), &[])?;
    let reader = v8::Local::<v8::Object>::try_from(reader).ok()?;

    let pull_key = v8::String::new(scope, "pull")?;
    let pull = reader.get(scope, pull_key.into())?;
    let pull = v8::Local::<v8::Function>::try_from(pull).ok()?;

    let status_key = v8::String::new(scope, "__status")?;
    let chunk_key = v8::String::new(scope, "__chunk")?;

    let mut parts: Vec<Vec<u8>> = Vec::new();
    loop {
        // A fresh collector per pull: the callback is synchronous, so a global is
        // a simple way to hand two values back out of it.
        let global = scope.get_current_context().global(scope);
        global.set(scope, status_key.into(), v8::undefined(scope).into());

        let collector = make_pull_collector(scope, &status_key, &chunk_key)?;
        let result = pull.call(scope, reader.into(), &[collector.into()])?;
        if scope.is_execution_terminating() {
            return None;
        }
        let status = global
            .get(scope, status_key.into())?
            .number_value(scope)
            .unwrap_or(-1.0);
        if status == 0.0 {
            break;
        }
        if status < 0.0 {
            return None;
        }
        let chunk = global.get(scope, chunk_key.into())?;
        let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(chunk) else {
            return None;
        };
        let mut bytes = vec![0u8; view.byte_length()];
        let copied = view.copy_contents(&mut bytes);
        bytes.truncate(copied);
        parts.push(bytes);
        let _ = result;
    }

    Some(parts.concat())
}

/// Builds the `(status, buffer)` callback a blob reader's `pull` expects.
fn make_pull_collector<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    status_key: &v8::Local<'s, v8::String>,
    chunk_key: &v8::Local<'s, v8::String>,
) -> Option<v8::Local<'s, v8::Function>> {
    // The keys travel as the function's data so the callback body stays a plain
    // `fn` pointer.
    let keys = v8::Object::new(scope);
    keys.set(
        scope,
        v8::Integer::new(scope, 0).into(),
        (*status_key).into(),
    );
    keys.set(
        scope,
        v8::Integer::new(scope, 1).into(),
        (*chunk_key).into(),
    );
    let builder = v8::Function::builder(pull_collector)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(2);
    builder.data(keys.into()).build(scope)
}

fn pull_collector(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Ok(keys) = v8::Local::<v8::Object>::try_from(args.data()) else {
        return;
    };
    let index = |i: i32| -> Option<v8::Local<'_, v8::Value>> {
        let key = v8::Integer::new(scope, i);
        keys.get(scope, key.into())
    };
    let global = scope.get_current_context().global(scope);
    if let Some(status_key) = index(0) {
        global.set(scope, status_key, args.get(0));
    }
    if let Some(chunk_key) = index(1) {
        if args.length() > 1 {
            global.set(scope, chunk_key, args.get(1));
        }
    }
}

/// Builds a `Uint8Array` over a fresh backing store.
fn uint8_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Uint8Array>> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    v8::Uint8Array::new(scope, buffer, 0, bytes.len())
}

/// Builds a Node `Buffer` over a fresh backing store.
///
/// `Buffer.from(arrayBuffer)` rather than `new Buffer(...)`: the latter is
/// deprecated and prints a warning to stderr, which every test that captures
/// stderr would see.
fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let buffer = buffer_constructor(scope)?;
    let from_key = v8::String::new(scope, "from")?;
    let from = buffer.get(scope, from_key.into())?;
    let from = v8::Local::<v8::Function>::try_from(from).ok()?;
    from.call(scope, buffer.into(), &[array_buffer.into()])
}

/// The global `Buffer`, looked up per call so no handle outlives its context.
fn buffer_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let value = global.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Encodes `bytes` with `name`, or answers `None` for a name Bun rejects.
///
/// The accepted set is measured, not derived: `utf16-le` is accepted while
/// `utf-16le` is not, `base64-url` is not accepted, `binary` is `latin1`, and
/// `buffer` is a `Buffer` rather than a string. All of it is ASCII-case-insensitive.
fn encode_digest<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let lowered = name.to_ascii_lowercase();
    match lowered.as_str() {
        "hex" => {
            let text: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            string_value(scope, &text)
        }
        "base64" => string_value(scope, &base64_encode(bytes, b"+/", true)),
        "base64url" => string_value(scope, &base64_encode(bytes, b"-_", false)),
        "latin1" | "binary" => {
            let text: String = bytes.iter().map(|byte| *byte as char).collect();
            string_value(scope, &text)
        }
        "ascii" => {
            // Node's `ascii` masks the high bit, and Bun inherits it.
            let text: String = bytes.iter().map(|byte| (*byte & 0x7f) as char).collect();
            string_value(scope, &text)
        }
        "utf8" => string_value(scope, &String::from_utf8_lossy(bytes)),
        "utf16le" | "ucs2" | "ucs-2" | "utf16-le" => {
            // Built from the code units directly rather than through a Rust
            // `String`: `from_utf16_lossy` replaces an unpaired surrogate with
            // U+FFFD, and a digest is arbitrary bytes, so a pair that happens to
            // look like half a surrogate must survive into the JS string. The
            // oracle's output for SHA-256 of "abc" contains exactly that case
            // (code unit 56896, a lone high surrogate).
            let units: Vec<u16> = bytes
                .chunks(2)
                .map(|pair| {
                    let low = u16::from(pair[0]);
                    let high = pair.get(1).copied().map(u16::from).unwrap_or(0);
                    low | (high << 8)
                })
                .collect();
            v8::String::new_from_two_byte(scope, &units, v8::NewStringType::Normal)
                .map(|value| value.into())
        }
        "buffer" => buffer_from(scope, bytes),
        _ => None,
    }
}

fn string_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    text: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    Some(v8::String::new(scope, text)?.into())
}

fn base64_encode(bytes: &[u8], alphabet: &[u8; 2], pad: bool) -> String {
    const DIGITS: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        let combined = (first << 16) | (second << 8) | third;
        let digit = |value: u32| -> char {
            match value {
                0..=61 => DIGITS[value as usize] as char,
                62 => alphabet[0] as char,
                _ => alphabet[1] as char,
            }
        };
        out.push(digit((combined >> 18) & 0x3f));
        out.push(digit((combined >> 12) & 0x3f));
        if chunk.len() > 1 {
            out.push(digit((combined >> 6) & 0x3f));
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(digit(combined & 0x3f));
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// What a `digest`/`hash` output argument asked for.
enum Output<'s> {
    /// No argument (or `null`/`undefined`): a fresh buffer.
    Fresh,
    /// An encoding name.
    Encoding(String),
    /// A buffer to write into, returned as-is.
    Into(v8::Local<'s, v8::Value>),
}

/// Interprets the output argument, or throws and answers `None`.
///
/// `null` and `undefined` mean "no encoding", while a number, `false`, `true`, an
/// object or a symbol are `ERR_INVALID_ARG_TYPE` with the *output* wording. The
/// split between "wrong kind of thing" and "unknown encoding" is measured: a
/// number is the former, an unrecognised string the latter.
fn output_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Output<'s>> {
    if value.is_null() || value.is_undefined() {
        return Some(Output::Fresh);
    }
    if value.is_string() || value.is_string_object() {
        let name = value.to_string(scope)?.to_rust_string_lossy(scope);
        return Some(Output::Encoding(name));
    }
    if value.is_array_buffer() || value.is_array_buffer_view() {
        return Some(Output::Into(value));
    }
    throw_type_coded(
        scope,
        "ERR_INVALID_ARG_TYPE",
        "output must be of type string or ArrayBuffer or ArrayBufferView",
    );
    None
}

/// Writes `digest` into `target`, which must hold at least `digest.len()` bytes.
///
/// Returns the target itself: Bun returns the same object, not a view onto it,
/// and a target longer than the digest keeps its tail untouched.
fn write_into_target(
    scope: &mut v8::PinScope<'_, '_>,
    target: v8::Local<'_, v8::Value>,
    digest: &[u8],
) -> Option<()> {
    let needed = digest.len();
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(target) {
        // The length is measured in bytes, so a `Uint16Array(16)` is 32 bytes and
        // passes a 32-byte requirement — measured, and not what a element count
        // would say.
        if view.byte_length() < needed {
            throw_type_coded(
                scope,
                "ERR_INVALID_ARG_TYPE",
                &format!("TypedArray must be at least {needed} bytes"),
            );
            return None;
        }
        // SAFETY: the view reports at least `needed` writable bytes at `data()`,
        // and the target is alive for the copy.
        unsafe {
            std::ptr::copy_nonoverlapping(digest.as_ptr(), view.data().cast::<u8>(), needed);
        }
        return Some(());
    }
    let buffer = v8::Local::<v8::ArrayBuffer>::try_from(target).ok()?;
    if buffer.byte_length() < needed {
        throw_type_coded(
            scope,
            "ERR_INVALID_ARG_TYPE",
            &format!("TypedArray must be at least {needed} bytes"),
        );
        return None;
    }
    let data = buffer.data()?;
    // SAFETY: the buffer reports at least `needed` writable bytes and is alive.
    unsafe {
        std::ptr::copy_nonoverlapping(digest.as_ptr(), data.as_ptr().cast::<u8>(), needed);
    }
    Some(())
}

/// Emits a finished digest according to `output`.
///
/// `fresh_buffer` decides what an absent encoding produces, which is the one
/// place the two families differ: a per-class `digest()` is a `Uint8Array` while
/// `CryptoHasher`'s is a `Buffer`.
fn emit<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    output: Output<'s>,
    digest: &[u8],
    fresh_buffer: bool,
) -> Option<v8::Local<'s, v8::Value>> {
    match output {
        Output::Into(target) => {
            write_into_target(scope, target, digest)?;
            Some(target)
        }
        Output::Encoding(name) => match encode_digest(scope, digest, &name) {
            Some(value) => Some(value),
            None => {
                throw_type_coded(
                    scope,
                    "ERR_INVALID_ARG_VALUE",
                    &format!("Unknown encoding: {name}"),
                );
                None
            }
        },
        Output::Fresh => {
            if fresh_buffer {
                buffer_from(scope, digest)
            } else {
                uint8_array(scope, digest).map(|value| value.into())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-instance state
// ---------------------------------------------------------------------------

/// Stores `state` on `object` with a finaliser that frees it.
fn attach_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    state: State,
) {
    let pointer = Box::into_raw(Box::new(std::cell::RefCell::new(state)));
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
            // SAFETY: allocated by `attach_state` for this object alone, and this
            // finaliser is the only thing that frees it.
            drop(unsafe { Box::from_raw(address as *mut std::cell::RefCell<State>) });
        }),
    );
}

/// Whether `object` carries this crate's state at all.
///
/// The internal-field count is checked first: an object built by some other code
/// has no fields, and `get_aligned_pointer_from_internal_field` on such an object
/// reads a tagged JS value as a pointer — which is a misaligned dereference, not
/// a null check. That is a real crash, not a theoretical one.
fn has_state(object: v8::Local<'_, v8::Object>) -> bool {
    if object.internal_field_count() <= STATE_FIELD as usize {
        return false;
    }
    // SAFETY: the object has at least one internal field, so the accessor reads
    // initialised field storage.
    !unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }.is_null()
}

/// Runs `body` with the receiver's state.
fn with_state<R>(
    object: v8::Local<'_, v8::Object>,
    body: impl FnOnce(&mut State) -> R,
) -> Option<R> {
    if object.internal_field_count() <= STATE_FIELD as usize {
        return None;
    }
    // SAFETY: the pointer was written by `attach_state` into this object's field
    // 0, and nothing but its finaliser clears or replaces it.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut std::cell::RefCell<State>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above, and the finaliser runs only once the object is
    // unreachable, which cannot happen while `object` is a live local.
    let cell = unsafe { &*pointer };
    let mut state = cell.borrow_mut();
    Some(body(&mut state))
}

// ---------------------------------------------------------------------------
// Bun.hash
// ---------------------------------------------------------------------------

/// Seed conversion: `HashObject.rs`'s `seed_of` plus JSC's `toUInt64NoTruncate`.
///
/// A seed of any other type becomes 0, so `hash("abc","zzz")`, `hash("abc",true)`
/// and `hash("abc",null)` all equal `hash("abc",0)`. That includes the coercible
/// ones — measured, `hash("abc", "7")`, `hash("abc", true)` and
/// `hash("abc", [7])` are all the seed-0 answer, not the seed-7 one — because
/// `seed_of` tests the type and never converts it. A `BigInt` wraps modulo 2^64.
/// A number follows JSC, and none of it is guessable:
///
/// * `NaN` is 0, `-Infinity` is 0, `Infinity` is `u64::MAX`;
/// * `>= 2^64` saturates to `u64::MAX`;
/// * otherwise truncate toward zero and wrap modulo 2^64, so `-1` is `2^64-1`
///   and `1.9` is `1`.
///
/// All of that is measured across the full double range. A plain `as u64` cast
/// would get every large negative seed wrong, because Rust saturates. Calling
/// `number_value` to read a number is the other trap: it converts, so it would
/// accept a `String`/`Boolean`/`Number` object that Bun reads as 0.
fn seed_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<'_, v8::Value>) -> u64 {
    if value.is_big_int() {
        if let Ok(big) = v8::Local::<v8::BigInt>::try_from(value) {
            // `u64_value` wraps modulo 2^64, which is what `toBigUInt64` does; the
            // lossless flag is therefore deliberately ignored.
            let (value, _) = big.u64_value();
            return value;
        }
        return 0;
    }
    if !value.is_number() {
        return 0;
    }
    let Some(number) = value.number_value(scope) else {
        return 0;
    };
    if number.is_nan() || number == f64::NEG_INFINITY {
        return 0;
    }
    if number >= 18_446_744_073_709_551_616.0 {
        return u64::MAX;
    }
    let modulus = 18_446_744_073_709_551_616.0_f64;
    number.trunc().rem_euclid(modulus) as u64
}

fn install_hash<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let hash = rn_core::named_method_with_length(scope, "hash", 1, hash_callback)?;
    // Every variant is an own property of the function, and `Bun.hash` itself is
    // callable: `Bun.hash.wyhash` is a distinct function object with the same
    // result, which is measured rather than implied.
    //
    // Each variant is installed by its own statement rather than through a
    // table: `MapFnTo` is implemented for the fully generic function item, and
    // a `fn` pointer in a `&[( &str, fn(..) )]` has already lost it.
    let variants: [v8::Local<'s, v8::Function>; 12] = [
        rn_core::named_method_with_length(scope, "wyhash", 1, wyhash_callback)?,
        rn_core::named_method_with_length(scope, "adler32", 1, adler32_callback)?,
        rn_core::named_method_with_length(scope, "crc32", 1, crc32_callback)?,
        rn_core::named_method_with_length(scope, "cityHash32", 1, city_hash32_callback)?,
        rn_core::named_method_with_length(scope, "cityHash64", 1, city_hash64_callback)?,
        rn_core::named_method_with_length(scope, "xxHash32", 1, xxhash32_callback)?,
        rn_core::named_method_with_length(scope, "xxHash64", 1, xxhash64_callback)?,
        rn_core::named_method_with_length(scope, "xxHash3", 1, xxhash3_callback)?,
        rn_core::named_method_with_length(scope, "murmur32v2", 1, murmur32v2_callback)?,
        rn_core::named_method_with_length(scope, "murmur32v3", 1, murmur32v3_callback)?,
        rn_core::named_method_with_length(scope, "murmur64v2", 1, murmur64v2_callback)?,
        rn_core::named_method_with_length(scope, "rapidhash", 1, rapidhash_callback)?,
    ];
    let names = [
        "wyhash",
        "adler32",
        "crc32",
        "cityHash32",
        "cityHash64",
        "xxHash32",
        "xxHash64",
        "xxHash3",
        "murmur32v2",
        "murmur32v3",
        "murmur64v2",
        "rapidhash",
    ];
    for (name, function) in names.iter().zip(variants) {
        let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
        hash.define_own_property(
            scope,
            key.into(),
            function.into(),
            v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or_else(|| format!("cannot define Bun.hash.{name}"))?;
    }
    set_member(scope, target, "hash", hash.into())
}

/// The shared front half of every `Bun.hash*` member: the bytes and the seed.
fn hash_arguments(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
) -> Option<(Vec<u8>, u64)> {
    let data = args.get(0);
    if data.is_symbol() {
        // `String(symbol)` throws V8's own `Cannot convert a symbol to a string`,
        // which is the message the spec pins; producing it by converting is the
        // only way to get the text exactly right.
        data.to_string(scope);
        return None;
    }
    if data.is_null() || data.is_undefined() {
        throw_invalid_data(scope);
        return None;
    }
    let bytes = match bytes_of(scope, data) {
        Some(bytes) => bytes,
        // Everything Bun accepts was tried; anything left goes through
        // `String()`, which is what makes `hash(42) === hash("42")` and
        // `hash({}) === hash("[object Object]")` hold.
        None => data
            .to_string(scope)?
            .to_rust_string_lossy(scope)
            .into_bytes(),
    };
    Some((bytes, seed_of(scope, args.get(1))))
}

fn hash_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    emit_bigint(scope, &mut rv, wyhash::hash(seed, &bytes));
}

fn wyhash_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    hash_callback(scope, args, rv);
}

fn adler32_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    // Adler-32 has no seed: the JS binding takes one argument, and a second one
    // is ignored entirely.
    let Some((bytes, _)) = hash_arguments(scope, &args) else {
        return;
    };
    rv.set(v8::Number::new(scope, f64::from(hashes::adler32(&bytes))).into());
}

fn crc32_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    rv.set(v8::Number::new(scope, f64::from(crc32(seed as u32, &bytes))).into());
}

fn city_hash32_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, _)) = hash_arguments(scope, &args) else {
        return;
    };
    rv.set(v8::Number::new(scope, f64::from(hashes::city_hash32(&bytes))).into());
}

fn city_hash64_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    emit_bigint(scope, &mut rv, hashes::city_hash64(&bytes, seed));
}

fn xxhash32_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    rv.set(v8::Number::new(scope, f64::from(hashes::xxhash32(&bytes, seed as u32))).into());
}

fn xxhash64_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    emit_bigint(scope, &mut rv, hashes::xxhash64(&bytes, seed));
}

fn xxhash3_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    // Measured: `xxHash3` truncates its seed to 32 bits, so `seed 2^32+5` equals
    // `seed 5` but `wyhash` at the same seeds differs.
    emit_bigint(
        scope,
        &mut rv,
        hashes::xxhash3(&bytes, u64::from(seed as u32)),
    );
}

fn murmur32v2_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    rv.set(v8::Number::new(scope, f64::from(hashes::murmur32v2(&bytes, seed as u32))).into());
}

fn murmur32v3_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    rv.set(v8::Number::new(scope, f64::from(hashes::murmur32v3(&bytes, seed as u32))).into());
}

fn murmur64v2_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    emit_bigint(scope, &mut rv, hashes::murmur64v2(&bytes, seed));
}

fn rapidhash_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((bytes, seed)) = hash_arguments(scope, &args) else {
        return;
    };
    emit_bigint(scope, &mut rv, hashes::rapidhash(&bytes, seed));
}

fn emit_bigint(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, value: u64) {
    rv.set(v8::BigInt::new_from_u64(scope, value).into());
}

/// CRC-32, which Bun takes from zlib.
///
/// This is zlib's `crc32()`: a *running* CRC seeded by the second argument, so
/// `crc32("", 5)` is `5` rather than `0`, which is why the initial value is
/// inverted and the result inverted back. Implemented here rather than through
/// `rn-bind-zlib` because that crate is an `internalBinding` provider and linking
/// it for one function would drag the whole zlib namespace in.
fn crc32(seed: u32, data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for (index, entry) in table.iter_mut().enumerate() {
            let mut value = index as u32;
            for _ in 0..8 {
                value = if value & 1 != 0 {
                    (value >> 1) ^ 0xedb8_8320
                } else {
                    value >> 1
                };
            }
            *entry = value;
        }
        table
    });
    let mut crc = !seed;
    for &byte in data {
        crc = table[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

// ---------------------------------------------------------------------------
// The per-algorithm classes
// ---------------------------------------------------------------------------

fn build_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: usize,
    spec: &ClassSpec,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let data = v8::Integer::new(scope, index as i32).into();
    // `ConstructorBehavior::Allow`, not `Throw`: `Throw` removes the function's
    // `prototype` property entirely, which would make `Bun.SHA256.prototype`
    // `undefined` — and the prototype is where every method lives. Refusing a
    // plain call is done in the body with `ERR_ILLEGAL_CONSTRUCTOR`, which is
    // what Bun throws and what `rn_core::class` does for the same reason.
    let constructor = v8::FunctionTemplate::builder(pair_constructor)
        .constructor_behavior(v8::ConstructorBehavior::Allow)
        .length(0)
        .data(data)
        .build(scope);
    constructor
        .instance_template(scope)
        .set_internal_field_count(1);
    let class_name = v8::String::new(scope, spec.name)
        .ok_or_else(|| format!("cannot allocate the class name {}", spec.name))?;
    constructor.set_class_name(class_name);

    let function = constructor
        .get_function(scope)
        .ok_or_else(|| format!("cannot instantiate the {} class", spec.name))?;
    let name_key = v8::String::new(scope, spec.name)
        .ok_or_else(|| format!("cannot allocate {}", spec.name))?;
    function.set_name(name_key);

    let prototype_key = v8::String::new(scope, "prototype").ok_or("cannot allocate prototype")?;
    let prototype = function
        .get(scope, prototype_key.into())
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .ok_or_else(|| format!("cannot read the {} prototype", spec.name))?;

    // Everything below is installed on the real objects rather than on templates,
    // for one reason: `FunctionTemplate::builder` only accepts a three-argument
    // callback, so an accessor has no route through it, and `define_property`
    // appends in call order — which is how `byteLength` comes out first, as Bun's
    // does (`Object.getOwnPropertyNames(Bun.SHA256.prototype)` puts it before
    // `digest` and `update`).
    //
    // V8 inserts `constructor` as the prototype's *first* property, while Bun's
    // is last. The order is observable through `getOwnPropertyNames`, so the
    // implicit one is removed here and re-added at the end of this function.
    let constructor_key =
        v8::String::new(scope, "constructor").ok_or("cannot allocate constructor")?;
    prototype.delete(scope, constructor_key.into());

    let byte_length = v8::String::new(scope, "byteLength").ok_or("cannot allocate byteLength")?;
    let getter = v8::Function::builder(pair_byte_length_getter)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
        .data(data)
        .build(scope)
        .ok_or("cannot instantiate the byteLength getter")?;
    define_getter(scope, prototype, byte_length, getter, "get byteLength")
        .ok_or("cannot define the instance byteLength")?;

    let digest_key = v8::String::new(scope, "digest").ok_or("cannot allocate digest")?;
    let digest = v8::Function::builder(pair_digest)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
        .data(data)
        .build(scope)
        .ok_or("cannot instantiate digest")?;
    digest.set_name(digest_key);
    prototype
        .set(scope, digest_key.into(), digest.into())
        .ok_or("cannot define digest")?;

    let update_key = v8::String::new(scope, "update").ok_or("cannot allocate update")?;
    let update = v8::Function::builder(pair_update)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(1)
        .data(data)
        .build(scope)
        .ok_or("cannot instantiate update")?;
    update.set_name(update_key);
    prototype
        .set(scope, update_key.into(), update.into())
        .ok_or("cannot define update")?;

    // `Object.prototype.toString.call(new Bun.SHA256())` is `[object SHA256]`.
    let tag_key = v8::Symbol::get_to_string_tag(scope);
    let tag_value = v8::String::new(scope, spec.name).ok_or("cannot allocate toStringTag")?;
    prototype
        .set(scope, tag_key.into(), tag_value.into())
        .ok_or("cannot define toStringTag")?;

    let static_getter = v8::Function::builder(pair_static_byte_length_getter)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
        .data(data)
        .build(scope)
        .ok_or("cannot instantiate the static byteLength getter")?;
    define_getter(
        scope,
        v8::Local::<v8::Object>::from(function),
        byte_length,
        static_getter,
        "get byteLength",
    )
    .ok_or("cannot define the static byteLength")?;

    let hash_key = v8::String::new(scope, "hash").ok_or("cannot allocate hash")?;
    let hash = v8::Function::builder(pair_hash)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(2)
        .data(data)
        .build(scope)
        .ok_or("cannot instantiate the static hash")?;
    hash.set_name(hash_key);
    function
        .set(scope, hash_key.into(), hash.into())
        .ok_or("cannot define the static hash")?;

    // `constructor` last, which is where Bun's prototype lists it.
    define_own(scope, prototype, constructor_key, function.into())
        .ok_or("cannot restore the prototype constructor")?;

    Ok(function)
}

/// Defines `key` on `target` as a getter-only accessor.
///
/// A `v8::Function` rather than a `FunctionTemplate`, because only the function
/// form gives the callback a receiver: `PropertyCallbackArguments` exposes the
/// *holder*, which for an inherited accessor is the prototype, and
/// `byteLength` has to answer `undefined`-shaped errors for a wrong receiver
/// rather than silently reporting the class's own length.
///
/// `define_own_property` names the function `get <key>` for free, which is what
/// `Object.getOwnPropertyDescriptor(...).get.name` reports on Bun.
/// Defines a plain data property with Bun's attributes: writable, enumerable,
/// non-configurable.
fn define_own<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    key: v8::Local<'s, v8::String>,
    value: v8::Local<'s, v8::Value>,
) -> Option<bool> {
    target.define_own_property(scope, key.into(), value, v8::PropertyAttribute::DONT_DELETE)
}

fn define_getter<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    key: v8::Local<'s, v8::String>,
    getter: v8::Local<'s, v8::Function>,
    name: &str,
) -> Option<bool> {
    // V8 names an accessor installed from a template `get <key>` by itself, but a
    // plain `Function` keeps whatever name it was given — and Bun reports
    // `"get byteLength"`, so it is set rather than left empty.
    if let Some(name) = v8::String::new(scope, name) {
        getter.set_name(name);
    }
    let mut descriptor =
        v8::PropertyDescriptor::new_from_get_set(getter.into(), v8::undefined(scope).into());
    descriptor.set_configurable(false);
    target.define_property(scope, key.into(), &descriptor)
}

/// `new Bun.SHA256()`.
fn pair_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let spec = class_of(&args);
    if !args.is_construct_call() {
        throw_type_coded(
            scope,
            "ERR_ILLEGAL_CONSTRUCTOR",
            &format!("{} constructor cannot be invoked without 'new'", spec.name),
        );
        return;
    }
    let Some(algorithm) = digest::resolve(spec.algorithm) else {
        throw_digest_error(
            scope,
            &DigestError::UnknownAlgorithm(spec.algorithm.to_string()),
            UnknownAlgorithmStyle::Instance,
        );
        return;
    };
    let digest = match Digest::new(algorithm) {
        Ok(digest) => digest,
        Err(error) => {
            throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance);
            return;
        }
    };
    let this = args.this();
    attach_state(
        scope,
        this,
        State::Plain {
            digest,
            digested: false,
        },
    );
    rv.set(this.into());
}

/// Reads the receiver as a hasher, or throws `ERR_INVALID_THIS` and answers `None`.
fn receiver_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    this: v8::Local<'s, v8::Value>,
    class: &str,
) -> Option<v8::Local<'s, v8::Object>> {
    if let Ok(object) = v8::Local::<v8::Object>::try_from(this) {
        if has_state(object) {
            return Some(object);
        }
    }
    throw_invalid_this(scope, class, this);
    None
}

/// `Bun.SHA256.prototype.byteLength` — a getter.
///
/// On a non-instance it throws a message naming the class and carries **no**
/// `code`, which is measured and different from every other error here.
fn pair_byte_length_getter<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let spec = class_of(&args);
    let this = args.this();
    let length = if has_state(this) {
        with_state(this, |state| match state {
            State::Plain { digest, .. } => Some(digest.length()),
            State::Keyed { algorithm, .. } => Some(algorithm.length),
        })
        .flatten()
    } else {
        None
    };
    match length {
        Some(length) => rv.set(v8::Integer::new(scope, length as i32).into()),
        None => throw_getter_on_non_instance(scope, spec.name, "byteLength"),
    }
}

/// The per-class static `byteLength`, which needs no receiver: it is a fact
/// about the class rather than about an instance.
fn pair_static_byte_length_getter<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let spec = class_of(&args);
    let Some(algorithm) = digest::resolve(spec.algorithm) else {
        return;
    };
    rv.set(v8::Integer::new(scope, algorithm.length as i32).into());
}

fn throw_getter_on_non_instance(scope: &mut v8::PinScope<'_, '_>, class: &str, member: &str) {
    let Some(text) = v8::String::new(
        scope,
        &format!("The {class}.{member} getter can only be used on instances of {class}"),
    ) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// `Bun.SHA256.prototype.update(input, encoding)`.
///
/// The second argument is accepted and **ignored**: `update("616263","hex")`
/// hashes the six characters, which is the opposite of `CryptoHasher`'s
/// behaviour and the reason the two cannot share a body.
fn pair_update<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let spec = class_of(&args);
    let this = args.this();
    let Some(object) = receiver_state(scope, this.into(), spec.name) else {
        return;
    };
    let Some(input) = bytes_of(scope, args.get(0)) else {
        throw_invalid_input(scope);
        return;
    };
    let outcome = with_state(object, |state| match state {
        State::Plain { digest, digested } => {
            if *digested {
                Err(Outcome::AlreadyUpdated)
            } else {
                digest.update(&input).map_err(Outcome::Failed)
            }
        }
        State::Keyed { .. } => unreachable!("per-class hashers are never keyed"),
    });
    match outcome {
        Some(Ok(())) => rv.set(this.into()),
        Some(Err(Outcome::AlreadyUpdated)) => throw_already_digested(scope, spec.name, "update"),
        Some(Err(Outcome::Failed(error))) => {
            throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance)
        }
        None => throw_invalid_this(scope, spec.name, this.into()),
    }
}

/// The internal outcome of an update or digest, before it becomes a JS error.
enum Outcome {
    AlreadyUpdated,
    Failed(DigestError),
}

/// `Bun.SHA256.prototype.digest(output)`.
fn pair_digest<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let spec = class_of(&args);
    let this = args.this();
    let Some(object) = receiver_state(scope, this.into(), spec.name) else {
        return;
    };
    // The output argument is validated before the state is touched, so an
    // invalid arg leaves the hasher usable — measured: a `digest("bogus")` that
    // throws does not consume the digest.
    let Some(output) = output_of(scope, args.get(0)) else {
        return;
    };
    let outcome = with_state(object, |state| match state {
        State::Plain { digest, digested } => {
            if *digested {
                return Err(Outcome::AlreadyUpdated);
            }
            let mut bytes = vec![0u8; digest.length()];
            match digest.finish_into(&mut bytes) {
                Ok(()) => {
                    *digested = true;
                    Ok(bytes)
                }
                Err(error) => Err(Outcome::Failed(error)),
            }
        }
        State::Keyed { .. } => unreachable!("per-class hashers are never keyed"),
    });
    match outcome {
        Some(Ok(bytes)) => {
            if let Some(value) = emit(scope, output, &bytes, false) {
                rv.set(value);
            }
        }
        Some(Err(Outcome::AlreadyUpdated)) => {
            throw_already_digested(scope, spec.name, "digest again")
        }
        Some(Err(Outcome::Failed(error))) => {
            throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance)
        }
        None => throw_invalid_this(scope, spec.name, this.into()),
    }
}

/// `Bun.SHA256.hash(input, output)` — the static one-shot.
fn pair_hash<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let spec = class_of(&args);
    let Some(input) = bytes_of(scope, args.get(0)) else {
        throw_invalid_input(scope);
        return;
    };
    let Some(output) = output_of(scope, args.get(1)) else {
        return;
    };
    let Some(algorithm) = digest::resolve(spec.algorithm) else {
        throw_digest_error(
            scope,
            &DigestError::UnknownAlgorithm(spec.algorithm.to_string()),
            UnknownAlgorithmStyle::Instance,
        );
        return;
    };
    let bytes = match Digest::new(algorithm).and_then(|mut digest| {
        digest.update(&input)?;
        digest.finish()
    }) {
        Ok(bytes) => bytes,
        Err(error) => {
            throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance);
            return;
        }
    };
    if let Some(value) = emit(scope, output, &bytes, false) {
        rv.set(value);
    }
}

// ---------------------------------------------------------------------------
// Bun.CryptoHasher
// ---------------------------------------------------------------------------

fn install_crypto_hasher<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // `Allow` for the same reason as the per-class templates: `Throw` would drop
    // `.prototype`, and `CryptoHasher.prototype` has to exist.
    let constructor = v8::FunctionTemplate::builder(crypto_hasher_constructor)
        .constructor_behavior(v8::ConstructorBehavior::Allow)
        .length(0)
        .build(scope);
    constructor
        .instance_template(scope)
        .set_internal_field_count(1);
    let class_name =
        v8::String::new(scope, "CryptoHasher").ok_or("cannot allocate CryptoHasher")?;
    constructor.set_class_name(class_name);

    // Methods go on the real prototype for two reasons: the order Bun reports
    // (`algorithm`, `byteLength`, `copy`, `digest`, `update`, `constructor`) is
    // the order they are defined, and V8 inserts `constructor` first, so it has
    // to be removed and re-added last.
    let function = constructor
        .get_function(scope)
        .ok_or("cannot instantiate CryptoHasher")?;
    CRYPTO_HASHER_TEMPLATE.with(|slot| {
        *slot.borrow_mut() = Some(v8::Global::new(scope, constructor));
    });
    let name_key = v8::String::new(scope, "CryptoHasher").ok_or("cannot allocate CryptoHasher")?;
    function.set_name(name_key);

    let prototype_key = v8::String::new(scope, "prototype").ok_or("cannot allocate prototype")?;
    let prototype = function
        .get(scope, prototype_key.into())
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .ok_or("cannot read the CryptoHasher prototype")?;
    let constructor_key =
        v8::String::new(scope, "constructor").ok_or("cannot allocate constructor")?;
    prototype.delete(scope, constructor_key.into());

    let algorithm_key = v8::String::new(scope, "algorithm").ok_or("cannot allocate algorithm")?;
    let algorithm_getter = v8::Function::builder(crypto_hasher_algorithm_getter)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
        .build(scope)
        .ok_or("cannot instantiate the algorithm getter")?;
    define_getter(
        scope,
        prototype,
        algorithm_key,
        algorithm_getter,
        "get algorithm",
    )
    .ok_or("cannot define CryptoHasher.algorithm")?;

    let byte_length_key =
        v8::String::new(scope, "byteLength").ok_or("cannot allocate byteLength")?;
    let byte_length_getter = v8::Function::builder(crypto_hasher_byte_length_getter)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
        .build(scope)
        .ok_or("cannot instantiate the byteLength getter")?;
    define_getter(
        scope,
        prototype,
        byte_length_key,
        byte_length_getter,
        "get byteLength",
    )
    .ok_or("cannot define CryptoHasher.byteLength")?;

    let copy_key = v8::String::new(scope, "copy").ok_or("cannot allocate copy")?;
    let copy = v8::Function::builder(crypto_hasher_copy)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
        .build(scope)
        .ok_or("cannot instantiate copy")?;
    copy.set_name(copy_key);
    prototype
        .set(scope, copy_key.into(), copy.into())
        .ok_or("cannot define CryptoHasher.copy")?;

    let digest_key = v8::String::new(scope, "digest").ok_or("cannot allocate digest")?;
    let digest = v8::Function::builder(crypto_hasher_digest)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
        .build(scope)
        .ok_or("cannot instantiate digest")?;
    digest.set_name(digest_key);
    prototype
        .set(scope, digest_key.into(), digest.into())
        .ok_or("cannot define CryptoHasher.digest")?;

    let update_key = v8::String::new(scope, "update").ok_or("cannot allocate update")?;
    let update = v8::Function::builder(crypto_hasher_update)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(2)
        .build(scope)
        .ok_or("cannot instantiate update")?;
    update.set_name(update_key);
    prototype
        .set(scope, update_key.into(), update.into())
        .ok_or("cannot define CryptoHasher.update")?;

    let tag_key = v8::Symbol::get_to_string_tag(scope);
    let tag_value = v8::String::new(scope, "CryptoHasher").ok_or("cannot allocate toStringTag")?;
    prototype
        .set(scope, tag_key.into(), tag_value.into())
        .ok_or("cannot define CryptoHasher toStringTag")?;

    define_own(scope, prototype, constructor_key, function.into())
        .ok_or("cannot restore the CryptoHasher prototype constructor")?;

    // `algorithms` is a getter whose array is fresh on every read — measured:
    // `CryptoHasher.algorithms === CryptoHasher.algorithms` is false.
    let algorithms_key =
        v8::String::new(scope, "algorithms").ok_or("cannot allocate algorithms")?;
    let algorithms_getter = v8::Function::builder(crypto_hasher_algorithms_getter)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
        .build(scope)
        .ok_or("cannot instantiate the algorithms getter")?;
    define_getter(
        scope,
        v8::Local::<v8::Object>::from(function),
        algorithms_key,
        algorithms_getter,
        "get algorithms",
    )
    .ok_or("cannot define CryptoHasher.algorithms")?;

    let hash_key = v8::String::new(scope, "hash").ok_or("cannot allocate hash")?;
    let hash = v8::Function::builder(crypto_hasher_hash)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(2)
        .build(scope)
        .ok_or("cannot instantiate CryptoHasher.hash")?;
    hash.set_name(hash_key);
    function
        .set(scope, hash_key.into(), hash.into())
        .ok_or("cannot define CryptoHasher.hash")?;

    set_member(scope, target, "CryptoHasher", function.into())
}

/// `new Bun.CryptoHasher(algorithm, hmacKey)`.
fn crypto_hasher_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    if !args.is_construct_call() {
        throw_type_coded(
            scope,
            "ERR_ILLEGAL_CONSTRUCTOR",
            "CryptoHasher constructor cannot be invoked without 'new'",
        );
        return;
    }
    let algorithm_value = args.get(0);
    if !algorithm_value.is_string() && !algorithm_value.is_string_object() {
        throw_type_coded(scope, "ERR_INVALID_ARG_TYPE", "algorithm must be a string");
        return;
    }
    let Some(name) = algorithm_value
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
    else {
        return;
    };
    let Some(algorithm) = digest::resolve(&name) else {
        throw_digest_error(
            scope,
            &DigestError::UnknownAlgorithm(name),
            UnknownAlgorithmStyle::Instance,
        );
        return;
    };

    // The second argument is the HMAC key. `null` and `undefined` mean "no key",
    // which is why `new CryptoHasher("sha256", null)` hashes; a `Blob` is *not*
    // accepted here even though it is accepted as an update input.
    let key_value = args.get(1);
    let key = if key_value.is_null() || key_value.is_undefined() {
        None
    } else if key_value.is_string() || key_value.is_string_object() {
        key_value
            .to_string(scope)
            .map(|text| text.to_rust_string_lossy(scope).into_bytes())
    } else if key_value.is_array_buffer() || key_value.is_array_buffer_view() {
        bytes_of(scope, key_value)
    } else {
        throw_type_coded(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "hmacKey must be a string, ArrayBuffer or ArrayBufferView",
        );
        return;
    };

    let state = match key {
        Some(key) => State::Keyed {
            algorithm,
            key,
            data: Vec::new(),
            digested: false,
        },
        None => match Digest::new(algorithm) {
            Ok(digest) => State::Plain {
                digest,
                digested: false,
            },
            Err(error) => {
                throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance);
                return;
            }
        },
    };

    let this = args.this();
    attach_state(scope, this, state);
    rv.set(this.into());
}

fn crypto_hasher_algorithms_getter(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let array = v8::Array::new(scope, CRYPTO_HASHER_ALGORITHMS.len() as i32);
    for (index, name) in CRYPTO_HASHER_ALGORITHMS.iter().enumerate() {
        let Some(value) = v8::String::new(scope, name) else {
            return;
        };
        array.set_index(scope, index as u32, value.into());
    }
    rv.set(array.into());
}

/// `CryptoHasher.prototype.algorithm`.
fn crypto_hasher_algorithm_getter<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let this = args.this();
    if !has_state(this) {
        throw_crypto_hasher_getter(scope, "algorithm");
        return;
    }
    let name = with_state(this, |state| match state {
        State::Plain { digest, .. } => Some(digest.name().to_string()),
        State::Keyed {
            algorithm,
            digested,
            ..
        } => {
            // A consumed HMAC no longer reports an algorithm: `digest()` then
            // `.algorithm` throws `HMAC has been consumed`.
            if *digested {
                None
            } else {
                Some(algorithm.name.to_string())
            }
        }
    })
    .flatten();
    match name {
        Some(name) => {
            if let Some(value) = v8::String::new(scope, &name) {
                rv.set(value.into());
            }
        }
        None => throw_error_coded(
            scope,
            "ERR_CRYPTO_OPERATION_FAILED",
            "HMAC has been consumed and is no longer usable",
        ),
    }
}

/// `CryptoHasher.prototype.byteLength`.
fn crypto_hasher_byte_length_getter<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let this = args.this();
    if !has_state(this) {
        throw_crypto_hasher_getter(scope, "byteLength");
        return;
    }
    let length = with_state(this, |state| match state {
        State::Plain { digest, .. } => Some(digest.length()),
        State::Keyed { algorithm, .. } => Some(algorithm.length),
    })
    .flatten();
    match length {
        Some(length) => rv.set(v8::Integer::new(scope, length as i32).into()),
        None => throw_error_coded(
            scope,
            "ERR_CRYPTO_OPERATION_FAILED",
            "HMAC has been consumed and is no longer usable",
        ),
    }
}

/// The `CryptoHasher` getter-on-a-non-instance message, which carries no `code`.
fn throw_crypto_hasher_getter(scope: &mut v8::PinScope<'_, '_>, member: &str) {
    let Some(text) = v8::String::new(
        scope,
        &format!("The CryptoHasher.{member} getter can only be used on instances of CryptoHasher"),
    ) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// `CryptoHasher.prototype.update(input, encoding)`.
///
/// The second argument **is** honoured for strings here: `update("616263","hex")`
/// decodes to `abc`. That is measured, and it is the opposite of the per-class
/// behaviour, where the same call hashes the six characters.
fn crypto_hasher_update<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let this = args.this();
    if !has_state(this) {
        throw_invalid_this(scope, "CryptoHasher", this.into());
        return;
    }

    let input = args.get(0);
    let decoded = if input.is_string() || input.is_string_object() {
        let encoding = args.get(1);
        let name = encoding
            .is_string()
            .then(|| encoding.to_string(scope))
            .flatten()
            .map(|text| text.to_rust_string_lossy(scope));
        let Some(text) = input
            .to_string(scope)
            .map(|text| text.to_rust_string_lossy(scope))
        else {
            return;
        };
        match name.as_deref() {
            Some(name) => match decode_string(&text, name) {
                Ok(bytes) => Some(bytes),
                // An unknown encoding is silently ignored, so `update("abc","nope")`
                // hashes `abc` as UTF-8 rather than throwing.
                Err(DecodeError::Unknown) => Some(text.into_bytes()),
                Err(DecodeError::OddHex) => {
                    throw_type_coded(
                        scope,
                        "ERR_INVALID_ARG_VALUE",
                        &format!(
                            "The argument 'encoding' is invalid for data of length {}. Received '{name}'",
                            text.chars().count()
                        ),
                    );
                    return;
                }
            },
            None => Some(text.into_bytes()),
        }
    } else {
        bytes_of(scope, input)
    };

    let Some(bytes) = decoded else {
        throw_invalid_input(scope);
        return;
    };

    let outcome = with_state(this, |state| match state {
        State::Plain { digest, digested } => {
            // `CryptoHasher` re-arms after a digest rather than refusing, so an
            // update after `digest()` starts a fresh input.
            *digested = false;
            digest.update(&bytes).err()
        }
        State::Keyed { data, digested, .. } => {
            if *digested {
                data.clear();
                *digested = false;
            }
            data.extend_from_slice(&bytes);
            None
        }
    });
    match outcome {
        Some(Some(error)) => throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance),
        Some(None) => rv.set(this.into()),
        None => throw_invalid_this(scope, "CryptoHasher", this.into()),
    }
}

/// Why a string could not be decoded.
enum DecodeError {
    Unknown,
    /// Odd-length hex, which Bun rejects rather than dropping the nibble.
    OddHex,
}

/// Decodes `text` as `encoding` for `CryptoHasher.update`.
///
/// The accepted set is `Buffer`'s, wider than `digest`'s, because here a string
/// is being turned into bytes rather than bytes into a string.
fn decode_string(text: &str, encoding: &str) -> Result<Vec<u8>, DecodeError> {
    let lowered = encoding.to_ascii_lowercase();
    match lowered.as_str() {
        "utf8" | "utf-8" => Ok(text.as_bytes().to_vec()),
        "hex" => {
            let digits: Vec<u8> = text
                .bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();
            if !digits.len().is_multiple_of(2) {
                return Err(DecodeError::OddHex);
            }
            let mut out = Vec::with_capacity(digits.len() / 2);
            for pair in digits.chunks(2) {
                let high = hex_digit(pair[0]).ok_or(DecodeError::Unknown)?;
                let low = hex_digit(pair[1]).ok_or(DecodeError::Unknown)?;
                out.push((high << 4) | low);
            }
            Ok(out)
        }
        "base64" => base64_decode(text, false).ok_or(DecodeError::Unknown),
        "base64url" => base64_decode(text, true).ok_or(DecodeError::Unknown),
        "latin1" | "binary" => Ok(text.chars().map(|ch| ch as u32 as u8).collect()),
        "ucs2" | "ucs-2" | "utf16le" | "utf16-le" => {
            let mut out = Vec::with_capacity(text.len() * 2);
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            Ok(out)
        }
        "ascii" => Ok(text.chars().map(|ch| ch as u32 as u8 & 0x7f).collect()),
        _ => Err(DecodeError::Unknown),
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn base64_decode(text: &str, url_safe: bool) -> Option<Vec<u8>> {
    let mut digits = Vec::with_capacity(text.len());
    for byte in text.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' if !url_safe => 62,
            b'/' if !url_safe => 63,
            b'-' if url_safe => 62,
            b'_' if url_safe => 63,
            _ => return None,
        };
        digits.push(value);
    }
    if digits.len() % 4 == 1 {
        digits.truncate(digits.len() - 1);
    }
    let mut out = Vec::with_capacity(digits.len() * 3 / 4);
    for chunk in digits.chunks(4) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).copied().map(u32::from).unwrap_or(0);
        let third = chunk.get(2).copied().map(u32::from).unwrap_or(0);
        let fourth = chunk.get(3).copied().map(u32::from).unwrap_or(0);
        let combined = (first << 18) | (second << 12) | (third << 6) | fourth;
        out.push((combined >> 16) as u8);
        if chunk.len() > 2 {
            out.push((combined >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(combined as u8);
        }
    }
    Some(out)
}

/// `CryptoHasher.prototype.digest(output)`.
///
/// Three things differ from the per-class `digest`, all measured:
///
/// * an absent encoding yields a `Buffer`, not a `Uint8Array`;
/// * the minimum write-target length is 64 bytes for every algorithm, not the
///   digest's own length;
/// * a digest is **not** terminal: a second call hashes the empty input.
fn crypto_hasher_digest<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let this = args.this();
    if !has_state(this) {
        throw_invalid_this(scope, "CryptoHasher", this.into());
        return;
    }
    let Some(output) = output_of(scope, args.get(0)) else {
        return;
    };
    let outcome = with_state(this, |state| match state {
        State::Plain { digest, digested } => {
            let mut bytes = vec![0u8; digest.length()];
            match digest.finish_into(&mut bytes) {
                Ok(()) => {
                    *digested = true;
                    Ok(bytes)
                }
                Err(error) => Err(error),
            }
        }
        State::Keyed {
            algorithm,
            key,
            data,
            digested,
        } => match digest::hmac_once(algorithm.name, key, data) {
            Some(Ok(bytes)) => {
                *digested = true;
                Ok(bytes)
            }
            Some(Err(error)) => Err(error),
            None => Err(DigestError::UnknownAlgorithm(algorithm.name.to_string())),
        },
    });
    match outcome {
        Some(Ok(bytes)) => {
            if let Some(value) = emit_crypto_hasher(scope, output, &bytes) {
                rv.set(value);
            }
        }
        Some(Err(error)) => throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance),
        None => throw_invalid_this(scope, "CryptoHasher", this.into()),
    }
}

/// Emits a `CryptoHasher` digest, whose write-target floor is 64 bytes.
fn emit_crypto_hasher<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    output: Output<'s>,
    digest: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    match output {
        Output::Into(target) => {
            // Measured: `CryptoHasher` requires 64 bytes whatever the algorithm,
            // because its internal scratch buffer is `EVP_MAX_MD_SIZE`.
            let available = if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(target) {
                view.byte_length()
            } else if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(target) {
                buffer.byte_length()
            } else {
                0
            };
            if available < digest::MAX_DIGEST_LEN {
                throw_type_coded(
                    scope,
                    "ERR_INVALID_ARG_TYPE",
                    &format!(
                        "TypedArray must be at least {} bytes",
                        digest::MAX_DIGEST_LEN
                    ),
                );
                return None;
            }
            write_into_target(scope, target, digest)?;
            Some(target)
        }
        other => emit(scope, other, digest, true),
    }
}

/// `CryptoHasher.prototype.copy()`.
fn crypto_hasher_copy<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let this = args.this();
    if !has_state(this) {
        throw_invalid_this(scope, "CryptoHasher", this.into());
        return;
    }

    let copied = with_state(this, |state| match state {
        State::Plain { digest, .. } => digest.copy().map(|forked| State::Plain {
            digest: forked,
            digested: false,
        }),
        State::Keyed {
            algorithm,
            key,
            data,
            ..
        } => Ok(State::Keyed {
            algorithm,
            key: key.clone(),
            data: data.clone(),
            digested: false,
        }),
    });
    let Some(copied) = copied else {
        throw_invalid_this(scope, "CryptoHasher", this.into());
        return;
    };
    let state = match copied {
        Ok(state) => state,
        Err(error) => {
            throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance);
            return;
        }
    };

    // The copy is built from the instance template rather than by calling the
    // constructor: the constructor needs an algorithm name, and re-deriving one
    // from the state would mean a second lookup that could disagree with the
    // digest the copy actually carries. `InstanceTemplate::NewInstance` builds
    // an object whose prototype is the right one, which is all `instanceof`
    // needs.
    let template = match instance_template(scope) {
        Some(template) => template,
        None => {
            throw_error_coded(
                scope,
                "ERR_CRYPTO_OPERATION_FAILED",
                "cannot read the CryptoHasher instance template",
            );
            return;
        }
    };
    let Some(instance) = template.new_instance(scope) else {
        throw_error_coded(
            scope,
            "ERR_CRYPTO_OPERATION_FAILED",
            "cannot allocate the CryptoHasher copy",
        );
        return;
    };
    attach_state(scope, instance, state);
    rv.set(instance.into());
}

// The `CryptoHasher` instance template, stashed once per isolate.
//
// A `FunctionTemplate` cannot be recovered from an instantiated function, and
// `copy` needs one to build an object with the right prototype without running
// the constructor. So the template is stashed in a per-isolate slot the first
// time `install_crypto_hasher` runs.
thread_local! {
    static CRYPTO_HASHER_TEMPLATE: std::cell::RefCell<Option<v8::Global<v8::FunctionTemplate>>> =
        const { std::cell::RefCell::new(None) };
}

fn instance_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::ObjectTemplate>> {
    CRYPTO_HASHER_TEMPLATE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|template| v8::Local::new(scope, template).instance_template(scope))
    })
}

/// `CryptoHasher.hash(algorithm, input, output)` — the static one-shot.
fn crypto_hasher_hash<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let algorithm_value = args.get(0);
    if !algorithm_value.is_string() && !algorithm_value.is_string_object() {
        throw_type_coded(scope, "ERR_INVALID_ARG_TYPE", "algorithm must be a string");
        return;
    }
    let Some(name) = algorithm_value
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
    else {
        return;
    };
    // The input is validated before the algorithm name, which is measured:
    // `CryptoHasher.hash('bogus')` reports the *input* error, and
    // `CryptoHasher.hash('bogus', 'abc')` reports the algorithm one.
    let Some(input) = bytes_of(scope, args.get(1)) else {
        throw_invalid_input(scope);
        return;
    };
    // The static form's unknown-algorithm message *is* quoted, unlike the
    // instance form's.
    let Some(algorithm) = digest::resolve(&name) else {
        throw_digest_error(
            scope,
            &DigestError::UnknownAlgorithm(name),
            UnknownAlgorithmStyle::Static,
        );
        return;
    };
    let Some(output) = output_of(scope, args.get(2)) else {
        return;
    };
    let bytes = match Digest::new(algorithm).and_then(|mut digest| {
        digest.update(&input)?;
        digest.finish()
    }) {
        Ok(bytes) => bytes,
        Err(error) => {
            throw_digest_error(scope, &error, UnknownAlgorithmStyle::Instance);
            return;
        }
    };
    // The static form's absent-encoding result is a `Buffer`, like the instance
    // form's, and its write-target floor follows the `CryptoHasher` rule.
    if let Some(value) = emit_crypto_hasher(scope, output, &bytes) {
        rv.set(value);
    }
}
