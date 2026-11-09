//! `internalBinding('string_decoder')` for rustnode.
//!
//! The JavaScript in `vendor/libnode-js/lib/string_decoder.js` is unchanged
//! Node code. It allocates the decoder's entire native state itself:
//!
//! ```js
//! this[kNativeDecoder] = Buffer.alloc(kSize);   // 7 bytes
//! this[kNativeDecoder][kEncodingField] = encodingsMap[this.encoding];
//! ```
//!
//! So this namespace exposes no handle and owns no registry: `decode` and
//! `flush` are plain functions that read and write the caller's byte buffer
//! through the `k*Field` offsets. That is also why the constants below must
//! match `StringDecoder::Fields` in `src/string_decoder.h` exactly — the
//! JavaScript indexes the buffer with them directly.
//!
//! # Field layout
//!
//! ```text
//! byte 0  1  2  3  4  5  6
//!      [ incomplete ][M][B][E]
//! ```
//!
//! * `kIncompleteCharactersStart..kIncompleteCharactersEnd` (0..4) is the
//!   retained tail of a split character. Four bytes is the widest it can get:
//!   three bytes of a four-byte UTF-8 character that were seen and still need
//!   one, or two UTF-16LE bytes plus the two that complete a surrogate pair.
//! * `kMissingBytes` (4) is how many bytes the retained character still needs.
//! * `kBufferedBytes` (5) is how many bytes are already in the incomplete
//!   buffer.
//! * `kEncodingField` (6) is the `encodings` index, i.e. Node's `enum encoding`.
//!
//! Both counters are `u8`, so the whole state is `kNumFields == kSize == 7`
//! bytes and the JavaScript's `Buffer.alloc(kSize)` is exactly one state.
//!
//! # Where the work happens
//!
//! * [`state`] is Node's `StringDecoder` struct and `DecodeData`/`FlushData`:
//!   what to emit, and what to retain. It is pure and tested without an
//!   isolate.
//! * [`encode`] is `StringBytes::Encode`: turning those bytes into a V8 string.
//!
//! Splitting them this way keeps the retention logic — the entire point of the
//! class — testable directly, while leaving replacement-character placement to
//! V8, which is where Node gets it from too.

pub mod encode;
pub mod state;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::state::{State, FIELD_COUNT, SIZE};

/// Members exposed on the namespace object, matching
/// `contracts/string_decoder.json` and `InitializeStringDecoder`.
///
/// `kSize` and `kNumFields` are the same number (7) but Node records them as
/// separate members because they answer different questions: `kNumFields` is
/// the field count and `kSize` is `sizeof(StringDecoder)`. Both belong in the
/// list because the contract requires them.
pub const MEMBERS: &[&str] = &[
    "decode",
    "encodings",
    "flush",
    "kBufferedBytes",
    "kEncodingField",
    "kIncompleteCharactersEnd",
    "kIncompleteCharactersStart",
    "kMissingBytes",
    "kNumFields",
    "kSize",
];

/// The `encodings` array, in `enum encoding` order.
///
/// `lib/internal/util.js` builds `encodingsMap` by iterating this array, so an
/// entry's position *is* the value the JS stores into `kEncodingField`. The
/// order comes from Node's `enum encoding`, not from `normalizeEncoding`:
/// `buffer` sits between `hex` and `base64url`, and `latin1` between `utf16le`
/// and `hex`, because `BINARY` is an alias of `LATIN1` and never appears.
pub const ENCODINGS: &[&str] = &[
    "ascii",
    "utf8",
    "base64",
    "utf16le",
    "latin1",
    "hex",
    "buffer",
    "base64url",
];

/// The `string_decoder` namespace.
pub struct StringDecoder;

impl BindingModule for StringDecoder {
    fn namespace(&self) -> &'static str {
        "string_decoder"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        // Every value is built before any `set` call. `set` takes `scope`
        // mutably, so building a value inside its argument would need two
        // simultaneous `&mut` borrows of the same scope.
        let encodings = encoding_names(scope)?;
        let decode_fn = function(scope, "decode", decode)?;
        let flush_fn = function(scope, "flush", flush)?;
        let constants: [(&str, i32); 7] = [
            ("kIncompleteCharactersStart", state::INCOMPLETE_START),
            ("kIncompleteCharactersEnd", state::INCOMPLETE_END),
            ("kMissingBytes", state::MISSING_BYTES),
            ("kBufferedBytes", state::BUFFERED_BYTES),
            ("kEncodingField", state::ENCODING_FIELD),
            ("kNumFields", FIELD_COUNT as i32),
            ("kSize", SIZE as i32),
        ];
        let integers: Vec<v8::Local<'s, v8::Integer>> = constants
            .iter()
            .map(|(_, value)| v8::Integer::new(scope, *value))
            .collect();

        let mut values: Vec<(&str, v8::Local<'s, v8::Value>)> = vec![
            ("decode", decode_fn),
            ("encodings", encodings.into()),
            ("flush", flush_fn),
        ];
        for ((name, _), integer) in constants.iter().zip(integers) {
            values.push((name, integer.into()));
        }

        let mut keys = Vec::with_capacity(values.len());
        for (name, _) in &values {
            let Some(key) = v8::String::new(scope, name) else {
                return Err(format!("cannot allocate string_decoder member {name}"));
            };
            keys.push(key);
        }
        for ((name, value), key) in values.into_iter().zip(keys) {
            if object.set(scope, key.into(), value) != Some(true) {
                return Err(format!("cannot install string_decoder member {name}"));
            }
        }
        Ok(object)
    }
}

/// Builds `encodings` as a real JavaScript array of the encoding names.
///
/// Node fills it with `Array::New` + `Set(index, name)`, so `.length` is 8 and
/// numeric properties are the names; the recorded contract says the same.
fn encoding_names<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Array>, String> {
    let array = v8::Array::new(scope, ENCODINGS.len() as i32);
    let mut names = Vec::with_capacity(ENCODINGS.len());
    for name in ENCODINGS {
        let Some(value) = v8::String::new(scope, name) else {
            return Err(format!("cannot allocate encoding name {name}"));
        };
        names.push((value, *name));
    }
    for (index, (value, name)) in names.into_iter().enumerate() {
        if array.set_index(scope, index as u32, value.into()) != Some(true) {
            return Err(format!("cannot store encoding name {name}"));
        }
    }
    Ok(array)
}

/// Builds a `v8::Function` from a plain callback.
///
/// Closures cannot be used here: V8's callback-data slot is statically sized, so
/// a capturing closure would overrun it. Every callback in this crate is a plain
/// `fn`.
fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate string_decoder function {name}"))?;
    Ok(function.into())
}

/// Reads the caller's `kSize`-byte state buffer without copying it.
///
/// The buffer is `Buffer.alloc(kSize)`, i.e. a `Uint8Array` covering a whole
/// `ArrayBuffer`, so `data()` is the start of the state. Node uses
/// `Buffer::Data`, which ignores a view's byte offset; `ArrayBufferView::data`
/// adds it, which is the same thing for the shape the JavaScript passes and
/// more correct for a subarray.
///
/// A buffer shorter than `kSize` is refused: `decode` would otherwise read past
/// the end of the view.
fn state_pointer(value: v8::Local<v8::Value>) -> Option<*mut u8> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    if view.byte_length() < SIZE {
        return None;
    }
    let data = view.data().cast::<u8>();
    if data.is_null() {
        return None;
    }
    Some(data)
}

/// Borrows the state buffer as a [`State`] for the duration of one callback.
///
/// # Safety
///
/// `pointer` must come from [`state_pointer`], so it covers at least `SIZE`
/// bytes of a view that stays reachable for the whole call. The caller must not
/// hold any other reference into those bytes while the returned borrow lives.
unsafe fn state_from<'scope, 'a>(pointer: *mut u8) -> &'a mut State
where
    'scope: 'a,
{
    // SAFETY: delegated to the caller. `State` is `#[repr(C)]` with `u8` fields
    // only, so it is valid for any byte contents, and it is exactly `SIZE`
    // bytes, which `state_pointer` proved the view holds.
    unsafe { &mut *pointer.cast::<State>() }
}

/// `decode(state, chunk)`.
///
/// Returns the decoded string, retaining any incomplete trailing character in
/// `state` for the next call.
fn decode<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(pointer) = state_pointer(args.get(0)) else {
        throw_type_error(
            scope,
            "The string_decoder state must be a Uint8Array of at least kSize bytes",
        );
        return;
    };
    let Some(chunk) = chunk_bytes(args.get(1)) else {
        throw_type_error(scope, "The chunk must be a Buffer, TypedArray or DataView");
        return;
    };
    // SAFETY: `state_pointer` proved the argument view covers `SIZE` bytes and
    // it stays reachable for this call; nothing else borrows it here.
    let state = unsafe { state_from(pointer) };

    let Some(decoded) = state.decode(&chunk) else {
        throw_type_error(scope, "Unknown string_decoder encoding");
        return;
    };

    // The prepend is a completed character from the previous chunk and the body
    // is this chunk's own bytes, so they are decoded separately and joined — the
    // same two-step `DecodeData` performs.
    let body = &chunk[decoded.body];
    let mut parts: Vec<v8::Local<'s, v8::String>> = Vec::with_capacity(2);
    for bytes in [&decoded.prepend[..], body] {
        if bytes.is_empty() {
            continue;
        }
        match encode::to_v8_string(scope, decoded.encoding, bytes) {
            Ok(text) => parts.push(text),
            Err(_) => {
                throw_string_too_long(scope);
                return;
            }
        }
    }

    match parts.as_slice() {
        [] => rv.set_empty_string(),
        [only] => rv.set((*only).into()),
        [left, right] => match v8::String::concat(scope, *left, *right) {
            Some(joined) => rv.set(joined.into()),
            None => throw_string_too_long(scope),
        },
        _ => rv.set_empty_string(),
    }
}

/// `flush(state)`.
///
/// Emits whatever `decode` retained, then clears the state so the decoder can be
/// reused. `lib/string_decoder.js` only calls this when `kBufferedBytes > 0`,
/// but Node's `FlushData` is safe to call either way and returns the empty
/// string, so this does the same.
fn flush<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(pointer) = state_pointer(args.get(0)) else {
        throw_type_error(
            scope,
            "The string_decoder state must be a Uint8Array of at least kSize bytes",
        );
        return;
    };
    // SAFETY: as in `decode`.
    let state = unsafe { state_from(pointer) };

    let Some(flushed) = state.flush() else {
        throw_type_error(scope, "Unknown string_decoder encoding");
        return;
    };
    if flushed.bytes.is_empty() {
        rv.set_empty_string();
        return;
    }
    match encode::to_v8_string(scope, flushed.encoding, &flushed.bytes) {
        Ok(text) => rv.set(text.into()),
        Err(_) => throw_string_too_long(scope),
    }
}

/// Copies the chunk out of JavaScript memory.
///
/// Node reads the view in place through `ArrayBufferViewContents`. Copying up
/// front means the decoder never holds a borrow across the V8 allocation that
/// building the result string performs.
fn chunk_bytes(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let mut buffer = vec![0u8; view.byte_length()];
    let written = view.copy_contents(&mut buffer);
    buffer.truncate(written);
    Some(buffer)
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let text = v8::String::new(scope, message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// Throws the `Error` Node raises when input is longer than a V8 string can
/// hold, carrying its `ERR_STRING_TOO_LONG` code.
///
/// `MakeString` throws this rather than a `TypeError`, and `lib/internal/errors.js`
/// and user code both match on the code, so the property is what matters. The
/// message text follows `node_errors.h`.
fn throw_string_too_long(scope: &mut v8::PinScope<'_, '_>) {
    throw_errored(scope, "code", "ERR_STRING_TOO_LONG");
}

/// Throws an `Error` with one property set, e.g. a Node error `code`.
///
/// `lib/internal/errors.js` branches on `err.code`, so the string matters more
/// than the class. The message is the one `node_errors.h` formats for
/// `ERR_STRING_TOO_LONG`.
fn throw_errored(scope: &mut v8::PinScope<'_, '_>, property: &str, value: &str) {
    let message = format!(
        "Cannot create a string longer than 0x{:x} characters",
        v8::String::MAX_LENGTH
    );
    let text = v8::String::new(scope, &message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        let key = v8::String::new(scope, property);
        let stored = v8::String::new(scope, value);
        if let (Some(key), Some(stored)) = (key, stored) {
            object.set(scope, key.into(), stored.into());
        }
    }
    scope.throw_exception(exception);
}

/// Registers the `string_decoder` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(StringDecoder);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Encoding;

    /// Maps an index in [`ENCODINGS`] back to its variant.
    ///
    /// `Encoding::from_field` maps the stored byte to a variant, and
    /// `lib/internal/util.js` derives that byte from [`ENCODINGS`], so the
    /// array's order and the discriminants have to agree. The test below pins
    /// that, and this helper is the check.
    fn encoding_at(index: usize) -> Option<Encoding> {
        Encoding::from_field(index as u8)
    }

    #[test]
    fn namespace_and_members_match_the_contract() {
        let binding = StringDecoder;
        assert_eq!(binding.namespace(), "string_decoder");
        assert_eq!(
            binding.members(),
            &[
                "decode",
                "encodings",
                "flush",
                "kBufferedBytes",
                "kEncodingField",
                "kIncompleteCharactersEnd",
                "kIncompleteCharactersStart",
                "kMissingBytes",
                "kNumFields",
                "kSize",
            ]
        );
        assert!(binding.deferred().is_empty(), "nothing is deferred");
    }

    #[test]
    fn constants_match_node() {
        // Recorded from `internalBinding('string_decoder')` in Node 22.
        assert_eq!(state::INCOMPLETE_START, 0);
        assert_eq!(state::INCOMPLETE_END, 4);
        assert_eq!(state::MISSING_BYTES, 4);
        assert_eq!(state::BUFFERED_BYTES, 5);
        assert_eq!(state::ENCODING_FIELD, 6);
        assert_eq!(FIELD_COUNT, 7);
        assert_eq!(SIZE, 7);
    }

    #[test]
    fn encodings_are_in_enum_encoding_order() {
        // The index in this array is what the JS writes into `kEncodingField`,
        // so the position of every entry is load-bearing.
        assert_eq!(ENCODINGS[Encoding::Ascii as usize], "ascii");
        assert_eq!(ENCODINGS[Encoding::Utf8 as usize], "utf8");
        assert_eq!(ENCODINGS[Encoding::Base64 as usize], "base64");
        assert_eq!(ENCODINGS[Encoding::Ucs2 as usize], "utf16le");
        assert_eq!(ENCODINGS[Encoding::Latin1 as usize], "latin1");
        assert_eq!(ENCODINGS[Encoding::Hex as usize], "hex");
        assert_eq!(ENCODINGS[Encoding::Buffer as usize], "buffer");
        assert_eq!(ENCODINGS[Encoding::Base64Url as usize], "base64url");
        assert_eq!(ENCODINGS.len(), 8, "encodings.length is recorded as 8");
    }

    #[test]
    fn every_encoding_index_round_trips() {
        for (index, name) in ENCODINGS.iter().enumerate() {
            let encoding = encoding_at(index).unwrap_or_else(|| panic!("{name} maps"));
            assert_eq!(encoding.field() as usize, index);
        }
        assert_eq!(
            encoding_at(ENCODINGS.len()),
            None,
            "past the end is invalid"
        );
    }
}
