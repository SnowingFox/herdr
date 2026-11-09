//! The remaining members: `atob`/`btoa`, the `ArrayBuffer` helpers, the buffer
//! prototype slot, and the two length constants.
//!
//! These are the ones with no `ArrayBufferView` in sight, so they each need a
//! different piece of V8:
//!
//! * `atob`/`btoa` run simdutf's base64 codec in *strict WHATWG* mode, which is
//!   not the forgiving mode `Buffer.from(s, 'base64')` uses. The difference is
//!   visible: `atob('a-_h')` throws, `Buffer.from('a-_h', 'base64')` does not.
//! * `setBufferPrototype` stores the prototype `node_buffer.cc` keeps on the
//!   `Realm`, so later `Buffer` construction can install it. rustnode has no
//!   Realm object, so the slot lives here.
//! * `createUnsafeArrayBuffer` allocates a backing store that is *not* zeroed,
//!   which is the whole point of the name.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::args;

// ---------------------------------------------------------------------------
// atob / btoa
// ---------------------------------------------------------------------------

/// The error codes `Atob` returns instead of throwing.
///
/// `lib/buffer.js` maps these onto the DOM exceptions the WHATWG spec names, so
/// the *numbers* are the contract, not the messages.
pub mod atob_error {
    /// A single character remained.
    pub const SINGLE_CHARACTER: i32 = -1;
    /// An invalid character.
    pub const INVALID_CHARACTER: i32 = -2;
    /// Any other simdutf failure.
    pub const UNRECOGNIZED: i32 = -3;
}

/// `btoa(input)`: base64-encode a string, one byte per code unit.
///
/// `Err(-1)` when a code unit is above `0xFF`, which `lib/buffer.js` turns into
/// `InvalidCharacterError`. The codec is simdutf's strict base64, so the output
/// is padded standard base64 — `btoa` never produces base64url.
pub(crate) fn btoa_result<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<v8::Local<'s, v8::String>, i32> {
    let Ok(string) = v8::Local::<v8::String>::try_from(value) else {
        return Err(atob_error::INVALID_CHARACTER);
    };
    let units = args::string_to_units(&string, scope);
    let mut bytes = Vec::with_capacity(units.len());
    for unit in units {
        if unit > 0xFF {
            return Err(atob_error::INVALID_CHARACTER);
        }
        bytes.push(unit as u8);
    }
    let encoded_len =
        v8::simdutf::base64_length_from_binary(bytes.len(), v8::simdutf::Base64Options::Default);
    let mut out = vec![0u8; encoded_len];
    // SAFETY: `out` has exactly the length simdutf reports as required for this
    // input and options.
    let written = unsafe {
        v8::simdutf::binary_to_base64(&bytes, &mut out, v8::simdutf::Base64Options::Default)
    };
    out.truncate(written);
    args::latin1_string(scope, &out).ok_or(atob_error::UNRECOGNIZED)
}

/// `atob(input)`: decode strict base64 to a one-byte string.
///
/// `Err` carries the negative code `lib/buffer.js` switches on. The decoder is
/// simdutf's `Loose` last-chunk mode with the *default* alphabet, which is what
/// makes the behaviour exactly WHATWG forgiving-base64: `+`/`/` only, `=` only
/// as trailing padding, ASCII whitespace ignored, and `\v`/`\f` rejected
/// because WHATWG's whitespace set excludes them.
pub(crate) fn atob_result<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<v8::Local<'s, v8::String>, i32> {
    let Ok(string) = v8::Local::<v8::String>::try_from(value) else {
        return Err(atob_error::INVALID_CHARACTER);
    };
    // `Atob` works on the string's bytes, so a two-byte input is first narrowed
    // to Latin-1 and rejected if it does not fit.
    let units = args::string_to_units(&string, scope);
    let mut input = Vec::with_capacity(units.len());
    for unit in units {
        if unit > 0xFF {
            return Err(atob_error::INVALID_CHARACTER);
        }
        input.push(unit as u8);
    }

    let mut out = vec![0u8; v8::simdutf::maximal_binary_length_from_base64(&input)];
    // SAFETY: `out` has the maximal length simdutf documents for this input.
    let result = unsafe {
        v8::simdutf::base64_to_binary(
            &input,
            &mut out,
            v8::simdutf::Base64Options::Default,
            v8::simdutf::LastChunkHandling::Loose,
        )
    };
    if !result.is_ok() {
        return Err(match result.error {
            v8::simdutf::ErrorCode::InvalidBase64Character => atob_error::INVALID_CHARACTER,
            v8::simdutf::ErrorCode::Base64InputRemainder => atob_error::SINGLE_CHARACTER,
            _ => atob_error::UNRECOGNIZED,
        });
    }
    out.truncate(result.count);
    args::latin1_string(scope, &out).ok_or(atob_error::UNRECOGNIZED)
}

// ---------------------------------------------------------------------------
// Buffer prototype
// ---------------------------------------------------------------------------

thread_local! {
    /// The prototype `setBufferPrototype` recorded.
    ///
    /// `node_buffer.cc` stores it on the `Realm`
    /// (`realm->set_buffer_prototype_object(proto)`), and `Buffer::New` reads it
    /// back with `env->buffer_prototype_object()` so a fresh `Uint8Array` can be
    /// given Buffer's methods. rustnode has no `Realm` object yet, so the slot
    /// is here; when `rn-core` grows one, this should move.
    static BUFFER_PROTOTYPE: RefCell<Option<v8::Global<v8::Object>>> = const { RefCell::new(None) };
}

/// The prototype `setBufferPrototype` installed, if any.
pub fn buffer_prototype<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    BUFFER_PROTOTYPE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|prototype| v8::Local::new(scope, prototype))
    })
}

/// `setBufferPrototype(proto)`.
pub(crate) fn set_buffer_prototype(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<bool> {
    let value = args.get(0);
    let Ok(prototype) = v8::Local::<v8::Object>::try_from(value) else {
        args::throw_type_error(scope, "The prototype must be an object");
        return None;
    };
    let global = v8::Global::new(scope, prototype);
    BUFFER_PROTOTYPE.with(|slot| {
        *slot.borrow_mut() = Some(global);
    });
    Some(true)
}

// ---------------------------------------------------------------------------
// ArrayBuffer helpers
// ---------------------------------------------------------------------------

/// `createUnsafeArrayBuffer(size)`: an ArrayBuffer whose contents are not
/// zeroed.
///
/// Node passes `BackingStoreInitializationMode::kUninitialized`, and the callers
/// overwrite every byte: `createUnsafeBuffer` builds a Buffer that is about to be
/// filled by `Buffer.from`, `allocUnsafe` hands it to user code that is expected
/// to fill it, and `createUnsafeAlignedBuffer` computes the padding itself.
/// Zero-filling would trade that speed for a guarantee nobody asked for.
///
/// The `size == 0` and "building a snapshot" cases fall back to a zeroed buffer
/// in Node; a zero-length backing store has nothing to leave uninitialised, so
/// the distinction only matters for the snapshot path, which rustnode does not
/// have yet.
pub(crate) fn create_unsafe_array_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
) -> Option<v8::Local<'s, v8::ArrayBuffer>> {
    if args.length() != 1 {
        args::throw_range_error(scope, "Invalid array buffer length");
        return None;
    }
    let Some(size) = args::number_to_size(scope, args.get(0)) else {
        args::throw_range_error(scope, "Invalid array buffer length");
        return None;
    };
    if size == 0 {
        return Some(v8::ArrayBuffer::new(scope, 0));
    }
    let store = v8::ArrayBuffer::new_backing_store(scope, size).make_shared();
    Some(v8::ArrayBuffer::with_backing_store(scope, &store))
}

/// `arrayBufferAlignedOffset(arrayBuffer, alignment)`.
///
/// Node reports how many bytes to skip so a view over the buffer starts at a
/// multiple of `alignment`, because V8 does not let an embedder choose where a
/// backing store lands. The C++ also returns `0` while building a snapshot, so a
/// serialized buffer does not bake in this process's allocation addresses.
///
/// This implementation computes the real offset from the backing store address,
/// which is what the non-snapshot path does. It is valid for exactly the reason
/// Node's is: a non-resizable ArrayBuffer's backing store never moves, so an
/// offset measured now stays aligned for the buffer's lifetime. `alignment` must
/// be a power of two; `lib/internal/buffer.js` validates that before calling.
pub(crate) fn array_buffer_aligned_offset(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<f64> {
    let Some(alignment) = args::number_to_size(scope, args.get(1)) else {
        args::throw_range_error(scope, "Invalid alignment");
        return None;
    };
    if alignment == 0 || !alignment.is_power_of_two() {
        args::throw_range_error(scope, "Invalid alignment");
        return None;
    }
    let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(args.get(0)) else {
        args::throw_type_error(scope, "The first argument must be an ArrayBuffer");
        return None;
    };
    let Some(data) = buffer.data() else {
        // A zero-length buffer has no address to align, and every offset into it
        // is trivially fine.
        return Some(0.0);
    };
    let start = data.as_ptr() as usize;
    let offset = (alignment - (start & (alignment - 1))) & (alignment - 1);
    Some(offset as f64)
}

/// `copyArrayBuffer(target, targetStart, source, sourceStart, bytesToCopy)`.
///
/// The web streams implementation uses this to move bytes between two
/// `ArrayBuffer`s; `CHECK_EQ(bytesCopied, bytesToCopy)` in the C++ means a short
/// copy is a fatal error there. Here a short copy simply reports the number of
/// bytes moved, and the JS `assert(canCopyArrayBuffer(...))` before each call
/// keeps the lengths in range.
pub(crate) fn copy_array_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<f64> {
    let Ok(target) = v8::Local::<v8::ArrayBuffer>::try_from(args.get(0)) else {
        args::throw_type_error(scope, "The destination must be an ArrayBuffer");
        return None;
    };
    let target_start = args.get(1).uint32_value(scope).unwrap_or(0) as usize;
    let Ok(source) = v8::Local::<v8::ArrayBuffer>::try_from(args.get(2)) else {
        args::throw_type_error(scope, "The source must be an ArrayBuffer");
        return None;
    };
    let source_start = args.get(3).uint32_value(scope).unwrap_or(0) as usize;
    let count = args.get(4).uint32_value(scope).unwrap_or(0) as usize;

    let target_length = target.byte_length();
    let source_length = source.byte_length();
    let count = count
        .min(source_length.saturating_sub(source_start))
        .min(target_length.saturating_sub(target_start));
    if count == 0 {
        return Some(0.0);
    }

    // Stage the source: the two buffers may be the same object, in which case a
    // direct copy would read bytes it had already overwritten.
    let Some(source_data) = source.data() else {
        return Some(0.0);
    };
    // SAFETY: the source ArrayBuffer holds `source_length` readable bytes at its
    // data pointer while it is reachable, which it is as an argument.
    let staged = unsafe {
        std::slice::from_raw_parts(source_data.as_ptr().cast::<u8>(), source_length)
            [source_start..source_start + count]
            .to_vec()
    };
    let Some(target_data) = target.data() else {
        return Some(0.0);
    };
    // SAFETY: the target ArrayBuffer holds `target_length` writable bytes at its
    // data pointer while it is reachable, and the staged copy is separate
    // storage, so there is no aliasing.
    unsafe {
        let destination =
            std::slice::from_raw_parts_mut(target_data.as_ptr().cast::<u8>(), target_length);
        destination[target_start..target_start + count].copy_from_slice(&staged);
    }
    Some(count as f64)
}

/// `setDetachKey(arrayBuffer, key)`.
///
/// Records the `[[ArrayBufferDetachKey]]` that `structuredClone` checks, so a
/// Buffer marked with
/// `markAsUntransferable`'s `kDetachKey` symbol cannot be transferred. V8 owns
/// the storage; this only forwards.
pub(crate) fn set_detach_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<bool> {
    let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(args.get(0)) else {
        args::throw_type_error(scope, "The first argument must be an ArrayBuffer");
        return None;
    };
    buffer.set_detach_key(args.get(1));
    Some(true)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `kMaxLength`, the largest Buffer Node will allocate.
///
/// `node_buffer.h` defines it as `v8::Uint8Array::kMaxLength`, and in this V8
/// that is `TypedArray::kMaxByteLength / sizeof(uint8_t)`, i.e. the underlying
/// `ArrayBuffer::kMaxByteLength`. On a 64-bit build without the V8 sandbox that
/// is `2^53 - 1`, which is what a real Node binary reports; with the sandbox it
/// is the sandbox's safe buffer size. Taking it from V8 rather than writing the
/// number out is what makes both correct.
pub fn max_length() -> usize {
    v8::TypedArray::MAX_BYTE_LENGTH
}

/// `kStringMaxLength`, `v8::String::kMaxLength`.
pub fn string_max_length() -> usize {
    v8::String::MAX_LENGTH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_length_matches_what_node_reports() {
        // A real Node 22 on x86_64 reports 9007199254740991 = 2^53 - 1 for both
        // `binding.kMaxLength` and `buffer.constants.MAX_LENGTH`, and that is
        // `ArrayBuffer::kMaxByteLength` on a non-sandboxed 64-bit build.
        if usize::BITS == 64 && max_length() > u32::MAX as usize {
            assert_eq!(max_length(), (1usize << 53) - 1);
        }
    }

    #[test]
    fn string_max_length_is_a_sane_positive_value() {
        assert!(string_max_length() > 0);
        assert!(string_max_length() < usize::MAX);
    }

    #[test]
    fn atob_error_codes_are_what_buffer_js_switches_on() {
        // lib/buffer.js: case -2 -> Invalid character, case -1 -> single
        // character remained, case -3 -> unrecognized simdutf error.
        assert_eq!(atob_error::SINGLE_CHARACTER, -1);
        assert_eq!(atob_error::INVALID_CHARACTER, -2);
        assert_eq!(atob_error::UNRECOGNIZED, -3);
    }
}
