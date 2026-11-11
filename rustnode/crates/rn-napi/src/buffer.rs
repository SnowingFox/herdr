//! `napi_create_arraybuffer`, the `Buffer` surface, and typed arrays.
//!
//! Two families live here and they are different in kind:
//!
//! * **Owned** buffers — `napi_create_arraybuffer`, `napi_create_buffer`,
//!   `napi_create_buffer_copy`. The runtime allocates the memory and V8 frees it
//!   when the buffer is collected. Nothing to get wrong beyond the copy.
//! * **External** buffers — `napi_create_external_buffer`,
//!   `napi_create_external_arraybuffer`. The addon owns the memory and passes a
//!   finalizer. The lifetime has to be V8's, not ours: the backing store is built
//!   with `new_backing_store_from_ptr` and a deleter, so V8 calls the addon's
//!   finalizer exactly when the buffer becomes unreachable, or at isolate
//!   shutdown. Freeing it any earlier is a use-after-free the addon cannot see
//!   until GC timing changes.
//!
//! # The trap this module avoids
//!
//! Externalization is the place where relying on "V8 zeroes internal fields"
//! would be fatal: a buffer's backing store outlives the `napi_value` handle, so
//! any scheme that reads its pointer out of an internal field would read a stale
//! slot once V8 moved the object. The pointer here travels in the backing store
//! and in the deleter's own `deleter_data`, both of which V8 owns for exactly as
//! long as the memory is live. No internal field is involved, so the question of
//! whether V8 zeroes them never arises.

use std::ffi::c_void;

use rn_v8_sys::v8;

use crate::abi::{NapiEnv, NapiFinalize, NapiTypedarrayType};

/// What an external buffer's deleter needs to call the addon's finalizer.
///
/// Boxed and handed to V8 as `deleter_data`, so V8 frees it after calling the
/// deleter. The `env` is the environment the buffer was created against; it is
/// leaked by `load`, so it outlives any buffer.
struct ExternalBuffer {
    env: *mut NapiEnv,
    data: *mut c_void,
    finalize: NapiFinalize,
    finalize_hint: *mut c_void,
}

/// The deleter V8 calls when an external buffer becomes unreachable.
///
/// # Threading
///
/// V8 may call this from a GC thread, which is not the isolate's thread. The
/// addon's finalizer therefore cannot run here — it may call `napi_throw_error`
/// or create values, and both need a scope on the isolate's thread. It is
/// deferred through [`crate::finalizer`], the same way Node parks it on
/// `pending_finalizers` and drains from `SetImmediate`.
///
/// # Safety
///
/// Called by V8 with the `deleter_data` given to `new_backing_store_from_ptr`.
unsafe extern "C" fn drop_external_buffer(
    _data: *mut c_void,
    _length: usize,
    deleter_data: *mut c_void,
) {
    if deleter_data.is_null() {
        return;
    }
    // SAFETY: `deleter_data` is the `Box<ExternalBuffer>` created in
    // `external_backing_store`, and V8 calls the deleter exactly once.
    let buffer = unsafe { Box::from_raw(deleter_data as *mut ExternalBuffer) };
    if let Some(finalize) = buffer.finalize {
        let env = buffer.env as usize;
        let data = buffer.data as usize;
        let hint = buffer.finalize_hint as usize;
        // The closure is `Send` because it captures only addresses, and it runs
        // on the loop's thread where a scope exists.
        let queued = rn_core::finalizer::enqueue(move |scope| {
            let guard = crate::scope::ScopeGuard::enter(scope);
            // SAFETY: the addon's own callback with the pointers it supplied. The
            // addon owns `data` and is being told to release it now.
            unsafe {
                finalize(
                    env as *mut NapiEnv,
                    data as *mut c_void,
                    hint as *mut c_void,
                )
            };
            drop(guard);
        });
        if !queued {
            tracing::error!(
                "an external buffer's finalizer could not be queued; \
                 the addon's release callback will not run"
            );
        }
    }
    // The addon's `data` is the addon's to free, and it has just been told to.
    drop(buffer);
}

/// Builds a backing store over memory the addon owns.
///
/// # Safety
///
/// `data` must point at `length` readable bytes that stay valid until the
/// finalizer runs. `env` must be a live environment.
pub(crate) unsafe fn external_backing_store(
    env: *mut NapiEnv,
    data: *mut c_void,
    length: usize,
    finalize: NapiFinalize,
    finalize_hint: *mut c_void,
) -> v8::UniqueRef<v8::BackingStore> {
    let buffer = Box::new(ExternalBuffer {
        env,
        data,
        finalize,
        finalize_hint,
    });
    // SAFETY: the caller guarantees `data` is valid for `length` and outlives the
    // finalizer. V8 takes ownership of the deleter data and calls the deleter once.
    unsafe {
        v8::ArrayBuffer::new_backing_store_from_ptr(
            data,
            length,
            drop_external_buffer,
            Box::into_raw(buffer).cast(),
        )
    }
}

/// The element kind a typed array is requested as.
///
/// `napi_typedarray_type` is a C enum, so the shim receives it as an integer and
/// this turns it back into something exhaustive. `None` means the addon passed a
/// value this build has no name for, which the shim reports as `napi_invalid_arg`.
pub(crate) fn typed_array_kind(raw: i32) -> Option<NapiTypedarrayType> {
    Some(match raw {
        0 => NapiTypedarrayType::Int8,
        1 => NapiTypedarrayType::Uint8,
        2 => NapiTypedarrayType::Uint8Clamped,
        3 => NapiTypedarrayType::Int16,
        4 => NapiTypedarrayType::Uint16,
        5 => NapiTypedarrayType::Int32,
        6 => NapiTypedarrayType::Uint32,
        7 => NapiTypedarrayType::Float32,
        8 => NapiTypedarrayType::Float64,
        9 => NapiTypedarrayType::BigInt64,
        10 => NapiTypedarrayType::BigUint64,
        11 => NapiTypedarrayType::Float16,
        _ => return None,
    })
}

/// The size in bytes of one element of `kind`.
pub(crate) fn element_size(kind: NapiTypedarrayType) -> usize {
    match kind {
        NapiTypedarrayType::Int8 | NapiTypedarrayType::Uint8 | NapiTypedarrayType::Uint8Clamped => {
            1
        }
        NapiTypedarrayType::Int16 | NapiTypedarrayType::Uint16 | NapiTypedarrayType::Float16 => 2,
        NapiTypedarrayType::Int32 | NapiTypedarrayType::Uint32 | NapiTypedarrayType::Float32 => 4,
        NapiTypedarrayType::Float64
        | NapiTypedarrayType::BigInt64
        | NapiTypedarrayType::BigUint64 => 8,
    }
}

/// Creates the V8 typed array `kind` over `buffer`.
///
/// # Safety
///
/// `buffer` must be a live `ArrayBuffer` from `scope`, and
/// `byte_offset + length * element_size` must be within it (the caller checks).
pub(crate) fn new_typed_array<'s>(
    scope: &v8::PinScope<'s, '_>,
    kind: NapiTypedarrayType,
    buffer: v8::Local<'s, v8::ArrayBuffer>,
    byte_offset: usize,
    length: usize,
) -> Option<v8::Local<'s, v8::Value>> {
    Some(match kind {
        NapiTypedarrayType::Int8 => v8::Int8Array::new(scope, buffer, byte_offset, length)?.into(),
        NapiTypedarrayType::Uint8 => {
            v8::Uint8Array::new(scope, buffer, byte_offset, length)?.into()
        }
        // V8 has no clamped-array constructor; it is reached through the typed
        // array's own API, so an addon asking for one gets the closest exact type
        // rather than a silently different element size.
        NapiTypedarrayType::Uint8Clamped => {
            v8::Uint8ClampedArray::new(scope, buffer, byte_offset, length)?.into()
        }
        NapiTypedarrayType::Int16 => {
            v8::Int16Array::new(scope, buffer, byte_offset, length)?.into()
        }
        NapiTypedarrayType::Uint16 => {
            v8::Uint16Array::new(scope, buffer, byte_offset, length)?.into()
        }
        NapiTypedarrayType::Int32 => {
            v8::Int32Array::new(scope, buffer, byte_offset, length)?.into()
        }
        NapiTypedarrayType::Uint32 => {
            v8::Uint32Array::new(scope, buffer, byte_offset, length)?.into()
        }
        NapiTypedarrayType::Float32 => {
            v8::Float32Array::new(scope, buffer, byte_offset, length)?.into()
        }
        NapiTypedarrayType::Float64 => {
            v8::Float64Array::new(scope, buffer, byte_offset, length)?.into()
        }
        NapiTypedarrayType::BigInt64 => {
            v8::BigInt64Array::new(scope, buffer, byte_offset, length)?.into()
        }
        NapiTypedarrayType::BigUint64 => {
            v8::BigUint64Array::new(scope, buffer, byte_offset, length)?.into()
        }
        // This rusty_v8 build has `Float16Array` as a type but no conversion from
        // it to `v8::Value`, so a `napi_value` cannot name one. Returning `None`
        // makes the shim report `napi_generic_failure`, which is honest: the addon
        // learns the kind is unsupported instead of getting a wrong-sized array.
        NapiTypedarrayType::Float16 => return None,
    })
}

/// The `napi_typedarray_type` a V8 typed array reports.
///
/// The inverse of [`typed_array_kind`], used by `napi_get_typedarray_info`.
pub(crate) fn kind_of(array: &v8::Local<'_, v8::ArrayBufferView>) -> Option<NapiTypedarrayType> {
    if array.is_int8_array() {
        Some(NapiTypedarrayType::Int8)
    } else if array.is_uint8_array() {
        Some(NapiTypedarrayType::Uint8)
    } else if array.is_uint8_clamped_array() {
        Some(NapiTypedarrayType::Uint8Clamped)
    } else if array.is_int16_array() {
        Some(NapiTypedarrayType::Int16)
    } else if array.is_uint16_array() {
        Some(NapiTypedarrayType::Uint16)
    } else if array.is_int32_array() {
        Some(NapiTypedarrayType::Int32)
    } else if array.is_uint32_array() {
        Some(NapiTypedarrayType::Uint32)
    } else if array.is_float32_array() {
        Some(NapiTypedarrayType::Float32)
    } else if array.is_float64_array() {
        Some(NapiTypedarrayType::Float64)
    } else if array.is_big_int64_array() {
        Some(NapiTypedarrayType::BigInt64)
    } else if array.is_big_uint64_array() {
        Some(NapiTypedarrayType::BigUint64)
    } else if array.is_float16_array() {
        Some(NapiTypedarrayType::Float16)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_typed_array_kind_round_trips_through_its_discriminant() {
        // An addon passes the C enum by value, so the mapping is ABI. A wrong
        // entry makes an addon allocate one element size and read another.
        for raw in 0..=11 {
            let kind = typed_array_kind(raw).expect("every declared kind is named");
            assert_eq!(kind as i32, raw, "discriminant must round trip");
        }
        assert!(
            typed_array_kind(12).is_none(),
            "an unknown kind is rejected"
        );
        assert!(typed_array_kind(-1).is_none());
    }

    #[test]
    fn the_element_sizes_match_the_typed_arrays_they_describe() {
        // `napi_create_typedarray` computes byte length from this, so a wrong size
        // silently allocates the wrong amount of memory.
        for (kind, expected) in [
            (NapiTypedarrayType::Int8, 1),
            (NapiTypedarrayType::Uint8, 1),
            (NapiTypedarrayType::Uint8Clamped, 1),
            (NapiTypedarrayType::Int16, 2),
            (NapiTypedarrayType::Uint16, 2),
            (NapiTypedarrayType::Float16, 2),
            (NapiTypedarrayType::Int32, 4),
            (NapiTypedarrayType::Uint32, 4),
            (NapiTypedarrayType::Float32, 4),
            (NapiTypedarrayType::Float64, 8),
            (NapiTypedarrayType::BigInt64, 8),
            (NapiTypedarrayType::BigUint64, 8),
        ] {
            assert_eq!(element_size(kind), expected, "{kind:?}");
        }
    }
}
