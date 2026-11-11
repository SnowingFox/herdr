//! The `NativeKeyObject` base class, and the three queries over it.
//!
//! `lib/internal/crypto/keys.js` builds every `KeyObject` class itself, but it
//! cannot build the *base* one: the C++ class is what owns the key material and
//! what `isKeyObject` brands. So the shape is a callback:
//!
//! ```js
//! const { 0: KeyObject, 1: SecretKeyObject, 2: PublicKeyObject, 3: PrivateKeyObject } =
//!   createNativeKeyObjectClass((NativeKeyObject) => {
//!     class KeyObject extends NativeKeyObject { … }
//!     return [KeyObject, SecretKeyObject, PublicKeyObject, PrivateKeyObject];
//!   });
//! ```
//!
//! This module supplies `NativeKeyObject`, receives the array, and keeps the four
//! constructors. They have to be kept because the *native* side constructs keys
//! too — `generateKeyPairSync` with no encoding, and `getKeyObjectSlots` — and
//! those paths have no access to the JavaScript closure.
//!
//! # Why `createNativeKeyObjectClass` is not a no-op
//!
//! A plausible shortcut is to return the callback's array unchanged and let
//! JavaScript own everything. That fails `test-crypto-keyobject-brand-check.js`,
//! which sets a plain object's prototype to `KeyObject.prototype` and asserts
//! `util.types.isKeyObject(spoofed) === false`. The distinguishing fact has to be
//! native state on a real instance, so the base constructor stores one internal
//! field holding the key, and `isKeyObject` tests that field's presence.
//!
//! # Why the handle is copied into the key
//!
//! `NativeKeyObject::New` does `new NativeKeyObject(env, args.This(),
//! handle->Data())` — it *copies* the `KeyObjectData` out of the handle rather
//! than pointing at it. `KeyObjectData` is reference counted, so that is cheap and
//! it means the `KeyObject` stays valid after the handle is collected.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::state::KeyData;

/// The internal field every native key object carries.
///
/// `BaseObject::kInternalFieldCount` is 1 for `KeyObjectHandle` and
/// `NativeKeyObject` alike: the field is the `KeyObjectData`.
pub(crate) const KEY_DATA_FIELD: i32 = 0;

/// The internal field holding a boolean marker meaning "field 0 holds a key".
///
/// Two fields rather than one because V8 does not guarantee that internal fields
/// start zeroed, and reading an uninitialised aligned-pointer field is undefined
/// behaviour — it panicked on a misaligned address here. The marker is a plain
/// internal field written with `set_internal_field`, which stores a `Value` and is
/// well defined to read as `undefined` before anything writes it.
pub(crate) const KEY_PRESENT_FIELD: i32 = 1;

/// The internal field count both native key classes reserve.
pub(crate) const INTERNAL_FIELD_COUNT: usize = KEY_PRESENT_FIELD as usize + 1;

/// Stores `data` on `object`, replacing whatever was there.
///
/// `KeyObjectHandle::init` assigns to `data_` on an object that already exists,
/// which is how `keys.js` uses it: `new KeyObjectHandle()` then
/// `handle.init(type, ...)`. The finalizer is installed once, on the first store,
/// and later stores reuse the same box — a second finalizer would double-free.
///
/// # Why there are two fields
///
/// V8 does **not** guarantee that internal fields start zeroed, and reading an
/// uninitialised aligned-pointer field is undefined behaviour: here it aborted the
/// process with a misaligned-address panic. So field 0 holds the pointer only once
/// field 1 says it does, and field 1 is written with `set_internal_field` — a plain
/// `Value` slot, well defined to read as `undefined` before anything writes it.
pub(crate) fn set_key_data(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    data: KeyData,
) {
    if let Some(pointer) = key_pointer(scope, object) {
        // SAFETY: `key_pointer` returned this only because the marker is set, so
        // field 0 holds the box this function created.
        let cell = unsafe { &*pointer };
        if let Ok(mut cell) = cell.try_borrow_mut() {
            *cell = data;
        }
        return;
    }

    let pointer = Box::into_raw(Box::new(RefCell::new(data)));
    object.set_aligned_pointer_in_internal_field(
        KEY_DATA_FIELD,
        pointer.cast::<std::ffi::c_void>().cast_const(),
        0,
    );
    // The marker goes in *after* the pointer, so a reader that sees the marker
    // always sees a pointer that was already written.
    let marker = v8::Boolean::new(scope, true);
    object.set_internal_field(KEY_PRESENT_FIELD as usize, marker.into());
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut RefCell<KeyData>;
            // SAFETY: allocated just above for this object alone, and this
            // finalizer is the only thing that frees it.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
}

/// The key box a native key object holds, or `None` when it has none.
///
/// Safe in the sense that matters: it reads an aligned-pointer field only when
/// [`KEY_PRESENT_FIELD`] says this function wrote it, so an object that was never
/// given a key — including one from JavaScript with no internal fields at all —
/// cannot make it read uninitialised memory.
fn key_pointer(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
) -> Option<*mut RefCell<KeyData>> {
    if object.internal_field_count() <= KEY_PRESENT_FIELD as usize {
        return None;
    }
    // `get_internal_field` hands back the field as `Data`; `Local<Value>` is
    // constructible from any `Data` through the typed `try_from`, which is the
    // supported direction of that conversion.
    let Some(marker) = object.get_internal_field(scope, KEY_PRESENT_FIELD as usize) else {
        // A field index past the count is `None`; the `internal_field_count`
        // check above makes that unreachable, but "no key" is the safe answer.
        return None;
    };
    let marker = v8::Local::<v8::Value>::try_from(marker).ok()?;
    if !marker.boolean_value(scope) {
        return None;
    }
    // SAFETY: the marker says `set_key_data` wrote this field for this object,
    // and the finalizer installed there is the only thing that clears it.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(KEY_DATA_FIELD, 0) }
        as *mut RefCell<KeyData>;
    (!pointer.is_null()).then_some(pointer)
}

/// Runs `body` with the key an object holds.
///
/// `None` means the receiver is not a native key object. The closure cannot leak
/// the borrow, and nothing here calls back into V8 while holding it.
pub(crate) fn with_key_data<R>(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&KeyData) -> R,
) -> Option<R> {
    let pointer = key_pointer(scope, object)?;
    // SAFETY: `key_pointer` returned a live box for this object.
    let cell = unsafe { &*pointer };
    let data = cell.try_borrow().ok()?;
    Some(body(&data))
}

/// Whether `value` carries this crate's native key state.
///
/// This is the brand `util.types.isKeyObject` reports. It tests native state, not
/// the prototype chain, which is what makes it immune to `Object.setPrototypeOf`
/// and to replacing `KeyObject[Symbol.hasInstance]` — both of which
/// `test-crypto-keyobject-brand-check.js` performs.
pub(crate) fn is_native_key_object(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> bool {
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return false;
    };
    with_key_data(scope, object, |_| ()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The field index the class protocol depends on.
    ///
    /// `INTERNAL_FIELD_COUNT` is what the templates reserve, and a store to an
    /// index at or beyond it writes nowhere — silently, since V8 does not check.
    /// So the constant is pinned rather than inferred.
    #[test]
    fn the_internal_field_layout_is_a_pointer_and_a_marker() {
        // The two indices are what the templates reserve; a mismatch would make
        // the marker write land outside the object, where V8 silently drops it and
        // every key then reports as absent.
        assert_eq!(KEY_DATA_FIELD, 0);
        assert_eq!(KEY_PRESENT_FIELD, 1);
        assert_eq!(INTERNAL_FIELD_COUNT, 2);
    }
}
