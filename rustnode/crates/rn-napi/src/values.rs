//! `napi_value` <-> `v8::Local<v8::Value>`.
//!
//! Node does this with a `memcpy` and no allocation:
//!
//! ```c
//! inline napi_value JsValueFromV8LocalValue(v8::Local<v8::Value> local) {
//!   return reinterpret_cast<napi_value>(*local);
//! }
//! inline v8::Local<v8::Value> V8LocalValueFromJsValue(napi_value v) {
//!   v8::Local<v8::Value> local;
//!   memcpy(static_cast<void*>(&local), &v, sizeof(v));
//!   return local;
//! }
//! ```
//!
//! `*local` dereferences the handle to the object pointer, and reconstructing a
//! `Local` from that pointer is valid only because V8's handle lives in the
//! enclosing handle scope and `Local` is just `{ T* }`. rusty_v8 models `Local`
//! the same way (`#[repr(C)] struct Local<'s, T>(NonNull<T>, PhantomData<&'s ()>)`),
//! so the same reinterpretation works — and, as in Node, it is sound exactly when
//! the handle scope outlives every use of the resulting value. That invariant is
//! what [`crate::scope`] enforces.

use rn_v8_sys::v8;

use crate::abi::NapiValue;
use crate::scope::with_scope;

/// Reinterprets a V8 local as the opaque `napi_value` an addon receives.
///
/// The handle is not copied or rooted: the addon gets V8's pointer and keeps it
/// valid only as long as the enclosing scope, which is the Node-API contract.
pub(crate) fn to_napi(value: v8::Local<'_, v8::Value>) -> *mut NapiValue {
    // SAFETY: `Local` is `#[repr(C)]` over a `NonNull<T>`, so its only field is the
    // object pointer; copying those bytes out is the same `*local` Node does. A
    // null pointer cannot occur because rusty_v8's `Local` is never empty.
    unsafe { std::mem::transmute_copy::<v8::Local<'_, v8::Value>, *mut NapiValue>(&value) }
}

/// Rebuilds the `v8::Local` behind a `napi_value`.
///
/// # Safety
///
/// `handle` must be a value produced by [`to_napi`] (or by a nested call that did
/// so) inside a handle scope that is still alive.
pub(crate) unsafe fn from_napi<'s>(handle: *mut NapiValue) -> Option<v8::Local<'s, v8::Value>> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: caller guarantees the pointer is a live V8 handle; the lifetime is
    // chosen by the caller and bounded by the current scope.
    Some(unsafe { std::mem::transmute_copy::<*mut NapiValue, v8::Local<'s, v8::Value>>(&handle) })
}

/// Runs `f` inside the current Node-API scope, or reports that there is none.
///
/// Every shim starts here. Node's equivalent is `CHECK_ENV` plus the implicit
/// assumption that V8 handed it a scope; rustnode has to ask, because its scopes
/// are established per entry point rather than by V8 itself.
pub(crate) fn in_scope<'s, R>(f: impl FnOnce(&mut v8::PinScope<'s, '_>) -> R) -> Option<R> {
    // SAFETY: the shims call this from an entry point that has entered a scope
    // guard, and they never return a handle past their own frame. `'s` is the
    // caller's assertion, documented on `with_scope`.
    unsafe { with_scope(f) }
}

/// Resolves a `napi_value` argument inside a scope callback.
///
/// A free function rather than a wrapper type so a shim can resolve several
/// arguments in one closure without fighting the borrow checker over the scope.
///
/// # Safety
///
/// `handle` must come from [`to_napi`] in a live scope.
pub(crate) unsafe fn arg<'s>(handle: *mut NapiValue) -> Option<v8::Local<'s, v8::Value>> {
    unsafe { from_napi(handle) }
}

/// The `napi_valuetype` a `Local` reports, mirroring `napi_typeof`.
///
/// Node classifies a function as `napi_function` before `napi_object` because
/// `IsFunction()` and `IsObject()` can both be true. The order below is Node's,
/// from `js_native_api_v8.cc`.
pub(crate) fn type_of(local: &v8::Local<'_, v8::Value>) -> crate::abi::NapiValueType {
    use crate::abi::NapiValueType;
    if local.is_undefined() {
        NapiValueType::Undefined
    } else if local.is_null() {
        NapiValueType::Null
    } else if local.is_boolean() {
        NapiValueType::Boolean
    } else if local.is_number() {
        NapiValueType::Number
    } else if local.is_string() {
        NapiValueType::String
    } else if local.is_symbol() {
        NapiValueType::Symbol
    } else if local.is_function() {
        NapiValueType::Function
    } else if local.is_external() {
        NapiValueType::External
    } else if local.is_big_int() {
        NapiValueType::Bigint
    } else {
        NapiValueType::Object
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_values_do_not_resolve() {
        // `napi_value` arguments are frequently null (every optional out parameter
        // is), and resolving one must not fabricate a handle.
        // SAFETY: null is rejected before any dereference.
        assert!(unsafe { from_napi(std::ptr::null_mut()) }.is_none());
    }
}
