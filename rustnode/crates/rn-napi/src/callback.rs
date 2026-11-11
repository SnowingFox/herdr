//! The callbacks an addon's `napi_value`s travel into.
//!
//! When an addon calls `napi_create_function` it hands Node-API a C function
//! pointer. Node wraps that pointer in a `v8::FunctionTemplate` whose callback
//! rebuilds a `napi_callback_info` and calls it. The same has to happen here: V8
//! must be given a Rust `unsafe extern "C" fn`, and that function is where the
//! `napi_value` bridge becomes observable from JavaScript.
//!
//! The template's callback *data* is a heap-allocated [`CallbackData`] carrying the
//! addon's pointer and its `void* data`, which is how Node smuggles the same pair
//! through V8's data slot.

use std::ffi::c_void;

use rn_v8_sys::v8;

use crate::abi::{NapiCallbackInfo, NapiEnv};
use crate::env::Env;

/// What a `napi_create_function` callback needs when V8 invokes it.
pub(crate) struct CallbackData {
    /// The addon's `napi_callback`.
    pub(crate) callback: crate::abi::NapiCallback,
    /// The `void* data` the addon attached, handed back through
    /// `napi_get_cb_info`.
    pub(crate) data: *mut c_void,
    /// The environment the function was created in, so the callback runs against
    /// the addon's `napi_env` rather than whichever one happens to be current.
    pub(crate) env: *mut Env,
}

/// The `napi_callback_info` Node hands a callback.
///
/// Node's is a `v8impl::FunctionCallbackWrapper*` living on the callback's own
/// stack frame. This mirrors that: the frame is constructed inside the V8
/// callback, pointed at by `napi_callback_info`, and gone when the callback
/// returns — which is why `napi_get_cb_info` has to be called during the callback
/// and a saved `napi_callback_info` is invalid afterwards.
pub(crate) struct CallbackFrame<'s> {
    /// V8's argument list, already collected for this scope.
    pub(crate) argv: &'s [v8::Local<'s, v8::Value>],
    /// `this`: the receiver for a method call, the global object for a plain one.
    pub(crate) this: v8::Local<'s, v8::Object>,
    /// `new.target`, so `napi_get_new_target` can tell a construct call from a
    /// plain one.
    pub(crate) new_target: v8::Local<'s, v8::Value>,
    /// The addon's `void* data`.
    pub(crate) data: *mut c_void,
    /// The environment the callback was created against.
    ///
    /// `napi_get_cb_info` does not expose it, but keeping it on the frame is what
    /// lets a later entry point (the deferred `napi_make_callback`) recover the
    /// right environment from a `napi_callback_info` alone.
    #[allow(dead_code)]
    pub(crate) env: *mut Env,
}

/// Wraps an addon callback into the `v8::FunctionCallback` V8 will call.
///
/// This is installed only through [`build_function`], which puts the matching
/// [`CallbackData`] in the template's data slot.
unsafe extern "C" fn invoke_addon_callback(info: *const v8::FunctionCallbackInfo) {
    // SAFETY: V8 passes a valid callback-info pointer to every function callback,
    // and this function is only ever installed as one.
    let info = unsafe { &*info };
    v8::callback_scope!(unsafe scope, info);

    let parts = info.get_parts();
    let Some(data) = external_data(parts.data) else {
        // No data slot means the template was installed incorrectly. A JS
        // `TypeError` is the honest report; returning `undefined` would look like
        // an addon bug.
        let exception = v8::String::new(scope, "native callback has no data slot")
            .map(|text| v8::Exception::type_error(scope, text))
            .unwrap_or_else(|| v8::undefined(scope).into());
        scope.throw_exception(exception);
        return;
    };

    // SAFETY: every `CallbackData` is leaked when its function is created, so the
    // pointer is valid for the life of the process.
    let data = unsafe { &*data };
    let Some(callback) = data.callback else {
        return;
    };

    let args = v8::FunctionCallbackArguments::from_function_callback_info(info);
    let argc = args.length();
    let mut argv = Vec::with_capacity(argc.max(0) as usize);
    for index in 0..argc {
        argv.push(args.get(index));
    }

    let mut frame = CallbackFrame {
        argv: &argv,
        this: args.this(),
        new_target: args.new_target(),
        data: data.data,
        env: data.env,
    };

    // The frame's address is the `napi_callback_info`. It is a local, so it cannot
    // outlive this call, matching Node's wrapper.
    let frame_ptr = &mut frame as *mut CallbackFrame<'_> as *mut NapiCallbackInfo;
    let env_ptr = data.env.cast::<NapiEnv>();

    // The addon's callback runs inside this scope, so the `napi_value`s it creates
    // are handles from this scope and stay valid until it returns.
    let guard = crate::scope::ScopeGuard::enter(scope);
    // SAFETY: the callback is the addon's own function pointer, the environment is
    // the one it registered against, and the frame is on this stack frame for the
    // whole call.
    let result = unsafe { callback(env_ptr, frame_ptr) };
    drop(guard);

    // `napi_callback` returns the value to hand back to JavaScript. A null return
    // means the addon threw or has nothing to return, in which case Node leaves the
    // return value as `undefined`.
    if !result.is_null() {
        // SAFETY: `result` is a handle the addon created inside this scope, which
        // is still alive here.
        if let Some(value) = unsafe { crate::values::from_napi(result) } {
            let mut rv = v8::ReturnValue::from_function_callback_info(info);
            rv.set(value);
        }
    }
}

/// Recovers the [`CallbackData`] a template's data slot points at.
fn external_data(slot: v8::Local<'_, v8::Value>) -> Option<*const CallbackData> {
    let external = v8::Local::<v8::External>::try_from(slot).ok()?;
    let pointer = external.value() as *const CallbackData;
    (!pointer.is_null()).then_some(pointer)
}

/// Leaks a [`CallbackData`] and returns it as the pointer a template's data slot
/// carries.
///
/// Leaking is deliberate and matches Node: the function object may be called at any
/// point until the isolate dies, and Node-API offers no way to tell the runtime when
/// an addon's function becomes unreachable.
pub(crate) fn boxed_callback_data(
    callback: crate::abi::NapiCallback,
    data: *mut c_void,
    env: *mut Env,
) -> *mut CallbackData {
    Box::into_raw(Box::new(CallbackData {
        callback,
        data,
        env,
    }))
}

/// Builds the V8 function for an addon callback.
pub(crate) fn build_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    data: *mut CallbackData,
    length: i32,
) -> Option<v8::Local<'s, v8::Function>> {
    let external = v8::External::new(scope, data.cast());
    let template = v8::FunctionTemplate::builder_raw(invoke_addon_callback)
        .data(external.into())
        .length(length)
        .build(scope);
    let function = template.get_function(scope)?;
    if !name.is_empty() {
        if let Some(name) = v8::String::new(scope, name) {
            function.set_name(name);
        }
    }
    Some(function)
}
