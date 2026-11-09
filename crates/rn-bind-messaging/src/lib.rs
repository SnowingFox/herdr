//! `internalBinding('messaging')` for rustnode.
//!
//! `lib/internal/worker/js_transferable.js` is loaded by `internal/fs/*` and
//! `internal/url.js`, so this namespace is on the critical path for
//! `require('fs')` even though nothing in the stdlib posts a message.
//!
//! # What works
//!
//! `structuredClone` is real: it round-trips a value through V8's own
//! `ValueSerializer`/`ValueDeserializer`, which is the same machinery
//! `MessagePort.postMessage` uses, so the clone semantics (transferred
//! ArrayBuffers aside) match Node's. `setDeserializerCreateObjectFunction`
//! retains the callback `js_transferable.js` installs.
//!
//! # What is deferred, and why
//!
//! `MessageChannel`, `MessagePort`, `BroadcastChannel` and the four functions
//! that operate on a port need a real port object with a message queue, a
//! serialization delegate that understands host objects, and a cross-thread
//! transport. None of that exists, and a port that accepted `postMessage` and
//! never delivered would be worse than an absent one: `worker_threads` code
//! would hang instead of failing at the point of use.

use std::cell::RefCell;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/messaging.json`.
///
/// The port machinery is absent on purpose; see the module docs.
pub const MEMBERS: &[&str] = &[
    "DOMException",
    "QuotaExceededError",
    "exposeLazyDOMExceptionProperty",
    "setDeserializerCreateObjectFunction",
    "structuredClone",
];

/// Members this build does not install yet.
pub const DEFERRED: &[(&str, &str)] = &[
    (
        "MessageChannel",
        "needs a port object with a message queue and a cross-thread transport",
    ),
    (
        "MessagePort",
        "same scope as MessageChannel: a port that never delivers would hang worker code rather than fail at use",
    ),
    (
        "broadcastChannel",
        "same scope as MessageChannel",
    ),
    (
        "drainMessagePort",
        "operates on a MessagePort",
    ),
    (
        "moveMessagePortToContext",
        "operates on a MessagePort",
    ),
    (
        "receiveMessageOnPort",
        "operates on a MessagePort",
    ),
    (
        "stopMessagePort",
        "operates on a MessagePort",
    ),
];

thread_local! {
    /// The deserializer object-creation callback `js_transferable.js` installs.
    static CREATE_OBJECT: RefCell<Option<v8::Global<v8::Function>>> =
        const { RefCell::new(None) };
}

pub struct Messaging;

impl BindingModule for Messaging {
    fn namespace(&self) -> &'static str {
        "messaging"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 5] = [
            (
                "setDeserializerCreateObjectFunction",
                function(
                    scope,
                    "setDeserializerCreateObjectFunction",
                    set_deserializer_create_object_function,
                )?,
            ),
            (
                "structuredClone",
                function(scope, "structuredClone", structured_clone)?,
            ),
            ("DOMException", dom_exception_constructor(scope)),
            ("QuotaExceededError", quota_exceeded_error(scope)),
            (
                "exposeLazyDOMExceptionProperty",
                function(
                    scope,
                    "exposeLazyDOMExceptionProperty",
                    expose_lazy_dom_exception_property,
                )?,
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Messaging);
}

/// A `DOMException` built the way the platform expects.
///
/// `lib/internal/util.js` uses this for `AbortSignal` and the web streams, so
/// it needs `name`, `message` and `code` to behave.
fn dom_exception_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let template = v8::FunctionTemplate::builder(new_dom_exception).build(scope);
    if let Some(name) = v8::String::new(scope, "DOMException") {
        template.set_class_name(name);
    }
    match template.get_function(scope) {
        Some(function) => function.into(),
        None => v8::undefined(scope).into(),
    }
}

fn new_dom_exception(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let message = args
        .get(0)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let name = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_else(|| "Error".to_string());

    let object = args.this();
    let values: [(&str, String); 2] = [("message", message.clone()), ("name", name.clone())];
    for (key, value) in values {
        if let (Some(key), Some(text)) =
            (v8::String::new(scope, key), v8::String::new(scope, &value))
        {
            object.set(scope, key.into(), text.into());
        }
    }
    if let Some(key) = v8::String::new(scope, "code") {
        object.set(scope, key.into(), v8::Integer::new(scope, 0).into());
    }
    rv.set(object.into());
}

fn quota_exceeded_error<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let template = v8::FunctionTemplate::builder(new_quota_exceeded_error).build(scope);
    if let Some(name) = v8::String::new(scope, "QuotaExceededError") {
        template.set_class_name(name);
    }
    match template.get_function(scope) {
        Some(function) => function.into(),
        None => v8::undefined(scope).into(),
    }
}

fn new_quota_exceeded_error(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // A `QuotaExceededError` is a `DOMException` with a fixed name and code.
    let message = args
        .get(0)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let object = args.this();
    if let (Some(key), Some(text)) = (
        v8::String::new(scope, "message"),
        v8::String::new(scope, &message),
    ) {
        object.set(scope, key.into(), text.into());
    }
    if let (Some(key), Some(text)) = (
        v8::String::new(scope, "name"),
        v8::String::new(scope, "QuotaExceededError"),
    ) {
        object.set(scope, key.into(), text.into());
    }
    if let Some(key) = v8::String::new(scope, "code") {
        // QUOTA_EXCEEDED_ERR is 22 in the DOM spec.
        object.set(scope, key.into(), v8::Integer::new(scope, 22).into());
    }
    rv.set(object.into());
}

fn expose_lazy_dom_exception_property(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // Node installs a lazy getter for `DOMException` on the target. The
    // constructor here is already installed eagerly, so the lazy hook has
    // nothing left to do; accepting it keeps `js_transferable.js` loadable.
    let _ = scope;
}

fn set_deserializer_create_object_function(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let callback = v8::Local::<v8::Function>::try_from(args.get(0))
        .ok()
        .map(|callback| v8::Global::new(scope, callback));
    CREATE_OBJECT.with(|slot| *slot.borrow_mut() = callback);
}

/// The delegate that makes plain (non-host) values serializable.
struct PlainSerializer;

impl v8::ValueSerializerImpl for PlainSerializer {
    fn throw_data_clone_error<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        message: v8::Local<'s, v8::String>,
    ) {
        // V8 gives the message; the exception type is the platform's.
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
    }

    fn is_host_object<'s>(
        &self,
        _scope: &mut v8::PinScope<'s, '_>,
        _object: v8::Local<'s, v8::Object>,
    ) -> Option<bool> {
        // No host objects are registered, so nothing is one. Returning `None`
        // here would abort the clone; `Some(false)` is the correct answer.
        Some(false)
    }
}

fn structured_clone(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = args.get(0);
    let serializer = v8::ValueSerializer::new(scope, Box::new(PlainSerializer));
    let Some(true) = serializer.write_value(scope.get_current_context(), value) else {
        // V8 has already thrown, which is what `structuredClone` should do for
        // an uncloneable value (a function, a WeakMap, a symbol).
        return;
    };
    let data = serializer.release();

    let deserializer = v8::ValueDeserializer::new(scope, Box::new(PlainDeserializer), &data);
    match deserializer.read_value(scope.get_current_context()) {
        Some(cloned) => rv.set(cloned),
        None => {
            // A read failure means the bytes were malformed, which cannot
            // happen from a clone we just wrote; throwing keeps it visible.
            throw(
                scope,
                "structuredClone: the serialized value could not be read back",
            );
        }
    }
}

struct PlainDeserializer;

impl v8::ValueDeserializerImpl for PlainDeserializer {
    fn get_shared_array_buffer_from_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _id: u32,
    ) -> Option<v8::Local<'s, v8::SharedArrayBuffer>> {
        let message =
            v8::String::new(scope, "structuredClone cannot transfer a SharedArrayBuffer")?;
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
        None
    }

    fn get_wasm_module_from_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _id: u32,
    ) -> Option<v8::Local<'s, v8::WasmModuleObject>> {
        let message = v8::String::new(
            scope,
            "structuredClone cannot transfer a WebAssembly.Module",
        )?;
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
        None
    }
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_member_and_deferral_lists_do_not_overlap() {
        for (deferred, _) in DEFERRED {
            assert!(
                !MEMBERS.contains(deferred),
                "{deferred} cannot be both installed and deferred"
            );
        }
    }

    #[test]
    fn every_contract_member_is_accounted_for() {
        // 12 recorded members: 5 installed, 7 deferred.
        assert_eq!(MEMBERS.len() + DEFERRED.len(), 12);
    }
}
