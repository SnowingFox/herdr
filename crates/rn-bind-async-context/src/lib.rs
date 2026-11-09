//! `internalBinding('async_context_frame')` for rustnode.
//!
//! `AsyncLocalStorage` keeps its state on a value V8 carries across every
//! continuation: promise resolutions, `queueMicrotask`, `setTimeout` and the
//! rest restore it for you. V8 exposes that value as "continuation preserved
//! embedder data", so this namespace is a two-function window onto it.
//!
//! Node reaches the same two accessors through `GetExtrasBindingObject()`,
//! which is how the fast API path in V8's extras reaches them; the underlying
//! calls are `Context::Set/GetContinuationPreservedEmbedderData`, which the
//! `v8` crate exposes directly.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/async_context_frame.json`.
pub const MEMBERS: &[&str] = &[
    "getContinuationPreservedEmbedderData",
    "setContinuationPreservedEmbedderData",
];

pub struct AsyncContextFrame;

impl BindingModule for AsyncContextFrame {
    fn namespace(&self) -> &'static str {
        "async_context_frame"
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
        let values: [(&str, v8::Local<v8::Value>); 2] = [
            (
                "getContinuationPreservedEmbedderData",
                function(scope, "getContinuationPreservedEmbedderData", get_data)?,
            ),
            (
                "setContinuationPreservedEmbedderData",
                function(scope, "setContinuationPreservedEmbedderData", set_data)?,
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
    registry.register_module(AsyncContextFrame);
}

fn get_data(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `undefined` until the JavaScript layer stores a frame, which is the state
    // `AsyncContextFrame.current()` expects outside any `run()`.
    let data = scope.get_continuation_preserved_embedder_data();
    rv.set(data);
}

fn set_data(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let value = args.get(0);
    scope.set_continuation_preserved_embedder_data(value);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rn_core::AsyncIds;

    fn read<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
    ) -> v8::Local<'s, v8::Value> {
        let key = v8::String::new(scope, "getContinuationPreservedEmbedderData").expect("key");
        let function =
            v8::Local::<v8::Function>::try_from(object.get(scope, key.into()).expect("fn"))
                .expect("a function");
        function
            .call(scope, object.into(), &[])
            .expect("the call to succeed")
    }

    fn write(scope: &mut v8::PinScope, object: v8::Local<v8::Object>, value: v8::Local<v8::Value>) {
        let key = v8::String::new(scope, "setContinuationPreservedEmbedderData").expect("key");
        let function =
            v8::Local::<v8::Function>::try_from(object.get(scope, key.into()).expect("fn"))
                .expect("a function");
        function
            .call(scope, object.into(), &[value])
            .expect("the call to succeed");
    }

    #[test]
    fn the_data_round_trips_through_the_context() {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();

        let mut isolate = v8::Isolate::new(Default::default());
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);

        let mut async_ids = AsyncIds::new();
        let mut ctx = InstallCtx {
            async_ids: &mut async_ids,
        };
        let object = AsyncContextFrame.install(scope, &mut ctx).expect("install");

        // Nothing is stored yet.
        assert!(read(scope, object).is_undefined());

        let marker = v8::Integer::new(scope, 42);
        write(scope, object, marker.into());
        let stored = read(scope, object);
        assert_eq!(stored.int32_value(scope), Some(42));
    }
}
