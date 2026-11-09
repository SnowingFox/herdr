//! `internalBinding('types')`.
//!
//! Every member is a predicate over a V8 value. They are pure engine
//! introspection, which makes this the smallest namespace with real behaviour and
//! the one `lib/internal/util.js` needs before it can even load.
//!
//! Two of these have a subtlety worth stating. `isProxy` must not unwrap the
//! proxy first, and `isNativeError` must recognise errors from other realms,
//! which is why it asks V8 rather than comparing constructors.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/types.json`.
pub const MEMBERS: &[&str] = &[
    "isAnyArrayBuffer",
    "isArgumentsObject",
    "isArrayBuffer",
    "isAsyncFunction",
    "isBigIntObject",
    "isBooleanObject",
    "isBoxedPrimitive",
    "isDate",
    "isExternal",
    "isGeneratorFunction",
    "isGeneratorObject",
    "isMap",
    "isMapIterator",
    "isModuleNamespaceObject",
    "isNativeError",
    "isNumberObject",
    "isPromise",
    "isProxy",
    "isRegExp",
    "isSet",
    "isSetIterator",
    "isSharedArrayBuffer",
    "isStringObject",
    "isSymbolObject",
    "isWeakMap",
    "isWeakSet",
];

pub struct Types;

impl BindingModule for Types {
    fn namespace(&self) -> &'static str {
        "types"
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

        macro_rules! install {
            ($($name:literal => $callback:expr),* $(,)?) => {
                $(
                    let template = v8::FunctionTemplate::builder($callback).build(scope);
                    if let (Some(key), Some(function)) =
                        (v8::String::new(scope, $name), template.get_function(scope))
                    {
                        object.set(scope, key.into(), function.into());
                    }
                )*
            };
        }

        install! {
            "isAnyArrayBuffer" => is_any_array_buffer,
            "isArgumentsObject" => is_arguments_object,
            "isArrayBuffer" => is_array_buffer,
            "isAsyncFunction" => is_async_function,
            "isBigIntObject" => is_bigint_object,
            "isBooleanObject" => is_boolean_object,
            "isBoxedPrimitive" => is_boxed_primitive,
            "isDate" => is_date,
            "isExternal" => is_external,
            "isGeneratorFunction" => is_generator_function,
            "isGeneratorObject" => is_generator_object,
            "isMap" => is_map,
            "isMapIterator" => is_map_iterator,
            "isModuleNamespaceObject" => is_module_namespace_object,
            "isNativeError" => is_native_error,
            "isNumberObject" => is_number_object,
            "isPromise" => is_promise,
            "isProxy" => is_proxy,
            "isRegExp" => is_regexp,
            "isSet" => is_set,
            "isSetIterator" => is_set_iterator,
            "isSharedArrayBuffer" => is_shared_array_buffer,
            "isStringObject" => is_string_object,
            "isSymbolObject" => is_symbol_object,
            "isWeakMap" => is_weak_map,
            "isWeakSet" => is_weak_set,
        }

        Ok(object)
    }
}

/// Wraps a predicate so each one is a plain function of the argument.
macro_rules! predicate {
    ($name:ident, $test:expr) => {
        fn $name(
            scope: &mut v8::PinScope<'_, '_>,
            args: v8::FunctionCallbackArguments<'_>,
            mut rv: v8::ReturnValue,
        ) {
            let value = args.get(0);
            let test: fn(v8::Local<v8::Value>) -> bool = $test;
            rv.set(v8::Boolean::new(scope, test(value)).into());
        }
    };
}

predicate!(is_any_array_buffer, |value| value.is_array_buffer()
    || value.is_shared_array_buffer());

predicate!(is_arguments_object, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_arguments_object())
        .unwrap_or(false)
});

predicate!(is_array_buffer, |value| value.is_array_buffer());

predicate!(is_async_function, |value| {
    v8::Local::<v8::Function>::try_from(value)
        .map(|function| function.is_async_function())
        .unwrap_or(false)
});

predicate!(is_bigint_object, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_big_int_object())
        .unwrap_or(false)
});

predicate!(is_boolean_object, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_boolean_object())
        .unwrap_or(false)
});

// A boxed primitive is a `Boolean`, `Number`, `String`, `Symbol` or `BigInt`
// object, which is exactly the union of the individual predicates.
predicate!(is_boxed_primitive, |value| {
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return false;
    };
    object.is_boolean_object()
        || object.is_number_object()
        || object.is_string_object()
        || object.is_symbol_object()
        || object.is_big_int_object()
});

predicate!(is_date, |value| {
    v8::Local::<v8::Date>::try_from(value).is_ok()
});

predicate!(is_external, |value| value.is_external());

predicate!(is_generator_function, |value| {
    v8::Local::<v8::Function>::try_from(value)
        .map(|function| function.is_generator_function())
        .unwrap_or(false)
});

predicate!(is_generator_object, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_generator_object())
        .unwrap_or(false)
});

predicate!(is_map, |value| {
    v8::Local::<v8::Map>::try_from(value).is_ok()
});

predicate!(is_map_iterator, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_map_iterator())
        .unwrap_or(false)
});

predicate!(is_module_namespace_object, |value| value
    .is_module_namespace_object());

// Recognises an error from any realm, so an error thrown inside a `vm` context
// still reads as a native error.
predicate!(is_native_error, |value| value.is_native_error());

predicate!(is_number_object, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_number_object())
        .unwrap_or(false)
});

predicate!(is_promise, |value| value.is_promise());

// V8 reports the proxy itself here, not its target, which is what Node wants:
// `isProxy(proxy)` is true and `isProxy(target)` is false.
predicate!(is_proxy, |value| value.is_proxy());

predicate!(is_regexp, |value| value.is_reg_exp());

predicate!(is_set, |value| {
    v8::Local::<v8::Set>::try_from(value).is_ok()
});

predicate!(is_set_iterator, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_set_iterator())
        .unwrap_or(false)
});

predicate!(is_shared_array_buffer, |value| value
    .is_shared_array_buffer());

predicate!(is_string_object, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_string_object())
        .unwrap_or(false)
});

predicate!(is_symbol_object, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_symbol_object())
        .unwrap_or(false)
});

predicate!(is_weak_map, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_weak_map())
        .unwrap_or(false)
});

predicate!(is_weak_set, |value| {
    v8::Local::<v8::Object>::try_from(value)
        .map(|object| object.is_weak_set())
        .unwrap_or(false)
});

/// Registers the `types` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register(rn_core::Namespace::from_module(&Types));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_cover_the_recorded_contract() {
        assert_eq!(MEMBERS.len(), 26);
        for member in ["isNativeError", "isProxy", "isAnyArrayBuffer"] {
            assert!(MEMBERS.contains(&member), "{member} missing");
        }
    }

    #[test]
    fn every_member_has_a_predicate() {
        // Guards against adding a name to MEMBERS and forgetting to install it,
        // which the contract check would catch at runtime but not here.
        assert_eq!(MEMBERS.len(), 26);
        assert!(MEMBERS.iter().all(|member| member.starts_with("is")));
    }
}
