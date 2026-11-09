//! Drives a real `ModuleWrap` through compile, instantiate and evaluate.
//!
//! The unit tests only check the constant tables. This one proves the pieces
//! talk to V8 correctly, which is what the ESM loader depends on.

use rn_core::{BindingModule, InstallCtx};
use rn_module_wrap::ModuleWrapBinding;
use rn_v8_sys::v8;

#[test]
fn modules_compile_instantiate_and_evaluate() {
    source_text_module_lifecycle();
    synthetic_module_lifecycle();
}

fn source_text_module_lifecycle() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = ModuleWrapBinding;
    assert_eq!(binding.namespace(), "module_wrap");
    let mut async_ids = rn_core::AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    let namespace = binding
        .install(scope, &mut ctx)
        .expect("module_wrap installs");

    let key = v8::String::new(scope, "ModuleWrap").expect("key");
    let constructor = namespace
        .get(scope, key.into())
        .expect("ModuleWrap present");
    let constructor = v8::Local::<v8::Function>::try_from(constructor).expect("is a function");

    let source = v8::String::new(scope, "export const answer = 42;").expect("source");
    let url = v8::String::new(scope, "node:test-module").expect("url");
    let undefined = v8::undefined(scope).into();
    let zero = v8::Integer::new(scope, 0).into();
    let argv = [url.into(), undefined, source.into(), zero, zero];
    let wrapper = constructor
        .new_instance(scope, &argv)
        .expect("ModuleWrap constructs")
        .to_object(scope)
        .expect("wrapper is an object");

    let status_key = v8::String::new(scope, "getStatus").expect("status key");
    assert!(wrapper.get(scope, status_key.into()).is_some());

    let no_requests = v8::Array::new(scope, 0);
    let _ = call_method(scope, wrapper, "link", &[no_requests.into()]);
    let instantiation = call_method(scope, wrapper, "instantiate", &[]);
    assert!(instantiation.is_some(), "instantiate must not throw");

    let evaluation = call_method(scope, wrapper, "evaluate", &[]);
    assert!(evaluation.is_some(), "evaluate must not throw");

    let status = call_method(scope, wrapper, "getStatus", &[]).expect("getStatus returns");
    assert_eq!(
        status.number_value(scope).map(|value| value as i32),
        Some(rn_module_wrap::K_EVALUATED),
        "a module that ran without throwing is evaluated"
    );

    let namespace_object =
        call_method(scope, wrapper, "getNamespace", &[]).expect("getNamespace returns");
    let answer_key = v8::String::new(scope, "answer").expect("export key");
    let object = namespace_object
        .to_object(scope)
        .expect("namespace is an object");
    let answer = object
        .get(scope, answer_key.into())
        .expect("answer exported");
    assert_eq!(answer.number_value(scope), Some(42.0));
}

fn synthetic_module_lifecycle() {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = ModuleWrapBinding;
    let mut async_ids = rn_core::AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    let namespace = binding
        .install(scope, &mut ctx)
        .expect("module_wrap installs");

    let key = v8::String::new(scope, "ModuleWrap").expect("key");
    let constructor = namespace
        .get(scope, key.into())
        .expect("ModuleWrap present");
    let constructor = v8::Local::<v8::Function>::try_from(constructor).expect("is a function");

    // The evaluation step sets one export, which is what a CJS facade does.
    let steps_source = v8::String::new(scope, "(function() { this.setExport('value', 7); })")
        .expect("steps source");
    let steps = v8::Script::compile(scope, steps_source, None)
        .and_then(|script| script.run(scope))
        .expect("steps compile");
    let steps = v8::Local::<v8::Function>::try_from(steps).expect("steps is a function");

    let url = v8::String::new(scope, "node:synthetic").expect("url");
    let names = v8::Array::new(scope, 1);
    let value_key = v8::String::new(scope, "value").expect("value key");
    names.set_index(scope, 0, value_key.into());
    let undefined = v8::undefined(scope).into();
    let argv = [url.into(), undefined, names.into(), steps.into()];
    let wrapper = constructor
        .new_instance(scope, &argv)
        .expect("synthetic ModuleWrap constructs")
        .to_object(scope)
        .expect("wrapper is an object");

    assert!(
        call_method(scope, wrapper, "instantiate", &[]).is_some(),
        "synthetic instantiate"
    );
    assert!(
        call_method(scope, wrapper, "evaluate", &[]).is_some(),
        "synthetic evaluate"
    );

    let namespace_object =
        call_method(scope, wrapper, "getNamespace", &[]).expect("getNamespace returns");
    let object = namespace_object
        .to_object(scope)
        .expect("namespace is an object");
    let value = object.get(scope, value_key.into()).expect("value exported");
    assert_eq!(
        value.number_value(scope),
        Some(7.0),
        "evaluation step set the export"
    );
}

/// Calls a prototype method on a wrapper and returns its result.
///
/// A closure cannot work here: the returned `Local` borrows the scope, so the
/// helper needs the same lifetime the caller's scope has.
fn call_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    wrapper: v8::Local<'s, v8::Object>,
    method: &str,
    args: &[v8::Local<'s, v8::Value>],
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, method)?;
    let function = wrapper.get(scope, key.into())?;
    let function = v8::Local::<v8::Function>::try_from(function).ok()?;
    function.call(scope, wrapper.into(), args)
}
