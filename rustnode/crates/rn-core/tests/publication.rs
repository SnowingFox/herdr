//! The publication helpers mean what they say about `new` **and** about `name`.
//!
//! `rn_core::method` must produce a function with no `[[Construct]]`, and
//! `rn_core::class` one that has it. That is half the contract every binding
//! crate relies on now, and it is invisible at the call site: both return the
//! same `FunctionBuilder` type, so a mistake is not a compile error.
//!
//! The other half is naming. Node's `SetMethod(context, target, "open", Open)`
//! ends with `function->SetName(name_string)`, so `binding.fs.open.name` is
//! `"open"`; a bare `FunctionTemplate::builder` leaves it `""`. The same file
//! therefore pins `named_method`, `set_method`, `set_class` and the deliberate
//! exception, `set_fast_method`, whose Node counterpart omits `SetName` on
//! purpose.
//!
//! The end-to-end consequence — the exact set of `internalBinding()` members
//! that accept `new`, diffed against the pinned oracle — is measured by
//! `tools/constructible-audit.py`, which observes the *shipping* object after
//! the vendored `lib/**` bootstrap has run. This file pins the primitive those
//! 500-odd call sites are built on, so a change to V8's builder defaults, or to
//! these two wrappers, fails here with the reason rather than as a wall of
//! audit output.

use rn_v8_sys::v8;

fn with_scope<R>(body: impl for<'s> FnOnce(&mut v8::PinScope<'s, '_>) -> R) -> R {
    static V8: std::sync::Once = std::sync::Once::new();
    V8.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    body(scope)
}

fn noop(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
}

/// Whether JavaScript can `new` this value: the `[[Construct]]` bit itself.
///
/// This is `Object::is_constructor`, i.e. the property `new` consults. Testing
/// for an own `prototype` property instead is wrong in both directions, which is
/// why this test uses the engine's answer.
fn constructible(function: v8::Local<v8::Function>) -> bool {
    let object: v8::Local<v8::Object> = function.into();
    object.is_constructor()
}

#[test]
fn a_method_has_no_construct() {
    with_scope(|scope| {
        let template = rn_core::method(noop).build(scope);
        let function = template
            .get_function(scope)
            .expect("a method template always yields a function");
        assert!(
            !constructible(function),
            "`rn_core::method` must match Node's SetMethod, which passes \
             ConstructorBehavior::kThrow: `new` on the result is a TypeError. If \
             this fails, V8's builder default changed or the wrapper lost the \
             behavior, and every binding member built through it became \
             constructible again."
        );
    });
}

#[test]
fn a_class_has_a_construct() {
    with_scope(|scope| {
        let template = rn_core::class(noop).build(scope);
        let function = template
            .get_function(scope)
            .expect("a class template always yields a function");
        assert!(
            constructible(function),
            "`rn_core::class` must match Node's SetConstructorFunction: the classes \
             `lib/**` writes `new` against have to stay constructible. Without this \
             half, over-correcting the method default would silently break \
             `new binding.Zlib()` and 77 other real classes."
        );
    });
}

/// The pair is distinguishable, which is what makes the default meaningful.
///
/// A wrapper that set both the same way would pass one of the two tests above by
/// accident on whichever default V8 happens to have, and the audit would then be
/// the only thing standing between a real class and a `TypeError`.
#[test]
fn method_and_class_disagree() {
    with_scope(|scope| {
        let method = rn_core::method(noop)
            .build(scope)
            .get_function(scope)
            .expect("method");
        let class = rn_core::class(noop)
            .build(scope)
            .get_function(scope)
            .expect("class");
        assert_ne!(
            constructible(method),
            constructible(class),
            "the two builders must differ in [[Construct]]; otherwise every call \
             site that names its kind is decoration"
        );
    });
}

/// `rn_core::method_function` is the same promise for the `Function` builder.
#[test]
fn a_method_function_has_no_construct() {
    with_scope(|scope| {
        let function = rn_core::method_function(noop)
            .build(scope)
            .expect("a Function builder always produces a function");
        assert!(
            !constructible(function),
            "`v8::Function::builder` defaults to ConstructorBehavior::Allow too, so \
             the Function-shaped helper must carry the same kThrow."
        );
    });
}

/// The other half of `SetMethod`: the function reports the property name.
///
/// `SetMethod(context, target, "open", Open)` ends with
/// `function->SetName(name_string)`, so `binding.fs.open.name` is `"open"` on
/// Node. V8's builder leaves it `""`, which was true of 403 of 527 members here
/// and is observable in stack traces and `util.inspect`.
#[test]
fn a_named_method_carries_its_name() {
    with_scope(|scope| {
        let function = rn_core::named_method(scope, "open", noop).expect("a named method");
        assert_eq!(
            function.get_name(scope).to_rust_string_lossy(scope),
            "open",
            "`rn_core::named_method` must name the function after its property, \
             the way `node::SetMethod` does. Without this every binding member \
             published through a template reports `name === \"\"`."
        );
        assert!(
            !constructible(function),
            "naming must not change [[Construct]]: Node's `SetMethod` sets both."
        );
    });
}

/// The name has to survive publication, which is what a caller actually observes.
#[test]
fn a_published_method_reports_its_property_name() {
    with_scope(|scope| {
        let target = v8::Object::new(scope);
        rn_core::set_named_method_with_length(scope, target, "writeBuffer", 4, noop)
            .expect("a published method");

        let key = v8::String::new(scope, "writeBuffer").expect("a key");
        let value = target.get(scope, key.into()).expect("the published member");
        let function: v8::Local<v8::Function> = value
            .try_into()
            .expect("the published member is a function");
        assert_eq!(
            function.get_name(scope).to_rust_string_lossy(scope),
            "writeBuffer",
            "`SetMethod` publishes the function under the property name and names \
             the function from it; both sides have to agree or the divergence \
             returns the moment the property is renamed."
        );
        assert!(
            !constructible(function),
            "publishing must keep `SetMethod`'s kThrow."
        );
    });
}

/// `SetFastMethod` is the one `SetMethod` variant that omits `SetName`.
///
/// Node's `buffer.copy.name`, `os.getTotalMem.name`, `types.isDate.name`,
/// `permission.has.name` and `zlib.crc32.name` are all `""`. A helper that named
/// everything would trade the reported defect for a fresh one in the opposite
/// direction, so this pins the exemption rather than leaving it to the audit.
#[test]
fn a_fast_method_stays_unnamed() {
    with_scope(|scope| {
        let target = v8::Object::new(scope);
        rn_core::set_fast_method(scope, target, "copy", noop).expect("a published fast method");

        let key = v8::String::new(scope, "copy").expect("a key");
        let value = target.get(scope, key.into()).expect("the published member");
        let function: v8::Local<v8::Function> = value
            .try_into()
            .expect("the published member is a function");
        assert_eq!(
            function.get_name(scope).to_rust_string_lossy(scope),
            "",
            "`SetFastMethod`/`SetFastMethodNoSideEffect` do not call `SetName`, so \
             Node's copies are unnamed. Naming these would be a divergence."
        );
    });
}

/// `SetConstructorFunction(…, SET_CLASS_NAME)` names the class from the property.
#[test]
fn a_published_class_reports_its_property_name() {
    with_scope(|scope| {
        let target = v8::Object::new(scope);
        let template = rn_core::class(noop).build(scope);
        let function =
            rn_core::set_class(scope, target, "FSReqCallback", template).expect("a class");

        assert_eq!(
            function.get_name(scope).to_rust_string_lossy(scope),
            "FSReqCallback",
            "`SetConstructorFunction` sets the class name from the property it is \
             published under, which is what `f.name` reports."
        );
        assert!(
            constructible(function),
            "`set_class` is `SetConstructorFunction`, so the class keeps [[Construct]]."
        );
    });
}
