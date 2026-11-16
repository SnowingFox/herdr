//! How a binding publishes a JavaScript function.
//!
//! Every `internalBinding()` namespace is a plain object whose members `lib/**`
//! calls. Two kinds of member live there, and Node distinguishes them at
//! creation time, not at call time:
//!
//! * **Methods** — nearly all of them — go through `node::SetMethod`,
//!   `SetMethodNoSideEffect`, `SetFastMethod`, `SetProtoMethod` or
//!   `SetInstanceMethod` (`src/util.cc`), every one of which passes
//!   `v8::ConstructorBehavior::kThrow`. The resulting function object has no
//!   `[[Construct]]`, so `new process.binding('fs').open(…)` and
//!   `new binding.TCP.prototype.connect()` are both a `TypeError`.
//! * **Classes** — `crypto.Hash`, `tcp_wrap.TCP`, `zlib.Zlib` and 80-odd
//!   others — are published through `SetConstructorFunction` or a bare
//!   `FunctionTemplate::New`, which default to `kAllow`. `lib/**` really does
//!   `new` those, and `new` on their *prototype's* methods is still a
//!   `TypeError`, because those go through `SetProtoMethod`.
//!
//! V8's `FunctionTemplate::builder` defaults to `ConstructorBehavior::Allow`,
//! which is the *opposite* default from Node's binding helpers. That is not a
//! cosmetic difference: a method built with the permissive default silently
//! accepts `new`, so a use of `new` that should have failed in review worked
//! here and failed on Node. Being more permissive than the reference is its own
//! kind of incompatibility — the code passes here and breaks there.
//!
//! So the default is inverted: [`method`] is what a binding should reach for,
//! for a namespace member *and* for a prototype method, and [`class`] is the
//! deliberate exception that has to say so at the call site.
//! `crates/rn-core/tests/publication.rs` pins the two primitives;
//! `tools/constructible-audit.py` measures the consequence end to end, diffing
//! the exact set of members and prototype methods that accept `new` against the
//! pinned oracle in both directions.
//!
//! # Naming is the same decision, one field over
//!
//! `SetMethod(context, target, "open", Open)` names the function after the
//! property it publishes it under: the last line of that helper is
//! `function->SetName(name_string)`. `FunctionTemplate::builder` does not, so a
//! function built here and set on an object reports `f.name === ""`. That is
//! observable — it reaches stack traces, `util.inspect`, and any `lib/**` code
//! that names a function by its `.name` — and it is what
//! `tools/function-name-audit.py` measures against the oracle for every member
//! and prototype method in every namespace.
//!
//! The publish helpers below are the chokepoint for that. [`set_method`] and
//! [`named_method`] are `SetMethod`, name included, so a call site that uses
//! them cannot publish an unnamed function. The exceptions are explicit and
//! named after the Node helper they mirror:
//!
//! * [`set_fast_method`] is `SetFastMethod`/`SetFastMethodNoSideEffect`, whose
//!   slow-path function Node leaves **unnamed** — `SetFastMethod` is the one
//!   `SetMethod` variant that omits `SetName`, so `binding.copy.name` is `""`
//!   on Node too. Naming those would be its own divergence.
//! * Templates placed in an `ObjectTemplate` (a `PrototypeTemplate`, or an
//!   `InstanceTemplate`) are named by V8 from the property key, so
//!   [`method`]/[`class`] are correct there without a name. Extracted with
//!   `get_function` and set on a real object, they are not — that is what
//!   [`named_method`] is for.

use rn_v8_sys::v8;

/// Builder for a **method**, matching Node's `SetMethod`: not constructible.
///
/// `new fn()` on the result throws `TypeError: … is not a constructor`, which is
/// what Node does for every member published through `SetMethod`,
/// `SetMethodNoSideEffect`, `SetFastMethod`, `SetProtoMethod` or
/// `SetInstanceMethod`.
///
/// The builder carries no name. That is only correct when the template is placed
/// in an `ObjectTemplate` under a key, where V8 names the function from the key.
/// A template that is extracted with `get_function` and set on a real object must
/// go through [`named_method`] instead, or the function reports `name === ""`.
pub fn method<'s>(
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::FunctionBuilder<'s, v8::FunctionTemplate> {
    v8::FunctionTemplate::builder(callback).constructor_behavior(v8::ConstructorBehavior::Throw)
}

/// Builder for a **class**, matching Node's `SetConstructorFunction`.
///
/// Only for a member Node itself publishes as a constructor — a `BaseObject`
/// subclass whose JavaScript side writes `new`. Everything else, including every
/// method on such a class's prototype, is [`method`].
pub fn class<'s>(
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::FunctionBuilder<'s, v8::FunctionTemplate> {
    v8::FunctionTemplate::builder(callback)
}

/// [`method`] for the `v8::Function` builder, for call sites that want a
/// function object without an intermediate `FunctionTemplate`.
///
/// Same constructor behaviour, and the same reason: `FunctionBuilder` defaults
/// to `ConstructorBehavior::Allow`, Node's `SetMethod` passes `kThrow`.
pub fn method_function<'s>(
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::FunctionBuilder<'s, v8::Function> {
    v8::Function::builder(callback).constructor_behavior(v8::ConstructorBehavior::Throw)
}

/// [`method_function`] with a callback the caller already has as a raw pointer.
pub fn method_function_raw<'s>(
    callback: v8::FunctionCallback,
) -> v8::FunctionBuilder<'s, v8::Function> {
    v8::Function::builder_raw(callback).constructor_behavior(v8::ConstructorBehavior::Throw)
}

/// Builds a method and names it `name`, without publishing it anywhere.
///
/// This is the half of Node's `SetMethod` that V8's builder omits:
/// `FunctionTemplate::New(…)->GetFunction(context)` followed by
/// `function->SetName(name_string)`. Use it whenever the caller needs the
/// function itself — to store it in a thread-local for later instantiation, to
/// publish it on a prototype *object* rather than a prototype *template*, or to
/// hand it to a `set` that takes a `Value`.
pub fn named_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    named_method_with_length(scope, name, 0, callback)
}

/// [`named_method`] with Node's `length`, which most bindings pass explicitly.
pub fn named_method_with_length<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let function = method(callback)
        .length(length)
        .build(scope)
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate the function template for {name}"))?;
    let key =
        v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate the name {name}"))?;
    function.set_name(key);
    Ok(function)
}

/// Names a template that the caller already shaped, and returns its function.
///
/// The few members whose template needs a shape adjustment the builders cannot
/// express — `createELDHistogram` calls `remove_prototype`, `ModuleWrap` sets its
/// class name — still have to come out named. Everything else should use
/// [`named_method`] or [`set_method`], which cannot be called without a name.
pub fn named_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    template: v8::Local<'s, v8::FunctionTemplate>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot instantiate the function template for {name}"))?;
    let key =
        v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate the name {name}"))?;
    function.set_name(key);
    Ok(function)
}

/// Publishes a method on `target` under `name`, naming it after that property.
///
/// This is `node::SetMethod` exactly: `kThrow`, `length` 0, a plain `Set`, and
/// `SetName`. The returned function is the one that was published, for the few
/// call sites that also keep a reference to it.
pub fn set_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    set_named_method_with_length(scope, target, name, 0, callback)
}

/// [`set_method`] with an explicit `length`, still named after the property.
pub fn set_named_method_with_length<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let function = named_method_with_length(scope, name, length, callback)?;
    let key =
        v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate the name {name}"))?;
    target
        .set(scope, key.into(), function.into())
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(function)
}

/// Publishes a fast-API method on `target` under `name`, leaving it **unnamed**.
///
/// `SetFastMethod` and `SetFastMethodNoSideEffect` are the only `SetMethod`
/// variants that do not call `SetName`, so Node's `binding.buffer.copy.name`,
/// `os.getTotalMem.name`, `types.isDate.name`, `permission.has.name` and
/// `zlib.crc32.name` are all `""`. The fast-API thunk Node installs alongside the
/// slow path is not reachable from this crate, so the observable difference the
/// `CFunction` makes is nil; what matters is the name, and naming these would be
/// a fresh divergence in the opposite direction.
///
/// Reach for this only for a member Node publishes with `SetFastMethod*`. Every
/// other member is [`set_method`].
pub fn set_fast_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let function = method(callback)
        .build(scope)
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate the function template for {name}"))?;
    let key =
        v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate the name {name}"))?;
    target
        .set(scope, key.into(), function.into())
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(function)
}

/// Publishes a **class** on `target` under `name`, matching
/// `SetConstructorFunction(…, SET_CLASS_NAME)`.
///
/// The class name is what V8 reports as `f.name`, what `new f()` prints in a
/// stack trace, and what `[[Prototype]].constructor.name` returns — Node sets it
/// from the property name, so the two cannot drift here either.
pub fn set_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    template: v8::Local<'s, v8::FunctionTemplate>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let key =
        v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate the name {name}"))?;
    template.set_class_name(key);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot instantiate the class {name}"))?;
    target
        .set(scope, key.into(), function.into())
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(function)
}
