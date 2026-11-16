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
//! # Name and length are one decision, two fields
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
//! The same helper call also decides `f.length`, and it decides it **zero**.
//! Every `SetMethod` variant builds its template through `NewFunctionTemplate`,
//! which passes an explicit `0` for the length (`src/util.cc`), and
//! `SetConstructorFunction` takes the template as given — also `0` for the
//! `NewFunctionTemplate` every class in `src/**` is built from. V8's
//! `FunctionTemplate::New` honours whatever length it is handed, so a binding
//! that passes the callback's real arity reports a longer function than Node's.
//! `f.length` is observable to `lib/**` and to anything inspecting a binding, so
//! this is a real divergence and not a cosmetic one.
//!
//! The publish helpers below are the chokepoint for both fields. [`set_method`]
//! and [`named_method`] are `SetMethod` complete — name *and* length 0 — so a
//! call site that uses them cannot publish a function that differs from Node's
//! on either. The exceptions are explicit and named after what Node does:
//!
//! * [`set_fast_method`] is `SetFastMethod`/`SetFastMethodNoSideEffect`, whose
//!   slow-path function Node leaves **unnamed** — `SetFastMethod` is the one
//!   `SetMethod` variant that omits `SetName`, so `binding.copy.name` is `""`
//!   on Node too. Naming those would be its own divergence. Its length is still
//!   0, like every other `SetMethod` member.
//! * [`set_extras_method`] / [`named_extras_method`] are V8's own
//!   `SimpleInstallFunction(isolate, base, name, builtin, len, kAdapt)`, the
//!   only publisher in this tree that records a **non-zero** length. It is what
//!   installs the extras binding `async_context_frame` and `trace_events`
//!   republish from (`deps/v8/src/init/bootstrapper.cc`), so those three members
//!   genuinely report 1, 1 and 5.
//! * [`class_with_length`] is `FunctionTemplate::SetLength(n)` before
//!   `SetConstructorFunction`, which `src/node_serdes.cc` does once, for
//!   `Deserializer`. No other constructor in `src/**` sets a length.
//! * Templates placed in an `ObjectTemplate` (a `PrototypeTemplate`, or an
//!   `InstanceTemplate`) are named by V8 from the property key, so
//!   [`method`]/[`class`] are correct there without a name. Extracted with
//!   `get_function` and set on a real object, they are not — that is what
//!   [`named_method`] is for.

use rn_v8_sys::v8;

/// Builder for a **method**, matching Node's `SetMethod`: not constructible, and
/// `length` **0**.
///
/// `new fn()` on the result throws `TypeError: … is not a constructor`, which is
/// what Node does for every member published through `SetMethod`,
/// `SetMethodNoSideEffect`, `SetFastMethod`, `SetProtoMethod` or
/// `SetInstanceMethod`.
///
/// The length is 0 because every one of those helpers builds its template
/// through `NewFunctionTemplate(isolate, callback, …, /*length=*/0, …)`. Node
/// never passes a binding callback's real arity, so neither does this: a call
/// site that reaches for `.length(n)` on the result reports a function Node does
/// not have. The only non-zero lengths in the binding surface come from V8's own
/// `SimpleInstallFunction` ([`extras_method`]) and from `src/node_serdes.cc`'s
/// single `SetLength` ([`class_with_length`]).
///
/// The builder carries no name. That is only correct when the template is placed
/// in an `ObjectTemplate` under a key, where V8 names the function from the key.
/// A template that is extracted with `get_function` and set on a real object must
/// go through [`named_method`] instead, or the function reports `name === ""`.
pub fn method<'s>(
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::FunctionBuilder<'s, v8::FunctionTemplate> {
    v8::FunctionTemplate::builder(callback)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
}

/// Builder for a **class**, matching Node's `SetConstructorFunction`: length **0**.
///
/// Only for a member Node itself publishes as a constructor — a `BaseObject`
/// subclass whose JavaScript side writes `new`. Everything else, including every
/// method on such a class's prototype, is [`method`].
///
/// The length is 0 for the same reason as [`method`]: every constructor in
/// `src/**` is a `NewFunctionTemplate`, and `SetConstructorFunction` takes that
/// template as it is. The one exception is named [`class_with_length`].
pub fn class<'s>(
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::FunctionBuilder<'s, v8::FunctionTemplate> {
    v8::FunctionTemplate::builder(callback).length(0)
}

/// [`class`] with a length Node sets explicitly, for `FunctionTemplate::SetLength`.
///
/// `src/node_serdes.cc` is the only place in `src/**` that calls `SetLength` on
/// a template it publishes (`des->SetLength(1)`), which is why
/// `binding.Deserializer.length` is 1 while every other constructor Node
/// installs is 0. Reach for this only for a member Node does that to; otherwise
/// the length is 0 and [`class`] is right.
pub fn class_with_length<'s>(
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::FunctionBuilder<'s, v8::FunctionTemplate> {
    v8::FunctionTemplate::builder(callback).length(length)
}

/// [`method`] for the `v8::Function` builder, for call sites that want a
/// function object without an intermediate `FunctionTemplate`.
///
/// Same constructor behaviour and length, and the same reason: `FunctionBuilder`
/// defaults to `ConstructorBehavior::Allow` and length 0 only by accident, while
/// Node's `SetMethod` passes `kThrow` and an explicit 0 on purpose.
pub fn method_function<'s>(
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::FunctionBuilder<'s, v8::Function> {
    v8::Function::builder(callback)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
}

/// [`method_function`] with a callback the caller already has as a raw pointer.
pub fn method_function_raw<'s>(
    callback: v8::FunctionCallback,
) -> v8::FunctionBuilder<'s, v8::Function> {
    v8::Function::builder_raw(callback)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(0)
}

/// Builds a method and names it `name`, without publishing it anywhere.
///
/// This is the half of Node's `SetMethod` that V8's builder omits:
/// `FunctionTemplate::New(…)->GetFunction(context)` followed by
/// `function->SetName(name_string)`. Use it whenever the caller needs the
/// function itself — to store it in a thread-local for later instantiation, to
/// publish it on a prototype *object* rather than a prototype *template*, or to
/// hand it to a `set` that takes a `Value`.
///
/// The length is [`method`]'s, i.e. 0.
pub fn named_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    named_method_with_length(scope, name, 0, callback)
}

/// [`named_method`] with an explicit `length`.
///
/// Only two callers may pass a non-zero length, and both mirror a Node publisher
/// that really records one — see [`extras_method`] and [`class_with_length`].
/// Every other member Node publishes is 0 through `NewFunctionTemplate`, so a
/// non-zero length here is a divergence to justify at the call site.
pub fn named_method_with_length<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let function = v8::FunctionTemplate::builder(callback)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(length)
        .build(scope)
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate the function template for {name}"))?;
    let key =
        v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate the name {name}"))?;
    function.set_name(key);
    Ok(function)
}

/// A function shaped like V8's own `SimpleInstallFunction`, which records a length.
///
/// `async_context_frame` and `trace_events` do not build their members with
/// `SetMethod` at all: both copy them off `context->GetExtrasBindingObject()`,
/// and V8 installed those with
/// `SimpleInstallFunction(isolate, base, name, builtin, len, kAdapt)`. That
/// helper passes `len` to the function's `shared_function_info`, so the published
/// function really does report it — `trace.length` is 5 and
/// `isTraceCategoryEnabled.length` is 1, while `getContinuationPreservedEmbedderData`
/// is 0 and `setContinuationPreservedEmbedderData` is 1.
///
/// This is the one place in the binding surface where a non-zero length is
/// correct, so it says so in its name instead of leaving a `.length(n)` to look
/// like an arity someone typed.
pub fn extras_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    named_method_with_length(scope, name, length, callback)
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
///
/// Non-zero is reserved for a member Node copies out of the V8 extras binding,
/// where `SimpleInstallFunction` recorded the length. See [`extras_method`].
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
