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

use rn_v8_sys::v8;

/// Builder for a **method**, matching Node's `SetMethod`: not constructible.
///
/// `new fn()` on the result throws `TypeError: … is not a constructor`, which is
/// what Node does for every member published through `SetMethod`,
/// `SetMethodNoSideEffect`, `SetFastMethod`, `SetProtoMethod` or
/// `SetInstanceMethod`.
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
