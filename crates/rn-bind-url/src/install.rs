//! V8 plumbing shared by the namespace's members.
//!
//! Every callback here is a plain `fn`, never a closure. V8 stores callback data
//! in a statically sized slot, so a capturing closure would overrun it; a plain
//! function has no captures and monomorphises to a bare pointer.
//!
//! Each method is installed by building the `FunctionTemplate` into a local
//! first. `FunctionTemplate::builder(..).build(scope)` borrows the scope mutably,
//! and `object.set(scope, ..)` needs it again in the same expression, which the
//! borrow checker rejects; hoisting keeps the two borrows sequential.

use rn_v8_sys::v8;

/// Creates a JavaScript string, mapping a failed allocation to an error string.
pub(crate) fn string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, value).ok_or_else(|| format!("could not allocate string {value:?}"))
}

/// Defines one member as an ordinary data property.
///
/// `SetMethod`/`SetMethodNoSideEffect` in `node_url.cc` end in a plain `Set` with
/// no attribute argument, so the property is writable, enumerable and
/// configurable. `lib/internal/url.js` reads these once at module scope.
pub(crate) fn define_method(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("could not create url.{name}"))?;
    let key = string(scope, name)?;
    object
        .set(scope, key.into(), function.into())
        .ok_or_else(|| format!("could not define {name:?}"))?;
    Ok(())
}

/// Throws a plain `Error`.
pub(crate) fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let text = v8::String::new(scope, message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

/// Sets a string property on an object, ignoring allocation failure.
///
/// Used only while building an exception, where there is nothing useful left to
/// do if the allocation fails.
pub(crate) fn set_string_property(
    scope: &mut v8::PinScope<'_, '_>,
    target: v8::Local<'_, v8::Value>,
    name: &str,
    value: &str,
) {
    let Ok(object) = v8::Local::<v8::Object>::try_from(target) else {
        return;
    };
    let (Some(key), Some(text)) = (v8::String::new(scope, name), v8::String::new(scope, value))
    else {
        return;
    };
    object.set(scope, key.into(), text.into());
}

/// Throws the `ERR_INVALID_URL` error `ThrowInvalidURL` builds.
///
/// `ERR_INVALID_URL` is declared as a `TypeError` in `node_errors.h`, not a
/// plain `Error`, so `error instanceof TypeError` is true — `lib/internal/url.js`
/// relies on nothing here, but user code and Node's own tests do.
///
/// Node attaches `input`, and `base` when one was supplied, only from `Parse`
/// and `PathToFileURL`; `GetOrigin` passes neither. That split is why `input` is
/// an `Option` rather than always set.
pub(crate) fn throw_invalid_url(
    scope: &mut v8::PinScope<'_, '_>,
    input: Option<&str>,
    base: Option<&str>,
) {
    let Some(message) = v8::String::new(scope, "Invalid URL") else {
        return;
    };
    let exception = v8::Exception::type_error(scope, message);
    set_string_property(scope, exception, "code", "ERR_INVALID_URL");
    if let Some(input) = input {
        set_string_property(scope, exception, "input", input);
    }
    if let Some(base) = base {
        set_string_property(scope, exception, "base", base);
    }
    scope.throw_exception(exception);
}

/// Reads an argument as an owned string, stringifying it the way Node's
/// `Utf8Value` does.
///
/// The JavaScript layer has already coerced the values it passes, so this is a
/// formality; `None` means V8 refused the conversion, which happens only when a
/// pending exception is already set.
pub(crate) fn argument_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<String> {
    args.get(index)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
}

/// Whether the argument at `index` is a JavaScript string.
pub(crate) fn is_string(args: &v8::FunctionCallbackArguments<'_>, index: i32) -> bool {
    v8::Local::<v8::String>::try_from(args.get(index)).is_ok()
}

/// Reads a boolean argument with Node's `IsTrue()` semantics.
///
/// `args[n]->IsTrue()` is false for every value except the boolean `true`, so an
/// absent argument reads as false. `lib/url.js` always passes booleans here.
pub(crate) fn is_true(args: &v8::FunctionCallbackArguments<'_>, index: i32) -> bool {
    args.get(index).is_true()
}
