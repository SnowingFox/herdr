//! Reading and calling the JavaScript hooks a serializer delegate forwards to.
//!
//! Node's `src/node_serdes.cc` makes the JavaScript object *be* the delegate:
//! `ThrowDataCloneError` looks up `_getDataCloneError` on `object()` and calls
//! it, `WriteHostObject` looks up `_writeHostObject`, and `ReadHostObject` looks up
//! `_readHostObject`. Every one of those is a plain property read plus a call, so
//! the mechanics live here once and the serializer and deserializer only decide
//! what to do with the answer.
//!
//! # Failing a V8 delegate hook
//!
//! The trait methods return `Option<...>`, where `None` means "an exception is
//! pending, stop now". V8 reads that as a failed serialization and propagates the
//! exception to the caller of `writeValue`/`readValue`. That is why a hook that
//! found no function to call has to throw rather than return a default: returning
//! a plausible value would silently produce a payload the other side cannot read.

use rn_v8_sys::v8;

/// Which exception a data-clone failure raises.
///
/// Node calls `this._getDataCloneError` as a constructor with the message, so the
/// class comes from JavaScript and `lib/v8.js` sets it to `Error`. Reading the
/// property is the point: a subclass can replace it, and the thrown object has to
/// be that class. The fallback below is only for a serializer used before
/// `lib/v8.js` ran, which cannot happen through the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// `Error`, carrying V8's own message.
    Error,
    /// `TypeError`, for a hook that could not be resolved at all.
    TypeError,
}

/// Calls `object[name](arguments…)`, returning the result.
///
/// A missing or non-callable property yields `None` *without* throwing, so the
/// caller can decide whether the absence is legal. `GetSharedArrayBufferId` is
/// the one hook where it is: Node falls back to the base delegate when the
/// JavaScript side never defined it.
pub fn call_hook<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    arguments: &[v8::Local<'s, v8::Value>],
) -> Option<v8::Local<'s, v8::Value>> {
    let value = read_hook(scope, object, name)?;
    let function = v8::Local::<v8::Function>::try_from(value).ok()?;
    let receiver: v8::Local<'s, v8::Value> = object.into();
    function.call(scope, receiver, arguments)
}

/// Reads `object[name]`.
pub fn read_hook<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

/// Throws `message` as `kind`, for a hook that could not be resolved.
///
/// The `code` property mirrors what `THROW_ERR_INVALID_ARG_TYPE` would produce,
/// so a caller inspecting the failure sees a Node-shaped error rather than a bare
/// `TypeError`.
pub fn throw_with_code(
    scope: &mut v8::PinScope<'_, '_>,
    kind: ErrorKind,
    code: &str,
    message: &str,
) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = match kind {
        ErrorKind::Error => v8::Exception::error(scope, text),
        ErrorKind::TypeError => v8::Exception::type_error(scope, text),
    };
    if let (Ok(object), Some(code_value)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, code),
    ) {
        if let Some(key) = v8::String::new(scope, "code") {
            let _ = object.set(scope, key.into(), code_value.into());
        }
    }
    scope.throw_exception(exception);
}

/// `THROW_ERR_CONSTRUCT_CALL_REQUIRED`, worded as Node words it.
///
/// `src/node_serdes.cc` throws this from inside the constructor callback rather
/// than using `ConstructorBehavior::kThrow`, because the prototype has to stay
/// attached to the function for `class DefaultSerializer extends Serializer` to
/// work.
pub fn throw_construct_call_required(scope: &mut v8::PinScope<'_, '_>, class: &str) {
    let message = format!("Class constructor {class} cannot be invoked without 'new'");
    throw_with_code(
        scope,
        ErrorKind::TypeError,
        "ERR_CONSTRUCT_CALL_REQUIRED",
        &message,
    );
}

/// `THROW_ERR_INVALID_ARG_TYPE`, which every argument check in this namespace
/// uses.
pub fn throw_invalid_arg_type(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    throw_with_code(scope, ErrorKind::TypeError, "ERR_INVALID_ARG_TYPE", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fallback_kinds_are_the_two_node_uses() {
        // `ThrowDataCloneError` calls JavaScript, which supplies the class;
        // everything else is a plain `TypeError`. Pinning them here keeps a
        // future hook from quietly picking the wrong one.
        assert_ne!(ErrorKind::Error, ErrorKind::TypeError);
    }
}
