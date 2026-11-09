//! `ShutdownWrap` and `WriteWrap`, and the completion protocol for both.
//!
//! # The shape Node builds, and why each part matters
//!
//! `src/stream_wrap.cc`'s `Initialize` creates one `FunctionTemplate` for each
//! request type and pre-creates the fields JavaScript attaches, so the object
//! shape stays monomorphic:
//!
//! | field | set by | read by |
//! | --- | --- | --- |
//! | `oncomplete` | `lib/net.js` / `lib/internal/stream_base_commons.js` | this crate |
//! | `callback` | `lib/net.js` (`ShutdownWrap`) | `afterShutdown` |
//! | `handle` | `lib/net.js` / `afterWriteDispatched` | `onWriteComplete` |
//! | `async` | `afterWriteDispatched` | `writevGeneric`'s caller |
//! | `bytes` | `afterWriteDispatched` | same |
//! | `buffer` | `afterWriteDispatched` | keeps the data alive |
//! | `writeStatus` | this crate, when a write finished inline | `afterWriteDispatched` |
//!
//! `writeStatus` is the subtle one. A write can complete inside the
//! `handle.writeBuffer(...)` call, before JavaScript has had a chance to assign
//! `req.oncomplete` — it cannot, because the `req` object is the *return value*.
//! Node records the status on the object (`ReportWritesToJSStreamListener::
//! OnStreamAfterReqFinished`) and `afterWriteDispatched` replays it:
//!
//! ```js
//! const status = req.writeStatus;
//! if (status !== null) {
//!   req.writeStatus = null;
//!   req.oncomplete(status);
//! }
//! ```
//!
//! So this crate must set `writeStatus` to a number and *not* try to call a
//! `null` `oncomplete`, and it must leave `writeStatus` as `null` on a request
//! that completed later, because a stale number would fire the callback twice.
//!
//! # Why the wraps carry no libuv state
//!
//! A `WriteWrap` is a JavaScript object JavaScript owns; the `uv_write_t` lives
//! in the socket binding, and its completion finds the wrap through the handle.
//! Keeping them separate is what lets `lib/net.js` construct a `ShutdownWrap`
//! with no native call at all (`new ShutdownWrap()` then `handle.shutdown(req)`).

use rn_v8_sys::v8;

/// Field index holding the request's native completion state.
///
/// Node uses internal fields for `AsyncWrap` bookkeeping; rustnode needs only a
/// place to park the handle a write is bound to, which is the same slot for both
/// request types.
const COMPLETION_FIELD: i32 = 0;

/// One request type's JavaScript-side contract.
///
/// Public because it appears in [`constructor`]'s signature.
pub trait RequestKind {
    /// The class name `FunctionTemplate::SetClassName` publishes.
    const NAME: &'static str;
    /// The fields Node pre-creates on the instance template, so instances are
    /// monomorphic.
    const FIELDS: &'static [&'static str];
    /// The fields pre-created with `false` rather than `null`.
    const BOOLEAN_FIELDS: &'static [&'static str];
    /// The fields pre-created with `0` rather than `null`.
    const NUMBER_FIELDS: &'static [&'static str];
}

/// `ShutdownWrap`, as `src/stream_wrap.cc` builds it.
pub struct ShutdownWrap;

/// `WriteWrap`, as `src/stream_wrap.cc` builds it.
pub struct WriteWrap;

impl RequestKind for ShutdownWrap {
    const NAME: &'static str = "ShutdownWrap";
    // `sw->InstanceTemplate()->Set(...)` sets exactly these three to null, with
    // the comment "we need to set handle and callback to null, so that those
    // fields are created and functions do not become megamorphic".
    const FIELDS: &'static [&'static str] = &["oncomplete", "callback", "handle"];
    const BOOLEAN_FIELDS: &'static [&'static str] = &[];
    const NUMBER_FIELDS: &'static [&'static str] = &[];
}

impl RequestKind for WriteWrap {
    const NAME: &'static str = "WriteWrap";
    const FIELDS: &'static [&'static str] = &[
        "oncomplete",
        "callback",
        "handle",
        "buffer",
        // The slot `afterWriteDispatched` replays a synchronous completion out
        // of. Node initialises it to null, and only a write that finished
        // before JS could attach `oncomplete` writes a number here.
        "writeStatus",
    ];
    const BOOLEAN_FIELDS: &'static [&'static str] = &["async"];
    const NUMBER_FIELDS: &'static [&'static str] = &["bytes"];
}

/// Builds the constructor for a request type.
///
/// Each is `new`-only: `src/stream_wrap.cc`'s `IsConstructCallCallback` does
/// `CHECK(args.IsConstructCall())`, so calling one without `new` aborts Node.
/// rustnode throws a `TypeError` instead — the same failure, without the crash.
///
/// Note that this is *not* `ConstructorBehavior::Throw`: that makes the function
/// refuse `new` as well, which would defeat the whole point. The construct check
/// happens inside the callback.
pub fn constructor<'s, K: RequestKind>(
    scope: &mut v8::PinScope<'s, '_>,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);

    let instance = template.instance_template(scope);
    // One internal field, which is where a write parks the socket it belongs to
    // so a completion can find it. `ShutdownWrap::kInternalFieldCount` and
    // `WriteWrap::kInternalFieldCount` are both 1 in Node.
    instance.set_internal_field_count(1);

    let null = v8::null(scope);
    for field in K::FIELDS {
        let key = v8::String::new(scope, field).ok_or("cannot allocate a request field name")?;
        instance.set(key.into(), null.into());
    }
    let false_value = v8::Boolean::new(scope, false);
    for field in K::BOOLEAN_FIELDS {
        let key = v8::String::new(scope, field).ok_or("cannot allocate a request field name")?;
        instance.set(key.into(), false_value.into());
    }
    let zero = v8::Integer::new(scope, 0);
    for field in K::NUMBER_FIELDS {
        let key = v8::String::new(scope, field).ok_or("cannot allocate a request field name")?;
        instance.set(key.into(), zero.into());
    }

    let Some(text) = v8::String::new(scope, K::NAME) else {
        return Err(format!("cannot allocate the name {}", K::NAME));
    };
    template.set_class_name(text);

    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {}", K::NAME))?;
    function.set_name(text);
    Ok(function.into())
}

/// The `ShutdownWrap` constructor callback.
///
/// Node's is `IsConstructCallCallback`, which only clears the request's state.
/// `new ShutdownWrap()` therefore produces an object with the pre-created fields
/// and nothing else; `lib/net.js` fills `oncomplete`, `handle` and `callback`
/// immediately afterwards and then calls `handle.shutdown(req)`.
pub fn shutdown_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_not_constructor(scope, "ShutdownWrap");
        return;
    }
    let object = args.this();
    clear_completion(scope, object);
    rv.set(object.into());
}

/// The `WriteWrap` constructor callback.
///
/// Native code calls this to build a request object for a write that did not
/// complete inline (`StreamBase::Write`'s `InstanceTemplate()->NewInstance`
/// path), and `lib/internal/stream_base_commons.js` never constructs one
/// directly. It is exported so `internalBinding('stream_wrap').WriteWrap` exists,
/// as it does in Node.
pub fn write_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_not_constructor(scope, "WriteWrap");
        return;
    }
    let object = args.this();
    clear_completion(scope, object);
    rv.set(object.into());
}

/// Resets the internal field, matching `StreamReq::ResetObject`.
fn clear_completion(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) {
    let empty = v8::undefined(scope);
    object.set_internal_field(COMPLETION_FIELD as usize, empty.into());
}

/// Throws the `TypeError` Node's `CHECK` amounts to, without the abort.
fn throw_not_constructor(scope: &mut v8::PinScope<'_, '_>, name: &str) {
    let message = format!("Class constructor {name} cannot be invoked without 'new'");
    if let Some(text) = v8::String::new(scope, &message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

/// The status a completed write or shutdown reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// The request finished, with libuv's status (0 for success).
    Done(i32),
}

/// Delivers a completion to a request object's `oncomplete`, or parks it when
/// JavaScript has not attached one yet.
///
/// This is `ReportWritesToJSStreamListener::OnStreamAfterReqFinished`: if
/// `oncomplete` is a function, call it with `(status, handle, undefined)`; if it
/// is not, record the status in `writeStatus` so `afterWriteDispatched` can
/// replay it once it has the request object.
///
/// Returns whether the handler was called.
pub fn report_completion(
    scope: &mut v8::PinScope<'_, '_>,
    request: v8::Local<v8::Object>,
    status: i32,
    handle: Option<v8::Local<v8::Object>>,
    error: Option<&str>,
) -> bool {
    let Some(oncomplete_key) = v8::String::new(scope, "oncomplete") else {
        return false;
    };
    let Some(value) = request.get(scope, oncomplete_key.into()) else {
        return false;
    };
    let Ok(handler) = v8::Local::<v8::Function>::try_from(value) else {
        // Not attached yet. `afterWriteDispatched` checks `writeStatus !== null`
        // on the object it just received and replays the call, so the number has
        // to be there even though nobody is listening now.
        if let Some(status_key) = v8::String::new(scope, "writeStatus") {
            request.set(
                scope,
                status_key.into(),
                v8::Integer::new(scope, status).into(),
            );
        }
        if let Some(text) = error {
            if let Some(error_key) = v8::String::new(scope, "error") {
                if let Some(message) = v8::String::new(scope, text) {
                    request.set(scope, error_key.into(), message.into());
                }
            }
        }
        return false;
    };

    let status_value: v8::Local<v8::Value> = v8::Integer::new(scope, status).into();
    // `handle` is `stream->GetObject()`, the socket the write belongs to. The
    // completion for a shutdown has it too; a `ShutdownWrap` therefore also gets
    // three arguments, which `lib/net.js`'s `afterShutdown` ignores because it
    // reads `this.handle` instead.
    let handle_value: v8::Local<v8::Value> = match handle {
        Some(handle) => handle.into(),
        None => v8::undefined(scope).into(),
    };
    let error_value: v8::Local<v8::Value> = match error {
        Some(text) => match v8::String::new(scope, text) {
            Some(text) => text.into(),
            None => v8::undefined(scope).into(),
        },
        None => v8::undefined(scope).into(),
    };

    let receiver: v8::Local<v8::Value> = request.into();
    let _ = handler.call(scope, receiver, &[status_value, handle_value, error_value]);
    true
}

/// Sets `request.oncomplete`, which is what a native completion looks for.
///
/// Node's templates pre-create the field, so this is a plain assignment; it
/// exists as a function so the write path and the tests agree on the name.
pub fn set_oncomplete(
    scope: &mut v8::PinScope<'_, '_>,
    request: v8::Local<v8::Object>,
    handler: v8::Local<v8::Function>,
) -> bool {
    let Some(key) = v8::String::new(scope, "oncomplete") else {
        return false;
    };
    request.set(scope, key.into(), handler.into());
    true
}

/// Reads `request.handle`, the socket a request belongs to.
pub fn handle_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    request: v8::Local<v8::Object>,
) -> Option<v8::Local<'s, v8::Object>> {
    let key = v8::String::new(scope, "handle")?;
    let value = request.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Reads `request.oncomplete` as a function, if JavaScript attached one.
pub fn oncomplete_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    request: v8::Local<v8::Object>,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, "oncomplete")?;
    let value = request.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_request_kinds_match_node_field_for_field() {
        // `src/stream_wrap.cc`: ShutdownWrap pre-creates oncomplete, callback and
        // handle; WriteWrap additionally pre-creates async, bytes, buffer and
        // writeStatus. A missing field is not a crash, it is a deoptimised
        // object that `lib/net.js` then writes through a slow path.
        assert_eq!(
            <ShutdownWrap as RequestKind>::FIELDS,
            &["oncomplete", "callback", "handle"]
        );
        assert_eq!(
            <WriteWrap as RequestKind>::FIELDS,
            &["oncomplete", "callback", "handle", "buffer", "writeStatus"]
        );
        assert_eq!(<WriteWrap as RequestKind>::BOOLEAN_FIELDS, &["async"]);
        assert_eq!(<WriteWrap as RequestKind>::NUMBER_FIELDS, &["bytes"]);
    }
}
