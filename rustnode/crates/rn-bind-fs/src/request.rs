//! Request shapes and error objects.
//!
//! `lib/fs.js` calls every binding member in one of three shapes and expects a
//! specific reply for each:
//!
//! | trailing argument | call shape | binding must |
//! | --- | --- | --- |
//! | absent | synchronous | return the value, or throw |
//! | `FSReqCallback` instance | callback | return `undefined`, later call `req.oncomplete(...)` |
//! | `kUsePromises` symbol | promise | return a `Promise` |
//!
//! The distinction is made by inspecting the trailing argument, exactly as
//! `GetReqWrap()` does in `src/node_file.cc`: an object is a callback request,
//! and the `kUsePromises` sentinel is a symbol created by this binding at
//! install time. Everything about *delivering* the result lives in
//! `complete.rs`; this module only classifies and builds error values.

use rn_v8_sys::v8;
use rn_v8_sys::v8::{Local, Object};

use crate::error::FsError;

/// Which delivery mode an operation's trailing argument selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// No request argument: return the value or throw.
    Sync,
    /// An `FSReqCallback` instance: call `req.oncomplete` later.
    Callback,
    /// The `kUsePromises` symbol: return a promise.
    Promise,
}

/// Classifies a call from its trailing argument.
///
/// Node tests `value->IsObject()` rather than checking for a specific
/// constructor, so a plain `{}` selects callback mode too. Matching that keeps
/// any `fs` internals that pass their own object working.
pub fn classify<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    tail: Option<Local<'s, v8::Value>>,
) -> (Delivery, Option<Local<'s, v8::Object>>) {
    let Some(tail) = tail else {
        return (Delivery::Sync, None);
    };
    if tail.is_object() && !tail.is_null() {
        if let Ok(object) = Local::<v8::Object>::try_from(tail) {
            return (Delivery::Callback, Some(object));
        }
    }
    if is_use_promises(scope, tail) {
        return (Delivery::Promise, None);
    }
    // Node returns `nullptr` from `GetReqWrap` for anything else, which its
    // callers treat as "no request" and then run the synchronous path. Several
    // internal callers pass `undefined` explicitly to mean synchronous.
    (Delivery::Sync, None)
}

/// Detects the `kUsePromises` sentinel.
///
/// The symbol is created once at install time and published as a property on
/// the namespace object; the JS layer passes that exact value back in the
/// request slot. Identity comparison is what makes this robust — the property
/// name is incidental, and a user-created symbol with the same description must
/// not be mistaken for it.
fn is_use_promises<'s>(scope: &mut v8::PinScope<'s, '_>, value: Local<'s, v8::Value>) -> bool {
    let context = scope.get_current_context();
    let Some(sentinel) = context.get_slot::<Sentinel>() else {
        return false;
    };
    let sentinel: Local<v8::Value> = Local::new(scope, &sentinel.0);
    value.strict_equals(sentinel)
}

/// Context-slot payload holding the sentinel symbol.
///
/// A V8 context slot is used rather than a global property so user JavaScript
/// cannot overwrite the sentinel and silently change the meaning of a call.
struct Sentinel(v8::Global<v8::Value>);

/// Publishes the `kUsePromises` sentinel on the namespace object and records it
/// in a context slot for `is_use_promises`.
pub fn install_sentinel<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    namespace: Local<'s, Object>,
) -> Option<Local<'s, v8::Symbol>> {
    let description = v8::String::new(scope, "kUsePromises")?;
    let sentinel = v8::Symbol::new(scope, Some(description));
    let key = v8::String::new(scope, "kUsePromises")?;
    namespace.set(scope, key.into(), sentinel.into())?;

    // The symbol belongs to this context, so it is rooted next to it rather than
    // in a process-wide static.
    let symbol: Local<v8::Value> = sentinel.into();
    let rooted = v8::Global::new(scope.as_ref(), symbol);
    scope
        .get_current_context()
        .set_slot(std::rc::Rc::new(Sentinel(rooted)));
    Some(sentinel)
}

/// Builds the `Error` object Node's `UVException` would have produced.
///
/// Fidelity matters more than it looks: `err.code` and `err.errno` are asserted
/// by user code and by Node's own tests, and `err.message` appears in snapshots.
pub fn error_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    error: &FsError,
) -> Option<Local<'s, v8::Value>> {
    let message = v8::String::new(scope, &error.message())?;
    let exception = v8::Exception::error(scope, message);
    let object: Local<v8::Object> = exception.try_into().ok()?;

    let errno = v8::Number::new(scope, f64::from(error.errno));
    set(scope, object, "errno", errno.into())?;
    let code = v8::String::new(scope, error.code())?;
    set(scope, object, "code", code.into())?;
    let syscall = v8::String::new(scope, error.syscall)?;
    set(scope, object, "syscall", syscall.into())?;

    if let Some(path) = &error.path {
        let text = String::from_utf8_lossy(path);
        let value = v8::String::new(scope, &text)?;
        set(scope, object, "path", value.into())?;
    }
    if let Some(dest) = &error.dest {
        let text = String::from_utf8_lossy(dest);
        let value = v8::String::new(scope, &text)?;
        set(scope, object, "dest", value.into())?;
    }

    Some(exception)
}

fn set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: Local<v8::Object>,
    key: &str,
    value: Local<v8::Value>,
) -> Option<()> {
    let key = v8::String::new(scope, key)?;
    object.set(scope, key.into(), value)?;
    Some(())
}

/// Throws `error`, for the synchronous calling convention.
pub fn throw_error(scope: &mut v8::PinScope<'_, '_>, error: &FsError) {
    if let Some(value) = error_object(scope, error) {
        scope.throw_exception(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testsupport::with_context as with_scope;

    #[test]
    fn absent_request_is_synchronous() {
        with_scope(|scope| {
            let (mode, object) = classify(scope, None);
            assert_eq!(mode, Delivery::Sync);
            assert!(object.is_none());
        });
    }

    #[test]
    fn object_request_is_a_callback() {
        with_scope(|scope| {
            let value = v8::Object::new(scope);
            let (mode, object) = classify(scope, Some(value.into()));
            assert_eq!(mode, Delivery::Callback);
            assert!(object.is_some());
        });
    }

    #[test]
    fn undefined_request_falls_back_to_synchronous() {
        with_scope(|scope| {
            let value = v8::undefined(scope);
            let (mode, _) = classify(scope, Some(value.into()));
            assert_eq!(mode, Delivery::Sync);
        });
    }

    #[test]
    fn sentinel_selects_promise_mode_by_identity() {
        with_scope(|scope| {
            let namespace = v8::Object::new(scope);
            let sentinel = install_sentinel(scope, namespace).expect("sentinel");
            let (mode, _) = classify(scope, Some(sentinel.into()));
            assert_eq!(mode, Delivery::Promise);

            // A lookalike symbol with the same description must not match.
            let description = v8::String::new(scope, "kUsePromises").expect("description");
            let lookalike = v8::Symbol::new(scope, Some(description));
            let (mode, _) = classify(scope, Some(lookalike.into()));
            assert_eq!(mode, Delivery::Sync);
        });
    }

    #[test]
    fn error_object_carries_node_properties() {
        with_scope(|scope| {
            let error = FsError::from_errno("stat", libc::ENOENT).path("/nope-xyz");
            let value = error_object(scope, &error).expect("error object");
            let object: Local<v8::Object> = value.try_into().expect("is an object");

            let read = |scope: &mut v8::PinScope<'_, '_>, key: &str| -> String {
                let key = v8::String::new(scope, key).expect("key");
                object
                    .get(scope, key.into())
                    .map(|value| value.to_rust_string_lossy(scope))
                    .unwrap_or_default()
            };

            assert_eq!(read(scope, "code"), "ENOENT");
            assert_eq!(read(scope, "syscall"), "stat");
            assert_eq!(read(scope, "path"), "/nope-xyz");
            assert_eq!(read(scope, "errno"), "-2");
            assert_eq!(
                read(scope, "message"),
                "ENOENT: no such file or directory, stat '/nope-xyz'"
            );
        });
    }

    #[test]
    fn error_object_omits_absent_path() {
        with_scope(|scope| {
            let error = FsError::from_errno("close", libc::EBADF);
            let value = error_object(scope, &error).expect("error object");
            let object: Local<v8::Object> = value.try_into().expect("is an object");
            let key = v8::String::new(scope, "path").expect("key");
            let path = object.get(scope, key.into()).expect("get");
            // Node's `UVException` only assigns `path` when the context has one,
            // so the property is simply absent and reads back as `undefined`.
            assert!(path.is_undefined());
            assert!(!path.is_string());
        });
    }

    #[test]
    fn error_object_reports_dest_for_two_path_calls() {
        with_scope(|scope| {
            let error = FsError::from_errno("rename", libc::EXDEV)
                .path("/a")
                .dest("/b");
            let value = error_object(scope, &error).expect("error object");
            let object: Local<v8::Object> = value.try_into().expect("is an object");
            let key = v8::String::new(scope, "dest").expect("key");
            let dest = object.get(scope, key.into()).expect("dest");
            assert_eq!(dest.to_rust_string_lossy(scope), "/b");
        });
    }
}
