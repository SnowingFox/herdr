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

use crate::copy_tree::CopyError;
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

/// Classifies a call whose request slot is a *fixed* position, not the tail.
///
/// `stat` and `fstat` are the two members whose request argument is followed by
/// a real operand, so [`classify`] must not be pointed at their last argument.
/// Both JS shapes are `stat(path, useBigint, req, throwIfNoEntry)` and
/// `fstat(fd, useBigint, req, shouldNotThrow)`, and `src/node_file.cc` reads
/// slot 2 in both:
///
/// ```text
/// if (!args[2]->IsUndefined()) {  // stat(path, use_bigint, req, ...)
///   FSReqBase* req_wrap_async = GetReqWrap(args, 2, use_bigint);
/// ```
///
/// The distinction is load-bearing rather than cosmetic. `fs.promises.stat`
/// passes `options.throwIfNoEntry`, which defaults to `true`, as slot 3 — so
/// classifying the *tail* answered "synchronous" for a promise-mode call. The
/// binding then returned the raw `Float64Array`/`BigInt64Array` of stat slots
/// where `internal/fs/promises.js` awaited it, and `await` on a typed array
/// throws `TypeError: Method Promise.prototype.then called on incompatible
/// receiver`. `lstat` is three arguments long, so its request slot *is* the
/// tail and it never showed the bug.
///
/// `undefined` in the slot means "no request", which is what the callback-free
/// `binding.stat(path, bigint, undefined, throwIfNoEntry)` sync form passes.
pub fn classify_slot<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    index: i32,
) -> (Delivery, Option<Local<'s, v8::Object>>) {
    if args.length() <= index {
        return classify(scope, None);
    }
    let slot = args.get(index);
    // Only an absent slot falls through to `classify`; `undefined` here is the
    // sync form's explicit "no request", which `classify` also answers.
    classify(scope, Some(slot))
}

/// Detects the `kUsePromises` sentinel.
///
/// The symbol is created once at install time and published as a property on
/// the namespace object; the JS layer passes that exact value back in the
/// request slot. Identity comparison is what makes this robust — the property
/// name is incidental, and a user-created symbol with the same description must
/// not be mistaken for it.
fn is_use_promises<'s>(scope: &mut v8::PinScope<'s, '_>, value: Local<'s, v8::Value>) -> bool {
    let Some(sentinel) = sentinel(scope) else {
        return false;
    };
    value.strict_equals(sentinel)
}

thread_local! {
    /// The `kUsePromises` sentinel this realm published.
    ///
    /// Thread-local rather than a V8 context slot, which is where it used to live.
    /// A context slot is stored in the context's Rust-side annex, and a snapshot
    /// build pays for it twice: the annex entry makes `CreateBlob` abort naming a
    /// `NativeContext`, and the `Global` it held is a second root the serializer
    /// has to be told about. A thread-local costs neither, and it is the same
    /// lifetime the annex had — one realm per thread.
    ///
    /// Identity still has to survive a snapshot load, which is what
    /// [`attach_for_snapshot`] and [`restore_from_snapshot`] are for.
    static SENTINEL: std::cell::RefCell<Option<v8::Global<v8::Value>>> =
        const { std::cell::RefCell::new(None) };
}

/// The sentinel this realm published, as a handle in `scope`.
fn sentinel<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<Local<'s, v8::Value>> {
    SENTINEL.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|sentinel| Local::new(scope, sentinel))
    })
}

/// Publishes the `kUsePromises` sentinel on the namespace object and remembers it.
pub fn install_sentinel<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    namespace: Local<'s, Object>,
) -> Option<Local<'s, v8::Symbol>> {
    let description = v8::String::new(scope, "kUsePromises")?;
    let sentinel = v8::Symbol::new(scope, Some(description));
    let key = v8::String::new(scope, "kUsePromises")?;
    namespace.set(scope, key.into(), sentinel.into())?;

    let value: Local<v8::Value> = sentinel.into();
    let rooted = v8::Global::new(scope.as_ref(), value);
    SENTINEL.with(|slot| *slot.borrow_mut() = Some(rooted));
    Some(sentinel)
}

/// Hands the sentinel to the snapshot build so it is carried across the blob.
///
/// Registered with `rn_core::snapshot_data`. Attaching the symbol is what makes it
/// serialisable at all: the namespace property alone would be reachable from the
/// context, but the thread-local `Global` rooting it is not, and `add_context_data`
/// is what tells V8 the object belongs in the blob. The `Global` is left in place —
/// dropping it would make this realm's `is_use_promises` stop recognising calls
/// between now and `CreateBlob`.
pub fn attach_for_snapshot<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _context: Local<'s, v8::Context>,
) -> Local<'s, v8::Data> {
    match sentinel(scope) {
        Some(sentinel) => sentinel.into(),
        // A realm that never installed `fs` has no sentinel, and an absent one is
        // not an error. `undefined` still occupies this provider's index, which is
        // what keeps the load side's numbering aligned.
        None => v8::undefined(scope).into(),
    }
}

/// Puts the sentinel back from the blob, so `is_use_promises` recognises it again.
///
/// The symbol the load hands back is the *same object* the serialised namespace
/// property points at, because V8 serialised one object and both references are to
/// it. That is exactly the property `install_sentinel` establishes at build time,
/// so a loaded realm classifies `openFileHandle(…, kUsePromises)` as a promise call
/// rather than falling through to the callback path.
pub fn restore_from_snapshot(
    scope: &mut v8::PinScope<'_, '_>,
    data: Local<'_, v8::Data>,
) -> Result<(), String> {
    let Some(symbol) = Local::<v8::Value>::try_from(data).ok() else {
        return Err("the blob's fs entry is not a value".to_string());
    };
    if symbol.is_undefined() {
        // This realm installed `fs` without a sentinel, which is the state
        // `install_sentinel` refuses to produce; treat it as nothing to restore.
        SENTINEL.with(|slot| *slot.borrow_mut() = None);
        return Ok(());
    }
    if !symbol.is_symbol() {
        return Err("the blob's fs entry is not the kUsePromises symbol".to_string());
    }
    let rooted = v8::Global::new(scope.as_ref(), symbol);
    SENTINEL.with(|slot| *slot.borrow_mut() = Some(rooted));
    Ok(())
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

/// Builds the exception `cp`'s error variants turn into.
///
/// Three distinct shapes are reachable from `fs.cp`, and a caller can tell them
/// apart from the object it receives:
///
/// * [`CopyError::Errno`] is an `ErrnoException`: the message is
///   `CODE, strerror 'path'`, the leading name is the symbolic errno, `errno` is
///   positive, and there is no syscall term in the text.
/// * [`CopyError::Uv`] is a `UVException`: `CODE: uv_strerror, syscall 'path'`
///   and a negated `errno`.
/// * the `ERR_FS_CP_*` variants are plain errors with a `code`, an `errno` and
///   the message the C++ formatted — including the `[CODE]: ` prefix that
///   `ERR_FS_CP_EEXIST` carries inside its own text.
///
/// [`CopyError::Special`] is absent: a socket, FIFO or unknown entry is reported
/// to the asynchronous caller as a kind and a path so the JavaScript layer builds
/// the error, and `fs.cpSync` never reports one at all.
pub fn copy_error_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    error: &CopyError,
) -> Option<Local<'s, v8::Value>> {
    match error {
        CopyError::Errno {
            errno,
            syscall,
            path,
        } => {
            let raw = errno.abs().max(1);
            let errno_text = code_for_code_point(raw);
            let mut message = String::from(errno_text);
            message.push_str(", ");
            message.push_str(description_for_code_point(raw));
            message.push_str(" '");
            message.push_str(&String::from_utf8_lossy(path));
            message.push('\'');
            let text = v8::String::new(scope, &message)?;
            let exception = v8::Exception::error(scope, text);
            let object: Local<v8::Object> = exception.try_into().ok()?;
            set_ordinal(scope, object, "errno", raw)?;
            let code = v8::String::new(scope, errno_text)?;
            set(scope, object, "code", code.into())?;
            let syscall = v8::String::new(scope, syscall)?;
            set(scope, object, "syscall", syscall.into())?;
            let path = v8::String::new(scope, &String::from_utf8_lossy(path))?;
            set(scope, object, "path", path.into())?;
            Some(exception)
        }
        CopyError::Uv {
            errno,
            syscall,
            path,
        } => error_object(
            scope,
            &FsError::from_errno(syscall, errno.abs()).path(path.clone()),
        ),
        CopyError::Einval(message) => {
            cp_code_error(scope, "ERR_FS_CP_EINVAL", message, libc::EINVAL)
        }
        CopyError::SymlinkToSubdirectory(message) => cp_code_error(
            scope,
            "ERR_FS_CP_SYMLINK_TO_SUBDIRECTORY",
            message,
            libc::EINVAL,
        ),
        CopyError::Eexist(message) => {
            cp_code_error(scope, "ERR_FS_CP_EEXIST", message, libc::EEXIST)
        }
        CopyError::Eisdir(message) => cp_code_error(scope, "ERR_FS_EISDIR", message, libc::EISDIR),
        CopyError::Special { .. } => None,
    }
}

/// An `ERR_FS_CP_*` error: `code`, `errno`, and the message already formatted.
fn cp_code_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    code: &str,
    message: &str,
    errno: i32,
) -> Option<Local<'s, v8::Value>> {
    let text = v8::String::new(scope, message)?;
    let exception = v8::Exception::error(scope, text);
    let object: Local<v8::Object> = exception.try_into().ok()?;
    let code = v8::String::new(scope, code)?;
    set(scope, object, "code", code.into())?;
    set_ordinal(scope, object, "errno", errno)?;
    Some(exception)
}

fn set_ordinal<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: Local<v8::Object>,
    key: &str,
    value: i32,
) -> Option<()> {
    set(scope, object, key, v8::Integer::new(scope, value).into())
}

/// The symbolic errno name for a positive errno, as `errno_string` renders it.
fn code_for_code_point(errno: i32) -> &'static str {
    crate::error::code_for_errno(errno)
}

/// libuv's `uv_strerror` text for a positive errno.
fn description_for_code_point(errno: i32) -> &'static str {
    crate::error::description_for_errno(errno)
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
