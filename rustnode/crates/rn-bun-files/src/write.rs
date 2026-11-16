//! `Bun.write(destination, data)`.
//!
//! # The destination
//!
//! A path string, an open file descriptor, or a `Bun.file`. The `Bun.file` case
//! is what makes `Bun.write(Bun.file("out.txt"), "x")` work: the write goes to
//! the path the Blob names, not to the Blob.
//!
//! # The payload
//!
//! A string, `Uint8Array`, `ArrayBuffer`, `Blob`, `ReadableStream` or
//! `Response`. Numbers are **coerced**, not rejected: `Bun.write(p, 42)` writes
//! `"42"` (two bytes), so the payload test cannot be "is this blob-y".
//!
//! # Parent directories are created
//!
//! Measured: `Bun.write("deep/nested/x.txt", "created")` succeeds with no
//! `mkdir`. Node's `fs.writeFile` throws `ENOENT` there, so this is a real
//! divergence and copying Node's behaviour would be the wrong choice.
//!
//! # Two argument errors with different wording
//!
//! A missing destination uses Node's validator phrasing
//! (`The "destination" argument must be of type path, file descriptor, or Blob.
//! Received undefined`); a missing payload uses Bun's own
//! (`Bun.write(pathOrFdOrBlob, blob) expects a Blob-y thing to write`). Both are
//! **synchronous** throws: measured, the arguments are checked before any
//! promise exists, so `try { Bun.write() } catch` catches them.
//!
//! # Two paths, one for each kind of payload
//!
//! A string, number, `ArrayBuffer` or view is copied synchronously and the
//! promise is settled before it is returned — which is still a promise, because
//! the observable contract is `await Bun.write(...)` either way.
//!
//! A `Blob`, `Response` or `ReadableStream` has to be drained through its own
//! asynchronous API, so the path is chained: the payload's bytes promise gets a
//! `then` whose handler writes and settles the promise this call returns.

use std::io::Write;

use rn_v8_sys::v8;

use crate::blob;
use crate::error::{self, SyscallError};

/// A `Bun.write` destination.
#[derive(Debug, Clone)]
pub enum Target {
    /// A filesystem path, written by creating it (and its parents).
    Path(String),
    /// An open descriptor, written in place and left open.
    Descriptor(i32),
}

/// `Bun.write(destination, data)`.
pub fn bun_write<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s, v8::Value>,
) {
    let destination = args.get(0);
    let Some(target) = write_target(scope, destination) else {
        let received = describe(scope, destination);
        error::throw_invalid_arg(
            scope,
            &format!(
                "The \"destination\" argument must be of type path, file descriptor, or Blob. Received {received}"
            ),
        );
        return;
    };

    let payload = args.get(1);
    if args.length() < 2 || payload.is_null_or_undefined() {
        error::throw_invalid_arg(
            scope,
            "Bun.write(pathOrFdOrBlob, blob) expects a Blob-y thing to write",
        );
        return;
    }

    if needs_async_drain(scope, payload) {
        write_async(scope, rv, target, payload);
        return;
    }

    let Some(result) = payload_bytes(scope, payload) else {
        error::throw_invalid_arg(
            scope,
            "Bun.write(pathOrFdOrBlob, blob) expects a Blob-y thing to write",
        );
        return;
    };
    match result {
        Ok(bytes) => settle(scope, rv, write_to(&target, &bytes)),
        Err(reason) => error::throw_type_error(scope, &reason),
    }
}

/// Interprets the destination argument.
fn write_target<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Target> {
    if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
        return Some(Target::Path(text.to_rust_string_lossy(scope)));
    }
    if value.is_number() {
        return Some(Target::Descriptor(value.number_value(scope)? as i32));
    }
    if let Ok(object) = v8::Local::<v8::Object>::try_from(value) {
        // A `Bun.file` carries the path it was built from, so writing to one
        // targets that path. A plain `Blob` has no `name`, so it is refused
        // rather than guessed at.
        if let Some(name) = property(scope, object, "name") {
            if let Ok(name) = v8::Local::<v8::String>::try_from(name) {
                return Some(Target::Path(name.to_rust_string_lossy(scope)));
            }
        }
    }
    None
}

fn property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    let value = object.get(scope, key.into())?;
    if value.is_undefined() {
        None
    } else {
        Some(value)
    }
}

/// The text Node's validator puts after `Received`.
fn describe(scope: &mut v8::PinScope, value: v8::Local<v8::Value>) -> String {
    if value.is_undefined() {
        return "undefined".to_string();
    }
    if value.is_null() {
        return "null".to_string();
    }
    value
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_else(|| "an unknown value".to_string())
}

/// The bytes a synchronous payload holds.
fn payload_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Result<Vec<u8>, String>> {
    if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
        return Some(Ok(text.to_rust_string_lossy(scope).into_bytes()));
    }

    // Anything else that is not binary is `String()`-coerced, not rejected.
    // Measured on Bun 1.4.4: `Bun.write(p, {a: 1})` writes `"[object Object]"`,
    // `[1, 2]` writes `"12"`, and a function writes its source text. Numbers and
    // booleans are the same rule, which is why they need no separate arm. `null`
    // and `undefined` are the only refusals.
    if value.is_null() || value.is_undefined() {
        return None;
    }
    if let Some(bytes) = binary_bytes(scope, value) {
        return Some(Ok(bytes));
    }
    value
        .to_string(scope)
        .map(|text| Ok(text.to_rust_string_lossy(scope).into_bytes()))
}

/// Bytes of an `ArrayBuffer` or any view over one.
fn binary_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Vec<u8>> {
    let (buffer, offset, length) = if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value)
    {
        (buffer, 0, buffer.byte_length())
    } else if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        (view.buffer(scope)?, view.byte_offset(), view.byte_length())
    } else {
        return None;
    };

    let store = buffer.get_backing_store();
    let mut bytes = vec![0u8; length];
    if length == 0 {
        return Some(bytes);
    }
    let Some(data) = store.data() else {
        // A detached buffer has no pointer; its content is nothing.
        return Some(bytes);
    };
    // SAFETY: the backing store is alive for the duration of this copy, and
    // `offset + length` lies inside it because that is how the view was built.
    unsafe {
        let source = data.as_ptr().cast::<u8>().add(offset);
        std::ptr::copy_nonoverlapping(source, bytes.as_mut_ptr(), length);
    }
    Some(bytes)
}

/// Whether a payload has to be drained through its own asynchronous API.
///
/// A `ReadableStream`, a `Blob` and a `Response` all answer `getReader()` or
/// `arrayBuffer()`. Everything else this function accepts is copied directly.
fn needs_async_drain<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> bool {
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return false;
    };
    property(scope, object, "getReader").is_some()
        || property(scope, object, "arrayBuffer").is_some()
}

/// Writes a synchronous payload to `target`, for `Bun.file(...).write`.
///
/// `None` means the payload is not a byte sequence this can copy synchronously,
/// which is the same answer [`payload_bytes`] gives.
pub fn write_payload<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: &Target,
    payload: v8::Local<'s, v8::Value>,
) -> Option<Result<usize, SyscallError>> {
    match payload_bytes(scope, payload)? {
        Ok(bytes) => Some(write_to(target, &bytes)),
        Err(reason) => Some(Err(SyscallError {
            errno: libc::EINVAL,
            code: "EINVAL",
            message: reason,
        })),
    }
}

/// Writes `bytes` to `target`.
fn write_to(target: &Target, bytes: &[u8]) -> Result<usize, SyscallError> {
    match target {
        Target::Path(path) => blob::write_file(path, bytes),
        Target::Descriptor(descriptor) => {
            // SAFETY: `from_raw_fd` takes ownership, which this must not do — the
            // caller still owns the descriptor and closes it itself, and the
            // recorded behaviour is that `Bun.write(fd, ...)` leaves it open.
            // `ManuallyDrop` suppresses the close so the write borrows it.
            let mut file = std::mem::ManuallyDrop::new(unsafe {
                <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(*descriptor)
            });
            match file.write_all(bytes) {
                Ok(()) => Ok(bytes.len()),
                Err(cause) => Err(SyscallError::new(&cause, "write", &descriptor.to_string())),
            }
        }
    }
}

/// Settles the returned promise with `result`.
fn settle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
    result: Result<usize, SyscallError>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        error::throw_type_error(scope, "cannot create a promise");
        return;
    };
    let promise = resolver.get_promise(scope);
    match result {
        Ok(written) => {
            let value = v8::Number::new(scope, written as f64);
            resolver.resolve(scope, value.into());
        }
        Err(failure) => {
            let value = error::syscall_value(scope, &failure);
            resolver.reject(scope, value);
        }
    }
    rv.set(promise.into());
}

/// What a pending write needs when its payload is drained asynchronously.
///
/// The box holds the resolver rather than a value: the promise this call returns
/// is the one the resolver owns, so the handler settles the caller's promise
/// instead of producing a second one.
struct Pending {
    target: Target,
    resolver: v8::Global<v8::PromiseResolver>,
}

/// The byte source for a `Bun.write` payload, as a promise.
///
/// A `Blob` and a `Response` answer `arrayBuffer()` themselves. A
/// `ReadableStream` does not, so it is wrapped in a `Response` — which is Node's
/// own, and whose body draining is already the tested path for a stream.
fn byte_promise<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    payload: v8::Local<'s, v8::Value>,
    object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Promise>> {
    if let Some(method) = property(scope, object, "arrayBuffer") {
        if let Some(value) = drain_via_method(scope, payload, method) {
            return Some(value);
        }
    }

    let response = response_constructor(scope)?;
    let body = response.new_instance(scope, &[payload])?;
    let method = property(scope, body, "arrayBuffer")?;
    drain_via_method(scope, body.into(), method)
}

/// Calls a zero-argument async method and returns its promise.
fn drain_via_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    receiver: v8::Local<'s, v8::Value>,
    method: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Promise>> {
    let method = v8::Local::<v8::Function>::try_from(method).ok()?;
    let value = method.call(scope, receiver, &[])?;
    v8::Local::<v8::Promise>::try_from(value).ok()
}

thread_local! {
    /// The realm's `Response`, for wrapping a `ReadableStream`.
    ///
    /// A `Global` is isolate-scoped, so this is per isolate; [`crate::blob::clear`]
    /// drops it when a realm ends.
    static RESPONSE: std::cell::RefCell<Option<v8::Global<v8::Function>>> =
        const { std::cell::RefCell::new(None) };
}

/// The realm's `Response` constructor, or `None` before the web globals exist.
fn response_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    if let Some(cached) = RESPONSE.with(|slot| slot.borrow().as_ref().cloned()) {
        return Some(v8::Local::new(scope, cached));
    }
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Response")?;
    let value = global.get(scope, key.into())?;
    let function = v8::Local::<v8::Function>::try_from(value).ok()?;
    RESPONSE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, function)));
    Some(function)
}

/// The asynchronous drain, for a `ReadableStream`, `Blob` or `Response`.
///
/// The promise returned to JavaScript is the resolver's own promise, and the
/// payload's bytes promise is chained onto a handler that writes those bytes and
/// then settles it.
fn write_async<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
    target: Target,
    payload: v8::Local<'s, v8::Value>,
) {
    let Some(object) = v8::Local::<v8::Object>::try_from(payload).ok() else {
        error::throw_invalid_arg(
            scope,
            "Bun.write(pathOrFdOrBlob, blob) expects a Blob-y thing to write",
        );
        return;
    };
    let Some(bytes) = byte_promise(scope, payload, object) else {
        error::throw_invalid_arg(
            scope,
            "Bun.write(pathOrFdOrBlob, blob) expects a Blob-y thing to write",
        );
        return;
    };

    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        error::throw_type_error(scope, "cannot create a promise");
        return;
    };
    let promise = resolver.get_promise(scope);
    rv.set(promise.into());

    let pending = Box::new(Pending {
        target,
        resolver: v8::Global::new(scope, resolver),
    });
    let pointer = Box::into_raw(pending);
    let external = v8::External::new(scope, pointer.cast());
    let Some(handler) = v8::Function::builder(drain_trampoline)
        .data(external.into())
        .build(scope)
    else {
        // SAFETY: `pointer` came from `Box::into_raw` above and was never given
        // to a template, so this is the only owning reference.
        unsafe { drop(Box::from_raw(pointer)) };
        error::throw_type_error(scope, "cannot chain the write");
        return;
    };
    if bytes.then(scope, handler).is_none() {
        error::throw_type_error(scope, "cannot chain the write");
    }
}

/// Writes the drained bytes and settles the caller's promise.
fn drain_trampoline<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(external) = v8::Local::<v8::External>::try_from(args.data()).ok() else {
        return;
    };
    // SAFETY: the pointer came from `Box::into_raw` in `write_async`, was given
    // to exactly one function template, and that template's handler runs at most
    // once. Taking ownership here releases the box — and the `Global` resolver
    // inside it — when this function returns.
    let pending = unsafe { Box::from_raw(external.value().cast::<Pending>()) };
    let resolver = v8::Local::new(scope, &pending.resolver);

    let Some(bytes) = binary_bytes(scope, args.get(0)) else {
        let value = error::syscall_value(
            scope,
            &SyscallError {
                errno: 0,
                code: "EINVAL",
                message: "EINVAL: invalid argument, write".to_string(),
            },
        );
        resolver.reject(scope, value);
        return;
    };

    match write_to(&pending.target, &bytes) {
        Ok(written) => {
            let value = v8::Number::new(scope, written as f64);
            resolver.resolve(scope, value.into());
        }
        Err(failure) => {
            let value = error::syscall_value(scope, &failure);
            resolver.reject(scope, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_clone_keeps_the_path() {
        let target = Target::Path("a/b.txt".to_string());
        let Target::Path(path) = target.clone() else {
            panic!("a path target stayed a path");
        };
        assert_eq!(path, "a/b.txt");
    }
}
