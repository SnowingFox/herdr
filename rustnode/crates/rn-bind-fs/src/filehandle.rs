//! `FileHandle` and `openFileHandle` — the two members `fs.promises` needs.
//!
//! `lib/internal/fs/promises.js` cannot open a file without them:
//!
//! ```js
//! return new FileHandle(await PromisePrototypeThen(
//!   binding.openFileHandle(path, flagsNumber, mode, kUsePromises),
//!   undefined, handleErrorFromBinding));
//! ```
//!
//! There is no fallback, so `fs.promises.open()` and every `fh.read()`,
//! `fh.write()`, `fh.stat()` and `fh.close()` behind it threw
//! `binding.openFileHandle is not a function`.
//!
//! # What the JavaScript layer actually calls
//!
//! The whole native surface the vendored `promises.js` uses is four members:
//!
//! * `handle.fd` — the descriptor, read once in `FileHandle`'s constructor into
//!   `this[kFd]` and used for every subsequent `binding.read` / `binding.writeBuffer`
//!   call, so reads and writes go through the *existing* bindings.
//! * `handle.getAsyncId()` — `AsyncWrap::GetAsyncId`, for async_hooks.
//! * `handle.close()` — returns a `Promise` that settles once the descriptor is
//!   closed, because `FileHandle.close()` chains on it.
//! * `handle.closeSync()` — closes synchronously.
//!
//! That is why this is a small type rather than a port of Node's `FileHandle`:
//! the stream and read/write machinery lives in `promises.js` and the fs
//! bindings, and only the descriptor's ownership moves here.
//!
//! # Ownership
//!
//! The descriptor is owned by the handle from construction. `close` and
//! `closeSync` each release it exactly once and are idempotent afterwards, which
//! matters because `FileHandle.close()` guards on `this[kFd] === -1` and
//! `[kCloseSync]` guards separately — the two can both be reached.
//!
//! A handle that is garbage collected without being closed closes the descriptor
//! and warns, matching `FileHandle::~FileHandle`'s "was closed during garbage
//! collection" behaviour without the fatal throw: a throw from a finalizer has no
//! JavaScript stack to land on, and Node's own comment says tearing down the
//! process there is the only option available to it. Emitting the warning and
//! releasing the descriptor is the useful half.

use std::cell::Cell;

use rn_v8_sys::v8;
use rn_v8_sys::v8::Local;

use crate::fsops;

/// Internal field holding the `*mut HandleState`.
const HANDLE_FIELD: i32 = 0;

/// Everything one `FileHandle` owns.
///
/// The descriptor is in a `Cell` because `close` and `closeSync` are `&self`
/// methods on the JavaScript object and both have to consume it exactly once.
pub struct HandleState {
    descriptor: Cell<i32>,
    /// `AsyncWrap`'s id for this resource, stable across calls.
    async_id: f64,
    /// The `StreamBase` half, boxed so its address is stable.
    ///
    /// `StreamBase::AddMethods` makes `FileHandle` a stream, which is what lets
    /// `new StreamPipe(fileHandle, sink)` work — `lib/internal/http2/core.js` does
    /// exactly that in `startFilePipe`. The state is behind a `Box` because the
    /// ops reach it through a raw pointer recorded once, and a move would
    /// invalidate it.
    stream: Box<crate::filehandle_stream::FileHandleStream>,
}

impl HandleState {
    /// Takes the descriptor out, leaving `-1`.
    ///
    /// Returns `None` when it was already taken, which is what makes a double
    /// close a no-op rather than an `EBADF` for a descriptor another part of the
    /// process may have since reused.
    fn take(&self) -> Option<i32> {
        let fd = self.descriptor.get();
        if fd < 0 {
            return None;
        }
        self.descriptor.set(-1);
        // `AfterClose()`: the stream half reads the same descriptor, so it has to
        // learn that it is gone — otherwise a read completion already in flight
        // would re-arm and read a number the process may have since reused, and a
        // readable side that was flowing would never be told to stop.
        self.stream.after_close();
        Some(fd)
    }
}

/// Builds the `FileHandle` constructor.
///
/// `src/node_file.cc`'s `FileHandle::New` takes an `Int32` descriptor and
/// optionally an offset and a length, which the constructor stores for the
/// read/write fast paths. `promises.js` only ever passes the descriptor, but the
/// two optionals are accepted so a caller reaching into the binding directly sees
/// the same arity.
///
/// The async id comes from [`rn_bind_async_wrap::next_async_id`], the same
/// counter `Environment::new_async_id` uses, so a `FileHandle`'s id cannot
/// collide with a socket's. `promises.js` reads it through `getAsyncId()` to key
/// the handle's `async_id_symbol`.
pub fn constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<Local<'s, v8::Value>, String> {
    // No `ConstructorBehavior::Throw` here: the default is `Call`, which allows
    // `new`, and `Throw` makes the function non-constructible entirely.
    let template = rn_core::class(new_handle).build(scope);
    let name = v8::String::new(scope, "FileHandle").ok_or("cannot allocate the FileHandle name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    for (name, template) in [
        ("close", rn_core::method(close).build(scope)),
        ("closeSync", rn_core::method(close_sync).build(scope)),
        // `FileHandle::Initialize` installs `releaseFD` right after `closeSync`
        // and before `StreamBase::AddMethods`, so the position matches Node's.
        (
            "releaseFD",
            rn_core::method(crate::filehandle_stream::release_fd).build(scope),
        ),
        ("getAsyncId", rn_core::method(get_async_id).build(scope)),
    ] {
        let key = v8::String::new(scope, name)
            .ok_or_else(|| format!("cannot allocate the name {name}"))?;
        prototype.set(key.into(), template.into());
    }

    // `StreamBase::AddMethods`. `FileHandle::Initialize` calls it right after
    // installing its own three methods, and the resulting prototype order is
    // observable, so the `StreamBase` surface follows them here too. Without this
    // the class cannot be an end of a `StreamPipe`, and `sendFile` — the one
    // caller — fails at the *type check* rather than at the write.
    crate::filehandle_stream::install_stream_base(scope, prototype)?;

    // `FileHandle::fd` is a plain data property in Node, set by `StreamBase`'s
    // `SetMethod`-adjacent setup. It is an accessor here so the value is `-1`
    // once the descriptor has been taken: `promises.js` caches the descriptor in
    // its own `kFd` and only re-reads `handle.fd` on the deserialize path, but a
    // stale value there would point at a descriptor the process may have reused.
    let fd_getter = rn_core::method(get_fd).build(scope);
    let fd_key = v8::String::new(scope, "fd").ok_or("cannot allocate the fd accessor name")?;
    prototype.set_accessor_property(
        fd_key.into(),
        Some(fd_getter),
        None,
        v8::PropertyAttribute::DONT_ENUM,
    );

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the FileHandle constructor")?;
    constructor.set_name(name);
    Ok(constructor.into())
}

/// Reads the handle state behind a `FileHandle` object.
fn raw_handle(object: v8::Local<v8::Object>) -> Option<*mut HandleState> {
    // SAFETY: the field only ever holds a pointer produced by `new_handle`, and
    // the object is a live local so the allocation is alive.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) }
        as *mut HandleState;
    (!pointer.is_null()).then_some(pointer)
}

/// The `HandleState` behind a `FileHandle` object.
///
/// Exposed to sibling modules in this crate: the `StreamBase` half needs the
/// descriptor, and it must not keep a second copy that could drift.
pub(crate) fn raw_handle_state(object: v8::Local<'_, v8::Object>) -> Option<*mut HandleState> {
    raw_handle(object)
}

impl HandleState {
    /// The `StreamBase` half.
    pub(crate) fn stream(&self) -> *mut crate::filehandle_stream::FileHandleStream {
        self.stream.as_ref() as *const crate::filehandle_stream::FileHandleStream as *mut _
    }

    /// `FileHandle::Release`: hand the descriptor back and mark the handle closed,
    /// without closing it.
    ///
    /// Both the outer `descriptor` and the stream half's copy are cleared, because
    /// `handle.fd` reads this one while a read completion reads the other. They
    /// are two views of one fact, so the transition is written once, here.
    pub(crate) fn release(&self) -> i32 {
        let fd = self.descriptor.get();
        self.descriptor.set(-1);
        self.stream.after_close();
        fd
    }

    /// Whether this handle is mid-operation, `FileHandle::GetTransferMode`'s
    /// `reading_ || closing_ || closed_`.
    ///
    /// `promises.js` refuses a transfer in all three states with
    /// `Cannot transfer FileHandle while in use`, so this is the native half of
    /// the same rule. A descriptor already taken reads as closed, which is what
    /// stops a second transfer of the same handle.
    pub(crate) fn is_busy(&self) -> bool {
        self.descriptor.get() < 0 || self.stream.is_closed()
    }
}

/// The `FileHandle` constructor function, as `openFileHandle` resolves it.
///
/// Cached because a rebuild needs to construct a handle from native code, and
/// `promises.js` does `new FileHandle(nativeHandle)`: the object has to be the
/// same class `openFileHandle` resolves, with the same prototype, internal field
/// and finalizer, or the receiving side's `fh.readFile()` finds no state.
pub(crate) fn constructor_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    let cached = CONSTRUCTOR_FUNCTION.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|function| v8::Local::new(scope, function))
    });
    if let Some(function) = cached {
        return Some(function);
    }
    let value = constructor(scope).ok()?;
    let function = v8::Local::<v8::Function>::try_from(value).ok()?;
    CONSTRUCTOR_FUNCTION.with(|slot| {
        *slot.borrow_mut() = Some(v8::Global::new(scope, function));
    });
    Some(function)
}

thread_local! {
    /// The `FileHandle` constructor, built once and rooted.
    static CONSTRUCTOR_FUNCTION: std::cell::RefCell<Option<v8::Global<v8::Function>>> =
        const { std::cell::RefCell::new(None) };
}

/// Builds a native `FileHandle` around `descriptor`, Node's
/// `FileHandle::TransferData::Deserialize`.
pub(crate) fn new_native_handle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    descriptor: i32,
) -> Option<v8::Local<'s, v8::Object>> {
    let constructor = constructor_function(scope)?;
    let argument: v8::Local<'s, v8::Value> = v8::Integer::new(scope, descriptor).into();
    constructor.new_instance(&*scope, &[argument])
}

/// Borrows the handle state behind a `FileHandle` object.
fn with_handle<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&HandleState) -> R,
) -> Option<R> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer is live, and every method below
    // only reads it or mutates through its `Cell`.
    Some(body(unsafe { &*pointer }))
}

/// `new FileHandle(fd)`.
fn new_handle(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(scope, "FileHandle cannot be invoked without 'new'");
        return;
    }
    let Some(fd) = crate::args::int32(scope, args.get(0)) else {
        throw_type_error(scope, "The fd argument must be a number");
        return;
    };
    if fd < 0 {
        throw_type_error(scope, "The fd argument must be non-negative");
        return;
    }
    // `FileHandle::New`'s optional `(offset, length)`. `core.js` passes them from
    // `respondWithFile(path, headers, { offset, length })`, and the stream half
    // uses them to bound a `StreamPipe` transfer. Absent means "no offset, read to
    // EOF", which is `-1` for the length.
    let offset = crate::args::int64(scope, args.get(1)).unwrap_or(-1);
    let length = crate::args::int64(scope, args.get(2)).unwrap_or(-1);

    let state = Box::new(HandleState {
        descriptor: Cell::new(fd),
        // A fresh id per handle: an async id identifies the resource, so two
        // FileHandles must not share one.
        async_id: rn_bind_async_wrap::next_async_id(),
        stream: Box::new(crate::filehandle_stream::FileHandleStream::new(
            fd, offset, length,
        )),
    });
    let pointer = Box::into_raw(state);
    let object = args.this();
    object.set_aligned_pointer_in_internal_field(HANDLE_FIELD, pointer.cast(), 0);

    // SAFETY: `pointer` names the live allocation, and `stream` inside it is the
    // box whose address the ops record — a `Box` does not move with its owner.
    let stream = unsafe { (*pointer).stream.state_pointer() };
    // `StreamBase::GetObject()`: what the default listener delivers a read to.
    // SAFETY: `stream` is live and owned by the box above.
    unsafe { (*stream).owner_object = Some(v8::Global::new(scope.as_ref(), object)) };
    // SAFETY: the box's address is final and it lives as long as the state that
    // points at it.
    unsafe { (*pointer).stream.install_owner() };
    // The handle is a host object that can only move, so the messaging layer has
    // to recognise it before a transfer list is read. Marking at construction is
    // Node's `BaseObject` recording its wrapper once.
    rn_core::host_object::mark(scope, object, crate::filehandle_transfer::FILE_HANDLE_KIND);
    // `StreamBase::FromObject` is how `StreamPipe` finds a stream, and a
    // `FileHandle` has no `uv_stream_t` to publish, so the *state* is published.
    // SAFETY: `stream` is live for as long as the object is.
    unsafe { rn_uv::streams::attach_state(scope, object, stream) };

    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut HandleState;
            // SAFETY: `pointer` came from `Box::into_raw` above and this
            // finalizer runs exactly once.
            let state = unsafe { &*pointer };
            if let Some(fd) = state.take() {
                // `FileHandle::~FileHandle` closes the descriptor and reports
                // that it was closed during garbage collection. A throw from a
                // finalizer has no stack to land on, so the warning is the
                // observable half.
                if let Err(error) = fsops::close(fd) {
                    tracing::warn!(
                        fd,
                        code = error.code(),
                        "closing a FileHandle descriptor during garbage collection failed"
                    );
                }
                tracing::warn!(
                    fd,
                    "a FileHandle was closed during garbage collection; close it explicitly"
                );
            }
            // SAFETY: no other owner exists and nothing else frees this.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    let _ = weak;
    rv.set(object.into());
}

/// `handle.fd`.
fn get_fd(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let fd = with_handle(args.this(), |state| state.descriptor.get()).unwrap_or(-1);
    rv.set(v8::Integer::new(scope, fd).into());
}

/// `handle.getAsyncId()`. `AsyncWrap::GetAsyncId`.
fn get_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = with_handle(args.this(), |state| state.async_id).unwrap_or(rn_core::INVALID_ASYNC_ID);
    rv.set(v8::Number::new(scope, id).into());
}

/// `handle.close()`, which resolves once the descriptor is closed.
///
/// `FileHandle.close()` does `SafePromisePrototypeFinally(this[kHandle].close(), ...)`,
/// so the return value has to be a promise whatever happens.
fn close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let result = with_handle(args.this(), |state| match state.take() {
        Some(fd) => fsops::close(fd),
        None => Ok(()),
    });
    let payload = match result {
        Some(Ok(())) => Ok(crate::complete::Payload::Unit),
        Some(Err(error)) => Err(crate::complete::Failure::Syscall(error)),
        // A receiver that is not a FileHandle closes nothing and resolves, which
        // is what `ASSIGN_OR_RETURN_UNWRAP`'s early return amounts to.
        None => Ok(crate::complete::Payload::Unit),
    };
    match crate::complete::deliver_to_promise(scope, crate::complete::Completion { payload }) {
        Some(promise) => rv.set(promise.into()),
        None => rv.set_undefined(),
    }
}

/// `handle.closeSync()`.
fn close_sync(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let result = with_handle(args.this(), |state| match state.take() {
        Some(fd) => fsops::close(fd),
        None => Ok(()),
    });
    if let Some(Err(error)) = result {
        crate::request::throw_error(scope, &error);
    }
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}
