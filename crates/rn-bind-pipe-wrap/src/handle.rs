//! The `Pipe` constructor and its prototype.
//!
//! `src/pipe_wrap.cc` builds this from the same `HandleWrap`/`LibuvStreamWrap`
//! stack `TCP` uses, so the read and write methods come from
//! [`rn_uv::stream_base`] exactly as they do for a socket. What a pipe adds is a
//! path-based `bind`, a path-based `connect`, and `fchmod`.

use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::handle::{self, HandleState, StreamState};
use rn_uv::uv_loop;

use crate::methods::finalize_handle;

/// The internal field holding the `*mut PipeHandle`.
const HANDLE_FIELD: i32 = 0;

/// Everything one `Pipe` instance owns.
pub struct PipeHandle {
    /// The libuv handle, boxed because libuv requires it not to move.
    pub pipe: Box<uv::uv_pipe_t>,
    /// The shared stream state, whose `stream` points at `pipe`.
    pub state: StreamState,
    /// `PipeWrap::SocketType`: [`crate::SOCKET`], [`crate::SERVER`] or
    /// [`crate::IPC`].
    pub kind: i32,
    /// The finalizer registration, parked here so it lives as long as the
    /// handle.
    pub weak: Option<v8::Weak<v8::Object>>,
}

impl PipeHandle {
    /// Creates and initialises a `uv_pipe_t` on the process' loop.
    pub fn new(kind: i32) -> Option<Box<Self>> {
        let loop_pointer = uv_loop::loop_ptr()?;
        let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_pipe_t>::zeroed());
        // `ipc` is true only for the handle `lib/internal/child_process.js`
        // builds to carry descriptors; `lib/net.js` never sets it.
        let ipc = i32::from(kind == crate::IPC);
        // SAFETY: `storage` is a live, aligned, zeroed `uv_pipe_t` and
        // `loop_pointer` is the process' loop.
        let status = unsafe { uv::uv_pipe_init(loop_pointer, storage.as_mut_ptr(), ipc) };
        if status != 0 {
            tracing::error!(status, "uv_pipe_init failed");
            return None;
        }
        // SAFETY: `uv_pipe_init` succeeded. Boxing it keeps the address stable.
        let mut pipe = unsafe { Box::from_raw(Box::into_raw(storage).cast::<uv::uv_pipe_t>()) };
        let stream = pipe.as_mut() as *mut uv::uv_pipe_t as *mut uv::uv_stream_t;
        Some(Box::new(Self {
            pipe,
            state: StreamState::new(stream),
            kind,
            weak: None,
        }))
    }

    /// The `uv_stream_t` a stream operation takes.
    pub fn stream(&self) -> *mut uv::uv_stream_t {
        self.state.stream
    }
}

thread_local! {
    /// The handle an accept has prepared, waiting for its JavaScript wrapper.
    static PENDING_ACCEPT: std::cell::RefCell<Option<Box<PipeHandle>>> =
        const { std::cell::RefCell::new(None) };
    /// The constructor, so native code can instantiate one for an accepted pipe.
    static CONSTRUCTOR: std::cell::RefCell<Option<v8::Global<v8::Function>>> =
        const { std::cell::RefCell::new(None) };
}

/// Takes the parked accept handle, if there is one.
pub fn take_pending_accept() -> Option<Box<PipeHandle>> {
    PENDING_ACCEPT.with(|slot| slot.borrow_mut().take())
}

/// Parks a handle for the next `Pipe` construction to adopt.
pub fn park_accept(handle: Box<PipeHandle>) {
    PENDING_ACCEPT.with(|slot| *slot.borrow_mut() = Some(handle));
}

/// The raw handle behind a `Pipe` object, or `None` when it is not one.
pub fn raw_handle(object: v8::Local<v8::Object>) -> Option<*mut PipeHandle> {
    // SAFETY: the field only ever holds a pointer produced by `install`, and the
    // object is a live local so the allocation is alive.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) }
        as *mut PipeHandle;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Borrows the handle behind a `Pipe` object.
pub fn with_handle<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut PipeHandle) -> R,
) -> Option<R> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer is live.
    Some(body(unsafe { &mut *pointer }))
}

/// Builds the `Pipe` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(new).length(1).build(scope);

    // `src/pipe_wrap.cc` pre-creates no fields on `Pipe` itself (unlike `TCP`),
    // but `lib/net.js` assigns `owner_symbol`, `onread` and `onconnection` the
    // same way, and pre-creating them keeps the instance monomorphic.
    let instance = template.instance_template(scope);
    instance.set_internal_field_count(1);
    let reading = v8::Boolean::new(scope, false);
    instance.set(key(scope, "reading")?.into(), reading.into());
    let null = v8::null(scope);
    instance.set(key(scope, "onconnection")?.into(), null.into());
    instance.set(key(scope, "onread")?.into(), null.into());

    let prototype = template.prototype_template(scope);

    // `HandleWrap`.
    prototype.set(
        key(scope, "close")?.into(),
        v8::FunctionTemplate::builder(crate::methods::close)
            .length(0)
            .constructor_behavior(v8::ConstructorBehavior::Throw)
            .build(scope)
            .into(),
    );
    for (name, template) in [
        (
            "ref",
            v8::FunctionTemplate::builder(crate::methods::reference)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "unref",
            v8::FunctionTemplate::builder(crate::methods::unreference)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "hasRef",
            v8::FunctionTemplate::builder(crate::methods::has_reference)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
    ] {
        prototype.set(key(scope, name)?.into(), template.into());
    }

    // `LibuvStreamWrap` / `StreamBase`.
    for (name, template) in [
        (
            "readStart",
            v8::FunctionTemplate::builder(crate::methods::read_start)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "readStop",
            v8::FunctionTemplate::builder(crate::methods::read_stop)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "shutdown",
            v8::FunctionTemplate::builder(crate::methods::shutdown)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeBuffer",
            v8::FunctionTemplate::builder(crate::methods::write_buffer)
                .length(2)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writev",
            v8::FunctionTemplate::builder(crate::methods::writev)
                .length(3)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeUtf8String",
            v8::FunctionTemplate::builder(crate::methods::write_utf8)
                .length(2)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeAsciiString",
            v8::FunctionTemplate::builder(crate::methods::write_ascii)
                .length(2)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeLatin1String",
            v8::FunctionTemplate::builder(crate::methods::write_latin1)
                .length(2)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeUcs2String",
            v8::FunctionTemplate::builder(crate::methods::write_ucs2)
                .length(2)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
    ] {
        prototype.set(key(scope, name)?.into(), template.into());
    }

    for (name, getter) in [
        (
            "fd",
            v8::FunctionTemplate::builder(crate::methods::get_fd)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "bytesRead",
            v8::FunctionTemplate::builder(crate::methods::get_bytes_read)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "bytesWritten",
            v8::FunctionTemplate::builder(crate::methods::get_bytes_written)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeQueueSize",
            v8::FunctionTemplate::builder(crate::methods::get_write_queue_size)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
    ] {
        prototype.set_accessor_property(
            key(scope, name)?.into(),
            Some(getter),
            None,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        );
    }

    let is_stream_base = v8::Boolean::new(scope, true);
    prototype.set(key(scope, "isStreamBase")?.into(), is_stream_base.into());

    // `PipeWrap`'s own methods.
    for (name, template) in [
        (
            "bind",
            v8::FunctionTemplate::builder(crate::methods::bind)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "listen",
            v8::FunctionTemplate::builder(crate::methods::listen)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "connect",
            v8::FunctionTemplate::builder(crate::methods::connect)
                .length(2)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "open",
            v8::FunctionTemplate::builder(crate::methods::open)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "fchmod",
            v8::FunctionTemplate::builder(crate::methods::fchmod)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
    ] {
        prototype.set(key(scope, name)?.into(), template.into());
    }

    let Some(name) = v8::String::new(scope, "Pipe") else {
        return Err("cannot allocate the Pipe class name".to_string());
    };
    template.set_class_name(name);
    let function = template.get_function(scope).ok_or("cannot allocate Pipe")?;
    function.set_name(name);

    CONSTRUCTOR.with(|slot| {
        *slot.borrow_mut() = Some(v8::Global::new(scope.as_ref(), function));
    });

    Ok(function.into())
}

/// Instantiates a `Pipe` from native code, for an accepted pipe.
pub fn instantiate<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let constructor = CONSTRUCTOR.with(|slot| slot.borrow().clone())?;
    let constructor: v8::Local<v8::Function> = v8::Local::new(scope, &constructor);
    let argument: v8::Local<v8::Value> = v8::Integer::new(scope, crate::SOCKET).into();
    let result = constructor.new_instance(&*scope, &[argument]);
    result
}

/// The `Pipe` constructor: `new Pipe(SOCKET | SERVER | IPC)`.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        // `src/pipe_wrap.cc` `CHECK(args.IsConstructCall())`.
        throw_type_error(scope, "Pipe cannot be invoked without 'new'");
        return;
    }
    // `CHECK(args[0]->IsInt32())`: a missing argument converts rather than
    // failing, so the type is checked as well.
    let Some(kind) = args.get(0).int32_value(scope) else {
        throw_type_error(scope, "Pipe requires a socket type");
        return;
    };
    if !args.get(0).is_int32() {
        throw_type_error(scope, "Pipe requires a socket type");
        return;
    }

    let handle = take_pending_accept().or_else(|| PipeHandle::new(kind));
    let Some(mut handle) = handle else {
        throw_error(scope, "uv_pipe_init failed");
        return;
    };
    handle.kind = kind;

    let object = args.this();
    install(scope, object, handle);
    rv.set(object.into());
}

/// Installs a handle's native state and finalizer on a `Pipe` object.
fn install(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    mut handle: Box<PipeHandle>,
) {
    let state_pointer = &mut handle.state as *mut StreamState;
    // SAFETY: the stream is live and lives in the same box as the state.
    unsafe { handle::set_owner(handle.stream(), state_pointer) };
    handle.state.owner_object = Some(v8::Global::new(scope.as_ref(), object));

    let pointer = Box::into_raw(handle);
    object.set_aligned_pointer_in_internal_field(
        HANDLE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    install_finalizer(scope, object, pointer);
}

/// Registers the finalizer that retires a handle when V8 collects its wrapper.
///
/// As for a socket: the finalizer closes rather than frees, because libuv may
/// still call back and `handle->data` has to stay valid until it does.
fn install_finalizer(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    pointer: *mut PipeHandle,
) {
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut PipeHandle;
            // SAFETY: `pointer` came from `Box::into_raw` in `install` and this
            // finalizer runs exactly once.
            let handle = unsafe { &mut *pointer };
            if handle.state.state == HandleState::Initialized {
                handle.state.state = HandleState::Closing;
                // SAFETY: the stream is live and not closing.
                unsafe { uv::uv_close(handle::as_handle(handle.stream()), Some(finalize_handle)) };
            } else {
                // SAFETY: no other owner exists and libuv is finished with it.
                drop(unsafe { Box::from_raw(pointer) });
            }
        }),
    );

    // The `Weak` has to outlive the registration or the finalizer is cancelled,
    // so it is parked in the allocation it finalizes.
    // SAFETY: `pointer` was just created and is not aliased yet.
    unsafe {
        (*pointer).weak = Some(weak);
    }
}

fn key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))
}

/// Throws a `TypeError`, which is what a failed `CHECK` amounts to here.
pub fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

/// Throws an `Error`.
pub fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::error(scope, text);
        scope.throw_exception(error);
    }
}
