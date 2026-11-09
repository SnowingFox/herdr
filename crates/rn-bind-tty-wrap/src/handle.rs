//! The `TTY` constructor and its prototype.
//!
//! `TTYWrap` is `LibuvStreamWrap` over a `uv_tty_t`, so most of the prototype is
//! the shared stream surface from [`rn_uv::stream_base`]. What a terminal adds is
//! `getWindowSize` and `setRawMode`, and a constructor that takes a descriptor
//! rather than a socket type.
//!
//! # Construction failure is reported, not thrown
//!
//! `uv_tty_init` fails for a descriptor that is not a terminal, and `src/
//! tty_wrap.cc` handles that by `MarkAsUninitialized()` and filling the second
//! constructor argument — a context object `lib/tty.js` turns into
//! `ERR_TTY_INIT_FAILED`. It deliberately does *not* throw from the constructor,
//! because the object is still returned and the caller decides.

use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::handle::{HandleState, StreamState};
use rn_uv::uv_loop;

use crate::methods;

/// The internal field holding the `*mut TtyHandle`.
const HANDLE_FIELD: i32 = 0;

/// Everything one `TTY` instance owns.
pub struct TtyHandle {
    /// The libuv handle, boxed because libuv requires it not to move.
    pub tty: Box<uv::uv_tty_t>,
    /// The shared stream state, whose `stream` points at `tty`.
    pub state: StreamState,
    /// The descriptor the terminal was opened on.
    ///
    /// `LibuvStreamWrap::set_fd` records it because `uv_fileno` on a tty can
    /// report the *original* descriptor rather than the one libuv wrapped, and
    /// `socket.fd` has to report what the caller passed.
    pub fd: i32,
    /// Bytes read so far, for `handle.bytesRead`.
    pub bytes_read: u64,
    /// Bytes handed to writes so far, for `handle.bytesWritten`.
    pub bytes_written: u64,
    /// The finalizer registration, parked here so it lives as long as the
    /// handle.
    pub weak: Option<v8::Weak<v8::Object>>,
}

impl TtyHandle {
    /// Creates and initialises a `uv_tty_t` over `fd`.
    ///
    /// Returns the handle and libuv's status; a failure still produces a handle,
    /// because `src/tty_wrap.cc` keeps the object and reports the status through
    /// the constructor's context argument.
    pub fn new(fd: i32) -> Option<(Box<Self>, i32)> {
        let loop_pointer = uv_loop::loop_ptr()?;
        let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_tty_t>::zeroed());
        // SAFETY: `storage` is a live, aligned, zeroed `uv_tty_t`, `loop_pointer`
        // is the process' loop, and `fd` is the caller's descriptor. `readable`
        // is 0 because `src/tty_wrap.cc` passes 0 and lets `readStart` decide.
        let status = unsafe { uv::uv_tty_init(loop_pointer, storage.as_mut_ptr(), fd, 0) };
        if status != 0 {
            // `uv_tty_init` may have left the storage untouched, so it is dropped
            // rather than read.
            return None;
        }
        // SAFETY: `uv_tty_init` succeeded, so the value is initialised. Boxing it
        // keeps the address stable for the handle's life.
        let mut tty = unsafe { Box::from_raw(Box::into_raw(storage).cast::<uv::uv_tty_t>()) };
        let stream = tty.as_mut() as *mut uv::uv_tty_t as *mut uv::uv_stream_t;
        Some((
            Box::new(Self {
                tty,
                state: StreamState::new(stream),
                fd,
                bytes_read: 0,
                bytes_written: 0,
                weak: None,
            }),
            0,
        ))
    }

    /// The `uv_stream_t` a stream operation takes.
    pub fn stream(&self) -> *mut uv::uv_stream_t {
        self.state.stream
    }

    /// The raw `uv_tty_t`, for the terminal-only calls.
    pub fn raw(&mut self) -> *mut uv::uv_tty_t {
        &mut *self.tty as *mut uv::uv_tty_t
    }
}

/// The raw handle behind a `TTY` object, or `None` when it is not one.
pub fn raw_handle(object: v8::Local<v8::Object>) -> Option<*mut TtyHandle> {
    // SAFETY: the field only ever holds a pointer produced by `install`, and the
    // object is a live local so the allocation is alive.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) }
        as *mut TtyHandle;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Borrows the handle behind a `TTY` object.
pub fn with_handle<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut TtyHandle) -> R,
) -> Option<R> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer is live, and every borrow is scoped
    // to one callback.
    Some(body(unsafe { &mut *pointer }))
}

/// Builds the `TTY` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    // `new TTY(fd, ctx)`.
    let template = v8::FunctionTemplate::builder(new).length(2).build(scope);

    let instance = template.instance_template(scope);
    instance.set_internal_field_count(1);
    // `lib/net.js` assigns these on every socket it wraps, and a `TTY` can back
    // one through `net.Socket({ fd })`.
    let reading = v8::Boolean::new(scope, false);
    instance.set(crate::key(scope, "reading")?.into(), reading.into());
    let null = v8::null(scope);
    instance.set(crate::key(scope, "onread")?.into(), null.into());

    let prototype = template.prototype_template(scope);

    // `HandleWrap`.
    let close = v8::FunctionTemplate::builder(methods::close)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(crate::key(scope, "close")?.into(), close.into());
    let reference = v8::FunctionTemplate::builder(methods::reference)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(crate::key(scope, "ref")?.into(), reference.into());
    let unreference = v8::FunctionTemplate::builder(methods::unreference)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(crate::key(scope, "unref")?.into(), unreference.into());
    let has_reference = v8::FunctionTemplate::builder(methods::has_reference)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(crate::key(scope, "hasRef")?.into(), has_reference.into());
    // `AsyncWrap`'s id. `tty.WriteStream` inherits from `net.Socket`, and
    // `net.js` reads `this._handle.getAsyncId()` unconditionally.
    let get_async_id = v8::FunctionTemplate::builder(methods::get_async_id)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(crate::key(scope, "getAsyncId")?.into(), get_async_id.into());

    // `LibuvStreamWrap` / `StreamBase`.
    let stream_methods: [(&str, i32, v8::Local<v8::FunctionTemplate>); 9] = [
        (
            "readStart",
            0,
            stream_callback(scope, 0, methods::read_start),
        ),
        ("readStop", 0, stream_callback(scope, 0, methods::read_stop)),
        ("shutdown", 1, stream_callback(scope, 1, methods::shutdown)),
        (
            "writeBuffer",
            2,
            stream_callback(scope, 2, methods::write_buffer),
        ),
        ("writev", 3, stream_callback(scope, 3, methods::writev)),
        (
            "writeUtf8String",
            2,
            stream_callback(scope, 2, methods::write_utf8),
        ),
        (
            "writeAsciiString",
            2,
            stream_callback(scope, 2, methods::write_ascii),
        ),
        (
            "writeLatin1String",
            2,
            stream_callback(scope, 2, methods::write_latin1),
        ),
        (
            "writeUcs2String",
            2,
            stream_callback(scope, 2, methods::write_ucs2),
        ),
    ];
    for (name, _arity, template) in stream_methods {
        prototype.set(crate::key(scope, name)?.into(), template.into());
    }

    // The `StreamBase` accessors.
    for (name, getter) in [
        ("fd", methods::get_fd as Method),
        ("bytesRead", methods::get_bytes_read),
        ("bytesWritten", methods::get_bytes_written),
        ("writeQueueSize", methods::get_write_queue_size),
    ] {
        let _ = getter;
        let template = match name {
            "fd" => v8::FunctionTemplate::builder(methods::get_fd),
            "bytesRead" => v8::FunctionTemplate::builder(methods::get_bytes_read),
            "bytesWritten" => v8::FunctionTemplate::builder(methods::get_bytes_written),
            _ => v8::FunctionTemplate::builder(methods::get_write_queue_size),
        };
        let template = template
            .length(0)
            .constructor_behavior(v8::ConstructorBehavior::Throw)
            .build(scope);
        prototype.set_accessor_property(
            crate::key(scope, name)?.into(),
            Some(template),
            None,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        );
    }

    // `StreamBase::AddMethods` sets this; `lib/net.js` and
    // `lib/internal/tls/wrap.js` test it before treating a handle as a stream.
    let is_stream_base = v8::Boolean::new(scope, true);
    prototype.set(
        crate::key(scope, "isStreamBase")?.into(),
        is_stream_base.into(),
    );

    // `TTYWrap`'s own methods.
    let get_window_size = v8::FunctionTemplate::builder(methods::get_window_size)
        .length(1)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(
        crate::key(scope, "getWindowSize")?.into(),
        get_window_size.into(),
    );
    let set_raw_mode = v8::FunctionTemplate::builder(methods::set_raw_mode)
        .length(1)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(crate::key(scope, "setRawMode")?.into(), set_raw_mode.into());
    // `LibuvStreamWrap::SetBlocking`, which `lib/net.js` calls for a stdio fd on
    // Windows; harmless and expected to exist everywhere.
    let set_blocking = v8::FunctionTemplate::builder(methods::set_blocking)
        .length(1)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(
        crate::key(scope, "setBlocking")?.into(),
        set_blocking.into(),
    );

    let Some(name) = v8::String::new(scope, "TTY") else {
        return Err("cannot allocate the TTY class name".to_string());
    };
    template.set_class_name(name);
    let function = template.get_function(scope).ok_or("cannot allocate TTY")?;
    function.set_name(name);
    Ok(function.into())
}

/// Builds one stream method template.
fn stream_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    arity: i32,
    function: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::Local<'s, v8::FunctionTemplate> {
    v8::FunctionTemplate::builder(function)
        .length(arity)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope)
}

/// The shape every method callback has.
pub type Method =
    fn(&mut v8::PinScope<'_, '_>, v8::FunctionCallbackArguments<'_>, v8::ReturnValue<'_>);

/// The `TTY` constructor: `new TTY(fd, ctx)`.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        // `src/tty_wrap.cc` `CHECK(args.IsConstructCall())`.
        crate::throw_type_error(scope, "TTY cannot be invoked without 'new'");
        return;
    }
    let Some(fd) = args.get(0).int32_value(scope) else {
        return;
    };
    if fd < 0 {
        // `CHECK_GE(fd, 0)`.
        crate::throw_type_error(scope, "TTY requires a non-negative descriptor");
        return;
    }

    let object = args.this();
    match TtyHandle::new(fd) {
        Some((handle, _status)) => install(scope, object, handle),
        None => {
            // `uv_tty_init` failed. `src/tty_wrap.cc` marks the wrap
            // uninitialised and reports the status through the second argument,
            // which is what `lib/tty.js` turns into `ERR_TTY_INIT_FAILED`. There
            // is no handle to install, so the object keeps its field empty and
            // every method reports `EBADF`.
            let status = uv::uv_errno_t_UV_ENOTTY;
            collect_exception_info(scope, args.get(1), status, "uv_tty_init");
        }
    }
    rv.set(object.into());
}

/// Fills `{ errno, code, message, syscall }`, which is `CollectUVExceptionInfo`.
fn collect_exception_info(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Value>,
    errno: i32,
    syscall: &str,
) {
    let Ok(object) = v8::Local::<v8::Object>::try_from(object) else {
        return;
    };
    let Some(code) = v8::String::new(scope, &crate::error_name(errno)) else {
        return;
    };
    let Some(message) = v8::String::new(scope, &crate::error_message(errno)) else {
        return;
    };
    let Some(syscall) = v8::String::new(scope, syscall) else {
        return;
    };
    for (name, value) in [
        ("errno", v8::Integer::new(scope, errno).into()),
        ("code", code.into()),
        ("message", message.into()),
        ("syscall", syscall.into()),
    ] {
        if let Some(key) = v8::String::new(scope, name) {
            object.set(scope, key.into(), value);
        }
    }
}

/// Installs a handle's native state and finalizer on a `TTY` object.
fn install(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    mut handle: Box<TtyHandle>,
) {
    // The `data` libuv callbacks read has to point at the state inside the final
    // allocation, so it is set after the box exists and never changes again.
    let state_pointer = &mut handle.state as *mut StreamState;
    // SAFETY: the stream is live and lives in the same box as the state.
    unsafe { rn_uv::handle::set_owner(handle.stream(), state_pointer) };
    handle.state.owner_object = Some(v8::Global::new(scope.as_ref(), object));

    let pointer = Box::into_raw(handle);
    object.set_aligned_pointer_in_internal_field(
        HANDLE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    // `process_wrap`'s stdio handling needs the `uv_stream_t` behind a handle it
    // was handed, and it cannot read this crate's private allocation.
    // SAFETY: `state_pointer` is the live state this function just installed.
    unsafe { rn_uv::streams::attach(scope, object, state_pointer) };
    install_finalizer(scope, object, pointer);
}

/// Registers the finalizer that retires a handle when V8 collects its wrapper.
///
/// As for a socket: the finalizer closes rather than frees, because libuv may
/// still call back and `handle->data` has to stay valid until it does.
fn install_finalizer(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    pointer: *mut TtyHandle,
) {
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut TtyHandle;
            // SAFETY: `pointer` came from `Box::into_raw` in `install` and this
            // finalizer runs exactly once.
            let handle = unsafe { &mut *pointer };
            if handle.state.state == HandleState::Initialized {
                handle.state.state = HandleState::Closing;
                // SAFETY: the stream is live and not closing.
                unsafe {
                    uv::uv_close(
                        rn_uv::handle::as_handle(handle.stream()),
                        Some(methods::finalize_handle),
                    )
                };
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
