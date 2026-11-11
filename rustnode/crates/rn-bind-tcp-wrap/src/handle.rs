//! The `TCP` constructor and its prototype.
//!
//! Node builds `TCP` from three stacked `FunctionTemplate`s: `HandleWrap`
//! (`close`/`ref`/`unref`/`hasRef`), `LibuvStreamWrap` (`StreamBase`'s read and
//! write methods plus `writeQueueSize` and `setBlocking`) and `TCPWrap`
//! (`bind`/`listen`/`connect`/…). The stack is observable only through
//! `instanceof` checks and `isStreamBase`, both of which `lib/net.js` performs;
//! rustnode flattens it into one prototype and installs `isStreamBase` as a real
//! property, which covers every read in `lib/**`.
//!
//! # Per-handle native state
//!
//! Each instance owns one `uv_tcp_t` and one [`StreamState`]. A `uv_tcp_t` must
//! not move once `uv_tcp_init` has run, so it lives in its own allocation whose
//! address is never handed to anything that could relocate it. The JavaScript
//! object holds that allocation behind an internal field.
//!
//! # Lifetime
//!
//! Three things have to agree on when the handle dies: V8 (which may collect the
//! wrapper at any time), libuv (which calls back until `uv_close` completes), and
//! the read/write completions (which hold `handle->data`). A finalizer alone is
//! not enough, because a close may be in flight when the wrapper is collected and
//! libuv's close callback still reads `data`.
//!
//! So the finalizer *closes* the handle when the wrapper dies and only frees the
//! allocation once libuv has finished with it. That keeps the invariant the rest
//! of the crate relies on: `handle->data` is valid whenever libuv can call.

use std::ffi::c_void;
use std::ptr;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::handle::{self, HandleState, StreamState};
use rn_uv::uv_loop;

/// The internal field holding the `*mut TcpHandle`.
const HANDLE_FIELD: i32 = 0;

/// Everything one `TCP` instance owns.
pub struct TcpHandle {
    /// The libuv handle, boxed because libuv requires it not to move.
    pub tcp: Box<uv::uv_tcp_t>,
    /// The shared stream state, whose `stream` points at `tcp`.
    pub state: StreamState,
    /// `TCPWrap::SocketType`: [`crate::SOCKET`] or [`crate::SERVER`].
    pub kind: i32,
    /// The finalizer registration, parked here so it lives as long as the
    /// handle.
    pub weak: Option<v8::Weak<v8::Object>>,
}

impl TcpHandle {
    /// Creates and initialises a `uv_tcp_t` on the process' loop.
    pub fn new(kind: i32) -> Option<Box<Self>> {
        let loop_pointer = uv_loop::loop_ptr()?;
        let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_tcp_t>::zeroed());
        // SAFETY: `storage` is a live, aligned, zeroed `uv_tcp_t` and
        // `loop_pointer` is the process' loop.
        let status = unsafe { uv::uv_tcp_init(loop_pointer, storage.as_mut_ptr()) };
        if status != 0 {
            tracing::error!(status, "uv_tcp_init failed");
            return None;
        }
        // SAFETY: `uv_tcp_init` succeeded, so the value is initialised. Boxing it
        // with the right type keeps the address stable for the handle's life.
        let mut tcp = unsafe { Box::from_raw(Box::into_raw(storage).cast::<uv::uv_tcp_t>()) };
        let stream = tcp.as_mut() as *mut uv::uv_tcp_t as *mut uv::uv_stream_t;
        Some(Box::new(Self {
            tcp,
            state: StreamState::new(stream),
            kind,
            weak: None,
        }))
    }

    /// Adopts an already-initialised handle, so an accepted socket keeps the
    /// `uv_tcp_t` libuv filled in.
    pub fn adopt(tcp: Box<uv::uv_tcp_t>, kind: i32) -> Box<Self> {
        let stream = tcp.as_ref() as *const uv::uv_tcp_t as *mut uv::uv_stream_t;
        Box::new(Self {
            tcp,
            state: StreamState::new(stream),
            kind,
            weak: None,
        })
    }

    /// The provider `src/tcp_wrap.cc` selects from the socket type.
    ///
    /// `TCPWrap::New` maps `SOCKET` to `PROVIDER_TCPWRAP` and `SERVER` to
    /// `PROVIDER_TCPSERVERWRAP` before the constructor runs, so the kind is
    /// answerable from `getProviderType()` before any reset.
    pub fn provider(kind: i32) -> u32 {
        if kind == crate::SERVER {
            rn_core::async_wrap::PROVIDER_TCPSERVERWRAP
        } else {
            rn_core::async_wrap::PROVIDER_TCPWRAP
        }
    }

    /// The `uv_stream_t` a stream operation takes.
    pub fn stream(&self) -> *mut uv::uv_stream_t {
        self.state.stream
    }
}

/// The raw handle behind a `TCP` object, or `None` when the object is not one.
///
/// This is the address a method needs; callers that want a borrow use
/// [`with_handle`].
///
/// The internal-field count is checked first because V8 aborts in debug builds
/// and reads out-of-bounds memory in release builds when a field outside the
/// object's range is asked for. That check is what
/// `BaseObject::FromJSObject` performs before it casts, so it is also what
/// makes `ASSIGN_OR_RETURN_UNWRAP` answer `UV_EBADF` for a receiver that is not
/// a handle instead of crashing.
pub fn raw_handle(object: v8::Local<v8::Object>) -> Option<*mut TcpHandle> {
    if object.internal_field_count() <= HANDLE_FIELD as usize {
        return None;
    }
    // SAFETY: the field only ever holds a pointer produced by `install`, and the
    // object is a live local so the allocation has not been freed.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) }
        as *mut TcpHandle;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Borrows the handle behind a `TCP` object.
///
/// Returns `None` for a non-`TCP` receiver, which is what
/// `ASSIGN_OR_RETURN_UNWRAP` reports as `UV_EBADF`.
pub fn with_handle<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut TcpHandle) -> R,
) -> Option<R> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer is live, and every borrow is scoped
    // to one callback.
    Some(body(unsafe { &mut *pointer }))
}

thread_local! {
    /// The constructor function, and the handles waiting to be wrapped.
    ///
    /// `ConnectionWrap::OnConnection` has to build the accepted handle before it
    /// can ask JavaScript for a wrapper, and it must not build a second
    /// `uv_tcp_t`: `uv_accept` already filled the first one and a `uv_tcp_t`
    /// cannot move after initialisation. The accepted handle is parked here and
    /// the constructor adopts it instead of creating another.
    static CONSTRUCTOR: std::cell::RefCell<Option<v8::Global<v8::Function>>> =
        const { std::cell::RefCell::new(None) };
    static PENDING_ACCEPT: std::cell::RefCell<Option<Box<TcpHandle>>> =
        const { std::cell::RefCell::new(None) };
}

/// Takes the parked accept handle, if there is one.
pub fn take_pending_accept() -> Option<Box<TcpHandle>> {
    PENDING_ACCEPT.with(|slot| slot.borrow_mut().take())
}

/// Parks a handle for the next `TCP` construction to adopt.
pub fn park_accept(handle: Box<TcpHandle>) {
    PENDING_ACCEPT.with(|slot| *slot.borrow_mut() = Some(handle));
}

/// Builds the `TCP` constructor and its prototype.
///
/// Every V8 template API wants a `PinScope<_, _, ()>` — a scope with no context
/// entered — so the template is built in the caller's handle scope before the
/// context matters. That is why this takes the scope it is given and never enters
/// a context itself.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(new).length(1).build(scope);

    // `src/tcp_wrap.cc` pre-creates these so instances stay monomorphic and
    // `lib/net.js` assigns them through the fast path:
    //   t->InstanceTemplate()->Set("reading", false)
    //   t->InstanceTemplate()->Set("onconnection", null)
    let instance = template.instance_template(scope);
    // `src/tcp_wrap.cc` pre-creates `reading` as `false` and `onconnection` as
    // `null`. Pre-creating them on the template keeps the shape monomorphic; the
    // constructor also sets them, because a template property is only a default
    // and `lib/net.js` writes these on every socket it builds.
    instance.set_internal_field_count(1);
    let reading = v8::Boolean::new(scope, false);
    instance.set(key(scope, "reading")?.into(), reading.into());
    let null = v8::null(scope);
    instance.set(key(scope, "onconnection")?.into(), null.into());
    instance.set(key(scope, "onread")?.into(), null.into());

    let prototype = template.prototype_template(scope);

    // `HandleWrap`.
    for (name, template) in [
        (
            "close",
            v8::FunctionTemplate::builder(crate::methods::close)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
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
        // `AsyncWrap`'s id, which `lib/net.js` reads as
        // `this._handle.getAsyncId()` on both the connect and the server paths.
        (
            "getAsyncId",
            v8::FunctionTemplate::builder(crate::methods::get_async_id)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        // `AsyncWrap::AsyncReset` and `AsyncWrap::GetProviderType`, which
        // `lib/internal/http/agent.js::asyncResetHandle` needs before it will
        // reset a pooled socket:
        //
        //     if (handle && typeof handle.asyncReset === 'function')
        //       handle.asyncReset(new ReusedHandle(handle.getProviderType(), handle))
        //
        // A missing `asyncReset` is not an error there — the branch is simply
        // skipped — so without these two the reused socket keeps the previous
        // request's id and `socket[async_id_symbol]` stays `-1`.
        (
            "asyncReset",
            v8::FunctionTemplate::builder(crate::methods::async_reset)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "getProviderType",
            v8::FunctionTemplate::builder(crate::methods::get_provider_type)
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
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeBuffer",
            v8::FunctionTemplate::builder(crate::methods::write_buffer)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writev",
            v8::FunctionTemplate::builder(crate::methods::writev)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeUtf8String",
            v8::FunctionTemplate::builder(crate::methods::write_utf8)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        // The other three string encodings exist for direct users of the handle;
        // `stream_base_commons` reaches them only when a caller bypasses
        // `writeGeneric`, which converts non-UTF-8 strings to a `Buffer` first.
        (
            "writeAsciiString",
            v8::FunctionTemplate::builder(crate::methods::write_utf8)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeLatin1String",
            v8::FunctionTemplate::builder(crate::methods::write_utf8)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "writeUcs2String",
            v8::FunctionTemplate::builder(crate::methods::write_utf8)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
    ] {
        prototype.set(key(scope, name)?.into(), template.into());
    }

    // The accessor properties `StreamBase::AddMethods` installs.
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

    // `StreamBase::AddMethods` sets this to `true`; `lib/internal/http/server.js`
    // and `lib/internal/tls/wrap.js` test it before treating a handle as a
    // stream.
    let is_stream_base = v8::Boolean::new(scope, true);
    prototype.set(key(scope, "isStreamBase")?.into(), is_stream_base.into());

    // `TCPWrap`'s own methods.
    for (name, template) in [
        (
            "open",
            v8::FunctionTemplate::builder(crate::methods::open)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "bind",
            v8::FunctionTemplate::builder(crate::methods::bind)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "bind6",
            v8::FunctionTemplate::builder(crate::methods::bind6)
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
                .length(3)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "connect6",
            v8::FunctionTemplate::builder(crate::methods::connect6)
                .length(3)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "getsockname",
            v8::FunctionTemplate::builder(crate::methods::getsockname)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "getpeername",
            v8::FunctionTemplate::builder(crate::methods::getpeername)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "setNoDelay",
            v8::FunctionTemplate::builder(crate::methods::set_no_delay)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "setKeepAlive",
            v8::FunctionTemplate::builder(crate::methods::set_keep_alive)
                .length(2)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "setTypeOfService",
            v8::FunctionTemplate::builder(crate::methods::set_type_of_service)
                .length(1)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "getTypeOfService",
            v8::FunctionTemplate::builder(crate::methods::get_type_of_service)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
        (
            "reset",
            v8::FunctionTemplate::builder(crate::methods::reset)
                .length(0)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .build(scope),
        ),
    ] {
        prototype.set(key(scope, name)?.into(), template.into());
    }

    let Some(name) = v8::String::new(scope, "TCP") else {
        return Err("cannot allocate the TCP class name".to_string());
    };
    template.set_class_name(name);
    let function = template.get_function(scope).ok_or("cannot allocate TCP")?;
    function.set_name(name);

    CONSTRUCTOR.with(|slot| {
        *slot.borrow_mut() = Some(v8::Global::new(scope.as_ref(), function));
    });

    Ok(function.into())
}

/// Instantiates a `TCP` from native code, for an accepted socket.
///
/// Equivalent to `ConnectionWrap::Instantiate`: it calls the constructor with the
/// `SOCKET` type, which then adopts the handle [`park_accept`] put aside.
pub fn instantiate<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let constructor = CONSTRUCTOR.with(|slot| slot.borrow().clone())?;
    let constructor: v8::Local<v8::Function> = v8::Local::new(scope, &constructor);
    let argument: v8::Local<v8::Value> = v8::Integer::new(scope, crate::SOCKET).into();
    let receiver: v8::Local<v8::Value> = v8::undefined(&**scope).into();
    let _ = receiver;
    constructor.new_instance(&*scope, &[argument])
}

/// The `TCP` constructor: `new TCP(SOCKET | SERVER)`.
///
/// `src/tcp_wrap.cc` rejects a call that is not `new` and an argument that is not
/// an `Int32`; both are `CHECK`s there and throws here.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        // `src/tcp_wrap.cc` `CHECK(args.IsConstructCall())`.
        crate::handle::throw_type_error(scope, "TCP cannot be invoked without 'new'");
        return;
    }
    let Some(kind) = args.get(0).int32_value(scope) else {
        // `CHECK(args[0]->IsInt32())`. A missing argument reads as `undefined`,
        // which does convert — so this checks the type, not just the conversion,
        // to match the `CHECK`.
        crate::handle::throw_type_error(scope, "TCP requires a socket type");
        return;
    };
    if !args.get(0).is_int32() {
        crate::handle::throw_type_error(scope, "TCP requires a socket type");
        return;
    }

    // An accept in flight supplies the handle; anything else creates one.
    let handle = take_pending_accept().or_else(|| TcpHandle::new(kind));
    let Some(mut handle) = handle else {
        // `src/tcp_wrap.cc` `CHECK_EQ(uv_tcp_init(...), 0)`.
        crate::handle::throw_error(scope, "uv_tcp_init failed");
        return;
    };
    handle.kind = kind;
    // `TCPWrap::New` picks the provider from the socket type *before* the
    // constructor body runs, and `ConnectionWrap`'s base `AsyncWrap(env, object,
    // provider)` then calls `AsyncReset(object)`. That reset is what allocates
    // the handle's first async id and emits its first `init`, so a socket is
    // traceable from construction rather than from its first reset.
    handle.state.async_wrap = rn_core::AsyncWrapState::uninitialised(TcpHandle::provider(kind));

    let object = args.this();
    install(scope, object, handle, args);
    // The initial reset runs after `install` so the object already carries its
    // native state: `emitInitNative` calls into JavaScript, and a hook that
    // reads `handle.getAsyncId()` would otherwise reach an uninstalled handle.
    crate::handle::with_handle(object, |handle| {
        rn_bind_async_wrap::async_reset(scope, &mut handle.state.async_wrap, object, object, None);
    });

    // The defaults `src/tcp_wrap.cc` pre-creates. Setting them here as well as on
    // the instance template is what makes them observable: `lib/net.js` reads
    // `handle.reading` and assigns `handle.onconnection` on every socket.
    if let Some(key) = v8::String::new(scope, "reading") {
        object.set(scope, key.into(), v8::Boolean::new(scope, false).into());
    }
    let null = v8::null(scope);
    for name in ["onconnection", "onread"] {
        if let Some(key) = v8::String::new(scope, name) {
            object.set(scope, key.into(), null.into());
        }
    }

    rv.set(object.into());
}

/// Installs a handle's native state and finalizer on a `TCP` object.
pub fn install(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    mut handle: Box<TcpHandle>,
    _args: v8::FunctionCallbackArguments<'_>,
) {
    // The `data` libuv callbacks read has to point at the state inside the final
    // allocation, so it is set after the box exists and never changes again.
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
    // `process_wrap`'s stdio handling needs the `uv_stream_t` behind a handle it
    // was handed, and it cannot read this crate's private allocation. Recording
    // the pairing in `rn-uv` is how the two namespaces agree without either
    // reaching into the other.
    // SAFETY: `state_pointer` is the live state this function just installed.
    unsafe { rn_uv::streams::attach(scope, object, state_pointer) };
    install_finalizer(scope, object, pointer);
}

/// Registers the finalizer that retires a handle when V8 collects its wrapper.
///
/// The finalizer starts `uv_close` rather than freeing immediately: libuv may
/// still call back, and `handle->data` has to stay valid until it does. The close
/// callback is what frees.
fn install_finalizer(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    pointer: *mut TcpHandle,
) {
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut TcpHandle;
            // SAFETY: `pointer` came from `Box::into_raw` in `install` and this
            // finalizer runs exactly once.
            let handle = unsafe { &mut *pointer };
            if handle.state.state == HandleState::Initialized {
                // The wrapper died while the socket was still open. Close it so
                // libuv releases the descriptor; the close callback frees the
                // box, because libuv still holds `data` until then.
                handle.state.state = HandleState::Closing;
                // SAFETY: the stream is live and not closing.
                unsafe {
                    uv::uv_close(
                        handle::as_handle(handle.stream()),
                        Some(crate::methods::finalize_handle),
                    )
                };
            } else {
                // Nothing is in flight, so nothing else will read this.
                // SAFETY: as above; no other owner exists.
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

/// The shape every method callback has, so the loops above can list them.
pub type Method =
    fn(&mut v8::PinScope<'_, '_>, v8::FunctionCallbackArguments<'_>, v8::ReturnValue<'_>);

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

/// Reads argument `index` as an `i32`, falling back to `0`.
pub fn arg_i32(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> i32 {
    args.get(index).int32_value(scope).unwrap_or(0)
}

/// Reads argument `index` as a Rust string, if it is a string.
pub fn arg_string(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<String> {
    args.get(index)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
}

/// Points a `uv_buf_t` at a `Uint8Array`'s bytes.
///
/// # Safety
///
/// The view's backing store must stay alive until libuv is done with the buffer.
/// `lib/internal/stream_base_commons.js` holds `req.buffer` for exactly that
/// reason.
pub unsafe fn view_buffer(value: v8::Local<v8::Value>) -> Option<uv::uv_buf_t> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() {
        if length == 0 {
            return Some(uv::uv_buf_t {
                base: ptr::null_mut(),
                len: 0,
            });
        }
        return None;
    }
    Some(uv::uv_buf_t {
        base: data.cast(),
        len: length,
    })
}
