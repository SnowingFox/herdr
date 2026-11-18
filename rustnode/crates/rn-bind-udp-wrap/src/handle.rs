//! The `UDP` constructor and its prototype.
//!
//! Node builds `UDP` from two templates: `HandleWrap` (`close`/`ref`/`unref`/
//! `hasRef` and `getAsyncId`, which comes from `AsyncWrap` underneath it) and
//! `UDPWrap` itself (`bind`/`send`/…). `lib/internal/dgram.js`'s
//! `getHandleWrapType` also does `stream instanceof UDP`, so the constructor has
//! to be the one installed on this namespace — there is no separate marker.
//!
//! # Per-handle native state
//!
//! Each instance owns one `uv_udp_t` and one [`UdpHandle`] holding the rooted
//! JavaScript object, the receive callbacks and the async id. A `uv_udp_t` must
//! not move once `uv_udp_init` has run, so it lives in its own allocation whose
//! address is never handed to anything that could relocate it.
//!
//! # Lifetime
//!
//! Three things have to agree on when the handle dies: V8 (which may collect the
//! wrapper at any time), libuv (which calls back until `uv_close` completes), and
//! the send completions (which hold `handle->data`). The finalizer therefore
//! *closes* the handle when the wrapper dies and only frees the allocation once
//! libuv's close callback has run, which keeps `handle->data` valid for as long
//! as libuv can call.

use std::ffi::c_void;
use std::ptr;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::handle::HandleState;
use rn_uv::uv_loop;

use crate::methods;

/// The internal field holding the `*mut UdpHandle`.
const HANDLE_FIELD: i32 = 0;

/// Everything one `UDP` instance owns.
pub struct UdpHandle {
    /// The libuv handle, boxed because libuv requires it not to move.
    pub udp: Box<uv::uv_udp_t>,
    /// Lifecycle, mirroring `HandleWrap::state_`.
    pub state: HandleState,
    /// The object this handle belongs to, rooted so a completion can call
    /// `onmessage`/`onerror` on it.
    pub owner_object: Option<v8::Global<v8::Object>>,
    /// `AsyncWrap::get_async_id()`, which `lib/dgram.js` reads once per socket
    /// into `async_id_symbol`.
    pub async_id: f64,
    /// The buffer `uv_udp_recv_start`'s allocator produced for the datagram the
    /// receive callback has not reported yet.
    ///
    /// It lives on the handle rather than in a thread-local because several
    /// sockets can be receiving at once, and only the handle ties an allocation
    /// to its own datagram. Holding the owned [`Allocation`] rather than a raw
    /// pointer is what makes an abandoned buffer free itself when the handle is
    /// closed.
    pub pending_allocation: Option<rn_uv::handle::Allocation>,
    /// `UDPWrap::net_permission_granted_`: whether this handle has already been
    /// allowed onto the network, so `recvStart` does not re-check it on every
    /// call.
    ///
    /// Set by a successful `bind`, `connect` or `open`, exactly as
    /// `src/udp_wrap.cc` sets it, and by the first `recvStart` that passes the
    /// check. A handle that was granted a socket this way keeps receiving after
    /// `process.permission.drop('net')`, which is Node's behaviour: the drop
    /// stops the next socket, not the one already bound.
    pub net_permission_granted: bool,
    /// The finalizer registration, parked here so it lives as long as the
    /// handle.
    pub weak: Option<v8::Weak<v8::Object>>,
}

impl UdpHandle {
    /// Creates and initialises a `uv_udp_t` on the process' loop.
    pub fn new() -> Option<Box<Self>> {
        let loop_pointer = uv_loop::loop_ptr()?;
        let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_udp_t>::zeroed());
        // SAFETY: `storage` is a live, aligned, zeroed `uv_udp_t` and
        // `loop_pointer` is the process' loop.
        let status = unsafe { uv::uv_udp_init(loop_pointer, storage.as_mut_ptr()) };
        if status != 0 {
            tracing::error!(status, "uv_udp_init failed");
            return None;
        }
        // SAFETY: `uv_udp_init` succeeded, so the value is initialised. Boxing it
        // with the right type keeps the address stable for the handle's life.
        let udp = unsafe { Box::from_raw(Box::into_raw(storage).cast::<uv::uv_udp_t>()) };
        Some(Box::new(Self {
            udp,
            state: HandleState::Initialized,
            owner_object: None,
            async_id: crate::next_async_id(),
            pending_allocation: None,
            net_permission_granted: false,
            weak: None,
        }))
    }

    /// Whether the handle can still be used, matching `HandleWrap::IsAlive`.
    pub fn is_alive(&self) -> bool {
        self.state == HandleState::Initialized
    }

    /// The raw handle libuv's `uv_udp_*` calls take.
    pub fn raw(&mut self) -> *mut uv::uv_udp_t {
        &mut *self.udp as *mut uv::uv_udp_t
    }

    /// Whether libuv considers the handle closed or closing.
    pub fn is_closing(&self) -> bool {
        // SAFETY: the handle is live while this state exists.
        unsafe { uv::uv_is_closing(crate::as_handle(self.udp.as_ref() as *const _ as *mut _)) != 0 }
    }
}

/// The raw handle behind a `UDP` object, or `None` when it is not one.
pub fn raw_handle(object: v8::Local<v8::Object>) -> Option<*mut UdpHandle> {
    // SAFETY: the field only ever holds a pointer produced by `install`, and the
    // object is a live local so the allocation has not been freed.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) }
        as *mut UdpHandle;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Borrows the handle behind a `UDP` object.
///
/// Returns `None` for a non-`UDP` receiver, which is what
/// `ASSIGN_OR_RETURN_UNWRAP` reports as `UV_EBADF`.
pub fn with_handle<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut UdpHandle) -> R,
) -> Option<R> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer is live, and every borrow is scoped
    // to one callback.
    Some(body(unsafe { &mut *pointer }))
}

thread_local! {
    /// A handle an accept prepared, waiting for the `UDP` constructor to adopt it.
    ///
    /// `uv_accept` fills an already-initialised `uv_udp_t`, and a handle must not
    /// move after `uv_udp_init`, so the received one is parked here and the
    /// constructor adopts it instead of initialising another.
    static PENDING_ACCEPT: std::cell::RefCell<Option<Box<UdpHandle>>> =
        const { std::cell::RefCell::new(None) };
    /// The constructor, so native code can instantiate one for a received socket.
    static CONSTRUCTOR: std::cell::RefCell<Option<v8::Global<v8::Function>>> =
        const { std::cell::RefCell::new(None) };
}

/// Parks a handle for the next `UDP` construction to adopt.
fn park_accept(handle: Box<UdpHandle>) {
    PENDING_ACCEPT.with(|slot| *slot.borrow_mut() = Some(handle));
}

/// Takes the parked accept handle, if there is one.
fn take_pending_accept() -> Option<Box<UdpHandle>> {
    PENDING_ACCEPT.with(|slot| slot.borrow_mut().take())
}

/// Closes a handle no wrapper adopted, so its descriptor cannot leak.
fn close_unadopted(mut handle: UdpHandle) {
    // SAFETY: nothing else holds this handle, so closing it here is the only
    // reference and no close callback is needed.
    unsafe { uv::uv_close(crate::as_handle(handle.raw()), None) };
}

/// Instantiates a `UDP` from native code, for a received datagram socket.
///
/// The constructor adopts whatever [`park_accept`] put aside, so this is the same
/// shape `ConnectionWrap::Instantiate` uses for TCP.
fn instantiate<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let constructor = CONSTRUCTOR.with(|slot| slot.borrow().clone())?;
    let constructor: v8::Local<v8::Function> = v8::Local::new(scope, &constructor);
    let receiver: v8::Local<v8::Value> = v8::undefined(&**scope).into();
    let _ = receiver;
    constructor.new_instance(&*scope, &[])
}

/// A `UDP` handed to `child.send` or `cluster`, as `uv_write2` sees it.
///
/// `cluster`'s `SharedHandle` sends a datagram socket's listening handle so every
/// worker can `recvStart` on the same descriptor, which only works if the handle
/// can cross the IPC channel.
struct Transfer<'a>(&'a UdpHandle);

impl rn_uv::handle_transfer::Transferable for Transfer<'_> {
    fn transfer_handle(&self) -> *mut uv::uv_handle_t {
        crate::as_handle(self.0.udp.as_ref() as *const _ as *mut uv::uv_udp_t)
    }

    fn transfer_is_alive(&self) -> bool {
        self.0.is_alive()
    }
}

/// Reads a `UDP` out of a value the resolver has already matched to this class.
///
/// Only called after `[[HasInstance]]` established the class, because every
/// handle binding stores its pointer in internal field 0 and a blind read would
/// cast one binding's allocation to another's type.
pub(crate) fn transfer_lookup<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<Box<dyn rn_uv::handle_transfer::Transferable>> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer came from `install`, so it points at
    // a live `UdpHandle`. The borrowed value only lives for the send call.
    let handle = unsafe { &*pointer };
    Some(Box::new(Transfer(handle)))
}

/// Accepts a datagram descriptor `uv_write2` delivered, as `AcceptHandle<UDPWrap>`.
///
/// # Safety
///
/// `parent` must be a live IPC pipe with a descriptor pending on it.
pub(crate) unsafe fn accept_transferred<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    parent: *mut uv::uv_stream_t,
    _kind: uv::uv_handle_type,
) -> Option<v8::Local<'s, v8::Object>> {
    let mut client = UdpHandle::new()?;
    // SAFETY: the client's handle is live and `parent` holds the pending
    // descriptor. `AcceptHandle<UDPWrap>` casts the `uv_udp_t` to a
    // `uv_stream_t` for `uv_accept`, which is how libuv moves a datagram
    // descriptor between handles.
    let status = unsafe { uv::uv_accept(parent, client.raw().cast::<uv::uv_stream_t>()) };
    if status != 0 {
        tracing::error!(status, "uv_accept failed for a transferred udp handle");
        crate::handle::close_unadopted(*client);
        return None;
    }
    // The constructor adopts the parked handle the same way it adopts one for a
    // worker's own `dgram.createSocket`.
    crate::handle::park_accept(client);
    let object = instantiate(scope);
    if object.is_none() {
        if let Some(orphan) = take_pending_accept() {
            crate::handle::close_unadopted(*orphan);
        }
    }
    object
}

/// Builds the `UDP` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::class(new).build(scope);

    // `src/udp_wrap.cc` sets `UDPWrapBase::kInternalFieldCount`, which is one
    // more than `HandleWrap`'s so the base pointer fits alongside the handle.
    // rustnode keeps both in one allocation, so one field carries the pointer.
    let instance = template.instance_template(scope);
    instance.set_internal_field_count(1);

    let prototype = template.prototype_template(scope);

    // `HandleWrap` plus `AsyncWrap::GetAsyncId`.
    for (name, template) in [
        ("close", rn_core::method(methods::close).build(scope)),
        ("ref", rn_core::method(methods::reference).build(scope)),
        ("unref", rn_core::method(methods::unreference).build(scope)),
        (
            "hasRef",
            rn_core::method(methods::has_reference).build(scope),
        ),
        (
            "getAsyncId",
            rn_core::method(methods::get_async_id).build(scope),
        ),
        // `UDPWrapBase::AddMethods`.
        (
            "recvStart",
            rn_core::method(methods::recv_start).build(scope),
        ),
        ("recvStop", rn_core::method(methods::recv_stop).build(scope)),
    ] {
        prototype.set(crate::key(scope, name)?.into(), template.into());
    }

    // `UDPWrap`'s own methods. `SetProtoMethod` builds through
    // `NewFunctionTemplate`, so Node reports `length` 0 for every one of them
    // however many arguments the JavaScript side passes.
    //
    // Each has to be named rather than reached through a `fn` pointer: V8 stores
    // the callback in a statically sized slot, which requires a zero-sized type,
    // and a `fn` pointer is not one.
    let methods: [(&str, v8::Local<v8::FunctionTemplate>); 22] = [
        ("open", callback(scope, methods::open)),
        ("bind", callback(scope, methods::bind)),
        ("connect", callback(scope, methods::connect)),
        ("send", callback(scope, methods::send)),
        ("bind6", callback(scope, methods::bind6)),
        ("connect6", callback(scope, methods::connect6)),
        ("send6", callback(scope, methods::send6)),
        ("disconnect", callback(scope, methods::disconnect)),
        ("getpeername", callback(scope, methods::getpeername)),
        ("getsockname", callback(scope, methods::getsockname)),
        ("addMembership", callback(scope, methods::add_membership)),
        ("dropMembership", callback(scope, methods::drop_membership)),
        (
            "addSourceSpecificMembership",
            callback(scope, methods::add_source_membership),
        ),
        (
            "dropSourceSpecificMembership",
            callback(scope, methods::drop_source_membership),
        ),
        (
            "setMulticastInterface",
            callback(scope, methods::set_multicast_interface),
        ),
        (
            "setMulticastTTL",
            callback(scope, methods::set_multicast_ttl),
        ),
        (
            "setMulticastLoopback",
            callback(scope, methods::set_multicast_loopback),
        ),
        ("setBroadcast", callback(scope, methods::set_broadcast)),
        ("setTTL", callback(scope, methods::set_ttl)),
        ("bufferSize", callback(scope, methods::buffer_size)),
        (
            "getSendQueueSize",
            callback(scope, methods::get_send_queue_size),
        ),
        (
            "getSendQueueCount",
            callback(scope, methods::get_send_queue_count),
        ),
    ];
    for (name, template) in methods {
        prototype.set(crate::key(scope, name)?.into(), template.into());
    }

    // `t->PrototypeTemplate()->SetAccessorProperty(fd, GetFD, …)`.
    let get_fd = rn_core::method(methods::get_fd).build(scope);
    prototype.set_accessor_property(
        crate::key(scope, "fd")?.into(),
        Some(get_fd),
        None,
        v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
    );

    let Some(name) = v8::String::new(scope, "UDP") else {
        return Err("cannot allocate the UDP class name".to_string());
    };
    template.set_class_name(name);
    let function = template.get_function(scope).ok_or("cannot allocate UDP")?;
    function.set_name(name);

    // Parked so a received datagram descriptor can be wrapped in a `UDP` object
    // without re-running the constructor's `UdpHandle::new`.
    CONSTRUCTOR.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope.as_ref(), function)));

    Ok(function.into())
}

/// Builds one non-constructible method template, matching `SetProtoMethod`.
///
/// No arity parameter, because `SetProtoMethod` reports 0: Node builds the
/// template through `NewFunctionTemplate`, which passes an explicit 0 for the
/// length whatever the callback actually reads.
fn callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    function: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::Local<'s, v8::FunctionTemplate> {
    rn_core::method(function).build(scope)
}

/// The shape every method callback has, so the table above can name them.
pub type Method =
    fn(&mut v8::PinScope<'_, '_>, v8::FunctionCallbackArguments<'_>, v8::ReturnValue<'_>);

/// The `UDP` constructor: `new UDP()`.
///
/// `src/udp_wrap.cc` reads no arguments at all; `lib/internal/dgram.js` decides
/// v4 versus v6 by which method it binds onto the instance afterwards.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        // `src/udp_wrap.cc` `CHECK(args.IsConstructCall())`.
        crate::throw_type_error(scope, "UDP cannot be invoked without 'new'");
        return;
    }

    // A receive in flight supplies the handle; anything else initialises one.
    let handle = take_pending_accept().or_else(UdpHandle::new);
    let Some(handle) = handle else {
        // `src/udp_wrap.cc` `CHECK_EQ(uv_udp_init(...), 0)`.
        crate::throw_error(scope, "uv_udp_init failed");
        return;
    };

    let object = args.this();
    install(scope, object, handle);
    rv.set(object.into());
}

/// Installs a handle's native state and finalizer on a `UDP` object.
fn install(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    mut handle: Box<UdpHandle>,
) {
    handle.owner_object = Some(v8::Global::new(scope.as_ref(), object));

    let pointer = Box::into_raw(handle);
    // SAFETY: `pointer` is a fresh allocation from `Box::into_raw`, and the
    // handle is live so its `data` slot can be written.
    unsafe { crate::set_owner((*pointer).udp.as_mut() as *mut uv::uv_udp_t, pointer) };
    object.set_aligned_pointer_in_internal_field(
        HANDLE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
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
    pointer: *mut UdpHandle,
) {
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut UdpHandle;
            // SAFETY: `pointer` came from `Box::into_raw` in `install` and this
            // finalizer runs exactly once.
            let handle = unsafe { &mut *pointer };
            if handle.state == HandleState::Initialized {
                // The wrapper died while the socket was still open. Close it so
                // libuv releases the descriptor; the close callback frees the
                // box, because libuv still holds `data` until then.
                handle.state = HandleState::Closing;
                // SAFETY: the handle is live and not closing.
                unsafe {
                    uv::uv_close(
                        crate::as_handle(handle.raw()),
                        Some(methods::finalize_handle),
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

/// The address object `lib/dgram.js` reads out of `getsockname`/`getpeername`.
///
/// `AddressToJS` fills `{ address, family, port }` on a caller-provided object,
/// and `lib/dgram.js`'s `socket.address()` reads exactly those three.
pub fn fill_address(
    scope: &mut v8::PinScope<'_, '_>,
    target: v8::Local<v8::Object>,
    parsed: &rn_uv::addr::Address,
) -> bool {
    let (Some(address), Some(family)) = (
        v8::String::new(scope, &parsed.address),
        v8::String::new(scope, parsed.family),
    ) else {
        return false;
    };
    for (name, value) in [
        ("address", address.into()),
        ("family", family.into()),
        (
            "port",
            v8::Number::new(scope, f64::from(parsed.port)).into(),
        ),
    ] {
        let Some(key) = v8::String::new(scope, name) else {
            return false;
        };
        // The caller checks the return of `getsockname`, so a failure to define
        // a property is reported as `EINVAL` rather than silently dropped.
        if target.set(scope, key.into(), value).is_none() {
            return false;
        }
    }
    true
}

/// Reads a `sockaddr` libuv filled into `storage`, if it is an IP address.
///
/// # Safety
///
/// `storage` must have been filled by a libuv call that returned success.
pub unsafe fn parse_storage(storage: &uv::sockaddr_storage) -> Option<rn_uv::addr::Address> {
    // SAFETY: `sockaddr_storage` leads with the same family word `sockaddr`
    // reads, and the caller guarantees libuv filled it.
    unsafe { rn_uv::addr::from_sockaddr(&*ptr::from_ref(storage).cast::<uv::sockaddr>()) }
}
