//! `Bun.udpSocket(options)`.
//!
//! Three measured facts shape this, and each is easy to get wrong:
//!
//! 1. **It returns a `Promise`, not a socket.** `Bun.udpSocket({...})` is a
//!    promise that resolves to the socket, so `await` is required and
//!    `s.send(...)` on the un-awaited value is a `TypeError` about a promise.
//! 2. **`send` is `send(data, port, address)`** — port *before* address, three
//!    positional arguments. Reversing them throws
//!    `Expected "port" to be an integer between 1 and 65535`, which is the
//!    measured message for a wrong order.
//! 3. **There is no `bind()`.** Binding happens through the constructor's
//!    `{port}`, and `port` afterwards reports the assigned port; `{port: 0}`
//!    means "pick one".
//!
//! # Failure modes are two different mechanisms
//!
//! Measured, and the difference matters because a caller sees a throw in one case
//! and a rejected promise in the other:
//!
//! ```text
//! Bun.udpSocket()          !! THROW  TypeError ERR_INVALID_ARG_TYPE "Expected an object"
//! Bun.udpSocket(42)        !! REJECT TypeError ERR_INVALID_ARG_TYPE "Expected an object"
//! Bun.udpSocket({port:-1}) !! REJECT TypeError ERR_INVALID_ARG_TYPE
//!                              "Expected \"port\" to be an integer between 0 and 65535"
//! ```
//!
//! So a *missing* argument throws synchronously — the function checks its own
//! arity before it builds any promise — while an argument that is present but
//! wrong rejects. This reproduces that split.
//!
//! # The surface
//!
//! Measured prototype members: `addMembership, address,
//! addSourceSpecificMembership, binaryType, close, closed, dropMembership,
//! dropSourceSpecificMembership, fd, hostname, port, ref, reload, remoteAddress,
//! send, sendMany, setBroadcast, setMulticastInterface, setMulticastLoopback,
//! setMulticastTTL, setTTL, unref`.
//!
//! The socket itself is `rn-bind-udp-wrap`'s `uv_udp_t` wrapper, driven directly:
//! the receive path already delivers `(data, port, address)` the way `dgram` reads
//! it, and reusing it means one libuv socket implementation rather than two.
//!
//! # Test hygiene, from the spec
//!
//! An open UDP socket keeps the event loop alive, so every path that creates one
//! closes it, and the tests close in a `finally`. A test that opens one and
//! forgets to close hangs the suite rather than failing it.

use std::collections::HashMap;

use rn_v8_sys::v8;

/// One live socket's state.
struct Socket {
    /// The libuv handle, boxed because libuv requires it not to move once
    /// `uv_udp_init` has run.
    handle: Box<libuv_sys2::uv_udp_t>,
    /// The bound address, once `uv_udp_bind` has run.
    bound: Option<BoundAddress>,
    /// The port the caller asked for, or 0 for "pick one".
    requested_port: u16,
    /// The host the caller asked for.
    requested_host: String,
    closed: bool,
    /// The object this socket reports to, rooted so a receive can call `data`.
    owner: Option<v8::Global<v8::Object>>,
    /// `socket.data(sock, data, port, address)`, if one was given.
    on_data: Option<v8::Global<v8::Function>>,
    /// How `binaryType` reports payloads: `'buffer'` by default.
    binary_type: &'static str,
    /// Parked so the finalizer registration outlives `create`.
    weak: Option<v8::Weak<v8::Object>>,
    /// The connected peer, from `{connect: {port, hostname}}`.
    remote: Option<BoundAddress>,
}

/// A socket address, in the shape `address` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundAddress {
    address: String,
    family: &'static str,
    port: u16,
}

// Every live socket, keyed by the address of its allocation.
//
// A `thread_local` table rather than a per-object internal field, because
// libuv's receive callback is `extern "C"` and can only carry one `data`
// pointer; the pointer it carries is the socket's own address, and this maps
// that back to the owned box. Removal happens on `close`, so the table does not
// grow without bound.
thread_local! {
    static SOCKETS: std::cell::RefCell<HashMap<usize, Box<Socket>>> =
        std::cell::RefCell::new(HashMap::new());
}

/// Installs the one member.
pub(crate) fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    rn_uv::callback::remember_context(scope);
    crate::define_method(scope, target, "udpSocket", 1, udp_socket)
}

/// `Bun.udpSocket(options)`.
fn udp_socket<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let options = args.get(0);
    // The arity check runs before the promise exists, which is what makes a
    // missing argument a throw rather than a rejection. Measured.
    if args.length() == 0 || options.is_undefined() {
        throw_type_error(scope, "Expected an object");
        return;
    }
    // Everything from here rejects: the shape is validated inside the promise's
    // executor, so a bad option is a rejection. Measured for `udpSocket(42)` and
    // for `{port: -1}`.
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        throw_type_error(scope, "cannot allocate the udpSocket promise");
        return;
    };
    let promise = resolver.get_promise(scope);

    match create(scope, options) {
        Ok(socket) => {
            resolver.resolve(scope, socket.into());
        }
        Err(failure) => {
            let Some(message) = v8::String::new(scope, &failure.message) else {
                return;
            };
            let exception = v8::Exception::type_error(scope, message);
            if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
                if let Some(key) = v8::String::new(scope, "code") {
                    if let Some(value) = v8::String::new(scope, "ERR_INVALID_ARG_TYPE") {
                        let _ = object.set(scope, key.into(), value.into());
                    }
                }
            }
            resolver.reject(scope, exception);
        }
    }
    rv.set(promise.into());
}

/// Why a socket could not be created.
struct Failure {
    message: String,
}

/// Validates the options and builds the socket.
fn create<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    options: v8::Local<'s, v8::Value>,
) -> Result<v8::Local<'s, v8::Object>, Failure> {
    let Ok(object) = v8::Local::<v8::Object>::try_from(options) else {
        return Err(Failure {
            message: "Expected an object".to_string(),
        });
    };

    // `port` is validated first because that is the order Bun's message implies:
    // `{port: -1}` reports the port, not the missing callbacks.
    let port = match property(scope, object, "port") {
        Some(value) if value.is_number() => {
            let number = value.number_value(scope).unwrap_or(0.0);
            if !(0.0..=65535.0).contains(&number) || number.fract() != 0.0 {
                return Err(port_failure(0));
            }
            number as u16
        }
        Some(value) if !value.is_undefined() && !value.is_null() => return Err(port_failure(0)),
        // No port and no `connect` leaves an unbound socket, which is legal.
        _ => 0,
    };

    let hostname = property(scope, object, "hostname")
        .filter(|value| value.is_string())
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_else(|| "0.0.0.0".to_string());

    // `{connect: {port, hostname}}` makes this a client socket.
    let connect = property(scope, object, "connect").and_then(|value| {
        let peer = v8::Local::<v8::Object>::try_from(value).ok()?;
        let port = property(scope, peer, "port")
            .and_then(|value| value.number_value(scope))
            .map(|number| number as u16)?;
        let host = property(scope, peer, "hostname")
            .filter(|value| value.is_string())
            .map(|value| value.to_rust_string_lossy(scope))
            .unwrap_or_else(|| "127.0.0.1".to_string());
        Some((host, port))
    });

    // The object first, so the receive callback can reach it.
    // The object comes from the template's instance template, which is what gives
    // it the internal field the accessors read; a plain `Object::new` has no
    // fields and writing one aborts V8.
    let Some(socket_object) = socket_prototype(scope) else {
        return Err(Failure {
            message: "cannot build the udpSocket prototype".to_string(),
        });
    };

    // `socket: { data(...) }` is where payloads go.
    let on_data = property(scope, object, "socket")
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .and_then(|callbacks| property(scope, callbacks, "data"))
        .and_then(|value| v8::Local::<v8::Function>::try_from(value).ok())
        .map(|function| v8::Global::new(scope.as_ref(), function));
    let binary_type = property(scope, object, "binaryType")
        .filter(|value| value.is_string())
        .map(|value| {
            if value.to_rust_string_lossy(scope) == "uint8array" {
                "uint8array"
            } else {
                "buffer"
            }
        })
        .unwrap_or("buffer");

    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        return Err(Failure {
            message: "there is no socket loop".to_string(),
        });
    };
    let mut handle = Box::new(unsafe {
        // SAFETY: `uv_udp_t` is plain C data; `uv_udp_init` fills it.
        std::mem::zeroed::<libuv_sys2::uv_udp_t>()
    });
    // SAFETY: the loop is live and the storage is zeroed.
    let status = unsafe { libuv_sys2::uv_udp_init(loop_pointer, &mut *handle) };
    if status != 0 {
        return Err(Failure {
            message: format!("uv_udp_init: {}", rn_bind_uv::message(status)),
        });
    }

    // Bind, unless this is a connected client with no local port of its own.
    let mut bound = None;
    if port != 0 || connect.is_none() {
        let family = if hostname.contains(':') {
            rn_uv::addr::ip6(&hostname, port).map(AddressFamily::Six)
        } else {
            rn_uv::addr::ip4(&hostname, port).map(AddressFamily::Four)
        };
        let Ok(address) = family else {
            return Err(Failure {
                message: "Invalid address".to_string(),
            });
        };
        // SAFETY: the handle is live and the address is a live `sockaddr`.
        let status = unsafe {
            match &address {
                AddressFamily::Four(address) => libuv_sys2::uv_udp_bind(
                    &mut *handle,
                    (address as *const libuv_sys2::sockaddr_in).cast(),
                    0,
                ),
                AddressFamily::Six(address) => libuv_sys2::uv_udp_bind(
                    &mut *handle,
                    (address as *const libuv_sys2::sockaddr_in6).cast(),
                    0,
                ),
            }
        };
        if status != 0 {
            return Err(Failure {
                message: format!("uv_udp_bind: {}", rn_bind_uv::message(status)),
            });
        }
        bound = sockname(&mut handle, &hostname);
    }

    let remote = match &connect {
        Some((host, peer_port)) => match peer_address(host, *peer_port) {
            Some(address) => {
                // SAFETY: the handle is live and the address is a live `sockaddr`.
                let status = unsafe {
                    match &address {
                        AddressFamily::Four(address) => libuv_sys2::uv_udp_connect(
                            &mut *handle,
                            (address as *const libuv_sys2::sockaddr_in).cast(),
                        ),
                        AddressFamily::Six(address) => libuv_sys2::uv_udp_connect(
                            &mut *handle,
                            (address as *const libuv_sys2::sockaddr_in6).cast(),
                        ),
                    }
                };
                if status != 0 {
                    return Err(Failure {
                        message: format!("uv_udp_connect: {}", rn_bind_uv::message(status)),
                    });
                }
                Some(BoundAddress {
                    address: host.clone(),
                    family: if host.contains(':') { "IPv6" } else { "IPv4" },
                    port: *peer_port,
                })
            }
            None => {
                return Err(Failure {
                    message: "Invalid address".to_string(),
                })
            }
        },
        None => None,
    };

    // If a callback was given, start receiving. `uv_udp_recv_start` is what makes
    // the socket deliver anything, so a socket with no `data` simply never gets
    // called back rather than failing.
    if let Some(callback) = on_data.as_ref() {
        let _ = callback;
        // SAFETY: the handle is live.
        let status =
            unsafe { libuv_sys2::uv_udp_recv_start(&mut *handle, Some(alloc_cb), Some(recv_cb)) };
        if status != 0 {
            return Err(Failure {
                message: format!("uv_udp_recv_start: {}", rn_bind_uv::message(status)),
            });
        }
    }

    let socket = Box::new(Socket {
        handle,
        bound,
        requested_port: port,
        requested_host: hostname,
        closed: false,
        owner: Some(v8::Global::new(scope.as_ref(), socket_object)),
        on_data,
        binary_type,
        remote,
        weak: None,
    });
    let address = std::ptr::from_ref(&*socket) as usize;
    let handle_pointer =
        socket.handle.as_ref() as *const libuv_sys2::uv_udp_t as *mut libuv_sys2::uv_udp_t;
    // SAFETY: the handle is live; `data` is how the callbacks find the table
    // entry, and the entry lives until `close` removes it.
    unsafe { (*handle_pointer).data = address as *mut std::ffi::c_void };
    SOCKETS.with(|table| table.borrow_mut().insert(address, socket));

    socket_object.set_aligned_pointer_in_internal_field(0, address as *const std::ffi::c_void, 0);
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        socket_object,
        Box::new(move || {
            // The wrapper went away without `close()` having run: close the
            // handle so libuv stops calling back, then drop the entry. Without
            // this, a socket whose result was dropped keeps the loop alive
            // forever.
            cancel(address);
        }),
    );
    SOCKETS.with(|table| {
        if let Some(socket) = table.borrow_mut().get_mut(&address) {
            socket.weak = Some(weak);
        }
    });
    Ok(socket_object)
}

/// An address in the family `uv_udp_bind` needs.
enum AddressFamily {
    Four(libuv_sys2::sockaddr_in),
    Six(libuv_sys2::sockaddr_in6),
}

fn peer_address(host: &str, port: u16) -> Option<AddressFamily> {
    if host.contains(':') {
        rn_uv::addr::ip6(host, port).ok().map(AddressFamily::Six)
    } else {
        rn_uv::addr::ip4(host, port).ok().map(AddressFamily::Four)
    }
}

/// `uv_udp_getsockname`, in the shape `address` reports.
fn sockname(handle: &mut libuv_sys2::uv_udp_t, fallback_host: &str) -> Option<BoundAddress> {
    let mut storage = std::mem::MaybeUninit::<libuv_sys2::sockaddr_storage>::zeroed();
    let mut length = std::mem::size_of::<libuv_sys2::sockaddr_storage>() as i32;
    // SAFETY: the handle is live and the storage is a live, correctly-sized
    // out-parameter.
    let status =
        unsafe { libuv_sys2::uv_udp_getsockname(handle, storage.as_mut_ptr().cast(), &mut length) };
    if status != 0 {
        return None;
    }
    // SAFETY: libuv filled the storage in and returned success.
    let address = unsafe { storage.assume_init() };
    // SAFETY: the storage holds a `sockaddr` of the family it reports.
    let parsed = unsafe {
        rn_uv::addr::from_sockaddr(
            &*(&address as *const libuv_sys2::sockaddr_storage).cast::<libuv_sys2::sockaddr>(),
        )
    }?;
    Some(BoundAddress {
        address: parsed.address,
        family: parsed.family,
        port: parsed.port,
    })
    .map(|mut bound| {
        // Bun reports the *requested* hostname for `hostname`, and the address the
        // socket is bound to for `address`; a wildcard bind reports `0.0.0.0`.
        if bound.address.is_empty() {
            bound.address = fallback_host.to_string();
        }
        bound
    })
}

/// The failure for a bad `port`, with Bun's message.
fn port_failure(which: u8) -> Failure {
    Failure {
        message: format!("Expected \"port\" to be an integer between {which} and 65535"),
    }
}

/// libuv's allocate callback for a receive.
///
/// # Safety
///
/// Called by libuv with a live handle.
unsafe extern "C" fn alloc_cb(
    _handle: *mut libuv_sys2::uv_handle_t,
    suggested: usize,
    buffer: *mut libuv_sys2::uv_buf_t,
) {
    if buffer.is_null() {
        return;
    }
    let storage = vec![0u8; suggested.max(4096)].into_boxed_slice();
    let length = storage.len();
    // SAFETY: `buffer` is libuv's out-parameter; the allocation is reclaimed by
    // `recv_cb`.
    unsafe {
        (*buffer).base = Box::into_raw(storage).cast::<u8>().cast();
        (*buffer).len = length;
    }
}

/// libuv's receive callback: hands the datagram to the socket's `data`.
///
/// # Safety
///
/// Called by libuv with the buffer [`alloc_cb`] produced.
unsafe extern "C" fn recv_cb(
    handle: *mut libuv_sys2::uv_udp_t,
    nread: isize,
    buffer: *const libuv_sys2::uv_buf_t,
    addr: *const libuv_sys2::sockaddr,
    _flags: u32,
) {
    if handle.is_null() || buffer.is_null() {
        return;
    }
    // SAFETY: the buffer is the one `alloc_cb` produced for this datagram.
    let raw = unsafe { &*buffer };
    let base = raw.base.cast::<u8>();
    let capacity = raw.len;

    if nread > 0 {
        // SAFETY: `data` is the table key the socket was installed under.
        let key = unsafe { (*handle).data } as usize;
        // SAFETY: libuv wrote `nread` bytes into the allocation.
        let bytes = unsafe { std::slice::from_raw_parts(base, nread as usize) }.to_vec();
        // SAFETY: a null `addr` means the family was not reported.
        let family = if addr.is_null() {
            None
        } else {
            // SAFETY: libuv filled the address in.
            unsafe { rn_uv::addr::from_sockaddr(&*addr) }
        };
        deliver(key, bytes, family);
    }

    // SAFETY: the allocation is the one `alloc_cb` made with this length.
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(base, capacity)) });
}

/// Calls the socket's `data(sock, data, port, address)`.
fn deliver(key: usize, bytes: Vec<u8>, from: Option<rn_uv::addr::Address>) {
    let (owner, callback, binary_type) = SOCKETS.with(|table| {
        let table = table.borrow();
        let Some(socket) = table.get(&key) else {
            return (None, None, "buffer");
        };
        (
            socket.owner.clone(),
            socket.on_data.clone(),
            socket.binary_type,
        )
    });
    let (Some(owner), Some(callback)) = (owner, callback) else {
        return;
    };

    rn_uv::callback::with_context(|scope| {
        let socket = v8::Local::new(scope, &owner);
        let callback = v8::Local::new(scope, &callback);
        let Some(payload) = payload_view(scope, &bytes, binary_type) else {
            return;
        };
        let port = v8::Number::new(
            scope,
            f64::from(from.as_ref().map_or(0, |address| address.port)),
        );
        let address = match from.as_ref().map(|address| address.address.as_str()) {
            Some(address) => v8::String::new(scope, address)
                .map(Into::into)
                .unwrap_or_else(|| v8::undefined(scope).into()),
            None => v8::undefined(scope).into(),
        };
        let receiver: v8::Local<v8::Value> = socket.into();
        let caught = {
            let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
            let inner = &mut try_catch.init();
            let _ = callback.call(
                inner,
                receiver,
                &[socket.into(), payload, port.into(), address],
            );
            inner
                .exception()
                .map(|exception| v8::Global::new(inner, exception))
        };
        if let Some(caught) = caught {
            // A throw from `data` has to reach the runtime's uncaught path, or
            // V8 prints it and the process exits 0.
            let exception = v8::Local::new(&*scope, &caught);
            rn_errors::report_uncaught_exception(scope, exception);
        }
    });
}

/// The payload as `binaryType` asks: a `Buffer` or a `Uint8Array`.
fn payload_view<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
    binary_type: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let view = v8::Uint8Array::new(scope, array_buffer, 0, bytes.len())?;
    if binary_type == "buffer" {
        if let Some(prototype) = buffer_prototype(scope) {
            view.set_prototype(scope, prototype.into());
        }
    }
    Some(view.into())
}

/// `Buffer.prototype`, as `lib/buffer.js` installed it on the global.
fn buffer_prototype<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let value = global.get(scope, key.into())?;
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let prototype = v8::String::new(scope, "prototype")?;
    let value = object.get(scope, prototype.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Closes the socket behind `key` and removes it from the table.
fn cancel(key: usize) {
    let Some(mut socket) = SOCKETS.with(|table| table.borrow_mut().remove(&key)) else {
        return;
    };
    if socket.closed {
        return;
    }
    socket.closed = true;
    // SAFETY: the handle is live and not closing.
    unsafe {
        let handle = std::ptr::from_mut(&mut *socket.handle).cast::<libuv_sys2::uv_handle_t>();
        libuv_sys2::uv_udp_recv_stop(std::ptr::from_mut(&mut *socket.handle));
        if libuv_sys2::uv_is_closing(handle) == 0 {
            libuv_sys2::uv_close(handle, None);
        }
    }
    // The box is dropped here, so the handle's storage goes with it. That is safe
    // only because `uv_close` was called: libuv's close callback for a handle with
    // no other work does not dereference it after this point, and the loop
    // processes the close before any further receive for a handle it has removed
    // from its active list.
    drop(socket);
}

// ---------------------------------------------------------------------------
// The socket prototype
// ---------------------------------------------------------------------------

/// The prototype members, in Bun's measured order.
///
/// Measured with `Object.getOwnPropertyNames(Object.getPrototypeOf(s))`:
/// `addMembership, address, addSourceSpecificMembership, binaryType, close,
/// closed, dropMembership, dropSourceSpecificMembership, fd, hostname, port,
/// ref, reload, remoteAddress, send, sendMany, setBroadcast,
/// setMulticastInterface, setMulticastLoopback, setMulticastTTL, setTTL, unref`.
pub(crate) const PROTOTYPE_MEMBERS_IN_ORDER: &[&str] = &[
    "addMembership",
    "address",
    "addSourceSpecificMembership",
    "binaryType",
    "close",
    "closed",
    "dropMembership",
    "dropSourceSpecificMembership",
    "fd",
    "hostname",
    "port",
    "ref",
    "reload",
    "remoteAddress",
    "send",
    "sendMany",
    "setBroadcast",
    "setMulticastInterface",
    "setMulticastLoopback",
    "setMulticastTTL",
    "setTTL",
    "unref",
];

/// The accessors on the prototype.
const PROTOTYPE_GETTERS: &[&str] = &[
    "address",
    "binaryType",
    "closed",
    "fd",
    "hostname",
    "port",
    "remoteAddress",
];

/// Builds the socket prototype.
///
/// An `ObjectTemplate` so each getter is installed without a setter:
/// `ObjectTemplate::set_accessor_property` takes `Option<FunctionTemplate>` for
/// each half, which the `PropertyDescriptor` path cannot express.
fn socket_prototype<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    // Two templates, for the same reason `spawn.rs` documents: an
    // `ObjectTemplate` is the only thing that can install a getter *without* a
    // setter, and a plain object built from it has no `constructor` of its own —
    // which is what Bun's `Object.getOwnPropertyNames` reports. The internal field
    // that holds this socket's table key lives on the instance template.
    let constructor = v8::FunctionTemplate::builder(no_socket_constructor).build(scope);
    constructor
        .instance_template(scope)
        .set_internal_field_count(1);
    let prototype_template = v8::ObjectTemplate::new(scope);
    for name in PROTOTYPE_MEMBERS_IN_ORDER {
        if PROTOTYPE_GETTERS.contains(name) {
            let getter = getter_template(scope, name)?;
            prototype_template.set_accessor_property(
                v8::String::new(scope, name)?.into(),
                Some(getter),
                None,
                v8::PropertyAttribute::DONT_DELETE,
            );
        } else {
            let function = method_template(scope, name)?;
            prototype_template.set(v8::String::new(scope, name)?.into(), function.into());
        }
    }
    let instance = constructor.instance_template(scope).new_instance(scope)?;
    let prototype = prototype_template.new_instance(scope)?;
    instance.set_prototype(scope, prototype.into());
    Some(instance)
}

/// The placeholder constructor's callback.
///
/// A socket is created by `Bun.udpSocket`, never with `new`, so this exists only
/// because V8 requires a callback. It throws rather than returning an empty
/// object, so a caller who reaches it learns why.
fn no_socket_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    throw_type_error(scope, "a socket is created by Bun.udpSocket, not with new");
}

/// The template for one getter member.
fn getter_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Option<v8::Local<'s, v8::FunctionTemplate>> {
    Some(match name {
        "address" => rn_core::method(get_address).build(scope),
        "binaryType" => rn_core::method(get_binary_type).build(scope),
        "closed" => rn_core::method(get_closed).build(scope),
        "fd" => rn_core::method(get_fd).build(scope),
        "hostname" => rn_core::method(get_hostname).build(scope),
        "port" => rn_core::method(get_port).build(scope),
        "remoteAddress" => rn_core::method(get_remote_address).build(scope),
        other => {
            tracing::error!(member = other, "no udpSocket getter for this name");
            return None;
        }
    })
}

/// The template for one method member.
fn method_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Option<v8::Local<'s, v8::FunctionTemplate>> {
    // `send` and `sendMany` report length 3 on Bun; the rest report 0.
    Some(match name {
        "close" => rn_core::method(method_close).build(scope),
        "send" => rn_core::method(method_send).length(3).build(scope),
        "sendMany" => rn_core::method(method_send_many).length(3).build(scope),
        "ref" => rn_core::method(method_noop).build(scope),
        "unref" => rn_core::method(method_noop).build(scope),
        "reload" => rn_core::method(method_noop).build(scope),
        "addMembership" => rn_core::method(method_noop).build(scope),
        "dropMembership" => rn_core::method(method_noop).build(scope),
        "addSourceSpecificMembership" => rn_core::method(method_noop).build(scope),
        "dropSourceSpecificMembership" => rn_core::method(method_noop).build(scope),
        "setBroadcast" => rn_core::method(method_noop).build(scope),
        "setMulticastInterface" => rn_core::method(method_noop).build(scope),
        "setMulticastLoopback" => rn_core::method(method_noop).build(scope),
        "setMulticastTTL" => rn_core::method(method_noop).build(scope),
        "setTTL" => rn_core::method(method_noop).build(scope),
        other => {
            tracing::error!(member = other, "no udpSocket method for this name");
            return None;
        }
    })
}

/// The table key behind a socket object.
fn key_of(receiver: v8::Local<'_, v8::Object>) -> Option<usize> {
    // SAFETY: the field only ever holds the key `create` stored, and the table
    // entry lives until `close` removes it.
    let key = unsafe { receiver.get_aligned_pointer_from_internal_field(0, 0) } as usize;
    if key == 0 {
        None
    } else {
        Some(key)
    }
}

/// Borrows a socket from the table.
fn with_socket<R>(
    args: &v8::FunctionCallbackArguments<'_>,
    body: impl FnOnce(&mut Socket) -> R,
) -> Option<R> {
    let key = key_of(args.this())?;
    SOCKETS.with(|table| table.borrow_mut().get_mut(&key).map(|socket| body(socket)))
}

fn get_address(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = with_socket(&args, |socket| socket.bound.clone()).flatten();
    match value {
        Some(bound) => {
            let object = v8::Object::new(scope);
            let set = |name: &str, value: v8::Local<'_, v8::Value>| {
                if let Some(key) = v8::String::new(scope, name) {
                    let _ = object.set(scope, key.into(), value);
                }
            };
            if let Some(address) = v8::String::new(scope, &bound.address) {
                set("address", address.into());
            }
            if let Some(family) = v8::String::new(scope, bound.family) {
                set("family", family.into());
            }
            set("port", v8::Number::new(scope, f64::from(bound.port)).into());
            rv.set(object.into());
        }
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn get_binary_type(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `'buffer'` by default.
    let value = with_socket(&args, |socket| socket.binary_type.to_string())
        .unwrap_or_else(|| "buffer".to_string());
    match v8::String::new(scope, &value) {
        Some(value) => rv.set(value.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn get_closed(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // A socket removed from the table by `close` is closed, which is why the
    // absent case reports `true` rather than `undefined`.
    let closed = with_socket(&args, |socket| socket.closed).unwrap_or(true);
    rv.set(v8::Boolean::new(scope, closed).into());
}

fn get_fd(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // SAFETY: the handle is live while the table entry exists.
    let fd = with_socket(&args, |socket| unsafe {
        let mut descriptor: libuv_sys2::uv_os_fd_t = -1;
        let _ = libuv_sys2::uv_fileno(
            std::ptr::from_mut(&mut *socket.handle).cast(),
            &mut descriptor,
        );
        descriptor
    })
    .unwrap_or(-1);
    rv.set(v8::Integer::new(scope, fd).into());
}

fn get_hostname(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: the requested hostname, `"0.0.0.0"` when none was given.
    let value = with_socket(&args, |socket| socket.requested_host.clone())
        .unwrap_or_else(|| "0.0.0.0".to_string());
    match v8::String::new(scope, &value) {
        Some(value) => rv.set(value.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn get_port(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: the *bound* port, so `{port: 0}` reports the assigned one.
    let port = with_socket(&args, |socket| {
        socket
            .bound
            .as_ref()
            .map_or(socket.requested_port, |bound| bound.port)
    })
    .unwrap_or(0);
    rv.set(v8::Number::new(scope, f64::from(port)).into());
}

fn get_remote_address(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `undefined` without `{connect}`, the peer with it.
    let value = with_socket(&args, |socket| socket.remote.clone()).flatten();
    match value {
        Some(bound) => {
            let object = v8::Object::new(scope);
            let set = |name: &str, value: v8::Local<'_, v8::Value>| {
                if let Some(key) = v8::String::new(scope, name) {
                    let _ = object.set(scope, key.into(), value);
                }
            };
            if let Some(address) = v8::String::new(scope, &bound.address) {
                set("address", address.into());
            }
            if let Some(family) = v8::String::new(scope, bound.family) {
                set("family", family.into());
            }
            set("port", v8::Number::new(scope, f64::from(bound.port)).into());
            rv.set(object.into());
        }
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn method_close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if let Some(key) = key_of(args.this()) {
        cancel(key);
    }
    rv.set(v8::undefined(scope).into());
}

/// `send(data, port, address)`.
///
/// Measured order of checks: arity first (`Expected 3 arguments, got N`), then
/// the port range, then the payload type, then the address. Getting the order
/// wrong changes which message a caller sees.
fn method_send(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let arity = args.length();
    // A connected socket accepts `send(data)` alone, which is measured:
    // `s3.send('x')` returns `true` for a `{connect}` socket.
    let connected = with_socket(&args, |socket| socket.remote.is_some()).unwrap_or(false);
    if arity != 3 && !(connected && arity == 1) {
        throw_type_error(scope, &format!("Expected 3 arguments, got {arity}"));
        return;
    }
    let payload = [args.get(0), args.get(1), args.get(2)];
    match send_validated(scope, args.this(), &payload) {
        Ok(()) => rv.set(v8::Boolean::new(scope, true).into()),
        Err(status) => throw_send_status(scope, status),
    }
}

/// Validates and sends one datagram, in Bun's measured check order.
///
/// The single path both `send` and `sendMany` use, so the two cannot disagree
/// about which message a bad argument produces.
fn send_validated(
    scope: &mut v8::PinScope<'_, '_>,
    receiver: v8::Local<'_, v8::Object>,
    payload: &[v8::Local<'_, v8::Value>; 3],
) -> Result<(), Option<i32>> {
    let connected = SOCKETS
        .with(|table| {
            key_of(receiver).and_then(|key| {
                table
                    .borrow()
                    .get(&key)
                    .map(|socket| socket.remote.is_some())
            })
        })
        .unwrap_or(false);

    // A connected socket accepts a lone payload; anything else needs three
    // arguments, and the arity error comes before any type check.
    let arity = if payload[1].is_undefined() && payload[2].is_undefined() {
        1
    } else {
        3
    };
    if arity == 1 && !connected {
        return Err(None);
    }

    let destination = if arity == 1 {
        SOCKETS
            .with(|table| {
                key_of(receiver).and_then(|key| {
                    table
                        .borrow()
                        .get(&key)
                        .and_then(|socket| socket.remote.clone())
                })
            })
            .ok_or(None)?
    } else {
        let port_value = payload[1];
        if !port_value.is_number() {
            throw_port(scope);
            return Err(None);
        }
        let number = port_value.number_value(scope).unwrap_or(0.0);
        if !(1.0..=65535.0).contains(&number) || number.fract() != 0.0 {
            throw_port(scope);
            return Err(None);
        }
        let address_value = payload[2];
        if !address_value.is_string() {
            throw_type_error(scope, "Invalid address");
            return Err(None);
        }
        let text = address_value.to_rust_string_lossy(scope);
        if peer_address(&text, number as u16).is_none() {
            throw_type_error(scope, "Invalid address");
            return Err(None);
        }
        let family = if text.contains(':') { "IPv6" } else { "IPv4" };
        BoundAddress {
            address: text,
            family,
            port: number as u16,
        }
    };

    let bytes = if payload[0].is_string() {
        payload[0].to_rust_string_lossy(scope).into_bytes()
    } else {
        match unsafe { view_bytes(payload[0]) } {
            Some(bytes) => bytes,
            None => {
                throw_type_error(
                    scope,
                    "Expected ArrayBufferView or string as first argument",
                );
                return Err(None);
            }
        }
    };

    let Some(key) = key_of(receiver) else {
        return Err(None);
    };
    SOCKETS.with(|table| {
        let mut table = table.borrow_mut();
        let Some(socket) = table.get_mut(&key) else {
            return Err(None);
        };
        send_datagram(socket, &bytes, &destination).map_err(Some)
    })
}

/// Throws a failed send's status as an error.
fn throw_send_status(scope: &mut v8::PinScope<'_, '_>, status: Option<i32>) {
    let Some(status) = status else {
        return;
    };
    if let Some(message) = v8::String::new(scope, &rn_bind_uv::message(status)) {
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
    }
}

/// Sends one datagram, returning libuv's status.
fn send_datagram(socket: &mut Socket, bytes: &[u8], destination: &BoundAddress) -> Result<(), i32> {
    let buffer = libuv_sys2::uv_buf_t {
        base: bytes.as_ptr() as *mut std::ffi::c_char,
        len: bytes.len(),
    };
    let address = peer_address(&destination.address, destination.port)
        .ok_or(libuv_sys2::uv_errno_t_UV_EINVAL)?;
    // SAFETY: the handle is live, the buffer outlives the call because libuv
    // copies it into its own send queue, and the address is a live `sockaddr`.
    let status = unsafe {
        match &address {
            AddressFamily::Four(address) => libuv_sys2::uv_udp_try_send(
                std::ptr::from_mut(&mut *socket.handle),
                &buffer,
                1,
                (address as *const libuv_sys2::sockaddr_in).cast(),
            ),
            AddressFamily::Six(address) => libuv_sys2::uv_udp_try_send(
                std::ptr::from_mut(&mut *socket.handle),
                &buffer,
                1,
                (address as *const libuv_sys2::sockaddr_in6).cast(),
            ),
        }
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(status)
    }
}

/// `sendMany(datagrams)` on a connected socket.
///
/// Measured: the member exists; behaviour was not exercised by the spec. The
/// form it accepts is a list of `[data, port, address]` tuples or
/// `[data]` for a connected socket, which is what the name implies and what Bun's
/// documentation states.
fn method_send_many(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let list = args.get(0);
    let Ok(list) = v8::Local::<v8::Array>::try_from(list) else {
        throw_type_error(scope, "Expected an array of datagrams");
        return;
    };
    let mut count = 0f64;
    for index in 0..list.length() {
        let Some(entry) = list.get_index(scope, index) else {
            break;
        };
        let mut forwarded: [v8::Local<'_, v8::Value>; 3] = [
            v8::undefined(scope).into(),
            v8::undefined(scope).into(),
            v8::undefined(scope).into(),
        ];
        if let Ok(entry) = v8::Local::<v8::Array>::try_from(entry) {
            for slot in 0..entry.length().min(3) {
                if let Some(value) = entry.get_index(scope, slot) {
                    forwarded[slot as usize] = value;
                }
            }
        } else {
            forwarded[0] = entry;
        }
        // Each entry is dispatched through the same validation a single `send`
        // performs, so a bad element reports the same error.
        match send_validated(scope, args.this(), &forwarded) {
            Ok(()) => count += 1.0,
            Err(status) => {
                throw_send_status(scope, status);
                return;
            }
        }
    }
    rv.set(v8::Number::new(scope, count).into());
}

fn method_noop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `ref`/`unref`/`reload` and the multicast and TTL setters exist on Bun's
    // prototype; the spec records their existence and arity only. They report
    // `undefined`, which is what Bun's do for the cases measured.
    let _ = with_socket(&args, |_| ());
    rv.set(v8::undefined(scope).into());
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let exception = v8::Exception::type_error(scope, text);
        if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
            if let Some(key) = v8::String::new(scope, "code") {
                if let Some(value) = v8::String::new(scope, "ERR_INVALID_ARG_TYPE") {
                    let _ = object.set(scope, key.into(), value.into());
                }
            }
        }
        scope.throw_exception(exception);
    }
}

fn throw_port(scope: &mut v8::PinScope<'_, '_>) {
    throw_type_error(
        scope,
        "Expected \"port\" to be an integer between 1 and 65535",
    );
}

/// Reads a named property, if it exists.
fn property<'s>(
    scope: &v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

/// The bytes of an `ArrayBufferView`, as a copy.
///
/// # Safety
///
/// The view's backing store must stay alive until this returns, which it does
/// because the caller's value is a live local.
unsafe fn view_bytes(value: v8::Local<'_, v8::Value>) -> Option<Vec<u8>> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() {
        return if length == 0 { Some(Vec::new()) } else { None };
    }
    // SAFETY: the caller guarantees the view's bytes are live for this call.
    Some(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prototype_order_is_buns_measured_order() {
        assert_eq!(PROTOTYPE_MEMBERS_IN_ORDER.len(), 22);
        assert_eq!(
            PROTOTYPE_MEMBERS_IN_ORDER.first().copied(),
            Some("addMembership")
        );
        assert_eq!(PROTOTYPE_MEMBERS_IN_ORDER.last().copied(), Some("unref"));
        for name in PROTOTYPE_GETTERS {
            assert!(
                PROTOTYPE_MEMBERS_IN_ORDER.contains(name),
                "{name} is a getter but missing from the order list"
            );
        }
        // Everything else in the order list is a method, and the builder's `match`
        // has an arm for every one of them.
        let methods: Vec<&&str> = PROTOTYPE_MEMBERS_IN_ORDER
            .iter()
            .filter(|name| !PROTOTYPE_GETTERS.contains(name))
            .collect();
        assert_eq!(
            methods.len(),
            15,
            "Bun reports fifteen prototype methods alongside its seven getters"
        );
        // There is no `bind` on Bun's socket.
        assert!(!PROTOTYPE_MEMBERS_IN_ORDER.contains(&"bind"));
    }

    #[test]
    fn the_port_messages_name_the_range_bun_names() {
        // Measured: the constructor reports 0 and 65535; `send` reports 1.
        assert_eq!(
            port_failure(0).message,
            "Expected \"port\" to be an integer between 0 and 65535"
        );
        assert_eq!(
            port_failure(1).message,
            "Expected \"port\" to be an integer between 1 and 65535"
        );
    }
}
