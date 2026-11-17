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
//! # `sendMany` and the option members are measured, not inferred
//!
//! The documentation's shape for `sendMany` is wrong in every particular, so it
//! is worth stating here rather than only at the function:
//!
//! ```text
//! connected    sendMany(['a','b','c'])         => 3   one datagram per element
//! unconnected  sendMany(['p', port, addr, …])  => 2   consecutive flat triplets
//! both         sendMany([])                    => 0
//! ```
//!
//! Validation is complete before the first datagram leaves, and a connected
//! socket has to be sent to with a NULL address — supplying the peer returns
//! `EISCONN`, which is how the first implementation broke every connected send.
//! The setters each report differently: `setTTL`/`setMulticastTTL` return the
//! truncated number and reject anything outside `1..=255`;
//! `setBroadcast`/`setMulticastLoopback` return the argument unchanged; and
//! `setMulticastInterface` reports a parse failure as `false` rather than a
//! throw. `reload(options)` replaces `socket.data` and does **not** rebind.
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
    /// Whether the text could not be parsed as an inet address, so sending to it
    /// must fail with libuv's `EINVAL` rather than before the call.
    unparsable: bool,
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
    /// Keys whose socket has been closed, kept so the members that still answer
    /// through a closed socket can tell "closed" from "never existed". Bounded by
    /// the number of sockets a process created and closed.
    static CLOSED: std::cell::RefCell<std::collections::HashSet<usize>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
    /// Sockets that have been `uv_close`d but whose libuv close callback has not
    /// run yet. The box is held here because freeing it earlier is a
    /// use-after-free: libuv writes to the handle in `uv__finish_close`.
    static CLOSING: std::cell::RefCell<HashMap<usize, Box<Socket>>> =
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
                    unparsable: false,
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
        unparsable: false,
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

/// Closes the socket behind `key` and forgets its table entry.
///
/// The `uv_udp_t` **must outlive** the `uv_close` call: libuv completes the close
/// asynchronously and writes to the handle in `uv__finish_close`. Freeing the box
/// here is a use-after-free that aborts the process with
/// `Assertion '!(handle->flags & UV_HANDLE_CLOSED)' failed` — measured on `master`
/// before this change. So the allocation is handed to [`CLOSING`] and reclaimed by
/// the close callback, which is the only place it is guaranteed to be finished
/// with.
fn cancel(key: usize) {
    let Some(socket) = SOCKETS.with(|table| table.borrow_mut().remove(&key)) else {
        // Already closed, or never existed: a second `close()` is a no-op.
        return;
    };
    if socket.closed {
        return;
    }
    let mut socket = socket;
    socket.closed = true;
    CLOSED.with(|closed| closed.borrow_mut().insert(key));
    // SAFETY: the handle is live and not closing.
    unsafe {
        let handle = std::ptr::from_mut(&mut *socket.handle).cast::<libuv_sys2::uv_handle_t>();
        libuv_sys2::uv_udp_recv_stop(std::ptr::from_mut(&mut *socket.handle));
        if libuv_sys2::uv_is_closing(handle) != 0 {
            // Someone else is closing it; hand the box over so the callback can
            // free it, and do not call `uv_close` again.
            CLOSING.with(|closing| closing.borrow_mut().insert(key, socket));
            return;
        }
        CLOSING.with(|closing| closing.borrow_mut().insert(key, socket));
        libuv_sys2::uv_close(handle, Some(finish_close));
    }
}

/// libuv's close callback: reclaims the socket box for the key it carries.
///
/// The key travels in the handle's `data` pointer, which `create` already set to
/// the table key, so this needs no extra plumbing.
extern "C" fn finish_close(handle: *mut libuv_sys2::uv_handle_t) {
    // SAFETY: libuv passes the handle it was given, and `create` stored the table
    // key in its `data` field.
    let key = unsafe { (*handle).data } as usize;
    // Dropping the box here is safe: libuv has finished with the handle.
    let _finished = CLOSING.with(|closing| closing.borrow_mut().remove(&key));
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
///
/// The arities are measured: `send` and `sendMany` are 3, `reload` and the TTL
/// and flag setters are 1, `addMembership`/`dropMembership` are 2, the
/// source-specific pair is 3, and `close`/`ref`/`unref` are 0.
fn method_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Option<v8::Local<'s, v8::FunctionTemplate>> {
    Some(match name {
        "close" => rn_core::method(method_close).build(scope),
        "send" => rn_core::method(method_send).length(3).build(scope),
        "sendMany" => rn_core::method(method_send_many).length(3).build(scope),
        "ref" | "unref" => rn_core::method(method_keepalive).build(scope),
        "reload" => rn_core::method(method_reload).length(1).build(scope),
        "addMembership" => rn_core::method(method_join_membership)
            .length(2)
            .build(scope),
        "dropMembership" => rn_core::method(method_leave_membership)
            .length(2)
            .build(scope),
        "addSourceSpecificMembership" => rn_core::method(method_join_source_membership)
            .length(3)
            .build(scope),
        "dropSourceSpecificMembership" => rn_core::method(method_leave_source_membership)
            .length(3)
            .build(scope),
        "setBroadcast" => rn_core::method(method_set_broadcast).length(1).build(scope),
        "setMulticastInterface" => rn_core::method(method_set_multicast_interface)
            .length(1)
            .build(scope),
        "setMulticastLoopback" => rn_core::method(method_set_multicast_loopback)
            .length(1)
            .build(scope),
        "setMulticastTTL" => rn_core::method(method_set_multicast_ttl)
            .length(1)
            .build(scope),
        "setTTL" => rn_core::method(method_set_unicast_ttl)
            .length(1)
            .build(scope),
        other => {
            tracing::error!(member = other, "no udpSocket method for this name");
            return None;
        }
    })
}

/// The argument-carrying members, each forwarding its boolean to one shared
/// handler; `MapFnTo` needs a distinct function item per template, and the
/// explicit lifetimes keep the forwarding sound.
fn method_join_membership<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    method_membership(scope, args, rv, true);
}

fn method_leave_membership<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    method_membership(scope, args, rv, false);
}

fn method_join_source_membership<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    method_source_membership(scope, args, rv, true);
}

fn method_leave_source_membership<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    method_source_membership(scope, args, rv, false);
}

fn method_set_broadcast<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    method_set_flag(scope, args, rv, false);
}

fn method_set_multicast_loopback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    method_set_flag(scope, args, rv, true);
}

fn method_set_unicast_ttl<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    method_set_ttl(scope, args, rv, false);
}

fn method_set_multicast_ttl<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    method_set_ttl(scope, args, rv, true);
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
    // A closed socket fails before the arity check: measured, `close(); send()`
    // reports "Socket is closed" rather than the arity message.
    if is_closed(&args) {
        throw_socket_closed(scope);
        return;
    }
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

/// Whether the receiver's socket has been closed.
///
/// A key in [`CLOSED`] is closed; a key still in [`SOCKETS`] is live. A key in
/// neither is a socket whose result was dropped, which reads as closed too.
fn is_closed(args: &v8::FunctionCallbackArguments<'_>) -> bool {
    let Some(key) = key_of(args.this()) else {
        return true;
    };
    if CLOSED.with(|closed| closed.borrow().contains(&key)) {
        return true;
    }
    SOCKETS.with(|table| {
        table
            .borrow()
            .get(&key)
            .map(|socket| socket.closed)
            .unwrap_or(true)
    })
}

/// Throws Bun's `Socket is closed` error, which carries no `code`.
fn throw_socket_closed(scope: &mut v8::PinScope<'_, '_>) {
    if let Some(message) = v8::String::new(scope, "Socket is closed") {
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
    }
}

/// Reads a `(port, address)` pair in Bun's measured check order: the port range
/// first, then the address.
///
/// The port is read with `ToNumber`, then checked for an integer in `1..=65535`:
/// measured, `'1000'` and a `Number` object are accepted, while `null`,
/// `undefined`, an object, a float and out-of-range values all report the port
/// range error. A boolean is accepted too — `true` is port 1.
///
/// The address takes any value `uv_inet_pton` accepts after a `String()`
/// coercion — `'0x7f000001'`, `'127.1'`, `'2130706433'` and `'127.000.000.001'`
/// are all `127.0.0.1` — but a value that converts to something unparsable is
/// `TypeError: Invalid address`. The two classes are distinguishable: a *number*
/// that parses still reports `EINVAL` from `send`, while a string that does not
/// parse reports the `TypeError`.
fn destination_of(
    scope: &mut v8::PinScope<'_, '_>,
    port_value: v8::Local<'_, v8::Value>,
    address_value: v8::Local<'_, v8::Value>,
) -> Option<BoundAddress> {
    // `null` and `undefined` are the one case `ToNumber` would silently accept as
    // 0, so they are refused up front; everything else (a string, a boolean, a
    // `Number` object, an array holding one number) converts, which is measured:
    // `'1000'`, `new Number(1000)`, `true` and `[1000]` all send, while a plain
    // object converts to `NaN` and reports the range.
    if port_value.is_null() || port_value.is_undefined() {
        throw_port(scope);
        return None;
    }
    let Some(number) = port_value.number_value(scope) else {
        throw_port(scope);
        return None;
    };
    if !(1.0..=65535.0).contains(&number) || number.fract() != 0.0 {
        throw_port(scope);
        return None;
    }
    let port = number as u16;

    // The address goes through Bun's `inet_pton`-shaped parser, which is
    // glibc's `inet_aton` for IPv4 plus `inet_pton` for IPv6. Two distinct
    // failures are measurable and they are not interchangeable:
    //
    //   * a value that is `String()`-ed to something the parser rejects
    //     (`'127.0.0.1:80'`, `'localhost'`, `'256.0.0.1'`, `''`) is
    //     `TypeError: Invalid address`;
    //   * a value the parser *accepts* but cannot route to (`'10.1'`, `'0x1'`,
    //     a *number* like `42`) reaches `send` and fails there with libuv's
    //     `EINVAL`.
    //
    // `inet_aton` is also what makes `'0x7f000001'`, `'127.1'`, `'2130706433'`
    // and `'017700000001'` all mean `127.0.0.1`.
    let Some(text) = address_text(scope, address_value) else {
        throw_type_error(scope, "Invalid address");
        return None;
    };
    let parsable = parse_inet(&text).is_some();
    // A *number* whose text form is not an inet address still goes to `send` and
    // fails there with libuv's `EINVAL`, which is why the two failure classes
    // are distinguishable rather than collapsed.
    let unparsable = !parsable && address_value.is_number();
    if !parsable && !unparsable {
        throw_type_error(scope, "Invalid address");
        return None;
    }
    let family = if text.contains(':') { "IPv6" } else { "IPv4" };
    Some(BoundAddress {
        address: text,
        family,
        port,
        unparsable,
    })
}

/// The `String()` form of an address argument, or `None` when it has none.
///
/// `null`/`undefined` have no meaningful text; a boolean does (`'true'`), but
/// measured, it is rejected as `Invalid address` rather than sent, so it is
/// refused here too.
fn address_text(scope: &v8::PinScope<'_, '_>, value: v8::Local<'_, v8::Value>) -> Option<String> {
    if value.is_null() || value.is_undefined() || value.is_boolean() {
        return None;
    }
    Some(value.to_rust_string_lossy(scope))
}

/// Whether `text` is an inet address libuv can send to.
///
/// `Some(())` for a parsable address, `None` for one glibc's parser rejects. The
/// accepted IPv4 forms are `inet_aton`'s: `a.b.c.d`, `a.b.c`, `a.b` and a bare
/// 32-bit number, in decimal, octal (`0` prefix) or hex (`0x`).
fn parse_inet(text: &str) -> Option<()> {
    if text.is_empty() {
        return None;
    }
    if text.contains(':') {
        // IPv6 is `inet_pton`-only: there is no shorthand on this path, which is
        // why `::1` reaches `send` and fails with `EAFNOSUPPORT` there.
        return rn_uv::addr::ip6(text, 0).ok().map(|_| ());
    }
    inet_aton_value(text).map(|_| ())
}

/// The dotted-quad form of an IPv4 address, or the input unchanged for IPv6.
///
/// `inet_aton` accepts `'127.1'`, `'0x7f000001'`, `'2130706433'` and octal, but
/// `uv_ip4_addr` calls `inet_pton` and accepts only the four-part decimal form, so
/// the shorthand has to be expanded before the send. An input that is not an
/// accepted form is returned as-is and fails in `uv_ip4_addr`, which is the
/// behaviour a caller sees.
fn normalise_inet(text: &str) -> String {
    if text.contains(':') {
        return text.to_string();
    }
    match inet_aton_value(text) {
        Some(value) => {
            let [a, b, c, d] = value.to_be_bytes();
            format!("{a}.{b}.{c}.{d}")
        }
        None => text.to_string(),
    }
}

/// `inet_aton`'s value for `text`, or `None` when it does not parse.
///
/// `inet_aton` places the first `n-1` components in the top bytes and lets the
/// last one fill every remaining byte, which is what makes `'127.1'` equal
/// `127.0.0.1` and `'127.0.1'` equal `127.0.0.1` as well.
fn inet_aton_value(text: &str) -> Option<u32> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let count = parts.len();
    let mut address = 0u32;
    for (index, part) in parts.iter().enumerate() {
        let value = parse_inet_number(part)?;
        let last = index + 1 == count;
        // The last component spans every byte the earlier ones did not claim.
        let remaining_bytes = 4 - (count - 1);
        let limit = if last {
            match remaining_bytes {
                4 => u64::from(u32::MAX),
                3 => 0x00ff_ffff,
                2 => 0x0000_ffff,
                _ => u64::from(u8::MAX),
            }
        } else {
            u64::from(u8::MAX)
        };
        if value > limit {
            return None;
        }
        if last {
            address |= value as u32;
        } else {
            // Component `index` occupies byte `3 - index`, counting from the top.
            address |= (value as u32) << (8 * (3 - index));
        }
    }
    Some(address)
}

/// One dotted component: decimal, octal (`0` prefix) or hex (`0x` prefix).
fn parse_inet_number(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    let (radix, digits) =
        if let Some(rest) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            if rest.is_empty() {
                // `'0x'` alone is not a number.
                return None;
            }
            (16, rest)
        } else if part.len() > 1 && part.starts_with('0') {
            (8, &part[1..])
        } else {
            (10, part)
        };
    if !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// The bytes of a datagram payload: a string, or any `ArrayBufferView`.
///
/// Throws and returns `None` for anything else. The message differs by member —
/// `send` says "as first argument", `sendMany` says "as payload" — so the caller
/// supplies it; measured, they are not interchangeable.
fn payload_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    payload: v8::Local<'_, v8::Value>,
    message: &str,
) -> Option<Vec<u8>> {
    if payload.is_string() {
        return Some(payload.to_rust_string_lossy(scope).into_bytes());
    }
    // SAFETY: `view_bytes` copies, and `payload` is a live local for the call.
    match unsafe { view_bytes(payload) } {
        Some(bytes) => Some(bytes),
        None => {
            throw_type_error(scope, message);
            None
        }
    }
}

/// The `send` member's payload message.
const SEND_PAYLOAD_MESSAGE: &str = "Expected ArrayBufferView or string as first argument";

/// The `sendMany` member's payload message, which names the element instead.
const SEND_MANY_PAYLOAD_MESSAGE: &str = "Expected ArrayBufferView or string as payload";

/// Validates and sends one datagram, in Bun's measured check order.
///
/// The checks are payload, port, address — `send('x',0,'a')` reports the port and
/// not the payload type, which is why the payload is read last.
fn send_validated(
    scope: &mut v8::PinScope<'_, '_>,
    receiver: v8::Local<'_, v8::Object>,
    payload: &[v8::Local<'_, v8::Value>; 3],
) -> Result<(), Option<i32>> {
    // A connected socket accepts a lone payload; anything else needs three
    // arguments, and the arity error comes before any type check.
    let arity = if payload[1].is_undefined() && payload[2].is_undefined() {
        1
    } else {
        3
    };
    // `arity == 1` is only reachable on a connected socket, checked above. It
    // means "the peer is implicit", so the datagram is sent with a null address;
    // passing the peer explicitly returns `EISCONN`.
    let destination = if arity == 1 {
        None
    } else {
        match destination_of(scope, payload[1], payload[2]) {
            Some(destination) => Some(destination),
            None => return Err(None),
        }
    };

    let Some(bytes) = payload_bytes(scope, payload[0], SEND_PAYLOAD_MESSAGE) else {
        return Err(None);
    };

    let Some(key) = key_of(receiver) else {
        return Err(None);
    };
    SOCKETS.with(|table| {
        let mut table = table.borrow_mut();
        let Some(socket) = table.get_mut(&key) else {
            return Err(None);
        };
        send_datagram(socket, &bytes, destination.as_ref()).map_err(Some)
    })
}

/// Throws a failed send's status as an error.
fn throw_send_status(scope: &mut v8::PinScope<'_, '_>, status: Option<i32>) {
    let Some(status) = status else {
        return;
    };
    throw_uv_status(scope, status, "send");
}

/// Sends one datagram, returning libuv's status.
///
/// A **connected** socket must pass a NULL address to `uv_udp_try_send`: passing
/// the peer explicitly returns `EISCONN` ("socket is already connected"), which is
/// how the first implementation broke every connected send.
///
/// The address reaches libuv as dotted-quad text, so a shorthand form `inet_aton`
/// accepts (`'127.1'`, `'0x7f000001'`) is normalised first — `uv_ip4_addr` is
/// `inet_pton` and rejects those.
fn send_datagram(
    socket: &mut Socket,
    bytes: &[u8],
    destination: Option<&BoundAddress>,
) -> Result<(), i32> {
    let buffer = libuv_sys2::uv_buf_t {
        base: bytes.as_ptr() as *mut std::ffi::c_char,
        len: bytes.len(),
    };
    let address = match destination {
        Some(destination) if destination.unparsable => {
            return Err(libuv_sys2::uv_errno_t_UV_EINVAL)
        }
        Some(destination) => {
            let normalised = normalise_inet(&destination.address);
            Some(
                peer_address(&normalised, destination.port)
                    .ok_or(libuv_sys2::uv_errno_t_UV_EINVAL)?,
            )
        }
        None => None,
    };
    // SAFETY: the handle is live, the buffer outlives the call because libuv
    // copies it into its own send queue, and the address is a live `sockaddr`
    // (or null for a connected socket).
    let status = unsafe {
        match &address {
            None => libuv_sys2::uv_udp_try_send(
                std::ptr::from_mut(&mut *socket.handle),
                &buffer,
                1,
                std::ptr::null(),
            ),
            Some(AddressFamily::Four(address)) => libuv_sys2::uv_udp_try_send(
                std::ptr::from_mut(&mut *socket.handle),
                &buffer,
                1,
                (address as *const libuv_sys2::sockaddr_in).cast(),
            ),
            Some(AddressFamily::Six(address)) => libuv_sys2::uv_udp_try_send(
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

/// `sendMany(datagrams)` — a **flat** argument list, not an array of tuples.
///
/// Measured against Bun 1.4.4 (none of this is documented, and the tuple shape
/// the name implies is wrong in every particular):
///
/// ```text
/// connected    sendMany(['a','b','c'])            => 3   (each element one datagram)
/// unconnected  sendMany(['p', port, addr, ...])   => 2   (triplets, flat)
/// both         sendMany([])                       => 0
/// ```
///
/// The two shapes are decided by the socket, not the array: a connected socket
/// reads every element as a payload, an unconnected one reads the array as
/// consecutive `(data, port, address)` triplets and requires the length to be a
/// multiple of three.
///
/// # Validation is complete before the first datagram leaves
///
/// `sendMany(['a', port, ok, 'b', 0, ok])` throws and delivers **nothing**, so
/// the checks run over the whole array first. That is observable only as "how
/// many arrived", which is why it is spelled out here. Order within a triplet is
/// payload, then port, then address; the arity error for an unconnected socket
/// comes before all three.
fn method_send_many(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if args.length() == 0 {
        throw_type_error(scope, "Expected 1 argument, got 0");
        return;
    }
    // As with `send`, a closed socket is reported before anything else.
    if is_closed(&args) {
        throw_socket_closed(scope);
        return;
    }
    let Ok(list) = v8::Local::<v8::Array>::try_from(args.get(0)) else {
        throw_type_error(
            scope,
            "Expected first argument to be a array for 'sendMany'.",
        );
        return;
    };
    let connected = with_socket(&args, |socket| socket.remote.is_some()).unwrap_or(false);
    let length = list.length() as usize;
    if !connected && !length.is_multiple_of(3) {
        throw_type_error(scope, "Expected 3 arguments for each packet");
        return;
    }

    // Everything is validated and copied before anything is sent. The order
    // inside a packet is measured: payload, then port, then address — so
    // `[42, 'x', 'y']` reports the payload and `['a', 'x', 'y']` reports the
    // port.
    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    let mut destinations: Vec<Option<BoundAddress>> = Vec::new();
    let mut index = 0;
    while index < length {
        let Some(payload) = list.get_index(scope, index as u32) else {
            return;
        };
        let Some(bytes) = payload_bytes(scope, payload, SEND_MANY_PAYLOAD_MESSAGE) else {
            return;
        };
        let destination = if connected {
            None
        } else {
            let port_value = list
                .get_index(scope, (index + 1) as u32)
                .unwrap_or_else(|| v8::undefined(scope).into());
            let address_value = list
                .get_index(scope, (index + 2) as u32)
                .unwrap_or_else(|| v8::undefined(scope).into());
            let Some(destination) = destination_of(scope, port_value, address_value) else {
                return;
            };
            Some(destination)
        };
        datagrams.push(bytes);
        destinations.push(destination);
        index += if connected { 1 } else { 3 };
    }

    let Some(key) = key_of(args.this()) else {
        return;
    };
    let mut sent = 0f64;
    let failure = SOCKETS.with(|table| {
        let mut table = table.borrow_mut();
        // The key came from the receiver a moment ago, so `None` here means the
        // socket closed in between; that is not an error to report.
        let socket = table.get_mut(&key)?;
        for (bytes, destination) in datagrams.iter().zip(&destinations) {
            if let Err(status) = send_datagram(socket, bytes, destination.as_ref()) {
                return Some(status);
            }
            sent += 1.0;
        }
        None
    });
    match failure {
        None => rv.set(v8::Number::new(scope, sent).into()),
        Some(status) => throw_send_status(scope, Some(status)),
    }
}

/// `ref()` and `unref()`: both return `undefined`, whatever the socket's state.
fn method_keepalive(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `undefined` on a live socket and on a closed one alike, so no
    // refcount is observable through the return value.
    let _ = with_socket(&args, |_| ());
    rv.set(v8::undefined(scope).into());
}

/// `reload(options)`.
///
/// Measured: it takes the same option object the constructor does and returns
/// `undefined`. The parts of the option object it acts on are **narrower** than
/// the constructor's, and each was measured:
///
/// * a `socket.data` callback **replaces** the previous one, and the socket keeps
///   its bound port and its connection;
/// * `port` is validated but does **not** rebind — a socket reloaded with
///   `{port: 12345}` keeps reporting its original port;
/// * `connect` is accepted and ignored, so the peer survives;
/// * a non-object argument is `TypeError: Expected an object` with
///   `code: "ERR_INVALID_ARG_TYPE"`, and the arity message is
///   `Expected 1 argument`.
fn method_reload(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if args.length() == 0 {
        throw_type_error(scope, "Expected 1 argument");
        return;
    }
    let options = args.get(0);
    let Ok(object) = v8::Local::<v8::Object>::try_from(options) else {
        throw_coded_type_error(scope, "Expected an object", "ERR_INVALID_ARG_TYPE");
        return;
    };
    // `port` is validated with the constructor's range, which allows 0.
    if let Some(value) = property(scope, object, "port") {
        if !value.is_undefined() && !value.is_null() {
            let number = value.number_value(scope);
            let valid = number
                .is_some_and(|number| (0.0..=65535.0).contains(&number) && number.fract() == 0.0);
            if !valid {
                throw_coded_type_error(
                    scope,
                    "Expected \"port\" to be an integer between 0 and 65535",
                    "ERR_INVALID_ARG_TYPE",
                );
                return;
            }
        }
    }
    // A new `socket.data` replaces the old one; everything else about the socket
    // survives.
    let on_data = property(scope, object, "socket")
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .and_then(|socket| property(scope, socket, "data"))
        .and_then(|value| v8::Local::<v8::Function>::try_from(value).ok());
    if let Some(callback) = on_data {
        let global = v8::Global::new(scope, callback);
        let _ = with_socket(&args, |socket| {
            socket.on_data = Some(global);
        });
    }
    rv.set(v8::undefined(scope).into());
}

/// `setTTL(ttl)` and `setMulticastTTL(ttl)`.
///
/// Measured: both return the **number** they were given, after truncation
/// (`setTTL(4.7)` is `4`), and both throw libuv's own `EINVAL` for an out-of-range
/// value — `setTTL(0)` and `setMulticastTTL(0)` are `EINVAL`, and so is anything
/// above 255. `setTTL('3')` is `3` and `setTTL(true)` is `1`, so the argument is
/// coerced; `null`, `undefined` and an object are `EINVAL` rather than a
/// `TypeError`, because the coercion lands on `NaN` and libuv refuses it.
fn method_set_ttl<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
    multicast: bool,
) {
    let Some((value, status)) = ttl_argument(scope, &args, multicast) else {
        return;
    };
    if let Some(status) = status {
        throw_setsockopt_status(scope, status);
        return;
    }
    rv.set(v8::Number::new(scope, f64::from(value)).into());
}

/// Reads a TTL argument, applying it, and returns the value to report or the
/// libuv status that failed.
///
/// `None` means the socket is gone and a throw is already pending.
fn ttl_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    multicast: bool,
) -> Option<(i32, Option<i32>)> {
    if args.length() == 0 {
        throw_type_error(scope, "Expected 1 argument, got 0");
        return None;
    }
    let value = args.get(0);
    // Everything converts through `ToNumber`; a failed conversion is `NaN`, which
    // libuv refuses with `EINVAL` exactly as it refuses 0 and 256.
    let number = value.number_value(scope).unwrap_or(f64::NAN);
    let flag = if number.is_nan() {
        i32::MIN
    } else {
        number.trunc() as i32
    };
    if is_closed(args) {
        throw_setsockopt_status(scope, libuv_sys2::uv_errno_t_UV_EBADF);
        return None;
    }
    let status = with_socket(args, |socket| {
        // Bun rejects a TTL outside `1..=255` for both setters, before libuv sees
        // it — and libuv accepts 0 for the multicast one, so the range has to be
        // checked here rather than left to the call.
        if !(1..=255).contains(&flag) {
            return Some(libuv_sys2::uv_errno_t_UV_EINVAL);
        }
        // SAFETY: the handle is live and not closing.
        let status = unsafe {
            if multicast {
                libuv_sys2::uv_udp_set_multicast_ttl(std::ptr::from_mut(&mut *socket.handle), flag)
            } else {
                libuv_sys2::uv_udp_set_ttl(std::ptr::from_mut(&mut *socket.handle), flag)
            }
        };
        (status != 0).then_some(status)
    })?;
    Some((flag, status))
}

/// `setBroadcast(flag)` and `setMulticastLoopback(flag)`.
///
/// Measured: both return the argument **unchanged** — `setBroadcast('yes')` is
/// `'yes'`, `setBroadcast(0)` is `0`, `setMulticastLoopback(null)` is `null` —
/// while the socket is set from the argument's truthiness.
fn method_set_flag<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
    multicast_loop: bool,
) {
    if args.length() == 0 {
        throw_type_error(scope, "Expected 1 argument, got 0");
        return;
    }
    let value = args.get(0);
    let flag = i32::from(value.boolean_value(scope));
    if is_closed(&args) {
        throw_setsockopt_status(scope, libuv_sys2::uv_errno_t_UV_EBADF);
        return;
    }
    let status = with_socket(&args, |socket| {
        // SAFETY: the handle is live and not closing.
        let status = unsafe {
            if multicast_loop {
                libuv_sys2::uv_udp_set_multicast_loop(std::ptr::from_mut(&mut *socket.handle), flag)
            } else {
                libuv_sys2::uv_udp_set_broadcast(std::ptr::from_mut(&mut *socket.handle), flag)
            }
        };
        (status != 0).then_some(status)
    });
    match status {
        Some(Some(status)) => throw_setsockopt_status(scope, status),
        Some(None) => rv.set(value),
        None => {}
    }
}

/// `setMulticastInterface(interface)`.
///
/// Measured: returns `true` when libuv accepted the interface and `false` when it
/// could not parse it — the one member on the prototype that reports a failure as
/// `false` rather than a throw. An interface that *parses* but is not a local
/// address (`'1.2.3.4'`, or a number like `42`) still throws `EADDRNOTAVAIL`, so
/// the throw path is preserved. The shorthand `inet_aton` forms are expanded
/// first, so `'0x7f000001'` and `'127.1'` are accepted.
fn method_set_multicast_interface(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if args.length() == 0 {
        throw_type_error(scope, "Expected 1 argument, got 0");
        return;
    }
    let text = normalise_inet(&args.get(0).to_rust_string_lossy(scope));
    let Ok(interface) = std::ffi::CString::new(text) else {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    };
    if is_closed(&args) {
        throw_setsockopt_status(scope, libuv_sys2::uv_errno_t_UV_EBADF);
        return;
    }
    let status = with_socket(&args, |socket| {
        // SAFETY: the handle is live and the string outlives the call.
        let status = unsafe {
            libuv_sys2::uv_udp_set_multicast_interface(
                std::ptr::from_mut(&mut *socket.handle),
                interface.as_ptr(),
            )
        };
        Some(status)
    });
    match status.flatten() {
        // `UV_EINVAL` is what libuv returns for an interface it could not parse,
        // and Bun turns that one status into `false`.
        Some(status) if status == libuv_sys2::uv_errno_t_UV_EINVAL => {
            rv.set(v8::Boolean::new(scope, false).into());
        }
        Some(0) => rv.set(v8::Boolean::new(scope, true).into()),
        Some(status) => throw_setsockopt_status(scope, status),
        None => {}
    }
}

/// `addMembership(group, interface?)` and `dropMembership(group, interface?)`.
///
/// Measured: returns `true` on success. A group that does not parse is `EINVAL`,
/// dropping a group that was never joined is `EADDRNOTAVAIL`, and an omitted
/// interface means "the default one".
fn method_membership<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
    join: bool,
) {
    if args.length() == 0 {
        throw_type_error(scope, "Expected 1 argument, got 0");
        return;
    }
    let group = args.get(0).to_rust_string_lossy(scope);
    let Ok(group) = std::ffi::CString::new(group) else {
        throw_setsockopt_status(scope, libuv_sys2::uv_errno_t_UV_EINVAL);
        return;
    };
    let interface = optional_cstring(scope, &args, 1);
    let membership = if join {
        libuv_sys2::uv_membership_UV_JOIN_GROUP
    } else {
        libuv_sys2::uv_membership_UV_LEAVE_GROUP
    };
    if is_closed(&args) {
        throw_setsockopt_status(scope, libuv_sys2::uv_errno_t_UV_EBADF);
        return;
    }
    let status = with_socket(&args, |socket| {
        // SAFETY: the handle is live and both strings outlive the call.
        let status = unsafe {
            libuv_sys2::uv_udp_set_membership(
                std::ptr::from_mut(&mut *socket.handle),
                group.as_ptr(),
                interface
                    .as_ref()
                    .map_or(std::ptr::null(), |interface| interface.as_ptr()),
                membership,
            )
        };
        Some(status)
    });
    match status.flatten() {
        Some(0) => rv.set(v8::Boolean::new(scope, true).into()),
        Some(status) => throw_setsockopt_status(scope, status),
        None => {}
    }
}

/// `addSourceSpecificMembership(source, group)` and its `drop` counterpart.
///
/// Measured: these need **three** arguments (`length` is 3) and throw `EINVAL`
/// even when given a well-formed multicast address, because Bun passes the
/// arguments in an order libuv rejects. That is reproduced rather than corrected —
/// a caller that worked would be diverging from Bun.
fn method_source_membership<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
    join: bool,
) {
    if args.length() == 0 {
        throw_type_error(scope, "Expected 1 argument, got 0");
        return;
    }
    let source = args.get(0).to_rust_string_lossy(scope);
    let group = args.get(1).to_rust_string_lossy(scope);
    let (Ok(source), Ok(group)) = (
        std::ffi::CString::new(source),
        std::ffi::CString::new(group),
    ) else {
        throw_setsockopt_status(scope, libuv_sys2::uv_errno_t_UV_EINVAL);
        return;
    };
    let interface = optional_cstring(scope, &args, 2);
    let membership = if join {
        libuv_sys2::uv_membership_UV_JOIN_GROUP
    } else {
        libuv_sys2::uv_membership_UV_LEAVE_GROUP
    };
    if is_closed(&args) {
        throw_setsockopt_status(scope, libuv_sys2::uv_errno_t_UV_EBADF);
        return;
    }
    let status = with_socket(&args, |socket| {
        // SAFETY: the handle is live and every string outlives the call.
        let status = unsafe {
            libuv_sys2::uv_udp_set_source_membership(
                std::ptr::from_mut(&mut *socket.handle),
                group.as_ptr(),
                interface
                    .as_ref()
                    .map_or(std::ptr::null(), |interface| interface.as_ptr()),
                source.as_ptr(),
                membership,
            )
        };
        Some(status)
    });
    match status.flatten() {
        Some(0) => rv.set(v8::Boolean::new(scope, true).into()),
        Some(status) => throw_setsockopt_status(scope, status),
        None => {}
    }
}

/// An optional string argument as a `CString`, or `None` when omitted.
fn optional_cstring(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<std::ffi::CString> {
    let value = args.get(index);
    if value.is_undefined() || value.is_null() {
        return None;
    }
    std::ffi::CString::new(value.to_rust_string_lossy(scope)).ok()
}

/// Throws a libuv `setsockopt` failure in Bun's shape.
///
/// Bun formats these as `"<NAME>: <message>, <operation>"` and attaches
/// `code: "<NAME>"`; libuv's bare message is only the middle part. Measured, the
/// operation suffix is `setsockopt` for the membership and TTL setters and `send`
/// for a datagram failure.
fn throw_setsockopt_status(scope: &mut v8::PinScope<'_, '_>, status: i32) {
    throw_uv_status(scope, status, "setsockopt");
}

/// Throws a libuv failure as `"<NAME>: <message>, <operation>"` with `code`.
fn throw_uv_status(scope: &mut v8::PinScope<'_, '_>, status: i32, operation: &str) {
    let name = rn_bind_uv::name(status);
    let message = rn_bind_uv::message(status);
    let text = format!("{name}: {message}, {operation}");
    let Some(message) = v8::String::new(scope, &text) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let (Some(key), Some(value)) = (
            v8::String::new(scope, "code"),
            v8::String::new(scope, &name),
        ) {
            let _ = object.set(scope, key.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Throws a `TypeError` carrying a `code`, which is how Bun's argument errors
/// distinguish themselves from libuv's.
fn throw_coded_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let exception = v8::Exception::type_error(scope, text);
        if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
            if let Some(key) = v8::String::new(scope, "code") {
                if let Some(value) = v8::String::new(scope, code) {
                    let _ = object.set(scope, key.into(), value.into());
                }
            }
        }
        scope.throw_exception(exception);
    }
}

/// Throws a `TypeError` with Bun's udp `ERR_INVALID_ARG_TYPE` code.
fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    throw_coded_type_error(scope, message, "ERR_INVALID_ARG_TYPE");
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
