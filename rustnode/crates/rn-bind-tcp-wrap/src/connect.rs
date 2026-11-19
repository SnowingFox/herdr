//! `TCPWrap::Connect` / `Connect6`, and their completion.
//!
//! `lib/net.js`'s `internalConnect` builds a `TCPConnectWrap`, assigns
//! `oncomplete = afterConnect` and the `address`/`port`/`localAddress`/
//! `localPort`/`addressType` fields, then calls `handle.connect(req, address, port)`.
//! The completion calls `afterConnect(status, handle, req, readable, writable)`,
//! so all five arguments have to arrive — `readable` and `writable` are what
//! decide whether `net.js` starts reading and writing, and a missing one turns a
//! connected socket into one that never reads.

use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::addr;
use rn_uv::handle::StreamState;

use crate::handle::TcpHandle;

/// Issues `uv_tcp_connect` for a request built by `lib/net.js`.
///
/// Returns libuv's status: `0` when the completion is queued, a negative error
/// otherwise. `lib/net.js` destroys the socket on a non-zero status, so an error
/// here must not also produce a callback.
pub fn dispatch(
    scope: &mut v8::PinScope<'_, '_>,
    handle: &mut TcpHandle,
    request: &v8::Local<v8::Object>,
    handle_object: v8::Local<v8::Object>,
    address: &str,
    port: u16,
    family: u8,
) -> i32 {
    // `uv_ip4_addr`/`uv_ip6_addr` reject anything that is not a numeric literal,
    // which is exactly Node's behaviour: `lib/net.js` resolves names through
    // `dns.lookup` and only ever passes an address here.
    let parsed = if family == 4 {
        addr::ip4(address, port).map(ParsedAddress::V4)
    } else {
        addr::ip6(address, port).map(ParsedAddress::V6)
    };
    // `int err = uv_ip_addr(*ip_address, port, &addr); if (err == 0) { ... }`
    // (`src/tcp_wrap.cc:580`). Node returns the parse error without constructing
    // a wrap, so nothing is emitted and nothing is rooted.
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(status) => return status,
    };

    // `AsyncHooks::DefaultTriggerAsyncIdScope trigger_scope(wrap);` then
    // `new ConnectWrap(env, req_wrap_obj, PROVIDER_TCPCONNECTWRAP)`
    // (`src/tcp_wrap.cc:586-588`). The async resource is the *request*, not the
    // socket: `lib/net.js` builds one `TCPConnectWrap` per attempt and
    // `lib/internal/http/agent.js` resets and reuses the socket, so the request
    // is what names a single connection. The handle's own `TCPWRAP` came from
    // the `TCP` constructor and this path does not touch it.
    //
    // The trigger scope is the handle, so the request's `triggerAsyncId` is the
    // socket being connected rather than whatever happened to be executing.
    let socket_id = handle.state.async_wrap.async_id;
    let async_wrap = rn_bind_async_wrap::with_default_trigger_async_id(socket_id, || {
        new_connect_wrap(scope, *request)
    });

    // The request and the object it belongs to are rooted for the completion.
    let completion = Box::new(ConnectCompletion {
        request: v8::Global::new(scope.as_ref(), *request),
        handle: v8::Global::new(scope.as_ref(), handle_object),
        // The state is needed to answer `uv_is_readable`/`uv_is_writable` when
        // the connection completes; the handle owns it, so a raw pointer is
        // enough as long as the handle outlives the connect.
        state: &mut handle.state as *mut StreamState,
        async_wrap,
    });
    let completion = Box::into_raw(completion);

    let storage = Box::into_raw(Box::new(std::mem::MaybeUninit::<uv::uv_connect_t>::zeroed()));
    // SAFETY: `storage` is a live, aligned, zeroed `uv_connect_t`.
    let request_ref = unsafe { (*storage).as_mut_ptr() };
    // SAFETY: `request_ref` is live and `data` is the slot libuv hands back.
    unsafe {
        (*request_ref).data = completion.cast::<c_void>();
    }

    // SAFETY: the handle is live and the `sockaddr` in `parsed` outlives this
    // call — libuv copies it.
    let status = unsafe {
        match &parsed {
            ParsedAddress::V4(address) => uv::uv_tcp_connect(
                request_ref,
                handle.tcp.as_mut(),
                std::ptr::from_ref(address).cast(),
                Some(after_connect),
            ),
            ParsedAddress::V6(address) => uv::uv_tcp_connect(
                request_ref,
                handle.tcp.as_mut(),
                std::ptr::from_ref(address).cast(),
                Some(after_connect),
            ),
        }
    };

    if status != 0 {
        // `if (err) { delete req_wrap; }` — nothing was queued, so the callback
        // will not run and both allocations are still ours. Node's destructor
        // runs `EmitDestroy` for the id the constructor just created, which is
        // what keeps the `init` from being unbalanced.
        rn_bind_async_wrap::emit_destroy(async_wrap.async_id);
        // SAFETY: both came from `Box::into_raw` above and libuv refused the
        // request.
        unsafe {
            drop(Box::from_raw(storage));
            drop(Box::from_raw(completion));
        }
    }

    status
}

/// The `sockaddr` an address literal parsed into, kept alive across the call.
enum ParsedAddress {
    V4(uv::sockaddr_in),
    V6(uv::sockaddr_in6),
}

/// `new ConnectWrap(env, req_wrap_obj, PROVIDER_TCPCONNECTWRAP)`.
///
/// The request object is the resource `init` receives, not the socket:
/// `lib/net.js`'s `afterConnect` is handed the same `req`, and Node's
/// `lookupPublicResource` maps it through `resource_symbol` back to itself, so
/// passing it directly is the answer that lookup would give.
fn new_connect_wrap(
    scope: &mut v8::PinScope<'_, '_>,
    request: v8::Local<v8::Object>,
) -> rn_core::AsyncWrapState {
    let mut state =
        rn_core::AsyncWrapState::uninitialised(rn_core::async_wrap::PROVIDER_TCPCONNECTWRAP);
    if let Some((async_id, trigger_async_id)) = rn_bind_async_wrap::emit_init_for_new_resource(
        scope,
        request,
        rn_core::async_wrap::PROVIDER_TCPCONNECTWRAP,
    ) {
        state.async_id = async_id;
        state.trigger_async_id = trigger_async_id;
    }
    state
}

/// State a queued connect carries to its completion.
struct ConnectCompletion {
    request: v8::Global<v8::Object>,
    handle: v8::Global<v8::Object>,
    state: *mut StreamState,
    /// The request's `AsyncWrap` fields: `PROVIDER_TCPCONNECTWRAP` and the ids
    /// the `init` hook was given, so the completion can push a context and emit
    /// `before`/`after`/`destroy` for the same resource Node does.
    async_wrap: rn_core::AsyncWrapState,
}

/// libuv's connect completion, which drives `afterConnect` in `lib/net.js`.
///
/// The request object is the resource, not the socket: `lib/net.js`'s
/// `afterConnect` receives the same `req` and Node's `AsyncWrap` maps it through
/// `resource_symbol` back to itself, so `new_connect_wrap` hands it over
/// directly, which is the same answer `lookupPublicResource` would give.
///
/// # Safety
///
/// Called by libuv with the `uv_connect_t` [`dispatch`] allocated.
unsafe extern "C" fn after_connect(request: *mut uv::uv_connect_t, status: i32) {
    if request.is_null() {
        return;
    }
    // SAFETY: `dispatch` stored this pointer in `data`.
    let completion = unsafe { (*request).data.cast::<ConnectCompletion>() };
    // SAFETY: the request came from `Box<MaybeUninit<uv_connect_t>>` and libuv is
    // finished with it.
    drop(unsafe { Box::from_raw(request.cast::<std::mem::MaybeUninit<uv::uv_connect_t>>()) });

    if completion.is_null() {
        return;
    }
    // SAFETY: the pointer came from `Box::into_raw` and nothing else reclaimed it.
    let completion = unsafe { Box::from_raw(completion) };

    // `ConnectionWrap::AfterConnect` computes these from the handle *after* the
    // connection succeeds, and `afterConnect` uses them to decide whether to
    // start reading and writing.
    let (readable, writable) = if status != 0 {
        (false, false)
    } else {
        // SAFETY: `state` points into the handle that owns the connect, which is
        // still alive: `lib/net.js` keeps the socket referenced until the
        // completion runs.
        let state = unsafe { &*completion.state };
        let stream = state.stream;
        // SAFETY: the stream is live.
        unsafe {
            (
                uv::uv_is_readable(stream) != 0,
                uv::uv_is_writable(stream) != 0,
            )
        }
    };

    rn_uv::callback::with_context(|scope| {
        let request: v8::Local<v8::Object> = v8::Local::new(scope, &completion.request);
        let handle: v8::Local<v8::Object> = v8::Local::new(scope, &completion.handle);

        let Some(key) = v8::String::new(scope, "oncomplete") else {
            return;
        };
        let Some(value) = request.get(scope, key.into()) else {
            return;
        };
        let Ok(callback) = v8::Local::<v8::Function>::try_from(value) else {
            return;
        };

        // `afterConnect(status, handle, req, readable, writable)`, with `this` as
        // the request object — that is what `req_wrap->MakeCallback` does.
        let arguments: [v8::Local<v8::Value>; 5] = [
            v8::Integer::new(scope, status).into(),
            handle.into(),
            request.into(),
            v8::Boolean::new(scope, readable).into(),
            v8::Boolean::new(scope, writable).into(),
        ];
        let receiver: v8::Local<v8::Value> = request.into();
        // `ReqWrap::Done` runs the completion through `MakeCallback`, which
        // pushes the request's async context and emits `before`/`after` for it,
        // so `executionAsyncId()` inside `afterConnect` answers the request's id.
        // Calling the handler bare left the request's `init` with no matching
        // `before`, which is exactly what `init-hooks.js`'s `sanityCheck`
        // reports as "called before" / "expects 1 before".
        let callback = v8::Global::new(scope.as_ref(), callback);
        let context = rn_core::callback_scope::AsyncContext::from(completion.async_wrap);
        let resource = v8::Global::new(scope.as_ref(), request);
        let receiver = v8::Global::new(scope.as_ref(), receiver);
        let arguments: Vec<v8::Global<v8::Value>> = arguments
            .iter()
            .map(|argument| v8::Global::new(scope.as_ref(), *argument))
            .collect();
        let result = rn_core::callback_scope::with_scope(
            scope,
            rn_core::callback_scope::ScopeArgs {
                context,
                resource: Some(resource),
                frame: None,
            },
            |scoped| {
                let callback: v8::Local<v8::Function> = v8::Local::new(scoped, &callback);
                let receiver = v8::Local::new(scoped, &receiver);
                let arguments: Vec<v8::Local<v8::Value>> = arguments
                    .iter()
                    .map(|argument| v8::Local::new(scoped, argument))
                    .collect();
                let _ = callback.call(scoped, receiver, &arguments);
            },
        );
        // `ReqWrap<uv_connect_t>::Done` calls `EmitDestroy` after the callback
        // returns, so the `init` this wrap emitted is balanced.
        if result.is_some() {
            rn_bind_async_wrap::emit_destroy(completion.async_wrap.async_id);
        }
    });
}
