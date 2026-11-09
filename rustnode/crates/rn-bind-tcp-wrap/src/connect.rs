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
    // The request and the object it belongs to are rooted for the completion.
    let completion = Box::new(ConnectCompletion {
        request: v8::Global::new(scope.as_ref(), *request),
        handle: v8::Global::new(scope.as_ref(), handle_object),
        // The state is needed to answer `uv_is_readable`/`uv_is_writable` when
        // the connection completes; the handle owns it, so a raw pointer is
        // enough as long as the handle outlives the connect.
        state: &mut handle.state as *mut StreamState,
    });
    let completion = Box::into_raw(completion);

    let storage = Box::into_raw(Box::new(std::mem::MaybeUninit::<uv::uv_connect_t>::zeroed()));
    // SAFETY: `storage` is a live, aligned, zeroed `uv_connect_t`.
    let request_ref = unsafe { (*storage).as_mut_ptr() };
    // SAFETY: `request_ref` is live and `data` is the slot libuv hands back.
    unsafe {
        (*request_ref).data = completion.cast::<c_void>();
    }

    // `uv_ip4_addr`/`uv_ip6_addr` reject anything that is not a numeric literal,
    // which is exactly Node's behaviour: `lib/net.js` resolves names through
    // `dns.lookup` and only ever passes an address here.
    let status = if family == 4 {
        match addr::ip4(address, port) {
            Ok(sockaddr) => {
                // SAFETY: the handle is live and `sockaddr` outlives this call.
                unsafe {
                    uv::uv_tcp_connect(
                        request_ref,
                        handle.tcp.as_mut(),
                        std::ptr::from_ref(&sockaddr).cast(),
                        Some(after_connect),
                    )
                }
            }
            Err(status) => status,
        }
    } else {
        match addr::ip6(address, port) {
            Ok(sockaddr) => {
                // SAFETY: as above.
                unsafe {
                    uv::uv_tcp_connect(
                        request_ref,
                        handle.tcp.as_mut(),
                        std::ptr::from_ref(&sockaddr).cast(),
                        Some(after_connect),
                    )
                }
            }
            Err(status) => status,
        }
    };

    if status != 0 {
        // Nothing was queued, so the callback will not run and both allocations
        // are still ours.
        // SAFETY: both came from `Box::into_raw` above and libuv refused the
        // request.
        unsafe {
            drop(Box::from_raw(storage));
            drop(Box::from_raw(completion));
        }
    }

    status
}

/// State a queued connect carries to its completion.
struct ConnectCompletion {
    request: v8::Global<v8::Object>,
    handle: v8::Global<v8::Object>,
    state: *mut StreamState,
}

/// libuv's connect completion, which drives `afterConnect` in `lib/net.js`.
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
        let _ = callback.call(&*scope, receiver, &arguments);
    });
}
