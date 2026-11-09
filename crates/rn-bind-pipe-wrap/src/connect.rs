//! `PipeWrap::Connect`, and the completion `afterConnect` expects.
//!
//! `lib/net.js`'s `internalConnect` builds a `PipeConnectWrap`, sets
//! `oncomplete = afterConnect` and `address` to the path, then calls
//! `handle.connect(req, path)`. The completion passes the same five arguments a
//! TCP connect does — `(status, handle, req, readable, writable)` — even though
//! only the first three are meaningful for a pipe.

use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::handle::StreamState;

use crate::handle::PipeHandle;

/// Issues `uv_pipe_connect2` for a request built by `lib/net.js`.
///
/// Returns libuv's status: `0` when the completion is queued, a negative error
/// otherwise. `lib/net.js` destroys the socket on a non-zero status.
pub fn dispatch(
    scope: &mut v8::PinScope<'_, '_>,
    handle: &mut PipeHandle,
    request: &v8::Local<v8::Object>,
    handle_object: v8::Local<v8::Object>,
    path: &str,
) -> i32 {
    let completion = Box::new(ConnectCompletion {
        request: v8::Global::new(scope.as_ref(), *request),
        handle: v8::Global::new(scope.as_ref(), handle_object),
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

    // A path may start with `\0` for the Linux abstract namespace, so it must not
    // go through `CString`: the length is passed explicitly and truncation is
    // refused, matching `UV_PIPE_NO_TRUNCATE` in `src/pipe_wrap.cc`.
    let bytes = path.as_bytes();
    // SAFETY: the handle is live and `bytes` outlives the call.
    let status = unsafe {
        uv::uv_pipe_connect2(
            request_ref,
            handle.pipe.as_mut(),
            bytes.as_ptr().cast(),
            bytes.len(),
            uv::UV_PIPE_NO_TRUNCATE,
            Some(after_connect),
        )
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

    // `ConnectionWrap::AfterConnect` computes these from the handle after the
    // connection succeeds. `afterConnect` uses them to decide whether to start
    // reading and writing, so a wrong value turns a connected pipe into one that
    // never reads.
    let (readable, writable) = if status != 0 {
        (false, false)
    } else {
        // SAFETY: `state` points into the handle that owns the connect, which is
        // still alive because `lib/net.js` keeps the socket referenced until the
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
        // the request object.
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
