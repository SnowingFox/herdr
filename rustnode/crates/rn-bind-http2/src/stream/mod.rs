//! `binding.Http2Stream`: one stream's handle and its prototype methods.
//!
//! `lib/internal/http2/core.js` never constructs this. It receives one as the
//! `handle` argument of `onSessionHeaders` and wraps it:
//!
//! ```js
//! stream = new ServerHttp2Stream(session, handle, id, {}, obj);
//! ```
//!
//! so the handle has to exist before that callback fires. [`handle_for`] creates it
//! from the callbacks module, and the session keeps it rooted per id so a later
//! `on_data_chunk` or `on_stream_close` can reach it — there is no local handle in a
//! libuv callback. Node gets the same reachability from
//! `nghttp2_session_set_stream_user_data`, which stores a pointer in nghttp2's own
//! stream object; a map of `v8::Global`s is the Rust spelling.
//!
//! # Scope of this increment
//!
//! The constructor, the id, the state refresh and the four `StreamBase` counters are
//! installed. The frame-submitting methods (`respond`, `info`, `trailers`,
//! `pushPromise`) submit real nghttp2 frames. The write path copies into a pending
//! queue that [`provider`] drains, rather than reading back through a `StreamBase`,
//! because the writable side in `core.js` is a JavaScript `Duplex`.
//!
//! `sendFile`'s descriptor path is absent: it needs `fs`'s `FileHandle`, which is
//! deferred in `rn-bind-fs`, and nothing else in `lib/**` reaches for it.

pub mod provider;
pub mod stream_base;

use std::cell::{Cell, RefCell};
use std::ptr;

use rn_v8_sys::v8;

use crate::ffi;
use crate::session::SessionState;

/// The internal field holding the `*mut StreamHandleState`.
const STREAM_FIELD: i32 = 0;

/// The native half of a `binding.Http2Stream`.
///
/// The authoritative stream record lives in [`SessionState::streams`] keyed by id,
/// because nghttp2 owns the protocol state and the record is only what the
/// callbacks need to see. This struct carries what each prototype method needs
/// without a second map lookup.
pub struct StreamHandleState {
    /// The session this stream belongs to.
    pub session: *mut SessionState,
    /// `nghttp2_stream`'s id.
    pub id: i32,
    /// `headers_category()`.
    pub category: i32,
    /// `streamOptions` the stream was created with.
    pub options: i32,
    /// The JS object, rooted.
    pub object: RefCell<Option<v8::Global<v8::Object>>>,
    /// Whether the readable side has been started.
    pub reading: Cell<bool>,
    /// `AsyncWrap`'s identity for this stream: the id `getAsyncId` reports and
    /// the trigger id `async_hooks` records.
    ///
    /// Node's `Http2Stream` is an `AsyncWrap`, so every stream is an async
    /// resource with its own id. `core.js` stores `handle.getAsyncId()` on
    /// `async_id_symbol` and uses it for `defaultTriggerAsyncIdScope`, so a
    /// placeholder id collapses a stream's async context onto whatever id it
    /// borrowed — which is what `AsyncLocalStorage` reports as the wrong store.
    pub async_wrap: rn_core::AsyncWrapState,
    /// The async context frame captured when the stream was created.
    ///
    /// `AsyncWrap`'s constructor stores `async_context_frame::current()`, and every
    /// callback the resource runs restores it. `AsyncLocalStorage` propagates
    /// through *this*, not through the id: without it `storage.getStore()` is
    /// `undefined` inside a stream callback even though `executionAsyncId()` is
    /// right.
    pub context_frame: Option<v8::Global<v8::Value>>,
    /// The `StreamBase` half.
    ///
    /// `Http2Stream` is `AsyncWrap + StreamBase` in Node, and this is what makes
    /// the handle usable as either end of a `StreamPipe` — `lib/internal/http2`'s
    /// `sendFile` path and the tests that pipe a stream into another stream both
    /// depend on it. The `StreamState` is kept here rather than beside the box so
    /// the allocation that the ops' owner pointer names is this one.
    pub stream: crate::stream::stream_base::StreamHalf,
}

thread_local! {
    /// The one `Http2Stream` constructor this isolate publishes and makes handles
    /// from, together with the isolate it belongs to.
    ///
    /// Node caches the template on the `Environment`
    /// (`env->http2stream_constructor_template()`, `src/node_http2.cc:3664-3675`) so
    /// that `Initialize` publishing `binding.Http2Stream` and `Http2Stream::New`
    /// building a handle both use the *same* template — which is the only reason a
    /// handle is an `instanceof` the class JavaScript can see. Building a second
    /// template for either site leaves every handle an instance of a class nobody
    /// can reach, so `instanceof` is false and a patched prototype method is
    /// invisible to the handle `core.js` calls into.
    ///
    /// The cached `v8::Global` dies with the isolate rather than beside it:
    /// [`reset_constructor_cache`] drops it when the namespace is installed, and
    /// `rn-bind-http2`'s `install` is the only writer — it runs once per isolate, for
    /// the main thread and again on each worker thread, which has an isolate of its
    /// own — so the drop happens before the isolate that owned the global is
    /// disposed. The recorded address is a second line of defence for a read that
    /// arrives between two installs, which is the sqlite template cache's
    /// arrangement.
    static CONSTRUCTOR: RefCell<Option<CachedConstructor>> = const { RefCell::new(None) };
}

/// A `Http2Stream` constructor belonging to one isolate, by address.
struct CachedConstructor {
    isolate: usize,
    constructor: v8::Global<v8::Function>,
}

/// The isolate address a scope belongs to, for the cache's ownership check.
///
/// Address-comparison alone cannot distinguish a new isolate from a disposed one
/// that happened to be allocated at the same address; that is why the cache is
/// also cleared on install. The address is only ever compared, never dereferenced.
fn isolate_address(scope: &v8::PinScope<'_, '_>) -> usize {
    let isolate: &v8::Isolate = scope.as_ref();
    // SAFETY: reading the address is not a dereference.
    unsafe { std::mem::transmute::<v8::UnsafeRawIsolatePtr, usize>(isolate.as_raw_isolate_ptr()) }
}

/// Drops the cached constructor when the namespace is installed.
///
/// Called from the namespace install, which happens once per isolate: the main
/// thread installs before running any JavaScript, and a worker thread installs on
/// its own thread before its realm boots. Dropping here is what keeps the
/// `v8::Global` from outliving the isolate that owns it — `sqlite` resets its
/// per-isolate template caches the same way, and for the same reason.
///
/// Unconditional rather than keyed on the isolate address, because two isolates
/// allocated one after the other can share an address: a disposed isolate's
/// `Global` is a handle into freed storage, and an address comparison cannot tell
/// the two apart. "Install happened" is the fact that can, because the registry
/// caches the namespace object, so a second install in one isolate rebuilds
/// nothing that is still in use.
pub fn reset_constructor_cache() {
    CONSTRUCTOR.with(|slot| *slot.borrow_mut() = None);
}

/// The cached `Http2Stream` constructor function, if this isolate has one.
fn cached_constructor<'s>(scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    let address = isolate_address(scope);
    CONSTRUCTOR.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|cached| cached.isolate == address)
            .map(|cached| v8::Local::new(scope, &cached.constructor))
    })
}

/// Builds the `Http2Stream` constructor and its prototype.
///
/// This is `Initialize`'s template-building block plus `SetConstructorFunction`
/// publishing it: the first call in an isolate builds the template and caches the
/// function, and every later call — including the one inside [`handle_for`] —
/// returns that same function, so a handle's prototype *is* the exported class's
/// prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    if let Some(constructor) = cached_constructor(scope) {
        return Ok(constructor.into());
    }
    let function = build_constructor(scope)?;
    let address = isolate_address(scope);
    let rooted = v8::Global::new(scope.as_ref(), function);
    CONSTRUCTOR.with(|slot| {
        *slot.borrow_mut() = Some(CachedConstructor {
            isolate: address,
            constructor: rooted,
        })
    });
    Ok(function.into())
}

/// Builds the `Http2Stream` template and returns the function it produced.
fn build_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let template = rn_core::class(new).build(scope);
    let name = v8::String::new(scope, "Http2Stream")
        .ok_or("cannot allocate the Http2Stream class name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(STREAM_FIELD as usize + 1);

    let prototype = template.prototype_template(scope);
    macro_rules! install {
        ($($name:literal => $method:expr),* $(,)?) => {
            $(
                let method_template = rn_core::method($method)
                    .build(scope);
                let key = v8::String::new(scope, $name)
                    .ok_or_else(|| format!("cannot allocate Http2Stream.{}", $name))?;
                prototype.set(key.into(), method_template.into());
            )*
        };
    }
    install! {
        "id" => get_id,
        "destroy" => destroy,
        "rstStream" => rst_stream,
        "respond" => respond,
        "info" => info,
        "trailers" => trailers,
        "pushPromise" => push_promise,
        "priority" => priority,
        "disableAutoTrailers" => disable_auto_trailers,
        "refreshState" => refresh_state,
        "readStart" => read_start,
        "readStop" => read_stop,
        "shutdown" => shutdown,
        "writeBuffer" => write_buffer,
        "writev" => writev,
        "writeAsciiString" => write_ascii,
        "writeUtf8String" => write_utf8,
        "writeUcs2String" => write_ucs2,
        "writeLatin1String" => write_latin1,
        "useUserBuffer" => use_user_buffer,
        "bytesRead" => get_bytes_read,
        "bytesWritten" => get_bytes_written,
        "getAsyncId" => get_async_id,
    }

    // `t->PrototypeTemplate()->Set("isStreamBase", True(isolate))`, which
    // `StreamBase::AddMethods` installs. `lib/internal/http2/core.js` tests it
    // before treating a handle as a stream (`core.js:1385`), and `StreamPipe`'s
    // constructor is the other reader: without it the handle cannot be a pipe end.
    let is_stream_base = v8::Boolean::new(scope, true);
    prototype.set(
        v8::String::new(scope, "isStreamBase")
            .ok_or("cannot allocate the isStreamBase name")?
            .into(),
        is_stream_base.into(),
    );

    template
        .get_function(scope)
        .ok_or_else(|| "cannot allocate the Http2Stream constructor".to_string())
}

/// `new binding.Http2Stream()`.
///
/// Node's template has **no** `New` callback — `Initialize` builds it with
/// `FunctionTemplate::New(isolate)` and a class name — so constructing one from
/// JavaScript yields an empty object carrying the prototype and an internal field.
/// [crate::stream::handle_for] is what fills that field in when *this* crate makes
/// the stream, which is the only path any caller takes; a bare construction has no
/// state and every method on it reports the "no state" case rather than crashing.
fn new(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Node's template has no `New` callback at all, so V8 applies the default
    // return: the value of `this`. Called with `new` that is the fresh instance,
    // which is why the receiver is echoed here rather than left as `undefined`.
    // Called without `new` it is the global object, which is also exactly what
    // Node yields - the one constructor in this namespace where a plain call is
    // legal and the answer is observable.
    rv.set(args.this().into());
}

/// The state behind a stream handle object.
fn with_state<R>(
    object: v8::Local<'_, v8::Object>,
    body: impl FnOnce(&StreamHandleState) -> R,
) -> Option<R> {
    if object.internal_field_count() <= STREAM_FIELD as usize {
        return None;
    }
    // SAFETY: the field only ever holds a pointer installed by `handle_for`, and
    // the object is a live local so its finalizer has not run.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STREAM_FIELD, 0) }
        as *mut StreamHandleState;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above; the borrow is scoped to one callback.
    Some(body(unsafe { &*pointer }))
}

/// The session behind a stream handle.
fn session_of(object: v8::Local<'_, v8::Object>) -> Option<&'static SessionState> {
    let pointer = with_state(object, |state| state.session)?;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: a stream is only reachable through the session that created it, so
    // the session outlives it.
    Some(unsafe { &*pointer })
}

/// Creates the JS handle for `stream_id`, reusing the one the session holds.
pub fn handle_for<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    session: &SessionState,
    stream_id: i32,
    category: i32,
    options: i32,
) -> Option<v8::Local<'s, v8::Object>> {
    if let Some(existing) = session.handles.borrow().get(&stream_id) {
        return Some(v8::Local::new(scope, existing));
    }
    // `constructor` returns the isolate's cached function when there is one, so
    // this instance is made from the same template `binding.Http2Stream` was
    // published from. That is what makes `handle instanceof binding.Http2Stream`
    // true and what lets `core.js`'s prototype patches reach this handle.
    let function = v8::Local::<v8::Function>::try_from(constructor(scope).ok()?).ok()?;
    let object = function.new_instance(scope, &[])?;

    let state = Box::into_raw(Box::new(StreamHandleState {
        session: (session as *const SessionState).cast_mut(),
        id: stream_id,
        category,
        options,
        object: RefCell::new(Some(v8::Global::new(scope.as_ref(), object))),
        reading: Cell::new(false),
        // The id comes from the one sequence the JavaScript side also draws from,
        // which is what `Environment::new_async_id` guarantees and what a local
        // counter would not.
        context_frame: rn_bind_async_wrap::current_context_frame(scope),
        async_wrap: rn_core::AsyncWrapState {
            async_id: rn_bind_async_wrap::next_async_id(),
            trigger_async_id: current_trigger_async_id(),
            provider: rn_core::async_wrap::PROVIDER_HTTP2STREAM,
        },
        stream: stream_base::StreamHalf::new(),
    }));
    object.set_aligned_pointer_in_internal_field(STREAM_FIELD, state.cast::<std::ffi::c_void>(), 0);

    // The `StreamBase` half. `Http2Stream` is `AsyncWrap + StreamBase` in Node,
    // so this is what lets the handle be an end of a `StreamPipe` — and the
    // `owner_object` is what the default listener delivers a read to.
    // SAFETY: `state` is the live allocation just made, and its `stream` field is
    // in that same allocation so it outlives the state.
    unsafe {
        (*state).stream.install_owner(state);
        let pointer = (*state).stream.state_pointer();
        (*pointer).owner_object = Some(v8::Global::new(scope.as_ref(), object));
        // `StreamBase::FromObject` is how `StreamPipe` finds a stream. An HTTP/2
        // stream has no `uv_stream_t`, so the *state* is published.
        rn_uv::streams::attach_state(scope, object, pointer);
    }

    let address = state as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this finalizer
            // runs exactly once.
            drop(unsafe { Box::from_raw(address as *mut StreamHandleState) });
        }),
    );
    // The weak handle must outlive the object it finalizes.
    std::mem::forget(weak);

    session
        .handles
        .borrow_mut()
        .insert(stream_id, v8::Global::new(scope.as_ref(), object));
    Some(object)
}

/// The JS handle for `stream_id`, if one exists.
pub fn object_for<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    session: &SessionState,
    stream_id: i32,
) -> Option<v8::Local<'s, v8::Object>> {
    session
        .handles
        .borrow()
        .get(&stream_id)
        .map(|handle| v8::Local::new(scope, handle))
}

/// The `StreamBase` state behind a stream handle object.
///
/// Used by [`settle_writes`], which has the object but needs the state the
/// listener layer takes.
pub fn state_pointer_of(
    object: v8::Local<'_, v8::Object>,
) -> Option<*mut rn_uv::handle::StreamState> {
    with_state(object, |state| state.stream.state_pointer())
}

/// The rooted handle for `stream_id`, as a `Global`.
///
/// [`settle_writes`] runs from a libuv completion, where no local handle exists.
pub fn object_for_anywhere(
    session: &SessionState,
    stream_id: i32,
) -> Option<v8::Global<v8::Object>> {
    session.handles.borrow().get(&stream_id).cloned()
}

/// Delivers `bytes` to `stream_id`'s readable side through its `onread`.
///
/// `stream_base_commons.js`'s `onStreamRead` does not take the byte count as an
/// argument: it reads it from `streamBaseState[kReadBytesOrError]` and builds a
/// `FastBuffer` over the `ArrayBuffer` it is given at
/// `streamBaseState[kArrayBufferOffset]`. So the count is published first, then
/// `onread` is called with the buffer — which is exactly what
/// `CallJSOnreadMethod` does.
///
/// The `onread` a stream handle carries is assigned by `core.js` in `kInit`
/// (`handle.onread = onStreamRead`), so the property lookup is the same one
/// `lib/net.js` relies on.
pub fn deliver_data(session: &SessionState, stream_id: i32, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    // Whether the readable side is flowing, mirrored on the record so the data
    // path can see it without a V8 scope. `readStart`/`readStop` are the only
    // writers, and `OnDataChunkReceived` is what reads it.
    let reading = session
        .streams
        .borrow()
        .get(&stream_id)
        .map(|record| record.reading)
        .unwrap_or(false);
    {
        let mut streams = session.streams.borrow_mut();
        let Some(record) = streams.get_mut(&stream_id) else {
            return;
        };
        // `Http2Stream::Destroy` in `src/node_http2.cc` states this exactly:
        //
        //   // Mark destroyed immediately so OnDataChunkReceived stops EmitRead
        //   // into an already-destroyed JS stream (which would treat the byte
        //   // count as errno).
        //
        // That is not a theoretical hazard here. With the teardown deferred out of
        // a receive, a stream `core.js` has already destroyed still had reads
        // emitted into it, and `onStreamRead` read a byte count (7616) out of
        // `streamBaseState` where a negative errno belongs, throwing
        // `ERR_OUT_OF_RANGE` from `getSystemErrorName`. Clamping that value would
        // hide the bug; not emitting is the fix.
        if record.destroyed {
            return;
        }
        record.received_bytes += bytes.len() as u64;
        // `OnDataChunkReceived`: consume immediately when the owner is reading,
        // otherwise remember the credit for `ReadStart` to hand back. A paused
        // stream that never accounts for the bytes never reopens its window.
        if !reading {
            record.paused_unconsumed += bytes.len();
        }
    }
    // Staged rather than delivered: this runs inside `nghttp2_session_mem_recv`,
    // and reaching JavaScript there drains `core.js` teardown for streams nghttp2
    // is still walking. `flush_inbound` hands it over once the receive returns,
    // which is also the tick that separates `'response'` from the body.
    session
        .inbound
        .borrow_mut()
        .push(crate::session::InboundEvent {
            stream_id,
            kind: crate::session::InboundKind::Data(bytes.to_vec()),
        });
}

/// Delivers one staged chunk to `stream_id`'s readable side.
///
/// Only called from [`flush_inbound`], once `nghttp2_session_mem_recv` returned.
///
/// The destroyed check happens here and not only where the bytes were staged:
/// staging defers delivery across the tick `'response'` was queued on, and that
/// tick is exactly where `core.js` can destroy the stream. Emitting into a
/// destroyed readable side is what makes `onStreamRead` read a stale positive byte
/// count as errno (7616, `ERR_OUT_OF_RANGE`) — the hazard `Http2Stream::Destroy`
/// documents and `deliver_data` already guards at its own entry.
fn emit_read(session: &SessionState, stream_id: i32, payload: Vec<u8>) {
    // Only a stream `core.js` has destroyed must be skipped. A missing record is
    // not by itself that signal — `on_stream_close` retires the record for a normal
    // end too, and dropping those reads is what emptied an ordinary response.
    if session
        .streams
        .borrow()
        .get(&stream_id)
        .is_some_and(|record| record.destroyed)
    {
        return;
    }
    if session.destroyed_streams.borrow().contains(&stream_id) {
        return;
    }
    let _ = rn_uv::callback::with_context(|scope| {
        // Without a handle there is nothing to deliver to, and `in_stream_scope`
        // below would find nothing anyway.
        let Some(object) = object_for(scope, session, stream_id) else {
            return;
        };
        // A listener may be attached — a `StreamPipe` pushing onto this stream as
        // its source, or a `TLSWrap`. `StreamResource::EmitRead` delivers to that
        // listener first and only falls through to `onread` when the chain is
        // empty, which is the whole reason a pipe can read from an HTTP/2 stream.
        // Delivering straight to `onread` made every attached listener invisible.
        if let Some(state) = state_pointer_of(object) {
            let listening = {
                // SAFETY: the state lives as long as the object, which is alive
                // for this call.
                unsafe { rn_uv::listener::listener_count(state) > 0 }
            };
            if listening {
                // The bytes are copied into an `Allocation`, which `emit_read`
                // hands to the listener and the listener releases. `streamBaseState`
                // is published by the default listener, not here, so a listener
                // that consumes the bytes never sees a stale count.
                let Some(mut allocation) = rn_uv::handle::Allocation::new(payload.len()) else {
                    return;
                };
                // SAFETY: `allocation` holds `payload.len()` writable bytes and
                // `payload` is a distinct live buffer of that length.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        payload.as_ptr(),
                        allocation.base(),
                        payload.len(),
                    )
                };
                // SAFETY: the state is live, and `emit_read` holds no reference to
                // it across the listener call.
                unsafe {
                    rn_uv::listener::emit_read(
                        state,
                        payload.len() as isize,
                        rn_uv::listener::ReadBuffer::Allocated(allocation),
                    )
                };
                return;
            }
        }
        // `streamBaseState[kReadBytesOrError] = nread`, without which `onStreamRead`
        // sees a stale count and pushes the wrong slice.
        rn_uv::stream::with_state(|state| {
            state.set(rn_uv::handle::K_READ_BYTES_OR_ERROR, payload.len() as u32)
        });
        let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(payload.into_boxed_slice());
        let store: v8::SharedRef<v8::BackingStore> = store.into();
        let buffer: v8::Local<v8::Value> =
            v8::ArrayBuffer::with_backing_store(scope, &store).into();
        // Inside the stream's async scope: `onStreamRead` is a stream callback, so
        // it runs as the stream resource with the frame captured at its creation.
        let _ = in_stream_scope(scope, session, stream_id, |scope| {
            let Some(object) = object_for(scope, session, stream_id) else {
                return;
            };
            let Some(handler) = onread_of(scope, object) else {
                return;
            };
            let _ = handler.call(scope, object.into(), &[buffer]);
        });
    });
}

/// Reports end-of-stream on `stream_id`'s readable side.
///
/// A non-positive count is how `onStreamRead` learns the stream ended:
/// `lib/net.js` turns `UV_EOF` into `'end'` and any other negative into
/// `'error'`.
///
/// # When to call this, and when not to
///
/// Exactly one condition emits EOF: a DATA frame whose `NGHTTP2_FLAG_END_STREAM`
/// is set, which is Node's `Http2Session::HandleDataFrame`
/// (`src/node_http2.cc:1664`). A response that ends on its headers (204, 304,
/// `{ endStream: true }`) gets its `push(null)` from `core.js`, which reads
/// `endOfStream` off the flags it was handed — not from here.
///
/// Emitting EOF from `on_stream_close` used to look necessary, because
/// `core.js` gates its teardown on `stream._readableState.ended` and a stream
/// that never ended appeared to hang. It was not: it made `ended` true for every
/// closed stream, so a stream that closed *early* — a truncated response, a peer
/// RST_STREAM — reported a clean end, and `onStreamClose`'s
/// `!peerReadableEnded` branch, which raises `ERR_HTTP2_STREAM_ABORTED` and
/// `ERR_HTTP2_STREAM_ERROR`, became unreachable. A partial download then looked
/// identical to a complete one. The hang has a different cause and a correct
/// fix: `core.js` waits for `'end'`/`'finish'` and calls `stream.read(0)` to
/// drive the readable side, which works as soon as EOF is only sent when the
/// peer actually ended the stream.
///
/// Delivered by [`flush_inbound`] once `nghttp2_session_mem_recv` has returned.
fn deliver_eof(session: &SessionState, stream_id: i32) {
    let _ = rn_uv::callback::with_context(|scope| {
        let Some(object) = object_for(scope, session, stream_id) else {
            return;
        };
        // `EmitRead(UV_EOF)` on the stream's own `StreamBase`, so an attached
        // listener sees the end before JavaScript does. A `StreamPipe` reading
        // from this stream as its source stops and shuts its sink down in
        // `OnStreamRead`'s `nread <= 0` branch, and delivering straight to
        // `onread` left that listener invisible — the pipe then never finished and
        // the sink's writable side stayed open.
        if let Some(state) = state_pointer_of(object) {
            let listening = {
                // SAFETY: the state lives as long as the object, which is alive
                // for this call.
                unsafe { rn_uv::listener::listener_count(state) > 0 }
            };
            if listening {
                // SAFETY: the state is live, and `emit_read` holds no reference to
                // it across the listener call.
                unsafe {
                    rn_uv::listener::emit_read(
                        state,
                        EOF as isize,
                        rn_uv::listener::ReadBuffer::Listener(rn_uv::sys::uv_buf_t {
                            base: std::ptr::null_mut(),
                            len: 0,
                        }),
                    )
                };
                return;
            }
        }
        rn_uv::stream::with_state(|state| {
            state.set(rn_uv::handle::K_READ_BYTES_OR_ERROR, EOF as u32)
        });
        // The EOF push is what makes the `Duplex` emit `'end'`, so it has to run in
        // the stream's async scope like any other callback. Left unscoped, `'data'`
        // saw the store and `'end'` did not — the asymmetry that made this look
        // half-fixed.
        let _ = in_stream_scope(scope, session, stream_id, |scope| {
            let Some(object) = object_for(scope, session, stream_id) else {
                return;
            };
            let Some(handler) = onread_of(scope, object) else {
                return;
            };
            // No buffer argument, as `CallJSOnreadMethod` does for an error.
            let _ = handler.call(scope, object.into(), &[]);
        });
    });
}

/// `UV_EOF`.
const EOF: i32 = -4095;

/// Stages `END_STREAM` for `stream_id`, for [`flush_inbound`] to deliver.
///
/// Called from inside `nghttp2_session_mem_recv`, where reaching JavaScript runs
/// `core.js` teardown for streams nghttp2 is still walking.
pub fn stage_eof(session: &SessionState, stream_id: i32) {
    session
        .inbound
        .borrow_mut()
        .push(crate::session::InboundEvent {
            stream_id,
            kind: crate::session::InboundKind::Eof,
        });
}

/// Stages `on_stream_close` for `stream_id`, for [`flush_inbound`] to deliver.
///
/// Queued behind that stream's body and EOF because nghttp2 delivers DATA before
/// `END_STREAM` closes the stream. `core.js`'s `onStreamClose` asks
/// `stream._readableState.ended`, so a close drained first reports a clean end as
/// `ERR_HTTP2_STREAM_ABORTED`.
pub fn stage_close(session: &SessionState, stream_id: i32, code: u32, peer_reset: bool) {
    session
        .inbound
        .borrow_mut()
        .push(crate::session::InboundEvent {
            stream_id,
            kind: crate::session::InboundKind::Close { code, peer_reset },
        });
}

/// Delivers `on_stream_close` for `stream_id` immediately, outside any receive.
///
/// Used when the close arrives with `receiving == false`: nothing is queued ahead
/// of it, so there is nothing to preserve order against, and `core.js` expects it
/// in the turn it happened. Staging it there delayed a graceful
/// `session.close(cb)` past the point where `core.js` still accepted one.
pub fn deliver_close_now(session: &SessionState, stream_id: i32, code: u32, peer_reset: bool) {
    deliver_stream_close(session, stream_id, code, peer_reset);
}

/// Delivers every event the last receive staged, in arrival order.
///
/// `OnDataChunkReceived`, `HandleDataFrame` and `OnStreamClose` all run inside
/// `nghttp2_session_mem_recv`. Reaching JavaScript from there is not safe: the
/// tick queue it drains runs `core.js` teardown for streams nghttp2 is still
/// walking, and the drain can re-enter `nghttp2_session_mem_send` from the
/// deferred write flush. Every one of them stages instead, and this drains the
/// queue once `mem_recv` has returned.
///
/// Delivering here is also what puts `'end'` on a later tick than `'response'`.
/// `core.js` queues the `'response'` emission with `process.nextTick`, so a body
/// delivered from inside the receive arrived in the same turn as the headers and
/// `'response'`/`'data'`/`'end'` were reported together — which is why a listener
/// attached after `await once(req, 'response')` missed `'end'` and hung.
pub fn flush_inbound(session: &SessionState) {
    // The tick drain comes first, before any of these events reach JavaScript.
    // `core.js` queues `'response'` on `process.nextTick`, so `'end'` must not be
    // delivered until that tick has run — otherwise `'response'`/`'data'`/`'end'`
    // share a turn and a listener attached after `await once(req, 'response')`
    // misses `'end'` and hangs.
    //
    // Draining explicitly rather than relying on a scope closing above is what makes
    // this transport-independent: a `TLSWrap` runs its whole state machine inside
    // one scope, so a session consuming a TLS socket finishes nested and no scope
    // closes.
    let _ = rn_uv::callback::with_context(|scope| {
        rn_core::task_queue::checkpoint_now(scope, rn_uv::uv_loop::in_run());
    });
    // Then everything queued, in arrival order: body, EOF, then the close nghttp2
    // delivers after `END_STREAM`. That order is the contract — `core.js`'s
    // `onStreamClose` asks `stream._readableState.ended`, so a close drained before
    // its EOF reports a clean end as `ERR_HTTP2_STREAM_ABORTED`.
    drain_staged(session);
    // Every staged event has now been delivered, so the destroyed-stream marks have
    // done their job. Dropping them here is what keeps the set bounded: without it,
    // one entry per destroyed stream accumulates for the life of the session — a
    // slow leak on any long-lived connection.
    //
    // Clearing is sound because every staged event is delivered before this point,
    // so no mark is still load-bearing. A stream destroyed during the drain above
    // has its remaining staged events delivered in the same drain, and the marks are
    // only read by `emit_read` — which runs inside the drain. Staging itself cannot
    // produce a *new* event for a destroyed stream in a later receive: `deliver_data`
    // bails on a destroyed and on a missing record, and `stage_eof`/`stage_close`
    // are reached only from `mem_recv` frame callbacks, which a stream that has
    // already closed no longer produces.
    session.destroyed_streams.borrow_mut().clear();
}

/// Delivers every queued event for this session, in arrival order.
fn drain_staged(session: &SessionState) {
    loop {
        // One event at a time: delivering runs JavaScript that can stage more.
        let next = {
            let mut queue = session.inbound.borrow_mut();
            if queue.is_empty() {
                None
            } else {
                Some(queue.remove(0))
            }
        };
        let Some(event) = next else {
            return;
        };
        match event.kind {
            crate::session::InboundKind::Data(bytes) => {
                if !bytes.is_empty() {
                    emit_read(session, event.stream_id, bytes);
                }
            }
            crate::session::InboundKind::Eof => deliver_eof(session, event.stream_id),
            crate::session::InboundKind::Close { code, peer_reset } => {
                deliver_stream_close(session, event.stream_id, code, peer_reset);
            }
        }
    }
}

/// Calls `core.js`'s per-stream close callback.
fn deliver_stream_close(session: &SessionState, stream_id: i32, code: u32, peer_reset: bool) {
    let _ = rn_uv::callback::with_context(|scope| {
        let args = [
            v8::Integer::new(scope, code as i32).into(),
            v8::Boolean::new(scope, peer_reset).into(),
        ];
        call_stream_callback(
            scope,
            session,
            stream_id,
            |callbacks| callbacks.stream_close.clone(),
            &args,
        );
    });
}

/// Runs `body` inside `stream_id`'s captured async context.
///
/// This is `InternalCallbackScope` for this stream: `async_hooks` sees the
/// resource, and `AsyncLocalStorage` sees the frame that was current when the
/// stream was created. Both come from the handle state rather than from whatever
/// happened to be executing when the callback fired.
///
/// A callback for a stream that has been closed runs unscoped. That is deliberate:
/// the earlier cut of this reached through the handle unconditionally and
/// segfaulted, because a destroyed stream's state is no longer safe to read.
fn in_stream_scope<R>(
    scope: &mut v8::PinScope<'_, '_>,
    session: &SessionState,
    stream_id: i32,
    body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> R,
) -> Option<R> {
    let handle = session.handles.borrow().get(&stream_id).cloned()?;
    let object = v8::Local::new(scope, &handle);
    let (context, frame) = with_state(object, |state| {
        (
            rn_core::callback_scope::AsyncContext {
                async_id: state.async_wrap.async_id(),
                trigger_async_id: state.async_wrap.trigger_async_id,
            },
            state.context_frame.clone(),
        )
    })?;
    rn_core::callback_scope::with_scope(
        scope,
        rn_core::callback_scope::ScopeArgs {
            context,
            resource: Some(v8::Global::new(scope.as_ref(), object)),
            frame,
        },
        body,
    )
}

/// The `onread` a stream handle carries, if `core.js` assigned one.
fn onread_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, "onread")?;
    let value = object.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

/// Takes up to `limit` bytes from a stream's pending queue.
///
/// Returns `(bytes, ended)`, or `None` when the stream has no record. `ended` says
/// whether the stream is finished, which is what lets the provider report
/// `NGHTTP2_DATA_FLAG_EOF` rather than asking to be called again.
///
/// Scope-free on purpose: the provider's read callback runs inside
/// `nghttp2_session_mem_send`, and taking a `Vec<u8>` needs no V8 at all.
pub fn take_pending(
    session: &SessionState,
    stream_id: i32,
    limit: usize,
) -> Option<(Vec<u8>, bool)> {
    let mut streams = session.streams.borrow_mut();
    let record = streams.get_mut(&stream_id)?;
    let take = record.pending.len().min(limit);
    let bytes = record.pending.drain(..take).collect::<Vec<u8>>();
    record.sent_bytes += take as u64;
    // The provider is being asked for data, so the "wants more" hint it raised is
    // now satisfied; `settle_writes` will re-raise it if the queue empties again.
    record.wants_write = false;
    Some((bytes, record.ended && record.pending.is_empty()))
}

/// Raises `OnStreamWantsWrite` when the stream is waiting for more data.
///
/// `Http2Stream::OnRead` calls `EmitWantsWrite(length)` from the provider when it
/// has drained its queue and is still writable (`src/node_http2.cc:2877`). That is
/// the *only* thing that resumes a `StreamPipe` over an HTTP/2 sink, because
/// `HasWantsWrite()` is true and the pipe therefore never resumes its source
/// itself.
///
/// The provider runs inside `nghttp2_session_mem_send`, where a V8 call is not
/// legal, so the fact is recorded there and delivered here, on the loop thread
/// with a scope.
pub fn settle_writes(session: &SessionState, stream_id: i32) {
    let wants = {
        let streams = session.streams.borrow();
        match streams.get(&stream_id) {
            Some(record) => record.wants_write,
            None => return,
        }
    };
    if !wants {
        return;
    }
    let Some(object) = crate::stream::object_for_anywhere(session, stream_id) else {
        return;
    };
    let _ = rn_uv::callback::with_context(|scope| {
        let object: v8::Local<v8::Object> = v8::Local::new(scope, &object);
        if let Some(state) = crate::stream::state_pointer_of(object) {
            // SAFETY: the stream state lives as long as the object, and
            // `emit_wants_write` holds no reference to it across the call.
            unsafe { rn_uv::listener::emit_wants_write(state, 65_536) };
        }
    });
}

/// Calls a per-stream callback with the stream handle as the receiver.
///
/// Used by `on_stream_close` and the trailer path, where `core.js`'s callback reads
/// `this[kOwner]` to find the `Http2Stream` it belongs to.
pub fn call_stream_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    session: &SessionState,
    stream_id: i32,
    pick: impl FnOnce(&crate::SessionCallbacks) -> Option<v8::Global<v8::Function>>,
    args: &[v8::Local<'s, v8::Value>],
) {
    // Inside the stream's async scope, like every other per-stream callback.
    // `onStreamClose` is what emits `'end'`, so an unscoped call here is why
    // `AsyncLocalStorage.getStore()` was `undefined` in an `'end'` handler.
    let Some(global) = crate::callbacks::pick_global(pick) else {
        return;
    };
    let callback = v8::Local::new(scope, global);
    let _ = in_stream_scope(scope, session, stream_id, |scope| {
        let Some(object) = object_for(scope, session, stream_id) else {
            return;
        };
        let _ = callback.call(scope, object.into(), args);
    });
}

/// `Http2Stream::GetID`.
fn get_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = with_state(args.this(), |state| state.id).unwrap_or(-1);
    rv.set(v8::Integer::new(scope, id).into());
}

/// `Http2Stream::EmitWantTrailers`: tell `core.js` the body is done and it may
/// send trailers.
///
/// The receiver is the stream handle, because `core.js`'s `onStreamTrailers`
/// starts with `this[kOwner]` (`lib/internal/http2/core.js:513`) and `kOwner` is
/// set on the handle at `:2316`. [`call_stream_callback`] is what supplies that
/// receiver and the stream's async scope, both of which Node gets from
/// `MakeCallback`.
///
/// Called from the DATA provider's read callback, on nghttp2's own stack, which
/// is where Node calls it too. That is safe because `core.js` runs
/// `sendTrailers` through `setImmediate` (`:2612`, "Send the trailers in
/// setImmediate so we don't do it on nghttp2 stack"), so nothing submits a frame
/// re-entrantly. A `wantTrailers` listener is the one place user code can run
/// here, and Node gives it the same reach.
pub fn emit_want_trailers(session: &SessionState, stream_id: i32) {
    let _ = rn_uv::callback::with_context(|scope| {
        call_stream_callback(
            scope,
            session,
            stream_id,
            |callbacks| callbacks.stream_trailers.clone(),
            &[],
        );
    });
}

/// `Http2Stream::Destroy`.
fn destroy(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if let (Some(state), Some(id)) = (
        session_of(args.this()),
        with_state(args.this(), |handle| handle.id),
    ) {
        if let Some(record) = state.streams.borrow_mut().get_mut(&id) {
            record.destroyed = true;
        }
        state.destroyed_streams.borrow_mut().insert(id);
        submit_rst(state, id, ffi::NGHTTP2_CANCEL_CODE);
    }
}

/// `Http2Stream::RstStream`.
fn rst_stream(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let code = args.get(0).uint32_value(scope).unwrap_or(0);
    if let (Some(state), Some(id)) = (
        session_of(args.this()),
        with_state(args.this(), |handle| handle.id),
    ) {
        submit_rst(state, id, code);
    }
}

/// Submits an RST_STREAM and schedules the write that carries it.
fn submit_rst(state: &SessionState, stream_id: i32, code: u32) {
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    // Recorded rather than submitted when nghttp2 is mid-receive. `on_stream_close`
    // and `destroy` both run from a callback, which is inside `mem_recv`. Order is
    // preserved by the queue, so an RST submitted after a DATA still applies after
    // it.
    if state.receiving.get() {
        state
            .deferred_submits
            .borrow_mut()
            .push(crate::session::DeferredSubmit::RstStream { stream_id, code });
        crate::session::schedule_write(state);
        return;
    }
    // Drain what is already queued *before* the reset. `core.js` submits an RST
    // from `finishCloseStream` as soon as the writable side finishes, while the
    // response's DATA is still sitting behind a deferred flush — so the RST would
    // overtake the body and the peer would see a reset stream instead of a
    // response. `stream.end(); stream.close()` hit exactly that: the server
    // received no data at all.
    //
    // Flushing is only legal when `receiving` is false; `send_pending_data`
    // enforces that itself and leaves the write scheduled when it declines,
    // which is the same shape Node's `SendPendingData` has.
    crate::session::flush_pending(state);
    // SAFETY: `raw` is a live nghttp2 session.
    unsafe {
        ffi::nghttp2_submit_rst_stream(raw, ffi::NGHTTP2_FLAG_NONE, stream_id, code);
    }
    crate::session::schedule_write(state);
}

/// `Http2Stream::Priority`: advisory only, and nghttp2 deprecated RFC 7540
/// priorities, which is why `test-http2-priority-event.js` notes they are gone.
fn priority(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
}

/// `Http2Stream::DisableAutoTrailers`.
fn disable_auto_trailers(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    // Node's `DisableAutoTrailers` only clears `auto_empty_trailers`
    // (`src/node_http2.cc:3224`). That flag chooses between Node's *native*
    // empty-trailer submit at EOF and its JavaScript one, and this crate always
    // takes the JavaScript path (see `StreamRecord::has_trailers`), so there is no
    // state to clear: `has_trailers` stays set either way, the EOF withholds
    // `END_STREAM`, and `core.js` sends whatever `addTrailers` collected. Clearing
    // `has_trailers` here would instead suppress the notification that
    // `addTrailers` is waiting for.
}

/// Submits a header block for `id` with `flags`, returning nghttp2's status.
fn submit_headers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    flags: u8,
) -> Option<i32> {
    let state = session_of(args.this())?;
    let id = with_state(args.this(), |handle| handle.id)?;
    let raw = crate::session_ptr(state)?;
    let headers = crate::headers::nv_from_array(scope, args.get(0))?;
    if state.receiving.get() {
        state
            .deferred_submits
            .borrow_mut()
            .push(crate::session::DeferredSubmit::Headers {
                stream_id: id,
                headers: crate::headers::pairs_of(&headers),
                flags,
            });
        crate::session::schedule_write(state);
        return Some(0);
    }
    // SAFETY: `raw` is live and `headers` owns its storage for the call; nghttp2
    // copies the pairs it is given.
    let status = unsafe {
        ffi::nghttp2_submit_headers(
            raw,
            flags,
            id,
            ptr::null(),
            headers.as_ptr(),
            headers.len(),
            ptr::null_mut(),
        )
    };
    crate::session::schedule_write(state);
    Some(status)
}

/// `Http2Stream::Info`: non-final HEADERS, no END_STREAM.
fn info(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    match submit_headers(scope, args, ffi::NGHTTP2_FLAG_NONE) {
        Some(status) => rv.set(v8::Integer::new(scope, status).into()),
        None => rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_INVALID_ARGUMENT).into()),
    }
}

/// `Http2Stream::Trailers`.
///
/// `SubmitTrailers` splits on an empty header block: a non-empty one is a trailer
/// HEADERS frame (`nghttp2_submit_trailer`, which sets `END_STREAM`), while an
/// empty one goes to `SubmitEmptyTrailers` (`src/node_http2.cc:2584`), which
/// submits an *empty DATA frame* carrying `END_STREAM` instead. The difference is
/// visible to the peer: a zero-length DATA frame is not a headers block, so the
/// client emits no `'trailers'` event. `sendTrailers({})` and the compat layer's
/// no-registered-trailers case both take this branch, so treating an empty block
/// as a HEADERS frame would invent a `trailers` event Node never emits.
fn trailers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    let Some(headers) = crate::headers::nv_from_array(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_INVALID_ARGUMENT).into());
        return;
    };
    if state.receiving.get() {
        state
            .deferred_submits
            .borrow_mut()
            .push(crate::session::DeferredSubmit::Trailer {
                stream_id: id,
                headers: crate::headers::pairs_of(&headers),
            });
        crate::session::schedule_write(state);
        rv.set(v8::Integer::new(scope, 0).into());
        return;
    }
    let status = submit_trailers(raw, id, &headers);
    crate::session::schedule_write(state);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `SubmitTrailers`'s two branches, shared with the deferred replay.
pub(crate) fn submit_trailers(
    raw: *mut ffi::nghttp2_session,
    stream_id: i32,
    block: &crate::headers::HeaderBlock,
) -> i32 {
    if block.is_empty() {
        // `SubmitEmptyTrailers`: an empty DATA frame with `END_STREAM`. The
        // provider reports EOF with no bytes, which is what makes the frame zero
        // length rather than merely empty.
        let provider = provider::Provider::end_stream();
        // SAFETY: `raw` is live, `provider` outlives the call, and nghttp2 copies
        // the provider it is given.
        return unsafe {
            ffi::nghttp2_submit_data2(
                raw,
                ffi::NGHTTP2_FLAG_END_STREAM,
                stream_id,
                provider.as_ptr(),
            )
        };
    }
    // SAFETY: `raw` is live and `block` owns its storage for the call.
    unsafe { ffi::nghttp2_submit_trailer(raw, stream_id, block.as_ptr(), block.len()) }
}

/// `Http2Stream::PushPromise`.
fn push_promise(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    if state.session_type != crate::session::SESSION_SERVER {
        rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_PROTO).into());
        return;
    }
    let Some(headers) = crate::headers::nv_from_array(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_INVALID_ARGUMENT).into());
        return;
    };
    let options = args.get(1).uint32_value(scope).unwrap_or(0) as i32;
    // Submitted inline even while `receiving`, which is the one place in this
    // module that does not go through `defer_or`.
    //
    // `Http2Stream::SubmitPushPromise` calls `nghttp2_submit_push_promise` with no
    // such gate (`src/node_http2.cc:2687`), and Node reaches it from inside
    // `mem_recv` routinely: `pushStream` is legal from a `'data'` handler, which
    // runs synchronously from `OnDataChunkReceived`. Only *sending* is unsafe
    // there, which is why the flush below stays a `schedule_write`.
    //
    // Deferring is not merely unnecessary, it is incompatible with what this
    // function has to return. nghttp2 assigns the promised stream id as it queues
    // the frame, and `core.js` reads `ret.id()` from the returned handle
    // immediately (`vendor/libnode-js/lib/internal/http2/core.js:3223`), so the
    // id must exist before the call returns.
    // SAFETY: `raw` is live and `headers` owns its storage for the call.
    let promised = unsafe {
        ffi::nghttp2_submit_push_promise(
            raw,
            ffi::NGHTTP2_FLAG_NONE,
            id,
            headers.as_ptr(),
            headers.len(),
            ptr::null_mut(),
        )
    };
    if promised <= 0 {
        // `core.js` turns a number into an error, so every failure returns the
        // code itself: `NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE` and
        // `NGHTTP2_ERR_STREAM_CLOSED` each have their own error class there.
        rv.set(v8::Integer::new(scope, promised).into());
        return;
    }
    state.streams.borrow_mut().insert(
        promised,
        crate::session::StreamRecord {
            id: promised,
            category: ffi::NGHTTP2_HCAT_PUSH_RESPONSE,
            options,
            ..Default::default()
        },
    );
    crate::session::schedule_write(state);
    // On success `PushPromise` returns the *handle object*, not the id:
    // `src/node_http2.cc:3271` sets `args.GetReturnValue().Set(stream->object())`.
    // A bare id here is read by `core.js` as an error code, and since a stream id
    // is positive it becomes `new NghttpError(<id>)` — `Unknown error code` — on a
    // push that actually succeeded.
    let Some(handle) = handle_for(
        scope,
        state,
        promised,
        ffi::NGHTTP2_HCAT_PUSH_RESPONSE,
        options,
    ) else {
        rv.set(v8::Integer::new(scope, promised).into());
        return;
    };
    rv.set(handle.into());
}

/// `Http2Stream::Respond`: the final response HEADERS, with a body provider.
fn respond(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    let Some(headers) = crate::headers::nv_from_array(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, ffi::NGHTTP2_ERR_INVALID_ARGUMENT).into());
        return;
    };
    let options = args.get(1).uint32_value(scope).unwrap_or(0) as i32;
    let empty_payload = options & crate::STREAM_OPTION_EMPTY_PAYLOAD != 0;
    // `SubmitResponse` sets `has_trailers` from `STREAM_OPTION_GET_TRAILERS`
    // before handing the provider to nghttp2 (`src/node_http2.cc:2497`), which is
    // what the read callback consults at EOF.
    if let Some(record) = state.streams.borrow_mut().get_mut(&id) {
        if options & crate::STREAM_OPTION_GET_TRAILERS != 0 {
            record.has_trailers = true;
        }
    }
    if state.receiving.get() {
        state
            .deferred_submits
            .borrow_mut()
            .push(crate::session::DeferredSubmit::Response {
                stream_id: id,
                headers: crate::headers::pairs_of(&headers),
                empty_payload,
            });
        crate::session::schedule_write(state);
        rv.set(v8::Integer::new(scope, id).into());
        return;
    }
    let provider = provider::Provider::new(state, id, options);
    // `nghttp2_submit_response2` half-closes the outbound stream, which is why
    // `core.js` uses it only for the final response and `info` for anything else.
    // SAFETY: `raw` is live, `headers` owns its storage for the call, and
    // `provider` outlives it.
    let status = unsafe {
        ffi::nghttp2_submit_response2(
            raw,
            id,
            headers.as_ptr(),
            headers.len(),
            if empty_payload {
                ptr::null()
            } else {
                provider.as_ptr()
            },
        )
    };
    if status != 0 {
        rv.set(v8::Integer::new(scope, status).into());
        return;
    }
    crate::session::schedule_write(state);
    rv.set(v8::Integer::new(scope, id).into());
}

/// `Http2Stream::RefreshState`: publish this stream's window and close flags.
fn refresh_state(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    // SAFETY: `raw` is live and every getter below only reads.
    let (window, local_close, remote_close) = unsafe {
        (
            ffi::nghttp2_session_get_stream_local_window_size(raw, id),
            ffi::nghttp2_session_get_stream_local_close(raw, id),
            ffi::nghttp2_session_get_stream_remote_close(raw, id),
        )
    };
    let _ = crate::state::Http2State::with(|shared| {
        shared.set_stream_state(
            crate::state::IDX_STREAM_STATE_LOCAL_WINDOW_SIZE,
            f64::from(window),
        );
        shared.set_stream_state(
            crate::state::IDX_STREAM_STATE_LOCAL_CLOSE,
            f64::from(local_close),
        );
        shared.set_stream_state(
            crate::state::IDX_STREAM_STATE_REMOTE_CLOSE,
            f64::from(remote_close),
        );
    });
}

/// `StreamBase::ReadStart`.
///
/// Routed through the ops so the record's mirrored `reading` flag and the paused
/// flow-control credit are updated together — the data path reads that flag from
/// `mem_recv`, where the handle's own `Cell` is not reachable.
fn read_start(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = state_pointer_of(args.this()) else {
        return;
    };
    // SAFETY: the state lives as long as the object, which is this call.
    let status = unsafe { (*state).ops.read_start(state) };
    rv.set(v8::Integer::new(_scope, status).into());
}

/// `StreamBase::ReadStop`.
fn read_stop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = state_pointer_of(args.this()) else {
        return;
    };
    // SAFETY: as above.
    let status = unsafe { (*state).ops.read_stop(state) };
    rv.set(v8::Integer::new(scope, status).into());
}

/// `StreamBase::Shutdown`: end this stream's writable side.
///
/// Marking the record `ended` is what lets the *existing* provider report
/// `NGHTTP2_DATA_FLAG_EOF` on its next read, which is how END_STREAM reaches the
/// wire. Submitting a second provider here instead was the bug: nghttp2 answers
/// `NGHTTP2_ERR_DATA_EXIST` and the first provider never learns the body is
/// complete.
fn shutdown(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(args.this()) else {
        return;
    };
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    if let Some(record) = state.streams.borrow_mut().get_mut(&id) {
        record.ended = true;
    }
    // `resume_data` is not a submit: it only re-arms the provider nghttp2 already
    // holds, which is why it is safe here even mid-receive.
    // SAFETY: `raw` is live and `id` is a stream this session owns.
    let status = unsafe { ffi::nghttp2_session_resume_data(raw, id) };
    crate::session::schedule_write(state);
    if let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) {
        rn_bind_stream_wrap::wrap::report_completion(scope, request, 0, None, None);
    }
    // `shutdownWritable` reads `1` as "finished synchronously" and only then runs
    // `afterShutdown`, which is what emits `'finish'` on the writable side.
    // nghttp2's `0` means "queued", and the completion above has already run, so
    // there is nothing left to wait for.
    let finished = if status >= 0 { 1 } else { status };
    rv.set(v8::Integer::new(scope, finished).into());
}

/// `StreamBase::Writev`, which `stream_base_commons.js` reaches for a chunk list.
fn writev(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let mut bytes = Vec::new();
    if let Ok(array) = v8::Local::<v8::Array>::try_from(args.get(1)) {
        let all_buffers = args.get(2).boolean_value(scope);
        let stride = if all_buffers { 1 } else { 2 };
        let count = (array.length() as usize) / stride;
        for index in 0..count {
            let Some(value) = array.get_index(scope, (index * stride) as u32) else {
                continue;
            };
            // SAFETY: `stream_base_commons` keeps every view alive on `req.chunks`.
            if let Some(buffer) = unsafe { rn_uv::stream_base::view_buffer(value) } {
                // SAFETY: the view is live for this call.
                let slice =
                    unsafe { std::slice::from_raw_parts(buffer.base.cast::<u8>(), buffer.len) };
                bytes.extend_from_slice(slice);
            }
        }
    }
    queue_write(scope, args.this(), id, bytes, args.get(0), &mut rv);
}

/// The four `write*String` forms, which differ only in encoding.
///
/// `writeGeneric` in `lib/internal/stream_base_commons.js` picks one by the
/// encoding the caller asked for, so all four have to exist or a plain
/// `stream.end('text')` fails with "is not a function".
fn write_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    encoding: rn_core::Encoding,
    rv: &mut v8::ReturnValue<'_>,
) {
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    let Ok(text) = v8::Local::<v8::String>::try_from(args.get(1)) else {
        return;
    };
    let length = text.length();
    let mut units = vec![0u16; length];
    text.write_v2(scope, 0, &mut units, v8::WriteFlags::empty());
    let bytes = rn_core::codec::write(
        &units,
        encoding,
        rn_core::codec::storage_size(&units, encoding),
    );
    queue_write(scope, args.this(), id, bytes, args.get(0), rv);
}

/// `writeAsciiString`.
fn write_ascii(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_string(scope, args, rn_core::Encoding::Ascii, &mut rv);
}

/// `writeUtf8String`.
fn write_utf8(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_string(scope, args, rn_core::Encoding::Utf8, &mut rv);
}

/// `writeUcs2String`.
fn write_ucs2(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_string(scope, args, rn_core::Encoding::Ucs2, &mut rv);
}

/// `writeLatin1String`.
fn write_latin1(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_string(scope, args, rn_core::Encoding::Binary, &mut rv);
}

/// `StreamBase::WriteBuffer`.
fn write_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(id) = with_state(args.this(), |handle| handle.id) else {
        return;
    };
    // SAFETY: `stream_base_commons` keeps the view alive on `req.buffer`.
    let Some(buffer) = (unsafe { rn_uv::stream_base::view_buffer(args.get(1)) }) else {
        rv.set(v8::Integer::new(scope, -22).into());
        return;
    };
    // SAFETY: the view is live for the call; the bytes are copied below.
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.base.cast::<u8>(), buffer.len) }.to_vec();
    queue_write(scope, args.this(), id, bytes, args.get(0), &mut rv);
}

/// Appends `bytes` to the stream's body queue and asks nghttp2 to read again.
///
/// Deliberately does **not** submit a provider. `respond()` and `request()` each
/// submit exactly one, and nghttp2 rejects a second with `NGHTTP2_ERR_DATA_EXIST`
/// (`-529`) — which is what a `shutdown()` after a write was hitting, so the body
/// went out with END_STREAM unset and the peer waited for a terminator that never
/// came. `nghttp2_session_resume_data` is how more bytes are offered to the
/// existing provider after it reported `NGHTTP2_ERR_DEFERRED`.
fn queue_write(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    id: i32,
    bytes: Vec<u8>,
    request: v8::Local<'_, v8::Value>,
    rv: &mut v8::ReturnValue<'_>,
) {
    let Some(state) = session_of(object) else {
        return;
    };
    let Some(raw) = crate::session_ptr(state) else {
        return;
    };
    let length = bytes.len();
    if let Some(record) = state.streams.borrow_mut().get_mut(&id) {
        record.pending.extend_from_slice(&bytes);
        record.sent_bytes += length as u64;
    }
    // Wakes the provider that is already installed, which is what makes the
    // deferred read happen rather than waiting for the next frame to arrive.
    // SAFETY: `raw` is live and `id` is a stream this session owns.
    let status = unsafe { ffi::nghttp2_session_resume_data(raw, id) };
    crate::session::schedule_write(state);
    if let Ok(request) = v8::Local::<v8::Object>::try_from(request) {
        rn_bind_stream_wrap::wrap::report_completion(scope, request, 0, None, None);
    }
    rv.set(v8::Integer::new(scope, status.max(0)).into());
}

/// `StreamBase::UseUserBuffer`, which an HTTP/2 stream does not support.
fn use_user_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    /// `UV_ENOTSUP`.
    const ENOTSUP: i32 = -4028;
    rv.set(v8::Integer::new(scope, ENOTSUP).into());
}

/// `StreamBase::bytesRead`.
fn get_bytes_read(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = session_of(args.this())
        .and_then(|session| {
            with_state(args.this(), |handle| handle.id).and_then(|id| {
                session
                    .streams
                    .borrow()
                    .get(&id)
                    .map(|record| record.received_bytes)
            })
        })
        .unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `StreamBase::bytesWritten`.
fn get_bytes_written(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = session_of(args.this())
        .and_then(|session| {
            with_state(args.this(), |handle| handle.id).and_then(|id| {
                session
                    .streams
                    .borrow()
                    .get(&id)
                    .map(|record| record.sent_bytes)
            })
        })
        .unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `AsyncWrap::getAsyncId`.
fn get_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = with_state(args.this(), |state| state.async_wrap.async_id())
        .unwrap_or(rn_core::INVALID_ASYNC_ID);
    rv.set(v8::Number::new(scope, id).into());
}

/// The async id that is currently executing, which becomes a stream's trigger.
///
/// `AsyncWrap`'s constructor reads `async_hooks.executionAsyncId()` for this, so
/// that a stream created inside a `run()` is parented to whatever ran it.
fn current_trigger_async_id() -> f64 {
    rn_bind_async_wrap::execution_async_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_data_flag_bits_are_nghttp2s() {
        // The provider sets these on `*data_flags`; a wrong bit would either end a
        // stream early or never end it.
        assert_eq!(provider::DATA_FLAG_EOF, 0x01);
        assert_eq!(provider::ERR_DEFERRED, -508);
    }

    #[test]
    fn the_stream_field_count_leaves_room_for_the_state_pointer() {
        // `with_state` refuses an object whose field count is not larger than the
        // index, which is how a bare `{}` passed as a stream handle is rejected
        // rather than read as a null state.
        assert_eq!(STREAM_FIELD, 0);
    }
}
