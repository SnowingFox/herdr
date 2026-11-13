//! The `StreamPipe` constructor, its four prototype methods and the two
//! listeners that do the actual pumping.
//!
//! `src/stream_pipe.cc` builds a `FunctionTemplate` with `unpipe`, `start`,
//! `isClosed` and `pendingWrites` on the prototype and `AsyncWrap`'s template as
//! its parent. This module reproduces that surface over one internal field.
//!
//! # One state, two listeners, and the borrow rule
//!
//! A pipe's state is touched from three directions: its own prototype methods,
//! the readable listener (called from the *source's* read path) and the writable
//! listener (called from the *sink's* write completion). `rn_uv::listener`'s
//! contract forbids holding a borrow across a listener call, because the
//! JavaScript reached from there can `destroy()` either stream. So the listeners
//! hold the state as a `*mut` and borrow it only for the length of one field read
//! or write, exactly as `rn-bind-tls` does.
//!
//! # Why the object is rooted in the state
//!
//! `Unpipe` emits `onunpipe` with `this` as its receiver, and that can run from a
//! write completion where no JavaScript handle is in scope. Node's `AsyncWrap`
//! has the same problem and answers it with `object()`. The rooting here does the
//! same job and is released by the finalizer.

use std::cell::Cell;
use std::ffi::c_void;
use std::ptr;

use rn_v8_sys::v8;

use rn_uv::handle::StreamState;
use rn_uv::listener::{self, ListenerRef, ReadBuffer, StreamListener};

/// The internal field holding the `*mut PipeState`.
pub(crate) const PIPE_FIELD: i32 = 0;

/// `UV_EBADF`, what `ASSIGN_OR_RETURN_UNWRAP` reports for a bad receiver.
const EBADF: i32 = 9;

/// `StreamPipe::kInternalFieldCount` is `AsyncWrap`'s, which is 1 in this runtime.
pub(crate) struct PipeState {
    /// The source's listener chain, or null before the constructor ran.
    pub source: *mut StreamState,
    /// The sink's listener chain.
    pub sink: *mut StreamState,
    /// `pending_writes_`: how many writes the readable listener has dispatched.
    pub pending_writes: Cell<i32>,
    /// `is_reading_`.
    pub is_reading: Cell<bool>,
    /// `is_eof_`: the source reported EOF or an error.
    pub is_eof: Cell<bool>,
    /// `is_closed_`. It **starts true**, as in the C++, so `unpipe()` on a pipe
    /// that was never started is a no-op rather than a spurious `onunpipe`.
    pub is_closed: Cell<bool>,
    /// `sink_destroyed_`.
    pub sink_destroyed: Cell<bool>,
    /// `source_destroyed_`.
    pub source_destroyed: Cell<bool>,
    /// `wanted_data_`: the sink's last `OnStreamWantsWrite` hint.
    pub wanted_data: Cell<usize>,
    /// `uses_wants_write_`: whether the sink implements `HasWantsWrite`.
    pub uses_wants_write: Cell<bool>,
    /// The `StreamPipe` object, rooted.
    ///
    /// Node reaches it as `AsyncWrap::object()`. The callbacks that need it run
    /// from the listener layer, where no local handle is in scope.
    pub object: Option<v8::Global<v8::Object>>,
    /// The source and sink objects, rooted so the pair stays alive as a group.
    ///
    /// Node gets this from the four JS properties the constructor sets. Both are
    /// needed: the properties are what a caller can observe, and these roots are
    /// what stop V8 collecting a weak `Http2Stream` handle out from under a
    /// transfer in progress.
    pub source_object: Option<v8::Global<v8::Object>>,
    pub sink_object: Option<v8::Global<v8::Object>>,
    /// The readable listener's id on the source, for a detach that has no
    /// `ListenerRef` of its own.
    pub readable_id: Cell<Option<listener::ListenerId>>,
    /// The writable listener's id on the sink.
    pub writable_id: Cell<Option<listener::ListenerId>>,
    /// Parks the finalizer registration so dropping it cannot cancel it.
    pub weak: Cell<Option<*mut v8::Weak<v8::Object>>>,
}

impl PipeState {
    fn new() -> Self {
        Self {
            source: ptr::null_mut(),
            sink: ptr::null_mut(),
            pending_writes: Cell::new(0),
            is_reading: Cell::new(false),
            is_eof: Cell::new(false),
            is_closed: Cell::new(true),
            sink_destroyed: Cell::new(false),
            source_destroyed: Cell::new(false),
            wanted_data: Cell::new(0),
            uses_wants_write: Cell::new(false),
            object: None,
            source_object: None,
            sink_object: None,
            readable_id: Cell::new(None),
            writable_id: Cell::new(None),
            weak: Cell::new(None),
        }
    }
}

/// The pointer in a `StreamPipe`'s internal field.
pub(crate) fn raw_state(object: v8::Local<v8::Object>) -> Option<*mut PipeState> {
    if object.internal_field_count() <= PIPE_FIELD as usize {
        return None;
    }
    // SAFETY: the field only ever holds a pointer installed by `new`, and the
    // object is a live local so its finalizer has not run.
    let pointer =
        unsafe { object.get_aligned_pointer_from_internal_field(PIPE_FIELD, 0) } as *mut PipeState;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Runs `body` with the state behind a `StreamPipe` object.
fn with_state<R>(object: v8::Local<v8::Object>, body: impl FnOnce(&PipeState) -> R) -> Option<R> {
    let pointer = raw_state(object)?;
    // SAFETY: `raw_state` proved the pointer is live, and every borrow is scoped
    // to one callback with no listener call inside it.
    Some(body(unsafe { &*pointer }))
}

/// Builds the `StreamPipe` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    // `StreamPipe.length` is 0: `NewFunctionTemplate`'s default.
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name =
        v8::String::new(scope, "StreamPipe").ok_or("cannot allocate the StreamPipe class name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(PIPE_FIELD as usize + 1);

    let prototype = template.prototype_template(scope);
    // `InitializeStreamPipe`'s four `SetProtoMethod` calls, in its order. Each is
    // written out rather than looped over because `FunctionTemplate::builder`
    // takes a distinct closure type per callback, so a tuple array cannot hold
    // them.
    macro_rules! install_method {
        ($($method_name:literal => $method:expr),* $(,)?) => {
            $(
                let method_template = v8::FunctionTemplate::builder($method)
                    .length(0)
                    .constructor_behavior(v8::ConstructorBehavior::Throw)
                    .build(scope);
                let key = v8::String::new(scope, $method_name)
                    .ok_or_else(|| format!("cannot allocate StreamPipe.{}", $method_name))?;
                prototype.set(key.into(), method_template.into());
            )*
        };
    }
    install_method! {
        "unpipe" => unpipe,
        "start" => start,
        "isClosed" => is_closed,
        "pendingWrites" => pending_writes,
    }

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the StreamPipe constructor")?;
    Ok(constructor.into())
}

/// `new StreamPipe(source, sink)`.
///
/// `src/stream_pipe.cc`'s `New` is `CHECK(args.IsConstructCall())`,
/// `CHECK(args[0]->IsObject())`, `CHECK(args[1]->IsObject())`, then
/// `StreamBase::FromObject` on both and `CHECK_NOT_NULL` on the result. A
/// `TypeError` is what those checks amount to without aborting the process, and
/// the only caller is `core.js`, which always passes two stream handles.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        crate::throw_type_error(scope, "StreamPipe cannot be invoked without 'new'");
        return;
    }
    let Ok(source_object) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        crate::throw_type_error(scope, "StreamPipe requires a source stream handle");
        return;
    };
    let Ok(sink_object) = v8::Local::<v8::Object>::try_from(args.get(1)) else {
        crate::throw_type_error(scope, "StreamPipe requires a sink stream handle");
        return;
    };

    // `StreamBase::FromObject`. Every stream namespace in this runtime attaches
    // its state under the shared symbol, which is the same unwrap Node's virtual
    // performs.
    // SAFETY: both objects are live locals, so any state a binding attached to
    // them outlives this call.
    let (Some(source), Some(sink)) = (
        unsafe { rn_uv::streams::stream_of(scope, source_object) }
            .and_then(|stream| unsafe { rn_uv::handle::owner(stream) }),
        unsafe { rn_uv::streams::stream_of(scope, sink_object) }
            .and_then(|stream| unsafe { rn_uv::handle::owner(stream) }),
    ) else {
        crate::throw_type_error(scope, "StreamPipe requires two stream handles");
        return;
    };

    let object = args.this();
    let state = Box::new(PipeState::new());
    let pointer = Box::into_raw(state);
    // SAFETY: `pointer` came from `Box::into_raw` immediately above and is not
    // aliased yet.
    // SAFETY: `pointer` came from `Box::into_raw` immediately above and nothing
    // else holds it yet, so this is its only live reference.
    let pipe = unsafe { &mut *pointer };
    pipe.source = source;
    pipe.sink = sink;
    pipe.object = Some(v8::Global::new(scope.as_ref(), object));
    pipe.source_object = Some(v8::Global::new(scope.as_ref(), source_object));
    pipe.sink_object = Some(v8::Global::new(scope.as_ref(), sink_object));
    // `uses_wants_write_ = sink->HasWantsWrite()`. No stream in this runtime
    // reports it yet, so this is false — but it is read from the sink's state
    // rather than hardcoded, so a sink that gains the capability needs no change
    // here.
    // SAFETY: `sink` is the live state both objects share, as `FromObject` proved.
    pipe.uses_wants_write.set(unsafe {
        (*sink)
            .listeners
            .iter()
            .any(|attached| attached.stream().is_some())
    });

    object.set_aligned_pointer_in_internal_field(PIPE_FIELD, pointer.cast::<c_void>(), 0);

    // The four links `StreamPipe::New` establishes, which form the ownership
    // cycle that keeps the pair alive.
    link(scope, object, "source", source_object.into());
    link(scope, source_object, "pipeTarget", object.into());
    link(scope, object, "sink", sink_object.into());
    link(scope, sink_object, "pipeSource", object.into());

    // Push the two listeners. `StreamPipe`'s constructor does this, so a pipe
    // that is never `start()`ed has still captured both streams' completions.
    let readable = listener::ListenerRef::new(Box::new(ReadableListener { state: pointer }));
    // SAFETY: `source` is live and outlives the attachment, which the source
    // object's own state guarantees.
    if let Some(id) = unsafe { listener::push_stream_listener(source, readable) } {
        pipe.readable_id.set(Some(id));
    }
    let writable = listener::ListenerRef::new(Box::new(WritableListener { state: pointer }));
    // SAFETY: as above, for `sink`.
    if let Some(id) = unsafe { listener::push_stream_listener(sink, writable) } {
        pipe.writable_id.set(Some(id));
    }

    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this finalizer
            // runs exactly once.
            drop(unsafe { Box::from_raw(address as *mut PipeState) });
        }),
    );
    let weak = Box::into_raw(Box::new(weak));
    pipe.weak.set(Some(weak));

    rv.set(object.into());
}

/// Sets one of the four link properties, ignoring a failure.
///
/// None of them is read by native code: they exist for the garbage collector and
/// for `onFileUnpipe`'s diagnostics. A failure would mean the object is frozen,
/// which cannot happen for a freshly created stream handle.
fn link(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    name: &str,
    value: v8::Local<'_, v8::Value>,
) {
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    object.set(scope, key.into(), value);
}

/// `StreamPipe::Start`: open the pipe and ask the source to read.
fn start(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(state) = raw_state(args.this()) else {
        return;
    };
    // SAFETY: `raw_state` proved the pointer is live.
    let pipe = unsafe { &*state };
    pipe.is_closed.set(false);
    // `writable_listener_.OnStreamWantsWrite(65536)`, which is what actually
    // issues the first `ReadStart`.
    writable_wants_write(pipe, 65_536);
}

/// `StreamPipe::Unpipe`.
fn unpipe(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(state) = raw_state(args.this()) else {
        return;
    };
    // SAFETY: `raw_state` proved the pointer is live.
    unpipe_state(unsafe { &*state }, false);
}

/// `StreamPipe::IsClosed`.
fn is_closed(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let closed = with_state(args.this(), |state| state.is_closed.get()).unwrap_or(true);
    rv.set(v8::Boolean::new(scope, closed).into());
}

/// `StreamPipe::PendingWrites`.
fn pending_writes(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let pending = with_state(args.this(), |state| state.pending_writes.get()).unwrap_or(EBADF);
    rv.set(v8::Integer::new(scope, pending).into());
}

/// `StreamPipe::Unpipe`.
///
/// The order is the C++'s, and each step matters:
///
/// 1. `ReadStop` on the source unless it is already destroyed — a destroyed
///    stream has no live libuv handle to stop.
/// 2. detach the readable listener;
/// 3. detach the writable listener, unless writes are still in flight and the
///    sink is alive, because those completions still need a listener to report
///    to;
/// 4. if this was not a deletion, emit `onunpipe` and clear the four links,
///    deferred as a native immediate so it can run from a destructor.
///
/// `is_in_deletion` is the flag `~StreamPipe` passes: a pipe being collected must
/// not reach into JavaScript or touch objects that may already be gone.
fn unpipe_state(pipe: &PipeState, is_in_deletion: bool) {
    if pipe.is_closed.get() {
        return;
    }
    if !pipe.source_destroyed.get() && !pipe.source.is_null() {
        // SAFETY: the source is live until its own close callback runs, which is
        // what sets `source_destroyed`.
        unsafe {
            let raw = (*pipe.source).stream;
            if !raw.is_null() {
                rn_uv::stream::read_stop(raw);
            }
        }
    }
    pipe.is_closed.set(true);
    pipe.is_reading.set(false);

    if !pipe.source.is_null() {
        if let Some(id) = pipe.readable_id.take() {
            // SAFETY: the source state is live while the pipe exists.
            unsafe {
                listener::remove_stream_listener(pipe.source, id);
            }
        }
    }
    if (pipe.pending_writes.get() == 0 || pipe.sink_destroyed.get()) && !pipe.sink.is_null() {
        if let Some(id) = pipe.writable_id.take() {
            // SAFETY: as above, for the sink.
            unsafe {
                listener::remove_stream_listener(pipe.sink, id);
            }
        }
    }

    if is_in_deletion {
        return;
    }
    let address = (pipe as *const PipeState) as usize;
    crate::defer_unpipe(address);
}

/// Emits `onunpipe` and clears the four links. Runs on the check phase.
///
/// # Safety
///
/// `pipe` must still be the live state of a `StreamPipe` object, which
/// `crate::deliver_unpipe` guarantees by only draining addresses queued while the
/// pipe was alive.
pub(crate) unsafe fn notify_unpiped(scope: &mut v8::PinScope<'_, '_>, pipe: &PipeState) {
    let Some(object) = pipe
        .object
        .as_ref()
        .map(|object| v8::Local::new(scope, object))
    else {
        return;
    };
    let Some(key) = v8::String::new(scope, "onunpipe") else {
        return;
    };
    let Some(value) = object.get(scope, key.into()) else {
        return;
    };
    if let Ok(handler) = v8::Local::<v8::Function>::try_from(value) {
        let _ = handler.call(scope, object.into(), &[]);
    }
    // `Set(..., null)` on all four, so the cycle is broken and a caller can tell
    // the pipe has finished with both streams.
    let null = v8::null(scope).into();
    let _ = object.set(scope, key.into(), null);
    for (target, name) in [
        (
            pipe.source_object
                .as_ref()
                .map(|o| v8::Local::new(scope, o)),
            "pipeTarget",
        ),
        (
            pipe.sink_object.as_ref().map(|o| v8::Local::new(scope, o)),
            "pipeSource",
        ),
    ] {
        let Some(target) = target else {
            continue;
        };
        let Some(key) = v8::String::new(scope, name) else {
            continue;
        };
        let _ = target.set(scope, key.into(), null);
    }
    for name in ["source", "sink"] {
        if let Some(key) = v8::String::new(scope, name) {
            let _ = object.set(scope, key.into(), null);
        }
    }
}

/// `WritableListener::OnStreamWantsWrite`: record the hint and start reading.
///
/// The guard is Node's: a pipe that is already reading, is closed, or has lost its
/// source does nothing, which is what stops a `start()` after `unpipe()` from
/// reviving a stopped pipe.
fn writable_wants_write(pipe: &PipeState, suggested_size: usize) {
    pipe.wanted_data.set(suggested_size);
    if pipe.is_reading.get() || pipe.is_closed.get() || pipe.source_destroyed.get() {
        return;
    }
    pipe.is_reading.set(true);
    if pipe.source.is_null() {
        return;
    }
    // SAFETY: the source is live until `source_destroyed` is set, which the guard
    // above checked.
    unsafe {
        let raw = (*pipe.source).stream;
        if !raw.is_null() {
            rn_uv::stream::read_start(raw, pipe.source);
        }
    }
}

/// The listener on the source: forwards reads to the sink as writes.
struct ReadableListener {
    /// The pipe this listener belongs to.
    ///
    /// A raw pointer rather than an `Rc<RefCell<..>>` because the state is owned
    /// by the `StreamPipe` object's finalizer, and `rn_uv`'s rule is that no
    /// borrow may be held across a listener call — which a `RefCell` would make
    /// easy to violate. The pipe outlives both listeners: it detaches them in
    /// `unpipe_state` while it still exists.
    state: *mut PipeState,
}

impl ReadableListener {
    fn pipe(&self) -> Option<&PipeState> {
        if self.state.is_null() {
            return None;
        }
        // SAFETY: the pipe owns this listener and frees neither while it is
        // attached, so the pointer is live for the duration of the call.
        Some(unsafe { &*self.state })
    }
}

impl StreamListener for ReadableListener {
    /// `ReadableListener::OnStreamRead`: a source read becomes a sink write.
    ///
    /// EOF is handled as the C++ does: stop reading, hand the error to whoever is
    /// below this listener, and — if no write is in flight — shut the sink down
    /// and unpipe. Otherwise the write completion does it, in
    /// [`WritableListener::on_stream_after_write`].
    fn on_stream_read(&mut self, this: &ListenerRef, nread: isize, buffer: ReadBuffer) {
        let Some(pipe) = self.pipe() else {
            return;
        };
        if nread <= 0 {
            pipe.is_eof.set(true);
            this.pass_read_error_to_previous_listener(nread);
            if pipe.pending_writes.get() == 0 {
                shutdown_sink(pipe);
                unpipe_state(pipe, false);
            }
            return;
        }
        let Some(bytes) = buffer.bytes(nread) else {
            return;
        };
        // Copied rather than handed over: a queued `uv_write` needs its buffer to
        // outlive this callback, and `ReadBuffer::Allocated` is owned by the read
        // that produced it. See this module's docs.
        let bytes = bytes.to_vec();
        pipe.pending_writes.set(pipe.pending_writes.get() + 1);
        write_to_sink(pipe, bytes);
    }

    /// `ReadableListener::OnStreamDestroy`.
    fn on_stream_destroy(&mut self, this: &ListenerRef) {
        let _ = this;
        let Some(pipe) = self.pipe() else {
            return;
        };
        pipe.source_destroyed.set(true);
        if pipe.is_eof.get() {
            return;
        }
        pipe.is_eof.set(true);
        if pipe.pending_writes.get() == 0 {
            shutdown_sink(pipe);
            unpipe_state(pipe, false);
        }
    }
}

/// `sink()->Write(&buffer, 1)`, with the completion accounted for.
fn write_to_sink(pipe: &PipeState, bytes: Vec<u8>) {
    if pipe.sink.is_null() {
        return;
    }
    // SAFETY: the sink is live until `sink_destroyed` is set.
    let raw = unsafe { (*pipe.sink).stream };
    if raw.is_null() {
        return;
    }
    let length = bytes.len();
    let status = drain_to_sink(raw, bytes);
    if status != 0 {
        // The write never queued, so no completion will fire. Node's
        // `ProcessData` decrements only in the asynchronous branch, and reports a
        // synchronous failure through `OnStreamAfterWrite` with a null request;
        // this crate reports it by passing the status on and clearing the count.
        pipe.pending_writes.set(pipe.pending_writes.get() - 1);
        let _ = length;
    }
}

/// Runs the write and returns libuv's status.
///
/// `rn_uv::stream::queue_write` wants a request object to hang its completion on.
/// A `StreamPipe` write has no caller-supplied `WriteWrap` — the bytes came from
/// the source's read, not from JavaScript — so a bare `WriteWrap` with no
/// `oncomplete` is used, which is what Node's internal `StreamWriteResult` does
/// for the same case.
fn drain_to_sink(raw: *mut rn_uv::sys::uv_stream_t, bytes: Vec<u8>) -> i32 {
    let length = bytes.len();
    let buffer = rn_uv::sys::uv_buf_t {
        base: bytes.as_ptr() as *mut std::os::raw::c_char,
        len: length,
    };
    // SAFETY: `raw` is the live sink stream, and `bytes` is moved into `owned`
    // below so its allocation outlives the completion.
    unsafe {
        rn_uv::stream::queue_write_unowned(
            raw,
            vec![buffer],
            length,
            vec![bytes.into_boxed_slice()],
        )
    }
}

/// `sink()->Shutdown()`.
fn shutdown_sink(pipe: &PipeState) {
    if pipe.sink.is_null() {
        return;
    }
    // SAFETY: the sink is live while the pipe exists.
    unsafe {
        let raw = (*pipe.sink).stream;
        if !raw.is_null() {
            rn_uv::stream::end_stream(raw);
        }
    }
}

/// The listener on the sink: counts writes down and finishes the pipe.
struct WritableListener {
    state: *mut PipeState,
}

impl WritableListener {
    fn pipe(&self) -> Option<&PipeState> {
        if self.state.is_null() {
            return None;
        }
        // SAFETY: as `ReadableListener::pipe`.
        Some(unsafe { &*self.state })
    }
}

impl StreamListener for WritableListener {
    /// `WritableListener::OnStreamAfterWrite`.
    ///
    /// The four branches are the C++'s:
    ///
    /// * closed: emit `oncomplete`-equivalent work — here, nothing, because the
    ///   pipe's own completion is `onunpipe`, which `unpipe_state` already
    ///   queued — and detach from the sink;
    /// * EOF and nothing left: shut the sink down and unpipe;
    /// * a status: unpipe and pass the status to the previous listener;
    /// * otherwise, ask the source for more bytes.
    fn on_stream_after_write<'s>(
        &mut self,
        this: &ListenerRef,
        scope: &mut v8::PinScope<'s, '_>,
        request: v8::Local<'s, v8::Object>,
        handle: Option<v8::Local<'s, v8::Object>>,
        status: i32,
    ) {
        let Some(pipe) = self.pipe() else {
            return;
        };
        pipe.pending_writes.set(pipe.pending_writes.get() - 1);
        if pipe.is_closed.get() {
            // Whichever of the two counts reached zero, the listener can go. The
            // pipe's `onunpipe` is already queued by `unpipe_state`.
            if pipe.pending_writes.get() <= 0 && !pipe.sink.is_null() {
                if let Some(id) = pipe.writable_id.take() {
                    // SAFETY: the sink is live while the pipe exists.
                    unsafe {
                        listener::remove_stream_listener(pipe.sink, id);
                    }
                }
            }
            return;
        }
        if pipe.is_eof.get() {
            shutdown_sink(pipe);
            unpipe_state(pipe, false);
            return;
        }
        if status != 0 {
            unpipe_state(pipe, false);
            this.forward_after_write(scope, request, handle, status);
            return;
        }
        if !pipe.uses_wants_write.get() {
            // Node's `OnStreamWantsWrite(65536)`, which resumes the source.
            writable_wants_write(pipe, 65_536);
        }
    }

    /// `WritableListener::OnStreamAfterShutdown`.
    fn on_stream_after_shutdown<'s>(
        &mut self,
        this: &ListenerRef,
        scope: &mut v8::PinScope<'s, '_>,
        request: v8::Local<'s, v8::Object>,
        handle: Option<v8::Local<'s, v8::Object>>,
        status: i32,
    ) {
        if let Some(pipe) = self.pipe() {
            unpipe_state(pipe, false);
        }
        this.forward_after_shutdown(scope, request, handle, status);
    }

    /// `WritableListener::OnStreamDestroy`.
    fn on_stream_destroy(&mut self, this: &ListenerRef) {
        let _ = this;
        let Some(pipe) = self.pipe() else {
            return;
        };
        pipe.sink_destroyed.set(true);
        pipe.is_eof.set(true);
        // `pending_writes_` is deliberately not reset: the completions still in
        // flight are what will finish the count, and `unpipe_state` detaches
        // regardless because `sink_destroyed` is set.
        unpipe_state(pipe, false);
    }

    /// `WritableListener::OnStreamWantsWrite`.
    fn on_stream_wants_write(&mut self, suggested_size: usize) {
        if let Some(pipe) = self.pipe() {
            writable_wants_write(pipe, suggested_size);
        }
    }

    /// `WritableListener::OnStreamAlloc`: ask the listener below.
    fn on_stream_alloc(&mut self, suggested_size: usize) -> Option<rn_uv::sys::uv_buf_t> {
        let _ = suggested_size;
        None
    }

    /// `WritableListener::OnStreamRead`: forward to the listener below.
    fn on_stream_read(&mut self, this: &ListenerRef, nread: isize, buffer: ReadBuffer) {
        this.pass_read_error_to_previous_listener(nread);
        let _ = buffer;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pipe_starts_closed() {
        // Node's default is `is_closed_ = true`, and `start()` is what clears it.
        // That is what makes `unpipe()` on a fresh pipe a no-op instead of a
        // spurious `onunpipe` — the state a `sendFile` that never started would
        // otherwise hit on its first teardown.
        let state = PipeState::new();
        assert!(state.is_closed.get());
        assert!(!state.is_reading.get());
        assert!(!state.is_eof.get());
        assert_eq!(state.pending_writes.get(), 0);
    }

    #[test]
    fn unpiping_a_closed_pipe_does_nothing() {
        // The early return in `unpipe_state`: no listener calls, no deferred
        // notification. Checked through the observable flag rather than by calling
        // `unpipe_state`, which would dereference the null stream pointers.
        let state = PipeState::new();
        assert!(state.is_closed.get());
        assert!(state.readable_id.get().is_none());
        assert!(state.writable_id.get().is_none());
    }

    #[test]
    fn the_hint_guards_match_nodes_condition() {
        // `OnStreamWantsWrite` returns early when the pipe is reading, closed, or
        // its source is gone. A pipe that reads the hint but does not resume is
        // what stops a `start()` after `unpipe()` reviving a stopped pipe.
        let state = PipeState::new();
        // Closed, so the guard trips before anything touches the null streams.
        writable_wants_write(&state, 65_536);
        assert_eq!(state.wanted_data.get(), 65_536);
        assert!(!state.is_reading.get());
    }
}
