//! `createHeapSnapshotStream(options)` and the handle it returns.
//!
//! `src/heap_utils.cc`'s `HeapSnapshotStream` is three things stacked into one
//! object: an `AsyncWrap` (so it has an async id), a `StreamBase` (so
//! `lib/internal/stream_base_commons.js`'s `onStreamRead` can drive it) and a
//! `v8::OutputStream` (so V8 has somewhere to put the serialized snapshot).
//!
//! # When the snapshot is taken, and when it is serialized
//!
//! Node separates the two, and the split is observable:
//!
//! * `CreateHeapSnapshotStream` calls `GetHeapProfiler()->TakeHeapSnapshot()`
//!   immediately, so the graph is captured at the moment `v8.getHeapSnapshot()`
//!   is called even though nothing has been read yet.
//! * `ReadStart` then calls `snapshot_->Serialize(this, kJSON)`, so the bytes
//!   are only produced once the `Readable` asks for them.
//!
//! `v8::Isolate::take_heap_snapshot` in the `v8` crate does both in one call and
//! has no way to hand back the intermediate snapshot. So both happen in
//! `createHeapSnapshotStream`: the graph is captured then, and V8's own chunks
//! are collected into one buffer that `ReadStart` later delivers. The captured
//! graph is the one Node captures at that same point — what differs is that the
//! JSON exists in memory slightly sooner, not that it describes another heap.
//!
//! Collecting into a buffer rather than calling into JavaScript from inside the
//! V8 callback is also what makes this sound. `take_heap_snapshot` needs
//! `&mut Isolate`, which a callback only obtains through the raw pointer
//! `set_snapshot_isolate` recorded, and no second V8 scope may be opened through
//! it. The callback therefore only touches a `Vec<u8>`, and every JavaScript
//! call happens after it has returned, on the real scope.
//!
//! # The read protocol
//!
//! `ReadStart` reproduces `HeapSnapshotStream::ReadStart`: V8's chunks are
//! re-cut into `GetChunkSize()`-sized pieces, each is published to
//! `streamBaseState` and pushed through `onread`, and then `EndOfStream` reports
//! `UV_EOF`. Backpressure is ignored on purpose — `WriteAsciiChunk` in
//! `src/heap_utils.cc` returns `kContinue` unconditionally and `ReadStop` is a
//! no-op returning 0 — so the whole document is pushed in one synchronous burst
//! and buffered by the `Readable`, which is exactly what Node does. Measured
//! against a real Node binary, both runtimes produce the same shape: every chunk
//! is 65536 bytes except the last, and `bytesRead` equals the document's length.
//!
//! # What is not here
//!
//! The write half of `StreamBase` — `writeBuffer`, `writev`, the `write*String`
//! methods, `shutdown` and `useUserBuffer`. Node installs them because
//! `StreamBase::AddMethods` puts the whole surface on every stream template, but
//! `HeapSnapshotStream::DoWrite` and `DoShutdown` are `UNREACHABLE()`: a snapshot
//! stream is read-only, so reaching them is a bug in either runtime. Installing
//! methods that could only ever throw would suggest otherwise.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;

use rn_v8_sys::v8;

/// Internal field holding the `*mut SnapshotStream`.
const STATE_FIELD: i32 = 0;

thread_local! {
    /// The `HeapSnapshotStream` constructor, rooted across native calls.
    ///
    /// `createHeapSnapshotStream` needs it long after `install` returned, and a
    /// function callback cannot carry captured state, so it lives here — the
    /// same arrangement `crates/rn-bind-tcp-wrap/src/handle.rs` uses for its own
    /// constructor.
    static CONSTRUCTOR: RefCell<Option<v8::Global<v8::Function>>> = const { RefCell::new(None) };
}

/// Roots `constructor` for later use by [`constructor_for`].
pub fn remember_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    constructor: v8::Local<v8::Function>,
) {
    CONSTRUCTOR.with(|slot| {
        *slot.borrow_mut() = Some(v8::Global::new(scope.as_ref(), constructor));
    });
}

/// The rooted constructor, or `None` when the namespace was never installed.
pub fn constructor_for<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    CONSTRUCTOR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|constructor| v8::Local::new(scope, constructor))
    })
}

/// `HeapSnapshotStream::GetChunkSize()`: "big chunks == faster".
pub const CHUNK_SIZE: usize = 65536;

/// `UV_EOF` from `uv.h`.
pub fn uv_eof() -> i32 {
    rn_uv::sys::uv_errno_t_UV_EOF
}

/// The native half of one `HeapSnapshotStream` object.
pub struct SnapshotStream {
    /// V8's serialized snapshot, taken when `createHeapSnapshotStream` ran.
    ///
    /// Taken rather than borrowed so the buffer is released the moment
    /// `ReadStart` begins delivering it: Node drops the snapshot in
    /// `EndOfStream`, and holding a second copy for the object's whole life
    /// would double the cost of a stream nobody reads.
    snapshot: RefCell<Option<Vec<u8>>>,
    /// `StreamBase::bytes_read_`.
    bytes_read: Cell<u64>,
    /// `StreamBase::kOnReadFunctionField`, which Node keeps in an internal
    /// field behind a prototype accessor.
    ///
    /// A rooted copy rather than an internal field because the value is a
    /// `v8::Function` and a raw internal field would not keep it alive. The
    /// observable contract is only that `handle.onread = fn` and the native
    /// read path agree on what is there, which this keeps.
    onread: RefCell<Option<v8::Global<v8::Function>>>,
    /// Parks the finalizer registration so dropping it cannot cancel it.
    weak: RefCell<Option<v8::Weak<v8::Object>>>,
}

impl SnapshotStream {
    /// The bytes read so far, which `bytesRead` reports.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.get()
    }

    /// Whether the snapshot has been handed over.
    pub fn is_finished(&self) -> bool {
        self.snapshot.borrow().is_none()
    }

    /// The `onread` function, if one is assigned.
    fn onread<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
        self.onread
            .borrow()
            .as_ref()
            .map(|onread| v8::Local::new(scope, onread))
    }

    /// Assigns `onread`, mirroring `BaseObject::InternalFieldSet`'s
    /// `&Value::IsFunction` check: a non-function leaves the field alone.
    fn set_onread(&self, scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) {
        let Ok(function) = v8::Local::<v8::Function>::try_from(value) else {
            return;
        };
        *self.onread.borrow_mut() = Some(v8::Global::new(scope.as_ref(), function));
    }
}

/// Runs `body` with the state behind a `HeapSnapshotStream` object.
///
/// `None` for an object this crate did not construct, which is the situation
/// `ASSIGN_OR_RETURN_UNWRAP`'s `UV_EBADF` covers in Node.
pub fn with_stream<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&SnapshotStream) -> R,
) -> Option<R> {
    // SAFETY: the field only ever holds a pointer installed by [`create`], and
    // the object is a live local so its finalizer has not run.
    let address =
        unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) } as usize;
    if address == 0 {
        return None;
    }
    // SAFETY: as above — the address is the live state this object owns.
    Some(body(unsafe { &*(address as *const SnapshotStream) }))
}

/// Builds the `HeapSnapshotStream` constructor and its prototype.
///
/// Node builds this template lazily and caches it on the `Environment`
/// (`streambaseoutputstream_constructor_template`); rustnode registers a
/// namespace once per process, so the constructor is built once here.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    // `FunctionTemplate::New(isolate)` with no callback and the default length.
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name =
        v8::String::new(scope, "HeapSnapshotStream").ok_or("cannot allocate the class name")?;
    template.set_class_name(name);

    let instance = template.instance_template(scope);
    instance.set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    // `StreamBase::AddMethods` installs the four accessors first, then the
    // methods, then `isStreamBase`. The order is kept because it is what a
    // caller iterating the prototype sees.
    for (key, accessor) in [
        ("fd", v8::FunctionTemplate::builder(get_fd)),
        (
            "_externalStream",
            v8::FunctionTemplate::builder(get_external),
        ),
        ("bytesRead", v8::FunctionTemplate::builder(get_bytes_read)),
        (
            "bytesWritten",
            v8::FunctionTemplate::builder(get_bytes_written),
        ),
    ] {
        let accessor = accessor
            .length(0)
            .constructor_behavior(v8::ConstructorBehavior::Throw)
            .build(scope);
        let key = v8::String::new(scope, key).ok_or("cannot allocate an accessor name")?;
        prototype.set_accessor_property(
            key.into(),
            Some(accessor),
            None,
            v8::PropertyAttribute::DONT_DELETE,
        );
    }

    for (key, method) in [
        ("readStart", v8::FunctionTemplate::builder(read_start)),
        ("readStop", v8::FunctionTemplate::builder(read_stop)),
    ] {
        let method = method
            .length(0)
            .constructor_behavior(v8::ConstructorBehavior::Throw)
            .build(scope);
        let key = v8::String::new(scope, key).ok_or("cannot allocate a method name")?;
        prototype.set(key.into(), method.into());
    }

    // `t->PrototypeTemplate()->Set("isStreamBase", True(isolate))`.
    let is_stream_base = v8::Boolean::new(scope, true);
    let key = v8::String::new(scope, "isStreamBase").ok_or("cannot allocate isStreamBase")?;
    prototype.set(key.into(), is_stream_base.into());

    // `AddAccessor(..., DontDelete | DontEnum, ..., kOnReadFunctionField)`.
    // The attributes are part of the surface: `Object.keys(handle)` is empty in
    // Node because every accessor is non-enumerable, and a data property here
    // would make `onread` show up in an inspection of the handle.
    let getter = v8::FunctionTemplate::builder(get_onread)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let setter = v8::FunctionTemplate::builder(set_onread)
        .length(1)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let key = v8::String::new(scope, "onread").ok_or("cannot allocate onread")?;
    prototype.set_accessor_property(
        key.into(),
        Some(getter),
        Some(setter),
        v8::PropertyAttribute::DONT_DELETE,
    );

    let function = template
        .get_function(scope)
        .ok_or("cannot allocate the HeapSnapshotStream constructor")?;
    function.set_name(name);
    Ok(function.into())
}

/// Allocates one stream object holding `snapshot`.
///
/// Built through the constructor's prototype so the object reports
/// `HeapSnapshotStream` as its class, has the two pre-created properties, and
/// carries the internal field the methods read.
pub fn create<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    constructor: v8::Local<'s, v8::Function>,
    snapshot: Vec<u8>,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = constructor.new_instance(&*scope, &[])?;
    let state = Box::into_raw(Box::new(SnapshotStream {
        snapshot: RefCell::new(Some(snapshot)),
        bytes_read: Cell::new(0),
        onread: RefCell::new(None),
        weak: RefCell::new(None),
    }));
    object.set_aligned_pointer_in_internal_field(STATE_FIELD, state.cast::<c_void>(), 0);

    let address = state as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this
            // finalizer runs exactly once.
            drop(unsafe { Box::from_raw(address as *mut SnapshotStream) });
        }),
    );
    // SAFETY: `state` is live and this is its only borrow.
    *unsafe { &(*state).weak }.borrow_mut() = Some(weak);
    Some(object)
}

/// The constructor callback.
///
/// `FunctionTemplate::New(isolate)` in `src/heap_utils.cc` has no callback at
/// all. This exists so the object [`create`] allocates is a real instance, and
/// so a script that somehow reaches the constructor gets an object whose methods
/// report nothing read rather than one whose internal field is null.
fn new(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set(args.this().into());
}

/// `StreamBase::GetFD()` — always -1, because this stream has no descriptor.
fn get_fd(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set(v8::Integer::new(scope, -1).into());
}

/// `StreamBase::GetExternal()` — the stream's own address, wrapped in a V8
/// `External` the way `StreamBase::GetExternal` does.
///
/// Nothing in `lib/**` reads it; it exists because it is part of the surface
/// `StreamBase::AddMethods` installs, and leaving it `undefined` would be a gap
/// a caller could not distinguish from a stream that had no state.
fn get_external(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // SAFETY: the field only ever holds a pointer installed by [`create`], and
    // the object is a live local so its finalizer has not run. Only the address
    // is taken, never dereferenced.
    let address = unsafe {
        args.this()
            .get_aligned_pointer_from_internal_field(STATE_FIELD, 0)
    };
    if address.is_null() {
        return;
    }
    let external = v8::External::new(scope, address as *mut c_void);
    rv.set(external.into());
}

/// `StreamBase::GetBytesRead()`.
fn get_bytes_read(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = with_stream(args.this(), SnapshotStream::bytes_read).unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `StreamBase::GetBytesWritten()`. A snapshot stream is never written to, so
/// this reports the counter's initial value rather than a measurement.
fn get_bytes_written(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set(v8::Number::new(scope, 0.0).into());
}

/// `HeapSnapshotStream::ReadStart`: deliver the snapshot and report the end.
///
/// Everything is pushed before this returns, so a call from inside a `data`
/// handler finds the snapshot already taken and does nothing. Node reaches the
/// same place through `snapshot_.reset()` in `EndOfStream`.
fn read_start<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    // Taking the buffer is what makes a second `readStart` a no-op: the first
    // call owns the bytes from here on.
    let snapshot = with_stream(object, |stream| stream.snapshot.borrow_mut().take()).flatten();
    let Some(snapshot) = snapshot else {
        // A stream that already delivered everything. Node `CHECK`s the
        // snapshot is non-null here, which aborts; returning 0 is the same
        // answer without the abort, and no correct caller reaches it.
        rv.set(v8::Integer::new(scope, 0).into());
        return;
    };

    rn_uv::stream::state_array(scope);
    for chunk in snapshot.chunks(CHUNK_SIZE) {
        // `EmitRead` counts before the listener sees the bytes, so `bytesRead`
        // is already up to date inside `onread`.
        with_stream(object, |stream| {
            stream
                .bytes_read
                .set(stream.bytes_read.get() + chunk.len() as u64)
        });
        if !emit_chunk(scope, object, chunk) {
            break;
        }
    }

    // `EndOfStream`: `EmitRead(UV_EOF)`, which `onStreamRead` turns into
    // `push(null)` and therefore `end` followed by `close`.
    emit_eof(scope, object);
    rv.set(v8::Integer::new(scope, 0).into());
}

/// `HeapSnapshotStream::ReadStop` — `return 0`, with nothing to stop.
///
/// `onStreamRead` calls this whenever `push` reports backpressure. Node's
/// version is empty because the whole snapshot is already on its way by then.
fn read_stop(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set(v8::Integer::new(scope, 0).into());
}

/// Delivers one chunk the way `StreamBase::CallJSOnreadMethod` does.
///
/// The count and offset go into the shared `streamBaseState` first, because
/// `onStreamRead` reads them before it looks at its argument. Returns whether
/// `onread` was callable; `lib/internal/heap_utils.js` assigns it in the
/// `HeapSnapshotStream` constructor, and Node's `CHECK(onread->IsFunction())`
/// would abort where this reports that there is nowhere to deliver.
fn emit_chunk<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    chunk: &[u8],
) -> bool {
    rn_uv::stream::with_state(|state| {
        state.set(rn_uv::handle::K_READ_BYTES_OR_ERROR, chunk.len() as u32);
        state.set(rn_uv::handle::K_ARRAY_BUFFER_OFFSET, 0);
    });

    let Some(onread) = with_stream(object, |stream| stream.onread(scope)).flatten() else {
        return false;
    };
    // A fresh backing store per chunk: `onStreamRead` wraps it in a
    // `FastBuffer` that outlives this call, so the bytes cannot come from a
    // buffer that is about to be reused.
    let store = v8::ArrayBuffer::new_backing_store_from_vec(chunk.to_vec()).make_shared();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let argument: v8::Local<'s, v8::Value> = buffer.into();
    let receiver: v8::Local<'s, v8::Value> = object.into();
    let _ = onread.call(scope, receiver, &[argument]);
    true
}

/// `HeapSnapshotStream::EndOfStream`: `EmitRead(UV_EOF)`.
fn emit_eof<'s>(scope: &mut v8::PinScope<'s, '_>, object: v8::Local<'s, v8::Object>) {
    rn_uv::stream::with_state(|state| {
        state.set(rn_uv::handle::K_READ_BYTES_OR_ERROR, uv_eof() as u32);
        state.set(rn_uv::handle::K_ARRAY_BUFFER_OFFSET, 0);
    });
    let Some(onread) = with_stream(object, |stream| stream.onread(scope)).flatten() else {
        return;
    };
    let receiver: v8::Local<'s, v8::Value> = object.into();
    let _ = onread.call(scope, receiver, &[]);
}

/// The `onread` accessor's getter, `BaseObject::InternalFieldGet`.
fn get_onread(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = with_stream(args.this(), |stream| stream.onread(scope)).flatten();
    match value {
        Some(value) => rv.set(value.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// The `onread` accessor's setter.
fn set_onread(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let value = args.get(0);
    with_stream(args.this(), |stream| stream.set_onread(scope, value));
}
