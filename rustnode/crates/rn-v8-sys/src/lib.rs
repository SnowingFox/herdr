//! Pins the V8 build rustnode links against.
//!
//! rustnode does not replace the JavaScript engine. It links the same V8 major
//! version Node 28 ships so that `v8.serialize`, real `vm` contexts, GC timing
//! and stack formatting behave identically.

pub use v8;

pub mod platform;

use std::cell::RefCell;

unsafe extern "C" {
    fn rn_v8_sys__set_stack_limit(isolate: v8::UnsafeRawIsolatePtr, stack_limit: usize);
    fn rn_v8_sys__measure_memory(
        isolate: v8::UnsafeRawIsolatePtr,
        context: *const v8::Context,
        resolver: *const v8::PromiseResolver,
        mode: i32,
        execution: i32,
    ) -> bool;
    /// `v8::HeapProfiler::QueryObjects`, via the shim in this crate.
    ///
    /// `filter` is called once per heap object with `user` and the object's raw
    /// pointer; it answers whether the object matches. The return value is a raw
    /// `v8::Array*` — the tagged pointer a `v8::Local` holds — or null when the
    /// shim refused its arguments.
    fn rn_v8_sys__query_objects(
        isolate: v8::UnsafeRawIsolatePtr,
        context: *const v8::Context,
        filter: extern "C" fn(*mut std::ffi::c_void, *const v8::Object) -> bool,
        user: *mut std::ffi::c_void,
        out: *mut *mut v8::Array,
    ) -> bool;
    /// `v8::HeapProfiler::TakeHeapSnapshot(options)` + `HeapSnapshot::Serialize`,
    /// via the shim in this crate.
    ///
    /// The crate's own `Isolate::take_heap_snapshot` calls the no-argument
    /// `TakeHeapSnapshot()`, so V8 always applies its default
    /// `HeapSnapshotOptions`. This passes Node's two flags through instead.
    fn rn_v8_sys__take_heap_snapshot(
        isolate: v8::UnsafeRawIsolatePtr,
        expose_internals: bool,
        expose_numeric_values: bool,
        write: extern "C" fn(*mut std::ffi::c_void, *const std::os::raw::c_char, usize) -> bool,
        user: *mut std::ffi::c_void,
    ) -> bool;
    /// `v8::HeapProfiler::AddBuildEmbedderGraphCallback`, via the shim in this
    /// crate. See [`register_embedder_graph`].
    fn rn_v8_sys__add_build_embedder_graph_callback(
        isolate: v8::UnsafeRawIsolatePtr,
        callback: extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void),
        user: *mut std::ffi::c_void,
    ) -> bool;
    /// The matching removal.
    fn rn_v8_sys__remove_build_embedder_graph_callback(isolate: v8::UnsafeRawIsolatePtr);
    /// Adds one node to a graph and returns it as an opaque handle.
    fn rn_v8_sys__embedder_graph_add_node(
        graph: *mut std::ffi::c_void,
        name: *const std::os::raw::c_char,
        size: usize,
    ) -> *mut std::ffi::c_void;
    /// Adds a named edge between two nodes the same graph returned.
    fn rn_v8_sys__embedder_graph_add_edge(
        graph: *mut std::ffi::c_void,
        from: *mut std::ffi::c_void,
        to: *mut std::ffi::c_void,
        name: *const std::os::raw::c_char,
    );
}

/// One node in the embedder graph V8 is building.
///
/// Opaque on purpose: the shim owns the storage and V8 owns it from the moment
/// it is added, so all Rust keeps is this handle. It is valid only for the
/// duration of one [`EmbedderGraph::add_node`] call's graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmbedderNode(*mut std::ffi::c_void);

/// The embedder graph V8 hands a build callback, for adding nodes and edges.
///
/// A snapshot taken without an embedder callback contains no native nodes at
/// all: no `Node / MessagePort`, no `Node / Worker`. Node always has one — it
/// registers `Environment::BuildEmbedderGraph` at isolate creation — so a test
/// that looks for those nodes asserts on a walk that rustnode has to reproduce
/// itself. This is the write side of that walk; see [`register_embedder_graph`]
/// for the read side.
#[derive(Clone, Copy, Debug)]
pub struct EmbedderGraph {
    raw: *mut std::ffi::c_void,
}

impl EmbedderGraph {
    /// Wraps the pointer a build callback is given.
    ///
    /// # Safety
    ///
    /// `raw` must be the `v8::EmbedderGraph*` of the callback currently running,
    /// used only inside it.
    #[must_use]
    pub unsafe fn from_raw(raw: *mut std::ffi::c_void) -> Self {
        Self { raw }
    }

    /// Adds a node named `name` with `size` bytes and returns its handle.
    ///
    /// `name` is joined with `"Node / "` by the graph, matching Node's
    /// `MemoryRetainerNode::NamePrefix`, so `"MessagePort"` becomes the snapshot
    /// node `Node / MessagePort`. Returns `None` for an allocation failure, which
    /// V8 does not distinguish from a rejected argument.
    #[must_use]
    pub fn add_node(&self, name: &str, size: usize) -> Option<EmbedderNode> {
        let name = std::ffi::CString::new(name).ok()?;
        // SAFETY: `self.raw` is the graph of the running callback, and `name`
        // outlives the call.
        let node = unsafe { rn_v8_sys__embedder_graph_add_node(self.raw, name.as_ptr(), size) };
        if node.is_null() {
            None
        } else {
            Some(EmbedderNode(node))
        }
    }

    /// Adds a named edge `from --name--> to`.
    ///
    /// Both nodes must have come from this graph. V8 stores the `char*` rather
    /// than copying it, so the name has to outlive the snapshot; `'static` names
    /// are interned once by [`static_edge_name`] instead of leaked per snapshot.
    pub fn add_edge(&self, from: EmbedderNode, to: EmbedderNode, name: &'static str) {
        let Some(name) = static_edge_name(name) else {
            return;
        };
        // SAFETY: both handles came from this graph and are still owned by it,
        // the snapshot has not been serialized yet, and `name` lives for the
        // process.
        unsafe {
            rn_v8_sys__embedder_graph_add_edge(self.raw, from.0, to.0, name);
        }
    }
}

/// The `char*` for an edge name V8 will hold for a snapshot's lifetime.
///
/// Interned by literal address, so a snapshot costs no allocation per edge and
/// the pointer V8 keeps is valid for the process rather than for one snapshot.
fn static_edge_name(name: &'static str) -> Option<*const std::os::raw::c_char> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static NAMES: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
    let names = NAMES.get_or_init(|| Mutex::new(HashMap::new()));
    let key = name.as_ptr() as usize;
    let mut names = names.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(pointer) = names.get(&key) {
        return Some(*pointer as *const std::os::raw::c_char);
    }
    let pointer = std::ffi::CString::new(name).ok()?.into_raw();
    names.insert(key, pointer as usize);
    Some(pointer)
}

/// The state a registered build callback carries.
pub struct EmbedderGraphCallback {
    /// Adds the nodes and edges for one snapshot. Called on the thread taking
    /// it, with the graph to fill.
    ///
    /// No `Send`/`Sync` bound: the registration is thread-local and V8 calls it
    /// on the thread that registered it, so a walk that touches per-thread state
    /// is the point rather than a hazard.
    pub build: Box<dyn Fn(EmbedderGraph)>,
}

/// Registers `callback` to add embedder nodes to every snapshot of `isolate`.
///
/// Returns false when the isolate has no heap profiler. The registration lives
/// for the isolate's lifetime; [`unregister_embedder_graph`] removes it.
///
/// # Safety
///
/// `isolate` must be the live isolate this thread owns, and it must outlive the
/// registration. `callback` runs on the snapshotting thread while V8 holds no
/// JavaScript scope of its own, so it may only write to the graph — it must not
/// call into V8.
pub unsafe fn register_embedder_graph(
    isolate: &v8::Isolate,
    callback: EmbedderGraphCallback,
) -> bool {
    // The one registration this thread forwards to.
    //
    // Thread-local for the same reason `Isolate` is: a worker's snapshot must run
    // the worker's walk, not the main thread's. Boxed and then leaked into the
    // slot so the pointer V8 keeps is stable for the isolate's life.
    thread_local! {
        static SLOT: std::cell::Cell<*mut EmbedderGraphCallback> =
            const { std::cell::Cell::new(std::ptr::null_mut()) };
    }

    /// The `extern "C"` body V8 calls: forwards to the thread's registration.
    ///
    /// # Safety
    ///
    /// `graph` is the live `v8::EmbedderGraph*` of the snapshot being taken.
    extern "C" fn trampoline(_user: *mut std::ffi::c_void, graph: *mut std::ffi::c_void) {
        SLOT.with(|slot| {
            let callback = slot.get();
            if callback.is_null() || graph.is_null() {
                return;
            }
            // SAFETY: the pointer was boxed and leaked by the registration
            // below, and V8 calls this on the thread that registered it.
            let callback = unsafe { &*callback };
            // SAFETY: the graph is live for the duration of this call.
            (callback.build)(unsafe { EmbedderGraph::from_raw(graph) });
        });
    }

    let boxed = Box::into_raw(Box::new(callback));
    SLOT.with(|slot| {
        // Replacing a previous registration would leak it; there is one per
        // isolate and one isolate per thread here, so a second call is a bug the
        // caller would see as a doubled node count. Freeing the old one is the
        // honest answer.
        let previous = slot.replace(boxed);
        if !previous.is_null() {
            // SAFETY: it came from `Box::into_raw` above.
            drop(unsafe { Box::from_raw(previous) });
        }
    });
    // SAFETY: the isolate is the caller's live one; the trampoline reads only
    // thread-local state and the graph V8 hands it.
    unsafe {
        rn_v8_sys__add_build_embedder_graph_callback(
            isolate.as_raw_isolate_ptr(),
            trampoline,
            std::ptr::null_mut(),
        )
    }
}

/// Removes the build callback registered for `isolate`.
///
/// # Safety
///
/// `isolate` must be the isolate [`register_embedder_graph`] was called with,
/// and no snapshot may be in progress on this thread.
pub unsafe fn unregister_embedder_graph(isolate: &v8::Isolate) {
    // SAFETY: the caller guarantees the isolate and that no snapshot runs now.
    unsafe { rn_v8_sys__remove_build_embedder_graph_callback(isolate.as_raw_isolate_ptr()) };
}

/// Which `HeapSnapshotOptions` a snapshot is taken with.
///
/// `lib/internal/heap_utils.js`'s `getHeapSnapshotOptions` builds
/// `Uint8Array([+exposeInternals, +exposeNumericValues])`, and Node's
/// `src/heap_utils.cc:GetHeapSnapshotOptions` maps those bytes onto
/// `HeapSnapshotMode` and `NumericsMode`. The names here are the JS option names
/// rather than the V8 enum names, so the two mappings cannot be confused.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeapSnapshotOptions {
    pub expose_internals: bool,
    pub expose_numeric_values: bool,
}

impl HeapSnapshotOptions {
    /// A regular snapshot with numeric values hidden, which is V8's default.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expose_internals: false,
            expose_numeric_values: false,
        }
    }
}

/// Takes a heap snapshot with `options` and serializes it as JSON.
///
/// `write` is called once or more with consecutive chunks of one JSON document
/// and returns whether to continue; returning `false` aborts the snapshot.
/// Returns `Err` when V8 produced no snapshot, which happens on allocation
/// failure, or when `write` aborted.
///
/// This is the options-taking sibling of `Isolate::take_heap_snapshot`, whose
/// binding in the `v8` crate calls the no-argument `TakeHeapSnapshot()` and so
/// always gets V8's default `HeapSnapshotOptions`.
///
/// # Safety
///
/// `isolate` must be a live isolate on the calling thread, entered by no other
/// scope for the duration. V8 calls `write` synchronously on this thread before
/// this returns, so no handle may be collected during the call.
pub unsafe fn take_heap_snapshot(
    isolate: &v8::Isolate,
    options: HeapSnapshotOptions,
    write: impl FnMut(&[u8]) -> bool,
) -> Result<(), &'static str> {
    /// What the `extern "C"` trampoline receives: the caller's closure and
    /// whether it asked to stop.
    struct Sink<'a> {
        write: &'a mut dyn FnMut(&[u8]) -> bool,
        aborted: &'a mut bool,
    }

    /// Forwards one chunk to the closure and records an abort.
    ///
    /// # Safety
    ///
    /// `user` is the `*mut Sink` `take_heap_snapshot` passes, alive for the
    /// duration of the one synchronous call V8 makes it from.
    extern "C" fn trampoline(
        user: *mut std::ffi::c_void,
        data: *const std::os::raw::c_char,
        size: usize,
    ) -> bool {
        // SAFETY: see the function docs.
        let sink = unsafe { &mut *user.cast::<Sink<'_>>() };
        if data.is_null() {
            // `EndOfStream` is reported as an empty chunk by the shim's own
            // `OutputStream`, and there is nothing left to hand on.
            return true;
        }
        // SAFETY: V8 owns `size` bytes at `data` for the duration of the call.
        let chunk = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) };
        let keep_going = (sink.write)(chunk);
        if !keep_going {
            *sink.aborted = true;
        }
        keep_going
    }

    let mut write = write;
    let mut aborted = false;
    let mut sink = Sink {
        write: &mut write,
        aborted: &mut aborted,
    };
    // SAFETY: `sink` outlives the call below, which is synchronous and the only
    // reader; the isolate is the caller's live one.
    let taken = unsafe {
        rn_v8_sys__take_heap_snapshot(
            isolate.as_raw_isolate_ptr(),
            options.expose_internals,
            options.expose_numeric_values,
            trampoline,
            (&mut sink as *mut Sink<'_>).cast(),
        )
    };
    if !taken {
        return Err("V8 could not take a heap snapshot");
    }
    if aborted {
        return Err("the heap snapshot was aborted");
    }
    Ok(())
}

/// Sets `v8::Isolate::SetStackLimit` on the current isolate.
///
/// # Safety
///
/// `stack_limit` must be a valid stack boundary for the isolate's running
/// thread for the full isolate lifetime.
pub unsafe fn set_isolate_stack_limit(isolate: &v8::Isolate, stack_limit: usize) {
    // SAFETY: the caller provides a valid stack limit for this isolate's thread
    // and `as_raw_isolate_ptr` is the v8 crate's own raw-isolate escape hatch.
    unsafe { rn_v8_sys__set_stack_limit(isolate.as_raw_isolate_ptr(), stack_limit) };
}

/// `v8::MeasureMemoryMode`, via the shim in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum MeasureMemoryMode {
    Summary = 0,
    Detailed = 1,
}

/// `v8::MeasureMemoryExecution`, via the shim in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum MeasureMemoryExecution {
    Default = 0,
    Eager = 1,
}

/// Calls `v8::Isolate::MeasureMemory` with `MeasureMemoryDelegate::Default`.
///
/// Returns the promise associated with `resolver` on success.
///
/// # Safety
///
/// `resolver` and `scope` must belong to the same entered isolate/context.
pub unsafe fn measure_memory<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    resolver: v8::Local<'s, v8::PromiseResolver>,
    mode: MeasureMemoryMode,
    execution: MeasureMemoryExecution,
) -> Option<v8::Local<'s, v8::Promise>> {
    let isolate: &v8::Isolate = scope.as_ref();
    let context = scope.get_current_context();
    // SAFETY: the pointers come from live locals in the current entered scope,
    // and `mode` / `execution` are pinned to V8's enum values.
    let started = unsafe {
        rn_v8_sys__measure_memory(
            isolate.as_raw_isolate_ptr(),
            &*context,
            &*resolver,
            mode as i32,
            execution as i32,
        )
    };
    if !started {
        return None;
    }
    Some(resolver.get_promise(scope))
}

/// The state `query_objects` hands to the shim's predicate callback.
struct QueryFilter<'s> {
    /// The scope `query_objects` is running under, as a raw pointer.
    ///
    /// Stored raw rather than as `&PinScope` because V8 calls the predicate while
    /// `query_objects` already holds the `&mut PinScope` it passed to the shim;
    /// a second mutable borrow is impossible, and a `&` borrow taken here would
    /// have to be alive across the FFI call that owns the `&mut`. The pointee
    /// outlives every callback: it is the caller's scope, and V8 calls `Filter`
    /// synchronously inside `QueryObjects`.
    scope: *const v8::PinScope<'s, 's>,
    context: v8::Local<'s, v8::Context>,
    search: v8::Local<'s, v8::Object>,
}

/// `Histogram`-free `PrototypeChainHas::Filter`: does `object` belong to this
/// context and have `search` in its prototype chain?
///
/// This is `src/internal_only_v8.cc:23` written against the crate's own bindings.
/// The creation-context test comes first and is what keeps an object from another
/// realm out of the result — `test-v8-query-objects.js` builds a second `vm`
/// context and asserts its objects are not counted.
fn object_matches(
    scope: &v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    context: v8::Local<'_, v8::Context>,
    search: v8::Local<'_, v8::Object>,
) -> bool {
    // `GetCreationContext().ToLocal(&creation_context)`: a `MaybeLocal` that is
    // empty for an object with no creation context (a handle from a detached
    // isolate, or one V8 has no record for).
    let Some(creation_context) = object.get_creation_context(scope) else {
        return false;
    };
    if creation_context != context {
        return false;
    }
    // `for (proto = object->GetPrototype(); proto->IsObject(); proto =
    // proto->GetPrototype())`: walk to the end of the chain, which is `null` (not
    // an object) and ends the loop.
    let mut proto = object.get_prototype(scope);
    while let Some(current) = proto {
        if !current.is_object() {
            break;
        }
        if current == v8::Local::<v8::Value>::from(search) {
            return true;
        }
        let Ok(current) = v8::Local::<v8::Object>::try_from(current) else {
            break;
        };
        proto = current.get_prototype(scope);
    }
    false
}

/// The `extern "C"` trampoline the shim calls once per heap object.
///
/// # Safety
///
/// `user` must be the `*mut QueryFilter` `query_objects` passed for the duration of
/// one shim call, and `object` must be a live V8 object pointer for the same call.
extern "C" fn query_filter_trampoline(
    user: *mut std::ffi::c_void,
    object: *const v8::Object,
) -> bool {
    // SAFETY: `query_objects` guarantees both come from its own frame, and V8 calls
    // the predicate synchronously inside `QueryObjects`.
    let state = unsafe { &*(user as *const QueryFilter<'_>) };
    let Some(object) = (unsafe { object.as_ref() }) else {
        return false;
    };
    // The pointer is the tagged object the shim read out of its own `Local`, so it
    // is the same handle by construction. `v8::Local` is `#[repr(C)]` over
    // `NonNull<T>`, which is what the shim's `operator*` returns.
    let object =
        unsafe { std::mem::transmute::<*const v8::Object, v8::Local<'_, v8::Object>>(object) };
    // SAFETY: see `QueryFilter::scope` — the pointee is the caller's live scope and
    // `Filter` runs synchronously inside the call that borrowed it mutably.
    let scope = unsafe { &*state.scope };
    object_matches(scope, object, state.context, state.search)
}

/// `v8::HeapProfiler::QueryObjects`: the `v8.queryObjects` walk.
///
/// Returns every object in `scope`'s current context whose prototype chain
/// contains `search`.
///
/// # Safety
///
/// `scope` must be a live scope in the isolate being queried, and `search` must be
/// an object from it. The shim hands raw pointers back to `query_filter_trampoline`
/// while V8 holds them, so no handle may be collected during the call — which the
/// entered scope guarantees.
pub unsafe fn query_objects<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    search: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Array>> {
    let isolate: &v8::Isolate = scope.as_ref();
    let context = scope.get_current_context();
    let filter = QueryFilter {
        scope: (scope as *const v8::PinScope<'_, '_>).cast(),
        context,
        search,
    };
    let user = (&filter as *const QueryFilter<'_>).cast_mut().cast();
    // The shim writes a `v8::Local<v8::Array>` into this slot. `v8::Local` is
    // `#[repr(C)]` over `NonNull<T>` (the crate's own declaration), so a
    // `Local<Array>` and a `*mut Array` have the same size and pass identically.
    let mut array: *mut v8::Array = std::ptr::null_mut();
    // SAFETY: the filter lives for the whole call, the isolate and context come
    // from the same entered scope, and `array` is a live out-slot for the duration.
    let found = unsafe {
        rn_v8_sys__query_objects(
            isolate.as_raw_isolate_ptr(),
            &*context,
            query_filter_trampoline,
            user,
            (&mut array as *mut *mut v8::Array).cast(),
        )
    };
    if !found || array.is_null() {
        return None;
    }
    // SAFETY: the shim just wrote a handle this scope owns into `array`, and
    // `Local` is `#[repr(C)]` over the same `NonNull<T>` a `*mut T` is.
    Some(unsafe { std::mem::transmute::<*mut v8::Array, v8::Local<'s, v8::Array>>(array) })
}

thread_local! {
    /// Whether the platform installed into V8 is ours.
    ///
    /// A `CustomPlatform` diverts every foreground post to [`platform`]'s queue, so
    /// `pump_message_loop` would then find an empty default queue and report that
    /// nothing ran. The flag picks the right drain without a global lookup, and it
    /// is per thread because "did *this* thread install the platform" is the
    /// question — installation happens once, before any isolate exists.
    static CUSTOM_PLATFORM: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Records that [`platform::new_platform`] produced the installed platform.
///
/// Called by whoever installs it, on the thread that calls
/// `V8::initialize_platform`. Without this the drain would keep asking V8's default
/// runner for work and never see a task posted through `PlatformImpl`.
pub fn use_custom_platform() {
    CUSTOM_PLATFORM.with(|slot| slot.set(true));
}

/// Runs the tasks V8 has queued for this isolate.
/// Returns whether any task ran. `wait_for_work` is false throughout: the queue
/// is drained from the event loop's per-iteration checkpoint, so blocking there
/// would stall the loop whenever nothing was posted.
///
/// With the default platform the tasks live in V8's own foreground runner, which
/// `pump_message_loop` pops from. With [`platform::new_platform`] installed they
/// live in [`platform`]'s queue instead, because `CustomPlatform` hands every post
/// to `PlatformImpl` and never queues it internally — so the drain has to be ours.
///
/// The platform is cached after the first call. `v8::V8::get_current_platform`
/// takes V8's global-state mutex and clones a `SharedRef`, and this runs on every
/// loop iteration; V8 is initialised once and `DisposePlatform` is never called
/// before the process exits, so the cached handle cannot go stale.
///
/// At most [`DRAIN_TASK_BUDGET`] tasks run per call. A task may post another, and
/// an unbounded drain would then never hand control back to libuv; Node's own
/// flush runs what the runner already holds and leaves later arrivals to the next
/// iteration.
pub fn pump_platform_tasks(scope: &v8::PinScope<'_, '_>) -> bool {
    /// Tasks one call will run before returning to the loop.
    const DRAIN_TASK_BUDGET: usize = 64;

    if CUSTOM_PLATFORM.with(|slot| slot.get()) {
        return platform::drain(scope);
    }

    thread_local! {
        static PLATFORM: RefCell<Option<v8::SharedRef<v8::Platform>>> =
            const { RefCell::new(None) };
    }

    PLATFORM.with(|slot| {
        // `try_borrow_mut`, not `borrow_mut`: a task run below may execute
        // JavaScript that reaches back into this function. A reentrant flush has
        // nothing to do — the outer call is already draining the queue — so
        // reporting "nothing ran" is both correct and panic-free.
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return false;
        };
        let platform = slot.get_or_insert_with(v8::V8::get_current_platform);
        let mut ran_any = false;
        for _ in 0..DRAIN_TASK_BUDGET {
            if !v8::Platform::pump_message_loop(platform, scope.as_ref(), false) {
                break;
            }
            ran_any = true;
        }
        ran_any
    })
}

/// V8 version rustnode requires. Keep aligned with `deps/v8/include/v8-version.h`
/// of the Node source pinned in `tools/node-pin.toml`.
pub const REQUIRED_V8_MAJOR: u32 = 15;
pub const REQUIRED_V8_MINOR: u32 = 2;

/// Returns an error when the linked V8 is not the pinned major/minor.
pub fn check_linked_v8() -> Result<(), String> {
    let version = v8::V8::get_version();
    let mut parts = version.split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    if major != REQUIRED_V8_MAJOR || minor != REQUIRED_V8_MINOR {
        return Err(format!(
            "linked V8 {version} does not match required {REQUIRED_V8_MAJOR}.{REQUIRED_V8_MINOR}"
        ));
    }
    Ok(())
}
