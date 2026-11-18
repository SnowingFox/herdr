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
