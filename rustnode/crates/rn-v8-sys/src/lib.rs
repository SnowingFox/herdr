//! Pins the V8 build rustnode links against.
//!
//! rustnode does not replace the JavaScript engine. It links the same V8 major
//! version Node 28 ships so that `v8.serialize`, real `vm` contexts, GC timing
//! and stack formatting behave identically.

pub use v8;

unsafe extern "C" {
    fn rn_v8_sys__set_stack_limit(isolate: v8::UnsafeRawIsolatePtr, stack_limit: usize);
    fn rn_v8_sys__measure_memory(
        isolate: v8::UnsafeRawIsolatePtr,
        context: *const std::ffi::c_void,
        resolver: *const std::ffi::c_void,
        mode: i32,
        execution: i32,
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

/// `v8::MeasureMemoryMode`, from `v8-statistics.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasureMemoryMode {
    Summary = 0,
    Detailed = 1,
}

/// `v8::MeasureMemoryExecution`, from `v8-statistics.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasureMemoryExecution {
    Default = 0,
    Eager = 1,
    Lazy = 2,
}

/// Enqueues a memory measurement whose result resolves `resolver`'s promise.
///
/// This is `v8::MeasureMemoryDelegate::Default(isolate, context, resolver, mode)`
/// followed by `isolate->MeasureMemory(std::move(delegate), execution)`, both of
/// which the `v8` crate leaves unbound. The whole sequence runs in
/// `src/measure_memory.cc` so the `std::unique_ptr` the delegate arrives in never
/// crosses the FFI boundary.
///
/// The return value is V8's: `false` means the request was not enqueued. Node
/// ignores it, and so does `vm.js`; the promise is the observable outcome either
/// way, and it rejects through V8 if the measurement cannot complete.
///
/// # Safety
///
/// `context` must be the isolate's current context and `resolver` a resolver
/// created in it, both alive for the duration of the call. V8 keeps the context
/// and the resolver's promise, not a borrow of either.
pub unsafe fn measure_memory(
    scope: &v8::PinScope<'_, '_>,
    context: v8::Local<'_, v8::Context>,
    resolver: v8::Local<'_, v8::PromiseResolver>,
    mode: MeasureMemoryMode,
    execution: MeasureMemoryExecution,
) -> bool {
    let isolate: &v8::Isolate = scope;

    // A `v8::Local` is one pointer, which is why it can be handed over as one.
    // This is the same reinterpretation `rn-napi`'s `values.rs` makes for
    // `napi_value`, and for the same reason: the v8 crate keeps `Local`'s only
    // field private, and `ptr_to_local` in its `support.h` is the C++ spelling
    // of exactly this copy.
    //
    // SAFETY: `Local<T>` is `#[repr(C)]` over a single `NonNull<T>`, so copying
    // those bytes out yields the pointer V8's own `Local` holds.
    let context = unsafe { std::mem::transmute_copy::<_, *const std::ffi::c_void>(&context) };
    // SAFETY: as above.
    let resolver = unsafe { std::mem::transmute_copy::<_, *const std::ffi::c_void>(&resolver) };

    // SAFETY: the caller guarantees both handles are live in `scope`'s isolate,
    // and `as_raw_isolate_ptr` is the v8 crate's raw-isolate escape hatch.
    unsafe {
        rn_v8_sys__measure_memory(
            isolate.as_raw_isolate_ptr(),
            context,
            resolver,
            mode as i32,
            execution as i32,
        )
    }
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
