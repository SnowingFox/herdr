//! Pins the V8 build rustnode links against.
//!
//! rustnode does not replace the JavaScript engine. It links the same V8 major
//! version Node 28 ships so that `v8.serialize`, real `vm` contexts, GC timing
//! and stack formatting behave identically.

pub use v8;

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

/// Runs the tasks V8 has queued for this isolate on the process' platform.
///
/// Returns whether any task ran. `wait_for_work` is false throughout: the queue
/// is drained from the event loop's per-iteration checkpoint, so blocking there
/// would stall the loop whenever nothing was posted.
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
