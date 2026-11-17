//! Worker thread stack sizing and V8 stack-limit calculation.
//!
//! Node's worker path (`src/node_worker.cc`) does both:
//! * chooses the worker thread's stack size from `resourceLimits.stackSizeMb`
//!   (or a 4 MiB default), and
//! * computes a stack-limit address from the current stack top and the chosen
//!   size, leaving a 192 KiB buffer for embedder/native frames.

/// The default worker stack size (`Worker::stack_size_`).
const DEFAULT_STACK_SIZE_BYTES: usize = 4 * 1024 * 1024;
/// Extra room left for native frames (`Worker::kStackBufferSize`).
const STACK_BUFFER_SIZE_BYTES: usize = 192 * 1024;
const MB: f64 = 1024.0 * 1024.0;

/// The worker thread stack size in bytes for this request.
#[must_use]
pub(crate) fn stack_size_bytes(resource_limits: [f64; 4]) -> usize {
    let requested = resource_limits[crate::K_STACK_SIZE_MB as usize];
    if requested > 0.0 {
        ((requested * MB) as usize).max(STACK_BUFFER_SIZE_BYTES)
    } else {
        DEFAULT_STACK_SIZE_BYTES
    }
}

/// The V8 stack-limit address for the current worker thread.
///
/// This mirrors Node's `stack_top - (stack_size - kStackBufferSize)`.
#[must_use]
pub(crate) fn stack_limit(resource_limits: [f64; 4]) -> *mut u32 {
    let stack_size = stack_size_bytes(resource_limits);
    let marker = 0u8;
    let stack_top = (&marker as *const u8) as usize;
    let usable = stack_size.saturating_sub(STACK_BUFFER_SIZE_BYTES);
    stack_top.saturating_sub(usable) as *mut u32
}
