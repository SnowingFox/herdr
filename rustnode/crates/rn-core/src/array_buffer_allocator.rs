//! Counting `ArrayBuffer` allocator.
//!
//! Node reports `process.memoryUsage().arrayBuffers` from
//! `array_buffer_allocator->total_mem_usage()`
//! (`src/node_process_methods.cc:222-250`), which only means anything because
//! the isolate it belongs to was created with a `NodeArrayBufferAllocator` that
//! counts every allocation and subtracts every free. The isolate V8 builds
//! itself by default is created with `ArrayBuffer::Allocator::NewDefaultAllocator`
//! — a plain `malloc`/`free` pair with no counter at all — so a runtime that
//! instantiates an isolate without supplying one has no figure to report and can
//! only hardcode a zero.
//!
//! This module supplies one. It is a `v8::ArrayBuffer::Allocator` implemented
//! through `v8::new_rust_allocator` and its `RustAllocatorVtable`, so V8 routes
//! every backing-store allocation and free through [`allocate_zeroed`],
//! [`allocate_uninitialized`] and [`free`] here.
//!
//! # The figure is live memory, not a high-water mark
//!
//! `arrayBuffers` is what is allocated *right now*. `free` subtracts the length
//! V8 passes it, which is the same length it passed to the matching
//! `Allocate`/`AllocateUninitialized` (`v8-array-buffer.h:169-173`: "That memory
//! is guaranteed to be previously allocated by `Allocate`"), so a buffer that is
//! collected brings the figure down. A counter that only ever adds would report
//! a plausible-looking number that never falls, which is why the tests measure
//! reclamation and not only growth.
//!
//! # One counter per isolate, read through the thread
//!
//! Node gives every `Environment` — the main thread and each worker — its own
//! allocator, and a worker's `memoryUsage().arrayBuffers` reports its own
//! buffers rather than the process total. Measured on the pinned oracle: a main
//! thread holding 64 MiB reports `64.13` while a fresh worker reports `0.13`.
//! So the counter is created per isolate, not shared process-wide.
//!
//! The counter is found when it is *read*, not when it is allocated. The
//! allocator instance keeps its own `Arc<Counter>`, so a backing store whose last
//! reference is dropped on another thread still decrements the counter that owns
//! it. Only [`live_array_buffer_bytes`] goes through thread-local state, and it
//! is called from a binding on the isolate's own thread, where at most one
//! isolate is current.
//!
//! # `external` is not touched
//!
//! V8 accounts memory obtained from an isolate's array-buffer allocator as
//! external memory itself (`v8-array-buffer.h:119-127`), which is why rustnode's
//! `external` already grew with `new Uint8Array(65536)` while `arrayBuffers`
//! stayed at zero. Supplying an allocator changes which implementation V8 calls,
//! not whether it counts the result, so this module deliberately makes no
//! `AdjustAmountOfExternalAllocatedMemory` call: doing so would count the same
//! bytes a second time and make the two figures disagree by the size of every
//! live buffer.
//!
//! # Why this compiles
//!
//! `v8::new_rust_allocator` is gated on `#[cfg(not(feature = "v8_enable_sandbox"))]`.
//! The gate is not on in this workspace: `cargo tree -e features -p rn-cli -i v8`
//! enables only `default` and `use_custom_libcxx`, and the prebuilt
//! `librusty_v8.a` is downloaded without the `_sandbox` suffix, whose build
//! arguments (`v8-152.2.0/build.rs:415-433`) set `v8_enable_sandbox=false` and
//! `v8_enable_pointer_compression=false`. A sandboxed build has no `Allocate` /
//! `Free` seam to hook, so enabling that feature turns this module's use of
//! `new_rust_allocator` into a compile error rather than a silent fallback.

use std::alloc::{alloc, alloc_zeroed, dealloc, Layout};
use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rn_v8_sys::v8;

/// Alignment of every backing store handed to V8.
///
/// V8's own default allocator is `malloc`/`free`, which returns 16-byte aligned
/// memory on x86-64, and V8 may use the alignment for vectorised copies. The
/// same alignment is used on the way out, because `dealloc` has to be given the
/// layout the allocation was made with.
const ALIGN: usize = 16;

/// Live bytes allocated through one isolate's allocator.
///
/// `Relaxed` is enough because the value is a statistic: `Allocate` and `Free`
/// for one backing store both go through this counter, and a reader only needs
/// each individual add or subtract to be atomic, not ordered against anything
/// else.
#[derive(Debug)]
pub struct Counter {
    live: AtomicUsize,
}

impl Counter {
    fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
        }
    }

    fn grow(&self, length: usize) {
        self.live.fetch_add(length, Ordering::Relaxed);
    }

    fn shrink(&self, length: usize) {
        self.live.fetch_sub(length, Ordering::Relaxed);
    }

    /// Bytes currently allocated through this counter.
    pub fn live_bytes(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }
}

/// The layout an allocation of `length` bytes is made and released with.
///
/// A zero-length request is still a real allocation to V8 (`Free` is called with
/// the same zero length), and `Layout` rejects a size of zero, so the size is
/// floored at one byte rather than the pointer being a special case: one byte of
/// slack is cheaper than a second code path that can disagree with this one.
fn layout_for(length: usize) -> Option<Layout> {
    Layout::from_size_align(length.max(1), ALIGN).ok()
}

unsafe extern "C" fn allocate_zeroed(handle: &Counter, length: usize) -> *mut c_void {
    let Some(layout) = layout_for(length) else {
        return std::ptr::null_mut();
    };
    // SAFETY: `layout` has a non-zero size, which is what `alloc_zeroed`
    // requires.
    let pointer = unsafe { alloc_zeroed(layout) };
    if pointer.is_null() {
        return std::ptr::null_mut();
    }
    handle.grow(length);
    pointer.cast()
}

unsafe extern "C" fn allocate_uninitialized(handle: &Counter, length: usize) -> *mut c_void {
    let Some(layout) = layout_for(length) else {
        return std::ptr::null_mut();
    };
    // SAFETY: as above.
    let pointer = unsafe { alloc(layout) };
    if pointer.is_null() {
        return std::ptr::null_mut();
    }
    handle.grow(length);
    pointer.cast()
}

unsafe extern "C" fn free(handle: &Counter, data: *mut c_void, length: usize) {
    if data.is_null() {
        return;
    }
    let Some(layout) = layout_for(length) else {
        // Unreachable for a length this module allocated, since the same
        // computation succeeded then. Leaking is the only alternative to
        // releasing with a layout that may not match, and it cannot happen.
        return;
    };
    // SAFETY: `data` came from `alloc`/`alloc_zeroed` with this same layout, and
    // V8 guarantees the length is the one it allocated.
    unsafe { dealloc(data.cast(), layout) };
    handle.shrink(length);
}

unsafe extern "C" fn drop_counter(handle: *const Counter) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is the `Arc::into_raw` produced by `with_counted_array_buffer_allocator`,
    // and V8 calls this exactly once, when the allocator itself is destroyed.
    drop(unsafe { Arc::from_raw(handle) });
}

static VTABLE: v8::RustAllocatorVtable<Counter> = v8::RustAllocatorVtable {
    allocate: allocate_zeroed,
    allocate_uninitialized,
    free,
    drop: drop_counter,
};

thread_local! {
    /// The counter belonging to this thread's isolate.
    ///
    /// The allocator owns its `Arc` too; this is a second reference kept only so
    /// a binding can read the figure without holding the isolate.
    static CURRENT: RefCell<Option<Arc<Counter>>> = const { RefCell::new(None) };
}

/// Returns `params` with a counting allocator installed.
///
/// Every isolate in the process has to be created through this — the main one in
/// `rn-cli` and each worker's in `rn-bind-worker` — or its `arrayBuffers` is a
/// zero with nothing behind it.
pub fn with_counted_array_buffer_allocator(params: v8::CreateParams) -> v8::CreateParams {
    let counter = Arc::new(Counter::new());
    CURRENT.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&counter)));
    let handle = Arc::into_raw(counter);
    // SAFETY: `VTABLE` is a `static`, so it outlives every isolate, and the
    // `Arc` behind `handle` is released only in `drop_counter`.
    let allocator = unsafe { v8::new_rust_allocator(handle, &VTABLE) };
    params.array_buffer_allocator(allocator)
}

/// Bytes this thread's isolate currently holds in `ArrayBuffer` backing stores.
///
/// Reports zero when the isolate was not created through
/// [`with_counted_array_buffer_allocator`], which is the honest answer: nothing counted it.
pub fn live_array_buffer_bytes() -> usize {
    CURRENT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(0, |counter| counter.live_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three vtable entries as V8 calls them: allocate, allocate, free.
    fn exercise(counter: &Counter, length: usize, zeroed: bool) -> *mut c_void {
        if zeroed {
            unsafe { allocate_zeroed(counter, length) }
        } else {
            unsafe { allocate_uninitialized(counter, length) }
        }
    }

    #[test]
    fn a_live_allocation_is_counted_and_a_freed_one_is_not() {
        // Direction first: `arrayBuffers` is live memory, so the counter has to
        // fall when a buffer is released. A counter that only ever grew would
        // pass the growth half of this test and fail here.
        let counter = Counter::new();
        assert_eq!(counter.live_bytes(), 0);

        let pointer = exercise(&counter, 4096, false);
        assert!(!pointer.is_null());
        assert_eq!(counter.live_bytes(), 4096);

        unsafe { free(&counter, pointer, 4096) };
        assert_eq!(counter.live_bytes(), 0);
    }

    #[test]
    fn zeroed_and_uninitialized_allocations_are_both_counted() {
        let counter = Counter::new();
        let zeroed = exercise(&counter, 1024, true);
        let uninitialized = exercise(&counter, 2048, false);
        assert_eq!(counter.live_bytes(), 3072);

        unsafe {
            free(&counter, zeroed, 1024);
            free(&counter, uninitialized, 2048);
        }
        assert_eq!(counter.live_bytes(), 0);
    }

    #[test]
    fn a_zero_length_allocation_round_trips() {
        // V8 can ask for zero bytes and will call `Free` with the same length,
        // so the pair has to be symmetric rather than special-cased on one side.
        let counter = Counter::new();
        let pointer = exercise(&counter, 0, true);
        assert!(!pointer.is_null());
        assert_eq!(counter.live_bytes(), 0);
        unsafe { free(&counter, pointer, 0) };
        assert_eq!(counter.live_bytes(), 0);
    }

    #[test]
    fn a_zeroed_allocation_is_actually_zero() {
        // `Allocate` promises zeroed memory and `AllocateUninitialized` does not.
        // Returning uninitialized memory from the zeroed path would hand
        // JavaScript a buffer with data in it.
        let counter = Counter::new();
        let pointer = exercise(&counter, 256, true);
        assert!(!pointer.is_null());
        let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), 256) };
        assert!(bytes.iter().all(|byte| *byte == 0));
        unsafe { free(&counter, pointer, 256) };
    }

    #[test]
    fn the_live_total_tracks_many_interleaved_allocations() {
        let counter = Counter::new();
        let pointers: Vec<*mut c_void> = (0..32)
            .map(|_| exercise(&counter, 1 << 16, false))
            .collect();
        assert_eq!(counter.live_bytes(), 32 << 16);
        for (index, pointer) in pointers.into_iter().enumerate() {
            if index % 2 == 0 {
                unsafe { free(&counter, pointer, 1 << 16) };
            }
        }
        assert_eq!(counter.live_bytes(), 16 << 16);
    }
}
