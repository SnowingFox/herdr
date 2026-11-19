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
    /// `--debug-arraybuffer-allocations`: every live backing store, by address.
    ///
    /// `DebuggingArrayBufferAllocator::allocations_`
    /// (`src/api/environment.cc:171`), which the flag exists for. Node's copy is
    /// an `unordered_map` guarded by a `Mutex`; the mutex is here too because a
    /// backing store's last reference can be dropped on another thread, which is
    /// the same reason the counter is atomic. `None` in the default build, so a
    /// process without the flag pays no lock and allocates nothing.
    tracked: Option<std::sync::Mutex<std::collections::HashMap<usize, usize>>>,
}

impl Counter {
    fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
            tracked: None,
        }
    }

    /// A counter that also records every live address.
    fn debugging() -> Self {
        Self {
            live: AtomicUsize::new(0),
            tracked: Some(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn grow(&self, length: usize) {
        self.live.fetch_add(length, Ordering::Relaxed);
    }

    fn shrink(&self, length: usize) {
        self.live.fetch_sub(length, Ordering::Relaxed);
    }

    /// Records a new allocation, on the debug path.
    ///
    /// Returns `false` when the address is already live, which is the condition
    /// `RegisterPointerInternal`'s `CHECK_EQ(allocations_.count(data), 0)` turns
    /// into an abort. A double registration means one backing store was handed out
    /// twice, and continuing would let the second free release memory the first
    /// still owns.
    fn track(&self, address: usize, length: usize) -> bool {
        let Some(tracked) = self.tracked.as_ref() else {
            return true;
        };
        let Ok(mut tracked) = tracked.lock() else {
            // A poisoned lock means another thread already aborted on a defect of
            // the same allocator; reporting the abort here is the honest answer.
            return false;
        };
        tracked.insert(address, length).is_none()
    }

    /// Removes an allocation, on the debug path.
    ///
    /// Returns `false` when the address was not live, `UnregisterPointerInternal`'s
    /// `CHECK_NE(it, allocations_.end())` — a free of something never allocated, or
    /// of the same block twice.
    fn untrack(&self, address: usize, length: usize) -> bool {
        let Some(tracked) = self.tracked.as_ref() else {
            return true;
        };
        let Ok(mut tracked) = tracked.lock() else {
            return false;
        };
        let Some(recorded) = tracked.get(&address).copied() else {
            return false;
        };
        // `if (size > 0) CHECK_EQ(it->second, size)`: V8 must free a block with the
        // length it allocated it with, because that length is what `dealloc` needs
        // for the layout. Node's `CHECK` runs *before* `allocations_.erase(it)`, so
        // a mismatched free leaves the entry in place and aborts; this reports the
        // same refusal without removing it, so the caller's abort is the only
        // difference.
        if length != 0 && recorded != length {
            return false;
        }
        tracked.remove(&address);
        true
    }

    /// Whether every allocation was released.
    ///
    /// `~DebuggingArrayBufferAllocator`'s `CHECK(allocations_.empty())`. The
    /// equivalent check cannot run at this process's exit: `terminate` calls
    /// `std::process::exit`, which destroys no Rust values and so never drops the
    /// isolate, and V8 still owns whatever backing stores are live at that point.
    /// Running the check there reported every program as leaking, so the teardown
    /// half of the flag is a stated gap rather than a false alarm — see
    /// `rn-compat`'s notes for `--debug-arraybuffer-allocations`.
    #[cfg(test)]
    fn all_released(&self) -> bool {
        match self.tracked.as_ref() {
            Some(tracked) => tracked.lock().map(|map| map.is_empty()).unwrap_or(false),
            None => true,
        }
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
    if !handle.track(pointer as usize, length) {
        abort_double_registration();
    }
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
    if !handle.track(pointer as usize, length) {
        abort_double_registration();
    }
    pointer.cast()
}

unsafe extern "C" fn free(handle: &Counter, data: *mut c_void, length: usize) {
    if data.is_null() {
        return;
    }
    if !handle.untrack(data as usize, length) {
        abort_bad_free();
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

/// `RegisterPointerInternal`'s `CHECK_EQ(allocations_.count(data), 0)`.
///
/// Only reachable with `--debug-arraybuffer-allocations`. Node's `CHECK` aborts
/// the process with a message naming the failed condition, and so does this:
/// printing a warning and continuing would let a second owner free memory the
/// first still holds, which is the corruption the flag exists to find early.
fn abort_double_registration() -> ! {
    rn_core_abort(
        "--debug-arraybuffer-allocations: an ArrayBuffer backing store was registered twice",
    )
}

/// `UnregisterPointerInternal`'s `CHECK_NE(...)` and `CHECK_EQ(it->second, size)`.
fn abort_bad_free() -> ! {
    rn_core_abort(
        "--debug-arraybuffer-allocations: a backing store was freed that was not \
         registered, or freed with a different length than it was allocated with",
    )
}

/// Stops the process the way a failed `CHECK` does.
///
/// `abort()` rather than a panic: this crate is a C callback, the process state
/// (a half-freed backing store) is what the abort reports, and a Rust panic
/// unwinding out of an `extern "C"` function is undefined.
fn rn_core_abort(message: &str) -> ! {
    rn_core_log_abort(message);
    std::process::abort()
}

/// Writes the message before `abort`, so a redirected stderr names the defect.
fn rn_core_log_abort(message: &str) {
    crate::hook_slot::write_stderr(&format!(
        "# Fatal error in ArrayBuffer allocator\n# {message}\n"
    ));
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
    with_array_buffer_allocator(params, false)
}

/// The same, plus `DebuggingArrayBufferAllocator`'s live-address bookkeeping.
///
/// This is `--debug-arraybuffer-allocations`: `ArrayBufferAllocator::Create`
/// picks the debugging subtype when `per_process::cli_options->
/// debug_arraybuffer_allocations` is set (`src/api/environment.cc:196`), and it
/// exists so a backing store that is freed twice, freed with the wrong length, or
/// never freed at all stops the process instead of corrupting the heap quietly.
///
/// `debugging` is the CLI's own record rather than a store lookup: the allocator
/// is installed when the isolate is created, which is before
/// `internalBinding('options')` exists.
pub fn with_debugging_array_buffer_allocator(params: v8::CreateParams) -> v8::CreateParams {
    with_array_buffer_allocator(params, true)
}

fn with_array_buffer_allocator(params: v8::CreateParams, debugging: bool) -> v8::CreateParams {
    let counter = Arc::new(if debugging {
        Counter::debugging()
    } else {
        Counter::new()
    });
    CURRENT.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&counter)));
    let handle = Arc::into_raw(counter);
    // SAFETY: `VTABLE` is a `static`, so it outlives every isolate, and the
    // `Arc` behind `handle` is released only in `drop_counter`.
    let allocator = unsafe { v8::new_rust_allocator(handle, &VTABLE) };
    params.array_buffer_allocator(allocator)
}

/// Whether every backing store this thread's isolate handed out was released.
///
/// `~DebuggingArrayBufferAllocator`'s `CHECK(allocations_.empty())`, exposed for
/// the unit tests rather than for the CLI: see [`Counter::all_released`] for why
/// the real teardown cannot make this check.
#[cfg(test)]
#[must_use]
pub fn all_array_buffers_released() -> bool {
    CURRENT.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_none_or(|counter| counter.all_released())
    })
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

    /// The debug allocator records and releases addresses, which is the whole of
    /// what `--debug-arraybuffer-allocations` adds.
    ///
    /// The default allocator must answer `true` throughout, or a process that did
    /// not ask for the flag would be told it leaked.
    #[test]
    fn the_debugging_counter_tracks_each_address_and_the_default_one_does_not() {
        let debugging = Counter::debugging();
        assert!(debugging.all_released());

        let pointer = exercise(&debugging, 4096, false);
        let address = pointer as usize;
        assert!(!debugging.all_released(), "a live block must be recorded");
        // The same address recorded twice is `RegisterPointerInternal`'s
        // `CHECK_EQ(allocations_.count(data), 0)`, which aborts in the allocator.
        assert!(
            !debugging.track(address, 4096),
            "registering a live address twice must be refused"
        );
        // A free of an address that was never registered is
        // `UnregisterPointerInternal`'s `CHECK_NE`.
        assert!(
            !debugging.untrack(address + 1, 4096),
            "freeing an unregistered address must be refused"
        );
        // A free with the wrong length is the `CHECK_EQ(it->second, size)` in the
        // same function.
        assert!(
            !debugging.untrack(address, 8192),
            "freeing with the wrong length must be refused"
        );
        // The address is still registered after those refusals, because the
        // length check does not remove it.
        assert!(!debugging.all_released());

        unsafe { free(&debugging, pointer, 4096) };
        assert!(debugging.all_released(), "the release must be recorded");

        let plain = Counter::new();
        let pointer = exercise(&plain, 4096, false);
        assert!(
            plain.all_released(),
            "the default allocator records nothing"
        );
        assert!(plain.track(pointer as usize, 4096));
        unsafe { free(&plain, pointer, 4096) };
        assert_eq!(plain.live_bytes(), 0);
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
