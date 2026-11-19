//! What a compression handle's library allocations account to.
//!
//! `node_zlib.cc`'s `CompressionStreamMemoryOwner` installs its own `zalloc` and
//! `zfree` on the `z_stream` (`src/node_zlib.cc:1349-1352`), stores each
//! allocation's real size in a header, and accumulates it into `zlib_memory_`.
//! `MemoryInfo` then reports `zlib_memory_ + unreported_allocations_` as
//! `Node / zlib_memory` (`:718-722`). The node is what
//! `test/pummel/test-heapdump-zlib.js` asserts appears only after the stream has
//! been written to, because nothing is allocated until `deflateInit2_` runs.
//!
//! This reproduces the accounting, not the numbers: the totals depend on which
//! compressor library made which allocation, and rustnode's zlib is libz-rs
//! rather than zlib, so a byte-for-byte match is not available. The oracle's own
//! total for the same script differs between its own runs and between
//! compressors (284,680 for gzip over `hello world`, 9,096 for the same bytes
//! through an inflate handle), so the honest thing is a real total from real
//! allocations. Every *class* size is pinned against the oracle instead — see
//! `handle.rs`.

use std::ffi::c_void;

/// A handle's running total of live library allocations.
///
/// `zalloc`/`zfree` are called by the compressor on whatever thread drives it and
/// receive nothing but the `opaque` pointer, so the counter has to be reachable
/// from a bare pointer and mutable through it. That rules out `Cell` unless the
/// tracker never moves, so it is always held behind a `Box` the handle owns.
pub(crate) struct MemoryOwner {
    /// Bytes currently handed out to the compressor, headers included.
    ///
    /// `AtomicUsize` rather than `Cell` so the two allocator callbacks can be
    /// `extern "C"` without an aliasing argument: they take `*mut c_void` and
    /// there may in principle be two of them live at once for one handle (a
    /// reset racing a write). Relaxed ordering is enough because the number is
    /// only ever read as a single value by a snapshot.
    live: std::sync::atomic::AtomicUsize,
}

impl MemoryOwner {
    pub(crate) fn new() -> Box<Self> {
        Box::new(Self {
            live: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// The `opaque` pointer the compressor hands back to `zalloc`/`zfree`.
    ///
    /// Taken from `&self` rather than the `Box`, so nothing here depends on how
    /// the owner is held; the caller keeps the `Box` alive for the stream's
    /// lifetime, which is what makes the address stable.
    pub(crate) fn opaque(&self) -> *mut c_void {
        (self as *const Self as *mut Self).cast()
    }

    /// Bytes currently held by the compressor.
    ///
    /// This is `zlib_memory_`: after a `close()` the compressor frees
    /// everything, so the total goes back to zero and the node disappears.
    pub(crate) fn bytes(&self) -> usize {
        self.live.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn add(&self, bytes: usize) {
        self.live
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    fn sub(&self, bytes: usize) {
        // Saturating: a library that frees something it did not allocate here
        // would otherwise wrap the total to a huge number and make the snapshot
        // report gigabytes for a single stream.
        let _ = self.live.fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |live| Some(live.saturating_sub(bytes)),
        );
    }
}

/// How many header bytes each allocation carries.
///
/// `reserveSizeAndAlign` is `max(sizeof(size_t), alignof(max_align_t))`, which is
/// 16 on x86-64, and the header stores the real size so `zfree` can subtract the
/// same number it added. The pointer handed back is past the header, so the
/// returned allocation keeps the alignment `alloc` gave it plus a multiple of 16.
const HEADER: usize = 16;

extern "C" fn zalloc(opaque: *mut c_void, items: u32, size: u32) -> *mut c_void {
    let Ok(total) = (items as usize).checked_mul(size as usize).ok_or(()) else {
        return std::ptr::null_mut();
    };
    if total == 0 {
        // zlib treats a zero-size request as satisfied by a null return.
        return std::ptr::null_mut();
    }
    let Some(payload) = total.checked_add(HEADER) else {
        return std::ptr::null_mut();
    };
    // SAFETY: `Layout` requires a non-zero size, checked above.
    let Ok(layout) = std::alloc::Layout::from_size_align(payload, HEADER) else {
        return std::ptr::null_mut();
    };
    // SAFETY: `payload` is non-zero, so the layout is valid.
    let block = unsafe { std::alloc::alloc(layout) };
    if block.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `block` points at `payload` writable bytes and `HEADER` is 16, so
    // the first `usize` is inside it.
    unsafe {
        block.cast::<usize>().write(payload);
    }
    if !opaque.is_null() {
        // SAFETY: `opaque` is the `MemoryOwner` of the handle whose `z_stream`
        // this allocator was installed on, and it outlives the stream.
        unsafe { &*opaque.cast::<MemoryOwner>() }.add(payload);
    }
    // The caller gets the bytes after the header, which is what lets `zfree`
    // find the size again from the pointer it is handed.
    // SAFETY: the header occupies the first `HEADER` bytes of the block.
    unsafe { block.add(HEADER) }.cast()
}

extern "C" fn zfree(opaque: *mut c_void, pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: `zalloc` returned a pointer `HEADER` bytes into a block whose first
    // `usize` holds that block's size, and only this pair of functions hands out
    // and takes back these pointers.
    let block = unsafe { pointer.cast::<u8>().sub(HEADER) };
    // SAFETY: as above; the size was written by `zalloc`.
    let payload = unsafe { block.cast::<usize>().read() };
    if !opaque.is_null() {
        // SAFETY: as in `zalloc`.
        unsafe { &*opaque.cast::<MemoryOwner>() }.sub(payload);
    }
    // SAFETY: `payload` is the size the matching `zalloc` allocated with, and
    // `HEADER` is the alignment it used.
    if let Ok(layout) = std::alloc::Layout::from_size_align(payload, HEADER) {
        unsafe { std::alloc::dealloc(block, layout) };
    }
}

/// Installs this owner's allocator on `stream`.
///
/// `src/node_zlib.cc:1349` does the same three assignments to the `z_stream` the
/// context owns, once, before any `deflateInit2_`/`inflateInit2_` call. The
/// compressor keeps them for its own lifetime, so they only have to be set once.
pub(crate) fn install(stream: &mut libz_rs_sys::z_stream, owner: &MemoryOwner) {
    stream.zalloc = Some(zalloc);
    stream.zfree = Some(zfree);
    stream.opaque = owner.opaque();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allocation_is_counted_with_its_header_and_released_on_free() {
        let owner = MemoryOwner::new();
        let pointer = zalloc(owner.opaque(), 100, 1);
        assert!(!pointer.is_null());
        assert_eq!(owner.bytes(), 100 + HEADER);
        zfree(owner.opaque(), pointer);
        assert_eq!(owner.bytes(), 0);
    }

    #[test]
    fn an_aligned_pointer_round_trips_through_the_header() {
        let owner = MemoryOwner::new();
        let pointer = zalloc(owner.opaque(), 1, 1);
        assert!(!pointer.is_null());
        // The payload keeps the alignment the header size gives it, which is what
        // the compressor relies on for its own `max_align_t` fields.
        assert_eq!(pointer as usize % HEADER, 0);
        zfree(owner.opaque(), pointer);
        assert_eq!(owner.bytes(), 0);
    }

    #[test]
    fn a_zero_size_request_is_null_and_costs_nothing() {
        let owner = MemoryOwner::new();
        assert!(zalloc(owner.opaque(), 0, 4).is_null());
        assert!(zalloc(owner.opaque(), 4, 0).is_null());
        assert_eq!(owner.bytes(), 0);
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        let owner = MemoryOwner::new();
        zfree(owner.opaque(), std::ptr::null_mut());
        assert_eq!(owner.bytes(), 0);
    }

    #[test]
    fn a_free_without_a_matching_allocation_cannot_underflow_the_total() {
        // Reached when a library frees memory this owner never accounted for: the
        // total must stay a plausible byte count rather than wrapping.
        let owner = MemoryOwner::new();
        owner.sub(4096);
        assert_eq!(owner.bytes(), 0);
    }
}
