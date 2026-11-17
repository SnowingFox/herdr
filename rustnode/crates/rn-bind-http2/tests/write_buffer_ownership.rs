//! A write buffer must point into the allocation that outlives the write.
//!
//! `rn_uv::stream::buffer_from` exists because the obvious spelling of "hand a
//! `Vec` to libuv" is a use-after-free:
//!
//! ```ignore
//! let buffer = uv_buf_t { base: bytes.as_ptr().cast(), len: bytes.len() };
//! queue_write_unowned(stream, vec![buffer], len, vec![bytes.into_boxed_slice()]);
//! ```
//!
//! `into_boxed_slice` shrinks the allocation to `len`, and `RawVec` implements
//! that shrink as `realloc` whenever `capacity != len`. A pointer taken from the
//! `Vec` before the box exists therefore names a block that may already be
//! freed by the time libuv writes from it. That was the real defect: the whole
//! HTTP/2 frame path (`session::write_to_stream`) took the address first, so
//! every frame was written out of freed memory.
//!
//! # Why this test needs its own allocator
//!
//! It cannot be observed with the system allocator. glibc answers a shrinking
//! `realloc` in place — measured across 500 varied size pairs, zero moves — so
//! the stale pointer stays valid and the write silently produces correct bytes
//! on a machine that is only "not allowed" to do this. valgrind reports it
//! because it models the block as freed regardless of what glibc returns;
//! nothing a test can do at the protocol level reproduces that on glibc alone.
//!
//! So the test installs a moving allocator: every shrink really does move, and
//! the freed block is overwritten before it is returned to the system. Under
//! that allocator the defect becomes a wrong byte in the buffer, which is an
//! ordinary assertion.
//!
//! # What this covers
//!
//! The shared primitive: that the `uv_buf_t` a caller hands to libuv points into
//! the `Box<[u8]>` that the same call returns as the write's `owned` storage.
//! Every write site that keeps its bytes alive (`session::write_to_stream`,
//! `TLSWrap`'s `flush`, `StreamPipe`'s `write_to_sink`, and `writev`'s string
//! chunks) now goes through it, so this is the one place the invariant can be
//! pinned. `a_pointer_taken_before_the_box_is_caught` is the negative control:
//! it spells out the old order and asserts this allocator turns it into a
//! visible corruption, which is what proves the test would fail on the bug.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Set by the allocator on every shrink, so a test can prove the move
    /// happened rather than assert against an allocator that quietly kept the
    /// block. Thread-local because cargo runs the tests in this file in parallel
    /// threads against one global allocator, and a shared flag would let one
    /// test observe another's shrink.
    static SHRINK_MOVED: Cell<bool> = const { Cell::new(false) };
    /// Whether the block being freed right now is one this allocator moved, which
    /// is the only case where poisoning is ours to do.
    static IN_SHRINK: Cell<bool> = const { Cell::new(false) };
}

/// Overwrites a block before freeing it, and moves on every shrink.
///
/// Both halves are needed. Moving is what makes a stale pointer point somewhere
/// else; overwriting is what makes reading through it observably wrong instead
/// of accidentally right, because a freed block's contents are undefined and
/// often still the old bytes.
struct MovingShrink;

const POISON: u8 = 0xDD;

unsafe impl GlobalAlloc for MovingShrink {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is a valid allocation layout, delegated unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if !IN_SHRINK.with(|flag| flag.replace(false)) {
            // SAFETY: `pointer` came from this allocator with `layout`.
            unsafe { System.dealloc(pointer, layout) };
            return;
        }
        // A shrunk-away tail is exactly what a stale write buffer points at, so
        // poison it before the allocator can hand it to anyone else.
        // SAFETY: `pointer` still owns `layout.size()` bytes at this point.
        unsafe { std::ptr::write_bytes(pointer, POISON, layout.size()) };
        // SAFETY: as above; the block is ours to release.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            // SAFETY: delegated unchanged; a grow is not the shape under test.
            return unsafe { System.realloc(pointer, layout, new_size) };
        }
        SHRINK_MOVED.with(|flag| flag.set(true));
        let new_layout = Layout::from_size_align(new_size, layout.align())
            .expect("a shrink keeps the alignment, so this layout is valid");
        // SAFETY: `new_layout` is valid and this is a fresh allocation.
        let moved = unsafe { System.alloc(new_layout) };
        if moved.is_null() {
            return moved;
        }
        // SAFETY: `new_size < layout.size()`, so the old block holds at least
        // `new_size` bytes, and `moved` has room for them.
        unsafe { std::ptr::copy_nonoverlapping(pointer, moved, new_size) };
        IN_SHRINK.with(|flag| flag.set(true));
        // SAFETY: `pointer` is still the live old block with its own layout.
        unsafe { self.dealloc(pointer, layout) };
        moved
    }
}

#[global_allocator]
static ALLOCATOR: MovingShrink = MovingShrink;

/// The `Vec` shapes that reach a write site with spare capacity.
fn spare_capacity_vecs() -> Vec<(&'static str, Vec<u8>)> {
    // `send_pending_data` and `TLSWrap::pending_output` grow with
    // `extend_from_slice`, which always over-reserves.
    let mut extended = Vec::new();
    for chunk in [1u8, 2, 3] {
        extended.extend_from_slice(&[chunk; 10]);
    }
    // `codec::write` reserves a worst-case encoded size and fills less.
    let mut reserved = Vec::with_capacity(100);
    reserved.extend_from_slice(&[7u8; 30]);
    vec![("extend_from_slice", extended), ("with_capacity", reserved)]
}

#[test]
fn a_pointer_taken_before_the_box_is_caught() {
    // The negative control. This is the exact order the defect used, and the
    // assertion is that it produces a buffer whose bytes are not the payload —
    // i.e. that this allocator makes the bug observable at all. If this ever
    // starts passing the payload through, the other test no longer proves
    // anything.
    for (shape, bytes) in spare_capacity_vecs() {
        let expected = bytes.clone();
        SHRINK_MOVED.with(|flag| flag.set(false));
        let buffer = rn_uv::sys::uv_buf_t {
            base: bytes.as_ptr().cast_mut().cast(),
            len: bytes.len(),
        };
        let _owned = bytes.into_boxed_slice();
        assert!(
            SHRINK_MOVED.with(|flag| flag.get()),
            "{shape}: the allocator did not move on shrink, so this control proves nothing"
        );
        // SAFETY: this is deliberately reading a freed block, which is the whole
        // point of the control; it stays inside one allocation's old extent.
        let seen = unsafe { std::slice::from_raw_parts(buffer.base.cast::<u8>(), buffer.len) };
        assert_ne!(
            seen,
            &expected[..],
            "{shape}: the stale pointer still read the payload, so the defect \
             would slip past this test"
        );
    }
}

#[test]
fn the_write_buffer_points_into_its_owned_allocation() {
    for (shape, bytes) in spare_capacity_vecs() {
        let expected = bytes.clone();
        SHRINK_MOVED.with(|flag| flag.set(false));
        let (buffer, owned) = rn_uv::stream::buffer_from(bytes);
        assert!(
            SHRINK_MOVED.with(|flag| flag.get()),
            "{shape}: expected a moving shrink"
        );

        // The two facts a write depends on: the buffer points at the allocation
        // the completion keeps alive, and that allocation still holds the bytes.
        assert_eq!(
            buffer.base.cast::<u8>(),
            owned.as_ptr().cast_mut(),
            "{shape}: the buffer must point at the box's own allocation"
        );
        assert_eq!(
            buffer.len,
            owned.len(),
            "{shape}: length must match the box"
        );
        // SAFETY: `buffer.base` is `owned.as_ptr()` and `buffer.len` is its
        // length, just asserted.
        let seen = unsafe { std::slice::from_raw_parts(buffer.base.cast::<u8>(), buffer.len) };
        assert_eq!(
            seen,
            &expected[..],
            "{shape}: the buffer must still hold the payload"
        );
    }
}
