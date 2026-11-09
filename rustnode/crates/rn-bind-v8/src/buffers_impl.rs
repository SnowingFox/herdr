//! The three statistics buffers shared with JavaScript.
//!
//! Node's `BindingData` holds one `AliasedFloat64Array` per buffer, exposes the
//! typed array to the realm, and writes into the same bytes from the
//! `update*Buffer()` functions. `lib/v8.js` then reads the numbers back out by
//! index. The element type and the length are part of that contract: a
//! `Uint32Array` of the same byte length would put four fields where the
//! JavaScript layer expects eight, and a buffer one element short would make the
//! last index read `undefined`.
//!
//! Node keeps these in per-realm binding data and reaches them through the
//! receiver. The functions here take no receiver — `lib/v8.js` calls
//! `updateHeapStatisticsBuffer()` as a bare function — so the buffers live in
//! thread-local storage, which is where Node's realm-scoped state ends up too:
//! one isolate per thread, one realm per thread.
//!
//! The handles are `AliasedUint8Array` because that type already solves the
//! hard part: it allocates a V8-owned backing store, keeps a `Global` alive so
//! V8 cannot collect it, and reads and writes the same bytes the typed array
//! sees. What it does not have is a `Float64Array` element type, which is why
//! [`Buffers`] builds the typed arrays itself and keeps the aliasing handle for
//! the writes.

use std::cell::RefCell;

use rn_core::{AliasedUint8Array, Element};
use rn_v8_sys::v8;

use crate::constants::{
    HEAP_CODE_STATISTICS_INDEXES, HEAP_SPACE_STATISTICS_INDEXES, HEAP_STATISTICS_INDEXES,
};

/// `kHeapStatisticsPropertiesCount`: one element per `HEAP_STATISTICS_INDEXES`
/// entry.
pub const HEAP_STATISTICS_LENGTH: usize = HEAP_STATISTICS_INDEXES.len();

/// `kHeapSpaceStatisticsPropertiesCount`.
pub const HEAP_SPACE_STATISTICS_LENGTH: usize = HEAP_SPACE_STATISTICS_INDEXES.len();

/// `kHeapCodeStatisticsPropertiesCount`.
pub const HEAP_CODE_STATISTICS_LENGTH: usize = HEAP_CODE_STATISTICS_INDEXES.len();

/// The three buffers, each an aliased `Float64Array`.
pub struct Buffers {
    pub(crate) heap_statistics: AliasedUint8Array,
    pub(crate) heap_space_statistics: AliasedUint8Array,
    pub(crate) heap_code_statistics: AliasedUint8Array,
}

impl Buffers {
    /// Allocates the three buffers and their typed arrays.
    pub fn new(scope: &mut v8::PinScope) -> Result<Self, String> {
        Ok(Self {
            heap_statistics: allocate(scope, HEAP_STATISTICS_LENGTH)?,
            heap_space_statistics: allocate(scope, HEAP_SPACE_STATISTICS_LENGTH)?,
            heap_code_statistics: allocate(scope, HEAP_CODE_STATISTICS_LENGTH)?,
        })
    }
}

/// One `Float64Array` of `elements` doubles, shared with Rust.
///
/// `Element::Double` is what makes `AliasedUint8Array` produce a
/// `Float64Array`; the width and the index arithmetic follow from it, so
/// `set_float(4, ..)` writes the fifth double the JavaScript layer reads as
/// `buffer[4]`.
fn allocate(scope: &mut v8::PinScope, elements: usize) -> Result<AliasedUint8Array, String> {
    AliasedUint8Array::new(scope, elements, Element::Double)
}

thread_local! {
    /// The buffers the `update*Buffer()` functions write into.
    ///
    /// `RefCell<Option<_>>` rather than a `OnceCell` because install runs per
    /// realm: a fresh isolate replaces the previous realm's buffers instead of
    /// writing into a dead isolate's memory.
    static BUFFERS: RefCell<Option<Buffers>> = const { RefCell::new(None) };
}

/// Publishes the buffers for the update functions, dropping a previous realm's.
pub(crate) fn install(_scope: &mut v8::PinScope, buffers: Buffers) {
    BUFFERS.with(|slot| *slot.borrow_mut() = Some(buffers));
}

/// Whether the buffers have been installed on this thread.
pub fn is_installed() -> bool {
    BUFFERS.with(|slot| slot.borrow().is_some())
}

fn with<R>(body: impl FnOnce(&Buffers) -> R) -> Option<R> {
    BUFFERS.with(|slot| slot.borrow().as_ref().map(body))
}

/// Writes the heap statistics buffer through `body`.
///
/// Missing buffers mean the namespace was never installed, which cannot happen
/// from JavaScript because the update function only exists on the installed
/// object. Doing nothing is therefore the right answer rather than throwing.
pub fn with_heap_statistics(body: impl FnOnce(&AliasedUint8Array)) {
    let _ = with(|buffers| body(&buffers.heap_statistics));
}

/// Writes the heap space statistics buffer through `body`.
pub(crate) fn with_heap_space_statistics(body: impl FnOnce(&AliasedUint8Array)) {
    let _ = with(|buffers| body(&buffers.heap_space_statistics));
}

/// Writes the heap code statistics buffer through `body`.
pub(crate) fn with_heap_code_statistics(body: impl FnOnce(&AliasedUint8Array)) {
    let _ = with(|buffers| body(&buffers.heap_code_statistics));
}

/// Reads one element of the heap statistics buffer.
///
/// This is how a test observes that a JavaScript write landed: the typed array
/// and this handle are the same bytes, so a value written from either side is
/// visible from the other.
pub fn heap_statistics_at(index: usize) -> Option<f64> {
    with(|buffers| buffers.heap_statistics.get_float(index)).flatten()
}

/// Reads one element of the heap space statistics buffer.
pub fn heap_space_statistics_at(index: usize) -> Option<f64> {
    with(|buffers| buffers.heap_space_statistics.get_float(index)).flatten()
}

/// Reads one element of the heap code statistics buffer.
pub fn heap_code_statistics_at(index: usize) -> Option<f64> {
    with(|buffers| buffers.heap_code_statistics.get_float(index)).flatten()
}

/// The byte length of the heap statistics buffer, which is
/// `HEAP_STATISTICS_LENGTH * 8`.
pub fn heap_statistics_byte_length() -> Option<usize> {
    with(|buffers| buffers.heap_statistics.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_buffer_lengths_are_one_element_per_index_constant() {
        // Fourteen heap statistics, four per-space statistics, four code
        // statistics. `lib/v8.js` derives `kNumberOfHeapSpaces` from a
        // different array, but these three are indexed by the constants above.
        assert_eq!(HEAP_STATISTICS_LENGTH, 15);
        assert_eq!(HEAP_SPACE_STATISTICS_LENGTH, 4);
        assert_eq!(HEAP_CODE_STATISTICS_LENGTH, 4);
    }

    #[test]
    fn the_buffers_are_unset_before_install() {
        // A thread that never installed the namespace has nothing to write
        // into, and the accessors say so instead of inventing a zero.
        assert_eq!(heap_statistics_at(0), None);
        assert!(!is_installed());
    }
}
