//! The external-reference table a snapshot build hands to V8.
//!
//! # What V8 wants
//!
//! Every `FunctionTemplate`/`Function` built from a Rust callback embeds the
//! address of a monomorphised `extern "C"` thunk (`MapFnTo`'s generated `c_fn`).
//! Serialising an isolate that retains one aborts with
//! `Unknown external reference 0x…` unless the address appears in the table
//! passed as `CreateParams::external_references`; on load, V8 reads an index into
//! that same table instead of a pointer, which is what makes a blob portable
//! between processes whose ASLR layout differs.
//!
//! # Why this is a registry and not a list
//!
//! Node has no generated list either. `src/node_external_reference.h:38`'s
//! `ExternalReferenceRegistry::Register(ExternalReferenceType addr)` is a
//! *runtime* registry: every binding pushes the addresses it hands V8 as it
//! installs its templates, and the vector that results becomes
//! `CreateParams::external_references`. The count is discovered, not predicted,
//! and it is complete exactly when the realm has finished bootstrapping.
//!
//! rustnode matches that shape. [`record`] is called by the builders in
//! [`crate::function`] as they create templates, so the funnel that already
//! exists for naming and length is also the funnel for this. A site that calls
//! the `v8` builder directly is invisible here, which is the one thing to keep in
//! mind: [`crate::function`]'s builders are the contract, and the snapshot
//! contract test names the sites that bypass them.
//!
//! # The ordering problem this exists to make explicit
//!
//! `CreateParams::external_references` is consumed when the isolate is *created*,
//! while the table is filled when templates are *built* — which happens during
//! realm bootstrap, after the isolate exists. For an ordinary run that is
//! harmless, because nothing is ever serialised. A snapshot build has to create
//! its creator isolate with a table that is already complete, which is why the
//! build path bootstraps twice: once to discover the addresses, once to serialise
//! a realm built with them registered.
//!
//! `CreateParams::external_references` appends the terminating null entry itself
//! (`isolate_create_params.rs:77-87`), so this table does not.
//!
//! # Sorting
//!
//! The table is passed in registration order and V8 scans it linearly, so it does
//! not have to be sorted. That is measured rather than assumed — see
//! `a_descending_external_reference_table_still_builds` in the snapshot contract
//! test — because V8's own `ExternalReferenceTable` is sorted by address and a
//! reader could reasonably guess the parameter is searched the same way. If a V8
//! bump ever changes that, the test fails rather than the build silently
//! producing a blob V8 cannot reload.

use std::cell::RefCell;
use std::ffi::c_void;

use rn_v8_sys::v8;

thread_local! {
    /// The thunk addresses this thread's realm has handed to V8, in the order
    /// they were recorded, with duplicates removed.
    ///
    /// Thread-local for the same reason as the binding registry: one thread hosts
    /// one realm at a time, and the addresses belong to whatever isolate is
    /// building templates on it.
    ///
    /// A `Vec` scanned linearly rather than a set: a snapshot build records a few
    /// thousand addresses once, and every read happens at one instant
    /// (`CreateParams` construction) rather than on any hot path.
    static RECORDED: RefCell<Vec<*mut c_void>> = const { RefCell::new(Vec::new()) };
}

/// Records `address` as an external reference V8 must know about.
///
/// Idempotent: a thunk recorded twice appears once. Several binding modules
/// legitimately build the same callback more than once — a namespace installed
/// into two realms, a template rebuilt by `install` — and a duplicate entry would
/// make V8's index differ from the one the build recorded for no benefit.
pub fn record(address: *mut c_void) {
    if address.is_null() {
        return;
    }
    RECORDED.with(|recorded| {
        let mut recorded = recorded.borrow_mut();
        if !recorded.contains(&address) {
            recorded.push(address);
        }
    });
}

/// The table to hand [`v8::CreateParams::external_references`].
///
/// Empty is a valid answer and the right one for a run that will never serialise:
/// a non-snapshot process has no use for the table, and filling it would cost a
/// `CreateParams` field it never reads.
pub fn table() -> Vec<v8::ExternalReference> {
    RECORDED.with(|recorded| {
        recorded
            .borrow()
            .iter()
            .map(|address| v8::ExternalReference { pointer: *address })
            .collect()
    })
}

/// How many distinct addresses are recorded, for the build to report.
pub fn recorded_count() -> usize {
    RECORDED.with(|recorded| recorded.borrow().len())
}

/// Forgets every recorded address.
///
/// Only the snapshot build uses this, between its discovery pass and its
/// serialising pass: the second bootstrap records the same addresses again, and
/// keeping the first pass's copy would leave the table describing a realm that no
/// longer exists. Tests use it to observe a clean table.
pub fn clear() {
    RECORDED.with(|recorded| recorded.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(value: usize) -> *mut c_void {
        value as *mut c_void
    }

    /// The four properties the build depends on: duplicates collapse, order is
    /// kept, a null is not an entry, and `table` and `recorded_count` agree.
    #[test]
    fn recording_is_idempotent_and_keeps_first_seen_order() {
        clear();
        record(address(0x30));
        record(address(0x10));
        record(address(0x30));
        record(std::ptr::null_mut());
        record(address(0x20));

        assert_eq!(
            recorded_count(),
            3,
            "three distinct non-null addresses were recorded"
        );
        let table = table();
        assert_eq!(table.len(), 3);
        // `ExternalReference` is a union, so it is compared through `PartialEq`,
        // which reads the `pointer` field — the same field a caller sets.
        let expected = [
            v8::ExternalReference {
                pointer: address(0x30),
            },
            v8::ExternalReference {
                pointer: address(0x10),
            },
            v8::ExternalReference {
                pointer: address(0x20),
            },
        ];
        assert_eq!(
            table, expected,
            "registration order is preserved, not sorted, and the null is absent"
        );
        clear();
    }

    #[test]
    fn a_cleared_table_is_empty() {
        record(address(0x1));
        clear();
        assert_eq!(recorded_count(), 0);
        assert!(table().is_empty());
    }
}
