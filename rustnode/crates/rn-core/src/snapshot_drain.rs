//! Dropping the thread-local handles a realm leaves behind.
//!
//! # Why this exists
//!
//! `CreateBlob` runs `SerializedHandleChecker::CheckGlobalAndEternalHandles` and
//! aborts on every `v8::Global` that is neither reachable from a serialised
//! context nor from a serialised embedder object. rustnode keeps per-realm
//! identity in thread-local `v8::Global` caches across many crates, so a snapshot
//! build has to empty them before it serialises:
//!
//! ```text
//! (Global handles) handle not serialized: 0x38044cb5d051 <JSFunction internalBinding …>
//! (Global handles) handle not serialized: 0x0b48ea5e1811 <Uint8Array map = 0x…>
//! # Fatal error
//! # CheckGlobalAndEternalHandles failed
//! ```
//!
//! The build also needs this for a second, separate reason: a `--build-snapshot`
//! bootstraps a **discovery** realm first, to learn the external-reference table,
//! and then bootstraps the realm it actually serialises. The discovery realm's
//! cached binding objects belong to the discovery isolate, which is disposed
//! before the second pass runs; leaving them in place makes the second pass fault
//! with `attempt to access Handle hosted by disposed Isolate`. Dropping them is
//! what gives the second pass the empty caches a fresh process would have.
//!
//! # Why the crates register hooks instead of `rn-core` owning the slots
//!
//! The slots live in the crates that declare them — `hook_slot`'s loaders,
//! `rn-bind-fs`'s request table, the inspector's contexts — and `rn-core` cannot
//! name them without depending on every binding crate, which would invert the
//! dependency direction the binding registry exists to keep. So each crate
//! registers the drain it owns, the same shape as
//! [`crate::host_object::register_transfer_kind`], and this module runs them.
//!
//! Registration is idempotent by name, because `BindingRegistry::new` runs the
//! install path more than once per process (once for the CLI's registry, once per
//! worker thread) and a crate registers from its own `register`.
//!
//! # What a drain must and must not drop
//!
//! A drain drops handles that are *derived* — caches, tables, objects rebuilt from
//! the realm that is about to be serialised. It must not drop a handle whose
//! absence would change behaviour after a load, and two are named here because the
//! abort list contains them:
//!
//! * `internalBinding` and `requireBuiltin` are the realm's loader entry points.
//!   A drain that dropped them would produce a blob that loads and then cannot
//!   resolve a builtin. They stay, and the load path reinstalls them from the
//!   serialised realm the same way `register_transfer_kind` and the messaging
//!   hooks are reinstalled per isolate.

use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    /// One drain per crate, keyed by name so re-registration replaces rather than
    /// accumulates.
    ///
    /// `BTreeMap` rather than a `Vec` so the order is deterministic: a drain that
    /// depends on another crate's having run first would otherwise be ordered by
    /// link order. Nothing depends on it today, and the determinism is what would
    /// make such a dependency visible rather than intermittent.
    static DRAINS: RefCell<BTreeMap<&'static str, fn()>> = const { RefCell::new(BTreeMap::new()) };
}

/// Registers `drain` as the way to drop the handles `crate_name` keeps.
pub fn register(crate_name: &'static str, drain: fn()) {
    DRAINS.with(|drains| {
        drains.borrow_mut().insert(crate_name, drain);
    });
}

/// Runs every registered drain, dropping the realm's thread-local handles.
///
/// `rn-core`'s own slots are dropped first and directly rather than through the
/// registry: this module and [`crate::hook_slot`] and [`crate::realm`] are the
/// same crate, so registering with itself would only add a level of indirection
/// over a call it can make.
///
/// Returns how many drains ran, so a build can report that the mechanism is
/// actually wired rather than assume it: a count of zero would mean every slot
/// stays populated and the abort would name the same handles it always did.
pub fn drop_realm_handles() -> usize {
    drop_core_handles();
    let drains: Vec<fn()> = DRAINS.with(|drains| drains.borrow().values().copied().collect());
    for drain in &drains {
        drain();
    }
    drains.len() + 1
}

/// Drops the handles `rn-core` itself keeps for the realm on this thread.
///
/// The binding registry's cache is the one that matters most: it holds
/// `v8::Global<Object>` for every namespace a realm installed, keyed by realm id,
/// and it is what faults with `attempt to access Handle hosted by disposed
/// Isolate` when a second realm on the same thread asks for a namespace the first
/// one had cached.
fn drop_core_handles() {
    crate::hook_slot::drop_realm_handles();
    crate::env_proxy::forget_realm_proxy();
    if let Some(registry) = crate::realm::installed() {
        registry.clear_installed();
    }
}

/// How many drains are registered. Tests read it; a build reports it.
pub fn drain_count() -> usize {
    DRAINS.with(|drains| drains.borrow().len())
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static RAN: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    fn count_a() {
        RAN.with(|ran| ran.set(ran.get() + 1));
    }

    fn count_b() {
        RAN.with(|ran| ran.set(ran.get() + 1));
    }

    /// Every registered drain runs, and re-registering a name replaces rather
    /// than adding a second entry — which is what makes running the install path
    /// twice per process harmless.
    ///
    /// The returned count is the registered drains plus one for `rn-core`'s own,
    /// which runs directly rather than through the registry.
    #[test]
    fn registering_twice_replaces_and_every_drain_runs() {
        RAN.with(|ran| ran.set(0));
        register("probe-a", count_a);
        register("probe-a", count_a);
        register("probe-b", count_b);
        assert!(
            drain_count() >= 2,
            "a repeated name is one entry; other tests may have registered more"
        );
        let before = drain_count();

        let ran = drop_realm_handles();
        assert_eq!(
            ran,
            before + 1,
            "every registered drain ran, plus rn-core's own"
        );
        assert_eq!(
            RAN.with(|ran| ran.get()),
            2,
            "each ran exactly once, not once per registration"
        );
    }
}
