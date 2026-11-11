//! The permission-model check `enableLoadExtension` and `loadExtension` need.
//!
//! Node refuses extension loading outright when the permission model is enabled,
//! because loading a shared object is arbitrary native code execution and the
//! model exists to bound exactly that. `src/node_sqlite.cc` checks
//! `env()->permission()->enabled()` in `Open` (for `allowExtension`) and again in
//! `LoadExtension`, so both paths are closed.
//!
//! `rn-permission` owns the installed model. This module is the one-line bridge,
//! kept separate so the sqlite crate's dependency on the permission crate is
//! visible in one place.

/// Whether the installed permission model enforces anything.
pub fn enabled() -> bool {
    rn_permission::runtime::is_enabled()
}
