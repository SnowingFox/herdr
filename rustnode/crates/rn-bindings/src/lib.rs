//! Aggregates the `internalBinding()` namespaces implemented across the
//! workspace.
//!
//! Each `crates/rn-bind-*` crate owns one namespace group and exports
//! `register(&mut BindingRegistry)`. `install_all` is generated from the crates
//! present on disk by `tools/regen-bindings.sh`, so adding a binding crate
//! never means editing a shared file.

mod install_all;

pub use install_all::install_all;

/// Runs every loaded addon's teardown. See
/// [`rn_bind_process_methods::run_addon_teardowns`].
///
/// Re-exported because the CLI depends on this crate and not on the loader crate
/// directly, and a teardown caller should not have to know which crate owns the
/// loaded-addon list.
pub use rn_bind_process_methods::run_addon_teardowns;
