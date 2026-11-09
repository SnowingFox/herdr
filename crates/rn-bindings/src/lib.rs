//! Aggregates the `internalBinding()` namespaces implemented across the
//! workspace.
//!
//! Each `crates/rn-bind-*` crate owns one namespace group and exports
//! `register(&mut BindingRegistry)`. `install_all` is generated from the crates
//! present on disk by `tools/regen-bindings.sh`, so adding a binding crate
//! never means editing a shared file.

mod install_all;

pub use install_all::install_all;
