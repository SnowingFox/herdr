//! Building the binding registry for a worker realm.
//!
//! `rn-bindings` is the crate that knows how to assemble a registry — it is the
//! `install_all` list — and `rn-bindings` depends on every binding crate,
//! including this one. A worker therefore cannot call it directly without a
//! cycle, so it asks `rn-core::realm` for whatever factory the runtime installed
//! at startup. That is the same seam `native_immediates` uses to let a producer
//! wake a loop it does not own.
//!
//! The consequence worth knowing: a worker can only start in a process that has
//! installed the factory. That is every real rustnode process, and a test that
//! wants a worker installs it too. A missing factory is reported as such rather
//! than turning into a mysterious `internalBinding` failure deep in the realm
//! bootstrap.

/// Builds a registry for a new realm.
pub fn build() -> Result<rn_core::BindingRegistry, String> {
    rn_core::realm::build_registry()
}
