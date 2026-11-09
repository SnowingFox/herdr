//! `internalBinding('config')` and `internalBinding('constants')`.
//!
//! Both namespaces carry build-time and platform facts rather than runtime
//! behaviour, so this crate is pure data plus the V8 object construction that
//! publishes it. Nothing here allocates handles or touches the event loop.
//!
//! Values were derived from Node 28's own sources. See `sources.rs` for the
//! exact provenance of every table.

pub mod config;
pub mod constants;
mod install;
pub mod sources;
pub mod value;

pub use config::Config;
pub use constants::Constants;
use rn_core::{BindingRegistry, Namespace};
pub use value::Value;

pub(crate) use install::{
    install_constant, install_readonly, null_proto_object, string, table_object,
};

/// Registers this crate's namespaces with the binding registry.
///
/// `tools/regen-bindings.sh` discovers every `crates/rn-bind-*` directory and
/// calls this, so a workstream adds a crate without editing a shared manifest.
/// Members come from each `BindingModule::members`, which is what `rn-compat`
/// checks against `contracts/<namespace>.json`; a name listed here but never
/// installed would let the contract pass while `lib/**` reads `undefined`.
pub fn register(registry: &mut BindingRegistry) {
    registry.register(Namespace::from_module(&Config));
    registry.register(Namespace::from_module(&Constants));
}
