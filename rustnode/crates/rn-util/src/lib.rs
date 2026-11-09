//! `internalBinding('types')` and `internalBinding('util')`.
//!
//! These two are the first namespaces the builtin loader cannot start without:
//! `lib/internal/util.js` destructures both, and `realm.js` reaches `internal/util`
//! before it can define anything else.

pub mod types;
pub mod util;

pub use types::Types;
pub use util::Util;

/// Registers the namespaces this crate implements.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    types::register(registry);
    util::register(registry);
}
