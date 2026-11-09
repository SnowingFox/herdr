//! The 73 `internalBinding()` namespaces `lib/**` expects.
//!
//! Each module owns one namespace and is validated against the generated
//! contract in `contracts/<namespace>.json`.

pub mod registry;

pub use registry::install_all;
