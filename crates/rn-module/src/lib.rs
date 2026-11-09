//! CommonJS and ES module loading.
//!
//! Resolution rules are taken from the Node checkout pinned in
//! `tools/node-pin.toml`; `lib/internal/modules/**` remains the source of truth
//! and is executed unchanged inside the snapshot.

pub mod cjs;
pub mod esm;
pub mod resolver;

pub use resolver::{resolve, ResolutionError};
