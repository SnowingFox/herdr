//! Binding kernel: the Rust counterpart of Node's `node::Env`, `BaseObject` and
//! `AsyncWrap`.
//!
//! Every `internalBinding()` namespace in `lib/**` receives objects produced
//! here, so this crate owns the ABI that the unchanged JavaScript layer sees.

pub mod async_wrap;
pub mod binding;
pub mod env;
pub mod error;
pub mod handle;
pub mod queue;

pub use binding::{BindingRegistry, Namespace};
pub use env::Env;
pub use error::KernelError;
