//! Binding kernel: the Rust counterpart of Node's `node::Env`, `BaseObject` and
//! `AsyncWrap`.
//!
//! Every `internalBinding()` namespace in `lib/**` receives objects produced
//! here, so this crate owns the ABI that the unchanged JavaScript layer sees.

pub mod abi;
pub mod aliased_buffer;
pub mod async_wrap;
pub mod binding;
pub mod env;
pub mod error;
pub mod handle;
pub mod hook_slot;
pub mod queue;
pub mod symbol;

pub use abi::{BindingModule, InstallCtx};
pub use aliased_buffer::{AliasedUint8Array, Element};
pub use async_wrap::AsyncIds;
pub use binding::{BindingRegistry, Installer, Namespace};
pub use env::Env;
pub use error::KernelError;
pub use queue::TaskQueue;
pub use symbol::{define_mark, symbol, CONTEXTIFY_CONTEXT, HOST_DEFINED_OPTION, PRIVATE_SYMBOLS};
