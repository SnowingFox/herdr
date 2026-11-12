//! Binding kernel: the Rust counterpart of Node's `node::Env`, `BaseObject` and
//! `AsyncWrap`.
//!
//! Every `internalBinding()` namespace in `lib/**` receives objects produced
//! here, so this crate owns the ABI that the unchanged JavaScript layer sees.

pub mod abi;
pub mod aliased_buffer;
pub mod async_wrap;
pub mod binding;
pub mod callback_scope;
pub mod codec;
pub mod env;
pub mod env_proxy;
pub mod error;
pub mod finalizer;
pub mod handle;
pub mod hook_slot;
pub mod host_object;
pub mod native_immediates;
pub mod per_context;
pub mod queue;
pub mod realm;
pub mod symbol;

pub use abi::{BindingModule, InstallCtx};
pub use aliased_buffer::{AliasedUint8Array, Element};
pub use async_wrap::{AsyncIds, AsyncWrapState, INVALID_ASYNC_ID};
pub use binding::{BindingRegistry, Installer, Namespace};
pub use codec::Encoding;
pub use env::Env;
pub use error::KernelError;
pub use per_context::{
    per_context_exports, per_isolate_symbols_object, private_symbols_object,
    set_per_context_exports, PER_CONTEXT_EXPORTS,
};
pub use queue::TaskQueue;
pub use symbol::{
    define_mark, per_isolate_symbol, per_isolate_symbol_description, symbol, CONTEXTIFY_CONTEXT,
    HOST_DEFINED_OPTION, PER_ISOLATE_SYMBOLS, PRIVATE_SYMBOLS,
};
