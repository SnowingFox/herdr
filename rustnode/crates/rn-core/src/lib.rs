//! Binding kernel: the Rust counterpart of Node's `node::Env`, `BaseObject` and
//! `AsyncWrap`.
//!
//! Every `internalBinding()` namespace in `lib/**` receives objects produced
//! here, so this crate owns the ABI that the unchanged JavaScript layer sees.

pub mod abi;
pub mod aliased_buffer;
pub mod array_buffer_allocator;
pub mod async_wrap;
pub mod binding;
pub mod callback_scope;
pub mod codec;
pub mod env;
pub mod env_proxy;
pub mod error;
pub mod exit_state;
pub mod finalizer;
pub mod function;
pub mod handle;
pub mod heap_retainers;
pub mod hook_slot;
pub mod host_object;
pub mod isolate_params;
pub mod native_immediates;
pub mod per_context;
pub mod platform_tasks;
pub mod profile;
pub mod queue;
pub mod realm;
pub mod symbol;
pub mod task_queue;
#[cfg(test)]
mod test_support;
pub mod watchdog;

pub use abi::{BindingModule, InstallCtx};
pub use aliased_buffer::{AliasedUint8Array, Element};
pub use array_buffer_allocator::{
    live_array_buffer_bytes, with_counted_array_buffer_allocator,
    with_debugging_array_buffer_allocator,
};
pub use async_wrap::{AsyncIds, AsyncWrapState, INVALID_ASYNC_ID};
pub use binding::{BindingRegistry, Installer, Namespace};
pub use codec::Encoding;
pub use env::Env;
pub use error::KernelError;
pub use function::{
    class, class_with_length, extras_method, method, method_function, method_function_raw,
    named_method, named_method_with_length, named_template, set_class, set_fast_method, set_method,
    set_named_method_with_length,
};
pub use isolate_params::{
    installable_memory, max_old_space_size_percentage_mb, set_isolate_create_params_for_node,
};
pub use per_context::{
    per_context_exports, per_isolate_symbols_object, private_symbols_object,
    set_per_context_exports, PER_CONTEXT_EXPORTS,
};
pub use queue::TaskQueue;
pub use symbol::{
    define_mark, per_isolate_symbol, per_isolate_symbol_description, symbol, CONTEXTIFY_CONTEXT,
    HOST_DEFINED_OPTION, PER_ISOLATE_SYMBOLS, PRIVATE_SYMBOLS,
};
