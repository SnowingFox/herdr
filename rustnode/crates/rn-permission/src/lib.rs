//! The permission model for rustnode.
//!
//! Node's permission model lives in `src/permission/` and is consulted from
//! both the binding layer (`node_file.cc`, `node_worker.cc`, `node_wasi.cc`,
//! `process_wrap.cc`, `spawn_sync.cc`, `node_binding.cc`) and, for the file
//! system, from `lib/fs.js` and `lib/internal/fs/promises.js` before the native
//! call. rustnode keeps the same split:
//!
//! * [`PermissionModel`] owns the grants and answers every check;
//! * [`PermissionBinding`] is `internalBinding('permission')`, which
//!   `lib/internal/process/permission.js` wraps into `process.permission`;
//! * [`AccessDenied`] is the `ERR_ACCESS_DENIED` payload, with the `permission`
//!   and `resource` fields the JavaScript error constructor takes;
//! * [`runtime`] is where the CLI installs the one model the native checks read,
//!   so a crate enforcing a scope does not have to be handed the model.
//!
//! # Gated resources
//!
//! The JavaScript layer only ever asks about these scopes, and the native layer
//! enforces the rest:
//!
//! | Scope | Gated operation | Enforced by |
//! | --- | --- | --- |
//! | `fs.read` | opening, reading, stating, listing | `lib/fs.js`, `lib/internal/fs/promises.js` |
//! | `fs.write` | writing, creating, renaming, unlinking, chmod/chown/utimes | `lib/fs.js`, `lib/internal/fs/promises.js` |
//! | `fs` | `fs.symlink` only, which needs both halves | `lib/fs.js`, `lib/internal/fs/promises.js` |
//! | `child` | `spawn`, `spawnSync`, `exec`, `execFile`, `fork` | `process_wrap.cc`, `spawn_sync.cc` |
//! | `worker` | `new Worker()` | `node_worker.cc` |
//! | `addon` | `process.dlopen`, `internalBinding` of a linked binding | `node_binding.cc` |
//! | `wasi` | `new WASI()` | `node_wasi.cc` |
//! | `inspector` | opening the inspector, `console` previews | `lib/internal/util/inspector.js` |
//! | `net` | TCP/UDP/Pipe servers and sockets | `tcp_wrap.cc`, `udp_wrap.cc`, `pipe_wrap.cc` |
//! | `env` | every environment variable except the ones Node keeps | env scrub at startup |
//! | `ffi` | `node:ffi` calls | `lib/ffi.js` |
//! | `openssl.store` | OpenSSL STORE loaders | crypto layer |
//!
//! # Cost
//!
//! A check starts with one boolean: when the model is off (the default) it
//! returns without taking a lock, resolving a path, or touching the
//! filesystem. When it is on, a filesystem check resolves the path lexically
//! and walks a prefix tree of the grants. Nothing is canonicalised: Node's
//! model compares unresolved paths, and symlink following is a documented
//! limitation of the model rather than something a check can fix.

pub mod binding;
pub mod enforcement;
pub mod env;
pub mod model;
pub mod path;
pub mod runtime;

pub use binding::{PermissionBinding, MEMBERS};
pub use enforcement::{AccessDeniedError, PermissionGate};
pub use model::{
    AccessDenied, PermissionConfig, PermissionModel, PermissionScope, PermissionShared,
};
pub use path::{resolve_path, wildcard_if_dir, RadixTree};

/// Registers the `permission` namespace with the runtime.
///
/// The binding is installed around the model the CLI put in [`runtime`], so
/// `process.permission.has()` and the native checks answer from one set of
/// grants: a `process.permission.drop()` revokes access for `fs` too. Without
/// an installed model the binding still exists and grants everything, which is
/// what a process started without `--permission` must do.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    let model =
        runtime::shared().unwrap_or_else(|| std::sync::Arc::new(PermissionModel::disabled()));
    registry.register_module(PermissionBinding::new(model));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_installs_the_model_the_cli_supplied() {
        // A CLI that built an enforcing model must see that model behind
        // `internalBinding('permission')`; installing a fresh disabled one here
        // is what made every check a no-op.
        let model = runtime::install(PermissionModel::with_cwd(
            "/work",
            PermissionConfig {
                allow_fs_read: vec!["*".to_string()],
                ..PermissionConfig::enforce()
            },
        ));
        let mut registry = rn_core::BindingRegistry::new();
        register(&mut registry);
        assert!(registry.can_install("permission"));
        assert!(runtime::shared().is_some_and(|shared| std::sync::Arc::ptr_eq(&shared, &model)));
        assert!(model.check_fs_read("/etc/passwd").is_ok());
        assert!(model.check_fs_write("/etc/passwd").is_err());
        runtime::clear();
    }

    #[test]
    fn register_without_an_installed_model_still_grants_everything() {
        runtime::clear();
        let mut registry = rn_core::BindingRegistry::new();
        register(&mut registry);
        assert!(registry.can_install("permission"));
        assert!(!runtime::is_enabled());
    }
}
