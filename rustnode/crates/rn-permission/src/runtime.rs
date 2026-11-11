//! Where the process's model lives, for the crates that have to enforce it.
//!
//! `internalBinding('permission')` owns the model from JavaScript's point of
//! view, but Node's checks also happen in namespaces that have no reason to
//! know about each other: `fs` before every path operation, `process_wrap` and
//! `spawn_sync` before a spawn, `worker` before a thread starts. Passing the
//! model down through every crate's constructor would mean a parameter each of
//! them ignores on every normal run, and a `BindingRegistry` entry that exists
//! only to carry it.
//!
//! The CLI therefore installs the model once, before the registry is built, and
//! [`crate::register`] hands the binding the same `Arc`. That is the
//! arrangement `rn-bind-options` already uses for the parsed option store, so
//! there is one answer to "how does a binding see runtime state the CLI owns"
//! rather than two.
//!
//! # Cost
//!
//! A check is one `thread_local` borrow plus the model's own early return:
//! when the model is absent or disabled — every run without `--permission` — it
//! returns without resolving a path or taking the model's lock. That matters
//! because `fs` calls this on every operation, and Node's own model is a single
//! boolean load on the same path.
//!
//! # Threads
//!
//! The model is per thread, matching the rest of the runtime: rustnode has one
//! V8 thread and no worker threads yet, so there is no second thread for a
//! check to run on. A worker implementation must copy the `Arc` into the
//! worker's thread-local state rather than assume this one is visible there;
//! `PermissionShared` is an `Arc` for exactly that reason.

use std::cell::RefCell;

use crate::enforcement::{AccessDeniedError, PermissionGate};
use crate::model::{AccessDenied, PermissionModel, PermissionScope, PermissionShared};

thread_local! {
    static MODEL: RefCell<Option<PermissionShared>> = const { RefCell::new(None) };
}

/// Installs `model` as the process's model and returns the shared handle.
///
/// Replaces any previous model, so a test can install a fresh one.
pub fn install(model: PermissionModel) -> PermissionShared {
    let shared: PermissionShared = std::sync::Arc::new(model);
    install_shared(shared.clone());
    shared
}

/// Installs an already-shared model.
pub fn install_shared(model: PermissionShared) {
    MODEL.with(|slot| {
        *slot.borrow_mut() = Some(model);
    });
}

/// Removes the installed model, so a later check sees no model at all.
///
/// Only tests need this; the CLI installs one model for the life of the process.
pub fn clear() {
    MODEL.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

/// The installed model, if the CLI installed one.
pub fn shared() -> Option<PermissionShared> {
    MODEL.with(|slot| slot.borrow().clone())
}

/// Whether the installed model enforces anything.
pub fn is_enabled() -> bool {
    MODEL.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|model| model.is_enabled())
    })
}

/// Whether the installed model is in `--permission-audit` mode.
pub fn is_audit() -> bool {
    MODEL.with(|slot| slot.borrow().as_ref().is_some_and(|model| model.is_audit()))
}

/// A gate over the installed model.
///
/// `PermissionGate::disabled()` when nothing is installed, so a caller can hold
/// the result and skip its own branching.
pub fn gate() -> PermissionGate {
    match shared() {
        Some(model) => PermissionGate::new(model),
        None => PermissionGate::disabled(),
    }
}

/// Runs `check` against the installed model and reports the denial that has to
/// be raised, if any.
///
/// A disabled or audit model reports nothing: the first has nothing to deny and
/// the second deliberately does not act on a denial.
fn evaluate(
    check: impl FnOnce(&PermissionModel) -> Result<(), AccessDenied>,
) -> Option<AccessDeniedError> {
    MODEL.with(|slot| {
        let slot = slot.borrow();
        let model = slot.as_ref()?;
        if !model.is_enabled() || model.is_audit() {
            return None;
        }
        check(model).err().map(AccessDeniedError::new)
    })
}

/// Checks a filesystem read of `path`, given as the raw bytes the JavaScript
/// layer passed.
///
/// Bytes rather than `&str` because paths are not required to be valid UTF-8
/// and Node compares the unresolved bytes; a lossy conversion here could turn a
/// denied path into a granted one.
pub fn deny_fs_read(path: &[u8]) -> Option<AccessDeniedError> {
    evaluate(|model| model.check_fs_read_bytes(path))
}

/// Checks a filesystem write of `path`.
pub fn deny_fs_write(path: &[u8]) -> Option<AccessDeniedError> {
    evaluate(|model| model.check_fs_write_bytes(path))
}

/// Checks spawning `resource`, the executable, which Node reports in the
/// denial's `resource` field.
pub fn deny_child_process(resource: &str) -> Option<AccessDeniedError> {
    evaluate(|model| model.check_child_process_resource(resource))
}

/// Checks creating a worker thread.
pub fn deny_worker() -> Option<AccessDeniedError> {
    evaluate(PermissionModel::check_worker)
}

/// Checks loading the named native addon.
pub fn deny_addon(resource: &str) -> Option<AccessDeniedError> {
    evaluate(|model| model.check_addon_named(resource))
}

/// Checks instantiating WASI.
pub fn deny_wasi() -> Option<AccessDeniedError> {
    evaluate(PermissionModel::check_wasi)
}

/// Checks opening a network server or socket.
pub fn deny_net(resource: &str) -> Option<AccessDeniedError> {
    evaluate(|model| model.check_net(resource))
}

/// Checks enabling the inspector.
pub fn deny_inspector() -> Option<AccessDeniedError> {
    evaluate(PermissionModel::check_inspector)
}

/// Checks a `--allow-env` grant for `name`.
///
/// `permission.has('env', name)` answers this through the binding; this is the
/// same question for a Rust call site that has no V8 scope.
pub fn deny_env(name: &str) -> Option<AccessDeniedError> {
    evaluate(|model| {
        if model.has(PermissionScope::Env, Some(name)) {
            Ok(())
        } else {
            Err(AccessDenied::new(PermissionScope::Env, name))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PermissionConfig;

    /// The thread-local is shared by every test in this binary, so each test
    /// installs the model it needs rather than relying on a previous one.
    fn install_model(cwd: &str, config: PermissionConfig) -> PermissionShared {
        install(PermissionModel::with_cwd(cwd, config))
    }

    #[test]
    fn no_model_denies_nothing() {
        clear();
        assert!(!is_enabled());
        assert!(!is_audit());
        assert!(deny_fs_read(b"/etc/passwd").is_none());
        assert!(deny_child_process("/bin/sh").is_none());
        assert!(deny_worker().is_none());
        assert!(deny_env("SECRET").is_none());
    }

    #[test]
    fn an_enforcing_model_denies_and_reports_the_scope() {
        install_model("/work", PermissionConfig::enforce());
        assert!(is_enabled());
        let denied = deny_fs_read(b"/etc/passwd").expect("denied");
        assert_eq!(denied.code(), "ERR_ACCESS_DENIED");
        assert_eq!(denied.permission(), "FileSystemRead");
        assert_eq!(denied.resource(), "/etc/passwd");
        assert!(deny_fs_write(b"/etc/passwd").is_some());
        assert!(deny_child_process("/bin/sh").is_some());
        assert!(deny_worker().is_some());
        assert!(deny_env("SECRET").is_some());
    }

    #[test]
    fn a_grant_turns_the_same_check_into_an_allow() {
        // A directory grant gains a `/*` wildcard only when the path exists,
        // because `WildcardIfDir` probes the filesystem once per grant. Using a
        // real temporary directory keeps this test about the check rather than
        // about the probe.
        let directory =
            std::env::temp_dir().join(format!("rn-permission-runtime-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("create temp dir");
        let directory = directory.to_string_lossy().into_owned();

        let model = install_model("/work", PermissionConfig::enforce());
        let inside = format!("{directory}/file");
        assert!(deny_child_process("/bin/sh").is_some());
        model.grant_fs(PermissionScope::FileSystemRead, &directory);
        assert!(deny_fs_read(inside.as_bytes()).is_none());
        assert!(deny_fs_write(inside.as_bytes()).is_some());
    }

    #[test]
    fn audit_mode_reports_nothing() {
        install_model("/work", PermissionConfig::audit());
        assert!(is_enabled());
        assert!(is_audit());
        assert!(deny_fs_read(b"/etc/passwd").is_none());
        assert!(deny_child_process("/bin/sh").is_none());
    }

    #[test]
    fn the_gate_wraps_the_installed_model() {
        install_model("/work", PermissionConfig::enforce());
        let gate = gate();
        assert!(gate.is_enabled());
        assert!(gate.deny_fs_read("/etc/passwd").is_some());
    }
}
