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

use rn_v8_sys::v8;

use crate::enforcement::{AccessDeniedError, PermissionGate};
use crate::model::{AccessDenied, PermissionModel, PermissionScope, PermissionShared};

thread_local! {
    static MODEL: RefCell<Option<PermissionShared>> = const { RefCell::new(None) };
    /// The IPC channel's descriptor, `-1` when this process has none.
    static IPC_CHANNEL_FD: RefCell<i32> = const { RefCell::new(-1) };
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

/// The denial `check` reports, whether or not the model acts on it.
///
/// `--permission-audit` checks and publishes but does not deny, so a caller that
/// has a V8 scope and wants to publish the denial to
/// `node:permission-model:<scope>` needs the denial even in audit mode. That is
/// what this answers and [`evaluate`] does not: `evaluate` is for callers that
/// can only act, and audit mode has nothing for them to act on.
///
/// The caller decides whether to throw and whether to publish; this only
/// reports. A disabled model returns `None`, which is the common case and costs
/// the same borrowing and boolean load as [`evaluate`].
fn observe(
    check: impl FnOnce(&PermissionModel) -> Result<(), AccessDenied>,
) -> Option<AccessDeniedError> {
    MODEL.with(|slot| {
        let slot = slot.borrow();
        let model = slot.as_ref()?;
        if !model.is_enabled() {
            return None;
        }
        check(model).err().map(AccessDeniedError::new)
    })
}

/// Publishes `denied` to `node:permission-model:<scope>`, the diagnostics
/// channel `Permission::Publish` creates on first use.
///
/// Node publishes from every denying check, so a subscriber sees one message per
/// denial. rustnode reaches the channel through
/// `lib/internal/diagnostics_channel`, which is JavaScript: a
/// `diagnostics_channel` publication is a function call on the channel object,
/// and only V8 can make it. The import is done with the builtin loader rather
/// than at install time because a process that never subscribes must not pay for
/// the module, and a channel with no subscriber publishes nothing anyway.
///
/// Failures are swallowed deliberately: publishing is an observation, and a
/// missing channel or a throwing subscriber must not turn into a different
/// error than the denial itself.
fn publish(scope: &mut v8::PinScope<'_, '_>, denied: &AccessDeniedError) {
    let Some(channel) = permission_channel(scope, denied.scope()) else {
        return;
    };
    let Some(text) = v8::String::new(scope, "publish") else {
        return;
    };
    let Some(value) = channel.get(scope, text.into()) else {
        return;
    };
    let Ok(publish) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };

    let message = v8::Object::new(scope);
    for (name, value) in [
        ("permission", denied.permission()),
        ("resource", denied.resource()),
    ] {
        if let (Some(key), Some(text)) =
            (v8::String::new(scope, name), v8::String::new(scope, value))
        {
            message.set(scope, key.into(), text.into());
        }
    }
    // `drop` is `undefined` for a denial, which is what `Publish` passes for
    // `dropped=false`; the property is present so a subscriber destructuring it
    // sees `undefined` rather than nothing.
    if let (Some(key), Some(undefined)) =
        (v8::String::new(scope, "drop"), Some(v8::undefined(scope)))
    {
        message.set(scope, key.into(), undefined.into());
    }

    let receiver: v8::Local<v8::Value> = channel.into();
    let _ = publish.call(scope, receiver, &[message.into()]);
}

/// Looks up `node:permission-model:<scope>`, if the module can be loaded.
fn permission_channel<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    scope_kind: PermissionScope,
) -> Option<v8::Local<'s, v8::Object>> {
    let name = format!("node:permission-model:{}", channel_suffix(scope_kind));
    let require = rn_core::hook_slot::require(scope)?;
    let id = v8::String::new(scope, "node:diagnostics_channel")?;
    let exports = require.call(scope, v8::undefined(scope).into(), &[id.into()])?;
    let exports = v8::Local::<v8::Object>::try_from(exports).ok()?;
    let key = v8::String::new(scope, "channel")?;
    let channel = exports.get(scope, key.into())?;
    let channel = v8::Local::<v8::Function>::try_from(channel).ok()?;
    let name = v8::String::new(scope, &name)?;
    let result = channel.call(scope, exports.into(), &[name.into()])?;
    v8::Local::<v8::Object>::try_from(result).ok()
}

/// `GetDiagnosticsChannelName`'s suffix for one scope.
fn channel_suffix(scope: PermissionScope) -> &'static str {
    match scope {
        PermissionScope::FileSystem
        | PermissionScope::FileSystemRead
        | PermissionScope::FileSystemWrite => "fs",
        PermissionScope::ChildProcess => "child",
        PermissionScope::WorkerThreads => "worker",
        PermissionScope::Net => "net",
        PermissionScope::Inspector => "inspector",
        PermissionScope::Wasi => "wasi",
        PermissionScope::Addon => "addon",
        PermissionScope::Ffi => "ffi",
        PermissionScope::OpenSSLStore => "openssl-store",
        PermissionScope::Env => "env",
    }
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

/// [`deny_worker`] for a call site with a V8 scope, publishing the denial to
/// `node:permission-model:worker` first.
pub fn check_worker<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<AccessDeniedError> {
    let denied = observe(PermissionModel::check_worker)?;
    publish(scope, &denied);
    if is_audit() {
        return None;
    }
    Some(denied)
}

/// Checks loading the named native addon.
pub fn deny_addon(resource: &str) -> Option<AccessDeniedError> {
    evaluate(|model| model.check_addon_named(resource))
}

/// [`deny_addon`] for a call site that has a V8 scope, which also publishes the
/// denial to `node:permission-model:addon`.
///
/// In audit mode this publishes and then returns `None`, because
/// `--permission-audit` checks without denying and the diagnostics message is the
/// only thing the caller can act on. That is the distinction
/// `test-permission-audit-addons-does-not-deny.js` draws: audit mode reaches the
/// real loader, logs the denial, and fails with `ERR_DLOPEN_FAILED` for a missing
/// file rather than `ERR_DLOPEN_DISABLED`.
pub fn check_addon<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    resource: &str,
) -> Option<AccessDeniedError> {
    let denied = observe(|model| model.check_addon_named(resource))?;
    publish(scope, &denied);
    if is_audit() {
        return None;
    }
    Some(denied)
}

/// [`deny_net`] for a call site with a V8 scope, publishing the denial to
/// `node:permission-model:net` first.
pub fn check_net<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    resource: &str,
) -> Option<AccessDeniedError> {
    let denied = observe(|model| model.check_net(resource))?;
    publish(scope, &denied);
    if is_audit() {
        return None;
    }
    Some(denied)
}

/// Checks instantiating WASI.
pub fn deny_wasi() -> Option<AccessDeniedError> {
    evaluate(PermissionModel::check_wasi)
}

/// Checks opening a network server or socket.
///
/// `resource` is the host (or socket path) as written. The `&str` is only
/// dereferenced when the model is installed and enforcing, so a caller that has
/// the text anyway — `tcp_wrap`'s connect, which already parsed it — pays
/// nothing extra on a run without `--permission`, and nothing allocates.
pub fn deny_net(resource: &str) -> Option<AccessDeniedError> {
    evaluate(|model| model.check_net(resource))
}

/// The descriptor of this process's IPC channel, if it has one.
///
/// `LibuvStreamWrap::IsProcessStdioOrIPCChannel` exempts the standard streams and
/// the IPC channel from the `net` check, because adopting them is how a fork or
/// cluster child talks to its parent and Node has already granted that channel
/// by handing it over. `-1` means there is no channel, which is what a process
/// started without `--ipc` sees.
pub fn ipc_channel_fd() -> i32 {
    IPC_CHANNEL_FD.with(|slot| *slot.borrow())
}

/// Records the IPC channel's descriptor for [`ipc_channel_fd`].
///
/// The child-process layer sets this once when it creates the channel. Nothing
/// calls it yet: rustnode's fork has no IPC channel, so the exemption currently
/// covers only `fd <= 2`.
pub fn set_ipc_channel_fd(fd: i32) {
    IPC_CHANNEL_FD.with(|slot| {
        *slot.borrow_mut() = fd;
    });
}

/// Whether adopting `fd` is allowed without the `net` permission.
///
/// Port of `LibuvStreamWrap::IsProcessStdioOrIPCChannel`.
pub fn is_process_stdio_or_ipc_channel(fd: i32) -> bool {
    fd >= 0 && (fd <= 2 || fd == ipc_channel_fd())
}

/// Whether the installed model is enforcing `addon` and has not granted it.
///
/// This is the half of `Environment::no_native_addons()` that comes from the
/// permission model rather than from `--addons`: `InitializePermission` clears
/// `options_->allow_native_addons` when `--permission` was given without
/// `--allow-addons`, and *not* in audit mode, where the denial has to be
/// published by the `addon` check instead.
///
/// `false` when no model is installed, which keeps a bare binding harness able to
/// load addons the way Node's default does.
pub fn enforces_addon_without_grant() -> bool {
    MODEL.with(|slot| {
        let slot = slot.borrow();
        let Some(model) = slot.as_ref() else {
            return false;
        };
        model.is_enabled() && !model.is_audit() && !model.has(PermissionScope::Addon, None)
    })
}

/// Checks enabling the inspector.
pub fn deny_inspector() -> Option<AccessDeniedError> {
    evaluate(PermissionModel::check_inspector)
}

/// [`deny_inspector`] for a call site with a V8 scope, publishing the denial to
/// `node:permission-model:inspector` first.
///
/// `resource` is Node's name for the internal entry point — `"StartIoThread"`,
/// `"WaitForConnect"` and so on — rather than anything the caller supplied.
pub fn check_inspector<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    resource: &str,
) -> Option<AccessDeniedError> {
    let denied = observe(|model| model.check_inspector_named(resource))?;
    publish(scope, &denied);
    if is_audit() {
        return None;
    }
    Some(denied)
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

/// What reading `name` should report, given the permission model.
///
/// This is the pair of questions `EnvGetter` and `EnvQuery` ask before they
/// answer, and the answer differs by mode:
///
/// * **Enforcing** (`Report`): if the startup scrub removed `name`, the read
///   still answers "absent", but the denial is published to
///   `node:permission-model:env` and the removal is warned about once.
/// * **Audit** (`Report`): nothing was removed, so the real value is returned,
///   and an access to a name enforcing *would* have removed is published
///   without a warning.
/// * **Disabled** (`Nothing`): no model, nothing to report.
///
/// The caller decides whether to publish, because publishing runs JavaScript
/// and only the interceptor has a scope to do it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvReadReport {
    /// No model, or the model is neither enforcing nor auditing.
    Nothing,
    /// The variable was removed at startup and the read must look absent.
    Removed {
        denied: AccessDeniedError,
        /// Whether this read gets the one-time warning.
        ///
        /// `ShouldWarnAboutRemovedEnvVar` consumes the warning, so it is
        /// answered here rather than by the caller: asking twice would consume
        /// it twice and the second read would never warn.
        warn: bool,
    },
    /// Audit mode: the value is real, but the access is a denial under
    /// enforcement.
    Audited { denied: AccessDeniedError },
}

/// Classifies a read of `name`, as `EnvGetter`/`EnvQuery` do.
pub fn inspect_env_read(name: &str) -> EnvReadReport {
    let Some(model) = shared() else {
        return EnvReadReport::Nothing;
    };
    if !model.is_enabled() {
        return EnvReadReport::Nothing;
    }
    let denied = AccessDeniedError::new(AccessDenied::new(PermissionScope::Env, name));
    if model.is_audit() {
        // `AuditEnvVar` publishes only for a name that was denied at startup,
        // which `record_removed_env_vars` did *not* record in audit mode — so
        // the record is the only thing that can answer, and a name the model
        // simply does not grant is not reported.
        return if was_denied_at_startup(name) {
            EnvReadReport::Audited { denied }
        } else {
            EnvReadReport::Nothing
        };
    }
    if model.env_var_was_removed(name) {
        // `ReportRemovedEnvVar` publishes every time and warns once, and the
        // warning is what `take_removed_env_var_warning` hands to
        // `pre_execution.js`'s `warnAboutRemovedProxyEnvVars`.
        return EnvReadReport::Removed {
            denied,
            warn: model.take_removed_env_var_warning(name),
        };
    }
    EnvReadReport::Nothing
}

/// Whether audit mode recorded `name` as one that enforcing would remove.
///
/// `WasDeniedAtStartup` in `permission/env_permission.cc`: true when either the
/// scrub or the audit pass put the name in `denied`. Unlike
/// [`PermissionModel::env_var_was_removed`] it therefore answers in audit mode
/// too, which is the mode it exists for.
fn was_denied_at_startup(name: &str) -> bool {
    AUDITED.with(|slot| slot.borrow().as_ref().is_some_and(|set| set.contains(name)))
}

/// Records the names the audit pass would have removed.
///
/// Called by the CLI after `rn_permission::env::record_audited`, which is the
/// Rust side of `RecordAuditedEnvironmentVariables`.
pub fn record_audited_env_vars<I, S>(names: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let set: std::collections::BTreeSet<String> = names
        .into_iter()
        .map(|name| crate::model::normalize_env_name(name.as_ref()))
        .collect();
    AUDITED.with(|slot| {
        *slot.borrow_mut() = Some(set);
    });
}

/// Whether reading `name` is denied by the permission model.
///
/// Enforcing a read is not about throwing — `process.env.X` never throws for a
/// removed variable — it is about the *value*: a removed variable reads as
/// absent, which is why `EnvGetter` returns `kNo` for it and the ordinary
/// missing-property path answers `undefined`.
pub fn env_read_is_denied(name: &str) -> bool {
    shared().is_some_and(|model| model.is_enabled() && model.env_var_was_removed(name))
}

/// Publishes a denial to `node:permission-model:env`.
///
/// Exposed so the `process.env` interceptor can report a read without knowing
/// how the channel is reached.
pub fn publish_env_denial(scope: &mut v8::PinScope<'_, '_>, denied: &AccessDeniedError) {
    publish(scope, denied);
}

thread_local! {
    /// The names the audit pass recorded, from `record_audited_env_vars`.
    static AUDITED: RefCell<Option<std::collections::BTreeSet<String>>> =
        const { RefCell::new(None) };
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
    fn a_read_of_a_removed_variable_reports_and_warns_once() {
        // `EnvGetter`/`EnvQuery`'s pair of questions: publish every time, warn
        // once. `test-permission-env-warning.js` counts three publications for
        // two reads and one `in` check, and exactly one warning.
        let model = install_model("/work", PermissionConfig::enforce());
        model.record_removed_env_vars(["PERMISSION_ENV_SECRET"]);

        assert!(env_read_is_denied("PERMISSION_ENV_SECRET"));

        match inspect_env_read("PERMISSION_ENV_SECRET") {
            EnvReadReport::Removed { denied, warn } => {
                assert_eq!(denied.permission(), "Env");
                assert_eq!(denied.resource(), "PERMISSION_ENV_SECRET");
                assert!(warn, "the first read warns");
            }
            other => panic!("expected Removed, got {other:?}"),
        }
        match inspect_env_read("PERMISSION_ENV_SECRET") {
            EnvReadReport::Removed { warn, .. } => {
                assert!(!warn, "the second read must not warn again");
            }
            other => panic!("expected Removed, got {other:?}"),
        }
        // A variable the model does not grant but never removed is not reported:
        // `ReportRemovedEnvVar` asks `WasRemovedByEnvironmentScrub` first.
        assert_eq!(inspect_env_read("RN_NEVER_SET"), EnvReadReport::Nothing);
        assert!(!env_read_is_denied("RN_NEVER_SET"));
    }

    #[test]
    fn audit_mode_reports_a_read_but_removes_nothing() {
        // Audit mode's `AuditEnvVar` reports only names the enforcing model
        // would have taken away, which is why the CLI has to record them
        // separately: `record_removed_env_vars` is a no-op in audit mode.
        install_model("/work", PermissionConfig::audit());
        record_audited_env_vars(["PERMISSION_ENV_SECRET"]);
        assert_eq!(
            inspect_env_read("PERMISSION_ENV_SECRET"),
            EnvReadReport::Audited {
                denied: AccessDeniedError::new(AccessDenied::new(
                    PermissionScope::Env,
                    "PERMISSION_ENV_SECRET"
                )),
            }
        );
        // An allowed variable, and one created at runtime, report nothing.
        assert_eq!(
            inspect_env_read("PERMISSION_ENV_ALLOWED"),
            EnvReadReport::Nothing
        );
        assert_eq!(
            inspect_env_read("PERMISSION_ENV_RUNTIME"),
            EnvReadReport::Nothing
        );
        // And nothing is denied: the value must still be readable.
        assert!(!env_read_is_denied("PERMISSION_ENV_SECRET"));
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

    #[test]
    fn net_and_addon_deny_by_default_and_allow_when_granted() {
        let model = install_model("/work", PermissionConfig::enforce());
        let denied = deny_net("example.com").expect("denied");
        assert_eq!(denied.permission(), "Net");
        assert_eq!(denied.resource(), "example.com");
        assert_eq!(
            denied.message(),
            "Access to this API has been restricted. Use --allow-net to manage permissions."
        );
        assert!(deny_addon("").is_some());

        model.grant_fs(PermissionScope::Net, "");
        model.grant_fs(PermissionScope::Addon, "");
        assert!(deny_net("example.com").is_none());
        assert!(deny_addon("").is_none());
    }

    #[test]
    fn dropping_net_revokes_it_and_dropping_addon_denies_it_for_good() {
        // `net` is `AllowRevokePermission`; `addon` is `DenyOnlyPermission`,
        // whose `Drop` denies the scope irreversibly.
        let model = install_model("/work", PermissionConfig::enforce());
        model.grant_fs(PermissionScope::Net, "");
        model.grant_fs(PermissionScope::Addon, "");

        model.drop_permission(PermissionScope::Net, "");
        assert!(deny_net("example.com").is_some());
        model.grant_fs(PermissionScope::Net, "");
        assert!(deny_net("example.com").is_none());

        model.drop_permission(PermissionScope::Addon, "");
        assert!(deny_addon("").is_some());
        model.grant_fs(PermissionScope::Addon, "");
        assert!(deny_addon("").is_some());
    }

    #[test]
    fn the_ipc_channel_and_standard_streams_are_exempt_from_net() {
        clear();
        set_ipc_channel_fd(-1);
        for fd in 0..=2 {
            assert!(is_process_stdio_or_ipc_channel(fd), "fd {fd}");
        }
        assert!(!is_process_stdio_or_ipc_channel(3));
        assert!(!is_process_stdio_or_ipc_channel(-1));

        // The descriptor is whatever `NODE_CHANNEL_FD` named at startup, which is
        // how a fork child's channel avoids the check.
        set_ipc_channel_fd(7);
        assert!(is_process_stdio_or_ipc_channel(7));
        assert!(!is_process_stdio_or_ipc_channel(8));
        // A negative "channel" is not a channel, so nothing is exempt by
        // accident: `fd >= 0` still has to hold.
        set_ipc_channel_fd(-1);
        assert!(!is_process_stdio_or_ipc_channel(-1));
    }

    #[test]
    fn the_addons_loader_is_disabled_only_while_enforcing_an_ungranted_addon() {
        clear();
        // No model: Node's default is that addons load, and a bare binding
        // harness must agree.
        assert!(!enforces_addon_without_grant());

        install_model("/work", PermissionConfig::enforce());
        assert!(enforces_addon_without_grant());

        let model = shared().expect("installed");
        model.grant_fs(PermissionScope::Addon, "");
        assert!(!enforces_addon_without_grant());

        // Audit mode keeps the loader on so the denial can be published.
        install_model("/work", PermissionConfig::audit());
        assert!(!enforces_addon_without_grant());
    }
}
