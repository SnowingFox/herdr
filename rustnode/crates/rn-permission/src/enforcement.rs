//! Turning a denial into the JavaScript error Node throws.
//!
//! `CreateAccessDeniedError` in `src/permission/permission.cc` builds an
//! ordinary `Error` whose message is `ERR_ACCESS_DENIED`'s template plus the
//! flag suggestion, then sets two own properties on it:
//!
//! ```text
//! err.code       = 'ERR_ACCESS_DENIED'   (set by node::Err)
//! err.permission = 'FileSystemRead'      (set by the permission model)
//! err.resource   = '/etc/passwd'
//! ```
//!
//! `lib/internal/errors.js` has the matching constructor:
//!
//! ```js
//! E('ERR_ACCESS_DENIED', function(msg, permission = '', resource = '') {
//!   this.permission = permission;
//!   this.resource = resource;
//!   return msg;
//! }, Error);
//! ```
//!
//! so the two sides agree field for field. Other crates hold a
//! [`PermissionGate`] and call a `deny_*` method; a `Some` result means
//! "denied, throw this", `None` means "allowed".

use rn_v8_sys::v8;

use crate::model::{AccessDenied, PermissionModel, PermissionShared};

/// The error code every denial carries.
pub const ERR_ACCESS_DENIED: &str = "ERR_ACCESS_DENIED";

/// A denial, ready to become a JavaScript value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDeniedError {
    error: AccessDenied,
}

impl AccessDeniedError {
    pub fn new(error: AccessDenied) -> Self {
        Self { error }
    }

    pub fn code(&self) -> &'static str {
        self.error.code()
    }

    pub fn permission(&self) -> &'static str {
        self.error.permission()
    }

    pub fn resource(&self) -> &str {
        self.error.resource()
    }

    pub fn message(&self) -> String {
        self.error.message()
    }

    /// The scope that was denied, for callers that need to branch on it.
    pub fn scope(&self) -> crate::model::PermissionScope {
        self.error.scope
    }

    /// Builds the JavaScript error and schedules it, the equivalent of
    /// `THROW_IF_INSUFFICIENT_PERMISSIONS`'s `ThrowAccessDenied`.
    ///
    /// Returns the undefined value `throw_exception` produces so a callback can
    /// `return` it directly.
    pub fn throw<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
        let error = self.to_value(scope);
        scope.throw_exception(error)
    }

    /// Builds the error object without throwing it, for callbacks that reject a
    /// promise or hand the error to a callback instead.
    pub fn to_value<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
        let message = v8::String::new(scope, &self.message());
        let error = match message {
            Some(message) => v8::Exception::error(scope, message),
            // A failed allocation leaves V8 with an exception pending; return
            // null rather than a half-built object.
            None => return v8::null(scope).into(),
        };

        if let Ok(object) = v8::Local::<v8::Object>::try_from(error) {
            set_string_property(scope, object, "code", self.code());
            set_string_property(scope, object, "permission", self.permission());
            set_string_property(scope, object, "resource", self.resource());
        }

        error
    }
}

fn set_string_property(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: &str,
) {
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    let Some(value) = v8::String::new(scope, value) else {
        return;
    };
    object.set(scope, key.into(), value.into());
}

/// The enforcement half of the model, handed to binding crates.
///
/// `PermissionGate::disabled()` is the common case and every method is a
/// no-op on it, so a crate can hold a gate unconditionally instead of
/// threading an `Option` through its call sites.
#[derive(Debug, Clone, Default)]
pub struct PermissionGate {
    model: Option<PermissionShared>,
}

impl PermissionGate {
    /// A gate that allows everything.
    pub fn disabled() -> Self {
        Self { model: None }
    }

    /// A gate backed by a model shared with `internalBinding('permission')`.
    pub fn new(model: PermissionShared) -> Self {
        Self { model: Some(model) }
    }

    /// A gate from a model this gate takes ownership of.
    pub fn from_model(model: PermissionModel) -> Self {
        Self {
            model: Some(std::sync::Arc::new(model)),
        }
    }

    pub fn model(&self) -> Option<&PermissionShared> {
        self.model.as_ref()
    }

    pub fn is_enabled(&self) -> bool {
        self.model.as_ref().is_some_and(|model| model.is_enabled())
    }

    /// `--permission-audit`: the model reports denials but the caller must not
    /// enforce them.
    pub fn is_audit(&self) -> bool {
        self.model.as_ref().is_some_and(|model| model.is_audit())
    }

    /// Whether a denial should actually be raised.
    fn enforces(&self) -> bool {
        self.model
            .as_ref()
            .is_some_and(|model| model.is_enabled() && !model.is_audit())
    }

    fn evaluate(&self, result: Result<(), AccessDenied>) -> Option<AccessDeniedError> {
        match result {
            Ok(()) => None,
            Err(error) => {
                if self.enforces() {
                    Some(AccessDeniedError::new(error))
                } else {
                    None
                }
            }
        }
    }

    /// Checks a filesystem read; `Some` means the caller must deny.
    pub fn deny_fs_read(&self, path: &str) -> Option<AccessDeniedError> {
        let model = self.model.as_ref()?;
        self.evaluate(model.check_fs_read(path))
    }

    /// Checks a filesystem write; `Some` means the caller must deny.
    pub fn deny_fs_write(&self, path: &str) -> Option<AccessDeniedError> {
        let model = self.model.as_ref()?;
        self.evaluate(model.check_fs_write(path))
    }

    /// Checks spawning a child process. `resource` is the executable, which
    /// Node puts in the denial's `resource` field.
    pub fn deny_child_process(&self, resource: &str) -> Option<AccessDeniedError> {
        let model = self.model.as_ref()?;
        self.evaluate(model.check_child_process_resource(resource))
    }

    /// Checks creating a worker.
    pub fn deny_worker(&self) -> Option<AccessDeniedError> {
        let model = self.model.as_ref()?;
        self.evaluate(model.check_worker())
    }

    /// Checks loading a native addon.
    pub fn deny_addon(&self, resource: &str) -> Option<AccessDeniedError> {
        let model = self.model.as_ref()?;
        self.evaluate(model.check_addon_named(resource))
    }

    /// Checks instantiating WASI.
    pub fn deny_wasi(&self) -> Option<AccessDeniedError> {
        let model = self.model.as_ref()?;
        self.evaluate(model.check_wasi())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforcing() -> PermissionGate {
        PermissionGate::from_model(PermissionModel::enforcing("/work"))
    }

    #[test]
    fn disabled_gate_allows_everything() {
        let gate = PermissionGate::disabled();
        assert!(!gate.is_enabled());
        assert!(!gate.is_audit());
        assert!(gate.deny_fs_read("/etc/passwd").is_none());
        assert!(gate.deny_fs_write("/etc/passwd").is_none());
        assert!(gate.deny_child_process("/bin/sh").is_none());
        assert!(gate.deny_worker().is_none());
        assert!(gate.deny_addon("").is_none());
        assert!(gate.deny_wasi().is_none());
    }

    #[test]
    fn enforcing_gate_denies_by_default() {
        let gate = enforcing();
        assert!(gate.is_enabled());
        let denied = gate.deny_fs_read("/etc/passwd").expect("denied");
        assert_eq!(denied.code(), "ERR_ACCESS_DENIED");
        assert_eq!(denied.permission(), "FileSystemRead");
        assert_eq!(denied.resource(), "/etc/passwd");
    }

    #[test]
    fn audit_gate_reports_but_does_not_deny() {
        let gate = PermissionGate::from_model(PermissionModel::with_cwd(
            "/work",
            crate::model::PermissionConfig::audit(),
        ));
        assert!(gate.is_enabled());
        assert!(gate.is_audit());
        assert!(gate.deny_fs_read("/etc/passwd").is_none());
        assert!(gate.deny_child_process("/bin/sh").is_none());
    }

    #[test]
    fn a_granted_scope_passes() {
        let gate = PermissionGate::from_model(PermissionModel::with_cwd(
            "/work",
            crate::model::PermissionConfig {
                allow_fs_read: vec!["*".to_string()],
                allow_child_process: true,
                ..crate::model::PermissionConfig::enforce()
            },
        ));
        assert!(gate.deny_fs_read("/etc/passwd").is_none());
        assert!(gate.deny_child_process("/bin/sh").is_none());
        assert!(gate.deny_fs_write("/etc/passwd").is_some());
    }

    #[test]
    fn the_denial_message_names_the_managing_flag() {
        let gate = enforcing();
        assert_eq!(
            gate.deny_child_process("/usr/bin/git").unwrap().message(),
            "Access to this API has been restricted. Use --allow-child-process to manage permissions."
        );
        assert_eq!(
            gate.deny_addon("").unwrap().message(),
            "Access to this API has been restricted. Use --allow-addons to manage permissions."
        );
        assert_eq!(
            gate.deny_wasi().unwrap().message(),
            "Access to this API has been restricted. Use --allow-wasi to manage permissions."
        );
    }
}
