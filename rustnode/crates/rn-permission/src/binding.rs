//! `internalBinding('permission')`.
//!
//! `lib/internal/process/permission.js` reads this binding and wraps it:
//!
//! ```text
//! permission.has(scope, reference)   -> is this scope/resource granted?
//! permission.drop(scope, reference)  -> revoke a grant, irreversibly
//! permission.takeRemovedEnvVarWarning(name)
//! ```
//!
//! The JavaScript side has already validated `scope` and normalised
//! `reference` (URLs to file paths for `fs.*`, `Uint8Array` passed through
//! raw), so the binding only converts the reference and answers.
//!
//! The model is stored in the V8 context, not in a global: two isolates, or two
//! contexts in one isolate, each get their own. The context owns its slot, so a
//! torn-down context cannot leave a model behind for another one to find.

use std::rc::Rc;
use std::sync::Arc;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::model::{PermissionModel, PermissionScope, PermissionShared};

/// The members `lib/internal/process/permission.js` touches.
pub const MEMBERS: &[&str] = &["has", "drop", "takeRemovedEnvVarWarning"];

/// Lets one `Arc<PermissionModel>` be reachable from a V8 context slot, which
/// only accepts `Rc`.
///
/// The binding holds the same model the enforcement gates hold, so
/// `process.permission.drop()` revokes access for the native checks too.
struct ModelSlot(PermissionShared);

/// `internalBinding('permission')`.
pub struct PermissionBinding {
    model: PermissionShared,
}

impl PermissionBinding {
    /// Builds the binding around an existing model, so the same grants answer
    /// both `process.permission.has()` and the enforcement helpers.
    pub fn new(model: PermissionShared) -> Self {
        Self { model }
    }

    /// Builds the binding from a model it takes ownership of.
    pub fn from_model(model: PermissionModel) -> Self {
        Self::new(Arc::new(model))
    }

    pub fn model(&self) -> &PermissionShared {
        &self.model
    }
}

impl BindingModule for PermissionBinding {
    fn namespace(&self) -> &'static str {
        "permission"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        scope
            .get_current_context()
            .set_slot(Rc::new(ModelSlot(Arc::clone(&self.model))));

        let object = v8::Object::new(scope);

        install_member(scope, object, "has", has_callback)?;
        install_member(scope, object, "drop", drop_callback)?;
        install_member(
            scope,
            object,
            "takeRemovedEnvVarWarning",
            take_removed_env_var_warning_callback,
        )?;

        // Node freezes the binding object. `lib/**` relies on it not changing
        // under it, and it stops user code swapping `has` for a stub.
        object.set_integrity_level(scope, v8::IntegrityLevel::Frozen);

        Ok(object)
    }
}

/// Defines one callback on the binding object.
fn install_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let function = v8::FunctionTemplate::builder(callback)
        .build(scope)
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate permission.{name}"))?;
    let key = v8::String::new(scope, name)
        .ok_or_else(|| format!("cannot allocate permission.{name} name"))?;
    object
        .set(scope, key.into(), function.into())
        .ok_or_else(|| format!("cannot define permission.{name}"))?;
    Ok(())
}

fn model_from_scope(scope: &v8::PinScope<'_, '_>) -> Option<PermissionShared> {
    let slot = scope.get_current_context().get_slot::<ModelSlot>()?;
    Some(Arc::clone(&slot.0))
}

/// Converts a reference argument into the text the model compares.
///
/// `lib/internal/process/permission.js` forwards `Uint8Array` unchanged so
/// non-UTF-8 paths survive the trip, which is why a view is read as bytes
/// rather than stringified.
fn reference_text(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<String> {
    if value.is_undefined() || value.is_null() {
        return None;
    }
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let mut buffer = vec![0u8; view.byte_length()];
        let written = view.copy_contents(&mut buffer);
        buffer.truncate(written);
        return Some(String::from_utf8_lossy(&buffer).into_owned());
    }
    let string = value.to_string(scope)?;
    Some(string.to_rust_string_lossy(scope))
}

fn string_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments,
    index: i32,
) -> Option<String> {
    args.get(index)
        .to_string(scope)
        .map(|string| string.to_rust_string_lossy(scope))
}

/// `permission.has(scope[, reference])`.
///
/// Answers `false` for an unknown scope and for an empty reference, matching
/// the C++ `Has()`: the permissions root is not a scope, and an empty path is
/// not a substring of every grant.
fn has_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let granted = model_from_scope(scope).is_some_and(|model| {
        let label = string_argument(scope, &args, 0).unwrap_or_default();
        let Some(permission) = PermissionScope::from_label(&label) else {
            return false;
        };
        match reference_text(scope, args.get(1)) {
            Some(reference) if reference.is_empty() => false,
            Some(reference) => model.has(permission, Some(&reference)),
            None => model.has(permission, None),
        }
    });
    rv.set_bool(granted);
}

/// `permission.drop(scope[, reference])`. Dropping the permissions root is a
/// no-op, as in the C++ implementation.
fn drop_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let Some(model) = model_from_scope(scope) else {
        return;
    };
    let label = string_argument(scope, &args, 0).unwrap_or_default();
    let Some(permission) = PermissionScope::from_label(&label) else {
        return;
    };
    let reference = reference_text(scope, args.get(1)).unwrap_or_default();
    model.drop_permission(permission, &reference);
}

/// `permission.takeRemovedEnvVarWarning(name)`.
///
/// Answers whether the environment scope removed `name` at startup and no
/// warning has been emitted for it yet, recording that one now is.
fn take_removed_env_var_warning_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let warning = model_from_scope(scope).is_some_and(|model| {
        let name = string_argument(scope, &args, 0).unwrap_or_default();
        model.take_removed_env_var_warning(&name)
    });
    rv.set_bool(warning);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn binding_declares_the_members_the_js_layer_reads() {
        let binding = PermissionBinding::from_model(PermissionModel::disabled());
        assert_eq!(binding.namespace(), "permission");
        let declared: BTreeSet<&str> = binding.members().iter().copied().collect();
        let expected: BTreeSet<&str> = ["has", "drop", "takeRemovedEnvVarWarning"]
            .into_iter()
            .collect();
        assert_eq!(declared, expected);
    }

    #[test]
    fn binding_shares_the_gate_model() {
        let model = Arc::new(PermissionModel::with_cwd(
            "/work",
            crate::model::PermissionConfig {
                allow_fs_read: vec!["*".to_string()],
                ..crate::model::PermissionConfig::enforce()
            },
        ));
        let gate = crate::enforcement::PermissionGate::new(Arc::clone(&model));
        let binding = PermissionBinding::new(Arc::clone(&model));

        assert!(gate.deny_fs_read("/etc/passwd").is_none());
        // Dropping through the binding must be visible to the gate, because
        // both point at one model.
        model.drop_permission(PermissionScope::FileSystemRead, "");
        assert!(gate.deny_fs_read("/etc/passwd").is_some());
        assert!(!binding.model().has(PermissionScope::FileSystemRead, None));
    }
}
