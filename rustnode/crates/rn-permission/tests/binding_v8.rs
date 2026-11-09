//! Drives `internalBinding('permission')` through a real V8 isolate.
//!
//! The unit tests above exercise the model directly; this checks the part the
//! JavaScript layer actually touches: the installed object, its frozen state,
//! argument handling for strings and typed arrays, and the denial error shape.
//!
//! V8 can only be initialised once per process, so every test in this file
//! shares one initialised platform through [`with_scope`].

use std::sync::Mutex;
use std::sync::{Arc, Once};

use rn_core::BindingModule;
use rn_permission::enforcement::PermissionGate;
use rn_permission::model::{PermissionConfig, PermissionModel, PermissionScope};
use rn_permission::PermissionBinding;
use rn_v8_sys::v8;

static INIT: Once = Once::new();
static ISOLATE_LOCK: Mutex<()> = Mutex::new(());

/// Runs `body` inside a fresh isolate and context, with `binding` installed and
/// available as the global `permission`.
fn with_scope(binding: PermissionBinding, body: impl FnOnce(&mut v8::PinScope<'_, '_>)) {
    let _guard = ISOLATE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let mut ctx = rn_core::InstallCtx {
        async_ids: &mut rn_core::AsyncIds::default(),
    };
    let object = binding
        .install(scope, &mut ctx)
        .expect("install permission binding");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "permission").expect("key");
    global.set(scope, key.into(), object.into());

    body(scope);
}

/// Evaluates `source` and returns the result as a Rust string, panicking with
/// the JavaScript exception on failure.
fn eval(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let Some(source) = v8::String::new(scope, source) else {
        panic!("cannot allocate script source");
    };
    let Some(script) = v8::Script::compile(scope, source, None) else {
        let exception = scope
            .exception()
            .map(|exception| exception.to_rust_string_lossy(scope))
            .unwrap_or_else(|| "<compile failed>".to_string());
        panic!("javascript did not compile: {exception}");
    };
    match script.run(scope) {
        Some(value) => value.to_rust_string_lossy(scope),
        None => {
            let exception = scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "<no exception>".to_string());
            panic!("javascript threw: {exception}");
        }
    }
}

fn enforcing() -> PermissionModel {
    PermissionModel::enforcing("/work")
}

#[test]
fn exposes_exactly_the_js_members_and_is_frozen() {
    with_scope(PermissionBinding::from_model(enforcing()), |scope| {
        assert_eq!(
            eval(
                scope,
                "Object.getOwnPropertyNames(permission).sort().join(',')",
            ),
            "drop,has,takeRemovedEnvVarWarning"
        );
        assert_eq!(eval(scope, "String(Object.isFrozen(permission))"), "true");
        assert_eq!(
            eval(scope, "typeof permission.has + typeof permission.drop"),
            "functionfunction"
        );
    });
}

#[test]
fn denies_by_default_through_the_binding() {
    with_scope(PermissionBinding::from_model(enforcing()), |scope| {
        assert_eq!(
            eval(
                scope,
                "JSON.stringify([permission.has('fs.read'), permission.has('fs.read', '/etc/passwd'), \
                 permission.has('fs.write', '/etc/passwd'), permission.has('child'), \
                 permission.has('worker'), permission.has('addon'), permission.has('wasi')])",
            ),
            "[false,false,false,false,false,false,false]"
        );
    });
}

#[test]
fn an_unknown_scope_answers_false_instead_of_throwing() {
    with_scope(PermissionBinding::from_model(enforcing()), |scope| {
        assert_eq!(
            eval(
                scope,
                "JSON.stringify([permission.has('nope'), permission.has(''), permission.has('nope', '/x')])",
            ),
            "[false,false,false]"
        );
    });
}

#[test]
fn an_empty_reference_answers_false() {
    with_scope(PermissionBinding::from_model(enforcing()), |scope| {
        assert_eq!(
            eval(
                scope,
                "JSON.stringify([permission.has('fs.read', ''), permission.has('fs.read', undefined)])",
            ),
            "[false,false]"
        );
    });
}

#[test]
fn grants_are_visible_through_the_binding() {
    let model = PermissionModel::with_cwd(
        "/work",
        PermissionConfig {
            allow_fs_read: vec!["/tmp/*".to_string()],
            allow_child_process: true,
            ..PermissionConfig::enforce()
        },
    );
    with_scope(PermissionBinding::from_model(model), |scope| {
        assert_eq!(
            eval(
                scope,
                "JSON.stringify([permission.has('fs.read', '/tmp/x'), \
                 permission.has('fs.read', '/etc/passwd'), permission.has('child'), \
                 permission.has('fs.read')])",
            ),
            // The bare `fs.read` scope is closed: a path grant does not open it.
            "[true,false,true,false]"
        );
    });
}

#[test]
fn a_typed_array_reference_is_read_as_bytes() {
    with_scope(PermissionBinding::from_model(enforcing()), |scope| {
        // `lib/internal/process/permission.js` forwards `Uint8Array` unchanged
        // so non-UTF-8 paths survive; the binding must read the bytes rather
        // than stringify the view.
        assert_eq!(
            eval(
                scope,
                "permission.has('fs.read', new Uint8Array([47, 116, 109, 112, 47, 120]))",
            ),
            "false"
        );
    });

    let model = PermissionModel::with_cwd(
        "/work",
        PermissionConfig {
            allow_fs_read: vec!["/tmp/*".to_string()],
            ..PermissionConfig::enforce()
        },
    );
    with_scope(PermissionBinding::from_model(model), |scope| {
        assert_eq!(
            eval(
                scope,
                "permission.has('fs.read', new Uint8Array([47, 116, 109, 112, 47, 120]))",
            ),
            "true"
        );
    });
}

#[test]
fn drop_through_the_binding_reaches_the_enforcement_gate() {
    let model = Arc::new(PermissionModel::with_cwd(
        "/work",
        PermissionConfig {
            allow_fs_read: vec!["*".to_string()],
            ..PermissionConfig::enforce()
        },
    ));
    let gate = PermissionGate::new(Arc::clone(&model));
    assert!(gate.deny_fs_read("/etc/passwd").is_none());

    // The binding installs the very same `Arc`, which is how a
    // `process.permission.drop()` from JavaScript revokes access for the
    // native checks that share the gate.
    with_scope(PermissionBinding::new(Arc::clone(&model)), |scope| {
        assert_eq!(
            eval(scope, "permission.has('fs.read', '/etc/passwd')"),
            "true"
        );
        eval(scope, "permission.drop('fs.read')");
        assert_eq!(
            eval(scope, "permission.has('fs.read', '/etc/passwd')"),
            "false"
        );
    });

    assert!(gate.deny_fs_read("/etc/passwd").is_some());
}

#[test]
fn drop_of_an_unknown_scope_is_a_no_op() {
    with_scope(PermissionBinding::from_model(enforcing()), |scope| {
        eval(
            scope,
            "permission.drop('nope'); permission.drop('nope', '/x')",
        );
        assert_eq!(eval(scope, "String(1)"), "1");
    });
}

#[test]
fn denial_errors_carry_code_permission_and_resource() {
    let model = PermissionModel::enforcing("/work");
    let denied = model.check_fs_read("/etc/passwd").expect_err("denied");
    let error = rn_permission::enforcement::AccessDeniedError::new(denied);

    with_scope(PermissionBinding::from_model(model), |scope| {
        let value = error.to_value(scope);
        let global = scope.get_current_context().global(scope);
        let key = v8::String::new(scope, "denial").expect("key");
        global.set(scope, key.into(), value);

        assert_eq!(
            eval(
                scope,
                "JSON.stringify({ code: denial.code, permission: denial.permission, \
                 resource: denial.resource, message: denial.message, name: denial.name })",
            ),
            // The shape `lib/internal/errors.js` produces for `ERR_ACCESS_DENIED`.
            r#"{"code":"ERR_ACCESS_DENIED","permission":"FileSystemRead","resource":"/etc/passwd","message":"Access to this API has been restricted. Use --allow-fs-read to manage permissions.","name":"Error"}"#
        );
        // An ordinary `Error`, so `instanceof Error` and the stack work.
        assert_eq!(eval(scope, "String(denial instanceof Error)"), "true");
    });
}

#[test]
fn a_removed_env_var_warns_once() {
    let model = enforcing();
    model.record_removed_env_vars(["HTTP_PROXY"]);
    with_scope(PermissionBinding::from_model(model), |scope| {
        assert_eq!(
            eval(
                scope,
                "JSON.stringify([permission.takeRemovedEnvVarWarning('HTTP_PROXY'), \
                 permission.takeRemovedEnvVarWarning('HTTP_PROXY'), \
                 permission.takeRemovedEnvVarWarning('PATH')])",
            ),
            "[true,false,false]"
        );
    });
}

#[test]
fn two_contexts_get_independent_models() {
    let _guard = ISOLATE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();

    for (index, granted) in [(0, true), (1, false)] {
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        let model = if granted {
            PermissionModel::with_cwd(
                "/work",
                PermissionConfig {
                    allow_fs_read: vec!["*".to_string()],
                    ..PermissionConfig::enforce()
                },
            )
        } else {
            PermissionModel::enforcing("/work")
        };
        let binding = PermissionBinding::from_model(model);
        let mut ctx = rn_core::InstallCtx {
            async_ids: &mut rn_core::AsyncIds::default(),
        };
        let object = binding.install(scope, &mut ctx).expect("install");
        let global = scope.get_current_context().global(scope);
        let key = v8::String::new(scope, "permission").expect("key");
        global.set(scope, key.into(), object.into());

        let expected = if granted { "true" } else { "false" };
        assert_eq!(
            eval(scope, "permission.has('fs.read', '/etc/passwd')"),
            expected,
            "context {index}"
        );
    }
}

#[test]
fn the_model_reports_the_scope_it_denied() {
    let gate = PermissionGate::from_model(PermissionModel::enforcing("/work"));
    let denied = gate.deny_addon("").expect("denied");
    assert_eq!(denied.scope(), PermissionScope::Addon);
    assert_eq!(
        denied.message(),
        "Access to this API has been restricted. Use --allow-addons to manage permissions."
    );
}
