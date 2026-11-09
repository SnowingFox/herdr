//! Proves `compileFunction` really compiles Node's vendored sources.
//!
//! The unit tests check the table; this one drives V8 with the same parameters
//! Node's `BuiltinLoader` uses, so a wrong wrapper shows up as a compile failure
//! rather than as a mysterious runtime error later.
//!
//! V8 can be initialized once per process, so every assertion lives in one test
//! sharing one isolate rather than in several tests racing to initialize it.

use rn_js2c::{builtin_by_id, builtin_sources, BuiltinKind};
use rn_v8_sys::v8;

#[test]
fn node_sources_compile_under_node_wrapper_parameters() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();

    let mut compiled = 0;
    let mut failures = Vec::new();
    for builtin in builtin_sources() {
        if matches!(builtin.kind(), BuiltinKind::SourceTextModule) {
            continue;
        }
        match rn_builtins::compile(scope, builtin.id(), builtin.source(), builtin.kind()) {
            Some(_) => compiled += 1,
            None => {
                let detail = scope
                    .exception()
                    .map(|exception| exception.to_rust_string_lossy(scope))
                    .unwrap_or_default();
                failures.push((builtin.id(), detail));
                scope.reset();
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} builtin(s) failed to compile: {:?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
    assert!(compiled > 400, "only {compiled} builtins compiled");

    let util = builtin_by_id("internal/util").expect("internal/util");
    let function = rn_builtins::compile(scope, util.id(), util.source(), util.kind())
        .expect("internal/util compiles");
    let length = function
        .get(
            scope,
            v8::String::new(scope, "length").expect("length key").into(),
        )
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_default();
    assert_eq!(
        length,
        util.parameters().len().to_string(),
        "compiled arity must match the declared wrapper parameters"
    );
}
