//! `contextify.measureMemory` end to end.
//!
//! The promise this member returns is resolved by a task V8 posts to the
//! platform's foreground runner, not by anything JavaScript queued, so a test
//! that only calls it and inspects the promise would hang on the pending state.
//! [`settle`] therefore pumps that queue, which is the same flush
//! `rn_core::platform_tasks::pump_foreground_tasks` performs for the loop.
//!
//! The shape assertions mirror `test/common/measure-memory.js` in Node's suite:
//! `summary` reports only `total`, and `detailed` adds `current` and `other`.
//! That file is the contract the `test-vm-measure-memory*` tests are written
//! against, so a shape that differs here fails those tests even though this
//! binding returned a promise.

use rn_bind_contextify::Contextify;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

fn initialize_once() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Starts a measurement and stores the result on `globalThis.__out`, then pumps
/// V8's platform queue until it settles.
///
/// Returns the JSON-serialized result. Panics with the rejection reason if the
/// measurement rejects, which is a shape difference worth surfacing rather than
/// a timeout.
///
/// The platform flush is the whole point of driving this from Rust rather than
/// through `run`: the promise cannot settle without it, so a test that never
/// pumped would assert against `pending`.
fn measure(mode: &str, execution: &str) -> String {
    initialize_once();
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let mut context_scope = v8::ContextScope::new(scope, context);
    let scope = &mut context_scope;

    let mut async_ids = AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    let namespace = Contextify
        .install(scope, &mut ctx)
        .expect("install contextify");

    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "contextify").expect("key");
    global
        .set(scope, key.into(), namespace.into())
        .expect("set the binding");

    let source = format!(
        r#"
        globalThis.__out = 'pending';
        contextify.measureMemory(
          contextify.constants.measureMemory.mode.{mode},
          contextify.constants.measureMemory.execution.{execution},
        ).then(
          (result) => {{ globalThis.__out = JSON.stringify(result); }},
          (error) => {{ globalThis.__out = 'rejected: ' + error; }},
        );
        "#
    );
    let code = v8::String::new(scope, &source).expect("code");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    v8::Script::compile(scope, code, None)
        .expect("compile")
        .run(scope)
        .expect("run");

    // The measurement's GC task is posted to the foreground runner rather than
    // queued in JavaScript, so the promise cannot settle without this flush. The
    // bound exists so a bug reports itself instead of hanging the test binary.
    let platform = v8::V8::get_current_platform();
    for _ in 0..2_000 {
        v8::Platform::pump_message_loop(&platform, scope.as_ref(), false);
        scope.perform_microtask_checkpoint();

        let global = scope.get_current_context().global(scope);
        let key = v8::String::new(scope, "__out").expect("k");
        let value = global.get(scope, key.into()).expect("__out");
        let text = value.to_rust_string_lossy(scope);
        if text != "pending" {
            return text;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("measureMemory({mode}, {execution}) never settled");
}

/// `result.total` / `result.current` carry `jsMemoryEstimate` and a two-element
/// `jsMemoryRange`, per `assertResultShape`.
fn assert_range_shape(result: &str, field: &str) {
    let needle = format!("\"{field}\":");
    assert!(
        result.contains(&needle),
        "expected `{field}` in the result: {result}"
    );
    assert!(
        result.contains("\"jsMemoryEstimate\":"),
        "expected jsMemoryEstimate in the result: {result}"
    );
    assert!(
        result.contains("\"jsMemoryRange\":["),
        "expected jsMemoryRange in the result: {result}"
    );
}

#[test]
fn summary_reports_only_the_total() {
    // `assertSummaryShape`: `total` exists and `current` does not, which is what
    // separates the two modes in `test/common/measure-memory.js`.
    let result = measure("SUMMARY", "EAGER");
    assert!(
        !result.starts_with("rejected:"),
        "summary measurement rejected: {result}"
    );
    assert_range_shape(&result, "total");
    assert!(
        !result.contains("\"current\":"),
        "summary must not report `current`: {result}"
    );
}

#[test]
fn detailed_reports_the_current_context_and_other_contexts() {
    // `assertSingleDetailedShape`: `total` and `current` are present and `other`
    // is an array. With a single context that array is empty.
    let result = measure("DETAILED", "EAGER");
    assert!(
        !result.starts_with("rejected:"),
        "detailed measurement rejected: {result}"
    );
    assert_range_shape(&result, "total");
    assert_range_shape(&result, "current");
    assert!(
        result.contains("\"other\":["),
        "detailed must report an `other` array: {result}"
    );
}
