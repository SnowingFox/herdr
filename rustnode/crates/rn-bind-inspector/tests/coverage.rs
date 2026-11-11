//! `internalBinding('profiler')`: coverage that produces a file Node's reader accepts.
//!
//! The distinction this file exists to pin: a `takeCoverage` that returns without
//! error and writes nothing is indistinguishable from one that works, until someone
//! runs `--experimental-test-coverage` and gets an empty report. So every test here
//! checks a file on disk, parses it, and asserts on the hit counts inside.
//!
//! The file shape is the contract: `lib/internal/test_runner/coverage.js` reads
//! `JSON.parse(file).result`, and each entry is `{url, functions: [{ranges: [{count}]}]}`.
//! Node writes exactly the payload V8's `Profiler.takePreciseCoverage` produced, and so
//! does this.

use rn_bind_inspector::Profiler;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Runs `body` with a live isolate, scope and context.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    rn_bind_inspector::set_isolate(&mut isolate);
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let mut scope = scope.init();
    let context = v8::Context::new(&scope, Default::default());
    let scope = std::pin::pin!(v8::ContextScope::new(&mut scope, context));
    let mut scope = scope;
    body(&mut scope)
}

fn init_v8() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the `profiler` namespace and binds it to `__profiler`.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let object = Profiler
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the profiler namespace");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__profiler").expect("allocating __profiler");
    global.set(scope, key.into(), object.into());
}

/// Compiles and runs `source`, panicking with the exception text on a throw.
fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) {
    let text = source;
    let source = v8::String::new(scope, source).expect("allocating the script");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = try_catch.init();
    let script = match v8::Script::compile(&scope, source, None) {
        Some(script) => script,
        None => {
            let message = scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(&scope))
                .unwrap_or_else(|| "no exception reported".to_string());
            panic!("the script must compile: {message}\n--- source ---\n{text}");
        }
    };
    let _ = script.run(&scope);
    if scope.has_caught() {
        let exception = scope.exception().expect("a caught exception");
        panic!(
            "the script threw: {}",
            exception.to_rust_string_lossy(&scope)
        );
    }
}

/// A fresh directory per test, so one test's files cannot satisfy another's assertion.
fn scratch_directory(name: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "rn-inspector-coverage-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

#[test]
fn take_coverage_writes_a_file_node_s_reader_can_parse() {
    let directory = scratch_directory("parse");
    with_context(|scope| {
        install(scope);
        run(
            scope,
            &format!(
                r"__profiler.setCoverageDirectory({path:?});
                  __profiler.setSourceMapCacheGetter(() => undefined);
                  __profiler.startCoverage();
                  function hit(a) {{ return a * 2; }}
                  hit(21);
                  function miss() {{ return 0; }}
                  globalThis.written = __profiler.takeCoverage();",
                path = directory.to_string_lossy()
            ),
        );
        let written = run_to_string(scope, "String(written)");
        assert_eq!(
            written, "1",
            "takeCoverage must report the file it wrote, so a caller can tell an empty \
             collection from a missing directory"
        );

        let files: Vec<_> = std::fs::read_dir(&directory)
            .expect("the coverage directory must exist")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        assert_eq!(files.len(), 1, "one take must write one file: {files:?}");
        let name = files[0]
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a file name");
        // `lib/internal/test_runner/coverage.js` globs `coverage-*.json`, so a file
        // named anything else is collected and then ignored.
        assert!(
            name.starts_with("coverage-") && name.ends_with(".json"),
            "the file name must be the one Node's reader looks for, not {name}"
        );

        let text = std::fs::read_to_string(&files[0]).expect("the coverage file must be readable");
        let parsed: serde_json::Value =
            serde_json::from_str(&text).expect("the coverage file must be JSON");
        // The reader checks `parsed.result`; a `{result: {result: ...}}` wrapper would
        // make every script disappear from the report.
        let scripts = parsed["result"]
            .as_array()
            .unwrap_or_else(|| panic!("the file must carry a `result` array; was {text}"));
        assert!(
            !scripts.is_empty(),
            "the file must describe at least one script; was {text}"
        );

        // The hit counts are the point: a file with every count at zero would parse and
        // report 0% coverage for code that ran.
        let hit = find_function(scripts, "hit")
            .unwrap_or_else(|| panic!("the profile must include `hit`; was {text}"));
        assert_eq!(
            hit["ranges"][0]["count"], 1,
            "`hit` was called once and the profile must say so: {hit}"
        );
    });
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn take_coverage_writes_nothing_without_a_directory() {
    // The honest answer when nobody asked for coverage. Node's
    // `V8CoverageConnection::WriteProfile` returns early in the same situation, and a
    // file in the current directory instead would be litter from a program that never
    // requested coverage.
    with_context(|scope| {
        install(scope);
        run(
            scope,
            "__profiler.startCoverage(); function f() {} f(); \
             globalThis.written = __profiler.takeCoverage();",
        );
        assert_eq!(
            run_to_string(scope, "String(written)"),
            "0",
            "takeCoverage must write nothing when no directory was set"
        );
    });
}

#[test]
fn end_coverage_forgets_the_directory() {
    let directory = scratch_directory("end");
    with_context(|scope| {
        install(scope);
        run(
            scope,
            &format!(
                "__profiler.setCoverageDirectory({:?});",
                directory.to_string_lossy()
            ),
        );
        assert_eq!(
            rn_bind_inspector::coverage_directory().as_deref(),
            Some(directory.as_path()),
            "setCoverageDirectory must record the path"
        );
        run(scope, "__profiler.endCoverage();");
        assert_eq!(
            rn_bind_inspector::coverage_directory(),
            None,
            "endCoverage must clear the directory so a later take writes nothing"
        );
    });
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn start_coverage_twice_does_not_reset_the_counts() {
    let directory = scratch_directory("twice");
    with_context(|scope| {
        install(scope);
        run(
            scope,
            &format!(
                r"__profiler.setCoverageDirectory({path:?});
                  __profiler.setSourceMapCacheGetter(() => undefined);
                  __profiler.startCoverage();
                  function counted() {{ return 1; }}
                  counted();
                  __profiler.startCoverage();
                  globalThis.written = __profiler.takeCoverage();",
                path = directory.to_string_lossy()
            ),
        );
        // A second `startCoverage` that re-enabled precise coverage would discard the
        // counts recorded so far, which reports 0% for code that already ran.
        assert_eq!(run_to_string(scope, "String(written)"), "1");
        let file = std::fs::read_dir(&directory)
            .expect("the coverage directory must exist")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .next()
            .expect("a coverage file");
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&file).expect("readable"))
                .expect("valid JSON");
        let scripts = parsed["result"].as_array().expect("a result array");
        let counted = find_function(scripts, "counted")
            .unwrap_or_else(|| panic!("`counted` must be in the profile"));
        assert_eq!(
            counted["ranges"][0]["count"], 1,
            "a second startCoverage must not reset the counts: {counted}"
        );
    });
    let _ = std::fs::remove_dir_all(&directory);
}

/// The function entry with `name` across every script in a coverage result.
fn find_function<'a>(
    scripts: &'a [serde_json::Value],
    name: &str,
) -> Option<&'a serde_json::Value> {
    scripts.iter().find_map(|script| {
        script["functions"]
            .as_array()?
            .iter()
            .find(|function| function["functionName"] == name)
    })
}

/// Runs `source` and returns its completion value as a string.
fn run_to_string(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let source = v8::String::new(scope, source).expect("allocating the script");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = try_catch.init();
    let script = v8::Script::compile(&scope, source, None).expect("the script must compile");
    script
        .run(&scope)
        .map(|value| value.to_rust_string_lossy(&scope))
        .unwrap_or_default()
}
