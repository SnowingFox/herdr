//! `TextEncoder#encodeInto` against a real `node` binary and against the
//! recorded expectations.
//!
//! `tests/encode-into-cases.js` prints one JSON line per case: `read`,
//! `written` and the destination's bytes, which together are the whole
//! observable contract. Two tests consume it, and they answer different
//! questions.
//!
//! * [`the_cases_match_the_recorded_expectations`] compares the in-process
//!   isolate's answers with `tests/encode-into-expected.jsonl`. That file is the
//!   `node` oracle's own output for this script, committed verbatim, so the
//!   expectations cannot drift from the file they are supposed to describe and
//!   a machine without `node` still checks every byte.
//!
//! * [`the_cases_match_a_real_node_binary`] runs the *same* file under `node`
//!   and under the built `rustnode` binary and requires identical stdout. This
//!   is the differential: it is the only check that can catch the two runtimes
//!   disagreeing in a way the recorded expectations happen to share, and it is
//!   the one that would have caught the `encodeInto` defect's siblings. It
//!   skips loudly when `node` is absent rather than failing, because a Rust
//!   workspace is not guaranteed to have one.
//!
//! The reference binary is the oracle `tools/node-pin.toml` pins, resolved by
//! [`rn_node_oracle`], not whatever `node` is on `PATH`: `encodeInto` is a
//! `TextEncoder` implementation detail that has changed between Node versions,
//! so a released Node on `PATH` is a different reference rather than a weaker
//! one. With no oracle this differential skips loudly; with a wrong-version one
//! it fails.

use std::path::PathBuf;
use std::process::Command;

use rn_bind_encoding::EncodingBinding;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// The probe script, shared with the two `Command`-driven tests below.
const CASES: &str = include_str!("encode-into-cases.js");
/// The `node` oracle's stdout for [`CASES`], committed.
const EXPECTED: &str = include_str!("encode-into-expected.jsonl");

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cases_path() -> PathBuf {
    crate_dir().join("tests").join("encode-into-cases.js")
}

/// The `rustnode` binary, which `tools/check.sh` builds before the tests run.
fn rustnode_binary() -> PathBuf {
    let mut path = crate_dir();
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

/// Runs `CASES` inside a fresh isolate with the binding installed.
///
/// V8's platform is process-global, so the caller owns initialisation; this
/// only sets up an isolate and a context with the namespace on the global.
fn run_in_isolate() -> String {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = EncodingBinding
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("the encoding binding installs");

    let global = context.global(scope);
    let key = v8::String::new(scope, "__encodingBinding").expect("key");
    global
        .set(scope, key.into(), binding.into())
        .expect("binds the namespace");

    // `console.log` is what the probe calls, and a bare isolate has none.
    let console_shim = v8::String::new(
        scope,
        r#"
        globalThis.console = {
          log(message) { globalThis.__out.push(String(message)); },
        };
        globalThis.__out = [];
        "#,
    )
    .expect("console shim");
    let script = v8::Script::compile(scope, console_shim, None).expect("compiles");
    script.run(scope).expect("console shim runs");

    let source = v8::String::new(scope, CASES).expect("cases");
    let script = v8::Script::compile(scope, source, None).expect("compiles");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    if script.run(scope).is_none() || scope.has_caught() {
        let exception = scope
            .exception()
            .map(|value| value.to_rust_string_lossy(scope))
            .unwrap_or_else(|| "unknown exception".to_string());
        panic!("the probe threw: {exception}");
    }

    let collected = v8::String::new(scope, "__out").expect("key");
    let out = global.get(scope, collected.into()).expect("__out");
    let out = v8::Local::<v8::Array>::try_from(out).expect("__out is an array");
    let mut lines = String::new();
    for index in 0..out.length() {
        let line = out.get_index(scope, index).expect("element");
        lines.push_str(&line.to_rust_string_lossy(scope));
        lines.push('\n');
    }
    lines
}

/// One JSON object per line, parsed loosely: only `name` and the fields that
/// matter for a readable diff are compared, and the raw line is the fallback.
fn normalize(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect()
}

#[test]
fn the_cases_match_the_recorded_expectations() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let actual = normalize(&run_in_isolate());
    let expected = normalize(EXPECTED);
    assert_eq!(
        actual.len(),
        expected.len(),
        "the probe printed {} cases, the expectations hold {}",
        actual.len(),
        expected.len()
    );
    let mut failures = Vec::new();
    for (index, (actual, expected)) in actual.iter().zip(expected.iter()).enumerate() {
        if actual != expected {
            failures.push(format!(
                "case {index}:\n  expected {expected}\n  actual   {actual}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ from the recorded `node` output:\n{}",
        failures.len(),
        expected.len(),
        failures.join("\n")
    );
    // The cases are only worth their count if the table covers what it claims
    // to. These are the shapes the defect report named; losing one silently
    // would leave the boundary untested.
    for required in [
        "exact-ascii",
        "short-by-1-ascii",
        "zero-dest",
        "astral-short-by-1",
        "mixed-exact",
        "empty-source",
        "detached-dest",
    ] {
        assert!(
            expected
                .iter()
                .any(|line| line.contains(&format!("\"name\":\"{required}\""))),
            "the case table no longer covers {required}"
        );
    }
}

#[test]
fn the_cases_match_the_pinned_oracle() {
    let Some(oracle) = rn_node_oracle::require_oracle("rn-bind-encoding encodeInto") else {
        return;
    };
    let node_version = oracle.version.clone();

    let run = |binary: &std::path::Path, arguments: &[&str]| -> std::process::Output {
        Command::new(binary)
            .args(arguments)
            .arg(cases_path())
            .output()
            .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()))
    };

    let reference = run(&oracle.path, &[]);
    assert!(
        reference.status.success(),
        "{} failed: {}",
        oracle.describe(),
        String::from_utf8_lossy(&reference.stderr)
    );

    let rustnode = rustnode_binary();
    assert!(
        rustnode.exists(),
        "{} is missing; tools/check.sh builds it before the tests",
        rustnode.display()
    );
    let candidate = run(&rustnode, &[]);
    assert!(
        candidate.status.success(),
        "rustnode failed: {}",
        String::from_utf8_lossy(&candidate.stderr)
    );

    let reference = normalize(&String::from_utf8_lossy(&reference.stdout));
    let candidate = normalize(&String::from_utf8_lossy(&candidate.stdout));
    assert_eq!(
        reference.len(),
        candidate.len(),
        "node {node_version} printed {} cases, rustnode printed {}",
        reference.len(),
        candidate.len()
    );
    let mut failures = Vec::new();
    for (index, (reference, candidate)) in reference.iter().zip(candidate.iter()).enumerate() {
        if reference != candidate {
            failures.push(format!(
                "case {index}:\n  node {node_version} {reference}\n  rustnode          {candidate}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ from {}\n{}",
        failures.len(),
        reference.len(),
        oracle.describe(),
        failures.join("\n")
    );
}
