//! `URLPattern` against a real `node` binary and against the recorded
//! expectations.
//!
//! `tests/url-pattern-cases.js` prints one JSON line per case. Two tests consume
//! it, and they answer different questions:
//!
//! * [`the_cases_match_the_recorded_expectations`] compares the in-process
//!   isolate's answers with `tests/url-pattern-expected.jsonl`.
//! * [`the_cases_match_a_real_node_binary`] runs the *same* file under the
//!   pinned `node` oracle and under the built `rustnode` binary and requires
//!   identical stdout.
//!
//! The second is the one that matters for this crate. The defect it was written
//! for — component getters landing as `undefined`-valued data properties — was
//! invisible to every member-level check, because the member existed and was
//! callable. Only running the getter and reading the descriptor finds it.
//!
//! The first exists so a machine without `node` still checks every byte, and so
//! a *change* in behaviour is a diff rather than a silent pass.

use std::path::PathBuf;
use std::process::Command;

use rn_bind_url_pattern::UrlPattern;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// The probe script, shared with the `Command`-driven test below.
const CASES: &str = include_str!("url-pattern-cases.js");
/// The oracle's stdout for [`CASES`], committed verbatim.
const EXPECTED: &str = include_str!("url-pattern-expected.jsonl");

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cases_path() -> PathBuf {
    crate_dir().join("tests").join("url-pattern-cases.js")
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
/// The probe needs `require`, which a bare isolate has no way to provide, so the
/// namespace object is published as `__urlPattern` and the script's `require` is
/// shimmed to hand it back. That keeps the case file identical to the one the
/// oracle runs, which is the whole point of the comparison.
fn run_in_isolate() -> String {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = UrlPattern
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("the url_pattern binding installs");

    let global = context.global(scope);
    let key = v8::String::new(scope, "__urlPattern").expect("key");
    global
        .set(scope, key.into(), binding.into())
        .expect("binds the namespace");

    // `console.log` is what the probe calls, `require` is how it reaches the
    // binding, and `globalThis` needs the constructor installed the way
    // `rn-realm` does it so the global cases have something to observe.
    let shim = v8::String::new(
        scope,
        r#"
        globalThis.__out = [];
        globalThis.console = {
          log(message) { globalThis.__out.push(String(message)); },
        };
        globalThis.require = (id) => {
          if (id !== "url") throw new Error("unexpected require: " + id);
          return { URLPattern: globalThis.__urlPattern.URLPattern };
        };
        Object.defineProperty(globalThis, "URLPattern", {
          value: globalThis.__urlPattern.URLPattern,
          writable: true,
          enumerable: false,
          configurable: true,
        });
        "#,
    )
    .expect("shim");
    let script = v8::Script::compile(scope, shim, None).expect("compiles");
    script.run(scope).expect("shim runs");

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

fn normalize(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect()
}

/// Initialises V8's process-global platform exactly once.
///
/// `V8::initialize_platform` and `V8::initialize` are process-wide, and calling
/// them a second time panics. Several tests in this binary need an isolate, so
/// they all go through this instead of each initialising their own.
fn initialise_v8() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

#[test]
fn the_cases_match_the_recorded_expectations() {
    initialise_v8();

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

    // Losing one of these silently would leave the exact behaviour this crate
    // was fixed for untested, so they are required to still be present.
    for required in [
        "descriptor-pathname",
        "descriptor-hasRegExpGroups",
        "component-object-form",
        "test-literal-true",
        "exec-named-group-result",
        "global-typeof",
        "global-descriptor",
        "getter-borrowed-receiver",
        "error-port-not-a-number",
        "unicode-group-name",
        "relative-input-no-base",
        "group-order/:a/:b/:c",
    ] {
        assert!(
            expected
                .iter()
                .any(|line| line.contains(&format!("\"name\":\"{required}\""))),
            "the case table no longer covers {required}"
        );
    }
}

/// The two properties the defect was: the components must be *accessors*, and a
/// component must read its own pattern rather than `undefined`.
///
/// This is stated separately from the case table because it is the part of the
/// behaviour a future refactor is most likely to regress without noticing: a
/// data property holding the right value would pass every value comparison while
/// making `pathname` a writable field instead of a read-only accessor.
#[test]
fn the_component_properties_are_accessors_not_data_properties() {
    initialise_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = UrlPattern
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("the url_pattern binding installs");
    let global = context.global(scope);
    let key = v8::String::new(scope, "__urlPattern").expect("key");
    global
        .set(scope, key.into(), binding.into())
        .expect("binds the namespace");

    let shim = v8::String::new(
        scope,
        r#"
        globalThis.__report = [];
        const { URLPattern } = globalThis.__urlPattern;
        for (const name of ["protocol", "username", "password", "hostname",
                            "port", "pathname", "search", "hash"]) {
          const d = Object.getOwnPropertyDescriptor(URLPattern.prototype, name);
          const pattern = new URLPattern({ pathname: "/books/:id" });
          globalThis.__report.push(
            name + " get=" + (d && typeof d.get) +
            " value=" + (d && "value" in d) +
            " readable=" + (pattern[name] !== undefined));
        }
        "#,
    )
    .expect("shim");
    let script = v8::Script::compile(scope, shim, None).expect("compiles");
    script.run(scope).expect("the probe runs");

    let key = v8::String::new(scope, "__report").expect("key");
    let report = global.get(scope, key.into()).expect("__report");
    let report = v8::Local::<v8::Array>::try_from(report).expect("__report is an array");
    assert_eq!(report.length(), 8, "one line per component");

    for index in 0..report.length() {
        let line = report
            .get_index(scope, index)
            .expect("element")
            .to_rust_string_lossy(scope);
        assert!(
            line.contains("get=function"),
            "a component is not an accessor: {line}"
        );
        assert!(
            !line.contains("value=true"),
            "a component is a data property: {line}"
        );
        // The getter must also *work*: an accessor that returns `undefined`
        // would satisfy the descriptor check and still be the original bug.
        assert!(
            line.ends_with("readable=true"),
            "a component read back undefined: {line}"
        );
    }
}

/// The `node` this test compares against.
///
/// The pinned oracle wins over whatever is on `PATH`. An older `node` has a
/// different `URLPattern` (or none), so a packaged v22 would report differences
/// that are not defects.
fn reference_node() -> Option<(PathBuf, String)> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(explicit) = std::env::var("RUSTNODE_ORACLE_NODE") {
        candidates.push(PathBuf::from(explicit));
    }
    candidates.push(
        PathBuf::from("/tmp/oracle-dl")
            .join("node-v28.0.0-nightly20261111e8c1160d20-linux-x64")
            .join("bin")
            .join("node"),
    );

    for candidate in candidates {
        let Ok(output) = Command::new(&candidate).arg("--version").output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Some((candidate, version));
    }
    None
}

#[test]
fn the_cases_match_a_real_node_binary() {
    let Some((node, node_version)) = reference_node() else {
        eprintln!(
            "skipping the differential: the pinned oracle is not present. \
             The recorded expectations in tests/url-pattern-expected.jsonl are \
             the oracle's output for the same file and still run above."
        );
        return;
    };

    let run = |binary: &PathBuf| -> std::process::Output {
        Command::new(binary)
            .arg(cases_path())
            .output()
            .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()))
    };

    let reference = run(&node);
    assert!(
        reference.status.success(),
        "{} failed: {}",
        node.display(),
        String::from_utf8_lossy(&reference.stderr)
    );
    eprintln!("comparing against {} ({node_version})", node.display());

    let rustnode = rustnode_binary();
    assert!(
        rustnode.exists(),
        "{} is missing; tools/check.sh builds it before the tests",
        rustnode.display()
    );
    let candidate = run(&rustnode);
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
        "{} of {} cases differ from node {node_version} ({}):\n{}",
        failures.len(),
        reference.len(),
        node.display(),
        failures.join("\n")
    );
}
