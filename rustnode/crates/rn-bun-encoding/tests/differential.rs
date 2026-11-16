//! `Bun`, from the built runtime, compared case by case against Bun 1.4.4.
//!
//! # Why the comparison is a corpus and not a script per case
//!
//! There are seven members and roughly 400 measured behaviours. A Rust assertion
//! per case would be 400 blocks of duplication, and — worse — each expectation
//! would be a number typed into the test rather than a measurement. So:
//!
//! * `tests/corpus.json` is the corpus: a list of `{name, expression}`, where the
//!   expression is JavaScript evaluated inside a `try`.
//! * `tests/oracle/record.sh` runs it under the Bun binary and writes
//!   `tests/oracle/expected.json`, which is committed. That file is the pinned
//!   measurement, so reading it is how a reviewer sees what Bun actually does.
//! * this test runs the same corpus under the built runtime and compares.
//!
//! The corpus is shared, so the two sides cannot drift: an input added for Bun is
//! automatically an input for rustnode. `the_recorded_expectations_still_match_the_oracle`
//! replays the file against the binary, so a stale recording fails rather than
//! quietly becoming the specification.
//!
//! # What is compared
//!
//! Not the return value as JSON. JSON drops the things that matter most on this
//! surface — `Infinity`, `NaN`, `-0`, key order, and the difference between a
//! `Temporal.PlainDate` and the string it serialises to — so [`HARNESS`] walks
//! every result into a canonical form that keeps them, and the whole record is
//! compared. A failure prints both records, so the diff names the field.
//!
//! The error case is compared verbatim: constructor name, `code`, and message. That
//! is the half a compat layer usually gets wrong — an implementation that refuses
//! the right inputs with the wrong words passes an `instanceof` check and fails a
//! user.

use std::collections::BTreeMap;
use std::process::Command;

/// The recorded measurement of Bun 1.4.4's behaviour.
const EXPECTED: &str = include_str!("oracle/expected.json");

/// The corpus both runtimes execute.
const CORPUS: &str = include_str!("corpus.json");

/// Where the Bun oracle lives, or the reason this test cannot compare.
///
/// A missing binary is a **skip with a printed reason**, never a pass. This
/// project has paid for silent skips twice; an unmeasured comparison must not read
/// as a measured one.
fn bun_oracle() -> Option<String> {
    let path = std::env::var("RUSTNODE_BUN_ORACLE")
        .unwrap_or_else(|_| "/tmp/bun-dl/bun-linux-x64/bun".to_string());
    if std::path::Path::new(&path).is_file() {
        Some(path)
    } else {
        eprintln!(
            "skipped: no Bun oracle at {path}; set RUSTNODE_BUN_ORACLE to compare. \
             This is a skip, not a pass: the members were not compared against Bun."
        );
        None
    }
}

/// The built runtime.
///
/// `CARGO_BIN_EXE_rustnode` is only defined for the crate that declares the
/// binary, so a dependent crate cannot use it; `tools/check.sh` builds
/// `target/debug/rustnode` before the test sweep for exactly this reason.
fn rustnode() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

/// One corpus entry.
#[derive(serde::Deserialize)]
struct Case {
    name: String,
    expression: String,
}

/// The corpus as Rust sees it.
fn cases() -> Vec<Case> {
    serde_json::from_str(CORPUS).expect("tests/corpus.json is valid")
}

/// The JavaScript harness: the encoder, then the corpus, then the loop.
///
/// `record.sh` reads this same function through the `harness` test binary, so the
/// two sides cannot disagree about what a case is.
pub fn harness() -> String {
    let mut script = String::from(HARNESS_PRELUDE);
    script.push_str("const cases = [\n");
    for case in cases() {
        script.push_str("  [");
        script.push_str(&serde_json::to_string(&case.name).expect("a name is a string"));
        script.push_str(", () => (");
        script.push_str(&case.expression);
        script.push_str(")],\n");
    }
    script.push_str("];\n");
    script.push_str(HARNESS_EPILOGUE);
    script
}

/// Runs the whole corpus under `binary` and returns its JSON output.
fn record(binary: &std::path::Path) -> BTreeMap<String, serde_json::Value> {
    let script = harness();
    let output = Command::new(binary)
        .args(["-e", &script])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{} refused the corpus ({}):\n{stderr}",
        binary.display(),
        output.status
    );
    serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!(
            "{} did not print the corpus result: {error}\nstdout: {stdout}\nstderr: {stderr}",
            binary.display()
        )
    })
}

#[test]
fn every_member_matches_bun() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let expected: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(EXPECTED).expect("the recorded expectations are valid JSON");
    let actual = record(&rustnode());

    let mut failures: Vec<String> = Vec::new();
    for (name, want) in &expected {
        match actual.get(name) {
            None => failures.push(format!("{name}: absent from rustnode's output")),
            Some(got) if got != want => failures.push(format!(
                "{name}\n     bun:      {}\n     rustnode: {}",
                serde_json::to_string(want).unwrap_or_default(),
                serde_json::to_string(got).unwrap_or_default()
            )),
            Some(_) => {}
        }
    }
    for name in actual.keys() {
        if !expected.contains_key(name) {
            failures.push(format!(
                "{name}: rustnode produced a case the oracle did not"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ from Bun 1.4.4 (oracle: {oracle}):\n{}",
        failures.len(),
        expected.len(),
        failures.join("\n")
    );
    // A comparison over an empty corpus passes and proves nothing.
    assert!(
        expected.len() > 300,
        "the corpus has only {} cases; a differential this small cannot cover seven \
         namespaces",
        expected.len()
    );
}

/// The recording must still be reproducible from the oracle.
///
/// This is what keeps `expected.json` from becoming a fossil: it replays the
/// corpus under the Bun binary and requires the file to match. When Bun is
/// unavailable it skips with a reason, the same rule as above.
#[test]
fn the_recorded_expectations_still_match_the_oracle() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let expected: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(EXPECTED).expect("the recorded expectations are valid JSON");
    let recorded = record(std::path::Path::new(&oracle));
    let mut stale: Vec<String> = Vec::new();
    for (name, want) in &expected {
        match recorded.get(name) {
            None => stale.push(format!("{name}: absent from the oracle's output")),
            Some(got) if got != want => stale.push(format!(
                "{name}\n     recorded: {}\n     oracle:   {}",
                serde_json::to_string(want).unwrap_or_default(),
                serde_json::to_string(got).unwrap_or_default()
            )),
            Some(_) => {}
        }
    }
    assert!(
        stale.is_empty(),
        "tests/oracle/expected.json no longer matches the Bun binary at {oracle}; \
         re-record it with tests/oracle/record.sh and review the diff:\n{}",
        stale.join("\n")
    );
}

/// `Bun` is absent under Node and present-but-non-enumerable under rustnode.
///
/// This is the "it cannot break Node" half. `Bun` is rustnode's addition; Node has
/// no such global, and a script written for Node must not see one it did not
/// install. Non-enumerability is what keeps Node's own globals audit, which walks
/// `Object.keys(globalThis)`, from failing every test in the suite.
#[test]
fn bun_does_not_leak_into_node() {
    let script = "process.stdout.write(JSON.stringify({bun: typeof Bun, enumerable: \
                  Object.keys(globalThis).includes('Bun'), own: \
                  Object.getOwnPropertyNames(globalThis).includes('Bun')}))";
    let ours = Command::new(rustnode())
        .args(["-e", script])
        .output()
        .expect("the built runtime runs");
    let ours: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&ours.stdout)).expect("the probe emits JSON");
    assert_eq!(ours["bun"], "object", "rustnode must have installed Bun");
    assert_eq!(
        ours["enumerable"], false,
        "Bun must not appear in Object.keys(globalThis)"
    );
    assert_eq!(
        ours["own"], true,
        "Bun must be an own property, discoverable by name"
    );

    let Some(oracle) = rn_node_oracle::require_oracle("the Bun global is rustnode-only") else {
        return;
    };
    let theirs = oracle.eval(script);
    let theirs: serde_json::Value = serde_json::from_str(&theirs).expect("the probe emits JSON");
    assert_eq!(
        theirs["bun"], "undefined",
        "the Node oracle has a Bun global, so this comparison is about the wrong runtime \
         or something installed it there"
    );
}

/// The encoder and the loop, identical under both runtimes.
const HARNESS_PRELUDE: &str = r#"
function encode(value) {
  if (value === undefined) return { u: 1 };
  if (value === null) return { z: 1 };
  const type = typeof value;
  if (type === "boolean") return { b: value };
  if (type === "number") {
    if (Number.isNaN(value)) return { n: "NaN" };
    if (value === Infinity) return { n: "Infinity" };
    if (value === -Infinity) return { n: "-Infinity" };
    if (Object.is(value, -0)) return { n: "-0" };
    return { n: String(value) };
  }
  if (type === "bigint") return { i: String(value) };
  if (type === "string") return { s: value };
  if (type === "function") return { f: value.name };
  if (type === "symbol") return { y: String(value) };
  // A Temporal instance and the string it serialises to are indistinguishable
  // through JSON, so the constructor name is what separates them.
  if (typeof Temporal !== "undefined") {
    if (value instanceof Temporal.Instant) return { t: ["Instant", String(value)] };
    if (value instanceof Temporal.PlainDate) return { t: ["PlainDate", String(value)] };
    if (value instanceof Temporal.PlainTime) return { t: ["PlainTime", String(value)] };
    if (value instanceof Temporal.PlainDateTime) return { t: ["PlainDateTime", String(value)] };
  }
  if (Array.isArray(value)) return { a: value.map(encode) };
  const entries = [];
  for (const key of Object.keys(value)) entries.push([key, encode(value[key])]);
  const proto = Object.getPrototypeOf(value);
  const ctor = proto && proto.constructor ? proto.constructor.name : null;
  return { o: entries, c: ctor };
}
"#;

const HARNESS_EPILOGUE: &str = r#"
const out = {};
for (const [name, run] of cases) {
  let record;
  try {
    record = { ok: true, value: encode(run()) };
  } catch (error) {
    record = {
      ok: false,
      name: error && error.constructor ? error.constructor.name : null,
      code: error === undefined || error === null || error.code === undefined
        ? null
        : String(error.code),
      message: error ? String(error.message) : null,
    };
  }
  out[name] = record;
}
process.stdout.write(JSON.stringify(out));
"#;
