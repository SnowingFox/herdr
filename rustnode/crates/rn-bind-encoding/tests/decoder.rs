//! `decodeUTF8` and the `Blob` text path against a real `node` binary and
//! against the recorded expectations.
//!
//! `tests/decoder-cases.js` prints one `<label>: <result>` line per case, which
//! is the whole observable contract of the operation: the string it returned,
//! or the error it threw. Two tests consume it and answer different questions.
//!
//! * [`the_recorded_cases_are_what_the_oracle_prints`] re-runs the script on the
//!   oracle named by `RUSTNODE_ORACLE_NODE`, or the pinned one under
//!   `/tmp/oracle-dl`, and requires `tests/decoder-expected.txt` to match it
//!   exactly. That keeps the committed expectations from drifting away from the
//!   `node` they claim to describe. It skips loudly when no oracle is present,
//!   because a Rust workspace is not guaranteed to have one.
//!
//! * [`the_cases_match_the_recorded_expectations`] runs the same file under the
//!   built `rustnode` binary and compares with the committed expectations. This
//!   is the one that runs everywhere and is the regression guard.
//!
//! Node's `decodeUTF8` signature is `(list, ignoreBom, fatal)`. The three
//! separate defects this file pins — swapped flags, an unstripped BOM, and a
//! rejected plain `ArrayBuffer` — are all invisible to a contract that only
//! checks a member exists, which is why the probe goes through `TextDecoder`,
//! `Blob` and `Response` instead of calling the binding directly.

use std::path::PathBuf;
use std::process::Command;

/// The probe script.
const CASES: &str = include_str!("decoder-cases.js");
/// The pinned oracle's stdout for [`CASES`], committed verbatim.
const EXPECTED: &str = include_str!("decoder-expected.txt");

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cases_path() -> PathBuf {
    crate_dir().join("tests").join("decoder-cases.js")
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

/// The `node` this compares against: `RUSTNODE_ORACLE_NODE`, then the pinned
/// nightly, then whatever is on `PATH`.
///
/// The pinned path comes before `PATH` on purpose. The image's default `node`
/// is much older than the revision rustnode tracks, and its `TextDecoder` is a
/// different implementation, so comparing against it would produce findings
/// that only describe the version gap.
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
    candidates.push(PathBuf::from("node"));

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

fn run(binary: &PathBuf) -> String {
    let output = Command::new(binary)
        .arg(cases_path())
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        output.status.success(),
        "{} failed: {}",
        binary.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn normalize(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect()
}

/// Compares two case lists, reporting the label and both sides per mismatch.
fn assert_same(actual: &[String], expected: &[String], context: &str) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "the probe printed {} cases, {context} holds {}",
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
        "{} of {} cases differ from {context}:\n{}",
        failures.len(),
        expected.len(),
        failures.join("\n")
    );
}

#[test]
fn the_cases_match_the_recorded_expectations() {
    let expected = normalize(EXPECTED);
    let actual = normalize(&run(&rustnode_binary()));
    assert_same(&actual, &expected, "the recorded expectations");

    // The table is only worth its count if it still covers the shapes the
    // defects involved. Losing one silently would leave that boundary untested.
    for required in [
        "bom/default",
        "bom/ignoreBOM-true",
        "fatal/true-bad",
        "input/plain-arraybuffer",
        "input/dataview",
        "blob/text",
        "blob/arrayBuffer",
        "response/blob-text",
    ] {
        assert!(
            expected
                .iter()
                .any(|line| line.starts_with(&format!("{required}:"))),
            "the case table no longer covers {required}"
        );
    }
}

#[test]
fn the_recorded_cases_are_what_the_oracle_prints() {
    let Some((node, version)) = reference_node() else {
        eprintln!(
            "skipping the oracle check: no RUSTNODE_ORACLE_NODE, no pinned nightly \
             under /tmp/oracle-dl, and no `node` on PATH. The committed \
             expectations were produced by \
             v28.0.0-nightly20261111e8c1160d20 and still run above."
        );
        return;
    };
    eprintln!(
        "checking the recorded cases against {} ({version})",
        node.display()
    );
    assert_same(
        &normalize(&run(&node)),
        &normalize(EXPECTED),
        &format!("node {version}"),
    );
}

/// The probe must be the file the crate ships, not a copy that drifted.
#[test]
fn the_probe_is_the_file_on_disk() {
    let on_disk = std::fs::read_to_string(cases_path()).expect("the probe is readable");
    assert_eq!(
        on_disk, CASES,
        "tests/decoder-cases.js drifted from the included copy"
    );
}
