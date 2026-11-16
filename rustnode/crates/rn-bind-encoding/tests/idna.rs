//! `toASCII` / `toUnicode` against a real `node` binary and against the
//! recorded expectations.
//!
//! `tests/idna-cases.js` prints one `<label> <ascii> <unicode> <bindingAscii>
//! <bindingUnicode>` line per case. Four columns rather than two because Node
//! has two different conversions under these three names:
//!
//! * `url.domainToASCII`/`domainToUnicode` go through `set_hostname` on a
//!   `ws://x` seed (`src/node_url.cc:224`), so `"a/b"` truncates to `"a"` and a
//!   `:port` suffix is refused.
//! * `encoding_binding`'s `toASCII`/`toUnicode` are bare `ada::idna` calls
//!   (`src/encoding_binding.cc:492`), so `"a/b"` stays `"a/b"` and the label
//!   rules apply to the whole string.
//!
//! Legacy `url.parse()` normalises a host through the *binding*, which is why
//! the binding columns are in this probe rather than only the `url` ones: the
//! defect this file guards was in the binding, and a two-column table of
//! `url.domainToASCII` alone would not have seen it.
//!
//! Two tests consume the probe and answer different questions.
//!
//! * [`the_cases_match_the_recorded_expectations`] runs the built `rustnode`
//!   and compares with `tests/idna-expected.txt`, committed verbatim from the
//!   oracle. This is the one that runs everywhere.
//!
//! * [`the_recorded_cases_are_what_the_oracle_prints`] re-runs the probe on the
//!   pinned oracle and requires that file to still match it. It skips loudly
//!   when no oracle is present, because a machine without Node should still be
//!   able to check every byte.
//!
//! The oracle is resolved by [`rn_node_oracle`], not whatever `node` is on
//! `PATH`: IDNA tables move between ICU versions, so a different Node is a
//! different reference rather than a weaker one.

use std::path::PathBuf;
use std::process::Command;

/// The probe script.
const CASES: &str = include_str!("idna-cases.js");
/// The pinned oracle's stdout for [`CASES`], committed verbatim.
const EXPECTED: &str = include_str!("idna-expected.txt");

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cases_path() -> PathBuf {
    crate_dir().join("tests").join("idna-cases.js")
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

fn run(binary: &PathBuf) -> String {
    let output = Command::new(binary)
        // `--expose-internals` is what makes `internalBinding('encoding_binding')`
        // reachable from a script; without it the binding columns report
        // `MISSING`, which would silently halve the probe.
        .arg("--expose-internals")
        .arg("--no-warnings")
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
        .map(|line| line.trim_end().to_string())
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
    for (actual, expected) in actual.iter().zip(expected.iter()) {
        if actual != expected {
            failures.push(format!("\n  expected {expected}\n  actual   {actual}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ from {context}:{}",
        failures.len(),
        expected.len(),
        failures.join("")
    );
}

#[test]
fn the_cases_match_the_recorded_expectations() {
    let expected = normalize(EXPECTED);
    let actual = normalize(&run(&rustnode_binary()));
    assert_same(&actual, &expected, "the recorded expectations");

    // The table is only worth its count if it still covers the shapes the
    // divergence had. Losing one silently would leave that boundary untested.
    for required in [
        "zero-width-space",
        "zero-width-joiner",
        "ideographic-full-stop",
        "fullwidth-full-stop",
        "halfwidth-katakana",
        "uppercase-ascii",
        "label-64-bytes",
        "total-256-bytes",
        "already-punycode-invalid",
        "empty-label-middle",
        "trailing-dot",
        "lone-surrogate",
        "umlaut-mixed-label",
    ] {
        assert!(
            expected
                .iter()
                .any(|line| line.starts_with(&format!("{required} "))),
            "the case table no longer covers {required}"
        );
    }
}

#[test]
fn the_recorded_cases_are_what_the_oracle_prints() {
    let Some(oracle) = rn_node_oracle::require_oracle("rn-bind-encoding IDNA") else {
        return;
    };
    let output = Command::new(&oracle.path)
        .arg("--expose-internals")
        .arg("--no-warnings")
        .arg(cases_path())
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", oracle.path.display()));
    assert!(
        output.status.success(),
        "{} failed: {}",
        oracle.describe(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_same(
        &normalize(&String::from_utf8_lossy(&output.stdout)),
        &normalize(EXPECTED),
        &oracle.describe(),
    );
}

/// The probe must be the file the crate ships, not a copy that drifted.
#[test]
fn the_probe_is_the_file_on_disk() {
    let on_disk = std::fs::read_to_string(cases_path()).expect("the probe is readable");
    assert_eq!(
        on_disk, CASES,
        "tests/idna-cases.js drifted from the included copy"
    );
}
