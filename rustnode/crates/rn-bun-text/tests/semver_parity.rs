//! `Bun.semver` against the recorded Bun 1.4.4 answers.
//!
//! The recorded file is the oracle's own output for a cross product of versions
//! and ranges, produced by running `Bun.semver.satisfies`/`.order` under
//! `/tmp/bun-dl/bun-linux-x64/bun` (1.4.4). Re-deriving the expected values by
//! hand would pin whatever this implementation does; the oracle is the
//! authority, and the unusual cases — invalid ranges matching everything,
//! invalid versions matching nothing, `order` throwing on empty input — are
//! exactly where a hand-written table would go wrong.

use serde_json::Value;

fn oracle() -> Value {
    let text = include_str!("data/semver-oracle.json");
    serde_json::from_str(text).expect("the recorded oracle file is valid JSON")
}

#[test]
fn satisfies_matches_bun() {
    let oracle = oracle();
    let cases = oracle["satisfies"].as_array().expect("satisfies cases");
    let mut failures = Vec::new();
    for case in cases {
        let version = case[0].as_str().expect("version");
        let range = case[1].as_str().expect("range");
        let expected = case[2].as_bool().expect("expected");
        let actual = rn_bun_text::semver::satisfies(version, range);
        if actual != expected {
            failures.push(format!(
                "satisfies({version:?}, {range:?}) = {actual}, bun says {expected}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases disagree with Bun:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[test]
fn order_matches_bun() {
    let oracle = oracle();
    let cases = oracle["order"].as_array().expect("order cases");
    let mut failures = Vec::new();
    for case in cases {
        let left = case[0].as_str().expect("left");
        let right = case[1].as_str().expect("right");
        let expected = &case[2];
        let actual = rn_bun_text::semver::order(Some(left), Some(right));
        let matches = match (expected.as_i64(), &actual) {
            (Some(expected), Ok(actual)) => expected == i64::from(*actual),
            (None, Err(error)) => {
                // The recorded shape is `throw:<ctor>:<json message>`.
                let recorded = expected.as_str().expect("throw string");
                let mut parts = recorded.splitn(3, ':');
                let _throw = parts.next();
                let constructor = parts.next().unwrap_or("");
                let message: String =
                    serde_json::from_str(parts.next().unwrap_or("\"\"")).unwrap_or_default();
                constructor == "Error" && error.message() == message
            }
            _ => false,
        };
        if !matches {
            failures.push(format!(
                "order({left:?}, {right:?}) = {actual:?}, bun says {expected}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases disagree with Bun:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
