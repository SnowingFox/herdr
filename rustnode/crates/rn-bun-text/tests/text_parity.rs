//! `stringWidth`, `stripANSI`, `wrapAnsi`, `sliceAnsi` and `escapeHTML` against
//! the recorded Bun 1.4.4 answers.
//!
//! The recordings in `tests/data/text-oracle.json` are Bun's own output, produced
//! by running the probes under `/tmp/bun-dl/bun-linux-x64/bun` (1.4.4). Comparing
//! against recorded values rather than re-deriving them is what makes this a
//! parity test: an expectation written by reading the Rust would pin whatever the
//! Rust happens to do, which is the failure mode this project has already been
//! burned by.
//!
//! # Why the exact strings, not just lengths
//!
//! `wrapAnsi` and `sliceAnsi` re-emit ANSI state, so two implementations can
//! agree on the visible characters and still differ by closing a style with
//! `\x1b[0m` where Bun emits `\x1b[39m`. Comparing the whole string catches that;
//! comparing `stringWidth` of the result would not. The multi-byte and
//! combining-character cases are pinned the same way, because a cluster that is
//! measured correctly can still be cut at the wrong column.

use serde_json::Value;

use rn_bun_text::ansi;
use rn_bun_text::html;
use rn_bun_text::slice::{self, SliceOptions};
use rn_bun_text::width;
use rn_bun_text::wrap::{self, WrapOptions};

fn oracle() -> Value {
    let text = include_str!("data/text-oracle.json");
    serde_json::from_str(text).expect("the recorded text oracle is valid JSON")
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// Renders UTF-16 back to a `String` for comparison, keeping escapes visible.
fn render(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// Collects every disagreement so one run reports all of them.
struct Failures(Vec<String>);

impl Failures {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn check<T: std::fmt::Debug + PartialEq<U>, U: std::fmt::Debug>(
        &mut self,
        label: &str,
        actual: T,
        expected: U,
    ) {
        if actual != expected {
            self.0
                .push(format!("{label}: got {actual:?}, bun says {expected:?}"));
        }
    }

    fn finish(self, total: usize) {
        assert!(
            self.0.is_empty(),
            "{} of {total} cases disagree with Bun:\n{}",
            self.0.len(),
            self.0.join("\n")
        );
    }
}

#[test]
fn string_width_matches_bun() {
    let oracle = oracle();
    let cases = oracle["stringWidth"].as_array().expect("stringWidth cases");
    let mut failures = Failures::new();
    for case in cases {
        let text = case[0].as_str().expect("input");
        let count_ansi = case[1].as_bool().expect("countAnsiEscapeCodes");
        let wide = case[2].as_bool().expect("ambiguousAsWide");
        let per_code_point = case[3].as_bool().expect("perCodePoint");
        let expected = case[4].as_u64().expect("width") as usize;

        let units = units(text);
        let actual = if per_code_point {
            width::per_code_point_width_of(&units, !count_ansi, wide)
        } else {
            width::visible_width(&units, count_ansi, wide)
        };
        failures.check(
            &format!("stringWidth({text:?}, ansi={count_ansi}, wide={wide}, pcp={per_code_point})"),
            actual,
            expected,
        );
    }
    failures.finish(cases.len());
}

#[test]
fn strip_ansi_matches_bun() {
    let oracle = oracle();
    let cases = oracle["stripANSI"].as_array().expect("stripANSI cases");
    let mut failures = Failures::new();
    for case in cases {
        let text = case[0].as_str().expect("input");
        let expected = case[1].as_str().expect("output");
        let actual = render(&ansi::strip(&units(text)));
        failures.check(&format!("stripANSI({text:?})"), actual, expected);
    }
    failures.finish(cases.len());
}

#[test]
fn wrap_ansi_matches_bun() {
    let oracle = oracle();
    let cases = oracle["wrapAnsi"].as_array().expect("wrapAnsi cases");
    let mut failures = Failures::new();
    for case in cases {
        let text = case[0].as_str().expect("input");
        let columns_value = case[1].as_f64().expect("columns");
        let columns = if columns_value > 0.0 {
            columns_value.trunc() as usize
        } else {
            0
        };
        let expected = case[2].as_str().expect("output");
        let hard = case[3].as_bool().unwrap_or(false);
        let word_wrap = case[4].as_bool().unwrap_or(true);
        let trim = case[5].as_bool().unwrap_or(true);
        let options = WrapOptions {
            hard,
            word_wrap,
            trim,
            ambiguous_is_narrow: true,
        };
        let actual = render(&wrap::wrap(&units(text), columns, options));
        failures.check(
            &format!(
                "wrapAnsi({text:?}, {columns}, hard={hard}, wordWrap={word_wrap}, trim={trim})"
            ),
            actual,
            expected,
        );
    }
    failures.finish(cases.len());
}

#[test]
fn slice_ansi_matches_bun() {
    let oracle = oracle();
    let cases = oracle["sliceAnsi"].as_array().expect("sliceAnsi cases");
    let mut failures = Failures::new();
    for case in cases {
        let text = case[0].as_str().expect("input");
        let start = case[1].as_f64().expect("start");
        // A `null` end is the recorded form of "absent", which becomes
        // `+Infinity` the way `String.prototype.slice` treats it.
        let end = case[2].as_f64().unwrap_or(f64::INFINITY);
        let expected = case[3].as_str().expect("output");

        let options = SliceOptions::default();
        let units = units(text);
        let total = slice::total_width(&units, options);
        let (from, to) = resolve(start, end, total);
        let actual = if to <= from {
            String::new()
        } else {
            render(&slice::slice(&units, from, to, options))
        };
        failures.check(
            &format!("sliceAnsi({text:?}, {start}, {end})"),
            actual,
            expected,
        );
    }
    failures.finish(cases.len());
}

#[test]
fn escape_html_matches_bun() {
    let oracle = oracle();
    let cases = oracle["escapeHTML"].as_array().expect("escapeHTML cases");
    let mut failures = Failures::new();
    for case in cases {
        let text = case[0].as_str().expect("input");
        let expected = case[1].as_str().expect("output");
        let actual = html::escape_html(text);
        failures.check(&format!("escapeHTML({text:?})"), actual, expected);
    }
    failures.finish(cases.len());
}

/// `String.prototype.slice`'s index resolution, in columns.
fn resolve(start: f64, end: f64, total: usize) -> (usize, usize) {
    let from = if start < 0.0 {
        total as f64 + start
    } else {
        start
    };
    let to = if end < 0.0 { total as f64 + end } else { end };
    let from = from.max(0.0);
    if to.is_infinite() {
        return (from as usize, usize::MAX);
    }
    let to = to.min(total as f64);
    if to <= from {
        return (from as usize, from as usize);
    }
    (from as usize, to as usize)
}
