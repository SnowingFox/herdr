//! One recorded test outcome, shared by the runner and the dashboard.

use serde::{Deserialize, Serialize};

/// The plan line Node's `common.skip()` prints, verbatim.
///
/// `test/common/index.js` writes it through `console.log`, so it always lands at
/// the start of a line in stdout, and `skip()` calls `process.exit()` right
/// after, so it is the only evidence a skipped file leaves behind. The exit code
/// cannot stand in for it: `skip()` exits 0 from `test/parallel/**` and 1 from
/// `test/known_issues/**`, so an exit code alone reads a skipped known-issue test
/// as a failure and a skipped parallel test as a pass.
pub const SKIP_PLAN_PREFIX: &str = "1..0 # Skipped:";

/// The glyph rustnode's spec reporter prints for a failed test, `U+2716`.
///
/// This is deliberately a *rustnode-shaped* rule, not a Node one. Real Node,
/// with stdout piped as the harness always pipes it, writes TAP
/// (`not ok 2 - inner fails`) and never this glyph; rustnode writes the spec
/// reporter's output instead because `test:summary` is never emitted. Matching
/// the glyph therefore buys detection of the failure rustnode currently reports
/// and then denies with exit 0, at the cost of being tied to rustnode's reporter
/// choice.
///
/// The consequence, stated so it is not a surprise later: if rustnode switches
/// to TAP output to match Node, this marker stops matching and
/// `misreported_passes` silently goes back to zero. The test
/// `a_passing_row_that_reported_a_failing_subtest_is_corrected_to_failed` pins
/// the rule, and `docs`/README record the dependency, so the switch has to deal
/// with it rather than quietly lose the check.
pub const FAILURE_MARKER: &str = "\u{2716}";

/// What a file actually did, as opposed to how it exited.
///
/// A skipped file asserts nothing, so it is deliberately neither a pass nor a
/// failure. Reporting skips as failures would be as misleading as the old
/// behaviour of reporting them as passes: both invent an assertion that never
/// ran.
///
/// There is deliberately no fourth variant for "exit 0 but the output said
/// failed". That case is folded into [`Outcome::Failed`], because the counts
/// that reach the user are `passed + skipped + failed == total` and a fourth
/// population would have to be folded into one of them anyway. The *evidence*
/// is recorded separately, on the row, so the report can explain the correction
/// instead of just applying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Skipped,
    Failed,
}

/// What a scan of one file's stdout proved, independent of the exit code.
///
/// Both answers are line-anchored, so one pass over the bytes produces both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanResult {
    /// A `1..0 # Skipped:` plan line appeared at the start of a line.
    pub skipped: bool,
    /// A `✖` appeared at the start of a line, after leading whitespace and ANSI
    /// colour escapes. Means the reporter announced a failing test.
    pub reported_failure: bool,
}

/// Detects both markers at the start of a line, across chunk boundaries.
///
/// A plain `contains` would be wrong three times over:
///
/// - `stdout_head` only keeps the first couple of KiB, so a marker can be
///   missing from a truncated head even though the file really printed it. The
///   runner therefore feeds every byte through this scanner and records the
///   verdict, rather than re-reading the head later.
/// - A test is free to mention either marker mid-line — a diagnostic such as
///   `note: 1..0 # Skipped: ...` is not a plan line — so matching is anchored to
///   the start of the line.
/// - The failure marker arrives wrapped in ANSI colour codes and indented when a
///   test sets `FORCE_COLOR` (rustnode's own `test-runner-reporters.js` does
///   exactly that), so the real line begins `"  \x1b[31m✖ ..."`. Leading
///   whitespace and escapes are skipped before either marker is compared.
///
/// The scanner keeps the first [`LINE_PREFIX_CAP`] bytes of each line rather than
/// running a byte-level state machine: both markers sit at the very start of a
/// line, so a short prefix decides the question, and buffering sidesteps the
/// multi-byte UTF-8 and escape-sequence splitting that a per-byte automaton
/// would have to get right.
#[derive(Debug, Clone, Default)]
pub struct MarkerScanner {
    /// First [`LINE_PREFIX_CAP`] bytes of the line being read.
    line: Vec<u8>,
    scan: ScanResult,
}

/// Enough for indentation, a colour escape and the marker with room to spare.
/// A line longer than this cannot still be *starting* with a marker past the
/// cap, so dropping the tail loses nothing.
const LINE_PREFIX_CAP: usize = 64;

impl MarkerScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds the next chunk of stdout. Chunks may split any marker anywhere.
    pub fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                self.finish_line();
                continue;
            }
            if self.line.len() < LINE_PREFIX_CAP {
                self.line.push(byte);
            }
        }
    }

    /// Evaluates the final line, which normally has no trailing newline.
    pub fn finish(&mut self) {
        self.finish_line();
    }

    fn finish_line(&mut self) {
        let text = String::from_utf8_lossy(&self.line);
        // `common.skip()` prints through `console.log`, so its plan line is
        // always at column zero. Matching it without trimming indentation keeps
        // an indented mention in a diagnostic from counting as a skip.
        if text.starts_with(SKIP_PLAN_PREFIX) {
            self.scan.skipped = true;
        }
        // The reporter indents nested tests and wraps the glyph in colour codes
        // when `FORCE_COLOR` is set, so this one is compared after both are
        // stripped.
        if visible_start(&text).starts_with(FAILURE_MARKER) {
            self.scan.reported_failure = true;
        }
        self.line.clear();
    }

    pub fn result(&self) -> ScanResult {
        self.scan
    }
}

/// Strips leading indentation and ANSI escape sequences from one line.
///
/// Only ASCII is skipped, so for text that is valid UTF-8 the returned slice
/// starts on a character boundary and can be compared to a multi-byte marker
/// directly.
fn visible_start(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut index = 0;
    loop {
        while index < bytes.len() && (bytes[index] == b' ' || bytes[index] == b'\t') {
            index += 1;
        }
        // CSI escape: `ESC [`, then parameters, then a final byte in 0x40..=0x7e.
        if index + 1 < bytes.len() && bytes[index] == 0x1b && bytes[index + 1] == b'[' {
            let mut end = index + 2;
            while end < bytes.len() && !(0x40..=0x7e).contains(&bytes[end]) {
                end += 1;
            }
            if end < bytes.len() {
                index = end + 1;
                continue;
            }
            // An unterminated escape cannot be followed by a marker.
            return "";
        }
        break;
    }
    &text[index..]
}

/// Whether `text` contains a line the reporter marked as a failing test.
pub fn has_failure_marker(text: &str) -> bool {
    scan_text(text).reported_failure
}

/// Scans a complete stdout blob for both markers.
pub fn scan_text(text: &str) -> ScanResult {
    let mut scanner = MarkerScanner::new();
    scanner.push(text.as_bytes());
    scanner.finish();
    scanner.result()
}

/// Whether `text` contains a skip plan line.
pub fn has_skip_plan_line(text: &str) -> bool {
    scan_text(text).skipped
}

/// Outcome of running a single Node test file against the rustnode binary.
///
/// The file is written as a one-element JSON array so the dashboard can read
/// every `*.json` in a result directory without knowing which runner produced
/// it. Fields added later are optional so old result files keep loading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResult {
    /// Path relative to the Node test root, for example `parallel/test-fs-open.js`.
    pub file: String,
    /// First path segment of `file`, for example `parallel`.
    #[serde(default)]
    pub suite: String,
    pub passed: bool,
    /// Whether the file skipped itself instead of asserting anything.
    ///
    /// This is an `Option` rather than a bare `bool` on purpose. Result files
    /// written before this field existed carry no value at all, and treating
    /// that absence as `false` would preserve the bug for every historical run,
    /// including the 4 rows in the 400-row baseline that skipped while being
    /// recorded as passes. `None` therefore means "not recorded", and
    /// [`FileResult::is_skipped`] recovers the answer from the stdout that run
    /// did record. A recorded `Some(_)` always wins.
    #[serde(default)]
    pub skipped: Option<bool>,
    /// Whether stdout announced a failing test while the process exited 0.
    ///
    /// `test:summary` is never emitted, so `harness.js`'s
    /// `if (!data.success) process.exitCode = ...` never runs and a file whose
    /// subtests failed can still exit 0. When that happens the exit code and the
    /// output disagree, and the output is the honest one: the subtest failed.
    ///
    /// Only meaningful for a row that would otherwise be a pass, so it is a
    /// correction rather than a fourth state. Like `skipped`, `None` means "not
    /// recorded" and the verdict is recovered from `stdout_head`, which is what
    /// reclassifies historical runs.
    ///
    /// This is a rustnode-shaped rule — see [`FAILURE_MARKER`].
    #[serde(default)]
    pub misreported: Option<bool>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub timed_out: bool,
    /// `// Flags:` header values passed to the runtime, in order.
    #[serde(default)]
    pub flags: Vec<String>,
    /// First couple of KiB of stdout, where Node's reporters write summaries.
    #[serde(default)]
    pub stdout_head: String,
    /// First couple of KiB of stderr, enough to see why a file failed.
    #[serde(default)]
    pub stderr_head: String,
}

impl FileResult {
    /// Builds a result for a test that never got to run.
    pub fn not_run(file: &str, reason: impl Into<String>) -> Self {
        let (suite, _) = split_path(file);
        Self {
            file: file.to_string(),
            suite: suite.to_string(),
            passed: false,
            skipped: Some(false),
            misreported: Some(false),
            exit_code: None,
            duration_ms: 0,
            timed_out: false,
            flags: Vec::new(),
            stdout_head: String::new(),
            stderr_head: reason.into(),
        }
    }

    /// Whether this row is a skip, including rows recorded before `skipped` existed.
    pub fn is_skipped(&self) -> bool {
        self.skipped
            .unwrap_or_else(|| has_skip_plan_line(&self.stdout_head))
    }

    /// Whether stdout announced a failure the exit code denied.
    ///
    /// The recorded field wins when present; otherwise the row's stdout is
    /// scanned, so a result file written before this field existed still gets
    /// the right answer.
    pub fn reported_failure(&self) -> bool {
        self.misreported
            .unwrap_or_else(|| has_failure_marker(&self.stdout_head))
    }

    /// What the file did, in one answer.
    ///
    /// Precedence, in order:
    ///
    /// 1. `timed_out` means the harness killed the process, so whatever it
    ///    printed first is not its own verdict. The runner never records
    ///    `skipped` for a killed file, and a hang counts against the runtime.
    /// 2. A skip means the body never ran, so it outranks `passed`. This crate
    ///    never writes both, but if a row somehow claims both, the stronger
    ///    claim is the one that says no assertion executed.
    /// 3. A `passed` row whose own output announced a failing test is corrected
    ///    to a failure. Only `passed` rows can be corrected: a non-zero exit is
    ///    already a failure, so the marker would add nothing there, and a skip
    ///    outranks both because it already said nothing ran.
    /// 4. Otherwise `passed` decides.
    pub fn outcome(&self) -> Outcome {
        if self.timed_out {
            return Outcome::Failed;
        }
        if self.is_skipped() {
            return Outcome::Skipped;
        }
        if self.passed && self.reported_failure() {
            return Outcome::Failed;
        }
        if self.passed {
            Outcome::Passed
        } else {
            Outcome::Failed
        }
    }

    /// Whether this row is a real pass that the exit code denied.
    ///
    /// The report uses this to say how many files changed verdict because of the
    /// marker rule, separately from the ones that changed because they skipped.
    pub fn is_misreported_pass(&self) -> bool {
        !self.timed_out && !self.is_skipped() && self.passed && self.reported_failure()
    }
}

/// Splits `parallel/test-fs-open.js` into (`parallel`, `test-fs-open.js`).
pub fn split_path(file: &str) -> (&str, &str) {
    match file.split_once('/') {
        Some((suite, rest)) => (suite, rest),
        None => ("", file),
    }
}

/// The suite directory a test file lives in, for example `es-module`.
pub fn suite_of(file: &str) -> String {
    split_path(file).0.to_string()
}

/// Groups a test file by the subsystem its name advertises.
///
/// `parallel/test-fs-open.js` and `es-module/test-esm-import.mjs` both land in
/// `fs`, which is the unit a binding workstream owns.
pub fn cluster_of(file: &str) -> String {
    let (_, base) = split_path(file);
    let name = base.strip_prefix("test-").unwrap_or(base);
    let name = name
        .strip_suffix(".mjs")
        .or_else(|| name.strip_suffix(".js"))
        .unwrap_or(name);
    let cluster = name.split('-').next().unwrap_or("").trim();
    if cluster.is_empty() {
        "unknown".to_string()
    } else {
        cluster.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        file: &str,
        stdout: &str,
        passed: bool,
        exit_code: i32,
        skipped: Option<bool>,
    ) -> FileResult {
        FileResult {
            file: file.to_string(),
            suite: suite_of(file),
            passed,
            skipped,
            // `None` means "not recorded", so the stdout decides. That is also
            // what an old result file carries, which is what these tests
            // exercise.
            misreported: None,
            exit_code: Some(exit_code),
            duration_ms: 5,
            timed_out: false,
            flags: Vec::new(),
            stdout_head: stdout.to_string(),
            stderr_head: String::new(),
        }
    }

    #[test]
    fn cluster_uses_the_first_name_segment() {
        assert_eq!(cluster_of("parallel/test-fs-open.js"), "fs");
        assert_eq!(
            cluster_of("parallel/test-abortcontroller.js"),
            "abortcontroller"
        );
        assert_eq!(cluster_of("es-module/test-esm-loader.mjs"), "esm");
        assert_eq!(cluster_of("internet/test-dgram-connect.js"), "dgram");
    }

    #[test]
    fn cluster_survives_odd_names() {
        assert_eq!(cluster_of("parallel/test-.js"), "unknown");
        assert_eq!(cluster_of("sequential/test-fs-watch.js"), "fs");
    }

    #[test]
    fn result_without_optional_fields_still_loads() {
        let json = r#"[{"file":"parallel/test-x.js","passed":true}]"#;
        let parsed: Vec<FileResult> = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].passed);
        assert_eq!(parsed[0].duration_ms, 0);
        assert!(parsed[0].flags.is_empty());
        assert_eq!(parsed[0].skipped, None, "no field means not recorded");
    }

    #[test]
    fn a_plan_line_at_the_start_of_a_line_is_a_skip() {
        let mut scanner = MarkerScanner::new();
        scanner.push(b"1..0 # Skipped: no IPv6 support\n");
        assert!(scanner.result().skipped);
        assert!(has_skip_plan_line("1..0 # Skipped: missing SQLite"));
    }

    #[test]
    fn a_plan_line_after_other_output_is_still_a_skip() {
        let mut scanner = MarkerScanner::new();
        scanner.push(b"some diagnostic\n\n1..0 # Skipped: late\n");
        assert!(scanner.result().skipped);
    }

    #[test]
    fn the_same_text_mid_line_is_not_a_skip() {
        assert!(!has_skip_plan_line(
            "warning: 1..0 # Skipped: is emitted by common.skip"
        ));
        assert!(!has_skip_plan_line("x1..0 # Skipped: no"));
        assert!(!has_skip_plan_line("  1..0 # Skipped: indented"));
    }

    #[test]
    fn the_prefix_alone_without_the_directive_is_not_a_skip() {
        // `1..0` is a legal TAP plan; only the skip directive marks a skip.
        assert!(!has_skip_plan_line("1..0\n"));
        assert!(!has_skip_plan_line("1..3 # Skipped: no"));
    }

    #[test]
    fn the_marker_is_found_when_a_chunk_boundary_splits_it() {
        let text = b"leading line\n\n1..0 # Skipped: missing FFI";
        for split in 0..text.len() {
            let mut scanner = MarkerScanner::new();
            scanner.push(&text[..split]);
            scanner.push(&text[split..]);
            scanner.finish();
            assert!(
                scanner.result().skipped,
                "missed the marker when split after byte {split}"
            );
        }
    }

    #[test]
    fn a_truncated_head_that_lost_the_marker_is_not_a_skip() {
        // Documents why the runner scans the whole stream instead of the head:
        // once the bytes are gone, the head alone cannot answer the question.
        assert!(!has_skip_plan_line("x".repeat(4096).as_str()));
    }

    #[test]
    fn an_old_row_recovers_its_skip_from_the_recorded_stdout() {
        let old = row(
            "parallel/test-cluster-dgram-ipv6only.js",
            "1..0 # Skipped: no IPv6 support",
            true,
            0,
            None,
        );
        assert_eq!(old.outcome(), Outcome::Skipped);
        assert!(old.is_skipped());
    }

    #[test]
    fn a_recorded_field_wins_over_the_stdout_text() {
        let recorded = row(
            "parallel/test-x.js",
            "1..0 # Skipped: said in a trace",
            true,
            0,
            Some(false),
        );
        assert_eq!(recorded.outcome(), Outcome::Passed);
    }

    #[test]
    fn a_skip_outranks_a_contradictory_pass() {
        let malformed = row(
            "parallel/test-x.js",
            "1..0 # Skipped: no",
            true,
            0,
            Some(true),
        );
        assert_eq!(malformed.outcome(), Outcome::Skipped);
    }

    #[test]
    fn a_timeout_is_a_failure_even_if_a_skip_line_was_seen() {
        let mut killed = row(
            "parallel/test-x.js",
            "1..0 # Skipped: then hung",
            false,
            0,
            Some(true),
        );
        killed.timed_out = true;
        assert_eq!(killed.outcome(), Outcome::Failed);
    }

    #[test]
    fn a_plain_exit_zero_is_a_pass_and_a_nonzero_is_a_failure() {
        assert_eq!(
            row("parallel/test-x.js", "", true, 0, Some(false)).outcome(),
            Outcome::Passed
        );
        assert_eq!(
            row("parallel/test-x.js", "", false, 1, Some(false)).outcome(),
            Outcome::Failed
        );
    }

    // --- the failure marker: exit 0 with output saying a test failed ---------

    /// Verbatim rustnode output for a failing subtest, captured from
    /// `rustnode /tmp/subtest_probe.js` on this tree.
    const SUBTEST_FAILURE_STDOUT: &str =
        "▶ outer\n  ✔ inner passes (0.50284ms)\n  ✖ inner fails (1.272754ms)\n✖ outer (2.85912ms)";

    #[test]
    fn a_failure_marker_at_the_start_of_a_line_is_detected() {
        assert!(has_failure_marker(SUBTEST_FAILURE_STDOUT));
        // Indented, as a nested failure is.
        assert!(has_failure_marker("  ✖ inner fails"));
        // With no trailing newline, which the last line never has.
        let mut scanner = MarkerScanner::new();
        scanner.push(SUBTEST_FAILURE_STDOUT.as_bytes());
        scanner.finish();
        assert!(scanner.result().reported_failure);
    }

    #[test]
    fn an_ansi_wrapped_indented_failure_marker_is_detected() {
        // Captured from `parallel/test-runner-reporters.js`, which sets
        // `FORCE_COLOR=1` itself, so its own output is colourised even though
        // stdout is a pipe.
        let line = "  \u{1b}[31m\u{2716} should default to outputing TAP to stdout \u{1b}[90m(66.293103ms)\u{1b}[39m\u{1b}[39m";
        assert!(has_failure_marker(line));
        assert!(has_failure_marker(&format!("{line}\n")));
    }

    #[test]
    fn a_failure_marker_mid_line_is_not_detected() {
        // `test-runner-reporters.js` asserts on child output containing the
        // glyph, so the text may appear inside a message or a quote.
        assert!(!has_failure_marker("assert.match(out, /✖ failing tests:/)"));
        assert!(!has_failure_marker("expected: '✖ failing'"));
        assert!(!has_failure_marker("see ✖ above"));
    }

    #[test]
    fn a_passing_row_without_a_marker_is_still_a_pass() {
        let clean = row(
            "parallel/test-fs-open.js",
            "▶ outer\n  ✔ inner passes (0.5ms)\n✔ outer (0.6ms)",
            true,
            0,
            Some(false),
        );
        assert_eq!(clean.outcome(), Outcome::Passed);
        assert!(!clean.is_misreported_pass());
    }

    #[test]
    fn a_passing_row_that_reported_a_failing_subtest_is_corrected_to_failed() {
        // This is the hollow pass: the runtime exits 0 while its own output
        // says a subtest failed. Pins FAILURE_MARKER's rustnode shape.
        let hollow = row(
            "parallel/test-runner-reporters.js",
            SUBTEST_FAILURE_STDOUT,
            true,
            0,
            Some(false),
        );
        assert_eq!(hollow.outcome(), Outcome::Failed);
        assert!(hollow.is_misreported_pass());
    }

    #[test]
    fn a_marker_on_a_row_that_was_already_failing_adds_nothing() {
        let failed = row(
            "parallel/test-x.js",
            SUBTEST_FAILURE_STDOUT,
            false,
            1,
            Some(false),
        );
        assert_eq!(failed.outcome(), Outcome::Failed);
        assert!(
            !failed.is_misreported_pass(),
            "a non-zero exit is already a failure; the marker is not the cause"
        );
    }

    #[test]
    fn a_marker_on_a_skipped_row_stays_a_skip() {
        // The skip says nothing ran, which outranks anything printed after it.
        let mixed = row(
            "parallel/test-x.js",
            "1..0 # Skipped: no IPv6 support\n✖ leftover",
            true,
            0,
            Some(true),
        );
        assert_eq!(mixed.outcome(), Outcome::Skipped);
        assert!(!mixed.is_misreported_pass());
    }

    #[test]
    fn a_marker_on_a_timed_out_row_stays_a_timeout() {
        let mut killed = row(
            "parallel/test-x.js",
            "  ✖ inner fails",
            true,
            0,
            Some(false),
        );
        killed.timed_out = true;
        assert_eq!(killed.outcome(), Outcome::Failed);
        assert!(!killed.is_misreported_pass());
    }

    #[test]
    fn an_old_row_recovers_a_misreported_pass_from_its_recorded_stdout() {
        // A result file written before `misreported` existed: the field is
        // absent, so the recorded stdout has to answer for it.
        let json = r#"[{
            "file": "parallel/test-runner-reporters.js",
            "suite": "parallel",
            "passed": true,
            "exit_code": 0,
            "timed_out": false,
            "stdout_head": "▶ node:test reporters\n  \u001b[31m✖ first \u001b[39m\n  \u001b[31m✖ second \u001b[39m",
            "stderr_head": ""
        }]"#;
        let parsed: Vec<FileResult> = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed[0].misreported, None, "field absent in old files");
        assert_eq!(parsed[0].outcome(), Outcome::Failed);
        assert!(parsed[0].is_misreported_pass());
    }

    #[test]
    fn a_recorded_misreported_field_wins_over_the_stdout_text() {
        let mut recorded = row(
            "parallel/test-x.js",
            "  ✖ mentioned in a trace",
            true,
            0,
            Some(false),
        );
        recorded.misreported = Some(false);
        assert_eq!(recorded.outcome(), Outcome::Passed);
    }

    #[test]
    fn the_failure_marker_is_found_across_every_chunk_split() {
        let text = "header\n  \u{1b}[31m\u{2716} inner fails\u{1b}[39m\n";
        let bytes = text.as_bytes();
        for split in 0..bytes.len() {
            let mut scanner = MarkerScanner::new();
            scanner.push(&bytes[..split]);
            scanner.push(&bytes[split..]);
            scanner.finish();
            assert!(
                scanner.result().reported_failure,
                "missed the marker when split after byte {split}"
            );
        }
    }
}
