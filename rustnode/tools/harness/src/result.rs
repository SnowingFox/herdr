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

/// What a file actually did, as opposed to how it exited.
///
/// A skipped file asserts nothing, so it is deliberately neither a pass nor a
/// failure. Reporting skips as failures would be as misleading as the old
/// behaviour of reporting them as passes: both invent an assertion that never
/// ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Skipped,
    Failed,
}

/// Detects [`SKIP_PLAN_PREFIX`] at the start of a line, across chunk boundaries.
///
/// A plain `contains` would be wrong twice over. `stdout_head` only keeps the
/// first couple of KiB, so the marker can be missing from a truncated head even
/// though the file really skipped; the runner therefore feeds every byte through
/// this scanner and records the verdict, rather than re-reading the head later.
/// And a test is free to mention the text mid-line — a diagnostic such as
/// `note: 1..0 # Skipped: ...` is not a plan line — so matching is anchored to
/// the first column.
#[derive(Debug, Clone, Copy)]
pub struct SkipScanner {
    state: ScanState,
}

#[derive(Debug, Clone, Copy)]
enum ScanState {
    /// At the start of a line, with `n` bytes of the prefix matched so far.
    LineStart(usize),
    /// Past the first column with no match; only a newline can recover.
    MidLine,
    Found,
}

impl Default for SkipScanner {
    fn default() -> Self {
        Self {
            state: ScanState::LineStart(0),
        }
    }
}

impl SkipScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds the next chunk of stdout. Chunks may split the marker anywhere.
    pub fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state = match self.state {
                ScanState::Found => ScanState::Found,
                ScanState::MidLine => {
                    if byte == b'\n' {
                        ScanState::LineStart(0)
                    } else {
                        ScanState::MidLine
                    }
                }
                ScanState::LineStart(matched) => {
                    let expected = SKIP_PLAN_PREFIX.as_bytes()[matched];
                    if byte == expected {
                        if matched + 1 == SKIP_PLAN_PREFIX.len() {
                            ScanState::Found
                        } else {
                            ScanState::LineStart(matched + 1)
                        }
                    } else if byte == b'\n' {
                        // An empty line leaves the next one at column zero.
                        ScanState::LineStart(0)
                    } else {
                        ScanState::MidLine
                    }
                }
            };
            if matches!(self.state, ScanState::Found) {
                break;
            }
        }
    }

    pub fn found(&self) -> bool {
        matches!(self.state, ScanState::Found)
    }
}

/// Whether `text` contains a skip plan line.
pub fn has_skip_plan_line(text: &str) -> bool {
    let mut scanner = SkipScanner::new();
    scanner.push(text.as_bytes());
    scanner.found()
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
    /// 3. Otherwise `passed` decides.
    pub fn outcome(&self) -> Outcome {
        if self.timed_out {
            return Outcome::Failed;
        }
        if self.is_skipped() {
            return Outcome::Skipped;
        }
        if self.passed {
            Outcome::Passed
        } else {
            Outcome::Failed
        }
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
        let mut scanner = SkipScanner::new();
        scanner.push(b"1..0 # Skipped: no IPv6 support\n");
        assert!(scanner.found());
        assert!(has_skip_plan_line("1..0 # Skipped: missing SQLite"));
    }

    #[test]
    fn a_plan_line_after_other_output_is_still_a_skip() {
        let mut scanner = SkipScanner::new();
        scanner.push(b"some diagnostic\n\n1..0 # Skipped: late\n");
        assert!(scanner.found());
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
            let mut scanner = SkipScanner::new();
            scanner.push(&text[..split]);
            scanner.push(&text[split..]);
            assert!(
                scanner.found(),
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
}
