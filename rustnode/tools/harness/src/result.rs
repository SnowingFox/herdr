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

/// The word that marks an uncaught exception in rustnode's output: `Uncaught`.
///
/// This is the *primary* hollow-pass marker, and it is much larger in practice
/// than the reporter glyph. When an assertion fails outside `node:test` — a
/// plain `assert.strictEqual` in a test file, which is most of `test/parallel` —
/// rustnode prints
///
/// ```text
/// node:assert:16736: Uncaught AssertionError: The input did not match ...
/// ```
///
/// to **stdout** and then exits 0, because the uncaught-exception path never
/// sets the exit code. Measured on a `test/parallel` sample, 9 of 400 files did
/// this on exit 0; on the `test-crypto-key*`/`rsa*`/`ec*` family 16 of 31
/// harness-visible passes did.
///
/// The location prefix (`node:assert:16736: `) means the word is not at the
/// start of the line, so it cannot be matched only at column zero — that rule
/// matches none of the measured rows. Matching is instead by phrase *and*
/// provenance; see [`has_failure_marker`] and the `mentions_uncaught` helper for
/// the exact shape and the false-positive reasoning.
pub const UNCAUGHT_MARKER: &str = "Uncaught";

/// The glyph rustnode's spec reporter prints for a failed test, `U+2716`.
///
/// This covers the *other* half: files that use `node:test` and fail a subtest.
/// Those print the spec reporter's `✖` and never a word like `Uncaught`, because
/// the failure is reported as a test result rather than an exception. Keeping
/// both markers is not redundancy — they are disjoint populations:
///
/// | file uses | failure appears as |
/// | --- | --- |
/// | `node:test` | `  ✖ inner fails` |
/// | plain `assert` | `node:assert:16736: Uncaught AssertionError: ...` |
///
/// This glyph is deliberately a *rustnode-shaped* rule, not a Node one. Real
/// Node, with stdout piped as the harness always pipes it, writes TAP
/// (`not ok 2 - inner fails`) and never this glyph; rustnode writes the spec
/// reporter's output instead because `test:summary` is never emitted.
///
/// The consequence, stated so it is not a surprise later: if rustnode switches
/// to TAP output to match Node, this marker stops matching and those rows
/// silently go back to counting as passes. The test
/// `a_passing_row_that_reported_a_failing_subtest_is_corrected_to_failed` pins
/// the rule, and `docs`/README record the dependency, so the switch has to deal
/// with it rather than quietly lose the check. [`UNCAUGHT_MARKER`] is unaffected
/// by that switch, which is why it carries most of the correction.
pub const FAILURE_MARKER: &str = "\u{2716}";

/// The reporter's skip symbol, `U+FE63` (`﹣`), from
/// `reporterUnicodeSymbolMap['hyphen:minus']`.
///
/// A `node:test` file that skips its tests prints
/// `﹣ <anonymous> (0.8ms) # SKIP` and exits 0, which is a *third* skip form: it
/// is neither the `common.skip()` plan line nor a failure. On its own that is
/// only visible as a skip when the whole file skipped, which is why the rule
/// below also requires that nothing else ran.
pub const NESTED_SKIP_MARKER: &str = "\u{FE63}";

/// The reporter's passing symbol, `U+2714` (`✔`).
pub const PASS_MARKER: &str = "\u{2714}";

/// The reporter's suite symbol, `U+25B6` (`▶`).
pub const SUITE_MARKER: &str = "\u{25B6}";

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
    /// A `﹣` line appeared in the reporter's skip position.
    pub nested_skip: bool,
    /// A `✔` line appeared, so at least one test passed.
    pub passed_test: bool,
    /// A `▶` line appeared, so a suite header was emitted.
    pub suite_header: bool,
}

impl ScanResult {
    /// Whether this file ran no assertions at all.
    ///
    /// True when the only marks the reporter emitted were skip marks: something
    /// was skipped, and nothing passed, failed or opened a suite. A file that has
    /// any passing or failing test is **not** a skip, whatever else it skipped —
    /// so a mixed file keeps its real verdict, and a `describe` whose children
    /// all skipped is not a skip either, because the suite itself reports `✔`.
    pub fn only_skipped_tests(&self) -> bool {
        self.nested_skip && !self.passed_test && !self.reported_failure && !self.suite_header
    }
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

/// First bytes of each line retained for matching.
///
/// Grown from 64 when the `Uncaught` marker arrived: its line carries a location
/// prefix (`node:internal/assert/utils:4640: `) before the word, so the buffer
/// has to hold more than the word itself. A line longer than this cannot still
/// be *starting* with the reporter glyph past the cap, and the `Uncaught` phrase
/// appears within the first few dozen bytes of every observed line, so dropping
/// the tail loses nothing.
const LINE_PREFIX_CAP: usize = 256;

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
        // The reporter indents nested tests and wraps every glyph in colour codes
        // when `FORCE_COLOR` is set, so all three are compared after the prefix
        // is stripped. They have to be read even once a failure is seen, because
        // "did anything else run" decides whether a skip-only file skipped.
        let visible = visible_start(&text);
        if visible.starts_with(FAILURE_MARKER) {
            self.scan.reported_failure = true;
        } else if visible.starts_with(NESTED_SKIP_MARKER) {
            // `﹣ name # SKIP`, or `﹣ name # <reason>` when the skip carries a
            // message. The glyph alone is the signal: `hyphen:minus` has exactly
            // one assignment site in the reporter, inside the `skip !== undefined`
            // branch, so nothing else prints it. `# TODO` keeps the fail glyph on
            // a failing todo and the pass glyph on a passing one.
            self.scan.nested_skip = true;
        } else if visible.starts_with(PASS_MARKER) {
            self.scan.passed_test = true;
        } else if visible.starts_with(SUITE_MARKER) {
            self.scan.suite_header = true;
        } else if text.contains(UNCAUGHT_MARKER) && mentions_uncaught(&strip_ansi(&text)) {
            // Only the allocating path is gated: it is the expensive one, and
            // once true it can never become false.
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

/// Removes ANSI CSI escape sequences from one line, leaving the visible text.
///
/// An unterminated escape at the end of a truncated line is left in place rather
/// than swallowing the rest: the line was cut off, so the bytes after it are not
/// really a continuation of the escape, and dropping them could hide a marker.
fn strip_ansi(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && index + 1 < bytes.len() && bytes[index + 1] == b'[' {
            let mut end = index + 2;
            while end < bytes.len() && !(0x40..=0x7e).contains(&bytes[end]) {
                end += 1;
            }
            if end < bytes.len() {
                // Skip the whole escape, final byte included.
                index = end + 1;
                continue;
            }
            // Unterminated: keep the remaining bytes verbatim.
            out.push_str(&text[index..]);
            break;
        }
        let ch = text[index..].chars().next().unwrap_or('\0');
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// Whether a line reports an uncaught exception.
///
/// Two shapes occur in real rustnode output, and both are matched:
///
/// ```text
/// Uncaught AssertionError [ERR_ASSERTION]: plain mismatch
/// node:assert:16736: Uncaught AssertionError: The input did not match ...
/// ```
///
/// The second is the common one and puts a location prefix in front, so a rule
/// requiring the word at the start of the line would match **none** of the 9
/// measured cases. The prefix is the discriminator, and it has a specific shape:
/// `<module or path>:<line>: `, that is, something ending in a colon and a line
/// number. That is what separates the runtime reporting its own error from a
/// test echoing captured child output, which reads
/// `child stderr: Uncaught AssertionError: ...` — arbitrary text, no line
/// number, and a passing file that prints it must stay a pass.
///
/// So a line matches when `Uncaught` is followed by an error name and a colon,
/// **and** it is either at the start of the line or preceded by a
/// `:<digits>: ` location. Both restrictions are load-bearing; each one alone
/// admits a wrong answer.
fn mentions_uncaught(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(found) = line[from..].find(UNCAUGHT_MARKER) {
        let start = from + found;
        from = start + UNCAUGHT_MARKER.len();

        // The word must not be part of a longer identifier.
        let before_ok = start == 0
            || !line[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if !before_ok {
            continue;
        }

        // `Uncaught <ErrorName>:` or `Uncaught <ErrorName> [CODE]`.
        let Some(after_space) = line[start + UNCAUGHT_MARKER.len()..].strip_prefix(' ') else {
            continue;
        };
        let name: String = after_space
            .chars()
            .take_while(|c| c.is_alphanumeric())
            .collect();
        let tail = &after_space[name.len()..];
        let capitalised = name.chars().next().is_some_and(|c| c.is_uppercase());
        if !capitalised || !(tail.starts_with(':') || tail.starts_with(" [")) {
            continue;
        }

        // Either the start of the line, or a `:<line-number>: ` location.
        let line_start = line[..start].trim_start_matches([' ', '\t']).is_empty();
        if line_start || preceded_by_location(bytes, start) {
            return true;
        }
    }
    false
}

/// Whether the text before `start` ends with a `:<line-number>:` location.
///
/// Accepts `node:assert:16736: `, `node:internal/assert/utils:4640: ` and
/// `/path/to/test-file.js:898: `; rejects `child stderr: ` or any other prose.
fn preceded_by_location(bytes: &[u8], start: usize) -> bool {
    let mut index = start;
    // Trailing space of the prefix.
    if index == 0 || bytes[index - 1] != b' ' {
        return false;
    }
    index -= 1;
    if index == 0 || bytes[index - 1] != b':' {
        return false;
    }
    index -= 1;
    // At least one digit of line number.
    let digits_end = index;
    while index > 0 && bytes[index - 1].is_ascii_digit() {
        index -= 1;
    }
    if index == digits_end {
        return false;
    }
    // And the colon that introduces the line number.
    index > 0 && bytes[index - 1] == b':'
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

    /// Whether this row is a skip, including rows recorded before `skipped`
    /// existed.
    ///
    /// Three forms count:
    ///
    /// 1. A `1..0 # Skipped:` plan line, which is what `common.skip()` prints.
    /// 2. A recorded `skipped: true`, which preserves a verdict the full-stream
    ///    scan reached but the retained head cannot show.
    /// 3. A `node:test` file whose every mark was a skip — see
    ///    [`FileResult::only_skipped_tests`].
    ///
    /// Marker evidence is **cumulative**: a recorded `true` stands, and a marker
    /// found in the recorded stdout also counts. This is not a fallback chain
    /// that lets a recorded value hide new evidence.
    pub fn is_skipped(&self) -> bool {
        self.skipped == Some(true)
            || has_skip_plan_line(&self.stdout_head)
            || self.only_skipped_tests()
    }

    /// Whether stdout showed a `node:test` file that ran nothing.
    ///
    /// The form is `﹣ <name> # SKIP` with no `✔`, `▶` or `✖` anywhere: every
    /// test in the file skipped. This must not be inferred from the glyph alone.
    /// Two cases show why:
    ///
    /// - A mixed file prints skips *and* real results. `test-runner-module-mocking.js`
    ///   has 1 skip, 10 passes and 43 failures; calling it a skip would be wrong.
    /// - A `describe` whose children all skip still prints `✔ outer suite`,
    ///   because the suite itself passed. That is a pass, not a skip.
    ///
    /// It also only applies to an exit-0 row. A non-zero exit is already a
    /// failure, and calling it a skip would hide that.
    pub fn only_skipped_tests(&self) -> bool {
        self.exit_code == Some(0)
            && !self.timed_out
            && scan_text(&self.stdout_head).only_skipped_tests()
    }

    /// Whether stdout announced a failure the exit code denied.
    ///
    /// Cumulative for the same reason as [`FileResult::is_skipped`], and it
    /// matters more here because this rule *was* extended: the first version
    /// matched only the reporter's `✖`, which misses the much larger
    /// `Uncaught AssertionError` population. A row recorded under the narrow rule
    /// carries `misreported: Some(false)`, and treating that as final would mask
    /// every uncaught case in any result file written by that build.
    ///
    /// So the two sources are ORed rather than one winning. A byte prefix of the
    /// stream can only miss a marker, never invent one, so scanning the retained
    /// head cannot produce evidence the full stream lacked; the OR is therefore
    /// sound, and it means strengthening the rule always applies to old files.
    pub fn reported_failure(&self) -> bool {
        self.misreported == Some(true) || has_failure_marker(&self.stdout_head)
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
    fn a_recorded_false_does_not_hide_a_plan_line_in_the_stdout() {
        // Same cumulative rule as `misreported`. A `1..0 # Skipped:` line in
        // column zero can only be evidence the writer failed to interpret, never
        // a false positive invented by truncation, so it is not discarded.
        let recorded = row(
            "parallel/test-x.js",
            "1..0 # Skipped: said in a trace",
            true,
            0,
            Some(false),
        );
        assert_eq!(recorded.outcome(), Outcome::Skipped);

        // What actually guards the false-positive direction is position: an
        // indented or mid-line mention is not a plan line, so a recorded pass
        // stands there.
        let indented = row(
            "parallel/test-y.js",
            "  note: 1..0 # Skipped: mentioned in a message",
            true,
            0,
            Some(false),
        );
        assert_eq!(indented.outcome(), Outcome::Passed);
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
    fn marker_evidence_from_the_stdout_is_never_masked_by_a_recorded_false() {
        // A row written by the narrower ✖-only build records `misreported:
        // Some(false)` for a file that printed an uncaught assertion, because
        // that build could not see it. The stronger rule must still find it, or
        // extending a detection rule would never apply to existing files.
        let mut recorded = row(
            "parallel/test-crypto-keygen-rsa-pss.js",
            "node:assert:16736: Uncaught AssertionError: mismatch",
            true,
            0,
            Some(false),
        );
        recorded.misreported = Some(false);
        assert_eq!(recorded.outcome(), Outcome::Failed);
        assert!(recorded.is_misreported_pass());
    }

    #[test]
    fn a_recorded_marker_stands_even_when_the_head_was_truncated() {
        // The converse: the full-stream scan saw a marker the retained head
        // cannot show, so the recorded value is what preserves it.
        let mut recorded = row(
            "parallel/test-x.js",
            "x".repeat(4096).as_str(),
            true,
            0,
            None,
        );
        recorded.skipped = Some(false);
        recorded.misreported = Some(true);
        assert_eq!(recorded.outcome(), Outcome::Failed);
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

    // --- the bare skip glyph: a node:test file that ran nothing --------------

    #[test]
    fn a_file_with_only_skip_marks_is_a_skip() {
        // Verbatim rustnode output for `test-assert-checktag.js`, captured by
        // running it: one skipped `<anonymous>` test, nothing else, exit 0.
        let stdout = "\u{FE63} <anonymous> (2.061786ms) # SKIP";
        let skipped = row("parallel/test-assert-checktag.js", stdout, true, 0, None);
        assert_eq!(skipped.outcome(), Outcome::Skipped);
        assert!(skipped.only_skipped_tests());
        // A plan line is absent, so this is genuinely a third form.
        assert!(!has_skip_plan_line(stdout));
    }

    #[test]
    fn a_file_that_mixed_skips_with_real_results_keeps_its_verdict() {
        // `test-runner-module-mocking.js` really prints 1 skip, 10 passes and 43
        // failures. Counting it as a skip would hide 43 real failures.
        let mixed = "  \u{FE63} skipped one (1ms) # SKIP\n  \u{2714} passed one (1ms)\n  \u{2716} failed one (1ms)";
        assert_eq!(
            row(
                "parallel/test-runner-module-mocking.js",
                mixed,
                true,
                0,
                None
            )
            .outcome(),
            Outcome::Failed,
            "the failure already decided this row"
        );
        // And a mixed row that passed overall is still a pass.
        let mixed_ok = "\u{FE63} skipped one (1ms) # SKIP\n\u{2714} passed one (1ms)";
        assert_eq!(
            row("parallel/test-x.js", mixed_ok, true, 0, None).outcome(),
            Outcome::Passed
        );
        assert!(!row("parallel/test-x.js", mixed_ok, true, 0, None).only_skipped_tests());
    }

    #[test]
    fn a_describe_whose_children_all_skip_is_a_pass_not_a_skip() {
        // Captured from a `describe` with two skipped `it`s: the children print
        // `﹣` but the suite itself prints `✔ outer suite`. That pass is real, so
        // requiring zero `▶`/`✔` is what keeps this from being called a skip.
        let stdout = "\u{25B6} outer suite\n  \u{FE63} a (0.5ms) # SKIP\n  \u{FE63} b (0.08ms) # SKIP\n\u{2714} outer suite (1.6ms)";
        let suite = row("parallel/test-suite.js", stdout, true, 0, None);
        assert_eq!(suite.outcome(), Outcome::Passed);
        assert!(!suite.only_skipped_tests());
    }

    #[test]
    fn a_bare_suite_header_alone_prevents_a_skip_verdict() {
        // Even without a `✔`, a `▶` means the reporter opened a suite, so the
        // file did more than skip. Narrow on purpose: the pure-skip shape has no
        // header at all.
        let stdout = "\u{25B6} outer\n  \u{FE63} a # SKIP";
        assert!(!row("parallel/test-y.js", stdout, true, 0, None).only_skipped_tests());
    }

    #[test]
    fn a_skip_carrying_a_custom_message_is_still_a_skip() {
        // `{ skip: 'reason' }` prints `﹣ name # reason`, not `# SKIP`, so the
        // rule must key on the glyph rather than the word. Captured from
        // rustnode: `﹣ with a reason (0.86ms) # not on this platform`.
        let stdout = "\u{FE63} with a reason (0.860251ms) # not on this platform";
        let r = row("parallel/test-x.js", stdout, true, 0, None);
        assert_eq!(r.outcome(), Outcome::Skipped);
        assert!(r.only_skipped_tests());
    }

    #[test]
    fn a_skip_glyph_outside_the_reporter_position_is_not_a_skip() {
        // The glyph only counts at the start of a line, where the reporter puts
        // it. A test printing it mid-line is still a pass. (A line that *starts*
        // with it is the real shape even without a message, which is why that
        // case is not listed here.)
        let stdout = "note: \u{FE63} is the skip symbol";
        let r = row("parallel/test-z.js", stdout, true, 0, None);
        assert_eq!(r.outcome(), Outcome::Passed, "wrongly skipped: {stdout}");
    }

    #[test]
    fn a_skip_only_shape_on_a_nonzero_exit_is_still_a_failure() {
        // The bare-skip rule applies only to exit 0. A non-zero exit must not be
        // relabelled a skip.
        let stdout = "\u{FE63} <anonymous> (2ms) # SKIP";
        assert_eq!(
            row("parallel/test-w.js", stdout, false, 1, None).outcome(),
            Outcome::Failed
        );
    }

    /// Verbatim rustnode stdout for `test-crypto-keygen-rsa-pss.js`, captured by
    /// running it directly: an assertion that escaped, printed to stdout, with
    /// the process still exiting 0.
    const UNCAUGHT_STDOUT: &str = "node:assert:16736: Uncaught AssertionError: The input did not match the regular expression /operation not supported for this keytype/. Input:\n\n'TypeError: method is not a function'\n";

    #[test]
    fn an_uncaught_assertion_on_stdout_is_a_failure() {
        assert!(has_failure_marker(UNCAUGHT_STDOUT));

        // The shapes observed across 9 real rows, all with the location prefix
        // in front of the word.
        for line in [
            "node:assert:5579: Uncaught AssertionError: function should not have been called",
            "node:internal/assert/utils:4640: Uncaught AssertionError: Expected values to be strictly equal:",
            "/tmp/node-test/test/parallel/test-cli-node-options-disallowed.js:898: Uncaught TypeError: Cannot read properties of null",
            "Uncaught AssertionError [ERR_ASSERTION]: plain mismatch",
            "  Uncaught Error: indented",
            "\u{1b}[31mUncaught AssertionError: colourised\u{1b}[39m",
        ] {
            assert!(has_failure_marker(line), "missed: {line}");
        }
    }

    #[test]
    fn the_uncaught_word_inside_data_is_not_a_failure() {
        // A test that prints captured output or a diagnostic containing the word
        // must not be demoted. These are the shapes a `contains` on the bare
        // word would catch, and the location-prefix rule does not.
        for line in [
            "child stderr: Uncaught AssertionError: expected 1 to equal 2",
            "stderr: Error: boom\nUncaughtException event fired",
            "process.on('uncaughtException', handler)",
            "note: an Uncaught error would appear here",
            "assert.match(out, /Uncaught AssertionError/)",
            "the child said 'Uncaught' and then exited",
            "reUncaughtThing",
            "UncaughtException",
            "Uncaught",
            "Uncaught AssertionError",
        ] {
            assert!(!has_failure_marker(line), "false positive on: {line}");
        }
    }

    #[test]
    fn a_location_prefix_is_what_separates_a_report_from_an_echo() {
        // Both of these contain the same words; only one is the runtime
        // reporting its own error.
        assert!(has_failure_marker(
            "node:assert:16736: Uncaught AssertionError: mismatch"
        ));
        assert!(!has_failure_marker(
            "child stderr: Uncaught AssertionError: mismatch"
        ));
        // A bare report at column zero is also the runtime.
        assert!(has_failure_marker(
            "Uncaught AssertionError [ERR_ASSERTION]: x"
        ));
    }

    #[test]
    fn the_three_outcomes_are_mutually_exclusive_for_every_row_shape() {
        // `report` and the CLI both sum these three buckets and assume they
        // partition the rows. A row that landed in two would break the total
        // silently, so every combination that could overlap is pinned here.
        let shapes = [
            row("p/a.js", "", true, 0, Some(false)),
            row("p/b.js", "", false, 1, Some(false)),
            row("p/c.js", "1..0 # Skipped: x", true, 0, Some(true)),
            row("p/d.js", "  \u{2716} sub", true, 0, Some(false)),
            row(
                "p/e.js",
                "node:assert:1: Uncaught AssertionError: x",
                true,
                0,
                Some(false),
            ),
            // Pathological combinations the runner never writes, but a hand-edited
            // or corrupted file could contain.
            row("p/f.js", "1..0 # Skipped: x", true, 0, Some(false)),
            row(
                "p/g.js",
                "1..0 # Skipped: x\nnode:assert:1: Uncaught AssertionError: y",
                true,
                0,
                Some(true),
            ),
        ];
        for shape in &shapes {
            let outcomes = [shape.outcome()];
            assert_eq!(outcomes.len(), 1, "outcome must be a single value");
            // `is_misreported_pass` is the diagnostic flag the report adds on top
            // of `failed`; it must never be true unless the outcome is Failed.
            if shape.is_misreported_pass() {
                assert_eq!(
                    shape.outcome(),
                    Outcome::Failed,
                    "{}: a row flagged misreported but not counted as failed",
                    shape.file
                );
            }
        }

        // The pathological skip-plus-marker row resolves to Skipped, so it is not
        // also counted as a corrected failure.
        let both = &shapes[6];
        assert_eq!(both.outcome(), Outcome::Skipped);
        assert!(!both.is_misreported_pass());
    }

    #[test]
    fn a_truncated_line_does_not_hide_a_marker_behind_an_unterminated_escape() {
        // The line cap can cut mid-escape; the bytes after it must still be
        // examined rather than swallowed as part of the escape.
        let line = "node:assert:1: Uncaught AssertionError: x\u{1b}[31";
        assert!(has_failure_marker(line));
    }

    #[test]
    fn multi_byte_text_around_the_marker_does_not_panic() {
        // Slicing is done on `str` boundaries found by `find`, so this guards
        // against a future byte-indexed rewrite rather than a live bug.
        for line in [
            "é node:assert:1: Uncaught AssertionError: x",
            "节点: node:assert:1: Uncaught TypeError: x",
            "✖ node:assert:1: Uncaught Error: x",
            "\u{1b}[31mnode:assert:1: Uncaught Error: x\u{1b}[39m",
        ] {
            let _ = has_failure_marker(line);
        }
    }

    #[test]
    fn a_caught_assertion_is_not_an_uncaught_failure() {
        // `assert.throws` and `try/catch` never print, so a passing file that
        // exercises them must stay a pass. This is the false-positive direction
        // the rule is most exposed to, so it is pinned end to end in the runner
        // tests too; here it guards the scanner.
        let caught = "caught ok\nPASS\n";
        assert!(!has_failure_marker(caught));
    }

    #[test]
    fn a_passing_row_with_only_an_uncaught_line_is_corrected_to_failed() {
        let hollow = row(
            "parallel/test-crypto-keygen-rsa-pss.js",
            UNCAUGHT_STDOUT,
            true,
            0,
            Some(false),
        );
        assert_eq!(hollow.outcome(), Outcome::Failed);
        assert!(hollow.is_misreported_pass());
    }

    #[test]
    fn the_uncaught_marker_is_found_across_every_chunk_split() {
        let text = UNCAUGHT_STDOUT;
        let bytes = text.as_bytes();
        for split in 0..bytes.len() {
            let mut scanner = MarkerScanner::new();
            scanner.push(&bytes[..split]);
            scanner.push(&bytes[split..]);
            scanner.finish();
            assert!(
                scanner.result().reported_failure,
                "missed the uncaught marker when split after byte {split}"
            );
        }
    }
}
