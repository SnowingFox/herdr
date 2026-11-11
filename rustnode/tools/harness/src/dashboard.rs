//! Pass-rate table over recorded results.
//!
//! A result directory may hold many runs. Showing the same test twice would make
//! a cluster look bigger than it is, so the dashboard first collapses every run
//! down to one vote per file: the newest recorded outcome wins. That way a test
//! that was failing and is now fixed simply reads as passing, and re-running a
//! subset never inflates the total.
//!
//! Skipped files are counted separately and kept out of the pass rate. A skip
//! asserts nothing, so counting it as a pass inflates the headline number and
//! counting it as a failure understates it; the rate is passes over files that
//! actually ran.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::result::{cluster_of, FileResult, Outcome};

/// One row of the table: a subsystem and how its tests did.
#[derive(Debug, Clone, Serialize)]
pub struct ClusterRow {
    pub cluster: String,
    pub passed: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Every file in the cluster: `passed + skipped + failed`.
    pub total: usize,
    /// Files that actually asserted something: `passed + failed`.
    pub judged: usize,
    /// Files counted as failed because their output announced a failing test
    /// while the process exited 0. A subset of `failed`, not a fourth column.
    pub misreported: usize,
    /// `passed / judged`, or 0.0 when nothing in the cluster ran.
    pub rate: f64,
}

/// The whole dashboard, in the shape `--json` prints.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Result directory that was read.
    pub results_dir: String,
    /// Number of `*.json` files that contributed.
    pub runs: usize,
    /// One row per cluster, sorted by name.
    pub clusters: Vec<ClusterRow>,
    pub passed: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Every file counted once: `passed + skipped + failed`.
    pub total: usize,
    /// Files that actually asserted something: `passed + failed`.
    pub judged: usize,
    /// Files counted as failed because their own output announced a failing test
    /// while the process exited 0. A subset of `failed`, reported so the
    /// correction is visible rather than silent.
    pub misreported: usize,
    /// `passed / judged`, with skips excluded from the denominator.
    pub rate: f64,
    /// Failing files, longest-to-fix first is not knowable, so alphabetical.
    pub failures: Vec<FailureRow>,
    /// Skipped files, alphabetical, so the excluded population is auditable.
    pub skips: Vec<SkipRow>,
}

/// A single skipped test, so `--json` can show what the rate left out.
#[derive(Debug, Clone, Serialize)]
pub struct SkipRow {
    pub file: String,
    pub cluster: String,
    /// The message after `1..0 # Skipped:`, when the row recorded one.
    pub reason: String,
}

/// A single failing test, kept so `--json` can drive per-subsystem triage.
#[derive(Debug, Clone, Serialize)]
pub struct FailureRow {
    pub file: String,
    pub cluster: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// The process exited 0 but its own output announced a failing test.
    ///
    /// This is the hollow-pass case: a subtest failed and the runtime reported
    /// success, because `test:summary` never reached the exit-code path.
    pub misreported: bool,
    /// Truncated first stderr line, enough to name the missing builtin.
    pub reason: String,
}

/// What a directory of results amounts to.
#[derive(Debug, Default)]
pub struct Tally {
    pub runs: usize,
    /// Newest outcome per file, keyed by relative path.
    pub latest: BTreeMap<String, FileResult>,
}

/// Reads every `*.json` in `dir` and keeps the newest outcome for each file.
///
/// "Newest" is decided by the result file's name, which the runner writes as
/// `run-<zero-padded epoch seconds>[-label].json`. Files that do not parse or do
/// not follow that scheme are skipped rather than aborting the dashboard, so one
/// interrupted run cannot hide the rest of the numbers.
pub fn tally(dir: &Path) -> Result<Tally, String> {
    if !dir.is_dir() {
        return Ok(Tally::default());
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut tally = Tally::default();
    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(results) = serde_json::from_str::<Vec<FileResult>>(&text) else {
            continue;
        };
        tally.runs += 1;
        // Paths are sorted, so later files overwrite earlier ones: the last
        // write for a file is the newest one.
        for result in results {
            tally.latest.insert(result.file.clone(), result);
        }
    }
    Ok(tally)
}

/// Builds the report from a tally.
pub fn report(tally: &Tally, results_dir: &Path) -> Report {
    // (passed, skipped, failed, misreported)
    let mut totals: BTreeMap<String, (usize, usize, usize, usize)> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut skips = Vec::new();
    for result in tally.latest.values() {
        let cluster = cluster_of(&result.file);
        let entry = totals.entry(cluster.clone()).or_insert((0, 0, 0, 0));
        match result.outcome() {
            Outcome::Passed => entry.0 += 1,
            Outcome::Skipped => {
                entry.1 += 1;
                skips.push(SkipRow {
                    file: result.file.clone(),
                    cluster,
                    reason: skip_reason(&result.stdout_head),
                });
            }
            Outcome::Failed => {
                entry.2 += 1;
                // A corrected pass is counted in `failed` and named here, so the
                // report can say how much of the failure count came from the
                // output disagreeing with the exit code.
                let misreported = result.is_misreported_pass();
                if misreported {
                    entry.3 += 1;
                }
                failures.push(FailureRow {
                    file: result.file.clone(),
                    cluster,
                    exit_code: result.exit_code,
                    timed_out: result.timed_out,
                    misreported,
                    reason: failure_reason(result),
                });
            }
        }
    }
    failures.sort_by(|a, b| a.file.cmp(&b.file));
    skips.sort_by(|a, b| a.file.cmp(&b.file));

    let clusters: Vec<ClusterRow> = totals
        .into_iter()
        .map(|(cluster, (passed, skipped, failed, misreported))| {
            let judged = passed + failed;
            ClusterRow {
                cluster,
                passed,
                skipped,
                failed,
                total: passed + skipped + failed,
                judged,
                misreported,
                rate: rate(passed, judged),
            }
        })
        .collect();
    let passed: usize = clusters.iter().map(|row| row.passed).sum();
    let skipped: usize = clusters.iter().map(|row| row.skipped).sum();
    let failed: usize = clusters.iter().map(|row| row.failed).sum();
    let misreported: usize = clusters.iter().map(|row| row.misreported).sum();
    let total: usize = clusters.iter().map(|row| row.total).sum();
    let judged = passed + failed;

    Report {
        results_dir: results_dir.display().to_string(),
        runs: tally.runs,
        clusters,
        passed,
        skipped,
        failed,
        total,
        judged,
        misreported,
        rate: rate(passed, judged),
        failures,
        skips,
    }
}

/// Why a failing row failed, in the form that is most useful to a reader.
///
/// A corrected pass has no stderr worth showing — the process claimed success
/// and may have written nothing there — so the reason names the evidence that
/// actually decided the verdict.
fn failure_reason(result: &FileResult) -> String {
    if result.is_misreported_pass() {
        return "exit 0 but output reported a failing test".to_string();
    }
    first_line(&result.stderr_head)
}

/// The rate column for one row.
///
/// A row with nothing judged gets a dash, not `0.0%`: printing zero there would
/// claim every file failed when in fact every file skipped, which is the exact
/// confusion this report exists to remove.
fn rate_cell(judged: usize, rate: f64) -> String {
    if judged == 0 {
        format!("{:>8}", "—")
    } else {
        format!("{:>7.1}%", rate * 100.0)
    }
}

/// `passed / judged`, or 0.0 when no file was actually judged.
fn rate(passed: usize, judged: usize) -> f64 {
    if judged == 0 {
        0.0
    } else {
        passed as f64 / judged as f64
    }
}

/// The text after `1..0 # Skipped:`, for a row that recorded a plan line.
fn skip_reason(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(crate::result::SKIP_PLAN_PREFIX))
        .map(|rest| rest.trim())
        .unwrap_or("")
        .to_string()
}

fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let line = line.trim();
    const LIMIT: usize = 120;
    if line.chars().count() <= LIMIT {
        return line.to_string();
    }
    let mut truncated: String = line.chars().take(LIMIT).collect();
    truncated.push('…');
    truncated
}

/// Renders the aligned text table.
///
/// Widths are computed from the data so long cluster names do not shift the
/// numeric columns, and the total row is separated by a rule. The rate column is
/// passes over judged files; the skipped column is printed next to it so the
/// three populations are legible and `passed + skipped + failed` is the total.
pub fn render_table(report: &Report) -> String {
    let mut out = String::new();
    if report.total == 0 {
        out.push_str(&format!(
            "no results in {}; run the suite first\n",
            report.results_dir
        ));
        return out;
    }

    let name_width = report
        .clusters
        .iter()
        .map(|row| row.cluster.chars().count())
        .chain(std::iter::once("cluster".len()))
        .chain(std::iter::once("TOTAL".len()))
        .max()
        .unwrap_or(7)
        .max(7);

    out.push_str(&format!(
        "{:<name_width$} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
        "cluster",
        "passed",
        "skipped",
        "failed",
        "total",
        "rate",
        name_width = name_width
    ));
    for row in &report.clusters {
        out.push_str(&format!(
            "{:<name_width$} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
            row.cluster,
            row.passed,
            row.skipped,
            row.failed,
            row.total,
            rate_cell(row.judged, row.rate),
            name_width = name_width
        ));
    }
    let rule = "-".repeat(name_width + 43);
    out.push_str(&rule);
    out.push('\n');
    out.push_str(&format!(
        "{:<name_width$} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
        "TOTAL",
        report.passed,
        report.skipped,
        report.failed,
        report.total,
        rate_cell(report.judged, report.rate),
        name_width = name_width
    ));
    out.push_str(&format!(
        "\n{} test file(s) from {} run(s) in {}\n",
        report.total, report.runs, report.results_dir
    ));
    out.push_str(&format!(
        "rate is passed / (passed + failed); {} skipped file(s) are excluded\n",
        report.skipped
    ));
    if report.misreported > 0 {
        out.push_str(&format!(
            "{} of the {} failed file(s) exited 0 while their output reported a failing test\n",
            report.misreported, report.failed
        ));
    }

    if !report.failures.is_empty() {
        const SHOWN: usize = 10;
        out.push_str(&format!("\nfailing files ({}):\n", report.failures.len()));
        for failure in report.failures.iter().take(SHOWN) {
            let status = if failure.misreported {
                // The exit code is the misleading part, so say what it was and
                // that the output disagreed rather than printing a bare exit 0.
                "exit 0 ✖".to_string()
            } else {
                match (failure.timed_out, failure.exit_code) {
                    (true, _) => "timeout".to_string(),
                    (false, Some(code)) => format!("exit {code}"),
                    (false, None) => "signal".to_string(),
                }
            };
            out.push_str(&format!(
                "  {:<52} {:<9} {}\n",
                failure.file, status, failure.reason
            ));
        }
        if report.failures.len() > SHOWN {
            out.push_str(&format!(
                "  … {} more; use --json for the full list\n",
                report.failures.len() - SHOWN
            ));
        }
    }

    if !report.skips.is_empty() {
        const SHOWN: usize = 5;
        out.push_str(&format!("\nskipped files ({}):\n", report.skips.len()));
        for skip in report.skips.iter().take(SHOWN) {
            out.push_str(&format!("  {:<52} {}\n", skip.file, skip.reason));
        }
        if report.skips.len() > SHOWN {
            out.push_str(&format!(
                "  … {} more; use --json for the full list\n",
                report.skips.len() - SHOWN
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::suite_of;
    use crate::result::FileResult;

    fn result(file: &str, passed: bool, stderr: &str) -> FileResult {
        FileResult {
            file: file.to_string(),
            suite: suite_of(file),
            passed,
            skipped: Some(false),
            misreported: Some(false),
            exit_code: Some(if passed { 0 } else { 1 }),
            duration_ms: 5,
            timed_out: false,
            flags: Vec::new(),
            stdout_head: String::new(),
            stderr_head: stderr.to_string(),
        }
    }

    /// A row that skipped: exit 0 is how `test/parallel/**` skips, so the exit
    /// code alone cannot distinguish it from a pass.
    fn skipped_result(file: &str, reason: &str) -> FileResult {
        FileResult {
            file: file.to_string(),
            suite: suite_of(file),
            passed: false,
            skipped: Some(true),
            misreported: Some(false),
            exit_code: Some(0),
            duration_ms: 5,
            timed_out: false,
            flags: Vec::new(),
            stdout_head: format!("1..0 # Skipped: {reason}"),
            stderr_head: String::new(),
        }
    }

    fn write_run(dir: &Path, name: &str, results: &[FileResult]) {
        std::fs::create_dir_all(dir).expect("mkdir");
        std::fs::write(
            dir.join(name),
            serde_json::to_string(results).expect("json"),
        )
        .expect("write");
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("rn-harness-dash-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("mkdir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn tallies_one_vote_per_file_across_runs() {
        let dir = TempDir::new("dedupe");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                result("parallel/test-fs-open.js", false, "no fs"),
                result("parallel/test-fs-read.js", false, "no fs"),
            ],
        );
        // The newer run fixed one of the two files.
        write_run(
            &dir.0,
            "run-0000000200.json",
            &[result("parallel/test-fs-open.js", true, "")],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.runs, 2);
        assert_eq!(report.total, 2, "one vote per file, not per run");
        assert_eq!(report.passed, 1);
        assert_eq!(report.clusters[0].cluster, "fs");
        assert_eq!(report.clusters[0].passed, 1);
        assert_eq!(report.clusters[0].total, 2);
    }

    #[test]
    fn newest_run_wins_even_when_it_is_listed_first_in_sort_order() {
        let dir = TempDir::new("newest");
        // A labelled run sorts after the plain run of the same second, so make
        // sure the label does not make an old result look newer than a new one.
        write_run(
            &dir.0,
            "run-0000000200.json",
            &[result("parallel/test-a-b.js", true, "")],
        );
        write_run(
            &dir.0,
            "run-0000000100-fs.json",
            &[result("parallel/test-a-b.js", false, "old")],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.passed, 1, "the newer plain run must win");
    }

    #[test]
    fn clusters_are_grouped_by_name_not_by_suite() {
        let dir = TempDir::new("clusters");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                result("parallel/test-fs-open.js", false, ""),
                result("sequential/test-fs-watch.js", true, ""),
                result("es-module/test-esm-loader.mjs", false, ""),
            ],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        let clusters: Vec<(&str, usize, usize)> = report
            .clusters
            .iter()
            .map(|row| (row.cluster.as_str(), row.passed, row.total))
            .collect();
        assert_eq!(clusters, vec![("esm", 0, 1), ("fs", 1, 2)]);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.failed, 2, "esm-loader and fs-open both failed");
    }

    #[test]
    fn the_three_totals_reconcile_with_the_file_count() {
        let dir = TempDir::new("reconcile");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                result("parallel/test-fs-open.js", true, ""),
                result("parallel/test-fs-read.js", false, "no fs"),
                skipped_result("parallel/test-fs-skip.js", "missing SQLite"),
                skipped_result("sequential/test-fs-watch.js", "no IPv6 support"),
            ],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.passed, 1, "only the real pass counts");
        assert_eq!(report.skipped, 2, "skips are their own population");
        assert_eq!(report.failed, 1);
        assert_eq!(
            report.passed + report.skipped + report.failed,
            report.total,
            "the three numbers must account for every file"
        );
        assert_eq!(report.total, 4);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.skips.len(), 2);
        for row in &report.clusters {
            assert_eq!(
                row.passed + row.skipped + row.failed,
                row.total,
                "cluster {} does not reconcile",
                row.cluster
            );
        }
    }

    #[test]
    fn skips_are_excluded_from_the_pass_rate() {
        let dir = TempDir::new("skip-rate");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                result("parallel/test-fs-open.js", true, ""),
                result("parallel/test-fs-read.js", false, "no fs"),
                skipped_result("parallel/test-fs-skip.js", "missing SQLite"),
                skipped_result("parallel/test-fs-skip2.js", "missing SQLite"),
            ],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        // 1 of 2 judged files pass, not 1 of 4 recorded files (25%) and not
        // 1 of 4 minus skips confused with failures.
        assert!((report.rate - 0.5).abs() < 1e-9, "rate was {}", report.rate);
        assert_eq!(report.total, 4);
    }

    #[test]
    fn an_all_skipped_report_has_no_rate_instead_of_a_fake_zero_or_one() {
        let dir = TempDir::new("all-skipped");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                skipped_result("parallel/test-a-b.js", "no IPv6 support"),
                skipped_result("parallel/test-c-d.js", "no IPv6 support"),
            ],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.total, 2);
        assert_eq!(report.skipped, 2);
        assert_eq!(report.failed, 0);
        assert_eq!(report.passed, 0);
        assert_eq!(report.rate, 0.0, "no file was judged");
        let table = render_table(&report);
        assert!(table.contains("skipped"), "{table}");
    }

    #[test]
    fn a_skip_is_not_listed_as_a_failure() {
        let dir = TempDir::new("skip-not-failure");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[skipped_result("parallel/test-fs-skip.js", "missing SQLite")],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert!(report.failures.is_empty(), "a skip is not a failure");
        assert_eq!(report.skips[0].file, "parallel/test-fs-skip.js");
        assert_eq!(report.skips[0].reason, "missing SQLite");
    }

    #[test]
    fn an_old_result_file_without_the_skipped_field_still_loads_and_classifies() {
        let dir = TempDir::new("old-format");
        // Exactly what a pre-change runner wrote: no `skipped` key at all, a
        // skipped file with exit 0 recorded as `passed: true`.
        let old = r#"[
          {
            "file": "parallel/test-cluster-dgram-ipv6only.js",
            "suite": "parallel",
            "passed": true,
            "exit_code": 0,
            "duration_ms": 87,
            "timed_out": false,
            "flags": [],
            "stdout_head": "1..0 # Skipped: no IPv6 support",
            "stderr_head": ""
          }
        ]"#;
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        std::fs::write(dir.0.join("run-0000000100.json"), old).expect("write");

        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.skipped, 1, "the recorded stdout proves the skip");
        assert_eq!(report.passed, 0, "a skip must not be counted as a pass");
        assert_eq!(report.failed, 0, "nor as a failure");
        assert_eq!(report.total, 1);
        assert_eq!(report.skips[0].reason, "no IPv6 support");
    }

    #[test]
    fn a_timeout_is_still_a_failure_and_never_a_skip() {
        let dir = TempDir::new("timeout-skip");
        let mut killed = result("parallel/test-hang.js", false, "timed out after 30s");
        killed.timed_out = true;
        killed.exit_code = None;
        write_run(&dir.0, "run-0000000100.json", &[killed]);
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.failed, 1);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.total, 1);
    }

    /// A row that exited 0 while its own output announced a failing test.
    fn hollow_result(file: &str, stdout: &str) -> FileResult {
        FileResult {
            file: file.to_string(),
            suite: suite_of(file),
            passed: true,
            skipped: Some(false),
            misreported: Some(true),
            exit_code: Some(0),
            duration_ms: 5,
            timed_out: false,
            flags: Vec::new(),
            stdout_head: stdout.to_string(),
            stderr_head: String::new(),
        }
    }

    #[test]
    fn a_hollow_pass_is_counted_as_failed_and_reported_as_misreported() {
        let dir = TempDir::new("hollow");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                result("parallel/test-fs-open.js", true, ""),
                hollow_result(
                    "parallel/test-runner-reporters.js",
                    "▶ node:test reporters\n  ✖ first\n✖ node:test reporters",
                ),
            ],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.passed, 1, "only the clean file passes");
        assert_eq!(
            report.failed, 1,
            "the hollow pass counts against the runtime"
        );
        assert_eq!(report.misreported, 1, "and is named as a correction");
        assert_eq!(report.skipped, 0);
        assert_eq!(
            report.passed + report.skipped + report.failed,
            report.total,
            "the correction must not break the sum"
        );
        assert_eq!(report.total, 2);
        assert!((report.rate - 0.5).abs() < 1e-9, "rate was {}", report.rate);

        let row = report
            .failures
            .iter()
            .find(|row| row.file == "parallel/test-runner-reporters.js")
            .expect("the hollow pass must be listed as a failure");
        assert!(row.misreported);
        assert_eq!(row.exit_code, Some(0));
        assert!(
            row.reason
                .contains("exit 0 but output reported a failing test"),
            "the reason must name the disagreement: {}",
            row.reason
        );
    }

    #[test]
    fn misreported_is_a_subset_of_failed_not_a_fourth_population() {
        let dir = TempDir::new("hollow-subset");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                hollow_result("parallel/test-runner-reporters.js", "  ✖ first"),
                result("parallel/test-buffer-bytelength.js", false, "no buffer"),
                skipped_result("parallel/test-a-skip.js", "no IPv6 support"),
            ],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.failed, 2, "one ordinary failure plus one correction");
        assert_eq!(report.misreported, 1);
        assert!(
            report.misreported <= report.failed,
            "misreported must never exceed failed"
        );
        assert_eq!(report.passed, 0);
        assert_eq!(report.total, 3);
        let cluster_misreported: usize = report.clusters.iter().map(|row| row.misreported).sum();
        assert_eq!(cluster_misreported, report.misreported);
    }

    #[test]
    fn an_old_file_with_a_hollow_pass_re_reads_as_failed() {
        let dir = TempDir::new("old-hollow");
        // No `misreported` key: this is what the previous harness wrote for a
        // file whose subtests failed and which still exited 0.
        let old = r#"[
          {
            "file": "parallel/test-runner-reporters.js",
            "suite": "parallel",
            "passed": true,
            "skipped": false,
            "exit_code": 0,
            "duration_ms": 189,
            "timed_out": false,
            "stdout_head": "\u25b6 node:test reporters\n  \u001b[31m\u2716 first \u001b[39m\n  \u001b[31m\u2716 second \u001b[39m",
            "stderr_head": ""
          }
        ]"#;
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        std::fs::write(dir.0.join("run-0000000100.json"), old).expect("write");
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.passed, 0);
        assert_eq!(report.failed, 1);
        assert_eq!(report.misreported, 1);
        assert_eq!(report.total, 1);
    }

    /// The four rows named in the bug report, plus two hollow passes: real
    /// records from runs against the pinned tree, written before `skipped` and
    /// `misreported` existed, all recorded as `passed: true` with exit 0.
    fn recorded_skips_fixture() -> &'static str {
        include_str!("../tests/fixtures/run-1794255368768-skips.json")
    }

    #[test]
    fn the_four_recorded_skips_are_reported_as_skipped_not_passed() {
        let dir = TempDir::new("recorded-skips");
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        std::fs::write(
            dir.0.join("run-1794255368768.json"),
            recorded_skips_fixture(),
        )
        .expect("write");

        let tally = tally(&dir.0).expect("tally");
        assert_eq!(tally.latest.len(), 10, "every row must parse");
        let report = report(&tally, &dir.0);

        let expected = [
            "parallel/test-assert-checktag.js",
            "parallel/test-child-process-exec-any-shells-windows.js",
            "parallel/test-child-process-stdio-overlapped.js",
            "parallel/test-cluster-dgram-ipv6only.js",
            "parallel/test-cluster-net-listen-ipv6only-false.js",
        ];
        let reported: Vec<&str> = report.skips.iter().map(|row| row.file.as_str()).collect();
        assert_eq!(
            reported, expected,
            "four plan-line skips and one bare-glyph skip, in file order"
        );

        assert_eq!(report.skipped, 5);
        // test-fs-open.js is the only clean pass; the three hollow passes and the
        // one real failure are all failures.
        assert_eq!(report.passed, 1, "only test-fs-open.js really passed");
        assert_eq!(report.failed, 4);
        assert_eq!(
            report.misreported, 3,
            "two rows printed the reporter glyph, one an uncaught assertion"
        );
        assert_eq!(report.total, 10);
        assert_eq!(report.passed + report.skipped + report.failed, 10);
        // 1 of 5 judged files pass. The old harness said 9 of 10 (90%).
        assert!((report.rate - 0.2).abs() < 1e-9, "rate was {}", report.rate);

        // The bare-glyph row has no plan line, so its reason is empty rather than
        // a parsed message; the outcome is what matters.
        assert_eq!(report.skips[0].reason, "");
        assert_eq!(report.skips[1].reason, "Windows specific test.");
        assert_eq!(report.skips[3].reason, "no IPv6 support");

        let corrected: Vec<&str> = report
            .failures
            .iter()
            .filter(|row| row.misreported)
            .map(|row| row.file.as_str())
            .collect();
        assert_eq!(
            corrected,
            vec![
                "parallel/test-assert-deep.js",
                "parallel/test-crypto-keygen-rsa-pss.js",
                "parallel/test-runner-reporters.js"
            ]
        );
    }

    #[test]
    fn failures_are_listed_with_a_short_reason() {
        let dir = TempDir::new("failures");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                result(
                    "parallel/test-fs-open.js",
                    false,
                    "\n\nReferenceError: require is not defined\n at x",
                ),
                result("parallel/test-fs-read.js", true, ""),
            ],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].file, "parallel/test-fs-open.js");
        assert_eq!(
            report.failures[0].reason,
            "ReferenceError: require is not defined"
        );
    }

    #[test]
    fn long_reasons_are_truncated() {
        let dir = TempDir::new("long-reason");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[result("parallel/test-x-y.js", false, &"e".repeat(400))],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert!(report.failures[0].reason.chars().count() <= 121);
    }

    #[test]
    fn empty_directory_renders_an_explanation_instead_of_a_table() {
        let dir = TempDir::new("empty");
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.total, 0);
        let table = render_table(&report);
        assert!(table.contains("run the suite first"), "{table}");
        assert!(!table.contains("TOTAL"), "{table}");
    }

    #[test]
    fn missing_directory_is_not_an_error() {
        let tally = tally(Path::new("/nonexistent/rn-harness-results")).expect("tally");
        assert_eq!(tally.runs, 0);
        assert!(tally.latest.is_empty());
    }

    #[test]
    fn unparseable_files_are_skipped() {
        let dir = TempDir::new("garbage");
        std::fs::write(dir.0.join("run-0000000100.json"), "not json").expect("write");
        write_run(
            &dir.0,
            "run-0000000200.json",
            &[result("parallel/test-a-b.js", true, "")],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        assert_eq!(report.runs, 1);
        assert_eq!(report.total, 1);
    }

    #[test]
    fn table_aligns_columns_and_ends_with_the_total() {
        let dir = TempDir::new("table");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                result("parallel/test-fs-open.js", true, ""),
                result(
                    "parallel/test-very-long-cluster-name-here-x-y.js",
                    false,
                    "",
                ),
            ],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        let table = render_table(&report);
        let total_line = table
            .lines()
            .find(|line| line.starts_with("TOTAL"))
            .expect("total row");
        assert!(
            total_line.contains("1") && total_line.contains("2"),
            "{table}"
        );
        assert!(total_line.contains("50.0%"), "{table}");
        // Every row must have the same width up to the numbers.
        let widths: Vec<usize> = table
            .lines()
            .filter(|line| line.contains('%'))
            .map(|line| line.find(char::is_numeric).unwrap_or(0))
            .collect();
        assert!(
            widths.windows(2).all(|pair| pair[0] == pair[1]),
            "columns drift: {table}"
        );
    }

    #[test]
    fn a_row_with_nothing_judged_prints_a_dash_not_a_zero_rate() {
        let dir = TempDir::new("dash-rate");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[skipped_result("parallel/test-a-b.js", "no IPv6 support")],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        let table = render_table(&report);
        assert!(
            !table.contains("0.0%"),
            "an all-skipped row must not read as 0% passing: {table}"
        );
        assert!(table.contains('—'), "expected a dash rate cell: {table}");
    }

    #[test]
    fn the_table_headers_name_all_three_outcomes() {
        let dir = TempDir::new("headers");
        write_run(
            &dir.0,
            "run-0000000100.json",
            &[
                result("parallel/test-fs-open.js", true, ""),
                skipped_result("parallel/test-fs-skip.js", "no IPv6 support"),
                result("parallel/test-fs-read.js", false, "no fs"),
            ],
        );
        let report = report(&tally(&dir.0).expect("tally"), &dir.0);
        let table = render_table(&report);
        let header = table.lines().next().expect("header row");
        for column in ["passed", "skipped", "failed", "total", "rate"] {
            assert!(
                header.contains(column),
                "header is missing {column}: {table}"
            );
        }
        let total_line = table
            .lines()
            .find(|line| line.starts_with("TOTAL"))
            .expect("total row");
        let numbers: Vec<&str> = total_line
            .split_whitespace()
            .filter(|word| word.chars().all(|c| c.is_ascii_digit()))
            .collect();
        assert_eq!(
            numbers,
            vec!["1", "1", "1", "3"],
            "TOTAL must print passed, skipped, failed, total: {table}"
        );
        assert!(
            table.contains("skipped file(s) are excluded"),
            "the table must say skips are out of the rate: {table}"
        );
    }
}
