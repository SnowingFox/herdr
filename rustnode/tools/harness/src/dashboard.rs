//! Pass-rate table over recorded results.
//!
//! A result directory may hold many runs. Showing the same test twice would make
//! a cluster look bigger than it is, so the dashboard first collapses every run
//! down to one vote per file: the newest recorded outcome wins. That way a test
//! that was failing and is now fixed simply reads as passing, and re-running a
//! subset never inflates the total.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::result::{cluster_of, FileResult};

/// One row of the table: a subsystem and how its tests did.
#[derive(Debug, Clone, Serialize)]
pub struct ClusterRow {
    pub cluster: String,
    pub passed: usize,
    pub total: usize,
    /// `passed / total`, or 0.0 when the cluster somehow has no tests.
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
    pub total: usize,
    pub rate: f64,
    /// Failing files, longest-to-fix first is not knowable, so alphabetical.
    pub failures: Vec<FailureRow>,
}

/// A single failing test, kept so `--json` can drive per-subsystem triage.
#[derive(Debug, Clone, Serialize)]
pub struct FailureRow {
    pub file: String,
    pub cluster: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
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
    let mut totals: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failures = Vec::new();
    for result in tally.latest.values() {
        let cluster = cluster_of(&result.file);
        let entry = totals.entry(cluster.clone()).or_insert((0, 0));
        entry.1 += 1;
        if result.passed {
            entry.0 += 1;
        } else {
            failures.push(FailureRow {
                file: result.file.clone(),
                cluster,
                exit_code: result.exit_code,
                timed_out: result.timed_out,
                reason: first_line(&result.stderr_head),
            });
        }
    }
    failures.sort_by(|a, b| a.file.cmp(&b.file));

    let clusters: Vec<ClusterRow> = totals
        .into_iter()
        .map(|(cluster, (passed, total))| ClusterRow {
            cluster,
            passed,
            total,
            rate: rate(passed, total),
        })
        .collect();
    let passed: usize = clusters.iter().map(|row| row.passed).sum();
    let total: usize = clusters.iter().map(|row| row.total).sum();

    Report {
        results_dir: results_dir.display().to_string(),
        runs: tally.runs,
        clusters,
        passed,
        total,
        rate: rate(passed, total),
        failures,
    }
}

fn rate(passed: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    }
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
/// numeric columns, and the total row is separated by a rule.
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
        "{:<name_width$} {:>8} {:>8} {:>8}\n",
        "cluster",
        "passed",
        "total",
        "rate",
        name_width = name_width
    ));
    for row in &report.clusters {
        out.push_str(&format!(
            "{:<name_width$} {:>8} {:>8} {:>7.1}%\n",
            row.cluster,
            row.passed,
            row.total,
            row.rate * 100.0,
            name_width = name_width
        ));
    }
    let rule = "-".repeat(name_width + 26);
    out.push_str(&rule);
    out.push('\n');
    out.push_str(&format!(
        "{:<name_width$} {:>8} {:>8} {:>7.1}%\n",
        "TOTAL",
        report.passed,
        report.total,
        report.rate * 100.0,
        name_width = name_width
    ));
    out.push_str(&format!(
        "\n{} test file(s) from {} run(s) in {}\n",
        report.total, report.runs, report.results_dir
    ));

    if !report.failures.is_empty() {
        const SHOWN: usize = 10;
        out.push_str(&format!("\nfailing files ({}):\n", report.failures.len()));
        for failure in report.failures.iter().take(SHOWN) {
            let status = match (failure.timed_out, failure.exit_code) {
                (true, _) => "timeout".to_string(),
                (false, Some(code)) => format!("exit {code}"),
                (false, None) => "signal".to_string(),
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
            exit_code: Some(if passed { 0 } else { 1 }),
            duration_ms: 5,
            timed_out: false,
            flags: Vec::new(),
            stdout_head: String::new(),
            stderr_head: stderr.to_string(),
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
}
