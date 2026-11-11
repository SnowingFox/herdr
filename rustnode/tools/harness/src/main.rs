//! Measures how much of Node's own test suite rustnode passes.
//!
//! Two subcommands:
//!
//! ```text
//! rn-harness run     --node <binary> --tests <node-tree>/test [filters]
//! rn-harness report  [--results <dir>] [--json]
//! ```
//!
//! `run` executes test files and writes one JSON file per invocation. `report`
//! folds every recorded file into the per-subsystem table each workstream reads.
//!
//! The Node test tree is never vendored here: it is 103 MB, it belongs to the
//! pinned revision, and the harness only needs a path to it.

mod dashboard;
mod result;
mod runner;
mod select;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use crate::select::{Filter, SMOKE_SUBSET, SUITES};

const USAGE: &str = "\
rn-harness — pass rate of Node's own test suite against a node-compatible binary

USAGE:
    rn-harness run    --node <binary> --tests <dir> [options]
    rn-harness report [--results <dir>] [--json]

RUN OPTIONS:
    --node <path>        executable under test (default: ./target/debug/rustnode)
    --tests <path>       path to the Node checkout's test/ directory (required)
    --suite <name>       run only this suite; repeatable. One of:
                         parallel, sequential, es-module, internet, pummel,
                         message, known_issues, node-api
    --filter <substring> run only files whose path contains this text;
                         repeatable, case-insensitive
    --only <path>        run one exact test path, relative to test/;
                         repeatable. Overrides --suite and --filter
    --limit <n>          stop after n selected files
    --all                run every test file; without a selector the runner
                         runs the fixed 10-file smoke subset instead
    --smoke              run the fixed 10-file subset across core subsystems
    --timeout <seconds>  per-file limit (default: 30)
    --jobs <n>           concurrent files for parallel-safe suites
                         (default: available parallelism, capped at 8)
    --results <dir>      where to write the result file
                         (default: tools/harness/results)
    --label <name>       suffix the result file so runs stay distinguishable
    --quiet              do not stream per-file progress

REPORT OPTIONS:
    --results <dir>      directory of result files (default: tools/harness/results)
    --json               print the report as JSON instead of a table

EXAMPLES:
    # default: the 10-file smoke subset, against the debug build
    rn-harness run --tests /tmp/node/test

    # the whole suite, one suite at a time
    rn-harness run --tests /tmp/node/test --all

    # every fs test in parallel and sequential, then look at the table
    rn-harness run --tests /tmp/node/test --filter test-fs- --limit 50
    rn-harness report

    # what a workstream owner runs for their own subsystem
    rn-harness run --tests /tmp/node/test --filter test-buffer- --label buffer
    rn-harness report --json

The test tree is cloned, never vendored:

    git clone --depth 1 --filter=blob:none --sparse \\
        https://github.com/nodejs/node /tmp/node
    cd /tmp/node && git sparse-checkout set test
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run_command(&args[1..]).map(ExitCode::from),
        Some("report") => report_command(&args[1..]),
        Some("--help" | "-h" | "help") | None => {
            print!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(format!("unknown subcommand '{other}'\n\n{USAGE}")),
    };
    match result {
        Ok(code) => code,
        Err(message) => {
            eprintln!("rn-harness: {message}");
            ExitCode::from(2)
        }
    }
}

fn default_results_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results")
}

fn next_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn run_command(args: &[String]) -> Result<u8, String> {
    let mut node: Option<PathBuf> = None;
    let mut tests: Option<PathBuf> = None;
    let mut results = default_results_dir();
    let mut filter = Filter::default();
    let mut timeout = Duration::from_secs(30);
    let mut jobs = None;
    let mut label: Option<String> = None;
    let mut quiet = false;
    let mut smoke = false;
    let mut all = false;

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "--node" => node = Some(PathBuf::from(next_value(args, &mut index, arg)?)),
            "--tests" => tests = Some(PathBuf::from(next_value(args, &mut index, arg)?)),
            "--results" => results = PathBuf::from(next_value(args, &mut index, arg)?),
            "--suite" => {
                let suite = next_value(args, &mut index, arg)?;
                if !SUITES.contains(&suite.as_str()) {
                    return Err(format!(
                        "unknown suite '{suite}'; expected one of {}",
                        SUITES.join(", ")
                    ));
                }
                filter.suites.push(suite);
            }
            "--filter" => filter.names.push(next_value(args, &mut index, arg)?),
            "--only" => filter.only.push(next_value(args, &mut index, arg)?),
            "--limit" => {
                let raw = next_value(args, &mut index, arg)?;
                let parsed: usize = raw
                    .parse()
                    .map_err(|_| format!("--limit needs a number, got '{raw}'"))?;
                filter.limit = Some(parsed);
            }
            "--timeout" => {
                let raw = next_value(args, &mut index, arg)?;
                let parsed: u64 = raw
                    .parse()
                    .map_err(|_| format!("--timeout needs whole seconds, got '{raw}'"))?;
                if parsed == 0 {
                    return Err("--timeout must be at least 1 second".to_string());
                }
                timeout = Duration::from_secs(parsed);
            }
            "--jobs" => {
                let raw = next_value(args, &mut index, arg)?;
                let parsed: usize = raw
                    .parse()
                    .map_err(|_| format!("--jobs needs a number, got '{raw}'"))?;
                if parsed == 0 {
                    return Err("--jobs must be at least 1".to_string());
                }
                jobs = Some(parsed);
            }
            "--label" => label = Some(next_value(args, &mut index, arg)?),
            "--smoke" => smoke = true,
            "--all" => all = true,
            "--quiet" => quiet = true,
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(0);
            }
            other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
        }
        index += 1;
    }

    let node = node.unwrap_or_else(default_node_path);
    let tests = tests.ok_or_else(|| {
        "--tests <path> is required (the Node checkout's test/ directory)".to_string()
    })?;
    // Tests execute from the Node checkout root, so a relative runtime path
    // would resolve against the wrong directory. Resolve both now, while they
    // still mean what the caller typed.
    let node = std::path::absolute(&node)
        .map_err(|error| format!("cannot resolve {}: {error}", node.display()))?;
    let tests = std::path::absolute(&tests)
        .map_err(|error| format!("cannot resolve {}: {error}", tests.display()))?;
    runner::check_node_binary(&node)?;

    if smoke {
        filter.only = SMOKE_SUBSET.iter().map(|path| path.to_string()).collect();
        filter.suites.clear();
        filter.names.clear();
        // A smoke run is a fixed subset; a limit would silently trim it.
        filter.limit = None;
    } else if !all && !selects_anything(&filter) {
        // A full walk is 5,666 files and currently fails almost entirely, so the
        // default is the small subset that says something in one second.
        filter.only = SMOKE_SUBSET.iter().map(|path| path.to_string()).collect();
        if !quiet {
            println!(
                "no --suite/--filter/--only/--limit given; running the {}-file smoke subset (use --all for everything)",
                SMOKE_SUBSET.len()
            );
        }
    }

    let selection = select::collect(&tests, &filter)?;
    if selection.tests.is_empty() {
        return Err(format!(
            "no tests matched under {}; check --suite, --filter and --only",
            tests.display()
        ));
    }

    let mut config = runner::RunConfig::new(node.clone(), tests.clone());
    config.timeout = timeout;
    if let Some(jobs) = jobs {
        config.jobs = jobs;
    }

    if !quiet {
        println!(
            "running {} test file(s) with {} ({} job(s), {}s timeout)",
            selection.tests.len(),
            node.display(),
            config.jobs,
            timeout.as_secs()
        );
    }

    let mut done = 0usize;
    let mut announce = |result: &result::FileResult| {
        done += 1;
        if !quiet {
            let status = match result.outcome() {
                result::Outcome::Passed => "pass",
                result::Outcome::Skipped => "skip",
                result::Outcome::Failed if result.is_misreported_pass() => "fail*",
                result::Outcome::Failed if result.timed_out => "timeout",
                result::Outcome::Failed => "fail",
            };
            println!(
                "  [{done}/{}] {status:<7} {:>6}ms {}",
                selection.tests.len(),
                result.duration_ms,
                result.file
            );
        }
    };
    let results_vec = runner::run_all(&config, &selection.tests, &mut announce);

    let run_id = runner::run_id();
    let file_name = runner::result_file_name(&run_id, label.as_deref());
    let written = runner::write_results(&results, &file_name, &results_vec)?;
    let passed_total = results_vec
        .iter()
        .filter(|r| r.outcome() == result::Outcome::Passed)
        .count();
    let skipped_total = results_vec
        .iter()
        .filter(|r| r.outcome() == result::Outcome::Skipped)
        .count();
    let misreported_total = results_vec
        .iter()
        .filter(|r| r.is_misreported_pass())
        .count();
    let failed_total = results_vec.len() - passed_total - skipped_total;
    let judged = passed_total + failed_total;
    let total = results_vec.len();

    // A skip is neither a pass nor a failure, so the headline rate is passes
    // over files that actually ran, and the skipped count is printed next to it
    // rather than folded into either side. `fail*` rows are failures the runtime
    // reported as successes; they are already inside `failed`.
    println!(
        "{passed_total}/{judged} judged passed ({:.1}%); {skipped_total} skipped; {failed_total} failed ({misreported_total} exit 0 with failing output); {total} total",
        if judged == 0 {
            0.0
        } else {
            passed_total as f64 / judged as f64 * 100.0
        }
    );
    if misreported_total > 0 {
        println!("fail* marks a file whose own output reported a failing test while it exited 0");
    }
    println!("results written to {}", written.display());
    println!("run `rn-harness report` for the per-subsystem breakdown");

    // A run that measured something is a successful run even when nothing
    // passes: the point is the number, not the verdict. Exit 0 so scripts can
    // continue; use `report` or the result files to gate.
    Ok(0)
}

/// Whether the caller narrowed the run to something smaller than the full suite.
fn selects_anything(filter: &Filter) -> bool {
    !filter.suites.is_empty()
        || !filter.names.is_empty()
        || !filter.only.is_empty()
        || filter.limit.is_some()
}

/// Falls back to the workspace debug binary so the common case needs no flag.
fn default_node_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/rustnode")
}

fn report_command(args: &[String]) -> Result<ExitCode, String> {
    let mut results = default_results_dir();
    let mut json = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--results" => results = PathBuf::from(next_value(args, &mut index, "--results")?),
            "--json" => json = true,
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
        }
        index += 1;
    }

    let tally = dashboard::tally(&results)?;
    let report = dashboard::report(&tally, &results);
    if json {
        let text = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
        println!("{text}");
    } else {
        print!("{}", dashboard::render_table(&report));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tests_flag_is_rejected_with_guidance() {
        let error = run_command(&[]).expect_err("must fail");
        assert!(error.contains("--tests"), "{error}");
    }

    #[test]
    fn unknown_suite_is_rejected() {
        let error = run_command(&[
            "--tests".into(),
            "/tmp".into(),
            "--suite".into(),
            "nope".into(),
        ])
        .expect_err("must fail");
        assert!(error.contains("unknown suite"), "{error}");
    }

    #[test]
    fn a_flag_without_a_value_is_rejected() {
        let error = run_command(&["--tests".into()]).expect_err("must fail");
        assert!(error.contains("needs a value"), "{error}");
    }

    #[test]
    fn non_numeric_limit_is_rejected() {
        let error = run_command(&[
            "--tests".into(),
            "/tmp".into(),
            "--limit".into(),
            "many".into(),
        ])
        .expect_err("must fail");
        assert!(error.contains("--limit"), "{error}");
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let error = run_command(&[
            "--tests".into(),
            "/tmp".into(),
            "--timeout".into(),
            "0".into(),
        ])
        .expect_err("must fail");
        assert!(error.contains("--timeout"), "{error}");
    }

    #[test]
    fn a_bare_run_counts_as_no_selection() {
        assert!(!selects_anything(&Filter::default()));
        let narrowed = Filter {
            names: vec!["fs".into()],
            ..Filter::default()
        };
        assert!(selects_anything(&narrowed));
        let capped = Filter {
            limit: Some(1),
            ..Filter::default()
        };
        assert!(selects_anything(&capped));
    }

    #[test]
    fn smoke_subset_has_no_duplicates_and_ten_entries() {
        let mut sorted = SMOKE_SUBSET.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), SMOKE_SUBSET.len(), "duplicate smoke entry");
        assert_eq!(SMOKE_SUBSET.len(), 10);
        assert!(SMOKE_SUBSET
            .iter()
            .all(|path| path.starts_with("parallel/") || path.starts_with("es-module/")));
    }
}
