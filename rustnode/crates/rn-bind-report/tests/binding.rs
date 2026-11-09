//! End-to-end checks that drive `report` through the CLI.
//!
//! The config surface is what `lib/internal/process/report.js` exposes as
//! `process.report`, so these drive it the same way that wrapper does. The
//! report itself is checked for the properties that make it safe to attach to a
//! bug report: valid JSON, consistent internal facts, and no leaked secrets.

use std::path::PathBuf;
use std::process::Command;

fn rustnode() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

fn run(script: &str, env: &[(&str, &str)]) -> String {
    let mut command = Command::new(rustnode());
    command.arg("--expose-internals").arg("-e").arg(script);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().expect("the rustnode binary must be built");
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

const PRELUDE: &str = "const realm = require('internal/bootstrap/realm');\
const report = realm.internalBinding('report');";

#[test]
fn the_settings_round_trip_through_the_binding() {
    // `lib/internal/process/report.js` is a thin wrapper over exactly these
    // accessors, so a setter that did not stick would silently change what a
    // crash report contains.
    let output = run(
        &format!(
            "{PRELUDE}
            const before = [report.getCompact(), report.getExcludeEnv(),
                            report.getExcludeNetwork(), report.getSignal()];
            report.setCompact(true);
            report.setExcludeEnv(true);
            report.setExcludeNetwork(true);
            report.setSignal('SIGUSR1');
            const after = [report.getCompact(), report.getExcludeEnv(),
                           report.getExcludeNetwork(), report.getSignal()];
            console.log(before.join(','), after.join(','));"
        ),
        &[],
    );
    // The defaults come from node_options.h: not compact, SIGUSR2.
    assert_eq!(output, "false,false,false,SIGUSR2 true,true,true,SIGUSR1");
}

#[test]
fn the_three_should_report_predicates_default_as_node_does() {
    let output = run(
        &format!(
            "{PRELUDE}
            console.log(report.shouldReportOnFatalError(),
                        report.shouldReportOnSignal(),
                        report.shouldReportOnUncaughtException());
            report.setReportOnFatalError(true);
            report.setReportOnSignal(false);
            report.setReportOnUncaughtException(false);
            console.log(report.shouldReportOnFatalError(),
                        report.shouldReportOnSignal(),
                        report.shouldReportOnUncaughtException());"
        ),
        &[],
    );
    // A signal report is on by default and a fatal-error one is not.
    assert_eq!(output, "false true true\ntrue false false");
}

#[test]
fn write_report_creates_a_valid_json_document() {
    let path = std::env::temp_dir().join(format!("rustnode-report-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let output = run(
        &format!(
            "{PRELUDE}
            report.setDirectory('{directory}');
            report.setFilename('{name}');
            console.log(report.writeReport('a test event', 'test', '', null));",
            directory = path.parent().expect("a temp dir").display(),
            name = path.file_name().expect("a file name").to_string_lossy(),
        ),
        &[],
    );
    assert_eq!(output, path.to_string_lossy());

    let document = std::fs::read_to_string(&path).expect("the report must exist");
    let parsed: serde_json::Value =
        serde_json::from_str(&document).expect("the report must be valid JSON");

    // The facts inside the report have to agree with each other: a report whose
    // pid does not match its own process section is worse than no report. The
    // pid is the child's, so compare the two fields rather than this process.
    assert_eq!(parsed["header"]["reportVersion"], 3);
    assert_eq!(parsed["header"]["trigger"], "test");
    let header_pid = parsed["header"]["processId"].as_u64();
    assert!(
        header_pid.is_some_and(|pid| pid > 0),
        "the report needs a pid"
    );
    assert_eq!(parsed["process"]["pid"], parsed["header"]["processId"]);
    for section in ["header", "javascriptStack", "resourceUsage", "process"] {
        assert!(parsed.get(section).is_some(), "missing {section}");
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_secret_shaped_environment_variable_is_redacted_in_the_report() {
    // A report is meant to be attached to a bug report, so a token must not
    // arrive with its value attached.
    let path =
        std::env::temp_dir().join(format!("rustnode-report-env-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = run(
        &format!(
            "{PRELUDE}
            report.setDirectory('{directory}');
            report.setFilename('{name}');
            report.writeReport('env check', 'test', '', null);",
            directory = path.parent().expect("a temp dir").display(),
            name = path.file_name().expect("a file name").to_string_lossy(),
        ),
        &[("RUSTNODE_TEST_SECRET_TOKEN", "must-not-appear")],
    );

    let document = std::fs::read_to_string(&path).expect("the report must exist");
    assert!(
        !document.contains("must-not-appear"),
        "a secret value must not reach the report"
    );
    assert!(
        document.contains("<redacted>"),
        "the secret must be present but redacted, so the key is still visible"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn get_report_returns_the_document_without_writing_it() {
    let output = run(
        &format!("{PRELUDE} console.log(report.getReport().length > 100);"),
        &[],
    );
    assert_eq!(output, "true");
}

#[test]
fn a_report_can_be_written_when_the_directory_was_never_set() {
    // The default is the current directory, and a crash handler has to be able
    // to write even when nothing configured a path.
    let output = run(
        &format!(
            "{PRELUDE}
            const path = report.writeReport('default path', 'test', '', null);
            console.log(path.length > 0, path.endsWith('.json'));"
        ),
        &[],
    );
    assert_eq!(output, "true true");
}
