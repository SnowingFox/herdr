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

fn run_in(script: &str, cwd: &std::path::Path) -> String {
    let mut command = Command::new(rustnode());
    command
        .current_dir(cwd)
        .arg("--expose-internals")
        .arg("-e")
        .arg(script);
    let output = command.output().expect("the rustnode binary must be built");
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// A disposable working directory. `writeReport` with no configured directory
/// writes next to the cwd, so a test of that default must not run in the crate
/// source tree.
fn scratch_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rustnode-report-cwd-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
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
    // `TriggerNodeReport` returns the *name* it was given, not the joined path:
    // `process.report.writeReport()` reports `x.json` while writing
    // `<directory>/x.json`. A caller that wants the location joins it itself.
    assert_eq!(
        output,
        path.file_name().expect("a file name").to_string_lossy()
    );

    let document = std::fs::read_to_string(&path).expect("the report must exist");
    let parsed: serde_json::Value =
        serde_json::from_str(&document).expect("the report must be valid JSON");

    // The facts inside the report have to agree with each other: a report whose
    // pid does not match its own process section is worse than no report. The
    // pid is the child's, so compare the two fields rather than this process.
    // `NODE_REPORT_VERSION` is 5; emitting 3 tells a consumer to parse the
    // document with a schema that predates the fields it is reading.
    assert_eq!(parsed["header"]["reportVersion"], 5);
    assert_eq!(parsed["header"]["trigger"], "test");
    let header_pid = parsed["header"]["processId"].as_u64();
    assert!(
        header_pid.is_some_and(|pid| pid > 0),
        "the report needs a pid"
    );
    for section in [
        "header",
        "javascriptStack",
        "javascriptHeap",
        "nativeStack",
        "resourceUsage",
        "uvthreadResourceUsage",
        "libuv",
        "workers",
        "environmentVariables",
        "userLimits",
        "sharedObjects",
    ] {
        assert!(parsed.get(section).is_some(), "missing {section}");
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_document_is_node_report_version_5_with_node_sections() {
    // `reportVersion` is the schema a consumer parses the document with, and the
    // section set is the rest of that contract. This build emitted version 3 with
    // a `process` section Node never writes and without `libuv`, `workers`,
    // `uvthreadResourceUsage`, `sharedObjects` or top-level `userLimits`.
    let output = run(
        &format!(
            "{PRELUDE}
            const document = JSON.parse(report.getReport());
            console.log(document.header.reportVersion);
            console.log(Object.keys(document).join(','));
            console.log(Object.keys(document.header).join(','));
            console.log(JSON.stringify(document.header.filename));
            console.log(document.header.event, '|', document.header.trigger);"
        ),
        &[],
    );
    let mut lines = output.lines();
    assert_eq!(lines.next(), Some("5"), "NODE_REPORT_VERSION is 5");
    assert_eq!(
        lines.next(),
        Some(
            "header,javascriptStack,javascriptHeap,nativeStack,resourceUsage,\
             uvthreadResourceUsage,libuv,workers,environmentVariables,userLimits,\
             sharedObjects"
        )
    );
    let header = lines.next().expect("the header keys");
    for field in [
        "reportVersion",
        "event",
        "trigger",
        "filename",
        "dumpEventTime",
        "dumpEventTimeStamp",
        "processId",
        "threadId",
        "cwd",
        "commandLine",
        "nodejsVersion",
        "glibcVersionRuntime",
        "glibcVersionCompiler",
        "wordSize",
        "arch",
        "platform",
        "componentVersions",
        "release",
        "osName",
        "osRelease",
        "osVersion",
        "osMachine",
        "cpus",
        "networkInterfaces",
        "host",
    ] {
        assert!(header.contains(field), "the header needs {field}: {header}");
    }
    // `environmentVariables` and `userLimits` are sections, not header fields.
    assert!(!header.contains("environmentVariables"));
    assert!(!header.contains("userLimits"));
    // `getReport()` has no filename, and Node writes `null` rather than omitting
    // the key.
    assert_eq!(lines.next(), Some("null"));
    assert_eq!(lines.next(), Some("JavaScript API | GetReport"));
}

#[test]
fn the_document_never_invents_a_process_section() {
    let output = run(
        &format!(
            "{PRELUDE}
            const document = JSON.parse(report.getReport());
            console.log(Object.prototype.hasOwnProperty.call(document, 'process'));
            console.log(Array.isArray(document.workers), document.workers.length);
            console.log(typeof document.sharedObjects[0]);
            console.log(typeof document.userLimits.open_files.soft);
            console.log(Object.keys(document.javascriptHeap.heapSpaces).length > 0);"
        ),
        &[],
    );
    assert_eq!(output, "false\ntrue 0\nstring\nnumber\ntrue");
}

#[test]
fn write_report_prints_nodes_banners_and_returns_the_given_name() {
    // A monitoring wrapper greps for these two lines, and the return value is the
    // name the caller supplied rather than the joined path.
    let directory =
        std::env::temp_dir().join(format!("rustnode-report-banner-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a scratch directory");
    let mut command = Command::new(rustnode());
    let output = command
        .arg("--expose-internals")
        .arg("-e")
        .arg(format!(
            "const realm = require('internal/bootstrap/realm');\
             const report = realm.internalBinding('report');\
             report.setDirectory('{directory}');\
             report.setFilename('banner.json');\
             console.log(report.writeReport('event', 'API', undefined, null));",
            directory = directory.display()
        ))
        .output()
        .expect("the rustnode binary must be built");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stdout.trim(), "banner.json");
    assert!(
        stderr.contains("Writing Node.js report to file: banner.json"),
        "the banner must name the file the way Node does: {stderr}"
    );
    assert!(
        stderr.contains("Node.js report completed"),
        "the completion line is what a wrapper waits for: {stderr}"
    );
    // `undefined` must not become the literal filename "undefined".
    assert!(directory.join("banner.json").is_file());
    let _ = std::fs::remove_dir_all(&directory);
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
    // to write even when nothing configured a path. The cwd is a scratch
    // directory because the report lands in it for real.
    let cwd = scratch_dir();
    let output = run_in(
        &format!(
            "{PRELUDE}
            const path = report.writeReport('default path', 'test', '', null);
            console.log(path.length > 0, path.endsWith('.json'), path);"
        ),
        &cwd,
    );
    let mut fields = output.split(' ');
    assert_eq!(fields.next(), Some("true"), "a name must be produced");
    assert_eq!(fields.next(), Some("true"), "it must be a json report");
    // The name is relative, so an unconfigured directory resolves it against the
    // cwd. `report.` is the prefix `DiagnosticFilename` uses.
    let name = fields.next().expect("the reported name");
    assert!(
        name.starts_with("report."),
        "a generated name starts with the report prefix, got {name}"
    );
    let written = cwd.join(name);
    assert!(written.is_file(), "the report must actually exist on disk");

    let _ = std::fs::remove_dir_all(&cwd);
}
