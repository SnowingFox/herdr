//! `process.title` renames the process, checked through `ps` and `/proc`.
//!
//! A read-back test cannot distinguish a working setter from one that stores the
//! string and changes nothing: `process.title = 'x'; process.title` answers `'x'`
//! either way. Node's setter calls `uv_set_process_title`, which rewrites the
//! memory the kernel hands back for `argv`, so the observable is the operating
//! system's view — `ps -o args=`, `ps -o comm=` and `/proc/<pid>/cmdline`.
//!
//! That distinction is the whole point of this file. The first implementation of
//! `setup_args` passed libuv a freshly allocated copy of `argv`, so `ps -o comm=`
//! changed (libuv sets the comm name through a separate call) while
//! `/proc/<pid>/cmdline` kept the original command line. A read-back test passed
//! on it; this one does not.

use std::process::Command;

/// Runs a script under the built binary and returns its stdout.
fn run(script: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["-e", script])
        .output()
        .expect("rustnode runs");
    assert!(
        out.status.success(),
        "the script failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A script that renames the process and reports what the OS says.
///
/// `execSync` with `ps` and a read of `/proc/<pid>/cmdline` cover the three
/// surfaces that matter. The title is longer than the original `argv[0]` so a
/// truncation at the original length would show up as a mismatch rather than
/// passing as a prefix.
const RENAME: &str = r#"
const { execSync } = require('child_process');
const field = (command) => execSync(command, { encoding: 'utf8' }).trim();
const cmdline = () =>
  field('tr "\\0" " " < /proc/' + process.pid + '/cmdline');
const before = { cmdline: cmdline() };
process.title = 'herdr-title-probe';
const after = {
  cmdline: cmdline(),
  args: field('ps -o args= -p ' + process.pid),
  comm: field('ps -o comm= -p ' + process.pid),
};
process.stdout.write(JSON.stringify({
  readBack: process.title,
  beforeChanged: before.cmdline !== after.cmdline,
  cmdline: after.cmdline,
  args: after.args,
  comm: after.comm,
}));
"#;

/// The title really reaches the kernel's view of the command line.
#[test]
fn setting_the_title_renames_the_process_as_ps_reports_it() {
    let output = run(RENAME);
    let report: serde_json::Value = serde_json::from_str(&output).expect("the probe produced JSON");

    assert_eq!(
        report["readBack"], "herdr-title-probe",
        "the getter has to see the new title"
    );
    assert_eq!(
        report["beforeChanged"], true,
        "/proc/<pid>/cmdline must change when the title is set: an unchanged \
         command line means `uv_setup_args` was given a copy of argv rather than \
         the block the kernel reports, so the rename is invisible to `ps`"
    );
    assert_eq!(
        report["cmdline"], "herdr-title-probe",
        "/proc/<pid>/cmdline has to be the new title"
    );
    assert!(
        report["args"]
            .as_str()
            .is_some_and(|args| args.starts_with("herdr-title-probe")),
        "`ps -o args=` has to start with the new title, got {:?}",
        report["args"]
    );
    // libuv truncates the comm name to the kernel's 15-byte limit, the same way
    // it does for Node, so only the prefix is asserted.
    assert!(
        report["comm"]
            .as_str()
            .is_some_and(|comm| comm.starts_with("herdr-title")),
        "`ps -o comm=` has to be truncated from the new title, got {:?}",
        report["comm"]
    );
}

/// The oracle behaves the same way, so the assertions above are Node's contract.
///
/// Without this, "the title reaches `ps`" could be a rustnode-specific choice.
/// The oracle already proves Node does it; what this pins is that the *shape* of
/// the answer is comparable — same fields, same truncation — so a future change
/// to the probe cannot silently stop measuring the thing.
#[test]
fn the_oracle_renames_the_process_the_same_way() {
    let Some(oracle) = rn_node_oracle::require_oracle("process.title ps parity") else {
        return;
    };
    let out = Command::new(oracle.reference_path())
        .arg("-e")
        .arg(RENAME)
        .output()
        .expect("the oracle runs");
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("the oracle probe produced JSON");
    assert_eq!(
        report["beforeChanged"], true,
        "the oracle's cmdline changes"
    );
    assert_eq!(report["cmdline"], "herdr-title-probe");
    assert!(
        report["comm"]
            .as_str()
            .is_some_and(|comm| comm.starts_with("herdr-title")),
        "the oracle's comm is truncated the same way, got {:?}",
        report["comm"]
    );
}
