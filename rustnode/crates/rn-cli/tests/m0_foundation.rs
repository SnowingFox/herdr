//! Milestone M0: the binary links the pinned V8 and evaluates JavaScript.

use std::process::Command;

fn rustnode(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(args)
        .output()
        .expect("rustnode runs")
}

#[test]
fn eval_prints_integer_result() {
    let out = rustnode(&["-p", "1+1"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "2");
}

#[test]
fn console_log_writes_stdout() {
    let out = rustnode(&["-e", "console.log(1+1)"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "2");
}

#[test]
fn console_error_writes_stderr() {
    let out = rustnode(&["-e", "console.error('bad')"]);
    assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "bad");
}

#[test]
fn thrown_error_exits_nonzero() {
    let out = rustnode(&["-e", "throw new Error('boom')"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Uncaught Error: boom"));
}

#[test]
fn script_file_runs() {
    let dir = std::env::temp_dir().join("rustnode-m0");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("script.js");
    std::fs::write(&path, "console.log(6*7)").expect("write script");
    let out = rustnode(&[path.to_str().expect("utf8 path")]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "42");
}

#[test]
fn linked_v8_matches_pin() {
    let out = rustnode(&["-p", "process.versions.v8"]);
    let version = String::from_utf8_lossy(&out.stdout);
    assert!(version.trim().starts_with("15.2."), "got {version}");
}
