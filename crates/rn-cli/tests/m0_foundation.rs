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

#[test]
fn a_script_path_becomes_the_second_argument() {
    // `process.argv[1]` is the script, which is how a program finds itself, and
    // the arguments after it belong to the script.
    let dir = std::env::temp_dir().join("rustnode-argv-script");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("argv.js");
    std::fs::write(&path, "console.log(JSON.stringify(process.argv))").expect("write script");
    let out = rustnode(&[path.to_str().expect("utf8 path"), "one", "two"]);
    let printed = String::from_utf8_lossy(&out.stdout);
    let printed = printed.trim();
    let expected_path = std::path::absolute(&path)
        .expect("an absolute path")
        .to_string_lossy()
        .into_owned();
    assert!(
        printed.contains(&format!("\"{expected_path}\",\"one\",\"two\"]")),
        "argv must be [execPath, script, args], got {printed}"
    );
}

#[test]
fn eval_arguments_follow_the_executable() {
    // Node reports no script slot for `-e`, so the arguments start at index 1,
    // and an explicit `--` is only a separator.
    let out = rustnode(&[
        "-e",
        "console.log(JSON.stringify(process.argv.slice(1)))",
        "--",
        "a",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), r#"["a"]"#);

    let out = rustnode(&[
        "-e",
        "console.log(JSON.stringify(process.argv.slice(1)))",
        "a",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), r#"["a"]"#);

    let out = rustnode(&["-p", "JSON.stringify(process.argv.length)"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");
}

#[test]
fn exec_argv_reproduces_the_entry_point() {
    // A child process inherits these, so they have to exclude the executable and
    // any script path but keep `-e` and its source.
    let out = rustnode(&[
        "--expose-internals",
        "-p",
        "JSON.stringify(process.execArgv)",
    ]);
    let printed = String::from_utf8_lossy(&out.stdout);
    let printed = printed.trim();
    assert!(
        printed.starts_with(r#"["--expose-internals","-p","#),
        "got {printed}"
    );
    assert!(
        !printed.contains("rustnode\""),
        "the executable must not be in execArgv, got {printed}"
    );
}
