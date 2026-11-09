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

#[test]
fn a_builtin_can_be_required_with_its_scheme() {
    // `node:path` and `path` name the same module, and user code writes both.
    // The internal loader matches ids verbatim, so the scheme has to be
    // normalized away before the lookup.
    let out = rustnode(&["-e", "console.log(typeof require('node:path').join)"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "function");

    let out = rustnode(&[
        "-e",
        "console.log(require('node:path') === require('path'))",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true");
}

#[test]
fn an_unknown_specifier_still_fails_with_the_scheme_stripped() {
    // The wrapper must not turn a typo into a silent success.
    let out = rustnode(&["-e", "require('node:not-a-real-builtin')"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not-a-real-builtin"),
        "the error must name the specifier"
    );
}

#[test]
fn a_relative_specifier_is_not_treated_as_a_builtin() {
    let out = rustnode(&["-e", "require('./does-not-exist.js')"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("./does-not-exist.js"),
        "the specifier must survive untouched so the loader can report it"
    );
}

#[test]
fn structured_clone_is_a_real_serializer_round_trip() {
    // It comes from the messaging binding, so a cycle has to survive and a
    // copied object has to stop sharing identity with the original.
    let out = rustnode(&[
        "-e",
        "const o = {n: 1}; o.self = o; const c = structuredClone(o);\n\
         console.log(c.self === c, c === o, c.n);",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true false 1");
}

#[test]
fn text_encoder_and_decoder_are_the_node_implementations() {
    // `internal/encoding` is the vendored Node module, so the encoding label and
    // the byte values have to match Node's rather than be plausible.
    let out = rustnode(&[
        "-e",
        "const e = new TextEncoder();\n\
         console.log(e.encoding, JSON.stringify(Array.from(e.encode('héllo'))));\n\
         const d = new TextDecoder();\n\
         console.log(d.encoding, d.decode(new Uint8Array([104, 195, 169, 108, 108, 111])));",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "utf-8 [104,195,169,108,108,111]\nutf-8 héllo"
    );
}

#[test]
fn the_buffer_global_is_the_module_itself() {
    // The global must be the same function `require('buffer')` hands out, not a
    // second copy: `instanceof` across the two has to hold.
    let out = rustnode(&[
        "-e",
        "console.log(Buffer === require('buffer').Buffer,\n\
         Buffer.from('hi').toString('base64'),\n\
         Buffer.byteLength('héllo'));",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true aGk= 6");
}

#[test]
fn btoa_and_atob_round_trip() {
    let out = rustnode(&["-e", "console.log(btoa('hi'), atob('aGk='))"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "aGk= hi");
}
