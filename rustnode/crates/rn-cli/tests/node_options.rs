//! `NODE_OPTIONS`, end to end through the built binary.
//!
//! # Why this file exists
//!
//! `NODE_OPTIONS` was parsed by nobody: `rn-cli` read only `std::env::args()`,
//! so every flag in the variable was silently dropped. That is the worst shape a
//! gap can take, because the program still runs and the failure surfaces far
//! from its cause — a `NODE_OPTIONS=--require ./setup.js` bootstrap simply never
//! happening looks like a broken script.
//!
//! # What is pinned here
//!
//! The rules come from `OptionsParser<Options>::Parse` with
//! `required_env_settings = kAllowedInEnvvar` (`src/node_options-inl.h:430`) and
//! `ParseNodeOptionsEnvVar` (`src/node_options.cc:2575`). The two halves that
//! matter and are easy to get wrong:
//!
//! * an option Node marks `kDisallowedInEnvvar` **and** one Node has never heard
//!   of are both rejected, with the same message shape and exit code 9. "Parse
//!   everything" would accept a typo and silently not apply it;
//! * the environment is parsed *before* the command line and into the same
//!   values, so a scalar takes the command line's and a list keeps both.
//!
//! Expectations are literal rather than measured against `node`, because the
//! `node` on a test machine is not necessarily the pinned version. The
//! differential against the real oracle is `tools/node-options-diff.sh`, which
//! compares stderr and status byte for byte; this file is the always-on
//! equivalent for the shapes it can express without a second binary.

use std::process::Command;

/// Runs the built binary with `NODE_OPTIONS` set to `options` and `-e` to
/// `script`, returning status, stdout and stderr.
///
/// `NODE_OPTIONS` is removed first so a value inherited from whatever ran the
/// tests cannot change the result.
fn run_env(options: &str, script: &str) -> (i32, String, String) {
    run_env_args(options, script, &[])
}

fn run_env_args(options: &str, script: &str, args: &[&str]) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustnode"));
    command
        .env_remove("NODE_OPTIONS")
        .env("NODE_OPTIONS", options);
    for argument in args {
        command.arg(argument);
    }
    command.args(["-e", script]);
    let out = command.output().expect("rustnode runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Asserts the script printed `expected` and exited 0.
fn expect_env(options: &str, script: &str, expected: &str) {
    let (code, stdout, stderr) = run_env(options, script);
    assert_eq!(
        stdout.trim(),
        expected,
        "NODE_OPTIONS={options:?} exited {code}, stderr: {stderr}"
    );
    assert_eq!(code, 0, "NODE_OPTIONS={options:?} stderr: {stderr}");
}

/// Asserts the variable was rejected with `message` embedded in stderr, exit 9.
///
/// The whole line is checked rather than a substring: the prefix is `argv[0]`,
/// which changes with how the binary was invoked, so the assertion compares the
/// part after it and requires the exit status Node uses for a bad option.
///
/// The trailing newline is added here rather than trimmed, because the
/// tokenizer's messages already carry one and printing them produces a blank
/// line — which is part of Node's output and must not be normalized away.
fn expect_rejected(options: &str, message: &str) {
    let (code, stdout, stderr) = run_env(options, "console.log(1)");
    assert_eq!(
        code, 9,
        "NODE_OPTIONS={options:?} should exit 9, printed {stdout:?}, stderr: {stderr}"
    );
    assert!(
        stderr.ends_with(&format!("{message}\n")),
        "NODE_OPTIONS={options:?} stderr {stderr:?} does not end with {message:?} plus a newline"
    );
    assert!(
        stdout.trim().is_empty(),
        "NODE_OPTIONS={options:?} must not run the script, printed {stdout:?}"
    );
}

// ---------------------------------------------------------------------------
// Allowed options take effect
// ---------------------------------------------------------------------------

#[test]
fn max_http_header_size_reaches_the_http_module() {
    // `lib/http.js` reads this through `getOptionValue` when the module loads,
    // so a value that never reached the option store leaves the default 16384.
    expect_env(
        "--max-http-header-size=32768",
        "console.log(require('http').maxHeaderSize)",
        "32768",
    );
}

#[test]
fn require_runs_the_preload() {
    let directory = temp_dir("require");
    let preload = directory.join("pre.js");
    std::fs::write(&preload, "globalThis.PRELOADED = 1;\n").expect("write the preload");

    expect_env(
        &format!("--require {}", preload.display()),
        "console.log(globalThis.PRELOADED)",
        "1",
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn two_requires_both_run() {
    let directory = temp_dir("two-requires");
    let first = directory.join("first.js");
    let second = directory.join("second.js");
    std::fs::write(&first, "globalThis.ORDER = ['first'];\n").expect("write the first");
    std::fs::write(&second, "globalThis.ORDER.push('second');\n").expect("write the second");

    // The environment's occurrences are all recorded, in order. `Parse` calls
    // `emplace_back` for a list, so both survive rather than the last winning.
    expect_env(
        &format!(
            "--require {} --require {}",
            first.display(),
            second.display()
        ),
        "console.log(globalThis.ORDER.join(','))",
        "first,second",
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_no_flag_negation_reaches_the_option_store() {
    // `--no-warnings` sets `warnings` false. The observable is the warning
    // itself: `lib/internal/process/warning.js` returns early when the flag is
    // off, so an unparsed variable emits the warning and a parsed one does not.
    let (code, stdout, stderr) = run_env("--no-warnings", "process.emitWarning('boom')");
    assert_eq!(code, 0);
    assert!(stdout.trim().is_empty());
    assert!(
        !stderr.contains("Warning: boom"),
        "--no-warnings must suppress the warning, stderr: {stderr}"
    );

    // The other direction, so the test cannot pass by the warning never
    // existing at all.
    let (_, _, stderr) = run_env("", "process.emitWarning('boom')");
    assert!(
        stderr.contains("Warning: boom"),
        "without the flag the warning must appear, stderr: {stderr}"
    );
}

#[test]
fn a_single_dash_alias_resolves_before_the_allow_list() {
    // `-r` is not in Node's table; `--require` is. `Parse` expands aliases
    // before looking the name up, which is why the single-dash spelling is
    // accepted rather than reported as unknown.
    let directory = temp_dir("alias");
    let preload = directory.join("pre.js");
    std::fs::write(&preload, "globalThis.SHORT = 1;\n").expect("write the preload");

    expect_env(
        &format!("-r {}", preload.display()),
        "console.log(globalThis.SHORT)",
        "1",
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_v8_flag_from_the_variable_reaches_v8() {
    // `--stack-trace-limit` is a `kInteger` option that `Parse` also pushes onto
    // the V8 argument vector. `Error.stackTraceLimit` is V8's own field, so this
    // only changes when the flag really reached `V8::SetFlagsFromString`.
    expect_env(
        "--stack-trace-limit=42",
        "console.log(Error.stackTraceLimit)",
        "42",
    );
}

#[test]
fn a_quoted_value_keeps_its_spaces() {
    // The tokenizer consumes the quotes rather than including them, and a space
    // inside them is not a separator.
    expect_env(
        r#"--title="a b c""#,
        "const v = require('internal/test/binding').internalBinding('options') \
         .getCLIOptionsValues(); console.log(v['--title'])",
        "a b c",
    );
}

#[test]
fn an_empty_variable_is_no_flags() {
    // `NODE_OPTIONS=""` must behave exactly like no variable at all rather than
    // producing one empty argument.
    expect_env("", "console.log(require('http').maxHeaderSize)", "16384");
}

// ---------------------------------------------------------------------------
// The command line composes with the variable
// ---------------------------------------------------------------------------

#[test]
fn a_list_option_keeps_both_sources_with_the_variable_first() {
    // `src/node.cc` parses the environment and then the command line into one
    // `PerProcessOptions`, and a list option appends. A merge that put the
    // command line first, or that replaced instead of appending, would reorder
    // or drop a preload.
    let directory = temp_dir("both-sources");
    let from_env = directory.join("env.js");
    let from_cli = directory.join("cli.js");
    std::fs::write(&from_env, "globalThis.ORDER = ['env'];\n").expect("write the env preload");
    std::fs::write(&from_cli, "globalThis.ORDER.push('cli');\n").expect("write the cli preload");

    let script = "console.log(globalThis.ORDER.join(','))";
    let (code, stdout, stderr) = run_env_args(
        &format!("--require {}", from_env.display()),
        script,
        &["--require", &from_cli.display().to_string()],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout.trim(), "env,cli", "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_scalar_takes_the_command_lines_value() {
    // The variable is parsed first, so the command line overwrites it.
    let script = "const v = require('internal/test/binding').internalBinding('options') \
                  .getCLIOptionsValues(); console.log(v['--title'])";
    let (code, stdout, stderr) = run_env_args("--title=from-env", script, &["--title=from-cli"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout.trim(), "from-cli", "stderr: {stderr}");
}

// ---------------------------------------------------------------------------
// Rejected values
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_flag_is_rejected() {
    // The heart of the allow-list rule: an option the table does not know is
    // rejected in this mode, not ignored. Ignoring it would make a typo in the
    // variable a silent no-op.
    expect_rejected(
        "--not-a-real-flag",
        "--not-a-real-flag is not allowed in NODE_OPTIONS",
    );
}

#[test]
fn a_disallowed_option_is_rejected() {
    // `--eval` is a real option, marked `kDisallowedInEnvvar`: running code from
    // an environment variable is not something Node allows.
    expect_rejected("--eval=1", "--eval= is not allowed in NODE_OPTIONS");
    expect_rejected("-e 1", "-e is not allowed in NODE_OPTIONS");
    expect_rejected("--help", "--help is not allowed in NODE_OPTIONS");
    expect_rejected(
        "--expose-internals",
        "--expose-internals is not allowed in NODE_OPTIONS",
    );
}

#[test]
fn the_rejection_repeats_the_spelling_that_was_typed() {
    // The underscore normalization happens after the name is recorded, so a
    // message that named the normalized form would send someone looking for a
    // flag that is not in their variable.
    expect_rejected(
        "--expose_internals",
        "--expose_internals is not allowed in NODE_OPTIONS",
    );
    expect_rejected("--no-eval", "--no-eval is not allowed in NODE_OPTIONS");
}

#[test]
fn a_double_dash_is_rejected() {
    // `Parse` rejects `--` itself in this mode (`src/node_options-inl.h:359`),
    // rather than treating it as the end of the flags. Letting it through would
    // let the rest of the variable smuggle in non-flag text.
    expect_rejected("--", "-- is not allowed in NODE_OPTIONS");
}

#[test]
fn a_missing_value_is_rejected() {
    expect_rejected("--require", "--require requires an argument");
    expect_rejected(
        "--max-http-header-size=",
        "--max-http-header-size= requires an argument",
    );
    // A following flag is not a value, so this does not consume `--no-warnings`.
    expect_rejected("--title --no-warnings", "--title requires an argument");
}

#[test]
fn a_negated_non_boolean_is_rejected() {
    expect_rejected(
        "--no-max-http-header-size",
        "--no-max-http-header-size is an invalid negation because it is not a boolean option",
    );
}

#[test]
fn a_malformed_quote_is_rejected() {
    // The tokenizer's messages keep the trailing newline the C++ literal has, so
    // a malformed value prints a blank line after the error.
    expect_rejected(
        r#"--title="abc\"#,
        "invalid value for NODE_OPTIONS (invalid escape)\n",
    );
    expect_rejected(
        r#"--title="abc"#,
        "invalid value for NODE_OPTIONS (unterminated string)\n",
    );
}

#[test]
fn a_v8_flag_node_does_not_declare_is_rejected() {
    // `--stack-size` reaches V8 from the command line, but Node's table has no
    // entry for it, so `Parse` never forwards it from the variable. Accepting
    // anything that starts with `--` would let a typo through.
    expect_rejected(
        "--stack-size=512",
        "--stack-size= is not allowed in NODE_OPTIONS",
    );
    expect_rejected("--trace-gc", "--trace-gc is not allowed in NODE_OPTIONS");
}

#[test]
fn an_out_of_range_inspect_port_is_rejected() {
    // `ParseAndValidatePort` rejects a non-zero port below 1024 and anything
    // above 65535, with one sentence for both.
    expect_rejected("--inspect-port=80", "must be 0 or in range 1024 to 65535.");
    expect_rejected(
        "--inspect-port=99999",
        "must be 0 or in range 1024 to 65535.",
    );
}

#[test]
fn a_rejected_value_stops_the_process_before_the_script_runs() {
    // The observable is that the script did not run. `expect_rejected` asserts
    // stdout is empty, which is what makes this the same assertion as the rest;
    // the case is called out because it is the property that makes a rejection
    // a startup failure rather than a warning.
    let (code, stdout, stderr) = run_env("--not-a-real-flag", "console.log('SHOULD NOT RUN')");
    assert_eq!(code, 9);
    assert!(stdout.trim().is_empty(), "printed {stdout:?}");
    assert!(
        stderr.contains("is not allowed in NODE_OPTIONS"),
        "stderr: {stderr}"
    );
}

#[test]
fn the_rejection_is_prefixed_with_the_program_name() {
    // `StartInternal` prints `"%s: %s\n", argv[0], error`, so the prefix is the
    // path the binary was invoked by — not a fixed `"node"` or `"rustnode"`.
    // This is what makes the differential against the oracle byte-identical.
    let (code, _, stderr) = run_env("--not-a-real-flag", "console.log(1)");
    assert_eq!(code, 9);
    let expected_prefix = env!("CARGO_BIN_EXE_rustnode");
    assert!(
        stderr.trim_end().starts_with(expected_prefix),
        "stderr {stderr:?} should start with {expected_prefix:?}"
    );
}

/// A scratch directory unique to one test.
///
/// The tests run in parallel, so a shared name would let one test's preload be
/// read by another.
fn temp_dir(name: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "rustnode-node-options-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&base).expect("create the scratch directory");
    base
}
