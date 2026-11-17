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

/// Runs the built binary with `arguments` and no `NODE_OPTIONS`, returning
/// status, stdout and stderr.
///
/// `NODE_OPTIONS` is removed so a value inherited from whatever ran the tests
/// cannot change the result; the environment path has its own helpers below.
///
/// The child runs in a scratch directory, because some of the flags this file
/// exercises make V8 write files: `--prof` and `--log-all` drop
/// `isolate-<address>-<pid>-v8.log` in the current directory, and `--jitless`
/// plus a tracing flag can drop `jit-<pid>.dump`. Measured on this tree, running
/// the accepted-flags case from the package root left 22 such files behind, and
/// they then showed up as untracked files in the repository. A scratch directory
/// keeps the tree clean whatever the binary decides to write.
fn run_args(arguments: &[&str]) -> (i32, String, String) {
    let directory = std::env::temp_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .env_remove("NODE_OPTIONS")
        .current_dir(&directory)
        .args(arguments)
        .output()
        .expect("rustnode runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Same as [`run_args`], but for dynamically built arguments.
fn run_args_owned(arguments: &[String]) -> (i32, String, String) {
    let directory = std::env::temp_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .env_remove("NODE_OPTIONS")
        .current_dir(&directory)
        .args(arguments)
        .output()
        .expect("rustnode runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Asserts `--flag` is accepted and that the script still runs.
///
/// Running the script is the part that matters: exit 0 alone would also be
/// reported by a process that accepted the flag and then did nothing, which is
/// the silent-acceptance shape this whole change exists to remove.
///
/// The marker goes to **stderr**, not stdout, because several of these flags are
/// V8 tracing flags that write to stdout — and `--trace-gc-verbose` interleaves
/// with a script's own stdout writes *within a line*, so a stdout marker came
/// back as `[59195ran` spliced into a GC line. V8's tracing never writes to
/// stderr, so a stderr marker is the one that survives intact.
fn expect_accepted(flag: &str) {
    let (code, stdout, stderr) = run_args(&[flag, "-e", "process.stderr.write('script-ran\\n')"]);
    assert_eq!(code, 0, "{flag} should be accepted, stderr: {stderr}");
    assert!(
        stderr.lines().any(|line| line.trim() == "script-ran"),
        "{flag} must still run the script, stdout: {stdout:?}, stderr: {stderr:?}"
    );
}

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

// ---------------------------------------------------------------------------
// V8 flags on the command line
// ---------------------------------------------------------------------------
//
// Node keeps no list of V8 flags: `OptionsParser<Options>::Parse` resolves a name
// through its own option table and pushes everything else onto `v8_args`, which
// `ProcessGlobalArgsInternal` ends by handing to
// `V8::SetFlagsFromCommandLine(&argc, argv, true)` (`src/node.cc:827`). Whatever
// V8 leaves behind is `bad option: <flag>` and the process exits 9
// (`src/node.cc:833`). rustnode used to run a hand-written allow-list instead,
// so it rejected 22 of the 24 V8 flags the pinned oracle accepts — which is how
// a flag sweep measured a process that had exited during argument parsing and
// reported an apparent 89% win.

/// The 22 V8 flags the allow-list used to reject, all of which the oracle
/// accepts.
///
/// This is the list the defect was measured on. Each is checked for exit 0 *and*
/// for the script running, because "accepted and then ignored" is exactly the
/// failure that looks like a pass.
const ACCEPTED_V8_FLAGS: &[&str] = &[
    "--max-semi-space-size=1",
    "--min-semi-space-size=1",
    "--trace-gc",
    "--trace-gc-verbose",
    "--gc-interval=100",
    "--stress-compaction",
    "--print-bytecode",
    "--print-opt-code",
    "--turbo-stats",
    "--no-opt",
    "--jitless",
    "--single-threaded",
    "--predictable",
    "--no-lazy",
    "--wasm-tier-up",
    "--max-lazy",
    "--opt",
    "--always-sparkplug",
    "--no-flush-bytecode",
    "--stress-scavenge=0",
    "--prof",
    "--log-all",
];

#[test]
fn v8_flags_the_option_table_does_not_declare_are_accepted() {
    for flag in ACCEPTED_V8_FLAGS {
        expect_accepted(flag);
    }
}

#[test]
fn a_bogus_flag_is_a_bad_option_with_nodes_message_and_status() {
    // The oracle prints `<argv[0]>: bad option: --totally-bogus-flag=1` and
    // exits 9. The message text is part of the contract because Node's own tests
    // and the harness read it; the prefix is `argv[0]`, so it is compared from
    // the first colon onward.
    let (code, stdout, stderr) = run_args(&["--totally-bogus-flag=1", "-e", "console.log(1)"]);
    assert_eq!(code, 9, "stderr: {stderr}");
    assert!(
        stdout.is_empty(),
        "the script must not run, printed {stdout:?}"
    );
    let prefix = format!("{}: ", env!("CARGO_BIN_EXE_rustnode"));
    assert_eq!(
        stderr.trim_end(),
        format!("{prefix}bad option: --totally-bogus-flag=1"),
        "stderr: {stderr}"
    );
}

#[test]
fn every_bad_flag_is_reported_not_only_the_first() {
    // Node's loop over the leftovers prints one line per flag, so two unknown
    // flags produce two lines rather than stopping at the first.
    let (code, _, stderr) = run_args(&["--bogus-a", "--bogus-b", "-e", "1"]);
    assert_eq!(code, 9, "stderr: {stderr}");
    assert!(stderr.contains("bad option: --bogus-a"), "stderr: {stderr}");
    assert!(stderr.contains("bad option: --bogus-b"), "stderr: {stderr}");
}

#[test]
fn a_trailing_unknown_flag_after_eval_is_still_a_bad_option() {
    // `-e` does not end option parsing in Node. A trailing unknown flag is still
    // handed to V8 and rejected as `bad option`.
    let (code, stdout, stderr) = run_args(&["-e", "0", "--bogus-xyz"]);
    assert_eq!(code, 9, "stderr: {stderr}");
    assert!(stdout.trim().is_empty(), "stdout: {stdout:?}");
    let prefix = format!("{}: ", env!("CARGO_BIN_EXE_rustnode"));
    assert_eq!(
        stderr.trim_end(),
        format!("{prefix}bad option: --bogus-xyz"),
        "stderr: {stderr}"
    );
}

#[test]
fn a_trailing_valid_flag_after_eval_still_applies() {
    // `--no-warnings` after `-e` must still be treated as a runtime option.
    let script = "process.emitWarning('boom')";
    let (without_code, _, without_stderr) = run_args(&["-e", script]);
    let (with_code, _, with_stderr) = run_args(&["-e", script, "--no-warnings"]);
    assert_eq!(without_code, 0, "stderr: {without_stderr}");
    assert_eq!(with_code, 0, "stderr: {with_stderr}");
    assert!(
        without_stderr.contains("Warning: boom"),
        "without the flag the warning should be present, stderr: {without_stderr}"
    );
    assert!(
        !with_stderr.contains("Warning: boom"),
        "trailing --no-warnings should suppress the warning, stderr: {with_stderr}"
    );
}

#[test]
fn a_trailing_value_flag_after_eval_is_parsed() {
    let (code, stdout, stderr) = run_args(&[
        "-e",
        "console.log(process.execArgv.includes('--max-old-space-size=256'))",
        "--max-old-space-size=256",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout.trim(), "true", "stderr: {stderr}");
}

#[test]
fn a_trailing_double_dash_after_eval_only_separates_script_args() {
    let script = "console.log(JSON.stringify(process.argv.slice(1)))";
    let (only_dash_code, only_dash_stdout, only_dash_stderr) = run_args(&["-e", script, "--"]);
    assert_eq!(only_dash_code, 0, "stderr: {only_dash_stderr}");
    assert_eq!(only_dash_stdout.trim(), "[]", "stderr: {only_dash_stderr}");

    let (extra_code, extra_stdout, extra_stderr) = run_args(&["-e", script, "--", "extra"]);
    assert_eq!(extra_code, 0, "stderr: {extra_stderr}");
    assert_eq!(
        extra_stdout.trim(),
        r#"["extra"]"#,
        "stderr: {extra_stderr}"
    );
}

#[test]
fn a_script_argument_that_looks_like_a_flag_is_not_reparsed_as_runtime_option() {
    let directory = temp_dir("trailing-script-args");
    let script = directory.join("show.js");
    std::fs::write(
        &script,
        "console.log(JSON.stringify(process.argv.slice(2)));\n",
    )
    .expect("write script");
    let args = vec![
        script.to_string_lossy().into_owned(),
        "--bogus-xyz".to_string(),
        "value".to_string(),
    ];
    let (code, stdout, stderr) = run_args_owned(&args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        r#"["--bogus-xyz","value"]"#,
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_declared_flag_rustnode_has_not_implemented_is_not_forwarded() {
    // The rule `forward_v8_flags` used to state as a comment: a flag the table
    // declares is Node's, so handing it to V8 would change V8's behaviour behind
    // rustnode's back. `--report-compact` is declared by the table and not
    // implemented by the CLI, so it stays a rejection rather than becoming a V8
    // flag that V8 would also refuse (as a `bad option`) or, worse, accept.
    let (code, _, stderr) = run_args(&["--report-compact", "-e", "1"]);
    assert_eq!(code, 9, "stderr: {stderr}");
    assert!(
        stderr.contains("unsupported option '--report-compact'"),
        "stderr: {stderr}"
    );
}

#[test]
fn an_expose_gc_flag_installs_v8s_own_gc() {
    // `--expose-gc` is a `kV8Option` in Node's table, so it is forwarded and V8
    // installs the real extension. A Rust-side `gc` would not be the function
    // V8's own tests call, and `gc()` actually collecting is what distinguishes
    // the real one from a stub that returns.
    let (code, stdout, stderr) = run_args(&["--expose-gc", "-e", "gc(); console.log(typeof gc)"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout.trim(), "function", "stderr: {stderr}");
}

#[test]
fn max_old_space_size_still_moves_the_heap_limit() {
    // Load-bearing before this change and after it: the limit is what
    // `v8.getHeapStatistics().heap_size_limit` reports, so a flag that reached
    // no V8 leaves a constant. The two runs also have to differ from each other,
    // which a single run against a remembered number cannot show.
    let script = "console.log(require('v8').getHeapStatistics().heap_size_limit)";
    let (small_code, small, small_err) = run_args(&["--max-old-space-size=100", "-e", script]);
    let (large_code, large, large_err) = run_args(&["--max-old-space-size=512", "-e", script]);
    assert_eq!(small_code, 0, "stderr: {small_err}");
    assert_eq!(large_code, 0, "stderr: {large_err}");
    let small: u64 = small.trim().parse().expect("a number");
    let large: u64 = large.trim().parse().expect("a number");
    assert!(
        large > small,
        "--max-old-space-size=512 ({large}) must raise the limit above =100 ({small})"
    );
}

#[test]
fn max_old_space_size_percentage_sizes_the_heap_and_beats_max_old_space_size() {
    // `--max-old-space-size-percentage` is a Node option, not a V8 one:
    // `src/node_options.cc:237` converts it against the machine's memory and
    // appends `--max_old_space_size=<mb>` to the V8 argument vector, which is
    // what makes it win over any `--max-old-space-size`. Before this landed the
    // flag was `unsupported option`, and
    // `test-max-old-space-size-percentage.js` failed on its first case.
    let script = "console.log(require('v8').getHeapStatistics().heap_size_limit)";
    let (code, stdout, stderr) = run_args(&["--max-old-space-size-percentage=50", "-e", script]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let limit: u64 = stdout.trim().parse().expect("a number");
    // 50% of this machine's usable memory, so anything below 1 GB proves the
    // flag did nothing at all. The exact figure is machine-dependent, which is
    // why this is a floor plus a comparison rather than a constant.
    assert!(
        limit > 1024 * 1024 * 1024,
        "50% of the machine's memory must exceed a gigabyte, got {limit}"
    );

    // The percentage beats an explicit size, in either order. Both orders are
    // checked because the answer comes from where Node *appends* its argument,
    // not from where the flag appeared.
    for arguments in [
        [
            "--max-old-space-size=1000",
            "--max-old-space-size-percentage=50",
        ],
        [
            "--max-old-space-size-percentage=50",
            "--max-old-space-size=1000",
        ],
    ] {
        let (code, stdout, stderr) = run_args(&[arguments[0], arguments[1], "-e", script]);
        assert_eq!(code, 0, "stderr: {stderr}");
        let with_percentage: u64 = stdout.trim().parse().expect("a number");
        assert_eq!(
            with_percentage,
            limit,
            "{} must not change the percentage's answer",
            arguments.join(" ")
        );
    }

    // And the last percentage in one source wins, because `CheckOptions` reads
    // the field the walk left behind.
    let (code, stdout, stderr) = run_args(&[
        "--max-old-space-size-percentage=25",
        "--max-old-space-size-percentage=50",
        "-e",
        script,
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout.trim().parse::<u64>().ok(), Some(limit));
}

#[test]
fn max_old_space_size_percentage_rejects_what_node_rejects() {
    // Node's own message, verbatim, because `test-max-old-space-size-percentage`
    // matches it with a regular expression and the process exits 9.
    for (value, expected) in [
        (
            "0",
            "--max-old-space-size-percentage must be greater than 0 and up to 100. Got: 0",
        ),
        (
            "101",
            "--max-old-space-size-percentage must be greater than 0 and up to 100. Got: 101",
        ),
        (
            "-1",
            "--max-old-space-size-percentage must be greater than 0 and up to 100. Got: -1",
        ),
        (
            "abc",
            "--max-old-space-size-percentage must be greater than 0 and up to 100. Got: abc",
        ),
        (
            "1%",
            "--max-old-space-size-percentage must be greater than 0 and up to 100. Got: 1%",
        ),
        ("", "--max-old-space-size-percentage= requires an argument"),
    ] {
        let flag = format!("--max-old-space-size-percentage={value}");
        let (code, _, stderr) = run_args(&[&flag, "-e", "1"]);
        assert_eq!(code, 9, "{flag} must be rejected, stderr: {stderr}");
        assert!(
            stderr.contains(expected),
            "{flag} stderr was {stderr:?}, expected {expected:?}"
        );
    }

    // The bare form refuses a value that looks like a flag rather than reading
    // it as a negative percentage.
    let (code, _, stderr) = run_args(&["--max-old-space-size-percentage", "-1", "-e", "1"]);
    assert_eq!(code, 9, "stderr: {stderr}");
    assert!(
        stderr.contains("--max-old-space-size-percentage requires an argument"),
        "stderr: {stderr}"
    );

    // Two spellings with valid values still succeed, so the rejection above is
    // about the value rather than the flag being unusable in that shape.
    let (code, _, stderr) = run_args(&["--max-old-space-size-percentage", "50", "-e", "1"]);
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn max_old_space_size_percentage_from_node_options_is_validated_and_used() {
    // The variable is a separate parse in Node, and its value is checked even
    // when the command line replaces it: `NODE_OPTIONS=...=0` plus a
    // command-line `=50` fails on the environment's 0 on the oracle.
    let script = "console.log(require('v8').getHeapStatistics().heap_size_limit)";
    let (code, stdout, stderr) = run_env("--max-old-space-size-percentage=100", script);
    assert_eq!(code, 0, "stderr: {stderr}");
    let from_env: u64 = stdout.trim().parse().expect("a number");
    assert!(from_env > 1024 * 1024 * 1024, "got {from_env}");

    let (code, _, stderr) = run_env_args(
        "--max-old-space-size-percentage=0",
        "",
        &["--max-old-space-size-percentage=50", "-e", script],
    );
    assert_eq!(code, 9, "stderr: {stderr}");
    assert!(
        stderr.contains("must be greater than 0 and up to 100. Got: 0"),
        "stderr: {stderr}"
    );
}

#[test]
fn allow_natives_syntax_still_parses_natives_intrinsics() {
    // The intrinsic is a parse error unless V8 has the flag, so this fails at
    // compile time rather than by a wrong answer.
    let (code, stdout, stderr) = run_args(&[
        "--allow-natives-syntax",
        "-e",
        "function f() {}; console.log(%GetOptimizationStatus(f) >= 0)",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout.trim(), "true", "stderr: {stderr}");
}

#[test]
fn a_v8_flag_is_recorded_in_exec_argv() {
    // Node pushes the argument onto `exec_args` before looking it up, so
    // `process.execArgv` carries it in the spelling that was typed.
    let (code, stdout, stderr) = run_args(&[
        "--expose_gc",
        "-e",
        "console.log(JSON.stringify(process.execArgv))",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        r#"["--expose_gc","-e","console.log(JSON.stringify(process.execArgv))"]"#,
        "stderr: {stderr}"
    );
}

#[test]
fn an_underscored_v8_flag_reaches_v8_the_same_way_the_dashed_one_does() {
    // `Parse` replaces `_` with `-` after the leading dashes, so the oracle
    // treats both spellings as one flag. `--allow_natives_syntax` appears in
    // Node's own test headers, so a runtime that accepts only the dashed form
    // rejects a command line `node` runs.
    let script = "function f() {}; console.log(%GetOptimizationStatus(f) >= 0)";
    for flag in ["--allow-natives-syntax", "--allow_natives_syntax"] {
        let (code, stdout, stderr) = run_args(&[flag, "-e", script]);
        assert_eq!(code, 0, "{flag} stderr: {stderr}");
        assert_eq!(stdout.trim(), "true", "{flag} stderr: {stderr}");
    }
}

#[test]
fn trace_gc_actually_traces_instead_of_merely_exiting_zero() {
    // The silent-acceptance check. `--trace-gc` is accepted by V8 or it is not;
    // what proves it *took effect* is that GC lines appear, and that they stop
    // appearing without the flag. V8 prints them to stdout, so the assertion is
    // on stdout in both directions — a check that only looked at stderr would
    // pass on a build that printed nothing.
    let script = "for (let i = 0; i < 200; i++) new Array(1000).fill(i)";
    let (off_code, off, off_err) = run_args(&["-e", script]);
    let (on_code, on, on_err) = run_args(&["--trace-gc", "-e", script]);
    assert_eq!(off_code, 0, "stderr: {off_err}");
    assert_eq!(on_code, 0, "stderr: {on_err}");
    assert!(
        !off.contains("Scavenge") && !off.contains("Mark-Compact"),
        "without the flag there must be no GC trace, stdout: {off}"
    );
    assert!(
        on.contains("Scavenge") || on.contains("Mark-Compact"),
        "--trace-gc must print GC traces, stdout: {on}"
    );
}

#[test]
fn jitless_actually_disables_the_jit_instead_of_merely_exiting_zero() {
    // `--jitless` removes executable memory, so WebAssembly is not installed at
    // all. That is a V8-level effect no Rust-side parsing can fake, and it is
    // observable in one line.
    let (on_code, on, on_err) = run_args(&["--jitless", "-e", "console.log(typeof WebAssembly)"]);
    let (off_code, off, off_err) = run_args(&["-e", "console.log(typeof WebAssembly)"]);
    assert_eq!(on_code, 0, "stderr: {on_err}");
    assert_eq!(off_code, 0, "stderr: {off_err}");
    assert_eq!(off.trim(), "object", "without the flag: {off}");
    assert_eq!(
        on.trim(),
        "undefined",
        "--jitless must remove WebAssembly: {on}"
    );
}

#[test]
fn a_v8_flag_from_the_variable_uses_the_same_authority() {
    // The variable's legal V8 flags already went through the option table, so
    // they reach `v8_args` there rather than here. `--jitless` is one, and it
    // has to arrive before `V8::initialize` — a flag set after it is ignored,
    // which would show up as WebAssembly still being present.
    expect_env("--jitless", "console.log(typeof WebAssembly)", "undefined");
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
