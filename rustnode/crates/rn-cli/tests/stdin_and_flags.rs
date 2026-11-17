//! The two command-line surfaces Node's own CLI has and rustnode did not.
//!
//! # A script piped on stdin did not run, and exited 0
//!
//! ```text
//! $ echo 'console.log(1)' | rustnode      # printed nothing, exit 0
//! $ echo 'console.log(1)' | node          # printed 1, exit 0
//! ```
//!
//! That silent success is the worst shape a failure can take: anything that
//! checks only the status code reads a pass. The cause was structural — with no
//! script argument the parser produced `Source::Empty`, which evaluated the
//! string `"0"` — so the fix is a real stdin entry point rather than a special
//! case. `src/node.cc:395-405` decides it: with `first_argv` empty and
//! `uv_guess_handle(STDIN_FILENO) != UV_TTY`, Node runs
//! `internal/main/eval_stdin`, which reads the source and hands it to
//! `evalScript`. That is what gives the piped script `module`, `require`,
//! `__filename` and a `[stdin]` module id, while leaving `require.main`
//! undefined.
//!
//! # `--version`, `-v`, `--help` and `-h` were all rejected
//!
//! ```text
//! $ rustnode --version -> rustnode: unsupported option '--version'
//! ```
//!
//! They are ordinary options in Node's table (`src/node_options.cc:1694-1696`,
//! with the `-h`/`-v` aliases), and their output is part of the interface: a
//! version check reads it, and CI compares it. `--version` is answered in
//! `InitializeOncePerProcess` after the V8 argument vector is applied, which is
//! why `node --version --not-a-real-flag` is a `bad option` and exits 9 instead
//! of printing. `--help` is a main script (`internal/main/print_help`), so it
//! runs with the realm up and its text is generated from the option table.
//!
//! # Why the expectations are literal here
//!
//! The version string is compared against `tools/node-pin.toml` rather than
//! against whatever `node` is on `PATH`: a different Node is a different engine,
//! and the point of these assertions is that the pinned identity is what this
//! binary reports.

use std::io::Write;
use std::process::{Command, Stdio};

/// What running the binary produced.
struct Run {
    stdout: String,
    stderr: String,
    status: Option<i32>,
}

/// Runs the binary with `arguments`, feeding `stdin` through a pipe.
///
/// stdin is always a pipe here, never a terminal, which is the branch under
/// test: `Command` gives the child a terminal only when the parent has one, so a
/// test runner cannot reach the REPL branch by accident.
fn run(arguments: &[&str], stdin: &str) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the rustnode binary starts");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(stdin.as_bytes())
        .expect("the script is written");
    let output = child.wait_with_output().expect("the child finishes");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        status: output.status.code(),
    }
}

/// The version `tools/node-pin.toml` records for the reference binary.
fn pinned_version() -> String {
    let pin = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node-pin.toml"),
    )
    .expect("the pin is readable");
    pin.lines()
        .find_map(|line| line.trim().strip_prefix("oracle_version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("the pin records oracle_version")
        .to_string()
}

/// A bare pipe runs the script and exits 0. The bug this file exists for.
#[test]
fn a_script_piped_on_stdin_runs() {
    let run = run(&[], "console.log(1)\n");
    assert_eq!(run.stdout, "1\n", "stderr: {}", run.stderr);
    assert_eq!(run.status, Some(0));
}

/// The piped script is a CommonJS module, which is what `module`, `require` and
/// the undefined `require.main` say.
///
/// Node's `[stdin]` id and filename are part of it: `evalScript` is called with
/// `'[stdin]'` as the name, and `createModule` builds `path.join(cwd, name)`
/// from it.
#[test]
fn a_piped_script_is_a_commonjs_module_without_a_main() {
    let run = run(
        &[],
        "console.log(JSON.stringify({\n\
           module: typeof module,\n\
           require: typeof require,\n\
           main: require.main === undefined,\n\
           id: module.id,\n\
           filename: __filename,\n\
           dirname: __dirname,\n\
         }))\n",
    );
    assert_eq!(
        run.stdout.trim(),
        r#"{"module":"object","require":"function","main":true,"id":"[stdin]","filename":"[stdin]","dirname":"."}"#,
        "stderr: {}",
        run.stderr
    );
    assert_eq!(run.status, Some(0));
}

/// `process.argv[1]` is absent for a bare stdin script, because nothing was
/// consumed as an entry point.
#[test]
fn a_piped_script_has_no_script_in_argv() {
    let run = run(&[], "console.log(process.argv.length)\n");
    assert_eq!(run.stdout.trim(), "1", "stderr: {}", run.stderr);
}

/// `-` is the documented stdin marker and it stays in `argv`, with the arguments
/// after it belonging to the script.
///
/// The distinction from `--` is the easy thing to get wrong: `node -- a b` makes
/// `a` the script path and fails to find it, so `--` forwards nothing here.
#[test]
fn a_dash_marks_stdin_and_forwards_the_arguments_after_it() {
    let run = run(
        &["-", "x", "y"],
        "console.log(JSON.stringify(process.argv.slice(1)))\n",
    );
    assert_eq!(
        run.stdout.trim(),
        r#"["-","x","y"]"#,
        "stderr: {}",
        run.stderr
    );
    assert_eq!(run.status, Some(0));
}

/// An explicit exit code from the script is the process's exit code.
#[test]
fn a_piped_script_propagates_its_exit_code() {
    let run = run(&[], "process.exit(7)\n");
    assert_eq!(run.status, Some(7));
}

/// A throwing piped script exits non-zero and reports the error the way the
/// oracle does, naming `[stdin]` as the source.
#[test]
fn a_throwing_piped_script_is_reported_and_fails() {
    let run = run(&[], "throw new Error('boom')\n");
    assert_eq!(run.status, Some(1));
    assert!(
        run.stderr.contains("[stdin]:1"),
        "the throw has to name its source: {}",
        run.stderr
    );
    assert!(run.stderr.contains("Error: boom"), "{}", run.stderr);
}

/// `--print` applies to a stdin script: `echo 1+1 | node -p` prints `2`.
#[test]
fn print_applies_to_a_piped_script() {
    let run = run(&["-p"], "1 + 1\n");
    assert_eq!(run.stdout.trim(), "2", "stderr: {}", run.stderr);
    assert_eq!(run.status, Some(0));
}

/// `--input-type=module` applies to a stdin script as well, so an `import`
/// statement is a module rather than a syntax error.
#[test]
fn input_type_module_applies_to_a_piped_script() {
    let run = run(
        &["--input-type=module"],
        "import path from 'node:path';\nconsole.log(path.basename('/a/b'));\n",
    );
    assert_eq!(run.stdout.trim(), "b", "stderr: {}", run.stderr);
    assert_eq!(run.status, Some(0));
}

/// An empty pipe is an empty program, not an error.
#[test]
fn an_empty_pipe_exits_zero() {
    let run = run(&[], "");
    assert_eq!(run.stdout, "");
    assert_eq!(run.status, Some(0));
}

/// `--version` and `-v` print the pinned version identity and exit 0.
///
/// The exact bytes matter: the string is what a CI version check compares, so a
/// trailing newline and the leading `v` are part of the contract.
#[test]
fn version_prints_the_pinned_identity() {
    let expected = format!("{}\n", pinned_version());
    for argument in ["--version", "-v"] {
        let run = run(&[argument], "");
        assert_eq!(run.stdout, expected, "{argument}");
        assert_eq!(run.stderr, "", "{argument}");
        assert_eq!(run.status, Some(0), "{argument}");
    }
}

/// The version wins over a script argument, which is what `node --version
/// app.js` does: it prints the version and never loads `app.js`.
#[test]
fn version_wins_over_a_script_argument() {
    let run = run(&["--version", "definitely-not-a-script.js"], "");
    assert_eq!(run.stdout, format!("{}\n", pinned_version()));
    assert_eq!(run.status, Some(0));
}

/// A flag after the eval source belongs to the script, so `node -e ... a
/// --version` does not print the version.
///
/// This is the direction that is easy to get wrong, and the one that matters: a
/// program that accepts `--version` of its own would otherwise never see it.
#[test]
fn a_flag_after_the_script_belongs_to_the_script() {
    let run = run(
        &[
            "-e",
            "console.log(JSON.stringify(process.argv.slice(1)))",
            "a",
            "--version",
        ],
        "",
    );
    assert_eq!(run.stdout.trim(), r#"["a","--version"]"#, "{}", run.stderr);
}

/// `--help` prints Node's usage text, with this binary's name in the two places
/// the text names the program.
#[test]
fn help_prints_the_usage_text() {
    let run = run(&["--help"], "");
    assert_eq!(run.status, Some(0));
    assert_eq!(run.stderr, "");
    let first_line = run.stdout.lines().next().unwrap_or_default();
    assert_eq!(
        first_line, "Usage: rustnode [options] [ script.js ] [arguments]",
        "the usage line has to name this binary"
    );
    assert!(
        run.stdout.contains("       rustnode inspect [options]"),
        "the inspect usage line has to name it too"
    );
    // The text is generated from the option table, so it has to be the whole
    // table rather than a header: these are entries from different parts of it,
    // including one whose help text wraps.
    for needle in [
        "  -                           script read from stdin (default if no",
        "  -e, --eval=...              evaluate script",
        "  -v, --version               print Node.js version",
        "Documentation can be found at https://nodejs.org/",
    ] {
        assert!(run.stdout.contains(needle), "missing {needle:?}");
    }
}

/// `-h` is the same text as `--help`.
#[test]
fn short_help_is_the_same_text() {
    let long = run(&["--help"], "");
    let short = run(&["-h"], "");
    assert_eq!(short.stdout, long.stdout);
    assert_eq!(short.status, Some(0));
}

/// `--help` wins over `-e`, which is the order `src/node.cc:371` puts them in:
/// the help check comes before the `has_eval_string` branch.
#[test]
fn help_wins_over_an_eval_string() {
    let run = run(&["-e", "console.log('EVALSCRIPT-EXECUTED')", "--help"], "");
    assert!(
        !run.stdout.contains("EVALSCRIPT-EXECUTED"),
        "the eval script must not run: {}",
        run.stdout
    );
    assert!(run.stdout.starts_with("Usage: rustnode "), "{}", run.stdout);
    assert_eq!(run.status, Some(0));
}

/// A rejected flag still fails when `--version` was asked for, because V8 sees
/// the argument vector before Node answers the version request.
#[test]
fn a_rejected_flag_beats_version() {
    let run = run(&["--version", "--not-a-real-flag"], "");
    assert_eq!(run.status, Some(9));
    assert!(
        run.stderr.contains("bad option: --not-a-real-flag"),
        "{}",
        run.stderr
    );
    assert!(run.stdout.is_empty(), "{}", run.stdout);
}
