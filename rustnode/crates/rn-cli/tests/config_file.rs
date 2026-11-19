//! `--config-file` reads its file, and reports a bad one the way Node does.
//!
//! # Why this file exists
//!
//! `--config-file` was declared in the option table, accepted by the walk, and
//! never opened. A command line that named a config that does not exist ran the
//! script as though the flag were absent:
//!
//! ```text
//! $ rustnode --config-file=i-do-not-exist.json -p '"Hello"'
//! Hello
//! $ echo $?
//! 0
//! ```
//!
//! # What is pinned here, and what is not
//!
//! Only the read and its two error shapes are in scope. `test-config-file.js` has
//! ten cases and eight of them are `nodeVersion` selection and the `configs`
//! array, which need Node's `ConfigReader` semantics (`src/node_config_file.cc`)
//! and are not implemented. The two this file covers are:
//!
//! * `should handle non existing json`;
//! * `should handle empty json`.
//!
//! A file whose root *is* an object is read, accepted, and not applied — see
//! `config_file`'s note on scope. The last two tests below pin that deliberately:
//! without them, "reads the file" and "reads the file and does nothing with it"
//! would be indistinguishable from the outside on a green run.
//!
//! # Why the two lines are asserted separately
//!
//! Node's first line has no program prefix and its second does, because they come
//! from two different places (`FPrintF` inside the reader, then the startup error
//! vector). Asserting the whole stderr block byte for byte is the only shape that
//! catches a change that prefixes the first line or drops the blank line the
//! `Root value unexpected` case prints.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A scratch directory that removes itself when the test finishes.
///
/// Each test gets its own, named from the test's own name, so two tests running
/// in parallel cannot overwrite each other's config file.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rustnode-config-file-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the scratch directory is created");
        Self { path }
    }

    fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.path.join(name);
        std::fs::write(&path, contents).expect("the fixture file is written");
        path
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// What one run produced.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Runs the built binary in `directory` with `arguments`.
fn run_in(directory: &Path, arguments: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .env_remove("NODE_OPTIONS")
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("rustnode runs");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// This process's `argv[0]`, which is what the prefixed lines carry.
///
/// Read from the spawned binary's own report rather than assumed, because the
/// test harness invokes it by absolute path and `StartInternal` uses `argv[0]`
/// verbatim. `CARGO_BIN_EXE_rustnode` is not necessarily spelled the way the OS
/// reports it after the child starts, so the value is taken from a run.
fn program_name() -> String {
    let directory = std::env::temp_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .env_remove("NODE_OPTIONS")
        .current_dir(&directory)
        .args(["-p", "process.execPath"])
        .output()
        .expect("rustnode runs");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// `should handle non existing json` from `test-config-file.js`.
///
/// Node's two lines, in order: the reader's own sentence with no program name,
/// then the error-vector entry prefixed with `argv[0]`. `--config-file=` and the
/// separate spelling are covered too, since the alias table declares all three
/// spellings and only the `=` form is what the test itself uses.
#[test]
fn a_missing_config_file_is_reported_the_way_node_does() {
    let scratch = Scratch::new("missing");
    let program = program_name();
    // Note `--experimental-default-config-file=<path>` is *not* here: that
    // spelling refuses any value, so it reports its own message instead of
    // trying to open anything. Its bare form does read the default file, which
    // `a_bare_flag_reads_the_default_file` covers.
    for spelling in [
        "--config-file=i-do-not-exist.json",
        "--experimental-config-file=i-do-not-exist.json",
    ] {
        let run = run_in(scratch.path(), &[spelling, "-p", "\"Hello, World!\""]);
        assert_eq!(run.code, 9, "{spelling} must exit 9");
        // Nothing is written to stdout: the flag failed before the script ran.
        assert_eq!(run.stdout, "", "{spelling} must not print");
        assert_eq!(
            run.stderr,
            format!(
                "Cannot read configuration from i-do-not-exist.json: no such file or directory\n\
                 {program}: i-do-not-exist.json: not found\n"
            ),
            "{spelling}"
        );
    }
}

/// `should handle empty json` from `test-config-file.js`.
///
/// The fixture is a single newline, which simdjson fails to iterate rather than
/// finding a non-object root — so the first line is `Can't parse`, not the
/// `Root value unexpected` one. Both spellings of that distinction are pinned
/// here because they are distinguishable in Node's output and were measured.
#[test]
fn an_empty_config_file_is_invalid_content() {
    let scratch = Scratch::new("empty");
    let program = program_name();
    for contents in [b"\n".as_slice(), b"", b"   \n\t\n", b"{"] {
        scratch.write("empty.json", contents);
        let run = run_in(
            scratch.path(),
            &["--config-file=empty.json", "-p", "\"Hello, World!\""],
        );
        assert_eq!(run.code, 9, "{contents:?} must exit 9");
        assert_eq!(run.stdout, "", "{contents:?} must not print");
        assert_eq!(
            run.stderr,
            format!("Can't parse empty.json\n{program}: empty.json: invalid content\n"),
            "{contents:?}"
        );
    }
}

/// A root that is not an object is the other `InvalidContent` message.
///
/// simdjson answers `INCORRECT_TYPE` rather than failing to parse, so the reader
/// prints `Root value unexpected not an object` followed by a blank line. That
/// blank line is part of Node's output (`"…for %s\n\n"`), which is why the whole
/// block is compared rather than a line at a time.
#[test]
fn a_non_object_root_is_invalid_content() {
    let scratch = Scratch::new("non-object");
    let program = program_name();
    for contents in [b"not json".as_slice(), b"[]", b"5", b"\"x\"", b"null"] {
        scratch.write("root.json", contents);
        let run = run_in(
            scratch.path(),
            &["--config-file=root.json", "-p", "\"Hello, World!\""],
        );
        assert_eq!(run.code, 9, "{contents:?} must exit 9");
        assert_eq!(run.stdout, "", "{contents:?} must not print");
        assert_eq!(
            run.stderr,
            format!(
                "Root value unexpected not an object for root.json\n\n\
                 {program}: root.json: invalid content\n"
            ),
            "{contents:?}"
        );
    }
}

/// A file that is not UTF-8 is a parse failure, not an open failure.
///
/// Node's reader hands the parser raw bytes, so a bad sequence is `Can't parse`
/// with `invalid content` — not `Cannot read configuration`. `read_to_string`
/// would have produced the other message, which is why the reader takes bytes.
#[test]
fn a_config_file_that_is_not_utf8_is_invalid_content() {
    let scratch = Scratch::new("utf8");
    let program = program_name();
    scratch.write("bad.json", b"\xff\xfe{}");
    let run = run_in(scratch.path(), &["--config-file=bad.json", "-p", "1"]);
    assert_eq!(run.code, 9);
    assert_eq!(
        run.stderr,
        format!("Can't parse bad.json\n{program}: bad.json: invalid content\n")
    );
}

/// An empty `=` value is a missing argument, and the walk stops there.
///
/// `Parse` breaks on a missing argument, so a later `--config-file=` cannot
/// rescue the command line: `--config-file= --config-file=ok.json` reports the
/// missing argument on the oracle rather than reading `ok.json`.
#[test]
fn an_empty_inline_value_requires_an_argument() {
    let scratch = Scratch::new("missing-arg");
    let program = program_name();
    scratch.write("ok.json", b"{}");
    for spelling in [
        "--config-file=",
        "--experimental-config-file=",
        // The "default" spelling refuses any value, including an empty one, so
        // this reports its own message rather than a missing argument.
    ] {
        let run = run_in(scratch.path(), &[spelling, "-p", "1"]);
        assert_eq!(run.code, 9, "{spelling}");
        assert_eq!(
            run.stderr,
            format!("{program}: {spelling} requires an argument\n")
        );
    }
    let run = run_in(
        scratch.path(),
        &["--config-file=", "--config-file=ok.json", "-p", "1"],
    );
    assert_eq!(run.code, 9, "the walk stops at the first missing argument");
    assert_eq!(
        run.stderr,
        format!("{program}: --config-file= requires an argument\n")
    );
    let run = run_in(
        scratch.path(),
        &["--experimental-default-config-file=ok.json", "-p", "1"],
    );
    assert_eq!(run.code, 9);
    assert_eq!(
        run.stderr,
        format!("{program}: --experimental-default-config-file does not take an argument\n")
    );
}

/// A bare flag reads `node.config.json`, and that path is what `execArgv` shows.
///
/// `GetDataFromArgs` rewrites the bare spelling to `--config-file=node.config.json`
/// before the parse runs, so the rewrite is observable twice: the default file is
/// the one opened, and `process.execArgv` reports the `=` form rather than the
/// bare word. Recording the bare word instead would let the store's `apply` take
/// the *next* argument as the value, which silently swallowed `-p` and produced a
/// process that printed nothing while exiting 0.
#[test]
fn a_bare_flag_reads_the_default_file() {
    let scratch = Scratch::new("bare");
    let program = program_name();
    let run = run_in(scratch.path(), &["--config-file", "-p", "\"H\""]);
    assert_eq!(run.code, 9);
    assert_eq!(
        run.stderr,
        format!(
            "Cannot read configuration from node.config.json: no such file or directory\n\
             {program}: node.config.json: not found\n"
        )
    );

    scratch.write("node.config.json", b"{}");
    let run = run_in(
        scratch.path(),
        &["--config-file", "-p", "JSON.stringify(process.execArgv)"],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        r#"["--config-file=node.config.json","-p","JSON.stringify(process.execArgv)"]"#
    );
}

/// A config whose root is an object is read and accepted, without being applied.
///
/// This is the documented limit of this change: the read and its errors are
/// implemented, and the semantics are not. The assertion is deliberately about
/// the *absence* of an error — a valid file must behave exactly as it did before
/// the file was read at all, because refusing or warning on one would break runs
/// that work today on the strength of a feature this change does not claim.
#[test]
fn a_valid_config_file_is_accepted_and_not_applied() {
    let scratch = Scratch::new("valid");
    // `max-http-header-size` is what `test-config-file.js` reads back, so it is
    // the field that would move if the contents were applied. 10 against the
    // default 16384 makes the difference unmissable.
    scratch.write(
        "node.config.json",
        br#"{"nodeOptions":{"max-http-header-size":10}}"#,
    );
    let run = run_in(
        scratch.path(),
        &[
            "--config-file=node.config.json",
            "-p",
            "require(\"node:http\").maxHeaderSize",
        ],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert_eq!(run.stderr, "", "a valid config must not warn");
    assert_ne!(
        run.stdout.trim(),
        "10",
        "this change does not apply config contents; if it starts to, this test \
         and the scope note in `config_file` both need revisiting"
    );
}

/// A file the process cannot read reports libuv's description, not libc's.
///
/// The two differ in case — libuv says `permission denied`, libc says
/// `Permission denied` — and Node prints libuv's, because `ParseConfig`
/// formats `uv_strerror`. `chmod 000` is skipped for a root user, for whom the
/// mode changes nothing.
#[cfg(unix)]
#[test]
fn an_unreadable_config_file_reports_libuvs_description() {
    use std::os::unix::fs::PermissionsExt;

    // Root can read anything, so the fixture would produce a successful read and
    // the test would assert nothing. Node's own suite skips the same way.
    // SAFETY: `geteuid` has no preconditions and no side effects.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let scratch = Scratch::new("unreadable");
    let program = program_name();
    let path = scratch.write("locked.json", b"{}");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .expect("the fixture is made unreadable");
    let run = run_in(scratch.path(), &["--config-file=locked.json", "-p", "1"]);
    // Restore before asserting so a failure does not leave an unreadable file
    // behind for the directory cleanup.
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
    assert_eq!(run.code, 9);
    assert_eq!(
        run.stderr,
        format!(
            "Cannot read configuration from locked.json: permission denied\n\
             {program}: locked.json: not found\n"
        )
    );
}
