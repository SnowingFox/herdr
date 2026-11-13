//! What a throw from the entry point must do before the process exits.
//!
//! # Why this file exists
//!
//! The entry point — a script file, a `-e`/`-p` script, or an `.mjs` module — is
//! the one place where a throw used to be formatted and printed by the CLI
//! itself, in `crates/rn-cli/src/main.rs`. That is a second uncaught path, and
//! it has two consequences that no other part of the runtime has:
//!
//! * `process.on('uncaughtException')` and
//!   `process.setUncaughtExceptionCaptureCallback` never see the throw, because
//!   the handler lives behind `process._fatalException` and the CLI never called
//!   it. A script whose only failure is a top-level throw exits 1 with the
//!   handler unrun, where Node runs the handler and exits with whatever the
//!   handler left in `process.exitCode`.
//! * The status cannot be influenced by the handler, so any test written as
//!   "handle the entry-point error and assert on the side effects" reports a
//!   failure that has nothing to do with what it measured.
//!
//! # What is pinned here
//!
//! Every case is a statement about Node's ordering, taken from
//! `src/node_errors.cc::TriggerUncaughtException`:
//!
//! * `_fatalException` first, and only a `false` answer reaches print-and-exit;
//! * a handler that sets `process.exitCode` decides the status;
//! * a handler that sets nothing exits 0, because it took responsibility;
//! * no handler at all exits 1 and prints the error;
//! * `exit` is emitted exactly once, from the fatal path, when the error is fatal.
//!
//! The expectations are literal rather than measured against `node`, because the
//! `node` on a test machine is not necessarily the pinned version, and these are
//! status codes rather than formatted output.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What running a script produced.
struct Run {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
}

/// Runs `arguments` under the rustnode binary, killing it if it outlives `limit`.
fn rustnode(arguments: &[&str], limit: Duration) -> Run {
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the rustnode binary starts");

    let mut timed_out = false;
    let status = loop {
        match child.try_wait().expect("the child can be polled") {
            Some(status) => break Some(status),
            None if started.elapsed() > limit => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    let output = child
        .wait_with_output()
        .expect("the child's output is readable");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: status.and_then(|status| status.code()),
        timed_out,
    }
}

/// Runs `script` through `-e`.
fn eval(script: &str) -> Run {
    rustnode(&["-e", script], Duration::from_secs(20))
}

/// Writes `source` to a temporary file with `extension` and runs it.
fn script_file(name: &str, extension: &str, source: &str) -> Run {
    let directory = std::env::temp_dir().join("rustnode-uncaught-entry");
    std::fs::create_dir_all(&directory).expect("the temporary directory is writable");
    let path = directory.join(format!("{name}.{extension}"));
    std::fs::write(&path, source).expect("the script is writable");
    let path = path.to_str().expect("the temporary path is UTF-8");
    rustnode(&[path], Duration::from_secs(20))
}

#[test]
fn a_top_level_throw_reaches_the_uncaught_exception_listener() {
    // The measured divergence this file exists for: the handler runs, sets 3,
    // and the process exits 3 instead of printing the error and exiting 1.
    let run = script_file(
        "listener",
        "js",
        "process.on('uncaughtException', (error) => {\n\
           console.log('handler: ' + error.message);\n\
           process.exitCode = 3;\n\
         });\n\
         throw new Error('top-level boom');\n",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(
        run.exit_code,
        Some(3),
        "the handler's `process.exitCode` decides the status; stderr: {}",
        run.stderr
    );
    assert_eq!(
        run.stdout.trim(),
        "handler: top-level boom",
        "the listener must run; stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("top-level boom"),
        "a handled exception must not be printed; stderr: {}",
        run.stderr
    );
}

#[test]
fn a_top_level_throw_reaches_the_capture_callback() {
    // `setUncaughtExceptionCaptureCallback` has priority over the listener in
    // `onGlobalUncaughtException` (`lib/internal/process/execution.js`), so the
    // listener below must not run.
    let run = script_file(
        "capture",
        "js",
        "process.on('uncaughtException', () => console.log('listener'));\n\
         process.setUncaughtExceptionCaptureCallback((error) => {\n\
           console.log('capture: ' + error.message);\n\
           process.exitCode = 4;\n\
         });\n\
         throw new Error('captured');\n",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(4), "stderr: {}", run.stderr);
    assert_eq!(run.stdout.trim(), "capture: captured");
}

#[test]
fn a_handler_that_sets_no_code_exits_zero() {
    // The handler took responsibility, so there is nothing fatal left: Node
    // exits 0. This is the case that made 51 of the `uncaughtException` files
    // report a rustnode failure while the oracle exited 0.
    let run = script_file(
        "absorbed",
        "js",
        "process.on('uncaughtException', () => {});\n\
         throw new Error('absorbed');\n",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(
        run.exit_code,
        Some(0),
        "an absorbed entry-point throw is not a failure; stderr: {}",
        run.stderr
    );
    assert_eq!(run.stdout, "");
}

#[test]
fn a_throw_nothing_handles_prints_and_exits_one() {
    let run = script_file("fatal", "js", "throw new Error('nobody home');\n");
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(1), "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("nobody home"),
        "an unhandled throw must be printed; stderr: {}",
        run.stderr
    );
}

#[test]
fn a_handler_that_schedules_work_keeps_the_process_alive() {
    // The other half of "the handler took responsibility": Node carries on into
    // the event loop, so a timer the handler armed still fires. A fix that ran
    // the handler and then exited regardless would pass every status assertion
    // above and fail this one.
    let run = eval(
        "process.on('uncaughtException', () => {\n\
           setTimeout(() => console.log('later'), 5);\n\
         });\n\
         throw new Error('after');",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0), "stderr: {}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        "later",
        "work the handler scheduled must run; stderr: {}",
        run.stderr
    );
}

#[test]
fn an_eval_throw_reaches_the_listener() {
    // `-e` is a bare script rather than a module, and it reaches the fatal path
    // through `evalScript` rather than through the loader. Both have to report.
    let run = eval(
        "process.on('uncaughtException', (error, type) => {\n\
           console.log(type + ':' + error.message);\n\
           process.exitCode = 5;\n\
         });\n\
         throw new Error('from eval');",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(5), "stderr: {}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        "uncaughtException:from eval",
        "the `type` argument is `uncaughtException` for a synchronous throw"
    );
}

#[test]
fn a_print_eval_throw_reaches_the_listener() {
    // `-p` shares `evaluate_script` with `-e`, so it must not print a result and
    // must not skip the handler either.
    let run = rustnode(
        &[
            "-p",
            "process.on('uncaughtException', () => console.log('handled'));\
             throw new Error('p boom')",
        ],
        Duration::from_secs(20),
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0), "stderr: {}", run.stderr);
    assert_eq!(run.stdout.trim(), "handled");
}

#[test]
fn an_esm_entry_point_throw_reaches_the_listener() {
    // A synchronous `throw` in an `.mjs` entry point is caught by the loader's
    // `TryCatch` around the entry call, and reaches
    // `triggerUncaughtException(err, false)`. The listener still runs; the point
    // is that the CLI must not print it itself.
    let run = script_file(
        "listener",
        "mjs",
        "process.on('uncaughtException', (error, type) => {\n\
           console.log(type + ':' + error.message);\n\
           process.exitCode = 6;\n\
         });\n\
         throw new Error('esm boom');\n",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(6), "stderr: {}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        "uncaughtException:esm boom",
        "a synchronous entry-point throw is not a rejection; stderr: {}",
        run.stderr
    );
}

#[test]
fn a_top_level_await_rejection_is_reported_as_a_rejection() {
    // The one entry-point case that really is promise-framed:
    // `asyncRunEntryPointWithESMLoader` awaits the module graph and its `catch`
    // calls `triggerUncaughtException(err, true /* fromPromise */)`, so the
    // `type` the listener receives is `unhandledRejection`. A fix that reported
    // every entry-point failure as `uncaughtException` would pass the previous
    // test and fail this one.
    let run = script_file(
        "tla",
        "mjs",
        "process.on('uncaughtException', (error, type) => {\n\
           console.log(type + ':' + error.message);\n\
           process.exitCode = 7;\n\
         });\n\
         await Promise.reject(new Error('tla boom'));\n",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(7), "stderr: {}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        "unhandledRejection:tla boom",
        "an awaited rejection is promise-framed; stderr: {}",
        run.stderr
    );
}

#[test]
fn a_fatal_entry_point_throw_emits_exit_once() {
    // `onGlobalUncaughtException` emits `exit` itself when it declines the
    // error, so the CLI must not emit it a second time. Two emits are visible to
    // a listener that counts them, and to a `mustCall`-shaped assertion.
    let run = script_file(
        "exit-once",
        "js",
        "let count = 0;\n\
         process.on('exit', () => { count += 1; console.log('exit ' + count); });\n\
         throw new Error('fatal');\n",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(1), "stderr: {}", run.stderr);
    assert_eq!(run.stdout.trim(), "exit 1", "stderr: {}", run.stderr);
}

#[test]
fn a_handled_entry_point_throw_emits_exit_once() {
    // The handled case reaches the same emit from the normal exit sequence, so
    // the count must still be one: the fatal path must not have emitted first.
    let run = script_file(
        "exit-once-handled",
        "js",
        "let count = 0;\n\
         process.on('uncaughtException', () => {});\n\
         process.on('exit', () => { count += 1; console.log('exit ' + count); });\n\
         throw new Error('handled');\n",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0), "stderr: {}", run.stderr);
    assert_eq!(run.stdout.trim(), "exit 1", "stderr: {}", run.stderr);
}

#[test]
fn a_rewritten_fatal_exception_is_still_honoured() {
    // `_fatalException` is monkey-patchable on purpose, and
    // `src/node_errors.cc` reads it from the process object on every report. A
    // Rust copy of the handler would ignore this replacement.
    let run = script_file(
        "patched",
        "js",
        "process._fatalException = () => {\n\
           console.log('patched');\n\
           process.exitCode = 8;\n\
           return true;\n\
         };\n\
         throw new Error('patched boom');\n",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(8), "stderr: {}", run.stderr);
    assert_eq!(run.stdout.trim(), "patched");
    assert!(
        !run.stderr.contains("patched boom"),
        "a handled exception must not be printed; stderr: {}",
        run.stderr
    );
}
