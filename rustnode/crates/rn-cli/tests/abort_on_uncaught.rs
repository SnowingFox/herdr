//! What `--abort-on-uncaught-exception` must do.
//!
//! # Why this file exists
//!
//! The flag was parsed and reported but had no behaviour: it sat in
//! `rn-cli/src/args.rs`'s `IGNORED_WITHOUT_VALUE`, so every Node test that passed
//! it asked for a signal death and got exit 1.
//!
//! # The order, from `src/node_errors.cc:1193`
//!
//! `TriggerUncaughtException` checks the abort *above* its call to
//! `errors::TriggerUncaughtException`, which is the only path to
//! `process._fatalException`. On the abort path therefore:
//!
//! * the error is printed,
//! * `_fatalException` is never called, so `process.on('uncaughtException')`
//!   never runs and cannot suppress the abort,
//! * `'exit'` handlers never run,
//! * the process dies by signal.
//!
//! `process.setUncaughtExceptionCaptureCallback(fn)` is the exception, and it is
//! the reason the gate cannot be the CLI flag alone: the callback clears
//! `shouldAbortOnUncaughtToggle[0]`, which `src/api/environment.cc:65` reads
//! alongside the option. `test-process-exception-capture-should-abort-on-uncaught.js`
//! exists to pin exactly that, and its comment says so: "This should make the
//! process not crash even though the flag was passed."
//!
//! # Why the expectations are literals
//!
//! `test/common/index.js:635` accepts 132, 133 or 134 for an abort, so the exact
//! status is not part of Node's contract. These assert 134 because that is what
//! `std::process::abort()` produces here, and because a `panic!` would produce
//! 101 with Rust text on stderr — the failure mode this file is guarding against.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What running a script produced.
struct Run {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    signal: Option<i32>,
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
    use std::os::unix::process::ExitStatusExt;
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: status.and_then(|status| status.code()),
        signal: status.and_then(|status| status.signal()),
        timed_out,
    }
}

/// Runs `script` through `-e` with `flags` in front of it.
fn eval_with(flags: &[&str], script: &str) -> Run {
    let mut arguments = flags.to_vec();
    arguments.extend(["-e", script]);
    rustnode(&arguments, Duration::from_secs(20))
}

/// `SIGABRT`, which is what `std::process::abort()` raises.
///
/// `test/common/index.js:635` accepts 132, 133 or 134 — SIGILL, SIGTRAP or
/// SIGABRT — because the exact one depends on the platform and the code path.
/// Asserting the signal rather than a status is what makes the assertion mean
/// "died by a signal at all": a `panic!` would give status 101 and no signal,
/// and a normal exit would give status 1 and no signal.
const SIGABRT: i32 = 6;

/// Asserts that `run` died the way an abort dies, and explains when it did not.
#[track_caller]
fn assert_aborted(run: &Run) {
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(
        run.signal,
        Some(SIGABRT),
        "an abort is a signal death, not an exit code (status {:?}); stderr: {}",
        run.exit_code,
        run.stderr
    );
    assert_eq!(run.exit_code, None, "a signal death has no exit code");
    // `panic!` would inject Rust text and exit 101 rather than raising a signal.
    assert!(
        !run.stderr.contains("panicked"),
        "the abort must not go through `panic!`; stderr: {}",
        run.stderr
    );
}

#[test]
fn an_uncaught_throw_dies_by_signal_and_prints_the_error() {
    let run = eval_with(&["--abort-on-uncaught-exception"], "throw new Error('x')");
    assert_aborted(&run);
    assert!(
        run.stderr.contains("Uncaught Error: x"),
        "the error is printed before the abort; stderr: {}",
        run.stderr
    );
    // `panic!` would add two lines of Rust text and exit 101. Neither the status
    // nor these phrases may appear.
    assert!(
        !run.stderr.contains("panicked"),
        "the abort must not go through `panic!`; stderr: {}",
        run.stderr
    );
}

#[test]
fn an_uncaught_exception_listener_does_not_prevent_the_abort() {
    // The listener lives inside `process._fatalException`, which the abort path
    // never reaches, so it must not run and must not change the status.
    let run = eval_with(
        &["--abort-on-uncaught-exception"],
        "process.on('uncaughtException', () => console.log('HANDLER'));\n\
         throw new Error('boom');",
    );
    assert_aborted(&run);
    assert_eq!(
        run.stdout, "",
        "the listener must not run; stdout: {}",
        run.stdout
    );
}

#[test]
fn an_exit_listener_does_not_run_on_the_abort_path() {
    // `'exit'` is emitted by `_fatalException` and by the normal exit sequence,
    // both of which the abort precedes.
    let run = eval_with(
        &["--abort-on-uncaught-exception"],
        "process.on('exit', () => console.log('EXIT RAN'));\n\
         throw new Error('boom');",
    );
    assert_aborted(&run);
    assert_eq!(
        run.stdout, "",
        "no 'exit' handler may run before an abort; stdout: {}",
        run.stdout
    );
}

#[test]
fn a_capture_callback_prevents_the_abort() {
    // The one case that is not the flag alone: `setUncaughtExceptionCaptureCallback`
    // clears `shouldAbortOnUncaughtToggle[0]`, which the native gate reads. An
    // implementation keyed on the CLI flag fails exactly here while passing every
    // other test in this file.
    let run = eval_with(
        &["--abort-on-uncaught-exception"],
        "process.setUncaughtExceptionCaptureCallback((error) => {\n\
           console.log('CAPTURE ' + error.message);\n\
         });\n\
         throw new Error('foo');",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(
        run.exit_code,
        Some(0),
        "the capture callback handles the error, so nothing is fatal; stderr: {}",
        run.stderr
    );
    assert_eq!(run.stdout.trim(), "CAPTURE foo");
}

#[test]
fn clearing_the_capture_callback_restores_the_abort() {
    // `setUncaughtExceptionCaptureCallback(null)` writes `1` back over the toggle
    // (`lib/internal/process/execution.js:121`), so the abort must come back.
    // Without this, an implementation that latched "a capture callback was ever
    // installed" would pass the test above.
    let run = eval_with(
        &["--abort-on-uncaught-exception"],
        "process.setUncaughtExceptionCaptureCallback(() => {});\n\
         process.setUncaughtExceptionCaptureCallback(null);\n\
         throw new Error('restored');",
    );
    assert_aborted(&run);
    assert!(
        run.stderr.contains("Uncaught Error: restored"),
        "stderr: {}",
        run.stderr
    );
}

#[test]
fn the_underscore_spelling_is_accepted_too() {
    // `src/node.cc:794` searches its V8 argument vector for both spellings, and
    // Node's own test headers use both, so rejecting one breaks a command line
    // `node` runs.
    let run = eval_with(&["--abort_on_uncaught_exception"], "throw new Error('x')");
    assert_aborted(&run);
}

#[test]
fn without_the_flag_a_handler_still_decides_the_status() {
    // The control for the whole file: the flag is what changes the order, not the
    // reporting path. A handler that takes responsibility still exits 0.
    let run = eval_with(
        &[],
        "process.on('uncaughtException', () => { process.exitCode = 3; });\n\
         throw new Error('handled');",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(
        run.exit_code,
        Some(3),
        "without the flag the handler runs; stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("handled"),
        "a handled error must not be printed; stderr: {}",
        run.stderr
    );
}

#[test]
fn without_the_flag_an_unhandled_throw_still_exits_one() {
    // Point 6 of the landing rule, and the reason a `std::process::abort()` in the
    // reporting path unconditionally would be wrong.
    let run = eval_with(&[], "throw new Error('nobody home')");
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(
        run.exit_code,
        Some(1),
        "the default path is unchanged; stderr: {}",
        run.stderr
    );
}

#[test]
fn a_throw_from_a_timer_callback_aborts() {
    // The event loop reaches the same funnel, so the flag has to apply there too.
    let run = eval_with(
        &["--abort-on-uncaught-exception"],
        "setTimeout(() => { throw new Error('later'); }, 1);",
    );
    assert_aborted(&run);
    assert!(
        run.stderr.contains("Uncaught Error: later"),
        "stderr: {}",
        run.stderr
    );
}

/// A throw from an `fs` completion callback aborts.
///
/// This depends on #77. `crates/rn-bind-fs/src/complete.rs` used to deliver the
/// callback with `let _ = handler.call(...)`, which left the exception pending on
/// the isolate: V8's default reporter printed `Uncaught …` to *stdout* and the
/// process exited 0, so nothing reached the abort check. #77 routed every
/// completion sink through one shared reporter, and this assertion now holds.
///
/// It was `#[ignore]`d while #77 was unmerged; that ignore is gone now that the
/// dependency has landed, which was the stated definition of done for the merge.
///
/// `a_throw_from_a_timer_callback_aborts` above is the working sibling: timers
/// already reported through the funnel, so the flag was observable there even
/// before #77.
#[test]
fn a_throw_from_an_fs_callback_aborts() {
    let run = eval_with(
        &["--abort-on-uncaught-exception"],
        "require('fs').exists('/definitely/not/here', () => {\n\
           throw new Error('from fs');\n\
         });",
    );
    assert_aborted(&run);
    assert_eq!(
        run.stdout, "",
        "the error must not be printed to stdout; stdout: {}",
        run.stdout
    );
}
