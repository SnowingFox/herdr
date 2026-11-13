//! What an unhandled promise rejection must do before the process exits.
//!
//! # Why this file exists
//!
//! V8 reports a rejection through one isolate-level callback, and only that
//! callback reaches `internal/process/promises.js`. `setPromiseRejectCallback`
//! in the `task_queue` namespace merely records the JavaScript function: the
//! registration itself takes `&mut Isolate`, so it cannot come from a binding.
//! Nothing registered it, which meant the recorded function was dead — no
//! `unhandledRejection` listener ever ran and an unhandled rejection never
//! changed the exit code.
//!
//! # What is pinned here
//!
//! The vendored `promises.js` already implements every mode correctly, so these
//! cases are about the wiring rather than about the policy: each one would pass
//! trivially if the handler were reimplemented in Rust, and each one fails if
//! the registration or the `promiseRejectHandler(type, promise, reason)`
//! forwarding is wrong.
//!
//! * the default `--unhandled-rejections=throw` mode raises, so the process
//!   exits 1 having printed the error;
//! * a listener absorbs it and the process exits 0;
//! * a listener that sets `process.exitCode` decides the status;
//! * the other four modes do what `getUnhandledRejectionsMode` says;
//! * a rejection with no listener reaches `uncaughtException` with
//!   `type === 'unhandledRejection'`, and
//!   `setUncaughtExceptionCaptureCallback` still takes precedence over it;
//! * a worker's own isolate reports its own rejections.

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

/// Runs `script` through `-e` with `mode` as `--unhandled-rejections`.
fn eval_in_mode(mode: &str, script: &str) -> Run {
    let flag = format!("--unhandled-rejections={mode}");
    rustnode(&[flag.as_str(), "-e", script], Duration::from_secs(20))
}

/// Writes `source` to a temporary file with `extension` and runs it.
fn script_file(name: &str, extension: &str, source: &str) -> Run {
    let directory = std::env::temp_dir().join("rustnode-unhandled-rejection");
    std::fs::create_dir_all(&directory).expect("the temporary directory is writable");
    let path = directory.join(format!("{name}.{extension}"));
    std::fs::write(&path, source).expect("the script is writable");
    let path = path.to_str().expect("the temporary path is UTF-8");
    rustnode(&[path], Duration::from_secs(20))
}

#[test]
fn an_unhandled_rejection_is_fatal_by_default() {
    // The measured divergence: rustnode printed nothing and exited 0 for a
    // rejected promise in a `.then` callback, where Node raises it and exits 1.
    let run = eval("Promise.resolve().then(() => { throw new Error('micro'); });");
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(
        run.exit_code,
        Some(1),
        "an unhandled rejection is fatal in the default mode; stderr: {}",
        run.stderr
    );
    assert!(
        run.stderr.contains("micro"),
        "the rejection must be printed; stderr: {}",
        run.stderr
    );
    assert!(
        run.stderr.contains("node:internal/process/promises"),
        "the output must carry Node's promises framing; stderr: {}",
        run.stderr
    );
}

#[test]
fn an_unhandled_rejection_listener_runs_and_decides_the_status() {
    let run = eval(
        "process.on('unhandledRejection', (reason, promise) => {\n\
           console.log('UR: ' + reason.message + ' ' + (promise instanceof Promise));\n\
         });\n\
         Promise.reject(new Error('quiet'));",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(
        run.exit_code,
        Some(0),
        "a handled rejection is not fatal; stderr: {}",
        run.stderr
    );
    assert_eq!(
        run.stdout.trim(),
        "UR: quiet true",
        "the listener receives the reason and the promise itself"
    );
}

#[test]
fn the_second_listener_argument_is_the_rejected_promise() {
    // `promiseRejectHandler` forwards `message.GetPromise()`, so the object the
    // listener sees must be the same one the script created. A forwarding bug
    // that passed the reason twice, or an unresolved promise, fails here.
    let run = eval(
        "let seen;\n\
         process.on('unhandledRejection', (reason, promise) => { seen = promise; });\n\
         const created = Promise.reject(new Error('identity'));\n\
         process.on('exit', () => console.log('same: ' + (seen === created)));",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0), "stderr: {}", run.stderr);
    assert_eq!(run.stdout.trim(), "same: true");
}

#[test]
fn a_listener_that_sets_the_exit_code_decides_it() {
    let run = eval(
        "process.on('unhandledRejection', () => { process.exitCode = 7; });\n\
         Promise.reject(new Error('coded'));",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(7), "stderr: {}", run.stderr);
}

#[test]
fn the_warn_mode_warns_and_still_exits_zero() {
    // `alwaysWarnUnhandledRejectionsMode`: emit `unhandledRejection`, then the
    // warning. No raise, so the status stays 0.
    let run = eval_in_mode("warn", "Promise.reject(new Error('warned'));");
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0), "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("UnhandledPromiseRejectionWarning"),
        "the warning must be printed; stderr: {}",
        run.stderr
    );
}

#[test]
fn the_warn_with_error_code_mode_warns_and_exits_one() {
    let run = eval_in_mode(
        "warn-with-error-code",
        "Promise.reject(new Error('coded warning'));",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(1), "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("UnhandledPromiseRejectionWarning"),
        "the warning must be printed; stderr: {}",
        run.stderr
    );
}

#[test]
fn the_none_mode_is_silent() {
    let run = eval_in_mode("none", "Promise.reject(new Error('silent'));");
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0), "stderr: {}", run.stderr);
    assert_eq!(run.stdout, "");
    assert!(
        !run.stderr.contains("UnhandledPromiseRejection"),
        "`none` must print no warning; stderr: {}",
        run.stderr
    );
}

#[test]
fn the_strict_mode_raises_even_with_a_listener() {
    // `strictUnhandledRejectionsMode` calls `triggerUncaughtException` *before*
    // emitting `unhandledRejection`, so the listener still runs but the
    // exception has already been raised.
    let run = eval_in_mode(
        "strict",
        "process.on('unhandledRejection', () => console.log('listener'));\n\
         Promise.reject(new Error('strict boom'));",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(1), "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("strict boom"),
        "strict mode must print the error; stderr: {}",
        run.stderr
    );
    assert_eq!(
        run.stdout.trim(),
        "listener",
        "the listener still runs after the raise; stderr: {}",
        run.stderr
    );
}

#[test]
fn a_rejection_with_no_listener_reaches_uncaught_exception() {
    // `throwUnhandledRejectionsMode` calls `triggerUncaughtException(err, true)`,
    // so an `uncaughtException` listener sees it with
    // `type === 'unhandledRejection'`. This is the funnel that makes an
    // unhandled rejection a normal uncaught exception rather than a second
    // fatal path.
    let run = eval(
        "process.on('uncaughtException', (error, type) => {\n\
           console.log(type + ':' + error.message);\n\
           process.exitCode = 9;\n\
         });\n\
         Promise.reject(new Error('funnel'));",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(9), "stderr: {}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        "unhandledRejection:funnel",
        "the rejection reaches the uncaught listener with its own type"
    );
}

#[test]
fn the_capture_callback_takes_precedence_over_the_listener() {
    // `onGlobalUncaughtException` runs `captureFn` and skips the emit entirely,
    // so an installed capture callback must win. `strict` mode is used because
    // it raises unconditionally, which makes the precedence observable without
    // depending on the default mode's raise.
    let run = eval_in_mode(
        "strict",
        "process.on('uncaughtException', () => console.log('listener'));\n\
         process.setUncaughtExceptionCaptureCallback((error) => {\n\
           console.log('capture:' + error.message);\n\
           process.exitCode = 4;\n\
         });\n\
         Promise.reject(new Error('captured'));",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(
        run.stdout.trim(),
        "capture:captured",
        "stderr: {}",
        run.stderr
    );
    // The capture callback ran, so the exception was handled and the status is
    // the one it set.
    assert_eq!(run.exit_code, Some(4), "stderr: {}", run.stderr);
}

#[test]
fn a_worker_reports_its_own_rejections() {
    // The callback is per-isolate state, so a worker needs its own registration.
    // Without it a worker's `unhandledRejection` listener never fires and the
    // worker exits 0 having tested nothing.
    let run = script_file(
        "worker",
        "js",
        r#"const { Worker } = require('worker_threads');
const worker = new Worker(`
  process.on('unhandledRejection', (reason) => {
    console.log('worker: ' + reason.message);
    process.exitCode = 6;
  });
  Promise.reject(new Error('from worker'));
`, { eval: true });
worker.on('exit', (code) => console.log('code: ' + code));
"#,
    );
    assert!(!run.timed_out, "the process must not hang");
    // The worker bootstrap logs a tracing warning on the parent's stdout, so the
    // assertion is on the lines that matter rather than on the whole stream.
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert!(
        lines.contains(&"worker: from worker"),
        "the worker's own listener must run; stdout: {:?}, stderr: {}",
        run.stdout,
        run.stderr
    );
    assert!(
        lines.contains(&"code: 6"),
        "the worker's exit code must be the one its listener set; stdout: {:?}",
        run.stdout
    );
}

#[test]
fn a_late_handler_reports_rejection_handled() {
    // `handledRejection` pushes onto `asyncHandledRejections` and
    // `processPromiseRejections` emits `rejectionHandled` for it. That whole
    // path only runs when V8 reported the pair, so it is a check on the
    // `kPromiseHandlerAddedAfterReject` half of the forwarding.
    let run = eval(
        "process.on('unhandledRejection', () => console.log('UR'));\n\
         process.on('rejectionHandled', () => console.log('RH'));\n\
         const promise = Promise.reject(new Error('late'));\n\
         setTimeout(() => promise.catch(() => {}), 5);",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0), "stderr: {}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        "UR\nRH",
        "the late handler must produce `rejectionHandled`; stderr: {}",
        run.stderr
    );
}

#[test]
fn a_caught_rejection_is_not_reported() {
    // The negative control: a rejection that is handled in the same tick must
    // reach neither the listener nor the fatal path. A forwarding bug that
    // reported every rejection would pass every test above and fail this one.
    let run = eval(
        "process.on('unhandledRejection', () => console.log('should not run'));\n\
         process.on('rejectionHandled', () => console.log('should not run either'));\n\
         Promise.reject(new Error('handled')).catch(() => console.log('caught'));",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0), "stderr: {}", run.stderr);
    assert_eq!(run.stdout.trim(), "caught");
}
