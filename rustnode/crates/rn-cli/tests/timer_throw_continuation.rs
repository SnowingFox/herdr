//! A timer callback that throws must not stop the timer handle when the throw is
//! absorbed.
//!
//! # The defect these pin
//!
//! `crates/rn-bind-timers/src/lib.rs::run_timer_callback` used to call
//! `stop_timer()` after it reported a throwing callback:
//!
//! ```text
//! Err(exception) => {
//!     record_uncaught(scope, exception);
//!     stop_timer();          // <-- was here
//! }
//! ```
//!
//! `stop_timer()` is `uv_timer_stop` on the handle `processTimers` is called
//! from. When a handler *absorbs* the throw, Node keeps looping — and the handle
//! must stay armed for the deadline `processTimers` reported, or nothing ever
//! rearms it, because `lib/internal/timers.js` only calls `scheduleTimer` for a
//! *new* list that beats `nextExpiry` and stays silent for the one it already
//! knows. So after an absorbed throw every pending timer in the process was
//! dropped: a later `setTimeout` never fired, and neither did one the handler
//! itself scheduled.
//!
//! The sibling path shows this is not inherent: `run_immediate_callback` reports
//! the throw and stops nothing, which is why `setImmediate` and `nextTick`
//! continued correctly while `setTimeout` did not.
//!
//! # What the fix does instead
//!
//! It reproduces `Environment::RunTimers`' retry, not merely the absence of a
//! stop: after an absorbed throw the callback is called *again*, because that is
//! what Node does (`do { ... } while (ret.IsEmpty() && env->can_call_into_js())`).
//! The retry is load-bearing, and the second test below is the one that shows it:
//! a timer the handler scheduled is only in `timerListMap` after the handler ran,
//! so a fix that merely left the old deadline armed would still lose it. Node
//! also leaves the handle completely untouched on the fatal path, where there is
//! no iteration left to need it.
//!
//! # How these tests are written
//!
//! They assert Node's answers, which are measured rather than guessed — a
//! process that absorbed the throw exits 0 and runs the later timeout, printing
//! both lines. The third test is the control that the defect is specific to the
//! timer handle: it passes with or without the fix and must keep passing.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What running a script produced.
struct Run {
    stdout: String,
    exit_code: Option<i32>,
    timed_out: bool,
}

/// Runs `script` through `-e`, killing it if it outlives `limit`.
fn eval(script: &str) -> Run {
    let limit = Duration::from_secs(20);
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["-e", script])
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
        exit_code: status.and_then(|status| status.code()),
        timed_out,
    }
}

#[test]
fn a_later_timer_still_fires_after_an_absorbed_throw() {
    let run = eval(
        "process.on('uncaughtException', (error) => console.log('absorbed: ' + error.message));\n\
         setTimeout(() => { throw new Error('boom'); }, 1);\n\
         setTimeout(() => { console.log('second ran'); }, 40);",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0), "an absorbed throw is not fatal");
    assert_eq!(
        run.stdout.trim(),
        "absorbed: boom\nsecond ran",
        "Node runs the later timer; rustnode stops the handle and drops it"
    );
}

#[test]
fn a_timer_the_handler_schedules_still_fires() {
    // The sharper form: the handle is stopped *after* the handler ran, so even
    // work the handler itself queued is lost. A fix that only preserved a
    // deadline already armed would still fail this one.
    let run = eval(
        "process.on('uncaughtException', () => {\n\
           setTimeout(() => console.log('handler timer'), 5);\n\
         });\n\
         setTimeout(() => { throw new Error('boom'); }, 1);",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0));
    assert_eq!(run.stdout.trim(), "handler timer");
}

#[test]
fn the_rest_of_the_expiry_runs_after_an_absorbed_throw() {
    // The same expiry, so the deadline was certainly still armed: what is
    // missing without the retry is the *rest of the list*, which `processTimers`
    // walks inside one call. Node re-enters `processTimers` after the throw, and
    // an implementation that only refrains from stopping the handle leaves `B`
    // unrun until the next iteration — or, for a single-expiry program, never.
    //
    // Measured on Node: `A`, `handled`, `B`, exit 0.
    let run = eval(
        "process.on('uncaughtException', () => console.log('handled'));\n\
         setTimeout(() => { console.log('A'); throw new Error('boom'); }, 1);\n\
         setTimeout(() => { console.log('B'); }, 1);",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0));
    assert_eq!(
        run.stdout.trim(),
        "A\nhandled\nB",
        "the sibling timer in the same expiry must still run"
    );
}

#[test]
fn a_fatal_timer_throw_still_exits_and_stops_repeating() {
    // The other half of the decision: when nothing absorbs the throw, Node stops
    // calling `processTimers` — `can_call_into_js()` is false — so a `setInterval`
    // that throws must not keep re-entering. The retry condition must therefore
    // be the report's own answer, not an unconditional loop.
    let run = eval("setInterval(() => { console.log('tick'); throw new Error('boom'); }, 1);");
    assert!(
        !run.timed_out,
        "the process must not hang on a fatal interval"
    );
    assert_eq!(run.exit_code, Some(1), "an unhandled throw exits non-zero");
    assert_eq!(
        run.stdout.trim(),
        "tick",
        "the throwing interval must run once, not once per retry"
    );
}

#[test]
fn an_immediate_and_a_tick_do_continue_after_an_absorbed_throw() {
    // The control that shows the defect is specific to the timer handle rather
    // than to uncaught exceptions in general. This passes today, and it must
    // keep passing: `run_immediate_callback` stops nothing after reporting.
    let run = eval(
        "process.on('uncaughtException', (error) => console.log('absorbed: ' + error.message));\n\
         setImmediate(() => { throw new Error('boom'); });\n\
         setImmediate(() => console.log('second immediate ran'));\n\
         process.nextTick(() => console.log('tick ran'));",
    );
    assert!(!run.timed_out, "the process must not hang");
    assert_eq!(run.exit_code, Some(0));
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert!(lines.contains(&"tick ran"), "stdout: {:?}", run.stdout);
    assert!(
        lines.contains(&"second immediate ran"),
        "stdout: {:?}",
        run.stdout
    );
}
