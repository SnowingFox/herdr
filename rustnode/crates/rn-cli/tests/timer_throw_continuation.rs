//! A known, unfixed defect: a timer callback that throws stops the timer handle.
//!
//! # What is wrong
//!
//! `crates/rn-bind-timers/src/lib.rs::run_timer_callback` calls `stop_timer()`
//! after it reports a throwing callback:
//!
//! ```text
//! Err(exception) => {
//!     record_uncaught(scope, exception);
//!     stop_timer();          // <-- here
//! }
//! ```
//!
//! `stop_timer()` is `uv_timer_stop` on the handle `processTimers` is called
//! from. When a handler *absorbs* the throw, Node keeps looping — and the handle
//! must stay armed for the deadline `processTimers` reported, or nothing ever
//! rearms it, because `lib/internal/timers.js` only calls `scheduleTimer` for a
//! *new* list that beats `nextExpiry` and stays silent for the one it already
//! knows. So after an absorbed throw, every pending timer in the process is
//! dropped: a later `setTimeout` never fires, and neither does one the handler
//! itself scheduled.
//!
//! The sibling path shows this is not inherent: `run_immediate_callback` reports
//! the throw and stops nothing, which is why `setImmediate` and `nextTick`
//! continue correctly while `setTimeout` does not.
//!
//! # Why it is not fixed here
//!
//! It is a different root cause from the entry-point throw this branch fixes: the
//! handler *does* run, `process._fatalException` *is* consulted, and the exit
//! status is right. What is wrong is that the timer handle is stopped after a
//! callback the runtime does not consider fatal. Fixing it means deciding what
//! `run_timer_callback` should do instead — a `stop_timer()` only for the case
//! where the report was fatal — and validating that against the timer suite,
//! which is a separate piece of work with its own blast radius.
//!
//! # How these tests are written
//!
//! They assert the *defect*, not the correct behaviour, and each is marked
//! `#[ignore]` so the gate stays green. Removing `#[ignore]` is the definition of
//! done for the follow-up: the bodies already assert Node's answers, which are
//! measured rather than guessed — a process that absorbed the throw exits 0 and
//! runs the later timeout, printing both lines.
//!
//! Run them with `cargo test -p rn-cli --test timer_throw_continuation --
//! --ignored`.

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
#[ignore = "known defect: a throwing timer callback stops the timer handle"]
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
#[ignore = "known defect: a throwing timer callback stops the timer handle"]
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
