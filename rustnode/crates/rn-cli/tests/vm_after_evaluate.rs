//! `vm`'s `microtaskMode: 'afterEvaluate'` contract, against the pinned oracle.
//!
//! # What the mode means
//!
//! `vm.createContext` with `microtaskMode: 'afterEvaluate'` gives the realm its
//! own `v8::MicrotaskQueue` under `MicrotasksPolicy::Explicit`. The isolate's
//! default queue is drained at the end of every native-to-JavaScript callback
//! (`InternalCallbackScope::Close`), but this realm's queue is drained by nobody
//! except `runInContext`, and only after the script body has returned:
//! `ContextifyScript::EvalMachine` (`src/node_contextify.cc`) ends with
//!
//! ```text
//! result = script->Run(context);
//! if (!result.IsEmpty() && mtask_queue != nullptr)
//!   mtask_queue->PerformCheckpoint(env->isolate());
//! ```
//!
//! Three separate requirements follow from those two lines, and each one broke
//! at a different time:
//!
//! 1. The checkpoint exists at all. rustnode built the queue and never drained
//!    it, so a `.then` in that mode ran *never* — not late, never.
//! 2. The checkpoint is skipped when the body produced no value. `!result
//!    .IsEmpty()` is false when the body threw or was terminated, so a body that
//!    threw must leave its queued microtask pending rather than running it.
//! 3. The checkpoint is *inside* the watchdog's window. `timed_out` is a
//!    watchdog-owned flag the thread sets before `TerminateExecution`, and
//!    `EvalMachine` converts it to `ERR_SCRIPT_EXECUTION_TIMEOUT` after the
//!    checkpoint. A drain that runs after the watchdog is dropped, or that
//!    samples the flag before it, reports a body loop's timeout but lets a
//!    microtask loop outlive its deadline and escape (`#3020`).
//!
//! Requirement 3 is what makes this subtle: the failing shape is a *5 ms*
//! deadline on a body that busy-waits on `hrtime()` and calls the same `loop()`
//! the microtask calls. Draining after the deadline with the guard removed
//! reached the function's own 2000 ms escape and threw from there instead.
//!
//! # Why byte-exact comparisons
//!
//! Every case prints one line and is compared with [`rn_node_oracle`], the build
//! `tools/node-pin.toml` pins. A hand-written expectation would encode what this
//! author believed V8's ordering to be; the timing cases below are exactly the
//! ones where that belief was wrong twice.

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// A file name no other test in this process uses.
fn script_path() -> std::path::PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("rn-vm-after-{}-{n}.js", std::process::id()))
}

/// Runs `binary <script file>` and returns its stdout and stderr, trimmed.
fn run(binary: &str, body: &str) -> (String, String) {
    let path = script_path();
    std::fs::write(&path, body).expect("the script file is writable");
    let output = Command::new(binary)
        .arg(&path)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    let _ = std::fs::remove_file(&path);
    (
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    )
}

/// The pinned oracle, resolved and announced once per test binary.
fn reference() -> Option<&'static str> {
    static ORACLE: std::sync::OnceLock<Option<rn_node_oracle::Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-cli vm afterEvaluate"))
        .as_ref()
        .map(|oracle| oracle.reference_path())
}

/// Asserts stdout matches the pinned oracle byte for byte.
///
/// Returns `None` when no oracle could be resolved, so a machine without the
/// pinned build skips loudly through the resolver's own announcement rather than
/// comparing against whatever `node` happens to be on `PATH`.
fn same_as_oracle(body: &str) -> Option<String> {
    let expected = run(reference()?, body).0;
    let actual = run(env!("CARGO_BIN_EXE_rustnode"), body).0;
    assert_eq!(actual, expected, "script was:\n{body}");
    Some(actual)
}

macro_rules! same_as_oracle {
    ($body:expr $(,)?) => {
        match same_as_oracle($body) {
            Some(printed) => printed,
            None => return,
        }
    };
}

#[test]
fn an_after_evaluate_microtask_runs_when_the_script_returns() {
    // Requirement 1, the primary defect: before the checkpoint existed the
    // sandbox kept its seed value because the `.then` never ran at all.
    let printed = same_as_oracle!(
        r#"
        const vm = require('vm');
        const sandbox = { out: '?' };
        const result = vm.runInNewContext(
          'Promise.resolve().then(() => { globalThis.out = "ran"; }); 42;',
          sandbox,
          { microtaskMode: 'afterEvaluate' });
        console.log(JSON.stringify({ result, out: sandbox.out }));
        "#
    );
    assert_eq!(printed, r#"{"result":42,"out":"ran"}"#);
}

#[test]
fn the_microtask_queue_runs_in_order_and_after_the_body() {
    // The queue is FIFO and drains only once the body is finished, so the
    // body's own push comes first. `queueMicrotask` is not a global in a `vm`
    // realm, so the two queued jobs both come from promises.
    let printed = same_as_oracle!(
        r#"
        const vm = require('vm');
        const out = [];
        vm.runInNewContext(
          'Promise.resolve().then(() => out.push("first"));' +
          'Promise.resolve().then(() => out.push("second"));' +
          'out.push("body");',
          { out },
          { microtaskMode: 'afterEvaluate' });
        console.log(JSON.stringify(out));
        "#
    );
    assert_eq!(printed, r#"["body","first","second"]"#);
}

#[test]
fn a_thrown_body_leaves_the_microtask_queue_undrained() {
    // Requirement 2: `EvalMachine` guards the checkpoint with
    // `!result.IsEmpty()`, so a throwing body must not drain. The microtask is
    // still pending afterwards, which `out` proves.
    let printed = same_as_oracle!(
        r#"
        const vm = require('vm');
        const sandbox = { out: 'not-run' };
        let caught;
        try {
          vm.runInNewContext(
            'Promise.resolve().then(() => { globalThis.out = "ran"; });' +
            'throw new Error("body");',
            sandbox,
            { microtaskMode: 'afterEvaluate' });
        } catch (error) {
          caught = error.message;
        }
        console.log(JSON.stringify({ caught, out: sandbox.out }));
        "#
    );
    assert_eq!(printed, r#"{"caught":"body","out":"not-run"}"#);
}

#[test]
fn a_microtask_loop_is_killed_by_the_same_deadline_as_the_body() {
    // Requirement 3, the case that a late drain gets wrong. The body returns, so
    // the checkpoint runs, and the microtask it queued loops forever. The
    // watchdog must still be armed and `timed_out` must be sampled afterwards,
    // or this reaches the function's own 2000 ms escape instead.
    let printed = same_as_oracle!(
        r#"
        const vm = require('vm');
        const NS_PER_MS = 1000000n;
        const hrtime = process.hrtime.bigint;
        function loop() {
          const start = hrtime();
          while (1) {
            const span = (hrtime() - start) / NS_PER_MS;
            if (span >= 2000n) throw new Error('escaped the timeout');
          }
        }
        try {
          vm.runInNewContext(
            'Promise.resolve().then(() => loop());',
            { hrtime, loop },
            { timeout: 10, microtaskMode: 'afterEvaluate' });
          console.log('no throw');
        } catch (error) {
          console.log(JSON.stringify({ code: error.code, message: error.message }));
        }
        "#
    );
    assert_eq!(
        printed,
        r#"{"code":"ERR_SCRIPT_EXECUTION_TIMEOUT","message":"Script execution timed out after 10ms"}"#
    );
}

#[test]
fn a_body_loop_that_also_queued_a_looping_microtask_times_out_once() {
    // `test/parallel/test-vm-timeout-escape-promise.js`: the body loops and the
    // queued microtask loops too. The body loop is terminated, so the checkpoint
    // is skipped — the microtask must never get the chance to run and the
    // report must be this call's timeout, not the microtask's.
    let printed = same_as_oracle!(
        r#"
        const vm = require('vm');
        const NS_PER_MS = 1000000n;
        const hrtime = process.hrtime.bigint;
        function loop() {
          const start = hrtime();
          while (1) {
            const span = (hrtime() - start) / NS_PER_MS;
            if (span >= 2000n) throw new Error('escaped the timeout');
          }
        }
        try {
          vm.runInNewContext(
            'Promise.resolve().then(() => loop()); loop();',
            { hrtime, loop },
            { timeout: 5, microtaskMode: 'afterEvaluate' });
          console.log('no throw');
        } catch (error) {
          console.log(JSON.stringify({ code: error.code, message: error.message }));
        }
        "#
    );
    assert_eq!(
        printed,
        r#"{"code":"ERR_SCRIPT_EXECUTION_TIMEOUT","message":"Script execution timed out after 5ms"}"#
    );
}

#[test]
fn a_microtask_may_contextify_a_new_sandbox_during_the_drain() {
    // The drain runs user code, and that code can reach `vm.createContext`,
    // which mutates the same registry the queue was read from. Reading the
    // queue through a borrow held across the checkpoint would abort here.
    let printed = same_as_oracle!(
        r#"
        const vm = require('vm');
        const sandbox = { vm, out: '?' };
        vm.runInNewContext(
          'Promise.resolve().then(() => {' +
          '  vm.createContext({});' +
          '  globalThis.out = "ok";' +
          '});',
          sandbox,
          { microtaskMode: 'afterEvaluate' });
        console.log(sandbox.out);
        "#
    );
    assert_eq!(printed, "ok");
}

#[test]
fn a_context_without_the_mode_is_unchanged_by_the_drain() {
    // The counterpart: a context made without `microtaskMode` has no explicit
    // queue, so it rides the isolate's default policy and is drained at the next
    // native-to-JavaScript callback boundary rather than inside `runInNewContext`.
    // So `out` is still unset when the call returns and `"ran"` after one tick.
    // A drain that fired for every context would set it synchronously.
    let printed = same_as_oracle!(
        r#"
        const vm = require('vm');
        const sandbox = { out: '?' };
        vm.runInNewContext(
          'Promise.resolve().then(() => { globalThis.out = "ran"; });',
          sandbox);
        const atReturn = sandbox.out;
        queueMicrotask(() => {
          console.log(JSON.stringify({ atReturn, after: sandbox.out }));
        });
        "#
    );
    assert_eq!(printed, r#"{"atReturn":"?","after":"ran"}"#);
}
