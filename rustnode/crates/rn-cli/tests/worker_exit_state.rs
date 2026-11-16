//! `process.exitCode` and `process._exiting` are per environment, not per
//! process.
//!
//! Node keeps both on `node::Environment` (`Environment::exit_code()` and the
//! private-symbol fields `internal/bootstrap/node.js:92-129` defines), so a
//! worker's exit status is the worker's own. `#143` moved them onto a
//! process-wide `static`, which made a worker's exit code the parent's:
//!
//! ```text
//! $ rustnode -e 'const {Worker}=require("worker_threads");
//!   const w=new Worker("throw new Error(\"x\")",{eval:true});
//!   w.on("error",()=>{}); w.on("exit",c=>console.log("worker exit",c));
//!   console.log("main exitCode", process.exitCode);'
//! worker exit 1 main exitCode 1     <- the defect; Node prints `undefined`
//! ```
//!
//! and because the parent's `_exiting` was set by the worker's exit, the
//! parent's own `exit` handlers stopped running. Both are asserted here from a
//! user program, and each expectation is the pinned oracle's answer rather than
//! a description of this code.
//!
//! The Rust half of the same property — that two threads do not share the
//! value — is `rn_core::exit_state`'s own `another_thread_does_not_see_this_
//! environments_state`, which fails on the old shape without needing a binary.

use std::process::Command;

/// Runs `source` under `binary` and returns `(code, stdout, stderr)`.
fn run(binary: &str, source: &str) -> (i32, String, String) {
    let output = Command::new(binary)
        .arg("-e")
        .arg(source)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The pinned oracle, or `None` when there is none.
fn oracle() -> Option<&'static rn_node_oracle::Oracle> {
    static ORACLE: std::sync::OnceLock<Option<rn_node_oracle::Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-cli worker exit state"))
        .as_ref()
}

/// Asserts rustnode's stdout and exit status are the oracle's, byte for byte.
///
/// The status is part of the comparison, not just the output: the whole defect
/// was a *process* exiting with its worker's code while printing everything a
/// correct run prints. A test that compared stdout alone would have passed on
/// the broken build.
fn same_as_oracle(source: &str) -> Option<(i32, String)> {
    let reference = oracle()?.reference_path();
    let (expected_code, expected_stdout, _) = run(reference, source);
    let (code, stdout, stderr) = run(env!("CARGO_BIN_EXE_rustnode"), source);
    assert_eq!(
        (code, stdout.as_str()),
        (expected_code, expected_stdout.as_str()),
        "script was:\n{source}\nrustnode stderr: {stderr}"
    );
    Some((code, stdout))
}

/// Runs `source` under rustnode alone and asserts its `(code, stdout)`.
///
/// Used where the assertion is about rustnode reaching a state the oracle cannot
/// be asked about directly (a nested worker, a value read from the parent after a
/// worker has already exited), so the expectation is written out and justified in
/// the test rather than derived.
fn expect_rustnode(source: &str, expected_code: i32, expected_stdout: &str) {
    let (code, stdout, stderr) = run(env!("CARGO_BIN_EXE_rustnode"), source);
    assert_eq!(
        (code, stdout.as_str()),
        (expected_code, expected_stdout),
        "script was:\n{source}\nrustnode stderr: {stderr}"
    );
}

#[test]
fn a_worker_that_exits_non_zero_does_not_set_the_parents_exit_code() {
    let Some((code, printed)) = same_as_oracle(
        "const { Worker } = require('worker_threads');\n\
         const w = new Worker('throw new Error(\"x\")', { eval: true });\n\
         w.on('error', () => {});\n\
         w.on('exit', (c) => console.log('worker exit', c, 'main', process.exitCode));",
    ) else {
        return;
    };
    // Node: `worker exit 1 main undefined`, status 0. The defect printed `main
    // 1` and exited 1, because the worker's code was written to the process-wide
    // field the parent's exit path then read.
    assert_eq!(printed.trim(), "worker exit 1 main undefined");
    assert_eq!(code, 0, "the parent must keep its own status");
}

#[test]
fn a_worker_that_sets_its_own_exit_code_exits_the_worker_with_it() {
    let Some((code, printed)) = same_as_oracle(
        "const { Worker } = require('worker_threads');\n\
         const w = new Worker('process.exitCode = 1;', { eval: true });\n\
         w.on('exit', (c) => console.log('worker exit', c, 'main', process.exitCode));",
    ) else {
        return;
    };
    // The worker's `exitCode` still decides the worker's status, which is the
    // half of the old behaviour that was right and must survive the split.
    assert_eq!(printed.trim(), "worker exit 1 main undefined");
    assert_eq!(code, 0);
}

#[test]
fn the_parents_exit_handlers_run_after_a_worker_has_exited() {
    let Some((code, printed)) = same_as_oracle(
        "const { Worker } = require('worker_threads');\n\
         const w = new Worker('throw new Error(\"x\")', { eval: true });\n\
         w.on('error', () => {});\n\
         w.on('exit', () => console.log('worker exited'));\n\
         process.on('exit', (c) => console.log('parent exit', c, process._exiting));",
    ) else {
        return;
    };
    // This is the second half of the defect: the worker's exit set the shared
    // `_exiting`, so the parent's own `exit` emit was suppressed as if it had
    // already run. `test-worker-uncaught-exception.js` asserts exactly this
    // ("Exit callback called twice in worker") and failed because of it.
    assert_eq!(
        printed.trim(),
        "worker exited\nparent exit 0 true",
        "the parent's exit sequence must run, and be marked as having run"
    );
    assert_eq!(code, 0);
}

#[test]
fn a_workers_process_exit_reports_its_code_and_a_second_call_is_a_no_op() {
    let Some((code, printed)) = same_as_oracle(
        "const { Worker } = require('worker_threads');\n\
         const w = new Worker(\n\
           'process.exit(42); process.exit(7);', { eval: true });\n\
         w.on('exit', (c) => {\n\
           console.log('worker exit', c);\n\
           process.on('exit', () => console.log('parent exit handler ran'));\n\
         });",
    ) else {
        return;
    };
    // 42 rather than 7: `per_thread.js`'s `exit` checks `process._exiting` before
    // emitting and before `reallyExit`, so the second call must not overwrite the
    // first. On the process-wide field a worker's second call *was* suppressed
    // too, so this alone would not have caught the defect — the pair below it is
    // what proves the flag is scoped to the worker.
    assert_eq!(printed.trim(), "worker exit 42\nparent exit handler ran");
    assert_eq!(code, 0);
}

#[test]
fn a_workers_exit_does_not_make_a_later_parent_process_exit_a_no_op() {
    // The scoping check that the second-call test cannot make: the parent calls
    // `process.exit()` only *after* a worker has exited, so its `_exiting` must
    // still be false and its handlers must run. With one shared field the worker
    // had already set it, `exit` was skipped, and the process terminated with the
    // code the worker left behind.
    expect_rustnode(
        "const { Worker } = require('worker_threads');\n\
         const w = new Worker('process.exit(3);', { eval: true });\n\
         w.on('exit', () => {\n\
           process.on('exit', (c) => console.log('parent handler', c));\n\
           process.exit(0);\n\
         });",
        0,
        "parent handler 0\n",
    );
}

#[test]
fn two_workers_have_independent_exit_codes() {
    // One worker cannot see the other's, which is the same property one level
    // down: the state belongs to a thread, not to the worker subsystem.
    expect_rustnode(
        "const { Worker } = require('worker_threads');\n\
         const codes = [];\n\
         let done = 0;\n\
         for (const body of ['process.exitCode = 1;', 'process.exitCode = 2;']) {\n\
           const w = new Worker(body, { eval: true });\n\
           w.on('exit', (c) => {\n\
             codes.push(c);\n\
             if (++done === 2) console.log(codes.sort().join(','), process.exitCode);\n\
           });\n\
         }",
        0,
        "1,2 undefined\n",
    );
}
