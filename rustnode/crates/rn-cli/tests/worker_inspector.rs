//! Differential checks for the worker-side inspector and for the diagnostics
//! channel the runtime writes on.
//!
//! Two defects were measurable from a user program, and each one is a divergence
//! from the pinned Node 28 nightly (`tools/node-pin.toml`) rather than a stylistic
//! preference:
//!
//! 1. `new inspector.Session(); session.connect()` inside a `Worker` threw
//!    `The inspector is not available: no isolate was recorded`. Node's inspector
//!    is one `V8Inspector` per isolate, so a worker's own bootstrap has to record
//!    its own isolate; it did not, so `ensure_inspector` had nothing to create
//!    against.
//! 2. Every `new Worker(...)` wrote a `tracing` warning to the *program's stdout*,
//!    because the subscriber had no writer (which defaults to stdout) and the
//!    default filter was `warn`. A program printing JSON was corrupted, and
//!    `rustnode app.js | jq .` failed.
//!
//! Every expected string below was measured on the oracle and then compared with
//! the built `rustnode` binary. Where a test can defer to the oracle it does, so
//! the expectation is Node's own output rather than a description of this code.
//!
//! These run the built binary because both defects are only visible from outside
//! it: an error thrown out of `Session.connect`, and the bytes a process writes to
//! its stdout.

use std::process::Command;

/// Runs `source` under `binary` with `--expose-internals` and returns
/// `(code, stdout, stderr)`.
fn run(binary: &str, source: &str) -> (i32, String, String) {
    let out = Command::new(binary)
        .args(["--expose-internals", "-e", source])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A file name no other test in this process uses.
fn script_path() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("rn-worker-inspector-{}-{n}.js", std::process::id()))
}

/// Runs `source` as a script *file* under `binary`, returning `(code, stdout,
/// stderr)`.
///
/// A file rather than `-e` because `__filename` is what lets a worker re-execute
/// the same script, and `-e` has no `__filename`.
fn run_file(binary: &str, source: &str) -> (i32, String, String) {
    let path = script_path();
    std::fs::write(&path, source).expect("the script file is writable");
    let out = Command::new(binary)
        .args(["--expose-internals"])
        .arg(&path)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    let _ = std::fs::remove_file(&path);
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The pinned oracle, or `None` when there is none.
fn oracle() -> Option<&'static rn_node_oracle::Oracle> {
    static ORACLE: std::sync::OnceLock<Option<rn_node_oracle::Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-cli worker inspector"))
        .as_ref()
}

/// Asserts `source` prints `expected` on stdout and exits 0 under rustnode.
fn expect(source: &str, expected: &str) {
    let (code, stdout, stderr) = run(env!("CARGO_BIN_EXE_rustnode"), source);
    assert_eq!(
        stdout.trim(),
        expected,
        "script exited {code}, stderr: {stderr}"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
}

/// Asserts rustnode's stdout and exit status are the oracle's, byte for byte.
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

/// An inline worker whose body is `body`, so the script needs no `__filename`.
fn worker_eval(body: &str) -> String {
    format!(
        "const {{ Worker }} = require('worker_threads');\n\
         const w = new Worker({body:?}, {{ eval: true }});\n\
         w.on('message', (m) => {{ console.log(m); }});"
    )
}

// ------------------------------------------------------ inspector in a worker --

#[test]
fn a_worker_opens_its_own_inspector_session_and_evaluates() {
    // The reported defect, in the reported shape: `new inspector.Session()`,
    // `connect()`, and `Runtime.evaluate('1+1')`. Before the worker recorded its
    // isolate this threw `The inspector is not available: no isolate was
    // recorded`, so the parent received nothing and the process exited 1.
    //
    // `evaluated 2` is the oracle's line: Node's inspector is per-isolate and a
    // worker has its own, which is why the expression is evaluated against the
    // worker's context rather than the main thread's.
    let source = "const { Worker } = require('worker_threads');\n\
                  const w = new Worker(`\n\
                    const { parentPort } = require('worker_threads');\n\
                    const inspector = require('inspector');\n\
                    const s = new inspector.Session();\n\
                    s.connect();\n\
                    s.post('Runtime.evaluate', { expression: '1+1' }, (err, res) => {\n\
                      parentPort.postMessage(err ? 'err ' + err.message\n\
                                                 : 'evaluated ' + res.result.value);\n\
                      s.disconnect();\n\
                    });\n\
                  `, { eval: true });\n\
                  w.on('message', (m) => { console.log('main got', m); w.terminate(); });";
    expect(source, "main got evaluated 2");
}

#[test]
fn two_workers_each_evaluate_in_their_own_context() {
    // A cheaper fix would have been to record the *main thread's* isolate on the
    // worker's thread, or to share one inspector between them. Both make
    // `Runtime.evaluate` answer from the wrong context or from an isolate that is
    // not the caller's, so the state each worker sees is what this asserts: a
    // global set inside worker N must read back as worker N's value.
    let source = "const { Worker, isMainThread, parentPort, workerData } = \
                    require('worker_threads');\n\
                  globalThis.whichIsolate = 'main';\n\
                  if (isMainThread) {\n\
                    const results = [];\n\
                    for (let i = 0; i < 2; i++) {\n\
                      const w = new Worker(__filename, { workerData: i });\n\
                      w.on('message', (m) => {\n\
                        results.push(m);\n\
                        if (results.length === 2) console.log(JSON.stringify(results.sort()));\n\
                      });\n\
                    }\n\
                  } else {\n\
                    globalThis.whichIsolate = 'worker' + workerData;\n\
                    const s = new (require('inspector').Session)();\n\
                    s.connect();\n\
                    s.post('Runtime.evaluate', { expression: 'globalThis.whichIsolate' },\n\
                           (err, res) => {\n\
                      parentPort.postMessage(err ? 'err ' + err.message : res.result.value);\n\
                      s.disconnect();\n\
                    });\n\
                  }";
    let reference = match oracle() {
        Some(oracle) => oracle.reference_path(),
        None => return,
    };
    let (expected_code, expected_stdout, expected_stderr) = run_file(reference, source);
    let (code, stdout, stderr) = run_file(env!("CARGO_BIN_EXE_rustnode"), source);
    assert_eq!(
        (code, stdout.as_str()),
        (expected_code, expected_stdout.as_str()),
        "rustnode stderr: {stderr}\noracle stderr: {expected_stderr}"
    );
    assert_eq!(stdout.trim(), r#"["worker0","worker1"]"#);
}

#[test]
fn the_main_thread_inspector_session_still_works() {
    // The working case this change must not break. `Session` on the main thread
    // connects to the isolate `main` recorded, and a fix that moved the
    // registration into the worker without keeping the main thread's would have
    // passed the two tests above and broken this one.
    expect(
        "const s = new (require('inspector').Session)();\n\
         s.connect();\n\
         s.post('Runtime.evaluate', { expression: '6*7' }, (err, res) => {\n\
           console.log(err ? 'err ' + err.message : 'evaluated ' + res.result.value);\n\
           s.disconnect();\n\
         });",
        "evaluated 42",
    );
}

// ------------------------------------------------ stdout belongs to the program --

#[test]
fn a_worker_starting_writes_nothing_to_the_program_stdout() {
    // The second defect, in the shape it was reported: `rustnode app.js | jq .`
    // failed because one tracing line preceded the JSON. The assertion is on the
    // exact bytes, so any runtime output on stdout fails here — not only the one
    // warning this change removed.
    let source = worker_eval(
        "const { parentPort } = require('worker_threads');\n\
                              parentPort.postMessage('hi');",
    );
    let (code, stdout, stderr) = run(env!("CARGO_BIN_EXE_rustnode"), &source);
    assert_eq!(
        stdout, "hi\n",
        "a worker's startup must not write to stdout; stderr was: {stderr}"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn json_from_a_worker_program_is_byte_identical_to_the_oracle() {
    // The end-to-end form of the same claim, against the oracle rather than a
    // hand-written string: a program that starts a worker and prints one JSON
    // object must produce the oracle's bytes. This is what `jq .` reads.
    let source = "const { Worker } = require('worker_threads');\n\
                  const w = new Worker(`\n\
                    const { parentPort } = require('worker_threads');\n\
                    parentPort.postMessage('hi');\n\
                  `, { eval: true });\n\
                  w.on('message', (m) => {\n\
                    console.log(JSON.stringify({ hello: 'world', value: 42, m }));\n\
                  });";
    let Some((_, stdout)) = same_as_oracle(source) else {
        return;
    };
    // The oracle's line, restated so the test says what it accepted rather than
    // only that the two binaries agreed.
    assert_eq!(stdout.trim(), r#"{"hello":"world","value":42,"m":"hi"}"#);
}

#[test]
fn neither_stream_carries_a_diagnostic_by_default() {
    // The stderr half of the decision. Moving the subscriber to stderr would have
    // left a warning on every worker start that the oracle does not print, so the
    // default filter is `off` and the oracle's empty stderr is the standard.
    //
    // Measured on the oracle: a program that starts a worker writes nothing to
    // either stream but its own `console.log`. `RUST_LOG` still opts in, which the
    // next test covers.
    let source = worker_eval(
        "const { parentPort } = require('worker_threads');\n\
                              parentPort.postMessage('started');",
    );
    let reference = match oracle() {
        Some(oracle) => oracle.reference_path(),
        None => return,
    };
    let (oracle_code, oracle_stdout, oracle_stderr) = run(reference, &source);
    let (code, stdout, stderr) = run(env!("CARGO_BIN_EXE_rustnode"), &source);
    assert_eq!(
        (code, stdout.as_str(), stderr.as_str()),
        (oracle_code, oracle_stdout.as_str(), oracle_stderr.as_str()),
        "a worker start must be as silent as the oracle's"
    );
    assert_eq!(
        stderr, "",
        "the runtime must print no diagnostic by default"
    );
}

#[test]
fn rust_log_turns_diagnostics_back_on_without_touching_stdout() {
    // The diagnostics are still reachable, which is what makes defaulting them off
    // an opt-out rather than a deletion. They go to stderr, so a caller that asked
    // for them sees them and the program's stdout is still its own.
    //
    // The target is `rn_bind_worker`, whose teardown emits a `debug!` on every
    // worker exit — a diagnostic that fires on exactly the code path this change
    // touches. The assertion is that asking for it puts it on stderr and leaves
    // stdout with nothing but the program's own line.
    let source = worker_eval(
        "const { parentPort } = require('worker_threads');\n\
                              parentPort.postMessage('started');",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .env("RUST_LOG", "rn_bind_worker=debug")
        .args(["--expose-internals", "-e", &source])
        .output()
        .expect("rustnode runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stdout, "started\n",
        "RUST_LOG must not send diagnostics to stdout; stderr: {stderr}"
    );
    assert!(
        stderr.contains("rn_bind_worker"),
        "RUST_LOG=rn_bind_worker=debug must reach stderr; stderr was: {stderr:?}"
    );
}
