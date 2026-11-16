//! Every `process` property `internal/bootstrap/node.js` assigns must exist.
//!
//! `rn-realm` cannot run `internal/bootstrap/node.js`, so it reproduces the
//! module's `process` assignments by hand. A hand-maintained copy of an upstream
//! list drifts: `_kill` was missing, which made `process.kill()` — including the
//! `process.kill(pid, 0)` liveness probe — throw `TypeError: process._kill is not
//! a function`, and `_getActiveRequests`, `_getActiveHandles`,
//! `getActiveResourcesInfo`, `constrainedMemory`, `availableMemory`, `ref`,
//! `unref`, `openStdin`, `finalization` and `allowedNodeEnvironmentFlags` were
//! missing with it.
//!
//! Each case names the property and the shape Node reports, so the table below is
//! a transcription of `node.js` rather than of what rustnode happens to do. It
//! runs the built binary because these properties only exist inside a live
//! isolate.

use std::process::Command;

/// Runs `source` under the built binary and returns `(code, stdout, stderr)`.
fn run(source: &str) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["-e", source])
        .output()
        .expect("rustnode runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn expect(source: &str, expected: &str) {
    let (code, stdout, stderr) = run(source);
    assert_eq!(
        stdout.trim(),
        expected,
        "script exited {code}, stderr: {stderr}"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
}

/// `internal/bootstrap/node.js:157-167`, assigned straight from `rawMethods`.
///
/// ```js
/// process.dlopen = rawMethods.dlopen;
/// process.uptime = rawMethods.uptime;
/// process._getActiveRequests = rawMethods._getActiveRequests;
/// process._getActiveHandles = rawMethods._getActiveHandles;
/// process.getActiveResourcesInfo = rawMethods.getActiveResourcesInfo;
/// process.reallyExit = rawMethods.reallyExit;
/// process._kill = rawMethods._kill;
/// ```
#[test]
fn the_raw_methods_block_is_installed() {
    for name in [
        "dlopen",
        "uptime",
        "_getActiveRequests",
        "_getActiveHandles",
        "getActiveResourcesInfo",
        "reallyExit",
        "_kill",
    ] {
        expect(&format!("console.log(typeof process.{name})"), "function");
    }
}

/// `internal/bootstrap/node.js:170-181`, through `wrapProcessMethods` and
/// `perThreadSetup`.
#[test]
fn the_per_thread_block_is_installed() {
    for name in [
        "loadEnvFile",
        "_rawDebug",
        "cpuUsage",
        "threadCpuUsage",
        "resourceUsage",
        "memoryUsage",
        "constrainedMemory",
        "availableMemory",
        "kill",
        "exit",
        "execve",
        "ref",
        "unref",
        "hrtime",
    ] {
        expect(&format!("console.log(typeof process.{name})"), "function");
    }
}

/// `process.kill(pid, 0)` is the liveness probe every supervising program uses,
/// and it reaches libc only through `process._kill`. Before the fix this threw.
#[test]
fn process_kill_can_probe_liveness() {
    expect("console.log(process.kill(process.pid, 0))", "true");
}

/// A signal actually delivered through `process.kill` reaches a handler. A timer
/// holds the loop open, because signal delivery is asynchronous: without it the
/// process exits before the handler runs, which is what Node does too.
#[test]
fn process_kill_delivers_a_signal() {
    expect(
        "process.on('SIGUSR2', () => { console.log('handled'); }); \
         const t = setTimeout(() => console.log('timeout'), 2000); \
         process.on('SIGUSR2', () => { clearTimeout(t); }); \
         process.kill(process.pid, 'SIGUSR2');",
        "handled",
    );
}

/// `process.ref()` and `process.unref()` must reach the process' handle rather
/// than being absent. Calling `ref` is the cheap proof they are callable; an
/// undefined value throws.
#[test]
fn process_ref_and_unref_are_callable() {
    expect("process.ref(); process.unref(); console.log('ok')", "ok");
}

/// `internal/bootstrap/node.js:204,207` — `openStdin` returns `process.stdin`
/// after resuming it.
#[test]
fn open_stdin_returns_stdin() {
    expect(
        "console.log(process.openStdin() === process.stdin, process.stdin.isPaused())",
        "true false",
    );
}

/// `internal/bootstrap/node.js:245-263`. The accessor is observable through
/// `getOwnPropertyDescriptor`, and its getter replaces itself with a data
/// property on first read, exactly as Node's does.
#[test]
fn allowed_node_environment_flags_is_a_set_behind_an_accessor() {
    expect(
        "const before = Object.getOwnPropertyDescriptor(process, 'allowedNodeEnvironmentFlags'); \
         const flags = process.allowedNodeEnvironmentFlags; \
         const after = Object.getOwnPropertyDescriptor(process, 'allowedNodeEnvironmentFlags'); \
         console.log(flags instanceof Set, before.enumerable, before.configurable, \
                     typeof before.get, typeof after.get, flags.has('--trace-warnings'));",
        "true true true function undefined true",
    );
}

/// `internal/bootstrap/node.js:185-202`. `finalization` is an accessor with a
/// getter and a setter, so it reports `enumerable`/`configurable` but no
/// `writable` — a data property would report `writable`. That distinction is what
/// makes a replacement possible, which is how a test that stubs it works.
#[test]
fn finalization_is_an_accessor_over_the_registry_holder() {
    expect(
        "const d = Object.getOwnPropertyDescriptor(process, 'finalization'); \
         console.log(typeof process.finalization, d.enumerable, d.configurable, \
                     typeof d.get, typeof d.set); \
         process.finalization = 'replaced'; \
         console.log(process.finalization);",
        "object true true function function\nreplaced",
    );
}

/// `internal/bootstrap/node.js:356,419` — the two methods assigned outside the
/// per-thread block that are not accessors.
#[test]
fn emit_warning_and_get_builtin_module_are_installed() {
    expect(
        "console.log(typeof process.emitWarning, typeof process.getBuiltinModule)",
        "function function",
    );
}
