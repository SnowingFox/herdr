//! Where the tick and microtask queues drain relative to libuv's phases.
//!
//! # The contract
//!
//! Node does not drain `process.nextTick` and V8's microtask queue between loop
//! iterations; it drains them at the end of *every* native-to-JavaScript
//! callback. That is `InternalCallbackScope::Close` (`src/api/callback.cc`), and
//! it is why a callback that queues a tick has it run before the loop advances
//! to the check phase:
//!
//! ```text
//! io-cb, microtask, setImmediate      (an fs.readFile callback)
//! io-cb, nextTick, setImmediate
//! connect-cb, tick, handle-close-cb   (a socket's own teardown)
//! ```
//!
//! rustnode used to drain only in `rn_io::Loop::tick`, after a whole
//! `uv_run(UV_RUN_ONCE)` iteration, so every one of those came out one phase
//! late — `io-cb, setImmediate, microtask`. Nothing hung and no callback was
//! lost, which is what made it silent: a program took a different branch rather
//! than failing.
//!
//! # Why these are byte-exact comparisons
//!
//! Every case below prints one `JSON` array from an `'exit'` handler and is
//! compared byte for byte against the pinned Node oracle. An ordering claim is
//! only meaningful as an equality, and a hand-written expectation would encode
//! whatever the author believed rather than what Node does.
//!
//! # Which reference binary
//!
//! [`rn_node_oracle`], like every other differential test here: the binary
//! `tools/node-pin.toml` pins, never whatever `node` resolves to on `PATH`. That
//! distinction is load-bearing for this file rather than tidiness. `PATH` on a
//! developer image is Node 22, the pin is Node 28, and the two disagree about one
//! thing these tests cover: an uncaught exception's already-queued work runs
//! *before* the check phase on v22 and after it on v28 —
//! `["io-cb","caught","tick","micro","immediate"]` against
//! `["io-cb","caught","immediate","tick","micro"]`. Comparing against `PATH`
//! would therefore assert the wrong order on any machine whose `node` happened to
//! be v22, which is exactly the defect `feb59b04` (#110) fixed for eighteen
//! other targets. A missing oracle skips this file loudly.

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// A script that records `out` and prints it from `'exit'`, so a stray early
/// `console.log` cannot stand in for the real order.
fn script(body: &str) -> String {
    format!(
        "const out = [];\n\
         process.on('exit', () => console.log(JSON.stringify(out)));\n\
         {body}"
    )
}

/// A file name no other test in this process uses.
///
/// The scripts are written to real files rather than passed with `-e` because
/// several of them pass `__filename` to `fs.readFile` to get a genuine poll-phase
/// completion, and `-e` has no `__filename`.
fn script_path() -> std::path::PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("rn-drain-{}-{n}.js", std::process::id()))
}

/// Runs `binary <script file>` and returns its trimmed stdout.
fn run(binary: &str, body: &str) -> String {
    let path = script_path();
    std::fs::write(&path, script(body)).expect("the script file is writable");
    let output = Command::new(binary)
        .arg(&path)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "{binary} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// The pinned oracle, resolved and announced once per test binary.
fn oracle() -> Option<&'static rn_node_oracle::Oracle> {
    static ORACLE: std::sync::OnceLock<Option<rn_node_oracle::Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-cli drain order"))
        .as_ref()
}

/// The reference binary for the comparisons, or `None` when there is no oracle.
fn reference() -> Option<&'static str> {
    oracle().map(|oracle| oracle.reference_path())
}

fn rustnode(body: &str) -> String {
    run(env!("CARGO_BIN_EXE_rustnode"), body)
}

/// Asserts rustnode matches the pinned oracle byte for byte.
///
/// Returns `None` when no oracle could be resolved, so a machine without the
/// pinned build skips loudly through the resolver's own announcement rather than
/// comparing against whatever `node` happens to be on `PATH`.
fn same_as_oracle(body: &str) -> Option<String> {
    let reference = reference()?;
    let expected = run(reference, body);
    let actual = rustnode(body);
    assert_eq!(actual, expected, "script was:\n{body}");
    Some(actual)
}

/// [`same_as_oracle`], as a statement in a test body.
///
/// A test that cannot resolve the pinned oracle returns instead of asserting,
/// which is the skip [`rn_node_oracle::require_oracle`] already announced. This
/// is a macro rather than a `let ... else` at every call site because the bodies
/// are multi-line raw strings and the early return belongs to the helper's
/// contract, not to each test.
macro_rules! same_as_oracle {
    ($body:expr $(,)?) => {
        match same_as_oracle($body) {
            Some(printed) => printed,
            None => return,
        }
    };
}

#[test]
fn a_microtask_queued_by_an_io_callback_runs_before_the_check_phase() {
    // The first sequence from the finding. `fs.readFile` completes in the poll
    // phase, so the queue it belongs to is checked before `setImmediate` in the
    // check phase — but only if the drain happens at the callback boundary.
    let printed = same_as_oracle!(
        "const fs = require('fs');\n\
         fs.readFile(__filename, () => {\n\
           out.push('io-cb');\n\
           queueMicrotask(() => out.push('microtask'));\n\
           setImmediate(() => out.push('setImmediate'));\n\
         });",
    );
    assert_eq!(printed, r#"["io-cb","microtask","setImmediate"]"#);
}

#[test]
fn a_next_tick_queued_by_an_io_callback_runs_before_the_check_phase() {
    // The second sequence. The tick queue is checked before V8's microtask queue
    // and both are checked before the phase advances.
    let printed = same_as_oracle!(
        "const fs = require('fs');\n\
         fs.readFile(__filename, () => {\n\
           out.push('io-cb');\n\
           process.nextTick(() => out.push('nextTick'));\n\
           setImmediate(() => out.push('setImmediate'));\n\
         });",
    );
    assert_eq!(printed, r#"["io-cb","nextTick","setImmediate"]"#);
}

#[test]
fn a_sockets_close_runs_after_the_tick_its_connect_handler_queued() {
    // The third sequence, and the one that bites real code: `lib/net.js` routes
    // a destroy through `process.nextTick(emitErrorCloseNT, ...)`, so a handle
    // close delivered before that tick emits `'close'` before the socket's own
    // teardown step. Before the fix this printed
    // `["connect-cb","handle-close-cb","tick"]`.
    let printed = same_as_oracle!(
        "const net = require('net');\n\
         const server = net.createServer((s) => s.end());\n\
         server.listen(0, '127.0.0.1', () => {\n\
           const socket = net.connect(server.address().port, '127.0.0.1');\n\
           socket.on('connect', () => {\n\
             out.push('connect-cb');\n\
             process.nextTick(() => out.push('tick'));\n\
             socket.destroy();\n\
           });\n\
           socket.on('close', () => {\n\
             out.push('handle-close-cb');\n\
             server.close();\n\
           });\n\
         });",
    );
    assert_eq!(
        printed, r#"["connect-cb","tick","handle-close-cb"]"#,
        "the socket's own tick must win over the handle close"
    );
}

#[test]
fn a_timer_callback_drains_both_queues_before_the_check_phase() {
    // The timer phase is last in an iteration, so this order was already right
    // before the fix — it is here because the fix moved the drain and a timer is
    // the phase most likely to regress.
    let printed = same_as_oracle!(
        "setTimeout(() => {\n\
           out.push('timer-cb');\n\
           process.nextTick(() => out.push('nextTick'));\n\
           queueMicrotask(() => out.push('microtask'));\n\
           setImmediate(() => out.push('setImmediate'));\n\
         }, 1);",
    );
    assert_eq!(
        printed,
        r#"["timer-cb","nextTick","microtask","setImmediate"]"#
    );
}

#[test]
fn a_promise_callback_from_an_io_callback_beats_a_later_timer() {
    // Promises and immediates, with a timer behind both. The `.then` must come
    // from the same callback boundary, so it precedes the check phase and
    // therefore the 1ms timer.
    let printed = same_as_oracle!(
        "const fs = require('fs');\n\
         fs.readFile(__filename, () => {\n\
           out.push('io-cb');\n\
           Promise.resolve().then(() => out.push('then'));\n\
           setImmediate(() => out.push('setImmediate'));\n\
           setTimeout(() => out.push('timer'), 1);\n\
         });",
    );
    assert_eq!(printed, r#"["io-cb","then","setImmediate","timer"]"#);
}

#[test]
fn a_tick_that_queues_another_tick_drains_to_exhaustion() {
    // The drain is a loop, not a single pass: a tick that queues a tick and a
    // microtask must have all of them run before the check phase. A
    // one-pass implementation would emit `tick1, immediate, tick2, micro`.
    let printed = same_as_oracle!(
        "const fs = require('fs');\n\
         fs.readFile(__filename, () => {\n\
           out.push('io-cb');\n\
           process.nextTick(() => {\n\
             out.push('tick1');\n\
             process.nextTick(() => out.push('tick2'));\n\
             queueMicrotask(() => out.push('micro'));\n\
           });\n\
           setImmediate(() => out.push('immediate'));\n\
         });",
    );
    assert_eq!(printed, r#"["io-cb","tick1","tick2","micro","immediate"]"#);
}

#[test]
fn two_timers_in_one_list_drain_between_their_callbacks() {
    // `listOnTimeout` calls `runNextTicks()` before each timer after the first,
    // so a tick queued by `t1` runs before `t2` rather than after the whole
    // list. This is JavaScript-side and was already correct; it guards the
    // checkpoint against running too eagerly and reordering the list.
    let printed = same_as_oracle!(
        "setTimeout(() => {\n\
           out.push('t1');\n\
           process.nextTick(() => out.push('tick'));\n\
         }, 1);\n\
         setTimeout(() => out.push('t2'), 1);",
    );
    assert_eq!(printed, r#"["t1","tick","t2"]"#);
}

#[test]
fn two_immediates_in_one_phase_drain_between_their_callbacks() {
    // The same rule on the check phase, which is the phase the ticket's first
    // two sequences are ordered against.
    let printed = same_as_oracle!(
        "setImmediate(() => {\n\
           out.push('i1');\n\
           process.nextTick(() => out.push('tick'));\n\
         });\n\
         setImmediate(() => out.push('i2'));",
    );
    assert_eq!(printed, r#"["i1","tick","i2"]"#);
}

#[test]
fn a_handled_throw_skips_the_checkpoint_but_the_next_callback_still_drains() {
    // `InternalCallbackScope::Close` returns at `if (failed_) return;`, so a
    // callback that threw does not drain: the report wins, and the queues it
    // left run from the next callback boundary. The `'exit'` order here is v28's.
    let printed = same_as_oracle!(
        "const fs = require('fs');\n\
         process.on('uncaughtException', () => out.push('caught'));\n\
         fs.readFile(__filename, () => {\n\
           out.push('io-cb');\n\
           process.nextTick(() => out.push('tick'));\n\
           queueMicrotask(() => out.push('micro'));\n\
           setImmediate(() => out.push('immediate'));\n\
           throw new Error('boom');\n\
         });",
    );
    assert_eq!(
        printed.as_str(),
        r#"["io-cb","caught","immediate","tick","micro"]"#
    );
    assert!(!printed.is_empty());
}

#[test]
fn a_throwing_timer_still_drains_its_own_queues() {
    // `RunTimers` is a plain `InternalCallbackScope`, not a
    // `InternalMakeCallback`, so `Close` drains even though `processTimers`
    // threw — the throw was already handed to `_fatalException` by the handle's
    // own `TryCatchScope`. This is the one callback path where the failure flag
    // must be cleared rather than honoured.
    let _printed = same_as_oracle!(
        "process.on('uncaughtException', () => out.push('caught'));\n\
         setTimeout(() => {\n\
           out.push('timer-cb');\n\
           process.nextTick(() => out.push('tick'));\n\
           queueMicrotask(() => out.push('micro'));\n\
           setImmediate(() => out.push('immediate'));\n\
           throw new Error('boom');\n\
         }, 1);",
    );
    assert_eq!(
        _printed.as_str(),
        r#"["timer-cb","caught","tick","micro","immediate"]"#
    );
}

#[test]
fn a_throwing_immediate_does_not_stop_its_siblings() {
    // `CheckImmediate` retries `processImmediate` while `has_outstanding()` is
    // set, so a throw that ended the call early leaves the sibling immediates to
    // run in this same phase instead of the next one.
    let _printed = same_as_oracle!(
        "process.on('uncaughtException', () => out.push('caught'));\n\
         setImmediate(() => {\n\
           out.push('immediate-cb');\n\
           process.nextTick(() => out.push('tick'));\n\
           queueMicrotask(() => out.push('micro'));\n\
           throw new Error('boom');\n\
         });\n\
         setImmediate(() => out.push('sibling'));",
    );
    assert_eq!(
        _printed.as_str(),
        r#"["immediate-cb","caught","sibling","tick","micro"]"#
    );
}

#[test]
fn a_throwing_tick_does_not_stop_the_tick_queue() {
    // `processTicksAndRejections` catches a throwing tick, emits `after` and
    // `destroy`, and continues with the queue. The next tick runs before the
    // loop advances, which is what keeps the two halves of the drain symmetric.
    let _printed = same_as_oracle!(
        "process.on('uncaughtException', () => out.push('caught'));\n\
         process.nextTick(() => {\n\
           out.push('tick-cb');\n\
           process.nextTick(() => out.push('tick2'));\n\
           queueMicrotask(() => out.push('micro'));\n\
           throw new Error('boom');\n\
         });\n\
         setImmediate(() => out.push('immediate'));",
    );
    assert_eq!(
        _printed.as_str(),
        r#"["tick-cb","caught","immediate","tick2","micro"]"#
    );
}

#[test]
fn async_hooks_sees_the_drained_queues_in_order() {
    // The `before` hooks are what a real tracing program reads, and they are
    // ordered by the same drain: `Timeout`, then the `TickObject` and
    // `Microtask` the timer queued, then the `Immediate` of the check phase.
    // Before the fix this sequence was unchanged for a timer (the timer phase is
    // last), which is why the same case over an I/O callback is the one that
    // regresses — see the test after this one.
    let printed = same_as_oracle!(
        "const async_hooks = require('async_hooks');\n\
         const ids = new Map();\n\
         async_hooks.createHook({\n\
           init(id, type) { ids.set(id, type); },\n\
           before(id) {\n\
             const t = ids.get(id);\n\
             if (t === 'TickObject' || t === 'Microtask' || t === 'Immediate' || t === 'Timeout')\n\
               out.push('before:' + t);\n\
           },\n\
         }).enable();\n\
         setTimeout(() => {\n\
           out.push('timer-cb');\n\
           process.nextTick(() => out.push('nextTick'));\n\
           queueMicrotask(() => out.push('microtask'));\n\
           setImmediate(() => out.push('setImmediate'));\n\
         }, 1);",
    );
    assert_eq!(
        printed,
        r#"["before:Timeout","timer-cb","before:TickObject","nextTick","before:Microtask","microtask","before:Immediate","setImmediate"]"#
    );
}

#[test]
fn async_hooks_orders_an_io_callback_hooks_before_the_check_phase() {
    // The async_hooks shape of the ticket: the `TickObject` created by the
    // `fs.readFile` callback must fire its `before` hook before the `Immediate`
    // that callback queued. Before the fix the `Immediate` came first, which is
    // the same divergence as the plain-JSON cases observed through tracing.
    //
    // The `FSREQCALLBACK` wrap's own `before` hook is excluded: the finding's
    // scope is the drain, and rustnode does not yet emit a `before` hook for
    // that wrap at all (a separate, pre-existing gap in the async-wrap
    // installation — its absence is visible on the unfixed binary too, and the
    // `close` ordering the ticket cares about is unaffected by it).
    let printed = same_as_oracle!(
        "const fs = require('fs');\n\
         const async_hooks = require('async_hooks');\n\
         const ids = new Map();\n\
         async_hooks.createHook({\n\
           init(id, type) { ids.set(id, type); },\n\
           before(id) {\n\
             const t = ids.get(id);\n\
             if (t === 'TickObject' || t === 'Microtask' || t === 'Immediate')\n\
               out.push('before:' + t);\n\
           },\n\
         }).enable();\n\
         fs.readFile(__filename, () => {\n\
           out.push('io-cb');\n\
           process.nextTick(() => out.push('nextTick'));\n\
           queueMicrotask(() => out.push('microtask'));\n\
           setImmediate(() => out.push('setImmediate'));\n\
         });",
    );
    assert_eq!(
        printed,
        r#"["io-cb","before:TickObject","nextTick","before:Microtask","microtask","before:Immediate","setImmediate"]"#
    );
}

#[test]
fn a_connect_refused_by_a_closed_port_reports_the_error_before_the_close() {
    // The observable consequence the finding names for `net`: `lib/net.js`
    // routes a failed connect through `process.nextTick(emitErrorCloseNT, ...)`,
    // so a handle close delivered before that tick emits `'close'` first. This
    // is the five-line program a user would write to notice the defect.
    let printed = same_as_oracle!(
        "const net = require('net');\n\
         const server = net.createServer();\n\
         server.listen(0, '127.0.0.1', () => {\n\
           const port = server.address().port;\n\
           server.close(() => {\n\
             const socket = net.connect(port, '127.0.0.1');\n\
             socket.on('error', (e) => out.push('error:' + e.code));\n\
             socket.on('close', () => out.push('close'));\n\
           });\n\
         });",
    );
    assert_eq!(printed, r#"["error:ECONNREFUSED","close"]"#);
}

#[test]
fn a_tick_chain_queued_by_an_io_callback_starves_the_loop_until_it_ends() {
    // `processTicksAndRejections` loops until the queue is empty, and a tick
    // that re-queues itself therefore keeps the check phase from running at all.
    // This is the case that catches a checkpoint implemented as "one pass over
    // the queue": `setImmediate` would appear in the middle of the chain.
    let printed = same_as_oracle!(
        "const fs = require('fs');\n\
         fs.readFile(__filename, () => {\n\
           out.push('io');\n\
           let n = 0;\n\
           process.nextTick(function again() {\n\
             if (++n < 500) process.nextTick(again);\n\
             else out.push('ticks=' + n);\n\
           });\n\
           setImmediate(() => out.push('immediate'));\n\
         });",
    );
    assert_eq!(printed, r#"["io","ticks=500","immediate"]"#);
}

#[test]
fn a_synchronous_native_call_inside_a_callback_does_not_drain() {
    // The checkpoint belongs at the boundary where control returns to the loop,
    // so a native binding called *from* JavaScript — `fs.readFileSync` here, plus
    // a `Buffer` allocation — must not drain, even though it opens a callback
    // scope of its own. Draining there would run the ticks in the middle of the
    // JavaScript stack that is still executing.
    let printed = same_as_oracle!(
        "const fs = require('fs');\n\
         fs.readFile(__filename, () => {\n\
           out.push('io-cb');\n\
           fs.readFileSync(__filename);\n\
           Buffer.alloc(16).fill(1);\n\
           process.nextTick(() => out.push('tick'));\n\
           queueMicrotask(() => out.push('micro'));\n\
           setImmediate(() => out.push('immediate'));\n\
         });",
    );
    assert_eq!(printed, r#"["io-cb","tick","micro","immediate"]"#);
}

#[test]
fn the_checkpoint_holds_inside_a_worker_thread() {
    // A worker has its own isolate, loop and thread-local checkpoint state, so
    // the same ordering has to hold there and must not be answered from the
    // main thread's registration. `postMessage` is the only channel that can
    // carry the order out of the worker, so this script is written verbatim
    // rather than through `script()`'s exit-handler wrapper.
    let body = "const { Worker, isMainThread, parentPort } = require('worker_threads');\n\
                if (isMainThread) {\n\
                  new Worker(__filename).on('message', (m) => console.log(JSON.stringify(m)));\n\
                } else {\n\
                  const fs = require('fs');\n\
                  const out = [];\n\
                  fs.readFile(__filename, () => {\n\
                    out.push('io-cb');\n\
                    process.nextTick(() => out.push('tick'));\n\
                    queueMicrotask(() => out.push('micro'));\n\
                    setImmediate(() => { out.push('immediate'); parentPort.postMessage(out); });\n\
                  });\n\
                }";
    let Some(reference) = reference() else {
        return;
    };
    let expected = run_verbatim(reference, body);
    let actual = run_verbatim(env!("CARGO_BIN_EXE_rustnode"), body);
    // rustnode's worker bootstrap emits one `WARN rn_bind_inspector: the
    // inspector namespace was installed without an isolate` line on *stdout*
    // before any JavaScript runs. That is pre-existing and unrelated — the
    // baseline binary prints it too — but it is a real defect of its own (a
    // program's stdout is polluted), so the assertion drops exactly that shape
    // rather than loosening the comparison.
    let actual = strip_tracing(&actual);
    assert_eq!(actual, expected);
    assert_eq!(actual, r#"["io-cb","tick","micro","immediate"]"#);
}

/// Drops tracing-format lines (`<rfc3339 timestamp>  LEVEL target: message`).
fn strip_tracing(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|line| {
            let is_warn = line.contains(" WARN ") || line.contains(" ERROR ");
            let starts_with_timestamp = line
                .split_once(' ')
                .is_some_and(|(first, _)| first.len() == 27 && first.ends_with('Z'));
            !(is_warn && starts_with_timestamp)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Runs `source` as a script file, with no wrapper around it.
fn run_verbatim(binary: &str, source: &str) -> String {
    let path = script_path();
    std::fs::write(&path, source).expect("the script file is writable");
    let output = Command::new(binary)
        .arg(&path)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "{binary} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}
