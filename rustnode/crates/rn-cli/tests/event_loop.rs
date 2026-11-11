//! The event loop, checked against real `node` running the same script.
//!
//! Every expectation here is recorded from the `node` binary on the same
//! machine, not written by hand: the ordering rules that matter —
//! `process.nextTick` before a promise, a 0ms timer after both, an immediate
//! before a timer that is not yet due, `unref()` deciding exit — are exactly the
//! rules that look plausible when invented and are wrong when guessed.
//!
//! The tests spawn the real `rustnode` binary, because the whole point is that
//! the process runs the loop after the script body and then exits by itself.
//! An in-process test could not observe that.
//!
//! Where `node` may legitimately differ, the test says why. The one case is a
//! `setTimeout(f, 0)` racing a `setImmediate(g)` in the same turn: real `node`
//! prints `g` first about 19 times in 20 and `f` first the rest, so pinning
//! either order would be a flaky test rather than a stronger one.

use std::process::Command;

/// `node`'s result for `script`, if the reference binary is available.
fn node(script: &str) -> String {
    let output = Command::new("node")
        .arg("-e")
        .arg(script)
        .output()
        .expect("node must be on PATH to record the reference output");
    assert!(
        output.status.success(),
        "node failed on {script:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

/// `rustnode`'s result for `script`.
fn rustnode(script: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg(script)
        .output()
        .expect("rustnode runs");
    assert!(
        output.status.success(),
        "rustnode failed on {script:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

/// Asserts `rustnode` prints exactly what `node` prints.
fn same_as_node(script: &str) -> String {
    let expected = node(script);
    let actual = rustnode(script);
    assert_eq!(actual, expected, "script was: {script}");
    actual
}

#[test]
fn a_zero_timer_reports_after_a_microtask_and_before_exit() {
    // The ordering the issue names: the timer callback runs after the
    // microtask, and the process does not exit until it has run.
    let printed = same_as_node(
        "setTimeout(() => console.log('timeout'), 0);\n\
         queueMicrotask(() => console.log('microtask'));\n\
         console.log('sync');",
    );
    assert_eq!(printed, "sync\nmicrotask\ntimeout\n");
}

#[test]
fn a_then_callback_from_the_script_body_runs_before_the_process_exits() {
    // No timer and no tick here: if the loop did not drain V8's microtask queue
    // after the script, `resolved 1` would never appear.
    let printed = same_as_node(
        "Promise.resolve(1).then(v => console.log('resolved', v));\n\
         console.log('sync');",
    );
    assert_eq!(printed, "sync\nresolved 1\n");
}

#[test]
fn next_tick_runs_before_a_promise_and_before_a_timer() {
    // Node's documented order: the tick queue drains to exhaustion, then V8's
    // microtask queue, then the loop's timer phase. This is the case that a
    // default V8 microtask policy gets wrong, because it drains promises as soon
    // as the script's call depth drops.
    let printed = same_as_node(
        "setTimeout(() => console.log('timer'), 0);\n\
         queueMicrotask(() => console.log('microtask'));\n\
         process.nextTick(() => console.log('tick'));\n\
         Promise.resolve().then(() => console.log('then'));\n\
         console.log('sync');",
    );
    assert_eq!(printed, "sync\ntick\nmicrotask\nthen\ntimer\n");
}

#[test]
fn a_nested_timer_runs_after_the_sibling_scheduled_before_it() {
    // `a` schedules `c` while the 0ms list is being drained, so `c` cannot run in
    // the same pass: `b`, already in the list, must come first.
    let printed = same_as_node(
        "setTimeout(() => { console.log('a'); setTimeout(() => console.log('c'), 0); }, 0);\n\
         setTimeout(() => console.log('b'), 0);",
    );
    assert_eq!(printed, "a\nb\nc\n");
}

#[test]
fn an_interval_runs_until_it_clears_itself() {
    let printed = same_as_node(
        "let n = 0;\n\
         const id = setInterval(() => { console.log('tick', ++n); if (n === 3) clearInterval(id); }, 1);",
    );
    assert_eq!(printed, "tick 1\ntick 2\ntick 3\n");
}

#[test]
fn an_immediate_runs_after_the_poll_phase_and_before_a_later_timer() {
    // The immediate is queued for the check phase, which follows poll; the 20ms
    // timer is not due until the loop has waited, so the immediate wins even
    // though the timer was scheduled first.
    let printed = same_as_node(
        "setTimeout(() => console.log('timeout'), 20);\n\
         setImmediate(() => console.log('immediate'));",
    );
    assert_eq!(printed, "immediate\ntimeout\n");
}

#[test]
fn an_unrefed_timer_alone_does_not_keep_the_process_alive() {
    // `unref()` is the promise that a pending timer will not delay exit. The
    // process must exit without ever calling the callback.
    let printed = same_as_node(
        "setTimeout(() => console.log('never'), 1).unref();\n\
         console.log('done');",
    );
    assert_eq!(printed, "done\n");
}

#[test]
fn an_unrefed_deadline_still_fires_while_refed_work_keeps_the_loop_turning() {
    // The deadline is already due by the time the immediate finishes, so the
    // timer phase at the top of the next turn runs it. This is the other half of
    // `unref()`: it means "do not wait for me", not "never run me".
    //
    // The order of these two is deliberately not asserted. A 0ms timer and a
    // `setImmediate` race by definition — the timer fires in the next timer
    // phase, which is after the current poll phase, and a loaded scheduler can
    // put either first. Node's own documentation calls this order
    // non-deterministic. What this test is about is that the unref'd timer runs
    // *at all* while something else keeps the loop turning, so it compares the
    // set of lines both runtimes printed rather than their order.
    //
    // `same_as_node` is deliberately not used here: it asserts the two outputs
    // are byte-identical, which is exactly the race this test must not depend
    // on. It flaked under `cargo test --workspace` for that reason.
    let script = "setTimeout(() => console.log('timer'), 0).unref();\n\
                  setImmediate(() => console.log('immediate'));";
    let mut expected: Vec<String> = node(script).lines().map(str::to_string).collect();
    let mut actual: Vec<String> = rustnode(script).lines().map(str::to_string).collect();
    expected.sort_unstable();
    actual.sort_unstable();
    assert_eq!(
        actual, expected,
        "both runtimes must print the same set of lines, in any order"
    );
    assert_eq!(
        actual,
        ["immediate", "timer"],
        "the unref'd timer must still run while ref'd work keeps the loop turning"
    );
}

#[test]
fn an_unrefed_timer_that_is_not_due_before_the_last_turn_never_runs() {
    // With a 50ms deadline and one immediate, the loop has nothing left after the
    // immediate, so it must stop rather than wait the remaining milliseconds.
    // The margin is 50ms rather than 5ms on purpose: real `node` fires a 4ms
    // unref'd deadline next to an immediate and skips a 5ms one, so a small
    // timer here would be measuring scheduler latency rather than the rule.
    let printed = same_as_node(
        "setTimeout(() => console.log('timer'), 50).unref();\n\
         setImmediate(() => console.log('immediate'));",
    );
    assert_eq!(printed, "immediate\n");
}

#[test]
fn an_unrefed_interval_runs_only_while_other_work_keeps_the_loop_alive() {
    let printed = same_as_node(
        "let n = 0;\n\
         const id = setInterval(() => { if (++n < 3) console.log('tick', n); }, 1).unref();\n\
         setTimeout(() => console.log('ref done'), 10);",
    );
    assert_eq!(printed, "tick 1\ntick 2\nref done\n");
}

#[test]
fn an_interval_that_is_cleared_before_it_fires_does_not_keep_the_process_alive() {
    let printed = same_as_node(
        "const id = setInterval(() => console.log('nope'), 1);\n\
         clearInterval(id);\n\
         console.log('cleared');",
    );
    assert_eq!(printed, "cleared\n");
}

#[test]
fn an_immediate_that_is_cleared_does_not_keep_the_process_alive() {
    let printed = same_as_node(
        "const id = setImmediate(() => console.log('nope'));\n\
         clearImmediate(id);\n\
         console.log('cleared');",
    );
    assert_eq!(printed, "cleared\n");
}

#[test]
fn timer_arguments_are_forwarded_to_the_callback() {
    // `setTimeout(f, ms, ...args)` is how `lib/**` passes a callback's context,
    // and `internal/timers.js` stores `_timerArgs` for it. The two are asserted
    // separately because a 1ms timer and a queued immediate race, and which runs
    // first is not a rule either implementation promises.
    let printed = same_as_node("setTimeout((a, b) => console.log(a, b), 1, 'one', 2);");
    assert_eq!(printed, "one 2\n");

    let printed = same_as_node("setImmediate((a) => console.log('immediate', a), 'arg');");
    assert_eq!(printed, "immediate arg\n");
}

#[test]
fn a_throwing_timer_callback_exits_non_zero() {
    // Node prints the error and exits 1; it does not resume the loop. The exact
    // stack differs between the two binaries, so only the status and the error
    // identity are compared.
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg("setTimeout(() => { throw new Error('boom') }, 0); console.log('scheduled');")
        .output()
        .expect("rustnode runs");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stdout.trim(), "scheduled");
    assert!(stderr.contains("Error: boom"), "stderr was {stderr}");
}

#[test]
fn a_timer_measuring_its_own_delay_sees_at_least_what_it_asked_for() {
    // A `setTimeout(f, 30)` that fired early would break every retry and timeout
    // in `lib/**`. The lower bound is the only portable assertion: an upper bound
    // is a scheduling test, not a correctness one.
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg(
            "const start = Date.now();\n\
             setTimeout(() => console.log('slept', Date.now() - start >= 30), 30);",
        )
        .output()
        .expect("rustnode runs");
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "slept true");
}

#[test]
fn the_timer_globals_are_the_timers_module_exports() {
    // `lib/net.js` and `timers/promises` compare the global against the module
    // export, so they have to be the same function objects.
    let printed = same_as_node(
        "console.log(\n\
           setTimeout === require('timers').setTimeout,\n\
           setInterval === require('timers').setInterval,\n\
           setImmediate === require('timers').setImmediate,\n\
           clearTimeout === require('timers').clearTimeout,\n\
           clearInterval === require('timers').clearInterval,\n\
           clearImmediate === require('timers').clearImmediate);",
    );
    assert_eq!(printed, "true true true true true true\n");
}

#[test]
fn a_timer_id_can_be_passed_to_clear_timeout() {
    // `Timeout`'s `SymbolToPrimitive` registers the id in `knownTimersById`, so a
    // numeric id clears the timer. That path runs entirely through the binding's
    // `asyncId`, which is why it is worth pinning.
    let printed = same_as_node(
        "const id = setTimeout(() => console.log('nope'), 1);\n\
         clearTimeout(id[Symbol.toPrimitive]());\n\
         console.log('cleared');",
    );
    assert_eq!(printed, "cleared\n");
}

#[test]
fn next_tick_is_a_function_and_survives_a_timer_boundary() {
    // `dns.lookup` calls `process.nextTick` from inside a lookup callback, so a
    // tick queued from a timer must still run.
    let printed = same_as_node(
        "console.log(typeof process.nextTick);\n\
         setTimeout(() => process.nextTick(() => console.log('tick from timer')), 1);",
    );
    assert_eq!(printed, "function\ntick from timer\n");
}

#[test]
fn a_dns_lookup_callback_reaches_the_tick_queue() {
    // `dns.lookup` for a literal address resolves through `process.nextTick`,
    // which is the exact failure this loop had to fix: the lookup threw
    // `process.nextTick is not a function` before the task queue was installed.
    let printed = same_as_node(
        "const dns = require('dns');\n\
         dns.lookup('127.0.0.1', (error, address) => console.log(error ? 'error' : address));\n\
         console.log('scheduled');",
    );
    assert_eq!(printed, "scheduled\n127.0.0.1\n");
}

#[test]
fn two_dns_lookups_both_report() {
    // Two lookups in one script is the case that failed while the first one
    // worked: the second needs the tick queue to still be alive.
    let printed = same_as_node(
        "const dns = require('dns');\n\
         dns.lookup('::1', (error, address) => console.log('one', error ? 'error' : address));\n\
         dns.lookup('127.0.0.1', (error, address) => console.log('two', error ? 'error' : address));",
    );
    assert_eq!(printed, "one ::1\ntwo 127.0.0.1\n");
}

#[test]
fn a_script_that_sets_process_exit_code_still_exits_with_it() {
    // The loop runs before the exit status is read, so a rework of the CLI tail
    // could silently swallow `process.exitCode`. A timer that runs first proves
    // the loop did not overwrite it.
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg("process.exitCode = 3; setTimeout(() => console.log('ran'), 1);")
        .output()
        .expect("rustnode runs");
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ran");
}

#[test]
fn a_timer_created_inside_a_tick_runs_and_its_promise_drains() {
    // The tick drains to exhaustion first, so the timer it creates is scheduled
    // after the script's own promise. The promise inside the timer then drains
    // before the loop looks for more work.
    let printed = same_as_node(
        "process.nextTick(() => {\n\
           console.log('tick');\n\
           setTimeout(() => {\n\
             console.log('timer from tick');\n\
             Promise.resolve().then(() => console.log('then in timer'));\n\
           }, 0);\n\
         });\n\
         Promise.resolve().then(() => console.log('then in script'));\n\
         console.log('sync');",
    );
    assert_eq!(
        printed,
        "sync\ntick\nthen in script\ntimer from tick\nthen in timer\n"
    );
}

#[test]
fn an_interval_that_unrefs_itself_stops_keeping_the_process_alive() {
    // `unref()` from inside the callback must take effect for the next turn: the
    // process exits after the tick that unref'd, not after the following one.
    let printed = same_as_node(
        "let n = 0;\n\
         const id = setInterval(() => {\n\
           console.log('tick', ++n);\n\
           if (n === 2) id.unref();\n\
         }, 1);",
    );
    assert_eq!(printed, "tick 1\ntick 2\n");
}

#[test]
fn all_five_queues_drain_in_node_order_from_one_script() {
    // Ticks, promises, `queueMicrotask` callbacks, immediates and timers queued
    // in one script body: the microtask queues drain before the loop starts, then
    // the check phase, then the timer phase.
    //
    // The timer is 20ms rather than 0ms on purpose. A 0ms timer races the
    // immediate for the first turn — real `node` prints the immediate first about
    // 19 times in 20 and the timer first the rest — so asserting either order
    // would be a flaky test rather than a stricter one. At 20ms the timer cannot
    // be the first phase, which is the ordering this test is about.
    let printed = same_as_node(
        "console.log('a');\n\
         setTimeout(() => console.log('timer'), 20);\n\
         setImmediate(() => console.log('imm'));\n\
         process.nextTick(() => console.log('tick'));\n\
         Promise.resolve().then(() => console.log('then'));\n\
         queueMicrotask(() => console.log('micro'));\n\
         console.log('b');",
    );
    assert_eq!(printed, "a\nb\ntick\nthen\nmicro\nimm\ntimer\n");
}

#[test]
fn a_tcp_echo_round_trip_completes() {
    // The regression the libuv loop exists for. A `TCP` handle lives on libuv's
    // loop, so nothing about it works unless that loop is the one being pumped:
    // `listen()` reported a port because it is synchronous enough, but no accept
    // and no connect ever happened. Measured against real `node`, which prints
    // `got hi`.
    let printed = same_as_node(
        "const s=require('net').createServer(c=>{c.end('hi'); s.close()});\n\
         s.listen(0,()=>{const p=s.address().port;\n\
           const c=net.connect(p,()=>{});\n\
           c.on('data',d=>{console.log('got',d.toString()); c.end()})});",
    );
    assert_eq!(printed, "got hi\n");
}

#[test]
fn a_udp_datagram_reaches_its_own_socket() {
    // `dgram` is the second handle family: `send()` called back because the send
    // completion was already runnable, while `on('message')` never fired because
    // the receive side needed the loop pumped.
    let printed = same_as_node(
        "const d=require('dgram'); const s=d.createSocket('udp4');\n\
         s.on('message',m=>{console.log('RECV',m.toString()); s.close()});\n\
         s.bind(0,'127.0.0.1',()=>s.send('ping',s.address().port,'127.0.0.1'))",
    );
    assert_eq!(printed, "RECV ping\n");
}

#[test]
fn a_spawned_child_reports_its_exit_event() {
    // `process_wrap`'s exit callback is a libuv one, so the `exit` event is the
    // third handle family that only fires on the pumped loop. A pid came back
    // from `spawn()` before, which made the missing event easy to miss.
    let printed = same_as_node(
        "require('child_process').spawn('sh',['-c','exit 7']).on('exit',c=>console.log('exit',c))",
    );
    assert_eq!(printed, "exit 7\n");
}

#[test]
fn a_natural_exit_runs_the_exit_handlers() {
    // The loop settling is the ordinary way a process ends, and `exit` has to be
    // emitted for it just as it is for an explicit `process.exit()`. It was not:
    // the CLI read `process.exitCode` and called `std::process::exit` directly, so
    // every `process.on('exit', ...)` in `test/common` and `lib/**` was silently
    // skipped. That is what let a failing `node:test` file exit 0.
    let printed = same_as_node(
        "process.on('exit', (code) => console.log('EXIT EVENT', code));\n\
         console.log('body');",
    );
    assert_eq!(printed, "body\nEXIT EVENT 0\n");
}

#[test]
fn a_natural_exit_emit_is_guarded_by_exiting() {
    // A listener that calls `process.exit()` must not make the event fire a
    // second time: the exit sequence sets `process._exiting` before emitting, the
    // same flag `per_thread.js` checks. The event is counted rather than printed
    // because a second emit is the bug.
    //
    // Nothing is printed by real `node` here either: the re-entrant `exit()`
    // terminates inside the first listener, so the second never runs. The check
    // is that rustnode agrees on that, and on the status.
    let printed = same_as_node(
        "let n = 0;\n\
         process.on('exit', () => { n++; process.exit(); });\n\
         process.on('exit', () => console.log('sees', n));",
    );
    assert_eq!(printed, "");
}

#[test]
fn before_exit_is_emitted_before_exit() {
    let printed = same_as_node(
        "process.on('beforeExit', (code) => console.log('BEFORE', code));\n\
         process.on('exit', (code) => console.log('EXIT', code));",
    );
    assert_eq!(printed, "BEFORE 0\nEXIT 0\n");
}

#[test]
fn work_scheduled_from_before_exit_prevents_the_exit() {
    // This is the documented contract, not an edge case: `beforeExit` may
    // schedule work, and the process then keeps running. `internal/test_runner`'s
    // `harness.js` is built on it — its `exitHandler` waits for pending subtests
    // there — so getting it wrong is what made a failing `node:test` file exit 0
    // even though the failure itself was reported.
    let printed = same_as_node(
        "let n = 0;\n\
         process.on('beforeExit', () => {\n\
           console.log('BE', ++n);\n\
           if (n < 3) setTimeout(() => console.log('timer', n), 1);\n\
         });",
    );
    assert_eq!(printed, "BE 1\ntimer 1\nBE 2\ntimer 2\nBE 3\n");
}

#[test]
fn a_tick_from_before_exit_does_not_prevent_the_exit() {
    // The counterpart to the test above: `nextTick` and microtasks are drained
    // during the emit's own checkpoint and do not keep the loop alive, so the
    // process still exits. Node's `test-process-beforeexit.js` pins the same
    // asymmetry.
    let printed = same_as_node(
        "process.on('beforeExit', () => {\n\
           console.log('BE');\n\
           process.nextTick(() => console.log('tick'));\n\
           queueMicrotask(() => console.log('micro'));\n\
         });",
    );
    assert_eq!(printed, "BE\ntick\nmicro\n");
}

#[test]
fn the_exit_handler_can_change_the_status() {
    // Node re-reads `process.exitCode` after emitting, because a handler is
    // allowed to change it. The argument is the resolved code (`0`), while
    // `process.exitCode` is still unset inside the handler — the two are
    // different values, and real `node` shows both.
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg(
            "process.on('exit', (code) => {\n\
               console.log('saw', code, 'exitCode =', process.exitCode);\n\
               process.exitCode = 5;\n\
             });",
        )
        .output()
        .expect("rustnode runs");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "saw 0 exitCode = undefined"
    );
}

#[test]
fn a_failing_nested_subtest_exits_non_zero() {
    // The regression this work exists for. `node:test` reports failure by setting
    // `process.exitCode` from a `test:summary` listener, and that summary is only
    // produced when the harness's `beforeExit` handler finalises the root test.
    // Without `beforeExit` the report printed and the process still exited 0, so
    // `tools/harness` graded a file with failing subtests as a pass.
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg(
            "const { test } = require('node:test');\n\
             test('outer', async (t) => {\n\
               await t.test('inner passes', () => {});\n\
               await t.test('inner fails', () => { throw new Error('boom'); });\n\
             });",
        )
        .output()
        .expect("rustnode runs");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a failing subtest must not exit 0; stdout was {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fail 2"),
        "no failure summary in stdout:\n{stdout}"
    );
}

#[test]
fn a_passing_subtest_file_exits_zero() {
    // The control for the test above: the fix must not make every `node:test`
    // file fail. Without it, an implementation that always exits 1 would pass.
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg(
            "const { test } = require('node:test');\n\
             test('outer', async (t) => {\n\
               await t.test('inner passes', () => {});\n\
             });",
        )
        .output()
        .expect("rustnode runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a passing subtest file must exit 0; stdout was {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn an_explicit_process_exit_still_reports_its_code() {
    // The explicit path already reached `per_thread.js`'s wrapper. It is checked
    // here because the natural path was rebuilt around the same emit and a shared
    // helper must not change what the explicit call does.
    for code in [0, 5] {
        let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
            .arg("-e")
            .arg(format!(
                "process.on('exit', (c) => console.log('EVENT', c));\n\
                 process.exit({code});"
            ))
            .output()
            .expect("rustnode runs");
        assert_eq!(output.status.code(), Some(code));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            format!("EVENT {code}")
        );
    }
}

#[test]
fn an_uncaught_exception_still_exits_one_and_emits_exit() {
    // An uncaught throw is the third way a process ends. Node emits `exit` with
    // 1 for it, which is asserted alongside the status so a fix for the natural
    // path cannot regress the fatal one.
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg("process.on('exit', (c) => console.log('EVENT', c)); throw new Error('boom');")
        .output()
        .expect("rustnode runs");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "EVENT 1");
}
