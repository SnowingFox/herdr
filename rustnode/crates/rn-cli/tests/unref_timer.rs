//! An unref'd timer must fire when its deadline is reached, whatever the delay.
//!
//! # What this pins
//!
//! `setTimeout(f, d).unref()` fires for small `d` and silently never fires for
//! larger `d`, as long as the process has a live socket keeping the loop turning.
//! The failure was delay-dependent, not ref-dependent, and the threshold sat at
//! 500ms because that is the delay `lib/net.js`'s connect path arms: a
//! `setTimeout(..., 500)` appears in `internalConnectMultiple`'s lookup callback.
//!
//! The mechanism was in `rn_bind_timers::apply_timer_result`. `processTimers`
//! returns a signed deadline, and Node's `Environment::RunTimers` reads three
//! cases:
//!
//! * `0` — no timer lists left; unref the handle.
//! * `> 0` — the next expiry, with at least one ref'd timer behind it; re-arm and
//!   `uv_ref`.
//! * `< 0` — `-expiry` with **no** ref'd timer behind it; re-arm and `uv_unref`.
//!
//! rustnode treated every non-positive value as "stop". With two lists — say a
//! 500ms unref'd connect timer and a 1200ms timer — the 500ms list fires, the
//! next expiry is the 1200ms one with no ref'd timer behind it, so
//! `processTimers` returns `-1200`, and the handle was stopped. The 1200ms list
//! then never ran, because `lib/internal/timers.js` only calls `scheduleTimer`
//! when a *new* list beats `nextExpiry`; the pending deadline was already known
//! to it, so it stayed silent forever.
//!
//! That is why the observable symptom looked like "longer delays never fire" and
//! why a listener-only loop (no socket) never reproduced it: the 500ms list only
//! exists when something connects.
//!
//! # Why this compares against real `node`
//!
//! The expectation is not "a timer fires within some window"; it is "this script
//! prints WATCHDOG and exits 0", which is a fact about Node's semantics rather
//! than about this runtime. Running the same script under `node` is what keeps a
//! later rewrite of the timer path from quietly redefining away the case.

use std::process::Command;
use std::time::{Duration, Instant};

/// Builds the bisect script for one delay.
///
/// The socket is only ever touched to attach a `'data'` listener: it exists so
/// the loop has a ref'd handle of its own and `lib/net.js` arms its 500ms unref'd
/// connect timer, which is the second timer *list* the bug needed.
fn script(delay_ms: u64) -> String {
    format!(
        "const net = require('net');\n\
         const server = net.createServer((socket) => {{ socket.on('data', () => {{}}); }});\n\
         server.listen(0, () => {{\n\
           net.connect({{ port: server.address().port }}, () => {{}});\n\
         }});\n\
         setTimeout(() => {{ console.log('WATCHDOG'); process.exit(0); }}, {delay_ms}).unref();"
    )
}

/// What running `script` produced, with the duration it took.
struct Run {
    stdout: String,
    success: bool,
    elapsed: Duration,
}

/// Runs `script` under `binary`, killing it if it outlives `limit`.
fn run(binary: &str, script: &str, limit: Duration) -> Run {
    let started = Instant::now();
    let mut child = Command::new(binary)
        .arg("-e")
        .arg(script)
        // Piped, not inherited: the assertions are about what the child printed,
        // and an inherited descriptor would leave `wait_with_output` with nothing.
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("cannot spawn {binary}: {error}"));

    // A timer bug that never fires has to be a failed assertion rather than a
    // test harness timeout, so the child is polled and killed rather than waited
    // on indefinitely.
    let mut killed = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => panic!("cannot poll {binary}: {error}"),
        }
        if started.elapsed() > limit {
            killed = true;
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("cannot collect {binary}'s output: {error}"));
    Run {
        stdout: String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .to_string(),
        success: !killed && output.status.success(),
        elapsed: started.elapsed(),
    }
}

/// The delays the bug needed to be visible at, plus the two that always worked.
///
/// 500 is the exact boundary: `lib/net.js`'s own connect timer, so a timer of
/// exactly 500ms lands in the *same* list as it and cannot expose the second-list
/// case. Everything above it does.
const DELAYS_MS: &[u64] = &[200, 500, 1200, 2000];

/// The two-condition reproduction, kept verbatim because it is what isolates the
/// bug from every innocent explanation.
///
/// The `setTimeout(..., 500)` below is *not* ours: it is `lib/net.js`'s connect
/// timer, armed from `internalConnectMultiple`'s lookup callback. That is what
/// makes an 800ms application timer sit in a *second, later* list, which is the
/// condition the bug needed.
///
/// Condition A: a live socket and one unref'd deadline. The loop wakes at the
/// 500ms connect deadline, `processTimers` runs, the next expiry is the 800ms
/// list with nothing ref'd behind it, and `processTimers` returns `-expiry`.
/// Condition B: the same plus any ref'd timer. `processTimers` now returns
/// `+expiry`, so the value is treated as "re-arm" and the 800ms list survives.
///
/// The difference between A and B is *only* the sign of the return value, which is
/// why "an 800ms unref'd timer fires when something ref'd is also pending, and
/// never fires otherwise" is the exact symptom — and why it looks like a loop
/// liveness problem rather than a timer one.
const SOCKET_PREFIX: &str = "\
const net = require('net');\n\
const server = net.createServer((socket) => { socket.on('data', () => {}); });\n\
server.listen(0, () => {\n\
  net.connect({ port: server.address().port }, () => {});\n\
});\n";

/// Condition A: the unref'd deadline fires and is the only thing reported.
///
/// The process does not exit afterwards — the listening socket is ref'd, so
/// neither does `node` — which is why the assertion is about the printed line and
/// not about a clean exit. `timeout`-style killing is the harness's job.
fn condition_a() -> String {
    format!("{SOCKET_PREFIX}setTimeout(() => console.log('FIRED'), 800).unref();")
}

/// Condition B: the same deadline, with a ref'd timer also pending.
fn condition_b() -> String {
    format!(
        "{SOCKET_PREFIX}setTimeout(() => console.log('FIRED'), 800).unref();\n\
         setTimeout(() => {{ console.log('ref 1500'); process.exit(0); }}, 1500);"
    )
}

#[test]
fn an_unrefed_deadline_fires_alone_and_with_a_refed_timer_pending() {
    // Both conditions, because the bug lived exactly in the difference between
    // them: a fix that only made B work would leave the HTTP timeouts broken, and
    // B already worked before any change.
    for (name, script) in [("A", condition_a()), ("B", condition_b())] {
        let reference = run("node", &script, Duration::from_secs(10));
        assert!(
            reference.stdout.contains("FIRED"),
            "`node` did not fire the 800ms unref'd timer in condition {name}; \
             the reference behaviour cannot be established"
        );

        let actual = run(
            env!("CARGO_BIN_EXE_rustnode"),
            &script,
            Duration::from_secs(10),
        );
        assert!(
            actual.stdout.contains("FIRED"),
            "the 800ms unref'd timer never fired in condition {name} \
             (stdout {:?}, {} elapsed)",
            actual.stdout,
            actual.elapsed.as_millis()
        );
    }
}

#[test]
fn a_lone_unrefed_deadline_still_gets_the_event_loop_running() {
    // The failure mode this pins is "the loop neither expires the deadline nor
    // exits", so the assertion is that the process made progress at all: with the
    // bug it was killed at the limit having printed nothing.
    let actual = run(
        env!("CARGO_BIN_EXE_rustnode"),
        &condition_a(),
        Duration::from_secs(10),
    );
    assert_eq!(
        actual.stdout,
        "FIRED",
        "condition A printed something other than the fired deadline \
         ({} elapsed)",
        actual.elapsed.as_millis()
    );
    assert!(
        actual.elapsed >= Duration::from_millis(800),
        "condition A printed too early to have honoured the deadline ({}ms)",
        actual.elapsed.as_millis()
    );
}

#[test]
fn an_unrefed_timer_fires_at_every_delay_under_node() {
    // The reference. `node` is the specification for what these scripts mean, so
    // a failure here would be a broken environment rather than a rustnode bug,
    // and it has to be reported as such instead of as a parity difference.
    for &delay in DELAYS_MS {
        let reference = run("node", &script(delay), Duration::from_secs(10));
        assert!(
            reference.success,
            "`node` did not fire an unref'd {delay}ms timer ({}); \
             the reference behaviour for this test cannot be established",
            reference.elapsed.as_millis()
        );
        assert_eq!(
            reference.stdout, "WATCHDOG",
            "`node` printed something unexpected for a {delay}ms timer"
        );
    }
}

#[test]
fn an_unrefed_timer_fires_at_every_delay_and_the_process_exits() {
    // The bug. `200` and `500` passed before the fix and `1200` and `2000` hung
    // until killed, so the delays are kept in one test: shortening this list to
    // the ones that used to fail would let a regression that broke short delays
    // pass.
    for &delay in DELAYS_MS {
        let actual = run(
            env!("CARGO_BIN_EXE_rustnode"),
            &script(delay),
            Duration::from_secs(10),
        );
        assert!(
            actual.success,
            "an unref'd {delay}ms timer did not let the process exit \
             ({} elapsed, stdout {:?})",
            actual.elapsed.as_millis(),
            actual.stdout
        );
        assert_eq!(
            actual.stdout, "WATCHDOG",
            "an unref'd {delay}ms timer did not fire"
        );
    }
}

#[test]
fn the_timer_does_not_fire_early() {
    // The re-arm must not collapse the deadline. An unref'd 1200ms timer that
    // fired at the connect timer's 500ms boundary would satisfy the assertions
    // above while being a different bug: the handle would be re-armed from the
    // wrong expiry.
    let actual = run(
        env!("CARGO_BIN_EXE_rustnode"),
        &script(1200),
        Duration::from_secs(10),
    );
    assert!(
        actual.success,
        "the 1200ms timer did not let the process exit"
    );
    assert!(
        actual.elapsed >= Duration::from_millis(1200),
        "the 1200ms timer fired after only {}ms",
        actual.elapsed.as_millis()
    );
}

#[test]
fn an_unrefed_timer_alone_does_not_keep_the_process_alive() {
    // The other half of `unref`'s contract, which the re-arm could break: a
    // re-armed handle left ref'd would keep the process open for a deadline the
    // caller explicitly excluded. `node` exits immediately here without firing.
    let script = "setTimeout(() => console.log('FIRED'), 5000).unref();";
    let reference = run("node", script, Duration::from_secs(10));
    assert!(reference.success, "`node` did not exit on an unref'd timer");
    assert_eq!(reference.stdout, "", "`node` fired a cancelled deadline");

    let actual = run(
        env!("CARGO_BIN_EXE_rustnode"),
        script,
        Duration::from_secs(10),
    );
    assert!(
        actual.success,
        "the process did not exit with only an unref'd timer left"
    );
    assert_eq!(
        actual.stdout, "",
        "an unref'd timer that nothing else keeps the loop alive for must not fire"
    );
    assert!(
        actual.elapsed < Duration::from_secs(5),
        "the unref'd timer held the process open for {}ms",
        actual.elapsed.as_millis()
    );
}
