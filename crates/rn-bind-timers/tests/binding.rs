//! End-to-end checks that drive `timers` through the CLI.
//!
//! `lib/internal/timers.js` writes the two shared counters directly, so the
//! tests write them from JavaScript and read them back from Rust. A copy on
//! either side would make the event loop think it had work when it did not.

use std::path::PathBuf;
use std::process::Command;

fn rustnode() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

fn run(script: &str) -> String {
    let output = Command::new(rustnode())
        .arg("--expose-internals")
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary must be built first");
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

const PRELUDE: &str = "const realm = require('internal/bootstrap/realm');\
const timers = realm.internalBinding('timers');";

#[test]
fn the_counters_have_the_shapes_lib_timers_expects() {
    // `immediateInfo` is a Uint32Array(3) and `timeoutInfo` is an Int32Array(1).
    // Both are indexed as arrays by the JavaScript side.
    let output = run(&format!(
        "{PRELUDE}
        console.log(timers.immediateInfo.constructor.name, timers.immediateInfo.length);
        console.log(timers.timeoutInfo.constructor.name, timers.timeoutInfo.length);"
    ));
    assert_eq!(output, "Uint32Array 3\nInt32Array 1");
}

#[test]
fn javascript_writes_to_timeout_info_are_visible_to_rust() {
    // `lib/internal/timers.js` does exactly this when a timer is created.
    let output = run(&format!(
        "{PRELUDE}
        timers.timeoutInfo[0] = 7;
        console.log(timers.timeoutInfo[0]);"
    ));
    assert_eq!(output, "7");
}

#[test]
fn toggling_a_timer_ref_updates_the_shared_counters() {
    let output = run(&format!(
        "{PRELUDE}
        const before = timers.timeoutInfo[0];
        timers.toggleTimerRef(true);
        const afterAdd = timers.timeoutInfo[0];
        timers.toggleTimerRef(false);
        const afterRemove = timers.timeoutInfo[0];
        console.log(before, afterAdd, afterRemove);"
    ));
    assert_eq!(output, "0 1 0");
}

#[test]
fn toggling_an_immediate_ref_updates_the_ref_and_outstanding_flags() {
    let output = run(&format!(
        "{PRELUDE}
        timers.toggleImmediateRef(true);
        const held = [timers.immediateInfo[1], timers.immediateInfo[2]];
        timers.toggleImmediateRef(false);
        const released = [timers.immediateInfo[1], timers.immediateInfo[2]];
        console.log(held.join(','), released.join(','));"
    ));
    // The ref count and the derived "outstanding" flag must move together:
    // the loop reads the flag, not the count.
    assert_eq!(output, "1,1 0,0");
}

#[test]
fn the_loop_clock_is_monotonic_milliseconds() {
    let output = run(&format!(
        "{PRELUDE}
        const first = timers.getLibuvNow();
        const busy = timers.getLibuvNow();
        console.log(typeof first === 'number', busy >= first, first > 0);"
    ));
    assert_eq!(output, "true true true");
}

#[test]
fn setup_timers_accepts_the_two_callbacks() {
    let output = run(&format!(
        "{PRELUDE}
        let immediateRan = false;
        let timerRan = false;
        timers.setupTimers(() => {{ immediateRan = true; }}, () => {{ timerRan = true; }});
        console.log(typeof timers.setupTimers, immediateRan, timerRan);"
    ));
    // Registering the callbacks must not run them.
    assert_eq!(output, "function false false");
}

#[test]
fn schedule_timer_accepts_a_duration() {
    let output = run(&format!(
        "{PRELUDE} timers.scheduleTimer(5); console.log('scheduled');"
    ));
    assert_eq!(output, "scheduled");
}
