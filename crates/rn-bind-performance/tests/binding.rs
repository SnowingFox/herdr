//! End-to-end checks that drive `performance` through the CLI.
//!
//! `lib/internal/process/pre_execution.js` calls `markBootstrapComplete()` on
//! every start, and `perf_hooks` reads the milestone array directly, so the
//! shapes and the "not reached yet" sentinel are both part of the contract.

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
const perf = realm.internalBinding('performance');\
const C = perf.constants;";

#[test]
fn the_shared_buffers_have_node_shapes() {
    let output = run(&format!(
        "{PRELUDE}
        console.log(perf.milestones.constructor.name, perf.milestones.length);
        console.log(perf.observerCounts.constructor.name, perf.observerCounts.length);
        console.log(perf.uvMetricsBuffer.constructor.name, perf.uvMetricsBuffer.length);"
    ));
    // Eight milestones, six entry types, three loop counters.
    assert_eq!(output, "Float64Array 8\nUint32Array 6\nFloat64Array 3");
}

#[test]
fn unreached_milestones_stay_at_the_negative_sentinel() {
    // `perf_hooks` checks for -1 to decide whether a milestone happened. A zero
    // would claim every milestone occurred at the time origin.
    let output = run(&format!(
        "{PRELUDE}
        const loopExit = C.NODE_PERFORMANCE_MILESTONE_LOOP_EXIT;
        console.log(perf.milestones[loopExit]);"
    ));
    assert_eq!(output, "-1");
}

#[test]
fn mark_bootstrap_complete_records_the_final_milestone() {
    let output = run(&format!(
        "{PRELUDE}
        const index = C.NODE_PERFORMANCE_MILESTONE_BOOTSTRAP_COMPLETE;
        const before = perf.milestones[index];
        perf.markBootstrapComplete();
        const after = perf.milestones[index];
        console.log(before, after >= 0);"
    ));
    assert_eq!(output, "-1 true");
}

#[test]
fn the_time_origin_and_first_milestone_are_known_at_startup() {
    let output = run(&format!(
        "{PRELUDE}
        const timestamp = C.NODE_PERFORMANCE_MILESTONE_TIME_ORIGIN_TIMESTAMP;
        const origin = C.NODE_PERFORMANCE_MILESTONE_TIME_ORIGIN;
        console.log(perf.milestones[timestamp] > 0, perf.milestones[origin] >= 0);"
    ));
    assert_eq!(output, "true true");
}

#[test]
fn now_advances_in_milliseconds() {
    let output = run(&format!(
        "{PRELUDE}
        const first = perf.now();
        let total = 0;
        for (let i = 0; i < 2000000; i++) total += i;
        const second = perf.now();
        console.log(typeof first, second > first, first >= 0);"
    ));
    assert_eq!(output, "number true true");
}

#[test]
fn notify_publishes_an_entry_only_when_someone_observes_that_type() {
    // `notify(type, entry)` is the entry publication path, not the milestone
    // path: `perf_hooks` only receives entries for types with a live observer,
    // and skipping the rest is the point of the observer counts.
    let output = run(&format!(
        "{PRELUDE}
        const seen = [];
        perf.setupObservers((entry) => seen.push(entry));
        // No observers registered yet, so this must not reach the callback.
        perf.notify('gc', {{ detail: 'skipped' }});
        const gc = C.NODE_PERFORMANCE_ENTRY_TYPE_GC;
        perf.observerCounts[gc] = 1;
        perf.notify('gc', {{ detail: 'delivered' }});
        perf.notify('not-a-real-type', {{ detail: 'ignored' }});
        console.log(seen.length, seen[0].detail);"
    ));
    assert_eq!(output, "1 delivered");
}

#[test]
fn setup_observers_installs_the_entry_callback() {
    // The callback is where every published entry goes; `perf_hooks` owns the
    // per-type filtering from there.
    let output = run(&format!(
        "{PRELUDE}
        let called = false;
        perf.setupObservers(() => {{ called = true; }});
        const gc = C.NODE_PERFORMANCE_ENTRY_TYPE_GC;
        perf.observerCounts[gc] = 1;
        perf.notify('gc', {{}});
        console.log(called);"
    ));
    assert_eq!(output, "true");
}

#[test]
fn the_constants_cover_gc_types_flags_entry_types_and_milestones() {
    let output = run(&format!(
        "{PRELUDE}
        console.log(C.NODE_PERFORMANCE_GC_MAJOR, C.NODE_PERFORMANCE_GC_FLAGS_FORCED,
                    C.NODE_PERFORMANCE_ENTRY_TYPE_GC, C.NODE_PERFORMANCE_MILESTONE_TIME_ORIGIN);"
    ));
    // The enum positions, which `perf_hooks` compares against.
    assert_eq!(output, "2 2 0 1");
}

#[test]
fn loop_counters_report_not_measured_rather_than_zero() {
    // A zero mask means "nothing measured", which is different from a measured
    // zero; reporting the latter would make event-loop utilization look idle.
    let output = run(&format!(
        "{PRELUDE}
        const mask = perf.uvMetricsInfo();
        console.log(typeof mask, mask === 0n, perf.loopIdleTime());"
    ));
    assert_eq!(output, "bigint true 0");
}

#[test]
fn the_eld_histogram_refuses_rather_than_pretending() {
    // `createELDHistogram` measures event-loop delay. Returning a working-looking
    // instrument that never records would be worse than an honest failure.
    let output = run(&format!(
        "{PRELUDE}
        try {{ perf.createELDHistogram(); console.log('built'); }}
        catch (e) {{ console.log('threw', e.message.includes('not implemented')); }}"
    ));
    assert_eq!(output, "threw true");
}
