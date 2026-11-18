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

const PRELUDE: &str = "\
const perf = require('internal/test/binding').internalBinding('performance');\
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
    // `eval_string` calls `markBootstrapComplete()` itself, so by the time user
    // code runs the milestone is already set — that is what Node reports, and the
    // oracle confirms it (`before` is a real timestamp in `node --expose-internals
    // -e`, not the `-1` sentinel). This test used to expect `-1`, which encoded
    // the old `-e` path: the CLI compiled a bare `v8::Script`, nothing called
    // `markBootstrapComplete`, and the milestone stayed unset.
    //
    // What the milestone means is unchanged, so the assertions are on the
    // contract rather than on the exact timestamp: it is set, and calling the
    // marker again leaves it set.
    let output = run(&format!(
        "{PRELUDE}
        const index = C.NODE_PERFORMANCE_MILESTONE_BOOTSTRAP_COMPLETE;
        const before = perf.milestones[index];
        perf.markBootstrapComplete();
        const after = perf.milestones[index];
        console.log(before >= 0, after >= 0);"
    ));
    assert_eq!(output, "true true");
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
    // The GC kinds are `v8::GCType` enumerators, so `MAJOR` is
    // `kGCTypeMarkSweepCompact` (4) and `MINOR_MARK_SWEEP` is
    // `kGCTypeMinorMarkSweep` (2). This expectation used to say `2 2 0 1`,
    // which pinned the swapped pair as correct; `perf_hooks.constants` reports
    // `4 2 0 1` under the oracle and a consumer filtering `detail.kind` on
    // `MAJOR` would otherwise see scavenges.
    assert_eq!(output, "4 2 0 1");
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
fn create_histogram_returns_a_recordable_histogram() {
    // The headline defect this test replaces: `createHistogram()` used to throw
    // `_Histogram is not a constructor`, because `performance.Histogram` was
    // installed as `undefined`. Asserting the values, not just that it built.
    let output = run("const { createHistogram } = require('perf_hooks');
        const h = createHistogram({ lowest: 1, highest: 1000, figures: 3 });
        for (const value of [1, 2, 3, 5, 8, 13, 21]) h.record(value);
        console.log(h.count, h.min, h.max, h.percentile(50), h.percentile(100));
        console.log(h.countBigInt, h.minBigInt, h.maxBigInt);
        console.log(typeof h.mean, h.mean > 0, h.stddev > 0);
        console.log([...h.percentiles.keys()].join(','));");
    // The 50th percentile of these seven samples is 5 (the oracle reports the
    // same), and `max` is 21 because 21 happens to end its bucket at three
    // significant figures. Only four percentile rows are emitted: the tick
    // density at this sample count does not reach the 93.75 half-distance.
    assert_eq!(
        output,
        "7 1 21 5 21\n7n 1n 21n\nnumber true true\n0,50,75,87.5,100"
    );
}

#[test]
fn an_empty_histogram_reports_nodes_sentinels() {
    // `min` is `INT64_MAX` (reported as a Number first, so it loses precision),
    // `max` is 0 and mean/stddev are NaN. A zero-initialised minimum would claim
    // every value was recorded at 0.
    let output = run("const { createHistogram } = require('perf_hooks');
        const h = createHistogram({ lowest: 1, highest: 1000, figures: 2 });
        console.log(h.count, h.min, h.max, h.minBigInt, h.maxBigInt);
        console.log(Number.isNaN(h.mean), Number.isNaN(h.stddev));
        console.log(JSON.stringify([...h.percentiles.entries()]));");
    assert_eq!(
        output,
        "0 9223372036854776000 0 9223372036854775807n 0n\ntrue true\n[[100,0]]"
    );
}

#[test]
fn a_value_above_the_cap_counts_as_exceeding() {
    let output = run("const { createHistogram } = require('perf_hooks');
        const h = createHistogram({ lowest: 1, highest: 100, figures: 3 });
        h.record(50);
        h.record(101);
        h.record(1000000);
        console.log(h.count, h.exceeds, h.exceedsBigInt);");
    assert_eq!(output, "1 2 2n");
}

#[test]
fn reset_clears_the_data_and_bumps_the_reset_count() {
    let output = run("const { createHistogram } = require('perf_hooks');
        const h = createHistogram({ lowest: 1, highest: 1000, figures: 3 });
        h.record(10);
        const before = h.resetCount;
        h.reset();
        console.log(before, h.resetCount, h.count, h.max);");
    assert_eq!(output, "0 1 0 0");
}

#[test]
fn adding_a_histogram_to_itself_doubles_every_count() {
    // `add(self)` shares one state cell, so a naive implementation that borrows
    // the cell twice would panic; the count is the proof it merged instead.
    let output = run("const { createHistogram } = require('perf_hooks');
        const h = createHistogram({ lowest: 1, highest: 1000, figures: 3 });
        h.record(10);
        h.record(20);
        h.add(h);
        console.log(h.count, h.min, h.max);");
    assert_eq!(output, "4 10 20");
}

#[test]
fn a_snapshot_is_independent_and_diffs_against_it() {
    let output = run("const { createHistogram } = require('perf_hooks');
        const h = createHistogram({ lowest: 1, highest: 1000, figures: 3 });
        h.record(10);
        const snapshot = h.snapshot();
        h.record(20);
        h.record(30);
        const difference = h.diff(snapshot);
        console.log(snapshot.count, h.count, difference.count, difference.min);");
    // The snapshot must not see the two later records; the difference holds only
    // those two, so its minimum is 20.
    assert_eq!(output, "1 3 2 20");
}

#[test]
fn the_sliding_window_keeps_the_records_inside_its_ring() {
    // Two chunks of two records hold four records exactly, so all four survive;
    // the fifth is the record that reuses the oldest chunk. The oracle reports
    // `4 10 40` for the first block and `3 30 50` after the fifth record, which
    // is the rule this pins.
    let output = run(
        "const { createSlidingWindowHistogram } = require('perf_hooks');
        const h = createSlidingWindowHistogram({
          chunks: 2, recordsPerChunk: 2, lowest: 1, highest: 1000, figures: 2,
        });
        for (const value of [10, 20, 30, 40]) h.record(value);
        const first = h.snapshot();
        console.log(first.count, first.min, first.max);
        h.record(50);
        const second = h.snapshot();
        console.log(second.count, second.min, second.max);",
    );
    assert_eq!(output, "4 10 40\n3 30 50");
}

#[test]
fn monitor_event_loop_delay_records_intervals() {
    // `monitorEventLoopDelay()` builds an ELD histogram through
    // `createELDHistogram`, which used to throw "not implemented".
    //
    // The loop has to actually run for the interval timer to fire: a busy wait
    // blocks the loop and records nothing, in Node as well as here. So the
    // measurement happens from a `setTimeout`, which is also what makes the
    // enable/disable return values observable in the right order.
    let output = run("const { monitorEventLoopDelay } = require('perf_hooks');
        const histogram = monitorEventLoopDelay({ resolution: 1 });
        const before = histogram.count;
        histogram.enable();
        console.log('enableAgain', histogram.enable());
        setTimeout(() => {
          console.log('disable', histogram.disable());
          console.log('disableAgain', histogram.disable());
          console.log(before, histogram.count > 0, histogram.min > 0,
                      Number.isFinite(histogram.mean), histogram.max >= histogram.min);
        }, 20);");
    assert_eq!(
        output,
        "enableAgain false\ndisable true\ndisableAgain false\n0 true true true true"
    );
}

#[test]
fn the_eld_factory_is_not_a_constructor() {
    // `createELDHistogram` is a plain method, not a constructor: the handle is
    // made by calling it, and `uv_timer_init` inside is what makes it a sampler.
    // `new` on it therefore fails the way `--expose-internals` under the oracle
    // does, with a `TypeError` and no `code`.
    let output = run(&format!(
        "{PRELUDE}
        try {{ new perf.createELDHistogram(); console.log('built'); }}
        catch (e) {{ console.log('threw', e.name, e.code); }}"
    ));
    assert_eq!(output, "threw TypeError undefined");
}
