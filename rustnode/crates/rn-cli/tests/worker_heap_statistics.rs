//! `worker.getHeapStatistics()` and the worker that runs out of heap.
//!
//! Both are observable from a user program and both were broken in a way that
//! cost a Node test file:
//!
//! * `test/parallel/test-worker-heap-statistics.js` never answered, because
//!   `Worker.prototype.getHeapStatistics` did not exist at all — the JS half
//!   threw `this[kHandle]?.getHeapStatistics is not a function`, the promise was
//!   never settled, and the file timed out rather than failing;
//! * `test/parallel/test-worker-resource-limits.js` aborted the *process* with
//!   `Fatal JavaScript out of memory: CALL_AND_RETRY_LAST`, because a worker's
//!   heap limit produced a V8 fatal error instead of `Worker::Exit`'s
//!   `ERR_WORKER_OUT_OF_MEMORY`.
//!
//! Each assertion here is the pinned oracle's answer, not a description of this
//! code. The heap *sizes* are not compared — they legitimately differ between a
//! runtime with a startup snapshot and one without — so what is pinned is the
//! shape of the answer, the error codes and the exit statuses.

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
        .get_or_init(|| rn_node_oracle::require_oracle("rn-cli worker heap statistics"))
        .as_ref()
}

/// Asserts rustnode's stdout and exit status are the oracle's.
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

/// The fifteen fields `src/node_worker.cc:1251-1265` reports, sorted.
const FIELDS: &[&str] = &[
    "does_zap_garbage",
    "external_memory",
    "heap_size_limit",
    "malloced_memory",
    "number_of_detached_contexts",
    "number_of_native_contexts",
    "peak_malloced_memory",
    "total_allocated_bytes",
    "total_available_size",
    "total_global_handles_size",
    "total_heap_size",
    "total_heap_size_executable",
    "total_physical_size",
    "used_global_handles_size",
    "used_heap_size",
];

#[test]
fn worker_get_heap_statistics_reports_nodes_fifteen_fields() {
    // The keys are compared as a whole, sorted list: a missing or extra field is
    // exactly what `test-worker-heap-statistics.js` asserts, and a spot check of
    // three names would pass on an object carrying twelve.
    let source = r#"
      const { Worker } = require('worker_threads');
      const w = new Worker('require("worker_threads").parentPort.postMessage(1)', { eval: true });
      w.once('message', async () => {
        const stats = await w.getHeapStatistics();
        console.log(Object.keys(stats).sort().join(','));
        console.log(typeof stats.does_zap_garbage, typeof stats.heap_size_limit);
        console.log(Object.getPrototypeOf(stats) === null);
        console.log(stats.heap_size_limit > 0);
        w.terminate();
      });
      w.once('error', (error) => { console.log('error', error.code); });
    "#;
    let (code, stdout, stderr) = run(env!("CARGO_BIN_EXE_rustnode"), source);
    assert_eq!(code, 0, "stderr: {stderr}");
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next().unwrap_or_default(),
        FIELDS.join(","),
        "stdout: {stdout:?}"
    );
    // `Boolean::New` for the one bool and `Number::New` for the rest, which is
    // the pair `src/node_worker.cc:1257-1264` builds.
    assert_eq!(lines.next().unwrap_or_default(), "boolean number");
    // `NewDictionaryInstanceNullProto`.
    assert_eq!(lines.next().unwrap_or_default(), "true");
    assert_eq!(lines.next().unwrap_or_default(), "true");
}

#[test]
fn worker_get_heap_statistics_rejects_after_the_worker_is_gone() {
    // `Worker::GetHeapStatistics` returns an empty handle when
    // `RequestInterrupt` finds no environment, and `lib/internal/worker.js`
    // turns that into `ERR_WORKER_NOT_RUNNING`. This is the second half of
    // `test-worker-heap-statistics.js`, and it is the shape a stub returning a
    // plausible object would fail.
    let source = r#"
      const { Worker } = require('worker_threads');
      const w = new Worker('', { eval: true });
      w.once('exit', async () => {
        try {
          await w.getHeapStatistics();
          console.log('resolved');
        } catch (error) {
          console.log('rejected', error.code);
        }
      });
    "#;
    if let Some((code, stdout)) = same_as_oracle(source) {
        assert_eq!(code, 0, "oracle run failed");
        assert_eq!(stdout.trim(), "rejected ERR_WORKER_NOT_RUNNING");
    }
}

#[test]
fn a_worker_past_its_old_generation_limit_reports_out_of_memory_and_the_parent_survives() {
    // The acceptance case for the heap work. Before the isolate was sized from
    // the machine *and* the near-heap-limit callback existed, this aborted the
    // whole process with `Fatal JavaScript out of memory:
    // CALL_AND_RETRY_LAST`. What it must do instead is exactly
    // `Worker::Exit(kGenericUserError, "ERR_WORKER_OUT_OF_MEMORY", ...)`:
    // an `error` event with that code, an `exit` with status 1, and a parent that
    // is still running.
    let source = r#"
      const { Worker } = require('worker_threads');
      const w = new Worker(`
        const held = [];
        while (true) held.push([held]);
      `, { eval: true, resourceLimits: { maxOldGenerationSizeMb: 16 } });
      w.on('error', (error) => console.log('error', error.code));
      w.on('exit', (code) => {
        console.log('exit', code);
        console.log('parent alive');
      });
    "#;
    let (code, stdout, stderr) = run(env!("CARGO_BIN_EXE_rustnode"), source);
    assert_eq!(code, 0, "the parent must exit cleanly, stderr: {stderr}");
    assert!(
        !stderr.contains("Fatal JavaScript out of memory"),
        "the heap limit must not abort the process, stderr: {stderr}"
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        ["error ERR_WORKER_OUT_OF_MEMORY", "exit 1", "parent alive"],
        "stdout: {stdout:?}"
    );
}

#[test]
fn a_worker_resource_limit_round_trips_every_field_the_caller_named() {
    // `test-worker-resource-limits.js` opens with
    // `assert.deepStrictEqual(w.resourceLimits, testResourceLimits)`, so all
    // four named limits have to come back as given. That is the half the JS
    // layer's `parseResourceLimits` and this crate's `getResourceLimits` own.
    //
    // The *unnamed* half is deliberately not asserted: on the oracle a worker
    // with no `resourceLimits` reports the effective constraints
    // (`maxOldGenerationSizeMb: 4096`, `maxYoungGenerationSizeMb: 96` on this
    // box), because `UpdateResourceConstraints` writes the configured values back
    // into `resource_limits_` when the caller left them at `-1`. rustnode reports
    // `-1` for those, which is a divergence in reporting rather than in
    // enforcement — the isolate is created with the machine's constraints either
    // way — and closing it needs the effective values written back to state the
    // parent thread reads.
    let source = r#"
      const { Worker } = require('worker_threads');
      const limits = {
        maxOldGenerationSizeMb: 16,
        maxYoungGenerationSizeMb: 4,
        codeRangeSizeMb: 16,
        stackSizeMb: 1,
      };
      const w = new Worker('require("worker_threads").parentPort.postMessage(1)', {
        eval: true,
        resourceLimits: limits,
      });
      console.log(['maxOldGenerationSizeMb', 'maxYoungGenerationSizeMb',
        'codeRangeSizeMb', 'stackSizeMb']
        .every((key) => w.resourceLimits[key] === limits[key]));
      w.once('message', () => w.terminate());
    "#;
    if let Some((code, stdout)) = same_as_oracle(source) {
        assert_eq!(code, 0, "oracle run failed");
        assert_eq!(stdout.trim(), "true");
    }
}

#[test]
fn a_worker_named_young_generation_is_the_one_its_isolate_enforces() {
    // The sizing half of `UpdateResourceConstraints`: a named
    // `maxYoungGenerationSizeMb` has to reach `CreateParams`, or the worker's
    // `new_space` ignores it. Measured through `v8.getHeapSpaceStatistics()`
    // inside the worker, because that is what
    // `test-worker-resource-limits.js` asserts against its own limit.
    let source = r#"
      const { Worker } = require('worker_threads');
      const script = `
        const v8 = require('v8');
        const space = v8.getHeapSpaceStatistics().find((s) => s.space_name === 'new_space');
        const limit = require('worker_threads').resourceLimits.maxYoungGenerationSizeMb;
        require('worker_threads').parentPort.postMessage(
          space.space_size / 1024 / 1024 < limit * 2);
      `;
      for (const maxYoungGenerationSizeMb of [4, 32]) {
        const w = new Worker(script, {
          eval: true,
          resourceLimits: { maxOldGenerationSizeMb: 16, maxYoungGenerationSizeMb },
        });
        w.once('message', (ok) => { console.log(ok); w.terminate(); });
      }
    "#;
    if let Some((code, stdout)) = same_as_oracle(source) {
        assert_eq!(code, 0, "oracle run failed");
        // `new_space` stays under twice the named young generation, for both a
        // small and a large limit: a hardcoded semi-space would fail one of them.
        assert_eq!(stdout.trim(), "true\ntrue");
    }
}
