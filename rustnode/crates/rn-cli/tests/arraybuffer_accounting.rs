//! `process.memoryUsage().arrayBuffers`, measured against the pinned oracle.
//!
//! `arrayBuffers` is the one figure in `memoryUsage()` that a runtime can report
//! as a constant without anything looking wrong: `0` is a plausible number, and
//! every other field is a real measurement, so a smoke test that only checks the
//! object's keys and that the numbers are positive passes on a runtime that never
//! counts a byte. These tests pin the two properties a constant cannot have —
//! that the figure *grows* with live buffers and *falls* when they are collected —
//! and the property a second counter would break, that `external` does not move
//! twice when a buffer is allocated.
//!
//! # Ranges, not bytes
//!
//! The allocator is not Node's: this build counts what V8 asks Rust for, Node
//! counts what `NodeArrayBufferAllocator` asks `malloc` for, and the two differ in
//! bookkeeping overhead by a small, implementation-defined amount. Each shape is
//! therefore pinned as a range around the requested size plus a direction, and
//! the ratio between the two runtimes is what is compared, so a counter that is
//! off by an allocation header still passes while a counter that is zero, doubled
//! or monotonic fails.
//!
//! # Why the scripts are run rather than the handler called
//!
//! `--expose-gc` gives the script a real `gc()`, and reclamation is only
//! observable after one. A binding-level test cannot collect the isolate's heap,
//! so it could only ever see the growth half.

use std::process::Command;

/// One runtime's measurement of one shape, in bytes.
#[derive(Debug, Clone, Copy)]
struct Sample {
    array_buffers: f64,
    external: f64,
}

/// Runs `script` under `binary` and parses the `arrayBuffers`/`external` pair it
/// prints as its last line of JSON.
fn measure(binary: &str, script: &str) -> Sample {
    let output = Command::new(binary)
        .args(["--expose-gc", "-e", script])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    assert!(
        output.status.success(),
        "{binary} exited {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .rfind(|line| line.starts_with('{'))
        .unwrap_or_else(|| panic!("{binary} printed no JSON sample; stdout: {stdout}"));
    let array_buffers = field(line, "arrayBuffers");
    let external = field(line, "external");
    Sample {
        array_buffers,
        external,
    }
}

/// The value of `"name": <number>` in a flat JSON object.
fn field(json: &str, name: &str) -> f64 {
    let key = format!("\"{name}\":");
    let start = json
        .find(&key)
        .unwrap_or_else(|| panic!("{json} has no {name} field"))
        + key.len();
    let rest = &json[start..];
    let end = rest
        .find(|c: char| c != '.' && c != '-' && !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end]
        .parse()
        .unwrap_or_else(|error| panic!("{name} in {json} is not a number: {error}"))
}

const MIB: f64 = 1024.0 * 1024.0;

/// A script that collects the heap and prints what the runtime reports.
///
/// Three full collections rather than one: a buffer that is only referenced from
/// a young-generation slot may survive the first, and reporting a mid-collection
/// figure would make the reclamation test flaky rather than wrong.
fn sampling(setup: &str) -> String {
    format!(
        r#"
        {setup}
        for (let i = 0; i < 3; i++) gc();
        const usage = process.memoryUsage();
        console.log(JSON.stringify({{
          arrayBuffers: usage.arrayBuffers,
          external: usage.external,
        }}));
        "#
    )
}

/// Resolves the pinned oracle once, skipping loudly when there is none.
fn oracle() -> Option<&'static rn_node_oracle::Oracle> {
    static ORACLE: std::sync::OnceLock<Option<rn_node_oracle::Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-cli arraybuffer accounting"))
        .as_ref()
}

/// Runs `script` under both runtimes.
fn both(script: &str) -> Option<(Sample, Sample)> {
    let oracle = oracle()?;
    let reference = measure(oracle.reference_path(), script);
    let rustnode = measure(env!("CARGO_BIN_EXE_rustnode"), script);
    println!(
        "oracle {reference:?} / rustnode {rustnode:?} for {}",
        script.lines().next().unwrap_or("").trim()
    );
    Some((reference, rustnode))
}

/// Asserts `sample.array_buffers` is inside `[low, high]` MiB.
fn assert_mib(sample: Sample, low: f64, high: f64, what: &str) {
    assert!(
        sample.array_buffers >= low * MIB && sample.array_buffers <= high * MIB,
        "{what}: arrayBuffers is {:.2} MiB, outside [{low}, {high}] MiB",
        sample.array_buffers / MIB
    );
}

#[test]
fn an_idle_isolate_reports_a_small_but_non_zero_figure() {
    // Node's own bootstrap holds a few small backing stores, so the baseline is
    // tens of kilobytes rather than zero. The upper bound is what catches a
    // counter that was never reset or that counts the whole heap; the exact
    // figure is not pinned because it depends on how many internal buffers the
    // bootstrap allocates.
    let Some((reference, rustnode)) = both(&sampling("")) else {
        return;
    };
    assert_mib(reference, 0.0, 4.0, "oracle baseline");
    assert_mib(rustnode, 0.0, 4.0, "rustnode baseline");
    assert!(
        rustnode.array_buffers > 0.0,
        "arrayBuffers is exactly zero on an isolate that must hold some backing stores"
    );
}

#[test]
fn a_thousand_sixty_four_kibibyte_views_are_counted_in_full() {
    // The shape measured when this defect was found: 1000 x 64 KiB is 62.5 MiB
    // of backing store, and both runtimes report it. The range is wide enough for
    // allocator overhead and narrow enough that a half-counted, doubled or
    // still-zero figure fails.
    let Some((reference, rustnode)) = both(&sampling(
        "const keep = [];
         for (let i = 0; i < 1000; i++) keep.push(new Uint8Array(65536));
         globalThis.retained = keep;",
    )) else {
        return;
    };
    assert_mib(reference, 55.0, 75.0, "oracle after 1000 x 64 KiB");
    assert_mib(rustnode, 55.0, 75.0, "rustnode after 1000 x 64 KiB");
}

#[test]
fn a_few_large_buffers_are_counted_and_external_is_not_doubled() {
    // `external` comes from `v8_heap_stats.external_memory()` and already
    // includes allocator memory, which is why it grew while `arrayBuffers` was
    // stuck at zero. A counting allocator that *also* called
    // `AdjustAmountOfExternalAllocatedMemory` would push `external` to roughly
    // twice the live bytes, so the two figures are compared against each other
    // here rather than each against a constant: they have to agree about the same
    // buffers.
    let Some((reference, rustnode)) = both(&sampling(
        "const keep = [
           new ArrayBuffer(8 * 1048576),
           new ArrayBuffer(8 * 1048576),
           new ArrayBuffer(8 * 1048576),
         ];
         globalThis.retained = keep;",
    )) else {
        return;
    };
    assert_mib(reference, 24.0, 34.0, "oracle after 3 x 8 MiB");
    assert_mib(rustnode, 24.0, 34.0, "rustnode after 3 x 8 MiB");

    for (name, sample) in [("oracle", reference), ("rustnode", rustnode)] {
        let excess = sample.external - sample.array_buffers;
        assert!(
            excess < 6.0 * MIB,
            "{name}: external ({:.2} MiB) exceeds arrayBuffers ({:.2} MiB) by more than the \
             non-buffer external memory this shape can account for, which is what double \
             counting would look like",
            sample.external / MIB,
            sample.array_buffers / MIB
        );
    }
}

#[test]
fn the_figure_falls_when_the_buffers_are_collected() {
    // The property a monotonic counter cannot have. Both figures are taken in one
    // process: grow to 62.5 MiB, drop every reference, collect, and read again.
    // The figure has to come back down to roughly where it started.
    //
    // The whole script is an IIFE because `-e` evaluates its source in a scope
    // that outlives the program, so `let keep` at the top level of `-e` stays
    // reachable and nothing is collected. Measured on the oracle: the same script
    // written to a file reclaims to 0.19 MiB, and passed to `-e` stays at
    // 62.63 MiB. That is a property of the harness, not of either runtime, and it
    // would make this test pass on a counter that never falls.
    let script = r#"
        (() => {
        const read = () => {
          for (let i = 0; i < 3; i++) gc();
          const usage = process.memoryUsage();
          return { arrayBuffers: usage.arrayBuffers, external: usage.external };
        };
        const before = read();
        let keep = [];
        for (let i = 0; i < 1000; i++) keep.push(new Uint8Array(65536));
        const grown = read();
        keep = null;
        const reclaimed = read();
        console.log(JSON.stringify({
          before: before.arrayBuffers,
          grown: grown.arrayBuffers,
          reclaimed: reclaimed.arrayBuffers,
          beforeExternal: before.external,
          grownExternal: grown.external,
          reclaimedExternal: reclaimed.external,
        }));
        })();
    "#;
    let oracle = match oracle() {
        Some(oracle) => oracle,
        None => return,
    };

    let output = Command::new(oracle.reference_path())
        .args(["--expose-gc", "-e", script])
        .output()
        .expect("the declared oracle runs");
    assert!(
        output.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reference = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let reference = reference.as_str();

    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["--expose-gc", "-e", script])
        .output()
        .expect("rustnode runs");
    assert!(
        output.status.success(),
        "rustnode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let actual = actual.as_str();

    for (name, line) in [("oracle", reference), ("rustnode", actual)] {
        let before = field(line, "before");
        let grown = field(line, "grown");
        let reclaimed = field(line, "reclaimed");
        assert!(
            grown - before > 55.0 * MIB,
            "{name}: growing 62.5 MiB of views moved arrayBuffers by only {:.2} MiB",
            (grown - before) / MIB
        );
        assert!(
            reclaimed < before + 4.0 * MIB,
            "{name}: arrayBuffers went {:.2} -> {:.2} -> {:.2} MiB and did not come back down, \
             so the counter is a high-water mark rather than live memory",
            before / MIB,
            grown / MIB,
            reclaimed / MIB
        );
        // The same has to be true of `external`, and for the same reason: it is
        // V8's own external accounting over the same backing stores, so a fix that
        // reclaimed `arrayBuffers` by decrementing a counter while leaking the
        // memory would show up here as an `external` that never falls.
        let grown_external = field(line, "grownExternal");
        let reclaimed_external = field(line, "reclaimedExternal");
        assert!(
            reclaimed_external < grown_external - 40.0 * MIB,
            "{name}: external stayed at {:.2} MiB after collection (from {:.2}), so the buffers \
             were not actually released",
            reclaimed_external / MIB,
            grown_external / MIB
        );
    }
}

#[test]
fn a_worker_reports_its_own_buffers_not_the_process_total() {
    // `arrayBuffers` is per `Environment` in Node: the main thread keeps 64 MiB
    // and a fresh worker still reports its own small baseline. An allocator shared
    // process-wide would make the worker report the parent's buffers, which is a
    // wrong answer that still looks like a working counter.
    let script = r#"
        const { Worker, isMainThread, parentPort } = require('node:worker_threads');
        const read = () => {
          for (let i = 0; i < 3; i++) gc();
          return process.memoryUsage().arrayBuffers;
        };
        if (isMainThread) {
          const keep = [];
          for (let i = 0; i < 16; i++) keep.push(new ArrayBuffer(4 * 1048576));
          const mainHeld = read();
          const worker = new Worker(`
            const { parentPort } = require('node:worker_threads');
            const read = () => {
              for (let i = 0; i < 3; i++) gc();
              return process.memoryUsage().arrayBuffers;
            };
            const empty = read();
            const keep = [];
            for (let i = 0; i < 8; i++) keep.push(new ArrayBuffer(4 * 1048576));
            const grown = read();
            parentPort.postMessage({ empty, grown });
          `, { eval: true });
          worker.on('message', (workerUsage) => {
            console.log(JSON.stringify({
              mainHeld,
              workerEmpty: workerUsage.empty,
              workerGrown: workerUsage.grown,
            }));
            worker.terminate();
          });
        }
    "#;
    let Some(oracle) = oracle() else {
        return;
    };

    let check = |name: &str, line: &str| {
        let main_held = field(line, "mainHeld");
        let worker_empty = field(line, "workerEmpty");
        let worker_grown = field(line, "workerGrown");
        assert!(
            main_held > 60.0 * MIB,
            "{name}: the main thread did not retain its 64 MiB of buffers ({:.2} MiB)",
            main_held / MIB
        );
        assert!(
            worker_empty < 4.0 * MIB,
            "{name}: a fresh worker reported {:.2} MiB, which is the parent's buffers rather \
             than its own",
            worker_empty / MIB
        );
        assert!(
            worker_grown - worker_empty > 28.0 * MIB,
            "{name}: a worker's own 32 MiB of buffers moved its figure by only {:.2} MiB",
            (worker_grown - worker_empty) / MIB
        );
    };

    for (name, binary) in [
        ("oracle", oracle.reference_path().to_string()),
        ("rustnode", env!("CARGO_BIN_EXE_rustnode").to_string()),
    ] {
        let output = Command::new(&binary)
            .args(["--expose-gc", "-e", script])
            .output()
            .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
        assert!(
            output.status.success(),
            "{name} exited {:?}; stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .rfind(|line| line.starts_with('{'))
            .unwrap_or_else(|| panic!("{name} printed no sample; stdout: {stdout}"));
        check(name, line);
    }
}
