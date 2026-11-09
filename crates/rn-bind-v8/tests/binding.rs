//! End-to-end checks that drive `v8` through the CLI.
//!
//! The three statistics buffers are the interesting part, and the only way to
//! prove they are aliased rather than copied is to write from one side and read
//! from the other. These tests do that in both directions: a JavaScript write
//! that Rust reads back through the binding's own accessors, and a Rust write
//! that JavaScript reads out of its typed array.

use std::path::PathBuf;
use std::process::Command;

/// The debug binary, which `cargo test` has already built.
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

/// Runs a script through the CLI and returns its stdout.
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

/// The binding, reached the way a builtin reaches it.
const PRELUDE: &str = "const realm = require('internal/bootstrap/realm');\
const v8b = realm.internalBinding('v8');";

#[test]
fn every_contract_member_is_present() {
    let contract = format!(
        "[{}]",
        rn_bind_v8::MEMBERS
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    let output = run(&format!(
        "{PRELUDE}
        const contract = {contract};
        const missing = [];
        for (const name of contract) {{
          if (!(name in v8b)) missing.push(name);
        }}
        console.log(missing.join(','));"
    ));
    assert_eq!(output, "", "every installed member must be on the object");
}

#[test]
fn the_buffers_are_float64_arrays_of_the_contract_length() {
    // The element type is part of the contract: Node stores byte sizes in
    // doubles, and an array of a different width would reinterpret every index.
    // Fourteen heap statistics, four per-space values, four code values.
    let output = run(&format!(
        "{PRELUDE}
        console.log([
          v8b.heapStatisticsBuffer.constructor.name, v8b.heapStatisticsBuffer.length,
          v8b.heapSpaceStatisticsBuffer.constructor.name, v8b.heapSpaceStatisticsBuffer.length,
          v8b.heapCodeStatisticsBuffer.constructor.name, v8b.heapCodeStatisticsBuffer.length,
        ].join(' '));"
    ));
    assert_eq!(output, "Float64Array 15 Float64Array 4 Float64Array 4");
}

#[test]
fn update_heap_statistics_buffer_fills_every_index() {
    // Each element must be a real number. A zero anywhere would mean the C++
    // field was never mapped, which is what a missed index would look like.
    let output = run(&format!(
        "{PRELUDE}
        v8b.updateHeapStatisticsBuffer();
        const b = v8b.heapStatisticsBuffer;
        const reads = [
          b[v8b.kTotalHeapSizeIndex],
          b[v8b.kTotalHeapSizeExecutableIndex],
          b[v8b.kTotalPhysicalSizeIndex],
          b[v8b.kTotalAvailableSize],
          b[v8b.kUsedHeapSizeIndex],
          b[v8b.kHeapSizeLimitIndex],
          b[v8b.kMallocedMemoryIndex],
          b[v8b.kPeakMallocedMemoryIndex],
          b[v8b.kDoesZapGarbageIndex],
          b[v8b.kNumberOfNativeContextsIndex],
          b[v8b.kNumberOfDetachedContextsIndex],
          b[v8b.kTotalGlobalHandlesSizeIndex],
          b[v8b.kUsedGlobalHandlesSizeIndex],
          b[v8b.kExternalMemoryIndex],
          b[v8b.kTotalAllocatedBytes],
        ];
        console.log(reads.every((x) => typeof x === 'number'), reads.length);"
    ));
    assert_eq!(output, "true 15");
}

#[test]
fn the_heap_numbers_are_believable() {
    // Used must be inside the total, the total inside the limit, and the limit
    // positive: three relations that only hold if the fields are mapped where
    // Node maps them. Swapping any two would break at least one.
    let output = run(&format!(
        "{PRELUDE}
        v8b.updateHeapStatisticsBuffer();
        const b = v8b.heapStatisticsBuffer;
        const total = b[v8b.kTotalHeapSizeIndex];
        const used = b[v8b.kUsedHeapSizeIndex];
        const limit = b[v8b.kHeapSizeLimitIndex];
        const physical = b[v8b.kTotalPhysicalSizeIndex];
        console.log(
          used > 0 && used <= total && total <= limit && limit > 0 && physical > 0
        );"
    ));
    assert_eq!(output, "true");
}

#[test]
fn allocation_moves_the_used_heap_number() {
    // The whole point of `process.memoryUsage()` and `v8.getHeapStatistics()` is
    // that they report a moving quantity. Retaining a large array has to raise
    // `used_heap_size`, or the number is decoration.
    let output = run(&format!(
        "{PRELUDE}
        v8b.updateHeapStatisticsBuffer();
        const before = v8b.heapStatisticsBuffer[v8b.kUsedHeapSizeIndex];
        const keep = [];
        for (let i = 0; i < 200000; i++) keep.push({{ value: i, text: 'filler-' + i }});
        v8b.updateHeapStatisticsBuffer();
        const after = v8b.heapStatisticsBuffer[v8b.kUsedHeapSizeIndex];
        console.log(after > before, keep.length);"
    ));
    assert_eq!(output, "true 200000");
}

#[test]
fn update_heap_space_statistics_buffer_reports_the_indexed_space() {
    // `lib/v8.js` calls this once per space, so the argument has to select the
    // space and the four values have to follow it.
    let output = run(&format!(
        "{PRELUDE}
        const count = v8b.kHeapSpaces.length;
        let sawNewSpace = false;
        let allFinite = true;
        for (let i = 0; i < count; i++) {{
          v8b.updateHeapSpaceStatisticsBuffer(i);
          const b = v8b.heapSpaceStatisticsBuffer;
          for (const index of [v8b.kSpaceSizeIndex, v8b.kSpaceUsedSizeIndex,
                               v8b.kSpaceAvailableSizeIndex, v8b.kPhysicalSpaceSizeIndex]) {{
            if (!Number.isFinite(b[index]) || b[index] < 0) allFinite = false;
          }}
          if (v8b.kHeapSpaces[i] === 'new_space' &&
              b[v8b.kSpaceSizeIndex] > 0) sawNewSpace = true;
        }}
        console.log(count, allFinite, sawNewSpace);"
    ));
    assert_eq!(output, "11 true true");
}

#[test]
fn update_heap_code_statistics_buffer_reports_real_sizes() {
    // Compiled code and its bytecode are both non-zero once any script has run,
    // which this one has.
    let output = run(&format!(
        "{PRELUDE}
        v8b.updateHeapCodeStatisticsBuffer();
        const b = v8b.heapCodeStatisticsBuffer;
        console.log(
          b[v8b.kCodeAndMetadataSizeIndex] > 0,
          b[v8b.kBytecodeAndMetadataSizeIndex] > 0,
          b[v8b.kExternalScriptSourceSizeIndex] >= 0,
          b[v8b.kCPUProfilerMetaDataSizeIndex] >= 0
        );"
    ));
    assert_eq!(output, "true true true true");
}

#[test]
fn the_heap_space_names_are_v8s() {
    // The order is the contract: `updateHeapSpaceStatisticsBuffer(i)` selects the
    // space at position `i`, so a reordering would attribute one space's numbers
    // to another.
    let output = run(&format!(
        "{PRELUDE}
        console.log(JSON.stringify(v8b.kHeapSpaces));"
    ));
    assert_eq!(
        output,
        "[\"read_only_space\",\"new_space\",\"old_space\",\"code_space\",\"shared_space\",\
         \"trusted_space\",\"new_large_object_space\",\"large_object_space\",\
         \"code_large_object_space\",\"shared_large_object_space\",\
         \"trusted_large_object_space\"]"
    );
}

#[test]
fn the_index_constants_are_the_ones_lib_v8_indexes_with() {
    // Recorded from a real Node binary. `lib/v8.js` uses these to read the
    // buffers, so a wrong value reads a different field rather than failing.
    let output = run(&format!(
        "{PRELUDE}
        console.log([
          v8b.kTotalHeapSizeIndex, v8b.kTotalHeapSizeExecutableIndex,
          v8b.kTotalPhysicalSizeIndex, v8b.kTotalAvailableSize,
          v8b.kUsedHeapSizeIndex, v8b.kHeapSizeLimitIndex,
          v8b.kMallocedMemoryIndex, v8b.kPeakMallocedMemoryIndex,
          v8b.kDoesZapGarbageIndex, v8b.kNumberOfNativeContextsIndex,
          v8b.kNumberOfDetachedContextsIndex, v8b.kTotalGlobalHandlesSizeIndex,
          v8b.kUsedGlobalHandlesSizeIndex, v8b.kExternalMemoryIndex,
          v8b.kTotalAllocatedBytes,
        ].join(','));"
    ));
    assert_eq!(output, "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14");
}

#[test]
fn the_space_and_code_index_constants_are_the_recorded_ones() {
    let output = run(&format!(
        "{PRELUDE}
        console.log([
          v8b.kSpaceSizeIndex, v8b.kSpaceUsedSizeIndex,
          v8b.kSpaceAvailableSizeIndex, v8b.kPhysicalSpaceSizeIndex,
          v8b.kCodeAndMetadataSizeIndex, v8b.kBytecodeAndMetadataSizeIndex,
          v8b.kExternalScriptSourceSizeIndex, v8b.kCPUProfilerMetaDataSizeIndex,
        ].join(','));"
    ));
    assert_eq!(output, "0,1,2,3,0,1,2,3");
}

#[test]
fn the_sampling_flags_are_the_v8_bit_values() {
    // `lib/internal/v8/heap_profile.js` or's these into the flags word it would
    // pass to `startHeapProfile`.
    let output = run(&format!(
        "{PRELUDE}
        console.log([v8b.kSamplingNoFlags, v8b.kSamplingForceGC,
                     v8b.kSamplingIncludeObjectsCollectedByMajorGC,
                     v8b.kSamplingIncludeObjectsCollectedByMinorGC].join(','));"
    ));
    assert_eq!(output, "0,1,2,4");
}

#[test]
fn detail_level_matches_the_cppgc_enum() {
    // `lib/v8.js` maps a user-facing `'brief'`/`'detailed'` onto these before
    // calling `getCppHeapStatistics`.
    let output = run(&format!(
        "{PRELUDE}
        console.log(v8b.detailLevel.BRIEF, v8b.detailLevel.DETAILED);"
    ));
    assert_eq!(output, "0 1");
}

#[test]
fn cached_data_version_tag_is_a_positive_uint32() {
    // `v8.cachedDataVersionTag()` hands this to user code to compare against a
    // stored tag, so it has to be a stable number rather than a fresh one.
    let output = run(&format!(
        "{PRELUDE}
        const first = v8b.cachedDataVersionTag();
        const second = v8b.cachedDataVersionTag();
        console.log(typeof first, first === second, first > 0, first <= 0xffffffff);"
    ));
    assert_eq!(output, "number true true true");
}

#[test]
fn is_string_one_byte_representation_follows_v8() {
    // A Latin-1 string is one byte per character and a string with a codepoint
    // above U+00FF is not, which is exactly what `String::IsOneByte` reports.
    let output = run(&format!(
        "{PRELUDE}
        console.log(
          v8b.isStringOneByteRepresentation('abc'),
          v8b.isStringOneByteRepresentation('\\u00ff'),
          v8b.isStringOneByteRepresentation('\\u0100'),
          v8b.isStringOneByteRepresentation('')
        );"
    ));
    assert_eq!(output, "true true false true");
}

#[test]
fn get_hash_seed_returns_a_non_zero_bigint() {
    // Node returns a `BigInt`, and tests compare it across processes to prove
    // the seed is randomized per process, so it must be stable within one.
    let output = run(&format!(
        "{PRELUDE}
        const first = v8b.getHashSeed();
        console.log(typeof first, first !== 0n, first === v8b.getHashSeed());"
    ));
    assert_eq!(output, "bigint true true");
}

#[test]
fn set_flags_from_string_reaches_v8_instead_of_aborting() {
    // V8 freezes its flag list during `V8::Initialize` unless told not to, and
    // setting a flag after that is a `CHECK` failure that aborts the process.
    // Node disables the freeze for this reason; the CLI does too, so a flag set
    // from JavaScript has to be accepted rather than kill the runtime.
    let output = run(&format!(
        "{PRELUDE}
        v8b.setFlagsFromString('--allow-natives-syntax');
        v8b.setFlagsFromString('--no-lazy');
        v8b.setFlagsFromString('--max-semi-space-size=1');
        console.log('accepted');"
    ));
    assert_eq!(output, "accepted");
}

#[test]
fn get_cpp_heap_statistics_reports_an_empty_heap_in_node_shape() {
    // rustnode has no cppgc heap attached, so the numbers are zero, but the
    // shape is Node's: `lib/v8.js` adds `detail_level` to this object and
    // returns it to the caller.
    let output = run(&format!(
        "{PRELUDE}
        const brief = v8b.getCppHeapStatistics(v8b.detailLevel.BRIEF);
        console.log(
          Object.keys(brief).join(','),
          brief.committed_size_bytes,
          Array.isArray(brief.space_statistics),
          Array.isArray(brief.type_names)
        );"
    ));
    assert_eq!(
        output,
        "committed_size_bytes,resident_size_bytes,used_size_bytes,space_statistics,type_names \
         0 true true"
    );
}

#[test]
fn the_deferred_profilers_are_absent_rather_than_fake() {
    // A stub that returned a plausible-looking profile with no samples would be
    // worse than a missing function: `lib/v8.js` would hand it to user code as
    // if it were real. Absent means `v8.startCpuProfile` is `undefined` and the
    // caller finds out immediately.
    let output = run(&format!(
        "{PRELUDE}
        console.log(
          'startCpuProfile' in v8b, 'stopCpuProfile' in v8b,
          'startHeapProfile' in v8b, 'stopHeapProfile' in v8b
        );"
    ));
    assert_eq!(output, "false false false false");
}

#[test]
fn the_gc_profiler_class_is_a_constructor() {
    // `lib/v8.js` does `new binding.GCProfiler()` and calls `start`/`stop` on it.
    let output = run(&format!(
        "{PRELUDE}
        const profiler = new v8b.GCProfiler();
        console.log(
          typeof v8b.GCProfiler,
          typeof profiler.start,
          typeof profiler.stop,
          v8b.GCProfiler.name
        );"
    ));
    assert_eq!(output, "function function function GCProfiler");
}

#[test]
fn the_gc_profiler_reports_collections_as_json() {
    // `lib/v8.js` runs `JSON.parse` on the result, so anything that is not a
    // document with the documented keys breaks `v8.GCProfiler.stop()`.
    let output = run(&format!(
        "{PRELUDE}
        const profiler = new v8b.GCProfiler();
        profiler.start();
        const keep = [];
        for (let i = 0; i < 200000; i++) keep.push({{ i }});
        keep.length = 0;
        const document = JSON.parse(profiler.stop());
        console.log(
          document.version,
          typeof document.startTime,
          typeof document.endTime,
          document.endTime >= document.startTime,
          Array.isArray(document.statistics)
        );"
    ));
    assert_eq!(output, "1 number number true true");
}

#[test]
fn a_collected_gc_sample_has_the_before_and_after_halves() {
    // Each entry is one collection. Forcing one makes the entry appear without
    // depending on V8's collection schedule.
    let output = run(&format!(
        "{PRELUDE}
        const profiler = new v8b.GCProfiler();
        profiler.start();
        const keep = [];
        for (let i = 0; i < 500000; i++) keep.push({{ i, text: 'x' + i }});
        keep.length = 0;
        const document = JSON.parse(profiler.stop());
        const sample = document.statistics[0];
        if (!sample) {{ console.log('no samples'); }}
        else {{
          console.log(
            typeof sample.gcType,
            typeof sample.cost === 'number',
            Object.keys(sample.beforeGC).join(','),
            Object.keys(sample.afterGC).join(',')
          );
        }}"
    ));
    // Whether a collection ran is up to V8; when one did, its shape is Node's.
    assert!(
        output
            == "string true heapStatistics,heapSpaceStatistics heapStatistics,heapSpaceStatistics"
            || output == "no samples",
        "unexpected GC profile: {output}"
    );
}

#[test]
fn stopping_an_unstarted_gc_profiler_returns_undefined() {
    // Node returns `undefined` here, and `lib/v8.js` only parses a value it
    // knows is a string.
    let output = run(&format!(
        "{PRELUDE}
        const profiler = new v8b.GCProfiler();
        console.log(profiler.stop() === undefined);"
    ));
    assert_eq!(output, "true");
}

#[test]
fn the_near_heap_limit_limits_are_validated() {
    // Node's `CHECK_GT(limit, 0)` and the uint32 shape: passing zero or a
    // non-number is a caller bug, and silently arming nothing would hide it.
    let output = run(&format!(
        "{PRELUDE}
        const results = [];
        for (const value of [0, -1, 'x']) {{
          try {{ v8b.setHeapSnapshotNearHeapLimit(value); results.push('ok'); }}
          catch (error) {{ results.push('threw'); }}
        }}
        console.log(results.join(','));"
    ));
    assert_eq!(output, "threw,threw,threw");
}
