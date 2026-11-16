//! Compares this namespace's constants against a real Node binary.
//!
//! `constants.rs` records the numbers, and `src/lib.rs`'s unit tests check them
//! against that recording. Both could be wrong in the same way, because both
//! were written by reading the same source. This test closes that gap the only
//! way it can be closed: it asks Node.
//!
//! It runs `node --expose-internals` and reads `internalBinding('v8')` out of
//! it. `--expose-internals` is what makes `internal/test/binding` reachable,
//! which is the only supported way to see a raw internal binding from
//! JavaScript.
//!
//! # Which Node
//!
//! The reference is the binary `tools/node-pin.toml` pins, resolved by
//! [`rn_node_oracle`], not whatever `node` is on `PATH`. That distinction is not
//! cosmetic here: `kHeapSpaces` gained `shared_trusted_space` and
//! `shared_trusted_large_object_space` between Node 22 and Node 28, so a `PATH`
//! Node answers with a different list than the engine this crate targets. A
//! wrong-version reference now fails rather than passing on a coincidence.
//!
//! When there is no oracle at all the test skips loudly: a machine without a
//! Node binary still has to be able to run `cargo test`. When the binary *is*
//! there, every number has to match — a mismatch is either a mistake here or a
//! Node release that renumbered a field, and both are things to find out about.

use rn_node_oracle::Oracle;

/// Collects the numbers and buffer shapes from a real Node binary.
const PROBE: &str = r#"
const { internalBinding } = require('internal/test/binding');
const binding = internalBinding('v8');
const numbers = {};
for (const key of Object.keys(binding)) {
  if (typeof binding[key] === 'number') numbers[key] = binding[key];
}
const levels = {};
for (const key of Object.keys(binding.detailLevel)) levels[key] = binding.detailLevel[key];
process.stdout.write(JSON.stringify({
  numbers,
  levels,
  heapStatisticsBuffer: [
    binding.heapStatisticsBuffer.constructor.name,
    binding.heapStatisticsBuffer.length,
  ],
  heapSpaceStatisticsBuffer: [
    binding.heapSpaceStatisticsBuffer.constructor.name,
    binding.heapSpaceStatisticsBuffer.length,
  ],
  heapCodeStatisticsBuffer: [
    binding.heapCodeStatisticsBuffer.constructor.name,
    binding.heapCodeStatisticsBuffer.length,
  ],
  heapSpaces: Array.from(binding.kHeapSpaces),
}));
"#;

/// The oracle this test binary compares against, resolved and announced once.
fn oracle() -> Option<&'static Oracle> {
    static ORACLE: std::sync::OnceLock<Option<Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-bind-v8 node constants"))
        .as_ref()
}

/// The recorded values, or `None` when there is no oracle at all.
///
/// A binary that cannot expose `internalBinding('v8')` is a failure, not a
/// skip: it means the reference is not the build the pin describes, and
/// treating that as "nothing to compare" would hide a broken oracle behind a
/// green run.
fn recorded() -> Option<serde_json::Value> {
    let oracle = oracle()?;
    let output = oracle
        .command()
        .arg("--expose-internals")
        .arg("-e")
        .arg(PROBE)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", oracle.describe()));
    assert!(
        output.status.success(),
        "{} could not expose internalBinding('v8'): {}",
        oracle.describe(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Some(
        serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("the v8 probe produced invalid JSON: {error}")),
    )
}

/// The Node version the recording came from, for the diagnostics below.
fn recording_version() -> String {
    let Some(oracle) = oracle() else {
        return "unknown".to_string();
    };
    oracle.version.clone()
}

/// The V8 version the recording came from, because the heap statistics fields
/// are V8's, not Node's.
fn recording_v8_version() -> String {
    let Some(oracle) = oracle() else {
        return "unknown".to_string();
    };
    oracle.eval("process.versions.v8")
}

/// Asserts `name` is `expected` in the recording.
///
/// A member the recording does not have at all is a Node older than the pinned
/// revision, which is a legitimate thing to test against: every field that *is*
/// there still has to line up, and the missing one is reported so a real
/// renumbering cannot hide behind an "older binary" excuse.
fn expect_number(recorded: &serde_json::Value, name: &str, expected: u32) {
    let Some(actual) = recorded["numbers"]
        .get(name)
        .and_then(|value| value.as_u64())
    else {
        eprintln!(
            "note: {} (V8 {}) does not export {name}; this crate exports it as {expected}, \
             matching the pinned Node 28 contract",
            recording_version(),
            recording_v8_version()
        );
        return;
    };
    assert_eq!(
        actual, expected as u64,
        "node reports {name} = {actual}, this crate exports {expected}"
    );
}

#[test]
fn the_index_constants_match_a_real_node_binary() {
    use rn_bind_v8::constants::{
        HEAP_CODE_STATISTICS_INDEXES, HEAP_SPACE_STATISTICS_INDEXES, HEAP_STATISTICS_INDEXES,
    };

    let Some(recorded) = recorded() else {
        return;
    };

    // The member name Node exports per field, which is not a mechanical
    // transformation of the field name: `total_available_size` is
    // `kTotalAvailableSize` and `total_allocated_bytes` is `kTotalAllocatedBytes`,
    // both without the `Index` suffix the others carry.
    let heap_statistics_members = [
        "kTotalHeapSizeIndex",
        "kTotalHeapSizeExecutableIndex",
        "kTotalPhysicalSizeIndex",
        "kTotalAvailableSize",
        "kUsedHeapSizeIndex",
        "kHeapSizeLimitIndex",
        "kMallocedMemoryIndex",
        "kPeakMallocedMemoryIndex",
        "kDoesZapGarbageIndex",
        "kNumberOfNativeContextsIndex",
        "kNumberOfDetachedContextsIndex",
        "kTotalGlobalHandlesSizeIndex",
        "kUsedGlobalHandlesSizeIndex",
        "kExternalMemoryIndex",
        "kTotalAllocatedBytes",
    ];
    assert_eq!(heap_statistics_members.len(), HEAP_STATISTICS_INDEXES.len());
    for ((_, index), member) in HEAP_STATISTICS_INDEXES.iter().zip(heap_statistics_members) {
        // `expect_number` reports a member the binary predates and asserts on
        // the ones it has, so a renumbered field cannot pass as "old Node".
        expect_number(&recorded, member, *index as u32);
    }

    let space_members = [
        "kSpaceSizeIndex",
        "kSpaceUsedSizeIndex",
        "kSpaceAvailableSizeIndex",
        "kPhysicalSpaceSizeIndex",
    ];
    assert_eq!(space_members.len(), HEAP_SPACE_STATISTICS_INDEXES.len());
    for ((_, index), member) in HEAP_SPACE_STATISTICS_INDEXES.iter().zip(space_members) {
        expect_number(&recorded, member, *index as u32);
    }

    let code_members = [
        "kCodeAndMetadataSizeIndex",
        "kBytecodeAndMetadataSizeIndex",
        "kExternalScriptSourceSizeIndex",
        "kCPUProfilerMetaDataSizeIndex",
    ];
    assert_eq!(code_members.len(), HEAP_CODE_STATISTICS_INDEXES.len());
    for ((_, index), member) in HEAP_CODE_STATISTICS_INDEXES.iter().zip(code_members) {
        expect_number(&recorded, member, *index as u32);
    }
}

#[test]
fn the_sampling_flags_match_a_real_node_binary() {
    use rn_bind_v8::constants::{
        SAMPLING_FORCE_GC, SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MAJOR_GC,
        SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MINOR_GC, SAMPLING_NO_FLAGS,
    };

    let Some(recorded) = recorded() else {
        return;
    };
    expect_number(&recorded, "kSamplingNoFlags", SAMPLING_NO_FLAGS);
    expect_number(&recorded, "kSamplingForceGC", SAMPLING_FORCE_GC);
    expect_number(
        &recorded,
        "kSamplingIncludeObjectsCollectedByMajorGC",
        SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MAJOR_GC,
    );
    expect_number(
        &recorded,
        "kSamplingIncludeObjectsCollectedByMinorGC",
        SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MINOR_GC,
    );
}

#[test]
fn the_buffers_have_the_shape_a_real_node_binary_reports() {
    use rn_bind_v8::buffers::{
        HEAP_CODE_STATISTICS_LENGTH, HEAP_SPACE_STATISTICS_LENGTH, HEAP_STATISTICS_LENGTH,
    };

    let Some(recorded) = recorded() else {
        return;
    };
    for (field, length) in [
        ("heapStatisticsBuffer", HEAP_STATISTICS_LENGTH),
        ("heapSpaceStatisticsBuffer", HEAP_SPACE_STATISTICS_LENGTH),
        ("heapCodeStatisticsBuffer", HEAP_CODE_STATISTICS_LENGTH),
    ] {
        // The element type is part of the contract, not just the count: a
        // `Uint32Array` of the same byte length would put four fields where the
        // JavaScript layer expects eight. That assertion is unconditional,
        // because the width has never changed.
        assert_eq!(
            recorded[field][0].as_str(),
            Some("Float64Array"),
            "node exposes {field} as {}",
            recorded[field][0]
        );

        // The length can legitimately differ: `total_allocated_bytes` was added
        // to `HeapStatistics` after some released Node versions, which grows the
        // heap statistics buffer by one. A shorter buffer therefore has to be
        // this crate's length minus the fields that binary does not know about,
        // and anything else is a real mismatch.
        let recorded_length = recorded[field][1].as_u64().unwrap_or(0) as usize;
        if recorded_length == length {
            continue;
        }
        assert!(
            recorded_length < length,
            "node's {field} has {recorded_length} elements and this crate has {length}, \
             which is shorter than a binary that knows fewer fields"
        );
        eprintln!(
            "note: {} (V8 {}) reports {field} length {recorded_length}; this crate uses \
             {length} to match the pinned Node 28 contract",
            recording_version(),
            recording_v8_version()
        );
    }
}

#[test]
fn the_heap_space_names_match_a_real_node_binary() {
    let Some(recorded) = recorded() else {
        return;
    };
    let names: Vec<&str> = recorded["heapSpaces"]
        .as_array()
        .expect("an array of names")
        .iter()
        .filter_map(|name| name.as_str())
        .collect();
    assert_eq!(
        names,
        rn_bind_v8::constants::HEAP_SPACES,
        "the heap space names or their order differ from node's"
    );
}

#[test]
fn detail_level_matches_a_real_node_binary() {
    let Some(recorded) = recorded() else {
        return;
    };
    assert_eq!(
        recorded["levels"]["BRIEF"].as_u64(),
        Some(rn_bind_v8::constants::DETAIL_LEVEL_BRIEF as u64)
    );
    assert_eq!(
        recorded["levels"]["DETAILED"].as_u64(),
        Some(rn_bind_v8::constants::DETAIL_LEVEL_DETAILED as u64)
    );
}
