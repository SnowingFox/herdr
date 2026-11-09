//! The numbered index constants, and everything else `lib/v8.js` compares by
//! value rather than by name.
//!
//! Each table is `(field name, index)` in ascending index order. The index is
//! both the value of the `k*Index` constant and the element of the statistics
//! buffer it addresses, so one table drives both and they cannot disagree.
//!
//! The values were recorded from a real Node binary (`--expose-internals`,
//! `internalBinding('v8')`) rather than read out of `src/node_v8.cc`, because
//! the C++ numbers its properties with a macro: reading the source only proves
//! the macro was transcribed correctly, not that this runtime and Node number
//! the fields the same way. `tests/parity.rs` re-records them from whatever Node
//! binary is on `PATH` when one is, so a Node upgrade that renumbers a field
//! fails a test instead of silently mislabelling every size.

/// `HEAP_STATISTICS_PROPERTIES` from `src/node_v8.cc`, in index order.
pub const HEAP_STATISTICS_INDEXES: &[(&str, usize)] = &[
    ("total_heap_size", 0),
    ("total_heap_size_executable", 1),
    ("total_physical_size", 2),
    ("total_available_size", 3),
    ("used_heap_size", 4),
    ("heap_size_limit", 5),
    ("malloced_memory", 6),
    ("peak_malloced_memory", 7),
    ("does_zap_garbage", 8),
    ("number_of_native_contexts", 9),
    ("number_of_detached_contexts", 10),
    ("total_global_handles_size", 11),
    ("used_global_handles_size", 12),
    ("external_memory", 13),
    ("total_allocated_bytes", 14),
];

/// `HEAP_SPACE_STATISTICS_PROPERTIES` from `src/node_v8.cc`, in index order.
pub const HEAP_SPACE_STATISTICS_INDEXES: &[(&str, usize)] = &[
    ("space_size", 0),
    ("space_used_size", 1),
    ("space_available_size", 2),
    ("physical_space_size", 3),
];

/// `HEAP_CODE_STATISTICS_PROPERTIES` from `src/node_v8.cc`, in index order.
pub const HEAP_CODE_STATISTICS_INDEXES: &[(&str, usize)] = &[
    ("code_and_metadata_size", 0),
    ("bytecode_and_metadata_size", 1),
    ("external_script_source_size", 2),
    ("cpu_profiler_metadata_size", 3),
];

/// The heap spaces `Isolate::GetHeapSpaceStatistics` reports, in the order its
/// index takes.
///
/// This is a snapshot of what V8 15.2 reports, and it has to be: `lib/v8.js`
/// builds `kNumberOfHeapSpaces` from this array's length and then indexes the
/// buffer by position. The names are listed in `HEAP_SPACES` order and the
/// isolate's own space count is checked against them at install time, so a V8
/// that added a space shows up as a startup error rather than as one space
/// quietly reporting another space's numbers.
pub const HEAP_SPACES: &[&str] = &[
    "read_only_space",
    "new_space",
    "old_space",
    "code_space",
    "shared_space",
    "trusted_space",
    "new_large_object_space",
    "large_object_space",
    "code_large_object_space",
    "shared_large_object_space",
    "trusted_large_object_space",
];

/// `v8::HeapProfiler::SamplingFlags::kSamplingNoFlags`.
pub const SAMPLING_NO_FLAGS: u32 = 0;

/// `v8::HeapProfiler::SamplingFlags::kSamplingForceGC`.
pub const SAMPLING_FORCE_GC: u32 = 1 << 0;

/// `v8::HeapProfiler::SamplingFlags::kSamplingIncludeObjectsCollectedByMajorGC`.
pub const SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MAJOR_GC: u32 = 1 << 1;

/// `v8::HeapProfiler::SamplingFlags::kSamplingIncludeObjectsCollectedByMinorGC`.
pub const SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MINOR_GC: u32 = 1 << 2;

/// `cppgc::HeapStatistics::DetailLevel::kBrief`.
pub const DETAIL_LEVEL_BRIEF: u8 = 0;

/// `cppgc::HeapStatistics::DetailLevel::kDetailed`.
pub const DETAIL_LEVEL_DETAILED: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recorded_heap_statistics_indexes_are_the_ones_node_exports() {
        // Recorded from `node --expose-internals` printing each
        // `k*Index` member of `internalBinding('v8')`.
        let expected = [
            ("total_heap_size", "kTotalHeapSizeIndex", 0),
            (
                "total_heap_size_executable",
                "kTotalHeapSizeExecutableIndex",
                1,
            ),
            ("total_physical_size", "kTotalPhysicalSizeIndex", 2),
            ("total_available_size", "kTotalAvailableSize", 3),
            ("used_heap_size", "kUsedHeapSizeIndex", 4),
            ("heap_size_limit", "kHeapSizeLimitIndex", 5),
            ("malloced_memory", "kMallocedMemoryIndex", 6),
            ("peak_malloced_memory", "kPeakMallocedMemoryIndex", 7),
            ("does_zap_garbage", "kDoesZapGarbageIndex", 8),
            (
                "number_of_native_contexts",
                "kNumberOfNativeContextsIndex",
                9,
            ),
            (
                "number_of_detached_contexts",
                "kNumberOfDetachedContextsIndex",
                10,
            ),
            (
                "total_global_handles_size",
                "kTotalGlobalHandlesSizeIndex",
                11,
            ),
            (
                "used_global_handles_size",
                "kUsedGlobalHandlesSizeIndex",
                12,
            ),
            ("external_memory", "kExternalMemoryIndex", 13),
            ("total_allocated_bytes", "kTotalAllocatedBytes", 14),
        ];
        assert_eq!(HEAP_STATISTICS_INDEXES.len(), expected.len());
        for ((field, index), (expected_field, _, expected_index)) in
            HEAP_STATISTICS_INDEXES.iter().zip(expected)
        {
            assert_eq!(*field, expected_field);
            assert_eq!(*index, expected_index, "{field} moved");
        }
    }

    #[test]
    fn the_heap_space_statistics_indexes_are_the_ones_node_exports() {
        // Recorded the same way: `kSpaceSizeIndex` is 0 and
        // `kPhysicalSpaceSizeIndex` is 3.
        assert_eq!(HEAP_SPACE_STATISTICS_INDEXES[0], ("space_size", 0));
        assert_eq!(HEAP_SPACE_STATISTICS_INDEXES[1], ("space_used_size", 1));
        assert_eq!(
            HEAP_SPACE_STATISTICS_INDEXES[2],
            ("space_available_size", 2)
        );
        assert_eq!(HEAP_SPACE_STATISTICS_INDEXES[3], ("physical_space_size", 3));
    }

    #[test]
    fn the_heap_code_statistics_indexes_are_the_ones_node_exports() {
        // `kCodeAndMetadataSizeIndex` 0, `kBytecodeAndMetadataSizeIndex` 1,
        // `kExternalScriptSourceSizeIndex` 2, `kCPUProfilerMetaDataSizeIndex`
        // 3 — including Node's unusual capitalisation of `MetaData`.
        assert_eq!(
            HEAP_CODE_STATISTICS_INDEXES[0],
            ("code_and_metadata_size", 0)
        );
        assert_eq!(
            HEAP_CODE_STATISTICS_INDEXES[1],
            ("bytecode_and_metadata_size", 1)
        );
        assert_eq!(
            HEAP_CODE_STATISTICS_INDEXES[2],
            ("external_script_source_size", 2)
        );
        assert_eq!(
            HEAP_CODE_STATISTICS_INDEXES[3],
            ("cpu_profiler_metadata_size", 3)
        );
    }
}
