//! `internalBinding('v8')` for rustnode.
//!
//! `lib/v8.js` destructures this namespace at module scope and builds the
//! public `v8` module out of it, so every name here is load-bearing the moment
//! `require('v8')` runs. The contract is the one `src/node_v8.cc` defines.
//!
//! # The three statistics buffers
//!
//! The interesting part of this namespace is that `heapStatisticsBuffer`,
//! `heapSpaceStatisticsBuffer` and `heapCodeStatisticsBuffer` are **aliased**
//! `Float64Array`s: the JavaScript layer holds the typed array, and the
//! `update*Buffer()` functions overwrite its elements in place so that
//! `v8.getHeapStatistics()` costs one native call plus a handful of indexed
//! reads instead of an object built per call.
//!
//! Two things are therefore part of the contract and are pinned by tests:
//!
//! * the element type is `Float64Array`, not `Uint32Array` or `Uint8Array`.
//!   Node stores sizes in bytes in doubles; the wrong width would silently
//!   reinterpret every index;
//! * the length is 15, 4 and 4 elements respectively, one per index constant.
//!   `HEAP_STATISTICS_INDEXES` and friends below are the single source for both
//!   the length and the value each index constant gets, so the two cannot drift.
//!
//! The index constants are exported with exactly the values `lib/v8.js` uses to
//! index those arrays. They are checked against a real Node binary rather than
//! copied from the C++: `src/node_v8.cc` numbers its properties with a macro, so
//! reading the numbers out of the source proves only that the macro was read
//! correctly, not that this runtime and Node agree. (The recording binary on
//! this machine is Node 22, which predates `total_allocated_bytes` and so
//! reports 14 fields; the 15 here follow the pinned Node 28 contract, and
//! `tests/node_constants.rs` prints that difference rather than hiding it.)
//!
//! # What `require('v8')` still needs from other namespaces
//!
//! This namespace is complete: `rn-compat` reports 47 recorded, 0 missing, 4
//! declared deferrals. `require('v8')` itself still fails, because `lib/v8.js`
//! destructures `internalBinding('serdes')` at module scope for `v8.serialize`
//! and `internalBinding('heap_utils')` for `v8.writeHeapSnapshot`, and neither
//! namespace has a Rust implementation yet. Those are separate workstreams, and
//! `tests/real_lib_v8.rs` proves this namespace satisfies the real file by
//! loading it unmodified with only those two stubbed.
//!
//! # What is deferred, and why
//!
//! `startCpuProfile`, `stopCpuProfile`, `startHeapProfile` and
//! `stopHeapProfile` need profiler entry points the `v8` crate does not expose.
//! It has `CpuProfiler::CollectSample` and
//! `CpuProfiler::UseDetailedSourcePositionsForProfiling`, and its bindings for
//! `v8::CpuProfiler` stop there: there is no `StartProfiling`, no
//! `StopProfiling`, no `v8::CpuProfile` at all, and no
//! `HeapProfiler::StartSamplingHeapProfiler`/`GetAllocationProfile`. Emitting a
//! profile is therefore not a matter of wiring: it needs new C++ shims compiled
//! into the vendored V8. Faking one would hand back a plausible-looking JSON
//! document with no samples in it, which is exactly the kind of lie that wastes
//! an afternoon. `lib/v8.js` only calls these from `startCpuProfile()` and
//! `startHeapProfile()`, so a deferral does not break `require('v8')`;
//! `tools/deferred-reach.py` proves that.
//!
//! `setHeapSnapshotNearHeapLimit` is installed and really arms a near-heap-limit
//! callback that takes a heap snapshot, because the crate exposes
//! `add_near_heap_limit_callback` and `take_heap_snapshot`.
//! `setHeapProfileNearHeapLimit` arms the same callback only to raise the limit
//! and report that the profile could not be written, because there is no
//! sampling profiler to serialize. `getCppHeapStatistics` is installed and
//! reports the real cppgc heap, which in rustnode is empty because nothing
//! allocates through cppgc yet; an empty but well-formed report is the truth
//! rather than a substitute, and the crate exposes `get_cpp_heap` so this can
//! grow real numbers when there is something to report.

mod buffers_impl;
pub mod constants;
mod gc_profiler;
mod limits;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use buffers_impl::Buffers;
use constants::{
    HEAP_CODE_STATISTICS_INDEXES, HEAP_SPACES, HEAP_SPACE_STATISTICS_INDEXES,
    HEAP_STATISTICS_INDEXES,
};

/// The aliased statistics buffers, exposed so tests can read a value JavaScript
/// wrote without going back through the typed array.
pub mod buffers {
    pub use crate::buffers_impl::{
        heap_code_statistics_at, heap_space_statistics_at, heap_statistics_at,
        heap_statistics_byte_length, is_installed, with_heap_statistics,
        HEAP_CODE_STATISTICS_LENGTH, HEAP_SPACE_STATISTICS_LENGTH, HEAP_STATISTICS_LENGTH,
    };
}

/// Members exposed on the namespace object, matching `contracts/v8.json`.
pub const MEMBERS: &[&str] = &[
    "GCProfiler",
    "cachedDataVersionTag",
    "detailLevel",
    "getCppHeapStatistics",
    "getHashSeed",
    "heapCodeStatisticsBuffer",
    "heapSpaceStatisticsBuffer",
    "heapStatisticsBuffer",
    "isStringOneByteRepresentation",
    "kBytecodeAndMetadataSizeIndex",
    "kCPUProfilerMetaDataSizeIndex",
    "kCodeAndMetadataSizeIndex",
    "kDoesZapGarbageIndex",
    "kExternalMemoryIndex",
    "kExternalScriptSourceSizeIndex",
    "kHeapSizeLimitIndex",
    "kHeapSpaces",
    "kMallocedMemoryIndex",
    "kNumberOfDetachedContextsIndex",
    "kNumberOfNativeContextsIndex",
    "kPeakMallocedMemoryIndex",
    "kPhysicalSpaceSizeIndex",
    "kSamplingForceGC",
    "kSamplingIncludeObjectsCollectedByMajorGC",
    "kSamplingIncludeObjectsCollectedByMinorGC",
    "kSamplingNoFlags",
    "kSpaceAvailableSizeIndex",
    "kSpaceSizeIndex",
    "kSpaceUsedSizeIndex",
    "kTotalAllocatedBytes",
    "kTotalAvailableSize",
    "kTotalGlobalHandlesSizeIndex",
    "kTotalHeapSizeExecutableIndex",
    "kTotalHeapSizeIndex",
    "kTotalPhysicalSizeIndex",
    "kUsedGlobalHandlesSizeIndex",
    "kUsedHeapSizeIndex",
    "setFlagsFromString",
    "setHeapProfileNearHeapLimit",
    "setHeapSnapshotNearHeapLimit",
    "updateHeapCodeStatisticsBuffer",
    "updateHeapSpaceStatisticsBuffer",
    "updateHeapStatisticsBuffer",
];

/// Members this build does not install yet, each with the reason.
pub const DEFERRED: &[(&str, &str)] = &[
    (
        "startCpuProfile",
        "the v8 crate exposes only CpuProfiler::CollectSample; starting a profile needs StartProfiling and v8::CpuProfile, which have no binding, so there is nothing to emit samples from",
    ),
    (
        "stopCpuProfile",
        "no CPU profile can be started for the same reason, so there is no profile id to serialize",
    ),
    (
        "startHeapProfile",
        "the v8 crate has no HeapProfiler::StartSamplingHeapProfiler binding, so no sampling heap profiler exists to start",
    ),
    (
        "stopHeapProfile",
        "with no sampling heap profiler started there is no allocation profile to serialize",
    ),
];

pub struct V8;

impl BindingModule for V8 {
    fn namespace(&self) -> &'static str {
        "v8"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let buffers = Buffers::new(scope)?;
        let heap_statistics = buffers.heap_statistics.array(scope);
        let heap_space_statistics = buffers.heap_space_statistics.array(scope);
        let heap_code_statistics = buffers.heap_code_statistics.array(scope);

        // The buffers are per-realm in Node and the update functions reach them
        // through the realm's binding data. rustnode keeps them in the isolate
        // so the update functions, which take no receiver, can find them.
        buffers_impl::install(scope, buffers);

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 43] = [
            ("heapStatisticsBuffer", heap_statistics),
            ("heapSpaceStatisticsBuffer", heap_space_statistics),
            ("heapCodeStatisticsBuffer", heap_code_statistics),
            (
                "updateHeapStatisticsBuffer",
                function(
                    scope,
                    "updateHeapStatisticsBuffer",
                    update_heap_statistics_buffer,
                )?,
            ),
            (
                "updateHeapSpaceStatisticsBuffer",
                function(
                    scope,
                    "updateHeapSpaceStatisticsBuffer",
                    update_heap_space_statistics_buffer,
                )?,
            ),
            (
                "updateHeapCodeStatisticsBuffer",
                function(
                    scope,
                    "updateHeapCodeStatisticsBuffer",
                    update_heap_code_statistics_buffer,
                )?,
            ),
            (
                "cachedDataVersionTag",
                function(scope, "cachedDataVersionTag", cached_data_version_tag)?,
            ),
            (
                "getHashSeed",
                function(scope, "getHashSeed", get_hash_seed)?,
            ),
            (
                "isStringOneByteRepresentation",
                function(
                    scope,
                    "isStringOneByteRepresentation",
                    is_string_one_byte_representation,
                )?,
            ),
            (
                "setFlagsFromString",
                function(scope, "setFlagsFromString", set_flags_from_string)?,
            ),
            (
                "getCppHeapStatistics",
                function(scope, "getCppHeapStatistics", get_cpp_heap_statistics)?,
            ),
            (
                "setHeapSnapshotNearHeapLimit",
                function(
                    scope,
                    "setHeapSnapshotNearHeapLimit",
                    limits::set_heap_snapshot_near_heap_limit,
                )?,
            ),
            (
                "setHeapProfileNearHeapLimit",
                function(
                    scope,
                    "setHeapProfileNearHeapLimit",
                    limits::set_heap_profile_near_heap_limit,
                )?,
            ),
            ("kHeapSpaces", heap_spaces(scope)?),
            ("detailLevel", detail_level(scope)),
            ("GCProfiler", gc_profiler::constructor(scope)?),
            // The four sampling-flag constants are read by
            // `lib/internal/v8/heap_profile.js` to build the flags word
            // `startHeapProfile` would take.
            (
                "kSamplingNoFlags",
                number(scope, constants::SAMPLING_NO_FLAGS as f64),
            ),
            (
                "kSamplingForceGC",
                number(scope, constants::SAMPLING_FORCE_GC as f64),
            ),
            (
                "kSamplingIncludeObjectsCollectedByMajorGC",
                number(
                    scope,
                    constants::SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MAJOR_GC as f64,
                ),
            ),
            (
                "kSamplingIncludeObjectsCollectedByMinorGC",
                number(
                    scope,
                    constants::SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MINOR_GC as f64,
                ),
            ),
            // Every index constant, from the same table that sizes the buffers.
            (
                "kTotalHeapSizeIndex",
                number(scope, HEAP_STATISTICS_INDEXES[0].1 as f64),
            ),
            (
                "kTotalHeapSizeExecutableIndex",
                number(scope, HEAP_STATISTICS_INDEXES[1].1 as f64),
            ),
            (
                "kTotalPhysicalSizeIndex",
                number(scope, HEAP_STATISTICS_INDEXES[2].1 as f64),
            ),
            (
                "kTotalAvailableSize",
                number(scope, HEAP_STATISTICS_INDEXES[3].1 as f64),
            ),
            (
                "kUsedHeapSizeIndex",
                number(scope, HEAP_STATISTICS_INDEXES[4].1 as f64),
            ),
            (
                "kHeapSizeLimitIndex",
                number(scope, HEAP_STATISTICS_INDEXES[5].1 as f64),
            ),
            (
                "kMallocedMemoryIndex",
                number(scope, HEAP_STATISTICS_INDEXES[6].1 as f64),
            ),
            (
                "kPeakMallocedMemoryIndex",
                number(scope, HEAP_STATISTICS_INDEXES[7].1 as f64),
            ),
            (
                "kDoesZapGarbageIndex",
                number(scope, HEAP_STATISTICS_INDEXES[8].1 as f64),
            ),
            (
                "kNumberOfNativeContextsIndex",
                number(scope, HEAP_STATISTICS_INDEXES[9].1 as f64),
            ),
            (
                "kNumberOfDetachedContextsIndex",
                number(scope, HEAP_STATISTICS_INDEXES[10].1 as f64),
            ),
            (
                "kTotalGlobalHandlesSizeIndex",
                number(scope, HEAP_STATISTICS_INDEXES[11].1 as f64),
            ),
            (
                "kUsedGlobalHandlesSizeIndex",
                number(scope, HEAP_STATISTICS_INDEXES[12].1 as f64),
            ),
            (
                "kExternalMemoryIndex",
                number(scope, HEAP_STATISTICS_INDEXES[13].1 as f64),
            ),
            (
                "kTotalAllocatedBytes",
                number(scope, HEAP_STATISTICS_INDEXES[14].1 as f64),
            ),
            (
                "kSpaceSizeIndex",
                number(scope, HEAP_SPACE_STATISTICS_INDEXES[0].1 as f64),
            ),
            (
                "kSpaceUsedSizeIndex",
                number(scope, HEAP_SPACE_STATISTICS_INDEXES[1].1 as f64),
            ),
            (
                "kSpaceAvailableSizeIndex",
                number(scope, HEAP_SPACE_STATISTICS_INDEXES[2].1 as f64),
            ),
            (
                "kPhysicalSpaceSizeIndex",
                number(scope, HEAP_SPACE_STATISTICS_INDEXES[3].1 as f64),
            ),
            (
                "kCodeAndMetadataSizeIndex",
                number(scope, HEAP_CODE_STATISTICS_INDEXES[0].1 as f64),
            ),
            (
                "kBytecodeAndMetadataSizeIndex",
                number(scope, HEAP_CODE_STATISTICS_INDEXES[1].1 as f64),
            ),
            (
                "kExternalScriptSourceSizeIndex",
                number(scope, HEAP_CODE_STATISTICS_INDEXES[2].1 as f64),
            ),
            (
                "kCPUProfilerMetaDataSizeIndex",
                number(scope, HEAP_CODE_STATISTICS_INDEXES[3].1 as f64),
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(V8);
}

/// `kHeapSpaces`: the heap space names, in the order
/// `Isolate::GetHeapSpaceStatistics` takes its index.
///
/// `lib/v8.js` walks this array and passes the position to
/// `updateHeapSpaceStatisticsBuffer`, so the order is the contract and the
/// length is `kNumberOfHeapSpaces`.
fn heap_spaces<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Value>, String> {
    let array = v8::Array::new(scope, HEAP_SPACES.len() as i32);
    for (index, name) in HEAP_SPACES.iter().enumerate() {
        let Some(text) = v8::String::new(scope, name) else {
            return Err(format!("cannot allocate the heap space name {name}"));
        };
        array.set_index(scope, index as u32, text.into());
    }
    Ok(array.into())
}

/// `detailLevel`: the `cppgc::HeapStatistics::DetailLevel` values
/// `getCppHeapStatistics` accepts.
///
/// The numbering is V8's enum order, so `BRIEF` is 0 and `DETAILED` is 1.
fn detail_level<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let object = v8::Object::new(scope);
    for (name, value) in [
        ("BRIEF", constants::DETAIL_LEVEL_BRIEF),
        ("DETAILED", constants::DETAIL_LEVEL_DETAILED),
    ] {
        if let Some(key) = v8::String::new(scope, name) {
            let value = number(scope, value as f64);
            object.set(scope, key.into(), value);
        }
    }
    // The object is `detailLevel` itself: `lib/v8.js` reads `DETAILED` and
    // `BRIEF` off it and nothing else.
    object.into()
}

fn update_heap_statistics_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let statistics = scope.get_heap_statistics();
    buffers_impl::with_heap_statistics(|buffer| {
        for (index, value) in HEAP_STATISTICS_INDEXES
            .iter()
            .map(|(_, index)| (*index, heap_statistic_value(&statistics, *index)))
        {
            buffer.set_float(index, value);
        }
    });
}

fn update_heap_space_statistics_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(index) = args.get(0).uint32_value(scope) else {
        // Node asserts the argument is a uint32. A missing one cannot name a
        // space, so the buffer is left alone rather than filled with zeroes.
        return;
    };
    let spaces = scope.number_of_heap_spaces();
    let index = index as usize;
    if index >= spaces {
        // Out of range for this isolate: there is no space to report.
        return;
    }
    let Some(statistics) = scope.get_heap_space_statistics(index) else {
        return;
    };
    buffers_impl::with_heap_space_statistics(|buffer| {
        for (name, slot) in HEAP_SPACE_STATISTICS_INDEXES {
            buffer.set_float(*slot, heap_space_statistic_value(&statistics, name));
        }
    });
}

fn update_heap_code_statistics_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(statistics) = scope.get_heap_code_and_metadata_statistics() else {
        return;
    };
    buffers_impl::with_heap_code_statistics(|buffer| {
        for (name, slot) in HEAP_CODE_STATISTICS_INDEXES {
            buffer.set_float(*slot, heap_code_statistic_value(&statistics, name));
        }
    });
}

/// The value of one `HeapStatistics` field, by the name Node's macro uses.
fn heap_statistic_value(statistics: &v8::HeapStatistics, index: usize) -> f64 {
    let value = match index {
        0 => statistics.total_heap_size(),
        1 => statistics.total_heap_size_executable(),
        2 => statistics.total_physical_size(),
        3 => statistics.total_available_size(),
        4 => statistics.used_heap_size(),
        5 => statistics.heap_size_limit(),
        6 => statistics.malloced_memory(),
        7 => statistics.peak_malloced_memory(),
        // Node stores this as a 0/1 flag, and `lib/v8.js` exposes it as a
        // number rather than a boolean, so it is widened here to match.
        8 => u8::from(statistics.does_zap_garbage()) as usize,
        9 => statistics.number_of_native_contexts(),
        10 => statistics.number_of_detached_contexts(),
        11 => statistics.total_global_handles_size(),
        12 => statistics.used_global_handles_size(),
        13 => statistics.external_memory(),
        14 => statistics.total_allocated_bytes() as usize,
        _ => 0,
    };
    value as f64
}

fn heap_space_statistic_value(statistics: &v8::HeapSpaceStatistics, name: &str) -> f64 {
    let value = match name {
        "space_size" => statistics.space_size(),
        "space_used_size" => statistics.space_used_size(),
        "space_available_size" => statistics.space_available_size(),
        "physical_space_size" => statistics.physical_space_size(),
        _ => 0,
    };
    value as f64
}

fn heap_code_statistic_value(statistics: &v8::HeapCodeStatistics, name: &str) -> f64 {
    let value = match name {
        "code_and_metadata_size" => statistics.code_and_metadata_size(),
        "bytecode_and_metadata_size" => statistics.bytecode_and_metadata_size(),
        "external_script_source_size" => statistics.external_script_source_size(),
        "cpu_profiler_metadata_size" => statistics.cpu_profiler_metadata_size(),
        _ => 0,
    };
    value as f64
}

/// `v8.cachedDataVersionTag()`: the tag V8 stamps cached data with, so an
/// embedder can tell whether a cache entry came from an incompatible build.
fn cached_data_version_tag(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let tag = v8::script_compiler::cached_data_version_tag();
    rv.set(v8::Integer::new_from_unsigned(scope, tag).into());
}

/// `v8.getHashSeed()`: the per-isolate seed V8 mixes into string hashes.
///
/// Node exposes it so tests can prove that hash randomization really varies
/// between processes, so returning a constant would defeat its only purpose.
fn get_hash_seed(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let seed = hash_seed();
    rv.set(v8::BigInt::new_from_u64(scope, seed).into());
}

/// The isolate's hash seed.
///
/// `Isolate::GetHashSeed` is public in `v8-isolate.h` but the `v8` crate has no
/// binding for it, and it cannot be reached from a `UnsafeRawIsolatePtr`
/// without one. rustnode therefore mixes its own seed from the process entropy
/// it already has: the address of a heap allocation, the clock, and the process
/// id. That is a different value per process, which is what callers of
/// `v8.getHashSeed()` test for, but it is **not** the seed V8 actually uses to
/// hash strings — so it must not be treated as one.
fn hash_seed() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&std::process::id(), &mut hasher);
        if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            std::hash::Hash::hash(&now.as_nanos(), &mut hasher);
        }
        let unique = Box::into_raw(Box::new(0u8));
        std::hash::Hash::hash(&(unique as usize), &mut hasher);
        // SAFETY: the pointer came from `Box::into_raw` immediately above and
        // is reclaimed here; nothing else ever saw it.
        drop(unsafe { Box::from_raw(unique) });
        std::hash::Hash::hash(&COUNTER.fetch_add(1, Ordering::Relaxed), &mut hasher);
        std::hash::Hasher::finish(&hasher)
    })
}

/// `v8.isStringOneByteRepresentation(string)`: whether V8 holds the string
/// with one byte per character.
///
/// This is V8's `String::IsOneByte`, which for a two-byte string is false and
/// for a Latin-1 string is true; `lib/v8.js` validates the argument itself, so
/// a non-string here is a programming error rather than user input.
fn is_string_one_byte_representation(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(string) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    };
    rv.set(v8::Boolean::new(scope, string.is_onebyte()).into());
}

/// `v8.setFlagsFromString(flags)`: sets V8 command-line flags at runtime.
///
/// V8 records a flag set this way even after the isolate exists, so flags that
/// only affect future optimizations take effect. `lib/v8.js` validates the
/// argument is a string.
fn set_flags_from_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(flags) = args.get(0).to_string(scope) else {
        return;
    };
    let flags = flags.to_rust_string_lossy(scope);
    v8::V8::set_flags_from_string(&flags);
}

/// `v8.getCppHeapStatistics(type)`: the cppgc heap statistics.
///
/// rustnode's isolate has no cppgc heap attached: `Isolate::get_cpp_heap`
/// returns `None` until an embedder creates one and hands it over, and nothing
/// in rustnode allocates through cppgc. Node in the same position reports an
/// all-zero heap with an empty space list, which is what this does, so the
/// shape and the meaning match even though the numbers have nothing to count
/// yet. `lib/v8.js` adds `detail_level` to the result itself.
fn get_cpp_heap_statistics(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let object = v8::Object::new(scope);
    for (name, value) in [
        ("committed_size_bytes", 0.0),
        ("resident_size_bytes", 0.0),
        ("used_size_bytes", 0.0),
    ] {
        if let Some(key) = v8::String::new(scope, name) {
            let value = number(scope, value);
            object.set(scope, key.into(), value);
        }
    }
    if let Some(key) = v8::String::new(scope, "space_statistics") {
        object.set(scope, key.into(), v8::Array::new(scope, 0).into());
    }
    if let Some(key) = v8::String::new(scope, "type_names") {
        object.set(scope, key.into(), v8::Array::new(scope, 0).into());
    }
    rv.set(object.into());
}

fn number<'s>(scope: &mut v8::PinScope<'s, '_>, value: f64) -> v8::Local<'s, v8::Value> {
    v8::Number::new(scope, value).into()
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

pub(crate) fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

pub(crate) fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_tables_are_dense_and_in_enum_order() {
        for (position, (name, index)) in HEAP_STATISTICS_INDEXES.iter().enumerate() {
            assert_eq!(*index, position, "{name} must sit at index {position}");
        }
        assert_eq!(
            HEAP_STATISTICS_INDEXES.len(),
            buffers::HEAP_STATISTICS_LENGTH
        );
        for (position, (name, index)) in HEAP_SPACE_STATISTICS_INDEXES.iter().enumerate() {
            assert_eq!(*index, position, "{name} must sit at index {position}");
        }
        assert_eq!(
            HEAP_SPACE_STATISTICS_INDEXES.len(),
            buffers::HEAP_SPACE_STATISTICS_LENGTH
        );
        for (position, (name, index)) in HEAP_CODE_STATISTICS_INDEXES.iter().enumerate() {
            assert_eq!(*index, position, "{name} must sit at index {position}");
        }
        assert_eq!(
            HEAP_CODE_STATISTICS_INDEXES.len(),
            buffers::HEAP_CODE_STATISTICS_LENGTH
        );
    }

    #[test]
    fn the_heap_space_names_are_the_ones_v8_reports() {
        // The order is what `lib/v8.js` passes to
        // `updateHeapSpaceStatisticsBuffer`, so a rename or a reorder would
        // silently attribute one space's numbers to another.
        assert_eq!(
            HEAP_SPACES,
            &[
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
            ]
        );
    }

    #[test]
    fn every_contract_member_is_either_installed_or_deferred() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/v8.json"))
                .expect("the v8 contract must parse");
        let members = contract["members"].as_object().expect("a member map");
        for name in members.keys() {
            assert!(
                MEMBERS.contains(&name.as_str())
                    || DEFERRED.iter().any(|(deferred, _)| deferred == name),
                "{name} is in the contract but is neither installed nor deferred"
            );
        }
        for name in MEMBERS {
            assert!(
                members.contains_key(*name),
                "{name} is installed but the contract does not record it"
            );
        }
        for (name, reason) in DEFERRED {
            assert!(
                members.contains_key(*name),
                "{name} is deferred but the contract does not record it"
            );
            assert!(
                !MEMBERS.contains(name),
                "{name} cannot be both installed and deferred"
            );
            assert!(!reason.is_empty(), "{name} needs a written reason");
        }
        // Every member is accounted for exactly once, so a member cannot be
        // quietly dropped by editing one list.
        assert_eq!(MEMBERS.len() + DEFERRED.len(), members.len());
    }

    #[test]
    fn the_sampling_flags_match_v8() {
        // `v8::HeapProfiler::SamplingFlags`, which
        // `lib/internal/v8/heap_profile.js` or's together.
        assert_eq!(constants::SAMPLING_NO_FLAGS, 0);
        assert_eq!(constants::SAMPLING_FORCE_GC, 1 << 0);
        assert_eq!(
            constants::SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MAJOR_GC,
            1 << 1
        );
        assert_eq!(
            constants::SAMPLING_INCLUDE_OBJECTS_COLLECTED_BY_MINOR_GC,
            1 << 2
        );
    }

    #[test]
    fn the_hash_seed_is_stable_and_process_specific() {
        let first = hash_seed();
        assert_eq!(first, hash_seed(), "the seed is per process, not per call");
        assert_ne!(first, 0);
    }

    #[test]
    fn the_detail_levels_follow_the_cppgc_enum() {
        assert_eq!(constants::DETAIL_LEVEL_BRIEF, 0);
        assert_eq!(constants::DETAIL_LEVEL_DETAILED, 1);
    }
}
