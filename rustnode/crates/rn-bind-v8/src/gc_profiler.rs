//! `GCProfiler`: the `v8.GCProfiler` class.
//!
//! `lib/v8.js` wraps this in one line each way — `start()` and `stop()` — and
//! `stop()` does `JSON.parse` on whatever `stop` returns, so the return value is
//! the whole contract. It is a JSON document describing each garbage collection
//! that ran between the two calls:
//!
//! ```text
//! {"version":1,"startTime":1731000000000,"statistics":[
//!   {"gcType":"Scavenge",
//!    "beforeGC":{"heapStatistics":{...},"heapSpaceStatistics":[...]},
//!    "cost":412.5,
//!    "afterGC":{"heapStatistics":{...},"heapSpaceStatistics":[...]}}],
//!  "endTime":1731000000123}
//! ```
//!
//! Field names, their order and the `gcType` spellings are Node's, because the
//! result is read by name.
//!
//! `cost` is in **microseconds**: Node divides the nanosecond delta by 1e3 and
//! calls the result a cost, which reads like milliseconds but is not.
//! Reproducing the number as Node reports it matters more than fixing the name,
//! so this divides the same way.
//!
//! `beforeGC.heapStatistics` carries a deliberately reduced field set. Node
//! omits `does_zap_garbage` and the two context counts from the profiler even
//! though the statistics buffer has them, so the report has them too.
//!
//! # How the samples are collected
//!
//! `Isolate::add_gc_prologue_callback` and `add_gc_epilogue_callback` are real
//! in the `v8` crate, so this is a real profiler: the prologue records the heap
//! state and the start time, the epilogue records the elapsed time and the heap
//! state again, and the pair becomes one entry.
//!
//! Each `GCProfiler` instance owns its own state, reached from the callbacks
//! through the data pointer V8 hands back, so two instances record
//! independently rather than sharing a slot. The state is freed by the object's
//! finalizer, which also unregisters both callbacks: leaving them registered
//! after the state is gone would give V8 a dangling data pointer.

use rn_v8_sys::v8;

use crate::throw;

/// `GCProfiler::kInternalFieldCount`: one internal field holding the state
/// pointer.
const STATE_FIELD: i32 = 0;

/// One garbage collection, as Node's `JSONWriter` records it.
struct GcSample {
    /// `Scavenge`, `MarkSweepCompact` and the rest, spelled as Node spells them.
    gc_type: &'static str,
    /// Microseconds, which is what Node reports.
    cost: f64,
    before: HeapSnapshotState,
    after: HeapSnapshotState,
}

/// The heap state at one side of a collection.
struct HeapSnapshotState {
    total_heap_size: usize,
    total_heap_size_executable: usize,
    total_physical_size: usize,
    total_available_size: usize,
    total_global_handles_size: usize,
    used_global_handles_size: usize,
    used_heap_size: usize,
    heap_size_limit: usize,
    malloced_memory: usize,
    external_memory: usize,
    peak_malloced_memory: usize,
    spaces: Vec<SpaceState>,
}

struct SpaceState {
    name: String,
    size: usize,
    used_size: usize,
    available_size: usize,
    physical_size: usize,
}

/// The state one `GCProfiler` instance owns.
struct ProfilerState {
    /// Which of the three states this profiler is in, which is what makes
    /// `start()` and `stop()` behave the way Node's do.
    status: Status,
    start_time_millis: u64,
    samples: Vec<GcSample>,
    /// The collection in progress, between its prologue and its epilogue.
    ///
    /// V8 can run a prologue for one collection and the epilogue for another if
    /// a collection is nested; Node tracks the type for the same reason and
    /// drops an epilogue whose type does not match, which this does too.
    current: Option<InProgress>,
    /// Whether the two callbacks are registered. V8 aborts if asked to remove a
    /// callback that is not registered, so this is what makes it safe to skip
    /// the removal after a `stop()` that never followed a `start()`.
    registered: bool,
    /// Kept alive so the finalizer that frees this state stays registered.
    /// Dropping it early would cancel the finalizer and leak the box.
    weak: Option<v8::Weak<v8::Object>>,
}

struct InProgress {
    gc_type: &'static str,
    /// The same type as its raw bits, because the epilogue's value is compared
    /// against the one the prologue saw rather than re-named.
    gc_type_bits: u32,
    started: std::time::Instant,
    before: HeapSnapshotState,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Status {
    Initialized,
    Started,
    Stopped,
}

/// Installs the `GCProfiler` constructor on the namespace object.
pub(crate) fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(construct)
        .constructor_behavior(v8::ConstructorBehavior::Allow)
        .build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    for (name, method) in [
        ("start", v8::FunctionTemplate::builder(start).build(scope)),
        ("stop", v8::FunctionTemplate::builder(stop).build(scope)),
    ] {
        let Some(key) = v8::String::new(scope, name) else {
            return Err(format!("cannot allocate the GCProfiler method name {name}"));
        };
        prototype.set(key.into(), method.into());
    }

    let Some(name) = v8::String::new(scope, "GCProfiler") else {
        return Err("cannot allocate the GCProfiler class name".to_string());
    };
    template.set_class_name(name);

    let function = template
        .get_function(scope)
        .ok_or("cannot allocate the GCProfiler constructor")?;
    Ok(function.into())
}

/// `new GCProfiler()`: allocates the state and its finalizer.
fn construct(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        // Node asserts this, which means `binding.GCProfiler()` without `new`
        // is a programming error rather than something to tolerate.
        throw(scope, "GCProfiler must be called with new");
        return;
    }
    let object = args.this();
    install_state(scope, object);
    rv.set(object.into());
}

/// Allocates the state, stores its address in the object, and registers the
/// finalizer that unregisters the callbacks and frees it.
fn install_state(scope: &mut v8::PinScope, object: v8::Local<v8::Object>) {
    let pointer = Box::into_raw(Box::new(ProfilerState {
        status: Status::Initialized,
        start_time_millis: 0,
        samples: Vec::new(),
        current: None,
        registered: false,
        weak: None,
    }));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<std::ffi::c_void>().cast_const(),
        0,
    );

    let address = pointer as usize;
    let weak = v8::Weak::with_finalizer(
        scope,
        object,
        Box::new(move |isolate| {
            let pointer = address as *mut ProfilerState;
            // SAFETY: `install_state` allocated this box and nothing else frees
            // it. The finalizer runs once, and the callbacks are removed before
            // the allocation is released, so no callback can observe it after.
            let state = unsafe { &mut *pointer };
            if state.registered {
                isolate.remove_gc_prologue_callback(prologue, pointer.cast());
                isolate.remove_gc_epilogue_callback(epilogue, pointer.cast());
            }
            // The `Weak` lives inside the state it finalizes, so clearing it
            // here is the last use; V8 treats dropping it as a no-op because
            // the second pass is already running.
            state.weak = None;
            // SAFETY: as above.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );

    // SAFETY: `pointer` came from `Box::into_raw` immediately above and is not
    // otherwise aliased until the finalizer takes it back.
    if let Some(state) = unsafe { pointer.as_mut() } {
        state.weak = Some(weak);
    }
}

/// Runs `body` with the instance's state.
fn with_state<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut ProfilerState) -> R,
) -> Option<R> {
    // SAFETY: the field is only ever written by `install_state`, which stores a
    // `Box<ProfilerState>` that outlives the object because the object's
    // finalizer frees it.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut ProfilerState;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above. Every callback that reaches here is synchronous and on
    // the isolate's own thread, so the borrows never overlap.
    let state = unsafe { &mut *pointer };
    Some(body(state))
}

/// `profiler.start()`: arms the two GC callbacks.
fn start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();
    let Some(armed) = with_state(object, |state| {
        if state.status != Status::Initialized {
            // Node returns early, so starting twice or after a stop does
            // nothing rather than replacing the document in progress.
            return false;
        }
        state.status = Status::Started;
        state.start_time_millis = now_millis();
        state.samples.clear();
        state.current = None;
        true
    }) else {
        throw(scope, "GCProfiler is not initialized");
        return;
    };
    if !armed {
        return;
    }

    let Some(pointer) = state_pointer(object) else {
        return;
    };
    scope.add_gc_prologue_callback(prologue, pointer, v8::GCType::kGCTypeAll);
    scope.add_gc_epilogue_callback(epilogue, pointer, v8::GCType::kGCTypeAll);
    // Recorded so `stop()` removes exactly what was added. V8 checks that the
    // callback it is asked to remove is registered, so removing one that was
    // never added aborts the process rather than returning an error.
    with_state(object, |state| state.registered = true);
}

/// `profiler.stop()`: removes the callbacks and returns the JSON document.
fn stop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let object = args.this();
    let outcome = with_state(object, |state| {
        if state.status != Status::Started {
            // `stop()` before `start()`, or after an earlier `stop()`: Node
            // returns `undefined` and `lib/v8.js` only parses a value it knows
            // is a string, so there is nothing to report.
            return None;
        }
        state.status = Status::Stopped;
        let document = render(state, now_millis());
        // The callbacks are unregistered on stop as well as in the finalizer: a
        // stopped profiler that stayed registered would keep capturing heap
        // statistics for a document nobody asks for again.
        let registered = std::mem::replace(&mut state.registered, false);
        Some((document, registered))
    });
    let Some(outcome) = outcome else {
        // Thrown only when the instance never got its state, which means it was
        // not constructed through this constructor.
        throw(scope, "GCProfiler is not initialized");
        return;
    };
    let Some((document, registered)) = outcome else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    if registered {
        if let Some(pointer) = state_pointer(object) {
            scope.remove_gc_prologue_callback(prologue, pointer);
            scope.remove_gc_epilogue_callback(epilogue, pointer);
        }
    }
    let Some(text) = v8::String::new(scope, &document) else {
        throw(scope, "cannot allocate the GC profile");
        return;
    };
    rv.set(text.into());
}

/// The object's state pointer, as the type the GC callbacks take.
fn state_pointer(object: v8::Local<v8::Object>) -> Option<*mut std::ffi::c_void> {
    // SAFETY: as in `with_state`; this only reads the field, it does not
    // dereference it.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut ProfilerState;
    if pointer.is_null() {
        None
    } else {
        Some(pointer.cast())
    }
}

/// `BeforeGCCallback`: records the heap state and the start time.
unsafe extern "C" fn prologue(
    isolate: v8::UnsafeRawIsolatePtr,
    gc_type: v8::GCType,
    _flags: v8::GCCallbackFlags,
    data: *mut std::ffi::c_void,
) {
    if data.is_null() || isolate.is_null() {
        return;
    }
    // SAFETY: `data` is the `ProfilerState` this profiler registered, which the
    // finalizer keeps alive until both callbacks are removed.
    let state = unsafe { &mut *(data as *mut ProfilerState) };
    if state.current.is_some() {
        // A nested collection: the outer one's state is kept and the inner
        // prologue ignored, so prologues and epilogues stay paired.
        return;
    }
    let mut raw = isolate;
    // SAFETY: V8 passes the isolate whose callback this is, and it is alive for
    // the duration of the call.
    let isolate = unsafe { v8::Isolate::ref_from_raw_isolate_ptr_mut(&mut raw) };
    let (gc_type, gc_type_bits) = gc_type_name(gc_type);
    state.current = Some(InProgress {
        gc_type,
        gc_type_bits,
        started: std::time::Instant::now(),
        before: capture(isolate),
    });
}

/// `AfterGCCallback`: records the elapsed time and the heap state again.
unsafe extern "C" fn epilogue(
    isolate: v8::UnsafeRawIsolatePtr,
    gc_type: v8::GCType,
    _flags: v8::GCCallbackFlags,
    data: *mut std::ffi::c_void,
) {
    if data.is_null() || isolate.is_null() {
        return;
    }
    // SAFETY: as in `prologue`.
    let state = unsafe { &mut *(data as *mut ProfilerState) };
    let Some(current) = state.current.as_ref() else {
        return;
    };
    if current.gc_type_bits != gc_type.0 {
        // This epilogue belongs to a different collection than the pending
        // prologue, so pairing them would misattribute the cost.
        return;
    }
    let mut raw = isolate;
    // SAFETY: as in `prologue`.
    let isolate = unsafe { v8::Isolate::ref_from_raw_isolate_ptr_mut(&mut raw) };
    let after = capture(isolate);
    let Some(current) = state.current.take() else {
        return;
    };
    let elapsed = current.started.elapsed();
    state.samples.push(GcSample {
        gc_type: current.gc_type,
        // Node divides nanoseconds by 1e3 and calls the result a cost, so the
        // unit is microseconds. Matching the number matters more than the name.
        cost: elapsed.as_nanos() as f64 / 1e3,
        before: current.before,
        after,
    });
}

/// Reads the heap state Node records on each side of a collection.
fn capture(isolate: &mut v8::Isolate) -> HeapSnapshotState {
    let statistics = isolate.get_heap_statistics();
    let spaces = isolate.number_of_heap_spaces();
    let mut space_states = Vec::with_capacity(spaces);
    for index in 0..spaces {
        let Some(space) = isolate.get_heap_space_statistics(index) else {
            continue;
        };
        space_states.push(SpaceState {
            name: space.space_name().to_string_lossy().into_owned(),
            size: space.space_size(),
            used_size: space.space_used_size(),
            available_size: space.space_available_size(),
            physical_size: space.physical_space_size(),
        });
    }
    HeapSnapshotState {
        total_heap_size: statistics.total_heap_size(),
        total_heap_size_executable: statistics.total_heap_size_executable(),
        total_physical_size: statistics.total_physical_size(),
        total_available_size: statistics.total_available_size(),
        total_global_handles_size: statistics.total_global_handles_size(),
        used_global_handles_size: statistics.used_global_handles_size(),
        used_heap_size: statistics.used_heap_size(),
        heap_size_limit: statistics.heap_size_limit(),
        malloced_memory: statistics.malloced_memory(),
        external_memory: statistics.external_memory(),
        peak_malloced_memory: statistics.peak_malloced_memory(),
        spaces: space_states,
    }
}

/// Renders the document Node's `JSONWriter` produces.
fn render(state: &ProfilerState, end_time_millis: u64) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(256 + state.samples.len() * 1024);
    let _ = write!(
        out,
        "{{\"version\":1,\"startTime\":{},\"statistics\":[",
        state.start_time_millis
    );
    for (position, sample) in state.samples.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"gcType\":\"{}\",\"beforeGC\":", sample.gc_type);
        write_state(&mut out, &sample.before);
        let _ = write!(out, ",\"cost\":{},\"afterGC\":", sample.cost);
        write_state(&mut out, &sample.after);
        out.push('}');
    }
    let _ = write!(out, "],\"endTime\":{}}}", end_time_millis);
    out
}

fn write_state(out: &mut String, state: &HeapSnapshotState) {
    use std::fmt::Write;

    let _ = write!(
        out,
        "{{\"heapStatistics\":{{\"totalHeapSize\":{},\"totalHeapSizeExecutable\":{},\
         \"totalPhysicalSize\":{},\"totalAvailableSize\":{},\"totalGlobalHandlesSize\":{},\
         \"usedGlobalHandlesSize\":{},\"usedHeapSize\":{},\"heapSizeLimit\":{},\
         \"mallocedMemory\":{},\"externalMemory\":{},\"peakMallocedMemory\":{}}},\
         \"heapSpaceStatistics\":[",
        state.total_heap_size,
        state.total_heap_size_executable,
        state.total_physical_size,
        state.total_available_size,
        state.total_global_handles_size,
        state.used_global_handles_size,
        state.used_heap_size,
        state.heap_size_limit,
        state.malloced_memory,
        state.external_memory,
        state.peak_malloced_memory,
    );
    for (position, space) in state.spaces.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"spaceName\":\"{}\",\"spaceSize\":{},\"spaceUsedSize\":{},\
             \"spaceAvailableSize\":{},\"physicalSpaceSize\":{}}}",
            space.name, space.size, space.used_size, space.available_size, space.physical_size
        );
    }
    out.push_str("]}");
}

/// `GetGCTypeName`: the spelling Node puts in `gcType`.
fn gc_type_name(gc_type: v8::GCType) -> (&'static str, u32) {
    let name = match gc_type.0 {
        bits if bits == v8::GCType::kGCTypeScavenge.0 => "Scavenge",
        bits if bits == v8::GCType::kGCTypeMinorMarkSweep.0 => "MinorMarkSweep",
        bits if bits == v8::GCType::kGCTypeMarkSweepCompact.0 => "MarkSweepCompact",
        bits if bits == v8::GCType::kGCTypeIncrementalMarking.0 => "IncrementalMarking",
        bits if bits == v8::GCType::kGCTypeProcessWeakCallbacks.0 => "ProcessWeakCallbacks",
        _ => "Unknown",
    };
    (name, gc_type.0)
}

/// Wall-clock milliseconds, the unit Node uses for `startTime` and `endTime`.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_state() -> HeapSnapshotState {
        HeapSnapshotState {
            total_heap_size: 0,
            total_heap_size_executable: 0,
            total_physical_size: 0,
            total_available_size: 0,
            total_global_handles_size: 0,
            used_global_handles_size: 0,
            used_heap_size: 0,
            heap_size_limit: 0,
            malloced_memory: 0,
            external_memory: 0,
            peak_malloced_memory: 0,
            spaces: Vec::new(),
        }
    }

    #[test]
    fn the_gc_type_names_match_node() {
        for (value, expected) in [
            (v8::GCType::kGCTypeScavenge, "Scavenge"),
            (v8::GCType::kGCTypeMinorMarkSweep, "MinorMarkSweep"),
            (v8::GCType::kGCTypeMarkSweepCompact, "MarkSweepCompact"),
            (v8::GCType::kGCTypeIncrementalMarking, "IncrementalMarking"),
            (
                v8::GCType::kGCTypeProcessWeakCallbacks,
                "ProcessWeakCallbacks",
            ),
        ] {
            assert_eq!(gc_type_name(value).0, expected);
        }
        assert_eq!(gc_type_name(v8::GCType(0)).0, "Unknown");
    }

    #[test]
    fn an_empty_document_has_the_shape_the_javascript_layer_parses() {
        let state = ProfilerState {
            status: Status::Stopped,
            start_time_millis: 1_731_000_000_000,
            samples: Vec::new(),
            current: None,
            registered: false,
            weak: None,
        };
        assert_eq!(
            render(&state, 1_731_000_000_123),
            "{\"version\":1,\"startTime\":1731000000000,\"statistics\":[],\
             \"endTime\":1731000000123}"
        );
    }

    #[test]
    fn a_sample_renders_every_field_the_javascript_layer_reads() {
        let mut before = empty_state();
        before.total_heap_size = 1;
        before.peak_malloced_memory = 11;
        before.spaces = vec![SpaceState {
            name: "new_space".to_string(),
            size: 1024,
            used_size: 512,
            available_size: 256,
            physical_size: 1024,
        }];
        let state = ProfilerState {
            status: Status::Stopped,
            start_time_millis: 10,
            samples: vec![GcSample {
                gc_type: "Scavenge",
                cost: 12.5,
                before,
                after: empty_state(),
            }],
            current: None,
            registered: false,
            weak: None,
        };
        let document = render(&state, 20);
        // The field names and their order are Node's; anything reading the
        // document by name depends on both.
        assert!(document.starts_with(
            "{\"version\":1,\"startTime\":10,\"statistics\":[{\"gcType\":\"Scavenge\",\
             \"beforeGC\":"
        ));
        assert!(document.contains("\"totalHeapSize\":1"));
        assert!(document.contains("\"peakMallocedMemory\":11"));
        assert!(document.contains(
            "\"heapSpaceStatistics\":[{\"spaceName\":\"new_space\",\"spaceSize\":1024,\
             \"spaceUsedSize\":512,\"spaceAvailableSize\":256,\"physicalSpaceSize\":1024}]"
        ));
        assert!(document.contains("\"cost\":12.5"));
        assert!(document.ends_with("],\"endTime\":20}"));
    }
}
