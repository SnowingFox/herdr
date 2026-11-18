//! The `MeasureMemory` shim, driven directly against a real V8 isolate.
//!
//! This is the end-to-end proof that the FFI crossing is correct, without going
//! through `lib/vm.js`: it builds the same call Node does
//! (`src/node_contextify.cc:2005`) and checks that V8 resolves the promise with
//! the shape `vm.measureMemory()` is documented to return.
//!
//! The pump matters. `Isolate::MeasureMemory` does not measure inline; it
//! enqueues a request and posts a task to the isolate's **foreground** task
//! runner (`v8/src/heap/memory-measurement.cc:306`, `ScheduleGCTask`). Nothing
//! resolves until that queue is drained, which in an embedder is
//! `platform->DrainTasks(isolate)` — the call Node makes once per event-loop
//! iteration in `SpinEventLoopInternal`. So the test pumps the platform between
//! checks, and a shim that "worked" without a pump would only be proven to have
//! enqueued something.

use rn_v8_sys::v8;

/// Drains the foreground task queue until the promise settles or we give up.
///
/// The bound is a fixed number of pumps rather than a wall-clock timeout so a
/// failure is deterministic on a loaded machine.
fn settle(
    platform: &v8::SharedRef<v8::Platform>,
    scope: &mut v8::PinScope,
    promise: v8::Local<v8::Promise>,
) -> bool {
    for _ in 0..64 {
        if promise.state() != v8::PromiseState::Pending {
            return true;
        }
        let isolate: &v8::Isolate = scope;
        let pumped = v8::Platform::pump_message_loop(platform, isolate, false);
        if !pumped {
            // Nothing was queued this turn. The measurement may still be waiting
            // on a GC the platform has scheduled on a worker, so keep going
            // briefly rather than exiting on the first empty turn.
            std::thread::yield_now();
        }
    }
    promise.state() != v8::PromiseState::Pending
}

#[test]
fn measure_memory_resolves_a_promise_with_the_documented_shape() {
    // Same platform instance the loop would use, kept alive for the pumps.
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform.clone());
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    {
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);

        let resolver = v8::PromiseResolver::new(scope).expect("a resolver");
        let promise = resolver.get_promise(scope);

        // SAFETY: the resolver was created in this scope's current context, and
        // both outlive the call.
        let accepted = unsafe {
            rn_v8_sys::measure_memory(
                scope,
                scope.get_current_context(),
                resolver,
                rn_v8_sys::MeasureMemoryMode::Summary,
                rn_v8_sys::MeasureMemoryExecution::Eager,
            )
        };
        assert!(accepted, "V8 declined to enqueue the measurement");

        assert!(
            settle(&platform, scope, promise),
            "the promise never settled: V8 enqueued the request but its \
             foreground task was never drained"
        );
        assert_eq!(
            promise.state(),
            v8::PromiseState::Fulfilled,
            "the measurement rejected; V8 rejects only when it cannot complete"
        );

        // `assertSummaryShape` in `test/common/measure-memory.js` requires
        // `typeof result.total === 'object'` with numeric `jsMemoryEstimate` and
        // a two-element `jsMemoryRange`. The numbers themselves are heap
        // dependent, so only their types and ordering are asserted.
        let result: v8::Local<v8::Value> = promise.result(scope);
        let result = v8::Local::<v8::Object>::try_from(result).expect("result is an object");
        let total = read(scope, result, "total");
        let total = v8::Local::<v8::Object>::try_from(total).expect("total is an object");

        let estimate = read(scope, total, "jsMemoryEstimate");
        let estimate =
            v8::Local::<v8::Number>::try_from(estimate).expect("jsMemoryEstimate is a number");
        let range = read(scope, total, "jsMemoryRange");
        let range = v8::Local::<v8::Array>::try_from(range).expect("jsMemoryRange is an array");
        assert_eq!(range.length(), 2, "jsMemoryRange is [low, high]");

        let low = range
            .get_index(scope, 0)
            .and_then(|v| v8::Local::<v8::Number>::try_from(v).ok())
            .expect("range low is a number");
        let high = range
            .get_index(scope, 1)
            .and_then(|v| v8::Local::<v8::Number>::try_from(v).ok())
            .expect("range high is a number");

        assert!(
            estimate.value() > 0.0,
            "a live isolate reports a non-zero estimate"
        );
        assert!(
            low.value() <= estimate.value() && estimate.value() <= high.value(),
            "the estimate lies inside its own range"
        );
    }

    drop(isolate);
    // SAFETY: the isolate is gone and this test owns the process-wide V8
    // initialisation, so disposing here cannot race another isolate.
    unsafe {
        v8::V8::dispose();
        v8::V8::dispose_platform();
    }
}

/// Reads `name` off `object`, failing the test rather than returning `None`.
fn read<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> v8::Local<'s, v8::Value> {
    let key = v8::String::new(scope, name).expect("a key");
    object.get(scope, key.into()).expect("the property exists")
}
