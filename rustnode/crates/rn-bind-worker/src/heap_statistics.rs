//! `worker.getHeapStatistics()`: a snapshot taken across the thread boundary.
//!
//! `src/node_worker.cc:1187` implements this as a handoff in three steps, and
//! each one is forced by which thread may touch what:
//!
//! 1. The parent's `Worker::GetHeapStatistics` builds a
//!    `WorkerHeapStatisticsTaker` in the *parent's* isolate and returns it to
//!    `lib/internal/worker.js`, which sets `taker.ondone`. That object cannot be
//!    touched by the worker's thread.
//! 2. `w->RequestInterrupt(...)` makes the worker's thread read
//!    `isolate()->GetHeapStatistics()`. Only that thread may call it, and it must
//!    be an interrupt rather than a request the worker might service later: a
//!    worker spinning in a loop would otherwise never answer.
//! 3. `env->SetImmediateThreadsafe(...)` posts the numbers back to the parent's
//!    loop, which builds the object and calls `taker.ondone(stats)`.
//!
//! rustnode keeps the same three steps with the same ownership boundary. What
//! crosses a thread is only an `Arc<Mutex<Option<[f64; 15]>>>` for the numbers
//! and a [`v8::IsolateHandle`] for the interrupt, because a `v8::Local` or a
//! `v8::Global` from either isolate is meaningless on the other thread.
//!
//! # Why the delivery is polled from the check phase
//!
//! Node wakes the parent's loop with `uv_async_send` on its tasks queue. The
//! equivalent here is the existing cross-thread wake handle, and the existing
//! check-phase hooks: `has_finished` already reports "a worker owes the parent
//! something", so the pending statistics are reported through a predicate of
//! their own. That keeps one mechanism for "the worker's thread has news", which
//! is the same reason the exit is polled there rather than joined on.

use std::sync::{Arc, Mutex};

use rn_v8_sys::v8;

use crate::handle::{PendingHeapStatistics, HEAP_STATISTIC_FIELDS, HEAP_STATISTIC_NAMES};

/// The numbers a worker's isolate reported, or the fact that it never answered.
pub type HeapStatistics = Arc<Mutex<Option<[f64; HEAP_STATISTIC_FIELDS]>>>;

/// The data an interrupt callback is given.
///
/// Boxed by the parent and kept alive there until it is delivered or the worker
/// is dropped, so the callback only ever *reads* it. Nothing is freed on the
/// worker's thread: an interrupt that V8 discards during isolate teardown would
/// otherwise leak, and more importantly the parent is the only side that knows
/// when the last reader is done.
pub struct InterruptData {
    statistics: HeapStatistics,
    /// The parent's loop, woken so the check phase delivers the result.
    parent_wake: Option<rn_uv::wake::ThreadToken>,
}

/// Asks the worker's thread for a heap snapshot, with `taker` as the object to
/// call `ondone` on.
///
/// Returns the boxed interrupt data, which the caller must keep alive for as long
/// as the interrupt can run (that is, until the isolate is disposed). `None` when
/// the worker's isolate no longer exists, which is Node's `RequestInterrupt`
/// returning false for `env_ == nullptr` — `lib/internal/worker.js` reads that as
/// `ERR_WORKER_NOT_RUNNING`.
pub fn request(
    isolate: &v8::IsolateHandle,
    taker: v8::Global<v8::Object>,
    parent_wake: Option<rn_uv::wake::ThreadToken>,
) -> Option<(PendingHeapStatistics, Box<InterruptData>)> {
    let statistics: HeapStatistics = Arc::new(Mutex::new(None));
    let data = Box::new(InterruptData {
        statistics: Arc::clone(&statistics),
        parent_wake,
    });
    let pointer = (&*data as *const InterruptData).cast_mut().cast();
    if !isolate.request_interrupt(read_heap_statistics, pointer) {
        return None;
    }
    Some((PendingHeapStatistics::new(taker, statistics), data))
}

/// The interrupt body: read this isolate's heap statistics and wake the parent.
///
/// # Safety
///
/// Called by V8 on the worker's own thread with the pointer [`request`] boxed.
/// The isolate pointer is the one V8 is interrupting, and `data` outlives the
/// interrupt because the parent owns it.
unsafe extern "C" fn read_heap_statistics(
    isolate: v8::UnsafeRawIsolatePtr,
    data: *mut std::ffi::c_void,
) {
    if isolate.is_null() || data.is_null() {
        return;
    }
    // SAFETY: the pointer came from `request`'s `Box`, which the parent keeps
    // alive for the life of the interrupt, and the isolate is the one V8 is
    // currently interrupting on this thread.
    let data = unsafe { &*data.cast::<InterruptData>() };
    let mut isolate = unsafe { v8::Isolate::from_raw_isolate_ptr(isolate) };
    let statistics = isolate.get_heap_statistics();
    // The fifteen values `src/node_worker.cc:1251-1265` reports, in that order.
    // `does_zap_garbage` is a bool there and a number here because the whole
    // array is one `Vec<f64>`; the delivery turns it back into a boolean.
    let values = [
        statistics.total_heap_size() as f64,
        statistics.total_heap_size_executable() as f64,
        statistics.total_physical_size() as f64,
        statistics.total_available_size() as f64,
        statistics.used_heap_size() as f64,
        statistics.heap_size_limit() as f64,
        statistics.malloced_memory() as f64,
        statistics.peak_malloced_memory() as f64,
        f64::from(u8::from(statistics.does_zap_garbage())),
        statistics.number_of_native_contexts() as f64,
        statistics.number_of_detached_contexts() as f64,
        statistics.total_global_handles_size() as f64,
        statistics.used_global_handles_size() as f64,
        statistics.external_memory() as f64,
        statistics.total_allocated_bytes() as f64,
    ];
    if let Ok(mut slot) = data.statistics.lock() {
        *slot = Some(values);
    }
    if let Some(token) = data.parent_wake {
        // Wakes the parent out of `uv__io_poll` so its check phase runs and
        // delivers the numbers. A token whose thread has gone is inert.
        let _ = token.notify();
    }
}

/// Builds the statistics object `taker.ondone` receives and calls it.
///
/// This is the parent's half of `SetImmediateThreadsafe`
/// (`src/node_worker.cc:1218-1282`): a null-prototype object with the fifteen
/// fields, and `ondone` called with it. Returns whether a callback ran, which the
/// check phase uses to decide whether it did work this turn.
pub fn deliver(scope: &mut v8::PinScope<'_, '_>, pending: &PendingHeapStatistics) -> bool {
    let Some(values) = pending.values() else {
        // The interrupt has not run yet; the entry stays queued.
        return false;
    };
    let Some(taker) = pending.taker(scope) else {
        return true;
    };
    let Some(statistics) = build(scope, &values) else {
        return true;
    };
    let Some(key) = v8::String::new(scope, "ondone") else {
        return true;
    };
    let Some(ondone) = taker.get(scope, key.into()) else {
        return true;
    };
    let Ok(ondone) = v8::Local::<v8::Function>::try_from(ondone) else {
        return true;
    };
    // `MakeCallback`, so a throw inside `ondone` propagates rather than being
    // swallowed: `lib/internal/worker.js` only resolves a promise here, but a
    // subclass that overrode it could throw.
    let _ = ondone.call(scope, taker.into(), &[statistics.into()]);
    true
}

/// The null-prototype object `NewDictionaryInstanceNullProto` builds.
fn build<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    values: &[f64; HEAP_STATISTIC_FIELDS],
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    object.set_prototype(scope, v8::null(scope).into());
    for (name, value) in HEAP_STATISTIC_NAMES.iter().zip(values) {
        let key = v8::String::new(scope, name)?;
        // `Boolean::New` for `does_zap_garbage` and `Number::New` for the rest,
        // which is the pair `src/node_worker.cc:1259` builds.
        let value: v8::Local<v8::Value> = if *name == "does_zap_garbage" {
            v8::Boolean::new(scope, *value != 0.0).into()
        } else {
            v8::Number::new(scope, *value).into()
        };
        object.set(scope, key.into(), value);
    }
    Some(object)
}
