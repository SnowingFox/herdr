//! `worker.takeHeapSnapshot()`: capture on the worker thread, deliver on parent.
//!
//! `lib/internal/worker.js` mirrors `getHeapStatistics()`:
//!
//! ```text
//! const taker = this[kHandle]?.takeHeapSnapshot(optionsArray);
//! taker.ondone = (handle) => resolve(new HeapSnapshotStream(handle));
//! ```
//!
//! so the thread split is the same:
//!
//! 1. create and return a taker object in the parent's isolate;
//! 2. use `RequestInterrupt` so the worker thread does the isolate read;
//! 3. wake the parent and call `taker.ondone(handle)` from the check phase.

use std::sync::{Arc, Mutex};

use rn_v8_sys::v8;

use crate::handle::PendingHeapSnapshot;

/// Serialized snapshot bytes from the worker, once ready.
pub type HeapSnapshot = Arc<Mutex<Option<Vec<u8>>>>;

/// The data an interrupt callback is given.
///
/// Boxed by the parent and kept alive there until the isolate is disposed, so
/// the callback only reads from it.
pub struct InterruptData {
    snapshot: HeapSnapshot,
    /// The parent's loop, woken so the check phase delivers the result.
    parent_wake: Option<rn_uv::wake::ThreadToken>,
}

/// Asks the worker's thread for a heap snapshot.
///
/// Returns boxed interrupt data the caller must keep alive for as long as the
/// interrupt may run.
pub fn request(
    isolate: &v8::IsolateHandle,
    taker: v8::Global<v8::Object>,
    parent_wake: Option<rn_uv::wake::ThreadToken>,
) -> Option<(PendingHeapSnapshot, Box<InterruptData>)> {
    let snapshot: HeapSnapshot = Arc::new(Mutex::new(None));
    let data = Box::new(InterruptData {
        snapshot: Arc::clone(&snapshot),
        parent_wake,
    });
    let pointer = (&*data as *const InterruptData).cast_mut().cast();
    if !isolate.request_interrupt(read_heap_snapshot, pointer) {
        return None;
    }
    Some((PendingHeapSnapshot::new(taker, snapshot), data))
}

/// The interrupt body: read this isolate's snapshot bytes and wake the parent.
///
/// # Safety
///
/// Called by V8 on the worker's own thread with the pointer `request` boxed.
unsafe extern "C" fn read_heap_snapshot(
    isolate: v8::UnsafeRawIsolatePtr,
    data: *mut std::ffi::c_void,
) {
    if isolate.is_null() || data.is_null() {
        return;
    }
    // SAFETY: the pointer came from `request`'s `Box`, which the parent keeps
    // alive for the life of the interrupt.
    let data = unsafe { &*data.cast::<InterruptData>() };
    let mut isolate = unsafe { v8::Isolate::from_raw_isolate_ptr(isolate) };
    let mut bytes: Vec<u8> = Vec::new();
    isolate.take_heap_snapshot(|chunk| match bytes.try_reserve(chunk.len()) {
        Ok(()) => {
            bytes.extend_from_slice(chunk);
            true
        }
        Err(_) => false,
    });
    if let Ok(mut slot) = data.snapshot.lock() {
        *slot = Some(bytes);
    }
    if let Some(token) = data.parent_wake {
        let _ = token.notify();
    }
}

/// Builds the stream handle `taker.ondone` receives and calls it.
///
/// Returns whether a callback ran.
pub fn deliver(scope: &mut v8::PinScope<'_, '_>, pending: &PendingHeapSnapshot) -> bool {
    let Some(bytes) = pending.bytes() else {
        return false;
    };
    let Some(taker) = pending.taker(scope) else {
        return true;
    };
    let Some(stream) = build_stream(scope, bytes) else {
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
    let _ = ondone.call(scope, taker.into(), &[stream.into()]);
    true
}

/// Creates one `HeapSnapshotStream` handle around `bytes`.
fn build_stream<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: Vec<u8>,
) -> Option<v8::Local<'s, v8::Object>> {
    let constructor = match rn_bind_heap_utils::stream::constructor_for(scope) {
        Some(constructor) => constructor,
        None => {
            let value = rn_bind_heap_utils::stream::constructor(scope).ok()?;
            let constructor = v8::Local::<v8::Function>::try_from(value).ok()?;
            rn_bind_heap_utils::stream::remember_constructor(scope, constructor);
            constructor
        }
    };
    rn_bind_heap_utils::stream::create(scope, constructor, bytes)
}
