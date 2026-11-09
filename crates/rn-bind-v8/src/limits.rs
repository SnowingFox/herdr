//! The two near-heap-limit diagnostics: `setHeapSnapshotNearHeapLimit` and
//! `setHeapProfileNearHeapLimit`.
//!
//! Both arm a callback V8 runs when the heap approaches its limit. Node's
//! `Environment` tracks how many times each may fire before uninstalling
//! itself; `lib/v8.js` also guards the calls with its own one-shot flags, so the
//! count here is a second line of defence against a callback firing more often
//! than the caller asked for.
//!
//! # What each one can actually do
//!
//! `setHeapSnapshotNearHeapLimit` is real. The `v8` crate exposes
//! `add_near_heap_limit_callback`, `remove_near_heap_limit_callback` and
//! `take_heap_snapshot`, which are exactly the three pieces Node's
//! `HeapSnapshotNearHeapLimitCallback` needs: raise the limit so the snapshot
//! can be allocated, write the snapshot, and let V8 restore the limit once the
//! heap falls back.
//!
//! `setHeapProfileNearHeapLimit` arms the same callback but cannot write a heap
//! profile: that needs `HeapProfiler::GetAllocationProfile`, which the crate has
//! no binding for, and an allocation profile is only meaningful if a sampling
//! profiler was started first, which `startHeapProfile` cannot do either. What
//! it does instead is raise the limit and say on stderr that no profile was
//! written, so a near-limit event does not become an OOM and the reason is
//! visible. A fabricated profile would be worse than none.
//!
//! # Why the isolate pointer is captured at arm time
//!
//! The callback V8 calls takes `(data, current_limit, initial_limit)` and no
//! isolate, but writing a snapshot needs one. Node reaches it through
//! `Environment`; here the arming call captures `Isolate::as_raw_isolate_ptr`
//! into the callback's `data` and reconstructs a borrow from it. That is sound
//! because the registration lives exactly as long as the isolate: V8 drops a
//! near-heap-limit callback with the isolate that owns it, and rustnode creates
//! one isolate for the process. The alternative — declaring `Isolate::GetCurrent`
//! by hand — means hard-coding a mangled symbol name, which breaks silently the
//! day the C++ signature changes.
//!
//! Both callbacks must return a heap limit greater than the current one, or V8
//! may crash, so every return path raises it.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::OnceLock;

use rn_v8_sys::v8;

use crate::throw;

fn snapshot_state() -> &'static SnapshotState {
    static STATE: OnceLock<SnapshotState> = OnceLock::new();
    STATE.get_or_init(SnapshotState::default)
}

fn profile_state() -> &'static ProfileState {
    static STATE: OnceLock<ProfileState> = OnceLock::new();
    STATE.get_or_init(ProfileState::default)
}

/// State shared with [`snapshot_callback`].
#[derive(Default)]
struct SnapshotState {
    /// How many snapshots the caller allowed.
    limit: AtomicU32,
    /// How many have been written.
    taken: AtomicU32,
    /// Whether the callback is currently registered, so a second call does not
    /// register it twice.
    armed: AtomicBool,
}

#[derive(Default)]
struct ProfileState {
    armed: AtomicBool,
    reported: AtomicBool,
}

/// The isolate the callbacks belong to.
///
/// V8's `AddNearHeapLimitCallback` keeps only the most recently added callback
/// for an isolate, so one slot is enough: a second registration replaces the
/// first rather than adding to it. The value is a leaked
/// `Box<UnsafeRawIsolatePtr>`, handed to the callback as its `data` pointer so
/// the callback does not have to name `Isolate::GetCurrent`'s mangled symbol.
static ISOLATE: AtomicUsize = AtomicUsize::new(0);

/// `v8.setHeapSnapshotNearHeapLimit(limit)`: take up to `limit` heap snapshots as
/// the heap approaches its limit.
///
/// The snapshots land in the working directory, named the way Node's
/// `DiagnosticFilename` names them, and the path is printed to stderr the way
/// Node prints it, so a user who runs into the limit can find the file.
pub(crate) fn set_heap_snapshot_near_heap_limit(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(limit) = positive_uint32(scope, &args, "setHeapSnapshotNearHeapLimit") else {
        return;
    };
    let state = snapshot_state();
    if state.armed.swap(true, Ordering::SeqCst) {
        // Already armed. `lib/v8.js` filters repeated calls itself, so this is
        // only reachable when the two disagree, and keeping the first arming is
        // what the guard above it means.
        return;
    }
    state.limit.store(limit, Ordering::SeqCst);
    state.taken.store(0, Ordering::SeqCst);
    let data = isolate_data(scope);
    scope.add_near_heap_limit_callback(snapshot_callback, data);
}

/// `v8.setHeapProfileNearHeapLimit(limit)`: raise the heap limit when it is
/// approached, and report that no profile was written.
pub(crate) fn set_heap_profile_near_heap_limit(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let _limit = match positive_uint32(scope, &args, "setHeapProfileNearHeapLimit") {
        Some(limit) => limit,
        None => return,
    };
    let state = profile_state();
    if state.armed.swap(true, Ordering::SeqCst) {
        return;
    }
    state.reported.store(false, Ordering::SeqCst);
    let data = isolate_data(scope);
    scope.add_near_heap_limit_callback(profile_callback, data);
}

/// Packages the current isolate for a near-heap-limit callback.
///
/// The callback signature has no isolate parameter, so the pointer travels in
/// the `data` slot.
fn isolate_data(scope: &v8::PinScope<'_, '_>) -> *mut std::ffi::c_void {
    let isolate: &v8::Isolate = scope;
    // SAFETY: `scope` is a live scope on this thread, so its isolate is live.
    let raw = unsafe { isolate.as_raw_isolate_ptr() };
    // Leaked on purpose: the box has to outlive the registration, and the
    // registration lives until the isolate is destroyed. Freeing it from a
    // callback that may run during isolate teardown would be worse than not
    // freeing it, so one box per registration is the whole cost.
    let boxed = Box::into_raw(Box::new(raw));
    ISOLATE.store(boxed as usize, Ordering::SeqCst);
    boxed.cast()
}

/// The isolate a near-heap-limit callback should act on.
///
/// # Safety
///
/// `data` must be the pointer [`isolate_data`] handed to the registration this
/// callback belongs to.
unsafe fn isolate_from_data(data: *mut std::ffi::c_void) -> Option<v8::UnsafeRawIsolatePtr> {
    if data.is_null() {
        return None;
    }
    // SAFETY: `data` came from `Box::into_raw` in `isolate_data` and that box is
    // never freed, so reading it is valid.
    let raw = unsafe { *(data as *const v8::UnsafeRawIsolatePtr) };
    if raw.is_null() {
        None
    } else {
        Some(raw)
    }
}

/// Reads the limit argument the way Node's `setHeapSnapshotNearHeapLimit` does.
///
/// Node has two checks that reject different things:
/// `CHECK(args[0]->IsUint32())` rejects a negative number, a fractional number
/// and a string, and `CHECK_GT(limit, 0)` rejects zero. Both throw here rather
/// than crashing the process, but the set of accepted values is Node's.
///
/// `uint32_value` alone is not enough: it converts `-1` to `4294967295` and a
/// numeric string to its value, neither of which is `IsUint32`.
fn positive_uint32(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    member: &str,
) -> Option<u32> {
    let value = args.get(0);
    if !value.is_uint32() {
        throw(scope, &format!("{member} expects a uint32"));
        return None;
    }
    let Some(limit) = value.uint32_value(scope) else {
        throw(scope, &format!("{member} expects a uint32"));
        return None;
    };
    if limit == 0 {
        throw(scope, &format!("{member} expects a positive limit"));
        return None;
    }
    Some(limit)
}

/// The near-heap-limit callback that writes heap snapshots.
unsafe extern "C" fn snapshot_callback(
    data: *mut std::ffi::c_void,
    current_heap_limit: usize,
    initial_heap_limit: usize,
) -> usize {
    // V8 must get a larger limit back, so this is the floor for every path out.
    let raised = raised_limit(current_heap_limit, initial_heap_limit);
    let state = snapshot_state();

    let allowed = state.limit.load(Ordering::SeqCst);
    let taken = state.taken.load(Ordering::SeqCst);
    if taken >= allowed {
        state.armed.store(false, Ordering::SeqCst);
        return raised;
    }

    // SAFETY: `data` is the pointer `isolate_data` gave this registration.
    let Some(mut raw) = (unsafe { isolate_from_data(data) }) else {
        return raised;
    };
    // SAFETY: `raw` names the isolate that registered this callback, which is
    // alive for the duration of the call.
    let isolate = unsafe { v8::Isolate::ref_from_raw_isolate_ptr_mut(&mut raw) };

    let filename = snapshot_filename(taken + 1);
    match write_snapshot(isolate, &filename) {
        Err(error) => {
            eprintln!(
                "Failed to write heap snapshot {}: {error}",
                filename.display()
            );
            // A failure is not retried: the next collection would fail the same
            // way, and repeated attempts would slow the allocation that is
            // already close to the limit.
            state.armed.store(false, Ordering::SeqCst);
        }
        Ok(()) => {
            state.taken.store(taken + 1, Ordering::SeqCst);
            eprintln!("Wrote snapshot to {}", filename.display());
            if taken + 1 >= allowed {
                // Node removes the callback once it has taken the number of
                // snapshots it was asked for.
                state.armed.store(false, Ordering::SeqCst);
            }
        }
    }
    raised
}

/// The near-heap-limit callback for the heap-profile diagnostic.
unsafe extern "C" fn profile_callback(
    _data: *mut std::ffi::c_void,
    current_heap_limit: usize,
    initial_heap_limit: usize,
) -> usize {
    let state = profile_state();
    let raised = raised_limit(current_heap_limit, initial_heap_limit);
    // Printing once keeps a heap that keeps approaching its limit from flooding
    // stderr; the limit is still raised each time so the process can continue.
    if !state.reported.swap(true, Ordering::SeqCst) {
        eprintln!(
            "Failed to write heap profile: the sampling heap profiler is not implemented, \
             so there is no profile to write"
        );
    }
    state.armed.store(false, Ordering::SeqCst);
    raised
}

/// Writes one heap snapshot to `path`.
///
/// The file is created on the first chunk rather than up front so a snapshot
/// that produces nothing leaves no empty file behind, and the handle is dropped
/// before returning so the data is flushed by the time the caller reports the
/// path.
fn write_snapshot(isolate: &mut v8::Isolate, path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;

    let mut file: Option<std::fs::File> = None;
    let mut failure: Option<std::io::Error> = None;
    isolate.take_heap_snapshot(|chunk| {
        if file.is_none() {
            match std::fs::File::create(path) {
                Ok(handle) => file = Some(handle),
                Err(error) => {
                    failure = Some(error);
                    return false;
                }
            }
        }
        let Some(handle) = file.as_mut() else {
            return false;
        };
        match handle.write_all(chunk) {
            Ok(()) => true,
            Err(error) => {
                failure = Some(error);
                false
            }
        }
    });
    drop(file);
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// The limit a callback must return.
///
/// Node adds the young generation's maximum size to the current limit so the
/// diagnostic has room to allocate. There is no cheap way to ask the isolate for
/// that size from inside the callback, so this adds fixed headroom: all V8
/// requires is that the new limit exceeds the current one.
fn raised_limit(current_heap_limit: usize, initial_heap_limit: usize) -> usize {
    // A quarter of the initial limit, clamped so a small heap still gets real
    // headroom and a huge one does not ask for gigabytes.
    let headroom = (initial_heap_limit / 4).clamp(1 << 20, 64 << 20);
    current_heap_limit.saturating_add(headroom)
}

/// Where the next snapshot goes: the working directory, with a name in Node's
/// `DiagnosticFilename` form.
fn snapshot_filename(number: u32) -> std::path::PathBuf {
    let directory = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let pid = std::process::id();
    directory.join(format!("Heap.{pid}.{number}.heapsnapshot"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_raised_limit_is_always_greater_than_the_current_one() {
        // V8 may crash if a near-heap-limit callback returns a smaller limit,
        // so this is the one invariant every path has to hold.
        for (current, initial) in [
            (0usize, 0usize),
            (1024, 2048),
            (1 << 30, 4 << 30),
            (usize::MAX / 2, usize::MAX),
        ] {
            let raised = raised_limit(current, initial);
            assert!(raised > current, "{current} -> {raised} is not an increase");
        }
    }

    #[test]
    fn a_snapshot_name_identifies_the_process_and_the_ordinal() {
        let name = snapshot_filename(2);
        let text = name.file_name().expect("a file name").to_string_lossy();
        assert!(text.starts_with(&format!("Heap.{}", std::process::id())));
        assert!(text.ends_with(".2.heapsnapshot"));
    }

    #[test]
    fn the_shared_state_starts_unarmed() {
        // A fresh process has registered neither callback, so the first call
        // arms it rather than being treated as a repeat.
        assert!(!snapshot_state().armed.load(Ordering::SeqCst));
        assert!(!profile_state().armed.load(Ordering::SeqCst));
        assert_eq!(ISOLATE.load(Ordering::SeqCst), 0);
    }
}
