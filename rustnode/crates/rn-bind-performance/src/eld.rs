//! `createELDHistogram`, the native half of `perf_hooks.monitorEventLoopDelay()`.
//!
//! `lib/internal/perf/event_loop_delay.js` calls
//! `createELDHistogram(resolution, samplePerIteration, lowest, highest, figures)`
//! and wraps the returned object in `ELDHistogram`, which is a `Histogram` with
//! `enable()`/`disable()` that forward to `start()`/`stop()` on this handle. So
//! the object has to carry both the histogram handle interface and the two
//! control methods.
//!
//! # Two sampling modes, two libuv primitives
//!
//! Node's `IntervalHistogram` is a `uv_timer_t` that fires every `resolution`
//! milliseconds and records `recordDelta()`, which is the delay between
//! successive timer callbacks. `IterationHistogram` is a
//! `uv_prepare_t`/`uv_check_t` pair that measures how long the loop spent
//! between the prepare phase and the check phase — the per-iteration latency —
//! and records that.
//!
//! Both are unreferenced, because a histogram that kept the process alive would
//! mean `monitorEventLoopDelay()` could never let a script exit.
//!
//! # Why the handles are owned here rather than by a wrapper crate
//!
//! The timer and check handles have to outlive every call into this module and
//! be closed on the loop, and their callbacks need the histogram's state. They
//! are boxed alongside a raw pointer to the state so the callback can reach it
//! without a JavaScript hop. The state itself lives in
//! [`crate::histogram_binding`]'s internal field, so the JavaScript object and
//! the callback share one histogram.

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use crate::hdr::{HdrHistogram, Layout};
use crate::histogram_binding::{self, HistogramState};

/// Which way the histogram samples the loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// `uv_timer_t` firing every `resolution` milliseconds.
    Interval,
    /// `uv_prepare_t`/`uv_check_t` around each iteration.
    Iteration,
}

/// The native state one ELD handle owns.
///
/// The histogram itself is *not* here: it lives on the JavaScript object so the
/// whole `Histogram` accessor surface works on the same data. This struct holds
/// only the sampling machinery plus a borrowed pointer to that state.
pub struct EldState {
    mode: Mode,
    /// `resolution_`, in milliseconds.
    resolution: u64,
    /// Whether `enable()` has armed the handles.
    enabled: bool,
    /// A pointer to the histogram state on the JavaScript object.
    ///
    /// # Why a raw pointer
    ///
    /// A libuv callback fires from inside `uv_run`, which is a plain Rust call
    /// with no handle on the JavaScript object. The alternate designs are a
    /// global lookup keyed by a `uv_handle_t` (an extra indirection for every
    /// tick) or moving the histogram here and having the accessors go through
    /// it (which would leave the JS object without one). The pointer is set when
    /// `start()` arms the handles and cleared when the object is finalized, and
    /// every use is guarded by `enabled`.
    histogram: *mut RefCell<HistogramState>,
    /// The interval timer, for [`Mode::Interval`].
    timer: Option<Box<uv::uv_timer_t>>,
    /// The prepare and check handles, for [`Mode::Iteration`].
    prepare: Option<Box<uv::uv_prepare_t>>,
    check: Option<Box<uv::uv_check_t>>,
    /// `prepare_time_`: `uv_hrtime()` at the last prepare phase.
    prepare_time: u64,
    /// `check_time_`: `uv_hrtime()` at the last check phase.
    check_time: u64,
    /// `timeout_`: the `uv_backend_timeout` observed at the last prepare phase.
    timeout: i64,
}

// SAFETY: the struct is only ever touched from the thread that created the
// loop, which is also the isolate's thread. `histogram` points at state owned by
// a JavaScript object on that same thread.
unsafe impl Send for EldState {}

impl EldState {
    /// Builds the sampling state for one handle.
    pub fn new(mode: Mode, resolution: u64, histogram: *mut RefCell<HistogramState>) -> Self {
        Self {
            mode,
            resolution,
            enabled: false,
            histogram,
            timer: None,
            prepare: None,
            check: None,
            prepare_time: 0,
            check_time: 0,
            timeout: 0,
        }
    }

    /// Runs `body` with the histogram this handle measures.
    ///
    /// # Safety
    ///
    /// `body` must not re-enter JavaScript, and the pointer must still name the
    /// live state of the object this handle belongs to. Both are guaranteed by
    /// the callers in this module: they run either from a V8 callback holding
    /// the object alive, or from a libuv callback that only mutated the handle
    /// while `enabled` was true.
    unsafe fn with_histogram<R>(
        &mut self,
        body: impl FnOnce(&mut HistogramState) -> R,
    ) -> Option<R> {
        if self.histogram.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees the pointer is live.
        let cell = unsafe { &*self.histogram };
        let mut state = cell.borrow_mut();
        Some(body(&mut state))
    }
}

/// Reaches the [`EldState`] behind a libuv handle's `data` pointer.
///
/// The pointer stored in `data` is the `Box<EldState>`'s address, which is
/// stable because it was boxed before the handles were initialised.
///
/// # Safety
///
/// `handle` must be one this module initialised.
unsafe fn state_from_handle<T>(handle: *mut T) -> Option<&'static mut EldState> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the handle is live and ours, so `data` holds
    // the pointer `arm` stored there.
    let data = unsafe { (*(handle as *mut uv::uv_handle_t)).data };
    if data.is_null() {
        return None;
    }
    // SAFETY: `data` is the `Box<EldState>` address stored by `arm`.
    Some(unsafe { &mut *(data as *mut EldState) })
}

/// `IntervalHistogram::TimerCB`.
///
/// # Safety
///
/// Called by libuv with the timer this module started.
unsafe extern "C" fn on_interval_timer(handle: *mut uv::uv_timer_t) {
    // SAFETY: `handle` is the timer `arm` initialised and stored.
    let Some(state) = (unsafe { state_from_handle(handle) }) else {
        return;
    };
    if !state.enabled {
        return;
    }
    // SAFETY: the histogram pointer is live while the object owns this handle.
    let _ = unsafe { state.with_histogram(|histogram| histogram.record_delta()) };
}

/// `IterationHistogram::PrepareCB`: remember when the iteration's poll begins.
///
/// # Safety
///
/// Called by libuv with the prepare handle this module started.
unsafe extern "C" fn on_prepare(handle: *mut uv::uv_prepare_t) {
    // SAFETY: `handle` is the prepare handle `arm` initialised and stored.
    let Some(state) = (unsafe { state_from_handle(handle) }) else {
        return;
    };
    if !state.enabled {
        return;
    }
    state.prepare_time = crate::monotonic_nanos();
    // SAFETY: the handle's `loop` is the process' live loop.
    state.timeout = unsafe { uv::uv_backend_timeout((*handle).loop_) }.into();
}

/// `IterationHistogram::CheckCB`: record the latency the iteration observed.
///
/// The latency is the time from the previous check phase to this one's prepare
/// phase, plus any time poll spent beyond what it was told it could wait. The
/// second term is the point of the measurement: a loop that wanted to sleep 1ms
/// and actually slept 50ms reports the 49ms as delay.
///
/// # Safety
///
/// Called by libuv with the check handle this module started.
unsafe extern "C" fn on_check(handle: *mut uv::uv_check_t) {
    // SAFETY: `handle` is the check handle `arm` initialised and stored.
    let Some(state) = (unsafe { state_from_handle(handle) }) else {
        return;
    };
    if !state.enabled {
        return;
    }

    let check_time = crate::monotonic_nanos();
    let poll_time = check_time.saturating_sub(state.prepare_time);
    let mut latency = state.prepare_time.saturating_sub(state.check_time);

    if state.timeout >= 0 {
        let timeout_ns = (state.timeout as u64).saturating_mul(1_000_000);
        if poll_time > timeout_ns {
            latency += poll_time - timeout_ns;
        }
    }

    // A zero latency is recorded as 1ns, because a histogram cannot express a
    // zero-width sample and Node does the same.
    let recorded = if latency == 0 { 1 } else { latency };
    let _ = unsafe { state.with_histogram(|histogram| histogram.record(recorded as i64)) };
    state.check_time = check_time;
}

/// Arms the handles, or re-arms them after a `stop()`.
///
/// # Safety
///
/// `state` must be the live `Box<EldState>` this handle owns, and the loop must
/// be the process' loop.
unsafe fn arm(state: &mut EldState) -> bool {
    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        return false;
    };
    // The `Box<EldState>` address is what the callbacks get back through
    // `handle.data`; it is stable for as long as this state lives.
    let data = state as *mut EldState as *mut c_void;

    match state.mode {
        Mode::Interval => {
            let mut timer = Box::new(unsafe { std::mem::zeroed::<uv::uv_timer_t>() });
            // SAFETY: `loop_pointer` is the live loop and `timer` is an aligned,
            // writable `uv_timer_t`.
            let status =
                unsafe { uv::uv_timer_init(loop_pointer, timer.as_mut() as *mut uv::uv_timer_t) };
            if status != 0 {
                return false;
            }
            let pointer = timer.as_mut() as *mut uv::uv_timer_t;
            // SAFETY: the handle was just initialised on this loop.
            unsafe {
                uv::uv_handle_set_data(pointer.cast(), data);
                uv::uv_unref(pointer.cast());
            }
            // SAFETY: `pointer` is live and `on_interval_timer` only touches
            // thread-local state plus the histogram.
            let status = unsafe {
                uv::uv_timer_start(
                    pointer,
                    Some(on_interval_timer),
                    state.resolution,
                    state.resolution,
                )
            };
            if status != 0 {
                return false;
            }
            state.timer = Some(timer);
            true
        }
        Mode::Iteration => {
            let mut prepare = Box::new(unsafe { std::mem::zeroed::<uv::uv_prepare_t>() });
            let mut check = Box::new(unsafe { std::mem::zeroed::<uv::uv_check_t>() });
            // SAFETY: both boxes are aligned and writable, and the loop is live.
            unsafe {
                if uv::uv_prepare_init(loop_pointer, prepare.as_mut() as *mut uv::uv_prepare_t) != 0
                {
                    return false;
                }
                if uv::uv_check_init(loop_pointer, check.as_mut() as *mut uv::uv_check_t) != 0 {
                    return false;
                }
                uv::uv_handle_set_data((prepare.as_mut() as *mut uv::uv_prepare_t).cast(), data);
                uv::uv_handle_set_data((check.as_mut() as *mut uv::uv_check_t).cast(), data);
                uv::uv_unref((prepare.as_mut() as *mut uv::uv_prepare_t).cast());
                uv::uv_unref((check.as_mut() as *mut uv::uv_check_t).cast());
            }

            state.check_time = crate::monotonic_nanos();
            state.prepare_time = state.check_time;
            state.timeout = 0;

            // SAFETY: both handles are live on the loop and the callbacks only
            // touch thread-local state plus the histogram.
            unsafe {
                if uv::uv_check_start(check.as_mut() as *mut uv::uv_check_t, Some(on_check)) != 0 {
                    return false;
                }
                if uv::uv_prepare_start(prepare.as_mut() as *mut uv::uv_prepare_t, Some(on_prepare))
                    != 0
                {
                    return false;
                }
                uv::uv_unref((check.as_mut() as *mut uv::uv_check_t).cast());
                uv::uv_unref((prepare.as_mut() as *mut uv::uv_prepare_t).cast());
            }
            state.prepare = Some(prepare);
            state.check = Some(check);
            true
        }
    }
}

/// Stops whatever [`arm`] started.
///
/// # Safety
///
/// `state` must own live handles, or none.
unsafe fn disarm(state: &mut EldState) {
    // SAFETY: each handle, when present, is one `arm` initialised on the loop.
    unsafe {
        if let Some(timer) = state.timer.as_mut() {
            uv::uv_timer_stop(timer.as_mut() as *mut uv::uv_timer_t);
        }
        if let Some(check) = state.check.as_mut() {
            uv::uv_check_stop(check.as_mut() as *mut uv::uv_check_t);
        }
        if let Some(prepare) = state.prepare.as_mut() {
            uv::uv_prepare_stop(prepare.as_mut() as *mut uv::uv_prepare_t);
        }
    }
}

/// Closes and frees the handles, which libuv requires before the state goes.
///
/// # Safety
///
/// `state` must own handles that are no longer started.
unsafe fn close_handles(state: &mut EldState) {
    // SAFETY: the handles are ours and stopped. The close callback is `None`,
    // so libuv frees the handle storage it was given; the `Box` must therefore
    // outlive the close, which is why the boxes are leaked rather than dropped.
    unsafe {
        let close = |handle: *mut uv::uv_handle_t| {
            if !handle.is_null() && uv::uv_is_closing(handle) == 0 {
                uv::uv_close(handle, None);
            }
        };
        if let Some(timer) = state.timer.as_mut() {
            close((timer.as_mut() as *mut uv::uv_timer_t).cast());
        }
        if let Some(check) = state.check.as_mut() {
            close((check.as_mut() as *mut uv::uv_check_t).cast());
        }
        if let Some(prepare) = state.prepare.as_mut() {
            close((prepare.as_mut() as *mut uv::uv_prepare_t).cast());
        }
    }
}

// ---------------------------------------------------------------------------
// The JavaScript-facing surface.
// ---------------------------------------------------------------------------

/// Which field holds the [`EldState`] on the ELD object.
///
/// One more than the histogram's own field, so the object can carry both: the
/// JS layer calls the `Histogram` prototype methods on it *and* `start`/`stop`,
/// and those need different state.
const ELD_FIELD: i32 = 1;

thread_local! {
    static ELD_TEMPLATE: RefCell<Option<v8::Global<v8::FunctionTemplate>>> = const { RefCell::new(None) };
}

/// The [`EldState`] behind an ELD object.
fn eld_pointer(object: v8::Local<'_, v8::Object>) -> *mut RefCell<EldState> {
    if object.internal_field_count() <= ELD_FIELD as usize {
        return ptr::null_mut();
    }
    // SAFETY: the field is only written by `create`, on an object of this
    // module's template.
    unsafe {
        object.get_aligned_pointer_from_internal_field(ELD_FIELD, 0) as *mut RefCell<EldState>
    }
}

/// The `createELDHistogram` value, built so `new` on it fails.
///
/// `SetMethod` in Node installs a plain function whose `prototype` is absent, so
/// `new createELDHistogram()` throws `TypeError: ... is not a constructor`.
/// `FunctionTemplate::builder(...).build(...).get_function()` produces a
/// constructible function instead, which would make `new` reach the body and
/// throw `ERR_OUT_OF_RANGE` about the missing arguments — a different error for
/// the same mistake. `remove_prototype` is what makes the function
/// non-constructible here, which is also what `tools/constructible-audit.py`
/// observes through `Reflect.construct`.
pub(crate) fn create_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::method(create).length(5).build(scope);
    template.remove_prototype();
    // `SetMethod` names this after the property it is published under. The
    // template still has to be shaped first (`remove_prototype`), so this is
    // `named_template` rather than `named_method`.
    Ok(rn_core::named_template(scope, "createELDHistogram", template)?.into())
}

/// `createELDHistogram(resolution, samplePerIteration, lowest, highest, figures)`.
pub(crate) fn create(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(resolution) = args.get(0).uint32_value(scope) else {
        histogram_binding::throw_out_of_range(scope, "resolution must be a positive integer");
        return;
    };
    if resolution == 0 {
        histogram_binding::throw_out_of_range(scope, "resolution must be a positive integer");
        return;
    }
    let sample_per_iteration = args.get(1).boolean_value(scope);
    let (Ok(lowest), Ok(highest)) = (
        histogram_binding::int64_from_value(scope, args.get(2)),
        histogram_binding::int64_from_value(scope, args.get(3)),
    ) else {
        histogram_binding::throw_out_of_range(scope, "the histogram bounds are out of range");
        return;
    };
    let Some(figures) = args.get(4).uint32_value(scope) else {
        histogram_binding::throw_out_of_range(scope, "figures must be an unsigned integer");
        return;
    };
    let Ok(layout) = Layout::new(lowest, highest, figures as i32) else {
        histogram_binding::throw_out_of_range(scope, "Invalid histogram options");
        return;
    };

    let Some(template) = ELD_TEMPLATE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|template| v8::Local::new(scope, template))
    }) else {
        histogram_binding::throw_out_of_range(scope, "the histogram template is missing");
        return;
    };
    let instance = template.instance_template(scope);
    let Some(object) = instance.new_instance(scope) else {
        return;
    };

    // The object carries the histogram state in field 0, exactly like a plain
    // histogram, so every accessor method works on it unchanged.
    let histogram = HistogramState::new(HdrHistogram::new(layout), 0.0, 0);
    histogram_binding::install_state(scope, object, histogram);
    let histogram_pointer = histogram_binding::state_pointer(object);

    let mode = if sample_per_iteration {
        Mode::Iteration
    } else {
        Mode::Interval
    };
    let state = EldState::new(mode, u64::from(resolution), histogram_pointer);
    histogram_binding::install_eld_state(scope, object, state);

    rv.set(object.into());
}

/// `start(reset)`.
fn start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let reset = args.get(0).boolean_value(scope);
    let object = args.this();
    let pointer = eld_pointer(object);
    if pointer.is_null() {
        histogram_binding::throw_type_error(scope, "Illegal invocation");
        return;
    }
    // SAFETY: `pointer` is the live allocation for this object.
    let cell = unsafe { &*pointer };
    let mut state = cell.borrow_mut();
    if state.enabled {
        return;
    }
    state.enabled = true;
    if reset {
        if let Some(histogram_pointer) = {
            let histogram = histogram_binding::state_pointer(object);
            if histogram.is_null() {
                None
            } else {
                Some(histogram)
            }
        } {
            // SAFETY: the histogram state is on the same object, which is alive.
            let histogram_cell = unsafe { &*histogram_pointer };
            histogram_cell.borrow_mut().reset();
        }
    }
    // SAFETY: `state` is the live state this handle owns and the loop is live.
    unsafe {
        if !arm(&mut state) {
            state.enabled = false;
        }
    }
}

/// `stop()`.
fn stop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    let pointer = eld_pointer(object);
    if pointer.is_null() {
        histogram_binding::throw_type_error(scope, "Illegal invocation");
        return;
    }
    // SAFETY: `pointer` is the live allocation for this object.
    let cell = unsafe { &*pointer };
    let mut state = cell.borrow_mut();
    if !state.enabled {
        return;
    }
    state.enabled = false;
    // SAFETY: the handles, when present, were started by `arm`.
    unsafe { disarm(&mut state) };
}

/// `~IntervalHistogram`: stop and close the handles.
///
/// Exposed so the object's finalizer can release the libuv handles. Calling
/// `uv_close` from a V8 finalizer is what Node's `HandleWrap` does, and the
/// handles were unreferenced, so nothing here can revive a drained loop.
pub fn release_handles(pointer: *mut RefCell<EldState>) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: the pointer came from `install_eld_state` and the finalizer runs
    // exactly once.
    let cell = unsafe { &*pointer };
    if let Ok(mut state) = cell.try_borrow_mut() {
        state.enabled = false;
        // SAFETY: the handles belong to this state.
        unsafe {
            disarm(&mut state);
            close_handles(&mut state);
        }
        state.histogram = ptr::null_mut();
    }
}

/// Builds the ELD constructor, carrying the histogram prototype methods plus
/// `start`/`stop`.
///
/// The shared methods are what make `eld.count`, `eld.percentile(50)` and the
/// rest resolvable: `ELDHistogram` extends `Histogram` in
/// `lib/internal/perf/event_loop_delay.js`, and the native object here has to
/// offer the same handle interface.
pub(crate) fn register_template(scope: &mut v8::PinScope<'_, '_>) -> Result<(), String> {
    // `rn_core::class`, because this template exists to be handed to
    // `ObjectTemplate::new_instance`, and a non-constructible template makes
    // `new_instance` abort inside V8. The handle itself is never reachable
    // through `new` from JavaScript: `createELDHistogram` is the only way to get
    // one, and it is published as a method.
    let template = rn_core::class(noop_constructor).length(0).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(2);
    if let Some(name) = v8::String::new(scope, "Histogram") {
        // Node names the ELD handle's class `Histogram`, not `ELDHistogram`:
        // `ELDHistogram` is the JavaScript wrapper's name, and the handle itself
        // reports `Histogram` when inspected.
        template.set_class_name(name);
    }

    histogram_binding::add_histogram_methods(scope, template)?;

    let prototype = template.prototype_template(scope);
    for (name, length, callback) in [
        ("start", 1, histogram_binding::method(scope, 1, start)),
        ("stop", 0, histogram_binding::method(scope, 0, stop)),
    ] {
        let key = v8::String::new(scope, name).ok_or("cannot allocate a method name")?;
        let _ = length;
        prototype.set(key.into(), callback.into());
    }

    ELD_TEMPLATE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, template)));
    Ok(())
}

/// A constructor that does nothing, for a template whose instances are only
/// ever built by `create`.
///
/// `uv_timer_init` and friends are what make an ELD handle; letting JavaScript
/// call `new` would produce an object with no handles and a `start()` that
/// silently did nothing.
fn noop_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    histogram_binding::throw_type_error(scope, "Illegal constructor");
}
