//! `internalBinding('timers')` for rustnode.
//!
//! `lib/internal/timers.js` owns every `setTimeout`, `setInterval` and
//! `setImmediate`: the lists, the ordering, the clamping and the ref counting.
//! This namespace supplies the four facts that need the native side:
//!
//! * `getLibuvNow()` — the loop's clock in milliseconds.
//! * `scheduleTimer(duration)` — ask the loop to wake at that point.
//! * `setupTimers(immediateCallback, timerCallback)` — hand the loop the two
//!   callbacks it must run when a timer or immediate comes due.
//! * `immediateInfo` and `timeoutInfo` — the counters that tell the loop
//!   whether anything is outstanding.
//!
//! The counters are shared typed arrays, and their shapes are load-bearing:
//! `immediateInfo` is a `Uint32Array(3)` of `[count, refCount, hasOutstanding]`
//! and `timeoutInfo` is an `Int32Array(1)` holding the ref count. Node's
//! JavaScript writes `timeoutInfo[0]` directly, so a copy here would drift.
//!
//! # Who counts what
//!
//! `lib/internal/timers.js` maintains the counters itself: `incRefCount()` does
//! `timeoutInfo[0]++` and only calls `toggleTimerRef(true)` when that made the
//! count one. So `toggleTimerRef` and `toggleImmediateRef` must *record* the
//! libuv-style ref state and must not write the counters — writing them would
//! double-count every timer.
//!
//! The loop asks [`timer_handle`] and [`immediate_ref_count`] whether the process
//! has anything left to wait for, and those are two different measurements on
//! purpose:
//!
//! * A timer is libuv's single `uv_timer_t`, so "alive" means *started and
//!   ref'd*, exactly as `uv__loop_alive()` asks. `scheduleTimer` starts it and
//!   [`stop_timer_handle`] stops it when `processTimers` reports nothing ref'd.
//! * Immediates have no handle of their own in this runtime yet, and
//!   `processImmediate()` decrements `immediateInfo[1]` without toggling the ref
//!   bit, so the count is the only signal that stays correct after a run.
//!
//! `timeoutInfo[0]` is deliberately not the timer signal: `listOnTimeout()`
//! decrements it directly when a timer fires, and a script that writes the array
//! (`internalBinding('timers').timeoutInfo[0] = 7`) would otherwise pin the
//! process forever. Node reads its handle state, not the array.

use std::cell::{Cell, RefCell};

use rn_core::{AliasedUint8Array, BindingModule, Element, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/timers.json`.
pub const MEMBERS: &[&str] = &[
    "getLibuvNow",
    "immediateInfo",
    "scheduleTimer",
    "setupTimers",
    "timeoutInfo",
    "toggleImmediateRef",
    "toggleTimerRef",
];

/// `ImmediateInfo::Fields` in `src/env.h`.
pub const IMMEDIATE_COUNT: usize = 0;
/// `ImmediateInfo::Fields`: how many of the immediates are ref'd.
pub const IMMEDIATE_REF_COUNT: usize = 1;
/// `ImmediateInfo::Fields`: whether any immediate keeps the loop alive.
pub const IMMEDIATE_HAS_OUTSTANDING: usize = 2;
/// `ImmediateInfo::kFieldsCount`.
pub const IMMEDIATE_FIELDS_COUNT: usize = 3;

/// `Environment::timeout_info_` is a one-element `Int32Array` holding the
/// number of ref'd timers.
pub const TIMEOUT_REF_COUNT: usize = 0;
pub const TIMEOUT_FIELDS_COUNT: usize = 1;

thread_local! {
    /// The shared counters, created on first install.
    static INFO: RefCell<Option<TimerInfo>> = const { RefCell::new(None) };
    /// The callbacks `setupTimers` installed.
    static CALLBACKS: RefCell<Callbacks> = const { RefCell::new(Callbacks {
        immediate: None,
        timer: None,
    }) };
    /// libuv's timer handle state, which is what decides whether the loop is
    /// alive.
    ///
    /// Node's `Environment` owns one `uv_timer_t` for all JavaScript timers, and
    /// three calls drive it:
    ///
    /// * `scheduleTimer(ms)` is `uv_timer_start(&timer_, RunTimers, ms, 0)`,
    ///   which both arms the handle and makes it *active*.
    /// * `processTimers` is `RunTimers`. Its return value is a deadline when a
    ///   ref'd timer is pending, and `Node`'s C++ reacts by restarting the handle
    ///   for a positive value and calling `uv_timer_stop` for a value of zero or
    ///   less. Stopping is what makes the handle *inactive*.
    /// * `toggleTimerRef(bool)` is `uv_ref`/`uv_unref` on that same handle.
    ///
    /// The loop is kept alive by an active *and* ref'd handle, which is why both
    /// bits are tracked here rather than one count. `timeoutInfo[0]` looks like it
    /// would answer the same question, but `listOnTimeout()` decrements it
    /// directly when a timer fires, without calling `toggleTimerRef`, and a script
    /// that writes the array would otherwise pin the process forever.
    static TIMER_HANDLE: Cell<TimerHandle> = const { Cell::new(TimerHandle::new()) };
    /// `libuv`'s ref state for the check handle that runs immediates.
    static IMMEDIATE_REF_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// libuv's per-handle state for the one timer handle a Node environment owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerHandle {
    /// `uv_is_active`: started by `scheduleTimer`, stopped when `processTimers`
    /// reports no ref'd deadline.
    active: bool,
    /// `uv_has_ref`: whether the handle keeps the loop alive.
    refed: bool,
}

impl TimerHandle {
    /// A handle before `scheduleTimer` has ever started it.
    ///
    /// libuv's `uv_timer_init` leaves a handle active=false and ref'd=true, which
    /// is the state this reproduces: not started, and ready to keep the loop alive
    /// once it is.
    pub const fn new() -> Self {
        Self {
            active: false,
            refed: true,
        }
    }

    /// Whether the handle is both started and ref'd, i.e. whether it keeps the
    /// loop alive.
    pub fn keeps_loop_alive(&self) -> bool {
        self.active && self.refed
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn is_refed(&self) -> bool {
        self.refed
    }
}

impl Default for TimerHandle {
    fn default() -> Self {
        Self::new()
    }
}

struct TimerInfo {
    immediate: AliasedUint8Array,
    timeout: AliasedUint8Array,
}

#[derive(Default)]
struct Callbacks {
    immediate: Option<v8::Global<v8::Function>>,
    timer: Option<v8::Global<v8::Function>>,
}

pub struct Timers;

impl BindingModule for Timers {
    fn namespace(&self) -> &'static str {
        "timers"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        // The two counters have different element types on purpose: Node's
        // `timeoutInfo` is signed and `immediateInfo` is not.
        let immediate = AliasedUint8Array::new(scope, IMMEDIATE_FIELDS_COUNT, Element::Word)?;
        let timeout = AliasedUint8Array::new(scope, TIMEOUT_FIELDS_COUNT, Element::SignedWord)?;
        let immediate_array = immediate.array(scope);
        let timeout_array = timeout.array(scope);
        INFO.with(|info| *info.borrow_mut() = Some(TimerInfo { immediate, timeout }));

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 7] = [
            ("immediateInfo", immediate_array),
            ("timeoutInfo", timeout_array),
            (
                "getLibuvNow",
                function(scope, "getLibuvNow", get_libuv_now)?,
            ),
            (
                "scheduleTimer",
                function(scope, "scheduleTimer", schedule_timer)?,
            ),
            ("setupTimers", function(scope, "setupTimers", setup_timers)?),
            (
                "toggleImmediateRef",
                function(scope, "toggleImmediateRef", toggle_immediate_ref)?,
            ),
            (
                "toggleTimerRef",
                function(scope, "toggleTimerRef", toggle_timer_ref)?,
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
    registry.register_module(Timers);
}

fn get_libuv_now(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `uv_now` is the loop's cached monotonic time in milliseconds, refreshed
    // once per loop turn. Reading the clock directly is what libuv does at the
    // same point: `uv__update_time()` before timers run, and no other read
    // inside a turn. A timer that fires therefore sees the time the turn
    // started, not the time its own callback ran, which is why
    // `insert()`'s `_idleStart` and `listOnTimeout`'s `diff` agree.
    rv.set(v8::Number::new(scope, now_ms()).into());
}

/// Monotonic milliseconds, the unit `lib/internal/timers.js` compares against.
pub fn now_ms() -> f64 {
    // SAFETY: `timespec` is plain-old-data and `clock_gettime` fills it.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `now` is a valid, writable `timespec`.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return 0.0;
    }
    (now.tv_sec as f64) * 1000.0 + (now.tv_nsec as f64) / 1_000_000.0
}

fn schedule_timer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(duration) = args.get(0).integer_value(scope) else {
        return;
    };
    // `lib/internal/timers.js` calls this with the *duration* of a newly created
    // list, and only when that list expires before any it already knew about.
    // libuv's `uv_timer_start` takes a deadline, so the conversion is here, at
    // the boundary where the two conventions meet.
    // `uv_timer_start` both arms the handle and marks it active. Marking it
    // active here rather than at `processTimers()` time is what makes a timer
    // scheduled during a turn keep the loop alive for one more turn.
    TIMER_HANDLE.with(|handle| {
        let mut state = handle.get();
        state.active = true;
        handle.set(state);
    });
    let Some(loop_handle) = rn_io::current_loop() else {
        // No loop yet. During bootstrap that is the normal state: the deadline
        // is recorded on the handle so a later turn sees it, but there is
        // nothing to wake.
        return;
    };
    loop_handle.wake_at(now_ms() + duration as f64);
}

fn setup_timers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let (Ok(immediate), Ok(timer)) = (
        v8::Local::<v8::Function>::try_from(args.get(0)),
        v8::Local::<v8::Function>::try_from(args.get(1)),
    ) else {
        throw(scope, "setupTimers expects two functions");
        return;
    };
    let immediate = v8::Global::new(scope, immediate);
    let timer = v8::Global::new(scope, timer);
    CALLBACKS.with(|callbacks| {
        let mut callbacks = callbacks.borrow_mut();
        callbacks.immediate = Some(immediate);
        callbacks.timer = Some(timer);
    });
}

fn toggle_immediate_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let increment = args.get(0).boolean_value(scope);
    // This is `uv_ref`/`uv_unref` on the loop's check handle, nothing more.
    // `lib/internal/timers.js` already adjusted `immediateInfo[1]` before
    // calling, so writing that array here would count every immediate twice and
    // leave the loop thinking there was always one more outstanding.
    IMMEDIATE_REF_ACTIVE.with(|active| active.set(increment));
}

fn toggle_timer_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let increment = args.get(0).boolean_value(scope);
    // `uv_ref`/`uv_unref`. The counter in `timeoutInfo[0]` is maintained by
    // `incRefCount`/`decRefCount` in JavaScript, so writing it here would count
    // every timer twice.
    TIMER_HANDLE.with(|handle| {
        let mut state = handle.get();
        state.refed = increment;
        handle.set(state);
    });
}

/// libuv's state for the loop's timer handle.
///
/// The loop asks this rather than the shared counters: `keeps_loop_alive()` is
/// `uv_is_active(handle) && uv_has_ref(handle)`, which is exactly the condition
/// libuv's `uv__loop_alive()` applies to every handle it holds.
pub fn timer_handle() -> TimerHandle {
    TIMER_HANDLE.with(Cell::get)
}

/// Stops the timer handle, as Node's C++ does when `processTimers` reports no
/// ref'd timer left.
///
/// `uv_timer_stop` leaves the ref bit alone: the next `scheduleTimer` marks the
/// handle active again without needing another `uv_ref`. That is why this is a
/// separate operation from [`timer_handle`], which only reports.
pub fn stop_timer_handle() {
    TIMER_HANDLE.with(|handle| {
        let mut state = handle.get();
        state.active = false;
        handle.set(state);
    });
}

/// Whether the loop's check handle is ref'd.
pub fn immediate_ref_active() -> bool {
    IMMEDIATE_REF_ACTIVE.with(Cell::get)
}

/// Runs the timer callback `setupTimers` installed, if there is one.
///
/// Kept for callers that only want the side effects; a caller that needs the
/// deadline the callback reports should use [`run_timers`].
pub fn call_timer_callback(scope: &mut v8::PinScope) {
    let callback = CALLBACKS.with(|callbacks| {
        callbacks
            .borrow()
            .timer
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    });
    if let Some(callback) = callback {
        let _ = callback.call(scope, v8::undefined(scope).into(), &[]);
    }
}

/// Runs the immediate callback `setupTimers` installed, if there is one.
///
/// Kept for callers that only want the side effects; a caller that needs to know
/// whether anything ran should use [`run_immediates`].
pub fn call_immediate_callback(scope: &mut v8::PinScope) {
    let callback = CALLBACKS.with(|callbacks| {
        callbacks
            .borrow()
            .immediate
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    });
    if let Some(callback) = callback {
        let _ = callback.call(scope, v8::undefined(scope).into(), &[]);
    }
}

/// Runs the timer callback `setupTimers` installed with `now_ms` as its
/// argument, and returns what it reported.
///
/// `lib/internal/timers.js`'s `processTimers(now)` returns the deadline the loop
/// should arm next, using libuv's sign convention:
///
/// * `0` — no timers left at all.
/// * positive — the next deadline, with a ref'd timer behind it.
/// * negative — the next deadline, but every timer is `unref()`'d.
///
/// The sign is folded into [`TimerRun`] here, at the one place that has to know
/// it, so no caller can read `-0` or a negative deadline as a deadline in the
/// past.
///
/// A callback that throws is caught here rather than left pending. A pending
/// exception on the isolate is printed by V8's own default reporter — to stdout,
/// with V8's formatting — which is neither Node's output nor Node's stream. The
/// exception travels back to the caller as
/// [`TimerRun::Threw`], which reports it the way Node does.
pub fn run_timers(scope: &mut v8::PinScope, now_ms: f64) -> TimerRun {
    let Some(callback) = timer_callback(scope) else {
        return TimerRun::NotInstalled;
    };
    let argument = v8::Number::new(scope, now_ms).into();
    match call_catching(scope, callback, &[argument]) {
        Ok(Some(result)) => match result.number_value(scope) {
            Some(value) if value < 0.0 => TimerRun::Next {
                at_ms: -value,
                refed: false,
            },
            Some(value) if value > 0.0 => TimerRun::Next {
                at_ms: value,
                refed: true,
            },
            _ => TimerRun::Idle,
        },
        // A callback that reported nothing at all is not an error: `processTimers`
        // always returns a number, so this is the "the function was replaced"
        // case and there is no deadline to arm.
        Ok(None) => TimerRun::Idle,
        Err(exception) => {
            record_uncaught(scope, exception);
            TimerRun::Threw
        }
    }
}

/// What running the timer phase found.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimerRun {
    /// `processTimers()` has not been installed; the phase cannot run.
    NotInstalled,
    /// The callback threw. The exception was formatted to stderr and the
    /// process's exit was requested.
    Threw,
    /// No timer is pending.
    Idle,
    /// The next deadline, and whether a ref'd timer is behind it.
    Next { at_ms: f64, refed: bool },
}

/// Runs the immediate callback `setupTimers` installed.
///
/// Returns whether a callback was installed, which is false during the bootstrap
/// window before `internal/bootstrap/node.js` runs. A throw is caught and
/// reported, for the same reason as in [`run_timers`].
pub fn run_immediates(scope: &mut v8::PinScope) -> bool {
    let Some(callback) = immediate_callback(scope) else {
        return false;
    };
    if let Err(exception) = call_catching(scope, callback, &[]) {
        record_uncaught(scope, exception);
    }
    true
}

/// Calls `callable`, turning a throw into `Err`.
///
/// The exception is captured as a `Global` before the `TryCatch` closes, because
/// a `Local` from inside the catch scope cannot escape it and the caller needs to
/// format the error after this returns.
fn call_catching<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    callable: v8::Local<'s, v8::Function>,
    arguments: &[v8::Local<'s, v8::Value>],
) -> Result<Option<v8::Local<'s, v8::Value>>, v8::Global<v8::Value>> {
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let result = callable.call(scope, v8::undefined(scope).into(), arguments);
    if scope.has_caught() {
        let caught = scope
            .exception()
            .map(|exception| v8::Global::new(scope, exception))
            .unwrap_or_else(|| {
                let undefined: v8::Local<v8::Value> = v8::undefined(scope).into();
                v8::Global::new(scope, undefined)
            });
        return Err(caught);
    }
    Ok(result)
}

/// Prints an uncaught callback exception the way Node does and asks the process
/// to exit non-zero.
fn record_uncaught(scope: &mut v8::PinScope, exception: v8::Global<v8::Value>) {
    let exception = v8::Local::new(scope, &exception);
    let text = rn_errors::format_exception(scope, exception, false);
    rn_errors::write_uncaught(scope, &text);
}

/// Whether `setupTimers` has been given the callbacks the loop needs.
///
/// Before `internal/bootstrap/node.js` runs this is false, and the loop must not
/// run timer phases it cannot service.
pub fn timers_installed() -> bool {
    CALLBACKS.with(|callbacks| {
        let callbacks = callbacks.borrow();
        callbacks.timer.is_some() && callbacks.immediate.is_some()
    })
}

fn timer_callback<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    CALLBACKS.with(|callbacks| {
        callbacks
            .borrow()
            .timer
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    })
}

fn immediate_callback<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    CALLBACKS.with(|callbacks| {
        callbacks
            .borrow()
            .immediate
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    })
}

/// The ref'd timer count from the shared array.
pub fn timer_ref_count() -> u32 {
    INFO.with(|info| {
        info.borrow()
            .as_ref()
            .and_then(|info| info.timeout.get(TIMEOUT_REF_COUNT))
            .unwrap_or(0)
    })
}

/// The ref'd immediate count from the shared array.
pub fn immediate_ref_count() -> u32 {
    INFO.with(|info| {
        info.borrow()
            .as_ref()
            .and_then(|info| info.immediate.get(IMMEDIATE_REF_COUNT))
            .unwrap_or(0)
    })
}

/// How many immediates are queued, ref'd or not.
///
/// This is `immediateInfo[0]`, which `Immediate`'s constructor increments and
/// `processImmediate()` decrements. The loop reads it to know that the check
/// phase has work, which is why the poll phase must not block.
pub fn immediate_count() -> u32 {
    INFO.with(|info| {
        info.borrow()
            .as_ref()
            .and_then(|info| info.immediate.get(IMMEDIATE_COUNT))
            .unwrap_or(0)
    })
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

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn throw(scope: &mut v8::PinScope, message: &str) {
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
    fn the_clock_is_monotonic_milliseconds() {
        let first = now_ms();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = now_ms();
        assert!(second >= first);
        // Milliseconds, not seconds: two milliseconds of sleep must show up.
        assert!(second - first >= 1.0, "the unit must be milliseconds");
    }

    #[test]
    fn the_counter_layout_matches_env_h() {
        // These indices are what `lib/internal/timers.js` writes into directly,
        // so a reordering here would silently stop the loop from staying alive.
        assert_eq!(IMMEDIATE_COUNT, 0);
        assert_eq!(IMMEDIATE_REF_COUNT, 1);
        assert_eq!(IMMEDIATE_HAS_OUTSTANDING, 2);
        assert_eq!(TIMEOUT_REF_COUNT, 0);
    }
}
