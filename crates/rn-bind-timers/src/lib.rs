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

use std::cell::RefCell;

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
    /// Durations `scheduleTimer` has been asked to wake at, in milliseconds.
    ///
    /// The event loop that would honour these does not exist yet; recording
    /// them keeps the call honest instead of pretending a timer was armed.
    static SCHEDULED: RefCell<Vec<i64>> = const { RefCell::new(Vec::new()) };
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
    // `uv_now` is the loop's cached monotonic time in milliseconds. The loop
    // does not exist yet, so this reads the clock directly, which is what the
    // loop does when it refreshes that cache.
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
    SCHEDULED.with(|scheduled| {
        let mut scheduled = scheduled.borrow_mut();
        // Only the earliest deadline matters to a loop, and the list is kept
        // short so a long-lived process cannot grow it without bound.
        scheduled.push(duration);
        if scheduled.len() > 1024 {
            scheduled.drain(..512);
        }
    });
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
    INFO.with(|info| {
        if let Some(info) = info.borrow().as_ref() {
            let current = info.immediate.get(IMMEDIATE_REF_COUNT).unwrap_or(0);
            let next = if increment {
                current.saturating_add(1)
            } else {
                current.saturating_sub(1)
            };
            info.immediate.set(IMMEDIATE_REF_COUNT, next);
            // `hasOutstanding` is derived: any ref'd immediate keeps the loop
            // alive, which is the only thing the count is used for.
            info.immediate
                .set(IMMEDIATE_HAS_OUTSTANDING, u32::from(next > 0));
        }
    });
}

fn toggle_timer_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let increment = args.get(0).boolean_value(scope);
    INFO.with(|info| {
        if let Some(info) = info.borrow().as_ref() {
            let current = info.timeout.get(TIMEOUT_REF_COUNT).unwrap_or(0);
            let next = if increment {
                current.saturating_add(1)
            } else {
                current.saturating_sub(1)
            };
            info.timeout.set(TIMEOUT_REF_COUNT, next);
            // Node writes the same count into the `immediateInfo` count slot so
            // `process._getActiveHandles` can report timers without a second
            // array.
            info.immediate.set(IMMEDIATE_COUNT, next);
        }
    });
}

/// Runs the timer callback `setupTimers` installed, if there is one.
///
/// `lib/internal/timers.js` normally drives this itself; the runtime calls it
/// when it has to process a due timer from the native side.
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
