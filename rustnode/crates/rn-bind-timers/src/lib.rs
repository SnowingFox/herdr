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
//! # The handles are libuv's, and they are the point
//!
//! Node's `Environment` owns one `uv_timer_t`, one check handle for
//! `setImmediate` and one idle handle, and the callbacks those handles run are
//! `processTimers` and `processImmediate`. rustnode does exactly that: the
//! handles are created on the loop `rn-uv` owns, and `libuv` decides when they
//! fire because it is `uv_run` that runs them.
//!
//! That is what makes the ordering Node's rather than an approximation of it.
//! `uv__run_timers` is the last thing an iteration does, `uv__run_check` is
//! after poll and before close, and `uv__run_idle` runs before poll without
//! letting it block — so an immediate cannot be starved by a poll that waits for
//! a timer, and a 0ms timer created in the script body is due before the first
//! iteration rather than after it.
//!
//! # Who counts what
//!
//! `lib/internal/timers.js` maintains the counters itself: `incRefCount()` does
//! `timeoutInfo[0]++` and only calls `toggleTimerRef(true)` when that made the
//! count one. So `toggleTimerRef` and `toggleImmediateRef` must map onto
//! `uv_ref`/`uv_unref` of the corresponding handle and must not write the
//! counters — writing them would double-count every timer.
//!
//! `timeoutInfo[0]` is deliberately not the timer signal: `listOnTimeout()`
//! decrements it directly when a timer fires, and a script that writes the array
//! (`internalBinding('timers').timeoutInfo[0] = 7`) would otherwise pin the
//! process forever or let it exit early. libuv reads its handle state, not the
//! array.
//!
//! # The idle handle
//!
//! Node runs `setImmediate` callbacks from a check handle, and starts an idle
//! handle while an immediate is outstanding. The idle handle is what defeats
//! `uv__io_poll`'s "nothing to wait for" shortcut, and it also makes the check
//! phase run before poll blocks when the only other work is a timer that is not
//! due yet. Without it, `setImmediate(g)` next to `setTimeout(f, 200)` would sit
//! in poll for 200ms before running `g`; with it, `g` runs first, in the
//! iteration that starts immediately.

use std::cell::{Cell, RefCell};
use std::pin::Pin;

use libuv_sys2 as uv;
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
    /// The three libuv handles `Environment` owns for JavaScript timers.
    ///
    /// Created lazily, on the first `scheduleTimer`, `setImmediate` or
    /// `processTimers` call, because a handle needs the loop and the loop is
    /// created by whoever needs it first. `None` means "not created yet".
    static HANDLES: RefCell<Handles> = const { RefCell::new(Handles::new()) };
    /// Extra work the check phase runs after `processImmediate`.
    ///
    /// `setImmediate` is not the only thing Node's check phase carries: a
    /// `MessagePort` is delivered from it too. The handle lives in this crate and
    /// the consumer lives in another namespace, so the consumer registers here
    /// rather than this crate depending on it.
    static CHECK_PHASE_HOOK: Cell<Option<fn(&mut v8::PinScope<'_, '_>)>> = const { Cell::new(None) };

    /// Additional check-phase hooks, run after the primary one.
    ///
    /// A list rather than one slot because the producers live in crates that
    /// cannot depend on each other; see `add_check_phase_hook`.
    static EXTRA_CHECK_PHASE_HOOKS: RefCell<Vec<fn(&mut v8::PinScope<'_, '_>)>> =
        const { RefCell::new(Vec::new()) };

    /// Predicates for work that keeps the process alive outside libuv.
    static EXTERNAL_WORK: RefCell<Vec<fn() -> bool>> = const { RefCell::new(Vec::new()) };

    /// Predicates for work the check phase must run, beyond immediates.
    static EXTRA_CHECK_PHASE_PENDING: RefCell<Vec<fn() -> bool>> = const { RefCell::new(Vec::new()) };
    /// Whether that extra work has anything queued.
    ///
    /// A `MessagePort` with a message waiting needs the check phase to run once,
    /// and nothing in `immediateInfo` says so, so the handle is started from this
    /// predicate as well as from the immediate count.
    static CHECK_PHASE_PENDING: RefCell<Option<fn() -> bool>> = const { RefCell::new(None) };
}

/// The JavaScript callbacks the loop's handles run.
#[derive(Default)]
struct Callbacks {
    immediate: Option<v8::Global<v8::Function>>,
    timer: Option<v8::Global<v8::Function>>,
}

struct TimerInfo {
    immediate: AliasedUint8Array,
    timeout: AliasedUint8Array,
}

/// The libuv handles a Node environment keeps for its timers.
///
/// Each is a `Pin<Box<..>>`: libuv requires a handle not to move after
/// `uv_*_init`, so it is allocated first and initialised where it sits.
struct Handles {
    timer: Option<Pin<Box<uv::uv_timer_t>>>,
    check: Option<Pin<Box<uv::uv_check_t>>>,
    idle: Option<Pin<Box<uv::uv_idle_t>>>,
}

impl Handles {
    const fn new() -> Self {
        Self {
            timer: None,
            check: None,
            idle: None,
        }
    }
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
        // The loop's timer and check handles fire from inside `uv_run`, where
        // there is no V8 scope and no entered context. Recording the isolate and
        // context here is what lets their callbacks reach JavaScript at all, and
        // `timers` installs earlier than any I/O binding, so doing it here is
        // what makes the first `setTimeout` work rather than the first
        // `net.connect`.
        rn_uv::callback::remember_context(scope);

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
    // `uv_now` is the loop's cached time, which libuv refreshes once per
    // iteration. Measured against real `node`, `getLibuvNow()` reports the time
    // the *call* was made, not the start of the iteration: across a 300ms busy
    // wait inside a script the value advances by 299ms, and `_idleStart` shows
    // the same. Node's `Environment::Now()` therefore refreshes before reading,
    // and so does this.
    //
    // It matters for accuracy, not just cosmetics: `uv_timer_start` adds its
    // timeout to the same cached value, so a stale cache would arm a timer
    // against a deadline that had already partly elapsed.
    rn_uv::uv_loop::update_time();
    rv.set(v8::Number::new(scope, rn_uv::uv_loop::now_ms()).into());
}

/// Monotonic milliseconds from a fresh read of the clock.
///
/// This is the fallback for a caller that runs before the loop exists. Unlike
/// [`rn_uv::uv_loop::now_ms`] it is not cached, so it must not be used where
/// Node compares against `_idleStart`.
pub fn wall_now_ms() -> f64 {
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
    // `uv_timer_start` takes a timeout and adds it to the loop's cached time, so
    // it is the same unit; the important part is that it is `uv_timer_start` and
    // not a deadline recorded on the side, because only libuv's own timer heap
    // decides how long the next poll waits.
    let Some(timer) = ensure_timer_handle() else {
        return;
    };
    // A negative duration is a timer already due, which libuv spells as 0.
    let timeout = u64::try_from(duration).unwrap_or(0);
    // `uv_timer_start` adds the timeout to the loop's *cached* time, so the
    // cache has to be fresh or the timer is armed against a deadline that has
    // already partly elapsed. `lib/internal/timers.js` computed `duration` from
    // a fresh `getLibuvNow()`, so the two must agree.
    rn_uv::uv_loop::update_time();
    // SAFETY: `timer` is the live handle this module owns, and the callback only
    // touches thread-local state plus V8 through `rn_uv::callback`.
    let status = unsafe { uv::uv_timer_start(timer, Some(on_timer), timeout, 0) };
    if status != 0 {
        tracing::error!(status, "uv_timer_start failed");
    }
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
    // The handle callbacks were installed before JavaScript could name them, so
    // this is only about recording them. Creating the handles here rather than
    // on first `scheduleTimer` means the first timer does not pay for two
    // `uv_*_init` calls inside a poll that is already timed out.
    let _ = ensure_timer_handle();
    let _ = ensure_immediate_handles();
    // Native immediates (`AsyncWrap::EmitDestroy`'s deferred `destroy`) are
    // queued by another crate and drained from this one's check phase, so the
    // queue needs a way to ask for that phase. Registering here rather than
    // lazily matters: a destroy queued from the script body must arm the handle
    // before the loop decides it has nothing left to do.
    rn_core::native_immediates::set_wakeup(arm_check_phase);
}

fn toggle_immediate_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let increment = args.get(0).boolean_value(scope);
    // `uv_ref`/`uv_unref` on the loop's check handle, and start/stop of the idle
    // handle that stops poll from blocking while an immediate is queued.
    // `lib/internal/timers.js` already adjusted `immediateInfo[1]` before
    // calling, so writing that array here would count every immediate twice and
    // leave the loop thinking there was always one more outstanding.
    let Some((check, idle)) = ensure_immediate_handles() else {
        return;
    };
    // SAFETY: both are the live handles this module owns.
    unsafe {
        if increment {
            // `uv_check_start` both activates the handle and, because a handle
            // is ref'd by default, makes the loop count it. Re-starting an
            // already active handle is a no-op, so this is safe on every
            // immediate. The idle handle stops poll from blocking while an
            // immediate is waiting for the check phase.
            let status = uv::uv_check_start(check, Some(on_check));
            if status != 0 {
                tracing::error!(status, "uv_check_start failed");
            }
            uv::uv_ref(check.cast());
            uv::uv_idle_start(idle, Some(on_idle));
        } else {
            // Only the idle handle and the ref bit change here. The check handle
            // keeps running: an `unref()`'d immediate must still be run by any
            // later iteration that happens for another reason, which is what real
            // `node` does with a 20ms timer next to `setImmediate(f).unref()`.
            uv::uv_unref(check.cast());
            uv::uv_idle_stop(idle);
        }
    }
}

fn toggle_timer_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let increment = args.get(0).boolean_value(scope);
    // `uv_ref`/`uv_unref` on the timer handle. The counter in `timeoutInfo[0]` is
    // maintained by `incRefCount`/`decRefCount` in JavaScript, so writing it here
    // would count every timer twice.
    let Some(timer) = ensure_timer_handle() else {
        return;
    };
    // SAFETY: `timer` is the live handle this module owns.
    unsafe {
        if increment {
            uv::uv_ref(timer.cast());
        } else {
            uv::uv_unref(timer.cast());
        }
    }
}

/// The loop's `uv_timer_t`, created on first use.
///
/// `None` means the loop itself could not be created, which is the only way a
/// handle here can fail.
fn ensure_timer_handle() -> Option<*mut uv::uv_timer_t> {
    HANDLES.with(|handles| {
        let mut handles = handles.borrow_mut();
        if handles.timer.is_none() {
            let loop_pointer = rn_uv::uv_loop::loop_ptr()?;
            let handle = Box::pin(std::mem::MaybeUninit::<uv::uv_timer_t>::zeroed());
            // SAFETY: `handle` points at a live, aligned, zeroed slot, and
            // `loop_pointer` is the process' live loop.
            let status = unsafe { uv::uv_timer_init(loop_pointer, pin_ptr(&handle)) };
            if status != 0 {
                tracing::error!(status, "uv_timer_init failed");
                return None;
            }
            // SAFETY: `uv_timer_init` succeeded, so the slot is initialised.
            handles.timer = Some(unsafe { assume_init(handle) });
            rn_uv::ledger::record_created();
        }
        handles
            .timer
            .as_ref()
            .map(|handle| std::ptr::from_ref(&**handle).cast_mut())
    })
}

/// The loop's check and idle handles, created on first use.
fn ensure_immediate_handles() -> Option<(*mut uv::uv_check_t, *mut uv::uv_idle_t)> {
    HANDLES.with(|handles| {
        let mut handles = handles.borrow_mut();
        let loop_pointer = rn_uv::uv_loop::loop_ptr()?;
        if handles.check.is_none() {
            let handle = Box::pin(std::mem::MaybeUninit::<uv::uv_check_t>::zeroed());
            // SAFETY: as in `ensure_timer_handle`.
            let status = unsafe { uv::uv_check_init(loop_pointer, pin_ptr(&handle)) };
            if status != 0 {
                tracing::error!(status, "uv_check_init failed");
                return None;
            }
            // SAFETY: `uv_check_init` succeeded.
            let check = unsafe { assume_init(handle) };
            rn_uv::ledger::record_created();
            // The check handle is started on demand by `toggleImmediateRef(true)`
            // and unref'd once the queue drains, so it is created inactive here:
            // an active ref'd check handle would keep the process alive forever,
            // and one active but unref'd would still run `processImmediate` on
            // every iteration for nothing.
            handles.check = Some(check);
        }
        if handles.idle.is_none() {
            let handle = Box::pin(std::mem::MaybeUninit::<uv::uv_idle_t>::zeroed());
            // SAFETY: as in `ensure_timer_handle`.
            let status = unsafe { uv::uv_idle_init(loop_pointer, pin_ptr(&handle)) };
            if status != 0 {
                tracing::error!(status, "uv_idle_init failed");
                return None;
            }
            // SAFETY: `uv_idle_init` succeeded.
            let idle = unsafe { assume_init(handle) };
            rn_uv::ledger::record_created();
            // The idle handle is unref'd at init, as Node's is. It exists only to
            // make `uv__io_poll` return without waiting while an immediate is
            // outstanding; an active *ref'd* idle handle would keep the process
            // alive forever, because `uv_idle_start` re-adds it to the loop's
            // active count on every start.
            // SAFETY: `idle` is the live handle just initialised.
            unsafe { uv::uv_unref(std::ptr::from_ref(&*idle).cast_mut().cast()) };
            handles.idle = Some(idle);
        }
        let check = handles
            .check
            .as_ref()
            .map(|handle| std::ptr::from_ref(&**handle).cast_mut())?;
        let idle = handles
            .idle
            .as_ref()
            .map(|handle| std::ptr::from_ref(&**handle).cast_mut())?;
        Some((check, idle))
    })
}

/// A mutable pointer to the handle a `Pin<Box<MaybeUninit<_>>>` holds.
fn pin_ptr<T>(handle: &Pin<Box<std::mem::MaybeUninit<T>>>) -> *mut T {
    // `MaybeUninit` is never assumed initialised through this pointer, so the
    // `Unpin` requirement `Pin::get_mut` would impose is irrelevant here; the
    // address of `MaybeUninit<T>` and `T` is the same and libuv writes into it
    // in place.
    handle.as_ptr().cast::<T>().cast_mut()
}

/// Wraps a `Pin<Box<MaybeUninit<T>>>` an init call filled in.
///
/// # Safety
///
/// The caller must have run the matching `uv_*_init` successfully on this slot.
unsafe fn assume_init<T>(handle: Pin<Box<std::mem::MaybeUninit<T>>>) -> Pin<Box<T>> {
    // SAFETY: the caller guarantees the slot is initialised, and `Pin<Box<_>>`
    // keeps the value at the address libuv was given, which is the requirement
    // libuv places on a handle.
    unsafe { std::mem::transmute::<Pin<Box<std::mem::MaybeUninit<T>>>, Pin<Box<T>>>(handle) }
}

/// `uv_timer_t`'s callback: run `processTimers`.
///
/// # Safety
///
/// Called by libuv with the timer handle this module initialised.
unsafe extern "C" fn on_timer(_handle: *mut uv::uv_timer_t) {
    // SAFETY: this callback only touches thread-local state and V8, which the
    // loop only runs while the isolate exists.
    unsafe { run_timer_callback() };
}

/// `uv_check_t`'s callback: run the native immediates, then `processImmediate`.
///
/// # Safety
///
/// Called by libuv with the check handle this module initialised.
unsafe extern "C" fn on_check(_handle: *mut uv::uv_check_t) {
    // `Environment::CheckImmediate` runs `RunAndClearNativeImmediates()` *before*
    // `processImmediate`, and the order is observable: `AsyncWrap::EmitDestroy`
    // defers a `destroy` hook through the native queue, so a destroy that became
    // due in this iteration is reported before any `setImmediate` callback. Doing
    // it the other way round puts every destroy one immediate too late.
    let native_pending = rn_core::native_immediates::has_pending();
    if native_pending {
        rn_uv::callback::with_context(|scope| {
            rn_core::native_immediates::run_and_clear(scope);
        });
    }
    // SAFETY: as in `on_timer`.
    unsafe { run_immediate_callback() };
    // Anything else Node runs in the check phase. A `MessagePort` becomes
    // readable the moment it is posted to, and delivery goes last so a message
    // handler that queues an immediate does not run in the same phase the
    // message arrived in.
    //
    // This is a registered hook rather than a direct call because the check
    // handle lives here while message delivery lives in another namespace, and
    // the direction that avoids a cycle is for the owner of the phase to ask.
    let hook = CHECK_PHASE_HOOK.with(Cell::get);
    if let Some(hook) = hook {
        rn_uv::callback::with_context(hook);
    }
    // The additional hooks run after the primary one, in registration order.
    // Each is a separate `with_context` so a hook that throws cannot leave the
    // isolate entered for the next one.
    let extra: Vec<fn(&mut v8::PinScope<'_, '_>)> =
        EXTRA_CHECK_PHASE_HOOKS.with(|hooks| hooks.borrow().clone());
    for hook in extra {
        rn_uv::callback::with_context(hook);
    }
    // `processImmediate` decrements `immediateInfo[1]` directly when it runs an
    // immediate, so `toggleImmediateRef(false)` is not called for the last one
    // and the ref this handle took would keep the loop alive forever. Node's
    // `Environment` stops the check handle once the queue is drained for exactly
    // this reason: an active ref'd handle is work, and an empty immediate queue
    // is not.
    //
    // The extra check-phase work is part of that decision: a second message
    // posted while the first was being delivered must run in a later iteration,
    // so the handle stays armed while anything is still queued.
    if check_phase_pending() {
        return;
    }
    if immediate_ref_count() == 0 {
        if let Some((check, idle)) = immediate_handles() {
            // SAFETY: both are the live handles this module owns.
            unsafe {
                uv::uv_unref(check.cast());
                uv::uv_idle_stop(idle);
            }
        }
    }
}

/// Registers the callback the check phase runs after `processImmediate`.
///
/// Replaces the previous hook. Used by the realm that owns the phase.
pub fn set_check_phase_hook(hook: fn(&mut v8::PinScope<'_, '_>)) {
    CHECK_PHASE_HOOK.with(|slot| slot.set(Some(hook)));
}

/// Adds a second check-phase hook, kept alongside the first.
///
/// The phase has more than one producer of work and they live in crates that
/// must not depend on each other: `rn-realm` owns the `MessagePort` delivery,
/// and `rn-bind-worker` reports worker exits from the same phase — but the worker
/// crate depends on `rn-realm`, so `rn-realm` cannot name it. A list keeps the
/// ownership honest: each producer registers itself and neither has to know
/// about the other.
///
/// Registered at most once per function pointer, so a realm that installs twice
/// on the same thread does not run the same hook twice per iteration.
pub fn add_check_phase_hook(hook: fn(&mut v8::PinScope<'_, '_>)) {
    EXTRA_CHECK_PHASE_HOOKS.with(|hooks| {
        let mut hooks = hooks.borrow_mut();
        if !hooks.contains(&hook) {
            hooks.push(hook);
        }
    });
}

/// Removes a hook added by [`add_check_phase_hook`].
///
/// A worker's realm installs its own hooks on its thread; clearing them when the
/// realm ends is what stops a reused thread from running a disposed isolate's
/// callbacks.
pub fn clear_extra_check_phase_hooks() {
    EXTRA_CHECK_PHASE_HOOKS.with(|hooks| hooks.borrow_mut().clear());
}

/// Whether an immediate is queued or a ref'd check-phase consumer is waiting.
///
/// The check handle is started on demand, so this is also the signal that the
/// handle must be started before the next iteration for its work to run.
pub fn check_phase_pending() -> bool {
    // A native immediate (`AsyncWrap::EmitDestroy`'s deferred `destroy`, for
    // one) runs at the start of this phase, so its presence keeps the handle
    // armed exactly like a JavaScript immediate does.
    if rn_core::native_immediates::has_pending() {
        return true;
    }
    if immediate_count() > 0 {
        return true;
    }
    if rn_bind_worker_pending() {
        return true;
    }
    CHECK_PHASE_PENDING.with(|pending| pending.borrow().is_some_and(|pending| pending()))
}

/// Registers a predicate saying the check phase has work beyond immediates.
///
/// A `MessagePort` with a queued message is exactly that: its delivery runs in
/// the check phase, but nothing in `immediateInfo` records it. The consumer
/// registers here so this crate keeps owning the handle without depending on it.
pub fn set_check_phase_pending(pending: fn() -> bool) {
    CHECK_PHASE_PENDING.with(|slot| *slot.borrow_mut() = Some(pending));
}

/// Adds a predicate saying the check phase has work beyond immediates.
///
/// Additive for the same reason the hooks are: a worker's exit is reported from
/// this phase and the worker crate cannot be named here.
pub fn add_check_phase_pending_predicate(predicate: fn() -> bool) {
    EXTRA_CHECK_PHASE_PENDING.with(|predicates| {
        let mut predicates = predicates.borrow_mut();
        if !predicates.contains(&predicate) {
            predicates.push(predicate);
        }
    });
}

/// Removes every predicate added by [`add_check_phase_pending_predicate`].
pub fn clear_check_phase_pending_predicates() {
    EXTRA_CHECK_PHASE_PENDING.with(|predicates| predicates.borrow_mut().clear());
}

/// Whether an added predicate says the check phase has work.
fn rn_bind_worker_pending() -> bool {
    EXTRA_CHECK_PHASE_PENDING
        .with(|predicates| predicates.borrow().iter().any(|predicate| predicate()))
}

/// Adds a predicate that keeps the process alive outside libuv.
///
/// A running `Worker` is the case: its thread has its own loop, so nothing on
/// *this* loop records it, and yet Node's process waits for it. Additive for the
/// same reason [`add_check_phase_hook`] is — the producers cannot depend on each
/// other.
pub fn add_external_work_predicate(predicate: fn() -> bool) {
    EXTERNAL_WORK.with(|predicates| {
        let mut predicates = predicates.borrow_mut();
        if !predicates.contains(&predicate) {
            predicates.push(predicate);
        }
    });
}

/// Removes every predicate added by [`add_external_work_predicate`].
pub fn clear_external_work_predicates() {
    EXTERNAL_WORK.with(|predicates| predicates.borrow_mut().clear());
}

/// Whether any registered predicate says the process must stay alive.
///
/// Arming the check phase here is deliberate: this function is only asked when
/// the loop is deciding whether to keep running, and a `true` answer means the
/// work it is keeping the loop for runs in the *check phase*. libuv's check
/// handle is started on demand, so without this the loop would run iterations
/// whose phase never fires and spin until the turn limit.
#[must_use]
pub fn has_external_work() -> bool {
    let pending =
        EXTERNAL_WORK.with(|predicates| predicates.borrow().iter().any(|predicate| predicate()));
    if pending {
        arm_check_phase();
    }
    pending
}

/// Arms the check phase for work that does not go through `setImmediate`.
///
/// This is `uv_async_send` for a consumer whose readiness is tracked in Rust
/// rather than by libuv: it starts the check handle and refs it, so the loop runs
/// one more iteration and does not exit under it. `lib/internal/timers.js` takes
/// the same path through `toggleImmediateRef`, which is why both end up here.
pub fn arm_check_phase() {
    let Some((check, idle)) = ensure_immediate_handles() else {
        return;
    };
    // SAFETY: both are the live handles this module owns.
    unsafe {
        let status = uv::uv_check_start(check, Some(on_check));
        if status != 0 {
            tracing::error!(status, "uv_check_start failed");
            return;
        }
        uv::uv_ref(check.cast());
        uv::uv_idle_start(idle, Some(on_idle));
    }
}

/// `uv_idle_t`'s callback, which has nothing to do.
///
/// The handle exists to stop poll from blocking, so being run is the whole job.
///
/// # Safety
///
/// Called by libuv with the idle handle this module initialised.
unsafe extern "C" fn on_idle(_handle: *mut uv::uv_idle_t) {}

/// Runs `processTimers` through libuv's callback scope.
///
/// # Safety
///
/// Only called from inside `uv_run`, while the isolate the bindings were
/// installed into is alive.
unsafe fn run_timer_callback() {
    rn_uv::callback::with_context(|scope| {
        let Some(callback) = timer_callback(scope) else {
            return;
        };
        let now = rn_uv::uv_loop::now_ms();
        let argument: v8::Local<v8::Value> = v8::Number::new(scope, now).into();
        match call_catching(scope, callback, &[argument]) {
            Ok(Some(result)) => {
                // The return value is the next deadline, using libuv's sign
                // convention: positive when a ref'd timer is behind it, negative
                // when every timer is unref'd, zero when the lists are empty.
                // Node's C++ reacts by restarting the handle for a positive value
                // and stopping it otherwise, and that reaction belongs here
                // because it is a fact about the handle, not about JavaScript.
                apply_timer_result(result.number_value(scope));
            }
            // A callback that reported nothing is the "function was replaced"
            // case; there is no deadline to arm.
            Ok(None) => stop_timer(),
            Err(exception) => {
                record_uncaught(scope, exception);
                stop_timer();
            }
        }
    });
}

/// Re-arms the timer handle from `processTimers`' return value.
///
/// This is `Environment::RunTimers` in `src/env.cc`, and the sign convention is
/// three cases, not two:
///
/// | value | meaning | reaction |
/// | --- | --- | --- |
/// | `0` | no timer lists left | unref the handle |
/// | `> 0` | next expiry, at least one *ref'd* timer behind it | re-arm for it, `uv_ref` |
/// | `< 0` | `-expiry` of the next list, **no** ref'd timer behind it | re-arm for it, `uv_unref` |
///
/// The negative case is the one that is easy to get wrong, and getting it wrong
/// is invisible until a second timer list exists. Treating a negative value as
/// "stop" instead of "re-arm unref'd" drops the pending unref'd deadline: after
/// the earlier list fires, `processTimers` returns `-expiry`, the handle stops,
/// and nothing ever arms it again because `lib/internal/timers.js` only calls
/// `scheduleTimer` when a *new* list beats `nextExpiry`. The next expiry is
/// already known to it, so it stays silent and the timer never runs.
///
/// That is exactly the shape of the keep-alive failure: `lib/net.js` arms a 500ms
/// unref'd connect timer beside an application timer, and any application timer
/// longer than 500ms was dropped at the moment the connect timer fired. It is
/// also why the failure looked delay-dependent rather than ref-dependent.
fn apply_timer_result(value: Option<f64>) {
    let Some(value) = value else {
        // `processTimers` was replaced or reported nothing, so there is no
        // deadline to arm, matching Node's `ret.IsEmpty()` early return.
        stop_timer();
        return;
    };
    if value == 0.0 {
        // Nothing is scheduled. Node does not stop the handle here — the one-shot
        // timer is already inactive after firing — but it does drop the ref so an
        // idle timer handle cannot keep the process alive.
        unref_timer();
        return;
    }

    let Some(timer) = ensure_timer_handle() else {
        return;
    };
    // A negative value's magnitude is the absolute deadline, so both signs are
    // re-armed; only the ref bit differs. `processTimers` reports an absolute
    // deadline and `uv_timer_start` takes a delay, so the loop's cached time is
    // subtracted. The cache is refreshed first for the same reason
    // `scheduleTimer` refreshes it: the callback that produced `value` may have
    // taken milliseconds.
    rn_uv::uv_loop::update_time();
    let now = rn_uv::uv_loop::now_ms();
    let deadline = value.abs();
    // `duration_ms > 0 ? duration_ms : 1` in Node: a deadline that has already
    // passed is armed for one millisecond rather than zero, so the next iteration
    // runs it after poll rather than spinning.
    let delay = ((deadline - now) as u64).max(1);
    // SAFETY: `timer` is the live handle this module owns.
    let status = unsafe { uv::uv_timer_start(timer, Some(on_timer), delay, 0) };
    if status != 0 {
        tracing::error!(status, "uv_timer_start failed while re-arming");
        return;
    }
    // `expiry_ms > 0 ? uv_ref(h) : uv_unref(h)`. Leaving a re-armed handle ref'd
    // when only unref'd timers remain would hold the process open for a deadline
    // that was explicitly excluded from keeping it alive.
    // SAFETY: `timer` is the live handle this module owns.
    unsafe {
        if value > 0.0 {
            uv::uv_ref(timer.cast());
        } else {
            uv::uv_unref(timer.cast());
        }
    }
}

/// `uv_unref`s the timer handle without touching its (already elapsed) arming.
fn unref_timer() {
    if let Some(timer) = timer_handle() {
        // SAFETY: `timer` is the live handle this module owns.
        unsafe { uv::uv_unref(timer.cast()) };
    }
}

/// Stops the loop's timer handle, as `uv_timer_stop` does.
fn stop_timer() {
    if let Some(timer) = timer_handle() {
        // SAFETY: `timer` is the live handle this module owns.
        unsafe { uv::uv_timer_stop(timer) };
    }
}

/// Runs `processImmediate` through libuv's callback scope.
///
/// # Safety
///
/// Only called from inside `uv_run`, while the isolate the bindings were
/// installed into is alive.
unsafe fn run_immediate_callback() {
    rn_uv::callback::with_context(|scope| {
        let Some(callback) = immediate_callback(scope) else {
            return;
        };
        if let Err(exception) = call_catching(scope, callback, &[]) {
            record_uncaught(scope, exception);
        }
    });
}

/// The loop's timer handle, if it has been created.
fn timer_handle() -> Option<*mut uv::uv_timer_t> {
    HANDLES.with(|handles| {
        handles
            .borrow()
            .timer
            .as_ref()
            .map(|handle| std::ptr::from_ref(&**handle).cast_mut())
    })
}

/// The loop's check and idle handles, if they have been created.
fn immediate_handles() -> Option<(*mut uv::uv_check_t, *mut uv::uv_idle_t)> {
    HANDLES.with(|handles| {
        let handles = handles.borrow();
        let check = handles
            .check
            .as_ref()
            .map(|handle| std::ptr::from_ref(&**handle).cast_mut())?;
        let idle = handles
            .idle
            .as_ref()
            .map(|handle| std::ptr::from_ref(&**handle).cast_mut())?;
        Some((check, idle))
    })
}

/// Runs the timer callback `setupTimers` installed, if there is one.
///
/// Kept for callers that only want the side effects; the loop itself goes
/// through the handle callback above.
pub fn call_timer_callback(scope: &mut v8::PinScope) {
    let callback = timer_callback(scope);
    if let Some(callback) = callback {
        let _ = callback.call(scope, v8::undefined(scope).into(), &[]);
    }
}

/// Runs the immediate callback `setupTimers` installed, if there is one.
pub fn call_immediate_callback(scope: &mut v8::PinScope) {
    let callback = immediate_callback(scope);
    if let Some(callback) = callback {
        let _ = callback.call(scope, v8::undefined(scope).into(), &[]);
    }
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

/// Reports an uncaught callback exception the way Node does and asks the process
/// to exit non-zero when nothing handled it.
///
/// A throw from a timer or immediate callback is an uncaught exception in the
/// public sense: `process.setUncaughtExceptionCaptureCallback` and a
/// `process.on('uncaughtException')` listener both have to see it before it is
/// printed. `write_uncaught` skips them, so this goes through
/// `report_uncaught_exception`, which calls `process._fatalException` first and
/// only prints when it declines.
fn record_uncaught(scope: &mut v8::PinScope, exception: v8::Global<v8::Value>) {
    let exception = v8::Local::new(scope, &exception);
    rn_errors::report_uncaught_exception(scope, exception);
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
/// `processImmediate()` decrements.
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

/// Closes the three libuv handles this crate owns on the current thread.
///
/// **This is what makes a worker's loop able to end.** `uv_run(UV_RUN_DEFAULT)`
/// returns only when nothing is referenced, so a timer handle left *started* —
/// the normal state after `setInterval` — keeps the loop alive forever, and a
/// `terminate()` that only stopped running JavaScript would hang. Node's
/// `Environment` has the same requirement and does it in `TimerWrapHandle` and
/// `Immediate` teardown: stop the handle, then close it.
///
/// Each handle is stopped before it is closed, because `uv_close` on a started
/// timer leaves libuv calling back into a handle whose Rust owner is going away.
/// The storage is *not* freed here: the close callback is the only place that
/// knows libuv is finished with it, and `rn_uv::uv_loop::close_loop` is what
/// pumps the loop until that callback runs.
///
/// Idempotent, because a teardown can run twice on a thread — once from the
/// realm's own exit and once from the loop's `Drop`.
///
/// Returns how many handles it asked libuv to close, so a caller can compare its
/// total against what it created.
pub fn close_handles() -> usize {
    let (timer, check, idle) = HANDLES.with(|handles| {
        let mut handles = handles.borrow_mut();
        (
            handles.timer.take(),
            handles.check.take(),
            handles.idle.take(),
        )
    });

    let mut closing = 0usize;
    // The storage has to outlive the close: libuv keeps the handle pointer and
    // writes to it until the callback runs. So each box is deliberately leaked
    // here and reclaimed by its typed close callback, which is the only place
    // that knows libuv is finished with it. Dropping the `Pin<Box<_>>` at the end
    // of this function would free storage libuv is still writing to — and then
    // the callback's `Box::from_raw` would free it a second time.
    if let Some(timer) = timer {
        let pointer = std::ptr::from_ref(&*timer).cast_mut();
        // SAFETY: `timer` was initialised by `ensure_timer_handle`, and this is
        // the only path that closes it because `HANDLES` gave up the box above.
        unsafe {
            uv::uv_timer_stop(pointer);
            uv::uv_close(pointer.cast(), Some(timer_closed));
        }
        std::mem::forget(timer);
        closing += 1;
    }
    if let Some(check) = check {
        let pointer = std::ptr::from_ref(&*check).cast_mut();
        // SAFETY: as above.
        unsafe {
            uv::uv_check_stop(pointer);
            uv::uv_close(pointer.cast(), Some(check_closed));
        }
        std::mem::forget(check);
        closing += 1;
    }
    if let Some(idle) = idle {
        let pointer = std::ptr::from_ref(&*idle).cast_mut();
        // SAFETY: as above.
        unsafe {
            uv::uv_idle_stop(pointer);
            uv::uv_close(pointer.cast(), Some(idle_closed));
        }
        std::mem::forget(idle);
        closing += 1;
    }
    closing
}

/// Records and frees a closed timer handle.
///
/// # Safety
///
/// Called by libuv as the `uv_close` callback for a `uv_timer_t` whose `Pin<Box<_>>`
/// was released by [`close_handles`].
unsafe extern "C" fn timer_closed(handle: *mut uv::uv_handle_t) {
    rn_uv::ledger::record_closed();
    // SAFETY: `close_handles` released the box that owned this handle, and libuv
    // is done with it now, so this is the one deallocation.
    unsafe { drop(Box::from_raw(handle as *mut uv::uv_timer_t)) };
}

/// Records and frees a closed check handle.
///
/// # Safety
///
/// As [`timer_closed`], for a `uv_check_t`.
unsafe extern "C" fn check_closed(handle: *mut uv::uv_handle_t) {
    rn_uv::ledger::record_closed();
    // SAFETY: as in `timer_closed`.
    unsafe { drop(Box::from_raw(handle as *mut uv::uv_check_t)) };
}

/// Records and frees a closed idle handle.
///
/// # Safety
///
/// As [`timer_closed`], for a `uv_idle_t`.
unsafe extern "C" fn idle_closed(handle: *mut uv::uv_handle_t) {
    rn_uv::ledger::record_closed();
    // SAFETY: as in `timer_closed`.
    unsafe { drop(Box::from_raw(handle as *mut uv::uv_idle_t)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_is_monotonic_milliseconds() {
        let first = wall_now_ms();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = wall_now_ms();
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

    #[test]
    fn the_timer_handle_is_created_once_and_keeps_its_address() {
        // libuv stores the handle's address when it is initialised, so a handle
        // that moved afterwards would corrupt the loop's timer heap.
        let first = ensure_timer_handle().expect("the loop is creatable");
        let second = ensure_timer_handle().expect("the loop is creatable");
        assert_eq!(first, second);
    }

    #[test]
    fn the_check_and_idle_handles_are_created_once_and_keep_their_addresses() {
        let first = ensure_immediate_handles().expect("the loop is creatable");
        let second = ensure_immediate_handles().expect("the loop is creatable");
        assert_eq!(first, second);
        // SAFETY: both are the live handles this module owns.
        unsafe {
            // Neither is active at init: the check handle is started by
            // `toggleImmediateRef(true)` and the idle handle by the same call.
            // An active handle at init would make every process refuse to exit,
            // which is exactly the bug this test exists to catch.
            assert_eq!(
                uv::uv_is_active(first.0.cast()),
                0,
                "check starts on demand"
            );
            assert_eq!(uv::uv_is_active(first.1.cast()), 0, "idle starts on demand");
        }
    }

    #[test]
    fn a_negative_process_timers_result_rearms_the_handle_instead_of_stopping_it() {
        // `processTimers` returns `-expiry` when the next deadline has no ref'd
        // timer behind it. Node's `Environment::RunTimers` re-arms for it and
        // unrefs; treating the value as "stop" drops the pending deadline and the
        // timer never fires, because `lib/internal/timers.js` only calls
        // `scheduleTimer` for a *new* list that beats `nextExpiry` — the pending
        // one is already known to it, so it stays silent forever.
        //
        // This asserts the handle really becomes active and ref-less, which is
        // the pair that makes a later iteration expire it without keeping the
        // process alive.
        let timer = ensure_timer_handle().expect("the loop is creatable");
        // A deadline in the future relative to the loop's cached clock, expressed
        // the way `processTimers` does for the unref'd case.
        rn_uv::uv_loop::update_time();
        let now = rn_uv::uv_loop::now_ms();
        apply_timer_result(Some(-(now + 60_000.0)));

        // SAFETY: `timer` is the live handle this module owns.
        unsafe {
            assert_eq!(
                uv::uv_is_active(timer.cast()),
                1,
                "a negative result must leave the handle armed"
            );
            assert_eq!(
                uv::uv_has_ref(timer.cast()),
                0,
                "an unref'd deadline must not keep the process alive"
            );
            // Leave the loop as it was found, or the test process would stay
            // alive for a minute.
            uv::uv_timer_stop(timer);
        }
    }

    #[test]
    fn a_positive_process_timers_result_rearms_the_handle_refed() {
        // The ref'd half of the same convention. Getting this backwards would
        // let the process exit with a ref'd timer still pending.
        let timer = ensure_timer_handle().expect("the loop is creatable");
        rn_uv::uv_loop::update_time();
        let now = rn_uv::uv_loop::now_ms();
        apply_timer_result(Some(now + 60_000.0));

        // SAFETY: `timer` is the live handle this module owns.
        unsafe {
            assert_eq!(
                uv::uv_is_active(timer.cast()),
                1,
                "a positive result must leave the handle armed"
            );
            assert_eq!(
                uv::uv_has_ref(timer.cast()),
                1,
                "a ref'd deadline must keep the process alive"
            );
            uv::uv_timer_stop(timer);
        }
    }

    #[test]
    fn a_zero_process_timers_result_leaves_no_ref_behind() {
        // `0` is an empty timer set: the handle must not count as work, or the
        // process would never exit once any timer had been used.
        let timer = ensure_timer_handle().expect("the loop is creatable");
        apply_timer_result(Some(0.0));
        // SAFETY: `timer` is the live handle this module owns.
        unsafe {
            assert_eq!(
                uv::uv_has_ref(timer.cast()),
                0,
                "an empty timer set is not work"
            );
            uv::uv_timer_stop(timer);
        }
    }
}
