//! `internalBinding('task_queue')` for rustnode.
//!
//! This is where `process.nextTick`, the promise rejection hooks and the
//! microtask drain meet. The JavaScript side lives in
//! `lib/internal/process/task_queues.js`, which drives `tickInfo` as a
//! `Uint8Array(2)` of flags and asks this binding to enqueue and to drain.
//!
//! The two flags in `tickInfo` are [`HAS_TICK_SCHEDULED`] and
//! [`HAS_REJECTION_TO_WARN`]. They are a shared buffer, not properties: the
//! JavaScript side writes them directly, so a copy in Rust would drift the
//! moment either side touched it.

use std::cell::RefCell;

use rn_core::{AliasedUint8Array, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// `TickInfo::Fields` in `src/env.h`: a tick is queued.
pub const HAS_TICK_SCHEDULED: usize = 0;
/// `TickInfo::Fields` in `src/env.h`: an unhandled rejection needs a warning.
pub const HAS_REJECTION_TO_WARN: usize = 1;
/// `TickInfo::kFieldsCount`: the buffer's length.
pub const TICK_INFO_FIELDS: usize = 2;

/// `v8::PromiseRejectEvent` values, as `promiseRejectEvents` publishes them.
pub const PROMISE_REJECT_WITH_NO_HANDLER: u32 = 0;
pub const PROMISE_HANDLER_ADDED_AFTER_REJECT: u32 = 1;

/// Members exposed on the namespace object, matching `contracts/task_queue.json`.
pub const MEMBERS: &[&str] = &[
    "enqueueMicrotask",
    "promiseRejectEvents",
    "runMicrotasks",
    "setPromiseRejectCallback",
    "setTickCallback",
    "tickInfo",
];

/// The JavaScript callbacks `task_queues.js` installs.
///
/// Node keeps these on `Environment`; rustnode keeps them here because nothing
/// else reads them. `None` means the JavaScript layer has not bootstrapped that
/// far, which is the normal state during the realm bootstrap.
#[derive(Default)]
struct Callbacks {
    tick: Option<v8::Global<v8::Function>>,
    promise_reject: Option<v8::Global<v8::Function>>,
}

thread_local! {
    static CALLBACKS: RefCell<Callbacks> = RefCell::new(Callbacks::default());
    /// The shared tick buffer, created on first install.
    ///
    /// The registry caches the installed namespace object, so `install` runs
    /// once per process and this stays the same buffer the JavaScript side
    /// holds.
    static TICK_INFO: RefCell<Option<AliasedUint8Array>> = const { RefCell::new(None) };
}

/// The binding. Holds no state of its own; the tick buffer a scope is needed to
/// allocate lives in [`TICK_INFO`], created during [`install`](BindingModule::install).
pub struct TaskQueue;

impl BindingModule for TaskQueue {
    fn namespace(&self) -> &'static str {
        "task_queue"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let tick_info = AliasedUint8Array::new(scope, TICK_INFO_FIELDS, rn_core::Element::Byte)?;
        let array = tick_info.array(scope);
        TICK_INFO.with(|slot| *slot.borrow_mut() = Some(tick_info));

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 6] = [
            ("tickInfo", array),
            ("promiseRejectEvents", promise_reject_events(scope)),
            (
                "enqueueMicrotask",
                function(scope, "enqueueMicrotask", enqueue_microtask)?,
            ),
            (
                "runMicrotasks",
                function(scope, "runMicrotasks", run_microtasks)?,
            ),
            (
                "setTickCallback",
                function(scope, "setTickCallback", set_tick_callback)?,
            ),
            (
                "setPromiseRejectCallback",
                function(
                    scope,
                    "setPromiseRejectCallback",
                    set_promise_reject_callback,
                )?,
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the `task_queue` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(TaskQueue);
}

/// Whether a tick is queued, as `task_queues.js` last left the flag.
pub fn has_tick_scheduled() -> bool {
    TICK_INFO.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|info| info.flag(HAS_TICK_SCHEDULED))
    })
}

/// Whether an unhandled rejection is waiting to be reported.
pub fn has_rejection_to_warn() -> bool {
    TICK_INFO.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|info| info.flag(HAS_REJECTION_TO_WARN))
    })
}

/// Sets a tick flag from Rust, mirroring what the JavaScript side does by
/// writing into the typed array.
pub fn set_tick_flag(field: usize, value: bool) {
    TICK_INFO.with(|slot| {
        if let Some(info) = slot.borrow().as_ref() {
            info.set(field, u32::from(value));
        }
    });
}

fn promise_reject_events<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let events = v8::Object::new(scope);
    let no_handler = v8::Integer::new(scope, PROMISE_REJECT_WITH_NO_HANDLER as i32);
    let handled_after = v8::Integer::new(scope, PROMISE_HANDLER_ADDED_AFTER_REJECT as i32);
    let _ = set(
        scope,
        events,
        "kPromiseRejectWithNoHandler",
        no_handler.into(),
    );
    let _ = set(
        scope,
        events,
        "kPromiseHandlerAddedAfterReject",
        handled_after.into(),
    );
    events.into()
}

fn enqueue_microtask(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw(scope, "enqueueMicrotask expects a function");
        return;
    };
    scope.enqueue_microtask(callback);
}

fn run_microtasks(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    scope.perform_microtask_checkpoint();
}

fn set_tick_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw(scope, "setTickCallback expects a function");
        return;
    };
    let callback = v8::Global::new(scope, callback);
    CALLBACKS.with(|callbacks| callbacks.borrow_mut().tick = Some(callback));
}

fn set_promise_reject_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw(scope, "setPromiseRejectCallback expects a function");
        return;
    };
    let callback = v8::Global::new(scope, callback);
    CALLBACKS.with(|callbacks| callbacks.borrow_mut().promise_reject = Some(callback));
}

/// Runs the installed tick callback, if any.
///
/// `lib/internal/process/task_queues.js` is what normally drains, so this exists
/// for the runtime to call when it has to process ticks itself.
pub fn call_tick_callback(scope: &mut v8::PinScope) {
    let callback = CALLBACKS.with(|callbacks| {
        callbacks
            .borrow()
            .tick
            .as_ref()
            .map(|tick| v8::Local::new(scope, tick))
    });
    if let Some(callback) = callback {
        let _ = callback.call(scope, v8::undefined(scope).into(), &[]);
    }
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
