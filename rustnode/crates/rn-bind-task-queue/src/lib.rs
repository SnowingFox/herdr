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
//!
//! # The V8 registration is the binding's other half
//!
//! `setPromiseRejectCallback` only stores the JavaScript function;
//! `internal/process/promises.js` then expects V8 to call it. That is the
//! isolate-level `Isolate::SetPromiseRejectCallback`
//! (`node::task_queue::PromiseRejectCallback` in `src/node_task_queue.cc`), not
//! a namespace method, so it cannot be installed from a binding callback: the
//! only API takes `&mut Isolate`, which a callback cannot obtain soundly. The
//! CLI and the worker setup therefore call [`install_isolate_callbacks`] once
//! per isolate, the same arrangement `rn-module-wrap` uses for `import.meta`.
//!
//! Without it the stored function is dead: `process.on('unhandledRejection')`
//! never fires, `--unhandled-rejections=throw` never raises, and an unhandled
//! rejection never affects the exit code.

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

/// Whether a V8 promise reject event reaches JavaScript.
///
/// `src/node_task_queue.cc::PromiseRejectCallback` forwards exactly two of the
/// four `v8::PromiseRejectEvent` values and silently drops the other two:
///
/// * `kPromiseRejectAfterResolved` and `kPromiseResolveAfterResolved` describe a
///   promise that has already settled, which is not an unhandled rejection and
///   has no meaning to `internal/process/promises.js` — its comment at the top of
///   `promiseRejectHandler` says both are "filtered out in C++
///   (src/node_task_queue.cc) and never reach JS".
///
/// Kept as a named predicate rather than an inline match so the rule is testable
/// without depending on V8 emitting one of the filtered events for some script;
/// no ordinary JavaScript shape makes it do so on V8 15.2.
pub fn forwards_reject_event(event: v8::PromiseRejectEvent) -> bool {
    matches!(
        event,
        v8::PromiseRejectEvent::PromiseRejectWithNoHandler
            | v8::PromiseRejectEvent::PromiseHandlerAddedAfterReject
    )
}

/// Withdraws a rejected promise from unhandled-rejection tracking, by reporting
/// the handler-added event directly.
///
/// This is `ThrowIfPromiseRejected` in `src/module_wrap.cc`: V8 creates the
/// promise a module evaluation returns, so the embedder never gets to attach a
/// handler before the rejection happens. When the embedder is about to convert
/// that rejection into a thrown error, the JavaScript side must be told the
/// rejection is handled or `internal/process/promises.js` reports it a second
/// time as an unhandled rejection — after the caller has already reported it as
/// an uncaught exception.
///
/// The event is reported with `undefined` as the reason, exactly as Node does,
/// and it must precede the throw.
pub fn mark_promise_handled(scope: &mut v8::PinScope<'_, '_>, promise: v8::Local<v8::Promise>) {
    let Some(callback) = CALLBACKS.with(|callbacks| {
        callbacks
            .borrow()
            .promise_reject
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    }) else {
        return;
    };
    let kind = v8::Integer::new(scope, PROMISE_HANDLER_ADDED_AFTER_REJECT as i32);
    let promise: v8::Local<v8::Value> = promise.into();
    let argv = [kind.into(), promise, v8::undefined(scope).into()];
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    // A throw here would mean `handledRejection` failed, which cannot be
    // reported from inside a conversion that is already unwinding. Node ignores
    // the result the same way (`ThrowIfPromiseRejected` only checks whether the
    // call itself returned empty).
    let _ = callback.call(scope, v8::undefined(scope).into(), &argv);
}

/// Installs V8's isolate-level promise rejection callback.
///
/// This is the registration `src/node_task_queue.cc` gets for free from
/// `Isolate::SetPromiseRejectCallback` in `SetIsolateMiscHandlers`
/// (`src/api/environment.cc`), which is where Node wires
/// `node::task_queue::PromiseRejectCallback` before any JavaScript runs.
///
/// It has to happen from the CLI rather than from [`TaskQueue::install`]:
/// `set_promise_reject_callback` takes `&mut Isolate`, and a binding callback
/// cannot obtain one (the `v8` crate documents `FunctionCallbackArguments::get_isolate`
/// as unsound while a callback scope is open). The namespace method only records
/// the JavaScript function; this is what makes V8 call it.
///
/// Call once per isolate, before user code runs. A worker needs its own call:
/// the callback is per-isolate state, exactly as Node sets it per isolate in
/// `CreateIsolateData`.
pub fn install_isolate_callbacks(isolate: &mut v8::Isolate) {
    isolate.set_promise_reject_callback(promise_reject_callback);
}

/// The isolate-level handler, following `node::task_queue::PromiseRejectCallback`.
///
/// Three behaviours from the C++ are load-bearing:
///
/// * Only `kPromiseRejectWithNoHandler` and `kPromiseHandlerAddedAfterReject`
///   reach JavaScript. V8 also reports `kPromiseRejectAfterResolved` and
///   `kPromiseResolveAfterResolved`, which are unhandled-rejection *tracking*
///   noise for a promise that was resolved, and
///   `internal/process/promises.js::promiseRejectHandler` says in a comment that
///   they are filtered out here and never arrive.
/// * `kPromiseHandlerAddedAfterReject` has no reason: its value is `undefined`
///   (`src/node_task_queue.cc`), because the promise is what matters.
/// * The call runs with the promise's async context pushed, so
///   `executionAsyncId()` inside `promiseRejectHandler` answers the promise's id.
///
/// `extern "C"` because V8 takes a bare function pointer with no data slot, so
/// the JavaScript callback is read from [`CALLBACKS`] on every call. That also
/// means a later `setPromiseRejectCallback` is picked up without re-installing
/// anything, which is what a second realm needs.
extern "C" fn promise_reject_callback(message: v8::PromiseRejectMessage) {
    let event = message.get_event();
    if !forwards_reject_event(event) {
        // `kPromiseRejectAfterResolved` / `kPromiseResolveAfterResolved`: never
        // forwarded, per the comment in `internal/process/promises.js`.
        return;
    }
    // `kPromiseHandlerAddedAfterReject` has no reason: `src/node_task_queue.cc`
    // passes `undefined` for it because the promise is the whole message and
    // `promises.js::handledRejection(promise)` only takes the promise.
    let value = match event {
        v8::PromiseRejectEvent::PromiseRejectWithNoHandler => message.get_value(),
        _ => None,
    };

    v8::callback_scope!(unsafe scope, &message);
    let promise = message.get_promise();
    // `AsyncWrap::kInvalidAsyncId` for a promise created outside any async
    // context; `promises.js` handles a missing id by skipping the push too.
    let async_id = promise_symbol_value(scope, promise, "async_id_symbol");
    let trigger_async_id = promise_symbol_value(scope, promise, "trigger_async_id_symbol");

    let Some(callback) = CALLBACKS.with(|callbacks| {
        callbacks
            .borrow()
            .promise_reject
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    }) else {
        // `promises.js` calls `listenForRejections()` during the bootstrap, so a
        // rejection before that has nowhere to go. Node `CHECK`s here; returning
        // is the honest answer for a runtime whose bootstrap is allowed to fail
        // without taking the process down.
        return;
    };

    let kind = v8::Integer::new(scope, event as i32);
    let reason: v8::Local<v8::Value> = match value {
        Some(value) => value,
        None => v8::undefined(scope).into(),
    };
    let promise_value: v8::Local<v8::Value> = promise.into();

    // The push and pop around the call are `AsyncHooks::push_async_context` /
    // `pop_async_context` in `src/node_task_queue.cc`. The pop is conditional on
    // the same pair being valid, and on the handler not having switched the
    // executing id away from the promise's.
    let pushed = rn_bind_async_wrap::promise_context_is_pushable(async_id, trigger_async_id);
    if pushed {
        let object = v8::Local::<v8::Object>::try_from(promise_value).ok();
        rn_bind_async_wrap::push_promise_context(scope, async_id, trigger_async_id, object);
    }

    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let _ = callback.call(
        scope,
        v8::undefined(scope).into(),
        &[kind.into(), promise_value, reason],
    );

    if pushed && rn_bind_async_wrap::execution_async_id() == async_id {
        // `src/node_task_queue.cc` pops only when the executing id is still the
        // promise's: "This condition might not be true if async_hooks was
        // enabled during the promise callback execution." Popping a frame the
        // handler already popped would corrupt the stack.
        rn_bind_async_wrap::pop_promise_context(scope, async_id);
    }

    // V8 does not expect this callback to return with an exception pending, so
    // a throw out of `promiseRejectHandler` is printed rather than left to
    // escape into the engine. Node does the same and with the same wording.
    if scope.has_caught() && !scope.has_terminated() {
        let detail = scope
            .exception()
            .map(|exception| exception.to_rust_string_lossy(scope))
            .unwrap_or_default();
        rn_core::hook_slot::write_stderr(&format!(
            "Exception in PromiseRejectCallback:\n{detail}\n"
        ));
    }
}

/// `promise[symbol]` as a number, or `AsyncWrap::kInvalidAsyncId` when absent.
///
/// `src/node_task_queue.cc::GetAssignedPromiseAsyncId` reads these through the
/// per-isolate symbols rather than through a private name, which is the same
/// arrangement `rn-core`'s symbol table provides.
fn promise_symbol_value(
    scope: &mut v8::PinScope<'_, '_>,
    promise: v8::Local<v8::Promise>,
    symbol_name: &str,
) -> f64 {
    const INVALID_ASYNC_ID: f64 = -1.0;
    let Some(symbol) = rn_core::per_isolate_symbol(scope, symbol_name) else {
        return INVALID_ASYNC_ID;
    };
    let object: v8::Local<v8::Value> = promise.into();
    let Ok(object) = v8::Local::<v8::Object>::try_from(object) else {
        return INVALID_ASYNC_ID;
    };
    object
        .get(scope, symbol.into())
        .and_then(|value| value.number_value(scope))
        .unwrap_or(INVALID_ASYNC_ID)
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
