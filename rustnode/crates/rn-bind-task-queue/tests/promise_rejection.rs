//! What the isolate-level promise rejection callback must forward to JavaScript.
//!
//! # Why this file exists
//!
//! `setPromiseRejectCallback` only records the JavaScript function that
//! `internal/process/promises.js` installs. V8 reports a rejection through
//! `Isolate::SetPromiseRejectCallback`, which no binding can register (the only
//! API takes `&mut Isolate`), so for a while nothing registered it at all: the
//! recorded function was dead, `process.on('unhandledRejection')` never ran and
//! an unhandled rejection never changed the exit code.
//!
//! These tests drive the real V8 callback. They assert the three things
//! `src/node_task_queue.cc::PromiseRejectCallback` decides before JavaScript
//! sees anything:
//!
//! * `kPromiseRejectWithNoHandler` arrives as `(0, promise, reason)`;
//! * `kPromiseHandlerAddedAfterReject` arrives as `(1, promise, undefined)`
//!   because there is no reason to pass;
//! * `kPromiseRejectAfterResolved` and `kPromiseResolveAfterResolved` never
//!   arrive at all, which `internal/process/promises.js` states in a comment
//!   and relies on.
//!
//! The JavaScript handler is a Rust trampoline here rather than the vendored
//! `promiseRejectHandler`, so a failure names the forwarding rule that broke
//! instead of looking like a bug in Node's own code.

use std::cell::RefCell;

use rn_bind_task_queue::{TaskQueue, PROMISE_HANDLER_ADDED_AFTER_REJECT};
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// One call the JavaScript handler received, as the values V8 produced.
#[derive(Debug, Clone, PartialEq)]
struct Forwarded {
    /// The event number, which is what `promiseRejectHandler` switches on.
    kind: u32,
    /// The reason, or `"<undefined>"` for the handler-added event.
    reason: String,
    /// Whether the second argument was the rejected promise itself.
    promise_matches: bool,
}

thread_local! {
    /// What the handler saw, in order. A thread-local rather than a captured
    /// value because a `v8::Function` callback is a bare `fn`.
    static SEEN: RefCell<Vec<Forwarded>> = const { RefCell::new(Vec::new()) };
}

/// The JS-visible handler: records `(kind, promise, reason)` and nothing else.
fn record(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let kind = args.get(0).uint32_value(scope).unwrap_or(u32::MAX);
    let promise = args.get(1);
    let reason = args.get(2);
    SEEN.with(|seen| {
        seen.borrow_mut().push(Forwarded {
            kind,
            reason: if reason.is_undefined() {
                "<undefined>".to_string()
            } else {
                reason.to_rust_string_lossy(scope)
            },
            // `globalThis.__promise` is the promise the script rejected, so the
            // second argument can be checked for identity rather than for shape.
            promise_matches: promise == promise_under_test(scope),
        });
    });
}

/// `globalThis.__promise`, or `undefined` when the script has not set it.
fn promise_under_test<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let global = scope.get_current_context().global(scope);
    let Some(key) = v8::String::new(scope, "__promise") else {
        return v8::undefined(scope).into();
    };
    global
        .get(scope, key.into())
        .unwrap_or_else(|| v8::undefined(scope).into())
}

fn take_seen() -> Vec<Forwarded> {
    SEEN.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
}

/// Runs `body` against an isolate with the real callback installed.
fn with_isolate<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    // `Explicit` so a test decides when the microtask queue drains: the
    // `PromiseResolveWhileRejectingException` events a test uses to prove
    // filtering only happen at a checkpoint.
    isolate.set_microtasks_policy(v8::MicrotasksPolicy::Explicit);
    rn_bind_task_queue::install_isolate_callbacks(&mut isolate);

    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    body(scope)
}

/// Installs the namespace object and points `setPromiseRejectCallback` at
/// [`record`], the way `lib/internal/process/task_queues.js` does.
fn install_with_recorder(scope: &mut v8::PinScope<'_, '_>) {
    let mut async_ids = AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    let object = TaskQueue.install(scope, &mut ctx).expect("install");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__taskQueue").expect("key");
    global.set(scope, key.into(), object.into());

    let template = v8::FunctionTemplate::builder(record).build(scope);
    let callback = template.get_function(scope).expect("a function");
    let source = v8::String::new(scope, "__taskQueue.setPromiseRejectCallback((...a) => a)")
        .expect("source");
    let _ = source;
    // The recorder is installed directly: `setPromiseRejectCallback` validates
    // its argument as a function and stores it, which is all that is needed.
    let setter_key = v8::String::new(scope, "setPromiseRejectCallback").expect("key");
    let setter = object.get(scope, setter_key.into()).expect("setter");
    let setter = v8::Local::<v8::Function>::try_from(setter).expect("a function");
    let _ = setter.call(scope, object.into(), &[callback.into()]);
}

/// Runs `source` and drains microtasks.
fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) {
    let source = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, source, None).expect("compile");
    script.run(scope).expect("run");
    scope.perform_microtask_checkpoint();
}

#[test]
fn an_unhandled_rejection_reaches_the_recorded_callback() {
    with_isolate(|scope| {
        install_with_recorder(scope);
        // The promise is created and published *before* it is rejected: V8
        // reports the rejection synchronously from inside `Promise.reject`, so
        // `globalThis.__promise = Promise.reject(...)` would still be
        // `undefined` when the handler compares.
        run(
            scope,
            "globalThis.__promise = new Promise((resolve, reject) => {\n\
               globalThis.__reject = reject;\n\
             });\n\
             globalThis.__reject(new Error('unhandled'));",
        );

        let seen = take_seen();
        assert_eq!(
            seen.len(),
            1,
            "one rejection must produce exactly one call, got {seen:?}"
        );
        assert_eq!(seen[0].kind, 0, "kPromiseRejectWithNoHandler");
        assert_eq!(seen[0].reason, "Error: unhandled");
        assert!(
            seen[0].promise_matches,
            "the second argument must be the rejected promise itself"
        );
    });
}

#[test]
fn the_handler_added_event_carries_no_reason() {
    // `src/node_task_queue.cc` passes `undefined` for this event because the
    // promise is the whole message; `promises.js::handledRejection(promise)`
    // only takes the promise.
    with_isolate(|scope| {
        install_with_recorder(scope);
        run(
            scope,
            "const rejecting = new Promise((resolve, reject) => {\n\
               globalThis.__reject = reject;\n\
             });\n\
             globalThis.__promise = rejecting;\n\
             globalThis.__reject(new Error('late'));",
        );
        // A handler added in a *later* tick is what produces the handler-added
        // event; adding it now would handle the rejection before V8 reports it.
        run(scope, "globalThis.__promise.catch(() => {});");

        let seen = take_seen();
        let kinds: Vec<u32> = seen.iter().map(|entry| entry.kind).collect();
        assert_eq!(
            kinds,
            vec![0, PROMISE_HANDLER_ADDED_AFTER_REJECT],
            "a late handler reports the rejection and then the handler"
        );
        assert_eq!(
            seen[1].reason, "<undefined>",
            "the handler-added event has no reason"
        );
        assert!(
            seen[1].promise_matches,
            "the handler-added event still carries the promise"
        );
    });
}

#[test]
fn resolve_after_resolved_events_are_filtered_out() {
    // V8 reports `kPromiseResolveAfterResolved` and `kPromiseRejectAfterResolved`
    // for a promise that has already settled. Node filters both, and
    // `internal/process/promises.js` says so: "kPromiseRejectAfterResolved and
    // kPromiseResolveAfterResolved are filtered out in C++
    // (src/node_task_queue.cc) and never reach JS." If they did reach it, the
    // `switch` in `promiseRejectHandler` would see a `type` it has no case for.
    //
    // The filter is asserted directly rather than through a script: V8 15.2
    // does not emit either event for a double `resolve()` or a second `.then`
    // on a settled promise, so no ordinary JavaScript shape produces one to
    // observe. Deciding the question with a predicate keeps the rule pinned
    // instead of leaving it to whatever V8 happens to report on a given build.
    use rn_bind_task_queue::forwards_reject_event;
    assert!(
        forwards_reject_event(v8::PromiseRejectEvent::PromiseRejectWithNoHandler),
        "an unhandled rejection must reach JavaScript"
    );
    assert!(
        forwards_reject_event(v8::PromiseRejectEvent::PromiseHandlerAddedAfterReject),
        "a late handler must reach JavaScript"
    );
    assert!(
        !forwards_reject_event(v8::PromiseRejectEvent::PromiseRejectAfterResolved),
        "kPromiseRejectAfterResolved must be filtered out"
    );
    assert!(
        !forwards_reject_event(v8::PromiseRejectEvent::PromiseResolveAfterResolved),
        "kPromiseResolveAfterResolved must be filtered out"
    );

    // And the forwarding really does honour it. A rejection whose handler is
    // attached in the same expression still reports `no handler` first — V8
    // emits that event synchronously from `reject()` itself, before `.catch`
    // can attach — and then reports the handler. So the expected sequence is
    // exactly the two forwarded kinds, and the filter must not have inserted
    // anything else.
    with_isolate(|scope| {
        install_with_recorder(scope);
        run(
            scope,
            "Promise.resolve(1).then(() => 2).then(() => {}, () => {});\n\
             Promise.reject(new Error('handled')).catch(() => {});",
        );
        let kinds: Vec<u32> = take_seen().iter().map(|entry| entry.kind).collect();
        assert_eq!(
            kinds,
            vec![0, PROMISE_HANDLER_ADDED_AFTER_REJECT],
            "the rejection and its late handler, and nothing else"
        );
    });
}

#[test]
fn no_callback_installed_means_nothing_is_forwarded_and_nothing_crashes() {
    // A rejection can arrive before `promises.js` has called
    // `listenForRejections()`. Node `CHECK`s here; a runtime whose bootstrap is
    // allowed to fail must not take the process down, so the callback returns.
    with_isolate(|scope| {
        let mut async_ids = AsyncIds::new();
        let mut ctx = InstallCtx {
            async_ids: &mut async_ids,
        };
        let object = TaskQueue.install(scope, &mut ctx).expect("install");
        let global = scope.get_current_context().global(scope);
        let key = v8::String::new(scope, "__taskQueue").expect("key");
        global.set(scope, key.into(), object.into());

        run(scope, "Promise.reject(new Error('early'));");
        assert!(
            take_seen().is_empty(),
            "no callback means no forwarding, and no panic"
        );
    });
}

#[test]
fn a_throwing_handler_does_not_escape_into_v8() {
    // V8 does not expect this callback to return with an exception pending.
    // `src/node_task_queue.cc` prints it and clears the exception, and a
    // runtime that lets it escape aborts the process on the next allocation.
    with_isolate(|scope| {
        let mut async_ids = AsyncIds::new();
        let mut ctx = InstallCtx {
            async_ids: &mut async_ids,
        };
        let object = TaskQueue.install(scope, &mut ctx).expect("install");

        let template = v8::FunctionTemplate::builder(
            |_scope: &mut v8::PinScope<'_, '_>,
             _args: v8::FunctionCallbackArguments<'_>,
             _rv: v8::ReturnValue| {
                // The handler itself throws; the callback must contain it.
                let message = v8::String::new(_scope, "handler threw").expect("message");
                let error = v8::Exception::error(_scope, message);
                _scope.throw_exception(error);
            },
        )
        .build(scope);
        let callback = template.get_function(scope).expect("a function");
        let setter_key = v8::String::new(scope, "setPromiseRejectCallback").expect("key");
        let setter = object.get(scope, setter_key.into()).expect("setter");
        let setter = v8::Local::<v8::Function>::try_from(setter).expect("a function");
        let _ = setter.call(scope, object.into(), &[callback.into()]);

        run(scope, "Promise.reject(new Error('handled badly'));");
        // Reaching this assertion at all is the point: the store below aborts
        // the process if the exception from the handler is still pending.
        let key = v8::String::new(scope, "__survived").expect("key");
        let global = scope.get_current_context().global(scope);
        global.set(scope, key.into(), v8::Boolean::new(scope, true).into());
        let read = global.get(scope, key.into()).expect("__survived");
        assert!(read.is_true(), "the isolate must still be usable");
    });
}
