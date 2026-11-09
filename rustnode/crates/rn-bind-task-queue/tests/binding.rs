//! End-to-end checks that drive `task_queue` through a real V8 isolate.
//!
//! The interesting properties are the ones `lib/internal/process/task_queues.js`
//! depends on: `tickInfo` is a typed array both sides share, `enqueueMicrotask`
//! really schedules work on the isolate's microtask queue, and
//! `runMicrotasks` really drains it.

use rn_bind_task_queue::{TaskQueue, HAS_REJECTION_TO_WARN, HAS_TICK_SCHEDULED};
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Creates the isolate every test in this file shares.
///
/// `V8::initialize` may only run once per process, so the tests run on one
/// isolate in sequence rather than one each.
fn with_isolate<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    with_isolate_with_policy(v8::MicrotasksPolicy::Auto, body)
}

/// Same, but lets a test choose when microtasks drain.
fn with_isolate_with_policy<T>(
    policy: v8::MicrotasksPolicy,
    body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T,
) -> T {
    static INIT: std::sync::Once = std::sync::Once::new();
    let create = || {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    };
    INIT.call_once(create);

    let mut isolate = v8::Isolate::new(Default::default());
    isolate.set_microtasks_policy(policy);
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    body(scope)
}

fn install<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Object> {
    let mut async_ids = AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    TaskQueue.install(scope, &mut ctx).expect("install")
}

#[test]
fn every_contract_member_is_installed() {
    with_isolate(|scope| {
        let object = install(scope);
        for member in rn_bind_task_queue::MEMBERS {
            let key = v8::String::new(scope, member).expect("key");
            let value = object.get(scope, key.into()).expect("member");
            assert!(
                !value.is_undefined(),
                "{member} must be defined on the namespace object"
            );
        }
    });
}

#[test]
fn tick_info_is_a_shared_two_byte_array() {
    with_isolate(|scope| {
        let object = install(scope);
        let key = v8::String::new(scope, "tickInfo").expect("key");
        let value = object.get(scope, key.into()).expect("tickInfo");
        let array = v8::Local::<v8::Uint8Array>::try_from(value).expect("a Uint8Array");
        assert_eq!(array.byte_length(), 2);
        assert_eq!(array.length(), 2);

        // Both flags the JS side reads start clear.
        assert_eq!(
            array
                .get_index(scope, HAS_TICK_SCHEDULED as u32)
                .map(|v| v.uint32_value(scope)),
            Some(Some(0))
        );
        assert_eq!(
            array
                .get_index(scope, HAS_REJECTION_TO_WARN as u32)
                .map(|v| v.uint32_value(scope)),
            Some(Some(0))
        );
    });
}

#[test]
fn writing_the_typed_array_is_visible_to_rust() {
    with_isolate(|scope| {
        let object = install(scope);
        let key = v8::String::new(scope, "tickInfo").expect("key");
        let value = object.get(scope, key.into()).expect("tickInfo");
        let array = v8::Local::<v8::Uint8Array>::try_from(value).expect("a Uint8Array");

        assert!(!rn_bind_task_queue::has_tick_scheduled());
        array.set_index(
            scope,
            HAS_TICK_SCHEDULED as u32,
            v8::Integer::new(scope, 1).into(),
        );
        // Reading through Rust must see the byte the JavaScript side wrote:
        // that is the whole point of the aliased buffer.
        assert!(rn_bind_task_queue::has_tick_scheduled());

        array.set_index(
            scope,
            HAS_TICK_SCHEDULED as u32,
            v8::Integer::new(scope, 0).into(),
        );
        assert!(!rn_bind_task_queue::has_tick_scheduled());
    });
}

#[test]
fn a_rust_write_lands_in_the_javascript_view() {
    with_isolate(|scope| {
        let object = install(scope);
        let key = v8::String::new(scope, "tickInfo").expect("key");
        let value = object.get(scope, key.into()).expect("tickInfo");
        let array = v8::Local::<v8::Uint8Array>::try_from(value).expect("a Uint8Array");

        rn_bind_task_queue::set_tick_flag(HAS_REJECTION_TO_WARN, true);
        let read = array
            .get_index(scope, HAS_REJECTION_TO_WARN as u32)
            .expect("index")
            .uint32_value(scope);
        assert_eq!(read, Some(1));
        rn_bind_task_queue::set_tick_flag(HAS_REJECTION_TO_WARN, false);
    });
}

#[test]
fn enqueue_microtask_defers_work_until_the_checkpoint() {
    // The default policy drains microtasks at the end of `script.run`, which
    // would hide whether `enqueueMicrotask` really deferred anything. The
    // explicit policy leaves them queued so the assertion means something.
    with_isolate_with_policy(v8::MicrotasksPolicy::Explicit, |scope| {
        let object = install(scope);
        let global = scope.get_current_context().global(scope);

        // `globalThis.ran = false; enqueueMicrotask(() => { globalThis.ran = true; });`
        // The namespace object is exposed as a global so the script can call
        // through `this` without a receiver, the way `task_queues.js` does.
        let key = v8::String::new(scope, "__taskQueue").expect("key");
        global.set(scope, key.into(), object.into());
        let source = v8::String::new(
            scope,
            "globalThis.ran = false; __taskQueue.enqueueMicrotask(() => { globalThis.ran = true; });",
        )
        .expect("source");
        let script = v8::Script::compile(scope, source, None).expect("compile");
        script.run(scope).expect("run");

        let flag = |scope: &mut v8::PinScope<'_, '_>| {
            let key = v8::String::new(scope, "ran").expect("key");
            global
                .get(scope, key.into())
                .expect("ran")
                .boolean_value(scope)
        };
        // The microtask has not run: `enqueueMicrotask` only schedules it.
        assert!(!flag(scope));

        scope.perform_microtask_checkpoint();
        assert!(flag(scope));
    });
}

#[test]
fn run_microtasks_is_a_function_on_the_namespace() {
    with_isolate(|scope| {
        let object = install(scope);
        let key = v8::String::new(scope, "runMicrotasks").expect("key");
        let value = object.get(scope, key.into()).expect("runMicrotasks");
        assert!(value.is_function());
    });
}

#[test]
fn promise_reject_events_match_the_v8_enum() {
    with_isolate(|scope| {
        let object = install(scope);
        let key = v8::String::new(scope, "promiseRejectEvents").expect("key");
        let value = object.get(scope, key.into()).expect("events");
        let events = v8::Local::<v8::Object>::try_from(value).expect("an object");

        let read = |name: &str| {
            let key = v8::String::new(scope, name).expect("key");
            events
                .get(scope, key.into())
                .expect("member")
                .uint32_value(scope)
        };
        // These are `v8::PromiseRejectEvent`'s values, which the JavaScript
        // side compares against the event number V8 hands it.
        assert_eq!(read("kPromiseRejectWithNoHandler"), Some(0));
        assert_eq!(read("kPromiseHandlerAddedAfterReject"), Some(1));
    });
}
