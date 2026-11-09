//! The `worker` namespace as `lib/**` actually reads it, through a real V8 isolate.
//!
//! `contracts/worker.json` records `kind` and `arity` per member, which is
//! enough to catch a missing name but not a wrong *value*: `threadId` recorded
//! as `number` passes whether it is 0 or 7. The expectations here were taken
//! from a stock Node 28 binary (`node --expose-internals`, reading
//! `internalBinding('worker')` through `internal/test/binding`), so they are a
//! parity check rather than a restatement of the Rust code.
//!
//! The property-attribute cases exist because `src/node_worker.cc` installs the
//! namespace through two different V8 hooks: `NODE_DEFINE_CONSTANT` for the five
//! `k*` values (`DontDelete | ReadOnly`) and a per-isolate accessor template for
//! the six thread facts (plain writable properties). A reader that only compares
//! values cannot tell those apart, and `lib/internal/worker.js` writes to
//! neither — but `test/common/**` and V8's own `Object.getOwnPropertyDescriptor`
//! based checks can.

use rn_bind_worker::Worker;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Runs `body` with a live isolate, scope and context.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    body(scope)
}

/// Installs the namespace and exposes it as the global `worker`.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let mut async_ids = AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    let object = Worker.install(scope, &mut ctx).expect("install");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__worker").expect("key");
    global.set(scope, key.into(), object.into());
}

/// Evaluates `source` and returns its completion value.
fn eval<'s>(scope: &mut v8::PinScope<'s, '_>, source: &str) -> v8::Local<'s, v8::Value> {
    let source = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, source, None).expect("compile");
    script.run(scope).expect("run")
}

/// Reads `expression` after installing the binding, as a JSON string.
fn read(expression: &str) -> String {
    with_context(|scope| {
        install(scope);
        let source = format!("JSON.stringify({expression})");
        let value = eval(scope, &source);
        value.to_rust_string_lossy(scope)
    })
}

#[test]
fn the_constants_are_the_indices_node_worker_h_declares() {
    // These are indices into the `Float64Array(kTotalResourceLimitCount)` that
    // `lib/internal/worker.js` builds, not megabyte counts. Getting one wrong
    // aliases two limits onto each other without raising anything.
    assert_eq!(
        read(
            "[__worker.kMaxYoungGenerationSizeMb, __worker.kMaxOldGenerationSizeMb, \
               __worker.kCodeRangeSizeMb, __worker.kStackSizeMb, \
               __worker.kTotalResourceLimitCount]"
        ),
        "[0,1,2,3,4]"
    );
}

#[test]
fn the_main_thread_facts_match_a_stock_node_binary() {
    // Recorded from `node --expose-internals`: threadId 0, threadName "",
    // isMainThread true, isInternalThread false, ownsProcessState true.
    assert_eq!(
        read(
            "[__worker.threadId, __worker.threadName, __worker.isMainThread, \
               __worker.isInternalThread, __worker.ownsProcessState]"
        ),
        r#"[0,"",true,false,true]"#
    );
}

#[test]
fn resource_limits_and_the_environment_port_are_undefined_on_the_main_thread() {
    // `ResourceLimitsGetter` returns nothing without a worker context, and
    // `getEnvMessagePort` returns nothing when `Environment::message_port()` is
    // empty. Both are real Node behaviour, not gaps in this binding:
    // `lib/internal/worker.js` guards `resourceLimits` with `isMainThread`, and
    // the only `getEnvMessagePort()` caller runs from the worker bootstrap.
    assert_eq!(
        read("[typeof __worker.resourceLimits, typeof __worker.getEnvMessagePort()]"),
        r#"["undefined","undefined"]"#
    );
}

#[test]
fn get_env_message_port_is_a_zero_arity_function() {
    // `contracts/worker.json` records arity 0; `test/common/**` calls it with no
    // arguments and `createWorkerStdio()` does the same.
    assert_eq!(
        read("[typeof __worker.getEnvMessagePort, __worker.getEnvMessagePort.length]"),
        r#"["function",0]"#
    );
}

#[test]
fn the_constants_are_read_only_and_not_configurable() {
    // `NODE_DEFINE_CONSTANT` is `DontDelete | ReadOnly`. This matters because a
    // test that assigns to `kStackSizeMb` to change a limit must fail rather
    // than silently make the next `require('worker_threads')` use a different
    // array stride.
    assert_eq!(
        read(
            "(() => { \
               const d = Object.getOwnPropertyDescriptor(__worker, 'kStackSizeMb'); \
               return [d.writable, d.enumerable, d.configurable]; \
             })()"
        ),
        "[false,true,false]"
    );
}

#[test]
fn the_thread_facts_are_writable_and_configurable() {
    // The per-isolate accessors materialise as ordinary properties on Node, so
    // a script may shadow them. `write` below proves the value really moves and
    // is not a V8-level constant.
    assert_eq!(
        read(
            "(() => { \
               const d = Object.getOwnPropertyDescriptor(__worker, 'threadId'); \
               return [d.writable, d.enumerable, d.configurable]; \
             })()"
        ),
        "[true,true,true]"
    );
    assert_eq!(
        read("(() => { __worker.threadId = 42; return __worker.threadId; })()"),
        "42"
    );
}

#[test]
fn the_namespace_has_exactly_the_contract_members_and_no_worker_yet() {
    // `Worker` is deferred, so it must be absent rather than a stub: a
    // constructor that neither started a thread nor delivered a message would
    // hang `new Worker(...)` instead of failing where it is used.
    //
    // The list is `Object.getOwnPropertyNames`, so it pins that `members()` and
    // the installed object agree. On this one point it is stricter than a stock
    // Node binary: Node installs the six thread facts as lazy per-isolate
    // accessors, and a lazy accessor whose getter returns nothing never
    // materialises, so `resourceLimits` is absent from
    // `Object.getOwnPropertyNames(internalBinding('worker'))` on the main thread
    // (`'resourceLimits' in binding` is `false`, while `binding.resourceLimits`
    // still reads `undefined` from the template). rustnode has no lazy-accessor
    // stage, so it installs the property with the value the getter would have
    // produced. The observable value is identical — `undefined` either way —
    // and installing it keeps `members()` from naming a property the object
    // does not carry.
    let contract: serde_json::Value =
        serde_json::from_str(include_str!("../../../contracts/worker.json"))
            .expect("the worker contract parses");
    let mut expected: Vec<String> = contract["members"]
        .as_object()
        .expect("members")
        .keys()
        .filter(|name| name.as_str() != "Worker")
        .cloned()
        .collect();
    expected.sort();

    let actual = read("Object.getOwnPropertyNames(__worker).sort()");
    let actual: Vec<String> = serde_json::from_str(&actual).expect("a string array");
    assert_eq!(actual, expected);
}

#[test]
fn the_registry_hands_out_one_object_per_namespace() {
    // `BindingRegistry::install` caches per isolate because `lib/**` relies on
    // two `internalBinding('worker')` calls returning the identical object:
    // `pre_execution.js` reads this namespace three times and
    // `internal/worker/messaging.js` compares `threadId` across modules.
    with_context(|scope| {
        let mut registry = rn_core::BindingRegistry::new();
        registry.register_module(Worker);
        let first = registry.install(scope, "worker").expect("first install");
        let second = registry.install(scope, "worker").expect("second install");
        assert!(first.strict_equals(second.into()));
    });
}
