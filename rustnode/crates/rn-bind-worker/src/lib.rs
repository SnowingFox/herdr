//! `internalBinding('worker')` for rustnode.
//!
//! `lib/internal/process/pre_execution.js` reads this namespace at module
//! scope — `assert(internalBinding('worker').isMainThread)` and
//! `internalBinding('worker').threadId` — so *every* entry in Node's own test
//! tree fails before the first line of a test runs until the namespace exists.
//! That is why the main-thread surface lands here first, separately from the
//! `Worker` constructor.
//!
//! # The shape Node really returns
//!
//! `src/node_worker.cc` splits this namespace across two V8 initialisation
//! hooks, which is visible from JavaScript and worth reproducing exactly:
//!
//! * `CreateWorkerPerContextProperties` defines the five `k*` resource-limit
//!   constants with `NODE_DEFINE_CONSTANT`, meaning `DontDelete | ReadOnly`,
//!   enumerable and **not** configurable.
//! * `CreateWorkerPerIsolateProperties` installs `threadId`, `threadName`,
//!   `isMainThread`, `isInternalThread`, `ownsProcessState`, `resourceLimits`
//!   as lazy accessors on the *per-isolate* template, and `getEnvMessagePort`
//!   plus the `Worker` constructor as ordinary function properties.
//!
//! The distinction is observable: on a stock Node 28 the six lazy members come
//! back from `Object.getOwnPropertyDescriptor` as
//! `{ writable: true, enumerable: true, configurable: true }` — plain data
//! properties after first access — while the constants report
//! `{ writable: false, enumerable: true, configurable: false }`. rustnode has
//! one install hook rather than two, so it materialises the lazy accessors
//! eagerly and gives each family the attribute set Node ends up with.
//!
//! Materialising eagerly is visible in one place only. A lazy accessor whose
//! getter returns nothing never materialises, so on the main thread
//! `'resourceLimits' in internalBinding('worker')` is **false** in real Node
//! even though reading the property yields `undefined`. Installing it eagerly
//! makes it an own property whose value is that same `undefined`. Nothing in
//! `lib/**` distinguishes the two — `internal/worker.js` guards the read with
//! `!isMainThread` and never tests for presence — and keeping `members()`
//! honest is worth more than reproducing V8's laziness.
//!
//! # What this build reports on the main thread
//!
//! Values were checked against a real `node --expose-internals` binary, not
//! inferred from the source alone:
//!
//! ```text
//! kMaxYoungGenerationSizeMb 0   kMaxOldGenerationSizeMb 1   kCodeRangeSizeMb 2
//! kStackSizeMb 3                kTotalResourceLimitCount 4
//! threadId 0    threadName ""    isMainThread true
//! isInternalThread false         ownsProcessState true
//! resourceLimits undefined       getEnvMessagePort() undefined
//! ```
//!
//! `threadName` being `""` rather than `'main'` is the one that surprises: the
//! `Environment` constructor's `thread_name` parameter defaults to an empty
//! `string_view` and the main thread never overrides it. `lib/internal/worker.js`
//! passes it straight through to `worker_threads.threadName`, so `''` is what a
//! main-thread script observes.
//!
//! `resourceLimits` is absent from the main thread because `ResourceLimitsGetter`
//! returns nothing when `env->worker_context()` is null, and
//! `getEnvMessagePort` returns nothing when `env->message_port()` is empty —
//! which it is for the main thread, where no worker entry point exists to
//! create one. `lib/internal/worker.js` guards the first (`!isMainThread ?
//! makeResourceLimits(...) : {}`) and `createWorkerStdio()` is the only caller
//! of the second, reached solely from the worker-side bootstrap switch.
//!
//! # `Worker` is deferred
//!
//! See `DEFERRED` below. A constructor that returned an object capable of
//! neither starting a thread nor posting a message would make
//! `new Worker(...)` hang instead of failing where it is used, so the name is
//! declared absent rather than stubbed.
//!
//! # The `k*` values are indices, not sizes
//!
//! `lib/internal/worker.js` uses them to address a shared `Float64Array`:
//!
//! ```js
//! const resourceLimitsArray = new Float64Array(kTotalResourceLimitCount);
//! ret[kMaxOldGenerationSizeMb] = MathMax(obj.maxOldGenerationSizeMb, 2);
//! ```
//!
//! They come from `enum ResourceLimits` in `src/node_worker.h`, where the
//! declaration order *is* the numbering. Swapping two would silently alias
//! `maxYoungGenerationSizeMb` onto `maxOldGenerationSizeMb` — no error, just the
//! wrong limit enforced — so the order below is load-bearing and pinned by a
//! test.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/worker.json`.
pub const MEMBERS: &[&str] = &[
    "getEnvMessagePort",
    "isInternalThread",
    "isMainThread",
    "kCodeRangeSizeMb",
    "kMaxOldGenerationSizeMb",
    "kMaxYoungGenerationSizeMb",
    "kStackSizeMb",
    "kTotalResourceLimitCount",
    "ownsProcessState",
    "resourceLimits",
    "threadId",
    "threadName",
];

/// Members this build does not install yet.
pub const DEFERRED: &[(&str, &str)] = &[(
    "Worker",
    "needs a second isolate, a MessagePort pair with a cross-thread transport, \
     and the worker-side bootstrap that runs lib/internal/main/worker_thread.js; \
     a constructor that started no thread and delivered no message would hang \
     new Worker() instead of failing at the point of use",
)];

/// Index of `maxYoungGenerationSizeMb` in the shared resource-limit array.
///
/// `enum ResourceLimits` in `src/node_worker.h`, in declaration order.
pub const K_MAX_YOUNG_GENERATION_SIZE_MB: i32 = 0;
/// Index of `maxOldGenerationSizeMb` in the shared resource-limit array.
pub const K_MAX_OLD_GENERATION_SIZE_MB: i32 = 1;
/// Index of `codeRangeSizeMb` in the shared resource-limit array.
pub const K_CODE_RANGE_SIZE_MB: i32 = 2;
/// Index of `stackSizeMb` in the shared resource-limit array.
pub const K_STACK_SIZE_MB: i32 = 3;
/// Number of slots in the shared resource-limit array.
pub const K_TOTAL_RESOURCE_LIMIT_COUNT: i32 = 4;

// The array must have a slot for every index above, or `parseResourceLimits`
// in `lib/internal/worker.js` writes past the end of the `Float64Array`.
const _: () = assert!(K_TOTAL_RESOURCE_LIMIT_COUNT > K_STACK_SIZE_MB);

/// The thread id the main thread reports.
///
/// `AllocateEnvironmentThreadId()` starts at 0 and the main environment is the
/// first one allocated, so the main thread is always id 0.
pub const MAIN_THREAD_ID: i32 = 0;

/// The thread name the main thread reports.
///
/// `Environment::Create`'s `thread_name` parameter defaults to `""` and the
/// main-thread call site in `NodeMainInstance::CreateMainEnvironment` does not
/// pass one, so the empty string is what a main-thread script sees through
/// `worker_threads.threadName`.
pub const MAIN_THREAD_NAME: &str = "";

pub struct Worker;

impl BindingModule for Worker {
    fn namespace(&self) -> &'static str {
        "worker"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        // `NODE_DEFINE_CONSTANT`: enumerable, non-writable, non-configurable.
        for (name, value) in [
            ("kMaxYoungGenerationSizeMb", K_MAX_YOUNG_GENERATION_SIZE_MB),
            ("kMaxOldGenerationSizeMb", K_MAX_OLD_GENERATION_SIZE_MB),
            ("kCodeRangeSizeMb", K_CODE_RANGE_SIZE_MB),
            ("kStackSizeMb", K_STACK_SIZE_MB),
            ("kTotalResourceLimitCount", K_TOTAL_RESOURCE_LIMIT_COUNT),
        ] {
            define(
                scope,
                object,
                name,
                v8::Integer::new(scope, value).into(),
                v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
            )?;
        }

        // The six lazy per-isolate accessors, materialised. A plain assignment
        // creates exactly the attributes V8 reports for them on Node:
        // writable, enumerable and configurable.
        //
        // `resourceLimits` is deliberately `undefined`: the getter in
        // `node_worker.cc` returns nothing when the environment has no worker
        // context, which on the main thread it never does. `lib/internal/worker.js`
        // branches on `isMainThread` before reading it, so an absent value is the
        // correct one and a made-up object would be the wrong one.
        let members: [(&str, v8::Local<v8::Value>); 6] = [
            ("threadId", v8::Integer::new(scope, MAIN_THREAD_ID).into()),
            (
                "threadName",
                v8::String::new(scope, MAIN_THREAD_NAME)
                    .ok_or("cannot allocate the thread name")?
                    .into(),
            ),
            ("isMainThread", v8::Boolean::new(scope, true).into()),
            ("isInternalThread", v8::Boolean::new(scope, false).into()),
            ("ownsProcessState", v8::Boolean::new(scope, true).into()),
            ("resourceLimits", v8::undefined(scope).into()),
        ];
        for (name, value) in members {
            define(scope, object, name, value, v8::PropertyAttribute::NONE)?;
        }

        // `getEnvMessagePort` is an ordinary method. It returns `undefined` on
        // the main thread because `Environment::message_port()` is empty there;
        // only a worker entry point installs one.
        let get_env_message_port = function(scope, "getEnvMessagePort", get_env_message_port)?;
        define(
            scope,
            object,
            "getEnvMessagePort",
            get_env_message_port,
            v8::PropertyAttribute::NONE,
        )?;

        Ok(object)
    }
}

/// Registers the `worker` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Worker);
}

/// `getEnvMessagePort()`: the port the worker entry point talks to its parent on.
///
/// The main thread has none — `Environment::message_port()` stays empty until a
/// worker's `CreateEnvMessagePort()` fills it — so this returns `undefined`,
/// matching `src/node_worker.cc`'s `if (!port.IsEmpty())` guard. That is not a
/// gap: `createWorkerStdio()` in `lib/internal/worker/io.js` is the only caller
/// and it runs only from the worker-side bootstrap switch.
fn get_env_message_port(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // Leaving the return value unset yields `undefined`.
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

fn define(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
    attributes: v8::PropertyAttribute,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object
        .define_own_property(scope, key.into(), value, attributes)
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_resource_limit_indices_match_node_worker_h() {
        // `enum ResourceLimits { kMaxYoungGenerationSizeMb,
        // kMaxOldGenerationSizeMb, kCodeRangeSizeMb, kStackSizeMb,
        // kTotalResourceLimitCount }` — declaration order is the numbering.
        // The "every index fits in the array" invariant is a `const` assertion
        // next to the declarations, so it cannot be forgotten here.
        assert_eq!(K_MAX_YOUNG_GENERATION_SIZE_MB, 0);
        assert_eq!(K_MAX_OLD_GENERATION_SIZE_MB, 1);
        assert_eq!(K_CODE_RANGE_SIZE_MB, 2);
        assert_eq!(K_STACK_SIZE_MB, 3);
        assert_eq!(K_TOTAL_RESOURCE_LIMIT_COUNT, 4);
    }

    #[test]
    fn every_contract_member_is_installed_or_deferred() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/worker.json"))
                .expect("the worker contract parses");
        let recorded = contract["members"]
            .as_object()
            .expect("the contract has a members object");
        for member in recorded.keys() {
            assert!(
                MEMBERS.contains(&member.as_str())
                    || DEFERRED.iter().any(|(name, _)| name == member),
                "{member} is in the contract but neither installed nor deferred"
            );
        }
    }

    #[test]
    fn the_deferred_member_is_only_worker() {
        assert_eq!(DEFERRED.len(), 1);
        assert_eq!(DEFERRED[0].0, "Worker");
    }
}
