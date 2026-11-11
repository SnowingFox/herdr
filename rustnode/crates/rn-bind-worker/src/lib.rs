//! `internalBinding('worker')` for rustnode.
//!
//! `lib/internal/process/pre_execution.js` reads this namespace at module
//! scope — `assert(internalBinding('worker').isMainThread)` and
//! `internalBinding('worker').threadId` — so *every* entry in Node's own test
//! tree fails before the first line of a test runs until the namespace exists.
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
//! # The six facts are per thread, not per process
//!
//! `isMainThread`, `threadId`, `threadName`, `isInternalThread`,
//! `ownsProcessState` and `resourceLimits` describe *the realm being
//! bootstrapped*, which is why Node installs them from a per-isolate template.
//! A worker's own realm must see `isMainThread === false` and its own
//! `threadId`, while the parent keeps answering `true` and `0`. They are read
//! from a thread-local realm record for exactly that reason; a process-global
//! constant would make the worker believe it is the main thread and
//! `internal/worker.js` would then skip installing `parentPort` entirely.
//!
//! # What the main thread reports
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

pub mod handle;
pub mod parent;
pub mod registry;
pub mod run;
mod worker;

use std::cell::RefCell;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub use crate::handle::{next_thread_id, SpawnRequest, WorkerHandle, JOIN_TIMEOUT};
pub use crate::parent::{any_keeps_loop_alive, has_finished, report_finished, tracked_count};

/// The worker crate's share of the check phase.
///
/// Registered by the realm that owns the loop, because this crate cannot install
/// it itself: the check handle belongs to `rn-bind-timers` and the realm's
/// install is what arms it. The body reports every worker whose thread has
/// stopped, which is Node's `onexit` timing.
fn report_worker_exits(scope: &mut v8::PinScope<'_, '_>) {
    let _ = report_finished(scope);
}

/// Registers this crate's check-phase hook, and its liveness predicate.
///
/// Called by the realm's runtime install, on every thread. On the main thread it
/// is what makes `worker.on('exit')` fire; in a worker it is harmless — that
/// thread has no workers of its own unless the worker creates one, in which case
/// it needs exactly the same wiring.
pub fn install_check_phase() {
    // The parent needs a `uv_async_t` of its own before any worker can tell it
    // anything: `ThreadToken::notify` finds no handle without one, so a worker's
    // finish would be a silent no-op. The callback runs on *this* thread, from
    // inside its loop, which is the only place that can arm this thread's check
    // handle — the very thing a foreign thread cannot do for itself.
    rn_uv::wake::install_current_thread(|| {
        rn_bind_timers::arm_check_phase();
        rn_bind_messaging::schedule_ports_with_mail();
    });
    rn_bind_timers::add_check_phase_hook(report_worker_exits);
    // A running worker pins the loop even though it owns nothing on this loop's
    // libuv handle set: its thread has a loop of its own. Node calls this
    // `env->add_refs(1)` on `startThread`.
    rn_bind_timers::add_external_work_predicate(any_keeps_loop_alive);
    // And the phase has to stay armed while an exit is owed, or the report runs
    // after the loop has already decided it has nothing to do.
    rn_bind_timers::add_check_phase_pending_predicate(has_finished);
}
pub use crate::run::WorkerThread;
pub use crate::worker::install_worker_constructor;

/// Members exposed on the namespace object, matching `contracts/worker.json`.
pub const MEMBERS: &[&str] = &[
    "Worker",
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
///
/// Empty: this crate installs every member of `contracts/worker.json`.
pub const DEFERRED: &[(&str, &str)] = &[];

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

/// The facts about the realm on this thread.
///
/// `Environment` holds these per isolate in Node; this is the same split, one
/// level up. The default is the main thread, which is what a realm that never
/// called [`set_realm`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmFacts {
    /// `internalBinding('worker').isMainThread`.
    pub is_main_thread: bool,
    /// `threadId`, from `AllocateEnvironmentThreadId`.
    pub thread_id: i32,
    /// `threadName`, as passed to `Environment::Create`.
    pub thread_name: String,
    /// `isInternalThread`, which only the module-loader worker sets.
    pub is_internal_thread: bool,
    /// `ownsProcessState`: false in a worker, because `process` is shared.
    pub owns_process_state: bool,
}

impl Default for RealmFacts {
    fn default() -> Self {
        Self {
            is_main_thread: true,
            thread_id: MAIN_THREAD_ID,
            thread_name: MAIN_THREAD_NAME.to_string(),
            is_internal_thread: false,
            owns_process_state: true,
        }
    }
}

impl RealmFacts {
    /// The facts `Worker::Run` passes to `CreateEnvironment` for a worker.
    ///
    /// `ownsProcessState` is false because a worker does not own the process:
    /// that is what makes `process.chdir`, `process.abort` and the credential
    /// setters unavailable there, and it is the switch
    /// `internal/bootstrap/switches/does_not_own_process_state.js` selects on.
    #[must_use]
    pub fn worker(thread_id: i32, thread_name: impl Into<String>) -> Self {
        Self {
            is_main_thread: false,
            thread_id,
            thread_name: thread_name.into(),
            is_internal_thread: false,
            owns_process_state: false,
        }
    }
}

thread_local! {
    /// The facts for the realm bootstrapping on this thread.
    ///
    /// A `RefCell` rather than a `OnceCell` because a worker thread bootstraps
    /// one realm and then exits; the main thread never replaces its value, and a
    /// reused thread would set it again.
    static FACTS: RefCell<RealmFacts> = RefCell::new(RealmFacts::default());

    /// The resource limits this realm enforces, or `None` on the main thread.
    ///
    /// `ResourceLimitsGetter` returns nothing without a worker context, so this
    /// stays `None` on the main thread and `getResourceLimits` reports
    /// `undefined` there.
    static RESOURCE_LIMITS: RefCell<Option<[f64; 4]>> = const { RefCell::new(None) };
}

/// Records the facts for the realm this thread is bootstrapping.
///
/// Called by the worker thread before its realm bootstrap and by nothing on the
/// main thread, which is why the default already describes the main thread.
pub fn set_realm(facts: RealmFacts, resource_limits: Option<[f64; 4]>) {
    FACTS.with(|slot| *slot.borrow_mut() = facts);
    RESOURCE_LIMITS.with(|slot| *slot.borrow_mut() = resource_limits);
}

/// The facts for this thread's realm.
#[must_use]
pub fn realm_facts() -> RealmFacts {
    FACTS.with(|slot| slot.borrow().clone())
}

/// The limits this realm enforces, if it is a worker.
#[must_use]
pub fn resource_limits() -> Option<[f64; 4]> {
    RESOURCE_LIMITS.with(|slot| *slot.borrow())
}

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
        let facts = realm_facts();

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
        // `resourceLimits` is `undefined` on the main thread: the getter in
        // `node_worker.cc` returns nothing when the environment has no worker
        // context, which on the main thread it never does. In a worker it is the
        // array `lib/internal/worker.js` turns into the public object.
        let limits: v8::Local<v8::Value> = match resource_limits() {
            Some(limits) => float64_array(scope, &limits),
            None => v8::undefined(scope).into(),
        };
        let members: [(&str, v8::Local<v8::Value>); 6] = [
            ("threadId", v8::Integer::new(scope, facts.thread_id).into()),
            (
                "threadName",
                v8::String::new(scope, &facts.thread_name)
                    .ok_or("cannot allocate the thread name")?
                    .into(),
            ),
            (
                "isMainThread",
                v8::Boolean::new(scope, facts.is_main_thread).into(),
            ),
            (
                "isInternalThread",
                v8::Boolean::new(scope, facts.is_internal_thread).into(),
            ),
            (
                "ownsProcessState",
                v8::Boolean::new(scope, facts.owns_process_state).into(),
            ),
            ("resourceLimits", limits),
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

        // The constructor `lib/internal/worker.js` calls as `new WorkerImpl(...)`.
        let constructor = install_worker_constructor(scope)?;
        define(
            scope,
            object,
            "Worker",
            constructor,
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
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Leaving the return value unset yields `undefined`, which is what the main
    // thread must report.
    if let Some(port) = rn_core::hook_slot::env_message_port(scope) {
        rv.set(port.into());
    }
}

/// Builds a `Float64Array` from `values`, the way `parseResourceLimits` expects.
///
/// The `v8` crate's `Float64Array::new` takes an `ArrayBuffer` plus an offset and
/// length, so the buffer is allocated first. Index access on a typed array is
/// `Value`-typed in this binding, which is why the values go in as `Number`s.
fn float64_array<'s>(scope: &mut v8::PinScope<'s, '_>, values: &[f64]) -> v8::Local<'s, v8::Value> {
    let buffer = v8::ArrayBuffer::new(scope, std::mem::size_of_val(values));
    let Some(array) = v8::Float64Array::new(scope, buffer, 0, values.len()) else {
        return v8::undefined(scope).into();
    };
    for (index, value) in values.iter().enumerate() {
        let index = u32::try_from(index).unwrap_or(0);
        let number = v8::Number::new(scope, *value);
        let _ = array.set_index(scope, index, number.into());
    }
    array.into()
}

/// Reads `length` doubles out of a `Float64Array` value, or `None` when the
/// value is not one.
fn read_float64_array(
    scope: &v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
    length: usize,
) -> Option<Vec<f64>> {
    let array = v8::Local::<v8::Float64Array>::try_from(value).ok()?;
    let mut values = Vec::with_capacity(length);
    for index in 0..length {
        let index = u32::try_from(index).ok()?;
        let entry = array.get_index(scope, index)?;
        values.push(entry.number_value(scope)?);
    }
    Some(values)
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
    fn nothing_is_deferred_any_more() {
        // `Worker` used to be here with a reason that was correct at the time.
        // Keeping the list empty is the assertion that the whole namespace is
        // installed, so a future gap has to be declared rather than inherited.
        assert!(DEFERRED.is_empty(), "the worker namespace is complete");
    }

    #[test]
    fn the_main_thread_facts_are_the_defaults() {
        let facts = RealmFacts::default();
        assert!(facts.is_main_thread);
        assert_eq!(facts.thread_id, MAIN_THREAD_ID);
        assert_eq!(facts.thread_name, MAIN_THREAD_NAME);
        assert!(!facts.is_internal_thread);
        assert!(facts.owns_process_state);
    }

    #[test]
    fn a_worker_does_not_own_the_process_and_is_not_the_main_thread() {
        // `does_not_own_process_state.js` is selected on this, and
        // `lib/internal/worker.js` guards `parentPort` installation on
        // `isMainThread` being false. Both would silently do the wrong thing if
        // these two flags were the main thread's.
        let facts = RealmFacts::worker(7, "WorkerThread");
        assert!(!facts.is_main_thread);
        assert!(!facts.owns_process_state);
        assert_eq!(facts.thread_id, 7);
        assert_eq!(facts.thread_name, "WorkerThread");
    }
}

thread_local! {
    /// The parent's stop flag, published by [`publish_stop_flag`].
    ///
    /// A reference to the parent's `Arc`, not a copy: `worker.terminate()` sets
    /// it from the parent's thread, and `terminate_execution` can abort V8 inside
    /// any callback. `worker_thread.js`'s `process._fatalException` then runs,
    /// cannot serialize the abort, and posts `COULD_NOT_SERIALIZE_ERROR` — which
    /// the parent emits as `Uncaught null: null` after a terminate that actually
    /// worked. Node avoids the path with `env->set_can_call_into_js(false)` in
    /// `Worker::Exit`; this is the same answer at the one place JavaScript asks.
    static STOP_FLAG: std::cell::RefCell<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>> =
        const { std::cell::RefCell::new(None) };

    /// The exit code a worker's `process.exit()` recorded.
    ///
    /// Set by `process.reallyExit` when the realm is not the main thread. The
    /// worker's loop stops on [`rn_core::hook_slot::EXIT_REQUESTED`], and this is
    /// what the thread body reports to the parent afterwards.
    static EXIT_CODE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

/// Publishes the shared stop flag for this worker's realm.
///
/// The flag is an `Arc<AtomicBool>` the parent sets from its own thread, so the
/// realm-local copy has to be a reference to it rather than a `bool`: a
/// termination can arrive at any moment, including in the middle of a callback,
/// and the fatal handler must see it immediately rather than at the next
/// scheduler check.
pub fn publish_stop_flag(flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    STOP_FLAG.with(|slot| *slot.borrow_mut() = Some(flag));
}

/// Whether this worker's realm is stopping.
pub fn is_stopping() -> bool {
    STOP_FLAG.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst))
    })
}

/// Drops the published flag, so a reused thread starts clean.
pub fn clear_stopping() {
    STOP_FLAG.with(|slot| *slot.borrow_mut() = None);
}

/// Records the exit code a worker's `process.exit()` asked for.
///
/// This is `process.reallyExit`'s worker branch. It also sets `process._exiting`,
/// which is what makes a second `process.exit()` a no-op and what `lib/**` reads
/// to decide whether output should still be flushed.
pub fn record_worker_exit_code(scope: &mut v8::PinScope<'_, '_>, code: i32) {
    EXIT_CODE.with(|slot| slot.set(Some(code)));
    if let Some(process) = global_process(scope) {
        if let Some(key) = v8::String::new(scope, "exitCode") {
            let _ = process.set(scope, key.into(), v8::Integer::new(scope, code).into());
        }
        if let Some(key) = v8::String::new(scope, "_exiting") {
            let _ = process.set(scope, key.into(), v8::Boolean::new(scope, true).into());
        }
    }
}

/// The exit code a worker's `process.exit()` asked for, if any.
#[must_use]
pub fn recorded_exit_code() -> Option<i32> {
    EXIT_CODE.with(std::cell::Cell::get)
}

/// Clears the recorded exit code, so a reused thread starts clean.
pub fn clear_exit_code() {
    EXIT_CODE.with(|slot| slot.set(None));
}

fn global_process<'s>(scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "process")?;
    let process = global.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(process).ok()
}
