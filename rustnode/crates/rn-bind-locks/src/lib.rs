//! `internalBinding('locks')` for rustnode.
//!
//! `lib/internal/locks.js` implements the Web Locks *interface* — option
//! conversion, abort signals, the diagnostics channels, `Lock` objects — and
//! delegates the algorithm to the binding, exactly as it delegates to
//! `src/node_locks.cc` in Node. Loading the namespace used to throw, which made
//! `navigator.locks` and the lazy `require('internal/locks')` in
//! `lib/worker_threads.js` fail before any lock was taken; the algorithm itself
//! lives in [`locks`], and this module is the promise plumbing around it.
//!
//! # The five members
//!
//! `request` and `query` are `SetMethod` members, so `length` is 0 and `new` is a
//! `TypeError`. The three strings are `NODE_DEFINE_CONSTANT`s: read-only,
//! non-configurable, enumerable. All five verified against the pinned oracle:
//!
//! ```text
//! request  {"writable":true,"enumerable":true,"configurable":true}  len 0  name "request"
//! query    {"writable":true,"enumerable":true,"configurable":true}  len 0  name "query"
//! LOCK_MODE_SHARED    "shared"     {"writable":false,"configurable":false}
//! LOCK_MODE_EXCLUSIVE "exclusive"  {"writable":false,"configurable":false}
//! LOCK_STOLEN_ERROR   "LOCK_STOLEN" {"writable":false,"configurable":false}
//! ```
//!
//! # Two promises per request
//!
//! `request` builds two resolvers and returns the second one's promise. The
//! first (`waiting`) is settled with the callback's return value as soon as the
//! request is resolved; the second (`released`) is settled when the lock is
//! *released*, which for a promise-returning callback is later. `locks.request`
//! in JavaScript returns the released promise, so that is the value `await` sees.
//! Both are marked handled at creation, which is Node's guard against an
//! unhandled-rejection warning for the internal half nobody awaits.
//!
//! # Where the per-request state lives
//!
//! A [`Slot`] holds the two resolvers and the callback, in a thread-local table
//! keyed by request id. That is deliberate: a `v8::Global` may only be used from
//! the thread that owns its isolate, and every use of a slot below happens on
//! that thread — the algorithm hands back an id, never a handle, which is what
//! makes the cross-environment case work at all.
//!
//! # Waking another environment
//!
//! `src/node_locks.cc` calls `env->SetImmediateThreadsafe`, which schedules a
//! callback on the target's loop. The equivalent here is `uv_async_send` on that
//! thread's wake handle ([`rn_uv::wake`]), followed by a check-phase hook that
//! runs [`process_env`] on the target thread. The hook is what keeps the V8 half
//! on the owning thread; the flag it reads is the "there is something to do"
//! signal, so an idle loop does no lock work at all.

pub mod locks;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::locks::{EnvId, Manager, Mode, Request, Step};

/// Members exposed on the namespace object, matching `contracts/locks.json`.
pub const MEMBERS: &[&str] = &[
    "LOCK_MODE_EXCLUSIVE",
    "LOCK_MODE_SHARED",
    "LOCK_STOLEN_ERROR",
    "query",
    "request",
];

/// Members this namespace needs but cannot install yet.
///
/// Empty: all five recorded members are installed and behave as Node's do.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `LOCK_STOLEN_ERROR`, the message `convertLockError` compares against.
pub const LOCK_STOLEN_ERROR: &str = "LOCK_STOLEN";
/// `LOCK_MODE_SHARED`.
pub const LOCK_MODE_SHARED: &str = "shared";
/// `LOCK_MODE_EXCLUSIVE`.
pub const LOCK_MODE_EXCLUSIVE: &str = "exclusive";

/// `internalBinding('locks')`.
pub struct LocksBinding;

impl BindingModule for LocksBinding {
    fn namespace(&self) -> &'static str {
        "locks"
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
        rn_core::set_method(scope, object, "request", request)?;
        rn_core::set_method(scope, object, "query", query)?;
        // `CreatePerIsolateProperties` uses `target->Set` with
        // `ReadOnly | DontDelete`, so the properties are enumerable and not
        // configurable, and stay data properties rather than accessors.
        for (name, value) in [
            ("LOCK_MODE_SHARED", LOCK_MODE_SHARED),
            ("LOCK_MODE_EXCLUSIVE", LOCK_MODE_EXCLUSIVE),
            ("LOCK_STOLEN_ERROR", LOCK_STOLEN_ERROR),
        ] {
            let key = v8::String::new(scope, name).ok_or("cannot allocate a constant name")?;
            let value = v8::String::new(scope, value).ok_or("cannot allocate a constant value")?;
            object
                .define_own_property(
                    scope,
                    key.into(),
                    value.into(),
                    v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
                )
                .ok_or_else(|| format!("cannot define the constant {name}"))?;
        }
        Ok(object)
    }
}

/// Registers the `locks` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(LocksBinding);
}

// ---------------------------------------------------------------------------
// Per-request state
// ---------------------------------------------------------------------------

/// The promises and callback one request owns.
struct Slot {
    waiting: v8::Global<v8::PromiseResolver>,
    released: v8::Global<v8::PromiseResolver>,
    /// Taken when the request is granted or missed. Kept as an `Option` so the
    /// slot can outlive the callback: a stolen lock's slot stays until the user
    /// callback settles, which is how its `released` promise stays rejected once.
    callback: Option<v8::Global<v8::Function>>,
}

thread_local! {
    /// This thread's request slots, by request id.
    static SLOTS: RefCell<HashMap<u64, Slot>> = RefCell::new(HashMap::new());
    /// This thread's environment id, assigned on first use.
    static ENV: Cell<EnvId> = const { Cell::new(0) };
    /// This thread's own wake flag, once the environment has registered.
    ///
    /// The check phase asks whether a wake is outstanding on every iteration the
    /// handle is armed, so it cannot afford the process-wide table's mutex. The
    /// flag is the same allocation the table holds, so a foreign thread's store
    /// is visible here.
    static OWN_WAKE: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
}

fn env_id() -> EnvId {
    ENV.with(|cell| {
        let current = cell.get();
        if current != 0 {
            return current;
        }
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let assigned = NEXT.fetch_add(1, Ordering::Relaxed);
        cell.set(assigned);
        assigned
    })
}

// ---------------------------------------------------------------------------
// The environments the manager can wake
// ---------------------------------------------------------------------------

/// What one environment publishes so another thread can reach it.
struct Registration {
    /// The `uv_async_t` token for the thread, once it has a wake handle.
    token: Option<rn_uv::wake::ThreadToken>,
    /// Set by a foreign thread that queued work for this one.
    pending: Arc<AtomicBool>,
}

fn environments() -> &'static Mutex<HashMap<EnvId, Registration>> {
    static ENVS: OnceLock<Mutex<HashMap<EnvId, Registration>>> = OnceLock::new();
    ENVS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Registers this thread once, so a foreign environment can wake it later.
fn register_current_environment() -> EnvId {
    let env = env_id();
    let mut envs = environments()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = envs.entry(env).or_insert_with(|| Registration {
        token: None,
        pending: Arc::new(AtomicBool::new(false)),
    });
    // The wake handle is created by the realm's check-phase install, which runs
    // before user code, so this normally succeeds on the first request. Reading it
    // again covers a request queued from a host that installs later.
    if entry.token.is_none() {
        entry.token = rn_uv::wake::current_thread_token();
    }
    let pending = Arc::clone(&entry.pending);
    drop(envs);
    OWN_WAKE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(pending);
        }
    });
    env
}

/// Makes `env` run one [`process_env`] pass from its own loop.
fn wake_environment(env: EnvId) {
    let (pending, token) = {
        let envs = environments()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match envs.get(&env) {
            Some(registration) => (Arc::clone(&registration.pending), registration.token),
            // An environment that has gone away needs no wake: its cleanup
            // removed its requests, and its lock entries were dropped with it.
            None => return,
        }
    };
    // The flag is set before the signal so the hook cannot observe a wake with
    // nothing to do, which would cost an extra pass.
    pending.store(true, Ordering::SeqCst);
    if let Some(token) = token {
        let _ = token.notify();
    }
}

/// Drops everything this thread's environment owns.
///
/// Called from the worker teardown path, where Node runs
/// `LockManager::OnEnvironmentCleanup`: a worker that terminates while holding a
/// lock, or while queued behind one, must not leave either behind, because the
/// lock would never be released and every waiter would park forever.
pub fn cleanup_current_environment() {
    let env = ENV.with(Cell::get);
    if env == 0 {
        return;
    }
    let wake = manager()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .cleanup_env(env);
    environments()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&env);
    SLOTS.with(|slots| slots.borrow_mut().clear());
    OWN_WAKE.with(|slot| *slot.borrow_mut() = None);
    ENV.with(|cell| cell.set(0));
    // Anything queued behind this environment's locks can now make progress.
    for target in wake {
        wake_environment(target);
    }
}

fn manager() -> &'static Mutex<Manager> {
    static MANAGER: OnceLock<Mutex<Manager>> = OnceLock::new();
    MANAGER.get_or_init(|| Mutex::new(Manager::default()))
}

// ---------------------------------------------------------------------------
// The check-phase hook
// ---------------------------------------------------------------------------

/// Runs the deferred work another environment queued for this one.
///
/// This is `SetImmediateThreadsafe`'s body. It is a check-phase hook rather than
/// a call inside the wake callback because the wake closure belongs to
/// `rn-bind-worker` and is shared by every producer; the hook is additive for
/// exactly that reason.
fn on_check_phase(scope: &mut v8::PinScope<'_, '_>) {
    let env = ENV.with(Cell::get);
    if env == 0 {
        return;
    }
    if !take_pending_wake() {
        return;
    }
    process_env(scope, env);
}

/// Whether a wake for this thread is outstanding, so the check phase has work.
///
/// Node's equivalent is the fact that `SetImmediateThreadsafe` queues a native
/// immediate, which `Environment::CheckImmediate` always runs. Here the phase is
/// armed by this predicate instead, because a wake is a flag rather than a queued
/// callback.
fn has_pending_wake() -> bool {
    OWN_WAKE.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|pending| pending.load(Ordering::SeqCst))
    })
}

/// Takes this thread's outstanding wake, if there is one.
fn take_pending_wake() -> bool {
    OWN_WAKE.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|pending| pending.swap(false, Ordering::SeqCst))
    })
}

// ---------------------------------------------------------------------------
// `request`
// ---------------------------------------------------------------------------

/// `request(name, clientId, mode, steal, ifAvailable, callback)`.
///
/// Node `CHECK`s every argument, which from Rust can only become a `TypeError`.
/// `lib/internal/locks.js` has already converted the options dictionary, so a
/// wrong type here means a caller bypassed it.
fn request(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Ok(name) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        throw_type_error(scope, "locks.request name must be a string");
        return;
    };
    let Ok(client_id) = v8::Local::<v8::String>::try_from(args.get(1)) else {
        throw_type_error(scope, "locks.request clientId must be a string");
        return;
    };
    let Ok(mode) = v8::Local::<v8::String>::try_from(args.get(2)) else {
        throw_type_error(scope, "locks.request mode must be a string");
        return;
    };
    if !args.get(3).is_boolean() || !args.get(4).is_boolean() {
        throw_type_error(
            scope,
            "locks.request steal and ifAvailable must be booleans",
        );
        return;
    }
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(5)) else {
        throw_type_error(scope, "locks.request callback must be a function");
        return;
    };

    let Some(name) = read_utf16(scope, name) else {
        return;
    };
    let client_id = client_id.to_rust_string_lossy(scope);
    // Node: `mode.ToStringView() == "shared" ? Shared : Exclusive`, so anything
    // that is not exactly `shared` is exclusive.
    let mode = if mode.to_rust_string_lossy(scope) == LOCK_MODE_SHARED {
        Mode::Shared
    } else {
        Mode::Exclusive
    };
    let steal = args.get(3).boolean_value(scope);
    let if_available = args.get(4).boolean_value(scope);

    let (Some(waiting), Some(released)) = (
        v8::PromiseResolver::new(scope),
        v8::PromiseResolver::new(scope),
    ) else {
        throw_type_error(scope, "locks.request could not create its promises");
        return;
    };
    // Node marks both handled, so an internal half nobody awaits cannot report an
    // unhandled rejection.
    waiting.get_promise(scope).mark_as_handled();
    let released_promise = released.get_promise(scope);
    released_promise.mark_as_handled();

    let env = register_current_environment();
    // The hook is per thread and additive, so registering on each request is
    // idempotent by the timers crate's own rule.
    rn_bind_timers::add_check_phase_hook(on_check_phase);
    // `LockManager::Request` registers `OnEnvironmentCleanup` with
    // `env->AddCleanupHook` on the environment's first request, and only then.
    // Without it a worker that queues a request and is then terminated leaves the
    // request in the process-wide queue forever: every later request for that
    // resource blocks behind an environment that no longer exists. Measured
    // before this existed — `navigator.locks.request` after a terminated worker
    // never resolved, where the oracle granted it in 1 ms.
    rn_core::hook_slot::add_teardown_hook(cleanup_current_environment);
    // A woken environment's pass runs in the check phase, so the phase has to stay
    // armed while a wake is outstanding or the loop can decide it has nothing to do
    // before the pass runs.
    rn_bind_timers::add_check_phase_pending_predicate(has_pending_wake);

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

    SLOTS.with(|slots| {
        slots.borrow_mut().insert(
            id,
            Slot {
                waiting: v8::Global::new(scope.as_ref(), waiting),
                released: v8::Global::new(scope.as_ref(), released),
                callback: Some(v8::Global::new(scope.as_ref(), callback)),
            },
        );
    });

    manager()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .enqueue(Request {
            id,
            env,
            name,
            mode,
            client_id,
            steal,
            if_available,
        });

    process_env(scope, env);
    rv.set(released_promise.into());
}

// ---------------------------------------------------------------------------
// `query`
// ---------------------------------------------------------------------------

/// `query()`, resolved with `{ held, pending }` for this environment.
fn query(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        throw_type_error(scope, "locks.query could not create its promise");
        return;
    };
    // Node sets the return value before doing the work, so JavaScript always gets
    // a promise even if building the snapshot fails.
    let promise = resolver.get_promise(scope);
    rv.set(promise.into());

    let env = env_id();
    let (held, pending) = {
        let manager = manager()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (manager.held_by(env), manager.pending_by(env))
    };

    let held_array = v8::Array::new(scope, held.len() as i32);
    for (index, lock) in held.iter().enumerate() {
        let Some(info) = lock_info(scope, &lock.name, lock.mode, &lock.client_id) else {
            return;
        };
        held_array.set_index(scope, index as u32, info.into());
    }
    let pending_array = v8::Array::new(scope, pending.len() as i32);
    for (index, request) in pending.iter().enumerate() {
        let Some(info) = lock_info(scope, &request.name, request.mode, &request.client_id) else {
            return;
        };
        pending_array.set_index(scope, index as u32, info.into());
    }

    // `NewDictionaryInstance` over `{"held", "pending"}` gives plain data
    // properties in that order, which is what the oracle reports.
    let result = v8::Object::new(scope);
    if let Some(key) = v8::String::new(scope, "held") {
        result.set(scope, key.into(), held_array.into());
    }
    if let Some(key) = v8::String::new(scope, "pending") {
        result.set(scope, key.into(), pending_array.into());
    }
    resolver.resolve(scope, result.into());
}

/// The `{ name, mode, clientId }` shape `CreateLockInfoObject` builds.
fn lock_info<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &[u16],
    mode: Mode,
    client_id: &str,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    let name = v8::String::new_from_two_byte(scope, name, v8::NewStringType::Normal)?;
    let mode = v8::String::new(
        scope,
        match mode {
            Mode::Shared => LOCK_MODE_SHARED,
            Mode::Exclusive => LOCK_MODE_EXCLUSIVE,
        },
    )?;
    let client_id = v8::String::new(scope, client_id)?;
    for (key, value) in [
        ("name", name.into()),
        ("mode", mode.into()),
        ("clientId", client_id.into()),
    ] {
        let key = v8::String::new(scope, key)?;
        object.set(scope, key.into(), value);
    }
    Some(object)
}

// ---------------------------------------------------------------------------
// The queue pass
// ---------------------------------------------------------------------------

/// Runs `ProcessQueue` for `env` on this thread, until nothing can progress.
///
/// Node's `while (true)` loop, with the same shape: one grant or miss per pass,
/// and the loop continues after a grant so a released lock can immediately admit
/// the next request in the same turn.
fn process_env(scope: &mut v8::PinScope<'_, '_>, env: EnvId) {
    loop {
        let plan = manager()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .process(env);

        for target in &plan.wake {
            wake_environment(*target);
        }
        for id in &plan.reject {
            reject_stolen(scope, *id);
        }

        match plan.step {
            None => return,
            Some(Step::Miss(request)) => {
                handle_miss(scope, &request);
                return;
            }
            Some(Step::Grant(granted)) => {
                if !handle_grant(scope, &granted) {
                    return;
                }
            }
        }
    }
}

/// `ifAvailable` on a busy resource: run the callback with `null`.
///
/// Mirrors the first branch of `ProcessQueue`: a throwing callback rejects both
/// internal promises and stops the pass, a promise-returning one resolves
/// `waiting` with that promise and settles `released` when it settles, and
/// anything else settles both immediately.
fn handle_miss(scope: &mut v8::PinScope<'_, '_>, request: &Request) {
    let Some(callback) = take_callback(request.id) else {
        return;
    };
    let callback = v8::Local::new(scope, callback);
    let null = v8::null(scope).into();

    let caught = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let inner = &mut try_catch.init();
        let result = callback.call(inner, v8::undefined(inner).into(), &[null]);
        match result {
            Some(result) => Ok(result),
            None => Err(inner
                .exception()
                .unwrap_or_else(|| v8::undefined(inner).into())),
        }
    };

    let result = match caught {
        Ok(result) => result,
        Err(exception) => {
            reject_both(scope, request.id, exception);
            return;
        }
    };

    if let Ok(promise) = v8::Local::<v8::Promise>::try_from(result) {
        attach_if_available(scope, promise, request.id);
        resolve_waiting(scope, request.id, promise.into());
        return;
    }

    resolve_waiting(scope, request.id, result);
    settle_released(scope, request.id, result, false);
    remove_slot(request.id);
}

/// Attaches the handlers that settle a missed request's `released` promise.
fn attach_if_available(
    scope: &mut v8::PinScope<'_, '_>,
    promise: v8::Local<'_, v8::Promise>,
    id: u64,
) {
    let (Some(on_fulfilled), Some(on_rejected)) = (
        handler(scope, id, if_available_fulfilled),
        handler(scope, id, if_available_rejected),
    ) else {
        return;
    };
    promise.then2(scope, on_fulfilled, on_rejected);
}

/// `OnIfAvailableFulfill`: resolve `released` with the settled value.
fn if_available_fulfilled(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(id) = handler_id(&args) else {
        return;
    };
    settle_released(scope, id, args.get(0), false);
    remove_slot(id);
}

/// `OnIfAvailableReject`: reject `released` with the settled reason.
fn if_available_rejected(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(id) = handler_id(&args) else {
        return;
    };
    settle_released(scope, id, args.get(0), true);
    remove_slot(id);
}

/// A granted request: run the callback with the lock and wire the release.
///
/// Returns whether the pass should continue, which is Node's `return` on every
/// failure path in the grant branch.
fn handle_grant(scope: &mut v8::PinScope<'_, '_>, granted: &locks::Granted) -> bool {
    let request = &granted.request;
    let Some(callback) = take_callback(request.id) else {
        return true;
    };
    let callback = v8::Local::new(scope, callback);
    let Some(info) = lock_info(scope, &request.name, request.mode, &request.client_id) else {
        return false;
    };

    let caught = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let inner = &mut try_catch.init();
        let result = callback.call(inner, v8::undefined(inner).into(), &[info.into()]);
        match result {
            Some(result) => Ok(result),
            None => Err(inner
                .exception()
                .unwrap_or_else(|| v8::undefined(inner).into())),
        }
    };

    let result = match caught {
        Ok(result) => result,
        Err(exception) => {
            // Node rejects both promises and leaves the granted lock in
            // `held_locks_`, which the oracle reproduces: after a synchronous
            // throw the resource stays held. The slot is dropped so the rejection
            // is reported once; the lock entry deliberately is not.
            reject_both(scope, request.id, exception);
            return false;
        }
    };

    if let Ok(promise) = v8::Local::<v8::Promise>::try_from(result) {
        attach_release(scope, promise, request.id);
        // `waiting` resolves now with the callback's promise; `released` waits
        // for it to settle.
        resolve_waiting(scope, request.id, promise.into());
        return true;
    }

    resolve_waiting(scope, request.id, result);
    release(scope, request.id, result, false);
    true
}

/// Attaches the handlers that release a lock when the callback's promise settles.
fn attach_release(scope: &mut v8::PinScope<'_, '_>, promise: v8::Local<'_, v8::Promise>, id: u64) {
    let (Some(on_fulfilled), Some(on_rejected)) = (
        handler(scope, id, lock_fulfilled),
        handler(scope, id, lock_rejected),
    ) else {
        return;
    };
    if promise.then2(scope, on_fulfilled, on_rejected).is_none() {
        // Node reports a failure to attach as a rejection of both promises.
        if let Some(exception) = take_pending_exception(scope) {
            reject_both(scope, id, exception);
        }
    }
}

/// `OnLockCallbackFulfilled`: release the lock and settle `released`.
fn lock_fulfilled(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(id) = handler_id(&args) else {
        return;
    };
    let env = env_id();
    release(scope, id, args.get(0), false);
    process_env(scope, env);
}

/// `OnLockCallbackRejected`: release the lock and reject `released`.
fn lock_rejected(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(id) = handler_id(&args) else {
        return;
    };
    let env = env_id();
    release(scope, id, args.get(0), true);
    process_env(scope, env);
}

/// `ReleaseLockAndProcessQueue`'s settling half.
///
/// A stolen lock's `released` promise was already rejected, so settling it again
/// is skipped — `Lock::is_stolen` in Node, and here the flag survives in the
/// manager even though the held entry is gone.
fn release(
    scope: &mut v8::PinScope<'_, '_>,
    id: u64,
    value: v8::Local<'_, v8::Value>,
    rejected: bool,
) {
    let stolen = manager()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .release_and_report_stolen(id);
    if !stolen {
        settle_released(scope, id, value, rejected);
    }
    remove_slot(id);
}

/// Rejects a stolen lock's `released` promise with `LOCK_STOLEN`.
///
/// This is the deferred half of the theft: Node rejects inline because both
/// environments share an isolate, while here the rejection has to run on the
/// thread that owns the promise.
fn reject_stolen(scope: &mut v8::PinScope<'_, '_>, id: u64) {
    let Some(resolver) = slot_released(scope, id) else {
        return;
    };
    let Some(message) = v8::String::new(scope, LOCK_STOLEN_ERROR) else {
        return;
    };
    let error = v8::Exception::error(scope, message);
    // The slot stays: the user callback is still pending, and its release path
    // must not settle `released` a second time. The manager's stolen set is what
    // answers that question, so nothing has to be recorded here.
    resolver.reject(scope, error);
}

// ---------------------------------------------------------------------------
// Slot helpers
// ---------------------------------------------------------------------------

fn take_callback(id: u64) -> Option<v8::Global<v8::Function>> {
    SLOTS.with(|slots| slots.borrow_mut().get_mut(&id)?.callback.take())
}

fn remove_slot(id: u64) {
    SLOTS.with(|slots| slots.borrow_mut().remove(&id));
}

fn resolve_waiting(scope: &mut v8::PinScope<'_, '_>, id: u64, value: v8::Local<'_, v8::Value>) {
    let Some(resolver) = SLOTS.with(|slots| {
        slots
            .borrow()
            .get(&id)
            .map(|slot| v8::Local::new(scope, &slot.waiting))
    }) else {
        return;
    };
    resolver.resolve(scope, value);
}

fn settle_released(
    scope: &mut v8::PinScope<'_, '_>,
    id: u64,
    value: v8::Local<'_, v8::Value>,
    rejected: bool,
) {
    let Some(resolver) = slot_released(scope, id) else {
        return;
    };
    if rejected {
        resolver.reject(scope, value);
    } else {
        resolver.resolve(scope, value);
    }
}

fn slot_released<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    id: u64,
) -> Option<v8::Local<'s, v8::PromiseResolver>> {
    SLOTS.with(|slots| {
        slots
            .borrow()
            .get(&id)
            .map(|slot| v8::Local::new(scope, &slot.released))
    })
}

/// Rejects both internal promises with `reason` and drops the slot.
fn reject_both(scope: &mut v8::PinScope<'_, '_>, id: u64, reason: v8::Local<'_, v8::Value>) {
    let pair = SLOTS.with(|slots| {
        slots.borrow().get(&id).map(|slot| {
            (
                v8::Local::new(scope, &slot.waiting),
                v8::Local::new(scope, &slot.released),
            )
        })
    });
    if let Some((waiting, released)) = pair {
        waiting.reject(scope, reason);
        released.reject(scope, reason);
    }
    remove_slot(id);
}

/// Builds one of the internal settle handlers, carrying the request id as data.
fn handler<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    id: u64,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Option<v8::Local<'s, v8::Function>> {
    let data = v8::Number::new(scope, id as f64);
    // `length` 0 and not constructible, like every other internal callback V8
    // sees here; nothing in `lib/**` observes either.
    v8::Function::builder(callback)
        .data(data.into())
        .length(0)
        .build(scope)
}

/// The request id a handler was built with.
fn handler_id(args: &v8::FunctionCallbackArguments<'_>) -> Option<u64> {
    let number = v8::Local::<v8::Number>::try_from(args.data()).ok()?;
    let value = number.value();
    if value < 1.0 {
        return None;
    }
    // An id is a small positive integer by construction: it comes from
    // `AtomicU64::fetch_add` and is stored as an exact f64 for well under
    // 2^53 requests.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some(value as u64)
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

/// Reads a JavaScript string as UTF-16 code units, as `TwoByteValue` does.
///
/// A lossy UTF-8 conversion would map lone surrogates onto U+FFFD and make two
/// distinct names compare equal.
fn read_utf16(
    scope: &mut v8::PinScope<'_, '_>,
    string: v8::Local<'_, v8::String>,
) -> Option<Vec<u16>> {
    let length = string.length();
    let mut units = vec![0u16; length];
    string.write_v2(scope, 0, &mut units, v8::WriteFlags::empty());
    Some(units)
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

fn take_pending_exception<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Value>> {
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let inner = &mut try_catch.init();
    inner.exception()
}
