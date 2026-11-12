//! `internalBinding('async_wrap')` for rustnode.
//!
//! `lib/internal/async_hooks.js` implements the public `async_hooks` API on top
//! of this namespace: it keeps the hook callbacks, and the shared arrays here
//! hold the state both sides read and write on every async operation.
//!
//! # The three shared arrays
//!
//! | Name | Type | Meaning |
//! | --- | --- | --- |
//! | `async_hook_fields` | `Uint32Array(9)` | one count per hook kind, plus the stack length |
//! | `async_id_fields` | `Float64Array(4)` | execution id, trigger id, next id, default trigger id |
//! | `async_ids_stack` | `Float64Array(32)` | the execution-context stack, two slots per entry |
//!
//! The types are not incidental. Async ids are doubles, and `kInvalidAsyncId`
//! is `-1`, so an id array has to be a `Float64Array`; the hook counts are
//! `Uint32Array` because Node increments them from JavaScript on every hook.
//!
//! # `Providers`
//!
//! `Providers` maps every async resource kind to its numeric id. Those numbers
//! are the `ProviderType` enum in `src/async_wrap.h`, so they are generated from
//! that header rather than written by hand: a wrong id makes `async_hooks` label
//! every resource with the wrong name, which is silent and confusing.

use std::cell::RefCell;

use rn_core::{AliasedUint8Array, BindingModule, Element, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/async_wrap.json`.
pub const MEMBERS: &[&str] = &[
    "Providers",
    "async_hook_fields",
    "async_id_fields",
    "async_ids_stack",
    "clearAsyncIdStack",
    "constants",
    "executionAsyncResource",
    "execution_async_resources",
    "getPromiseHooks",
    "popAsyncContext",
    "pushAsyncContext",
    "queueDestroyAsyncId",
    "registerDestroyHook",
    "setCallbackTrampoline",
    "setPromiseHooks",
    "setupHooks",
];

/// Every provider and its id, from `NODE_ASYNC_PROVIDER_TYPES` in
/// `src/async_wrap.h`.
///
/// Generated from the pinned Node source and checked against the count in the
/// header, so an edit there without regenerating this is a test failure rather
/// than a silently wrong label.
pub const PROVIDERS: &[(&str, u32)] = &[
    ("NONE", 0),
    ("DIRHANDLE", 1),
    ("DNSCHANNEL", 2),
    ("ELDHISTOGRAM", 3),
    ("FILEHANDLE", 4),
    ("FILEHANDLECLOSEREQ", 5),
    ("BLOBREADER", 6),
    ("FSEVENTWRAP", 7),
    ("FSREQCALLBACK", 8),
    ("GLOBREQUEST", 9),
    ("FSREQPROMISE", 10),
    ("GETADDRINFOREQWRAP", 11),
    ("GETNAMEINFOREQWRAP", 12),
    ("HEAPSNAPSHOT", 13),
    ("HTTP2SESSION", 14),
    ("HTTP2STREAM", 15),
    ("HTTP2PING", 16),
    ("HTTP2SETTINGS", 17),
    ("HTTPINCOMINGMESSAGE", 18),
    ("HTTPCLIENTREQUEST", 19),
    ("LOCKS", 20),
    ("DTLS_ENDPOINT", 21),
    ("DTLS_SESSION", 22),
    ("JSSTREAM", 23),
    ("MESSAGEPORT", 24),
    ("PIPECONNECTWRAP", 25),
    ("PIPESERVERWRAP", 26),
    ("PIPEWRAP", 27),
    ("PROCESSWRAP", 28),
    ("PROMISE", 29),
    ("QUERYWRAP", 30),
    ("QUIC_ENDPOINT", 31),
    ("QUIC_LOGSTREAM", 32),
    ("QUIC_SESSION", 33),
    ("QUIC_STREAM", 34),
    ("QUIC_UDP", 35),
    ("SHUTDOWNWRAP", 36),
    ("SIGNALWRAP", 37),
    ("STATWATCHER", 38),
    ("STREAMPIPE", 39),
    ("TCPCONNECTWRAP", 40),
    ("TCPSERVERWRAP", 41),
    ("TCPWRAP", 42),
    ("TTYWRAP", 43),
    ("UDPSENDWRAP", 44),
    ("UDPWRAP", 45),
    ("SIGINTWATCHDOG", 46),
    ("WORKER", 47),
    ("WORKERCPUPROFILE", 48),
    ("WORKERCPUUSAGE", 49),
    ("WORKERHEAPPROFILE", 50),
    ("WORKERHEAPSNAPSHOT", 51),
    ("WORKERHEAPSTATISTICS", 52),
    ("WRITEWRAP", 53),
    ("ZLIB", 54),
    ("CHECKPRIMEREQUEST", 55),
    ("PBKDF2REQUEST", 56),
    ("KEYPAIRGENREQUEST", 57),
    ("KEYGENREQUEST", 58),
    ("KEYEXPORTREQUEST", 59),
    ("ARGON2REQUEST", 60),
    ("CIPHERREQUEST", 61),
    ("DERIVEBITSREQUEST", 62),
    ("HASHREQUEST", 63),
    ("RANDOMBYTESREQUEST", 64),
    ("RANDOMPRIMEREQUEST", 65),
    ("SCRYPTREQUEST", 66),
    ("SIGNREQUEST", 67),
    ("TLSWRAP", 68),
    ("VERIFYREQUEST", 69),
];

/// `AsyncHooks::Fields` in `src/env.h`: one count per hook kind.
pub const HOOK_FIELDS: &[(&str, usize)] = &[
    ("kInit", 0),
    ("kBefore", 1),
    ("kAfter", 2),
    ("kDestroy", 3),
    ("kPromiseResolve", 4),
    ("kTotals", 5),
    ("kCheck", 6),
    ("kStackLength", 7),
    ("kUsesExecutionAsyncResource", 8),
];

/// `AsyncHooks::kFieldsCount`.
pub const HOOK_FIELDS_COUNT: usize = 9;

/// `fields_[kCheck] = 1`: async_hooks consistency checks are on by default.
///
/// `src/env.cc:2015-2020` sets this because `--no-force-async-hooks-checks`
/// is what turns it off, not the absence of hooks. The field gates the
/// stack-corruption comparison in `pop_async_context`.
pub const CHECK_ENABLED: u32 = 1;

/// `AsyncHooks::UidFields` in `src/env.h`.
pub const UID_FIELDS: &[(&str, usize)] = &[
    ("kExecutionAsyncId", 0),
    ("kTriggerAsyncId", 1),
    ("kAsyncIdCounter", 2),
    ("kDefaultTriggerAsyncId", 3),
];

/// `AsyncHooks::kUidFieldsCount`.
pub const UID_FIELDS_COUNT: usize = 4;

/// `async_ids_stack_` is allocated as `16 * 2` in `src/env.cc`: sixteen nested
/// contexts, each an execution id and a trigger id.
pub const ASYNC_IDS_STACK_LENGTH: usize = 16 * 2;

/// `AsyncWrap::kInvalidAsyncId`.
pub const INVALID_ASYNC_ID: f64 = -1.0;

/// `AsyncWrap::get_provider_type()`, for a handle that may not be one.
///
/// Node's `GetProviderType` reports `PROVIDER_NONE` before it unwraps, so a
/// method call on a non-handle answers `0` rather than throwing. That is
/// observable, which is why this takes an `Option`.
pub fn provider_type_or_none(state: Option<&rn_core::AsyncWrapState>) -> u32 {
    state
        .map(rn_core::AsyncWrapState::provider)
        .unwrap_or(rn_core::async_wrap::PROVIDER_NONE)
}

/// `AsyncWrap::GetAsyncId`, for a handle that may not be one.
///
/// Node sets `kInvalidAsyncId` as the return value *before* unwrapping, so a
/// non-handle answers `-1` rather than throwing. `lib/net.js` checks
/// `typeof handle.getAsyncId === 'function'` and then trusts the answer, so a
/// wrong value here is a silently wrong socket id.
pub fn async_id_or_invalid(state: Option<&rn_core::AsyncWrapState>) -> f64 {
    state
        .map(rn_core::AsyncWrapState::async_id)
        .unwrap_or(INVALID_ASYNC_ID)
}

/// `AsyncWrap::AsyncReset`, the part that needs V8.
///
/// `resource` is what the `init` hook receives and `object` is the handle the id
/// belongs to; they differ on a reset, where `lib/internal/http/agent.js` passes
/// a `ReusedHandle` wrapper. Node only writes `resource_symbol` when they
/// differ.
///
/// The order is `AsyncWrap::AsyncReset`'s, step for step:
///
/// 1. `destroy` for the *previous* id, if there was one — queued, not called,
///    because `EmitDestroy` defers through the native immediate queue;
/// 2. a fresh id from the shared counter, unless the caller supplied one;
/// 3. the trigger id from `get_default_trigger_async_id`;
/// 4. `resource[resource_symbol] = resource`, so `emitInitNative`'s public
///    resource lookup finds the wrapper the caller handed over;
/// 5. `init` with `(asyncId, "PROVIDER", triggerAsyncId, resource)`.
///
/// The result is written back into `state`, so a `getAsyncId()` after this call
/// answers the new id.
pub fn async_reset(
    scope: &mut v8::PinScope<'_, '_>,
    state: &mut rn_core::AsyncWrapState,
    resource: v8::Local<v8::Object>,
    object: v8::Local<v8::Object>,
    execution_async_id: Option<f64>,
) {
    // `if (async_id_ != kInvalidAsyncId) EmitDestroy();` — the resource was in
    // use, so its old id needs a matching destroy before a new one is generated.
    // `EmitDestroy()` leaves `async_id_` invalid, which is what stops a second
    // reset emitting the same destroy twice.
    if state.async_id != INVALID_ASYNC_ID {
        emit_destroy(state.async_id);
        state.async_id = INVALID_ASYNC_ID;
    }

    // `async_id_ = execution_async_id == kInvalidAsyncId ? new_async_id()
    //             : execution_async_id`.
    state.async_id = match execution_async_id {
        Some(id) if id != INVALID_ASYNC_ID => id,
        _ => next_async_id(),
    };
    state.trigger_async_id = default_trigger_async_id();

    // `if (resource != obj) obj->Set(resource_symbol, resource)`. The *handle*
    // carries the resource, not the other way round: `emitInitNative` resolves
    // the public object for a hook by reading `resource[resource_symbol]`, so the
    // mapping has to be on the object the hook is given.
    //
    // The symbol has to be the one `internalBinding('symbols')` publishes, because
    // `lookupPublicResource` reads the same key; a symbol minted here would be a
    // different key and every lookup would silently miss.
    if !resource.strict_equals(object.into()) {
        if let Ok(key) = rn_bind_symbols::ensure(scope, "resource_symbol", "resource_symbol") {
            object.set(scope, key.into(), resource.into());
        }
    }

    emit_async_init(
        scope,
        resource,
        state.provider,
        state.async_id,
        state.trigger_async_id,
    );
}

/// `AsyncReset` for a handle whose `StreamState` this crate cannot name.
///
/// The frame capture in `AsyncReset` is `src/async_wrap.cc:635`'s
/// `set_context_frame(async_context_frame::current())`. A socket needs it for
/// `AsyncLocalStorage` to reach its callbacks, and only the binding that owns
/// the `StreamState` can store it — `rn-uv` owns the field, and the binding
/// already has the `&mut` borrow.
///
/// This is the same call as [`async_reset`] with the frame returned instead of
/// written, so the two cannot disagree about when the capture happens: it is
/// after the id is assigned, which is when Node captures it.
pub fn current_context_frame(scope: &mut v8::PinScope<'_, '_>) -> Option<v8::Global<v8::Value>> {
    let frame = scope.get_continuation_preserved_embedder_data();
    if frame.is_undefined() {
        None
    } else {
        Some(v8::Global::new(scope.as_ref(), frame))
    }
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static HOOKS: RefCell<Hooks> = const {
        RefCell::new(Hooks {
            init: None,
            before: None,
            after: None,
            destroy: None,
            promise_resolve: None,
            trampoline: None,
        })
    };
    /// The `execution_async_resources` array, which holds one resource object
    /// per stack entry that has a JavaScript-visible resource.
    static RESOURCES: RefCell<Option<v8::Global<v8::Array>>> = const { RefCell::new(None) };
    /// `Environment::destroy_async_id_list()`: ids whose `destroy` hook has not
    /// been called yet.
    ///
    /// Node keeps this on `Environment` and drains it from a ref'd native
    /// immediate, so the hook fires in the check phase after the resource went
    /// away rather than inline.
    static DESTROY_IDS: RefCell<Vec<f64>> = const { RefCell::new(Vec::new()) };
}

struct State {
    hook_fields: AliasedUint8Array,
    id_fields: AliasedUint8Array,
    ids_stack: AliasedUint8Array,
}

#[derive(Default)]
struct Hooks {
    init: Option<v8::Global<v8::Function>>,
    before: Option<v8::Global<v8::Function>>,
    after: Option<v8::Global<v8::Function>>,
    destroy: Option<v8::Global<v8::Function>>,
    promise_resolve: Option<v8::Global<v8::Function>>,
    trampoline: Option<v8::Global<v8::Function>>,
}

pub struct AsyncWrap;

impl BindingModule for AsyncWrap {
    fn namespace(&self) -> &'static str {
        "async_wrap"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let hook_fields = AliasedUint8Array::new(scope, HOOK_FIELDS_COUNT, Element::Word)?;
        let id_fields = AliasedUint8Array::new(scope, UID_FIELDS_COUNT, Element::Double)?;
        let ids_stack = AliasedUint8Array::new(scope, ASYNC_IDS_STACK_LENGTH, Element::Double)?;

        let hook_array = hook_fields.array(scope);
        let id_array = id_fields.array(scope);
        let stack_array = ids_stack.array(scope);

        // `AsyncHooks::AsyncHooks` calls `clear_async_id_stack()` before
        // anything else, and that is what seeds the buffers:
        //
        //     async_id_fields_[kExecutionAsyncId] = 0;
        //     async_id_fields_[kTriggerAsyncId] = 0;
        //     fields_[kStackLength] = 0;
        //
        // (`src/env.cc:232-237`). The counter starts at one and the default
        // trigger stays `-1`, which is the "no scope" sentinel that makes
        // `getDefaultTriggerAsyncId` fall back to the execution id.
        id_fields.set_float(UID_FIELDS[0].1, 0.0);
        id_fields.set_float(UID_FIELDS[1].1, 0.0);
        id_fields.set_float(UID_FIELDS[2].1, 1.0);
        id_fields.set_float(UID_FIELDS[3].1, INVALID_ASYNC_ID);
        // `fields_[kCheck] = 1` (`src/env.cc:2020`): async_hooks checks are
        // always on unless `--no-force-async-hooks-checks` is passed. The flag
        // is what enables the stack-corruption comparison in
        // `pop_async_context`, so leaving it at zero silently disables the
        // check that catches a mismatched push/pop pair.
        hook_fields.set(HOOK_FIELDS[6].1, CHECK_ENABLED);

        STATE.with(|state| {
            *state.borrow_mut() = Some(State {
                hook_fields,
                id_fields,
                ids_stack,
            })
        });

        let resources = v8::Array::new(scope, 0);
        RESOURCES.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, resources)));

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 16] = [
            ("Providers", providers_object(scope)),
            ("constants", constants_object(scope)),
            ("async_hook_fields", hook_array),
            ("async_id_fields", id_array),
            ("async_ids_stack", stack_array),
            ("execution_async_resources", resources.into()),
            (
                "executionAsyncResource",
                function(scope, "executionAsyncResource", execution_async_resource)?,
            ),
            ("setupHooks", function(scope, "setupHooks", setup_hooks)?),
            (
                "pushAsyncContext",
                function(scope, "pushAsyncContext", push_async_context)?,
            ),
            (
                "popAsyncContext",
                function(scope, "popAsyncContext", pop_async_context)?,
            ),
            (
                "clearAsyncIdStack",
                function(scope, "clearAsyncIdStack", clear_async_id_stack)?,
            ),
            (
                "queueDestroyAsyncId",
                function(scope, "queueDestroyAsyncId", queue_destroy_async_id)?,
            ),
            (
                "registerDestroyHook",
                function(scope, "registerDestroyHook", register_destroy_hook)?,
            ),
            (
                "setCallbackTrampoline",
                function(scope, "setCallbackTrampoline", set_callback_trampoline)?,
            ),
            (
                "setPromiseHooks",
                function(scope, "setPromiseHooks", set_promise_hooks)?,
            ),
            (
                "getPromiseHooks",
                function(scope, "getPromiseHooks", get_promise_hooks)?,
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        // The scope every native callback needs. Registered here because this is
        // where the shared arrays exist and where `async_context_frame` has been
        // installed; `rn-uv` asks `rn-core` for a scope and never learns that
        // this crate answers.
        register_callback_scope();
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(AsyncWrap);
}

fn providers_object<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let object = v8::Object::new(scope);
    for (name, id) in PROVIDERS {
        if let Some(key) = v8::String::new(scope, name) {
            object.set(
                scope,
                key.into(),
                v8::Integer::new_from_unsigned(scope, *id).into(),
            );
        }
    }
    object.into()
}

fn constants_object<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let object = v8::Object::new(scope);
    let mut values: Vec<(&str, usize)> = HOOK_FIELDS.to_vec();
    values.extend_from_slice(UID_FIELDS);
    for (name, value) in values {
        if let Some(key) = v8::String::new(scope, name) {
            object.set(
                scope,
                key.into(),
                v8::Integer::new(scope, value as i32).into(),
            );
        }
    }
    object.into()
}

/// The execution async id, from the shared `async_id_fields` array.
///
/// `lib/internal/async_hooks.js` writes this slot from JavaScript on every
/// resource transition; the runtime reads it back when it needs to know what is
/// currently executing.
pub fn execution_async_id() -> f64 {
    STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.id_fields.get_float(UID_FIELDS[0].1))
            .unwrap_or(INVALID_ASYNC_ID)
    })
}

/// The trigger async id, from the shared `async_id_fields` array.
pub fn trigger_async_id() -> f64 {
    STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.id_fields.get_float(UID_FIELDS[1].1))
            .unwrap_or(INVALID_ASYNC_ID)
    })
}

/// Hands out the next async id and advances the shared counter.
///
/// The counter lives in `async_id_fields[kAsyncIdCounter]` because JavaScript
/// also advances it when it creates a resource itself, so both sides have to
/// draw from one sequence.
pub fn next_async_id() -> f64 {
    STATE.with(|state| {
        let state = state.borrow();
        let Some(state) = state.as_ref() else {
            return INVALID_ASYNC_ID;
        };
        // `Environment::new_async_id` is a *pre*-increment:
        //
        //     async_id_fields()[kAsyncIdCounter] += 1;
        //     return async_id_fields()[kAsyncIdCounter];
        //
        // (`src/env-inl.h:433-436`), and `newAsyncId` in
        // `lib/internal/async_hooks.js` is `++async_id_fields[kAsyncIdCounter]`
        // for the same reason. Returning the counter *before* advancing it
        // handed out an id that the JavaScript side then reused for its own
        // resource, which is how two different resources ended up sharing one
        // id.
        let counter = state.id_fields.get_float(UID_FIELDS[2].1).unwrap_or(1.0) + 1.0;
        state.id_fields.set_float(UID_FIELDS[2].1, counter);
        counter
    })
}

/// The default trigger async id, as `Environment::get_default_trigger_async_id`
/// computes it.
///
/// `kDefaultTriggerAsyncId` is written by `defaultTriggerAsyncIdScope` and is
/// `-1` outside one; a negative value means "use the execution async id", which
/// is the id of whatever is currently running.
pub fn default_trigger_async_id() -> f64 {
    let default_trigger = STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.id_fields.get_float(UID_FIELDS[3].1))
            .unwrap_or(INVALID_ASYNC_ID)
    });
    if default_trigger < 0.0 {
        return execution_async_id();
    }
    default_trigger
}

/// Establishes the top-level execution context, Node's `{ 1, 0 }` scope.
///
/// Node runs the entry point inside
///
/// ```c
/// // src/node.cc:287-293
/// InternalCallbackScope callback_scope(
///     env, Object::New(env->isolate()), { 1, 0 },
///     InternalCallbackScope::kSkipAsyncHooks);
/// ```
///
/// whose constructor calls `push_async_context(1, 0, object)`
/// (`src/api/callback.cc:124-126`). `kSkipAsyncHooks` suppresses the `before`
/// hook, but the push still happens, so the id every top-level resource
/// inherits as its trigger is **1**, and `executionAsyncId()` answers 1 for the
/// whole script body.
///
/// rustnode never ran that scope, so the buffers kept the values
/// `clear_async_id_stack` seeds — execution `0` and, before that function was
/// corrected, `-1`. Every resource created at top level therefore reported
/// `triggerAsyncId()` as `-1`, which is what
/// `test-async-hooks-promise.js` and its two siblings assert against.
///
/// `kSkipAsyncHooks` is why this does not emit a `before` hook: the scope is
/// opened before any hook could be registered.
pub fn push_top_level_context(scope: &mut v8::PinScope<'_, '_>) {
    // `InternalCallbackScope` is constructed with `Object::New(isolate)` as the
    // scope's resource and hands it to `push_async_context`, which stores it in
    // `native_execution_async_resources_[0]`. `executionAsyncResource()` then
    // answers that object for the whole script body — it is what makes the
    // top-level call in `test-async-hooks-execution-async-resource.js` truthy.
    //
    // The JS `executionAsyncResource()` reads `execution_async_resources[index]`
    // first and only falls back to the native accessor, so putting the object
    // in the shared array covers both readers.
    let resource = v8::Object::new(scope);
    RESOURCES.with(|slot| {
        if let Some(resources) = slot.borrow().as_ref() {
            let resources = v8::Local::new(scope, resources);
            resources.set_index(scope, 0, resource.into());
        }
    });
    STATE.with(|state| {
        let state = state.borrow();
        let Some(state) = state.as_ref() else {
            return;
        };
        let offset = state.hook_fields.get(HOOK_FIELDS[7].1).unwrap_or(0) as usize;
        if offset * 2 >= ASYNC_IDS_STACK_LENGTH {
            return;
        }
        let previous_execution = state.id_fields.get_float(UID_FIELDS[0].1).unwrap_or(0.0);
        let previous_trigger = state.id_fields.get_float(UID_FIELDS[1].1).unwrap_or(0.0);
        state.ids_stack.set_float(offset * 2, previous_execution);
        state.ids_stack.set_float(offset * 2 + 1, previous_trigger);
        state.hook_fields.set(HOOK_FIELDS[7].1, (offset + 1) as u32);
        state.id_fields.set_float(UID_FIELDS[0].1, 1.0);
        state.id_fields.set_float(UID_FIELDS[1].1, 0.0);
    });
}

/// `AsyncHooks::provider_string`: the name `init` receives for a provider id.
///
/// Node keeps one internalized string per provider in `IsolateData` and indexes
/// it by the enum value. The table here is the same one `Providers` publishes, so
/// an id and its name cannot disagree.
pub fn provider_name(provider: u32) -> Option<&'static str> {
    PROVIDERS
        .iter()
        .find(|(_, id)| *id == provider)
        .map(|(name, _)| *name)
}

/// The `AsyncWrap` implementation of [`rn_core::callback_scope`].
///
/// Every method below is a fragment of `src/api/callback.cc`, cited at the
/// method. It is registered by [`AsyncWrap::install`], so a stream read or a
/// write completion that runs through `rn_uv` gets the same treatment a timer
/// callback already does.
struct ScopeHooks;

impl rn_core::callback_scope::CallbackScopeHooks for ScopeHooks {
    fn open(
        &self,
        scope: &mut v8::PinScope<'_, '_>,
        args: &rn_core::callback_scope::ScopeArgs,
    ) -> Option<v8::Global<v8::Value>> {
        // `async_context_frame::exchange(env, context_frame)`
        // (`src/api/callback.cc:117`). **First**, before the context is pushed
        // and before `before` fires: the constructor exchanges the frame at
        // `:117`, pushes at `:124` and emits `before` at `:127`. Order matters
        // because a `before` hook that reads `getStore()` sees the callback's own
        // frame — hooking it up after the push but before the exchange would have
        // the hook observe the caller's.
        let prior = exchange_frame(scope, args.frame.as_ref());

        // `async_hooks()->push_async_context(async_id, trigger_async_id, object)`
        // (`src/api/callback.cc:124`). This is what makes `executionAsyncId()`
        // inside the callback answer the resource's id, and it happens whether
        // or not any hook is enabled: the id stack is state JavaScript reads
        // directly.
        push_context(scope, args.context, args.resource.as_ref());

        // `AsyncWrap::EmitBefore` (`src/api/callback.cc:127`), guarded by the
        // same `async_id != 0 && !skip_hooks_`.
        if args.context.is_resource() {
            emit_hook(scope, HOOK_FIELDS[1].1, args.context.async_id);
        }

        prior
    }

    fn close(
        &self,
        scope: &mut v8::PinScope<'_, '_>,
        args: &rn_core::callback_scope::ScopeArgs,
        prior_frame: Option<v8::Global<v8::Value>>,
        threw: bool,
    ) {
        // `if (!failed_ && async_context_.async_id != 0 && !skip_hooks_)
        //      AsyncWrap::EmitAfter(...)` (`src/api/callback.cc:154`). Node
        // skips `after` for a callback that threw, and the `after` the user
        // sees is emitted from the fatal-exception path instead.
        if !threw && args.context.is_resource() {
            emit_hook(scope, HOOK_FIELDS[2].1, args.context.async_id);
        }

        // `env_->async_hooks()->pop_async_context(async_context_.async_id)`
        // (`src/api/callback.cc:159`). Unconditional, exactly as Node's is: a
        // throw must not leave the id stack deeper for the rest of the process.
        pop_context(scope, args.context.async_id);

        // `async_context_frame::set(env_, prior_context_frame_.Get(isolate))`
        // (`src/api/callback.cc:161`). The other direction of the exchange, and
        // it is what stops a store written inside the callback from leaking out
        // to the next thing that runs. Also unconditional.
        restore_frame(scope, prior_frame);
    }

    fn report_uncaught(&self, scope: &mut v8::PinScope<'_, '_>, error: v8::Local<v8::Value>) {
        // `TriggerUncaughtException` hands the error to `process._fatalException`
        // first and only prints when that declines. `rn_errors` is the one
        // implementation of that order in the runtime: the event loop, the timers
        // and the thread-safe functions all use it, and a second copy here would
        // be free to drift.
        rn_errors::report_uncaught_exception(scope, error);
    }
}

/// Pushes an async context onto the shared stack.
///
/// `AsyncHooks::push_async_context` (`src/env.cc:133`) stores the *outgoing*
/// pair so the matching pop restores it, then installs the incoming one.
fn push_context(
    scope: &mut v8::PinScope<'_, '_>,
    context: rn_core::callback_scope::AsyncContext,
    resource: Option<&v8::Global<v8::Object>>,
) {
    if !context.is_resource() {
        return;
    }
    // `execution_async_resources[offset] = resource`. Only the JS-visible
    // resource goes in this array; `executionAsyncResource()` reads it by index,
    // so an entry that is missing reads as `undefined` rather than as the wrong
    // resource.
    let offset = STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.hook_fields.get(HOOK_FIELDS[7].1))
            .unwrap_or(0) as usize
    });
    if let Some(resource) = resource {
        let local = v8::Local::new(scope, resource);
        RESOURCES.with(|slot| {
            if let Some(resources) = slot.borrow().as_ref() {
                let resources = v8::Local::new(scope, resources);
                resources.set_index(scope, offset as u32, local.into());
            }
        });
    }
    STATE.with(|state| {
        let state = state.borrow();
        let Some(state) = state.as_ref() else {
            return;
        };
        let offset = state.hook_fields.get(HOOK_FIELDS[7].1).unwrap_or(0) as usize;
        if offset * 2 >= ASYNC_IDS_STACK_LENGTH {
            return;
        }
        let previous_execution = state
            .id_fields
            .get_float(UID_FIELDS[0].1)
            .unwrap_or(INVALID_ASYNC_ID);
        let previous_trigger = state
            .id_fields
            .get_float(UID_FIELDS[1].1)
            .unwrap_or(INVALID_ASYNC_ID);
        state.ids_stack.set_float(offset * 2, previous_execution);
        state.ids_stack.set_float(offset * 2 + 1, previous_trigger);
        state.hook_fields.set(HOOK_FIELDS[7].1, (offset + 1) as u32);
        state.id_fields.set_float(UID_FIELDS[0].1, context.async_id);
        state
            .id_fields
            .set_float(UID_FIELDS[1].1, context.trigger_async_id);
    });
}

/// Pops the innermost async context, restoring the pair it saved.
///
/// `AsyncHooks::pop_async_context` (`src/env.cc:173`). Tolerant of an empty
/// stack for the reason Node's comment gives: a fatal exception may already have
/// cleared it.
fn pop_context(scope: &mut v8::PinScope<'_, '_>, expected: f64) {
    if expected <= 0.0 {
        return;
    }
    STATE.with(|state| {
        let state = state.borrow();
        let Some(state) = state.as_ref() else {
            return;
        };
        let depth = state.hook_fields.get(HOOK_FIELDS[7].1).unwrap_or(0) as usize;
        if depth == 0 {
            return;
        }
        let offset = depth - 1;
        // `async_id_fields_[kExecutionAsyncId] = async_ids_stack_[2 * offset]`.
        // The restore is the point of the pop: without it the next callback to
        // run would inherit this one's id.
        let saved_execution = state
            .ids_stack
            .get_float(offset * 2)
            .unwrap_or(INVALID_ASYNC_ID);
        let saved_trigger = state
            .ids_stack
            .get_float(offset * 2 + 1)
            .unwrap_or(INVALID_ASYNC_ID);
        state.id_fields.set_float(UID_FIELDS[0].1, saved_execution);
        state.id_fields.set_float(UID_FIELDS[1].1, saved_trigger);
        state.hook_fields.set(HOOK_FIELDS[7].1, offset as u32);
    });
    // `js_execution_async_resources()->Set(length, offset)` — the JS array's
    // `length` is the shadow of the stack depth, and `executionAsyncResource()`
    // reads `execution_async_resources[index]` directly, so the stale entry has
    // to go for the same reason.
    RESOURCES.with(|slot| {
        if let Some(resources) = slot.borrow().as_ref() {
            let resources = v8::Local::new(scope, resources);
            let length = STATE.with(|state| {
                state
                    .borrow()
                    .as_ref()
                    .and_then(|state| state.hook_fields.get(HOOK_FIELDS[7].1))
                    .unwrap_or(0)
            });
            if let Some(key) = v8::String::new(scope, "length") {
                resources.set(
                    scope,
                    key.into(),
                    v8::Integer::new_from_unsigned(scope, length).into(),
                );
            }
        }
    });
}

/// Calls one `async_hooks` listener kind with `async_id`.
///
/// `AsyncWrap::Emit` (`src/async_wrap.cc`): the counter in `async_hook_fields` is
/// what says whether anybody is listening, so a disabled hook costs one array
/// read. A hook that throws is fatal in Node (`emitHook`'s `catch` calls
/// `fatalError`), which `fatal_hook_error` reproduces.
fn emit_hook(scope: &mut v8::PinScope<'_, '_>, field: usize, async_id: f64) {
    let enabled = STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.hook_fields.get(field))
            .unwrap_or(0)
    });
    if enabled == 0 {
        return;
    }
    let hook = HOOKS.with(|hooks| {
        let hooks = hooks.borrow();
        let hook = if field == HOOK_FIELDS[1].1 {
            hooks.before.as_ref()
        } else {
            hooks.after.as_ref()
        };
        hook.map(|hook| v8::Local::new(scope, hook))
    });
    let Some(hook) = hook else {
        return;
    };
    let argument: v8::Local<v8::Value> = v8::Number::new(scope, async_id).into();
    let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
    let scope = &mut try_catch.init();
    let _ = hook.call(scope, v8::undefined(scope).into(), &[argument]);
    if let Some(exception) = scope.exception() {
        // `fatalError(e)` in `lib/internal/async_hooks.js`: the JS `emitHook`
        // catches a throwing hook and rethrows it, so the exception escapes
        // `AsyncWrap::Emit` into `MakeCallback` and becomes the callback's own.
        // Reporting it through the shared path is the closest honest equivalent,
        // and it keeps the exception from being left pending on the isolate.
        rn_errors::report_uncaught_exception(scope, exception);
    }
}

/// Installs `frame` and returns the one it replaced, rooted.
///
/// `async_context_frame::exchange` (`src/async_context_frame.cc:41`) skips the
/// set when the frame is unchanged, which is the common case and avoids a V8
/// call per callback.
fn exchange_frame(
    scope: &mut v8::PinScope<'_, '_>,
    frame: Option<&v8::Global<v8::Value>>,
) -> Option<v8::Global<v8::Value>> {
    let prior = scope.get_continuation_preserved_embedder_data();
    let wanted: v8::Local<v8::Value> = match frame {
        Some(frame) => v8::Local::new(scope, frame),
        // An absent frame is `undefined`: `AsyncContextFrame.current()` answers
        // `undefined` outside any `run()`, and that is what `getStore()` turns
        // into the storage's default value.
        None => v8::undefined(scope).into(),
    };
    if prior != wanted {
        scope.set_continuation_preserved_embedder_data(wanted);
    }
    // `undefined` needs no root: it is not a value that can be collected, and
    // keeping a `Global` for it would be a slot to free for no reason.
    if prior.is_undefined() {
        None
    } else {
        Some(v8::Global::new(scope.as_ref(), prior))
    }
}

/// Puts `prior` back, the exit half of the exchange.
fn restore_frame(scope: &mut v8::PinScope<'_, '_>, prior: Option<v8::Global<v8::Value>>) {
    let value: v8::Local<v8::Value> = match prior {
        Some(prior) => v8::Local::new(scope, &prior),
        None => v8::undefined(scope).into(),
    };
    scope.set_continuation_preserved_embedder_data(value);
}

/// Registers the scope implementation with the kernel.
///
/// Called from [`AsyncWrap::install`], which is the point where the shared
/// arrays and the frame binding both exist. Registering here rather than from
/// the CLI is what keeps the dependency pointing one way: `rn-uv` asks
/// `rn-core` for a scope and never learns that `async_wrap` exists.
pub fn register_callback_scope() {
    rn_core::callback_scope::set_hooks(std::rc::Rc::new(ScopeHooks));
}

/// `AsyncWrap::EmitAsyncInit`.
///
/// Calls the `init` hook with `(asyncId, type, triggerAsyncId, resource)`. The
/// two early returns are Node's: the hook is skipped when no `init` hook is
/// registered, and the type is looked up from the provider id rather than passed
/// in, so a wrong provider shows up as the wrong label rather than a panic.
///
/// `resource` is what the caller hands over, *not* the handle itself: for a
/// reset, `lib/internal/http/agent.js` passes a `ReusedHandle` wrapper and
/// `init` is expected to see that wrapper. `emitInitNative` then resolves
/// `resource[resource_symbol]` for the public object, which is why the wrapper
/// is what has to be passed through unchanged.
pub fn emit_async_init(
    scope: &mut v8::PinScope<'_, '_>,
    resource: v8::Local<v8::Object>,
    provider: u32,
    async_id: f64,
    trigger_async_id: f64,
) {
    // `if (async_hooks->fields()[AsyncHooks::kInit] == 0) return;`. The count is
    // maintained by `lib/internal/async_hooks.js` as hooks are enabled, so this
    // is the same short circuit Node takes on the hot path.
    let enabled = STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.hook_fields.get(HOOK_FIELDS[0].1))
            .unwrap_or(0)
    });
    if enabled == 0 {
        return;
    }
    let Some(name) = provider_name(provider) else {
        // An id outside `Providers` is a programming error, and Node's
        // `provider_string` would index out of bounds. Reporting nothing is the
        // only safe answer here.
        tracing_error_unknown_provider(provider);
        return;
    };
    let Some(init) = HOOKS.with(|hooks| {
        hooks
            .borrow()
            .init
            .as_ref()
            .map(|hook| v8::Local::new(scope, hook))
    }) else {
        return;
    };
    let Some(kind) = v8::String::new(scope, name) else {
        return;
    };
    let arguments = [
        v8::Number::new(scope, async_id).into(),
        kind.into(),
        v8::Number::new(scope, trigger_async_id).into(),
        resource.into(),
    ];
    // `init_fn->Call(env->context(), object, arraysize(argv), argv)`: the
    // resource is the receiver, which is observable through `this` inside the
    // hook.
    let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
    let scope = &mut try_catch.init();
    let _ = init.call(scope, resource.into(), &arguments);
    // Node installs a fatal-rethrow `TryCatchScope` here; the exception travels
    // on to the embedder's own uncaught path either way, so the throw is left
    // pending rather than swallowed.
    let _ = scope.has_caught();
}

/// Reports a provider id that is not in the table.
///
/// Only reachable through a wrong constant on the Rust side, and it must not
/// take the process down: a handle that cannot name its provider still has a
/// working async id.
fn tracing_error_unknown_provider(provider: u32) {
    tracing::error!(provider, "async_wrap: no provider name for this id");
}

/// `AsyncWrap::EmitDestroy(Environment*, double)`.
///
/// Queues the id for the `destroy` hook and asks the loop for a check phase. The
/// hook is *not* called here: Node defers it through `destroy_async_id_list` and
/// `Environment::SetImmediate`, which is why a `destroy` is observable one check
/// phase after the resource is gone rather than inline.
pub fn emit_destroy(async_id: f64) {
    // `if (fields()[kDestroy] == 0 || !can_call_into_js()) return;`. Queuing an
    // id nobody will read would keep the loop awake for nothing.
    let enabled = STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.hook_fields.get(HOOK_FIELDS[3].1))
            .unwrap_or(0)
    });
    if enabled == 0 {
        return;
    }
    DESTROY_IDS.with(|ids| ids.borrow_mut().push(async_id));
    rn_core::native_immediates::set_immediate(drain_destroy_ids);
}

/// `DestroyAsyncIdsCallback`: calls the `destroy` hook once per queued id.
///
/// Node swaps the list out before iterating so an id queued by a `destroy`
/// handler lands in the list the next pass drains, and keeps looping while the
/// list is non-empty. That matters here because a `destroy` handler that drops
/// the last reference to another resource queues its destroy from inside this
/// callback.
fn drain_destroy_ids(scope: &mut v8::PinScope<'_, '_>) {
    loop {
        let batch = DESTROY_IDS.with(|ids| std::mem::take(&mut *ids.borrow_mut()));
        if batch.is_empty() {
            return;
        }
        for async_id in batch {
            let Some(destroy) = HOOKS.with(|hooks| {
                hooks
                    .borrow()
                    .destroy
                    .as_ref()
                    .map(|hook| v8::Local::new(scope, hook))
            }) else {
                return;
            };
            let argument: v8::Local<v8::Value> = v8::Number::new(scope, async_id).into();
            let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
            let scope = &mut try_catch.init();
            let _ = destroy.call(scope, v8::undefined(scope).into(), &[argument]);
            if scope.has_caught() {
                return;
            }
        }
    }
}

/// The current depth of the async id stack.
pub fn stack_length() -> u32 {
    STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.hook_fields.get(HOOK_FIELDS[7].1))
            .unwrap_or(0)
    })
}

/// Pushes an async context around a native callback, as Node's
/// `AsyncHooks::push_async_context` does for `PromiseRejectCallback`.
///
/// `src/node_task_queue.cc` pushes the promise's `async_id_symbol` and
/// `trigger_async_id_symbol` before it calls the JavaScript handler and pops
/// after, so `executionAsyncId()` inside `promiseRejectHandler` answers the
/// promise's id rather than whatever the last callback left behind. The push is
/// skipped when either id is missing — `AsyncWrap::kInvalidAsyncId` — which is
/// the case for a promise created outside any async context (`vm` realms and
/// the bootstrap).
///
/// The resource is stored so `executionAsyncResource()` inside the handler
/// answers the promise itself, which is the same `Local`-in-the-array
/// arrangement [`push_context`] uses for every other callback.
pub fn push_promise_context(
    scope: &mut v8::PinScope<'_, '_>,
    async_id: f64,
    trigger_async_id: f64,
    promise: Option<v8::Local<'_, v8::Object>>,
) {
    let resource = promise.map(|promise| v8::Global::new(scope, promise));
    push_context(
        scope,
        rn_core::callback_scope::AsyncContext {
            async_id,
            trigger_async_id,
        },
        resource.as_ref(),
    );
}

/// Pops the context [`push_promise_context`] pushed.
pub fn pop_promise_context(scope: &mut v8::PinScope<'_, '_>, async_id: f64) {
    pop_context(scope, async_id);
}

/// Whether either id is `kInvalidAsyncId`, in which case no context is pushed.
pub fn promise_context_is_pushable(async_id: f64, trigger_async_id: f64) -> bool {
    async_id != INVALID_ASYNC_ID && trigger_async_id != INVALID_ASYNC_ID
}

fn execution_async_resource(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // The top of the stack is the currently executing resource. Node returns
    // the resource it stored for that entry, or `undefined` when there is none,
    // which is the state before any async operation starts.
    let index = STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .and_then(|state| state.hook_fields.get(7))
            .unwrap_or(0) as usize
    });
    let resource = RESOURCES.with(|slot| {
        let resources = slot.borrow();
        let resources = resources.as_ref()?;
        let resources = v8::Local::new(scope, resources);
        if index == 0 {
            return None;
        }
        resources.get_index(scope, index as u32 - 1)
    });
    match resource {
        Some(resource) => rv.set(resource),
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn setup_hooks(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `SetupHooks` takes a *single object* whose properties are named
    // `init`/`before`/`after`/`destroy`/`promise_resolve`, not five positional
    // arguments:
    //
    //     CHECK(args[0]->IsObject());
    //     SET_HOOK_FN(init); SET_HOOK_FN(before); ...
    //
    // `internal/bootstrap/node.js` passes `nativeHooks` straight from
    // `internal/async_hooks`, which is exactly that object. Reading positional
    // arguments instead left every slot `null`, so `EmitAsyncInit` and
    // `EmitDestroy` found no function to call and the hooks were emitted into
    // nothing — while `async_hook_fields` still counted them, which is why the
    // gap was invisible from JavaScript.
    let Ok(hooks) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        // `CHECK(args[0]->IsObject())`.
        throw_type_error(scope, "setupHooks expects an object of hook functions");
        return;
    };
    let capture = |name: &str| -> Option<v8::Global<v8::Function>> {
        let key = v8::String::new(scope, name)?;
        let value = hooks.get(scope, key.into())?;
        let function = v8::Local::<v8::Function>::try_from(value).ok()?;
        Some(v8::Global::new(scope, function))
    };
    let init = capture("init");
    let before = capture("before");
    let after = capture("after");
    let destroy = capture("destroy");
    let promise_resolve = capture("promise_resolve");
    // `CHECK(env->async_hooks_init_function().IsEmpty())`: Node asserts this is
    // called once. A second call is a programming error rather than a state
    // transition, so it throws instead of silently replacing a live table.
    let already_installed = HOOKS.with(|hooks| hooks.borrow().init.is_some());
    if already_installed && init.is_some() {
        throw_type_error(scope, "setupHooks has already been called");
        return;
    }
    HOOKS.with(|hooks| {
        let mut hooks = hooks.borrow_mut();
        if init.is_some() {
            hooks.init = init;
        }
        if before.is_some() {
            hooks.before = before;
        }
        if after.is_some() {
            hooks.after = after;
        }
        if destroy.is_some() {
            hooks.destroy = destroy;
        }
        if promise_resolve.is_some() {
            hooks.promise_resolve = promise_resolve;
        }
    });
}

/// `AsyncWrap::PushAsyncContext`, the native half of the stack growth path.
///
/// `lib/internal/async_hooks.js` writes the pair inline while the array has
/// room and only calls this when it does not:
///
/// ```js
/// function pushAsyncContext(asyncId, triggerAsyncId, resource) {
///   const offset = async_hook_fields[kStackLength];
///   execution_async_resources[offset] = resource;
///   if (offset * 2 >= async_wrap.async_ids_stack.length)
///     return pushAsyncContext_(asyncId, triggerAsyncId);
///   async_wrap.async_ids_stack[offset * 2] = async_id_fields[kExecutionAsyncId];
///   async_wrap.async_ids_stack[offset * 2 + 1] = async_id_fields[kTriggerAsyncId];
///   async_hook_fields[kStackLength]++;
///   async_id_fields[kExecutionAsyncId] = asyncId;
///   async_id_fields[kTriggerAsyncId] = triggerAsyncId;
/// }
/// ```
///
/// So this reads **args 0 and 1** (the new ids), and writes the *saved* pair —
/// the currently executing ids — into the stack before installing the new ones.
/// The two details that were wrong here:
///
/// * it read args 1 and 2, which are `triggerAsyncId` and `undefined`;
/// * it stored the incoming pair instead of the previous one, so a pop restored
///   the ids that had just been pushed rather than the ones they replaced.
fn push_async_context(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `double async_id = args[0]->NumberValue(...)`; Node does not check the
    // type because the `CHECK_GE` below catches a non-number.
    let async_id = args.get(0).number_value(scope).unwrap_or(INVALID_ASYNC_ID);
    let trigger_id = args.get(1).number_value(scope).unwrap_or(INVALID_ASYNC_ID);
    let grown = STATE.with(|state| {
        let mut state = state.borrow_mut();
        let state = state.as_mut()?;
        let offset = state.hook_fields.get(HOOK_FIELDS[7].1).unwrap_or(0) as usize;
        // `if (offset * 2 >= async_ids_stack_.Length()) grow_async_ids_stack();`
        // `grow_async_ids_stack` is `reserve(Length() * 3)`, so a nested context
        // 1000 frames deep costs two growths rather than one per frame.
        let elements = state.ids_stack.len() / 8;
        if offset * 2 >= elements {
            let grown = state.ids_stack.reserve(scope, elements * 3).ok()?;
            Some(grown)
        } else {
            None
        }
    });
    // The JavaScript layer holds its own reference to the array, so a grown
    // store has to be published or the next inline push writes into the
    // detached one. `AsyncHooks::grow_async_ids_stack` does the same by
    // assigning `env->async_ids_stack_string()` on the binding object.
    if let Some(grown) = grown {
        publish_ids_stack(scope, grown);
    }
    STATE.with(|state| {
        let state = state.borrow();
        let Some(state) = state.as_ref() else {
            return;
        };
        let offset = state.hook_fields.get(HOOK_FIELDS[7].1).unwrap_or(0) as usize;
        let elements = state.ids_stack.len() / 8;
        if offset * 2 >= elements {
            return;
        }
        // The saved pair is what a pop restores, so it is the *outgoing*
        // context, not the incoming one.
        let previous_execution = state
            .id_fields
            .get_float(UID_FIELDS[0].1)
            .unwrap_or(INVALID_ASYNC_ID);
        let previous_trigger = state
            .id_fields
            .get_float(UID_FIELDS[1].1)
            .unwrap_or(INVALID_ASYNC_ID);
        state.ids_stack.set_float(offset * 2, previous_execution);
        state.ids_stack.set_float(offset * 2 + 1, previous_trigger);
        // `async_hook_fields[kStackLength]` is the depth, which JavaScript reads.
        state.hook_fields.set(HOOK_FIELDS[7].1, (offset + 1) as u32);
        // Installing the new context is what makes `executionAsyncId()` inside
        // the callback answer the resource the callback runs for.
        state.id_fields.set_float(UID_FIELDS[0].1, async_id);
        state.id_fields.set_float(UID_FIELDS[1].1, trigger_id);
    });
}

/// Replaces `async_ids_stack` on the namespace object with a grown array.
fn publish_ids_stack(scope: &mut v8::PinScope<'_, '_>, grown: v8::Local<'_, v8::Value>) {
    let Some(binding) = rn_core::hook_slot::internal_binding(scope) else {
        return;
    };
    let Some(name) = v8::String::new(scope, "async_wrap") else {
        return;
    };
    let Some(namespace) = binding.call(scope, v8::undefined(scope).into(), &[name.into()]) else {
        return;
    };
    let Ok(namespace) = v8::Local::<v8::Object>::try_from(namespace) else {
        return;
    };
    let Some(key) = v8::String::new(scope, "async_ids_stack") else {
        return;
    };
    namespace.set(scope, key.into(), grown);
}

fn pop_async_context(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let expected = args.get(0).number_value(scope).unwrap_or(INVALID_ASYNC_ID);
    let matched = STATE.with(|state| {
        let state = state.borrow();
        let Some(state) = state.as_ref() else {
            return false;
        };
        let depth = state.hook_fields.get(HOOK_FIELDS[7].1).unwrap_or(0) as usize;
        if depth == 0 {
            return false;
        }
        // `AsyncHooks::pop_async_context`: the pair lives at `depth - 1`, *two*
        // slots per entry, so the execution id is at `2 * (depth - 1)` and the
        // trigger id one past it.
        //
        // This used to read `ids_stack[depth - 1]`, the trigger id of the
        // previous frame, so the corruption check compared against the wrong
        // number and a legitimate pop was refused.
        let offset = depth - 1;
        let saved_execution = state
            .ids_stack
            .get_float(offset * 2)
            .unwrap_or(INVALID_ASYNC_ID);
        let saved_trigger = state
            .ids_stack
            .get_float(offset * 2 + 1)
            .unwrap_or(INVALID_ASYNC_ID);
        // `if (kCheck > 0 && async_id_fields[kExecutionAsyncId] != async_id)`
        // is `FailWithCorruptedAsyncStack` in Node. A mismatch is reported
        // rather than aborting, and the pop still happens: refusing to pop
        // would leak the frame and leave `executionAsyncId()` answering an id
        // whose callback has already returned.
        let current = state
            .id_fields
            .get_float(UID_FIELDS[0].1)
            .unwrap_or(INVALID_ASYNC_ID);
        if current != expected {
            tracing::error!(
                expected,
                actual = current,
                "async_wrap: async hook stack has become corrupted"
            );
        }
        state.hook_fields.set(HOOK_FIELDS[7].1, offset as u32);
        state.id_fields.set_float(UID_FIELDS[0].1, saved_execution);
        state.id_fields.set_float(UID_FIELDS[1].1, saved_trigger);
        // The return value is `fields_[kStackLength] > 0` *after* the pop, i.e.
        // whether a frame remains — not whether the id matched.
        offset > 0
    });
    rv.set(v8::Boolean::new(scope, matched).into());
}

fn clear_async_id_stack(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let _ = scope;
    // `AsyncHooks::clear_async_id_stack` resets the ids as well as the depth:
    //
    //     async_id_fields_[kExecutionAsyncId] = 0;
    //     async_id_fields_[kTriggerAsyncId] = 0;
    //     fields_[kStackLength] = 0;
    //
    // (`src/env.cc:232-237`). Only the depth was reset here, so a fatal
    // exception left the execution id pointing at a resource whose callback had
    // already unwound.
    STATE.with(|state| {
        if let Some(state) = state.borrow().as_ref() {
            state.hook_fields.set(HOOK_FIELDS[7].1, 0);
            state.id_fields.set_float(UID_FIELDS[0].1, 0.0);
            state.id_fields.set_float(UID_FIELDS[1].1, 0.0);
        }
    });
}

fn queue_destroy_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `AsyncWrap::QueueDestroyAsyncId` takes one number and hands it to
    // `EmitDestroy`. This is `lib/internal/async_hooks.js`'s own `emitDestroy`
    // path: the JavaScript side decides *when* a resource is gone, and the
    // native side owns the deferral and the hook call.
    // `CHECK(args[0]->IsNumber())`. The type is checked, not just converted:
    // `number_value` would happily read `'42'` as 42, and a binding that coerces
    // hides the caller's bug.
    if !args.get(0).is_number() {
        throw_type_error(scope, "queueDestroyAsyncId expects a number");
        return;
    }
    let Some(async_id) = args.get(0).number_value(scope) else {
        throw_type_error(scope, "queueDestroyAsyncId expects a number");
        return;
    };
    emit_destroy(async_id);
}

fn register_destroy_hook(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `AsyncWrap::RegisterDestroyHook` ties a `destroy` hook to a *JavaScript
    // object's* collection, which needs a weak handle plus the optional
    // `destroyed` property bag. `v8::Weak`'s guaranteed finalizer runs with no
    // scope, and the bag has to be read on the isolate thread before deciding,
    // so a correct implementation needs a V8 callback context this layer does
    // not have yet. Queuing the id unconditionally would emit a `destroy` for
    // every promoted promise, which is worse than not emitting one.
    //
    // Nothing on the TCP reset path needs it: a handle's destroy is driven by
    // `AsyncReset` and `close`, not by collection. Declared in `DEFERRED`.
    let _ = scope;
}

fn set_callback_trampoline(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let trampoline = v8::Local::<v8::Function>::try_from(args.get(0))
        .ok()
        .map(|function| v8::Global::new(scope, function));
    HOOKS.with(|hooks| hooks.borrow_mut().trampoline = trampoline);
}

fn set_promise_hooks(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // V8 owns the promise hooks; `Context::SetPromiseHooks` takes the four
    // callbacks and returns nothing, so an absent hook is passed as undefined.
    let hook = |index: i32| -> Option<v8::Local<v8::Function>> {
        v8::Local::<v8::Function>::try_from(args.get(index)).ok()
    };
    let init = hook(0);
    let before = hook(1);
    let after = hook(2);
    let resolve = hook(3);
    scope.set_promise_hooks(init, before, after, resolve);
}

fn get_promise_hooks(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // V8 exposes no getter for the installed hooks; Node reads them back from
    // its own environment. rustnode has not stored them, so the honest answer is
    // an array of the four slots the caller expects, all undefined.
    let array = v8::Array::new(scope, 4);
    for index in 0..4 {
        array.set_index(scope, index, v8::undefined(scope).into());
    }
    rv.set(array.into());
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

/// Throws a `TypeError`, which is what a failed `CHECK` amounts to here.
fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_provider_ids_are_dense_and_start_at_zero() {
        // `ProviderType` is an enum starting at zero, and `Providers` is the
        // only place JavaScript sees the mapping, so a gap would mislabel every
        // resource after it.
        for (index, (name, id)) in PROVIDERS.iter().enumerate() {
            assert_eq!(*id, index as u32, "{name} must be at position {index}");
        }
        assert!(PROVIDERS.len() > 60, "Node 28 declares 70 providers");
        assert_eq!(PROVIDERS[0].0, "NONE");
    }

    #[test]
    fn the_field_layouts_match_env_h() {
        assert_eq!(HOOK_FIELDS[0], ("kInit", 0));
        assert_eq!(HOOK_FIELDS[7], ("kStackLength", 7));
        assert_eq!(HOOK_FIELDS_COUNT, 9);
        assert_eq!(UID_FIELDS[0], ("kExecutionAsyncId", 0));
        assert_eq!(UID_FIELDS_COUNT, 4);
        // Sixteen nested contexts, each two slots.
        assert_eq!(ASYNC_IDS_STACK_LENGTH, 32);
    }
}
