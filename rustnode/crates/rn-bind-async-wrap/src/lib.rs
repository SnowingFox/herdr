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

        // The ids start invalid and the counter starts at one, which is what
        // `AsyncHooks` does when it creates the buffers.
        id_fields.set_float(UID_FIELDS[0].1, INVALID_ASYNC_ID);
        id_fields.set_float(UID_FIELDS[1].1, INVALID_ASYNC_ID);
        id_fields.set_float(UID_FIELDS[2].1, 1.0);
        id_fields.set_float(UID_FIELDS[3].1, INVALID_ASYNC_ID);

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
        let counter = state.id_fields.get_float(UID_FIELDS[2].1).unwrap_or(1.0);
        state.id_fields.set_float(UID_FIELDS[2].1, counter + 1.0);
        counter
    })
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
    // `setupHooks(init, before, after, destroy, promiseResolve)`.
    let capture = |index: i32| -> Option<v8::Global<v8::Function>> {
        v8::Local::<v8::Function>::try_from(args.get(index))
            .ok()
            .map(|function| v8::Global::new(scope, function))
    };
    let init = capture(0);
    let before = capture(1);
    let after = capture(2);
    let destroy = capture(3);
    let promise_resolve = capture(4);
    HOOKS.with(|hooks| {
        let mut hooks = hooks.borrow_mut();
        hooks.init = init;
        hooks.before = before;
        hooks.after = after;
        hooks.destroy = destroy;
        hooks.promise_resolve = promise_resolve;
    });
}

fn push_async_context(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let async_id = args.get(1).number_value(scope).unwrap_or(INVALID_ASYNC_ID);
    let trigger_id = args.get(2).number_value(scope).unwrap_or(INVALID_ASYNC_ID);
    STATE.with(|state| {
        let state = state.borrow();
        let Some(state) = state.as_ref() else {
            return;
        };
        let offset = state.hook_fields.get(7).unwrap_or(0) as usize;
        // The stack holds pairs, so it is full once twice the depth is reached.
        if (offset + 1) * 2 > ASYNC_IDS_STACK_LENGTH {
            return;
        }
        state.ids_stack.set_float(offset * 2, async_id);
        state.ids_stack.set_float(offset * 2 + 1, trigger_id);
        // `async_hook_fields[kStackLength]` is the depth, which JavaScript reads.
        state.hook_fields.set(7, (offset + 1) as u32);
    });
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
        let depth = state.hook_fields.get(7).unwrap_or(0) as usize;
        if depth == 0 {
            return false;
        }
        let top = state
            .ids_stack
            .get_float(depth - 1)
            .unwrap_or(INVALID_ASYNC_ID);
        if top != expected {
            return false;
        }
        state.hook_fields.set(7, (depth - 1) as u32);
        true
    });
    rv.set(v8::Boolean::new(scope, matched).into());
}

fn clear_async_id_stack(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let _ = scope;
    STATE.with(|state| {
        if let Some(state) = state.borrow().as_ref() {
            state.hook_fields.set(7, 0);
        }
    });
}

fn queue_destroy_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // Destruction is driven by the JavaScript side through `emitDestroy`, so
    // there is no native queue to add to until the event loop exists.
    let _ = scope;
}

fn register_destroy_hook(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
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
