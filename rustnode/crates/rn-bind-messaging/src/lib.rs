//! `internalBinding('messaging')` for rustnode.
//!
//! `lib/internal/worker/js_transferable.js` is loaded by `internal/fs/*` and
//! `internal/url.js`, so this namespace is on the critical path for
//! `require('fs')`. It is also where `lib/internal/worker/io.js` gets
//! `MessagePort` and `MessageChannel`, and that module is required by
//! `worker_threads`, which `test/common/index.js` loads for every one of Node's
//! own tests. So without a real `MessagePort` here, every test in the suite fails
//! before its first line with
//! `Cannot read properties of undefined (reading 'prototype')`.
//!
//! # What works
//!
//! * `structuredClone` round-trips a value through V8's own
//!   `ValueSerializer`/`ValueDeserializer`, the same machinery `postMessage`
//!   uses.
//! * `MessageChannel` builds a real entangled pair, and posting on one port
//!   delivers to the other's `message` event, `onmessage` handler or
//!   `receiveMessageOnPort` call, on this thread.
//! * `broadcastChannel` joins the process-wide group of that name, so posting
//!   reaches every other channel on the name — in one thread or across two, with
//!   no fixed number of members — and never reaches the poster.
//! * `moveMessagePortToContext` re-homes a port into a `vm` realm, moving its
//!   queue and leaving the old handle inert.
//! * `receiveMessageOnPort`, `drainMessagePort` and `stopMessagePort` read and
//!   control that same queue.
//! * Transferring an `ArrayBuffer` detaches it on the sender; transferring a
//!   `MessagePort` moves it.
//!
//! # What is deferred, and why
//!
//! Nothing. [`DEFERRED`] is empty because every member of
//! `contracts/messaging.json` is installed. Two were listed here and both reasons
//! were false on this tree: `broadcastChannel` claimed a second thread was needed
//! for a channel to have a peer — Node delivers between two channels on one name
//! inside a single thread — and `moveMessagePortToContext` claimed the
//! sandbox-to-realm table was unreachable without a dependency cycle, which
//! `rn-core::hook_slot` removes.
//!
//! # Why the template has to be exactly this shape
//!
//! `lib/internal/worker/io.js` takes
//! `ObjectGetOwnPropertyDescriptors(MessagePort.prototype)`, clones the
//! prototype, re-parents it onto `NodeEventTarget.prototype`, then copies `ref`,
//! `unref`, `hasRef` and `close` back from the clone. Those four are inherited
//! from `HandleWrap` in Node, so they have to be inherited from a `HandleWrap`
//! template here too, or the copy restores nothing and every one of those methods
//! is missing from the final prototype.
//!
//! The `oninit` symbol is what makes a port work at all. `io.js` defines
//! `MessagePort.prototype[oninit]`; Node calls it from inside the constructor,
//! where it runs `initNodeEventTarget` and `setupPortReferencing`. That second
//! call is what `unref()`s a fresh port and `ref()`s plus `start()`s it when the
//! first `message` listener arrives. A port that never runs `oninit` never
//! delivers anything.

mod delivery;
mod deserialize;
pub mod port;
mod serialize;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::port::{Dispatch, MessagePortData, PortInner};

pub use crate::delivery::{
    emit_message_installed, has_delivery_pending, install_emit_message, run as run_message_ports,
};
pub use crate::port::{
    has_deliverable_message, live_port_count, refresh_owner_tokens, schedule_ports_with_mail,
    set_check_phase_armed,
};

/// Whether a `MessagePort` is still keeping the loop alive.
///
/// Node's `uv__loop_alive` sees the port's `uv_async_t` as an active handle while
/// it is receiving and ref'd, so the loop must consult the same fact.
pub fn has_message_port_work() -> bool {
    delivery::has_work()
}

/// Members exposed on the namespace object, matching `contracts/messaging.json`.
///
/// The order is the contract's, which is V8's template order: constructors and
/// methods are installed in the order Node's `CreatePerIsolateProperties` and
/// `CreatePerContextProperties` do, and `rn-compat` compares the sets.
pub const MEMBERS: &[&str] = &[
    "DOMException",
    "MessageChannel",
    "MessagePort",
    "QuotaExceededError",
    "broadcastChannel",
    "drainMessagePort",
    "exposeLazyDOMExceptionProperty",
    "moveMessagePortToContext",
    "receiveMessageOnPort",
    "setDeserializerCreateObjectFunction",
    "stopMessagePort",
    "structuredClone",
];

/// Members this build does not install yet.
///
/// Empty, and honestly so: every member of `contracts/messaging.json` is
/// installed. Two were listed here and both reasons turned out to be false on this
/// tree — `broadcastChannel` claimed a second thread was needed for a channel to
/// have a peer (Node delivers between two channels on one name in one thread), and
/// `moveMessagePortToContext` claimed the sandbox-to-realm table was unreachable
/// without a dependency cycle (contextify publishes it through `rn_core::hook_slot`).
pub const DEFERRED: &[(&str, &str)] = &[];

/// Internal field holding the `*mut PortSlot` a `MessagePort` owns.
///
/// Node's `MessagePort::kInternalFieldCount` is 1 and holds the
/// `MessagePortData` pointer; this holds the Rust side of the same thing.
const PORT_FIELD: i32 = 0;

/// `kNormalObject`: the host-object id that means "read a plain value instead".
///
/// `src/node_messaging.cc`:
///
/// ```text
/// // Hack to have WriteHostObject inform ReadHostObject that the value
/// // should be treated as a regular JS object. Used to transfer process.env.
/// static const uint32_t kNormalObject = static_cast<uint32_t>(-1);
/// ```
///
/// It is not an index into the host-object vector, which is why it can be the
/// largest `u32`: every real id is a small count.
pub(crate) const K_NORMAL_OBJECT: u32 = u32::MAX;

/// `process.env` as the ordinary object its serialised form carries.
///
/// `SerializationContext::WriteHostObject` builds `Object::New(isolate)` and
/// fills it with `env_vars()->AssignToObject()`, so the clone holds the variables
/// as they were at serialisation time. Building it fresh rather than returning
/// the proxy is what makes the *receiver* get a copy: sending the proxy itself
/// would make the clone live, and Node's comment notes the prototype difference
/// as a known wart rather than a behaviour to preserve.
pub(crate) fn env_pairs_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    for entry in rn_env::vars() {
        let (Some(key), Some(value)) = (
            v8::String::new(scope, &entry.name),
            v8::String::new(scope, &entry.value),
        ) else {
            continue;
        };
        object.set(scope, key.into(), value.into());
    }
    Some(object)
}

thread_local! {
    /// The deserializer object-creation callback `js_transferable.js` installs.
    ///
    /// Node keeps this on `Environment` as `messaging_deserialize_create_object_`
    /// and calls it from `JSTransferable::Data::Deserialize` with the
    /// `deserializeInfo` string a `[kClone]` method returned. It is the hook that
    /// turns `'internal/blocklist:InternalBlockList'` into a real
    /// `InternalBlockList` instance whose prototype is `BlockList.prototype`.
    static CREATE_OBJECT: RefCell<Option<v8::Global<v8::Function>>> =
        const { RefCell::new(None) };

    /// The `MessagePort` instance template, so a transfered port can be rebuilt.
    ///
    /// Node calls `GetMessagePortConstructorTemplate(...)->InstanceTemplate()
    /// ->NewInstance(context)`, which creates the object *without* running the
    /// constructor callback. `Function::new_instance` would run it, and the
    /// constructor deliberately throws.
    ///
    /// Per realm, because the template's prototype is the realm's own
    /// `MessagePort.prototype` — `internal/worker/io.js` rewrites that object in
    /// place, so a second realm installs a template over a *different* prototype.
    /// One shared slot made the shadow realm's install replace the principal
    /// realm's template, and `new Worker()`'s `this[kHandle].messagePort` was then
    /// an object built from the wrong realm's template. Its prototype had no `on`,
    /// which surfaced as `this[kPort].on is not a function` in
    /// `lib/internal/worker.js:302`.
    static INSTANCE_TEMPLATE: RefCell<Vec<(f64, v8::Global<v8::ObjectTemplate>)>> =
        const { RefCell::new(Vec::new()) };
}

/// The state one `MessagePort` object points at.
///
/// Boxed and referenced from an internal field, released by the object's
/// guaranteed finalizer. The `Rc<PortInner>` inside is what a peer keeps the
/// channel alive through after this object is collected.
struct PortSlot {
    inner: Rc<PortInner>,
    /// Keeps the guaranteed finalizer registered for the object's lifetime.
    /// Dropping a `Weak` cancels its finalizer, so this has to sit somewhere the
    /// object owns.
    _weak: RefCell<Option<v8::Weak<v8::Object>>>,
}

pub struct Messaging;

impl BindingModule for Messaging {
    fn namespace(&self) -> &'static str {
        "messaging"
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

        // The ports come first so `internal/worker/io.js` can read their
        // prototypes; it runs long before anything calls a method on one.
        let message_port = install_message_port(scope)?;
        let message_channel = install_message_channel(scope)?;

        let values: [(&str, v8::Local<v8::Value>); 12] = [
            // `DOMException` and `QuotaExceededError` are Node's per-context
            // scripts' exports, not classes built here. Node's own
            // `CreatePerContextProperties` reads both off
            // `GetPerContextExports`, so `internalBinding('messaging').DOMException`
            // is the *same* constructor as the `DOMException` global — which is
            // what makes `instanceof DOMException` hold across the two, and what
            // makes `[kClone]` reachable when a DOMException is posted.
            ("DOMException", dom_exception_constructor(scope)),
            ("MessageChannel", message_channel),
            ("MessagePort", message_port),
            ("QuotaExceededError", quota_exceeded_error(scope)),
            (
                "broadcastChannel",
                function(scope, "broadcastChannel", broadcast_channel)?,
            ),
            (
                "drainMessagePort",
                function(scope, "drainMessagePort", drain_message_port)?,
            ),
            (
                "exposeLazyDOMExceptionProperty",
                function(
                    scope,
                    "exposeLazyDOMExceptionProperty",
                    expose_lazy_dom_exception_property,
                )?,
            ),
            (
                "moveMessagePortToContext",
                function(
                    scope,
                    "moveMessagePortToContext",
                    move_message_port_to_context,
                )?,
            ),
            (
                "receiveMessageOnPort",
                function(scope, "receiveMessageOnPort", receive_message_on_port)?,
            ),
            (
                "setDeserializerCreateObjectFunction",
                function(
                    scope,
                    "setDeserializerCreateObjectFunction",
                    set_deserializer_create_object_function,
                )?,
            ),
            (
                "stopMessagePort",
                function(scope, "stopMessagePort", stop_message_port)?,
            ),
            (
                "structuredClone",
                function(scope, "structuredClone", structured_clone)?,
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
    registry.register_module(Messaging);
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Builds the `HandleWrap` template `MessagePort` inherits from.
///
/// Node's `HandleWrap` is a real template with `close`, `ref`, `unref` and
/// `hasRef` on it. `io.js` reads those four off `MessagePort.prototype`'s
/// descriptor set and copies them back after re-parenting, so they must exist.
fn handle_wrap_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::FunctionTemplate>, String> {
    let template = rn_core::class(handle_wrap_constructor).build(scope);
    if let Some(name) = v8::String::new(scope, "HandleWrap") {
        template.set_class_name(name);
    }
    let prototype = template.prototype_template(scope);
    install_method(scope, prototype, "close", handle_wrap_close)?;
    install_method(scope, prototype, "hasRef", handle_wrap_has_ref)?;
    install_method(scope, prototype, "ref", handle_wrap_ref)?;
    install_method(scope, prototype, "unref", handle_wrap_unref)?;
    Ok(template)
}

/// Installs one method function on `prototype`.
///
/// Each call is a separate generic instantiation, which is what lets
/// `MapFnTo<FunctionCallback>` resolve for that concrete function.
///
/// `ObjectTemplate::set` takes a `Template` rather than an instantiated
/// function, which is what Node's `SetProtoMethod` passes too: each instance
/// then gets its own function object closing over that instance.
fn install_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: v8::Local<'s, v8::ObjectTemplate>,
    name: &str,
    method: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    // `SetProtoMethod` in Node, which is `ConstructorBehavior::kThrow`. Both the
    // `MessagePort` pair and the four `HandleWrap` methods `io.js` copies back
    // onto `MessagePort.prototype` come through here, so this is the one place
    // that decides their constructibility.
    let template = rn_core::method(method).build(scope);
    if let Some(key) = v8::String::new(scope, name) {
        template.set_class_name(key);
    }
    let key = v8::String::new(scope, name)
        .ok_or_else(|| format!("cannot allocate the method name {name}"))?;
    prototype.set(key.into(), template.into());
    Ok(())
}

/// Installs the `MessagePort` constructor and returns it as a value.
fn install_message_port<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let handle_wrap = handle_wrap_template(scope)?;

    let template = rn_core::class(message_port_constructor).build(scope);
    if let Some(name) = v8::String::new(scope, "MessagePort") {
        template.set_class_name(name);
    }
    // Node's `MessagePort::kInternalFieldCount` is 1.
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    // `m->Inherit(HandleWrap::GetConstructorTemplate(isolate_data))`.
    template.inherit(handle_wrap);

    let prototype = template.prototype_template(scope);
    install_method(scope, prototype, "postMessage", post_message)?;
    install_method(scope, prototype, "start", start)?;

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the MessagePort constructor")?;
    if let Some(name) = v8::String::new(scope, "MessagePort") {
        constructor.set_name(name);
    }
    // `io.js` rewrites `MessagePort.prototype` in place, so instances have to be
    // built from the same instance template every time; rooting it is what lets
    // a transferred port be rebuilt with the prototype `io.js` produced.
    let instance = template.instance_template(scope);
    let realm = rn_core::hook_slot::current_realm_id(scope);
    let instance = v8::Global::new(scope, instance);
    INSTANCE_TEMPLATE.with(|slot| {
        let mut slot = slot.borrow_mut();
        match slot.iter_mut().find(|(key, _)| *key == realm) {
            Some((_, existing)) => *existing = instance,
            None => slot.push((realm, instance)),
        }
    });
    Ok(constructor.into())
}

/// Installs the `MessageChannel` constructor and returns it as a value.
fn install_message_channel<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::class(message_channel_constructor).build(scope);
    if let Some(name) = v8::String::new(scope, "MessageChannel") {
        template.set_class_name(name);
    }
    // `MessageChannel.prototype` owns nothing but `constructor`; `io.js` adds the
    // `Symbol.toStringTag`. The two ports hang off the instance as `port1` and
    // `port2`, set by the constructor.
    template
        .instance_template(scope)
        .set_internal_field_count(0);

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the MessageChannel constructor")?;
    if let Some(name) = v8::String::new(scope, "MessageChannel") {
        constructor.set_name(name);
    }
    Ok(constructor.into())
}

// ---------------------------------------------------------------------------
// Port objects
// ---------------------------------------------------------------------------

/// Builds one `MessagePort` object around `data`.
///
/// Runs the `oninit` hook the way Node's constructor does, which is what wires
/// up the `EventTarget` state and the listener-driven `ref`/`start` behaviour.
pub fn new_port_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    data: Arc<MessagePortData>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let realm = rn_core::hook_slot::current_realm_id(scope);
    let instance_template = INSTANCE_TEMPLATE.with(|slot| {
        slot.borrow()
            .iter()
            .find(|(key, _)| *key == realm)
            .map(|(_, template)| v8::Local::new(scope, template))
    });
    let Some(instance_template) = instance_template else {
        return Err("the MessagePort instance template is not installed".to_string());
    };
    // `InstanceTemplate::NewInstance` builds the object with the internal field
    // count and prototype the template declares, and does *not* run the
    // constructor callback — which is required, because that callback throws.
    let object = instance_template
        .new_instance(scope)
        .ok_or("cannot allocate a MessagePort")?;

    let inner = PortInner::new(data);
    let slot = Box::into_raw(Box::new(PortSlot {
        inner,
        _weak: RefCell::new(None),
    }));
    // SAFETY: `slot` came from `Box::into_raw` and is freed exactly once, by the
    // guaranteed finalizer installed below.
    let external = v8::External::new(scope, slot.cast());
    object.set_internal_field(PORT_FIELD as usize, external.into());

    let address = slot as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut PortSlot;
            // SAFETY: as above; nothing else frees this allocation.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );

    // Delivery needs the object to use as `this`, so the port holds a weak
    // reference to it rather than a root that would pin every port forever. The
    // clone's finalizer is empty: its only job is to be a non-owning handle.
    let peer = weak.clone_with_guaranteed_finalizer(Box::new(|| {}));
    // SAFETY: `slot` is live and exclusively reachable through this local.
    let inner = unsafe { &*slot }.inner.clone();
    inner.attach_object(peer);
    // The finalizer is only kept alive while its `Weak` is; parking it in the
    // slot ties its life to the object's.
    // SAFETY: as above.
    *unsafe { &*slot }._weak.borrow_mut() = Some(weak);

    run_oninit(scope, object);
    Ok(object)
}

/// Calls the `oninit` hook `io.js` defines on the prototype.
///
/// Node looks the symbol up on the object and calls it when it is a function.
/// A port built before `io.js` ran has no hook, and Node skips it the same way.
fn run_oninit(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) {
    let Ok(symbol) = rn_bind_symbols::ensure(scope, "oninit", "oninit") else {
        return;
    };
    let Some(value) = object.get(scope, symbol.into()) else {
        return;
    };
    let Ok(init) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };
    let _ = init.call(scope, object.into(), &[]);
}

/// The `PortInner` behind `object`, if `object` is a `MessagePort`.
pub fn port_state_of<'s>(
    scope: &v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<Rc<PortInner>> {
    let field = object.get_internal_field(scope, PORT_FIELD as usize)?;
    let external = v8::Local::<v8::External>::try_from(field).ok()?;
    let pointer = external.value() as *const PortSlot;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: a non-null pointer in this field was installed by
    // `new_port_object`, and stays valid until the object's finalizer runs —
    // which cannot happen while `object` is a live local.
    Some(unsafe { &*pointer }.inner.clone())
}

/// Throws a `TypeError` carrying `message`.
pub fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// Throws a `TypeError` with `code` set on the error object, which is how Node's
/// `THROW_ERR_*` macros surface their `code` property.
///
/// `THROW_ERR_INVALID_ARG_TYPE` constructs a `TypeError` and then assigns `code`
/// from the macro's entry in `node_errors.h`, so a script can branch on
/// `err.code === 'ERR_INVALID_ARG_TYPE'`. A bare `v8::Exception::type_error` has
/// no `code`, which is the difference between "the same class" and "the same
/// error".
fn throw_type_error_with_code(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    if let (Ok(object), Some(key), Some(value)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, "code"),
        v8::String::new(scope, code),
    ) {
        let _ = object.set(scope, key.into(), value.into());
    }
    scope.throw_exception(exception);
}

/// Throws `new DOMException(message, 'DataCloneError')`, Node's
/// `ThrowDataCloneException`.
/// `node_messaging.cc` builds the exception from
/// `GetDOMException(context)->NewInstance(context, {message, "DataCloneError"})`,
/// which is the per-context class: `name` is `DataCloneError`, `code` is 25, and
/// the object is an `Error`. `test-structuredClone-domexception.js` asserts on
/// `name`, so the approximation this replaces (a `TypeError` with the same text)
/// could not pass it.
///
/// When the per-context class is unavailable the message still has to surface, so
/// the fallback is an ordinary `Error` carrying the same text rather than silence.
#[doc(hidden)]
pub fn throw_data_clone_exception(
    scope: &mut v8::PinScope<'_, '_>,
    message: v8::Local<'_, v8::Value>,
) {
    let Some(constructor) = per_context_export(scope, "DOMException") else {
        let text = message
            .to_string(scope)
            .unwrap_or_else(|| v8::String::empty(scope));
        let exception = v8::Exception::error(scope, text);
        scope.throw_exception(exception);
        return;
    };
    let Ok(constructor) = v8::Local::<v8::Function>::try_from(constructor) else {
        return;
    };
    let Some(name) = v8::String::new(scope, "DataCloneError") else {
        return;
    };
    // `NewInstance(context, 2, argv)`: the constructor takes
    // `(message, options)` and a string second argument is the *name*.
    let Some(exception) = constructor.new_instance(scope, &[message, name.into()]) else {
        return;
    };
    scope.throw_exception(exception.into());
}

/// Sets `no_message_symbol` as the return value.
///
/// `io.js`'s `receiveMessageOnPort` compares against this symbol to choose
/// between `undefined` and `{ message }`, so it has to be the same identity
/// `internalBinding('symbols')` publishes.
fn set_no_message(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue<'_>) {
    match rn_bind_symbols::ensure(scope, "no_message_symbol", "no_message_symbol") {
        Ok(symbol) => rv.set(symbol.into()),
        Err(_) => rv.set(v8::undefined(scope).into()),
    }
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

fn message_port_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    // Node's `MessagePort::New` throws `ERR_CONSTRUCT_CALL_INVALID` and does not
    // use `ConstructorBehavior::kThrow`, precisely so the prototype stays on the
    // function. Both `new MessagePort()` and `MessagePort()` reach this.
    throw_type_error_with_code(
        scope,
        "ERR_CONSTRUCT_CALL_INVALID",
        "Constructor cannot be called",
    );
}

fn message_channel_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error_with_code(
            scope,
            "ERR_CONSTRUCT_CALL_REQUIRED",
            "Cannot call constructor without `new`",
        );
        return;
    }

    let first = MessagePortData::new();
    let second = MessagePortData::new();
    MessagePortData::entangle(&first, &second);

    let (Ok(port1), Ok(port2)) = (
        new_port_object(scope, first),
        new_port_object(scope, second),
    ) else {
        return;
    };

    let this = args.this();
    for (name, port) in [("port1", port1), ("port2", port2)] {
        if let Some(key) = v8::String::new(scope, name) {
            this.set(scope, key.into(), port.into());
        }
    }
    rv.set(this.into());
}

/// `broadcastChannel(name)`: a port in the process-wide group called `name`.
///
/// `MessagePort::New(env, env->context(), {}, SiblingGroup::Get(*name))`. Two
/// consequences are the whole feature and both are observable:
///
/// * the group is *named*, so it is shared by every `BroadcastChannel` on that
///   name in the process, on any thread, with no upper bound on members —
///   `lib/internal/worker/io.js:383` calls this from the constructor, which is
///   why two channels on one name deliver to each other in a single thread and
///   need no `Worker` to have a second participant;
/// * the group is *not* anonymous, so losing a member does not close the
///   survivors. `SiblingGroup::Disentangle` only closes a last peer when
///   `name_.empty()`.
///
/// Node `CHECK`s `args[0]->IsString()` and aborts otherwise, because the only
/// caller is `io.js`, which stringifies the name first (`` `${name}` ``). Aborting
/// a process because internal JavaScript passed a non-string is not worth
/// reproducing — this project has already decided that class of divergence is
/// worse than the crash it copies — so a non-string is coerced, which is what
/// `io.js` does anyway. Unreachable from `BroadcastChannel`.
fn broadcast_channel(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let name = args.get(0).to_rust_string_lossy(scope);

    let data = MessagePortData::new();
    data.join_named(&name);

    let Ok(port) = new_port_object(scope, data) else {
        throw_type_error(scope, "broadcastChannel: cannot allocate a MessagePort");
        return;
    };
    rv.set(port.into());
}

/// `moveMessagePortToContext(port, sandbox)`: re-home a port into a `vm` realm.
///
/// `MessagePort::MoveToContext` (`src/node_messaging.cc:1180`) in three steps:
///
/// 1. it must be a `MessagePort` and not closing, else `ERR_INVALID_ARG_TYPE` or
///    `ERR_CLOSED_MESSAGE_PORT`;
/// 2. `ContextifyContext::ContextFromContextifiedSandbox(env, sandbox)`, else
///    `ERR_INVALID_ARG_TYPE` with "Invalid context argument";
/// 3. under `Context::Scope` for that realm, `MessagePort::New(env, context,
///    std::move(data))` — which detaches the old port and builds the new object
///    from *that realm's* instance template, so the result's prototype is the
///    target realm's `MessagePort.prototype`, not this one's.
///
/// Step 2 goes through `rn_core::hook_slot`, which is where `rn-bind-contextify`
/// publishes the lookup. Node reads a static table; this reads the same table
/// through a slot, so the two crates keep their existing order and neither gains
/// a dependency edge.
fn move_message_port_to_context<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let port = v8::Local::<v8::Object>::try_from(args.get(0))
        .ok()
        .and_then(|object| port_state_of(scope, object));
    let Some(state) = port else {
        throw_type_error_with_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"port\" argument must be a MessagePort instance",
        );
        return;
    };
    if state.closing.get() {
        // `THROW_ERR_CLOSED_MESSAGE_PORT`, whose message is the one `postMessage`
        // uses for a closed port.
        throw_error_with_code(
            scope,
            "ERR_CLOSED_MESSAGE_PORT",
            "Cannot send data on closed MessagePort",
        );
        return;
    }

    let Some(context) = rn_core::hook_slot::sandbox_context(scope, args.get(1)) else {
        throw_type_error_with_code(scope, "ERR_INVALID_ARG_TYPE", "Invalid context argument");
        return;
    };

    // `port->Detach()`: the queue moves to the new object and the old one is left
    // with no `data_`. It is not a transfer, so no close marker is queued for a
    // peer and no `close` event is owed — the port is inert, not closed.
    state.detach_for_move();
    let data = Arc::clone(&state.data);

    // `Context::Scope context_scope(context_wrapper->context())` around
    // `MessagePort::New`. Everything below allocates in the target realm, which is
    // what makes the result's prototype that realm's.
    let mut context_scope = std::pin::pin!(v8::ContextScope::new(&mut **scope, context));
    let scope = &mut *context_scope;
    match new_port_object(scope, data) {
        Ok(port) => rv.set(port.into()),
        Err(message) => throw_type_error(scope, &message),
    }
}

/// Throws `new Error(message)` carrying `code`, Node's `THROW_ERR_*` for the codes
/// whose class is `Error` rather than `TypeError`.
fn throw_error_with_code(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    if let (Ok(object), Some(key), Some(value)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, "code"),
        v8::String::new(scope, code),
    ) {
        let _ = object.set(scope, key.into(), value.into());
    }
    scope.throw_exception(exception);
}

fn handle_wrap_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    // `HandleWrap` is only a prototype parent here. Node's constructor is
    // `BaseObject` initialisation and is not reachable from JavaScript.
    let _ = scope;
}

// ---------------------------------------------------------------------------
// Port methods
// ---------------------------------------------------------------------------

fn post_message<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    if args.length() == 0 {
        throw_type_error(scope, "Not enough arguments to MessagePort.postMessage");
        return;
    }

    let this = args.this();
    let Some(state) = port_state_of(scope, this) else {
        throw_type_error(scope, "Value of \"this\" must be of MessagePort");
        return;
    };

    // Serialization happens even for a closed port, because the transfer list
    // still has to be validated and a clone error still has to be raised. Node
    // passes the port as `source_port` so a list naming it can be refused.
    let message = match serialize::serialize(
        scope,
        args.get(0),
        args.get(1),
        Some(this),
        serialize::TransferList::Argument,
    ) {
        Ok(message) => message,
        Err(serialize::SerializeError::DataClone(text)) => {
            // `Message::Serialize` routes every transfer-list and clone failure
            // through `ThrowDataCloneException`, so the class is
            // `DOMException`/`DataCloneError` with code 25 — not a `TypeError`.
            throw_data_clone_exception_str(scope, &text);
            return;
        }
        Err(serialize::SerializeError::NotIterableTransferList) => {
            // `GetTransferList`'s `THROW_ERR_INVALID_ARG_TYPE`, which *is* a
            // `TypeError` and carries `code` `ERR_INVALID_ARG_TYPE`.
            throw_type_error_with_code(
                scope,
                "ERR_INVALID_ARG_TYPE",
                "Optional transferList argument must be an iterable",
            );
            return;
        }
        Err(serialize::SerializeError::NotIterableOptionsTransfer) => {
            throw_type_error_with_code(
                scope,
                "ERR_INVALID_ARG_TYPE",
                "Optional options.transfer argument must be an iterable",
            );
            return;
        }
        Err(serialize::SerializeError::NotIterableSequence) => {
            // This path is for `structuredClone` only, but keep the fallback here
            // so the postMessage contract does not panic if the call shape changes.
            throw_type_error_with_code(
                scope,
                "ERR_INVALID_ARG_TYPE",
                "Optional transferList argument must be an iterable",
            );
            return;
        }
        Err(serialize::SerializeError::Thrown) => return,
    };

    if state.closing.get() {
        // `PostMessage` returns `serialization_maybe` when `data_ == nullptr` — a
        // value the caller never sets, so the observable answer for a closed or
        // detached port is `undefined`, not `true`. `io.js` treats `undefined` as
        // "could not post" and raises `InvalidStateError` for the
        // `BroadcastChannel` wrapper, so this is load-bearing.
        rv.set(v8::undefined(scope).into());
        return;
    }

    // The same `data_ == nullptr` case for a port moved into another realm: it is
    // not closing, but it no longer owns a queue. `MessagePort::PostMessage`
    // returns without dispatching here, which is what makes the old handle inert
    // rather than a second live end of the same channel.
    if state.is_detached() {
        rv.set(v8::Boolean::new(scope, true).into());
        return;
    }

    // Node's `PostMessage` dispatches into the group, whose members are reached
    // through the sender's `MessagePortData`.
    match state.data.dispatch(&message) {
        Dispatch::Delivered => {
            // Wake every port that now has something to read. `dispatch` only
            // enqueues; the scheduling is what makes a port on this thread run.
            for peer in state.data.peers() {
                if let Some(owner) = peer.owner() {
                    owner.schedule();
                }
            }
            rv.set(v8::Boolean::new(scope, true).into());
        }
        // `Just(false)`: the group has no member other than the sender. `io.js`'s
        // `BroadcastChannel.postMessage` turns this into
        // `DOMException('Message could not be posted.')`.
        Dispatch::NoDestinations => {
            rv.set(v8::Boolean::new(scope, false).into());
        }
        // `Nothing()`. `MessagePortData::Dispatch` returns it for an unentangled
        // port, which `PostMessage` turns into no return value at all — and the
        // "is not entangled" text becomes a process warning, not an exception.
        Dispatch::NotEntangled => {
            rv.set(v8::undefined(scope).into());
        }
        // `Nothing()` for a group with more room than a transfer list can honour.
        // Node reports the reason through its `error` out-parameter; the reply is
        // the same `undefined`.
        Dispatch::TransferablesMultipleDestinations => {
            rv.set(v8::undefined(scope).into());
        }
        // `Just(true)` plus a warning: the target was itself transferred, so the
        // post reaches nobody. The script keeps running and the loss is reported.
        Dispatch::DeliveredWithWarning(text) => {
            rn_core::hook_slot::emit_warning(scope, text);
            rv.set(v8::Boolean::new(scope, true).into());
        }
    }
}

fn start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    let Some(state) = port_state_of(scope, this) else {
        return;
    };
    if state.closing.get() {
        return;
    }
    state.start();
}

fn handle_wrap_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    if let Some(state) = port_state_of(scope, this) {
        // `HandleWrap::Ref` is `if (IsAlive(wrap)) uv_ref(...)`, so a port past
        // its close callback stays unref'd however often `ref()` is called.
        //
        // `set_ref` also takes this thread's wake handle ref, which is what makes a
        // foreign thread's post run this thread's loop — see `PortInner::hold_wake`.
        state.set_ref();
    }
}

fn handle_wrap_unref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    if let Some(state) = port_state_of(scope, this) {
        state.clear_ref();
    }
}

fn handle_wrap_has_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    let refed = port_state_of(scope, this)
        .map(|state| state.has_ref())
        .unwrap_or(false);
    rv.set(v8::Boolean::new(scope, refed).into());
}

fn handle_wrap_close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    if let Some(state) = port_state_of(scope, this) {
        state.close();
    }
}

// ---------------------------------------------------------------------------
// The queue accessors
// ---------------------------------------------------------------------------

fn receive_message_on_port(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(state) = port_argument(scope, &args) else {
        return;
    };
    // `ReceiveMessage`: the front is peeked, and a close marker is honoured
    // before the `wants_message` test, so `receiveMessageOnPort` on a port that
    // was never started still closes it. Returning `no_message_symbol` is the
    // whole output — the close event itself is dispatched from the check phase,
    // exactly as a self-initiated `close()` delivers it.
    if let Some(true) = state.data.front_is_close() {
        if let Some(message) = state.data.dequeue() {
            debug_assert!(message.close);
        }
        state.clone().close_quietly();
        set_no_message(scope, &mut rv);
        return;
    }
    if state.closing.get() {
        set_no_message(scope, &mut rv);
        return;
    }
    let Some(message) = state.data.dequeue() else {
        set_no_message(scope, &mut rv);
        return;
    };
    match deserialize::deserialize(scope, &message) {
        Ok(deserialized) => rv.set(deserialized.value),
        Err(()) => set_no_message(scope, &mut rv),
    }
}

fn drain_message_port(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    // `MessagePort::Drain` forces a read even for a port that is not receiving,
    // which is what `worker_threads` uses to discard what is left on exit.
    let Some(state) = port_argument(scope, &args) else {
        return;
    };
    while let Some(message) = state.data.dequeue() {
        if message.close {
            state.close();
            break;
        }
    }
}

fn stop_message_port(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(state) = port_argument(scope, &args) else {
        return;
    };
    state.stop();
}

/// Reads the `port` argument the three accessors share.
fn port_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
) -> Option<Rc<PortInner>> {
    let Ok(object) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error_with_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"port\" argument must be a MessagePort instance",
        );
        return None;
    };
    let state = port_state_of(scope, object);
    if state.is_none() {
        throw_type_error_with_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"port\" argument must be a MessagePort instance",
        );
    }
    state
}

// ---------------------------------------------------------------------------
// The rest of the namespace
// ---------------------------------------------------------------------------

/// `DOMException` from the per-context scripts, or a throwing placeholder.
///
/// `lib/internal/util.js` and `lib/internal/abort_controller.js` both construct
/// `internalBinding('messaging').DOMException`, and `internal/worker/clone_dom_exception.js`
/// re-exports it. Node reads it off `GetPerContextExports`; this does the same
/// through [`rn_core::per_context_exports`], so the binding hands back the very
/// constructor the global is.
///
/// The placeholder is only reachable before the per-context scripts have run,
/// which the bootstrap does not do: a namespace installed earlier would otherwise
/// have to return `undefined` and every caller would fail somewhere unrelated.
/// Throwing names the cause instead.
fn dom_exception_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    per_context_export(scope, "DOMException").unwrap_or_else(|| placeholder_constructor(scope))
}

fn quota_exceeded_error<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    per_context_export(scope, "QuotaExceededError")
        .unwrap_or_else(|| placeholder_constructor(scope))
}

/// One export of the per-context scripts' `exports` object.
fn per_context_export<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let exports = rn_core::per_context_exports(scope)?;
    let key = v8::String::new(scope, name)?;
    let value = exports.get(scope, key.into())?;
    if value.is_function() {
        Some(value)
    } else {
        None
    }
}

/// A constructor that throws, standing in for a per-context export that has not
/// been produced yet.
///
/// Deliberately not a plausible `DOMException`: a plausible one is what made this
/// bug invisible for so long, because it constructed fine and was simply not an
/// `Error`.
fn placeholder_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    function(scope, "missingPerContextExport", missing_per_context_export)
        .unwrap_or_else(|_| v8::undefined(scope).into())
}

fn missing_per_context_export(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    throw_type_error(
        scope,
        "this class is an export of the internal/per_context scripts, \
         which have not run in this context",
    );
}

fn expose_lazy_dom_exception_property(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // Node installs a lazy accessor for `DOMException` on the target. Two things
    // need the property to exist: `internal/bootstrap/web/exposed-wildcard.js`
    // calls this during pre-execution, and `internal/blob.js` throws
    // `lazyDOMException(...)` from `arrayBuffer()` and the stream error path.
    //
    // The constructor is installed eagerly rather than lazily because it is the
    // per-context scripts' `DOMException`, which the messaging namespace already
    // has to resolve; there is nothing to defer, and an accessor that only
    // forwards to it would add a getter to the startup path for no saving.
    let target = match v8::Local::<v8::Object>::try_from(args.get(0)) {
        Ok(target) => target,
        Err(_) => scope.get_current_context().global(scope),
    };
    let Some(key) = v8::String::new(scope, "DOMException") else {
        return;
    };
    let constructor = dom_exception_constructor(scope);
    // `define_property` rather than `set`: Node installs every global
    // non-enumerably, and `test/common/index.js` fails a test for any global
    // name it does not recognise when it walks `globalThis`. A `set` here made
    // `DOMException` visible to that walk.
    //
    // The flags are Node's, read from the `globalThis` of a real binary:
    // `{ writable: true, enumerable: false, configurable: true }`.
    // `SetLazyDataProperty(..., DontEnum)` produces them, so configuring only
    // the enumerable bit would leave `configurable: false` and break any
    // test that replaces the global.
    let mut descriptor = v8::PropertyDescriptor::new_from_value_writable(constructor, true);
    descriptor.set_enumerable(false);
    descriptor.set_configurable(true);
    if target
        .define_property(scope, key.into(), &descriptor)
        .is_none()
    {
        target.set(scope, key.into(), constructor);
    }
}

fn set_deserializer_create_object_function(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `SetDeserializerCreateObjectFunction`: `CHECK(args[0]->IsFunction())` then
    // store it on the realm. Type-strict on purpose — a non-function here would
    // be stored and only fail much later, inside a deserialisation, with nothing
    // pointing back at the caller that installed it.
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(
            scope,
            "setDeserializerCreateObjectFunction requires a function",
        );
        return;
    };
    let callback = v8::Global::new(scope, callback);
    CREATE_OBJECT.with(|slot| *slot.borrow_mut() = Some(callback));
}

/// Calls the create-object hook, Node's `JSTransferable::Data::Deserialize`.
///
/// This is the call that reconstructs a host object from the
/// `deserializeInfo` string its `[kClone]` returned. Node's shape:
///
/// ```text
/// CHECK(!env->messaging_deserialize_create_object().IsEmpty());
/// if (!create_object->Call(context, Null(isolate), 1, &info).ToLocal(&ret) ||
///     !ret->IsObject()) return {};
/// if (!JSTransferable::IsJSTransferable(env, context, ret.As<Object>())) return {};
/// ```
///
/// Both post-conditions are checked here rather than dropped, because the object
/// the hook returns is what `[kDeserialize]` is later called on: a non-object or
/// an unmarked object would fail at a point that names neither the hook nor the
/// `deserializeInfo` that produced it.
pub(crate) fn create_object_from_info<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    deserialize_info: &str,
) -> Option<v8::Local<'s, v8::Object>> {
    let callback = CREATE_OBJECT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|callback| v8::Local::new(scope, callback))
    });
    let Some(callback) = callback else {
        // Node `CHECK`s here, which aborts. A missing hook is a bootstrap bug —
        // `js_transferable.js` installs it from `setup()` — so the message says
        // which bootstrap step is missing instead of throwing something vague.
        throw_type_error(
            scope,
            "Cannot deserialize a host object: \
             internal/worker/js_transferable setup() has not run",
        );
        return None;
    };
    let info = v8::String::new(scope, deserialize_info)?;
    // `Null(isolate)` as `this`: the hook is a plain arrow function in
    // `js_transferable.js`, so it never reads its receiver.
    let argument = info.into();
    let created = callback.call(scope, v8::null(scope).into(), &[argument])?;
    let Ok(object) = v8::Local::<v8::Object>::try_from(created) else {
        throw_type_error(
            scope,
            &format!("The create-object hook returned a non-object for {deserialize_info}"),
        );
        return None;
    };
    // `JSTransferable::IsJSTransferable`: the hook may return any object, but only
    // a marked one can be filled in by `[kDeserialize]`.
    if js_transfer_mode(scope, object).is_none() {
        throw_type_error(
            scope,
            &format!("The create-object hook returned an unmarked object for {deserialize_info}"),
        );
        return None;
    }
    Some(object)
}

/// The `transfer_mode_private_symbol` `markTransferMode` writes.
fn transfer_mode_key<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Symbol> {
    // The same identity `util.privateSymbols` installs, from the shared table in
    // `rn_core`. A symbol created here would be a different key and every
    // `markTransferMode` write would be invisible to this read.
    rn_core::symbol(scope, "node:transfer_mode")
}

/// Whether `markTransferMode` stamped this object, Node's `HasPrivate` probe.
///
/// Presence, not a mode test: an object marked `kDisallowCloneAndTransfer` is
/// still a `JSTransferable`, and Node answers "this is a host object, and it
/// cannot be cloned" rather than falling through to copying its properties.
pub(crate) fn js_marked(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> bool {
    let key = transfer_mode_key(scope);
    object.has(scope, key.into()).unwrap_or(false)
}

/// The transfer mode `markTransferMode` stored, if this object is marked.
///
/// `JSTransferable::GetTransferMode` requires a `Uint32` and otherwise disallows,
/// so a non-numeric value reports "not cloneable" rather than guessing.
pub(crate) fn js_transfer_mode(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> Option<rn_core::host_object::TransferMode> {
    let key = transfer_mode_key(scope);
    let value = object.get(scope, key.into())?;
    if !value.is_uint32() {
        return None;
    }
    Some(rn_core::host_object::TransferMode::from_bits(
        value.uint32_value(scope)?,
    ))
}

/// Runs `[kClone]` on a marked object, Node's `JSTransferable::CloneForMessaging`.
///
/// `TransferOrClone<kCloneable>` in `src/node_messaging.cc` is exactly this: look
/// the symbol up, require a function, call it with no arguments, then take
/// `data` and `deserializeInfo` off the result. The `data` value is held in the
/// payload; `deserializeInfo` is handed to the create-object hook on the way back.
pub(crate) fn js_clone_for_messaging<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<std::sync::Arc<dyn rn_core::host_object::TransferData>> {
    let mode = js_transfer_mode(scope, object)?;
    if !mode.is_cloneable() {
        return None;
    }
    let Ok(symbol) =
        rn_bind_symbols::ensure(scope, "messaging_clone_symbol", "messaging_clone_symbol")
    else {
        return None;
    };
    let method = object.get(scope, symbol.into())?;
    let method = v8::Local::<v8::Function>::try_from(method).ok()?;

    // `Call(context, target(), 0, nullptr)`: the object is the receiver, so a
    // `[kClone]` written against `this` sees its own state.
    let result = method.call(scope, object.into(), &[])?;
    let result = v8::Local::<v8::Object>::try_from(result).ok()?;

    let data = get_key(scope, result, "data")?;
    let info = get_key(scope, result, "deserializeInfo")?;
    // `Utf8Value` in Node stringifies, so a non-string that converts is accepted
    // and one that does not is a clone failure.
    let info = info.to_string(scope)?;
    Some(std::sync::Arc::new(JsClone {
        deserialize_info: info.to_rust_string_lossy(scope),
        data: v8::Global::new(scope, data),
    }))
}

/// `object.name`, as a value.
fn get_key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

/// One object cloned through `kClone`, Node's `JSTransferable::Data`.
///
/// The two fields `[kClone]` returned, held apart because they are consumed at
/// different times: `deserializeInfo` names the class to build *before* the
/// payload is read, and `data` is that class's state, written after the payload.
struct JsClone {
    /// `'module:Constructor'`, from the `[kClone]` result.
    deserialize_info: String,
    /// The `data` value, held across the call.
    data: v8::Global<v8::Value>,
}

impl rn_core::host_object::TransferData for JsClone {
    fn rebuild<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
        // `JSTransferable::Data::Deserialize`. This is the call the bug report
        // names: the hook was stored by
        // `setDeserializerCreateObjectFunction` and never invoked, so a cloned
        // `BlockList` never got a `BlockList`-shaped object to fill in.
        create_object_from_info(scope, &self.deserialize_info)
    }

    fn write_data(
        &self,
        scope: &mut v8::PinScope<'_, '_>,
        serializer: &dyn v8::ValueSerializerHelper,
    ) -> bool {
        // `FinalizeTransferWrite` writes `data_` into the serializer, which is
        // what puts it after the main payload in the message buffer.
        let data: v8::Local<v8::Value> = v8::Local::new(scope, &self.data);
        serializer
            .write_value(scope.get_current_context(), data)
            .unwrap_or(false)
    }

    fn read_data(
        &self,
        scope: &mut v8::PinScope<'_, '_>,
        deserializer: &dyn v8::ValueDeserializerHelper,
        target: v8::Local<'_, v8::Object>,
    ) -> bool {
        // `JSTransferable::FinalizeTransferRead`: read the value that follows the
        // main payload, then call `this[kDeserialize](data)` when the prototype
        // has one. A missing or non-function hook is *not* an error in Node — it
        // returns `JustVoid()` — because `kClone` alone is enough for an object
        // whose receiver needs no state.
        let context = scope.get_current_context();
        let Some(data) = deserializer.read_value(context) else {
            return false;
        };
        let Ok(symbol) = rn_bind_symbols::ensure(
            scope,
            "messaging_deserialize_symbol",
            "messaging_deserialize_symbol",
        ) else {
            return true;
        };
        let Some(method) = target.get(scope, symbol.into()) else {
            return true;
        };
        let Ok(method) = v8::Local::<v8::Function>::try_from(method) else {
            return true;
        };
        method.call(scope, target.into(), &[data]).is_some()
    }
}

fn structured_clone<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let value = args.get(0);
    // `structuredClone(value, options)` goes through `Message::Serialize` and
    // `Message::Deserialize` in Node, with `options.transfer` as the transfer
    // list — the same machinery `postMessage` uses. Doing it any other way makes
    // a transfer silently a copy, and `test-structuredClone-domexception.js`
    // asserts that transferring a `DOMException` throws.
    let transfer_list = transfer_list_from_options(scope, args.get(1));
    // `structuredClone` has no source port; Node passes an empty `Local<Object>`
    // so the source-port branch is skipped entirely.
    let message = match serialize::serialize(
        scope,
        value,
        transfer_list,
        None,
        serialize::TransferList::Sequence,
    ) {
        Ok(message) => message,
        Err(serialize::SerializeError::DataClone(reason)) => {
            throw_data_clone_exception_str(scope, &reason);
            return;
        }
        Err(serialize::SerializeError::NotIterableTransferList)
        | Err(serialize::SerializeError::NotIterableOptionsTransfer)
        | Err(serialize::SerializeError::NotIterableSequence) => {
            // Node reaches this through the `webidl` converter in
            // `js_transferable.js`, which rejects a non-sequence `transfer`
            // before the native layer sees it.
            throw_type_error_with_code(
                scope,
                "ERR_INVALID_ARG_TYPE",
                "Failed to execute 'structuredClone': transfer in Options \
                 cannot be converted to sequence.",
            );
            return;
        }
        // V8 already scheduled the exception.
        Err(serialize::SerializeError::Thrown) => return,
    };
    match deserialize::deserialize(scope, &message) {
        Ok(deserialized) => rv.set(deserialized.value),
        Err(()) => {
            throw_type_error(
                scope,
                "structuredClone: the serialized value could not be read back",
            );
        }
    }
}

/// `options.transfer`, or `undefined` when there is no options object.
fn transfer_list_from_options<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    options: v8::Local<'s, v8::Value>,
) -> v8::Local<'s, v8::Value> {
    let Ok(options) = v8::Local::<v8::Object>::try_from(options) else {
        return v8::undefined(scope).into();
    };
    let Some(key) = v8::String::new(scope, "transfer") else {
        return v8::undefined(scope).into();
    };
    options
        .get(scope, key.into())
        .unwrap_or_else(|| v8::undefined(scope).into())
}

/// [`throw_data_clone_exception`] for a Rust-side message.
pub(crate) fn throw_data_clone_exception_str(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    throw_data_clone_exception(scope, text.into());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    Ok(rn_core::named_method(scope, name, callback)?.into())
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
    fn the_member_and_deferral_lists_do_not_overlap() {
        for (deferred, _) in DEFERRED {
            assert!(
                !MEMBERS.contains(deferred),
                "{deferred} cannot be both installed and deferred"
            );
        }
    }

    #[test]
    fn every_contract_member_is_accounted_for() {
        // 12 recorded members: 10 installed, 2 deferred.
        assert_eq!(MEMBERS.len() + DEFERRED.len(), 12);
    }

    #[test]
    fn every_contract_member_is_named_in_the_contract() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/messaging.json"))
                .expect("the messaging contract parses");
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
    fn the_deferred_members_each_carry_a_reason() {
        // `tools/deferred-reach.py` parses these, and an empty reason would make
        // a deferral indistinguishable from an oversight.
        for (member, reason) in DEFERRED {
            assert!(!reason.is_empty(), "{member} is deferred with no reason");
        }
    }
}
