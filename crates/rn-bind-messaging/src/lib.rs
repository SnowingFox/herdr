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
//! * `receiveMessageOnPort`, `drainMessagePort` and `stopMessagePort` read and
//!   control that same queue.
//! * Transferring an `ArrayBuffer` detaches it on the sender; transferring a
//!   `MessagePort` moves it.
//!
//! # What is deferred, and why
//!
//! `moveMessagePortToContext` needs the `vm` context a port is retargeted at, and
//! `broadcastChannel` needs a named sibling group whose members sit in more than
//! one thread. Both are listed in [`DEFERRED`] with the reason, and
//! `tools/deferred-reach.py` confirms neither is called while a module loads.
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
mod port;
mod serialize;

use std::cell::RefCell;
use std::rc::Rc;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::port::{MessagePortData, PortInner};

pub use crate::delivery::{
    emit_message_installed, has_delivery_pending, install_emit_message, run as run_message_ports,
};
pub use crate::port::set_check_phase_armed;

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
    "drainMessagePort",
    "exposeLazyDOMExceptionProperty",
    "receiveMessageOnPort",
    "setDeserializerCreateObjectFunction",
    "stopMessagePort",
    "structuredClone",
];

/// Members this build does not install yet.
pub const DEFERRED: &[(&str, &str)] = &[
    (
        "broadcastChannel",
        "needs a process-wide named sibling group whose participants can live in \
         more than one thread; with no Worker there is no second participant, and a \
         channel that could never receive would hang rather than fail at use",
    ),
    (
        "moveMessagePortToContext",
        "needs contextify to supply the target vm context a port is moved into",
    ),
];

/// Internal field holding the `*mut PortSlot` a `MessagePort` owns.
///
/// Node's `MessagePort::kInternalFieldCount` is 1 and holds the
/// `MessagePortData` pointer; this holds the Rust side of the same thing.
const PORT_FIELD: i32 = 0;

thread_local! {
    /// The deserializer object-creation callback `js_transferable.js` installs.
    static CREATE_OBJECT: RefCell<Option<v8::Global<v8::Function>>> =
        const { RefCell::new(None) };

    /// The `MessagePort` instance template, so a transfered port can be rebuilt.
    ///
    /// Node calls `GetMessagePortConstructorTemplate(...)->InstanceTemplate()
    /// ->NewInstance(context)`, which creates the object *without* running the
    /// constructor callback. `Function::new_instance` would run it, and the
    /// constructor deliberately throws.
    static INSTANCE_TEMPLATE: RefCell<Option<v8::Global<v8::ObjectTemplate>>> =
        const { RefCell::new(None) };
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

        let values: [(&str, v8::Local<v8::Value>); 10] = [
            ("DOMException", dom_exception_constructor(scope)),
            ("MessageChannel", message_channel),
            ("MessagePort", message_port),
            ("QuotaExceededError", quota_exceeded_error(scope)),
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
    let template = v8::FunctionTemplate::builder(handle_wrap_constructor).build(scope);
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
    let template = v8::FunctionTemplate::builder(method).build(scope);
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

    let template = v8::FunctionTemplate::builder(message_port_constructor).build(scope);
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
    INSTANCE_TEMPLATE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, instance)));
    Ok(constructor.into())
}

/// Installs the `MessageChannel` constructor and returns it as a value.
fn install_message_channel<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(message_channel_constructor).build(scope);
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
    data: Rc<MessagePortData>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let instance_template = INSTANCE_TEMPLATE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|template| v8::Local::new(scope, template))
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

/// Rebuilds a port around an existing queue, for `MessagePort` transfer.
///
/// The sender is detached first: a transferred port has to refuse to post or
/// receive, or the two objects would share one queue.
fn clone_port_into<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Object>> {
    let state = port_state_of(scope, source)?;
    state.detach_for_transfer();
    let data = Rc::clone(&state.data);
    new_port_object(scope, data).ok()
}

/// Throws a `TypeError` carrying `message`.
pub fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
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
    throw_type_error(scope, "Constructor cannot be called");
}

fn message_channel_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(scope, "Cannot call constructor without `new`");
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
    // still has to be validated and a clone error still has to be raised.
    let (message, ports) = match serialize::serialize(scope, args.get(0), args.get(1)) {
        Ok(pair) => pair,
        Err(Some(text)) => {
            throw_type_error(scope, &text);
            return;
        }
        Err(None) => return,
    };

    if state.closing.get() {
        rv.set(v8::Boolean::new(scope, true).into());
        return;
    }

    // Node's `PostMessage` dispatches into the group, whose members are reached
    // through the sender's `MessagePortData`.
    let dispatched = state.data.dispatch(&message);
    if !dispatched {
        // Node emits a warning rather than throwing, so a script that posts on a
        // detached port keeps running.
        rn_core::hook_slot::write_stderr("Warning: MessagePortData is not entangled.\n");
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    }

    // A transferred port is detached here and rebuilt on the receiving side by
    // the deserializer, which moves the queue rather than copying it. The port
    // travels inside the serialized payload because `write_host_object` wrote its
    // id there, so nothing extra is queued.
    for port in ports {
        let object: v8::Local<v8::Object> = v8::Local::new(scope, &port);
        if let Some(transferred) = port_state_of(scope, object) {
            transferred.detach_for_transfer();
        }
    }

    // Wake every port that now has something to read.
    for peer in state.data.peers() {
        if let Some(owner) = peer.owner() {
            owner.schedule();
        }
    }
    rv.set(v8::Boolean::new(scope, true).into());
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
        state.refed.set(true);
    }
}

fn handle_wrap_unref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    if let Some(state) = port_state_of(scope, this) {
        state.refed.set(false);
    }
}

fn handle_wrap_has_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    let refed = port_state_of(scope, this)
        .map(|state| state.refed.get() && !state.closing.get())
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
    if state.closing.get() {
        set_no_message(scope, &mut rv);
        return;
    }
    let Some(message) = state.data.dequeue() else {
        set_no_message(scope, &mut rv);
        return;
    };
    if message.close {
        state.close();
        set_no_message(scope, &mut rv);
        return;
    }
    match deserialize::deserialize(scope, &message.data, &message.array_buffers) {
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
        throw_type_error(
            scope,
            "The \"port\" argument must be a MessagePort instance",
        );
        return None;
    };
    let state = port_state_of(scope, object);
    if state.is_none() {
        throw_type_error(
            scope,
            "The \"port\" argument must be a MessagePort instance",
        );
    }
    state
}

// ---------------------------------------------------------------------------
// The rest of the namespace
// ---------------------------------------------------------------------------

/// A `DOMException` built the way the platform expects.
///
/// `lib/internal/util.js` uses this for `AbortSignal` and the web streams, so it
/// needs `name`, `message` and `code` to behave.
fn dom_exception_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let template = v8::FunctionTemplate::builder(new_dom_exception).build(scope);
    if let Some(name) = v8::String::new(scope, "DOMException") {
        template.set_class_name(name);
    }
    match template.get_function(scope) {
        Some(function) => function.into(),
        None => v8::undefined(scope).into(),
    }
}

fn new_dom_exception(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let message = args
        .get(0)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let name = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_else(|| "Error".to_string());

    let object = args.this();
    let values: [(&str, String); 2] = [("message", message.clone()), ("name", name.clone())];
    for (key, value) in values {
        if let (Some(key), Some(text)) =
            (v8::String::new(scope, key), v8::String::new(scope, &value))
        {
            object.set(scope, key.into(), text.into());
        }
    }
    if let Some(key) = v8::String::new(scope, "code") {
        object.set(scope, key.into(), v8::Integer::new(scope, 0).into());
    }
    rv.set(object.into());
}

fn quota_exceeded_error<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let template = v8::FunctionTemplate::builder(new_quota_exceeded_error).build(scope);
    if let Some(name) = v8::String::new(scope, "QuotaExceededError") {
        template.set_class_name(name);
    }
    match template.get_function(scope) {
        Some(function) => function.into(),
        None => v8::undefined(scope).into(),
    }
}

fn new_quota_exceeded_error(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // A `QuotaExceededError` is a `DOMException` with a fixed name and code.
    let message = args
        .get(0)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let object = args.this();
    if let (Some(key), Some(text)) = (
        v8::String::new(scope, "message"),
        v8::String::new(scope, &message),
    ) {
        object.set(scope, key.into(), text.into());
    }
    if let (Some(key), Some(text)) = (
        v8::String::new(scope, "name"),
        v8::String::new(scope, "QuotaExceededError"),
    ) {
        object.set(scope, key.into(), text.into());
    }
    if let Some(key) = v8::String::new(scope, "code") {
        // QUOTA_EXCEEDED_ERR is 22 in the DOM spec.
        object.set(scope, key.into(), v8::Integer::new(scope, 22).into());
    }
    rv.set(object.into());
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
    // The constructor is installed eagerly rather than lazily because it is a
    // single function template that `MessagePort` already needs: there is nothing
    // to defer, and an accessor that only forwards to the constructor would add a
    // getter to the startup path for no saving.
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
    let descriptor = v8::PropertyDescriptor::new_from_value_writable(constructor, true);
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
    let callback = v8::Local::<v8::Function>::try_from(args.get(0))
        .ok()
        .map(|callback| v8::Global::new(scope, callback));
    CREATE_OBJECT.with(|slot| *slot.borrow_mut() = callback);
}

/// The delegate that makes plain (non-host) values serializable.
struct PlainSerializer;

impl v8::ValueSerializerImpl for PlainSerializer {
    fn throw_data_clone_error<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        message: v8::Local<'s, v8::String>,
    ) {
        // V8 gives the message; the exception type is the platform's.
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
    }

    fn is_host_object<'s>(
        &self,
        _scope: &mut v8::PinScope<'s, '_>,
        _object: v8::Local<'s, v8::Object>,
    ) -> Option<bool> {
        // No host objects are registered, so nothing is one. Returning `None`
        // here would abort the clone; `Some(false)` is the correct answer.
        Some(false)
    }
}

fn structured_clone(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = args.get(0);
    let serializer = v8::ValueSerializer::new(scope, Box::new(PlainSerializer));
    let Some(true) = serializer.write_value(scope.get_current_context(), value) else {
        // V8 has already thrown, which is what `structuredClone` should do for
        // an uncloneable value (a function, a WeakMap, a symbol).
        return;
    };
    let data = serializer.release();

    let deserializer = v8::ValueDeserializer::new(scope, Box::new(PlainDeserializer), &data);
    match deserializer.read_value(scope.get_current_context()) {
        Some(cloned) => rv.set(cloned),
        None => {
            // A read failure means the bytes were malformed, which cannot
            // happen from a clone we just wrote; throwing keeps it visible.
            throw_type_error(
                scope,
                "structuredClone: the serialized value could not be read back",
            );
        }
    }
}

struct PlainDeserializer;

impl v8::ValueDeserializerImpl for PlainDeserializer {
    fn get_shared_array_buffer_from_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _id: u32,
    ) -> Option<v8::Local<'s, v8::SharedArrayBuffer>> {
        throw_type_error(scope, "structuredClone cannot transfer a SharedArrayBuffer");
        None
    }

    fn get_wasm_module_from_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _id: u32,
    ) -> Option<v8::Local<'s, v8::WasmModuleObject>> {
        throw_type_error(
            scope,
            "structuredClone cannot transfer a WebAssembly.Module",
        );
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
