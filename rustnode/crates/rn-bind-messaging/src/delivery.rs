//! Delivering queued messages to a port's `message` event.
//!
//! This is `MessagePort::OnMessage`. Node runs it from a `uv_async_t` callback;
//! the event loop calls [`run`] from its check phase instead, which is where
//! libuv would have run the same work.
//!
//! # What it calls
//!
//! `emitMessage(data, ports, type)` from `internal/per_context/messageport`, the
//! per-context export Node's `GetEmitMessageFunction` looks up. That function
//! calls `this[kHybridDispatch]` — which `initNodeEventTarget` installed — and
//! that is what invokes the `message` listeners, the `onmessage` handler, and
//! the `kCreateEvent` override `io.js` defines for `MessageEvent`.
//!
//! # Why the per-context function has to be fetched rather than constructed
//!
//! `emitMessage` is one function per realm, not one per port, and it is written
//! in JavaScript. Re-implementing it here would mean re-implementing the
//! `kCurrentlyReceivingPorts` handshake that `io.js` uses to attach transferred
//! ports to the event, so it is compiled once from the vendored source and
//! rooted.

use std::cell::RefCell;
use std::rc::Rc;

use rn_v8_sys::v8;

use crate::deserialize;
use crate::port::{take_closing, take_pending, PortInner};

thread_local! {
    /// `emitMessage`, from `internal/per_context/messageport`.
    ///
    /// Rooted because a delivery happens long after the module that produced it
    /// has finished running.
    static EMIT_MESSAGE: RefCell<Option<v8::Global<v8::Function>>> = const { RefCell::new(None) };
}

/// Compiles `internal/per_context/messageport` and roots its `emitMessage`.
///
/// `load` is what compiles a per-context builtin by id; the CLI owns it because
/// the builtin table belongs to `rn-builtins`. Keeping the dependency as a
/// callback is what lets this crate stay a binding crate rather than reaching
/// into the module system.
///
/// Returns the reason it could not install when the builtin is missing or its
/// source throws, so the CLI can say why delivery is unavailable instead of
/// letting every port silently drop messages.
pub fn install_emit_message<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    load: impl FnOnce(&mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>>,
) -> Result<(), String> {
    // Node's `GetEmitMessageFunction` reads `emitMessage` off
    // `GetPerContextExports`: `internal/per_context/messageport` already ran
    // during the realm bootstrap and put it there. Taking the same path means one
    // compile per realm and one `exports` object, so the function a port delivers
    // through is the one the bootstrap produced.
    if let Some(exports) = rn_core::per_context_exports(scope) {
        if let Some(emit) = function_named(scope, exports, "emitMessage") {
            EMIT_MESSAGE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, emit)));
            return Ok(());
        }
    }

    let function = load(scope).ok_or("internal/per_context/messageport could not be compiled")?;

    // The kind is `kPerContextScript`, whose parameters are
    // `(exports, primordials, privateSymbols, perIsolateSymbols)`.
    //
    // `messageport.js` reads only `SymbolFor` from `primordials` at module scope,
    // but the two symbol objects are supplied from the same builders the
    // bootstrap uses anyway: passing an empty object is how the per-context
    // scripts came to be run against missing globals in the first place, and a
    // script that starts reading one of them would fail here rather than
    // silently see `undefined`.
    let exports = v8::Object::new(scope);
    let primordials = primordials_from_global(scope)
        .ok_or("the primordials global is missing; the realm bootstrap has not run")?;
    let private_symbols = rn_core::private_symbols_object(scope)
        .map_err(|reason| format!("cannot build privateSymbols: {reason}"))?;
    let per_isolate_symbols = rn_core::per_isolate_symbols_object(scope)
        .map_err(|reason| format!("cannot build perIsolateSymbols: {reason}"))?;

    let arguments = [
        exports.into(),
        primordials.into(),
        private_symbols.into(),
        per_isolate_symbols.into(),
    ];
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let _ = function.call(scope, exports.into(), &arguments);
    if scope.has_caught() {
        let message = scope
            .exception()
            .map(|exception| exception.to_rust_string_lossy(scope))
            .unwrap_or_default();
        return Err(format!("internal/per_context/messageport threw: {message}"));
    }

    let emit = function_named(scope, exports, "emitMessage")
        .ok_or("internal/per_context/messageport has no emitMessage")?;
    EMIT_MESSAGE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, emit)));
    Ok(())
}

/// `object[name]` when it is a function.
fn function_named<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, name)?;
    let value = object.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

/// Reads the `primordials` global the realm bootstrap installs.
///
/// `bootstrap.rs` sets it on the global because `realm.js` reads it as a bare
/// identifier inside its wrapper, so the same object is reachable here.
fn primordials_from_global<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "primordials")?;
    let value = global.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Whether `emitMessage` has been installed.
pub fn emit_message_installed() -> bool {
    EMIT_MESSAGE.with(|slot| slot.borrow().is_some())
}

/// Node's per-turn message budget.
///
/// `MessagePort::OnMessage` stops after at least 1000 messages and re-triggers
/// the handle for the rest, so one busy channel cannot starve the timer phase.
const PROCESSING_LIMIT: usize = 1000;

/// Delivers everything queued for `port`.
///
/// Returns whether a message was delivered, which the loop uses to decide
/// whether another turn is warranted.
pub fn deliver<'s>(scope: &mut v8::PinScope<'s, '_>, port: &Rc<PortInner>) -> bool {
    let Some(emit) = EMIT_MESSAGE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|function| v8::Local::new(scope, function))
    }) else {
        return false;
    };
    if port.closing.get() {
        return false;
    }

    let mut delivered = false;
    for _ in 0..PROCESSING_LIMIT {
        let Some(object) = port.object(scope) else {
            // The JavaScript object was collected; there is nothing left to
            // dispatch to, and the queue goes with it.
            return delivered;
        };
        let Some(message) = port.data.dequeue() else {
            return delivered;
        };
        if message.close {
            // A close marker is delivered as a `close` event, which is the
            // `handle_onclose` hook `io.js` installs on the prototype.
            close_event(scope, object);
            return delivered;
        }

        // A parse failure is reported as a `messageerror` event, not as an
        // uncaught exception, so the read runs inside its own `TryCatch` and a
        // caught exception never escapes to the loop.
        let payload = {
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let scope = &mut try_catch.init();
            deserialize::deserialize(scope, &message)
                .ok()
                .map(|payload| (v8::Global::new(scope, payload.value), payload.ports))
        };

        match payload {
            Some((value, ports)) => {
                let value: v8::Local<v8::Value> = v8::Local::new(scope, &value);
                emit_message(scope, emit, object, value, &ports);
                delivered = true;
            }
            None => {
                // Node's `OnMessage` catches the parse failure and emits
                // `messageerror` with the exception as its payload.
                let error: v8::Local<v8::Value> = v8::undefined(scope).into();
                emit_message(scope, emit, object, error, &[]);
                delivered = true;
            }
        }
    }
    // The budget ran out with messages left; the loop will run this port again.
    crate::port::requeue(vec![Rc::clone(port)]);
    delivered
}

/// Calls `emitMessage(data, ports, type)` with `this` as the port.
fn emit_message<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    emit: v8::Local<'s, v8::Function>,
    object: v8::Local<'s, v8::Object>,
    data: v8::Local<'s, v8::Value>,
    ports: &[v8::Global<v8::Object>],
) {
    let ports = ports_array(scope, ports);
    let Some(kind) = v8::String::new(scope, "message") else {
        return;
    };
    let arguments = [data, ports, kind.into()];
    let _ = emit.call(scope, object.into(), &arguments);
}

/// Builds the `ports` argument as an array of the objects a message carried.
fn ports_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    ports: &[v8::Global<v8::Object>],
) -> v8::Local<'s, v8::Value> {
    let array = v8::Array::new(scope, ports.len() as i32);
    for (index, port) in ports.iter().enumerate() {
        let port: v8::Local<v8::Object> = v8::Local::new(scope, port);
        array.set_index(scope, index as u32, port.into());
    }
    array.into()
}

/// Dispatches the `close` event.
///
/// `io.js` installs `onclose` under `handle_onclose` on the prototype and Node's
/// `HandleWrap` calls it after `uv_close` completes, so the event fires from the
/// close phase rather than from `close()` itself.
fn close_event<'s>(scope: &mut v8::PinScope<'s, '_>, object: v8::Local<'s, v8::Object>) {
    let Ok(symbol) = rn_bind_symbols::ensure(scope, "handle_onclose", "handle_onclose") else {
        return;
    };
    let Some(value) = object.get(scope, symbol.into()) else {
        return;
    };
    let Ok(handler) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };
    let _ = handler.call(scope, object.into(), &[]);
}

/// Runs the loop's share of port work: deliver pending messages, then dispatch
/// the close events that are owed.
///
/// Called from the check phase, which is where libuv would have run the async
/// handle a posted message triggers.
pub fn run<'s>(scope: &mut v8::PinScope<'s, '_>) -> bool {
    let mut worked = false;

    for port in take_pending() {
        if deliver(scope, &port) {
            worked = true;
        }
    }

    // A close event is dispatched in the close phase in Node, but the events are
    // owed the moment `close()` runs and the loop only gets one call per phase
    // here. Dispatching them after the messages keeps `close` last, which is the
    // observable part.
    for port in take_closing() {
        let Some(object) = port.object(scope) else {
            continue;
        };
        close_event(scope, object);
        worked = true;
    }

    worked
}

/// Whether any port still has work the loop must run.
pub fn has_work() -> bool {
    crate::port::any_keeps_loop_alive()
}

/// Whether a message or close event is queued for the check phase.
///
/// Distinct from [`has_work`]: a ref'd port pins the process open even with
/// nothing queued, while a posted message needs the check phase to run once. The
/// check handle is started from this predicate, so an idle port does not make the
/// loop run a phase for nothing.
pub fn has_delivery_pending() -> bool {
    crate::port::has_delivery_pending()
}
