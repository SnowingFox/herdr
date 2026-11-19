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
    let primordials =
        primordials(scope).ok_or("the realm bootstrap has not recorded its primordials yet")?;
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
/// The realm's `primordials` object.
///
/// Read from the hook slot, not from `globalThis`: Node's `primordials` is a
/// bootstrap-local that is never a global, and a process where
/// `Object.getOwnPropertyNames(globalThis)` carries it fails Node's own
/// `test/common/index.js` globals audit. This used to read the global because
/// the bootstrap put it there; the bootstrap now records it instead.
fn primordials<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    rn_core::hook_slot::primordials(scope)
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
/// This is `MessagePort::OnMessage` + `ReceiveMessage` (`src/node_messaging.cc`).
/// Two details of that pair are load-bearing and were both missing:
///
/// * A close marker is honoured **even for a port that is not receiving**.
///   `ReceiveMessage` peeks the queue's front and bails out with
///   `no_message_symbol` only when the front is *not* a close message, so a close
///   is the one thing a listener-less port still notices.
/// * A close marker calls `Close()` on the receiver. That is what drops the
///   port's handle, and skipping it is why a port whose peer had closed went on
///   pinning the loop forever: `close` fired, the state never changed, and
///   `keeps_loop_alive` kept answering `true`.
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

    let mut delivered = false;
    // A port with work to do is a live handle, so its wrapper is rooted before any
    // delivery is attempted: the queue is delivered to that wrapper, and one that
    // was collected while a message waited would drop the message with no event.
    // This is Node's `ClearWeak()` in `BaseObject::increase_refcount`, applied to
    // the port half of the rule (`receiving_messages_`).
    port.pin_for_delivery(scope);
    for _ in 0..PROCESSING_LIMIT {
        // The close marker is read before anything else, which is Node's order:
        // `ReceiveMessage` peeks the front and returns to `OnMessage`, which only
        // checks `IsDetached()` *before* the loop, so a port that went closing
        // while a marker was queued still consumes it. The same order matters for
        // a normal message: `data_` going null is the detached case, and a port
        // that merely started closing keeps its queue.
        if port.closed.get() {
            return delivered;
        }
        let Some(object) = port.object(scope) else {
            return delivered;
        };
        // `ReceiveMessage`'s `wants_message` gate: a port that is not receiving
        // consumes a queued entry only when the front is a close marker. Anything
        // else stays in the queue for `receiveMessageOnPort`, which is how Node
        // lets a listener-less port hold its messages — `port1.postMessage(x)`
        // with no listener on `port2`, then `receiveMessageOnPort(port2)` later,
        // returns the message on Node and returned `undefined` here.
        //
        // The close marker is exempt because Node's condition is
        // `!wants_message && !front->IsCloseMessage()`: a port whose peer went away
        // must notice even with no listener.
        if !port.receiving.get() && port.data.front_is_close() != Some(true) {
            return delivered;
        }
        let Some(message) = port.data.dequeue() else {
            return delivered;
        };
        if message.close {
            // `if (received->IsCloseMessage()) { Close(); return no_message_symbol; }`.
            // `close()` queues the close event for the close phase and marks the
            // port closing, so `keeps_loop_alive` stops seeing it — and the
            // event is dispatched by [`run`]'s close loop exactly once, the same
            // way a self-initiated `close()` is.
            port.clone().close_quietly();
            return delivered;
        }

        // A parse failure is reported as a `messageerror` event, not as an
        // uncaught exception, so the read runs inside its own `TryCatch` and a
        // caught exception never escapes to the loop.
        //
        // The exception is kept, not discarded. `test-worker-message-port-transfer-
        // fake-js-transferable.js` reads `exception.message` off the event and
        // expects `Missing internal module '<path>'`, which is the error the
        // receiving create-object hook threw while rebuilding the transferred
        // object — the only place that message exists. Emitting `undefined` made
        // every `messageerror` payload empty, so a listener could not tell a
        // context mismatch from a bad `deserializeInfo` at all.
        let payload = {
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let scope = &mut try_catch.init();
            // The port object's own creation context, which is Node's
            // `GetCreationContextChecked()` and the reason a port moved with
            // `moveMessagePortToContext` receives into the realm it was moved to.
            let target = object.get_creation_context(scope).unwrap_or_else(|| {
                scope.get_current_context()
            });
            match deserialize::deserialize(scope, &message, target) {
                Ok(deserialized) => Ok((
                    v8::Global::new(scope, deserialized.value),
                    deserialized.ports,
                )),
                Err(()) => Err(scope
                    .exception()
                    .map(|exception| v8::Global::new(scope, exception))),
            }
        };

        match payload {
            Ok((value, ports)) => {
                let value: v8::Local<v8::Value> = v8::Local::new(scope, &value);
                emit_message(scope, emit, object, value, &ports, "message");
                delivered = true;
            }
            Err(exception) => {
                // Node's `OnMessage` catches the parse failure and emits
                // `messageerror` with the caught exception as its payload. When
                // the failure was reported by returning `Err` without throwing —
                // a payload V8 refused to read, say — there is nothing to pass,
                // and `undefined` is Node's own answer for a throw of no value.
                let error: v8::Local<v8::Value> = match &exception {
                    Some(exception) => v8::Local::new(scope, exception),
                    None => v8::undefined(scope).into(),
                };
                emit_message(scope, emit, object, error, &[], "messageerror");
                delivered = true;
            }
        }
    }
    // The budget ran out with messages left; the loop will run this port again.
    crate::port::requeue(vec![Rc::clone(port)]);
    delivered
}

/// Calls `emitMessage(data, ports, type)` with `this` as the port.
///
/// `kind` is `'message'` or `'messageerror'`, and it is a parameter rather than a
/// constant because `emitMessage` dispatches on it: `messageport.js` calls
/// `kHybridDispatch(event, kind)` and falls back to `onmessage`/`onmessageerror`
/// by comparing the string. Hard-coding `'message'` made every deserialize
/// failure arrive as a `message` event whose data happened to be the exception,
/// so `port2.on('messageerror')` never ran and the test hung waiting for it.
fn emit_message<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    emit: v8::Local<'s, v8::Function>,
    object: v8::Local<'s, v8::Object>,
    data: v8::Local<'s, v8::Value>,
    ports: &[v8::Global<v8::Object>],
    kind: &str,
) {
    let ports = ports_array(scope, ports);
    let Some(kind) = v8::String::new(scope, kind) else {
        return;
    };
    let arguments = [data, ports, kind.into()];
    // A throw inside a `'message'` listener is uncaught: the message arrived from
    // the port's own delivery, not from a call the user made. Node's
    // `MakeCallback` routes it through `TriggerUncaughtException`; ignoring the
    // result prints it and still exits 0.
    let caught = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
        let inner = &mut try_catch.init();
        let _ = emit.call(inner, object.into(), &arguments);
        inner
            .exception()
            .map(|exception| v8::Global::new(inner, exception))
    };
    if let Some(caught) = caught {
        let exception = v8::Local::new(&*scope, &caught);
        rn_errors::report_uncaught_exception(scope, exception);
    }
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
    //
    // Only an event that *earned this iteration* is dispatched. An event owed by a
    // port that a close marker closed was queued during the delivery loop above,
    // and Node dispatches it in a later close phase — which exists only if
    // something else keeps the loop turning. Dispatching it here would be that
    // later phase happening immediately, and `port2.on('close', f);
    // port1.close()` would print what Node does not.
    let mut owed_later = Vec::new();
    for owed in take_closing() {
        // An event a close marker queued is dispatched one phase later, which is
        // Node's ordering: the marker is consumed in this phase and the event
        // belongs to the next one, if there is one.
        if !owed.creates_iteration && owed.deferred == 0 {
            owed_later.push(crate::port::CloseOwed {
                port: owed.port,
                creates_iteration: false,
                deferred: 1,
            });
            continue;
        }
        let port = owed.port;
        let Some(object) = port.object(scope) else {
            port.mark_closed();
            continue;
        };
        close_event(scope, object);
        port.mark_closed();
        worked = true;
    }
    if !owed_later.is_empty() {
        crate::port::requeue_closing(owed_later);
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
/// Whether a delivery is queued for the check phase.
///
/// `uv__loop_alive` has three terms, and the runtime has to consult the same
/// three or it stops the loop before the phase that would drain its queue:
///
/// * `uv__has_active_handles` — a ref'd port, which is
///   [`any_keeps_loop_alive`]'s first two cases.
/// * `closing_handles` — a port that closed and still owes its `close` event,
///   which is the third.
/// * **queued work that has not run yet.** rustnode's stand-in for a
///   `uv_async_send` is a `PENDING` entry, and unlike libuv's async handle it is
///   not itself a handle the loop counts. So a queued delivery has to be reported
///   here, or a worker whose script has returned would end its thread with the
///   message still in `PENDING` — measured: `parentPort.postMessage` from a worker
///   script body never reached the parent.
///
/// A *close marker on a listener-less port* is the one case where the queue must
/// not force an iteration. `port2.on('close', f); port1.close()` prints nothing
/// under Node, because the peer's marker is queued by the close phase and nothing
/// refs the loop after it; forcing an iteration there would dispatch an event Node
/// never delivers, and it would also spin, since the drain re-queues nothing and
/// the predicate stayed true.
pub fn has_delivery_pending() -> bool {
    crate::port::any_keeps_loop_alive() || crate::port::has_deliverable_message()
}
