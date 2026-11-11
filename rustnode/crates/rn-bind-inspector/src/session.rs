//! `inspector.Connection`: one CDP session driven from JavaScript.
//!
//! `lib/inspector.js` builds `Session` on top of this class:
//!
//! ```js
//! this.#connection = new Connection((message) => this.#onMessage(message));
//! this.#connection.dispatch(JSONStringify({ id, method, params }));
//! this.#connection.disconnect();
//! ```
//!
//! So the class is a *transport*, not a protocol implementation. It hands the raw
//! string to V8's inspector and reports whatever comes back, and all of CDP —
//! `Runtime.evaluate`, `Profiler.start`, `Debugger.*` — arrives through that one
//! path. That is why this file is small and why its tests can assert real protocol
//! behaviour instead of the shape of an object.
//!
//! # Replies are synchronous unless they cannot be
//!
//! V8 calls the channel's `send_response` from inside `dispatch`, so the callback
//! `lib/inspector.js` registered runs before `dispatch` returns. That ordering is
//! observable and Node relies on it: `session.post('Runtime.evaluate', cb)`
//! followed by an assertion on the next line passes. The exception is a reply
//! produced *while* a reply is being delivered — a callback that posts again — or
//! one produced from a GC callback, where entering JavaScript is illegal. Those
//! are queued and delivered after the outermost delivery, which is what Node's
//! `ScheduleFlush` does.
//!
//! # Where the session lives
//!
//! In a thread-local slot table rather than through a pointer cycle
//! (object → state → session → channel → state). A session holds its channel, the
//! channel has to reach the JavaScript callback, and the object has to reach the
//! session: any direct arrangement of those links is a cycle that leaks or dangles
//! depending on which half is freed first. The table breaks it — the channel holds
//! a slot *index*, the object holds the same index, and both reach one entry whose
//! lifetime the table owns.
//!
//! During `dispatch` the session is moved out of its slot, so the reply path can
//! borrow the slot freely. It is put back afterwards unless something (a re-entrant
//! `disconnect()`) cleared `live` meanwhile, in which case it is dropped here.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::agent;

/// The internal field holding a connection's slot index.
const SLOT_FIELD: i32 = 0;

/// One open connection.
struct Connection {
    /// The session, while it is not mid-dispatch.
    session: Option<&'static v8::inspector::V8InspectorSession>,
    /// The JavaScript callback that receives inspector messages.
    callback: Option<v8::Global<v8::Function>>,
    /// Cleared by `disconnect()`, so a late reply is dropped rather than
    /// resurrecting a session the caller closed.
    live: bool,
}

impl Connection {
    fn new(callback: v8::Global<v8::Function>) -> Self {
        Self {
            session: None,
            callback: Some(callback),
            live: true,
        }
    }
}

thread_local! {
    static SLOTS: RefCell<Vec<Option<Connection>>> = const { RefCell::new(Vec::new()) };
}

/// Creates a slot for `connection`, reusing a freed one when possible.
fn allocate_slot(connection: Connection) -> usize {
    SLOTS.with(|slots| {
        let mut slots = slots.borrow_mut();
        if let Some(index) = slots.iter().position(Option::is_none) {
            slots[index] = Some(connection);
            return index;
        }
        slots.push(Some(connection));
        slots.len() - 1
    })
}

/// Runs `body` against the connection in `index`, if it is still there.
fn with_slot<R>(index: usize, body: impl FnOnce(&mut Connection) -> R) -> Option<R> {
    SLOTS.with(|slots| {
        let mut slots = slots.borrow_mut();
        let connection = slots.get_mut(index)?.as_mut()?;
        Some(body(connection))
    })
}

/// Empties a slot, dropping whatever it holds.
///
/// The drop happens after the borrow is released because dropping a session drops
/// its channel, and the channel borrows the same table when V8 tears the session
/// down.
fn free_slot(index: usize) {
    let connection = SLOTS.with(|slots| slots.borrow_mut().get_mut(index).and_then(Option::take));
    drop(connection);
}

/// Converts an inspector `StringView` to a Rust string.
///
/// The 8-bit case is Latin-1 rather than ASCII — V8 returns an 8-bit view for a
/// message built from an 8-bit buffer — so those bytes are widened to code points
/// instead of being treated as UTF-8. Assuming UTF-8 turns a non-ASCII
/// `Runtime.evaluate` result into replacement characters.
pub fn string_view_to_string(view: &v8::inspector::StringView<'_>) -> String {
    match (view.characters8(), view.characters16()) {
        (Some(bytes), _) => bytes.iter().map(|byte| char::from(*byte)).collect(),
        (_, Some(units)) => String::from_utf16_lossy(units),
        _ => String::new(),
    }
}

/// The V8 channel for one connection.
struct ConnectionChannel {
    index: usize,
}

impl v8::inspector::ChannelImpl for ConnectionChannel {
    fn send_response(
        &self,
        _call_id: i32,
        mut message: v8::UniquePtr<v8::inspector::StringBuffer>,
    ) {
        let text = message
            .as_mut()
            .map(|buffer| string_view_to_string(&buffer.string()))
            .unwrap_or_default();
        deliver(self.index, text);
    }

    fn send_notification(&self, mut message: v8::UniquePtr<v8::inspector::StringBuffer>) {
        let text = message
            .as_mut()
            .map(|buffer| string_view_to_string(&buffer.string()))
            .unwrap_or_default();
        deliver(self.index, text);
    }

    fn flush_protocol_notifications(&self) {}
}

/// Hands `text` to the JavaScript callback.
///
/// Synchronous and re-entrant, which is what `lib/inspector.js` is written against: a
/// callback that posts another command has its reply delivered inside the post, so
/// `session.post('Profiler.enable', () => session.post('Profiler.start', ...))` nests
/// to whatever depth the script writes. Node's `JSBindingsConnection` does exactly
/// this — its delivery guard only covers the GC case and the deferred flush, not a
/// nested dispatch — and a queue here would reorder the replies relative to the
/// scripts that post them.
///
/// Nothing holds the slot's `RefCell` across the call: the callback is cloned out
/// first, so a nested `dispatch` (which takes its own short borrow) cannot panic.
fn deliver(index: usize, text: String) {
    let callback = with_slot(index, |connection| {
        if !connection.live {
            return None;
        }
        connection.callback.clone()
    })
    .flatten();

    let Some(callback) = callback else {
        return;
    };
    // A delivery happens either inside `dispatch`, which the caller entered through a
    // V8 scope, or from a loop callback with none open. `with_context` establishes a
    // handle scope and enters the context, which the second case requires and the
    // first tolerates.
    rn_uv::callback::with_context(|scope| {
        let function = v8::Local::new(scope, &callback);
        let Some(text) = v8::String::new(scope, &text) else {
            return;
        };
        let undefined = v8::undefined(scope).into();
        let _ = function.call(scope, undefined, &[text.into()]);
    });
}

/// `new Connection(callback)` — opens a session against the inspector.
fn constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(scope, "Connection requires a callback function");
        return;
    };

    // `Session.connect()` is legal without `open()` — `lib/internal/util/inspector.js`
    // uses exactly that to talk to the inspector in-process — so the inspector is
    // created here when it does not exist yet rather than requiring `--inspect`.
    if !agent::ensure_inspector(scope) {
        throw_error(
            scope,
            "The inspector is not available: no isolate was recorded",
        );
        return;
    }

    let index = allocate_slot(Connection::new(v8::Global::new(scope, callback)));
    let channel = v8::inspector::Channel::new(Box::new(ConnectionChannel { index }));
    let Some(session) = agent::connect(channel) else {
        // The channel is dropped with the session, so nothing reaches the slot.
        free_slot(index);
        throw_error(scope, "the inspector could not open a session");
        return;
    };
    with_slot(index, |connection| connection.session = Some(session));

    // V8 requires the stored value to be aligned like a pointer, and rejects
    // anything else with "Unaligned pointer" and an abort. Scaling the index by the
    // pointer size keeps it aligned; `slot_of` divides it back out.
    this.set_aligned_pointer_in_internal_field(
        SLOT_FIELD,
        slot_tag(index) as *const std::ffi::c_void,
        0,
    );
    // A collected object frees its slot, which drops the session. The callback
    // also lives there, so this is what ends the object's reach into V8.
    let weak = v8::Weak::with_guaranteed_finalizer(scope, this, Box::new(move || free_slot(index)));
    std::mem::forget(weak);
    rv.set(this.into());
}

/// The aligned value that encodes a slot index.
///
/// `0` is reserved for "not a connection", so the index is offset by one before being
/// scaled. The scale is the pointer size, which is what makes the value satisfy V8's
/// alignment requirement for an internal field.
fn slot_tag(index: usize) -> usize {
    (index + 1) * std::mem::size_of::<*const std::ffi::c_void>()
}

/// Reads the slot index a connection object carries.
fn slot_of(object: v8::Local<v8::Object>) -> Option<usize> {
    if object.internal_field_count() == 0 {
        return None;
    }
    // SAFETY: the field is written by `constructor` through `slot_tag`, so a non-zero
    // value decodes to the index it was made from.
    let stored = unsafe { object.get_aligned_pointer_from_internal_field(SLOT_FIELD, 0) } as usize;
    if stored == 0 {
        return None;
    }
    Some(stored / std::mem::size_of::<*const std::ffi::c_void>() - 1)
}

/// `connection.dispatch(message)`.
fn dispatch(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(message) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        throw_type_error(scope, "dispatch requires a string");
        return;
    };
    let message = message.to_rust_string_lossy(scope);
    let Some(index) = slot_of(args.this()) else {
        throw_type_error(scope, "dispatch called on a connection that is closed");
        return;
    };

    // The session stays in the slot, so a reply delivered inside `dispatch` can find
    // it again — `deliver` calls the JavaScript callback, which is free to post
    // another command, and that nested `dispatch` looks the session up here. The
    // borrow is released before the call for the same reason: only the raw pointer
    // crosses it.
    let session = with_slot(index, |connection| {
        if !connection.live {
            return None;
        }
        connection.session
    })
    .flatten();
    let Some(session) = session else {
        return;
    };

    // Node asks `V8InspectorSession::canDispatchMethod` first and only falls through to
    // its own dispatcher when V8 says no. This is the same order with the same
    // reasoning: a method V8 owns must reach V8, and one it does not must not be handed
    // to it, or the frontend gets `method not found` for a domain that exists.
    if let Some(reply) = crate::domains::dispatch(&message) {
        for (method, params) in &reply.notifications {
            deliver(
                index,
                crate::domains::Reply::notification_message(method, params),
            );
        }
        deliver(index, reply.to_message());
        return;
    }

    let view = v8::inspector::StringView::from(message.as_bytes());
    session.dispatch_protocol_message(view);

    // A pause requested while this message was being dispatched — `Debugger.pause` is
    // the case that matters — needs its `Debugger.paused` to reach the frontend, and
    // V8 has already produced it by the time `dispatch` returns.
    if crate::pause::pause_requested() && crate::pause::take_pause_request() {
        crate::pause::wake();
    }
}

/// `connection.disconnect()`.
fn disconnect(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(index) = slot_of(args.this()) else {
        return;
    };
    // The session is *not* dropped. V8 owns its storage until the isolate goes away,
    // and a drop here would free a session that a nested dispatch on the stack is
    // still using. Node does the same — `Agent` never frees a session, it only stops
    // routing to it — and the slot's `live` flag is what makes an already-sent reply
    // go nowhere.
    with_slot(index, |connection| {
        connection.live = false;
        connection.callback = None;
        connection.session = None;
    });
}

/// Asks every open `Connection` to pause before its next statement.
///
/// Node's `callAndPauseOnStart` pauses the *agent's* session, which is the one a
/// CDP client attaches to. Here that is every attached frontend session plus every
/// `Connection` a script opened, because there is no separate agent session.
pub fn pause_all(reason: &str) {
    let indices: Vec<usize> = SLOTS.with(|slots| {
        slots
            .borrow()
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_ref().map(|_| index))
            .collect()
    });
    for index in indices {
        with_slot(index, |connection| {
            if let Some(session) = connection.session.as_ref() {
                agent::schedule_pause_on_next_statement(session, reason);
            }
        });
    }
    crate::server::pause_all_sessions(reason);
}

/// Sends `message` to every open `Connection`.
pub fn broadcast(message: &str) {
    let indices: Vec<usize> = SLOTS.with(|slots| {
        slots
            .borrow()
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_ref().map(|_| index))
            .collect()
    });
    for index in indices {
        deliver(index, message.to_string());
    }
}

fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(message) = v8::String::new(scope, message) {
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
    }
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(message) = v8::String::new(scope, message) {
        let exception = v8::Exception::type_error(scope, message);
        scope.throw_exception(exception);
    }
}

/// Installs `Connection` on the namespace object under `name`.
///
/// `MainThreadConnection` is the same class: its only difference in Node is that
/// it connects to *another* environment's agent, and rustnode has one environment.
pub fn install_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &'static str,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template.set_class_name(v8::String::new(scope, name).ok_or("cannot allocate the class name")?);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    // `SetProtoMethod` in Node: the *template* goes on the prototype template, not
    // an instantiated function. V8 rejects anything else with "Invalid value, must
    // be a primitive or a Template" and aborts the process, which is a hard crash
    // rather than a compile error.
    let methods = [
        (
            "dispatch",
            v8::FunctionTemplate::builder(dispatch).build(scope),
        ),
        (
            "disconnect",
            v8::FunctionTemplate::builder(disconnect).build(scope),
        ),
    ];
    for (method, function) in methods {
        let key = v8::String::new(scope, method)
            .ok_or_else(|| format!("cannot allocate the name {method}"))?;
        template
            .prototype_template(scope)
            .set(key.into(), function.into());
    }

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the Connection constructor")?;
    let key = v8::String::new(scope, name).ok_or("cannot allocate the namespace key")?;
    target.set(scope, key.into(), constructor.into());
    Ok(())
}
