//! The SSL callbacks that call into JavaScript.
//!
//! `crypto_tls.cc`'s `SSLInfoCallback` (`:679`) is the one this module lands
//! first, because without it a handshake can complete at the OpenSSL level and
//! `secureConnect` still never fires: `flags_.established` is set *here*, and
//! `onhandshakedone` is what `lib/internal/tls/wrap.js` turns into the event.
//!
//! # R2 is the whole difficulty
//!
//! OpenSSL invokes this callback **on its own stack**, from inside
//! `SSL_do_handshake` or `SSL_read`. The JavaScript it runs can call
//! `destroy()` on the socket, which reaches `destroySSL`, which frees the `SSL`
//! whose stack frame is still live. Node handles this with two mechanisms:
//!
//! 1. `SSLLibraryCallScope` (`crypto_tls.h:47`) raises a depth counter around
//!    every entry into the library, and this callback checks it before calling
//!    JavaScript — so a callback that would re-enter does not;
//! 2. `HandleScope` + `Context::Scope` inside the callback, so it has a scope of
//!    its own even though its caller is C++ with no V8 frame.
//!
//! Here the second is [`rn_uv::callback::with_context`], the same helper
//! `rn_uv::handle::deliver_read` uses for `onread`, and the first is
//! `WrapState::in_library_call`.
//!
//! # No borrow across the call
//!
//! The state is reached through [`crate::state::with_state`], which scopes the
//! `RefCell` borrow to one closure. Everything this module needs is *copied out*
//! under that borrow — the rooted object, whether the handshake just finished,
//! the current time — and the JavaScript runs after it has ended. A callback that
//! destroys the wrap mid-call therefore finds a state that is not borrowed, which
//! is the only way the re-entrancy is survivable at all.

use std::cell::{Cell, RefCell};
use std::os::raw::{c_char, c_int, c_void};
use std::rc::Rc;

use crate::state::WrapState;
use openssl_sys as ffi;
use rn_v8_sys::v8;

/// `TLSWrap::SSLInfoCallback` (`crypto_tls.cc:679`).
///
/// Installed by `SSL_set_info_callback` in [`crate::ssl::Ssl::new`]'s follow-up.
/// `where_` is a bitmask of `SSL_CB_*` constants; only the handshake-start and
/// handshake-done bits are acted on, which is Node's guard on the first line.
///
/// # Safety
///
/// OpenSSL calls this with the `SSL*` that `SSL_set_app_data` named, and `arg`
/// is the address of that wrap's `RefCell<WrapState>` — the value
/// [`crate::ssl::Ssl::set_app_data`] was given. Both are live for the duration of
/// the call by construction: the wrap cannot be destroyed while its own `SSL` is
/// inside a library call.
pub unsafe extern "C" fn info(ssl: *const ffi::SSL, where_: c_int, _ret: c_int) {
    if where_ & (crate::ffi_extra::SSL_CB_HANDSHAKE_START | crate::ffi_extra::SSL_CB_HANDSHAKE_DONE)
        == 0
    {
        return;
    }
    if ssl.is_null() {
        return;
    }
    // SAFETY: the caller guarantees the pairing, per this function's contract.
    let data = unsafe { ffi::SSL_get_ex_data(ssl, 0) };
    if data.is_null() {
        return;
    }
    let cell = data as *const std::cell::RefCell<WrapState>;

    // Everything the JavaScript needs is taken from the *slot*, not from the
    // `RefCell`. That distinction is the whole of R2 here: `cycle` holds the
    // `RefCell` borrow across `SSL_read`/`SSL_write`, which is exactly the stack
    // this callback runs on, so `try_borrow` would fail and the handshake would
    // never report itself as finished.
    //
    // Node's C++ has the same split without the borrow: the flag lives in
    // `flags_` and the object in `object()`, both readable while the state
    // machine is running. [`CallbackSlot`] is that: the two fields the callback
    // needs, written once at `wrap()` time and read here without the `RefCell`.
    let Some(slot) = SLOTS.with(|slots| {
        slots
            .borrow()
            .iter()
            .find(|slot| slot.cell == cell)
            .cloned()
    }) else {
        return;
    };
    let Some(object) = slot.object.clone() else {
        return;
    };
    // The depth is recorded so a future callback can check it. The two events
    // this handles are both delivered through `deliver_events`, never from here,
    // so the value is informational at this point.
    let _depth = slot.depth.get();

    // The handshake-done flag is set through the slot, which does not borrow the
    // wrap's `RefCell` — `cycle` is holding it on this very stack.
    if where_ & crate::ffi_extra::SSL_CB_HANDSHAKE_DONE != 0 {
        slot.established.set(true);
    }

    // JavaScript must not run on the library's stack: a handler can call back
    // into the handle, and `wrap.js`'s `onhandshakedone` does exactly that (it
    // writes the finished session, starts the next phase, and can `destroy()`).
    // Node's own solution is `ScheduleDeferredCycle`; here the event is recorded
    // and the outer `cycle` delivers it once its borrow has been released.
    if where_ & crate::ffi_extra::SSL_CB_HANDSHAKE_DONE != 0 {
        slot.pending_done.set(true);
    }
    if where_ & crate::ffi_extra::SSL_CB_HANDSHAKE_START != 0 {
        slot.pending_start.set(true);
    }
    // `object` is held only to keep the root alive across this call; the delivery
    // happens in `deliver_events`.
    drop(object);
}

/// Runs the events the info callback recorded, after the state borrow is gone.
///
/// Called by [`crate::cycle::run`] once its phases have released the `RefCell`.
/// This is the second half of the R2 split: the callback records, and this
/// delivers — so the JavaScript runs with no borrow held and no `SSL` stack frame
/// below it.
///
/// Node defers through `env()->SetImmediate` for the cert callback
/// (`ScheduleCertCb`, `crypto_tls.cc:515`) and through `ScheduleDeferredCycle`
/// for the rest. Delivering here rather than through an immediate is correct for
/// these two events because they carry no data the caller could mutate, and a
/// handshake that has already completed does not depend on the order relative to
/// other immediates.
pub fn deliver_events(object: Option<&v8::Global<v8::Object>>, handles: &CallbackHandles) {
    let done = handles.pending_done.replace(false);
    let started = handles.pending_start.replace(false);
    if !done && !started {
        return;
    }
    let Some(object) = object else {
        return;
    };
    let object = object.clone();
    let _ = rn_uv::callback::with_context(|scope| {
        let object = v8::Local::new(scope, object);
        if done {
            // `crypto_tls.cc:696`: `flags_.established` was set by the callback;
            // `onhandshakedone` is `wrap.js:977`'s handler, which fires
            // `secureConnect`.
            call_handler(scope, object, "onhandshakedone", &[]);
        }
        if started {
            // `crypto_tls.cc:684`: `onhandshakestart(now)`, where `now` is
            // `env->GetNow()` — the loop clock. A `Date` of `NaN` makes `wrap.js`
            // assert, because it compares `now >= lastHandshakeTime` and `NaN`
            // fails every comparison.
            if let Some(date) = v8::Date::new(scope, rn_uv::uv_loop::now_ms()) {
                let value: v8::Local<v8::Value> = date.into();
                call_handler(scope, object, "onhandshakestart", &[value]);
            }
        }
    });
}

thread_local! {
    /// One slot per live wrap, so a callback can read what it needs without the
    /// wrap's `RefCell`.
    ///
    /// This is the whole of R2's mechanism. `cycle` holds `RefCell<WrapState>`
    /// borrowed across `SSL_read`/`SSL_write`, and the info callback runs on that
    /// very stack — so `try_borrow` there *always* fails. Node's C++ has the same
    /// split without a borrow: `flags_` and `object()` are plain fields readable
    /// while the state machine runs.
    ///
    /// A table rather than one slot because a process has many wraps: a client
    /// and a server in one process is the ordinary case for a TLS test.
    static SLOTS: RefCell<Vec<CallbackSlot>> = const { RefCell::new(Vec::new()) };
}

/// A wrap's callback inputs, mirrored outside its `RefCell`.
///
/// Every field is a `Cell` or a `Global` handle, so reading one never needs the
/// wrap's state borrow. The slot is removed by [`unregister`], which
/// `destroySSL` and the finalizer both reach.
#[derive(Clone)]
struct CallbackSlot {
    /// The state cell this slot mirrors, and the key OpenSSL's `ex_data` hands
    /// back.
    cell: *const RefCell<WrapState>,
    /// The rooted `TLSWrap` object.
    object: Option<v8::Global<v8::Object>>,
    /// `flags_.established`, mirrored so the callback can set it mid-handshake.
    established: Rc<Cell<bool>>,
    /// `library_call_depth`, mirrored so the callback can check re-entrancy.
    depth: Rc<Cell<u32>>,
    /// `SSL_CB_HANDSHAKE_DONE` was seen and has not been delivered.
    pending_done: Rc<Cell<bool>>,
    /// `SSL_CB_HANDSHAKE_START` was seen and has not been delivered.
    pending_start: Rc<Cell<bool>>,
    /// Which side of the handshake this wrap is, so a callback that only applies
    /// to one can skip the other without the state borrow.
    kind: crate::ssl::Kind,
    /// `flags_.session_callbacks`, so `NewSessionCallback` can answer
    /// `has_session_callbacks()` without the state borrow.
    session_callbacks: Rc<Cell<bool>>,
    /// `flags_.alpn_callback_enabled`, read by `SelectALPNCallback`.
    alpn_callback_enabled: Rc<Cell<bool>>,
    /// The `next_sess_` slot the get-session callback drains.
    session: crate::state::SessionSlot,
    /// The `alpn_protos_` list a server's `SelectALPNCallback` matches against.
    alpn_protos: Rc<RefCell<Vec<u8>>>,
    /// `flags_.awaiting_new_session`, which `EncOut` must honour: a server parks
    /// its output until `newSessionDone` runs, so a ticket can never be sent
    /// before the application has decided whether to store the session.
    awaiting_new_session: Rc<Cell<bool>>,
}

/// Records the mirrors a wrap's callbacks read.
///
/// Called once from `wrap()` after the state exists, and undone by
/// [`unregister`].
pub fn register(
    cell: *const RefCell<WrapState>,
    object: v8::Global<v8::Object>,
    kind: crate::ssl::Kind,
    session: crate::state::SessionSlot,
) -> CallbackHandles {
    let established = Rc::new(Cell::new(false));
    let depth = Rc::new(Cell::new(0));
    let pending_done = Rc::new(Cell::new(false));
    let pending_start = Rc::new(Cell::new(false));
    let session_callbacks = Rc::new(Cell::new(false));
    let alpn_callback_enabled = Rc::new(Cell::new(false));
    let alpn_protos = Rc::new(RefCell::new(Vec::new()));
    let awaiting_new_session = Rc::new(Cell::new(false));
    SLOTS.with(|slots| {
        let mut slots = slots.borrow_mut();
        // A wrap registered twice — which a handle swap can do — replaces its
        // own entry rather than accumulating one per swap.
        slots.retain(|slot| slot.cell != cell);
        slots.push(CallbackSlot {
            cell,
            object: Some(object),
            established: Rc::clone(&established),
            depth: Rc::clone(&depth),
            pending_done: Rc::clone(&pending_done),
            pending_start: Rc::clone(&pending_start),
            kind,
            session_callbacks: Rc::clone(&session_callbacks),
            alpn_callback_enabled: Rc::clone(&alpn_callback_enabled),
            session,
            alpn_protos: Rc::clone(&alpn_protos),
            awaiting_new_session: Rc::clone(&awaiting_new_session),
        });
    });
    CallbackHandles {
        established,
        depth,
        pending_done,
        pending_start,
        session_callbacks,
        alpn_callback_enabled,
        alpn_protos,
        awaiting_new_session,
        cell: Some(cell),
    }
}

/// The mirrors [`register`] created, held by the wrap.
///
/// The wrap writes `established` from its own code and `depth` beside its own
/// counter, so a callback that runs mid-handshake sees the same values the
/// `RefCell` would have held.
pub struct CallbackHandles {
    /// `flags_.established`, shared with the slot.
    pub established: Rc<Cell<bool>>,
    /// `library_call_depth`, shared with the slot.
    pub depth: Rc<Cell<u32>>,
    /// A `HANDSHAKE_DONE` event awaiting delivery.
    pub pending_done: Rc<Cell<bool>>,
    /// A `HANDSHAKE_START` event awaiting delivery.
    pub pending_start: Rc<Cell<bool>>,
    /// `flags_.session_callbacks`, shared with the slot.
    pub session_callbacks: Rc<Cell<bool>>,
    /// `flags_.alpn_callback_enabled`, shared with the slot.
    pub alpn_callback_enabled: Rc<Cell<bool>>,
    /// The server's `alpn_protos_`, shared with the slot.
    pub alpn_protos: Rc<RefCell<Vec<u8>>>,
    /// `flags_.awaiting_new_session`, shared with the slot.
    pub awaiting_new_session: Rc<Cell<bool>>,
    /// The state cell this set of handles was registered for.
    ///
    /// Held so [`CallbackHandles::unregister`] can drop the slot without a caller
    /// having to reconstruct the address. `None` for a set made by
    /// [`CallbackHandles::clone_handles`], which is for delivery only and never
    /// unregisters.
    pub cell: Option<*const RefCell<WrapState>>,
}

impl CallbackHandles {
    /// A second set of handles sharing the same cells, for delivery after the
    /// state borrow has been released.
    ///
    /// `cycle` needs the handles while it holds the state borrow and again after
    /// releasing it, and the state itself is what it released. Cloning the `Rc`s
    /// keeps both views on one set of cells.
    pub fn clone_handles(&self) -> Self {
        Self {
            established: Rc::clone(&self.established),
            depth: Rc::clone(&self.depth),
            pending_done: Rc::clone(&self.pending_done),
            pending_start: Rc::clone(&self.pending_start),
            session_callbacks: Rc::clone(&self.session_callbacks),
            alpn_callback_enabled: Rc::clone(&self.alpn_callback_enabled),
            alpn_protos: Rc::clone(&self.alpn_protos),
            awaiting_new_session: Rc::clone(&self.awaiting_new_session),
            // Delivery-only: the owning set is the one that unregisters, so this
            // copy must not drop the slot a second time.
            cell: None,
        }
    }

    /// Drops this wrap's slot from the callback table.
    ///
    /// Idempotent and a no-op for a delivery-only copy. Called by
    /// [`crate::state::WrapState::destroy`], which is the one teardown path.
    pub fn unregister(&self) {
        if let Some(cell) = self.cell {
            unregister(cell);
        }
    }
}

/// Drops a wrap's slot, so a freed state address cannot be matched by a later
/// wrap that reuses it.
pub fn unregister(cell: *const RefCell<WrapState>) {
    if cell.is_null() {
        return;
    }
    SLOTS.with(|slots| slots.borrow_mut().retain(|slot| slot.cell != cell));
}

/// Clears `flags_.awaiting_new_session` without borrowing the wrap's state.
///
/// `newSessionDone` is reached from inside `SSL_do_handshake`: OpenSSL calls
/// `NewSessionCallback`, which emits `'newSession'`, whose `done` calls
/// `newSessionDone()`. `cycle` holds the state's `RefCell` on that very stack, so
/// `with_state` would fail and the method would report "Invalid TLSWrap receiver"
/// — measured against a local `tls.createServer` before this existed.
///
/// The flag lives in the callback slot for exactly this reason (see
/// [`CallbackSlot`]), so the write goes through the slot rather than the state.
pub fn clear_awaiting_new_session(cell: *const RefCell<WrapState>) {
    if cell.is_null() {
        return;
    }
    SLOTS.with(|slots| {
        for slot in slots.borrow().iter().filter(|slot| slot.cell == cell) {
            slot.awaiting_new_session.set(false);
        }
    });
}

/// The slot for the wrap whose `SSL` is `ssl`, read through the app-data pointer.
///
/// This is the lookup every OpenSSL-initiated callback in this module starts
/// with, and it deliberately never touches the wrap's `RefCell`: the callbacks run
/// on the library's stack, where `cycle` holds that borrow.
fn slot_of(ssl: *const ffi::SSL) -> Option<CallbackSlot> {
    if ssl.is_null() {
        return None;
    }
    // SAFETY: the caller is an OpenSSL callback for `ssl`, and `wrap()` installed
    // the wrap's state cell as its app-data at index 0, which
    // `crate::callback::install` documents.
    let data = unsafe { ffi::SSL_get_ex_data(ssl, 0) };
    if data.is_null() {
        return None;
    }
    let cell = data as *const RefCell<WrapState>;
    SLOTS.with(|slots| {
        slots
            .borrow()
            .iter()
            .find(|slot| slot.cell == cell)
            .cloned()
    })
}

/// `TLSWrap`'s `NewSessionCallback` (`crypto_tls.cc:152`).
///
/// OpenSSL calls this once per completed handshake with the session it would
/// resume from, and it is what makes `'session'` fire on the client and
/// `'newSession'` on the server. It returns 0 on every path, as Node's does: the
/// return value only tells OpenSSL whether the session is still needed, and the
/// application here keeps its own copy in JavaScript.
///
/// # Why nothing is returned for a wrap without session callbacks
///
/// `wrap.js` installs `onnewsession` unconditionally on the client, but turns the
/// callbacks on only when a listener exists or the server asked for them. A wrap
/// that never called `enableSessionCallbacks` must not run the handler, which is
/// Node's `has_session_callbacks()` guard, and the reason `https.get`'s socket —
/// which does attach one — is the case this increment exists for.
///
/// # Safety
///
/// OpenSSL invokes this with the `SSL*` and session it owns, both live for the
/// duration of the call.
pub unsafe extern "C" fn new_session(ssl: *mut ffi::SSL, session: *mut ffi::SSL_SESSION) -> c_int {
    let Some(slot) = slot_of(ssl) else {
        return 0;
    };
    if !slot.session_callbacks.get() {
        return 0;
    }
    // `SecureContext::kMaxSessionSize`: a session too large to store is dropped
    // rather than serialized into a buffer JavaScript cannot use.
    // SAFETY: `session` is live for the duration of the call, per this function's
    // contract.
    let Some(session_der) = (unsafe { crate::ssl::encode(session) }) else {
        return 0;
    };
    if session_der.len() > MAX_SESSION_SIZE {
        return 0;
    }
    // SAFETY: as above.
    let id = unsafe { crate::ssl::session_id(session) };

    // On a server the handshake is parked until `newSessionDone`, so the session
    // cannot be lost between the callback and the application's `'newSession'`
    // handler. A client has nothing to wait for, which is why `onnewsessionclient`
    // emits synchronously.
    if slot.kind == crate::ssl::Kind::Server {
        slot.awaiting_new_session.set(true);
    }
    let object = slot.object.clone();
    let buffer_der = session_der;
    let session_id = id;
    // JavaScript must not run on the library's stack: `'newSession'` handlers
    // commonly call `session.setSession()` on another socket, which re-enters the
    // SSL. Node handles this by emitting from inside the callback anyway
    // (`MakeCallback`), and so does this — the difference is that
    // `MakeCallback`'s exception path is handled in `call_handler`.
    //
    // The handler is `onnewsession` for both kinds: `wrap.js` assigns
    // `onnewsessionclient` to that same property for a client (`:1011`).
    let _ = rn_uv::callback::with_context(|scope| {
        let Some(object) = object.as_ref().map(|object| v8::Local::new(scope, object)) else {
            return;
        };
        let arguments = match (
            buffer_to_view(scope, &session_id),
            buffer_to_view(scope, &buffer_der),
        ) {
            (Some(id), Some(session)) => [id, session],
            _ => return,
        };
        let values: [v8::Local<'_, v8::Value>; 2] = [arguments[0].into(), arguments[1].into()];
        call_handler(scope, object, "onnewsession", &values);
    });
    0
}

/// `SecureContext::kMaxSessionSize`, `10 * 1024` (`crypto_context.h:105`).
const MAX_SESSION_SIZE: usize = 10 * 1024;

/// A non-negative integral `f64` as a `usize`, for the ALPN callback's offset.
///
/// `as` would truncate a fractional or negative value into a plausible-looking
/// index, and the offset is the *only* thing the JavaScript answer communicates —
/// so an out-of-range one has to be rejected rather than coerced.
fn number_to_index(value: f64) -> Option<usize> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 {
        return None;
    }
    if value > usize::MAX as f64 {
        return None;
    }
    Some(value as usize)
}

/// `TLSWrap`'s `GetSessionCallback` (`crypto_tls.cc:109`).
///
/// OpenSSL asks this while it is *starting* a handshake, to make resumption
/// possible. Node answers with `next_sess_.release()`, which is the session
/// `loadSession` decoded, and sets `*copy = 0` to say the `SSL` owns the pointer
/// from here.
///
/// The slot is reached without the wrap's `RefCell` because this runs inside
/// `SSL_do_handshake`, where `cycle` holds that borrow — see [`slot_of`].
///
/// # Safety
///
/// OpenSSL invokes this with a live `SSL*` and `copy` a writable `int`. The
/// returned session must be owned by the caller, which is what `release` does.
pub unsafe extern "C" fn get_session(
    ssl: *mut ffi::SSL,
    _key: *const std::os::raw::c_uchar,
    _length: c_int,
    copy: *mut c_int,
) -> *mut ffi::SSL_SESSION {
    if !copy.is_null() {
        // SAFETY: `copy` is a live out-parameter, per this function's contract.
        unsafe { *copy = 0 };
    }
    let Some(slot) = slot_of(ssl) else {
        return std::ptr::null_mut();
    };
    slot.session.take_ptr()
}

/// `TLSWrap`'s `SelectALPNCallback` (`crypto_tls.cc:227`), the **server** half of
/// ALPN.
///
/// Two modes, both from Node:
///
/// * `flags_.alpn_callback_enabled` (an `ALPNCallback` option was given): the raw
///   offered wire-format list goes to JavaScript, which answers with an offset
///   into it, `undefined` to reject everything, or throws;
/// * otherwise the wrap matches the offered list against `alpn_protos_` with
///   `SSL_select_next_proto`, and a list with no overlap is a fatal alert as RFC
///   7301 requires.
///
/// A client does not come here at all: it calls `SSL_set_alpn_protos` and lets
/// OpenSSL do the matching, which is `setALPNProtocols`'s client branch.
///
/// # Safety
///
/// All pointers are OpenSSL's own, valid for the duration of the call, and
/// `out`/`outlen` are out-parameters this function writes exactly once.
pub unsafe extern "C" fn select_alpn(
    ssl: *mut ffi::SSL,
    out: *mut *const std::os::raw::c_uchar,
    out_len: *mut std::os::raw::c_uchar,
    offered: *const std::os::raw::c_uchar,
    offered_len: std::os::raw::c_uint,
    _arg: *mut std::os::raw::c_void,
) -> c_int {
    if ssl.is_null() || out.is_null() || out_len.is_null() {
        return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    let Some(slot) = slot_of(ssl) else {
        return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
    };
    // SAFETY: the caller guarantees `offered` points at `offered_len` bytes.
    let offered_bytes = if offered.is_null() || offered_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(offered, offered_len as usize) }
    };

    if slot.alpn_callback_enabled.get() {
        let object = slot.object.clone();
        let offered_copy = offered_bytes.to_vec();
        let offset = rn_uv::callback::with_context(|scope| {
            let object = object
                .as_ref()
                .map(|object| v8::Local::new(scope, object))?;
            let buffer = buffer_to_view(scope, &offered_copy)?;
            call_handler_returning(scope, object, "ALPNCallback", &[buffer.into()])
        })
        .flatten();
        // `undefined` — which is what a missing handler or an `undefined` return
        // looks like — rejects every proposed protocol, and Node sends a fatal
        // alert for it rather than silently continuing without ALPN.
        let Some(offset) = offset else {
            return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
        };
        let Some(start) = number_to_index(offset) else {
            return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
        };
        if start >= offered_bytes.len() {
            return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        let length = offered_bytes[start] as usize;
        let body = start + 1;
        if body + length > offered_bytes.len() {
            return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        // SAFETY: `out` and `out_len` are live out-parameters, and the slice the
        // pointer names is OpenSSL's own `offered` buffer, which outlives the
        // callback.
        unsafe {
            *out = offered.add(body);
            *out_len = length as std::os::raw::c_uchar;
        }
        return ffi::SSL_TLSEXT_ERR_OK;
    }

    // The list is borrowed for the duration of this call rather than cloned:
    // `SSL_select_next_proto` points `selected` *into* it, and OpenSSL reads the
    // bytes only after this callback returns — so a temporary clone would be a
    // dangling pointer, which showed up as
    // `ERR_SSL_TLSV1_ALERT_DECODE_ERROR` on the peer and
    // `ERR_SSL_BAD_EXTENSION` on the client.
    //
    // The borrow is short and nothing here calls back into JavaScript, so it
    // cannot be re-entered; `try_borrow` reports it rather than panicking if it
    // ever is.
    let Ok(supported) = slot.alpn_protos.try_borrow() else {
        return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
    };
    if supported.is_empty() {
        return ffi::SSL_TLSEXT_ERR_NOACK;
    }
    let mut selected: *mut std::os::raw::c_uchar = std::ptr::null_mut();
    let mut selected_len: std::os::raw::c_uchar = 0;
    // SAFETY: both lists are live for the duration of the call, and the two
    // out-parameters are live locals. `SSL_select_next_proto` only reads the two
    // lists and points `selected` into `supported`.
    let negotiated = unsafe {
        ffi::SSL_select_next_proto(
            &mut selected,
            &mut selected_len,
            supported.as_ptr(),
            supported.len() as std::os::raw::c_uint,
            offered_bytes.as_ptr(),
            offered_bytes.len() as std::os::raw::c_uint,
        )
    };
    if negotiated != ffi::OPENSSL_NPN_NEGOTIATED || selected.is_null() {
        return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    // SAFETY: the out-parameters are live, and `selected` points into
    // `supported`, which the `RefCell` in the slot owns for as long as the wrap
    // does — so the bytes are still valid when OpenSSL reads them after this
    // returns.
    unsafe {
        *out = selected;
        *out_len = selected_len;
    }
    ffi::SSL_TLSEXT_ERR_OK
}

/// `TLSWrap`'s `KeylogCallback` (`crypto_tls.cc:135`).
///
/// One `'keylog'` emission per NSS key-log line, with the newline Node appends.
/// This is diagnostic rather than load-bearing, but `--tls-keylog` and
/// `setKeylogCallback` both reach it, and a listener that never fires would make
/// a debugging aid silently useless.
///
/// # Safety
///
/// OpenSSL invokes this with a live `SSL*` and a NUL-terminated `line`.
pub unsafe extern "C" fn keylog(ssl: *const ffi::SSL, line: *const std::os::raw::c_char) {
    if ssl.is_null() || line.is_null() {
        return;
    }
    let Some(slot) = slot_of(ssl) else {
        return;
    };
    // SAFETY: `line` is NUL-terminated, per OpenSSL's contract for this callback.
    let text = unsafe { std::ffi::CStr::from_ptr(line) };
    let mut bytes = text.to_bytes().to_vec();
    bytes.push(b'\n');
    let object = slot.object.clone();
    let _ = rn_uv::callback::with_context(|scope| {
        let Some(object) = object.as_ref().map(|object| v8::Local::new(scope, object)) else {
            return;
        };
        let Some(buffer) = buffer_to_view(scope, &bytes) else {
            return;
        };
        call_handler(scope, object, "onkeylog", &[buffer.into()]);
    });
}

/// A `Buffer` over a copy of `bytes`.
///
/// `Buffer` rather than a bare `Uint8Array` because `wrap.js` passes the session
/// straight to `Buffer.concat` (`wrapSessionState`) and reads it back with
/// `Buffer.isBuffer`, both of which reject a plain view.
fn buffer_to_view<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Uint8Array>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let view = v8::Uint8Array::new(scope, array_buffer, 0, array_buffer.byte_length())?;
    if let Some(prototype) = buffer_prototype(scope) {
        view.set_prototype(scope, prototype.into());
    }
    Some(view)
}

/// `Buffer.prototype` from the global, so a buffer this crate builds is a real
/// `Buffer` rather than a bare `Uint8Array`.
fn buffer_prototype<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let buffer_key = v8::String::new(scope, "Buffer")?;
    let buffer = global.get(scope, buffer_key.into())?;
    let buffer = v8::Local::<v8::Object>::try_from(buffer).ok()?;
    let prototype_key = v8::String::new(scope, "prototype")?;
    let value = buffer.get(scope, prototype_key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Calls `object[name](...args)` and returns the number it answered, if any.
///
/// `SelectALPNCallback` is the one handler whose return value is consumed, and
/// Node treats `undefined` there as "reject everything" rather than as zero — so
/// the distinction between "returned a number" and "returned nothing" is
/// load-bearing, which is why this is separate from [`call_handler`].
fn call_handler_returning<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    arguments: &[v8::Local<'s, v8::Value>],
) -> Option<f64> {
    let key = v8::String::new(scope, name)?;
    let value = object.get(scope, key.into())?;
    let handler = v8::Local::<v8::Function>::try_from(value).ok()?;
    let receiver: v8::Local<'s, v8::Value> = object.into();
    let caught = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
        let inner = &mut try_catch.init();
        let returned = handler.call(inner, receiver, arguments);
        let result = returned.map(|value| value.number_value(inner));
        (
            result,
            inner
                .exception()
                .map(|exception| v8::Global::new(inner, exception)),
        )
    };
    if let Some(caught) = caught.1 {
        let exception = v8::Local::new(&*scope, &caught);
        rn_errors::report_uncaught_exception(scope, exception);
        return None;
    }
    caught.0.flatten()
}

/// Calls `object[name](...args)` when the property is a function.
///
/// Node's pattern is `object->Get(context, name_str).ToLocal(&cb) && cb->IsFunction()`,
/// so a missing handler is not an error: a client has no `onhandshakestart`, and
/// a wrap built directly has neither.
fn call_handler<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    arguments: &[v8::Local<'s, v8::Value>],
) {
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    let Some(value) = object.get(scope, key.into()) else {
        return;
    };
    let Ok(handler) = v8::Local::<v8::Function>::try_from(value) else {
        return;
    };
    let receiver: v8::Local<'s, v8::Value> = object.into();
    // A throw here is uncaught: the callback runs from OpenSSL's stack inside a
    // libuv read completion, so nothing above it can handle one. Node's
    // `MakeCallback` catches it and routes it through `TriggerUncaughtException`,
    // which is what prints it under Node's framing and sets a non-zero exit code.
    // Ignoring the result leaves V8 to print it while the process exits 0.
    let caught = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
        let inner = &mut try_catch.init();
        let _ = handler.call(inner, receiver, arguments);
        inner
            .exception()
            .map(|exception| v8::Global::new(inner, exception))
    };
    if let Some(caught) = caught {
        let exception = v8::Local::new(&*scope, &caught);
        rn_errors::report_uncaught_exception(scope, exception);
    }
}

/// Installs the info callback and the app-data pointer on a fresh `SSL`.
///
/// This is the half of `TLSWrap::InitSSL` (`crypto_tls.cc:547`) that needs the
/// wrap to exist already: `SSL_set_app_data(ssl, this)` is how the callback finds
/// its way back, and the callback cannot be installed before there is an address
/// to install.
///
/// # Safety
///
/// `ssl` must be live, and `cell` must be the address of the `RefCell<WrapState>`
/// that outlives it. `wrap()` establishes both: the state is allocated for the
/// object's lifetime and the `SSL` is freed by that same state's teardown.
pub unsafe fn install(ssl: *mut ffi::SSL, cell: *mut std::cell::RefCell<WrapState>) {
    if ssl.is_null() || cell.is_null() {
        return;
    }
    // SAFETY: the caller guarantees the state outlives the SSL.
    unsafe {
        // `SSL_set_app_data(ssl, this)` is `SSL_set_ex_data(ssl, 0, this)`, which
        // is the slot `ffi::SSL_get_ex_data(ssl, 0)` reads back.
        ffi::SSL_set_ex_data(ssl, 0, cell.cast::<c_void>());
        crate::ffi_extra::SSL_set_info_callback(ssl, Some(info));
        // The session callbacks live on the `SSL_CTX`, which the `SSL` shares with
        // every other wrap built from the same `SecureContext` — so this is
        // Node's `sc_->SetGetSessionCallback(...)` / `SetNewSessionCallback(...)`
        // in `TLSWrap::TLSWrap` (`crypto_tls.cc:413`), run once per wrap rather
        // than once per context. Installing it here rather than at context
        // creation keeps the callback table keyed by the SSL's app-data, so a
        // callback for one wrap cannot read another's state.
        let ctx = crate::ffi_extra::SSL_get_SSL_CTX(ssl);
        if !ctx.is_null() {
            ffi::SSL_CTX_sess_set_new_cb(ctx, Some(new_session));
            ffi::SSL_CTX_sess_set_get_cb(ctx, Some(get_session));
        }
    }
}

/// `SSL_set_cert_cb`'s signature, for the increment-4 callbacks.
///
/// Declared here so the shape is recorded next to the callback it belongs with.
pub type CertCallback = Option<unsafe extern "C" fn(*mut ffi::SSL, *mut c_void) -> c_int>;

/// The unused-parameter guard for the callback's `ret`.
#[allow(dead_code)]
fn ret_is_unused(_: c_int, _: *const c_char) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A callback with no handshake bits returns immediately, which is the
    /// common case: `SSL_set_info_callback` fires for many events and Node acts
    /// on two.
    #[test]
    fn a_non_handshake_event_does_nothing() {
        // No SSL is involved, so the early return is the whole assertion: a
        // callback that dereferenced first would crash here.
        // SAFETY: null is explicitly handled after the bitmask test.
        unsafe { info(std::ptr::null(), 0, 0) };
    }

    /// A handshake-bit event with a null `SSL` returns rather than dereferencing.
    #[test]
    fn a_null_ssl_is_reported_not_dereferenced() {
        // SAFETY: null is explicitly handled.
        unsafe { info(std::ptr::null(), crate::ffi_extra::SSL_CB_HANDSHAKE_DONE, 1) };
    }

    /// The two constants are the ones `ssl.h` defines, because a wrong bit would
    /// silently never fire.
    #[test]
    fn the_handshake_bits_are_node_s() {
        assert_eq!(crate::ffi_extra::SSL_CB_HANDSHAKE_START, 0x10);
        assert_eq!(crate::ffi_extra::SSL_CB_HANDSHAKE_DONE, 0x20);
    }

    /// `install` on a null SSL is a no-op, which is what a wrap whose context was
    /// closed needs.
    #[test]
    fn installing_on_a_null_ssl_does_nothing() {
        // SAFETY: null is explicitly handled.
        unsafe { install(std::ptr::null_mut(), std::ptr::null_mut()) };
    }
}
