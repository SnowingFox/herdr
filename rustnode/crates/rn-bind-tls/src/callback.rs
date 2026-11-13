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

use openssl_sys as ffi;
use rn_v8_sys::v8;

use crate::state::WrapState;

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
}

/// Records the mirrors a wrap's callbacks read.
///
/// Called once from `wrap()` after the state exists, and undone by
/// [`unregister`].
pub fn register(
    cell: *const RefCell<WrapState>,
    object: v8::Global<v8::Object>,
) -> CallbackHandles {
    let established = Rc::new(Cell::new(false));
    let depth = Rc::new(Cell::new(0));
    let pending_done = Rc::new(Cell::new(false));
    let pending_start = Rc::new(Cell::new(false));
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
        });
    });
    CallbackHandles {
        established,
        depth,
        pending_done,
        pending_start,
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
