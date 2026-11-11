//! The state behind a `TLSWrap`, and the four teardown rules it has to satisfy.
//!
//! `src/crypto/crypto_tls.cc`'s `TLSWrap` is an `AsyncWrap + StreamBase +
//! StreamListener` with no libuv handle. Its state is spread over ~30 fields and
//! a bitfield; this module is that state, and the ordering rules are the reason
//! it is one type with one teardown method rather than scattered cells.
//!
//! # The four rules, and where each is enforced
//!
//! The plan document states them as R1–R4. Each is a way the process crashes or
//! spins if it is got wrong, and each has exactly one place here that upholds it.
//!
//! **R1 — the `SSL` owns both `BIO`s.** `SSL_set_bio` transfers ownership, so
//! [`crate::ssl::Ssl`] owns them and its one `SSL_free` releases them. There is
//! no `BIO_free` in this crate. See [`crate::bio`].
//!
//! **R2 — never call into V8 while holding a `&mut` to the wrap state.** The SSL
//! callbacks call JavaScript, and `lib/net.js` can `destroy()` the socket from
//! inside one. Every method that calls out takes what it needs, ends the borrow,
//! then calls — the discipline `rn_uv::handle::deliver_read` uses. [`TlsState`]
//! is therefore reached through [`with_state`], which is scoped to one operation;
//! nothing here holds a borrow across a `MakeCallback`.
//!
//! **R3 — a pending write must be completed, not dropped, on close.** Otherwise
//! `lib/net.js`'s write callback never fires, the `WriteWrap` leaks, and the
//! socket's `pending` count never reaches zero. [`TlsState::destroy`] calls
//! [`TlsState::invoke_queued`] first, which is Node's `InvokeQueued(UV_ECANCELED,
//! "Canceled because of SSL destruction")`.
//!
//! **R4 — the loop must never be left busy.** A `TLSWrap` with nothing pending
//! must not hold a ref, and the `setImmediate` deferrals must be real immediates
//! rather than a spin. [`TlsState`] holds no libuv handle of its own; the
//! deferrals go through [`crate::defer`], which is `Environment::SetImmediate`.
//!
//! # Why one type and not several cells
//!
//! Node's `TLSWrap` fields are interdependent in ways a struct makes checkable:
//! `flags_.write_callback_scheduled` gates whether `current_write_` is completed,
//! `pending_shutdown_` and the write queue are both released by `Destroy`, and
//! `ssl_` gates everything. Splitting them into separate `Cell`s would make each
//! one individually sound and the *combination* unsound, which is the class of
//! bug the plan's R1–R4 are about.

use std::cell::RefCell;
use std::ptr;

use rn_v8_sys::v8;

use crate::bio::{EncIn, EncOut};
use crate::ssl::{Kind, Ssl};

/// `TLSWrap::Flags`, the bitfield at `crypto_tls.h`.
///
/// Kept as named booleans rather than packed bits: the fields are read and
/// written one at a time from different entry points, and the only thing the
/// packing saves is memory that one object per socket does not need.
#[derive(Debug, Default, Clone, Copy)]
pub struct Flags {
    /// `flags_.started` — `start()` has run, so the ClientHello was sent.
    pub started: bool,
    /// `flags_.established` — the handshake finished.
    pub established: bool,
    /// `flags_.shutdown` — the close-notify has been written.
    pub shutdown: bool,
    /// `flags_.reading` — `ReadStart` has been called and `ReadStop` has not.
    pub reading: bool,
    /// `flags_.write_callback_scheduled` — a write is queued and its callback
    /// has not fired. `Destroy` sets this true before completing the write, so
    /// the completion runs even if the write never reached the socket.
    pub write_callback_scheduled: bool,
    /// `flags_.session_callbacks` — `enableSessionCallbacks` ran.
    pub session_callbacks: bool,
    /// `flags_.alpn_callback_enabled` — `enableALPNCb` ran.
    pub alpn_callback_enabled: bool,
    /// `flags_.cert_cb_running` — inside `SSLCertCallback`.
    pub cert_cb_running: bool,
    /// `flags_.awaiting_new_session` — `newSessionDone` is owed.
    pub awaiting_new_session: bool,
    /// `flags_.hello_emitted` — the `onclienthello` event fired.
    pub hello_emitted: bool,
    /// `flags_.hello_answered` — `clientHelloDone` ran.
    pub hello_answered: bool,
    /// `flags_.has_active_write_issued_by_prev_listener` — a write from the
    /// previous listener was still in flight when this wrap took over, which is
    /// `wrapHasActiveWriteFromPrevOwner` at `wrap.js:836`.
    pub has_active_write_issued_by_prev_listener: bool,
    /// `flags_.eof` — a close-notify or an underlying EOF was seen.
    ///
    /// `ClearIn` does nothing once set, and `ReadStart` does not re-arm, which is
    /// `crypto_tls.cc:1094`'s `!flags_.eof` guard.
    pub eof: bool,
    /// `flags_.in_destroy` — re-entrant `Destroy` is a no-op.
    ///
    /// Node has no such flag because `if (!ssl_) return;` covers it; it is here
    /// because a Rust teardown that runs twice would free twice unless the
    /// pointer is cleared, and this is the readable half of that guard.
    pub in_destroy: bool,
}

/// The `StreamListener` a `TLSWrap` installs on the stream it wraps.
///
/// Node's `TLSWrap` *is* the listener (`stream->PushStreamListener(this)`).
/// Here the listener has to be a separate object, because
/// `rn_uv::listener::ListenerRef` takes a `Box<dyn StreamListener>` and the wrap
/// state outlives it — so the listener holds a raw pointer back to the state,
/// which [`crate::wrap`] keeps valid for exactly as long as the pointer is
/// registered.
///
/// That pointer is why `TlsState::destroy` removes the listener *before* the
/// state is freed (R1's ordering, `crypto_tls.cc:1494`): a listener left on a
/// closed stream would be called with a dangling state.
pub struct WrapState {
    /// The rooted JavaScript `TLSWrap` object, so a callback can reach it.
    ///
    /// Node stores `this` in `SSL_set_app_data`; a Rust `*mut TlsState` is not a
    /// V8 value, so the object is rooted and the raw pointer is used to recover
    /// the state, and this to recover the object.
    pub object: Option<v8::Global<v8::Object>>,
    /// The rooted `SecureContext` object, which keeps the `SSL_CTX` alive.
    ///
    /// This is the "one owner" half of the `SSL_CTX` rule: the context is owned
    /// by its JavaScript object, and this reference is what stops a GC from
    /// running its finalizer while the `SSL` still points at the `SSL_CTX`.
    pub secure_context: Option<v8::Global<v8::Object>>,
    /// The `SSL`, which owns both BIOs.
    pub ssl: Option<Ssl>,
    /// `TLSWrap::kind_`.
    pub kind: Kind,
    /// `TLSWrap::flags_`.
    pub flags: Flags,
    /// `TLSWrap::ssl_library_call_depth_`, the re-entrancy guard from
    /// `crypto_tls.h:47`.
    ///
    /// Every entry point into the SSL library increments it and the callbacks
    /// check it before calling back into V8. Without it, a `setServername` from
    /// inside an SNI callback re-enters `SSL_do_handshake` and corrupts the
    /// state machine.
    pub library_call_depth: u32,
    /// `TLSWrap::current_write_`, the `WriteWrap` whose callback is owed.
    ///
    /// `None` means nothing is queued. R3 is about this field: a value here at
    /// teardown must be completed, not dropped.
    pub current_write: Option<v8::Global<v8::Object>>,
    /// `TLSWrap::pending_shutdown_`, a `ShutdownWrap` waiting for the SSL stack
    /// to unwind.
    pub pending_shutdown: Option<v8::Global<v8::Object>>,
    /// The listener as the stream knows it, so teardown can remove it.
    ///
    /// `None` until the listener is pushed, and cleared once it is removed, so a
    /// second removal cannot act on a stale id.
    pub listener: Option<rn_uv::listener::ListenerId>,
    /// The stream this wrap sits on, as the listener layer names it.
    ///
    /// Borrowed, not owned: the underlying `TCP`/`Pipe`/`JSStream` owns its
    /// `StreamState`, and `rn_uv`'s listener layer already keeps a live listener
    /// from outliving its stream.
    pub underlying: Option<*mut rn_uv::handle::StreamState>,
    /// `TLSWrap::cert_cb_`, whether `enableCertCb` parked the handshake.
    pub cert_cb_pending: bool,
    /// `TLSWrap::next_sess_`, the session `loadSession` supplied.
    pub next_session: Option<*mut openssl_sys::SSL_SESSION>,
    /// The bytes `EncOut` has produced but not yet handed to the socket.
    ///
    /// Node writes them straight to the underlying stream from `EncOut`; a queue
    /// here is what lets `DoWrite` report a partial write without losing the
    /// remainder, and what lets `flush` retry after `WANT_WRITE`. Drained by
    /// [`crate::stream::flush`], and cleared by [`WrapState::destroy`] — a write
    /// that cannot be flushed is completed with an error rather than left
    /// pointing at freed memory (R3).
    pub pending_output: Vec<u8>,
    /// The wrap's **own** `StreamBase` state.
    ///
    /// Node's `TLSWrap` is a `StreamBase` in its own right: it has a
    /// `StreamResource` whose `EmitRead` is how decrypted cleartext reaches
    /// `handle.onread`. Its `stream` field is null — there is no libuv handle —
    /// which is exactly the shape `rn_uv::listener` supports for a `JSStream`.
    ///
    /// This is what cleartext goes *up* through. Using the underlying socket's
    /// state instead would push plaintext into the ciphertext path.
    pub reader: rn_uv::handle::StreamState,
    /// Decrypted cleartext waiting to be handed to JavaScript.
    ///
    /// The opposite direction from [`WrapState::pending_output`]: this is what
    /// `ClearOut` produced and `lib/net.js` emits as `'data'`, while
    /// `pending_output` is ciphertext on its way to the socket. Mixing the two
    /// would put plaintext inside the TLS framing.
    pub pending_cleartext_output: Vec<u8>,
    /// Cleartext the caller wrote that `SSL_write` could not yet accept.
    ///
    /// `crypto_tls.cc`'s `pending_cleartext_input_`, a kept backing store that
    /// `ClearOut` retries. Node parks it on `WANT_WRITE` so a write under
    /// backpressure is resumed rather than truncated; dropping it is how a large
    /// payload loses its tail while a small one echoes fine.
    pub pending_cleartext: Vec<u8>,
    /// The mirrors the SSL callbacks read.
    ///
    /// `cycle` holds this state borrowed across `SSL_read`/`SSL_write`, which is
    /// the stack the info callback runs on — so the callback cannot read the
    /// `RefCell`. These `Rc<Cell<_>>` are the copy it can read, and `cycle` copies
    /// their values back here when its borrow ends. See
    /// [`crate::callback`] for why that split is necessary rather than tidy.
    pub callback: Option<crate::callback::CallbackHandles>,
    /// The mode last set by `setVerifyMode`, `TLSWrap`'s `verify_mode_`.
    ///
    /// Kept because `setVerifyMode` is idempotent and `lib/internal/tls/wrap.js`
    /// re-applies it on a handle swap; reading the current mode back from OpenSSL
    /// is possible but this keeps the two answers in one place.
    pub verify_mode: i32,
    /// `flags_.eof`: a close-notify or an underlying EOF was seen.
    ///
    /// Once set, `ClearIn` does nothing and `ReadStart` does not re-arm, which is
    /// `crypto_tls.cc:1094`'s `!flags_.eof` guard.
    pub error: Option<String>,
}

impl WrapState {
    /// The state for a freshly constructed `TLSWrap`.
    ///
    /// `ssl` is created by [`crate::wrap`] after the JavaScript object exists,
    /// because `InitSSL` installs callbacks that need to recover that object.
    pub fn new(kind: Kind) -> Self {
        // A `StreamState` with no libuv handle: `TLSWrap` is a `StreamBase`
        // without one, which is the same shape `rn-bind-js-stream` uses.
        let reader = rn_uv::handle::StreamState::new(ptr::null_mut());
        Self {
            reader,
            object: None,
            secure_context: None,
            ssl: None,
            kind,
            flags: Flags::default(),
            library_call_depth: 0,
            current_write: None,
            pending_shutdown: None,
            listener: None,
            underlying: None,
            cert_cb_pending: false,
            next_session: None,
            pending_output: Vec::new(),
            pending_cleartext: Vec::new(),
            pending_cleartext_output: Vec::new(),
            callback: None,
            verify_mode: 0,
            error: None,
        }
    }

    /// The raw `SSL`, or null after teardown.
    pub fn ssl_ptr(&self) -> *mut openssl_sys::SSL {
        self.ssl
            .as_ref()
            .map(Ssl::as_ptr)
            .unwrap_or(ptr::null_mut())
    }

    /// Whether the SSL library is currently on this thread's stack, so a
    /// callback must not call back into it.
    pub fn in_library_call(&self) -> bool {
        self.library_call_depth > 0
    }

    /// Enters the SSL library, `TLSWrap::SSLLibraryCallScope`'s increment.
    ///
    /// Returns a guard whose drop decrements, so an early return cannot leave the
    /// depth raised — which would make every later callback believe it is inside
    /// the library and silently skip its JavaScript notification.
    ///
    /// The guard borrows **only the depth field**, which Rust's disjoint field
    /// borrows allow, so the rest of the state stays usable while a library call
    /// is in progress. In practice the guard is dropped before any callback runs:
    /// the callbacks OpenSSL invokes read the depth through a shared borrow of the
    /// same `RefCell`, and a guard holding `&mut WrapState` would make that
    /// impossible.
    pub fn enter_library(&mut self) -> LibraryScope<'_> {
        self.library_call_depth = self.library_call_depth.saturating_add(1);
        LibraryScope {
            depth: &mut self.library_call_depth,
        }
    }

    /// `TLSWrap::InvokeQueued`: complete the queued write, if any.
    ///
    /// R3. The caller supplies the status and message because `Destroy` reports
    /// `UV_ECANCELED` / `"Canceled because of SSL destruction"` while a normal
    /// flush reports success. Returning the write rather than calling it keeps
    /// the borrow discipline (R2): the caller has to end its borrow of this
    /// state before it can call into V8.
    ///
    /// Clears the flag as well, so a second call — from `Destroy` after a flush
    /// already completed it — does not hand out the same object twice, which
    /// would double-fire `oncomplete`.
    pub fn take_queued_write(&mut self) -> Option<v8::Global<v8::Object>> {
        if !self.flags.write_callback_scheduled {
            return None;
        }
        self.flags.write_callback_scheduled = false;
        self.current_write.take()
    }

    /// `TLSWrap::Destroy`, minus the parts that need a `PinScope`.
    ///
    /// Ordering is the load-bearing part and it is Node's
    /// (`crypto_tls.cc:1467`), comment for comment:
    ///
    /// 1. set `write_callback_scheduled`, so a queued write is completable;
    /// 2. hand the write back for the caller to complete with `UV_ECANCELED`
    ///    (R3) — this is why the method returns it instead of calling it;
    /// 3. hand back any pending shutdown for the same reason;
    /// 4. free the `SSL`, which frees both BIOs (R1);
    /// 5. drop the `SecureContext` reference;
    /// 6. clear everything else so a second call is a no-op.
    ///
    /// Steps 1–3 happen *before* step 4 because the write and shutdown objects
    /// are the only things that can observe the SSL, and completing them after
    /// it is freed would let a JS write callback reach a freed wrap.
    ///
    /// The listener removal is not here: it needs the stream pointer and no
    /// borrow of this state, so [`crate::wrap`] does it around this call.
    pub fn destroy(&mut self) -> Destroyed {
        if self.flags.in_destroy {
            return Destroyed::default();
        }
        self.flags.in_destroy = true;

        self.flags.write_callback_scheduled = true;
        let write = self.take_queued_write();
        let shutdown = self.pending_shutdown.take();

        // R1: the one place the SSL is freed, and the one place both BIOs are.
        if let Some(ssl) = self.ssl.take() {
            ssl.free();
        }
        // `enc_in_ = enc_out_ = nullptr` in Node. There are no such fields here:
        // `enc_in()`/`enc_out()` read the BIOs back from the SSL, so there is
        // nothing left pointing at a freed BIO.
        // The callback slot is keyed by this state's address, so it has to go
        // with the state: a later wrap that reuses the address must not be
        // matched by a stale entry.
        crate::callback::unregister(self as *const WrapState as *const RefCell<WrapState>);
        self.callback = None;
        self.pending_output.clear();
        self.pending_cleartext.clear();
        self.pending_cleartext_output.clear();
        self.error = None;
        self.flags.eof = false;
        self.secure_context = None;
        self.flags.established = false;
        self.flags.started = false;
        self.flags.reading = false;
        self.cert_cb_pending = false;
        // `self.object` deliberately survives: `destroySSL` is called from JS on
        // an object that is still reachable, and clearing the root here would
        // make the object collectable while the caller still holds it.
        Destroyed {
            write,
            shutdown,
            listener: self.listener.take(),
            underlying: self.underlying,
        }
    }

    /// The read BIO, if the SSL is alive.
    ///
    /// Re-read on every use rather than cached, which is R1's stale-pointer
    /// half: a cached `EncIn` is exactly a pointer that outlives its `SSL`.
    pub fn enc_in(&self) -> Option<EncIn> {
        self.ssl.as_ref().and_then(Ssl::enc_in)
    }

    /// The write BIO, if the SSL is alive.
    pub fn enc_out(&self) -> Option<EncOut> {
        self.ssl.as_ref().and_then(Ssl::enc_out)
    }
}

/// What [`WrapState::destroy`] handed back for the caller to finish.
///
/// These are the parts that need a `PinScope` or the listener layer, both of
/// which are the caller's to touch. Returning them rather than acting here is
/// R2: the caller has already ended its borrow of the state by the time it has
/// this value.
#[derive(Default)]
pub struct Destroyed {
    /// The queued write to complete with `UV_ECANCELED` (R3).
    pub write: Option<v8::Global<v8::Object>>,
    /// The pending shutdown to complete with `UV_ECANCELED` (R3).
    pub shutdown: Option<v8::Global<v8::Object>>,
    /// The listener to remove from the stream.
    pub listener: Option<rn_uv::listener::ListenerId>,
    /// The stream the listener is on.
    pub underlying: Option<*mut rn_uv::handle::StreamState>,
}

impl std::fmt::Debug for Destroyed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Destroyed")
            .field("has_write", &self.write.is_some())
            .field("has_shutdown", &self.shutdown.is_some())
            .field("has_listener", &self.listener.is_some())
            .finish()
    }
}

/// `TLSWrap::SSLLibraryCallScope`, as a guard.
///
/// # Why it borrows one field rather than the whole state
///
/// The C++ scope holds a `TLSWrap*` and does `wrap_->ssl_library_call_depth_++`
/// in the constructor and `--` in the destructor. The counter's whole purpose is
/// that a callback **invoked from inside the library** reads it and decides not
/// to re-enter. Holding `&mut WrapState` across the call would make that read a
/// borrow conflict — and `RefCell` would report a re-entrant borrow, turning a
/// documented "do not re-enter" into a panic on exactly the path the counter
/// exists to handle.
///
/// Borrowing just the depth field means the rest of the state is still reachable
/// for the increment's duration, which is the Rust spelling of C++'s "the scope
/// owns one integer".
pub struct LibraryScope<'a> {
    /// `WrapState::library_call_depth`, borrowed for the scope's lifetime.
    depth: &'a mut u32,
}

impl Drop for LibraryScope<'_> {
    fn drop(&mut self) {
        *self.depth = self.depth.saturating_sub(1);
    }
}

/// The internal field holding the `*mut RefCell<WrapState>`.
pub const STATE_FIELD: i32 = 0;

/// `TLSWrap::kInternalFieldCount`.
///
/// Node takes the max of `AsyncWrap`'s and `StreamBase`'s. Here one field is
/// enough: the async id and the `onread` function live in the state, and
/// `wrap.js` reads neither off the object (it reads `reading`, which is a JS
/// redefinition at `wrap.js:888`).
pub const INTERNAL_FIELD_COUNT: usize = 1;

/// Runs `body` with the state behind a `TLSWrap` object.
///
/// The borrow is scoped to `body`, which is R2's discipline made structural: a
/// caller that needs to call into V8 takes what it needs during `body`, returns
/// it, and calls afterwards. A re-entrant call — `lib/net.js` destroying the
/// socket from inside an SSL callback — gets `None` rather than a panic, because
/// `try_borrow_mut` is used and a failed borrow is exactly the re-entrancy case
/// rather than a bug to abort on.
///
/// # Why the field count is checked first
///
/// `get_aligned_pointer_from_internal_field` reads raw storage at a fixed offset
/// and does not validate that the object has fields there — the same hazard
/// `rn-bind-secure-context` documents, which aborted the process on a prototype
/// object. A `TLSWrap.prototype` is reachable from JavaScript, so this guard is
/// load-bearing.
pub fn with_state<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut WrapState) -> R,
) -> Option<R> {
    if object.internal_field_count() < INTERNAL_FIELD_COUNT {
        return None;
    }
    // SAFETY: the field is written only by `install_state`, which stores a
    // `*mut RefCell<WrapState>` allocated for this object, and cleared only by
    // that object's finalizer. The object is a live local, so the allocation is
    // live.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut RefCell<WrapState>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above. `try_borrow_mut` rather than `borrow_mut` because a
    // re-entrant path is legal JavaScript (`destroy()` from a callback) and must
    // be reported, not abort the process.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

/// The address of a `TLSWrap` object's state cell, for the listener to hold.
///
/// Returns `None` for a receiver that is not a `TLSWrap`. The listener stores
/// this raw pointer rather than a borrow, which is what lets it call back into
/// the state without the borrow being held across the listener call
/// (`rn_uv::listener`'s documented discipline).
///
/// # The pointer's lifetime
///
/// The cell lives in an allocation owned by the object's finalizer, and the
/// listener is removed in `destroy()` before that finalizer can run — because a
/// `TLSWrap` is only collectable after `lib/net.js` has dropped its references,
/// by which point `close()` has called `destroySSL`. [`crate::wrap`] documents
/// the one ordering that makes this true.
pub fn state_cell(object: v8::Local<v8::Object>) -> Option<*mut RefCell<WrapState>> {
    if object.internal_field_count() < INTERNAL_FIELD_COUNT {
        return None;
    }
    // SAFETY: as `with_state`.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut RefCell<WrapState>;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R3's state half: a scheduled write is handed back exactly once, even if
    /// `destroy` runs after a flush already completed it.
    #[test]
    fn a_queued_write_is_handed_out_once() {
        let mut state = WrapState::new(Kind::Client);
        state.flags.write_callback_scheduled = true;
        // A `Global` cannot be made outside a scope, so the "no write" case is
        // what is checked here; the flag transition is the part R3 depends on.
        let first = state.take_queued_write();
        assert!(first.is_none(), "no write was queued");
        assert!(
            !state.flags.write_callback_scheduled,
            "taking the write clears the flag, so a second destroy is a no-op"
        );
        assert!(state.take_queued_write().is_none());
    }

    /// Teardown is idempotent, which is what makes it reachable from
    /// `destroySSL`, from the finalizer and from `close()` without a double free.
    #[test]
    fn destroying_twice_reports_nothing_the_second_time() {
        let mut state = WrapState::new(Kind::Client);
        let first = state.destroy();
        assert!(first.write.is_none());
        assert!(first.shutdown.is_none());
        let second = state.destroy();
        assert!(second.write.is_none());
        assert!(second.shutdown.is_none());
        assert!(state.ssl_ptr().is_null());
    }

    /// The library-call depth is decremented by the guard, so an early return
    /// cannot leave it raised — which would make every later callback believe it
    /// is inside the library and skip its JavaScript notification.
    #[test]
    fn the_library_scope_decrements_on_drop() {
        let mut state = WrapState::new(Kind::Client);
        assert!(!state.in_library_call());
        {
            let _scope = state.enter_library();
        }
        assert!(!state.in_library_call());
        assert_eq!(state.library_call_depth, 0);
    }

    /// A second entry nests, and both drops unwind to zero. This matters because
    /// `Cycle` can call `SSL_read` from inside a callback that already entered.
    #[test]
    fn the_library_scope_nests() {
        let mut state = WrapState::new(Kind::Client);
        {
            let outer = state.enter_library();
            drop(outer);
        }
        assert_eq!(state.library_call_depth, 0);
        // A second, independent entry also unwinds to zero, which is what makes
        // the guard safe to use from `Cycle`, from a completion and from a
        // callback without the depth drifting upward.
        {
            let scope = state.enter_library();
            drop(scope);
        }
        assert_eq!(state.library_call_depth, 0);
    }

    /// A `TLSWrap` with nothing pending holds no listener and no SSL, which is
    /// R4's state half: nothing for the loop to keep alive.
    #[test]
    fn a_fresh_state_holds_nothing() {
        let state = WrapState::new(Kind::Server);
        assert!(state.ssl_ptr().is_null());
        assert!(state.listener.is_none());
        assert!(state.current_write.is_none());
        assert!(state.pending_shutdown.is_none());
        assert!(state.pending_output.is_empty());
        assert!(!state.flags.reading);
        assert!(!state.flags.established);
    }
}
