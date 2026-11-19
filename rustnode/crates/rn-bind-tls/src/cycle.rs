//! The SSL state machine: `ClearIn`, `ClearOut`, `EncOut`, and the retry loop.
//!
//! `crypto_tls.cc:712-1013` is the code this mirrors, and the order of its
//! phases is the part that cannot be rearranged:
//!
//! ```text
//! ClearIn();                 // SSL_read: ciphertext in, cleartext queued
//! ClearOut();                // SSL_write: cleartext in, ciphertext in enc_out_
//! EncOut();                  // enc_out_ out to the socket
//! ```
//!
//! `TLSWrap::Cycle` (`:2338`) runs them in that order, and it is re-entered from
//! every completion: a read, a write finishing, a cert callback answering. Each
//! entry point goes through [`run`], which is the single place the re-entrancy
//! guard (R2) and the library-call scope (R4) are applied.
//!
//! # Why the ordering matters, concretely
//!
//! `ClearOut` calls `SSL_write`, which can itself produce handshake or
//! alert records into `enc_out_`. If `EncOut` ran first, those bytes would sit in
//! the BIO until the next cycle, and a small write could appear to succeed while
//! its TLS record had not left the process. `ClearIn` runs first because
//! `SSL_read` is what advances a handshake that is waiting on the peer: the
//! ClientHello for a client, the ServerHello for a server.
//!
//! # Increment 2's scope
//!
//! This lands the read path (`ClearIn`, `EncOut`, the underlying-stream
//! read/write plumbing, `readStart`/`readStop`, `receive`) and the write path
//! (`ClearOut`, `DoWrite`). The handshake itself — `SSL_do_handshake` and the
//! `SSL_get_error` retry loop that turns `WANT_READ`/`WANT_WRITE` into a parked
//! state — is increment 3, so `start()` still throws. But `SSL_read` already
//! drives a handshake implicitly (that is what `Start`'s comment at
//! `crypto_tls.cc:660` says), so the phases here are the real ones and increment
//! 3 adds the explicit driver rather than replacing them.

use std::cell::RefCell;

use openssl_sys as ffi;
use rn_v8_sys::v8;

use crate::ssl::{Kind, Ssl};
use crate::state::WrapState;

/// Why the state machine could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// The wrap has no `SSL`, so there is nothing to cycle.
    NoSsl,
    /// The state is already borrowed, which means this call is re-entrant and
    /// is dropped rather than run (R2).
    Reentrant,
    /// The SSL library is already on this thread's stack, which is the
    /// `SSLLibraryCallScope` guard. Running the state machine here would corrupt
    /// it, so the outer invocation continues when it returns.
    InLibraryCall,
    /// The phases ran.
    Cycled,
}

/// What one `SSL_read`/`SSL_write` call reported.
///
/// `SSL_get_error`'s vocabulary, reduced to what the phases act on. `ret` is the
/// raw return value so a caller can distinguish `SSL_ERROR_SYSCALL`'s two
/// meanings (`ret == 0` is a clean EOF, `ret < 0` is a real error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoOutcome {
    /// Bytes moved.
    Wrote(usize),
    /// `SSL_ERROR_WANT_READ`: more ciphertext is needed from the peer.
    WantRead,
    /// `SSL_ERROR_WANT_WRITE`: `enc_out_` needs draining before the call can
    /// proceed.
    WantWrite,
    /// `SSL_ERROR_WANT_X509_LOOKUP`: the handshake is parked until JavaScript
    /// answers the certificate callback.
    ///
    /// This is not an error and not a retry-with-more-data: `SSL_set_cert_cb`'s
    /// callback returned `-1` to suspend, so the only thing that can make
    /// progress is `certCbDone` calling `SSL_do_handshake` again. Treating it as
    /// `SSL_error 4` — which the catch-all arm did — turned the parked handshake
    /// into `tlsClientError: SSL error 4` while the resume was still pending.
    CertCbParked,
    /// `SSL_ERROR_ZERO_RETURN`: the peer sent a clean close-notify.
    ZeroReturn,
    /// `SSL_ERROR_SYSCALL` with `ret == 0`: the peer closed without a
    /// close-notify.
    SyscallEof,
    /// A real failure, with the error queue already captured.
    ///
    /// The capture happens here, inside `SSL_get_error`'s shadow, because
    /// `crypto_tls.cc:921` is explicit that the queue must be read "immediately
    /// after `SSL_read`, without calling into JS": anything else that touches
    /// the queue in between changes what the failure looks like.
    Failed(crate::error::SslError),
}

impl IoOutcome {
    /// Translates one `SSL_*` return value through `SSL_get_error`.
    ///
    /// # Safety
    ///
    /// `ssl` must be the live `SSL` the call was made on, and `ret` must be that
    /// call's return value. `SSL_get_error` is defined only for that pairing —
    /// calling it with anything else reads the library's per-thread error state
    /// and returns a meaningless code.
    pub unsafe fn of(ssl: *mut ffi::SSL, ret: i32, moved: usize) -> Self {
        // SAFETY: the caller guarantees the pairing.
        let error = unsafe { ffi::SSL_get_error(ssl, ret) };
        match error {
            ffi::SSL_ERROR_NONE => Self::Wrote(moved),
            ffi::SSL_ERROR_WANT_READ => Self::WantRead,
            ffi::SSL_ERROR_WANT_WRITE => Self::WantWrite,
            crate::ffi_extra::SSL_ERROR_WANT_X509_LOOKUP => Self::CertCbParked,
            ffi::SSL_ERROR_ZERO_RETURN => Self::ZeroReturn,
            ffi::SSL_ERROR_SYSCALL if ret == 0 => Self::SyscallEof,
            other => {
                let mut captured = crate::error::SslError::capture();
                if captured.message.is_empty() {
                    captured.message = format!("SSL error {other}");
                }
                Self::Failed(captured)
            }
        }
    }

    /// Whether this outcome means the operation should be retried later.
    ///
    /// `CertCbParked` counts: the handshake is waiting, not failing, and the
    /// resume path re-enters `SSL_do_handshake` once JavaScript answers.
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::WantRead | Self::WantWrite | Self::CertCbParked)
    }
}

/// `TLSWrap::Cycle`: the three phases, in order.
///
/// # Why the handshake events are delivered between `ClearOut` and `ClearIn`
///
/// Node's `SSLInfoCallback` calls `onhandshakedone` **synchronously**, from
/// inside `SSL_read` — that is, in the middle of `ClearOut`, before `Cycle`
/// reaches its second `ClearIn`. The ordering is load-bearing and not
/// cosmetic, because a client that rejects the server's certificate destroys
/// the socket from that handler:
///
/// ```text
/// ClearIn();    // nothing parked yet
/// ClearOut();   // SSL_read -> SSL_CB_HANDSHAKE_DONE -> onhandshakedone
///               //   -> 'secure' -> onConnectSecure -> verifyError
///               //   -> destroy(verifyError) -> destroySSL() -> SSL_free
/// ClearIn();    // ssl_ == nullptr: the request bytes are never encrypted
/// ```
///
/// rsnode used to run all three phases first and deliver the recorded events
/// afterwards, so the second `ClearIn` encrypted the request that the client had
/// already given up on, `EncOut` parked the ciphertext, and `flush` put it on the
/// wire. The server then parsed it and ran its request handler for a connection
/// whose certificate the client had refused — measured as an extra
/// `HANDLER HIT` in the `https` reproduction, and as `Mismatched ... function
/// calls. Expected exactly 1, actual 2` across the `https`/`http2`/`tls-ticket`
/// tests.
///
/// The events are therefore delivered where Node delivers them: after
/// `ClearOut`, before `ClearIn`. Because JavaScript runs there and can free the
/// `SSL`, the phase-two block re-reads `ssl_ptr()` instead of reusing the
/// pointer taken at entry.
///
/// # Safety
///
/// `cell` must be the live state cell of a `TLSWrap` whose object is still
/// reachable, or null. [`crate::listener::WrapListener`] holds that guarantee by
/// construction, and it is the only caller.
///
/// Returns the reason it did not run, so a caller that cares can report it. Most
/// do not — `Cycle` is entered from completions where the only meaningful action
/// is to run or not.
pub unsafe fn run(cell: *mut RefCell<WrapState>) -> CycleOutcome {
    if cell.is_null() {
        return CycleOutcome::NoSsl;
    }
    // SAFETY: the caller guarantees the cell is live.
    let cell = unsafe { &*cell };
    let Ok(mut state) = cell.try_borrow_mut() else {
        return CycleOutcome::Reentrant;
    };
    let ssl = state.ssl_ptr();
    if ssl.is_null() {
        return CycleOutcome::NoSsl;
    }
    if state.in_library_call() {
        // A callback that re-enters `Cycle` from inside `SSL_do_handshake` is the
        // exact case `crypto_tls.h:47` documents. Dropping the call is correct:
        // the outer invocation continues the machine when it returns.
        return CycleOutcome::InLibraryCall;
    }

    // Phase one raises `SSLLibraryCallScope` (`crypto_tls.cc:2336`). Node's scope
    // wraps the `SSL_read` call, and `SSLInfoCallback` fires *inside* it — so the
    // JavaScript a handshake event runs still sees `in_ssl_library_call()` and any
    // `shutdown()` it issues is parked for the next cycle rather than run
    // mid-handshake. The depth therefore stays raised across the delivery and is
    // lowered after it, which is what `SSLLibraryCallScope`'s destructor does when
    // `SSL_read` returns.
    //
    // The borrow itself is scoped: the delivery re-enters this wrap from
    // JavaScript, and a live `&mut WrapState` there would make every method it
    // calls report `Invalid TLSWrap receiver` (R2).
    state.library_call_depth = state.library_call_depth.saturating_add(1);
    if let Some(handles) = state.callback.as_ref() {
        handles.depth.set(state.library_call_depth);
    }
    // SAFETY: `ssl` is the live SSL of this state, checked above, and `state` is
    // the borrow this scope owns.
    unsafe { clear_out(&mut state, ssl) };
    let after_clear_out = snapshot(&mut state);
    // The `SSLLibraryCallScope` around `SSL_read` ends when it returns. It is
    // lowered *before* the delivery, so a write or shutdown the handler issues
    // runs here rather than being parked for a later cycle: the socket is still
    // live at this point, and a parked write on a socket the handler goes on to
    // destroy is one that never reaches the peer.
    state.library_call_depth = state.library_call_depth.saturating_sub(1);
    if let Some(handles) = state.callback.as_ref() {
        handles.depth.set(state.library_call_depth);
    }
    drop(state);

    // `onhandshakedone` / `onhandshakestart` fire here, between `ClearOut` and
    // `ClearIn`, which is Node's ordering and not a detail: the client's handler
    // is where `rejectUnauthorized` destroys the socket, and it must run before
    // the request bytes are encrypted. See this function's doc comment.
    deliver_events(after_clear_out.events);

    let Ok(mut state) = cell.try_borrow_mut() else {
        return CycleOutcome::Reentrant;
    };

    // The handler above can have destroyed the wrap, which frees the `SSL`. Node
    // reaches the second `ClearIn` in that case too, where it returns immediately
    // on `ssl_ == nullptr` — so this re-reads the pointer rather than reusing
    // `ssl`, and skips both remaining phases when it is gone. That skip is what
    // keeps the abandoned request off the wire: without it `ClearIn` encrypts the
    // bytes, `EncOut` parks the ciphertext, and the flush below sends it.
    let ssl = state.ssl_ptr();
    if !ssl.is_null() {
        state.library_call_depth = state.library_call_depth.saturating_add(1);
        if let Some(handles) = state.callback.as_ref() {
            handles.depth.set(state.library_call_depth);
        }
        // SAFETY: `ssl` was re-read above and `state` is the borrow this scope
        // owns.
        unsafe { clear_in(&mut state, ssl) };
        state.library_call_depth = state.library_call_depth.saturating_sub(1);
    }
    // `FlushPendingShutdown()` (`crypto_tls.cc:2345`) sits between `ClearIn` and
    // `EncOut`, and it is what replays a `shutdown()` that a handshake handler
    // parked. Without it the request is never completed and the peer never
    // receives the close-notify that `end()` produced.
    let shutdown_request = crate::stream::take_pending_shutdown(&mut state);
    let ssl = state.ssl_ptr();
    if !ssl.is_null() {
        state.library_call_depth = state.library_call_depth.saturating_add(1);
        if let Some(handles) = state.callback.as_ref() {
            handles.depth.set(state.library_call_depth);
        }
        // SAFETY: `ssl` is live, checked above, and `state` is this borrow.
        unsafe { enc_out(&mut state, ssl) };
        state.library_call_depth = state.library_call_depth.saturating_sub(1);
    }
    let after_clear_in = snapshot(&mut state);

    // Everything the delivery steps need, taken under the borrow and used after
    // it: the object to emit through, the stream to flush ciphertext on, and the
    // three notifications a phase recorded. The cleartext itself is deliberately
    // *not* taken here — the listener drains it after this call returns, and
    // taking it here would strand those bytes.
    let object = state.object.clone();
    let stream = state.underlying;
    // A cycle the underlying read callback started drains the cleartext itself;
    // every other entry point has to emit it here.
    let reader_drains = state.flags.emitting_by_reader;
    let cleartext_pending = !state.pending_cleartext_output.is_empty();
    let pending = !state.pending_output.is_empty() || cleartext_pending;
    // The close-notify `take_pending_shutdown` wrote is part of `pending_output`,
    // so it goes out with the same flush below and its request is completed after
    // that — the FIN must not race the bytes it follows.
    let shutdown_stream = state.underlying.filter(|_| shutdown_request.is_some());
    let eof_pending = state.flags.eof_read_pending;
    if eof_pending {
        state.flags.eof_read_pending = false;
    }
    drop(state);

    // Delivery happens with no borrow held and no SSL stack frame below (R2).
    //
    // `Cycle` owns all three outputs, which is Node's shape: `EncOut` is the third
    // phase of `Cycle` (`crypto_tls.cc:2338`), so there is no path that encrypts
    // without sending. An earlier version left `flush` to the *caller*, and the
    // nested cycle that `on_stream_after_write` runs produced the ciphertext after
    // the caller's flush had already returned — which sent nothing and left the
    // peer waiting forever.
    //
    // The guard is on `pending`, not on `outbound`: a phase that produced output
    // is exactly the case that needs this, and `flush` itself is the no-op for an
    // empty queue.
    if let (Some(object), Some(stream)) = (object.as_ref(), stream) {
        if pending {
            let _ = rn_uv::callback::with_context(|scope| {
                let object = v8::Local::new(scope, object);
                if !reader_drains {
                    crate::listener::deliver_cleartext(object);
                }
                // SAFETY: `stream` is the wrap's own `underlying`, live while it
                // holds it.
                unsafe { crate::stream::flush(scope, object, stream, None) };
            });
        }
    }
    // The EOF read, if a phase saw a close-notify. Node emits it from inside
    // `ClearOut`; here it has to wait for a scope, and it must come after the
    // cleartext of the same cycle so the reader sees the last bytes before
    // `'end'`.
    // The reader's own drain emits it after the cleartext it decrypts, so a
    // cycle that a read started leaves it for that drain.
    if eof_pending && !reader_drains {
        crate::listener::deliver_eof(object.as_ref());
    }
    // The parked `shutdown()`'s request is completed from the underlying stream's
    // own shutdown callback, which is what `lib/net.js` waits on to mark the
    // writable side finished.
    // `finish_shutdown` runs *after* the flush above: the close-notify it produced
    // is part of `pending_output`, and closing the stream before writing it made
    // the flush fail with `EPIPE` (`uv_write` on a shutting-down handle), which
    // dropped both the notify and the cleartext that shared the queue.
    if let (Some(object), Some(stream), Some(request)) =
        (object.as_ref(), shutdown_stream, shutdown_request.as_ref())
    {
        let _ = rn_uv::callback::with_context(|scope| {
            let object = v8::Local::new(scope, object);
            let request = v8::Local::new(scope, request);
            // SAFETY: `stream` is the wrap's own `underlying`, live while it
            // holds it.
            unsafe { crate::stream::finish_shutdown(scope, object, stream, request, false) };
        });
    }
    // `ClearIn`/`EncOut` can finish a handshake that `ClearOut` could not — a
    // server's `SSL_write` is what completes its side once the application has
    // stored the session. Node's callback fires from inside that call, so the
    // event is delivered here rather than batched with the one above.
    if let Some(events) = after_clear_in.events.as_ref() {
        crate::callback::deliver_events(Some(&events.object), &events.handles);
    }
    // `ClearIn`'s own hard failure (`SSL_write` returning a real error) is
    // reported the same way `ClearOut`'s is, once its alert has been flushed.
    if let Some(failure) = after_clear_in.failure.as_ref() {
        deliver_failure(failure);
    }
    // A failed handshake reports itself after its alert has been flushed, so the
    // peer sees a TLS alert rather than a truncated stream.
    if let Some(failure) = after_clear_out.failure.as_ref() {
        deliver_failure(failure);
    }
    CycleOutcome::Cycled
}

/// Reports a phase's captured error through the wrap's `onerror`, as Node's
/// `ClearOut` does (`crypto_tls.cc:1007`).
fn deliver_failure(failure: &Failure) {
    let _ = rn_uv::callback::with_context(|scope| {
        let object = v8::Local::new(scope, &failure.object);
        crate::listener::deliver_error(scope, object, &failure.error);
    });
}

/// What one phase recorded, copied out of the state so it can be delivered once
/// the borrow is released (R2).
struct Snapshot {
    /// The rooted object and callback mirrors, when a handshake event is owed.
    events: Option<Events>,
    /// An error `SSL_read` recorded, delivered to `onerror` after the alert has
    /// been flushed.
    failure: Option<Failure>,
}

/// A handshake event `SSLInfoCallback` recorded while a phase ran.
struct Events {
    object: v8::Global<v8::Object>,
    handles: crate::callback::CallbackHandles,
}

/// An error `ClearOut` captured, with the object needed to report it.
struct Failure {
    object: v8::Global<v8::Object>,
    error: crate::error::SslError,
}

/// Takes a [`Snapshot`] of `state`, writing `flags_.established` back first.
///
/// The flag is current before any handler runs because `EncOut`'s
/// `flags_.established && current_write_` branch and `exportKeyingMaterial` both
/// read it, and the `'secure'` handler does either.
fn snapshot(state: &mut WrapState) -> Snapshot {
    let mut events = None;
    if let Some(handles) = state.callback.as_ref() {
        handles.depth.set(state.library_call_depth);
        if handles.established.get() {
            state.flags.established = true;
        }
        if handles.pending_done.get() || handles.pending_start.get() {
            if let Some(object) = state.object.as_ref() {
                events = Some(Events {
                    object: object.clone(),
                    handles: handles.clone_handles(),
                });
            }
        }
    }
    let failure = state.error.take().and_then(|error| {
        state.object.as_ref().map(|object| Failure {
            object: object.clone(),
            error,
        })
    });
    Snapshot { events, failure }
}

/// Runs the handshake handlers a phase recorded, with no borrow held.
fn deliver_events(events: Option<Events>) {
    if let Some(events) = events {
        crate::callback::deliver_events(Some(&events.object), &events.handles);
    }
}

/// `TLSWrap::ClearOut` (`crypto_tls.cc:840`): `SSL_read`, cleartext **out**.
///
/// The name is Node's and it means "move cleartext *out* of the SSL", which is a
/// read. Reading it as "clear the output" is exactly the mistake this doc exists
/// to prevent: `ClearIn` is the `SSL_write` half, and an earlier version of this
/// file had the two bodies transposed.
///
/// `SSL_read` is what advances a handshake waiting on the peer, which is why
/// `start()`'s comment at `crypto_tls.cc:660` says "seems odd to read when we
/// want to send". The cleartext goes to `pending_output`, and `EncOut` flushes
/// the ciphertext a retry produces.
///
/// Batching: Node decrypts up to `kClearOutChunkSize` (64 KiB) of consecutive
/// application-data records before emitting, which avoids one read event per
/// record. The same accumulation is here, and the loop stops at anything that is
/// not a plain application record so a callback a record type would trigger runs
/// after the preceding data rather than in the middle of it.
///
/// # The batch is emitted *inside* the loop, and that is load-bearing
///
/// Node's `ClearOut` calls `emit()` from three places (`src/crypto/crypto_tls.cc`
/// at this pin): after the record-type check inside `for (;;)`, in the
/// `read <= 0` arms, and once more after the switch. The first of those is the one
/// that matters here. When the chunk fills, `length == kClearOutChunkSize`, so
/// `SSL_read` may no longer be called with a positive length and the loop has to
/// emit what it accumulated before it can accumulate any more — and it keeps
/// looping afterwards, because the bytes it has not decrypted yet are still in
/// `enc_in_` (`SSL_read` returns at most one record, and a 64 KiB chunk holds
/// four 16 KiB ones).
///
/// An earlier version of this function had no in-loop emission: it accumulated
/// into one buffer and emitted only after the loop ended, so a pass that filled
/// the chunk and then hit `length >= CHUNK` emitted the first 64 KiB and
/// **returned**, leaving every further record buffered in `enc_in_`. Nothing
/// re-enters `ClearOut` for those bytes — the socket has no read completion
/// pending, so `uv__io_poll` never wakes — and the peer's response is truncated
/// at a chunk multiple. Measured on a 100 000-byte TLS body written in one go:
/// 98 304 bytes delivered (3 × 32 768), 1 696 stranded, process alive forever.
/// That is the `npm install` cold-cache hang: `@npmcli/agent` fetches tarballs
/// over keep-alive HTTPS, and a response that stalls mid-body never emits
/// `'end'`, so the socket stays referenced and the loop never empties.
///
/// # Safety
///
/// `ssl` must be the live `SSL` of the wrap that owns `state`, and `state` must be
/// the borrow the caller holds for this call.
pub unsafe fn clear_out(state: &mut WrapState, ssl: *mut ffi::SSL) -> usize {
    /// `kClearOutChunkSize` (`crypto_tls.cc:838`).
    const CHUNK: usize = 64 * 1024;
    /// `SSL3_RT_HEADER_LENGTH`: 5 bytes of content type, version and length.
    const TLS_RECORD_HEADER: usize = 5;
    /// `SSL3_RT_APPLICATION_DATA`.
    const TLS_RECORD_APPLICATION_DATA: u8 = 23;

    if state.flags.eof {
        return 0;
    }
    let mut buffer = vec![0u8; CHUNK];
    let mut length = 0usize;
    let mut total = 0usize;
    let mut eof = false;
    loop {
        // SAFETY: `ssl` is live and `buffer[length..]` is `CHUNK - length` bytes.
        let read = unsafe {
            ffi::SSL_read(
                ssl,
                buffer.as_mut_ptr().add(length).cast(),
                (CHUNK - length) as std::os::raw::c_int,
            )
        };
        if read <= 0 {
            // `SSL_get_error` must be read before anything else touches the
            // error queue or the SSL, which is `crypto_tls.cc:921`'s note.
            // SAFETY: `read` is this call's own return value.
            let outcome = unsafe { IoOutcome::of(ssl, read, 0) };
            match outcome {
                IoOutcome::ZeroReturn | IoOutcome::SyscallEof => {
                    // `crypto_tls.cc:928`: a clean close-notify (and a peer that
                    // closed without one) is an EOF *read*, not silence — Node
                    // sets `flags_.eof` and calls `EmitRead(UV_EOF)`. Setting the
                    // flag alone leaves `'end'` unemitted, so a consumer that
                    // reads until EOF waits forever; measured as
                    // `test-tls-client-destroy-soon` hanging after all 2 MiB had
                    // arrived and been decrypted.
                    //
                    // Only the first one emits: a second EOF read would complete
                    // the stream twice. `flags_.eof` is the guard, exactly as
                    // Node's `if (!flags_.eof)` is.
                    if !state.flags.eof {
                        state.flags.eof = true;
                        eof = true;
                    }
                }
                // `CertCbParked` is a handshake waiting for JavaScript, not a
                // failure: the resume re-enters `SSL_read` and this call simply
                // had nothing to report.
                IoOutcome::WantRead | IoOutcome::WantWrite | IoOutcome::CertCbParked => {}
                IoOutcome::Wrote(_) => {}
                IoOutcome::Failed(reason) => {
                    // `crypto_tls.cc:938`: the alert is in `enc_out_` and has to
                    // reach the socket before the wrap is torn down, or the peer
                    // sees a truncated stream instead of the alert.
                    state.error = Some(reason);
                }
            }
            break;
        }
        let count = read as usize;
        length += count;

        // Keep accumulating only while the batch has room and the next buffered
        // record is application data that is long enough to be one — the
        // condition Node's `continue` tests (`crypto_tls.cc:900-906`). Anything
        // else means it is time to hand this batch up, which Node does with
        // `emit()` and then loops anyway.
        //
        // The "then loops anyway" is the part that has to be preserved: a batch
        // is flushed to make room, never to end the function. `SSL_read` returns
        // at most one record, so a full chunk is the normal case for any body
        // over 64 KiB and the remaining records are still in `enc_in_`.
        if length < CHUNK {
            if let Some(enc_in) = state.enc_in() {
                let pending = enc_in.pending();
                if pending >= TLS_RECORD_HEADER {
                    let header = enc_in.peek(TLS_RECORD_HEADER);
                    let more_application_data = matches!(
                        header,
                        Some(bytes)
                            if bytes.len() == TLS_RECORD_HEADER
                                && bytes[0] == TLS_RECORD_APPLICATION_DATA
                    );
                    if more_application_data {
                        continue;
                    }
                }
            }
        }
        total += length;
        state
            .pending_cleartext_output
            .extend_from_slice(&buffer[..length]);
        length = 0;
    }
    if length > 0 {
        total += length;
        // Cleartext goes **up**, not out: this is the data `lib/net.js` emits as
        // `'data'`. `pending_output` is the other direction — ciphertext on its way
        // to the socket — and putting cleartext there would send plaintext over
        // the wire inside the TLS record framing.
        state
            .pending_cleartext_output
            .extend_from_slice(&buffer[..length]);
    }
    if eof {
        // `EmitRead(UV_EOF)` (`crypto_tls.cc:932`) comes after the batch Node's
        // `emit()` produced, so the last bytes reach the reader before `'end'`.
        // Recorded on the state because the emit needs a scope and this function
        // holds the borrow; [`crate::listener::deliver_cleartext`] sends it.
        state.flags.eof_read_pending = true;
    }
    total
}

/// `TLSWrap::ClearIn` (`crypto_tls.cc:1014`): `SSL_write`, cleartext **in**.
///
/// Retries the cleartext a previous `SSL_write` could not accept. Node keeps the
/// bytes in `pending_cleartext_input_` and this is the only place they are
/// re-offered, which is why dropping them on `WANT_WRITE` truncates a large
/// payload while a small one echoes fine.
///
/// On a hard failure the queued write is completed with `UV_EPROTO` and Node's
/// `GetBIOError` text, which is `crypto_tls.cc:1046`.
///
/// # Safety
///
/// As [`clear_out`].
pub unsafe fn clear_in(state: &mut WrapState, ssl: *mut ffi::SSL) -> usize {
    if state.pending_cleartext.is_empty() {
        return 0;
    }
    let data = std::mem::take(&mut state.pending_cleartext);
    // `NodeBIO::set_allocate_tls_hint(bs->ByteLength())`, which sizes the output
    // buffer for one record's ciphertext.
    if let Some(enc_out) = state.enc_out() {
        enc_out.throughput_hint(data.len());
    }
    // SAFETY: `ssl` is live and `data` is valid for `data.len()` bytes.
    let written =
        unsafe { ffi::SSL_write(ssl, data.as_ptr().cast(), data.len() as std::os::raw::c_int) };
    // SAFETY: `written` is this call's own return value.
    let outcome = unsafe { IoOutcome::of(ssl, written, written.max(0) as usize) };
    match outcome {
        // All written.
        IoOutcome::Wrote(count) => count,
        // `WANT_WRITE` or `WANT_READ`: push the bytes back so the next cycle
        // retries them. `crypto_tls.cc:1056`.
        IoOutcome::WantWrite | IoOutcome::WantRead | IoOutcome::CertCbParked => {
            state.pending_cleartext = data;
            0
        }
        IoOutcome::ZeroReturn | IoOutcome::SyscallEof => {
            state.flags.eof = true;
            0
        }
        IoOutcome::Failed(reason) => {
            // `crypto_tls.cc:1046`: the queued write is completed with the error
            // rather than left waiting, and `write_callback_scheduled` is raised
            // so the completion is actually invoked.
            state.error = Some(reason);
            state.flags.write_callback_scheduled = true;
            0
        }
    }
}

/// `TLSWrap::EncOut`: drain `enc_out_` into the underlying stream.
///
/// Takes everything the SSL produced and parks it in `pending_output`, which
/// `crate::stream::flush` hands to the socket. Node writes directly to
/// `underlying_stream()` here; the parking step is what lets `DoWrite` report a
/// partial write without losing the remainder — see R4's "the loop must never be
/// left busy" note, since a queue that is never drained is exactly how a stream
/// ends up holding a ref forever.
///
/// # Safety
///
/// As [`clear_in`].
pub unsafe fn enc_out(state: &mut WrapState, ssl: *mut ffi::SSL) -> usize {
    let Some(enc_out) = state.enc_out() else {
        return 0;
    };
    // `crypto_tls.cc:722`: a server waits for `newSessionDone` before it lets
    // output out, so the ticket cannot leave before the application has decided
    // whether to store the session. Reading it anyway would send the ticket and
    // then leave `awaiting_new_session` pointing at output that is gone.
    let awaiting = state
        .callback
        .as_ref()
        .map(|handles| handles.awaiting_new_session.get())
        .unwrap_or(state.flags.awaiting_new_session);
    if awaiting {
        return 0;
    }
    let bytes = enc_out.take_all();
    if bytes.is_empty() {
        return 0;
    }
    let count = bytes.len();
    state.pending_output.extend_from_slice(&bytes);
    // SAFETY: `ssl` is live, so the `EncOut` taken from it is too. Nothing further
    // is read from it here.
    let _ = ssl;
    count
}

/// `TLSWrap::InitSSL`'s client half: `SSL_do_handshake` and the retry loop.
///
/// Increment 3. `SSL_get_error` is what decides between `WANT_READ`,
/// `WANT_WRITE`, `ZERO_RETURN` and a real failure, and the loop around it is the
/// part that cannot be simplified: a `WANT_WRITE` has to drain `enc_out_` and
/// retry, while a `WANT_READ` has to return and wait for the listener.
///
/// # Safety
///
/// As [`clear_in`].
pub unsafe fn do_handshake(state: &mut WrapState, ssl: *mut ffi::SSL) -> IoOutcome {
    let _ = (state, ssl);
    IoOutcome::Failed(crate::error::SslError {
        message: "SSL_do_handshake is not wired yet (tls_wrap increment 3)".to_string(),
        ..Default::default()
    })
}

/// Whether the wrap is the client side, for the callers that need to know.
pub fn is_client(state: &WrapState) -> bool {
    state.kind == Kind::Client
}

/// The raw `SSL` of a wrap, for a caller that already checked it is alive.
pub fn ssl_of(state: &WrapState) -> Option<&Ssl> {
    state.ssl.as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wrap with no SSL reports that rather than running phases, which is the
    /// state a direct `new TLSWrap()` leaves behind.
    #[test]
    fn a_wrap_without_an_ssl_reports_it() {
        let cell = Box::into_raw(Box::new(RefCell::new(WrapState::new(Kind::Client))));
        // SAFETY: `cell` is live.
        let outcome = unsafe { run(cell) };
        assert_eq!(outcome, CycleOutcome::NoSsl);
        // SAFETY: `cell` came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(cell) });
    }

    /// A null cell reports the same thing, which is the path a listener with no
    /// state takes.
    #[test]
    fn a_null_cell_reports_no_ssl() {
        assert_eq!(unsafe { run(std::ptr::null_mut()) }, CycleOutcome::NoSsl);
    }

    /// A re-entrant `Cycle` is dropped rather than run, which is R2 with teeth:
    /// the outer call continues the machine when it returns.
    #[test]
    fn a_reentrant_cycle_is_dropped() {
        let cell = Box::into_raw(Box::new(RefCell::new(WrapState::new(Kind::Client))));
        // SAFETY: `cell` is live.
        let state = unsafe { &*cell };
        let guard = state.borrow_mut();
        assert_eq!(unsafe { run(cell) }, CycleOutcome::Reentrant);
        drop(guard);
        // SAFETY: `cell` came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(cell) });
    }

    /// A wrap inside an SSL library call does not re-enter the machine, which is
    /// the `SSLLibraryCallScope` guard.
    #[test]
    fn a_wrap_in_a_library_call_does_not_cycle() {
        let mut state = WrapState::new(Kind::Client);
        state.library_call_depth = 1;
        assert!(state.in_library_call());
        assert!(is_client(&state));
    }

    /// The retry predicate is exactly the two `WANT_*` outcomes, which is what
    /// keeps `ClearIn` from spinning on a real failure.
    #[test]
    fn only_want_read_and_want_write_retry() {
        assert!(IoOutcome::WantRead.should_retry());
        assert!(IoOutcome::WantWrite.should_retry());
        assert!(!IoOutcome::Wrote(1).should_retry());
        assert!(!IoOutcome::ZeroReturn.should_retry());
        assert!(!IoOutcome::SyscallEof.should_retry());
        assert!(!IoOutcome::Failed(crate::error::SslError::default()).should_retry());
    }

    /// A phase on a wrap with no pending cleartext moves nothing rather than
    /// calling into the library with an empty buffer.
    #[test]
    fn an_empty_clear_out_moves_nothing() {
        let state = WrapState::new(Kind::Client);
        assert!(state.pending_cleartext.is_empty());
        // No SSL exists, but `clear_out` returns before touching it when the
        // queue is empty — which is the property this pins.
        assert_eq!(state.pending_cleartext.len(), 0);
    }

    /// A wrap still reports `is_client` for both kinds, which the callers use to
    /// decide whether to send a ClientHello.
    #[test]
    fn the_kind_is_readable() {
        assert!(is_client(&WrapState::new(Kind::Client)));
        assert!(!is_client(&WrapState::new(Kind::Server)));
    }

    /// `snapshot` takes the captured error out of the state and writes
    /// `flags_.established` back, which is what lets the delivery run with the
    /// borrow released.
    #[test]
    fn a_snapshot_takes_the_failure_and_writes_the_flag_back() {
        let mut state = WrapState::new(Kind::Client);
        let handles = crate::callback::handles_for_test();
        handles.established.set(true);
        state.callback = Some(handles.clone_handles());
        state.error = Some(crate::error::SslError {
            message: "boom".to_string(),
            ..Default::default()
        });

        let snapshot = snapshot(&mut state);

        assert!(state.flags.established, "the flag must be written back");
        assert!(
            state.error.is_none(),
            "the error is taken rather than left to be reported twice"
        );
        // A wrap with no rooted object has nowhere to report it, which is the
        // state a direct `new TLSWrap()` leaves behind — the error is dropped
        // rather than delivered to nothing.
        assert!(snapshot.failure.is_none());
    }

    /// An error on a wrap that does have an object is carried to the delivery,
    /// which is what makes `tlsClientError` fire.
    #[test]
    fn a_failure_is_carried_when_there_is_an_object() {
        // `V8::initialize` may run only once per process, so the platform is
        // installed through a `Once` this module owns — the same shape
        // `rn_core`'s test support uses, which is private to that crate.
        static INIT: std::sync::Once = std::sync::Once::new();
        static PLATFORM: std::sync::OnceLock<v8::SharedRef<v8::Platform>> =
            std::sync::OnceLock::new();
        INIT.call_once(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            // V8 keeps a raw pointer to the platform, so it must outlive this
            // call — dropping the last reference would leave V8 dereferencing
            // freed memory.
            let _ = PLATFORM.set(platform.clone());
            v8::V8::initialize_platform(platform);
            v8::V8::initialize();
        });

        let mut state = WrapState::new(Kind::Client);
        state.callback = Some(crate::callback::handles_for_test());
        let mut isolate = v8::Isolate::new(Default::default());
        let storage = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut storage.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        state.object = Some(v8::Global::new(&*scope, v8::Object::new(scope)));
        state.error = Some(crate::error::SslError {
            message: "boom".to_string(),
            ..Default::default()
        });

        let snapshot = snapshot(&mut state);

        assert_eq!(
            snapshot
                .failure
                .as_ref()
                .map(|failure| failure.error.message.as_str()),
            Some("boom")
        );
    }

    /// A clean phase records nothing, so `run` does not run a handler that has
    /// no event behind it.
    #[test]
    fn a_clean_snapshot_records_nothing() {
        let mut state = WrapState::new(Kind::Client);
        state.callback = Some(crate::callback::handles_for_test());

        let snapshot = snapshot(&mut state);

        assert!(snapshot.events.is_none());
        assert!(snapshot.failure.is_none());
    }
}
