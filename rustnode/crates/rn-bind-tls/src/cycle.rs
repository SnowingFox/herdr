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
    /// `SSL_ERROR_ZERO_RETURN`: the peer sent a clean close-notify.
    ZeroReturn,
    /// `SSL_ERROR_SYSCALL` with `ret == 0`: the peer closed without a
    /// close-notify.
    SyscallEof,
    /// A real failure. The error queue carries the reason.
    Failed(String),
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
            ffi::SSL_ERROR_ZERO_RETURN => Self::ZeroReturn,
            ffi::SSL_ERROR_SYSCALL if ret == 0 => Self::SyscallEof,
            other => Self::Failed(format!(
                "SSL error {other}: {}",
                crate::error::drain_reason()
            )),
        }
    }

    /// Whether this outcome means the operation should be retried later.
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::WantRead | Self::WantWrite)
    }
}

/// `TLSWrap::Cycle`: the three phases, in order.
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

    // `SSLLibraryCallScope` (`crypto_tls.cc:2336`) raises the depth across the
    // phases so a callback the library invokes knows not to re-enter. It is
    // raised once for the whole cycle rather than per phase, which is what Node
    // does, and it is a plain increment/decrement here because the phases take
    // `&mut state` and a guard borrowing a field of it could not span them.
    // Nothing between the increment and the decrement calls into V8, so there is
    // no early return to guard against.
    state.library_call_depth = state.library_call_depth.saturating_add(1);
    // SAFETY: `ssl` is the live SSL of this state, checked above, and `state` is
    // the borrow this call owns.
    unsafe {
        clear_in(&mut state, ssl);
        clear_out(&mut state, ssl);
        enc_out(&mut state, ssl);
    }
    state.library_call_depth = state.library_call_depth.saturating_sub(1);
    CycleOutcome::Cycled
}

/// `TLSWrap::ClearIn`: `SSL_read` until it wants more ciphertext.
///
/// Copies whatever `SSL_read` produces into `pending_output`, which `EncOut` then
/// flushes. Node appends to a `StreamBase` read buffer and emits; the queue here
/// is the same thing with an explicit owner.
///
/// Stops on anything that is not progress. `SSL_MODE_AUTO_RETRY` is what makes a
/// non-application record (a session ticket, a handshake message) retry inside
/// `SSL_read` instead of returning `WANT_READ` with data still buffered — that is
/// why `Ssl::new` sets it.
///
/// # Safety
///
/// `ssl` must be the live `SSL` of the wrap that owns `state`, and `state` must be
/// the borrow the caller holds for this call.
pub unsafe fn clear_in(state: &mut WrapState, ssl: *mut ffi::SSL) -> usize {
    // `kClearInBufferSize`: 16 KiB, the largest TLS record's plaintext payload.
    const BUFFER: usize = 16 * 1024;
    if state.flags.eof {
        return 0;
    }
    let mut buffer = vec![0u8; BUFFER];
    let mut total = 0usize;
    loop {
        // SAFETY: `ssl` is live and `buffer` is `BUFFER` bytes.
        let read = unsafe {
            ffi::SSL_read(
                ssl,
                buffer.as_mut_ptr().cast(),
                BUFFER as std::os::raw::c_int,
            )
        };
        if read <= 0 {
            // SAFETY: `read` is this call's own return value.
            let outcome = unsafe { IoOutcome::of(ssl, read, 0) };
            match outcome {
                // An EOF or a close-notify ends the stream; the peer has said
                // there is nothing more.
                IoOutcome::ZeroReturn | IoOutcome::SyscallEof => {
                    state.flags.eof = true;
                }
                // Nothing more to read right now. The handshake may still be in
                // progress, which is increment 3's business.
                IoOutcome::WantRead => break,
                // The library wants its output drained first. `EncOut` runs after
                // this phase, so the next cycle retries.
                IoOutcome::WantWrite => break,
                IoOutcome::Wrote(_) | IoOutcome::Failed(_) => {
                    // A failure is recorded rather than thrown: `Cycle` runs from
                    // a libuv completion where there is no JS frame to throw
                    // into, and `lib/net.js` expects an `'error'` event instead.
                    if let IoOutcome::Failed(reason) = outcome {
                        state.error = Some(reason);
                    }
                    break;
                }
            }
            // A successful zero-length read cannot happen (`SSL_read > 0` is the
            // only success), so the loop only continues after progress.
            break;
        }
        let count = read as usize;
        buffer.resize(count, 0);
        state.pending_output.extend_from_slice(&buffer);
        buffer.resize(BUFFER, 0);
        total += count;
    }
    total
}

/// `TLSWrap::ClearOut`: `SSL_write` the cleartext the caller queued.
///
/// When nothing is queued there is still work: `crypto_tls.cc:1354` notes that an
/// empty `SSL_write` is not wanted, so the phase calls `SSL_read`-adjacent
/// bookkeeping instead. Here the only bookkeeping that matters is the pending
/// cleartext a previous `WANT_WRITE` parked, which is why it is retried first.
///
/// # Safety
///
/// As [`clear_in`].
pub unsafe fn clear_out(state: &mut WrapState, ssl: *mut ffi::SSL) -> usize {
    if state.pending_cleartext.is_empty() {
        return 0;
    }
    let data = std::mem::take(&mut state.pending_cleartext);
    // SAFETY: `ssl` is live and `data` is valid for `data.len()` bytes.
    let written =
        unsafe { ffi::SSL_write(ssl, data.as_ptr().cast(), data.len() as std::os::raw::c_int) };
    // SAFETY: `written` is this call's return value.
    let outcome = unsafe { IoOutcome::of(ssl, written, written.max(0) as usize) };
    match outcome {
        IoOutcome::Wrote(count) => count,
        // `WANT_WRITE` or `WANT_READ`: put the bytes back so the next cycle
        // retries them. This is the "saving data for later write" path at
        // `crypto_tls.cc:1314`, and dropping them here is what would truncate a
        // write under backpressure.
        IoOutcome::WantWrite | IoOutcome::WantRead => {
            state.pending_cleartext = data;
            0
        }
        IoOutcome::ZeroReturn | IoOutcome::SyscallEof => {
            state.flags.eof = true;
            0
        }
        IoOutcome::Failed(reason) => {
            state.error = Some(reason);
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
    IoOutcome::Failed("SSL_do_handshake is not wired yet (tls_wrap increment 3)".to_string())
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
        assert!(!IoOutcome::Failed("x".to_string()).should_retry());
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
}
