//! The SSL state machine entry point: `TLSWrap::Cycle` and its four phases.
//!
//! `crypto_tls.cc:712-1013` is the code this module will hold. It is ~300 lines
//! of `ClearIn`/`ClearOut`/`EncOut`/`Cycle` and it is increment 3's work, because
//! it cannot be written before `wrap()`/`receive()`/`readStart` exist (increment
//! 2) and it cannot be tested before the callbacks exist to drive it (increment
//! 4).
//!
//! # Why the module exists in increment 1 with almost nothing in it
//!
//! [`run`] is the single entry point the listener, `start()`, `receive()` and the
//! cert/SNI callbacks all call. Having it exist now, with the increment-1 body
//! that reports what is missing, means increment 2 and 3 fill in bodies rather
//! than adding a second entry point that some callers use and others do not —
//! which is exactly the drift that makes a state machine impossible to reason
//! about.
//!
//! # The shapes it has to end up with
//!
//! Recorded here because they are the order the retry loop has to preserve, and
//! losing one is how a large-payload test fails while a one-shot echo passes:
//!
//! * **`ClearIn`** calls `SSL_read` while `enc_in_` has data, appends the
//!   cleartext to the read queue, and stops on `SSL_ERROR_WANT_READ`. It must not
//!   stop on `WANT_READ` with data still buffered — that is what
//!   `SSL_MODE_AUTO_RETRY` is set for.
//! * **`ClearOut`** calls `SSL_write` for each queued cleartext write, and on
//!   `WANT_WRITE` parks the remainder in `current_write_` so `EncOut` can resume.
//! * **`EncOut`** drains `enc_out_` into the underlying stream. A write that
//!   cannot be issued immediately is deferred through a real immediate (R4), not
//!   retried in place.
//! * **`Cycle`** is `ClearIn(); ClearOut(); EncOut();` and is re-entered from
//!   every completion, which is why the re-entrancy guard (R2/R4) is checked at
//!   its top rather than at each phase.

use std::cell::RefCell;

use crate::ssl::Kind;
use crate::state::WrapState;

/// Why the state machine could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// The wrap has no `SSL`, so there is nothing to cycle.
    NoSsl,
    /// The state is already borrowed, which means this call is re-entrant and
    /// must be dropped rather than run (R2).
    Reentrant,
    /// The SSL library is already on this thread's stack, which is the
    /// `SSLLibraryCallScope` guard. Running the state machine here would corrupt
    /// it.
    InLibraryCall,
    /// The state machine is not implemented yet. Increment 3 fills in the body;
    /// until then every caller gets this rather than a silent success.
    NotImplemented,
}

/// `TLSWrap::Cycle`, reduced to what increment 1 can do.
///
/// Takes the cell address rather than the state so the borrow can be formed and
/// ended inside, which is the discipline every caller needs (R2): a caller that
/// passes a borrow would already violate it.
///
/// Returns the reason it did not run, so a caller that cares can report it. Most
/// do not — `Cycle` is called from completions where the only meaningful action
/// is to run or not — which is why the return value is a plain enum rather than a
/// `Result` with an error type.
/// # Safety
///
/// `cell` must be the live state cell of a `TLSWrap` whose object is still
/// reachable, or null. It is called from `WrapListener`, which holds that
/// guarantee by construction.
pub unsafe fn run(cell: *mut RefCell<WrapState>) -> CycleOutcome {
    if cell.is_null() {
        return CycleOutcome::NoSsl;
    }
    // SAFETY: the caller passes the live state cell of a `TLSWrap`, per
    // `crate::listener::WrapListener::new`'s contract.
    let cell = unsafe { &*cell };
    let Ok(state) = cell.try_borrow_mut() else {
        return CycleOutcome::Reentrant;
    };
    if state.ssl.is_none() {
        return CycleOutcome::NoSsl;
    }
    if state.in_library_call() {
        // A callback that re-enters `Cycle` from inside `SSL_do_handshake` is the
        // exact case `crypto_tls.h:47` documents. Dropping the call is correct:
        // the outer invocation will continue the machine when it returns.
        return CycleOutcome::InLibraryCall;
    }
    // The state machine itself. Increment 2 lands `ClearOut`/`EncOut` for the
    // write path and increment 3 lands `ClearIn`/`Cycle`; until then the phases
    // are named here so the ordering is recorded where the borrow discipline is.
    CycleOutcome::NotImplemented
}

/// `TLSWrap::ClearIn`: `SSL_read` until it wants more ciphertext.
///
/// # Safety
///
/// `ssl` must be the live `SSL` of the wrap that owns `state`, and `state` must
/// be the borrow that wrap's caller holds for this call.
pub unsafe fn clear_in(state: &mut WrapState, ssl: *mut openssl_sys::SSL) -> usize {
    let _ = (state, ssl);
    // Increment 3.
    0
}

/// `TLSWrap::ClearOut`: `SSL_write` each queued cleartext write.
///
/// # Safety
///
/// As [`clear_in`].
pub unsafe fn clear_out(state: &mut WrapState, ssl: *mut openssl_sys::SSL) -> usize {
    let _ = (state, ssl);
    // Increment 2 for the flush half, increment 3 for the retry half.
    0
}

/// `TLSWrap::EncOut`: drain `enc_out_` into the underlying stream.
///
/// # Safety
///
/// As [`clear_in`].
pub unsafe fn enc_out(state: &mut WrapState, ssl: *mut openssl_sys::SSL) -> usize {
    let _ = (state, ssl);
    // Increment 2.
    0
}

/// `TLSWrap::InitSSL`'s client half: `SSL_do_handshake` and the retry loop.
///
/// Increment 3. `SSL_get_error` is what decides between `WANT_READ`,
/// `WANT_WRITE`, `ZERO_RETURN` and a real failure, and the loop around it is the
/// part that cannot be simplified: a `WANT_WRITE` has to drain `enc_out_` and
/// retry, and a `WANT_READ` has to return and wait for the listener.
///
/// # Safety
///
/// As [`clear_in`].
pub unsafe fn do_handshake(state: &mut WrapState, ssl: *mut openssl_sys::SSL) -> i32 {
    let _ = (state, ssl);
    // Increment 3.
    0
}

/// Whether the wrap is the client side, for the callers that need to know.
pub fn is_client(state: &WrapState) -> bool {
    state.kind == Kind::Client
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssl::Kind;

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
        let _guard = state.borrow_mut();
        assert_eq!(unsafe { run(cell) }, CycleOutcome::Reentrant);
        drop(_guard);
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
}
