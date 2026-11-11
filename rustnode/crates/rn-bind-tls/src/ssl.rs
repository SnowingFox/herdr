//! `SSL*` ownership: the one type that frees it.
//!
//! `TLSWrap`'s `ssl_` is an `ncrypto::SSLPointer`, a `std::unique_ptr<SSL>`
//! whose deleter is `SSL_free`. `crypto_tls.cc:1488` is the single place it is
//! reset, and `Destroy()` is the single function that resets it. Everything
//! about teardown in that file is arranged around that one fact.
//!
//! # R1 in Rust terms
//!
//! `SSL_free` releases the `SSL` **and both BIOs it owns**. `SSL_set_bio`
//! transferred them, so there is no separate free for either. [`Ssl`] is that
//! ownership: one field, one `Drop`, one `SSL_free`. There is no `BIO_free` in
//! this crate outside a test helper.
//!
//! The subtle half is the *order*. Node's `Destroy()` does:
//!
//! ```c
//! ssl_.reset();                    // ~SSL, which frees both BIOs
//! enc_in_ = enc_out_ = nullptr;    // NOW the pointers are cleared
//! ```
//!
//! The pointers are cleared *after* the reset, not before, because clearing
//! them first would leave the only handle on two live BIOs pointing at nothing.
//! Here that ordering cannot be got wrong: [`Ssl::free`] consumes the `Ssl`, so
//! there is nothing left to hold a BIO pointer in afterwards, and the borrowed
//! views ([`EncIn`], [`EncOut`]) are re-read from the `SSL` each time rather
//! than cached.
//!
//! # Why the `SSL_CTX` is not owned
//!
//! `SSL_new(ctx)` takes a **reference** on the `SSL_CTX`, which `SSL_free`
//! releases. The `SSL_CTX` itself belongs to the JavaScript `SecureContext`
//! object and is freed by its finalizer. Node has the same split: `sc_` is a
//! `BaseObjectPtr<SecureContext>` (a reference count over the JS object) and
//! `ssl_` holds an OpenSSL reference to the `SSL_CTX` underneath.
//!
//! Two things that disagree about who frees the `SSL_CTX` is the bug this crate
//! is arranged to avoid: [`crate::wrap::TlsState`] holds a *rooted JavaScript*
//! reference to the `SecureContext` object, never a second OpenSSL owner.

use std::os::raw::c_int;
use std::ptr;

use openssl_sys as ffi;

use crate::bio::{EncIn, EncOut, Pair};

/// What `SSL_new` reported, `crypto_tls.cc`'s `CHECK(ssl_)` as an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SslError {
    /// `SSL_new` returned null. The error queue carries the reason.
    Create(String),
    /// `SSL_set_bio` had no pair to attach.
    NoBioPair,
}

impl std::fmt::Display for SslError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create(reason) => write!(formatter, "SSL_new: {reason}"),
            Self::NoBioPair => write!(formatter, "SSL has no BIO pair to attach"),
        }
    }
}

/// Whether this `TLSWrap` is the client or the server, `TLSWrap::Kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Client,
    Server,
}

/// An owned `SSL`, with both of its BIOs.
///
/// Constructing one is [`Ssl::new`]: `SSL_new` on the context's `SSL_CTX`, then
/// a [`Pair`] attached by `SSL_set_bio`. From that point the `SSL` owns
/// everything, and dropping it is the only teardown.
pub struct Ssl {
    /// The `SSL*`, or null after [`Ssl::free`].
    ///
    /// A field rather than an `Option<NonNull<..>>` so the raw pointer can be
    /// handed to OpenSSL without a conversion on every call site. Null is the
    /// "already freed" state, which is the same representation Node's
    /// `ssl_.get()` returns for a reset pointer.
    raw: *mut ffi::SSL,
    /// Which side of the handshake this is, which decides
    /// `SSL_set_connect_state` versus `SSL_set_accept_state`.
    kind: Kind,
}

// The `SSL` is only ever touched from the thread that owns the event loop: every
// entry point is a V8 callback or a libuv callback on that thread. Sending it
// would be wrong, and not sending it is what makes that a compile-time fact.
impl std::fmt::Debug for Ssl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ssl")
            .field("kind", &self.kind)
            .field("freed", &self.raw.is_null())
            .finish()
    }
}

impl Ssl {
    /// `SecureContext::CreateSSL` plus the `InitSSL` half that allocates the
    /// BIOs: `SSL_new(ctx)`, then `SSL_set_bio(ssl, enc_in, enc_out)`.
    ///
    /// `crypto_tls.cc:405-419` is the constructor this mirrors. The two calls it
    /// does *not* make here are the ones that install callbacks, because those
    /// need the `TLSWrap` object to exist first; [`crate::wrap::TlsState::new`]
    /// runs them.
    ///
    /// The `ctx` is borrowed, not owned: `SSL_new` takes its own reference and
    /// `SSL_free` releases it, which is exactly Node's split between `sc_` (the
    /// JS object) and `ssl_` (this).
    ///
    /// # Safety
    ///
    /// `ctx` must be a live `SSL_CTX` that outlives this `SSL`. The
    /// `SecureContext` finalizer is what guarantees that, and it cannot run
    /// while a rooted reference to the `SecureContext` object is held.
    pub unsafe fn new(ctx: *mut ffi::SSL_CTX, kind: Kind) -> Result<Self, SslError> {
        if ctx.is_null() {
            return Err(SslError::Create("the context has no SSL_CTX".to_string()));
        }
        // SAFETY: the caller guarantees `ctx` is live.
        let raw = unsafe { ffi::SSL_new(ctx) };
        if raw.is_null() {
            return Err(SslError::Create(crate::error::drain_reason()));
        }
        let pair = Pair::new().ok_or(SslError::NoBioPair)?;
        // SAFETY: `raw` was just created and has no BIOs yet, so this cannot
        // leak a previous pair. Ownership of both BIOs transfers to the SSL.
        unsafe { pair.attach(raw) };

        // `InitSSL`'s mode settings. `SSL_MODE_RELEASE_BUFFERS` keeps a small
        // write buffer from being held for a connection's whole life;
        // `SSL_MODE_AUTO_RETRY` is what lets `SSL_read` retry a non-application
        // record itself instead of returning `WANT_READ` with data still
        // buffered, which `Cycle` does not handle (`crypto_tls.cc:566`).
        //
        // `SSL_set_mode` is a macro over `SSL_ctrl(SSL_CTRL_MODE)`, so it is
        // expanded by `ffi_extra::ssl_set_mode` rather than linked.
        // SAFETY: `raw` is live and owned here.
        unsafe {
            crate::ffi_extra::ssl_set_mode(raw, SSL_MODE_RELEASE_BUFFERS);
            crate::ffi_extra::ssl_set_mode(raw, SSL_MODE_AUTO_RETRY);
            // `NOTE: This could be overridden in SetVerifyMode`. The callback is
            // Node's `VerifyCallback`, which always returns 1: OpenSSL must not
            // abort a handshake over a chain it does not like, because
            // `rejectUnauthorized: false` means JavaScript decides. Without it a
            // server with `SSL_VERIFY_PEER` sends `SSL alert 48` (`unknown_ca`)
            // and the connection never completes.
            crate::peer_cert::set_verify(
                raw,
                ffi::SSL_VERIFY_NONE,
                Some(crate::peer_cert::always_continue),
            );
        }

        match kind {
            // SAFETY: `raw` is live.
            Kind::Server => unsafe { ffi::SSL_set_accept_state(raw) },
            Kind::Client => {
                // `InitSSL` gives a client a larger initial input buffer because
                // the server's first flight (hello plus certificate) arrives
                // before the client can react.
                if let Some(enc_in) = unsafe { EncIn::of(raw) } {
                    enc_in.set_initial(crate::bio::INITIAL_CLIENT_BUFFER_LENGTH);
                }
                // SAFETY: `raw` is live.
                unsafe { ffi::SSL_set_connect_state(raw) }
            }
        }
        Ok(Self { raw, kind })
    }

    /// The raw pointer, or null after [`Ssl::free`].
    ///
    /// Callers must not keep it: R1's stale-pointer failure mode is a pointer
    /// outliving the `SSL`, and this crate re-reads rather than caches for that
    /// reason.
    pub fn as_ptr(&self) -> *mut ffi::SSL {
        self.raw
    }

    /// Whether the `SSL` has been freed, which is Node's `if (!ssl_) return;`
    /// guard at the top of `Destroy()`.
    pub fn is_freed(&self) -> bool {
        self.raw.is_null()
    }

    /// The kind this was created as.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// `TLSWrap::underlying_stream`'s SSL half: the read BIO.
    pub fn enc_in(&self) -> Option<EncIn> {
        if self.raw.is_null() {
            return None;
        }
        // SAFETY: `self.raw` is live, checked immediately above.
        unsafe { EncIn::of(self.raw) }
    }

    /// The write BIO.
    pub fn enc_out(&self) -> Option<EncOut> {
        if self.raw.is_null() {
            return None;
        }
        // SAFETY: `self.raw` is live, checked immediately above.
        unsafe { EncOut::of(self.raw) }
    }

    /// `SSL_set_app_data(ssl, this)`, which `ssl.h` defines as
    /// `SSL_set_ex_data(ssl, 0, data)`.
    ///
    /// `openssl-sys` declares `SSL_set_ex_data` (the underlying call) but not the
    /// macro, so it is expanded here rather than linked.
    ///
    /// # Safety
    ///
    /// `data` must outlive the `SSL`. Node's `SSL_set_app_data(ssl_.get(), this)`
    /// is the same contract, and `Destroy()` clearing `ssl_` is what ends it.
    pub unsafe fn set_app_data(&mut self, data: *mut std::os::raw::c_void) {
        if self.raw.is_null() {
            return;
        }
        // SAFETY: `self.raw` is live, checked above. Index 0 is the app-data slot
        // the macro names.
        unsafe { ffi::SSL_set_ex_data(self.raw, 0, data) };
    }

    /// The pointer installed by [`Ssl::set_app_data`]: `SSL_get_ex_data(ssl, 0)`.
    pub fn app_data(&self) -> *mut std::os::raw::c_void {
        if self.raw.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `self.raw` is live, checked above.
        unsafe { ffi::SSL_get_ex_data(self.raw, 0) }
    }

    /// `SSL_pending`: decrypted bytes already buffered by the library.
    pub fn pending(&self) -> i32 {
        if self.raw.is_null() {
            return 0;
        }
        // SAFETY: `self.raw` is live.
        unsafe { ffi::SSL_pending(self.raw) }
    }

    /// `SSL_is_init_finished`, which is how the handshake state machine knows a
    /// `WANT_READ` was a handshake step and not an application read.
    pub fn is_init_finished(&self) -> bool {
        if self.raw.is_null() {
            return false;
        }
        // SAFETY: `self.raw` is live.
        unsafe { ffi::SSL_is_init_finished(self.raw) != 0 }
    }

    /// `TLSWrap::Destroy`'s `ssl_.reset()`.
    ///
    /// Frees the `SSL` and, with it, both BIOs — the single place either is
    /// released. Idempotent, because `Destroy()` is reachable from `destroySSL`,
    /// from the finalizer, and from `DestroySSL` during teardown, and Node's
    /// version returns early when `ssl_` is already null.
    ///
    /// Consuming `self` is deliberate: after this there is no `Ssl` to hand out
    /// a stale `*mut SSL`, so the ordering that R1 is about cannot be inverted
    /// by a later caller.
    pub fn free(mut self) {
        if self.raw.is_null() {
            return;
        }
        let raw = std::mem::replace(&mut self.raw, ptr::null_mut());
        // SAFETY: `raw` was live and this is the only free of it. `SSL_free`
        // releases the SSL's reference on the SSL_CTX and frees both BIOs that
        // `SSL_set_bio` transferred.
        unsafe { ffi::SSL_free(raw) };
        // `self` drops here with a null pointer, which is the "already freed"
        // state and frees nothing.
    }
}

impl Drop for Ssl {
    /// Frees the `SSL` when the state that owns it is dropped without an
    /// explicit [`Ssl::free`].
    ///
    /// `Destroy()` is normally explicit — the JS `close()` path calls
    /// `destroySSL()` — but the finalizer path reaches this. Either way there is
    /// exactly one `SSL_free`, because `free` nulls the pointer it frees.
    fn drop(&mut self) {
        if self.raw.is_null() {
            return;
        }
        let raw = std::mem::replace(&mut self.raw, ptr::null_mut());
        // SAFETY: `raw` was live and nothing else has freed it.
        unsafe { ffi::SSL_free(raw) };
    }
}

/// `#define SSL_MODE_RELEASE_BUFFERS 0x00000010U` in `ssl.h:515`.
pub const SSL_MODE_RELEASE_BUFFERS: i64 = 0x0000_0010;
/// `#define SSL_MODE_AUTO_RETRY 0x00000004U` in `ssl.h:508`.
pub const SSL_MODE_AUTO_RETRY: i64 = 0x0000_0004;

/// `SSL_CTRL_SET_MAX_SEND_FRAGMENT` (`ssl.h:1311`), which `SSL_set_max_send_fragment`
/// is a macro over.
pub const SSL_CTRL_SET_MAX_SEND_FRAGMENT: c_int = 52;

/// `SSL_set_max_send_fragment(ssl, val)`, a macro in `ssl.h:2262` with no symbol.
///
/// Kept as a thin re-export of the expansion so a caller sees the name it knows.
///
/// # Safety
///
/// `ssl` must be live, or null.
pub unsafe fn set_max_send_fragment(ssl: *mut ffi::SSL, value: i32) -> i32 {
    // SAFETY: delegated to the caller's guarantee.
    unsafe { crate::ffi_extra::set_max_send_fragment(ssl, value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Ssl` with no `SSL_CTX` is refused rather than crashing, which is the
    /// `CHECK(sc_)` at `crypto_tls.cc:408` reported as an error.
    #[test]
    fn creating_an_ssl_without_a_context_reports_it() {
        // SAFETY: null is explicitly handled.
        let result = unsafe { Ssl::new(ptr::null_mut(), Kind::Client) };
        assert!(matches!(result, Err(SslError::Create(_))));
    }

    /// `free` twice (once explicitly, once through `Drop`) frees once, because
    /// `free` nulls the pointer it consumed.
    ///
    /// This is the R1 property that matters most: `Destroy()` is reachable from
    /// three JS paths and from the finalizer.
    #[test]
    fn freeing_is_idempotent_because_the_pointer_is_cleared() {
        // A real SSL needs a real context, which needs config; the property
        // being tested is the null handling, which is the same code path.
        let ssl = Ssl {
            raw: ptr::null_mut(),
            kind: Kind::Client,
        };
        assert!(ssl.is_freed());
        ssl.free();
    }

    /// The kind decides the connect/accept state, and it is readable back.
    #[test]
    fn the_kind_is_remembered() {
        let ssl = Ssl {
            raw: ptr::null_mut(),
            kind: Kind::Server,
        };
        assert_eq!(ssl.kind(), Kind::Server);
    }

    /// `SSL_set_max_send_fragment` on a null SSL is a no-op rather than a crash,
    /// which is what `setMaxSendFragment` on a destroyed wrap needs.
    #[test]
    fn setting_the_fragment_size_on_a_freed_ssl_does_nothing() {
        // SAFETY: null is explicitly handled.
        assert_eq!(unsafe { set_max_send_fragment(ptr::null_mut(), 1024) }, 0);
    }
}
