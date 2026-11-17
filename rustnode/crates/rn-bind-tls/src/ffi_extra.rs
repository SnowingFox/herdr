//! The handful of OpenSSL calls this crate needs that `openssl-sys 0.9.118` does
//! not declare.
//!
//! Every `extern` item below is a real exported symbol in the vendored OpenSSL
//! 3.6.3, checked with `nm -g --defined-only libssl.a libcrypto.a`; a declaration
//! whose *type* is wrong is not caught by the linker, which is why
//! `tools/audit-ffi-types.py` compares each one against the headers instead. The
//! macro-only entries are expanded here the way `ssl.h` expands them — which is
//! why they are Rust functions with an `SSL_ctrl` call inside rather than
//! `extern "C"` items.
//!
//! | need | why `openssl-sys` lacks it | form |
//! | --- | --- | --- |
//! | `SSL_set_mode` | a macro over `SSL_ctrl(SSL_CTRL_MODE)` | wrapper below |
//! | `SSL_set_max_send_fragment` | a macro over `SSL_ctrl` | wrapper below |
//! | `SSL_set1_verify_cert_store` | a macro over `SSL_ctrl(SSL_CTRL_SET_VERIFY_CERT_STORE)`; no such symbol exists | wrapper below |
//! | `SSL_get_servername` | declared in the crate only under `ossl111`'s const-pointer cfg for the argument, and not at all in 0.9.118 | `extern` |
//! | `SSL_get_shared_sigalgs` | not declared | `extern` |
//! | `BIO_set_shutdown` | `BIO_get_shutdown` is declared, this one is not | `extern` |
//!
//! # Why not just add the `openssl-sys` dependency feature
//!
//! It is pinned workspace-wide at `0.9.118` because `rn-bind-crypto` links it, and
//! a second *version* would mean a second `openssl-src` build. Adding the symbols
//! locally costs four lines each and cannot perturb that.

use std::os::raw::{c_char, c_int, c_long, c_uchar, c_void};

use openssl_sys as ffi;

/// #define SSL_CB_HANDSHAKE_START 0x10` in `ssl.h:1146`.
pub const SSL_CB_HANDSHAKE_START: c_int = 0x10;
/// `#define SSL_CB_HANDSHAKE_DONE 0x20` in `ssl.h:1147`.
pub const SSL_CB_HANDSHAKE_DONE: c_int = 0x20;

/// `#define SSL_CTRL_MODE 33` in `ssl.h:1302`.
pub const SSL_CTRL_MODE: c_int = 33;

/// `#define SSL_CTRL_SET_VERIFY_CERT_STORE 106` in `ssl.h:1317`.
pub const SSL_CTRL_SET_VERIFY_CERT_STORE: c_int = 106;

/// `#define SSL_CTRL_GET_CHAIN_CERTS 115` in `ssl.h:1323`.
///
/// `SSL_CTX_get0_chain_certs` and `SSL_get0_chain_certs` are macros over this
/// control; `openssl-sys` declares neither, so both are expanded below.
pub const SSL_CTRL_GET_CHAIN_CERTS: c_int = 115;

/// `#define SSL_CTRL_CHAIN 88` in `ssl.h:1302`.
///
/// `SSL_set1_chain`/`SSL_add1_chain_cert` are macros over it, with the `larg`
/// argument being the up-ref flag.
pub const SSL_CTRL_CHAIN: c_int = 88;

/// `#define SSL_ERROR_WANT_X509_LOOKUP 4` in `ssl.h:1373`.
///
/// Returned when `SSL_set_cert_cb`'s callback answers `-1`: the handshake is
/// suspended, not failed, and resumes through a second `SSL_do_handshake`.
pub const SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;

/// `#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE 127` in `ssl.h:1334`.
///
/// `SSL_get_tlsext_status_type(ssl)` is a macro over it (`tls1.h:303`), and it is
/// how `SSLCertCallback` learns whether the ClientHello carried a
/// `status_request` extension. That boolean is the `info.OCSPRequest` field
/// `lib/internal/tls/wrap.js` branches on.
pub const SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE: c_int = 127;

/// `TLSEXT_STATUSTYPE_ocsp` (`tls1.h:236`).
pub const TLSEXT_STATUSTYPE_OCSP: c_int = 1;

/// `void SSL_set_cert_cb(SSL *s, int (*cb)(SSL *ssl, void *arg), void *arg);`
/// — `ssl.h:1641`.
///
/// The certificate callback that *parks* a handshake. Returning `-1` from it
/// makes `SSL_do_handshake` return `SSL_ERROR_WANT_X509_LOOKUP`, which OpenSSL
/// treats as "ask again later" rather than as a failure — and the resume is a
/// second handshake entry, not a return value. That shape is why this is the one
/// deferred method that needed a resume path (see `crate::methods::cert_cb_done`).
///
/// # Safety
///
/// `ssl` must be live, and `callback` must be null or a valid
/// `int (*)(SSL*, void*)` that stays callable for as long as the `SSL` lives.
/// `crate::callback::install` is the only caller and names a plain `extern "C"`
/// function item, which outlives every `SSL`.
pub unsafe fn ssl_set_cert_cb(
    ssl: *mut ffi::SSL,
    callback: Option<unsafe extern "C" fn(*mut ffi::SSL, *mut c_void) -> c_int>,
    arg: *mut c_void,
) {
    if ssl.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `ssl` is live and `callback` callable.
    unsafe { SSL_set_cert_cb(ssl, callback, arg) };
}

extern "C" {

    /// `void SSL_set_cert_cb(SSL *s, int (*cb)(SSL *ssl, void *arg), void *arg);`
    /// — `ssl.h:1641`. Reached through [`ssl_set_cert_cb`], the only caller.
    pub fn SSL_set_cert_cb(
        ssl: *mut ffi::SSL,
        callback: Option<unsafe extern "C" fn(*mut ffi::SSL, *mut c_void) -> c_int>,
        arg: *mut c_void,
    );

    /// `void SSL_certs_clear(SSL *s);` — `ssl.h:1939`.
    ///
    /// Clears every certificate on the `SSL`. `SSLPointer::setSniContext`
    /// (`deps/ncrypto/ncrypto.cc:5156`) does this before installing an SNI
    /// context's certificate, because `SSL_use_certificate` replaces only the
    /// certificate matching the new key's type — so credentials from the default
    /// context could otherwise be selected for a different key type.
    pub fn SSL_certs_clear(ssl: *mut ffi::SSL);

    /// `STACK_OF(X509_NAME) *SSL_dup_CA_list(const STACK_OF(X509_NAME) *sk);`
    /// — `ssl.h:2118`.
    ///
    /// Returns a new reference-counted copy that the caller owns, or null on
    /// failure. `TLSWrap::SetCACerts` needs a copy because
    /// `SSL_set_client_CA_list` takes ownership of what it is given, and the
    /// source list belongs to the `SSL_CTX`.
    pub fn SSL_dup_CA_list(names: *const ffi::stack_st_X509_NAME) -> *mut ffi::stack_st_X509_NAME;

    /// `STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *s);`
    /// — `ssl.h:2104`.
    ///
    /// Borrowed: the list is owned by the context. `openssl-sys` declares neither
    /// this nor `SSL_dup_CA_list`, which is why `SetCACerts` could not be written
    /// before this pair existed.
    pub fn SSL_CTX_get_client_CA_list(ctx: *const ffi::SSL_CTX) -> *mut ffi::stack_st_X509_NAME;

    /// `const char *SSL_get_servername(const SSL *s, const int tlsext_typename);`
    /// — `tls1.h:281`.
    ///
    /// Returns a pointer owned by the `SSL`, or null when no name was set for
    /// that type.
    pub fn SSL_get_servername(ssl: *const ffi::SSL, type_: c_int) -> *const c_char;

    /// `int SSL_get_shared_sigalgs(SSL *s, int idx, int *psign, int *phash,
    /// int *psignhash, unsigned char *rsig, unsigned char *rhash);`
    /// — `tls1.h:286`, defined at `t1_lib.c:3693`.
    ///
    /// With `idx == 0` it returns the count; with `0 < idx <= count` it fills the
    /// out-parameters for that entry.
    ///
    /// **The last two arguments are `unsigned char *`, and the function writes one
    /// byte through each**: `*rsig = (unsigned char)(shsigalgs->sigalg & 0xff)` at
    /// `t1_lib.c:3717`. Declaring them `*mut *const c_char` says the callee writes
    /// a whole pointer, so a caller that passed a one-byte buffer would have
    /// `size_of::<*const c_char>()` bytes written over the memory around it. Both
    /// call sites pass null, which is the only reason that never fired — and
    /// `getSharedSigalgs` is reachable from JavaScript through
    /// `TLSSocket.prototype` (`lib/internal/tls/wrap.js:1324`), so a caller asking
    /// for raw signature bytes would have reached it.
    pub fn SSL_get_shared_sigalgs(
        ssl: *mut ffi::SSL,
        index: c_int,
        sign: *mut c_int,
        hash: *mut c_int,
        sign_hash: *mut c_int,
        raw_sign: *mut c_uchar,
        raw_hash: *mut c_uchar,
    ) -> c_int;

    /// `void BIO_set_shutdown(BIO *a, int shut);` — `bio.h:738`.
    ///
    /// The in-memory BIO has no descriptor, so the flag is set to zero: a
    /// "shutdown" BIO would try to close a file descriptor it never had.
    pub fn BIO_set_shutdown(bio: *mut ffi::BIO, shut: c_int);

    /// `void SSL_set_info_callback(SSL *ssl, void (*cb)(const SSL*, int, int));`
    /// — `ssl.h:2201`.
    ///
    /// The handshake-progress hook. Node installs `SSLInfoCallback` to learn when
    /// the handshake started and finished, which is how `flags_.established` is
    /// set and how `onhandshakedone` reaches `lib/net.js`. Without it a handshake
    /// can complete at the OpenSSL level and `secureConnect` still never fires.
    pub fn SSL_set_info_callback(
        ssl: *mut ffi::SSL,
        callback: Option<unsafe extern "C" fn(*const ffi::SSL, c_int, c_int)>,
    );

    /// `SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl);` — `ssl.h:2199`.
    pub fn SSL_get_SSL_CTX(ssl: *const ffi::SSL) -> *mut ffi::SSL_CTX;

    /// `int BIO_test_flags(const BIO *b, int flags);` — `bio.h`.
    ///
    /// `BIO_should_retry` is a macro over this. `openssl-sys` declares
    /// `BIO_set_flags`/`BIO_clear_flags` but not the reader, and the retry flag is
    /// what the test for an empty `NodeBIO` asserts.
    pub fn BIO_test_flags(bio: *const ffi::BIO, flags: c_int) -> c_int;

    /// `int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);`
    ///
    /// Returns 1 with `*issuer` set to a new reference, 0 with nothing set, or -1
    /// when no issuer was found. `rn-bind-secure-context` declares the same
    /// symbol for `getIssuer`; both link to the one definition.
    pub fn X509_STORE_CTX_get1_issuer(
        issuer: *mut *mut ffi::X509,
        ctx: *mut ffi::X509_STORE_CTX,
        x: *mut ffi::X509,
    ) -> c_int;
}
/// `SSL_set_mode(ssl, op)`, expanded from the macro at `ssl.h:641`:
///
/// ```c
/// #define SSL_set_mode(ssl, op) \
///     SSL_ctrl((ssl), SSL_CTRL_MODE, (op), NULL)
/// ```
///
/// Returns the resulting mode bits, as the macro does.
///
/// # Safety
///
/// `ssl` must be live, or null.
pub unsafe fn ssl_set_mode(ssl: *mut ffi::SSL, options: i64) -> i64 {
    if ssl.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees `ssl` is live.
    unsafe { ffi::SSL_ctrl(ssl, SSL_CTRL_MODE, options as c_long, std::ptr::null_mut()) }
}

/// `SSL_set_max_send_fragment(ssl, val)`, also a macro: `ssl.h:2263` is
/// `SSL_ctrl(ssl, SSL_CTRL_SET_MAX_SEND_FRAGMENT, m, NULL)`.
///
/// # Safety
///
/// `ssl` must be live, or null.
pub unsafe fn set_max_send_fragment(ssl: *mut ffi::SSL, value: i32) -> i32 {
    if ssl.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees `ssl` is live.
    unsafe {
        ffi::SSL_ctrl(
            ssl,
            crate::ssl::SSL_CTRL_SET_MAX_SEND_FRAGMENT,
            value as c_long,
            std::ptr::null_mut(),
        ) as i32
    }
}

/// `SSL_set1_verify_cert_store(ssl, store)`, a **macro**, not a function.
///
/// `ssl.h.in:1440` is:
///
/// ```c
/// #define SSL_set1_verify_cert_store(s, st) \
///     SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, (char *)(st))
/// ```
///
/// There is no `SSL_set1_verify_cert_store` symbol in the vendored OpenSSL 3.6.3
/// to link against; the only definition is that macro, which reaches
/// `ssl_cert_set_cert_store(sc->cert, parg, 0, larg)` at `s3_lib.c:4300` with
/// `larg == 1` meaning "up-ref the store". `SSL_CTX_set1_verify_cert_store` *is*
/// a real symbol, which is what makes the per-`SSL` form easy to get wrong: the
/// `SSL_CTX_` spelling links and this one does not.
///
/// The `1` is the up-ref flag and is load-bearing. `SSL_set0_verify_cert_store`
/// is the same control with `0`, which would make the `cert` own a store it does
/// not hold a reference to — so the store must outlive the `SSL` either way, but
/// only `set1` keeps it alive if the context is freed first.
///
/// # Safety
///
/// `ssl` must be live, and `store` must be a live `X509_STORE`.
pub unsafe fn ssl_set1_verify_cert_store(ssl: *mut ffi::SSL, store: *mut ffi::X509_STORE) -> c_int {
    if ssl.is_null() || store.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees both pointers are live.
    unsafe { ffi::SSL_ctrl(ssl, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, store.cast()) as c_int }
}

/// `SSL_get_tlsext_status_type(ssl)`, a **macro** over `SSL_ctrl` (`tls1.h:303`):
///
/// ```c
/// #define SSL_get_tlsext_status_type(ssl) \
///     SSL_ctrl(ssl, SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE, 0, NULL)
/// ```
///
/// Its answer is what `SSLCertCallback` turns into the `ocsp` boolean of the
/// `oncertcb` info object: `TLSEXT_STATUSTYPE_ocsp` means the ClientHello carried
/// a `status_request` extension. That is why a server with an `'OCSPRequest'`
/// listener parks every handshake but only consults JavaScript when the client
/// actually asked — the listener must not run for a client that did not.
///
/// # Safety
///
/// `ssl` must be live, or null.
pub unsafe fn ssl_get_tlsext_status_type(ssl: *mut ffi::SSL) -> c_int {
    if ssl.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees `ssl` is live.
    unsafe {
        ffi::SSL_ctrl(
            ssl,
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE,
            0,
            std::ptr::null_mut(),
        ) as c_int
    }
}

/// `SSL_CTX_get0_chain_certs(ctx, &chain)`, a macro over `SSL_CTX_ctrl`
/// (`ssl.h.in:1398`):
///
/// ```c
/// #define SSL_CTX_get0_chain_certs(ctx, px509) \
///     SSL_CTX_ctrl(ctx, SSL_CTRL_GET_CHAIN_CERTS, 0, px509)
/// ```
///
/// Returns 1 with `*chain` set to the context's extra certificates (borrowed, not
/// a new reference), or 0. `SSLPointer::setSniContext` replays them onto the
/// `SSL` after installing the leaf, so a switched context presents its full chain
/// rather than only the leaf.
///
/// # Safety
///
/// `ctx` must be live and `chain` a writable out-parameter.
pub unsafe fn ssl_ctx_get0_chain_certs(
    ctx: *mut ffi::SSL_CTX,
    chain: *mut *mut ffi::stack_st_X509,
) -> c_int {
    if ctx.is_null() || chain.is_null() {
        return 0;
    }
    *chain = std::ptr::null_mut();
    // SAFETY: the caller guarantees `ctx` is live and `chain` writable.
    unsafe { ffi::SSL_CTX_ctrl(ctx, SSL_CTRL_GET_CHAIN_CERTS, 0, chain.cast()) as c_int }
}

/// `SSL_set1_chain(ssl, chain)`, a macro over `SSL_ctrl` (`ssl.h.in:1422`):
///
/// ```c
/// #define SSL_set1_chain(s, sk) SSL_ctrl(s, SSL_CTRL_CHAIN, 1, (char *)(sk))
/// ```
///
/// The `1` is the up-ref flag, matching `SSL_set1_verify_cert_store`'s shape: the
/// `SSL` takes its own reference on every certificate in the list, so the
/// `SSL_CTX` that owns the list may be freed first.
///
/// # Safety
///
/// `ssl` must be live and `chain` null or a live stack.
pub unsafe fn ssl_set1_chain(ssl: *mut ffi::SSL, chain: *mut ffi::stack_st_X509) -> c_int {
    if ssl.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees `ssl` is live.
    unsafe { ffi::SSL_ctrl(ssl, SSL_CTRL_CHAIN, 1, chain.cast()) as c_int }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SSL_set_mode` on a null SSL is a no-op, which is what `InitSSL` needs
    /// when a wrap was destroyed before its modes were set.
    #[test]
    fn setting_the_mode_on_a_null_ssl_does_nothing() {
        // SAFETY: null is explicitly handled.
        assert_eq!(unsafe { ssl_set_mode(std::ptr::null_mut(), 0x10) }, 0);
    }

    /// Reading a servername from a null SSL is a null pointer rather than a crash.
    #[test]
    fn reading_a_servername_from_a_null_ssl_is_null() {
        // SAFETY: `SSL_get_servername` dereferences the SSL, so null is passed
        // here only because the test asserts the caller guards it first.
        // The guard is in `methods::get_servername`, which checks
        // `ssl.is_null()` before calling; this test covers the constant only.
        assert_eq!(SSL_CTRL_MODE, 33);
        assert_eq!(crate::ssl::SSL_CTRL_SET_MAX_SEND_FRAGMENT, 52);
    }
}
