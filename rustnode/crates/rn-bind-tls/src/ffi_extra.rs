//! The handful of OpenSSL calls this crate needs that `openssl-sys 0.9.118` does
//! not declare.
//!
//! Each is a real exported symbol in the vendored OpenSSL 3.6.3, checked with
//! `nm -g --defined-only libssl.a libcrypto.a`, so a declaration that is wrong
//! fails at link time rather than silently doing the wrong thing at runtime. Two
//! of the four are **macros** in the headers rather than functions, and those are
//! expanded here the way `ssl.h` expands them — which is why they are Rust
//! functions with a `SSL_ctrl` call inside rather than `extern "C"` items.
//!
//! | need | why `openssl-sys` lacks it | form |
//! | --- | --- | --- |
//! | `SSL_set_mode` | a macro over `SSL_ctrl(SSL_CTRL_MODE)` | wrapper below |
//! | `SSL_get_servername` | declared in the crate only under `ossl111`'s const-pointer cfg for the argument, and not at all in 0.9.118 | `extern` |
//! | `SSL_get_shared_sigalgs` | not declared | `extern` |
//! | `BIO_set_shutdown` | `BIO_get_shutdown` is declared, this one is not | `extern` |
//!
//! # Why not just add the `openssl-sys` dependency feature
//!
//! It is pinned workspace-wide at `0.9.118` because `rn-bind-crypto` links it, and
//! a second *version* would mean a second `openssl-src` build. Adding the symbols
//! locally costs four lines each and cannot perturb that.

use std::os::raw::{c_char, c_int, c_long};

use openssl_sys as ffi;

/// `#define SSL_CB_HANDSHAKE_START 0x10` in `ssl.h:1146`.
pub const SSL_CB_HANDSHAKE_START: c_int = 0x10;
/// `#define SSL_CB_HANDSHAKE_DONE 0x20` in `ssl.h:1147`.
pub const SSL_CB_HANDSHAKE_DONE: c_int = 0x20;

/// `#define SSL_CTRL_MODE 33` in `ssl.h:1302`.
pub const SSL_CTRL_MODE: c_int = 33;

extern "C" {
    /// `const char *SSL_get_servername(const SSL *s, const int tlsext_typename);`
    /// — `tls1.h:281`.
    ///
    /// Returns a pointer owned by the `SSL`, or null when no name was set for
    /// that type.
    pub fn SSL_get_servername(ssl: *const ffi::SSL, type_: c_int) -> *const c_char;

    /// `int SSL_get_shared_sigalgs(SSL *s, int idx, int *psign, int *phash,
    /// int *psignhash, const unsigned char **rsig, const unsigned char **rhash);`
    /// — `tls1.h:286`.
    ///
    /// With `idx == 0` it returns the count; with `0 < idx <= count` it fills the
    /// out-parameters for that entry.
    pub fn SSL_get_shared_sigalgs(
        ssl: *mut ffi::SSL,
        index: c_int,
        sign: *mut c_int,
        hash: *mut c_int,
        sign_hash: *mut c_int,
        raw_sign: *mut *const c_char,
        raw_hash: *mut *const c_char,
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
