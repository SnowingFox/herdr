//! The four OpenSSL functions this crate needs that `openssl-sys 0.9.118` does
//! not declare.
//!
//! Each one is a real exported symbol in the vendored OpenSSL 3.6.3 — checked
//! with `nm -g --defined-only libssl.a libcrypto.a`, not assumed — and each is a
//! macro or an inline in the C headers, so there is no function to link against
//! without writing the declaration here:
//!
//! | function | why `openssl-sys` lacks it |
//! | --- | --- |
//! | `SSL_CTX_set_timeout` | declared in `ssl.h` but not in the crate's bindings |
//! | `SSL_CTX_clear_mode` | a macro over `SSL_CTX_ctrl(SSL_CTRL_CLEAR_MODE)`, so no symbol |
//! | `X509_STORE_add_crl` | declared in `x509_vfy.h`, not in the crate's bindings |
//! | `PEM_read_bio_Parameters` | declared in `pem.h`, not in the crate's bindings |
//!
//! Every declaration below is checked against the vendored header, quoted in the
//! comment above it. Adding a declaration that does not exist in the linked
//! library would fail at link time rather than silently, which is the property
//! that makes this acceptable: the failure mode is a build error, not a wrong
//! answer at runtime.

use std::os::raw::{c_char, c_int, c_long, c_void};

use openssl_sys as ffi;

/// `#define SSL_CTRL_SET_SIGALGS_LIST 98` in `ssl.h`.
pub const SSL_CTRL_SET_SIGALGS_LIST: c_int = 98;

/// `#define SSL_CTRL_SET_GROUPS_LIST 92` in `ssl.h`.
///
/// `SSL_CTRL_SET_CURVES_LIST` is an alias for it in OpenSSL 3.
pub const SSL_CTRL_SET_GROUPS_LIST: c_int = 92;

/// `#define SSL_CTRL_CLEAR_MODE 78` in `ssl.h`.
pub const SSL_CTRL_CLEAR_MODE: c_int = 78;

/// `#define SSL_CTRL_OPTIONS 32` in `ssl.h`.
///
/// `openssl-sys` only declares it under `libressl`, because on OpenSSL
/// `SSL_CTX_set_options` is a real function that the crate does declare. It is
/// kept here for the read-back in the tests, where the control is the only way
/// to read the bits back without a second declaration.
pub const SSL_CTRL_OPTIONS: c_int = 32;

extern "C" {
    /// `__owur long SSL_CTX_set_timeout(SSL_CTX *ctx, long t);`
    pub fn SSL_CTX_set_timeout(ctx: *mut ffi::SSL_CTX, t: c_long) -> c_long;

    /// `int X509_STORE_add_crl(X509_STORE *xs, X509_CRL *x);`
    pub fn X509_STORE_add_crl(xs: *mut ffi::X509_STORE, x: *mut ffi::X509_CRL) -> c_int;

    /// `EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);`
    pub fn PEM_read_bio_Parameters(bp: *mut ffi::BIO, x: *mut *mut ffi::EVP_PKEY) -> *mut ffi::EVP_PKEY;

    /// `int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);`
    ///
    /// Returns 1 with `*issuer` set to a new reference, 0 with nothing set, or
    /// -1 when no issuer was found. The caller frees `*issuer` with `X509_free`.
    pub fn X509_STORE_CTX_get1_issuer(
        issuer: *mut *mut ffi::X509,
        ctx: *mut ffi::X509_STORE_CTX,
        x: *mut ffi::X509,
    ) -> c_int;

    /// `X509_VERIFY_PARAM *X509_STORE_get0_param(X509_STORE *ctx);`
    ///
    /// The store's verification parameters, which is where `X509_STORE_set_flags`
    /// records what it was given.
    pub fn X509_STORE_get0_param(ctx: *mut ffi::X509_STORE) -> *mut ffi::X509_VERIFY_PARAM;
}

/// `SSL_CTX_clear_mode`, written as the macro it is.
///
/// # Safety
///
/// `ctx` must be a live `SSL_CTX`.
pub unsafe fn ssl_ctx_clear_mode(ctx: *mut ffi::SSL_CTX, op: c_long) -> c_long {
    unsafe { ffi::SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_MODE, op, std::ptr::null_mut()) }
}

/// `SSL_CTX_set1_sigalgs_list`, written as the macro it is.
///
/// # Safety
///
/// `ctx` must be a live `SSL_CTX` and `list` a NUL-terminated string that
/// outlives the call.
pub unsafe fn ssl_ctx_set1_sigalgs_list(ctx: *mut ffi::SSL_CTX, list: *const c_char) -> c_long {
    unsafe { ffi::SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, list as *mut c_void) }
}

/// `SSL_CTX_set1_curves_list`, written as the macro it is.
///
/// # Safety
///
/// As [`SSL_CTX_set1_sigalgs_list`].
pub unsafe fn ssl_ctx_set1_curves_list(ctx: *mut ffi::SSL_CTX, list: *const c_char) -> c_long {
    unsafe { ffi::SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, list as *mut c_void) }
}
