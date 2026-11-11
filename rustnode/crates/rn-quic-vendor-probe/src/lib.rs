//! Feasibility probe for the QUIC C dependencies.
//!
//! This crate answers one question and then stops: can `ngtcp2`, `nghttp3` and
//! the ngtcp2 OpenSSL crypto glue — built from the pinned Node vendored trees
//! with `cc-rs` and linked against the vendored OpenSSL this workspace already
//! builds — be compiled and called from Rust here?
//!
//! It deliberately implements no QUIC. There is no `ngtcp2_conn` wrapper, no
//! transport-parameter binding, no socket integration and no V8 in this crate.
//! The FFI declarations below cover only what the shim in `shim/` calls, which
//! is enough to prove the three libraries compile, link and run.
//!
//! Every function here returns the shim's status code unchanged: `0` means the
//! call worked, anything else is a failure the shim encoded. The tests in
//! `tests/` assert on those codes, so a silently-linked-but-broken build fails
//! rather than passing on link success alone.

use std::ffi::CStr;

extern "C" {
    fn rn_quic_probe_ngtcp2_version() -> *const std::os::raw::c_char;
    fn rn_quic_probe_nghttp3_version() -> *const std::os::raw::c_char;
    fn rn_quic_probe_ngtcp2_roundtrip() -> std::os::raw::c_int;
    fn rn_quic_probe_nghttp3_roundtrip() -> std::os::raw::c_int;
    fn rn_quic_probe_ossl_quic_symbols() -> std::os::raw::c_int;
}

/// A version string from either library, copied out of the C static.
fn version_of(symbol: unsafe extern "C" fn() -> *const std::os::raw::c_char) -> String {
    // SAFETY: both version accessors return a pointer to a NUL-terminated
    // static string owned by the library, which outlives this call.
    let pointer = unsafe { symbol() };
    assert!(!pointer.is_null(), "version accessor returned null");
    // SAFETY: as above; the pointer is non-null and NUL-terminated.
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

/// The ngtcp2 version string compiled into this crate.
pub fn ngtcp2_version() -> String {
    version_of(rn_quic_probe_ngtcp2_version)
}

/// The nghttp3 version string compiled into this crate.
pub fn nghttp3_version() -> String {
    version_of(rn_quic_probe_nghttp3_version)
}

/// Runs the ngtcp2 transport-parameter encode/decode round trip.
///
/// Returns the shim's status: `0` on success.
pub fn ngtcp2_roundtrip() -> i32 {
    // SAFETY: the shim takes no arguments and only touches its own stack
    // buffers and ngtcp2's public API.
    unsafe { rn_quic_probe_ngtcp2_roundtrip() }
}

/// Creates and destroys an nghttp3 server connection.
///
/// Returns the shim's status: `0` on success.
pub fn nghttp3_roundtrip() -> i32 {
    // SAFETY: the shim takes no arguments and frees everything it allocates.
    unsafe { rn_quic_probe_nghttp3_roundtrip() }
}

/// Resolves the OpenSSL 3.5+ QUIC entry points the ngtcp2 ossl backend binds.
///
/// Returns the shim's status: `0` on success.
pub fn ossl_quic_symbols() -> i32 {
    // SAFETY: the shim only takes the address of two exported functions.
    unsafe { rn_quic_probe_ossl_quic_symbols() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_the_vendored_ones() {
        // Pinned in `deps/ngtcp2/*/lib/includes/*/version.h`. Asserting the
        // exact string is what proves the vendored tree was built and not a
        // system copy that the linker found first.
        assert_eq!(ngtcp2_version(), "1.25.0");
        assert_eq!(nghttp3_version(), "1.18.0");
    }

    #[test]
    fn ngtcp2_roundtrip_succeeds() {
        assert_eq!(ngtcp2_roundtrip(), 0, "ngtcp2 encode/decode round trip");
    }

    #[test]
    fn nghttp3_roundtrip_succeeds() {
        assert_eq!(nghttp3_roundtrip(), 0, "nghttp3 server conn create/destroy");
    }

    #[test]
    fn openssl_exposes_the_quic_tls_callbacks() {
        assert_eq!(ossl_quic_symbols(), 0, "OpenSSL 3.5+ QUIC entry points");
    }
}
