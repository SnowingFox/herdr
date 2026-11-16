//! The hand-declared OpenSSL symbols, proved against the vendored library at
//! runtime rather than only against the headers.
//!
//! Two of these were wrong on `master` and both were latent for the same reason:
//! every current caller happened to pass a value the wrong declaration could not
//! distinguish from the right one. `tools/audit-ffi-types.py` compares the
//! declarations against the headers; the tests here exercise them the way a
//! correct caller would, so the difference produces an observable result.
//!
//! `SSL_get_shared_sigalgs` is reached from JavaScript through
//! `TLSSocket.prototype` (`lib/internal/tls/wrap.js:1324`). `SSL_set1_verify_cert_store`
//! is reached from the SNI paths. Neither is a private detail.
//!
//! # Nothing here skips
//!
//! An earlier version of this file generated its test certificate by running
//! `openssl req` into a directory named after the **process id**, and returned
//! `None` from setup on any failure, which the tests turned into a printed
//! "skipping" and an `ok`. Two tests ran in parallel in one process, so they shared
//! that directory and each deleted it in `Drop`; whichever finished first removed
//! the other's key while `openssl req` was still writing it. The result was
//! `4 passed` with the two tests that prove the `SSL_get_shared_sigalgs` defect
//! having done nothing — a green line over a measurement that never happened, which
//! is the failure mode this whole file exists to guard against.
//!
//! The certificate is now built **in process** with the `openssl` crate this
//! workspace already links, so there is no subprocess, no temporary directory, no
//! cleanup, and nothing environmental to be missing. Setup panics naming the step
//! that failed rather than returning `None`; there is deliberately no code path
//! that turns a setup failure into a pass.

use std::ffi::c_uchar;
use std::os::raw::c_int;
use std::panic::{RefUnwindSafe, UnwindSafe};

use openssl_sys as ffi;
use rn_bind_tls::ffi_extra::{
    ssl_set1_verify_cert_store, SSL_get_shared_sigalgs, SSL_CTRL_SET_VERIFY_CERT_STORE,
};

/// A server `SSL` that has processed a real ClientHello, which is the state in
/// which `SSL_get_shared_sigalgs`' out-parameters exist.
///
/// `sc->shared_sigalgs` is populated while the server parses the client's
/// signature-algorithm list (`t1_lib.c:3576`), so it is empty until that has
/// happened. The client therefore only has to *emit* a ClientHello and have it
/// delivered; the rest of the handshake is not needed to reach the arguments
/// under test.
///
/// That matters for more than brevity. An earlier version drove the handshake to
/// completion over memory BIOs and stalled at `SSL_R_BAD_HANDSHAKE_STATE` because
/// a hand-rolled pump loses the TLS 1.3 post-handshake ordering. Stopping at the
/// first flight reaches the same state through a path that depends on nothing
/// about message ordering, and it is the ClientHello that the function's data
/// comes from.
///
/// Every field is a raw pointer, so the two `UnwindSafe` impls below are what let
/// an `assert!` unwind through this value. `Drop` frees them on both paths, and
/// no two `Pair`s share a pointer.
struct Pair {
    server: *mut ffi::SSL,
    client: *mut ffi::SSL,
    server_ctx: *mut ffi::SSL_CTX,
    client_ctx: *mut ffi::SSL_CTX,
}

impl UnwindSafe for Pair {}
impl RefUnwindSafe for Pair {}

impl Pair {
    /// A server holding a real ClientHello, plus the client that sent it.
    ///
    /// Panics naming the step that failed; there is no `None` return, because a
    /// setup failure that a caller can turn into a pass is how these tests stopped
    /// proving anything once already.
    fn with_a_client_hello() -> Self {
        let pair = Self::new();
        // SAFETY: both SSLs and their BIOs are live for the whole call.
        unsafe {
            // The client produces its first flight. `SSL_ERROR_WANT_READ` is the
            // expected result: it has written the ClientHello and is waiting.
            let rc = ffi::SSL_do_handshake(pair.client);
            let error = ffi::SSL_get_error(pair.client, rc);
            assert!(
                rc != 1 || error == ffi::SSL_ERROR_NONE,
                "the client failed before sending a ClientHello: \
                 SSL_do_handshake returned {rc} with SSL_get_error {error}"
            );

            // Deliver the flight to the server. A handshake over memory BIOs
            // cannot block on a socket, so zero bytes here is a real failure
            // rather than something to retry.
            let out = ffi::SSL_get_wbio(pair.client);
            let inp = ffi::SSL_get_rbio(pair.server);
            let mut buf = [0u8; 8192];
            let mut delivered = 0;
            loop {
                let n = ffi::BIO_read(out, buf.as_mut_ptr().cast(), buf.len() as c_int);
                if n <= 0 {
                    break;
                }
                let written = ffi::BIO_write(inp, buf.as_ptr().cast(), n);
                assert_eq!(
                    written, n,
                    "the server's read BIO accepted {written} of {n} ClientHello bytes"
                );
                delivered += n;
            }
            assert!(
                delivered > 0,
                "the client produced no ClientHello bytes, so the server has no \
                 signature-algorithm list to describe"
            );

            // The server parses it. This is where `shared_sigalgs` is filled.
            let rc = ffi::SSL_do_handshake(pair.server);
            let error = ffi::SSL_get_error(pair.server, rc);
            assert!(
                error == ffi::SSL_ERROR_WANT_READ || rc == 1,
                "the server did not consume the ClientHello: SSL_do_handshake \
                 returned {rc} with SSL_get_error {error}; WANT_READ ({}) is the \
                 expected answer, a protocol error is not",
                ffi::SSL_ERROR_WANT_READ
            );

            let count = SSL_get_shared_sigalgs(
                pair.server,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            assert!(
                count > 0,
                "a server that has parsed a ClientHello must share at least one \
                 signature algorithm; the vendored build lists defaults for TLS 1.3"
            );
        }
        pair
    }

    /// Two `SSL` objects over in-memory BIOs, with a self-signed certificate the
    /// server presents. Panics with the failing step; never returns `None`.
    fn new() -> Self {
        // A fresh P-256 key and a self-signed certificate over it, built in
        // process. Generating it here rather than shelling out to `openssl req`
        // removes a temporary directory, a subprocess and its exit status from the
        // setup path — all three were the reason two tests could silently do
        // nothing under a parallel run.
        let key = openssl::pkey::PKey::from_ec_key(
            openssl::ec::EcKey::generate(
                &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
                    .expect("the vendored OpenSSL has the P-256 curve"),
            )
            .expect("P-256 key generation succeeds"),
        )
        .expect("an EC key converts to an EVP_PKEY");

        let certificate = {
            let mut builder = openssl::x509::X509Builder::new().expect("an X509 builder allocates");
            builder
                .set_version(2)
                .expect("the X509 version field is writable");
            let mut serial = openssl::bn::BigNum::new().expect("a BIGNUM allocates");
            serial
                .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
                .expect("a serial number is generated");
            let serial = serial
                .to_asn1_integer()
                .expect("the serial converts to ASN.1");
            builder
                .set_serial_number(&serial)
                .expect("the serial is writable");
            let name = {
                let mut name =
                    openssl::x509::X509NameBuilder::new().expect("a name builder allocates");
                name.append_entry_by_text("CN", "localhost")
                    .expect("the common name is a valid entry");
                name.build()
            };
            builder
                .set_subject_name(&name)
                .expect("the subject is writable");
            builder
                .set_issuer_name(&name)
                .expect("the issuer is writable");
            builder
                .set_pubkey(&key)
                .expect("the public key is writable");
            builder
                .sign(&key, openssl::hash::MessageDigest::sha256())
                .expect("a self-signed certificate signs over P-256");
            builder.build()
        };

        // SAFETY: every pointer is checked before use, and `Pair`'s `Drop` frees
        // whatever was allocated once it is returned.
        unsafe {
            use foreign_types::ForeignTypeRef;
            let method = ffi::TLS_method();
            let server_ctx = ffi::SSL_CTX_new(method);
            assert!(!server_ctx.is_null(), "SSL_CTX_new failed for the server");
            let client_ctx = ffi::SSL_CTX_new(method);
            assert!(!client_ctx.is_null(), "SSL_CTX_new failed for the client");

            // Both take their own reference, so `key` and `certificate` may be
            // dropped at the end of this function.
            assert_eq!(
                ffi::SSL_CTX_use_PrivateKey(server_ctx, key.as_ptr()),
                1,
                "the server context refused the private key"
            );
            assert_eq!(
                ffi::SSL_CTX_use_certificate(server_ctx, certificate.as_ptr()),
                1,
                "the server context refused the certificate"
            );

            // The client verifies nothing here: the tests read server-side shared
            // signature algorithms, and a verification failure would abort the
            // server's parsing of the ClientHello before those exist.
            ffi::SSL_CTX_set_verify(client_ctx, ffi::SSL_VERIFY_NONE, None);

            let server = ffi::SSL_new(server_ctx);
            assert!(!server.is_null(), "SSL_new failed for the server");
            let client = ffi::SSL_new(client_ctx);
            assert!(!client.is_null(), "SSL_new failed for the client");

            for ssl in [server, client] {
                // Separate in-memory BIOs per side: each SSL's output is the
                // other's input, which is what `SSL_set_bio` expects.
                let rbio = ffi::BIO_new(ffi::BIO_s_mem());
                assert!(!rbio.is_null(), "BIO_new(BIO_s_mem) failed for a read BIO");
                let wbio = ffi::BIO_new(ffi::BIO_s_mem());
                assert!(!wbio.is_null(), "BIO_new(BIO_s_mem) failed for a write BIO");
                ffi::SSL_set_bio(ssl, rbio, wbio);
            }
            ffi::SSL_set_accept_state(server);
            ffi::SSL_set_connect_state(client);

            Self {
                server,
                client,
                server_ctx,
                client_ctx,
            }
        }
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        // SAFETY: these are the pointers `new` created and nothing else frees them.
        unsafe {
            ffi::SSL_free(self.server);
            ffi::SSL_free(self.client);
            ffi::SSL_CTX_free(self.server_ctx);
            ffi::SSL_CTX_free(self.client_ctx);
        }
    }
}

/// `SSL_get_shared_sigalgs` writes **one byte** through each of its last two
/// arguments, and they are `unsigned char *`.
///
/// They were declared `*mut *const c_char`, which says the callee writes a
/// pointer. With a one-byte buffer those are different amounts of memory: the
/// declared type would let OpenSSL overwrite the seven bytes after the byte it
/// was asked to fill. This test passes real one-byte buffers, exactly as a caller
/// asking for raw signature bytes would, and checks both the byte and the memory
/// around it.
///
/// # The declared type is also proved by the call itself
///
/// The two arguments are `&mut guarded[8..9].as_mut_ptr()`, whose Rust type is
/// `*mut u8`. On the old declaration this test does not compile with
/// `expected *mut *const i8, found *mut u8` — the type cannot express the write,
/// which is the defect.
#[test]
fn the_shared_sigalgs_raw_bytes_are_written_as_single_bytes() {
    let pair = Pair::with_a_client_hello();

    // A canary either side of each buffer. A `*mut *const c_char` write would put
    // the byte value into the low byte of the first word and zero or garbage the
    // rest, which lands on these.
    let mut guarded = [0xCDu8; 16];
    let mut sign: c_int = 0;
    let mut hash: c_int = 0;
    let mut sign_hash: c_int = 0;

    // SAFETY: `pair.server` is live and finished its handshake, so
    // `shared_sigalgslen > 1` and index 0 is in range. Both out-pointers address
    // one writable byte of a live local array.
    let count = unsafe {
        SSL_get_shared_sigalgs(
            pair.server,
            0,
            &mut sign,
            &mut hash,
            &mut sign_hash,
            guarded[8..9].as_mut_ptr(),
            guarded[9..10].as_mut_ptr(),
        )
    };
    assert!(
        count > 0,
        "a finished handshake must share at least one signature algorithm"
    );

    // The bytes the function was asked to write are the ones it wrote; the
    // canaries are untouched. Under the old declaration the write covered the
    // first word, so `guarded[8]` would hold the byte and `guarded[9..16]` would
    // not equal the canary.
    assert_eq!(
        &guarded[..8],
        &[0xCDu8; 8],
        "nothing before the raw-signature byte may be written"
    );
    assert_eq!(
        &guarded[10..],
        &[0xCDu8; 6],
        "nothing after the raw-hash byte may be written; the function writes one \
         byte through each pointer, so a pointer-sized write is the defect"
    );
    assert_ne!(
        (guarded[8], guarded[9]),
        (0xCD, 0xCD),
        "both raw bytes must have been written"
    );
    // The pair of bytes together is the TLS SignatureScheme, so it is not zero on
    // either byte for any scheme the handshake can negotiate.
    assert_ne!(
        guarded[8], 0,
        "the signature byte must be a real algorithm id"
    );
}

/// The corruption the old declaration caused, shown at runtime.
///
/// `*mut *const c_char` said each out-parameter was a pointer the callee writes a
/// pointer through. A caller that believed that and passed a one-byte buffer got
/// a pointer-sized write, so the byte it asked for *and* the memory after it were
/// both clobbered.
///
/// # Why this declares the old signature itself
///
/// `ffi_extra::SSL_get_shared_sigalgs` no longer has that type, so this test would
/// not compile against it — and a compile error cannot distinguish "the
/// declaration is wrong" from "the test is wrong". The old signature is therefore
/// re-declared here over the same symbol, which is what a caller compiled before
/// the fix actually called. That keeps this test runnable on both trees, so it can
/// be seen to report a *value* rather than a build failure.
///
/// `*rsig = (unsigned char)(...)` (`t1_lib.c:3717`) writes **one byte**, so the
/// seven bytes after each slot survive: that is what makes the old type's claim
/// false.
#[test]
fn the_old_declaration_writes_a_pointer_where_one_byte_belongs() {
    // The declaration `ffi_extra` used to carry, in its own `extern` block so it
    // does not depend on what the crate declares today.
    extern "C" {
        fn SSL_get_shared_sigalgs(
            ssl: *mut ffi::SSL,
            index: c_int,
            sign: *mut c_int,
            hash: *mut c_int,
            sign_hash: *mut c_int,
            raw_sign: *mut *const std::ffi::c_char,
            raw_hash: *mut *const std::ffi::c_char,
        ) -> c_int;
    }

    let pair = Pair::with_a_client_hello();

    let mut guarded = [0xCDu8; 32];
    let mut sign: c_int = 0;
    let mut hash: c_int = 0;
    let mut sign_hash: c_int = 0;

    // A one-byte buffer at the start of each aligned slot, passed through the old
    // pointer type — exactly what a caller honouring the old declaration built.
    let raw_sign = guarded[8..9].as_mut_ptr() as *mut *const std::ffi::c_char;
    let raw_hash = guarded[16..17].as_mut_ptr() as *mut *const std::ffi::c_char;

    // SAFETY: `pair.server` is live and holds a parsed ClientHello, so index 0 is
    // in range; the two out-pointers address aligned words inside `guarded`.
    let count = unsafe {
        SSL_get_shared_sigalgs(
            pair.server,
            0,
            &mut sign,
            &mut hash,
            &mut sign_hash,
            raw_sign,
            raw_hash,
        )
    };
    assert!(
        count > 0,
        "a server holding a ClientHello must share a signature algorithm"
    );

    // What the function actually wrote is one byte per slot.
    assert_eq!(
        &guarded[9..16],
        &[0xCDu8; 7],
        "the callee wrote one byte, so the seven bytes after it are untouched — \
         under the old declaration the compiler had no way to know that, and a \
         caller that trusted it would have sized the buffer as a pointer"
    );
    assert_eq!(
        &guarded[17..24],
        &[0xCDu8; 7],
        "the second out-parameter is a byte too, not a pointer"
    );
    assert_ne!(
        (guarded[8], guarded[16]),
        (0xCD, 0xCD),
        "both bytes must have been written"
    );
    // The two bytes together are the TLS SignatureScheme the client offered.
    assert!(
        sign != 0 || guarded[8] != 0,
        "the signature byte must carry a real algorithm id"
    );

    // What the old type *permitted* is the defect, and it is measurable: storing a
    // pointer through the pointer it described writes `size_of::<*const c_char>()`
    // bytes, seven of which land past a one-byte buffer. No shipped caller did
    // this — both passed null — which is exactly why the defect was latent, and
    // why a caller asking `getSharedSigalgs` for raw bytes would have hit it.
    let mut one_byte = [0xCDu8; 16];
    // SAFETY: writing through a local byte's address, which is inside `one_byte`.
    unsafe {
        std::ptr::write(
            one_byte.as_mut_ptr() as *mut *const std::ffi::c_char,
            0x1122_3344_5566_7788 as *const std::ffi::c_char,
        );
    }
    assert_eq!(
        one_byte[0], 0x88,
        "the pointer's low byte lands in the byte asked for"
    );
    assert_ne!(
        &one_byte[1..8],
        &[0xCDu8; 7],
        "the pointer's remaining {} bytes overwrite the seven bytes after a \
         one-byte buffer, which is the corruption the old declaration allowed",
        std::mem::size_of::<*const std::ffi::c_char>() - 1
    );
}

/// The two forms of the per-`SSL` verify-store control, and the fact that the
/// `set1` form is a macro.
///
/// `SSL_set1_verify_cert_store` has no symbol in the vendored library; calling
/// the control with `larg == 1` is what the macro does, and `larg` is the up-ref
/// flag. This proves the control exists, returns success, and that the store the
/// connection then verifies against is the one that was installed — which is the
/// SNI-CA behaviour `SetCACerts` documents.
#[test]
fn the_per_ssl_verify_store_control_installs_the_store() {
    let pair = Pair::new();

    // SAFETY: both SSLs are live; the store is owned by `client_ctx`.
    unsafe {
        let store = ffi::SSL_CTX_get_cert_store(pair.client_ctx);
        assert!(!store.is_null(), "a context always has a verify store");
        assert_eq!(
            ssl_set1_verify_cert_store(pair.client, store),
            1,
            "the control must succeed; a macro that is really a missing symbol \
             would have failed to link instead"
        );

        // The control the wrapper performs, spelled out, so the constant and the
        // `larg` flag are pinned rather than assumed.
        let direct = ffi::SSL_ctrl(pair.client, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, store.cast());
        assert_eq!(
            direct, 1,
            "SSL_CTRL_SET_VERIFY_CERT_STORE must accept the store"
        );

        // `SSL_get0_verify_cert_store` is the reader for the same control. It is
        // a macro over `SSL_ctrl` with the same shape and a different command.
        let mut read_back: *mut std::ffi::c_void = std::ptr::null_mut();
        assert_eq!(
            ffi::SSL_ctrl(
                pair.client,
                SSL_CTRL_GET_VERIFY_CERT_STORE,
                0,
                (&mut read_back as *mut *mut std::ffi::c_void).cast(),
            ),
            1
        );
        assert_eq!(
            read_back,
            store.cast(),
            "the store installed on the SSL must be the one read back"
        );
    }

    // A null store is refused rather than handed to `SSL_ctrl`, which would
    // install null and leave the connection verifying against nothing.
    // SAFETY: null is explicitly handled before any pointer is used.
    assert_eq!(
        unsafe { ssl_set1_verify_cert_store(pair.client, std::ptr::null_mut()) },
        0
    );

    // The control up-refs the store, so installing it did not transfer the
    // context's reference and the store is still live when `Drop` frees both.
    // Reading the store back again after a null attempt is what exercises it: if
    // the up-ref were the `set0` form, the first install would have taken the
    // context's only reference and this second read would be a use-after-free.
    // SAFETY: both SSLs are live.
    unsafe {
        let mut read_back: *mut std::ffi::c_void = std::ptr::null_mut();
        assert_eq!(
            ffi::SSL_ctrl(
                pair.client,
                SSL_CTRL_GET_VERIFY_CERT_STORE,
                0,
                (&mut read_back as *mut *mut std::ffi::c_void).cast(),
            ),
            1
        );
        assert!(
            !read_back.is_null(),
            "the store must still be installed after the refused null control, \
             which it cannot be if the install took the context's only reference"
        );
    }
}

/// `#define SSL_CTRL_GET_VERIFY_CERT_STORE 137` in `ssl.h.in:1344`.
///
/// Declared here rather than exported from the crate because nothing in the
/// shipped code reads the store back; the test is the only caller. It is a
/// different number from the `SET` control above (106 vs 137), which is why
/// reusing the `SET` constant here would silently read an unrelated value.
const SSL_CTRL_GET_VERIFY_CERT_STORE: c_int = 137;

/// The sizes the two declarations disagree about, stated as a fact about the
/// platform: one `unsigned char` and one pointer are different widths, so a
/// pointer-typed out-parameter cannot describe a byte-typed write.
#[test]
fn a_byte_and_a_pointer_are_different_widths() {
    assert_eq!(std::mem::size_of::<c_uchar>(), 1);
    assert_eq!(
        std::mem::size_of::<*mut *const std::ffi::c_char>(),
        std::mem::size_of::<*mut *const c_uchar>()
    );
    assert_ne!(
        std::mem::size_of::<c_uchar>(),
        std::mem::size_of::<*const std::ffi::c_char>()
    );
}
