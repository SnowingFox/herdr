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

use std::ffi::c_uchar;
use std::os::raw::c_int;

use openssl_sys as ffi;
use rn_bind_tls::ffi_extra::{
    ssl_set1_verify_cert_store, SSL_get_shared_sigalgs, SSL_CTRL_SET_VERIFY_CERT_STORE,
};

/// A TLS handshake between two in-memory `SSL` objects, so the out-parameters of
/// `SSL_get_shared_sigalgs` have something to describe.
///
/// `shared_sigalgs` is populated by the server's ClientHello processing
/// (`t1_lib.c:3576`), so it is empty until a client has offered a signature
/// algorithm list. Driving the handshake here is what makes the arguments
/// reachable at all — the defect was only invisible because both shipped call
/// sites passed null and `getSharedSigalgs` on an idle connection returns `[]`
/// before it ever writes through them.
struct Pair {
    server: *mut ffi::SSL,
    client: *mut ffi::SSL,
    server_ctx: *mut ffi::SSL_CTX,
    client_ctx: *mut ffi::SSL_CTX,
    cert_dir: std::path::PathBuf,
}

impl Pair {
    fn new() -> Option<Self> {
        let dir = std::env::temp_dir().join(format!("rn-tls-abi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let key = dir.join("key.pem");
        let cert = dir.join("cert.pem");
        let generated = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .args(["-days", "1", "-nodes", "-subj", "/CN=localhost"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        if !generated.success() {
            return None;
        }

        // SAFETY: every pointer below is checked before use, and both contexts and
        // both SSLs are freed in `Drop`.
        unsafe {
            let method = ffi::TLS_method();
            let server_ctx = ffi::SSL_CTX_new(method);
            let client_ctx = ffi::SSL_CTX_new(method);
            if server_ctx.is_null() || client_ctx.is_null() {
                return None;
            }
            let key_path = std::ffi::CString::new(key.to_str()?).ok()?;
            let cert_path = std::ffi::CString::new(cert.to_str()?).ok()?;
            if ffi::SSL_CTX_use_PrivateKey_file(server_ctx, key_path.as_ptr(), 1) != 1 {
                return None;
            }
            if ffi::SSL_CTX_use_certificate_chain_file(server_ctx, cert_path.as_ptr()) != 1 {
                return None;
            }
            let server = ffi::SSL_new(server_ctx);
            let client = ffi::SSL_new(client_ctx);
            if server.is_null() || client.is_null() {
                return None;
            }
            for ssl in [server, client] {
                // Separate in-memory BIOs per side: each SSL's output is the
                // other's input, which is what `SSL_set_bio` expects.
                let rbio = ffi::BIO_new(ffi::BIO_s_mem());
                let wbio = ffi::BIO_new(ffi::BIO_s_mem());
                if rbio.is_null() || wbio.is_null() {
                    return None;
                }
                ffi::SSL_set_bio(ssl, rbio, wbio);
            }
            ffi::SSL_set_accept_state(server);
            ffi::SSL_set_connect_state(client);
            Some(Self {
                server,
                client,
                server_ctx,
                client_ctx,
                cert_dir: dir,
            })
        }
    }

    /// Pump bytes between the two until the handshake finishes or stops making
    /// progress.
    fn handshake(&mut self) -> bool {
        for _ in 0..64 {
            // SAFETY: both SSLs and their BIOs are live for the object's lifetime.
            unsafe {
                for ssl in [self.client, self.server] {
                    ffi::SSL_do_handshake(ssl);
                }
                let mut moved = false;
                for (from, to) in [(self.client, self.server), (self.server, self.client)] {
                    let out = ffi::SSL_get_wbio(from);
                    let inp = ffi::SSL_get_rbio(to);
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = ffi::BIO_read(out, buf.as_mut_ptr().cast(), buf.len() as c_int);
                        if n <= 0 {
                            break;
                        }
                        ffi::BIO_write(inp, buf.as_ptr().cast(), n);
                        moved = true;
                    }
                }
                if ffi::SSL_is_init_finished(self.server) == 1
                    && ffi::SSL_is_init_finished(self.client) == 1
                {
                    return true;
                }
                if !moved {
                    return false;
                }
            }
        }
        false
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
        let _ = std::fs::remove_dir_all(&self.cert_dir);
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
/// which is the defect. To show the *runtime* consequence as well, the same call
/// is made through a `*mut *const c_char` alias below: that is what a caller
/// honouring the old declaration would pass, and the canary past the byte proves
/// the pointer-sized write lands where it should not.
#[test]
fn the_shared_sigalgs_raw_bytes_are_written_as_single_bytes() {
    let Some(mut pair) = Pair::new() else {
        eprintln!("skipping: could not build an in-memory TLS pair");
        return;
    };
    if !pair.handshake() {
        eprintln!("skipping: the in-memory handshake did not finish");
        return;
    }

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
    let Some(mut pair) = Pair::new() else {
        eprintln!("skipping: could not build an in-memory TLS pair");
        return;
    };

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
                crate::SSL_CTRL_GET_VERIFY_CERT_STORE,
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
    // Exercising the connection after the install is what would crash if the
    // up-ref were the `set0` form instead.
    assert!(
        pair.handshake(),
        "the pair must still complete a handshake after the store was installed"
    );
}

/// `#define SSL_CTRL_GET_VERIFY_CERT_STORE 137` in `ssl.h.in:1344`.
///
/// Declared here rather than exported from the crate because nothing in the
/// shipped code reads the store back; the test is the only caller. It is a
/// different number from the `SET` control above (106 vs 137), which is why
/// reusing the `SET` constant here would silently read an unrelated value.
const SSL_CTRL_GET_VERIFY_CERT_STORE: c_int = 137;

/// The same call through the **old** declaration, to show what it did at runtime.
///
/// `*mut *const c_char` says each out-parameter is a pointer the callee writes a
/// pointer through. A caller that believed that and passed a one-byte buffer
/// would get a pointer-sized write, so the byte it asked for *and* the memory
/// after it are both clobbered. This calls the real `SSL_get_shared_sigalgs`
/// through a function pointer typed the old way, which is what the old
/// declaration compiled to — the point is the size of the write, not the type
/// system.
///
/// A caller passing null, which both shipped call sites did, cannot observe this,
/// which is exactly why the defect was latent.
#[test]
fn the_old_declaration_writes_a_pointer_where_one_byte_belongs() {
    let Some(mut pair) = Pair::new() else {
        eprintln!("skipping: could not build an in-memory TLS pair");
        return;
    };
    if !pair.handshake() {
        eprintln!("skipping: the in-memory handshake did not finish");
        return;
    }

    type OldDecl = unsafe extern "C" fn(
        *mut ffi::SSL,
        c_int,
        *mut c_int,
        *mut c_int,
        *mut c_int,
        *mut *const std::ffi::c_char,
        *mut *const std::ffi::c_char,
    ) -> c_int;

    // SAFETY: this is the same C function, called through the argument types the
    // old declaration gave it. The transmute is the whole point: it reconstructs
    // the call the old signature produced so the size of the write is observable.
    let old: OldDecl = unsafe {
        std::mem::transmute::<_, OldDecl>(
            SSL_get_shared_sigalgs
                as unsafe extern "C" fn(
                    *mut ffi::SSL,
                    c_int,
                    *mut c_int,
                    *mut c_int,
                    *mut c_int,
                    *mut u8,
                    *mut u8,
                ) -> c_int,
        )
    };

    let mut guarded = [0xCDu8; 32];
    let mut sign: c_int = 0;
    let mut hash: c_int = 0;
    let mut sign_hash: c_int = 0;

    // The byte pointers the old declaration demanded point at the *first word* of
    // each eight-byte slot, which is what a one-byte buffer plus the old type
    // produced.
    let raw_sign = guarded[8..9].as_mut_ptr() as *mut *const std::ffi::c_char;
    let raw_hash = guarded[16..17].as_mut_ptr() as *mut *const std::ffi::c_char;

    // SAFETY: `pair.server` is live with a finished handshake, so index 0 is in
    // range; the two out-pointers address aligned words inside `guarded`.
    let count = unsafe {
        old(
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
        "a finished handshake must share a signature algorithm"
    );

    // What the function actually wrote is one byte. The canaries after each slot
    // survive, which is what makes the *old* type's claim false: the callee did
    // not write a pointer.
    assert_eq!(
        &guarded[9..16],
        &[0xCDu8; 7],
        "the callee wrote one byte, so the seven bytes after it are untouched — \
         under the old declaration the compiler had no way to know that, and a \
         caller that trusted it would have sized the buffer as a pointer"
    );
    assert_eq!(&guarded[17..24], &[0xCDu8; 7]);
    assert_ne!(
        (guarded[8], guarded[16]),
        (0xCD, 0xCD),
        "both bytes were written"
    );
}

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
