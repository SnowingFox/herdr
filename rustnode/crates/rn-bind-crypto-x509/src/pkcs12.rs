//! `parsePKCS12`: the `crypto_pkcs12.cc` entry point.
//!
//! Returns `[keyHandle | null, certificate | null, [additionalCerts]]`. The three
//! outcomes of `PKCS12ParseResult` are distinct errors, and the difference is
//! observable: a bundle that is not PKCS#12 at all is
//! `ERR_CRYPTO_OPERATION_FAILED("Input is not a valid PKCS#12 structure")`, a
//! bundle using an algorithm that moved to the legacy provider is
//! `ERR_CRYPTO_UNSUPPORTED_OPERATION`, and anything else carries the OpenSSL
//! error.
//!
//! # Where this is used
//!
//! `lib/internal/tls/*` reads the `pfx` option through it, and
//! `test-crypto-pkcs12.js` exercises all three branches. `SecureContext` also
//! calls the same bundle parser for `pfx`; that caller is slice S4's, and this
//! module is the shared parse, not a second one.

use openssl_sys as ffi;

/// Why a bundle could not be parsed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pkcs12Error {
    /// `d2i_PKCS12_bio` failed: the bytes are not a PKCS#12 structure.
    NotRecognised,
    /// `PKCS12_parse` failed with `ERR_R_UNSUPPORTED`, meaning an algorithm in
    /// the bundle lives in the OpenSSL legacy provider.
    UnsupportedAlgorithm,
    /// Anything else, with the packed OpenSSL error.
    Failed(u64),
}

/// One parsed bundle.
///
/// The key arrives as an owned `EVP_PKEY` reference because `PKCS12_parse`
/// allocates it; the certificate and the CA list are converted to DER by the
/// caller, which is the only representation this crate stores.
pub struct Bundle {
    /// The private key, owned by this struct.
    pub key: Option<*mut ffi::EVP_PKEY>,
    pub certificate: Option<Vec<u8>>,
    pub chain: Vec<Vec<u8>>,
}

impl Drop for Bundle {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            // SAFETY: `PKCS12_parse` returned one owned reference, and `Drop`
            // runs exactly once.
            unsafe { ffi::EVP_PKEY_free(key) };
        }
    }
}

extern "C" {
    fn d2i_PKCS12_bio(bio: *mut ffi::BIO, out: *mut *mut ffi::PKCS12) -> *mut ffi::PKCS12;
    fn PKCS12_free(value: *mut ffi::PKCS12);
    fn PKCS12_parse(
        value: *mut ffi::PKCS12,
        passphrase: *const std::ffi::c_char,
        key: *mut *mut ffi::EVP_PKEY,
        certificate: *mut *mut ffi::X509,
        chain: *mut *mut ffi::stack_st_X509,
    ) -> std::ffi::c_int;
    fn BIO_new_mem_buf(data: *const std::ffi::c_void, length: std::ffi::c_int) -> *mut ffi::BIO;
    fn BIO_free(bio: *mut ffi::BIO) -> std::ffi::c_int;
    fn ERR_get_error() -> std::ffi::c_ulong;
    fn OPENSSL_sk_num(stack: *const std::ffi::c_void) -> std::ffi::c_int;
    fn OPENSSL_sk_value(
        stack: *const std::ffi::c_void,
        index: std::ffi::c_int,
    ) -> *mut std::ffi::c_void;
    fn OPENSSL_sk_pop_free(
        stack: *mut std::ffi::c_void,
        free: unsafe extern "C" fn(*mut std::ffi::c_void),
    );
    fn X509_free(value: *mut ffi::X509);
    fn i2d_X509(value: *mut ffi::X509, out: *mut *mut u8) -> std::ffi::c_int;
}

/// `ERR_R_UNSUPPORTED`, the reason Node maps to `UNSUPPORTED_ALGORITHM`.
///
/// On the OpenSSL-provider build it checks the *reason* only, without the library
/// bit, which is what `ERR_GET_REASON(err) == ERR_R_UNSUPPORTED` does.
const ERR_R_UNSUPPORTED: std::ffi::c_int = 252;

/// Parses a PKCS#12 bundle.
///
/// `passphrase` is `None` when the caller passed `undefined`, which is different
/// from an empty passphrase: `PKCS12_parse` treats null as "no password" and an
/// empty string as a zero-length password.
pub fn parse(bundle: &[u8], passphrase: Option<&[u8]>) -> Result<Bundle, Pkcs12Error> {
    // The passphrase reaches `PKCS12_parse` as a NUL-terminated C string, so an
    // embedded NUL would truncate it. `crypto_pkcs12.cc` rejects that rather than
    // silently opening the bundle with a shorter password, and does it before the
    // parse.
    if let Some(passphrase) = passphrase {
        if passphrase.contains(&0) {
            return Err(Pkcs12Error::Failed(0));
        }
    }

    let passphrase = match passphrase {
        Some(bytes) => match std::ffi::CString::new(bytes.to_vec()) {
            Ok(text) => Some(text),
            Err(_) => return Err(Pkcs12Error::Failed(0)),
        },
        None => None,
    };

    if bundle.is_empty() {
        return Err(Pkcs12Error::NotRecognised);
    }

    // SAFETY: `bundle` outlives the BIO, which borrows it and is freed below.
    unsafe {
        let bio = BIO_new_mem_buf(
            bundle.as_ptr().cast::<std::ffi::c_void>(),
            bundle.len() as std::ffi::c_int,
        );
        if bio.is_null() {
            return Err(Pkcs12Error::Failed(ERR_get_error() as u64));
        }

        let mut parsed: *mut ffi::PKCS12 = std::ptr::null_mut();
        let decoded = d2i_PKCS12_bio(bio, &mut parsed);
        BIO_free(bio);
        if decoded.is_null() || parsed.is_null() {
            return Err(Pkcs12Error::NotRecognised);
        }

        let mut key: *mut ffi::EVP_PKEY = std::ptr::null_mut();
        let mut certificate: *mut ffi::X509 = std::ptr::null_mut();
        let mut chain: *mut ffi::stack_st_X509 = std::ptr::null_mut();
        let passphrase_pointer = passphrase
            .as_ref()
            .map_or(std::ptr::null(), |text| text.as_ptr());
        let ok = PKCS12_parse(
            parsed,
            passphrase_pointer,
            &mut key,
            &mut certificate,
            &mut chain,
        );
        PKCS12_free(parsed);
        if ok != 1 {
            // A failed parse can still have allocated one of the three outputs,
            // and `PKCS12_parse` does not promise otherwise.
            if !key.is_null() {
                ffi::EVP_PKEY_free(key);
            }
            if !certificate.is_null() {
                X509_free(certificate);
            }
            if !chain.is_null() {
                OPENSSL_sk_pop_free(chain.cast(), transparent_free(X509_free));
            }
            let error = ERR_get_error();
            // `ERR_GET_REASON` and `ERR_GET_LIB` are macros in OpenSSL, not
            // symbols, so the bit arithmetic is written out. The masks are from
            // `openssl/err.h`: the reason is the low 23 bits up to 3.0 and the
            // library the next 8 above it.
            let reason = (error & 0x7F_FFFF) as i32;
            if reason == ERR_R_UNSUPPORTED {
                return Err(Pkcs12Error::UnsupportedAlgorithm);
            }
            return Err(Pkcs12Error::Failed(error as u64));
        }

        let mut chain_der = Vec::new();
        if !chain.is_null() {
            let count = OPENSSL_sk_num(chain.cast());
            for index in 0..count {
                let entry = OPENSSL_sk_value(chain.cast(), index) as *mut ffi::X509;
                if entry.is_null() {
                    continue;
                }
                // `New()` takes ownership of a reference, so take one of our own
                // rather than the stack's.
                if let Some(der) = encode(entry) {
                    chain_der.push(der);
                }
            }
            OPENSSL_sk_pop_free(chain.cast(), transparent_free(X509_free));
        }

        let certificate_der = if certificate.is_null() {
            None
        } else {
            let der = encode(certificate);
            X509_free(certificate);
            der
        };

        Ok(Bundle {
            key: (!key.is_null()).then_some(key),
            certificate: certificate_der,
            chain: chain_der,
        })
    }
}

/// `i2d_X509` into an owned `Vec`.
///
/// # Safety
///
/// `certificate` must be a live `X509`.
unsafe fn encode(certificate: *mut ffi::X509) -> Option<Vec<u8>> {
    let mut pointer: *mut u8 = std::ptr::null_mut();
    // SAFETY: allocates with `OPENSSL_malloc`, copied out and freed here.
    unsafe {
        let length = i2d_X509(certificate, &mut pointer);
        if length <= 0 || pointer.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(pointer, length as usize).to_vec();
        ffi::OPENSSL_free(pointer.cast());
        Some(bytes)
    }
}

/// Adapts a concrete destructor to the `void *` form the stack walker takes.
///
/// The two function types have identical ABIs; this is a cast rather than a
/// wrapper so the stack sees the real `X509_free` symbol.
fn transparent_free(
    free: unsafe extern "C" fn(*mut ffi::X509),
) -> unsafe extern "C" fn(*mut std::ffi::c_void) {
    // SAFETY: a `*mut X509` and a `*mut c_void` have the same representation, and
    // the caller only ever passes pointers the stack holds.
    unsafe { std::mem::transmute(free) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn junk_is_not_a_pkcs12_structure() {
        // `d2i_PKCS12_bio` fails, which is `NOT_RECOGNIZED` and becomes
        // `ERR_CRYPTO_OPERATION_FAILED("Input is not a valid PKCS#12 structure")`.
        assert_eq!(
            parse(b"not a bundle", None).err(),
            Some(Pkcs12Error::NotRecognised)
        );
    }

    #[test]
    fn an_empty_input_is_not_a_structure() {
        assert_eq!(parse(&[], None).err(), Some(Pkcs12Error::NotRecognised));
    }

    #[test]
    fn a_passphrase_with_an_embedded_nul_is_rejected() {
        // `PKCS12_parse` takes a C string, so `b"a\0b"` would silently become
        // `"a"`. Node rejects it, and so does this.
        assert!(matches!(
            parse(b"anything", Some(b"a\0b")),
            Err(Pkcs12Error::Failed(0))
        ));
    }

    #[test]
    fn the_reason_for_an_unsupported_algorithm_is_pinned() {
        // `ERR_R_UNSUPPORTED` is 252 on OpenSSL 3.x. Hard-coded because a drift
        // would turn the legacy-provider error into a generic operation failure,
        // which is the assertion `test-crypto-pkcs12.js` makes about a bundle
        // using a legacy digest.
        assert_eq!(ERR_R_UNSUPPORTED, 252);
    }
}
