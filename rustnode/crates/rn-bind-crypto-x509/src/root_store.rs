//! The root-certificate store `lib/tls.js` reaches before any `SecureContext`.
//!
//! Five accessors, all in `crypto_context.cc` in Node:
//!
//! | member | what it returns |
//! | --- | --- |
//! | `getBundledRootCertificates()` | the PEM of Node's compiled-in roots |
//! | `getExtraCACertificates()` | the PEM of `NODE_EXTRA_CA_CERTS`' file |
//! | `getSystemCACertificates()` | the PEM of the OS trust store |
//! | `getUserRootCertificates()` | the PEM of what `resetRootCertStore` set |
//! | `resetRootCertStore(array)` | replaces the user list |
//!
//! # The bundled list is empty here, and that is a real answer
//!
//! Node compiles `node_root_certs.h` into the binary: roughly 130 root
//! certificates as a generated C array, 200 KB of text. rustnode has no such
//! generated blob, and inventing one — or worse, substituting this machine's
//! `/etc/ssl/certs` and calling it "bundled" — would make
//! `tls.getCACertificates('bundled')` report a trust store that is not the one a
//! Node release ships. An empty list is what this build actually bundles, and the
//! `tls` tests that need the real list (`test-tls-get-ca-certificates-bundled.js`)
//! are slice S4/S6's to make pass, with the generator that produces the blob.
//!
//! `getSystemCACertificates` and `getExtraCACertificates` **are** real: they read
//! files, and a wrong answer there would be a lie about what the process trusts.

use std::sync::{Mutex, OnceLock};

use openssl::x509::X509;

/// `NODE_EXTRA_CA_CERTS`, read once per process.
///
/// `OnceLock` because Node reads the file once and caches it: a second read would
/// pick up a file changed mid-run and make `tls.getCACertificates('extra')`
/// disagree with the store the process already built.
fn extra_cas() -> &'static OnceLock<Vec<String>> {
    static EXTRA: OnceLock<Vec<String>> = OnceLock::new();
    &EXTRA
}

/// The user-supplied roots, which `resetRootCertStore` replaces.
fn user_roots() -> &'static Mutex<Vec<String>> {
    static USER: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    USER.get_or_init(|| Mutex::new(Vec::new()))
}

/// `getBundledRootCertificates()`: what this build compiles in, which is nothing.
///
/// See the module docs: this is deliberately empty rather than a substitute.
pub fn bundled() -> Vec<String> {
    Vec::new()
}

/// `getExtraCACertificates()`: the certificates in `NODE_EXTRA_CA_CERTS`.
///
/// Empty when the variable is unset, which is the same thing Node reports.
pub fn extra() -> Vec<String> {
    extra_cas()
        .get_or_init(|| {
            let Ok(path) = std::env::var("NODE_EXTRA_CA_CERTS") else {
                return Vec::new();
            };
            match std::fs::read(&path) {
                Ok(bytes) => pem_certificates(&bytes).unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        })
        .clone()
}

/// `getSystemCACertificates()`: the OS trust store as PEM strings.
///
/// The file and directory come from OpenSSL's own defaults
/// (`X509_get_default_cert_file`/`_dir`), which is what
/// `GetOpenSSLSystemCertificates` reads on a non-Apple, non-Windows build. Both
/// are consulted, because a distribution can put roots in either.
pub fn system() -> Vec<String> {
    static SYSTEM: OnceLock<Vec<String>> = OnceLock::new();
    SYSTEM
        .get_or_init(|| {
            let mut certificates = Vec::new();
            // SAFETY: both return static NUL-terminated strings.
            unsafe {
                let file = std::ffi::CStr::from_ptr(openssl_sys::X509_get_default_cert_file());
                if let Some(path) = file.to_str().ok().filter(|path| !path.is_empty()) {
                    if let Ok(bytes) = std::fs::read(path) {
                        certificates.extend(pem_certificates(&bytes).unwrap_or_default());
                    }
                }
                let directory = std::ffi::CStr::from_ptr(openssl_sys::X509_get_default_cert_dir());
                if let Some(path) = directory.to_str().ok().filter(|path| !path.is_empty()) {
                    certificates.extend(directory_certificates(std::path::Path::new(path)));
                }
            }
            certificates
        })
        .clone()
}

/// Every PEM certificate in a directory, in sorted name order.
///
/// Sorted because `readdir` order is not stable and `tls.getCACertificates`
/// returns a list: an unstable order would make that list differ between runs for
/// no reason.
fn directory_certificates(directory: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    let mut certificates = Vec::new();
    for path in paths {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        certificates.extend(pem_certificates(&bytes).unwrap_or_default());
    }
    certificates
}

/// `getUserRootCertificates()`: the certificates `resetRootCertStore` set.
pub fn user() -> Vec<String> {
    user_roots()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
}

/// `resetRootCertStore(certificates)`: replaces the user list.
///
/// An empty array clears the list, which is `root_certs->certs_from_users =
/// std::make_unique<X509Set>()` in `ResetRootCertStore`. Every entry must parse,
/// which is why this reports the failure rather than storing a partial list: a
/// half-populated store would verify some chains and not others.
pub fn reset(pem_strings: &[Vec<u8>]) -> Result<usize, ()> {
    let mut parsed = Vec::with_capacity(pem_strings.len());
    for entry in pem_strings {
        // Store PEM, because that is the shape all five getters return; parsing
        // and re-encoding here is what proves the entry is a certificate.
        let Some(certificates) = pem_certificates(entry) else {
            return Err(());
        };
        parsed.extend(certificates);
    }
    let count = parsed.len();
    let mut roots = user_roots()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *roots = parsed;
    Ok(count)
}

/// Every certificate in a PEM blob, re-encoded as PEM.
///
/// One input string may hold several certificates; Node's `LoadCertsFromBIO`
/// reads all of them, so a bundle file works and a single certificate works.
fn pem_certificates(bytes: &[u8]) -> Option<Vec<String>> {
    let certificates = parse_pem(bytes)?;
    // `X509::stack_from_pem` returns an empty vector for input that holds no
    // certificate at all rather than failing, so an entry that parses to nothing
    // is an error here. Without this a caller could pass garbage and have the
    // store silently reset to empty, which looks like success.
    if certificates.is_empty() {
        return None;
    }
    Some(
        certificates
            .into_iter()
            .map(|der| {
                let certificate = X509::from_der(&der).ok()?;
                let pem = certificate.to_pem().ok()?;
                String::from_utf8(pem).ok()
            })
            .collect::<Option<Vec<String>>>()?,
    )
}

/// Every certificate in a PEM blob, as DER.
fn parse_pem(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let certificates = X509::stack_from_pem(bytes).ok()?;
    let mut encoded = Vec::with_capacity(certificates.len());
    for certificate in certificates {
        encoded.push(certificate.to_der().ok()?);
    }
    Some(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(cn: &str) -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::X509Name;

        let key = PKey::from_rsa(Rsa::generate(2048).expect("RSA")).expect("pkey");
        let mut name = X509Name::builder().expect("name");
        name.append_entry_by_text("CN", cn).expect("CN");
        let name = name.build();
        let mut builder = X509::builder().expect("builder");
        builder.set_version(2).expect("version");
        let serial = BigNum::from_u32(1).expect("serial");
        builder
            .set_serial_number(&serial.to_asn1_integer().expect("integer"))
            .expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&key).expect("pubkey");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("notBefore"))
            .expect("notBefore");
        builder
            .set_not_after(&Asn1Time::days_from_now(1).expect("notAfter"))
            .expect("notAfter");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        builder.build().to_pem().expect("pem")
    }

    #[test]
    fn the_bundled_store_is_empty_because_this_build_bundles_nothing() {
        // Not a placeholder: the generator that produces `node_root_certs.h` has
        // not been ported, and an empty list is the honest answer. When it is
        // ported this assertion becomes a count.
        assert!(bundled().is_empty());
    }

    #[test]
    fn resetting_the_user_store_replaces_it() {
        let first = self_signed("first");
        let second = self_signed("second");
        assert_eq!(reset(&[first]).expect("parses"), 1);
        assert_eq!(user().len(), 1);
        assert_eq!(reset(&[second.clone(), second]).expect("parses"), 2);
        assert_eq!(user().len(), 2);
        // An empty array clears it, which `ResetRootCertStore` special-cases.
        assert_eq!(reset(&[]).expect("parses"), 0);
        assert!(user().is_empty());
    }

    #[test]
    fn an_unparseable_entry_rejects_the_whole_reset() {
        // A half-applied store would verify some chains and not others, so the
        // failure is all-or-nothing.
        assert!(reset(&[b"not a certificate".to_vec()]).is_err());
        assert!(user().is_empty());
    }

    #[test]
    fn one_blob_may_hold_several_certificates() {
        // `LoadCertsFromBIO` reads every certificate in the input, which is what
        // makes a bundle file work as `NODE_EXTRA_CA_CERTS`.
        let mut bundle = self_signed("one");
        bundle.extend_from_slice(&self_signed("two"));
        assert_eq!(pem_certificates(&bundle).expect("parses").len(), 2);
    }
}
