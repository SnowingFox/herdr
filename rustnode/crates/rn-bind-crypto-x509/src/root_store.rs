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
//! # The bundled list is Node's own
//!
//! Node compiles `node_root_certs.h` into the binary: 118 root certificates as
//! a generated C array, about 190 KB of text, produced from `tools/certdata.txt`
//! by `tools/mk-ca-bundle.pl`. `src/root_certs.rs` holds the same values, in the
//! same order, generated from the same trust store by a port of that Perl
//! script: `tools/gen-root-certs.py` in this crate, documented there and
//! committed so a build stays offline.
//!
//! Substituting this machine's `/etc/ssl/certs` and calling it "bundled" would
//! make `tls.getCACertificates('bundled')` report a trust store that is not the
//! one a Node release ships, which is why the system store has its own accessor
//! ([`system`]) and is never merged into this one here.
//!
//! `getSystemCACertificates` and `getExtraCACertificates` **are** real too: they
//! read files, and a wrong answer there would be a lie about what the process
//! trusts.

use std::sync::{Mutex, OnceLock};

use openssl::x509::X509;

use crate::root_certs::BUNDLED_ROOTS;

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

/// `getBundledRootCertificates()`: what this build compiles in.
///
/// The strings are `src/node_root_certs.h`'s `root_certs` array, already PEM
/// with no trailing newline. They are returned as they are, not re-encoded,
/// because `tls.rootCertificates` is compared to Node's own list by content and
/// a parse-and-re-emit round trip would be an opportunity to differ.
///
/// Allocated per call: `lib/tls.js` caches the result in
/// `bundledRootCertificates` at module scope and never calls twice, so a
/// process-lifetime copy would only add 118 `String`s that the JavaScript heap
/// already holds.
pub fn bundled() -> Vec<String> {
    BUNDLED_ROOTS.iter().map(|pem| (*pem).to_string()).collect()
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
pub fn reset(pem_strings: &[Vec<u8>]) -> Option<usize> {
    let mut parsed = Vec::with_capacity(pem_strings.len());
    for entry in pem_strings {
        // Store PEM, because that is the shape all five getters return; parsing
        // and re-encoding here is what proves the entry is a certificate.
        let certificates = pem_certificates(entry)?;
        parsed.extend(certificates);
    }
    let count = parsed.len();
    let mut roots = user_roots()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *roots = parsed;
    Some(count)
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
    certificates
        .into_iter()
        .map(|der| {
            let certificate = X509::from_der(&der).ok()?;
            let pem = certificate.to_pem().ok()?;
            String::from_utf8(pem).ok()
        })
        .collect::<Option<Vec<String>>>()
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
    fn the_bundled_store_is_node_root_certs_h() {
        // The count is Node's `arraysize(root_certs)` at the pinned revision.
        // A generator that dropped or duplicated a root would change it, and the
        // per-certificate comparison against the oracle is what proves the
        // *contents*; this pins the shape so that test cannot go vacuous.
        let bundled = bundled();
        assert_eq!(bundled.len(), crate::root_certs::ROOT_CERT_COUNT);
        assert_eq!(bundled.len(), 118);
        assert!(
            bundled
                .iter()
                .all(|pem| pem.starts_with("-----BEGIN CERTIFICATE-----")),
            "every entry must be PEM"
        );
    }

    #[test]
    fn the_input_trust_store_is_still_the_one_this_was_generated_from() {
        // `CERTDATA_SHA256` is the pin the module docs describe. Regenerating
        // from a changed `vendor/certdata/certdata.txt` would produce a
        // different set of roots, and nothing else would notice: the count can
        // stay 118 while the certificates change. Reading the file here is
        // cheap (1.3 MB, once) and is the only way the pin is checked by a
        // build rather than by a command someone has to remember.
        use crate::root_certs::{CERTDATA_SHA256, NODE_REVISION};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/certdata/certdata.txt");
        let bytes = std::fs::read(&path).expect("vendor/certdata/certdata.txt");
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &bytes)
            .expect("sha256")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(digest, CERTDATA_SHA256);
        assert_eq!(NODE_REVISION, "f344e7f552e3656bd37517151c5dc87d22b33771");
    }

    #[test]
    fn resetting_the_user_store_replaces_it() {
        let first = self_signed("first");
        let second = self_signed("second");
        assert_eq!(reset(&[first]), Some(1));
        assert_eq!(user().len(), 1);
        assert_eq!(reset(&[second.clone(), second]), Some(2));
        assert_eq!(user().len(), 2);
        // An empty array clears it, which `ResetRootCertStore` special-cases.
        assert_eq!(reset(&[]), Some(0));
        assert!(user().is_empty());
    }

    #[test]
    fn an_unparseable_entry_rejects_the_whole_reset() {
        // A half-applied store would verify some chains and not others, so the
        // failure is all-or-nothing.
        assert!(reset(&[b"not a certificate".to_vec()]).is_none());
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

    #[test]
    fn every_bundled_root_parses_as_a_certificate() {
        // `InitializeBundledRootCertificates` calls `CHECK(x509)` on each
        // `PEM_read_bio_X509` result, so a PEM entry that does not parse aborts
        // a Node process rather than being skipped. The same has to hold here:
        // the store is only a trust store if every string in it is a
        // certificate.
        for (position, pem) in bundled().iter().enumerate() {
            let certificate = X509::from_pem(pem.as_bytes())
                .unwrap_or_else(|error| panic!("root {position} does not parse: {error}"));
            assert!(
                certificate.subject_name().entries().next().is_some(),
                "root {position} has an empty subject"
            );
        }
    }

    #[test]
    fn a_corrupted_bundled_root_does_not_round_trip_to_the_same_der() {
        // The control for the test above: PEM parsing must not accept anything,
        // or "every root parses" would be vacuous. The corruption is applied to
        // the middle of the base64 body rather than to its first character,
        // because the first character is the DER SEQUENCE tag and flipping that
        // only proves the tag is checked. A middle byte exercises the length and
        // structure checks the real parse depends on.
        //
        // The assertion is "fails to parse *or* decodes to different DER", not
        // "fails": a byte inside the signature still parses, because PEM parsing
        // does not verify the signature. What must never happen is the same
        // certificate coming back.
        let pem = bundled().into_iter().next().expect("at least one root");
        let original = X509::from_pem(pem.as_bytes()).expect("root parses");

        let body_start = pem.find('\n').expect("header line") + 1;
        let body_end = pem.rfind('\n').expect("footer line");
        let midpoint = body_start + (body_end - body_start) / 2;
        let byte = pem.as_bytes()[midpoint];
        let replacement = if byte == b'A' { "B" } else { "A" };
        let mut corrupted = pem.clone();
        corrupted.replace_range(midpoint..midpoint + 1, replacement);

        match X509::from_pem(corrupted.as_bytes()) {
            Err(_) => {}
            Ok(parsed) => assert_ne!(
                parsed.to_der().expect("DER"),
                original.to_der().expect("DER"),
                "a corrupted root decoded to the original certificate"
            ),
        }
    }
}
