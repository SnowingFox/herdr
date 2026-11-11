//! The certificate bytes behind an `X509Certificate`, with no V8 in sight.
//!
//! `crypto_x509.cc` has two state types and the split between them is the whole
//! design:
//!
//! * `X509CertificateSnapshot` — an **immutable `Vec<DER>`**. Certificate zero is
//!   the leaf, the rest are its issuers. It is shareable (Node holds it in a
//!   `shared_ptr`) and it is what gets cloned or transferred to a worker: a
//!   worker receives the DER list, not a pointer into another isolate's heap.
//! * `ManagedX509` — one **live `X509 *`**, isolate-local, always reparsed from
//!   the snapshot.
//!
//! Keeping the bytes authoritative and re-parsing on use is what
//! `crypto_x509.cc` does deliberately (`X509Certificate::New` at line 1576 keeps
//! "the live certificate independent from the backend object that was serialized
//! while creating the immutable snapshot", because some backends "populate or
//! invalidate lazy caches while encoding malformed-but-parseable input").
//!
//! # Why an `Arc` over `Vec<Vec<u8>>` rather than an `X509` per level
//!
//! An `X509 *` is not `Send`, and `X509Certificate` is cloneable across threads.
//! DER bytes are `Send + Sync`, so the snapshot can be an `Arc` that a worker
//! shares directly. Every live `X509` is built inside the isolate that asks for
//! it.

use std::sync::Arc;

use foreign_types::ForeignType;
use openssl::x509::X509;

/// One certificate chain, as DER, leaf first.
///
/// Cloning is a pointer bump; the bytes never change after construction.
#[derive(Clone)]
pub struct Snapshot {
    certificates: Arc<Vec<Vec<u8>>>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Snapshot")
            .field("certificates", &self.certificates.len())
            .finish_non_exhaustive()
    }
}

impl Snapshot {
    /// A snapshot over already-encoded DER, or `None` for an empty list.
    ///
    /// `crypto_x509.cc`'s `Create(std::vector<DER>)` rejects an empty list, and
    /// it re-encodes every entry so a caller cannot smuggle in bytes that parse
    /// but do not survive a round trip. Both are done here, at the one place a
    /// snapshot is built from foreign bytes.
    pub fn from_der(certificates: Vec<Vec<u8>>) -> Option<Self> {
        if certificates.is_empty() {
            return None;
        }
        let mut normalised = Vec::with_capacity(certificates.len());
        for certificate in &certificates {
            let parsed = parse_der(certificate)?;
            normalised.push(encode_der(&parsed)?);
        }
        Some(Self {
            certificates: Arc::new(normalised),
        })
    }

    /// A snapshot over one leaf plus the issuers from `issuers`.
    ///
    /// This is `X509CertificateSnapshot::Create(X509View, STACK_OF(X509)*,
    /// issuers_start)`: `issuers` is the chain as the caller received it and
    /// `issuers_start` skips the entries the caller already accounted for — the
    /// peer chain puts the leaf at index 0 on the client and not on the server,
    /// which is the whole reason the offset exists.
    pub fn from_leaf_and_issuers(
        leaf: &X509,
        issuers: &[Vec<u8>],
        issuers_start: usize,
    ) -> Option<Self> {
        let mut certificates = Vec::with_capacity(issuers.len().saturating_sub(issuers_start) + 1);
        certificates.push(encode_der(leaf)?);
        for issuer in issuers.iter().skip(issuers_start) {
            // Re-encode rather than trusting the caller's bytes, exactly as the
            // chain constructor does for the leaf.
            let parsed = parse_der(issuer)?;
            certificates.push(encode_der(&parsed)?);
        }
        Some(Self {
            certificates: Arc::new(certificates),
        })
    }

    /// A snapshot whose first certificate is `leaf` and whose remaining entries
    /// are the already-encoded DER in `issuers`.
    pub fn from_leaf_der_and_issuers(leaf: Vec<u8>, issuers: &[Vec<u8>]) -> Option<Self> {
        let mut certificates = Vec::with_capacity(issuers.len() + 1);
        certificates.push(leaf);
        certificates.extend(issuers.iter().cloned());
        Self::from_der(certificates)
    }

    /// How many certificates the chain holds, leaf included.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Whether the chain is empty, which [`Snapshot::from_der`] makes unreachable.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// The DER bytes at `index`, or `None` past the end.
    pub fn der_at(&self, index: usize) -> Option<&[u8]> {
        self.certificates.get(index).map(Vec::as_slice)
    }

    /// Every certificate's DER, leaf first.
    ///
    /// `getX509CertificateSnapshot` returns exactly this list, and
    /// `parseX509Snapshot` consumes it, so the two share one representation.
    pub fn to_der_list(&self) -> Vec<Vec<u8>> {
        self.certificates.as_ref().clone()
    }

    /// The live `X509` at `index`, reparsed.
    ///
    /// Every accessor on `X509Certificate` starts here, which is what makes the
    /// object's state the bytes rather than a backend handle.
    pub fn parse(&self, index: usize) -> Option<X509> {
        parse_der(self.der_at(index)?)
    }

    /// Total encoded size, which is the memory this snapshot accounts for.
    pub fn size_bytes(&self) -> usize {
        self.certificates.iter().map(Vec::len).sum()
    }
}

/// Parses one DER certificate, rejecting trailing bytes.
///
/// `ParseCertificate` in `crypto_x509.cc` requires `cursor == end`, so a buffer
/// holding one certificate followed by junk is a parse failure rather than a
/// silent partial read.
pub fn parse_der(bytes: &[u8]) -> Option<X509> {
    if bytes.is_empty() {
        return None;
    }
    let parsed = X509::from_der(bytes).ok()?;
    // Round-tripping is the check that nothing was left over: `X509::from_der`
    // accepts a prefix, and re-encoding a truncated read would silently drop the
    // remainder.
    let len = i2d_len(&parsed)?;
    (len == bytes.len()).then_some(parsed)
}

/// Parses a certificate the way `X509Pointer::Parse` does: PEM first, then DER.
///
/// The order matters and is Node's: `PEM_read_bio_X509_AUX` first, and only if
/// that fails, `d2i_X509`. A PEM parser that accepted anything would make
/// `new X509Certificate('<junk>')` succeed where Node throws.
pub fn parse_pem_or_der(bytes: &[u8]) -> Option<X509> {
    if let Ok(parsed) = X509::from_pem(bytes) {
        return Some(parsed);
    }
    parse_der(bytes)
}

/// The DER encoding of a parsed certificate.
pub fn encode_der(certificate: &X509) -> Option<Vec<u8>> {
    certificate.to_der().ok()
}

/// The DER length `i2d_X509` reports, used to detect trailing bytes.
fn i2d_len(certificate: &X509) -> Option<usize> {
    // SAFETY: `i2d_X509` only reads the certificate and, with a null output
    // pointer, returns the encoded length. `as_ptr` is the borrowed handle the
    // safe wrapper holds.
    let len = unsafe { openssl_sys::i2d_X509(certificate.as_ptr(), std::ptr::null_mut()) };
    (len > 0).then_some(len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate, generated here rather than checked in so the
    /// test does not depend on a fixture file.
    fn self_signed() -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Name, X509};

        let key = PKey::from_rsa(Rsa::generate(2048).expect("RSA generates")).expect("a pkey");
        let mut name = X509Name::builder().expect("a name");
        name.append_entry_by_text("CN", "test").expect("CN");
        let name = name.build();
        let mut builder = X509::builder().expect("a builder");
        builder.set_version(2).expect("version");
        let serial = BigNum::from_u32(1).expect("serial");
        builder
            .set_serial_number(&serial.to_asn1_integer().expect("an integer"))
            .expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&key).expect("pubkey");
        let not_before = Asn1Time::days_from_now(0).expect("notBefore");
        let not_after = Asn1Time::days_from_now(1).expect("notAfter");
        builder.set_not_before(&not_before).expect("notBefore");
        builder.set_not_after(&not_after).expect("notAfter");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        builder.build().to_der().expect("der")
    }

    #[test]
    fn a_der_certificate_round_trips_through_a_snapshot() {
        let der = self_signed();
        let snapshot = Snapshot::from_der(vec![der.clone()]).expect("a snapshot");
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.der_at(0), Some(der.as_slice()));
        assert_eq!(snapshot.size_bytes(), der.len());
    }

    #[test]
    fn an_empty_snapshot_is_refused() {
        // `X509CertificateSnapshot::Create` returns null for an empty vector, and
        // the binding turns that into ERR_CRYPTO_OPERATION_FAILED.
        assert!(Snapshot::from_der(Vec::new()).is_none());
    }

    #[test]
    fn invalid_der_is_refused_not_stored() {
        assert!(Snapshot::from_der(vec![vec![1, 2, 3]]).is_none());
    }

    #[test]
    fn trailing_bytes_after_a_certificate_are_refused() {
        let mut der = self_signed();
        der.push(0);
        // `X509::from_der` alone accepts the prefix; the length check is what
        // rejects it, and that is the behaviour `ParseCertificate` has.
        assert!(parse_der(&der).is_none());
    }

    #[test]
    fn a_pem_certificate_parses() {
        let der = self_signed();
        let pem = X509::from_der(&der)
            .expect("parses")
            .to_pem()
            .expect("re-encodes");
        let parsed = parse_pem_or_der(&pem).expect("parses the PEM");
        assert_eq!(encode_der(&parsed).as_deref(), Some(der.as_slice()));
    }

    #[test]
    fn a_chain_keeps_leaf_first_order() {
        let leaf = self_signed();
        let issuer = self_signed();
        let snapshot =
            Snapshot::from_leaf_der_and_issuers(leaf.clone(), std::slice::from_ref(&issuer))
                .expect("snapshot");
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot.der_at(0), Some(leaf.as_slice()));
        assert_eq!(snapshot.der_at(1), Some(issuer.as_slice()));
        assert!(snapshot.parse(0).is_some());
        assert!(snapshot.parse(2).is_none());
    }

    #[test]
    fn issuers_start_skips_the_entries_the_caller_already_has() {
        // The peer chain puts the leaf at index 0 on the client and not on the
        // server, which is why `issuers_start` exists.
        let leaf = self_signed();
        let first = self_signed();
        let second = self_signed();
        let leaf_x509 = parse_der(&leaf).expect("parses");
        let snapshot =
            Snapshot::from_leaf_and_issuers(&leaf_x509, &[first.clone(), second.clone()], 1)
                .expect("snapshot");
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot.der_at(0), Some(leaf.as_slice()));
        assert_eq!(snapshot.der_at(1), Some(second.as_slice()));
    }
}
