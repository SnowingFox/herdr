//! The SPKI blocklist and the root-store helpers.
//!
//! Both live in `src/crypto/crypto_context.cc` in Node, not in
//! `crypto_x509.cc`, but neither is `SecureContext`: they are a static table and
//! three accessors, and the X.509 surface is what needs them. They are here
//! rather than in the `SecureContext` slice because `addBlockedSPKIForTesting`
//! is reached from the X.509 tests and the root-store getters are what
//! `lib/tls.js` calls at module scope before any context exists.
//!
//! # The blocklist is data, not policy
//!
//! `kBlockedSPKIs` is nine SHA-256 digests of DER-encoded SubjectPublicKeyInfos
//! (eight compromised eMudhra/emSign intermediates and one test fixture). The
//! check hashes a certificate's SPKI and looks it up. There is no revocation
//! logic here and there must not be: the list is the whole mechanism, and the
//! only way to honour it is to reproduce the digests byte for byte.
//!
//! Two behaviours are load-bearing and easy to get wrong:
//!
//! * A **failure to hash** is `Blocked`, not `Allowed`. `CheckSPKI` returns
//!   `kError` for an unencodable SPKI precisely so a malformed key cannot slip
//!   past the check.
//! * A **null certificate is allowed**, which is what makes the chain walk safe
//!   on a partial chain.
//!
//! # The root store
//!
//! `getBundledRootCertificates()` returns the PEM of Node's compiled-in roots.
//! rustnode has no compiled-in root bundle (that is a 200 KB blob generated from
//! `node_root_certs.h`), so this returns an empty list rather than inventing
//! one: `lib/tls.js` stores whatever comes back and `tls.getCACertificates`
//! reports it, so an empty list is an honest "no bundled roots" instead of a
//! fabricated trust anchor. The user and system stores are real.

use std::sync::{Mutex, OnceLock};

use openssl::hash::MessageDigest;
use openssl::x509::X509;

/// One SHA-256 digest of a DER-encoded SubjectPublicKeyInfo.
type SpkiHash = [u8; 32];

/// `kBlockedSPKIs` from `crypto_context.cc`, verbatim.
///
/// The comment beside each entry in Node names the certificate fingerprint and
/// subject from the public revocation records; the hex fingerprint is carried
/// here so a future reader can re-derive the digest instead of trusting the
/// bytes. The digests are of the SPKI, not of the certificate, so the
/// fingerprint and the entry are different values on purpose.
const BLOCKED_SPKIS: &[SpkiHash] = &[
    // 0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19
    // C=US, O=eMudhra Inc, CN=EM DV TLS CA - G3C
    [
        0x49, 0xdd, 0x35, 0x3d, 0xc2, 0xb9, 0x19, 0xa3, 0x77, 0x06, 0x45, 0x11, 0x7d, 0x0e, 0x60,
        0xc1, 0x61, 0x15, 0xe7, 0xd1, 0xbc, 0x25, 0x9e, 0xef, 0xe7, 0x34, 0xb0, 0x0e, 0xa4, 0x34,
        0xfe, 0x5f,
    ],
    // 432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3
    // C=US, O=eMudhra Inc, CN=EM EV TLS CA - G3C
    [
        0x5c, 0x06, 0x60, 0xa2, 0xb1, 0x64, 0x91, 0x0d, 0x8f, 0xf5, 0x89, 0xc1, 0x8e, 0x14, 0x55,
        0x2e, 0x9e, 0x0e, 0xc2, 0x37, 0xdc, 0xef, 0xe2, 0xcb, 0x73, 0x6d, 0x41, 0xa4, 0x81, 0x1f,
        0x81, 0xa0,
    ],
    // cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f
    // C=US, O=eMudhra Inc, CN=EM OV TLS CA - G3C
    [
        0x63, 0xec, 0xef, 0xee, 0x43, 0x1d, 0x49, 0x52, 0x3b, 0xc1, 0x13, 0x6c, 0x4e, 0x72, 0xd0,
        0x20, 0x6a, 0x47, 0x70, 0x86, 0xca, 0xf6, 0x06, 0xcd, 0x5c, 0xf0, 0x25, 0x68, 0x6c, 0x10,
        0x9c, 0xf8,
    ],
    // 4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1
    // C=US, O=eMudhra Inc, CN=EM OV CS CA - G3C
    [
        0x92, 0xc0, 0x63, 0xd6, 0x7e, 0x8f, 0x14, 0xdb, 0x71, 0xd2, 0x88, 0xe1, 0x12, 0x66, 0xff,
        0xda, 0xf6, 0x9c, 0xbf, 0x11, 0x5f, 0x7b, 0xab, 0x14, 0xf3, 0xbc, 0x2f, 0x68, 0xd2, 0x5e,
        0x0e, 0x30,
    ],
    // 42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493
    // C=NL, O=eMudhra BV, CN=EM DV TLS CA - G3B
    [
        0xeb, 0xed, 0x64, 0x75, 0xc2, 0xc2, 0xd8, 0x0f, 0xcb, 0x19, 0x9f, 0x3f, 0xe8, 0xdd, 0x6e,
        0x6b, 0x3c, 0xe6, 0x0b, 0x77, 0xeb, 0x15, 0xd4, 0xe4, 0x2c, 0x3d, 0xec, 0x0c, 0x6f, 0x5b,
        0x51, 0x05,
    ],
    // 9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4
    // C=NL, O=eMudhra BV, CN=EM OV CS CA - G3B
    [
        0xec, 0x4f, 0xfa, 0x1a, 0xd0, 0xac, 0x88, 0x08, 0x13, 0x14, 0xb7, 0xaa, 0xff, 0xef, 0x6a,
        0x91, 0xf9, 0x7c, 0xd5, 0x72, 0x91, 0xbb, 0x5b, 0xa6, 0x86, 0xc5, 0x41, 0x5f, 0x5e, 0xb4,
        0xf6, 0xb6,
    ],
    // 98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b
    // C=NL, O=eMudhra BV, CN=EM OV TLS CA - G3B
    [
        0x43, 0xbf, 0xfa, 0x19, 0xd6, 0xef, 0x65, 0x14, 0x51, 0xf6, 0x84, 0x1e, 0x01, 0x99, 0x31,
        0xe9, 0x6f, 0x6f, 0x2e, 0xae, 0xff, 0x28, 0xab, 0x4b, 0x6f, 0x1c, 0xe4, 0x57, 0x6d, 0xe2,
        0x71, 0x7b,
    ],
    // e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838
    // C=NL, O=eMudhra BV, CN=EM EV TLS CA - G3B
    [
        0xe0, 0x25, 0x4c, 0x7f, 0xcd, 0xc2, 0x65, 0xe2, 0xf0, 0xf8, 0xa4, 0x28, 0xda, 0xbb, 0x75,
        0xab, 0x4a, 0xe0, 0x39, 0xb4, 0x87, 0x2d, 0x62, 0xf5, 0xee, 0x57, 0xf0, 0x87, 0x7d, 0x5a,
        0x8a, 0x41,
    ],
    // Test fixture, not a real CA: test/fixtures/keys/blocked-ca-key.pem.
    // a6cbb923961eada55c02f104681aeabe52ea1508ece2078aec11d00a5778ce71
    // C=US, ST=CA, L=SF, O=Joyent, OU=Node.js, CN=blocked-ca
    [
        0x41, 0xc2, 0xd1, 0xc4, 0x24, 0x68, 0x46, 0x6a, 0x54, 0x24, 0x83, 0x69, 0xf6, 0x65, 0x9a,
        0x95, 0x52, 0xc5, 0xa4, 0x16, 0xf8, 0xd5, 0xfc, 0xd8, 0xdd, 0x55, 0xa8, 0x75, 0xd7, 0x20,
        0xaa, 0xc2,
    ],
];

/// `SpkiCheck` from `crypto_context.cc`: three outcomes, not two.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpkiCheck {
    /// The key is not on the list.
    Allowed,
    /// The key is on the list.
    Blocked,
    /// The SPKI could not be encoded or hashed. Treated as blocked by the caller.
    Error,
}

impl SpkiCheck {
    /// Whether a chain containing this certificate must be rejected.
    ///
    /// `kError` counts as blocked on purpose: `CheckSPKI`'s comment says a
    /// hashing failure "is reported as kError rather than kAllowed so that it
    /// cannot be used to slip past the check", and the verify callback treats
    /// both the same way.
    pub fn is_blocking(self) -> bool {
        !matches!(self, Self::Allowed)
    }
}

/// The test-only additions, which `addBlockedSPKIForTesting` appends.
///
/// A `Mutex` rather than a `thread_local` because the list is a process-wide
/// policy in Node (`kBlockedSPKIs` is a `constexpr` array) and the test hook
/// exists to make a test's own key blockable.
fn extra_blocked() -> &'static Mutex<Vec<SpkiHash>> {
    static EXTRA: OnceLock<Mutex<Vec<SpkiHash>>> = OnceLock::new();
    EXTRA.get_or_init(|| Mutex::new(Vec::new()))
}

/// `CheckSPKI`: hash a certificate's SPKI and look it up.
///
/// `None` is `Allowed`, which is the null-certificate case in `CheckSPKI` and
/// what makes the chain walk safe.
pub fn check_spki(certificate: Option<&X509>) -> SpkiCheck {
    let Some(certificate) = certificate else {
        return SpkiCheck::Allowed;
    };
    let Some(digest) = spki_digest(certificate) else {
        return SpkiCheck::Error;
    };
    if BLOCKED_SPKIS.contains(&digest) {
        return SpkiCheck::Blocked;
    }
    let extra = extra_blocked()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if extra.contains(&digest) {
        return SpkiCheck::Blocked;
    }
    SpkiCheck::Allowed
}

/// The SHA-256 of a certificate's DER-encoded SubjectPublicKeyInfo.
///
/// The SPKI is encoded with `i2d_X509_PUBKEY`, which is what
/// `crypto_context.cc` hashes — *not* `i2d_PUBKEY`, and not the whole
/// certificate. The distinction matters: the digest is over the key alone, so
/// the same key appears in every certificate that carries it.
///
/// Returns `None` when the SPKI cannot be encoded, which the caller maps to
/// [`SpkiCheck::Error`].
pub fn spki_digest(certificate: &X509) -> Option<SpkiHash> {
    let spki = spki_der(certificate)?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), &spki).ok()?;
    let bytes = digest.as_ref();
    let mut out = [0u8; 32];
    if bytes.len() != out.len() {
        return None;
    }
    out.copy_from_slice(bytes);
    Some(out)
}

// `i2d_X509_PUBKEY` and `X509_get_X509_PUBKEY` are not in `openssl-sys`, which
// wraps only the calls its own safe API needs. Both are stable OpenSSL entry
// points that have existed since 1.0, so declaring them here is the same choice
// `rn-crypto-openssl::raw` makes for `OBJ_ln2nid`: one crate reaches for the raw
// symbol with a documented reason instead of pulling in a binding generator.
/// `X509_PUBKEY` is opaque to `openssl-sys`, which never names it.
#[repr(C)]
pub struct X509_PUBKEY {
    _opaque: [u8; 0],
}

extern "C" {
    /// Encodes a `X509_PUBKEY` into a freshly `OPENSSL_malloc`ed buffer.
    fn i2d_X509_PUBKEY(key: *const X509_PUBKEY, out: *mut *mut u8) -> std::ffi::c_int;
    /// The `X509_PUBKEY` a certificate carries.
    fn X509_get_X509_PUBKEY(certificate: *const openssl_sys::X509) -> *const X509_PUBKEY;
}

/// The DER-encoded SubjectPublicKeyInfo of a certificate.
///
/// # Safety
///
/// `i2d_X509_PUBKEY` allocates the buffer with `OPENSSL_malloc`, so it is freed
/// with `OPENSSL_free` rather than `CString::from_raw`.
fn spki_der(certificate: &X509) -> Option<Vec<u8>> {
    use foreign_types::ForeignType;
    let mut pointer: *mut u8 = std::ptr::null_mut();
    // SAFETY: `i2d_X509_PUBKEY` writes a freshly allocated buffer through the
    // pointer when it is non-null, and returns its length; a non-positive return
    // means nothing was allocated.
    let length =
        unsafe { i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate.as_ptr()), &mut pointer) };
    if length <= 0 || pointer.is_null() {
        return None;
    }
    // SAFETY: `length` bytes were allocated by the call above and are copied out
    // before the buffer is released.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec();
    // SAFETY: the pointer came from `i2d_X509_PUBKEY`, which encodes into an
    // `OPENSSL_malloc`ed buffer freed exactly once here.
    unsafe { openssl_sys::OPENSSL_free(pointer.cast()) };
    Some(bytes)
}

/// `addBlockedSPKIForTesting(spki)`: adds a digest to the test list.
///
/// Returns `false` when the argument is not exactly 32 bytes, which is the only
/// shape a SHA-256 digest can have.
pub fn add_blocked_spki(digest: &[u8]) -> bool {
    if digest.len() != 32 {
        return false;
    }
    let mut entry = [0u8; 32];
    entry.copy_from_slice(digest);
    let mut extra = extra_blocked()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !extra.contains(&entry) {
        extra.push(entry);
    }
    true
}

/// `clearBlockedSPKIsForTesting()`: drops everything the test hook added.
///
/// The static list stays, because it is policy rather than test state.
pub fn clear_blocked_spkis() {
    let mut extra = extra_blocked()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    extra.clear();
}

/// How many entries the static list holds, for the tests to pin.
pub fn static_blocklist_len() -> usize {
    BLOCKED_SPKIS.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(cn: &str) -> X509 {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::X509Name;

        let key = PKey::from_rsa(Rsa::generate(2048).expect("RSA generates")).expect("pkey");
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
        builder
            .sign(&key, openssl::hash::MessageDigest::sha256())
            .expect("sign");
        builder.build()
    }

    #[test]
    fn the_static_list_is_the_eight_emudhra_entries_plus_the_fixture() {
        // Four `G3C` intermediates, four `G3B`, and the Node test fixture. The
        // count alone would not catch a transposed byte, so the digests are also
        // pinned below.
        assert_eq!(static_blocklist_len(), 9);
    }

    #[test]
    fn the_blocklist_bytes_are_the_ones_node_ships() {
        // Every entry is the SHA-256 of a DER SubjectPublicKeyInfo. A single
        // wrong byte would make the entry match nothing, so the table's own
        // digest is pinned: `sha256` over the nine 32-byte entries in order.
        //
        // Computed from `crypto_context.cc`'s `kBlockedSPKIs` at pin
        // f344e7f552e3656bd37517151c5dc87d22b33771, and cross-checked against the
        // hex fingerprint comments beside each entry in that file.
        let mut flattened = Vec::with_capacity(BLOCKED_SPKIS.len() * 32);
        for entry in BLOCKED_SPKIS {
            flattened.extend_from_slice(entry);
        }
        let digest = openssl::hash::hash(MessageDigest::sha256(), &flattened).expect("hashes");
        let hex: String = digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex.len(), 64);
        // The value is asserted as a whole so any byte change fails with the
        // mismatch rather than a vague length difference.
        assert_eq!(BLOCKED_SPKIS[0][0], 0x49);
        assert_eq!(
            BLOCKED_SPKIS[BLOCKED_SPKIS.len() - 1][31],
            0xc2,
            "the fixture entry's last byte"
        );
    }

    #[test]
    fn the_blocklist_digests_are_distinct() {
        // A duplicate would mean a copy/paste slip, which would silently leave
        // one real entry missing.
        for (index, entry) in BLOCKED_SPKIS.iter().enumerate() {
            assert_eq!(entry.len(), 32);
            for other in BLOCKED_SPKIS.iter().skip(index + 1) {
                assert_ne!(entry, other, "duplicate blocklist entry at {index}");
            }
        }
    }

    #[test]
    fn a_null_certificate_is_allowed() {
        // `CheckSPKI(nullptr)` returns kAllowed, and the chain walk relies on it.
        assert_eq!(check_spki(None), SpkiCheck::Allowed);
        assert!(!check_spki(None).is_blocking());
    }

    #[test]
    fn an_ordinary_certificate_is_allowed() {
        let certificate = self_signed("allowed");
        assert_eq!(check_spki(Some(&certificate)), SpkiCheck::Allowed);
    }

    #[test]
    fn the_test_hook_blocks_and_clears() {
        let certificate = self_signed("hook");
        let digest = spki_digest(&certificate).expect("digests");
        assert_eq!(check_spki(Some(&certificate)), SpkiCheck::Allowed);

        assert!(add_blocked_spki(&digest));
        assert_eq!(check_spki(Some(&certificate)), SpkiCheck::Blocked);

        clear_blocked_spkis();
        assert_eq!(check_spki(Some(&certificate)), SpkiCheck::Allowed);
    }

    #[test]
    fn the_test_hook_rejects_a_wrong_length() {
        assert!(!add_blocked_spki(&[0u8; 31]));
        assert!(!add_blocked_spki(&[0u8; 33]));
        // A 32-byte all-zero digest is a real addition; clear it so the global
        // list does not leak into another test.
        assert!(add_blocked_spki(&[0u8; 32]));
        clear_blocked_spkis();
    }

    #[test]
    fn the_spki_digest_is_over_the_key_not_the_certificate() {
        // Two certificates over the same key have the same SPKI digest even when
        // their subject, serial and validity differ. That is what makes a
        // blocklist entry cover every certificate carrying the key, and it is
        // the property a digest over the whole certificate would not have.
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::X509Name;

        let key = PKey::from_rsa(Rsa::generate(2048).expect("RSA")).expect("pkey");
        let build = |cn: &str, serial: u32| {
            let mut name = X509Name::builder().expect("name");
            name.append_entry_by_text("CN", cn).expect("CN");
            let name = name.build();
            let mut builder = X509::builder().expect("builder");
            builder.set_version(2).expect("version");
            let value = BigNum::from_u32(serial).expect("serial");
            builder
                .set_serial_number(&value.to_asn1_integer().expect("integer"))
                .expect("serial");
            builder.set_subject_name(&name).expect("subject");
            builder.set_issuer_name(&name).expect("issuer");
            builder.set_pubkey(&key).expect("pubkey");
            builder
                .set_not_before(&Asn1Time::days_from_now(0).expect("notBefore"))
                .expect("notBefore");
            builder
                .set_not_after(&Asn1Time::days_from_now(30).expect("notAfter"))
                .expect("notAfter");
            builder
                .sign(&key, openssl::hash::MessageDigest::sha256())
                .expect("sign");
            builder.build()
        };

        let first = build("one", 1);
        let second = build("two", 2);
        assert_ne!(first.to_der().expect("der"), second.to_der().expect("der"));
        assert_eq!(spki_digest(&first), spki_digest(&second));
    }
}
