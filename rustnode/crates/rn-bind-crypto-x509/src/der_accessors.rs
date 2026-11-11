//! The byte- and OID-level accessors: `raw`, `tbs`, `serialNumber`,
//! `fingerprint*`, `signatureAlgorithm*`, `version`, `keyUsage`.
//!
//! Every one of these reads the **snapshot DER** or a live reparse of it; none
//! keeps state.

use openssl::hash::MessageDigest;
use openssl::x509::X509;
use openssl_sys as ffi;

use crate::alt_names::object_text;

extern "C" {
    fn X509_get_serialNumber(certificate: *mut ffi::X509) -> *mut ffi::ASN1_INTEGER;
    fn ASN1_INTEGER_to_BN(
        value: *const ffi::ASN1_INTEGER,
        bn: *mut ffi::BIGNUM,
    ) -> *mut ffi::BIGNUM;
    fn BN_bn2hex(value: *const ffi::BIGNUM) -> *mut std::ffi::c_char;
    fn BN_free(value: *mut ffi::BIGNUM);
    fn X509_get_signature_nid(certificate: *const ffi::X509) -> std::ffi::c_int;
    fn OBJ_nid2ln(nid: std::ffi::c_int) -> *const std::ffi::c_char;
    fn X509_get0_signature(
        signature: *mut *const ffi::ASN1_BIT_STRING,
        algorithm: *mut *const ffi::X509_ALGOR,
        certificate: *const ffi::X509,
    );
    fn X509_get_ext_d2i(
        certificate: *mut ffi::X509,
        nid: std::ffi::c_int,
        critical: *mut std::ffi::c_int,
        index: *mut std::ffi::c_int,
    ) -> *mut std::ffi::c_void;
    fn OPENSSL_sk_num(stack: *const std::ffi::c_void) -> std::ffi::c_int;
    fn OPENSSL_sk_value(
        stack: *const std::ffi::c_void,
        index: std::ffi::c_int,
    ) -> *mut std::ffi::c_void;
    fn OPENSSL_sk_pop_free(
        stack: *mut std::ffi::c_void,
        free: unsafe extern "C" fn(*mut std::ffi::c_void),
    );
    fn ASN1_OBJECT_free(object: *mut ffi::ASN1_OBJECT);
    fn ASN1_STRING_length(value: *const ffi::ASN1_STRING) -> std::ffi::c_int;
    fn ASN1_STRING_get0_data(value: *const ffi::ASN1_STRING) -> *const std::ffi::c_uchar;
    fn ASN1_STRING_type(value: *const ffi::ASN1_STRING) -> std::ffi::c_int;
    fn ASN1_get_object(
        pointer: *mut *const std::ffi::c_uchar,
        length: *mut std::ffi::c_long,
        tag: *mut std::ffi::c_int,
        tag_class: *mut std::ffi::c_int,
        max: std::ffi::c_long,
    ) -> std::ffi::c_int;
}

/// `V_ASN1_BIT_STRING`.
const V_ASN1_BIT_STRING: i32 = 3;
/// `V_ASN1_SEQUENCE`, `V_ASN1_UNIVERSAL`, `V_ASN1_CONSTRUCTED`.
const V_ASN1_SEQUENCE: i32 = 16;
const V_ASN1_UNIVERSAL: i32 = 0;
const V_ASN1_CONSTRUCTED: i32 = 0x20;

/// `X509_get_signature_nid`'s long name: `"sha256WithRSAEncryption"`.
pub fn signature_algorithm(certificate: &X509) -> Option<String> {
    use foreign_types::ForeignType;
    // SAFETY: reads the certificate only.
    let nid = unsafe { X509_get_signature_nid(certificate.as_ptr()) };
    if nid == ffi::NID_undef {
        return None;
    }
    // SAFETY: the returned name is a static string owned by OpenSSL.
    let name = unsafe { OBJ_nid2ln(nid) };
    if name.is_null() {
        return None;
    }
    // SAFETY: `OBJ_nid2ln` returned a NUL-terminated static string.
    unsafe { std::ffi::CStr::from_ptr(name) }
        .to_str()
        .ok()
        .map(str::to_string)
}

/// The signature algorithm's OID in dotted form, e.g. `1.2.840.113549.1.1.11`.
pub fn signature_algorithm_oid(certificate: &X509) -> Option<String> {
    signature_identifier(certificate).map(|(oid, _)| oid)
}

/// The serial number, upper-cased hex.
///
/// `BignumPointer::toHex` produces `toUpper(BN_bn2hex(serial))`, so a serial of
/// zero is `"0"` rather than an empty string, and the letters are upper case.
pub fn serial_number(certificate: &X509) -> Option<String> {
    use foreign_types::ForeignType;
    // SAFETY: the certificate is live for the call, and `toUpper` needs no
    // mutable access beyond the cast Node makes for the same reason.
    unsafe {
        let serial = X509_get_serialNumber(certificate.as_ptr() as *mut ffi::X509);
        if serial.is_null() {
            return None;
        }
        let bn = ASN1_INTEGER_to_BN(serial, std::ptr::null_mut());
        if bn.is_null() {
            return None;
        }
        let hex = BN_bn2hex(bn);
        let text = if hex.is_null() {
            None
        } else {
            let value = std::ffi::CStr::from_ptr(hex).to_str().ok().map(|text| {
                // `ToUpper` is applied to the hex digits only; the string is
                // ASCII either way.
                text.to_ascii_uppercase()
            });
            ffi::OPENSSL_free(hex.cast());
            value
        };
        BN_free(bn);
        text
    }
}

/// `X509_digest` in the `AA:BB:…` form the fingerprints use.
pub fn fingerprint(certificate: &X509, digest: MessageDigest) -> Option<String> {
    let raw = certificate.digest(digest).ok()?;
    let bytes = raw.as_ref();
    if bytes.is_empty() {
        return None;
    }
    let mut text = String::with_capacity(bytes.len() * 3 - 1);
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            text.push(':');
        }
        text.push_str(&format!("{byte:02X}"));
    }
    Some(text)
}

/// `X509_get_version` plus one, which is how the X.509 version is reported.
///
/// `None` for a version outside 0..=2, which `getVersion` treats as "leave the
/// property unset".
pub fn version(certificate: &X509) -> Option<i32> {
    let raw = certificate.version();
    if !(0..=2).contains(&raw) {
        return None;
    }
    Some(raw + 1)
}

/// The extended-key-usage OIDs, dotted, in the order the extension lists them.
///
/// `None` when the extension is absent, which the binding reports as
/// `undefined`. `enumUsages` returns `false` for an absent extension and for one
/// it cannot decode; both become `None` here because `undefined` is what the
/// JavaScript reads either way.
pub fn key_usage(certificate: &X509) -> Option<Vec<String>> {
    use foreign_types::ForeignType;
    // SAFETY: decodes into a freshly allocated `STACK_OF(ASN1_OBJECT)` that is
    // released below, and reads only the certificate.
    unsafe {
        let stack = X509_get_ext_d2i(
            certificate.as_ptr() as *mut ffi::X509,
            ffi::NID_ext_key_usage,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if stack.is_null() {
            return None;
        }
        let count = OPENSSL_sk_num(stack);
        let mut usages = Vec::new();
        let mut ok = true;
        for index in 0..count {
            let object = OPENSSL_sk_value(stack, index) as *const ffi::ASN1_OBJECT;
            match object_text(object, true) {
                Some(text) => usages.push(text),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        // The elements are `ASN1_OBJECT`s, so the destructor is `ASN1_OBJECT_free`.
        OPENSSL_sk_pop_free(
            stack,
            std::mem::transmute::<
                unsafe extern "C" fn(*mut ffi::ASN1_OBJECT),
                unsafe extern "C" fn(*mut std::ffi::c_void),
            >(ASN1_OBJECT_free),
        );
        ok.then_some(usages)
    }
}

/// The exact `TBSCertificate` bytes of a DER certificate.
///
/// Read from the encoded bytes rather than re-encoded, because the signature
/// covers the certificate as it was received: a re-encode can normalise a
/// non-minimal length or reorder a `SET`, which would change the bytes the
/// signature applies to.
///
/// The walk is `GetExactTbs`: read the outer `SEQUENCE`, require it to consume
/// the whole input, then read the first element of its content.
pub fn exact_tbs(certificate: &[u8]) -> Option<Vec<u8>> {
    let outer = read_sequence(certificate)?;
    if outer.encoded_len != certificate.len() {
        return None;
    }
    let inner =
        read_sequence(&certificate[outer.content_start..outer.content_start + outer.content_len])?;
    let start = outer.content_start + inner.encoded_start;
    Some(certificate[start..start + inner.encoded_len].to_vec())
}

/// One `SEQUENCE`, as offsets into the input.
#[derive(Debug)]
struct Sequence {
    /// Where the encoded element starts, relative to the input.
    encoded_start: usize,
    /// How many bytes the encoded element occupies, header included.
    encoded_len: usize,
    /// Where the content starts, relative to the input.
    content_start: usize,
    /// How many content bytes there are.
    content_len: usize,
}

/// `ReadSequence`: one definite-length constructed `SEQUENCE`.
fn read_sequence(input: &[u8]) -> Option<Sequence> {
    if input.is_empty() || input.len() > i64::MAX as usize {
        return None;
    }
    let mut content = input.as_ptr();
    let mut content_length: std::ffi::c_long = 0;
    let mut tag: std::ffi::c_int = 0;
    let mut tag_class: std::ffi::c_int = 0;
    // SAFETY: `content` points into `input`, and `input.len()` is the maximum the
    // call may read.
    let flags = unsafe {
        ASN1_get_object(
            &mut content,
            &mut content_length,
            &mut tag,
            &mut tag_class,
            input.len() as std::ffi::c_long,
        )
    };
    const INDEFINITE_LENGTH: std::ffi::c_int = 0x01;
    const DECODE_ERROR: std::ffi::c_int = 0x80;
    if (flags & (INDEFINITE_LENGTH | DECODE_ERROR)) != 0
        || (flags & V_ASN1_CONSTRUCTED) == 0
        || tag != V_ASN1_SEQUENCE
        || tag_class != V_ASN1_UNIVERSAL
        || content_length < 0
    {
        return None;
    }
    let header_length = content as usize - input.as_ptr() as usize;
    let length = content_length as usize;
    if header_length > input.len() || length > input.len() - header_length {
        return None;
    }
    Some(Sequence {
        encoded_start: 0,
        encoded_len: header_length + length,
        content_start: header_length,
        content_len: length,
    })
}

/// The raw bytes of a certificate's signature value.
///
/// `None` when the signature is not a well-formed `BIT STRING` with no unused
/// bits, which is what `CreateSignature` rejects.
pub fn signature_bytes(certificate: &X509) -> Option<Vec<u8>> {
    use foreign_types::ForeignType;
    let mut signature: *const ffi::ASN1_BIT_STRING = std::ptr::null();
    // SAFETY: the certificate is live and both out-parameters accept null.
    unsafe { X509_get0_signature(&mut signature, std::ptr::null_mut(), certificate.as_ptr()) };
    if signature.is_null() {
        return None;
    }
    // SAFETY: `signature` is borrowed from the certificate.
    unsafe {
        // `ASN1_BIT_STRING` is an `ASN1_STRING`, so the string accessors take the
        // pointer once it is cast; the type check is what proves the cast is
        // valid, which is the order `CreateSignature` uses.
        let generic = signature.cast::<ffi::ASN1_STRING>();
        if ASN1_STRING_type(generic) != V_ASN1_BIT_STRING {
            return None;
        }
        let length = ASN1_STRING_length(generic);
        let data = ASN1_STRING_get0_data(generic);
        if length < 0 || (length > 0 && data.is_null()) {
            return None;
        }
        if length == 0 {
            return Some(Vec::new());
        }
        Some(std::slice::from_raw_parts(data, length as usize).to_vec())
    }
}

/// The signature algorithm identifier and the signature value together.
pub fn signature_identifier(certificate: &X509) -> Option<(String, Option<Vec<u8>>)> {
    use foreign_types::ForeignType;
    let mut algorithm: *const ffi::X509_ALGOR = std::ptr::null();
    // SAFETY: reads the certificate.
    unsafe { X509_get0_signature(std::ptr::null_mut(), &mut algorithm, certificate.as_ptr()) };
    if algorithm.is_null() {
        return None;
    }
    // SAFETY: `algorithm` is borrowed from the certificate for this call.
    crate::alt_names::algorithm_identifier(algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(cn: &str, serial: u32) -> X509 {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::X509Name;

        let key = PKey::from_rsa(Rsa::generate(2048).expect("RSA")).expect("pkey");
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
            .set_not_after(&Asn1Time::days_from_now(1).expect("notAfter"))
            .expect("notAfter");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        builder.build()
    }

    #[test]
    fn the_serial_number_is_upper_case_hex() {
        let certificate = self_signed("serial", 0xDEAD_BEEF);
        assert_eq!(serial_number(&certificate).as_deref(), Some("DEADBEEF"));
    }

    #[test]
    fn a_sha256_signature_reports_the_long_name_and_the_oid() {
        // `OBJ_nid2ln` for `sha256WithRSAEncryption`, and the OID
        // `1.2.840.113549.1.1.11`. Both are asserted by
        // `test-crypto-x509.js`, so a NID mix-up cannot pass here.
        let certificate = self_signed("sig", 1);
        assert_eq!(
            signature_algorithm(&certificate).as_deref(),
            Some("sha256WithRSAEncryption")
        );
        assert_eq!(
            signature_algorithm_oid(&certificate).as_deref(),
            Some("1.2.840.113549.1.1.11")
        );
    }

    #[test]
    fn the_version_is_one_based() {
        // The builder was given version 2 (v3), and the reported value is 3.
        let certificate = self_signed("version", 1);
        assert_eq!(version(&certificate), Some(3));
    }

    #[test]
    fn the_fingerprint_is_colon_separated_upper_hex() {
        let certificate = self_signed("fingerprint", 1);
        let text = fingerprint(&certificate, MessageDigest::sha1()).expect("a fingerprint");
        // SHA-1 is 20 bytes, so 20 groups of two hex digits and 19 colons.
        assert_eq!(text.len(), 20 * 2 + 19);
        assert_eq!(text.matches(':').count(), 19);
        assert!(text
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == ':'));
        // The SHA-256 form is longer and independent.
        let sha256 = fingerprint(&certificate, MessageDigest::sha256()).expect("sha256");
        assert_eq!(sha256.len(), 32 * 2 + 31);
    }

    #[test]
    fn the_tbs_starts_at_the_outer_sequence_content() {
        let certificate = self_signed("tbs", 1);
        let der = certificate.to_der().expect("der");
        let tbs = exact_tbs(&der).expect("a tbs");
        // The TBS is a prefix of the certificate, after the outer header, and
        // strictly shorter than the whole thing.
        assert!(tbs.len() < der.len());
        assert!(der
            .windows(tbs.len())
            .any(|window| window == tbs.as_slice()));
        // Its first byte is the `SEQUENCE` tag of the TBS itself.
        assert_eq!(tbs[0], 0x30);
    }

    #[test]
    fn trailing_bytes_make_the_tbs_unavailable() {
        // `GetExactTbs` requires the outer sequence to consume the whole input,
        // so a certificate with junk appended has no exact TBS.
        let certificate = self_signed("tbs", 1);
        let mut der = certificate.to_der().expect("der");
        der.push(0);
        assert!(exact_tbs(&der).is_none());
    }

    #[test]
    fn an_absent_key_usage_extension_is_none() {
        assert!(key_usage(&self_signed("usage", 1)).is_none());
    }

    #[test]
    fn the_signature_bytes_are_the_bit_string_payload() {
        let certificate = self_signed("signature", 1);
        let bytes = signature_bytes(&certificate).expect("a signature");
        // RSA-2048 produces a 256-byte signature.
        assert_eq!(bytes.len(), 256);
    }
}
