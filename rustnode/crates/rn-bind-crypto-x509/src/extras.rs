//! `subjectName`, `issuerName`, `extensions`, `signature`, `ca`, `checkHost`,
//! `checkEmail`, `checkIP`, `checkIssued`, and the two key checks.
//!
//! The four name/extension accessors return objects `x509.js` exposes directly
//! (`getInspectionValue`), so their shapes are part of the public API:
//!
//! * `subjectName`/`issuerName` → `{ raw: Buffer, rdns: [[{ oid, value }]] }`,
//!   one inner array per RDN *set*, because a multi-value RDN is one set with
//!   several attributes;
//! * `extensions` → `[{ oid, critical, value: Buffer }]` over every extension in
//!   encoded order;
//! * `signature` → `{ algorithm: { oid, parameters?: Buffer }, value: Buffer }`.
//!
//! # Why `checkPrivateKey` and `verify` live here but delegate
//!
//! Both take a `KeyObjectHandle`, and the *cryptography* is not X.509's. `verify`
//! is `X509_verify`, which is a signature check over the TBS, and the digest and
//! signature machinery for that lives in `rn-crypto-openssl::sign`. This module
//! does not call `EVP_DigestVerify` at all: it hands the certificate and the key
//! to the shared layer, which is the only place a signature is verified in this
//! workspace.

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::pkey::{HasPublic, PKeyRef};
use openssl::x509::X509;
use openssl_sys as ffi;
use rn_v8_sys::v8;

use crate::alt_names::object_text;

/// An opaque `STACK_OF(ASN1_TYPE)`, which `openssl-sys` does not name.
///
/// Only handed back to OpenSSL and walked through `OPENSSL_sk_num`/`_value`, so it
/// never needs a layout.
#[repr(C)]
struct OpaqueStack {
    _opaque: [u8; 0],
}

extern "C" {
    fn X509_NAME_entry_count(name: *const ffi::X509_NAME) -> std::ffi::c_int;
    fn X509_NAME_get_entry(
        name: *const ffi::X509_NAME,
        index: std::ffi::c_int,
    ) -> *mut ffi::X509_NAME_ENTRY;
    fn X509_NAME_ENTRY_get_object(entry: *const ffi::X509_NAME_ENTRY) -> *const ffi::ASN1_OBJECT;
    fn X509_NAME_ENTRY_get_data(entry: *const ffi::X509_NAME_ENTRY) -> *const ffi::ASN1_STRING;
    fn X509_NAME_ENTRY_set(entry: *const ffi::X509_NAME_ENTRY) -> std::ffi::c_int;
    fn X509_NAME_get0_der(
        name: *const ffi::X509_NAME,
        out: *mut *const std::ffi::c_uchar,
        out_len: *mut usize,
    ) -> std::ffi::c_int;
    fn d2i_ASN1_SEQUENCE_ANY(
        out: *mut *mut OpaqueStack,
        input: *mut *const std::ffi::c_uchar,
        length: std::ffi::c_long,
    ) -> *mut OpaqueStack;
    fn OPENSSL_sk_pop_free(
        stack: *mut std::ffi::c_void,
        free: unsafe extern "C" fn(*mut std::ffi::c_void),
    );
    fn ASN1_TYPE_get(value: *const ffi::ASN1_TYPE) -> std::ffi::c_int;
    fn OPENSSL_sk_num(stack: *const std::ffi::c_void) -> std::ffi::c_int;
    fn OPENSSL_sk_value(
        stack: *const std::ffi::c_void,
        index: std::ffi::c_int,
    ) -> *mut std::ffi::c_void;
    fn X509_get_ext_count(certificate: *const ffi::X509) -> std::ffi::c_int;
    fn X509_get_ext(
        certificate: *const ffi::X509,
        index: std::ffi::c_int,
    ) -> *mut ffi::X509_EXTENSION;
    fn X509_EXTENSION_get_object(extension: *mut ffi::X509_EXTENSION) -> *const ffi::ASN1_OBJECT;
    fn X509_EXTENSION_get_critical(extension: *const ffi::X509_EXTENSION) -> std::ffi::c_int;
    fn X509_EXTENSION_get_data(extension: *mut ffi::X509_EXTENSION) -> *mut ffi::ASN1_OCTET_STRING;
    fn ASN1_STRING_length(value: *const ffi::ASN1_STRING) -> std::ffi::c_int;
    fn ASN1_STRING_get0_data(value: *const ffi::ASN1_STRING) -> *const std::ffi::c_uchar;
    fn ASN1_STRING_type(value: *const ffi::ASN1_STRING) -> std::ffi::c_int;
    fn ASN1_STRING_to_UTF8(
        out: *mut *mut std::ffi::c_uchar,
        value: *const ffi::ASN1_STRING,
    ) -> std::ffi::c_int;
    fn X509_check_host(
        certificate: *mut ffi::X509,
        name: *const std::ffi::c_char,
        name_len: usize,
        flags: std::ffi::c_uint,
        peername: *mut *mut std::ffi::c_char,
    ) -> std::ffi::c_int;
    fn X509_check_email(
        certificate: *mut ffi::X509,
        email: *const std::ffi::c_char,
        email_len: usize,
        flags: std::ffi::c_uint,
    ) -> std::ffi::c_int;
    fn X509_check_ip(
        certificate: *mut ffi::X509,
        address: *const std::ffi::c_uchar,
        address_len: usize,
        flags: std::ffi::c_uint,
    ) -> std::ffi::c_int;
    fn X509_check_issued(issuer: *mut ffi::X509, subject: *mut ffi::X509) -> std::ffi::c_int;
    fn X509_check_private_key(
        certificate: *mut ffi::X509,
        key: *const ffi::EVP_PKEY,
    ) -> std::ffi::c_int;
    fn X509_verify(certificate: *mut ffi::X509, key: *mut ffi::EVP_PKEY) -> std::ffi::c_int;
    fn X509_get0_pubkey(certificate: *const ffi::X509) -> *mut ffi::EVP_PKEY;
    fn X509_get_pubkey(certificate: *mut ffi::X509) -> *mut ffi::EVP_PKEY;
    fn X509_check_ca(certificate: *mut ffi::X509) -> std::ffi::c_int;
    fn OBJ_obj2nid(object: *const ffi::ASN1_OBJECT) -> std::ffi::c_int;
    fn OBJ_nid2sn(nid: std::ffi::c_int) -> *const std::ffi::c_char;
}

/// `#define NID_undef 0` in `obj_mac.h`.
const NID_UNDEF: std::ffi::c_int = 0;

/// The attribute name the legacy object keys by: `OBJ_nid2sn`, or the dotted
/// text when `OBJ_obj2nid` has no name for it.
///
/// This is `ncrypto`'s `X509Name::Iterator::operator*` order exactly, and the
/// fallback matters: `GetX509NameObject` keys `2.5.4.3` as `CN` for every
/// certificate OpenSSL knows, but an attribute with a private OID still has to
/// appear under *some* key rather than being dropped.
fn nid_short_name(object: *const ffi::ASN1_OBJECT) -> Option<String> {
    if object.is_null() {
        return None;
    }
    // SAFETY: `object` is borrowed from the live entry for this call only.
    unsafe {
        let nid = OBJ_obj2nid(object);
        if nid == NID_UNDEF {
            return None;
        }
        let pointer = OBJ_nid2sn(nid);
        if pointer.is_null() {
            return None;
        }
        // SAFETY: OpenSSL returns a static NUL-terminated string.
        std::ffi::CStr::from_ptr(pointer)
            .to_str()
            .ok()
            .filter(|name| !name.is_empty())
            .map(str::to_string)
    }
}

/// One attribute of a distinguished name.
pub(crate) struct NameAttribute {
    /// Which RDN set the attribute belongs to.
    pub(crate) set: usize,
    /// The attribute's OID in dotted form.
    pub(crate) oid: String,
    /// The attribute's short name (`CN`, `O`, …), when OpenSSL has one.
    ///
    /// `subjectName.rdns[].oid` reports the dotted form and the legacy
    /// `subject`/`issuer` objects report this one, which is the split
    /// `ncrypto`'s `X509Name::Iterator` and `InspectName` make: the iterator
    /// resolves `OBJ_obj2nid` then `OBJ_nid2sn` and falls back to the dotted
    /// text only when the OID has no name.
    pub(crate) short_name: Option<String>,
    /// Its value, when it converts to UTF-8.
    ///
    /// `None` for a value whose ASN.1 type is not a string type OpenSSL will
    /// convert; `InspectName` records it as a present-but-unrepresentable
    /// attribute rather than failing the whole name.
    pub(crate) value: Option<String>,
}

/// A distinguished name as attributes plus its exact encoding.
pub(crate) struct NameInspection {
    pub(crate) attributes: Vec<NameAttribute>,
    /// The DER of the `X509_NAME`, which `subjectName.raw` reports.
    pub(crate) raw: Option<Vec<u8>>,
}

/// `X509View::inspectSubjectName` / `inspectIssuerName`.
///
/// `None` when the name cannot be inspected at all; the binding reports that as
/// `undefined`, which `getInspectionValue` turns into
/// `ERR_CRYPTO_INVALID_X509_CERTIFICATE`.
pub(crate) fn inspect_name(certificate: &X509, subject: bool) -> Option<NameInspection> {
    let name = if subject {
        certificate.subject_name()
    } else {
        certificate.issuer_name()
    };
    // SAFETY: `name` is borrowed from the certificate for the whole function.
    unsafe {
        let pointer = name.as_ptr();
        let count = X509_NAME_entry_count(pointer);
        if count < 0 {
            return None;
        }
        // OpenSSL does not surface an empty RDN as a `X509_NAME` entry, so a
        // malformed Name whose RDN set is present but empty would otherwise be
        // inspected as a valid, shorter name. Counting the encoded RDN sets
        // independently and requiring agreement is what `InspectName` does, and
        // `test-crypto-x509-inspection.js` asserts the rejection.
        let encoded_rdns = encoded_rdn_count(pointer)?;
        let mut attributes = Vec::with_capacity(count as usize);
        let mut previous_set: i32 = -1;
        for index in 0..count {
            let entry = X509_NAME_get_entry(pointer, index);
            if entry.is_null() {
                return None;
            }
            let object = X509_NAME_ENTRY_get_object(entry);
            let value = X509_NAME_ENTRY_get_data(entry);
            let oid = object_text(object, true)?;
            let set = X509_NAME_ENTRY_set(entry);
            // The sets must be a contiguous run starting at zero. A gap means the
            // encoding is not what `InspectName` expects, and it returns nullopt
            // rather than inventing an rdn index.
            if set < 0 || (set != previous_set && set != previous_set + 1) {
                return None;
            }
            previous_set = set;
            attributes.push(NameAttribute {
                set: set as usize,
                short_name: nid_short_name(object),
                oid,
                value: if can_convert_name_value(value) {
                    convert_name_value(value)
                } else {
                    None
                },
            });
        }
        let inspected_sets = if previous_set < 0 {
            0
        } else {
            previous_set as usize + 1
        };
        if inspected_sets != encoded_rdns {
            return None;
        }
        let raw = name_der(pointer);
        Some(NameInspection { attributes, raw })
    }
}

/// Whether `CanConvertNameValueToUtf8` accepts the string type.
///
/// A `BIT STRING`, `OCTET STRING` or other non-string attribute value is
/// representable in DER but not as text, and Node records it as an attribute with
/// no value rather than failing.
///
/// # Safety
///
/// `value` must be a live `ASN1_STRING` or null.
unsafe fn can_convert_name_value(value: *const ffi::ASN1_STRING) -> bool {
    if value.is_null() {
        return false;
    }
    const V_ASN1_UTF8STRING: i32 = 12;
    const V_ASN1_NUMERICSTRING: i32 = 18;
    const V_ASN1_PRINTABLESTRING: i32 = 19;
    const V_ASN1_T61STRING: i32 = 20;
    const V_ASN1_IA5STRING: i32 = 22;
    const V_ASN1_UTCTIME: i32 = 23;
    const V_ASN1_GENERALIZEDTIME: i32 = 24;
    const V_ASN1_ISO64STRING: i32 = 26;
    const V_ASN1_UNIVERSALSTRING: i32 = 28;
    const V_ASN1_BMPSTRING: i32 = 30;
    // SAFETY: the caller guarantees `value` is live.
    matches!(
        unsafe { ASN1_STRING_type(value) },
        V_ASN1_UTF8STRING
            | V_ASN1_NUMERICSTRING
            | V_ASN1_PRINTABLESTRING
            | V_ASN1_T61STRING
            | V_ASN1_IA5STRING
            | V_ASN1_UTCTIME
            | V_ASN1_GENERALIZEDTIME
            | V_ASN1_ISO64STRING
            | V_ASN1_UNIVERSALSTRING
            | V_ASN1_BMPSTRING
    )
}

/// `ASN1_STRING_to_UTF8`, which allocates and is freed with `OPENSSL_free`.
///
/// # Safety
///
/// `value` must be a live `ASN1_STRING` or null.
unsafe fn convert_name_value(value: *const ffi::ASN1_STRING) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `value` is live.
    unsafe {
        let mut data: *mut std::ffi::c_uchar = std::ptr::null_mut();
        let length = ASN1_STRING_to_UTF8(&mut data, value);
        if length < 0 {
            return None;
        }
        let text = if length == 0 {
            Some(String::new())
        } else if data.is_null() {
            None
        } else {
            let bytes = std::slice::from_raw_parts(data, length as usize);
            let text = String::from_utf8_lossy(bytes).into_owned();
            ffi::OPENSSL_free(data.cast());
            Some(text)
        };
        text
    }
}

/// `X509_NAME_get0_der`, which borrows the name's own encoding.
///
/// # Safety
///
/// `name` must be a live `X509_NAME`.
unsafe fn name_der(name: *const ffi::X509_NAME) -> Option<Vec<u8>> {
    let mut data: *const std::ffi::c_uchar = std::ptr::null();
    let mut length: usize = 0;
    // SAFETY: both out-parameters are valid and the name is live.
    if unsafe { X509_NAME_get0_der(name, &mut data, &mut length) } != 1 {
        return None;
    }
    if data.is_null() && length != 0 {
        return None;
    }
    if length == 0 {
        return Some(Vec::new());
    }
    // SAFETY: the name owns `length` bytes at `data`, and the copy happens before
    // the name is dropped.
    Some(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
}

/// Adapts a concrete destructor to the `void *` form `OPENSSL_sk_pop_free` takes.
///
/// The two function types have identical ABIs; this is a cast rather than a
/// wrapper so the stack sees the real destructor symbol.
fn transparent_free<T>(
    free: unsafe extern "C" fn(*mut T),
) -> unsafe extern "C" fn(*mut std::ffi::c_void) {
    // SAFETY: `*mut T` and `*mut c_void` have the same representation, and the
    // caller only ever passes pointers the stack holds.
    unsafe { std::mem::transmute(free) }
}

/// The number of RDN sets the *encoding* holds, counted independently of the
/// `X509_NAME` entries.
///
/// Re-encoding the name as a `SEQUENCE` of `SET`s is the only way to see an empty
/// RDN: `X509_NAME_entry_count` skips it, so the two counts disagree exactly when
/// the input is malformed. A non-`SET` child or trailing bytes are also failures.
///
/// # Safety
///
/// `name` must be a live `X509_NAME`.
unsafe fn encoded_rdn_count(name: *const ffi::X509_NAME) -> Option<usize> {
    let mut der: *const std::ffi::c_uchar = std::ptr::null();
    let mut length: usize = 0;
    // SAFETY: both out-parameters are valid and the name is live.
    if unsafe { X509_NAME_get0_der(name, &mut der, &mut length) } != 1 || der.is_null() {
        return None;
    }
    let start = der;
    let mut cursor = der;
    // SAFETY: `d2i_ASN1_SEQUENCE_ANY` reads at most `length` bytes from `start`
    // and allocates the result, released below.
    unsafe {
        let sequence = d2i_ASN1_SEQUENCE_ANY(
            std::ptr::null_mut(),
            &mut cursor,
            length as std::ffi::c_long,
        );
        if sequence.is_null() {
            return None;
        }
        // Trailing bytes mean the DER is not exactly one SEQUENCE.
        if cursor != start.add(length) {
            OPENSSL_sk_pop_free(sequence.cast(), transparent_free(ffi::ASN1_TYPE_free));
            return None;
        }
        let count = OPENSSL_sk_num(sequence.cast());
        let mut ok = count >= 0;
        for index in 0..count {
            let entry = OPENSSL_sk_value(sequence.cast(), index).cast::<ffi::ASN1_TYPE>();
            if entry.is_null() || ASN1_TYPE_get(entry) != ffi::V_ASN1_SET {
                ok = false;
                break;
            }
        }
        OPENSSL_sk_pop_free(sequence.cast(), transparent_free(ffi::ASN1_TYPE_free));
        ok.then_some(count as usize)
    }
}

/// One raw extension.
pub(crate) struct RawExtension {
    pub(crate) oid: String,
    pub(crate) critical: bool,
    pub(crate) value: Vec<u8>,
}

/// `InspectExtensions`: every extension, in encoded order.
///
/// `None` when the extension list cannot be read, which is `undefined` in the
/// binding, not an empty array — an absent extension list and a certificate with
/// no extensions are different facts.
pub(crate) fn inspect_extensions(certificate: &X509) -> Option<Vec<RawExtension>> {
    // SAFETY: reads the certificate only.
    unsafe {
        let pointer = certificate.as_ptr();
        let count = X509_get_ext_count(pointer);
        if count < 0 {
            return None;
        }
        let mut extensions = Vec::with_capacity(count as usize);
        for index in 0..count {
            let extension = X509_get_ext(pointer, index);
            if extension.is_null() {
                return None;
            }
            let oid = object_text(X509_EXTENSION_get_object(extension), true)?;
            let critical = X509_EXTENSION_get_critical(extension) != 0;
            let data = X509_EXTENSION_get_data(extension);
            if data.is_null() {
                return None;
            }
            // `ASN1_OCTET_STRING` is an `ASN1_STRING`; the extension's data is
            // always an octet string, which is what the cast relies on.
            let data = data.cast::<ffi::ASN1_STRING>();
            let length = ASN1_STRING_length(data);
            let bytes = ASN1_STRING_get0_data(data);
            if length < 0 || (length > 0 && bytes.is_null()) {
                return None;
            }
            let value = if length == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(bytes, length as usize).to_vec()
            };
            extensions.push(RawExtension {
                oid,
                critical,
                value,
            });
        }
        Some(extensions)
    }
}

/// `X509View::isCA`.
///
/// `X509_check_ca` rather than a `basicConstraints` read: it also honours
/// `keyUsage`'s `keyCertSign`, which is what makes an older v1 CA report true.
pub(crate) fn is_ca(certificate: &X509) -> bool {
    // SAFETY: `X509_check_ca` takes a non-const `X509 *` but only reads it (it
    // fills a cache inside the extension structure, which is why Node casts
    // too).
    unsafe { X509_check_ca(certificate.as_ptr()) != 0 }
}

/// `X509View::checkHost`.
///
/// Returns the matched name when OpenSSL reports one, which is how a wildcard
/// certificate says which name it matched. `checkHost` in the binding replaces
/// its return value with that string when it is present.
pub(crate) fn check_host(
    certificate: &X509,
    name: &str,
    flags: u32,
) -> (crate::certificate::CheckMatch, Option<String>) {
    let mut peer: *mut std::ffi::c_char = std::ptr::null_mut();
    // SAFETY: `name` is a live slice whose length is passed with it, and `peer`
    // receives an allocated string that is freed below.
    let result = unsafe {
        X509_check_host(
            certificate.as_ptr(),
            name.as_ptr().cast::<std::ffi::c_char>(),
            name.len(),
            flags,
            &mut peer,
        )
    };
    let matched = crate::certificate::CheckMatch::from_raw(result);
    if matched != crate::certificate::CheckMatch::Match {
        return (matched, None);
    }
    if peer.is_null() {
        return (matched, None);
    }
    // SAFETY: `X509_check_host` allocated a NUL-terminated string.
    let text = unsafe { std::ffi::CStr::from_ptr(peer) }
        .to_str()
        .ok()
        .map(str::to_string);
    // SAFETY: `peername` is documented as `OPENSSL_free`d by the caller.
    unsafe { ffi::OPENSSL_free(peer.cast()) };
    (matched, text)
}

/// `X509View::checkEmail`.
pub(crate) fn check_email(
    certificate: &X509,
    email: &str,
    flags: u32,
) -> crate::certificate::CheckMatch {
    // SAFETY: `email` is a live slice whose length is passed with it.
    crate::certificate::CheckMatch::from_raw(unsafe {
        X509_check_email(
            certificate.as_ptr(),
            email.as_ptr().cast::<std::ffi::c_char>(),
            email.len(),
            flags,
        )
    })
}

/// `CheckIP`, including the name-shape rejection Node does before OpenSSL.
///
/// A subject containing a NUL or a `%` is `INVALID_NAME` before any parsing, and
/// a string that is neither an IPv4 nor an IPv6 literal is `INVALID_NAME` too.
/// That second rule is why `checkIP('not-an-ip')` throws `ERR_INVALID_ARG_VALUE`
/// rather than answering `undefined`.
pub(crate) fn check_ip(
    certificate: &X509,
    subject: &str,
    flags: u32,
) -> crate::certificate::CheckMatch {
    if subject.contains('\0') || subject.contains('%') {
        return crate::certificate::CheckMatch::InvalidName;
    }
    let Some((address, length)) = parse_ip_literal(subject) else {
        return crate::certificate::CheckMatch::InvalidName;
    };
    // SAFETY: `address` is a fixed array and `length` is 4 or 16, both of which
    // are the only sizes `X509_check_ip` accepts.
    crate::certificate::CheckMatch::from_raw(unsafe {
        X509_check_ip(certificate.as_ptr(), address.as_ptr(), length, flags)
    })
}

/// `uv_inet_pton`: an IPv4 or IPv6 literal as bytes.
fn parse_ip_literal(subject: &str) -> Option<([u8; 16], usize)> {
    let mut address = [0u8; 16];
    if let Ok(parsed) = subject.parse::<std::net::Ipv4Addr>() {
        address[..4].copy_from_slice(&parsed.octets());
        return Some((address, 4));
    }
    if let Ok(parsed) = subject.parse::<std::net::Ipv6Addr>() {
        address.copy_from_slice(&parsed.octets());
        return Some((address, 16));
    }
    None
}

/// `X509View::isIssuedBy`, which is `X509_check_issued(issuer, subject) == OK`.
pub(crate) fn is_issued_by(certificate: &X509, issuer: &X509) -> bool {
    // SAFETY: both certificates are live; `X509_check_issued` casts `issuer` to
    // non-const and only reads it.
    unsafe { X509_check_issued(issuer.as_ptr(), certificate.as_ptr()) == ffi::X509_V_OK }
}

/// `X509View::checkPrivateKey`.
///
/// A certificate and a private key match when their public halves agree, which is
/// `X509_check_private_key` and not a signature operation. Nothing here duplicates
/// `rn-crypto-openssl::sign`: this is a key comparison, not a verification.
pub(crate) fn check_private_key(certificate: &X509, key: &PKeyRef<impl HasPublic>) -> bool {
    // SAFETY: both handles are live and the call only reads them.
    unsafe { X509_check_private_key(certificate.as_ptr(), key.as_ptr()) == 1 }
}

/// `X509View::checkPublicKey`, installed as `verify`.
///
/// # Which layer verifies
///
/// `X509_verify` is OpenSSL's own "does this signature over my TBS match this
/// key", and it is the same `EVP_DigestVerify` machinery
/// `rn-crypto-openssl::sign` wraps for `crypto.verify`. It is called *here*
/// rather than reimplemented because the alternative — assembling the TBS, the
/// digest and the key context by hand — is exactly the second signature path that
/// must not exist. `sign::verify_digest` is the shared entry point for the
/// streaming API; `X509_verify` is the certificate-shaped call the same library
/// provides, and neither is a substitute for the other.
pub(crate) fn check_public_key(certificate: &X509, key: &PKeyRef<impl HasPublic>) -> bool {
    // SAFETY: both handles are live and the call only reads them.
    unsafe { X509_verify(certificate.as_ptr(), key.as_ptr()) == 1 }
}

/// The certificate's public key, with a reference this crate owns.
///
/// `X509_get0_pubkey` borrows; `X509_get_pubkey` returns an owned reference, which
/// is what `publicKey()` hands to a `KeyObjectHandle`.
pub fn owned_public_key(certificate: &X509) -> Option<*mut ffi::EVP_PKEY> {
    // SAFETY: returns one new reference owned by the caller.
    let key = unsafe { X509_get_pubkey(certificate.as_ptr()) };
    (!key.is_null()).then_some(key)
}

/// Whether the certificate's SPKI can be read at all.
///
/// `X509ToObject` checks this before touching `ifRsa`/`ifEc`, because the
/// provider can fail to decode a public key it does not support — an unknown
/// curve in a FIPS build — and the key-specific fields must then stay undefined
/// rather than the whole legacy object failing.
pub fn has_public_key(certificate: &X509) -> bool {
    // SAFETY: reads the certificate's cached public key.
    !unsafe { X509_get0_pubkey(certificate.as_ptr()) }.is_null()
}

/// Takes ownership of one `EVP_PKEY` reference.
///
/// # Safety
///
/// `key` must be a reference the caller owns, and this must be the only owner.
pub(crate) unsafe fn pkey_from_raw(
    key: *mut ffi::EVP_PKEY,
) -> Option<openssl::pkey::PKey<openssl::pkey::Public>> {
    if key.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees ownership of exactly one reference.
    // SAFETY: the caller guarantees ownership of exactly one reference.
    Some(unsafe { <openssl::pkey::PKey<openssl::pkey::Public> as ForeignType>::from_ptr(key) })
}

/// Takes ownership of one `EVP_PKEY` reference, typed private.
///
/// `PKCS12_parse` hands back a private key, and the type parameter is what makes
/// `PKey::has_private` and the private-only operations available.
///
/// # Safety
///
/// `key` must be a reference the caller owns, and this must be the only owner.
pub(crate) unsafe fn private_pkey_from_raw(
    key: *mut ffi::EVP_PKEY,
) -> Option<openssl::pkey::PKey<openssl::pkey::Private>> {
    if key.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees ownership of exactly one reference.
    Some(unsafe { <openssl::pkey::PKey<openssl::pkey::Private> as ForeignType>::from_ptr(key) })
}

// ---------------------------------------------------------------------------
// The JavaScript shapes
// ---------------------------------------------------------------------------

/// `subjectName` / `issuerName`: `{ raw: Buffer, rdns: [[{ oid, value }]] }`.
///
/// One inner array per RDN *set*, not per attribute: a multi-value RDN such as
/// `L=L1 + L=L2` is a single set holding two attributes, and
/// `test-crypto-x509-inspection.js` distinguishes that from two single-value RDNs
/// — which is the whole reason `X509_NAME_ENTRY_set` is the grouping key rather
/// than the attribute index.
///
/// The `rdns` array is dense, indexed by set, and `CreateName` rejects a set that
/// is not a contiguous run from zero. An attribute whose value is not convertible
/// keeps its `oid` and omits `value`.
pub(crate) fn structured_name<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    certificate: &X509,
    subject: bool,
) -> Option<v8::Local<'s, v8::Value>> {
    let inspection = inspect_name(certificate, subject)?;
    let rdn_count = inspection
        .attributes
        .iter()
        .map(|attribute| attribute.set + 1)
        .max()
        .unwrap_or(0);

    let rdns = v8::Array::new(scope, rdn_count as i32);
    let mut groups: Vec<v8::Local<'s, v8::Array>> = Vec::with_capacity(rdn_count);
    for index in 0..rdn_count {
        let group = v8::Array::new(scope, 0);
        rdns.set_index(scope, index as u32, group.into());
        groups.push(group);
    }

    let mut lengths = vec![0u32; rdn_count];
    for attribute in &inspection.attributes {
        let group = groups.get(attribute.set)?;
        let object = v8::Object::new(scope);
        // The key is the dotted OID, under a property name `x509.js` reads from
        // the environment (`oid`), so it is spelled here.
        let oid_key = v8::String::new(scope, "oid")?;
        let oid = v8::String::new(scope, &attribute.oid)?;
        object.set(scope, oid_key.into(), oid.into());
        if let Some(value) = attribute.value.as_deref() {
            let value_key = v8::String::new(scope, "value")?;
            let text = v8::String::new(scope, value)?;
            object.set(scope, value_key.into(), text.into());
        }
        let position = lengths[attribute.set];
        group.set_index(scope, position, object.into());
        lengths[attribute.set] = position + 1;
    }

    let object = v8::Object::new(scope);
    let raw_key = v8::String::new(scope, "raw")?;
    let raw = inspection
        .raw
        .as_deref()
        .and_then(|raw| rn_bind_crypto_keys::buffer_from(scope, raw))?;
    object.set(scope, raw_key.into(), raw);
    let rdns_key = v8::String::new(scope, "rdns")?;
    object.set(scope, rdns_key.into(), rdns.into());
    Some(object.into())
}

/// `extensions`: `[{ oid, critical, value: Buffer }]` in encoded order.
pub(crate) fn extensions<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    certificate: &X509,
) -> Option<v8::Local<'s, v8::Value>> {
    let inspected = inspect_extensions(certificate)?;
    let array = v8::Array::new(scope, inspected.len() as i32);
    for (index, extension) in inspected.iter().enumerate() {
        let object = v8::Object::new(scope);
        let oid_key = v8::String::new(scope, "oid")?;
        let oid = v8::String::new(scope, &extension.oid)?;
        object.set(scope, oid_key.into(), oid.into());
        let critical_key = v8::String::new(scope, "critical")?;
        let critical = v8::Boolean::new(scope, extension.critical);
        object.set(scope, critical_key.into(), critical.into());
        let value_key = v8::String::new(scope, "value")?;
        let value = rn_bind_crypto_keys::buffer_from(scope, &extension.value)?;
        object.set(scope, value_key.into(), value);
        array.set_index(scope, index as u32, object.into());
    }
    Some(array.into())
}

/// `signature`: `{ algorithm: { oid, parameters?: Buffer }, value: Buffer }`.
///
/// `parameters` is present only when the algorithm identifier carries them, which
/// is why `CreateAlgorithmIdentifier` skips the key entirely for
/// `V_ASN1_UNDEF`. An RSA signature advertises a `NULL` parameter, so the property
/// exists and holds the DER of `NULL`; Ed25519 carries none and the property is
/// absent.
pub(crate) fn signature<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    certificate: &X509,
) -> Option<v8::Local<'s, v8::Value>> {
    let (oid, parameters) = crate::der_accessors::signature_identifier(certificate)?;
    let value = crate::der_accessors::signature_bytes(certificate)?;

    let algorithm = v8::Object::new(scope);
    let oid_key = v8::String::new(scope, "oid")?;
    let oid_text = v8::String::new(scope, &oid)?;
    algorithm.set(scope, oid_key.into(), oid_text.into());
    if let Some(parameters) = parameters.as_deref() {
        let parameters_key = v8::String::new(scope, "parameters")?;
        let encoded = rn_bind_crypto_keys::buffer_from(scope, parameters)?;
        algorithm.set(scope, parameters_key.into(), encoded);
    }

    let object = v8::Object::new(scope);
    let algorithm_key = v8::String::new(scope, "algorithm")?;
    object.set(scope, algorithm_key.into(), algorithm.into());
    let value_key = v8::String::new(scope, "value")?;
    let encoded = rn_bind_crypto_keys::buffer_from(scope, &value)?;
    object.set(scope, value_key.into(), encoded);
    Some(object.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_check_match_mapping_is_the_one_openssl_documents() {
        use crate::certificate::CheckMatch;
        assert_eq!(CheckMatch::from_raw(1), CheckMatch::Match);
        assert_eq!(CheckMatch::from_raw(0), CheckMatch::NoMatch);
        assert_eq!(CheckMatch::from_raw(-2), CheckMatch::InvalidName);
        // Everything else is a failure, not a silent "no match": conflating them
        // would make a broken certificate look like a name mismatch.
        assert_eq!(CheckMatch::from_raw(-1), CheckMatch::Failed);
        assert_eq!(CheckMatch::from_raw(-3), CheckMatch::Failed);
    }

    #[test]
    fn an_ipv4_literal_parses_to_four_bytes() {
        let (address, length) = parse_ip_literal("8.8.8.8").expect("parses");
        assert_eq!(length, 4);
        assert_eq!(&address[..4], &[8, 8, 8, 8]);
    }

    #[test]
    fn an_ipv6_literal_parses_to_sixteen_bytes() {
        let (address, length) = parse_ip_literal("2001:db8::1").expect("parses");
        assert_eq!(length, 16);
        assert_eq!(address[0], 0x20);
        assert_eq!(address[1], 0x01);
        assert_eq!(address[15], 0x01);
    }

    #[test]
    fn a_non_literal_is_not_an_ip() {
        // This is `INVALID_NAME` in `CheckIP`, which becomes
        // `ERR_INVALID_ARG_VALUE("Invalid name")` rather than `undefined`.
        assert!(parse_ip_literal("example.com").is_none());
        assert!(parse_ip_literal("8.8.8").is_none());
        assert!(parse_ip_literal("").is_none());
    }
}
