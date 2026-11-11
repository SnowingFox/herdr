//! `subjectAltName` and `infoAccess`: the `GENERAL_NAME` printing.
//!
//! Both outputs are a list of `GENERAL_NAME`s rendered by
//! `ncrypto::PrintGeneralName`, separated by `", "` for a SAN and `"\n"` for
//! infoAccess. The value escaping is [`crate::names::push_alt_name`]; this module
//! is the per-type dispatch and the two extension walks.
//!
//! # The five name types, and what each emits
//!
//! | `GENERAL_NAME` | prefix | escaping mode |
//! | --- | --- | --- |
//! | `GEN_DNS` | `DNS:` | Latin-1 by byte |
//! | `GEN_EMAIL` | `email:` | Latin-1 by byte |
//! | `GEN_URI` | `URI:` | Latin-1 by byte |
//! | `GEN_IPADD` | `IP Address:` | none; dotted quad or `%X:%X:…` |
//! | `GEN_DIRNAME` | `DirName:` | UTF-8, RFC 2253 form |
//! | `GEN_RID` | `Registered ID:` | none; dotted OID |
//! | `GEN_OTHERNAME` | `othername:` | UTF-8 or IA5, prefix inside the quotes |
//! | anything else | `<unsupported>` | none |
//!
//! # Why `GEN_OTHERNAME` has five supported OIDs
//!
//! `PrintGeneralName` maps `NID_id_on_SmtpUTF8Mailbox`, `NID_XmppAddr`,
//! `NID_SRVName`, `NID_ms_upn` and `NID_NAIRealm` to a label, and prints
//! `othername:<unsupported>` for every other OID **or** for one of the five whose
//! value has the wrong string type (`SRVName` must be an `IA5String`; the rest
//! must be a `UTF8String`). The test asserts both the label and the marker.

use openssl::x509::X509;
use openssl_sys as ffi;

use crate::names::{push_alt_name, AltNameOption, UNSUPPORTED_OTHERNAME};

/// The NIDs `PrintGeneralName` gives an `othername` label to.
///
/// `openssl-sys` exports `NID_ms_upn` but not the other four, so all five are
/// written here as the numbers `obj_mac.h` gives at the vendored OpenSSL 3.6.3.
/// They are ABI-stable identifier values, not configuration.
const NID_ID_ON_SMTPUTF8MAILBOX: i32 = 1208;
const NID_XMPPADDR: i32 = 1209;
const NID_SRVNAME: i32 = 1210;
const NID_NAIREALM: i32 = 1211;

/// `V_ASN1_UTF8STRING` and `V_ASN1_IA5STRING`, from `openssl/asn1.h`.
const V_ASN1_UTF8STRING: i32 = 12;
const V_ASN1_IA5STRING: i32 = 22;

/// The `GEN_*` discriminants, from `openssl/x509v3.h`.
const GEN_OTHERNAME: i32 = 0;
const GEN_EMAIL: i32 = 1;
const GEN_DNS: i32 = 2;
const GEN_DIRNAME: i32 = 4;
const GEN_URI: i32 = 6;
const GEN_IPADD: i32 = 7;
const GEN_RID: i32 = 8;

/// `OTHERNAME` from `openssl/x509v3.h`.
///
/// `openssl-sys` does not name this struct, so it is mirrored here. The layout is
/// `ASN1_OBJECT *type_id; ASN1_TYPE *value;`, which has not changed since 1.0.
#[repr(C)]
struct OtherName {
    type_id: *mut ffi::ASN1_OBJECT,
    value: *mut ffi::ASN1_TYPE,
}

/// `X509_ALGOR`, which `openssl-sys` declares only behind its safe wrapper.
#[repr(C)]
struct X509Algor {
    algorithm: *mut ffi::ASN1_OBJECT,
    parameter: *mut ffi::ASN1_TYPE,
}

// The stack accessors are OpenSSL macros over `OPENSSL_sk_*`, which
// `openssl-sys` does export. Declaring the typed wrappers here is what lets the
// general-name stacks be walked without a second binding generator.
extern "C" {
    fn X509_ALGOR_get0(
        object: *mut *const ffi::ASN1_OBJECT,
        parameter_type: *mut std::ffi::c_int,
        parameter_value: *mut *const std::ffi::c_void,
        algor: *const X509Algor,
    );
    fn ASN1_TYPE_new() -> *mut ffi::ASN1_TYPE;
    fn ASN1_TYPE_free(value: *mut ffi::ASN1_TYPE);
    fn ASN1_TYPE_set1(
        value: *mut ffi::ASN1_TYPE,
        kind: std::ffi::c_int,
        data: *const std::ffi::c_void,
    ) -> std::ffi::c_int;
    fn i2d_ASN1_TYPE(value: *const ffi::ASN1_TYPE, out: *mut *mut u8) -> std::ffi::c_int;
    fn ASN1_STRING_length(value: *const ffi::ASN1_STRING) -> std::ffi::c_int;
    fn ASN1_STRING_get0_data(value: *const ffi::ASN1_STRING) -> *const std::ffi::c_uchar;
    fn OBJ_obj2txt(
        buf: *mut std::ffi::c_char,
        buf_len: std::ffi::c_int,
        object: *const ffi::ASN1_OBJECT,
        no_name: std::ffi::c_int,
    ) -> std::ffi::c_int;
    fn X509_get_ext_by_NID(
        certificate: *mut ffi::X509,
        nid: std::ffi::c_int,
        last_pos: std::ffi::c_int,
    ) -> std::ffi::c_int;
    fn X509_get_ext(
        certificate: *const ffi::X509,
        loc: std::ffi::c_int,
    ) -> *mut ffi::X509_EXTENSION;
    fn X509_EXTENSION_get_object(extension: *mut ffi::X509_EXTENSION) -> *const ffi::ASN1_OBJECT;
    fn X509V3_EXT_d2i(extension: *mut ffi::X509_EXTENSION) -> *mut std::ffi::c_void;
    fn GENERAL_NAMES_free(names: *mut ffi::stack_st_GENERAL_NAME);
    fn X509_NAME_print_ex(
        out: *mut ffi::BIO,
        name: *const ffi::X509_NAME,
        indent: std::ffi::c_int,
        flags: std::ffi::c_ulong,
    ) -> std::ffi::c_int;
    fn OBJ_obj2nid(object: *const ffi::ASN1_OBJECT) -> std::ffi::c_int;
    fn OPENSSL_sk_num(stack: *const std::ffi::c_void) -> std::ffi::c_int;
    fn OPENSSL_sk_value(
        stack: *const std::ffi::c_void,
        index: std::ffi::c_int,
    ) -> *mut std::ffi::c_void;
    fn OPENSSL_sk_pop_free(
        stack: *mut std::ffi::c_void,
        free: unsafe extern "C" fn(*mut std::ffi::c_void),
    );
}

/// The `GetSubjectAltNameString` outcomes.
///
/// A missing extension and a malformed one are different: the first is
/// `undefined`, the second throws for direct inspection but is a `"DNS:"`
/// sentinel for the legacy TLS object. `Absent` and `Malformed` are separate
/// variants so the caller cannot conflate them.
#[derive(Debug)]
pub enum SubjectAltName {
    /// The extension is not present.
    Absent,
    /// The formatted list.
    Text(String),
    /// Present, but `SafeX509SubjectAltNamePrint` refused it.
    Malformed,
}

/// `X509View::getSubjectAltName`.
pub fn subject_alt_name(certificate: &X509) -> SubjectAltName {
    use foreign_types::ForeignType;
    // SAFETY: `certificate` outlives the call, and `X509_get_ext_by_NID` with a
    // `last_pos` of -1 only searches.
    let index = unsafe { X509_get_ext_by_NID(certificate.as_ptr(), ffi::NID_subject_alt_name, -1) };
    if index < 0 {
        return SubjectAltName::Absent;
    }
    match format_general_names(certificate, index, ", ") {
        Some(text) => SubjectAltName::Text(text),
        None => SubjectAltName::Malformed,
    }
}

/// `X509View::getInfoAccess`.
///
/// `None` when the extension is absent, matching `GetInfoAccessString`'s
/// `undefined`. A present-but-unformattable extension is also `None` rather than
/// an error: `SafeX509InfoAccessPrint` has no throwing path, so the binding leaves
/// the property unset.
pub fn info_access(certificate: &X509) -> Option<String> {
    use foreign_types::ForeignType;
    // SAFETY: as in `subject_alt_name`.
    let index = unsafe { X509_get_ext_by_NID(certificate.as_ptr(), ffi::NID_info_access, -1) };
    if index < 0 {
        return None;
    }
    // SAFETY: `index` came from the search above on this certificate.
    let extension = unsafe { X509_get_ext(certificate.as_ptr(), index) };
    if extension.is_null() {
        return None;
    }
    format_info_access(extension)
}

/// Walks a SAN extension and joins the names with `separator`.
fn format_general_names(certificate: &X509, index: i32, separator: &str) -> Option<String> {
    use foreign_types::ForeignType;
    // SAFETY: `index` indexes this certificate's extensions.
    let extension = unsafe { X509_get_ext(certificate.as_ptr(), index) };
    if extension.is_null() {
        return None;
    }
    // `SafeX509SubjectAltNamePrint` checks the OID before decoding, so a
    // mis-indexed extension cannot be read as a SAN.
    // SAFETY: `extension` is live for the call.
    let kind = unsafe { OBJ_obj2nid(X509_EXTENSION_get_object(extension)) };
    if kind != ffi::NID_subject_alt_name {
        return None;
    }
    // SAFETY: `X509V3_EXT_d2i` decodes the extension into a freshly allocated
    // `GENERAL_NAMES`, released by `GENERAL_NAMES_free` below.
    let names = unsafe { X509V3_EXT_d2i(extension) } as *mut ffi::stack_st_GENERAL_NAME;
    if names.is_null() {
        return None;
    }
    // SAFETY: `names` is a live `GENERAL_NAMES` stack.
    let count = unsafe { OPENSSL_sk_num(names.cast()) };
    // An empty extension is a failure in `SafeX509SubjectAltNamePrint`
    // (`ok = count > 0`), not an empty string.
    let mut output = String::new();
    let mut ok = count > 0;
    for position in 0..count {
        if !ok {
            break;
        }
        // SAFETY: `position` is in range.
        let name = unsafe { OPENSSL_sk_value(names.cast(), position) }.cast::<ffi::GENERAL_NAME>();
        if name.is_null() {
            ok = false;
            break;
        }
        if position != 0 {
            output.push_str(separator);
        }
        // SAFETY: `name` is a live `GENERAL_NAME` borrowed from `names`.
        ok = unsafe { push_general_name(&mut output, name) };
    }
    // SAFETY: `names` came from `X509V3_EXT_d2i` and is released exactly once.
    unsafe { GENERAL_NAMES_free(names) };
    ok.then_some(output)
}

/// Walks an `AUTHORITY_INFO_ACCESS` extension.
fn format_info_access(extension: *mut ffi::X509_EXTENSION) -> Option<String> {
    // SAFETY: `extension` is a live extension owned by the caller.
    let kind = unsafe { OBJ_obj2nid(X509_EXTENSION_get_object(extension)) };
    if kind != ffi::NID_info_access {
        return None;
    }
    // SAFETY: decodes into a freshly allocated stack freed below.
    let descriptions =
        unsafe { X509V3_EXT_d2i(extension) } as *mut ffi::stack_st_ACCESS_DESCRIPTION;
    if descriptions.is_null() {
        return None;
    }
    // SAFETY: `descriptions` is a live stack.
    let count = unsafe { OPENSSL_sk_num(descriptions.cast()) };
    let mut output = String::new();
    let mut ok = count > 0;
    for position in 0..count {
        if !ok {
            break;
        }
        // SAFETY: `position` is in range.
        let description = unsafe { OPENSSL_sk_value(descriptions.cast(), position) }
            .cast::<ffi::ACCESS_DESCRIPTION>();
        if description.is_null() {
            ok = false;
            break;
        }
        if position != 0 {
            output.push('\n');
        }
        // SAFETY: `description` points at a live `ACCESS_DESCRIPTION` from the
        // stack, so both its fields are valid for this iteration.
        ok = unsafe {
            let method = (*description).method;
            let location = (*description).location;
            if method.is_null() || location.is_null() {
                false
            } else {
                // `ObjectToText(method, false)` keeps the long name, which is why
                // `infoAccess` reads `OCSP` and `CA Issuers` rather than a dotted
                // OID.
                match object_text(method, false) {
                    Some(text) => {
                        output.push_str(&text);
                        output.push_str(" - ");
                        push_general_name(&mut output, location)
                    }
                    None => false,
                }
            }
        };
    }
    // SAFETY: released exactly once, with the element destructor.
    unsafe {
        OPENSSL_sk_pop_free(
            descriptions.cast(),
            transparent_free(ffi::ACCESS_DESCRIPTION_free),
        )
    };
    ok.then_some(output)
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

/// `ncrypto::PrintGeneralName`: one `GENERAL_NAME` into `out`.
///
/// Returns `false` on any structural problem, which the callers turn into a
/// failed print rather than a partial string.
///
/// # Safety
///
/// `name` must be a live `GENERAL_NAME` that this call only reads.
unsafe fn push_general_name(out: &mut String, name: *mut ffi::GENERAL_NAME) -> bool {
    // SAFETY: the caller guarantees `name` is live.
    let kind = unsafe { (*name).type_ };
    match kind {
        GEN_DNS => {
            out.push_str("DNS:");
            // SAFETY: for a `GEN_DNS` the union holds an `ASN1_IA5STRING`.
            unsafe { push_ia5(out, (*name).d.cast::<ffi::ASN1_STRING>()) }
        }
        GEN_EMAIL => {
            out.push_str("email:");
            // SAFETY: for `GEN_EMAIL` the union holds an `ASN1_IA5STRING`.
            unsafe { push_ia5(out, (*name).d.cast::<ffi::ASN1_STRING>()) }
        }
        GEN_URI => {
            out.push_str("URI:");
            // SAFETY: for `GEN_URI` the union holds an `ASN1_IA5STRING`.
            unsafe { push_ia5(out, (*name).d.cast::<ffi::ASN1_STRING>()) }
        }
        GEN_IPADD => {
            out.push_str("IP Address:");
            // SAFETY: for `GEN_IPADD` the union holds an `ASN1_OCTET_STRING`,
            // which is layout-compatible with `ASN1_STRING`.
            unsafe { push_ip(out, (*name).d.cast::<ffi::ASN1_STRING>()) }
        }
        GEN_DIRNAME => {
            out.push_str("DirName:");
            // SAFETY: for `GEN_DIRNAME` the union holds an `X509_NAME`.
            unsafe { push_directory_name(out, (*name).d.cast::<ffi::X509_NAME>()) }
        }
        GEN_RID => {
            out.push_str("Registered ID:");
            // SAFETY: for `GEN_RID` the union holds an `ASN1_OBJECT`.
            let object = unsafe { (*name).d.cast::<ffi::ASN1_OBJECT>() };
            // `PrintGeneralName` always prints the numeric form here, never the
            // OID's text name, and says why: a RID is an identifier, not a label.
            match unsafe { object_text(object, true) } {
                Some(text) => {
                    out.push_str(&text);
                    true
                }
                None => false,
            }
        }
        GEN_OTHERNAME => unsafe { push_other_name(out, (*name).d.cast::<OtherName>()) },
        _ => {
            out.push_str("<unsupported>");
            true
        }
    }
}

/// A DNS name, e-mail address or URI, as an `IA5String`.
///
/// # Safety
///
/// `value` must be a live `ASN1_IA5STRING`, or null.
unsafe fn push_ia5(out: &mut String, value: *mut ffi::ASN1_STRING) -> bool {
    if value.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees `value` is live.
    unsafe {
        let length = ASN1_STRING_length(value);
        if length < 0 {
            return false;
        }
        let data = ASN1_STRING_get0_data(value);
        if data.is_null() && length != 0 {
            return false;
        }
        let bytes = if length == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(data, length as usize)
        };
        push_alt_name(out, bytes, AltNameOption::None, None);
    }
    true
}

/// An IP address, as an `OCTET STRING`.
///
/// Four bytes is a dotted quad; sixteen is eight `%X` groups joined by `:`. Any
/// other length is `<invalid length=N>`, which is what the OpenSSL-provider build
/// emits — and it is reachable, because a certificate can carry a five-byte
/// `iPAddress`.
///
/// # Safety
///
/// `value` must be a live `ASN1_OCTET_STRING`, or null.
unsafe fn push_ip(out: &mut String, value: *mut ffi::ASN1_STRING) -> bool {
    if value.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees `value` is live.
    unsafe {
        let length = ASN1_STRING_length(value);
        if length < 0 {
            return false;
        }
        let data = ASN1_STRING_get0_data(value);
        if data.is_null() && length != 0 {
            return false;
        }
        let bytes = if length == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(data, length as usize)
        };
        match bytes.len() {
            4 => out.push_str(&format!(
                "{}.{}.{}.{}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            )),
            16 => {
                for group in 0..8 {
                    let pair = (u16::from(bytes[2 * group]) << 8) | u16::from(bytes[2 * group + 1]);
                    if group == 0 {
                        out.push_str(&format!("{pair:X}"));
                    } else {
                        out.push_str(&format!(":{pair:X}"));
                    }
                }
            }
            other => out.push_str(&format!("<invalid length={other}>")),
        }
    }
    true
}

/// A `DirName`, printed RFC 2253-style and then escaped as UTF-8.
///
/// # Safety
///
/// `name` must be a live `X509_NAME`, or null.
unsafe fn push_directory_name(out: &mut String, name: *mut ffi::X509_NAME) -> bool {
    if name.is_null() {
        return false;
    }
    let flags = crate::names::rfc2253_in_json_flags();
    let Some(printed) = crate::bio::with_memory_bio(|bio| {
        // SAFETY: the BIO and the name are both live for the call.
        unsafe { X509_NAME_print_ex(bio.raw(), name, 0, flags) >= 0 }
    }) else {
        return false;
    };
    push_alt_name(out, printed.as_bytes(), AltNameOption::Utf8, None);
    true
}

/// An `othername`.
///
/// # Safety
///
/// `name` must be a live `OTHERNAME`, or null.
unsafe fn push_other_name(out: &mut String, name: *mut OtherName) -> bool {
    if name.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees `name` is live.
    unsafe {
        let type_id = (*name).type_id;
        let value = (*name).value;
        if type_id.is_null() || value.is_null() {
            return false;
        }
        let nid = OBJ_obj2nid(type_id);
        // `(label, must_be_utf8)`, from `PrintGeneralName`'s switch.
        let (label, unicode) = match nid {
            NID_ID_ON_SMTPUTF8MAILBOX => ("SmtpUTF8Mailbox", true),
            NID_XMPPADDR => ("XmppAddr", true),
            NID_SRVNAME => ("SRVName", false),
            ffi::NID_ms_upn => ("UPN", true),
            NID_NAIREALM => ("NAIRealm", true),
            _ => {
                out.push_str(UNSUPPORTED_OTHERNAME);
                return true;
            }
        };
        let kind = (*value).type_;
        let expected = if unicode {
            V_ASN1_UTF8STRING
        } else {
            V_ASN1_IA5STRING
        };
        if kind != expected {
            out.push_str(UNSUPPORTED_OTHERNAME);
            return true;
        }
        let string = (*value).value.asn1_string;
        if string.is_null() {
            return false;
        }
        out.push_str("othername:");
        let length = ASN1_STRING_length(string);
        if length < 0 {
            return false;
        }
        let data = ASN1_STRING_get0_data(string);
        if data.is_null() && length != 0 {
            return false;
        }
        let bytes = if length == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(data, length as usize)
        };
        // The label goes *through* `push_alt_name`, so a quoted value reads
        // `othername:"XmppAddr:…"` with the label inside the quotes.
        push_alt_name(
            out,
            bytes,
            if unicode {
                AltNameOption::Utf8
            } else {
                AltNameOption::None
            },
            Some(label),
        );
    }
    true
}

/// `ObjectToText`: an OID as text, or its dotted form.
///
/// Two calls, because `OBJ_obj2txt` has no way to ask for the length otherwise.
///
/// # Safety
///
/// `object` must be a live `ASN1_OBJECT` or null.
pub(crate) unsafe fn object_text(object: *const ffi::ASN1_OBJECT, no_name: bool) -> Option<String> {
    if object.is_null() {
        return None;
    }
    let no_name = i32::from(no_name);
    // SAFETY: the caller guarantees `object` is live, and both calls only read
    // it.
    unsafe {
        let length = OBJ_obj2txt(std::ptr::null_mut(), 0, object, no_name);
        if length <= 0 || length == i32::MAX {
            return None;
        }
        let mut buffer = vec![0u8; length as usize + 1];
        let written = OBJ_obj2txt(
            buffer.as_mut_ptr().cast::<std::ffi::c_char>(),
            length + 1,
            object,
            no_name,
        );
        if written != length {
            return None;
        }
        buffer.truncate(length as usize);
        String::from_utf8(buffer).ok()
    }
}

/// Allocates an `ASN1_TYPE` copy, which the signature printer needs.
pub(crate) fn asn1_type_new() -> *mut ffi::ASN1_TYPE {
    // SAFETY: allocates one `ASN1_TYPE`.
    unsafe { ASN1_TYPE_new() }
}

/// Copies a parameter into an `ASN1_TYPE`.
pub(crate) fn asn1_type_set1(
    value: *mut ffi::ASN1_TYPE,
    kind: i32,
    data: *const std::ffi::c_void,
) -> bool {
    // SAFETY: the caller owns `value` and guarantees `data` matches `kind`.
    unsafe { ASN1_TYPE_set1(value, kind, data) == 1 }
}

/// Encodes an `ASN1_TYPE` as DER.
pub(crate) fn asn1_type_der(value: *mut ffi::ASN1_TYPE) -> Option<Vec<u8>> {
    // SAFETY: the caller owns `value`.
    unsafe {
        let mut pointer: *mut u8 = std::ptr::null_mut();
        let length = i2d_ASN1_TYPE(value, &mut pointer);
        if length <= 0 || pointer.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(pointer, length as usize).to_vec();
        ffi::OPENSSL_free(pointer.cast());
        Some(bytes)
    }
}

/// Frees an `ASN1_TYPE`.
pub(crate) fn asn1_type_free(value: *mut ffi::ASN1_TYPE) {
    // SAFETY: the caller owns `value`.
    unsafe { ASN1_TYPE_free(value) };
}

/// Reads an `X509_ALGOR`'s algorithm OID and its encoded parameters.
///
/// One function for both callers: `signatureAlgorithmOid` wants the OID,
/// `signature` wants both. Splitting it would duplicate the `X509_ALGOR_get0`
/// call and give the two a chance to disagree about the parameter encoding.
pub(crate) fn algorithm_identifier(
    algor: *const ffi::X509_ALGOR,
) -> Option<(String, Option<Vec<u8>>)> {
    if algor.is_null() {
        return None;
    }
    let mut object: *const ffi::ASN1_OBJECT = std::ptr::null();
    let mut parameter_type: i32 = -1;
    let mut parameter_value: *const std::ffi::c_void = std::ptr::null();
    // SAFETY: `algor` is live and the three out-parameters are valid for the
    // call, which only reads the algorithm.
    unsafe {
        X509_ALGOR_get0(
            &mut object,
            &mut parameter_type,
            &mut parameter_value,
            algor as *const X509Algor,
        );
    }
    // SAFETY: `object` came from `X509_ALGOR_get0` and is borrowed from `algor`.
    let oid = unsafe { object_text(object, true) }?;
    // `V_ASN1_UNDEF` is -1: no parameters, which is the common case for Ed25519
    // and for the RSA signature algorithms.
    if parameter_type == -1 {
        return Some((oid, None));
    }
    let copy = asn1_type_new();
    if copy.is_null() {
        return Some((oid, None));
    }
    if !asn1_type_set1(copy, parameter_type, parameter_value) {
        asn1_type_free(copy);
        return Some((oid, None));
    }
    let der = asn1_type_der(copy);
    asn1_type_free(copy);
    Some((oid, der))
}
