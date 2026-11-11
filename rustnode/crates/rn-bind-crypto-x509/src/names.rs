//! The text forms `X509Certificate` reports, and the escaping they need.
//!
//! Four different formatters are in play and swapping any two of them produces a
//! plausible string that fails `test-x509-escaping.js`:
//!
//! | output | formatter |
//! | --- | --- |
//! | `subject` / `issuer` | `X509_NAME_print_ex` with `kX509NameFlagsMultiline` |
//! | `subjectAltName` | per-`GENERAL_NAME` printing with [`alt_name`] escaping |
//! | `infoAccess` | `method - <general name>` per access description |
//! | `subjectName.rdns[].oid` | `OBJ_obj2txt` with `no_name = 1` (dotted) |
//!
//! # Why the escaping is reimplemented rather than delegated
//!
//! `X509V3_EXT_print` would print a subjectAltName, and OpenSSL has no way to
//! make it produce Node's quoting. `SafeX509SubjectAltNamePrint` exists in
//! `ncrypto` for exactly this reason: a SAN value is attacker-controlled text
//! that Node splices into a comma-separated list, so a value containing a comma,
//! a quote or a control character has to be quoted and escaped or it forges
//! list structure. `test-x509-escaping.js` feeds a certificate whose SAN is
//! `good.example.com, DNS:evil.example.com` and asserts the output is
//! `DNS:"good.example.com\\u002c DNS:evil.example.com"`.
//!
//! The rules, from `ncrypto.cc`'s `IsSafeAltName`/`PrintAltName`:
//!
//! * `"`, `\`, `,` and `'` always force quoting.
//! * A control character or a non-ASCII byte forces quoting; for a `DirName`
//!   (which is UTF-8) only ASCII controls do.
//! * Inside quotes, `\\` and `\"` are escaped, a comma becomes `\u002c` (not
//!   `,`), anything printable stays, and everything else becomes a Latin-1
//!   `\u00XX`.

use openssl::x509::X509;

// `X509_NAME_print_ex` is not in `openssl-sys`; the safe wrapper only exposes
// the RFC 2253 and oneline forms it needs. Declaring it here keeps the escaping
// flags explicit, which is the point of this module.
extern "C" {
    /// Prints a name into a BIO with explicit flags.
    fn X509_NAME_print_ex(
        out: *mut openssl_sys::BIO,
        name: *const openssl_sys::X509_NAME,
        indent: std::ffi::c_int,
        flags: std::ffi::c_ulong,
    ) -> std::ffi::c_int;
}

/// `ALT_NAME_UTF8`: the value is UTF-8 rather than Latin-1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AltNameOption {
    /// Treat non-ASCII bytes as unsafe Latin-1, which is what a DNS name,
    /// e-mail or URI gets.
    None,
    /// Treat bytes with the high bit set as safe UTF-8, which is what a
    /// `DirName` gets.
    Utf8,
}

/// What `PrintGeneralName` writes for an `othername` it cannot format.
///
/// A known extension OID with an unexpected value type, or one of the five
/// supported OIDs with the wrong string type, prints this marker inside the
/// `othername:` label rather than failing. `test-x509-escaping.js` asserts the
/// marker for the BoringSSL branch and for a `SRVName` that is not an IA5String.
pub const UNSUPPORTED_OTHERNAME: &str = "othername:<unsupported>";

/// `IsSafeAltName`: whether a value can be written without quoting.
pub fn is_safe_alt_name(value: &[u8], option: AltNameOption) -> bool {
    for &byte in value {
        match byte {
            b'"' | b'\\' | b',' | b'\'' => return false,
            _ => {
                let is_control = if option == AltNameOption::Utf8 {
                    byte < b' ' || byte == 0x7f
                } else {
                    !(b' '..=b'~').contains(&byte)
                };
                if is_control {
                    return false;
                }
            }
        }
    }
    true
}

/// `PrintAltName`: append a value, quoted and escaped when it is not safe.
///
/// `prefix` is the `safe_prefix` parameter, and whether a caller passes it is
/// the difference between two outputs `test-x509-escaping.js` pins:
///
/// * `DNS:`, `URI:`, `email:` and `IP Address:` are written to the buffer
///   *before* this is called, so a quoted value reads `URI:"http://…/a\u002cb"`
///   with the quotes around the value alone.
/// * An `othername` passes its label *through* here, so a quoted value reads
///   `othername:"XmppAddr:good.example.com\u0000abc123"` with the label inside
///   the quotes. That is `PrintGeneralName`'s `GEN_OTHERNAME` branch, which is
///   the only caller that hands `PrintAltName` a non-null prefix.
pub fn push_alt_name(out: &mut String, value: &[u8], option: AltNameOption, prefix: Option<&str>) {
    if is_safe_alt_name(value, option) {
        // Safe names are appended unchanged, for backward compatibility.
        if let Some(prefix) = prefix {
            out.push_str(prefix);
            out.push(':');
        }
        // `String::from_utf8_lossy` rather than a strict decode: a safe name is
        // ASCII by construction in the `None` case, and in the `Utf8` case the
        // bytes came from OpenSSL's own UTF-8 printer.
        out.push_str(&String::from_utf8_lossy(value));
        return;
    }

    out.push('"');
    if let Some(prefix) = prefix {
        out.push_str(prefix);
        out.push(':');
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            _ => {
                let printable = (b' '..=b'~').contains(&byte) && byte != b',';
                let utf8_continuation = option == AltNameOption::Utf8 && byte & 0x80 != 0;
                if utf8_continuation {
                    // A multi-byte UTF-8 sequence has to be copied whole, or its
                    // individual bytes would be escaped apart and the result
                    // would not decode.
                    let start = index;
                    while index < value.len() && value[index] & 0x80 != 0 {
                        index += 1;
                    }
                    out.push_str(&String::from_utf8_lossy(&value[start..index]));
                    continue;
                }
                if printable {
                    out.push(byte as char);
                } else {
                    // Latin-1 escape, which is what every control character and
                    // every comma becomes.
                    out.push_str("\\u00");
                    out.push(HEX[(byte >> 4) as usize] as char);
                    out.push(HEX[(byte & 0x0f) as usize] as char);
                }
            }
        }
        index += 1;
    }
    out.push('"');
}

/// A DER-encoded `X509_NAME` as `X509_NAME_print_ex` renders it for the
/// `subject` and `issuer` properties.
///
/// `kX509NameFlagsMultiline` is
/// `ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_UTF8_CONVERT |
/// XN_FLAG_SEP_MULTILINE | XN_FLAG_FN_SN`, with `XN_FLAG_FN_SN` being zero, so
/// the short name (`CN`, `O`) is used and each RDN is on its own line.
pub fn multiline_name_flags() -> std::ffi::c_ulong {
    /// Escape the characters RFC 2253 requires.
    const ASN1_STRFLGS_ESC_2253: std::ffi::c_ulong = 1;
    /// Escape control characters.
    const ASN1_STRFLGS_ESC_CTRL: std::ffi::c_ulong = 2;
    /// Convert to UTF-8 before printing.
    const ASN1_STRFLGS_UTF8_CONVERT: std::ffi::c_ulong = 0x10;
    /// One line per field.
    const XN_FLAG_SEP_MULTILINE: std::ffi::c_ulong = 4 << 16;

    ASN1_STRFLGS_ESC_2253
        | ASN1_STRFLGS_ESC_CTRL
        | ASN1_STRFLGS_UTF8_CONVERT
        | XN_FLAG_SEP_MULTILINE
}

/// The RFC 2253 form used inside a JSON-quoted `DirName` SAN.
///
/// `kX509NameFlagsRFC2253WithinUtf8JSON` is `XN_FLAG_RFC2253` with
/// `ASN1_STRFLGS_ESC_MSB` and `ASN1_STRFLGS_ESC_CTRL` cleared, because the
/// surrounding [`push_alt_name`] call escapes those. Leaving them set would
/// double-escape a control character.
pub fn rfc2253_in_json_flags() -> std::ffi::c_ulong {
    /// RFC 2253's own escaping set (MSB and control flags excluded here).
    const ASN1_STRFLGS_RFC2253_BASE: std::ffi::c_ulong = 1
        | 0x10  // UTF8_CONVERT
        | 0x80  // DUMP_UNKNOWN
        | 0x100; // DUMP_DER
    /// Reverse the DN.
    const XN_FLAG_DN_REV: std::ffi::c_ulong = 1 << 20;
    /// `, ` between RDNs and `+` within one.
    const XN_FLAG_SEP_COMMA_PLUS: std::ffi::c_ulong = 2 << 16;
    /// Dump unknown fields.
    const XN_FLAG_DUMP_UNKNOWN_FIELDS: std::ffi::c_ulong = 1 << 24;

    ASN1_STRFLGS_RFC2253_BASE
        | XN_FLAG_SEP_COMMA_PLUS
        | XN_FLAG_DN_REV
        | XN_FLAG_DUMP_UNKNOWN_FIELDS
}

/// Renders a certificate's subject or issuer through `X509_NAME_print_ex`.
///
/// Returns `None` when OpenSSL refuses to print the name, which the binding maps
/// to `undefined` — the same thing `ToV8Value(context, BIOPointer&&)` does with
/// an empty bio.
pub fn print_name(certificate: &X509, subject: bool) -> Option<String> {
    use foreign_types::ForeignTypeRef;

    let name = if subject {
        certificate.subject_name()
    } else {
        certificate.issuer_name()
    };
    let flags = multiline_name_flags();
    crate::bio::with_memory_bio(|bio| {
        // SAFETY: the BIO is live for the call and `name` is borrowed from the
        // certificate, which outlives it; a negative return is a print failure.
        unsafe { X509_NAME_print_ex(bio.raw(), name.as_ptr(), 0, flags) >= 0 }
    })
}
