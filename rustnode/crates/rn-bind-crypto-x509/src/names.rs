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

// `BIO_free`, which `openssl-sys` does not export: the safe crate frees BIOs
// through its own wrapper, which is not constructible over a raw pointer here.
extern "C" {
    // Releases one BIO reference.
    fn BIO_free(bio: *mut openssl_sys::BIO) -> std::ffi::c_int;
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
/// The `DNS:`/`URI:`-style prefix is *not* a parameter. In `PrintGeneralName`
/// the prefix is written to the buffer before this is called, so a quoted value
/// comes out as `URI:"http://…/a\u002cb"` with the quotes around the value
/// alone. Folding the prefix in here would produce `"URI:http://…"`, which is a
/// different string and the assertion `test-x509-escaping.js` makes about
/// `infoAccess`.
pub fn push_alt_name(out: &mut String, value: &[u8], option: AltNameOption) {
    if is_safe_alt_name(value, option) {
        // Safe names are appended unchanged, for backward compatibility.
        //
        // `String::from_utf8_lossy` rather than a strict decode: a safe name is
        // ASCII by construction in the `None` case, and in the `Utf8` case the
        // bytes came from OpenSSL's own UTF-8 printer.
        out.push_str(&String::from_utf8_lossy(value));
        return;
    }

    out.push('"');
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
    // SAFETY: `X509_NAME_print_ex` writes into the BIO and reads the name, both
    // of which live for the call; the negative return is a printing failure.
    unsafe {
        let bio = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
        if bio.is_null() {
            return None;
        }
        let result = X509_NAME_print_ex(bio, name.as_ptr(), 0, flags);
        let text = if result < 0 { None } else { bio_to_string(bio) };
        BIO_free(bio);
        text
    }
}

/// Reads a memory BIO's contents and frees nothing.
///
/// # Safety
///
/// `bio` must be a live `BIO_s_mem`.
unsafe fn bio_to_string(bio: *mut openssl_sys::BIO) -> Option<String> {
    let mut data: *mut std::ffi::c_char = std::ptr::null_mut();
    // SAFETY: `BIO_get_mem_data` only writes the pointer and returns the length.
    let length = unsafe { openssl_sys::BIO_get_mem_data(bio, &mut data) };
    if length < 0 || (length > 0 && data.is_null()) {
        return None;
    }
    if length == 0 {
        return Some(String::new());
    }
    // SAFETY: the BIO owns `length` bytes at `data`, which stay valid until the
    // BIO is freed by the caller after this returns.
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length as usize) };
    // Node builds these with `String::NewFromUtf8`, which is not
    // lossy: a name that is not valid UTF-8 fails to print rather than being
    // mangled. `ASN1_STRFLGS_UTF8_CONVERT` makes that unreachable in practice.
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The escaping cases `test-x509-escaping.js` asserts, as `(input, expected)`.
    const CASES: &[(&str, &str)] = &[
        // A safe DNS name is unchanged.
        ("good.example.com", "good.example.com"),
        // A comma forces quoting and becomes `\u002c`, not `,`.
        (
            "good.example.com, DNS:evil.example.com",
            "\"good.example.com\\u002c DNS:evil.example.com\"",
        ),
        // A quote is escaped.
        ("\"evil.example.com\"", "\"\\\"evil.example.com\\\"\""),
        // A backslash is escaped.
        ("a\\b", "\"a\\\\b\""),
        // A newline becomes a Latin-1 escape.
        (
            "good.example.com\nOCSP - URI:http://evil.example.com/",
            "\"good.example.com\\u000aOCSP - URI:http://evil.example.com/\"",
        ),
        // A NUL byte likewise.
        (
            "XmppAddr:good.example.com\0abc123",
            "\"XmppAddr:good.example.com\\u0000abc123\"",
        ),
        // A single quote forces quoting even though it is printable.
        ("it's", "\"it's\""),
    ];

    #[test]
    fn the_escaping_rules_match_the_node_test_table() {
        for (input, expected) in CASES {
            let mut out = String::new();
            push_alt_name(&mut out, input.as_bytes(), AltNameOption::None);
            assert_eq!(&out, expected, "escaping {input:?}");
        }
    }

    #[test]
    fn a_uri_without_commas_is_not_quoted() {
        // The test asserts `URI:http://example.com/?a=b&c=d` stays bare: most
        // legitimate URIs must not need escaping.
        let mut out = String::from("URI:");
        push_alt_name(
            &mut out,
            b"http://example.com/?a=b&c=d",
            AltNameOption::None,
        );
        assert_eq!(out, "URI:http://example.com/?a=b&c=d");
    }

    #[test]
    fn a_uri_with_a_comma_is_quoted_around_the_value_only() {
        // The prefix is written before the value is quoted, so the quotes wrap
        // the value and not the `URI:` label — `URI:"http://…/a\u002cb"`.
        let mut out = String::from("URI:");
        push_alt_name(&mut out, b"http://example.com/a,b", AltNameOption::None);
        assert_eq!(out, "URI:\"http://example.com/a\\u002cb\"");
    }

    #[test]
    fn percent_encoding_is_safe() {
        // `%2C` is three safe bytes, so it must not be quoted; the test asserts
        // exactly this because it looks like a comma.
        let mut out = String::from("URI:");
        push_alt_name(&mut out, b"http://example.com/a%2Cb", AltNameOption::None);
        assert_eq!(out, "URI:http://example.com/a%2Cb");
    }

    #[test]
    fn a_latin1_high_byte_is_escaped_not_decoded() {
        // `DNS:"ex\u00e4mple.com"`: in a DNS name `0xe4` is Latin-1, so it is
        // escaped rather than read as a UTF-8 lead byte.
        let mut out = String::from("DNS:");
        push_alt_name(&mut out, b"ex\xe4mple.com", AltNameOption::None);
        assert_eq!(out, "DNS:\"ex\\u00e4mple.com\"");
    }

    #[test]
    fn a_utf8_dir_name_keeps_its_multibyte_sequence() {
        // In the `Utf8` mode a high byte is part of a valid sequence and has to
        // survive as UTF-8, not be escaped byte by byte. It still needs quoting
        // because of the comma.
        let mut out = String::from("DirName:");
        push_alt_name(&mut out, "München, evil".as_bytes(), AltNameOption::Utf8);
        assert_eq!(out, "DirName:\"München\\u002c evil\"");
    }

    #[test]
    fn a_mid_string_comma_forces_quoting() {
        // `L=Somewhere\, CN = evil.example.com`: the comma is escaped by
        // `X509_NAME_print_ex`, not by this code, so what is pinned here is only
        // that a comma is never treated as safe.
        assert!(!is_safe_alt_name(b"a,b", AltNameOption::None));
    }

    #[test]
    fn the_multiline_flags_are_the_ones_ncrypto_uses() {
        // `ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL |
        // ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_MULTILINE`, with
        // `XN_FLAG_FN_SN` == 0. A dropped flag changes the separator or the
        // escaping and every `subject` assertion fails.
        assert_eq!(multiline_name_flags(), 0x4_0013);
    }
}
