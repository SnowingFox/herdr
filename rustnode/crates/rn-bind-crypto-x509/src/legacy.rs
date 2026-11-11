//! `toLegacyObject()`: the `translatePeerCertificate` input object.
//!
//! `x509.js` calls the native `toLegacy`, then hands the result to
//! `internal/tls/common`'s `translatePeerCertificate`, which is the function that
//! produced `getPeerCertificate()`'s shape before `X509Certificate` existed. So
//! this object is **not** the public shape — it is the intermediate one, and the
//! field names are the legacy ones (`subjectaltname`, `valid_from`,
//! `fingerprint256`, `ext_key_usage`), with the distinguished names as plain
//! objects keyed by attribute name.
//!
//! # Why every field is computed, and none is a placeholder
//!
//! `X509ToObject` fills a fixed 19-slot dictionary. Four of those slots —
//! `modulus`, `exponent`, `pubkey`/`bits`, and the curve names — are key-type
//! specific and *are* legitimately left `undefined` when the certificate's public
//! key cannot be decoded; Node says so in a comment and returns early. Everything
//! else is a real answer.
//!
//! A `toLegacyObject` that returned a well-formed object with empty strings would
//! move the failure into `translatePeerCertificate` and then into TLS, where it is
//! attributed to the handshake rather than to this crate. So the fields that
//! cannot be computed are left **undefined**, which is the same thing Node does and
//! which `assert.strictEqual(obj.issuerCertificate, undefined)` in
//! `test-x509-escaping.js` shows the consumers tolerate.

use openssl::x509::X509;
use openssl_sys as ffi;
use rn_v8_sys::v8;

use crate::der_accessors;
use crate::extras;

/// The 19 slot names, in order, from `X509ToObject`.
///
/// A `DictionaryTemplate` rather than a plain object because the slot order is
/// part of the dictionary protocol and a plain `Object` would let a later
/// `SetValue` silently create a differently-named property.
const SLOTS: &[&str] = &[
    "subject",
    "issuer",
    "subjectaltname",
    "infoAccess",
    "ca",
    "modulus",
    "exponent",
    "pubkey",
    "bits",
    "valid_from",
    "valid_to",
    "fingerprint",
    "fingerprint256",
    "fingerprint512",
    "ext_key_usage",
    "serialNumber",
    "raw",
    "asn1Curve",
    "nistCurve",
];

/// Builds the legacy object for `certificate`, or `None` when it cannot be built.
///
/// Returning `None` propagates as `undefined` from `toLegacy`, which `x509.js`
/// then passes to `translatePeerCertificate`. That function throws on a
/// non-object, so a `None` is visible rather than silent.
pub fn to_legacy<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    certificate: &X509,
) -> Option<v8::Local<'s, v8::Value>> {
    let mut values: Vec<v8::Local<'s, v8::Value>> = Vec::with_capacity(SLOTS.len());

    // 0-1: the distinguished names, as plain objects keyed by attribute name.
    values.push(legacy_name(scope, certificate, true)?);
    values.push(legacy_name(scope, certificate, false)?);

    // 2: `subjectaltname`, with the legacy `"DNS:"` sentinel for a malformed
    // extension instead of throwing — the same value `GetSubjectAltNameString`
    // produces in its `kReturnLegacySentinel` mode.
    values.push(match crate::alt_names::subject_alt_name(certificate) {
        crate::alt_names::SubjectAltName::Absent => v8::undefined(scope).into(),
        crate::alt_names::SubjectAltName::Text(text) => string_or_empty(scope, &text),
        crate::alt_names::SubjectAltName::Malformed => string_or_empty(scope, "DNS:"),
    });

    // 3: `infoAccess`.
    values.push(match crate::alt_names::info_access(certificate) {
        Some(text) => string_or_empty(scope, &text),
        None => v8::undefined(scope).into(),
    });

    // 4: `ca`.
    values.push(v8::Boolean::new(scope, extras::is_ca(certificate)).into());

    // 5-8: the key-specific slots, which are only filled when the public key
    // decodes. `X509ToObject` leaves all four undefined otherwise and returns
    // immediately, and that early return is what this reproduces.
    let mut key_fields: [v8::Local<'s, v8::Value>; 4] = [
        v8::undefined(scope).into(),
        v8::undefined(scope).into(),
        v8::undefined(scope).into(),
        v8::undefined(scope).into(),
    ];
    let mut curves: [v8::Local<'s, v8::Value>; 2] =
        [v8::undefined(scope).into(), v8::undefined(scope).into()];
    if extras::has_public_key(certificate) {
        if let Some(key) = extras::owned_public_key(certificate) {
            // SAFETY: `owned_public_key` returned one reference this scope owns.
            let owned = unsafe { extras::pkey_from_raw(key) };
            if let Some(key) = owned {
                fill_key_fields(scope, &key, &mut key_fields, &mut curves);
            }
        }
    }
    values.extend(key_fields);

    // 9-10: `valid_from` / `valid_to`, as the printed strings.
    values.push(match crate::dates::print_time(certificate, true) {
        Some(text) => string_or_empty(scope, &text),
        None => v8::undefined(scope).into(),
    });
    values.push(match crate::dates::print_time(certificate, false) {
        Some(text) => string_or_empty(scope, &text),
        None => v8::undefined(scope).into(),
    });

    // 11-13: the three fingerprints.
    for digest in [
        openssl::hash::MessageDigest::sha1(),
        openssl::hash::MessageDigest::sha256(),
        openssl::hash::MessageDigest::sha512(),
    ] {
        values.push(match der_accessors::fingerprint(certificate, digest) {
            Some(text) => string_or_empty(scope, &text),
            None => v8::undefined(scope).into(),
        });
    }

    // 14: `ext_key_usage`, an array of dotted OIDs.
    values.push(match der_accessors::key_usage(certificate) {
        Some(usages) => {
            let items: Vec<v8::Local<v8::Value>> = usages
                .iter()
                .filter_map(|usage| v8::String::new(scope, usage).map(Into::into))
                .collect();
            v8::Array::new_with_elements(scope, &items).into()
        }
        None => v8::undefined(scope).into(),
    });

    // 15: `serialNumber`.
    values.push(match der_accessors::serial_number(certificate) {
        Some(text) => string_or_empty(scope, &text),
        None => v8::undefined(scope).into(),
    });

    // 16: `raw`, the DER as a Buffer.
    values.push(match certificate.to_der().ok() {
        Some(der) => rn_bind_crypto_keys::buffer_from(scope, &der)
            .unwrap_or_else(|| v8::undefined(scope).into()),
        None => v8::undefined(scope).into(),
    });

    // 17-18: the ASN.1 and NIST curve names.
    values.extend(curves);

    object_with_slots(scope, &values)
}

/// Builds a plain object whose properties are `SLOTS` in order.
///
/// A plain object rather than a `DictionaryTemplate`: the template is a V8
/// startup optimisation in Node and its observable result is an ordinary object,
/// so the simpler construction is the same value.
fn object_with_slots<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    values: &[v8::Local<'s, v8::Value>],
) -> Option<v8::Local<'s, v8::Value>> {
    let object = v8::Object::new(scope);
    for (name, value) in SLOTS.iter().zip(values.iter()) {
        // `Set` (not `CreateDataProperty`) matches `X509ToObject`'s `Set` helper,
        // which skips undefined values: a missing slot reads `undefined` either
        // way, and skipping keeps the object's own-key list to the values that
        // are actually known.
        if value.is_undefined() {
            continue;
        }
        let key = v8::String::new(scope, name)?;
        object.set(scope, key.into(), *value);
    }
    Some(object.into())
}

/// Fills `modulus`, `exponent`, `pubkey`, `bits` and the two curve names.
///
/// Only two key families are handled, which is what `X509ToObject`'s `ifRsa` and
/// `ifEc` do: DSA certificates report no key details at all, and Ed25519 reports
/// none either, because neither has the `modulus`/`bits`/curve shape. That is not
/// a gap being papered over — it is the legacy shape.
fn fill_key_fields<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    fields: &mut [v8::Local<'s, v8::Value>; 4],
    curves: &mut [v8::Local<'s, v8::Value>; 2],
) {
    use foreign_types::ForeignTypeRef;
    let id = key.id();
    if id == openssl::pkey::Id::RSA || id == openssl::pkey::Id::RSA_PSS {
        // SAFETY: `EVP_PKEY_get_bn_param` allocates the `BIGNUM` it returns.
        unsafe {
            let modulus = bn_param(key.as_ptr(), c"n");
            if let Some(modulus) = modulus {
                // `GetModulusString` is `BIOPointer::New(n)` then the BIO's text,
                // which is `BN_print`'s hex form with no `0x` prefix.
                if let Some(text) = bn_hex(modulus) {
                    fields[0] = string_or_empty(scope, &text);
                }
                fields[3] =
                    v8::Integer::new(scope, openssl_sys::BN_num_bits(modulus) as i32).into();
                openssl_sys::BN_free(modulus);
            }
            if let Some(exponent) = bn_param(key.as_ptr(), c"e") {
                // `GetExponentString` prints `0x` and then `BN_print`.
                if let Some(text) = bn_hex(exponent) {
                    fields[1] = string_or_empty(scope, &format!("0x{text}"));
                }
                openssl_sys::BN_free(exponent);
            }
            // `GetPubKey` is `rsa.derPublicKey()`, i.e. `i2d_PUBKEY` over the
            // certificate's key, which is the SPKI.
            if let Some(der) = spki_of(key.as_ptr()) {
                fields[2] = rn_bind_crypto_keys::buffer_from(scope, &der)
                    .unwrap_or_else(|| v8::undefined(scope).into());
            }
        }
        return;
    }

    if id == openssl::pkey::Id::EC {
        // The EC public point in the key's own conversion form, which
        // `ECPointToBuffer` produces.
        // SAFETY: `key` is live and holds an EC key, which is what `id` proved.
        if let Some(point) = unsafe { ec_public_point(key.as_ptr()) } {
            fields[2] = rn_bind_crypto_keys::buffer_from(scope, &point)
                .unwrap_or_else(|| v8::undefined(scope).into());
        }
        // SAFETY: reads the key's curve, which the key owns.
        unsafe {
            let group = ec_group(key.as_ptr());
            if !group.is_null() {
                let bits = openssl_sys::EC_GROUP_order_bits(group);
                if bits > 0 {
                    fields[3] = v8::Integer::new(scope, bits).into();
                }
            }
            let nid = ec_curve_nid(key.as_ptr());
            if nid != 0 {
                if let Some(name) = short_name(nid) {
                    curves[0] = string_or_empty(scope, &name);
                }
                if let Some(name) = nist_name(nid) {
                    curves[1] = string_or_empty(scope, &name);
                }
            }
        }
    }
}

/// The legacy distinguished-name object: `{ CN: 'x', O: ['a', 'b'] }`.
///
/// `GetX509NameObject` builds it with a **null prototype**, keys it by the
/// attribute's *short name* rather than its OID, and repeats a name as an array
/// only when it occurs more than once. That array-on-repetition rule is why
/// `C=US\nO=X\nO=Y` gives `O: ['X', 'Y']` while a single `O` gives a bare
/// string.
///
/// The key is `OBJ_nid2sn`'s answer, falling back to the dotted OID for an OID
/// OpenSSL has no name for. `x509.js`'s `toLegacyObject()` and `getPeerCertificate`
/// both read these keys by attribute name, so keying by OID silently produces an
/// object whose `subject.CN` is `undefined`.
fn legacy_name<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    certificate: &X509,
    subject: bool,
) -> Option<v8::Local<'s, v8::Value>> {
    let inspection = extras::inspect_name(certificate, subject)?;
    // A null prototype, as `Object::New(isolate, Null(isolate), …)` does. The
    // distinction is observable: `deepStrictEqual` compares prototypes, and
    // `test-x509-escaping.js` compares these objects against
    // `Object.assign({__proto__: null}, …)`.
    let object = v8::Object::new(scope);
    let null = v8::null(scope);
    object.set_prototype(scope, null.into());

    for attribute in &inspection.attributes {
        let Some(value) = attribute.value.as_deref() else {
            // `GetX509NameObject` omits a value it cannot convert rather than
            // writing an empty string, keeping the valid siblings.
            continue;
        };
        let property = attribute.short_name.as_deref().unwrap_or(&attribute.oid);
        let key = v8::String::new(scope, property)?;
        let value = v8::String::new(scope, value)?;
        let existing = object.get(scope, key.into());
        match existing {
            Some(existing) if !existing.is_undefined() => {
                if let Ok(array) = v8::Local::<v8::Array>::try_from(existing) {
                    let length = array.length();
                    array.set_index(scope, length, value.into());
                } else {
                    let items = [existing, value.into()];
                    object.set(
                        scope,
                        key.into(),
                        v8::Array::new_with_elements(scope, &items).into(),
                    );
                }
            }
            _ => {
                object.set(scope, key.into(), value.into());
            }
        }
    }
    Some(object.into())
}

/// A string value, or `undefined` when the allocator fails.
fn string_or_empty<'s>(scope: &mut v8::PinScope<'s, '_>, text: &str) -> v8::Local<'s, v8::Value> {
    match v8::String::new(scope, text) {
        Some(value) => value.into(),
        None => v8::undefined(scope).into(),
    }
}

// `BIGNUM` helpers. `openssl-sys` exports `BN_num_bits` and `BN_free`; the
// parameter reader and the printer are declared here because the safe crate's
// equivalents are on its own `BigNum` type, which cannot be built over a borrowed
// pointer without taking ownership.
extern "C" {
    fn EVP_PKEY_get_bn_param(
        key: *const ffi::EVP_PKEY,
        name: *const std::ffi::c_char,
        out: *mut *mut ffi::BIGNUM,
    ) -> std::ffi::c_int;
    fn BN_print(bio: *mut ffi::BIO, value: *const ffi::BIGNUM) -> std::ffi::c_int;
    fn i2d_PUBKEY(key: *const ffi::EVP_PKEY, out: *mut *mut u8) -> std::ffi::c_int;
    fn EC_POINT_point2buf(
        group: *const ffi::EC_GROUP,
        point: *const ffi::EC_POINT,
        form: std::ffi::c_int,
        buf: *mut *mut u8,
        len: *mut usize,
    ) -> usize;
    fn EVP_PKEY_get0_EC_KEY(key: *const ffi::EVP_PKEY) -> *const ffi::EC_KEY;
    fn EC_KEY_get0_group(key: *const ffi::EC_KEY) -> *const ffi::EC_GROUP;
    fn EC_KEY_get0_public_key(key: *const ffi::EC_KEY) -> *const ffi::EC_POINT;
    fn EC_GROUP_get_curve_name(group: *const ffi::EC_GROUP) -> std::ffi::c_int;
    fn OBJ_nid2sn(nid: std::ffi::c_int) -> *const std::ffi::c_char;
    fn EC_curve_nid2nist(nid: std::ffi::c_int) -> *const std::ffi::c_char;
}

/// One numeric key parameter, owned by the caller.
///
/// # Safety
///
/// `key` must be a live `EVP_PKEY`.
unsafe fn bn_param(key: *const ffi::EVP_PKEY, name: &std::ffi::CStr) -> Option<*mut ffi::BIGNUM> {
    let mut value: *mut ffi::BIGNUM = std::ptr::null_mut();
    // SAFETY: the caller guarantees `key` is live, `name` is NUL-terminated, and
    // the returned `BIGNUM` is freed by the caller.
    let ok = unsafe { EVP_PKEY_get_bn_param(key, name.as_ptr(), &mut value) };
    (ok == 1 && !value.is_null()).then_some(value)
}

/// `BN_print`'s hex form, which is upper-case with no prefix.
///
/// # Safety
///
/// `value` must be a live `BIGNUM`.
unsafe fn bn_hex(value: *const ffi::BIGNUM) -> Option<String> {
    crate::bio::with_memory_bio(|bio| {
        // SAFETY: the BIO and the `BIGNUM` are both live for the call.
        unsafe { BN_print(bio.raw(), value) == 1 }
    })
}

/// `i2d_PUBKEY`: the SPKI of a key.
///
/// # Safety
///
/// `key` must be a live `EVP_PKEY`.
unsafe fn spki_of(key: *const ffi::EVP_PKEY) -> Option<Vec<u8>> {
    let mut pointer: *mut u8 = std::ptr::null_mut();
    // SAFETY: allocates with `OPENSSL_malloc`, copied out and freed below.
    unsafe {
        let length = i2d_PUBKEY(key, &mut pointer);
        if length <= 0 || pointer.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(pointer, length as usize).to_vec();
        ffi::OPENSSL_free(pointer.cast());
        Some(bytes)
    }
}

/// The EC public point in the key's conversion form.
///
/// # Safety
///
/// `key` must be a live `EVP_PKEY` holding an EC key.
unsafe fn ec_public_point(key: *const ffi::EVP_PKEY) -> Option<Vec<u8>> {
    // SAFETY: reads the key's EC component, which stays owned by `key`.
    unsafe {
        let ec = EVP_PKEY_get0_EC_KEY(key);
        if ec.is_null() {
            return None;
        }
        let group = EC_KEY_get0_group(ec);
        let point = EC_KEY_get0_public_key(ec);
        if group.is_null() || point.is_null() {
            return None;
        }
        // `POINT_CONVERSION_UNCOMPRESSED` is 4 and is what
        // `EC_KEY_get_conv_form` defaults to. A key generated with an explicit
        // form would report it here; the default is the same one
        // `ECPointToBuffer` uses for a certificate's key, because a certificate
        // carries no conversion form.
        const POINT_CONVERSION_UNCOMPRESSED: std::ffi::c_int = 4;
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let mut length: usize = 0;
        let written = EC_POINT_point2buf(
            group,
            point,
            POINT_CONVERSION_UNCOMPRESSED,
            &mut buffer,
            &mut length,
        );
        if written == 0 || buffer.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(buffer, length).to_vec();
        ffi::OPENSSL_free(buffer.cast());
        Some(bytes)
    }
}

/// The `EC_GROUP` of an EC key.
///
/// # Safety
///
/// `key` must be a live `EVP_PKEY`.
unsafe fn ec_group(key: *const ffi::EVP_PKEY) -> *const ffi::EC_GROUP {
    // SAFETY: reads the key's EC component.
    unsafe {
        let ec = EVP_PKEY_get0_EC_KEY(key);
        if ec.is_null() {
            return std::ptr::null();
        }
        EC_KEY_get0_group(ec)
    }
}

/// The curve's NID, or 0 for an unnamed curve.
///
/// # Safety
///
/// `key` must be a live `EVP_PKEY`.
unsafe fn ec_curve_nid(key: *const ffi::EVP_PKEY) -> i32 {
    // SAFETY: reads the key's EC component.
    unsafe {
        let group = ec_group(key);
        if group.is_null() {
            return 0;
        }
        EC_GROUP_get_curve_name(group)
    }
}

/// `OBJ_nid2sn`.
fn short_name(nid: i32) -> Option<String> {
    // SAFETY: returns a static NUL-terminated string or null.
    let pointer = unsafe { OBJ_nid2sn(nid) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: static string owned by OpenSSL.
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_str()
        .ok()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

/// `EC_curve_nid2nist`.
fn nist_name(nid: i32) -> Option<String> {
    // SAFETY: returns a static NUL-terminated string or null.
    let pointer = unsafe { EC_curve_nid2nist(nid) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: static string owned by OpenSSL.
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_str()
        .ok()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}
