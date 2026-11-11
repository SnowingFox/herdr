//! PEM and DER parsing with Node's three-outcome result.
//!
//! Importing a key is the one place where "what went wrong" has to be preserved
//! exactly, because `GetPublicOrPrivateKeyFromJs` uses the answer to decide which
//! parser to try next:
//!
//! ```text
//! TryParsePublicKeyPEM
//!   -> Ok          use the public key
//!   -> NOT_RECOGNIZED   fall back to TryParsePrivateKey
//!   -> anything else    throw "Failed to read asymmetric key"
//! ```
//!
//! So a private PEM passed to `createPublicKey`, and a public PEM passed to
//! `createPrivateKey`, both have to answer `NotRecognized` from the *wrong*
//! parser rather than failing. The check that produces that answer is structural
//! — does the PEM body carry a `PRIVATE KEY` header — and not an OpenSSL error.

use openssl::pkey::PKey as OpenSslPKey;

use crate::encode::{KeyEncoding, KeyFormat, PrivateKeyEncoding};
use crate::error::{clear_error, failure, failure_with_passphrase, ParseResult};
use crate::pkey::PKey;

/// Parses a private key from PEM, optionally with a passphrase.
///
/// This calls `PEM_read_bio_PrivateKey` directly instead of using
/// `openssl::pkey::PKey::private_key_from_pem_callback`, for one reason that
/// decides a whole error path: **the `openssl` crate's callback wrapper returns 0
/// when the closure reports an error** (`util::invoke_passwd_cb`, which even
/// carries a `FIXME restore error stack`). Returning 0 tells OpenSSL "here is a
/// zero-length passphrase", so an encrypted key fails with `bad decrypt`. Node's
/// `PasswordCallback` returns **-1**, which makes OpenSSL raise
/// `PEM_R_BAD_PASSWORD_READ` — and *that* is the marker `TryParsePrivateKey`
/// inspects to report `NEED_PASSPHRASE`, which becomes
/// `ERR_MISSING_PASSPHRASE`. With the crate's wrapper, every encrypted key
/// without a passphrase would report a decrypt failure instead.
///
/// It also means no prompt: with a null callback OpenSSL falls back to its default
/// UI method, which reads stdin.
pub fn parse_private_key_pem(bytes: &[u8], passphrase: Option<&[u8]>) -> ParseResult<PKey> {
    /// What the C callback receives as `user_data`.
    struct CallbackData<'a> {
        passphrase: Option<&'a [u8]>,
    }

    /// `pem_password_cb`: fills `buf` and returns the length, or -1 when no
    /// passphrase is available.
    unsafe extern "C" fn password_callback(
        buf: *mut std::ffi::c_char,
        size: std::ffi::c_int,
        _rwflag: std::ffi::c_int,
        user_data: *mut std::ffi::c_void,
    ) -> std::ffi::c_int {
        if user_data.is_null() || size <= 0 {
            return -1;
        }
        // SAFETY: `user_data` is the `&CallbackData` `parse_private_key_pem`
        // passes below, which outlives this call.
        let data = unsafe { &*(user_data as *const CallbackData<'_>) };
        let Some(passphrase) = data.passphrase else {
            return -1;
        };
        let size = size as usize;
        if passphrase.len() > size {
            return -1;
        }
        // SAFETY: `buf` points at `size` writable bytes, and the copy is bounded
        // by both the passphrase and that size.
        unsafe {
            std::ptr::copy_nonoverlapping(passphrase.as_ptr().cast(), buf, passphrase.len());
        }
        passphrase.len() as std::ffi::c_int
    }

    // A `CString` copy is not needed: `BIO_new_mem_buf` does not require a NUL
    // terminator, and reading past the end of a live slice is what the explicit
    // length prevents.
    // SAFETY: `bytes` is live for the whole call and its length is passed with
    // it; the returned BIO owns a copy and is freed exactly once below.
    let bio = unsafe {
        openssl_sys::BIO_new_mem_buf(bytes.as_ptr().cast(), bytes.len().try_into().unwrap_or(0))
    };
    if bio.is_null() {
        clear_error();
        return Err(failure(false));
    }
    let data = CallbackData { passphrase };
    // SAFETY: `bio` is live; the callback signature matches `pem_password_cb`,
    // and `data` outlives the call.
    let key = unsafe {
        openssl_sys::PEM_read_bio_PrivateKey(
            bio,
            std::ptr::null_mut(),
            Some(password_callback),
            (&data as *const CallbackData<'_>).cast_mut().cast(),
        )
    };
    // SAFETY: `bio` came from `BIO_new_mem_buf` and is owned here; nothing else
    // holds it. `BIO_free_all` is the only free `openssl-sys` exports, and it is
    // `BIO_free` for a BIO with no chain.
    unsafe { openssl_sys::BIO_free_all(bio) };
    if key.is_null() {
        return Err(failure_with_passphrase(false, passphrase.is_some()));
    }
    // SAFETY: `key` is a new reference from `PEM_read_bio_PrivateKey`, adopted by
    // `from_ptr` exactly once.
    use foreign_types::ForeignType;
    let key = unsafe { OpenSslPKey::from_ptr(key) };
    // A successful read can still leave entries behind (the PEM reader records
    // the "encrypted, so I asked" step); Node clears them through
    // `MarkPopErrorOnReturn`, and leaving them would give the next
    // `ThrowCryptoError` an unrelated reason.
    clear_error();
    Ok(PKey::from_private(key))
}

/// Parses a private key from DER.
pub fn parse_private_key_der(bytes: &[u8], encoding: KeyEncoding) -> ParseResult<PKey> {
    let key = match encoding {
        // SEC1 is EC-only, and `d2i_ECPrivateKey` on an RSA key fails with a
        // parse error rather than a type error, which is the right outcome.
        KeyEncoding::Sec1 => OpenSslPKey::private_key_from_der(bytes),
        // PKCS#1 is RSA-only. `PKey::private_key_from_der` is `d2i_PrivateKey`,
        // which reads the type-specific form — exactly PKCS#1 for RSA — whereas
        // `private_key_from_pkcs8` insists on the PKCS#8 wrapper. Using the
        // PKCS#8 reader for `KeyEncoding::Pkcs1` would reject every PKCS#1 key
        // `generateKeyPairSync` writes.
        KeyEncoding::Pkcs1 => OpenSslPKey::private_key_from_der(bytes),
        // PKCS#8, and also the default when the caller did not name one: Node
        // treats an unnamed type as PKCS#1 for the generate context and as
        // PKCS#8 for input, and `d2i_AutoPrivateKey` accepts both.
        KeyEncoding::Pkcs8 | KeyEncoding::Spki => OpenSslPKey::private_key_from_der(bytes),
    };
    match key {
        Ok(key) => Ok(PKey::from_private(key)),
        // `PKey::private_key_from_der` drains the queue into its `ErrorStack`, so
        // the failure is classified from there rather than from the (now empty)
        // queue. DER carries no passphrase, so `had_passphrase` is false.
        Err(error) => Err(crate::error::from_error_stack(&error, false)),
    }
}

/// Parses a public key from PEM, reporting `NotRecognized` for a private key.
///
/// This is `EVPKeyPointer::TryParsePublicKeyPEM`. The structural check comes
/// first: a PEM block whose header names a private key is not a public key, and
/// saying so lets the caller fall through to the private-key parser instead of
/// throwing.
pub fn parse_public_key_pem(bytes: &[u8]) -> ParseResult<PKey> {
    if looks_like_private_pem(bytes) {
        return Err(failure(true));
    }
    match OpenSslPKey::public_key_from_pem(bytes) {
        Ok(key) => match PKey::from_public(key) {
            Some(key) => Ok(key),
            None => Err(failure(false)),
        },
        Err(error) => {
            // A PEM block of some other kind — a certificate, a CSR, arbitrary
            // text — is "not a public key" rather than an OpenSSL failure.
            // Node draws the same line: `TryParsePublicKeyPEM` reports
            // NOT_RECOGNIZED when no recognised header is present.
            if !has_pem_header(bytes, b"PUBLIC KEY") && !has_pem_header(bytes, b"RSA PUBLIC KEY") {
                // The third step of `TryParsePublicKeyPEM`: an X.509 certificate
                // is accepted as a source of a public key. `crypto.createVerify`
                // is routinely called with a certificate instead of a key — every
                // TLS test does it — and `X509_get_pubkey` is what Node uses.
                if has_pem_header(bytes, b"CERTIFICATE") {
                    return parse_public_key_from_certificate_pem(bytes);
                }
                return Err(failure(true));
            }
            Err(crate::error::from_error_stack(&error, false))
        }
    }
}

/// `d2i_X509` then `X509_get_pubkey`: a certificate's public key.
///
/// A certificate that does not parse is `NotRecognized` rather than `Failed`,
/// which keeps `GetPublicOrPrivateKeyFromJs`'s fallback to the private-key parser
/// working: a caller can pass either kind and the wrong one is not fatal.
fn parse_public_key_from_certificate_pem(bytes: &[u8]) -> ParseResult<PKey> {
    let certificate = match openssl::x509::X509::from_pem(bytes) {
        Ok(certificate) => certificate,
        Err(_) => {
            crate::error::clear_error();
            return Err(failure(true));
        }
    };
    match certificate.public_key() {
        Ok(key) => PKey::from_public(key).ok_or_else(|| failure(false)),
        Err(_) => {
            crate::error::clear_error();
            Err(failure(false))
        }
    }
}

/// Parses a public key from DER.
pub fn parse_public_key_der(bytes: &[u8], encoding: KeyEncoding) -> ParseResult<PKey> {
    match encoding {
        KeyEncoding::Pkcs1 => openssl::rsa::Rsa::public_key_from_der_pkcs1(bytes)
            .ok()
            .and_then(|rsa| OpenSslPKey::from_rsa(rsa).ok())
            .and_then(PKey::from_public)
            .ok_or_else(|| failure(false)),
        // SPKI is what `i2d_PUBKEY` reads, and the other encodings are not
        // public-key encodings at all, so they are `NotRecognized`.
        KeyEncoding::Spki => OpenSslPKey::public_key_from_der(bytes)
            .ok()
            .and_then(PKey::from_public)
            .ok_or_else(|| failure(false)),
        KeyEncoding::Pkcs8 | KeyEncoding::Sec1 => Err(failure(true)),
    }
}

/// Parses a key whose kind is not known in advance, which is what
/// `createPublicKey` on a private key needs.
pub fn parse_public_or_private_key(
    bytes: &[u8],
    format: KeyFormat,
    encoding: Option<KeyEncoding>,
    passphrase: Option<&[u8]>,
) -> ParseResult<PKey> {
    match format {
        KeyFormat::Pem => {
            // PEM carries its own kind, so the public parser is tried first and
            // its `NotRecognized` answer is the signal to try the private one.
            match parse_public_key_pem(bytes) {
                Ok(key) => Ok(key),
                Err(error) if error.kind == crate::error::ParseError::NotRecognized => {
                    parse_private_key_pem(bytes, passphrase)
                }
                Err(error) => Err(error),
            }
        }
        KeyFormat::Der => {
            let encoding = encoding.unwrap_or(KeyEncoding::Pkcs8);
            match encoding {
                // A PKCS#1 DER block can hold either half, so try the public
                // reader and fall back to the private one. That is Node's
                // `is_public` branch: `!IsRSAPrivateKey(buffer)`.
                KeyEncoding::Pkcs1 => {
                    if is_rsa_private_der(bytes) {
                        parse_private_key_der(bytes, encoding)
                    } else {
                        parse_public_key_der(bytes, encoding)
                    }
                }
                KeyEncoding::Spki => parse_public_key_der(bytes, encoding),
                KeyEncoding::Pkcs8 | KeyEncoding::Sec1 => parse_private_key_der(bytes, encoding),
            }
        }
        _ => Err(failure(true)),
    }
}

/// Parses a private key given the encoding configuration the JavaScript sent.
pub fn parse_private_key(bytes: &[u8], config: &PrivateKeyEncoding) -> ParseResult<PKey> {
    let format = config.format.unwrap_or(KeyFormat::Pem);
    match format {
        KeyFormat::Pem => parse_private_key_pem(bytes, config.passphrase.as_deref()),
        KeyFormat::Der => {
            parse_private_key_der(bytes, config.encoding.unwrap_or(KeyEncoding::Pkcs8))
        }
        _ => Err(failure(true)),
    }
}

/// The generic entry point: parses either kind, given a configuration.
pub fn parse_public_key(
    bytes: &[u8],
    format: KeyFormat,
    encoding: Option<KeyEncoding>,
    passphrase: Option<&[u8]>,
) -> ParseResult<PKey> {
    parse_public_or_private_key(bytes, format, encoding, passphrase)
}

/// Whether a PEM block's header names a private key.
fn looks_like_private_pem(bytes: &[u8]) -> bool {
    has_pem_header(bytes, b"PRIVATE KEY")
        || has_pem_header(bytes, b"RSA PRIVATE KEY")
        || has_pem_header(bytes, b"EC PRIVATE KEY")
        || has_pem_header(bytes, b"DSA PRIVATE KEY")
        || has_pem_header(bytes, b"ENCRYPTED PRIVATE KEY")
        || has_pem_header(bytes, b"DH PARAMETERS")
}

/// Whether the bytes contain `-----BEGIN <label>-----`.
///
/// A structural scan rather than a parse: the question is which *kind* of PEM
/// block this is, and asking OpenSSL would conflate "not a public key" with
/// "a public key that does not parse".
fn has_pem_header(bytes: &[u8], label: &[u8]) -> bool {
    let mut header = Vec::with_capacity(label.len() + 16);
    header.extend_from_slice(b"-----BEGIN ");
    header.extend_from_slice(label);
    header.extend_from_slice(b"-----");
    bytes
        .windows(header.len())
        .any(|window| window == header.as_slice())
}

/// `EVPKeyPointer::IsRSAPrivateKey`: whether a DER block is a PKCS#1
/// `RSAPrivateKey`.
///
/// Both `RSAPrivateKey` and `RSAPublicKey` are a `SEQUENCE`, and their first
/// element is what distinguishes them: a private key starts with `INTEGER 0` (or
/// 1, for multi-prime) and a public key starts with the modulus, which is the
/// product of two primes and therefore at least 4. Node's test is therefore
/// `first three content bytes are 02 01 0X` with `0X & 0xFE == 0`, which this
/// reproduces exactly — a `02 01 02` would be a modulus of 2 and cannot occur.
///
/// Checking only for `0x02` at the content offset, as an earlier version did,
/// accepted any `SEQUENCE { INTEGER ...`, which a `RSAPublicKey`'s modulus
/// encoding also satisfies when the leading modulus byte happens to be tagged.
fn is_rsa_private_der(bytes: &[u8]) -> bool {
    let Some((offset, length)) = asn1_sequence(bytes) else {
        return false;
    };
    length >= 3
        && bytes[offset] == 0x02
        && bytes[offset + 1] == 0x01
        && (bytes[offset + 2] & 0xfe) == 0
}

/// `IsASN1Sequence`: the content offset and length of a top-level SEQUENCE.
///
/// Returns `None` for anything that is not a definite-length DER SEQUENCE large
/// enough for its own header.
fn asn1_sequence(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() < 2 || bytes[0] != 0x30 {
        return None;
    }
    let (header, length) = if bytes[1] & 0x80 == 0 {
        (2usize, usize::from(bytes[1]))
    } else {
        // A long-form length: the low seven bits say how many length bytes
        // follow. Anything over four is larger than a key and is rejected rather
        // than parsed.
        let count = usize::from(bytes[1] & 0x7f);
        if count == 0 || count > 4 || bytes.len() < 2 + count {
            return None;
        }
        let mut length = 0usize;
        for byte in &bytes[2..2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        (2 + count, length)
    };
    // The declared length has to fit the buffer, or the offsets below would read
    // past the end.
    if bytes.len() < header + length {
        return None;
    }
    Some((header, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_PRIVATE_PEM: &str = include_str!("../tests/data/rsa-2048.pem");

    fn rsa_public_pem() -> Vec<u8> {
        let key = OpenSslPKey::private_key_from_pem(RSA_PRIVATE_PEM.as_bytes()).expect("fixture");
        key.public_key_to_pem().expect("exports")
    }

    #[test]
    fn a_private_pem_is_not_recognized_as_a_public_key() {
        // This is the answer that makes `createPublicKey(privatePem)` fall
        // through to the private parser instead of throwing.
        let error = parse_public_key_pem(RSA_PRIVATE_PEM.as_bytes()).expect_err("not public");
        assert_eq!(error.kind, crate::error::ParseError::NotRecognized);
    }

    #[test]
    fn a_public_pem_parses() {
        let key = parse_public_key_pem(&rsa_public_pem()).expect("a public key");
        assert_eq!(key.algorithm(), Some(crate::algorithm::RSA));
        assert!(!key.has_private());
    }

    #[test]
    fn arbitrary_text_is_not_recognized() {
        let error = parse_public_key_pem(b"hello, world").expect_err("not a key");
        assert_eq!(error.kind, crate::error::ParseError::NotRecognized);
    }

    #[test]
    fn a_private_pem_parses_as_a_private_key() {
        let key = parse_private_key(RSA_PRIVATE_PEM.as_bytes(), &PrivateKeyEncoding::default())
            .expect("a private key");
        assert!(key.has_private());
        assert_eq!(key.bits(), 2048);
    }

    #[test]
    fn an_encrypted_pem_without_a_passphrase_needs_one() {
        let key = OpenSslPKey::private_key_from_pem(RSA_PRIVATE_PEM.as_bytes()).expect("fixture");
        let encrypted = key
            .private_key_to_pem_pkcs8_passphrase(
                openssl::symm::Cipher::aes_128_cbc(),
                b"correct-horse",
            )
            .expect("encrypts");

        let error = parse_private_key(&encrypted, &PrivateKeyEncoding::default())
            .expect_err("needs a passphrase");
        assert_eq!(error.kind, crate::error::ParseError::NeedPassphrase);

        let config = PrivateKeyEncoding {
            passphrase: Some(b"correct-horse".to_vec()),
            ..Default::default()
        };
        assert!(parse_private_key(&encrypted, &config).is_ok());

        let wrong = PrivateKeyEncoding {
            passphrase: Some(b"wrong".to_vec()),
            ..Default::default()
        };
        assert!(parse_private_key(&encrypted, &wrong).is_err());
    }

    #[test]
    fn pem_round_trips_both_kinds_through_the_generic_parser() {
        let public = parse_public_or_private_key(&rsa_public_pem(), KeyFormat::Pem, None, None)
            .expect("a public key");
        assert!(!public.has_private());

        let private =
            parse_public_or_private_key(RSA_PRIVATE_PEM.as_bytes(), KeyFormat::Pem, None, None)
                .expect("a private key");
        assert!(private.has_private());
    }

    #[test]
    fn der_pkcs1_distinguishes_the_two_halves() {
        let key = OpenSslPKey::private_key_from_pem(RSA_PRIVATE_PEM.as_bytes()).expect("fixture");

        let private_der = key
            .rsa()
            .expect("RSA")
            .private_key_to_der()
            .expect("exports");
        assert!(is_rsa_private_der(&private_der));
        let parsed = parse_public_or_private_key(
            &private_der,
            KeyFormat::Der,
            Some(KeyEncoding::Pkcs1),
            None,
        )
        .expect("parses");
        assert!(parsed.has_private());

        let public_der = key
            .rsa()
            .expect("RSA")
            .public_key_to_der_pkcs1()
            .expect("exports");
        assert!(!is_rsa_private_der(&public_der));
        let parsed = parse_public_or_private_key(
            &public_der,
            KeyFormat::Der,
            Some(KeyEncoding::Pkcs1),
            None,
        )
        .expect("parses");
        assert!(!parsed.has_private());
    }

    #[test]
    fn an_spki_der_parses_as_public_and_pkcs8_as_private() {
        let key = OpenSslPKey::private_key_from_pem(RSA_PRIVATE_PEM.as_bytes()).expect("fixture");
        let spki = key.public_key_to_der().expect("exports");
        let pkcs8 = key.private_key_to_pkcs8().expect("exports");

        assert!(!parse_public_key_der(&spki, KeyEncoding::Spki)
            .expect("SPKI is a public encoding")
            .has_private());
        assert!(parse_private_key_der(&pkcs8, KeyEncoding::Pkcs8)
            .expect("PKCS#8 is a private encoding")
            .has_private());
    }

    #[test]
    fn a_pem_header_scan_finds_the_block_kind() {
        // The fixture is a PKCS#8 `PRIVATE KEY`; the type-specific headers are
        // what a SEC1 or PKCS#1 export would carry, so the scan is exercised on
        // synthesised blocks rather than on a header this fixture does not have.
        assert!(has_pem_header(RSA_PRIVATE_PEM.as_bytes(), b"PRIVATE KEY"));
        assert!(has_pem_header(
            b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n",
            b"RSA PRIVATE KEY"
        ));
        assert!(!has_pem_header(RSA_PRIVATE_PEM.as_bytes(), b"PUBLIC KEY"));
        // A prefix of a longer label must not match: `PRIVATE KEY` is inside
        // `ENCRYPTED PRIVATE KEY`, so the scan has to anchor on `-----BEGIN `.
        assert!(!has_pem_header(
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
            b"PRIVATE KEY"
        ));
    }

    #[test]
    fn a_clear_failure_clears_the_queue() {
        // A failed parse must not leave its OpenSSL error behind for the next
        // `ThrowCryptoError` to report as this one's cause.
        let _ = parse_private_key_pem(
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            None,
        );
        assert!(
            crate::error::openssl_error().is_none(),
            "the queue is drained"
        );
        clear_error();
    }
}
