//! OpenSSL error mapping: the `ERR_OSSL_*` shape Node's tests read.
//!
//! Node has two different error paths and they are not interchangeable:
//!
//! * `THROW_ERR_CRYPTO_*` throws a `NodeError` with a `code` such as
//!   `ERR_CRYPTO_INVALID_KEYTYPE` and no OpenSSL detail. That is the binding
//!   crate's job, because it needs the JavaScript error templates.
//! * `ThrowCryptoError` throws an ordinary `Error` whose `code` is derived from
//!   the packed OpenSSL error, e.g. `ERR_OSSL_EVP_BAD_DECRYPT`, plus `library`
//!   and `reason` fields. That is this module's job.
//!
//! The code is built from the *short* library id (`EVP`), not the library's
//! display name (`EVP routines`), and a test that only checks the message text
//! will not notice the difference.

/// One entry from OpenSSL's error queue, unpacked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSslError {
    /// The packed `unsigned long` OpenSSL returned.
    pub packed: u64,
    /// The library's short id, e.g. `"EVP"`. Empty when Node's `OSSL_ERROR_CODES_MAP`
    /// has no entry for the numeric id, which is the case for `ERR_LIB_PROVIDER`
    /// and `ERR_LIB_DECODER`.
    pub library: String,
    /// The library's *display* name, e.g. `"EVP routines"` or `"DECODER routines"`.
    ///
    /// This is what Node puts in the error's `library` property: it comes from
    /// `ERR_lib_error_string`, not from the code table, so a library with no code
    /// entry still reports its name.
    pub library_display: String,
    /// The reason string, e.g. `"bad decrypt"`.
    pub reason: String,
    /// `error:1C800064:Provider routines::bad decrypt`, which is what
    /// `ERR_error_string_n` produces.
    pub message: String,
}

impl OpenSslError {
    /// The `code` property: `ERR_OSSL_<LIBRARY>_<REASON>` with the reason's
    /// spaces and punctuation turned into underscores.
    ///
    /// This is `node::error::Decorate`. Two details come straight from it:
    ///
    /// * the library segment is empty for a library outside Node's table, which
    ///   is why a provider error is `ERR_OSSL_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE`
    ///   and not `ERR_OSSL_PROVIDER_...`; and
    /// * `SSL` drops the `OSSL_` prefix, because `ERR_OSSL_SSL_...` is a code
    ///   Node deliberately does not produce.
    pub fn code(&self) -> String {
        let library = self.library.to_ascii_uppercase();
        let reason: String = self
            .reason
            .to_ascii_uppercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        if library.is_empty() {
            return format!("ERR_OSSL_{reason}");
        }
        if library == "SSL" {
            return format!("ERR_{library}_{reason}");
        }
        format!("ERR_OSSL_{library}_{reason}")
    }
}

/// Pops the most recent error off OpenSSL's queue and unpacks it.
///
/// Returns `None` when the queue is empty, which happens when a caller reports a
/// failure that OpenSSL did not record — a loader that reports "not found"
/// without an error, for instance. Node treats that as "no OpenSSL detail" and
/// throws a plain `Error` with only the caller's message, so `None` here means
/// the same thing.
pub fn openssl_error() -> Option<OpenSslError> {
    // SAFETY: `ERR_get_error` only reads and mutates OpenSSL's thread-local
    // error queue. The strings it and the two lookups return are static and
    // NUL-terminated for the process' life.
    unsafe {
        let packed = openssl_sys::ERR_get_error();
        if packed == 0 {
            return None;
        }
        let display = c_string(openssl_sys::ERR_lib_error_string(packed));
        let reason = c_string(openssl_sys::ERR_reason_error_string(packed));
        let message = error_string(packed);
        Some(OpenSslError {
            packed,
            library: short_library_name(&display, openssl_sys::ERR_GET_LIB(packed)),
            reason,
            message,
            library_display: display,
        })
    }
}

/// Unpacks an already-popped packed OpenSSL error into its Node shape.
///
/// For callers that hold a packed value rather than a queue entry — most
/// importantly `ThrowCryptoError`, which receives one from a `ParseFailure` and
/// has to attach `library` and `reason` without touching the queue again.
pub fn openssl_error_for(packed: u64) -> Option<OpenSslError> {
    if packed == 0 {
        return None;
    }
    // SAFETY: the two lookups only read a packed value, and the strings they
    // return are static and NUL-terminated.
    unsafe {
        let display = c_string(openssl_sys::ERR_lib_error_string(packed));
        let display = if display.is_empty() {
            // The error table has no name for this library; the message already
            // carries whatever it could produce.
            String::new()
        } else {
            display
        };
        Some(OpenSslError {
            packed,
            library: short_library_name(&display, openssl_sys::ERR_GET_LIB(packed)),
            reason: c_string(openssl_sys::ERR_reason_error_string(packed)),
            message: error_string(packed),
            library_display: display,
        })
    }
}

/// `ERR_error_string_n`, which formats the packed value into the
/// `error:XXXXXXXX:library::reason` form.
fn error_string(packed: u64) -> String {
    // `ERR_error_string_n` is not exported by `openssl-sys`; it is declared
    // here. `ERR_error_string` (no length) is, but it writes into a static
    // buffer that is not thread-safe, and the packed value is already known so
    // the bounded form is both available and safer.
    extern "C" {
        fn ERR_error_string_n(packed: u64, buffer: *mut std::ffi::c_char, length: usize);
    }
    // 256 bytes is more than the longest string OpenSSL produces and is what
    // Node's `ThrowCryptoError` allocates.
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is `buffer.len()` bytes and the call writes at most
    // that many, NUL-terminating what it writes.
    unsafe {
        ERR_error_string_n(packed, buffer.as_mut_ptr().cast(), buffer.len());
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

/// Reads a `*const c_char` OpenSSL owns as a `String`, treating null or invalid
/// UTF-8 as empty rather than failing.
fn c_string(pointer: *const std::ffi::c_char) -> String {
    if pointer.is_null() {
        return String::new();
    }
    // SAFETY: the pointer is either null, handled above, or a static
    // NUL-terminated string owned by OpenSSL.
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

/// Clears OpenSSL's error queue.
///
/// Called after an operation whose failure is reported as a `NodeError` rather
/// than as OpenSSL detail, so a later `ThrowCryptoError` does not pick up this
/// operation's leftovers and report the wrong reason.
pub fn clear_error() {
    // SAFETY: only touches the thread-local error queue.
    unsafe { openssl_sys::ERR_clear_error() }
}

/// The three outcomes Node's `ParseKeyResult` distinguishes.
///
/// The difference between `NotRecognized` and `Failed` is load-bearing:
/// `GetPublicOrPrivateKeyFromJs` tries the public-key parser first and, when it
/// reports `NotRecognized`, falls back to the private-key parser. Treating "this
/// is not a public key" as a hard failure would make every `createPrivateKey`
/// call throw before it reached the parser that can read it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// The input is not a key of this kind at all.
    NotRecognized,
    /// The input is an encrypted key and a passphrase is required.
    NeedPassphrase,
    /// The input looked like a key and could not be parsed.
    Failed,
}

/// A failed parse: which of the three outcomes, plus the OpenSSL detail.
///
/// Node's `ncrypto::Result<EVPKeyPointer, PKParseError>` carries both fields,
/// because the caller needs the kind to decide whether to fall back to the other
/// parser and the detail to build `ThrowCryptoError`. Dropping the detail would
/// make a wrong-passphrase failure report only "Failed to read private key" with
/// no `code`, and `test-crypto-keygen-async-encrypted-private-key.js` asserts on
/// the code.
#[derive(Clone, Debug)]
pub struct ParseFailure {
    pub kind: ParseError,
    pub openssl_error: Option<OpenSslError>,
}

impl ParseFailure {
    /// The packed error, or 0 when OpenSSL recorded nothing. 0 is what
    /// `ThrowCryptoError` treats as "use the caller's message as-is".
    pub fn packed(&self) -> u64 {
        self.openssl_error.as_ref().map_or(0, |error| error.packed)
    }
}

/// A parse that either produced a key or reported why it could not.
pub type ParseResult<T> = Result<T, ParseFailure>;

/// Classifies a failure that came back as an `openssl::error::ErrorStack`.
///
/// `openssl`'s helpers drain the error queue into the returned `ErrorStack`, so by
/// the time a caller has one, `ERR_peek_error` sees nothing. Classifying from the
/// stack is therefore the only option, and it is also more precise than scanning
/// the queue after the fact.
pub fn failure_from(error: &openssl::error::ErrorStack) -> ParseFailure {
    from_error_stack(error, false)
}

/// [`failure_from`], with Node's `had_passphrase` flag.
///
/// # Why `PEM_R_BAD_PASSWORD_READ` decides it
///
/// Node's `keyOrError` checks `ERR_GET_LIB == ERR_LIB_PEM &&
/// ERR_GET_REASON == PEM_R_BAD_PASSWORD_READ` and reports `NEED_PASSPHRASE` only
/// when the caller supplied no passphrase. That marker is raised only by
/// `PEM_read_bio_PrivateKey` when its password callback failed, so its presence
/// means exactly "a passphrase was needed and not supplied".
///
/// Node tests only `ERR_peek_error` — the *oldest* entry — and on the OpenSSL this
/// binary links (**3.6.3**, not the 4.1.0 Node vendors) the marker is the *last*
/// of five entries. Scanning the whole stack is what keeps the distinction on
/// this version without weakening it: no other operation raises that reason.
pub fn from_error_stack(error: &openssl::error::ErrorStack, had_passphrase: bool) -> ParseFailure {
    let mut oldest: Option<OpenSslError> = None;
    let mut missing_passphrase = false;
    for entry in error.errors() {
        let (library, reason) = unpacked_ids(entry);
        if oldest.is_none() {
            oldest = Some(from_stack_entry(entry, library));
        }
        if library == ERR_LIB_PEM && reason == PEM_R_BAD_PASSWORD_READ {
            missing_passphrase = true;
        }
    }
    let kind = if missing_passphrase && !had_passphrase {
        ParseError::NeedPassphrase
    } else {
        ParseError::Failed
    };
    ParseFailure {
        kind,
        openssl_error: oldest,
    }
}

/// The library and reason ids of one `openssl` stack entry.
///
/// `openssl::error::Error` exposes `library()` and `reason()` as display-ready
/// strings, not the numeric ids, so they are taken from the packed value it
/// keeps. The packed form is `lib | func<<12 | reason<<23` in OpenSSL 3, which
/// `ERR_GET_LIB`/`ERR_GET_REASON` unpacks.
fn unpacked_ids(entry: &openssl::error::Error) -> (std::ffi::c_int, std::ffi::c_int) {
    let packed = entry.code();
    // `ERR_GET_LIB`/`ERR_GET_REASON` are pure unpackers, so no unsafe is needed.
    (
        openssl_sys::ERR_GET_LIB(packed),
        openssl_sys::ERR_GET_REASON(packed),
    )
}

/// Builds an [`OpenSslError`] from an `openssl` stack entry.
fn from_stack_entry(entry: &openssl::error::Error, library: std::ffi::c_int) -> OpenSslError {
    let packed = entry.code();
    // `Error::library`/`reason` are `Option<&str>`: they are `None` when OpenSSL
    // has no string for an id, which happens for provider-specific reasons the
    // linked build does not register. An absent name is reported as the empty
    // string rather than dropped, because the numeric ids are what
    // `ERR_OSSL_<LIB>_<REASON>` is built from.
    let display = entry.library().unwrap_or("");
    let reason_text = entry.reason().unwrap_or("");
    OpenSslError {
        packed,
        library: short_library_name(display, library),
        reason: reason_text.to_string(),
        message: error_string(packed),
        library_display: display.to_string(),
    }
}

/// Recovers the short library id from OpenSSL's display name.
///
/// `ERR_lib_error_string` returns names like `EVP routines`, `PEM routines`,
/// `Provider routines` and `Diffie-Hellman routines`; the code Node builds uses
/// the short id (`EVP`, `PEM`, `Provider`, `DH`). The first word of the display
/// name is the short id for all but a handful, and the handful are listed.
fn short_library_name(_display: &str, library: std::ffi::c_int) -> String {
    // Node maps the *numeric* library id through a fixed table
    // (`OSSL_ERROR_CODES_MAP` in `crypto_util.cc`) and leaves the segment empty
    // for anything outside it. That is why a provider error's code is
    // `ERR_OSSL_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE` with no `PROVIDER_` in it:
    // OpenSSL 3 introduced `ERR_LIB_PROVIDER`, which Node's table predates.
    //
    // The numbers are OpenSSL 3's `ERR_LIB_*` from `openssl/err.h`. They are not
    // guessable — `RSA` is 4, not 3, and `BIO` is 32, not 21 — and getting one
    // wrong produces a plausible code for the wrong library, so each is copied
    // from the header rather than inferred.
    match library {
        // `OSSL_ERROR_CODES_MAP`.
        2 => "SYS",
        3 => "BN",
        4 => "RSA",
        5 => "DH",
        6 => "EVP",
        7 => "BUF",
        8 => "OBJ",
        9 => "PEM",
        10 => "DSA",
        11 => "X509",
        13 => "ASN1",
        14 => "CONF",
        15 => "CRYPTO",
        16 => "EC",
        20 => "SSL",
        32 => "BIO",
        33 => "PKCS7",
        34 => "X509V3",
        36 => "RAND",
        38 => "ENGINE",
        39 => "OCSP",
        40 => "UI",
        41 => "COMP",
        42 => "ECDSA",
        43 => "ECDH",
        46 => "CMS",
        48 => "HMAC",
        128 => "USER",
        // `OSSL_ERROR_CODES_MAP_OPENSSL_ONLY`.
        35 => "PKCS12",
        37 => "DSO",
        44 => "OSSL_STORE",
        45 => "FIPS",
        47 => "TS",
        50 => "CT",
        51 => "ASYNC",
        52 => "KDF",
        53 => "SM2",
        // Outside the table: no library segment at all.
        _ => "",
    }
    .to_string()
}

/// The `ERR_OSSL_*` code for a packed error, without needing its display parts.
///
/// This is the form the bindings should use when they hold the packed value: it
/// reads the library id out of the value itself, so it cannot disagree with
/// OpenSSL about which library the error came from. Reverse-mapping a display
/// name is the alternative, and it is fragile — `"digital envelope routines"` is
/// `EVP`, `"Diffie-Hellman routines"` is `DH`, and a name not in the table
/// silently loses its segment.
pub fn ossl_code_for(packed: u64, reason: &str) -> String {
    let library = short_library_name("", openssl_sys::ERR_GET_LIB(packed));
    OpenSslError {
        packed,
        library,
        library_display: String::new(),
        reason: reason.to_string(),
        message: String::new(),
    }
    .code()
}

///
/// Used by paths that called OpenSSL directly rather than through the `openssl`
/// crate, so nothing has consumed the queue yet.
///
/// `not_recognized` is set by the caller when the reason is structural — the PEM
/// header was a different kind of key — rather than being an OpenSSL failure, and
/// in that case the queue is cleared so the fallback parser does not inherit it.
pub fn failure(not_recognized: bool) -> ParseFailure {
    failure_with_passphrase(not_recognized, false)
}

/// [`failure`], with Node's `had_passphrase` flag.
pub fn failure_with_passphrase(not_recognized: bool, had_passphrase: bool) -> ParseFailure {
    if not_recognized {
        clear_error();
        return ParseFailure {
            kind: ParseError::NotRecognized,
            openssl_error: None,
        };
    }
    let mut oldest: Option<OpenSslError> = None;
    let mut missing_passphrase = false;
    while let Some(error) = openssl_error() {
        // Every entry is scanned, not just the first: on OpenSSL 3.6.3 the
        // `PEM_R_BAD_PASSWORD_READ` marker is the *last* of five entries, while
        // Node's `ERR_peek_error` only ever sees the oldest.
        if openssl_sys::ERR_GET_LIB(error.packed) == ERR_LIB_PEM
            && openssl_sys::ERR_GET_REASON(error.packed) == PEM_R_BAD_PASSWORD_READ
        {
            missing_passphrase = true;
        }
        // The oldest entry is the root cause, and it is the one
        // `ThrowCryptoError` reports.
        if oldest.is_none() {
            oldest = Some(error);
        }
    }
    let kind = if missing_passphrase && !had_passphrase {
        ParseError::NeedPassphrase
    } else {
        ParseError::Failed
    };
    ParseFailure {
        kind,
        openssl_error: oldest,
    }
}

/// `ERR_LIB_PEM` from OpenSSL's `err.h`; `openssl-sys` does not export the
/// library ids.
const ERR_LIB_PEM: std::ffi::c_int = 9;
/// `PEM_R_BAD_PASSWORD_READ` from OpenSSL's `pemerr.h`.
const PEM_R_BAD_PASSWORD_READ: std::ffi::c_int = 104;
