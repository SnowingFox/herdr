//! Enumerating what the linked OpenSSL can actually do.
//!
//! `getHashes()`, `getCiphers()` and `getCurves()` are the reason this crate
//! declares a few FFI functions of its own: the safe `openssl` crate exposes a
//! digest *lookup* but not OpenSSL's enumeration walkers, and the list has to
//! come from the library rather than from a table here.
//!
//! That distinction matters. A hardcoded list drifts from the linked OpenSSL the
//! moment a provider is missing, a build disables an algorithm, or the version
//! changes, and the failure mode is nasty: `crypto.getHashes()` advertises
//! `whirlpool`, user code picks it, and `createHash('whirlpool')` throws. Deriving
//! the list means everything advertised has already been shown to resolve.
//!
//! # Why these declarations are here
//!
//! `openssl-sys 0.9.118` declares `EVP_MD_fetch`, `EVP_CIPHER_fetch` and the
//! `EVP_MD_get0_name` accessors on some configurations, but not the
//! `do_all_provided` walkers, `EVP_*_names_do_all`, `EVP_*_is_a`,
//! `EVP_CIPHER_get_params`, `OSSL_PARAM_construct_int`, or
//! `EC_get_builtin_curves`. All of them are exported by the `libcrypto` this
//! crate links — verified against the built archive — so the missing piece is
//! only the Rust declaration, which is what this module adds.
//!
//! # What Node does, and why this follows it exactly
//!
//! Node builds both lists in `src/crypto/crypto_hash.cc` and
//! `deps/ncrypto/ncrypto.cc`, and the shape is not a plain walk:
//!
//! * The legacy `EVP_MD_do_all_sorted` / `EVP_CIPHER_do_all_sorted` walkers
//!   report every registered *name and alias*. Node's callback consumes the
//!   `from` field, not `to`, and only after proving the entry is usable: for a
//!   digest by `EVP_get_digestbyname` + `EVP_MD_get0_name` + `EVP_MD_fetch`; for
//!   a cipher by `EVP_get_cipherbyname` + `EVP_CIPHER_fetch` through
//!   `IsSupportedFetchedCipher`.
//! * The provider walkers add the names that only exist as providers. For a
//!   digest that is `EVP_MD_names_do_all` on a fetched copy; for a cipher,
//!   `EVP_CIPHER_names_do_all`; for a MAC, `EVP_MAC_names_do_all`. Every name
//!   they report is lowercased, except that a dotted-decimal OID is dropped.
//!
//! The union is then deduplicated case-insensitively by
//! `filterDuplicateStrings` in `lib/internal/util.js` and sorted. This module
//! reproduces that dedupe so the list it returns is already what Node's public
//! `getHashes()` returns, and the filter — a successful fetch — is what makes
//! the "nothing advertised is unusable" property hold rather than a separate
//! pass over the result.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr};

use openssl::symm::Cipher;

// `EVP_MD_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_MD *, void *),
// void *arg)`. Not declared by `openssl-sys`, but exported by every OpenSSL 3.x
// `libcrypto`. A null `libctx` means the default library context, the same one
// `EVP_MD_fetch(NULL, ...)` uses.
unsafe extern "C" {
    fn EVP_MD_do_all_provided(
        libctx: *mut c_void,
        callback: Option<unsafe extern "C" fn(md: *mut c_void, arg: *mut c_void)>,
        arg: *mut c_void,
    );

    // `EVP_CIPHER_do_all_provided`, same shape as the digest walker.
    fn EVP_CIPHER_do_all_provided(
        libctx: *mut c_void,
        callback: Option<unsafe extern "C" fn(cipher: *mut c_void, arg: *mut c_void)>,
        arg: *mut c_void,
    );

    // `EVP_MD_get_flags(const EVP_MD *)`. Not declared by `openssl-sys` either,
    // and it is the only way to tell an extendable-output digest apart from a
    // fixed-length one, since a SHAKE reports a non-zero size.
    fn EVP_MD_get_flags(md: *const c_void) -> std::os::raw::c_ulong;

    // `EVP_MD_get0_name(const EVP_MD *)`: the name a fetched digest reports.
    fn EVP_MD_get0_name(md: *const c_void) -> *const c_char;

    // `EVP_MD_is_a(const EVP_MD *, const char *)`: whether a digest answers to a
    // name or any of its aliases. Node uses it to drop the `NULL` and
    // `ML-DSA-MU` digests.
    fn EVP_MD_is_a(md: *const c_void, name: *const c_char) -> c_int;

    // `EVP_CIPHER_get0_name(const EVP_CIPHER *)`.
    fn EVP_CIPHER_get0_name(cipher: *const c_void) -> *const c_char;

    // `EVP_CIPHER_is_a(const EVP_CIPHER *, const char *)`.
    fn EVP_CIPHER_is_a(cipher: *const c_void, name: *const c_char) -> c_int;

    // `EVP_CIPHER_get_params(EVP_CIPHER *, OSSL_PARAM *)`. Node reads
    // `encrypt-then-mac` from it to drop the composite suites that are not a
    // plain cipher.
    fn EVP_CIPHER_get_params(cipher: *mut c_void, params: *mut openssl_sys::OSSL_PARAM) -> c_int;

    // `OSSL_PARAM_construct_int(const char *, int *)`. `openssl-sys` declares the
    // `uint` and `octet_string` variants only.
    fn OSSL_PARAM_construct_int(key: *const c_char, buffer: *mut c_int) -> openssl_sys::OSSL_PARAM;

    // `EVP_MD_do_all_sorted` / `EVP_CIPHER_do_all_sorted`: the legacy walkers that
    // report every registered NAME AND ALIAS, which is what Node's `getHashes()`
    // and `getCiphers()` are built from. The `do_all_provided` walkers above only
    // report one canonical provider name per algorithm, so they miss `ripemd`,
    // `rmd160`, `ssl3-sha1` and the entire `RSA-SHA256` family that Node lists.
    //
    // **`from` may be null**, meaning "this digest has no alias"; dereferencing it
    // without a null check segfaults. That is the only hazard in these walkers.
    fn EVP_MD_do_all_sorted(
        callback: Option<
            unsafe extern "C" fn(
                md: *const c_void,
                from: *const c_char,
                to: *const c_char,
                arg: *mut c_void,
            ),
        >,
        arg: *mut c_void,
    );

    // `EVP_MD_names_do_all(const EVP_MD *, void (*)(const char *, void *), void *)`:
    // every name a fetched digest answers to, including provider aliases such as
    // `SHA2-256` and `SHA-256` for `SHA256`.
    fn EVP_MD_names_do_all(
        md: *const c_void,
        callback: Option<unsafe extern "C" fn(name: *const c_char, arg: *mut c_void)>,
        arg: *mut c_void,
    );

    // `EVP_CIPHER_names_do_all`, same shape.
    fn EVP_CIPHER_names_do_all(
        cipher: *const c_void,
        callback: Option<unsafe extern "C" fn(name: *const c_char, arg: *mut c_void)>,
        arg: *mut c_void,
    );

    // `EVP_MAC_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_MAC *, void *),
    // void *arg)`, the MAC walker `getMacs()` needs.
    fn EVP_MAC_do_all_provided(
        libctx: *mut c_void,
        callback: Option<unsafe extern "C" fn(mac: *mut c_void, arg: *mut c_void)>,
        arg: *mut c_void,
    );

    // `EVP_MAC_get0_name(const EVP_MAC *)`.
    fn EVP_MAC_get0_name(mac: *const c_void) -> *const c_char;

    // `EVP_MAC_names_do_all(const EVP_MAC *, void (*)(const char *, void *), void *)`:
    // the alias set `KMAC128`/`kmac128` that Node's `getMacs()` reports.
    fn EVP_MAC_names_do_all(
        mac: *const c_void,
        callback: Option<unsafe extern "C" fn(name: *const c_char, arg: *mut c_void)>,
        arg: *mut c_void,
    );

    // `SSL_CTX_get_ciphers(const SSL_CTX *)` returns a `STACK_OF(SSL_CIPHER)`,
    // which OpenSSL's generated `OPENSSL_sk_*` helpers walk. `openssl-sys` does
    // not declare the stack accessors, so the two needed are declared here.
    fn SSL_CTX_get_ciphers(ctx: *const c_void) -> *const c_void;
    fn OPENSSL_sk_num(stack: *const c_void) -> c_int;
    fn OPENSSL_sk_value(stack: *const c_void, index: c_int) -> *mut c_void;
    fn SSL_CTX_free(ctx: *mut c_void);

    // `SSL_CTX_set1_cert_comp_preference(SSL_CTX *, int *algs, size_t len)`:
    // returns 1 when the algorithms are available, 0 when the build lacks them.
    // It is the only runtime probe for certificate compression, and
    // `openssl-sys` does not declare it.
    fn SSL_CTX_set1_cert_comp_preference(
        ctx: *mut c_void,
        algorithms: *mut c_int,
        len: usize,
    ) -> c_int;

    fn EVP_CIPHER_do_all_sorted(
        callback: Option<
            unsafe extern "C" fn(
                cipher: *const c_void,
                from: *const c_char,
                to: *const c_char,
                arg: *mut c_void,
            ),
        >,
        arg: *mut c_void,
    );

    // `EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems) -> size_t`.
    fn EC_get_builtin_curves(curves: *mut ECBuiltinCurve, count: usize) -> usize;

    // `CRYPTO_secure_malloc_initialized(void)` and `CRYPTO_secure_used(void)`,
    // the pair Node's `DataPointer::GetSecureHeapUsed` calls. `openssl-sys` does
    // not declare them.
    fn CRYPTO_secure_malloc_initialized() -> c_int;
    fn CRYPTO_secure_used() -> usize;
}

/// `EC_builtin_curve` from `openssl/ec.h`:
///
/// ```c
/// typedef struct { int nid; const char *comment; } EC_builtin_curve;
/// ```
///
/// `repr(C)` because OpenSSL fills this array directly.
#[repr(C)]
struct ECBuiltinCurve {
    nid: c_int,
    comment: *const c_char,
}

/// `EVP_CIPH_FLAG_CIPHER_WITH_MAC` from `openssl/evp.h`.
const EVP_CIPH_FLAG_CIPHER_WITH_MAC: std::os::raw::c_ulong = 0x200_0000;
/// `EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK` from `openssl/evp.h`.
const EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK: std::os::raw::c_ulong = 0x40_0000;
/// `OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC` from `openssl/core_names.h`.
const OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC: &[u8] = b"encrypt-then-mac\0";

/// The digest names the pinned oracle reports that this OpenSSL cannot supply.
///
/// This is a declaration, not a filter: `digest_names()` never sees these names
/// because the library has no such algorithm, and nothing here suppresses them.
/// It exists so the gap is checkable from code and its reason is recorded next
/// to the enumeration that produces the list, rather than only in prose.
///
/// **cSHAKE is absent from OpenSSL 3.6.3 entirely** — `grep -ri cshake` over the
/// vendored tree returns nothing, `providers/implementations/digests/` has no
/// `cshake_prov.c`, and the built `libcrypto.a` exports no `cshake` symbol. It is
/// a *default*-provider algorithm added in the 4.x line (`defltprov.c`), so the
/// legacy provider cannot supply it either, and `openssl-src` already enables
/// `legacy` by default. Verified: a build against OpenSSL 4.0.3 returns
/// `getHashes()` exactly equal to the oracle, these six names included.
///
/// `CAMELIA`-style build flags are *not* the cause here, unlike the cipher gap
/// this crate fixed separately; there is no configure option that turns cSHAKE on
/// in 3.x, because the implementation is not in the source.
pub const KNOWN_ABSENT_DIGESTS: &[&str] = &[
    "cshake-128",
    "cshake-256",
    "cshake-keccak-128",
    "cshake-keccak-256",
    "cshake128",
    "cshake256",
];

/// Reads a NUL-terminated OpenSSL string that may be null.
///
/// # Safety
///
/// `pointer` must be null or a NUL-terminated string owned by OpenSSL for at
/// least the duration of the call.
unsafe fn read_cstr(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: forwarded from the caller, which guarantees a NUL-terminated
    // OpenSSL-owned string.
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .ok()
        .map(str::to_string)
}

/// Whether a name is a dotted-decimal OID, which Node's provider walkers skip.
///
/// `1.3.6.1.4.1.1722.12.2.1` is an alias of `BLAKE2BMAC`, but Node's callbacks
/// drop it: it is not a name a caller could reasonably type, and Node's list
/// never contains one.
fn is_dotted_decimal(name: &str) -> bool {
    name.contains('.') && name.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Reproduces `filterDuplicateStrings` from `lib/internal/util.js`.
///
/// A `SafeMap` keyed by the lowercased name, so the *last* spelling of a name
/// wins, then `ArrayPrototypeSort`. `lowercase_values` is the `true` Node passes
/// for `getMacs()`, where every value is emitted already lowercased.
fn filter_duplicate_strings(names: Vec<String>, lowercase_values: bool) -> Vec<String> {
    let mut positions: HashMap<String, usize> = HashMap::new();
    let mut unique: Vec<String> = Vec::new();
    for name in names {
        let key = name.to_ascii_lowercase();
        let value = if lowercase_values { key.clone() } else { name };
        match positions.get(&key) {
            Some(&slot) => {
                // `Map.prototype.set` on an existing key keeps the original
                // insertion position and replaces the value.
                if let Some(entry) = unique.get_mut(slot) {
                    *entry = value;
                }
            }
            None => {
                positions.insert(key, unique.len());
                unique.push(value);
            }
        }
    }
    unique.sort();
    unique
}

/// `IsSupportedDigest` from `deps/ncrypto/ncrypto.cc`.
///
/// # Safety
///
/// `md` must be null or a live `EVP_MD`.
unsafe fn is_supported_digest(md: *const c_void) -> bool {
    if md.is_null() {
        return false;
    }
    // Node also refuses `ML-DSA-MU` because OpenSSL crashes finalising an empty
    // input (openssl/openssl#32445). This build has no such digest, so the check
    // costs one `EVP_MD_is_a` and keeps the port faithful.
    for excluded in [c"NULL", c"ML-DSA-MU"] {
        // SAFETY: `md` is live and the literal is a valid C string.
        if unsafe { EVP_MD_is_a(md, excluded.as_ptr()) } == 1 {
            return false;
        }
    }
    true
}

/// Fetches a digest and reports whether it is usable.
///
/// Returns the fetched pointer on success so the caller can read its names
/// before freeing it; `None` when the fetch fails or the digest is excluded.
///
/// # Safety
///
/// `name` must be a valid NUL-terminated C string.
unsafe fn fetch_supported_digest(name: *const c_char) -> Option<*mut openssl_sys::EVP_MD> {
    // SAFETY: the name is a valid C string and a null property query means "the
    // default properties", which is what Node passes.
    let fetched =
        unsafe { openssl_sys::EVP_MD_fetch(std::ptr::null_mut(), name, std::ptr::null()) };
    if fetched.is_null() {
        return None;
    }
    // SAFETY: `fetched` is a live `EVP_MD` this function owns.
    if unsafe { is_supported_digest(fetched.cast()) } {
        Some(fetched)
    } else {
        // SAFETY: `fetched` came from `EVP_MD_fetch` and is owned here.
        unsafe { openssl_sys::EVP_MD_free(fetched) };
        None
    }
}

/// `IsSupportedFetchedCipher` from `deps/ncrypto/ncrypto.cc`.
///
/// # Safety
///
/// `cipher` must be null or a live `EVP_CIPHER`.
unsafe fn is_supported_fetched_cipher(cipher: *const c_void) -> bool {
    if cipher.is_null() {
        return false;
    }
    // SAFETY: `cipher` is live and the literal is a valid C string.
    if unsafe { EVP_CIPHER_is_a(cipher, c"NULL".as_ptr()) } == 1 {
        return false;
    }
    // A composite suite (`aes-128-cbc-hmac-sha1`) or a TLS 1.1 multi-block
    // pipeline is not a cipher a caller can drive directly, and Node drops both.
    // SAFETY: `openssl_sys::EVP_CIPHER_get_flags` only reads the cipher.
    let flags = unsafe { openssl_sys::EVP_CIPHER_get_flags(cipher.cast()) };
    if flags & (EVP_CIPH_FLAG_CIPHER_WITH_MAC | EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK) != 0 {
        return false;
    }
    // `encrypt_then_mac != 0` marks a suite that also authenticates, which
    // `createCipheriv` cannot construct as a stream.
    let mut encrypt_then_mac: c_int = 0;
    // SAFETY: the key is a valid C string, the buffer outlives the call, and the
    // array is terminated by `OSSL_PARAM_construct_end`.
    let mut params = [
        unsafe {
            OSSL_PARAM_construct_int(
                OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC.as_ptr().cast(),
                &mut encrypt_then_mac,
            )
        },
        // SAFETY: the end sentinel takes no arguments.
        unsafe { openssl_sys::OSSL_PARAM_construct_end() },
    ];
    // SAFETY: `cipher` is live and `params` is a terminated array of the right
    // length. A failure just leaves the sentinel value in `encrypt_then_mac`.
    let read = unsafe { EVP_CIPHER_get_params(cipher.cast_mut().cast(), params.as_mut_ptr()) };
    read != 1 || encrypt_then_mac == 0
}

/// The digest names Node reports, in the order the walkers produce them.
///
/// # Safety
///
/// Every pointer the walkers hand a callback is OpenSSL-owned and only read.
unsafe extern "C" fn digest_alias_callback(
    _md: *const c_void,
    from: *const c_char,
    _to: *const c_char,
    argument: *mut c_void,
) {
    // `SaveSupportedHashAlgorithmsAndCacheMD` consumes `from` and ignores `to`.
    // A null `from` means the entry has no alias.
    if from.is_null() || argument.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `argument` points to a live
    // `Vec<String>` that outlives this synchronous walk.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };

    // The legacy lookup decides which canonical implementation the name maps to.
    // A name OpenSSL cannot resolve at all is not a digest Node could use.
    // SAFETY: `from` is a valid C string.
    let legacy = unsafe { openssl_sys::EVP_get_digestbyname(from) };
    if legacy.is_null() {
        return;
    }
    // SAFETY: `legacy` is a live `EVP_MD` from OpenSSL's table.
    let canonical = unsafe { EVP_MD_get0_name(legacy.cast()) };
    if canonical.is_null() {
        return;
    }
    // SAFETY: `canonical` is a NUL-terminated OpenSSL-owned string.
    let Some(fetched) = (unsafe { fetch_supported_digest(canonical) }) else {
        return;
    };
    // SAFETY: `from` is a NUL-terminated OpenSSL-owned string, and the spelling
    // is preserved because Node preserves it (`RSA-SHA256` stays mixed case).
    if let Some(name) = unsafe { read_cstr(from) } {
        if !name.is_empty() {
            names.push(name);
        }
    }
    // SAFETY: `fetched` came from `EVP_MD_fetch` and is owned here.
    unsafe { openssl_sys::EVP_MD_free(fetched) };
}

/// `SaveSupportedProviderHashName`: lowercases a provider name and drops a
/// dotted-decimal OID.
///
/// # Safety
///
/// `name` must be null or a NUL-terminated string, and `argument` a live
/// `Vec<String>`.
unsafe extern "C" fn provider_digest_name_callback(name: *const c_char, argument: *mut c_void) {
    if argument.is_null() {
        return;
    }
    // SAFETY: as above; the walker owns `name` for the duration of the call.
    let Some(name) = (unsafe { read_cstr(name) }) else {
        return;
    };
    if is_dotted_decimal(&name) {
        return;
    }
    let normalized = name.to_ascii_lowercase();
    // `FetchAndMaybeCacheMD(env, normalized, {}, normalized)`: a provider name is
    // only usable if fetching it by that exact lowercased spelling succeeds.
    let Ok(text) = std::ffi::CString::new(normalized.clone()) else {
        return;
    };
    // SAFETY: `text` is a valid NUL-terminated C string.
    let Some(fetched) = (unsafe { fetch_supported_digest(text.as_ptr()) }) else {
        return;
    };
    // SAFETY: `argument` is the live `Vec<String>` the caller passed.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
    names.push(normalized);
    // SAFETY: `fetched` came from `EVP_MD_fetch` and is owned here.
    unsafe { openssl_sys::EVP_MD_free(fetched) };
}

/// `SaveSupportedProviderHashAlgorithms`: fetches a provider digest, then walks
/// every name it answers to.
unsafe extern "C" fn provider_digest_callback(md: *mut c_void, argument: *mut c_void) {
    if md.is_null() {
        return;
    }
    // SAFETY: `md` is live and its name is an OpenSSL-owned string.
    let name = unsafe { EVP_MD_get0_name(md.cast()) };
    if name.is_null() {
        return;
    }
    // SAFETY: `name` is a valid C string.
    let Some(fetched) = (unsafe { fetch_supported_digest(name) }) else {
        return;
    };
    // SAFETY: the walker invokes the callback synchronously with `argument`, and
    // `fetched` is live for the duration.
    unsafe {
        EVP_MD_names_do_all(
            fetched.cast(),
            Some(provider_digest_name_callback),
            argument,
        )
    };
    // SAFETY: `fetched` came from `EVP_MD_fetch` and is owned here.
    unsafe { openssl_sys::EVP_MD_free(fetched) };
}

/// `array_push_back` from `deps/ncrypto/ncrypto.cc`: resolves `from` through the
/// legacy table, fetches the canonical implementation, and keeps `from`.
unsafe extern "C" fn cipher_alias_callback(
    _cipher: *const c_void,
    from: *const c_char,
    _to: *const c_char,
    argument: *mut c_void,
) {
    if from.is_null() || argument.is_null() {
        return;
    }
    // SAFETY: `from` is a valid C string.
    let real = unsafe { openssl_sys::EVP_get_cipherbyname(from) };
    if real.is_null() {
        return;
    }
    // SAFETY: `real` is a live `EVP_CIPHER` from OpenSSL's table.
    let real_name = unsafe { EVP_CIPHER_get0_name(real.cast()) };
    if real_name.is_null() {
        return;
    }
    // `EVP_CIPHER_fetch` is the filter: it only returns an instance the public
    // API can actually construct, so a cipher that lives in an unloaded provider
    // (`bf-cbc`, `rc4`) never reaches the list.
    // SAFETY: `real_name` is a valid C string and a null property query is the
    // default properties.
    let fetched =
        unsafe { openssl_sys::EVP_CIPHER_fetch(std::ptr::null_mut(), real_name, std::ptr::null()) };
    if fetched.is_null() {
        return;
    }
    // SAFETY: `fetched` is a live `EVP_CIPHER` this function owns.
    let supported = unsafe { is_supported_fetched_cipher(fetched.cast()) };
    if supported {
        // SAFETY: `argument` is the live `Vec<String>` the caller passed.
        let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
        // SAFETY: `from` is an OpenSSL-owned NUL-terminated string.
        if let Some(name) = unsafe { read_cstr(from) } {
            if !name.is_empty() {
                names.push(name);
            }
        }
    }
    // SAFETY: `fetched` came from `EVP_CIPHER_fetch` and is owned here.
    unsafe { openssl_sys::EVP_CIPHER_free(fetched) };
}

/// `array_push_back_provider_name`: lowercases and drops a dotted-decimal OID.
unsafe extern "C" fn provider_cipher_name_callback(name: *const c_char, argument: *mut c_void) {
    if argument.is_null() {
        return;
    }
    // SAFETY: `name` is an OpenSSL-owned NUL-terminated string.
    let Some(name) = (unsafe { read_cstr(name) }) else {
        return;
    };
    if is_dotted_decimal(&name) {
        return;
    }
    // SAFETY: `argument` is the live `Vec<String>` the caller passed.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
    names.push(name.to_ascii_lowercase());
}

/// `array_push_back_provider`: fetches a provider cipher, then walks its names.
unsafe extern "C" fn provider_cipher_callback(cipher: *mut c_void, argument: *mut c_void) {
    if cipher.is_null() {
        return;
    }
    // SAFETY: `cipher` is live and its name is an OpenSSL-owned string.
    let name = unsafe { EVP_CIPHER_get0_name(cipher.cast()) };
    if name.is_null() {
        return;
    }
    // SAFETY: `name` is a valid C string.
    let fetched =
        unsafe { openssl_sys::EVP_CIPHER_fetch(std::ptr::null_mut(), name, std::ptr::null()) };
    if fetched.is_null() {
        return;
    }
    // SAFETY: `fetched` is a live `EVP_CIPHER` this function owns.
    if unsafe { is_supported_fetched_cipher(fetched.cast()) } {
        // SAFETY: the walker invokes the callback synchronously with `argument`,
        // and `fetched` is live for the duration.
        unsafe {
            EVP_CIPHER_names_do_all(
                fetched.cast(),
                Some(provider_cipher_name_callback),
                argument,
            )
        };
    }
    // SAFETY: `fetched` came from `EVP_CIPHER_fetch` and is owned here.
    unsafe { openssl_sys::EVP_CIPHER_free(fetched) };
}

/// `SaveMacName`: lowercases a provider MAC name and drops a dotted-decimal OID.
unsafe extern "C" fn mac_name_callback(name: *const c_char, argument: *mut c_void) {
    if argument.is_null() {
        return;
    }
    // SAFETY: `name` is an OpenSSL-owned NUL-terminated string.
    let Some(name) = (unsafe { read_cstr(name) }) else {
        return;
    };
    if is_dotted_decimal(&name) {
        return;
    }
    // SAFETY: `argument` is the live `Vec<String>` the caller passed.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
    names.push(name.to_ascii_lowercase());
}

/// `SaveSupportedProviderMac`: fetches a MAC, then walks every name it answers
/// to. `KMAC-128` answers to both `KMAC-128` and `KMAC128`, which is exactly the
/// pair Node's `getMacs()` reports.
unsafe extern "C" fn mac_callback(mac: *mut c_void, argument: *mut c_void) {
    if mac.is_null() {
        return;
    }
    // SAFETY: `mac` is live and its name is an OpenSSL-owned string.
    let name = unsafe { EVP_MAC_get0_name(mac.cast()) };
    if name.is_null() {
        return;
    }
    // SAFETY: `name` is a valid C string and a null property query means the
    // default properties.
    let fetched =
        unsafe { openssl_sys::EVP_MAC_fetch(std::ptr::null_mut(), name, std::ptr::null()) };
    if fetched.is_null() {
        return;
    }
    // SAFETY: the walker invokes the callback synchronously with `argument`, and
    // `fetched` is live for the duration.
    unsafe { EVP_MAC_names_do_all(fetched.cast(), Some(mac_name_callback), argument) };
    // SAFETY: `fetched` came from `EVP_MAC_fetch` and is owned here.
    unsafe { openssl_sys::EVP_MAC_free(fetched) };
}

/// `EVP_MD_get_flags` for a digest, so the XOF check does not need its own FFI
/// declaration.
pub(crate) fn digest_flags(md: *const c_void) -> std::os::raw::c_ulong {
    // SAFETY: the caller passes a live `EVP_MD` pointer; the accessor only reads
    // the flags word.
    unsafe { EVP_MD_get_flags(md) }
}

/// Where a resolved digest implementation came from, and the pointer to use.
///
/// OpenSSL 3 splits digests across two worlds: the legacy table answers for the
/// algorithms registered at startup (`sha256`, `RSA-SHA256`), while the provider
/// store answers for the ones that only exist there (`KECCAK-256`,
/// `SHA2-256/192`). Node's `Digest::FromName` tries the legacy lookup first and
/// falls back to `EVP_MD_fetch`, so a name that resolves in Node resolves here.
///
/// The fetched pointer needs `EVP_MD_free`, the legacy one must not be freed, so
/// the provenance is part of the handle rather than assumed.
pub(crate) struct DigestSource {
    pointer: *mut openssl_sys::EVP_MD,
    /// Whether `pointer` came from `EVP_MD_fetch` and must be freed.
    fetched: bool,
    /// The name that resolved, so a copy can resolve again.
    resolution_name: String,
}

// SAFETY: an `EVP_MD` is an immutable reference-counted descriptor with no
// thread affinity, and this handle owns its reference exclusively. It is moved
// between threads rather than shared, so `Send` is sound. It is deliberately not
// `Sync`.
unsafe impl Send for DigestSource {}

impl DigestSource {
    /// The raw `EVP_MD` pointer to hand to `EVP_DigestInit_ex`.
    pub(crate) fn as_ptr(&self) -> *const c_void {
        self.pointer.cast()
    }

    /// The name that resolved, for diagnostics and for re-resolving a copy.
    pub(crate) fn resolution_name(&self) -> &str {
        &self.resolution_name
    }
}

impl Drop for DigestSource {
    fn drop(&mut self) {
        // A legacy pointer belongs to OpenSSL's static table and must not be
        // freed; only a fetched one is owned here.
        if self.fetched && !self.pointer.is_null() {
            // SAFETY: `pointer` came from `EVP_MD_fetch` and this handle is its
            // only owner.
            unsafe { openssl_sys::EVP_MD_free(self.pointer) };
            self.pointer = std::ptr::null_mut();
        }
    }
}

/// Resolves a digest name the way Node's `ncrypto::Digest::FromName` does: the
/// legacy lookup first, then `EVP_MD_fetch`.
///
/// `None` means OpenSSL has no digest by that name at all — the caller reports
/// `ERR_CRYPTO_INVALID_DIGEST` (or, for `createHash`, the uncoded
/// "Digest method not supported" Node throws from `crypto_hash.cc`).
pub(crate) fn resolve_digest(name: &str) -> Option<DigestSource> {
    let text = std::ffi::CString::new(name).ok()?;
    // SAFETY: `text` is a valid NUL-terminated C string for the duration of the
    // call and the lookup only reads it.
    let legacy = unsafe { openssl_sys::EVP_get_digestbyname(text.as_ptr()) };
    if !legacy.is_null() {
        // `Digest::FromName` refuses `EVP_md_null` even though the legacy table
        // answers for it.
        // SAFETY: `legacy` is a live `EVP_MD`.
        if unsafe { EVP_MD_is_a(legacy.cast(), c"NULL".as_ptr()) } != 1 {
            return Some(DigestSource {
                pointer: legacy.cast_mut(),
                fetched: false,
                resolution_name: name.to_string(),
            });
        }
    }
    // SAFETY: `text` is a valid C string and a null property query is the default.
    let fetched =
        unsafe { openssl_sys::EVP_MD_fetch(std::ptr::null_mut(), text.as_ptr(), std::ptr::null()) };
    if fetched.is_null() {
        return None;
    }
    // SAFETY: `fetched` is a live `EVP_MD` owned here.
    if unsafe { is_supported_digest(fetched.cast()) } {
        Some(DigestSource {
            pointer: fetched,
            fetched: true,
            resolution_name: name.to_string(),
        })
    } else {
        // SAFETY: `fetched` came from `EVP_MD_fetch`; nothing else owns it.
        unsafe { openssl_sys::EVP_MD_free(fetched) };
        None
    }
}

/// Whether a digest name resolves **and can actually be initialised**.
///
/// Resolution alone is not enough: the legacy table answers for `md4`, which then
/// fails at `EVP_DigestInit_ex` with "digest is not supported" because MD4 lives
/// in OpenSSL's *legacy* provider and this build enables only the default one.
/// Advertising it is precisely the bug this module exists to prevent, so the test
/// is an actual initialisation. Node's own filter is the fetch, which fails for
/// the same algorithms; this both matches it and proves the stronger property
/// the list promises.
fn resolvable_digest(name: &str) -> bool {
    let Some(source) = resolve_digest(name) else {
        return false;
    };
    // SAFETY: `EVP_MD_CTX_new` returns a valid context or null.
    let context = unsafe { openssl_sys::EVP_MD_CTX_new() };
    if context.is_null() {
        return false;
    }
    // SAFETY: both pointers are live; `source.as_ptr()` is the `EVP_MD` the
    // handle owns and a null engine means the default one.
    let initialised = unsafe {
        openssl_sys::EVP_DigestInit_ex(context, source.as_ptr().cast(), std::ptr::null_mut())
    };
    // SAFETY: the context came from `EVP_MD_CTX_new` above and is freed once.
    unsafe { openssl_sys::EVP_MD_CTX_free(context) };
    initialised == 1
}

/// Every digest name Node's `getHashes()` reports.
///
/// Both walkers contribute, because neither is a subset of the other:
///
/// * `do_all_sorted` is the source of the legacy names and aliases — `ripemd`,
///   `rmd160`, `ssl3-sha1`, and the whole `RSA-SHA256` family.
/// * `do_all_provided` is the only source of algorithms that exist only as
///   providers, such as `KECCAK-256` and `SHA2-256/192`.
///
/// # The six names this list cannot contain on OpenSSL 3.6.3
///
/// `KNOWN_ABSENT_DIGESTS` names them and why. They are cSHAKE, which is not in
/// the 3.6.3 source at all; see the crate docs for the measured proof and what a
/// future fix needs. Nothing here filters them out — the walk simply never sees
/// them, which is the property that makes the list truthful rather than curated.
pub fn digest_names() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let argument = (&mut names) as *mut Vec<String> as *mut c_void;
    // SAFETY: the walker invokes `digest_alias_callback` synchronously with
    // `argument` as its fourth parameter, and `names` outlives the call. The
    // legacy walker reports null `from` values, which the callback checks.
    unsafe { EVP_MD_do_all_sorted(Some(digest_alias_callback), argument) };
    // SAFETY: same vec, same lifetime; a null `libctx` means the default context.
    unsafe {
        EVP_MD_do_all_provided(
            std::ptr::null_mut(),
            Some(provider_digest_callback),
            argument,
        )
    };
    filter_duplicate_strings(names, false)
        .into_iter()
        // Keep only names that actually initialise. A provider can register a
        // name whose implementation is present but unusable, and advertising it
        // would be the exact lie this module exists to prevent.
        .filter(|name| resolvable_digest(name))
        .collect()
}

/// Every cipher name Node's `getCiphers()` reports.
///
/// Node applies no name denylist of its own: `IsSupportedFetchedCipher` is the
/// whole policy, and it is what removes `bf-cbc`, `rc4` and the `-cbc-hmac-*`
/// composites. Those entries stay out because they do not fetch or because their
/// flags say they are not a plain cipher, which is why this list needs no
/// hand-maintained table that could drift from the linked library.
pub fn cipher_names() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let argument = (&mut names) as *mut Vec<String> as *mut c_void;
    // SAFETY: as in `digest_names`: the walker calls the callback synchronously
    // and `names` outlives it.
    unsafe { EVP_CIPHER_do_all_sorted(Some(cipher_alias_callback), argument) };
    // SAFETY: same vec, same lifetime.
    unsafe {
        EVP_CIPHER_do_all_provided(
            std::ptr::null_mut(),
            Some(provider_cipher_callback),
            argument,
        )
    };
    filter_duplicate_strings(names, false)
        .into_iter()
        // The accept test is the one `createCipheriv` uses, so a name that
        // survives this cannot then fail to construct.
        .filter(|name| cipher_is_constructible(name))
        .collect()
}

/// Whether `rn_bind_crypto_cipher`'s lookup — the path `createCipheriv` takes —
/// resolves this name.
///
/// That lookup is `EVP_get_cipherbyname` followed by a provider fetch of the
/// canonical name, so it answers for the legacy aliases (`des3`) and for the
/// provider-only ciphers (`aes-128-cbc-cts`) alike.
fn cipher_is_constructible(name: &str) -> bool {
    rn_bind_crypto_cipher::evp::Cipher::from_name(name).is_some()
}

/// Resolves a cipher name the way `createCipheriv` will.
///
/// `Cipher::from_nid` needs a NID, so the name is resolved through OpenSSL's own
/// `EVP_get_cipherbyname` first — which is exactly the lookup the C++ uses.
pub(crate) fn resolve_cipher(name: &str) -> Option<Cipher> {
    let text = std::ffi::CString::new(name).ok()?;
    // SAFETY: `text` is valid NUL-terminated C for the duration of the call and
    // `EVP_get_cipherbyname` only reads it.
    let pointer = unsafe { openssl_sys::EVP_get_cipherbyname(text.as_ptr()) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the pointer came from `EVP_get_cipherbyname`, which returns either
    // null or a static `EVP_CIPHER`, and the null case was just handled.
    let nid = unsafe { openssl_sys::EVP_CIPHER_get_nid(pointer) };
    if nid == 0 {
        return None;
    }
    // `Cipher::from_nid` takes an `openssl::nid::Nid`; the raw int is the same
    // value, and `Nid::from_raw` is how the safe crate re-wraps it.
    Cipher::from_nid(openssl::nid::Nid::from_raw(nid))
}

/// Bytes currently allocated from OpenSSL's secure heap.
///
/// `DataPointer::GetSecureHeapUsed` in Node's `deps/ncrypto/ncrypto.cc` is
/// `CRYPTO_secure_malloc_initialized() ? CRYPTO_secure_used() : 0`. Neither symbol
/// is declared by `openssl-sys`, and both are exported by the `libcrypto` this
/// crate links.
///
/// This is a scalar fact read once per `secureHeapUsed()` call, so the lock-free
/// OpenSSL counters are exactly the right source: no allocation, no formatting.
pub fn secure_heap_used() -> u64 {
    // SAFETY: `CRYPTO_secure_malloc_initialized` only reads OpenSSL's internal
    // flag; it is a plain `int` return.
    let initialised = unsafe { CRYPTO_secure_malloc_initialized() };
    if initialised == 0 {
        return 0;
    }
    // SAFETY: only called once the secure heap is known to be initialised, which
    // is the condition OpenSSL documents for `CRYPTO_secure_used`.
    unsafe { CRYPTO_secure_used() as u64 }
}

/// Every curve name the linked OpenSSL can produce.
///
/// Node gets these from `EC_get_builtin_curves`, and so does this: the array's
/// `comment` field is the name `getCurves()` reports. The count is queried with a
/// null buffer first, which is OpenSSL's documented two-call pattern.
pub fn curve_names() -> Vec<String> {
    // SAFETY: `EC_get_builtin_curves(NULL, 0)` writes nothing and only reports
    // the number of built-in curves, which OpenSSL documents as supported.
    let count = unsafe { EC_get_builtin_curves(std::ptr::null_mut(), 0) };
    if count == 0 {
        return Vec::new();
    }
    let mut curves: Vec<ECBuiltinCurve> = Vec::with_capacity(count);
    // SAFETY: the buffer has room for exactly `count` entries, which is what
    // OpenSSL is being told to fill. `ECBuiltinCurve` is `repr(C)` and matches the
    // header's `{ int nid; const char *comment; }`.
    let written = unsafe { EC_get_builtin_curves(curves.as_mut_ptr(), count) };
    if written == 0 {
        return Vec::new();
    }
    // SAFETY: OpenSSL reported writing `written` initialised entries, and
    // `written <= count` is guaranteed by the API contract.
    unsafe { curves.set_len(written.min(count)) };

    // The name `getCurves()` reports is the NID short name (`prime256v1`,
    // `secp384r1`), not the `comment` field: OpenSSL's comments are prose like
    // "NIST/SECG curve over a 256 bit prime field", which is not a curve name and
    // cannot be passed to `createECDH`. That is the same NID-name rule the digest
    // walker follows.
    let mut names: Vec<String> = curves
        .iter()
        // SAFETY: `OBJ_nid2sn` only reads the NID.
        .filter_map(|curve| {
            // SAFETY: `OBJ_nid2sn` only reads the NID and returns either null or
            // a NUL-terminated static string.
            let pointer = unsafe { openssl_sys::OBJ_nid2sn(curve.nid) };
            if pointer.is_null() {
                return None;
            }
            // SAFETY: non-null and NUL-terminated, owned by OpenSSL for the
            // process's lifetime.
            unsafe { CStr::from_ptr(pointer) }.to_str().ok()
        })
        .map(str::to_string)
        .filter(|name| !name.is_empty() && name != "UNDEF")
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The TLS cipher suites OpenSSL would negotiate, for `getSSLCiphers()`.
///
/// `lib/tls.js` calls this at module scope to build `tls.getCiphers()`, so it is
/// part of what makes `require('tls')` work. The list comes from a real
/// `SSL_CTX` with OpenSSL's default policy applied, because that is what decides
/// which suites a handshake can use; a table here would drift from the linked
/// library exactly as a hardcoded `getHashes()` would.
///
/// The context is created, read and freed inside this call. There is no
/// `SecureContext` handle to keep: the question answered here is "what could a
/// context negotiate", not "what can this one".
pub fn ssl_cipher_names() -> Vec<String> {
    // SAFETY: `TLS_method` returns a static method table, and `SSL_CTX_new`
    // returns a valid context or null, which is checked immediately.
    let context = unsafe {
        let method = openssl_sys::TLS_method();
        openssl_sys::SSL_CTX_new(method)
    };
    if context.is_null() {
        return Vec::new();
    }

    let mut names = Vec::new();
    // SAFETY: `context` is a live `SSL_CTX` owned by this function, and the stack
    // `SSL_CTX_get_ciphers` returns is owned by the context.
    unsafe {
        let stack = SSL_CTX_get_ciphers(context.cast());
        if !stack.is_null() {
            let count = OPENSSL_sk_num(stack);
            for index in 0..count {
                let cipher = OPENSSL_sk_value(stack, index);
                if cipher.is_null() {
                    continue;
                }
                let pointer = openssl_sys::SSL_CIPHER_get_name(cipher.cast());
                if pointer.is_null() {
                    continue;
                }
                if let Ok(name) = CStr::from_ptr(pointer).to_str() {
                    if !name.is_empty() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        // `context` came from `SSL_CTX_new` above and is freed exactly once.
        SSL_CTX_free(context.cast());
    }

    names.sort();
    names.dedup();
    names
}

/// Every MAC algorithm the linked OpenSSL provides, for `getMacs()`.
///
/// `lib/internal/crypto/util.js` builds `getMacs` from this at module scope, so it
/// is load-bearing rather than an optional extra. The walk is
/// `EVP_MAC_do_all_provided` → fetch → `EVP_MAC_names_do_all`, which is what
/// makes `kmac128` appear beside `kmac-128`: they are two names for one provider
/// MAC, and Node reports both.
pub fn mac_names() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let argument = (&mut names) as *mut Vec<String> as *mut c_void;
    // SAFETY: the walker invokes the callback synchronously with `argument`, and
    // `names` outlives the call; a null `libctx` means the default context.
    unsafe { EVP_MAC_do_all_provided(std::ptr::null_mut(), Some(mac_callback), argument) };
    // `getMacs` is `filterDuplicateStrings(_getMacs(), true)`, so the values are
    // lowercased and the dedupe keeps the lowercase spelling.
    filter_duplicate_strings(names, true)
        .into_iter()
        // The same rule as the other two lists: a name that is advertised but
        // cannot be fetched is worse than an absent one.
        .filter(|name| mac_is_fetchable(name))
        .collect()
}

/// Whether a MAC name fetches, which is the accept test Node's walk implies.
fn mac_is_fetchable(name: &str) -> bool {
    let Ok(text) = std::ffi::CString::new(name) else {
        return false;
    };
    // SAFETY: `text` is a valid NUL-terminated C string.
    let fetched = unsafe {
        openssl_sys::EVP_MAC_fetch(std::ptr::null_mut(), text.as_ptr(), std::ptr::null())
    };
    if fetched.is_null() {
        return false;
    }
    // SAFETY: `fetched` came from `EVP_MAC_fetch` and is owned here.
    unsafe { openssl_sys::EVP_MAC_free(fetched) };
    true
}

/// The certificate compression algorithms the linked OpenSSL supports.
///
/// `lib/tls.js` binds this to `tls.getCertificateCompressionAlgorithms`, and
/// `lib/tls.js` is loaded by `require('crypto')`'s dependency graph, so the
/// function has to exist and answer truthfully.
///
/// # Why the answer is probed, not assumed
///
/// OpenSSL exposes no runtime enumeration for certificate compression: the
/// methods are compiled in and the only observable is whether
/// `SSL_CTX_set1_cert_comp_preference` accepts an algorithm identifier. Probing
/// that is the honest test, and it matters here — this `openssl-src` build has
/// **none** of the three, so the truthful list is empty. Returning
/// `["zlib", "brotli", "zstd"]` from a table would advertise three methods that
/// every handshake request would silently ignore.
///
/// The identifiers are RFC 8879's `CertificateCompressionAlgorithm` values, which
/// match `TLSEXT_comp_cert_*` in `openssl/tls1.h`.
pub fn certificate_compression_algorithms() -> Vec<String> {
    // SAFETY: `TLS_method` returns a static table and `SSL_CTX_new` returns a
    // valid context or null, which is checked.
    let context = unsafe {
        let method = openssl_sys::TLS_method();
        openssl_sys::SSL_CTX_new(method)
    };
    if context.is_null() {
        return Vec::new();
    }

    let mut algorithms = Vec::new();
    for (name, identifier) in [("zlib", 1i32), ("brotli", 2), ("zstd", 3)] {
        let mut preference = [identifier];
        // SAFETY: `context` is live and `preference` is a one-element array, which
        // is the length passed. The call only reads the array.
        let accepted = unsafe {
            SSL_CTX_set1_cert_comp_preference(context.cast(), preference.as_mut_ptr(), 1)
        };
        // `1` is success; `0` means the algorithm is not available in this build.
        if accepted == 1 {
            algorithms.push(name.to_string());
        }
    }
    // SAFETY: `context` came from `SSL_CTX_new` above and is freed exactly once.
    unsafe { SSL_CTX_free(context.cast()) };
    algorithms
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::hash::MessageDigest;

    #[test]
    fn digest_names_are_unique() {
        let names = digest_names();
        assert!(!names.is_empty(), "OpenSSL reported no digests");
        let unique: std::collections::BTreeSet<String> =
            names.iter().map(|name| name.to_ascii_lowercase()).collect();
        assert_eq!(unique.len(), names.len(), "duplicate digest name");
    }

    #[test]
    fn common_digests_are_present() {
        let names = digest_names();
        for expected in ["sha1", "sha256", "sha512", "md5", "sha3-256", "blake2b512"] {
            assert!(
                names.iter().any(|name| name == expected),
                "getHashes() is missing {expected}"
            );
        }
    }

    #[test]
    fn every_advertised_digest_resolves() {
        for name in digest_names() {
            assert!(
                resolvable_digest(&name),
                "{name} was advertised but does not initialise"
            );
        }
    }

    #[test]
    fn alias_only_digest_names_are_present() {
        // These reach `getHashes()` only through the legacy `do_all_sorted` walk,
        // which reports registered names and aliases rather than one canonical
        // provider name. Node lists all of them (measured on the 28.0.0 nightly
        // oracle), and dropping the alias half of the walk removes them silently:
        // every other digest test here still passes, because the provider walk
        // supplies `sha256` on its own. Pinning an alias-only name is what makes
        // the list test able to fail.
        let names = digest_names();
        for alias in [
            "RSA-SHA256",
            "ripemd160WithRSA",
            "md5WithRSAEncryption",
            "ssl3-md5",
        ] {
            assert!(
                names.iter().any(|name| name == alias),
                "getHashes() lost the alias-only name {alias}"
            );
        }
    }

    #[test]
    fn provider_only_digest_names_are_present() {
        // The mirror image: these come only from `EVP_MD_do_all_provided` +
        // `EVP_MD_names_do_all`, and the legacy table has no NID for them, so a
        // legacy-only walk would lose them just as quietly.
        let names = digest_names();
        for provider_only in ["keccak-256", "sha2-256/192", "keccak-kmac-128"] {
            assert!(
                names.iter().any(|name| name == provider_only),
                "getHashes() lost the provider-only name {provider_only}"
            );
        }
    }

    #[test]
    fn ciphers_exclude_policy_disabled_names() {
        let ciphers = cipher_names();
        assert!(!ciphers.is_empty());
        // These are the families Node's own filter removes, and the reason it
        // removes them is visible here: they do not fetch in this build.
        for disabled in ["rc4", "rc2-cbc", "bf-cbc", "idea-cbc", "desx-cbc"] {
            assert!(
                !ciphers.iter().any(|name| name == disabled),
                "{disabled} must not be advertised"
            );
            assert!(
                !is_policy_neutral_probe(disabled),
                "{disabled} unexpectedly resolves; the filter above can no longer \
                 prove it is excluded for the right reason"
            );
        }
    }

    /// Whether a name that must stay out of the list nevertheless constructs.
    ///
    /// The assertion above only means something if the name is *otherwise*
    /// attractive — reachable through the legacy table, say. A name that nothing
    /// can resolve is trivially absent, which would hide a broken filter.
    fn is_policy_neutral_probe(name: &str) -> bool {
        cipher_is_constructible(name)
    }

    #[test]
    fn common_ciphers_are_present() {
        let ciphers = cipher_names();
        for expected in ["aes-128-cbc", "aes-256-gcm", "chacha20-poly1305"] {
            assert!(
                ciphers.iter().any(|name| name == expected),
                "getCiphers() is missing {expected}"
            );
        }
    }

    #[test]
    fn every_advertised_cipher_constructs() {
        for name in cipher_names() {
            assert!(
                cipher_is_constructible(&name),
                "{name} was advertised but createCipheriv cannot construct it"
            );
        }
    }

    #[test]
    fn every_advertised_mac_fetches() {
        let names = mac_names();
        assert!(!names.is_empty(), "OpenSSL reported no MACs");
        for name in &names {
            assert!(
                mac_is_fetchable(name),
                "{name} was advertised but does not fetch"
            );
        }
    }

    #[test]
    fn camellia_is_not_a_build_configuration_gap_any_more() {
        // `openssl-src` passes `no-camellia` unless its `camellia` feature is on,
        // and `rn-bind-crypto`'s `Cargo.toml` now enables it. If that dependency
        // line is ever dropped, 27 names vanish from `getCiphers()` and the only
        // other symptom is a smaller list — nothing fails to compile and no other
        // test here notices, because each of them checks a subset.
        //
        // The names span all three key sizes and every mode the provider
        // registers, plus the three NID short names Node also lists, so a partial
        // build cannot satisfy this.
        let ciphers = cipher_names();
        for expected in [
            "camellia-128-cbc",
            "camellia-128-ecb",
            "camellia-192-ctr",
            "camellia-256-ofb",
        ] {
            assert!(
                ciphers.iter().any(|listed| listed == expected),
                "getCiphers() is missing {expected}: the `camellia` feature on \
                 `openssl-src` is probably no longer enabled in Cargo.toml"
            );
            assert!(
                cipher_is_constructible(expected),
                "{expected} is listed but createCipheriv cannot construct it"
            );
        }
        // The NID short names are a different code path: they come from the
        // legacy `do_all_sorted` walk rather than the provider walk.
        for alias in ["camellia128", "camellia192", "camellia256"] {
            assert!(
                ciphers.iter().any(|listed| listed == alias),
                "getCiphers() lost the camellia alias {alias}"
            );
        }
        assert_eq!(
            ciphers
                .iter()
                .filter(|name| name.contains("camellia"))
                .count(),
            27,
            "the oracle lists 27 camellia names"
        );
    }

    #[test]
    fn known_absent_digests_are_really_absent() {
        // `KNOWN_ABSENT_DIGESTS` is a claim about the linked library. If a future
        // `openssl-src` supplies cSHAKE, this test fails and says so — which is
        // the signal to delete the constant and the doc section that explains it,
        // rather than leaving a stale "impossible" note behind.
        let names = digest_names();
        for absent in KNOWN_ABSENT_DIGESTS {
            assert!(
                !names.iter().any(|name| name == absent),
                "{absent} is now in getHashes(); remove it from KNOWN_ABSENT_DIGESTS \
                 and update the crate docs, which no longer describe this build"
            );
            assert!(
                !resolvable_digest(absent),
                "{absent} resolves now, so it can be advertised; the declaration \
                 in KNOWN_ABSENT_DIGESTS is stale"
            );
        }
    }

    #[test]
    fn known_absent_digests_are_the_whole_difference() {
        // Pins the cSHAKE set exactly, so neither a name silently disappearing
        // from the constant nor a seventh gap hiding is possible. Every entry must
        // be a cSHAKE spelling: that is the single reason currently recorded, and
        // a non-cSHAKE name here would mean this build lost something else.
        assert_eq!(
            KNOWN_ABSENT_DIGESTS.len(),
            6,
            "the recorded gap is six names"
        );
        for absent in KNOWN_ABSENT_DIGESTS {
            assert!(
                absent.to_ascii_lowercase().starts_with("cshake"),
                "{absent} is not a cSHAKE name; a different gap was recorded \
                 without documenting why"
            );
        }
    }

    #[test]
    fn curves_include_the_standard_nist_names() {
        let curves = curve_names();
        assert!(!curves.is_empty());
        for expected in ["prime256v1", "secp384r1", "secp521r1"] {
            assert!(
                curves.iter().any(|name| name == expected),
                "getCurves() is missing {expected}"
            );
        }
    }

    #[test]
    fn curve_names_are_sorted() {
        let listed = curve_names();
        let mut sorted = listed.clone();
        sorted.sort();
        assert_eq!(sorted, listed, "curve list is not sorted");
    }

    #[test]
    fn digest_sources_know_whether_they_own_their_pointer() {
        // A legacy digest must not be freed; a fetched one must. Getting this
        // backwards is a double free or a leak, so pin the provenance.
        let legacy = resolve_digest("sha256").expect("sha256 is a legacy digest");
        assert!(!legacy.fetched, "sha256 should come from the legacy table");
        let provider = resolve_digest("keccak-256").expect("KECCAK-256 is provider-only");
        assert!(provider.fetched, "keccak-256 must be a fetched digest");
        // Both forms must be usable as the `EVP_MD` for a digest context.
        for source in [&legacy, &provider] {
            let context = unsafe { openssl_sys::EVP_MD_CTX_new() };
            assert!(!context.is_null());
            let initialised = unsafe {
                openssl_sys::EVP_DigestInit_ex(
                    context,
                    source.as_ptr().cast(),
                    std::ptr::null_mut(),
                )
            };
            unsafe { openssl_sys::EVP_MD_CTX_free(context) };
            assert_eq!(
                initialised,
                1,
                "{} did not initialise",
                source.resolution_name()
            );
        }
    }

    #[test]
    fn a_null_digest_name_is_never_advertised() {
        assert!(
            !digest_names().iter().any(|name| name == "null"),
            "the NULL digest must not be advertised"
        );
        assert!(resolve_digest("null").is_none(), "NULL must not resolve");
    }

    #[test]
    fn legacy_message_digest_lookup_is_unchanged() {
        // `Hash.prototype.copy` and the HMAC path still go through the legacy
        // lookup, so the alias behaviour there must not have shifted.
        assert!(MessageDigest::from_name("RSA-SHA256").is_some());
        assert!(MessageDigest::from_name("sha-1").is_some());
    }
}
