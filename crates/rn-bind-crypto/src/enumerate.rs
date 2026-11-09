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
//! `EVP_MD_get0_name` accessors, but not the `do_all_provided` walkers,
//! `EVP_MD_names_do_all`, or `EC_get_builtin_curves`. All of them are exported by
//! the `libcrypto` this crate links — verified against the built archive — so the
//! missing piece is only the Rust declaration, which is what this module adds.
//!
//! # What Node does, and where this differs
//!
//! `node_util.cc` builds the digest and cipher lists from `EVP_MD_do_all_sorted`
//! / `EVP_CIPHER_do_all_sorted` and filters the ciphers through Node's own
//! denylist. This walks the provider-aware `do_all_provided` lists instead, which
//! report what the *active providers* offer rather than every name ever compiled
//! in, and then keeps only the names that resolve through the safe API. That is a
//! stricter test than Node's, and it is the property the task requires: nothing
//! is advertised that cannot then be used.

use std::collections::BTreeSet;
use std::ffi::{c_char, c_int, c_void, CStr};

use openssl::hash::MessageDigest;
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

    // `EVP_MD_get_type(const EVP_MD *)`, the digest's NID.
    fn EVP_MD_get_type(md: *const c_void) -> std::os::raw::c_int;

    // `EVP_MD_get_flags(const EVP_MD *)`. Not declared by `openssl-sys` either,
    // and it is the only way to tell an extendable-output digest apart from a
    // fixed-length one, since a SHAKE reports a non-zero size.
    fn EVP_MD_get_flags(md: *const c_void) -> std::os::raw::c_ulong;

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

    // `EVP_MAC_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_MAC *, void *),
    // void *arg)`, the MAC walker `getMacs()` needs.
    fn EVP_MAC_do_all_provided(
        libctx: *mut c_void,
        callback: Option<unsafe extern "C" fn(mac: *mut c_void, arg: *mut c_void)>,
        arg: *mut c_void,
    );

    // `EVP_MAC_get0_name(const EVP_MAC *)`.
    fn EVP_MAC_get0_name(mac: *const c_void) -> *const c_char;

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

/// Collects the names of one digest or cipher into the callback's set.
///
/// **The name has to come from the NID, not from `EVP_MD_get0_name`.** A provider
/// reports its *provider long name*, so `EVP_MD_get0_name` says `SHA2-256` where
/// Node says `sha256`, and `SHA2-512/224` where Node says `sha512-224`. Node's
/// `getHashes()` is built on `EVP_MD_do_all_sorted`, which reports NID short names
/// and aliases. Both names happen to resolve as inputs, but a caller comparing
/// `getHashes()` against a literal `'sha256'` — which Node's own tests and a great
/// deal of user code do — fails if the list is spelled the provider's way.
///
/// The NID gives the authoritative short name (`OBJ_nid2sn`) and long name
/// (`OBJ_nid2ln`); both are recorded because Node reports both (`ripemd` and
/// `ripemd160`, `sha256` and, for the RSA signature variants, more).
///
/// # Safety
///
/// `argument` must point to a live `BTreeSet<String>`, which is what every caller
/// in this module passes, and `object` must be the `EVP_MD`/`EVP_CIPHER` pointer
/// the walker handed the callback.
unsafe fn record_name(object: *const c_void, argument: *mut c_void, nid_of: NidOf) {
    if object.is_null() || argument.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `argument` points to a live
    // `BTreeSet<String>` that outlives this call, which is true because the walk
    // is synchronous and the set is a local in the calling function.
    let names: &mut BTreeSet<String> = unsafe { &mut *(argument as *mut BTreeSet<String>) };
    // SAFETY: `nid_of` is `EVP_MD_get_type` or `EVP_CIPHER_get_nid`, both of
    // which only read the object they are handed.
    let nid = unsafe { nid_of(object) };
    // `NID_undef` is 0. A provider algorithm with no NID (the KECCAK variants, the
    // `NULL` digest) has no name Node could report, so it is skipped rather than
    // advertised under a provider-only spelling that `createHash` accepts but
    // `getHashes()` never lists in Node.
    if nid == 0 {
        return;
    }
    for name_of in [obj_short_name, obj_long_name] {
        // SAFETY: `OBJ_nid2*` accept any int and return either null or a
        // NUL-terminated static string.
        let pointer = unsafe { name_of(nid) };
        if pointer.is_null() {
            continue;
        }
        // SAFETY: non-null and NUL-terminated, owned by OpenSSL for the process's
        // lifetime.
        if let Ok(name) = unsafe { CStr::from_ptr(pointer) }.to_str() {
            if !name.is_empty() {
                names.insert(name.to_ascii_lowercase());
            }
        }
    }
}

/// Records the name and alias a `do_all_sorted` callback reports.
///
/// `to` is the alias being enumerated and is the name a caller types; `from` is
/// the name it aliases, or null when the entry has no alias. Node records `to` for
/// every entry, so both spellings of `ripemd`/`ripemd160` end up in the list.
///
/// # Safety
///
/// `argument` must point to a live `BTreeSet<String>`; `to` and `from` are
/// OpenSSL-owned C strings, and `from` may be null.
unsafe fn record_alias(
    argument: *mut c_void,
    from: *const c_char,
    to: *const c_char,
    resolve: fn(&str) -> bool,
) {
    if argument.is_null() || to.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `argument` points to a live
    // `BTreeSet<String>` that outlives this synchronous walk.
    let names: &mut BTreeSet<String> = unsafe { &mut *(argument as *mut BTreeSet<String>) };
    // SAFETY: `to` was checked non-null and is NUL-terminated.
    let Some(alias) = unsafe { CStr::from_ptr(to) }.to_str().ok() else {
        return;
    };
    let alias = alias.to_ascii_lowercase();
    if !alias.is_empty() && resolve(&alias) {
        names.insert(alias);
    }
    // `from` is null when there is no alias; dereferencing it would segfault.
    if from.is_null() {
        return;
    }
    // SAFETY: as for `to`.
    if let Ok(source) = unsafe { CStr::from_ptr(from) }.to_str() {
        let source = source.to_ascii_lowercase();
        if !source.is_empty() && resolve(&source) {
            names.insert(source);
        }
    }
}

unsafe extern "C" fn digest_alias_callback(
    _md: *const c_void,
    from: *const c_char,
    to: *const c_char,
    argument: *mut c_void,
) {
    // SAFETY: forwarded from `EVP_MD_do_all_sorted`.
    unsafe { record_alias(argument, from, to, resolvable_digest) }
}

unsafe extern "C" fn cipher_alias_callback(
    _cipher: *const c_void,
    from: *const c_char,
    to: *const c_char,
    argument: *mut c_void,
) {
    // SAFETY: forwarded from `EVP_CIPHER_do_all_sorted`.
    unsafe { record_alias(argument, from, to, |name| resolve_cipher(name).is_some()) }
}

/// Which accessor turns a digest or cipher object into its NID.
type NidOf = unsafe extern "C" fn(*const c_void) -> std::os::raw::c_int;

/// `OBJ_nid2sn`, behind a `*const c_void` argument so both name readers share a
/// signature.
unsafe extern "C" fn obj_short_name(nid: std::os::raw::c_int) -> *const c_char {
    // SAFETY: `OBJ_nid2sn` only reads the integer.
    unsafe { openssl_sys::OBJ_nid2sn(nid) }
}

/// `OBJ_nid2ln`.
unsafe extern "C" fn obj_long_name(nid: std::os::raw::c_int) -> *const c_char {
    // SAFETY: `OBJ_nid2ln` only reads the integer.
    unsafe { openssl_sys::OBJ_nid2ln(nid) }
}

/// `EVP_MD_get_type` adapted to [`NidOf`].
unsafe extern "C" fn digest_nid(md: *const c_void) -> std::os::raw::c_int {
    // SAFETY: `EVP_MD_get_type` only reads the digest.
    unsafe { EVP_MD_get_type(md) }
}

/// `EVP_CIPHER_get_nid` adapted to [`NidOf`].
unsafe extern "C" fn cipher_nid(cipher: *const c_void) -> std::os::raw::c_int {
    // SAFETY: `EVP_CIPHER_get_nid` only reads the cipher.
    unsafe { openssl_sys::EVP_CIPHER_get_nid(cipher.cast()) }
}

unsafe extern "C" fn digest_callback(md: *mut c_void, argument: *mut c_void) {
    // SAFETY: forwarded from `EVP_MD_do_all_provided`, whose contract matches.
    unsafe { record_name(md as *const c_void, argument, digest_nid) }
}

unsafe extern "C" fn cipher_callback(cipher: *mut c_void, argument: *mut c_void) {
    // SAFETY: forwarded from `EVP_CIPHER_do_all_provided`.
    unsafe { record_name(cipher as *const c_void, argument, cipher_nid) }
}

/// `EVP_MD_get_flags` for a digest, so the XOF check does not need its own FFI
/// declaration.
pub(crate) fn digest_flags(md: *const c_void) -> std::os::raw::c_ulong {
    // SAFETY: the caller passes a live `EVP_MD` pointer; the accessor only reads
    // the flags word.
    unsafe { EVP_MD_get_flags(md) }
}

/// Whether a digest name resolves **and can actually be used**.
///
/// `MessageDigest::from_name` is a legacy lookup that answers for algorithms the
/// active providers cannot supply: `md4` resolves and then fails at
/// `EVP_DigestInit_ex` with "digest is not supported", because MD4 lives in
/// OpenSSL's *legacy* provider and this build enables only the default one.
///
/// Advertising it is precisely the bug this module exists to prevent — a caller
/// reads `getHashes()`, picks `md4`, and `createHash` throws. So the filter is an
/// actual initialisation, not just a name lookup. That costs one context
/// allocation per candidate, which is paid once because `lib/internal/crypto/
/// util.js` caches the result.
fn resolvable_digest(name: &str) -> bool {
    let Some(digest) = MessageDigest::from_name(name) else {
        return false;
    };
    // SAFETY: `EVP_MD_CTX_new` returns a valid context or null.
    let context = unsafe { openssl_sys::EVP_MD_CTX_new() };
    if context.is_null() {
        return false;
    }
    // SAFETY: both pointers are live; `digest.as_ptr()` is the static `EVP_MD`
    // the `MessageDigest` holds and a null engine means the default one.
    let initialised =
        unsafe { openssl_sys::EVP_DigestInit_ex(context, digest.as_ptr(), std::ptr::null_mut()) };
    // SAFETY: the context came from `EVP_MD_CTX_new` above and is freed once.
    unsafe { openssl_sys::EVP_MD_CTX_free(context) };
    initialised == 1
}

/// Every digest name the linked OpenSSL can fetch.
pub fn digest_names() -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    let argument = (&mut names) as *mut BTreeSet<String> as *mut c_void;
    // Both walkers contribute, because neither is a subset of the other:
    //
    // * `do_all_sorted` is what Node's `getHashes()` is built from, and it is the
    //   only source of the legacy names and aliases — `ripemd`, `rmd160`,
    //   `ssl3-sha1`, and the `RSA-SHA256` signature family.
    // * `do_all_provided` is the only source of algorithms that exist only as
    //   providers, such as `blake2b512`, which the legacy table does not carry.
    //
    // The union is filtered to names that actually resolve, so a script that
    // enumerates and then uses every entry still cannot be told about a digest
    // that fails.
    //
    // SAFETY: the walker invokes `digest_alias_callback` synchronously with
    // `argument` as its fourth parameter, and `names` outlives the call.
    unsafe { EVP_MD_do_all_sorted(Some(digest_alias_callback), argument) };
    // SAFETY: same set, same lifetime; a null `libctx` means the default context.
    unsafe { EVP_MD_do_all_provided(std::ptr::null_mut(), Some(digest_callback), argument) };
    names
        .into_iter()
        // Keep only names that actually resolve. A provider may register a name
        // whose implementation is present but unusable, and advertising it would
        // be the exact lie this module exists to prevent.
        .filter(|name| resolvable_digest(name))
        .collect()
}

/// Every cipher name the linked OpenSSL can fetch.
///
/// Filtered by Node's policy denylist, because `getCiphers()` does not report the
/// ciphers `createCipheriv` refuses to construct, and by whether the name resolves
/// through the safe API.
pub fn cipher_names() -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    let argument = (&mut names) as *mut BTreeSet<String> as *mut c_void;
    // Both walkers, for the same reason as `digest_names`: the sorted walker
    // supplies Node's aliases and the provided walker supplies provider-only
    // ciphers.
    //
    // SAFETY: as in `digest_names`.
    unsafe { EVP_CIPHER_do_all_sorted(Some(cipher_alias_callback), argument) };
    // SAFETY: as above.
    unsafe { EVP_CIPHER_do_all_provided(std::ptr::null_mut(), Some(cipher_callback), argument) };
    names
        .into_iter()
        .filter(|name| !is_policy_disabled(name))
        .filter(|name| resolve_cipher(name).is_some())
        .collect()
}

/// Resolves a cipher name the way `createCipheriv` will.
///
/// `Cipher::from_nid` needs a NID, so the name is resolved through OpenSSL's own
/// `EVP_get_cipherbyname` first — which is exactly the lookup the C++ uses.
pub(crate) fn resolve_cipher(name: &str) -> Option<Cipher> {
    let text = std::ffi::CString::new(name).ok()?;
    // SAFETY: `text` is a valid NUL-terminated C string for the duration of the
    // call and `EVP_get_cipherbyname` only reads it.
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

/// Ciphers Node's policy removes from the advertised list.
///
/// These are algorithms OpenSSL still registers but that Node refuses to use for
/// `createCipheriv`, so reporting them would be the exact lie the task warns
/// about. The list follows the disabled families in Node's `node_util.cc`: the
/// export-grade and obsolete block ciphers, plus the null/disabled placeholders.
fn is_policy_disabled(name: &str) -> bool {
    if name.contains("null") || name.contains("disabled") {
        return true;
    }
    const DISABLED: &[&str] = &[
        // The bare family names are what the legacy `do_all_sorted` walker
        // reports; Node's list never contains them, only the concrete modes.
        "blowfish",
        "des",
        "des-cbc",
        "des-ecb",
        "des-cfb",
        "des-cfb8",
        "des-cfb64",
        "des-ofb",
        "des-ede",
        "des-ede-cbc",
        "des-ede-cfb",
        "des-ede-ofb",
        "des-ede3",
        "des-ede3-cbc",
        "des-ede3-cfb",
        "des-ede3-ofb",
        "des3",
        "des3-cbc",
        "desx",
        "desx-cbc",
        "rc2",
        "rc2-128",
        "rc2-40",
        "rc2-64",
        "rc2-40-cbc",
        "rc2-64-cbc",
        "rc2-cbc",
        "rc2-ecb",
        "rc2-cfb",
        "rc2-ofb",
        "rc4",
        "rc4-40",
        "rc4-hmac-md5",
        "idea",
        "idea-cbc",
        "idea-ecb",
        "idea-cfb",
        "idea-ofb",
        "seed",
        "seed-cbc",
        "seed-ecb",
        "seed-cfb",
        "seed-ofb",
        "bf",
        "bf-cbc",
        "bf-cfb",
        "bf-ecb",
        "bf-ofb",
        "cast",
        "cast-cbc",
        "cast5-cbc",
        "cast5-cfb",
        "cast5-ecb",
        "cast5-ofb",
        // Aliases OpenSSL keeps for the AES key-wrap modes; Node reports only the
        // `aes-NNN-wrap` spelling.
        "id-aes128-wrap",
        "id-aes192-wrap",
        "id-aes256-wrap",
        "id-aes128-wrap-pad",
        "id-aes192-wrap-pad",
        "id-aes256-wrap-pad",
    ];
    DISABLED.contains(&name)
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
/// is load-bearing rather than an optional extra.
pub fn mac_names() -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    let argument = (&mut names) as *mut BTreeSet<String> as *mut c_void;
    // SAFETY: the walker invokes the callback synchronously with `argument`, and
    // `names` outlives the call; a null `libctx` means the default context.
    unsafe { EVP_MAC_do_all_provided(std::ptr::null_mut(), Some(mac_callback), argument) };
    names.into_iter().collect()
}

unsafe extern "C" fn mac_callback(mac: *mut c_void, argument: *mut c_void) {
    if mac.is_null() || argument.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `argument` is a live `BTreeSet<String>`.
    let names: &mut BTreeSet<String> = unsafe { &mut *(argument as *mut BTreeSet<String>) };
    // SAFETY: `EVP_MAC_get0_name` only reads the MAC and returns a static string.
    let pointer = unsafe { EVP_MAC_get0_name(mac) };
    if pointer.is_null() {
        return;
    }
    // SAFETY: non-null and NUL-terminated.
    if let Ok(name) = unsafe { CStr::from_ptr(pointer) }.to_str() {
        let name = name.to_ascii_lowercase();
        if !name.is_empty() {
            names.insert(name);
        }
    }
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

    #[test]
    fn digest_names_are_lowercase_and_unique() {
        let names = digest_names();
        assert!(!names.is_empty(), "OpenSSL reported no digests");
        for name in &names {
            assert_eq!(*name, name.to_ascii_lowercase(), "{name} is not lowercase");
        }
        let unique: BTreeSet<_> = names.iter().collect();
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
                MessageDigest::from_name(&name).is_some(),
                "{name} was advertised but does not resolve"
            );
        }
    }

    #[test]
    fn ciphers_exclude_policy_disabled_names() {
        let ciphers = cipher_names();
        assert!(!ciphers.is_empty());
        for disabled in ["rc4", "rc2-cbc", "bf-cbc", "idea-cbc", "desx-cbc"] {
            assert!(
                !ciphers.iter().any(|name| name == disabled),
                "{disabled} must not be advertised"
            );
        }
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
    fn every_advertised_cipher_resolves() {
        for name in cipher_names() {
            assert!(
                resolve_cipher(&name).is_some(),
                "{name} was advertised but does not resolve"
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
}
