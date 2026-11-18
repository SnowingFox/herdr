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
use std::sync::Mutex;

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

/// Serialises every enumeration against every other enumeration, and forces
/// OpenSSL's one-time algorithm registration to finish before any walk starts.
///
/// # The defect
///
/// `OBJ_NAME_do_all_sorted` sizes a stack from `lh_OBJ_NAME_num_items()` and then
/// walks the lhash through `OBJ_NAME_do_all`, which holds **no lock** and writes
/// through an unchecked `d->names[d->n++]`.
///
/// The table it walks is populated by OpenSSL's one-time
/// `openssl_add_all_digests_int()` / `openssl_add_all_ciphers_int()`, reached
/// through `OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS | ..._CIPHERS)`.
/// Both `EVP_get_digestbyname` and `EVP_get_cipherbyname` call that init on their
/// first invocation, and it inserts dozens of entries. When the insert pushes the
/// lhash past its load factor, `expand()` **reallocs `lh->b` and relinks nodes
/// between buckets**; a traversal holding a stale index or a stale `->next` then
/// silently skips entries. That is why the names that vanish are always a
/// `pkey_type` alias pair (`RSA-SHA512` + `sha512WithRSAEncryption`,
/// `RSA-SHA3-224`): `EVP_add_digest` registers those last, so they live in the
/// buckets that `expand()` moves.
///
/// This is a genuine race and it is *ours to lose*: any thread that resolves a
/// digest or cipher by name can trigger the registration while another thread is
/// walking. Measured on this build, one walk racing one `EVP_get_digestbyname` +
/// `EVP_get_cipherbyname` call on another thread lost names on **31 of 80**
/// fresh-process runs (55-58 entries instead of 59); the same walk with the other
/// thread doing nothing lost none (0 of 80).
///
/// # The fix
///
/// Complete the registration *before* walking, once per process, while holding
/// this lock. After that the table is immutable for the life of the process (no
/// `OBJ_NAME_add` runs after init; the only other mutator is
/// `OBJ_NAME_cleanup`, which is not reached here), so a walk cannot race a
/// resize. The lock also keeps the fetches in each enumerator's second phase from
/// overlapping another thread's traversal, since digests, ciphers and MACs all
/// share this single `names_lh` table.
///
/// The registration is driven through `EVP_get_digestbyname`/`EVP_get_cipherbyname`
/// rather than by calling `OPENSSL_init_crypto` directly, so this touches only
/// the public API `openssl-sys` already exposes and asks for exactly the init the
/// walkers themselves request.
///
/// This is a leaf lock — nothing here calls back into another enumerator — so a
/// plain `Mutex` is enough, and its poisoning is deliberately ignored: a panic
/// while holding it cannot leave OpenSSL's tables in a state a retry would make
/// worse, and refusing every later `getHashes()` would be a far worse failure
/// than re-running a read-only walk.
static ENUMERATION: Mutex<()> = Mutex::new(());

/// Runs `walk` with the enumeration lock held and the algorithm table ready.
///
/// The lock is held for the whole enumeration, not just the registration: phase
/// two's `EVP_*_fetch` calls can themselves reach OpenSSL's init and config
/// machinery, and overlapping that with another thread's traversal is the same
/// hazard one level down.
fn serialised<T>(walk: impl FnOnce() -> T) -> T {
    let _guard = ENUMERATION
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    register_legacy_algorithms_once();
    walk()
}

/// Makes OpenSSL register every legacy digest and cipher, exactly once.
///
/// Called with [`ENUMERATION`] held. `EVP_get_digestbyname` and
/// `EVP_get_cipherbyname` each begin with `OPENSSL_init_crypto(...)` for the
/// matching `ADD_ALL_*` flag, so one call to each runs
/// `openssl_add_all_digests_int()` and `openssl_add_all_ciphers_int()` to
/// completion. Both are `RUN_ONCE`-guarded, so after the first call this is two
/// hash lookups.
fn register_legacy_algorithms_once() {
    // Names that are definitely present, so neither lookup can fail for its own
    // reasons: the point is the init each lookup performs, not its answer.
    let digest = c"sha256";
    let cipher = c"aes-128-cbc";
    // SAFETY: both literals are NUL-terminated C strings that outlive the calls,
    // and the lookups only read them. The return values are unused: each call
    // exists for its side effect of completing the matching `ADD_ALL_*` init.
    unsafe {
        openssl_sys::EVP_get_digestbyname(digest.as_ptr());
        openssl_sys::EVP_get_cipherbyname(cipher.as_ptr());
    }
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

/// Collects the `from` name of every entry `EVP_MD_do_all_sorted` visits.
///
/// This callback must stay free of `EVP_*_fetch` and any other call that can
/// reach OpenSSL's init path. See [`ENUMERATION`]: fetching from inside this walk
/// re-enters the machinery that populates the very table being traversed, which
/// makes OpenSSL's walker skip entries. That is how `getHashes()` came to lose
/// `RSA-SHA512`, `sha512WithRSAEncryption` and `RSA-SHA3-224`. The resolvability
/// test that used to live here now runs in a second pass, after the walk has
/// returned, in [`digest_names`].
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
    // SAFETY: `from` is a NUL-terminated OpenSSL-owned string, and the spelling
    // is preserved because Node preserves it (`RSA-SHA256` stays mixed case).
    let Some(name) = (unsafe { read_cstr(from) }) else {
        return;
    };
    if name.is_empty() {
        return;
    }
    // SAFETY: the caller guarantees `argument` points to a live
    // `Vec<String>` that outlives this synchronous walk.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
    names.push(name);
}

/// `SaveSupportedProviderHashName`: lowercases a provider name and drops a
/// dotted-decimal OID.
///
/// Like [`digest_alias_callback`] this only records the name; the fetch that
/// decides whether it is usable runs in a second pass, outside the traversal.
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
    // SAFETY: `argument` is the live `Vec<String>` the caller passed.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
    names.push(name.to_ascii_lowercase());
}

/// `SaveSupportedProviderHashAlgorithms`: records the canonical name of every
/// digest the provider walker hands over.
///
/// The fetch and the `EVP_MD_names_do_all` expansion that Node does here both
/// happen in [`provider_names_of`], after the traversal has returned.
unsafe extern "C" fn provider_digest_callback(md: *mut c_void, argument: *mut c_void) {
    if md.is_null() || argument.is_null() {
        return;
    }
    // SAFETY: `md` is live and its name is an OpenSSL-owned string.
    let name = unsafe { EVP_MD_get0_name(md.cast()) };
    // SAFETY: `name` is a NUL-terminated OpenSSL-owned string.
    let Some(name) = (unsafe { read_cstr(name) }) else {
        return;
    };
    // SAFETY: `argument` is the live `Vec<String>` the caller passed.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
    names.push(name);
}

/// Collects the `from` name of every entry `EVP_CIPHER_do_all_sorted` visits.
///
/// Like [`digest_alias_callback`] this only records the name. `EVP_CIPHER_fetch`
/// is the accept test Node applies, and it runs in [`cipher_names`]'s second
/// phase: fetching from inside the traversal makes `OBJ_NAME_do_all` skip
/// entries, which is the defect [`ENUMERATION`] documents.
///
/// # Safety
///
/// Every pointer the walker hands a callback is OpenSSL-owned and only read.
unsafe extern "C" fn cipher_alias_callback(
    _cipher: *const c_void,
    from: *const c_char,
    _to: *const c_char,
    argument: *mut c_void,
) {
    if from.is_null() || argument.is_null() {
        return;
    }
    // SAFETY: `from` is an OpenSSL-owned NUL-terminated string, and the spelling
    // is preserved because that is the spelling Node reports.
    let Some(name) = (unsafe { read_cstr(from) }) else {
        return;
    };
    if name.is_empty() {
        return;
    }
    // SAFETY: `argument` is the live `Vec<String>` the caller passed.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
    names.push(name);
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

/// `array_push_back_provider`: records the canonical name of every cipher the
/// provider walker hands over; [`cipher_names`] does the fetch afterwards.
unsafe extern "C" fn provider_cipher_callback(cipher: *mut c_void, argument: *mut c_void) {
    if cipher.is_null() || argument.is_null() {
        return;
    }
    // SAFETY: `cipher` is live and its name is an OpenSSL-owned string.
    let name = unsafe { EVP_CIPHER_get0_name(cipher.cast()) };
    // SAFETY: `name` is an OpenSSL-owned NUL-terminated string.
    let Some(name) = (unsafe { read_cstr(name) }) else {
        return;
    };
    // SAFETY: `argument` is the live `Vec<String>` the caller passed.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
    names.push(name);
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

/// `SaveSupportedProviderMac`: records the canonical name of every MAC the
/// provider walker hands over; [`mac_names`] fetches and expands it afterwards.
///
/// `KMAC-128` answers to both `KMAC-128` and `KMAC128`, which is exactly the pair
/// Node's `getMacs()` reports.
unsafe extern "C" fn mac_callback(mac: *mut c_void, argument: *mut c_void) {
    if mac.is_null() || argument.is_null() {
        return;
    }
    // SAFETY: `mac` is live and its name is an OpenSSL-owned string.
    let name = unsafe { EVP_MAC_get0_name(mac.cast()) };
    // SAFETY: `name` is an OpenSSL-owned NUL-terminated string.
    let Some(name) = (unsafe { read_cstr(name) }) else {
        return;
    };
    // SAFETY: `argument` is the live `Vec<String>` the caller passed.
    let names: &mut Vec<String> = unsafe { &mut *(argument as *mut Vec<String>) };
    names.push(name);
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
/// # Two phases, because OpenSSL's walkers are not re-entrant-safe
///
/// Phase one runs the two traversals and records every name they report, with
/// callbacks that touch nothing but the string being handed over. Phase two does
/// the resolving, the provider name expansion, and the "does it initialise"
/// filter, all after both traversals have returned.
///
/// The split is not cosmetic. `EVP_MD_do_all_sorted` walks `OBJ_NAME`'s lhash
/// through `OBJ_NAME_do_all`, which holds no lock and writes through an
/// unchecked `d->names[d->n++]` into a stack sized before the walk began;
/// calling `EVP_MD_fetch` from inside the callback — which is what this function
/// used to do, to decide whether each name was usable — re-enters OpenSSL's init
/// and provider machinery mid-traversal and makes entries disappear. That is the
/// defect: `getHashes()` lost `RSA-SHA512` and `sha512WithRSAEncryption` on one
/// gate run and `RSA-SHA3-224` on another. It needed no CPU load, only another
/// thread in the same process resolving a digest or cipher by name, because that
/// call completes OpenSSL's one-time algorithm registration and can resize the
/// table mid-walk. See [`ENUMERATION`] for the measurements and the fix.
///
/// # The six names this list cannot contain on OpenSSL 3.6.3
///
/// `KNOWN_ABSENT_DIGESTS` names them and why. They are cSHAKE, which is not in
/// the 3.6.3 source at all; see the crate docs for the measured proof and what a
/// future fix needs. Nothing here filters them out — the walk simply never sees
/// them, which is the property that makes the list truthful rather than curated.
pub fn digest_names() -> Vec<String> {
    serialised(|| {
        // Phase one: record what the walkers report. No OpenSSL calls beyond the
        // walks themselves, so nothing can perturb a traversal in progress.
        let mut legacy: Vec<String> = Vec::new();
        let argument = (&mut legacy) as *mut Vec<String> as *mut c_void;
        // SAFETY: the walker invokes `digest_alias_callback` synchronously with
        // `argument` as its fourth parameter, and `legacy` outlives the call.
        // The legacy walker reports null `from` values, which the callback
        // checks.
        unsafe { EVP_MD_do_all_sorted(Some(digest_alias_callback), argument) };

        let mut provider: Vec<String> = Vec::new();
        let argument = (&mut provider) as *mut Vec<String> as *mut c_void;
        // SAFETY: same shape; a null `libctx` means the default context.
        unsafe {
            EVP_MD_do_all_provided(
                std::ptr::null_mut(),
                Some(provider_digest_callback),
                argument,
            )
        };

        // Phase two: everything that can reach OpenSSL's init path, now that no
        // traversal is running. It stays inside the lock on purpose: `EVP_*_fetch`
        // can *insert* into `OBJ_NAME`'s table, and that table is shared by
        // digests, ciphers and MACs alike, so a concurrent `cipher_names()` on
        // another thread would otherwise mutate the table this thread just read.
        let mut names: Vec<String> = legacy
            .into_iter()
            // `SaveSupportedHashAlgorithmsAndCacheMD` keeps only names whose
            // canonical implementation this build can actually fetch.
            .filter(|name| legacy_digest_is_supported(name))
            .collect();
        for name in provider {
            names.extend(provider_digest_names_of(&name));
        }

        filter_duplicate_strings(names, false)
            .into_iter()
            // Keep only names that actually initialise. A provider can register
            // a name whose implementation is present but unusable, and
            // advertising it would be the exact lie this module exists to
            // prevent.
            .filter(|name| resolvable_digest(name))
            .collect()
    })
}

/// Whether a legacy `OBJ_NAME` entry names a digest this build can fetch.
///
/// This is the accept test `SaveSupportedHashAlgorithmsAndCacheMD` applies: look
/// the name up in the legacy table, read the canonical implementation's name, and
/// keep the entry only if that canonical name fetches.
fn legacy_digest_is_supported(name: &str) -> bool {
    let Ok(text) = std::ffi::CString::new(name) else {
        return false;
    };
    // SAFETY: `text` is a valid NUL-terminated C string for the duration of the
    // call and the lookup only reads it.
    let legacy = unsafe { openssl_sys::EVP_get_digestbyname(text.as_ptr()) };
    if legacy.is_null() {
        return false;
    }
    // SAFETY: `legacy` is a live `EVP_MD` from OpenSSL's table.
    let canonical = unsafe { EVP_MD_get0_name(legacy.cast()) };
    // SAFETY: `canonical` is a NUL-terminated OpenSSL-owned string, which the
    // fetch only reads.
    let fetched = unsafe { fetch_supported_digest(canonical) };
    let Some(fetched) = fetched else {
        return false;
    };
    // SAFETY: `fetched` came from `EVP_MD_fetch` and is owned here; the caller
    // only wanted the accept decision.
    unsafe { openssl_sys::EVP_MD_free(fetched) };
    true
}

/// `SaveSupportedProviderHashAlgorithms`'s per-digest expansion: fetch the
/// provider digest and return every lowercased alias it answers to.
///
/// The alias names are collected inside `EVP_MD_names_do_all` but fetched only
/// afterwards, so the traversal never re-enters OpenSSL's init path. Each alias
/// still has to fetch on its own, which is the test Node applies: a provider can
/// register a name whose implementation is unusable.
fn provider_digest_names_of(name: &str) -> Vec<String> {
    let Ok(text) = std::ffi::CString::new(name) else {
        return Vec::new();
    };
    // SAFETY: `text` is a valid NUL-terminated C string and a null property query
    // is the default properties.
    let Some(fetched) = (unsafe { fetch_supported_digest(text.as_ptr()) }) else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    let argument = (&mut names) as *mut Vec<String> as *mut c_void;
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

    names
        .into_iter()
        .filter(|alias| {
            let Ok(alias_text) = std::ffi::CString::new(alias.as_str()) else {
                return false;
            };
            // SAFETY: `alias_text` is a valid NUL-terminated C string.
            let alias_fetched = unsafe { fetch_supported_digest(alias_text.as_ptr()) };
            let Some(alias_fetched) = alias_fetched else {
                return false;
            };
            // SAFETY: `alias_fetched` came from `EVP_MD_fetch` and is owned here.
            unsafe { openssl_sys::EVP_MD_free(alias_fetched) };
            true
        })
        .collect()
}

/// Every cipher name Node's `getCiphers()` reports.
///
/// Node applies no name denylist of its own: `IsSupportedFetchedCipher` is the
/// whole policy, and it is what removes `bf-cbc`, `rc4` and the `-cbc-hmac-*`
/// composites. Those entries stay out because they do not fetch or because their
/// flags say they are not a plain cipher, which is why this list needs no
/// hand-maintained table that could drift from the linked library.
///
/// The walk and the accept tests are split into two phases for the reason
/// [`ENUMERATION`] records: `EVP_CIPHER_fetch` from inside `OBJ_NAME_do_all`'s
/// traversal makes OpenSSL's walker skip entries.
pub fn cipher_names() -> Vec<String> {
    serialised(|| {
        let mut legacy: Vec<String> = Vec::new();
        let argument = (&mut legacy) as *mut Vec<String> as *mut c_void;
        // SAFETY: the walker calls the callback synchronously and `legacy`
        // outlives it.
        unsafe { EVP_CIPHER_do_all_sorted(Some(cipher_alias_callback), argument) };

        let mut provider: Vec<String> = Vec::new();
        let argument = (&mut provider) as *mut Vec<String> as *mut c_void;
        // SAFETY: same shape, same lifetime.
        unsafe {
            EVP_CIPHER_do_all_provided(
                std::ptr::null_mut(),
                Some(provider_cipher_callback),
                argument,
            )
        };

        // Inside the lock, for the reason `digest_names` records: the fetch can
        // insert into the `OBJ_NAME` table that all three enumerators share.
        let mut names: Vec<String> = legacy
            .into_iter()
            .filter(|name| legacy_cipher_is_supported(name))
            .collect();
        for name in provider {
            names.extend(provider_cipher_names_of(&name));
        }

        filter_duplicate_strings(names, false)
            .into_iter()
            // The accept test is the one `createCipheriv` uses, so a name that
            // survives this cannot then fail to construct.
            .filter(|name| cipher_is_constructible(name))
            .collect()
    })
}

/// Whether a legacy `OBJ_NAME` cipher entry names an implementation this build
/// can actually construct.
///
/// This is `array_push_back`'s accept test from `deps/ncrypto/ncrypto.cc`: the
/// legacy lookup finds the real cipher, and `EVP_CIPHER_fetch` on its canonical
/// name decides whether the public API can build it. A cipher that lives in an
/// unloaded provider (`bf-cbc`, `rc4`) fails the fetch and stays out.
fn legacy_cipher_is_supported(name: &str) -> bool {
    let Ok(text) = std::ffi::CString::new(name) else {
        return false;
    };
    // SAFETY: `text` is a valid NUL-terminated C string for the duration of the
    // call and the lookup only reads it.
    let real = unsafe { openssl_sys::EVP_get_cipherbyname(text.as_ptr()) };
    if real.is_null() {
        return false;
    }
    // SAFETY: `real` is a live `EVP_CIPHER` from OpenSSL's table, and its
    // canonical name is an OpenSSL-owned NUL-terminated string.
    unsafe { fetch_cipher_is_supported(EVP_CIPHER_get0_name(real.cast())) }
}

/// `array_push_back_provider`: every lowercased alias the provider cipher
/// answers to.
///
/// The aliases are collected inside `EVP_CIPHER_names_do_all` but fetched only
/// afterwards, so the traversal never re-enters OpenSSL's init path.
fn provider_cipher_names_of(name: &str) -> Vec<String> {
    let Ok(text) = std::ffi::CString::new(name) else {
        return Vec::new();
    };
    // SAFETY: `text` is a valid NUL-terminated C string.
    let fetched = unsafe { fetch_cipher(text.as_ptr()) };
    let Some(fetched) = fetched else {
        return Vec::new();
    };
    if !unsafe { is_supported_fetched_cipher(fetched.cast()) } {
        // SAFETY: `fetched` came from `EVP_CIPHER_fetch` and is owned here.
        unsafe { openssl_sys::EVP_CIPHER_free(fetched) };
        return Vec::new();
    }
    let mut names: Vec<String> = Vec::new();
    let argument = (&mut names) as *mut Vec<String> as *mut c_void;
    // SAFETY: the walker invokes the callback synchronously with `argument`, and
    // `fetched` is live for the duration.
    unsafe {
        EVP_CIPHER_names_do_all(
            fetched.cast(),
            Some(provider_cipher_name_callback),
            argument,
        )
    };
    // SAFETY: `fetched` came from `EVP_CIPHER_fetch` and is owned here.
    unsafe { openssl_sys::EVP_CIPHER_free(fetched) };
    names
}

/// `EVP_CIPHER_fetch` for a NUL-terminated name pointer.
///
/// # Safety
///
/// `name` must be null or a NUL-terminated string. The returned pointer is owned
/// by the caller and needs `EVP_CIPHER_free`.
unsafe fn fetch_cipher(name: *const c_char) -> Option<*mut openssl_sys::EVP_CIPHER> {
    if name.is_null() {
        return None;
    }
    // SAFETY: the name is valid and a null property query means the default
    // properties.
    let fetched =
        unsafe { openssl_sys::EVP_CIPHER_fetch(std::ptr::null_mut(), name, std::ptr::null()) };
    (!fetched.is_null()).then_some(fetched)
}

/// Whether `EVP_CIPHER_fetch` on a name pointer succeeds and the result passes
/// `IsSupportedFetchedCipher`.
///
/// # Safety
///
/// `name` must be null or a NUL-terminated string.
unsafe fn fetch_cipher_is_supported(name: *const c_char) -> bool {
    let Some(fetched) = (unsafe { fetch_cipher(name) }) else {
        return false;
    };
    // SAFETY: `fetched` is live and owned here.
    let supported = unsafe { is_supported_fetched_cipher(fetched.cast()) };
    // SAFETY: `fetched` came from `EVP_CIPHER_fetch` and is owned here.
    unsafe { openssl_sys::EVP_CIPHER_free(fetched) };
    supported
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
    serialised(|| {
        // Phase one: record the canonical names the provider walker reports. See
        // [`ENUMERATION`]; the fetch below must not run inside the traversal.
        let mut canonical: Vec<String> = Vec::new();
        let argument = (&mut canonical) as *mut Vec<String> as *mut c_void;
        // SAFETY: the walker invokes the callback synchronously with `argument`,
        // and `canonical` outlives the call; a null `libctx` means the default
        // context.
        unsafe { EVP_MAC_do_all_provided(std::ptr::null_mut(), Some(mac_callback), argument) };

        // Phase two: expand each canonical name into the aliases it answers to,
        // inside the lock so no concurrent enumerator can mutate the shared
        // `OBJ_NAME` table mid-read.
        let mut names: Vec<String> = Vec::new();
        for name in canonical {
            names.extend(mac_aliases_of(&name));
        }

        // `getMacs` is `filterDuplicateStrings(_getMacs(), true)`, so the values
        // are lowercased and the dedupe keeps the lowercase spelling.
        filter_duplicate_strings(names, true)
            .into_iter()
            // The same rule as the other two lists: a name that is advertised
            // but cannot be fetched is worse than an absent one.
            .filter(|name| mac_is_fetchable(name))
            .collect()
    })
}

/// `SaveSupportedProviderMac`'s per-MAC expansion: fetch the MAC and return every
/// lowercased alias it answers to.
fn mac_aliases_of(name: &str) -> Vec<String> {
    let Ok(text) = std::ffi::CString::new(name) else {
        return Vec::new();
    };
    // SAFETY: `text` is a valid NUL-terminated C string and a null property query
    // means the default properties.
    let fetched = unsafe {
        openssl_sys::EVP_MAC_fetch(std::ptr::null_mut(), text.as_ptr(), std::ptr::null())
    };
    if fetched.is_null() {
        return Vec::new();
    }
    let mut names: Vec<String> = Vec::new();
    let argument = (&mut names) as *mut Vec<String> as *mut c_void;
    // SAFETY: the walker invokes the callback synchronously with `argument`, and
    // `fetched` is live for the duration.
    unsafe { EVP_MAC_names_do_all(fetched.cast(), Some(mac_name_callback), argument) };
    // SAFETY: `fetched` came from `EVP_MAC_fetch` and is owned here.
    unsafe { openssl_sys::EVP_MAC_free(fetched) };
    names
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

    /// The environment variable that marks a child of
    /// [`a_walk_racing_openssl_registration_loses_no_names`].
    const REGISTRATION_CHILD: &str = "RN_BIND_CRYPTO_REGISTRATION_CHILD";

    /// How many cold children the parent requires to pass.
    ///
    /// Racing one walk against one registration lost names on 31 of 80 fresh
    /// children pre-fix, so 20 children all passing by chance is about
    /// (49/80)^20 ≈ 7e-5. Each child is milliseconds of work, and the whole test
    /// is bounded by [`REGISTRATION_DEADLINE`] so a hang cannot wedge the suite.
    const REGISTRATION_ATTEMPTS: usize = 20;

    /// Wall-clock ceiling for the whole test, including every child.
    const REGISTRATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

    /// A walk must not lose names when OpenSSL's one-time registration runs
    /// beside it.
    ///
    /// This is the regression test for the gate failures that made
    /// `get_hashes_matches_node_except_the_declared_gap` lose `RSA-SHA512` +
    /// `sha512WithRSAEncryption` once and `RSA-SHA3-224` another time, while
    /// passing 6/6 in isolation.
    ///
    /// # Why this shape, and not a thread storm
    ///
    /// CPU load is irrelevant: four busy-loop threads beside the filtered test
    /// changed nothing. So did 16 threads merely calling `digest_names()`
    /// together, once the fetches stopped re-entering the walk. What does
    /// reproduce it is one thread walking while another makes the *first*
    /// `EVP_get_digestbyname`/`EVP_get_cipherbyname` call in the process: those
    /// run `OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS | ..._CIPHERS)`,
    /// whose `openssl_add_all_*_int()` inserts dozens of entries into the shared
    /// `OBJ_NAME` lhash. The insert can trigger `expand()`, which reallocs the
    /// bucket array and relinks nodes mid-traversal, and `OBJ_NAME_do_all` holds
    /// no lock while indexing that array. Pre-fix that lost names on 31 of 80
    /// fresh children; with the walk alone it never lost one (0 of 80).
    ///
    /// That is also why it needs the whole differential binary: the other tests
    /// resolve digests and ciphers by name, so they are what performs the first
    /// registration. Run alone against a warm process, the enumeration is stable.
    ///
    /// # Why the expectation is not hardcoded
    ///
    /// The child compares the racing walk against a walk taken *afterwards*, when
    /// nothing is in flight. That follows whatever this build's OpenSSL supplies
    /// and still fails the instant timing changes the answer, which is the
    /// property the list promises: `digest_names()` is a function of the linked
    /// library, never of scheduling.
    #[test]
    fn a_walk_racing_openssl_registration_loses_no_names() {
        if std::env::var_os(REGISTRATION_CHILD).is_some() {
            walk_racing_registration();
            return;
        }

        let executable = std::env::current_exe().expect("the test binary has a path");
        let started = std::time::Instant::now();
        for attempt in 0..REGISTRATION_ATTEMPTS {
            assert!(
                started.elapsed() < REGISTRATION_DEADLINE,
                "the registration probe exceeded {REGISTRATION_DEADLINE:?} after \
                 {attempt} of {REGISTRATION_ATTEMPTS} children"
            );
            let output = std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "enumerate::tests::a_walk_racing_openssl_registration_loses_no_names",
                    "--nocapture",
                ])
                .env(REGISTRATION_CHILD, "1")
                .output()
                .expect("spawn the probe child");
            assert!(
                output.status.success(),
                "cold child {attempt} lost names while OpenSSL registered its \
                 algorithms\n--- stdout ---\n{}\n--- stderr ---\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// The child half of
    /// [`a_walk_racing_openssl_registration_loses_no_names`].
    ///
    /// Two threads leave a barrier together: one walks, the other performs the
    /// process's first `EVP_get_digestbyname`/`EVP_get_cipherbyname` calls. The
    /// walker then has to match a walk taken after both have finished.
    fn walk_racing_registration() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let walker_barrier = std::sync::Arc::clone(&barrier);
        let walker = std::thread::spawn(move || {
            walker_barrier.wait();
            digest_names()
        });
        let registrar_barrier = std::sync::Arc::clone(&barrier);
        let registrar = std::thread::spawn(move || {
            registrar_barrier.wait();
            // Exactly the calls the other tests make, and exactly what
            // `serialised` front-loads. Deliberately *not* `serialised`, so this
            // reproduces a caller that resolves a digest without enumerating
            // first — which is what the differential binary does.
            for name in [c"sha256".as_ptr(), c"aes-128-cbc".as_ptr()] {
                // SAFETY: both literals are static NUL-terminated C strings and
                // the lookups only read them.
                unsafe {
                    openssl_sys::EVP_get_digestbyname(name);
                    openssl_sys::EVP_get_cipherbyname(name);
                }
            }
        });

        let raced = walker.join().expect("the walking thread finished");
        registrar.join().expect("the registering thread finished");

        // Nothing is in flight now, so this is what a quiet process reports.
        let settled = digest_names();
        assert!(!settled.is_empty(), "a settled walk reported no digests");
        assert_eq!(
            raced,
            settled,
            "the walk saw {} digests but a settled walk sees {}; the enumeration \
             is not deterministic across OpenSSL's algorithm registration.\n\
             missing: {:?}",
            raced.len(),
            settled.len(),
            settled
                .iter()
                .filter(|name| !raced.contains(name))
                .collect::<Vec<_>>()
        );
    }
}
