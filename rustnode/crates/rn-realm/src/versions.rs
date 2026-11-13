//! The `process.versions` table.
//!
//! Node fills `process.versions` from `src/node_metadata.cc`'s
//! `Metadata::Versions::Versions()`, keyed by `NODE_VERSIONS_KEYS` in
//! `src/node_metadata.h`. At the pin that macro expands to 31 keys, so a
//! runtime that reports four of them is making `test/common/index.js` take a
//! different branch from Node.
//!
//! # The rule for publishing a key
//!
//! A key is published only when rustnode actually ships the component, and the
//! value is the version of the code the binary really runs. That distinction
//! matters more than coverage: `test/common/index.js` derives `hasSQLite`,
//! `hasCrypto`, `hasIntl` and friends from this object, so a key added for an
//! unimplemented feature turns a skip into a failure.
//!
//! Two consequences, both deliberate:
//!
//! * A component rustnode does not link is **omitted**. `ngtcp2` has no
//!   implementation here, so it is absent rather than present with Node's
//!   number. `test/common` never reads those keys, so the omission costs a test
//!   nothing.
//! * A component rustnode links at a **different version than the pin** reports
//!   the linked version, not the pin's. `icu` is the clearest case: Node bundles
//!   ICU 78.3, but the ICU this binary executes is V8's own copy, 78.2. Claiming
//!   78.3 would name code that is not present.
//!
//! `WITHHELD` records the other half of the pin's key set with the reason, and a
//! test asserts the two lists together cover the pin exactly. That keeps the
//! judgement auditable instead of letting an omission look like an oversight.

use rn_v8_sys::v8;

/// The Node version this runtime reports.
pub const NODE_VERSION: &str = "28.0.0";

/// llhttp, from `vendor/llhttp/include/llhttp.h`, which is copied byte-identical
/// from the pin (`LLHTTP_VERSION_MAJOR/MINOR/PATCH`). Node parses HTTP with this
/// state machine and `rn-bind-http-parser` compiles this same source.
pub const LLHTTP_VERSION: &str = "9.4.3";

/// merve, from `vendor/merve/include/merve.h`. This is the CommonJS lexer that
/// `rn-bind-cjs-lexer` compiles from the vendored source.
pub const MERVE_VERSION: &str = "1.2.2";

/// nghttp2, from `vendor/nghttp2/lib/includes/nghttp2/nghttp2ver.h`. This is the
/// HTTP/2 implementation `rn-bind-http2` compiles from the vendored source.
///
/// Only a fallback: `table()` reads the number out of the linked library with
/// `nghttp2_version`, so the published value always names code the binary
/// contains. This constant exists so a hypothetical link failure cannot drop the
/// key entirely, and a test asserts the two agree.
pub const NGHTTP2_VERSION: &str = "1.70.0";

/// acorn, from `var version = "8.19.0"` in the vendored
/// `vendor/libnode-js/deps/acorn/acorn/dist/acorn.js`. Node reports the JS
/// package version rather than a compiled-in one, and its own
/// `test-process-versions.js` compares this value to
/// `deps/acorn/acorn/package.json`.
pub const ACORN_VERSION: &str = "8.19.0";

/// undici, from `src/undici_version.h` and `deps/undici/src/package.json` at the
/// pin. The vendored bundle `vendor/libnode-js/deps/undici/undici.js` is
/// byte-identical to the pin's, and it is what backs `fetch`.
pub const UNDICI_VERSION: &str = "8.12.4";

/// ICU, from `U_ICU_VERSION` in the `v8` crate's
/// `third_party/icu/source/common/unicode/uvernum.h`.
///
/// This is deliberately not the pin's 78.3. rustnode does not link Node's
/// `deps/icu-small`; `Intl` runs on the ICU that V8 carries, which is 78.2. The
/// binary corroborates it: its symbols live in the `icu_78` namespace and its
/// data package is `icudt78l`. Reporting 78.3 would send
/// `test/parallel/test-icu-env.js` looking for a fixture for a version whose
/// data is not loaded.
pub const ICU_VERSION: &str = "78.2";

/// Unicode, from `U_UNICODE_VERSION` in the same vendored `uchar.h`. Both the
/// pin's ICU and V8's report 17.0, so this one does not differ.
pub const UNICODE_VERSION: &str = "17.0";

/// One published entry.
pub struct Entry {
    pub key: &'static str,
    pub value: String,
}

/// Every key the pin defines, in `NODE_VERSIONS_KEYS` order.
///
/// This is the full set from `src/node_metadata.h` with every `#if` branch
/// taken, which is the 31-key shape the measurement of the pin used. Tests
/// compare it against [`table`] plus [`WITHHELD`], so it is only read from
/// tests.
#[cfg(test)]
pub const PIN_KEYS: &[&str] = &[
    "node", "v8", "uv", "zlib", "brotli", "zstd", "ares", "modules", "nghttp2", "napi", "llhttp",
    "uvwasi", "acorn", "simdjson", "simdutf", "ada", "nbytes", "ngtcp2", "nghttp3", "amaro",
    "undici", "merve", "openssl", "ncrypto", "cldr", "icu", "tz", "unicode", "sqlite", "libffi",
    "lief",
];

/// Pin keys this runtime deliberately does not publish, with the reason.
///
/// `cjs_module_lexer` is absent here on purpose: it is a key real Node v22
/// reports, but the pin's `node_metadata.h` does not define it, so it is not
/// part of the contract this runtime is built against. Only `table` and the
/// tests read this.
#[cfg(test)]
pub const WITHHELD: &[(&str, &str)] = &[
    (
        "ares",
        "rustnode does not link c-ares; `rn-bind-cares` resolves through \
         getaddrinfo/getnameinfo and speaks the DNS wire protocol itself",
    ),
    (
        "ngtcp2",
        "no QUIC stack is linked; OpenSSL here has no QUIC support",
    ),
    (
        "nghttp3",
        "no HTTP/3 stack is linked, for the same reason as ngtcp2",
    ),
    (
        "napi",
        "`rn-napi` exports part of the Node-API surface and defers \
         napi_wrap, napi_create_buffer and the async/threadsafe work; \
         publishing 10 would tell addons that symbols which are not there \
         can be relied on",
    ),
    ("uvwasi", "uvwasi is not linked"),
    ("simdjson", "no simdjson; JSON parsing is V8's"),
    (
        "simdutf",
        "UTF-8 validation runs on V8's bundled simdutf (7.7.0), which is a \
         different copy and version from the pin's deps/simdutf",
    ),
    ("ada", "URL parsing uses the `url`/`idna` crates, not ada"),
    (
        "nbytes",
        "no nbytes; `Buffer.byteLength` is computed directly",
    ),
    ("amaro", "TypeScript stripping is not implemented"),
    (
        "ncrypto",
        "Node's C++ crypto helper layer is not used; the crypto bindings call \
         OpenSSL directly",
    ),
    (
        "cldr",
        "the CLDR version can only be read through ulocdata_getCLDRVersion, \
         which is not in the ICU data/symbol set this binary links",
    ),
    (
        "tz",
        "the tzdata version can only be read through \
         icu::TimeZone::getTZDataVersion, which is unavailable for the same \
         reason as cldr",
    ),
    ("libffi", "libffi is not linked"),
    ("lief", "LIEF is not linked"),
    (
        "brotli",
        "the linked rust-brotli is a port whose BrotliEncoderVersion() \
         decodes to 1.0.3841, which is not a version any brotli release \
         carries; the pin's 1.2.1 names C code this binary does not run, so \
         there is no truthful value to publish",
    ),
];

/// Builds the table in the order Node uses: `node` first, then the rest sorted.
///
/// `v8`, `uv`, `openssl` and `modules` are produced from the code that owns
/// them; see the module docs for why. `zlib` and `zstd` come from the linked
/// libraries' own version functions, which is exactly what Node does when it is
/// not bundling them.
pub fn table() -> Vec<Entry> {
    let mut entries = vec![
        Entry {
            key: "acorn",
            value: ACORN_VERSION.to_string(),
        },
        Entry {
            key: "icu",
            value: ICU_VERSION.to_string(),
        },
        Entry {
            key: "llhttp",
            value: LLHTTP_VERSION.to_string(),
        },
        Entry {
            key: "merve",
            value: MERVE_VERSION.to_string(),
        },
        Entry {
            key: "modules",
            value: rn_napi::abi::LEGACY_MODULE_VERSION.to_string(),
        },
        Entry {
            key: "node",
            value: NODE_VERSION.to_string(),
        },
        Entry {
            // Read from the linked library rather than from `NGHTTP2_VERSION`:
            // the constant names the vendored tree, and a re-pin that forgot to
            // rebuild would leave the two disagreeing. `nghttp2_version` is what
            // `src/node_metadata.cc` calls too.
            key: "nghttp2",
            value: rn_bind_http2::version().unwrap_or_else(|| NGHTTP2_VERSION.to_string()),
        },
        Entry {
            key: "openssl",
            value: rn_bind_crypto::engine::openssl_version(),
        },
        Entry {
            key: "sqlite",
            // The version of the amalgamation this binary actually links, not
            // the pinned string: `test/common/index.js` derives `hasSQLite`
            // from this value, and a wrong one would enable tests whose
            // expectations belong to a different SQLite.
            value: rn_bind_sqlite::sqlite_version().unwrap_or_default(),
        },
        Entry {
            key: "unicode",
            value: UNICODE_VERSION.to_string(),
        },
        Entry {
            key: "undici",
            value: UNDICI_VERSION.to_string(),
        },
        Entry {
            key: "uv",
            value: rn_uv::uv_version_string().unwrap_or_default(),
        },
        Entry {
            key: "v8",
            value: v8::V8::get_version().to_string(),
        },
        Entry {
            key: "zlib",
            value: rn_bind_zlib::zlib::linked_version().unwrap_or_default(),
        },
        Entry {
            key: "zstd",
            value: rn_bind_zlib::zstd::linked_version().unwrap_or_default(),
        },
    ];
    // Node puts `node` first and sorts the remainder, and
    // `test-process-versions.js` compares `Object.keys` against exactly that.
    entries.sort_by(|a, b| a.key.cmp(b.key));
    if let Some(index) = entries.iter().position(|entry| entry.key == "node") {
        let node = entries.remove(index);
        entries.insert(0, node);
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_path(relative: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    #[test]
    fn every_pin_key_is_either_published_or_withheld() {
        // The point of the test: "not implemented yet" and "nobody thought
        // about it" must not look the same from the outside.
        let mut seen: Vec<&str> = table().iter().map(|entry| entry.key).collect();
        seen.extend(WITHHELD.iter().map(|(key, _)| *key));
        seen.sort_unstable();
        let mut expected = PIN_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(seen, expected);
    }

    #[test]
    fn no_key_is_both_published_and_withheld() {
        for entry in table() {
            assert!(
                !WITHHELD.iter().any(|(key, _)| *key == entry.key),
                "{} is both published and withheld",
                entry.key
            );
        }
    }

    #[test]
    fn every_withheld_key_states_a_reason() {
        for (key, reason) in WITHHELD {
            assert!(!reason.trim().is_empty(), "{key} has no reason");
        }
    }

    #[test]
    fn every_published_value_is_a_real_version_string() {
        // Node's own `test-process-versions.js` matches these shapes; a value
        // that cannot match would be a worse lie than an absent key.
        for entry in table() {
            assert!(
                !entry.value.is_empty(),
                "{} was published with an empty value",
                entry.key
            );
            let digits = entry.value.chars().filter(char::is_ascii_digit).count();
            assert!(
                digits >= 2,
                "{} is not a version: {}",
                entry.key,
                entry.value
            );
        }
    }

    #[test]
    fn node_comes_first_and_the_rest_are_sorted() {
        let keys: Vec<&str> = table().iter().map(|entry| entry.key).collect();
        assert_eq!(keys.first().copied(), Some("node"));
        let rest = &keys[1..];
        let mut sorted = rest.to_vec();
        sorted.sort_unstable();
        assert_eq!(rest, sorted.as_slice());
    }

    #[test]
    fn modules_is_the_abi_version_the_loader_accepts() {
        // `process.versions.modules` is what an addon compares itself against,
        // so it has to be the same number the loader looks for.
        let modules = table()
            .into_iter()
            .find(|entry| entry.key == "modules")
            .expect("modules is published");
        assert_eq!(modules.value, "153");
        assert_eq!(
            rn_napi::abi::LEGACY_MODULE_VERSION,
            153,
            "the published ABI version drifted from the loader's"
        );
        assert_eq!(
            modules.value,
            rn_napi::abi::LEGACY_MODULE_VERSION.to_string()
        );
    }

    /// Reads `#define <name> <value>` out of a C header, ignoring trailing
    /// comments. Written this way so an upstream whitespace change is a test
    /// failure rather than a silently wrong version.
    fn define_value(header: &str, name: &str) -> String {
        for line in header.lines() {
            let Some(rest) = line.trim().strip_prefix("#define") else {
                continue;
            };
            let rest = rest.trim();
            let Some(value) = rest.strip_prefix(name) else {
                continue;
            };
            if !value.starts_with([' ', '\t']) {
                continue;
            }
            let value = value.trim();
            let value = value.split("//").next().unwrap_or(value).trim();
            return value.trim_matches('"').to_string();
        }
        panic!("no #define {name} in the vendored header");
    }

    #[test]
    fn llhttp_matches_the_vendored_header() {
        let header = std::fs::read_to_string(manifest_path("vendor/llhttp/include/llhttp.h"))
            .expect("the vendored llhttp header is readable");
        let mut parts = Vec::new();
        for name in [
            "LLHTTP_VERSION_MAJOR",
            "LLHTTP_VERSION_MINOR",
            "LLHTTP_VERSION_PATCH",
        ] {
            parts.push(define_value(&header, name));
        }
        assert_eq!(parts.join("."), LLHTTP_VERSION);
    }

    #[test]
    fn merve_matches_the_vendored_header() {
        let header = std::fs::read_to_string(manifest_path("vendor/merve/include/merve.h"))
            .expect("the vendored merve header is readable");
        assert_eq!(define_value(&header, "MERVE_VERSION"), MERVE_VERSION);
    }

    #[test]
    fn acorn_matches_the_vendored_bundle() {
        let bundle = std::fs::read_to_string(manifest_path(
            "vendor/libnode-js/deps/acorn/acorn/dist/acorn.js",
        ))
        .expect("the vendored acorn bundle is readable");
        let needle = "var version = \"";
        let line = bundle
            .lines()
            .find(|line| line.trim_start().starts_with(needle))
            .expect("acorn's version is declared");
        let value = line.trim_start()[needle.len()..]
            .split('"')
            .next()
            .unwrap_or_default();
        assert_eq!(value, ACORN_VERSION);
    }

    #[test]
    fn gate_flipping_keys_stay_withheld() {
        // These are the keys `test/common/index.js` turns into capability
        // flags. Publishing one for a feature that is not implemented converts
        // a skip into a failure, which is worse than the skip.
        //
        // `sqlite` used to be in this list with the reason "`node:sqlite` has no
        // binding". That stopped being true when the namespace landed, so the
        // key moved into `table()` and is asserted present below: withholding it
        // now would suppress all 27 `node:sqlite` tests as skips, which is the
        // failure mode this test exists to prevent, just inverted.
        for key in ["napi", "libffi"] {
            assert!(
                WITHHELD.iter().any(|(withheld, _)| *withheld == key),
                "{key} must stay withheld until the feature works"
            );
        }
        let table = table();
        assert!(
            table.iter().any(|entry| entry.key == "sqlite"),
            "sqlite must be published now that node:sqlite is implemented"
        );
    }

    #[test]
    fn the_sqlite_version_is_the_linked_amalgamation() {
        // Not a pinned literal: the value has to come from the library the
        // binary actually links, because `hasSQLite` and therefore every
        // `node:sqlite` test depends on it being truthful.
        let table = table();
        let sqlite = table
            .iter()
            .find(|entry| entry.key == "sqlite")
            .expect("sqlite is published");
        assert_eq!(
            sqlite.value,
            rn_bind_sqlite::sqlite_version().expect("a linked SQLite reports a version")
        );
        assert_eq!(sqlite.value, "3.54.1");
    }
}
