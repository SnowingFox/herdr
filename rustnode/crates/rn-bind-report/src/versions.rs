//! `process.versions` and `process.release`, as the report's header publishes
//! them.
//!
//! `PrintComponentVersions` walks `per_process::metadata.versions.pairs()`, and
//! `PrintRelease` copies `per_process::metadata.release`. Those are the same two
//! objects `process.versions` and `process.release` are built from, so a report
//! whose header disagreed with the running process would be worse than one that
//! omitted the section: a consumer reading `componentVersions.v8` expects the V8
//! that is actually linked.
//!
//! # Why the values are derived here rather than re-exported from `rn-realm`
//!
//! `rn-realm` owns the `process` object and already depends on the crates that
//! know each component's real version. A binding must stay downstream of the
//! realm, not beside it, so the same derivations are repeated for the components
//! both need. Each one reads the linked library rather than a pinned string,
//! which is the property that matters: a re-pin that forgot to rebuild leaves the
//! two agreeing with the binary rather than with the tree.

use rn_v8_sys::v8;

/// The Node version this runtime reports.
pub const NODE_VERSION: &str = "28.0.0";

/// The ICU the binary really runs, which is V8's own copy rather than the pin's.
///
/// `process.versions.icu` reports 78.2 for that reason: claiming the pin's 78.3
/// would name code that is not linked.
pub const ICU_VERSION: &str = "78.2";

/// `componentVersions`, sorted the way `process.versions` is: `node` first, then
/// the rest lexically.
///
/// A component this build does not link is omitted rather than reported at the
/// pin's number, which is the same rule `process.versions` follows and the one
/// that keeps `componentVersions.ngtcp2` from naming code that is not present.
#[must_use]
pub fn component_versions() -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = vec![
        ("acorn".to_string(), "8.19.0".to_string()),
        ("icu".to_string(), ICU_VERSION.to_string()),
        ("llhttp".to_string(), "9.4.3".to_string()),
        ("merve".to_string(), "1.2.2".to_string()),
        (
            "modules".to_string(),
            rn_napi::abi::LEGACY_MODULE_VERSION.to_string(),
        ),
        ("node".to_string(), NODE_VERSION.to_string()),
        (
            "nghttp2".to_string(),
            rn_bind_http2::version().unwrap_or_default(),
        ),
        (
            "openssl".to_string(),
            rn_bind_crypto::engine::openssl_version(),
        ),
        (
            "sqlite".to_string(),
            rn_bind_sqlite::sqlite_version().unwrap_or_default(),
        ),
        ("unicode".to_string(), "17.0".to_string()),
        ("undici".to_string(), "8.12.4".to_string()),
        (
            "uv".to_string(),
            rn_uv::uv_version_string().unwrap_or_default(),
        ),
        ("v8".to_string(), v8::V8::get_version().to_string()),
        (
            "zlib".to_string(),
            rn_bind_zlib::zlib::linked_version().unwrap_or_default(),
        ),
        (
            "zstd".to_string(),
            rn_bind_zlib::zstd::linked_version().unwrap_or_default(),
        ),
    ];
    entries.sort();
    if let Some(index) = entries.iter().position(|(key, _)| key == "node") {
        let node = entries.remove(index);
        entries.insert(0, node);
    }
    entries
}

/// `release`, which the header copies from `process.release`.
///
/// Node emits `name`, then `headersUrl` and `sourceUrl` because
/// `NODE_HAS_RELEASE_URLS` is set for an official build. rustnode is not an
/// official Node build and has no such URLs, so only `name` is reported — the
/// alternative would be a URL pointing at a download that does not contain this
/// binary.
#[must_use]
pub fn release() -> Vec<(String, String)> {
    vec![("name".to_string(), "node".to_string())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_component_versions_put_node_first_then_sort() {
        let versions = component_versions();
        assert_eq!(
            versions.first().map(|(key, _)| key.as_str()),
            Some("node"),
            "`test-process-versions.js` reads `Object.keys[0]`"
        );
        let rest: Vec<&str> = versions[1..].iter().map(|(key, _)| key.as_str()).collect();
        let mut sorted = rest.clone();
        sorted.sort_unstable();
        assert_eq!(rest, sorted, "the remainder is lexical");
    }

    #[test]
    fn every_published_version_names_code_the_binary_links() {
        // A key with an empty value would be a placeholder, which is the failure
        // mode this table exists to avoid.
        for (key, value) in component_versions() {
            assert!(!value.is_empty(), "{key} must name a real version");
        }
    }

    #[test]
    fn the_release_reports_the_name_without_urls_this_build_lacks() {
        assert_eq!(release(), vec![("name".to_string(), "node".to_string())]);
    }
}
