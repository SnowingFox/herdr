//! `format` and origin serialization.
//!
//! `url_aggregator::get_origin` and `url_aggregator::Format` are both small, but
//! both encode decisions that look arbitrary until the JavaScript is read:
//!
//! * `origin` is `"null"` unless the scheme is special. `file:` is special and
//!   still answers `"null"`, and `blob:` is not special but inherits the origin
//!   of its path when that path is `http:` or `https:`.
//! * `format` deletes components rather than rebuilding the URL, so removing
//!   the search from `…/p?#` leaves `…/p` rather than `…/p?`. It also rewrites
//!   the host when `unicode` is set, and that rewrite is *re-parsed*, which is
//!   how a punycode host becomes its Unicode spelling while a port survives.

use url::Url;

use crate::idna;
use crate::model::{scheme_type, Offsets};

/// `scheme::type` values that `lib/internal/url.js` compares against by number.
const NOT_SPECIAL: u32 = 1;
const FILE: u32 = 6;
const HTTP: u32 = 0;
const HTTPS: u32 = 2;

/// `url_aggregator::get_origin`, as `getOrigin` returns it.
///
/// The result is a string in every case: an opaque origin is the four
/// characters `null`, not JavaScript `null`.
pub fn origin(url: &Url) -> String {
    let scheme = url.scheme();
    let kind = scheme_type(scheme);

    if kind != NOT_SPECIAL {
        // A `file:` URL's origin is opaque even though the scheme is special.
        if kind == FILE {
            return "null".to_string();
        }
        return format!("{scheme}://{}", host_and_port(url));
    }

    if scheme == "blob" {
        // A blob URL's "path" is an inner URL. Only an http(s) inner URL has an
        // origin Node will report; everything else, including a `blob:` URL with
        // an empty path, is opaque.
        let inner = url.path();
        if !inner.is_empty() {
            if let Ok(parsed) = Url::parse(inner) {
                if matches!(scheme_type(parsed.scheme()), HTTP | HTTPS) {
                    return format!("{}://{}", parsed.scheme(), host_and_port(&parsed));
                }
            }
        }
    }

    "null".to_string()
}

/// The host, with the port appended only when there is a non-default one.
///
/// The `url` crate already omits a port equal to the scheme's default, so
/// `url.port()` returning `None` is exactly "no port to print".
fn host_and_port(url: &Url) -> String {
    let mut rendered = url.host_str().unwrap_or("").to_string();
    if let Some(port) = url.port() {
        rendered.push(':');
        rendered.push_str(&port.to_string());
    }
    rendered
}

/// `BindingData::Format` with the JS flag names made explicit.
///
/// `keep_fragment`, `keep_search` and `keep_auth` are "keep" flags, matching the
/// JavaScript (`options.fragment = false` removes the fragment). `unicode`
/// rewrites the hostname rather than dropping anything.
///
/// An href that does not parse is returned unchanged. `node_url.cc` asserts the
/// re-parse succeeded, which aborts the process; returning the input is the
/// documented difference in the crate docs and cannot be worse for a caller.
pub fn format(
    href: &str,
    keep_fragment: bool,
    unicode: bool,
    keep_search: bool,
    keep_auth: bool,
) -> String {
    let Ok(mut url) = Url::parse(href) else {
        return href.to_string();
    };

    if !keep_fragment {
        url.set_fragment(None);
    }
    if !keep_search {
        url.set_query(None);
    }
    if !keep_auth {
        // Clearing both is order-dependent: `set_password(None)` drops the
        // password and the `:`, and an empty username drops the `@` as well.
        url.set_password(None).ok();
        url.set_username("").ok();
    }
    if unicode {
        if let Some(hostname) = url.host_str().map(str::to_string) {
            let decoded = idna::host_to_unicode(&hostname);
            if decoded != hostname {
                // The host cannot be reassigned through `set_host`: that runs
                // host parsing, which would punycode the Unicode straight back.
                // ada instead writes the decoded text into its href buffer, so
                // the serialization is spliced at the host's byte range here.
                let href = url.as_str().to_string();
                let offsets = Offsets::of(&url);
                let host_start = offsets.host_start as usize;
                // `host_start` may be the '@', with the hostname one byte later.
                let hostname_start = if href.as_bytes().get(host_start) == Some(&b'@') {
                    host_start + 1
                } else {
                    host_start
                };
                let hostname_end = offsets.host_end as usize;
                let mut spliced = String::with_capacity(href.len() + decoded.len());
                spliced.push_str(&href[..hostname_start.min(href.len())]);
                spliced.push_str(&decoded);
                spliced.push_str(&href[hostname_end.min(href.len())..]);
                return spliced;
            }
        }
    }

    url.as_str().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn formatted(href: &str, fragment: bool, unicode: bool, search: bool, auth: bool) -> String {
        format(href, fragment, unicode, search, auth)
    }

    #[test]
    fn everything_kept_is_the_identity() {
        let href = "https://user:pw@example.com:8080/a/b?q=1#f";
        assert_eq!(formatted(href, true, false, true, true), href);
    }

    #[test]
    fn dropping_the_fragment_removes_the_hash_and_its_text() {
        assert_eq!(
            formatted("https://a.com/p?q#f", false, false, true, true),
            "https://a.com/p?q"
        );
    }

    #[test]
    fn dropping_the_search_removes_the_question_mark() {
        assert_eq!(
            formatted("https://a.com/p?q#f", true, false, false, true),
            "https://a.com/p#f"
        );
    }

    #[test]
    fn an_empty_search_is_dropped_entirely_not_left_as_a_bare_question_mark() {
        assert_eq!(
            formatted("http://example.com/?", true, false, false, true),
            "http://example.com/"
        );
    }

    #[test]
    fn dropping_auth_removes_both_credentials() {
        assert_eq!(
            formatted(
                "https://user:pw@example.com:8080/a?q#f",
                true,
                false,
                true,
                false
            ),
            "https://example.com:8080/a?q#f"
        );
    }

    #[test]
    fn unicode_replaces_a_punycoded_hostname_and_keeps_the_port() {
        assert_eq!(
            formatted("http://xn--9ca.com:8080/x?q#h", true, true, true, true),
            "http://é.com:8080/x?q#h"
        );
    }

    #[test]
    fn unicode_leaves_a_non_punycoded_host_alone() {
        assert_eq!(
            formatted("http://example.com/x", true, true, true, true),
            "http://example.com/x"
        );
    }

    #[test]
    fn an_unparsable_href_is_returned_unchanged() {
        // Node aborts here; see the crate docs.
        assert_eq!(formatted("bad url", true, false, true, true), "bad url");
    }

    #[test]
    fn an_http_origin_is_scheme_and_authority_without_credentials() {
        let url = Url::parse("https://user:pw@example.com:8080/a?q#f").expect("parses");
        assert_eq!(origin(&url), "https://example.com:8080");
    }

    #[test]
    fn a_default_port_is_absent_from_the_origin() {
        let url = Url::parse("https://example.com:443/").expect("parses");
        assert_eq!(origin(&url), "https://example.com");
    }

    #[test]
    fn a_file_origin_is_the_string_null() {
        let url = Url::parse("file:///x").expect("parses");
        assert_eq!(origin(&url), "null");
    }

    #[test]
    fn a_non_special_scheme_has_an_opaque_origin() {
        for input in ["foo://bar/x", "mailto:a@b.c", "about:blank", "data:,x"] {
            let url = Url::parse(input).expect("parses");
            assert_eq!(origin(&url), "null", "input {input:?}");
        }
    }

    #[test]
    fn a_blob_url_inherits_an_http_origin_from_its_path() {
        let url = Url::parse("blob:https://example.com/u").expect("parses");
        assert_eq!(origin(&url), "https://example.com");
    }

    #[test]
    fn a_blob_url_with_a_non_http_inner_url_is_opaque() {
        for input in ["blob:file:///x", "blob:foo://bar/x", "blob:bad"] {
            let url = Url::parse(input).expect("parses");
            assert_eq!(origin(&url), "null", "input {input:?}");
        }
    }

    #[test]
    fn ws_and_ftp_origins_keep_their_own_scheme() {
        let url = Url::parse("ws://x:80/").expect("parses");
        assert_eq!(origin(&url), "ws://x");
        let url = Url::parse("ftp://x:21/").expect("parses");
        assert_eq!(origin(&url), "ftp://x");
    }
}
