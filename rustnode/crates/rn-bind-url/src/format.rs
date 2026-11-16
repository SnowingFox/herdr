//! `format` and origin serialization.
//!
//! `url_aggregator::get_origin` is ada's own function, exposed by the adapter as
//! [`ada_url::Url::origin`], so `getOrigin` is a single call: the opaque-origin
//! rules (`"null"` for every non-special scheme, including `file:`, and the
//! `blob:` recursion into an http(s) inner URL) are the C++ that Node ships
//! rather than a restatement of it.
//!
//! `format` is a *display* transformation, and one of its modes produces an
//! href that is not a URL: `unicode` rewrites the host to its decoded spelling,
//! so `http://xn--n3h/x` becomes `http://☃/x`. Node reaches that by assigning
//! `out->host` on its parsed object, which serializes the host field verbatim.
//! An aggregator cannot hold that shape — setting the host would run host
//! parsing and punycode the `☃` straight back — so the decoded text is spliced
//! into the serialization at the host's byte range instead. That is the one
//! place in this crate where a component is rewritten by offset rather than
//! through a setter, and it only ever affects the value `format` returns.

use ada_url::Url;

use crate::idna;
use crate::model::Offsets;

/// `url_aggregator::get_origin`, as `getOrigin` returns it.
///
/// The result is a string in every case: an opaque origin is the four
/// characters `null`, not JavaScript `null`.
pub fn origin(url: &Url) -> String {
    url.origin()
}

/// `BindingData::Format` with the JS flag names made explicit.
///
/// `keep_fragment`, `keep_search` and `keep_auth` are "keep" flags, matching the
/// JavaScript (`options.fragment = false` removes the fragment). `unicode`
/// rewrites the hostname rather than dropping anything.
///
/// An href that does not parse is returned unchanged, which is what Node does:
/// `Format` returns `args[0]` when the re-parse fails, because the IDNA encoder
/// can emit a label the decoder rejects. (The crate docs used to describe this
/// as a deliberate difference from Node; Node changed to match.)
pub fn format(
    href: &str,
    keep_fragment: bool,
    unicode: bool,
    keep_search: bool,
    keep_auth: bool,
) -> String {
    let Ok(mut url) = Url::parse(href, None) else {
        return href.to_string();
    };

    // Each component is cleared through ada's own setter, so the surrounding
    // components keep the byte layout ada would produce.
    if !keep_fragment {
        url.set_hash(None);
    }
    if !keep_search {
        url.set_search(None);
    }
    if !keep_auth {
        // Order matters only in that both must run: an empty username drops the
        // `@` too, and clearing the password first keeps the `:` from being
        // re-added by a non-empty username.
        url.set_password(None).ok();
        url.set_username(Some("")).ok();
    }

    if unicode && url.has_hostname() {
        let hostname = url.hostname().to_string();
        let decoded = idna::host_to_unicode(&hostname);
        if decoded != hostname {
            return splice_hostname(&url, &decoded);
        }
    }

    url.href().to_string()
}

/// Replaces the hostname of `url`'s serialization with `replacement`.
///
/// The range comes from ada's own components, so the `@` of a credential pair
/// (`host_start` points at it) is skipped and the port that follows
/// `host_end` is preserved.
fn splice_hostname(url: &Url, replacement: &str) -> String {
    let href = url.href();
    let offsets = Offsets::of(url);
    let mut start = offsets.host_start as usize;
    let end = (offsets.host_end as usize).min(href.len());
    if href.as_bytes().get(start) == Some(&b'@') {
        start += 1;
    }
    let mut spliced = String::with_capacity(href.len() + replacement.len());
    spliced.push_str(&href[..start.min(href.len())]);
    spliced.push_str(replacement);
    spliced.push_str(&href[end..]);
    spliced
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
    fn unicode_keeps_a_host_whose_punycode_label_does_not_decode() {
        // Node's `to_unicode` keeps an undecodable label verbatim rather than
        // dropping the host, so `xn--a` survives `format(..., unicode)`.
        assert_eq!(
            formatted("http://xn--a/x", true, true, true, true),
            "http://xn--a/x"
        );
    }

    #[test]
    fn unicode_and_dropped_auth_compose() {
        assert_eq!(
            formatted("http://u:p@xn--9ca.com/x", true, true, true, false),
            "http://é.com/x"
        );
    }

    #[test]
    fn an_unparsable_href_is_returned_unchanged() {
        assert_eq!(formatted("bad url", true, false, true, true), "bad url");
    }

    #[test]
    fn a_caret_in_the_path_survives_formatting() {
        // `format` re-parses, so the path encode set applies here too.
        assert_eq!(
            formatted("http://a/x^y", true, false, true, true),
            "http://a/x%5Ey"
        );
    }

    #[test]
    fn an_http_origin_is_scheme_and_authority_without_credentials() {
        let url = Url::parse("https://user:pw@example.com:8080/a?q#f", None).expect("parses");
        assert_eq!(origin(&url), "https://example.com:8080");
    }

    #[test]
    fn a_default_port_is_absent_from_the_origin() {
        let url = Url::parse("https://example.com:443/", None).expect("parses");
        assert_eq!(origin(&url), "https://example.com");
    }

    #[test]
    fn a_file_origin_is_the_string_null() {
        let url = Url::parse("file:///x", None).expect("parses");
        assert_eq!(origin(&url), "null");
    }

    #[test]
    fn a_non_special_scheme_has_an_opaque_origin() {
        for input in ["foo://bar/x", "mailto:a@b.c", "about:blank", "data:,x"] {
            let url = Url::parse(input, None).expect("parses");
            assert_eq!(origin(&url), "null", "input {input:?}");
        }
    }

    #[test]
    fn a_blob_url_inherits_an_http_origin_from_its_path() {
        let url = Url::parse("blob:https://example.com/u", None).expect("parses");
        assert_eq!(origin(&url), "https://example.com");
    }

    #[test]
    fn a_blob_url_with_a_non_http_inner_url_is_opaque() {
        for input in ["blob:file:///x", "blob:foo://bar/x", "blob:bad"] {
            let url = Url::parse(input, None).expect("parses");
            assert_eq!(origin(&url), "null", "input {input:?}");
        }
    }

    #[test]
    fn ws_and_ftp_origins_keep_their_own_scheme() {
        let url = Url::parse("ws://x:80/", None).expect("parses");
        assert_eq!(origin(&url), "ws://x");
        let url = Url::parse("ftp://x:21/", None).expect("parses");
        assert_eq!(origin(&url), "ftp://x");
    }
}
