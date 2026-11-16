//! The ten `update` actions.
//!
//! `update(href, action, value)` re-parses the href, applies one setter, and
//! returns the new serialization — or `false` when the setter rejected the
//! value. `lib/internal/url.js` only writes the result back when it is truthy,
//! so the boolean and the string are one return channel.
//!
//! # Why this is a dispatch table and not an algorithm
//!
//! This module used to re-implement each `url_aggregator::set_*` in Rust on top
//! of the `url` crate, because that crate's setters follow the WHATWG
//! algorithms while ada's have their own guards, and the guards are what makes
//! `update` agree with Node. Reproducing them by hand is how four divergences
//! got in: the guards are subtle (`set_host` truncates at a delimiter and
//! *ignores* a rejected port rather than failing; `set_port` requires a leading
//! digit), and each one was re-derived from the C++ instead of executed.
//!
//! [`ada_url::Url`] is a binding to the same `deps/ada/ada.cpp` that Node
//! vendors, so the guards are now the code that implements them. Every action
//! is one call, and the correspondence to `BindingData::Update` in
//! `src/node_url.cc` is one row per `case` there.
//!
//! Two details are Node's rather than ada's, and they are the only logic here:
//!
//! * `search` and `hash` cannot fail, and an empty value *clears* the
//!   component. ada exposes that as a separate `ada_clear_*` entry point
//!   because `set_search("")` means "an empty query is present" (`?`), which is
//!   a different URL. Node's `url_aggregator::set_search` clears on empty, so
//!   the mapping is `None` there and `Some("")` only from the JS-visible
//!   `?`/`#` values, which carry their sigil through.
//! * an out-of-range action number is Node's `UNREACHABLE`. `lib/**` never
//!   sends one, so refusing is the honest answer rather than inventing
//!   behaviour.

use ada_url::Url;

/// The action numbers, matching `enum url_update_action` in
/// `src/node_url.h` and `updateActions` in `lib/internal/url.js`.
///
/// The numbers are the wire contract between the JavaScript and the binding, so
/// they are listed in one place rather than repeated as literals.
pub const K_PROTOCOL: u32 = 0;
pub const K_HOST: u32 = 1;
pub const K_HOSTNAME: u32 = 2;
pub const K_PORT: u32 = 3;
pub const K_USERNAME: u32 = 4;
pub const K_PASSWORD: u32 = 5;
pub const K_PATHNAME: u32 = 6;
pub const K_SEARCH: u32 = 7;
pub const K_HASH: u32 = 8;
pub const K_HREF: u32 = 9;

/// Why a setter refused.
///
/// Only the distinction between "refused" and "the URL cannot be parsed at all"
/// is observable: both report `false` from `update`. It is kept because the
/// `kHref` action genuinely re-parses, and a caller that later wants to throw
/// needs to know which happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateError {
    /// The setter rejected the value.
    Refused,
    /// The href itself no longer parses.
    Unparsable,
}

/// Applies `action` to `href` with `value`, returning the new serialization.
///
/// Returns `Err` where Node returns `false`; the caller writes the new href into
/// `urlComponents` only after this succeeds.
pub fn update(href: &str, action: u32, value: &str) -> Result<String, UpdateError> {
    let mut url = Url::parse(href, None).map_err(|_| UpdateError::Unparsable)?;
    match action {
        K_PROTOCOL => url.set_protocol(value).map_err(|()| UpdateError::Refused)?,
        K_HOST => url
            .set_host(Some(value))
            .map_err(|()| UpdateError::Refused)?,
        K_HOSTNAME => url
            .set_hostname(Some(value))
            .map_err(|()| UpdateError::Refused)?,
        K_PORT => url
            .set_port(Some(value))
            .map_err(|()| UpdateError::Refused)?,
        K_USERNAME => url
            .set_username(Some(value))
            .map_err(|()| UpdateError::Refused)?,
        K_PASSWORD => url
            .set_password(Some(value))
            .map_err(|()| UpdateError::Refused)?,
        K_PATHNAME => url
            .set_pathname(Some(value))
            .map_err(|()| UpdateError::Refused)?,
        K_SEARCH => set_search(&mut url, value),
        K_HASH => set_hash(&mut url, value),
        K_HREF => url.set_href(value).map_err(|()| UpdateError::Refused)?,
        // Node's `UNREACHABLE` for any other number.
        _ => return Err(UpdateError::Refused),
    }
    Ok(url.href().to_string())
}

/// `url_aggregator::set_search`: empty clears, anything else is encoded in.
///
/// ada's `ada_set_search` never fails, so the only decision is which of its two
/// entry points an empty value maps to. See the module docs.
fn set_search(url: &mut Url, value: &str) {
    if value.is_empty() {
        url.set_search(None);
    } else {
        url.set_search(Some(value));
    }
}

/// `url_aggregator::set_hash`: the same empty-clears rule as [`set_search`].
fn set_hash(url: &mut Url, value: &str) {
    if value.is_empty() {
        url.set_hash(None);
    } else {
        url.set_hash(Some(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(href: &str, action: u32, value: &str) -> Option<String> {
        update(href, action, value).ok()
    }

    #[test]
    fn the_action_numbers_match_the_javascript_enum() {
        // `updateActions` in lib/internal/url.js.
        assert_eq!(
            [
                K_PROTOCOL, K_HOST, K_HOSTNAME, K_PORT, K_USERNAME, K_PASSWORD, K_PATHNAME,
                K_SEARCH, K_HASH, K_HREF
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
    }

    #[test]
    fn a_special_scheme_cannot_become_non_special() {
        // A refusal here is `false`, so the caller keeps the old href. (ada's
        // `set_protocol` returns true without touching the URL only for the
        // capitals case below, where the *input* is not a recognised scheme.)
        let base = "https://u:p@example.com:8080/a/b?q=1#f";
        assert_eq!(apply(base, K_PROTOCOL, "foo"), None);
        assert_eq!(apply(base, K_PROTOCOL, "example.org"), None);
        assert_eq!(
            apply(base, K_PROTOCOL, "http").as_deref(),
            Some("http://u:p@example.com:8080/a/b?q=1#f")
        );
    }

    #[test]
    fn a_target_scheme_in_capitals_refuses_the_same_way() {
        // `get_scheme_type` does not fold case, so `FILE` is not the file
        // scheme to ada's dispatcher; the refusal is still a `false`.
        let base = "https://user:pw@example.com:8080/a/b?q=1#f";
        assert_eq!(apply(base, K_PROTOCOL, "FILE"), None);
    }

    #[test]
    fn file_is_refused_when_credentials_or_a_port_are_present() {
        assert_eq!(apply("https://u:p@example.com/x", K_PROTOCOL, "file"), None);
        assert_eq!(
            apply("https://example.com:8080/x", K_PROTOCOL, "file"),
            None
        );
        assert_eq!(
            apply("https://example.com/x", K_PROTOCOL, "file").as_deref(),
            Some("file://example.com/x")
        );
    }

    #[test]
    fn a_non_special_scheme_cannot_become_special() {
        assert_eq!(apply("foo://bar/x", K_PROTOCOL, "https"), None);
        assert_eq!(apply("foo:/x", K_PROTOCOL, "https"), None);
    }

    #[test]
    fn a_scheme_needs_a_leading_letter() {
        for bad in ["", "1x", "-x", "a b", "%41"] {
            let outcome = apply("https://x.com/p", K_PROTOCOL, bad);
            // An empty value is a no-op in ada, everything else is refused.
            if bad.is_empty() {
                assert_eq!(outcome.as_deref(), Some("https://x.com/p"));
            } else {
                assert_eq!(outcome, None, "scheme {bad:?}");
            }
        }
    }

    #[test]
    fn a_valid_scheme_change_keeps_everything_else() {
        assert_eq!(
            apply("https://u:p@h.example:8080/a?q#f", K_PROTOCOL, "wss").as_deref(),
            Some("wss://u:p@h.example:8080/a?q#f")
        );
    }

    #[test]
    fn setting_the_default_port_clears_it() {
        assert_eq!(
            apply("https://ex.com:8080/p", K_PORT, "443").as_deref(),
            Some("https://ex.com/p")
        );
        // A non-special scheme has no default port, so it is kept.
        assert_eq!(
            apply("foo://ex.com:1/p", K_PORT, "80").as_deref(),
            Some("foo://ex.com:80/p")
        );
    }

    #[test]
    fn a_port_keeps_only_its_leading_digits() {
        assert_eq!(
            apply("https://ex.com:8080/p", K_PORT, "80a").as_deref(),
            Some("https://ex.com:80/p")
        );
    }

    #[test]
    fn a_port_must_start_with_a_digit_or_the_update_fails() {
        // ada's `set_port` returns false when the first character is not a
        // digit, and Node turns that into `false` from `update`, so the caller
        // keeps the whole old href — the port is not cleared. The old
        // implementation cleared the port for these shapes.
        for bad in ["x", "x1", "[::1]", "?q=2", "%41", "+80", " 8080 ", "-1"] {
            assert_eq!(
                apply("https://ex.com:8080/p", K_PORT, bad),
                None,
                "port {bad:?}"
            );
        }
    }

    #[test]
    fn a_port_that_is_only_whitespace_is_a_successful_no_op() {
        // Tab and newline are stripped before the leading-digit test, so a value
        // made only of them trims to empty and ada returns true having changed
        // nothing. A leading *space* is not stripped, which is why it fails.
        for noop in ["\t", "\n", "\t\t"] {
            assert_eq!(
                apply("https://ex.com:8080/p", K_PORT, noop).as_deref(),
                Some("https://ex.com:8080/p"),
                "port {noop:?}"
            );
        }
    }

    #[test]
    fn an_out_of_range_port_is_refused() {
        for bad in ["99999", "65536"] {
            assert_eq!(
                apply("https://ex.com:8080/p", K_PORT, bad),
                None,
                "port {bad:?}"
            );
        }
    }

    #[test]
    fn a_port_cannot_be_set_on_a_file_or_hostless_url() {
        assert_eq!(apply("file:///tmp/x", K_PORT, "80"), None);
        assert_eq!(apply("mailto:a@b.c", K_PORT, "80"), None);
    }

    #[test]
    fn host_and_hostname_differ_on_a_port_suffix() {
        assert_eq!(
            apply("https://ex.com/p", K_HOST, "a:8080").as_deref(),
            Some("https://a:8080/p")
        );
        assert_eq!(apply("https://ex.com/p", K_HOSTNAME, "a:8080"), None);
    }

    #[test]
    fn host_splits_the_value_at_a_delimiter_and_ignores_a_bad_port() {
        // `get_host_delimiter_location` stops at `: / \ ?`, so each of these
        // sets the host and leaves the port at 9. An empty port buffer after
        // the colon is not applied at all (`"x:"`), and a rejected one is
        // *ignored* rather than failing the update (`"x:99999"`, `"x:a"`).
        for value in ["x/y", "x\\y", "x?y", "x:y", "x:99999", "x:a", "x:"] {
            assert_eq!(
                apply("http://a:9/p", K_HOST, value).as_deref(),
                Some("http://x:9/p"),
                "host {value:?}"
            );
        }
        // A valid port in the value does replace the old one.
        assert_eq!(
            apply("http://a:9/p", K_HOST, "x:80").as_deref(),
            Some("http://x/p")
        );
    }

    #[test]
    fn an_empty_host_is_allowed_only_for_a_non_special_scheme() {
        assert_eq!(
            apply("foo://bar/baz", K_HOST, "").as_deref(),
            Some("foo:///baz")
        );
        assert_eq!(apply("https://ex.com/p", K_HOST, ""), None);
        assert_eq!(apply("https://ex.com/p", K_HOSTNAME, ""), None);
    }

    #[test]
    fn an_empty_host_gives_a_url_without_an_authority_one() {
        // `add_authority_slashes_if_needed`: `foo:/p` becomes `foo:///p`.
        assert_eq!(apply("foo:/p", K_HOST, "").as_deref(), Some("foo:///p"));
        assert_eq!(apply("foo:/p", K_HOSTNAME, "").as_deref(), Some("foo:///p"));
    }

    #[test]
    fn a_file_host_accepts_the_empty_value_and_collapses_localhost() {
        assert_eq!(
            apply("file:///tmp/x", K_HOST, "").as_deref(),
            Some("file:///tmp/x")
        );
        assert_eq!(
            apply("file:///tmp/x", K_HOST, "host").as_deref(),
            Some("file://host/tmp/x")
        );
    }

    #[test]
    fn credentials_cannot_be_set_without_a_host() {
        assert_eq!(apply("mailto:a@b.c", K_USERNAME, "u"), None);
        assert_eq!(apply("mailto:a@b.c", K_PASSWORD, "p"), None);
        assert_eq!(apply("file:///tmp/x", K_USERNAME, "u"), None);
    }

    #[test]
    fn a_username_is_percent_encoded() {
        assert_eq!(
            apply("https://u:p@ex.com/", K_USERNAME, "a b").as_deref(),
            Some("https://a%20b:p@ex.com/")
        );
    }

    #[test]
    fn a_password_can_be_added_and_cleared() {
        assert_eq!(
            apply("https://u@ex.com/", K_PASSWORD, "p").as_deref(),
            Some("https://u:p@ex.com/")
        );
        assert_eq!(
            apply("https://u:p@ex.com/", K_PASSWORD, "").as_deref(),
            Some("https://u@ex.com/")
        );
    }

    #[test]
    fn an_opaque_path_cannot_be_replaced() {
        assert_eq!(apply("mailto:a@b.c", K_PATHNAME, "/x"), None);
    }

    #[test]
    fn a_pathname_is_resolved_and_encoded() {
        assert_eq!(
            apply("https://x.com/p", K_PATHNAME, "/a/../b").as_deref(),
            Some("https://x.com/b")
        );
        assert_eq!(
            apply("https://x.com/p", K_PATHNAME, "a b").as_deref(),
            Some("https://x.com/a%20b")
        );
    }

    #[test]
    fn a_pathname_encodes_the_characters_ada_encodes() {
        // `^` is in ada's PATH_PERCENT_ENCODE table; the `url` crate's set
        // omitted it, which is what made parse and this setter disagree.
        assert_eq!(
            apply("http://a/", K_PATHNAME, "/x^y").as_deref(),
            Some("http://a/x%5Ey")
        );
        // A trailing space is encoded, not trimmed.
        assert_eq!(
            apply("http://a/", K_PATHNAME, "/x ").as_deref(),
            Some("http://a/x%20")
        );
        // A backslash is a path separator on a special URL.
        assert_eq!(
            apply("http://a/", K_PATHNAME, "\\z").as_deref(),
            Some("http://a/z")
        );
    }

    #[test]
    fn a_pathname_keeps_a_double_slash_file_path() {
        // `file:` URLs may have a path beginning `//`; the `url` crate folded it.
        assert_eq!(
            apply("file:///tmp/x", K_PATHNAME, "//x").as_deref(),
            Some("file:////x")
        );
        assert_eq!(
            apply("file://host/tmp/x", K_PATHNAME, "//x").as_deref(),
            Some("file://host//x")
        );
    }

    #[test]
    fn search_and_hash_strip_their_leading_sigil_and_encode() {
        assert_eq!(
            apply("https://x.com/p", K_SEARCH, "?q=2").as_deref(),
            Some("https://x.com/p?q=2")
        );
        assert_eq!(
            apply("https://x.com/p", K_HASH, "#h").as_deref(),
            Some("https://x.com/p#h")
        );
        assert_eq!(
            apply("https://x.com/p", K_SEARCH, "a b").as_deref(),
            Some("https://x.com/p?a%20b")
        );
    }

    #[test]
    fn a_lone_delimiter_sets_an_empty_but_present_component() {
        // `search = "?"` is an empty query that is *present*: the href keeps
        // the `?`. The old implementation stripped the sigil, saw an empty
        // string, and cleared the component instead.
        assert_eq!(
            apply("http://a/", K_SEARCH, "?").as_deref(),
            Some("http://a/?")
        );
        assert_eq!(
            apply("http://a/", K_HASH, "#").as_deref(),
            Some("http://a/#")
        );
    }

    #[test]
    fn an_empty_search_or_hash_clears_it() {
        assert_eq!(
            apply("https://a.com/x?q#h", K_SEARCH, "").as_deref(),
            Some("https://a.com/x#h")
        );
        assert_eq!(
            apply("https://a.com/x?q#h", K_HASH, "").as_deref(),
            Some("https://a.com/x?q")
        );
    }

    #[test]
    fn href_replaces_the_whole_url_and_refuses_an_invalid_one() {
        assert_eq!(
            apply("https://a.com/x", K_HREF, "file:///y").as_deref(),
            Some("file:///y")
        );
        assert_eq!(apply("https://a.com/x", K_HREF, "not a url"), None);
    }

    #[test]
    fn href_encodes_the_path_the_same_way_parsing_does() {
        assert_eq!(
            apply("https://a.com/x", K_HREF, "http://b/x^y").as_deref(),
            Some("http://b/x%5Ey")
        );
    }

    #[test]
    fn an_unknown_action_is_refused_instead_of_guessed() {
        assert_eq!(
            update("https://a.com/x", 42, "x"),
            Err(UpdateError::Refused)
        );
    }

    #[test]
    fn an_unparsable_href_reports_its_own_error() {
        assert_eq!(
            update("not a url", K_HASH, "h"),
            Err(UpdateError::Unparsable)
        );
    }
}
