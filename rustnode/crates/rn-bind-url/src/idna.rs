//! `domainToASCII` / `domainToUnicode`.
//!
//! Both members run their input through Node's *host* pipeline rather than
//! through a bare `idna::domain_to_ascii`. That is what Node does:
//! `DomainToASCII` in `src/node_url.cc` parses `ws://x` and calls
//! `set_hostname(input)` on the result, and `set_hostname` is
//! `url_aggregator::set_host_or_hostname`, which is the WHATWG host parser plus
//! ada's own `state override` handling.
//!
//! The order of operations inside that pipeline is observable, so it is spelled
//! out here rather than delegated wholesale:
//!
//! 1. Cut the view at the first host delimiter. For a special scheme ada scans
//!    with `find_next_host_delimiter_special`, whose set is `: / \ ? [`, and
//!    brackets suspend delimiting so `[::1]` survives. `@` is handled by
//!    `find_authority_delimiter` during parsing and therefore also ends the
//!    host here.
//! 2. Strip tab and newline characters from what is left.
//! 3. Parse it as a host (percent-decoding, UTS #46, IPv4/IPv6) and serialize,
//!    which lowercases and punycodes.
//! 4. Report failure when a colon was found. `set_hostname` refuses any value
//!    containing a `:port` suffix (`override_hostname == true` returns false),
//!    and Node maps that failure to the empty string.
//!
//! Step 1 is why `domainToASCII("a/b")` is `"a"`, step 3 is why `"a b.com"` and
//! `"a@b"` report `""`, and step 4 is why every `host:port` form reports `""`.
//! Calling `idna::domain_to_ascii` on the raw input would get all three wrong.

use url::Host;

/// The empty string both members report for an invalid domain.
///
/// Node returns `String::Empty` rather than throwing, and `lib/internal/url.js`
/// passes it through, so a caller of `url.domainToASCII()` sees `""`.
pub const INVALID: &str = "";

/// Where a hostname ends and whether a `:port` suffix followed.
///
/// Matches `get_host_delimiter_location(is_special = true, view)`: the scan stops
/// at `: / \ ? [`, a `[...]` range hides any delimiter inside it, and an
/// unclosed `[` consumes the rest of the input (`location = view_size`).
fn host_delimiter(input: &str) -> (usize, bool) {
    let mut brackets = 0u32;
    for (index, byte) in input.bytes().enumerate() {
        match byte {
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b':' if brackets == 0 => return (index, true),
            b'/' | b'?' if brackets == 0 => return (index, false),
            b'\\' if brackets == 0 => return (index, false),
            _ => {}
        }
    }
    (input.len(), false)
}

/// Removes ASCII tab and newline characters, as `remove_ascii_tab_or_newline`.
fn strip_tab_and_newline(input: &str) -> String {
    input
        .chars()
        .filter(|character| !matches!(character, '\t' | '\n' | '\r'))
        .collect()
}

/// The serialized hostname Node would end up with, or `None` where it reports
/// the empty string.
fn parsed_host(input: &str) -> Option<String> {
    let (end, had_port) = host_delimiter(input);
    // A `:port` suffix makes `set_hostname` fail outright; Node reports "".
    if had_port {
        return None;
    }
    let candidate = strip_tab_and_newline(&input[..end]);
    if candidate.is_empty() {
        return None;
    }
    let host = Host::parse(&candidate).ok()?;
    let serialized = host.to_string();
    if serialized.is_empty() {
        return None;
    }
    Some(serialized)
}

/// `domainToASCII`: the ASCII serialization of the parsed host.
pub fn domain_to_ascii(input: &str) -> String {
    parsed_host(input).unwrap_or_else(|| INVALID.to_string())
}

/// `domainToUnicode`: the ASCII hostname decoded back through UTS #46.
///
/// Node serializes the host first and only then calls `to_unicode`, so the input
/// makes a full ASCII round trip. `xn--n3h.net` therefore decodes to `☃.net`
/// while an IPv4 or IPv6 literal is passed through, since only the `xn--` prefix
/// names a punycode label.
pub fn domain_to_unicode(input: &str) -> String {
    match parsed_host(input) {
        Some(host) => host_to_unicode(&host),
        None => INVALID.to_string(),
    }
}

/// Decodes one serialized hostname to its Unicode spelling.
///
/// Shared with `format(..., unicode)` and with `getOrigin`'s host, both of which
/// rewrite a URL's host the same way.
pub fn host_to_unicode(host: &str) -> String {
    // Neither an IPv6 literal nor an IPv4 address has a Unicode form, and the
    // UTS #46 decoder would either reject or mangle them; both pass through.
    if host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok() {
        return host.to_string();
    }
    let (decoded, _errors) = idna::domain_to_unicode(host);
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ascii_domain_round_trips() {
        assert_eq!(domain_to_ascii("example.com"), "example.com");
        assert_eq!(domain_to_unicode("example.com"), "example.com");
    }

    #[test]
    fn an_ascii_domain_is_lowercased() {
        assert_eq!(domain_to_ascii("EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn a_unicode_domain_becomes_punycode_and_back() {
        assert_eq!(domain_to_ascii("例え.テスト"), "xn--r8jz45g.xn--zckzah");
        assert_eq!(domain_to_unicode("xn--r8jz45g.xn--zckzah"), "例え.テスト");
    }

    #[test]
    fn the_unicode_member_decodes_punycode_it_is_given() {
        assert_eq!(domain_to_unicode("xn--n3h.net"), "☃.net");
        assert_eq!(domain_to_unicode("xn--fiqs8s"), "中国");
    }

    #[test]
    fn a_path_delimiter_truncates_instead_of_failing() {
        // Node reports "a" for each of these: ada cuts the view at the delimiter
        // before parsing. A bare `idna::domain_to_ascii` would reject them.
        assert_eq!(domain_to_ascii("a/b"), "a");
        assert_eq!(domain_to_ascii("a?b"), "a");
        assert_eq!(domain_to_ascii("a\\b"), "a");
        assert_eq!(domain_to_ascii("x/y:z"), "x");
    }

    #[test]
    fn an_at_sign_ends_the_host() {
        // `find_authority_delimiter` stops at '@' only while scanning the
        // userinfo, which `set_hostname` is not doing, so "@b" keeps its '@'
        // and fails the forbidden-host-code-point check.
        assert_eq!(domain_to_ascii("@b"), "");
    }

    #[test]
    fn a_port_suffix_is_refused_rather_than_truncated() {
        // `set_hostname` passes `override_hostname = true`, which returns false
        // as soon as a colon is found outside brackets.
        for input in [
            "example.com:80",
            "a:80",
            "a:",
            "[::1]:80",
            "a:http",
            "x:y/z",
        ] {
            assert_eq!(domain_to_ascii(input), "", "input {input:?}");
            assert_eq!(domain_to_unicode(input), "", "input {input:?}");
        }
    }

    #[test]
    fn a_forbidden_host_code_point_reports_the_empty_string() {
        // `@` is not a delimiter for `set_hostname`, so "a@b" stays one view and
        // the host parser rejects it for containing a forbidden code point.
        for input in ["a b.com", "a@b", "@b", "a[b]", "a[b]c", ":", "", "xn--"] {
            assert_eq!(domain_to_ascii(input), "", "input {input:?}");
            assert_eq!(domain_to_unicode(input), "", "input {input:?}");
        }
    }

    #[test]
    fn ipv4_shorthand_is_parsed_as_an_address() {
        assert_eq!(domain_to_ascii("0x7f.1"), "127.0.0.1");
        assert_eq!(domain_to_unicode("0x7f.1"), "127.0.0.1");
    }

    #[test]
    fn percent_escapes_in_the_host_are_decoded() {
        assert_eq!(domain_to_ascii("%41.com"), "a.com");
    }

    #[test]
    fn an_ipv6_literal_survives_the_delimiter_scan_and_both_members() {
        // The brackets suspend delimiting, or "::1" would be cut at the first
        // colon and then refused for having a port.
        assert_eq!(domain_to_ascii("[::1]"), "[::1]");
        assert_eq!(domain_to_unicode("[::1]"), "[::1]");
        assert_eq!(domain_to_ascii("[2001:db8::1]"), "[2001:db8::1]");
    }

    #[test]
    fn an_unclosed_bracket_consumes_the_rest_of_the_input() {
        assert_eq!(domain_to_ascii("[::1"), "");
    }

    #[test]
    fn a_fullwidth_label_is_mapped_by_uts46() {
        assert_eq!(domain_to_ascii("ＡＢＣ.com"), "abc.com");
    }

    #[test]
    fn host_to_unicode_leaves_an_ipv4_address_alone() {
        assert_eq!(host_to_unicode("127.0.0.1"), "127.0.0.1");
    }
}
