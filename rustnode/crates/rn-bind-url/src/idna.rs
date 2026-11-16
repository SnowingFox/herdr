//! `domainToASCII` / `domainToUnicode`.
//!
//! Both members run their input through Node's *host* pipeline rather than
//! through a bare UTS #46 call. That is what Node does: `DomainToASCII` in
//! `src/node_url.cc` parses `ws://x` and calls `set_hostname(input)` on the
//! result, then reads the hostname back; `DomainToUnicode` does the same and
//! then decodes the result with `ada::idna::to_unicode`.
//!
//! Going through `set_hostname` is not an optimisation detail, it is the
//! semantics. The four things it buys, each of which a bare `domain_to_ascii`
//! gets wrong:
//!
//! 1. **The ASCII fast path.** ada's `to_ascii` short-circuits a pure-ASCII
//!    input to a lowercase mapping and does *no* UTS #46 validity checking, so
//!    `domainToASCII("xn--a")` is `"xn--a"` in Node even though the label is
//!    not valid punycode. A strict decoder rejects it and reports `""`.
//! 2. **Delimiter truncation.** `"a/b"` is `"a"`, because ada cuts the view at
//!    the first host delimiter before parsing.
//! 3. **IPv4 and IPv6.** `"0x7f.1"` is `"127.0.0.1"`; `"[::1]"` survives.
//! 4. **The `:port` refusal.** `set_hostname` passes `override_hostname = true`,
//!    which returns false as soon as a colon appears outside brackets, and Node
//!    maps that to the empty string.
//!
//! Implementing this as `parse("ws://x") + set_hostname` is therefore the
//! smallest correct thing, and it is literally Node's own composition. The
//! remaining piece is `to_unicode`, which the adapter exposes as
//! [`ada_url::Idna::unicode`] and which never fails: a label it cannot decode
//! is kept verbatim, which is why `domainToUnicode("xn--zz")` is `"xn--zz"` and
//! not `""`.

use ada_url::{Idna, Url};

/// The empty string both members report for an invalid domain.
///
/// Node returns `String::Empty` rather than throwing, and `lib/internal/url.js`
/// passes it through, so a caller of `url.domainToASCII()` sees `""`.
pub const INVALID: &str = "";

/// Node's `ws://x` seed, and why it is a special scheme.
///
/// `set_hostname` branches on the URL's scheme type: a special scheme takes the
/// domain parser (percent-decoding, UTS #46, IPv4), a non-special one takes the
/// opaque-host parser, which forbids far more characters. `DomainToASCII` seeds
/// a special scheme deliberately, so the domain rules apply.
const SEED: &str = "ws://x";

/// Runs `input` through `set_hostname` and answers the serialized hostname.
fn parsed_host(input: &str) -> Option<String> {
    let mut url = Url::parse(SEED, None).ok()?;
    url.set_hostname(Some(input)).ok()?;
    let host = url.hostname().to_string();
    if host.is_empty() {
        return None;
    }
    Some(host)
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
/// Shared with `format(..., unicode)`, which rewrites a URL's host the same way.
pub fn host_to_unicode(host: &str) -> String {
    Idna::unicode(host)
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
    fn a_malformed_punycode_label_is_passed_through() {
        // ada's ASCII fast path lowercases without validating, and Node's
        // `to_unicode` keeps a label it cannot decode. Neither member reports
        // the empty string for these.
        for input in ["xn--a", "xn--zz", "xn--", "xn--a-", "xn--0.com", "a.xn--a"] {
            assert_eq!(domain_to_ascii(input), input, "ascii {input:?}");
            assert_eq!(domain_to_unicode(input), input, "unicode {input:?}");
        }
    }

    #[test]
    fn a_malformed_label_keeps_its_valid_neighbours() {
        // The unit of failure is the label, not the domain.
        assert_eq!(domain_to_unicode("xn--a.xn--n3h"), "xn--a.☃");
    }

    #[test]
    fn a_path_delimiter_truncates_instead_of_failing() {
        assert_eq!(domain_to_ascii("a/b"), "a");
        assert_eq!(domain_to_ascii("a?b"), "a");
        assert_eq!(domain_to_ascii("a\\b"), "a");
        assert_eq!(domain_to_ascii("x/y:z"), "x");
    }

    #[test]
    fn an_at_sign_ends_the_host() {
        assert_eq!(domain_to_ascii("@b"), "");
        assert_eq!(domain_to_ascii("a@b"), "");
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
        for input in ["a b.com", "a@b", "@b", "a[b]", "a[b]c", ":", ""] {
            assert_eq!(domain_to_ascii(input), "", "input {input:?}");
            assert_eq!(domain_to_unicode(input), "", "input {input:?}");
        }
    }

    #[test]
    fn ipv4_shorthand_is_parsed_as_an_address() {
        assert_eq!(domain_to_ascii("0x7f.1"), "127.0.0.1");
        assert_eq!(domain_to_unicode("0x7f.1"), "127.0.0.1");
        assert_eq!(domain_to_ascii("1.2.3.4."), "1.2.3.4");
    }

    #[test]
    fn percent_escapes_in_the_host_are_decoded() {
        assert_eq!(domain_to_ascii("%41.com"), "a.com");
        assert_eq!(domain_to_ascii("xn--%41"), "xn--a");
    }

    #[test]
    fn an_ipv6_literal_survives_both_members() {
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
    fn a_sharp_s_uppercase_maps_the_way_ada_maps_it() {
        // `ẞ` uppercases to `ss` in ada, which is a difference from the `idna`
        // crate this crate used to use. The crate docs listed it as a known
        // divergence; it is now simply Node's answer.
        assert_eq!(domain_to_ascii("ẞ.com"), "xn--zca.com");
        assert_eq!(domain_to_unicode("xn--n3h.net"), "☃.net");
    }

    #[test]
    fn host_to_unicode_passes_an_ipv4_address_through() {
        assert_eq!(host_to_unicode("127.0.0.1"), "127.0.0.1");
    }
}
