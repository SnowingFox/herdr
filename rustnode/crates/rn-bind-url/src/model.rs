//! The parsed-URL model every member works on.
//!
//! Node keeps a `ada::url_aggregator`, which stores one serialized `href`
//! buffer plus nine `uint32` offsets into it. The JavaScript in
//! `lib/internal/url.js` does not read components out of the C++ struct: it
//! reads `urlComponents` and slices `href` itself. So the only thing that has
//! to match Node is the pair (serialized href, offsets), and that is what this
//! module produces.
//!
//! # Why the offsets are derived rather than queried
//!
//! The `url` crate serializes correctly but exposes no byte offsets, so
//! [`Offsets::of`] recomputes them from the crate's parts and the serialized
//! string. That is only sound because the serialization is canonical: every
//! component has exactly one spelling, so its position is a function of the
//! parts. `tests/node_parity.rs` checks the result against a real `node` for
//! every URL in its table, and the derivation is checked against Node's own
//! `urlComponents` for all of them.
//!
//! One detail is easy to get wrong and is worth stating: when a URL has
//! credentials, ada's `host_start` points at the `@`, not at the first
//! hostname byte. `lib/internal/url.js` compensates in its getters
//! (`if (href[host_start] === '@') startsAt++`), and `username` is read from
//! `protocol_end + 2` to `username_end`, which is why `username_end` must be
//! the byte index *after* the username, with the colon and password excluded.

use url::Url;

/// The "not present" value ada uses for an omitted component.
pub const OMITTED: u32 = u32::MAX;

/// The nine `urlComponents` entries, in the order Node stores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offsets {
    /// Byte index of the `:` after the scheme.
    pub protocol_end: u32,
    /// Byte index just past the username.
    pub username_end: u32,
    /// Byte index of `@` when there are credentials, else past the `//`.
    pub host_start: u32,
    /// Byte index just past the hostname, before any `:port`.
    pub host_end: u32,
    /// The port number, or [`OMITTED`].
    pub port: u32,
    /// Byte index where the path begins.
    pub pathname_start: u32,
    /// Byte index of the `?`, or [`OMITTED`].
    pub search_start: u32,
    /// Byte index of the `#`, or [`OMITTED`].
    pub hash_start: u32,
    /// ada's `scheme::type`: 0 http, 1 not special, 2 https, 3 ws, 4 ftp,
    /// 5 wss, 6 file.
    pub scheme_type: u32,
}

/// `ada::scheme::type` for a scheme name.
///
/// The numbering is not alphabetical and not a bitfield; `lib/internal/url.js`
/// compares against 0, 1, 2 and 6 literally, so the mapping lives in one place.
pub fn scheme_type(scheme: &str) -> u32 {
    match scheme {
        "http" => 0,
        "https" => 2,
        "ws" => 3,
        "ftp" => 4,
        "wss" => 5,
        "file" => 6,
        _ => 1,
    }
}

impl Offsets {
    /// Computes the offsets for an already-parsed URL.
    ///
    /// Every index is derived from the url crate's parts plus the canonical
    /// href, never by searching the string, so a component whose text happens
    /// to recur elsewhere cannot confuse the result.
    pub fn of(url: &Url) -> Self {
        let protocol_end = url.scheme().len() as u32 + 1;
        let mut offsets = Self {
            protocol_end,
            username_end: protocol_end,
            host_start: protocol_end,
            host_end: protocol_end,
            port: OMITTED,
            pathname_start: protocol_end,
            search_start: OMITTED,
            hash_start: OMITTED,
            scheme_type: scheme_type(url.scheme()),
        };

        let mut cursor = protocol_end as usize;
        if url.has_authority() {
            // "://" follows the scheme's colon.
            let authority_start = cursor + 2;
            let username = url.username();
            let password = url.password();
            let has_credentials = !username.is_empty() || password.is_some();

            if has_credentials {
                let username_end = authority_start + username.len();
                // `host_start` is the `@` itself, which sits one byte past a
                // colon-terminated password and must not also gain a colon
                // offset of its own.
                let host_start = username_end + password.map_or(0, |value| value.len() + 1);
                offsets.username_end = username_end as u32;
                offsets.host_start = host_start as u32;
                let hostname_len = url.host_str().map_or(0, str::len);
                offsets.host_end = (host_start + 1 + hostname_len) as u32;
                cursor = host_start + 1 + hostname_len;
            } else {
                offsets.username_end = authority_start as u32;
                offsets.host_start = authority_start as u32;
                let hostname_len = url.host_str().map_or(0, str::len);
                offsets.host_end = (authority_start + hostname_len) as u32;
                cursor = authority_start + hostname_len;
            }

            if let Some(port) = url.port() {
                offsets.port = u32::from(port);
                cursor += 1 + decimal_len(port);
            }
        }

        offsets.pathname_start = cursor as u32;
        cursor += url.path().len();

        if let Some(query) = url.query() {
            offsets.search_start = cursor as u32;
            cursor += 1 + query.len();
        }
        if url.fragment().is_some() {
            offsets.hash_start = cursor as u32;
            // The fragment is the last component, so no cursor update is needed.
        }

        offsets
    }

    /// The nine values in `urlComponents` order.
    pub fn as_array(&self) -> [u32; 9] {
        [
            self.protocol_end,
            self.username_end,
            self.host_start,
            self.host_end,
            self.port,
            self.pathname_start,
            self.search_start,
            self.hash_start,
            self.scheme_type,
        ]
    }
}

/// How many decimal digits a port's serialization takes.
fn decimal_len(port: u16) -> usize {
    // A `u16` is at most 65535, so the digit count is a lookup, not a loop.
    match port {
        0..=9 => 1,
        10..=99 => 2,
        100..=999 => 3,
        1000..=9999 => 4,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offsets_of(input: &str) -> ([u32; 9], String) {
        let url = Url::parse(input).expect("parses");
        (Offsets::of(&url).as_array(), url.as_str().to_string())
    }

    #[test]
    fn a_url_with_credentials_places_host_start_on_the_at_sign() {
        // Node: ["https://user:pw@example.com:8080/a/b?q=1#f", [6,12,15,27,8080,32,36,40,2]]
        let (offsets, _) = offsets_of("https://user:pw@example.com:8080/a/b?q=1#f");
        assert_eq!(offsets, [6, 12, 15, 27, 8080, 32, 36, 40, 2]);
    }

    #[test]
    fn a_url_without_credentials_has_no_username() {
        // Node: [5,7,7,18,omitted,18,omitted,omitted,0]
        let (offsets, _) = offsets_of("http://example.com");
        assert_eq!(offsets, [5, 7, 7, 18, OMITTED, 18, OMITTED, OMITTED, 0]);
    }

    #[test]
    fn a_default_port_is_omitted_from_both_href_and_offsets() {
        let (offsets, href) = offsets_of("http://example.com:80/");
        assert_eq!(href, "http://example.com/");
        assert_eq!(offsets[4], OMITTED);
    }

    #[test]
    fn an_opaque_path_puts_every_authority_offset_at_the_colon() {
        // Node: ["mailto:a@b.c", [7,7,7,7,omitted,7,omitted,omitted,1]]
        let (offsets, _) = offsets_of("mailto:a@b.c");
        assert_eq!(offsets, [7, 7, 7, 7, OMITTED, 7, OMITTED, OMITTED, 1]);
    }

    #[test]
    fn an_empty_query_and_fragment_still_get_an_offset() {
        let (offsets, href) = offsets_of("http://example.com/?#");
        assert_eq!(href, "http://example.com/?#");
        assert_eq!(offsets[6], 19);
        assert_eq!(offsets[7], 20);
    }

    #[test]
    fn the_scheme_type_matches_ada_numbering() {
        assert_eq!(scheme_type("http"), 0);
        assert_eq!(scheme_type("https"), 2);
        assert_eq!(scheme_type("ws"), 3);
        assert_eq!(scheme_type("ftp"), 4);
        assert_eq!(scheme_type("wss"), 5);
        assert_eq!(scheme_type("file"), 6);
        assert_eq!(scheme_type("foo"), 1);
    }

    #[test]
    fn port_digit_counts_cover_the_whole_u16_range() {
        assert_eq!(decimal_len(0), 1);
        assert_eq!(decimal_len(9), 1);
        assert_eq!(decimal_len(10), 2);
        assert_eq!(decimal_len(443), 3);
        assert_eq!(decimal_len(8080), 4);
        assert_eq!(decimal_len(65535), 5);
    }
}
