//! The parsed-URL model every member works on.
//!
//! Node keeps an `ada::url_aggregator`, which stores one serialized `href`
//! buffer plus nine `uint32` offsets into it. The JavaScript in
//! `lib/internal/url.js` does not read components out of the C++ struct: it
//! reads `urlComponents` and slices `href` itself. So the only thing that has
//! to match Node is the pair (serialized href, offsets).
//!
//! This module used to *derive* those offsets from the `url` crate's parts,
//! because that crate exposes no byte offsets. [`ada_url::Url`] exposes ada's
//! own `ada_url_components`, so the offsets are now read rather than
//! reconstructed — the two runtimes are the same C++ code, and there is no
//! derivation left in which to be subtly wrong.
//!
//! One detail is easy to get wrong and is worth stating: when a URL has
//! credentials, ada's `host_start` points at the `@`, not at the first hostname
//! byte. `lib/internal/url.js` compensates in its getters
//! (`if (href[host_start] === '@') startsAt++`), and `username` is read from
//! `protocol_end + 2` to `username_end`, which is why `username_end` must be
//! the byte index *after* the username, with the colon and password excluded.

use ada_url::{SchemeType, Url, UrlComponents};

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
    /// Reads the offsets out of a parsed URL.
    ///
    /// `ada_url::UrlComponents` already carries ada's numbers; the only work
    /// here is turning its `Option<u32>` "omitted" spelling back into
    /// [`OMITTED`], which is the value `urlComponents` stores.
    pub fn of(url: &Url) -> Self {
        let components = url.components();
        Self::from_components(&components, scheme_type_of(&url.scheme_type()))
    }

    /// The same read, from components that were fetched separately.
    ///
    /// `UrlComponents` is a plain copy, so a caller that already has one (the
    /// callbacks, which fetch it to avoid a second FFI call) does not need the
    /// `Url` again.
    pub fn from_components(components: &UrlComponents, scheme_type: u32) -> Self {
        Self {
            protocol_end: components.protocol_end,
            username_end: components.username_end,
            host_start: components.host_start,
            host_end: components.host_end,
            port: components.port.unwrap_or(OMITTED),
            pathname_start: components.pathname_start.unwrap_or(OMITTED),
            search_start: components.search_start.unwrap_or(OMITTED),
            hash_start: components.hash_start.unwrap_or(OMITTED),
            scheme_type,
        }
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

/// The numeric `scheme::type`, from ada's own enum rather than a name lookup.
///
/// Going through `SchemeType`'s discriminants keeps the adapter's numbering in
/// sync with the C++ enum automatically; [`scheme_type`] exists only for the
/// one caller that has a scheme *name* and no parsed URL.
fn scheme_type_of(value: &SchemeType) -> u32 {
    match value {
        SchemeType::Http => 0,
        SchemeType::NotSpecial => 1,
        SchemeType::Https => 2,
        SchemeType::Ws => 3,
        SchemeType::Ftp => 4,
        SchemeType::Wss => 5,
        SchemeType::File => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offsets_of(input: &str) -> ([u32; 9], String) {
        let url = Url::parse(input, None).expect("parses");
        (Offsets::of(&url).as_array(), url.href().to_string())
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
    fn the_enum_and_the_name_table_agree() {
        for scheme in ["http", "https", "ws", "wss", "ftp", "file", "foo"] {
            let url = Url::parse(&format!("{scheme}://example.com/x"), None).expect("parses");
            assert_eq!(
                scheme_type_of(&url.scheme_type()),
                scheme_type(scheme),
                "{scheme}"
            );
        }
    }

    #[test]
    fn a_double_slash_file_path_keeps_its_offsets() {
        // The shape the `url` crate could not represent at all. Node:
        // ["file:////a", [5,7,7,7,omitted,7,omitted,omitted,6]]
        let (offsets, href) = offsets_of("file:////a");
        assert_eq!(href, "file:////a");
        assert_eq!(offsets, [5, 7, 7, 7, OMITTED, 7, OMITTED, OMITTED, 6]);
    }
}
