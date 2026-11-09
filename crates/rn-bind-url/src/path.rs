//! `pathToFileURL`: turning a filesystem path into a `file:` URL.
//!
//! Node does this in two steps. `EncodePathChars` in `src/node_url.cc` walks the
//! path a byte at a time and percent-encodes a fixed set of ASCII characters
//! (the RFC 1738 "unsafe" list) before the result is parsed as a URL. Because
//! the percent sign itself is in that set, an input that already looks encoded
//! is double-encoded: `/tmp/a%20b` becomes `file:///tmp/a%2520b`. That is
//! deliberate, and it is why this cannot be replaced by the URL parser's own
//! escaping: the escaping has to happen before the parse, on raw path bytes.
//!
//! The encoded string is then handed to the URL parser, which is what supplies
//! the canonical `file://` spelling, empty-host handling and dot-segment
//! removal. Those are the parser's job here, not this module's.

/// Characters `EncodePathChars` replaces, from the `lookup_table` switch in
/// `src/node_url.cc`.
///
/// The table encodes exactly `\0 \t \n \r`, space, `" # % ? [ \ ] ^ | ~`. `\`
/// is only encoded for POSIX paths: on Windows it is a separator and becomes `/`
/// instead. Note `]` is in the set and `|` is `%7C`; reading the `ENCODE_CHAR`
/// macro's two hex-digit arguments in source order is the way to get this right,
/// since the macro parameter names run `HEX_DIGIT_2, HEX_DIGIT_1`.
const ENCODED: &[(char, &str)] = &[
    ('\0', "%00"),
    ('\t', "%09"),
    ('\n', "%0A"),
    ('\r', "%0D"),
    (' ', "%20"),
    ('"', "%22"),
    ('#', "%23"),
    ('%', "%25"),
    ('?', "%3F"),
    ('[', "%5B"),
    ('\\', "%5C"),
    (']', "%5D"),
    ('^', "%5E"),
    ('|', "%7C"),
    ('~', "%7E"),
];

/// Whether `pathToFileURL` should treat the path as a Windows path.
///
/// Node passes this in from JavaScript, which decides from `process.platform`
/// unless `options.windows` overrides it. rustnode is POSIX-only for now, so the
/// binding is always called with `false`; the flag is still threaded through so
/// the Windows branch is described where it belongs instead of being silently
/// dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFlavour {
    Posix,
    Windows,
}

impl PathFlavour {
    /// Maps the boolean Node passes as the second argument.
    pub fn from_windows_flag(windows: bool) -> Self {
        if windows {
            Self::Windows
        } else {
            Self::Posix
        }
    }
}

/// `EncodePathChars(input, os)`: the `file://`-prefixed string Ada then parses.
pub fn encode_path(input: &str, flavour: PathFlavour) -> String {
    let mut encoded = String::with_capacity(input.len() + 7);
    encoded.push_str("file://");
    for character in input.chars() {
        // A Windows backslash is a separator, not a character to escape.
        if flavour == PathFlavour::Windows && character == '\\' {
            encoded.push('/');
            continue;
        }
        match ENCODED
            .iter()
            .find(|(candidate, _)| *candidate == character)
        {
            Some((_, replacement)) => encoded.push_str(replacement),
            None => encoded.push(character),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posix(path: &str) -> String {
        encode_path(path, PathFlavour::Posix)
    }

    #[test]
    fn an_ordinary_path_gains_only_the_scheme() {
        assert_eq!(posix("/tmp/x"), "file:///tmp/x");
    }

    #[test]
    fn a_space_becomes_percent_twenty() {
        assert_eq!(posix("/tmp/a b"), "file:///tmp/a%20b");
    }

    #[test]
    fn a_percent_is_encoded_so_an_already_encoded_input_double_encodes() {
        // Node turns "/tmp/a%20b" into "file:///tmp/a%2520b"; the `%` in the
        // input is data, not an escape, so it must be escaped again.
        assert_eq!(posix("/tmp/a%20b"), "file:///tmp/a%2520b");
        assert_eq!(posix("/tmp/a%b"), "file:///tmp/a%25b");
    }

    #[test]
    fn a_tilde_is_encoded_although_the_url_parser_would_leave_it_alone() {
        // RFC 1738 lists `~` as unsafe; this is the one case where Node's
        // path encoding is stricter than URL path serialization.
        assert_eq!(posix("/tmp/~user"), "file:///tmp/%7Euser");
    }

    #[test]
    fn the_full_rfc_1738_set_is_encoded() {
        assert_eq!(posix("/a#b"), "file:///a%23b");
        assert_eq!(posix("/a?b"), "file:///a%3Fb");
        assert_eq!(posix("/a[b]"), "file:///a%5Bb%5D");
        assert_eq!(posix("/a\\b"), "file:///a%5Cb");
        assert_eq!(posix("/a^b"), "file:///a%5Eb");
        assert_eq!(posix("/a|b"), "file:///a%7Cb");
        assert_eq!(posix("/a\"b"), "file:///a%22b");
        assert_eq!(posix("/a\tb"), "file:///a%09b");
        assert_eq!(posix("/a\nb"), "file:///a%0Ab");
        assert_eq!(posix("/a\rb"), "file:///a%0Db");
    }

    #[test]
    fn sub_delimiters_and_non_ascii_are_left_for_the_parser() {
        // The lookup table only covers ASCII up to `~`; everything else is
        // passed through and escaped (or not) by the URL parser.
        assert_eq!(posix("/tmp/a&b=c+d"), "file:///tmp/a&b=c+d");
        assert_eq!(posix("/tmp/a;b"), "file:///tmp/a;b");
        assert_eq!(posix("/tmp/a:b"), "file:///tmp/a:b");
        assert_eq!(posix("/tmp/a@b"), "file:///tmp/a@b");
        assert_eq!(posix("/tmp/é"), "file:///tmp/é");
    }

    #[test]
    fn a_windows_backslash_becomes_a_separator_instead_of_an_escape() {
        assert_eq!(
            encode_path(r"C:\tmp\x", PathFlavour::Windows),
            "file://C:/tmp/x"
        );
        // The same input on POSIX is one opaque path segment.
        assert_eq!(posix(r"C:\tmp\x"), "file://C:%5Ctmp%5Cx");
    }
}
