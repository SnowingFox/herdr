//! The slice of `file:` URL handling the scope walk needs.
//!
//! `GetPackageScopeConfig` is written against a URL rather than a path: it
//! appends `./package.json` to the caller's URL and then repeatedly resolves
//! `../package.json` against the result, stopping when the pathname no longer
//! changes or when it names `node_modules/package.json`. That structure is not
//! incidental — it is how Node gets the "walk stops at node_modules" rule and
//! the "return a path to a package.json that does not exist" fallback for free.
//!
//! This module implements exactly that and no more. It is not a general URL
//! parser: only the `file:` scheme can produce a filesystem path, so any other
//! scheme is rejected while parsing, which is where Node's own `FileURLToPath`
//! would fail.
//!
//! Two behaviours are load-bearing and easy to get subtly wrong:
//!
//! * `file:` is a *special* scheme, so `file:relative.js` canonicalises to
//!   `/relative.js`, exactly as the URL standard's special-scheme rules force.
//!   Without that the walk would treat the input as a relative path.
//! * Relative resolution drops the base path's last segment unless the base
//!   ends in `/`, so `./package.json` against `file:///a/b/x.js` is
//!   `/a/b/package.json` while `../package.json` against
//!   `file:///a/b/package.json` is `/a/package.json`.

/// A parsed `file:` URL, reduced to the pathname the walk needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUrl {
    /// Decoded pathname. Always absolute, because `file:` is special.
    pub pathname: String,
}

/// Why a URL could not be turned into a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlError {
    /// The input is not a `file:` URL.
    Invalid,
    /// A `file:` URL with a host other than `localhost`.
    Host,
    /// A `file:` pathname that percent-encodes a slash.
    EncodedSlash,
}

/// Parses an absolute `file:` URL.
pub fn parse_file_url(input: &str) -> Result<FileUrl, UrlError> {
    let rest = strip_file_scheme(input).ok_or(UrlError::Invalid)?;
    // `file:` is a special scheme: everything after `file:` that is not an
    // authority belongs to an absolute path.
    let (authority, path) = match rest.strip_prefix("//") {
        Some(after_slashes) => match after_slashes.find('/') {
            Some(index) => (&after_slashes[..index], &after_slashes[index..]),
            None => (after_slashes, "/"),
        },
        None => ("", rest),
    };

    if !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost") {
        return Err(UrlError::Host);
    }

    // A query or fragment is not part of the pathname.
    let path = path.split(['?', '#']).next().unwrap_or_default();

    if path.starts_with('/') {
        Ok(FileUrl {
            pathname: remove_dot_segments(&percent_decode(path)?),
        })
    } else {
        // A relative reference under a special scheme still yields an absolute
        // pathname, because the scheme supplies an empty host and a root.
        Ok(FileUrl {
            pathname: remove_dot_segments(&percent_decode(&format!("/{path}"))?),
        })
    }
}

/// Returns the text after `file:`, when the input starts with that scheme.
fn strip_file_scheme(input: &str) -> Option<&str> {
    let colon = input.find(':')?;
    let scheme = &input[..colon];
    // A scheme is `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
    let mut characters = scheme.chars();
    if !characters.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    if !characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return None;
    }
    if !scheme.eq_ignore_ascii_case("file") {
        return None;
    }
    Some(&input[colon + 1..])
}

/// Resolves `reference` against `base`, per the URL standard's path rules.
///
/// Both references the walk uses are relative, so an absolute `reference` is
/// treated as a path in its own right rather than rejected.
pub fn resolve_reference(base: &str, reference: &str) -> String {
    if reference.starts_with('/') {
        return remove_dot_segments(reference);
    }
    let directory = match base.rfind('/') {
        // Keep the whole base when it already ends in a separator.
        Some(index) if index + 1 == base.len() => base,
        Some(index) => &base[..=index],
        None => "/",
    };
    remove_dot_segments(&format!("{directory}{reference}"))
}

/// The URL standard's dot-segment removal, applied to an absolute path.
fn remove_dot_segments(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    let trailing_slash = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let mut out = String::with_capacity(path.len());
    for segment in &stack {
        out.push('/');
        out.push_str(segment);
    }
    // The root always has a trailing separator, and so does a path that named
    // a directory; `pop()`-ing back to nothing must still produce `/`.
    if out.is_empty() || trailing_slash {
        out.push('/');
    }
    out
}

/// Decodes percent escapes.
///
/// An encoded `/` is refused rather than decoded, because decoding it would
/// silently change which directory is walked. Node makes the same check in
/// `FileURLToPath` for the same reason.
fn percent_decode(path: &str) -> Result<String, UrlError> {
    if !path.contains('%') {
        return Ok(path.to_string());
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' || index + 2 >= bytes.len() {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        let (Some(high), Some(low)) = (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        else {
            // A stray `%` is literal text, not an escape.
            out.push(bytes[index]);
            index += 1;
            continue;
        };
        let decoded = (high << 4) | low;
        if decoded == b'/' {
            return Err(UrlError::EncodedSlash);
        }
        out.push(decoded);
        index += 3;
    }
    String::from_utf8(out).map_err(|_| UrlError::Invalid)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(input: &str) -> String {
        parse_file_url(input).expect("parses").pathname
    }

    #[test]
    fn absolute_file_urls_become_pathnames() {
        assert_eq!(path("file:///tmp/x.js"), "/tmp/x.js");
        assert_eq!(path("file://localhost/tmp/x.js"), "/tmp/x.js");
        assert_eq!(path("file:///"), "/");
    }

    #[test]
    fn a_relative_reference_under_file_is_absolute() {
        // `file:` is a special scheme, so this is not a relative path. Node
        // reports `/package.json` for it, which only follows if the base
        // pathname is `/relative.js`.
        assert_eq!(path("file:relative.js"), "/relative.js");
        assert_eq!(
            resolve_reference(&path("file:relative.js"), "./package.json"),
            "/package.json"
        );
    }

    #[test]
    fn dot_segments_are_removed() {
        assert_eq!(path("file:///a/./b/../c/x.js"), "/a/c/x.js");
        assert_eq!(path("file:///a/b/"), "/a/b/");
        assert_eq!(path("file:///a//b/x.js"), "/a/b/x.js");
    }

    #[test]
    fn percent_escapes_are_decoded() {
        assert_eq!(path("file:///a%20b/x.js"), "/a b/x.js");
    }

    #[test]
    fn encoded_slash_is_refused() {
        assert_eq!(
            parse_file_url("file:///a%2Fb/x.js"),
            Err(UrlError::EncodedSlash)
        );
    }

    #[test]
    fn non_file_schemes_are_refused() {
        for input in [
            "https://example.com/a.js",
            "data:text/javascript,1",
            "/tmp/x.js",
            "",
        ] {
            assert_eq!(parse_file_url(input), Err(UrlError::Invalid), "{input}");
        }
    }

    #[test]
    fn a_remote_host_is_refused() {
        assert_eq!(parse_file_url("file://host/tmp/x.js"), Err(UrlError::Host));
    }

    #[test]
    fn resolution_appends_below_a_file_and_above_a_directory() {
        assert_eq!(
            resolve_reference("/tmp/a/b/x.js", "./package.json"),
            "/tmp/a/b/package.json"
        );
        assert_eq!(
            resolve_reference("/tmp/a/b/", "./package.json"),
            "/tmp/a/b/package.json"
        );
        assert_eq!(
            resolve_reference("/tmp/a/b/package.json", "../package.json"),
            "/tmp/a/package.json"
        );
    }

    #[test]
    fn resolution_at_the_root_is_a_fixed_point() {
        // This is how the walk terminates: resolving again must not move.
        let once = resolve_reference("/package.json", "../package.json");
        assert_eq!(once, "/package.json");
        assert_eq!(resolve_reference(&once, "../package.json"), once);
    }

    #[test]
    fn query_and_fragment_are_not_path() {
        assert_eq!(path("file:///tmp/x.js?q=1"), "/tmp/x.js");
        assert_eq!(path("file:///tmp/x.js#h"), "/tmp/x.js");
    }
}
