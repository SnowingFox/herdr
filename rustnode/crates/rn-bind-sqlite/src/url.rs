//! The `file:` URL handling `ValidateDatabasePath` performs.
//!
//! Node checks a candidate path's `href` with `ada::can_parse` and then requires
//! the scheme to be `file:`, returning the *href* rather than a decoded path:
//! SQLite's own URI handling does the decoding when
//! `SQLITE_OPEN_URI` is set, which it always is here.
//!
//! That means this module does not need a full URL parser. It needs to answer
//! three questions — can this be parsed as a URL at all, is it `file:`, and what
//! is the canonical href — which is what the checks below do. The subtlety that
//! matters is that `file:relative.db` is *not* a valid URL while
//! `file:///absolute.db` and `file://host/share.db` are, and Node's
//! `pathToFileURL` always produces the latter form.

/// Why a `file:` URL was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlError {
    /// The text does not parse as a URL.
    Invalid,
    /// It parses, but the scheme is not `file:`.
    NotFile,
}

/// The path part of a `file:` URL, or `None` when `href` is not one.
///
/// The returned text is handed straight to `sqlite3_open_v2` with
/// `SQLITE_OPEN_URI`, which is what Node does: the href keeps its `file:`
/// prefix and SQLite interprets the URI. `file:///tmp/x.db` therefore becomes
/// the path `/tmp/x.db` inside SQLite, and percent escapes are decoded there.
pub fn file_url_to_path(href: &str) -> Option<String> {
    if !href.starts_with("file:") {
        // Not a file URL. The caller decides whether that is a scheme error or
        // a plain invalid path.
        return None;
    }
    let rest = &href["file:".len()..];
    // `file:` followed by a slash is a hierarchical URL: `file:///path` or
    // `file://host/path`. `file:path` without one is not a valid URL (Node's
    // `pathToFileURL` never produces it and `new URL('file:x')` throws).
    let rest = rest.strip_prefix("//")?;
    // Strip an authority, which is empty for `file:///path` and a hostname
    // otherwise. An empty authority means the path starts at the next slash.
    let path_start = rest.find('/');
    match path_start {
        Some(index) => {
            let authority = &rest[..index];
            let path = &rest[index..];
            if authority.is_empty() || authority == "localhost" {
                Some(path.to_string())
            } else {
                // A remote host. Node passes it to SQLite, which cannot open a
                // network path and reports a plain SQLite error; keeping the
                // authority in the string preserves that behaviour.
                Some(format!("//{authority}{path}"))
            }
        }
        // `file://host` with no path. Node's `ada::can_parse` accepts it and
        // SQLite treats the empty path as an error, so it is passed along
        // rather than rejected here.
        None => Some(String::new()),
    }
}

/// Whether `href` parses as a `file:` URL, for the caller that must distinguish
/// `ERR_INVALID_URL` from `ERR_INVALID_URL_SCHEME`.
pub fn classify(href: &str) -> Result<String, UrlError> {
    // A URL needs a scheme, so the first colon has to come before any `/`, `?`
    // or `#`, and the scheme itself has to be non-empty and start with a letter.
    let Some(colon) = href.find(':') else {
        return Err(UrlError::Invalid);
    };
    let scheme = &href[..colon];
    if scheme.is_empty()
        || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return Err(UrlError::Invalid);
    }
    if !scheme.eq_ignore_ascii_case("file") {
        return Err(UrlError::NotFile);
    }
    file_url_to_path(href).ok_or(UrlError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_file_url_becomes_a_path() {
        assert_eq!(
            file_url_to_path("file:///tmp/example.db"),
            Some("/tmp/example.db".to_string())
        );
    }

    #[test]
    fn localhost_authority_is_dropped() {
        assert_eq!(
            file_url_to_path("file://localhost/tmp/example.db"),
            Some("/tmp/example.db".to_string())
        );
    }

    #[test]
    fn remote_authority_is_kept_so_sqlite_reports_the_error() {
        assert_eq!(
            file_url_to_path("file://example.com/share.db"),
            Some("//example.com/share.db".to_string())
        );
    }

    #[test]
    fn a_relative_file_url_is_not_parsed() {
        assert_eq!(file_url_to_path("file:relative.db"), None);
    }

    #[test]
    fn another_scheme_is_not_a_file_url() {
        assert_eq!(file_url_to_path("https://example.com/x.db"), None);
    }

    #[test]
    fn classify_separates_invalid_from_wrong_scheme() {
        assert_eq!(classify("https://example.com/x.db"), Err(UrlError::NotFile));
        assert_eq!(classify("not a url"), Err(UrlError::Invalid));
        assert_eq!(classify("file:///tmp/x.db"), Ok("/tmp/x.db".to_string()));
    }

    #[test]
    fn percent_escapes_are_left_for_sqlite_to_decode() {
        // Node passes the href through and lets SQLite's URI parser decode it,
        // so decoding here as well would double-decode `%20` into `%20`.
        assert_eq!(
            file_url_to_path("file:///tmp/two%20words.db"),
            Some("/tmp/two%20words.db".to_string())
        );
    }
}
