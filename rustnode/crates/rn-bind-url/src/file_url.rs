//! `node::url::FileURLToPath`: a `file:` URL as the filesystem path it names.
//!
//! This lives here rather than in the crate that first needed it because
//! `src/node_url.cc` owns it, in `namespace node::url`, and two other places in
//! that file's family reuse it. The `fs` binding's `legacyMainResolve` is one
//! caller: it reports `imported from <path>`, and `<path>` is this function's
//! result, not the URL it was given.
//!
//! # Bytes, not text
//!
//! The return type is `Vec<u8>`. A percent-encoded path may decode to bytes that
//! are not valid UTF-8, and Node's `FileURLToPath` returns a `std::string` that
//! carries them through untouched. A `String`-returning version would refuse
//! exactly the paths a real filesystem allows, and `lib/internal/modules/**`
//! compares the result against paths that came from the same filesystem.
//!
//! # What is delegated to ada
//!
//! Everything about parsing. ada is the C++ Node vendors (`deps/ada/ada.cpp`),
//! so "does this string parse as a URL" and "what is a `file:` URL's pathname"
//! are answered by Node's own code rather than by a second reading of the URL
//! standard. Two details come from that and are worth naming because a
//! hand-written parser gets them wrong:
//!
//! * `file:` is a *special* scheme, so `file:x.js` canonicalises to `/x.js`
//!   rather than staying relative.
//! * `file://localhost/x` serialises with an empty host, which is how Node
//!   tests for "no host". Anything still in `hostname()` is a real remote host
//!   and is refused on POSIX.
//!
//! The one thing not delegated is percent-decoding, because ada's
//! `unicode::percent_decode` is not exported by the Rust binding. The copy here
//! is ada's own loop: decode from the first escape onward, and leave anything
//! that is not a complete two-digit escape as literal text.

use ada_url::{SchemeType, Url};

/// Why a string could not become a path.
///
/// One variant per `ERR_*` the C++ throws, in the order it tests for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileUrlToPathError {
    /// `ada::parse` rejected the string. `ERR_INVALID_URL`.
    Invalid,
    /// A URL that parsed, but is not `file:`. `ERR_INVALID_URL_SCHEME`.
    Scheme,
    /// A `file:` URL with a host on POSIX. `ERR_INVALID_FILE_URL_HOST`.
    Host,
    /// A `file:` pathname containing `%2F`. `ERR_INVALID_FILE_URL_PATH`.
    EncodedSlash,
}

/// `FileURLToPath(env, url)`, POSIX branch.
///
/// The `url` argument is the *text* of a URL, which is what the C++ callers have
/// by the time they call in: `LegacyMainResolve` parses `args[2]` itself and
/// passes the aggregator.
pub fn file_url_to_path(input: &[u8]) -> Result<Vec<u8>, FileUrlToPathError> {
    let text = std::str::from_utf8(input).map_err(|_| FileUrlToPathError::Invalid)?;
    let url = Url::parse(text, None).map_err(|_| FileUrlToPathError::Invalid)?;
    if url.scheme_type() != SchemeType::File {
        return Err(FileUrlToPathError::Scheme);
    }
    if !url.hostname().is_empty() {
        return Err(FileUrlToPathError::Host);
    }

    let pathname = url.pathname().as_bytes();
    let mut first_percent = None;
    // `for (size_t i = 0; (i + 2) < pathname.size(); i++)`: only a complete
    // escape is inspected, so a trailing `%` is data rather than a first escape,
    // and the loop stops one short of the end even when the last three bytes
    // spell `%2F`.
    let mut index = 0;
    while index + 2 < pathname.len() {
        if pathname[index] == b'%' {
            if first_percent.is_none() {
                first_percent = Some(index);
            }
            // `(pathname[i + 2] | 0x20) == 'f'` — the `|` folds `F` onto `f`, so
            // both spellings of the hex digit are caught.
            if pathname[index + 1] == b'2' && pathname[index + 2] | 0x20 == b'f' {
                return Err(FileUrlToPathError::EncodedSlash);
            }
        }
        index += 1;
    }

    Ok(percent_decode(pathname, first_percent))
}

/// `ada::unicode::percent_decode`.
///
/// `first_percent` is the index of the first escape, or `None` when the pathname
/// holds none and the bytes are returned as they are.
fn percent_decode(input: &[u8], first_percent: Option<usize>) -> Vec<u8> {
    let Some(first) = first_percent else {
        return input.to_vec();
    };
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..first]);
    let mut index = first;
    while index < input.len() {
        if input[index] == b'%' && index + 2 < input.len() {
            if let (Some(high), Some(low)) =
                (hex_value(input[index + 1]), hex_value(input[index + 2]))
            {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(input[index]);
        index += 1;
    }
    out
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

    fn path(input: &[u8]) -> String {
        String::from_utf8(file_url_to_path(input).expect("a path")).expect("utf-8")
    }

    #[test]
    fn an_absolute_file_url_becomes_its_pathname() {
        assert_eq!(path(b"file:///tmp/x.js"), "/tmp/x.js");
        assert_eq!(path(b"file://localhost/tmp/x.js"), "/tmp/x.js");
        assert_eq!(path(b"file:///"), "/");
        assert_eq!(path(b"file://"), "/");
    }

    #[test]
    fn a_relative_reference_under_file_is_absolute() {
        // `file:` is special, so the path is rooted rather than relative. Node
        // reports `/x.js` for this, and the resolver's message depends on it.
        assert_eq!(path(b"file:x.js"), "/x.js");
    }

    #[test]
    fn dot_segments_are_removed() {
        assert_eq!(path(b"file:///tmp/a/../b/x.js"), "/tmp/b/x.js");
        assert_eq!(path(b"file:///a/./b/x.js"), "/a/b/x.js");
    }

    #[test]
    fn percent_escapes_are_decoded() {
        assert_eq!(path(b"file:///tmp/a%20b/x.js"), "/tmp/a b/x.js");
        // An encoded backslash is not an encoded slash, so it decodes to data.
        assert_eq!(path(b"file:///a%5Cb/x.js"), "/a\\b/x.js");
    }

    #[test]
    fn a_decoded_byte_sequence_need_not_be_utf8() {
        // `%FF` has no UTF-8 reading; Node carries the byte through, and a path
        // that names a real file with that byte must survive.
        assert_eq!(
            file_url_to_path(b"file:///tmp/a%FFb").expect("a path"),
            b"/tmp/a\xFFb".to_vec()
        );
    }

    #[test]
    fn an_encoded_slash_is_refused_in_either_case() {
        assert_eq!(
            file_url_to_path(b"file:///a%2Fb/x.js"),
            Err(FileUrlToPathError::EncodedSlash)
        );
        assert_eq!(
            file_url_to_path(b"file:///a%2fb/x.js"),
            Err(FileUrlToPathError::EncodedSlash)
        );
    }

    #[test]
    fn a_query_and_fragment_are_not_part_of_the_path() {
        assert_eq!(path(b"file:///tmp/x.js?q=1"), "/tmp/x.js");
        assert_eq!(path(b"file:///tmp/x.js#h"), "/tmp/x.js");
    }

    #[test]
    fn a_non_file_scheme_is_its_own_error() {
        assert_eq!(
            file_url_to_path(b"ftp://example.com/x"),
            Err(FileUrlToPathError::Scheme)
        );
        assert_eq!(
            file_url_to_path(b"data:text/javascript,1"),
            Err(FileUrlToPathError::Scheme)
        );
        assert_eq!(
            file_url_to_path(b"mailto:a@b"),
            Err(FileUrlToPathError::Scheme)
        );
    }

    #[test]
    fn a_relative_string_is_not_a_url() {
        assert_eq!(
            file_url_to_path(b"/tmp/x.js"),
            Err(FileUrlToPathError::Invalid)
        );
        assert_eq!(
            file_url_to_path(b"notaurl"),
            Err(FileUrlToPathError::Invalid)
        );
        assert_eq!(file_url_to_path(b""), Err(FileUrlToPathError::Invalid));
    }

    #[test]
    fn a_remote_host_is_refused() {
        assert_eq!(
            file_url_to_path(b"file://host/tmp/x.js"),
            Err(FileUrlToPathError::Host)
        );
    }

    #[test]
    fn percent_decoding_leaves_incomplete_escapes_alone() {
        assert_eq!(percent_decode(b"a%2", Some(1)), b"a%2".to_vec());
        assert_eq!(percent_decode(b"a%zzb", Some(1)), b"a%zzb".to_vec());
        assert_eq!(percent_decode(b"a%20b", Some(1)), b"a b".to_vec());
        // No first escape means nothing to decode, including a trailing `%`.
        assert_eq!(percent_decode(b"a%2", None), b"a%2".to_vec());
    }
}
