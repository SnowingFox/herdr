//! Path and `file:` URL conversion, reusing `node:url`'s own implementation.
//!
//! `Bun.pathToFileURL` and `Bun.fileURLToPath` are measured **identical to
//! `node:url` on every case**, including the two a hand-rolled encoder gets
//! wrong — `%23`/`%3F` escaping (so `/a#b?c.txt` is `file:///a%23b%3Fc.txt`) and
//! the `localhost` authority strip (`file://localhost/tmp/a` is `/tmp/a`).
//!
//! What `rn-bind-url` exposes is the C++ half: `EncodePathChars` plus ada's parse
//! for one direction, and `FileURLToPath` for the other. Those are the same
//! functions `node:url` reaches through the binding, so calling them here is not
//! a copy — it is the same code path with a different caller.
//!
//! The two directions agree with Node for different reasons, which is worth
//! keeping straight:
//!
//! * `pathToFileURL` encodes a fixed character set **before** parsing, because a
//!   `%` in the input is data and must be escaped again (`/tmp/a%20b` becomes
//!   `file:///tmp/a%2520b`). Escaping after the parse would get that wrong.
//! * `fileURLToPath` refuses a `%2F` in the pathname and strips an empty host,
//!   which is ada's rule and therefore Node's.

/// Why a URL could not become a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Not a `file:` URL: `ERR_INVALID_URL_SCHEME`, `The URL must be of scheme file`.
    Scheme,
    /// A `file:` URL with a host on POSIX: `ERR_INVALID_FILE_URL_HOST`.
    Host,
    /// A pathname containing `%2F`: `ERR_INVALID_FILE_URL_PATH`.
    EncodedSlash,
}

impl PathError {
    /// The `code` Node puts on this failure.
    pub fn code(self) -> &'static str {
        match self {
            Self::Scheme => "ERR_INVALID_URL_SCHEME",
            Self::Host => "ERR_INVALID_FILE_URL_HOST",
            Self::EncodedSlash => "ERR_INVALID_FILE_URL_PATH",
        }
    }

    /// Node's message for this failure.
    pub fn message(self) -> &'static str {
        match self {
            Self::Scheme => "The URL must be of scheme file",
            Self::Host => "File URL host must be \"localhost\" or empty on linux",
            Self::EncodedSlash => "File URL path must not include encoded / characters",
        }
    }
}

/// `pathToFileURL(path).href`.
///
/// Returns the serialised URL, which is what `Bun.pathToFileURL(p).href` reads.
/// The `URL` object itself is built by the JavaScript layer; this is only the
/// string the object is constructed from, exactly as `node:url` does it.
pub fn path_to_file_url(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    // Two steps, in this order and not the other way round: the fixed character
    // set is escaped *before* the parse, so a `%` in the input is data and gets
    // escaped again (`/tmp/a%20b` becomes `file:///tmp/a%2520b`). Escaping after
    // the parse would treat the input as already-encoded.
    let encoded = rn_bind_url::path::encode_path(path, rn_bind_url::path::PathFlavour::Posix);
    let url = ada_url::Url::parse(&encoded, None).ok()?;
    Some(url.href().to_string())
}

/// `fileURLToPath(url)`, which is `FileURLToPath` on the text of the URL.
pub fn file_url_to_path(url: &str) -> Result<String, PathError> {
    rn_bind_url::file_url::file_url_to_path(url.as_bytes())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|error| match error {
            rn_bind_url::file_url::FileUrlToPathError::Scheme => PathError::Scheme,
            rn_bind_url::file_url::FileUrlToPathError::Host => PathError::Host,
            rn_bind_url::file_url::FileUrlToPathError::EncodedSlash => PathError::EncodedSlash,
            // Measured: `Bun.fileURLToPath("/tmp/notaurl")` is
            // `ERR_INVALID_URL_SCHEME` with `The URL must be of scheme file`, not
            // an "Invalid URL" error — ada refuses a relative reference, and Bun
            // reports what Node's JavaScript layer would for a value that is not
            // a `file:` URL at all.
            rn_bind_url::file_url::FileUrlToPathError::Invalid => PathError::Scheme,
        })
}

/// Node's builtin module names, without the `node:` prefix.
///
/// `module.builtinModules` is the list, and it is what decides whether a bare
/// specifier answers as `node:<name>` in [`crate::fspath::resolve`]. Kept as a
/// sorted slice so a lookup is a binary search and an unknown name costs one
/// comparison per probe rather than a walk.
const NODE_BUILTINS: &[&str] = &[
    "_http_agent",
    "_http_client",
    "_http_common",
    "_http_incoming",
    "_http_outgoing",
    "_http_server",
    "_stream_duplex",
    "_stream_passthrough",
    "_stream_readable",
    "_stream_transform",
    "_stream_wrap",
    "_stream_writable",
    "_tls_common",
    "_tls_wrap",
    "assert",
    "assert/strict",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "dns/promises",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "inspector",
    "inspector/promises",
    "module",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "readline/promises",
    "repl",
    "stream",
    "stream/consumers",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "sys",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "util/types",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// Whether `name` is a Node builtin, so `"fs"` resolves to `"node:fs"`.
///
/// A specifier containing a `/` beyond a submodule path cannot be a builtin
/// alias (`./fs`, `some/fs`), so those are refused before the table is consulted.
pub fn is_node_builtin(name: &str) -> bool {
    if name.is_empty() || name.starts_with('.') || name.starts_with('/') {
        return false;
    }
    NODE_BUILTINS.binary_search(&name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_measured_url_cases_round_trip() {
        // Every `file:` case in the spec, both directions.
        assert_eq!(
            path_to_file_url("/tmp/x/a.txt").as_deref(),
            Some("file:///tmp/x/a.txt")
        );
        assert_eq!(
            path_to_file_url("/with space/a.txt").as_deref(),
            Some("file:///with%20space/a.txt")
        );
        assert_eq!(
            path_to_file_url("/a#b?c.txt").as_deref(),
            Some("file:///a%23b%3Fc.txt")
        );
        assert_eq!(
            file_url_to_path("file:///tmp/with%20space/a.txt").as_deref(),
            Ok("/tmp/with space/a.txt")
        );
        assert_eq!(
            file_url_to_path("file://localhost/tmp/a").as_deref(),
            Ok("/tmp/a")
        );
    }

    #[test]
    fn a_non_file_url_is_the_scheme_error() {
        // `fileURLToPath("/tmp/notaurl")` is `ERR_INVALID_URL_SCHEME` with
        // `The URL must be of scheme file`, which is exactly this pair.
        let failure = file_url_to_path("/tmp/notaurl").expect_err("refused");
        assert_eq!(failure.code(), "ERR_INVALID_URL_SCHEME");
        assert_eq!(failure.message(), "The URL must be of scheme file");
    }

    #[test]
    fn the_builtin_table_is_sorted_so_the_binary_search_is_valid() {
        // A hand-written table that is not sorted would fail the search for some
        // names and not others, which is the worst kind of lookup bug.
        let mut sorted = NODE_BUILTINS.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, NODE_BUILTINS);
    }

    #[test]
    fn the_builtins_bun_answers_with_a_prefix_are_all_present() {
        for name in ["fs", "path", "url", "http", "os", "crypto"] {
            assert!(is_node_builtin(name), "{name} is missing from the table");
        }
        assert!(!is_node_builtin("./fs"));
        assert!(!is_node_builtin("some-package"));
    }
}
