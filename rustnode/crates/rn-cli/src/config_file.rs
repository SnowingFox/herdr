//! Reading `--config-file`'s file, and reporting a bad one the way Node does.
//!
//! `--config-file` was declared in the option table and accepted by the walk, and
//! nothing ever opened the file. A process asked to read a config that does not
//! exist therefore ran the script as if the flag were not there:
//!
//! ```text
//! $ rustnode --config-file=i-do-not-exist.json -p '"Hello"'
//! Hello
//! $ echo $?
//! 0
//! ```
//!
//! Node exits 9 there, and prints two lines, not one:
//!
//! ```text
//! Cannot read configuration from i-do-not-exist.json: no such file or directory
//! /path/to/node: i-do-not-exist.json: not found
//! ```
//!
//! # Why the first line has no program prefix
//!
//! The two lines come from two different places. `ConfigReader::ParseConfig`
//! (`src/node_config_file.cc`) writes its diagnostic to stderr itself, as it
//! reads, with `FPrintF` and no `argv[0]`; it then returns `FileError` or
//! `InvalidContent`, and `InitializeOncePerProcess` pushes `<path>: not found` or
//! `<path>: invalid content` onto the error vector (`src/node.cc:1014-1019`),
//! which `StartInternal` prints as `"%s: %s\n"` against `argv[0]`. So the first
//! line is a bare sentence and the second is a prefixed message, and reproducing
//! one through the other's format would be wrong in a way a test can see.
//!
//! # Scope: the read and its errors, not the config's meaning
//!
//! Node's reader is about 600 lines (`src/node_config_file.cc`) and most of it is
//! semantics: `nodeVersion` selection, the `configs` array, namespace validation,
//! and turning accepted options back into an argument vector. None of that is
//! implemented here. What is implemented is the part the flag's absence made
//! invisible — that the file is opened, that one which cannot be read is a
//! startup error, and that one which is not a JSON object is one too.
//!
//! A file that parses as a JSON object is therefore read and accepted without
//! applying anything. That is deliberately the same *effect* such a file has
//! today (none), and it is the only choice that keeps the error path honest: to
//! report a missing file or a non-object root the bytes have to be read and
//! classified, and there is no way to "stop before reading" a file whose validity
//! is exactly what is being checked. Warning or failing on a valid file would
//! instead break runs that work today, on the strength of a feature this change
//! does not claim.

/// The byte-order mark `simdjson` skips before reading a document.
const BOM: char = '\u{feff}';

/// What `--config-file` cost the process, in the two lines Node writes.
///
/// Not one string because only the second line carries the program prefix; see
/// this module's note on where each comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFileError {
    /// The text `ConfigReader::ParseConfig` writes to stderr itself, verbatim.
    ///
    /// Already complete: it ends with its own newline, and the `Root value
    /// unexpected` variant even carries the blank line Node prints after it.
    /// Written with `eprint!` rather than `eprintln!` for that reason.
    pub diagnostic: String,
    /// `<path>: not found` or `<path>: invalid content`, which is what the reader
    /// contributes to the error vector `StartInternal` prints against the program
    /// name.
    pub message: String,
}

/// What the root of a config document turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Root {
    /// A JSON object, which Node's reader would go on to interpret.
    Object,
    /// A document that is not an object: `5`, `[]`, `"x"`, `not json`.
    NotAnObject,
    /// A document that cannot be parsed at all: empty, truncated, bad UTF-8.
    Unparseable,
}

/// Reads `path` and checks that it is a JSON object.
///
/// `Ok(())` means the file was opened and its root is an object. The caller does
/// not act on the contents; see this module's note on scope.
///
/// # Errors
///
/// Returns the two lines Node writes for a file it cannot read or cannot accept,
/// already in Node's wording: `diagnostic` is what `ConfigReader::ParseConfig`
/// prints itself, and `message` is the `<path>: not found` or
/// `<path>: invalid content` it contributes to the startup error vector.
pub fn read(path: &str) -> Result<(), ConfigFileError> {
    // Bytes rather than a string: `ReadFileSync` hands the parser raw bytes, and
    // a file that is not UTF-8 is a parse failure (`Can't parse`) rather than an
    // open failure. `read_to_string` would merge the two.
    let contents = match std::fs::read(path) {
        Ok(contents) => contents,
        Err(error) => return Err(unreadable(path, &error)),
    };
    match classify(&contents) {
        Root::Object => Ok(()),
        Root::NotAnObject => Err(ConfigFileError {
            // The blank line is Node's: `FPrintF(stderr, "Root value unexpected
            // not an object for %s\n\n", ...)`.
            diagnostic: format!("Root value unexpected not an object for {path}\n\n"),
            message: invalid_content(path),
        }),
        Root::Unparseable => Err(ConfigFileError {
            diagnostic: format!("Can't parse {path}\n"),
            message: invalid_content(path),
        }),
    }
}

/// The `<path>: invalid content` line a `ParseResult::InvalidContent` produces.
fn invalid_content(path: &str) -> String {
    format!("{path}: invalid content")
}

/// The two pieces of an open failure: libuv's description, then `not found`.
fn unreadable(path: &str, error: &std::io::Error) -> ConfigFileError {
    // `ParseConfig` formats `uv_strerror(r)`, where `r` is the raw `uv_fs_open`
    // result, so the text is libuv's and not the libc `strerror` one. They differ
    // in case (`no such file or directory` against `No such file or directory`),
    // which is why the answer comes from libuv rather than from a match here.
    let description = match error.raw_os_error() {
        Some(errno) => rn_uv::sys_error_message(errno),
        // No errno means the failure came from Rust rather than from the OS, so
        // there is no libuv spelling to reproduce. Node would have had an errno.
        None => error.to_string(),
    };
    ConfigFileError {
        diagnostic: format!("Cannot read configuration from {path}: {description}\n"),
        message: format!("{path}: not found"),
    }
}

/// Which of Node's outcomes `contents` produces.
///
/// This reproduces `ParseConfig`'s order — iterate, then `get_object` — rather
/// than being a "is it valid JSON" predicate, because the two are not the same
/// question. `not json` is *not* a parse failure in Node: simdjson's on-demand
/// reader only looks at the structural character, sees something that is not `{`,
/// and answers `INCORRECT_TYPE`, which the reader reports as `Root value
/// unexpected not an object`. An empty file fails earlier, inside `iterate`, and
/// is reported as `Can't parse`. The two messages are distinguishable in the
/// oracle's output, so they are distinguished here.
fn classify(contents: &[u8]) -> Root {
    let Ok(text) = std::str::from_utf8(contents) else {
        // An invalid UTF-8 sequence cannot be a JSON document; simdjson rejects
        // it in `iterate`, before any structural question is asked.
        return Root::Unparseable;
    };
    // simdjson accepts a leading byte-order mark, so it is dropped before either
    // check: `serde_json` would otherwise reject the mark as junk.
    let text = text.strip_prefix(BOM).unwrap_or(text);

    let first = text.trim_start().chars().next();
    // Nothing but whitespace never reaches the structural stage: `iterate` fails
    // on it, which is the `Can't parse` Node prints for an empty config.
    let Some(first) = first else {
        return Root::Unparseable;
    };
    // A NUL is not JSON whitespace and not a structural character either, but
    // simdjson rejects it in `iterate`, so it is a parse failure rather than a
    // non-object root.
    if text.contains('\0') {
        return Root::Unparseable;
    }

    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(_)) => Root::Object,
        Ok(_) => Root::NotAnObject,
        // A document `serde_json` rejects but simdjson accepts *as a token* is
        // decided by the first structural character: `{` and `"` mean the failure
        // is inside the value (truncated, unterminated), and anything else means
        // the root is simply not an object.
        Err(_) => match first {
            '{' | '"' => Root::Unparseable,
            _ => Root::NotAnObject,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, Root};

    /// What the pinned oracle prints for each document, as measured.
    ///
    /// Every row is a `printf` of the document into a file handed to
    /// `node --config-file=<path> -p '"H"'`. The table is the reason [`classify`]
    /// has three answers rather than two: Node distinguishes "cannot parse this at
    /// all" from "the root is not an object", and both end in `invalid content`.
    #[test]
    fn the_root_kind_matches_the_oracle() {
        for (document, expected) in [
            ("{}", Root::Object),
            ("{} ", Root::Object),
            ("{\"a\":1}", Root::Object),
            ("\u{feff}{}", Root::Object),
            ("\t{}", Root::Object),
            // Not an object: simdjson answers INCORRECT_TYPE for every one.
            ("not json", Root::NotAnObject),
            ("5", Root::NotAnObject),
            ("-1", Root::NotAnObject),
            ("null", Root::NotAnObject),
            ("true", Root::NotAnObject),
            ("[]", Root::NotAnObject),
            ("[1]", Root::NotAnObject),
            ("\"x\"", Root::NotAnObject),
            ("nulll", Root::NotAnObject),
            ("1x", Root::NotAnObject),
            ("[1,", Root::NotAnObject),
            ("[]x", Root::NotAnObject),
            ("}", Root::NotAnObject),
            (",", Root::NotAnObject),
            ("h\u{e9}llo", Root::NotAnObject),
            ("\u{feff}not json", Root::NotAnObject),
            // Unparseable: `iterate` fails before the structural stage.
            ("", Root::Unparseable),
            ("   ", Root::Unparseable),
            ("\n", Root::Unparseable),
            ("\t", Root::Unparseable),
            ("{", Root::Unparseable),
            ("{\"a\"", Root::Unparseable),
            ("\"abc", Root::Unparseable),
            ("{} x", Root::Unparseable),
        ] {
            assert_eq!(classify(document.as_bytes()), expected, "{document:?}");
        }
    }

    /// The one row where the emulation is known to differ, pinned so the
    /// difference is a recorded decision rather than a surprise.
    ///
    /// simdjson's on-demand reader stops after a complete root object and accepts
    /// `{}{}` — measured on the oracle, which prints `H` — while `serde_json`
    /// rejects the trailing value. Reproducing that would mean tracking which
    /// token the reader stopped at, which is the parse semantics this change
    /// deliberately leaves out; both spellings are documents no real config has,
    /// and the difference shows only as an extra `Can't parse` on a file that was
    /// never going to be applied.
    #[test]
    fn concatenated_objects_are_the_known_deviation() {
        assert_eq!(classify(b"{}{}"), Root::Unparseable);
    }

    /// Invalid UTF-8 is a parse failure, because Node reads bytes and its JSON
    /// reader rejects the sequence before any structural question is asked.
    #[test]
    fn invalid_utf8_cannot_be_parsed() {
        assert_eq!(classify(b"\xff\xfe{}"), Root::Unparseable);
    }
}
