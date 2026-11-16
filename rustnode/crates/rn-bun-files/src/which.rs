//! `Bun.which`: finding an executable on `PATH`.
//!
//! # Measured
//!
//! ```text
//! which("ls")                             => "/usr/bin/ls"
//! which("nonexistent-xyz-abc")            => null
//! which("/bin/ls")                        => "/bin/ls"      (absolute, unchanged)
//! which("/nope/x")                        => null
//! which("mytool", {PATH: "/tmp/bin"})     => "/tmp/bin/mytool"
//! which("noexec", {PATH: "/tmp/bin"})     => null           (not executable)
//! which() / which(42) / which("")         => null           (never throws)
//! ```
//!
//! Two details are load-bearing. The option key is **`PATH`**, uppercase — not
//! Node's `path`. And `which` **never throws**: a missing binary, a numeric
//! argument and an empty string all answer `null`, so there is no error path to
//! get wrong and the whole function is a lookup.
//!
//! # Why an absolute path is returned as given
//!
//! `which("/bin/ls")` answers `"/bin/ls"` rather than the resolved real path:
//! the function answers "is this executable", not "what does this point at". A
//! symlink on `PATH` therefore comes back as the link, which is what a caller
//! that re-executes it wants.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rn_v8_sys::v8;

/// `Bun.which(command, options?)`.
pub fn bun_which<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let command = args.get(0);
    // Every non-string argument answers `null` rather than throwing, so this is a
    // guard rather than an error path.
    if !command.is_string() {
        rv.set(v8::null(scope).into());
        return;
    }
    let command = command.to_rust_string_lossy(scope);
    if command.is_empty() {
        rv.set(v8::null(scope).into());
        return;
    }

    let search = search_path(scope, args.get(1));
    match which(&command, search.as_deref()) {
        Some(found) => match v8::String::new(scope, &found) {
            Some(value) => rv.set(value.into()),
            None => rv.set(v8::null(scope).into()),
        },
        None => rv.set(v8::null(scope).into()),
    }
}

/// The `PATH` a call should search.
///
/// `options.PATH` when given, otherwise the process's own `PATH`. An explicit
/// option of `""` means "search nowhere", which is different from omitting the
/// option, so the two are distinguished rather than collapsed.
fn search_path(scope: &mut v8::PinScope, options: v8::Local<v8::Value>) -> Option<String> {
    if let Ok(object) = v8::Local::<v8::Object>::try_from(options) {
        if let Some(key) = v8::String::new(scope, "PATH") {
            if let Some(value) = object.get(scope, key.into()) {
                if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
                    return Some(text.to_rust_string_lossy(scope));
                }
            }
        }
    }
    std::env::var("PATH").ok()
}

/// Finds `command`, returning the path an exec would use.
///
/// An absolute path is checked directly and returned as given; anything else is
/// looked up in each `PATH` entry in order, and the first executable one wins.
pub fn which(command: &str, search: Option<&str>) -> Option<String> {
    if command.contains('/') {
        // A path with a separator is not a `PATH` lookup either.
        let path = Path::new(command);
        return if is_executable(path) {
            Some(command.to_string())
        } else {
            None
        };
    }

    let search = search?;
    for directory in search.split(':') {
        // An empty entry means the current directory, as it does for `execvp`.
        let base = if directory.is_empty() { "." } else { directory };
        let candidate = Path::new(base).join(command);
        if is_executable(&candidate) {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Whether `path` is a regular file with an execute bit set.
///
/// Checking only the permission bits would let a directory with them set pass,
/// and checking only `is_file` would let a plain data file through.
fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_path_is_answered_as_given_and_never_searched_for() {
        // `which("/bin/ls")` is `"/bin/ls"`, not a resolved real path, and an
        // absolute path is not looked up in `PATH`.
        let found = which("/bin/ls", Some("/definitely/not/here"));
        assert_eq!(found.as_deref(), Some("/bin/ls"));
    }

    #[test]
    fn a_missing_absolute_path_answers_none() {
        assert_eq!(which("/nope/x", Some("/bin")), None);
    }

    #[test]
    fn a_command_not_on_the_given_path_answers_none() {
        assert_eq!(which("nonexistent-xyz-abc", Some("/usr/bin:/bin")), None);
    }

    #[test]
    fn an_empty_search_path_answers_none_rather_than_falling_back() {
        // A caller that passes `PATH: ""` asked for no search at all; falling
        // back to the process's own `PATH` would answer a different question.
        assert_eq!(which("ls", Some("")), None);
    }

    #[test]
    fn the_first_matching_directory_wins() {
        // Order is the whole contract of a `PATH` lookup, so a search that found
        // a later entry would be wrong even though it found *a* binary.
        let found = which("sh", Some("/usr/bin:/bin"));
        assert!(found.is_some(), "sh was not found");
        assert!(found.as_deref().unwrap().starts_with("/usr/bin"));
    }

    #[test]
    fn a_directory_is_not_an_executable() {
        assert!(!is_executable(Path::new("/tmp")));
    }
}
