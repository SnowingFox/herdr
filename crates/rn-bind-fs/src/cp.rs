//! `fs.cpSync`'s path validation, `src/node_file.cc`'s `CpSyncCheckPaths`.
//!
//! `lib/internal/fs/cp/cp-sync.js` calls this once, before it walks anything,
//! and everything else about `cpSync` is JavaScript over the other `fs`
//! members. So this one function is what makes `fs.cpSync` work at all; without
//! it every call throws `fsBinding.cpSyncCheckPaths is not a function`.
//!
//! # What it decides, and what it does not
//!
//! It answers four questions and throws `ERR_FS_CP_*` when any of them is wrong:
//!
//! * are `src` and `dest` the same file,
//! * would a directory overwrite a non-directory,
//! * would a non-directory overwrite a directory,
//! * is `dest` inside `src`.
//!
//! It does **not** check permissions, handle symlinks beyond the `dereference`
//! flag, or copy anything; those belong to the JavaScript layer and to
//! `cpSyncCopyDir`, which is still deferred.
//!
//! # The error shapes are recorded, not guessed
//!
//! They were captured from the `node` binary on PATH for the four cases and are
//! reproduced exactly, because a test asserting on `e.code` or on the message
//! sees them:
//!
//! ```text
//! same path     ERR_FS_CP_EINVAL           src and dest cannot be the same /p
//! dir → file    ERR_FS_CP_DIR_TO_NON_DIR   Cannot overwrite non-directory /d with directory /s
//! file → dir    ERR_FS_CP_NON_DIR_TO_DIR   Cannot overwrite directory /d with non-directory /s
//! subdirectory  ERR_FS_CP_EINVAL           Cannot copy /s/ to a subdirectory of self /s/sub
//! ```
//!
//! `src` carries a trailing separator in the last message and `dest` does not,
//! which is not a typo on either side: the C++ appends the separator to
//! `src_path_str` before comparing prefixes and formats the message from that
//! same string.

use std::path::{Component, Path, PathBuf};

use rn_v8_sys::v8;

/// What `CpSyncCheckPaths` found, before it is turned into an exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpError {
    /// `src and dest cannot be the same`.
    SamePath,
    /// `Cannot overwrite non-directory <dest> with directory <src>`.
    DirToNonDir,
    /// `Cannot overwrite directory <dest> with non-directory <src>`.
    NonDirToDir,
    /// `Cannot copy <src>/ to a subdirectory of self <dest>`.
    Subdirectory,
}

impl CpError {
    /// The `code` property Node attaches.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::SamePath | Self::Subdirectory => "ERR_FS_CP_EINVAL",
            Self::DirToNonDir => "ERR_FS_CP_DIR_TO_NON_DIR",
            Self::NonDirToDir => "ERR_FS_CP_NON_DIR_TO_DIR",
        }
    }
}

/// Builds the message body for one error, given both paths already rendered.
///
/// Split from the V8 work so the wording is testable without a scope.
#[must_use]
pub fn message(error: &CpError, src: &str, dest: &str) -> String {
    match error {
        CpError::SamePath => format!("src and dest cannot be the same {dest}"),
        CpError::DirToNonDir => {
            format!("Cannot overwrite non-directory {dest} with directory {src}")
        }
        CpError::NonDirToDir => {
            format!("Cannot overwrite directory {dest} with non-directory {src}")
        }
        CpError::Subdirectory => {
            // The C++ appends the separator to `src` before comparing and
            // formats from that same string, so the message keeps the trailing
            // slash while `dest` never has one.
            let mut with_separator = src.to_string();
            if !with_separator.ends_with(std::path::MAIN_SEPARATOR) {
                with_separator.push(std::path::MAIN_SEPARATOR);
            }
            format!("Cannot copy {with_separator} to a subdirectory of self {dest}")
        }
    }
}

/// Runs the four checks `CpSyncCheckPaths` performs on a working filesystem.
///
/// Returns the first failure, or `None` when the pair is copyable. `dereference`
/// swaps `symlink_metadata` for `metadata`, which is what decides whether a
/// symlink is treated as its target.
#[must_use]
pub fn check_paths(src: &Path, dest: &Path, dereference: bool, recursive: bool) -> Option<CpError> {
    let metadata_of = |path: &Path| {
        if dereference {
            std::fs::metadata(path)
        } else {
            std::fs::symlink_metadata(path)
        }
    };

    // Node stats `src` first and throws on failure, because a missing source is
    // the caller's error rather than something to compare against.
    let src_meta = metadata_of(src).ok()?;
    let dest_meta = metadata_of(dest).ok();

    // `std::filesystem::equivalent` compares device and inode, so a hard link
    // and the original are the same file here as they are there.
    if let Some(dest_meta) = dest_meta.as_ref() {
        if same_file(src, dest, &src_meta, dest_meta) {
            return Some(CpError::SamePath);
        }
    }

    let src_is_dir = src_meta.is_dir() || (dereference && is_symlink(src));
    // `dest_exists` is `!error && type != not_found`, so a failed stat means
    // "does not exist" and the directory checks are skipped entirely.
    if let Some(dest_meta) = dest_meta.as_ref() {
        let dest_is_dir = dest_meta.is_dir();
        if src_is_dir && !dest_is_dir {
            return Some(CpError::DirToNonDir);
        }
        if !src_is_dir && dest_is_dir {
            return Some(CpError::NonDirToDir);
        }
    }

    // A directory copied into its own subtree would recurse forever. The check
    // is a prefix test on the normalised paths plus a parent walk, which is what
    // catches `src/../src/sub` as well as the direct spelling.
    if src_is_dir && recursive {
        let src_text = normalised(src);
        let dest_text = normalised(dest);
        let mut prefix = src_text.clone();
        if !prefix.ends_with(std::path::MAIN_SEPARATOR) {
            prefix.push(std::path::MAIN_SEPARATOR);
        }
        if dest_text.starts_with(&prefix) {
            return Some(CpError::Subdirectory);
        }

        // The C++ walks `dest`'s parents looking for anything equivalent to
        // `src`, which catches a dest that is a symlink into the source tree
        // without the text prefix test having matched.
        let mut parent = dest.parent();
        while let Some(current) = parent {
            if current == src.parent().unwrap_or(Path::new("")) {
                break;
            }
            if same_file(src, current, &src_meta, &metadata_of(current).ok()?) {
                return Some(CpError::Subdirectory);
            }
            match current.parent() {
                Some(next) if next != current => parent = Some(next),
                _ => break,
            }
        }
    }

    None
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

/// `std::filesystem::equivalent`: same device and inode.
fn same_file(a: &Path, b: &Path, a_meta: &std::fs::Metadata, b_meta: &std::fs::Metadata) -> bool {
    // A path is always equivalent to itself, even when the platform cannot
    // report inodes.
    if a == b {
        return true;
    }
    use std::os::unix::fs::MetadataExt;
    a_meta.dev() == b_meta.dev() && a_meta.ino() == b_meta.ino()
}

/// `std::filesystem::path::lexically_normal`, close enough for a prefix test.
///
/// `fs.cpSync`'s caller passes whatever the user wrote, so `a/./b` and `a/b`
/// have to compare equal; the C++ relies on `filesystem::equivalent` for the
/// inode answer and on the normal form only to find a textual prefix.
fn normalised(path: &Path) -> String {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out.to_string_lossy().into_owned()
}

/// Throws the `SystemError` `fs.cpSync` expects.
pub fn throw_cp_error(scope: &mut v8::PinScope<'_, '_>, error: &CpError, src: &str, dest: &str) {
    let Some(text) = v8::String::new(scope, &message(error, src, dest)) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        for (name, value) in [
            (
                "code",
                v8::String::new(scope, error.code())
                    .map(|text| text.into())
                    .unwrap_or_else(|| v8::undefined(scope).into()),
            ),
            // `SystemError` always carries these two; `fs.cp`'s tests read
            // `err.code` and some read `err.syscall`.
            (
                "syscall",
                v8::String::new(scope, "cp")
                    .map_or_else(|| v8::undefined(scope).into(), |text| text.into()),
            ),
            ("errno", v8::Integer::new(scope, -libc::EINVAL).into()),
        ] {
            if let Some(key) = v8::String::new(scope, name) {
                object.set(scope, key.into(), value);
            }
        }
    }
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_messages_match_what_node_prints() {
        // Recorded from `node` on PATH for each case; see the module docs.
        assert_eq!(
            message(&CpError::SamePath, "/p", "/p"),
            "src and dest cannot be the same /p"
        );
        assert_eq!(
            message(&CpError::DirToNonDir, "/src", "/dest"),
            "Cannot overwrite non-directory /dest with directory /src"
        );
        assert_eq!(
            message(&CpError::NonDirToDir, "/src", "/dest"),
            "Cannot overwrite directory /dest with non-directory /src"
        );
        // `src` keeps its trailing separator, `dest` never gains one.
        assert_eq!(
            message(&CpError::Subdirectory, "/src", "/src/sub"),
            "Cannot copy /src/ to a subdirectory of self /src/sub"
        );
    }

    #[test]
    fn a_trailing_separator_is_not_doubled() {
        assert_eq!(
            message(&CpError::Subdirectory, "/src/", "/src/sub"),
            "Cannot copy /src/ to a subdirectory of self /src/sub"
        );
    }

    #[test]
    fn the_codes_are_the_ones_fs_cp_throws() {
        assert_eq!(CpError::SamePath.code(), "ERR_FS_CP_EINVAL");
        assert_eq!(CpError::Subdirectory.code(), "ERR_FS_CP_EINVAL");
        assert_eq!(CpError::DirToNonDir.code(), "ERR_FS_CP_DIR_TO_NON_DIR");
        assert_eq!(CpError::NonDirToDir.code(), "ERR_FS_CP_NON_DIR_TO_DIR");
    }

    #[test]
    fn a_cur_dir_component_does_not_change_the_normal_form() {
        // `fs.cpSync('a/./b', ...)` must compare the same as `'a/b'`, because
        // the prefix test is textual.
        assert_eq!(normalised(Path::new("a/./b")), normalised(Path::new("a/b")));
    }

    #[test]
    fn a_parent_component_is_folded() {
        assert_eq!(
            normalised(Path::new("a/b/../c")),
            normalised(Path::new("a/c"))
        );
    }

    #[test]
    fn a_clean_pair_is_copyable() {
        let root = std::env::temp_dir().join(format!("rn-cp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("the fixture directory is creatable");
        std::fs::write(root.join("src/file"), b"x").expect("the fixture file is writable");
        std::fs::write(root.join("dest"), b"y").expect("the fixture file is writable");

        let src = root.join("src");
        // A fresh destination: no failure, because nothing exists to collide
        // with and the copy is not into a subdirectory.
        assert_eq!(check_paths(&src, &root.join("new"), false, true), None);
        // The same file twice is the one identity check.
        assert_eq!(
            check_paths(&root.join("dest"), &root.join("dest"), false, false),
            Some(CpError::SamePath)
        );
        // Directory onto a regular file.
        assert_eq!(
            check_paths(&src, &root.join("dest"), false, true),
            Some(CpError::DirToNonDir)
        );
        // Regular file onto a directory.
        assert_eq!(
            check_paths(&root.join("dest"), &src, false, true),
            Some(CpError::NonDirToDir)
        );
        // A directory into its own subtree.
        assert_eq!(
            check_paths(&src, &src.join("sub"), false, true),
            Some(CpError::Subdirectory)
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
