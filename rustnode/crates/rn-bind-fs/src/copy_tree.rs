//! The recursive directory copy behind `fs.cpSync` and `fs.promises.cp`.
//!
//! `src/node_file.cc` implements this once, as `CopyDirRecursive`, and both
//! `cpSyncCopyDir` (synchronous) and `CpDirJob` (a threadpool job) call it. The
//! JavaScript in `lib/internal/fs/cp/` only walks the tree itself when a
//! `filter` has to run per entry, so this is the path every plain
//! `fs.cpSync(src, dest, { recursive: true })` takes — and the one that was
//! missing entirely while `cpSyncCopyDir`, `cpSyncOverrideFile` and `CpDirJob`
//! were declared deferred.
//!
//! # Two modes, not one
//!
//! [`CpOptions::fresh_destination`] is the difference between the two callers,
//! and it is a semantic difference rather than an optimisation:
//!
//! * `fs.cpSync` *merges* into an existing destination. It creates the
//!   destination with `mkdir -p` semantics, and whether an entry that already
//!   exists is replaced, skipped or reported depends on `force` and
//!   `errorOnExist`. Relative link targets are canonicalized.
//! * `fs.cp` only reaches this path for a destination that does not exist. It
//!   creates every directory with a bare `mkdir()` and every file with an
//!   exclusive copy, so anything already present — a symlink included — is
//!   `EEXIST`. Relative link targets are resolved lexically.
//!
//! # Why this is a transliteration
//!
//! The observable behaviour here *is* a filesystem, and the specification is
//! that filesystem: the resulting entries, their modes, their link targets, and
//! which of them a failure names. Reproducing the C++ branch order is what keeps
//! all four identical. A tidier implementation that "obviously" does the same
//! thing diverges on exactly the cases that are hard to reason about — a link
//! whose target is inside the destination, a directory that already exists under
//! an existing link, a read-only source file that still has to be stamped.
//!
//! Nothing here touches V8: it takes paths and options and returns a plain
//! error value, so the walk is testable without an isolate.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// `UV_FS_COPYFILE_EXCL`: refuse a destination that already exists.
const COPYFILE_EXCL: i32 = 0x01;

/// `CpDirOptions` from `src/node_file.cc`.
#[derive(Debug, Clone, Copy)]
pub struct CpOptions {
    pub force: bool,
    pub dereference: bool,
    pub error_on_exist: bool,
    pub verbatim_symlinks: bool,
    pub preserve_timestamps: bool,
    /// Set by `fs.cp()`, which only takes this path for a destination that did
    /// not exist. See the module docs.
    pub fresh_destination: bool,
    /// `fs.copyFile()`'s mode flags, used only for a fresh destination.
    pub copyfile_flags: i32,
}

impl CpOptions {
    /// The options `fs.cpSync`'s `cpSyncCopyDir` passes.
    #[must_use]
    pub fn for_sync(
        force: bool,
        dereference: bool,
        error_on_exist: bool,
        verbatim_symlinks: bool,
        preserve_timestamps: bool,
    ) -> Self {
        Self {
            force,
            dereference,
            error_on_exist,
            verbatim_symlinks,
            preserve_timestamps,
            fresh_destination: false,
            copyfile_flags: 0,
        }
    }

    /// The options `fs.cp`'s `CpDirJob` passes.
    #[must_use]
    pub fn for_fresh(
        force: bool,
        dereference: bool,
        error_on_exist: bool,
        verbatim_symlinks: bool,
        preserve_timestamps: bool,
        copyfile_flags: i32,
    ) -> Self {
        Self {
            force,
            dereference,
            error_on_exist,
            verbatim_symlinks,
            preserve_timestamps,
            fresh_destination: true,
            copyfile_flags,
        }
    }
}

/// One failure, already classified the way `CpError` classifies it.
///
/// The variants are not interchangeable. `Errno` becomes an `ErrnoException`
/// (message `CODE, strerror 'path'`, no syscall in the text), `Uv` becomes a
/// `UVException` (message `CODE: uv_strerror, syscall 'path'`), and `Einval`,
/// `SymlinkToSubdirectory` and `Eexist` become `ERR_FS_CP_*` objects whose
/// message is already formatted. A caller sees all of that, so all of it is
/// kept rather than collapsed into one errno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyError {
    /// `CpError::Std`: a `std::filesystem` failure.
    Errno {
        errno: i32,
        syscall: &'static str,
        path: Vec<u8>,
    },
    /// `CpError::Uv`: a `uv_fs_*` failure.
    Uv {
        errno: i32,
        syscall: &'static str,
        path: Vec<u8>,
    },
    /// `CpError::kEinval`.
    Einval(String),
    /// `CpError::kSymlinkToSubdirectory`.
    SymlinkToSubdirectory(String),
    /// `CpError::kEexist`, message including its `[CODE]` prefix.
    Eexist(String),
    /// `ERR_FS_EISDIR` from `CpSyncCheckPaths`: a directory source without
    /// `recursive`, message already formatted.
    Eisdir(String),
    /// `CpError::kSocket`/`kFifo`/`kUnknown`: reported by kind and path so the
    /// JavaScript layer can build the error with the wording it owns.
    Special { kind: &'static str, path: Vec<u8> },
}

fn bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn from_bytes(path: &[u8]) -> PathBuf {
    PathBuf::from(std::ffi::OsStr::from_bytes(path))
}

/// The errno a failed `std::io` call reported.
fn io_errno(error: &std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EIO)
}

/// The errno from the last failing libc call on this thread.
fn last_errno() -> i32 {
    // SAFETY: `errno` is only meaningful immediately after a failing libc call
    // on the same thread, which is exactly where this is called.
    unsafe { *libc::__errno_location() }
}

fn c_path(path: &Path) -> Result<std::ffi::CString, ()> {
    std::ffi::CString::new(bytes(path)).map_err(|_| ())
}

// ---------------------------------------------------------------------------
// The filesystem primitives the walk is built from
// ---------------------------------------------------------------------------

/// `std::filesystem::permissions(path, perms)`: set the mode bits exactly.
fn set_permissions(path: &Path, mode: u32) -> Result<(), CopyError> {
    let c_path = c_path(path).map_err(|()| CopyError::errno(libc::EINVAL, "cp", path))?;
    // SAFETY: `c_path` is NUL-terminated and the call only reads it.
    if unsafe { libc::chmod(c_path.as_ptr(), mode & 0o7777) } != 0 {
        return Err(CopyError::errno(last_errno(), "cp", path));
    }
    Ok(())
}

/// `std::filesystem::create_directories`, which is `mkdir -p`.
fn create_directories(path: &Path, display: &Path) -> Result<(), CopyError> {
    std::fs::create_dir_all(path).map_err(|error| CopyError::errno(io_errno(&error), "cp", display))
}

/// `uv_fs_mkdir(path, 0777)`: one level only, and never over anything present.
fn make_fresh_directory(path: &Path) -> Result<(), CopyError> {
    let c_path = c_path(path).map_err(|()| CopyError::uv(libc::EINVAL, "mkdir", &bytes(path)))?;
    // SAFETY: `c_path` is NUL-terminated and the call only reads it.
    if unsafe { libc::mkdir(c_path.as_ptr(), 0o777) } != 0 {
        return Err(CopyError::uv(last_errno(), "mkdir", &bytes(path)));
    }
    Ok(())
}

/// `uv_fs_copyfile`, with the flags the caller asked for.
fn uv_copy_file(source: &Path, destination: &Path, flags: i32) -> Result<(), CopyError> {
    crate::fsops::uv_copy_file(
        source.as_os_str().as_bytes(),
        destination.as_os_str().as_bytes(),
        flags,
    )
    .map_err(|error| CopyError::uv(error.raw_errno(), "copyfile", &bytes(destination)))
}

/// `s->st_atim.tv_sec + s->st_atim.tv_nsec / 1e9` from `CopyUtimes`.
fn seconds_as_double(seconds: i64, nanos: i64) -> f64 {
    seconds as f64 + nanos as f64 / 1e9
}

/// libuv's `uv__fs_to_timespec`, including its handling of a negative fraction.
fn timespec_from_double(time: f64) -> libc::timespec {
    if time.is_infinite() {
        return libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        };
    }
    if time.is_nan() {
        return libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        };
    }
    // C truncates toward zero when assigning a double to an integer and Rust's
    // `as` does the same, so the two agree on pre-epoch times as well.
    let mut seconds = time as libc::time_t;
    let mut nanos = ((time - seconds as f64) * 1e9) as libc::c_long;
    if nanos < 0 {
        nanos += 1_000_000_000;
        seconds -= 1;
    }
    libc::timespec {
        tv_sec: seconds,
        tv_nsec: nanos,
    }
}

/// `CopyUtimes`: stamp `dest` with `src`'s current access and modification times.
///
/// The double round trip is deliberate rather than an accident of the C++
/// signature. `CopyUtimes` reads `uv_stat_t`'s integer times, converts them to
/// `double` seconds, and hands those to `uv_fs_utime`, which converts back with
/// [`timespec_from_double`]. Reproducing both halves means the destination ends
/// up with the same nanosecond field the oracle's destination does, rather than
/// a more precise one.
fn copy_utimes(source: &Path, destination: &Path) -> Result<(), CopyError> {
    let metadata = std::fs::metadata(source)
        .map_err(|error| CopyError::uv(io_errno(&error), "stat", &bytes(source)))?;
    let atime = seconds_as_double(metadata.atime(), metadata.atime_nsec());
    let mtime = seconds_as_double(metadata.mtime(), metadata.mtime_nsec());
    let times = [timespec_from_double(atime), timespec_from_double(mtime)];
    let c_path = c_path(destination)
        .map_err(|()| CopyError::uv(libc::EINVAL, "utime", &bytes(destination)))?;
    // SAFETY: `c_path` is NUL-terminated and `times` is a two-element array of
    // correctly typed `timespec` values that the call reads.
    if unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) } != 0 {
        return Err(CopyError::uv(last_errno(), "utime", &bytes(destination)));
    }
    Ok(())
}

/// `normalizePathToArray`: the absolute path split into whole components.
fn normalize_path_to_array(path: &Path) -> Vec<Vec<u8>> {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    absolute
        .components()
        .map(|component| component.as_os_str().as_bytes().to_vec())
        .filter(|part| !part.is_empty())
        .collect()
}

/// `isInsideDir`: whether `dest` is `src` or sits underneath it.
///
/// Whole components, so `/a/b` does not contain `/a/bc` — the mistake a string
/// prefix test makes.
fn is_inside_dir(src: &Path, dest: &Path) -> bool {
    let src_parts = normalize_path_to_array(src);
    let dest_parts = normalize_path_to_array(dest);
    src_parts.len() <= dest_parts.len()
        && src_parts
            .iter()
            .zip(dest_parts.iter())
            .all(|(left, right)| left == right)
}

/// `std::filesystem::path::lexically_normal`, for the lexical link resolution
/// `fs.cp` uses on a fresh destination.
fn lexical_normal(path: PathBuf) -> PathBuf {
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
    out
}

/// A resolved link target, matching `weakly_canonical(abs(src / target))`.
fn resolved_target(src: &Path, target: &Path, fresh: bool) -> PathBuf {
    let joined = src.join(target);
    if fresh {
        // As `path.resolve()` does: lexical only, absolute targets verbatim.
        if target.is_absolute() {
            target.to_path_buf()
        } else {
            lexical_normal(joined)
        }
    } else {
        std::fs::canonicalize(&joined).unwrap_or_else(|_| lexical_normal(joined))
    }
}

/// The `kSocket`/`kFifo`/`kUnknown` classification `CopyDirRecursive` uses.
fn special_kind(mode: u32) -> &'static str {
    match mode & libc::S_IFMT {
        libc::S_IFSOCK => "socket",
        libc::S_IFIFO => "fifo",
        _ => "unknown",
    }
}

/// The `ERR_FS_CP_EEXIST` text the C++ formats, prefix included.
fn eexist_message(path: &Path) -> String {
    format!(
        "[ERR_FS_CP_EEXIST]: Target already exists: cp returned EEXIST ({} already exists)",
        path.display()
    )
}

// ---------------------------------------------------------------------------
// The recursive walk
// ---------------------------------------------------------------------------

/// `CopyDirRecursive`: copies `src`'s tree to `dest`, creating `dest` itself.
///
/// `dest_display` is the text a failure on `dest` itself reports, which is
/// `dest.ToString()` in the C++ — the JS string form of the buffer as the caller
/// spelled it, not a re-rendering of the resolved path.
pub fn copy_dir_recursive(
    src: &[u8],
    dest: &[u8],
    dest_display: &str,
    options: CpOptions,
) -> Result<(), CopyError> {
    let src_path = from_bytes(src);
    let dest_path = from_bytes(dest);
    let dest_display_path = from_bytes(dest_display.as_bytes());

    let mut dest_existed = false;
    if options.fresh_destination {
        make_fresh_directory(&dest_path)?;
    } else {
        dest_existed = dest_path.exists();
        create_directories(&dest_path, &dest_display_path)?;
    }

    copy_dir_contents(&src_path, &dest_path, &options)?;

    if !dest_existed {
        let permissions = std::fs::metadata(&src_path)
            .map_err(|error| CopyError::errno(io_errno(&error), "cp", &dest_display_path))?
            .permissions();
        set_permissions(&dest_path, permissions.mode())?;
    }
    if options.preserve_timestamps {
        copy_utimes(&src_path, &dest_path)?;
    }
    Ok(())
}

/// The recursive half: one directory's entries, then each subdirectory's.
fn copy_dir_contents(src: &Path, dest: &Path, options: &CpOptions) -> Result<(), CopyError> {
    let listing =
        std::fs::read_dir(src).map_err(|error| CopyError::errno(io_errno(&error), "cp", src))?;
    let dest_str = bytes(dest);

    // `std::filesystem::directory_iterator` yields `readdir` order, which is the
    // order this walk creates entries in. It is left alone rather than sorted:
    // the order decides which of two colliding entries an `EEXIST` names.
    for entry in listing {
        let entry = entry.map_err(|error| CopyError::errno(io_errno(&error), "cp", src))?;
        let entry_path = entry.path();
        let dest_path = dest.join(entry.file_name());

        let link_metadata = std::fs::symlink_metadata(&entry_path)
            .map_err(|error| CopyError::errno(io_errno(&error), "cp", &from_bytes(&dest_str)))?;
        let is_symlink = link_metadata.file_type().is_symlink();

        // With `dereference`, a link that resolves to a directory or a regular
        // file falls through to the branches below, which follow it. A link
        // whose target cannot be reached has nothing to copy, and `stat` is what
        // reports why: `std::filesystem::status` folds ENOTDIR into not_found,
        // so the C++ uses `stat` here and so does this.
        let followed =
            if is_symlink && options.dereference {
                Some(std::fs::metadata(&entry_path).map_err(|error| {
                    CopyError::uv(io_errno(&error), "stat", &bytes(&entry_path))
                })?)
            } else {
                None
            };

        if is_symlink && !options.dereference {
            copy_symlink(&entry_path, &dest_path, src, dest, options)?;
        } else if followed.as_ref().is_some_and(|meta| meta.is_dir())
            || (!is_symlink && std::fs::metadata(&entry_path).is_ok_and(|meta| meta.is_dir()))
        {
            copy_entry_directory(&entry_path, &dest_path, is_symlink, options)?;
        } else if followed.as_ref().is_some_and(|meta| meta.is_file())
            || (!is_symlink && std::fs::metadata(&entry_path).is_ok_and(|meta| meta.is_file()))
        {
            copy_entry_file(&entry_path, &dest_path, is_symlink, &dest_str, options)?;
        } else if options.fresh_destination {
            // A merge ignores sockets, FIFOs and unknown entries the way the
            // JavaScript walk does; only the threadpool job reports them.
            return Err(CopyError::Special {
                kind: special_kind(link_metadata.mode()),
                path: bytes(&dest_path),
            });
        } else if is_symlink && options.dereference {
            // Dereferencing a link to a FIFO still reaches a special file, and
            // the C++ reports it through the same branch as the fresh case.
            return Err(CopyError::Special {
                kind: special_kind(std::fs::metadata(&entry_path).map_or(0, |meta| meta.mode())),
                path: bytes(&dest_path),
            });
        }
    }
    Ok(())
}

/// A symbolic link: copied verbatim, or resolved to an absolute target.
///
/// `src` is the *source* directory being walked, which is what a relative target
/// is resolved against — so a link pointing at a sibling is copied pointing at
/// the original sibling in the source tree, not at its copy. That is what the
/// oracle does, and it is why `fs.cpSync` of a tree of links yields absolute
/// targets into the source.
fn copy_symlink(
    entry_path: &Path,
    dest_path: &Path,
    src: &Path,
    dest: &Path,
    options: &CpOptions,
) -> Result<(), CopyError> {
    let dest_err = |error: std::io::Error| CopyError::errno(io_errno(&error), "cp", dest);
    let target = std::fs::read_link(entry_path).map_err(dest_err)?;

    if options.verbatim_symlinks {
        return std::os::unix::fs::symlink(&target, dest_path).map_err(dest_err);
    }

    if let Ok(dest_meta) = std::fs::symlink_metadata(dest_path) {
        if dest_meta.file_type().is_symlink() {
            let current_target = std::fs::read_link(dest_path).map_err(dest_err)?;
            let source_target_is_dir =
                std::fs::metadata(entry_path).is_ok_and(|meta| meta.is_dir());
            if source_target_is_dir && is_inside_dir(&target, &current_target) {
                return Err(CopyError::Einval(format!(
                    "Cannot copy {} to a subdirectory of self {}",
                    target.display(),
                    current_target.display()
                )));
            }
            // Refusing this one is what keeps an existing destination link from
            // being unlinked out from under the source.
            if std::fs::metadata(dest_path).is_ok_and(|meta| meta.is_dir())
                && is_inside_dir(&current_target, &target)
            {
                return Err(CopyError::SymlinkToSubdirectory(format!(
                    "cannot overwrite {} with {}",
                    current_target.display(),
                    target.display()
                )));
            }
            // A symlink is replaced by `cp` even when `force` is false. The C++
            // keeps that for backward compatibility and asks the same question
            // in a comment.
            std::fs::remove_file(dest_path).map_err(dest_err)?;
        } else if dest_meta.is_file()
            && (!options.dereference || (!options.force && options.error_on_exist))
        {
            return Err(CopyError::errno(libc::EEXIST, "cp", dest_path));
        }
    }

    let absolute = resolved_target(src, &target, options.fresh_destination);
    std::os::unix::fs::symlink(&absolute, dest_path).map_err(dest_err)
}

/// A directory entry: created if needed, filled in, then given its mode.
fn copy_entry_directory(
    entry_path: &Path,
    dest_path: &Path,
    is_symlink: bool,
    options: &CpOptions,
) -> Result<(), CopyError> {
    let created = if options.fresh_destination {
        make_fresh_directory(dest_path)?;
        true
    } else if is_symlink {
        // Mirror the JavaScript walk: create the destination only when it does
        // not exist, and otherwise recurse into the existing path.
        if std::fs::symlink_metadata(dest_path).is_err() {
            std::fs::create_dir(dest_path)
                .map_err(|error| CopyError::errno(io_errno(&error), "cp", dest_path))?;
            true
        } else {
            false
        }
    } else {
        // `std::filesystem::create_directory` reports `false` rather than an
        // error when the path is already a directory.
        match std::fs::create_dir(dest_path) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(CopyError::errno(io_errno(&error), "cp", dest_path)),
        }
    };

    copy_dir_contents(entry_path, dest_path, options)?;

    if created {
        // Applied once the contents are in, because a read-only source
        // directory would otherwise refuse its own children.
        let permissions = std::fs::metadata(entry_path)
            .map_err(|error| CopyError::errno(io_errno(&error), "cp", dest_path))?
            .permissions();
        set_permissions(dest_path, permissions.mode())?;
    }
    if options.preserve_timestamps {
        copy_utimes(entry_path, dest_path)?;
    }
    Ok(())
}

/// A regular file, copied according to the overwrite rule.
fn copy_entry_file(
    entry_path: &Path,
    dest_path: &Path,
    is_symlink: bool,
    dest_str: &[u8],
    options: &CpOptions,
) -> Result<(), CopyError> {
    if is_symlink && !options.fresh_destination {
        // Only a dereferenced link reaches this branch as a link, so an occupied
        // destination is settled the way the JavaScript walk settles it:
        // replaced under `force`, left untouched otherwise.
        if std::fs::symlink_metadata(dest_path).is_ok() {
            if !options.force {
                if options.error_on_exist {
                    return Err(CopyError::Eexist(eexist_message(dest_path)));
                }
                return Ok(());
            }
            std::fs::remove_file(dest_path)
                .map_err(|error| CopyError::errno(io_errno(&error), "cp", dest_path))?;
        }
    }

    let copied = if options.fresh_destination {
        uv_copy_file(
            entry_path,
            dest_path,
            options.copyfile_flags | COPYFILE_EXCL,
        )?;
        true
    } else if std::fs::symlink_metadata(dest_path).is_ok() {
        if options.force {
            // The C++ asks `std::filesystem::copy_file` to overwrite, which
            // truncates. It reports a destination failure against `dest_str`,
            // the directory being filled in, not the file.
            crate::fsops::copy_file(
                entry_path.as_os_str().as_bytes(),
                dest_path.as_os_str().as_bytes(),
                0,
            )
            .map_err(|error| CopyError::errno(error.raw_errno(), "cp", &from_bytes(dest_str)))?;
            true
        } else if options.error_on_exist {
            return Err(CopyError::Eexist(eexist_message(dest_path)));
        } else {
            false
        }
    } else {
        // `std::filesystem::copy_file` with `overwrite_existing`, which is the
        // synchronous walk's primitive: it stamps nothing, so the destination's
        // times stay at the wall clock. `fs.copyFile` and `fs.cp` go through
        // `uv_copy_file` instead and carry the source's `atime`.
        //
        // A destination failure is reported against `dest_str`, the directory
        // being filled in, not the file.
        crate::fsops::copy_file(
            entry_path.as_os_str().as_bytes(),
            dest_path.as_os_str().as_bytes(),
            0,
        )
        .map_err(|error| CopyError::errno(error.raw_errno(), "cp", &from_bytes(dest_str)))?;
        true
    };

    if copied {
        if options.preserve_timestamps {
            copy_utimes(entry_path, dest_path)?;
        }
        // Both copies set the mode before writing the data, which clears
        // setuid/setgid; put the source mode back once the data is in.
        let permissions = std::fs::metadata(entry_path)
            .map_err(|error| CopyError::errno(io_errno(&error), "cp", dest_path))?
            .permissions();
        set_permissions(dest_path, permissions.mode())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The two entry points that are not the plain walk
// ---------------------------------------------------------------------------

/// `CpSyncOverrideFile`: replace `dest` with `src`, then apply `src`'s mode.
///
/// `lib/internal/fs/cp/cp-sync.js`'s `onFile` calls this when the destination
/// already exists and `force` is on. It unlinks first, so an existing
/// destination link is replaced rather than written through.
pub fn override_file(
    src: &[u8],
    dest: &[u8],
    mode: i32,
    preserve_timestamps: bool,
) -> Result<(), CopyError> {
    let src_path = from_bytes(src);
    let dest_path = from_bytes(dest);

    // `std::filesystem::remove` succeeds for a missing path as well, and the C++
    // only reports an error when one is set.
    match std::fs::remove_file(&dest_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(CopyError::errno(io_errno(&error), "unlink", &dest_path)),
    }

    if mode == 0 {
        // No mode means the faster `std::filesystem` copy, which truncates and
        // stamps nothing. This is the branch `fs.cpSync` takes for an existing
        // file destination, and the oracle's destination keeps a wall-clock
        // `atime` because of it.
        crate::fsops::copy_file(src, dest, 0).map_err(|error| CopyError::Errno {
            errno: error.raw_errno(),
            syscall: "cp",
            path: bytes(&dest_path),
        })?;
    } else {
        // A real mode means `uv_fs_copyfile`, which carries the source's times.
        crate::fsops::uv_copy_file(src, dest, mode).map_err(|error| CopyError::Uv {
            errno: error.raw_errno(),
            syscall: "cp",
            path: dest.to_vec(),
        })?;
    }

    // Both copy routines carry the source's permissions across, and `fs.cpSync`
    // depends on it: an overwrite of an existing file with a `0o604` source
    // leaves the destination `0o604`, where a bare create would leave whatever
    // the destination already had. The C++ gets this from
    // `std::filesystem::copy_file` and from `uv_fs_copyfile`, so it is stated
    // here rather than assumed of the copy above.
    let source_mode = std::fs::metadata(&src_path)
        .map_err(|error| CopyError::Errno {
            errno: io_errno(&error),
            syscall: "cp",
            path: bytes(&src_path),
        })?
        .permissions()
        .mode();
    set_permissions(&dest_path, source_mode)?;

    if preserve_timestamps {
        copy_utimes(&src_path, &dest_path)?;
    }
    Ok(())
}

/// The two checks `CpSyncCheckPaths` makes after the four identity questions.
///
/// `crate::cp::check_paths` answers "same file", "directory onto a
/// non-directory", "non-directory onto a directory" and "into its own subtree".
/// The C++ then refuses a directory when `recursive` is off and refuses special
/// files outright, and both are reachable from `fs.cpSync` today: without them a
/// non-recursive directory copy surfaced as
/// `ERR_INTERNAL_ASSERTION: Unreachable code` from `cp-sync.js`'s own
/// `assert.fail`, which is a bug report about Node rather than about the caller's
/// arguments.
pub fn check_tail(
    src: &[u8],
    dest: &[u8],
    dereference: bool,
    recursive: bool,
) -> Result<(), CopyError> {
    let src_path = from_bytes(src);

    let src_meta = if dereference {
        std::fs::metadata(&src_path)
    } else {
        std::fs::symlink_metadata(&src_path)
    }
    .map_err(|error| CopyError::Uv {
        errno: io_errno(&error),
        syscall: if dereference { "stat" } else { "lstat" },
        path: src.to_vec(),
    })?;

    let src_is_dir = src_meta.is_dir() || (dereference && src_meta.file_type().is_symlink());

    // `src` keeps the trailing separator in both the comparison and the message,
    // which is why the C++ appends it to the same string it prints.
    let mut src_text = src_path.to_string_lossy().into_owned();
    if !src_text.ends_with(std::path::MAIN_SEPARATOR) {
        src_text.push(std::path::MAIN_SEPARATOR);
    }

    if src_is_dir && !recursive {
        return Err(CopyError::Eisdir(format!(
            "Recursive option not enabled, cannot copy a directory: {src_text}"
        )));
    }

    match src_meta.mode() & libc::S_IFMT {
        libc::S_IFSOCK => {
            return Err(CopyError::Special {
                kind: "socket",
                path: dest.to_vec(),
            });
        }
        libc::S_IFIFO => {
            return Err(CopyError::Special {
                kind: "fifo",
                path: dest.to_vec(),
            });
        }
        libc::S_IFREG | libc::S_IFDIR | libc::S_IFLNK => {}
        _ => {
            return Err(CopyError::Special {
                kind: "unknown",
                path: dest.to_vec(),
            });
        }
    }
    Ok(())
}

impl CopyError {
    fn errno(errno: i32, syscall: &'static str, path: &Path) -> Self {
        Self::Errno {
            errno,
            syscall,
            path: bytes(path),
        }
    }

    fn uv(errno: i32, syscall: &'static str, path: &[u8]) -> Self {
        Self::Uv {
            errno,
            syscall,
            path: path.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rn-copy-tree-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("mkdir");
        path
    }

    /// A tree as sorted `path:content` / `path/` / `path->target` lines.
    fn tree_of(root: &Path) -> Vec<String> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .expect("read_dir")
                .map(|entry| entry.expect("entry").path())
                .collect();
            entries.sort();
            for path in entries {
                let relative = path.strip_prefix(root).expect("under root");
                let meta = std::fs::symlink_metadata(&path).expect("lstat");
                if meta.file_type().is_symlink() {
                    let target = std::fs::read_link(&path).expect("readlink");
                    out.push(format!("{}->{}", relative.display(), target.display()));
                } else if meta.is_dir() {
                    out.push(format!("{}/", relative.display()));
                    walk(root, &path, out);
                } else {
                    out.push(format!(
                        "{}:{}",
                        relative.display(),
                        std::fs::read_to_string(&path).unwrap_or_default()
                    ));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out
    }

    fn sync_options() -> CpOptions {
        CpOptions::for_sync(true, false, false, false, false)
    }

    fn copy(src: &Path, dest: &Path, options: CpOptions) -> Result<(), CopyError> {
        copy_dir_recursive(
            src.as_os_str().as_bytes(),
            dest.as_os_str().as_bytes(),
            &dest.to_string_lossy(),
            options,
        )
    }

    fn stamp(path: &Path, atime: i64, mtime: i64) {
        let times = [
            libc::timespec {
                tv_sec: atime,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: mtime,
                tv_nsec: 0,
            },
        ];
        let c_path = c_path(path).expect("path");
        // SAFETY: `c_path` is NUL-terminated and `times` is a valid pair.
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) },
            0
        );
    }

    fn mkfifo(path: &Path) {
        let c_path = c_path(path).expect("path");
        // SAFETY: `c_path` is NUL-terminated and the call only reads it.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
    }

    #[test]
    fn a_tree_is_copied_with_its_contents_and_modes() {
        let root = scratch("basic");
        let src = root.join("src");
        std::fs::create_dir_all(src.join("a/b")).expect("mkdir");
        std::fs::write(src.join("f1"), b"one").expect("write");
        std::fs::write(src.join("a/f2"), b"two").expect("write");
        std::fs::write(src.join("a/b/f3"), b"three").expect("write");
        set_permissions(&src.join("a/b/f3"), 0o640).expect("chmod");
        set_permissions(&src.join("a"), 0o751).expect("chmod");

        copy(&src, &root.join("dest"), sync_options()).expect("copy");

        assert_eq!(
            tree_of(&root.join("dest")),
            vec!["a/", "a/b/", "a/b/f3:three", "a/f2:two", "f1:one"]
        );
        for (relative, mode) in [("a/b/f3", 0o640), ("a", 0o751)] {
            assert_eq!(
                std::fs::metadata(root.join("dest").join(relative))
                    .expect("stat")
                    .mode()
                    & 0o777,
                mode,
                "{relative} must keep its source mode"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn preserve_timestamps_stamps_nested_directories_and_files() {
        let root = scratch("times");
        let src = root.join("src");
        std::fs::create_dir_all(src.join("sub")).expect("mkdir");
        std::fs::write(src.join("sub/f"), b"x").expect("write");
        std::fs::write(src.join("g"), b"y").expect("write");
        stamp(&src.join("sub/f"), 1111, 2222);
        stamp(&src.join("g"), 3333, 4444);
        stamp(&src.join("sub"), 5555, 6666);

        let mut options = sync_options();
        options.preserve_timestamps = true;
        copy(&src, &root.join("dest"), options).expect("copy");

        for (relative, mtime) in [("g", 4444), ("sub/f", 2222), ("sub", 6666)] {
            assert_eq!(
                std::fs::metadata(root.join("dest").join(relative))
                    .expect("stat")
                    .mtime(),
                mtime,
                "{relative} must keep the source's modification time"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_fresh_destination_refuses_anything_already_present() {
        let root = scratch("fresh");
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(src.join("f"), b"new").expect("write");
        std::fs::write(root.join("dest"), b"old").expect("write");

        let error = copy(
            &src,
            &root.join("dest"),
            CpOptions::for_fresh(true, false, false, false, false, 0),
        )
        .expect_err("a fresh destination may not already exist");
        assert!(
            matches!(
                error,
                CopyError::Uv {
                    syscall: "mkdir",
                    ..
                }
            ),
            "{error:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_overwrite_rule_decides_a_clash_inside_an_existing_tree() {
        let root = scratch("merge");
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(src.join("f"), b"new").expect("write");

        for (force, error_on_exist, expected) in [
            (true, false, "new"),
            (false, false, "old"),
            (true, true, "new"),
        ] {
            let dest = root.join(format!("dest-{force}-{error_on_exist}"));
            std::fs::create_dir_all(&dest).expect("mkdir");
            std::fs::write(dest.join("f"), b"old").expect("write");
            let options = CpOptions::for_sync(force, false, error_on_exist, false, false);
            copy(&src, &dest, options).expect("copy");
            assert_eq!(
                std::fs::read_to_string(dest.join("f")).expect("read"),
                expected,
                "force={force} errorOnExist={error_on_exist}"
            );
        }

        let dest = root.join("dest-eexist");
        std::fs::create_dir_all(&dest).expect("mkdir");
        std::fs::write(dest.join("f"), b"old").expect("write");
        let error = copy(
            &src,
            &dest,
            CpOptions::for_sync(false, false, true, false, false),
        )
        .expect_err("errorOnExist refuses the clash");
        assert!(matches!(error, CopyError::Eexist(_)), "{error:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlink_is_copied_verbatim_or_canonicalized() {
        let root = scratch("links");
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(src.join("real"), b"R").expect("write");
        std::os::unix::fs::symlink("real", src.join("lnk")).expect("symlink");

        copy(
            &src,
            &root.join("verbatim"),
            CpOptions::for_sync(true, false, false, true, false),
        )
        .expect("copy");
        assert_eq!(
            std::fs::read_link(root.join("verbatim/lnk")).expect("readlink"),
            PathBuf::from("real")
        );

        copy(&src, &root.join("resolved"), sync_options()).expect("copy");
        assert_eq!(
            std::fs::read_link(root.join("resolved/lnk")).expect("readlink"),
            src.join("real")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dereference_replaces_the_link_with_its_target() {
        let root = scratch("deref");
        let src = root.join("src");
        std::fs::create_dir_all(src.join("realdir")).expect("mkdir");
        std::fs::write(src.join("real"), b"R").expect("write");
        std::fs::write(src.join("realdir/inner"), b"I").expect("write");
        std::os::unix::fs::symlink("real", src.join("lnk")).expect("symlink");
        std::os::unix::fs::symlink("realdir", src.join("lnkdir")).expect("symlink");

        copy(
            &src,
            &root.join("dest"),
            CpOptions::for_sync(true, true, false, false, false),
        )
        .expect("copy");

        assert_eq!(
            tree_of(&root.join("dest")),
            vec![
                "lnk:R",
                "lnkdir/",
                "lnkdir/inner:I",
                "real:R",
                "realdir/",
                "realdir/inner:I"
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_fifo_inside_the_tree_is_ignored_by_a_merge_and_reported_by_a_fresh_copy() {
        let root = scratch("fifo");
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(src.join("ok"), b"x").expect("write");
        mkfifo(&src.join("p"));

        copy(&src, &root.join("merged"), sync_options()).expect("a merge skips the FIFO");
        assert_eq!(
            std::fs::read_dir(root.join("merged"))
                .expect("read_dir")
                .count(),
            1
        );

        let error = copy(
            &src,
            &root.join("fresh"),
            CpOptions::for_fresh(true, false, false, false, false, 0),
        )
        .expect_err("a fresh copy reports the FIFO");
        assert!(
            matches!(error, CopyError::Special { kind: "fifo", .. }),
            "{error:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn override_file_replaces_the_destination_and_can_stamp_it() {
        let root = scratch("override");
        std::fs::write(root.join("src"), b"NEW").expect("write");
        std::fs::write(root.join("dest"), b"OLD").expect("write");
        set_permissions(&root.join("src"), 0o604).expect("chmod");
        stamp(&root.join("src"), 7000, 8000);

        override_file(
            root.join("src").as_os_str().as_bytes(),
            root.join("dest").as_os_str().as_bytes(),
            0,
            true,
        )
        .expect("override");

        assert_eq!(
            std::fs::read_to_string(root.join("dest")).expect("read"),
            "NEW"
        );
        assert_eq!(
            std::fs::metadata(root.join("dest")).expect("stat").mtime(),
            8000
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn override_file_still_works_when_the_destination_is_missing() {
        // `std::filesystem::remove` reports "false, no error" for a missing
        // path, and the C++ only treats a set error code as a failure.
        let root = scratch("override-missing");
        std::fs::write(root.join("src"), b"NEW").expect("write");
        override_file(
            root.join("src").as_os_str().as_bytes(),
            root.join("dest").as_os_str().as_bytes(),
            0,
            false,
        )
        .expect("override");
        assert_eq!(
            std::fs::read_to_string(root.join("dest")).expect("read"),
            "NEW"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_double_round_trip_reproduces_libuvs_nanosecond_precision() {
        let timespec = timespec_from_double(seconds_as_double(1_700_000_000, 123_456_789));
        assert_eq!(timespec.tv_sec, 1_700_000_000);
        assert!(timespec.tv_nsec.abs_diff(123_456_789) < 1000);
        // A whole second survives exactly, which is what most fixtures use.
        assert_eq!(timespec_from_double(seconds_as_double(6_000, 0)).tv_nsec, 0);
    }

    #[test]
    fn a_negative_fraction_borrows_from_the_second() {
        let timespec = timespec_from_double(-0.5);
        assert_eq!(timespec.tv_sec, -1);
        assert_eq!(timespec.tv_nsec, 500_000_000);
    }

    #[test]
    fn is_inside_dir_compares_whole_components() {
        assert!(is_inside_dir(Path::new("/a/b"), Path::new("/a/b")));
        assert!(is_inside_dir(Path::new("/a/b"), Path::new("/a/b/c")));
        assert!(!is_inside_dir(Path::new("/a/b"), Path::new("/a/bc")));
        assert!(!is_inside_dir(Path::new("/a/b/c"), Path::new("/a/b")));
    }

    #[test]
    fn the_non_recursive_check_names_the_directory_it_refused() {
        let root = scratch("nonrec");
        std::fs::create_dir_all(root.join("d")).expect("mkdir");
        let error = check_tail(
            root.join("d").as_os_str().as_bytes(),
            root.join("dd").as_os_str().as_bytes(),
            false,
            false,
        )
        .expect_err("a directory without recursive is refused");
        match error {
            CopyError::Eisdir(message) => {
                assert_eq!(
                    message,
                    format!(
                        "Recursive option not enabled, cannot copy a directory: {}/",
                        root.join("d").display()
                    )
                );
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_special_file_check_reports_the_destination() {
        let root = scratch("special");
        mkfifo(&root.join("p"));
        let error = check_tail(
            root.join("p").as_os_str().as_bytes(),
            root.join("pd").as_os_str().as_bytes(),
            false,
            true,
        )
        .expect_err("a FIFO source is refused");
        assert_eq!(
            error,
            CopyError::Special {
                kind: "fifo",
                path: bytes(&root.join("pd")),
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
