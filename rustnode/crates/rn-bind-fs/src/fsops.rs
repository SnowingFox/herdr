//! The filesystem operations themselves.
//!
//! This module is deliberately free of V8: it takes raw bytes, numbers and
//! slices, and returns plain Rust data or an [`FsError`]. Everything about
//! JavaScript argument shapes lives in `install.rs`, and everything about
//! delivering results lives in `request.rs`. Splitting it this way means the
//! syscall behaviour — the part that has to match Node — is testable without an
//! isolate.
//!
//! The syscall names passed to [`FsError`] are the strings that appear in
//! `err.message`, so they are chosen to match `src/node_file.cc` exactly
//! (`scandir` rather than `readdir`, `statfs`, `copyfile`, and so on).

use std::os::unix::ffi::OsStrExt;

use crate::dirent::{read_dir, DirentEntry};
use crate::error::FsError;
use crate::flags;
use crate::stats::{Follow, StatFields};

pub use crate::stats::StatFsFields;

/// Borrowed view of a path coming from JavaScript.
///
/// `fs` accepts `string`, `Buffer` and `URL` paths and the JS layer already
/// normalised them to a string or buffer, so this is either UTF-8 text or raw
/// bytes. Both are kept as bytes because the kernel does not care.
pub type PathBytes = [u8];

fn c_path(path: &[u8], syscall: &'static str) -> Result<std::ffi::CString, FsError> {
    std::ffi::CString::new(path)
        .map_err(|_| FsError::from_errno(syscall, libc::EINVAL).path(path.to_vec()))
}

fn raw_cvt(rc: libc::c_int, syscall: &'static str) -> Result<libc::c_int, FsError> {
    raw_cvt_wide(rc as libc::ssize_t, syscall)
}

/// Same as [`raw_cvt`] but for calls that return `ssize_t` (`read`, `write`,
/// `readlink`), which are 64-bit on Linux and must not be narrowed.
fn raw_cvt_wide(rc: libc::ssize_t, syscall: &'static str) -> Result<libc::c_int, FsError> {
    if rc < 0 {
        // SAFETY: `errno` is only meaningful immediately after a failing libc
        // call on the same thread, which is exactly where this runs.
        let errno = unsafe { *libc::__errno_location() };
        Err(FsError::from_errno(syscall, errno))
    } else {
        Ok(rc as libc::c_int)
    }
}

/// Opens a path and returns the descriptor.
///
/// `flags` is libuv's numeric encoding, not the host's; see `flags.rs`.
pub fn open(path: &PathBytes, uv_open_flags: i32, mode: u32) -> Result<i32, FsError> {
    let host = flags::to_host_flags(uv_open_flags).map_err(|errno| {
        // The failure is about the requested flag set, and `open` is the
        // syscall the caller attempted, so it is named as such.
        FsError::from_errno("open", errno).path(path.to_vec())
    })?;

    // `O_CLOEXEC` is safe and always desirable here; Node sets it too so an
    // `exec` cannot leak descriptors into a child.
    let path_c = c_path(path, "open")?;
    // SAFETY: `path_c` is a valid NUL-terminated string and the remaining
    // arguments are plain integers. The call allocates a descriptor on success
    // which is owned by the returned `i32`.
    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            host | libc::O_CLOEXEC,
            mode as libc::mode_t,
        )
    };
    raw_cvt(fd, "open").map_err(|error| error.path(path.to_vec()))
}

/// Closes a descriptor, reporting `EBADF` for an unopened one.
pub fn close(fd: i32) -> Result<(), FsError> {
    // SAFETY: `close` only acts on the integer descriptor. A failure is
    // reported rather than ignored so `fs.close` behaves like Node's.
    let rc = unsafe { libc::close(fd) };
    raw_cvt(rc, "close").map(|_| ())
}

/// Reads into caller-provided memory. Returns the byte count.
pub fn read(fd: i32, buffer: &mut [u8], position: i64) -> Result<usize, FsError> {
    let length = buffer.len();
    if length == 0 {
        return Ok(0);
    }
    let written = if position < 0 {
        // SAFETY: `buffer` is a valid writable slice of `length` bytes, and the
        // descriptor was validated by the JS layer. `read` writes at most
        // `length` bytes, so the slice stays in bounds.
        unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), length) }
    } else {
        // SAFETY: as above, plus `pread` takes a byte offset and does not
        // change the file position, which is the documented meaning of a
        // non-negative `position` in `fs.read`.
        unsafe {
            libc::pread(
                fd,
                buffer.as_mut_ptr().cast(),
                length,
                position as libc::off_t,
            )
        }
    };
    raw_cvt_wide(written, "read").map(|count| count as usize)
}

/// Writes from caller-provided memory. Returns the byte count.
pub fn write(fd: i32, buffer: &[u8], position: i64) -> Result<usize, FsError> {
    if buffer.is_empty() {
        return Ok(0);
    }
    let written = if position < 0 {
        // SAFETY: `buffer` is a valid readable slice and `write` reads at most
        // its length. The descriptor comes from the JS layer.
        unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) }
    } else {
        // SAFETY: as above; `pwrite` does not move the file offset.
        unsafe {
            libc::pwrite(
                fd,
                buffer.as_ptr().cast(),
                buffer.len(),
                position as libc::off_t,
            )
        }
    };
    raw_cvt_wide(written, "write").map(|count| count as usize)
}

/// Positioned write used by `fs.write` when `position` is `null`.
///
/// Kept separate from [`write`] so the "append to current offset" path is
/// explicit: `pwrite` with `-1` is not portable and `write` is what Node's
/// `uv_fs_write` does for a negative offset.
pub fn write_at_current(fd: i32, buffer: &[u8]) -> Result<usize, FsError> {
    write(fd, buffer, -1)
}

/// Truncates the open descriptor to `length` bytes.
pub fn ftruncate(fd: i32, length: i64) -> Result<(), FsError> {
    // SAFETY: `ftruncate` only reads the descriptor and the new length. A
    // negative length is rejected by the kernel rather than by us.
    let rc = unsafe { libc::ftruncate(fd, length as libc::off_t) };
    raw_cvt(rc, "ftruncate").map(|_| ())
}

/// `fsync(2)`.
pub fn fsync(fd: i32) -> Result<(), FsError> {
    // SAFETY: `fsync` only reads the descriptor.
    let rc = unsafe { libc::fsync(fd) };
    raw_cvt(rc, "fsync").map(|_| ())
}

/// `fdatasync(2)`.
pub fn fdatasync(fd: i32) -> Result<(), FsError> {
    // SAFETY: `fdatasync` only reads the descriptor.
    let rc = unsafe { libc::fdatasync(fd) };
    raw_cvt(rc, "fdatasync").map(|_| ())
}

/// `chmod(2)`.
pub fn chmod(path: &PathBytes, mode: u32) -> Result<(), FsError> {
    let path_c = c_path(path, "chmod")?;
    // SAFETY: `path_c` is NUL-terminated; `mode` is a plain integer.
    let rc = unsafe { libc::chmod(path_c.as_ptr(), mode as libc::mode_t) };
    raw_cvt(rc, "chmod")
        .map(|_| ())
        .map_err(|error| error.path(path.to_vec()))
}

/// `fchmod(2)`.
pub fn fchmod(fd: i32, mode: u32) -> Result<(), FsError> {
    // SAFETY: `fchmod` only reads its integer arguments.
    let rc = unsafe { libc::fchmod(fd, mode as libc::mode_t) };
    raw_cvt(rc, "fchmod").map(|_| ())
}

/// `lchown(2)`: changes ownership of a symlink itself.
///
/// Takes precedence over `chown` on Unix in Node, because `fs.chown` is
/// documented to not follow symlinks there.
pub fn lchown(path: &PathBytes, uid: u32, gid: u32) -> Result<(), FsError> {
    let path_c = c_path(path, "lchown")?;
    // SAFETY: `path_c` is NUL-terminated; `uid` and `gid` are plain integers.
    // `lchown` does not follow a trailing symlink.
    let rc = unsafe { libc::lchown(path_c.as_ptr(), uid, gid) };
    raw_cvt(rc, "lchown")
        .map(|_| ())
        .map_err(|error| error.path(path.to_vec()))
}

/// `chown(2)`, following symlinks.
pub fn chown(path: &PathBytes, uid: u32, gid: u32) -> Result<(), FsError> {
    let path_c = c_path(path, "chown")?;
    // SAFETY: `path_c` is NUL-terminated and both ids are plain integers.
    let rc = unsafe { libc::chown(path_c.as_ptr(), uid, gid) };
    raw_cvt(rc, "chown")
        .map(|_| ())
        .map_err(|error| error.path(path.to_vec()))
}

/// `fchown(2)`.
pub fn fchown(fd: i32, uid: u32, gid: u32) -> Result<(), FsError> {
    // SAFETY: `fchown` only reads its integer arguments.
    let rc = unsafe { libc::fchown(fd, uid, gid) };
    raw_cvt(rc, "fchown").map(|_| ())
}

/// A timestamp pair in `[seconds, nanoseconds]` form.
///
/// Node accepts either two numbers, a `Date`, or `[seconds, nanos]`; the JS
/// layer normalises all of them before calling, so this is the only shape the
/// binding needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSpec {
    pub seconds: i64,
    pub nanos: i64,
}

impl TimeSpec {
    pub fn new(seconds: i64, nanos: i64) -> Self {
        Self { seconds, nanos }
    }

    fn to_libc(self) -> libc::timespec {
        libc::timespec {
            tv_sec: self.seconds as libc::time_t,
            tv_nsec: self.nanos as libc::c_long,
        }
    }
}

/// `utimes(2)`-style update through `utimensat`, which keeps nanosecond
/// precision that `utimes` would truncate.
pub fn utimes(
    path: &PathBytes,
    atime: TimeSpec,
    mtime: TimeSpec,
    follow: bool,
    syscall: &'static str,
) -> Result<(), FsError> {
    let path_c = c_path(path, syscall)?;
    let times = [atime.to_libc(), mtime.to_libc()];
    let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    // SAFETY: `path_c` is NUL-terminated, `times` is a two-element array of
    // correctly typed `timespec` values, and the call reads exactly those.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, path_c.as_ptr(), times.as_ptr(), flags) };
    raw_cvt(rc, syscall)
        .map(|_| ())
        .map_err(|error| error.path(path.to_vec()))
}

/// `futimens(2)`, used by `futimes`.
pub fn futimes(fd: i32, atime: TimeSpec, mtime: TimeSpec) -> Result<(), FsError> {
    let times = [atime.to_libc(), mtime.to_libc()];
    // SAFETY: `times` is a valid two-element array read by the call.
    let rc = unsafe { libc::futimens(fd, times.as_ptr()) };
    raw_cvt(rc, "futimes").map(|_| ())
}

/// `rename(2)`.
pub fn rename(from: &PathBytes, to: &PathBytes) -> Result<(), FsError> {
    let from_c = c_path(from, "rename")?;
    let to_c = c_path(to, "rename")?;
    // SAFETY: both paths are NUL-terminated C strings.
    let rc = unsafe { libc::rename(from_c.as_ptr(), to_c.as_ptr()) };
    raw_cvt(rc, "rename")
        .map(|_| ())
        .map_err(|error| error.path(from.to_vec()).dest(to.to_vec()))
}

/// `rmdir(2)`.
pub fn rmdir(path: &PathBytes) -> Result<(), FsError> {
    let path_c = c_path(path, "rmdir")?;
    // SAFETY: `path_c` is NUL-terminated.
    let rc = unsafe { libc::rmdir(path_c.as_ptr()) };
    raw_cvt(rc, "rmdir")
        .map(|_| ())
        .map_err(|error| error.path(path.to_vec()))
}

/// `unlink(2)`.
pub fn unlink(path: &PathBytes) -> Result<(), FsError> {
    let path_c = c_path(path, "unlink")?;
    // SAFETY: `path_c` is NUL-terminated.
    let rc = unsafe { libc::unlink(path_c.as_ptr()) };
    raw_cvt(rc, "unlink")
        .map(|_| ())
        .map_err(|error| error.path(path.to_vec()))
}

/// `link(2)`: creates a hard link.
pub fn link(existing: &PathBytes, new: &PathBytes) -> Result<(), FsError> {
    let existing_c = c_path(existing, "link")?;
    let new_c = c_path(new, "link")?;
    // SAFETY: both paths are NUL-terminated C strings.
    let rc = unsafe { libc::link(existing_c.as_ptr(), new_c.as_ptr()) };
    raw_cvt(rc, "link")
        .map(|_| ())
        .map_err(|error| error.path(existing.to_vec()).dest(new.to_vec()))
}

/// `symlink(2)`.
///
/// The `type` argument Node documents is Windows-only; on Unix `uv_fs_symlink`
/// ignores it, and so does this.
pub fn symlink(target: &PathBytes, link_path: &PathBytes) -> Result<(), FsError> {
    let target_c = c_path(target, "symlink")?;
    let link_c = c_path(link_path, "symlink")?;
    // SAFETY: both paths are NUL-terminated C strings.
    let rc = unsafe { libc::symlink(target_c.as_ptr(), link_c.as_ptr()) };
    raw_cvt(rc, "symlink")
        .map(|_| ())
        .map_err(|error| error.path(link_path.to_vec()).dest(target.to_vec()))
}

/// `readlink(2)`, returned as raw bytes.
pub fn readlink(path: &PathBytes) -> Result<Vec<u8>, FsError> {
    let path_c = c_path(path, "readlink")?;
    // Symlink targets can be arbitrarily long, so start at PATH_MAX and grow
    // when the buffer fills: `readlink` truncates silently, so a full buffer is
    // the signal to retry rather than a success.
    let mut size = libc::PATH_MAX as usize;
    loop {
        let mut buffer = vec![0u8; size];
        // SAFETY: `path_c` is NUL-terminated and `buffer` is a writable slice
        // of exactly the length passed, so `readlink` cannot overrun it.
        let rc =
            unsafe { libc::readlink(path_c.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) };
        let rc = raw_cvt_wide(rc, "readlink").map_err(|error| error.path(path.to_vec()))?;
        let length = rc as usize;
        if length < buffer.len() {
            buffer.truncate(length);
            return Ok(buffer);
        }
        size *= 2;
        if size > 1 << 20 {
            return Err(FsError::from_errno("readlink", libc::ENAMETOOLONG).path(path.to_vec()));
        }
    }
}

/// `realpath(3)`.
///
/// Uses `realpath(3)` rather than `std::fs::canonicalize` because Node reports
/// a specific syscall name and errno, and because `canonicalize` rejects paths
/// that do not exist with a different error shape.
pub fn realpath(path: &PathBytes) -> Result<Vec<u8>, FsError> {
    let path_c = c_path(path, "realpath")?;
    // SAFETY: `path_c` is NUL-terminated. `realpath` with a null buffer
    // allocates a result that the caller must free with `libc::free`.
    let resolved = unsafe { libc::realpath(path_c.as_ptr(), std::ptr::null_mut()) };
    if resolved.is_null() {
        // SAFETY: reading `errno` immediately after the failed call.
        let errno = unsafe { *libc::__errno_location() };
        return Err(FsError::from_errno("realpath", errno).path(path.to_vec()));
    }
    // SAFETY: `resolved` is non-null, NUL-terminated, and owned by us.
    let bytes = unsafe { std::ffi::CStr::from_ptr(resolved) }
        .to_bytes()
        .to_vec();
    // SAFETY: `resolved` came from `realpath`'s allocating form, so it must be
    // released with `libc::free` and is not used afterwards.
    unsafe { libc::free(resolved.cast()) };
    Ok(bytes)
}

/// `access(2)` with the caller's real ids, matching `uv_fs_access`.
pub fn access(path: &PathBytes, mode: i32) -> Result<(), FsError> {
    let path_c = c_path(path, "access")?;
    // SAFETY: `path_c` is NUL-terminated and `mode` is a bit mask of `R_OK`,
    // `W_OK`, `X_OK` and `F_OK`.
    let rc = unsafe { libc::access(path_c.as_ptr(), mode) };
    raw_cvt(rc, "access")
        .map(|_| ())
        .map_err(|error| error.path(path.to_vec()))
}

/// `copy_file_range`-backed copy, matching `uv_fs_copyfile`.
///
/// `mode` carries libuv's `UV_FS_COPYFILE_EXCL` and
/// `UV_FS_COPYFILE_FICLONE*` bits. FICLONE is treated as a hint: the copy is
/// still correct when the filesystem cannot reflink.
pub fn copy_file(source: &PathBytes, destination: &PathBytes, mode: i32) -> Result<(), FsError> {
    use std::io::{Read, Write};

    const UV_FS_COPYFILE_EXCL: i32 = 0x01;
    const UV_FS_COPYFILE_FICLONE: i32 = 0x02;
    const UV_FS_COPYFILE_FICLONE_FORCE: i32 = 0x04;

    let excl = mode & UV_FS_COPYFILE_EXCL != 0;
    let force_clone = mode & UV_FS_COPYFILE_FICLONE_FORCE != 0;
    let want_clone = mode & (UV_FS_COPYFILE_FICLONE | UV_FS_COPYFILE_FICLONE_FORCE) != 0;

    let source_path = std::path::Path::new(std::ffi::OsStr::from_bytes(source));
    let destination_path = std::path::Path::new(std::ffi::OsStr::from_bytes(destination));

    // Node's `copyfile` reports `EEXIST` for an existing destination only when
    // the exclusive bit is set, and truncates otherwise.
    let mut open_source = std::fs::File::open(source_path).map_err(|error| {
        FsError::from_errno("copyfile", error.raw_os_error().unwrap_or(libc::EIO))
            .path(source.to_vec())
    })?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if excl {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    let mut open_destination = options.open(destination_path).map_err(|error| {
        FsError::from_errno("copyfile", error.raw_os_error().unwrap_or(libc::EIO))
            .path(destination.to_vec())
    })?;

    if force_clone {
        // A forced reflink that cannot be satisfied must fail rather than
        // silently copy, which is what libuv does on Linux.
        let cloned = ioctl_clone(&open_source, &open_destination);
        if cloned {
            return Ok(());
        }
        if want_clone {
            return Err(FsError::from_errno("copyfile", libc::ENOTSUP).path(destination.to_vec()));
        }
    }

    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = open_source.read(&mut buffer).map_err(|error| {
            FsError::from_errno("copyfile", error.raw_os_error().unwrap_or(libc::EIO))
                .path(source.to_vec())
        })?;
        if read == 0 {
            break;
        }
        open_destination
            .write_all(&buffer[..read])
            .map_err(|error| {
                FsError::from_errno("copyfile", error.raw_os_error().unwrap_or(libc::EIO))
                    .path(destination.to_vec())
            })?;
    }

    Ok(())
}

/// Attempts `FICLONE`, reporting whether the filesystem honoured it.
fn ioctl_clone(source: &std::fs::File, destination: &std::fs::File) -> bool {
    use std::os::unix::io::AsRawFd;
    const FICLONE: libc::c_ulong = 0x4004_9409;
    // SAFETY: both descriptors are open for the lifetime of the call and
    // `FICLONE` takes the source fd as its argument. Failure is reported by the
    // return value, not by memory effects.
    let rc = unsafe { libc::ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) };
    rc == 0
}

/// `mkdir(2)` with `mkdir -p` semantics when `recursive` is set.
///
/// Returns the first directory that had to be created, which `fs.mkdirSync`
/// returns for the recursive form.
pub fn mkdir(path: &PathBytes, mode: u32, recursive: bool) -> Result<Option<Vec<u8>>, FsError> {
    if !recursive {
        let path_c = c_path(path, "mkdir")?;
        // SAFETY: `path_c` is NUL-terminated and `mode` is a plain integer.
        let rc = unsafe { libc::mkdir(path_c.as_ptr(), mode as libc::mode_t) };
        raw_cvt(rc, "mkdir")
            .map(|_| None::<Vec<u8>>)
            .map_err(|error| error.path(path.to_vec()))?;
        return Ok(None);
    }

    // Recursive creation walks from the shallowest missing ancestor so the
    // returned "first path created" matches `MKDirpSync`.
    let mut missing = Vec::new();
    let mut current = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(path));
    loop {
        match std::fs::metadata(&current) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Err(FsError::from_errno("mkdir", libc::ENOTDIR)
                        .path(current.as_os_str().as_bytes().to_vec()));
                }
                break;
            }
            Err(_) => {
                missing.push(current.clone());
                match current.parent() {
                    Some(parent) if parent != current => current = parent.to_path_buf(),
                    _ => break,
                }
            }
        }
    }

    let mut first_created: Option<Vec<u8>> = None;
    for directory in missing.iter().rev() {
        let bytes = directory.as_os_str().as_bytes();
        let path_c = c_path(bytes, "mkdir")?;
        // SAFETY: `path_c` is NUL-terminated and `mode` is a plain integer.
        let rc = unsafe { libc::mkdir(path_c.as_ptr(), mode as libc::mode_t) };
        if rc == 0 {
            if first_created.is_none() {
                first_created = Some(bytes.to_vec());
            }
            continue;
        }
        // SAFETY: reading `errno` immediately after the failed call.
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::EEXIST {
            continue;
        }
        return Err(FsError::from_errno("mkdir", errno).path(bytes.to_vec()));
    }

    Ok(first_created)
}

/// Creates a unique directory from a template ending in `XXXXXX`.
pub fn mkdtemp(template: &PathBytes, mode: u32) -> Result<Vec<u8>, FsError> {
    if !template.ends_with(b"XXXXXX") {
        // `mkdtemp(3)` itself returns EINVAL, but reporting the same code with
        // a clear path is friendlier and matches what Node surfaces.
        return Err(FsError::from_errno("mkdtemp", libc::EINVAL).path(template.to_vec()));
    }
    let mut buffer = template.to_vec();
    // SAFETY: `buffer` is NUL-terminated after `CString::new` below and ends
    // with the six `X` characters `mkdtemp` requires.
    let c_buffer = c_path(&buffer, "mkdtemp")?;
    buffer = c_buffer.as_bytes().to_vec();
    buffer.truncate(buffer.len());
    let mut owned = buffer.clone();
    owned.push(0);
    // SAFETY: `owned` ends with `XXXXXX\0` and is writable for its whole
    // length, which is `mkdtemp`'s contract. `mkdir` mode is applied below.
    let rc = unsafe { libc::mkdtemp(owned.as_mut_ptr().cast()) };
    if rc.is_null() {
        // SAFETY: reading `errno` immediately after the failed call.
        let errno = unsafe { *libc::__errno_location() };
        return Err(FsError::from_errno("mkdtemp", errno).path(template.to_vec()));
    }
    // `mkdtemp` creates with 0700; Node lets the platform pick and does not
    // take a mode, so `mode` is unused here but kept for signature symmetry
    // with `mkstemp`.
    let _ = mode;
    // SAFETY: `owned` is NUL-terminated after the call rewrote the template.
    let created = unsafe { std::ffi::CStr::from_ptr(owned.as_ptr().cast()) }
        .to_bytes()
        .to_vec();
    Ok(created)
}

/// Creates a unique file from a template ending in `XXXXXX`, returning its path
/// and descriptor.
pub fn mkstemp(template: &PathBytes) -> Result<(Vec<u8>, i32), FsError> {
    if !template.ends_with(b"XXXXXX") {
        return Err(FsError::from_errno("mkstemp", libc::EINVAL).path(template.to_vec()));
    }
    let mut owned = template.to_vec();
    owned.push(0);
    // SAFETY: `owned` ends with `XXXXXX\0` and is writable, which is what
    // `mkstemp` requires. The returned descriptor is owned by the caller.
    let fd = unsafe { libc::mkstemp(owned.as_mut_ptr().cast()) };
    if fd < 0 {
        // SAFETY: reading `errno` immediately after the failed call.
        let errno = unsafe { *libc::__errno_location() };
        return Err(FsError::from_errno("mkstemp", errno).path(template.to_vec()));
    }
    // SAFETY: `owned` holds the rewritten NUL-terminated template.
    let created = unsafe { std::ffi::CStr::from_ptr(owned.as_ptr().cast()) }
        .to_bytes()
        .to_vec();
    Ok((created, fd))
}

/// `scandir`-equivalent, returning entries in libuv's order.
pub fn readdir(path: &PathBytes) -> Result<Vec<DirentEntry>, FsError> {
    read_dir(path, "scandir")
}

/// Recursively walks a directory, matching `binding.readdirRecursive`.
///
/// Returns a flat list of names, a parallel list of types, a per-directory
/// count, and the relative directory names, which is the 4-tuple the JS
/// `getRecursiveDirents` destructures. Names carry their path relative to the
/// base because `fs.readdirSync(dir, { recursive: true })` returns those.
pub fn readdir_recursive(
    base: &PathBytes,
    syscall: &'static str,
) -> Result<RecursiveListing, FsError> {
    let mut listing = RecursiveListing::default();
    let mut queue: std::collections::VecDeque<(Vec<u8>, Vec<u8>)> =
        std::collections::VecDeque::new();
    queue.push_back((base.to_vec(), Vec::new()));

    while let Some((directory, prefix)) = queue.pop_front() {
        let entries = read_dir(&directory, syscall)?;
        listing.dirs.push(prefix.clone());
        listing.counts.push(entries.len());
        for entry in entries {
            let mut relative = prefix.clone();
            if !relative.is_empty() {
                relative.push(b'/');
            }
            relative.extend_from_slice(&entry.name);
            listing.names.push(relative.clone());
            listing.types.push(entry.kind);
            if entry.kind == crate::dirent::dirent_type::DIR {
                let mut child = directory.clone();
                if !child.ends_with(b"/") {
                    child.push(b'/');
                }
                child.extend_from_slice(&entry.name);
                queue.push_back((child, relative));
            }
        }
    }

    Ok(listing)
}

/// The four parallel arrays `getRecursiveDirents` reads.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecursiveListing {
    pub names: Vec<Vec<u8>>,
    pub types: Vec<i32>,
    pub counts: Vec<usize>,
    pub dirs: Vec<Vec<u8>>,
}

/// Fast path for `existsSync`, matching `ExistsSync` in `src/node_file.cc`.
pub fn exists(path: &PathBytes) -> bool {
    let Ok(path_c) = c_path(path, "stat") else {
        return false;
    };
    // SAFETY: `path_c` is NUL-terminated; `F_OK` only checks existence.
    unsafe { libc::access(path_c.as_ptr(), libc::F_OK) == 0 }
}

/// `internalModuleStat`: `0` for a file, `1` for a directory, negative errno
/// otherwise.
///
/// This exists so the module loader can classify a path without allocating
/// `Stats` objects or errors for every resolution attempt.
pub fn internal_module_stat(path: &PathBytes) -> i32 {
    match StatFields::for_path(path, Follow::Yes) {
        Ok(fields) => i32::from(crate::stats::is_directory(fields.mode)),
        Err(error) => error.errno,
    }
}

/// Reads a whole file as UTF-8 text, for `binding.readFileUtf8`.
pub fn read_file_utf8(path: &PathBytes, uv_open_flags: i32) -> Result<String, FsError> {
    let fd = open(path, uv_open_flags, 0o666)?;
    let result = read_all_fd(fd);
    let close_result = close(fd);
    match (result, close_result) {
        (Ok(bytes), Ok(())) => String::from_utf8(bytes).map_err(|_| {
            // Node reports invalid UTF-8 as a plain error rather than a UV
            // exception; `EILSEQ` is the closest errno and keeps `.code` sane.
            FsError::from_errno("read", libc::EILSEQ).path(path.to_vec())
        }),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

/// Writes UTF-8 text to a file, for `binding.writeFileUtf8`.
pub fn write_file_utf8(
    path: &PathBytes,
    text: &str,
    uv_open_flags: i32,
    mode: u32,
) -> Result<(), FsError> {
    let fd = open(path, uv_open_flags, mode)?;
    let result = write_all_fd(fd, text.as_bytes());
    let close_result = close(fd);
    result.and(close_result)
}

fn read_all_fd(fd: i32) -> Result<Vec<u8>, FsError> {
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = read(fd, &mut chunk, -1)?;
        if read == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&chunk[..read]);
    }
}

fn write_all_fd(fd: i32, mut data: &[u8]) -> Result<(), FsError> {
    while !data.is_empty() {
        let written = write(fd, data, -1)?;
        if written == 0 {
            return Err(FsError::from_errno("write", libc::EIO));
        }
        data = &data[written..];
    }
    Ok(())
}

/// `rmSync(path, maxRetries, recursive, retryDelay)`.
///
/// This is Node's own recursive-remove fast path, called by
/// `fs.rmSync`/`rmdirSync({recursive:true})` and by `mkdtempDisposable`'s
/// disposer. It is synchronous only: `lib/fs.js` never passes a request here.
///
/// Semantics copied from `RmSync` in `src/node_file.cc`:
///
/// * a missing path is a silent success;
/// * a directory without `recursive` fails with `ERR_FS_EISDIR`, not `EISDIR`,
///   because the check happens before any syscall;
/// * `EBUSY`, `EMFILE`, `ENFILE`, `ENOTEMPTY` and `EPERM` are retried up to
///   `maxRetries` times with a linearly growing `retryDelay` in milliseconds;
/// * the final failure is reported as a `UVException` with syscall `rm` and one
///   of `EPERM`, `ENOTEMPTY`, `ENOTDIR` or `EACCES`.
pub fn rm_sync(
    path: &PathBytes,
    max_retries: i32,
    recursive: bool,
    retry_delay_ms: i32,
) -> Result<(), FsError> {
    let target = std::path::Path::new(std::ffi::OsStr::from_bytes(path));

    // `symlink_status` matches `std::filesystem::symlink_status`: a dangling
    // symlink reports as a symlink rather than as missing, so it still gets
    // removed.
    let status = std::fs::symlink_metadata(target);
    let status = match status {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(
                FsError::from_errno("rm", error.raw_os_error().unwrap_or(libc::EIO))
                    .path(path.to_vec()),
            )
        }
    };

    if status.is_dir() && !recursive {
        // Node throws `ERR_FS_EISDIR` from JS-land before reaching libuv; the
        // errno form here keeps the failure expressible and the message close.
        return Err(FsError::from_errno("rm", libc::EISDIR).path(path.to_vec()));
    }

    let mut attempt = 1i32;
    let mut remaining = max_retries;
    loop {
        let result = if recursive {
            std::fs::remove_dir_all(target)
        } else {
            std::fs::remove_file(target)
        };

        match result {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(libc::EIO);
                // `ENOTEMPTY` and `EBUSY` and friends are transient on Linux
                // when a concurrent writer is still closing, so Node retries
                // them; anything else is final.
                let retryable = matches!(
                    errno,
                    libc::EBUSY | libc::EMFILE | libc::ENFILE | libc::ENOTEMPTY | libc::EPERM
                );
                if !retryable || remaining < 0 {
                    return Err(FsError::from_errno("rm", errno).path(path.to_vec()));
                }
                if retry_delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(
                        (attempt * retry_delay_ms) as u64,
                    ));
                }
                remaining -= 1;
                attempt += 1;
            }
        }
    }
}

/// `handleToFd` is a Windows-only helper; on Unix Node answers with
/// `ERR_FEATURE_UNAVAILABLE_ON_PLATFORM` before reaching the binding, so this
/// reports the same unsupported condition rather than pretending to work.
pub fn handle_to_fd() -> Result<i32, FsError> {
    Err(FsError::from_errno("handleToFd", libc::ENOSYS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::uv_flags;

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rn-fsops-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("mkdir");
            Self { path }
        }

        fn bytes(&self) -> &[u8] {
            self.path.as_os_str().as_bytes()
        }

        fn child(&self, name: &str) -> Vec<u8> {
            let mut path = self.bytes().to_vec();
            path.push(b'/');
            path.extend_from_slice(name.as_bytes());
            path
        }

        /// Converts a raw byte path into a `std::path::Path` for the test
        /// helpers in `std`, which only accept `AsRef<Path>`.
        fn as_path<'a>(&self, bytes: &'a [u8]) -> &'a std::path::Path {
            std::path::Path::new(std::ffi::OsStr::from_bytes(bytes))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn open_write_read_close_round_trip() {
        let dir = TempDir::new("roundtrip");
        let file = dir.child("data.bin");

        let fd = open(
            &file,
            uv_flags::O_RDWR | uv_flags::O_CREAT | uv_flags::O_TRUNC,
            0o644,
        )
        .expect("open");

        let payload = b"hello rustnode";
        let written = write(fd, payload, -1).expect("write");
        assert_eq!(written, payload.len());

        let read_back = read(fd, &mut [], -1).expect("zero-length read");
        assert_eq!(read_back, 0);

        let mut buffer = vec![0u8; payload.len()];
        let count = read(fd, &mut buffer, 0).expect("pread");
        assert_eq!(count, payload.len());
        assert_eq!(&buffer[..], payload);

        close(fd).expect("close");
        assert_eq!(std::fs::read(dir.as_path(&file)).expect("read"), payload);
    }

    #[test]
    fn positioned_write_does_not_move_offset() {
        let dir = TempDir::new("pwrite");
        let file = dir.child("pwrite.bin");
        let fd = open(
            &file,
            uv_flags::O_RDWR | uv_flags::O_CREAT | uv_flags::O_TRUNC,
            0o644,
        )
        .expect("open");

        write(fd, b"0123456789", -1).expect("write");
        // Write at an absolute offset; the file offset must stay at 10.
        write(fd, b"XY", 2).expect("pwrite");
        write(fd, b"!", -1).expect("append via offset");

        close(fd).expect("close");
        assert_eq!(
            std::fs::read(dir.as_path(&file)).expect("read"),
            b"01XY456789!"
        );
    }

    #[test]
    fn ftruncate_shortens_file() {
        let dir = TempDir::new("truncate");
        let file = dir.child("trunc.bin");
        std::fs::write(dir.as_path(&file), b"0123456789").expect("write");
        let fd = open(&file, uv_flags::O_RDWR, 0).expect("open");
        ftruncate(fd, 4).expect("ftruncate");
        close(fd).expect("close");
        assert_eq!(std::fs::read(dir.as_path(&file)).expect("read"), b"0123");
    }

    #[test]
    fn fsync_and_fdatasync_succeed_on_a_real_file() {
        let dir = TempDir::new("sync");
        let file = dir.child("sync.bin");
        let fd = open(&file, uv_flags::O_RDWR | uv_flags::O_CREAT, 0o600).expect("open");
        write(fd, b"data", -1).expect("write");
        fsync(fd).expect("fsync");
        fdatasync(fd).expect("fdatasync");
        close(fd).expect("close");
    }

    #[test]
    fn open_missing_file_reports_enoent() {
        let error = open(b"/definitely/not/here/xyzzy", uv_flags::O_RDONLY, 0).expect_err("fail");
        assert_eq!(error.code(), "ENOENT");
        assert_eq!(error.syscall, "open");
    }

    #[test]
    fn open_directory_for_writing_reports_eisdir() {
        let dir = TempDir::new("eisdir");
        let error = open(dir.bytes(), uv_flags::O_WRONLY, 0).expect_err("fail");
        assert_eq!(error.code(), "EISDIR");
    }

    #[test]
    fn open_below_a_file_reports_enotdir() {
        let dir = TempDir::new("enotdir");
        let file = dir.child("plain");
        std::fs::write(dir.as_path(&file), b"x").expect("write");
        let mut nested = file.clone();
        nested.extend_from_slice(b"/child");
        let error = open(&nested, uv_flags::O_RDONLY, 0).expect_err("fail");
        assert_eq!(error.code(), "ENOTDIR");
    }

    #[test]
    fn unreadable_file_reports_eacces() {
        // Running as root bypasses permission bits, so this only asserts the
        // mapping when the check can actually fail.
        // SAFETY: `geteuid` takes no arguments and has no side effects.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = TempDir::new("eacces");
        let file = dir.child("secret");
        std::fs::write(dir.as_path(&file), b"x").expect("write");
        let mut permissions = std::fs::metadata(dir.as_path(&file))
            .expect("metadata")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o000);
        std::fs::set_permissions(dir.as_path(&file), permissions).expect("chmod");

        let error = open(&file, uv_flags::O_RDONLY, 0).expect_err("fail");
        assert_eq!(error.code(), "EACCES");
    }

    #[test]
    fn read_on_directory_descriptor_reports_eisdir() {
        let dir = TempDir::new("read-eisdir");
        let fd = open(dir.bytes(), uv_flags::O_RDONLY, 0).expect("open dir");
        let error = read(fd, &mut [0u8; 16], -1).expect_err("fail");
        assert_eq!(error.code(), "EISDIR");
        assert_eq!(error.syscall, "read");
        close(fd).expect("close");
    }

    #[test]
    fn write_to_readonly_descriptor_reports_ebadf() {
        let dir = TempDir::new("ebadf");
        let file = dir.child("ro");
        std::fs::write(dir.as_path(&file), b"x").expect("write");
        let fd = open(&file, uv_flags::O_RDONLY, 0).expect("open");
        let error = write(fd, b"nope", -1).expect_err("fail");
        assert_eq!(error.code(), "EBADF");
        assert_eq!(error.syscall, "write");
        close(fd).expect("close");
    }

    #[test]
    fn rename_moves_file_and_reports_both_paths() {
        let dir = TempDir::new("rename");
        let from = dir.child("a");
        let to = dir.child("b");
        std::fs::write(dir.as_path(&from), b"payload").expect("write");

        rename(&from, &to).expect("rename");
        assert!(!std::path::Path::new(std::ffi::OsStr::from_bytes(&from)).exists());
        assert_eq!(std::fs::read(dir.as_path(&to)).expect("read"), b"payload");

        let missing = dir.child("nope");
        let error = rename(&missing, &to).expect_err("fail");
        assert_eq!(error.code(), "ENOENT");
        assert_eq!(error.syscall, "rename");
        assert_eq!(error.path.as_deref(), Some(missing.as_slice()));
        assert_eq!(error.dest.as_deref(), Some(to.as_slice()));
        assert!(error.message().contains("-> '"));
    }

    #[test]
    fn rmdir_and_unlink_remove_entries() {
        let dir = TempDir::new("remove");
        let sub = dir.child("sub");
        mkdir(&sub, 0o755, false).expect("mkdir");
        rmdir(&sub).expect("rmdir");

        let file = dir.child("file");
        std::fs::write(dir.as_path(&file), b"").expect("write");
        unlink(&file).expect("unlink");

        let error = rmdir(&sub).expect_err("missing");
        assert_eq!(error.code(), "ENOENT");
    }

    #[test]
    fn rmdir_on_non_empty_directory_reports_enotempty() {
        let dir = TempDir::new("notempty");
        let sub = dir.child("sub");
        mkdir(&sub, 0o755, false).expect("mkdir");
        let mut inside = sub.clone();
        inside.extend_from_slice(b"/kid");
        std::fs::write(dir.as_path(&inside), b"x").expect("write");

        let error = rmdir(&sub).expect_err("fail");
        assert_eq!(error.code(), "ENOTEMPTY");
    }

    #[test]
    fn unlink_on_directory_reports_eisdir() {
        let dir = TempDir::new("unlink-eisdir");
        let sub = dir.child("sub");
        mkdir(&sub, 0o755, false).expect("mkdir");
        let error = unlink(&sub).expect_err("fail");
        assert_eq!(error.code(), "EISDIR");
    }

    #[test]
    fn link_creates_a_second_name_for_the_same_inode() {
        let dir = TempDir::new("link");
        let original = dir.child("orig");
        let alias = dir.child("alias");
        std::fs::write(dir.as_path(&original), b"shared").expect("write");

        link(&original, &alias).expect("link");
        let a = StatFields::for_path(&original, Follow::Yes).expect("stat");
        let b = StatFields::for_path(&alias, Follow::Yes).expect("stat");
        assert_eq!(a.ino, b.ino);
        assert_eq!(a.nlink, 2);
    }

    #[test]
    fn symlink_and_readlink_round_trip() {
        let dir = TempDir::new("symlink");
        let target = dir.child("target");
        let link_path = dir.child("link");
        std::fs::write(dir.as_path(&target), b"content").expect("write");

        symlink(&target, &link_path).expect("symlink");
        assert_eq!(readlink(&link_path).expect("readlink"), target);
    }

    #[test]
    fn readlink_on_regular_file_reports_einval() {
        let dir = TempDir::new("readlink-einval");
        let file = dir.child("plain");
        std::fs::write(dir.as_path(&file), b"x").expect("write");
        let error = readlink(&file).expect_err("fail");
        assert_eq!(error.code(), "EINVAL");
    }

    #[test]
    fn readlink_handles_a_long_target() {
        let dir = TempDir::new("readlink-long");
        let mut target = dir.bytes().to_vec();
        for index in 0..40 {
            target.extend_from_slice(format!("/segment-{index}-padding-padding").as_bytes());
        }
        let link_path = dir.child("longlink");
        symlink(&target, &link_path).expect("symlink");
        assert_eq!(readlink(&link_path).expect("readlink"), target);
    }

    #[test]
    fn realpath_resolves_symlinks_and_dots() {
        let dir = TempDir::new("realpath");
        let sub = dir.child("sub");
        mkdir(&sub, 0o755, false).expect("mkdir");
        let mut dotted = sub.clone();
        dotted.extend_from_slice(b"/../sub/.");
        let resolved = realpath(&dotted).expect("realpath");
        assert_eq!(resolved, sub);
    }

    #[test]
    fn realpath_on_missing_path_reports_enoent() {
        let error = realpath(b"/definitely/not/here/xyzzy").expect_err("fail");
        assert_eq!(error.code(), "ENOENT");
        assert_eq!(error.syscall, "realpath");
    }

    #[test]
    fn access_reports_missing_and_present() {
        let dir = TempDir::new("access");
        let file = dir.child("present");
        std::fs::write(dir.as_path(&file), b"x").expect("write");

        access(&file, libc::F_OK).expect("exists");
        access(&file, libc::R_OK).expect("readable");
        let error = access(&dir.child("absent"), libc::F_OK).expect_err("fail");
        assert_eq!(error.code(), "ENOENT");
    }

    #[test]
    fn chmod_changes_permission_bits() {
        let dir = TempDir::new("chmod");
        let file = dir.child("mode");
        std::fs::write(dir.as_path(&file), b"x").expect("write");
        chmod(&file, 0o640).expect("chmod");
        let fields = StatFields::for_path(&file, Follow::Yes).expect("stat");
        assert_eq!(fields.mode & 0o777, 0o640);
    }

    #[test]
    fn fchmod_changes_permission_bits() {
        let dir = TempDir::new("fchmod");
        let file = dir.child("mode");
        std::fs::write(dir.as_path(&file), b"x").expect("write");
        let fd = open(&file, uv_flags::O_RDWR, 0).expect("open");
        fchmod(fd, 0o600).expect("fchmod");
        close(fd).expect("close");
        let fields = StatFields::for_path(&file, Follow::Yes).expect("stat");
        assert_eq!(fields.mode & 0o777, 0o600);
    }

    #[test]
    fn chown_to_own_ids_succeeds() {
        let dir = TempDir::new("chown");
        let file = dir.child("owner");
        std::fs::write(dir.as_path(&file), b"x").expect("write");
        let fields = StatFields::for_path(&file, Follow::Yes).expect("stat");
        // Chowning to the current owner needs no privilege.
        chown(&file, fields.uid as u32, fields.gid as u32).expect("chown");
        lchown(&file, fields.uid as u32, fields.gid as u32).expect("lchown");
        let fd = open(&file, uv_flags::O_RDONLY, 0).expect("open");
        fchown(fd, fields.uid as u32, fields.gid as u32).expect("fchown");
        close(fd).expect("close");
    }

    #[test]
    fn utimes_sets_both_timestamps() {
        let dir = TempDir::new("utimes");
        let file = dir.child("times");
        std::fs::write(dir.as_path(&file), b"x").expect("write");

        let atime = TimeSpec::new(1_000_000, 123_456_789);
        let mtime = TimeSpec::new(2_000_000, 987_654_321);
        utimes(&file, atime, mtime, true, "utimes").expect("utimes");

        let fields = StatFields::for_path(&file, Follow::Yes).expect("stat");
        assert_eq!(fields.atime_sec, atime.seconds);
        assert_eq!(fields.atime_nsec, atime.nanos);
        assert_eq!(fields.mtime_sec, mtime.seconds);
        assert_eq!(fields.mtime_nsec, mtime.nanos);
    }

    #[test]
    fn futimes_sets_both_timestamps() {
        let dir = TempDir::new("futimes");
        let file = dir.child("times");
        std::fs::write(dir.as_path(&file), b"x").expect("write");
        let fd = open(&file, uv_flags::O_RDWR, 0).expect("open");

        let atime = TimeSpec::new(3_000_000, 500);
        let mtime = TimeSpec::new(4_000_000, 600);
        futimes(fd, atime, mtime).expect("futimes");
        close(fd).expect("close");

        let fields = StatFields::for_path(&file, Follow::Yes).expect("stat");
        assert_eq!(fields.atime_sec, atime.seconds);
        assert_eq!(fields.mtime_sec, mtime.seconds);
    }

    #[test]
    fn lutimes_does_not_follow_the_symlink() {
        let dir = TempDir::new("lutimes");
        let target = dir.child("target");
        std::fs::write(dir.as_path(&target), b"x").expect("write");
        let link_path = dir.child("link");
        symlink(&target, &link_path).expect("symlink");

        let before = StatFields::for_path(&target, Follow::Yes).expect("stat");
        utimes(
            &link_path,
            TimeSpec::new(7_000_000, 0),
            TimeSpec::new(7_000_000, 0),
            false,
            "lutimes",
        )
        .expect("lutimes");

        let after = StatFields::for_path(&target, Follow::Yes).expect("stat");
        assert_eq!(
            after.mtime_sec, before.mtime_sec,
            "target must be untouched"
        );
        let link_stats = StatFields::for_path(&link_path, Follow::No).expect("lstat");
        assert_eq!(link_stats.mtime_sec, 7_000_000);
    }

    #[test]
    fn copy_file_copies_contents_and_respects_excl() {
        let dir = TempDir::new("copyfile");
        let source = dir.child("src");
        let destination = dir.child("dst");
        std::fs::write(dir.as_path(&source), b"copied bytes").expect("write");

        copy_file(&source, &destination, 0).expect("copy");
        assert_eq!(
            std::fs::read(dir.as_path(&destination)).expect("read"),
            b"copied bytes"
        );

        let error = copy_file(&source, &destination, 0x01).expect_err("excl");
        assert_eq!(error.code(), "EEXIST");
    }

    #[test]
    fn copy_file_missing_source_reports_enoent() {
        let dir = TempDir::new("copyfile-missing");
        let error = copy_file(&dir.child("nope"), &dir.child("dst"), 0).expect_err("fail");
        assert_eq!(error.code(), "ENOENT");
        assert_eq!(error.syscall, "copyfile");
    }

    #[test]
    fn mkdir_single_and_recursive() {
        let dir = TempDir::new("mkdir");
        let one = dir.child("one");
        assert_eq!(mkdir(&one, 0o755, false).expect("mkdir"), None);

        let deep = dir.child("a/b/c");
        let created = mkdir(&deep, 0o755, true).expect("mkdir -p");
        // `fs.mkdirSync(..., { recursive: true })` returns the *first*
        // directory created, not the deepest one.
        assert_eq!(created.as_deref(), Some(dir.child("a").as_slice()));
        assert!(std::path::Path::new(std::ffi::OsStr::from_bytes(&deep)).is_dir());

        // A second recursive call creates nothing and must not fail.
        assert_eq!(mkdir(&deep, 0o755, true).expect("again"), None);

        let error = mkdir(&one, 0o755, false).expect_err("exists");
        assert_eq!(error.code(), "EEXIST");
    }

    #[test]
    fn mkdir_under_a_file_reports_enotdir() {
        let dir = TempDir::new("mkdir-enotdir");
        let file = dir.child("file");
        std::fs::write(dir.as_path(&file), b"x").expect("write");
        let mut nested = file.clone();
        nested.extend_from_slice(b"/child");
        let error = mkdir(&nested, 0o755, false).expect_err("fail");
        assert_eq!(error.code(), "ENOTDIR");
    }

    #[test]
    fn mkdtemp_creates_a_unique_directory() {
        let dir = TempDir::new("mkdtemp");
        let mut template = dir.bytes().to_vec();
        template.extend_from_slice(b"/tmp-XXXXXX");

        let first = mkdtemp(&template, 0o700).expect("mkdtemp");
        let second = mkdtemp(&template, 0o700).expect("mkdtemp");
        assert_ne!(first, second);
        assert!(std::path::Path::new(std::ffi::OsStr::from_bytes(&first)).is_dir());
        assert!(first.starts_with(dir.bytes()));
    }

    #[test]
    fn mkdtemp_without_template_suffix_reports_einval() {
        let error = mkdtemp(b"/tmp/no-template", 0o700).expect_err("fail");
        assert_eq!(error.code(), "EINVAL");
    }

    #[test]
    fn mkstemp_creates_a_unique_file_and_descriptor() {
        let dir = TempDir::new("mkstemp");
        let mut template = dir.bytes().to_vec();
        template.extend_from_slice(b"/file-XXXXXX");

        let (path, fd) = mkstemp(&template).expect("mkstemp");
        assert!(fd >= 0);
        write(fd, b"temp", -1).expect("write");
        close(fd).expect("close");
        assert_eq!(std::fs::read(dir.as_path(&path)).expect("read"), b"temp");
    }

    #[test]
    fn readdir_returns_sorted_entries_with_types() {
        let dir = TempDir::new("readdir");
        for name in ["zebra", "alpha", "mike"] {
            std::fs::write(dir.as_path(&dir.child(name)), b"").expect("write");
        }
        mkdir(&dir.child("adir"), 0o755, false).expect("mkdir");

        let entries = readdir(dir.bytes()).expect("readdir");
        let names: Vec<String> = entries
            .iter()
            .map(|entry| String::from_utf8_lossy(&entry.name).into_owned())
            .collect();
        assert_eq!(names, vec!["adir", "alpha", "mike", "zebra"]);
        assert_eq!(entries[0].kind, crate::dirent::dirent_type::DIR);
        assert_eq!(entries[1].kind, crate::dirent::dirent_type::FILE);
    }

    #[test]
    fn readdir_recursive_reports_relative_names_and_counts() {
        let dir = TempDir::new("readdir-recursive");
        mkdir(&dir.child("sub"), 0o755, false).expect("mkdir");
        std::fs::write(dir.as_path(&dir.child("top.txt")), b"").expect("write");
        std::fs::write(dir.as_path(&dir.child("sub/inner.txt")), b"").expect("write");

        let listing = readdir_recursive(dir.bytes(), "scandir").expect("walk");
        let names: Vec<String> = listing
            .names
            .iter()
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .collect();
        assert!(names.contains(&"top.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));
        assert!(names.contains(&"sub/inner.txt".to_string()));
        assert_eq!(
            listing.counts.iter().sum::<usize>(),
            listing.names.len(),
            "counts must partition the names"
        );
        assert_eq!(listing.counts.len(), listing.dirs.len());
    }

    #[test]
    fn exists_distinguishes_present_from_absent() {
        let dir = TempDir::new("exists");
        let file = dir.child("here");
        std::fs::write(dir.as_path(&file), b"").expect("write");
        assert!(exists(&file));
        assert!(!exists(&dir.child("gone")));
        assert!(!exists(b"/definitely/not/here/xyzzy"));
    }

    #[test]
    fn internal_module_stat_classifies_file_directory_and_error() {
        let dir = TempDir::new("imstat");
        let file = dir.child("file");
        std::fs::write(dir.as_path(&file), b"").expect("write");

        assert_eq!(internal_module_stat(&file), 0);
        assert_eq!(internal_module_stat(dir.bytes()), 1);
        assert!(internal_module_stat(b"/definitely/not/here/xyzzy") < 0);
    }

    #[test]
    fn read_file_utf8_reads_text() {
        let dir = TempDir::new("read-utf8");
        let file = dir.child("text");
        std::fs::write(dir.as_path(&file), "héllo".as_bytes()).expect("write");
        assert_eq!(
            read_file_utf8(&file, uv_flags::O_RDONLY).expect("read"),
            "héllo"
        );
    }

    #[test]
    fn read_file_utf8_on_missing_file_reports_enoent() {
        let error =
            read_file_utf8(b"/definitely/not/here/xyzzy", uv_flags::O_RDONLY).expect_err("fail");
        assert_eq!(error.code(), "ENOENT");
    }

    #[test]
    fn write_file_utf8_writes_text() {
        let dir = TempDir::new("write-utf8");
        let file = dir.child("text");
        write_file_utf8(
            &file,
            "wörld",
            uv_flags::O_WRONLY | uv_flags::O_CREAT | uv_flags::O_TRUNC,
            0o644,
        )
        .expect("write");
        assert_eq!(
            std::fs::read_to_string(dir.as_path(&file)).expect("read"),
            "wörld"
        );
    }

    #[test]
    fn rm_sync_removes_a_file_and_ignores_a_missing_path() {
        let dir = TempDir::new("rm-file");
        let file = dir.child("gone");
        std::fs::write(dir.as_path(&file), b"x").expect("write");

        rm_sync(&file, 0, false, 0).expect("rm file");
        assert!(!std::path::Path::new(std::ffi::OsStr::from_bytes(&file)).exists());

        // A missing path is a silent success, matching Node.
        rm_sync(&file, 0, false, 0).expect("missing is fine");
    }

    #[test]
    fn rm_sync_removes_a_tree_only_when_recursive() {
        let dir = TempDir::new("rm-tree");
        let sub = dir.child("tree");
        mkdir(&sub, 0o755, false).expect("mkdir");
        let mut inner = sub.clone();
        inner.extend_from_slice(b"/inner");
        std::fs::write(dir.as_path(&inner), b"x").expect("write");

        // Without `recursive`, a directory is refused.
        let error = rm_sync(&sub, 0, false, 0).expect_err("directory needs recursive");
        assert_eq!(error.code(), "EISDIR");
        assert_eq!(error.syscall, "rm");

        rm_sync(&sub, 0, true, 0).expect("rm -r");
        assert!(!std::path::Path::new(std::ffi::OsStr::from_bytes(&sub)).exists());
    }

    #[test]
    fn rm_sync_removes_a_dangling_symlink() {
        let dir = TempDir::new("rm-dangling");
        let link_path = dir.child("dangling");
        symlink(b"/definitely/not/here", &link_path).expect("symlink");

        rm_sync(&link_path, 0, false, 0).expect("rm symlink");
        let error = StatFields::for_path(&link_path, Follow::No).expect_err("gone");
        assert_eq!(error.code(), "ENOENT");
    }

    #[test]
    fn handle_to_fd_is_unsupported_on_unix() {
        let error = handle_to_fd().expect_err("unsupported");
        assert_eq!(error.syscall, "handleToFd");
    }
}
