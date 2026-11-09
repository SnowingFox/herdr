//! errno to Node error-code mapping.
//!
//! Node never exposes raw errno values to JavaScript. Every failure crosses the
//! boundary as a `UVException` built from a context object that the native side
//! fills with the negated errno, the syscall name, and the operand paths. The
//! JavaScript in `lib/internal/errors.js` then looks the errno up in libuv's
//! error map to get the `code` and the message text.
//!
//! So this module only has to be right about two things: the *negated* errno
//! (libuv convention, `-ENOENT` not `ENOENT`) and the exact syscall string,
//! because both appear verbatim in `err.message`.

use std::ffi::CStr;
use std::fmt;

/// One filesystem failure, carrying everything JavaScript reads off the error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsError {
    /// Negated errno, as libuv reports it. `-2` for `ENOENT`.
    pub errno: i32,
    /// Syscall name, e.g. `open`, `stat`, `scandir`.
    pub syscall: &'static str,
    /// Primary operand path, if the operation had one.
    pub path: Option<Vec<u8>>,
    /// Secondary operand for two-path operations, e.g. `rename`, `link`.
    pub dest: Option<Vec<u8>>,
}

impl FsError {
    pub fn new(errno: i32, syscall: &'static str) -> Self {
        Self {
            errno,
            syscall,
            path: None,
            dest: None,
        }
    }

    /// Builds an error from a raw `libc` return value, matching libuv's
    /// convention of reporting `-errno` rather than `-1`.
    pub fn from_errno(syscall: &'static str, raw: i32) -> Self {
        Self::new(-raw.abs().max(1), syscall)
    }

    #[must_use]
    pub fn path(mut self, path: impl Into<Vec<u8>>) -> Self {
        self.path = Some(path.into());
        self
    }

    #[must_use]
    pub fn dest(mut self, dest: impl Into<Vec<u8>>) -> Self {
        self.dest = Some(dest.into());
        self
    }

    /// The positive errno, for `std::io::Error::from_raw_os_error`.
    pub fn raw_errno(&self) -> i32 {
        -self.errno
    }

    /// Symbolic name (`ENOENT`) as libuv's error map spells it.
    pub fn code(&self) -> &'static str {
        code_for_errno(self.raw_errno())
    }

    /// libuv's `uv_strerror` text for this errno, used as the message body.
    pub fn description(&self) -> &'static str {
        description_for_errno(self.raw_errno())
    }

    /// The `message` property Node would produce, reproduced exactly so
    /// snapshots and user assertions on `err.message` agree:
    /// `ENOENT: no such file or directory, stat '/nope'`.
    pub fn message(&self) -> String {
        let mut message = String::from(self.code());
        message.push_str(": ");
        message.push_str(self.description());
        message.push_str(", ");
        message.push_str(self.syscall);
        if let Some(path) = &self.path {
            message.push_str(" '");
            message.push_str(&String::from_utf8_lossy(path));
            message.push('\'');
        }
        if let Some(dest) = &self.dest {
            message.push_str(" -> '");
            message.push_str(&String::from_utf8_lossy(dest));
            message.push('\'');
        }
        message
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for FsError {}

impl From<std::io::Error> for FsError {
    fn from(error: std::io::Error) -> Self {
        Self::new(-error.raw_os_error().unwrap_or(libc::EIO).abs(), "open")
    }
}

/// libuv error names, restricted to the ones a filesystem syscall can produce
/// on Linux. Keeping the table local means the reported `code` never depends on
/// the host `libc` version.
pub fn code_for_errno(errno: i32) -> &'static str {
    match errno {
        libc::EACCES => "EACCES",
        libc::EAGAIN => "EAGAIN",
        libc::EBADF => "EBADF",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::EFAULT => "EFAULT",
        libc::EFBIG => "EFBIG",
        libc::EINTR => "EINTR",
        libc::EINVAL => "EINVAL",
        libc::EIO => "EIO",
        libc::EISDIR => "EISDIR",
        libc::ELOOP => "ELOOP",
        libc::EMFILE => "EMFILE",
        libc::EMLINK => "EMLINK",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENFILE => "ENFILE",
        libc::ENODEV => "ENODEV",
        libc::ENOENT => "ENOENT",
        libc::ENOMEM => "ENOMEM",
        libc::ENOSPC => "ENOSPC",
        libc::ENOSYS => "ENOSYS",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::ENOTSUP => "ENOTSUP",
        libc::ENOTTY => "ENOTTY",
        libc::ENXIO => "ENXIO",
        libc::EPERM => "EPERM",
        libc::EPIPE => "EPIPE",
        libc::EROFS => "EROFS",
        libc::ESPIPE => "ESPIPE",
        libc::ETXTBSY => "ETXTBSY",
        libc::EXDEV => "EXDEV",
        _ => "UNKNOWN",
    }
}

/// libuv's `uv_strerror` wording. Node interpolates this verbatim, so the
/// capitalisation and the absence of a trailing period both matter.
pub fn description_for_errno(errno: i32) -> &'static str {
    match errno {
        libc::EACCES => "permission denied",
        libc::EAGAIN => "resource temporarily unavailable",
        libc::EBADF => "bad file descriptor",
        libc::EBUSY => "resource busy or locked",
        libc::EEXIST => "file already exists",
        libc::EFAULT => "bad address in system call argument",
        libc::EFBIG => "file too large",
        libc::EINTR => "interrupted system call",
        libc::EINVAL => "invalid argument",
        libc::EIO => "i/o error",
        libc::EISDIR => "illegal operation on a directory",
        libc::ELOOP => "too many symbolic links encountered",
        libc::EMFILE => "too many open files",
        libc::EMLINK => "too many links",
        libc::ENAMETOOLONG => "name too long",
        libc::ENFILE => "file table overflow",
        libc::ENODEV => "no such device",
        libc::ENOENT => "no such file or directory",
        libc::ENOMEM => "not enough memory",
        libc::ENOSPC => "no space left on device",
        libc::ENOSYS => "function not implemented",
        libc::ENOTDIR => "not a directory",
        libc::ENOTEMPTY => "directory not empty",
        libc::ENOTSUP => "operation not supported on socket",
        libc::ENOTTY => "inappropriate ioctl for device",
        libc::ENXIO => "no such device or address",
        libc::EPERM => "operation not permitted",
        libc::EPIPE => "broken pipe",
        libc::EROFS => "read-only file system",
        libc::ESPIPE => "invalid seek",
        libc::ETXTBSY => "text file is busy",
        libc::EXDEV => "cross-device link not permitted",
        _ => "unknown error",
    }
}

/// `uv_strerror` for an arbitrary errno, using `libc::strerror_r` when the
/// table has no entry. Kept separate so the common path stays allocation-free.
pub fn description_for_errno_alloc(errno: i32) -> String {
    let known = description_for_errno(errno);
    if known != "unknown error" {
        return known.to_string();
    }
    let mut buffer = [0i8; 256];
    // SAFETY: `buffer` is a valid writable region of the size passed, and
    // `strerror_r` (XSI variant on Linux) only writes within it and returns
    // NUL-terminated data or an error code for which we ignore the buffer.
    let result = unsafe { libc::strerror_r(errno, buffer.as_mut_ptr(), buffer.len()) };
    if result != 0 {
        return known.to_string();
    }
    // SAFETY: on success `strerror_r` NUL-terminates within `buffer`.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_is_reported_negated_like_libuv() {
        let error = FsError::from_errno("stat", libc::ENOENT);
        assert_eq!(error.errno, -2);
        assert_eq!(error.raw_errno(), 2);
        assert_eq!(error.code(), "ENOENT");
    }

    #[test]
    fn message_matches_node_wording() {
        let error = FsError::from_errno("stat", libc::ENOENT).path("/nope-xyz");
        assert_eq!(
            error.message(),
            "ENOENT: no such file or directory, stat '/nope-xyz'"
        );
    }

    #[test]
    fn two_path_message_uses_arrow() {
        let error = FsError::from_errno("rename", libc::EXDEV)
            .path("/a")
            .dest("/b");
        assert_eq!(
            error.message(),
            "EXDEV: cross-device link not permitted, rename '/a' -> '/b'"
        );
    }

    #[test]
    fn required_error_codes_are_named() {
        assert_eq!(code_for_errno(libc::ENOENT), "ENOENT");
        assert_eq!(code_for_errno(libc::EACCES), "EACCES");
        assert_eq!(code_for_errno(libc::EISDIR), "EISDIR");
        assert_eq!(code_for_errno(libc::ENOTDIR), "ENOTDIR");
        assert_eq!(code_for_errno(libc::EEXIST), "EEXIST");
        assert_eq!(code_for_errno(libc::EPERM), "EPERM");
        assert_eq!(code_for_errno(libc::ENOTEMPTY), "ENOTEMPTY");
    }

    #[test]
    fn descriptions_match_libuv_not_libc() {
        // libc says "Is a directory"; libuv says "illegal operation on a
        // directory", and Node prints libuv's text.
        assert_eq!(
            description_for_errno(libc::EISDIR),
            "illegal operation on a directory"
        );
        assert_eq!(description_for_errno(libc::EACCES), "permission denied");
    }

    #[test]
    fn unknown_errno_falls_back_to_strerror() {
        let text = description_for_errno_alloc(9_999);
        assert!(!text.is_empty());
        assert_eq!(code_for_errno(9_999), "UNKNOWN");
    }

    #[test]
    fn io_error_conversion_preserves_errno() {
        let io = std::io::Error::from_raw_os_error(libc::EACCES);
        let error = FsError::from(io);
        assert_eq!(error.errno, -libc::EACCES);
        assert_eq!(error.code(), "EACCES");
    }
}
