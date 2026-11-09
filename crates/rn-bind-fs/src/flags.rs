//! Open flags and mode handling.
//!
//! `lib/fs.js` converts a user-facing flag *string* into a number with
//! `stringToFlags()` before calling into the binding, so the binding only ever
//! sees the numeric form. The numbers are not raw Linux `O_*` values: they are
//! libuv's own encoding, which is stable across platforms and is what Node
//! documents on `fs.constants`.
//!
//! Reproducing libuv's table matters because `fs.constants` is exported from
//! the `constants` namespace using these same numbers, and user code does
//! `open(path, constants.O_WRONLY | constants.O_CREAT)`.

/// libuv's `UV_FS_O_FILEMAP`-style flag bits, matching `include/uv.h`.
pub mod uv_flags {
    pub const O_RDONLY: i32 = 0x0000_0000;
    pub const O_WRONLY: i32 = 0x0000_0001;
    pub const O_RDWR: i32 = 0x0000_0002;
    pub const O_CREAT: i32 = 0x0000_0040;
    pub const O_EXCL: i32 = 0x0000_0080;
    pub const O_TRUNC: i32 = 0x0000_0200;
    pub const O_APPEND: i32 = 0x0000_0400;
    pub const O_SYNC: i32 = 0x0000_0800;
    pub const O_DSYNC: i32 = 0x0000_1000;
    pub const O_NONBLOCK: i32 = 0x0000_2000;
    pub const O_DIRECT: i32 = 0x0000_4000;
    pub const O_DIRECTORY: i32 = 0x0001_0000;
    pub const O_NOFOLLOW: i32 = 0x0002_0000;
    pub const O_NOATIME: i32 = 0x0004_0000;
    pub const O_CLOEXEC: i32 = 0x0008_0000;
    pub const O_SYMLINK: i32 = 0x0020_0000;
    pub const O_PATH: i32 = 0x0040_0000;
}

/// Translates libuv's flag bits into the host `O_*` bits.
///
/// The translation is a straight bit walk rather than a lookup table so an
/// unknown bit is a hard error instead of being silently dropped: `fs.open` is
/// not a place where guessing is acceptable.
pub fn to_host_flags(uv_flags: i32) -> Result<i32, i32> {
    // The two low bits encode the access mode as a number, not independent
    // bits, so they are decoded rather than tested.
    let mut flags = match uv_flags & (uv_flags::O_WRONLY | uv_flags::O_RDWR) {
        uv_flags::O_WRONLY => libc::O_WRONLY,
        uv_flags::O_RDWR => libc::O_RDWR,
        uv_flags::O_RDONLY => libc::O_RDONLY,
        _ => return Err(libc::EINVAL),
    };

    let mut bits = uv_flags & !(uv_flags::O_WRONLY | uv_flags::O_RDWR);
    let table: &[(i32, i32)] = &[
        (uv_flags::O_CREAT, libc::O_CREAT),
        (uv_flags::O_EXCL, libc::O_EXCL),
        (uv_flags::O_TRUNC, libc::O_TRUNC),
        (uv_flags::O_APPEND, libc::O_APPEND),
        (uv_flags::O_SYNC, libc::O_SYNC),
        (uv_flags::O_DSYNC, libc::O_DSYNC),
        (uv_flags::O_NONBLOCK, libc::O_NONBLOCK),
        (uv_flags::O_DIRECT, libc::O_DIRECT),
        (uv_flags::O_DIRECTORY, libc::O_DIRECTORY),
        (uv_flags::O_NOFOLLOW, libc::O_NOFOLLOW),
        (uv_flags::O_NOATIME, libc::O_NOATIME),
        (uv_flags::O_CLOEXEC, libc::O_CLOEXEC),
        (uv_flags::O_PATH, libc::O_PATH),
    ];
    for (uv_bit, host_bit) in table {
        if bits & uv_bit != 0 {
            flags |= host_bit;
            bits &= !uv_bit;
        }
    }
    if bits != 0 {
        // `O_SYMLINK` has no Linux equivalent; it is macOS-only. Every other
        // unknown bit is a bad argument. Node surfaces both as libuv errors, and
        // `uv_fs_open` rejects an unrecognised flag with `EINVAL`.
        if bits & uv_flags::O_SYMLINK != 0 {
            return Err(libc::EINVAL);
        }
        return Err(libc::EINVAL);
    }
    Ok(flags)
}

/// `O_SYMLINK` is accepted by the JS layer on every platform but only has
/// meaning on macOS. Detecting it separately lets `open` fail with the same
/// code Node uses instead of a generic invalid-argument error.
pub fn requests_symlink_open(uv_flags: i32) -> bool {
    uv_flags & uv_flags::O_SYMLINK != 0
}

/// Applies the process umask to a creation mode, matching `open(2)` semantics.
///
/// Node passes the raw mode to `uv_fs_open`, which passes it to the kernel; the
/// kernel applies the umask. Rust's `std::fs::OpenOptions` does the same, so
/// this is only used where a mode is stored rather than applied.
pub fn apply_umask(mode: i32, umask: i32) -> i32 {
    mode & !umask
}

/// Reads the current process umask without changing it.
///
/// `umask(2)` has no read-only form, so the value is restored immediately. The
/// call is not thread safe in the strict sense, but the window is a handful of
/// instructions and Node's own behaviour is to trust the kernel instead.
pub fn current_umask() -> u32 {
    // SAFETY: `umask` takes and returns a mode_t and has no memory side
    // effects. Restoring the previous value keeps the process state intact.
    let previous = unsafe { libc::umask(0o022) };
    // SAFETY: as above; this restores exactly what was read.
    unsafe { libc::umask(previous) };
    previous
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_is_zero() {
        assert_eq!(
            to_host_flags(uv_flags::O_RDONLY).expect("valid"),
            libc::O_RDONLY
        );
    }

    #[test]
    fn write_and_readwrite_decode_from_low_bits() {
        assert_eq!(
            to_host_flags(uv_flags::O_WRONLY).expect("valid") & libc::O_ACCMODE,
            libc::O_WRONLY
        );
        assert_eq!(
            to_host_flags(uv_flags::O_RDWR).expect("valid") & libc::O_ACCMODE,
            libc::O_RDWR
        );
    }

    #[test]
    fn combined_flags_translate_individually() {
        let uv = uv_flags::O_WRONLY | uv_flags::O_CREAT | uv_flags::O_TRUNC;
        let host = to_host_flags(uv).expect("valid");
        assert_eq!(host & libc::O_ACCMODE, libc::O_WRONLY);
        assert_ne!(host & libc::O_CREAT, 0);
        assert_ne!(host & libc::O_TRUNC, 0);
        assert_eq!(host & libc::O_APPEND, 0);
    }

    #[test]
    fn append_and_excl_round_trip() {
        let uv = uv_flags::O_RDWR | uv_flags::O_APPEND | uv_flags::O_EXCL;
        let host = to_host_flags(uv).expect("valid");
        assert_ne!(host & libc::O_APPEND, 0);
        assert_ne!(host & libc::O_EXCL, 0);
        assert_eq!(host & libc::O_ACCMODE, libc::O_RDWR);
    }

    #[test]
    fn symlink_flag_is_rejected_on_linux() {
        // `O_SYMLINK` is macOS-only; `uv_fs_open` reports a bad flag as EINVAL.
        let uv = uv_flags::O_RDONLY | uv_flags::O_SYMLINK;
        assert!(requests_symlink_open(uv));
        assert_eq!(to_host_flags(uv), Err(libc::EINVAL));
    }

    #[test]
    fn unknown_bit_is_rejected_not_dropped() {
        assert_eq!(to_host_flags(0x4000_0000), Err(libc::EINVAL));
    }

    #[test]
    fn umask_masking_clears_bits() {
        assert_eq!(apply_umask(0o777, 0o022), 0o755);
        assert_eq!(apply_umask(0o666, 0o077), 0o600);
    }
}
