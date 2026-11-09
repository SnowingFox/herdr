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

/// libuv's flag bits.
///
/// On Unix libuv does **not** define its own encoding: `include/uv/unix.h`
/// aliases every `UV_FS_O_*` straight onto the host `O_*` macro, so these must
/// equal the platform's values rather than a private bit layout. That is why
/// `O_SYNC` is `0x101000` on Linux and not a single bit — `O_SYNC` there is
/// defined as `__O_SYNC | O_DSYNC`, and `0x100000` is the bit that makes the
/// write durable.
///
/// Node's `fs.constants` is these same numbers, and `lib/internal/fs/utils.js`'s
/// `stringToFlags` composes flag *strings* out of them, so a value that disagrees
/// with the host turns `fs.open(path, 'rs')` into an `EINVAL`.
pub mod uv_flags {
    pub const O_RDONLY: i32 = libc::O_RDONLY;
    pub const O_WRONLY: i32 = libc::O_WRONLY;
    pub const O_RDWR: i32 = libc::O_RDWR;
    pub const O_CREAT: i32 = libc::O_CREAT;
    pub const O_EXCL: i32 = libc::O_EXCL;
    pub const O_TRUNC: i32 = libc::O_TRUNC;
    pub const O_APPEND: i32 = libc::O_APPEND;
    /// `__O_SYNC | O_DSYNC` on Linux, which is why translating it needs both
    /// bits rather than one.
    pub const O_SYNC: i32 = libc::O_SYNC;
    pub const O_DSYNC: i32 = libc::O_DSYNC;
    pub const O_NONBLOCK: i32 = libc::O_NONBLOCK;
    pub const O_DIRECT: i32 = libc::O_DIRECT;
    pub const O_DIRECTORY: i32 = libc::O_DIRECTORY;
    pub const O_NOFOLLOW: i32 = libc::O_NOFOLLOW;
    pub const O_NOATIME: i32 = libc::O_NOATIME;
    pub const O_CLOEXEC: i32 = libc::O_CLOEXEC;
    /// macOS-only; `0` on Linux, matching `uv/unix.h`'s
    /// `#else #define UV_FS_O_SYMLINK 0`.
    pub const O_SYMLINK: i32 = 0;
    pub const O_PATH: i32 = libc::O_PATH;
}

/// Translates a composed flag word into the host `O_*` bits.
///
/// Because [`uv_flags`] is already in host terms on Unix, this is no longer a
/// translation so much as a validation: it rejects bits this kernel does not
/// know, which is what `uv_fs_open` does, and it tolerates the composite values
/// (`O_SYNC`, and `O_TMPFILE`'s directory bits) that a single-bit walk would
/// misread as two independent flags.
pub fn to_host_flags(uv_flags: i32) -> Result<i32, i32> {
    // The two low bits encode the access mode as a number, not independent bits,
    // so they are decoded rather than tested. `O_RDONLY` is zero, which is why
    // the catch-all arm is the valid case and `_` is not reachable through it.
    let mode = uv_flags & (uv_flags::O_WRONLY | uv_flags::O_RDWR);
    if mode != uv_flags::O_RDONLY && mode != uv_flags::O_WRONLY && mode != uv_flags::O_RDWR {
        return Err(libc::EINVAL);
    }
    let mut flags = mode;

    // `O_SYNC` has to be taken as a unit before `O_DSYNC`, because on Linux the
    // `O_SYNC` value *contains* `O_DSYNC`. Consuming the composite first is what
    // keeps `rs+` from leaving `0x100000` behind as an unknown bit.
    let mut bits = uv_flags & !(uv_flags::O_WRONLY | uv_flags::O_RDWR);
    for (uv_bit, host_bit) in [
        (uv_flags::O_SYNC, libc::O_SYNC),
        (uv_flags::O_DSYNC, libc::O_DSYNC),
        (uv_flags::O_CREAT, libc::O_CREAT),
        (uv_flags::O_EXCL, libc::O_EXCL),
        (uv_flags::O_TRUNC, libc::O_TRUNC),
        (uv_flags::O_APPEND, libc::O_APPEND),
        (uv_flags::O_NONBLOCK, libc::O_NONBLOCK),
        (uv_flags::O_DIRECT, libc::O_DIRECT),
        (uv_flags::O_DIRECTORY, libc::O_DIRECTORY),
        (uv_flags::O_NOFOLLOW, libc::O_NOFOLLOW),
        (uv_flags::O_NOATIME, libc::O_NOATIME),
        // `O_CLOEXEC` is a flag on its own, but `open(2)` sets it for the
        // descriptor regardless, so dropping it from the request changes
        // nothing observable.
        (uv_flags::O_CLOEXEC, libc::O_CLOEXEC),
        (uv_flags::O_PATH, libc::O_PATH),
    ] {
        if bits & uv_bit == uv_bit && uv_bit != 0 {
            flags |= host_bit;
            bits &= !uv_bit;
        }
    }
    // `O_SYMLINK` has no Linux equivalent, so there is no bit to reject; see
    // `has_symlink_flag`. On a platform that does define it, the bit survives
    // into `bits` above and is reported as an unknown flag here.
    if bits != 0 {
        return Err(libc::EINVAL);
    }
    Ok(flags)
}

/// Whether this platform has an `O_SYMLINK` flag at all.
///
/// The JS layer can carry `O_SYMLINK` on every platform because `fs.constants`
/// is one table, but `include/uv/unix.h` defines `UV_FS_O_SYMLINK` as `0` where
/// the kernel has no such flag. On Linux there is therefore no bit a caller
/// could set, and reporting that directly is more honest than accepting a value
/// that `open(2)` would ignore.
pub fn has_symlink_flag() -> bool {
    uv_flags::O_SYMLINK != 0
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
    fn symlink_flag_does_not_exist_on_linux() {
        // `include/uv/unix.h` defines `UV_FS_O_SYMLINK` as `0` when the platform
        // has no `O_SYMLINK`, so there is no bit a caller could set and nothing
        // to reject. Asserting that keeps the constant honest: a made-up value
        // would make `open` fail for a flag no caller can name.
        assert_eq!(uv_flags::O_SYMLINK, 0);
        assert!(!has_symlink_flag());
        assert_eq!(
            to_host_flags(uv_flags::O_RDONLY).expect("valid"),
            libc::O_RDONLY
        );
    }

    #[test]
    fn sync_open_is_accepted() {
        // `fs.open(path, 'rs')` composes `O_RDONLY | O_SYNC`, and Linux defines
        // `O_SYNC` as `__O_SYNC | O_DSYNC`. Reading it as two independent bits
        // leaves `__O_SYNC` behind as "unknown" and turns the open into EINVAL,
        // which is exactly the bug this pins.
        let host = to_host_flags(uv_flags::O_RDONLY | uv_flags::O_SYNC).expect("valid");
        assert_eq!(host & libc::O_SYNC, libc::O_SYNC);
        assert_ne!(host & 0x10_0000, 0, "the __O_SYNC bit must survive");

        // The read-write form has to work for the same reason.
        let host = to_host_flags(uv_flags::O_RDWR | uv_flags::O_SYNC).expect("valid");
        assert_eq!(host & libc::O_ACCMODE, libc::O_RDWR);
        assert_eq!(host & libc::O_SYNC, libc::O_SYNC);

        // And `a+`-with-sync, the create-and-append form.
        let uv = uv_flags::O_RDWR | uv_flags::O_CREAT | uv_flags::O_APPEND | uv_flags::O_SYNC;
        let host = to_host_flags(uv).expect("valid");
        assert_ne!(host & libc::O_CREAT, 0);
        assert_ne!(host & libc::O_APPEND, 0);
    }

    #[test]
    fn the_constants_match_the_host_not_a_private_encoding() {
        // `fs.constants` is published from these values, and `stringToFlags`
        // composes flag strings out of them, so any that disagreed with the
        // platform would turn a valid flag string into EINVAL.
        assert_eq!(uv_flags::O_CREAT, libc::O_CREAT);
        assert_eq!(uv_flags::O_TRUNC, libc::O_TRUNC);
        assert_eq!(uv_flags::O_APPEND, libc::O_APPEND);
        assert_eq!(uv_flags::O_SYNC, libc::O_SYNC);
        assert_eq!(uv_flags::O_DSYNC, libc::O_DSYNC);
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
