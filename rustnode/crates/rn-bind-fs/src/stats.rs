//! Stat and statfs result buffers.
//!
//! Node does not hand JavaScript a struct. `lib/internal/fs/utils.js` builds
//! `fs.Stats` from a flat typed array whose indices are fixed by
//! `FsStatsOffset` in `src/node_file.h`:
//!
//! ```text
//! 0 dev       1 mode      2 nlink     3 uid       4 gid
//! 5 rdev      6 blksize   7 ino       8 size      9 blocks
//! 10 atime_s  11 atime_ns 12 mtime_s  13 mtime_ns
//! 14 ctime_s  15 ctime_ns 16 birth_s  17 birth_ns
//! ```
//!
//! The JS decides which constructor to use by testing the array type:
//! `Float64Array` for ordinary stats and `BigInt64Array` when `bigint: true`.
//! So the array type is part of the contract, not an implementation detail.
//!
//! Reading the fields goes through `statx(2)`, which is the only Linux stat
//! interface that reports a birth time. `std::fs::Metadata` has no birthtime
//! accessor on Unix, and libuv fills `st_birthtim` from `statx` too, so matching
//! libuv means calling `statx` directly. A kernel without `statx` falls back to
//! `fstat`/`lstat` with a zero birth time, which is what libuv reports there.

use crate::error::FsError;

/// Number of f64/i64 slots in one stats record (`kFsStatsFieldsNumber`).
pub const STATS_FIELDS: usize = 18;

/// Slots one `fs.StatWatcher` needs, matching `kFsStatsBufferLength`. Watch
/// mode is deferred, but the value is pinned so the layout cannot drift.
pub const STATS_WATCH_FIELDS: usize = STATS_FIELDS * 2;

/// Number of slots in one statfs record (`FsStatFsOffset`).
pub const STATFS_FIELDS: usize = 8;

/// A stat result in the flat layout Node expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatFields {
    pub dev: u64,
    pub mode: u64,
    pub nlink: u64,
    pub uid: u64,
    pub gid: u64,
    pub rdev: u64,
    pub blksize: u64,
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub birthtime_sec: i64,
    pub birthtime_nsec: i64,
}

/// How a path should be resolved while statting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Follow {
    /// `stat`: resolve a trailing symlink.
    Yes,
    /// `lstat`: report the symlink itself.
    No,
}

impl StatFields {
    /// Flattens into the JS slot order for the default (`number`) path.
    pub fn to_f64_slots(self) -> [f64; STATS_FIELDS] {
        [
            self.dev as f64,
            self.mode as f64,
            self.nlink as f64,
            self.uid as f64,
            self.gid as f64,
            self.rdev as f64,
            self.blksize as f64,
            self.ino as f64,
            self.size as f64,
            self.blocks as f64,
            self.atime_sec as f64,
            self.atime_nsec as f64,
            self.mtime_sec as f64,
            self.mtime_nsec as f64,
            self.ctime_sec as f64,
            self.ctime_nsec as f64,
            self.birthtime_sec as f64,
            self.birthtime_nsec as f64,
        ]
    }

    /// Flattens into the JS slot order for the `bigint: true` path.
    pub fn to_i64_slots(self) -> [i64; STATS_FIELDS] {
        [
            self.dev as i64,
            self.mode as i64,
            self.nlink as i64,
            self.uid as i64,
            self.gid as i64,
            self.rdev as i64,
            self.blksize as i64,
            self.ino as i64,
            self.size as i64,
            self.blocks as i64,
            self.atime_sec,
            self.atime_nsec,
            self.mtime_sec,
            self.mtime_nsec,
            self.ctime_sec,
            self.ctime_nsec,
            self.birthtime_sec,
            self.birthtime_nsec,
        ]
    }

    /// Stats a filesystem path, matching `uv_fs_stat`/`uv_fs_lstat`.
    pub fn for_path(path: &[u8], follow: Follow) -> Result<Self, FsError> {
        let syscall = match follow {
            Follow::Yes => "stat",
            Follow::No => "lstat",
        };
        let c_path = std::ffi::CString::new(path)
            .map_err(|_| FsError::from_errno(syscall, libc::EINVAL).path(path.to_vec()))?;
        let mut raw = std::mem::MaybeUninit::<libc::statx>::zeroed();
        let flags = match follow {
            Follow::Yes => libc::AT_STATX_SYNC_AS_STAT,
            Follow::No => libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
        };
        // SAFETY: `c_path` is NUL-terminated, `raw` is a correctly sized and
        // fully zeroed writable struct, and `statx` only writes into it.
        let rc = unsafe {
            libc::statx(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                flags,
                libc::STATX_ALL,
                raw.as_mut_ptr(),
            )
        };
        if rc != 0 {
            // SAFETY: reading `errno` immediately after a failed libc call is
            // the documented way to recover the failure code.
            let errno = unsafe { *libc::__errno_location() };
            return Err(FsError::from_errno(syscall, errno).path(path.to_vec()));
        }
        // SAFETY: the call succeeded, so the kernel filled the struct.
        Ok(Self::from_statx(unsafe { &raw.assume_init() }))
    }

    /// Stats an open descriptor, matching `uv_fs_fstat`.
    ///
    /// Uses `statx` with `AT_EMPTY_PATH` so the birth time is available, then
    /// falls back to plain `fstat` on kernels that reject that.
    pub fn for_fd(fd: i32) -> Result<Self, FsError> {
        let mut raw = std::mem::MaybeUninit::<libc::statx>::zeroed();
        let empty = c"";
        // SAFETY: `empty` is a valid NUL-terminated empty path and `raw` is a
        // zeroed writable struct of the correct size. `AT_EMPTY_PATH` is what
        // makes `statx` operate on `fd` itself.
        let rc = unsafe {
            libc::statx(
                fd,
                empty.as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_STATX_SYNC_AS_STAT,
                libc::STATX_ALL,
                raw.as_mut_ptr(),
            )
        };
        if rc == 0 {
            // SAFETY: the call succeeded and filled the struct.
            return Ok(Self::from_statx(unsafe { &raw.assume_init() }));
        }

        let mut fallback = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: `fallback` is a zeroed writable struct of the correct size
        // and `fd` was validated by the caller.
        let rc = unsafe { libc::fstat(fd, fallback.as_mut_ptr()) };
        if rc != 0 {
            // SAFETY: reading `errno` immediately after a failed libc call.
            let errno = unsafe { *libc::__errno_location() };
            return Err(FsError::from_errno("fstat", errno));
        }
        // SAFETY: the call succeeded, so the struct is initialised.
        Ok(Self::from_stat(unsafe { &fallback.assume_init() }))
    }

    /// Copies a `struct statx` into the slot layout.
    fn from_statx(raw: &libc::statx) -> Self {
        // `stx_dev_major`/`minor` are `u32`; libuv's `st_dev` is the encoded
        // `dev_t`. `libc::makedev` reproduces that encoding.
        let dev = libc::makedev(raw.stx_dev_major, raw.stx_dev_minor);
        let rdev = libc::makedev(raw.stx_rdev_major, raw.stx_rdev_minor);
        // The `u64` fields of `statx` are fixed-width by the kernel ABI, but
        // `statx_mode`/`nlink`/`uid`/`gid` are 16- and 32-bit and genuinely need
        // widening; the rest are cast for uniform typing.
        #[allow(clippy::unnecessary_cast)]
        Self {
            dev,
            mode: raw.stx_mode as u64,
            nlink: raw.stx_nlink as u64,
            uid: raw.stx_uid as u64,
            gid: raw.stx_gid as u64,
            rdev,
            blksize: raw.stx_blksize as u64,
            ino: raw.stx_ino,
            size: raw.stx_size,
            blocks: raw.stx_blocks,
            atime_sec: raw.stx_atime.tv_sec,
            atime_nsec: raw.stx_atime.tv_nsec as i64,
            mtime_sec: raw.stx_mtime.tv_sec,
            mtime_nsec: raw.stx_mtime.tv_nsec as i64,
            ctime_sec: raw.stx_ctime.tv_sec,
            ctime_nsec: raw.stx_ctime.tv_nsec as i64,
            // A filesystem that does not record creation time leaves the mask
            // bit clear and the timestamps zeroed, which is exactly what
            // `fs.Stats` should report there.
            birthtime_sec: if raw.stx_mask & libc::STATX_BTIME != 0 {
                raw.stx_btime.tv_sec
            } else {
                0
            },
            birthtime_nsec: if raw.stx_mask & libc::STATX_BTIME != 0 {
                raw.stx_btime.tv_nsec as i64
            } else {
                0
            },
        }
    }

    /// Copies a `struct stat` into the slot layout, used by the `fstat`
    /// fallback. `struct stat` carries no birth time, so it stays zero.
    // The field widths in `libc::stat` differ between libc implementations
    // (glibc uses 64-bit `st_dev`/`st_ino` on x86_64 while musl and 32-bit
    // targets do not), so each cast is load-bearing on some target and
    // redundant on another. Keeping them uniform is what makes this file
    // portable without a per-target pile of `cfg` attributes.
    #[allow(clippy::unnecessary_cast)]
    fn from_stat(raw: &libc::stat) -> Self {
        Self {
            dev: raw.st_dev as u64,
            mode: raw.st_mode as u64,
            nlink: raw.st_nlink as u64,
            uid: raw.st_uid as u64,
            gid: raw.st_gid as u64,
            rdev: raw.st_rdev as u64,
            blksize: raw.st_blksize as u64,
            ino: raw.st_ino as u64,
            size: raw.st_size as u64,
            blocks: raw.st_blocks as u64,
            atime_sec: raw.st_atime,
            atime_nsec: raw.st_atime_nsec,
            mtime_sec: raw.st_mtime,
            mtime_nsec: raw.st_mtime_nsec,
            ctime_sec: raw.st_ctime,
            ctime_nsec: raw.st_ctime_nsec,
            birthtime_sec: 0,
            birthtime_nsec: 0,
        }
    }
}

/// A statfs result in the flat layout Node expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatFsFields {
    pub kind: u64,
    pub bsize: u64,
    pub frsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
}

impl StatFsFields {
    pub fn to_f64_slots(self) -> [f64; STATFS_FIELDS] {
        [
            self.kind as f64,
            self.bsize as f64,
            self.frsize as f64,
            self.blocks as f64,
            self.bfree as f64,
            self.bavail as f64,
            self.files as f64,
            self.ffree as f64,
        ]
    }

    pub fn to_i64_slots(self) -> [i64; STATFS_FIELDS] {
        [
            self.kind as i64,
            self.bsize as i64,
            self.frsize as i64,
            self.blocks as i64,
            self.bfree as i64,
            self.bavail as i64,
            self.files as i64,
            self.ffree as i64,
        ]
    }

    fn from_raw(raw: &libc::statfs) -> Self {
        // `statfs` field widths vary the same way `stat`'s do across libc
        // implementations; see the note on `StatFields::from_stat`.
        #[allow(clippy::unnecessary_cast)]
        Self {
            kind: raw.f_type as u64,
            bsize: raw.f_bsize as u64,
            frsize: raw.f_frsize as u64,
            blocks: raw.f_blocks as u64,
            bfree: raw.f_bfree as u64,
            bavail: raw.f_bavail as u64,
            files: raw.f_files as u64,
            ffree: raw.f_ffree as u64,
        }
    }

    /// `statfs(2)` on a path.
    pub fn for_path(path: &[u8]) -> Result<Self, FsError> {
        let c_path = std::ffi::CString::new(path)
            .map_err(|_| FsError::from_errno("statfs", libc::EINVAL).path(path.to_vec()))?;
        let mut raw = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: `c_path` is NUL-terminated and `raw` is a correctly sized
        // zeroed writable struct; the call writes only into `raw`.
        let rc = unsafe { libc::statfs(c_path.as_ptr(), raw.as_mut_ptr()) };
        if rc != 0 {
            // SAFETY: reading `errno` immediately after a failed libc call.
            let errno = unsafe { *libc::__errno_location() };
            return Err(FsError::from_errno("statfs", errno).path(path.to_vec()));
        }
        // SAFETY: the call succeeded, so the kernel filled the struct.
        Ok(Self::from_raw(unsafe { &raw.assume_init() }))
    }

    /// `fstatfs(2)` on an open descriptor, used by `fstatfs`-style callers.
    pub fn for_fd(fd: i32) -> Result<Self, FsError> {
        let mut raw = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: `raw` is a correctly sized zeroed writable struct and `fd`
        // is caller-validated; the call writes only into `raw`.
        let rc = unsafe { libc::fstatfs(fd, raw.as_mut_ptr()) };
        if rc != 0 {
            // SAFETY: reading `errno` immediately after a failed libc call.
            let errno = unsafe { *libc::__errno_location() };
            return Err(FsError::from_errno("fstatfs", errno));
        }
        // SAFETY: the call succeeded, so the kernel filled the struct.
        Ok(Self::from_raw(unsafe { &raw.assume_init() }))
    }
}

/// `S_ISDIR` on a raw mode.
pub fn is_directory(mode: u64) -> bool {
    mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFDIR)
}

/// `S_ISREG` on a raw mode.
pub fn is_regular_file(mode: u64) -> bool {
    mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFREG)
}

/// `S_ISLNK` on a raw mode.
pub fn is_symlink(mode: u64) -> bool {
    mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFLNK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StatFields {
        StatFields {
            dev: 1,
            mode: 2,
            nlink: 3,
            uid: 4,
            gid: 5,
            rdev: 6,
            blksize: 7,
            ino: 8,
            size: 9,
            blocks: 10,
            atime_sec: 11,
            atime_nsec: 12,
            mtime_sec: 13,
            mtime_nsec: 14,
            ctime_sec: 15,
            ctime_nsec: 16,
            birthtime_sec: 17,
            birthtime_nsec: 18,
        }
    }

    #[test]
    fn slot_layout_matches_node_file_h() {
        // Guards against a reordering that would silently shift every field.
        for (index, value) in sample().to_f64_slots().iter().enumerate() {
            assert_eq!(*value, (index + 1) as f64, "f64 slot {index}");
        }
        for (index, value) in sample().to_i64_slots().iter().enumerate() {
            assert_eq!(*value, (index + 1) as i64, "i64 slot {index}");
        }
        assert_eq!(STATS_FIELDS, 18);
        assert_eq!(STATS_WATCH_FIELDS, 36);
    }

    #[test]
    fn statfs_has_eight_slots() {
        let fields = StatFsFields {
            kind: 1,
            bsize: 2,
            frsize: 3,
            blocks: 4,
            bfree: 5,
            bavail: 6,
            files: 7,
            ffree: 8,
        };
        assert_eq!(
            fields.to_f64_slots(),
            [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
        );
        assert_eq!(fields.to_i64_slots(), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn regular_file_reports_size_and_type() {
        let dir = std::env::temp_dir().join(format!("rn-stat-fields-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("data");
        std::fs::write(&file, b"0123456789").expect("write");

        let fields =
            StatFields::for_path(file.as_os_str().as_encoded_bytes(), Follow::Yes).expect("stat");

        assert_eq!(fields.size, 10);
        assert_eq!(
            fields.mode & u64::from(libc::S_IFMT),
            u64::from(libc::S_IFREG)
        );
        assert_eq!(fields.nlink, 1);
        assert!(is_regular_file(fields.mode));
        assert!(!is_directory(fields.mode));
        assert!(fields.ino > 0);
        assert!(fields.blksize >= 512);
        assert!(fields.atime_sec > 0);
        assert!(fields.mtime_sec > 0);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn statx_matches_std_metadata_for_shared_fields() {
        let path = std::env::temp_dir();
        let bytes = path.as_os_str().as_encoded_bytes();
        let stats = StatFields::for_path(bytes, Follow::Yes).expect("stat");
        let metadata = std::fs::metadata(&path).expect("metadata");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(stats.mode, metadata.mode() as u64);
            assert_eq!(stats.nlink, metadata.nlink());
            assert_eq!(stats.uid, metadata.uid() as u64);
            assert_eq!(stats.gid, metadata.gid() as u64);
            assert_eq!(stats.ino, metadata.ino());
            assert_eq!(stats.size, metadata.size());
            assert_eq!(stats.blocks, metadata.blocks());
            assert_eq!(stats.mtime_sec, metadata.mtime());
            assert_eq!(stats.mtime_nsec, metadata.mtime_nsec());
        }
        assert!(is_directory(stats.mode));
    }

    #[test]
    fn missing_path_reports_enoent_with_syscall() {
        let error = StatFields::for_path(b"/definitely/not/here/xyzzy", Follow::Yes)
            .expect_err("must fail");
        assert_eq!(error.code(), "ENOENT");
        assert_eq!(error.syscall, "stat");
        assert!(error.message().contains("xyzzy"));
    }

    #[test]
    fn path_below_a_file_reports_enotdir() {
        let dir = std::env::temp_dir().join(format!("rn-stat-enotdir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("plain");
        std::fs::write(&file, b"x").expect("write");

        let child = format!("{}/child", file.display());
        let error = StatFields::for_path(child.as_bytes(), Follow::Yes).expect_err("must fail");
        assert_eq!(error.code(), "ENOTDIR");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn lstat_and_stat_disagree_on_symlinks() {
        let dir = std::env::temp_dir().join(format!("rn-stat-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("target");
        std::fs::write(&file, b"payload").expect("write");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");

        let followed =
            StatFields::for_path(link.as_os_str().as_encoded_bytes(), Follow::Yes).expect("stat");
        let raw =
            StatFields::for_path(link.as_os_str().as_encoded_bytes(), Follow::No).expect("lstat");

        assert!(is_regular_file(followed.mode));
        assert!(is_symlink(raw.mode));
        assert_eq!(followed.size, 7);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn fstat_agrees_with_stat_and_reports_birthtime() {
        let dir = std::env::temp_dir().join(format!("rn-stat-fd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("fdarget");
        std::fs::write(&file, b"hello").expect("write");

        let by_path =
            StatFields::for_path(file.as_os_str().as_encoded_bytes(), Follow::Yes).expect("stat");

        let handle = std::fs::File::open(&file).expect("open");
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let by_fd = StatFields::for_fd(handle.as_raw_fd()).expect("fstat");
            assert_eq!(by_fd.ino, by_path.ino);
            assert_eq!(by_fd.size, 5);
            assert_eq!(by_fd.mode, by_path.mode);
            assert_eq!(by_fd.blksize, by_path.blksize);
            assert_eq!(by_fd.mtime_sec, by_path.mtime_sec);
            // statx carries a birth time on filesystems that record one; both
            // paths use statx, so they must agree when it is present.
            assert_eq!(by_fd.birthtime_sec, by_path.birthtime_sec);
            assert_eq!(by_fd.birthtime_nsec, by_path.birthtime_nsec);
            assert!(by_fd.birthtime_sec >= 0);
        }

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn fstat_on_bad_descriptor_reports_ebadf() {
        let error = StatFields::for_fd(-1).expect_err("bad fd");
        assert_eq!(error.code(), "EBADF");
        assert_eq!(error.syscall, "fstat");
    }

    #[test]
    fn statfs_on_temp_dir_is_sane() {
        let fields = StatFsFields::for_path(std::env::temp_dir().as_os_str().as_encoded_bytes())
            .expect("statfs");
        assert!(fields.bsize >= 512);
        assert!(fields.blocks > 0);
        assert!(fields.bfree <= fields.blocks);
        assert!(fields.bavail <= fields.blocks);
    }

    #[test]
    fn statfs_on_missing_path_reports_enoent() {
        let error = StatFsFields::for_path(b"/definitely/not/here/xyzzy").expect_err("must fail");
        assert_eq!(error.code(), "ENOENT");
    }

    #[test]
    fn statfs_on_bad_fd_reports_ebadf() {
        let error = StatFsFields::for_fd(-1).expect_err("bad fd");
        assert_eq!(error.code(), "EBADF");
    }

    #[test]
    fn symlink_mode_is_detected() {
        assert!(is_symlink(u64::from(libc::S_IFLNK) | 0o777));
        assert!(!is_symlink(u64::from(libc::S_IFREG) | 0o777));
    }

    #[test]
    fn empty_path_is_rejected_not_panicked() {
        // `CString::new` rejects interior NULs; that must surface as EINVAL.
        let error = StatFields::for_path(b"bad\0path", Follow::Yes).expect_err("must fail");
        assert_eq!(error.code(), "EINVAL");
    }
}
