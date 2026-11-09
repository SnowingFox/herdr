//! Directory entries: the `uv_dirent_type_t` numbering and libuv's sort order.
//!
//! `lib/internal/fs/utils.js` builds `fs.Dirent` from a `[names, types]` pair
//! where each type is a raw `uv_dirent_type_t`. Those numbers are ABI, not
//! implementation detail: `Dirent.isDirectory()` compares against
//! `UV_DIRENT_DIR` read from the `constants` binding.
//!
//! Ordering is the other half of the contract. `uv_fs_scandir` sorts entries,
//! so `fs.readdirSync` returns them sorted on every platform, and Node's tests
//! assert that. Reproducing it means sorting by the same rule libuv uses:
//! `strcmp` on the raw bytes, which is *not* the same as byte-order comparison
//! of `u8` values only because `strcmp` stops at the first difference and
//! treats bytes as `unsigned char`; the two agree for UTF-8, but the comparison
//! must not be done on decoded `String` values (that would use Unicode
//! collation and reorder non-ASCII names).

/// `uv_dirent_type_t` values, matching `include/uv.h` order.
pub mod dirent_type {
    pub const UNKNOWN: i32 = 0;
    pub const FILE: i32 = 1;
    pub const DIR: i32 = 2;
    pub const LINK: i32 = 3;
    pub const FIFO: i32 = 4;
    pub const SOCKET: i32 = 5;
    pub const CHAR: i32 = 6;
    pub const BLOCK: i32 = 7;
}

/// One directory entry, name in raw bytes plus its libuv type code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirentEntry {
    pub name: Vec<u8>,
    pub kind: i32,
}

impl DirentEntry {
    pub fn new(name: Vec<u8>, kind: i32) -> Self {
        Self { name, kind }
    }
}

/// Maps a `d_type` from `readdir(3)` onto `uv_dirent_type_t`.
///
/// `DT_UNKNOWN` must stay `UV_DIRENT_UNKNOWN`: the JS layer treats that as a
/// request to `lstat` each entry and build a `DirentFromStats`, so mapping it
/// to a guess would change `readdir(dir, { withFileTypes: true })` results on
/// filesystems that do not report types.
pub fn kind_from_dtype(dtype: u8) -> i32 {
    match dtype {
        libc::DT_REG => dirent_type::FILE,
        libc::DT_DIR => dirent_type::DIR,
        libc::DT_LNK => dirent_type::LINK,
        libc::DT_FIFO => dirent_type::FIFO,
        libc::DT_SOCK => dirent_type::SOCKET,
        libc::DT_CHR => dirent_type::CHAR,
        libc::DT_BLK => dirent_type::BLOCK,
        _ => dirent_type::UNKNOWN,
    }
}

/// Maps a file mode onto `uv_dirent_type_t`, used when a platform gave only
/// stats.
pub fn kind_from_mode(mode: u64) -> i32 {
    match mode & u64::from(libc::S_IFMT) {
        mode if mode == u64::from(libc::S_IFREG) => dirent_type::FILE,
        mode if mode == u64::from(libc::S_IFDIR) => dirent_type::DIR,
        mode if mode == u64::from(libc::S_IFLNK) => dirent_type::LINK,
        mode if mode == u64::from(libc::S_IFIFO) => dirent_type::FIFO,
        mode if mode == u64::from(libc::S_IFSOCK) => dirent_type::SOCKET,
        mode if mode == u64::from(libc::S_IFCHR) => dirent_type::CHAR,
        mode if mode == u64::from(libc::S_IFBLK) => dirent_type::BLOCK,
        _ => dirent_type::UNKNOWN,
    }
}

/// Sorts entries the way `uv_fs_scandir` does: ascending `strcmp` order of the
/// raw name bytes.
pub fn sort_like_libuv(entries: &mut [DirentEntry]) {
    entries.sort_by(|left, right| std::cmp::Ord::cmp(&left.name, &right.name));
}

/// Reads a directory without following any logic the JS layer owns.
///
/// Returns entries in libuv's sorted order. `.` and `..` are excluded, matching
/// `readdir(3)`/`uv_fs_scandir`.
pub fn read_dir(
    path: &[u8],
    syscall: &'static str,
) -> Result<Vec<DirentEntry>, crate::error::FsError> {
    use crate::error::FsError;
    use std::os::unix::ffi::OsStrExt;

    // The path arrives as raw bytes because `fs` accepts `Buffer` paths. It
    // must never be validated as UTF-8 first: a non-UTF-8 but perfectly valid
    // filename has to open.
    let directory = std::fs::read_dir(std::path::Path::new(std::ffi::OsStr::from_bytes(path)))
        .map_err(|error| {
            FsError::from_errno(syscall, error.raw_os_error().unwrap_or(libc::EIO))
                .path(path.to_vec())
        })?;

    let mut entries = Vec::new();
    for entry in directory {
        let entry = entry.map_err(|error| {
            FsError::from_errno(syscall, error.raw_os_error().unwrap_or(libc::EIO))
                .path(path.to_vec())
        })?;
        let name = entry.file_name();
        let name = OsStrExt::as_bytes(name.as_os_str()).to_vec();
        let kind = match entry.file_type() {
            Ok(file_type) => {
                if file_type.is_dir() {
                    dirent_type::DIR
                } else if file_type.is_file() {
                    dirent_type::FILE
                } else if file_type.is_symlink() {
                    dirent_type::LINK
                } else {
                    // Sockets, FIFOs and devices need `stat` to classify.
                    entry
                        .metadata()
                        .map(|metadata| {
                            use std::os::unix::fs::MetadataExt;
                            kind_from_mode(metadata.mode() as u64)
                        })
                        .unwrap_or(dirent_type::UNKNOWN)
                }
            }
            Err(_) => dirent_type::UNKNOWN,
        };
        entries.push(DirentEntry::new(name, kind));
    }

    sort_like_libuv(&mut entries);
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_codes_match_uv_h_order() {
        assert_eq!(dirent_type::UNKNOWN, 0);
        assert_eq!(dirent_type::FILE, 1);
        assert_eq!(dirent_type::DIR, 2);
        assert_eq!(dirent_type::LINK, 3);
        assert_eq!(dirent_type::FIFO, 4);
        assert_eq!(dirent_type::SOCKET, 5);
        assert_eq!(dirent_type::CHAR, 6);
        assert_eq!(dirent_type::BLOCK, 7);
    }

    #[test]
    fn dtype_mapping_covers_every_type() {
        assert_eq!(kind_from_dtype(libc::DT_REG), dirent_type::FILE);
        assert_eq!(kind_from_dtype(libc::DT_DIR), dirent_type::DIR);
        assert_eq!(kind_from_dtype(libc::DT_LNK), dirent_type::LINK);
        assert_eq!(kind_from_dtype(libc::DT_FIFO), dirent_type::FIFO);
        assert_eq!(kind_from_dtype(libc::DT_SOCK), dirent_type::SOCKET);
        assert_eq!(kind_from_dtype(libc::DT_CHR), dirent_type::CHAR);
        assert_eq!(kind_from_dtype(libc::DT_BLK), dirent_type::BLOCK);
        assert_eq!(kind_from_dtype(libc::DT_UNKNOWN), dirent_type::UNKNOWN);
    }

    #[test]
    fn mode_mapping_covers_every_type() {
        assert_eq!(kind_from_mode(u64::from(libc::S_IFREG)), dirent_type::FILE);
        assert_eq!(kind_from_mode(u64::from(libc::S_IFDIR)), dirent_type::DIR);
        assert_eq!(kind_from_mode(u64::from(libc::S_IFLNK)), dirent_type::LINK);
        assert_eq!(kind_from_mode(u64::from(libc::S_IFIFO)), dirent_type::FIFO);
        assert_eq!(
            kind_from_mode(u64::from(libc::S_IFSOCK)),
            dirent_type::SOCKET
        );
        assert_eq!(kind_from_mode(u64::from(libc::S_IFCHR)), dirent_type::CHAR);
        assert_eq!(kind_from_mode(u64::from(libc::S_IFBLK)), dirent_type::BLOCK);
        assert_eq!(kind_from_mode(0), dirent_type::UNKNOWN);
    }

    #[test]
    fn sort_is_bytewise_ascending() {
        let mut entries = vec![
            DirentEntry::new(b"zebra".to_vec(), dirent_type::FILE),
            DirentEntry::new(b"alpha".to_vec(), dirent_type::FILE),
            DirentEntry::new(b"Mike".to_vec(), dirent_type::FILE),
            DirentEntry::new(b"beta".to_vec(), dirent_type::FILE),
        ];
        sort_like_libuv(&mut entries);
        let names: Vec<&[u8]> = entries.iter().map(|entry| entry.name.as_slice()).collect();
        // Uppercase sorts before lowercase in byte order, unlike a case-folded
        // or locale-aware sort.
        assert_eq!(names, vec![b"Mike".as_slice(), b"alpha", b"beta", b"zebra"]);
    }

    #[test]
    fn read_dir_returns_sorted_entries() {
        let dir = std::env::temp_dir().join(format!("rn-dirent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        for name in ["zebra", "alpha", "mike", "bravo"] {
            std::fs::write(dir.join(name), b"").expect("write");
        }
        std::fs::create_dir_all(dir.join("sub")).expect("mkdir sub");
        std::os::unix::fs::symlink("/nowhere", dir.join("link")).expect("symlink");

        let entries = read_dir(dir.as_os_str().as_encoded_bytes(), "scandir").expect("readdir");
        let names: Vec<String> = entries
            .iter()
            .map(|entry| String::from_utf8_lossy(&entry.name).into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["alpha", "bravo", "link", "mike", "sub", "zebra"]
        );

        let by_name = |wanted: &str| {
            entries
                .iter()
                .find(|entry| entry.name == wanted.as_bytes())
                .map(|entry| entry.kind)
                .expect("entry present")
        };
        assert_eq!(by_name("sub"), dirent_type::DIR);
        assert_eq!(by_name("alpha"), dirent_type::FILE);
        assert_eq!(by_name("link"), dirent_type::LINK);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn read_dir_on_file_reports_enotdir() {
        let dir = std::env::temp_dir().join(format!("rn-dirent-enotdir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("plain");
        std::fs::write(&file, b"x").expect("write");

        let error =
            read_dir(file.as_os_str().as_encoded_bytes(), "scandir").expect_err("must fail");
        assert_eq!(error.code(), "ENOTDIR");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn read_dir_on_missing_path_reports_enoent() {
        let error = read_dir(b"/definitely/not/here/xyzzy", "scandir").expect_err("must fail");
        assert_eq!(error.code(), "ENOENT");
        assert_eq!(error.syscall, "scandir");
    }
}
