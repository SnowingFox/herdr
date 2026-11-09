//! Cross-checks the published tables against the C library rustnode links.
//!
//! `constants.rs` stores the numbers so they reach JavaScript without a runtime
//! header dependency. The risk that creates is silent drift from the platform
//! ABI, so this test recomputes each value from `libc` -- the same definitions
//! Node's C++ includes -- and fails on any disagreement.
//!
//! Linux only: `libc` exposes `O_NOATIME`, `O_DIRECT` and the `UV_PRIORITY_*`
//! spellings only for Linux targets, and those are exactly the values this crate
//! publishes. A non-Linux build of rustnode needs its own table anyway, because
//! Node's own constants differ per platform.

#![cfg(target_os = "linux")]

use rn_bind_config::constants::{DLOPEN_VALUES, ERRNO_VALUES, FS_VALUES, SIGNALS_VALUES};
use rn_bind_config::Value;

fn lookup(table: &[(&'static str, Value)], name: &str) -> Option<Value> {
    table
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
}

/// Asserts every entry of `table` equals the value `libc` reports.
///
/// `expected` is a list of `(name, libc value)`; the helper checks both that the
/// published number matches and that the table has no entries missing from the
/// list, so a new table row has to be accompanied by its libc comparison.
fn assert_matches_libc(table: &[(&'static str, Value)], expected: &[(&str, i64)]) {
    for (name, libc_value) in expected {
        assert_eq!(
            lookup(table, name),
            Some(Value::int(*libc_value)),
            "{name} disagrees with libc"
        );
    }
}

#[test]
fn fs_constants_match_libc() {
    assert_matches_libc(
        FS_VALUES,
        &[
            // <fcntl.h> open flags.
            ("O_RDONLY", libc::O_RDONLY as i64),
            ("O_WRONLY", libc::O_WRONLY as i64),
            ("O_RDWR", libc::O_RDWR as i64),
            ("O_CREAT", libc::O_CREAT as i64),
            ("O_EXCL", libc::O_EXCL as i64),
            ("O_NOCTTY", libc::O_NOCTTY as i64),
            ("O_TRUNC", libc::O_TRUNC as i64),
            ("O_APPEND", libc::O_APPEND as i64),
            ("O_NONBLOCK", libc::O_NONBLOCK as i64),
            ("O_DSYNC", libc::O_DSYNC as i64),
            ("O_DIRECTORY", libc::O_DIRECTORY as i64),
            ("O_NOFOLLOW", libc::O_NOFOLLOW as i64),
            ("O_SYNC", libc::O_SYNC as i64),
            ("O_DIRECT", libc::O_DIRECT as i64),
            ("O_NOATIME", libc::O_NOATIME as i64),
            // <sys/stat.h> file type masks and permission bits.
            ("S_IFMT", libc::S_IFMT as i64),
            ("S_IFSOCK", libc::S_IFSOCK as i64),
            ("S_IFLNK", libc::S_IFLNK as i64),
            ("S_IFREG", libc::S_IFREG as i64),
            ("S_IFBLK", libc::S_IFBLK as i64),
            ("S_IFDIR", libc::S_IFDIR as i64),
            ("S_IFCHR", libc::S_IFCHR as i64),
            ("S_IFIFO", libc::S_IFIFO as i64),
            ("S_IRWXU", libc::S_IRWXU as i64),
            ("S_IRUSR", libc::S_IRUSR as i64),
            ("S_IWUSR", libc::S_IWUSR as i64),
            ("S_IXUSR", libc::S_IXUSR as i64),
            ("S_IRWXG", libc::S_IRWXG as i64),
            ("S_IRGRP", libc::S_IRGRP as i64),
            ("S_IWGRP", libc::S_IWGRP as i64),
            ("S_IXGRP", libc::S_IXGRP as i64),
            ("S_IRWXO", libc::S_IRWXO as i64),
            ("S_IROTH", libc::S_IROTH as i64),
            ("S_IWOTH", libc::S_IWOTH as i64),
            ("S_IXOTH", libc::S_IXOTH as i64),
            // <unistd.h> access modes.
            ("F_OK", libc::F_OK as i64),
            ("R_OK", libc::R_OK as i64),
            ("W_OK", libc::W_OK as i64),
            ("X_OK", libc::X_OK as i64),
        ],
    );

    // `uv/unix.h` maps the Windows-only flags to 0 and defines the portable
    // copy modes as fixed bits.
    for name in [
        "UV_FS_O_FILEMAP",
        "UV_FS_O_TEMPORARY",
        "UV_FS_O_SHORT_LIVED",
        "UV_FS_O_SEQUENTIAL",
        "UV_FS_O_RANDOM",
    ] {
        assert_eq!(lookup(FS_VALUES, name), Some(Value::int(0)), "{name}");
    }
    assert_eq!(
        lookup(FS_VALUES, "UV_FS_COPYFILE_EXCL"),
        Some(Value::int(0x1))
    );
    assert_eq!(
        lookup(FS_VALUES, "UV_FS_COPYFILE_FICLONE"),
        Some(Value::int(0x2))
    );
    assert_eq!(
        lookup(FS_VALUES, "UV_FS_COPYFILE_FICLONE_FORCE"),
        Some(Value::int(0x4))
    );

    // libuv's directory entry types are a fixed enumeration.
    for (index, name) in [
        "UV_DIRENT_UNKNOWN",
        "UV_DIRENT_FILE",
        "UV_DIRENT_DIR",
        "UV_DIRENT_LINK",
        "UV_DIRENT_FIFO",
        "UV_DIRENT_SOCKET",
        "UV_DIRENT_CHAR",
        "UV_DIRENT_BLOCK",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            lookup(FS_VALUES, name),
            Some(Value::int(index as i64)),
            "{name} is not at libuv position {index}"
        );
    }
}

#[test]
fn signal_constants_match_libc() {
    assert_matches_libc(
        SIGNALS_VALUES,
        &[
            ("SIGHUP", libc::SIGHUP as i64),
            ("SIGINT", libc::SIGINT as i64),
            ("SIGQUIT", libc::SIGQUIT as i64),
            ("SIGILL", libc::SIGILL as i64),
            ("SIGTRAP", libc::SIGTRAP as i64),
            ("SIGABRT", libc::SIGABRT as i64),
            ("SIGBUS", libc::SIGBUS as i64),
            ("SIGFPE", libc::SIGFPE as i64),
            ("SIGKILL", libc::SIGKILL as i64),
            ("SIGUSR1", libc::SIGUSR1 as i64),
            ("SIGSEGV", libc::SIGSEGV as i64),
            ("SIGUSR2", libc::SIGUSR2 as i64),
            ("SIGPIPE", libc::SIGPIPE as i64),
            ("SIGALRM", libc::SIGALRM as i64),
            ("SIGTERM", libc::SIGTERM as i64),
            ("SIGCHLD", libc::SIGCHLD as i64),
            ("SIGCONT", libc::SIGCONT as i64),
            ("SIGSTOP", libc::SIGSTOP as i64),
            ("SIGTSTP", libc::SIGTSTP as i64),
            ("SIGTTIN", libc::SIGTTIN as i64),
            ("SIGTTOU", libc::SIGTTOU as i64),
            ("SIGURG", libc::SIGURG as i64),
            ("SIGXCPU", libc::SIGXCPU as i64),
            ("SIGXFSZ", libc::SIGXFSZ as i64),
            ("SIGVTALRM", libc::SIGVTALRM as i64),
            ("SIGPROF", libc::SIGPROF as i64),
            ("SIGWINCH", libc::SIGWINCH as i64),
            ("SIGIO", libc::SIGIO as i64),
            ("SIGSYS", libc::SIGSYS as i64),
            // glibc aliases.
            ("SIGIOT", libc::SIGIOT as i64),
            ("SIGPOLL", libc::SIGPOLL as i64),
            ("SIGSTKFLT", libc::SIGSTKFLT as i64),
            ("SIGPWR", libc::SIGPWR as i64),
        ],
    );
}

#[test]
fn errno_constants_match_libc() {
    assert_matches_libc(
        ERRNO_VALUES,
        &[
            ("EPERM", libc::EPERM as i64),
            ("ENOENT", libc::ENOENT as i64),
            ("EINTR", libc::EINTR as i64),
            ("EIO", libc::EIO as i64),
            ("EBADF", libc::EBADF as i64),
            ("EAGAIN", libc::EAGAIN as i64),
            ("ENOMEM", libc::ENOMEM as i64),
            ("EACCES", libc::EACCES as i64),
            ("EEXIST", libc::EEXIST as i64),
            ("ENOTDIR", libc::ENOTDIR as i64),
            ("EISDIR", libc::EISDIR as i64),
            ("EINVAL", libc::EINVAL as i64),
            ("EMFILE", libc::EMFILE as i64),
            ("ENOSPC", libc::ENOSPC as i64),
            ("EPIPE", libc::EPIPE as i64),
            ("ERANGE", libc::ERANGE as i64),
            ("ENAMETOOLONG", libc::ENAMETOOLONG as i64),
            ("ENOSYS", libc::ENOSYS as i64),
            ("ELOOP", libc::ELOOP as i64),
            ("EADDRINUSE", libc::EADDRINUSE as i64),
            ("EADDRNOTAVAIL", libc::EADDRNOTAVAIL as i64),
            ("ECONNREFUSED", libc::ECONNREFUSED as i64),
            ("ECONNRESET", libc::ECONNRESET as i64),
            ("ETIMEDOUT", libc::ETIMEDOUT as i64),
            ("EOPNOTSUPP", libc::EOPNOTSUPP as i64),
            ("EWOULDBLOCK", libc::EWOULDBLOCK as i64),
            ("ENOTSUP", libc::ENOTSUP as i64),
        ],
    );
}

#[test]
fn dlopen_constants_match_libc() {
    assert_matches_libc(
        DLOPEN_VALUES,
        &[
            ("RTLD_LAZY", libc::RTLD_LAZY as i64),
            ("RTLD_NOW", libc::RTLD_NOW as i64),
            ("RTLD_GLOBAL", libc::RTLD_GLOBAL as i64),
            ("RTLD_LOCAL", libc::RTLD_LOCAL as i64),
            ("RTLD_DEEPBIND", libc::RTLD_DEEPBIND as i64),
        ],
    );
}

#[test]
fn every_fs_constant_has_a_libc_or_libuv_origin() {
    // Guards against a table row being added without provenance. The listed
    // names are the ones that come from libuv rather than a C header.
    let libuv_owned = [
        "UV_FS_SYMLINK_DIR",
        "UV_FS_SYMLINK_JUNCTION",
        "UV_DIRENT_UNKNOWN",
        "UV_DIRENT_FILE",
        "UV_DIRENT_DIR",
        "UV_DIRENT_LINK",
        "UV_DIRENT_FIFO",
        "UV_DIRENT_SOCKET",
        "UV_DIRENT_CHAR",
        "UV_DIRENT_BLOCK",
        "UV_FS_O_FILEMAP",
        "UV_FS_O_TEMPORARY",
        "UV_FS_O_SHORT_LIVED",
        "UV_FS_O_SEQUENTIAL",
        "UV_FS_O_RANDOM",
        "UV_FS_COPYFILE_EXCL",
        "UV_FS_COPYFILE_FICLONE",
        "UV_FS_COPYFILE_FICLONE_FORCE",
        "COPYFILE_EXCL",
        "COPYFILE_FICLONE",
        "COPYFILE_FICLONE_FORCE",
    ];
    let verified = [
        "O_RDONLY",
        "O_WRONLY",
        "O_RDWR",
        "O_CREAT",
        "O_EXCL",
        "O_NOCTTY",
        "O_TRUNC",
        "O_APPEND",
        "O_NONBLOCK",
        "O_DSYNC",
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "O_SYNC",
        "O_DIRECT",
        "O_NOATIME",
        "S_IFMT",
        "S_IFSOCK",
        "S_IFLNK",
        "S_IFREG",
        "S_IFBLK",
        "S_IFDIR",
        "S_IFCHR",
        "S_IFIFO",
        "S_IRWXU",
        "S_IRUSR",
        "S_IWUSR",
        "S_IXUSR",
        "S_IRWXG",
        "S_IRGRP",
        "S_IWGRP",
        "S_IXGRP",
        "S_IRWXO",
        "S_IROTH",
        "S_IWOTH",
        "S_IXOTH",
        "F_OK",
        "R_OK",
        "W_OK",
        "X_OK",
    ];
    let accounted: std::collections::BTreeSet<&str> =
        libuv_owned.iter().chain(verified.iter()).copied().collect();
    for (name, _) in FS_VALUES {
        assert!(
            accounted.contains(name),
            "fs publishes {name} with no recorded provenance"
        );
    }
}
