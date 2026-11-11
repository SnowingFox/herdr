//! Where the `fs` members ask the permission model.
//!
//! `src/node_file.cc` checks the same two scopes at every entry point, and the
//! order and the exact paths matter:
//!
//! * `access`, `existsSync`, `stat`, `lstat`, `statfs`, `readlink`, `realpath`,
//!   `readdir`, `readFileUtf8` and `copyFile`'s source need `fs.read`;
//! * `unlink`, `rmdir`, `rmSync`, `mkdir`, `chmod`, `chown`, `lchown`, `utimes`,
//!   `lutimes`, `mkdtemp` and `copyFile`'s destination need `fs.write`;
//! * `rename` and `link` need `fs.read` on the source and `fs.write` on both
//!   operands, so a rename cannot be used to write somewhere it could not write;
//! * `symlink` needs `fs.read` **and** `fs.write` on the target, because a link
//!   that is followed later reads whatever it points at, plus `fs.write` on the
//!   link itself;
//! * `open` picks the scopes from its flag word, since `O_WRONLY` needs only
//!   write while `O_RDWR` needs both.
//!
//! # Why each member checks separately
//!
//! Node checks in the binding rather than in `lib/fs.js` for everything except
//! `lstat`, `realpath`, `symlink` and a handful of others that its own
//! JavaScript gates too. Both layers are present in rustnode for the same
//! reason they are in Node: the JavaScript gate produces the error Node's docs
//! describe, and the binding gate is what a caller that reaches the binding
//! directly — `internalBinding('fs')`, which `--expose-internals` makes
//! reachable — cannot skip.
//!
//! # Cost
//!
//! With no model installed, or a disabled one, each helper returns `None` after
//! a `thread_local` borrow and a boolean load. Nothing resolves a path or takes
//! the model's lock, which is what keeps a run without `--permission` at its
//! previous speed.

use rn_permission::AccessDeniedError;

/// `fs.read` on `path`.
pub fn deny_read(path: &[u8]) -> Option<AccessDeniedError> {
    rn_permission::runtime::deny_fs_read(path)
}

/// `fs.write` on `path`.
pub fn deny_write(path: &[u8]) -> Option<AccessDeniedError> {
    rn_permission::runtime::deny_fs_write(path)
}

/// The two scopes `open`'s flag word implies, as
/// `CheckOpenPermissions` derives them.
///
/// The access-mode bits are a number rather than independent flags, so they are
/// masked as a pair: `O_WRONLY` needs only write, `O_RDWR` needs both, and
/// `O_RDONLY` (which is zero) needs only read. The side-effect bits are checked
/// separately because `O_CREAT` and `O_TRUNC` write even under `O_RDONLY`, which
/// is why `fs.openSync(path, 'r+')` and `fs.openSync(path, 'wx')` both need the
/// write scope.
pub fn deny_open(path: &[u8], flags: i32) -> Option<AccessDeniedError> {
    use crate::flags::uv_flags;

    let access = flags & (uv_flags::O_WRONLY | uv_flags::O_RDWR);
    let side_effects = flags
        & (uv_flags::O_APPEND
            | uv_flags::O_CREAT
            | uv_flags::O_TRUNC
            // Windows-only; `0` in `uv/unix.h`, so it contributes no bit here.
            | uv_flags::O_SYMLINK);
    // `O_TEMPORARY` has no libuv spelling on Unix; `O_EXCL` only matters with
    // `O_CREAT`, which is already covered.
    if access != uv_flags::O_WRONLY {
        if let Some(denied) = deny_read(path) {
            return Some(denied);
        }
    }
    if access != uv_flags::O_RDONLY || side_effects != 0 {
        if let Some(denied) = deny_write(path) {
            return Some(denied);
        }
    }
    None
}

/// `fs.read` on `source` then `fs.write` on `destination`, the shape `copyFile`
/// and `rename`-like members use.
pub fn deny_copy(source: &[u8], destination: &[u8]) -> Option<AccessDeniedError> {
    deny_read(source).or_else(|| deny_write(destination))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rn_permission::runtime;
    use rn_permission::{PermissionConfig, PermissionModel, PermissionScope};

    fn enforcing() -> std::sync::Arc<PermissionModel> {
        runtime::install(PermissionModel::with_cwd(
            "/work",
            PermissionConfig::enforce(),
        ))
    }

    #[test]
    fn nothing_is_denied_without_a_model() {
        runtime::clear();
        assert!(deny_read(b"/etc/passwd").is_none());
        assert!(deny_write(b"/etc/passwd").is_none());
        assert!(deny_open(b"/etc/passwd", crate::flags::uv_flags::O_RDONLY).is_none());
    }

    #[test]
    fn a_read_grant_does_not_grant_write() {
        let model = enforcing();
        // `*` rather than `/work`, because a directory grant is probed on disk
        // and `/work` does not exist here; a non-existent path grant covers only
        // itself.
        model.grant_fs(PermissionScope::FileSystemRead, "*");
        assert!(deny_read(b"/work/a").is_none());
        assert!(deny_write(b"/work/a").is_some());
    }

    #[test]
    fn open_needs_the_scope_its_flags_imply() {
        use crate::flags::uv_flags;
        let model = enforcing();
        model.grant_fs(PermissionScope::FileSystemRead, "*");

        // Read-only is covered by the read grant alone.
        assert!(deny_open(b"/work/a", uv_flags::O_RDONLY).is_none());
        // Write-only does not need read, but does need write.
        let denied = deny_open(b"/work/a", uv_flags::O_WRONLY).expect("denied");
        assert_eq!(denied.permission(), "FileSystemWrite");
        // Read-write needs both.
        let denied = deny_open(b"/work/a", uv_flags::O_RDWR).expect("denied");
        assert_eq!(denied.permission(), "FileSystemWrite");

        // The side-effect bits write even under `O_RDONLY`.
        for flag in [uv_flags::O_CREAT, uv_flags::O_TRUNC, uv_flags::O_APPEND] {
            assert!(
                deny_open(b"/work/a", uv_flags::O_RDONLY | flag).is_some(),
                "flag {flag:#x} must be treated as a write"
            );
        }
    }

    #[test]
    fn open_reports_the_read_denial_before_the_write_one() {
        // `O_RDWR` on an ungranted path fails both checks; Node reports the
        // read denial because `CheckOpenPermissions` tests read first.
        enforcing();
        let denied = deny_open(b"/etc/passwd", crate::flags::uv_flags::O_RDWR).expect("denied");
        assert_eq!(denied.permission(), "FileSystemRead");
    }

    #[test]
    fn copy_checks_the_source_before_the_destination() {
        enforcing();
        let denied = deny_copy(b"/etc/passwd", b"/etc/shadow").expect("denied");
        assert_eq!(denied.permission(), "FileSystemRead");
        assert_eq!(denied.resource(), "/etc/passwd");
    }

    #[test]
    fn audit_mode_denies_nothing() {
        runtime::install(PermissionModel::with_cwd(
            "/work",
            PermissionConfig::audit(),
        ));
        assert!(deny_read(b"/etc/passwd").is_none());
        assert!(deny_write(b"/etc/passwd").is_none());
    }
}
