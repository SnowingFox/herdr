//! Parity with the real Node binary.
//!
//! Every expectation below was recorded by asking Node itself, not read off the
//! C++. The probes are the shapes `test/parallel/test-permission-fs-*.js` uses,
//! so a regression here means a Node test would have failed too.
//!
//! Recording procedure, from a checkout of the pinned revision:
//!
//! ```bash
//! node --permission --allow-fs-read=<pattern> -e \
//!   'console.log(process.permission.has("fs.read", "<probe>"))'
//! ```
//!
//! Run against Node 22.23.4, which answers the same as the pinned 28.0.0 for
//! everything here; `test-permission-fs-wildcard.js` asserts these exact values.

use rn_permission::model::{PermissionConfig, PermissionModel, PermissionScope};

fn read_model(patterns: &[&str]) -> PermissionModel {
    PermissionModel::with_cwd(
        "/",
        PermissionConfig {
            allow_fs_read: patterns.iter().map(|pattern| pattern.to_string()).collect(),
            ..PermissionConfig::enforce()
        },
    )
}

fn has(model: &PermissionModel, path: &str) -> bool {
    model.has(PermissionScope::FileSystemRead, Some(path))
}

/// `--allow-fs-read=/tmp/test*`: a prefix wildcard keeps the literal prefix and
/// covers everything from there on.
#[test]
fn prefix_wildcard_matches_node() {
    let model = read_model(&["/tmp/test*"]);
    assert!(has(&model, "/tmp/test"));
    assert!(has(&model, "/tmp/test/"));
    assert!(has(&model, "/tmp/test/file"));
    assert!(has(&model, "/tmp/test2"));
    assert!(!has(&model, "/tmp/tes"));
    assert!(!has(&model, "/tmp/te"));
}

/// `--allow-fs-read=/a/b/*`: a directory wildcard also matches the directory
/// itself, with or without a trailing separator, but not its siblings.
#[test]
fn directory_wildcard_matches_node() {
    let model = read_model(&["/a/b/*"]);
    assert!(has(&model, "/a/b/c"));
    assert!(has(&model, "/a/b"));
    assert!(has(&model, "/a/b/"));
    assert!(!has(&model, "/a/c/c"));
    assert!(!has(&model, "/a/bc"));
    assert!(!has(&model, "/a/"));
}

/// `--allow-fs-read=/etc/passwd.*` and `/home/*.js`: after the first `*`, the
/// rest of the pattern is ignored, so `/home/*.js` behaves like `/home/*`.
#[test]
fn a_suffix_after_a_wildcard_is_ignored_like_node() {
    let model = read_model(&["/etc/passwd.*", "/home/*.js"]);
    assert!(!has(&model, "/etc/passwd"));
    assert!(!has(&model, "/etc/password"));
    assert!(has(&model, "/home/another-file.md"));
    assert!(has(&model, "/home/x.js"));
    assert!(has(&model, "/home/"));
}

/// `--allow-fs-read=/show /slower /slown` alongside `/*` shapes: an exact grant
/// covers only itself, so `/slow` and `/slows` stay denied.
#[test]
fn exact_grants_do_not_leak_prefixes_like_node() {
    let model = read_model(&["/show", "/slower", "/slown"]);
    assert!(has(&model, "/show"));
    assert!(!has(&model, "/show/x"));
    assert!(has(&model, "/slown"));
    assert!(!has(&model, "/slow"));
    assert!(!has(&model, "/slows"));
}

/// `--allow-fs-read=/files/index.js`: an exact file grant matches the file, and
/// the probe's trailing separator is removed by resolution before the lookup.
#[test]
fn exact_file_grants_match_node() {
    let model = read_model(&["/files/index.js", "/files/index.json", "/files/i"]);
    assert!(has(&model, "/files/index.js"));
    assert!(has(&model, "/files/index.json"));
    assert!(has(&model, "/files/i"));
    assert!(!has(&model, "/files/index.j"));
}

/// `--allow-fs-read=*` grants the read scope outright, which is a different
/// answer from having no grants at all.
#[test]
fn star_grants_the_scope_like_node() {
    let model = read_model(&["*"]);
    assert!(has(&model, "/anything"));
    assert!(has(&model, "/"));
    // `has('fs.read')` with no reference answers "is the scope open".
    assert!(model.has(PermissionScope::FileSystemRead, None));
    // `has('fs')` needs both halves, and write is still closed.
    assert!(!model.has(PermissionScope::FileSystem, None));
    assert!(!model.has(PermissionScope::FileSystemWrite, None));
}

/// `--allow-fs-read=/` grants the whole tree, because `/` exists and so is
/// widened to `//*` → `/*`. Node answers `true` for `/x`, `/` and `/tmp/y`.
#[test]
fn granting_the_root_covers_everything_like_node() {
    let model = read_model(&["/"]);
    assert!(has(&model, "/x"));
    assert!(has(&model, "/"));
    assert!(has(&model, "/tmp/y"));
}

/// A path grant does not open the bare scope: Node answers `false` for
/// `has('fs.read')` even with `--allow-fs-read=/tmp`.
#[test]
fn a_path_grant_does_not_open_the_bare_scope() {
    let model = read_model(&["/tmp/*"]);
    assert!(!model.has(PermissionScope::FileSystemRead, None));
    assert!(has(&model, "/tmp/x"));
}

/// A grant naming an existing directory gains `/*`; one naming a path that does
/// not exist does not. This is `WildcardIfDir()` and it is why
/// `/tmp/does-not-exist` grants only itself.
#[test]
fn existing_directories_are_widened_like_node() {
    let existing = std::env::temp_dir();
    let existing = existing.to_str().expect("temp dir is utf-8");
    let model = read_model(&[existing]);
    assert!(has(&model, existing));
    assert!(has(&model, &format!("{existing}/rn-permission-probe")));

    let missing = "/rn-permission-definitely-not-here";
    let model = read_model(&[missing]);
    assert!(has(&model, missing));
    assert!(!has(&model, &format!("{missing}/child")));
}

/// Error fields, matching what `fs.readFileSync('/etc/hostname')` throws under
/// `--permission`:
/// `{"code":"ERR_ACCESS_DENIED","permission":"FileSystemRead","resource":"/etc/hostname"}`.
#[test]
fn denial_fields_match_node() {
    let model = read_model(&[]);
    let denied = model.check_fs_read("/etc/hostname").unwrap_err();
    assert_eq!(denied.code(), "ERR_ACCESS_DENIED");
    assert_eq!(denied.permission(), "FileSystemRead");
    assert_eq!(denied.resource(), "/etc/hostname");
    assert_eq!(
        denied.message(),
        "Access to this API has been restricted. Use --allow-fs-read to manage permissions."
    );
}

/// The resource Node reports is the path as the caller passed it, not the
/// resolved one: `fs.readFileSync('./nope.txt')` reports `./nope.txt`.
#[test]
fn the_reported_resource_is_the_argument_as_given() {
    let model = PermissionModel::with_cwd("/work", PermissionConfig::enforce());
    let denied = model.check_fs_read("./nope.txt").unwrap_err();
    assert_eq!(denied.resource(), "./nope.txt");
    let denied = model.check_fs_write("d/../../etc/hostname").unwrap_err();
    assert_eq!(denied.resource(), "d/../../etc/hostname");
}

/// Child process, worker and wasi denials, as observed from
/// `spawnSync`, `new Worker()` and `new WASI()` under `--permission`.
#[test]
fn non_filesystem_denials_match_node() {
    let model = PermissionModel::with_cwd("/work", PermissionConfig::enforce());
    let denied = model.check_child_process_resource("true").unwrap_err();
    assert_eq!(denied.permission(), "ChildProcess");
    assert_eq!(denied.resource(), "true");

    let denied = model.check_worker().unwrap_err();
    assert_eq!(denied.permission(), "WorkerThreads");
    assert_eq!(denied.resource(), "");

    let denied = model.check_wasi().unwrap_err();
    assert_eq!(denied.permission(), "WASI");
    assert_eq!(denied.resource(), "");
}

/// Node does not defend against symlink escapes, and neither does this model.
///
/// `doc/api/permissions.md`, "Limitations and Known Issues": "Symbolic links
/// will be followed even to locations outside of the set of paths that access
/// has been granted to." The check compares the path the caller passed, so a
/// path that is inside a granted directory but resolves, through a symlink, to
/// something outside it is granted.
///
/// This pins the behaviour deliberately: it is what Node does, and "fixing" it
/// here would both diverge from Node and cost a `realpath` per check. It is
/// recorded as a test so the gap is explicit rather than assumed absent.
#[test]
fn a_symlink_outside_the_grant_is_not_resolved() {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!("rn-permission-symlink-{}", std::process::id()));
    let granted = root.join("granted");
    let secret = root.join("secret");
    std::fs::create_dir_all(&granted).expect("create granted dir");
    std::fs::create_dir_all(&secret).expect("create secret dir");
    std::fs::write(secret.join("key.pem"), b"secret").expect("write secret");

    let link = granted.join("escape");
    let _ = std::fs::remove_file(&link);
    symlink(&secret, &link).expect("create symlink");

    let granted = granted.to_str().expect("utf-8").to_string();
    let model = read_model(&[&granted]);

    // The granted path itself is allowed...
    assert!(has(&model, &format!("{granted}/readme.txt")));
    // ...and so is the path through the symlink, because it is still spelled
    // with the granted prefix. Node answers the same.
    assert!(has(&model, &format!("{granted}/escape/key.pem")));
    // The secret's real path is denied, which is the only thing the check can
    // see.
    assert!(!has(&model, secret.to_str().expect("utf-8")));
}
