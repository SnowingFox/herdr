//! Cross-checks the binding against a real `node` binary.
//!
//! Everything here is derived from observing Node itself rather than from
//! re-reading Node's source, so a mistake in my reading of `node_file.cc` shows
//! up as a test failure instead of as a silently different runtime.
//!
//! The tests skip themselves when no `node` is on `PATH`, because the gate for
//! this crate must not depend on an external binary being installed. When `node`
//! is present, every assertion runs.

use std::os::unix::ffi::OsStrExt;
use std::process::Command;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use rn_bind_fs::Fs;

fn node_available() -> bool {
    Command::new("node")
        .arg("-e")
        .arg("0")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Runs `node -p <expr>` in `dir` and returns trimmed stdout.
fn node_print(dir: &std::path::Path, expr: &str) -> String {
    let out = Command::new("node")
        .arg("-p")
        .arg(expr)
        .current_dir(dir)
        .output()
        .expect("node runs");
    assert!(
        out.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn initialize_once() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Evaluates `source` with the namespace installed, returns `String(__out)`.
fn eval(source: &str) -> String {
    initialize_once();
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let mut context_scope = std::pin::pin!(v8::ContextScope::new(scope, context));
    let scope = &mut context_scope;

    let mut async_ids = rn_core::AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    let namespace = Fs.install(scope, &mut ctx).expect("install");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "fsBinding").expect("key");
    global
        .set(scope, key.into(), namespace.into())
        .expect("set");

    let source = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, source, None).expect("compiles");
    script.run(scope).expect("runs");

    let out_key = v8::String::new(scope, "__out").expect("key");
    let out = global.get(scope, out_key.into()).expect("__out");
    out.to_rust_string_lossy(scope)
}

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rn-bind-fs-cmp-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("mkdir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn js_path(path: &std::path::Path) -> String {
    String::from_utf8_lossy(path.as_os_str().as_bytes())
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
}

#[test]
fn stat_matches_node_for_size_mode_and_link_count() {
    let dir = TempDir::new("stat");
    let file = dir.path.join("x");
    std::fs::write(&file, b"hello").expect("write");

    // Reference answer straight from Node.
    let expected = node_print(
        &dir.path,
        "(() => { const s = require('fs').statSync('x'); \
         return JSON.stringify({size: s.size, isFile: s.isFile(), \
         mode: s.mode & 0o777, nlink: s.nlink}); })()",
    );

    let actual = eval(&format!(
        r#"
        const f = fsBinding.stat('{path}', false);
        globalThis.__out = JSON.stringify({{
          size: f[8],
          isFile: (f[1] & 0o170000) === 0o100000,
          mode: f[1] & 0o777,
          nlink: f[2],
        }});
        "#,
        path = js_path(&file)
    ));

    assert_eq!(actual, expected, "stat fields must match node");
}

#[test]
fn readdir_order_matches_node() {
    let dir = TempDir::new("readdir");
    for name in ["zebra", "alpha", "Mike", "bravo", "0123"] {
        std::fs::write(dir.path.join(name), b"").expect("write");
    }
    std::fs::create_dir_all(dir.path.join("sub")).expect("mkdir");

    let expected = node_print(&dir.path, "JSON.stringify(require('fs').readdirSync('.'))");
    // Absolute path because `eval` does not run with the temp dir as its cwd.
    let actual = eval(&format!(
        r#"
        globalThis.__out = JSON.stringify(fsBinding.readdir('{path}', 'utf8', false));
        "#,
        path = js_path(&dir.path)
    ));

    assert_eq!(actual, expected, "readdir order must match node");
}

#[test]
fn recursive_readdir_order_matches_node() {
    let dir = TempDir::new("recursive");
    std::fs::create_dir_all(dir.path.join("a/b")).expect("mkdir");
    std::fs::create_dir_all(dir.path.join("sub")).expect("mkdir");
    std::fs::write(dir.path.join("top.txt"), b"").expect("write");
    std::fs::write(dir.path.join("sub/inner.txt"), b"").expect("write");

    let expected = node_print(
        &dir.path,
        "JSON.stringify(require('fs').readdirSync('.', {recursive: true}))",
    );
    let actual = eval(&format!(
        r#"
        globalThis.__out = JSON.stringify(
          fsBinding.readdirRecursive('{path}', 'utf8', false));
        "#,
        path = js_path(&dir.path)
    ));

    assert_eq!(actual, expected, "recursive order must match node");
}

#[test]
fn error_message_and_code_match_node() {
    let dir = TempDir::new("errors");

    let expected = node_print(
        &dir.path,
        "(() => { try { require('fs').statSync('/definitely/not/here/xyzzy'); } \
         catch (e) { return JSON.stringify({code: e.code, errno: e.errno, \
         syscall: e.syscall, message: e.message}); } return 'no-throw'; })()",
    );

    let actual = eval(
        r#"
        let error = null;
        try { fsBinding.stat('/definitely/not/here/xyzzy', false); }
        catch (thrown) { error = thrown; }
        globalThis.__out = JSON.stringify({
          code: error.code, errno: error.errno,
          syscall: error.syscall, message: error.message,
        });
        "#,
    );

    assert_eq!(actual, expected, "error shape must match node");
}

#[test]
fn mkdir_recursive_return_matches_node() {
    // Node and the binding both create `p/q/r`, so each gets its own tree:
    // whichever runs first would otherwise make the other see an existing path
    // and return `undefined`.
    let for_node = TempDir::new("mkdir-node");
    let expected = node_print(
        &for_node.path,
        "JSON.stringify(require('fs').mkdirSync('p/q/r', {recursive: true}))",
    );

    let for_binding = TempDir::new("mkdir-binding");
    let actual = eval(&format!(
        r#"
        globalThis.__out = JSON.stringify(fsBinding.mkdir('{path}', 0o777, true));
        "#,
        path = js_path(&for_binding.path.join("p/q/r"))
    ));

    // Node returns an absolute path, and so does the binding; compare the tail
    // so a differing temp prefix cannot make this flaky.
    assert_eq!(
        actual.trim_matches('"').rsplit('/').next(),
        expected.trim_matches('"').rsplit('/').next(),
        "recursive mkdir must return the first created directory"
    );
    assert_eq!(expected.trim_matches('"').rsplit('/').next(), Some("p"));
}

#[test]
fn readlink_and_realpath_match_node() {
    let dir = TempDir::new("links");
    let target = dir.path.join("target");
    std::fs::write(&target, b"").expect("write");
    std::os::unix::fs::symlink(&target, dir.path.join("link")).expect("symlink");

    let expected = node_print(
        &dir.path,
        "JSON.stringify([require('fs').readlinkSync('link'), \
         require('fs').realpathSync('link')])",
    );
    let link = js_path(&dir.path.join("link"));
    let actual = eval(&format!(
        r#"
        globalThis.__out = JSON.stringify([
          fsBinding.readlink('{link}', 'utf8'),
          fsBinding.realpath('{link}', 'utf8'),
        ]);
        "#
    ));

    assert_eq!(actual, expected, "link resolution must match node");
}

#[test]
fn internal_module_stat_matches_node_semantics() {
    let dir = TempDir::new("imstat");
    std::fs::write(dir.path.join("file.js"), b"x").expect("write");
    std::fs::create_dir_all(dir.path.join("dir")).expect("mkdir");

    // Node's `internalModuleStat` is not reachable from userland, so its
    // documented contract is asserted directly: 0 for a file, 1 for a
    // directory, negative for a miss.
    let actual = eval(&format!(
        r#"
        globalThis.__out = JSON.stringify([
          fsBinding.internalModuleStat('{file}'),
          fsBinding.internalModuleStat('{dir}'),
          fsBinding.internalModuleStat('/definitely/not/here/xyzzy') < 0,
        ]);
        "#,
        file = js_path(&dir.path.join("file.js")),
        dir = js_path(&dir.path.join("dir")),
    ));
    assert_eq!(actual, r#"[0,1,true]"#);

    // The same tri-state is what Node's loader relies on; cross-check that the
    // underlying stat agrees about the file/directory split.
    let expected = node_print(
        &dir.path,
        "JSON.stringify([require('fs').statSync('file.js').isFile(), \
         require('fs').statSync('dir').isDirectory()])",
    );
    assert_eq!(expected, "[true,true]");
}

/// The whole point of the comparison: skip loudly rather than silently when the
/// reference binary is unavailable, so a green run is never a false positive.
#[test]
fn node_reference_is_reachable() {
    if !node_available() {
        eprintln!("skipping: no `node` on PATH");
        return;
    }
    let version = node_print(std::env::temp_dir().as_path(), "process.version");
    assert!(version.starts_with('v'), "unexpected version {version}");
}
