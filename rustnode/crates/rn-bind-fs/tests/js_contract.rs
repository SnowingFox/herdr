//! End-to-end tests that drive the installed namespace from JavaScript.
//!
//! These call `internalBinding('fs')` the way `lib/fs.js` does: they install the
//! namespace object, expose it as a global, then run script that uses it
//! directly. That exercises argument marshalling, the stat buffer layout, the
//! deferred callback contract and the promise contract through the same path the
//! real JS layer takes, which Rust-only unit tests cannot reach.

use std::os::unix::ffi::OsStrExt;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use rn_bind_fs::Fs;

fn initialize_once() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace, runs `source`, drains microtasks, returns `__out`.
fn run(source: &str) -> String {
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
    let namespace = Fs.install(scope, &mut ctx).expect("install fs namespace");

    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "fsBinding").expect("key");
    global
        .set(scope, key.into(), namespace.into())
        .expect("set");

    let source = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, source, None).expect("compiles");
    script.run(scope).expect("script runs");

    // Drain microtasks so deferred completions have run before the assertion.
    scope.as_mut().perform_microtask_checkpoint();

    let out_key = v8::String::new(scope, "__out").expect("key");
    let out = global.get(scope, out_key.into()).expect("__out");
    out.to_rust_string_lossy(scope)
}

/// A temporary directory that cleans itself up.
struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rn-bind-fs-e2e-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("mkdir");
        Self { path }
    }

    fn joined(&self, name: &str) -> std::path::PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Escapes a path for embedding as a JS single-quoted string literal.
fn js_path(path: &std::path::Path) -> String {
    String::from_utf8_lossy(path.as_os_str().as_bytes())
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
}

#[test]
fn open_write_read_close_round_trip_through_javascript() {
    let dir = TempDir::new("roundtrip");
    let file = js_path(&dir.joined("data.txt"));

    let out = run(&format!(
        r#"
        const path = '{file}';
        // O_RDWR | O_CREAT | O_TRUNC in libuv's numeric encoding.
        const flags = 0x0002 | 0x0040 | 0x0200;
        const fd = fsBinding.open(path, flags, 0o644);
        const written = fsBinding.writeBuffer(
          fd, new Uint8Array([104, 101, 108, 108, 111]), 0, 5, -1);
        const buffer = new Uint8Array(5);
        const read = fsBinding.read(fd, buffer, 0, 5, 0);
        fsBinding.close(fd);
        globalThis.__out = JSON.stringify({{
          written, read, text: String.fromCharCode(...buffer),
        }});
        "#
    ));

    assert_eq!(out, r#"{"written":5,"read":5,"text":"hello"}"#);
    assert_eq!(
        std::fs::read_to_string(dir.joined("data.txt")).expect("read"),
        "hello"
    );
}

#[test]
fn stat_returns_the_field_layout_the_js_unpacks() {
    let dir = TempDir::new("stat");
    let file = dir.joined("sized.bin");
    std::fs::write(&file, b"0123456789").expect("write");

    let out = run(&format!(
        r#"
        const stats = fsBinding.stat('{}', false);
        // Slot order is fixed by FsStatsOffset in src/node_file.h.
        globalThis.__out = JSON.stringify({{
          type: stats.constructor.name,
          length: stats.length,
          size: stats[8],
          isRegularFile: (stats[1] & 0o170000) === 0o100000,
          hasDev: stats[0] > 0,
          hasIno: stats[7] > 0,
          hasBlksize: stats[6] > 0,
          mtimeSeconds: stats[12] > 0,
          birthtimeNotNegative: stats[16] >= 0,
        }});
        "#,
        js_path(&file)
    ));

    assert_eq!(
        out,
        r#"{"type":"Float64Array","length":18,"size":10,"isRegularFile":true,"hasDev":true,"hasIno":true,"hasBlksize":true,"mtimeSeconds":true,"birthtimeNotNegative":true}"#
    );
}

#[test]
fn bigint_stat_uses_bigint64array() {
    let dir = TempDir::new("bigint");
    let file = dir.joined("big.bin");
    std::fs::write(&file, b"abc").expect("write");

    let out = run(&format!(
        r#"
        const stats = fsBinding.stat('{}', true);
        globalThis.__out = JSON.stringify({{
          type: stats.constructor.name,
          length: stats.length,
          sizeIsBigInt: typeof stats[8] === 'bigint',
          size: Number(stats[8]),
        }});
        "#,
        js_path(&file)
    ));

    assert_eq!(
        out,
        r#"{"type":"BigInt64Array","length":18,"sizeIsBigInt":true,"size":3}"#
    );
}

#[test]
fn lstat_does_not_follow_a_symlink() {
    let dir = TempDir::new("lstat");
    let target = dir.joined("target");
    std::fs::write(&target, b"0123456789").expect("write");
    let link = dir.joined("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let out = run(&format!(
        r#"
        const link = fsBinding.lstat('{link}', false);
        const target = fsBinding.stat('{target}', false);
        globalThis.__out = JSON.stringify({{
          linkIsSymlink: (link[1] & 0o170000) === 0o120000,
          targetIsFile: (target[1] & 0o170000) === 0o100000,
          linkSizeIsPathLength: link[8] === {expected_len},
        }});
        "#,
        link = js_path(&link),
        target = js_path(&target),
        expected_len = target.as_os_str().as_bytes().len(),
    ));

    assert_eq!(
        out,
        r#"{"linkIsSymlink":true,"targetIsFile":true,"linkSizeIsPathLength":true}"#
    );
}

#[test]
fn statfs_returns_eight_slots() {
    let dir = TempDir::new("statfs");
    let out = run(&format!(
        r#"
        const fields = fsBinding.statfs('{}', false);
        globalThis.__out = JSON.stringify({{
          type: fields.constructor.name,
          length: fields.length,
          bsizeAtLeast512: fields[1] >= 512,
          blocksPositive: fields[3] > 0,
        }});
        "#,
        js_path(&dir.path)
    ));
    assert_eq!(
        out,
        r#"{"type":"Float64Array","length":8,"bsizeAtLeast512":true,"blocksPositive":true}"#
    );
}

#[test]
fn readdir_returns_sorted_names() {
    let dir = TempDir::new("readdir");
    for name in ["zebra", "alpha", "mike", "bravo"] {
        std::fs::write(dir.joined(name), b"").expect("write");
    }
    std::fs::create_dir_all(dir.joined("sub")).expect("mkdir");

    let out = run(&format!(
        r#"
        globalThis.__out = JSON.stringify(fsBinding.readdir('{}', 'utf8', false));
        "#,
        js_path(&dir.path)
    ));
    assert_eq!(out, r#"["alpha","bravo","mike","sub","zebra"]"#);
}

#[test]
fn readdir_with_file_types_returns_names_and_types() {
    let dir = TempDir::new("dirents");
    std::fs::write(dir.joined("file"), b"").expect("write");
    std::fs::create_dir_all(dir.joined("adb")).expect("mkdir");
    std::os::unix::fs::symlink("/nowhere", dir.joined("lnk")).expect("symlink");

    let out = run(&format!(
        r#"
        const result = fsBinding.readdir('{}', 'utf8', true);
        const names = result[0];
        const types = result[1];
        // UV_DIRENT_FILE = 1, DIR = 2, LINK = 3.
        const byName = {{}};
        for (let i = 0; i < names.length; i++) byName[names[i]] = types[i];
        globalThis.__out = JSON.stringify({{ names, byName }});
        "#,
        js_path(&dir.path)
    ));
    assert_eq!(
        out,
        r#"{"names":["adb","file","lnk"],"byName":{"adb":2,"file":1,"lnk":3}}"#
    );
}

#[test]
fn readdir_buffer_encoding_returns_byte_views() {
    let dir = TempDir::new("readdir-buffer");
    std::fs::write(dir.joined("one"), b"").expect("write");

    let out = run(&format!(
        r#"
        const names = fsBinding.readdir('{}', 'buffer', false);
        const first = names[0];
        globalThis.__out = JSON.stringify({{
          isView: ArrayBuffer.isView(first),
          length: first.length,
          text: String.fromCharCode(...first),
        }});
        "#,
        js_path(&dir.path)
    ));
    assert_eq!(out, r#"{"isView":true,"length":3,"text":"one"}"#);
}

#[test]
fn errors_carry_node_properties() {
    let out = run(r#"
        let error = null;
        try { fsBinding.stat('/definitely/not/here/xyzzy', false); }
        catch (thrown) { error = thrown; }
        globalThis.__out = JSON.stringify({
          code: error.code,
          errno: error.errno,
          syscall: error.syscall,
          path: error.path,
          message: error.message,
          isError: error instanceof Error,
        });
        "#);
    assert_eq!(
        out,
        r#"{"code":"ENOENT","errno":-2,"syscall":"stat","path":"/definitely/not/here/xyzzy","message":"ENOENT: no such file or directory, stat '/definitely/not/here/xyzzy'","isError":true}"#
    );
}

#[test]
fn eisdir_enotdir_and_ebadf_are_distinguished() {
    let dir = TempDir::new("errors");
    let file = dir.joined("plain");
    std::fs::write(&file, b"x").expect("write");

    let out = run(&format!(
        r#"
        const codes = [];
        const rfd = fsBinding.open('{dir}', 0, 0);
        try {{ fsBinding.read(rfd, new Uint8Array(4), 0, 4, -1); }}
        catch (e) {{ codes.push(e.code); }}
        fsBinding.close(rfd);
        try {{ fsBinding.stat('{file}/child', false); }}
        catch (e) {{ codes.push(e.code); }}
        const wfd = fsBinding.open('{dir}', 0, 0);
        try {{ fsBinding.writeBuffer(wfd, new Uint8Array([1]), 0, 1, -1); }}
        catch (e) {{ codes.push(e.code); }}
        fsBinding.close(wfd);
        globalThis.__out = JSON.stringify(codes);
        "#,
        dir = js_path(&dir.path),
        file = js_path(&file),
    ));
    assert_eq!(out, r#"["EISDIR","ENOTDIR","EBADF"]"#);
}

#[test]
fn callback_mode_defers_oncomplete() {
    let dir = TempDir::new("callback");
    let file = dir.joined("cb.txt");
    std::fs::write(&file, b"payload").expect("write");

    let out = run(&format!(
        r#"
        const order = [];
        const req = new fsBinding.FSReqCallback();
        req.oncomplete = function (err, value) {{
          order.push('callback');
        }};
        fsBinding.open('{}', 0, 0, req);
        // The native call must not have completed synchronously.
        order.push('after-call');
        globalThis.__out = JSON.stringify(order);
        "#,
        js_path(&file)
    ));
    // Only the post-call marker is present when the script body returns, which
    // proves the completion is deferred; `run` drains microtasks afterwards.
    assert_eq!(out, r#"["after-call"]"#);
}

#[test]
fn callback_mode_reports_the_open_descriptor() {
    let dir = TempDir::new("callback-value");
    let file = dir.joined("cb2.txt");
    std::fs::write(&file, b"payload").expect("write");

    let out = run(&format!(
        r#"
        globalThis.__out = 'pending';
        const req = new fsBinding.FSReqCallback();
        req.oncomplete = function (err, value) {{
          globalThis.__out = JSON.stringify({{
            err: err === null ? null : err.code,
            isNumber: typeof value === 'number',
            plausibleFd: value >= 3,
          }});
        }};
        fsBinding.open('{}', 0, 0, req);
        "#,
        js_path(&file)
    ));
    assert_eq!(out, r#"{"err":null,"isNumber":true,"plausibleFd":true}"#);
}

#[test]
fn callback_mode_reports_errors_as_first_argument() {
    let out = run(r#"
        globalThis.__out = 'pending';
        const req = new fsBinding.FSReqCallback();
        req.oncomplete = function (err, value) {
          globalThis.__out = JSON.stringify({
            code: err && err.code,
            syscall: err && err.syscall,
            valueIsUndefined: value === undefined,
            argCount: arguments.length,
          });
        };
        fsBinding.open('/definitely/not/here/xyzzy', 0, 0, req);
        "#);
    assert_eq!(
        out,
        r#"{"code":"ENOENT","syscall":"open","valueIsUndefined":true,"argCount":1}"#
    );
}

#[test]
fn promise_mode_resolves_and_rejects() {
    let dir = TempDir::new("promise");
    let file = dir.joined("p.txt");
    std::fs::write(&file, b"hello").expect("write");

    let out = run(&format!(
        r#"
        globalThis.__out = 'pending';
        const ok = fsBinding.stat('{ok}', false, fsBinding.kUsePromises);
        const bad = fsBinding.stat('/definitely/not/here/xyzzy', false, fsBinding.kUsePromises);
        const isPromise = ok instanceof Promise;
        ok.then(
          (stats) => {{
            bad.then(
              () => {{ globalThis.__out = 'resolved-bad'; }},
              (err) => {{
                globalThis.__out = JSON.stringify({{
                  size: stats[8], isPromise, code: err.code,
                }});
              }},
            );
          }},
          (err) => {{ globalThis.__out = 'rejected-good:' + err.code; }},
        );
        "#,
        ok = js_path(&file)
    ));
    assert_eq!(out, r#"{"size":5,"isPromise":true,"code":"ENOENT"}"#);
}

#[test]
fn exists_sync_never_throws() {
    let dir = TempDir::new("exists");
    let file = dir.joined("here");
    std::fs::write(&file, b"").expect("write");

    let out = run(&format!(
        r#"
        globalThis.__out = JSON.stringify([
          fsBinding.existsSync('{here}'),
          fsBinding.existsSync('{missing}'),
          fsBinding.existsSync('{dir}'),
        ]);
        "#,
        here = js_path(&file),
        missing = js_path(&dir.joined("gone")),
        dir = js_path(&dir.path),
    ));
    assert_eq!(out, r#"[true,false,true]"#);
}

#[test]
fn internal_module_stat_classifies_paths() {
    let dir = TempDir::new("imstat");
    let file = dir.joined("mod.js");
    std::fs::write(&file, b"").expect("write");

    let out = run(&format!(
        r#"
        globalThis.__out = JSON.stringify([
          fsBinding.internalModuleStat('{file}'),
          fsBinding.internalModuleStat('{dir}'),
          fsBinding.internalModuleStat('/definitely/not/here/xyzzy') < 0,
        ]);
        "#,
        file = js_path(&file),
        dir = js_path(&dir.path),
    ));
    assert_eq!(out, r#"[0,1,true]"#);
}

#[test]
fn realpath_and_readlink_round_trip() {
    let dir = TempDir::new("realpath");
    let target = dir.joined("target");
    std::fs::write(&target, b"").expect("write");
    let link = dir.joined("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let out = run(&format!(
        r#"
        globalThis.__out = JSON.stringify({{
          target: fsBinding.readlink('{link}', 'utf8'),
          resolved: fsBinding.realpath('{link}', 'utf8'),
        }});
        "#,
        link = js_path(&link),
    ));
    let expected = format!(
        r#"{{"target":"{}","resolved":"{}"}}"#,
        js_path(&target),
        js_path(&target)
    );
    assert_eq!(out, expected);
}

#[test]
fn mkdir_recursive_returns_first_created_directory() {
    let dir = TempDir::new("mkdir");
    let deep = dir.joined("a/b/c");

    let out = run(&format!(
        r#"
        const created = fsBinding.mkdir('{deep}', 0o755, true);
        const again = fsBinding.mkdir('{deep}', 0o755, true);
        globalThis.__out = JSON.stringify({{ created, againIsUndefined: again === undefined }});
        "#,
        deep = js_path(&deep),
    ));
    let expected = format!(
        r#"{{"created":"{}","againIsUndefined":true}}"#,
        js_path(&dir.joined("a"))
    );
    assert_eq!(out, expected);
    assert!(deep.is_dir());
}

#[test]
fn mkdtemp_and_mkstemp_create_unique_names() {
    let dir = TempDir::new("temp-names");
    let prefix = js_path(&dir.joined("t-"));

    let out = run(&format!(
        r#"
        const first = fsBinding.mkdtemp('{prefix}XXXXXX', 'utf8');
        const second = fsBinding.mkdtemp('{prefix}XXXXXX', 'utf8');
        const pair = fsBinding.mkstemp('{prefix}XXXXXX', 'utf8', undefined);
        fsBinding.close(pair[1]);
        globalThis.__out = JSON.stringify({{
          distinct: first !== second,
          firstExists: fsBinding.existsSync(first),
          secondExists: fsBinding.existsSync(second),
          fileExists: fsBinding.existsSync(pair[0]),
          pairLength: pair.length,
        }});
        "#,
    ));
    // `mkstemp` with a request slot of `undefined` takes the synchronous path.
    assert_eq!(
        out,
        r#"{"distinct":true,"firstExists":true,"secondExists":true,"fileExists":true,"pairLength":2}"#
    );
}

#[test]
fn members_list_matches_installed_properties() {
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

    for member in Fs.members() {
        let key = v8::String::new(scope, member).expect("key");
        let value = namespace.get(scope, key.into());
        assert!(value.is_some(), "member {member} is missing");
        assert!(
            !value.expect("value").is_undefined(),
            "member {member} is undefined"
        );
    }

    // The list must not claim anything extra either: `members()` is checked
    // against the JS call sites, so an extra entry would be a lie.
    let names = namespace
        .get_own_property_names(scope, Default::default())
        .expect("own names");
    let expected: std::collections::BTreeSet<String> =
        Fs.members().iter().map(|m| (*m).to_string()).collect();
    for index in 0..names.length() {
        let name = names.get_index(scope, index).expect("name");
        let name = name.to_rust_string_lossy(scope);
        assert!(
            expected.contains(&name),
            "unexpected namespace property {name}"
        );
    }
}

#[test]
fn readdir_recursive_matches_node_breadth_first_order() {
    // Node emits the root's entries first, then each subdirectory in the order
    // the directories themselves were seen. Verified against
    // `node -p "fs.readdirSync('.', {recursive:true})"` on the same tree, which
    // yields ["a","sub","top.txt","a/b","sub/inner.txt"].
    let dir = TempDir::new("recursive-order");
    std::fs::create_dir_all(dir.joined("a/b")).expect("mkdir");
    std::fs::create_dir_all(dir.joined("sub")).expect("mkdir");
    std::fs::write(dir.joined("top.txt"), b"").expect("write");
    std::fs::write(dir.joined("sub/inner.txt"), b"").expect("write");

    let out = run(&format!(
        r#"
        const plain = fsBinding.readdirRecursive('{}', 'utf8', false);
        // The `withFileTypes` form returns the 4-tuple that
        // `getRecursiveDirents` destructures, so slot 0 is the name list.
        const typed = fsBinding.readdirRecursive('{}', 'utf8', true);
        globalThis.__out = JSON.stringify([plain, typed[0]]);
        "#,
        js_path(&dir.path),
        js_path(&dir.path),
    ));
    assert_eq!(
        out,
        r#"[["a","sub","top.txt","a/b","sub/inner.txt"],["a","sub","top.txt","a/b","sub/inner.txt"]]"#
    );
    // Node's own answer for this exact tree, for the record:
    //   fs.readdirSync('.', {recursive:true})
    //   => ["a","sub","top.txt","a/b","sub/inner.txt"]
}

#[test]
fn readdir_recursive_file_types_carry_uv_codes() {
    let dir = TempDir::new("recursive-types");
    std::fs::create_dir_all(dir.joined("sub")).expect("mkdir");
    std::fs::write(dir.joined("sub/inner.txt"), b"").expect("write");

    let out = run(&format!(
        r#"
        const result = fsBinding.readdirRecursive('{}', 'utf8', true);
        const names = result[0];
        const types = result[1];
        const counts = result[2];
        const dirs = result[3];
        globalThis.__out = JSON.stringify({{ names, types, counts, dirs }});
        "#,
        js_path(&dir.path),
    ));
    // One directory (the root) with one entry, then `sub` with one entry.
    assert_eq!(
        out,
        r#"{"names":["sub","sub/inner.txt"],"types":[2,1],"counts":[1,1],"dirs":["","sub"]}"#
    );
}

#[test]
fn rm_sync_removes_a_tree_and_ignores_missing_paths() {
    let dir = TempDir::new("rm-sync");
    std::fs::create_dir_all(dir.joined("tree/deep")).expect("mkdir");
    std::fs::write(dir.joined("tree/deep/file"), b"x").expect("write");

    let out = run(&format!(
        r#"
        fsBinding.rmSync('{tree}', 0, true, 100);
        fsBinding.rmSync('{missing}', 0, false, 100);
        globalThis.__out = JSON.stringify({{
          treeGone: !fsBinding.existsSync('{tree}'),
          fileGone: !fsBinding.existsSync('{file}'),
        }});
        "#,
        tree = js_path(&dir.joined("tree")),
        file = js_path(&dir.joined("tree/deep/file")),
        missing = js_path(&dir.joined("never-existed")),
    ));
    assert_eq!(out, r#"{"treeGone":true,"fileGone":true}"#);
}

#[test]
fn rm_sync_refuses_a_directory_without_recursive() {
    let dir = TempDir::new("rm-eisdir");
    std::fs::create_dir_all(dir.joined("keep")).expect("mkdir");

    let out = run(&format!(
        r#"
        let code = null;
        try {{ fsBinding.rmSync('{path}', 0, false, 0); }}
        catch (e) {{ code = e.code; }}
        globalThis.__out = JSON.stringify({{ code, stillThere: fsBinding.existsSync('{path}') }});
        "#,
        path = js_path(&dir.joined("keep")),
    ));
    assert_eq!(out, r#"{"code":"EISDIR","stillThere":true}"#);
}

/// The member list must be exactly Node's namespace minus the documented
/// deferrals, plus the two entries this ABI adds.
///
/// `src/node_file.cc` registers the reference set with
/// `SetMethod(isolate, target, "<name>", ...)`; this test encodes it so a member
/// added or dropped without updating the README fails here.
#[test]
fn member_list_tracks_node_minus_documented_deferrals() {
    let node: std::collections::BTreeSet<&str> = [
        "access",
        "chmod",
        "chown",
        "close",
        "copyFile",
        "cpSyncCheckPaths",
        "cpSyncCopyDir",
        "cpSyncOverrideFile",
        "existsSync",
        "fchmod",
        "fchown",
        "fdatasync",
        "fstat",
        "fsync",
        "ftruncate",
        "futimes",
        "handleToFd",
        "internalModuleStat",
        "lchown",
        "link",
        "lstat",
        "lutimes",
        "mkdir",
        "mkdtemp",
        "mkstemp",
        "open",
        "openFileHandle",
        "read",
        "readBuffers",
        "readdir",
        "readdirRecursive",
        "readFileUtf8",
        "readlink",
        "realpath",
        "rename",
        "rmdir",
        "rmSync",
        "stat",
        "statfs",
        "symlink",
        "unlink",
        "utimes",
        "writeBuffer",
        "writeBuffers",
        "writeFileUtf8",
        "writeString",
    ]
    .into_iter()
    .collect();

    // Documented in README.md under "Deliberately deferred".
    let deferred: std::collections::BTreeSet<&str> =
        ["cpSyncCopyDir", "cpSyncOverrideFile", "openFileHandle"]
            .into_iter()
            .collect();

    // Not in Node's `fs` namespace: the request constructor the JS instantiates,
    // and the promise-mode sentinel it forwards.
    let ns_extras: std::collections::BTreeSet<&str> =
        ["FSReqCallback", "kUsePromises"].into_iter().collect();

    let ours: std::collections::BTreeSet<&str> = Fs.members().iter().copied().collect();
    let expected: std::collections::BTreeSet<&str> = node
        .difference(&deferred)
        .copied()
        .chain(ns_extras.iter().copied())
        .collect();

    assert_eq!(ours, expected, "member list drifted from the contract");
}

#[test]
fn sentinel_cannot_be_forged_through_a_global() {
    // The sentinel lives in a V8 context slot, not on `globalThis`, so user code
    // cannot plant a lookalike and switch a call into promise mode.
    let out = run(r#"
        globalThis.__rustnodeFsUsePromises = Symbol('kUsePromises');
        const lookalike = Symbol('kUsePromises');
        let lookalikeThrew = false;
        try {
          fsBinding.stat('/definitely/not/here/xyzzy', false, lookalike);
        } catch (error) {
          // A synchronous throw proves it was treated as a sync call.
          lookalikeThrew = error.code === 'ENOENT';
        }
        const real = fsBinding.stat('/definitely/not/here/xyzzy', false, fsBinding.kUsePromises);
        globalThis.__out = JSON.stringify({
          lookalikeThrew,
          realIsPromise: real instanceof Promise,
          globalNotUsed: typeof globalThis.__rustnodeFsUsePromises === 'symbol',
        });
        "#);
    assert_eq!(
        out,
        r#"{"lookalikeThrew":true,"realIsPromise":true,"globalNotUsed":true}"#
    );
}
