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

    // Constructed by `lib/fs.js`, but registered with `SetConstructorFunction`
    // rather than `SetMethod`, so they are not in the `SetMethod` list above.
    // Both are load-bearing: `fs.readFile` and `fs.writeFile` construct them
    // unconditionally for `options.buffer === undefined`.
    let job_classes: std::collections::BTreeSet<&str> =
        ["ReadFileJob", "WriteFileJob"].into_iter().collect();

    let ours: std::collections::BTreeSet<&str> = Fs.members().iter().copied().collect();
    let expected: std::collections::BTreeSet<&str> = node
        .difference(&deferred)
        .copied()
        .chain(ns_extras.iter().copied())
        .chain(job_classes.iter().copied())
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

// ---------------------------------------------------------------------------
// The one-shot file jobs
// ---------------------------------------------------------------------------

/// Runs `source` through the real `rustnode` binary.
///
/// The jobs are the one part of this namespace that cannot be tested through
/// `run()` above: their completions arrive from inside `uv_run`, and a bare
/// isolate with a microtask checkpoint has no loop to run. Driving the CLI is
/// what exercises the queue, the pool thread and the `ondone` delivery in the
/// order the JavaScript expects.
fn run_in_binary(label: &str, source: &str) -> String {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    let script = std::env::temp_dir().join(format!(
        "rn-bind-fs-job-{label}-{}-{:?}.js",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&script, source).expect("write the script");
    let output = std::process::Command::new(&path)
        .arg(&script)
        .output()
        .unwrap_or_else(|error| panic!("the rustnode binary must be built first: {error}"));
    let _ = std::fs::remove_file(&script);
    assert!(
        output.status.success(),
        "script failed with {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn read_file_job_is_named_by_lib_fs_and_constructs() {
    // `lib/fs.js` destructures both names from the namespace at load time and
    // constructs them directly, so a missing entry is a `TypeError` before any
    // syscall. `class_name` matters too: the error message a caller sees for a
    // mis-shaped argument is built from it.
    let out = run(r#"
        const readJob = new fsBinding.ReadFileJob('/tmp/x', 0, 512, true);
        const writeJob = new fsBinding.WriteFileJob('/tmp/x', 0, 0o666, new Uint8Array(1));
        globalThis.__out = JSON.stringify({
          readName: fsBinding.ReadFileJob.name,
          writeName: fsBinding.WriteFileJob.name,
          readRun: typeof readJob.run,
          writeRun: typeof writeJob.run,
          readIsInstance: readJob instanceof fsBinding.ReadFileJob,
          writeIsInstance: writeJob instanceof fsBinding.WriteFileJob,
        });
        "#);
    assert_eq!(
        out,
        r#"{"readName":"ReadFileJob","writeName":"WriteFileJob","readRun":"function","writeRun":"function","readIsInstance":true,"writeIsInstance":true}"#
    );
}

#[test]
fn read_file_job_delivers_the_five_argument_shape_for_a_whole_file() {
    // `readFileAfterOneShot(err, buffer, fd, size, closeErr)`: a whole-file read
    // reports `fd === -1` and the buffer, and that buffer has to be a real
    // `Buffer` because `.toString(encoding)` and `Buffer.isBuffer` both run on it.
    let dir = TempDir::new("job-oneshot");
    let file = js_path(&dir.joined("small.txt"));
    std::fs::write(dir.joined("small.txt"), b"hello job").expect("write");

    let out = run_in_binary(
        "oneshot",
        &format!(
            r#"
const fs = require('fs');
fs.readFile('{file}', (err, data) => {{
  if (err) return console.log('ERR', err.message);
  console.log(JSON.stringify({{
    isBuffer: Buffer.isBuffer(data),
    text: data.toString('utf8'),
    length: data.length,
  }}));
}});
"#
        ),
    );
    assert_eq!(out, r#"{"isBuffer":true,"text":"hello job","length":9}"#);
}

#[test]
fn read_file_job_reports_an_open_failure_as_its_first_argument() {
    // The `err` row: `argv[0]` carries the `UVException`-shaped error and `fd`
    // is `-1`, so `readFileAfterOneShot` takes the `context.callback(err)` arm.
    let out = run_in_binary(
        "enoent",
        r#"
const fs = require('fs');
fs.readFile('/definitely/not/here/rn-fs-job', (err, data) => {
  console.log(JSON.stringify({
    code: err && err.code,
    syscall: err && err.syscall,
    errno: err && err.errno,
    data: data === undefined ? 'undefined' : typeof data,
  }));
});
"#,
    );
    assert_eq!(
        out,
        r#"{"code":"ENOENT","syscall":"open","errno":-2,"data":"undefined"}"#
    );
}

#[test]
fn a_file_above_the_read_limit_takes_the_chunked_path_without_truncation() {
    // The `fd >= 0` row. `kReadFileBufferLength` is 512 KiB, so a 1.5 MiB file
    // must come back as an open fd plus its size and be read by
    // `readFileAfterOneShot`'s chunked reader. A job that reported `-1` here
    // would hand back only the first chunk — a silent truncation, not an error —
    // which is why the length and the content are both asserted.
    let dir = TempDir::new("job-chunked");
    let path = dir.joined("large.bin");
    let size = 1536 * 1024;
    let content: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
    std::fs::write(&path, &content).expect("write");
    let file = js_path(&path);

    let out = run_in_binary(
        "chunked",
        &format!(
            r#"
const fs = require('fs');
fs.readFile('{file}', (err, data) => {{
  if (err) return console.log('ERR', err.message);
  let mismatch = -1;
  for (let i = 0; i < data.length; i++) {{
    if (data[i] !== (i % 251)) {{ mismatch = i; break; }}
  }}
  console.log(JSON.stringify({{ length: data.length, mismatch }}));
}});
"#
        ),
    );
    assert_eq!(
        out,
        format!(r#"{{"length":{size},"mismatch":-1}}"#),
        "a file above the limit must be read in full, not truncated"
    );
}

#[test]
fn write_file_job_writes_a_buffer_and_calls_ondone_once() {
    // `WriteFileJob`'s completion takes one argument: `lib/fs.js` assigns a
    // one-argument `ondone`, and anything else would silently be ignored.
    let dir = TempDir::new("job-write");
    let file = js_path(&dir.joined("out.bin"));
    let written = dir.joined("out.bin");

    let out = run_in_binary(
        "write",
        &format!(
            r#"
const fs = require('fs');
let calls = 0;
fs.writeFile('{file}', Buffer.from([1, 2, 3, 4]), (err) => {{
  calls++;
  console.log(JSON.stringify({{ err: err === null ? 'null' : String(err), calls }}));
}});
"#
        ),
    );
    assert_eq!(out, r#"{"err":"null","calls":1}"#);
    assert_eq!(
        std::fs::read(&written).expect("read back"),
        vec![1u8, 2, 3, 4]
    );
}

#[test]
fn write_file_job_reports_the_write_syscall_for_an_unwritable_path() {
    let out = run_in_binary(
        "write-enoent",
        r#"
const fs = require('fs');
fs.writeFile('/definitely/not/here/rn-fs-job.bin', 'x', (err) => {
  console.log(JSON.stringify({ code: err && err.code, syscall: err && err.syscall }));
});
"#,
    );
    assert_eq!(out, r#"{"code":"ENOENT","syscall":"open"}"#);
}

#[test]
fn promises_read_file_resolves_through_the_job() {
    // `internal/fs/promises.js` builds the same job and awaits `ondone`, so this
    // is the path `fs.promises.readFile` takes for a file under the limit.
    let dir = TempDir::new("job-promise");
    std::fs::write(dir.joined("p.txt"), b"promised").expect("write");
    let file = js_path(&dir.joined("p.txt"));

    let out = run_in_binary(
        "promise",
        &format!(
            r#"
const fs = require('fs');
fs.promises.readFile('{file}', 'utf8').then(
  (text) => console.log(JSON.stringify({{ text }})),
  (err) => console.log(JSON.stringify({{ err: err.message }})),
);
"#
        ),
    );
    assert_eq!(out, r#"{"text":"promised"}"#);
}

#[test]
fn a_write_above_the_chunk_size_still_lands_whole() {
    // `internal/fs/promises.js` only takes the job path for a buffer at or below
    // `kWriteFileMaxChunkSize` (512 KiB). This writes at that size through the
    // callback form, where `lib/fs.js` has no such cutoff, so the job's write
    // loop has to reach every byte.
    let dir = TempDir::new("job-write-large");
    let file = js_path(&dir.joined("large.bin"));
    let written = dir.joined("large.bin");
    let size = 1024 * 1024;

    let out = run_in_binary(
        "write-large",
        &format!(
            r#"
const fs = require('fs');
const data = Buffer.alloc({size}, 0x41);
fs.writeFile('{file}', data, (err) => {{
  console.log(JSON.stringify({{ err: err === null ? 'null' : String(err), length: data.length }}));
}});
"#
        ),
    );
    assert_eq!(out, format!(r#"{{"err":"null","length":{size}}}"#));
    let back = std::fs::read(&written).expect("read back");
    assert_eq!(back.len(), size);
    assert!(back.iter().all(|byte| *byte == 0x41));
}

#[test]
fn a_job_completion_restores_the_async_frame_of_its_caller() {
    // A `uv_queue_work` completion is neither a promise continuation nor a
    // timer, so V8 restores no embedder frame around it on its own. Node's
    // `AsyncWrap`/`MakeCallback` does, which is what makes `process.domain` and
    // `AsyncLocalStorage.getStore()` inside an `fs` callback answer with the
    // scope that started the call. Without the capture-and-restore in
    // `jobs.rs` this reported `null` for the read and `true` for the timer,
    // because libuv's timer phase runs through the JS timer machinery.
    let dir = TempDir::new("job-domain");
    std::fs::write(dir.joined("d.txt"), b"d").expect("write");
    let file = js_path(&dir.joined("d.txt"));

    let out = run_in_binary(
        "domain",
        &format!(
            r#"
const fs = require('fs');
const domain = require('domain');
const d = domain.create();
d.run(() => {{
  fs.readFile('{file}', () => {{
    console.log(JSON.stringify({{ readFile: process.domain === d }}));
  }});
  fs.writeFile('{file}.out', 'x', () => {{
    console.log(JSON.stringify({{ writeFile: process.domain === d }}));
  }});
}});
"#
        ),
    );
    assert_eq!(
        out, "{\"readFile\":true}\n{\"writeFile\":true}",
        "both job classes must deliver inside the caller's async frame"
    );
}

/// Runs `source` inline (`-e`) through the real `rustnode` binary.
///
/// Separate from `run_in_binary` above, which writes a script file: `require` of
/// an `internal/**` module resolves only under `-e` in this runtime (real `node`
/// rejects it from a file too), so a test that reaches a binding directly has to
/// evaluate its source inline. `flags` carries `--expose-internals` for those.
fn run_inline_with(label: &str, source: &str, flags: &[&str]) -> String {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    let output = std::process::Command::new(&path)
        .args(flags)
        .arg("-e")
        .arg(source)
        .output()
        .unwrap_or_else(|error| panic!("the rustnode binary must be built first: {error}"));
    assert!(
        output.status.success(),
        "{label}: script failed with {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

// ---------------------------------------------------------------------------
// The request slot is a position, not the tail
// ---------------------------------------------------------------------------

/// `stat` and `fstat` are the two members whose request argument is followed by
/// a real operand, so the shared `conclude!` tail classification answered
/// "synchronous" for them. The visible symptom was
/// `TypeError: Method Promise.prototype.then called on incompatible receiver
/// [object BigInt64Array]` from `fs.promises.stat`, because the binding handed
/// back the raw stat slot array where the promise layer expected a promise.
///
/// These tests drive the CLI because the promise path needs the real
/// `lib/internal/fs/promises.js`.
#[test]
fn promises_stat_and_fstat_resolve_through_promise_mode() {
    let dir = TempDir::new("slot-promise");
    let file = dir.joined("s.txt");
    std::fs::write(&file, b"x").expect("write");
    let path = js_path(&file);

    let out = run_in_binary(
        "slot-promise",
        &format!(
            r#"
const fs = require('fs');
(async () => {{
  const plain = await fs.promises.stat('{path}');
  const big = await fs.promises.stat('{path}', {{ bigint: true }});
  const viaLstat = await fs.promises.lstat('{path}');
  console.log(JSON.stringify({{
    stat: plain.constructor.name,
    statIsBigInt: typeof plain.size === 'bigint',
    bigint: big.constructor.name,
    bigintIsBigInt: typeof big.size === 'bigint',
    lstat: viaLstat.constructor.name,
  }}));
}})();
"#
        ),
    );
    assert_eq!(
        out,
        r#"{"stat":"Stats","statIsBigInt":false,"bigint":"BigIntStats","bigintIsBigInt":true,"lstat":"Stats"}"#
    );
}

/// `fstat` takes the fd instead of a path but has the same four-slot shape, so
/// it needs the positional read for the same reason.
///
/// The assertion is `instanceof Promise`, not a `then` error: raw `await` on a
/// typed array silently returns the array, so only the `PromisePrototypeThen`
/// that `internal/fs/promises.js` uses actually throws. Checking the returned
/// kind is the contract the JS layer depends on either way.
#[test]
fn promise_mode_fstat_resolves_through_its_own_request_slot() {
    let dir = TempDir::new("slot-fstat");
    let file = dir.joined("f.bin");
    std::fs::write(&file, b"123456").expect("write");

    let out = run_inline_with(
        "slot-fstat",
        &format!(
            r#"
const fs = require('fs');
const realm = require('internal/bootstrap/realm');
const binding = realm.internalBinding('fs');
(async () => {{
  const fd = fs.openSync('{path}', 'r');
  // Four arguments, because that is the shape that distinguishes the two
  // readings: with three, the request *is* the tail and both agree. `fs.js:520`
  // and `fs.js:2119` both pass a fourth argument.
  const plainCall = binding.fstat(fd, false, binding.kUsePromises, true);
  const bigCall = binding.fstat(fd, true, binding.kUsePromises, false);
  const plainIsPromise = plainCall instanceof Promise;
  const bigIsPromise = bigCall instanceof Promise;
  const plain = await plainCall;
  const big = await bigCall;
  fs.closeSync(fd);
  console.log(JSON.stringify({{
    plainIsPromise,
    bigIsPromise,
    plain: plain.constructor.name,
    plainSize: plain[8],
    big: big.constructor.name,
    bigSize: String(big[8]),
  }}));
}})();
"#,
            path = js_path(&file)
        ),
        &["--expose-internals"],
    );
    assert_eq!(
        out,
        r#"{"plainIsPromise":true,"bigIsPromise":true,"plain":"Float64Array","plainSize":6,"big":"BigInt64Array","bigSize":"6"}"#
    );
}

#[test]
fn the_stat_callback_form_calls_back_instead_of_returning_the_array() {
    // The same bug in the callback convention: `fs.stat(path, cb)` passes
    // `undefined` for `options.throwIfNoEntry`'s slot in one shape and `true` in
    // another, and a tail read made both look synchronous, so `oncomplete` was
    // never delivered and the callback silently never ran.
    let dir = TempDir::new("slot-callback");
    let file = dir.joined("c.txt");
    std::fs::write(&file, b"xy").expect("write");
    let path = js_path(&file);

    let out = run_in_binary(
        "slot-callback",
        &format!(
            r#"
const fs = require('fs');
let calls = 0;
fs.stat('{path}', (err, stats) => {{
  calls++;
  console.log(JSON.stringify({{
    err: err === null ? 'null' : String(err),
    isStats: stats && stats.constructor.name === 'Stats',
    size: stats && stats.size,
    calls,
  }}));
}});
fs.lstat('{path}', (err, stats) => {{
  console.log(JSON.stringify({{ lstatSize: stats && stats.size }}));
}});
"#
        ),
    );
    assert_eq!(
        out,
        "{\"err\":\"null\",\"isStats\":true,\"size\":2,\"calls\":1}\n{\"lstatSize\":2}"
    );
}

#[test]
fn a_missing_path_in_promise_mode_rejects_with_the_stat_error() {
    // `fs.promises.stat` defaults `throwIfNoEntry` to `true`, which is the value
    // that used to land in the request slot. The rejection has to come from the
    // async path, with `syscall: 'stat'`.
    let out = run_in_binary(
        "slot-enoent",
        r#"
const fs = require('fs');
(async () => {
  const seen = [];
  try { await fs.promises.stat('/definitely/not/here/slot'); }
  catch (e) { seen.push([e.code, e.syscall, e.errno].join(' ')); }
  // `throwIfNoEntry: false` resolves `undefined` rather than rejecting.
  const none = await fs.promises.stat('/definitely/not/here/slot', { throwIfNoEntry: false });
  // The callback form still reports it as `err`.
  await new Promise((resolve) => {
    fs.stat('/definitely/not/here/slot', (err) => {
      seen.push([err.code, err.syscall].join(' '));
      resolve();
    });
  });
  console.log(JSON.stringify({ seen, none: none === undefined }));
})();
"#,
    );
    assert_eq!(
        out,
        r#"{"seen":["ENOENT stat -2","ENOENT stat"],"none":true}"#
    );
}

#[test]
fn the_explicit_undefined_request_slot_stays_synchronous() {
    // `binding.stat(path, bigint, undefined, throwIfNoEntry)` is the sync form,
    // and it has an operand *after* the empty request slot. A positional read
    // must still answer "synchronous" for it, not "no request then error".
    let dir = TempDir::new("slot-sync");
    let file = dir.joined("s.txt");
    std::fs::write(&file, b"abc").expect("write");

    let out = run(&format!(
        r#"
        const missing = fsBinding.stat('/definitely/not/here/slot', false, undefined, false);
        const present = fsBinding.stat('{file}', false, undefined, true);
        globalThis.__out = JSON.stringify({{
          missingIsUndefined: missing === undefined,
          type: present.constructor.name,
          size: present[8],
        }});
        "#,
        file = js_path(&file)
    ));
    assert_eq!(
        out,
        r#"{"missingIsUndefined":true,"type":"Float64Array","size":3}"#
    );
}
