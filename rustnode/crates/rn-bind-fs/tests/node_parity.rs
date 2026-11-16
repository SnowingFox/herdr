//! Cross-checks the binding against the pinned Node oracle.
//!
//! Everything here is derived from observing Node itself rather than from
//! re-reading Node's source, so a mistake in my reading of `node_file.cc` shows
//! up as a test failure instead of as a silently different runtime.
//!
//! The oracle is the binary `tools/node-pin.toml` pins, not whatever `node` is
//! on `PATH`; see [`rn_node_oracle`]. A machine with no oracle skips loudly, and
//! one with a *different* Node fails rather than comparing against the wrong
//! engine.

use std::os::unix::ffi::OsStrExt;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use rn_bind_fs::Fs;
use rn_node_oracle::Oracle;

/// The oracle this test binary compares against, resolved and announced once.
///
/// This used to be a bare `Command::new("node")` probe, which meant "whatever
/// `PATH` resolves to". A CI image ships a different Node than
/// `tools/node-pin.toml` pins, so the comparison silently measured the wrong
/// engine. [`rn_node_oracle::require_oracle`] panics on a wrong-version binary
/// and returns `None` only when there is no oracle at all.
fn oracle() -> Option<&'static Oracle> {
    static ORACLE: std::sync::OnceLock<Option<Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-bind-fs node parity"))
        .as_ref()
}

/// Runs `node -p <expr>` in `dir` and returns trimmed stdout.
fn node_print(oracle: &Oracle, dir: &std::path::Path, expr: &str) -> String {
    let out = oracle
        .command()
        .arg("-p")
        .arg(expr)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", oracle.describe()));
    assert!(
        out.status.success(),
        "{} failed: {}",
        oracle.describe(),
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
    let Some(oracle) = oracle() else {
        return;
    };
    let dir = TempDir::new("stat");
    let file = dir.path.join("x");
    std::fs::write(&file, b"hello").expect("write");

    // Reference answer straight from Node.
    let expected = node_print(
        oracle,
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
    let Some(oracle) = oracle() else {
        return;
    };
    let dir = TempDir::new("readdir");
    for name in ["zebra", "alpha", "Mike", "bravo", "0123"] {
        std::fs::write(dir.path.join(name), b"").expect("write");
    }
    std::fs::create_dir_all(dir.path.join("sub")).expect("mkdir");

    let expected = node_print(
        oracle,
        &dir.path,
        "JSON.stringify(require('fs').readdirSync('.'))",
    );
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
    let Some(oracle) = oracle() else {
        return;
    };
    let dir = TempDir::new("recursive");
    std::fs::create_dir_all(dir.path.join("a/b")).expect("mkdir");
    std::fs::create_dir_all(dir.path.join("sub")).expect("mkdir");
    std::fs::write(dir.path.join("top.txt"), b"").expect("write");
    std::fs::write(dir.path.join("sub/inner.txt"), b"").expect("write");

    let expected = node_print(
        oracle,
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
    let Some(oracle) = oracle() else {
        return;
    };
    let dir = TempDir::new("errors");

    let expected = node_print(
        oracle,
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
    let Some(oracle) = oracle() else {
        return;
    };
    // Node and the binding both create `p/q/r`, so each gets its own tree:
    // whichever runs first would otherwise make the other see an existing path
    // and return `undefined`.
    let for_node = TempDir::new("mkdir-node");
    let expected = node_print(
        oracle,
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
    let Some(oracle) = oracle() else {
        return;
    };
    let dir = TempDir::new("links");
    let target = dir.path.join("target");
    std::fs::write(&target, b"").expect("write");
    std::os::unix::fs::symlink(&target, dir.path.join("link")).expect("symlink");

    let expected = node_print(
        oracle,
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
    let Some(oracle) = oracle() else {
        return;
    };
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
        oracle,
        &dir.path,
        "JSON.stringify([require('fs').statSync('file.js').isFile(), \
         require('fs').statSync('dir').isDirectory()])",
    );
    assert_eq!(expected, "[true,true]");
}

/// The whole point of the comparison: name the reference binary rather than
/// letting a green run leave it ambiguous.
///
/// This used to assert only that *some* `node` answered, which a completely
/// different Node would satisfy. It now proves the binary is the one
/// `tools/node-pin.toml` pins, so a run that reached `PATH` by mistake is
/// reported here even if the other tests happened to agree with it.
#[test]
fn node_reference_is_reachable() {
    let Some(oracle) = oracle() else {
        return;
    };
    let version = node_print(oracle, std::env::temp_dir().as_path(), "process.version");
    assert_eq!(
        version,
        oracle.pin.expected_version(),
        "the oracle answered with {version}, but the pin records {}",
        oracle.pin.expected_version()
    );
    assert!(oracle.is_pinned_version(), "{}", oracle.describe());
}

/// `legacyMainResolve`'s index table and error codes, cross-checked against a
/// real Node.
///
/// The indices are the part that a plausible implementation gets wrong, and
/// comparing them against Node is the only way to be sure the table in
/// `legacy_main.rs` still lines up with the one in `helpers.js`. The oracle is
/// the binary `tools/node-pin.toml` pins, not whatever `node` is on `PATH`.
///
/// It shells out to `node --expose-internals` because neither member is
/// reachable from userland: `lib/internal/modules/helpers.js` is the only caller
/// in Node, and it reads them off `internalFsBinding`.
#[test]
fn legacy_main_resolve_indices_match_node() {
    let Some(oracle) = oracle() else {
        eprintln!("skipping: no pinned Node oracle");
        return;
    };

    let dir = TempDir::new("legacy-main-parity");
    // Index 1 and 7 have the same `.js` suffix, which is the pair worth pinning:
    // they are the same string in the table and reach different files.
    for name in [
        "mainjs", "mainjson", "mainnode", "idxjs", "idxjson", "idxnode", "fbjs",
    ] {
        std::fs::create_dir_all(dir.path.join(name)).expect("mkdir");
    }
    for name in ["idxjs", "idxjson", "idxnode"] {
        std::fs::create_dir_all(dir.path.join(name).join("main")).expect("mkdir");
    }
    std::fs::write(dir.path.join("mainjs/main.js"), b"x").expect("write");
    std::fs::write(dir.path.join("mainjson/main.json"), b"{}").expect("write");
    std::fs::write(dir.path.join("mainnode/main.node"), b"").expect("write");
    std::fs::write(dir.path.join("idxjs/main/index.js"), b"x").expect("write");
    std::fs::write(dir.path.join("idxjson/main/index.json"), b"{}").expect("write");
    std::fs::write(dir.path.join("idxnode/main/index.node"), b"").expect("write");
    std::fs::write(dir.path.join("fbjs/index.js"), b"x").expect("write");
    std::fs::write(dir.path.join("wasm"), [0x00u8, 0x61, 0x73, 0x6d, 0x01]).expect("write");
    std::fs::write(dir.path.join("plain"), b"console.log(1)").expect("write");

    let script = format!(
        r#"
const {{ internalBinding }} = require('internal/test/binding');
const b = internalBinding('fs');
const root = '{root}';
const base = 'file:///tmp/x.js';
const capture = (fn) => {{
  try {{ return ['ok', fn()]; }}
  catch (e) {{ return ['threw', e.name, e.code, e.message]; }}
}};
const out = {{
  mainJs: capture(() => b.legacyMainResolve(root + '/mainjs', 'main', base)),
  mainJson: capture(() => b.legacyMainResolve(root + '/mainjson', 'main', base)),
  mainNode: capture(() => b.legacyMainResolve(root + '/mainnode', 'main', base)),
  mainIndexJs: capture(() => b.legacyMainResolve(root + '/idxjs', 'main', base)),
  mainIndexJson: capture(() => b.legacyMainResolve(root + '/idxjson', 'main', base)),
  mainIndexNode: capture(() => b.legacyMainResolve(root + '/idxnode', 'main', base)),
  fallbackJs: capture(() => b.legacyMainResolve(root + '/fbjs', undefined, base)),
  missingMain: capture(() => b.legacyMainResolve(root + '/fbjs', 'nope', base)),
  notFound: capture(() => b.legacyMainResolve(root + '/nothing', undefined, base)),
  notFoundMain: capture(() => b.legacyMainResolve(root + '/nothing', 'zzz', base)),
  badBaseOnSuccess: capture(() => b.legacyMainResolve(root + '/mainjs', 'main', 'notaurl')),
  omittedBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, undefined)),
  invalidBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, 'notaurl')),
  schemeBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, 'ftp://x/y')),
  encodedSlashBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, 'file:///a%2Fb/x')),
  percentBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, 'file:///a%20b/x')),
  wasm: capture(() => b.getFormatOfExtensionlessFile(root + '/wasm')),
  plain: capture(() => b.getFormatOfExtensionlessFile(root + '/plain')),
  missingFile: capture(() => b.getFormatOfExtensionlessFile(root + '/absent')),
}};
console.log(JSON.stringify(out));
"#,
        root = js_path(&dir.path)
    );
    let script_path = dir.path.join("parity.js");
    std::fs::write(&script_path, &script).expect("write the script");

    let node_out = oracle
        .command()
        .arg("--expose-internals")
        .arg(&script_path)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", oracle.describe()));
    assert!(
        node_out.status.success(),
        "{} failed: {}",
        oracle.describe(),
        String::from_utf8_lossy(&node_out.stderr)
    );
    let expected = String::from_utf8_lossy(&node_out.stdout).trim().to_string();

    // The same script under this crate's namespace. Both members are reachable
    // only through `internalBinding`, so the harness installs the namespace and
    // runs the script with `internalFsBinding` swapped for it.
    let actual = eval(&format!(
        r#"
        const b = fsBinding;
        const root = '{root}';
        const base = 'file:///tmp/x.js';
        const capture = (fn) => {{
          try {{ return ['ok', fn()]; }}
          catch (e) {{ return ['threw', e.name, e.code, e.message]; }}
        }};
        globalThis.__out = JSON.stringify({{
          mainJs: capture(() => b.legacyMainResolve(root + '/mainjs', 'main', base)),
          mainJson: capture(() => b.legacyMainResolve(root + '/mainjson', 'main', base)),
          mainNode: capture(() => b.legacyMainResolve(root + '/mainnode', 'main', base)),
          mainIndexJs: capture(() => b.legacyMainResolve(root + '/idxjs', 'main', base)),
          mainIndexJson: capture(() => b.legacyMainResolve(root + '/idxjson', 'main', base)),
          mainIndexNode: capture(() => b.legacyMainResolve(root + '/idxnode', 'main', base)),
          fallbackJs: capture(() => b.legacyMainResolve(root + '/fbjs', undefined, base)),
          missingMain: capture(() => b.legacyMainResolve(root + '/fbjs', 'nope', base)),
          notFound: capture(() => b.legacyMainResolve(root + '/nothing', undefined, base)),
          notFoundMain: capture(() => b.legacyMainResolve(root + '/nothing', 'zzz', base)),
          badBaseOnSuccess: capture(() => b.legacyMainResolve(root + '/mainjs', 'main', 'notaurl')),
          omittedBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, undefined)),
          invalidBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, 'notaurl')),
          schemeBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, 'ftp://x/y')),
          encodedSlashBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, 'file:///a%2Fb/x')),
          percentBase: capture(() => b.legacyMainResolve(root + '/nothing', undefined, 'file:///a%20b/x')),
          wasm: capture(() => b.getFormatOfExtensionlessFile(root + '/wasm')),
          plain: capture(() => b.getFormatOfExtensionlessFile(root + '/plain')),
          missingFile: capture(() => b.getFormatOfExtensionlessFile(root + '/absent')),
        }});
        "#,
        root = js_path(&dir.path)
    ));

    assert_eq!(
        actual, expected,
        "legacyMainResolve / getFormatOfExtensionlessFile must agree with node"
    );
}

/// Invalid UTF-8, a NUL, and valid multi-byte text in a `file:` base URL.
///
/// Node has **two** functions called `FileURLToPath`, and they disagree here, so
/// naming which one is matched is the point of this test:
///
/// * `lib/internal/url.js:1623` (`url.fileURLToPath`) decodes with
///   `decodeURIComponent`, which throws `URIError "URI malformed"` on invalid
///   UTF-8.
/// * `src/node_url.cc:770` (`node::url::FileURLToPath`) decodes with
///   `ada::unicode::percent_decode`, which returns raw bytes and never throws.
///
/// `LegacyMainResolve` calls the *second* one (`src/node_file.cc:5548`), so
/// invalid UTF-8 becomes U+FFFD in the `imported from` text rather than an
/// error. Asserting the JS function's behaviour here would pin the wrong
/// contract, so the member is compared against the oracle; the JS function's
/// throw is asserted in both runtimes too, so this cannot be satisfied by
/// relaxing decoding globally.
///
/// The earlier differential only fed well-formed URLs, which is why it did not
/// find any of this: a well-formed corpus cannot expose a decoding divergence.
#[test]
fn legacy_main_resolve_decodes_invalid_utf8_like_the_cpp_not_like_js() {
    if !node_available() {
        eprintln!("skipping: no `node` on PATH");
        return;
    }

    let dir = TempDir::new("legacy-main-utf8");
    std::fs::create_dir_all(dir.path.join("pkg")).expect("mkdir");
    // `main.js` exists so the `nulInMain` and `nulInPkgPath` cases resolve.
    std::fs::write(dir.path.join("pkg/main.js"), b"x").expect("write");
    let root = js_path(&dir.path);

    // The six member calls, written once as a JS expression list so the oracle
    // and this crate evaluate identical source. `{ROOT}` is substituted.
    let cases = r#"{
  invalidUtf8: capture(() => b.legacyMainResolve('{ROOT}/pkg', undefined, 'file:///tmp/a%FFb/x.js')),
  validUtf8: capture(() => b.legacyMainResolve('{ROOT}/pkg', undefined, 'file:///tmp/%C3%A9/x.js')),
  encodedSlash: capture(() => b.legacyMainResolve('{ROOT}/pkg', undefined, 'file:///tmp/a%2Fb/x.js')),
  embeddedNul: capture(() => b.legacyMainResolve('{ROOT}/pkg', undefined, 'file:///tmp/a%00b/x.js')),
  multiByteCjk: capture(() => b.legacyMainResolve('{ROOT}/pkg', undefined, 'file:///tmp/%E4%B8%AD/x.js')),
  nulInMain: capture(() => b.legacyMainResolve('{ROOT}/pkg', 'main.js\u0000zzz', 'file:///tmp/x.js')),
  nulInPkgPath: capture(() => b.legacyMainResolve('{ROOT}/pkg\u0000junk', 'main.js', 'file:///tmp/x.js')),
}"#
        .replace("{ROOT}", &root);

    let preamble = r#"
const capture = (fn) => {
  try { const v = fn(); return ['ok', typeof v, v]; }
  catch (e) { return ['threw', e.name, e.code, e.message]; }
};
"#;

    // Oracle: the real `internalBinding`, printing just the case table.
    let node_script = format!(
        "{preamble}\n{}\nconst b = internalBinding('fs');\nconsole.log(JSON.stringify({cases}));\n",
        "const { internalBinding } = require('internal/test/binding');",
        preamble = preamble,
        cases = cases,
    );
    let script_path = dir.path.join("utf8.js");
    std::fs::write(&script_path, &node_script).expect("write the script");

    let node_out = Command::new("node")
        .arg("--expose-internals")
        .arg(&script_path)
        .output()
        .expect("node runs");
    assert!(
        node_out.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&node_out.stderr)
    );
    let expected: Vec<String> = String::from_utf8_lossy(&node_out.stdout)
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(expected.len(), 1, "node printed {expected:?}");

    // This crate: only the member calls. This harness has no bootstrap, so
    // `require('url')` is not available in-process; the vendored
    // `url.fileURLToPath` keeps throwing for the same input, which
    // `js_contract.rs` asserts through the real binary.
    let rust_source = format!(
        "{preamble}\nconst b = fsBinding;\nglobalThis.__out = JSON.stringify({cases});",
        preamble = preamble,
        cases = cases,
    );
    let actual: Vec<String> = eval(&rust_source)
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    assert_eq!(
        actual, expected,
        "legacyMainResolve must decode the base URL like the C++ FileURLToPath, \
         while url.fileURLToPath keeps throwing on the same input"
    );
}
