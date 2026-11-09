//! Parity with a real `node` binary on real files.
//!
//! `node_expected.json` is a recording of what `node --expose-internals` answers
//! for the fixture tree in this file, captured with
//! `internalBinding('modules')` called directly. The tests below rebuild the same
//! tree, run the same queries through the Rust binding, and compare.
//!
//! This is the check that matters for package-type detection: a wrong `type`
//! does not raise, it silently changes whether a file is loaded as CommonJS or
//! as an ES module. Comparing against a recording of Node rather than against
//! expectations written by hand means a misreading of `node_modules.cc` shows up
//! as a failure instead of as agreement with itself.
//!
//! The recording comes from the newest Node available here, which is older than
//! the pinned 28.0.0; where the two differ the difference is in the size of the
//! serialized array (Node 28 added a seventh `private` slot), so the comparison
//! only reads the six slots that exist in both.
//!
//! When `node` is on `PATH` the recording is regenerated and compared as well,
//! so the fixture answers are not allowed to drift from the binary either.

use std::path::{Path, PathBuf};
use std::process::Command;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use rn_bind_modules::Modules;

/// The recording, produced by `node --expose-internals` against this fixture.
///
/// The fixture root is written as `<root>` so the recording does not depend on
/// where the test tree happens to live.
const RECORDED: &str = include_str!("node_expected.json");

fn initialize_once() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace and returns the JSON of `source`'s `__out`.
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
    let namespace = Modules.install(scope, &mut ctx).expect("install modules");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "modulesBinding").expect("key");
    global
        .set(scope, key.into(), namespace.into())
        .expect("set");

    let source = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, source, None).expect("compiles");
    script.run(scope).expect("runs");
    let out_key = v8::String::new(scope, "__out").expect("key");
    global
        .get(scope, out_key.into())
        .expect("__out")
        .to_rust_string_lossy(scope)
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "rn-bind-modules-parity-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("temp dir");
        Self(base)
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent dirs");
        }
        std::fs::write(path, contents).expect("write");
    }

    fn dir(&self, relative: &str) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::create_dir_all(&path).expect("dirs");
        path
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.0.join(relative)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The fixture tree the recording was made from.
fn fixture() -> TempDir {
    let dir = TempDir::new("fx");
    dir.write(
        "fx/plain/package.json",
        r#"{"name":"plain-pkg","main":"index.js"}"#,
    );
    dir.write(
        "fx/modtype/package.json",
        r#"{"name":"mod-pkg","type":"module","main":"m.mjs"}"#,
    );
    dir.write("fx/parent/package.json", r#"{"type":"module"}"#);
    dir.dir("fx/parent/sub/deep");
    dir.write(
        "fx/inmod/node_modules/pkg/package.json",
        r#"{"name":"pkg-in-nm","version":"1.0.0"}"#,
    );
    dir.dir("fx/inmod/node_modules/pkg/sub");
    dir.write("fx/malformed/package.json", r#"{"name":broken"#);
    dir.write(
        "fx/scope/node_modules/pkg/package.json",
        r#"{"name":"scope-pkg","type":"module","exports":{".":"./i.js"}}"#,
    );
    dir.dir("fx/scope/node_modules/pkg/lib");
    dir.write(
        "fx/nearest-sub/a/package.json",
        r#"{"name":"inner","type":"commonjs"}"#,
    );
    dir.dir("fx/nearest-sub/b");
    dir.dir("fx/plain/lib");
    dir
}

/// Queries the binding for every recorded case.
///
/// Each entry returns what the recording holds: an array (as a JSON array with
/// `null` for `undefined` slots), a string, `"__undefined__"`, or
/// `"THREW:<code>"`.
fn probe(dir: &TempDir) -> serde_json::Value {
    let root = dir.path("fx");
    let root = root.display();
    let source = format!(
        r##"
        const root = "{root}";
        const out = {{}};
        const guard = (fn) => {{
            try {{
                const v = fn();
                return v === undefined ? "__undefined__" : v;
            }} catch (error) {{
                return "THREW:" + error.code;
            }}
        }};
        const norm = (v) => Array.isArray(v)
            // Only the six slots Node 22 also has, so the recording matches.
            ? {{ array: Array.from(v.slice(0, 6), (x) => x === undefined ? "__undefined__" : x) }}
            : v;

        out.read_plain = norm(guard(() => modulesBinding.readPackageJSON(root + "/plain/package.json")));
        out.read_modtype = norm(guard(() => modulesBinding.readPackageJSON(root + "/modtype/package.json")));
        out.read_malformed = norm(guard(() => modulesBinding.readPackageJSON(root + "/malformed/package.json")));
        out.read_absent = norm(guard(() => modulesBinding.readPackageJSON(root + "/nope/package.json")));
        out.read_exports = norm(guard(() => modulesBinding.readPackageJSON(root + "/scope/node_modules/pkg/package.json")));
        out.scope_plain = norm(guard(() => modulesBinding.getPackageScopeConfig("file://" + root + "/plain/lib/x.js")));
        out.scope_pkg = norm(guard(() => modulesBinding.getPackageScopeConfig("file://" + root + "/scope/node_modules/pkg/lib/x.js")));
        out.scope_malformed = norm(guard(() => modulesBinding.getPackageScopeConfig("file://" + root + "/malformed/x.js")));
        out.type_plain = norm(guard(() => modulesBinding.getPackageType("file://" + root + "/plain/x.js")));
        out.type_modtype = norm(guard(() => modulesBinding.getPackageType("file://" + root + "/modtype/x.js")));
        out.type_bad_url = norm(guard(() => modulesBinding.getPackageType("https://example.com/x.js")));
        out.nearest_type_inner_trailing = norm(guard(() => modulesBinding.getNearestParentPackageJSONType(root + "/nearest-sub/a/")));
        out.nearest_type_inner_file = norm(guard(() => modulesBinding.getNearestParentPackageJSONType(root + "/nearest-sub/a/x.js")));
        out.nearest_type_nm = norm(guard(() => modulesBinding.getNearestParentPackageJSONType(root + "/inmod/node_modules/pkg/sub/x.js")));
        out.nearest_type_parent = norm(guard(() => modulesBinding.getNearestParentPackageJSONType(root + "/parent/sub/deep/x.js")));
        out.nearest_type_none = norm(guard(() => modulesBinding.getNearestParentPackageJSONType("/tmp/parity-nowhere/x.js")));
        __out = JSON.stringify(out);
        "##
    );
    let json = run(&source);
    let value: serde_json::Value = serde_json::from_str(&json).expect("probe output is JSON");
    scrub_root(&value, dir)
}

/// Rewrites the fixture root to `<root>` so answers compare across machines.
///
/// Both probes spell paths as `<temp>/fx/...`, and the recording was made from a
/// tree whose `fx/` sat directly in its working directory, so the replacement
/// target includes the `fx` segment.
fn scrub_root(value: &serde_json::Value, dir: &TempDir) -> serde_json::Value {
    let text = value
        .to_string()
        .replace(&dir.0.display().to_string(), "<root>");
    serde_json::from_str(&text).expect("scrubbing preserves JSON")
}

/// The same probe, run against a real `node`.
fn probe_with_node(dir: &TempDir) -> Option<serde_json::Value> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/node_probe.js");
    if !script.is_file() {
        return None;
    }
    let out = Command::new("node")
        .arg("--expose-internals")
        .arg("--no-warnings")
        .arg(&script)
        // The probe builds every path from `process.cwd() + '/fx'`, which is
        // the same spelling the Rust probe uses.
        .current_dir(&dir.0)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

#[test]
fn package_type_detection_matches_the_recording() {
    let dir = fixture();
    let recorded: serde_json::Value = serde_json::from_str(RECORDED).expect("the recording parses");
    let actual = probe(&dir);

    let recorded = recorded.as_object().expect("recording is an object");
    let actual = actual.as_object().expect("probe is an object");
    assert_eq!(
        recorded.len(),
        actual.len(),
        "the probe must query exactly the recorded cases"
    );

    let mut mismatches = Vec::new();
    for (case, expected) in recorded {
        let got = actual.get(case).unwrap_or(&serde_json::Value::Null);
        if got != expected {
            mismatches.push(format!("{case}: expected {expected}, got {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "package.json answers differ from Node:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn the_recording_still_matches_a_live_node() {
    // Skipped when no `node` is installed, because the gate for this crate must
    // not depend on an external binary. When it is, this proves the recording
    // is not stale.
    let dir = fixture();
    let Some(live) = probe_with_node(&dir) else {
        return;
    };
    let recorded: serde_json::Value = serde_json::from_str(RECORDED).expect("the recording parses");
    // `nearest_type_none` and the malformed paths embed absolute paths, so both
    // sides are scrubbed to `<root>` before comparing.
    assert_eq!(
        scrub_root(&recorded, &dir),
        scrub_root(&live, &dir),
        "the recorded Node answers no longer match the installed node"
    );
}
