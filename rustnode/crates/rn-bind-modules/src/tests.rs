//! End-to-end tests that drive the installed namespace from JavaScript.
//!
//! These install the namespace the way `lib/**` reaches it, expose it as a
//! global, and run script against real files in a temporary directory. That
//! exercises the same marshalling the loader uses, which Rust-only unit tests
//! cannot: array slot order, `undefined` versus a value, and null prototypes.

use std::path::PathBuf;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::Modules;

fn initialize_once() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace, runs `source`, returns `String(__out)`.
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
    let out = global.get(scope, out_key.into()).expect("__out");
    out.to_rust_string_lossy(scope)
}

/// A temporary directory that cleans itself up.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "rn-bind-modules-js-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("temp dir");
        Self(base)
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.0.join(relative)
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent dirs");
        }
        std::fs::write(&path, contents).expect("write");
        path
    }

    fn url(&self, relative: &str) -> String {
        format!("file://{}", self.path(relative).display())
    }

    fn string(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn read_package_json_returns_the_seven_slot_array() {
    let dir = TempDir::new("read-array");
    let path = dir.write("package.json", r#"{"name":"pkg","main":"index.js"}"#);
    let source = format!(
        r#"
        const value = modulesBinding.readPackageJSON({path:?});
        __out = JSON.stringify({{
            isArray: Array.isArray(value),
            length: value.length,
            name: value[0],
            main: value[1],
            type: value[2],
            imports: value[3],
            exports: value[4],
            filePath: value[5],
            private: value[6],
        }});
        "#,
        path = path.display().to_string()
    );
    let out = run(&source);
    assert_eq!(
        out,
        format!(
            r#"{{"isArray":true,"length":7,"name":"pkg","main":"index.js","type":"none","filePath":"{}"}}"#,
            path.display()
        )
    );
}

#[test]
fn read_package_json_reports_type_module() {
    let dir = TempDir::new("read-module");
    let path = dir.write("package.json", r#"{"name":"pkg","type":"module"}"#);
    let source = format!(
        "const v = modulesBinding.readPackageJSON({:?}); __out = v[2];",
        path.display().to_string()
    );
    assert_eq!(run(&source), "module");
}

#[test]
fn read_package_json_returns_undefined_when_absent() {
    let dir = TempDir::new("read-absent");
    let source = format!(
        "const v = modulesBinding.readPackageJSON({:?}); __out = String(v === undefined);",
        dir.path("nope/package.json").display().to_string()
    );
    assert_eq!(run(&source), "true");
}

#[test]
fn read_package_json_throws_invalid_package_config() {
    let dir = TempDir::new("read-malformed");
    let path = dir.write("package.json", r#"{"name":broken"#);
    let source = format!(
        r#"
        try {{
            modulesBinding.readPackageJSON({path:?});
            __out = "no throw";
        }} catch (error) {{
            __out = `${{error.code}}|${{error.name}}|${{error.message}}`;
        }}
        "#,
        path = path.display().to_string()
    );
    assert_eq!(
        run(&source),
        format!(
            "ERR_INVALID_PACKAGE_CONFIG|Error|Invalid package config {}.",
            path.display()
        )
    );
}

#[test]
fn exports_and_imports_come_back_as_raw_json_text() {
    let dir = TempDir::new("raw-fields");
    let path = dir.write(
        "package.json",
        r##"{"name":"p","exports":{".":"./i.js"},"imports":{"#a":"./a.js"}}"##,
    );
    let source = format!(
        r#"
        const v = modulesBinding.readPackageJSON({path:?});
        __out = JSON.stringify({{imports: v[3], exports: v[4]}});
        "#,
        path = path.display().to_string()
    );
    assert_eq!(
        run(&source),
        r##"{"imports":"{\"#a\":\"./a.js\"}","exports":"{\".\":\"./i.js\"}"}"##
    );
}

#[test]
fn nearest_parent_walks_up_from_the_given_path() {
    let dir = TempDir::new("nearest-js");
    dir.write("package.json", r#"{"name":"outer","type":"module"}"#);
    std::fs::create_dir_all(dir.path("sub/dir")).expect("dirs");
    let source = format!(
        r#"
        const value = modulesBinding.getNearestParentPackageJSON({check:?});
        __out = value === undefined ? "undefined" : value[0] + "|" + value[2];
        "#,
        check = dir.path("sub/dir/x.js").display().to_string()
    );
    assert_eq!(run(&source), "outer|module");
}

#[test]
fn nearest_parent_stops_at_node_modules() {
    // The enclosing package above `node_modules` must not supply the type: a
    // dependency is judged by its own package.json.
    let dir = TempDir::new("nearest-boundary");
    dir.write("package.json", r#"{"name":"outer","type":"module"}"#);
    std::fs::create_dir_all(dir.path("node_modules/dep/sub")).expect("dirs");
    let source = format!(
        r#"
        const value = modulesBinding.getNearestParentPackageJSON({check:?});
        __out = String(value === undefined);
        "#,
        check = dir.path("node_modules/dep/sub/x.js").display().to_string()
    );
    assert_eq!(run(&source), "true");
}

#[test]
fn nearest_parent_type_reports_undefined_without_a_package_json() {
    let dir = TempDir::new("nearest-type-none");
    std::fs::create_dir_all(dir.path("sub")).expect("dirs");
    let source = format!(
        "const t = modulesBinding.getNearestParentPackageJSONType({:?}); __out = String(t);",
        dir.path("sub/x.js").display().to_string()
    );
    assert_eq!(run(&source), "undefined");
}

#[test]
fn nearest_parent_type_reports_the_bare_type() {
    let dir = TempDir::new("nearest-type");
    dir.write("package.json", r#"{"type":"module"}"#);
    let source = format!(
        "const t = modulesBinding.getNearestParentPackageJSONType({:?}); __out = t;",
        dir.path("x.js").display().to_string()
    );
    assert_eq!(run(&source), "module");
}

#[test]
fn package_scope_config_walks_from_a_file_url() {
    let dir = TempDir::new("scope-js");
    dir.write("package.json", r#"{"name":"scope","type":"module"}"#);
    std::fs::create_dir_all(dir.path("lib")).expect("dirs");
    let source = format!(
        r#"
        const value = modulesBinding.getPackageScopeConfig({url:?});
        __out = Array.isArray(value) ? value[0] + "|" + value[2] : "string:" + value;
        "#,
        url = dir.url("lib/x.js")
    );
    assert_eq!(run(&source), "scope|module");
}

#[test]
fn package_scope_config_returns_a_path_string_when_nothing_is_found() {
    // The string, not `undefined`, is how the JavaScript layer tells "no
    // package" apart from "a package with no fields".
    let dir = TempDir::new("scope-none");
    std::fs::create_dir_all(dir.path("lib")).expect("dirs");
    let source = format!(
        r#"
        const value = modulesBinding.getPackageScopeConfig({url:?});
        __out = typeof value + "|" + value;
        "#,
        url = dir.url("lib/x.js")
    );
    let out = run(&source);
    assert!(out.starts_with("string|"), "{out}");
    assert!(out.ends_with("/package.json"), "{out}");
}

#[test]
fn package_scope_config_stops_at_node_modules() {
    let dir = TempDir::new("scope-boundary");
    dir.write("package.json", r#"{"type":"module"}"#);
    std::fs::create_dir_all(dir.path("node_modules/dep/lib")).expect("dirs");
    let source = format!(
        "const value = modulesBinding.getPackageScopeConfig({:?}); __out = value;",
        dir.url("node_modules/dep/lib/x.js")
    );
    let out = run(&source);
    assert!(
        out.ends_with("/node_modules/package.json"),
        "expected the node_modules sentinel, got {out}"
    );
}

#[test]
fn package_type_reports_none_and_undefined() {
    let dir = TempDir::new("package-type");
    dir.write("plain/package.json", r#"{"name":"plain"}"#);
    dir.write("esm/package.json", r#"{"type":"module"}"#);
    std::fs::create_dir_all(dir.path("none")).expect("dirs");
    let source = format!(
        r#"
        __out = JSON.stringify([
            modulesBinding.getPackageType({plain:?}),
            modulesBinding.getPackageType({esm:?}),
            String(modulesBinding.getPackageType({none:?})),
        ]);
        "#,
        plain = dir.url("plain/x.js"),
        esm = dir.url("esm/x.js"),
        none = dir.url("none/x.js")
    );
    assert_eq!(run(&source), r#"["none","module","undefined"]"#);
}

#[test]
fn package_type_rejects_a_non_file_url() {
    let source = r#"
        try {
            modulesBinding.getPackageType("https://example.com/x.js");
            __out = "no throw";
        } catch (error) {
            __out = `${error.code}|${error.name}|${error.input}`;
        }
    "#;
    assert_eq!(
        run(source),
        "ERR_INVALID_URL|TypeError|https://example.com/x.js"
    );
}

#[test]
fn root_package_json_finds_a_private_package() {
    let dir = TempDir::new("root-private");
    dir.write(
        "node_modules/dep/package.json",
        r#"{"name":"dep","private":true}"#,
    );
    std::fs::create_dir_all(dir.path("node_modules/dep/lib")).expect("dirs");
    let source = format!(
        "const v = modulesBinding.getRootPackageJSON({:?}); __out = v === undefined ? \"undefined\" : v[0];",
        dir.path("node_modules/dep/lib/x.js").display().to_string()
    );
    assert_eq!(run(&source), "dep");
}

#[test]
fn root_package_json_is_undefined_without_node_modules() {
    let dir = TempDir::new("root-none");
    dir.write("package.json", r#"{"name":"top"}"#);
    std::fs::create_dir_all(dir.path("lib")).expect("dirs");
    let source = format!(
        "const v = modulesBinding.getRootPackageJSON({:?}); __out = String(v === undefined);",
        dir.path("lib/x.js").display().to_string()
    );
    assert_eq!(run(&source), "true");
}

#[test]
fn parse_package_json_accepts_a_string_and_a_buffer() {
    let source = r#"
        const fromString = modulesBinding.parsePackageJSON('{"name":"a","type":"module"}', "/x/package.json");
        // A bare isolate has no `TextEncoder`, so build the bytes directly.
        // This is the `ArrayBufferView` branch `internal/vfs/setup.js` uses.
        const bytes = new Uint8Array([123, 34, 110, 97, 109, 101, 34, 58, 34, 98, 34, 125]);
        const fromBuffer = modulesBinding.parsePackageJSON(bytes, "/y/package.json");
        __out = JSON.stringify([fromString[0], fromString[2], fromBuffer[0], fromBuffer[2]]);
    "#;
    assert_eq!(run(source), r#"["a","module","b","none"]"#);
}

#[test]
fn parse_package_json_reports_a_syntax_error() {
    let source = r#"
        try {
            modulesBinding.parsePackageJSON('{"name":', "/x/package.json");
            __out = "no throw";
        } catch (error) {
            __out = error.code;
        }
    "#;
    assert_eq!(run(source), "ERR_INVALID_PACKAGE_CONFIG");
}

#[test]
fn constants_have_node_values_and_no_prototype() {
    let source = r#"
        const b = modulesBinding;
        __out = JSON.stringify({
            formats: [b.moduleFormats.kCommonJS, b.moduleFormats.kModule],
            formatsProto: Object.getPrototypeOf(b.moduleFormats),
            types: [b.cachedCodeTypes.kCommonJS, b.cachedCodeTypes.kESM,
                    b.cachedCodeTypes.kStrippedTypeScript],
            typesProto: Object.getPrototypeOf(b.cachedCodeTypes),
            statuses: Array.from(b.compileCacheStatus),
            statusLength: b.compileCacheStatus.length,
        });
    "#;
    assert_eq!(
        run(source),
        r#"{"formats":[0,1],"formatsProto":null,"types":[0,1,2],"typesProto":null,"statuses":["FAILED","ENABLED","ALREADY_ENABLED","DISABLED"],"statusLength":4}"#
    );
}

#[test]
fn compile_cache_disabled_reports_no_directory() {
    // The environment this runs in may set `NODE_DISABLE_COMPILE_CACHE`, so
    // assert the shape rather than a particular status.
    let source = r#"
        const result = modulesBinding.enableCompileCache("/tmp/rn-bind-modules-disabled-probe");
        __out = JSON.stringify({
            isArray: Array.isArray(result),
            length: result.length,
            statusType: typeof result[0],
            messageType: typeof result[1],
            directoryType: typeof result[2],
            dirIsString: typeof modulesBinding.getCompileCacheDir() === "string",
        });
    "#;
    assert_eq!(
        run(source),
        r#"{"isArray":true,"length":3,"statusType":"number","messageType":"string","directoryType":"string","dirIsString":true}"#
    );
}

#[test]
fn enable_compile_cache_rejects_a_non_string_directory() {
    let source = r#"
        try {
            modulesBinding.enableCompileCache(42);
            __out = "no throw";
        } catch (error) {
            __out = `${error.code}|${error.message}`;
        }
    "#;
    assert_eq!(
        run(source),
        "ERR_INVALID_ARG_TYPE|cacheDir should be a string"
    );
}

#[test]
fn flush_compile_cache_validates_its_argument() {
    let source = r#"
        const results = [];
        try { modulesBinding.flushCompileCache("x"); results.push("threw"); }
        catch (error) { results.push(error.code); }
        results.push(String(modulesBinding.flushCompileCache()));
        results.push(String(modulesBinding.flushCompileCache(true)));
        __out = results.join(",");
    "#;
    assert_eq!(run(source), "ERR_INVALID_ARG_TYPE,undefined,undefined");
}

#[test]
fn compile_cache_entries_round_trip_through_the_binding() {
    // The TypeScript transpile cache is the one Node's `lib/**` drives with
    // these two members, and it is the one shape this crate can store.
    let dir = TempDir::new("cache-roundtrip");
    if std::env::var_os("NODE_DISABLE_COMPILE_CACHE").is_some() {
        return;
    }
    let source = format!(
        r#"
        const cacheDir = {cache:?};
        const enabled = modulesBinding.enableCompileCache(cacheDir);
        if (enabled[0] !== 1 && enabled[0] !== 2) {{
            __out = "cache not enabled: " + enabled[0] + " " + enabled[1];
        }} else {{
            const key = modulesBinding.cachedCodeTypes.kStrippedTypeScript;
            const first = modulesBinding.getCompileCacheEntry("const a: number = 1;", "/app/m.ts", key);
            const hadTranspiled = first.transpiled !== undefined;
            modulesBinding.saveCompileCacheEntry(first.external, "const a = 1;");
            modulesBinding.flushCompileCache();
            const second = modulesBinding.getCompileCacheEntry("const a: number = 1;", "/app/m.ts", key);
            __out = JSON.stringify({{
                hadTranspiled,
                isNullProto: Object.getPrototypeOf(second) === null,
                transpiled: second.transpiled,
            }});
        }}
        "#,
        cache = dir.string()
    );
    let out = run(&source);
    assert_eq!(
        out,
        r#"{"hadTranspiled":false,"isNullProto":true,"transpiled":"const a = 1;"}"#
    );
}

#[test]
fn deferred_members_destructure_cleanly_at_module_scope() {
    // `tools/deferred-reach.py` flags these two because
    // `internal/modules/esm/translators.js` destructures them at module scope.
    // That is a false positive for *destructuring*: reading an absent member
    // yields `undefined` and cannot throw. It only breaks a module when the
    // member is *called* during load, which is what made `zlib.crc32c` fatal.
    // This pins the reason the deferral is safe so the two cannot drift apart.
    let source = r#"
        const { getWasmCompileCacheEntry, saveWasmCompileCacheEntry } = modulesBinding;
        const typeofOk = typeof getWasmCompileCacheEntry === "undefined" &&
                         typeof saveWasmCompileCacheEntry === "undefined";
        // A guard of the shape a caller would use before the call site.
        const guarded = typeof getWasmCompileCacheEntry === "function";
        __out = JSON.stringify({ typeofOk, guarded });
    "#;
    assert_eq!(run(source), r#"{"typeofOk":true,"guarded":false}"#);
}

#[test]
fn every_contract_member_is_installed_or_deferred() {
    // `rn-compat` checks this against `contracts/modules.json`; asserting it
    // here means a member dropped from both lists fails at the crate's own
    // test rather than only in the aggregate check. The registry's own
    // `Namespace` is what has to be complete, not `MEMBERS`, because a
    // deferred member must be *absent* from the installed list for the check
    // to be meaningful.
    use rn_core::Namespace;

    let contract: serde_json::Value =
        serde_json::from_str(include_str!("../../../contracts/modules.json"))
            .expect("contract parses");
    let members = contract["members"].as_object().expect("members");
    let namespace = Namespace::from_module(&crate::Modules);

    let undeclared = namespace.undeclared(members.keys().map(String::as_str));
    assert!(
        undeclared.is_empty(),
        "neither installed nor deferred: {undeclared:?}"
    );

    // Nothing may be claimed that the contract does not know about, and no
    // member may be both installed and deferred.
    for name in &namespace.members {
        assert!(members.contains_key(name), "{name} is not in the contract");
        assert!(
            !namespace.deferred.contains_key(name),
            "{name} is claimed twice"
        );
    }
    for (name, reason) in &namespace.deferred {
        assert!(members.contains_key(name), "{name} is not in the contract");
        assert!(!reason.trim().is_empty(), "{name} gives no reason");
    }
    assert_eq!(namespace.members.len(), 15, "installed member count");
    assert_eq!(namespace.deferred.len(), 2, "deferred member count");
}
