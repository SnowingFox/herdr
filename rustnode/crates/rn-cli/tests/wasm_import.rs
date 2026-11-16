//! Importing a `.wasm` file from ES modules, driven through the binary.
//!
//! `import('./x.wasm')` translated through
//! `lib/internal/modules/esm/translators.js`, which called
//! `getWasmCompileCacheEntry` unconditionally. That member was declared deferred
//! in `rn-bind-modules`, so every `.wasm` import threw
//! `TypeError: getWasmCompileCacheEntry is not a function` — not "ran without a
//! cache", which is what the deferral claimed. The detector that should have
//! found it (`tools/deferred-reach.py`) only looked at module scope, and the
//! call sits inside the `wasm` translator's function body.
//!
//! These tests are deliberately end-to-end: they run the real binary on a real
//! `.wasm` file and check that the module *instantiates* and its export
//! *executes*, because "the import resolved" would pass on a module whose
//! exports were never linked. The module bytes are built in Rust rather than
//! checked in, so the fixture states what it contains and needs no `wat` crate
//! or new dependency.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A scratch directory that each test owns outright.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "rustnode-wasm-import-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the fixture directory");
        Self { root }
    }

    fn write(&self, relative: &str, contents: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create the fixture parent");
        }
        std::fs::write(&path, contents).expect("write the fixture file");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn run_script(path: &Path) -> (String, String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg(path)
        .output()
        .expect("rustnode runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

fn stdout_of(path: &Path) -> String {
    let (stdout, stderr, ok) = run_script(path);
    assert!(ok, "the script failed: {stderr}");
    stdout.trim_end().to_string()
}

/// LEB128, as every wasm section header uses.
fn leb(value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut value = value;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn section(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    out.extend(leb(payload.len()));
    out.extend_from_slice(payload);
    out
}

fn vec_of(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = leb(items.len());
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// A module exporting `add(i32, i32) -> i32`, assembled here so the fixture is
/// readable.
///
/// Every byte is load-bearing: the first version of this helper emitted an
/// extra `0x00` after the local declaration count, which became
/// `unreachable`, and both runtimes rejected the call the same way — a useful
/// parity data point but not a test of the import path.
fn add_module() -> Vec<u8> {
    // type: (i32, i32) -> i32
    let types = vec_of(&[{
        let mut t = vec![0x60];
        t.extend(vec_of(&[vec![0x7f], vec![0x7f]]));
        t.extend(vec_of(&[vec![0x7f]]));
        t
    }]);
    // function: one function, type index 0
    let functions = vec_of(&[leb(0)]);
    // memory: one memory, minimum 1 page
    let memory = vec_of(&[{
        let mut m = vec![0x00];
        m.extend(leb(1));
        m
    }]);
    // export: "add" as a function, index 0
    let exports = vec_of(&[{
        let mut e = leb(3);
        e.extend(b"add");
        e.push(0x00);
        e.extend(leb(0));
        e
    }]);
    // code: no locals, local.get 0, local.get 1, i32.add, end
    let code = vec_of(&[{
        let body = [0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b];
        let mut c = leb(body.len());
        c.extend_from_slice(&body);
        c
    }]);

    let mut module = b"\0asm\x01\0\0\0".to_vec();
    module.extend(section(1, &types));
    module.extend(section(3, &functions));
    module.extend(section(5, &memory));
    module.extend(section(7, &exports));
    module.extend(section(10, &code));
    module
}

#[test]
fn a_wasm_module_imports_instantiates_and_its_export_runs() {
    let fixture = Fixture::new("add");
    fixture.write("lib.wasm", &add_module());
    let main = fixture.write(
        "main.mjs",
        br#"const module = await import('./lib.wasm');
console.log(Object.keys(module).join(','));
console.log(module.add(40, 2));
console.log(module.add(1, -1));
"#,
    );
    // The export list, then the two calls. A module that imported but did not
    // instantiate would print the keys and then throw from the call.
    assert_eq!(stdout_of(&main), "add\n42\n0");
}

#[test]
fn an_empty_wasm_module_imports_as_an_empty_namespace() {
    // The minimal module: header only, no sections. This is the case the
    // original repro used, and it exercises the translator on the shortest
    // possible input.
    let fixture = Fixture::new("empty");
    fixture.write("empty.wasm", b"\0asm\x01\0\0\0");
    let main = fixture.write(
        "main.mjs",
        br#"const module = await import('./empty.wasm');
console.log(typeof module, Object.keys(module).length);
"#,
    );
    assert_eq!(stdout_of(&main), "object 0");
}

#[test]
fn a_wasm_import_survives_an_enabled_compile_cache() {
    // The compile cache is the reason the translator calls the two binding
    // members at all, so the import has to work with the cache on and not just
    // off. `getWasmCompileCacheEntry` returns an entry with no `module` (a
    // miss), the caller compiles from the wire bytes, and then calls
    // `saveWasmCompileCacheEntry` — the exact path that threw when the members
    // were deferred.
    let fixture = Fixture::new("cache");
    fixture.write("lib.wasm", &add_module());
    let cache = fixture.root.join("cache");
    let main = fixture.write(
        "main.mjs",
        format!(
            "import {{ createRequire }} from 'node:module';\n\
             const require = createRequire(import.meta.url);\n\
             const {{ enableCompileCache }} = require('node:module');\n\
             const enabled = enableCompileCache({cache:?});\n\
             console.log('status', enabled.status);\n\
             const module = await import('./lib.wasm');\n\
             console.log(module.add(2, 3));\n",
            cache = cache.to_str().unwrap()
        )
        .as_bytes(),
    );
    // status 1 is ENABLED. 3 would be DISABLED, which happens when
    // `NODE_DISABLE_COMPILE_CACHE` is inherited from the machine running the
    // tests — so the assertion is on the import, and the status is reported
    // rather than pinned.
    let (stdout, stderr, ok) = run_script(&main);
    assert!(ok, "the script failed: {stderr}");
    let lines: Vec<&str> = stdout.trim_end().lines().collect();
    assert_eq!(lines.last(), Some(&"5"), "the export must run: {stdout}");
}
