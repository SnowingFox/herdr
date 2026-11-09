//! `require()` of real files, driven through the binary the way a user runs it.
//!
//! `require('./file.js')` is the whole point of a CommonJS runtime, and it broke
//! in a way no binding contract could catch: `util.privateSymbols` was missing
//! `module_source_private_symbol`, `lib/internal/modules/cjs/loader.js` destructured
//! it as `undefined`, and `module[undefined]` aliased every missing symbol onto the
//! string key `"undefined"`. `loadSource()` then read a *parent* `Module` object
//! back as a child's cached source and handed it to `compileFunctionForCJSLoader`,
//! which is type-strict, so the failure surfaced as a type error far from the
//! missing symbol.
//!
//! So these tests assert observable `require` behaviour rather than the internals:
//! resolution, the export shapes, the error code, and the per-module wrapper
//! parameters.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A scratch directory that each test owns outright.
///
/// The name carries the test name so the cases can run concurrently without
/// sharing a fixture, and it is removed on drop so a failing test does not leave
/// state behind for the next run.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "rustnode-file-require-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the fixture directory");
        Self { root }
    }

    /// Writes `contents` at `relative`, creating parent directories.
    fn write(&self, relative: &str, contents: &str) -> PathBuf {
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

/// Runs the script at `path`, returning `(stdout, stderr, success)`.
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

/// Runs the script at `path` and returns its trimmed stdout, failing with the
/// stderr when the process did not succeed.
fn stdout_of(path: &Path) -> String {
    let (stdout, stderr, ok) = run_script(path);
    assert!(ok, "the script failed: {stderr}");
    stdout.trim_end().to_string()
}

#[test]
fn a_relative_specifier_resolves_against_the_requiring_file() {
    let fixture = Fixture::new("relative");
    fixture.write(
        "sibling.js",
        "module.exports = { value: 'sibling value' };\n",
    );
    let main = fixture.write(
        "main.js",
        "const helper = require('./sibling.js');\nconsole.log(helper.value);\n",
    );
    assert_eq!(stdout_of(&main), "sibling value");
}

#[test]
fn an_absolute_specifier_loads_that_exact_file() {
    let fixture = Fixture::new("absolute");
    let dep = fixture.write("dep.js", "module.exports = 'absolute';\n");
    let main = fixture.write(
        "main.js",
        &format!(
            "console.log(require({dep:?}));\n",
            dep = dep.to_str().unwrap()
        ),
    );
    assert_eq!(stdout_of(&main), "absolute");
}

#[test]
fn a_required_module_can_require_further_modules() {
    // The bug this file exists for showed up one level down: the entry module
    // loaded, and the module *it* required received the wrong source.
    let fixture = Fixture::new("nested");
    fixture.write("leaf.js", "module.exports = 'leaf';\n");
    fixture.write(
        "middle.js",
        "module.exports = 'middle:' + require('./leaf.js');\n",
    );
    let main = fixture.write(
        "main.js",
        "console.log(require('./middle.js'));\nconsole.log(require('./middle.js'));\n",
    );
    assert_eq!(stdout_of(&main), "middle:leaf\nmiddle:leaf");
}

#[test]
fn a_subdirectory_module_resolves_its_parent_relative_require() {
    let fixture = Fixture::new("parent-relative");
    fixture.write("shared.js", "module.exports = 'shared';\n");
    fixture.write(
        "sub/deep.js",
        "module.exports = 'deep:' + require('../shared.js');\n",
    );
    let main = fixture.write("main.js", "console.log(require('./sub/deep.js'));\n");
    assert_eq!(stdout_of(&main), "deep:shared");
}

#[test]
fn a_json_file_is_parsed_rather_than_compiled() {
    let fixture = Fixture::new("json");
    fixture.write("data.json", r#"{"name":"data","n":7}"#);
    let main = fixture.write(
        "main.js",
        "const data = require('./data.json');\nconsole.log(data.name, data.n);\n",
    );
    assert_eq!(stdout_of(&main), "data 7");
}

#[test]
fn module_exports_and_the_exports_alias_are_both_visible() {
    // `module.exports` replaces the export object and `exports.foo` mutates it,
    // and a runtime that ignores either one is wrong in a different way.
    let fixture = Fixture::new("exports");
    fixture.write("replace.js", "module.exports = 'replaced';\n");
    fixture.write("augment.js", "exports.foo = 'augmented';\n");
    let main = fixture.write(
        "main.js",
        "console.log(require('./replace.js'), require('./augment.js').foo);\n",
    );
    assert_eq!(stdout_of(&main), "replaced augmented");
}

#[test]
fn a_missing_module_reports_module_not_found_with_the_specifier() {
    let fixture = Fixture::new("missing");
    let main = fixture.write(
        "main.js",
        "try { require('./nope.js'); }\n\
         catch (error) { console.log(error.code, error.message.split('\\n')[0]); }\n",
    );
    assert_eq!(
        stdout_of(&main),
        "MODULE_NOT_FOUND Cannot find module './nope.js'"
    );
}

#[test]
fn a_required_module_sees_its_own_filename_and_dirname() {
    // These are CommonJS wrapper parameters, not globals, so they have to be the
    // *required* file's path rather than the entry script's.
    let fixture = Fixture::new("meta");
    let dep = fixture.write("dep.js", "module.exports = [__filename, __dirname];\n");
    let main = fixture.write(
        "main.js",
        "const [filename, dirname] = require('./dep.js');\n\
         console.log(filename);\nconsole.log(dirname);\n",
    );
    let dep = dep.to_str().unwrap().to_string();
    let root = fixture.root.to_str().unwrap().to_string();
    assert_eq!(stdout_of(&main), format!("{dep}\n{root}"));
}

#[test]
fn the_entry_script_is_a_module_too() {
    // `rustnode script.js` is `node script.js`: the entry file is loaded through
    // the same CommonJS loader, so it gets the wrapper parameters and a `module`
    // whose exports a child can observe.
    let fixture = Fixture::new("entry");
    let main = fixture.write(
        "main.js",
        "console.log(typeof module, typeof exports, typeof require);\n\
         console.log(__filename.endsWith('main.js'), __dirname.length > 0);\n",
    );
    assert_eq!(stdout_of(&main), "object object function\ntrue true");
}

#[test]
fn a_package_resolves_by_name_through_node_modules() {
    let fixture = Fixture::new("node-modules");
    fixture.write(
        "node_modules/mypkg/package.json",
        r#"{"name":"mypkg","version":"1.2.3","main":"index.js"}"#,
    );
    fixture.write(
        "node_modules/mypkg/index.js",
        "module.exports = { name: 'mypkg', version: '1.2.3' };\n",
    );
    let main = fixture.write(
        "main.js",
        "const pkg = require('mypkg');\nconsole.log(pkg.name, pkg.version);\n",
    );
    assert_eq!(stdout_of(&main), "mypkg 1.2.3");
}

#[test]
fn the_same_file_required_twice_is_one_module_instance() {
    // The loader caches by resolved filename. A second compile would run the
    // module body twice and hand out two exports objects, which breaks any
    // module that keeps state.
    let fixture = Fixture::new("cache");
    fixture.write(
        "counter.js",
        "globalThis.__rnLoads = (globalThis.__rnLoads || 0) + 1;\n\
         module.exports = { loads: globalThis.__rnLoads };\n",
    );
    let main = fixture.write(
        "main.js",
        "const first = require('./counter.js');\n\
         const second = require('./counter.js');\n\
         console.log(first === second, first.loads);\n",
    );
    assert_eq!(stdout_of(&main), "true 1");
}

#[test]
fn private_symbols_are_all_present_and_distinct() {
    // The defect behind every case above: a missing entry is not an error the
    // JavaScript layer can report. The destructured binding is `undefined`, and
    // `object[undefined]` is the string key `"undefined"`, so all missing names
    // share one property — which is how a child module came to read its parent
    // back as its own source text.
    //
    // Asserting the count and the distinctness together is what makes that
    // failure loud: absent names collapse to one shared `undefined`.
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args([
            "--expose-internals",
            "-e",
            "const realm = require('internal/bootstrap/realm');\n\
             const symbols = realm.internalBinding('util').privateSymbols;\n\
             const names = Object.keys(symbols);\n\
             const missing = names.filter((name) => symbols[name] === undefined);\n\
             const values = names.map((name) => symbols[name]);\n\
             console.log(names.length, missing.length, new Set(values).size);",
        ])
        .output()
        .expect("rustnode runs");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // 22 recorded names, none undefined, and every one a distinct symbol.
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "22 0 22",
        "every private symbol must be installed and distinct"
    );
}
