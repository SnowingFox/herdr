//! End-to-end: a real `.node` addon loads and runs against the rustnode binary.
//!
//! These tests spawn the built `rustnode` binary rather than driving an isolate
//! directly, because the claim being tested is the one a user makes: `require()` of
//! a compiled addon works. That needs the real CLI bootstrap (so `process.dlopen`
//! is installed), the real CommonJS loader, and the real exported symbol table.
//!
//! Every test calls [`support::build_addon_or_abort`] first, which compiles the
//! addon from source on every run and aborts the process if the compile fails. That
//! is intentional: a stale binary has produced a false PASS in this project before,
//! and a check that a failed build cannot satisfy is worth the bluntness.

mod support;

use std::path::PathBuf;
use std::process::Command;

/// The `rustnode` binary `cargo test` built alongside this test.
fn rustnode() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

/// Runs a script through the CLI and returns `(stdout, stderr, success)`.
fn run(script: &str) -> (String, String, bool) {
    let binary = rustnode();
    assert!(
        binary.is_file(),
        "{} does not exist; the CLI must be built before these tests (the gate does this)",
        binary.display()
    );
    let output = Command::new(&binary)
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary must be runnable");
    (
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
        output.status.success(),
    )
}

/// Runs a script and asserts it succeeded, returning stdout.
fn run_ok(script: &str) -> String {
    let (stdout, stderr, success) = run(script);
    assert!(success, "script failed: {stderr}");
    stdout
}

/// JSON-escapes a path so it can be embedded in a script literal.
fn literal(path: &std::path::Path) -> String {
    format!("{:?}", path.to_string_lossy())
}

#[test]
fn a_real_addon_loads_and_computes_a_value() {
    // The headline claim: `add(2, 3)` is a JavaScript call into C, which produces a
    // JavaScript number. Nothing about it works if the `napi_value` bridge, the
    // entry point lookup, or the symbol resolution is wrong.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.addonName, addon.add(2, 3), addon.add(0.5, 0.25));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "rustnode-test-addon 5 0.75");
}

#[test]
fn a_native_function_calls_a_javascript_callback() {
    // The other direction of the bridge, and the one a value-table implementation
    // gets wrong: the string the callback receives was created by
    // `napi_create_string_utf8` inside C, and the callback's return value travelled
    // back out through `napi_call_function`.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.callWithNativeArgument((text) => '<' + text + '>'));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "<from native code>");
}

#[test]
fn nested_native_to_javascript_calls_work() {
    // `applyTwice(fn, value)` calls back into JavaScript twice from one native
    // frame, so a scope that is torn down after the first call fails here.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.applyTwice((x) => x * 2, 5));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "20");
}

#[test]
fn objects_arrays_and_typed_classification_cross_the_boundary() {
    // Object creation, named property set, array-with-length, element set and
    // `napi_typeof`, in one call. A bridge that only handled primitives would leave
    // every one of these unproven.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(JSON.stringify(addon.describe(42)));\n\
         console.log(JSON.stringify(addon.describe('text')));",
        literal(&build.path)
    ));
    assert_eq!(
        stdout,
        "{\"kind\":\"number\",\"multiples\":[0,7,14]}\n\
         {\"kind\":\"string\",\"multiples\":[0,7,14]}"
    );
}

#[test]
fn a_property_name_passes_from_javascript_into_native_code() {
    // The key crosses too: `readProperty` receives the name as a JavaScript string,
    // reads it with `napi_get_value_string_utf8`, and looks the property up.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.readProperty({{ greeting: 'hi', n: 7 }}, 'greeting'),\n\
                     addon.readProperty({{ greeting: 'hi', n: 7 }}, 'n'),\n\
                     addon.readProperty({{}}, 'absent'));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "hi 7 undefined");
}

#[test]
fn an_addon_error_surfaces_as_a_catchable_javascript_error() {
    // `napi_throw_type_error` from C must reach a JavaScript `catch` with the
    // `name` and `code` the addon asked for. A thrown error that V8 swallowed would
    // make the whole error path untrustworthy.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         try {{ addon.fail('custom message'); }}\n\
         catch (e) {{ console.log(e.name, e.code, e.message); }}",
        literal(&build.path)
    ));
    assert_eq!(stdout, "TypeError ERR_ADDON_FAILED custom message");
}

#[test]
fn the_addon_reports_the_runtimes_napi_and_node_version() {
    // `napi_get_version` and `napi_get_node_version` are what an addon uses to
    // decide what it may call, and `node_api_get_module_file_name` must be the
    // percent-encoded `file://` URL rather than a bare path.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         const info = addon.versionInfo();\n\
         console.log(info.napiVersion, info.nodeMajor,\n\
                     info.moduleFilename === require('url').pathToFileURL({}).href);",
        literal(&build.path),
        literal(&build.path)
    ));
    assert_eq!(stdout, "10 28 true");
}

#[test]
fn a_descriptor_table_registers_methods_and_values() {
    // `napi_define_properties` with an array of `napi_property_descriptor`s is how
    // almost every real addon registers, and it is what `1_hello_world` needs. Both
    // non-accessor descriptor forms are covered: `method` and `value`.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.addFromTable(20, 22), addon.tableMarker);\n\
         console.log(JSON.stringify(addon.describeProperties()));\n\
         // `napi_default_method` is writable|configurable without enumerable, so a\n\
         // method registered that way must not appear in Object.keys.\n\
         console.log(Object.keys(addon).includes('addFromTable'));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "42 table\n{\"label\":\"descriptor\"}\nfalse");
}

#[test]
fn require_of_a_dot_node_file_goes_through_the_commonjs_loader() {
    // The real-world path: `Module._extensions['.node']` calls `process.dlopen`. The
    // module is cached by the loader afterwards, which both runtimes do, so this
    // asserts the load happened and the export works rather than anything about the
    // cache.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const first = require({path});\n\
         const second = require({path});\n\
         console.log(first.add(1, 2), second.add(1, 2), first === second);",
        path = literal(&build.path)
    ));
    assert_eq!(stdout, "3 3 true");
}

#[test]
fn a_missing_addon_file_reports_dlopen_failed() {
    // Verified against real Node: `process.dlopen` on a nonexistent path produces
    // `ERR_DLOPEN_FAILED` with the loader's own text. `require` of the same path
    // produces `MODULE_NOT_FOUND` instead, because the loader checks first — the next
    // test pins that difference so the two are never conflated.
    let (stdout, _stderr, success) = run(
        "try { process.dlopen({ exports: {} }, '/definitely/not/here/addon.node'); }\n\
         catch (e) { console.log(e.name, e.code); console.log(e.message); }",
    );
    assert!(success);
    assert_eq!(
        stdout,
        "Error ERR_DLOPEN_FAILED\n\
         /definitely/not/here/addon.node: cannot open shared object file: No such file or directory"
    );
}

#[test]
fn a_non_shared_object_reports_the_loaders_message() {
    // A file that exists but is not an ELF shared object. The text comes from the
    // dynamic loader and is part of what a user compares against Node.
    let scratch = std::env::temp_dir().join(format!(
        "rn-napi-notso-{}-{:?}.node",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&scratch, b"this is not a shared object").expect("write");
    let (stdout, _stderr, success) = run(&format!(
        "try {{ process.dlopen({{ exports: {{}} }}, {}); }}\n\
         catch (e) {{ console.log(e.code, e.message); }}",
        literal(&scratch)
    ));
    let _ = std::fs::remove_file(&scratch);
    assert!(success);
    assert_eq!(
        stdout,
        format!("ERR_DLOPEN_FAILED {}: file too short", scratch.display())
    );
}

#[test]
fn a_shared_object_without_an_entry_point_reports_no_self_registration() {
    // The third error shape acceptance requires, and the one that distinguishes "this
    // is a library but not an addon" from "this file is broken". The message is
    // Node's, word for word, including the period inside the quotes.
    let scratch = std::env::temp_dir().join(format!(
        "rn-napi-nosym-{}-{:?}.node",
        std::process::id(),
        std::thread::current().id()
    ));
    let source = scratch.with_extension("c");
    std::fs::write(&source, b"int not_an_addon(void) { return 1; }\n").expect("write");
    let compiled = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&scratch)
        .arg(&source)
        .status()
        .expect("cc must be available");
    assert!(compiled.success(), "the fixture must compile");

    let (stdout, _stderr, success) = run(&format!(
        "try {{ process.dlopen({{ exports: {{}} }}, {}); }}\n\
         catch (e) {{ console.log(e.code); console.log(e.message); }}",
        literal(&scratch)
    ));
    let _ = std::fs::remove_file(&scratch);
    let _ = std::fs::remove_file(&source);
    assert!(success);
    assert_eq!(
        stdout,
        format!(
            "ERR_DLOPEN_FAILED\nModule did not self-register: '{}'.",
            scratch.display()
        )
    );
}

#[test]
fn dlopen_with_too_few_arguments_reports_missing_args() {
    // Node's `THROW_ERR_MISSING_ARGS`, matched exactly: a `TypeError` named
    // `ERR_MISSING_ARGS` with that message.
    let (stdout, _stderr, success) = run("try { process.dlopen(); }\n\
         catch (e) { console.log(e.name, e.code, e.message); }");
    assert!(success);
    assert_eq!(
        stdout,
        "TypeError ERR_MISSING_ARGS process.dlopen needs at least 2 arguments"
    );
}

#[test]
fn dlopen_twice_gives_each_load_its_own_exports_object_and_functions() {
    // Node's `1_hello_world` asserts that two loads of one addon produce two
    // distinct function objects, because `napi_create_function` must create a new
    // function each time rather than caching one per name. `require` hides this by
    // caching the module, so `process.dlopen` is called directly.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const path = {};\n\
         const first = {{ exports: {{}} }};\n\
         const second = {{ exports: {{}} }};\n\
         process.dlopen(first, path);\n\
         process.dlopen(second, path);\n\
         console.log(first.exports !== second.exports,\n\
                     first.exports.add !== second.exports.add,\n\
                     first.exports.add(2, 2), second.exports.add(2, 2));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "true true 4 4");
}
