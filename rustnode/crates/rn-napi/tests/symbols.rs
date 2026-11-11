//! The exported symbol table, checked against the built binary.
//!
//! This is the test that makes the export mechanism a fact rather than a claim. An
//! addon's `napi_*` imports are resolved by the dynamic loader against the rustnode
//! executable's dynamic symbol table; if a shim is defined but not published, the
//! addon loads and then dies on its first call with no useful message. So the set is
//! compared here, from the binary, rather than trusted.
//!
//! It also checks the reverse direction: the addon fixture's own undefined symbols
//! must all be covered by what the binary publishes. That is the pair a real addon
//! needs.

mod support;

use std::path::PathBuf;
use std::process::Command;

/// The built `rustnode` executable.
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

/// The `napi_*` and `node_api_*` names in the binary's dynamic symbol table.
fn exported_node_api_symbols() -> Vec<String> {
    let binary = rustnode();
    assert!(
        binary.is_file(),
        "{} does not exist; the CLI must be built before this test",
        binary.display()
    );
    let output = Command::new("nm")
        .args(["-D", "--defined-only"])
        .arg(&binary)
        .output()
        .expect("nm must be available");
    let text = String::from_utf8_lossy(&output.stdout);
    let mut names: Vec<String> = text
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|name| name.starts_with("napi_") || name.starts_with("node_api_"))
        .map(str::to_string)
        .collect();
    names.sort();
    names
}

#[test]
fn every_declared_shim_is_exported_from_the_binary() {
    // `shims::EXPORTED` is the list the crate claims to publish. If one of these is
    // missing from `.dynsym`, an addon calling it would fail to resolve at load time
    // — which is exactly the failure mode this test exists to catch early.
    let exported = exported_node_api_symbols();
    let mut missing: Vec<&str> = Vec::new();
    for name in rn_napi::EXPORTED {
        if !exported.iter().any(|symbol| symbol == name) {
            missing.push(name);
        }
    }
    assert!(
        missing.is_empty(),
        "declared but not exported from {}: {missing:?}\n\
         exported: {exported:?}",
        rustnode().display()
    );
}

#[test]
fn nothing_is_exported_beyond_the_declared_surface() {
    // The export is a pattern (`napi_*`), so a stray symbol with that prefix would
    // be published without being declared. That is worth knowing: an exported name
    // is a compatibility promise.
    let exported = exported_node_api_symbols();
    let mut undeclared: Vec<&String> = exported
        .iter()
        .filter(|symbol| !rn_napi::EXPORTED.contains(&symbol.as_str()))
        .collect();
    undeclared.sort();
    assert!(
        undeclared.is_empty(),
        "exported but not in shims::EXPORTED: {undeclared:?}"
    );
}

#[test]
fn the_surface_is_not_empty_and_covers_the_core() {
    // A zero-length export set would make the two tests above vacuously pass.
    let exported = exported_node_api_symbols();
    // Pinned exactly rather than as a floor: a floor lets a shim disappear while
    // the test stays green, and the number is a fact about this build that a
    // reviewer can check against `shims::EXPORTED`. The count only moves when a
    // shim is added or removed, and that is a deliberate, visible change.
    //
    // `EXTRA_EXPECTED_SYMBOLS` is not added in: its one entry,
    // `node_api_get_module_file_name`, is also listed in `shims::EXPORTED` because
    // the runtime defines it, so counting it twice would overstate the surface.
    assert_eq!(
        exported.len(),
        rn_napi::EXPORTED.len(),
        "the binary must publish exactly the declared surface: {exported:?}"
    );
    // The handful the end-to-end addon cannot work without, named individually so a
    // regression points at the missing capability rather than at a count.
    for required in [
        "napi_create_object",
        "napi_create_function",
        "napi_call_function",
        "napi_get_cb_info",
        "napi_throw_type_error",
        "napi_register_module_v1",
    ] {
        // The entry point is exported *by the addon*, not the runtime, so it is
        // checked in the addon's own table below rather than here.
        if required == "napi_register_module_v1" {
            continue;
        }
        assert!(
            exported.iter().any(|symbol| symbol == required),
            "{required} is not exported"
        );
    }
}

#[test]
fn the_addon_fixtures_imports_are_all_published() {
    // The end-to-end addon's undefined `napi_*` symbols are what the loader has to
    // satisfy. Comparing them against the published set is the pair a real addon
    // needs: if the fixture imports something rustnode does not export, the fixture
    // would fail to load, and if rustnode exports extra, that is already covered
    // above.
    let build = support::build_addon_or_abort();
    let imports = support::required_napi_imports(&build.path).expect("nm must work");
    assert!(
        imports.len() >= 15,
        "the addon should import a real surface, found {imports:?}"
    );
    let exported = exported_node_api_symbols();
    let mut unresolved: Vec<&String> = imports
        .iter()
        .filter(|symbol| !exported.contains(symbol))
        .collect();
    unresolved.sort();
    assert!(
        unresolved.is_empty(),
        "the addon imports symbols the binary does not export: {unresolved:?}"
    );
}

#[test]
fn the_addons_entry_point_is_exported_by_the_addon() {
    // The lookup the runtime performs is `dlsym(handle, "napi_register_module_v1")`.
    // If the fixture did not export it, every end-to-end test would be measuring the
    // "Module did not self-register" path instead.
    let build = support::build_addon_or_abort();
    let output = Command::new("nm")
        .args(["-D", "--defined-only"])
        .arg(&build.path)
        .output()
        .expect("nm must work");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("napi_register_module_v1"),
        "the fixture must export the Node-API entry point:\n{text}"
    );
}
