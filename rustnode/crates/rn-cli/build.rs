//! Publishes the Node-API shims in the `rustnode` binary's dynamic symbol table.
//!
//! # Why this file has to exist in the binary crate
//!
//! A `.node` addon is a shared object whose `napi_*` imports are undefined. When
//! the dynamic loader opens it, those imports are resolved against the global scope
//! of the process, which for a normal executable contains only what the linker was
//! asked to publish. The rustnode binary therefore has to export the `napi_*`
//! functions `rn-napi` defines.
//!
//! `cargo::rustc-link-arg` applies to the crate whose build script emits it, and
//! cargo does **not** forward it from a library dependency to the final binary. That
//! is not a guess: with the flag emitted from `rn-napi`'s build script the built
//! executable's `.dynsym` still contained zero `napi_*` entries, and the same flag
//! emitted here puts all of them in. So the flag lives here, beside the `[[bin]]`
//! target, and `rn-napi`'s crate docs point at this file.
//!
//! # Why the pattern form and not `--export-dynamic`
//!
//! `--export-dynamic` (`-rdynamic`) publishes every global symbol: thousands of
//! entries, a larger `.dynsym`, slower startup, and every internal symbol made
//! interposable by any addon that declares a matching name. `--export-dynamic-symbol`
//! publishes exactly the two Node-API prefixes and nothing else.
//!
//! # Windows
//!
//! Windows has no link-time equivalent: a DLL export is declared on the definition
//! (`__declspec(dllexport)`) and an addon links against an import library. That is
//! separate work, recorded as deferred rather than silently omitted, so a Windows
//! build says so at compile time instead of failing at addon load.

fn main() {
    let family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    if family == "unix" {
        // The glob is expanded by the linker against defined symbols, so both the
        // `napi_*` and `node_api_*` names are covered.
        println!("cargo::rustc-link-arg=-Wl,--export-dynamic-symbol=napi_*");
        println!("cargo::rustc-link-arg=-Wl,--export-dynamic-symbol=node_api_*");
    }
    if family == "windows" {
        println!(
            "cargo::warning=rn-napi publishes Node-API symbols from the binary on Unix \
             only; a Windows addon needs the import-library path, which is not built"
        );
    }
    println!("cargo::rerun-if-changed=build.rs");
}
