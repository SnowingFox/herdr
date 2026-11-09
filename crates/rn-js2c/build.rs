//! Generates the embedded builtin table from `vendor/libnode-js/lib/**` and
//! `vendor/libnode-js/deps/**`.
//!
//! This is the Rust counterpart of Node's `tools/js2c.cc`. It runs at build time
//! and writes `$OUT_DIR/builtins.rs`, which `src/lib.rs` `include!`s, so the
//! runtime never opens a file to load a builtin.
//!
//! The generator itself lives in `src/generate.rs` so the tests can exercise the
//! same code against fixture trees; this file only handles Cargo plumbing.
//!
//! Design notes:
//!
//! - **Deterministic.** The table is sorted by id and carries no timestamps,
//!   absolute paths, or environment data, so the same vendored tree always
//!   produces byte-identical output.
//! - **Incremental.** The output lives in `$OUT_DIR`, so Cargo reuses it until an
//!   input changes. Inputs are the vendored trees, `LIBJS.sha256`, and this
//!   crate's generator sources; if the content hash matches the previous run the
//!   file is not rewritten, which keeps `mtime`-based rebuild detection from
//!   cascading.
//! - **Verifying.** Every file is checked against `LIBJS.sha256` before it is
//!   embedded, so a modified or missing file is a build error that names it.
//!   That covers both trees: the manifest is keyed by js2c path, so `lib/fs.js`
//!   and `deps/undici/undici.js` are verified by one pass and one format.
//! - **Uncompressed.** See the note in `src/lib.rs`: V8 wants UTF-8 text to hand
//!   to the compiler, so compressing would only add a decode step to the startup
//!   path and would make the bytes unverifiable against the freeze manifest.

// The generator includes the library's scheme and hash modules so there is
// exactly one definition of the id rules; it uses only part of each, so dead
// code here is expected rather than a mistake.
#[allow(dead_code)]
#[path = "src/generate.rs"]
mod generate;
#[allow(dead_code)]
#[path = "src/scheme.rs"]
mod scheme;
#[allow(dead_code)]
#[path = "src/sha256.rs"]
mod sha256;

use std::env;
use std::path::PathBuf;

fn main() {
    // `rerun-if-changed` on a directory is recursive in Cargo, which covers
    // added and removed builtin files.
    for path in [
        scheme::VENDOR_LIB_RELATIVE,
        scheme::VENDOR_DEPS_RELATIVE,
        scheme::VENDOR_SHA256_RELATIVE,
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    for path in [
        "build.rs",
        "src/generate.rs",
        "src/scheme.rs",
        "src/sha256.rs",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set for build scripts"),
    );
    let lib_dir = manifest_dir.join(scheme::VENDOR_LIB_RELATIVE);
    let deps_dir = manifest_dir.join(scheme::VENDOR_DEPS_RELATIVE);
    let freeze_manifest = manifest_dir.join(scheme::VENDOR_SHA256_RELATIVE);

    let table = match generate::generate_table(
        &lib_dir,
        &deps_dir,
        &freeze_manifest,
        scheme::BUILTIN_FILE_COUNT,
        scheme::DEPS_FILE_COUNT,
    ) {
        Ok(table) => table,
        Err(error) => fail(&error),
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set for build scripts"));
    let dest = out_dir.join("builtins.rs");
    generate::write_if_changed(&dest, table.as_bytes()).unwrap_or_else(|error| {
        fail(&format!("cannot write {}: {error}", dest.display()));
    });
}

fn fail(message: &str) -> ! {
    // Build-script output is line-oriented and Cargo truncates long multi-line
    // detail, so report the whole message on one line.
    println!("cargo:error=rn-js2c: {message}");
    std::process::exit(1);
}
