//! Compiles the vendored llhttp and the thin C shim around it.
//!
//! Node parses HTTP with `deps/llhttp`, a generated C state machine that the
//! Node tree vendors. Reimplementing it is how request-smuggling bugs are born,
//! so `vendor/llhttp` holds the same three translation units and the same
//! header from the pinned Node revision and they are built as C.
//!
//! `shim/rn_llhttp.c` is the only C this project owns. It exists so Rust never
//! mirrors `llhttp_t` or `llhttp_settings_t`: both are generated structs whose
//! layout moves between llhttp releases, and a stale `#[repr(C)]` copy would be
//! an ABI bug that shows up as a crash or a silently wrong field.
//!
//! Updating llhttp means replacing the four files under `vendor/llhttp` from a
//! newer `deps/llhttp` and recording the Node commit in
//! `vendor/llhttp/README.md`. There is no patch on top: a local edit to the
//! parser would diverge from the behaviour Node ships, which is the only thing
//! this crate exists to reproduce.

fn main() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let llhttp = manifest.join("..").join("..").join("vendor").join("llhttp");
    let shim = manifest.join("shim");

    println!("cargo:rerun-if-changed={}", llhttp.display());
    println!("cargo:rerun-if-changed={}", shim.display());

    cc::Build::new()
        .include(llhttp.join("include"))
        .include(&shim)
        .file(llhttp.join("src").join("llhttp.c"))
        .file(llhttp.join("src").join("api.c"))
        .file(llhttp.join("src").join("http.c"))
        .file(shim.join("rn_llhttp.c"))
        .warnings(false)
        .compile("llhttp");
}
