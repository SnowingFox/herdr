//! Compiles the vendored merve and nothing else.
//!
//! `internalBinding('cjs_lexer').parse` answers "which names does this CommonJS
//! module statically export, and which modules does it re-export". Node answers
//! it with `deps/merve`, a C++ lexer, so `vendor/merve` holds the same single
//! translation unit and the same two headers from the pinned Node revision and
//! they are built as C++.
//!
//! `deps/merve` upstream is one file. `merve.cpp` includes `merve.h` and defines
//! the `merve_*` C ABI declared in `merve_c.h` in the same translation unit, so
//! there is no second object to compile and no link step of our own to get
//! wrong.
//!
//! # Why this does not define `MERVE_USE_SIMDUTF`
//!
//! Node's `merve.gyp` sets it and points at V8's bundled simdutf. It selects
//! `simdutf::convert_utf32_to_utf8` over merve's own encoder and
//! `simdutf::find` over `std::string_view::find` — two calls with the same
//! results, so it is a speedup and not a semantic. Leaving it undefined keeps
//! the vendored source free of any dependency on V8's third-party tree, and the
//! parity test in `tests/parity.rs` compares the output against a real Node
//! binary, which is what would catch a difference if that stopped being true.
//!
//! Updating merve means replacing the files under `vendor/merve` from a newer
//! `deps/merve`, recording the Node commit in `vendor/merve/README.md`, and
//! regenerating `vendor/merve/MERVE.sha256`. There is no patch on top: a local
//! edit to the lexer would diverge from the analysis Node ships, which is the
//! only thing this crate exists to reproduce.

fn main() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let merve = manifest.join("..").join("..").join("vendor").join("merve");

    println!("cargo:rerun-if-changed={}", merve.display());

    cc::Build::new()
        .cpp(true)
        // merve uses `consteval` lookup tables, so it needs C++20, which is what
        // `deps/merve/merve.gyp` declares for every non-Windows target.
        .std("c++20")
        .include(merve.join("include"))
        .file(merve.join("merve.cpp"))
        .warnings(false)
        .compile("merve");
}
