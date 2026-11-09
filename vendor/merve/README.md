# merve, as vendored by Node

`merve.cpp` and the two headers are copied byte-identical from `deps/merve` in
the Node revision pinned in `tools/node-pin.toml` (`f344e7f552e`, which reports
itself as 28.0.0). merve is version 1.2.2 there.

    deps/merve/LICENSE-MIT
    deps/merve/merve.cpp
    deps/merve/merve.h
    deps/merve/merve_c.h

MIT licensed; see `LICENSE-MIT`.

The upstream tree also carries `BUILD.gn`, `merve.gyp` and `unofficial.gni`.
Those are Node's build descriptions, not parser source, and this project
compiles merve from `crates/rn-bind-cjs-lexer/build.rs` instead, so they are not
vendored.

## Why the C rather than a Rust lexer

`internalBinding('cjs_lexer').parse` decides which names a CommonJS module
statically exports. Node feeds that answer to `cjs-module-lexer`-style interop,
so a wrong export list silently changes what an ESM `import` of a CommonJS file
observes. The analysis has subtleties that are easy to get almost right —
`exports.foo` versus `module.exports.foo`, bracket and escaped-key forms,
`Object.defineProperty(exports, ...)`, `__esModule`, transpiler reexport idioms,
and the rule that ESM syntax in the file is an error rather than an export — and
a hand-written replacement would agree with itself while disagreeing with Node.

rustnode's thesis is that only the *native glue* is rewritten, so the lexer
stays the exact C++ Node ships and this project owns only the Rust glue in
`crates/rn-bind-cjs-lexer/src/`.

## The C entry points

`merve.h` is the C++ API. `merve_c.h` is a C ABI over it, and the C ABI is what
Rust links against: `lexer_analysis` holds `std::vector`, `std::variant` and
`std::string_view`, none of which may cross an FFI boundary as a mirrored
`#[repr(C)]` struct. The `merve_*` functions hand back an opaque handle plus
`merve_string { data, length }` pairs instead, which Rust can read without ever
naming a C++ type.

The names are borrowed from the source buffer, so the source must outlive the
handle. `crates/rn-bind-cjs-lexer/src/ffi.rs` keeps both alive in one scope.

## simdutf

Upstream `merve.gyp` sets `MERVE_USE_SIMDUTF=1` and includes V8's bundled
simdutf. Without the define, `merve.cpp` selects its own UTF-8 encoder and
`std::string_view::find` instead of `simdutf::convert_utf32_to_utf8` and
`simdutf::find`. Both paths compute the same result; simdutf is a speedup, not a
semantic. This crate builds without the define, so the vendored source has no
dependency on V8's bundled third-party tree and the build stays a single C++
translation unit.

## Updating

Replace all four files from a newer Node checkout, then update this file with
the new commit and regenerate `MERVE.sha256`. `tools/verify-merve.sh` fails the
gate when the vendored tree no longer matches the pin, so an accidental local
edit cannot silently change which names a module reports as exported.

Nothing here may be edited locally. There is no patch file because there is no
patch: a change to this lexer belongs upstream in `nodejs/node`'s `deps/merve`.
