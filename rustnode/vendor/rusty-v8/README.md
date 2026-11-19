# rusty_v8, vendored

Rust bindings to V8, vendored from `denoland/rusty_v8` at the `v8-15.8` line
(crate version `158.0.0`), and **built against a V8 15.6.75 engine**.

## Why the bindings and the engine are different versions

`tools/node-pin.toml` pins V8 `15.6.75` because that is what Node 28 ships, and
`process.versions.v8` is compared against that oracle. No published `v8` crate
targets 15.6: the V8 submodule in `rusty_v8` went 15.2 → 15.8 and skipped 15.6
entirely (`git log -- v8 | grep 'to V8 15'` shows `15.0`, `15.2`, `15.8` only),
and the newest published crate is `152.2.0`, which is V8 15.2.

The 15.8 bindings are the tool here, not the destination. They compile against
15.6 headers with zero errors: `src/binding.cc` produces real objects and 757
defined `v8__` symbols, and the Rust API surface moved by exactly one removed
`pub fn` (`CppHeap::terminate`) which rustnode never calls. So the bindings pin
the 15.8 *source* while the engine is 15.6.75.

## The GN rooting, which is the actual change

Upstream `build.rs` roots GN at `CARGO_MANIFEST_DIR` and expects a layout of
`root/{build/, v8/, third_party/, rusty_v8/BUILD.gn}`. Splicing a 15.6 `v8/`
into that root fails twice:

    ERROR at //build/config/rust.gni:353:17: Could not read file.
    ERROR at //gni/v8.gni:222:29: Duplicate build argument declaration.

The second is the interesting one. The crate's `.gn` sets
`secondary_source = "//v8/"`, so V8 becomes a parallel source root and the same
file is reachable under two labels: V8's `third_party/googletest/BUILD.gn` does
`import("../../gni/v8.gni")`, which resolves to `//gni/v8.gni` from the root but
`//v8/gni/v8.gni` from V8's own `BUILD.gn`. Two labels, two `declare_args` runs,
and `gn gen` never completes.

The fix is to make **the V8 15.6.75 checkout the GN root**, so every V8 label has
exactly one meaning and V8's `build/` and `gni/` agree by construction — they
come from the same `gclient sync`. `build.rs` reads `RUSTY_V8_GN_ROOT` for that:

    /path/to/v8/          # GN root, a 15.6.75 checkout
      .gn
      build/              # V8 15.6's own DEPS pin (bc0661cf)
      v8 -> .             # self-symlink, for binding.cc's include path
      crate/              # this crate's sources and BUILD.gn

The `v8 -> .` self-symlink exists only because `src/binding.cc` includes
`"v8/src/execution/isolate-inl.h"` and needs a directory literally named `v8`.
Being a self-symlink, it never introduces a second GN label.

`BUILD.gn` and `src/deno_inspector/BUILD.gn` therefore address V8 with root
labels (`//:v8`, `//gni/v8.gni`, `//third_party/inspector_protocol:crdtp`)
rather than `//v8:...`. Those label rewrites are the only edits to upstream
build files.

## Building the engine

`tools/build-v8-15.6.sh` does the whole sequence and prints the archive paths.
It syncs V8 15.6.75, roots GN at that tree with this crate's `.gn`, builds
`//crate:rusty_v8`, and generates the matching `src_binding.rs`.

The resulting `librusty_v8.a` and `src_binding_*.rs` are consumed through
`RUSTY_V8_ARCHIVE`, which upstream `build.rs` treats as a directory holding both
files by their published names. That path never runs `gn gen` at all, which is
what a CI job wants.

## What the archive must satisfy

- `strings librusty_v8.a | grep '^15\.6\.'` prints `15.6.75-rusty`. The
  `-rusty` suffix comes from `v8_embedder_string = "-rusty"` in the crate's
  defaults, and it is what `process.versions.v8` reports.
- `nm --defined-only librusty_v8.a | grep -c ' T v8__'` is 757.
- The crate's own `default_args` must be used, not V8's. `v8_enable_javascript_promise_hooks`,
  `v8_enable_temporal_support`, the typed-array heap limits and the array-buffer
  internal field counts all live there. Building with V8's `.gn` instead drops
  them silently and the failure only shows up at run time as
  `Fatal error in v8::Context::SetPromiseHook: V8 was compiled without
  JavaScript Promise hooks`.
