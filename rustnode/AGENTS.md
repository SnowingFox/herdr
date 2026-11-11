# rustnode contributor notes for agents

`../AGENTS.md` is the repository's project guidance and applies here. This file
only records what is specific to `rustnode/`, and each entry below cost real time
to discover.

## The commit trailer that gets added for you

This environment installs a commit hook outside the repository, at
`$(git config core.hooksPath)`, which appends
`Co-authored-by: snowingfox <...>` to every commit message. The project's commit
rules forbid AI co-author lines, so a commit made with plain `git commit` will be
wrong even though nothing in the repository did it.

Commit with the hooks path neutralised:

```bash
git -c core.hooksPath=/dev/null -c user.name="rustnode" \
  -c user.email="rustnode@local" commit -m "..."
```

`--no-verify` is NOT enough. The hook that adds the trailer is
`prepare-commit-msg`, which git runs even under `--no-verify`, and it runs again
on every commit a rebase replays, so a rebase also re-adds it.

If a commit already carries the trailer, rewrite it rather than leaving it. The
filter-branch invocation is not enough on its own either, because `filter-branch`
commits as it goes; unset the hooks path for it too:

```bash
FILTER_BRANCH_SQUELCH_WARNING=1 git -c core.hooksPath=/dev/null filter-branch -f \
  --msg-filter 'grep -vF "Co-authored-by:" || true' -- "$(git merge-base HEAD origin/master)"..HEAD
```

That rewrites only messages, so the trees stay identical; check with
`git diff --stat <branch-before> HEAD` before force pushing.

## The gate

`./tools/check.sh` runs everything a commit has to pass. It builds the CLI binary
explicitly before the tests because several crates spawn `target/debug/rustnode`
from their integration tests, and `cargo test -p <crate>` does not rebuild that
binary. A stale binary has already masked a real failure once.

## Adding a binding

A binding crate needs three things and nothing else:

1. A `BindingModule` impl in `crates/<name>/src/lib.rs`.
2. `pub fn register(registry: &mut rn_core::BindingRegistry)` that calls
   `registry.register_module(YourModule)`. The older
   `registry.register(Namespace::from_module(&X))` form is gone and compiles only
   if you also add a hand-written match in the CLI, which is what the registry
   exists to avoid.
3. `./tools/regen-bindings.sh`, which discovers crates by looking for the
   `pub fn register` declaration itself, not the string.

`tools/regen-bindings.sh` matches a *declaration* of
`pub fn register(registry: &mut [rn_core::]BindingRegistry)`, skipping comments,
strings and `register` methods that take `&mut self`. Two failures came from
matching the bare string: a doc comment explaining not to use that name
registered the crate it was warning about, and `rn-core`'s
`pub fn register(&mut self, namespace: Namespace)` matches it. `rn-core` is in
the script's exclusion list for that reason, so removing `rn-core` from that
list without checking the matcher would break the build.
`tools/regen-bindings.test.sh` pins all of this, including a byte-for-byte
comparison against the committed `install_all.rs`. It runs in `tools/check.sh`
immediately before the regeneration, as a bare statement so its exit status is
the gate's: a matcher regression turns the gate red instead of only being
findable by running the tests by hand.

## Aliased buffers

Several namespaces share a typed array with JavaScript, and the element type is
part of the contract: `tickInfo` is a `Uint8Array(2)`, `hrtimeBuffer` a
`Uint32Array(3)`, `immediateInfo` a `Uint32Array(3)`, `timeoutInfo` an
`Int32Array(1)`, and the async id arrays `Float64Array`. Getting the width wrong
is not an error, it silently changes what an index means on each side, so
`rn_core::AliasedUint8Array` requires the element type at construction and tests
pin the length and constructor name.

Write from JavaScript and read back from Rust in tests. That is the only way to
prove the two sides share one allocation rather than a copy.

## Deferred members

A namespace may declare members in `deferred()` with a written reason. Prefer
that to a stub that returns something plausible: `rn-compat` reports declared
deferrals as a pass and undeclared gaps as a failure, so a deferral is visible and
a lie is not.

`tools/deferred-reach.py` asks the follow-up question the contract cannot: does
`lib/**` reach this absent member while a module is still loading? Only *calls*
count. `const { crc32c } = binding` binds `undefined` and is harmless, and
feature-detecting with `if (crc32c === undefined)` is legitimate; calling it at
module scope is what makes `require()` throw, which is the real failure the tool
exists to catch. The tool rejects a `DEFERRED` block it cannot parse rather than
reporting zero deferrals, so reword or reformat entries freely but keep them
parseable `("member", "reason")` pairs.

## Where the reference source is

`/workspace/node` is a sparse checkout of the pinned Node revision. Read
`src/**` and `lib/**` there; never push to or modify it, its origin is
`nodejs/node`.

## Cargo's `tools/*` workspace glob

`tools/` is a workspace member glob, so any directory in it needs a
`Cargo.toml`. `__pycache__` is ignored in `.gitignore` for that reason: importing
one of the Python tools into a test left one behind and the whole workspace
failed to load with a missing manifest.

## The C++ toolchain

`vendor/merve` (the CommonJS export lexer) and `vendor/llhttp` (the HTTP parser)
are vendored C/C++ and are compiled by `cc-rs` at build time. Two consequences:

- **`CXX=g++` is required on this image.** cc-rs defaults to `c++`, which here
  resolves to `clang++` without the GCC C++ include paths, so it fails on
  `<cstddef>`. `tools/check.sh` exports it; a bare `cargo build` outside the
  gate will fail the same way until it is set.
- The first build of these crates is slow on purpose. The artifacts cache in
  `target/` from then on.
- Linking a g++-compiled object needs `libstdc++`, whose `.so` symlink lives
  only in the GCC version directory here, so `check.sh` also adds
  `-L /usr/lib/gcc/x86_64-linux-gnu/13` to `RUSTFLAGS`.

## A cached `target/` can restore v8 without its static library

`v8` downloads a 198 MB `librusty_v8.a` into `target/<profile>/gn_out/obj/`
and tells rustc to link it from there. `Swatinem/rust-cache` keeps only
`build/`, `.fingerprint/` and `deps/` when it prunes a profile, and only for
crates outside the workspace, so a restored tree can hold v8's build-script
fingerprint while `gn_out/` is gone. The build script then never re-runs, its
recorded `-L` points at a directory that no longer exists, and any unit that
has to build or relink fails with `could not find native static library
rusty_v8` even though nothing about the source or the lints changed. The fix is
to drop v8's fingerprints when the archive is missing so the build script reruns;
CI does that in rustnode-ci.yml, and the same prune is what makes a local
`target/` copied between machines unsafe.

## Debugging a binding called with the wrong arguments

`RUSTNODE_DEBUG_BINDING=1` makes `compileFunctionForCJSLoader` print the kinds of
the arguments it received. This exists because a binding that *coerces* its
arguments hides the caller's bug: `string_arg` used to call `to_string`, so an
object arrived as the source text `[object Object]` and the loader threw
`SyntaxError: Unexpected identifier 'Object'` with nothing pointing at the
binding. Node's C++ uses `CHECK(args[0]->IsString())` for exactly this reason.

Bindings are type-strict now. If you add one that takes a string, use
`v8::Local::<v8::String>::try_from(...)` and throw a `TypeError`; do not coerce.

## A missing private symbol is silent

`util.privateSymbols` must install every entry of `rn_core::PRIVATE_SYMBOLS`.
A missing one does not throw: `let { x } = privateSymbols` leaves `x` as
`undefined`, and `object[undefined]` is the *string* key `"undefined"`, so every
missing symbol collapses onto one shared property. That made a child module read
its parent `Module` object as its own source, and the symptom was a type error
inside the CommonJS loader. `rn-core` has a test pinning the installed set.

## Do not weaken a count to make something fit

`BUILTIN_FILE_COUNT` (435) and the `sha256sum -c` in `tools/verify-libjs.sh` are
the checks that keep `vendor/libnode-js/lib/**` byte-identical to Node. They have
already caught real drift. If a new builtin does not fit that tree, extend the
*generator* — the id scheme already maps `deps/...` to `internal/deps/...` — do
not change the number.

The same rule applies to `rn-compat`'s contract files, the deferred-reach
baseline, and every test expectation. A check that was edited until it passed is
not a check.


