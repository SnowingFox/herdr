# rn-js2c

Node's `js2c` step, as Rust data.

Node does not ship `lib/**` as files at run time. `tools/js2c.cc` embeds every
builtin in a generated `node_javascript.cc`, and `BuiltinLoader` reads them from a
`BuiltinSourceMap` keyed by id. This crate does the same thing at build time:
`build.rs` walks `vendor/libnode-js/lib/**` and `vendor/libnode-js/deps/**`,
verifies each file against `vendor/libnode-js/LIBJS.sha256`, and emits a static
table that `src/lib.rs` `include!`s. There is no runtime file I/O to load a
builtin.

Two trees exist because Node's js2c is handed two: `lib/**` is globbed, and
`deps_files` is an explicit list in `node.gyp`. The one `deps/` file vendored here
is `deps/undici/undici.js`, which `lib/**` requires as
`internal/deps/undici/undici`. Each tree keeps its own exact count — 435 and 1 —
so neither can absorb the other's drift.

## API

```rust
use rn_js2c::{builtin_sources, builtin_by_id, BuiltinKind, BuiltinCategory};

// Every builtin, ordered exactly as Node's std::map orders them.
for builtin in builtin_sources() {
    let id: &'static str = builtin.id();          // "internal/fs/promises"
    let src: &'static str = builtin.source();     // byte-identical to lib/**
    let kind: BuiltinKind = builtin.kind();       // how V8 must compile it
    let cat: BuiltinCategory = builtin.category(); // Core vs Internal
    let params = builtin.parameters();            // wrapper arguments for V8
}

// One binary search, no allocation.
let fs = builtin_by_id("fs").expect("fs is a builtin");
assert!(fs.is_core());
```

Supporting entry points:

| function | purpose |
| --- | --- |
| `builtin_sources() -> &'static [Builtin]` | the whole table |
| `builtin_by_id(id) -> Option<&'static Builtin>` | lookup |
| `source(id) -> Option<&'static str>` | source text only |
| `exists(id) -> bool` | membership |
| `builtin_ids() -> &'static [&'static str]` | back `internalBinding('builtins').builtinIds` |
| `core_ids()` / `internal_ids()` | back `builtinCategories` |
| `natives()` | back the legacy `process.binding('natives')` object |
| `table_digest()` | identity of the whole table |
| `verify_against_manifest(&str)` | re-check a tree against `LIBJS.sha256` |

## Id scheme

The id is the string key of Node's `BuiltinSourceMap`, not an integer. Node 28
removed the numeric `node_builtin_ids.h` enum that older releases generated, so
the string is the only authoritative handle — and it is also exactly what
`lib/**` passes to `require()`.

Derivation, from `tools/js2c.cc::GetFileId`:

| js2c path | id |
| --- | --- |
| `lib/assert.js` | `assert` |
| `lib/internal/fs/promises.js` | `internal/fs/promises` |
| `lib/internal/readline/emitKeypressEvents.js` | `internal/readline/emitKeypressEvents` |
| `deps/acorn/acorn/dist/acorn.js` | `internal/deps/acorn/acorn/dist/acorn` |
| `deps/undici/undici.js` | `internal/deps/undici/undici` |

The `.js`/`.mjs` suffix is stripped, then a `deps/` prefix becomes
`internal/deps/` and a `lib/` prefix is dropped. Case is preserved; nothing else
is normalised.

Classification, from `src/builtin_info.cc::GetBuiltinSourceType` and
`lib/internal/bootstrap/realm.js`:

| kind | ids | compiled as |
| --- | --- | --- |
| `BootstrapRealm` | `internal/bootstrap/realm` | function, `process` + binding loaders |
| `BootstrapScript` | `internal/bootstrap/**` | function, `process` + `require` |
| `PerContextScript` | `internal/per_context/**` | function, `exports` + primordials |
| `MainScript` | `internal/main/**` | function, `process` + `require` |
| `Function` | everything else | ordinary CommonJS function |
| `SourceTextModule` | `.mjs`, `internal/deps/v8/tools/**` | ESM module |

`Core` vs `Internal` follows the `internal/` prefix, which is how
`lib/internal/bootstrap/realm.js` splits `publicBuiltinIds` from
`internalBuiltinIds`.

## Frozen data

- `build.rs` verifies every file in both trees against `LIBJS.sha256` and fails
  the build naming the file that drifted.
- The table digest is pinned in `tests/builtins.rs`, so a re-pin that changes
  ids, kinds, categories or text cannot pass by regenerating the manifest alone.
- `./tools/verify-libjs.sh` remains the outer gate: 435 `lib/` files and 1
  `deps/` file, byte-identical, with both counts enforced.

On an intentional Node re-pin: update `tools/node-pin.toml`, re-copy `lib/**`
and `deps/**`, regenerate `LIBJS.sha256`, refresh `TABLE_DIGEST`, all in one
commit.

## Why not compressed

V8 needs a `v8::String` of JavaScript source, and every consumer hands it to
`ScriptCompiler` directly. Compressing a 5.9 MB payload would add a decode step
to the first require of every builtin, defeat demand paging of rodata, and make
the embedded bytes impossible to check against the freeze manifest. Plain
`&'static str` also costs nothing at run time: no allocation, no copy.
