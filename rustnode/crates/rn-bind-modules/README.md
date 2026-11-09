# rn-bind-modules

`internalBinding('modules')` for rustnode — the namespace that makes CommonJS
file loading possible.

`lib/internal/modules/cjs/loader.js`, `lib/internal/modules/helpers.js` and
`lib/internal/modules/package_json_reader.js` all call it. Until it exists,
`require()` can only reach builtins: no user file can load. Everything here is
Node 28's own JavaScript reaching into Rust through the same call shapes.

## What is installed

15 of the 17 members in `contracts/modules.json`.

### Package metadata

| member | shape |
| --- | --- |
| `readPackageJSON(path, isESM, base, specifier)` | 7-slot array or `undefined` |
| `parsePackageJSON(source, jsonPath, isESM, base, specifier)` | 7-slot array; no filesystem, no cache |
| `getNearestParentPackageJSON(checkPath)` | 7-slot array or `undefined` |
| `getNearestParentPackageJSONType(checkPath)` | `"commonjs"` / `"module"` / `"none"` / `undefined` |
| `getRootPackageJSON(checkPath)` | 7-slot array or `undefined` |
| `getPackageScopeConfig(resolvedURL)` | 7-slot array **or a path string** |
| `getPackageType(url)` | `"commonjs"` / `"module"` / `"none"` / `undefined` |
| `moduleFormats`, `cachedCodeTypes` | null-prototype `{ kCommonJS, ... }` |

The serialized array is Node 28's shape:

```text
0 name  1 main  2 type  3 imports  4 exports  5 filePath  6 private
```

`type` is never absent — it is `"none"` when the file did not pick one — and
`imports`/`exports` arrive as **raw JSON text** for containers, so the JavaScript
layer parses them lazily and only when a specifier needs them.

### Three walks, not one

Choosing the wrong walk silently changes whether a file is CommonJS or an ES
module, which is why each is implemented separately:

- `getNearestParentPackageJSON{,Type}` — start at the *parent* of the given path
  and climb. A trailing separator is significant (`/a/b/` starts in `/a/b`,
  `/a/b` starts in `/a`). Stops at a directory named `node_modules`.
- `getPackageScopeConfig`, `getPackageType` — start at `package.json` beside the
  URL and resolve `../package.json` repeatedly. Stops when the pathname stops
  changing (the root) or when it names `node_modules/package.json`. On failure it
  returns the path it would have read, which is how the JavaScript layer tells
  "no package" from "an empty package".
- `getRootPackageJSON` — climb remembering the last two components so it can
  identify the package under `node_modules`; a *publishable* package encloses the
  file and yields nothing, a private one is the answer.

`package.json` answers are cached per realm and **never invalidated**, matching
Node: a file edited after it was read keeps its first value for the life of the
process. That is observable, so it is reproduced rather than improved.

### Compile cache

| member | status |
| --- | --- |
| `enableCompileCache(cacheDir, portable, readOnly, keyRoot)` | installed |
| `getCompileCacheDir()` | installed |
| `flushCompileCache(keepDeserializedCache)` | installed |
| `getCompileCacheEntry(source, filename, type)` | installed |
| `saveCompileCacheEntry(external, transpiled)` | installed |
| `compileCacheStatus` | installed |

The cache directory is tagged `v<version>-<arch>-<v8>-<uid>` so incompatible
caches never share one; `portable` omits the uid. Entries are stored under a
CRC-32 of `type ++ filename` with a five-word header (magic, source size, payload
size, source hash, payload hash) followed by the payload, written to a temporary
file and renamed so a concurrent reader never sees a partial file.

`lib/internal/modules/typescript.js` is the only consumer of
`getCompileCacheEntry`/`saveCompileCacheEntry`, and it stores plain transpiled
text, which is exactly what this implementation round-trips.

## Deferred

Two members, both declared in `DEFERRED` with reasons:

- `getWasmCompileCacheEntry`
- `saveWasmCompileCacheEntry`

Both are the WebAssembly half of the compile cache and both need V8 APIs the
linked `v8` crate does not expose: `WasmModuleObject::CompiledModule::Serialize()`
to produce bytes, and `WasmModuleCompilation` with a module-caching callback to
consume them. Without a way to produce the bytes there is nothing to store, so an
entry could never carry a `module` and the cache would silently never hit. A
cache that never hits is worse than an honest absence.

They are safe to defer at load time: `lib/internal/modules/esm/translators.js`
destructures both inside `translateWasm`, not at module scope, and destructuring
an absent member yields `undefined` rather than throwing. `tools/deferred-reach.py`
flags them because it treats module-scope destructuring as eager use; that is a
false positive here, and `deferred_members_destructure_cleanly_at_module_scope`
pins the reasoning.

## The esmodule lexer

`src/node_modules.cc` does **not** call `cjs_module_lexer`. ESM syntax detection
lives on the `contextify` namespace as `containsModuleSyntax`
(`src/node_contextify.cc`), called from `lib/internal/modules/esm/get_format.js`
and from the CommonJS loader's `wrapSafe`. So there is no lexer to port here, and
`parsePackageJSON` — despite the name — only parses JSON. Porting `merve` would
be work for `contextify`, not for this crate.

The JSON parser in `json.rs` reproduces simdjson's *on-demand* validation rather
than whole-document validation, because that is what Node actually does. The
consequence is visible: `{"name":"n","x":tru}` and `{"name":"n","x":{1:2}}` both
load, while `{"name":"n","x":[1,}` throws. Field typing is likewise Node's, and
not uniform — a non-string `name` or `type` is fatal, a non-string `main` is
dropped.

## Tests

- `src/json.rs`, `src/packages.rs`, `src/compile_cache.rs`, `src/url.rs` — unit
  tests over real temp directories: with and without `type`, a `package.json` in
  a parent directory, the `node_modules` boundary stopping each walk, malformed
  files, and the cache's stale/truncated/corrupt cases.
- `src/tests.rs` — drives the installed namespace from JavaScript, which is the
  only way to pin array slot order, `undefined` versus a value, and null
  prototypes.
- `tests/parity.rs` — rebuilds the same fixture tree and compares every query
  against `tests/node_expected.json`, a recording of
  `node --expose-internals` calling `internalBinding('modules')` directly. When
  `node` is on `PATH` the recording is regenerated and compared too, so the
  fixture answers cannot drift from the binary.

The recording came from the newest Node available locally, which is older than
the pinned 28.0.0. The only difference that matters is array width: Node 28 added
the seventh `private` slot, so the comparison reads the six slots both versions
have.

## End-to-end state

`./target/debug/rustnode --expose-internals -e 'require("internal/modules/helpers")'`
now reaches `url`:

```text
internalBinding('url'): the namespace has no Rust implementation yet
```

Before this crate it failed on `modules`. `url` is the remaining namespace on the
path to real file loading; `internal/url.js` requests it at module scope while
`internal/modules/package_json_reader.js` requires `internal/url` for
`fileURLToPath`.
