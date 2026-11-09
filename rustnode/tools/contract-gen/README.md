# contract-gen

Records the exact shape of every `internalBinding()` namespace the vendored
Node builtin JavaScript expects, and writes one JSON contract per namespace to
`rustnode/contracts/`.

## Regenerate

```bash
cd rustnode
./tools/contract-gen/generate.sh
```

Use `--node <path>` to record with a specific Node binary, and `--check` to
verify the committed contracts are current without rewriting them.

Equivalent manual invocation:

```bash
node --expose-internals tools/contract-gen/record.cjs \
  --lib vendor/libnode-js/lib --out /tmp/recorded.json
cargo run -p contract-gen -- /tmp/recorded.json --out contracts
cargo run -p rn-compat -- contracts --report
```

## Why `--expose-internals`

`require('module').internalBinding` is not exposed to user code, so a preload
cannot wrap the function the builtin layer actually calls. The only supported
bridge is `require('internal/test/binding')`, which exists only with
`--expose-internals` and hands back the same cached namespace object that
`lib/**` sees. `record.cjs` therefore runs *inside* a Node started with that
flag rather than monkey-patching a module export.

This is why the old `preload.cjs` recorder could never work: by the time a
preload runs, `internalBinding` has already been captured by the module
wrapper, and reassigning `module.internalBinding` changes nothing.

## Two sources, merged

| Source | Authoritative for | How |
| --- | --- | --- |
| runtime | `kind`, `arity`, object `properties` | reads each namespace through `internalBinding` |
| static | the member *set* | acorn AST pass over `vendor/libnode-js/lib/**` |

The static pass matters because a runtime recording only sees members that were
touched in the running process, on this platform, with this build's flags. It
resolves `internalBinding('ns')` call sites and the member reads on them,
including destructuring, renamed destructuring, namespace aliases, member
aliases, and `typeof` guards. A member found only statically is marked
`"origin": "static"` with `"kind": "unknown"` unless a call site or a `typeof`
guard proves otherwise.

## Node version

`tools/node-pin.toml` pins Node 28. Any Node that supports `--expose-internals`
works: binding member names, kinds, and arities are stable across the 22–28
range. The producing version is recorded in `meta.node` so a diff is
explainable, and `meta.node.pin_match` says whether it matched the pin.

Namespaces compiled out of the recording binary are recorded from the static
pass alone with `"reachable": false` and an `unreachable_reason`. On a build
with `node_use_quic=0` these are `dtls`, `quic` and `internal_only_v8`.

## Output

```json
{
  "namespace": "config",
  "reachable": true,
  "members": {
    "hasIntl":    { "kind": "boolean", "origin": "both" },
    "hasSmallICU": { "kind": "unknown", "origin": "static" },
    "getDefaultLocale": { "kind": "function", "arity": 0, "origin": "both" }
  }
}
```

`rn-compat` reads `namespace` and the member names and ignores `reachable`,
`origin`, `arity` and `properties`; they exist so a human and the recorder can
reason about provenance.

## Tests

```bash
node --expose-internals tools/contract-gen/record.test.cjs
cargo test -p contract-gen
```
