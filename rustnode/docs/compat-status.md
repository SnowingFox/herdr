# Compatibility status

rustnode claims Node compatibility structurally: the V8 engine and all 435
`lib/**` builtin JavaScript files are the same ones Node 28 ships, plus the
`deps/undici/undici.js` bundle Node's js2c embeds alongside them, so the only
thing that can differ is the native layer written in Rust. That claim is only worth
something if it is checked, so four gates check it. Each gate can fail on its
own, and each answers a different question.

| Gate | Question it answers | Fails when |
| --- | --- | --- |
| lib freeze | has anyone edited Node's JavaScript? | a vendored file differs from the pinned copy |
| llhttp freeze | has anyone edited Node's HTTP parser? | a vendored C file differs from the pinned copy |
| binding contracts | does a Rust `internalBinding()` namespace expose what the JavaScript reads? | a recorded member is missing |
| Node test suite | how much of Node actually behaves the same? | a test file exits non-zero |

Run all four from `rustnode/`:

```bash
./tools/verify-libjs.sh
./tools/verify-llhttp.sh
cargo run -p rn-compat
./tools/run-node-tests.sh
```

`llhttp` is the one piece of native code that is *not* rewritten: HTTP parsing is
a security surface, and two parsers disagreeing about where a request ends is the
whole request-smuggling vulnerability class. `vendor/llhttp` is Node's generated C
state machine, compiled unchanged; only the V8 glue around it is Rust. See
`vendor/llhttp/README.md`.

## Gate 1: lib freeze

`vendor/libnode-js/lib/**` holds Node's builtin JavaScript, copied byte-identical
from the commit in `tools/node-pin.toml` (`f344e7f552e`, Node 28.0.0). Editing
one of those files would turn a native-layer gap into a JavaScript fork, which
is exactly the failure mode this project exists to avoid.

```bash
cd rustnode
./tools/verify-libjs.sh
```

It prints
`vendor/libnode-js matches the pinned Node revision (435 lib files, 1 deps file)`
and exits 0, or names the modified file and exits 1. The check is a plain
`sha256sum -c` against `vendor/libnode-js/LIBJS.sha256` plus a file count, so it
needs no network and no Node binary. **Current state: passing, 435 `lib/` files
and 1 `deps/` file.**

If a genuine Node bug requires a JavaScript change, that is a design decision,
not a local edit: it means the native layer cannot express what the JavaScript
expects, and the fix belongs in Rust.

`vendor/libnode-js/deps/undici/undici.js` is frozen the same way, for the same
reason. Node's js2c embeds `lib/**` and an explicit `deps_files` list into one
builtin table, and `lib/**` requires that bundle by id — without it,
`require('internal/deps/undici/undici')` throws `Missing internal module` and
`fetch`, `Response`, `FormData` and the WebAssembly streaming callback are all
unreachable. The two trees are counted separately (435 and 1): a single total
would let one gain a file while the other lost one and still balance.

## Gate 2: binding contracts

The JavaScript layer reaches the native layer only through
`internalBinding('<namespace>')`. `contracts/<namespace>.json` records, for each
namespace, the member names a real Node binary exposes. `rn-compat` compares
those against what the Rust registry installs.

```bash
cd rustnode
cargo run -p rn-compat                    # checks ./contracts
cargo run -p rn-compat -- <contracts-dir>  # checks another directory
```

Recording a contract needs a real Node binary with an instrumented
`internalBinding`:

```bash
cd rustnode
RUSTNODE_CONTRACT_OUT=/tmp/recorded.json \
  node --require ./tools/contract-gen/preload.cjs <script-that-loads-the-namespaces>
cargo run -p contract-gen -- /tmp/recorded.json --out contracts
```

**Current state: not yet enforcing anything.** `contracts/` does not exist, so
`rn-compat` prints `no contracts in ...; shape check skipped` and exits 0. Gate 2
is scaffolding until the first contract files land, and a green `rn-compat` today
means nothing. The recording path also needs a Node build where
`require('node:module').internalBinding` is reachable; on the Node 22 build
available here it is not, so contracts have to be recorded from a Node 28 binary.

Until `contracts/` is populated, a binding crate's `members()` list is backed
only by reading the JavaScript call sites. That is the honest state: gate 2 is
the gate that makes a binding crate's claim checkable, and it is not switched on.

## Gate 3: Node's own test suite

The acceptance criterion is Node's own `test/` tree, not a curated subset.
The harness runs each test file in its own process with the rustnode binary as
the `node` executable, with a timeout, and records the outcome.

The test tree is never vendored. It is 103 MB, it belongs to whatever revision
you are comparing against, and the harness only needs a path to it:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/nodejs/node /tmp/node
cd /tmp/node && git sparse-checkout set test
```

### Running it

```bash
cd rustnode

# default: the fixed 10-file smoke subset, then the per-subsystem table
./tools/run-node-tests.sh --tests /tmp/node/test

# your own subsystem
./tools/run-node-tests.sh --tests /tmp/node/test --filter test-fs-

# one suite, or the whole tree
./tools/run-node-tests.sh --tests /tmp/node/test --suite sequential
./tools/run-node-tests.sh --tests /tmp/node/test --all
```

`--tests` is optional; without it the wrapper clones the test tree into
`$RUSTNODE_TEST_CACHE/node-test` (default `/tmp/rustnode-node-test`) on first
use. That clone tracks Node's default branch, so for numbers comparable to a
release, check out the commit in `tools/node-pin.toml` yourself and pass it as
`--tests`.

The harness itself is a small crate, so it can be driven directly:

```bash
cd rustnode
cargo run -p rn-harness -- run --tests /tmp/node/test --smoke
cargo run -p rn-harness -- report
cargo run -p rn-harness -- report --json
```

Result files land in `rustnode/tools/harness/results/`, which is gitignored. Each
run writes one `run-<timestamp>[-label].json`. `report` reads all of them and
keeps the newest outcome per test file, so fixed tests turn green without
re-running everything and repeated runs never inflate the total.

### What the numbers mean today

**Measured smoke subset — 0 of 10 files pass.**

This is one specific named subset: the fixed 10-file list in `SMOKE_SUBSET`
(`parallel/test-assert.js`, `test-buffer-bytelength.js`, `test-fs-open.js`,
`test-path-parse-format.js`, `test-util-inspect.js`, `test-events-once.js`,
`test-querystring-escape.js`, `test-string-decoder.js`, `test-timers-ordering.js`,
and `es-module/test-esm-import-meta.mjs`). Measured with the debug `rustnode`
binary against Node's test tree at its default branch.

The ten failures split into four causes, each naming the missing layer:

| Count | Cause | Owner |
| --- | --- | --- |
| 6 | `ReferenceError: require is not defined` | module loading (`rn-module`) |
| 1 | `SyntaxError: Cannot use import statement outside a module` | ESM loading (`rn-module`) |
| 2 | `unsupported option '--expose-internals'` | CLI option parsing (`rn-cli`) |
| 1 | `unsupported option '--no-warnings'` | CLI option parsing (`rn-cli`) |

None of these is a binding bug yet. The runtime cannot load a CommonJS module or
accept Node's flags, so no test reaches an `internalBinding()` call. Expect this
number to stay at 0 until `rn-module` and `rn-cli` land, and then to move in
steps rather than a curve, because a single fix (module loading) unblocks
thousands of files at once.

**Measured full suite — 1 of 5,666 files pass.** Same binary, same test tree,
every suite the harness knows: `parallel` (5,161), `sequential` (128),
`es-module` (252), `internet` (40), `pummel` (75), `message` (24),
`known_issues` (21). The single pass is
`parallel/test-regression-object-prototype.js`, which uses no `require` and no
flags — it exercises the V8 and prototype layer that already works. The full run
takes about six seconds because most files exit immediately.

Both numbers are a starting line, not a trend. Re-measure rather than quoting
these: they move every time a crate lands.

### Checking your own subsystem

A binding workstream owns one namespace, so it cares about the tests whose names
carry that subsystem. Run the filtered subset and read the table:

```bash
cd rustnode
./tools/run-node-tests.sh --tests /tmp/node/test --filter test-fs- --label fs
```

Useful selectors:

| Flag | Effect |
| --- | --- |
| `--filter <substring>` | case-insensitive substring match on the file path; repeatable |
| `--suite <name>` | one suite directory; repeatable |
| `--only <path>` | one exact file, relative to `test/`; repeatable, overrides the others |
| `--limit <n>` | stop after n selected files, for a quick look |
| `--smoke` | the fixed 10-file subset |
| `--all` | everything, instead of the default subset |
| `--timeout <seconds>` | per-file wall-clock limit (default 30) |
| `--jobs <n>` | concurrency for parallel-safe suites |
| `--label <name>` | suffix the result file so runs stay distinguishable |

`--filter` matches the path, so it crosses suites: `--filter test-fs` selects
`parallel/test-fs-*`, `sequential/test-fs-*`, `pummel/test-fs-*` and
`known_issues/test-fs-*` in one run (410 files here). That is intentional: a
subsystem's behaviour is not confined to one suite. Add `--suite parallel` when
you want to keep the run to one directory.

The dashboard groups by the first segment of the name after `test-`, so
`parallel/test-fs-open.js` and `sequential/test-fs-watch.js` both count under
`fs`. That segment is the file name's first hyphen-separated word, so
`test-string-decoder.js` lands under `string`, not `string_decoder`. Treat the
cluster column as a coarse hint for triage, not as an exact namespace mapping —
use `--filter` when you need an exact subsystem. `report --json` gives the same
data plus every failing file with its exit code and the first line of stderr,
which is usually enough to name the missing member.

## What none of these gates cover

- **`internet` tests need network access** and are skipped by most CI setups;
  they are selectable but their results depend on the machine.
- **`addons`, `js-native-api`, `node-api`, `cctest`, `fuzzers`** are compiled C++
  fixtures, not JavaScript, and the harness does not select them. Node-API
  support is `rn-napi`'s own concern.
- **A passing file is not proof of a matching subsystem.** Node's tests reuse
  helpers heavily; one test can touch a dozen namespaces. The suite measures
  observable behaviour, which is the point, but it will not tell you which member
  is wrong.
- **Timeouts are failures, not skips.** A file killed at 30 seconds counts
  against the pass rate. Raise `--timeout` before concluding a test is broken.

## Known divergences

Recorded differences from Node that are real, measured, and not yet fixed.
Each names why it exists, so it is not mistaken for a bug report or a to-do
without context.

### `zlib` level 4-6 compress less than Node

`libz-rs-sys` and the zlib Node vendors (zlib-ng) map compression levels
differently above level 3. Measured with `deflateSync` on a 4000-byte
alphabet-cycle payload:

| level | node | rustnode |
| --- | --- | --- |
| 1-3 | 79 | 78-79 |
| 4-6 | **60** | **79** |
| 7-9 | 60 | 60 |
| -1 (default) | 60 | 79 |

Decompression is byte-identical either way — a payload compressed by rustnode
round-trips through node and vice versa — so this affects compression ratio,
not correctness. Closing it means linking the same zlib Node vendors, which is
a build change of its own.

The zstd half of `zlib` does not share this: it links `zstd-sys`, which vendors
the same C sources Node bundles at the same version (`+zstd.1.5.7`), so
`zstdCompressSync` is byte-identical to Node's for the payloads in
`crates/rn-bind-zlib/tests/zstd_parity.rs`. The divergence above is specific to
`libz-rs-sys` and to `deflate`/`gzip`, and this change does not touch it.

### Web Streams globals are not installed

`ReadableStream`, `WritableStream`, `TransformStream` and their friends are
not on the global object. `internal/webstreams/**` loads correctly; the
globals are simply not wired, because `internal/bootstrap/node.js` never runs
in this build. `util.inspect`'s own test needs `ReadableStream`, and is the one
remaining failure in the Node test smoke set.

### `DOMException` is not a real `Error` subclass

`new DOMException('m','N')` reports `[object Object]` and `instanceof Error`
is `false`; Node gives `[object DOMException]` and `true`. The properties are
data properties on the instance rather than prototype accessors, so
`util.inspect` renders `{}` where Node renders `[object DOMException] { ... }`.

Node's own implementation is `lib/internal/per_context/domexception.js`, which
is vendored and correct. It cannot be `require`d, because it reads `primordials`
and `privateSymbols` as bare globals — it has to be *called* with those injected,
the way `run_per_context` already calls `primordials.js`.

The missing piece is small and specific: `run_per_context` in
`crates/rn-cli/src/bootstrap.rs` builds a `private_symbols` object and passes it
as an argument, but never exposes it as a global, so `domexception.js` has
nothing to read. Exposing it, then running that file through the same path,
should let the vendored implementation replace the hand-built one.

Two workers independently hit this and both reverted their attempts rather than
leave half-working surgery, which is why it is recorded here rather than guessed
at in the code.
