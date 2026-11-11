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
`vendor/libnode-js matches the pinned Node revision (435 lib files, 3 deps files)`
and exits 0, or names the modified file and exits 1. The check is a plain
`sha256sum -c` against `vendor/libnode-js/LIBJS.sha256` plus a file count, so it
needs no network and no Node binary. **Current state: passing, 435 `lib/` files
and 3 `deps/` files.**

If a genuine Node bug requires a JavaScript change, that is a design decision,
not a local edit: it means the native layer cannot express what the JavaScript
expects, and the fix belongs in Rust.

`vendor/libnode-js/deps/undici/undici.js` is frozen the same way, for the same
reason. Node's js2c embeds `lib/**` and an explicit `deps_files` list into one
builtin table, and `lib/**` requires that bundle by id — without it,
`require('internal/deps/undici/undici')` throws `Missing internal module` and
`fetch`, `Response`, `FormData` and the WebAssembly streaming callback are all
unreachable. The two trees are counted separately (435 and 3): a single total
would let one gain a file while the other lost one and still balance. The three
`deps/` files are `undici/undici.js` plus acorn's `dist/acorn.js` and
`acorn-walk/dist/walk.js`, which `lib/internal/repl/*`,
`lib/internal/errors/error_source.js` and
`lib/internal/modules/esm/module_job.js` parse with; `tools/node-pin.toml`
records why the eleven `deps/v8/tools/**.mjs` entries stay out.

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

**Current state: enforcing, against 74 contract files.** An earlier version of this
section said `contracts/` did not exist and that a green `rn-compat` meant nothing.
That is no longer true. `cargo run -p rn-compat -- contracts` now ends with:

```
binding shapes match .../contracts contracts (14 namespace(s) unregistered, 0 placeholder)
coverage ratchet holds: 59 namespace(s) recorded complete are still complete
```

Read those two lines carefully, because they say different things. **`unregistered`
is bring-up state**: a namespace with a contract that no Rust crate installs yet is
reported and does not fail the gate, so 14 of 74 namespaces are still uncovered.
**`placeholder` must be 0**, and the coverage ratchet fails the build if a namespace
that used to cover its contract stops doing so. `./tools/check.sh` runs exactly this
command with `--baseline contracts/complete-namespaces.txt`, so a regression cannot
pass the gate silently.

Recording a contract still needs a Node build where
`require('node:module').internalBinding` is reachable; on the Node 22 build
available here it is not, so contracts are recorded from a Node 28 binary.

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

These two numbers were bring-up measurements taken when the runtime could not load
a CommonJS module, and they had been stale for a long time. They are replaced here
with measurements, and the method is stated so the next person can repeat or refute
it.

**Smoke subset — 10 of 10 files pass.** The subset is the fixed 10-file list in
`SMOKE_SUBSET` (`parallel/test-assert.js`, `test-buffer-bytelength.js`,
`test-fs-open.js`, `test-path-parse-format.js`, `test-util-inspect.js`,
`test-events-once.js`, `test-querystring-escape.js`, `test-string-decoder.js`,
`test-timers-ordering.js`, and `es-module/test-esm-import-meta.mjs`). Measured
against the pinned tree with the four-marker rule, so a skip or a `node:test`
failure would not be counted as a pass:

```bash
cd rustnode
python3 tools/test-tail-map.py run --node /tmp/frozen/rustnode \
    --tests /tmp/node-pin/test --out /tmp/smoke.json \
    --only parallel/test-assert.js --only parallel/test-buffer-bytelength.js \
    --only parallel/test-fs-open.js --only parallel/test-path-parse-format.js \
    --only parallel/test-util-inspect.js --only parallel/test-events-once.js \
    --only parallel/test-querystring-escape.js --only parallel/test-string-decoder.js \
    --only parallel/test-timers-ordering.js --only es-module/test-esm-import-meta.mjs
python3 tools/test-tail-map.py score /tmp/smoke.json
```

The old text reported **0 of 10**, split across `require is not defined` (6 files),
an ESM loading error (1), and two rejected CLI options (2 × `--expose-internals`,
1 × `--no-warnings`). Those were real on the bring-up binary and every one is fixed
now, so this is a disproved claim rather than a deleted one: the same ten files pass.

The old text also said to expect the number to stay at 0 until `rn-module` and
`rn-cli` landed, and then to move in steps rather than a curve, because a single fix
would unblock thousands of files. That is what happened; the full-suite figure below
is the curve.

**Full suite — 2732 of 5714 files pass (47.8%), measured on `368e32ac`.**

That is the current number, and it is measured with the four-marker rule on a binary
built from that commit. An earlier version of this section said the figure was
unmeasurable pending #51; #51 merged at 11:11:55Z on 2026-11-11 via the `2fc0b17f`
merge, so it is measurable and has been measured.

Why the rule matters, and why a bare exit-code rate is not comparable: two defects
made `rn-harness` grade failures as passes.

1. `common.skip()` prints `1..0 # Skipped:` and exits 0, so a file that tested
   nothing was graded as passing. 485 files carry a skip marker on this tree.
2. Before #51, `beforeExit` was never emitted, so `node:test`'s `test:summary` never
   ran and a file whose subtests failed exited 0.

For scale, the same tool at the same scope on an earlier tree:

| scope | commit | binary | scoring rule | result |
| --- | --- | --- | --- | --- |
| 8 suites, 5714 files | `7af7b306` (pre-#51) | `c4ff9845…` | four-marker | 2855 passed (50.0%) |
| 8 suites, 5714 files | `52f79555` (#51) | `d8c0d9cd…` | four-marker | 2572 passed (45.0%) |
| 8 suites, 5714 files | `368e32ac` | `3c50d5e7…` | four-marker | **2732 passed (47.8%)** |
| `test/parallel` (5159) | `368e32ac` | `3c50d5e7…` | four-marker | 2550 passed (49.4%) |
| `test/parallel` (5159) | `f0649774` | `dc9355c7…` | four-marker | 2549 passed (49.4%) |

**47.8% and 49.4% are not a trend — they are different scopes.** The eight-suite
rate is lower because the extra suites carry failures `test/parallel` does not. Both
are measured, and neither may be converted into the other by arithmetic;
`docs/test-tail.md` holds the full provenance table and the decomposition that
closes only when both sides come from the same run.

The rate moved 45.0% → 47.8% because merges between those two trees closed whole
families — `worker_threads`, `fs/promises.cp`, the inspector namespace (329 skips to
zero) — not because the measurement changed. All five rows used the pinned tree
`f344e7f552e3656bd37517151c5dc87d22b33771` and the commands in `docs/test-tail.md`,
which also explains why the rule is a floor rather than a proof.

The old text reported 1 of 5,666 files passing and named
`parallel/test-regression-object-prototype.js` as the only pass. That was true of the
bring-up binary; it is not true now.

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

### `DOMException` is now Node's per-context class (fixed 2026-11-11)

Recorded here because it was a divergence for a long time and the *shape* of the
bug is the reusable lesson, not the fix.

`new DOMException('m','N')` reported `[object Object]`, `instanceof Error` was
`false`, and `code` was always `0`; Node gives `[object DOMException]`, `true`,
and the code table's value. The properties were data properties on the instance
rather than prototype accessors, so `util.inspect` rendered `{}`. `util.inspect`
and the WebCrypto and `QuotaExceededError` tests were failing on this alone.

**The cause was not `DOMException`.** `run_per_context` in
`crates/rn-cli/src/bootstrap.rs` ran only `internal/per_context/primordials` and
handed it empty objects in place of Node's `privateSymbols` and
`perIsolateSymbols`. `internal/per_context/domexception.js` is vendored and
correct, but it destructures `transfer_mode_private_symbol` from the first table
and `messaging_clone_symbol` + `messaging_deserialize_symbol` from the second, and
defines those last two as methods on one prototype. With the tables empty both
methods landed on the string key `"undefined"` and the second replaced the
first — so the class would have constructed and silently failed to clone. It
never got that far, because the file was not run at all: `DOMException` came from
a hand-built V8 function template in `rn-bind-messaging`.

**The fix.** `run_per_context` now runs all three files in Node's order, with the
arguments `InitializePrimordials` passes, and stores the shared `exports` object
on the context under the private key `node:per_context_binding_exports` the way
`GetPerContextExports` does. `rn_core::private_symbols_object` and
`rn_core::per_isolate_symbols_object` build the two tables from the single
`PER_ISOLATE_*` tables in `rn_core`, and `internalBinding('messaging')` reads
`DOMException` and `QuotaExceededError` back out of the stored exports instead of
building its own — so the binding and the global are the same constructor, which
`instanceof` across them requires.

**The general lesson, which is why this is written down.** A per-realm global that
is silently absent does not fail at its own site. It fails wherever an
`undefined` is used as a key or a value, which is far from the missing binding.
This project has now hit that twice: `util.privateSymbols` installed 4 of Node's
22 entries and every missing one collapsed onto the string key `"undefined"`
(which made a child `Module` read its parent's object as its own source), and
this case, where two prototype methods collapsed onto one key.

The audit that prevents a third: `rn_core::PER_ISOLATE_SYMBOLS` and
`PRIVATE_SYMBOLS` are each pinned against their contract file by a test, so a
re-pin that adds an entry fails rather than silently omitting it, and
`per_isolate_symbol_description` refuses a name outside the table instead of
handing out a fresh identity.

**The symbol table was re-keyed, not repaired.** This is worth stating precisely,
because the obvious reading — "master had a symbol-keying bug" — is wrong and
would send the next person looking for a regression that never shipped.
`internalBinding('symbols')` was correct before this change: the table in
`rn-bind-symbols/src/lib.rs` held 27 `(exposed name, description)` pairs in which
the two fields were *identical* for every entry (`("handle_onclose",
"handle_onclose")`, …, see `cab39a39` and `118a95df`, unchanged at
`45015ce3^` = `18b3a28f`), and `install` keyed the namespace by the first field —
`v8::String::new(scope, name)`. Since that field already was the description,
`internalBinding('symbols').handle_onclose` resolved and `require('internal/worker/io')`
loaded.

What the change did was single-source the table: it moved to
`rn_core::PER_ISOLATE_SYMBOLS` (commit `8e862d2c`) as `(C++ member name,
description)` — Node's `PER_ISOLATE_SYMBOL_PROPERTIES` shape — and `install` now
keys by the *description*, because `node_symbols.cc` does
(`env->PropertyName()->Description(isolate)`). Three entries differ between the
columns (`handle_onclose_symbol`/`handle_onclose`, `oninit_symbol`/`oninit`,
`onpskexchange_symbol`/`onpskexchange`); that split is new information the
one-column table could not express, not a defect it was hiding.

The risk was introduced *by* the refactor and caught before it merged: once the
member name is a separate column, keying the namespace by it would leave
`io.js`'s `handle_onclose` destructuring `undefined` and pass that to
`ObjectDefineProperty` as a property key, which throws at module scope. That is a
transient state of this refactor, not a bug on `master`, and the code now keys by
the description so it cannot recur.

Measured: `test-domexception-cause.js`, `test-domexception-subclass.js`,
`test-global-domexception.js`, `test-quotaexceedederror.js`,
`test-structuredClone-domexception.js`, `test-util-inspect.js` and
`test-webcrypto-random.js` all went from fail to pass, with no file regressing.
`tools/per-context-control.sh` is the negative control: 7 of its 8 checks fail
against the pre-fix binary and all 8 pass against this one.

### Version skew against the local `node` binary

The reference binary available on a development machine is a released `node`
(v22 here), but the behaviour rustnode has to reproduce is the pinned Node 28
tree in `tools/node-pin.toml`. Those disagree in places, and when they do the
pin wins: a difference the pinned tests demand is not a divergence from Node,
it is a divergence from an older Node. Parity scripts therefore assert the
pinned answer instead of diffing every line against the local binary, and say
which lines they exempt and why.

The cipher surface is the current example. Under v22, `ctsMode` and
`xtsStandard` are accepted and ignored on a cipher that does not implement
them; at the pin they throw `ERR_CRYPTO_UNSUPPORTED_OPERATION`, because
`CipherBase::CommonInit` in the pinned tree's `src/crypto/crypto_cipher.cc`
selects the cipher and then applies those `OSSL_PARAM`s, and a cipher that does
not advertise them fails there before any key or IV is used.
`crates/rn-bind-crypto-cipher` follows the pin, so a parity run against v22 is
expected to differ on exactly those two shapes and must match byte for byte
everywhere else.

The rule is not cipher-specific: when a parity run disagrees with the local
binary, check the pinned test tree first. "Matches v22" is evidence about v22,
not about the target.
