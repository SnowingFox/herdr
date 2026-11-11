# What remains in Node's test suite

A measured map of the failures left in `test/parallel`, written after the
clusters that a single fix could close were all closed. Sizes are distinct
files out of 5666, from a full baseline run of 2803 passing (49.5%).

Treat the sizes as relative priority, not as a promise that fixing one closes
exactly that many files: many carry more than one failure.

## Read this before quoting a number

**The 2803/5666 (49.5%) baseline in this file is stale.** Re-measured on
`origin/master` at `8b7c43b7` with a frozen binary and a fresh result directory,
the suite is **3799 of 5666 files recorded as passing (67.0%)**.

**But 817 of those 3799 "passes" never ran a test.** `common.skip()` prints
`1..0 # Skipped: <reason>` and calls `process.exit(0)`, and
`tools/harness/src/runner.rs` records `passed = !timed_out && exit_code == 0`,
so a skip is counted as a pass. Measured by scanning each row's retained
`stdout_head` for the marker:

| figure | value |
| --- | --- |
| files recorded as passing | **3799 / 5666 (67.0%)** |
| of which skipped | **817 (21.5% of recorded passes)** |
| files that actually ran and passed | **2982 / 5666 (52.6%)** |

**Quote 52.6% if the question is "how much of Node's suite actually works", and
67.0% only if the question is "how many files does the harness record as
passing".** The honest number is the 52.6%. The 817-skips figure is not a
measurement artifact of this machine: 789 of them (96.6%) are rustnode gaps that
real `node` would run — inspector, QUIC and DTLS are simply absent. Only 22 are
platform-inherent gates a Linux `node` would skip too.

The same scan on the previous baseline at `27d67077` reads 3735 recorded / 814
skipped / 2921 honest (65.9% / 51.6%), so the skip population is stable and the
recorded and honest series move together.

This re-measurement replaced the old 3733/5666 (65.9%). The delta is +64 files,
all attributed in the commit-by-commit notes below; the two apparent regressions
were temp-directory collisions in the harness, not code.

The current rates that matter for remaining work are `crypto` 21.7%, `tls` 7.3%
and `https` 2.7%, against `http` at 90.0% for contrast. Those three are the
lowest-rate clusters of any size, and they are the subject of the TLS and
asymmetric crypto workstream.

Two procedure details when re-measuring. Freeze the binary first and use a
separate result directory: `rn-harness report` keeps the newest outcome per file
per directory, so a rebuilt binary in the same directory silently mixes before
and after. And the Node test tree must be the pin: `f344e7f552e` is a full
40-character SHA, so `git fetch --depth 1 origin <full-sha>` into an empty repo
plus `sparse-checkout set test` is what works; without `--tests` the wrapper
clones Node's default branch and the numbers are not comparable.

## Measured at `8b7c43b7` — cluster deltas and attribution

Two full runs, both at the pinned tree
(`f344e7f552e3656bd37517151c5dc87d22b33771`), each with its own frozen binary and
its own never-reused result directory:

| run | binary | recorded | skipped | honest |
| --- | --- | --- | --- | --- |
| `27d67077` (old baseline) | `ad4832bf…` | 3735/5666 (65.9%) | 814 | 2921 (51.6%) |
| `8b7c43b7` (current) | `08186134…` | **3799/5666 (67.0%)** | 817 | **2982 (52.6%)** |

The old run reproduces the previously recorded 65.9% (3733 vs 3735 — two files of
run-to-run noise), which is what makes the new number comparable to it.

### Clusters the brief tracks, recomputed

| cluster | docs said | `27d67077` | `8b7c43b7` | delta | honest (ran & passed) | skipped |
| --- | --- | --- | --- | --- | --- | --- |
| `http` | 395/439 | 395/439 | 395/439 | +0 | 394/439 | 1 |
| `crypto` | 30/189 | 30/189 | **41/189** | **+11** | 33/189 | 8 |
| `tls` | 18/245 | 18/245 | 18/245 | +0 | 5/245 | 13 |
| `https` | 2/74 | 2/74 | 2/74 | +0 | 0/74 | 2 |
| `zlib` | 73/97 | 74/100 | **90/100** | **+16** | 90/100 | 0 |

`zlib` needs a note on the denominator: the harness "cluster" is every file whose
basename starts `test-zlib`, which is **100** across all seven suites. The docs'
**97** is `parallel/test-zlib*` only, where the current figure is **89/97**. Both
are correct for their definitions; the +16 is the same files either way.

**No cluster went down.** `tls`, `https` and `http` are unchanged.

### Every file that changed outcome, and what caused it

66 files went fail → pass and 2 went pass → fail, for a net +64.

**`#21` zstd — 18 files.** 7 `test-zlib-zstd-*` plus `test-zlib.js`,
`test-zlib-truncated.js`, `test-zlib-zero-byte.js`, `test-zlib-decode-strings.js`,
`test-zlib-random-byte-pipes.js`, `test-zlib-write-after-flush.js`,
`test-zlib-brotli-flush-invalid-kind.js`,
`test-zlib-convenience-async-round-trip.js`,
`test-zlib-convenience-methods.js`, `test-stream-iter-transform-sync.js`,
`test-vfs-zip-provider-handle.js`. Every one failed with `Uncaught Error: zstd is
not implemented by rn-bind-zlib`, which is the throw this merge removed. The
non-zstd files are there because they construct a zstd handle at module scope.

**`#19` DiffieHellman — 13 files.** `test-crypto-dh-{errors,generate-keys,
group-setters,known-groups,modp2-views,modp2,odd-key,padding,shared}.js`,
`pummel/test-crypto-dh-hash.js`, `pummel/test-crypto-dh-keys.js`,
`pummel/test-dh-regr.js`. Old failures are `_DiffieHellmanGroup is not a
constructor` (10) and `_DiffieHellman is not a constructor` (1). This is the
`crypto` +11.

**`#16` permission — 22 files.** `test-permission-*` (20) and
`test-cli-permission-*` (2). Old failures were `warning: --permission is accepted
but not implemented` (11) and `unsupported option '--allow-{net,addons,
inspector,wasi}'` (7), plus two assertion failures. This is the `permission`
cluster moving 23 → 43 recorded.

**`#17` TCP asyncReset / getProviderType — 3 files.** `test-cluster-concurrent-disconnect.js`
(failed with `TypeError [ERR_INVALID_ARG_TYPE]: The "err" argument must be of
type number. Received an instance of WriteWrap` from `getSystemErrorName` — the
handle was being passed where an int was expected), `test-async-wrap-destroyid.js`
and `test-socketaddress.js`.

**`#18` kClone host-object hook — 2 files.** `test-blocklist-clone.js` posts a
`BlockList` through a `MessageChannel` and asserts the deserialised copy is a
working `BlockList`; the old failure was `TypeError: data.check is not a
function`, exactly the missing-hook symptom. `test-messaging-marktransfermode.js`
is the other.

**Harness temp-directory collisions — 4 gains, 2 losses.** These are *not* code
changes and should not be read as regressions. `test-fastutf8stream-retry.js`,
`test-fs-readfilesync-pipe-large.js`, `test-fs-symlink-longpath.js` and
`test-fs-utils-get-dirents.js` moved fail → pass, and
`test-fs-existssync-memleak-longpath.js` and
`test-fs-realpath-stale-stat-values.js` moved pass → fail, all with `ENOENT` /
`EEXIST` under the shared `test/.tmp.<n>/` directory. Running the two "lost"
files alone against the same `8b7c43b7` binary gives **2/2 passing**, which
proves it is contention between concurrent files and not the tree.

**1 remaining file:** `test-perf-hooks-usertiming.js`, old failure
`TypeError: structuredClone: the serialized value could not be read back`, which
is consistent with `#18` but is the least directly evidenced attribution here.

## The skip population, grouped by gate

817 of the 3799 recorded passes are `1..0 # Skipped:` exits. Grouped by reason at
`8b7c43b7`:

| files | gate | real `node` would run it? |
| --- | --- | --- |
| 328 | `V8 inspector is disabled` (`process.features.inspector = false`) | **yes** — `--inspect` is an unsupported option here |
| 272 | `QUIC is not enabled` | **yes** — the flag warns as unimplemented |
| 54 | `DTLS is not enabled` | **yes** |
| 32 | `missing ESLint` (`tools/eslint` not checked out) | yes, but this is a fixture gap, not a runtime one |
| 31 | `missing SQLite` (`process.versions.sqlite`) | **yes** |
| 18 | `no IPv6 support` | **yes, and this one is a bug** — see below |
| 24 | OpenSSL build/feature gate (FIPS, PKCS#11, `openssl-cli`, BoringSSL) | mixed — some are genuine build differences |
| 18 | Windows-only test | no, inherent on Linux |
| 11 | `Requires Amaro` (TypeScript) | **yes** |
| 3 | Temporal, macOS-only, AIX-only, addon, Intl/ICU, trace events | mostly no |
| 12 | environment (`strace`, `wrk`, `ab`, `nop` binary, non-TTY, inotify) | no, inherent |

**789 of 817 (96.6%) are rustnode gaps rather than platform gates.** The single
largest fix available is the inspector: 328 files, spread over `repl` (101),
`debugger` (83), `inspector` (76) and `heap`/`cpu` (22). Second is QUIC at 272.

This is why the honest figure is 52.6% and not 67.0%. The clusters that look
strongest are the most affected: `repl` is recorded 102/102 but every one of
those is a skip, and `debugger` is 83/83 all skipped. `sqlite` is 26/26 all
skipped — the same pattern the sqlite worker hit, at 100%.

### The IPv6 skips are a real bug, not a gate

`common.hasIPv6` returns `Object.keys(os.networkInterfaces()).some(...)` looking
for `family === 'IPv6'`. rustnode's `os.networkInterfaces()` returns **lowercase**
`"ipv4"` / `"ipv6"` where Node returns `"IPv4"` / `"IPv6"`:

```
$ rustnode -e "console.log(JSON.stringify([...new Set(Object.values(require('os').networkInterfaces()).flat().map(x=>x.family))]))"
["ipv4","ipv6"]
$ node      -e "…same…"
["IPv4","IPv6"]
```

So `hasIPv6` is false even though `process.features.ipv6` is `true` and `::1` is
present in the interface list, and **18 files skip with "no IPv6 support" that
should run**. It also sets `internal: false` for loopback where Node sets `true`,
and leaves `mac` empty. This is a one-line casing fix in the `os` binding and it
unblocks 18 files; it is worth doing before any of the larger skip families.

### `process.versions` and the capability flags

`process.versions` is **not** the main skip family, contrary to expectation: it
accounts for 31 SQLite skips, 11 Amaro and 2 ICU. But it is a real and cheap gap,
and it blocks capability detection generally.

Node at the pin exposes **31** keys (`src/node_metadata.h`,
`NODE_VERSIONS_KEYS`). rustnode reports **4**:

```
node, openssl, uv, v8
```

Missing, in the order `NODE_VERSIONS_KEYS_BASE` lists them:

`zlib`, `brotli`, `zstd`, `ares`, `modules`, `nghttp2`, `napi`, `llhttp`,
`uvwasi`, `acorn`, `simdjson`, `simdutf`, `ada`, `nbytes`, `ngtcp2`, `nghttp3`,
`amaro`, `undici`, `merve` — plus the conditional groups `ncrypto` (with
`openssl`), `cldr`, `icu`, `tz`, `unicode`, `sqlite`, `libffi`, `lief`.

That is **27 missing keys**. `common` gates on several of them directly
(`hasSQLite`, `hasCrypto`, `hasFFI`) and on `process.config.variables` for others
(`hasIntl` reads `v8_enable_i18n_support`, `hasTemporal` reads
`v8_enable_temporal_support`) — and `process.config.variables` *is* populated
here, which is why Intl gates behave. Adding the version keys would let those
gates answer correctly without changing any other behaviour.

## Headline numbers from the original snapshot

| measure | before | after |
| --- | --- | --- |
| fixed 120-test sample of `test/parallel` | **58/120 (48.3%)** | **74/120 (61.7%)** |
| full `test/parallel` (5666 files, measured) | 2803 (49.5%) | 3799 (67.0%) recorded / 2982 (52.6%) honest, at `8b7c43b7` |
| `python3 tools/smoke.py` | 18/18 | 18/18 |
| `tools/parity.py` | 2755 bytes identical | 2755 bytes identical |
| `./tools/check.sh` gates | green | green |

The 2803/49.5% figure is a full measured baseline I ran before changing
anything. The "after" full run was still in flight when this was written (each
full pass is roughly two hours because ~85 files time out at 30s), so the
**sample is the only like-for-like before/after number**. It is the metric the
task brief specified, and it moved 14 files.

Why 14 sample files and far more at scale: the 120-file sample is the
alphabetically-first 120 of `test/parallel`, so it is heavy on `a*` and `bench*`
and contains no `child_process`, no `tls`, no `fs.cp`, no `crypto` webcrypto and
no `worker` tests. Every one of those clusters moved at full-suite scale without
appearing in the sample at all. Concretely, the fixes below carry a signal in
**987 distinct baseline failure files**; only ~14 of them sit inside the sample.

## Clusters closed

Counts are distinct files in the measured 5666-file baseline whose failure text
carried that signature. They overlap, so the counts are not additive; the union
is the 987 stated above.

| files | cluster | fix |
| --- | --- | --- |
| 413 | `Unexpected global(s) found: __argv, __stdout, __stderr, __v8Version, …` | `bootstrap.js` deletes its Rust hand-off globals; `set_global` defines globals non-enumerably; `exposeLazyDOMExceptionProperty` defines instead of assigns |
| 152 | `internalBinding('ipc_serdes')` has no implementation | new `ipc_serdes` namespace in `rn-bind-serdes`: V8 serialization with the `[4-byte BE length][payload]` framing and `ArrayBufferView` host-object tagging |
| 105 | `Missing internal module 'internal/deps/acorn/acorn/dist/acorn'` | vendored `deps/acorn/acorn/dist/acorn.js` + `acorn-walk/dist/walk.js` from the pinned revision; `deps_files` 1 → 3 |
| 106 | `--experimental-stream-iter is accepted but not implemented` | stopped warning: `stream/iter` resolves and the `test-quic-stream-iteration*` files pass |
| 82 | `Cannot destructure property 'subtle' of 'globalThis.crypto'` | installed WebCrypto in **file** mode (`crypto`, `Crypto`, `CryptoKey`, `SubtleCrypto`); `-e` mode had masked the gap |
| 37 | `fsBinding.cpSyncCheckPaths is not a function` | implemented `cpSyncCheckPaths`: the four `fs.cp` path-identity checks, with `ERR_FS_CP_*` shapes recorded from the real `node` binary |
| 32 | `setUncaughtExceptionCaptureCallback is not a function` | installed the four `internal/process/execution` hooks; routed timer/immediate throws through `process._fatalException`; added the `shouldAbortOnUncaughtToggle` aliased buffer |
| 22 | `No such built-in module: node:bench` | parse the CLI into `internalBinding('options')` values (`Store` mirrors `OptionsParser<Options>::Parse`), which is what gates `node:bench` |
| 22 | `--allow-natives-syntax is accepted but not implemented` | forwarded to V8 before `V8::Initialize`, both spellings |
| 14 | `process.getuid/geteuid/getgid/getegid/getgroups is not a function` | copied the credential getters onto `process`; fixed the `credentials` setters to resolve names instead of coercing, and to throw `UVException`'s exact shape |
| 8 | `internalBinding('signal_wrap')` has no implementation | new `rn-bind-signal-wrap`: `Signal` as a `HandleWrap` over `uv_signal_t` |

Two smaller commits support the above: `rn-bind-options` now has a `parsed`
module with 44 unit tests, and `rn-bind-os`'s `credentials` setters were
corrected (they coerced every non-numeric string to uid 0, so
`process.setuid('nobody')` tried to become root rather than reporting an unknown
credential).

Every fix above was verified against the `node` binary on PATH, and the
recorded-vs-actual comparison is in the commit body for each. The strongest
examples: `process.getgroups()` is byte-identical to `node`'s answer on this
machine; the four `fs.cpSync` error shapes match byte-for-byte including the
trailing separator `src` keeps in the subdirectory case; and
`setUncaughtExceptionCaptureCallback` followed by a throwing `setImmediate`
prints the same two lines and exits 0 under both runtimes.

## Deliberately not attempted, with sizes

These are the whole remaining tail as measured, largest first. A next worker can
pick from this list directly.

### 638 files — `tls_wrap`: **not tail work, do not start it**

The contract lists only three members (`TLSWrap`, `wrap`, `HAVE_SSL_TRACE`), which
makes it look like a weekend job. It is not. `TLSWrap` is a `StreamBase` whose
`DoWrite`/`DoRead` are `SSL_write`/`SSL_read` against an `SSL_CTX` created from a
`SecureContext`, plus `SSL_do_handshake`, the `SSL_get_error` retry machine,
session resumption, SNI callbacks, ALPN, OCSP and the TLS session-ticket keys.
`lib/internal/tls/wrap.js` drives it through fifteen proxied `HandleWrap`/
`TCPWrap` methods that all have to forward into a live SSL object.

This is a real TLS stack over OpenSSL, of the same order as the deferred
asymmetric crypto surface (`RsaKeyPairGenJob`, `KeyObjectHandle`,
`EcKeyPairGenJob`, `_DiffieHellmanGroup`, `isNativeKeyObject` — another ~110
files in this same list). **Recommendation: leave all of it to the crypto
workstream.** Starting `tls_wrap` here would have produced a partial handle that
fails deeper and less legibly than the current honest "no implementation yet".

### 148 files — `AssertionError: Expected values to be strictly equal`, no single cause

This is the true long tail: after removing every named signature, 148 files fail
on a bare value comparison. They are not one bug. Spot-checking put them in
`async_hooks` id sequencing, `AbortSignal` clone/reason semantics, `AsyncLocalStorage`
propagation through the HTTP agent, and `structuredClone` transfer lists. Closing
this needs per-family investigation, not a cluster fix.

### 116 files — `WorkerImpl is not a constructor`

`worker_threads`. `rn-bind-worker` declares `Worker` deferred with a reason that
is correct and still applies: it needs a second isolate, a cross-thread
`MessagePort` transport, and the worker-side bootstrap in
`internal/main/worker_thread.js`. This is a subsystem, not a namespace. It also
blocks a large share of the 148 above, because many of those tests spawn a worker
to check propagation.

### timeouts — now 94, was ~85

Measured **94** at `8b7c43b7` (and 97 at `27d67077` on the same machine), against
the ~85 this file previously recorded. The count is close between the two runs on
this machine, so most of the gap to ~85 is environment, not one merge. Distribution
now: `cluster` 21, `http` 14,
`child` 11, `dns` 11, `dgram` 6, `gc` 5, `async` 3, `fastutf8stream` 3, `worker`
3, then ones and twos. The count moving is a comparability caveat, not a
regression: a changed timeout population means the environment differs, so a file
that flipped outcome *and* timed out on either side should be re-run alone before
being called a fix or a regression.

All HTTP-related in the baseline (`test-async-hooks-http-agent*`,
`test-async-local-storage-http-*`, `test-http-server-keep-alive-*`). Root cause I
identified but did not fix: `HTTPParser#consume` throws because rustnode has no
`StreamBase` handle handoff, so `lib/internal/http/server.js` aborts the
connection path; the keep-alive socket then keeps the loop alive forever. A
related symptom is worth its own look: the process does not always exit after
`server.close()`, and orphaned `child-process-stay-alive-forever` children
accumulated during my first full run and had to be killed by hand.

### `--permission` — model enforced for four scopes, flag still on the warning list

**Correction, not a measurement from the full run below.** The old text said the
permission model was "genuinely absent" and that `--allow-fs-read` /
`--allow-child-process` did not gate anything. That is no longer true. #16
threaded the model from the CLI into every check, so `fs` read, `fs` write,
`child` and `env` are genuinely enforced: `/etc/passwd` returns
`ERR_ACCESS_DENIED` under `--permission`, is readable without it, and
`--allow-fs-read=/etc/passwd` re-enables it.

`test-permission-*` moved **23/88 → 44/88** on that merge. (My full-suite
measurement below puts the cluster's *honest* pass count lower, at 33/88 with 10
of the 43 recorded passes being skips — see the skip section; the 44/88 is the
pre-skip recorded figure on the change's own base.)

The flag legitimately **stays on the `UNIMPLEMENTED` warning list**, but for a
different reason than the old text gave. It is not that the model is absent — it
is that six scopes remain unenforced: **`net`, `worker`, `addon`, `wasi`,
`inspector`, `ffi`**. Tests that exercise those still see a warning, and the
warning is honest for them. Implementing the model for the remaining six is the
work that would let the flag come off the list; passing the flag only to tests
that do not need enforcement would be weakening a check, so do not do that.

### 27 files — `unsupported option '--snapshot-blob'`

Startup snapshots. The flag is not in `rn-cli`'s accepted list. Accepting it
would need `rn-bind-mksnapshot`'s snapshot build path to actually work, so this
is not a parser tweak.

### `block_list` — closed

Four members (`BlockList`, `SocketAddress`, `AF_INET`, `AF_INET6`), but
`BlockList` was a native rule engine: `addAddress`, `addRange`, `addSubnet`,
`check`, with IPv4/IPv6 CIDR prefix matching. It is implemented now
(`crates/rn-bind-block-list`), so this cluster is no longer a gap.

Of the sample files that exercise it, `test-blocklist.js`,
`test-net-blocklist.js`, `test-dgram-blocklist.js`, `test-net-server-blocklist.js`
and `test-net-server-blocklist-fail-closed.js` pass. Three still fail for reasons
outside this namespace: `test-blocklist-fast-api.js` needs `internalBinding('debug')`,
`test-tls-spki-blocklist.js` needs `tls_wrap`, and `test-blocklist-clone.js` needs
the messaging layer to round-trip a host object through `kClone`/`kDeserialize`
(the hook is stored by `setDeserializerCreateObjectFunction` but never invoked, so
the deserialised value arrives as a plain object).

### ~110 files — deferred asymmetric crypto

`isNativeKeyObject` (22), `RsaKeyPairGenJob` (19), `KeyObjectHandle` (18),
`EcKeyPairGenJob` (12), `_DiffieHellmanGroup` (11), `NamedKeyPairGenJob` (7),
plus `RandomBytesJob` and `KeyObjectHandle` variants. Belongs with `tls_wrap` in
the crypto workstream.

### `zstd` — closed (was "20 files — `zstd is not implemented`")

**Correction, not a measurement from the full run below.** Both throws that lived
in `rn-bind-zlib/src/handle.rs` are gone as of `8b7c43b7`: `ZstdCompress` and
`ZstdDecompress` build real handles, and the whole public surface is implemented
(`createZstdCompress`/`createZstdDecompress`, the four sync/async convenience
methods, every `ZSTD_C_*`/`ZSTD_D_*` parameter, and dictionaries).

Measured on that merge:

| measure | before | after |
| --- | --- | --- |
| `test-zlib-zstd` | 3/10 | **10/10** |
| `test-zlib` cluster | 73/97 | **89/97** |

Why compression output is **byte-identical** to Node's rather than merely
mutually decodable: Node vendors zstd **1.5.7** at `deps/zstd`, and this crate
links `zstd-sys` **2.0.17**, which vendors the same C sources at the same
version (`+zstd.1.5.7`). Both sides run the same compressor, so
`zstdCompressSync` produces the same bytes — a property `tests/zstd_parity.rs`
reports on several payloads rather than asserting, since only mutual decodability
is required.

**The `libz-rs-sys` level 4-6 divergence is untouched and is a different
thing.** `deflate`/`gzip` at levels 4-6 still compress to a ratio of 60 where
Node reaches 79, because those paths go through `libz-rs-sys` rather than Node's
zlib. Decompression is byte-identical either way, so it affects ratio, not
correctness. This change does not touch that path and does not fix it; see
`docs/compat-status.md` for the table.

### 17 + 12 files — `ReadFileJob` / `getWasmCompileCacheEntry`

Batched read job and the wasm compile-cache entry lookup. Both are declared
deferrals in `rn-bind-fs` with reasons that still hold.

### 12 files — `locks` namespace missing

`locks` is small but its consumer is `--experimental-locks`, which is itself not
implemented; implementing the namespace alone would move the failure rather than
close it.

## Honest caveats

* **The full-suite number has since been re-measured** — see "Measured at
  `8b7c43b7`" above. The original 49.5% baseline and the 65.9% figure that
  replaced it are both superseded by 67.0% recorded / 52.6% honest. The 120-file
  sample remains useful only as the like-for-like before/after for the original
  cluster-closing work; quote the full-pass number, not the sample.
* **Timeouts moved from ~85 to 94**, which matters if you compare this pass to
  the `27d67077` one: the timeout population is 94 here (`cluster` 21, `http` 14,
  `child` 11, `dns` 11), so a handful of files can flip for load reasons alone.
  Treat a file that changed outcome *and* timed out on either side as noise until
  re-run in isolation — that is exactly how the two apparent regressions in this
  pass were cleared.
* **A "pass" is not necessarily a test.** 817 of the 3799 recorded passes are
  `common.skip()` exits. Until `tools/harness` learns to detect the marker, any
  per-cluster rate in this file should be read as an upper bound.
* **The 987-file union is a signature match, not a per-file re-run.** A file that
  carried `__argv` in its stderr may also have failed for a second reason, so
  some of those 987 still fail. The sample going 58 → 74 is the evidence that the
  fixes are real; the 987 is the evidence that the sample understates them.
* **`--experimental-stream-iter` and `--allow-natives-syntax` were removed from
  the "unimplemented" warning list** because their behaviour now exists. That is
  the opposite of weakening a check: the warning had become a lie that tests read
  back. `--permission`, `--experimental-quic`, `--experimental-vm-modules` and
  the rest still warn.
* **The `deps_files` count moved 1 → 3.** That is a count change, which the
  project rules treat as a stop signal. It is legitimate here and was done the
  way `vendor/libnode-js/README.md` prescribes: two real files from Node's
  `node.gyp` `deps_files` list were vendored byte-identical, the count was
  updated in all three places that check it (`node-pin.toml`, `scheme.rs`,
  `verify-libjs.sh`) plus `TABLE_DIGEST`, and the README's "not vendored yet"
  paragraph was replaced with what is now vendored and what still is not
  (`deps/v8/tools/**.mjs`, eleven files, only reachable from `--prof-process`).
  No test expectation was relaxed.

## Files

Everything is committed on `node-test-tail` and fast-forwarded to
`origin/rustnode/main`.

New crates: `rustnode/crates/rn-bind-signal-wrap/` (`lib.rs`, `handle.rs`).
New modules: `rustnode/crates/rn-bind-options/src/parsed.rs`,
`rustnode/crates/rn-bind-serdes/src/ipc.rs`,
`rustnode/crates/rn-bind-fs/src/cp.rs`.
Vendored: `rustnode/vendor/libnode-js/deps/acorn/acorn/dist/acorn.js`,
`rustnode/vendor/libnode-js/deps/acorn/acorn-walk/dist/walk.js`.
