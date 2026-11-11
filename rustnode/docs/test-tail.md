# What remains in Node's test suite

A sized map of the failures left in Node's own test suite, used to decide what to
build next. Every number in it was produced by a command named next to it. Where a
number could not be measured, this file says so instead of estimating.

**What this map is for.** It ranks the remaining work by how many test files a fix
would unblock, so a worker can pick the largest honest target. It is not a release
gate, not a compatibility claim, and not a promise that fixing one family closes
exactly that many files: a file often carries more than one failure, and the
families below overlap.

**How the numbers were obtained.** `tools/test-tail-map.py` runs each test file in
its own process against a named binary and keeps the whole stdout and stderr. A
file counts as **passing only when it exits 0 *and* has none of four markers**:

| marker | what it means |
| --- | --- |
| `✖` on stdout | `node:test` printed a failing subtest |
| `Uncaught` on stdout or stderr | a plain-assert failure, often mid-line behind a `file:line:` prefix |
| `1..0 # Skipped` at column zero | `common.skip()` ran and exited 0 having tested nothing |
| `: # SKIP` | `node:test` skipped the test |

Everything that did not exit 0 is a failure; a timeout is a failure too, because a
killed process never stated a verdict. Files that skip are counted separately and
excluded from the ratio, since they measure nothing either way.

**What this map deliberately does not claim.** It does not claim the four-marker
rule is sound. It is a floor: a file that asserts nothing observable, or that
prints no output at all, cannot be told apart from a pass by reading output (see
"The rule is a floor, not a ceiling" below). It does not claim any figure below is
current beyond the binary it names, and it does not reconcile figures taken at
different scopes — a `test/parallel` rate and a seven-suite rate are different
measurements and are never combined.

## Pass-rate provenance

Every full-suite figure this project has published, with what it actually measured.
Read the **scoring rule** column before comparing any two rows; several pairs differ
by both scope and rule, and the differences do not add up.

| figure | commit | suite scope | scoring rule | verdict |
| --- | --- | --- | --- | --- |
| 2803/5666 (49.5%) | pre-`8b7c43b7` baseline | 7 suites, 5666 files | exit-code only | **superseded** — optimistic by both defect classes below |
| 3733/5666 (65.9%) | `27d67077` | 7 suites, 5666 files | exit-code only | **superseded** |
| 3735/5666 (65.9%) | `27d67077` re-run | 7 suites, 5666 files | exit-code only | **superseded** — the two-recorded-file delta from the row above is run noise |
| 3799/5666 (67.0%) | `8b7c43b7` | 7 suites, 5666 files | exit-code only | **superseded** |
| 2982/5666 (52.6%) | `8b7c43b7` | 7 suites, 5666 files | skip-aware | **superseded** — correct for skip counting, still scored on exit codes, so it still contains the #51 false passes |
| 3491/5159 (67.7%) | `7af7b306` | `test/parallel` only | exit-code only | **not reproducible here** — see the discrepancy note below; this work reads 3591 at the same commit |
| 3097/5159 (60.0%) | `52f79555` (#51) | `test/parallel` only | exit-code only | **not reproducible here** — this work reads 3218; still inflated by skips |
| 2855/5714 (50.0%) | `7af7b306` (pre-#51) | 8 suites, 5714 files | four-marker | **measured here** |
| 2572/5714 (45.0%) | `52f79555` (#51) | 8 suites, 5714 files | four-marker | **last measured eight-suite figure** |
| 2645/5159 (51.3%) | `7af7b306` (pre-#51) | `test/parallel` only | four-marker | **measured here** |
| 2393/5159 (46.4%) | `52f79555` (#51) | `test/parallel` only | four-marker | **measured here** |

### Why 52.6% is superseded, and why 45.0% is not a headline

Two defects made the harness grade failures as passes, and they are independent:

1. **Skips counted as passes.** `common.skip()` prints `1..0 # Skipped:` and calls
   `process.exit(0)`, and `rn-harness` records `passed = !timed_out && exit_code == 0`.
   Measured on the pre-#51 run below: 824 of its 3870 exit-0 files skipped, and 825
   files carry a skip marker in total (the extra one is a `known_issues` skip that
   exits 1).
2. **`node:test` failures counted as passes.** Until #51, `beforeExit` was never
   emitted, so `internal/test_runner/harness.js` never finalised the root test, so
   `test:summary` never ran and the process never set `process.exitCode`. A file
   whose subtests failed printed the failures and exited **0**. Reproduce on a
   pre-#51 binary:

   ```
   $ ./target/debug/rustnode -e "const {test}=require('node:test');test('f',()=>{throw new Error('x')})"
   ...  # prints the failure, no "tests N" summary
   $ echo $?
   0
   ```

   On #51's binary the same command exits 1, and 340 files in the suite import
   `node:test`.

**The honest current figure is unmeasured**, because #51 is still open and no tree
containing it is on `master`. Do not quote 45.0% as "the" pass rate: it is the
`52f79555` tree, which contains #51 but not anything merged after `7af7b306`, and it
is the last figure anyone measured rather than the current one. When #51 lands,
re-run `tools/test-tail-map.py` on the merge commit and replace this paragraph.

### A discrepancy this document does not resolve

PR #51 publishes 3491 passed before its fix and 3097 after, on `test/parallel`,
measured with `rn-harness`. Re-measuring the same two commits with
`tools/test-tail-map.py` gives **3591** and **3218** — 100 and 121 files higher.

The cause is not established, and this document does not pick a side. What is
ruled out or measured:

* **Not the temp-directory change.** Re-running the pre-fix commit with
  `--serial-id 0` (which reproduces `rn-harness`'s shared `test/.tmp.0/`, the way
  both of #51's runs were taken) gives 3581, only 10 below the 3591 measured with a
  per-file id. Collisions are real but they are not a 100-file effect.
* **Not the timeout.** #51 used 60 s; 30 s gives 3591 and 60 s gives 3581 at the
  same commit, so a longer limit moves the number *down* by reclassifying
  timeouts, not up.
* **Not a different suite set.** Both are `test/parallel` over the same pinned
  tree, and both select 5159 files.

The two directions of the fix agree in this work (+100 pre, +121 post), which is
consistent with a constant difference in how a pass was counted rather than with
either binary behaving differently. Anyone reusing #51's 3491/3097 pair should
re-measure first. The rows this document sizes come from its own runs, so the
discrepancy does not enter any family count.

### Provenance of the two runs measured for this document

Both runs used the same pinned Node tree, the same tool, a binary frozen before the
run, and the same command. They differ only by #51.

| | pre-#51 | post-#51 |
| --- | --- | --- |
| commit | `7af7b306` | `52f79555` (`origin/cursor/exit-and-test-status`, #51) |
| contains | #33, #46; **not** #51 | #33, #46, #51 |
| binary | `/tmp/frozen-pre51/rustnode` | `/tmp/frozen-pr51/rustnode` |
| sha256 (16) | `c4ff9845a0b34faf` | `d8c0d9cd691cfd07` |
| binary mtime (UTC) | 2026-11-11T10:10:26 | 2026-11-11T10:08:43 |
| Node tree | `f344e7f552e3656bd37517151c5dc87d22b33771` | same |
| command | `tools/test-tail-map.py run --node <binary> --tests /tmp/node-pin/test --jobs 8 --timeout 30` | same |
| exit-0 files | 3898 (68.2%) | 3454 (60.4%) |
| four-marker passes | **2855 (50.0%)** | **2572 (45.0%)** |
| skipped | 808 | 808 |
| failing | 2051 | 2334 |

Binary freshness: `rm target/debug/rustnode` does **not** force a rebuild, because
Cargo restores a cached hardlink whose mtime predates the build. `touch
crates/rn-cli/src/main.rs` and confirm `Compiling rn-cli` appears. Build env:
`RUSTUP_TOOLCHAIN=1.96.1 CXX=g++ RUSTFLAGS="-L /usr/lib/gcc/x86_64-linux-gnu/13"`.

## The rule is a floor, not a ceiling

The four-marker rule catches most of the #51 class but not all of it. On
`test/parallel`, the exit-code rule says 375 files flipped pass → fail when #51
landed. Of those 375:

| | files |
| --- | --- |
| the four-marker rule already called them not-passes on the pre-#51 binary | **118** |
| it still passed them, because the output carried **no marker at all** | **257** |

242 of the 257 are uncalled `common.mustCall`, and **193 of the 257 printed
completely empty output** pre-#51. `common.mustCall` reports
`Mismatched <anonymous> function calls. Expected exactly 1, actual 0.` from a code
path that only runs when the summary runs, so pre-#51 the file printed **nothing**
and exited 0. Example, `parallel/test-bench-context-control.js`:

```
$ /tmp/frozen-pre51/rustnode test/parallel/test-bench-context-control.js ; echo $?
0                      # empty output
$ /tmp/frozen-pr51/rustnode  test/parallel/test-bench-context-control.js ; echo $?
1                      # "Mismatched noop function calls. Expected exactly 1, actual 0."
```

So a `tools/test-tail-map.py` pass on a pre-#51 binary means only "exited 0 and
said nothing that looks like failure". It does not mean the assertions ran. On a
#51 binary the exit code carries the verdict and the rule is sound.

## Sizing, with provenance per row

All rows below are from the **post-#51 run** (binary `d8c0d9cd691cfd07`, commit
`52f79555`, 5714 files, 2334 failing) unless the row says otherwise. A row marked
*counted* was sized by matching a failure signature in the recorded output of that
run; a row marked *run* was re-run on the binary it names. Sizes are distinct files
and overlap, so they are not additive.

| files | family | provenance |
| --- | --- | --- |
| 640 | `internalBinding('tls_wrap')` has no implementation | counted |
| 151 | `AssertionError: … strictly equal`, no single cause | counted (132 in `test/parallel`) |
| 123 | `WorkerImpl is not a constructor` | counted |
| 114 | timeouts | counted |
| 28 | `fsBinding.cpSyncCopyDir is not a function` | counted |
| 19 | `fs.cp` calls `then()` on a `BigInt64Array` stat result | counted |
| 13 | `internalBinding('locks')` has no implementation | counted |
| 10 | `unsupported option '--snapshot-blob'` | counted |
| 0 | `ReadFileJob` / `WriteFileJob` | **run**, see below |

### `tls_wrap` — 640 files, and it is not tail work

The contract lists three members (`TLSWrap`, `wrap`, `HAVE_SSL_TRACE`), which makes
it look tractable. It is not. `TLSWrap` is a `StreamBase` whose `DoWrite`/`DoRead`
are `SSL_write`/`SSL_read` against an `SSL_CTX` from a `SecureContext`, plus
`SSL_do_handshake`, the `SSL_get_error` retry machine, session resumption, SNI
callbacks, ALPN, OCSP and the session-ticket keys. `lib/internal/tls/wrap.js`
proxies **16** handle methods (`ref`, `unref`, `hasRef`, `open`, `bind`, `listen`,
`connect`, `bind6`, `connect6`, `getsockname`, `getpeername`, `setNoDelay`,
`setKeepAlive`, `setSimultaneousAccepts`, `setBlocking`, `setPendingInstances`) into
a live SSL object.

This is a TLS stack over OpenSSL and belongs to the crypto workstream. Starting it
elsewhere would produce a partial handle that fails deeper and less legibly than the
current honest "no implementation yet".

### The strict-equal tail — 151 files, and it is not an async cluster

`Expected values to be strictly equal` is a substring, not a cause. Classified by
reading each failure body on the post-#51 run:

| split | files |
| --- | --- |
| worker-gated | 1 |
| async-shaped (file name or failure text mentions async hooks / ALS) | **0** |
| something else | 150 |

The async-shaped count is zero because the four files that used to be here
(`test-async-hooks-promise-triggerid.js`, `test-async-hooks-promise.js`,
`test-async-hooks-top-level-clearimmediate.js`,
`test-async-hooks-recursive-stack-runInAsyncScope.js`) **pass** on this tree: #33
established the top-level async context. A previous version of this document argued
the long tail was mostly async propagation; that claim was measured false when the
bucket was read file by file, and the last four genuine members have since been
fixed. The tail is ordinary native-surface gaps that happen to end in a
`strictEqual`.

### `WorkerImpl` — 123 files

`worker_threads`. `rn-bind-worker` declares `Worker` deferred, and the reason holds:
it needs a second isolate, a cross-thread `MessagePort` transport, and the
worker-side bootstrap in `internal/main/worker_thread.js`. It is a subsystem, not a
namespace.

### timeouts — 114 files

A timeout is a failure: the process was killed and never stated a verdict. The
count is load-sensitive, so treat a file that changed outcome *and* timed out on
either side as noise until re-run alone. `--timeout` raises the per-file limit.

### `fs.cp` — 28 + 19 files, two separate bugs

| files | failure |
| --- | --- |
| 28 | `cpSyncCopyDir is not a function` — `-r` recursion is still declared deferred |
| 19 | `Method Promise.prototype.then called on incompatible receiver [object BigInt64Array]` in `fs/promises` |

The second is the best ratio in the tail: it needs no async knowledge, only that the
promise path stop receiving bigint stat arrays.

### `locks` — 13 files

`internalBinding('locks')` is unimplemented. Its consumer is the Web Locks API
(`navigator.locks`, reached through `internal/locks.js`), not
`--experimental-locks`; `--experimental-locks` warns separately and the four
`test-web-locks*` files fail on the binding.

### `--snapshot-blob` — 10 files

Startup snapshots. The flag is not in `rn-cli`'s accepted list, and accepting it
would need `rn-bind-mksnapshot`'s snapshot build path to work, so it is not a parser
tweak.

### `ReadFileJob` / `WriteFileJob` — 0 files, closed by #46

**Correction.** This document previously listed "17 + 12 files — `ReadFileJob` /
`getWasmCompileCacheEntry`" and said both were deferrals with reasons that still
held. Both halves were wrong.

`ReadFileJob` and `WriteFileJob` are now installed by #46 (`97c56e36`), so they are
no longer in `crates/rn-bind-fs/src/install.rs`'s `DEFERRED` list at all. Measured
on `8cf029b2f3dba530` (current `master`, post-#46): of the 57 files in
`test/parallel` that call `fs.readFile(`/`fs.writeFile(` in callback form, **0**
still fail with `ReadFileJob is not a constructor` or
`WriteFileJob is not a constructor`, down from 34 across the whole suite before it.

The old *reason* was false even before the fix. It said reads "go through
read/readv until batching is measured as needed", but `vendor/libnode-js/lib/fs.js`
is byte-identical to Node's (`sha256 ee9167e6…` in `vendor/libnode-js/LIBJS.sha256`)
and constructs `new ReadFileJob(path, flagsNumber, kReadFileBufferLength, true)`
unconditionally in the `buffer === undefined` branch. There was never a fallback
path, so callback `fs.readFile` threw
`TypeError: ReadFileJob is not a constructor` — it did not read through `readv`.
Reproduce against a pre-#46 binary:

```
$ ./rustnode -e "require('fs').readFile('/etc/hostname',()=>{})"
Uncaught TypeError: ReadFileJob is not a constructor
```

`getWasmCompileCacheEntry` is still deferred, with a reason that is checkable rather
than aspirational: both it and `saveWasmCompileCacheEntry` need V8 APIs the linked
`v8` crate does not expose (`v8::WasmModuleCompilation` with a module-caching
callback, and `v8::WasmModuleObject::CompiledModule::Serialize()`). Its file count is
**not** measured here; the "12" the old text carried came from the superseded
baseline and is not reproduced.

### `zstd` — closed, and the level 4-6 divergence is recorded the other way round

Both throws that lived in `rn-bind-zlib/src/handle.rs` are gone; `zstdCompressSync`
and `createZstdCompress` are functions. Why the output can be byte-identical:
`cargo tree` shows `zstd-sys 2.0.17+zstd.1.5.7`, and Node's `deps/zstd/lib/zstd.h`
at the pin defines `ZSTD_VERSION_RELEASE 7` with major/minor 1.5 — the same
compressor at the same version.

**Correction to the previous text**, which said `deflate` at levels 4-6 gives
rustnode a ratio of 79 where Node reaches 60. Measured on the 4000-byte
alphabet-cycle payload, it is the reverse: rustnode produces **79 bytes** where Node
produces **60** (`deflateSync`, levels 4 and 6). `docs/compat-status.md` carries the
same inverted table and needs the same correction; it is out of scope here.

### `--permission` — model enforced for four scopes, flag still warns

The permission *model* is no longer absent: `fs` read, `fs` write, `child` and `env`
are enforced.

```
$ ./rustnode --permission -e "try{require('fs').readFileSync('/etc/passwd')}catch(e){console.log(e.code)}"
ERR_ACCESS_DENIED
$ ./rustnode --permission --allow-fs-read=/etc/passwd -e "console.log(require('fs').readFileSync('/etc/passwd','utf8').length)"
1069
```

The flag still appears on the `UNIMPLEMENTED` warning list, and that warning is
honest, because six scopes remain unenforced: `net`, `worker`, `addon`, `wasi`,
`inspector`, `ffi`. Passing the flag only to tests that do not need enforcement
would weaken a check, so do not do that. A per-scope file count is not measured
here.

### `block_list` — closed

`BlockList`, `SocketAddress`, `AF_INET` and `AF_INET6` are implemented in
`crates/rn-bind-block-list`, and the contract check reports the namespace `ok`. The
remaining `test-*blocklist*` failures point elsewhere: `test-blocklist-fast-api.js`
needs `internalBinding('debug')`, `test-tls-spki-blocklist.js` needs `tls_wrap`, and
`test-blocklist-clone.js` needs the `kClone`/`kDeserialize` host-object round trip.

### Deferred asymmetric crypto

`isNativeKeyObject`, `RsaKeyPairGenJob`, `KeyObjectHandle`, `EcKeyPairGenJob`,
`_DiffieHellmanGroup` and `NamedKeyPairGenJob` all read `undefined` from `require('crypto')`
today, so this surface is still absent. It belongs with `tls_wrap` in the crypto
workstream. **The "~110 files" the previous text gave is not reproduced**: that
figure came from the superseded baseline and counting it properly needs a per-member
signature match this document has not run.

## Claims removed from this document

Each of these appeared in an earlier version and did not survive checking. They are
recorded here so they are not reintroduced from memory.

| removed claim | why |
| --- | --- |
| "the strict-equal tail is mostly async propagation" | 144 files read individually: 4 async, 1 worker-gated, 139 other. Now 0 async, because #33 fixed the last four. |
| "`ReadFileJob`/`WriteFileJob` deferral reasons still hold" | They are not deferred any more (#46), and the stated reason was never true: `lib/fs.js` calls them unconditionally. |
| "a strict-equal `AbortSignal` file" | None. `test-abortsignal-cloneable.js` prints three `✖` subtests and then hangs to the 30 s timeout; it is a hang, not a `strictEqual`. |
| "a strict-equal `AsyncLocalStorage` file" | None. The four ALS failures are 2 timeouts (`http-agent`, `http-multiclients`), `_queryObjects is not a function`, and `assert.ok(storeGCed)` — no `strictEqual` among them. |
| "a `structuredClone` transfer-list failure" | No file fails on `structuredClone` with a transfer list as its recorded reason. The two files that print `Found invalid value in transferList` are `test-webstreams-clone-unref.js` and `test-whatwg-webstreams-transfer.js`, which exercise the Web Streams transfer path, not `structuredClone`. `test-structuredClone-global.js` fails with `Missing expected exception` and `test-structuredClone-domexception.js` passes. |
| "638 files — `tls_wrap`" | 640 on the post-#51 run. The old number is not wrong by much, but it was counted against a superseded baseline, so it is replaced rather than carried. |
| "148 files — strict equal" | 151 on the post-#51 run at eight-suite scope, 132 of them in `test/parallel`. |
| "116 files — `WorkerImpl`" | 123 on the post-#51 run. |
| "85 / 94 files — timeouts" | 114 on the post-#51 run. The old figures were load- and binary-dependent. |
| "17 + 12 files — `ReadFileJob` / `getWasmCompileCacheEntry`" | `ReadFileJob` is 0 after #46; the wasm-cache count is unmeasured, for the reason above. |
| "~110 files — deferred asymmetric crypto" | Unmeasured; see above. |
| "27 files — `--snapshot-blob`" | 10 on the post-#51 run. The old "27" counted files *mentioning* the flag (33 files across `test/**` mention `snapshot-blob`, and 29 are `test-snapshot-*`), but only 10 fail because the option was refused. |
| "12 files — `locks`" | 13 on the post-#51 run, and the consumer is the Web Locks API, not `--experimental-locks`. |
| "`--experimental-stream-iter` / `--allow-natives-syntax` were removed from the unimplemented list" | Verified: neither warns. `--experimental-vm-modules`, `--experimental-quic`, `--permission` and `--experimental-locks` still do. |
| "`deps_files` moved 1 → 3" | Verified by `./tools/verify-libjs.sh`: `435 lib files, 3 deps files`. |
| "everything is committed on `node-test-tail` and fast-forwarded to `origin/rustnode/main`" | No such branch exists, and `origin/rustnode/main` is at `8b7c43b7`, not at the text's tree. Removed rather than restated. |

## Other numbers this document does not quote

* **A per-cluster pass rate.** `rn-harness report` groups by the first name segment
  (`test-fs-open.js` → `fs`), which mixes suites and hides skips. Every rate quoted
  here is either whole-suite or a named family counted from the recorded run.
* **A "fixed" count for a merge.** The old text attributed 66 fail → pass to five
  PRs by matching failure text. That kind of attribution needs the same binary for
  both sides; none is reproduced here.
* **A before/after for the 120-file sample.** That sample was the alphabetically
  first 120 files of `test/parallel` (83 `test-a*`, 30 `test-bench*`, no
  `child_process`, no `fs-cp`), so it was never representative and its 58 → 74
  movement was measured under the exit-code-only rule.

## Reproducing any row

```bash
cd rustnode
export RUSTUP_TOOLCHAIN=1.96.1 CXX=g++ RUSTFLAGS="-L /usr/lib/gcc/x86_64-linux-gnu/13"

# the pinned Node tree, as a full 40-character SHA (not a branch)
git init /tmp/node-pin && cd /tmp/node-pin
git remote add origin https://github.com/nodejs/node
git fetch --depth 1 origin f344e7f552e3656bd37517151c5dc87d22b33771
git checkout FETCH_HEAD && git sparse-checkout set test && cd -

# a binary frozen before the run, so a later build cannot contaminate it
touch crates/rn-cli/src/main.rs
cargo build -p rn-cli
cp target/debug/rustnode /tmp/frozen/rustnode && chmod 755 /tmp/frozen/rustnode
sha256sum /tmp/frozen/rustnode && stat -c '%y' /tmp/frozen/rustnode

# measure, then size the families
python3 tools/test-tail-map.py run --node /tmp/frozen/rustnode \
    --tests /tmp/node-pin/test --out /tmp/full.json --jobs 8 --timeout 30
python3 tools/test-tail-map.py score /tmp/full.json
python3 tools/test-tail-map.py score /tmp/full.json --family tls_wrap --list
```

`./tools/check.sh --quick` is the gate; `--quick` skips only the workspace test
sweep. There is no `GATE` variable in this repository.
