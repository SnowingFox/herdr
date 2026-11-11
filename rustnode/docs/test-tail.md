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

**The headline finding, which overturns a premise this project has been working
from:** the `AssertionError: … strictly equal` tail is **not** an async-propagation
cluster, and it has **zero** async members today. See the next section.

## The headline finding: the async tail is not async

A previous version of this document, and the work plan built on it, assumed the
long tail of `AssertionError: … strictly equal` failures was mostly async
propagation. **It is not, and the count is now zero.**

Reading the strict-equal failures one by one, on the latest full run:

| tree | strict-equal files | worker-gated | async-shaped | other |
| --- | --- | --- | --- | --- |
| `52f79555` (#51) | 151 | 1 | **0** | 150 |
| `368e32ac` | 196 | 0 | **0** | 196 |

The four files that did belong to async propagation
(`test-async-hooks-promise-triggerid.js`, `test-async-hooks-promise.js`,
`test-async-hooks-top-level-clearimmediate.js`,
`test-async-hooks-recursive-stack-runInAsyncScope.js`) all **pass** today, because
#33 established the top-level async context.

This matters beyond the count: it means the tail cannot be closed by an
async-plumbing workstream. Every member is an ordinary native-surface gap that
happens to end in a `strictEqual`, and the largest single family inside it needs no
async knowledge at all. Any plan that treats this bucket as one cluster is planning
against a premise that was measured false.

## Pass-rate provenance

Every full-suite figure this project has published, with what it actually measured.
Read the **scoring rule** column before comparing any two rows; several pairs differ
by both scope and rule, and the differences do not add up.

| figure | commit | suite scope | scoring rule | verdict |
| --- | --- | --- | --- | --- |
| 2803/5666 (49.5%) | pre-`8b7c43b7` baseline | 7 suites, 5666 files | exit-code only | **superseded** — optimistic by both defect classes below |
| 3733/5666 (65.9%) | `27d67077` | 7 suites, 5666 files | exit-code only | **superseded** |
| 3735/5666 (65.9%) | `27d67077` re-run | 7 suites, 5666 files | exit-code only | **superseded** — the two-file delta from the row above is run noise |
| 3799/5666 (67.0%) | `8b7c43b7` | 7 suites, 5666 files | exit-code only | **superseded** |
| 2982/5666 (52.6%) | `8b7c43b7` | 7 suites, 5666 files | skip-aware | **superseded** — correct for skip counting, still scored on exit codes, so it still contains the #51 false passes |
| 3197/5159 (62.0%) | `52f79555` area | `test/parallel` only | exit-code only | **superseded** — counts 761 skips as passes and cannot see `node:test` failures |
| 3491/5159 (67.7%) | `7af7b306` | `test/parallel` only | exit-code only | **superseded** — pre-#51 |
| 3097/5159 (60.0%) | `52f79555` (#51) | `test/parallel` only | exit-code only | **superseded** — post-#51, still counts skips |
| 2855/5714 (50.0%) | `7af7b306` (pre-#51) | 8 suites, 5714 files | four-marker | **measured here** |
| 2572/5714 (45.0%) | `52f79555` (#51) | 8 suites, 5714 files | four-marker | **measured here** |
| **2732/5714 (47.8%)** | **`368e32ac`** | **8 suites, 5714 files** | **four-marker** | **headline — quote this one** |
| 2645/5159 (51.3%) | `7af7b306` (pre-#51) | `test/parallel` only | four-marker | **measured here** |
| 2393/5159 (46.4%) | `52f79555` (#51) | `test/parallel` only | four-marker | **measured here** — the honest `test/parallel` rate for that tree |
| 2550/5159 (49.4%) | `368e32ac` | `test/parallel` only | four-marker | **measured here** — the `test/parallel` rate `docs/project-context.md` quotes |
| 2549/5159 (49.4%) | `f0649774` | `test/parallel` only | four-marker | **measured here** — matches the eight-suite row below it |

The eight-suite and `test/parallel` rows are different measurements, and **neither
is a time series**: the trees differ by merges as well as by scope. Read them as
independent measurements of different trees, not as movement.

The two `49.4%` rows are the ones to compare against the `test/parallel` exit-code
rates above them, because those share a scope. The `47.8%` eight-suite row is the
headline because that is the scope with a complete run over every suite the harness
selects. **47.8% versus 49.4% is a scope difference, not movement.**

**Do not subtract across scopes, which is what produces a spurious residual.** The
`test/parallel` and eight-suite skip populations are different numbers — 761 vs 808
on the `52f79555` tree, 471 vs 485 on the later two — and mixing one into the other
leaves a handful of files that look like rounding but are not. (The `test/parallel`
figure counts the exit-0 skips the decomposition subtracts; one further file,
`parallel/test-worker-process-cwd.js`, carries a skip marker and exits non-zero, so
it is already outside the exit-0 count.) See the decomposition below, which closes
exactly when both sides come from the same run.

### Why 52.6% is superseded

Two defects made the harness grade failures as passes, and they are independent:

1. **Skips counted as passes.** `common.skip()` prints `1..0 # Skipped:` and calls
   `process.exit(0)`, and `rn-harness` records `passed = !timed_out && exit_code == 0`.
   Measured on the pre-#51 run below: 824 of its 3870 exit-0 files skipped, and 825
   files carry a skip marker in total (the extra one is a `known_issues` skip that
   exits 1).
2. **`node:test` failures counted as passes.** Before #51, `beforeExit` was never
   emitted, so `internal/test_runner/harness.js` never finalised the root test, so
   `test:summary` never ran and the process never set `process.exitCode`. A file
   whose subtests failed printed the failures and exited **0**. Reproduce on a
   pre-#51 binary:

   ```
   $ /tmp/frozen-pre51/rustnode -e "const {test}=require('node:test');test('f',()=>{throw new Error('x')})"
   ...  # prints the failure, no "tests N" summary
   $ echo $?
   0
   ```

   On a #51 binary the same command exits 1. 340 files in the suite import
   `node:test`.

**#51 merged at 11:11:55Z on 2026-11-11**, so both defects are now fixable rather
than pending, and the figure below is measured on a tree that contains the fix
(`368e32ac`, via the `2fc0b17f` merge). It is still scored with the four-marker
rule, because the harness on `master` does not yet count skips.

### The two instruments agree once the skip set is removed

`rn-harness` and `tools/test-tail-map.py` looked like they disagreed. They do not.
The whole difference is the skip set, and it closes exactly.

`rn-harness` scores `passed = !timed_out && exit_code == Some(0)` and **never reads
stdout for the verdict** (`tools/harness/src/runner.rs:271`); `stdout_head` exists
only for the human-readable failure reason. So a file that skips cannot be
distinguished from a file that passed, and the difference between the two rules is
exactly the set of files that exited 0, carried no failure marker, and printed a
skip line.

On the same run of the same tree, the decomposition is exact:

| tree | exit-0 | − skip markers | − `✖`/`Uncaught` | = four-marker pass | residual |
| --- | --- | --- | --- | --- | --- |
| `52f79555` (#51) | 3218 | −761 | −64 | **2393** | **0** |
| `368e32ac` | 3082 | −471 | −61 | **2550** | **0** |

(Both rows are `test/parallel` scope. The eight-suite total is
2732/5714, which is a different scope and is not comparable row-for-row with these.)

A four-file residual appears if the numbers are combined across scopes: 3197 − 808 =
2389 is one measurement's `test/parallel` exit-0 count minus the **eight-suite** skip
population, and 808 vs 761 is that scope difference (plus a 30 s vs 60 s timeout
difference in the exit-0 readings). Subtracting one scope's skips from another
scope's count leaves a few files over; at a single scope the closure is exact, as the
table shows.

Do not reopen this: the two rules differ by the skip set and nothing else.

The `stdout_head` cap is **not** an explanation for any of this. It is real — a
marker past 2 KiB is invisible to anything reading only the head — but the harness
does not read the head for its verdict, so the cap cannot move its count in either
direction. It affects only what a human sees when reading a failure reason.

### Why a sample of this suite misleads, and the general rule

Skips are **clustered by family**, not spread through the suite. On the
latest full run, 485 of 5714 files skip (8.5%), and they are not evenly
distributed:

| skip reason | files | share |
| --- | --- | --- |
| `QUIC is not enabled` | 270 | 55.7% |
| `DTLS is not enabled` | 54 | 11.1% |
| `missing ESLint` | 32 | 6.6% |
| `missing SQLite` | 31 | 6.4% |
| `Requires Amaro` | 12 | 2.5% |
| OpenSSL build/feature gates | 14 | 2.9% |
| Windows-only tests | 7 | 1.4% |
| addon not built / trace events | 6 | 1.2% |

**324 of the 485 (66.8%) are in the first two families**, and the single largest is
QUIC at 270 — a contiguous block of `test-quic-*.mjs` files that sit together in
sorted order. On the #51 tree the same measure was starker still: 617 of 761 skips
(81%) in three families, the largest run being 262 consecutive QUIC files.

The inspector family is the best illustration of why this matters: it was **329
skips** on `52f79555` and **0** on `368e32ac`, because the inspector namespace
landed. One merge removed 40% of the skip population. A sample drawn before that
merge from anywhere other than the `repl`/`debugger`/`inspector` block would have
missed all 329.

The consequence: **any sample that does not deliberately include a clustered family
will understate the inflation by a large factor.** On the #51 tree, a 60-file sample
drawn uniformly at random expected about 9 skips (mean 8.81 over 20,000 draws;
drawing 1 or fewer has probability 0.08%). A sample that happens to miss the QUIC
and inspector blocks reports almost no inflation, while the suite carries 485–808
skips.

This is the general form of the warning about alphabetical samples below. That
sample was unrepresentative because `test-a*` contains no `child_process`, `tls`,
`fs.cp` or `worker` files. The general rule is stronger: **every family in this
document is clustered, so a subset measures the subset, not the suite. Quote a
whole-suite count or name the family and count it exhaustively.**

### Provenance of the three runs measured for this document

All three used the same pinned Node tree, the same tool, a binary frozen before the
run, and the same command. The first two differ only by #51.

| | pre-#51 | #51 branch | latest full run |
| --- | --- | --- | --- |
| commit | `7af7b306` | `52f79555` (`origin/cursor/exit-and-test-status`) | `368e32ac` |
| contains | #33, #46; **not** #51 | #33, #46, #51 | #51 merged via `2fc0b17f`, plus later merges |
| binary | `/tmp/frozen-pre51/rustnode` | `/tmp/frozen-pr51/rustnode` | `/tmp/frozen-newmaster/rustnode` |
| sha256 (16) | `c4ff9845a0b34faf` | `d8c0d9cd691cfd07` | `3c50d5e7e04da6ab` |
| binary mtime (UTC) | 2026-11-11T10:10:26 | 2026-11-11T10:08:43 | 2026-11-11T11:32:30 |
| Node tree | `f344e7f552e3656bd37517151c5dc87d22b33771` | same | same |
| command | `tools/test-tail-map.py run --node <binary> --tests /tmp/node-pin/test --jobs 8 --timeout 30` | same | same |
| exit-0 files | 3898 (68.2%) | 3454 (60.4%) | 3282 (57.4%) |
| four-marker passes | **2855 (50.0%)** | **2572 (45.0%)** | **2732 (47.8%)** |
| skipped | 808 | 808 | 485 |
| failing | 2051 | 2334 | 2497 |

The latest full run is the one to quote. It is not an extrapolation from the
other two: it was measured on that commit with a binary built from it.

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

So a `tools/test-tail-map.py` pass on a **pre-#51** binary means only "exited 0 and
said nothing that looks like failure". It does not mean the assertions ran.

On a **#51-or-later** binary the exit code carries the verdict, so the rule has much
less room to be wrong — but it is still a rule about output, not a proof. 2141 of the
2732 passes (78%) print nothing at all, which is normal for a passing test and also
indistinguishable from a test that silently did nothing.

**That specific risk is measured, and it is small.** `tools/mustcall-sample.py`
instruments every `common.mustCall*` registration and every invocation of the
function it wraps, so it answers the question directly — no reference runtime
needed. Sampled from the passing set:

| sample | files with a registration | contaminated | Wilson 95% |
| --- | --- | --- | --- |
| seed 7, 20 files | 17 | **0** | 0.0% – 18.4% |
| seed 11, 60 files | 51 | **0** | 0.0% – 7.0% |
| seed 11, 200 files | 165 | **0** (3 runs) | 0.0% – 2.3% |

Reproduce the widest one:

```
python3 tools/mustcall-sample.py --results <dir with run-*.json> \
    --tests /tmp/node-pin/test --node-binary <binary> --limit 200 --seed 11
```

"Contaminated" means a file that passes while an assertion it registered never ran.
Zero in 165 files bounds that class below ~2.3% of `mustCall`-carrying passes.

**Treat this as a rate, not a per-file verdict.** One intermediate run of the same
200-file sample reported **1** contaminated file (7 unsatisfied assertions in
`parallel/test-cluster-concurrent-disconnect.js`), and three subsequent runs of the
identical command reported 0. A test whose async work sometimes finishes after the
`exit` handler will flip. Quote the bound, not the list.

This does **not** make the rule sound for every file — a file with no `mustCall`
registration and no output is still unaccounted for — so the pass figures remain an
upper bound. But the largest specific mechanism by which they could be inflated is
bounded at a few per cent, which is stronger than the earlier "cannot be checked on
this machine": that was true only before the tool existed.

(The cross-check against a reference runtime is still worth nothing here: the pin is
Node 28 and the only `node` on this machine is v22.23.4, which fails several pinned
files for v22's own reasons. That is why the tool reports the two answers separately
and only `unsatisfied` counts.)

## Sizing, with provenance per row

All rows below are from the **latest full run** (binary `3c50d5e7e04da6ab`,
commit `368e32ac`, 5714 files, 2497 failing) unless the row says otherwise. A row
marked *counted* was sized by matching a failure signature in the recorded output
of that run; a row marked *run* was re-run on the binary it names. Sizes are
distinct files and overlap, so they are not additive.

| files | family | provenance |
| --- | --- | --- |
| 646 | `internalBinding('tls_wrap')` has no implementation | counted |
| 196 | `AssertionError: … strictly equal`, no single cause | counted |
| 187 | timeouts | counted |
| 28 | `fsBinding.cpSyncCopyDir is not a function` | counted |
| 17 | `internalBinding('locks')` has no implementation | counted |
| 11 | `unsupported option '--snapshot-blob'` | counted |
| ~~123~~ 0 | `WorkerImpl is not a constructor` | counted — **closed** between #51 and `368e32ac` |
| ~~19~~ 0 | `fs.cp` `then()` on a `BigInt64Array` stat result | counted — **closed** |
| ~~0~~ 0 | `ReadFileJob` / `WriteFileJob` | **run** — closed by #46, still 0 |

The two closed rows are the most useful thing in this table: they show the map is
tracking a moving tree rather than describing a fixed one. Both are verified by
direct execution on `368e32ac`, not just by the absence of a signature:

```
$ ./rustnode -e "const {Worker}=require('worker_threads');const w=new Worker('console.log(1)',{eval:true});w.on('exit',c=>console.log('exit',c))"
1
exit 0
$ ./rustnode -e "require('fs/promises').cp('/etc/hostname','/tmp/x',{recursive:true}).then(()=>console.log('cp ok'))"
cp ok
```

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

### The strict-equal tail — 196 files, and it is not an async cluster

`Expected values to be strictly equal` is a substring, not a cause. Classified by
reading each failure body on the latest full run:

| split | files |
| --- | --- |
| worker-gated | 0 |
| async-shaped (file name or failure text mentions async hooks / ALS) | **0** |
| something else | 196 |

The four files that used to be here
(`test-async-hooks-promise-triggerid.js`, `test-async-hooks-promise.js`,
`test-async-hooks-top-level-clearimmediate.js`,
`test-async-hooks-recursive-stack-runInAsyncScope.js`) **pass**: #33 established the
top-level async context. A previous version of this document argued the long tail
was mostly async propagation; that claim was measured false when the bucket was read
file by file, and the last four genuine members have since been fixed. The tail is
ordinary native-surface gaps that happen to end in a `strictEqual`.

The bucket grew from 151 to 196 as #51 and later merges made previously silent
failures visible, which is the direction the scoring fix works in.

### `WorkerImpl` — closed, was 123 files

`worker_threads` now works. `rn-bind-worker` no longer declares `Worker` deferred,
and a real worker starts, runs and exits 0 (command in the sizing table above). This
was the second-largest family in the previous version of this document; it went to
zero between `52f79555` and `368e32ac`.

### timeouts — 187 files

A timeout is a failure: the process was killed and never stated a verdict. The
count is load-sensitive, so treat a file that changed outcome *and* timed out on
either side as noise until re-run alone. `--timeout` raises the per-file limit.

The count rose from 114 to 187, which is the `node:test` fix at work: a file that
used to exit 0 while its subtests failed now sometimes hangs instead of exiting,
and a hang is now recorded as a failure rather than a pass.

### `fs.cp` — 28 files left, from two bugs to one

| files | failure |
| --- | --- |
| 28 | `cpSyncCopyDir is not a function` — `-r` recursion is still declared deferred |

The other bug — `Method Promise.prototype.then called on incompatible receiver
[object BigInt64Array]` in `fs/promises`, 19 files — is **closed**, verified by
running `fs/promises.cp` successfully on `368e32ac`. That one needed no async
knowledge, only that the promise path stop receiving bigint stat arrays, which is
why it was flagged here as the best ratio in the tail.

### `locks` — 17 files

`internalBinding('locks')` is unimplemented. Its consumer is the Web Locks API
(`navigator.locks`, reached through `internal/locks.js`), not
`--experimental-locks`; `--experimental-locks` warns separately and the
`test-web-locks*` files fail on the binding.

### `--snapshot-blob` — 11 files

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
| "638 files — `tls_wrap`" | 646 on the latest full run. The old number was counted against a superseded baseline, so it is replaced rather than carried. |
| "148 files — strict equal" | 196 on the latest full run (151 on the #51 tree). The bucket grows as real failures stop being hidden. |
| "116 files — `WorkerImpl`" | 123 on the #51 tree, **0 on `368e32ac`** — `worker_threads` works; see the closed-family rows above. |
| "85 / 94 files — timeouts" | 187 on the latest full run. The old figures were load-, binary- and rule-dependent. |
| "17 + 12 files — `ReadFileJob` / `getWasmCompileCacheEntry`" | `ReadFileJob` is 0 after #46; the wasm-cache count is unmeasured, for the reason above. |
| "~110 files — deferred asymmetric crypto" | Unmeasured; see above. |
| "27 files — `--snapshot-blob`" | 11 on the latest full run. The old "27" counted files *mentioning* the flag, but only 11 fail because the option was refused. |
| "12 files — `locks`" | 17 on the latest full run, and the consumer is the Web Locks API, not `--experimental-locks`. |
| "20 files — `zstd is not implemented`" | 0: closed by #21. See the zstd section. |
| "fs.cp `then()` on a `BigInt64Array` — 19 files" | 0 on `368e32ac`: `fs/promises.cp` works. Verified by running it. |
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
