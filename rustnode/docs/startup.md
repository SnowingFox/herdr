# Startup: what was measured, what changed

Reference point: `tools/bench.py --samples 40`, release build, before any change.

```text
case                         node   rustnode  node/rust
empty                      16.58ms     39.80ms      0.42x
require('fs')              17.74ms     42.32ms      0.42x
peak RSS           node 41.8 MiB   rustnode 50.6 MiB
200k native calls  node 3.91ms      rustnode 1.32ms
```

## Where the 44 ms went

`perf` and `strace` are not installed on this image and there is no root, so the
breakdown came from phase timers compiled into the CLI (`RN_PROFILE_PHASES`) and
a per-builtin timer in `rn-builtins`. Median of repeated runs of `-e ''`:

| phase | cumulative | delta |
| --- | --- | --- |
| entry | 0.00 ms | — |
| tracing init | 0.05 ms | 0.05 |
| binding registry + Env | 0.40 ms | 0.35 |
| `new_default_platform` | 0.58 ms | 0.18 |
| `initialize_platform` | 0.63 ms | 0.05 |
| `V8::initialize` | 1.04 ms | 0.41 |
| `Isolate::new` | 2.39 ms | 1.35 |
| `Context::new` | 2.88 ms | 0.49 |
| `install_globals` (bootstrap.js) | 3.18 ms | 0.30 |
| primordials | 5.80 ms | 2.62 |
| realm.js executed | 15.62 ms | 9.82 |
| wrap require | 15.66 ms | 0.04 |
| install_early_globals | 26.62 ms | 10.96 |
| install_cjs_loader | 32.33 ms | 5.71 |
| RuntimeHooks::install | 33.85 ms | 1.52 |
| install_stdio | 34.64 ms | 0.79 |
| prepare_execution | 36.42 ms | 1.78 |
| user script | 36.56 ms | 0.14 |

So process start to `main` is ~1.9 ms, V8 bring-up is ~3 ms, and **~33 ms is
JavaScript bootstrap**. The brief's hypothesis — "V8 platform/isolate
initialisation" — is the small part. Module *compilation* is the large part.

Two measurements inside that block:

**65 builtins compiled, 17.3 ms.** Every one is a fresh compile in every
process: `rn-builtins::compile` went straight to
`ScriptCompiler::CompileFunction` with no cache.

**`natives` cost 4.1–4.6 ms.** `internalBinding('builtins')` eagerly built the
`{ id: source }` table over all 436 builtins — 1.25 MB of V8 strings — and
`realm.js` never reads it. `builtinCategories` (two more 436-element arrays) is
equally unread at startup. Node builds `natives` lazily through
`process.binding('natives')`.

## What changed

### 1. `natives` and `builtinCategories` are lazy (measured −2.2 ms, −12 MiB)

`rn-builtins` installs both as accessors. The first read builds the value and
caches it in a per-isolate Rust slot; later reads take the same path, so
callers cannot observe a difference. A self-replacing accessor was tried first
and re-enters itself through `define_own_property`, so the cache lives outside
the object.

`natives` still returns all 436 sources, with the same identity across reads.
Nothing is removed, so the member list still matches `contracts/builtins.json`.

### 2. Builtins boot from a build-time code cache (measured −13 ms)

`crates/rn-builtin-codegen` owns the one implementation of "compile this
builtin": it applies the kind's wrapper parameters and consumes a cache when
given one. Two callers share it — the runtime, and `rn-builtins`' build script,
which compiles the 65 startup builtins ahead of time and writes their
`create_code_cache()` blobs into `OUT_DIR`.

Measured on the same 65 builtins:

| | total |
| --- | --- |
| compile from source | 18.98 ms |
| consume code cache | 0.34 ms |

65 of 65 consumed, 0 rejected. The table is 554 KiB of blobs.

A cache is only valid for the V8 build and flags that produced it. Three things
keep that honest:

- the build script calls `rn_builtin_codegen::set_runtime_flags()`, the same
  pre-init flags `main` uses — V8's cache version tag covers flags, and a
  generator that omitted `--no-freeze-flags-after-init` produced blobs V8
  rejected for every builtin;
- V8 validates each blob and rejects a stale one rather than using it, so a
  mismatch costs time, not correctness;
- `a_generated_cache_is_consumed_rather_than_rejected` in `rn-builtins` asserts
  a build's own table is accepted, and `every_planned_builtin_has_a_generated_cache`
  asserts the table and the plan agree.

`cache_plan.rs` lists the 65. It was taken from a real startup rather than read
off `lib/**`, and the test above keeps it matching. A builtin missing from it
still works — it compiles from source, as before.

## Result

`tools/bench.py` cannot interleave runs, and this machine is noisy enough that a
baseline and an after run minutes apart disagree. So the headline number is a
paired measurement: both binaries built from the same tree, 60 runs each,
shuffled together with node's runs in one batch.

| binary | median | min | p25 |
| --- | --- | --- | --- |
| before (22 ms of source compile per start) | 43.38 ms | 40.67 ms | 42.34 ms |
| after | 22.98 ms | 21.72 ms | 22.46 ms |
| node | 19.23 ms | 16.95 ms | 18.43 ms |

**Startup 43.4 → 23.0 ms, 1.89x faster.** Against node that is 0.44x → 0.84x.

> **Historical figure.** Both the 23.0 ms and the 0.84x above measure *this cache
> change at this tree*. `#26` (worker_threads) later added ~5 ms to startup, and
> current `master` is ~0.76x against node, not 0.84x. See the section further
> down titled "The `#26` startup regression: 251 scans became 251 scans plus 251
> allocations" for the mechanism and the current measurement. The table and the
> comparison above are left as measured; they are a real record of the cache
> work, not a statement about today.

`tools/bench.py --samples 40`, one such run:

```text
case                         node   rustnode  node/rust
empty                      20.05ms     24.67ms      0.81x
require('fs')              19.77ms     25.49ms      0.78x
peak RSS           node 42.2 MiB   rustnode 38.7 MiB
200k native calls  node 4.36ms      rustnode 1.44ms
```

Peak RSS 50.6 → 38.7 MiB. Native calls are unchanged by this work and stay
about 3x faster than node.

## What is left

After the cache the same profile reads: V8 bring-up 2.4 ms, `Isolate::new`
+`Context::new` 2.4 ms, and ~15 ms of module *execution* — the top entries being
`internal/encoding` 2.7 ms, `internal/modules/cjs/loader` 1.4 ms, `internal/url`
0.8 ms, `internal/event_target` 0.8 ms, and 3.7 ms still compiling the handful of
builtins the plan does not cover.

The structural fix beyond this is a V8 startup snapshot: build primordials, the
realm bootstrap and the builtin table once, then `Context::from_snapshot`. The
`v8` crate exposes `Isolate::snapshot_creator`, `SnapshotCreator::set_default_context`
and `Context::from_snapshot` for this. It is the same shape as the code cache —
one artefact produced at build time, consumed per process — but it covers module
*execution* as well as compilation, which is the remaining 15 ms. It is a larger
change than the cache because the snapshot has to reproduce the exact isolate
state `main` builds by hand (platform, flags, isolate callbacks, microtask
policy), and because the builtin table and `hook_slot`'s thread-locals would have
to survive serialisation. The code cache landed first because it removes the
larger, better-isolated share of the cost with no change to bootstrap order.

Note that the figures in this section are from the cache work at its own tree.
The regression section below describes a ~5 ms cost added afterwards, so the
"remaining 15 ms" here is not the current split; re-run the phase report for
that.

### What a snapshot is now worth, and why it still cannot be built

Node's own control prices the lever: `node --no-node-snapshot -e 'void 0'` is
**46.40 ms against 18.52 ms** (median of 30, interleaved), so 27.9 ms of Node's
startup is work its snapshot removes. That is the whole gap to rustnode and more,
and it is the only lever here that is worth more than a couple of milliseconds.

`CLA-191`/`CLA-192` recorded this as blocked because a serializer-enabled
creator isolate has no `Float16Array`, so `primordials.js` throws before
anything can be serialised. That is still true of the intrinsic, but the wall is
narrower than "no snapshot is reachable", and both halves are now measured:

**The build gets past `primordials` if a stand-in is installed first.** Defining
`globalThis.Float16Array = class Float16Array extends Float32Array {}` in the
creator before running the vendored `primordials.js` completes it, and
`create_blob` then succeeds: a 527 KB blob from a realm carrying real
primordials. So the "cannot build at all" half of the blocker is a one-line
workaround in a build-only path, not a wall.

**The stand-in is why that is not a fix.** It survives the round trip and
`primordials.Float16Array` ends up bound to it, not to the intrinsic: after
`Context::from_snapshot`, `globalThis.__captured.BYTES_PER_ELEMENT` is **4**
(inherited from `Float32Array`) where the real intrinsic reports **2**. A
snapshot built this way would hand every `lib/**` module that destructures
`primordials.Float16Array` a constructor with the wrong element size, and nothing
would fail loudly until some code allocated one. That is a silent semantic error
in the shared library, so it is not shippable.

The honest remaining options, in order of cost:

1. Build the `v8` crate against V8 15.6, where `Float16Array` moved into
   `TYPED_ARRAYS_BASE` and a creator isolate has it. The newest published `v8`
   is 152.2.0 (V8 15.2), so this means a local v8 build.
2. Teach the build path to install the real intrinsic before `primordials.js`
   runs. A binding cannot synthesise it — `v8::Float16Array::new` needs the
   intrinsic to exist — so this is not a small patch either.

Until one of those lands, a snapshot is **not** reachable, and the correct
statement is "the blocker is a V8 version skew with a known workaround that is
not semantically safe", not "blocked with no path".


## The current phase budget (re-measured at `2d7ac642`)

The tables above record the code-cache work at its own tree. This one is a fresh
budget of the current startup, and it is the table to read before proposing a
startup change: it says where the 23-29 ms actually goes now, rather than where
it went when the cache landed.

Measured with `RN_PROFILE_PHASES=1`, release build, median of 60 runs, each run
in its own process, on an idle machine (load average 0.16-0.5, `cat /proc/loadavg`
recorded beside each batch). Deltas are the per-phase cost; cumulative is
measured from `main`. This is on `2d7ac642`, so it includes `install_bun` — but
see the note after the table, because that phase has grown a great deal since.

| phase | cumulative | delta | p25-p75 |
| --- | --- | --- | --- |
| tracing init | 0.03 | 0.03 | 0.03-0.04 |
| v8 link check | 0.04 | 0.01 | 0.01-0.01 |
| `uv_setup_args` | 0.05 | 0.01 | 0.01-0.01 |
| args parse + permission install | 0.10 | 0.05 | 0.04-0.06 |
| binding registry | 0.41 | 0.31 | 0.29-0.34 |
| `V8::initialize` | 1.03 | 0.62 | 0.58-0.67 |
| `Isolate::new` | 2.42 | 1.38 | 1.31-1.50 |
| `Context::new` | 2.83 | 0.42 | 0.39-0.44 |
| `install_globals` (bootstrap.js) | 3.17 | 0.34 | 0.32-0.36 |
| primordials | 6.77 | 3.56 | 3.34-4.11 |
| `realm.js` executed | 9.50 | 2.64 | 2.49-2.90 |
| **process source maps** | 14.14 | **4.55** | 4.29-4.81 |
| `install_bun` | 14.18 | **0.04** | 0.04-0.04 |
| install_early_globals | 18.01 | 3.82 | 3.73-4.02 |
| install_cjs_loader | 19.42 | 1.32 | 1.26-1.42 |
| install_stdio + console | 21.01 | 1.61 | 1.46-1.82 |
| prepare_execution | 22.75 | 1.33 | 1.24-1.96 |
| Runtime::install + eval builtins | 23.04 | 0.13 | 0.12-0.15 |
| push_top_level_context | 23.04 | 0.00 | — |
| user script | 23.05 | 0.01 | 0.01-0.01 |
| loop finished | 23.09 | 0.04 | 0.04-0.06 |

`install_bun` costs **0.04 ms** on this tree and it sits between
`process source maps` and `install_early_globals`.

### `install_bun` is 0.04 ms here and ~1.06 ms on current master

That difference is worth knowing before anyone budgets against 0.04. The number
above was measured at `2d7ac642`, which carried only `Bun.nanoseconds`; the
surface is now 78 members across seven crates, and one of them does measurable
work at startup. Measured by building each commit and taking a median of 9-15
runs of `-e '0'` per build:

| commit | `install_bun` | what it added |
| --- | --- | --- |
| `6f519a7a` | 0.04 ms | — (before any Bun crate) |
| `7da7d866` | 0.15 ms | the hashing crate |
| `7f457614` | 0.17 ms | the compression crate |
| `1d380cff` | 0.85 ms | the text crate |
| `fc0b6fe6` | 1.06 ms | plus files and process |

The text crate accounts for most of it, and the reason is concrete: it compiles
and runs an **8.5 KB JavaScript string** (`crates/rn-bun-text/src/streams.js`)
at every startup to build the seven `readableStreamTo*` helpers. That is a real
eager code compile in the startup path, not a table lookup.

The honest total was measured with an interleaved three-way batch (oracle, the
pre-Bun commit, current master, 40 runs of each in the same batch, load 4.8):
startup went **28.49 → 29.23 ms**, so the whole 78-member surface costs
**+0.74 ms, or 2.6%**, and against Node 1.34x → 1.37x.

That is a defensible price for the feature. The number in the table above is
simply not a budget for a surface that keeps growing: an eager 8.5 KB compile
will grow with the helpers. If startup becomes a target again, making those
helpers lazy — or compiling them through the builtin code cache the rest of the
runtime already uses — is the lever, and it is worth about 0.7 ms.

Three things this table changes about the older account:

**`process source maps` is the largest single phase, and it is one `require`.**
`install_process_source_maps` calls `require('internal/source_map/source_map_cache')`
to install two `process` accessors. That module reads `fs` at module scope, so
the load drags in `fs` (2.1 ms) and `buffer` (2.5 ms) — 4.4 ms of bootstrap for
two accessors that an empty script never calls. Node does not pay this: it ships
that module inside its startup snapshot.

**`realm.js` is no longer 9.8 ms.** The code cache plus `#26`'s fix moved it to
2.6 ms. `primordials` (3.4 ms) is now larger than `realm.js`.

**V8 bring-up is 2.8 ms of ~23 ms.** `V8::initialize` + `Isolate::new` +
`Context::new` is 2.8 ms; the JavaScript bootstrap is ~19 ms. Any proposal that
targets V8 initialisation is aiming at an eighth of the problem.

### What a first write costs, and why it is the biggest single number here

The budget above is a `void 0` budget, and `void 0` never touches stdio. A script
whose first act is to print pays a one-time cost that is larger than any single
bootstrap phase, and it lands in the `user script` row:

| phase budget, `-e 'console.log(1)'` | delta |
| --- | --- |
| `user script` (was 0.01 ms on `void 0`) | **7.09 ms** |
| every other phase | unchanged (max 4.55 ms) |

Interleaved wall clock agrees and puts the gap slightly higher, because wall time
also covers exec and teardown:

| | rustnode | node | rustnode delta | node delta |
| --- | --- | --- | --- | --- |
| `-e 'void 0'` | 26.32 | 21.85 | — | — |
| `-e 'console.log(1)'` | 35.45 | 24.52 | **+9.1 ms** | **+2.7 ms** |

Broken down in one process, it is a single lazy stream construction:

- `process.hrtime.bigint()` as the first statement: **0.001 ms**, same as Node
- that call followed by a `stderr.write`: **6.85 ms** against Node's 1.61 ms
- any write after an earlier write has warmed the stream: **0.016 ms**, against
  Node's 0.015 ms — identical

So the cost is the one-time construction of the stdio `Socket` behind
`process.stdout`/`process.stderr`. `getStdout()` builds it lazily in
`internal/bootstrap/switches/is_main_thread.js`, and it pulls in `net` and
`stream`; a cold `require('net')` here is 5.1-5.7 ms against Node's 0.74-0.94 ms.

**Pre-warming does not recover it.** `process.stderr.write('')` before the timed
work, then `console.log(1)`, measured 34.43-35.10 ms against 33.78 ms for the same
`console.log(1)` with no warm-up. The work moves, it does not disappear — the same
pattern as the deferred `source_map_cache` require recorded below. Winning here
means making the construction cheaper or sharing it with `install_stdio`, not
triggering it earlier.

**The apparent 5x cold-`require` deficit is this cost, not module loading.**
Requiring ten modules cold in separate processes — `net`, `stream`, `http`, `fs`,
`events`, `util`, `url`, `path`, `tty`, `string_decoder` — gives a flat
**4.7-5.2x** against Node with a constant **~5.2 ms** offset, including `path`,
which is a few hundred bytes and cannot cost 6 ms. Measuring three requires in
one process collapses it (`path` 0.758, then `url` 0.508, then `events` 0.014 ms).
A module-loading comparison taken from one `require` per process measures this
first-entry cost ten times and reports a loading problem that does not exist.

### The unmeasured 5 ms: process entry and dynamic loading

The table starts at `main`, and the wall clock does not. Median wall time for
`-e 'void 0'` is 26-28 ms against a last-mark of ~21.7 ms, and the gap is real
work that no in-process timer can see:

| segment | cost | how measured |
| --- | --- | --- |
| `fork` + `execve` + `ld.so` startup, before any Rust code | ~1.2 ms | a 440 KB Rust binary that only exits, same harness |
| relocation of rustnode's 95,333 `R_X86_64_RELATIVE` entries | ~0.2-0.4 ms | `LD_DEBUG=statistics`, 528k-374k cycles in the loader, 84-87% of it relocation |
| libc + V8 static initialisers, `.init_array` to `main` | ~0.1 ms | an `.init_array` constructor stamping `Instant::now()` |

Node's equivalent relocation count is 1,017, and its loader total is 327k
cycles. Packing the 95,333 relocations into a DT_RELR table
(`-Wl,-z,pack-relative-relocs`) collapses them to 23 KB, but measured against an
interleaved control it is **not a speedup**: 27.26 → 27.78 ms median at n=100 on
an idle box, and CPU time unchanged. The loader statistics exaggerate the cost
because `LD_DEBUG` timing includes its own accounting; wall clock is the
authority and it says relocation is not worth a linker flag.

### The null control has to be the same path, not just the same bytes

A null control on this box only works when both arms are the **same file path**.
Two byte-identical copies of the master binary, one in the build directory and one
in `/tmp`, measured 29.53 vs 30.48 ms at n=100 and then 29.61 vs 30.73 ms — a
reproducible **3.2-3.5%** gap that is placement, not the binary. Running the
*same* path under two labels gives 29.77 vs 29.73 ms (**0.1%**), and staging both
binaries in one directory gives 1.2%.

That 3.5% is larger than most changes anyone would propose here, and it points in
whichever direction the second path happens to be cold. Copying a candidate binary
somewhere convenient and comparing it against the original in its build tree is
exactly how a false 1.2x is manufactured; every comparison in this document puts
both arms in the same directory.

### Levers that were measured and did not help

Each of these was measured against an interleaved control in the same batch, on
an idle machine, at n=30-120, with both binaries in the same directory. The A/A
noise floor on this box — the same path under two labels, interleaved — is
**0.1%**; across two different directories it is **1.2-3.5%**, which is why
placement is controlled rather than assumed. Recording these because they are the
obvious ideas and each one would otherwise be tried again.

| lever | measured | verdict |
| --- | --- | --- |
| V8 `--single-threaded` | +59% | much worse; it forces a single-threaded platform |
| V8 `--no-opt`, `--lite-mode`, `--jitless` | +54-58% | much worse; the bootstrap needs the optimising tiers |
| V8 `--no-lazy` | +96% | much worse; eager compilation of everything |
| V8 `--no-compilation-cache` | +56% | confirms the builtin code cache is load-bearing |
| V8 `--no-expose-wasm`, `--predictable`, `--no-harmony` | +1.0 to +2.7% | neutral or worse |
| `--max-semi-space-size=1`, `--stress-scavenge=0` | -2.2 to -2.4% | inside the noise floor |
| `--no-concurrent-marking`, `--no-parallel-scavenge`, `--single-threaded-gc` | +1.3 to +2.8% | neutral or worse |
| platform thread pool 1/2/4 instead of auto | +9.5 to +11.3% | wrong direction; the pool is not the cost |
| deferring the `source_map_cache` require | -3.6 ms in its own phase, **+3.6% wall** | the cost moves to `install_early_globals`; net negative |
| DT_RELR packed relocations | 27.26 → 27.78 ms | inside noise, CPU unchanged |
| stripping 19 MB of symbols from the binary | 26.20 → 27.74 ms | inside noise |
| skipping the libuv threadpool drain at exit | +0.3 ms (worse) | teardown is not a cost |
| `_exit` to skip `atexit`/`.fini_array` | -0.19 ms | inside noise; teardown is not a cost |
| pre-warming `process.stderr` before `console.log(1)` | 34.43-35.10 vs 33.78 ms unwarmed | the stream cost moves, it does not go |
| `--cpu-prof` for attribution | rejected: `unsupported option '--cpu-prof'` | the CLI has no profiler flag, so attribution is by instrumented probes |

Two of these are worth understanding rather than just recording:

**Deferring `source_map_cache` moves work instead of removing it.** The phase
that loads it drops from 4.40 to 0.62 ms, and `install_early_globals` rises from
3.71 to 6.76 ms, because `internal/encoding` loads `internal/buffer` and the
`globalThis` walk in `install_web_globals` loads `internal/event_target`, so the
same modules are compiled slightly later. Process CPU time is
unchanged (30.5 vs 31.0 ms), and wall clock gets worse by 3.6%, once outside the
noise floor and reproducible across three batches. The lesson generalises: in
this bootstrap, a phase-table delta is not a saving until CPU time agrees.

**V8 flags now reach the CLI, but a sweep still has to check the exit status.**
`rn-cli` used to reject every V8 flag with `rustnode: unsupported option
'--no-opt'` before V8 saw it, so a flag sweep that passed the flag on the command
line measured a process that exited during argument parsing — 2.6 ms, an
apparent 89% win. The table above was taken by injecting the flag before
`V8::initialize` instead. V8 flags are now forwarded and V8 decides them, so
`--no-opt` on the command line measures the real thing; a flag V8 does not know
is still a `bad option` with exit 9, which is why every sweep must check for a
zero exit status before believing its numbers.

## Measuring it again


Set `RN_PROFILE_PHASES=1` and every phase reports to stderr at exit, with the
same boundaries the table above uses plus the ones the realm bootstrap added:

```bash
RN_PROFILE_PHASES=1 ./target/release/rustnode -e ''
```

The instrument lives in `rn-core/src/profile.rs`. It is compiled in but reads
nothing unless the variable is set: when it is unset, a mark is one cached-bool
test, so it does not perturb the thing it measures. Report one line per mark as
`cumulative` (from process entry) and `delta` (since the previous mark). The
sequence is linear, not a tree, so a mark that follows a nested one shows a
small delta and only its cumulative is meaningful.

This replaced the `RN_PROFILE_PHASES` timers that lived in the CLI and were lost
when `rn-cli` was refactored into `rn-realm`. Without them a regression could be
attributed to a commit by bisecting medians but not to a *phase*, which is
exactly what happened to the 5 ms that `#26` added: two hand-checked mechanisms
(binary size, the widened `has_external_work` predicate) were both wrong.

## The `#26` startup regression: 251 scans became 251 scans plus 251 allocations

`#26` did not make the option-list build quadratic. It was already
O(lookups × entries) on every tree, because `Store::value_of` is a linear scan of
the store. What `#26` added was a deep clone of the whole store *per lookup*: a
build that was 251 scans became 251 scans plus 251 allocations of a 217-entry
vector. Same class, a much worse constant. The rest of this section is the
evidence for that, and for the ~5 ms it cost.

`#26` (worker_threads) moved the parsed option store from a thread-local
`Store` to a process-wide one so a worker inherits the parent's command line.
The accessor kept its old signature, `fn store() -> Option<Store>`, and gained a
`.clone()` to satisfy the `OnceLock`:

```rust
PROCESS_STORE.get()?.lock().ok().map(|store| store.clone())
```

### The numbers that matter, and the two that are easy to confuse

The option **table** has **251** entries. The **store** holds **217** of them:
`ParsedValue::default_of` returns `None` for `kNoOp` and `kV8Option`, which have
no field in Node either, and the table contains 19 + 15 = 34 such entries
(`DefaultValue::Undefined` appears exactly 34 times, the same count from the
other side). Both numbers are correct about different things.

So one `getCLIOptionsValues()` call did **251 lookups, each deep-cloning a
217-entry vector** — about 54,500 `(String, ParsedValue)` pair clones. Writing
"251 clones of 251 entries" is off by 34 and is the kind of figure that gets
quoted, so `a_parsed_store_holds_only_the_options_that_have_a_default` in
`rn-bind-options` pins the 217 *derived from the table* rather than as a
literal: adding an option keeps the test honest.

The scan and the clone are separate costs, and only the second one is new.
`Store::value_of` is a linear scan (`self.values.iter().find(..)`), so one lookup
was O(entries) before `#26` and is O(entries) after; a build is
O(lookups × entries) either way. The clone did not change the class — each of the
251 lookups newly allocated and filled a 217-entry vector before doing the same
scan it always had. That allocation and copying is the ~5 ms, and it is why the
heading above talks about allocations rather than about a complexity class.

### Two builds, from one cause — and a duplicate call that was not one

Every tree from `05c691b2` to this head builds the list exactly **twice**. Two
things were going on, and an earlier draft of this section — and the comment on
`store()` — wrongly presented them as two causes of the same two builds. They are
independent:

1. **One cause of the two builds: `prepareExecution` deliberately clears the
   memo.** `getCLIOptionsValues()` is memoized in `internal/options.js:33`
   (`optionsDict ??=`), but `prepareExecution` calls `refreshRuntimeOptions()` →
   `refreshOptions()`, which sets `optionsDict = undefined`, so the build before
   that point is discarded and the build after it starts over. The two readers
   are the CJS loader's `initializeCJS` → `initializeCjsConditions` →
   `getOptionValue('--conditions')`, and `patchProcessObject`'s
   `addReadOnlyProcessAlias`. Captured stacks, in order, on this head:

   ```text
   #1  getCLIOptionsFromBinding  node:internal/options:34
       getOptionValue           node:internal/options:202
       initializeCjsConditions  node:internal/modules/helpers:220
       initializeCJS            node:internal/modules/cjs/loader:513

   #2  getCLIOptionsFromBinding  node:internal/options:34
       getOptionValue           node:internal/options:202
       addReadOnlyProcessAlias  node:internal/process/pre_execution:427
       patchProcessObject       node:internal/process/pre_execution:409
       prepareExecution         node:internal/process/pre_execution:115
   ```

   This is **not** two module instances: `require('internal/options')` is the
   same object through both loaders and `getOptionValue` is the same function,
   which was checked directly rather than assumed. It is one instance whose
   cache is invalidated on purpose. Node's ordering differs: it calls
   `refreshRuntimeOptions()` *before* `initializeModuleLoaders` (which is what
   reaches `initializeCJS`), so Node refreshes an unpopulated memo and its one
   later read builds once. rustnode reaches `initializeCJS` from
   `install_cjs_loader` before `prepare_execution`, so the refresh discards a
   real value. That ordering is a genuine divergence from Node and is left
   alone here: after the `Arc` fix it costs 0.08 ms.

2. **A duplicate call that was *not* a third build, but was still wrong.**
   `main.rs` called `allow_option_gated_builtins` before pre-execution, with the
   comment "rustnode does not run `pre_execution.js`". That premise is false:
   `prepare_execution` invokes `prepareMainThreadExecution`, whose
   `prepareExecution` calls `setupOptionGatedBuiltins()` at
   `internal/process/pre_execution.js:121` — which *is*
   `BuiltinModule.allowOptionGatedBuiltins(getOptionValue)`. Node applies it
   once, from inside pre-execution; rustnode applied it twice.

   Counting calls to `getCLIOptionsValues` shows **two on every tree**, including
   unfixed master: because the duplicate call reads through the same memo, it
   displaced `initializeCJS` as the *first* reader rather than adding a build.
   On unfixed master the first stack is
   `BuiltinModule.allowOptionGatedBuiltins (realm:293)` and the second is
   `patchProcessObject`; on this head the first is `initializeCJS` and the second
   is unchanged. So removing it is worth ~0.2 ms, and it is gone because it was
   Node's call made twice and its comment stated a false premise — not because
   it duplicated an expensive build.

   Nothing between the two calls needs a gated builtin either:
   `install_early_globals` reaches only `buffer`, `encoding`,
   `worker/js_transferable`, `async_hooks` and `util`, `install_cjs_loader` only
   `modules/cjs/loader`, and a worker calls `install_early_globals` but never the
   allow-list. It is removed along with the now-dead
   `rn_realm::allow_option_gated_builtins`, so rustnode now does it the way Node
   does.

### The fix

Hand back an `Arc<Store>` instead of a `Store`, so every lookup observes one
allocation. `Arc` rather than `Rc` because the process-wide slot is a `static`.
Worker inheritance is unchanged, and
`a_worker_reads_the_option_values_this_process_was_started_with` in
`rn-cli/tests/m0_foundation.rs` pins it: it reads `--strip-types`, a value the
runtime *corrects* rather than parses, so a worker that fell back to a fresh
copy of the table would report `true`.

The phase report located the cost without ambiguity, on the tree that still had
the duplicate call (unfixed master, `c236ee9c`): there, both marks that contain a
build moved — `allow_option_gated_builtins` **2.80 ms** and `prepare_execution`
**3.76 ms** — while the marks carrying no build (`primordials`,
`install_early_globals`) were unchanged.

`c236ee9c` is the only tree where both of those marks exist, because the
duplicate call is what supplied the first one. A head with it removed has no
`allow_option_gated_builtins` mark at all; only `prepare_execution` remains, and
on the current head it is **1.24 ms**. Do not compare the two across trees:
`0.34 ms` for that mark belongs to `a99cf945`, the intermediate commit that still
applied the allow-list twice, and quoting it beside a duplicate-free head mixes
two different programs.

The measurement that is unambiguous is per build, and it is the strongest
evidence here. Taken in-process over 200 calls after warm-up, one
`getCLIOptionsValues()` costs **2.60 ms unfixed and 0.087 ms fixed**. There are
**two builds on every tree** — pre-`#26`, unfixed master, and this head — so
`#26` did not add a build; it made each build cost that much. Two builds at
2.60 ms is 5.2 ms, two at 0.087 ms is 0.17 ms, and the ~5.0 ms between them is
what the batch measurements below show.

`install_cjs_loader` sits at ~2.9 ms on both trees, which is the loader itself
rather than an option read and is why it is not evidence of anything here.

Measured on one machine in one session, all binaries interleaved in a single
batch, 100 runs each, `-e ''`, release build. Absolute milliseconds drift
between batches on this machine, so the *difference* is the number to read; a
second 80-run batch is quoted below it.

| binary | median | min | p25 | p75 | vs node |
| --- | --- | --- | --- | --- | --- |
| node | 18.99 ms | 16.33 ms | 18.13 ms | 20.15 ms | — |
| before `#26` (`05c691b2`) | 24.99 ms | 22.31 ms | 24.35 ms | 25.92 ms | 0.76x |
| master `c236ee9c` | 29.51 ms | 26.99 ms | 28.86 ms | 30.76 ms | 0.64x |
| master + this change | 24.92 ms | 21.84 ms | 24.09 ms | 25.50 ms | 0.76x |

A second batch, 80 runs each, on the same binaries' predecessors gave
node 21.08 / `05c691b2` 27.21 / master 32.20 / changed 27.05 ms. So the recovery
is **4.6–5.7 ms** across three batches, which is the whole regression; the
leftover difference against `05c691b2` sits inside this machine's spread.

Removing the duplicate allow-list call is worth **~0.2 ms** at the median once
the `Arc` fix has made the lookups cheap: across 80 interleaved runs, the `Arc`
fix alone gave 27.28 ms and `Arc` + removal gave 27.05 ms, and on the pre-fix
tree removing the duplicate alone gave 30.01 → 29.86 ms over 60 runs. All three
deltas are inside a single p25-to-p75 band.

**It did not remove a build.** Counting calls to `getCLIOptionsValues` in the
process shows **two on every tree** — pre-`#26`, unfixed master, and this head —
because `allowOptionGatedBuiltins` and `patchProcessObject` both read through the
same memo, so the duplicate call simply moved the *first* build earlier rather
than adding a third. What `#26` changed is the cost of each build, not how many
there are. The duplicate call is gone because it was Node's call made twice and
because its comment stated a false premise, not because it was the bottleneck.

This does **not** close the remaining ~6 ms gap to node; that is separate work.

### Phase medians on this head

`RN_PROFILE_PHASES=1`, 40 runs, median `delta` per phase, from the shipped
binary:

```text
primordials                    3.29 ms
realm.js executed              2.53 ms
install_early_globals          5.21 ms
install_cjs_loader             2.95 ms
install_stdio + console        1.44 ms
prepare_execution              1.24 ms
```

`prepare_execution` is the single Node-shaped application of the allow-list, and
there is no longer an `allow_option_gated_builtins` mark because there is no
longer a call before pre-execution. The duplication was already cheap after the
`Arc` fix; it is gone because it was Node's call made twice, not because it was
the expensive part.

