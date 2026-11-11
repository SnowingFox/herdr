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
> current `master` is ~0.76x against node, not 0.84x. See the regression section
> further down ("The `#26` startup regression") for the mechanism and the
> current measurement. The table and the comparison above are left as measured;
> they are a real record of the cache work, not a statement about today.

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

## The `#26` startup regression: a quadratic option-list build

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

To be precise about the complexity, since the phrase "O(n²) lookup" is wrong for
this code: `Store::value_of` was already a linear scan (`self.values.iter()
.find(..)`), so one lookup was O(entries) before #26 and one lookup is
O(entries) after. A *build* is O(lookups × entries) either way. The clone did
not change the asymptotic class — it raised the constant and added ~54,500
allocations, because each of the 251 lookups newly allocated and filled a
217-entry vector before doing the same scan it always had. That allocation and
copying is the ~5 ms.

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

