# Three-way benchmark: Node, rustnode, Bun

This is a recorded run of `tools/bench.py` with its optional third column
enabled. It exists so the performance claim is checkable from repository state:
the commands below reproduce the table, and every number here is a median from
that tool rather than a figure copied out of a discussion.

Date: 2026-11-19. Tree: `2a804849` on `issue/three-way-bench`.

## What this does and does not say

**rsnode's JavaScript execution speed is identical to Node's.** ("rsnode" is the
project's name for the runtime; the binary is `rustnode`, and that is the name
the code and the tables use.) The vendored V8 and the `lib/**` builtin JavaScript
are byte-identical to the pinned Node 28 revision
(`vendor/libnode-js/lib/**` is checked by `tools/verify-libjs.sh` on every
commit), so the same source runs on the same engine. Any table that appears to
show rsnode executing JavaScript faster than Node is measuring something else —
process start, a native call, or a cache — and not the engine.

The differences this document records are therefore in exactly four places:

- how long the process takes to get to running a script (startup),
- how long a builtin takes to become loadable (the `require` cases),
- the cost of one native call on a hot loop,
- resident memory after a workload.

Nothing below is evidence that rsnode is faster at JavaScript. It is not, and it
cannot be, because it is the same JavaScript on the same V8.

## The machine

| fact | value |
| --- | --- |
| CPU count | 8 (`nproc`) |
| CPU | Intel(R) Xeon(R) Processor |
| load average | 0.9–1.7 (1-minute value sampled around the batches that produced the table; the wider "Noise" comparison spans 0.2–1.7) |
| memory | 47 GiB total, 15 GiB available |
| kernel | Linux 6.12.113+ |

Load average matters here: this is a shared VM, and a single `--samples 30`
batch is cheap enough to land inside someone else's compilation. One batch
recorded in the same session caught a spike (`arithmetic` 37.6 ms against 25.0 ms
either side) and was discarded; the table above is from five batches that did
not. See "Noise" below for the spread that survived, which is larger than a
reader would guess from the medians alone.

## The runtimes

| runtime | binary | version |
| --- | --- | --- |
| Node | `/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node` | `v28.0.0-nightly20261111e8c1160d20` |
| rustnode | `target/release/rustnode` (release profile) | `v28.0.0-nightly20261111e8c1160d20` |
| Bun | `/tmp/bun-dl/bun-linux-x64/bun` | `1.4.4` |

The Node binary is the pinned oracle from `tools/node-pin.toml`, not whatever
`node` is on `PATH`. The Bun binary is the pin in
`tools/fetch-bun-oracle.sh`. Bun is an **optional** column: with no Bun binary
present `tools/bench.py` prints the two-way table it has always printed.

**Bun is not a V8 runtime.** It reports `webkit` and no `v8` in
`process.versions` — its JavaScript engine is JavaScriptCore. That makes the
Bun column a comparison against a different engine, which is worth having but
is not the same comparison as Node against rustnode. It is also why the
native-call figure for Bun is not a measure of the same binding layer: the call
crosses a different FFI from a different engine's inline caches.

## Exact commands

From the repository root:

```bash
cd rustnode

export PATH="/usr/local/cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.96.1 CXX=g++ RUSTFLAGS="-L /usr/lib/gcc/x86_64-linux-gnu/13"
unset CARGO_TARGET_DIR

cargo build --release -p rn-cli
cargo build -p rn-cli

./tools/fetch-node-oracle.sh     # if the pinned oracle is not already present
./tools/fetch-bun-oracle.sh      # if Bun 1.4.4 is not already present

export NODE_BIN=/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node
env -u NODE_DISABLE_COMPILE_CACHE python3 tools/bench.py --samples 30
```

`env -u NODE_DISABLE_COMPILE_CACHE` is not optional on these machines. The
variable is exported globally here, and it disables the V8 compile cache for
every runtime that honours it, which changes startup by more than any difference
this table is about. Running without the `-u` produces a table that is not
comparable to this one.

`--json` gives the same numbers plus the fields the table does not print
(`bun_ok`, `bun_unavailable`, per-case `rust_per_bun`). Add `--samples 30` to
`--json` for the form used to compute the spread below.

## The recorded table

Median of 30 samples per case, from the five batches recorded in the first
session. Every cell is the median across those five batch medians. The per-batch
spread, and the wider spread when the whole tool is repeated in a later session,
are in "Noise" below — read them before quoting any single number here.

| case | node | rustnode | bun | node/rust | rust/bun |
| --- | --- | --- | --- | --- | --- |
| empty | 16.23 ms | 24.71 ms | n/a | 0.66x | — |
| arithmetic | 15.78 ms | 24.66 ms | 2.63 ms | 0.64x | 9.40x |
| print | 19.53 ms | 28.22 ms | 2.55 ms | 0.69x | 11.20x |
| `require('path')` | 15.65 ms | 24.84 ms | 3.46 ms | 0.63x | 7.19x |
| `require('util')` | 15.67 ms | 25.14 ms | 4.57 ms | 0.64x | 5.50x |
| `require('fs')` | 15.92 ms | 24.90 ms | 4.35 ms | 0.64x | 5.69x |
| peak RSS | 43.4 MiB | 45.3 MiB | 11.5 MiB | — | — |
| 200k native calls | 3.23 ms | 1.27 ms | 3.15 ms | — | — |

### How to read the ratios

Both ratios divide **the left column's time by the right column's time**, and
the header names the operand order:

- **`node/rust` = node_ms / rustnode_ms.** `0.64x` means Node took 64% of
  rustnode's wall time, i.e. rustnode was slower. Above `1.00x` would mean
  rustnode was faster.
- **`rust/bun` = rustnode_ms / bun_ms.** `9.40x` means rustnode took 9.4 times
  longer than Bun. Below `1.00x` would mean rustnode was faster than Bun.

A ratio below `1.00x` favours the right-hand runtime in both columns. The two
ratios point in opposite directions from rustnode's perspective, which is why
the header spells out the operands instead of labelling a column "speedup".

### One literal run

The table above is an aggregate. This is one unmodified `--samples 30` run,
printed by the tool as it ships, so the format can be checked against the
aggregate:

```text
case                         node   rustnode        bun  node/rust   rust/bun
------------------------------------------------------------------------------
empty                      15.20ms     24.76ms        n/a      0.61x          - (bun wrote 2301 bytes to stdout where node writes 0)
arithmetic                 15.06ms     24.78ms     2.64ms      0.61x      9.38x
print                      16.57ms     27.93ms     2.49ms      0.59x     11.20x
require('path')            15.59ms     24.44ms     3.48ms      0.64x      7.03x
require('util')            15.73ms     24.72ms     4.52ms      0.64x      5.47x
require('fs')              16.02ms     24.41ms     4.30ms      0.66x      5.67x

peak RSS           node 43.3 MiB   rustnode 45.3 MiB   bun 11.5 MiB
200k native calls  node 3.35ms      rustnode 1.28ms      bun 3.16ms
```

## Cases a runtime could not be measured on

Each of these is reported as unavailable rather than timed. A runtime that
errors, or that runs a different program than the case names, must not
contribute a number: `tools/bench.py` checks this before timing anything.

**`bun -e ''` is not an empty script, so Bun has no `empty` row.** Bun treats an
empty `-e` payload as "no script given" and prints its usage banner: 2301 bytes
on stdout, exit 0, in 0.86 ms. That 0.86 ms is the time to print `--help`, not
the time to boot the engine, and putting it in the row every reader looks at
first would be a silent lie in the table's most-quoted cell. `bench.py` refuses
it by comparing stdout against what Node writes for the case, and prints the row
as `n/a` with the reason. Arithmetic is Bun's nearest real startup case.

Because that banner path also exits before the engine boots, Bun's memory figure
is taken on `-e '0'` — a script that runs and does nothing — rather than on
`-e ''`. Measured over seven runs each: the banner path peaks at 7.7 MiB and a
real no-op at 11.4 MiB, so using the banner would have understated Bun's
footprint by about 3.8 MiB (a third). Node and rustnode differ by ~0.05 MiB and
~0.01 MiB between `-e ''` and `-e '0'`, so their figures stay on the `-e ''`
basis they have always used.

**No other case was refused.** All three runtimes ran `arithmetic`, `print`, and
the three `require` cases, and all three produced a native-call number. The
`require` cases are only run at all when rustnode's loader works, as before.

## Comparability: what is and is not comparable

Comparable:

- **Node against rustnode, on startup and `require`.** Same V8, same vendored
  JavaScript, same Node version string. This is the comparison the repository
  cares about, and `node/rust` is the column for it.
- **All three, on peak RSS.** Each is the `ru_maxrss` of a fresh process, so
  each is that runtime's own footprint. It measures the whole process, not the
  JavaScript heap, so it includes the binary's mappings.
- **The same case against the same runtime, across batches on this machine.**
  That is what the spread below is for.

Not comparable, or not comparable without care:

- **Bun's startup against Node's or rustnode's, as a statement about "the
  runtime".** Bun runs a different engine (JavaScriptCore), with a different
  module system and a different stdlib. Its `require` cases are its CommonJS
  compatibility layer, not Node's loader. The `rust/bun` column says how these
  two binaries behave on the same command line; it does not say that either
  runtime is better at Node's job.
- **The `200k native calls` figure as an absolute.** It is `process.cwd()` in a
  200k-iteration loop, and the number includes the loop itself. Measured
  separately at 31 samples: the same loop over a string literal is 0.71 ms
  (rustnode), 1.08 ms (Node) and 1.72 ms (Bun), so the call itself is 0.53 ms,
  2.13 ms and 1.46 ms — rustnode's binding path is about 4x cheaper than Node's
  and about 2.8x cheaper than Bun's. The raw column is what the tool prints;
  subtracting the loop is the honest attribution and it does not change the
  ordering.
- **Absolute milliseconds against another machine, or against this machine at
  another time.** The absolute numbers drift with load. The ratios are more
  stable than the millisecond columns but not immune; see below.
- **`empty` against `arithmetic` for Bun.** The `empty` row is `n/a` for Bun, so
  a reader must not read the missing cell as zero or as "fast". `arithmetic` is
  the nearest Bun row, and it is a real script execution.

## Noise

The honest summary: **rustnode and Bun repeat tightly; Node's own startup time
on this VM does not, and that is the main limit on how precise a `node/rust`
ratio can be.**

Within one session, five batches of `--samples 30` (load average sampled around
the batches, 0.9–1.7):

| case | `node/rust` range | `rust/bun` range |
| --- | --- | --- |
| empty | 0.61–0.67 | — |
| arithmetic | 0.63–0.65 | 9.23–9.96 |
| print | 0.61–0.70 | 11.05–11.36 |
| `require('path')` | 0.62–0.64 | 7.12–7.47 |
| `require('util')` | 0.59–0.68 | 5.40–5.69 |
| `require('fs')` | 0.63–0.65 | 5.66–5.84 |

Repeating the whole tool in a later session widens `node/rust` considerably. Over
16 batches pooled (three sessions: 5, 5 and 6 batches, the third recorded after
the gate had finished at load 0.2–0.5):

| runtime | `empty` range | spread as % of its own median |
| --- | --- | --- |
| Node | 15.6–19.7 ms | 24.5% |
| rustnode | 23.7–25.8 ms | 8.4% |
| Bun (arithmetic, its nearest row) | 2.59–3.44 ms | 32.2% |

Bun's *median* is stable — 2.59–2.68 ms for `arithmetic` across the batches that
did not catch a spike — but its per-run times are small enough that a spike
inflates its percentage range more than rustnode's. Node's spread is the one
that matters, because it is the runtime whose median moves.

Pooled `node/rust` medians were 0.64–0.69 across the six cases. The pooled
per-batch range for those clean batches was 0.59–0.83; including the spike batch
it reaches 0.41. **Quote the median and the range, never a single batch's ratio
to two decimal places.**

Node's millisecond column is bimodal on this VM, and that is the mechanism, not
general "load". 40 consecutive samples of `node -e '1 + 1'` in one batch sorted
into two clusters with a gap and nothing in it: 22 samples between 15.3 and
17.0 ms (median 15.9) and 18 samples between 19.1 and 21.6 ms (median 19.9). A
repeat of the same 40 samples split 20/20 instead, at 15.3–17.5 ms (median 16.0)
and 18.6–20.5 ms (median 19.7) — the *counts* move between runs, the two-cluster
shape does not.

Pinning Node to one CPU collapses it: `taskset -c 0 node -e '1 + 1'` gives a
median of 14.50 ms with a p25–p75 of 14.27–14.59, against 16.48 ms and
16.08–19.50 unpinned. Pinning rustnode makes it marginally *worse*
(24.20 → 25.21 ms), so a pinning-based fix would bias the comparison in
rustnode's favour, which is why the tool does not do it. Recorded here so the
next person does not "fix" the noise by pinning one side.

The slow cluster is consistent with Node's own worker threads competing for the
scheduler on an 8-CPU box; that is the reading the pinning result supports, not
something separately instrumented.

That asymmetry is also why `node/rust` is worse than 1.00x and why it moves:
rustnode's startup is dominated by single-threaded JavaScript bootstrap, which
the scheduler treats consistently, while Node's startup has enough parallel work
across its worker threads to land in either cluster.

Peak RSS is stable to within a few hundred KiB across batches
(rustnode 45.0–45.6 MiB, Node 43.4 MiB, Bun 11.5–11.6 MiB). The native-call
medians are stable to about ±0.15 ms (rustnode 1.22–1.31, Node 2.91–3.37, Bun
3.14–3.15).

**One earlier batch in the same session was discarded.** It recorded
`arithmetic` at 37.6 ms for rustnode against 24.5–26.2 ms in the batches either
side of it, and `print` at 41.7 ms against 28.1–29.3 ms. That is a load spike
landing across the batch, not a property of the runtime: the same pattern
appeared in every runtime's column in that batch. Publishing it, or publishing
a median that included it, would have reported a number about this VM's
neighbours. It is excluded from every range above except where a pooled range is
explicitly described as spanning all recorded batches.

## What the numbers say

- **Startup.** rustnode is slower to start than Node on every case here:
  `node/rust` is 0.66 by pooled median (pooled per-batch range 0.59–0.83), so
  Node reaches the script in roughly two thirds of rustnode's wall time. That
  gap is the JavaScript bootstrap, not V8 initialisation; `docs/startup.md`
  breaks it down phase by phase. Treat the ratio as "about two thirds, ±10% on
  this machine" rather than as a figure with two significant digits.
- **Builtin loading and first write.** The three `require` cases land at
  `node/rust` ~0.66, the same place as the startup cases: loading a small
  builtin adds roughly the same cost to both runtimes. `print` is the one row
  that moves, to ~0.69, because the first write costs each runtime about the
  same extra time over `empty` while the baseline it is added to differs.
  `docs/startup.md` shows the first-write cost is the cold stdio `Socket`
  construction rather than module compilation, which the code cache already
  covers.
- **Native calls.** rustnode's is the cheapest of the three: 1.27 ms against
  Node's 3.23 ms and Bun's 3.15 ms for the loop including its overhead, and
  0.53 ms against 2.13 ms and 1.46 ms once the loop is subtracted. This is the
  one column where rustnode wins, and it is a real win: the binding path is
  narrower than Node's.
- **Memory.** rustnode uses slightly more than Node (45.3 against 43.4 MiB) and
  four times Bun's 11.5 MiB. Bun's figure is not a like-for-like architectural
  comparison: JavaScriptCore's baseline footprint is not V8's.
- **JavaScript execution.** Unmeasured here on purpose, and not because the
  tool could not: it is identical by construction between Node and rustnode,
  and comparing it against Bun would be comparing two engines rather than two
  builds of the same one.

## Reproducing

The commands in "Exact commands" above reproduce the table. `tools/bench.py` is
not a measurement the gate makes — `tools/check.sh` never runs it — but the gate
does run `tools/bench.py --self-test`, for two properties that keep the tool safe
to run anywhere:

- with no Bun binary found, it prints the original two-way table unchanged and
  exits 0, so a machine without Bun is unaffected. The self-test pins that
  discovery answers `None` rather than raising and never returns a path it
  cannot execute, because that is the difference between a missing runtime and a
  traceback or a timed invocation of some unrelated `bun` alias.
- a runtime that cannot run a case is reported as unavailable and is never
  timed, so a missing feature becomes a visible gap rather than a zero. The
  self-test feeds the tool a banner-writing stub and a failing stub and requires
  both to be refused, while the case that prints on purpose is not.

The self-test needs no Node, no Bun and no built binary. It was verified to fail
under three separate mutations: dropping the executability check from
`find_bun`, removing the zero-denominator guard from `ratio`, and judging stdout
on the case that is supposed to write.
