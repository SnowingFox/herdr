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

The `Uncaught` marker was adjudicated against a real Node oracle and **kept
unchanged** — see "The `Uncaught` marker is sound, and must not be widened" below.
Briefly: 61 of the files it catches exit 0 while having printed a genuine
`Uncaught AssertionError`, and **none** of the 2880 passes prints the word at all,
so the marker is separating real failures from real passes rather than reacting to
message formatting.

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

**The floor has now been probed from both sides.** The rule can be wrong in two
directions — a pass that did nothing, and a failure that is not rustnode's — and
both are measured: "The rule is a floor, not a ceiling" bounds the first with an
instrumented sample, and "The oracle control" bounds the second by re-running every
rustnode failure under a real Node 28 built from the pin. The second is the larger
of the two and it is small: 22 of 5714 files.

**The headline finding, which overturns a premise this project has been working
from:** the `AssertionError: … strictly equal` tail is **not** an async-propagation
cluster, and it has **zero** async members today. See the next section.

## The headline finding: the async tail is not async

A previous version of this document, and the work plan built on it, assumed the
long tail of `AssertionError: … strictly equal` failures was mostly async
propagation. **It is not, and the count is now zero.**

Reading the strict-equal failures one by one, on the latest full run (`f0649774`):

| tree | strict-equal files | worker-gated | async-shaped | other |
| --- | --- | --- | --- | --- |
| `52f79555` (#51) | 151 | 1 | **0** | 150 |
| `f0649774` | 196 | 0 | **0** | 196 |

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
| 2731/5714 (47.8%) | `f0649774` | 8 suites, 5714 files | four-marker | **measured here** — superseded by the rows below |
| 2860/5714 (50.1%) | `59d661dc` | 8 suites, 5714 files | four-marker | **measured here** — reproduces the published 2863 figure within 3 files, see below |
| 2880/5714 (50.4%) | `c236ee9c` | 8 suites, 5714 files | four-marker | **last full measurement — quote this one** |
| 2879/5714 (50.4%) | `c236ee9c` | 8 suites, 5714 files | four-marker | **same binary, immediate re-run** — the run-to-run noise band is ±1 file |
| **2880/5692 (50.6%)** | **`c236ee9c`** | **8 suites, 5714 files** | **four-marker, oracle-corrected** | **the honest rate — see "The oracle control"** |
| 2645/5159 (51.3%) | `7af7b306` (pre-#51) | `test/parallel` only | four-marker | **measured here** |
| 2393/5159 (46.4%) | `52f79555` (#51) | `test/parallel` only | four-marker | **measured here** — the honest `test/parallel` rate for that tree |
| 2550/5159 (49.4%) | `368e32ac` | `test/parallel` only | four-marker | **measured here** — the `test/parallel` rate `docs/project-context.md` quotes |
| 2549/5159 (49.4%) | `f0649774` | `test/parallel` only | four-marker | **measured here** — matches the eight-suite row below it |

The eight-suite and `test/parallel` rows are different measurements, and **neither
is a time series**: the trees differ by merges as well as by scope. Read them as
four independent measurements of four different trees, not as movement.

The two `49.4%` rows are the ones to compare against the `test/parallel` exit-code
rates above them, because those are also `test/parallel`. The `50.6%` eight-suite
oracle-corrected row is the headline: it is the same scope and the same rule as the
`50.4%` row above it, with only the denominator corrected, so those two are the only
pair in this table that may be subtracted from each other.

**Do not subtract across scopes, which is what produces a spurious residual.** The
`test/parallel` and eight-suite skip populations are different numbers — 761 vs 808
on the `52f79555` tree, 471 vs 485 on `368e32ac` and `f0649774` — and mixing one into
the other leaves a handful of files that look like rounding but are not. (The
`test/parallel` figure counts the exit-0 skips the decomposition subtracts; one
further file, `parallel/test-worker-process-cwd.js`, carries a skip marker and exits
non-zero, so it is already outside the exit-0 count.) See the decomposition below,
which closes exactly when both sides come from the same run.

### Reproducing the 2863 figure, and why it is 2860 here

The published headline of `2863/5714 (50.1%)` was measured at `59d661dc`. Re-measured
here with the current tool and a binary built from that exact commit, it is
**2860/5714 (50.1%)** — the same rate to one decimal, three files lower.

The three-file difference is **not** attributable to a rule change or to a
regression, and it is not explained further here: the two runs were taken at
different times on the same machine, and three files is inside the run-to-run
variation this document already records for `27d67077` (3733 vs 3735). It is stated
as an unexplained residue rather than given a cause that was not measured.

Between `59d661dc` and `c236ee9c` the count moves 2860 → 2880, and here the cause
*is* measured: **zero files pass at `59d661dc` that fail at `c236ee9c`**, and 20 pass
at `c236ee9c` that fail earlier. All 20 are TLS-adjacent: 17 `test-tls-*`, 1
`test-crypto-x509-name-non-string.js`, and 2 `test-worker-terminate-*` /
`test-worker-message-port-transfer-terminate.js`, with no file outside those groups.
That is the peer-certificate work of #69 (`01912963`, `5a74c6d3`) and the later
merges, not measurement drift.

### The oracle control

Every figure above shares one blind spot: **a file rustnode fails is not
necessarily a file that should pass**. Node's own suite contains tests that fail on
real Node in a given environment, tests Node deliberately expects to fail, and tests
whose result depends on how the harness captures output. Counting those against
rustnode understates it. The control is to run exactly the files rustnode fails
under a real Node built from the same pinned source, and subtract the ones Node
fails too.

**Setup.** `nodejs/node` at `f344e7f552e3656bd37517151c5dc87d22b33771`
(reports `v28.0.0-pre`, V8 `15.6.75.33-node.11`, ICU 78.3), `./configure && make -j8`,
release binary at `out/Release/node`, ~44 min build. This is a real build of the
pin, not this machine's `node` (`v22.23.4` on `PATH`, which is **not** a valid
oracle: it fails several of these files for v22's own reasons).

**That build no longer exists.** The 44-minute source build was made on
2026-11-11 and has since been removed from the machine; `/home/ubuntu/oracle-node`
is gone, including `out/Release/node`, and no other Node 28 built from the pin is
on the filesystem. Every number in this and the following sections is a record of
what that binary measured on that day and stays valid as a measurement. The
*instruction to re-run it* is what was wrong. For new work, use the official Node
28 nightly as described under "Running the oracle" below, and read the
three-commit caveat there before reusing any figure that depends on streams or SEA.

**Method.** Take every file rustnode fails, drop `internet` (see below), and run
the remainder through `tools/test-tail-map.py` with the same `// Flags:` handling,
timeout and four-marker rule, with the oracle as `--node`. Then inspect every file
the oracle did not pass.

**Result, at `c236ee9c`.** 2353 in-scope failures were handed to the oracle. It
passed 2316 of them; 29 failed or timed out and 8 skipped, so 37 were not passes.
All 37 are accounted for below, and each row was checked rather than assumed:

| files | oracle outcome | why | counted as an oracle failure? |
| --- | --- | --- | --- |
| 19 | fails | `known_issues` suite: Node's own `test/known_issues/testcfg.py` sets `expect_fail = 1`. All 19 of 19 fail under real Node. | yes |
| 2 | aborts on heap | `test-shadow-realm-gc{,-module}.js` pass `--max-old-space-size=20`; Node's `parallel.status` lists both `SKIP`. | yes |
| 1 | fails | `test-snapshot-incompatible.js`: Node's `parallel.status` lists it `SKIP`; here it fails with `actual: ''`. | yes |
| 3 | fails only under a pipe | `test-process-getactiveresources{,-track-active-requests}.js`, `test-listen-fd-ebadf.js` fail when stdout is a pipe and **pass when it is a file**, for both binaries. The harness's capture method, not Node. | no |
| 4 | **exits 0** | `test-repl.js`, `test-worker-exit-code.js`, `sequential/test-repl-timeout-throw.js`, `test_legacy_uncaught_exception.js` print `Uncaught` as part of their expected output. The oracle says pass; the rule says fail. | no |
| 8 | skips | `1..0 # Skipped` for debug-only, missing h2load, QUIC, FIPS, addon reasons. A skip measures nothing. | no |

So `oracle_failures = 22`:

```
2880 / (5714 − 22) = 2880/5692 = 50.60%      # oracle-corrected
2880 /  5714                    = 50.40%      # raw, same run, same rule
```

**The correction is +0.19 points, and that is the finding.** The suspected blind
spot is real but small: 22 of 5714 files (0.4%) are ones real Node does not pass
either. It is not zero — mostly because `known_issues` is a suite that can never
pass — but it does not turn 50% into a materially different number. Under the
strictest definition (count every oracle non-pass, including the four the rule
misjudges and the three the harness breaks) the figure is 50.66%; if the eight
oracle skips are also removed from the denominator it is 50.67%. All definitions
agree to within 0.27 points.

Both sides carry a run-to-run noise band, and both are smaller than the correction.
The baseline re-run on the same binary and tree gave 2879 against 2880 (**±1 file =
±0.018 points**), and the oracle's 29 non-passes re-ran identically (**0 flaky**). So
the corrected rate over the noise band is **50.58%–50.60%**, and the raw rate is
50.39%–50.40%. The correction is still larger than the noise, which is why it is
reported to two decimals.

The denominator keeps all 5714 files and subtracts only oracle failures, exactly as
the formula above says. That is deliberately unkind to rustnode: its own 461 skips
stay in the denominator (they are not subtracted, only the oracle's are), so this
figure is a floor in the pessimistic direction as well. Subtracting them would
raise it, and no such variant is quoted here.

**What the control actually buys: the remaining gap is confirmed real.** 2316 of
2353 in-scope rustnode failures pass under real Node. The 22 that do not are named
in the table above. There is no longer an unexplained residual, and no suite is
blanket-excluded.

**Two harness confounds, found by reading failures and fixed in the tool.**
Ambient settings in the agent shell were changing outcomes, and un-scrubbed they
raised the oracle's failure count from 29 to 80:

| setting | effect |
| --- | --- |
| `NODE_DISABLE_COMPILE_CACHE=1` | 18 `test-compile-cache-*` files cannot exercise the cache at all |
| `NO_COLOR=1` / `FORCE_COLOR=0` | colour assertions see plain text (`test-console-tty-colors`, `test-node-output-console`) |
| `TERM=dumb` | REPL editing tests fail; `TERM=xterm` flips all six to exit 0 |

`tools/test-tail-map.py` now removes the first two and pins `TERM=xterm-256color`
when `TERM` is `dumb`, for **both** binaries. This is measurement hygiene, not a
compatibility fix, and it moved rustnode's own count too (2849 → 2880).

**`node-api` needed its fixtures built before it measured anything.** Without the
compiled addons, 46 `node-api` files fail under both binaries with
`Cannot find module './build/Release/...'`. `crates/rn-napi/tools/build-node-api-addons.py`
builds them (36 targets, needs `--js-native-api` and `--uv-include`). With them
built, 45 of 46 pass under the oracle and 10 of 46 under rustnode — a real 35-file
gap that the naive control would have excused as "oracle failures".

**Flakiness.** The 29 oracle non-passes were re-run at a 60 s timeout: **0 of 29
non-deterministic**, so nothing needed splitting between the sides. Nothing is
excluded here for flakiness.

**`internet` is not evidence.** 20 `internet` failures were excluded from both
sides. The suite may need network, and a network-dependent result says nothing
about compatibility in either direction.

**Reproduce.** The commands below are the ones that produced the numbers above.
They need a Node 28 binary and a copy of the pinned `test/` tree, and the binary
they name — the 44-minute source build at `/home/ubuntu/oracle-node` — **is no
longer present**. See "Running the oracle" for the nightly that replaces it and
for the three-commit caveat that applies to it. The `--node` and `--tests` paths
are the only things to change; the rest of each command is unchanged.

```bash
# the binary: was /home/ubuntu/oracle-node/out/Release/node, now absent
# the tree:   was /home/ubuntu/oracle-node, now absent

cd rustnode && export RUSTUP_TOOLCHAIN=1.96.1 CXX=g++ \
    RUSTFLAGS="-L /usr/lib/gcc/x86_64-linux-gnu/13"

python3 crates/rn-napi/tools/build-node-api-addons.py \
    --source <node-tree>/test/node-api \
    --output <node-tree>/test \
    --js-native-api <node-tree>/test/js-native-api \
    --uv-include <node-tree>/deps/uv/include

python3 tools/test-tail-map.py run --node /tmp/frozen-oracle-control/rustnode \
    --tests <node-tree>/test --out /tmp/rn-full.json --jobs 8 --timeout 30
python3 tools/test-tail-map.py score /tmp/rn-full.json

# then the same run with the oracle over every file the baseline failed
python3 tools/test-tail-map.py run --node <node28-binary> \
    --tests <node-tree>/test --out /tmp/oracle.json --jobs 8 --timeout 30 \
    $(sed 's|^|--only |' /tmp/failed.txt)
python3 tools/test-tail-map.py score /tmp/oracle.json
```

`<node-tree>` is a checkout of the pin; the "Reproducing any row" recipe above
builds a `test/`-only one at `/tmp/node-pin`, which is enough for every step here
except the `node-api` addon build, whose `--uv-include` needs `deps/uv/include`
from a full tree. `<node28-binary>` is any Node 28 as described under "Running the
oracle" — today the nightly, which is three commits behind the pin.

### The `Uncaught` marker is sound, and must not be widened

The oracle surfaced four files where it exits 0 but the rule says fail:
`test-repl.js`, `test-worker-exit-code.js`,
`sequential/test-repl-timeout-throw.js` and
`test_legacy_uncaught_exception.js`. That is either a rule defect or four genuine
rustnode failures, and the only way to tell is to read rustnode's output next to the
oracle's rather than assume the oracle is right about the verdict.

**All four are genuine rustnode failures, decided by exit code, not by the marker.**

| file | rustnode | oracle | decided by |
| --- | --- | --- | --- |
| `parallel/test-repl.js` | exit **1**, dies at `Uncaught null: null` on the `throw null` proxy case | exit 0, completes every transcript | exit code |
| `parallel/test-worker-exit-code.js` | exit **1**, `wrong exit for 7-changeCodeInExitWithUncaught / expected:98 but got:0` and two more | exit 0 | exit code |
| `sequential/test-repl-timeout-throw.js` | exit **1**, child asserted `9 !== 0` | exit 0, three `Uncaught ReferenceError: XXX` which the test expects | exit code |
| `node-api/.../test_legacy_uncaught_exception.js` | exit **9**, `unsupported option '--no-force-node-api-uncaught-exceptions-policy'` | exit 0 | exit code |

So the marker is not what fails them, and narrowing the rule would change **nothing**
for these four. That is worth stating plainly because the natural reading of the
oracle table — "the oracle passes, therefore the rule is wrong" — is false here: the
oracle passes the *file*, while rustnode fails it for a reason the oracle never hits.

**A narrower `Uncaught` condition was measured and rejected.** The most defensible
candidate is to count only an in-process assertion, i.e. require the word
`AssertionError` in the marker line, on the theory that plain `Uncaught Error:` text
is usually leaked child stderr. Under that rule:

| | files |
| --- | --- |
| fail → pass | 10 |
| pass → fail | **0** |
| passes before / after | 2880 / 2890 |

Ten files is small enough that a verdict change would be reviewable rather than a
rewrite of the measurement, so each was read against the oracle: all 10 pass there.
But reading them individually shows the rule is right and the oracle is not
comparable, because each names a *rustnode* gap:

| file | rustnode's marker | real? |
| --- | --- | --- |
| `test-cluster-primary-error.js` | `Uncaught TypeError: process._kill is not a function` | `typeof process._kill === 'undefined'` on rustnode; the test *deliberately* throws `'accidental error'` in a cluster process, so the text itself is expected and this is a mixed case |
| `test-crypto-keygen-key-object-without-encoding.js` | `Uncaught TypeError: method is not a function` (×2) | yes — cipher path is incomplete |
| `test-tls-multiple-cas-as-string.js` | `Uncaught Error: enableCertCb is not implemented yet` (×2) | yes — a deferred TLS member, named in the message |
| `test-inspector-stops-no-file.js` | `Uncaught Error: Cannot find module '.../no-such-script.js'` | expected output: the oracle prints the same error in its own format |
| `test-module-loading-globalpaths.js` | `Uncaught Error: Cannot find module 'foo'` | expected output: the oracle prints it from the child process |
| `test-module-main-preserve-symlinks-fail.js` | `Uncaught Error: Cannot find module '.../iDoNotExist'` | expected output, same shape |
| `test-worker-error-primitive.js` | `Uncaught string: boom`, `Uncaught boolean: true` | expected output: the test transfers primitives |
| `test-esm-symlink-type.js` | `Uncaught TypeError: Cannot read properties of null` | real, but it exits **1** on a standalone re-run, so the recorded `exit 0` is a flake |
| `test-crypto-keygen-async-encrypted-private-key-der.js` | `Uncaught TypeError: method is not a function` | yes — cipher path incomplete |
| `test-worker-stdio-from-preload-module.js` | `Uncaught TypeError: ...` | yes — real |

The class is real on both sides: some of these are expected transcript text that
rustnode prints in its own `Uncaught X: y` format (Node prints a source frame and
`^` instead), and some are actual missing features. Reading them one at a time:
**6 are real or mixed** (an incomplete cipher path, a deferred TLS member,
`process._kill` absent, a null deref, a worker stdio type error) and **4 are expected
transcript text** the test prints on purpose. **The distinguishing fact is not the
marker text, and no output-only rule can separate them reliably.** A rule keyed on
`AssertionError` would therefore credit 10 files, of which 6 are real failures and 1
of those (`test-esm-symlink-type.js`) exits 1 on a standalone re-run and is a flake.
That is a rule widened until it passes, which this document forbids.

**The decisive measurement against widening.** Across the whole run:

| | files |
| --- | --- |
| passes (2880) that print `Uncaught` anywhere | **0** |
| exit-0 non-passes whose marker is `Uncaught AssertionError` | 61 |
| exit-0 non-passes with other `Uncaught` text | 10 |

Zero false positives on the pass side is the strongest evidence available that the
marker is doing real work. It holds on both baseline runs: 0 of 2880 and 0 of 2879
passes print `Uncaught`. Meanwhile "ignore `Uncaught` when the exit code is 0" —
the change the oracle table invites — would flip **531 files** pass, of which only 68
have any oracle support and 462 have none. That is not a scoring fix; it is a
different measurement.

**Verdict: the rule stays as it is.** The 71 exit-0-but-marked files are a real
finding about rustnode, not about the rule: rustnode prints a fatal error and still
exits 0 in those cases, which Node does not do. That is a defect in rustnode's exit
status propagation and is now recorded as such in the failure map. The four files the
oracle flagged are genuine failures and remain in the 2373-failure population.

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
(`f0649774`). It is still scored with the four-marker
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
| `368e32ac` (measured) | 3082 | −471 | −61 | **2550** | **0** |
| `f0649774` | 3079 | −471 | −59 | **2549** | **0** |

(Both rows are `test/parallel` scope. The eight-suite total is
2731/5714, which is a different scope and is not comparable row-for-row with these.)

A four-file residual appears if the numbers are combined across scopes: 3197 − 808 =
2389 is one measurement's `test/parallel` exit-0 count minus the **eight-suite** skip
population, which is why it lands four files from 2393 instead of on it. `test/parallel`
carries 761 skips on that tree and the eight suites carry 808, so 808 vs 761 is the
scope difference (plus a 30 s vs 60 s timeout difference in the exit-0 readings).
Subtracting one scope's skips from another scope's count leaves a few files over; at a
single scope the closure is exact, as the table shows.

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
skips** on `52f79555` and **0** on `f0649774`, because the inspector namespace
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
| commit | `7af7b306` | `52f79555` (`origin/cursor/exit-and-test-status`) | `f0649774` |
| contains | #33, #46; **not** #51 | #33, #46, #51 | #51 merged via `2fc0b17f`, plus later merges |
| binary | `/tmp/frozen-pre51/rustnode` | `/tmp/frozen-pr51/rustnode` | `/tmp/frozen-latest/rustnode` |
| sha256 (16) | `c4ff9845a0b34faf` | `d8c0d9cd691cfd07` | `dc9355c765817048` |
| binary mtime (UTC) | 2026-11-11T10:10:26 | 2026-11-11T10:08:43 | 2026-11-11T12:08:11 |
| Node tree | `f344e7f552e3656bd37517151c5dc87d22b33771` | same | same |
| command | `tools/test-tail-map.py run --node <binary> --tests /tmp/node-pin/test --jobs 8 --timeout 30` | same | same |
| exit-0 files | 3898 (68.2%) | 3454 (60.4%) | 3279 (57.4%) |
| four-marker passes | **2855 (50.0%)** | **2572 (45.0%)** | **2731 (47.8%)** |
| skipped | 808 | 808 | 485 |
| failing | 2051 | 2334 | 2498 |

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
2731 passes in it (78%) print nothing at all, which is normal for a passing
test and also indistinguishable from a test that silently did nothing.

**That specific risk is measured, and it is small.** `tools/mustcall-sample.py`
instruments every `common.mustCall*` registration and every invocation of the function
it wraps, so it answers the question directly instead of inferring it from output.
Sampled from that run's passes:

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
Zero in 165 files bounds that class below ~2.3% of `mustCall`-carrying passes. The
tool also reports that 4 of its 51 files in the seed-11 sample exit non-zero under
the reference `node`, which is **not** evidence about rustnode: the pin is Node 28
and the only `node` on this machine is v22.23.4, which fails several of these files
for v22's own reasons (e.g. `test-stream2-transform.js` asserts `'abcdef' === 'abc'`
under v22's stream semantics). The tool reports the two answers separately for
exactly this reason, and only `unsatisfied` is used for the rate.

**Treat this as a rate, not a per-file verdict.** One intermediate run of the same
200-file sample reported **1** contaminated file (7 unsatisfied assertions in
`parallel/test-cluster-concurrent-disconnect.js`), and three subsequent runs of the
identical command reported 0. A test whose async work sometimes finishes after the
`exit` handler will flip. Quote the bound, not the list.

This does **not** make the rule sound for every file — a file with no `mustCall`
registration and no output is still unaccounted for — so the pass figures remain an
upper bound. But the largest specific mechanism by which they could be inflated is
measured at 0 of 51.

## Sizing, with provenance per row

All rows below are from the **`f0649774` full run** (binary `dc9355c765817048`,
5714 files, 2498 failing) unless the row says otherwise. A row
marked *counted* was sized by matching a failure signature in the recorded output
of that run; a row marked *run* was re-run on the binary it names. Sizes are
distinct files and overlap, so they are not additive.

**These family sizes are older than the pass-rate figures.** The pass-rate table
above is measured at `c236ee9c`; the per-family counts here are measured at
`f0649774`, which is a different tree. Do not read a family size here as current
without re-counting it on the newer run, and do not subtract one from the other.

### Re-counted on `c236ee9c`

Counting the same signatures on the newest full run changes two of the rows below
materially, so they are recorded here rather than left to be read from the older
table. Where a count comes from `test-tail-map.py`'s `FAMILIES` predicates it is
labelled *family*; where it is a plain substring count over stdout+stderr it is
labelled *signature*, because the two differ (the `strict equal` family additionally
requires the row to be a failure and reads stderr only).

| files | family / signature | status on `c236ee9c` |
| --- | --- | --- |
| 335 | `internalBinding('http2')` has no Rust implementation *(signature)* | **new largest gap**; not sized in the table below at all |
| 202 | `strict equal` *(family)* | grew from 196; as a raw substring it is 298 |
| 246 | timeouts *(family)* | grew from 188 |
| 11 | `--snapshot-blob` *(family)* | unchanged |
| 72 | `enableSessionCallbacks is not implemented` *(signature)* | tls_wrap member, below |
| 11 | `setALPNProtocols is not implemented` *(signature)* | tls_wrap member, below |
| 28 | `fsBinding.cpSyncCopyDir is not a function` *(signature)* | was 28 |
| ~~646~~ **0** | `internalBinding('tls_wrap')` has no implementation | **closed** — the namespace is now registered (`crates/rn-bind-tls`); 82 files still fail on deferred members rather than the namespace |

Read the `tls_wrap` row carefully: the family did not disappear, it moved from
"namespace absent" to "three members absent". 82 files is the union of the two
member signatures, and those files overlap with the strict-equal and timeout
buckets, so 82 is not additive with anything else on this page.

| files | family | provenance |
| --- | --- | --- |
| 646 | `internalBinding('tls_wrap')` has no implementation | counted |
| 196 | `AssertionError: … strictly equal`, no single cause | counted |
| 188 | timeouts | counted |
| 28 | `fsBinding.cpSyncCopyDir is not a function` | counted |
| 17 | `internalBinding('locks')` has no implementation | counted |
| 11 | `unsupported option '--snapshot-blob'` | counted |
| ~~123~~ 0 | `WorkerImpl is not a constructor` | counted — **closed** between #51 and `f0649774` |
| ~~19~~ 0 | `fs.cp` `then()` on a `BigInt64Array` stat result | counted — **closed** |
| ~~0~~ 0 | `ReadFileJob` / `WriteFileJob` | **run** — closed by #46, still 0 |

The two closed rows are the most useful thing in this table: they show the map is
tracking a moving tree rather than describing a fixed one. Both are verified by
direct execution on that tree, not just by the absence of a signature:

```
$ ./rustnode -e "const {Worker}=require('worker_threads');const w=new Worker('console.log(1)',{eval:true});w.on('exit',c=>console.log('exit',c))"
1
exit 0
$ ./rustnode -e "require('fs/promises').cp('/etc/hostname','/tmp/x',{recursive:true}).then(()=>console.log('cp ok'))"
cp ok
```

### Exit status is lost after a fatal error — 71 files

`71` of the 2373 failures exit **0** while having printed an `Uncaught` line. Under
the oracle the same files either pass silently or exit non-zero, so this is a
rustnode defect rather than a test expectation: rustnode prints a fatal error and
then reports success.

61 of the 71 carry `Uncaught AssertionError`, which means a test's own assertion
fired and the process still exited 0:

```
$ ./rustnode test/parallel/test-domain-no-error-handler-abort-on-uncaught-0.js
(node:… ) [DEP0032] DeprecationWarning: The `domain` module is deprecated…
node:internal/assert/utils:4640: Uncaught AssertionError: Test should have aborted
but instead exited with exit code 1 and signal null
$ echo $?
0
```

Under the oracle the same file exits 0 printing neither line. So this is not the
test being lenient; it is the runtime failing to set an exit status for an
assertion that already failed. The other 10 are non-assertion text — leaked child
stderr, or an error in a context whose status never reaches the parent — and are a
mixture of expected transcript text and real gaps.

The map had been crediting these to the `Uncaught` marker without naming the
underlying defect. It is one bug with 71 files attached, it does not overlap the
http2 family at all, and it is the largest group in the map that is a behaviour
defect rather than a missing namespace.

### `http2` — 335 files, now the largest single gap

`internalBinding('http2'): the namespace has no Rust implementation yet` appears in
the output of **335** failing files on `c236ee9c`, which makes it the largest family
in the suite and the one this document previously did not size at all. It is not in
the `FAMILIES` table above because that table predates the count; it is measured by
substring over the recorded run.

It is namespace absence, not a partial implementation: the same message names the
binding on every file, so this is a whole `http2` rather than a tail patch. Note
that `nghttp2` is **not** vendored under `rustnode/vendor/` (which holds
`libnode-js`, `llhttp`, `merve` and `sqlite`) and no crate in the workspace depends
on it, so building this means adding the implementation of the HTTP/2 protocol
itself, not only a binding layer over an existing parser. Plan it as a subsystem.

### `tls_wrap` — the namespace landed; 82 files still fail on members

**This section used to describe a 646-file family and is now mostly history.** On
`c236ee9c` the namespace is registered (`crates/rn-bind-tls`) and **0** files fail
with `internalBinding('tls_wrap'): the namespace has no Rust implementation yet`.
What remains is narrower: **82 files** fail on deferred members, 72 on
`enableSessionCallbacks is not implemented yet` and 11 on
`setALPNProtocols is not implemented yet` (one file carries both).

That is the predicted shape of a partial TLS stack, and it is worth stating because
the old text argued the opposite conclusion — that a partial handle would "fail
deeper and less legibly than the current honest 'no implementation yet'". What is
measurable here is the second half of that prediction, and it is the reverse: the 82
remaining files fail with the missing member named in plain text
(`Error: enableSessionCallbacks is not implemented yet: … (tls_wrap increment 4)`),
not with an opaque inner error. The namespace is no longer the reason any file fails.

The remaining member work is still OpenSSL surface: `TLSWrap` is a `StreamBase`
whose `DoWrite`/`DoRead` are `SSL_write`/`SSL_read` against an `SSL_CTX` from a
`SecureContext`, plus `SSL_do_handshake`, the `SSL_get_error` retry machine, session
resumption, SNI callbacks, ALPN, OCSP and the session-ticket keys. `lib/internal/tls/wrap.js`
proxies **16** handle methods (`ref`, `unref`, `hasRef`, `open`, `bind`, `listen`,
`connect`, `bind6`, `connect6`, `getsockname`, `getpeername`, `setNoDelay`,
`setKeepAlive`, `setSimultaneousAccepts`, `setBlocking`, `setPendingInstances`) into
a live SSL object. The two named members are the next increment, not the whole
stack.

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
zero between `52f79555` and `f0649774`.

### timeouts — 188 files

A timeout is a failure: the process was killed and never stated a verdict. The
count is load-sensitive, so treat a file that changed outcome *and* timed out on
either side as noise until re-run alone. `--timeout` raises the per-file limit.

The count rose from 114 to 188, which is the `node:test` fix at work: a file that
used to exit 0 while its subtests failed now sometimes hangs instead of exiting,
and a hang is now recorded as a failure rather than a pass.

### `fs.cp` — 28 files left, from two bugs to one

| files | failure |
| --- | --- |
| 28 | `cpSyncCopyDir is not a function` — `-r` recursion is still declared deferred |

The other bug — `Method Promise.prototype.then called on incompatible receiver
[object BigInt64Array]` in `fs/promises`, 19 files — is **closed**, verified by
running `fs/promises.cp` successfully on that tree. That one needed no async
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
| "638 files — `tls_wrap`" | 646 on the `f0649774` run. Superseded again: on `c236ee9c` the namespace is implemented and **0** files fail on namespace absence; 82 fail on two deferred members. |
| "a partial TLS handle would fail deeper and less legibly than 'no implementation yet'" | The remaining 82 files fail with the missing member named in the message — `Error: enableSessionCallbacks is not implemented yet: … (tls_wrap increment 4)` — rather than an opaque inner error, so the failure is shallow and legible. (The 646 namespace failures were closed by more than this change, so they are not attributed to it here.) |
| "148 files — strict equal" | 196 on the latest full run (151 on the #51 tree). The bucket grows as real failures stop being hidden. |
| "116 files — `WorkerImpl`" | 123 on the #51 tree, **0 on `f0649774`** — `worker_threads` works; see the closed-family rows above. |
| "85 / 94 files — timeouts" | 188 on the latest full run. The old figures were load-, binary- and rule-dependent. |
| "17 + 12 files — `ReadFileJob` / `getWasmCompileCacheEntry`" | `ReadFileJob` is 0 after #46; the wasm-cache count is unmeasured, for the reason above. |
| "~110 files — deferred asymmetric crypto" | Unmeasured; see above. |
| "27 files — `--snapshot-blob`" | 11 on the latest full run. The old "27" counted files *mentioning* the flag, but only 11 fail because the option was refused. |
| "12 files — `locks`" | 17 on the latest full run, and the consumer is the Web Locks API, not `--experimental-locks`. |
| "20 files — `zstd is not implemented`" | 0: closed by #21. See the zstd section. |
| "fs.cp `then()` on a `BigInt64Array` — 19 files" | 0 on `f0649774`: `fs/promises.cp` works. Verified by running it. |
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

### Running the oracle

The tool takes any runtime through `--node`, so the oracle is the same command with a
different binary.

**The build this section used to name is gone.** The oracle for every figure above
was a source build of the pin at `/home/ubuntu/oracle-node`, with its release binary
at `out/Release/node` — a ~44 min `./configure && make -j8` of
`f344e7f552e3656bd37517151c5dc87d22b33771` that reported `v28.0.0-pre`, V8
`15.6.75.33-node.11`. That directory has been removed from the machine, along with
the `/workspace/node` symlink that pointed at it. Nothing else on the filesystem is
Node 28 except Cursor's own bundled binaries; `node` on `PATH` is `v22.23.4` and is
still **not** a valid oracle.

**Use the official Node 28 nightly instead.** It is a published binary rather than a
build of the pin, and it is the current stand-in:

| | |
| --- | --- |
| binary | `/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node` |
| version | `v28.0.0-nightly20261111e8c1160d20`, V8 `15.6.75.50-node.11` |
| size / mtime | 158363856 bytes, 2026-11-11T11:02Z |
| commit | `768315cf71`, **3 commits behind** the pin `f344e7f552` |

Because it lives under `/tmp`, treat its presence as ephemeral: if the path is
absent, re-fetch that nightly build rather than concluding that no Node 28 oracle
can be had.

**The three-commit gap: what it does and does not disqualify.** `768315cf71` is an
ancestor of `f344e7f552`; the three commits between them touch only
`lib/stream.js`, `lib/stream/promises.js`, `src/compile_cache.*`, `src/node_sea.cc`,
`src/node_modules.cc`, `src/node_util.cc`, `src/env.*`, and SEA/stream tests. Nothing
in `lib/os.js`, `src/node_os.cc`, `src/node_env_var.cc`, or libuv is affected. So the
nightly is **behaviourally identical to the pin for interface, environment, and
error-path questions**, and it is **not identical for stream or SEA questions** —
`test-stream-*`, `test-sea-*`, `test-compile-cache-*`, and anything that reads
`process.env` through a path those commits changed. For a question in that second
group, rebuild the pin from scratch; for everything else, the nightly is a valid
oracle and its answers need no caveat.

Confirm the binary you have before quoting a result:

```bash
/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node -v
# v28.0.0-nightly20261111e8c1160d20  (V8 15.6.75.50-node.11)
```

Run the files rustnode fails through it. `--node` is the only switch needed: the
tool applies the same `// Flags:` handling, `TEST_*` environment and four-marker
rule to whichever binary it is given, so the two runs are comparable by
construction. `--tests` still needs a copy of the pinned `test/` tree; the
"Reproducing any row" recipe above creates one at `/tmp/node-pin`:

```bash
python3 tools/test-tail-map.py run \
    --node /tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node \
    --tests /tmp/node-pin/test --out /tmp/oracle.json \
    --jobs 8 --timeout 30 $(sed 's|^|--only |' /tmp/rustnode-failures.txt)
python3 tools/test-tail-map.py score /tmp/oracle.json
```

`internet` must stay out of that list: it may need network, and a network-dependent
result is not evidence in either direction.

**Rebuilding the pin from scratch is the fallback, not the default.** The build it
describes is no longer present, so this is a from-zero recipe, not a repair. It
takes ~44 min on 8 cores and is only worth doing when the question falls in the
stream/SEA group above. The tree must live **outside** the herdr checkout (its
`deps/crates` has its own `Cargo.toml`, which the herdr workspace would otherwise
claim) — that is why the original tree was at `/home/ubuntu/oracle-node` with
`/workspace/node` symlinked to it — and `make` needs `RUSTUP_TOOLCHAIN=1.96.1` or it
fails on `edition2024`:

```bash
mkdir -p /home/ubuntu/oracle-node && cd /home/ubuntu/oracle-node
git init -q . && git remote add origin https://github.com/nodejs/node
git fetch --depth 1 origin f344e7f552e3656bd37517151c5dc87d22b33771
git checkout -q FETCH_HEAD
export RUSTUP_TOOLCHAIN=1.96.1
./configure && make -j8
out/Release/node -v                   # must print v28.0.0-pre
```

`./tools/check.sh --quick` is the gate; `--quick` skips only the workspace test
sweep. There is no `GATE` variable in this repository.
