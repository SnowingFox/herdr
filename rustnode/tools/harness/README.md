# rn-harness

Measures how much of Node's own test suite rustnode passes, per subsystem.

The user-facing explanation of all three compatibility gates lives in
[`../../docs/compat-status.md`](../../docs/compat-status.md). This file is the
crate's own note on how it works and what it deliberately does not do.

## Two subcommands

```bash
cargo run -p rn-harness -- run  --tests /tmp/node/test --smoke
cargo run -p rn-harness -- report [--json]
```

`tools/run-node-tests.sh` wraps both, builds rustnode, and fetches the test tree
if you have not got one.

## Layout

| Module | Responsibility |
| --- | --- |
| `select` | finds `test-*.js` / `test-*.mjs` under a `test/` tree, reads `// Flags:` |
| `runner` | executes each file with a timeout and records the outcome |
| `result` | the recorded shape, shared by both sides |
| `dashboard` | folds result files into the per-cluster table |

## Design notes

**The test tree is an argument, never a copy.** It is 103 MB and tied to a Node
revision; vendoring it would put the specification inside the thing under test.

**Selection is deterministic.** Suites are walked in a fixed order and files are
sorted, so `--limit` picks the same files on every run and two runs are
comparable. `--only` resolves the exact paths given and errors on a missing one,
so a named subset cannot silently shrink when the test tree changes.

**Parallel-safe suites run wide, `sequential` runs alone.** Node splits its own
suite that way because those tests do not tolerate a shared machine.

**Every file is a fresh process.** The runtime under test cannot be trusted to
exit, so a wall-clock timeout kills the child's process group — otherwise a
forked grandchild keeps the output pipes open and the "timeout" never fires.

**One vote per test file in the dashboard.** Result files accumulate, and a file
that was failing in an old run but passes now must read as passing without
deleting history. The newest recorded outcome wins; totals count files, not
recorded rows.

**Passed, skipped and failed are three different things.** Skips arrive in three
forms, and all three are detected:

| form | what prints | exits |
| --- | --- | --- |
| `common.skip()` in `test/parallel/**` | `1..0 # Skipped: <reason>` | 0 |
| `common.skip()` in `test/known_issues/**` | `1..0 # Skipped: <reason>` | 1 |
| every test in a `node:test` file skipped | `﹣ <anonymous> (0.8ms) # SKIP` | 0 |

The exit code cannot classify any of them, which is why the markers are read
directly. The plan line is matched only in column zero, because `console.log`
always puts it there and an indented mention in a diagnostic must not count. It
is scanned from the **whole** stdout stream, not the truncated `stdout_head`.

The bare-glyph form is `﹣` (`U+FE63`, the reporter's `hyphen:minus`) at the start
of a line. It counts only when **nothing else ran**: no `✔`, no `▶` and no `✖`
anywhere, on an exit-0 row. That narrowness is deliberate, because the glyph
alone is not enough:

- a mixed file skips some tests and runs others — `test-runner-module-mocking.js`
  has 1 skip, 10 passes and 43 failures, and calling it a skip would hide 43 real
  failures;
- a `describe` whose children all skip still prints `✔ outer suite`, because the
  suite itself passed.

The glyph is keyed on rather than the `# SKIP` word because a skip carrying a
custom message prints `﹣ name # <reason>`, not `# SKIP`.

A skip is reported as its own outcome: it is neither a pass nor a failure, since
it asserts nothing. `report` prints `passed`, `skipped` and `failed` as separate
columns and computes the rate as `passed / (passed + failed)`, so skips are
excluded from either side. `passed + skipped + failed` always equals the total, a
cluster with nothing judged prints `—` instead of a `0.0%` that would read as
total failure, and the skipped files are listed so the exclusion is auditable.

**A file can exit 0 while reporting a failure.** Two disjoint mechanisms do
this, and both are detected from the same single scan of the whole stdout stream:

| the file uses | the failure appears as |
| --- | --- |
| plain `assert` (most of `test/parallel`) | `node:assert:16736: Uncaught AssertionError: ...` |
| `node:test` | `  ✖ inner fails` |

- **`Uncaught`** is the larger population. An assertion that escapes is printed
  to stdout and the process still exits 0, because the uncaught-exception path
  never sets the exit code. On a 400-file `test/parallel` sample 9 files did this;
  on the `test-crypto-key*`/`rsa*`/`ec*` family 16 of 31 harness-visible passes
  did. The word sits behind a location prefix, so it is matched where `Uncaught`
  is followed by an error name and a colon and is either at the start of the line
  or preceded by a `:<line-number>:` location. That location is what separates
  the runtime reporting its own error from a test echoing captured child output
  (`child stderr: Uncaught AssertionError: ...`), which stays a pass. A caught
  assertion — `assert.throws`, `try/catch` — prints nothing at all, so it is never
  involved.
- **`✖`** covers `node:test` files, which report failures as test results rather
  than exceptions. It is matched at the start of a line after leading whitespace
  and ANSI colour escapes, because a test that sets `FORCE_COLOR` (rustnode's own
  `test-runner-reporters.js` does) colourises its own output even when stdout is a
  pipe. This one is deliberately **rustnode-shaped**: real Node writes TAP
  (`not ok 2 - ...`) when stdout is piped and would never match. If rustnode
  switches to TAP output, this marker stops matching — the `Uncaught` rule is
  unaffected, which is why it carries most of the correction.

A row that exited 0 while reporting either kind of failure is counted as
**failed**, and `report` says how many of the failures were corrected this way so
the number is auditable rather than silent. This is a correction, not a fourth
column: `misreported` is always a subset of `failed`, and
`passed + skipped + failed == total` is unchanged.

Marker evidence is cumulative across builds. A recorded `misreported` value is
ORed with a scan of the row's recorded stdout rather than overriding it, so
strengthening the rule still applies to result files written by an older,
narrower build — which matters here, because the rule was extended once already
and the first version would have masked every `Uncaught` row.

**A run that measured something exits 0 even when nothing passes.** The number
is the deliverable early on. Gate on `report` or on the result files, not on the
runner's exit code.

## Deliberately not handled

- Compiled fixtures (`addons`, `js-native-api`, `node-api`, `cctest`, `fuzzers`)
  are not JavaScript and are not selected.
- Status files (`*.status`) and per-suite flags are ignored. A test Node's own
  runner would skip by status file is *not* detected as a skip; it runs, and is
  reported as whatever it does. Only the `1..0 # Skipped:` plan line that a test
  prints about itself is honoured. Teaching the harness to read `*.status` and
  the per-suite flag files is a separate decision, because it makes the recorded
  numbers depend on a second input tree and changes which files are comparable.
- `--test-reporter` and other flags Node's runner adds conditionally are not
  injected; only the file's own `// Flags:` line is honoured.
- No retries and no flake detection. A test that is intermittent shows up as
  whatever it did in the run that recorded it.
