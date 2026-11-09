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

**A run that measured something exits 0 even when nothing passes.** The number
is the deliverable early on. Gate on `report` or on the result files, not on the
runner's exit code.

## Deliberately not handled

- Compiled fixtures (`addons`, `js-native-api`, `node-api`, `cctest`, `fuzzers`)
  are not JavaScript and are not selected.
- Status files (`*.status`) and per-suite flags are ignored, so a test Node would
  skip for this platform is reported as a failure. That is the conservative
  direction: it never turns an unsupported feature into a pass.
- `--test-reporter` and other flags Node's runner adds conditionally are not
  injected; only the file's own `// Flags:` line is honoured.
- No retries and no flake detection. A test that is intermittent shows up as
  whatever it did in the run that recorded it.
