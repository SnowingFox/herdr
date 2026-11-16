# The Node oracle

Differential tests compare rustnode against a real Node binary. That binary is
**not** whatever `node` resolves to on `PATH`: it is the build
`tools/node-pin.toml` pins, and every test resolves it through
`tools/node-oracle` (`rn-node-oracle`) rather than spawning `node` itself.

## Why this exists

`tools/node-pin.toml` pins Node 28 at commit `f344e7f552e`. GitHub's
`ubuntu-latest` ships Node 22 on `PATH`. The two disagree about the crypto
surface in both directions, so `rn-bind-crypto/tests/differential.rs` failed on
CI while passing locally against the right binary — and neither log said which
engine it had measured. The tests were not too weak; they were testing a
different Node than the one rustnode targets.

## The one way to find the oracle

Resolution order, implemented in `tools/node-oracle/src/lib.rs`:

1. `RN_NODE_ORACLE` — an absolute path to the pinned binary.
2. `[node] oracle` in `tools/node-pin.toml`, expanded to `<dir>/bin/node`.
3. `node` on `PATH`.

`tools/check.sh` and the rustnode CI workflow both export `RN_NODE_ORACLE`
before running tests, so a gate run never depends on step 3. Every test prints

```
<what is being compared>: using oracle: <path> (<version> via <source>) pin <pinned version>
```

on success, and a failing assertion repeats the same line. The line is written
straight to stderr, not through `eprintln!`, because libtest discards captured
output for a passing test — a green log would otherwise never say what it
measured.

## Skip versus fail

| Situation | Behaviour |
| --- | --- |
| The oracle is the pinned build | Compare; print the oracle line. |
| No oracle anywhere | Skip, loudly. The vector and recorded-expectation tests still run. |
| A Node that is not the pinned build | **Fail.** |
| The pin file is unreadable | **Fail.** |

A version mismatch fails rather than skipping because a differential test
against a different Node is a *different test*, not a weaker one. Skipping would
be quieter than failing but equally dishonest: the gate would report success
without having performed the comparison at all, which is exactly how the Node 22
problem went unnoticed. `RN_NODE_ORACLE_ALLOW_VERSION_MISMATCH=1` downgrades the
mismatch to a warning for deliberate experiments, and the oracle line then says
`MISMATCH` so the log can never read as pinned-oracle evidence.

## Getting the binary

```bash
./tools/fetch-node-oracle.sh          # download into the pin's `oracle` directory
./tools/fetch-node-oracle.sh --check  # exit 3 if it is absent or the wrong version
```

The script is idempotent and verifies the tarball against the distribution's
`SHASUMS256.txt` when that manifest is published. `tools/check.sh` and CI call
it automatically.

## Re-pinning

When `[node] version` moves, update `[node] oracle` and `[node] oracle_version`
in the same commit. `oracle_version` records the exact string the binary reports
to `--version`; a nightly embeds its date and short SHA, so it is not derivable
from the release version. A mismatch between the two fails the pin's own unit
test (`tools/node-oracle/src/lib.rs`), which reads the real pin file.
