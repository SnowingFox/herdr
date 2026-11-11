#!/usr/bin/env bash
# The gate every commit has to pass, in one command.
#
#   ./tools/check.sh            # full gate
#   ./tools/check.sh --quick    # skip the workspace test sweep
#
# The order matters. `cargo build -p rn-cli` comes before the tests because
# several crates run the real binary from their integration tests: without it
# they would silently test a stale build, which has already masked a real bug.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
# `vendor/merve` is C++ and cc-rs picks `c++`, which on this image resolves to
# clang++ without the GCC C++ include paths, so it fails on `<cstddef>`. g++
# is installed and works. Pinning it here keeps the gate reproducible instead
# of depending on what `c++` happens to be.
export CXX="${CXX:-g++}"
# Linking a g++-compiled object needs libstdc++, whose `.so` symlink lives only
# in the GCC version directory here, not on the default linker search path.
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"
quick=0
[ "${1:-}" = "--quick" ] && quick=1

step() { printf '\n== %s ==\n' "$1"; }

step "the binding matcher still classifies crates correctly"
# Runs before the regeneration, and as its own plain statement: a bare command's
# status is the gate's status under `set -e`, whereas piping it into `tee` or
# capturing it in `$( )` would let a failing matcher fall through to a green
# gate. The tests are what justify the scanner's complexity, so they have to be
# able to fail this gate rather than being runnable only by hand.
./tools/regen-bindings.test.sh

step "every opt-in control still has a verdict to report"
# The controls that build the CLI or drive a real Node surface stay opt-in,
# because running them all here would add minutes to every commit. What does not
# stay opt-in is the property that makes them worth having: that each one
# distinguishes success from failure by exit status rather than by printing.
# `cipher-negative-control.sh` shipped documenting exit 2 while exiting 1, and
# nothing caught it because nothing read the script at all. This reads every
# control without running it, and self-tests against the defect shapes so the
# check itself cannot rot into a string of oks.
#
# A bare statement, for the same reason as the line above.
./tools/controls.test.sh

step "regenerating the binding registry"
./tools/regen-bindings.sh

step "building the workspace and the CLI binary"
# The CLI binary is built explicitly: integration tests that spawn it read
# `target/debug/rustnode`, and `cargo test -p <crate>` does not rebuild it.
cargo build --workspace
cargo build -p rn-cli

step "the per-context globals audit"
# Every assertion reads the rustnode realm (`primordials`, `DOMException`, the
# per-context symbol tables), so this needs the binary built above and cannot run
# with system node. It lived outside the gate and reported 44/44 for a while
# while 14 of those checks compared a value to itself.
#
# It runs *before* the cipher self-test, not after. That self-test deletes
# `target/debug/rustnode`, fails the build on purpose, then restores the binary
# by `cp`-ing a `mktemp` backup into the now-absent path, which gives it mode
# 0600 — no execute bit. Cargo restores the mode on any real rebuild, so master's
# remaining steps never noticed: the next one is `cargo test`, which rebuilds.
# This is the first step that execs the binary directly, so running it first
# keeps the audit's own result from depending on that restore behaviour.
./target/debug/rustnode tools/per-context-audit.js

step "the per-context globals still behave as Node's do"
# The control for the per-context work: DOMException is a real `Error`, the
# messaging binding hands back the same class, and `structuredClone` survives the
# per-isolate symbols. It ships as a plain statement for the same reason as the
# matcher tests above -- a bare command's status is the gate's status under
# `set -e`, while `| tee` or `$( )` would let a failing control fall through to a
# green gate. That is not hypothetical here: this control reported a stale PASS
# once already, which is why it re-checks the build it used.
#
# It belongs after the build because every assertion runs against the rustnode
# realm, and warm it costs ~0.4s, so there is no reason to leave it opt-in.
#
# It runs before the cipher self-test for the same reason the audit above does:
# that self-test restores `target/debug/rustnode` by `cp`-ing a `mktemp` backup
# into the path it deleted, which recreates the file mode 0600. This control
# execs the binary directly, so it has to run while the binary is still
# executable. `cargo test` later rebuilds and restores the mode, which is why
# nothing after the self-test noticed.
./tools/per-context-control.sh

step "the cipher control still reports a void run as a void run"
# The control's exit contract — 3 for "the build failed, so there is no
# verdict", distinct from 1 for "the control misbehaved" — is what stops a
# build failure being reported as a failed control. That was a real defect: a
# `compile_error!` used to exit 1 and print `RESULT: UNEXPECTED`. The contract
# is only worth having if something exercises it, so the self-test runs here
# rather than being a diagnostic nobody invokes. It injects a real
# `compile_error!`, so it sits after the build (warm cache makes it ~1s) and
# before the tests and lints, which would fail loudly if the restore ever left
# the source tree modified.
./tools/cipher-negative-control.sh --self-test

step "the exit handler can still fail a process"
# `common.mustCall` fails a file by calling `process.exit(1)` from inside a
# `process.on('exit')` listener. Before #60 wired the emit, that listener never
# ran on a natural loop exit, so ~2850 files under `test/parallel` reported a
# pass without checking anything and the suite's headline number was overstated.
#
# The Rust suite guards the emit itself (`a_natural_exit_runs_the_exit_handlers`
# and eight neighbours), but not this composition: `same_as_node` asserts
# `status.success()` on *both* runtimes, so no test there can express "exits 1",
# and the one test that calls `process.exit()` inside a handler passes no code.
# A regression where the emit runs but a re-entrant exit's code is dropped would
# leave every one of those green while `mustCall` silently became a no-op again.
#
# `--mechanism` asserts exactly that pair and needs no Node test tree, so it can
# run on every machine. The full six-case matrix still needs Node's own
# `test/common` and stays opt-in; it passes on current master.
#
# The binary is made executable first. The cipher self-test above restores
# `target/debug/rustnode` by `cp`-ing a `mktemp` backup into the path it deleted,
# which leaves the file mode 0600, and the next `cargo` invocation is what
# repairs it. `per-context-control.sh` and its audit work around the same thing
# by running earlier; this step cannot, because a control that execs a
# non-executable binary reports exit 126 and reads as a *runtime* failure rather
# than a missing mode bit. Restoring the mode here is the narrow fix: it makes
# the step independent of how the preceding self-test restored the binary,
# instead of depending on its restore behaviour staying what it is today.
chmod +x target/debug/rustnode
./tools/mustcall-negative-control.sh --mechanism

mustcall_tests="${RUSTNODE_TEST_CACHE:-${TMPDIR:-/tmp}}/rustnode-node-test/test"
if [ -f "$mustcall_tests/common/index.js" ]; then
  echo "mustcall control: a Node test tree is present at $mustcall_tests;"
  echo "mustcall control: ./tools/mustcall-negative-control.sh --quick --tests $mustcall_tests"
  echo "mustcall control: runs the full six-case matrix as well"
fi

if [ "$quick" -eq 0 ]; then
  step "running the workspace tests"
  cargo test --workspace
fi

step "formatting"
cargo fmt --all -- --check

step "lints"
cargo clippy --workspace --all-targets -- -D warnings

step "binding shapes against the recorded contracts"
# `--baseline` is the coverage ratchet: an unregistered namespace is bring-up
# state and passes, but one that used to cover its contract and no longer does
# is a regression. Without it a namespace could silently drop to a placeholder.
cargo run -q -p rn-compat -- contracts --baseline contracts/complete-namespaces.txt

step "deferred members reached at module scope"
# A declared deferral passes the contract check by design, so this is the only
# gate that catches a member `lib/**` calls while a module loads. It is part of
# the gate because it silently failed open once already.
./tools/deferred-reach.py

step "the smoke classifier still tells a gap from a defect"
# The classifier decides whether a failure counts against the runtime or is
# merely waiting on a binding. It got that wrong once, turning a missing
# feature into a skip, so the rule is pinned rather than trusted.
python3 tools/smoke.py --self-test

step "the vendored JavaScript is unchanged"
./tools/verify-libjs.sh

step "the vendored llhttp is unchanged"
# The HTTP parser is C copied from Node's tree and never patched: a local edit
# would change parse behaviour away from the one Node ships, which is the only
# thing the binding exists to reproduce.
./tools/verify-llhttp.sh

step "the vendored merve is unchanged"
# Same reasoning one namespace over: the CommonJS export analysis decides what an
# ESM `import` of a CommonJS file sees, and a local edit to the lexer would
# change that answer without failing anything else.
./tools/verify-merve.sh

step "the vendored nghttp2 is unchanged"
# HTTP/2's frame state machine, HPACK tables and error strings are `node:http2`'s
# compatibility surface, so the C library is held to the pinned Node revision
# rather than to a system libnghttp2 whose version depends on the host.
./tools/verify-nghttp2.sh

step "the vendored SQLite is unchanged"
# SQL semantics are `node:sqlite`'s whole compatibility surface, so the
# amalgamation is held to the pinned Node revision rather than to whatever a
# system library happens to be.
./tools/verify-sqlite.sh

printf '\nall checks passed\n'
