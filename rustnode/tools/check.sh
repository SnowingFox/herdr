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
quick=0
[ "${1:-}" = "--quick" ] && quick=1

step() { printf '\n== %s ==\n' "$1"; }

step "regenerating the binding registry"
./tools/regen-bindings.sh

step "building the workspace and the CLI binary"
# The CLI binary is built explicitly: integration tests that spawn it read
# `target/debug/rustnode`, and `cargo test -p <crate>` does not rebuild it.
cargo build --workspace
cargo build -p rn-cli

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

printf '\nall checks passed\n'
