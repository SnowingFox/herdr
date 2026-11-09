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
cargo run -q -p rn-compat -- contracts

step "the vendored JavaScript is unchanged"
./tools/verify-libjs.sh

printf '\nall checks passed\n'
