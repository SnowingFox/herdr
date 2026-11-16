#!/usr/bin/env bash
# Records Bun 1.4.4's behaviour for the encoding/parsing corpus.
#
# The corpus lives in `tests/case_script.rs` and the recorded answer in
# `tests/oracle/expected.json`. Re-record with:
#
#   crates/rn-bun-encoding/tests/oracle/record.sh
#
# and review the diff before committing: the file is the pinned measurement, so a
# change in it is a claim that Bun's behaviour changed (a new Bun version) or that
# a case was added. `differential.rs` fails when the file and the oracle disagree,
# which is what stops it from becoming a fossil.
#
# The corpus text comes from `record --print`, a Rust helper in this crate, so the
# two sides cannot drift: the same generated string is what both runtimes run.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$root"

BUN="${RUSTNODE_BUN_ORACLE:-/tmp/bun-dl/bun-linux-x64/bun}"
if [ ! -x "$BUN" ]; then
  echo "record.sh: no Bun binary at $BUN; set RUSTNODE_BUN_ORACLE" >&2
  exit 2
fi

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

# libtest frames stdout with its own progress lines, so the harness is written to
# a file and read back here.
harness="$(mktemp)"
RN_PRINT_HARNESS=1 RN_HARNESS_OUT="$harness" \
  cargo test --quiet -p rn-bun-encoding --test harness -- --nocapture >/dev/null 2>&1 || true
script="$(cat "$harness")"
rm -f "$harness"
if [ -z "$script" ]; then
  echo "record.sh: the harness came back empty" >&2
  exit 1
fi

"$BUN" -e "$script" > crates/rn-bun-encoding/tests/oracle/expected.json.tmp
mv crates/rn-bun-encoding/tests/oracle/expected.json.tmp \
   crates/rn-bun-encoding/tests/oracle/expected.json
echo "recorded $(python3 -c 'import json,sys; print(len(json.load(open("crates/rn-bun-encoding/tests/oracle/expected.json"))))') cases"
