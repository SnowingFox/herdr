#!/usr/bin/env bash
# The `worker_threads` negative control, and the evidence for its numbers.
#
#   ./tools/worker-threads-check.sh before   # run the control against a base ref
#   ./tools/worker-threads-check.sh after    # run the control against the working tree
#
# # Why this exists
#
# A "before/after" claim is only worth something if the two runs were produced by
# *different binaries*, and the harness makes that easy to get wrong: `rn-harness
# report` keeps the newest result per file per directory, so re-running into the
# same directory with a rebuilt binary silently mixes the two. This script builds
# into a fresh `CARGO_TARGET_DIR`, refuses to continue if the build failed, and
# refuses to test a binary older than the build it just started.
#
# It also aborts rather than reporting a number if the binary does not contain the
# feature under test, so "after" cannot pass by accident on a stale tree.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

phase="${1:-after}"
case "$phase" in
  before | after) ;;
  *)
    echo "usage: $0 [before|after]" >&2
    exit 2
    ;;
esac

tests_dir="${RUSTNODE_TEST_DIR:-/tmp/nodetest/test}"
if [ ! -d "$tests_dir" ]; then
  echo "rustnode: ${tests_dir} is not a directory; set RUSTNODE_TEST_DIR" >&2
  exit 2
fi

# A separate target directory per phase so the two binaries cannot overwrite each
# other, and a separate results directory because the harness merges per file.
target="${RUSTNODE_WORKER_TARGET:-/tmp/worker-threads-target-$phase}"
results="${RUSTNODE_WORKER_RESULTS:-/tmp/worker-threads-results-$phase}"
worktree="${RUSTNODE_WORKER_TREE:-}"

if [ "$phase" = "before" ]; then
  if [ -z "$worktree" ]; then
    echo "rustnode: set RUSTNODE_WORKER_TREE to a base-ref checkout for 'before'" >&2
    exit 2
  fi
  root="$(cd "$worktree" && pwd)"
  cd "$root"
fi

rm -rf "$results"

# The marker timestamp is taken *before* the build starts, so any binary the build
# produces is necessarily newer than it. A binary older than this cannot be the
# product of this build, which is the stale-artifact case the mtime check exists
# to catch.
marker="/tmp/worker-threads-build-start-$phase"
rm -f "$marker"
touch "$marker"

echo "== building (phase=$phase, target=$target)"
if ! CARGO_TARGET_DIR="$target" cargo build -p rn-cli -p rn-harness; then
  echo "rustnode: the build failed; refusing to measure anything" >&2
  exit 1
fi

binary="$target/debug/rustnode"
harness="$target/debug/rn-harness"
for artifact in "$binary" "$harness"; do
  if [ ! -x "$artifact" ]; then
    echo "rustnode: ${artifact} was not produced by the build" >&2
    exit 1
  fi
  if [ ! "$artifact" -nt "$marker" ]; then
    echo "rustnode: ${artifact} is older than this build; it is a stale artifact" >&2
    exit 1
  fi
done

# The control itself: does a worker run at all, and does it print? On the base ref
# this exits 1 with `WorkerImpl is not a constructor`, which is the failure the
# work exists to remove. Assert the *behaviour*, not the error text, so the check
# stays meaningful if Node's wording changes.
echo "== negative control"
control_out="$("$binary" -e '
const { Worker } = require("worker_threads");
const w = new Worker("console.log(\"worker-ran\")", { eval: true });
w.on("exit", () => process.exit(0));
w.on("error", () => process.exit(1));
' 2>&1)"
control_status=$?
if [ "$control_status" -ne 0 ] || ! printf '%s' "$control_out" | grep -q 'worker-ran'; then
  echo "rustnode: the control FAILED (status=${control_status})"
  printf '%s\n' "$control_out" | head -5
  exit 1
fi
echo "rustnode: the control PASSED (a worker ran and printed)"

echo "== measuring --filter test-worker-"
"$harness" run \
  --node "$binary" \
  --tests "$tests_dir" \
  --results "$results" \
  --filter test-worker-
"$harness" report --results "$results"
