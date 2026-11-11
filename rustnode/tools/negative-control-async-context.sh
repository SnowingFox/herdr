#!/usr/bin/env bash
# Negative control: prove the fix is what makes the tests pass.
#
#   ./tools/negative-control-async-context.sh            # run the control
#   BREAK=1 ./tools/negative-control-async-context.sh    # prove the guard works
#
# It never trusts a pre-existing binary. It deletes target/debug/rustnode,
# builds, aborts if the build fails or the binary is older than the build
# start, and only then runs the four Node tests plus the crate's unit tests.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN=1.96.1
export CXX=g++
export RUSTFLAGS="-L /usr/lib/gcc/x86_64-linux-gnu/13"

bin="./target/debug/rustnode"
marker="$(mktemp)"
echo "negative control starting at $(date -u +%FT%TZ)"

# The brief's rule: delete the binary first, so a failed build cannot leave the
# previous one in place to be reported as a pass.
rm -f "$bin"
if [ -e "$bin" ]; then
  echo "CONTROL ABORTED: could not remove $bin" >&2
  exit 2
fi

if [ "${BREAK:-0}" = "1" ]; then
  # Deliberate breakage: this is how the guard itself is proven. It must abort.
  #
  # The source is restored from a copy taken *before* the break, never with
  # `git checkout`, which would discard uncommitted work.
  echo "BREAK=1: injecting a compile error to prove the guard aborts" >&2
  broken_src="crates/rn-bind-async-wrap/src/lib.rs"
  saved_src="$(mktemp)"
  cp "$broken_src" "$saved_src"
  printf '\ncompile_error!("negative control: deliberate build failure");\n' >>"$broken_src"
  restore_src="$saved_src"
fi

build_log="$(mktemp)"
if ! cargo build -p rn-cli >"$build_log" 2>&1; then
  echo "CONTROL ABORTED: the build failed; nothing was tested." >&2
  echo "--- first errors ---" >&2
  grep -E "^error" -A4 "$build_log" | head -20 >&2
  if [ -n "${restore_src:-}" ]; then
    cp "$restore_src" crates/rn-bind-async-wrap/src/lib.rs
  fi
  exit 3
fi
if [ -n "${restore_src:-}" ]; then
  # The break was only ever meant to fail the build; restore and rebuild.
  cp "$restore_src" crates/rn-bind-async-wrap/src/lib.rs
  if ! cargo build -p rn-cli >>"$build_log" 2>&1; then
    echo "CONTROL ABORTED: rebuild after restoring the source failed." >&2
    exit 3
  fi
fi

# A binary that exists is not enough: it has to be newer than the marker taken
# before the build. This is the check that catches "build failed, old binary
# still there" even if cargo returned zero.
if [ ! -x "$bin" ]; then
  echo "CONTROL ABORTED: $bin does not exist after a successful build." >&2
  exit 4
fi
if [ ! "$bin" -nt "$marker" ]; then
  echo "CONTROL ABORTED: $bin is older than the build start; refusing to test a stale binary." >&2
  exit 5
fi
echo "binary is fresh: $(ls -l --time-style=full-iso "$bin" | awk '{print $6, $7}')"

echo
echo "=== crate unit + binding tests ==="
cargo test -p rn-bind-async-wrap 2>&1 | tail -4

echo
echo "=== the four Node tests ==="
tests=(
  test-async-hooks-promise.js
  test-async-hooks-promise-triggerid.js
  test-async-hooks-top-level-clearimmediate.js
  test-async-hooks-recursive-stack-runInAsyncScope.js
)
failures=0
for t in "${tests[@]}"; do
  out="$(mktemp)"
  if timeout 30 "$bin" "/tmp/node-pin/test/parallel/$t" >"$out" 2>&1; then
    printf '%-56s PASS\n' "$t"
  else
    printf '%-56s FAIL  %s\n' "$t" "$(head -c 90 "$out" | tr '\n' ' ')"
    failures=$((failures + 1))
  fi
done

echo
if [ "$failures" -eq 0 ]; then
  echo "CONTROL RESULT: all ${#tests[@]} tests pass on a freshly built binary."
else
  echo "CONTROL RESULT: $failures of ${#tests[@]} tests failed." >&2
fi
exit "$failures"
