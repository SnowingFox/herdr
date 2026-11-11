#!/usr/bin/env bash
# Measures the `test-http2*` family under the four-marker rule.
#
#   ./tools/http2-measure.sh <results-dir> [--tests <node-test-dir>]
#
# A file passes only when all five hold:
#
#   1. the process exits 0;
#   2. no `✖` anywhere in stdout or stderr;
#   3. no `Uncaught` anywhere in stdout or stderr (it can appear mid-line, so this
#      is a substring test, not a line-prefix test);
#   4. no `1..0 # Skipped` at column zero;
#   5. no `: # SKIP` anywhere.
#
# Exit status alone is not a pass: TAP files report failures inside their output
# and a `common.skip()` exits 0, so an exit-code count overstates the result. That
# is what these markers exist to catch.
#
# Per-file lines are written as `exit | markers | verdict`, then a summary.
#
# Exit codes:
#   0 every selected file was measured (whatever the verdicts were)
#   1 the harness could not be built or the test tree is missing
#   2 usage error
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

results="${1:-}"
shift || true
tests_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tests)
      tests_dir="${2:?--tests needs a directory}"
      shift 2
      ;;
    *)
      echo "usage: tools/http2-measure.sh <results-dir> [--tests <dir>]" >&2
      exit 2
      ;;
  esac
done

if [ -z "$results" ]; then
  echo "usage: tools/http2-measure.sh <results-dir> [--tests <dir>]" >&2
  exit 2
fi

binary="target/debug/rustnode"
if [ ! -x "$binary" ]; then
  echo "rustnode: $binary is not executable; build it first" >&2
  exit 1
fi

if [ -z "$tests_dir" ]; then
  cache="${RUSTNODE_TEST_CACHE:-${TMPDIR:-/tmp}}/rustnode-node-test"
  tests_dir="$cache/test"
fi
if [ ! -d "$tests_dir/parallel" ]; then
  echo "rustnode: no Node test tree at $tests_dir" >&2
  exit 1
fi

mkdir -p "$results"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The flags line of a Node test file, as the runtime should receive it. Node's own
# runner reads `// Flags: --x --y` from the first lines.
flags_of() {
  awk '/^\/\/ Flags:/{sub(/^\/\/ Flags:[[:space:]]*/, ""); print; exit}' "$1"
}

measure_one() {
  local file="$1"
  local name="${file#"$tests_dir"/}"
  local flags
  flags="$(flags_of "$file")"
  # shellcheck disable=SC2086 # the flags line is a space-separated list on purpose
  timeout 60 "$binary" $flags "$file" >"$work/out" 2>"$work/err"
  local status=$?
  local markers=""
  if grep -q '✖' "$work/out" "$work/err" 2>/dev/null; then
    markers="${markers}X"
  fi
  if grep -q 'Uncaught' "$work/out" "$work/err" 2>/dev/null; then
    markers="${markers}U"
  fi
  if grep -q '^1\.\.0 # Skipped' "$work/out" "$work/err" 2>/dev/null; then
    markers="${markers}S0"
  fi
  if grep -q ': # SKIP' "$work/out" "$work/err" 2>/dev/null; then
    markers="${markers}SK"
  fi
  local verdict="PASS"
  if [ "$status" -ne 0 ] || [ -n "$markers" ]; then
    verdict="FAIL"
  fi
  printf '%s | %s | %s\n' "$name" "$status" "${markers:-none} | $verdict"
  if [ "$verdict" = "PASS" ]; then
    return 0
  fi
  return 1
}

mapfile -t files < <(ls "$tests_dir"/parallel/test-http2*.js | sort)
total="${#files[@]}"
pass=0
fail=0
printf 'HEAD %s\n' "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
printf 'binary %s mtime %s\n' "$binary" "$(date -r "$binary" -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)"
printf 'files %d\n' "$total"
# Written to a file and printed afterwards rather than piped into `tee`: a
# pipeline would put the loop in a subshell, where the counters do not survive to
# be reported.
for file in "${files[@]}"; do
  if measure_one "$file"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
  fi
done >"$results/http2-files.txt"
cat "$results/http2-files.txt"

printf '\nPASS=%s FAIL=%s TOTAL=%s\n' "$pass" "$fail" "$total"
exit 0
