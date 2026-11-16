#!/usr/bin/env bash
# Differential: V8 flags on the *command line*, rustnode against the oracle.
#
# The defect this measures: rustnode ran a hand-written allow-list, so 22 of the
# 24 V8 flags the oracle accepts exited 9 with `unsupported option`. Both
# binaries are invoked through a shared argv[0] because a `bad option` line is
# prefixed with it.
#
#   ./tools/v8-flags-diff.sh [path-to-oracle] [path-to-rustnode]
#
# Exit codes:
#   0  every case matched
#   1  at least one case differed
set -uo pipefail

oracle="${1:-/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node}"
rustnode="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/debug/rustnode}"

for binary in "$oracle" "$rustnode"; do
  if [ ! -x "$binary" ]; then
    echo "v8-flags-diff: $binary is not executable; refusing to report a verdict" >&2
    exit 1
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

run() {
  local binary="$1"
  shift
  bash -c '
    binary="$1"; shift
    exec -a /usr/local/bin/node "$binary" "$@"
  ' _ "$binary" "$@" 2>"$work/stderr" >"$work/stdout"
  printf '%s\n' "$?"
}

failures=0
checks=0

# One flag, run under both binaries with a script that proves the process got far
# enough to run user code.
#
# The script writes to stderr, not stdout: `--trace-gc-verbose` and
# `--print-bytecode` write to stdout, and the verbose GC trace interleaves with a
# script's own writes within a line.
case_() {
  local flag="$1"
  local script="process.stderr.write('script-ran\\n')"

  local oracle_status rustnode_status
  oracle_status="$(run "$oracle" "$flag" -e "$script")"
  cp "$work/stderr" "$work/oracle.stderr"
  rustnode_status="$(run "$rustnode" "$flag" -e "$script")"
  cp "$work/stderr" "$work/rustnode.stderr"

  checks=$((checks + 1))
  if [ "$oracle_status" = "$rustnode_status" ] &&
    cmp -s "$work/oracle.stderr" "$work/rustnode.stderr"; then
    printf 'ok   %s\n' "$flag"
    return
  fi
  failures=$((failures + 1))
  printf 'FAIL %s: exit %s vs %s\n' "$flag" "$oracle_status" "$rustnode_status"
  diff "$work/oracle.stderr" "$work/rustnode.stderr" | sed 's/^/       /'
}

# The 24 flags the defect was measured on: 22 the allow-list rejected and the 2
# it already forwarded, so the fix cannot regress what worked.
for flag in \
  --max-semi-space-size=1 --min-semi-space-size=1 --trace-gc --trace-gc-verbose \
  --gc-interval=100 --stress-compaction --print-bytecode --print-opt-code \
  --turbo-stats --no-opt --jitless --single-threaded --predictable --no-lazy \
  --wasm-tier-up --max-lazy --opt --always-sparkplug --no-flush-bytecode \
  --stress-scavenge=0 --prof --log-all \
  --max-old-space-size=4096 --expose-gc; do
  case_ "$flag"
done

# Rejections, which are the half a permissive "accept anything" fix would break.
for flag in --totally-bogus-flag=1 --no-bogus --experimental-not-a-real-flag -x; do
  case_ "$flag"
done

printf '\n%d case(s), %d failure(s)\n' "$checks" "$failures"
if [ "$failures" -eq 0 ]; then
  exit 0
fi
exit 1
