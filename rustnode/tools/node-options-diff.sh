#!/usr/bin/env bash
# Differential: NODE_OPTIONS handling, rustnode against the pinned oracle.
#
# The oracle is the nightly the review names, never `node` from PATH. Both
# binaries are invoked through a shared argv[0] so the `<program>:` prefix on a
# rejected value is comparable byte for byte: Node prints `argv[0]` verbatim, so
# comparing two different paths would compare two different strings and hide a
# real difference in the message.
#
#   ./tools/node-options-diff.sh [path-to-oracle] [path-to-rustnode]
#
# Exit 0 when every case matches; 1 otherwise, naming the case.
#
# Exit codes:
#   0  every case matched
#   1  at least one case differed
#   2  a binary is missing (no verdict, which must not read as a pass)
set -uo pipefail

oracle="${1:-/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node}"
rustnode="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/debug/rustnode}"

for binary in "$oracle" "$rustnode"; do
  if [ ! -x "$binary" ]; then
    echo "node-options-diff: $binary is not executable; refusing to report a verdict" >&2
    exit 2
  fi
done
command -v python3 >/dev/null || { echo "node-options-diff: python3 is required" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A preload that makes its own effect observable, so `--require` is proven to
# have *run* rather than merely to have been accepted.
cat >"$work/pre.js" <<'JS'
globalThis.PRELOADED = (globalThis.PRELOADED || 0) + 1;
JS
cat >"$work/second.js" <<'JS'
globalThis.SECOND = (globalThis.SECOND || 0) + 1;
JS

# A script that prints one option's parsed value.
#
# `getCLIOptionsValues` is the layer `getOptionValue` reads, so it is the most
# direct observable for "the value reached the option layer" without depending on
# the consumer that happens to read it. It needs `--expose-internals`, which is
# passed on the command line rather than through the variable (Node disallows it
# there, and that is itself one of the cases below).
#
# The internal-testing warning it emits carries a PID and the runtime's own name,
# so `normalize` strips both before comparison: neither is what a case measures.
option_value() {
  printf 'console.log(JSON.stringify(require("internal/test/binding").internalBinding("options").getCLIOptionsValues()[%s]))' "\"$1\""
}

# Removes the two things that differ between two runs of the same binary.
#
# * `(node:12345)` — the PID, which no case is about.
# * `` --trace-warnings `` — Node prints `node` there and rustnode prints
#   `rustnode`, a naming difference that is not a NODE_OPTIONS behaviour.
#
# The program-name prefix on an error is *not* normalized: every case runs under a
# shared argv[0], so that field must match exactly, and normalizing it would hide
# a prefix regression.
normalize() {
  sed -E 's/\(node:[0-9]+\)/(node:PID)/; s/Use `(node|rustnode) --trace-warnings/Use `node --trace-warnings/'
}

# Runs one binary under a fixed argv[0] and records stdout, stderr and status.
#
# `exec -a` is what makes the two comparable: without it the program names
# differ, and every rejected-value case would differ for that reason alone
# rather than for a behavioural one.
run() {
  local binary="$1" env_value="$2" script="$3"
  shift 3
  NODE_OPTIONS="$env_value" bash -c '
    binary="$1"; script="$2"; shift 2
    exec -a /usr/local/bin/node "$binary" "$@" -e "$script"
  ' _ "$binary" "$script" "$@" 2>"$work/stderr" >"$work/stdout"
  printf '%s\n' "$?"
}

failures=0
checks=0

# One case: a NODE_OPTIONS value, a script, and optionally extra argv.
#
# The script is expected to print the same thing under both runtimes; a rejected
# value prints Node's message on stderr and exits 9 on both.
case_() {
  local name="$1" env_value="$2" script="$3"
  shift 3

  local oracle_status rustnode_status
  oracle_status="$(run "$oracle" "$env_value" "$script" "$@")"
  normalize <"$work/stdout" >"$work/oracle.stdout"
  normalize <"$work/stderr" >"$work/oracle.stderr"
  rustnode_status="$(run "$rustnode" "$env_value" "$script" "$@")"
  normalize <"$work/stdout" >"$work/rustnode.stdout"
  normalize <"$work/stderr" >"$work/rustnode.stderr"

  checks=$((checks + 1))
  local problems=()
  [ "$oracle_status" = "$rustnode_status" ] ||
    problems+=("exit $oracle_status vs $rustnode_status")
  cmp -s "$work/oracle.stdout" "$work/rustnode.stdout" ||
    problems+=("stdout $(printf '%q' "$(cat "$work/oracle.stdout")") vs $(printf '%q' "$(cat "$work/rustnode.stdout")")")
  cmp -s "$work/oracle.stderr" "$work/rustnode.stderr" ||
    problems+=("stderr $(printf '%q' "$(cat "$work/oracle.stderr")") vs $(printf '%q' "$(cat "$work/rustnode.stderr")")")

  if [ "${#problems[@]}" -eq 0 ]; then
    printf 'ok   %s\n' "$name"
    return
  fi
  failures=$((failures + 1))
  printf 'FAIL %s\n' "$name"
  printf '       NODE_OPTIONS=%s\n' "$(printf '%q' "$env_value")"
  local problem
  for problem in "${problems[@]}"; do
    printf '       %s\n' "$problem"
  done
}

# An allowed option takes effect. Each of these was a silent no-op before the
# variable was parsed at all.
case_ "max-http-header-size" "--max-http-header-size=32768" \
  'console.log(require("http").maxHeaderSize)'
case_ "require" "--require $work/pre.js" \
  'console.log(globalThis.PRELOADED)'
case_ "require twice" "--require $work/pre.js --require $work/second.js" \
  'console.log(globalThis.PRELOADED, globalThis.SECOND)'
case_ "warnings flag suppresses the real warning" "--no-warnings" \
  'process.emitWarning("boom")'
case_ "warnings flag off emits the warning" "" \
  'process.emitWarning("boom")'
case_ "conditions" "--conditions=diff-test" "$(option_value --conditions)" --expose-internals
case_ "stack-trace-limit" "--stack-trace-limit=42" \
  'console.log(Error.stackTraceLimit)'
case_ "max-old-space-size" "--max-old-space-size=100" \
  'console.log(require("v8").getHeapStatistics().heap_size_limit > 0)'
case_ "single-dash alias" "-r $work/pre.js" \
  'console.log(globalThis.PRELOADED)'
case_ "inline value" "--max-http-header-size=32768 --require=$work/pre.js" \
  'console.log(require("http").maxHeaderSize, globalThis.PRELOADED)'
case_ "quoted value with a space" "--title=\"a b c\"" \
  "$(option_value --title)" --expose-internals
case_ "empty variable" "" \
  'console.log(require("http").maxHeaderSize)'
# The command-line override only works for flags this CLI's own parser accepts,
# so the scalar case uses `--title`, which it does. `--max-http-header-size` on
# the command line is still rejected as an unsupported option (the CLI accepts a
# hand-written subset of Node's 251 flags); that gap predates this change and is
# recorded as a residual in the PR body.
case_ "scalar from both sources: command line wins" "--title=from-env" \
  "$(option_value --title)" --expose-internals --title=from-cli
case_ "list from both sources: both survive" "--require $work/pre.js" \
  'console.log(globalThis.PRELOADED, globalThis.SECOND)' --require "$work/second.js"
case_ "inspect-port sets the address without listening" "--inspect-port=9339" \
  "$(option_value --inspect-port)" --expose-internals
case_ "inspect-port from the variable, --inspect on the command line" \
  "--inspect-port=9339" "$(option_value --inspect)" --expose-internals
case_ "abort-on-uncaught-exception from the variable" \
  "--abort-on-uncaught-exception" "$(option_value --abort-on-uncaught-exception)" \
  --expose-internals

# A rejected value. These are the four shapes Node distinguishes, and each must
# produce Node's sentence *and* exit 9, not be silently dropped.
case_ "unknown flag" "--not-a-real-flag" 'console.log(1)'
case_ "disallowed --eval" "--eval=1" 'console.log(1)'
case_ "disallowed -e" "-e 1" 'console.log(1)'
case_ "disallowed --help" "--help" 'console.log(1)'
case_ "disallowed --expose-internals" "--expose-internals" 'console.log(1)'
case_ "disallowed underscored spelling" "--expose_internals" 'console.log(1)'
case_ "negated disallowed" "--no-eval" 'console.log(1)'
case_ "double dash" "--" 'console.log(1)'
case_ "missing value" "--require" 'console.log(1)'
case_ "empty inline value" "--max-http-header-size=" 'console.log(1)'
case_ "flag where a value belongs" "--title --no-warnings" 'console.log(1)'
case_ "negated non-boolean" "--no-max-http-header-size" 'console.log(1)'
case_ "invalid escape" '--title="abc\' 'console.log(1)'
case_ "unterminated string" '--title="abc' 'console.log(1)'
case_ "unknown V8 flag Node does not declare" "--stack-size=512" 'console.log(1)'
case_ "bare V8 flag Node does not declare" "--trace-gc" 'console.log(1)'
case_ "out-of-range inspect port" "--inspect-port=80" 'console.log(1)'
case_ "unparseable inspect port" "--inspect-port=abc:def" 'console.log(1)'

# One rejected value stops the process before the command line runs, so a bad
# `-e` body must not be reached.
case_ "rejection happens before the script" "--not-a-real-flag" \
  'console.log("SHOULD NOT RUN")'

printf '\n%d case(s), %d failure(s)\n' "$checks" "$failures"
if [ "$failures" -eq 0 ]; then
  exit 0
fi
exit 1
