#!/usr/bin/env bash
# Measures the `test-http2*` family under the four-marker rule, repeated N times.
#
#   ./tools/http2-measure.sh <results-dir> [--tests <node-test-dir>] [--runs N]
#
# A single run cannot adjudicate a small change. Two runs of the *same* binary
# disagreed on `test-http2-compat-errors.js`, and `test-http2-server-errors.js`
# segfaults in six of eight runs, so a one-shot total carries about ±2 of noise and
# an exit-code count overstates a pass rate for the same reason a single-file
# `rc=0` is a false positive.
#
# So each file runs N times (default 3) and the result is a *distribution*:
#
#   test-http2-foo.js | 0 0 0 | stable-pass | ...
#   test-http2-bar.js | 0 124 0 | unstable | ...
#
# The aggregate that decides anything is **files that pass in every run**. A file
# that flips is marked `unstable` and counted on neither side, so it can neither
# flatter nor damage a comparison.
#
# A file passes one run only when all five hold:
#
#   1. the process exits 0;
#   2. no `✖` anywhere in stdout or stderr;
#   3. no `Uncaught` anywhere in stdout or stderr (it can appear mid-line, so this
#      is a substring test, not a line-prefix test);
#   4. no `1..0 # Skipped` at column zero;
#   5. no `: # SKIP` anywhere.
#
# Columns, per file:
#
#   name | per-run outcomes | stability | markers seen | slowest run
#
# `stability` is `stable-pass`, `stable-fail` or `unstable`. `markers seen` is the
# union across runs, so an `Uncaught` that only appears sometimes is still visible.
#
# Exit codes:
#   0 every selected file was measured (whatever the verdicts were)
#   1 the binary or test tree is missing, or `--runs` is not a positive integer
#   2 usage error
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

usage() {
  echo "usage: tools/http2-measure.sh <results-dir> [--tests <dir>] [--runs N] [--only SUBSTR] [--limit N]" >&2
}

results=""
tests_dir=""
runs=3
only=""
limit=0
# Files are independent processes, and one that times out costs a full 60s. Running
# a few at once is what makes a 3x pass over the family finish in a sitting rather
# than overnight; it does not change any per-file verdict.
jobs="${HERDR_HTTP2_JOBS:-4}"
while [ $# -gt 0 ]; do
  case "$1" in
    --tests)
      tests_dir="${2:?--tests needs a directory}"
      shift 2
      ;;
    --runs)
      runs="${2:?--runs needs a count}"
      shift 2
      ;;
    --only)
      only="${2:?--only needs a substring}"
      shift 2
      ;;
    --limit)
      limit="${2:?--limit needs a count}"
      shift 2
      ;;
    --jobs)
      jobs="${2:?--jobs needs a count}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 2
      ;;
    -*)
      usage
      exit 2
      ;;
    *)
      if [ -n "$results" ]; then
        usage
        exit 2
      fi
      results="$1"
      shift
      ;;
  esac
done

if [ -z "$results" ]; then
  usage
  exit 2
fi
case "$runs" in
  '' | *[!0-9]*)
    echo "rustnode: --runs must be a positive integer, got '$runs'" >&2
    exit 1
    ;;
esac
if [ "$runs" -lt 1 ]; then
  echo "rustnode: --runs must be at least 1" >&2
  exit 1
fi

binary="${RUSTNODE_BIN:-target/debug/rustnode}"
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

# One run. Prints `<outcome>|<markers>|<verdict>|<seconds>` and nothing else.
#
# The outcome is the exit status, which is what distinguishes a timeout (124) from
# a crash (139/-11, 134/-6) from an ordinary failure, and it is the column that
# makes an unstable file's shape legible.
run_one() {
  local file="$1"
  local flags
  flags="$(flags_of "$file")"
  local started ended status
  # Scratch files are per-process: with `--jobs` above 1 several `run_one` bodies
  # run at once, and a shared output file would interleave two tests' output and
  # read as a false `Uncaught`.
  local scratch
  scratch="$(mktemp -d "$work/run.XXXXXX")"
  started=$(date +%s%N)
  # shellcheck disable=SC2086 # the flags line is a space-separated list on purpose
  set +e
  timeout 60 "$binary" $flags "$file" >"$scratch/out" 2>"$scratch/err"
  status=$?
  set -e
  ended=$(date +%s%N)
  local markers=""
  if grep -q '✖' "$scratch/out" "$scratch/err" 2>/dev/null; then
    markers="${markers}X"
  fi
  if grep -q 'Uncaught' "$scratch/out" "$scratch/err" 2>/dev/null; then
    markers="${markers}U"
  fi
  if grep -q '^1\.\.0 # Skipped' "$scratch/out" "$scratch/err" 2>/dev/null; then
    markers="${markers}S0"
  fi
  if grep -q ': # SKIP' "$scratch/out" "$scratch/err" 2>/dev/null; then
    markers="${markers}SK"
  fi
  rm -rf "$scratch"
  local verdict="PASS"
  if [ "$status" -ne 0 ] || [ -n "$markers" ]; then
    verdict="FAIL"
  fi
  printf '%s|%s|%s|%s' "$status" "${markers:-none}" "$verdict" "$(( (ended - started) / 1000000 ))"
}

mapfile -t files < <(ls "$tests_dir"/parallel/test-http2*.js | sort)
# `--only` and `--limit` exist so the harness can be exercised on a handful of
# files from the real tree — copying files out of it breaks their `../common`
# require and makes every file fail for a reason that is not the code under test.
if [ -n "$only" ]; then
  filtered=()
  for file in "${files[@]}"; do
    case "$file" in
      *"$only"*) filtered+=("$file") ;;
    esac
  done
  files=("${filtered[@]+"${filtered[@]}"}")
fi
if [ "$limit" -gt 0 ] && [ "${#files[@]}" -gt "$limit" ]; then
  files=("${files[@]:0:$limit}")
fi
total="${#files[@]}"
printf 'HEAD %s\n' "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
printf 'binary %s mtime %s\n' "$binary" "$(date -r "$binary" -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)"
printf 'files %d runs %d\n' "$total" "$runs"

outcome_file="$results/http2-files.txt"
: >"$outcome_file"
# One line per file, written by a worker into its own file, then concatenated in
# the original order. Ordering matters because the output is diffed between runs of
# two branches and a reordered list would drown the real difference.
per_file_dir="$work/per-file"
mkdir -p "$per_file_dir"

measure_file() {
  local index="$1"
  local file="$2"
  local name="${file#"$tests_dir"/}"
  local outcomes=()
  local markers_seen=""
  local slowest=0
  local passes=0
  local run record status markers verdict millis
  for ((run = 1; run <= runs; run++)); do
    record="$(run_one "$file")"
    IFS='|' read -r status markers verdict millis <<<"$record"
    outcomes+=("$status")
    if [ "$verdict" = "PASS" ]; then
      passes=$((passes + 1))
    fi
    if [ "$markers" != "none" ]; then
      case "$markers_seen" in
        *"$markers"*) ;;
        *) markers_seen="${markers_seen}${markers}" ;;
      esac
    fi
    if [ "$millis" -gt "$slowest" ]; then
      slowest="$millis"
    fi
  done
  local stability
  if [ "$passes" -eq "$runs" ]; then
    stability="stable-pass"
  elif [ "$passes" -eq 0 ]; then
    stability="stable-fail"
  else
    stability="unstable"
  fi
  printf '%s | %s | %s | %s | %sms\n' \
    "$name" "${outcomes[*]}" "$stability" "${markers_seen:-none}" "$slowest" \
    >"$per_file_dir/$index"
}
export -f measure_file run_one flags_of
export binary tests_dir runs work per_file_dir

# `xargs -P` gives each file its own process, and `run_one` already uses unique
# output paths per invocation through `$work`, so the workers cannot collide.
for index in "${!files[@]}"; do
  printf '%s\0%s\0' "$index" "${files[$index]}"
done | xargs -0 -n 2 -P "$jobs" bash -c 'measure_file "$0" "$1"'

for index in "${!files[@]}"; do
  cat "$per_file_dir/$index"
done >>"$outcome_file"

cat "$outcome_file"

stable_pass="$(awk -F'|' '$3 ~ /stable-pass/' "$outcome_file" | wc -l)"
stable_fail="$(awk -F'|' '$3 ~ /stable-fail/' "$outcome_file" | wc -l)"
unstable="$(awk -F'|' '$3 ~ /unstable/' "$outcome_file" | wc -l)"

printf '\nSTABLE_PASS=%s STABLE_FAIL=%s UNSTABLE=%s TOTAL=%s RUNS=%s\n' \
  "$stable_pass" "$stable_fail" "$unstable" "$total" "$runs"

# The unstable files are listed explicitly rather than left for a reader to find.
# A crash majority in that list is a reproducible defect, not noise, and hiding it
# inside an aggregate is how a real bug gets filed as "flaky" and forgotten.
if [ "$unstable" -ne 0 ]; then
  printf '\nunstable files (counted on neither side):\n'
  awk -F'|' '$3 ~ /unstable/ {printf "  %s |%s | %s\n", $1, $2, $4}' "$outcome_file"
fi

exit 0
