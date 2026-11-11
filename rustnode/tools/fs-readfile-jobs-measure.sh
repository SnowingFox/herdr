#!/usr/bin/env bash
# Runs the 58-file fs.readFile/fs.writeFile set against one binary and prints
# `file | exit | markers | verdict` per row.
#
# A test file "passing" is not proof it ran. On this runtime a failure can exit
# 0, and a skipped file exits 0 having run nothing, so four markers are checked
# on combined stdout+stderr:
#   ✖                 a node:test failure glyph
#   Uncaught          a plain-assert failure (mid-line, behind a location prefix)
#   1..0 # Skipped:   a whole-file skip
#   : # SKIP          a node:test skip glyph
# A row is a genuine pass only when it exits 0 and carries none of them.
#
#   ./tools/fs-readfile-jobs-measure.sh <binary> <label> [timeout-seconds]
set -uo pipefail

binary="${1:?usage: $0 <binary> <label> [timeout]}"
label="${2:?usage: $0 <binary> <label> [timeout]}"
timeout_seconds="${3:-60}"
tests_dir="${RUSTNODE_TEST_TREE:-/tmp/node-test/test}"
list="${RUSTNODE_FS_LIST:-/tmp/fs58.txt}"
out="${RUSTNODE_FS_OUT:-/tmp/fs-measure-${label}.tsv}"

[ -x "$binary" ] || { echo "no such binary: $binary" >&2; exit 2; }
[ -d "$tests_dir/parallel" ] || { echo "no test tree at $tests_dir" >&2; exit 2; }
[ -f "$list" ] || { echo "no file list at $list" >&2; exit 2; }

printf 'file\texit\tmarkers\tverdict\n' > "$out"

pass=0
fail=0
while read -r name; do
  [ -z "$name" ] && continue
  path="$tests_dir/parallel/$name"
  if [ ! -f "$path" ]; then
    printf '%s\t-\tmissing\tMISSING\n' "$name" >> "$out"
    fail=$((fail + 1))
    continue
  fi
  log=$(cd "$tests_dir" && timeout "$timeout_seconds" "$binary" "parallel/$name" 2>&1)
  status=$?

  markers=""
  case "$log" in *"✖"*) markers="${markers}FAIL_GLYPH " ;; esac
  case "$log" in *Uncaught*) markers="${markers}UNCAUGHT " ;; esac
  case "$log" in *"1..0 # Skipped:"*) markers="${markers}SKIP_ALL " ;; esac
  case "$log" in *"# SKIP"*) markers="${markers}SKIP_GLYPH " ;; esac
  [ "$status" -eq 124 ] && markers="${markers}TIMEOUT "
  [ "$status" -eq 139 ] && markers="${markers}SEGV "
  markers="${markers:-none}"

  if [ "$status" -eq 0 ] && [ "$markers" = "none" ]; then
    verdict=PASS
    pass=$((pass + 1))
  else
    verdict=FAIL
    fail=$((fail + 1))
  fi
  printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$markers" "$verdict" >> "$out"
done < "$list"

printf 'label=%s binary=%s mtime=%s head=%s\n' \
  "$label" \
  "$binary" \
  "$(date -u -r "$binary" '+%Y-%m-%dT%H:%M:%SZ')" \
  "$(git -C "$(cd "$(dirname "$0")/.." && pwd)" rev-parse --short HEAD 2>/dev/null || echo unknown)"

printf 'PASS=%d FAIL=%d TOTAL=%d\n' "$pass" "$fail" "$((pass + fail))"
printf 'rows written to %s\n' "$out"
