#!/usr/bin/env bash
# Differential: `--config-file`'s read and its error path, rustnode vs the oracle.
#
# Only the read and the two error shapes are compared. `test-config-file.js` has
# eight further cases about `nodeVersion` selection and the `configs` array, which
# need Node's `ConfigReader` semantics and are deliberately not implemented; a
# "valid config object" case below checks the one thing this change does claim —
# that such a file is read, accepted, and not applied.
#
#   ./tools/config-file-diff.sh [path-to-oracle] [path-to-rustnode]
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
    echo "config-file-diff: $binary is not executable; refusing to report a verdict" >&2
    exit 2
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

# The fixtures, one per shape a document can have. `empty.json` is a single
# newline because that is what Node's own fixture is, and the difference between
# a newline and a zero-length file is not observable in either runtime.
printf '\n' > empty.json
printf '' > zero.json
printf '   \n\t\n' > whitespace.json
printf 'not json' > notjson.json
printf '{}' > object.json
printf '{' > truncated.json
printf '[]' > array.json
printf '5' > number.json
printf '"x"' > string.json
printf '\xff\xfe{}' > bad-utf8.json
mkdir -p directory.json
echo '{}' > node.config.json
mkdir -p nodefault

total=0
diffs=0

# Runs one case in both runtimes and compares status, stdout and stderr.
#
# The program name is the one legitimate difference — Node prints `argv[0]`
# verbatim and the two binaries have different paths — so it is normalised to
# `<PROG>` before the comparison. A case whose stderr differs in any other way
# fails.
case_run() {
  local name="$1" directory="$2"
  shift 2
  local oracle_out oracle_err oracle_code rustnode_out rustnode_err rustnode_code
  oracle_out="$(cd "$directory" && "$oracle" "$@" -p '"H"' 2>"$work/oracle.err")"
  oracle_code=$?
  rustnode_out="$(cd "$directory" && "$rustnode" "$@" -p '"H"' 2>"$work/rustnode.err")"
  rustnode_code=$?
  oracle_err="$(sed -e "s|$oracle|<PROG>|g" "$work/oracle.err")"
  rustnode_err="$(sed -e "s|$rustnode|<PROG>|g" "$work/rustnode.err")"

  total=$((total + 1))
  if [ "$oracle_out" = "$rustnode_out" ] &&
     [ "$oracle_err" = "$rustnode_err" ] &&
     [ "$oracle_code" = "$rustnode_code" ]; then
    return
  fi
  diffs=$((diffs + 1))
  echo "DIFF: $name"
  echo "  args: $*"
  if [ "$oracle_out" != "$rustnode_out" ]; then
    echo "  stdout oracle:    $(printf '%s' "$oracle_out" | od -c | head -3)"
    echo "  stdout rustnode:  $(printf '%s' "$rustnode_out" | od -c | head -3)"
  fi
  if [ "$oracle_err" != "$rustnode_err" ]; then
    echo "  stderr oracle:"
    printf '%s\n' "$oracle_err" | sed 's/^/    /'
    echo "  stderr rustnode:"
    printf '%s\n' "$rustnode_err" | sed 's/^/    /'
  fi
  if [ "$oracle_code" != "$rustnode_code" ]; then
    echo "  code oracle=$oracle_code rustnode=$rustnode_code"
  fi
}

# `should handle non existing json` — the first of the two cases in scope.
case_run "missing inline" "$work" --config-file=i-do-not-exist.json
case_run "missing alias" "$work" --experimental-config-file=i-do-not-exist.json
# The "default" alias refuses a value, so its `=` form is not a read at all.
case_run "invalid default argument" "$work" --experimental-default-config-file=i-do-not-exist.json

# `should handle empty json` and the neighbouring unparseable shapes.
case_run "empty file" "$work" --config-file=empty.json
case_run "zero-length file" "$work" --config-file=zero.json
case_run "whitespace only" "$work" --config-file=whitespace.json
case_run "truncated object" "$work" --config-file=truncated.json
case_run "invalid utf8" "$work" --config-file=bad-utf8.json

# A root that is not an object: simdjson answers INCORRECT_TYPE, so the message
# is the `Root value unexpected` one rather than `Can't parse`.
case_run "non-object text" "$work" --config-file=notjson.json
case_run "non-object array" "$work" --config-file=array.json
case_run "non-object number" "$work" --config-file=number.json
case_run "non-object string" "$work" --config-file=string.json

# An open failure that is not ENOENT: libuv's wording is `illegal operation on a
# directory`, which is the case that separates `uv_strerror` from libc's
# `strerror`.
case_run "directory" "$work" --config-file=directory.json

# A valid object is read and accepted. The only object shape compared is `{}`,
# because every field inside one is Node's `ConfigReader` semantics: `{"a":1}`
# is `Unknown namespace a` there, which is validation this change does not
# implement. The scope note in `crates/rn-cli/src/config_file.rs` says the same.
case_run "valid object" "$work" --config-file=object.json
case_run "valid object alias" "$work" --experimental-config-file=object.json

# Spellings. The bare flag reads `node.config.json` and is rewritten in
# `execArgv`; the empty `=` form is a missing argument; a separate value is the
# script rather than a path.
case_run "bare flag, no default" "$work/nodefault" --config-file
case_run "bare alias, no default" "$work/nodefault" --experimental-config-file
case_run "bare default alias, no default" "$work/nodefault" --experimental-default-config-file
case_run "bare flag with default" "$work" --config-file
case_run "empty inline" "$work" --config-file=
case_run "empty inline alias" "$work" --experimental-config-file=
case_run "default alias with empty value" "$work" --experimental-default-config-file=
case_run "last config wins" "$work" --config-file=object.json --config-file=notjson.json
case_run "last alias wins" "$work" --experimental-config-file=object.json --config-file=notjson.json

# Ordering against the rest of the startup errors. A collected file error stops
# the command-line parse, so a bad flag is not reported alongside it; an env file
# failure does not stop the config read.
case_run "bad config hides a bad flag" "$work" --config-file=notjson.json --not-a-real-flag
case_run "good config does not hide a bad flag" "$work" --config-file=object.json --not-a-real-flag
case_run "env file plus config" "$work" --env-file=missing.env --config-file=missing.json
case_run "env file plus empty inline" "$work" --env-file=missing.env --config-file=
case_run "env file plus invalid default" "$work" --env-file=missing.env --experimental-default-config-file=x.json

echo "config-file-diff: $((total - diffs))/$total cases matched"
[ "$diffs" -eq 0 ] || exit 1
exit 0
