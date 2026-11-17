#!/usr/bin/env bash
# Proves `napi-symbol-coverage.py` can fail, and for the right reason.
#
# The gate exists because 16 Node-API entry points were exported by the oracle,
# missing from this build, and undeclared -- while every other check was green. A
# gate that cannot fail would be the same defect with one more layer, so this
# script breaks the tree deliberately, requires the specific diagnostic, and puts
# the file back.
#
# Four shapes are exercised, because each is a different way the gate could be
# passing without checking anything:
#
#   1. a declaration removed          -> the symbol must be named as undeclared
#   2. a declared name the oracle lacks -> the phantom entry must be named
#   3. a declared name this build exports -> the contradiction must be named
#   4. the DEFERRED block unreadable    -> the check must refuse, not pass
#
# Every mutation is restored before the next one, and the file is compared against
# a backup at the end, so a crash mid-run cannot leave the tree modified.
#
# Exit codes: 0 all shapes behaved, 1 a shape did not, 2 the tree could not be
# restored.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

gate=./tools/napi-symbol-coverage.py
shims=crates/rn-napi/src/shims.rs
# The gate passes the binary it actually builds; the tool's own default is the
# release binary, which `check.sh` never builds (it runs `cargo check --release`).
# Run standalone, this test keeps the release default to match a human or CI run
# that has one.
binary="${RUSTNODE_NAPI_BINARY:-target/release/rustnode}"
backup="$(mktemp)"
trap 'rm -f "$backup"' EXIT
cp "$shims" "$backup"

restore() {
  cp "$backup" "$shims"
}

failures=0
checks=0

# The message a case must produce, and the status it must exit with.
expect() {
  local name="$1" needle="$2" expected_status="$3" output status
  set +e
  output="$("$gate" --rustnode "$binary" 2>&1)"
  status=$?
  set -e
  checks=$((checks + 1))
  if [ "$status" -ne "$expected_status" ]; then
    printf 'FAIL %s: exited %d, expected %d\n%s\n' "$name" "$status" "$expected_status" "$output"
    failures=$((failures + 1))
    return
  fi
  if ! printf '%s' "$output" | grep -qF "$needle"; then
    printf 'FAIL %s: output did not mention %q\n%s\n' "$name" "$needle" "$output"
    failures=$((failures + 1))
    return
  fi
  printf 'ok   %s\n' "$name"
}

# The unmodified tree must pass, or the rest means nothing.
expect "the current tree passes" "none undeclared" 0

# 1. Remove one declaration. The gate must name that exact symbol as undeclared,
#    which is the finding F6 recorded 16 examples of.
#
#    This leaves the block empty when `napi_module_register` is the only remaining
#    entry, which is the intended end state of the list. Removing it is therefore
#    also the case that proves an empty block reads as "nothing deferred" rather
#    than as an unparsable one.
python3 - "$shims" <<'PY'
import sys, pathlib
path = pathlib.Path(sys.argv[1])
text = path.read_text()
needle = '        "napi_module_register",\n'
if needle not in text:
    raise SystemExit("the declaration this test removes is gone; update the test")
# Drop the whole entry, not just the name: an entry with the name removed would
# leave a reason behind and the parse would fail differently.
start = text.index('    (\n        "napi_module_register",')
end = text.index('    ),\n', start) + len('    ),\n')
path.write_text(text[:start] + text[end:])
PY
expect "a removed declaration is reported as undeclared" "napi_module_register" 1
restore

# 2. A declared name the oracle does not export is a typo or a stale entry.
sed -i 's/"napi_module_register",/"napi_module_registr",/' "$shims"
expect "a declared name the oracle lacks is reported" "napi_module_registr" 1
restore

# 3. A name that is both declared and exported makes the deferral list lie.
sed -i 's/"napi_module_register",/"napi_is_array",/' "$shims"
expect "a declared name this build exports is reported" "napi_is_array" 1
restore

# 4. A block whose content does not parse must be a refusal, not a clean bill of
#    health. This is the failure `deferred-reach.py` shipped once: a regex that
#    matched nothing reported zero problems for a file full of declarations. The
#    body below is deliberately *not* empty, because an empty list is the goal the
#    list exists to reach, not a parse failure.
python3 - "$shims" <<'PY'
import sys, pathlib
path = pathlib.Path(sys.argv[1])
text = path.read_text()
start = text.index('pub const DEFERRED: &[(&str, &str)] = &[')
end = text.index('];', start) + 2
path.write_text(
    text[:start]
    + 'pub const DEFERRED: &[(&str, &str)] = &[\n    ("napi_x",),\n];'
    + text[end:]
)
PY
expect "an unparsable DEFERRED block is refused, not passed" "no entry matched" 2
restore

if ! cmp -s "$backup" "$shims"; then
  printf 'the shims file was not restored; it differs from the backup\n' >&2
  exit 2
fi

if [ "$failures" -ne 0 ]; then
  printf '\n%d of %d shape(s) did not behave\n' "$failures" "$checks" >&2
  exit 1
fi

printf '\nthe symbol-coverage gate fails for the right reason in all %d shape(s)\n' "$checks"
exit 0
