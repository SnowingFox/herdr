#!/usr/bin/env bash
# Proves `constructible-audit.py --recorded` can fail, and that it cannot pass
# while comparing nothing.
#
# The gate step exists because rustnode was more permissive than Node about
# `new`: it accepted `new binding.fs.open()` where Node throws. `--recorded`
# judges that on every commit without a Node binary, from two fixtures the pinned
# oracle produced.
#
# It once could not fail. `--record` wrote `constructible-prototypes.json` as, per
# class, the prototype methods Node reports as *constructible*, and Node builds
# every prototype method with `SetProtoMethod` — `ConstructorBehavior::kThrow` — so
# the recording was `[]` for all 98 classes. `--recorded` in turn built its
# expectation as `{method: "constructor"}` from those lists, arrived at an empty
# dict per class, and compared nothing: it printed
# `0 prototype method(s) constructible only under rustnode` because it had looked
# at zero methods, not because there were none. Thirty members that accepted `new`
# they should not have, and later ten more, were invisible to the step that exists
# to find them.
#
# So this script breaks the fixtures deliberately and requires the specific
# outcome, because a gate whose blindness is untested is the defect it guards.
# Shapes exercised, one per way the recording could stop carrying information:
#
#   1. the committed fixture carries `function` rows, not only constructibles
#   2. the committed fixture yields a non-zero comparison count
#   3. an emptied prototype fixture exits 2 with the zero-comparison diagnostic,
#      rather than passing
#   4. the exact historical shape — one empty list per class — also exits 2
#   5. a fixture that contradicts rustnode is reported, so the comparison is live
#
# Every mutation happens in a temporary directory; nothing in the tree is written.
#
# Exit codes: 0 all shapes behaved, 1 a shape did not, 2 the audit would not run.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

audit=./tools/constructible-audit.py
members=tools/constructible-members.json
prototypes=tools/constructible-prototypes.json
binary=${RUSTNODE_BINARY:-./target/debug/rustnode}

failures=0
checks=0

pass() {
  checks=$((checks + 1))
  printf 'ok    %s\n' "$1"
}

fail() {
  checks=$((checks + 1))
  failures=$((failures + 1))
  printf 'FAIL  %s\n' "$1"
}

if [ ! -x "$binary" ]; then
  echo "constructible-audit control: no binary at $binary; build it first" >&2
  exit 2
fi
# A stale binary is indistinguishable from a regression here: the whole subject
# of this control is whether the engine says a published method has
# `[[Construct]]`, so a build from before the fix reports the defect back and the
# "contradicting fixture" shape would fail for a reason that has nothing to do
# with the audit. `cargo check` does not refresh the binary, which is how this
# bites. Comparing mtimes is the cheap half of the guard; rebuilding is the
# caller's job, and naming the file is what makes the next step obvious.
if [ -n "$(find crates tools/compat -name '*.rs' -newer "$binary" -print -quit 2>/dev/null)" ]; then
  echo "constructible-audit control: $binary is older than the Rust sources it must" >&2
  echo "constructible-audit control: reflect; run \`cargo build -p rn-cli\` first" >&2
  exit 2
fi
for fixture in "$members" "$prototypes"; do
  if [ ! -f "$fixture" ]; then
    echo "constructible-audit control: missing fixture $fixture" >&2
    exit 2
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Shape 1 and 2 read the committed fixtures directly: they are what the gate
# uses, so the properties that make the gate meaningful are properties of these
# two files rather than of anything this script constructs.
if python3 - "$members" "$prototypes" <<'PY'
import json
import sys

members_path, prototypes_path = sys.argv[1], sys.argv[2]
with open(prototypes_path, encoding="utf8") as handle:
    prototypes = json.load(handle)
with open(members_path, encoding="utf8") as handle:
    members = json.load(handle)

# Node builds prototype methods with SetProtoMethod, so none is constructible.
# A fixture with no `function` rows is the historical empty-list recording: it
# can only be produced by filtering on `kind == "constructor"`.
kinds = [kind for entry in prototypes.values() for kind in entry.values()]
total = len(kinds)
functions = sum(1 for kind in kinds if kind == "function")
constructors = sum(1 for kind in kinds if kind == "constructor")

if total == 0:
    print("the prototype fixture records no methods at all", file=sys.stderr)
    sys.exit(1)
if functions == 0:
    print("the prototype fixture records no non-constructible methods, which is "
          "the empty-list shape --record used to write", file=sys.stderr)
    sys.exit(1)
if constructors != 0:
    print(f"the prototype fixture claims {constructors} constructible prototype "
          "method(s); Node installs these with SetProtoMethod", file=sys.stderr)
    sys.exit(1)

# Every class the member fixture names must have a prototype entry, or the class
# is silently not compared.
missing = sorted(
    f"{namespace}.{name}"
    for namespace, names in members.items()
    for name in names
    if f"{namespace}.{name}" not in prototypes
)
if missing:
    print(f"{len(missing)} class(es) in the member fixture have no prototype "
          f"entry: {', '.join(missing[:5])}", file=sys.stderr)
    sys.exit(1)
print(f"{total} prototype method(s) recorded across {len(prototypes)} class(es), "
      f"{functions} non-constructible")
PY
then
  pass "the committed prototype fixture carries real, non-constructible methods"
else
  fail "the committed prototype fixture carries real, non-constructible methods"
fi

# Shape 2: the comparison count is what the audit is blind without, so it is
# asserted through the audit's own function rather than a re-implementation.
if python3 - "$members" "$prototypes" <<'PY'
import importlib.util
import json
import os
import sys

members_path, prototypes_path = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location(
    "constructible_audit", os.path.join("tools", "constructible-audit.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with open(prototypes_path, encoding="utf8") as handle:
    expected = module.prototype_methods(json.load(handle))
with open(members_path, encoding="utf8") as handle:
    members = json.load(handle)

# The same expansion --recorded performs, so the count reflects the gate path.
for namespace, names in members.items():
    for name in names:
        expected.setdefault((namespace, name), {})

# A rustnode that exposes the same names, in the same kinds, is the best case the
# count can assume: every recorded method becomes comparable.
actual = {key: dict(methods) for key, methods in expected.items()}
count = module.count_prototype_comparisons(expected, actual)
if count == 0:
    print("the audit would compare zero prototype methods", file=sys.stderr)
    sys.exit(1)
print(f"the audit compares {count} prototype method(s)")
PY
then
  pass "the committed fixtures yield a non-zero comparison count"
else
  fail "the committed fixtures yield a non-zero comparison count"
fi

# Shapes 3 and 4: the guard itself. Both fixtures sit beside each other because
# --recorded derives the prototype path from the member path.
empty="$work/empty"
mkdir -p "$empty"
cp "$members" "$empty/constructible-members.json"
echo '{}' >"$empty/constructible-prototypes.json"

set +e
output="$(python3 "$audit" --recorded "$empty/constructible-members.json" \
  --rustnode "$binary" 2>&1)"
status=$?
set -e
if [ "$status" -eq 2 ]; then
  pass "an empty prototype fixture exits 2"
else
  fail "an empty prototype fixture exited $status, expected 2 (a pass here is the defect)"
fi
if printf '%s' "$output" | grep -q "compared zero prototype methods"; then
  pass "an empty prototype fixture names the zero comparison"
else
  fail "an empty prototype fixture did not name the zero comparison: $output"
fi

# The precise historical shape: every class present, every list empty. This is
# what the gate was reading, and it exited 0.
blank="$work/blank"
mkdir -p "$blank"
cp "$members" "$blank/constructible-members.json"
python3 - "$prototypes" "$blank/constructible-prototypes.json" <<'PY'
import json
import sys

source, destination = sys.argv[1], sys.argv[2]
with open(source, encoding="utf8") as handle:
    recorded = json.load(handle)
with open(destination, "w", encoding="utf8") as handle:
    json.dump({path: [] for path in recorded}, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

set +e
output="$(python3 "$audit" --recorded "$blank/constructible-members.json" \
  --rustnode "$binary" 2>&1)"
status=$?
set -e
if [ "$status" -eq 2 ]; then
  pass "the empty-list-per-class shape exits 2"
else
  fail "the empty-list-per-class shape exited $status, expected 2 (this exact shape used to pass)"
fi

# Shape 5: the comparison is live. One recorded method is flipped to
# "constructor", which claims Node's prototype method accepts `new`. rustnode's
# does not, so the audit must report it as constructible only under node. If the
# loop were skipped -- as it was when the expectation was empty -- this would pass.
flipped="$work/flipped"
mkdir -p "$flipped"
cp "$members" "$flipped/constructible-members.json"
python3 - "$prototypes" "$flipped/constructible-prototypes.json" <<'PY'
import json
import sys

source, destination = sys.argv[1], sys.argv[2]
with open(source, encoding="utf8") as handle:
    recorded = json.load(handle)
# A method that is certainly on rustnode's prototype and certainly a plain
# function: `MessagePort.postMessage` is `SetProtoMethod` in both runtimes.
target = "messaging.MessagePort"
if target not in recorded or "postMessage" not in recorded[target]:
    print(f"the fixture does not record {target}.prototype.postMessage", file=sys.stderr)
    sys.exit(1)
recorded[target]["postMessage"] = "constructor"
with open(destination, "w", encoding="utf8") as handle:
    json.dump(recorded, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

set +e
output="$(python3 "$audit" --recorded "$flipped/constructible-members.json" \
  --rustnode "$binary" --json 2>&1)"
status=$?
set -e
if [ "$status" -eq 1 ]; then
  pass "a contradicting fixture fails the audit"
else
  fail "a contradicting fixture exited $status, expected 1"
fi
# `case` rather than `printf | grep -q`: under `pipefail` a large string piped
# into an early-exiting `grep -q` fails on SIGPIPE, which reads as "the method was
# not named" when it was.
case "$output" in
  *messaging.MessagePort.prototype.postMessage*)
    pass "a contradicting fixture names the method"
    ;;
  *)
    fail "a contradicting fixture did not name the method: ${output:0:400}"
    ;;
esac

echo
if [ "$failures" -ne 0 ]; then
  echo "$failures of $checks constructible-audit control(s) failed"
  exit 1
fi
echo "constructible-audit: $checks control(s) pass"
