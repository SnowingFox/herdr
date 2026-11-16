#!/usr/bin/env bash
# Proves `function-name-audit.py --recorded` can fail, and cannot pass while
# comparing nothing.
#
# The gate step exists because binding functions were published through V8's
# `FunctionTemplate::builder`, which leaves `name` as `""`, while Node's
# `SetMethod` names the function after the property it publishes it under. That
# is visible in stack traces and `util.inspect`, and it had already been reported
# twice before being fixed tree-wide, so the guard matters more than the count.
#
# Like the constructibility control, this one exists because a gate whose
# blindness is untested is the defect it guards. Shapes exercised:
#
#   1. the committed fixtures carry real names, not an empty recording
#   2. every class in the member fixture has a prototype entry, so no class is
#      silently uncompared
#   3. an emptied member fixture exits 2 rather than passing
#   4. a fixture that renames one member with an empty string is reported, so the
#      comparison is live and would have caught the original defect
#   5. a fixture that claims a name Node does not use is reported in the other
#      direction, so the guard cannot be satisfied by blanket-renaming
#
# Every mutation happens in a temporary directory; nothing in the tree is written.
#
# Exit codes: 0 all shapes behaved, 1 a shape did not, 2 the audit would not run.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

audit=./tools/function-name-audit.py
members=tools/function-name-members.json
prototypes=tools/function-name-prototypes.json
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
  echo "function-name-audit control: no binary at $binary; build it first" >&2
  exit 2
fi
# A stale binary is indistinguishable from a regression here: the subject of this
# control is what the engine reports as `f.name`, so a build from before the fix
# reports the defect back and shape 1 would pass for the wrong reason. `cargo
# check` does not refresh the binary, which is how this bites.
if [ -n "$(find crates -name '*.rs' -newer "$binary" -print -quit 2>/dev/null)" ]; then
  echo "function-name-audit control: $binary is older than the Rust sources it must" >&2
  echo "function-name-audit control: reflect; run \`cargo build -p rn-cli\` first" >&2
  exit 2
fi
for fixture in "$members" "$prototypes"; do
  if [ ! -f "$fixture" ]; then
    echo "function-name-audit control: missing fixture $fixture" >&2
    exit 2
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Shape 1: the committed fixtures are the ones the gate reads, so the property
# that makes the gate meaningful has to be a property of these two files.
if python3 - "$members" "$prototypes" <<'PY'
import json
import sys

members_path, prototypes_path = sys.argv[1], sys.argv[2]
with open(members_path, encoding="utf8") as handle:
    members = json.load(handle)
with open(prototypes_path, encoding="utf8") as handle:
    prototypes = json.load(handle)

def pairs(rows):
    """`(name, length)` for one recorded function, tolerating the old shape."""
    if isinstance(rows, str):
        return rows, None
    return rows.get("name", ""), rows.get("length")


total = sum(len(rows) for rows in members.values())
named = sum(1 for rows in members.values() for row in rows.values()
            if pairs(row)[0])
measured = sum(1 for rows in members.values() for row in rows.values()
               if pairs(row)[1] is not None)
if total == 0:
    print("the member fixture records no functions at all", file=sys.stderr)
    sys.exit(1)
if named == 0:
    print("the member fixture records no names, which is the shape a blind "
          "recording would write", file=sys.stderr)
    sys.exit(1)
# A fixture that keeps the names but drops the lengths is the same blindness one
# field over: the name half would still compare and report a clean run about the
# invariant that had gone blind.
if measured != total:
    print(f"the member fixture records a length for {measured} of {total} "
          "function(s); the length half would compare the rest zero times",
          file=sys.stderr)
    sys.exit(1)

# The exemptions are the reason this fixture stores names rather than a
# "should be named" boolean: Node itself leaves 65 of these empty, and two of them
# carry a name that is not their property name. A boolean cannot express either.
empty = sum(1 for rows in members.values() for row in rows.values()
            if not pairs(row)[0])
renamed = sorted(
    f"{namespace}.{member}={pairs(row)[0]!r}"
    for namespace, rows in members.items()
    for member, row in rows.items()
    if pairs(row)[0] and pairs(row)[0] != member
)
if empty == 0:
    print("the member fixture records no unnamed functions; SetFastMethod members "
          "are unnamed on Node too, so a recording with none is not Node's",
          file=sys.stderr)
    sys.exit(1)
# Lengths are the other half. Node records 0 for almost every `SetMethod` member
# and a handful of non-zero ones (`trace_events.trace` is 5), so a fixture with
# only zeros is not Node's either.
nonzero = sorted(
    f"{namespace}.{member}={pairs(row)[1]}"
    for namespace, rows in members.items()
    for member, row in rows.items()
    if pairs(row)[1]
)
if not nonzero:
    print("the member fixture records no non-zero lengths; V8's "
          "SimpleInstallFunction really does record them, so a recording with "
          "none is not Node's", file=sys.stderr)
    sys.exit(1)
print(f"{total} function(s) recorded, {named} named, {empty} unnamed, "
      f"{len(renamed)} with a name that is not the property name; "
      f"{measured} with a length, {len(nonzero)} non-zero")
PY
then
  pass "the committed member fixture carries real names and lengths"
else
  fail "the committed member fixture carries real names and lengths"
fi

# Shape 2: a class the member fixture names but the prototype fixture does not is
# compared zero times, which is exactly the blindness the count guard is for.
if python3 - "$members" "$prototypes" <<'PY'
import json
import sys

members_path, prototypes_path = sys.argv[1], sys.argv[2]
with open(members_path, encoding="utf8") as handle:
    members = json.load(handle)
with open(prototypes_path, encoding="utf8") as handle:
    prototypes = json.load(handle)

# Classes are only recorded when the engine calls the member a constructor. The
# oracle's own recording decides that, so it is re-derived here from the member
# fixture's companion rather than guessed from names.
import importlib.util
import os

spec = importlib.util.spec_from_file_location(
    "function_name_audit", os.path.join("tools", "function-name-audit.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
expected = module.prototype_methods(prototypes)
if not expected:
    print("the prototype fixture records no classes", file=sys.stderr)
    sys.exit(1)
methods = sum(len(entries) for entries in expected.values())
if methods == 0:
    print("the prototype fixture records no methods", file=sys.stderr)
    sys.exit(1)
print(f"{methods} prototype method name(s) across {len(expected)} class(es)")
PY
then
  pass "the committed prototype fixture carries real prototype names"
else
  fail "the committed prototype fixture carries real prototype names"
fi

# Shape 3: an emptied member fixture cannot be a pass. `--recorded` derives the
# prototype path from the member path, so both fixtures sit beside each other.
blind="$work/blind"
mkdir -p "$blind"
echo '{}' >"$blind/function-name-members.json"
cp "$prototypes" "$blind/function-name-prototypes.json"

set +e
output="$(python3 "$audit" --recorded "$blind/function-name-members.json" \
  --rustnode "$binary" 2>&1)"
status=$?
set -e
if [ "$status" -eq 2 ]; then
  pass "an empty member fixture exits 2"
else
  fail "an empty member fixture exited $status, expected 2 (a pass here is the defect)"
fi
case "$output" in
  *"compared zero namespace members"*)
    pass "an empty member fixture names the zero comparison"
    ;;
  *)
    fail "an empty member fixture did not name the zero comparison: ${output:0:400}"
    ;;
esac

# Shape 4: the defect this guard exists for, re-created in the fixture. One
# member Node names is recorded as unnamed, so rustnode's now-correct name
# contradicts it and the audit must say so.
unnamed="$work/unnamed"
mkdir -p "$unnamed"
cp "$prototypes" "$unnamed/function-name-prototypes.json"
python3 - "$members" "$unnamed/function-name-members.json" <<'PY'
import json
import sys

source, destination = sys.argv[1], sys.argv[2]
with open(source, encoding="utf8") as handle:
    recorded = json.load(handle)
# A member that is `SetMethod` in Node, so its name has to be its property name.
target = ("fs", "open")
if recorded.get(target[0], {}).get(target[1], {}).get("name") != target[1]:
    print(f"the fixture does not record fs.open as named", file=sys.stderr)
    sys.exit(1)
recorded[target[0]][target[1]]["name"] = ""
with open(destination, "w", encoding="utf8") as handle:
    json.dump(recorded, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

set +e
output="$(python3 "$audit" --recorded "$unnamed/function-name-members.json" \
  --rustnode "$binary" --json 2>&1)"
status=$?
set -e
if [ "$status" -eq 1 ]; then
  pass "a member recorded as unnamed fails the audit"
else
  fail "a member recorded as unnamed exited $status, expected 1"
fi
case "$output" in
  *'"namespace": "fs"'*'"member": "open"'*)
    pass "the empty-name failure names the member"
    ;;
  *)
    fail "the empty-name failure did not name the member: ${output:0:400}"
    ;;
esac

# Shape 5: the other direction. A fixture that renames `getSharedArrayBufferGrowable`
# to its property name claims Node does something it does not, so the audit must
# fail rather than allow a blanket rename to satisfy it.
renamed="$work/renamed"
mkdir -p "$renamed"
cp "$prototypes" "$renamed/function-name-prototypes.json"
python3 - "$members" "$renamed/function-name-members.json" <<'PY'
import json
import sys

source, destination = sys.argv[1], sys.argv[2]
with open(source, encoding="utf8") as handle:
    recorded = json.load(handle)
# The accessor Node republishes keeps V8's own name, which is not the property.
target = ("util", "getSharedArrayBufferGrowable")
if recorded.get(target[0], {}).get(target[1], {}).get("name") != "get growable":
    print("the fixture does not record getSharedArrayBufferGrowable as "
          "'get growable'", file=sys.stderr)
    sys.exit(1)
recorded[target[0]][target[1]]["name"] = "getSharedArrayBufferGrowable"
with open(destination, "w", encoding="utf8") as handle:
    json.dump(recorded, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

set +e
output="$(python3 "$audit" --recorded "$renamed/function-name-members.json" \
  --rustnode "$binary" --json 2>&1)"
status=$?
set -e
if [ "$status" -eq 1 ]; then
  pass "a blanket rename fails the audit"
else
  fail "a blanket rename exited $status, expected 1"
fi
case "$output" in
  *getSharedArrayBufferGrowable*)
    pass "the blanket-rename failure names the member"
    ;;
  *)
    fail "the blanket-rename failure did not name the member: ${output:0:400}"
    ;;
esac

# Shape 6: the length half, re-created in the fixture. `trace_events.trace` is 5
# on Node because V8's `SimpleInstallFunction` recorded it, so recording it as 0
# contradicts rustnode's now-correct value and the audit must say so.
wrong_length="$work/wrong-length"
mkdir -p "$wrong_length"
cp "$prototypes" "$wrong_length/function-name-prototypes.json"
python3 - "$members" "$wrong_length/function-name-members.json" <<'PY'
import json
import sys

source, destination = sys.argv[1], sys.argv[2]
with open(source, encoding="utf8") as handle:
    recorded = json.load(handle)
target = ("trace_events", "trace")
if recorded.get(target[0], {}).get(target[1], {}).get("length") != 5:
    print("the fixture does not record trace_events.trace with length 5",
          file=sys.stderr)
    sys.exit(1)
recorded[target[0]][target[1]]["length"] = 0
with open(destination, "w", encoding="utf8") as handle:
    json.dump(recorded, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

set +e
output="$(python3 "$audit" --recorded "$wrong_length/function-name-members.json" \
  --rustnode "$binary" --json 2>&1)"
status=$?
set -e
if [ "$status" -eq 1 ]; then
  pass "a member recorded with the wrong length fails the audit"
else
  fail "a member recorded with the wrong length exited $status, expected 1"
fi
case "$output" in
  *'"field": "length"'*'"member": "trace"'*|*'"member": "trace"'*'"field": "length"'*)
    pass "the wrong-length failure names the member and the field"
    ;;
  *)
    fail "the wrong-length failure did not name the member: ${output:0:400}"
    ;;
esac

# Shape 7: a fixture that drops `length` from every entry must not read as a
# clean run about the invariant it stopped measuring. The name half would still
# compare 524 members, so this is exactly the shape that reported `0
# disagreements` once already, one field over.
no_lengths="$work/no-lengths"
mkdir -p "$no_lengths"
cp "$prototypes" "$no_lengths/function-name-prototypes.json"
python3 - "$members" "$no_lengths/function-name-members.json" <<'PY'
import json
import sys

source, destination = sys.argv[1], sys.argv[2]
with open(source, encoding="utf8") as handle:
    recorded = json.load(handle)
for rows in recorded.values():
    for row in rows.values():
        row.pop("length", None)
with open(destination, "w", encoding="utf8") as handle:
    json.dump(recorded, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

set +e
output="$(python3 "$audit" --recorded "$no_lengths/function-name-members.json" \
  --rustnode "$binary" 2>&1)"
status=$?
set -e
if [ "$status" -eq 2 ]; then
  pass "a fixture with no lengths exits 2"
else
  fail "a fixture with no lengths exited $status, expected 2"
fi
case "$output" in
  *"compared zero member lengths"*)
    pass "a fixture with no lengths names the zero comparison"
    ;;
  *)
    fail "a fixture with no lengths did not name it: ${output:0:400}"
    ;;
esac

# Shape 8: the arithmetic has to be visible. The summary must print the recorded,
# compared and skipped counts, so a member that silently stopped being installed
# cannot hide inside a shrinking number nobody reads.
set +e
output="$(python3 "$audit" --recorded "$members" --rustnode "$binary" 2>&1)"
status=$?
set -e
if [ "$status" -eq 0 ]; then
  pass "the committed fixtures agree with the built binary on name and length"
else
  fail "the committed fixtures disagree with the binary (exit $status)"
fi
case "$output" in
  *"recorded "*"compared "*"skipped because deferred "*"skipped for no declared reason"*)
    pass "the summary prints recorded, compared, deferred and unexplained counts"
    ;;
  *)
    fail "the summary did not print the skip accounting: ${output:0:600}"
    ;;
esac
case "$output" in
  *"skipped because deferred 0"*)
    fail "the summary reports zero deferred skips; the fixture holds members that"\
" are declared deferred on this build"
    ;;
  *)
    pass "the deferred skip count is non-zero, as the fixture requires"
    ;;
esac

echo
if [ "$failures" -ne 0 ]; then
  echo "$failures of $checks function-name-audit control(s) failed"
  exit 1
fi
echo "function-name-audit: $checks control(s) pass"
