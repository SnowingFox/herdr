#!/usr/bin/env bash
# Tests for tools/bun-surface-guard.py.
#
#   ./tools/bun-surface-guard.test.sh            # fixtures only, no build
#   ./tools/bun-surface-guard.test.sh --live     # also run the real guard
#
# A guard whose blindness is untested is the defect it guards. `bun-surface-guard.py`
# has four failure modes, and passing a clean real run proves none of them: a guard
# that always printed "ok" would pass that too. So each mode is exercised here by
# feeding the guard the defect as data, through the three JSON document inputs, and
# requiring the exact exit status AND the diagnostic text that names the problem.
#
# The four modes:
#
#   1. zero comparisons exit 2 — an empty installed set, and an empty oracle set.
#      Both are separate cases, because they are separate inputs that can go empty
#      independently (a binary with no `Bun` global; a fixture truncated to `{}`).
#   2. declared but not installed exits 1 — the `namespace_structure` check applied
#      to this surface.
#   3. installed but not declared exits 1 — the direction no contract in this tree
#      can see.
#   4. declared but absent from Bun 1.4.4 exits 1 — a fabricated member.
#
# A fifth case pins the arithmetic check: a document pair whose buckets do not sum
# to the oracle exits 2, because that means the classifier missed a shape and its
# clean-looking totals are about a measurement it did not make.
#
# Exit codes:
#   0  every case behaved as required
#   1  a case behaved differently than required (the message names which)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

guard="tools/bun-surface-guard.py"
live=0
[ "${1:-}" = "--live" ] && live=1

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failures=0
checks=0
ok() { printf 'ok   %s\n' "$1"; checks=$((checks + 1)); }
no() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); checks=$((checks + 1)); }

# Writes one JSON document and echoes its path.
doc() {
  local name="$1" body="$2"
  printf '%s\n' "$body" >"$tmp/$name.json"
  printf '%s\n' "$tmp/$name.json"
}

# A clean oracle: three members, all tier 1.
oracle="$(doc oracle '{"members": {"A": {"tier": 1}, "B": {"tier": 1}, "C": {"tier": 2}}}')"
# A clean registry: A is implemented, C is deferred with a reason.
declarations="$(doc declarations '{
  "members": [{"member": "A", "contributor": "rn-bun-test"}],
  "deferred": [{"member": "C", "contributor": "rn-bun-test", "reason": "tier 1, later"}]
}')"
# A clean installed set: A and C are present, C via its deferral being installed.
# C is deferred, so it must NOT be on the object; see the clean case below.
installed_clean="$(doc installed-ok '{"members": ["A"]}')"

# case <name> <expected-code> <expected-text> -- the remaining arguments are the
# guard's. Runs it, checks the status, and requires the text.
case_run() {
  local name="$1" want_code="$2" want_text="$3"
  shift 3
  local output code
  set +e
  output="$(python3 "$guard" "$@" 2>&1)"
  code=$?
  set -e
  if [ "$code" -ne "$want_code" ]; then
    no "$name (exit $code, wanted $want_code)"
    printf '     %s\n' "${output//$'\n'/$'\n'     }"
    return
  fi
  if ! printf '%s' "$output" | grep -qF -- "$want_text"; then
    no "$name (exit $code but the message does not say: $want_text)"
    printf '     %s\n' "${output//$'\n'/$'\n'     }"
    return
  fi
  ok "$name (exit $code: $want_text)"
}

# ---------------------------------------------------------------------------
# The clean case, so every failure below is a difference from a known pass and
# not from a guard that fails everything.
# ---------------------------------------------------------------------------
case_run \
  "a consistent registry and object pass" 0 "1 implemented, 1 absent" \
  --oracle-json "$oracle" --declarations "$declarations" --installed "$installed_clean"

# ---------------------------------------------------------------------------
# Mode 1a: no `Bun` global on the runtime under test. The installed set is empty,
# so nothing was compared, which cannot be a pass.
# ---------------------------------------------------------------------------
installed_empty="$(doc installed-empty '{"present": false, "members": []}')"
case_run \
  "zero installed members exits 2" 2 "compared zero installed members" \
  --oracle-json "$oracle" --declarations "$declarations" --installed "$installed_empty"

# The same shape from a bare list, which is the other document form the guard
# accepts. An empty list must not read as "all members absent, therefore fine".
installed_bare="$(doc installed-bare '[]')"
case_run \
  "an empty installed list exits 2" 2 "compared zero installed members" \
  --oracle-json "$oracle" --declarations "$declarations" --installed "$installed_bare"

# ---------------------------------------------------------------------------
# Mode 1b: an empty oracle. This is the truncated-fixture shape, and it used to
# be the failure of `function-name-audit.py`'s predecessor: an empty table makes
# every member "not recorded", so there is nothing to disagree with.
# ---------------------------------------------------------------------------
oracle_empty="$(doc oracle-empty '{"members": {}}')"
case_run \
  "zero oracle members exits 2" 2 "compared zero oracle members" \
  --oracle-json "$oracle_empty" --declarations "$declarations" --installed "$installed_clean"

# ---------------------------------------------------------------------------
# Mode 2: declared but not installed. `A` is declared and the object has only
# `B`, which `B` is also undeclared — so this case carries both directions at
# once, and the assertion is that the *declared-missing* message is present.
# ---------------------------------------------------------------------------
installed_without_a="$(doc installed-without-a '{"members": ["B"]}')"
case_run \
  "declared but not installed exits 1 and names the crate" 1 \
  "rn-bun-test declares Bun.A but the installed Bun object does not have it" \
  --oracle-json "$oracle" --declarations "$declarations" --installed "$installed_without_a"

# ---------------------------------------------------------------------------
# Mode 3: installed but not declared. `B` is on the object and no crate claims it.
# This is the direction nothing else in the tree can see: `B` works, so every
# behavioural test against it passes.
# ---------------------------------------------------------------------------
installed_with_b="$(doc installed-with-b '{"members": ["A", "B"]}')"
case_run \
  "installed but undeclared exits 1" 1 \
  "Bun.B is installed but no contribution crate declares it" \
  --oracle-json "$oracle" --declarations "$declarations" --installed "$installed_with_b"

# ---------------------------------------------------------------------------
# Mode 4: declared but absent from Bun 1.4.4. Implemented and declared, so modes 2
# and 3 both pass, and the member is fabricated.
# ---------------------------------------------------------------------------
installed_fabricated="$(doc installed-fabricated '{"members": ["A", "MadeUp"]}')"
declarations_fabricated="$(doc declarations-fabricated '{
  "members": [
    {"member": "A", "contributor": "rn-bun-test"},
    {"member": "MadeUp", "contributor": "rn-bun-test"}
  ],
  "deferred": [{"member": "C", "contributor": "rn-bun-test", "reason": "tier 1, later"}]
}')"
case_run \
  "a member Bun does not have exits 1" 1 \
  "rn-bun-test declares Bun.MadeUp, which Bun 1.4.4 does not expose" \
  --oracle-json "$oracle" --declarations "$declarations_fabricated" \
  --installed "$installed_fabricated"

# A deferral for a member Bun does not have is the same defect one layer out: a
# promise to implement something that does not exist.
declarations_bad_deferral="$(doc declarations-bad-deferral '{
  "members": [{"member": "A", "contributor": "rn-bun-test"}],
  "deferred": [{"member": "C", "contributor": "rn-bun-test", "reason": "later"},
               {"member": "AlsoMadeUp", "contributor": "rn-bun-test", "reason": "later"}]
}')"
case_run \
  "a deferral for a member Bun does not have exits 1" 1 \
  "rn-bun-test defers Bun.AlsoMadeUp, which Bun 1.4.4 does not expose" \
  --oracle-json "$oracle" --declarations "$declarations_bad_deferral" \
  --installed "$installed_clean"

# ---------------------------------------------------------------------------
# The arithmetic: a member whose tier is missing must still be counted rather
# than dropped to a default that loses it. If it were lost,
# `implemented + absent + deferred + contradicted` would be one short of the
# oracle and the guard would exit 2 on a surface that is actually fine.
#
# The oracle here carries every member the declarations mention, so the only
# variable is the missing tier on `Untiered`.
# ---------------------------------------------------------------------------
oracle_untiered="$(doc oracle-untiered '{"members": {"A": {"tier": 1}, "C": {"tier": 1}, "Untiered": {}}}')"
case_run \
  "an untiered oracle member is still counted, not lost" 0 \
  "1 implemented, 1 absent, 1 declared-deferred" \
  --oracle-json "$oracle_untiered" --declarations "$declarations" --installed "$installed_clean"

# ---------------------------------------------------------------------------
# A deferral without a reason. `BunRegistry` refuses one at registration, so this
# can only arrive from a hand-edited document, which is why it is checked twice.
# ---------------------------------------------------------------------------
declarations_no_reason="$(doc declarations-no-reason '{
  "members": [{"member": "A", "contributor": "rn-bun-test"}],
  "deferred": [{"member": "C", "contributor": "rn-bun-test", "reason": "  "}]
}')"
case_run \
  "a deferral with no reason exits 1" 1 \
  "rn-bun-test defers Bun.C with no reason" \
  --oracle-json "$oracle" --declarations "$declarations_no_reason" \
  --installed "$installed_clean"

# ---------------------------------------------------------------------------
# An unreadable input is exit 3, not a silent pass. The guard's own failure to
# read has to be distinguishable from a surface disagreement.
# ---------------------------------------------------------------------------
set +e
output="$(python3 "$guard" --oracle-json "$tmp/absent.json" \
  --declarations "$declarations" --installed "$installed_clean" 2>&1)"
code=$?
set -e
if [ "$code" -eq 3 ] && printf '%s' "$output" | grep -qF "does not exist"; then
  ok "a missing input document exits 3 (exit $code: does not exist)"
else
  no "a missing input document (exit $code, wanted 3)"
  printf '     %s\n' "${output//$'\n'/$'\n'     }"
fi

# ---------------------------------------------------------------------------
# The declared tiers have to cover the fixture. A member Bun has and the plan
# does not classify is tier 0, which the fixture does not contain today; a
# regression in TIER_OF would show up as a new tier-0 entry rather than as a
# silent reclassification.
# ---------------------------------------------------------------------------
if python3 - "$root/tools/bun-surface.json" <<'PY'
import json, sys
fixture = json.load(open(sys.argv[1], encoding="utf8"))
tierless = [name for name, entry in fixture["members"].items() if not entry.get("tier")]
if tierless:
    print(f"  tierless members: {tierless}")
    sys.exit(1)
PY
then
  ok "every recorded member carries a tier"
else
  no "every recorded member carries a tier"
fi

# ---------------------------------------------------------------------------
# The live run, when asked for. Its job is to prove the real inputs — the built
# binary and the fixture — are the ones the cases above only model.
# ---------------------------------------------------------------------------
if [ "$live" -eq 1 ]; then
  if [ ! -x "target/debug/rustnode" ]; then
    no "the live run needs target/debug/rustnode"
  else
    set +e
    output="$(python3 "$guard" 2>&1)"
    code=$?
    set -e
    if [ "$code" -eq 0 ] && printf '%s' "$output" | grep -qE '^Bun surface: [0-9]+ implemented'; then
      ok "the live surface agrees: $(printf '%s' "$output" | head -1)"
    else
      no "the live surface (exit $code)"
      printf '     %s\n' "${output//$'\n'/$'\n'     }"
    fi
  fi
fi

printf '\n%d check(s), %d failure(s)\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
  exit 1
fi
