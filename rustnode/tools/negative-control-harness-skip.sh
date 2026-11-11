#!/usr/bin/env bash
# Negative control for skip classification in rn-harness.
#
#   ./tools/negative-control-harness-skip.sh
#
# Proves three things about the harness change:
#
#   1. The four rows named in the bug report, recorded by the *old* harness as
#      `passed: true` with exit 0, are reported as skipped by the new code.
#   2. A genuinely passing row and a genuinely failing row in the same result
#      file still classify as pass and fail, so the change is not a blanket
#      reclassification.
#   3. A failed build aborts instead of testing whatever binary was left over.
#      This is the failure mode that has produced a false PASS three times in
#      this project, so it is exercised rather than assumed: the binary is
#      deleted, its mtime must be newer than the build start, and the script
#      deliberately breaks the build once to show the guard fires.
#
# The result-directory proof needs no build at all; only the abort arm compiles.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

harness="$root/target/debug/rn-harness"
fixture="$root/tools/harness/tests/fixtures/run-1794255368768-skips.json"
work="$(mktemp -d)"

cleanup() {
  # A killed run must never leave the deliberately broken source behind: the
  # next `cargo build` would fail for a reason unrelated to the code.
  if [ -n "${break_target:-}" ] && [ -f "${work:-}/main.rs.orig" ]; then
    cp "$work/main.rs.orig" "$break_target" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  printf 'RESULT: FAIL — %s\n' "$1" >&2
  exit 1
}

printf '== 1. real-data classification (no build needed) ==\n'
[ -f "$fixture" ] || fail "fixture $fixture is missing"

# The fixture is copied under the old run id so the report treats it like any
# other recorded run. Nothing about the fixture is special-cased in the harness.
mkdir -p "$work/results"
cp "$fixture" "$work/results/run-1794255368768.json"

# The report must come from a freshly built binary. Delete it first so a stale
# one cannot answer the question, then rebuild and check the mtime.
#
# Touching the sources is load-bearing. `cargo` hardlinks a previously built
# artifact out of `target/debug/deps` and preserves its original mtime, so a
# build that does no work can leave a binary that looks older than the build even
# though it is byte-identical to the current source. Touching forces the
# recompile, which makes the mtime assertion below mean what it says.
rm -f "$harness"
find "$root/tools/harness/src" -name '*.rs' -exec touch {} +
build_started="$(date +%s)"
if ! cargo build -q -p rn-harness >"$work/build.log" 2>&1; then
  printf 'BUILD FAILED; refusing to test a stale binary\n' >&2
  tail -30 "$work/build.log" >&2
  fail "rn-harness did not build"
fi
[ -x "$harness" ] || fail "build succeeded but $harness is missing"
built_at="$(stat -c %Y "$harness")"
[ "$built_at" -ge "$build_started" ] || fail \
  "binary predates the build ($built_at < $build_started)"

"$harness" report --results "$work/results" --json >"$work/report.json" 2>"$work/report.err" \
  || fail "report failed: $(cat "$work/report.err")"
"$harness" report --results "$work/results" >"$work/report.txt" 2>&1 \
  || fail "text report failed"

printf -- '--- table ---\n'
cat "$work/report.txt"

python3 - "$work/report.json" <<'PY' || fail "the recorded skips did not classify correctly"
import json
import sys

report = json.load(open(sys.argv[1]))

expected_skips = {
    # four `1..0 # Skipped:` plan-line skips
    "parallel/test-child-process-exec-any-shells-windows.js",
    "parallel/test-child-process-stdio-overlapped.js",
    "parallel/test-cluster-dgram-ipv6only.js",
    "parallel/test-cluster-net-listen-ipv6only-false.js",
    # one bare-glyph skip: `﹣ <anonymous> # SKIP`, no plan line at all
    "parallel/test-assert-checktag.js",
}
reported_skips = {row["file"] for row in report["skips"]}

missing = expected_skips - reported_skips
if missing:
    print(f"FAIL: these recorded skips were not reported as skipped: {sorted(missing)}")
    sys.exit(1)

# The hollow passes: exited 0, output said a failure. Two mechanisms, and the
# control must see both or it only guards half the rule.
expected_misreported = {
    "parallel/test-assert-deep.js",          # reporter glyph ✖
    "parallel/test-runner-reporters.js",     # reporter glyph ✖
    "parallel/test-crypto-keygen-rsa-pss.js", # node:assert:16736: Uncaught ...
}
reported_misreported = {
    row["file"] for row in report["failures"] if row["misreported"]
}
if expected_misreported - reported_misreported:
    print("FAIL: these exit-0 rows reported a failing test but were not corrected: "
          f"{sorted(expected_misreported - reported_misreported)}")
    sys.exit(1)

# The control must not be a blanket reclassification: the real pass and the real
# failure in the same file must keep their old verdicts.
if report["passed"] != 1:
    print(f"FAIL: expected exactly 1 pass, got {report['passed']}")
    sys.exit(1)
if report["skipped"] != 5:
    print(f"FAIL: expected 5 skips, got {report['skipped']}")
    sys.exit(1)
if report["failed"] != 4:
    print(f"FAIL: expected 4 failures, got {report['failed']}")
    sys.exit(1)
if report["misreported"] != 3:
    print(f"FAIL: expected 3 corrected rows, got {report['misreported']}")
    sys.exit(1)
if report["misreported"] > report["failed"]:
    print("FAIL: misreported must be a subset of failed")
    sys.exit(1)
if report["passed"] + report["skipped"] + report["failed"] != report["total"]:
    print("FAIL: the three outcomes do not reconcile with total")
    sys.exit(1)

print(f"PASS: {report['skipped']} skips (incl. one bare-glyph) / {report['passed']} pass / {report['failed']} failure "
      f"({report['misreported']} corrected hollow passes) / {report['total']} total; "
      f"rate {report['rate']:.3f} over judged files")
PY
[ $? -eq 0 ] || exit 1

printf '\n== 2. deliberate build failure must abort ==\n'

# Break the crate for real. The break is appended to a module that `main.rs`
# actually declares: a new, unreferenced source file is never compiled, so
# writing one would let the build succeed and prove nothing. The original is
# saved byte-for-byte and restored below.
break_target="$root/tools/harness/src/main.rs"
cp "$break_target" "$work/main.rs.orig"

printf '\ncompile_error!("negative control: this build is supposed to fail");\n' >>"$break_target"

rm -f "$harness"
printf 'appended a compile_error! to %s and deleted %s\n' "$break_target" "$harness"

if cargo build -q -p rn-harness >"$work/break.log" 2>&1; then
  cp "$work/main.rs.orig" "$break_target"
  fail "the deliberately broken build SUCCEEDED; the abort guard cannot be trusted"
fi

if [ -e "$harness" ]; then
  cp "$work/main.rs.orig" "$break_target"
  fail "the broken build still produced a binary; a stale-binary check alone would not save us"
fi

printf -- '--- build failure (tail) ---\n'
grep -m3 -E "compile_error|error\[|error:" "$work/break.log" || tail -5 "$work/break.log"
printf 'the build failed and left no binary, so nothing could be tested\n'

# Restore, and prove the tree builds again so the control cannot leave it broken.
cp "$work/main.rs.orig" "$break_target"
if ! cmp -s "$break_target" "$work/main.rs.orig"; then
  fail "could not restore $break_target"
fi
if ! cargo build -q -p rn-harness >"$work/restore.log" 2>&1; then
  printf 'RESTORE BUILD FAILED after removing the deliberate break\n' >&2
  tail -20 "$work/restore.log" >&2
  fail "the tree did not build again after the negative control"
fi
[ -x "$harness" ] || fail "restored build did not produce $harness"
printf 'restored build succeeded; %s is back\n' "$harness"

printf '\nRESULT: PASS — recorded skips are skipped, pass/fail unchanged, broken build aborts\n'
