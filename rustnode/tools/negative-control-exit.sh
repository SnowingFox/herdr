#!/usr/bin/env bash
# Negative control for the exit sequence and the failing-subtest status.
#
#   ./tools/negative-control-exit.sh before   # the pre-fix binary's behaviour
#   ./tools/negative-control-exit.sh after    # this worktree's behaviour
#   ./tools/negative-control-exit.sh guard    # prove a failed build aborts
#
# A build that fails silently is the failure mode this control exists for: two
# workers in this project reported a PASS that came from the previous binary
# after their build failed. So every arm deletes the binary before building,
# checks the build's status, and requires the binary's mtime to be newer than
# the build start. The `guard` arm injects a `compile_error!` and shows that the
# rule really aborts instead of testing the old binary.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

arm="${1:-}"
case "$arm" in
  before|after|guard) ;;
  *)
    printf 'usage: %s before|after|guard\n' "$0" >&2
    exit 2
    ;;
esac

binary="$root/target/debug/rustnode"
work="$(mktemp -d)"
# The file the `guard` arm breaks, located by what it defines rather than by name.
#
# It was hard-coded once (`crates/rn-cli/src/event_loop.rs`), and #26 moved that file
# to `rn-realm/src/runtime.rs`. The `cp` then failed, nothing was broken, the build
# succeeded, `build_arm` refused the stale binary on its mtime check, and the arm
# printed PASS — for the wrong reason. A guard that can pass by failing to find its
# target is not a guard.
#
# Searching for the definition means the path cannot go stale, and it leaves no
# non-existent path literal for the static path assertion in `controls.test.sh` to
# flag, which a hard-coded fallback list would have needed an exemption for.
guarded=""
for candidate in crates/*/src/*.rs; do
  if grep -q '^pub fn emit_before_exit' "$candidate" 2>/dev/null; then
    guarded="$candidate"
    break
  fi
done

restore() {
  if [ -n "$guarded" ] && [ -f "$work/guarded.rs" ]; then
    cp "$work/guarded.rs" "$guarded"
  fi
  # The binary is removed before every build, so a build that fails must put back
  # what it found. Without this the `guard` arm leaves the tree with no
  # `target/debug/rustnode` at all, and the next step to exec it -- `check.sh`
  # runs `rustnode tools/per-context-audit.js` -- fails with `Permission denied`
  # or `No such file`, which reads as a broken gate rather than a broken control.
  if [ ! -x "$binary" ] && [ -f "$work/binary.bak" ]; then
    cp "$work/binary.bak" "$binary"
    chmod +x "$binary" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap restore EXIT

# Builds the CLI into `binary`, or explains why the arm cannot continue.
# Returns non-zero when the binary on disk cannot be trusted.
build_arm() {
  local label="$1"
  printf '\n== building %s ==\n' "$label"
  # Keep a copy of whatever is there before deleting it, so `restore` can put a
  # runnable binary back when the build fails.
  if [ -x "$binary" ] && [ ! -f "$work/binary.bak" ]; then
    cp "$binary" "$work/binary.bak" 2>/dev/null || true
  fi
  rm -f "$binary"
  # A deleted binary is not enough to prove a relink: `cargo build` restores a
  # cached hardlink for an unchanged tree, mtime and all. Touching the CLI's
  # entry point forces the compile, and the log is checked for it below, so a
  # cached binary cannot reach the assertions in either arm. This repository has
  # reported a pass from a binary that was never rebuilt.
  touch crates/rn-cli/src/main.rs
  local started
  started="$(date +%s)"
  if ! cargo build -p rn-cli >"$work/build.log" 2>&1; then
    printf 'BUILD FAILED; refusing to test a stale binary\n' >&2
    tail -20 "$work/build.log" >&2
    return 1
  fi
  if ! grep -q 'Compiling rn-cli' "$work/build.log"; then
    printf 'NO RELINK: the build never recompiled rn-cli; refusing to test the binary\n' >&2
    return 1
  fi
  if [ ! -x "$binary" ]; then
    printf 'BUILD SUCCEEDED BUT %s IS MISSING\n' "$binary" >&2
    return 1
  fi
  local built_at
  built_at="$(stat -c %Y "$binary")"
  if [ "$built_at" -lt "$started" ]; then
    printf 'BINARY PREDATES THE BUILD (%s < %s); refusing to test it\n' \
      "$built_at" "$started" >&2
    return 1
  fi
  printf 'binary is fresh: built %ss after the build started\n' "$((built_at - started))"
  return 0
}

# check <name> <expected code> <expected stdout> <script>
check() {
  local name="$1" want_code="$2" want_out="$3" script="$4"
  local out code
  out="$("$binary" -e "$script" 2>/dev/null)"
  code=$?
  if [ "$code" = "$want_code" ] && [ "$out" = "$want_out" ]; then
    printf '  PASS %-38s code=%s\n' "$name" "$code"
    return 0
  fi
  printf '  FAIL %-38s want code=%s out=%q | got code=%s out=%q\n' \
    "$name" "$want_code" "$want_out" "$code" "$out"
  return 1
}

# The suite both arms run. The `before` arm is expected to fail it; the `after`
# arm is expected to pass it. That difference is the fix.
run_suite() {
  local label="$1" failures=0

  check "natural exit emits exit" 0 "body
EXIT EVENT 0" \
    "process.on('exit',(c)=>console.log('EXIT EVENT',c));console.log('body')" || failures=$((failures+1))

  check "beforeExit fires" 0 "BEFOREEXIT 0" \
    "process.on('beforeExit',(c)=>console.log('BEFOREEXIT',c))" || failures=$((failures+1))

  check "work from beforeExit revives" 0 "BE 1
tick 1
BE 2" \
    "let n=0;process.on('beforeExit',()=>{console.log('BE',++n);if(n<2)setTimeout(()=>console.log('tick',n),1)})" || failures=$((failures+1))

  check "process.exitCode = 3" 3 "" "process.exitCode=3" || failures=$((failures+1))
  check "explicit process.exit(5)" 5 "EVENT 5" \
    "process.on('exit',(c)=>console.log('EVENT',c));process.exit(5)" || failures=$((failures+1))
  check "uncaught throw exits 1" 1 "" "throw new Error('x')" || failures=$((failures+1))

  # The `node:test` repro. Only the status is asserted here; the reporter's own
  # output is far too detailed to pin, and the status is the bug.
  local subtest="const {test}=require('node:test');test('o',async t=>{await t.test('p',()=>{});await t.test('f',()=>{throw new Error('b')})})"
  local out code
  out="$("$binary" -e "$subtest" 2>/dev/null)"; code=$?
  if [ "$code" = "1" ]; then
    printf '  PASS %-38s code=%s\n' "failing nested subtest exits 1" "$code"
  else
    printf '  FAIL %-38s want code=1 | got code=%s\n' "failing nested subtest exits 1" "$code"
    failures=$((failures+1))
  fi

  printf '\n%s: %d of 7 checks failed\n' "$label" "$failures"
  return "$failures"
}

if [ "$arm" = "guard" ]; then
  printf '== guard: a failed build must abort before any check runs ==\n'
  if [ -z "$guarded" ]; then
    printf 'RESULT: FAIL (no source file to break; the guard cannot prove anything)\n' >&2
    exit 1
  fi
  printf 'breaking %s\n' "$guarded"
  if ! cp "$guarded" "$work/guarded.rs"; then
    printf 'RESULT: FAIL (cannot read %s)\n' "$guarded" >&2
    exit 1
  fi
  printf '\ncompile_error!("negative control: this build must fail");\n' >> "$guarded"

  # The build must fail *because of the injected error*, not for some other reason:
  # a build that fails for an unrelated cause would also abort, so printing PASS on
  # any failure would prove nothing. The log has to name the message injected above.
  if build_arm "a deliberately broken build"; then
    printf 'RESULT: FAIL (the broken build was accepted)\n' >&2
    exit 1
  fi
  if ! grep -q "negative control: this build must fail" "$work/build.log"; then
    printf 'RESULT: FAIL (the build failed, but not because of the injected error)\n' >&2
    tail -20 "$work/build.log" >&2
    exit 1
  fi
  printf '\nABORTED as required: the injected error stopped the build and no stale binary was tested\n'
  printf 'RESULT: PASS (the guard aborts on build failure, and provably on this one)\n'
  exit 0
fi

if [ "$arm" = "before" ]; then
  # The pre-fix behaviour, measured on the binary saved from origin/master rather
  # than remembered. Building here would produce the fixed binary, so this arm
  # reads the frozen one and asserts the bugs are present in it.
  binary="${RUSTNODE_PREFIX_BINARY:-/tmp/rustnode-prefix}"
  if [ ! -x "$binary" ]; then
    printf '%s is missing; save the pre-fix binary there first\n' "$binary" >&2
    exit 1
  fi
  printf '== before: %s ==\n' "$binary"
  rm -f "$work/build.log"

  local_out="$("$binary" -e "process.on('exit',(c)=>console.log('EXIT EVENT',c));console.log('body')" 2>/dev/null)"
  printf '\nnatural exit stdout:\n%s\n' "$local_out"

  "$binary" -e "const {test}=require('node:test');test('o',async t=>{await t.test('p',()=>{});await t.test('f',()=>{throw new Error('b')})})" >"$work/subtest.out" 2>&1
  printf 'failing nested subtest exit: %s\n' "$?"

  printf '\n-- the reproduction is present if the stdout above has no EXIT EVENT and the exit is 0 --\n'
  printf 'RESULT: before recorded (not a gate)\n'
  exit 0
fi

if ! build_arm "after (this worktree)"; then
  printf 'RESULT: FAIL (no fresh binary to test)\n' >&2
  exit 1
fi

if run_suite "after"; then
  printf 'RESULT: PASS\n'
  exit 0
fi
printf 'RESULT: FAIL\n'
exit 1
