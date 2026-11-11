#!/usr/bin/env bash
# Negative control for the versions/IP-family change.
#
# The guard has to prove four things, in this order:
#
#   1. The measured binary was built by *this* invocation. Cargo hardlinks a
#      previously built artifact out of `target/debug/deps` and preserves its
#      old mtime, so a no-op build would leave a binary older than the build
#      start and the freshness assertion would fail on the good path. The
#      sources are touched first so the build really rebuilds.
#   2. The observations really come from the binary. The good build must report
#      uppercase families and more than four `process.versions` keys.
#   3. A broken build aborts instead of reporting a result. `compile_error!` is
#      injected into `crates/rn-cli/src/versions.rs`, which `main.rs` declares
#      as `mod versions;` and `bootstrap.rs` calls, so it is genuinely compiled.
#      A file that nothing references would compile away and the control would
#      be vacuous.
#   4. The tree is restored byte-for-byte, and that is *checked*. The snapshot
#      it compares against outlives the restore, so the check can fail; an
#      earlier version compared against a file `restore()` had just deleted and
#      swallowed the result with `|| true`, which could never fail at all.
#
# Exit codes: 0 the control behaved as required, 1 the control misbehaved (a
# check it asserts about the runtime failed), 3 no verdict (the build or the
# restore could not be completed, so the measurement says nothing about the
# runtime).
#
# These match `tools/cipher-negative-control.sh`, whose header states the same
# contract.
# `1` versus `3` is the distinction between "the runtime did the wrong thing"
# and "this run cannot tell you". A restore that fails after deleting its own
# backup fits neither of the first two answers, so it exits 3 and says the tree
# is suspect.
#
# The success path ends with an explicit `exit 0`. Letting the script fall off
# the end makes its status whatever the last command returned, so a later edit
# could leave it printing PASS while exiting non-zero.
#
# The victim is mutated in place, so an interrupted run would otherwise leave a
# deliberately broken source file behind. Four things prevent that: `restore`
# is the EXIT trap, `cp` and `cmp` are both checked so it cannot report success
# after a failed copy, the backups are kept when a restore fails, and a startup
# guard refuses to run on a tree that already contains the injected line — the
# SIGKILL case, which no trap can catch.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

binary="target/debug/rustnode"
victim="crates/rn-cli/src/versions.rs"

# A previous run killed with SIGKILL, or the machine going down mid-build, would
# leave the injected line in the tree with no trap able to help. Refuse to run on
# that rather than measuring a tree that is already broken for the wrong reason.
# Checked before the snapshot is taken, so the "original" is never the injected
# version.
if grep -q "compile_error!(\"negative control" "$victim"; then
  printf 'RESULT: NO VERDICT — %s still contains the injected compile_error!\n' "$victim" >&2
  printf 'from a previous interrupted run; restore it before running this control.\n' >&2
  exit 3
fi

snapshot="$(mktemp)"
if ! cp "$victim" "$snapshot" || ! cmp -s "$victim" "$snapshot"; then
  rm -f "$snapshot"
  printf 'RESULT: NO VERDICT — could not snapshot %s, so a restore cannot be verified\n' "$victim" >&2
  exit 3
fi

# Modelled on `restore_self_test` in `tools/cipher-negative-control.sh`, which
# exists in this shape because the naive version lost a source file: the copy
# was unchecked, the backup was deleted unconditionally, and the script printed
# success. Three properties, each load-bearing:
#
#   * `cp` and `cmp` are checked in one condition, so a short write is caught in
#     the same expression that made it rather than trusted.
#   * the comparison happens before any deletion, and the snapshot is only
#     removed once it is known to match.
#   * the backups are kept when a restore fails, so a recoverable tree is not
#     turned into a lost one.
restore() {
  if ! cp "$snapshot" "$victim" || ! cmp -s "$snapshot" "$victim"; then
    printf 'RESULT: NO VERDICT — could not restore %s; the original is at %s\n' \
      "$victim" "$snapshot" >&2
    printf 'The tree is suspect: %s may not match its pre-run contents.\n' "$victim" >&2
    return 1
  fi
  rm -f "$snapshot"
  return 0
}

# The wrapper's status is the trap's status. A bare `trap restore EXIT` would
# run the function and discard whether it succeeded, which is exactly how a
# damaged tree gets reported behind a green run.
#
# `restore` does not set a "already ran" flag and instead returns immediately
# unless the snapshot still exists, so re-entry is impossible: the successful
# path deletes the snapshot and the failed path returns 1 without deleting it,
# and either way a second call is a no-op. Setting a flag *before* the copy, as
# the cipher self-test does, is the other way to get this right; this control
# uses the snapshot's existence so there is only one piece of state.
restore_once() {
  [ -e "$snapshot" ] || return 0
  restore
}
trap 'restore_once || exit 3' EXIT

fail() {
  printf 'RESULT: FAIL — %s\n' "$1"
  exit 1
}

observe() {
  "$binary" -e '
    const os = require("os");
    const faces = Object.values(os.networkInterfaces()).flat().map((a) => a.family);
    const keys = Object.keys(process.versions).length;
    console.log(`families=${[...new Set(faces)].sort().join(",")} versions=${keys}`);
  ' 2>&1
}

# --- 1. good build, forced fresh -------------------------------------------
echo "touch sources so the build is not a no-op"
touch crates/rn-cli/src/main.rs "$victim"
rm -f "$binary"
start=$(date +%s)

if ! cargo build -p rn-cli >/tmp/negctl-build.log 2>&1; then
  printf 'RESULT: NO VERDICT — the unmodified tree did not build; see /tmp/negctl-build.log\n' >&2
  exit 3
fi

[ -x "$binary" ] || fail "the build produced no $binary"
binary_mtime=$(stat -c %Y "$binary")
[ "$binary_mtime" -ge "$start" ] || fail "binary is older than the build start (mtime $binary_mtime < $start)"

good="$(observe)"
echo "good build: $good"

case "$good" in
  *"families=IPv4,IPv6"*) ;;
  *) fail "the good build does not report uppercase families: $good" ;;
esac

# Parse the count instead of matching `versions=N` as a string: a glob for
# `versions=1` would also match `versions=13` and reject a good build.
version_count="${good##*versions=}"
case "$version_count" in
  ''|*[!0-9]*) fail "could not read a version count out of: $good" ;;
esac
if [ "$version_count" -le 4 ]; then
  fail "process.versions was not populated past the original four keys: $good"
fi

# --- 2. broken build must abort --------------------------------------------
printf '\ncompile_error!("negative control: this build is supposed to fail");\n' >> "$victim"
rm -f "$binary"

if cargo build -p rn-cli >/tmp/negctl-broken.log 2>&1; then
  fail "the deliberately broken build SUCCEEDED, so the control proves nothing"
fi

if [ -e "$binary" ]; then
  fail "the broken build left a binary behind, so a stale result could be reported"
fi

echo "--- broken build aborted (tail) ---"
grep -E "^error" /tmp/negctl-broken.log | tail -3

# --- 3. restore, and prove it against a snapshot that still exists ----------
# Run it here rather than leaving it to the trap so a failure is reported as the
# restore failure it is, before the rebuild can muddy the output.
if ! restore; then
  exit 3
fi

if ! cargo build -p rn-cli >/tmp/negctl-restore.log 2>&1; then
  printf 'RESULT: NO VERDICT — the restored tree did not rebuild\n' >&2
  exit 3
fi
after="$(observe)"
echo "restored build: $after"
[ "$after" = "$good" ] || fail "the restored build reports something different: $after != $good"

printf 'RESULT: PASS — fresh good build observed, broken build aborted, tree restored\n'
# The PASS is a message, not a verdict. Without this the script ends on the
# `printf`, so it reports printf's status -- 0 even when the tree is not what it
# claims. `set -uo pipefail` has no `-e` here on purpose (the control has to
# evaluate failing arms instead of aborting on them), which is exactly why the
# success path has to name its code.
exit 0
