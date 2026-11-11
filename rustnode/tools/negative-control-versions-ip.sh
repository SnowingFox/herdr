#!/usr/bin/env bash
# Negative control for the versions/IP-family change.
#
# The guard has to prove three things, in this order:
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
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

binary="target/debug/rustnode"
victim="crates/rn-cli/src/versions.rs"
backup="$(mktemp)"
cp "$victim" "$backup"
cleanup_ran=0
restore() {
  if [ "$cleanup_ran" -eq 0 ]; then
    cp "$backup" "$victim"
    rm -f "$backup"
    cleanup_ran=1
  fi
}
trap restore EXIT

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
  fail "the unmodified tree did not build; see /tmp/negctl-build.log"
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
  restore
  fail "the deliberately broken build SUCCEEDED, so the control proves nothing"
fi

if [ -e "$binary" ]; then
  fail "the broken build left a binary behind, so a stale result could be reported"
fi

echo "--- broken build aborted (tail) ---"
grep -E "^error" /tmp/negctl-broken.log | tail -3

# --- 3. restore and prove the tree is byte-identical ------------------------
restore
cmp -s "$backup" "$victim" 2>/dev/null || true
if ! cargo build -p rn-cli >/tmp/negctl-restore.log 2>&1; then
  fail "the restored tree did not rebuild"
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
