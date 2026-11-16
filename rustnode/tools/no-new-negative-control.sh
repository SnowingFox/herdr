#!/usr/bin/env bash
# Proves the without-`new` audit can fail, and that it fails for the right reason.
#
#   ./tools/no-new-negative-control.sh            # inject, assert, restore
#   ./tools/no-new-negative-control.sh --self-test # also re-run the audit clean
#
# Exit codes:
#   0  every case behaved as documented
#   1  a case did not, or the tree was left modified
#   3  the build failed, so there is no verdict
#
# # Why this exists
#
# `tools/no-new-audit.py` reports a table. A table that has never been seen to
# contain a defect is the same class of problem `tools/controls.test.sh`
# documents: it looks like evidence and has never held any. So this removes a
# guard the audit is supposed to watch for -- the one in `KeyObjectHandle`, which
# is the hole the audit was written to find -- and requires the audit to name it.
#
# # What is injected, exactly
#
# The `if !args.is_construct_call()` block at the top of
# `crates/rn-bind-crypto-keys/src/handle.rs::constructor` is replaced by a
# comment, nothing else. With it gone, a plain `KeyObjectHandle()` call reaches
# `args.this()`, which is the global object, and the constructor returns it. The
# oracle aborts on that call instead (`CHECK(args.IsConstructCall())`), so the
# audit must report `node aborts, rustnode returned object` for exactly that
# member and no other.
#
# The tree is restored from a backup in a `trap`, including on a failure, so a
# failed control cannot leave a modified source file behind.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"
# `CARGO_TARGET_DIR` defeats every stale-binary assumption, including this one:
# the build would succeed and write elsewhere, so the binary under test would be
# the previous one and the injected defect would never run.
unset CARGO_TARGET_DIR

target="crates/rn-bind-crypto-keys/src/handle.rs"
backup="$(mktemp)"
cp "$target" "$backup"

restore() {
  cp "$backup" "$target"
  rm -f "$backup"
}
trap restore EXIT

audit() { python3 tools/no-new-audit.py "$@" 2>&1; }

fail=0
report() { printf '%s %s\n' "$1" "$2"; }
ok() { report "ok  " "$1"; }
no() { report "FAIL" "$1"; fail=$((fail + 1)); }

# The guard, as it appears in the tree. Matched literally so a reworded guard
# fails this control loudly instead of silently injecting nothing.
guard=$(cat <<'RUST'
    if !args.is_construct_call() {
        throw(scope, &KeyError::ConstructCallRequired);
        return;
    }
RUST
)

if ! grep -qF "args.is_construct_call()" "$target"; then
  echo "control: $target has no construct-call guard to remove" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# (1) The clean tree passes, so a later failure is caused by the injection and
#     not by the tree arriving broken.
# ---------------------------------------------------------------------------
if ! audit >/tmp/no-new-control-clean.txt; then
  echo "control: the audit fails on an unmodified tree; nothing to prove" >&2
  tail -5 /tmp/no-new-control-clean.txt >&2
  exit 1
fi
if grep -qE "BAD|MISSING" /tmp/no-new-control-clean.txt; then
  echo "control: the audit reports a problem on an unmodified tree" >&2
  exit 1
fi
ok "the unmodified tree passes the audit"

# ---------------------------------------------------------------------------
# (2) Remove the guard and rebuild.
# ---------------------------------------------------------------------------
python3 - "$target" "$guard" <<'PY'
import sys

path, guard = sys.argv[1], sys.argv[2]
with open(path, encoding="utf8") as handle:
    source = handle.read()
if source.count(guard) != 1:
    raise SystemExit(f"control: the guard appears {source.count(guard)} times, expected 1")
with open(path, "w", encoding="utf8") as handle:
    handle.write(source.replace(guard, "    // NEGATIVE CONTROL: guard removed.\n"))
PY

if ! cargo build -p rn-cli >/tmp/no-new-control-build.txt 2>&1; then
  echo "control: the build failed, so the control has no verdict" >&2
  tail -20 /tmp/no-new-control-build.txt >&2
  exit 3
fi
ok "the defect builds"

# ---------------------------------------------------------------------------
# (3) The audit must reject it, name the member, and exit non-zero.
# ---------------------------------------------------------------------------
set +e
audit >/tmp/no-new-control-defect.txt
status=$?
set -e

if [ "$status" -ne 1 ]; then
  no "the audit exited $status on a tree with the guard removed (want 1)"
else
  ok "the audit exits 1 on the injected defect"
fi

if grep -q "crypto.KeyObjectHandle" /tmp/no-new-control-defect.txt &&
  grep "crypto.KeyObjectHandle" /tmp/no-new-control-defect.txt | grep -q "BAD"; then
  ok "the audit names crypto.KeyObjectHandle as the failing member"
else
  no "the audit did not report crypto.KeyObjectHandle"
fi

if grep "crypto.KeyObjectHandle" /tmp/no-new-control-defect.txt |
  grep -q "rustnode returned object"; then
  ok "the audit reports the returned object as the symptom"
else
  no "the audit did not report the returned object"
fi

# Exactly one member may be wrong: a wider failure means the injection broke
# something else, and the control would then be proving the wrong thing.
wrong=$(sed -n 's/.*constructors found: .* \([0-9][0-9]*\) wrong$/\1/p' /tmp/no-new-control-defect.txt)
if [ "${wrong:-}" = "1" ]; then
  ok "exactly one constructor is reported wrong"
else
  no "the audit reported '${wrong:-no count}' wrong constructors (want 1)"
fi

# ---------------------------------------------------------------------------
# (4) Restoring puts it back.
# ---------------------------------------------------------------------------
restore
trap - EXIT
if ! cargo build -p rn-cli >/tmp/no-new-control-rebuild.txt 2>&1; then
  echo "control: the restore build failed" >&2
  tail -20 /tmp/no-new-control-rebuild.txt >&2
  exit 3
fi
if audit >/tmp/no-new-control-restored.txt && ! grep -qE "BAD|MISSING" /tmp/no-new-control-restored.txt; then
  ok "the audit passes again once the guard is restored"
else
  no "the audit still fails after restoring the guard"
fi

if [ "$fail" -ne 0 ]; then
  echo "control: $fail case(s) failed" >&2
  exit 1
fi
echo "control: the without-new audit detects a removed construct guard"
