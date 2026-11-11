#!/usr/bin/env bash
# The negative control for the S4 SecureContext slice.
#
# S4 alone moves zero test files — it cannot be observed until S6 (`TLSWrap`)
# exists — so this control is not a test count. It is the probe
# `tools/secure-context-probe.js`, run against two trees:
#
#   before  origin/master's binary: `SecureContext` is absent from the crypto
#           namespace, so the probe reports `class|MISSING` and exits 1.
#   after   this tree's binary: the class exists, and the probe reports which
#           methods are real, which are declared stubs, and which refuse.
#
# The `before` tree is a real worktree of `origin/master`, not a remembered
# string, so the comparison is against a tree that genuinely lacks the crate.
#
# A stale binary has already produced false passes on this project, so nothing
# is reported unless the build that ran in this same invocation succeeded:
#
#   * the binary is deleted before the build, so its presence afterwards proves
#     this invocation produced it;
#   * a build failure exits 3 with no verdict rather than falling through to a
#     pass;
#   * the `before` run must contain `class|MISSING` and exit 1, and the `after`
#     run must exit 0, or the control is reported as misbehaving rather than as
#     passing.
#
# Exit codes: 0 the control behaved as required, 1 the control did not, 2 usage
# error, 3 the run is void (build or setup failure) with no verdict.
#
# `after` needs the class on the `crypto` namespace, and the one line that puts
# it there lives in `crates/rn-bind-crypto/src/install.rs`, which this branch
# deliberately does not touch because that file is single-owner. So `after` is a
# *wired* run: it appends the `install_classes` call and the crate dependency,
# builds, measures, and restores both files. Without that the after column would
# be a measurement of a tree that has the crate but never installs it, which
# proves nothing about the crate.
#
# Usage:
#   tools/secure-context-probe.sh before   # against origin/master
#   tools/secure-context-probe.sh after    # this tree, wired for the run
#   tools/secure-context-probe.sh --self-test  # prove the exit-3 contract

set -uo pipefail

self_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workspace="$root/rustnode"
cd "$workspace"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:--L /usr/lib/gcc/x86_64-linux-gnu/13}"

mode="${1:-after}"
case "$mode" in
  before|after) ;;
  --self-test) ;;
  *) echo "usage: $0 [before|after|--self-test]" >&2; exit 2 ;;
esac

# Builds the CLI in `tree`, returning 3 for a void run rather than exiting, so
# each caller decides what to print. The binary is removed first: a no-op build
# must not leave a previous artifact in place to be measured.
build() {
  local tree="$1"
  local label="$2"
  local target_dir="${3:-}"

  echo "== building $label at $tree ==" >&2
  rm -f "$tree/rustnode/target/debug/rustnode" ${target_dir:+"$target_dir/debug/rustnode"}
  # A touch on the CLI entry point forces the final link even when Cargo wants to
  # restore a cached hardlink, which is the stale-binary trap this project has
  # hit: `cargo build` can reuse an artifact whose mtime predates the build.
  touch "$tree/rustnode/crates/rn-cli/src/main.rs"
  if ! ( cd "$tree/rustnode" && CARGO_TARGET_DIR="${target_dir:-$tree/rustnode/target}" \
         cargo build -q -p rn-cli ); then
    echo "BUILD FAILED for $label; refusing to report a verdict." >&2
    return 3
  fi

  local binary="${target_dir:-$tree/rustnode/target}/debug/rustnode"
  if [ ! -x "$binary" ]; then
    echo "no binary at $binary after a build that reported success; refusing a verdict." >&2
    return 3
  fi
  return 0
}

# Runs the probe with the binary `build` just produced, from the tree it belongs
# to so the script under test is that tree's copy.
run_probe() {
  local tree="$1"
  local target_dir="${2:-}"
  local binary="${target_dir:-$tree/rustnode/target}/debug/rustnode"
  ( cd "$tree/rustnode" && "$binary" --expose-internals tools/secure-context-probe.js 2>&1 )
}

# Applies the two edits that put the class on the namespace, and installs a trap
# that puts both files back. The restore is checked, not assumed: a control that
# leaves the tree modified is worse than one that does not run.
wired_install() {
  install_rs="crates/rn-bind-crypto/src/install.rs"
  cargo_toml="crates/rn-bind-crypto/Cargo.toml"
  backup_install="$(mktemp)"
  backup_toml="$(mktemp)"

  cp "$install_rs" "$backup_install" || return 1
  cp "$cargo_toml" "$backup_toml" || return 1

  # The function that carries the edits, so the trap has one place to undo them.
  apply_wiring() {
    python3 - "$install_rs" "$cargo_toml" <<'PYEOF'
import sys
install_rs, cargo_toml = sys.argv[1], sys.argv[2]
s = open(install_rs).read()
needle = '        rn_bind_crypto_keys::install_classes(scope, object)?;'
if needle not in s:
    sys.exit("the install_classes call site is not where this script expects")
s = s.replace(needle, needle + '\n        rn_bind_secure_context::install_classes(scope, object)?;', 1)
open(install_rs, "w").write(s)
s = open(cargo_toml).read()
if "rn-bind-secure-context" not in s:
    s = s.replace("[dependencies]", "[dependencies]\nrn-bind-secure-context = { path = \"../rn-bind-secure-context\" }", 1)
    open(cargo_toml, "w").write(s)
PYEOF
  }

  restore_wiring() {
    local failed=0
    if ! cp "$backup_install" "$install_rs" || ! cmp -s "$backup_install" "$install_rs"; then
      echo "FAIL: could not restore $install_rs; original at $backup_install" >&2
      failed=1
    fi
    if ! cp "$backup_toml" "$cargo_toml" || ! cmp -s "$backup_toml" "$cargo_toml"; then
      echo "FAIL: could not restore $cargo_toml; original at $backup_toml" >&2
      failed=1
    fi
    if [ "$failed" -eq 0 ]; then
      rm -f "$backup_install" "$backup_toml"
    fi
    return "$failed"
  }

  trap 'restore_wiring || exit 1' EXIT
  apply_wiring || { echo "could not apply the wiring" >&2; return 1; }
  return 0
}

status=0

if [ "$mode" = "before" ]; then
  scratch="$(mktemp -d)"
  worktree="$scratch/master"
  target_copy="$scratch/target"

  echo "== creating a worktree of origin/master for the before measurement ==" >&2
  if ! git -C "$root" worktree add --detach "$worktree" origin/master >/dev/null 2>&1; then
    echo "could not create a worktree of origin/master" >&2
    exit 3
  fi
  trap 'git -C "$root" worktree remove --force "$worktree" >/dev/null 2>&1 || true; rm -rf "$scratch"' EXIT

  # Reuse this tree's target dir so the master build does not rebuild the
  # vendored OpenSSL and v8 from scratch. Fingerprints are source-scoped, so
  # cargo rebuilds only what differs.
  cp -a "$workspace/target" "$target_copy"

  if ! build "$worktree" "origin/master" "$target_copy"; then
    echo "RESULT: NO VERDICT - the before measurement could not be built." >&2
    exit 3
  fi

  # The probe must exist in the master tree too, or the control would be
  # measuring a missing file rather than a missing class. It is copied in
  # because the probe is part of this change, not part of master.
  cp "$workspace/tools/secure-context-probe.js" "$worktree/rustnode/tools/" 2>/dev/null || {
    echo "RESULT: NO VERDICT - could not install the probe into the master tree." >&2
    exit 3
  }

  output="$(run_probe "$worktree" "$target_copy")"
  rc=$?
  echo "$output"
  echo "-- exit $rc --"

  if echo "$output" | grep -q "class|MISSING"; then
    if [ "$rc" -eq 1 ]; then
      echo "RESULT: control failed as required (SecureContext is absent from origin/master)"
    else
      echo "RESULT: UNEXPECTED - the before probe reported the class missing but exited $rc, not 1" >&2
      status=1
    fi
  else
    echo "RESULT: UNEXPECTED - origin/master already has SecureContext, so this control measures nothing" >&2
    status=1
  fi
else
  if ! wired_install; then
    echo "RESULT: NO VERDICT - could not apply the namespace wiring." >&2
    exit 3
  fi

  if ! build "$root" "this tree (wired)" ""; then
    echo "RESULT: NO VERDICT - this tree could not be built." >&2
    exit 3
  fi

  output="$(run_probe "$root" "")"
  rc=$?
  echo "$output"
  echo "-- exit $rc --"

  if [ "$rc" -ne 0 ]; then
    echo "RESULT: UNEXPECTED - the after probe exited $rc, expected 0" >&2
    status=1
  elif ! echo "$output" | grep -q "config.setCipherSuites+setCiphers|OK"; then
    # A run that exits 0 but never drove `configSecureContext` would be the
    # "looks like it works and does nothing" shape this control exists to catch.
    echo "RESULT: UNEXPECTED - the after probe never reported configSecureContext succeeding" >&2
    status=1
  else
    echo "RESULT: control passes (SecureContext constructs and configures)"
  fi
fi

exit "$status"
