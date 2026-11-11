#!/usr/bin/env bash
# The negative control for the cipher slice, in a form that cannot pass on a
# stale binary.
#
# The control is the expression `new CipherBase(...)`, reached through
# `crypto.createCipheriv`. Before this crate landed `CipherBase` was absent from
# `internalBinding('crypto')`, so every call threw
# `TypeError: CipherBase is not a constructor`. After it lands the same
# expression constructs a handle and produces ciphertext.
#
# Two workers on this project have already been caught by a build failure
# followed by a "PASS" from the previously built binary, so this script refuses
# to report anything unless the build it ran in this same invocation succeeded:
#
#   * `cargo build` must exit 0, or the script exits 2 with no verdict;
#   * the binary must be newer than the moment the build started, so a stale
#     artifact cannot supply the answer;
#   * the before case must contain the expected failure text, and is a failure
#     of the control if it does not.
#
# Usage:
#   tools/cipher-negative-control.sh before   # against origin/master's binary
#   tools/cipher-negative-control.sh after    # against this tree's binary
#
# `before` builds `origin/master` in a throwaway worktree, so the comparison is
# against a tree that genuinely lacks the crate rather than against a remembered
# string.

set -uo pipefail

# `root` is the repository root; `workspace` is the cargo workspace inside it.
# The script uses both, because a worktree of `origin/master` is a whole
# checkout and its cargo workspace is in the same subdirectory.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workspace="$root/rustnode"
cd "$workspace"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:--L /usr/lib/gcc/x86_64-linux-gnu/13}"

mode="${1:-after}"
case "$mode" in
  before|after) ;;
  *) echo "usage: $0 [before|after]" >&2; exit 2 ;;
esac

# The control goes through `internalBinding("crypto")` rather than
# `crypto.createCipheriv`, because the latter also runs `prepareSecretKey`, which
# calls the *keys* slice's `isKeyObject`. Measuring the public API here would
# report the keys worker's gap as a cipher gap, which is exactly the kind of
# misattribution this control exists to prevent.
control='
const { internalBinding } = require("internal/test/binding");
const binding = internalBinding("crypto");
if (typeof binding.CipherBase !== "function") {
  throw new TypeError("CipherBase is not a constructor");
}
const cipher = new binding.CipherBase(
  true, "aes-256-cbc", Buffer.alloc(32), Buffer.alloc(16), -1);
const out = cipher.update(Buffer.from("0123456789abcdef"));
cipher.final();
process.stdout.write("CONSTRUCTED " + out.length + "\n");
'

build_and_run() {
  local tree="$1"
  local label="$2"
  local target_dir="${3:-}"

  echo "== building $label at $tree ==" >&2
  # The binary is removed first so a no-op build cannot leave a previous
  # artifact in place to be measured, and the build's exit status is checked
  # before anything is reported. Removing it is what makes existence afterwards
  # proof that this invocation produced it; an mtime comparison is too coarse
  # for a cached build that finishes inside one second.
  rm -f "$tree/rustnode/target/debug/rustnode" ${target_dir:+"$target_dir/debug/rustnode"}
  if ! ( cd "$tree/rustnode" && CARGO_TARGET_DIR="${target_dir:-$tree/rustnode/target}" \
         cargo build -q -p rn-cli ); then
    echo "BUILD FAILED for $label; refusing to report a verdict." >&2
    exit 2
  fi

  local binary="${target_dir:-$tree/rustnode/target}/debug/rustnode"
  if [ ! -x "$binary" ]; then
    echo "no binary at $binary after a build that reported success; refusing a verdict." >&2
    exit 2
  fi

  # `--expose-internals` is what makes `internal/test/binding` reachable
  # outside the test tree.
  ( cd "$tree/rustnode" && "$binary" --expose-internals -e "$control" 2>&1 )
}

status=0

if [ "$mode" = "before" ]; then
  scratch="$(mktemp -d)"
  worktree="$scratch/master"
  # A copy of this tree's target dir, so the master build reuses the vendored
  # OpenSSL and the prebuilt v8 archive instead of compiling them again. The
  # fingerprints are source-scoped, so cargo rebuilds only what differs.
  target_copy="$scratch/target"
  echo "== creating a worktree of origin/master for the before measurement ==" >&2
  if ! git -C "$root" worktree add --detach "$worktree" origin/master >/dev/null 2>&1; then
    echo "could not create a worktree of origin/master" >&2
    exit 2
  fi
  trap 'git -C "$root" worktree remove --force "$worktree" >/dev/null 2>&1 || true; rm -rf "$scratch"' EXIT
  cp -a "$workspace/target" "$target_copy"

  output="$(build_and_run "$worktree" "origin/master" "$target_copy")"
  echo "$output"
  if echo "$output" | grep -q "CipherBase is not a constructor"; then
    echo "RESULT: control failed as required (CipherBase is not a constructor)"
  else
    echo "RESULT: UNEXPECTED - the before control did not report the missing constructor" >&2
    status=1
  fi
else
  output="$(build_and_run "$root" "this tree" "")"
  echo "$output"
  if echo "$output" | grep -q "CONSTRUCTED"; then
    echo "RESULT: control passes (CipherBase constructed and produced output)"
  else
    echo "RESULT: UNEXPECTED - the after control did not construct ($output)" >&2
    status=1
  fi
fi

exit "$status"
