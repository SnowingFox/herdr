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
#   * `cargo build` must exit 0, or the script exits 3 with no verdict;
#   * the binary is deleted before the build, so its presence afterwards proves
#     this invocation produced it rather than a stale artifact supplying the
#     answer;
#   * the before case must contain the expected failure text, and is a failure
#     of the control if it does not.
#
# Exit codes: 0 the control behaved as required, 1 the control did not, 2 usage
# error, 3 the run is void (build or setup failure) with no verdict.
#
# The build is kept out of the captured command substitution for exactly that
# reason: `output="$(build_and_run ...)"` runs the function in a subshell, so an
# `exit 2` there ends only the subshell and the script falls through to the
# `status=1` path. That reported a build failure as "the control did not
# behave", which is a different answer from "there is no answer". The build now
# runs in the main shell and the failure exits 3 deliberately.
#
# Usage:
#   tools/cipher-negative-control.sh before   # against origin/master's binary
#   tools/cipher-negative-control.sh after    # against this tree's binary
#   tools/cipher-negative-control.sh --self-test  # prove the exit-3 contract
#
# `before` builds `origin/master` in a throwaway worktree, so the comparison is
# against a tree that genuinely lacks the crate rather than against a remembered
# string.

set -uo pipefail

# `root` is the repository root; `workspace` is the cargo workspace inside it.
# The script uses both, because a worktree of `origin/master` is a whole
# checkout and its cargo workspace is in the same subdirectory.
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

# The build is a separate step from the run, deliberately. The run's output has
# to be captured for its text, and a command substitution is a subshell, so an
# `exit` inside it would end only the subshell: the script would fall through to
# the `status=1` path and report "the control did not behave", which is a
# different answer from "there is no answer". Keeping the build in the main
# shell is what lets a failed build exit 3 directly.
#
# `build` returns 3 for a void run instead of exiting, because it is called from
# the `before` and `after` branches and each caller decides what to print.
build() {
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
    return 3
  fi

  local binary="${target_dir:-$tree/rustnode/target}/debug/rustnode"
  if [ ! -x "$binary" ]; then
    echo "no binary at $binary after a build that reported success; refusing a verdict." >&2
    return 3
  fi
  return 0
}

# Runs the control with the binary `build` just produced. `--expose-internals` is
# what makes `internal/test/binding` reachable outside the test tree.
run_control() {
  local tree="$1"
  local target_dir="${2:-}"
  local binary="${target_dir:-$tree/rustnode/target}/debug/rustnode"
  ( cd "$tree/rustnode" && "$binary" --expose-internals -e "$control" 2>&1 )
}

# Proves the void-run contract instead of asserting it in prose. A `compile_error!`
# is appended to a crate the build must compile, the script is run in `after`
# mode, and the exit status must be 3 — not 1, which is what the script used to
# report when the `exit` was swallowed by the command substitution. The source
# and the prebuilt binary are both restored, including when an assertion fails,
# so a self-test run leaves the tree exactly as it found it.
self_test() {
  local target="crates/rn-cli/src/main.rs"
  local binary="target/debug/rustnode"
  local source_backup binary_backup had_binary=0
  source_backup="$(mktemp)"
  binary_backup="$(mktemp)"
  cp "$target" "$source_backup"
  if [ -f "$binary" ]; then
    cp "$binary" "$binary_backup"
    had_binary=1
  fi

  restore_self_test() {
    cp "$source_backup" "$target"
    rm -f "$source_backup"
    if [ "$had_binary" -eq 1 ]; then
      cp "$binary_backup" "$binary"
    fi
    rm -f "$binary_backup"
  }
  trap restore_self_test EXIT

  printf '\ncompile_error!("injected by cipher-negative-control.sh --self-test");\n' >>"$target"

  local rc=0
  local out
  out="$("$self_path" after 2>&1)" || rc=$?

  local failures=0
  if [ "$rc" -ne 3 ]; then
    echo "FAIL: a build failure exited $rc, expected 3" >&2
    failures=$((failures + 1))
  fi
  if printf '%s' "$out" | grep -q "RESULT: control passes"; then
    echo "FAIL: a build failure still produced a PASS verdict" >&2
    failures=$((failures + 1))
  fi
  if printf '%s' "$out" | grep -q "CONSTRUCTED"; then
    echo "FAIL: a build failure still produced ciphertext output" >&2
    failures=$((failures + 1))
  fi
  if ! printf '%s' "$out" | grep -q "BUILD FAILED"; then
    echo "FAIL: the build failure was not reported" >&2
    failures=$((failures + 1))
  fi

  restore_self_test
  trap - EXIT

  if [ "$failures" -ne 0 ]; then
    echo "SELF-TEST FAILED ($failures assertion(s))" >&2
    return 1
  fi
  echo "SELF-TEST OK: a build failure exits 3, reports no verdict, and emits no PASS"
  return 0
}

if [ "$mode" = "--self-test" ]; then
  self_test
  exit $?
fi

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
    exit 3
  fi
  trap 'git -C "$root" worktree remove --force "$worktree" >/dev/null 2>&1 || true; rm -rf "$scratch"' EXIT
  cp -a "$workspace/target" "$target_copy"

  if ! build "$worktree" "origin/master" "$target_copy"; then
    echo "RESULT: NO VERDICT - the before measurement could not be built." >&2
    exit 3
  fi
  output="$(run_control "$worktree" "$target_copy")"
  echo "$output"
  if echo "$output" | grep -q "CipherBase is not a constructor"; then
    echo "RESULT: control failed as required (CipherBase is not a constructor)"
  else
    echo "RESULT: UNEXPECTED - the before control did not report the missing constructor" >&2
    status=1
  fi
else
  if ! build "$root" "this tree" ""; then
    echo "RESULT: NO VERDICT - this tree could not be built." >&2
    exit 3
  fi
  output="$(run_control "$root" "")"
  echo "$output"
  if echo "$output" | grep -q "CONSTRUCTED"; then
    echo "RESULT: control passes (CipherBase constructed and produced output)"
  else
    echo "RESULT: UNEXPECTED - the after control did not construct ($output)" >&2
    status=1
  fi
fi

exit "$status"
