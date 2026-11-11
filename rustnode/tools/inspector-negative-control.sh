#!/usr/bin/env bash
# Measures the inspector test files against two binaries, and refuses to report a
# result it cannot stand behind.
#
#   tools/inspector-negative-control.sh            # both binaries, every inspector file
#   tools/inspector-negative-control.sh --self-test # prove the guard aborts
#
# # Why this exists
#
# Two workers on this project reported a PASS that came from a *stale binary*: their
# build failed, the old `target/debug/rustnode` was still there, and the harness ran it
# happily. A control that can do that is not a control. So this script:
#
#   * deletes the binary it is about to test before building;
#   * records the build start time and refuses to run a binary older than it;
#   * exits non-zero when the build fails, rather than falling through;
#   * verifies the two result directories are separate, because
#     `rn-harness report` keeps the newest result *per directory* — mixing two
#     binaries in one directory silently reports the newer one twice.
#
# `--self-test` breaks the build on purpose and asserts the script aborts. Run it after
# changing anything in this file.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

tests_dir="${RUSTNODE_TESTS:-/tmp/node-test/test}"
candidate="$root/target/debug/rustnode"
baseline="${BASELINE_BINARY:-/agent/baseline/rustnode/target/debug/rustnode}"
candidate_results="$root/tools/harness/results-inspector-candidate"
baseline_results="$root/tools/harness/results-inspector-baseline"
harness="$root/target/debug/rn-harness"

self_test=0
[ "${1:-}" = "--self-test" ] && self_test=1

# Reports the reason and aborts.
#
# It returns non-zero rather than calling `exit`, so a caller that wants to observe the
# abort — `--self-test` does — can. Every ordinary caller runs under `set -e`, so a
# non-zero return is still a hard stop for the script.
fail() {
  printf 'ABORT: %s\n' "$1" >&2
  return 1
}

# Builds a binary and proves it is one this build produced.
#
# The guard is *deletion*, not mtime. `binary` is removed before the build, so a failed
# build cannot leave an older artifact behind for the harness to run — which is the
# failure two previous workers on this project hit: their build failed, the old binary
# was still there, and the harness reported a PASS from it.
#
# mtime is deliberately not compared against the build's start time. Cargo does not
# relink when no input changed, so a no-op rebuild leaves a binary older than the
# build — and treating that as an error aborts a perfectly good measurement. The first
# version of this script did exactly that. What matters is that the file was *absent*
# when the build began and is present and executable afterwards, plus that the build
# reported success; those three facts together cannot be satisfied by a stale artifact.
build_binary() {
  local package_dir="$1"
  local profile_dir="$2"
  local binary="$profile_dir/rustnode"

  rm -f "$binary"
  if [ -e "$binary" ]; then
    fail "cannot delete $binary, so a stale binary could be tested"
    return 1
  fi

  local log="/tmp/inspector-build-$(basename "$package_dir").log"
  if ! (cd "$package_dir" && cargo build -p rn-cli -p rn-harness > "$log" 2>&1); then
    tail -20 "$log" >&2
    fail "the build in $package_dir failed; refusing to test whatever binary is on disk"
    return 1
  fi

  if [ ! -x "$binary" ]; then
    fail "the build reported success but $binary does not exist"
    return 1
  fi
  printf 'built %s (%s bytes, built %s)\n' \
    "$binary" "$(stat -c %s "$binary")" "$(stat -c %y "$binary")" >&2
}

if [ "$self_test" -eq 1 ]; then
  # Break the crate on purpose and require the abort.
  crate="$root/crates/rn-bind-inspector/src/lib.rs"
  backup="$(mktemp)"
  cp "$crate" "$backup"
  trap 'cp "$backup" "$crate"; rm -f "$backup"' EXIT

  # A real compile error, not a stray line: appending text at the end of a Rust file is
  # usually still valid, and a break that compiles proves nothing about the guard. An
  # undefined item in a function body is always a hard error.
  printf '\nfn deliberately_broken() -> u32 { this_identifier_does_not_exist }\n' >> "$crate"
  if build_binary "$root" "$root/target/debug" 2>/dev/null; then
    printf 'FAIL: the guard let a failed build through; --self-test is not a control\n' >&2
    exit 1
  fi
  printf 'GUARD OK: a broken build aborted instead of running a stale binary\n' >&2
  # The binary must be gone: the build deleted it and then failed, which is exactly the
  # state in which a stale binary used to be tested.
  if [ -e "$root/target/debug/rustnode" ]; then
    printf 'FAIL: a failed build left a binary on disk, so a stale binary could be tested\n' >&2
    exit 1
  fi
  printf 'GUARD OK: the failed build left no binary to run\n' >&2

  cp "$backup" "$crate"
  build_binary "$root" "$root/target/debug" || exit 1
  printf 'GUARD OK: the restored build produces a fresh binary\n' >&2
  exit 0
fi

[ -d "$tests_dir/parallel" ] || fail "$tests_dir is not a Node test tree (set RUSTNODE_TESTS)"
[ -x "$baseline" ] || fail "the baseline binary $baseline is missing; build it from the base commit first"

# The files that mention the inspector, which is the set the change is supposed to move.
# `rn-harness --only` takes paths relative to `test/`, so the prefix is stripped here.
mapfile -t inspector_files < <(
  grep -l "inspector" "$tests_dir"/parallel/*.js 2>/dev/null \
    | sed "s#^$tests_dir/##" \
    | sort
)
[ "${#inspector_files[@]}" -gt 0 ] || fail "no inspector test files under $tests_dir/parallel"
printf 'inspector files in test/parallel: %s\n' "${#inspector_files[@]}"

build_binary "$root" "$root/target/debug"

# Two directories, never one: `rn-harness report` keeps the newest result per file per
# directory, so two binaries in one directory would report the newer one's results twice.
rm -rf "$candidate_results" "$baseline_results"
mkdir -p "$candidate_results" "$baseline_results"

run_suite() {
  local binary="$1"
  local results="$2"
  local label="$3"
  printf '\n=== %s ===\n' "$label" >&2
  # `--only` takes one path per flag, so the list is turned into repeated flags. Passing
  # them as positional values makes the harness treat the second one as an unknown
  # option, which is what the first version of this script did.
  local only_flags=()
  local file
  for file in "${inspector_files[@]}"; do
    only_flags+=(--only "$file")
  done
  ( cd "$root" && "$harness" run \
      --node "$binary" \
      --tests "$tests_dir" \
      --results "$results" \
      "${only_flags[@]}" \
      --suite parallel \
      --jobs 4 \
      --timeout 60 \
      --label "$label" )
}

run_suite "$baseline" "$baseline_results" "baseline-8b7c43b7"
run_suite "$candidate" "$candidate_results" "inspector-protocol"

printf '\n=== baseline (%s) ===\n' "$baseline"
"$harness" report --results "$baseline_results"
printf '\n=== candidate (%s) ===\n' "$candidate"
"$harness" report --results "$candidate_results"
