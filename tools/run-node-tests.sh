#!/usr/bin/env bash
# Runs Node's own test suite against rustnode and prints the per-subsystem table.
#
#   ./tools/run-node-tests.sh                       # smoke subset, then the table
#   ./tools/run-node-tests.sh --filter test-fs-     # your subsystem, then the table
#   ./tools/run-node-tests.sh --all                 # the whole suite, then the table
#
# The Node test tree is cloned on first use into a cache directory and never
# committed; pass --tests <dir> to use a checkout you already have.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

node_pin_commit="$(sed -n 's/^commit *= *"\(.*\)"/\1/p' tools/node-pin.toml | head -1)"
cache_root="${RUSTNODE_TEST_CACHE:-${TMPDIR:-/tmp}}"

usage() {
  cat <<'USAGE'
usage: tools/run-node-tests.sh [options] [-- extra rn-harness run options]

Convenience wrapper around `cargo run -p rn-harness`. It builds rustnode and
rn-harness, fetches Node's test/ tree if needed, runs the selection, then prints
the pass table for the result directory.

options:
  --tests <dir>    use this Node checkout's test/ directory instead of cloning
  --test-root <dir> clone Node's test/ tree into this directory (default:
                   $RUSTNODE_TEST_CACHE/node-test, else /tmp/rustnode-node-test)
  --release        test the release binary instead of the debug one
  --no-build       skip cargo build (use binaries already in target/)
  --report-only    only print the table for the existing results
  --results <dir>  result directory (default: tools/harness/results)
  --json           print the table as JSON
  -h, --help       this message

everything else is passed to `rn-harness run` unchanged, for example:
  --filter <substring>  --suite <name>  --only <path>  --limit <n>  --smoke
  --all  --timeout <seconds>  --jobs <n>  --label <name>  --quiet
USAGE
}

tests_dir=""
test_root=""
cargo_profile="dev"
target_dir="debug"
do_build=1
report_only=0
results_dir="tools/harness/results"
json=0
run_args=()

while [ $# -gt 0 ]; do
  case "$1" in
    --tests)
      tests_dir="${2:?--tests needs a directory}"
      shift 2
      ;;
    --test-root)
      test_root="${2:?--test-root needs a directory}"
      shift 2
      ;;
    --results)
      results_dir="${2:?--results needs a directory}"
      shift 2
      ;;
    --release)
      cargo_profile="release"
      target_dir="release"
      shift
      ;;
    --no-build)
      do_build=0
      shift
      ;;
    --report-only)
      report_only=1
      shift
      ;;
    --json)
      json=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      run_args+=("$@")
      break
      ;;
    *)
      run_args+=("$1")
      shift
      ;;
  esac
done

harness="./target/${target_dir}/rn-harness"
node_bin="./target/${target_dir}/rustnode"

if [ "$report_only" -eq 0 ] && [ "$do_build" -eq 1 ]; then
  # Build both binaries in one cargo invocation so the shared workspace
  # dependencies are compiled once.
  cargo build --profile "$cargo_profile" -p rn-cli -p rn-harness
fi

if [ "$report_only" -eq 0 ]; then
  if [ -z "$tests_dir" ]; then
    test_root="${test_root:-${cache_root}/rustnode-node-test}"
    if [ ! -d "${test_root}/test/parallel" ]; then
      echo "fetching Node's test tree into ${test_root}" >&2
      if [ -d "${test_root}/.git" ]; then
        git -C "$test_root" fetch --depth 1 origin "${node_pin_commit:-HEAD}" >&2 || true
      else
        git clone --depth 1 --filter=blob:none --sparse \
          https://github.com/nodejs/node "$test_root" >&2
      fi
      git -C "$test_root" sparse-checkout set test >&2
      echo "note: ${test_root} tracks Node's default branch; rustnode pins" >&2
      echo "      ${node_pin_commit:-an unknown commit} in tools/node-pin.toml." >&2
      echo "      Re-clone at that commit for numbers comparable to a release." >&2
    fi
    tests_dir="${test_root}/test"
  fi
  if [ ! -d "$tests_dir" ]; then
    echo "rustnode: ${tests_dir} is not a directory" >&2
    exit 2
  fi

  "$harness" run \
    --node "$node_bin" \
    --tests "$tests_dir" \
    --results "$results_dir" \
    "${run_args[@]+"${run_args[@]}"}"
fi

if [ "$json" -eq 1 ]; then
  "$harness" report --results "$results_dir" --json
else
  "$harness" report --results "$results_dir"
fi
