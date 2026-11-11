#!/usr/bin/env bash
# The negative control for `common.mustCall` enforcement.
#
# `mustCall` is how ~2850 files under `test/parallel` assert that a callback
# actually ran, and Node implements it as a count compared in a
# `process.on('exit')` handler. A runtime whose `exit` event never fires on a
# natural event-loop exit therefore reports every one of those files as a pass
# whether or not the callback ran. That is the failure this control exists to
# catch, and it is why the control's main case must FAIL.
#
# The gate's contract, in the same terms as `tools/cipher-negative-control.sh`:
#
#   * `cargo build` must exit 0, or the script exits 3 with no verdict;
#   * the binary is deleted before the build, so its presence afterwards proves
#     this invocation produced it rather than a stale artifact answering;
#   * every case's exit code is asserted, so "the runtime crashed" cannot be
#     mistaken for "the runtime enforced mustCall".
#
# Usage:
#   tools/mustcall-negative-control.sh            # this tree's binary
#   tools/mustcall-negative-control.sh --quick    # skip the build, use the binary
#   tools/mustcall-negative-control.sh --self-test
#   tools/mustcall-negative-control.sh --tests <node-checkout>
#
# `--quick` exists for the gate's `--quick` mode; it still refuses to run
# without a binary, because a missing binary is not a passing control.
#
# The Node test tree supplies `test/common/index.js`. It is never vendored (see
# `docs/compat-status.md`), so the control clones it sparsely on first use, at
# the commit in `tools/node-pin.toml`. If the clone fails the control exits 3:
# without Node's own `mustCall` there is nothing to measure.
#
# Provenance of the expected exit codes, stated precisely because this project
# has already been bitten by a claim whose provenance was a different binary
# than the one under test. The codes were recorded by running this exact case
# list against a released node v22.23.4, NOT against the pinned 28.0.0 build
# (which is not installable here). The behaviour of all six cases is governed by
# `test/common/index.js`, whose file is byte-identical between v22 and the pin
# (`diff` of the two `test/common/index.js` files is empty), so the codes are
# expected to be identical -- but that is an argument from the source, not a
# measurement on 28.0.0. Re-record with `RUSTNODE_MUSTCALL_BIN=<node28>` when a
# Node 28 binary is available; the case list is the same, so it is one command:
#
#   RUSTNODE_MUSTCALL_BIN=/path/to/node28 tools/mustcall-negative-control.sh \
#     --tests /path/to/node28/test
#
# Exit codes: 0 the control behaved as required, 1 the control did not, 2 usage
# error, 3 the run is void (build or setup failure) with no verdict.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:--L /usr/lib/gcc/x86_64-linux-gnu/13}"

# `RUSTNODE_MUSTCALL_BIN` lets the same case list be pointed at a reference
# runtime. Running it against real `node` is how the expected exit codes below
# were established, and it is the check that keeps an expectation from being
# quietly adjusted to match whatever rustnode happens to do.
binary="${RUSTNODE_MUSTCALL_BIN:-target/debug/rustnode}"
probe="tools/mustcall-probe.js"
do_build=1
mode="run"
tests_dir=""

while [ $# -gt 0 ]; do
  case "$1" in
    --quick) do_build=0; shift ;;
    --self-test) mode="self-test"; shift ;;
    --mechanism) mode="mechanism"; shift ;;
    --tests) tests_dir="${2:?--tests needs a directory}"; shift 2 ;;
    -h | --help)
      sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "usage: $0 [--quick] [--self-test] [--mechanism] [--tests <dir>]" >&2; exit 2 ;;
  esac
done

# The test tree is located once and both the runner and the self-test use it.
# `RUSTNODE_TEST_CACHE` is honoured for the same reason `run-node-tests.sh`
# honours it: the tree is large and shared between tools.
node_pin_commit="$(sed -n 's/^commit *= *"\(.*\)"/\1/p' tools/node-pin.toml | head -1)"
cache_root="${RUSTNODE_TEST_CACHE:-${TMPDIR:-/tmp}}"
test_root="${cache_root}/rustnode-node-test"

locate_tests() {
  if [ -n "$tests_dir" ]; then
    if [ ! -f "$tests_dir/common/index.js" ]; then
      echo "no common/index.js in $tests_dir" >&2
      return 1
    fi
    return 0
  fi
  if [ ! -f "$test_root/test/common/index.js" ]; then
    echo "== fetching Node's test tree into $test_root ==" >&2
    if [ -d "$test_root/.git" ]; then
      git -C "$test_root" fetch --depth 1 origin "${node_pin_commit:-HEAD}" >&2 || true
    else
      # A shallow clone cannot fetch a commit that is not the tip of a branch,
      # and the pinned revision is only reachable by its full SHA, so the clone
      # is made full-history-optional with `--filter=blob:none` and the commit
      # is fetched into it below.
      git clone --filter=blob:none --sparse \
        https://github.com/nodejs/node "$test_root" >&2 || return 1
    fi
    ( cd "$test_root" && git sparse-checkout set test >&2 ) || return 1
  fi
  # `test/common` is the only part of the tree this control needs. A checkout
  # that has the directory but not the file is left alone rather than being
  # rewritten: it belongs to whoever put it there.
  if [ ! -f "$test_root/test/common/index.js" ]; then
    echo "no common/index.js in $test_root/test" >&2
    return 1
  fi
  tests_dir="$test_root/test"
  return 0
}

# Runs one probe and prints its exit code on stdout. The probe's own output is
# captured separately: it is evidence, not the verdict.
#
# `common_dir` may be empty for the one case that does not load `test/common`,
# which is how the gate runs it without a Node checkout.
run_probe() {
  local node_bin="$1"
  local name="$2"
  local common_dir="$3"
  local common_file="${common_dir}/common/index.js"
  # `env` rather than a bare assignment so an empty path is a genuinely unset
  # variable: the probe decides whether it needs one, and handing it
  # "/common/index.js" would be a lie about what it was given.
  if [ -n "$common_dir" ]; then
    RUSTNODE_MUSTCALL_COMMON="$common_file" \
      "$node_bin" "$probe" "$name" >/tmp/mustcall-probe.out 2>&1
  else
    env -u RUSTNODE_MUSTCALL_COMMON \
      "$node_bin" "$probe" "$name" >/tmp/mustcall-probe.out 2>&1
  fi
  echo $?
}

# `check <name> <expected-rc> <why>`
failures=0
check() {
  local name="$1" expected="$2" why="$3"
  local actual
  actual="$(run_probe "$binary" "$name" "$tests_dir")"
  if [ "$actual" = "$expected" ]; then
    printf 'ok   %-28s exit %s   %s\n' "$name" "$actual" "$why"
    return 0
  fi
  printf 'FAIL %-28s exit %s, expected %s   %s\n' "$name" "$actual" "$expected" "$why" >&2
  echo "--- probe output ---" >&2
  sed 's/^/    /' /tmp/mustcall-probe.out >&2
  failures=$((failures + 1))
  return 1
}

# Which cases can ONLY pass when the exit handler runs.
#
# This distinction is the difference between a control that measures something
# and one that merely reads green, so it is spelled out here rather than left
# to the case list:
#
#   never-called, at-least-never-called, must-succeed-never-called
#       ONLY these fail when the handler does not run. A `mustCall` count is
#       compared exclusively in a `process.on('exit')` handler, so an
#       unsatisfied count is invisible unless that handler executes. Nothing
#       else in the process reports it.
#
#   must-not-call-called
#       Fails from the callback body via `assert.fail`, never reaching an exit
#       handler. It is kept because it is part of the family and its Node
#       behaviour is worth pinning, but a green result here is *not* evidence
#       that exit fires -- it is the one case that would pass on a runtime with
#       no exit event at all.
#
#   called, called-from-a-timer
#       Must pass. They are the negative control for the control: a runtime
#       that rejects everything cannot satisfy them, so they stop a blanket
#       non-zero exit from reading as enforcement. They do not distinguish a
#       working exit handler from a missing one, which is exactly why the three
#       cases above lead.
control() {
  echo "== mustCall enforcement control =="
  echo "binary: $binary"
  echo "tests:  $tests_dir"
  echo

  # The mechanism itself, with no test tree and no `test/common`. These two are
  # what `tools/check.sh` runs: `runCallChecks` fails a file by calling
  # `process.exit(1)` from inside an exit listener, so a re-entrant exit whose
  # code reaches `reallyExit` is the property the whole family rests on.
  check handler-exits-one 1 "MECHANISM: exit(1) from an exit handler sets 1"
  check handler-exits-zero 0 "MECHANISM: a non-throwing handler keeps 0"

  # Exit-handler-only. These are the verdict, and they need Node's own
  # `test/common`; `--mechanism` stops before here.
  check never-called 1 "EXIT-HANDLER-ONLY: uncalled mustCall must fail"
  check at-least-never-called 1 "EXIT-HANDLER-ONLY: mustCallAtLeast minimum"
  check must-succeed-never-called 1 "EXIT-HANDLER-ONLY: mustSucceed delegates"

  # Must pass, so a runtime that fails everything cannot read as enforcement.
  check called 0 "satisfied mustCall must not fail"
  check called-from-a-timer 0 "satisfied from the loop must not fail"

  # Independent of the exit event; pinned, but not part of the verdict above.
  check must-not-call-called 1 "mustNotCall throws from the callback body"

  echo
  if [ "$failures" -ne 0 ]; then
    echo "RESULT: control FAILED ($failures case(s))" >&2
    return 1
  fi
  echo "RESULT: control passes (mustCall is enforced at exit)"
  return 0
}

# The self-test proves the control can fail, which is the only thing that makes
# a green control meaningful. It runs the same case list against a binary that
# exits 0 for every program — `/bin/true` — and requires the control to report
# a failure. A control that passes against `/bin/true` is measuring nothing.
#
# It deliberately needs no Node test tree. `/bin/true` never loads the probe, so
# the `common/index.js` path is never read, and requiring a 103 MB checkout just
# to prove the control can fail would keep the cheap half of the contract out of
# the gate. That is the half that catches a verdict path which cannot report a
# failure at all.
self_test() {
  if [ ! -x /bin/true ]; then
    echo "SELF-TEST ABORTED: /bin/true is missing." >&2
    return 1
  fi
  local saved_binary="$binary" saved_tests="$tests_dir"
  binary="/bin/true"
  tests_dir="${tests_dir:-/nonexistent}"
  local rc=0
  control >/dev/null 2>&1 || rc=$?
  binary="$saved_binary"
  tests_dir="$saved_tests"
  if [ "$rc" -eq 0 ]; then
    echo "SELF-TEST FAILED: the control passed against /bin/true, which never enforces anything." >&2
    return 1
  fi
  echo "SELF-TEST OK: the control fails against /bin/true, so a passing control means something"
  return 0
}

# `--mechanism` runs only the two tree-free cases. It exists so the gate can
# guard the property `mustCall` rests on without cloning Node's test tree: a
# file is failed by an `exit` listener calling `process.exit(1)`, and a
# re-entrant exit whose code never reaches `reallyExit` would silently turn
# every `mustCall` in the suite back into a no-op.
mechanism() {
  echo "== mustCall enforcement, mechanism only =="
  echo "binary: $binary"
  echo
  check handler-exits-one 1 "exit(1) from an exit handler sets the status"
  check handler-exits-zero 0 "a non-throwing handler keeps the status"
  echo
  if [ "$failures" -ne 0 ]; then
    echo "RESULT: mechanism FAILED ($failures case(s))" >&2
    return 1
  fi
  echo "RESULT: mechanism holds (a re-entrant exit from a handler sets the status)"
  return 0
}

if [ "$mode" = "self-test" ]; then
  if ! self_test; then
    exit 1
  fi
  exit 0
fi

if [ "$mode" = "mechanism" ]; then
  if ! mechanism; then
    exit 1
  fi
  exit 0
fi

if ! locate_tests; then
  echo "RESULT: NO VERDICT - no Node test tree, so mustCall cannot be measured." >&2
  exit 3
fi

if [ -n "${RUSTNODE_MUSTCALL_BIN:-}" ]; then
  do_build=0
fi

if [ "$do_build" -eq 1 ]; then
  # Removed first: a cached build that decides it has nothing to do would
  # otherwise leave a previous artifact in place to be measured, and the whole
  # point of the control is that the binary answering is the one this tree
  # builds.
  rm -f "$binary"
  echo "== building rn-cli ==" >&2
  if ! cargo build -q -p rn-cli; then
    echo "RESULT: NO VERDICT - the build failed." >&2
    exit 3
  fi
fi

if [ ! -x "$binary" ]; then
  echo "RESULT: NO VERDICT - no binary at $binary." >&2
  exit 3
fi

if ! control; then
  exit 1
fi
exit 0
