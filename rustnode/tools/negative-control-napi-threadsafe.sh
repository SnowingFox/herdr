#!/usr/bin/env bash
# Negative control for the Node-API async work and thread-safe function surface.
#
#   ./tools/negative-control-napi-threadsafe.sh before   # origin/master, no shims
#   ./tools/negative-control-napi-threadsafe.sh after    # this worktree
#   ./tools/negative-control-napi-threadsafe.sh guard    # proves the control can fail
#
# Two arms run the same assertion against a freshly built binary: `before` is the
# commit this work branched from, where the twelve symbols do not exist, and
# `after` is this worktree. The third arm deliberately breaks the build to prove
# the harness in this script is not vacuous.
#
# # Why a failed build must abort
#
# A stale binary has produced a false PASS in this project more than once, and the
# failure mode is invisible: `cargo build` fails, the previous `target/debug/rustnode`
# is still there, the assertion runs against it, and it passes because that binary
# *did* have the feature. So this script deletes the binary before building,
# checks the build's exit status, and requires the binary's mtime to be newer than
# the moment the build started. Any of those failing aborts the arm.
#
# # Why the guard arm injects into `shims.rs`
#
# A previous control in this project was vacuous because it broke a module that
# nothing referenced, so the `compile_error!` was never compiled and the build
# succeeded. The guard arm therefore injects into `crates/rn-napi/src/shims.rs`,
# which is `pub mod shims` in `crates/rn-napi/src/lib.rs` and reachable from
# `rn-cli`'s dependency on `rn-napi` — a file the build genuinely compiles. If the
# guard arm's build *succeeds*, this script reports the control as broken rather
# than as a pass.

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

# The commit this work branched from. Named explicitly rather than as
# `origin/master`, because `origin/master` moves and the `before` arm has to mean
# one fixed tree.
before_revision="da92615c"

# Where the arm's build writes its binary. The `before` arm builds in its own
# worktree, which has its own `target/`, so a single hardcoded path would check the
# wrong file and report a missing binary.
binary="$root/target/debug/rustnode"
shims="crates/rn-napi/src/shims.rs"

work="$(mktemp -d)"
restore() {
  # Undo the guard arm's injection, whatever happened.
  if [ -f "$work/shims.rs" ]; then
    cp "$work/shims.rs" "$shims"
  fi
  rm -rf "$work"
}
trap restore EXIT

# The assertion both real arms run. One definition, so the only difference between
# them is which sources were compiled.
#
# The compiled fixture addon lives outside the tree being built, because the
# `before` arm's checkout has no `addon_async.c`: the addon is this work's, and
# only the runtime differs between the arms. Building it here from the current
# sources is what makes the two runs comparable — an old runtime against a new
# addon, which is the real-world case (an addon built once, run on both).
addon_source="$root/crates/rn-napi/tests/addon"
addon_output="$work/addon.node"

build_addon() {
  if ! cc -shared -fPIC -I "$addon_source" -o "$addon_output" \
      "$addon_source/addon.c" "$addon_source/addon_async.c" -pthread \
      >"$work/addon.log" 2>&1; then
    printf 'the fixture addon did not compile:\n' >&2
    cat "$work/addon.log" >&2
    return 1
  fi
}

script="$(cat <<JS
const addon = require($(printf '%s' "$addon_output" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'));
const assert = require('assert');

// 1. Async work: the value is computed on a pool thread and delivered from the
//    loop's thread. \`executedOffThread\` is the part a synchronous stand-in fails.
addon.runAsyncWork(7, (result) => {
  assert.strictEqual(result.value, 21, 'async work value');
  assert.strictEqual(result.executedOffThread, true, 'execute must run off the loop thread');
  process.stdout.write('ASYNC_OK\n');
});

// 2. Cancellation reaches libuv's queue, so the completion reports cancelled.
addon.queueAndCancel((result) => {
  assert.strictEqual(result.cancelled, true, 'the work must report cancelled');
  process.stdout.write('CANCEL_OK\n');
});

// 3. A real POSIX thread pushes 50 values through the thread-safe function, and
//    they arrive in order on the loop's thread.
const received = [];
addon.startThreadSafeProducer(
  (value) => { received.push(value); },
  50,
  (pushed) => {
    assert.strictEqual(received.length, 50, 'every value must arrive');
    assert.ok(received.every((value, index) => value === index), 'values must arrive in order');
    assert.strictEqual(pushed, 50, 'the finalizer must run once, after the last value');
    process.stdout.write('TSFN_OK\n');
  });

// 4. The context accessor works from the producing thread, not just the creator.
addon.threadSafeFunctionContext((matched) => {
  assert.strictEqual(matched, 1, 'the context must be readable from another thread');
  process.stdout.write('CONTEXT_OK\n');
});
JS
)"

run_arm() {
  local label="$1"
  printf '\n== %s ==\n' "$label"

  # The binary for whatever tree we are in: the `before` arm runs from its own
  # worktree and writes there.
  binary="$PWD/target/debug/rustnode"
  rm -f "$binary"

  local started
  started="$(date +%s)"
  if ! cargo build -p rn-cli >"$work/build.log" 2>&1; then
    printf 'BUILD FAILED; refusing to test a stale binary\n' >&2
    tail -20 "$work/build.log" >&2
    return 1
  fi

  if [ ! -x "$binary" ]; then
    printf 'BUILD SUCCEEDED BUT %s IS MISSING\n' "$binary" >&2
    return 1
  fi

  # mtime in whole seconds, so a build finishing inside the same second as it
  # started must be accepted rather than failing on sub-second rounding.
  local built_at
  built_at="$(stat -c %Y "$binary")"
  if [ "$built_at" -lt "$started" ]; then
    printf 'BINARY PREDATES THE BUILD (%s < %s); refusing to test it\n' \
      "$built_at" "$started" >&2
    return 1
  fi

  if ! build_addon; then
    return 1
  fi

  local status
  timeout 120 "$binary" "$work/script.js" >"$work/stdout" 2>"$work/stderr"
  status=$?

  printf 'exit=%s\n' "$status"
  printf -- '--- stdout ---\n'
  cat "$work/stdout"
  printf -- '--- first error line ---\n'
  grep -m1 -E "Error|error|not defined|symbol lookup" "$work/stderr" || true
  printf '\n'

  local expected="ASYNC_OK CANCEL_OK TSFN_OK CONTEXT_OK"
  local missing=""
  for token in $expected; do
    grep -q "$token" "$work/stdout" || missing="$missing $token"
  done

  if [ "$status" -eq 0 ] && [ -z "$missing" ]; then
    printf 'RESULT: PASS\n'
    return 0
  fi
  printf 'RESULT: FAIL (missing:%s)\n' "${missing:- none}"
  return 1
}

# The assertion script is a file so both arms run byte-identical text.
printf '%s\n' "$script" >"$work/script.js"

case "$arm" in
  before)
    printf 'checking out %s in a temporary worktree\n' "$before_revision"
    # A worktree rather than `git stash`: the `after` arm has to keep its sources,
    # and a checkout in place would destroy them.
    worktree="$work/before"
    if ! git worktree add --detach "$worktree" "$before_revision" >"$work/worktree.log" 2>&1; then
      printf 'could not create the worktree at %s:\n' "$before_revision" >&2
      cat "$work/worktree.log" >&2
      exit 1
    fi
    trap 'git worktree remove --force "$work/before" >/dev/null 2>&1; restore' EXIT
    # The repository root is the herdr checkout; rustnode is a workspace inside it,
    # so the build has to run from the subdirectory or cargo sees the outer
    # manifest and reports that `rn-cli` is not a package.
    cd "$worktree/rustnode"
    # The fixture addon in the `before` tree has no `addon_async.c`; the assertion
    # is the same file, which is the point: it fails there because the runtime
    # cannot load an addon importing these symbols.
    run_arm "before ($before_revision): the shims do not exist"
    exit $?
    ;;
  after)
    run_arm "after: this worktree"
    exit $?
    ;;
  guard)
    printf 'injecting compile_error! into %s to prove a broken build aborts\n' "$shims"
    cp "$shims" "$work/shims.rs"
    # Appended, not prepended: the point is that the file is compiled at all, and a
    # module that is not referenced never reaches the compiler even with an error
    # in it.
    printf '\ncompile_error!("negative control: this build must fail");\n' >>"$shims"

    binary="$root/target/debug/rustnode"
    rm -f "$binary"
    local_started="$(date +%s)"
    if cargo build -p rn-cli >"$work/build.log" 2>&1; then
      printf 'GUARD FAILED: the build succeeded with a compile_error! in a file that is\n' >&2
      printf 'supposed to be compiled. The control is vacuous and proves nothing.\n' >&2
      exit 1
    fi
    printf 'the build failed as it must:\n'
    grep -m1 "negative control: this build must fail" "$work/build.log" ||
      tail -5 "$work/build.log"

    if [ -x "$binary" ]; then
      printf 'GUARD FAILED: a binary survived the failed build, so a stale artifact\n' >&2
      printf 'could still satisfy an assertion.\n' >&2
      exit 1
    fi
    printf 'no binary was left behind\n'
    printf 'RESULT: GUARD PASS (a broken build cannot produce a result)\n'
    exit 0
    ;;
esac
