#!/usr/bin/env bash
# The `SharedArrayBuffer` clone control for `postMessage` and `structuredClone`.
#
#   ./tools/sab-clone-control.sh before   # the pre-fix tree
#   ./tools/sab-clone-control.sh after    # this worktree
#
# # Why this exists
#
# `worker_threads` could not construct a worker at all, and the cause was not at a
# message boundary: `lib/internal/worker.js:116` does
#
#     cwdCounter = new Uint32Array(constructSharedArrayBuffer(4));
#
# and posts it as part of the startup payload. Every `new Worker()` therefore
# serializes a typed array over a `SharedArrayBuffer`, and the messaging
# `SerializerDelegate` had no `get_shared_array_buffer_id`, so V8 reported
# `#<SharedArrayBuffer> could not be cloned` before the worker thread existed.
#
# A `SharedArrayBuffer` also cannot be fixed by treating it as a transfer: it is
# shared memory, so it stays usable on the sending side, and the receiver must end
# up with the *same* allocation rather than a copy. That is why the control checks
# both that the bytes agree and that a write on one side is visible on the other.
#
# # The expected output
#
# The three lines below are what node itself prints for this script; they were
# taken from node v22, not invented. Any missing line fails the run, so this can
# be run by the gate rather than only by hand.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

arm="${1:-after}"
case "$arm" in
  before | after) ;;
  *)
    printf 'usage: %s before|after\n' "$0" >&2
    exit 2
    ;;
esac

# The pre-fix commit, pinned rather than following a branch.
#
# `origin/master` used to be correct here and is now wrong: #58 merged the fix, so
# a moving ref makes the `before` arm build the fixed tree and pass, which is the
# same silent-meaning loss this project keeps finding. `bdfcb18b` is the merge
# before #58 and has no `get_shared_array_buffer_id`, so the arm fails for the
# right reason. Moving this default is a decision, not an automatic follow of
# master.
base_ref="${RUSTNODE_SAB_BASE:-bdfcb18b}"

work="$(mktemp -d)"
restore_sources() {
  if [ -d "$work/sources" ]; then
    cp "$work/sources/"*.rs crates/rn-bind-messaging/src/ 2>/dev/null
  fi
  rm -rf "$work"
}
trap restore_sources EXIT

binary="$root/target/debug/rustnode"

# The assertion both arms run, defined once so the only difference between the
# arms is which messaging crate was compiled.
script="$(cat <<'JS'
'use strict';
const assert = require('assert');
const { MessageChannel, Worker } = require('worker_threads');

let finished = false;
const finish = (code) => {
  if (finished) return;
  finished = true;
  process.exit(code);
};

// Without this a never-delivered message would hang the run instead of failing it.
const timer = setTimeout(() => {
  console.log('TIMEOUT: the expected lines never arrived');
  finish(1);
}, 8000);

// 1. structuredClone must return a shared buffer of the right length.
const cloned = structuredClone(new SharedArrayBuffer(16));
assert.strictEqual(cloned.constructor.name, 'SharedArrayBuffer', 'cloned type');
assert.strictEqual(cloned.byteLength, 16, 'cloned length');
console.log('structuredClone SharedArrayBuffer 16');

// 2. postMessage must deliver a shared buffer, and the *same* memory: a write on
//    the received side has to be visible through the sender's view. A copy would
//    pass a byte comparison and fail this.
const { port1, port2 } = new MessageChannel();
const original = new SharedArrayBuffer(16);
const view = new Uint8Array(original);
view[0] = 7;
port1.on('message', (received) => {
  assert.strictEqual(received.constructor.name, 'SharedArrayBuffer', 'received type');
  assert.strictEqual(received.byteLength, 16, 'received length');
  assert.strictEqual(new Uint8Array(received)[0], 7, 'the bytes crossed');
  // Write through the received view and read it back through the sender's.
  new Uint8Array(received)[1] = 9;
  assert.strictEqual(view[1], 9, 'the buffer is shared, not copied');
  // The sender's buffer must still be usable: a transfer would have detached it.
  assert.strictEqual(original.byteLength, 16, 'the sender buffer was not detached');
  console.log('postMessage SharedArrayBuffer 16');
  third();
});
port2.postMessage(original);

// 3. The case that was actually broken: constructing a worker at all. The payload
//    carries a Uint32Array over a SharedArrayBuffer.
function third() {
  const worker = new Worker(
    'const { parentPort } = require("worker_threads");' +
      'parentPort.postMessage("from-worker");',
    { eval: true },
  );
  worker.on('message', (value) => {
    assert.strictEqual(value, 'from-worker', 'worker payload: ' + value);
    console.log('worker said from-worker');
    clearTimeout(timer);
    worker.terminate().then(() => finish(0));
  });
  worker.on('error', (error) => {
    console.log('WORKER ERROR ' + (error && error.message));
    clearTimeout(timer);
    finish(1);
  });
}
JS
)"

run_arm() {
  local label="$1"
  printf '\n== %s ==\n' "$label"

  rm -f "$binary"

  # `cargo build` restores a cached hardlink for an unchanged binary, mtime and
  # all, so a deleted binary is not enough to prove a relink. Touching the CLI's
  # entry point forces one, and the log is checked for the compile that proves it.
  touch crates/rn-cli/src/main.rs

  local started
  started="$(date +%s)"
  if ! cargo build -p rn-cli >"$work/build.log" 2>&1; then
    printf 'BUILD FAILED; refusing to test a stale binary\n' >&2
    tail -30 "$work/build.log" >&2
    return 1
  fi

  if ! grep -q 'Compiling rn-cli' "$work/build.log"; then
    printf 'NO RELINK: the build never recompiled rn-cli; refusing to test the binary\n' >&2
    return 1
  fi

  if [ ! -x "$binary" ]; then
    printf 'BUILD SUCCEEDED BUT %s IS MISSING\n' "$binary" >&2
    return 1
  fi

  local built_at
  built_at="$(stat -c %Y "$binary")"
  if [ "$built_at" -lt "$started" ]; then
    printf 'BINARY PREDATES THE BUILD (%s < %s); refusing to test it\n' \
      "$built_at" "$started" >&2
    return 1
  fi

  local status
  "$binary" -e "$script" >"$work/stdout" 2>"$work/stderr"
  status=$?

  printf 'binary mtime=%s\n' "$built_at"
  printf 'exit=%s\n' "$status"
  printf -- '--- stdout ---\n'
  cat "$work/stdout"
  printf -- '--- first error line ---\n'
  grep -m1 -E "Error|error|assert|could not be cloned" "$work/stderr" || true
  printf '\n'

  local ok=1
  grep -qx 'structuredClone SharedArrayBuffer 16' "$work/stdout" || ok=0
  grep -qx 'postMessage SharedArrayBuffer 16' "$work/stdout" || ok=0
  grep -qx 'worker said from-worker' "$work/stdout" || ok=0
  if [ "$status" -eq 0 ] && [ "$ok" -eq 1 ]; then
    printf 'RESULT: PASS\n'
    return 0
  fi
  printf 'RESULT: FAIL\n'
  return 1
}

if [ "$arm" = "before" ]; then
  printf 'building the messaging crate from %s\n' "$base_ref"

  mkdir -p "$work/sources"
  cp crates/rn-bind-messaging/src/*.rs "$work/sources/"

  for file in port.rs serialize.rs deserialize.rs lib.rs delivery.rs; do
    if ! git show "$base_ref:rustnode/crates/rn-bind-messaging/src/$file" \
      >"crates/rn-bind-messaging/src/$file"; then
      printf 'cannot read %s at %s\n' "$file" "$base_ref" >&2
      exit 1
    fi
  done
fi

run_arm "$arm"
status=$?
printf '\nRESULT: %s\n' "$([ "$status" -eq 0 ] && echo PASS || echo FAIL)"
exit "$status"
