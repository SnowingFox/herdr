#!/usr/bin/env bash
# The worker post-flush control, plus the `SharedArrayBuffer` assertions.
#
#   ./tools/worker-post-flush-control.sh before   # the pre-fix tree
#   ./tools/worker-post-flush-control.sh after    # this worktree
#
# # CLA-137: a worker's `postMessage` must not wait for its own loop
#
# `parentPort.postMessage(x)` followed by a long synchronous computation is a
# normal worker pattern. Node writes to the channel at post time, so the parent
# sees the message immediately even though the worker is still busy. The messaging
# crate queued the message and then looked for the owning `PortInner` to schedule
# it — and that lookup returns `None` from a foreign thread by design, because
# `PortInner` is `Rc` and holds a `v8::Weak`. So nothing signalled the parent and
# the message only arrived when the worker's own loop came back around:
#
#     node      26ms
#     rustnode  347ms   (300ms busy loop + the wait for the loop to turn)
#
# That is worse than latency: a worker that posts and then blocks looks like it
# sent nothing, and a test asserting message ordering reads the failure as a lost
# message rather than a delayed one.
#
# # The threshold
#
# 100ms against a 300ms busy loop. Node measures ~26ms and the fixed tree ~48ms,
# the broken tree ~347ms, so there is headroom on both sides and the assertion is
# not timing-flaky.
#
# # What is asserted
#
#   worker post arrived under 100ms        (CLA-137)
#   structuredClone SharedArrayBuffer 16   (SAB clone)
#   postMessage SharedArrayBuffer 16       (SAB clone, same memory)
#   same object: true                      (SAB dedup)
#   cross-thread SharedArrayBuffer visible (SAB across a real worker)
#   worker said from-worker                (a worker constructs at all)
#
# The last five are here because they are the same subsystem and were previously
# argued in a PR body rather than asserted. The dedup line is the property that
# makes the shared counter work; `cross-thread` is the property that makes it
# correct across threads rather than only within one isolate.
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

# The commit before the flush fix. Pinned rather than following a branch, because
# a moving ref silently turns the `before` arm into the fixed tree and the arm
# stops failing — which has already happened once in this repository.
base_ref="${RUSTNODE_FLUSH_BASE:-origin/master}"

work="$(mktemp -d)"
restore_sources() {
  if [ -d "$work/sources" ]; then
    cp "$work/sources/"*.rs crates/rn-bind-messaging/src/ 2>/dev/null
  fi
  rm -rf "$work"
}
trap restore_sources EXIT

binary="$root/target/debug/rustnode"

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

const timer = setTimeout(() => {
  console.log('TIMEOUT: the expected lines never arrived');
  finish(1);
}, 15000);

// CLA-137. The worker posts first, then busy-loops without a blocking syscall, so
// the only thing that can deliver the message early is a signal at post time.
function flushCheck(next) {
  const started = Date.now();
  const source =
    'const { parentPort } = require("worker_threads");' +
    'parentPort.postMessage("sent-then-busy");' +
    'const end = Date.now() + 300;' +
    'while (Date.now() < end) {}';
  const worker = new Worker(source, { eval: true });
  worker.on('message', (value) => {
    const elapsed = Date.now() - started;
    assert.strictEqual(value, 'sent-then-busy', 'worker payload: ' + value);
    assert.ok(
      elapsed < 100,
      'the worker post must not wait for its own loop: saw ' + elapsed + 'ms',
    );
    console.log('worker post arrived under 100ms (' + elapsed + 'ms)');
    worker.terminate().then(next);
  });
  worker.on('error', (error) => {
    console.log('WORKER ERROR ' + (error && error.message));
    clearTimeout(timer);
    finish(1);
  });
}

function sabChecks() {
  const cloned = structuredClone(new SharedArrayBuffer(16));
  assert.strictEqual(cloned.constructor.name, 'SharedArrayBuffer', 'cloned type');
  assert.strictEqual(cloned.byteLength, 16, 'cloned length');
  console.log('structuredClone SharedArrayBuffer 16');

  const { port1, port2 } = new MessageChannel();
  const original = new SharedArrayBuffer(16);
  const view = new Uint8Array(original);
  view[0] = 7;
  port1.on('message', (received) => {
    assert.strictEqual(received.constructor.name, 'SharedArrayBuffer', 'received type');
    assert.strictEqual(received.byteLength, 16, 'received length');
    assert.strictEqual(new Uint8Array(received)[0], 7, 'the bytes crossed');
    // A write through the received view must be visible from the sender's.
    new Uint8Array(received)[1] = 9;
    assert.strictEqual(view[1], 9, 'the buffer is shared, not copied');
    assert.strictEqual(original.byteLength, 16, 'the sender buffer was not detached');
    console.log('postMessage SharedArrayBuffer 16');
    dedupChecks();
  });
  port2.postMessage(original);
}

// One buffer, referenced twice in one message: once directly and once as a
// `Uint32Array`'s backing store. Both ids must resolve to ONE object, or a
// counter written through the view stops being visible through the buffer.
function dedupChecks() {
  const { port1, port2 } = new MessageChannel();
  const shared = new SharedArrayBuffer(16);
  const typed = new Uint32Array(shared);
  typed[0] = 7;
  port1.once('message', (m) => {
    assert.strictEqual(m.buf.constructor.name, 'SharedArrayBuffer', 'direct is a SAB');
    assert.strictEqual(m.view.buffer.constructor.name, 'SharedArrayBuffer', 'view buffer is a SAB');
    assert.strictEqual(m.buf === m.view.buffer, true, 'same object: ' + (m.buf === m.view.buffer));
    console.log('same object: true');
    crossThreadChecks();
  });
  port2.postMessage({ buf: shared, view: typed });
}

// The property `cwdCounter` actually needs, and the one a single isolate cannot
// show: a copy would still look shared when both ends live on one heap.
function crossThreadChecks() {
  const sab = new SharedArrayBuffer(4);
  const view = new Uint32Array(sab);
  view[0] = 1;
  const source =
    'const { workerData, parentPort } = require("worker_threads");' +
    'const view = new Uint32Array(workerData.sab);' +
    'const before = view[0];' +
    'view[0] = 99;' +
    'parentPort.postMessage("saw " + before);';
  const worker = new Worker(source, { eval: true, workerData: { sab } });
  worker.on('message', (value) => {
    assert.strictEqual(value, 'saw 1', 'the worker saw the main thread value: ' + value);
    assert.strictEqual(view[0], 99, 'the worker write must be visible here, saw ' + view[0]);
    console.log('cross-thread SharedArrayBuffer visible');
    worker.terminate().then(constructCheck);
  });
  worker.on('error', (error) => {
    console.log('WORKER ERROR ' + (error && error.message));
    clearTimeout(timer);
    finish(1);
  });
}

function constructCheck() {
  const worker = new Worker(
    'const { parentPort } = require("worker_threads");' +
      'parentPort.postMessage("from-worker");',
    { eval: true },
  );
  worker.on('message', (value) => {
    assert.strictEqual(value, 'from-worker', 'worker payload: ' + value);
    console.log('worker said from-worker');
    worker.terminate().then(() => {
      clearTimeout(timer);
      finish(0);
    });
  });
  worker.on('error', (error) => {
    console.log('WORKER ERROR ' + (error && error.message));
    clearTimeout(timer);
    finish(1);
  });
}

flushCheck(sabChecks);
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
  grep -m1 -E "Error|error|assert|must not wait" "$work/stderr" || true
  printf '\n'

  local ok=1
  grep -q 'worker post arrived under 100ms' "$work/stdout" || ok=0
  grep -qx 'structuredClone SharedArrayBuffer 16' "$work/stdout" || ok=0
  grep -qx 'postMessage SharedArrayBuffer 16' "$work/stdout" || ok=0
  grep -qx 'same object: true' "$work/stdout" || ok=0
  grep -qx 'cross-thread SharedArrayBuffer visible' "$work/stdout" || ok=0
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
