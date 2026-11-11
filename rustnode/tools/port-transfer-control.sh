#!/usr/bin/env bash
# The same-isolate `MessagePort` transfer control.
#
#   ./tools/port-transfer-control.sh before   # the pre-TransferData messaging crate
#   ./tools/port-transfer-control.sh after    # this worktree
#
# # What this guards
#
# `Message.ports` used to be a second id vector beside `host_objects`, and a
# transferred port lived in it. Step (c) deleted it: a moved port is now a
# `PortTransferData` entry in the single host-object vector, and the receiving
# object is rebuilt by `TransferData::rebuild` instead of `clone_port_into`.
#
# The regression that move invites is a port that arrives as an *empty shell*: the
# object exists and has the prototype, but the queue behind it was not carried, so
# posting into it silently goes nowhere. That is the same shape as the
# `data.check is not a function` failure a clone once produced, and neither a
# passing test file nor an unchanged failure count can tell it apart from success
# in a suite that was already red. Hence this control: it asserts that the
# received port *delivers a message posted into it from the far end*.
#
# # Why an explicit binary
#
# A stale `target/debug/rustnode` has reported a pass in this project before. The
# binary is deleted before the build, every build result is checked, and the
# binary's mtime must be newer than the build start, so a failed build cannot
# reach the assertion in either arm.
#
# # The expected output
#
# The script prints `got 42` for the baseline and `transferred got 42` once the
# moved port has been posted into from the far side. Both lines are asserted, and
# a run with either missing exits non-zero, so this can be run by the gate rather
# than only by hand.
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

base_ref="${RUSTNODE_PORT_TRANSFER_BASE:-939f57a3}"

work="$(mktemp -d)"
restore_sources() {
  if [ -d "$work/sources" ]; then
    cp "$work/sources/"*.rs crates/rn-bind-messaging/src/ 2>/dev/null
  fi
  rm -rf "$work"
}
trap restore_sources EXIT

binary="$root/target/debug/rustnode"

# The assertion both arms run, defined once so the only thing that differs
# between the arms is which messaging crate was compiled.
script="$(cat <<'JS'
const assert = require('assert');
const { MessageChannel } = require('worker_threads');

let finished = false;
const finish = (code) => {
  if (finished) return;
  finished = true;
  process.exit(code);
};

// 1. Baseline: `port2.postMessage` delivers to `port1`, its entangled peer, so
//    the listener has to be on port1. This proves the harness below is sound, so
//    a later failure is the transfer and not the test.
const base = new MessageChannel();
base.port1.on('message', (m) => {
  assert.strictEqual(m, 42, 'baseline payload: ' + m);
  console.log('got', m);
  transfer();
});
base.port2.postMessage(42);

// 2. The transfer form. `moved1` crosses on the carrier channel; the port that
//    arrives must be a real `MessagePort` carrying `moved1`'s queue, so posting
//    from `moved2` — the far end of the moved channel — reaches it.
function transfer() {
  const { port1: moved1, port2: moved2 } = new MessageChannel();
  const { port1: carrier1, port2: carrier2 } = new MessageChannel();

  const timer = setTimeout(() => {
    // A port that never answers is the empty-shell failure, and without this the
    // run would hang instead of reporting it.
    console.log('TIMEOUT: the transferred port never delivered');
    finish(1);
  }, 5000);

  carrier2.onmessage = (event) => {
    assert.strictEqual(event.data, 'payload', 'carrier payload: ' + event.data);
    assert.strictEqual(event.ports.length, 1, 'the message must carry one port');
    // The shell check: a rebuilt port has the prototype and the methods. If the
    // payload was dropped, these are still present and only delivery fails, which
    // is why the post below matters more than this assertion.
    const moved = event.ports[0];
    assert.strictEqual(typeof moved.postMessage, 'function', 'the port lost postMessage');
    assert.strictEqual(moved.constructor.name, 'MessagePort', 'the port lost its class');

    moved.onmessage = (inner) => {
      assert.strictEqual(inner.data, 42, 'transferred payload: ' + inner.data);
      console.log('transferred got', inner.data);
      clearTimeout(timer);
      finish(0);
    };

    // Post into the moved port from the far end of the channel it was moved from.
    // This is the step that fails when the queue did not cross with the object.
    moved2.postMessage(42);
  };

  carrier1.postMessage('payload', [moved1]);
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
  grep -m1 -E "Error|error|assert" "$work/stderr" || true
  printf '\n'

  local ok=1
  grep -qx 'got 42' "$work/stdout" || ok=0
  grep -qx 'transferred got 42' "$work/stdout" || ok=0
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
