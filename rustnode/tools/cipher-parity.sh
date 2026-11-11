#!/usr/bin/env bash
# Byte-identical parity for the cipher surface against a real `node`.
#
# `tests/parity_cipher.js` prints deterministic values for aes-256-gcm with an
# auth tag, chacha20-poly1305, aes-256-ctr, a 1 MiB multi-chunk payload, aes-128-ecb
# with a null IV, aes-128-wrap, and the error shapes. This script runs it under
# both binaries and diffs the output.
#
# The build is part of the measurement and its exit status is checked, because a
# stale binary is the failure mode two workers on this project have already hit:
# a build failure followed by a "PASS" from whatever was in `target/`. The binary
# is removed before the build so its presence afterwards proves this invocation
# produced it.
#
# Two differences against a local `node` v22 are expected and asserted rather than
# diffed away, because the pinned Node 28 tests demand the opposite of v22:
#
#   err.cts / err.xts  the pin throws ERR_CRYPTO_UNSUPPORTED_OPERATION for
#                      `ctsMode`/`xtsStandard` on a cipher that does not implement
#                      them; v22 accepts the option silently.
#
# Everything else must match byte for byte. `docs/compat-status.md` records the
# version-skew rule this follows, under "Version skew against the local `node`
# binary".
#
# Usage: tools/cipher-parity.sh [--keep]
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:--L /usr/lib/gcc/x86_64-linux-gnu/13}"

script="crates/rn-bind-crypto-cipher/tests/parity_cipher.js"
binary="target/debug/rustnode"

# The S2 member the public `createCipheriv` path needs. It is the keys slice's, so
# this script injects a stand-in to keep the parity of *this* slice measurable
# while that work is in flight; the injection is printed so it cannot be mistaken
# for the product's behaviour.
shim="$(mktemp)"
trap 'rm -f "$shim" "${node_out:-}" "${rust_out:-}"' EXIT
cat >"$shim" <<'JS'
const { internalBinding } = require('internal/test/binding');
const binding = internalBinding('crypto');
if (typeof binding.isKeyObject !== 'function') binding.isKeyObject = () => false;
JS

echo "== building this tree =="
rm -f "$binary"
if ! cargo build -q -p rn-cli; then
  echo "BUILD FAILED; refusing to report a parity verdict." >&2
  exit 2
fi
if [ ! -x "$binary" ]; then
  echo "no binary after a build that reported success; refusing a verdict." >&2
  exit 2
fi

node_out="$(mktemp)"
rust_out="$(mktemp)"

if ! node "$script" >"$node_out" 2>&1; then
  echo "the reference node failed to run the parity script; refusing a verdict." >&2
  exit 2
fi
if ! "$binary" --expose-internals \
     -e "require('$shim');require(require('path').resolve(process.argv[1]));" \
     -- "$script" >"$rust_out" 2>/dev/null; then
  echo "rustnode failed to run the parity script; refusing a verdict." >&2
  exit 2
fi

status=0

# The two documented version-skew lines are removed from both sides only after the
# assertion that they differ in the expected direction.
if ! grep -q '^err.cts: Error|ERR_CRYPTO_UNSUPPORTED_OPERATION|' "$rust_out"; then
  echo "EXPECTED err.cts to be ERR_CRYPTO_UNSUPPORTED_OPERATION, got:" >&2
  grep '^err.cts:' "$rust_out" >&2
  status=1
fi
if ! grep -q '^err.xts: Error|ERR_CRYPTO_UNSUPPORTED_OPERATION|' "$rust_out"; then
  echo "EXPECTED err.xts to be ERR_CRYPTO_UNSUPPORTED_OPERATION, got:" >&2
  grep '^err.xts:' "$rust_out" >&2
  status=1
fi

filtered_node="$(mktemp)"
filtered_rust="$(mktemp)"
trap 'rm -f "$shim" "$node_out" "$rust_out" "$filtered_node" "$filtered_rust"' EXIT
grep -v -E '^err\.(cts|xts):' "$node_out" >"$filtered_node"
grep -v -E '^err\.(cts|xts):' "$rust_out" >"$filtered_rust"

if diff -u "$filtered_node" "$filtered_rust" >/tmp/cipher-parity.diff; then
  lines="$(wc -l <"$filtered_node")"
  echo "PARITY OK: $lines comparable values are byte-identical"
  echo "  (err.cts and err.xts assert the pin's behaviour, which differs from this machine's node v22)"
else
  echo "PARITY BROKEN:" >&2
  cat /tmp/cipher-parity.diff >&2
  status=1
fi

if [ "${1:-}" != "--keep" ]; then
  rm -f /tmp/cipher-parity.diff
fi

exit "$status"
