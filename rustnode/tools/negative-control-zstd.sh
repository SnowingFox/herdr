#!/usr/bin/env bash
# Negative control for the zstd surface.
#
#   ./tools/negative-control-zstd.sh before   # origin/master's zstd surface
#   ./tools/negative-control-zstd.sh after    # this worktree
#
# A failed build aborts with a non-zero exit: the binary is deleted first, every
# build result is checked, and the binary's mtime must be newer than the build
# start. Two workers in this project previously reported a PASS that came from
# the previous binary after their build failed, so a stale binary cannot reach
# the assertion in either arm.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

arm="${1:-}"
case "$arm" in
  before|after) ;;
  *)
    printf 'usage: %s before|after\n' "$0" >&2
    exit 2
    ;;
esac

work="$(mktemp -d)"
restore_sources() {
  if [ -d "$work/sources" ]; then
    cp "$work/sources/handle.rs" crates/rn-bind-zlib/src/handle.rs 2>/dev/null
    cp "$work/sources/lib.rs" crates/rn-bind-zlib/src/lib.rs 2>/dev/null
    cp "$work/sources/Cargo.toml" crates/rn-bind-zlib/Cargo.toml 2>/dev/null
    cp "$work/sources/zstd.rs" crates/rn-bind-zlib/src/zstd.rs 2>/dev/null
  fi
  rm -rf "$work"
}
trap restore_sources EXIT

binary="$root/target/debug/rustnode"

# The assertion both arms run. It is defined once, so the only thing that
# differs between the arms is which sources were compiled.
script="$(cat <<'JS'
const z = require('zlib');
const assert = require('assert');

// 1. The convenience methods exist.
assert.strictEqual(typeof z.zstdCompressSync, 'function', 'zstdCompressSync is missing');
assert.strictEqual(typeof z.zstdDecompressSync, 'function', 'zstdDecompressSync is missing');

// 2. A sync round trip returns the input, including the empty and NUL cases.
const roundTrip = (input) => z.zstdDecompressSync(z.zstdCompressSync(input));
assert.deepStrictEqual(roundTrip(Buffer.from('hello world')), Buffer.from('hello world'));
assert.deepStrictEqual(roundTrip(Buffer.alloc(0)), Buffer.alloc(0));
assert.deepStrictEqual(
  roundTrip(Buffer.from([0x00, 0xff, 0x00, 0x7f, 0x00])),
  Buffer.from([0x00, 0xff, 0x00, 0x7f, 0x00]));

// 3. The frame carries zstd's magic, not deflate's.
const frame = z.zstdCompressSync(Buffer.from('hello world'));
assert.deepStrictEqual([...frame.subarray(0, 4)], [0x28, 0xb5, 0x2f, 0xfd],
                       'frame does not start with the zstd magic');

// 4. The stream classes work, driven in more than one chunk.
const compress = z.createZstdCompress({ chunkSize: 64 });
const decompress = z.createZstdDecompress({ chunkSize: 64 });
const out = [];
compress.pipe(decompress);
decompress.on('data', (chunk) => out.push(chunk));
decompress.on('end', () => {
  const streamed = Buffer.concat(out).toString();
  assert.strictEqual(streamed, 'hello world', 'stream round trip: ' + streamed);
  process.stdout.write('ZSTD_OK');
});
decompress.on('error', (error) => {
  process.stderr.write('stream error: ' + ((error && error.stack) || error) + '\n');
  process.exitCode = 1;
});
compress.write(Buffer.from('hello '));
compress.write(Buffer.from('world'));
compress.end();
JS
)"

run_arm() {
  local label="$1"
  printf '\n== %s ==\n' "$label"

  # A stale binary is the failure mode this control exists to rule out, so it is
  # removed before the build and its freshness is checked after.
  rm -f "$binary"

  local started
  started="$(date +%s)"
  if ! cargo build -p rn-cli >"$work/build.log" 2>&1; then
    printf 'BUILD FAILED; refusing to test a stale binary\n' >&2
    tail -30 "$work/build.log" >&2
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

  printf 'exit=%s\n' "$status"
  printf -- '--- stdout ---\n'
  cat "$work/stdout"
  printf '\n'
  printf -- '--- first error line ---\n'
  grep -m1 -E "Error|error|assert" "$work/stderr" || true
  printf '\n'

  if [ "$status" -eq 0 ] && grep -q ZSTD_OK "$work/stdout"; then
    printf 'RESULT: PASS\n'
    return 0
  fi
  printf 'RESULT: FAIL\n'
  return 1
}

if [ "$arm" = "before" ]; then
  printf 'building origin/master'"'"'s zstd surface\n'

  # The worktree's sources are copied aside and restored on exit, so a failed
  # run cannot lose them.
  mkdir -p "$work/sources"
  cp crates/rn-bind-zlib/src/handle.rs "$work/sources/handle.rs"
  cp crates/rn-bind-zlib/src/lib.rs "$work/sources/lib.rs"
  cp crates/rn-bind-zlib/src/zstd.rs "$work/sources/zstd.rs"
  cp crates/rn-bind-zlib/Cargo.toml "$work/sources/Cargo.toml"

  for file in src/handle.rs src/lib.rs Cargo.toml; do
    if ! git show "origin/master:rustnode/crates/rn-bind-zlib/$file" \
      >"crates/rn-bind-zlib/$file"; then
      printf 'cannot read pre-change %s from origin/master\n' "$file" >&2
      exit 1
    fi
  done
  rm -f crates/rn-bind-zlib/src/zstd.rs

  run_arm "before (origin/master's zstd surface)"
  status=$?
  printf '\nRESULT: %s\n' "$([ "$status" -eq 0 ] && echo PASS || echo FAIL)"
  exit "$status"
fi

run_arm "after (this worktree)"
status=$?
printf '\nRESULT: %s\n' "$([ "$status" -eq 0 ] && echo PASS || echo FAIL)"
exit "$status"
