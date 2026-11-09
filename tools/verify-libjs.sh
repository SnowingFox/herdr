#!/usr/bin/env bash
# Fails when any vendored Node builtin JavaScript differs from the pinned copy.
#
# Two trees are vendored, from the same Node revision:
#
#   lib/**   Node's own builtin layer, 435 files
#   deps/**  the `deps_files` entries Node's js2c also embeds, 1 file
#            (`deps/undici/undici.js`, the esbuild bundle `lib/**` requires as
#            `internal/deps/undici/undici`)
#
# One `LIBJS.sha256` covers both because `sha256sum -c` is keyed by path: a
# `lib/...` entry and a `deps/...` entry are verified by the same pass and the
# same format, so the shell gate, the build script and the tests cannot disagree
# about what is frozen. The counts are still reported and enforced separately,
# because a single combined total would let one tree grow while the other shrank.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/vendor/libnode-js"

if ! sha256sum -c LIBJS.sha256 --quiet; then
  echo "vendor/libnode-js has been modified; builtin JavaScript must stay byte-identical" >&2
  exit 1
fi

lib_count="$(find lib -name '*.js' | wc -l)"
if [ "$lib_count" -ne 435 ]; then
  echo "expected 435 builtin files under lib/, found $lib_count" >&2
  exit 1
fi

deps_count="$(find deps -name '*.js' | wc -l)"
if [ "$deps_count" -ne 1 ]; then
  echo "expected 1 builtin file under deps/, found $deps_count" >&2
  exit 1
fi

echo "vendor/libnode-js matches the pinned Node revision ($lib_count lib files, $deps_count deps file)"
