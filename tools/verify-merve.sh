#!/usr/bin/env bash
# Fails when the vendored merve differs from the pinned Node revision.
#
# `vendor/merve` is C++ copied byte-identical from `deps/merve` in the Node
# revision `tools/node-pin.toml` pins. It is never patched: a local edit to the
# lexer would change which names a CommonJS module reports as exported, and that
# answer silently decides what an ESM `import` of the file sees. A wrong export
# list is not an error anywhere; it is just a different module. This check makes
# an accidental edit fail the gate instead of silently changing that answer.
#
# `MERVE.sha256` records the four files. Regenerate it only when updating the
# vendored merve to a newer Node revision, in the same commit as the files
# themselves and the commit recorded in `vendor/merve/README.md`.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/vendor/merve"

if ! sha256sum -c MERVE.sha256 --quiet; then
  echo "vendor/merve has been modified; the CommonJS lexer must stay byte-identical to the pinned Node revision" >&2
  exit 1
fi

# Node's tree also ships `BUILD.gn`, `merve.gyp` and `unofficial.gni`. They are
# build descriptions for Node's own build system and deliberately not vendored,
# so a stray copy appearing here means somebody half-copied the directory.
count="$(ls merve.cpp include/*.h | wc -l)"
if [ "$count" -ne 3 ]; then
  echo "expected 3 vendored merve sources, found $count" >&2
  exit 1
fi

for stray in BUILD.gn merve.gyp unofficial.gni; do
  if [ -e "$stray" ]; then
    echo "vendor/merve/$stray is Node's build description and should not be vendored" >&2
    exit 1
  fi
done

echo "vendor/merve matches the pinned Node revision ($count sources)"
