#!/usr/bin/env bash
# Fails when the vendored llhttp differs from the pinned Node revision.
#
# `vendor/llhttp` is C copied byte-identical from `deps/llhttp` in the Node
# revision `tools/node-pin.toml` pins. It is never patched: a local edit to the
# parser would change parse behaviour away from the one Node ships, which is the
# only reason the crate exists. This check makes an accidental edit fail the gate
# instead of silently changing how requests are parsed.
#
# `LLHTTP.sha256` records the four files. Regenerate it only when updating the
# vendored llhttp to a newer Node revision, in the same commit as the files
# themselves and the commit recorded in `vendor/llhttp/README.md`.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/vendor/llhttp"

if ! sha256sum -c LLHTTP.sha256 --quiet; then
  echo "vendor/llhttp has been modified; the HTTP parser must stay byte-identical to the pinned Node revision" >&2
  exit 1
fi

# The shim is the one file this project owns, and it is checked separately so a
# missing include or a widened ABI is a compile error rather than a surprise at
# runtime.
count="$(ls src/*.c include/*.h | wc -l)"
if [ "$count" -ne 4 ]; then
  echo "expected 4 vendored llhttp files, found $count" >&2
  exit 1
fi

echo "vendor/llhttp matches the pinned Node revision ($count files)"
