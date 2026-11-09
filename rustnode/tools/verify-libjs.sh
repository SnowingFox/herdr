#!/usr/bin/env bash
# Fails when any vendored Node builtin JavaScript differs from the pinned copy.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/vendor/libnode-js"

if ! sha256sum -c LIBJS.sha256 --quiet; then
  echo "vendor/libnode-js has been modified; builtin JavaScript must stay byte-identical" >&2
  exit 1
fi

count="$(find lib -name '*.js' | wc -l)"
if [ "$count" -ne 435 ]; then
  echo "expected 435 builtin files, found $count" >&2
  exit 1
fi

echo "vendor/libnode-js matches the pinned Node revision ($count files)"
