#!/usr/bin/env bash
# Fails when the vendored SQLite differs from the pinned Node revision.
#
# `vendor/sqlite` is the SQLite amalgamation copied byte-identical from
# `deps/sqlite` in the Node revision `tools/node-pin.toml` pins. It is never
# patched: SQL semantics are the compatibility surface, and a local edit would
# change them away from what Node produces. This check makes an accidental edit
# fail the gate instead of silently changing how queries behave.
#
# `SQLITE.sha256` records the three files. Regenerate it only when updating the
# vendored SQLite to a newer Node revision, in the same commit as the files
# themselves and the commit recorded in `vendor/sqlite/README.md`.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/vendor/sqlite"

if ! sha256sum -c SQLITE.sha256 --quiet; then
  echo "vendor/sqlite has been modified; the SQLite amalgamation must stay byte-identical to the pinned Node revision" >&2
  exit 1
fi

# Node builds exactly one SQLite translation unit plus its two headers, so a
# stray file means the vendor tree was assembled by hand rather than copied.
count="$(ls sqlite3.c sqlite3.h sqlite3ext.h | wc -l)"
if [ "$count" -ne 3 ]; then
  echo "expected 3 vendored SQLite files, found $count" >&2
  exit 1
fi

echo "vendor/sqlite matches the pinned Node revision ($count files)"
