#!/usr/bin/env bash
# Fails when the vendored nghttp2 differs from the pinned Node revision.
#
# `vendor/nghttp2` is nghttp2 1.70.0 copied byte-identical from `deps/nghttp2`
# in the Node revision `tools/node-pin.toml` pins. It is never patched: the
# protocol state machine, the HPACK tables and the error strings are the
# compatibility surface, and a local edit would change them away from what Node
# produces. This check makes an accidental edit fail the gate instead of silently
# changing how HTTP/2 behaves.
#
# `NGHTTP2.sha256` records every vendored file except this README and the digest
# file itself. Regenerate it only when updating the vendored nghttp2 to a newer
# Node revision, in the same commit as the files themselves and the commit
# recorded in `vendor/nghttp2/README.md`.
#
# Exit codes: 0 the tree matches the pin, 1 the tree has drifted
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/vendor/nghttp2"

if ! sha256sum -c NGHTTP2.sha256 --quiet; then
  echo "vendor/nghttp2 has been modified; HTTP/2 must stay byte-identical to the pinned Node revision" >&2
  exit 1
fi

# The compile set is not a judgment call: `nghttp2.gyp` lists it, and
# `crates/rn-bind-http2/build.rs` compiles exactly that list. Counting it here
# means a vendored tree that gained a file (or lost one, which would compile and
# then fail at link time with an undefined symbol) fails before the compiler has
# to say anything.
#
#   26 .c files: nghttp2_sources (25) plus sfparse.c, which is a second target in
#   the same gyp file and is linked into the same archive.
#   29 headers: 26 internal .h files, config.h, and the two public headers under
#   lib/includes/nghttp2.
sources="$(ls lib/*.c | wc -l)"
headers="$(ls lib/*.h | wc -l)"
public="$(ls lib/includes/config.h lib/includes/nghttp2/nghttp2.h lib/includes/nghttp2/nghttp2ver.h | wc -l)"
if [ "$sources" -ne 26 ] || [ "$headers" -ne 26 ] || [ "$public" -ne 3 ]; then
  echo "unexpected vendored nghttp2 layout: $sources .c files, $headers internal headers, $public public headers" >&2
  echo "(expected 26, 26 and 3; see deps/nghttp2/nghttp2.gyp at the pin)" >&2
  exit 1
fi

# The gyp's source list has to agree with what is on disk. Without this the
# count above could stay right while the set of files changed, and `build.rs`
# would compile a source list that no longer matches the tree it came from.
listed="$(grep -c "^      'lib/.*\.c'," nghttp2.gyp)"
if [ "$listed" -ne 26 ]; then
  echo "nghttp2.gyp lists $listed sources, expected 26 (25 nghttp2 + sfparse)" >&2
  exit 1
fi

echo "vendor/nghttp2 matches the pinned Node revision ($sources sources, $headers + $public headers)"
exit 0
