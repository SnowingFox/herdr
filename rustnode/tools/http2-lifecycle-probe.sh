#!/usr/bin/env bash
# Asserts that an HTTP/2 session which completes a request lets the process exit.
#
#   ./tools/http2-lifecycle-probe.sh
#
# The point is the *exit*, not the protocol. Two different leaks have already been
# hidden behind a `124` in this family, and a hang costs a timeout per file while
# looking like slowness rather than a leak:
#
#   * increment 1: nothing took ownership of the accepted socket, so it was never
#     destroyed;
#   * increment 3: a second DATA provider was rejected with
#     NGHTTP2_ERR_DATA_EXIST, so the body's END_STREAM was never sent, the peer
#     never saw `'end'`, and `core.js`'s cleanup — which is gated on
#     `_readableState.ended` — never ran;
#   * increment 5: `stream.end(); stream.close()` submitted an RST_STREAM that
#     overtook the still-deferred body, so the server received nothing at all.
#
# So the probe sets no timer of its own. A timer would let the process exit
# whether or not the loop drained, which is the measurement this tool exists to
# take. It also asserts that the body arrived and that `'end'` fired, because a
# process that exits having done nothing is not a pass either.
#
# Exit codes:
#   0 a request completed, `end` fired, and the process exited 0 on its own
#   1 the process hung, exited non-zero, or never completed the exchange
#   2 usage error, or the binary is missing
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

binary="${RUSTNODE_BIN:-target/debug/rustnode}"
if [ ! -x "$binary" ]; then
  echo "rustnode: $binary is not executable; build it first" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat >"$work/probe.js" <<'JS'
'use strict';
const http2 = require('http2');

const server = http2.createServer();
let bodies = 0;
let ends = 0;
// The `end(); close()` case: the body must still arrive even though the close is
// requested in the same tick as the end.
let racingBody = 0;
let raceClosed = 0;

server.on('session', (session) => session.on('error', () => {}));
server.on('stream', (stream, headers) => {
  if (headers[':path'] === '/race') {
    stream.on('data', (chunk) => {
      racingBody += chunk.length;
    });
    stream.on('end', () => {
      raceClosed++;
      stream.respond({ ':status': 200 });
      stream.end();
    });
    return;
  }
  stream.respond({ ':status': 200 });
  stream.end('ok');
});

server.listen(0, () => {
  const client = http2.connect(`http://localhost:${server.address().port}`);
  client.on('error', () => {});
  const request = client.request({ ':path': '/' });
  request.setEncoding('utf8');
  request.on('data', (chunk) => {
    bodies += chunk.length;
  });
  request.on('end', () => {
    ends++;

    // One tick later: `end()` immediately followed by `close()`, which used to
    // drop the body because the reset overtook the queued DATA.
    const raced = client.request({ ':method': 'POST', ':path': '/race' });
    raced.on('data', () => {});
    raced.on('error', () => {});
    raced.write(Buffer.alloc(30));
    raced.end();
    raced.close();
    raced.on('close', () => {
      // Both sides close, and nothing else is scheduled: whether the process exits
      // now is entirely up to whether every handle was released.
      client.close();
      server.close();
    });
  });
});

process.on('exit', (code) => {
  if (code !== 0) {
    return;
  }
  // Exiting without completing the exchange would pass a bare exit-code check
  // while proving nothing.
  if (bodies !== 2 || ends !== 1 || racingBody !== 30 || raceClosed !== 1) {
    console.error(
      'lifecycle probe: incomplete exchange ' +
      `bodies=${bodies} ends=${ends} raceBody=${racingBody} raceEnds=${raceClosed}`,
    );
    process.exitCode = 1;
  }
});
JS

budget=15
start=$(date +%s%N)
set +e
timeout "$budget" "$binary" "$work/probe.js" >"$work/stdout" 2>"$work/stderr"
status=$?
set -e
end=$(date +%s%N)
elapsed=$(( (end - start) / 1000000 ))

if [ "$status" -eq 124 ]; then
  echo "lifecycle probe: the process did not exit within ${budget}s (a handle leaked)" >&2
  echo "lifecycle probe: status=124 elapsed=${elapsed}ms" >&2
  sed -n '1,10p' "$work/stderr" >&2
  exit 1
fi
if [ "$status" -ne 0 ]; then
  echo "lifecycle probe: exited $status, expected 0" >&2
  sed -n '1,10p' "$work/stderr" >&2
  exit 1
fi

echo "lifecycle probe: request completed and the process exited 0 on its own in ${elapsed}ms"
exit 0
