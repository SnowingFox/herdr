#!/usr/bin/env bash
# Control: a TLS process must exit, and `server.close()` must reach its callback.
#
# This exists because every test in PR #62 asserted a *value* and none asserted
# that the process finished. A TLS stack that decrypts correctly and then refuses
# to let the process exit will hang every `test-tls-*` file it would otherwise
# pass, so the exit status is the measurement that matters.
#
# Three separate defects each produced the same symptom, and each is exercised
# here:
#
# 1. `getSession` threw. It is called while the server accepts a connection, so
#    the accept path aborted before `'secureConnection'` and the client's
#    handshake never completed at all.
# 2. `DoShutdown` did not call the underlying stream's own shutdown. The
#    close-notify reached the peer, the peer replied with its own, and neither
#    TCP connection was ever finished — so nothing closed.
# 3. `OnStreamAfterShutdown` was an empty body. The `ShutdownWrap` from
#    `handle.shutdown(req)` is completed *from that callback*, so swallowing it
#    left the writable side unfinished: `'finish'` never fired, `destroySoon`
#    never ran, and `server.close()`'s callback was never reached.
#
# The shape of the assertion matters: `CLOSED CALLBACK` is printed from inside the
# `server.close()` callback, so it cannot pass unless the server's listening
# handle and its accepted socket both really closed. A process that exits early
# because the loop drained would print nothing here and fail.
#
# Usage:
#   ./tools/tls-exit-control.sh            # build, then check
#   ./tools/tls-exit-control.sh <binary>   # check an existing binary
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

# How long the whole script may take. A correct run finishes in well under a
# second; the timeout only has to be generous enough not to be flaky on a loaded
# machine. A hang is the failure being measured, so this must be a real bound
# rather than something a slow run can trip over.
timeout_seconds="${TLS_EXIT_TIMEOUT:-10}"

if [ "$#" -ge 1 ]; then
  node="$1"
  if [ ! -x "$node" ]; then
    echo "ABORT: $node is not an executable file" >&2
    exit 2
  fi
else
  # The build result is checked rather than inferred from the file existing: a
  # failed build leaves the previous binary in place, which has already produced a
  # false PASS once in this project.
  if ! cargo build -p rn-cli 2>/tmp/tls-exit-control-build.log; then
    echo "ABORT: BUILD FAILED; not testing a stale binary" >&2
    tail -20 /tmp/tls-exit-control-build.log >&2
    exit 2
  fi
  node="$root/target/debug/rustnode"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A self-signed pair, generated rather than committed: a private key in the
# repository is a secret even when it is only a test fixture.
if ! openssl req -x509 -newkey rsa:2048 \
  -keyout "$work/key.pem" -out "$work/cert.pem" \
  -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1; then
  echo "ABORT: could not generate a test certificate; openssl is required" >&2
  exit 2
fi

script="$work/exit.js"
cat >"$script" <<JS
const tls = require('tls');
const fs = require('fs');
const opts = {
  key: fs.readFileSync('$work/key.pem'),
  cert: fs.readFileSync('$work/cert.pem'),
};
const server = tls.createServer(opts, (s) => { s.end('x'); });
server.on('tlsClientError', (e) => console.log('S:CLIENTERROR ' + e.message));
server.listen(0, () => {
  const c = tls.connect(
    { port: server.address().port, rejectUnauthorized: false },
    () => {
      c.on('data', () => {
        c.end();
        // Printed from inside the close callback, so it cannot appear unless the
        // listening handle and the accepted socket both really closed.
        server.close(() => console.log('CLOSED CALLBACK'));
      });
    });
  c.on('close', () => console.log('C:CLOSE'));
  c.on('error', (e) => console.log('C:ERROR ' + e.message));
});
JS

echo "== a TLS process exits and closes its server =="
set +e
output="$(timeout "$timeout_seconds" "$node" "$script" 2>&1)"
status=$?
set -e

echo "$output" | sed 's/^/   /'

if grep -q 'S:CLIENTERROR' <<<"$output"; then
  echo "FAIL: the server rejected the client: $(grep 'S:CLIENTERROR' <<<"$output")" >&2
  exit 1
fi
if grep -q 'C:ERROR' <<<"$output"; then
  echo "FAIL: the client reported an error: $(grep 'C:ERROR' <<<"$output")" >&2
  exit 1
fi
if ! grep -q 'CLOSED CALLBACK' <<<"$output"; then
  echo "FAIL: server.close() never reached its callback" >&2
  if [ "$status" -eq 124 ]; then
    echo "      the process was still running after ${timeout_seconds}s (killed)" >&2
  else
    echo "      the process exited $status without closing the server" >&2
  fi
  exit 1
fi
if [ "$status" -ne 0 ]; then
  echo "FAIL: the process exited $status, expected 0" >&2
  exit 1
fi

echo "PASS: the process exited 0 and printed the close callback"
