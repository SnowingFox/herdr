//! A graceful `close()` must reach its callback instead of hanging.
//!
//! Every `http2` teardown in Node's suite is `server.close(done)` or
//! `session.close(cb)`. `core.js` installs `once('close', cb)` and then relies on
//! `kMaybeDestroy` to destroy the session once nghttp2 has nothing left to send
//! or receive; the `close` event, and therefore the callback, is emitted from
//! `finishSessionClose`. Three separate defects kept that from happening, and each
//! one turned a readable assertion failure into a 60-second harness timeout:
//!
//! 1. `submit_goaway_now` passed `core.js`'s `lastStreamID` straight to nghttp2,
//!    translating `0` into `-1`. `nghttp2_session_add_goaway` rejects a
//!    `last_stream_id` shaped like one of *our* streams, and `-1` is odd, so a
//!    client's GOAWAY was never queued (`NGHTTP2_ERR_INVALID_ARGUMENT`, `-501`).
//!    `nghttp2_session_want_read` therefore stayed 1 forever and
//!    `maybe_notify_graceful_close` never fired.
//!
//! 2. `hasPendingData()` answered from a cached flag that `send_pending_data`
//!    maintained, instead of asking nghttp2 as `src/node_http2.cc:792` does. The
//!    cached value described the *previous* flush, so `kMaybeDestroy` could refuse
//!    to destroy a session that was already drained.
//!
//! 3. `detach` stopped the socket read *after* `finishSessionClose` had resumed
//!    it. Node's `MaybeStopReading` returns early once the session is closing,
//!    because the resume is what lets a graceful close observe the peer closing.
//!
//! A regression here does not fail loudly: it hangs. So each test asserts both the
//! callback transcript *and* that the process exits by itself inside a wall-clock
//! bound, which is the only way this defect is observable at all.
//!
//! # Guarding each defect separately
//!
//! The scenarios below overlap, and overlap is not coverage: reverting only defect
//! 1 (the GOAWAY) leaves all three of them passing, because defects 2 and 3 are
//! enough to carry these scripts to a clean exit. Only
//! [`a_client_only_close_queues_a_goaway`] fails when 1 is reverted — it is the one
//! shape with no second path to the same `close`. The invariant itself is pinned
//! directly by `session::tests` in the crate, which calls `nghttp2_submit_goaway`
//! and asserts the return code, so the exact fact (`-501` vs `0`) cannot be lost
//! behind an integration scenario that also depends on libuv timing.
//!
//! Revert output for each defect is recorded in the pull request body.
//!
//! Every expected transcript below is what the pinned Node
//! (`v28.0.0-nightly20261111e8c1160d20`) prints for the same script.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// Generous enough for a loaded CI machine, and far below the 60 s harness
/// timeout this defect used to burn.
///
/// A child still running at this point is killed and reports `ok == false`, so a
/// hang becomes a failed assertion rather than a stuck test binary.
const KILL_BUDGET: Duration = Duration::from_secs(20);

/// The `rustnode` binary, if it has been built.
///
/// `RUSTNODE_BIN` is honoured first, which is how this test can be pointed at
/// another build — the same variable `tools/http2-measure.sh` and the rest of the
/// harness already read.
fn rustnode() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("RUSTNODE_BIN") {
        let path = PathBuf::from(path);
        return path.exists().then_some(path);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("rustnode");
    path.exists().then_some(path)
}

/// Runs a script under rustnode, returning `(stdout, elapsed, exit_ok)`.
///
/// The child is killed once [`KILL_BUDGET`] elapses, and the returned `ok` is
/// `false` in that case. Without this the regression these tests exist to catch —
/// a `close()` that never completes — would hang the *test binary* instead of
/// failing it, and `cargo test` would sit there until CI's own timeout killed the
/// job with no message. A hang has to be a failed assertion here, or these tests
/// reproduce the very defect they guard.
fn run(script: &str) -> Option<(String, Duration, bool)> {
    let binary = rustnode()?;
    let started = Instant::now();
    let mut child = Command::new(&binary)
        .arg("-e")
        .arg(script)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("rustnode starts");
    // Poll rather than block, so the budget is enforced regardless of whether the
    // child is idle or spinning.
    let status = loop {
        match child.try_wait().expect("rustnode is waitable") {
            Some(status) => break Some(status),
            None if started.elapsed() >= KILL_BUDGET => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let elapsed = started.elapsed();
    let output = child
        .wait_with_output()
        .expect("rustnode output is readable");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Some((
        match status {
            // A killed child usually says nothing, and an assertion reading
            // "rustnode failed: " with no text is the least useful possible
            // diagnosis for the one defect that manifests as silence.
            None => {
                format!("<killed after {elapsed:?} without exiting; the close never completed>")
            }
            Some(_) => stdout,
        },
        elapsed,
        status.is_some_and(|status| status.success()),
    ))
}

/// A client `session.close(cb)` over a request that has already finished.
///
/// This is the shape `test-http2-compat-socket.js` and
/// `test-http2-compat-serverresponse-close.js` reach: the exchange completes, the
/// client closes, and the *server's* session must then see `close` so `server.close`
/// can drain.
const CLIENT_CLOSE: &str = r#"
'use strict';
const http2 = require('http2');

const seen = [];
let s0;
const server = http2.createServer();
server.on('session', (s) => {
  s0 = s;
  s.on('error', () => {});
  s.on('close', () => seen.push('server-session-close'));
});
server.on('request', (req, res) => {
  res.on('finish', () => s0.close(() => seen.push('server-close-cb')));
  res.end('ok');
});

server.listen(0, '127.0.0.1', () => {
  const c = http2.connect('http://127.0.0.1:' + server.address().port);
  c.on('error', () => {});
  const req = c.request({ ':path': '/' });
  req.resume();
  req.on('close', () => {
    c.close(() => seen.push('client-close-cb'));
    server.close(() => seen.push('server-close-done'));
  });
  req.end();
});

process.on('exit', () => console.log(JSON.stringify(seen.sort())));
"#;

/// `server.close(cb)` after a completed exchange, which is the teardown of most
/// compat-API tests.
const SERVER_CLOSE: &str = r#"
'use strict';
const http2 = require('http2');

const seen = [];
const server = http2.createServer();
server.on('session', (s) => s.on('error', () => {}));
server.on('request', (req, res) => {
  res.on('close', () => {
    process.nextTick(() => {
      server.close((err) => {
        seen.push(err ? 'close-cb:' + err.code : 'close-cb');
        console.log(JSON.stringify(seen));
      });
    });
  });
  res.end('ok');
});

server.listen(0, '127.0.0.1', () => {
  const c = http2.connect('http://127.0.0.1:' + server.address().port);
  c.on('error', () => {});
  const req = c.request({ ':path': '/' });
  req.resume();
  req.on('close', () => c.close());
  req.end();
});
"#;

#[test]
fn a_client_close_lets_the_server_session_close() {
    let Some((transcript, _elapsed, ok)) = run(CLIENT_CLOSE) else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    // Without the GOAWAY fix the server never sees the peer's shutdown, so
    // `server-session-close` is missing and the process hangs.
    assert_eq!(
        transcript,
        r#"["client-close-cb","server-close-cb","server-close-done","server-session-close"]"#,
        "a completed exchange must let both sessions reach `close`: {transcript}"
    );
}

#[test]
fn server_close_invokes_its_callback() {
    let Some((transcript, _elapsed, ok)) = run(SERVER_CLOSE) else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    // `ERR_SERVER_NOT_RUNNING` would mean the server had already closed itself,
    // which is a different defect: the callback must arrive with no error.
    assert_eq!(
        transcript, r#"["close-cb"]"#,
        "http2 server.close(cb) must call back with no error: {transcript}"
    );
}

#[test]
fn a_server_session_close_emits_close_after_the_peer_goes_away() {
    let Some((transcript, _elapsed, ok)) = run(r#"
'use strict';
const http2 = require('http2');

const seen = [];
let session;
const server = http2.createServer();
server.on('session', (s) => {
  session = s;
  s.on('error', () => {});
  s.on('close', () => seen.push('session-close'));
});
server.on('request', (req, res) => {
  res.on('finish', () => session.close(() => seen.push('close-cb')));
  res.end();
});

server.listen(0, '127.0.0.1', () => {
  const c = http2.connect('http://127.0.0.1:' + server.address().port);
  c.on('error', () => {});
  const req = c.request({ ':path': '/' });
  req.resume();
  req.on('end', () => {
    c.close();
    server.close(() => seen.push('server-close-done'));
  });
  req.end();
});

process.on('exit', () => console.log(JSON.stringify(seen.sort())));
"#)
    else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    // The peer's GOAWAY drives `onSessionGoaway` -> `destroy()` -> `close`, and
    // `detach` must not stop the read that `finishSessionClose` just resumed, or
    // this event never arrives.
    assert_eq!(
        transcript, r#"["close-cb","server-close-done","session-close"]"#,
        "a server session closed by the peer must emit `close`: {transcript}"
    );
}

/// The one shape that isolates the GOAWAY (defect 1).
///
/// Every other scenario here has a second path to the same `close`: the peer's
/// GOAWAY, or the teardown that carries on regardless. This one has none. The
/// client's request has already finished, so the server has nothing left to say and
/// never sends a GOAWAY of its own; nothing but the client's *own* GOAWAY can move
/// the session to `close`. If that frame is rejected as `NGHTTP2_ERR_INVALID_ARGUMENT`
/// for carrying our own stream parity, nothing happens at all and the process sits
/// there until it is killed.
///
/// Verified load-bearing: with `goaway_last_stream_id` reverted to the old
/// `0 -> -1` translation and `rn-cli` rebuilt, this test times out instead of
/// passing. The three scenarios above still pass on that same build.
#[test]
fn a_client_only_close_queues_a_goaway() {
    let Some((transcript, _elapsed, ok)) = run(r#"
'use strict';
const http2 = require('http2');

const seen = [];
const server = http2.createServer();
server.on('session', (s) => s.on('error', () => {}));
server.on('request', (req, res) => res.end('ok'));

server.listen(0, '127.0.0.1', () => {
  const c = http2.connect('http://127.0.0.1:' + server.address().port);
  c.on('error', () => {});
  const req = c.request({ ':path': '/' });
  req.resume();
  req.on('close', () => {
    // Sole owner of this session's shutdown: only the client's GOAWAY can drive
    // it to `close`, so this callback is the frame's own observable.
    c.close((err) => {
      seen.push(err ? 'cb:' + err.code : 'cb');
      server.close(() => seen.push('server-done'));
    });
  });
  req.end();
});

process.on('exit', () => console.log(JSON.stringify(seen.sort())));
"#)
    else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    assert_eq!(
        transcript, r#"["cb","server-done"]"#,
        "a client's own GOAWAY must be queued, or close() never calls back: {transcript}"
    );
}
