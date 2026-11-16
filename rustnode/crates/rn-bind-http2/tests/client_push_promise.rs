//! A client must dispatch a server's PUSH_PROMISE to JavaScript as a push.
//!
//! Node routes `NGHTTP2_PUSH_PROMISE` through the same handler as `HEADERS`
//! (`src/node_http2.cc:1152-1155`, an intentional fall-through) and takes the
//! stream id from `GetFrameID` (`1055-1059`), which answers
//! `frame->push_promise.promised_stream_id` for a promise. Together those two
//! facts are what make `core.js`'s two-phase behaviour work: the *promise* creates
//! the stream and emits `'stream'` with the promised headers, and the pushed
//! *response* then finds a known stream id and emits `'push'` instead of a second
//! `'stream'`.
//!
//! Without the dispatch arm the promise frame is dropped, so the stream is created
//! later from the pushed response. The body still arrives, which is what makes
//! this defect quiet: only the stream's *identity* and the announcing event are
//! wrong. The pushed response does not repeat `:path`, so the header block the
//! `'stream'` listener receives has no path, and `'push'` never fires at all
//! because there is no existing stream to fire it on.
//!
//! Each assertion below names one of those observable facts, so a revert says
//! which one broke rather than only that the transcript differs.
//!
//! The expected values are what the pinned Node
//! (`v28.0.0-nightly20261111e8c1160d20`) prints for the same script; they are
//! literals here because this test must not need an oracle binary to run.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// Far below the 60 s harness timeout, and enough for a debug build to serve one
/// push. A child still running at this point is killed and fails the test, so a
/// hang is an assertion rather than a stuck test binary.
const KILL_BUDGET: Duration = Duration::from_secs(20);

/// The `rustnode` binary, if it has been built.
///
/// `RUSTNODE_BIN` is honoured first, which is how this test can be pointed at
/// another build.
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

/// One server push of `/pushed`, recorded as JSON.
///
/// The session's `'stream'` listener is registered before the request is made, so
/// it sees the promised stream when the promise arrives. `promise` is what that
/// listener was handed, and `push` is what the stream's own `'push'` listener saw;
/// keeping them separate is the point, because they come from two different
/// frames.
const SCRIPT: &str = r#"
'use strict';
const http2 = require('http2');

const out = { promise: null, push: null, pushedBody: '', reqBody: '', streamEvents: [] };

const server = http2.createServer();
server.on('session', (s) => s.on('error', () => {}));
server.on('stream', (stream) => {
  stream.on('error', () => {});
  stream.respond({ ':status': 200 });
  stream.end('main');
  stream.pushStream({ ':path': '/pushed' }, (err, pushed) => {
    if (err) { out.pushError = err.message; return; }
    out.pushedId = pushed.id;
    pushed.respond({ ':status': 200, 'content-type': 'text/plain' });
    pushed.end('PUSHED-BODY-0123456789');
  });
});

server.listen(0, '127.0.0.1', () => {
  const client = http2.connect('http://127.0.0.1:' + server.address().port);
  client.on('error', () => {});

  client.on('stream', (stream, headers) => {
    out.streamEvents.push(stream.id);
    if (out.promise === null) {
      out.promise = {
        id: stream.id,
        path: headers[':path'] === undefined ? null : headers[':path'],
        scheme: headers[':scheme'] === undefined ? null : headers[':scheme'],
      };
      stream.setEncoding('utf8');
      stream.on('push', (h) => {
        out.push = {
          id: stream.id,
          status: h[':status'],
          contentType: h['content-type'],
        };
      });
      stream.on('error', () => {});
      let body = '';
      stream.on('data', (c) => body += c);
      stream.on('end', () => { out.pushedBody = body; });
    }
    stream.resume();
  });

  const req = client.request({ ':path': '/' });
  req.on('error', () => {});
  req.setEncoding('utf8');
  req.on('data', (c) => out.reqBody += c);
  req.end();

  setTimeout(() => {
    out.remoteEnablePush = client.remoteSettings.enablePush;
    console.log(JSON.stringify(out));
    process.exit(0);
  }, 1500);
});
"#;

/// Runs the script, returning its trimmed stdout.
///
/// The child is killed once [`KILL_BUDGET`] elapses; a child that does not exit by
/// itself fails the test with its partial output rather than hanging the suite.
fn run_script() -> Option<String> {
    let binary = rustnode()?;
    let started = Instant::now();
    let mut child = Command::new(&binary)
        .arg("-e")
        .arg(SCRIPT)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("rustnode starts");
    let mut timed_out = false;
    loop {
        match child.try_wait().expect("rustnode is waitable") {
            Some(_) => break,
            None if started.elapsed() >= KILL_BUDGET => {
                let _ = child.kill();
                timed_out = true;
                break;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let output = child.wait_with_output().expect("rustnode was captured");
    assert!(
        !timed_out,
        "rustnode did not exit within {KILL_BUDGET:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.status.success(),
        "rustnode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[test]
fn a_push_promise_reaches_javascript_as_a_push() {
    let Some(transcript) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    // The promise creates the stream, so the session `'stream'` listener sees the
    // promised stream with the promise's own headers. `:path` is the load-bearing
    // one: the pushed response does not repeat it, so a stream created from the
    // response has no path at all.
    assert_eq!(
        value(&transcript, "\"promise\":", '}'),
        "{\"id\":2,\"path\":\"/pushed\",\"scheme\":\"http\"",
        "the promised stream must be created by the PUSH_PROMISE, with its headers: {transcript}"
    );
    // The pushed response then finds a *known* stream id, which is what makes
    // `core.js` pick `'push'` over a second `'stream'`.
    assert_eq!(
        value(&transcript, "\"push\":", '}'),
        "{\"id\":2,\"status\":200,\"contentType\":\"text/plain\"",
        "the promised stream must emit 'push' with the pushed response's headers: {transcript}"
    );
    // The body path was never broken; kept so a change that dispatches the
    // promise but loses the pushed body cannot pass.
    assert_eq!(
        value(&transcript, "\"pushedBody\":\"", '"'),
        "PUSHED-BODY-0123456789",
        "the pushed body must arrive on the promised stream: {transcript}"
    );
    assert_eq!(
        value(&transcript, "\"reqBody\":\"", '"'),
        "main",
        "the originating request must still complete: {transcript}"
    );
    // Exactly one session `'stream'` event, for stream 2: the promise's. A second
    // entry would mean the pushed response was treated as a fresh stream again.
    assert_eq!(
        value(&transcript, "\"streamEvents\":", ']'),
        "[2",
        "only the PUSH_PROMISE may announce a stream, not the pushed response: {transcript}"
    );
    assert!(
        transcript.contains("\"remoteEnablePush\":true"),
        "the client must advertise push support for the server to promise at all: {transcript}"
    );
}

/// The value after `key`, up to but excluding the first `end` after it.
///
/// A hand-rolled slice rather than a JSON parser: the values asserted above are
/// short and unambiguous, and this keeps a binding crate from growing a
/// serialization dependency only to read its own transcript.
fn value<'a>(transcript: &'a str, key: &str, end: char) -> &'a str {
    let start = transcript
        .find(key)
        .unwrap_or_else(|| panic!("missing {key} in {transcript}"))
        + key.len();
    let rest = &transcript[start..];
    let stop = rest
        .find(end)
        .unwrap_or_else(|| panic!("unterminated {key} in {transcript}"));
    &rest[..stop]
}
