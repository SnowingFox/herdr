//! A successful push promise must hand back a stream handle, not a stream id.
//!
//! `Http2Stream::PushPromise` returns `stream->object()` on success and the
//! negative error code on failure (`src/node_http2.cc:3266-3271`). `core.js` relies
//! on that split: a number is taken as an error code, and anything else is a handle
//! it reads `.id()` from. Returning a bare id therefore does not merely lose a
//! field — a stream id is positive, so `pushStream` wraps it in `NghttpError` and a
//! push that *worked* reports `Unknown error code` with `errno` set to the new
//! stream's id.
//!
//! That is what this pins, on both submit paths:
//!
//!   * `/direct`, where nothing is on the stack; and
//!   * `/from-data`, where `pushStream` is called from a `'data'` handler, so the
//!     submit happens with `nghttp2_session_mem_recv` running. The binding used to
//!     defer the submit there and answer `0`, which is also a number and produced
//!     the same "Unknown error code" (with `errno` 0), so both had to be fixed.
//!
//! Every expectation below is the transcript a real `node`
//! (`v28.0.0-nightly20261111e8c1160d20`) produces for the same script.

use std::path::PathBuf;
use std::process::Command;

/// The `rustnode` binary, if it has been built.
fn rustnode() -> Option<PathBuf> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("rustnode");
    path.exists().then_some(path)
}

/// One push per path, each described the way `core.js` reads the return value.
const SCRIPT: &str = r#"
'use strict';
const http2 = require('http2');

const out = {};

function describe(push) {
  return {
    typeof: typeof push,
    isNumber: typeof push === 'number',
    id: push && push.id,
    hasRespond: typeof (push && push.respond),
  };
}

const server = http2.createServer();
server.on('session', (s) => s.on('error', () => {}));
server.on('stream', (stream, headers) => {
  stream.on('error', () => {});
  const p = headers[':path'];

  if (p === '/direct') {
    stream.pushStream({ ':path': '/pushed' }, (err, push) => {
      out.direct = { err: err && (err.code + ':' + err.message), ...describe(push) };
      push.respond({ ':status': 200 });
      push.end('pushed');
      stream.respond({ ':status': 200 });
      stream.end('ok');
    });
    return;
  }

  if (p === '/from-data') {
    // Reached synchronously from inside `nghttp2_session_mem_recv`, which is the
    // window where the binding used to defer the submit.
    stream.on('data', () => {
      stream.pushStream({ ':path': '/pushed' }, (err, push) => {
        out.fromData = { err: err && (err.code + ':' + err.message), ...describe(push) };
        push.respond({ ':status': 200 });
        push.end('pushed');
        stream.respond({ ':status': 200 });
        stream.end('ok');
      });
    });
    return;
  }

  stream.respond({ ':status': 200 });
  stream.end('ok');
});

server.listen(0, '127.0.0.1', () => {
  const base = 'http://127.0.0.1:' + server.address().port;
  const paths = ['/direct', '/from-data'];
  let i = 0;
  function next() {
    if (i >= paths.length) {
      server.close();
      console.log(JSON.stringify(out));
      return;
    }
    const path = paths[i++];
    const c = http2.connect(base);
    c.on('error', () => {});
    c.on('stream', (s) => s.resume());
    const req = c.request({ ':path': path, ':method': 'POST' });
    req.on('error', () => {});
    req.resume();
    req.on('close', () => { c.close(); next(); });
    // Headers first, body in a later segment, so the server's `'data'` handler
    // runs with `mem_recv` on the stack.
    req.write('body');
    setTimeout(() => req.end(), 30);
  }
  next();
});
"#;

/// Runs the script, returning its trimmed stdout.
fn run_script() -> Option<String> {
    let binary = rustnode()?;
    let output = Command::new(&binary)
        .arg("-e")
        .arg(SCRIPT)
        .output()
        .expect("rustnode runs");
    assert!(
        output.status.success(),
        "rustnode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// The transcript for one recorded push, isolated so a failure names which broke.
///
/// `record` is the key the script writes (`direct`/`fromData`), not the request
/// path: the two differ, and the transcript is the contract.
fn transcript_for<'a>(transcript: &'a str, record: &str) -> &'a str {
    let key = format!("\"{record}\":");
    let Some(start) = transcript.find(&key) else {
        panic!("missing {record} in {transcript}");
    };
    let rest = &transcript[start + key.len()..];
    let end = rest.find('}').map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn a_successful_push_returns_a_stream_handle() {
    let Some(transcript) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    // The exact transcript `node` prints for this script: no error, an object
    // rather than a number, the pushed stream's id, and a usable response.
    let expected = "{\"err\":null,\"typeof\":\"object\",\"isNumber\":false,\
\"id\":2,\"hasRespond\":\"function\"}";
    assert_eq!(
        transcript_for(&transcript, "direct"),
        expected,
        "a push that succeeds must report a handle, not an id: {transcript}"
    );
}

#[test]
fn a_push_submitted_inside_a_data_callback_also_returns_a_handle() {
    let Some(transcript) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    let expected = "{\"err\":null,\"typeof\":\"object\",\"isNumber\":false,\
\"id\":2,\"hasRespond\":\"function\"}";
    // Deferring the submit here answered `0`, which `core.js` could not tell
    // apart from an error code either. The frame has to be queued inline so the
    // promised id exists in time to be returned.
    assert_eq!(
        transcript_for(&transcript, "fromData"),
        expected,
        "a push from a 'data' handler must also report a handle: {transcript}"
    );
}
