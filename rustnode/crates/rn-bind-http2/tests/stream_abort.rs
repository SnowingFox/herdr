//! A stream that closes early must be observable as an abort, not a clean end.
//!
//! This is the HTTP/2 equivalent of a truncated download: the server promises a
//! `content-length`, sends part of it, then the stream dies. If the readable side
//! is ended before `core.js` asks whether it ended, `onStreamClose` sees
//! `peerReadableEnded === true`, takes its natural-close branch, and the caller
//! gets `'end'` with no error — a partial body indistinguishable from a full one.
//!
//! The bug was an unconditional `emit_eof` in `on_stream_close`. Node emits EOF in
//! exactly one place (`Http2Session::HandleDataFrame`, when `END_STREAM` is set)
//! and lets `core.js` decide; this test pins that, by asserting all three
//! outcomes and the two cases that must *not* change:
//!
//!   * a truncated body errors with `ERR_HTTP2_STREAM_ABORTED`;
//!   * a peer `RST_STREAM(NGHTTP2_CANCEL)` errors with `ERR_HTTP2_STREAM_ABORTED`;
//!   * a peer `RST_STREAM(NGHTTP2_INTERNAL_ERROR)` errors with
//!     `ERR_HTTP2_STREAM_ERROR`;
//!   * a headers-only response (204 / `endStream`) still ends cleanly;
//!   * an ordinary body still ends cleanly and the process exits by itself.
//!
//! The last one is the regression the old code was protecting against: a stream
//! whose readable side never ends keeps `core.js`'s teardown waiting, and the
//! process hangs. So the test asserts a natural exit, not just the transcript.
//!
//! Every expectation below is the transcript a real `node`
//! (`v28.0.0-nightly20261111e8c1160d20`) produces for the same script.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

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

/// The scenarios, as one script. Each path exercises a different close reason.
const SCRIPT: &str = r#"
'use strict';
const http2 = require('http2');

const out = {};
const server = http2.createServer();
server.on('session', (s) => s.on('error', () => {}));
server.on('stream', (stream, headers) => {
  // The server side of a reset stream errors too; without a listener the
  // process dies on the unhandled event before the transcript is written.
  stream.on('error', () => {});
  const p = headers[':path'];
  if (p === '/nobody') {
    stream.respond({ ':status': 204 }, { endStream: true });
    return;
  }
  if (p === '/empty') {
    stream.respond({ ':status': 200 });
    stream.end();
    return;
  }
  if (p === '/truncated') {
    stream.respond({ ':status': 200, 'content-length': '1000' });
    stream.write(Buffer.alloc(100, 0x61));
    setTimeout(() => stream.destroy(), 30);
    return;
  }
  if (p === '/cancel') {
    stream.close(http2.constants.NGHTTP2_CANCEL);
    return;
  }
  if (p === '/error') {
    stream.respond({ ':status': 200 });
    stream.write('x');
    setTimeout(() => stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR), 30);
    return;
  }
  stream.respond({ ':status': 200 });
  stream.end('ok');
});

server.listen(0, '127.0.0.1', () => {
  const c = http2.connect('http://127.0.0.1:' + server.address().port);
  c.on('error', () => {});
  const paths = ['/nobody', '/empty', '/truncated', '/cancel', '/error', '/ok'];
  let i = 0;
  function next() {
    if (i >= paths.length) {
      c.close();
      server.close();
      console.log(JSON.stringify(out));
      return;
    }
    const p = paths[i++];
    const rec = { events: [], bytes: 0 };
    const req = c.request({ ':path': p });
    req.on('data', (d) => { rec.bytes += d.length; });
    req.on('end', () => rec.events.push('end'));
    req.on('aborted', () => rec.events.push('aborted'));
    req.on('error', (e) => rec.events.push('error:' + e.code));
    req.on('close', () => {
      out[p] = rec;
      next();
    });
    req.end();
  }
  next();
});
"#;

/// Runs the script, returning `(stdout, elapsed, ok)`.
fn run_script() -> Option<(String, Duration, bool)> {
    let binary = rustnode()?;
    let started = Instant::now();
    let output = Command::new(&binary)
        .arg("-e")
        .arg(SCRIPT)
        .output()
        .expect("rustnode runs");
    let elapsed = started.elapsed();
    Some((
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        elapsed,
        output.status.success(),
    ))
}

/// The observed events for one path, as a comma-joined string.
fn events(transcript: &str, path: &str) -> String {
    // The transcript is `{"/nobody":{"events":["end"],"bytes":0},...}`, so the
    // slice after the key up to the matching `}` is enough without a JSON parser,
    // which this crate does not depend on.
    let key = format!("\"{path}\":{{\"events\":[");
    let Some(start) = transcript.find(&key) else {
        return format!("missing {path}");
    };
    let rest = &transcript[start + key.len()..];
    let Some(end) = rest.find(']') else {
        return format!("malformed {path}");
    };
    rest[..end].replace('"', "")
}

#[test]
fn a_truncated_response_aborts_instead_of_ending() {
    let Some((transcript, _, ok)) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    // Node: error ERR_HTTP2_STREAM_ABORTED. The body that did arrive is still
    // delivered, which is what makes the missing remainder dangerous.
    assert_eq!(
        events(&transcript, "/truncated"),
        "error:ERR_HTTP2_STREAM_ABORTED",
        "a truncated body must report an abort, not a clean end: {transcript}"
    );
}

#[test]
fn a_peer_cancel_aborts_and_a_peer_error_reports_the_code() {
    let Some((transcript, _, ok)) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    // NGHTTP2_CANCEL is one of the two "clean" codes, so core.js raises
    // ERR_HTTP2_STREAM_ABORTED rather than a protocol error.
    assert_eq!(
        events(&transcript, "/cancel"),
        "error:ERR_HTTP2_STREAM_ABORTED",
        "a cancelled stream must report an abort: {transcript}"
    );
    // A non-clean code names the error instead.
    assert_eq!(
        events(&transcript, "/error"),
        "error:ERR_HTTP2_STREAM_ERROR",
        "a reset with an error code must report it: {transcript}"
    );
}

#[test]
fn a_headers_only_and_an_ordinary_response_still_end_cleanly() {
    let Some((transcript, _, ok)) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    // These are the cases an unconditional EOF was papering over: a response that
    // ends on its headers, and one with a body. Both must still say `end`, and
    // neither may say `error`.
    assert_eq!(
        events(&transcript, "/nobody"),
        "end",
        "a 204 with endStream must end cleanly: {transcript}"
    );
    assert_eq!(
        events(&transcript, "/empty"),
        "end",
        "an empty body must end cleanly: {transcript}"
    );
    assert_eq!(
        events(&transcript, "/ok"),
        "end",
        "an ordinary body must end cleanly: {transcript}"
    );
}

#[test]
fn the_process_exits_by_itself_after_a_clean_exchange() {
    let Some((transcript, elapsed, ok)) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    // The hang this guards against: `core.js` gates teardown on the readable side
    // ending, so an `emit_eof` in the wrong place is one way to break it and
    // removing `emit_eof` everywhere is another. Node finishes this in ~110ms; the
    // bound is loose on purpose, because the point is "did not hang", not a
    // performance claim.
    assert!(
        elapsed < Duration::from_secs(5),
        "the process should exit on its own, took {elapsed:?}: {transcript}"
    );
}
