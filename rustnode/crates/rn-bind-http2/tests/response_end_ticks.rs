//! `'end'` must not share a tick with `'response'`.
//!
//! Upstream's idiom for a client request is:
//!
//! ```js
//! const [res] = await once(req, 'response');
//! await once(req, 'end');
//! ```
//!
//! The `'end'` listener is attached *after* the `await` has yielded. If the body
//! and the end of the stream are delivered in the same turn as the headers, that
//! listener is attached too late and never fires — and because `once` returns a
//! promise that simply never settles, the test hangs to its timeout instead of
//! failing. Node separates the two because its `ReadStart` follows the headers
//! frame, and because `core.js` queues `'response'` on `process.nextTick`.
//!
//! # Why these tests drive the observable contract rather than the mechanism
//!
//! Nothing here asserts *how* the separation is achieved — no tick count, no
//! internal ordering of the native delivery. Each test is a script whose
//! transcript is what the pinned Node prints for the same script, so the property
//! under test is the one JavaScript can see: after awaiting `'response'`, a
//! listener attached to `'end'` still fires, and the body arrived intact.
//!
//! The `MISSED` case has to be bounded by a timer rather than by `once` alone,
//! exactly as the upstream pattern is: a missing `'end'` is silence, not an
//! exception, so an unbounded wait would turn this regression into a hung test
//! binary rather than a failed assertion.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// Far below the 60 s harness timeout this defect used to burn, and comfortable
/// for a loaded machine. A child still running here is killed and reports
/// `ok == false`.
const KILL_BUDGET: Duration = Duration::from_secs(20);

/// The `rustnode` binary, if it has been built.
///
/// `RUSTNODE_BIN` is honoured first, which is how a negative control can point
/// these tests at a binary other than the workspace build.
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

/// Runs `script` under rustnode, returning `(stdout, elapsed, exit_ok)`.
///
/// The child is killed once [`KILL_BUDGET`] elapses and `ok` is `false` then, so
/// a regression that manifests as "`'end'` never arrived" fails this test instead
/// of hanging the test binary until the harness's own timeout.
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
            None => format!("<killed after {elapsed:?} without exiting; no `end` arrived>"),
            Some(_) => stdout,
        },
        elapsed,
        status.is_some_and(|status| status.success()),
    ))
}

/// A client request read with upstream's idiom: the `'end'` listener is attached
/// only after `'response'` has been awaited.
///
/// `BODY` proves the separation did not come at the cost of the payload, and
/// `END` proves `'end'` still arrives at all. A same-tick delivery prints
/// `MISSED` instead, because the listener is attached after the emission.
const LATE_LISTENER: &str = r#"
'use strict';
const http2 = require('http2');
const { once } = require('events');

async function main() {
  const server = http2.createServer();
  server.on('stream', (stream) => {
    stream.respond({ ':status': 200 });
    stream.end('hello');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  const client = http2.connect('http://127.0.0.1:' + server.address().port);
  client.on('error', () => {});
  await once(client, 'remoteSettings');

  const req = client.request({ ':path': '/' });
  req.on('error', () => {});

  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));

  let ended;
  const response = once(req, 'response');
  req.end();
  req.resume();
  await response;
  // The listener upstream attaches here. If `end` already fired, this is dead.
  ended = once(req, 'end');

  const verdict = await Promise.race([
    ended.then(() => 'CAUGHT'),
    new Promise((resolve) => setTimeout(() => resolve('MISSED'), 2000)),
  ]);
  console.log(JSON.stringify({
    verdict,
    body: Buffer.concat(chunks).toString(),
  }));
  try { client.close(); } catch {}
  try { server.close(); } catch {}
  process.exit(0);
}

main().catch((error) => {
  console.log('THREW ' + error.code);
  process.exit(1);
});
"#;

/// The control: the same request with the `'end'` listener attached before the
/// `await`, which is the shape that must keep working regardless of ordering.
const EARLY_LISTENER: &str = r#"
'use strict';
const http2 = require('http2');
const { once } = require('events');

async function main() {
  const server = http2.createServer();
  server.on('stream', (stream) => {
    stream.respond({ ':status': 200 });
    stream.end('hello');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  const client = http2.connect('http://127.0.0.1:' + server.address().port);
  client.on('error', () => {});
  await once(client, 'remoteSettings');

  const req = client.request({ ':path': '/' });
  req.on('error', () => {});

  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  const ended = once(req, 'end');

  req.end();
  req.resume();
  await once(req, 'response');

  const verdict = await Promise.race([
    ended.then(() => 'CAUGHT'),
    new Promise((resolve) => setTimeout(() => resolve('MISSED'), 2000)),
  ]);
  console.log(JSON.stringify({
    verdict,
    body: Buffer.concat(chunks).toString(),
  }));
  try { client.close(); } catch {}
  try { server.close(); } catch {}
  process.exit(0);
}

main().catch((error) => {
  console.log('THREW ' + error.code);
  process.exit(1);
});
"#;

#[test]
fn an_end_listener_attached_after_the_response_still_fires() {
    let Some((transcript, _elapsed, ok)) = run(LATE_LISTENER) else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    // Without the separation `verdict` is `MISSED`: `core.js` queues `'response'`
    // on a tick, so the body and `'end'` were already delivered by the time the
    // `await` resumed.
    assert_eq!(
        transcript, r#"{"verdict":"CAUGHT","body":"hello"}"#,
        "`end` must arrive after `response`'s tick, with the body intact: {transcript}"
    );
}

#[test]
fn an_end_listener_attached_before_the_response_still_fires() {
    let Some((transcript, _elapsed, ok)) = run(EARLY_LISTENER) else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    // The control. This passed before the fix, so it guards against the
    // separation being implemented by never delivering `'end'` at all — the shape
    // that would turn every completed request into a hang.
    assert_eq!(
        transcript, r#"{"verdict":"CAUGHT","body":"hello"}"#,
        "a listener attached before the await must still see `end`: {transcript}"
    );
}
