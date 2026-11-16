//! A stream handle must be an instance of the class `binding.Http2Stream` publishes.
//!
//! Node caches one `FunctionTemplate` on the `Environment`
//! (`env->http2stream_constructor_template()`, `src/node_http2.cc:3664-3675`) and uses
//! it for *both* halves of the job: `SetConstructorFunction` publishes it to
//! JavaScript, and `Http2Stream::New` (`src/node_http2.cc:2284-2297`) makes every
//! handle from `InstanceTemplate()->NewInstance(...)`. One template, so a handle's
//! prototype is the exported class's prototype.
//!
//! rustnode built a fresh template at each of those two sites, which produced two
//! classes with distinct prototypes. Nothing throws, so the defect is invisible
//! until something compares the two:
//!
//!   * `handle instanceof binding.Http2Stream` is false, and
//!     `handle.constructor !== binding.Http2Stream`;
//!   * a patch on `Http2Stream.prototype` is not seen by the handle `core.js` calls
//!     into, because the handle's prototype is a different object.
//!
//! The second one is what upstream's `test-http2-server-push-stream-errors.js` does:
//! it replaces `Http2Stream.prototype.pushPromise` with a mock returning a negative
//! error code and expects `stream.pushStream(...)` to route through it. With two
//! templates the real `pushPromise` runs instead, the mock is never called, and the
//! push *succeeds* where the test expects an error — so `pushStream`'s callback
//! receives `(null, stream)` and the test fails with `Expected one argument, got
//! [null, Http2Stream]`.
//!
//! Sessions are correct either way and this test pins that too, because the reason
//! they are correct is instructive: `core.js` calls `new binding.Http2Session(...)`
//! itself, so a session is made *by* the exported constructor and identity holds
//! trivially. Only handles built natively can get this wrong.
//!
//! Every expectation below is the transcript a real `node`
//! (`v28.0.0-nightly20261111e8c1160d20`) produces for the same script.

use std::path::PathBuf;
use std::process::Command;

/// The `rustnode` binary, if it has been built.
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

/// One request, with everything the identity question needs recorded.
///
/// `--expose-internals` is what makes `internalBinding('http2')` reachable, and the
/// `kHandle` symbol is found by description because the private symbol is not
/// exported under a name `core.js` would let a test import.
///
/// The two halves are deliberately in one script. The `instanceof` answer is what the
/// defect is, and the mock answer is what it *does* — a fix that made only the first
/// true would be a different bug, and the second assertion is the one upstream's
/// test depends on.
const SCRIPT: &str = r#"
'use strict';
const http2 = require('http2');
const { internalBinding } = require('internal/test/binding');
const binding = internalBinding('http2');

const out = {};

function handleOf(object) {
  const symbol = Object.getOwnPropertySymbols(object)
    .find((candidate) => String(candidate).includes('kHandle'));
  return symbol === undefined ? null : object[symbol];
}

// One key per answer rather than one joined string: a failure then names which
// half disagreed, and nothing here has to be parsed.
function record(prefix, handle, exported) {
  if (handle === null) {
    out[prefix + 'HandleFound'] = false;
    return;
  }
  out[prefix + 'HandleFound'] = true;
  out[prefix + 'InstanceOf'] = handle instanceof exported;
  out[prefix + 'CtorMatch'] = handle.constructor === exported;
  out[prefix + 'CtorName'] = handle.constructor && handle.constructor.name;
}

out.streamExportedType = typeof binding.Http2Stream;
out.sessionExportedType = typeof binding.Http2Session;

// The mock upstream's push-errors test installs. A distinct number so a stale
// real return value cannot pass by coincidence.
const SENTINEL = -999;
binding.Http2Stream.prototype.pushPromise = () => SENTINEL;

const server = http2.createServer();
server.on('session', (session) => {
  record('session', handleOf(session), binding.Http2Session);
});
server.on('stream', (stream) => {
  stream.on('error', () => {});
  const handle = handleOf(stream);
  record('stream', handle, binding.Http2Stream);

  out.mockPushPromise = handle === null ? null : handle.pushPromise('', 0);

  stream.pushStream({ ':path': '/x' }, (err, pushed) => {
    out.pushStreamError = err === null ? null : err.code;
    out.pushStreamHandle = pushed === undefined ? 'undefined' : typeof pushed;
    stream.respond({});
    stream.end();
  });
});

server.listen(0, '127.0.0.1', () => {
  const client = http2.connect('http://127.0.0.1:' + server.address().port);
  client.on('error', () => {});
  const req = client.request({ ':path': '/' });
  req.on('error', () => {});
  req.resume();
  setTimeout(() => {
    console.log(JSON.stringify(out));
    process.exit(0);
  }, 1200);
  req.end();
});
"#;

/// Runs the script, returning its stdout.
fn run_script() -> Option<String> {
    let binary = rustnode()?;
    let output = Command::new(&binary)
        .arg("--expose-internals")
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

/// Reads one `"key":value` pair out of the JSON transcript.
///
/// A missing key fails the test rather than defaulting, because a script that
/// stopped recording an answer would otherwise read as agreement. Every value this
/// test reads is a scalar, so a scan to the next delimiter is enough; strings are
/// unquoted and `null` stays `null`.
fn field<'a>(transcript: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\":");
    let Some(start) = transcript.find(&needle) else {
        panic!("missing {key} in {transcript}");
    };
    let rest = &transcript[start + needle.len()..];
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    rest[..end].trim_matches('"')
}

#[test]
fn a_stream_handle_is_an_instance_of_the_exported_class() {
    let Some(transcript) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    // The exported type is the control: a namespace that stopped exporting the class
    // would make `instanceof` a type error rather than a `false`, and this test would
    // be reporting a different defect.
    assert_eq!(
        field(&transcript, "streamExportedType"),
        "function",
        "the binding must export Http2Stream as a constructor: {transcript}"
    );
    assert_eq!(
        field(&transcript, "streamHandleFound"),
        "true",
        "the stream must carry a kHandle: {transcript}"
    );
    assert_eq!(
        field(&transcript, "streamInstanceOf"),
        "true",
        "a stream handle must be an instance of the class the binding exports: {transcript}"
    );
    assert_eq!(
        field(&transcript, "streamCtorMatch"),
        "true",
        "a stream handle's constructor must be the exported Http2Stream: {transcript}"
    );
}

#[test]
fn a_session_handle_is_still_an_instance_of_the_exported_class() {
    let Some(transcript) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    // `core.js` builds sessions itself with `new binding.Http2Session(type)`, so this
    // half was never broken. It is pinned so a fix for streams cannot regress the
    // session class it shares the code shape with.
    assert_eq!(
        field(&transcript, "sessionExportedType"),
        "function",
        "the binding must export Http2Session as a constructor: {transcript}"
    );
    assert_eq!(
        field(&transcript, "sessionInstanceOf"),
        "true",
        "a session handle must be an instance of the exported Http2Session: {transcript}"
    );
    assert_eq!(
        field(&transcript, "sessionCtorMatch"),
        "true",
        "a session handle's constructor must be the exported Http2Session: {transcript}"
    );
}

#[test]
fn patching_the_exported_prototype_reaches_the_real_handle() {
    let Some(transcript) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    // Upstream's `test-http2-server-push-stream-errors.js` in one assertion. With two
    // templates the real `pushPromise` runs and answers a real nghttp2 code (`-501`
    // once the stream is already closed), so the mock's `-999` never appears.
    assert_eq!(
        field(&transcript, "mockPushPromise"),
        "-999",
        "a method patched onto the exported prototype must be the one the handle \
         runs: {transcript}"
    );
    // The user-visible consequence, which is the assertion that separates a real fix
    // from one that only rearranges the classes: `core.js` reads a negative number
    // as an error code, so the mock turns this push into a failure. Before the fix
    // the push succeeded and the callback received `(null, handle)`.
    assert_eq!(
        field(&transcript, "pushStreamError"),
        "ERR_HTTP2_ERROR",
        "a mocked push must surface as an error, not a successful push: {transcript}"
    );
    assert_eq!(
        field(&transcript, "pushStreamHandle"),
        "undefined",
        "the callback of a failed push must not receive a stream handle: {transcript}"
    );
}
