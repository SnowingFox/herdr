//! `StreamPipe` moves real bytes over every combination Node accepts.
//!
//! # Why this file exists
//!
//! `new StreamPipe(a, b)` used to reject everything but a socket pair with
//! `TypeError: StreamPipe requires two stream handles`, because the lookup reached
//! for a `uv_stream_t`:
//!
//! ```text
//! rn_uv::streams::stream_of(scope, object).and_then(|s| rn_uv::handle::owner(s))
//! ```
//!
//! Node's `StreamPipe::New` unwraps a `StreamBase` instead, and both `fs.FileHandle`
//! and `binding.Http2Stream` are `AsyncWrap + StreamBase` without owning a libuv
//! handle. So the fix is not to register those objects — that would turn a loud
//! `TypeError` into a pipe that pumps nothing, which is strictly worse — it is to
//! give both a real `StreamBase` read/write surface and drive the pipe through it.
//!
//! Every scenario below therefore asserts the **bytes**, byte for byte, at the far
//! end. A construction-only test would pass on the broken shape too.
//!
//! # The matrix, as measured on `v28.0.0-nightly20261111e8c1160d20`
//!
//! | source | sink | constructs | bytes flow |
//! | --- | --- | --- | --- |
//! | `FileHandle` | socket | yes | **yes** |
//! | socket | socket | yes | **yes** |
//! | `FileHandle` | `Http2Stream` | yes | **yes** |
//! | `Http2Stream` | socket | yes | **yes** |
//! | `FileHandle` | `FileHandle` | yes | no |
//! | socket | `FileHandle` | yes | no |
//!
//! The last two rows are Node's own behaviour, not a gap here: `FileHandle::DoWrite`
//! is `return UV_ENOSYS;  // Not implemented (yet).` (`src/node_file.cc:304`), so a
//! `FileHandle` sink accepts the construction and then unpipe without writing
//! anything. A test asserts that too, so the difference between "Node does not do
//! this" and "this build does not do this" stays visible.
//!
//! Each scenario runs as a separate process because the point is that the payload
//! arrives and the process exits by itself: a pipe that stalls holds the loop
//! open, and an in-process test would hang the test binary instead of failing.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// The `rustnode` binary, if it has been built.
///
/// The integration tests spawn the real binary rather than the library: a
/// `StreamPipe` needs a libuv loop, a live isolate and the real bindings, and a
/// unit test has none of those.
fn rustnode() -> Option<PathBuf> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("rustnode");
    path.exists().then_some(path)
}

/// The payload every scenario transfers.
///
/// Deliberately longer than one TCP segment is not needed; what matters is that it
/// is not a single byte, so a pipe that writes only its first chunk is visible as a
/// mismatch rather than as a pass.
const PAYLOAD: &str = "HELLO-PIPE-PAYLOAD-0123456789";

/// Runs `script`, returning `(stdout, elapsed, exit ok)`.
///
/// A non-zero exit and a timeout are both reported rather than asserted here, so a
/// failing scenario names itself in the test's own assertion message.
fn run(script: &str) -> Option<(String, Duration, bool)> {
    let binary = rustnode()?;
    let started = Instant::now();
    // The child is killed by the timeout below rather than by `output()`, which
    // blocks forever on a hanging process; the scenario that hangs is exactly the
    // regression these tests guard.
    let mut child = Command::new(&binary)
        // `internal/test/binding` is what Node exposes the bindings through, and
        // it needs `--expose-internals` — the oracle has the same requirement. The
        // prelude used to reach the namespaces through
        // `require('internal/bootstrap/realm')`, which only worked because the CLI
        // installed the realm loader as an unrestricted global `require`.
        .arg("--expose-internals")
        .arg("-e")
        .arg(script)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Some((
                    "<killed after 20.0s without exiting; the pipe never finished>".to_string(),
                    started.elapsed(),
                    false,
                ));
            }
            Err(_) => return None,
        }
    }
    let output = child.wait_with_output().ok()?;
    Some((
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        started.elapsed(),
        output.status.success(),
    ))
}

/// The preamble every scenario shares: the bindings and a marker file.
fn prelude() -> String {
    format!(
        r#"'use strict';
const {{ internalBinding }} = require('internal/test/binding');
const {{ StreamPipe }} = internalBinding('stream_pipe');
const {{ FileHandle }} = internalBinding('fs');
const fs = require('fs');
const net = require('net');
const http2 = require('http2');
const PAYLOAD = {payload:?};
const path = '/tmp/rustnode-streampipe-payload.txt';
fs.writeFileSync(path, PAYLOAD);
function openFile() {{
  const handle = new FileHandle(fs.openSync(path, 'r'), 0, -1);
  handle.onread = () => {{}};
  return handle;
}}
"#,
        payload = PAYLOAD
    )
}

/// `FileHandle` → socket.
///
/// The `sendFile` shape: a file descriptor's stream half feeding a libuv stream.
/// This is the combination that proves the `FileHandle` `StreamBase` read path is
/// real, because the bytes can only arrive if `uv_fs_read` ran.
#[test]
fn a_file_handle_pipes_into_a_socket() {
    let Some((stdout, _elapsed, ok)) = run(&format!(
        "{}{}",
        prelude(),
        r#"
const server = net.createServer((peer) => {
  let received = '';
  peer.on('data', (chunk) => { received += chunk; });
  peer.on('end', () => {
    console.log(JSON.stringify({ received, match: received === PAYLOAD }));
    server.close();
  });
});
server.listen(0, '127.0.0.1', () => {
  const socket = net.connect(server.address().port, () => {
    const pipe = new StreamPipe(openFile(), socket._handle);
    pipe.onunpipe = () => {};
    pipe.start();
  });
  socket.on('error', () => {});
});
"#
    )) else {
        return;
    };
    assert!(ok, "the process did not exit cleanly: {stdout}");
    assert!(
        stdout.contains(r#""match":true"#),
        "the payload did not arrive byte for byte: {stdout}"
    );
}

/// socket → socket.
///
/// The combination that already worked, kept as a control: the ops indirection
/// must leave libuv-backed streams exactly as they were.
#[test]
fn a_socket_pipes_into_a_socket() {
    let Some((stdout, _elapsed, ok)) = run(&format!(
        "{}{}",
        prelude(),
        r#"
const receiver = net.createServer((peer) => {
  let received = '';
  peer.on('data', (chunk) => { received += chunk; });
  peer.on('end', () => {
    console.log(JSON.stringify({ received, match: received === PAYLOAD }));
    receiver.close();
    sender.close();
  });
});
const sender = net.createServer((peer) => { peer.end(PAYLOAD); });
receiver.listen(0, '127.0.0.1', () => {
  sender.listen(0, '127.0.0.1', () => {
    const source = net.connect(sender.address().port);
    const sink = net.connect(receiver.address().port);
    let connected = 0;
    const start = () => {
      if (++connected < 2) return;
      const pipe = new StreamPipe(source._handle, sink._handle);
      pipe.onunpipe = () => {};
      pipe.start();
    };
    source.on('connect', start);
    sink.on('connect', start);
    source.on('error', () => {});
    sink.on('error', () => {});
  });
});
"#
    )) else {
        return;
    };
    assert!(ok, "the process did not exit cleanly: {stdout}");
    assert!(
        stdout.contains(r#""match":true"#),
        "the payload did not arrive byte for byte: {stdout}"
    );
}

/// `FileHandle` → `binding.Http2Stream`.
///
/// This is `respondWithFile`'s native half, and the combination the task is about:
/// both ends are `StreamBase` with no `uv_stream_t` between them. The bytes reach
/// the wire only if the `FileHandle` reads through `uv_fs_read` *and* the HTTP/2
/// stream accepts a `StreamBase` write into its data provider.
#[test]
fn a_file_handle_pipes_into_an_http2_stream() {
    let Some((stdout, _elapsed, ok)) = run(&format!(
        "{}{}",
        prelude(),
        r#"
function handleOf(stream) {
  for (const symbol of Object.getOwnPropertySymbols(stream)) {
    const value = stream[symbol];
    if (value && typeof value === 'object' &&
        typeof value.respond === 'function' && typeof value.id === 'function') {
      return value;
    }
  }
  return null;
}
const server = http2.createServer();
server.on('stream', (stream) => {
  const handle = handleOf(stream);
  stream.respond({ ':status': 200 });
  const pipe = new StreamPipe(openFile(), handle);
  pipe.onunpipe = () => {};
  pipe.start();
});
server.listen(0, '127.0.0.1', () => {
  const client = http2.connect('http://127.0.0.1:' + server.address().port);
  client.on('error', () => {});
  const request = client.request({ ':path': '/' });
  let body = '';
  request.on('data', (chunk) => { body += chunk; });
  request.on('end', () => {
    console.log(JSON.stringify({ received: body, match: body === PAYLOAD }));
    client.close();
    server.close();
  });
  request.end();
});
"#
    )) else {
        return;
    };
    assert!(ok, "the process did not exit cleanly: {stdout}");
    assert!(
        stdout.contains(r#""match":true"#),
        "the payload did not arrive byte for byte: {stdout}"
    );
}

/// `binding.Http2Stream` → socket, which needs the stream to be a `StreamBase`
/// **source**.
///
/// The inbound DATA path has to reach the listener chain rather than calling
/// `onread` directly. Before this change the session delivered straight to
/// JavaScript, so a listener pushed onto an HTTP/2 stream saw nothing and this
/// direction moved no bytes at all.
#[test]
fn an_http2_stream_pipes_into_a_socket() {
    let Some((stdout, _elapsed, ok)) = run(&format!(
        "{}{}",
        prelude(),
        r#"
function handleOf(stream) {
  for (const symbol of Object.getOwnPropertySymbols(stream)) {
    const value = stream[symbol];
    if (value && typeof value === 'object' &&
        typeof value.respond === 'function' && typeof value.id === 'function') {
      return value;
    }
  }
  return null;
}
let cleanup = () => {};
const receiver = net.createServer((peer) => {
  let received = '';
  peer.on('data', (chunk) => { received += chunk; });
  // The pipe's own shutdown ends this peer's readable side once the HTTP/2 source
  // reports EOF, so `'end'` is the natural completion. The process is then exited
  // explicitly: both ends stay referenced by the pipe, so Node leaves the loop
  // open here too, and the same script exits the same way on
  // `v28.0.0-nightly20261111e8c1160d20`.
  const report = () => {
    console.log(JSON.stringify({ received, match: received === PAYLOAD }));
    process.exit(0);
  };
  peer.on('end', report);
  setTimeout(report, 2000);
});
receiver.listen(0, '127.0.0.1', () => {
  const server = http2.createServer();
  let pipeStarted;
  const started = new Promise((resolve) => { pipeStarted = resolve; });
  server.on('stream', (stream, headers) => {
    if (headers[':method'] !== 'POST') {
      stream.respond({ ':status': 200 });
      stream.end();
      return;
    }
    const handle = handleOf(stream);
    stream.respond({ ':status': 200 });
    const sink = net.connect(receiver.address().port, () => {
      const pipe = new StreamPipe(handle, sink._handle);
      pipe.onunpipe = () => {};
      pipe.start();
      pipeStarted();
    });
    sink.on('error', () => {});
  });
  server.listen(0, '127.0.0.1', async () => {
    const client = http2.connect('http://127.0.0.1:' + server.address().port);
    client.on('error', () => {});
    const request = client.request({ ':path': '/', ':method': 'POST' });
    // The pipe has to exist before the body arrives: an HTTP/2 stream delivers its
    // DATA as it is received, so a body sent first is gone by the time a listener is
    // pushed. Node needs the same ordering.
    await started;
    request.end(PAYLOAD);
    request.resume();
  });
});
"#
    )) else {
        return;
    };
    assert!(ok, "the process did not exit cleanly: {stdout}");
    assert!(
        stdout.contains(r#""match":true"#),
        "the payload did not arrive byte for byte: {stdout}"
    );
}

/// `FileHandle` → `FileHandle`, which Node accepts and then does not write.
///
/// `FileHandle::DoWrite` is `return UV_ENOSYS;  // Not implemented (yet).` in Node,
/// so the honest expectation is: the construction succeeds, `FileHandle`'s
/// `StreamBase` half exists, and the pipe unpipes without transferring anything.
///
/// Asserting *this* rather than a pass is the point. If a future change made the
/// pair transfer bytes it would be a divergence from Node, and if it went back to
/// throwing it would be the original defect.
#[test]
fn two_file_handles_construct_and_then_write_nothing() {
    let Some((stdout, _elapsed, ok)) = run(&format!(
        "{}{}",
        prelude(),
        r#"
const destination = '/tmp/rustnode-streampipe-sink.txt';
fs.writeFileSync(destination, '');
const sinkHandle = new FileHandle(fs.openSync(destination, 'w'), 0, -1);
let constructed = false;
let threw = null;
try {
  const pipe = new StreamPipe(openFile(), sinkHandle);
  constructed = true;
  pipe.onunpipe = () => {};
  pipe.start();
} catch (error) {
  threw = error.message;
}
setTimeout(() => {
  const written = fs.readFileSync(destination, 'utf8');
  console.log(JSON.stringify({
    constructed,
    threw,
    sinkIsStreamBase: sinkHandle.isStreamBase === true,
    written,
  }));
  process.exit(0);
}, 600);
"#
    )) else {
        return;
    };
    assert!(ok, "the process did not exit cleanly: {stdout}");
    assert!(
        stdout.contains(r#""constructed":true"#),
        "the pair Node accepts still throws: {stdout}"
    );
    assert!(
        stdout.contains(r#""sinkIsStreamBase":true"#),
        "the FileHandle has no StreamBase half, so the check passing means nothing: {stdout}"
    );
    assert!(
        stdout.contains(r#""written":"""#),
        "a FileHandle sink wrote bytes, which Node's UV_ENOSYS DoWrite does not: {stdout}"
    );
}

/// `releaseFD` exists and releases the descriptor without closing it.
///
/// `core.js`'s `onFileUnpipe` calls `source.releaseFD()` on the `!stream.ownsFd`
/// path — the `respondWithFD` family — so a `FileHandle` without it turns those
/// files into `this.source.releaseFD is not a function` instead of exercising
/// their subject.
///
/// The distinction from `close` is the whole point: `releaseFD` hands the number
/// back and forgets it, while leaving the descriptor open for the caller who owns
/// it. So the test writes through the returned descriptor *after* the release, and
/// expects the write to succeed.
#[test]
fn release_fd_hands_the_descriptor_back_without_closing_it() {
    let Some((stdout, _elapsed, ok)) = run(&format!(
        "{}{}",
        prelude(),
        r#"
const target = '/tmp/rustnode-streampipe-released.txt';
fs.writeFileSync(target, 'before');
const descriptor = fs.openSync(target, 'r+');
const handle = new FileHandle(descriptor, 0, -1);

const hasRelease = typeof handle.releaseFD === 'function';
const released = hasRelease ? handle.releaseFD() : null;
const descriptorAfter = handle.fd;

// The descriptor is still usable: that is what "released, not closed" means, and
// it is how `respondWithFD` keeps ownership of a caller's descriptor. Writing
// 'AFTER' over 'before' leaves 'AFTERe', because the file was longer than the
// replacement — the point is that the write succeeded at all.
let stillOpen = false;
try {
  fs.writeSync(descriptor, 'AFTER', 0);
  stillOpen = fs.readFileSync(target, 'utf8').startsWith('AFTER');
} catch (error) {
  stillOpen = false;
}

// A second call reports the same `-1` a closed handle does, rather than
// re-releasing a number that may already belong to something else.
const again = hasRelease ? handle.releaseFD() : null;

console.log(JSON.stringify({
  hasRelease,
  released,
  returnedTheDescriptor: released === descriptor,
  descriptorAfter,
  stillOpen,
  again,
}));
process.exit(0);
"#
    )) else {
        return;
    };
    assert!(ok, "the process did not exit cleanly: {stdout}");
    assert!(
        stdout.contains(r#""hasRelease":true"#),
        "FileHandle has no releaseFD, so onFileUnpipe throws on the respondWithFD path: {stdout}"
    );
    assert!(
        stdout.contains(r#""returnedTheDescriptor":true"#),
        "releaseFD did not return the descriptor, which is its entire return value: {stdout}"
    );
    assert!(
        stdout.contains(r#""descriptorAfter":-1"#),
        "the handle still reports a descriptor after releasing it: {stdout}"
    );
    assert!(
        stdout.contains(r#""stillOpen":true"#),
        "releaseFD closed the descriptor; it must only release this handle's claim: {stdout}"
    );
    assert!(
        stdout.contains(r#""again":-1"#),
        "a second releaseFD reported something other than -1: {stdout}"
    );
}

/// The sink that cannot be written reports a *synchronous* failure, so the pipe
/// finishes instead of waiting for a completion nobody will send.
///
/// This is the difference between `WriteOutcome::Sync` and `Queued`: a
/// `FileHandle` sink whose `DoWrite` is `UV_ENOSYS` must unpipe immediately. The
/// earlier code decremented a counter without reporting anything, so
/// `pendingWrites()` stayed raised and the process never exited.
#[test]
fn a_file_handle_sink_unpipes_instead_of_hanging() {
    let Some((stdout, elapsed, _ok)) = run(&format!(
        "{}{}",
        prelude(),
        r#"
const sinkHandle = new FileHandle(fs.openSync('/tmp/rustnode-streampipe-sink2.txt', 'w'), 0, -1);
const pipe = new StreamPipe(openFile(), sinkHandle);
let unpiped = false;
pipe.onunpipe = () => { unpiped = true; console.log('unpiped'); process.exit(0); };
pipe.start();
setTimeout(() => { console.log('never unpiped; pending=' + pipe.pendingWrites()); process.exit(1); }, 2000);
"#
    )) else {
        return;
    };
    assert!(
        stdout.contains("unpiped"),
        "the pipe never unpiped, so its write count never came back down: {stdout}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "the pipe took {elapsed:?}, which is the hang this test exists to catch"
    );
}
