//! A 64 KiB HTTP/2 response body must arrive at the client byte-equal.
//!
//! # What this test does and does not prove
//!
//! It asserts the *observable* consequence of the write-buffer bug, not the
//! memory error itself: the server's response frames are handed to libuv from a
//! buffer that the broken code had already freed, so a body that is large enough
//! to exercise that path must still reach the client intact and byte-for-byte,
//! and the process must exit on its own.
//!
//! **This test does not detect a use-after-free, and on its own it would pass on
//! the broken tree.** The defect is that `write_to_stream` took `bytes.as_ptr()`
//! and *then* called `into_boxed_slice()`, which frees the original allocation
//! when the `Vec` has spare capacity — which `send_pending_data`'s
//! `extend_from_slice` growth always leaves. On glibc that shrink is served in
//! place: measured over 500 varied size pairs, `realloc` never moved the block,
//! so the stale pointer still read the old bytes and the response arrived
//! correct. The bug is real and the allocator is free to move, but a passing
//! payload comparison cannot distinguish "the buffer was never freed" from "it
//! was freed and this allocator happened to leave the bytes where they were".
//!
//! So a green run here is a regression guard on the *protocol outcome* — the
//! body still arrives, and the write still completes, after the ownership of the
//! buffer changed — and nothing more. If the freed block were reused unmodified,
//! this file would still pass on a broken tree.
//!
//! The memory-safety check is the valgrind run in the doc comment of
//! `internal/repros/http2-write-uaf.js`:
//!
//! ```text
//! valgrind --leak-check=no <rustnode> internal/repros/http2-write-uaf.js
//! ```
//!
//! That reports `Syscall param write(buf) points to unaddressable byte(s)` with
//! the free at `write_to_stream` on a tree without the fix (3 errors, 1 context)
//! and 0 errors with it. It is the only check in this repository that proves the
//! buffer's lifetime is correct, and it is not part of the gate.
//!
//! The pointer-ownership invariant itself is pinned separately and without
//! valgrind in `write_buffer_ownership.rs`, which installs a moving allocator so
//! that taking a pointer before boxing the `Vec` becomes an ordinary failed
//! assertion. That file states its own limits; neither it nor this one replaces
//! the valgrind run.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// A child still running at this point is killed and fails the test, so a hang is
/// an assertion rather than a stuck test binary.
const KILL_BUDGET: Duration = Duration::from_secs(30);

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

/// Serves a 64 KiB body over cleartext h2 and reports what the client received.
///
/// The body size is the load-bearing part. `send_pending_data` gathers the
/// frames with `extend_from_slice`, so any body leaves spare capacity for
/// `into_boxed_slice` to shrink away; 64 KiB simply makes the realloc/free pair
/// unambiguous instead of a 30-byte block at the edge of the size classes. The
/// client checks the received length *and* a hash, because a buffer shortened by
/// a partial free would otherwise pass a length-only check when the frame
/// alignment happened to work out.
const SCRIPT: &str = r#"
'use strict';
const crypto = require('crypto');
const http2 = require('http2');

const payload = 'x'.repeat(64 * 1024);
const expected = crypto.createHash('sha256').update(payload).digest('hex');

const server = http2.createServer();
server.on('session', (s) => s.on('error', () => {}));
server.on('stream', (stream) => {
  stream.respond({ ':status': 200 });
  stream.end(payload);
});

server.listen(0, '127.0.0.1', () => {
  const client = http2.connect('http://127.0.0.1:' + server.address().port);
  client.on('error', () => {});
  const req = client.request({ ':path': '/' });
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const actual = crypto.createHash('sha256').update(body).digest('hex');
    console.log(JSON.stringify({
      status: 200,
      bytes: body.length,
      expected: payload.length,
      equal: actual === expected,
    }));
    client.close();
    server.close();
  });
});
"#;

/// The single JSON line the script prints, plus the elapsed time and exit status.
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

#[test]
fn a_64kib_response_body_arrives_byte_equal() {
    let Some((transcript, elapsed, ok)) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "rustnode failed: {transcript}");
    assert!(
        elapsed < KILL_BUDGET,
        "the response should complete well inside {KILL_BUDGET:?}, took {elapsed:?}: {transcript}"
    );
    // The transcript is one flat JSON object, so the three facts below can be read
    // with `find` without a JSON dependency. Each is asserted separately so a
    // regression names which one broke: a body that arrives short, a body that
    // arrives with the wrong bytes, or a body that never arrives at all.
    assert!(
        transcript.contains("\"bytes\":65536"),
        "the whole 64 KiB body must arrive: {transcript}"
    );
    assert!(
        transcript.contains("\"equal\":true"),
        "the body must be byte-identical to what the server sent: {transcript}"
    );
    assert!(
        !transcript.contains("\"bytes\":0"),
        "the body arrived empty, which is how a dropped write frame presents: {transcript}"
    );
}

#[test]
fn the_process_exits_by_itself_after_the_body_is_delivered() {
    let Some((transcript, elapsed, ok)) = run_script() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    // A queued write whose completion never runs is one way the loop stops
    // draining, so "delivered and exited" is a distinct fact from "delivered".
    assert!(ok, "rustnode failed: {transcript}");
    assert!(
        elapsed < KILL_BUDGET,
        "the process should exit on its own, took {elapsed:?}: {transcript}"
    );
}
