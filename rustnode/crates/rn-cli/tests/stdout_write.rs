//! `process.stdout.write`, checked byte for byte against real `node`.
//!
//! # What this pins
//!
//! A second `process.stdout.write` used to throw `write EINVAL`. The first write
//! went through `StreamBase::WriteString`, because `net.Socket` is created with
//! `writable: true` and `decodeStrings` off, so the chunk reaches the handle as a
//! *string*. The second write arrived through `StreamBase::Writev` instead — the
//! writable had buffered it while the first was in flight, and `clearBuffer`
//! flushes a queue with `_writev` — and `writev` called `view_buffer` on each
//! chunk, which only accepts an `ArrayBufferView`. A string is not one, so it
//! reported `EINVAL`. `console.log` appeared to work only because it was still
//! the bootstrap stub writing straight to descriptor 1.
//!
//! So the bug was never a handle state; it was that `writev` implemented only
//! half of `StreamBase::Writev`. Node encodes each string chunk in place with
//! `StringBytes::Write` under that chunk's own encoding, and the tests below hold
//! the Rust implementation to Node's bytes.
//!
//! # Why the output is compared as bytes
//!
//! The encodings are the point. `latin1`, `ascii`, `ucs2`, `hex` and `base64` all
//! produce different bytes from the same input, and `ucs2` in particular produces
//! bytes that are not valid UTF-8. Comparing `String` output would have to go
//! through a lossy conversion and could not tell `ucs2` from `utf8` at all.

use std::process::Command;

use rn_node_oracle::Oracle;

/// The oracle this test binary compares against, resolved and announced once.
///
/// See `rn-cli/tests/event_loop.rs` for why the resolution is shared: the oracle
/// line is printed once per test binary rather than once per test.
fn oracle() -> Option<&'static Oracle> {
    static ORACLE: std::sync::OnceLock<Option<Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-cli stdout write"))
        .as_ref()
}

/// Runs `script` under `binary` and returns raw stdout bytes and the exit status.
fn run(binary: &str, script: &str) -> (Vec<u8>, bool) {
    let output = Command::new(binary)
        .arg("-e")
        .arg(script)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    (output.stdout, output.status.success())
}

/// The oracle's reference bytes for `script`.
fn node(oracle: &Oracle, script: &str) -> Vec<u8> {
    let output = oracle
        .command()
        .arg("-e")
        .arg(script)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", oracle.describe()));
    assert!(
        output.status.success(),
        "{} itself failed on {script:?}: {}",
        oracle.describe(),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Asserts `rustnode` writes exactly the bytes the oracle writes, and exits
/// cleanly.
fn same_bytes_as_node(oracle: &Oracle, script: &str) -> Vec<u8> {
    let expected = node(oracle, script);
    let (actual, ok) = run(env!("CARGO_BIN_EXE_rustnode"), script);
    assert!(
        ok,
        "rustnode exited non-zero for {script:?}; stdout was {:?}",
        String::from_utf8_lossy(&actual)
    );
    assert_eq!(
        actual,
        expected,
        "script was: {script}\nrustnode: {:?}\nnode:     {:?}",
        String::from_utf8_lossy(&actual),
        String::from_utf8_lossy(&expected)
    );
    actual
}

#[test]
fn a_loop_of_writes_each_reaches_the_pipe() {
    let Some(oracle) = oracle() else {
        return;
    };
    // The reported reproduction. The first write was a string write and the rest
    // were writev chunks; only the first survived.
    let printed = same_bytes_as_node(
        oracle,
        "for (let i = 0; i < 5; i++) process.stdout.write('x' + i + ' ');\n\
         console.log();",
    );
    assert_eq!(printed, b"x0 x1 x2 x3 x4 \n");
}

#[test]
fn consecutive_writes_without_a_newline_stay_in_order() {
    let Some(oracle) = oracle() else {
        return;
    };
    // No newline anywhere: this is the queue-building case, where the second and
    // third writes are flushed through `_writev`.
    let printed = same_bytes_as_node(
        oracle,
        "process.stdout.write('a');\n\
         process.stdout.write('b');\n\
         process.stdout.write('c');",
    );
    assert_eq!(printed, b"abc");
}

#[test]
fn many_small_writes_are_not_lost_and_the_process_exits() {
    let Some(oracle) = oracle() else {
        return;
    };
    // 10,000 writes overflow the pipe repeatedly, so this exercises both the
    // synchronous path and the queued path, and would hang if a completion were
    // ever dropped.
    let printed = same_bytes_as_node(
        oracle,
        "for (let i = 0; i < 10000; i++) process.stdout.write('x');",
    );
    assert_eq!(printed.len(), 10000);
    assert!(printed.iter().all(|byte| *byte == b'x'));
}

#[test]
fn a_write_larger_than_the_pipe_buffer_arrives_whole() {
    let Some(oracle) = oracle() else {
        return;
    };
    // 200 KiB is well past any pipe buffer, so libuv must keep writing as the
    // reader drains. A partial write would show up as a length mismatch.
    let printed = same_bytes_as_node(oracle, "process.stdout.write('y'.repeat(200000));");
    assert_eq!(printed.len(), 200000);
    assert!(printed.iter().all(|byte| *byte == b'y'));
}

#[test]
fn repeated_stderr_writes_behave_like_stdout() {
    let Some(oracle) = oracle() else {
        return;
    };
    // stderr is a `Pipe` of its own with the same `StreamBase` methods; it must
    // not need a separate fix.
    let script = "for (let i = 0; i < 5; i++) process.stderr.write('e' + i + ' ');";
    let expected = oracle
        .command()
        .arg("-e")
        .arg(script)
        .output()
        .map(|output| output.stderr)
        .expect("node runs");
    let actual = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg(script)
        .output()
        .map(|output| output.stderr)
        .expect("rustnode runs");
    assert_eq!(actual, expected, "script was: {script}");
}

#[test]
fn console_log_still_works_and_interleaves_with_direct_writes() {
    let Some(oracle) = oracle() else {
        return;
    };
    // `console.log` used to be a bootstrap stub writing straight to descriptor 1,
    // which bypassed the queue the earlier `write` calls were still in and
    // printed out of order. The real console writes through `process.stdout`.
    let printed = same_bytes_as_node(
        oracle,
        "process.stdout.write('A');\n\
         process.stdout.write('B');\n\
         console.log('C');\n\
         process.stdout.write('D');",
    );
    assert_eq!(printed, b"ABC\nD");
}

#[test]
fn every_encoding_writes_the_bytes_node_writes() {
    let Some(oracle) = oracle() else {
        return;
    };
    // One case per `enum encoding`. `hex` and `base64` *decode* their input
    // rather than encoding it, `ucs2` emits UTF-16LE, and `ascii`/`latin1` take
    // the low byte of each code unit — no branch here is interchangeable.
    for (encoding, input) in [
        ("utf8", "héllo"),
        ("latin1", "\u{00e9}\u{00ff}"),
        ("binary", "\u{00e9}\u{00ff}"),
        ("ascii", "\u{00e9}\u{00ff}"),
        ("ucs2", "hi"),
        ("utf16le", "hi"),
        ("hex", "6869"),
        ("base64", "aGVsbG8="),
        ("base64url", "aGVsbG8"),
    ] {
        // Written twice so the second (and later) chunk goes through `writev`,
        // which is the path the bug was in.
        let script = format!(
            "process.stdout.write('{input}', '{encoding}');\n\
             process.stdout.write('{input}', '{encoding}');"
        );
        let printed = same_bytes_as_node(oracle, &script);
        assert!(
            !printed.is_empty(),
            "{encoding} produced no bytes for {input:?}"
        );
    }
}

#[test]
fn the_single_write_string_methods_honour_their_encoding() {
    let Some(oracle) = oracle() else {
        return;
    };
    // `writeLatin1String`, `writeAsciiString` and `writeUcs2String` share one
    // implementation with `writeUtf8String`; passing UTF-8 for all four would
    // make the name a lie and only shows up in the bytes.
    for encoding in ["latin1", "binary", "ascii", "ucs2", "utf16le", "utf8"] {
        let script = format!("process.stdout.write('\\u00e9\\u00ffhi', '{encoding}');");
        let printed = same_bytes_as_node(oracle, &script);
        assert!(!printed.is_empty(), "{encoding} produced no bytes");
    }
}

/// The same encodings over a socket, which reaches a different handle.
///
/// `process.stdout` is a pipe or a tty, and those wraps dispatched each
/// `write*String` method correctly from the start. `lib/net.js` uses a `TCP`
/// handle, whose methods were instead aliased to `writeUtf8String` — so a latin1
/// or ucs2 chunk was re-encoded as UTF-8 on the way out. Nothing above caught it
/// because every existing encoding test wrote to stdout.
///
/// The assertion compares the bytes that arrive at a server socket, not the
/// return values, so it fails on an inflated payload as well as on a wrong one.
#[test]
fn a_socket_write_string_method_honours_its_encoding() {
    let Some(oracle) = oracle() else {
        return;
    };
    // 0..=255 as latin1 is the case that showed the bug: every byte above 0x7f
    // becomes two UTF-8 bytes, so 256 characters arrive as 384 bytes.
    let script = r#"
        const net = require('net');
        const cases = [
          ['latin1', Buffer.from(Array.from({ length: 256 }, (_, i) => i)).toString('latin1')],
          ['ascii', '\u00e9\u00ffhi'],
          ['ucs2', 'hi\u4e16'],
          ['utf8', 'caf\u00e9\u4e16'],
        ];
        const seen = [];
        (async () => {
          for (const [encoding, text] of cases) {
            const hex = await new Promise((resolve, reject) => {
              const chunks = [];
              const server = net.Server((socket) => {
                socket.on('data', (chunk) => chunks.push(chunk));
                socket.on('end', () => {
                  socket.end();
                  server.close();
                  resolve(Buffer.concat(chunks).toString('hex'));
                });
              });
              server.on('error', reject);
              server.listen(0, '127.0.0.1', () => {
                const client = net.connect(server.address().port, '127.0.0.1', () => {
                  client.end(text, encoding);
                });
                client.on('error', reject);
              });
            });
            seen.push(hex);
          }
          console.log(seen.join('\n'));
        })();
    "#;
    let printed = same_bytes_as_node(oracle, script);
    let text = String::from_utf8(printed).expect("the probe prints hex");
    let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), 4, "one line per encoding, got {lines:?}");
    // latin1 0..=255 is exactly 256 bytes, unchanged by the hop.
    assert_eq!(
        lines[0].len(),
        512,
        "latin1 should send 256 bytes (512 hex digits), got {}",
        lines[0].len() / 2
    );
}
