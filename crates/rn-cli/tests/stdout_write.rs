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

/// Runs `script` under `binary` and returns raw stdout bytes and the exit status.
fn run(binary: &str, script: &str) -> (Vec<u8>, bool) {
    let output = Command::new(binary)
        .arg("-e")
        .arg(script)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    (output.stdout, output.status.success())
}

/// `node`'s reference bytes for `script`.
fn node(script: &str) -> Vec<u8> {
    let (stdout, ok) = run("node", script);
    assert!(ok, "node itself failed on {script:?}");
    stdout
}

/// Asserts `rustnode` writes exactly the bytes `node` writes, and exits cleanly.
fn same_bytes_as_node(script: &str) -> Vec<u8> {
    let expected = node(script);
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
    // The reported reproduction. The first write was a string write and the rest
    // were writev chunks; only the first survived.
    let printed = same_bytes_as_node(
        "for (let i = 0; i < 5; i++) process.stdout.write('x' + i + ' ');\n\
         console.log();",
    );
    assert_eq!(printed, b"x0 x1 x2 x3 x4 \n");
}

#[test]
fn consecutive_writes_without_a_newline_stay_in_order() {
    // No newline anywhere: this is the queue-building case, where the second and
    // third writes are flushed through `_writev`.
    let printed = same_bytes_as_node(
        "process.stdout.write('a');\n\
         process.stdout.write('b');\n\
         process.stdout.write('c');",
    );
    assert_eq!(printed, b"abc");
}

#[test]
fn many_small_writes_are_not_lost_and_the_process_exits() {
    // 10,000 writes overflow the pipe repeatedly, so this exercises both the
    // synchronous path and the queued path, and would hang if a completion were
    // ever dropped.
    let printed = same_bytes_as_node("for (let i = 0; i < 10000; i++) process.stdout.write('x');");
    assert_eq!(printed.len(), 10000);
    assert!(printed.iter().all(|byte| *byte == b'x'));
}

#[test]
fn a_write_larger_than_the_pipe_buffer_arrives_whole() {
    // 200 KiB is well past any pipe buffer, so libuv must keep writing as the
    // reader drains. A partial write would show up as a length mismatch.
    let printed = same_bytes_as_node("process.stdout.write('y'.repeat(200000));");
    assert_eq!(printed.len(), 200000);
    assert!(printed.iter().all(|byte| *byte == b'y'));
}

#[test]
fn repeated_stderr_writes_behave_like_stdout() {
    // stderr is a `Pipe` of its own with the same `StreamBase` methods; it must
    // not need a separate fix.
    let script = "for (let i = 0; i < 5; i++) process.stderr.write('e' + i + ' ');";
    let expected = Command::new("node")
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
    // `console.log` used to be a bootstrap stub writing straight to descriptor 1,
    // which bypassed the queue the earlier `write` calls were still in and
    // printed out of order. The real console writes through `process.stdout`.
    let printed = same_bytes_as_node(
        "process.stdout.write('A');\n\
         process.stdout.write('B');\n\
         console.log('C');\n\
         process.stdout.write('D');",
    );
    assert_eq!(printed, b"ABC\nD");
}

#[test]
fn every_encoding_writes_the_bytes_node_writes() {
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
        let printed = same_bytes_as_node(&script);
        assert!(
            !printed.is_empty(),
            "{encoding} produced no bytes for {input:?}"
        );
    }
}

#[test]
fn the_single_write_string_methods_honour_their_encoding() {
    // `writeLatin1String`, `writeAsciiString` and `writeUcs2String` share one
    // implementation with `writeUtf8String`; passing UTF-8 for all four would
    // make the name a lie and only shows up in the bytes.
    for encoding in ["latin1", "binary", "ascii", "ucs2", "utf16le", "utf8"] {
        let script = format!("process.stdout.write('\\u00e9\\u00ffhi', '{encoding}');");
        let printed = same_bytes_as_node(&script);
        assert!(!printed.is_empty(), "{encoding} produced no bytes");
    }
}
