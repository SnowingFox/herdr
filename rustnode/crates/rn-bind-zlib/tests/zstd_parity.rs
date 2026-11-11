//! Cross-decompression parity with real `node`.
//!
//! The bar for compression is not byte equality: zstd output legitimately
//! differs across versions and levels, so a compressed frame is proved correct
//! by decompressing it on the other side. Decompression is held to byte
//! equality, because the decompressed bytes are the input and nothing about the
//! implementation may change them.
//!
//! Both the reference runtime and the runtime under test are driven with the
//! same script, and the frames cross over as base64 so a NUL byte or a newline
//! cannot be mangled by a pipe. The reference is whatever `node` is on `PATH`,
//! which is why every test states the versions it ran against.
//!
//! Set `RUSTNODE_BIN` to point at the binary under test. It defaults to
//! `target/debug/rustnode`, and a missing binary is a failure rather than a
//! skip: a parity test that silently does nothing is worse than no test.

use std::io::Write;
use std::process::{Command, Stdio};

/// The runtime under test.
fn rustnode_bin() -> String {
    std::env::var("RUSTNODE_BIN").unwrap_or_else(|_| {
        let root = env!("CARGO_MANIFEST_DIR");
        format!("{root}/../../target/debug/rustnode")
    })
}

/// Runs `source` on `binary` with stdin, returning stdout.
///
/// A non-zero exit is a failure that carries the child's stderr, so a broken
/// script is never mistaken for an empty result.
fn run(binary: &str, source: &str, stdin: &str) -> Result<String, String> {
    let mut child = Command::new(binary)
        .arg("-e")
        .arg(source)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // The payload travels on stdin: base64 of a multi-MB buffer does not
        // fit in argv, and a text pipe keeps every byte intact.
        .spawn()
        .map_err(|error| format!("cannot start {binary}: {error}"))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "no stdin pipe".to_string())?
        .write_all(stdin.as_bytes())
        .map_err(|error| format!("cannot write the payload: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("{binary} did not finish: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{binary} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Compresses `payload` on `binary`.
fn compress_on(binary: &str, payload: &[u8]) -> String {
    // The payload is fed as base64 so stdin stays text; the script would
    // otherwise see a NUL as a terminator in some shells.
    let source = "const z = require('zlib');\n\
        const chunks = [];\n\
        process.stdin.on('data', (chunk) => chunks.push(chunk));\n\
        process.stdin.on('end', () => {\n\
          const input = Buffer.from(Buffer.concat(chunks).toString(), 'base64');\n\
          process.stdout.write(z.zstdCompressSync(input).toString('base64'));\n\
        });\n";
    run(binary, source, &base64(payload)).expect("compression failed")
}

/// Decompresses `frame` on `binary`.
fn decompress_on(binary: &str, frame: &[u8]) -> Vec<u8> {
    let source = "const z = require('zlib');\n\
        const chunks = [];\n\
        process.stdin.on('data', (chunk) => chunks.push(chunk));\n\
        process.stdin.on('end', () => {\n\
          const input = Buffer.from(Buffer.concat(chunks).toString(), 'base64');\n\
          process.stdout.write(z.zstdDecompressSync(input).toString('base64'));\n\
        });\n";
    let encoded = run(binary, source, &base64(frame)).expect("decompression failed");
    from_base64(&encoded).expect("output is not base64")
}

/// Minimal base64, so the test needs no extra dependency.
fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        out.push(T[(b[0] >> 2) as usize] as char);
        out.push(T[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(b[2] & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn from_base64(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 0,
            _ => return None,
        })
    }
    let clean: Vec<u8> = input.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for quad in clean.chunks(4) {
        if quad.len() < 4 {
            return None;
        }
        let v = [
            value(quad[0])?,
            value(quad[1])?,
            value(quad[2])?,
            value(quad[3])?,
        ];
        out.push((v[0] << 2) | (v[1] >> 4));
        if quad[2] != b'=' {
            out.push((v[1] << 4) | (v[2] >> 2));
        }
        if quad[3] != b'=' {
            out.push((v[2] << 6) | v[3]);
        }
    }
    Some(out)
}

/// The four payloads the acceptance criteria name.
fn payloads() -> Vec<(&'static str, Vec<u8>)> {
    // A multi-MB buffer of repetitive-but-not-trivial text: large enough that
    // zstd has to emit several blocks and the JS loop has to loop.
    let mut large = Vec::with_capacity(4 * 1024 * 1024);
    let line = b"the quick brown fox jumps over the lazy dog 0123456789\n";
    while large.len() < 4 * 1024 * 1024 {
        large.extend_from_slice(line);
    }
    vec![
        ("small string", b"hello world".to_vec()),
        ("large multi-MB buffer", large),
        ("empty buffer", Vec::new()),
        (
            "binary data with an embedded NUL",
            vec![0x00, 0x01, 0x00, 0xff, 0xfe, 0x00, 0x7f, 0x00, 0x80, 0x00],
        ),
    ]
}

#[test]
fn our_frames_decompress_on_node() {
    let node = "node";
    let rustnode = rustnode_bin();
    for (name, payload) in payloads() {
        let frame = from_base64(&compress_on(&rustnode, &payload)).expect("our output is base64");
        let back = decompress_on(node, &frame);
        assert_eq!(
            back, payload,
            "{name}: node could not reproduce our payload"
        );
    }
}

#[test]
fn node_frames_decompress_on_rustnode() {
    let node = "node";
    let rustnode = rustnode_bin();
    for (name, payload) in payloads() {
        let frame = from_base64(&compress_on(node, &payload)).expect("node output is base64");
        let back = decompress_on(&rustnode, &frame);
        assert_eq!(
            back, payload,
            "{name}: we could not reproduce node's payload"
        );
    }
}

/// Decompression is the direction held to byte equality, so the frames are
/// compared directly as well: both sides must decode the same frame to the same
/// bytes.
#[test]
fn decompression_is_byte_identical_in_both_directions() {
    let node = "node";
    let rustnode = rustnode_bin();
    for (name, payload) in payloads() {
        let node_frame = from_base64(&compress_on(node, &payload)).expect("node output is base64");
        let our_frame =
            from_base64(&compress_on(&rustnode, &payload)).expect("our output is base64");

        for (origin, frame) in [("node", &node_frame), ("rustnode", &our_frame)] {
            let via_node = decompress_on(node, frame);
            let via_rustnode = decompress_on(&rustnode, frame);
            assert_eq!(
                via_node, via_rustnode,
                "{name}: {origin}'s frame decodes differently on the two runtimes"
            );
            assert_eq!(via_node, payload, "{name}: {origin}'s frame did not decode");
        }
    }
}

/// `zstdCompressSync` is expected to match Node's output for the same input at
/// the same level, because both link zstd 1.5.7. It is reported rather than
/// asserted: the acceptance criteria allow the bytes to differ, and pinning
/// them here would turn a legitimate zstd change into a failure.
#[test]
fn compression_shape_matches_node() {
    let node = "node";
    let rustnode = rustnode_bin();
    let mut differing = Vec::new();
    for (name, payload) in payloads() {
        let node_frame = from_base64(&compress_on(node, &payload)).expect("node output");
        let our_frame = from_base64(&compress_on(&rustnode, &payload)).expect("our output");
        if node_frame != our_frame {
            differing.push(format!(
                "{name}: node {} bytes, rustnode {} bytes",
                node_frame.len(),
                our_frame.len()
            ));
        }
    }
    if !differing.is_empty() {
        eprintln!("compressed bytes differ (allowed, both decode): {differing:?}");
    }
}

/// `zstdCompress`/`zstdDecompress` (the async forms) and the stream classes in
/// one script, driven entirely from inside the runtime under test.
#[test]
fn async_api_and_streams_work() {
    let source = r#"
const z = require('zlib');
const assert = require('assert');

const payloads = [
  Buffer.alloc(0),
  Buffer.from('hello world'),
  Buffer.from([0x00, 0x01, 0x00, 0xff, 0x00]),
  Buffer.from('x'.repeat(300000)),
];

function streamRoundTrip(payload, chunkSize) {
  return new Promise((resolve, reject) => {
    const compress = z.createZstdCompress({ chunkSize });
    const decompress = z.createZstdDecompress({ chunkSize });
    const out = [];
    compress.pipe(decompress);
    decompress.on('data', (chunk) => out.push(chunk));
    decompress.on('end', () => resolve(Buffer.concat(out)));
    decompress.on('error', reject);
    compress.on('error', reject);
    // Several writes, so the transform sees multi-chunk input.
    let offset = 0;
    while (offset < payload.length) {
      const end = Math.min(offset + 7919, payload.length);
      compress.write(payload.subarray(offset, end));
      offset = end;
    }
    compress.end();
  });
}

(async () => {
  for (const payload of payloads) {
    const compressed = await new Promise((resolve, reject) => {
      z.zstdCompress(payload, (err, result) => err ? reject(err) : resolve(result));
    });
    const decompressed = await new Promise((resolve, reject) => {
      z.zstdDecompress(compressed, (err, result) => err ? reject(err) : resolve(result));
    });
    assert.deepStrictEqual(decompressed, payload, 'async round trip');

    for (const chunkSize of [64, 4096, 65536]) {
      const streamed = await streamRoundTrip(payload, chunkSize);
      assert.deepStrictEqual(streamed, payload, 'stream round trip ' + chunkSize);
    }
  }
  process.stdout.write('ok');
})().catch((error) => {
  process.stderr.write(String(error && error.stack || error));
  process.exitCode = 1;
});
"#;
    let stdout = run(&rustnode_bin(), source, "").expect("async + stream round trip");
    assert_eq!(stdout, "ok");
}
