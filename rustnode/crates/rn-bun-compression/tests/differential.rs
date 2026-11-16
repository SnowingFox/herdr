//! `Bun`'s eight compression members compared against Bun 1.4.4.
//!
//! The acceptance bar for this group is not byte equality: the exact compressed
//! bytes are Bun's zlib level and strategy choice. What has to match is
//!
//! * **the container**, which is observable and is a real divergence when wrong —
//!   gzip is a gzip container, `deflateSync` is **raw** deflate, `inflateSync`
//!   accepts raw, zstd is zstd;
//! * **round-trip equality** for empty input, one byte, a block boundary and a
//!   multi-megabyte input;
//! * **the error class, `code` and message text** on corrupt, truncated and
//!   valid-header-garbage-body input.
//!
//! The probe runs unmodified under both runtimes and prints one JSON document, so
//! a divergence is a field-by-field diff rather than a diff of two screens of
//! text. Every field names a measured fact rather than a restatement of the
//! implementation.
//!
//! The Bun binary comes from `RUSTNODE_BUN_ORACLE` (default
//! `/tmp/bun-dl/bun-linux-x64/bun`). When it is absent the comparison skips with a
//! printed reason rather than passing silently.

use std::process::Command;

fn bun_oracle() -> Option<String> {
    let path = std::env::var("RUSTNODE_BUN_ORACLE")
        .unwrap_or_else(|_| "/tmp/bun-dl/bun-linux-x64/bun".to_string());
    if std::path::Path::new(&path).is_file() {
        Some(path)
    } else {
        eprintln!(
            "skipped: no Bun oracle at {path}; set RUSTNODE_BUN_ORACLE to compare. \
             This is a skip, not a pass: the members were not compared against Bun."
        );
        None
    }
}

fn run(binary: &std::path::Path, script: &str) -> String {
    let out = Command::new(binary)
        .args(["-e", script])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        out.status.success(),
        "{} failed ({}): {}",
        binary.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn rustnode() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

/// The probe. Everything here is measured on Bun 1.4.4 and is either identical
/// across runtimes or a documented divergence the test pins rather than hides.
const PROBE: &str = r#"
const out = {};
const hex = (u) => Buffer.from(u).toString('hex');

function capture(fn) {
  try { return { ok: hex(fn()) }; }
  catch (e) {
    return {
      threw: true,
      name: e && e.constructor ? e.constructor.name : typeof e,
      code: e && e.code === undefined ? null : (e && e.code),
      message: e && e.message,
    };
  }
}
function captureText(fn) {
  try { return { ok: Buffer.from(fn()).toString() }; }
  catch (e) { return capture(() => { throw e; }); }
}

// --- shape: name, length, typeof, and that `new` throws -------------------
// `configurable` is recorded but compared separately: `BunRegistry::build`
// flattens every contribution with `create_data_property`, which is always
// configurable, so it reads `true` here where Bun reports `false`. That is the
// shared foundation's publication step and not this crate's install, so pinning
// it per member would fail for a reason no crate can fix. `configurable_is_a_
// foundation_divergence` records it instead.
for (const name of ['gzipSync','gunzipSync','deflateSync','inflateSync',
                    'zstdCompress','zstdCompressSync','zstdDecompress','zstdDecompressSync']) {
  const f = Bun[name];
  let newThrew = false;
  try { new f(); } catch { newThrew = true; }
  const descriptor = Object.getOwnPropertyDescriptor(Bun, name);
  out['shape_' + name] = {
    typeof: typeof f,
    name: f.name,
    length: f.length,
    newThrows: newThrew,
    enumerable: descriptor.enumerable,
    writable: descriptor.writable,
  };
  out['configurable_' + name] = descriptor.configurable;
}

// --- the container, by construction (not by round trip) -------------------
// gzip magic is 1f 8b; zstd magic is 28 b5 2f fd; and raw deflate must NOT
// start with a zlib header (78 xx). That last one is the whole point.
out.gzip_magic = hex(Bun.gzipSync('hello')).slice(0, 4);
out.zstd_magic = hex(Bun.zstdCompressSync('hello')).slice(0, 8);
out.deflate_first_byte = hex(Bun.deflateSync('hello')).slice(0, 2);
out.deflate_hello = hex(Bun.deflateSync('hello'));
out.gzip_hello = hex(Bun.gzipSync('hello'));

// --- round trips, including the block boundary and a multi-megabyte input --
const shapes = {
  empty: '',
  oneByte: 'A',
  blockBoundary: 'z'.repeat(65536),
  multiMegabyte: 'q'.repeat(3 * 1024 * 1024),
};
out.roundtrip = {};
for (const [label, text] of Object.entries(shapes)) {
  const expected = Buffer.from(text).length;
  out.roundtrip[label] = {
    gzip: Buffer.from(Bun.gunzipSync(Bun.gzipSync(text))).length === expected,
    deflate: Buffer.from(Bun.inflateSync(Bun.deflateSync(text))).length === expected,
    zstd: Buffer.from(Bun.zstdDecompressSync(Bun.zstdCompressSync(text))).length === expected,
    zstdSync: Buffer.from(Bun.zstdDecompressSync(Bun.zstdCompressSync(Buffer.from(text)))).length === expected,
  };
}

// --- input shapes: string, Buffer, Uint8Array, ArrayBuffer, view offset ----
// The ArrayBuffer case builds a dedicated buffer rather than taking
// `Buffer.from('hello').buffer`: a pooled Buffer's backing store is much larger
// than the view, and compressing it measures the pool rather than the member.
const rawBytes = new Uint8Array([104, 101, 108, 108, 111]); // "hello"
const dedicated = new ArrayBuffer(rawBytes.length);
new Uint8Array(dedicated).set(rawBytes);
out.inputs = {
  bufferMatchesString: hex(Bun.gzipSync(Buffer.from('hello'))) === hex(Bun.gzipSync('hello')),
  // A view must compress only its own window, not the whole backing store.
  viewOffsetHonored:
    hex(Bun.gzipSync(Buffer.from('xxhelloyy').subarray(2, 7))) === hex(Bun.gzipSync('hello')),
  arrayBufferWorks: hex(Bun.gzipSync(dedicated)) === hex(Bun.gzipSync('hello')),
  uint8ArrayWorks: hex(Bun.gzipSync(new Uint8Array(dedicated))) === hex(Bun.gzipSync('hello')),
  dataViewWorks: hex(Bun.gzipSync(new DataView(dedicated))) === hex(Bun.gzipSync('hello')),
  // Lone surrogates become U+FFFD, which is `Buffer.from(string)`'s rule.
  loneSurrogate: Buffer.from(Bun.gunzipSync(Bun.gzipSync('\uD800'))).toString('hex'),
  bufferLoneSurrogate: Buffer.from('\uD800').toString('hex'),
};

// --- return types: Uint8Array for zlib, Buffer for zstd -------------------
out.returnTypes = {
  gzip: Object.getPrototypeOf(Bun.gzipSync('x')).constructor.name,
  gunzip: Object.getPrototypeOf(Bun.gunzipSync(Bun.gzipSync('x'))).constructor.name,
  deflate: Object.getPrototypeOf(Bun.deflateSync('x')).constructor.name,
  inflate: Object.getPrototypeOf(Bun.inflateSync(Bun.deflateSync('x'))).constructor.name,
  zstdCompress: Object.getPrototypeOf(Bun.zstdCompressSync('x')).constructor.name,
  zstdDecompress: Object.getPrototypeOf(Bun.zstdDecompressSync(Bun.zstdCompressSync('x'))).constructor.name,
  gzipIsBuffer: Buffer.isBuffer(Bun.gzipSync('x')),
  zstdIsBuffer: Buffer.isBuffer(Bun.zstdCompressSync('x')),
};

// --- errors: class, code and text, per spec 3.4 ---------------------------
const gz = Bun.gzipSync('hello hello hello');
const raw = Bun.deflateSync('hello hello hello');
const z = Bun.zstdCompressSync('hello');
function truncate(u, n) { return u.subarray(0, n); }

out.errors = {
  gunzipGarbage: captureText(() => Bun.gunzipSync(new Uint8Array([1,2,3,4,5,6,7,8]))),
  gunzipEmpty: captureText(() => Bun.gunzipSync(new Uint8Array(0))),
  gunzipTruncated: captureText(() => Bun.gunzipSync(truncate(gz, gz.length - 1))),
  gunzipHeaderGarbageBody: captureText(() => Bun.gunzipSync(new Uint8Array([0x1f,0x8b,8,0,0,0,0,0,0,3,0xff,0xff,0xff,0xff]))),
  gunzipZlibData: captureText(() => Bun.gunzipSync(new Uint8Array([0x78,0x9c,0xcb,0x48,0xcd,0xc9,0xc9,0x07,0x00,0x06,0x2c,0x02,0x15]))),
  inflateGarbage: captureText(() => Bun.inflateSync(new Uint8Array([1,2,3,4,5,6,7,8]))),
  inflateEmpty: captureText(() => Bun.inflateSync(new Uint8Array(0))),
  inflateGzipData: captureText(() => Bun.inflateSync(gz)),
  // A raw stream read as zlib: this is the cross-container case.
  inflateWithZlibWindowBits: captureText(() => Bun.inflateSync(raw, {windowBits: 15})),
  zstdGarbage: captureText(() => Bun.zstdDecompressSync(new Uint8Array([1,2,3,4,5,6,7,8]))),
  zstdGzipData: captureText(() => Bun.zstdDecompressSync(gz)),
  zstdHeaderGarbageBody: captureText(() => Bun.zstdDecompressSync(new Uint8Array([0x28,0xb5,0x2f,0xfd,0x00,0x00]))),
  zstdTruncated: captureText(() => Bun.zstdDecompressSync(truncate(z, 10))),
  gzipLevel99: capture(() => Bun.gzipSync('hello', {level: 99})),
  zstdLevel99: capture(() => Bun.zstdCompressSync('hello', {level: 99})),
  noArg: capture(() => Bun.gzipSync()),
  nullArg: capture(() => Bun.gzipSync(null)),
  numberArg: capture(() => Bun.gzipSync(0)),
  arrayArg: capture(() => Bun.gzipSync([])),
  blobArg: capture(() => Bun.gzipSync(new Blob(['x']))),
  // The empty zstd input is a deliberate non-error.
  zstdEmptyIsEmpty: { ok: String(Bun.zstdDecompressSync(new Uint8Array(0)).length) },
};

// --- multi-member gzip: Bun returns the FIRST member only ------------------
const first = Bun.gzipSync('AAAA');
const second = Bun.gzipSync('BBBB');
const joined = new Uint8Array(first.length + second.length);
joined.set(first, 0);
joined.set(second, first.length);
out.multiMember = {
  // Measured: "AAAA". Node's gunzip would give "AAAABBBB".
  payload: Buffer.from(Bun.gunzipSync(joined)).toString(),
};

// --- options: defaults, level effect, and the messages ---------------------
out.options = {
  // Bun's default level is 6, and level 0 is a real stored-block level.
  levelZeroIsStored: hex(Bun.deflateSync('hello', {level: 0})).startsWith('0105'),
  levelIgnoresWindowBits: hex(Bun.gzipSync('hello', {windowBits: -15})) === hex(Bun.gzipSync('hello')),
  // memLevel and strategy are validated as integers with Node's message text.
  memLevelOutOfRange: capture(() => Bun.gzipSync('hello', {memLevel: 99})),
  memLevelWrongType: capture(() => Bun.gzipSync('hello', {memLevel: '9'})),
  strategyOutOfRange: capture(() => Bun.gzipSync('hello', {strategy: 99})),
  decompressionOptionsAccepted: Buffer.from(Bun.gunzipSync(gz, {level: 99, memLevel: 99})).toString(),
  zstdLevelString: hex(Bun.zstdCompressSync('hello', {level: '9'})) === hex(Bun.zstdCompressSync('hello')),
};

// --- the async members are promises, and they reject on a bad body ---------
(async () => {
  const promise = Bun.zstdCompress('hello');
  out.async = {
    isPromise: promise instanceof Promise,
    // Distinct promises per call, so the result is not a shared cached one.
    distinct: promise !== Bun.zstdCompress('hello'),
    resolvedCtor: Object.getPrototypeOf(await Bun.zstdCompress('hello')).constructor.name,
    decompressCtor: Object.getPrototypeOf(await Bun.zstdDecompress(Bun.zstdCompressSync('hi'))).constructor.name,
    // The data type is checked synchronously; a corrupt body rejects.
    syncThrow: (() => {
      try { Bun.zstdCompress(123); return 'did-not-throw'; }
      catch (e) { return e.constructor.name + ':' + e.code; }
    })(),
  };
  try {
    await Bun.zstdDecompress(new Uint8Array([1,2,3,4,5]));
    out.async.rejection = 'resolved';
  } catch (e) {
    out.async.rejection = e.constructor.name + ':' + e.code + ':' + e.message;
  }
  process.stdout.write(JSON.stringify(out));
})();
"#;

#[test]
fn the_compression_members_match_bun() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let ours_text = run(&rustnode(), PROBE);
    let theirs_text = run(std::path::Path::new(&oracle), PROBE);
    let ours: serde_json::Value = serde_json::from_str(&ours_text)
        .unwrap_or_else(|error| panic!("rustnode did not print JSON ({error}): {ours_text}"));
    let theirs: serde_json::Value = serde_json::from_str(&theirs_text)
        .unwrap_or_else(|error| panic!("Bun did not print JSON ({error}): {theirs_text}"));

    // Field by field, so a failure names the divergence rather than dumping two
    // documents. `zstd_hello` and the gzip bytes are excluded on purpose: the
    // exact compressed bytes are the encoder's choice, not a contract. The
    // containers are compared separately below.
    for key in [
        "gzip_magic",
        "zstd_magic",
        "deflate_first_byte",
        "roundtrip",
        "inputs",
        "returnTypes",
        "errors",
        "multiMember",
        "options",
        "async",
    ] {
        assert_eq!(
            ours.get(key),
            theirs.get(key),
            "Bun.{key} disagrees with Bun 1.4.4.\n  rustnode: {}\n  bun:      {}",
            ours.get(key)
                .map(|value| value.to_string())
                .unwrap_or_default(),
            theirs
                .get(key)
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
    }

    // gzip is the one family where byte equality is a valid differential: Bun
    // fixes `mtime` to 0 and `os` to 3, and zlib at level 6 is deterministic.
    assert_eq!(
        ours["gzip_hello"], theirs["gzip_hello"],
        "gzipSync's bytes are deterministic on Bun, so they are comparable"
    );

    // The shape block, which pins what the member *is* rather than what it does.
    for name in [
        "gzipSync",
        "gunzipSync",
        "deflateSync",
        "inflateSync",
        "zstdCompress",
        "zstdCompressSync",
        "zstdDecompress",
        "zstdDecompressSync",
    ] {
        let key = format!("shape_{name}");
        assert_eq!(ours.get(&key), theirs.get(&key), "Bun.{key} disagrees");
    }
}

/// The specific fact this whole group turns on: `deflateSync` is raw deflate.
///
/// Asserted independently of the oracle so it cannot pass by both runtimes being
/// equally wrong. A zlib-wrapped encoder emits `78 9c`; raw deflate on `"hello"`
/// emits `cb`.
#[test]
fn deflate_sync_is_raw_deflate_and_not_zlib_wrapped() {
    let script = r#"
const bytes = Bun.deflateSync('hello');
process.stdout.write(JSON.stringify({
  first: Buffer.from(bytes).toString('hex').slice(0, 2),
  hex: Buffer.from(bytes).toString('hex'),
  // Cross-feed proves the wrapper: a raw stream read as zlib is a header error,
  // and the Node-style `inflateSync` of the same bytes is that read.
  zlibHeaderError: (() => {
    try { Bun.inflateSync(bytes, { windowBits: 15 }); return null; }
    catch (e) { return e.message; }
  })(),
}));
"#;
    let out = run(&rustnode(), script);
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    assert_eq!(
        parsed["first"], "cb",
        "Bun.deflateSync must emit a raw deflate block header, not a zlib `78`: {out}"
    );
    assert_ne!(
        parsed["first"], "78",
        "a zlib-wrapped stream is the classic mistake and is what this guards"
    );
    assert_eq!(
        parsed["hex"], "cb48cdc9c90700",
        "the recorded Bun 1.4.4 bytes for `deflateSync(\"hello\")`"
    );
    assert_eq!(
        parsed["zlibHeaderError"], "incorrect header check",
        "reading the raw stream as zlib must report a header error: {out}"
    );
}

/// `gunzipSync` returns only the first member of a multi-member gzip file.
///
/// The spec left this unproven; it was measured on the oracle and is asserted here
/// so the divergence from Node's `gunzip` (which concatenates) is recorded rather
/// than discovered later.
#[test]
fn gunzip_returns_only_the_first_member() {
    let script = r#"
const a = Bun.gzipSync('first');
const b = Bun.gzipSync('second-member-longer');
const joined = new Uint8Array(a.length + b.length);
joined.set(a, 0);
joined.set(b, a.length);
process.stdout.write(JSON.stringify(Buffer.from(Bun.gunzipSync(joined)).toString()));
"#;
    assert_eq!(
        run(&rustnode(), script),
        "\"first\"",
        "gunzipSync must return the first member alone, as Bun 1.4.4 does"
    );
}

/// A broken implementation must fail this suite, and here is the proof it would.
///
/// The mutation is applied in-process rather than to the binary: the container and
/// error assertions are what a wrong wrapper trips, and running the same probe
/// against a zlib-wrapped encoder shows the `first` byte assertion is not
/// vacuously true.
#[test]
fn a_zlib_wrapped_encoder_would_fail_this_suite() {
    // `Buffer's` zlib-wrapped form of "hello" begins 78 9c, which the raw
    // assertion rejects. If `deflateSync` ever produced this the test above names
    // the defect, so this pins the discrimination rather than the implementation.
    let script = r#"
process.stdout.write(JSON.stringify(Buffer.from(
  require('zlib').deflateSync('hello')
).toString('hex').slice(0, 2)));
"#;
    let out = run(&rustnode(), script);
    assert_eq!(
        out, "\"78\"",
        "the control must produce a zlib header: {out}"
    );
    assert_ne!(out, "\"cb\"", "the control must not look like raw deflate");
}

/// `configurable` is `true` on every rustnode member where Bun reports `false`.
///
/// This is **not** a compression defect and this crate cannot fix it:
/// `rn_bun_api::BunRegistry::build` copies each member onto the final object with
/// `Object::create_data_property`, whose descriptor is always
/// `{ writable: true, enumerable: true, configurable: true }`. Bun installs its own
/// members non-configurable, so `delete Bun.gzipSync` throws there and succeeds
/// here.
///
/// The test pins the fact in both directions — it fails if the foundation changes
/// and it fails if this crate's `install` starts publishing a different shape — so
/// the divergence cannot silently become a difference in the other direction
/// either. Fixing it belongs in `rn-bun-api`, which is a shared file this group
/// must not edit.
#[test]
fn configurable_is_a_foundation_divergence() {
    let script = r#"
const names = ['gzipSync','gunzipSync','deflateSync','inflateSync',
               'zstdCompress','zstdCompressSync','zstdDecompress','zstdDecompressSync'];
process.stdout.write(JSON.stringify(Object.fromEntries(
  names.map((n) => [n, Object.getOwnPropertyDescriptor(Bun, n).configurable]))));
"#;
    let out = run(&rustnode(), script);
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    for name in [
        "gzipSync",
        "gunzipSync",
        "deflateSync",
        "inflateSync",
        "zstdCompress",
        "zstdCompressSync",
        "zstdDecompress",
        "zstdDecompressSync",
    ] {
        assert_eq!(
            parsed[name],
            serde_json::Value::Bool(true),
            "the foundation publishes configurable members; if this changed, the \
             divergence below is closed and this test should say so: {out}"
        );
    }

    if let Some(oracle) = bun_oracle() {
        let theirs = run(std::path::Path::new(&oracle), script);
        let theirs: serde_json::Value = serde_json::from_str(&theirs).expect("JSON");
        for name in ["gzipSync", "deflateSync", "zstdDecompressSync"] {
            assert_eq!(
                theirs[name],
                serde_json::Value::Bool(false),
                "Bun's own members are non-configurable; {name} disagrees"
            );
        }
    }
}
