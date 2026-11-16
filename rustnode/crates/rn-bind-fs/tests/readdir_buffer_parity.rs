//! `readdir`'s buffer encoding against the pinned Node oracle.
//!
//! # The defect this pins
//!
//! `fs.readdirSync(dir, { encoding: 'buffer' })` must return an array of real
//! `Buffer`s, not bare `Uint8Array`s. The distinction is not cosmetic:
//! `lib/internal/fs/utils.js`'s `join` branches on
//! `isUint8Array(path) && isUint8Array(name)` and then calls `Buffer.concat`,
//! which throws `TypeError: "list[0]" argument must be an instance of Buffer` on
//! a view that is not one. So with a `Uint8Array` the names are unusable for the
//! exact purpose the encoding exists for — joining them to their directory — even
//! though `ArrayBuffer.isView` said yes.
//!
//! `Buffer.isBuffer` is therefore the assertion, and it has to be made against a
//! runtime that has a real `Buffer` global. The in-process harness
//! (`tests/js_contract.rs`) installs a `Buffer` shim because it does not
//! bootstrap `lib/`, so it proves the binding consults `globalThis.Buffer` but not
//! that the value it produces passes Node's own `isBuffer`. These cases spawn the
//! binary for that reason.
//!
//! # Both directions
//!
//! A `Uint8Array` and a `Buffer` are both array-buffer views, so a test that only
//! asserted "it is a view with the right bytes" would have passed against the
//! defect. The assertions below separate the three facts that distinguish them:
//! `Buffer.isBuffer`, `Buffer.concat` accepting the value, and the constructor
//! name.

use std::path::PathBuf;
use std::process::Command;

/// The CLI binary this workspace builds.
///
/// `CARGO_BIN_EXE_rustnode` is only defined inside `rn-cli`'s own test targets, so
/// this workspace's binary is found relative to this crate. Both profiles are
/// accepted, and a missing binary makes the case skip rather than fail so
/// `cargo test -p rn-bind-fs` alone still works on a tree that never built the
/// CLI.
fn binary() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .to_path_buf();
    ["debug", "release"]
        .into_iter()
        .map(|profile| root.join("target").join(profile).join("rustnode"))
        .find(|path| path.exists())
}

fn oracle() -> Option<&'static rn_node_oracle::Oracle> {
    static ORACLE: std::sync::OnceLock<Option<rn_node_oracle::Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-bind-fs readdir buffer parity"))
        .as_ref()
}

fn run(program: &str, script: &str) -> String {
    let output = Command::new(program)
        .arg("-e")
        .arg(script)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} failed: {}\nscript: {script}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// A scratch directory whose entries have distinct names and lengths.
///
/// The names are deliberately not all one byte long: a buffer built with the
/// wrong length would otherwise still compare equal, and `Buffer.concat` would
/// not notice.
fn fixture() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "rn-readdir-buffer-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("mkdir");
    for name in ["a", "bb", "ccc", "Zebra"] {
        std::fs::write(root.join(name), b"").expect("write");
    }
    root
}

/// The facts that distinguish a `Buffer` from a `Uint8Array`.
const PROBE: &str = r#"
function probe(dir) {
  const fs = require('fs');
  const out = {};
  const syncNames = fs.readdirSync(dir, { encoding: 'buffer' });
  out.syncCount = syncNames.length;
  out.syncAllBuffers = syncNames.every((name) => Buffer.isBuffer(name));
  out.syncAllViews = syncNames.every((name) => ArrayBuffer.isView(name));
  out.syncConstructors = syncNames.map((name) => name.constructor.name);
  // The purpose the encoding exists for: joining a name to its directory. This
  // is the call that threw while the names were bare `Uint8Array`s.
  out.syncJoined = syncNames.every((name) => {
    try {
      Buffer.concat([Buffer.from(dir + '/'), name]);
      return true;
    } catch (error) {
      return error.constructor.name + ': ' + error.message;
    }
  });
  const rec = fs.readdirSync(dir, { encoding: 'buffer', recursive: true });
  out.recursiveAllBuffers = rec.every((name) => Buffer.isBuffer(name));
  out.recursiveTexts = rec.map((name) => name.toString());
  return out;
}
"#;

#[test]
fn readdir_with_a_buffer_encoding_returns_buffers_like_node() {
    let (Some(oracle), Some(binary)) = (oracle(), binary()) else {
        eprintln!("skipping: no pinned Node oracle or no rustnode binary");
        return;
    };
    let root = fixture();
    let dir = root.to_string_lossy().replace('\\', "\\\\");

    // The synchronous form.
    let sync = format!("{PROBE}\nconsole.log(JSON.stringify(probe('{dir}')));");
    let expected = run(oracle.reference_path(), &sync);
    let actual = run(binary.to_string_lossy().as_ref(), &sync);
    assert_eq!(
        actual,
        expected,
        "the buffer-encoded names differ from {}",
        oracle.describe()
    );
    // And the oracle's own answer is the one the finding describes, so a future
    // Node that changed it would show up here rather than silently redefining
    // what this test proves.
    assert!(
        expected.contains("\"syncAllBuffers\":true"),
        "the oracle no longer returns Buffers: {expected}"
    );
    assert!(
        expected.contains("\"syncJoined\":true"),
        "the oracle cannot concat its own names: {expected}"
    );

    // The callback and promise forms go through the same binding but a different
    // argument path, so they are worth comparing separately.
    let asynchronous = format!(
        r#"{PROBE}
const dir = '{dir}';
require('fs').readdir(dir, {{ encoding: 'buffer' }}, (error, names) => {{
  if (error) throw error;
  require('fs').promises.readdir(dir, {{ encoding: 'buffer' }}).then((promised) => {{
    console.log(JSON.stringify({{
      callbackAllBuffers: names.every((name) => Buffer.isBuffer(name)),
      promiseAllBuffers: promised.every((name) => Buffer.isBuffer(name)),
      callbackTexts: names.sort().map((name) => name.toString()),
    }}));
  }});
}});
"#
    );
    let expected = run(oracle.reference_path(), &asynchronous);
    let actual = run(binary.to_string_lossy().as_ref(), &asynchronous);
    assert_eq!(
        actual,
        expected,
        "the asynchronous buffer encodings differ from {}",
        oracle.describe()
    );
    assert!(
        expected.contains("\"callbackAllBuffers\":true")
            && expected.contains("\"promiseAllBuffers\":true"),
        "the oracle no longer returns Buffers asynchronously: {expected}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A `Buffer`-encoded name has to survive being passed back to `fs`.
///
/// This is the end-to-end reason the encoding exists, and it is the assertion
/// that fails when the value is a bare `Uint8Array`: `fs.statSync` accepts a
/// `Buffer` path but throws `ERR_INVALID_ARG_TYPE` on a `Uint8Array`.
#[test]
fn a_buffer_encoded_name_is_usable_as_a_path() {
    let (Some(oracle), Some(binary)) = (oracle(), binary()) else {
        eprintln!("skipping: no pinned Node oracle or no rustnode binary");
        return;
    };
    let root = fixture();
    let dir = root.to_string_lossy().replace('\\', "\\\\");
    let script = format!(
        r#"
const fs = require('fs');
const path = require('path');
const dir = '{dir}';
const names = fs.readdirSync(dir, {{ encoding: 'buffer' }}).sort();
const out = {{}};
for (const name of names) {{
  const full = Buffer.concat([Buffer.from(dir + path.sep), name]);
  out[name.toString()] = {{ isBuffer: Buffer.isBuffer(full),
                            size: fs.statSync(full).size }};
}}
console.log(JSON.stringify(out));
"#
    );
    let expected = run(oracle.reference_path(), &script);
    let actual = run(binary.to_string_lossy().as_ref(), &script);
    assert_eq!(
        actual,
        expected,
        "a joined buffer path differs from {}",
        oracle.describe()
    );

    let _ = std::fs::remove_dir_all(&root);
}
