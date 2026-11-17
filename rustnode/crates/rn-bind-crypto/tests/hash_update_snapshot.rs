//! `Hash.update()` must snapshot the bytes it is given.
//!
//! # Why this exists
//!
//! `Hash.prototype.update` used to copy the whole input view into a `Vec` before
//! handing it to OpenSSL. That is correct but expensive: hashing a 94 MB `Buffer`
//! cost an extra 94 MB of peak RSS, and the `readFileSync` + `hash` combination
//! retained 1.68x what Node did even though each half was at parity on its own.
//! The copy was removed so the bytes are hashed straight out of the V8 backing
//! store, which is what Node's `Hash::Update` does.
//!
//! That fix rests on one property, and this file is what pins it: `update()`
//! consumes the bytes **synchronously, before it returns**. If a later change
//! defers any part of the consumption — a job, a queued task, a thread pool — the
//! caller can mutate the buffer in the meantime and the digest silently becomes
//! the hash of different bytes. The failure would be a wrong hash rather than a
//! slow one, so it needs a test that fails on the mutation, not one that only
//! compares two digests of the same input.
//!
//! # Both engines' terms
//!
//! The assertion is written against the oracle as well as this runtime. Node
//! answers `true` for "the digest did not change when I mutated the buffer after
//! `update()`", so a rustnode `true` matching an oracle `true` is the property,
//! rather than a rustnode-only expectation that could drift.

use std::path::PathBuf;
use std::process::Command;

use rn_node_oracle::Oracle;

fn oracle() -> &'static Oracle {
    static ORACLE: std::sync::OnceLock<Oracle> = std::sync::OnceLock::new();
    ORACLE.get_or_init(|| match rn_node_oracle::resolve() {
        Ok(oracle) => {
            eprintln!("hash update snapshot: using {}", oracle.describe());
            oracle
        }
        Err(error) => panic!(
            "hash update snapshot: no usable Node oracle: {error}. \
             This test compares rustnode against the pinned Node and cannot run \
             without it; run `./tools/fetch-node-oracle.sh` or set RN_NODE_ORACLE."
        ),
    })
}

/// The `rustnode` binary under test.
///
/// Derived from this crate's manifest because `rn-bind-crypto` does not own the
/// binary, so `CARGO_BIN_EXE_*` is not defined for it. Debug is preferred:
/// `tools/check.sh` builds `target/debug/rustnode` explicitly before the test
/// sweep, while a release artifact may be arbitrarily old.
fn rustnode() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("rn-bind-crypto lives two directories below the workspace root")
        .to_path_buf();
    for profile in ["debug", "release"] {
        let candidate = root.join("target").join(profile).join("rustnode");
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "hash update snapshot: no rustnode binary under {}. \
         Run `cargo build -p rn-cli` first; the mutation behaviour is only \
         observable through the full runtime.",
        root.join("target").display()
    );
}

fn eval_rustnode(script: &str) -> String {
    let binary = rustnode();
    let output = Command::new(&binary)
        .arg("-e")
        .arg(script)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        output.status.success(),
        "{} failed on this script:\n{script}\nstatus: {}\nstderr: {}",
        binary.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Hashes `buffer`, mutates it after `update()` returns, then digests.
///
/// Both engines run this exact source, so a difference in the answer is a
/// difference in the runtimes rather than in the two scripts.
///
/// The answer is JSON so a mismatch prints both the boolean and the digest it
/// settled on, which is what distinguishes "did not snapshot" from "hashed the
/// wrong bytes".
const SNAPSHOT_PROBE: &str = r#"
const crypto = require('crypto');
const buffer = Buffer.alloc(64, 1);
const hash = crypto.createHash('sha256');
hash.update(buffer);
// Every byte changes after `update()` returned. A hash that reads the buffer
// lazily would produce the digest of 64 bytes of 0x09 instead.
buffer.fill(9);
const mutated = hash.digest('hex');
const untouchedHash = crypto.createHash('sha256');
untouchedHash.update(Buffer.alloc(64, 1));
const untouched = untouchedHash.digest('hex');
process.stdout.write(JSON.stringify({
  snapshotHeld: mutated === untouched,
  mutated,
  untouched,
}));
"#;

/// `Hmac.update()` shares `Hash.prototype.update` in Node, so it must snapshot
/// too. It reaches a different native state here, so it gets its own probe
/// rather than being assumed to follow.
const HMAC_SNAPSHOT_PROBE: &str = r#"
const crypto = require('crypto');
const buffer = Buffer.alloc(64, 1);
const mac = crypto.createHmac('sha256', 'key');
mac.update(buffer);
buffer.fill(9);
const mutated = mac.digest('hex');
const untouchedMac = crypto.createHmac('sha256', 'key');
untouchedMac.update(Buffer.alloc(64, 1));
process.stdout.write(JSON.stringify({
  snapshotHeld: mutated === untouchedMac.digest('hex'),
  mutated,
}));
"#;

fn json_field(rendered: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":");
    let start = rendered.find(&needle)? + needle.len();
    let rest = &rendered[start..];
    let value: String = rest
        .chars()
        .take_while(|ch| *ch != ',' && *ch != '}')
        .collect();
    Some(value.trim().to_string())
}

fn assert_snapshots(probe: &str, label: &str) {
    let oracle = oracle();
    let expected = oracle.eval(probe);
    let actual = eval_rustnode(probe);

    // The oracle must hold the property, or the probe is not testing what it
    // claims and a rustnode failure would be ambiguous.
    assert_eq!(
        json_field(&expected, "snapshotHeld").as_deref(),
        Some("true"),
        "{label}: the oracle did not snapshot, so this probe proves nothing: {expected}"
    );
    assert_eq!(
        json_field(&actual, "snapshotHeld").as_deref(),
        Some("true"),
        "{label}: mutating the buffer after update() changed the digest. \
         update() must consume the bytes before it returns; a deferred consumer \
         makes this a wrong hash, not a slow one.\n\
         rustnode: {actual}\noracle:   {expected}"
    );

    let untouched = json_field(&actual, "untouched");
    let mutated = json_field(&actual, "mutated");
    if let (Some(untouched), Some(mutated)) = (untouched, mutated) {
        assert_eq!(
            untouched, mutated,
            "{label}: the digest followed the mutation; the bytes were read lazily"
        );
    }
}

#[test]
fn hash_update_snapshots_the_bytes_it_was_given() {
    assert_snapshots(SNAPSHOT_PROBE, "Hash.update");
}

#[test]
fn hmac_update_snapshots_the_bytes_it_was_given() {
    assert_snapshots(HMAC_SNAPSHOT_PROBE, "Hmac.update");
}

/// `update()` has to hash exactly the view's bytes, not the whole backing store.
///
/// A borrow reads through the same pointer arithmetic a copy did, so the risk a
/// zero-copy change introduces is reading `byteOffset..byteOffset + byteLength`
/// as `0..byteLength` — which would be wrong in a way that only offset views
/// expose. All three view shapes a caller can build over one buffer are compared
/// against the oracle rather than against recorded digests.
#[test]
fn offset_views_hash_their_own_range_like_the_oracle() {
    const PROBE: &str = r#"
const crypto = require('crypto');
const buffer = Buffer.alloc(256);
for (let i = 0; i < 256; i++) buffer[i] = i;
const hash = (value) => crypto.createHash('sha256').update(value).digest('hex');
process.stdout.write(JSON.stringify({
  full: hash(buffer),
  subarray: hash(buffer.subarray(100, 108)),
  typedArrayAtByteOffset: hash(new Uint8Array(buffer.buffer, buffer.byteOffset + 50, 16)),
  dataViewAtByteOffset: hash(new DataView(buffer.buffer, buffer.byteOffset + 32, 16)),
}));
"#;
    let expected = oracle().eval(PROBE);
    let actual = eval_rustnode(PROBE);
    for field in [
        "full",
        "subarray",
        "typedArrayAtByteOffset",
        "dataViewAtByteOffset",
    ] {
        assert_eq!(
            json_field(&actual, field),
            json_field(&expected, field),
            "offset view {field} hashed different bytes than the oracle\n\
             rustnode: {actual}\noracle:   {expected}"
        );
    }
}
