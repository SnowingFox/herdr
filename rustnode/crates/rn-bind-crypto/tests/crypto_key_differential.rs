//! Differential tests for the crypto key constants and the `isCryptoKey` brand.
//!
//! Two divergences motivated this file, and both are of the shape that unit tests
//! cannot catch on their own:
//!
//! * The `kKeyFormat*` and `kKeyType*` tables were numbered one past Node's, as
//!   the `kKeyEncoding*` table had been before them. Every round trip inside this
//!   runtime agreed with itself, so an accessor-level check passed; only the
//!   absolute numbers were wrong. They are an internal protocol between
//!   `lib/internal/crypto/**` and the binding, and `--expose-internals` reads
//!   them straight off `internalBinding('crypto')`, which is what makes them
//!   observable.
//! * `util.types.isCryptoKey` threw, because `isNativeCryptoKey` was absent from
//!   that namespace.
//!
//! # Why this is differential and not a recorded table
//!
//! A recorded table is a second copy of the numbers under test, so it agrees with
//! whatever the first copy says once someone edits both. These read the oracle's
//! own `internalBinding('crypto')` and compare against the binary under test, so
//! a wrong number on either side fails.
//!
//! # A missing oracle is a failure, not a skip
//!
//! This project has shipped differential tests that reported success while
//! asserting nothing, because they could not find the oracle and returned early.
//! `rn_node_oracle::require_oracle` still exists for tests where skipping is
//! honest, but it is deliberately not used here: these two findings are the whole
//! point of the file, and a run that does not compare them has not tested
//! anything. [`oracle`] panics when nothing resolves.

use std::path::PathBuf;
use std::process::Command;

use rn_node_oracle::Oracle;

/// The oracle, resolved once and required.
///
/// `require_oracle` is not used on purpose: it returns `None` for a missing
/// oracle and the caller is expected to skip. Here a missing oracle is a broken
/// environment, so it panics with the search locations.
fn oracle() -> &'static Oracle {
    static ORACLE: std::sync::OnceLock<Oracle> = std::sync::OnceLock::new();
    ORACLE.get_or_init(|| match rn_node_oracle::resolve() {
        Ok(oracle) => {
            eprintln!("crypto key differential: using {}", oracle.describe());
            oracle
        }
        Err(error) => panic!(
            "crypto key differential: no usable Node oracle: {error}. \
             This test compares rustnode against the pinned Node and cannot run \
             without it; run `./tools/fetch-node-oracle.sh` or set RN_NODE_ORACLE."
        ),
    })
}

/// The `rustnode` binary under test.
///
/// `CARGO_BIN_EXE_*` is only defined for the crate that owns the binary, and
/// `rn-bind-crypto` does not, so the path is derived from this crate's manifest
/// the way `rn-bind-glob`'s binary tests do. A missing binary is a failure here
/// for the same reason a missing oracle is: the comparison is the test.
///
/// Debug is preferred over release deliberately. `tools/check.sh` builds
/// `target/debug/rustnode` explicitly before the test sweep, and its
/// `cargo check --release` does *not* rebuild the release binary — so inside the
/// gate the debug artifact is the fresh one and a leftover release binary could be
/// arbitrarily old. Testing a stale runtime would be worse than not testing.
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
        "crypto key differential: no rustnode binary under {}. \
         Run `cargo build -p rn-cli` (or `-p rn-cli --release`) first; the \
         constants and isCryptoKey are only observable through the full runtime.",
        root.join("target").display()
    );
}

/// Runs a script through the binary under test and returns stdout, trimmed.
///
/// A non-zero exit is a defect in this test rather than a missing feature: the
/// script is written to succeed on any correct runtime, so a failure means the
/// runtime threw somewhere it should not have.
fn eval_rustnode(script: &str) -> String {
    let binary = rustnode();
    let output = Command::new(&binary)
        .arg("--expose-internals")
        .arg("-e")
        .arg(script)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        output.status.success(),
        "{} failed on this script:\n{script}\n\
         status: {}\nstderr: {}",
        binary.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// The Node flag both probes need.
///
/// `internalBinding('crypto')` is only reachable through
/// `internal/test/binding`, and that module is behind `--expose-internals` on
/// the Node side too. Running the oracle without it fails rather than reporting a
/// missing constant, which is why the flag is passed explicitly rather than left
/// to [`Oracle::eval`]'s default.
const EXPOSE_INTERNALS: &[&str] = &["--expose-internals"];

/// The script that prints every numeric constant on the crypto binding, sorted,
/// one `name=value` per line.
///
/// `--expose-internals` plus `internal/test/binding` is how both runtimes reach
/// `internalBinding('crypto')`; that is the observation point CLA-217 names.
const CONSTANTS_PROBE: &str = r#"
const { internalBinding } = require('internal/test/binding');
const binding = internalBinding('crypto');
const lines = [];
for (const name of Object.keys(binding).sort()) {
  if (typeof binding[name] === 'number') lines.push(name + '=' + binding[name]);
}
process.stdout.write(lines.join('\n'));
"#;

/// The script that prints `util.types.isCryptoKey` for one input, wrapped so a
/// throw is a value rather than a crash.
///
/// `describe` names the input so a mismatch says which case disagreed.
const IS_CRYPTO_KEY_PROBE_PRELUDE: &str = r#"
const crypto = require('crypto');
const { isCryptoKey } = require('util').types;
function answer(label, value) {
  let out;
  try {
    out = String(isCryptoKey(value));
  } catch (error) {
    out = 'THREW ' + (error.code || error.name) + ': ' + error.message;
  }
  return label + '=' + out;
}
const lines = [];
"#;

/// Runs an `isCryptoKey` probe, awaiting the async cases so `subtle.importKey`
/// settles before the script ends.
fn is_crypto_key_probe(body: &str) -> String {
    format!("{IS_CRYPTO_KEY_PROBE_PRELUDE}(async () => {{\n{body}\nprocess.stdout.write(lines.join('\\n'));\n}})();")
}

/// Parses `name=value` lines into a sorted map, failing on a malformed line.
fn parse_pairs(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once('=') else {
            panic!("probe line is not name=value: {line:?}");
        };
        out.push((name.to_string(), value.to_string()));
    }
    out
}

/// The key-constant tables this test pins, named explicitly so a rename on one
/// side is a failure rather than a silent disappearance from the comparison.
///
/// These are the six tables that were shifted one past Node's numbering plus the
/// ones that were already correct, because a table that is only checked when it
/// is known to be broken is not checked at all.
const PINNED_CONSTANTS: &[&str] = &[
    "kKeyEncodingPKCS1",
    "kKeyEncodingPKCS8",
    "kKeyEncodingSPKI",
    "kKeyEncodingSEC1",
    "kKeyFormatDER",
    "kKeyFormatPEM",
    "kKeyFormatJWK",
    "kKeyFormatRawPublic",
    "kKeyFormatRawPrivate",
    "kKeyFormatRawSeed",
    "kKeyFormatStore",
    "kKeyTypeSecret",
    "kKeyTypePublic",
    "kKeyTypePrivate",
    "kSigEncDER",
    "kSigEncP1363",
    "kSignJobModeSign",
    "kSignJobModeVerify",
    "kWebCryptoCipherEncrypt",
    "kWebCryptoCipherDecrypt",
    "kWebCryptoKeyFormatRaw",
    "kWebCryptoKeyFormatPKCS8",
    "kWebCryptoKeyFormatSPKI",
    "kWebCryptoKeyFormatJWK",
    "kCryptoJobAsync",
    "kCryptoJobSync",
    "kCryptoJobWebCrypto",
];

#[test]
fn every_key_constant_matches_the_oracle() {
    let oracle = oracle();

    let expected = parse_pairs(&oracle.eval_with_args(EXPOSE_INTERNALS, CONSTANTS_PROBE));
    let actual = parse_pairs(&eval_rustnode(CONSTANTS_PROBE));

    let expected: std::collections::BTreeMap<String, String> = expected.into_iter().collect();
    let actual: std::collections::BTreeMap<String, String> = actual.into_iter().collect();

    let mut problems = Vec::new();

    for name in PINNED_CONSTANTS {
        // A typo in this list must not pass by silently matching nothing.
        let Some(want) = expected.get(*name) else {
            problems.push(format!(
                "{name}: the oracle does not report this constant at all, so the \
                 name in PINNED_CONSTANTS is wrong"
            ));
            continue;
        };
        match actual.get(*name) {
            Some(got) if got == want => {}
            Some(got) => problems.push(format!(
                "{name}: rustnode reports {got}, oracle {} reports {want}",
                oracle.describe()
            )),
            None => problems.push(format!("{name}: rustnode does not install it at all")),
        }
    }

    assert!(
        problems.is_empty(),
        "crypto key constants disagree with the pinned Node:\n  {}\n\n{}",
        problems.join("\n  "),
        oracle.describe()
    );
}

/// The six inputs the finding names, in the assignment's order, plus the
/// `isKeyObject` answer for the same values.
///
/// The two `KeyObject` cases are the ones worth stating plainly: the oracle
/// reports **false** for them, because `createSecretKey` and `generateKeyPairSync`
/// return `KeyObject`s, which a separate native class brands. `isCryptoKey` is
/// the `CryptoKey` test, and `util.types.isKeyObject` is its counterpart. A
/// runtime that answers `true` here has confused the two classes.
///
/// `keyObject` is printed alongside `cryptoKey` on purpose. The two brands are
/// independent in Node but share machinery here, so a `CryptoKey` that carries
/// key data answers `isKeyObject === true` — a real regression this comparison
/// caught on the rebase, which is why both accessors are asked of both classes.
fn is_crypto_key_cases() -> String {
    is_crypto_key_probe(
        r#"
  const { isKeyObject } = require('util').types;
  function both(label, value) {
    lines.push(answer(label + '.isCryptoKey', value));
    let other;
    try { other = String(isKeyObject(value)); }
    catch (error) { other = 'THREW ' + (error.code || error.name) + ': ' + error.message; }
    lines.push(label + '.isKeyObject=' + other);
  }
  both('createSecretKey', crypto.createSecretKey(Buffer.alloc(16, 1)));
  const pair = crypto.generateKeyPairSync('ed25519');
  both('generateKeyPairSync.publicKey', pair.publicKey);
  both('generateKeyPairSync.privateKey', pair.privateKey);
  const imported = await crypto.subtle.importKey(
    'raw', Buffer.alloc(16, 2), { name: 'AES-CBC' }, true, ['encrypt']);
  both('subtle.importKey', imported);
  both('plainObject', {});
  both('null', null);
  both('keyObjectShaped', Object.create(crypto.KeyObject.prototype));
"#,
    )
}

#[test]
fn is_crypto_key_matches_the_oracle_on_every_input() {
    let oracle = oracle();
    let probe = is_crypto_key_cases();

    let expected = oracle.eval_with_args(EXPOSE_INTERNALS, &probe);
    let actual = eval_rustnode(&probe);

    let expected = parse_pairs(&expected);
    let actual = parse_pairs(&actual);

    assert_eq!(
        expected.len(),
        14,
        "the oracle probe produced {} lines, not the fourteen it should \
         (seven inputs times isCryptoKey and isKeyObject): {expected:?}",
        expected.len()
    );

    let mut problems = Vec::new();
    for ((name, want), (actual_name, got)) in expected.iter().zip(actual.iter()) {
        if name != actual_name {
            problems.push(format!(
                "the outputs are out of order: oracle produced {name}, rustnode {actual_name}"
            ));
            continue;
        }
        if want != got {
            problems.push(format!("{name}: rustnode {got}, oracle {want}"));
        }
    }
    if actual.len() != expected.len() {
        problems.push(format!(
            "rustnode produced {} lines, the oracle {}",
            actual.len(),
            expected.len()
        ));
    }

    assert!(
        problems.is_empty(),
        "util.types.isCryptoKey disagrees with the pinned Node:\n  {}\n\n{}\n\
         oracle table: {expected:?}\nrustnode table: {actual:?}",
        problems.join("\n  "),
        oracle.describe()
    );

    // The oracle's own answers, pinned literally as well. The comparison above is
    // the real check, but a runtime and an oracle that were both wrong in the same
    // way would pass it, and these are the facts the finding is about: a
    // `CryptoKey` is `isCryptoKey` and not `isKeyObject`, and a `KeyObject` is
    // the other way round.
    let table: std::collections::BTreeMap<&str, &str> = expected
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(table.get("subtle.importKey.isCryptoKey"), Some(&"true"));
    assert_eq!(table.get("subtle.importKey.isKeyObject"), Some(&"false"));
    assert_eq!(table.get("createSecretKey.isCryptoKey"), Some(&"false"));
    assert_eq!(table.get("createSecretKey.isKeyObject"), Some(&"true"));
    assert_eq!(table.get("null.isCryptoKey"), Some(&"false"));
    assert_eq!(table.get("keyObjectShaped.isCryptoKey"), Some(&"false"));
    // The impostor is neither: it borrows `KeyObject.prototype` and has no
    // native state, so both brands reject it.
    assert_eq!(table.get("keyObjectShaped.isKeyObject"), Some(&"false"));
}
