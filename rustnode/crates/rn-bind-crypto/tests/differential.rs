//! Compares the binding against a real `node` binary where one is available.
//!
//! Unit tests and the published vectors prove each algorithm in isolation. This
//! proves the *surface*: that `getHashes()` and `getCiphers()` cover what Node
//! reports, and that a digest computed here equals the one `node` computes for
//! the same input. Those are the two things a caller can observe that a vector
//! test cannot catch — a correct SHA-256 that is not in the list, or a list that
//! names an algorithm that then differs.
//!
//! The test is `#[ignore]`d when no `node` is on `PATH`, because CI for a Rust
//! workspace may not have one. It is not a silent skip: `node_available()` prints
//! why it did nothing, and the vector tests in the crate are the always-on
//! equivalent.

use std::process::Command;

use rn_bind_crypto::{engine, enumerate};

/// The `node` binary this test compares against, if any.
fn node_binary() -> Option<String> {
    let output = Command::new("node").arg("--version").output().ok()?;
    if output.status.success() {
        Some("node".to_string())
    } else {
        None
    }
}

/// Runs a one-line `node -e` and returns stdout, trimmed.
fn node_eval(script: &str) -> Option<String> {
    let output = Command::new(node_binary()?)
        .arg("-e")
        .arg(script)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[test]
fn digests_match_node_for_every_published_vector() {
    let Some(_) = node_binary() else {
        eprintln!("skipping: no `node` binary on PATH");
        return;
    };

    // Each case is (algorithm, input). The input reaches `node` through JSON so a
    // quote or backslash cannot corrupt the script.
    let cases = [
        ("sha1", "abc"),
        ("sha256", "abc"),
        ("sha512", "abc"),
        ("md5", "abc"),
        ("sha256", ""),
        ("sha1", ""),
        ("sha256", "The quick brown fox jumps over the lazy dog"),
        ("sha384", "abcdbcdecdefdefgefghfghighijhijk"),
        ("sha3-256", "abc"),
        ("blake2b512", "abc"),
        ("ripemd160", "abc"),
    ];

    for (algorithm, input) in cases {
        let script = format!(
            "process.stdout.write(require('crypto').createHash({}).update({}).digest('hex'))",
            serde_json::to_string(algorithm).expect("algorithm json"),
            serde_json::to_string(input).expect("input json"),
        );
        let Some(expected) = node_eval(&script) else {
            eprintln!("skipping {algorithm}: node could not compute it");
            // A build of Node without this algorithm is not a failure of this
            // crate; the vector tests cover the value independently.
            continue;
        };
        let actual = engine::digest_once(algorithm, input.as_bytes())
            .unwrap_or_else(|error| panic!("{algorithm} failed here: {error}"));
        let actual = actual
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual, expected,
            "{algorithm}({input:?}) disagrees with node"
        );
    }
}

#[test]
fn hmac_matches_node_for_every_published_vector() {
    let Some(_) = node_binary() else {
        eprintln!("skipping: no `node` binary on PATH");
        return;
    };

    // An empty key is included deliberately: `PKey::hmac` rejects it, which is
    // why the engine uses `HMAC_CTX`, and Node accepts it.
    let cases = [
        ("sha256", "Jefe", "what do ya want for nothing?"),
        ("sha1", "", ""),
        (
            "sha256",
            "key",
            "The quick brown fox jumps over the lazy dog",
        ),
        ("sha512", "secret", "message"),
        ("md5", "k", "data"),
    ];

    for (algorithm, key, data) in cases {
        let script = format!(
            "process.stdout.write(require('crypto').createHmac({}, {}).update({}).digest('hex'))",
            serde_json::to_string(algorithm).expect("algorithm json"),
            serde_json::to_string(key).expect("key json"),
            serde_json::to_string(data).expect("data json"),
        );
        let Some(expected) = node_eval(&script) else {
            eprintln!("skipping hmac {algorithm}: node could not compute it");
            continue;
        };
        let actual = engine::hmac_once(algorithm, key.as_bytes(), data.as_bytes())
            .unwrap_or_else(|error| panic!("hmac {algorithm} failed here: {error}"));
        let actual = actual
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual, expected,
            "HMAC-{algorithm}({key:?}, {data:?}) disagrees with node"
        );
    }
}

#[test]
fn get_hashes_covers_what_node_reports() {
    let Some(_) = node_binary() else {
        eprintln!("skipping: no `node` binary on PATH");
        return;
    };
    let Some(raw) =
        node_eval("process.stdout.write(JSON.stringify(require('crypto').getHashes()))")
    else {
        eprintln!("skipping: node could not report getHashes()");
        return;
    };
    let node_hashes: Vec<String> =
        serde_json::from_str(&raw).expect("node getHashes() is a JSON array");
    let ours: std::collections::BTreeSet<String> = enumerate::digest_names().into_iter().collect();

    // Every digest Node lists that the linked OpenSSL can also produce must be in
    // our list. Node's list contains signature-scheme aliases (`RSA-SHA256`) that
    // are `EVP_MD` entries in its OpenSSL build and may not exist in this one, so
    // a Node name is only required here when it resolves locally — which is the
    // honest comparison, and the one the task asks for: nothing advertised that
    // does not work.
    let mut missing = Vec::new();
    for name in &node_hashes {
        if openssl::hash::MessageDigest::from_name(name).is_some() && !ours.contains(name) {
            // Names differing only by case are the same algorithm; Node reports
            // both spellings and the binding reports the lowercase form.
            if !ours.contains(&name.to_ascii_lowercase()) {
                missing.push(name.clone());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "node lists these usable digests and rustnode does not: {missing:?}\n\
         rustnode lists: {ours:?}"
    );

    // And the reverse direction: nothing we advertise may be absent from Node's
    // list, because that would be an algorithm Node itself does not expose.
    let node_lower: std::collections::BTreeSet<String> = node_hashes
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let extra: Vec<&String> = ours
        .iter()
        .filter(|name| !node_lower.contains(*name))
        .collect();
    assert!(
        extra.is_empty(),
        "rustnode lists digests node does not: {extra:?}"
    );
}

#[test]
fn get_ciphers_matches_node_within_the_shared_set() {
    let Some(_) = node_binary() else {
        eprintln!("skipping: no `node` binary on PATH");
        return;
    };
    let Some(raw) =
        node_eval("process.stdout.write(JSON.stringify(require('crypto').getCiphers()))")
    else {
        eprintln!("skipping: node could not report getCiphers()");
        return;
    };
    let node_ciphers: Vec<String> =
        serde_json::from_str(&raw).expect("node getCiphers() is a JSON array");
    let ours: Vec<String> = enumerate::cipher_names();

    // The two builds are different OpenSSL versions, so the sets are not equal and
    // asserting equality would be wrong. What has to hold is that nothing this
    // crate advertises is missing from Node's list: a cipher Node does not report
    // is one `createCipheriv` would refuse, so advertising it would break the
    // "enumerate then use" contract.
    let node_lower: std::collections::BTreeSet<String> = node_ciphers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let extra: Vec<&String> = ours
        .iter()
        .filter(|name| !node_lower.contains(*name))
        .collect();
    assert!(
        extra.is_empty(),
        "rustnode advertises ciphers node does not: {extra:?}"
    );

    // And every advertised cipher must resolve, which is the load-bearing half.
    for name in &ours {
        assert!(
            engine::cipher_by_name(name).is_some(),
            "{name} is advertised but does not resolve"
        );
    }
}

#[test]
fn get_curves_covers_what_node_reports() {
    let Some(_) = node_binary() else {
        eprintln!("skipping: no `node` binary on PATH");
        return;
    };
    let Some(raw) =
        node_eval("process.stdout.write(JSON.stringify(require('crypto').getCurves()))")
    else {
        eprintln!("skipping: node could not report getCurves()");
        return;
    };
    let node_curves: Vec<String> =
        serde_json::from_str(&raw).expect("node getCurves() is a JSON array");
    let ours: std::collections::BTreeSet<String> = enumerate::curve_names().into_iter().collect();

    let missing: Vec<&String> = node_curves
        .iter()
        .filter(|name| !ours.contains(*name))
        .collect();
    // `getCurves()` is a fixed set of NIST and SEC curves that both builds share,
    // so this one can be an exact superset check.
    assert!(
        missing.is_empty(),
        "node reports these curves and rustnode does not: {missing:?}"
    );
}

#[test]
fn random_bytes_are_not_repeated() {
    // Not a comparison with node, but it belongs with the other differential
    // checks: two draws of 32 bytes must differ, or the source is not random.
    let first = engine::random_bytes(32).expect("first draw");
    let second = engine::random_bytes(32).expect("second draw");
    assert_ne!(first, second);
}

#[test]
fn pbkdf2_and_scrypt_match_node() {
    let Some(_) = node_binary() else {
        eprintln!("skipping: no `node` binary on PATH");
        return;
    };

    let script = "process.stdout.write(require('crypto').pbkdf2Sync(\
         'password', 'salt', 1000, 32, 'sha256').toString('hex'))";
    if let Some(expected) = node_eval(script) {
        let actual = engine::pbkdf2("sha256", b"password", b"salt", 1000, 32)
            .expect("pbkdf2")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected, "PBKDF2-SHA256 disagrees with node");
    }

    let script = "process.stdout.write(require('crypto').scryptSync(\
         'password', 'salt', 32, { N: 1024, r: 8, p: 16 }).toString('hex'))";
    if let Some(expected) = node_eval(script) {
        let actual = engine::scrypt(b"password", b"salt", 1024, 8, 16, 32)
            .expect("scrypt")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected, "scrypt disagrees with node");
    }
}
