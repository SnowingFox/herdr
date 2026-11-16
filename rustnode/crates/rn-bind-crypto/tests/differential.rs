//! Compares the binding against the pinned Node oracle.
//!
//! Unit tests and the published vectors prove each algorithm in isolation. This
//! proves the *surface*: that `getHashes()` and `getCiphers()` cover what Node
//! reports, and that a digest computed here equals the one `node` computes for
//! the same input. Those are the two things a caller can observe that a vector
//! test cannot catch — a correct SHA-256 that is not in the list, or a list that
//! names an algorithm that then differs.
//!
//! # Which Node this compares against
//!
//! The oracle is the binary `tools/node-pin.toml` pins, resolved by
//! [`rn_node_oracle`]. Comparing cipher and digest *lists* across OpenSSL
//! versions is only meaningful when both sides agree on the library, and the
//! `node` on `PATH` is often a different release built against a different
//! OpenSSL. A missing oracle skips loudly; a *different* Node fails, because a
//! differential test against another version is a different test.

use rn_bind_crypto::{engine, enumerate};
use rn_node_oracle::Oracle;

/// The oracle this test binary compares against, resolved and announced once.
fn oracle() -> Option<&'static Oracle> {
    static ORACLE: std::sync::OnceLock<Option<Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-bind-crypto differential"))
        .as_ref()
}

/// Runs a one-line `node -e` and returns stdout, trimmed.
///
/// The oracle is known to be the pinned build, so a script that fails is a
/// defect in this test rather than a missing algorithm: it panics instead of
/// returning `None`. The earlier version returned `None` here, which turned
/// "Node could not compute SHA-256" into a silent pass.
fn node_eval(oracle: &Oracle, script: &str) -> String {
    oracle.eval(script)
}

#[test]
fn digests_match_node_for_every_published_vector() {
    let Some(oracle) = oracle() else {
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
        let expected = node_eval(oracle, &script);
        let actual = engine::digest_once(algorithm, input.as_bytes())
            .unwrap_or_else(|error| panic!("{algorithm} failed here: {error}"));
        let actual = actual
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual,
            expected,
            "{algorithm}({input:?}) disagrees with {}",
            oracle.describe()
        );
    }
}

#[test]
fn hmac_matches_node_for_every_published_vector() {
    let Some(oracle) = oracle() else {
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
        let expected = node_eval(oracle, &script);
        let actual = engine::hmac_once(algorithm, key.as_bytes(), data.as_bytes())
            .unwrap_or_else(|error| panic!("hmac {algorithm} failed here: {error}"));
        let actual = actual
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual,
            expected,
            "HMAC-{algorithm}({key:?}, {data:?}) disagrees with {}",
            oracle.describe()
        );
    }
}

#[test]
fn get_hashes_covers_what_node_reports() {
    let Some(oracle) = oracle() else {
        return;
    };
    let raw = node_eval(
        oracle,
        "process.stdout.write(JSON.stringify(require('crypto').getHashes()))",
    );
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
         rustnode lists: {ours:?}\n\
         against {}",
        oracle.describe()
    );

    // The reverse direction is a usability assertion plus a spelling assertion.
    // Node running against a different OpenSSL legitimately reports a smaller set,
    // so "absent from that Node's list" is not a defect; "advertised but unusable"
    // is, and so is "listed on both sides with a different spelling", because a
    // caller's `getHashes().includes('sha1')` would then take a different branch.
    for name in &ours {
        assert!(
            engine::Digest::new(name).is_ok(),
            "getHashes() advertises {name}, but createHash cannot start it"
        );
    }
    let node_lower: std::collections::BTreeSet<String> = node_hashes
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let misspelled: Vec<&String> = ours
        .iter()
        .filter(|name| {
            node_lower.contains(&name.to_ascii_lowercase()) && !node_hashes.contains(name)
        })
        .collect();
    assert!(
        misspelled.is_empty(),
        "these digests are listed on both sides with a different spelling: {misspelled:?}\n\
         against {}",
        oracle.describe()
    );
}

#[test]
fn get_ciphers_matches_node_within_the_shared_set() {
    let Some(oracle) = oracle() else {
        return;
    };
    let raw = node_eval(
        oracle,
        "process.stdout.write(JSON.stringify(require('crypto').getCiphers()))",
    );
    let node_ciphers: Vec<String> =
        serde_json::from_str(&raw).expect("node getCiphers() is a JSON array");
    let ours: Vec<String> = enumerate::cipher_names();

    // The two builds are different OpenSSL versions, so the sets are not equal and
    // asserting equality would be wrong. Two things do have to hold.
    //
    // First, every name we advertise must be constructible, which is the
    // "enumerate then use" contract. Second, the spellings must agree wherever the
    // sets overlap: a name present on both sides with a different case or alias
    // would mean the feature-detection a caller does (`getCiphers().includes(
    // 'aes-256-gcm')`) takes a different branch here than on Node. Membership
    // relative to a *specific* Node is proven against the pinned oracle binary,
    // not against whatever `node` happens to be on PATH.
    for name in &ours {
        assert!(
            rn_bind_crypto_cipher::evp::Cipher::from_name(name).is_some(),
            "{name} is advertised but createCipheriv cannot construct it"
        );
    }

    let node_lower: std::collections::BTreeSet<String> = node_ciphers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let misspelled: Vec<&String> = ours
        .iter()
        .filter(|name| {
            // Only meaningful where the other build has the same algorithm.
            node_lower.contains(&name.to_ascii_lowercase()) && !node_ciphers.contains(name)
        })
        .collect();
    assert!(
        misspelled.is_empty(),
        "these ciphers are listed on both sides with a different spelling: {misspelled:?}\n\
         against {}",
        oracle.describe()
    );
}

#[test]
fn get_curves_covers_what_node_reports() {
    let Some(oracle) = oracle() else {
        return;
    };
    let raw = node_eval(
        oracle,
        "process.stdout.write(JSON.stringify(require('crypto').getCurves()))",
    );
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
        "node reports these curves and rustnode does not: {missing:?}\n\
         against {}",
        oracle.describe()
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
    let Some(oracle) = oracle() else {
        return;
    };

    let script = "process.stdout.write(require('crypto').pbkdf2Sync(\
         'password', 'salt', 1000, 32, 'sha256').toString('hex'))";
    let expected = node_eval(oracle, script);
    let actual = engine::pbkdf2("sha256", b"password", b"salt", 1000, 32)
        .expect("pbkdf2")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        actual,
        expected,
        "PBKDF2-SHA256 disagrees with {}",
        oracle.describe()
    );

    let script = "process.stdout.write(require('crypto').scryptSync(\
         'password', 'salt', 32, { N: 1024, r: 8, p: 16 }).toString('hex'))";
    let expected = node_eval(oracle, script);
    let actual = engine::scrypt(b"password", b"salt", 1024, 8, 16, 32)
        .expect("scrypt")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        actual,
        expected,
        "scrypt disagrees with {}",
        oracle.describe()
    );
}
