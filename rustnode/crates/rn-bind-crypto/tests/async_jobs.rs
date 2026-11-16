//! The async job classes and the RSA cipher family, through the real binary.
//!
//! The unit tests in each crate cover the pieces; this file is the part they
//! cannot reach: that `lib/internal/crypto/random.js` and
//! `lib/internal/crypto/cipher.js` — unchanged Node code — find the members they
//! destructure, and that the asynchronous paths are *asynchronous*.
//!
//! # Why every case runs the real binary
//!
//! A job class installed in-process would test the installation, not the
//! protocol. The whole defect these cases exist for was that `randomFill`
//! constructs a `RandomBytesJob` unconditionally at `random.js:229`; only
//! running the vendored JavaScript can show that the constructor is reachable
//! from the call site that needed it.
//!
//! # Why the ordering cases are separate from the value cases
//!
//! A callback that fires with the right bytes before `randomBytes` returns is a
//! different bug from one that never fires. Both are real — the first is what an
//! inline "async" job produces — and a test that only checks the bytes cannot
//! tell them apart.
//!
//! `target/debug/rustnode` is built by `tools/check.sh` before the test sweep
//! precisely so these cases cannot read a stale binary. When it is absent they
//! skip rather than fail, so `cargo test -p rn-bind-crypto` alone still works.

use std::process::Command;

/// The CLI binary this workspace builds.
fn binary() -> Option<std::path::PathBuf> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .to_path_buf();
    let path = root.join("target").join("debug").join("rustnode");
    path.exists().then_some(path)
}

/// Runs a script and returns `(stdout, stderr, success)`.
fn run(script: &str) -> Option<(String, String, bool)> {
    let binary = binary()?;
    let output = Command::new(binary)
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary runs");
    Some((
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
        output.status.success(),
    ))
}

/// Runs a script that must print exactly `expected` and exit cleanly.
fn assert_prints(script: &str, expected: &str) {
    let Some((stdout, stderr, ok)) = run(script) else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "the script failed: {stderr}\nscript: {script}");
    assert_eq!(stdout, expected, "script: {script}\nstderr: {stderr}");
}

#[test]
fn random_bytes_with_a_callback_reaches_that_callback() {
    // The reported defect, verbatim: `randomFill` at `random.js:229` constructs
    // `new RandomBytesJob(kCryptoJobAsync, buf, offset, size)`, so before the
    // class existed every `randomBytes` with a callback threw
    // `TypeError: RandomBytesJob is not a constructor`.
    assert_prints(
        "require('crypto').randomBytes(8, (error, buffer) => \
         console.log(error === null ? 'ok ' + buffer.length : 'error ' + error.code));",
        "ok 8",
    );
}

#[test]
fn the_random_bytes_callback_does_not_fire_before_the_function_returns() {
    // Proving the callback is genuinely asynchronous. An implementation that
    // computed the fill inline and then called the callback would satisfy the
    // value check above and fail this one, which is exactly why a job that runs
    // its work on the threadpool has to be tested for ordering and not only for
    // output.
    assert_prints(
        "const crypto = require('crypto'); \
         let fired = false; \
         crypto.randomBytes(4, () => { fired = true; console.log('cb fired'); }); \
         console.log('returned, fired = ' + fired);",
        "returned, fired = false\ncb fired",
    );
}

#[test]
fn an_error_inside_the_job_reaches_the_callback_rather_than_throwing() {
    // A one-bit prime is `ERR_OSSL_BN_BITS_TOO_SMALL` from OpenSSL, raised on the
    // pool thread. It must arrive as `ondone`'s first argument: throwing from the
    // completion would be uncaught, because nothing above a libuv callback can
    // handle it.
    assert_prints(
        "const crypto = require('crypto'); \
         crypto.generatePrime(1, (error, prime) => \
           console.log(error ? error.code : 'no error', prime));",
        "ERR_OSSL_BN_BITS_TOO_SMALL undefined",
    );
}

#[test]
fn every_async_random_api_the_javascript_builds_a_job_for_works() {
    // `randomFill`, `randomInt`, `generatePrime` and `checkPrime` all go through
    // a `*Job`; `randomInt` is indirect, because its cache refill calls
    // `randomFill`. Each is checked for the shape `random.js` expects rather than
    // for a value, since the values are random.
    //
    // # Why the output is sorted before comparing
    //
    // These four jobs run on libuv's threadpool, so their callbacks fire in
    // *completion* order. Node's own ordering here is not deterministic either:
    // starting a slow `generatePrime` first still lets `randomFill` print ahead
    // of it, and sometimes `randomInt` overtakes `checkPrime`. Asserting a fixed
    // order would be asserting a property neither implementation has — and a
    // version of this test that passed would only have been passing because the
    // jobs completed fast enough to look sequential. Sorted, the comparison is
    // about which callbacks fired and with what, which is the real contract.
    let Some((stdout, stderr, ok)) = run("const crypto = require('crypto'); \
         crypto.randomFill(Buffer.alloc(4), (error, buffer) => \
           console.log('fill', error === null, buffer.length)); \
         crypto.randomInt(1, 10, (error, value) => \
           console.log('int', error === undefined, typeof value)); \
         crypto.generatePrime(64, (error, prime) => \
           console.log('prime', error === undefined, prime.byteLength, \
             prime.constructor.name)); \
         crypto.checkPrime(Buffer.from('ff', 'hex'), {}, (error, result) => \
           console.log('check', error === undefined, result));")
    else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(ok, "the script failed: {stderr}");
    let mut lines: Vec<&str> = stdout.lines().collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        vec![
            "check true false",
            "fill true 4",
            "int true number",
            "prime true 8 ArrayBuffer",
        ],
        "stderr: {stderr}"
    );
}

#[test]
fn the_synchronous_job_forms_still_return_their_tuples() {
    // `generatePrimeSync` and `checkPrimeSync` read `const { 0: err, 1: v } =
    // job.run()`, so `run()` has to return the tuple rather than a promise. Both
    // were also broken by the missing classes, which is why they are here.
    assert_prints(
        "const crypto = require('crypto'); \
         const prime = crypto.generatePrimeSync(16); \
         console.log('prime', prime.constructor.name, prime.byteLength); \
         console.log('check', crypto.checkPrimeSync(Buffer.from('ff', 'hex')));",
        "prime ArrayBuffer 2\ncheck false",
    );
}

#[test]
fn random_bytes_accepts_a_view_and_fills_only_that_range() {
    // `randomFill(buf.subarray(2, 5))` fills bytes 2..5 of the *view*, which is
    // the range `assertSize` validated. Validating against the backing store
    // instead would both reject this call and allow a range that runs into a
    // neighbouring view.
    assert_prints(
        "const crypto = require('crypto'); \
         const buffer = Buffer.alloc(8, 0xaa); \
         crypto.randomFill(buffer.subarray(2, 5), 0, 3, (error) => { \
           const hex = buffer.toString('hex'); \
           console.log(error, hex.slice(0, 4), hex.slice(10)); \
         });",
        "null aaaa aaaaaa",
    );
}

#[test]
fn the_four_rsa_cipher_members_are_installed_and_round_trip() {
    // `lib/internal/crypto/cipher.js` destructures all four at module scope, so a
    // missing one binds `undefined` and fails on the first call with
    // `TypeError: method is not a function`. The 2048-bit modulus fixes the
    // ciphertext at 256 bytes.
    assert_prints(
        "const crypto = require('crypto'); \
         const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', \
           { modulusLength: 2048 }); \
         const ciphertext = crypto.publicEncrypt(publicKey, Buffer.from('x')); \
         console.log('encrypt', ciphertext.length); \
         console.log('decrypt', crypto.privateDecrypt(privateKey, ciphertext).toString()); \
         const signed = crypto.privateEncrypt({ key: privateKey, \
           padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from('y')); \
         console.log('recover', crypto.publicDecrypt({ key: publicKey, \
           padding: crypto.constants.RSA_PKCS1_PADDING }, signed).toString());",
        "encrypt 256\ndecrypt x\nrecover y",
    );
}

#[test]
fn the_rsa_oaep_hash_and_label_are_honoured() {
    // OAEP's digest and label are two more arguments the same template reads,
    // and a label mismatch has to fail rather than produce the plaintext: that is
    // what makes the label part of the ciphertext's authentication.
    assert_prints(
        "const crypto = require('crypto'); \
         const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', \
           { modulusLength: 2048 }); \
         const label = Buffer.from('label'); \
         const ciphertext = crypto.publicEncrypt( \
           { key: publicKey, oaepHash: 'sha256', oaepLabel: label }, Buffer.from('hi')); \
         console.log('ok', crypto.privateDecrypt( \
           { key: privateKey, oaepHash: 'sha256', oaepLabel: label }, \
           ciphertext).toString()); \
         try { \
           crypto.privateDecrypt({ key: privateKey, oaepHash: 'sha256' }, ciphertext); \
           console.log('no throw'); \
         } catch (error) { console.log('mismatch', error.code); }",
        "ok hi\nmismatch ERR_OSSL_RSA_OAEP_DECODING_ERROR",
    );
}

#[test]
fn ecdh_completes_a_shared_secret_between_two_rustnode_peers() {
    // `new _ECDH(curve)` at `diffiehellman.js:232`. The length is a property of
    // the curve: a `P-256` secret is the field width, 32 bytes.
    assert_prints(
        "const crypto = require('crypto'); \
         const alice = crypto.createECDH('prime256v1'); \
         const bob = crypto.createECDH('prime256v1'); \
         alice.generateKeys(); bob.generateKeys(); \
         const fromAlice = alice.computeSecret(bob.getPublicKey()); \
         const fromBob = bob.computeSecret(alice.getPublicKey()); \
         console.log(fromAlice.equals(fromBob), fromAlice.length);",
        "true 32",
    );
}

#[test]
fn ecdh_public_keys_have_the_three_encodings() {
    // 66 hex characters compressed, 130 uncompressed and hybrid: these are the
    // `POINT_CONVERSION_*` values `diffiehellman.js` maps the string spellings
    // onto, and getting one wrong changes every public key this returns.
    assert_prints(
        "const crypto = require('crypto'); \
         const ecdh = crypto.createECDH('prime256v1'); \
         ecdh.generateKeys(); \
         console.log(['compressed', 'uncompressed', 'hybrid'] \
           .map((form) => ecdh.getPublicKey('hex', form).length).join(','));",
        "66,130,130",
    );
}

#[test]
fn ecdh_convert_key_round_trips_between_encodings() {
    // `ECDH.convertKey` is a separate member (`ECDHConvertKey`), and an empty key
    // returns the empty string rather than throwing — both are checked by
    // Node's own ECDH tests.
    assert_prints(
        "const crypto = require('crypto'); \
         const ecdh = crypto.createECDH('prime256v1'); \
         ecdh.generateKeys(); \
         const compressed = ecdh.getPublicKey(undefined, 'compressed'); \
         const back = crypto.ECDH.convertKey(compressed, 'prime256v1', 'buffer', 'hex'); \
         console.log('round trip', ecdh.getPublicKey('hex').equals?.() ?? \
           (back === ecdh.getPublicKey('hex'))); \
         console.log('empty', JSON.stringify(crypto.ECDH.convertKey( \
           Buffer.alloc(0), 'prime256v1')));",
        "round trip true\nempty \"\"",
    );
}
