//! Differential checks for the `crypto.subtle` surface.
//!
//! Every expected string in this file was measured on the pinned Node 28 nightly
//! (`v28.0.0-nightly20261111e8c1160d20`, the revision `tools/node-pin.toml`
//! records) with the oracle run itself — `rn_node_oracle::require_oracle` — and
//! then compared against the built `rustnode` binary. Nothing here was written by
//! reading the Rust, so a failure is a divergence a user could hit rather than a
//! description the code already satisfies.
//!
//! They run the built binary because every difference that matters here is
//! JavaScript-visible: whether `generateKey` resolves to a `CryptoKey` or to an
//! array of two, whether `sign` resolves a promise or a `[err, value]` tuple,
//! whether a usage invariant throws `SyntaxError` or `InvalidAccessError`.
//!
//! # Why the whole surface, not just the three reported defects
//!
//! All three reports — `generateKey` returning `[null, KeyObjectHandle]`, `sign`
//! failing, RSA key generation throwing — had one root: every WebCrypto
//! `*Job` treated `kCryptoJobWebCrypto` as another inline tuple mode. That is a
//! property of the job dispatch, not of three call sites, so the cases below
//! cover each job family that mode reaches: key generation (secret and pair),
//! HMAC sign/verify, the AEAD and block ciphers, RSA-OAEP, DH-based derivation,
//! HKDF, PBKDF2 and `wrapKey`. A fix that repaired `generateKey` alone would
//! leave the rest of the table red, which is the point of enumerating it.

use std::process::Command;

/// Runs `source` under the built binary and returns `(code, stdout, stderr)`.
///
/// `--expose-internals` is always passed. Two of the cases below reach
/// `internalBinding('crypto')` through `internal/test/binding`, and the flag is
/// also what lets a test observe `kKeyVariant*` — the constants whose absence
/// caused the AES defect — rather than inferring them from a round trip. Passing
/// it for every case keeps one helper instead of two, and it changes nothing for
/// the cases that only use `crypto.subtle`.
fn run(source: &str) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["--expose-internals", "-e", source])
        .output()
        .expect("rustnode runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Asserts the script printed `expected` and exited 0.
fn expect(source: &str, expected: &str) {
    let (code, stdout, stderr) = run(source);
    // The engine banner is stderr, not stdout, so it never reaches the
    // comparison; a warning that *does* land on stdout (the inspector's
    // worker-install notice) is filtered by the caller's expectation instead of
    // being tolerated here.
    assert_eq!(
        stdout.trim(),
        expected.trim(),
        "script exited {code}, stderr: {stderr}"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
}

/// The shape a value is summarised as, shared by every case.
///
/// Kept as one JavaScript function inside each script rather than duplicated per
/// test, so the labels in the expectations are produced the same way the oracle
/// produced them.
const SUMMARY: &str = r#"
async function line(label, fn) {
  try {
    const r = await fn();
    let d;
    if (r === undefined) d = 'undefined';
    else if (r === null) d = 'null';
    else if (typeof r === 'boolean') d = `boolean:${r}`;
    else if (typeof r === 'string') d = `string:${r}`;
    else if (ArrayBuffer.isView(r)) d = r.constructor.name;
    else if (r instanceof ArrayBuffer) d = 'ArrayBuffer';
    else if (typeof r === 'object' && r.constructor.name === 'CryptoKey') {
      d = `CryptoKey:${r.type}:${r.extractable}:${r.algorithm.name}:${r.usages.join('|')}`;
    } else {
      d = `${Object.prototype.toString.call(r)}:${Object.keys(r).sort().join(',')}`;
    }
    return `${label} OK ${d}`;
  } catch (e) {
    return `${label} THREW ${e.name} ${e.code === undefined ? '-' : e.code} ${JSON.stringify(e.message)}`;
  }
}
"#;

/// Wraps `body` in an async IIFE that prints each `line(...)` result in order.
fn script(lines: &[(&str, &str)]) -> String {
    let mut source = String::from("const { subtle } = globalThis.crypto;\n");
    source.push_str(SUMMARY);
    source.push_str("(async () => {\n");
    for (label, body) in lines {
        source.push_str(&format!(
            "  console.log(await line({label:?}, async () => {{ {body} }}));\n"
        ));
    }
    source.push_str("})();\n");
    source
}

// ---------------------------------------------------------------------------
// generateKey: the reported defect
// ---------------------------------------------------------------------------

#[test]
fn generate_key_resolves_a_cryptokey_for_a_symmetric_algorithm() {
    // Before this fix the binding returned `[null, KeyObjectHandle]` — a
    // `kCryptoJobWebCrypto` job that took the inline sync path — so every
    // symmetric `generateKey` resolved to a two-element array. `aes.js` then held
    // a plain array where a `CryptoKey` was expected, which is why
    // `subtle.encrypt` below reported "2nd argument is not of type CryptoKey".
    expect(
        &script(&[
            (
                "generateKey-AES-GCM",
                "return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);",
            ),
            (
                "generateKey-AES-CBC",
                "return subtle.generateKey({ name: 'AES-CBC', length: 128 }, false, ['encrypt']);",
            ),
            (
                "generateKey-AES-CTR",
                "return subtle.generateKey({ name: 'AES-CTR', length: 192 }, false, ['encrypt']);",
            ),
            (
                "generateKey-AES-KW",
                "return subtle.generateKey({ name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey']);",
            ),
            (
                "generateKey-HMAC",
                "return subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);",
            ),
        ]),
        "generateKey-AES-GCM OK CryptoKey:secret:true:AES-GCM:encrypt|decrypt
generateKey-AES-CBC OK CryptoKey:secret:false:AES-CBC:encrypt
generateKey-AES-CTR OK CryptoKey:secret:false:AES-CTR:encrypt
generateKey-AES-KW OK CryptoKey:secret:true:AES-KW:wrapKey|unwrapKey
generateKey-HMAC OK CryptoKey:secret:true:HMAC:sign|verify",
    );
}

#[test]
fn generate_key_resolves_a_cryptokeypair_for_an_asymmetric_algorithm() {
    // The pair form is where the second half of the defect lived: RSA, EC and
    // CFRG generation all threw `OperationError`, and the Ed25519 path threw
    // `ERR_INVALID_ARG_VALUE` before that because the named-keygen constructor
    // applied the traditional (`crypto.generateKeyPairSync`) validation to a
    // WebCrypto algorithm name.
    expect(
        &script(&[
            (
                "ECDSA",
                "const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
                 return `pub=${kp.publicKey.type}/${kp.publicKey.extractable},priv=${kp.privateKey.type}/${kp.privateKey.extractable},curve=${kp.publicKey.algorithm.namedCurve}`;",
            ),
            (
                "ECDH",
                "const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveBits']);
                 return `pub=${kp.publicKey.type},priv=${kp.privateKey.type},curve=${kp.privateKey.algorithm.namedCurve},usages=${kp.privateKey.usages.join('|')}`;",
            ),
            (
                "Ed25519",
                "const kp = await subtle.generateKey('Ed25519', true, ['sign', 'verify']);
                 return `pub=${kp.publicKey.type},priv=${kp.privateKey.type},alg=${kp.privateKey.algorithm.name}`;",
            ),
            (
                "RSA-OAEP",
                "const kp = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
                 return `pub=${kp.publicKey.type},priv=${kp.privateKey.type},mod=${kp.privateKey.algorithm.modulusLength},hash=${kp.privateKey.algorithm.hash.name}`;",
            ),
        ]),
        "ECDSA OK string:pub=public/true,priv=private/true,curve=P-256
ECDH OK string:pub=public,priv=private,curve=P-384,usages=deriveBits
Ed25519 OK string:pub=public,priv=private,alg=Ed25519
RSA-OAEP OK string:pub=public,priv=private,mod=1024,hash=SHA-256",
    );
}

#[test]
fn a_generated_pair_is_one_object_with_own_public_and_private_data_properties() {
    // `KeyGenJob::EncodeWebCryptoKey` builds a plain `v8::Object` and defines
    // `publicKey`/`privateKey` on it, so the keys are own data properties and the
    // prototype is `Object.prototype`. A `{publicKey}` shorthand literal would
    // pass a loose check while adding a prototype and leaving the property order
    // open, so both are asserted.
    expect(
        &script(&[(
            "shape",
            "const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
             const d = Object.getOwnPropertyDescriptor(kp, 'privateKey');
             return `keys=${Object.keys(kp).sort().join(',')},proto=${Object.getPrototypeOf(kp) === Object.prototype},data=${d.get === undefined && d.set === undefined}`;",
        )]),
        "shape OK string:keys=privateKey,publicKey,proto=true,data=true",
    );
}

#[test]
fn a_generated_pair_reports_the_extractable_flag_per_half() {
    // Node makes the public half extractable regardless and gives the private half
    // the caller's flag, because a public key cannot leak anything a signature
    // does not already publish. `KeyGenJob::EncodeWebCryptoKey` passes a literal
    // `true` for the public half and `webcrypto_config_.extractable` for the
    // private one, which is the asymmetry this pins.
    expect(
        &script(&[(
            "keypair-extractable",
            "const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
             return `pub=${kp.publicKey.extractable},priv=${kp.privateKey.extractable}`;",
        )]),
        "keypair-extractable OK string:pub=true,priv=false",
    );
}

#[test]
fn an_hmac_default_length_is_the_digest_blocksize() {
    // `hmacGenerateKey` passes `length = getBlockSize(hash.name)`, so a SHA-256
    // HMAC key is 512 bits and a SHA-512 one 1024. This is the number that proves
    // the secret job read the algorithm dictionary the WebCrypto branch passes
    // instead of the traditional `(mode, length)` pair.
    expect(
        &script(&[(
            "hmac-512",
            "const k = await subtle.generateKey({ name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
             return `len=${k.algorithm.length}`;",
        )]),
        "hmac-512 OK string:len=1024",
    );
}

#[test]
fn rsa_key_generation_succeeds_where_it_used_to_throw_a_domexception() {
    // The third reported defect. `RsaKeyPairGenJob` in `kCryptoJobWebCrypto` mode
    // carries the algorithm dictionary and two usage masks in the slots the
    // traditional form uses for encodings, so the constructor rejected the
    // algorithm and `jobPromise` turned the throw into an `OperationError`.
    expect(
        &script(&[(
            "rsa-oaep-op",
            "const kp = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
             const ct = await subtle.encrypt({ name: 'RSA-OAEP' }, kp.publicKey, new TextEncoder().encode('hello world'));
             const pt = await subtle.decrypt({ name: 'RSA-OAEP' }, kp.privateKey, ct);
             return `ct=${ct.byteLength},pt=${new TextDecoder().decode(pt)}`;",
        )]),
        "rsa-oaep-op OK string:ct=128,pt=hello world",
    );
    // RSA-PSS is the same job class with the variant's three extra slots, so it
    // exercises the offset arithmetic the variant introduces.
    expect(
        &script(&[(
            "rsa-pss-sign",
            "const kp = await subtle.generateKey({ name: 'RSA-PSS', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
             const sig = await subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, kp.privateKey, new TextEncoder().encode('hello world'));
             return `sig=${sig.byteLength}`;",
        )]),
        "rsa-pss-sign OK string:sig=128",
    );
}

// ---------------------------------------------------------------------------
// sign: the reported defect
// ---------------------------------------------------------------------------

#[test]
fn hmac_sign_and_verify_resolve_a_buffer_and_a_boolean() {
    // The second reported defect. `HmacJob`'s constructor read its slots one
    // position early — the sign mode was taken as the digest name and the digest
    // as the key — so `subtle.sign('HMAC', …)` could not work with any key.
    // `HmacTraits::EncodeOutput` also has two result types, a digest for sign and
    // a `Boolean` for verify, which the job has to pick between.
    expect(
        &script(&[(
            "hmac",
            "const raw = new Uint8Array(32).fill(7);
             const k = await subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);
             const msg = new TextEncoder().encode('hello world');
             const sig = await subtle.sign('HMAC', k, msg);
             const good = await subtle.verify('HMAC', k, sig, msg);
             const bad = await subtle.verify('HMAC', k, new Uint8Array(sig.byteLength), msg);
             return `sig=${sig.byteLength},verify=${good},bad=${bad}`;",
        )]),
        "hmac OK string:sig=32,verify=true,bad=false",
    );
}

#[test]
fn every_signature_family_resolves_an_arraybuffer() {
    // `SignJob` in WebCrypto mode: before the fix `run()` returned the `[err,
    // value]` tuple, so `subtle.sign` resolved to an array where the caller
    // expected the signature bytes — a silent wrong answer, not a throw. Each
    // family goes through a different path inside `run_sign`, so all four are
    // checked rather than one representative.
    expect(
        &script(&[
            (
                "ECDSA",
                "const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
                 const msg = new TextEncoder().encode('hello world');
                 const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, msg);
                 return `sig=${sig.byteLength},verify=${await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, kp.publicKey, sig, msg)}`;",
            ),
            (
                "Ed25519",
                "const kp = await subtle.generateKey('Ed25519', true, ['sign', 'verify']);
                 const msg = new TextEncoder().encode('hello world');
                 const sig = await subtle.sign('Ed25519', kp.privateKey, msg);
                 return `sig=${sig.byteLength},verify=${await subtle.verify('Ed25519', kp.publicKey, sig, msg)}`;",
            ),
            (
                "Ed448",
                "const kp = await subtle.generateKey('Ed448', true, ['sign', 'verify']);
                 const msg = new TextEncoder().encode('hello world');
                 const sig = await subtle.sign('Ed448', kp.privateKey, msg);
                 return `sig=${sig.byteLength},verify=${await subtle.verify('Ed448', kp.publicKey, sig, msg)}`;",
            ),
        ]),
        "ECDSA OK string:sig=64,verify=true
Ed25519 OK string:sig=64,verify=true
Ed448 OK string:sig=114,verify=true",
    );
}

// ---------------------------------------------------------------------------
// encrypt / decrypt
// ---------------------------------------------------------------------------

#[test]
fn the_aes_variants_are_published_so_each_cipher_is_the_one_it_names() {
    // The `kKeyVariantAES_*` constants were in `DEFERRED`, so every property read
    // `undefined`; `aes.js` passed `undefined` to `AESCipherJob`, whose
    // `uint32_value` coerced it to index 0 — AES-CTR — and AES-GCM then failed
    // with "Invalid counter". Pinning the round trip per mode is what makes a
    // silently-substituted cipher visible: all three would still "work" if they
    // all ran as the same one.
    expect(
        &script(&[
            (
                "AES-GCM",
                "const k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
                 const iv = new Uint8Array(12).fill(1);
                 const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode('hello world'));
                 const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, k, ct);
                 return `ct=${ct.byteLength},pt=${new TextDecoder().decode(pt)}`;",
            ),
            (
                "AES-CBC",
                "const k = await subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);
                 const iv = new Uint8Array(16).fill(1);
                 const ct = await subtle.encrypt({ name: 'AES-CBC', iv }, k, new TextEncoder().encode('hello world'));
                 const pt = await subtle.decrypt({ name: 'AES-CBC', iv }, k, ct);
                 return `ct=${ct.byteLength},pt=${new TextDecoder().decode(pt)}`;",
            ),
            (
                "AES-CTR",
                "const k = await subtle.generateKey({ name: 'AES-CTR', length: 256 }, true, ['encrypt', 'decrypt']);
                 const alg = { name: 'AES-CTR', counter: new Uint8Array(16), length: 64 };
                 const ct = await subtle.encrypt(alg, k, new TextEncoder().encode('hello world'));
                 const pt = await subtle.decrypt(alg, k, ct);
                 return `ct=${ct.byteLength},pt=${new TextDecoder().decode(pt)}`;",
            ),
        ]),
        "AES-GCM OK string:ct=27,pt=hello world
AES-CBC OK string:ct=16,pt=hello world
AES-CTR OK string:ct=11,pt=hello world",
    );
}

#[test]
fn the_aes_variant_constants_carry_nodes_numbers() {
    // The absolute values matter, not just the round trip: `crypto_aes.h` expands
    // `VARIANTS` as CTR, CBC and GCM at 128/192/256, the three KW variants, then
    // the OCB block, and `crypto_aes.cc` publishes each with
    // `static_cast<int>(AESKeyVariant::name)`. These are the oracle's numbers.
    let (code, stdout, stderr) = run(
        "const { internalBinding } = require('node:internal/test/binding');\n\
         const c = internalBinding('crypto');\n\
         const names = ['CTR_128','CBC_128','GCM_128','KW_128','OCB_128','GCM_256','OCB_256'];\n\
         console.log(names.map((n) => `${n}=${c['kKeyVariantAES_' + n]}`).join(' '));",
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "CTR_128=0 CBC_128=3 GCM_128=6 KW_128=9 OCB_128=12 GCM_256=8 OCB_256=14"
    );
}

// ---------------------------------------------------------------------------
// deriveBits / deriveKey
// ---------------------------------------------------------------------------

#[test]
fn every_derivation_family_resolves_a_secret() {
    // `subtle.deriveBits` reaches three different jobs: `DHBitsJob` for the two
    // Diffie-Hellman families, `HKDFJob` and `PBKDF2Job`. None worked before
    // this change — the DH job class did not exist at all, and the two KDF jobs
    // read their key slot as bytes when the WebCrypto path passes a
    // `KeyObjectHandle`, so both rejected with "The key must be a string or an
    // ArrayBufferView".
    expect(
        &script(&[
            (
                "ECDH",
                "const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                 const bits = await subtle.deriveBits({ name: 'ECDH', public: kp.publicKey }, kp.privateKey, 128);
                 return `bits=${bits.byteLength}`;",
            ),
            (
                "ECDH-key",
                "const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits', 'deriveKey']);
                 const k = await subtle.deriveKey({ name: 'ECDH', public: kp.publicKey }, kp.privateKey, { name: 'AES-GCM', length: 128 }, true, ['encrypt']);
                 return `${k.type}/${k.algorithm.name}/${k.algorithm.length}/${k.usages.join('|')}`;",
            ),
            (
                "X25519",
                "const kp = await subtle.generateKey('X25519', true, ['deriveBits']);
                 const bits = await subtle.deriveBits({ name: 'X25519', public: kp.publicKey }, kp.privateKey, 256);
                 return `bits=${bits.byteLength}`;",
            ),
            (
                "HKDF",
                "const k = await subtle.importKey('raw', new Uint8Array(32).fill(7), 'HKDF', false, ['deriveBits']);
                 const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(16), info: new Uint8Array(8) }, k, 128);
                 return `bits=${bits.byteLength}`;",
            ),
            (
                "PBKDF2",
                "const k = await subtle.importKey('raw', new Uint8Array(32).fill(7), 'PBKDF2', false, ['deriveBits']);
                 const bits = await subtle.deriveBits({ name: 'PBKDF2', salt: new Uint8Array(16), iterations: 100, hash: 'SHA-256' }, k, 128);
                 return `bits=${bits.byteLength}`;",
            ),
        ]),
        "ECDH OK string:bits=16
ECDH-key OK string:secret/AES-GCM/128/encrypt
X25519 OK string:bits=32
HKDF OK string:bits=16
PBKDF2 OK string:bits=16",
    );
}

// ---------------------------------------------------------------------------
// wrapKey / unwrapKey
// ---------------------------------------------------------------------------

#[test]
fn wrap_key_and_unwrap_key_round_trip_through_aes_kw() {
    // `subtle.wrapKey` is `exportKey` into an `AESCipherJob`, so it depends on
    // both the AES variants and the wrapping key's own handle. It failed at the
    // IV check before the variants existed.
    expect(
        &script(&[(
            "aes-kw",
            "const kwk = await subtle.importKey('raw', new Uint8Array(32).fill(7), 'AES-KW', true, ['wrapKey', 'unwrapKey']);
             const target = await subtle.importKey('raw', new Uint8Array(32).fill(3), 'AES-CBC', true, ['encrypt']);
             const wrapped = await subtle.wrapKey('raw', target, kwk, 'AES-KW');
             const un = await subtle.unwrapKey('raw', wrapped, kwk, 'AES-KW', 'AES-CBC', true, ['encrypt']);
             return `wrapped=${wrapped.byteLength},alg=${un.algorithm.name}`;",
        )]),
        "aes-kw OK string:wrapped=40,alg=AES-CBC",
    );
}

// ---------------------------------------------------------------------------
// importKey / exportKey formats
// ---------------------------------------------------------------------------

#[test]
fn every_key_format_round_trips_into_a_working_key() {
    // The formats themselves already worked for symmetric keys, but the
    // asymmetric half did not exist because `generateKey` never produced a
    // `CryptoKey`. `spki` and `pkcs8` lengths are fixed by the curve, so they are
    // usable as expectations; the RSA pair's DER length is not (a PKCS#8 integer
    // may or may not need a leading zero) and is therefore only used through its
    // round trip.
    expect(
        &script(&[
            (
                "raw",
                "const k = await subtle.importKey('raw', new Uint8Array(32).fill(7), { name: 'AES-GCM' }, true, ['encrypt']);
                 return `len=${(await subtle.exportKey('raw', k)).byteLength}`;",
            ),
            (
                "jwk",
                "const k = await subtle.importKey('raw', new Uint8Array(32).fill(7), { name: 'AES-GCM' }, true, ['encrypt']);
                 const jwk = await subtle.exportKey('jwk', k);
                 return `kty=${jwk.kty},alg=${jwk.alg},key_ops=${jwk.key_ops.join('|')},ext=${jwk.ext}`;",
            ),
            (
                "spki",
                "const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
                 return `len=${(await subtle.exportKey('spki', kp.publicKey)).byteLength}`;",
            ),
            (
                "pkcs8",
                "const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
                 return `len=${(await subtle.exportKey('pkcs8', kp.privateKey)).byteLength}`;",
            ),
            (
                "pkcs8-spki-use",
                "const kp = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
                 const pkcs8 = await subtle.exportKey('pkcs8', kp.privateKey);
                 const spki = await subtle.exportKey('spki', kp.publicKey);
                 const priv = await subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
                 const pub = await subtle.importKey('spki', spki, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
                 const ct = await subtle.encrypt({ name: 'RSA-OAEP' }, pub, new TextEncoder().encode('hello world'));
                 return `pt=${new TextDecoder().decode(await subtle.decrypt({ name: 'RSA-OAEP' }, priv, ct))}`;",
            ),
        ]),
        "raw OK string:len=32
jwk OK string:kty=oct,alg=A256GCM,key_ops=encrypt,ext=true
spki OK string:len=91
pkcs8 OK string:len=138
pkcs8-spki-use OK string:pt=hello world",
    );
}

// ---------------------------------------------------------------------------
// extractable and usages invariants
// ---------------------------------------------------------------------------
//
// These are JavaScript-side (`webcrypto_util.js` and the per-algorithm
// `validateKeyUsages`), and they already matched the oracle. They are pinned
// because the fix changes how the *binding* reports usages and extractable, and a
// wrong mask or flag would turn one of these into the wrong error rather than
// visibly breaking a round trip.

#[test]
fn the_usage_and_extractable_invariants_keep_nodes_classes_and_codes() {
    expect(
        &script(&[
            (
                "empty-usages",
                "return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, []);",
            ),
            (
                "bad-usage",
                "return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['sign']);",
            ),
            (
                "import-empty",
                "return subtle.importKey('raw', new Uint8Array(32).fill(7), { name: 'AES-GCM' }, true, []);",
            ),
            (
                "not-extractable",
                "const k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
                 return subtle.exportKey('raw', k);",
            ),
            (
                "public-sign",
                "const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
                 return subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.publicKey, new TextEncoder().encode('x'));",
            ),
        ]),
        r#"empty-usages THREW SyntaxError 12 "Usages cannot be empty when creating a key."
bad-usage THREW SyntaxError 12 "Unsupported key usage for AES-GCM key"
import-empty THREW SyntaxError 12 "Usages cannot be empty when importing a secret key."
not-extractable THREW InvalidAccessError 15 "key is not extractable"
public-sign THREW InvalidAccessError 15 "Unable to use this key to sign""#,
    );
}

// ---------------------------------------------------------------------------
// worker isolate
// ---------------------------------------------------------------------------

#[test]
fn subtle_behaves_identically_in_a_worker() {
    // A worker is a second isolate with its own `keys.js`, so its
    // `InternalCryptoKey` constructor — the one the WebCrypto keygen jobs build
    // keys through — is a different function object from the main thread's. A
    // binding that cached one constructor globally would produce keys the
    // worker's getters reject, so the worker case is a real second subject
    // rather than a repeat.
    let source = r#"
const { Worker } = require('node:worker_threads');
const body = `
  const { parentPort } = require('node:worker_threads');
  const { subtle } = globalThis.crypto;
  (async () => {
    const out = [];
    const k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    out.push('gen=' + k.constructor.name + '/' + k.algorithm.name);
    const hk = await subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    out.push('hmac=' + hk.constructor.name);
    const sig = await subtle.sign('HMAC', hk, new Uint8Array([1, 2, 3]));
    out.push('sig=' + sig.byteLength);
    const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    out.push('pair=' + Object.keys(kp).sort().join(','));
    out.push('digest=' + (await subtle.digest('SHA-256', new Uint8Array(0))).byteLength);
    parentPort.postMessage(out.join(';'));
  })().catch((e) => { parentPort.postMessage('THREW ' + e.name + ' ' + e.message); });
`;
const w = new Worker(body, { eval: true });
w.on('message', (m) => console.log(m));
"#;
    // The worker module's own load prints an inspector warning on stdout in a
    // build where the inspector namespace has no isolate yet; it is unrelated to
    // WebCrypto and would otherwise make this a test of the log rather than of
    // the surface. The measured line is the last one.
    let (code, stdout, stderr) = run(source);
    assert_eq!(code, 0, "stderr: {stderr}");
    let last = stdout.trim().lines().last().unwrap_or_default();
    assert_eq!(
        last,
        "gen=CryptoKey/AES-GCM;hmac=CryptoKey;sig=32;pair=privateKey,publicKey;digest=32"
    );
}

// ---------------------------------------------------------------------------
// The dispatch itself
// ---------------------------------------------------------------------------

#[test]
fn a_webcrypto_job_returns_a_promise_while_the_traditional_jobs_keep_their_shapes() {
    // The single invariant behind every case above: `CryptoJob::Run` creates a
    // resolver for `kCryptoJobWebCrypto`, schedules the work and returns the
    // promise; `kCryptoJobSync` returns `[err, value]` inline and
    // `kCryptoJobAsync` returns `undefined` and calls `ondone`. Collapsing the
    // three is what broke all of them at once, so the shapes are asserted
    // directly rather than only through their results.
    let source = r#"
const { internalBinding } = require('node:internal/test/binding');
const c = internalBinding('crypto');

const shapes = [];
shapes.push('webcrypto:' + Object.prototype.toString.call(
  new c.SecretKeyGenJob(2, 256, { name: 'AES-GCM', length: 256 }, 12, true).run()));
shapes.push('sync:' + Object.prototype.toString.call(
  new c.SecretKeyGenJob(1, 256).run()));
shapes.push('async:' + String(
  new c.SecretKeyGenJob(0, 256).run()));
console.log(shapes.join(' '));
"#;
    let (code, stdout, stderr) = run(source);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "webcrypto:[object Promise] sync:[object Array] async:undefined"
    );
}
