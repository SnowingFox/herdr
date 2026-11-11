//! End-to-end checks that drive the binding through a real V8 isolate.
//!
//! `lib/crypto.js` is unchanged Node code, so the only way to know this crate
//! speaks the right protocol is to run the same calls it makes. These tests
//! install the namespace exactly as `internalBinding('crypto')` would and then
//! exercise it from JavaScript.
//!
//! # One test, many cases
//!
//! V8's platform and global state are process-wide and can only be initialised
//! once, so every case runs from the single `crypto_binding_end_to_end` test
//! rather than as separate `#[test]` functions. A second isolate in a second
//! test would panic on the already-initialised platform, which is why the zlib
//! crate is laid out the same way.
//!
//! The expected digests are published standards (FIPS 180-4, RFC 4231, RFC 2202);
//! where a value is not from a standard it was cross-checked against a real
//! `node` binary, and the comment says so.

use rn_bind_crypto::Crypto;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// One named case: what to evaluate and what it must produce.
struct Case {
    name: &'static str,
    source: &'static str,
    expected: &'static str,
}

#[test]
fn crypto_binding_end_to_end() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = Crypto
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("install the crypto namespace");

    let global = scope.get_current_context().global(scope);
    let name = v8::String::new(scope, "binding").expect("allocate the binding name");
    global.set(scope, name.into(), binding.into());

    // A bare isolate has no Node globals. `Buffer.from` and `TextEncoder` are the
    // only two the cases use, so they are defined here over `Uint8Array` rather
    // than pulling in `lib/buffer.js`. Everything under test is the binding, not
    // the shims.
    let prelude = v8::String::new(
        scope,
        r#"
        globalThis.Buffer = {
          from(value) {
            if (typeof value === 'string') {
              return new TextEncoder().encode(value);
            }
            return new Uint8Array(value);
          },
          alloc(length) { return new Uint8Array(length); },
        };
        globalThis.TextEncoder = class TextEncoder {
          encode(text) {
            const bytes = [];
            for (let index = 0; index < text.length; index += 1) {
              const code = text.charCodeAt(index);
              if (code < 0x80) {
                bytes.push(code);
              } else if (code < 0x800) {
                bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
              } else {
                bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f),
                           0x80 | (code & 0x3f));
              }
            }
            return new Uint8Array(bytes);
          }
        };
        "#,
    )
    .expect("allocate the test prelude");
    let Some(script) = v8::Script::compile(scope, prelude, None) else {
        panic!("compile the test prelude");
    };
    script.run(scope).expect("run the test prelude");

    let mut failures = Vec::new();
    for case in cases() {
        let actual = evaluate(scope, case.source);
        if actual != case.expected {
            failures.push(format!(
                "{}\n  expected: {:?}\n  actual:   {:?}",
                case.name, case.expected, actual
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} crypto cases failed:\n\n{}",
        failures.len(),
        cases().len(),
        failures.join("\n\n")
    );
}

/// Runs `source` wrapped in a try/catch that turns a throw into its message, so a
/// case can assert on a deliberate failure without failing the whole test.
fn evaluate(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let wrapped = format!(
        "(function() {{ try {{ {source} }} catch (error) \
         {{ return 'THREW: ' + (error && error.message ? error.message : String(error)); }} }})()"
    );
    let Some(code) = v8::String::new(scope, &wrapped) else {
        return "ENOMEM: cannot allocate the script".to_string();
    };
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let result = v8::Script::compile(scope, code, None).and_then(|script| script.run(scope));
    match result {
        Some(value) => value.to_rust_string_lossy(scope),
        None => {
            let exception = scope
                .exception()
                .map(|value| value.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "no exception".to_string());
            format!("UNCAUGHT: {exception}")
        }
    }
}

/// The cases, each a name, a script and the exact string it must return.
fn cases() -> Vec<Case> {
    let mut cases = vec![
        Case {
            name: "every claimed member is on the namespace object",
            // `lib/internal/crypto/**` destructures these at module scope, so a
            // missing one binds `undefined` and fails later with a confusing
            // TypeError rather than at load.
            source: r#"
                const names = ['Hash', 'Hmac', 'HashJob', 'HmacJob', 'oneShotDigest',
                               'randomFillSync', 'secureBuffer', 'getHashes',
                               'getCiphers', 'getCurves', 'getCachedAliases',
                               'timingSafeEqual', 'getFipsCrypto',
                               'getFipsCryptoGeneration', 'getOpenSSLSecLevelCrypto',
                               'secureHeapUsed', 'kCryptoJobAsync', 'kCryptoJobSync',
                               'kCryptoJobWebCrypto', 'kKeyFormatDER', 'kKeyFormatPEM',
                               'kKeyTypeSecret', 'kSigEncDER', 'kSignJobModeSign',
                               'RSA_PKCS1_PSS_PADDING', 'X509_CHECK_FLAG_NO_WILDCARDS'];
                const missing = names.filter((name) => binding[name] === undefined);
                return missing.length === 0 ? 'all-present' : 'missing: ' + missing.join(',');
            "#,
            expected: "all-present",
        },
        Case {
            name: "SHA-256 of \"abc\" is the FIPS 180-4 value",
            source: r#"
                const handle = new binding.Hash('sha256', undefined, -1, {});
                handle.update('abc');
                return handle.digest('hex');
            "#,
            expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        },
        Case {
            name: "digest() without an encoding is a byte array",
            // `Hash.prototype._flush` pushes this straight into the stream.
            source: r#"
                const handle = new binding.Hash('sha1', undefined, -1, {});
                handle.update('abc');
                const digest = handle.digest();
                return digest.constructor.name + ':' + digest.length + ':' + digest[0];
            "#,
            // SHA-1("abc") is 20 bytes starting with 0xa9.
            expected: "Uint8Array:20:169",
        },
        Case {
            name: "update() decodes a string using the given encoding",
            // `update('616263', 'hex')` hashes the bytes 0x61 0x62 0x63, not the
            // six-character literal.
            source: r#"
                const handle = new binding.Hash('sha256', undefined, -1, {});
                const ok = handle.update('616263', 'hex');
                return String(ok) + ':' + handle.digest('hex');
            "#,
            expected: "true:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        },
        Case {
            name: "chunked updates equal one update",
            // `Hash.prototype._transform` feeds one chunk per write.
            source: r#"
                const whole = new binding.Hash('sha512', undefined, -1, {});
                whole.update(new TextEncoder().encode(
                  'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'));
                const split = new binding.Hash('sha512', undefined, -1, {});
                split.update(new TextEncoder().encode('abcdbcdecdefdefgefghfghighij'));
                split.update(new TextEncoder().encode('hijkijkljklmklmnlmnomnopnopq'));
                const a = whole.digest('hex');
                const b = split.digest('hex');
                return (a === b) + ':' + a.slice(0, 16);
            "#,
            // FIPS 180-4's 112-byte SHA-512 example, fed as one update and as
            // two; the digests must agree.
            expected: "true:204a8fc6dda82f0a",
        },
        Case {
            name: "base64 and latin1 output encodings",
            source: r#"
                const enc = (name) => {
                  const handle = new binding.Hash('sha256', undefined, -1, {});
                  handle.update('abc');
                  return handle.digest(name);
                };
                return enc('base64');
            "#,
            expected: "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=",
        },
        Case {
            name: "an unknown algorithm throws naming it",
            source: r#"
                new binding.Hash('no-such-digest', undefined, -1, {});
                return 'did-not-throw';
            "#,
            expected: "THREW: Digest method not supported: no-such-digest",
        },
        Case {
            name: "a finalised hash cannot be finalised again",
            source: r#"
                const handle = new binding.Hash('sha256', undefined, -1, {});
                handle.update('abc');
                handle.digest('hex');
                handle.digest('hex');
                return 'did-not-throw';
            "#,
            expected: "THREW: Digest already called",
        },
        Case {
            name: "copying a handle continues from the same state",
            // `Hash.prototype.copy` calls `new Hash(existingHandle, options)`.
            source: r#"
                const original = new binding.Hash('sha256', undefined, -1, {});
                original.update('abc');
                const copy = new binding.Hash(original, {});
                copy.update('def');
                return original.digest('hex').slice(0, 16) + '|'
                  + copy.digest('hex').slice(0, 16);
            "#,
            // SHA-256("abc") and SHA-256("abcdef"), both published-prefix values
            // cross-checked against `node`.
            expected: "ba7816bf8f01cfea|bef57ec7f53a6d40",
        },
        Case {
            name: "HMAC-SHA256 matches RFC 4231 case 2",
            source: r#"
                const handle = new binding.Hmac();
                handle.init('sha256', Buffer.from('Jefe'));
                handle.update('what do ya want for nothing?');
                return handle.digest('hex');
            "#,
            expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        },
        Case {
            name: "HMAC accepts an empty key",
            // `createHmac('sha1', '')` is legal Node API and RFC 2202 case 6.
            // This is why the engine uses `HMAC_CTX` rather than `PKey::hmac`,
            // which rejects an empty key.
            source: r#"
                const handle = new binding.Hmac();
                handle.init('sha1', Buffer.alloc(0));
                handle.update('');
                return handle.digest('hex');
            "#,
            expected: "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
        },
        Case {
            name: "randomFillSync touches only the requested range",
            source: r#"
                const buffer = new Uint8Array(8);
                binding.randomFillSync(buffer, 2, 4);
                const inside = buffer.slice(2, 6).some((byte) => byte !== 0);
                const outside = buffer[0] + buffer[1] + buffer[6] + buffer[7];
                return inside + ':' + outside;
            "#,
            expected: "true:0",
        },
        Case {
            name: "randomFillSync returns the buffer it filled",
            source: r#"
                const buffer = new Uint8Array(4);
                const returned = binding.randomFillSync(buffer, 0, 4);
                return String(returned === buffer);
            "#,
            expected: "true",
        },
        Case {
            name: "secureBuffer is zeroed and the requested length",
            source: r#"
                const buffer = binding.secureBuffer(16);
                return buffer.length + ':' + buffer.some((byte) => byte !== 0);
            "#,
            expected: "16:false",
        },
        Case {
            name: "every algorithm getHashes() advertises actually works",
            // The requirement that matters: a script that enumerates the list and
            // then uses each entry must not be told about an algorithm that fails.
            source: r#"
                const names = binding.getHashes();
                const failed = [];
                for (const name of names) {
                  try {
                    const handle = new binding.Hash(name, undefined, -1, {});
                    handle.update('abc');
                    handle.digest('hex');
                  } catch (error) {
                    failed.push(name);
                  }
                }
                return failed.length ? 'failed: ' + failed.join(',') : 'all-work';
            "#,
            expected: "all-work",
        },
        Case {
            name: "getHashes() uses Node's spelling, not the provider's",
            // OpenSSL's provider long name for SHA-256 is "SHA2-256"; Node reports
            // "sha256". A list spelled the provider's way breaks every caller that
            // looks up a literal.
            source: r#"
                const names = binding.getHashes();
                const wanted = ['sha1', 'sha256', 'sha512', 'md5', 'sha3-256',
                                'blake2b512'];
                const missing = wanted.filter((name) => !names.includes(name));
                return missing.length ? 'missing: ' + missing.join(',') : 'node-spelling';
            "#,
            expected: "node-spelling",
        },
        Case {
            name: "getHashes() does not leak provider-only names",
            source: r#"
                const names = binding.getHashes();
                const providerOnly = ['sha2-256', 'sha2-512', 'blake2b-512'];
                const leaked = providerOnly.filter((name) => names.includes(name));
                return leaked.length ? 'leaked: ' + leaked.join(',') : 'clean';
            "#,
            expected: "clean",
        },
        Case {
            name: "getCiphers() reports a usable list",
            source: r#"
                const names = binding.getCiphers();
                const wanted = ['aes-128-cbc', 'aes-256-gcm', 'chacha20-poly1305'];
                const missing = wanted.filter((name) => !names.includes(name));
                return missing.length ? 'missing: ' + missing.join(',')
                                     : 'ciphers-ok:' + (names.length > 20);
            "#,
            expected: "ciphers-ok:true",
        },
        Case {
            name: "getCiphers() excludes the families Node disables",
            source: r#"
                const names = binding.getCiphers();
                const forbidden = ['rc4', 'bf-cbc', 'idea-cbc', 'desx-cbc'];
                const present = forbidden.filter((name) => names.includes(name));
                return present.length ? 'leaked: ' + present.join(',') : 'clean';
            "#,
            expected: "clean",
        },
        Case {
            name: "getCurves() reports names createECDH accepts",
            // The `comment` field of OpenSSL's `EC_builtin_curve` is prose
            // ("NIST/SECG curve over a 256 bit prime field"), so the NID short
            // name is what has to be reported.
            source: r#"
                const names = binding.getCurves();
                const want = ['prime256v1', 'secp384r1', 'secp521r1'];
                const missing = want.filter((name) => !names.includes(name));
                return missing.length ? 'missing: ' + missing.join(',') : 'curves-ok';
            "#,
            expected: "curves-ok",
        },
        Case {
            name: "getCachedAliases maps every name to a non-negative id",
            // `getCachedHashId()` returns `-1` for a miss, so a listed digest
            // without an id would make the JavaScript take the slow path forever.
            source: r#"
                const cache = binding.getCachedAliases();
                const names = Object.keys(cache);
                const bad = names.filter((name) => !(cache[name] >= 0));
                return (cache.sha256 !== undefined) + ':' + bad.length + ':'
                  + (names.length > 10);
            "#,
            expected: "true:0:true",
        },
        Case {
            name: "timingSafeEqual compares bytes",
            source: r#"
                const same = binding.timingSafeEqual(
                  new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]));
                const differ = binding.timingSafeEqual(
                  new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]));
                return same + ':' + differ;
            "#,
            expected: "true:false",
        },
        Case {
            name: "timingSafeEqual rejects a length mismatch",
            // `crypto.timingSafeEqual` documents ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH.
            source: r#"
                binding.timingSafeEqual(new Uint8Array([1]), new Uint8Array([1, 2]));
                return 'did-not-throw';
            "#,
            expected: "THREW: Input buffers must have the same byte length",
        },
        Case {
            name: "FIPS is reported as off",
            // `openssl-src` builds without the FIPS provider, so true would make
            // the JavaScript layer behave as if a validated module were in use.
            source: r#"
                return binding.getFipsCrypto() + ':' + binding.getFipsCryptoGeneration();
            "#,
            expected: "false:0",
        },
        Case {
            name: "secureHeapUsed is undefined without a secure heap",
            // `secureHeapUsed()` turns `undefined` into the zeroed summary.
            source: "return String(binding.secureHeapUsed());",
            expected: "undefined",
        },
        Case {
            name: "oneShotDigest agrees with the Hash class",
            // `crypto.hash()` passes (algorithm, id, cache, input, encoding,
            // encodingId); the id and cache are the C++ fast path, but the
            // positions still have to line up or the input lands in the wrong slot.
            source: r#"
                const cache = binding.getCachedAliases();
                const oneShot = binding.oneShotDigest(
                  'sha256', cache.sha256, cache, 'abc', 'hex', 4, undefined);
                const handle = new binding.Hash('sha256', undefined, -1, {});
                handle.update('abc');
                return oneShot === handle.digest('hex') ? 'match' : 'mismatch:' + oneShot;
            "#,
            expected: "match",
        },
        Case {
            name: "HashJob returns a promise",
            // The WebCrypto `subtle.digest` path runs
            // `jobPromise(() => new HashJob(mode, algorithm, data))`, so `run()`
            // has to return a thenable.
            source: r#"
                const job = new binding.HashJob(
                  2, 'sha256', new TextEncoder().encode('abc'));
                return job.run().constructor.name;
            "#,
            expected: "Promise",
        },
        Case {
            name: "HmacJob returns a promise",
            source: r#"
                const job = new binding.HmacJob(
                  2, 'sha256', Buffer.from('key'),
                  new TextEncoder().encode('data'));
                return job.run().constructor.name;
            "#,
            expected: "Promise",
        },
    ];
    cases.extend([
        Case {
            name: "getMacs reports OpenSSL's MAC algorithms",
            // `lib/internal/crypto/util.js` builds `getMacs` from this at module
            // scope, so it has to return usable names rather than nothing.
            source: r#"
                const names = binding.getMacs();
                const wanted = ['hmac'];
                const missing = wanted.filter((name) => !names.includes(name));
                return missing.length ? 'missing: ' + missing.join(',')
                                      : 'macs:' + (names.length > 0);
            "#,
            expected: "macs:true",
        },
        Case {
            name: "getSSLCiphers reports a TLS 1.3 suite",
            // `lib/tls.js` reads this at module scope to build `tls.getCiphers()`.
            source: r#"
                const names = binding.getSSLCiphers();
                return names.length > 10
                  && names.includes('TLS_AES_128_GCM_SHA256')
                  && names.includes('TLS_AES_256_GCM_SHA384');
            "#,
            expected: "true",
        },
        Case {
            name: "getCertificateCompressionAlgorithms reports what the build has",
            // The answer is probed through `SSL_CTX_set1_cert_comp_preference`,
            // and this `openssl-src` build has no certificate compression, so the
            // truthful result is an empty list. A table would claim three methods
            // every handshake would ignore.
            source: r#"
                const names = binding.getCertificateCompressionAlgorithms();
                if (!Array.isArray(names)) return 'not-an-array';
                const bogus = names.filter((name) => !['zlib', 'brotli', 'zstd']
                  .includes(name));
                return bogus.length ? 'bogus: ' + bogus.join(',') : 'truthful:' + names.length;
            "#,
            expected: "truthful:0",
        },
        Case {
            name: "startLoadingCertificatesOffThread is callable",
            // `lib/tls.js` calls it at module scope, so a missing or throwing
            // implementation makes `require('tls')` fail.
            source: r#"
                binding.startLoadingCertificatesOffThread();
                return 'called';
            "#,
            expected: "called",
        },
        Case {
            name: "createNativeKeyObjectClass returns the callback's classes",
            // `keys.js` destructures the result into four classes at module scope
            // and constructs each with a real `KeyObjectHandle`. The base class
            // checks its argument the way Node's `NativeKeyObject::New` does
            // (`CHECK(KeyObjectHandle::HasInstance(...))`), so a real handle is
            // part of the contract and a string is not accepted.
            source: r#"
                const handle = new binding.KeyObjectHandle();
                handle.init(binding.kKeyTypeSecret, Buffer.alloc(16));
                const result = binding.createNativeKeyObjectClass((Base) => {
                  class KeyObject extends Base {
                    constructor(h) { super(h); this.tag = 'keyobject'; }
                  }
                  return [KeyObject];
                });
                const instance = new result[0](handle);
                return result.length + ':' + (instance instanceof result[0]) + ':'
                  + instance.tag;
            "#,
            expected: "1:true:keyobject",
        },
        Case {
            name: "createCryptoKeyClass returns the callback's classes",
            source: r#"
                const result = binding.createCryptoKeyClass((Base) => {
                  class CryptoKey extends Base {}
                  return [CryptoKey];
                });
                return result.length + ':' + typeof result[0];
            "#,
            expected: "1:function",
        },
        Case {
            name: "createX509CertificateClass returns the callback's classes",
            source: r#"
                const result = binding.createX509CertificateClass((Base) => {
                  class X509Certificate extends Base {}
                  return [X509Certificate];
                });
                return result.length + ':' + typeof result[0];
            "#,
            expected: "1:function",
        },
    ]);
    cases.extend([
        Case {
            name: "PBKDF2Job sync run matches RFC 6070",
            // `pbkdf2Sync` builds this job, calls `run()`, and destructures
            // `[error, result]`. Mode 1 is `kCryptoJobSync`.
            source: r#"
                const job = new binding.PBKDF2Job(
                  1, 'password', 'salt', 1000, 32, 'sha256');
                const out = job.run();
                const hex = Array.from(out[1]).map((b) => b.toString(16)
                  .padStart(2, '0')).join('');
                return String(out[0]) + ':' + hex;
            "#,
            // Verified against `crypto.pbkdf2Sync('password','salt',1000,32,'sha256')`
            // on a real node binary.
            expected: "undefined:632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3",
        },
        Case {
            name: "ScryptJob sync run matches node",
            source: r#"
                const job = new binding.ScryptJob(
                  1, 'password', 'salt', 1024, 8, 16, 32 * 1024 * 1024, 32);
                const out = job.run();
                const hex = Array.from(out[1]).map((b) => b.toString(16)
                  .padStart(2, '0')).join('');
                return hex;
            "#,
            expected: "1effd93afcf2b28964026631bf4362b0e5ed83cbd5f326b72eb687bfbc7ac567",
        },
        Case {
            name: "HKDFJob sync run matches RFC 5869 case 1",
            source: r#"
                const ikm = new Uint8Array(22).fill(0x0b);
                const salt = new Uint8Array(13);
                for (let i = 0; i < 13; i += 1) salt[i] = i;
                const info = new Uint8Array(10);
                for (let i = 0; i < 10; i += 1) info[i] = 0xf0 + i;
                const job = new binding.HKDFJob(1, 'sha256', ikm, salt, info, 42);
                const out = job.run();
                const hex = Array.from(out[1]).map((b) => b.toString(16)
                  .padStart(2, '0')).join('');
                return hex;
            "#,
            expected: concat!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865"
            ),
        },
        Case {
            name: "PBKDF2Job reports an error instead of throwing",
            // The sync contract is `[error, result]`, not a throw: `pbkdf2Sync`
            // destructures and throws itself, so a throw here would change the
            // error identity.
            source: r#"
                const job = new binding.PBKDF2Job(
                  1, 'password', 'salt', 1, 8, 'no-such-digest');
                const out = job.run();
                return out[0] instanceof Error ? 'error-first' : 'no-error';
            "#,
            expected: "error-first",
        },
    ]);
    cases.push(Case {
        name: "a digest of the empty input is the published value",
        // FIPS 180-4: SHA-256("") and MD5("").
        source: r#"
            const digest = (algorithm, input) => {
              const handle = new binding.Hash(algorithm, undefined, -1, {});
              handle.update(input);
              return handle.digest('hex');
            };
            return digest('sha256', '') + '|' + digest('md5', '');
        "#,
        expected: concat!(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "|",
            "d41d8cd98f00b204e9800998ecf8427e"
        ),
    });
    cases
}
