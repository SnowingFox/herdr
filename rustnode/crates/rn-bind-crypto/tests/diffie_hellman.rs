//! End-to-end checks for the Diffie-Hellman classes through a real V8 isolate.
//!
//! `lib/internal/crypto/diffiehellman.js` is unchanged Node code, so the only
//! way to know these classes speak the protocol it expects is to run the calls
//! it makes. This installs the `crypto` namespace exactly as
//! `internalBinding('crypto')` would — through `rn-bind-crypto`, because the DH
//! classes are members of that namespace, not a namespace of their own.
//!
//! # One test, many cases
//!
//! V8's platform is process-wide and initialises once, so every case runs from
//! the single `diffie_hellman_end_to_end` test. Same layout as
//! `rn-bind-crypto/tests/binding.rs` and `rn-bind-zlib`.
//!
//! # What is asserted, and against what
//!
//! The expected values are either a published RFC value (the RFC 3526 group
//! widths, the generator) or a property that must hold for any correct
//! implementation (two peers agree, a secret is padded to the prime's width, a
//! group instance has no setters). Nothing here pins a random value: DH keys come
//! from the CSPRNG, so a test that compared them to a constant would be asserting
//! a coincidence.

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
fn diffie_hellman_end_to_end() {
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

    // A bare isolate has no Node globals. `Buffer` is the one the DH methods
    // return through, so it is defined here over `Uint8Array` rather than
    // pulling in `lib/buffer.js`; `isBuffer` only needs to agree with `from`,
    // which is what the cases check.
    let prelude = v8::String::new(
        scope,
        r#"
        globalThis.Buffer = {
          from(value, start, length) {
            if (typeof value === 'string') {
              return new TextEncoder().encode(value);
            }
            if (value && value.byteLength !== undefined) {
              const begin = start === undefined ? 0 : start;
              const end = length === undefined ? value.byteLength : begin + length;
              return new Uint8Array(value.slice
                ? value.slice(begin, end)
                : value.buffer.slice(begin, end));
            }
            return new Uint8Array(value);
          },
          isBuffer(value) {
            return value instanceof Uint8Array && value.__isBuffer === true;
          },
        };
        // Mark anything `Buffer.from` returns as a Buffer, the way the real
        // `Buffer` constructor does, so `isBuffer` is a real check rather than
        // an alias for `instanceof Uint8Array`.
        const originalFrom = Buffer.from;
        Buffer.from = function (...args) {
          const result = originalFrom(...args);
          result.__isBuffer = true;
          return result;
        };
        globalThis.TextEncoder = class TextEncoder {
          encode(text) {
            const bytes = [];
            for (let index = 0; index < text.length; index += 1) {
              bytes.push(text.charCodeAt(index));
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
        "{} of {} Diffie-Hellman cases failed:\n\n{}",
        failures.len(),
        cases().len(),
        failures.join("\n\n")
    );
}

/// Runs `source` wrapped in a try/catch that turns a throw into a tagged string.
fn evaluate(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let wrapped = format!(
        "(function() {{ try {{ {source} }} catch (error) \
         {{ return 'THREW[' + (error && error.code ? error.code : 'nocode') + ']: ' + \
            (error && error.message ? error.message : String(error)); }} }})()"
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

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "buffer shim sanity",
            source: r#"
                const ab = new ArrayBuffer(4);
                const b = Buffer.from(ab, 0, 4);
                return typeof Buffer + ':' + typeof Buffer.from + ':' + typeof b + ':' + b.length;
            "#,
            expected: "object:function:object:4",
        },
        Case {
            name: "both classes exist on the crypto namespace",
            // `diffiehellman.js` destructures `DiffieHellman: _DiffieHellman` and
            // `DiffieHellmanGroup: _DiffieHellmanGroup` at module scope, so a
            // missing one is a TypeError at `require('crypto')` time.
            source: r#"
                const names = ['DiffieHellman', 'DiffieHellmanGroup'];
                const kinds = names.map((name) => typeof binding[name]).join(',');
                return kinds;
            "#,
            expected: "function,function",
        },
        Case {
            name: "modp14's prime is 2048 bits and its generator is 2",
            // RFC 3526 section 3: MODP 2048. A wrong prime is still a usable
            // prime and every derived value would silently change width.
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp14');
                return group.getPrime().length + ':' + group.getGenerator().length +
                       ':' + group.getGenerator()[0];
            "#,
            expected: "256:1:2",
        },
        Case {
            name: "modp5's prime is 1536 bits",
            source: r#"
                return new binding.DiffieHellmanGroup('modp5').getPrime().length;
            "#,
            expected: "192",
        },
        Case {
            name: "group names are case-insensitive",
            // `DHPointer::FindGroup` uses `CaseInsensitiveNameEqual`.
            source: r#"
                return new binding.DiffieHellmanGroup('MODP14').getPrime().length;
            "#,
            expected: "256",
        },
        Case {
            name: "an unknown group is ERR_CRYPTO_UNKNOWN_DH_GROUP",
            source: r#"
                return new binding.DiffieHellmanGroup('unknown-group');
            "#,
            expected: "THREW[ERR_CRYPTO_UNKNOWN_DH_GROUP]: Unknown DH group",
        },
        Case {
            name: "two peers agree on the same padded secret",
            // The core operation. `length` is included because an unpadded
            // secret would be a different length whenever its leading byte is
            // zero, and two peers would then compare unequal.
            source: r#"
                const alice = new binding.DiffieHellmanGroup('modp14');
                const bob = new binding.DiffieHellmanGroup('modp14');
                const alicePublic = alice.generateKeys();
                const bobPublic = bob.generateKeys();
                const a = alice.computeSecret(bobPublic);
                const b = bob.computeSecret(alicePublic);
                const equal = a.length === b.length && a.every((byte, i) => byte === b[i]);
                return equal + ':' + a.length;
            "#,
            expected: "true:256",
        },
        Case {
            name: "generateKeys is idempotent for a consistent pair",
            // `test-crypto-dh-generate-keys.js` case 2: neither key is missing, so
            // nothing is regenerated.
            source: r#"
                const dh = new binding.DiffieHellmanGroup('modp14');
                const first = dh.generateKeys();
                const second = dh.generateKeys();
                const same = first.length === second.length &&
                             first.every((byte, i) => byte === second[i]);
                return same;
            "#,
            expected: "true",
        },
        Case {
            name: "setting a private key changes the public key but not the private one",
            // `test-crypto-dh-generate-keys.js` cases 3 and 4. This is why
            // `generate_keys` recomputes rather than trusting a flag.
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp14');
                const dh = new binding.DiffieHellman(group.getPrime(), 2);
                const stale = dh.generateKeys();
                dh.setPrivateKey(Uint8Array.from([1, 2, 3, 4]));
                const regenerated = dh.generateKeys();
                const changed = stale.length !== regenerated.length ||
                                stale.some((byte, i) => byte !== regenerated[i]);
                const privateKey = dh.getPrivateKey();
                return changed + ':' + privateKey.length + ':' +
                       privateKey[0] + ',' + privateKey[1] + ',' + privateKey[2] + ',' + privateKey[3];
            "#,
            expected: "true:4:1,2,3,4",
        },
        Case {
            name: "a private key alone derives the public key",
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp14');
                const dh = new binding.DiffieHellman(group.getPrime(), 2);
                dh.setPrivateKey(Uint8Array.from([1, 2, 3, 4]));
                const before = (() => {
                  try { dh.getPublicKey(); return 'had-one'; }
                  catch (error) { return error.code; }
                })();
                dh.generateKeys();
                return before + ':' + (dh.getPublicKey().length === 256);
            "#,
            expected: "ERR_CRYPTO_INVALID_STATE:true",
        },
        Case {
            name: "getPublicKey before generateKeys is ERR_CRYPTO_INVALID_STATE",
            // `crypto_dh.cc` reports the argument text as the whole message.
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp14');
                const dh = new binding.DiffieHellman(group.getPrime(), 2);
                return dh.getPublicKey();
            "#,
            expected: "THREW[ERR_CRYPTO_INVALID_STATE]: No public key - did you forget to generate one?",
        },
        Case {
            name: "getPrivateKey before generateKeys is ERR_CRYPTO_INVALID_STATE",
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp14');
                const dh = new binding.DiffieHellman(group.getPrime(), 2);
                return dh.getPrivateKey();
            "#,
            expected: "THREW[ERR_CRYPTO_INVALID_STATE]: No private key - did you forget to generate one?",
        },
        Case {
            name: "computeSecret without a private key is ERR_CRYPTO_INVALID_STATE",
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp14');
                const peer = new binding.DiffieHellmanGroup('modp14');
                const peerPublic = peer.generateKeys();
                const dh = new binding.DiffieHellman(group.getPrime(), 2);
                return dh.computeSecret(peerPublic);
            "#,
            expected: "THREW[ERR_CRYPTO_INVALID_STATE]: Cannot compute shared secret without a private key",
        },
        Case {
            name: "a peer key of 1 is too small",
            source: r#"
                const dh = new binding.DiffieHellmanGroup('modp14');
                dh.generateKeys();
                return dh.computeSecret(Uint8Array.from([1]));
            "#,
            expected: "THREW[ERR_CRYPTO_INVALID_KEYLEN]: Supplied key is too small",
        },
        Case {
            name: "a peer key equal to the prime is too large",
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp14');
                const dh = new binding.DiffieHellman(group.getPrime(), 2);
                dh.generateKeys();
                return dh.computeSecret(group.getPrime());
            "#,
            expected: "THREW[ERR_CRYPTO_INVALID_KEYLEN]: Supplied key is too large",
        },
        Case {
            name: "generating parameters below 2 bits is ERR_OSSL_DH_MODULUS_TOO_SMALL",
            // The code, not just the message: `error::Decorate` builds it from
            // the library's short name (`DH`), which is not the display name
            // (`Diffie-Hellman`) upper-cased.
            source: r#"
                return new binding.DiffieHellman(1, 2);
            "#,
            expected: "THREW[ERR_OSSL_DH_MODULUS_TOO_SMALL]: error:0280007E:Diffie-Hellman routines::modulus too small",
        },
        Case {
            name: "a generator below 2 is ERR_OSSL_DH_BAD_GENERATOR",
            source: r#"
                return new binding.DiffieHellman(64, 1);
            "#,
            expected: "THREW[ERR_OSSL_DH_BAD_GENERATOR]: error:02800065:Diffie-Hellman routines::bad generator",
        },
        Case {
            name: "a negative generator is ERR_OSSL_DH_BAD_GENERATOR, not a huge unsigned one",
            // `crypto_dh.cc` passes the signed value to `BN_set_word`, which
            // rejects it. Casting to `u32` instead would make -1 into
            // 4294967295 and only fail the "below p" rule.
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp14');
                return new binding.DiffieHellman(group.getPrime(), -1);
            "#,
            expected: "THREW[ERR_OSSL_DH_BAD_GENERATOR]: error:02800065:Diffie-Hellman routines::bad generator",
        },
        Case {
            name: "a byte-array generator of 1 is ERR_OSSL_DH_BAD_GENERATOR",
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp14');
                return new binding.DiffieHellman(group.getPrime(), Uint8Array.from([1]));
            "#,
            expected: "THREW[ERR_OSSL_DH_BAD_GENERATOR]: error:02800065:Diffie-Hellman routines::bad generator",
        },
        Case {
            name: "a named group reports verifyError 0 without a primality test",
            // A 2048-bit safe-prime check is milliseconds; `DHPointer::check`
            // skips it for a group so a loop over groups stays fast.
            source: r#"
                return new binding.DiffieHellmanGroup('modp14').verifyError;
            "#,
            expected: "0",
        },
        Case {
            name: "a group prime supplied explicitly also reports 0",
            // `test-crypto-dh-known-groups.js` builds `createDiffieHellman(prime, g)`
            // from each group and asserts this. Without the recognised-group exit
            // the 8192-bit case runs two primality tests and times out.
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp18');
                const dh = new binding.DiffieHellman(group.getPrime(), 2);
                return dh.verifyError;
            "#,
            expected: "0",
        },
        Case {
            name: "verifyError is read-only on the instance",
            // `crypto_dh.cc` installs it with `ReadOnly | DontDelete`.
            source: r#"
                const dh = new binding.DiffieHellmanGroup('modp5');
                const original = dh.verifyError;
                try { dh.verifyError = 99; } catch (error) { /* strict mode throws */ }
                return original === dh.verifyError;
            "#,
            expected: "true",
        },
        Case {
            name: "a group instance has no setters",
            // `test-crypto-dh-group-setters.js`. `DiffieHellmanGroup` is a
            // different template from `DiffieHellman` for exactly this reason.
            source: r#"
                const group = new binding.DiffieHellmanGroup('modp5');
                const full = new binding.DiffieHellman(group.getPrime(), 2);
                return typeof group.setPrivateKey + ',' + typeof group.setPublicKey + ',' +
                       typeof full.setPrivateKey + ',' + typeof full.setPublicKey;
            "#,
            expected: "undefined,undefined,function,function",
        },
        Case {
            name: "results are Buffers, not plain typed arrays",
            // `diffiehellman.js` calls `.toString(encoding)` on them, which a
            // `Uint8Array` does not have.
            source: r#"
                const dh = new binding.DiffieHellmanGroup('modp14');
                const publicKey = dh.generateKeys();
                const prime = dh.getPrime();
                return Buffer.isBuffer(publicKey) + ',' + Buffer.isBuffer(prime) + ',' +
                       Buffer.isBuffer(dh.getGenerator());
            "#,
            expected: "true,true,true",
        },
        Case {
            name: "a 64-bit prime works end to end",
            // Small explicit parameters, which is the `rand_range(p - 3) + 2`
            // branch rather than the fixed-width group branch.
            source: r#"
                // A 64-bit safe prime (p = 2q + 1 for prime q), so verifyError is
                // clean apart from MODULUS_TOO_SMALL.
                const hex = 'fffffffffffffffffffffffffffffffeffffffffffffffff';
                const bytes = Uint8Array.from(hex.match(/../g).map((pair) => parseInt(pair, 16)));
                const alice = new binding.DiffieHellman(bytes, 2);
                const bob = new binding.DiffieHellman(bytes, 2);
                const alicePublic = alice.generateKeys();
                const bobPublic = bob.generateKeys();
                const a = alice.computeSecret(bobPublic);
                const b = bob.computeSecret(alicePublic);
                const equal = a.length === b.length && a.every((byte, i) => byte === b[i]);
                return equal;
            "#,
            expected: "true",
        },
    ]
}

/// Every `MEMBERS` entry this crate installs is on the `crypto` namespace.
///
/// Checks the crate's exported list against the parent crate's, so a rename in
/// one place and not the other is a compile-or-test failure rather than a member
/// that silently disappears from `internalBinding('crypto')`.
#[test]
fn the_installed_members_are_declared_by_the_parent_namespace() {
    use rn_core::BindingModule;

    let parent: std::collections::BTreeSet<&str> = Crypto.members().iter().copied().collect();
    for member in rn_bind_crypto_dh::MEMBERS {
        assert!(
            parent.contains(member),
            "{member} is installed by rn-bind-crypto-dh but is not in rn-bind-crypto's MEMBERS"
        );
    }
    // And the reverse: a name the parent claims must be one of these two or
    // installed by rn-bind-crypto itself, which `rn-compat` checks. This guards
    // only the pair this crate is responsible for.
    assert_eq!(
        rn_bind_crypto_dh::MEMBERS,
        &["DiffieHellman", "DiffieHellmanGroup"]
    );
}
