//! End-to-end cipher checks through a real V8 isolate, and the negative control.
//!
//! `lib/internal/crypto/cipher.js` and `lib/internal/crypto/aes.js` are unchanged
//! Node code, so the only way to know this crate speaks the right protocol is to
//! install the namespace the way `internalBinding('crypto')` does and then drive
//! the classes from JavaScript.
//!
//! # Why one test with many cases
//!
//! V8's platform and global state are process-wide and can only be initialised
//! once, so every case runs from a single `#[test]`. A second isolate in a second
//! test would panic on the already-initialised platform, which is why
//! `rn-bind-crypto` and `rn-bind-zlib` are laid out the same way.
//!
//! # The negative control
//!
//! The task requires a control that fails before the change and passes after.
//! Because this crate *is* the change, the control is written as the assertion
//! that the class exists and constructs:
//!
//! ```text
//! new CipherBase(true, 'aes-256-gcm', key, iv, 16)
//! ```
//!
//! Before this crate landed, `CipherBase` was absent from the namespace, so the
//! expression threw `TypeError: CipherBase is not a constructor`. Run it against
//! the pre-change binary to observe that; the harness script
//! `tools/cipher-negative-control.sh` does exactly that and refuses to report a
//! pass unless the binary under test was built successfully in the same
//! invocation, so a stale binary cannot produce a false pass.

use rn_bind_crypto_cipher::{install_classes, MEMBERS};
use rn_v8_sys::v8;

/// One named case: what to evaluate and what it must produce.
struct Case {
    name: &'static str,
    source: &'static str,
    expected: &'static str,
    /// A second expression to evaluate after a microtask checkpoint.
    ///
    /// Needed only for a case that observes a promise: the job settles the
    /// promise inline, but its `then` callback is a microtask, so reading the
    /// result requires a checkpoint between the two phases. Every other case
    /// leaves this `None` and is judged on `source` alone.
    settle: Option<&'static str>,
}

#[test]
fn cipher_binding_end_to_end() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    // The classes land on a plain object here rather than on `rn-bind-crypto`'s
    // namespace, because installing that whole namespace would pull in every
    // other member and make a cipher failure look like a hashing failure.
    let target = v8::Object::new(scope);
    install_classes(scope, target).expect("install CipherBase and AESCipherJob");

    let global = scope.get_current_context().global(scope);
    let name = v8::String::new(scope, "binding").expect("allocate the binding name");
    global.set(scope, name.into(), target.into());

    // A bare isolate has no Node globals. `Buffer` is the only one the cases
    // need, so it is defined here over `Uint8Array` rather than pulling in
    // `lib/buffer.js`: everything under test is the binding, not the shim.
    let prelude = v8::String::new(
        scope,
        r#"
        globalThis.Buffer = {
          // The binding emits a result as `Buffer.from(arrayBuffer, 0, length)`,
          // so the three-argument form has to work; the one-argument form is
          // what the cases use to build inputs.
          from(bytes, offset, length) {
            if (offset !== undefined) {
              return new Uint8Array(bytes, offset, length);
            }
            return Uint8Array.from(bytes, (b) => b);
          },
          alloc(size, fill) {
            const out = new Uint8Array(size);
            if (fill !== undefined) out.fill(fill);
            return out;
          },
        };
        globalThis.hex = (bytes) =>
          Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
        // A bare isolate has neither `TextEncoder` nor `TextDecoder`, so both
        // directions are spelled out. Only ASCII and two-byte sequences are
        // needed by these cases.
        globalThis.utf8 = (value) => {
          const out = [];
          for (const character of value) {
            const code = character.codePointAt(0);
            if (code < 0x80) {
              out.push(code);
            } else if (code < 0x800) {
              out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
            } else {
              out.push(0xe0 | (code >> 12),
                       0x80 | ((code >> 6) & 0x3f),
                       0x80 | (code & 0x3f));
            }
          }
          return Uint8Array.from(out);
        };
        globalThis.text = (bytes) => {
          let output = '';
          for (let index = 0; index < bytes.length;) {
            const byte = bytes[index];
            if (byte < 0x80) { output += String.fromCharCode(byte); index += 1; }
            else if (byte < 0xe0) {
              output += String.fromCharCode(((byte & 0x1f) << 6) | (bytes[index + 1] & 0x3f));
              index += 2;
            } else {
              output += String.fromCharCode(((byte & 0x0f) << 12) |
                                            ((bytes[index + 1] & 0x3f) << 6) |
                                            (bytes[index + 2] & 0x3f));
              index += 3;
            }
          }
          return output;
        };
        globalThis.concat = (...parts) => {
          const total = parts.reduce((sum, part) => sum + part.length, 0);
          const out = new Uint8Array(total);
          let offset = 0;
          for (const part of parts) { out.set(part, offset); offset += part.length; }
          return out;
        };
        globalThis.equalBytes = (a, b) => {
          if (a.length !== b.length) return false;
          for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
          return true;
        };
        "#,
    )
    .expect("allocate the prelude");
    scope.get_current_context().global(scope).set(
        scope,
        v8::String::new(scope, "prelude")
            .expect("prelude name")
            .into(),
        prelude.into(),
    );
    let _ = v8::Script::compile(scope, prelude, None)
        .and_then(|script| script.run(scope))
        .expect("run the test prelude");

    // Published vectors and values cross-checked against a real `node` binary.
    // Where a value is from a standard the comment says which.
    let cases = [
        // The negative control: before this crate landed, `CipherBase` was not a
        // constructor at all, so this threw and every case below failed with it.
        Case {
            name: "CipherBase is a constructor",
            source: "typeof binding.CipherBase",
            expected: "function",
            settle: None,
        },
        Case {
            name: "AESCipherJob is a constructor",
            source: "typeof binding.AESCipherJob",
            expected: "function",
            settle: None,
        },
        Case {
            name: "CipherBase has the six prototype methods",
            source: "['update','final','setAutoPadding','getAuthTag','setAuthTag','setAAD']\
                     .filter((m) => typeof binding.CipherBase.prototype[m] === 'function').length",
            expected: "6",
            settle: None,
        },
        // AESCipherJob's prototype has `run`, which is what `jobPromise` calls.
        Case {
            name: "AESCipherJob has run",
            source: "typeof binding.AESCipherJob.prototype.run",
            expected: "function",
            settle: None,
        },
        // AES-128 block cipher: FIPS 197 appendix C.1.
        Case {
            name: "aes-128-ecb known-answer (FIPS 197 C.1)",
            source: r#"(() => {
                const key = Buffer.from([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]);
                const plaintext = Buffer.from([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                                               0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff]);
                const cipher = new binding.CipherBase(true, 'aes-128-ecb', key, null, -1);
                // A block cipher pads by default; the published vector assumes it
                // does not.
                cipher.setAutoPadding(false);
                const out = concat(cipher.update(plaintext), cipher.final());
                return hex(out);
            })()"#,
            expected: "69c4e0d86a7b0430d8cdb78070b4c55a",
            settle: None,
        },
        // AES-128-CBC: NIST SP 800-38A F.2.1.
        Case {
            name: "aes-128-cbc known-answer (SP 800-38A F.2.1)",
            source: r#"(() => {
                const key = Buffer.from([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                                         0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]);
                const iv = Buffer.from([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]);
                const plaintext = Buffer.from([0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                                               0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a]);
                const cipher = new binding.CipherBase(true, 'aes-128-cbc', key, iv, -1);
                cipher.setAutoPadding(false);
                return hex(concat(cipher.update(plaintext), cipher.final()));
            })()"#,
            expected: "7649abac8119b246cee98e9b12e9197d",
            settle: None,
        },
        // The same cipher in reverse: a decipher must recover the plaintext.
        Case {
            name: "aes-128-cbc decrypts its own output",
            source: r#"(() => {
                const key = Buffer.from([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                                         0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]);
                const iv = Buffer.from([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]);
                const plaintext = utf8('round trip through the real handle');
                const cipher = new binding.CipherBase(true, 'aes-128-cbc', key, iv, -1);
                const ciphertext = concat(cipher.update(plaintext), cipher.final());
                const decipher = new binding.CipherBase(false, 'aes-128-cbc', key, iv, -1);
                const recovered = concat(decipher.update(ciphertext), decipher.final());
                return text(recovered) + '|' + equalBytes(recovered, plaintext);
            })()"#,
            expected: "round trip through the real handle|true",
            settle: None,
        },
        // GCM with a real tag: the tag has to come back from getAuthTag and be
        // accepted by a decipher, and the tag length has to be per-instance.
        Case {
            name: "aes-256-gcm round trip with a real tag",
            source: r#"(() => {
                const key = Buffer.alloc(32, 1);
                const iv = Buffer.alloc(12, 2);
                const plaintext = utf8('authenticated payload');
                const cipher = new binding.CipherBase(true, 'aes-256-gcm', key, iv, 16);
                const ciphertext = concat(cipher.update(plaintext), cipher.final());
                const tag = cipher.getAuthTag();
                const decipher = new binding.CipherBase(false, 'aes-256-gcm', key, iv, 16);
                if (!decipher.setAuthTag(tag)) return 'setAuthTag refused';
                const recovered = concat(decipher.update(ciphertext), decipher.final());
                return tag.length + '|' + text(recovered);
            })()"#,
            expected: "16|authenticated payload",
            settle: None,
        },
        // A wrong tag must fail at final(), not return bytes.
        Case {
            name: "aes-256-gcm rejects a wrong tag",
            source: r#"(() => {
                const key = Buffer.alloc(32, 1);
                const iv = Buffer.alloc(12, 2);
                const decipher = new binding.CipherBase(false, 'aes-256-gcm', key, iv, 16);
                decipher.setAuthTag(Buffer.alloc(16, 0xff));
                decipher.update(Buffer.alloc(16, 0));
                try { decipher.final(); return 'no throw'; }
                catch (error) { return error.message; }
            })()"#,
            expected: "Unsupported state or unable to authenticate data",
            settle: None,
        },
        // AAD participates in the tag: the same ciphertext with different AAD
        // must not authenticate.
        Case {
            name: "aes-256-gcm AAD is authenticated",
            source: r#"(() => {
                const key = Buffer.alloc(32, 1);
                const iv = Buffer.alloc(12, 2);
                const cipher = new binding.CipherBase(true, 'aes-256-gcm', key, iv, 16);
                cipher.setAAD(utf8('header'), -1);
                const ciphertext = concat(cipher.update(utf8('body')), cipher.final());
                const tag = cipher.getAuthTag();
                const decipher = new binding.CipherBase(false, 'aes-256-gcm', key, iv, 16);
                decipher.setAAD(utf8('different'), -1);
                decipher.setAuthTag(tag);
                decipher.update(ciphertext);
                try { decipher.final(); return 'no throw'; }
                catch { return 'rejected'; }
            })()"#,
            expected: "rejected",
            settle: None,
        },
        // ChaCha20-Poly1305 with AAD: RFC 8439 section 2.8.2, the published
        // ciphertext and tag, both compared in full.
        Case {
            name: "chacha20-poly1305 known-answer (RFC 8439 2.8.2)",
            source: r#"(() => {
                const key = Buffer.from([
                  0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
                  0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
                  0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
                  0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f]);
                const nonce = Buffer.from([0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47]);
                const aad = Buffer.from([0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7]);
                const plaintext = utf8(
                  "Ladies and Gentlemen of the class of '99: If I could offer you " +
                  "only one tip for the future, sunscreen would be it.");
                const cipher = new binding.CipherBase(true, 'chacha20-poly1305', key, nonce, 16);
                cipher.setAAD(aad, -1);
                const ciphertext = concat(cipher.update(plaintext), cipher.final());
                const tag = cipher.getAuthTag();
                return hex(ciphertext) + '|' + hex(tag);
            })()"#,
            expected: "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116|1ae10b594f09e26a7e902ecbd0600691",
            settle: None,
        },
        // A stream cipher produces output for a partial final block and applies
        // no padding: the output length equals the input length.
        Case {
            name: "aes-256-ctr has no padding",
            source: r#"(() => {
                const key = Buffer.alloc(32, 3);
                const iv = Buffer.alloc(16, 4);
                const plaintext = utf8('seventeen bytes!!');
                const cipher = new binding.CipherBase(true, 'aes-256-ctr', key, iv, -1);
                const ciphertext = concat(cipher.update(plaintext), cipher.final());
                return ciphertext.length + '/' + plaintext.length;
            })()"#,
            expected: "17/17",
            settle: None,
        },
        // The incremental path: many small updates must equal one big one, which
        // only holds if the context is genuinely streaming.
        Case {
            name: "multi-chunk update equals one-shot update",
            source: r#"(() => {
                const key = Buffer.alloc(32, 5);
                const iv = Buffer.alloc(16, 6);
                const payload = new Uint8Array(4096);
                for (let i = 0; i < payload.length; i += 1) payload[i] = (i * 7) & 0xff;

                const oneShot = new binding.CipherBase(true, 'aes-256-cbc', key, iv, -1);
                const single = concat(oneShot.update(payload), oneShot.final());

                const incremental = new binding.CipherBase(true, 'aes-256-cbc', key, iv, -1);
                const parts = [];
                for (let offset = 0; offset < payload.length; offset += 37) {
                  parts.push(incremental.update(payload.subarray(offset, offset + 37)));
                }
                parts.push(incremental.final());
                return equalBytes(single, concat(...parts));
            })()"#,
            expected: "true",
            settle: None,
        },
        // A one-shot cipher (XTS) must refuse a partial unit, keep its one-shot
        // slot unspent, and then accept the whole message.
        Case {
            name: "aes-128-xts refuses a partial unit and accepts a whole one",
            source: r#"(() => {
                const key = Buffer.alloc(32);
                for (let i = 16; i < 32; i += 1) key[i] = 1;
                const iv = Buffer.alloc(16, 7);
                const partial = new binding.CipherBase(true, 'aes-128-xts', key, iv, -1);
                let message = '';
                try { partial.update(Buffer.alloc(15)); } catch (error) { message = error.message; }
                // A fresh handle must accept the whole data unit, and produce one
                // byte of output per input byte.
                const whole = new binding.CipherBase(true, 'aes-128-xts', key, iv, -1);
                const out = concat(whole.update(Buffer.alloc(17, 9)), whole.final());
                return message + '|' + out.length;
            })()"#,
            expected: "Trying to add data in unsupported state|17",
            settle: None,
        },
        // `ctsMode` on a cipher that does not implement CTS is
        // ERR_CRYPTO_UNSUPPORTED_OPERATION, which the pinned test asserts.
        Case {
            name: "ctsMode on plain CBC is unsupported",
            source: r#"(() => {
                try {
                  new binding.CipherBase(true, 'aes-128-cbc', Buffer.alloc(16),
                                         Buffer.alloc(16), -1, 'CS1');
                  return 'no throw';
                } catch (error) { return error.code; }
            })()"#,
            expected: "ERR_CRYPTO_UNSUPPORTED_OPERATION",
            settle: None,
        },
        // AES-KW: RFC 3394 section 4.1, the 128-bit key and data vector.
        Case {
            name: "aes-128-wrap known-answer (RFC 3394 4.1)",
            source: r#"(() => {
                const key = Buffer.from([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]);
                const iv = Buffer.alloc(8, 0xa6);
                const plaintext = Buffer.from([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                                               0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff]);
                const cipher = new binding.CipherBase(true, 'aes-128-wrap', key, iv, -1);
                return hex(concat(cipher.update(plaintext), cipher.final()));
            })()"#,
            expected: "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
            settle: None,
        },
        // Error shapes: the `code` and message a caller branches on.
        Case {
            name: "unknown cipher",
            source: r#"(() => {
                try { new binding.CipherBase(true, 'aes-127', Buffer.alloc(16), null, -1); return 'no throw'; }
                catch (error) { return error.code + '|' + error.message; }
            })()"#,
            expected: "ERR_CRYPTO_UNKNOWN_CIPHER|Unknown cipher",
            settle: None,
        },
        Case {
            name: "wrong key length",
            source: r#"(() => {
                try { new binding.CipherBase(true, 'aes-128-ecb', Buffer.alloc(17), null, -1); return 'no throw'; }
                catch (error) { return error.code + '|' + error.name; }
            })()"#,
            expected: "ERR_CRYPTO_INVALID_KEYLEN|RangeError",
            settle: None,
        },
        Case {
            name: "missing IV",
            source: r#"(() => {
                try { new binding.CipherBase(true, 'aes-128-cbc', Buffer.alloc(16), null, -1); return 'no throw'; }
                catch (error) { return error.code + '|' + error.name; }
            })()"#,
            expected: "ERR_CRYPTO_INVALID_IV|TypeError",
            settle: None,
        },
        // A second `final()` is ERR_CRYPTO_INVALID_STATE, not a second block.
        Case {
            name: "second final is an invalid state",
            source: r#"(() => {
                const cipher = new binding.CipherBase(true, 'aes-128-cbc',
                                                      Buffer.alloc(16), Buffer.alloc(16), -1);
                cipher.update(Buffer.alloc(16));
                cipher.final();
                try { cipher.final(); return 'no throw'; }
                catch (error) { return error.code + '|' + error.message; }
            })()"#,
            expected: "ERR_CRYPTO_INVALID_STATE|Invalid state",
            settle: None,
        },
        // AESCipherJob: AES-128-CBC through the WebCrypto job path, matching
        // `crypto.subtle.encrypt` exactly. The key handle is the duck-typed
        // shape `lib/internal/crypto/keys.js` exposes.
        Case {
            name: "AESCipherJob AES-128-CBC matches subtle",
            source: r#"(() => {
                const handle = {
                  getKeyType() { return 1; },
                  export() {
                    return Buffer.from([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]);
                  },
                };
                const job = new binding.AESCipherJob(1, 1, handle,
                  Buffer.from([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                               0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff]),
                  3, Buffer.alloc(16, 0));
                globalThis.jobResult = 'unresolved';
                job.run().then((value) => { globalThis.jobResult = hex(value); });
                return 'scheduled';
            })()"#,
            // `run()` settles the promise inline for every mode; the `then`
            // callback is a microtask, so the value is read in the settle phase,
            // which is where the comparison happens.
            expected: "scheduled",
            settle: Some(
                "globalThis.jobResult === \
                 '69c4e0d86a7b0430d8cdb78070b4c55a9e978e6d16b086570ef794ef97984232' \
                 ? 'cbc job matches subtle' : globalThis.jobResult",
            ),
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        let mut expected = case.expected;
        let actual = evaluate(scope, case.source);
        let actual = match (actual.as_deref(), case.settle) {
            (Some(first), Some(second)) if first == case.expected => {
                // The settle expression is the verdict itself, so it decides
                // both the value and what it is compared against.
                expected = "cbc job matches subtle";
                evaluate(scope, second)
            }
            (other, _) => other.map(str::to_string),
        };
        if actual.as_deref() != Some(expected) {
            failures.push(format!(
                "{}: expected {:?}, got {:?}",
                case.name, expected, actual
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} cipher case(s) failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Compiles and runs one expression, returning its value as a string.
///
/// A thrown exception becomes its own message so a failing case reports *why*
/// rather than "no value", which is what makes a control useful. The `TryCatch`
/// is required for the same reason: without one a thrown exception leaves the
/// isolate dirty and every later case fails for an unrelated reason.
fn evaluate(scope: &mut v8::PinScope<'_, '_>, source: &str) -> Option<String> {
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let text = v8::String::new(scope, source)?;
    let value = v8::Script::compile(scope, text, None).and_then(|script| script.run(scope));
    if scope.has_caught() || value.is_none() {
        let exception = scope
            .exception()
            .map(|value| value.to_rust_string_lossy(scope))
            .unwrap_or_else(|| "unknown exception".to_string());
        return Some(exception);
    }
    // Deliver queued microtasks so a promise a case observes is settled. The
    // job resolves inline, so this is what makes `then` run before the value is
    // read — the same ordering the event loop would give between turns.
    scope.perform_microtask_checkpoint();
    value.map(|value| value.to_rust_string_lossy(scope))
}

#[test]
fn installed_members_are_the_two_classes_and_get_cipher_info() {
    // `getCiphers` and `getSSLCiphers` are `rn-bind-crypto`'s, not this crate's:
    // registering them twice would replace a working function. `getCipherInfo`
    // *is* this crate's because it lives in `crypto_cipher.cc`, but the parent
    // crate's `DEFERRED` list still names it, so the coordinator moves that one
    // entry at merge time.
    assert_eq!(MEMBERS, &["CipherBase", "AESCipherJob", "getCipherInfo"]);
}
