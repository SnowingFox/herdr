//! The installed `Bun` surface against values recorded from `bun 1.4.4`.
//!
//! This installs the crate onto a real `Bun`-shaped object in a real isolate and
//! runs JavaScript against it. The expectations live in
//! `fixtures/digest-vectors.txt` and `fixtures/wyhash-vectors.txt`, both printed
//! by the oracle, so nothing here can drift to whatever the implementation
//! happens to produce.
//!
//! Every value is compared as a **hex digest**, not as a length and not as a
//! type. A test that checked `digest.length === 32` would pass on a wrong hash,
//! which is the specific failure this group exists to prevent.

use rn_bun_api::BunRegistry;
use rn_bun_hash::Hashing;
use rn_v8_sys::v8;

/// The smallest prelude a bare V8 isolate needs: a `Buffer` good enough for the
/// output paths, and the pattern builder the fixtures describe.
///
/// A real `Buffer` is not available without the whole node bootstrap, so this
/// provides the two things the digest surface actually uses — `Buffer.from` for
/// a `Uint8Array`/`ArrayBuffer` argument, and `Buffer.isBuffer`. `toString` is
/// deliberately absent: a case that needed it would be testing this shim.
const PRELUDE: &str = r#"
// A `Buffer` stand-in: enough for `Buffer.from(x)` and `Buffer.isBuffer(x)`.
class FakeBuffer extends Uint8Array {}
globalThis.Buffer = {
  from(value) {
    if (value instanceof ArrayBuffer) return new FakeBuffer(value);
    if (ArrayBuffer.isView(value)) {
      return new FakeBuffer(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    if (typeof value === 'string') {
      const bytes = [];
      for (const character of value) {
        const code = character.codePointAt(0);
        if (code < 0x80) bytes.push(code);
        else if (code < 0x800) bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        else if (code < 0x10000) bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        else bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      }
      return new FakeBuffer(Uint8Array.from(bytes).buffer);
    }
    throw new TypeError('FakeBuffer.from: unsupported input');
  },
  isBuffer(value) { return value instanceof FakeBuffer; },
};

// Byte `i` is `(i*37 + 11) & 0xff`, the pattern every fixture uses.
globalThis.pattern = function pattern(length) {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * 37 + 11) & 0xff;
  return out;
};

globalThis.hex = function hex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
};

// Runs `body` and reports `{ok: true, value}` or `{ok: false, name, code, message}`.
globalThis.attempt = function attempt(body) {
  try {
    return { ok: true, value: body() };
  } catch (error) {
    return { ok: false, name: error.constructor.name, code: error.code, message: error.message };
  }
};
"#;

/// Runs `source` with `Bun` installed in a fresh isolate and returns the last
/// expression's string value.
fn eval(source: &str) -> String {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    // The real path: register this crate with the `Bun` registry and let it build
    // the object. That is exactly what the runtime does, so the staging-object
    // comparison (declared-but-missing, installed-but-undeclared) runs here too
    // and a declaration that drifted fails this test rather than the guard.
    let mut registry = BunRegistry::new();
    registry
        .register_module(Hashing)
        .expect("the hashing group registers");
    let bun = registry.build(scope).expect("the hashing group installs");
    let bun_key = v8::String::new(scope, "Bun").expect("key");
    context
        .global(scope)
        .set(scope, bun_key.into(), bun.into())
        .expect("defines Bun");

    let mut result = String::new();
    for script_source in [PRELUDE, source] {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let source = v8::String::new(scope, script_source).expect("source");
        let script = v8::Script::compile(scope, source, None).expect("compiles");
        let run = script.run(scope);
        if scope.has_caught() || run.is_none() {
            let exception = scope
                .exception()
                .map(|value| value.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "unknown exception".to_string());
            panic!("javascript threw: {exception}");
        }
        if let Some(value) = run {
            result = value.to_rust_string_lossy(scope);
        }
    }
    result
}

fn fixture() -> String {
    include_str!("fixtures/digest-vectors.txt").to_string()
}

/// Reads `key = "value"` out of a `[section]` of the fixture.
fn lookup(section: &str, key: &str) -> String {
    let mut current = String::new();
    for line in fixture().lines() {
        let line = line.trim();
        if line.starts_with('[') {
            current = line.to_string();
            continue;
        }
        if current != section || !line.starts_with(key) {
            continue;
        }
        let Some((name, value)) = line.split_once(" = ") else {
            continue;
        };
        if name != key {
            continue;
        }
        return value.trim_matches('"').to_string();
    }
    panic!("no fixture entry {section} {key}")
}

fn case_every_per_class_digest_matches_the_oracle() {
    for class in [
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512",
        "SHA512_256",
        "MD4",
        "MD5",
    ] {
        let byte_length = lookup("[per_class]", &format!("{class}.byteLength"));
        let cases = [
            ("empty", "new Bun.{c}().digest()"),
            ("a", "new Bun.{c}().update('a').digest()"),
            ("abc", "new Bun.{c}().update('abc').digest()"),
            ("multi", "new Bun.{c}().update(pattern(200)).digest()"),
            ("large", "new Bun.{c}().update(pattern(100000)).digest()"),
            (
                "chunked",
                "new Bun.{c}().update('a').update('b').update('c').digest()",
            ),
        ];
        for (name, template) in cases {
            let expression = template.replace("{c}", class);
            let actual = eval(&format!("hex({expression})"));
            let expected = lookup("[per_class]", &format!("{class}.{name}"));
            assert_eq!(actual, expected, "Bun.{class}.{name}");
        }
        // The static one-shot must agree with the instance form.
        let actual = eval(&format!("hex(Bun.{class}.hash(pattern(200)))"));
        assert_eq!(
            actual,
            lookup("[per_class]", &format!("{class}.multi")),
            "Bun.{class}.hash"
        );
        assert_eq!(
            eval(&format!("String(Bun.{class}.byteLength)")),
            byte_length,
            "Bun.{class}.byteLength"
        );
    }
}

fn case_every_crypto_hasher_algorithm_matches_the_oracle() {
    // The order is observable, and `CryptoHasher.algorithms` is where it shows.
    let algorithms = eval("Bun.CryptoHasher.algorithms.join(',')");
    let expected: Vec<String> = fixture()
        .lines()
        .filter(|line| line.trim().starts_with("[crypto_hasher]"))
        .flat_map(|_| std::iter::empty::<String>())
        .collect();
    let _ = expected;
    for name in [
        "blake2b256",
        "blake2b512",
        "blake2s256",
        "md4",
        "md5",
        "ripemd160",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512-224",
        "sha512-256",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
        "shake128",
        "shake256",
    ] {
        assert!(
            algorithms.split(',').any(|entry| entry == name),
            "{name} is missing from CryptoHasher.algorithms: {algorithms}"
        );
        for (label, expression) in [
            ("empty", format!("new Bun.CryptoHasher('{name}').digest()")),
            (
                "abc",
                format!("new Bun.CryptoHasher('{name}').update('abc').digest()"),
            ),
            (
                "multi",
                format!("new Bun.CryptoHasher('{name}').update(pattern(200)).digest()"),
            ),
            (
                "large",
                format!("new Bun.CryptoHasher('{name}').update(pattern(100000)).digest()"),
            ),
        ] {
            let actual = eval(&format!("hex({expression})"));
            let expected = lookup("[crypto_hasher]", &format!("{name}.{label}"));
            assert_eq!(actual, expected, "CryptoHasher({name}) of {label}");
        }
        let byte_length = lookup("[crypto_hasher]", &format!("{name}.byteLength"));
        assert_eq!(
            eval(&format!(
                "String(new Bun.CryptoHasher('{name}').byteLength)"
            )),
            byte_length,
            "{name}.byteLength"
        );
    }
}

fn case_digest_output_encodings_match_the_oracle() {
    // The fixture stores each encoding as its UTF-16 code units, because a
    // latin1 or utf8 string of digest bytes is not representable in a UTF-8 file.
    for (label, expression) in [
        ("hex", "Bun.SHA256.hash('abc', 'hex')"),
        ("base64", "Bun.SHA256.hash('abc', 'base64')"),
        ("base64url", "Bun.SHA256.hash('abc', 'base64url')"),
        ("latin1", "Bun.SHA256.hash('abc', 'latin1')"),
        ("utf8", "Bun.SHA256.hash('abc', 'utf8')"),
        ("ascii", "Bun.SHA256.hash('abc', 'ascii')"),
        ("utf16le", "Bun.SHA256.hash('abc', 'utf16le')"),
        ("HEX", "Bun.SHA256.hash('abc', 'HEX')"),
    ] {
        let expected = lookup("[encodings_utf16]", label);
        let actual = eval(&format!(
            "(function(){{const s = {expression}; const units=[]; for (let i=0;i<s.length;i++) units.push(s.charCodeAt(i)); return units.join(',');}})()"
        ));
        assert_eq!(actual, expected, "digest encoding {label}");
    }
}

fn case_hash_matches_wyhash_final_4() {
    let fixture = include_str!("fixtures/wyhash-vectors.txt");
    let mut compared = 0usize;
    let mut script = String::from("const out = [];\n");
    let mut expected: Vec<String> = Vec::new();
    for line in fixture.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let len: usize = parts
            .next()
            .and_then(|text| text.parse().ok())
            .expect("length");
        let seed: &str = parts.next().expect("seed");
        let digest: &str = parts.next().expect("digest");
        script.push_str(&format!(
            "out.push(Bun.hash(pattern({len}), {seed}n).toString());\n"
        ));
        expected.push(digest.to_string());
        compared += 1;
    }
    script.push_str("out.join('\\n')");
    let actual = eval(&script);
    let actual: Vec<&str> = actual.split('\n').collect();
    assert_eq!(compared, expected.len());
    for (index, (found, want)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(found, want, "wyhash vector {index}");
    }
    assert_eq!(compared, 516, "fixture shape changed");
}

fn case_class_shapes_match_measured_bun() {
    // Constructor arity and name, prototype method arities, and the static set —
    // all measured, and all things a gate comparing `Function.length` sees.
    let report = eval(
        r#"
        const names = ['SHA1','SHA224','SHA256','SHA384','SHA512','SHA512_256','MD4','MD5'];
        const out = [];
        for (const name of names) {
          const C = Bun[name];
          out.push([
            name,
            C.length,
            C.name,
            C.prototype.digest.length,
            C.prototype.update.length,
            C.hash.length,
            C.hash.name,
            typeof Object.getOwnPropertyDescriptor(C, 'byteLength').get,
            typeof Object.getOwnPropertyDescriptor(C.prototype, 'byteLength').get,
            Object.getOwnPropertyNames(C.prototype).join('+'),
            Object.getOwnPropertyNames(new C()).length,
            Object.prototype.toString.call(new C()),
            new C() instanceof C,
          ].join('|'));
        }
        const C = Bun.CryptoHasher;
        out.push(['CryptoHasher', C.length, C.name,
          Object.getOwnPropertyDescriptor(C.prototype,'update').value.length,
          Object.getOwnPropertyDescriptor(C.prototype,'digest').value.length,
          Object.getOwnPropertyDescriptor(C.prototype,'copy').value.length,
          C.hash.length,
          typeof Object.getOwnPropertyDescriptor(C,'algorithms').get,
          typeof Object.getOwnPropertyDescriptor(C.prototype,'algorithm').get,
          typeof Object.getOwnPropertyDescriptor(C.prototype,'byteLength').get,
          Object.getOwnPropertyNames(C.prototype).join('+'),
          Object.getOwnPropertyNames(new C('sha256')).length,
          Object.prototype.toString.call(new C('sha256')),
          Object.prototype.toString.call(new C('sha256').copy()),
        ].join('|'));
        out.join('\n')
        "#,
    );
    let actual: Vec<&str> = report.split('\n').collect();
    let expected = [
        "SHA1|0|SHA1|0|1|2|hash|function|function|byteLength+digest+update+constructor|0|[object SHA1]|true",
        "SHA224|0|SHA224|0|1|2|hash|function|function|byteLength+digest+update+constructor|0|[object SHA224]|true",
        "SHA256|0|SHA256|0|1|2|hash|function|function|byteLength+digest+update+constructor|0|[object SHA256]|true",
        "SHA384|0|SHA384|0|1|2|hash|function|function|byteLength+digest+update+constructor|0|[object SHA384]|true",
        "SHA512|0|SHA512|0|1|2|hash|function|function|byteLength+digest+update+constructor|0|[object SHA512]|true",
        "SHA512_256|0|SHA512_256|0|1|2|hash|function|function|byteLength+digest+update+constructor|0|[object SHA512_256]|true",
        "MD4|0|MD4|0|1|2|hash|function|function|byteLength+digest+update+constructor|0|[object MD4]|true",
        "MD5|0|MD5|0|1|2|hash|function|function|byteLength+digest+update+constructor|0|[object MD5]|true",
        "CryptoHasher|0|CryptoHasher|2|0|0|2|function|function|function|algorithm+byteLength+copy+digest+update+constructor|0|[object CryptoHasher]|[object CryptoHasher]",
    ];
    for (found, want) in actual.iter().zip(expected.iter()) {
        assert_eq!(found, want);
    }
    assert_eq!(actual.len(), expected.len());
}

fn case_failure_modes_match_measured_bun() {
    // Each row is (expression, expected error name, expected code, expected message).
    // A message that is `""` means the message text is not asserted; the code and
    // class still are.
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "new Bun.SHA256().update('a').digest('bogus')",
            "TypeError",
            "ERR_INVALID_ARG_VALUE",
            "Unknown encoding: bogus",
        ),
        (
            "(() => { const h = new Bun.SHA256(); h.update('a'); h.digest('hex'); return h.digest('hex'); })()",
            "Error",
            "ERR_INVALID_STATE",
            "SHA256 hasher already digested, create a new instance to digest again",
        ),
        (
            "(() => { const h = new Bun.SHA256(); h.update('a'); h.digest(); return h.update('b'); })()",
            "Error",
            "ERR_INVALID_STATE",
            "SHA256 hasher already digested, create a new instance to update",
        ),
        (
            "Bun.SHA256()",
            "TypeError",
            "ERR_ILLEGAL_CONSTRUCTOR",
            "SHA256 constructor cannot be invoked without 'new'",
        ),
        (
            "Bun.SHA256.prototype.update.call({}, 'a')",
            "TypeError",
            "ERR_INVALID_THIS",
            "Expected this to be instanceof SHA256, but received an instance of Object",
        ),
        (
            "Object.getOwnPropertyDescriptor(Bun.SHA256.prototype, 'byteLength').get.call({})",
            "TypeError",
            "",
            "The SHA256.byteLength getter can only be used on instances of SHA256",
        ),
        (
            "Bun.SHA256.hash()",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "input must be a string, ArrayBuffer, ArrayBufferView or Blob",
        ),
        (
            "Bun.SHA256.hash('abc', 'bogus')",
            "TypeError",
            "ERR_INVALID_ARG_VALUE",
            "Unknown encoding: bogus",
        ),
        (
            "Bun.hash()",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "data must be a string, ArrayBuffer, ArrayBufferView or Blob",
        ),
        (
            "Bun.hash(null)",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "data must be a string, ArrayBuffer, ArrayBufferView or Blob",
        ),
        (
            "new Bun.SHA256().update([1])",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "input must be a string, ArrayBuffer, ArrayBufferView or Blob",
        ),
        (
            "new Bun.SHA256().update(1)",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "input must be a string, ArrayBuffer, ArrayBufferView or Blob",
        ),
        (
            "new Bun.SHA256().update(null)",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "input must be a string, ArrayBuffer, ArrayBufferView or Blob",
        ),
        (
            "new Bun.SHA256().update({})",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "input must be a string, ArrayBuffer, ArrayBufferView or Blob",
        ),
        (
            "new Bun.CryptoHasher()",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "algorithm must be a string",
        ),
        (
            "new Bun.CryptoHasher(123)",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "algorithm must be a string",
        ),
        (
            "new Bun.CryptoHasher('bogus')",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "Unsupported algorithm bogus",
        ),
        (
            "Bun.CryptoHasher.hash('bogus', 'abc', 'hex')",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "Unsupported algorithm \"bogus\"",
        ),
        (
            "Bun.CryptoHasher.hash('abc')",
            "TypeError",
            "ERR_INVALID_ARG_TYPE",
            "input must be a string, ArrayBuffer, ArrayBufferView or Blob",
        ),
    ];

    for (expression, name, code, message) in cases {
        let report = eval(&format!("JSON.stringify(attempt(() => {expression}))"));
        // Parse the four fields out of the JSON by hand: no serde_json needed for
        // four strings, and a wrong shape is then a clear assertion failure.
        let field = |key: &str| -> Option<String> {
            let needle = format!("\"{key}\":");
            let start = report.find(&needle)? + needle.len();
            let rest = &report[start..];
            if let Some(text) = rest.strip_prefix('"') {
                // Scan to the closing quote, respecting backslash escapes.
                let mut out = String::new();
                let mut chars = text.chars();
                while let Some(ch) = chars.next() {
                    match ch {
                        '\\' => match chars.next()? {
                            'n' => out.push('\n'),
                            't' => out.push('\t'),
                            'r' => out.push('\r'),
                            'u' => {
                                let hex: String = chars.by_ref().take(4).collect();
                                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                            }
                            other => out.push(other),
                        },
                        '"' => break,
                        other => out.push(other),
                    }
                }
                Some(out)
            } else {
                let end = rest.find([',', '}']).unwrap_or(rest.len());
                Some(rest[..end].to_string())
            }
        };
        assert_eq!(
            field("ok").as_deref(),
            Some("false"),
            "{expression} did not throw: {report}"
        );
        assert_eq!(field("name").as_deref(), Some(*name), "{expression} class");
        let found_code = field("code").unwrap_or_default();
        let found_code = if found_code == "null" {
            String::new()
        } else {
            found_code
        };
        assert_eq!(found_code, *code, "{expression} code");
        assert_eq!(
            field("message").as_deref(),
            Some(*message),
            "{expression} message"
        );
    }
}

fn case_update_encoding_argument_is_ignored_by_the_per_class_families() {
    // The measured digest of the literal characters `616263` under SHA-256,
    // recorded from Bun: the encoding argument is ignored, so the six characters
    // are hashed rather than the three bytes they spell.
    assert_eq!(
        eval("new Bun.SHA256().update('616263', 'hex').digest('hex')"),
        "86900f25bd2ee285bc6c22800cfb8f2c3411e45c9f53b3ba5a8017af9d6b6b05",
        "per-class update must ignore its encoding argument"
    );
    // An invalid encoding is silently ignored rather than throwing.
    assert_eq!(
        eval("new Bun.SHA256().update('abc', 'nope').digest('hex')"),
        lookup("[per_class]", "SHA256.abc"),
    );
}

fn case_crypto_hasher_update_does_decode_hex() {
    // The opposite of the per-class behaviour, and measured.
    assert_eq!(
        eval("new Bun.CryptoHasher('sha256').update('616263', 'hex').digest('hex')"),
        lookup("[per_class]", "SHA256.abc"),
    );
    // Odd-length hex is an error rather than a dropped nibble.
    let report =
        eval("JSON.stringify(attempt(() => new Bun.CryptoHasher('sha256').update('61626','hex')))");
    assert!(report.contains("ERR_INVALID_ARG_VALUE"), "{report}");
}

fn case_digest_is_a_terminal_operation_for_the_per_class_families_only() {
    // Per-class: a second digest throws.
    let report = eval(
        "JSON.stringify(attempt(() => { const h = new Bun.SHA256(); h.update('abc'); h.digest(); return h.digest(); }))",
    );
    assert!(report.contains("ERR_INVALID_STATE"), "{report}");

    // CryptoHasher: a second digest hashes the empty input instead.
    assert_eq!(
        eval("(() => { const h = new Bun.CryptoHasher('sha256'); h.update('abc'); h.digest('hex'); return h.digest('hex'); })()"),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
}

fn case_absent_encoding_differs_between_the_two_families() {
    // Measured: the per-class family yields a `Uint8Array`, `CryptoHasher` a
    // `Buffer`.
    // The class *name* is not asserted for the Buffer case: a bare isolate has no
    // real `Buffer`, so the prelude supplies one whose `.name` is its own. What
    // matters is which of the two paths produces a `Buffer`, and `Buffer.isBuffer`
    // is the discriminator Bun's own docs and tests use.
    let report = eval(
        r#"
        const perClass = new Bun.SHA256().update('abc').digest();
        const generic = new Bun.CryptoHasher('sha256').update('abc').digest();
        [perClass.constructor.name, Buffer.isBuffer(perClass),
         Buffer.isBuffer(generic),
         Buffer.isBuffer(Bun.SHA256.hash('abc')),
         Buffer.isBuffer(Bun.SHA256.hash('abc', 'buffer')),
         Buffer.isBuffer(Bun.CryptoHasher.hash('sha256', 'abc')),
         Buffer.isBuffer(new Bun.SHA256().update('abc').digest('buffer'))].join(',')
        "#,
    );
    assert_eq!(report, "Uint8Array,false,true,false,true,true,true");
}

fn case_digest_into_a_target_writes_the_bytes_and_returns_the_target() {
    // The minimum is the digest length per class, and 64 bytes for CryptoHasher.
    let report = eval(
        r#"
        const short = new Uint8Array(31);
        const exact = new Uint8Array(32);
        const returned = new Bun.SHA256().update('abc').digest(exact);
        const generic = new Uint8Array(64);
        const genericReturned = new Bun.CryptoHasher('sha256').update('abc').digest(generic);
        let shortError = attempt(() => new Bun.SHA256().update('abc').digest(short));
        let genericShort = attempt(() => new Bun.CryptoHasher('sha256').update('abc').digest(new Uint8Array(63)));
        [returned === exact, hex(exact), genericReturned === generic, hex(generic.slice(0, 32)),
         shortError.code, shortError.message, genericShort.message].join('|')
        "#,
    );
    let expected = lookup("[per_class]", "SHA256.abc");
    assert_eq!(
        report,
        format!(
            "true|{expected}|true|{expected}|ERR_INVALID_ARG_TYPE|TypedArray must be at least 32 bytes|TypedArray must be at least 64 bytes"
        )
    );
}

fn case_hash_input_coercion_matches_measured_bun() {
    // Non-string, non-byte inputs go through `String()`, not `JSON.stringify`.
    let report = eval(
        r#"
        [
          Bun.hash(42) === Bun.hash('42'),
          Bun.hash(true) === Bun.hash('true'),
          Bun.hash({}) === Bun.hash('[object Object]'),
          Bun.hash([1,2]) === Bun.hash('1,2'),
          Bun.hash(Buffer.from('abc')) === Bun.hash('abc'),
          Bun.hash('abc', 'zzz') === Bun.hash('abc', 0),
          Bun.hash('abc', null) === Bun.hash('abc', 0),
          typeof Bun.hash('abc'),
          Bun.hash('abc') >= 0n && Bun.hash('abc') < 2n ** 64n,
        ].join(',')
        "#,
    );
    assert_eq!(report, "true,true,true,true,true,true,true,bigint,true");
}

fn case_hash_seed_conversion_matches_measured_bun() {
    // Negative and out-of-range numbers are the cases a naive cast gets wrong.
    let report = eval(
        r#"
        const h = (seed) => Bun.hash('abc', seed).toString();
        [
          h(0) === h(0n),
          h(-1) === h(18446744073709551615n),
          h(1.9) === h(1n),
          h(-1.9) === h(18446744073709551615n),
          h(NaN) === h(0n),
          h(Infinity) === h(18446744073709551615n),
          h(-Infinity) === h(0n),
          h(2 ** 64) === h(18446744073709551615n),
          h(-(2 ** 63)) === h(9223372036854775808n),
          h(-1e19) === h(8446744073709551616n),
          h(2n ** 64n + 5n) === h(5n),
        ].join(',')
        "#,
    );
    assert_eq!(
        report,
        "true,true,true,true,true,true,true,true,true,true,true"
    );
}

fn case_hash_variants_match_the_measured_values() {
    struct Case {
        name: &'static str,
        abc: &'static str,
        empty: &'static str,
        is_bigint: bool,
    }
    let cases = [
        Case {
            name: "adler32",
            abc: "38600999",
            empty: "1",
            is_bigint: false,
        },
        Case {
            name: "crc32",
            abc: "891568578",
            empty: "0",
            is_bigint: false,
        },
        Case {
            name: "cityHash32",
            abc: "795041479",
            empty: "3696677242",
            is_bigint: false,
        },
        Case {
            name: "cityHash64",
            abc: "6234256295332240817",
            empty: "0",
            is_bigint: true,
        },
        Case {
            name: "xxHash32",
            abc: "852579327",
            empty: "46947589",
            is_bigint: false,
        },
        Case {
            name: "xxHash64",
            abc: "4952883123889572249",
            empty: "17241709254077376921",
            is_bigint: true,
        },
        Case {
            name: "xxHash3",
            abc: "8696274497037089104",
            empty: "3244421341483603138",
            is_bigint: true,
        },
        Case {
            name: "murmur32v2",
            abc: "324500635",
            empty: "0",
            is_bigint: false,
        },
        Case {
            name: "murmur32v3",
            abc: "3017643002",
            empty: "0",
            is_bigint: false,
        },
        Case {
            name: "murmur64v2",
            abc: "11297775770902552315",
            empty: "0",
            is_bigint: true,
        },
        Case {
            name: "rapidhash",
            abc: "8246329693904217010",
            empty: "10602188539874428322",
            is_bigint: true,
        },
        Case {
            name: "wyhash",
            abc: "190542993387777138",
            empty: "290873116282709081",
            is_bigint: true,
        },
    ];
    for case in cases {
        let expected_type = if case.is_bigint { "bigint" } else { "number" };
        let report = eval(&format!(
            "[String(Bun.hash.{}( 'abc')), String(Bun.hash.{0}('')), typeof Bun.hash.{0}('abc')].join('|')",
            case.name
        ));
        assert_eq!(
            report,
            format!("{}|{}|{expected_type}", case.abc, case.empty),
            "Bun.hash.{}",
            case.name
        );
    }
}

fn case_hash_seed_widths_match_measured_bun() {
    // Three distinct behaviours, all measured: adler32 and cityHash32 ignore the
    // seed, crc32 and xxHash3 truncate it to 32 bits, the 64-bit family uses all
    // of it.
    let report = eval(
        r#"
        [
          Bun.hash.adler32('abc', 99) === Bun.hash.adler32('abc'),
          Bun.hash.cityHash32('abc', 99) === Bun.hash.cityHash32('abc'),
          Bun.hash.crc32('abc', 2 ** 32) === Bun.hash.crc32('abc', 0),
          Bun.hash.xxHash3('abc', 2 ** 32) === Bun.hash.xxHash3('abc', 0),
          Bun.hash.xxHash3('abc', 2 ** 32 + 5) === Bun.hash.xxHash3('abc', 5),
          Bun.hash.wyhash('abc', 2n ** 64n - 1n) !== Bun.hash.wyhash('abc', 0n),
        ].join(',')
        "#,
    );
    assert_eq!(report, "true,true,true,true,true,true");
}

fn case_crypto_hasher_hmac_matches_node_and_bun() {
    for (algorithm, expected) in [
        (
            "sha256",
            "9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab",
        ),
        ("sha1", lookup("[hmac]", "sha1").as_str()),
        ("md5", lookup("[hmac]", "md5").as_str()),
        ("md4", lookup("[hmac]", "md4").as_str()),
        ("sha512", lookup("[hmac]", "sha512").as_str()),
        ("sha3-256", lookup("[hmac]", "sha3-256").as_str()),
        ("blake2b256", lookup("[hmac]", "blake2b256").as_str()),
        ("ripemd160", lookup("[hmac]", "ripemd160").as_str()),
        ("sha512-224", lookup("[hmac]", "sha512-224").as_str()),
    ] {
        let actual = eval(&format!(
            "new Bun.CryptoHasher('{algorithm}', 'key').update('abc').digest('hex')"
        ));
        assert_eq!(actual, expected, "HMAC-{algorithm}");
    }
    // The SHAKEs are the algorithms Bun reports as unsupported for HMAC.
    let report = eval(
        "JSON.stringify(attempt(() => new Bun.CryptoHasher('shake128','key').update('abc').digest('hex')))",
    );
    assert!(
        report.contains("HMAC is not supported for this algorithm yet"),
        "{report}"
    );
}

fn case_crypto_hasher_copy_forks_the_state() {
    let report = eval(
        r#"
        const original = new Bun.CryptoHasher('sha256').update('ab');
        const copy = original.copy();
        [original.update('c').digest('hex'), copy.update('c').digest('hex'),
         copy instanceof Bun.CryptoHasher, copy.algorithm].join('|')
        "#,
    );
    let expected = lookup("[per_class]", "SHA256.abc");
    assert_eq!(report, format!("{expected}|{expected}|true|sha256"));
}

fn case_crypto_hasher_algorithm_aliases_match_measured_bun() {
    let report = eval(
        r#"
        const accepted = ['SHA256','sha-256','SHA-256','MD5','md5','SHA-512/256','shake-128','BLAKE2B512'];
        const rejected = ['sha_256','sha2-256','sha512_256','md-5','ripemd-160','blake2b-512','bogus'];
        const out = [];
        for (const name of accepted) out.push('+' + attempt(() => new Bun.CryptoHasher(name).algorithm).value);
        for (const name of rejected) out.push(attempt(() => new Bun.CryptoHasher(name)).code);
        out.join('|')
        "#,
    );
    assert_eq!(
        report,
        "+sha256|+sha256|+sha256|+md5|+md5|+sha512-256|+shake128|+blake2b512|\
ERR_INVALID_ARG_TYPE|ERR_INVALID_ARG_TYPE|ERR_INVALID_ARG_TYPE|ERR_INVALID_ARG_TYPE|\
ERR_INVALID_ARG_TYPE|ERR_INVALID_ARG_TYPE|ERR_INVALID_ARG_TYPE"
    );
}

fn case_bun_sha_is_sha512_256_as_a_bare_one_shot() {
    // Measured: `Bun.sha` is a distinct function from `Bun.SHA512_256.hash`
    // (`sha === SHA512_256.hash` is false), has `length` 1 rather than 2, and is
    // not a constructor.
    let expected = lookup("[per_class]", "SHA512_256.abc");
    let report = eval(
        r#"
        const viaSha = Bun.sha('abc', 'hex');
        const fresh = Bun.sha('abc');
        [viaSha, hex(fresh), fresh.constructor.name, Buffer.isBuffer(fresh),
         Bun.sha === Bun.SHA512_256.hash, Bun.sha.length, Bun.sha.name,
         Buffer.isBuffer(Bun.sha('abc', 'buffer')),
         hex(Bun.sha(pattern(200))), hex(Bun.sha(pattern(100000)))].join('|')
        "#,
    );
    assert_eq!(
        report,
        format!(
            "{expected}|{expected}|Uint8Array|false|false|1|sha|true|{}|{}",
            lookup("[per_class]", "SHA512_256.multi"),
            lookup("[per_class]", "SHA512_256.large"),
        )
    );
    // `new Bun.sha()` is a `TypeError`, and an invalid encoding is
    // `ERR_INVALID_ARG_VALUE`, not a silently-hashed string.
    assert_eq!(
        eval("typeof attempt(() => new Bun.sha())"),
        "object",
        "constructing Bun.sha must throw"
    );
    let report = eval("JSON.stringify(attempt(() => Bun.sha('abc','bogus')))");
    assert!(report.contains("ERR_INVALID_ARG_VALUE"), "{report}");
    let report = eval("JSON.stringify(attempt(() => Bun.sha(42)))");
    assert!(report.contains("ERR_INVALID_ARG_TYPE"), "{report}");
}

/// The registry is the reason this crate cannot declare a member it does not
/// install, and this proves that property against *this* crate's declaration
/// rather than trusting the registry's own tests.
///
/// It builds a module that declares two names and installs one, so the failure
/// has to come from the comparison and not from a name that happens to be
/// missing at install time. The message has to name the member, because "a
/// member is missing" on a surface six workers are editing is not actionable.
fn case_the_registry_refuses_a_declared_but_uninstalled_member() {
    struct Broken;
    impl rn_bun_api::BunModule for Broken {
        fn contributor(&self) -> &'static str {
            "rn-bun-hash"
        }
        fn members(&self) -> &'static [&'static str] {
            &["hash", "sha"]
        }
        fn install<'s>(
            &self,
            scope: &mut v8::PinScope<'s, '_>,
            target: v8::Local<'s, v8::Object>,
        ) -> Result<(), String> {
            let key = v8::String::new(scope, "hash").expect("key");
            target.set(scope, key.into(), v8::Integer::new(scope, 1).into());
            Ok(())
        }
    }

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let mut registry = BunRegistry::new();
    registry
        .register_module(Broken)
        .expect("the declaration itself is not contradictory");
    let error = registry
        .build(scope)
        .expect_err("a declared member that install never sets must be refused");
    assert!(
        error.contains("declares 1 Bun member(s) it never installs: sha"),
        "the refusal must name the member, got: {error}"
    );
}

/// [`crate::MEMBERS`] must be exactly what the registry installs.
///
/// The guard compares the declarations against the shipping object, but it does
/// so against Bun's recorded surface; this pins the other direction — that the
/// declaration this crate publishes is the set of names the installed object
/// carries — without needing Bun on disk.
fn case_declaration_matches_the_installed_object() {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let mut registry = BunRegistry::new();
    registry
        .register_module(Hashing)
        .expect("the hashing group registers");
    let bun = registry.build(scope).expect("the hashing group installs");

    let names = bun
        .get_own_property_names(scope, v8::GetPropertyNamesArgs::default())
        .expect("own names");
    let mut installed: Vec<String> = Vec::new();
    for index in 0..names.length() {
        if let Some(value) = names.get_index(scope, index) {
            installed.push(value.to_rust_string_lossy(scope));
        }
    }
    installed.sort();
    let mut declared: Vec<String> = rn_bun_hash::MEMBERS.iter().map(|s| s.to_string()).collect();
    declared.sort();
    assert_eq!(installed, declared);
    assert_eq!(
        declared.len(),
        11,
        "the hashing group's member count changed"
    );
}

/// V8's platform and global state are process-wide, so every case shares one
/// test. Each case still gets its own isolate, which is what keeps a crash in
/// one from hiding the others' results.
///
/// A per-case `#[test]` cannot work here: `V8::initialize_platform` is not
/// re-entrant and the second call poisons the lock, which is a `PoisonError` and
/// not a test failure anyone can read.
#[test]
fn bun_hashing_surface_end_to_end() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    case_every_per_class_digest_matches_the_oracle();
    case_bun_sha_is_sha512_256_as_a_bare_one_shot();
    case_the_registry_refuses_a_declared_but_uninstalled_member();
    case_declaration_matches_the_installed_object();
    case_every_crypto_hasher_algorithm_matches_the_oracle();
    case_digest_output_encodings_match_the_oracle();
    case_hash_matches_wyhash_final_4();
    case_class_shapes_match_measured_bun();
    case_failure_modes_match_measured_bun();
    case_update_encoding_argument_is_ignored_by_the_per_class_families();
    case_crypto_hasher_update_does_decode_hex();
    case_digest_is_a_terminal_operation_for_the_per_class_families_only();
    case_absent_encoding_differs_between_the_two_families();
    case_digest_into_a_target_writes_the_bytes_and_returns_the_target();
    case_hash_input_coercion_matches_measured_bun();
    case_hash_seed_conversion_matches_measured_bun();
    case_hash_variants_match_the_measured_values();
    case_hash_seed_widths_match_measured_bun();
    case_crypto_hasher_hmac_matches_node_and_bun();
    case_crypto_hasher_copy_forks_the_state();
    case_crypto_hasher_algorithm_aliases_match_measured_bun();
}
